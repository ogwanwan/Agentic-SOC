"""Claude(Anthropic API) LLM 클라이언트 — LLM_PROVIDER=anthropic일 때 GeminiClient 대신 쓴다.

역할
  프롬프트를 받아 Claude를 호출하고 응답을 JSON(dict)으로 파싱해 돌려준다. GeminiClient와 같은
  인터페이스·설정(출력 한도 8192, temperature 0.0)이라 LLM_PROVIDER만 바꾸면 그대로 교체된다.
  일시 오류(429 한도, 529 과부하, 연결 끊김)는 anthropic SDK가 서버 안내 시간만큼 기다렸다 재시도한다.
  시스템 프롬프트는 매 턴 같으므로 프롬프트 캐싱으로 표시해 반복 호출 비용을 줄이고, 호출마다 쓴 토큰을
  usage_totals에 누적한다(조사 1건 비용 측정용).

누가 부르나
  main.py build_llm_client()                 → ClaudeClient()    생성 (LLM_PROVIDER=anthropic)
  [20] agent/loop.py _safe_reason()          → reason()          조사 루프 매 턴
  [13-1] agent/seed_generation.py generate() → complete_json()   seed 후보 뽑기

무엇을 부르나
  [21] agent/prompts/__init__.py  build_system_prompt(), build_user_prompt()
  [22] anthropic  messages.create()

필요 환경변수: ANTHROPIC_API_KEY. 모델은 CLAUDE_MODEL(없으면 claude-sonnet-5).
테스트에서는 같은 인터페이스의 가짜 클라이언트로 바꿔 쓴다(tests/test_loop.py, tests/test_claude_client.py).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional

from .prompts import build_system_prompt, build_user_prompt

DEFAULT_MODEL = "claude-sonnet-5"


class ClaudeDecisionError(Exception):
    """LLM 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생 (loop.py가 1회 재시도 후 폴백)."""


class ClaudeClient:
    # SDK 재시도 횟수 (429·529·연결 오류). SDK는 retry-after 안내를 따르고, 없으면 지수 백오프한다.
    MAX_RETRIES = 4

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        # GeminiClient와 같은 값. 2000이면 LLM이 원본 참조를 옮겨 적다 응답이 잘려 조사가 멈춘다.
        max_tokens: int = 8192,
        # 같은 증거에 같은 판정이 나오도록 결정성을 우선한다 (GeminiClient와 동일).
        temperature: float = 0.0,
    ) -> None:
        # anthropic 패키지는 실제 API 호출 시에만 필요하므로 지연 import한다.
        from anthropic import Anthropic

        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise ValueError(
                "ANTHROPIC_API_KEY가 설정되지 않았습니다. .env 파일에 "
                "ANTHROPIC_API_KEY=발급받은_키 를 추가하거나 ClaudeClient(api_key=...)로 "
                "직접 전달하십시오."
            )
        self._client = Anthropic(api_key=resolved_key, max_retries=self.MAX_RETRIES)
        self.model = model or os.environ.get("CLAUDE_MODEL") or DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.temperature = temperature
        # 이 클라이언트로 한 모든 호출의 토큰 합계 (비용 추정용)
        self.usage_totals: Dict[str, int] = {
            "calls": 0, "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        }

    # [21] ← agent/loop.py [20] _safe_reason()에서 매 턴 호출 (GeminiClient.reason과 같은 인자)
    def reason(
        self,
        state: Any,
        tool_registry: Any,
        confidence_threshold: Optional[float] = None,
        force_terminate: bool = False,
        gate_rejection_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """조사 루프 전용: agent/prompts/의 조사 프롬프트를 만들어 호출한다.

        confidence_threshold: 시스템의 종료 임계값을 프롬프트에 노출해 LLM이 스스로 확인하게 한다.
        force_terminate: 강제 종료·max_call 마무리 턴에서 True — 도구 없이 판정만 요청한다.
        gate_rejection_reason: 직전 턴에 종료 관문이 거부한 사유 — LLM이 같은 종료를 반복하지 않게 한다.
        """
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(
            state,
            confidence_threshold=confidence_threshold,
            force_terminate=force_terminate,
            gate_rejection_reason=gate_rejection_reason,
        )
        # [22] → complete_json()으로 실제 호출 / [23] ← 파싱된 결정 dict를 loop.py로 돌려준다
        return self.complete_json(system_prompt, user_prompt)

    # [22] 실제 Claude 호출 — 조사 루프와 seed 생성([13-1]) 둘 다 여기로 온다
    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다."""
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            # 시스템 프롬프트(원칙·도구 목록·출력 형식)는 매 턴 같아서 캐시해 두고 다시 읽는다.
            system=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_prompt}],
        )
        self._add_usage(getattr(response, "usage", None))
        text = "".join(getattr(block, "text", "") for block in response.content if block.type == "text")
        if getattr(response, "stop_reason", None) == "max_tokens":
            # 잘린 JSON은 고칠 수 없다 — loop.py가 해석 실패로 보고 1회 재시도, 그래도 실패하면 폴백 판정
            raise ClaudeDecisionError(
                f"Claude 응답이 출력 한도({self.max_tokens} 토큰)에서 잘렸습니다.\n원본 응답(앞부분):\n{text[:500]}"
            )
        if not text.strip():
            raise ClaudeDecisionError(f"Claude가 빈 응답을 반환했습니다. (stop_reason={getattr(response, 'stop_reason', None)})")
        return self._parse_json(text)

    def _add_usage(self, usage: Any) -> None:
        self.usage_totals["calls"] += 1
        if usage is None:
            return
        for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            self.usage_totals[key] += int(getattr(usage, key, 0) or 0)

    # LLM이 가끔 JSON 중간에 markdown 리스트 문법(`- key: value`)을 섞어 json.loads()가 실패한다.
    # GeminiClient와 같은 보정을 적용한다.
    _MARKDOWN_BULLET_KEY_RE = re.compile(r'(?m)^(\s*)-\s*"?([A-Za-z_][A-Za-z0-9_]*)"?\s*:')

    @staticmethod
    def _parse_json(text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            # 1차 보정: trailing comma 제거, 2차 보정: markdown 리스트로 깨진 키 복구 (누적 적용)
            fixed = re.sub(r",\s*([\]}])", r"\1", cleaned)
            fixed = ClaudeClient._MARKDOWN_BULLET_KEY_RE.sub(r'\1"\2":', fixed)
            if fixed != cleaned:
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            raise ClaudeDecisionError(
                f"LLM 응답을 JSON으로 파싱하지 못했습니다: {exc}\n원본 응답:\n{text}"
            ) from exc
