"""Claude(Anthropic API) LLM 클라이언트 — LLM_PROVIDER=anthropic일 때 GeminiClient 대신 쓴다.

역할
  프롬프트를 받아 Claude를 호출하고 응답을 JSON(dict)으로 파싱해 돌려준다.

누가 부르나
  main.py build_llm_client()                 → ClaudeClient()    생성 (LLM_PROVIDER=anthropic)
  [20] agent/loop.py _safe_reason()          → reason()
  [13-1] agent/seed_generation.py generate() → complete_json()

무엇을 부르나
  [21] agent/prompts/__init__.py  build_system_prompt(), build_user_prompt()
  [22] anthropic  messages.create()          필요 환경변수: ANTHROPIC_API_KEY

주의: 아직 GeminiClient와 인터페이스가 완전히 같지 않다. reason()이 confidence_threshold·
force_terminate·gate_rejection_reason 인자를 받지 않아 지금 조사 루프에서는 첫 턴에 TypeError가 나고,
max_tokens(2000)·temperature도 Gemini 쪽 설정(8192·0.0)과 다르다 — Claude로 전환하기 전에 맞춰야 한다.
테스트에서는 같은 인터페이스의 가짜 클라이언트로 바꿔 쓴다(tests/test_loop.py).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from .prompts import build_system_prompt, build_user_prompt


class ClaudeDecisionError(Exception):
    """LLM 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생."""


class ClaudeClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-5-20250929",  # 실제 사용 모델명으로 교체
        max_tokens: int = 2000,
    ) -> None:
        # anthropic 패키지는 실제 API 호출 시에만 필요하므로 지연 import한다.
        from anthropic import Anthropic

        self._client = Anthropic(api_key=api_key)  # api_key=None이면 ANTHROPIC_API_KEY 환경변수 사용
        self.model = model
        self.max_tokens = max_tokens

    def reason(self, state: Any, tool_registry: Any) -> Dict[str, Any]:
        """조사 루프(agent/loop.py) 전용: prompts.py의 investigation 프롬프트로 호출."""
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(state)
        return self.complete_json(system_prompt, user_prompt)

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다.
        seed_generation.py(경량 LLM triage)처럼 조사 루프가 아닌 다른 용도에서도 재사용한다.
        """
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        return self._parse_json(text)

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
            # trailing comma(",]"/",}") 같은 사소한 문법 오류만 고쳐서 한 번 더 시도한다.
            fixed = re.sub(r",\s*([\]}])", r"\1", cleaned)
            if fixed != cleaned:
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass
            raise ClaudeDecisionError(
                f"LLM 응답을 JSON으로 파싱하지 못했습니다: {exc}\n원본 응답:\n{text}"
            ) from exc