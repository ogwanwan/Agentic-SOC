"""Gemini API를 사용하는 LLM 클라이언트.

claude_client.py의 ClaudeClient(Anthropic)와 동일하게 .reason(state, tool_registry) 인터페이스를
제공하므로, agent/loop.py의 InvestigationAgent(llm_client=...)에 이 클래스를 그대로
넣어 쓸 수 있다. 즉 Claude ↔ Gemini는 이 클라이언트만 교체하면 된다.

사전 준비:
    pip install google-genai
    export GEMINI_API_KEY=...   (Google AI Studio에서 발급한 무료 티어 키도 가능)

*** 2026-09-17 업데이트: confidence_threshold/force_terminate 전달 + temperature 0.0 ***
reason()이 loop.py로부터 confidence_threshold(LLM이 종료 조건을 스스로 검증하도록)와
force_terminate(max_call 도달 시 도구 호출 없이 판정만 요청하는 마무리 턴 여부)를
받아 prompts.build_user_prompt()에 그대로 전달하도록 확장했다.

temperature는 0.2 -> 0.0으로 낮췄다 — 같은 증거를 두고 실행마다 판정이 갈리는
재현성 이슈가 발견되어, 조사 판정처럼 일관성이 중요한 영역에서는 창의성보다
결정성을 우선하기로 했다.

*** 2026-09-17 추가 업데이트: gate_rejection_reason 전달 ***
loop.py의 종료 관문이 거부한 사유를 다음 턴 프롬프트에 노출하기 위해
gate_rejection_reason 파라미터를 추가로 받아 build_user_prompt()에 전달한다.
(종료 관문이 같은 사유로 계속 거부되는데 LLM이 그 사실을 몰라 동일 요청을
반복하며 사이클을 낭비하던 버그의 수정 일부.)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional

from .prompts import build_system_prompt, build_user_prompt


class GeminiDecisionError(Exception):
    """Gemini 응답을 기대한 JSON 스키마로 파싱하지 못했을 때 발생."""


class GeminiClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-3.5-flash-lite",  # 무료 티어 실습에서 지정한 모델
        # [2026-09-24] 2000 → 8192. EC2 main.py에서 LLM이 raw_ref 109개를 evidence에 옮겨 적다
        # 2000 토큰에서 응답이 잘려 JSON 파싱이 실패했고, 그 예외로 main.py 전체가 멈췄다.
        max_output_tokens: int = 8192,
        temperature: float = 0.0,
    ) -> None:
        # google-genai 패키지는 실제 호출 시에만 필요하므로 지연 import한다.
        from google import genai

        resolved_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not resolved_key:
            raise ValueError(
                "GEMINI_API_KEY가 설정되지 않았습니다. .env 파일에 "
                "GEMINI_API_KEY=발급받은_키 를 추가하거나 GeminiClient(api_key=...)로 "
                "직접 전달하십시오."
            )

        self._client = genai.Client(api_key=resolved_key)
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature

    # [21] agent/prompts.py 실행하여 프롬포트 호출
    def reason(
        self,
        state: Any,
        tool_registry: Any,
        confidence_threshold: Optional[float] = None,
        force_terminate: bool = False,
        gate_rejection_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """조사 루프(agent/loop.py) 전용: prompts.py의 investigation 프롬프트로 호출.

        confidence_threshold: 시스템의 종료 임계값을 프롬프트에 노출하기 위해 전달.
        force_terminate: max_call 도달 시 도구 호출 없이 판정만 받는 마무리 턴에서
        True로 호출됨.
        gate_rejection_reason: [2026-09-17 추가] 직전 턴에 종료 관문이 거부한 사유가
        있으면 전달 — LLM이 거부당한 사실을 인지하고 새 행동을 취하게 함.
        """
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(
            state,
            confidence_threshold=confidence_threshold,
            force_terminate=force_terminate,
            gate_rejection_reason=gate_rejection_reason,
        )
        return self.complete_json(system_prompt, user_prompt)

    # [22] 만들어진 프롬포트로 진짜 Gemini 호출
    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """범용 호출: 어떤 system/user 프롬프트든 받아서 JSON으로 파싱해 돌려준다.
        seed_generation.py(경량 LLM triage)처럼 조사 루프가 아닌 다른 용도에서도 재사용한다.
        """
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type="application/json",  # Gemini가 JSON만 반환하도록 강제
            max_output_tokens=self.max_output_tokens,
            temperature=self.temperature,
        )
        response = self._generate_with_retry(user_prompt, config)
        text = response.text
        if not text:
            raise GeminiDecisionError(
                f"Gemini가 빈 응답을 반환했습니다. (finish_reason 등을 확인하십시오)\n원본 응답: {response}"
            )
        return self._parse_json(text)

    # [2026-09-24] 503(서버 과부하)/429(분당 한도)는 일시적인 오류인데, 예전엔 한 번만 나도
    # main.py 전체가 예외로 끝났다(seed 생성 단계에서 연속 발생 확인). 이 두 코드만
    # 기다렸다가 다시 시도하고, 그 외 오류는 바로 올려 보낸다.
    _RETRYABLE_STATUS = {429, 503}
    _RETRY_DELAY_RE = re.compile(r"retryDelay['\"]?:\s*['\"]?(\d+(?:\.\d+)?)s")
    MAX_ATTEMPTS = 4
    BASE_DELAY_SECONDS = 15.0

    def _generate_with_retry(self, user_prompt: str, config: Any) -> Any:
        import time

        from google.genai import errors

        # 연결이 중간에 끊기는 오류(SSL EOF, WinError 10053 등)도 일시적이라 재시도한다.
        # 2026-09-24 재현성 실행 중 두 번 발생해 그 조사 1건이 통째로 실패했다.
        # google-genai는 httpx를 쓰므로 httpx.TransportError도 함께 잡는다.
        try:
            import httpx
            transport_errors: tuple = (OSError, httpx.TransportError)
        except ImportError:  # pragma: no cover - httpx는 google-genai 의존성
            transport_errors = (OSError,)

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                return self._client.models.generate_content(
                    model=self.model, contents=user_prompt, config=config
                )
            except transport_errors as exc:
                if attempt == self.MAX_ATTEMPTS:
                    raise
                delay = 5.0 * attempt
                print(f"[Gemini 연결 오류: {type(exc).__name__}] {delay:.0f}초 후 재시도 ({attempt}/{self.MAX_ATTEMPTS - 1})")
                time.sleep(delay)
            except errors.APIError as exc:
                if exc.code not in self._RETRYABLE_STATUS or attempt == self.MAX_ATTEMPTS:
                    raise
                # 429는 서버가 알려준 retryDelay를 따르고, 없으면 지수 백오프(15s, 30s, 60s)
                match = self._RETRY_DELAY_RE.search(str(exc))
                delay = float(match.group(1)) + 2.0 if match else self.BASE_DELAY_SECONDS * 2 ** (attempt - 1)
                print(f"[Gemini {exc.code}] {delay:.0f}초 후 재시도 ({attempt}/{self.MAX_ATTEMPTS - 1})")
                time.sleep(delay)
        raise AssertionError("unreachable")

    # [2026-09-18 추가] LLM이 가끔 JSON 응답 중간에 markdown 리스트 문법
    # (`- key: value`처럼 키 앞에 하이픈이 붙고 따옴표가 빠진 형태)을 섞어 넣어
    # json.loads()가 실패하는 사례가 발견됐다. 기존 trailing comma 보정으로는
    # 못 잡는 새로운 유형이라, 이 패턴을 정규식으로 감지해 정상 JSON 키 형태로
    # 복구하는 보정 단계를 추가했다.
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
            # 1차 보정: trailing comma 제거
            fixed = re.sub(r",\s*([\]}])", r"\1", cleaned)
            # 2차 보정: markdown 리스트 문법으로 깨진 키(`- key:` → `"key":`) 복구.
            # 두 보정을 순서대로 누적 적용해서, 두 문제가 같이 섞여 나온 경우도 처리한다.
            fixed = GeminiClient._MARKDOWN_BULLET_KEY_RE.sub(r'\1"\2":', fixed)

            if fixed != cleaned:
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass

            raise GeminiDecisionError(
                f"Gemini 응답을 JSON으로 파싱하지 못했습니다: {exc}\n원본 응답:\n{text}"
            ) from exc