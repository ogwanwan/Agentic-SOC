"""Gemini API LLM 클라이언트 (기본값).

역할
  조사 루프와 seed 생성에서 LLM을 부르는 창구. 프롬프트를 받아 Gemini를 호출하고,
  응답을 JSON(dict)으로 파싱해 돌려준다. temperature 0.0 — 같은 증거에 같은 판정이 나오도록
  창의성보다 결정성을 우선한다. 일시적 오류(429 한도, 503 과부하, 연결 끊김)는 기다렸다 재시도한다.

누가 부르나
  [20] agent/loop.py _safe_reason()         → reason()          조사 루프 매 턴
  [13-1] agent/seed_generation.py generate() → complete_json()   seed 후보 뽑기
  main.py build_llm_client()                 → GeminiClient()    생성 (LLM_PROVIDER=gemini, 기본)

무엇을 부르나
  [21] agent/prompts/__init__.py  build_system_prompt(), build_user_prompt()   조사 프롬프트 조립
  [22] google-genai  models.generate_content()                                 실제 API 호출

claude_client.py의 ClaudeClient와 인터페이스(.reason / .complete_json)가 같아서
LLM_PROVIDER 환경변수로 서로 바꿔 쓸 수 있다. 필요 환경변수: GEMINI_API_KEY.
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
        # 2000이던 값을 8192로 올렸다. EC2에서 LLM이 raw_ref 109개를 evidence에 옮겨 적다
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

    # [21] ← agent/loop.py [20] _safe_reason()에서 매 턴 호출
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
        # [21] → agent/prompts/__init__.py: 시스템 프롬프트(원칙·도구 목록·출력 형식) + 사용자 프롬프트(현재 State)
        system_prompt = build_system_prompt(tool_registry)
        user_prompt = build_user_prompt(
            state,
            confidence_threshold=confidence_threshold,
            force_terminate=force_terminate,
            gate_rejection_reason=gate_rejection_reason,
        )
        # [22] → complete_json()으로 실제 호출 / [23] ← 파싱된 결정 dict를 loop.py로 돌려준다
        return self.complete_json(system_prompt, user_prompt)

    # [22] 실제 Gemini 호출 — 조사 루프와 seed 생성([13-1]) 둘 다 여기로 온다
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

    # 503(서버 과부하)/429(분당 한도)는 일시적인 오류인데, 예전엔 한 번만 나도
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
        # 재현성 실행 중 두 번 발생해 그 조사 1건이 통째로 실패했다.
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

    # LLM이 가끔 JSON 응답 중간에 markdown 리스트 문법
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