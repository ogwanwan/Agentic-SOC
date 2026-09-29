"""LLM 응답 JSON 해석 — Gemini·Claude 클라이언트 공용.

역할
  LLM 응답 텍스트에서 조사 결정 JSON(dict)을 꺼낸다. 아래 순서로 시도하고, 각 후보에 흔한 형식 오류
  보정(trailing comma, markdown 리스트로 깨진 키)을 누적 적용한다.
    1. 응답 전체 (맨 앞 코드펜스 ```json 은 벗김)
    2. 응답 중간의 ```json … ``` 코드 블록
    3. 첫 '{'부터 마지막 '}'까지
  2·3은 JSON 앞뒤에 설명 문장이 붙은 응답용이다. Gemini는 API가 JSON만 내보내게 강제(response_mime_type)
  하지만 Claude는 강제 설정이 없어, 2026-09-28 첫 실제 실행에서 응답을 두 번 연속 "line 1 column 1"로
  해석하지 못해 폴백 판정이 났다.
  끝내 실패하면 첫 줄에 응답 앞부분을 담은 오류를 낸다 — 조사 루프가 notes에 첫 줄만 남기므로,
  다음 실패 때 원인을 추정이 아니라 확인할 수 있게 한다.

누가 부르나
  agent/gemini_client.py, agent/claude_client.py   complete_json() → parse_llm_json()
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Type

# LLM이 가끔 JSON 중간에 markdown 리스트 문법(`- key: value`, 키 앞 하이픈·따옴표 빠짐)을 섞는다
_MARKDOWN_BULLET_KEY_RE = re.compile(r'(?m)^(\s*)-\s*"?([A-Za-z_][A-Za-z0-9_]*)"?\s*:')
_TRAILING_COMMA_RE = re.compile(r",\s*([\]}])")
_FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n?```", re.DOTALL)
RESPONSE_HEAD_CHARS = 200


def _strip_leading_fence(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    return cleaned


def _candidates(text: str) -> List[str]:
    found = [_strip_leading_fence(text)]
    found += [block.strip() for block in _FENCED_BLOCK_RE.findall(text)]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        found.append(text[start:end + 1])
    return list(dict.fromkeys(c for c in found if c))


def _loads_with_fixes(candidate: str) -> Any:
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # 1차 보정: trailing comma 제거, 2차 보정: markdown 리스트로 깨진 키 복구 (누적 적용)
        fixed = _MARKDOWN_BULLET_KEY_RE.sub(r'\1"\2":', _TRAILING_COMMA_RE.sub(r"\1", candidate))
        if fixed == candidate:
            raise
        return json.loads(fixed)


def parse_llm_json(text: str, error_cls: Type[Exception], label: str = "LLM") -> Dict[str, Any]:
    """응답 텍스트에서 JSON 객체(dict)를 꺼낸다. 실패하면 error_cls(첫 줄에 응답 앞부분)를 낸다."""
    first_error = None
    for candidate in _candidates(text):
        try:
            value = _loads_with_fixes(candidate)
        except json.JSONDecodeError as exc:
            first_error = first_error or exc
            continue
        if isinstance(value, dict):
            return value
    head = " ".join(text.strip()[:RESPONSE_HEAD_CHARS].split())
    reason = first_error or "JSON 객체({...})가 아님"
    raise error_cls(
        f"{label} 응답을 JSON으로 파싱하지 못했습니다: {reason} | 응답 앞부분: {head!r}\n원본 응답:\n{text}"
    ) from first_error
