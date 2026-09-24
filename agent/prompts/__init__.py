"""Agent 판단·Prompt 담당 모듈 (패키지로 분리됨).

*** 2026-09-17 리팩터링: 프롬프트 본문을 yaml로 분리 ***
기존에는 이 모듈(agent/prompts.py) 안에 시스템 프롬프트 전체(역할, 원칙 1~7,
출력 스키마, 규칙)가 파이썬 문자열(SYSTEM_PROMPT_TEMPLATE)로 하드코딩되어 있었다.
오늘 하루 동안 이 프롬프트를 여러 차례 수정하면서(원칙 6/7 재설계, confidence
산정 기준 추가 등), 내용 변경마다 파이썬 코드 전체를 다시 봐야 하는 불편함이
있었다. 내용이 어느 정도 안정된 지금, 프롬프트 "내용"(investigation.yaml)과
"조립 로직"(이 파일)을 분리했다.

*** agent/seed_prompts.py는 이 리팩터링 대상이 아니다 ***
seed 생성(경량 LLM triage) 관련 프롬프트는 1차 탐지 단계가 확정되면 조사
에이전트 코드베이스에서 완전히 빠져나갈 예정이라, 지금 같이 yaml로 옮기면
나중에 다시 분리해야 하는 이중 작업이 된다. 그래서 agent/seed_prompts.py는
기존 그대로 별도 파일로 유지한다.

이 패키지의 공개 함수(build_system_prompt, build_user_prompt)는 기존
agent/prompts.py와 이름/시그니처가 동일하므로, 이 함수들을 가져다 쓰던
gemini_client.py 등의 코드는 수정할 필요가 없다 (agent.prompts가 모듈에서
패키지로 바뀌어도 `from .prompts import ...` 형태의 import 경로는 동일하게
동작한다).
"""

from __future__ import annotations

import json
from datetime import timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from ..provenance import strip_trace_fields
from ..tools.time_utils import parse_iso

# 원칙 7 Q1(시도 범위) 조회 구간. LLM에게 "trigger_time 기준 24시간 전"을 계산하라고 하면
# 1~2시간만 조회하는 경우가 반복돼(2026-09-24 재현성 테스트), 코드가 계산한 값을 그대로 준다.
AUTH_LOOKBACK_BEFORE = timedelta(hours=24)
AUTH_LOOKBACK_AFTER = timedelta(hours=1)


def auth_lookback_window(seed: Dict[str, Any]) -> Optional[list]:
    """seed에 src_ip와 기준 시각이 있으면 [시각-24h, 시각+1h] (UTC ISO 'Z')를 반환."""
    anchor = seed.get("trigger_time") or seed.get("timestamp")
    if not seed.get("src_ip") or not anchor:
        return None
    try:
        at = parse_iso(anchor).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None
    fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    return [fmt(at - AUTH_LOOKBACK_BEFORE), fmt(at + AUTH_LOOKBACK_AFTER)]

_PACKAGE_DIR = Path(__file__).resolve().parent


def _load_yaml(filename: str) -> Dict[str, Any]:
    with open(_PACKAGE_DIR / filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ----------------------------------------------------------------------
# investigation.yaml 로드 + 시스템 프롬프트 조립
# ----------------------------------------------------------------------
_investigation_spec = _load_yaml("investigation.yaml")


def _build_investigation_system_prompt_template() -> str:
    """investigation.yaml의 섹션들을 이어 붙여 최종 시스템 프롬프트 템플릿을 만든다.

    {tool_schema}는 build_system_prompt()에서 str.replace()로 치환된다
    (기존 .format() 방식 대신 replace를 쓰는 이유: output_schema 안에 JSON
    예시가 통째로 들어있어 중괄호가 많은데, .format()을 쓰려면 그 중괄호를
    전부 이스케이프({{ }})해야 해서 yaml 가독성이 떨어진다. replace는 그럴
    필요가 없다).
    """
    parts = [_investigation_spec["role"].strip()]

    parts.append("## 핵심 원칙")
    for principle in _investigation_spec["principles"]:
        parts.append(f"{principle['id']}. {principle['title']}: {principle['text'].strip()}")

    parts.append("## 강제 종료 턴 안내")
    parts.append(_investigation_spec["forced_termination_notice"].strip())

    parts.append("## 사용 가능한 도구")
    parts.append("{tool_schema}")

    parts.append("## 출력 형식")
    parts.append(
        "반드시 아래 JSON 스키마와 동일한 하나의 JSON 객체만 출력하십시오.\n"
        "다른 설명 문장, 마크다운, 코드펜스를 포함하지 마십시오.\n"
    )
    parts.append(_investigation_spec["output_schema"].strip())

    parts.append("규칙:")
    parts.append(_investigation_spec["rules"].strip())

    return "\n\n".join(parts) + "\n"


SYSTEM_PROMPT_TEMPLATE = _build_investigation_system_prompt_template()


def build_system_prompt(tool_registry: Any) -> str:
    return SYSTEM_PROMPT_TEMPLATE.replace("{tool_schema}", tool_registry.schema_text())


def build_user_prompt(
    state: Any,
    confidence_threshold: Optional[float] = None,
    force_terminate: bool = False,
    gate_rejection_reason: Optional[str] = None,
) -> str:
    payload: Dict[str, Any] = {
        "incident_id": state.incident_id,
        "seed": state.seed,
        "current_facts": state.facts,
        "current_hypotheses": [
            {
                "hyp_id": h.hyp_id,
                "title": h.title,
                "description": h.description,
                "confidence": h.confidence,
                "status": h.status,
            }
            for h in state.hypotheses.values()
        ],
        "current_unknowns": state.unknowns,
        "confirmed_evidence": [
            {
                "evidence_id": e.evidence_id,
                "layer": e.layer,
                "description": e.description,
                "confidence_contribution": e.confidence_contribution,
                "raw_refs": e.raw_refs,
            }
            for e in state.evidence
        ],
        "contradicting_evidence": [
            {"evidence_id": e.evidence_id, "layer": e.layer, "description": e.description, "raw_refs": e.raw_refs}
            for e in state.contradicting_evidence
        ],
        "current_confidence": round(state.current_confidence, 3),
        "confidence_threshold": confidence_threshold,
        "confidence_threshold_reached": (
            confidence_threshold is not None and state.current_confidence >= confidence_threshold
        ),
        "already_called_tools": [
            {"tool_name": t.tool_name, "input": t.input, "success": t.success}
            for t in state.tool_calls
        ],
        "investigated_layers": sorted(state.investigated_layers),
        # 추적용 필드(raw_ref_locations 등)는 LLM에게 안 보여준다 — loop.py는 도구 결과
        # 원본에서 그 값을 직접 읽으므로 인용 검증에는 영향 없음.
        "raw_observations_since_last_turn": strip_trace_fields(state.pending_observations),
        "known_raw_refs": state.raw_refs,
        "provenance_issues": state.provenance_issues,
        "tool_calls_used": len(state.tool_calls),
    }
    lookback = auth_lookback_window(state.seed)
    if lookback:
        payload["auth_lookback_window"] = lookback

    instruction = (
        "다음은 현재까지의 조사 상태입니다. 이를 바탕으로 시스템 프롬프트의 JSON 스키마에 "
        "맞춰 응답하십시오."
    )

    if gate_rejection_reason:
        payload["previous_termination_rejected"] = True
        payload["rejection_reason"] = gate_rejection_reason
        instruction += (
            f"\n\n[알림] 직전 턴에 당신이 요청한 종료(terminate)가 시스템에 의해 거부되었습니다. "
            f"거부 사유: {gate_rejection_reason}\n"
            "같은 상태로 다시 terminate를 요청하면 또 거부됩니다. 아래 중 하나를 선택하십시오:\n"
            "1) 아직 조회하지 않은 관련 계층의 도구를 호출해 추가 증거를 확보하십시오.\n"
            "2) 더 확인할 관련 계층이 없다면 termination_reason을 no_more_evidence로 바꿔 "
            "지금 증거로 판정하십시오. 단, 거부 사유가 '도구 N종류만'이거나 'audit으로 확인하지 않음'이면 "
            "종료 사유를 바꿔도 다시 거부되니, 사유에 적힌 도구를 먼저 호출하십시오. "
            "임계값을 넘기려고 이미 기록한 사실을 다시 evidence로 "
            "만들거나 confidence_contribution을 부풀리지 마십시오 (같은 raw_ref를 다시 인용한 "
            "evidence는 시스템이 신뢰도에 반영하지 않습니다)."
        )

    if force_terminate:
        payload["forced_termination"] = True
        instruction += (
            "\n\n[중요] 최대 조사 횟수에 도달했습니다. 이번 턴에는 도구를 호출할 수 없습니다. "
            "next_action을 반드시 \"terminate\"로 설정하고, 지금까지 확보한 증거만으로 "
            "final_verdict를 반드시 채우십시오 (null 금지)."
        )

    return instruction + "\n\n" + json.dumps(payload, ensure_ascii=False, indent=2)
