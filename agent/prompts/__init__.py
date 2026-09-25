"""조사 루프용 LLM 프롬프트 조립.

역할
  시스템 프롬프트: investigation.yaml(역할·판정 원칙·출력 형식·규칙) + 등록된 도구 설명을 이어 붙인다.
  사용자 프롬프트: 지금까지의 조사 상태(AgentState)를 JSON으로 만들고, 코드가 계산한 조회 구간
  (auth_lookback_window, query_windows)과 직전 종료 거부 사유·강제 종료 지시를 덧붙인다.

누가 부르나
  [21] agent/gemini_client.py / claude_client.py reason()  → build_system_prompt(), build_user_prompt()

무엇을 부르나
  investigation.yaml (같은 폴더)                 프롬프트 본문 — 판정 원칙을 바꿀 때는 이 파일을 고친다
  agent/tools/registry.py schema_text()          도구 설명
  agent/provenance.py strip_trace_fields()       LLM에게 보여줄 사본에서 추적용 필드 제거

프롬프트 "내용"(yaml)과 "조립 로직"(이 파일)을 나눠 두어 원칙을 고칠 때 코드를 건드리지 않게 했다.
seed 생성 프롬프트는 1차 탐지 연동 뒤 빠질 예정이라 agent/seed_prompts.py에 따로 둔다.
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
# 1~2시간만 조회하는 경우가 반복돼(재현성 테스트), 코드가 계산한 값을 그대로 준다.
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
    return [_fmt(at - AUTH_LOOKBACK_BEFORE), _fmt(at + AUTH_LOOKBACK_AFTER)]


# 계층별 첫 조회 구간 (seed 사건 구간 기준, 앞/뒤). auth만 정하고 나머지를 LLM에게 맡겼더니 같은 seed에서도
# audit을 24시간 무필터로 보거나(EC2 3728건) web을 seed 구간 11초만 보는 등 실행마다 달랐다.
# web: 같은 IP의 앞뒤 요청까지 봐야 반복 횟수(원칙 9)가 사건 경계에 덜 흔들린다.
# audit: 공격 뒤 후속 행위(명령 실행)를 보려고 뒤쪽을 더 넓힌다.
# network: 시스템 사전 조회(loop.NETWORK_PRECHECK_PAD)와 같은 구간.
LAYER_WINDOW_PADS = {
    "web": (timedelta(hours=1), timedelta(hours=1)),
    "audit": (timedelta(minutes=30), timedelta(hours=1)),
    "network": (timedelta(minutes=30), timedelta(minutes=30)),
}


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def layer_query_windows(seed: Dict[str, Any]) -> Optional[Dict[str, list]]:
    """seed 사건 구간(window, 없으면 trigger_time 한 점)으로 계층별 첫 조회 구간을 계산한다.

    auth는 원칙 7 Q1용 24시간 구간(auth_lookback_window)이고, src_ip가 있을 때만 준다.
    """
    window = seed.get("window") or []
    anchor = seed.get("trigger_time") or seed.get("timestamp")
    start = window[0] if len(window) == 2 else anchor
    end = window[1] if len(window) == 2 else anchor
    if not start or not end:
        return None
    try:
        start_dt = parse_iso(start).astimezone(timezone.utc)
        end_dt = parse_iso(end).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None
    windows = {layer: [_fmt(start_dt - before), _fmt(end_dt + after)]
               for layer, (before, after) in LAYER_WINDOW_PADS.items()}
    lookback = auth_lookback_window(seed)
    if lookback:
        windows["auth"] = lookback
    return windows

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


# [21] ← gemini_client.py / claude_client.py reason()에서 매 턴 호출 — 원칙·도구 목록·출력 형식
def build_system_prompt(tool_registry: Any) -> str:
    return SYSTEM_PROMPT_TEMPLATE.replace("{tool_schema}", tool_registry.schema_text())


# [21] ← reason()에서 매 턴 호출 — 현재 조사 상태 + 코드가 계산한 조회 구간 + 직전 거부 사유
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
    windows = layer_query_windows(state.seed)
    if windows:
        payload["query_windows"] = windows

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
