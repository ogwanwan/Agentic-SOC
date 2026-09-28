"""조사 결과 — 최종 investigation_result JSON 조립.

역할
  build_investigation_result(): 조사 상태(AgentState)와 최종 판정으로 결과 JSON을 만든다
    (판정, 증거 체인, 반박 증거, 타임라인, 호출한 도구, 신뢰도 변화, 원본 참조·검증 상태, 통계).
  main.py가 이 JSON을 results/investigation_agent/에 저장한다. 사람이 읽는 텍스트 보고서는
  만들지 않는다 — 최종 보고서는 이후 단계(ATT&CK 매핑·대응 권고) 결과까지 합쳐 따로 만든다.

누가 부르나
  [41] agent/loop.py InvestigationAgent.run()  → build_investigation_result()

무엇을 부르나
  agent/provenance.py provenance_report()      원본 참조 검증 결과(passed/incomplete/unavailable)
  agent/provenance.py evidence_ref_sources()   증거별 출처(supporting_tool_calls, seed_only_raw_refs)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .provenance import evidence_ref_sources, provenance_report, references


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# [41] ← agent/loop.py run() 끝에서 호출. 반환한 JSON이 [42]~[44]를 거쳐 main.py로 간다.
def build_investigation_result(
    state: Any,
    termination_reason: str,
    final_verdict: Optional[Dict[str, Any]],
    investigation_id: Optional[str] = None,
) -> Dict[str, Any]:
    investigation_id = investigation_id or (
        f"INV-{state.incident_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001"
    )

    leading_hyp = max(state.hypotheses.values(), key=lambda h: h.confidence, default=None)
    seed_refs = references(state.seed, seed=True)

    def ref_sources(e: Any) -> Dict[str, Any]:
        return evidence_ref_sources(e, state.tool_calls, seed_refs)

    evidence_chain = [
        {
            "sequence": e.sequence,
            "time": e.time,
            "layer": e.layer,
            "event_type": e.event_type,
            "description": e.description,
            "evidence_id": e.evidence_id,
            "supporting_hypothesis": e.supporting_hypothesis,
            "confidence_contribution": e.confidence_contribution,
            "source_log": e.source_log,
            "raw_ref": e.raw_refs[0] if e.raw_refs else None,
            "raw_refs": list(e.raw_refs),
            "empty_result_call": e.empty_result_call,
            **ref_sources(e),
        }
        for e in state.evidence
    ]

    contradicting_evidence = [
        {
            "sequence": e.sequence,
            "layer": e.layer,
            "evidence_id": e.evidence_id,
            "description": e.description,
            "confidence_reduction": abs(e.confidence_contribution),
            "explanation": e.description,
            "source_log": e.source_log,
            "raw_ref": e.raw_refs[0] if e.raw_refs else None,
            "raw_refs": list(e.raw_refs),
            "empty_result_call": e.empty_result_call,
            **ref_sources(e),
        }
        for e in state.contradicting_evidence
    ]

    tools_called = [
        {
            "sequence": t.sequence,
            "tool_name": t.tool_name,
            "input": t.input,
            "result_count": t.result_count,
            "result_summary": t.result_summary,
            "raw_refs": list(t.raw_refs),
            "queried_layers": list(t.queried_layers),
            **({"error": t.error} if not t.success else {}),
        }
        for t in state.tool_calls
    ]

    confidence_progression = [
        {"stage": c.stage, "confidence": c.confidence, "reason": c.reason}
        for c in state.confidence_progression
    ]

    initial_confidence = (
        state.confidence_progression[0].confidence if state.confidence_progression else 0.0
    )

    verdict = final_verdict or {
        "verdict": "INCONCLUSIVE",
        "confidence": round(state.current_confidence, 3),
        "severity": "UNKNOWN",
        "attack_type": leading_hyp.title if leading_hyp else "unknown",
        "affected_systems": [],
        "summary": "증거가 충분하지 않아 결론을 내리지 못했습니다.",
        "reasoning": "final_verdict가 제공되지 않아 시스템 기본값으로 대체되었습니다.",
    }
    verdict.setdefault(
        "summary",
        f"{verdict.get('attack_type', '알 수 없는 공격')} 가능성이 있으며, "
        f"신뢰도는 {verdict.get('confidence', state.current_confidence):.2f}입니다.",
    )
    # LLM 응답에 reasoning이 빠져 있는 극단적인 경우(폴백도 아니고
    # LLM이 스키마를 안 지킨 경우)를 방어. loop.py의 _derive_fallback_verdict()는
    # 이미 reasoning을 채워서 넘기므로 이 setdefault는 사실상 안전망 역할이다.
    verdict.setdefault("reasoning", "판단 근거가 명시적으로 제공되지 않았습니다.")

    return {
        "incident_id": state.incident_id,
        # 사건과 이후 단계(ATT&CK 매핑·최종 보고서)를 잇는 키. incident_id는 1차 탐지 사건이 커지면
        # 바뀌므로 안정 키를 최상위에 둔다(없는 사건 파일은 null → 연결은 incident_id로).
        "incident_key": state.seed.get("incident_key"),
        # 어느 판의 사건을 조사했는지 — 사건이 커져 재조사할 때 이전 결과와 구분한다
        "incident_snapshot": {
            "incident_id": state.incident_id,
            "member_count": (state.seed.get("detection") or {}).get("member_count"),
            "updated_at": state.seed.get("updated_at"),
        },
        "investigation_id": investigation_id,
        "investigation_status": "COMPLETE",
        "timestamp": _now_iso(),
        "initial_seed": state.seed,
        "raw_refs": list(state.raw_refs),
        "raw_ref_locations": dict(state.raw_ref_locations),
        "provenance": provenance_report(state),
        "hypothesis": {
            "title": leading_hyp.title if leading_hyp else None,
            "description": leading_hyp.description if leading_hyp else None,
            "confidence_initial": initial_confidence,
        },
        "evidence_chain": evidence_chain,
        "contradicting_evidence": contradicting_evidence,
        "attack_timeline": getattr(state, "attack_timeline", []),
        "confidence_progression": confidence_progression,
        "final_verdict": verdict,
        "tools_called": tools_called,
        "statistics": {
            "tool_calls_count": len(state.tool_calls),
            "tool_calls_max": None,  # InvestigationAgent.run()에서 채워 넣음
            "confidence_increase": round(state.current_confidence - initial_confidence, 3),
            # 증거 누적 신뢰도(루프가 계산). final_verdict.confidence는 LLM이 적은
            # "판정에 대한 확신도"라 둘이 다를 수 있다 — 리포트에서 따로 보여준다.
            "investigation_confidence": round(state.current_confidence, 3),
            "evidence_count": len(state.evidence),
            "contradicting_evidence_count": len(state.contradicting_evidence),
            "termination_reason": termination_reason,
        },
        "remaining_unknowns": state.unknowns,
        "investigation_notes": state.notes,
    }
