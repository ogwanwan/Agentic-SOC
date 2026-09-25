"""조사 결과 보고서 — 최종 investigation_result JSON 조립과 사람이 읽는 텍스트 보고서.

역할
  build_investigation_result(): 조사 상태(AgentState)와 최종 판정으로 결과 JSON을 만든다
    (판정, 증거 체인, 반박 증거, 타임라인, 호출한 도구, 신뢰도 변화, 원본 참조·검증 상태, 통계).
  format_text_report(): 그 JSON을 콘솔·대시보드에 붙일 텍스트로 바꾼다. 증거 설명 아래에는
    [원본 N줄]만 적고, 원본 위치는 맨 아래 Raw References에 범위로 묶어 보여 준다(compact_refs).

누가 부르나
  [41] agent/loop.py InvestigationAgent.run()  → build_investigation_result()
  [45] main.py main()                          → format_text_report()

무엇을 부르나
  agent/provenance.py provenance_report()      원본 참조 검증 결과(passed/incomplete/unavailable)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .provenance import provenance_report


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


# ----------------------------------------------------------------------
# 사람이 읽는 텍스트 리포트 (대시보드/디스코드 등에 그대로 출력하는 용도)
# ----------------------------------------------------------------------
_SOURCE_LABELS = (
    ("suricata", "Suricata"),
    ("apache", "Apache"),
    ("nginx", "Nginx"),
    ("auth", "Auth"),
    ("audit", "Audit"),
    ("eve.json", "Suricata"),
)


def _source_label(evidence: Dict[str, Any]) -> str:
    """source_log 문자열에서 [Suricata]/[Apache]/[Auth]/[Audit] 같은 표시 라벨을 뽑는다.
    매칭되는 키워드가 없으면 layer 값을 그대로 대문자화해서 사용한다.
    """
    source_log = (evidence.get("source_log") or "").lower()
    for keyword, label in _SOURCE_LABELS:
        if keyword in source_log:
            return label
    return (evidence.get("layer") or "unknown").capitalize()


def _hhmm(time_str: Optional[str]) -> str:
    """'2026-09-09T10:05:45Z' -> '10:05'. 파싱 실패 시 원본을 그대로 반환한다."""
    if not time_str:
        return "--:--"
    try:
        cleaned = time_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).strftime("%H:%M")
    except ValueError:
        # 이미 'HH:MM' 형태 등 ISO가 아닌 경우 그대로 사용
        return time_str


# [45] ← main.py에서 결과 JSON마다 호출
def format_text_report(result: Dict[str, Any]) -> str:
    """investigation_result(JSON)를 대시보드/Discord 등에 바로 붙여넣을 텍스트 리포트로 변환한다."""
    lines = []
    lines.append("INVESTIGATION RESULT")
    lines.append("━" * 28)
    lines.append(f"Incident {result['incident_id']}")
    lines.append("")

    lines.append("Initial Hypothesis")
    lines.append(result["hypothesis"].get("title") or "(가설 없음)")
    lines.append("")

    # 지지/반박 증거를 시간(sequence) 순으로 합쳐서 E1, E2... 로 번호를 매긴다.
    all_evidence = sorted(
        result["evidence_chain"] + result["contradicting_evidence"],
        key=lambda e: e.get("sequence", 0),
    )
    # 증거마다 원본 줄 번호 수십 개를 바로 아래 찍으니 읽기 힘들어, Findings에는
    # 줄 수만 적고 원본 위치는 맨 아래 Raw References에 범위로 압축해 모았다(전체 목록은 JSON).
    if all_evidence:
        lines.append("Investigation Findings")
        for ev in all_evidence:
            label = _source_label(ev)
            tag = " (반박)" if ev in result["contradicting_evidence"] else ""
            count = f" [원본 {len(ev['raw_refs'])}줄]" if ev.get("raw_refs") else ""
            lines.append(f"E{ev.get('sequence', '?')} [{label}]{tag} {ev['description']}{count}")
        lines.append("")

    timeline = result.get("attack_timeline") or []
    if timeline:
        lines.append("Timeline")
        for t in timeline:
            lines.append(f"{_hhmm(t.get('time'))} {t.get('event', '')}")
        lines.append("")

    verdict = result["final_verdict"]
    lines.append("Provisional Conclusion")
    lines.append(f"{verdict.get('verdict', 'UNKNOWN')} (severity {verdict.get('severity', 'UNKNOWN')}) — "
                 f"{verdict.get('attack_type', '')}")
    lines.append(verdict.get("summary", ""))
    lines.append("")

    lines.append(f"Supporting Evidence {len(result['evidence_chain'])}")
    lines.append(f"Contradicting Evidence {len(result['contradicting_evidence'])}")
    unresolved = result.get("remaining_unknowns") or []
    lines.append("Unresolved " + (unresolved[0] if unresolved else "없음"))
    for extra in unresolved[1:]:
        lines.append("           " + extra)
    lines.append("")

    # 예전엔 LLM의 판정 확신도만 "Investigation Confidence"로 찍어, 증거 누적
    # 신뢰도(0.45)와 판정 확신도(0.75)가 섞여 보였다. 둘을 이름을 나눠 함께 보여준다.
    lines.append(f"Verdict Confidence {verdict.get('confidence', 0):.2f} (판정 확신도, LLM 산정)")
    investigation_confidence = result.get("statistics", {}).get("investigation_confidence")
    if investigation_confidence is not None:
        lines.append(f"Investigation Confidence {investigation_confidence:.2f} (증거 누적 신뢰도, 시스템 계산)")
    lines.append("Raw reference validation: " + result.get("provenance", {}).get("status", "unavailable"))

    cited = [ev for ev in all_evidence if ev.get("raw_refs")]
    if cited:
        lines.append("")
        lines.append("Raw References (전체 목록은 JSON의 raw_refs)")
        for ev in cited:
            lines.append(f"E{ev.get('sequence', '?')} {compact_refs(ev['raw_refs'])}")

    return "\n".join(lines)


def compact_refs(refs: List[str], max_items: int = 6, keep_full_upto: int = 10) -> str:
    """참조가 keep_full_upto개 이하면 원문 그대로 나열하고(원본 추적 시 그대로 검색 가능),
    그보다 많으면 ['access.log:343', 'access.log:344', 'access.log:345', 'access.log:348', ...] →
    'access.log:343-345, 348, ...'처럼 파일별로 연속 줄을 범위로 묶는다. 묶음이 max_items를
    넘으면 나머지는 '외 N줄'로 줄인다. 줄 번호 형식이 아닌 참조는 그대로 둔다.
    """
    if len(refs) <= keep_full_upto:
        return ", ".join(refs)
    by_file: Dict[str, List[int]] = {}
    others: List[str] = []
    for ref in refs:
        name, _, line = ref.rpartition(":")
        if name and line.isdigit():
            by_file.setdefault(name, []).append(int(line))
        else:
            others.append(ref)

    parts = []
    for name, numbers in by_file.items():
        numbers = sorted(set(numbers))
        ranges = []
        start = prev = numbers[0]
        for n in numbers[1:] + [None]:
            if n is not None and n == prev + 1:
                prev = n
                continue
            ranges.append((start, prev))
            if n is not None:
                start = prev = n
        shown = [f"{a}-{b}" if a != b else f"{a}" for a, b in ranges[:max_items]]
        hidden = sum(b - a + 1 for a, b in ranges[max_items:])
        text = f"{name}:" + ", ".join(shown)
        if hidden:
            text += f" 외 {hidden}줄"
        parts.append(text)
    return " / ".join(parts + others)
