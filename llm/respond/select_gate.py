"""LLM 조치 "선택" 단계의 검문소 — 신규 설계(2026-10-06): LLM이 조치 목록을 짜고
code가 검문·안전망·순서 정리를 맡는다.

역할 분리
  select_gate.py (여기)  LLM이 돌려준 JSON의 **모양**만 본다 — 후보에 있는 id인가.
  decide.py             최소 필수 조치 보장(mandatory)·선행조건(requires)·캡·순서 정리.
  llm.py                조치가 정해진 뒤 7칸(reason·command·...) 작성 — 안 바뀐다.

"구조가 깨졌다"(JSON이 아님·actions 배열이 없음·문자열이 아닌 항목)는 전체 재시도감이고,
"모르는 id를 적었다"는 흔한 실수라 그 항목만 버리고 넘어간다 — 전체를 버리면 LLM이
정확히 기억 못 하는 id 하나 때문에 선택 전체가 날아간다.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from respond.decide import CandidatePool

MAX_WHY_CHARS = 200


class SelectionReport:
    """선택 단계에서 무슨 일이 있었는지 — run_log.jsonl에 그대로 기록된다."""

    def __init__(self) -> None:
        self.llm_called: bool = False
        self.llm_model: Optional[str] = None
        self.structurally_valid: bool = False
        self.retry_used: bool = False
        self.fallback_reason: Optional[str] = None
        self.unknown_ids: List[str] = []
        self.llm_rejected: List[Dict[str, str]] = []
        self.notes: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "llm_called": self.llm_called,
            "llm_model": self.llm_model,
            "structurally_valid": self.structurally_valid,
            "retry_used": self.retry_used,
            "fallback_reason": self.fallback_reason,
            "unknown_ids": self.unknown_ids,
            "llm_rejected": self.llm_rejected,
            "notes": self.notes,
        }


def validate_payload(
    pool: CandidatePool, payload: Any, report: SelectionReport,
) -> Optional[List[str]]:
    """구조 검사. 통과하면 (후보에 있는 id만 남긴) 선택 목록, 구조 자체가 틀렸으면 None.

    돌려준 목록이 비어 있어도(actions: []) 구조는 정상이다 — "이번 사건엔 조치가
    필요 없다"는 LLM의 판단일 수 있다. decide.py의 mandatory merge가 최소 필수
    조치는 그래도 넣어 주므로, 빈 선택을 특별히 막을 필요가 없다.
    """
    if not isinstance(payload, dict):
        report.fallback_reason = "선택 응답이 JSON 객체가 아님"
        return None

    raw_actions = payload.get("actions")
    if not isinstance(raw_actions, list):
        report.fallback_reason = "선택 응답에 actions 배열이 없음"
        return None
    if not all(isinstance(x, str) for x in raw_actions):
        report.fallback_reason = "actions 배열에 문자열이 아닌 항목이 있음"
        return None

    known = {c.template.template_id for c in pool.candidates}
    selected: List[str] = []
    seen: set = set()
    for action_id in raw_actions:
        if action_id in seen:
            continue
        seen.add(action_id)
        if action_id in known:
            selected.append(action_id)
        else:
            report.unknown_ids.append(action_id)

    rejected = payload.get("rejected")
    if isinstance(rejected, list):
        for item in rejected:
            if isinstance(item, dict) and isinstance(item.get("action_id"), str):
                why = str(item.get("why") or "")[:MAX_WHY_CHARS]
                report.llm_rejected.append({"action_id": item["action_id"], "why": why})

    report.structurally_valid = True
    return selected


if __name__ == "__main__":  # 자체 점검: python llm/respond/select_gate.py
    from respond.catalog import ActionTemplate
    from respond.decide import Candidate

    t1 = ActionTemplate("A", None, True, "LOW", "L2", "immediate", None, "x",
                         template_id="SYN_A", priority=1, rollback="x", side_effects="x",
                         verification="x", autonomy_reason="L2")
    t2 = ActionTemplate("B", None, True, "LOW", "L2", "immediate", None, "x",
                         template_id="SYN_B", priority=2, rollback="x", side_effects="x",
                         verification="x", autonomy_reason="L2")
    pool = CandidatePool(candidates=(Candidate(t1, None), Candidate(t2, None)),
                          mandatory_ids=frozenset())

    # 정상 — 후보 중 일부만 골라도 된다
    r1 = SelectionReport()
    assert validate_payload(pool, {"actions": ["SYN_A"]}, r1) == ["SYN_A"]
    assert r1.structurally_valid and r1.unknown_ids == []

    # 모르는 id는 그 항목만 버리고, 나머지는 받아들인다(전체 거절 아님)
    r2 = SelectionReport()
    assert validate_payload(pool, {"actions": ["SYN_A", "없는_id"]}, r2) == ["SYN_A"]
    assert r2.unknown_ids == ["없는_id"] and r2.structurally_valid

    # 중복은 한 번만
    r3 = SelectionReport()
    assert validate_payload(pool, {"actions": ["SYN_A", "SYN_A"]}, r3) == ["SYN_A"]

    # rejected는 기록만 한다(선택 로직에 영향 없음)
    r4 = SelectionReport()
    out = validate_payload(pool, {"actions": ["SYN_A"],
                                   "rejected": [{"action_id": "SYN_B", "why": "무관함"}]}, r4)
    assert out == ["SYN_A"] and r4.llm_rejected == [{"action_id": "SYN_B", "why": "무관함"}]

    # 빈 선택도 구조적으로는 정상
    r5 = SelectionReport()
    assert validate_payload(pool, {"actions": []}, r5) == [] and r5.structurally_valid

    # 구조가 깨지면 None — 전체 재시도/폴백 대상
    for bad in (None, "x", [], {"actions": "x"}, {"actions": [1, 2]}, {}):
        r = SelectionReport()
        assert validate_payload(pool, bad, r) is None, bad
        assert not r.structurally_valid

    print("ok")
