"""공용 계약 — decide.py(담당 A)가 만들고 llm.py/render.py(담당 B)가 채우는 자료형.

설계 문서 11절 그대로. `reason`/`summary`/`analyst_note`는 담당 A가 None으로 둔 채
넘기고 담당 B의 llm.py가 채운다. 여기서 값을 추측해 넣지 않는다.

2026-10-04 담당 B 동기화: render.py/llm.py/cli.py가 실제로 쓰는 필드·메서드가 없어서
생기는 AttributeError를 막기 위해 아래를 추가했다(내용은 바꾸지 않음, A와 상의 후 적용):
  - ResponsePlan.host / occurred_at / attack_type / evidence_refs / status_reason
  - Action.effective_reason() / Action.to_dict()
  - ResponsePlan.action_ids() / has_actions() / to_dict()
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# ResponsePlan.has_actions()가 쓰는, 조치가 실리는 상태 목록 (models.py와 동일)
_STATUSES_WITH_ACTIONS = ("recommended", "recommended_generic")


@dataclass
class Action:
    action_id: str
    title: str
    target: str
    target_source: str          # "seed_detail" | "tool_input" | "seed_src_ip" | "none"
    technique_id: Optional[str]
    technique_name: Optional[str]
    tactic_name: Optional[str]
    reversible: bool
    risk: str                   # "LOW" | "MED" | "HIGH"
    autonomy: str                # "L0" | "L1" | "L2"
    autonomy_downgraded_from: Optional[str]
    category: str                # "immediate" | "verify_needed"
    command_hint: Optional[str]
    evidence_ids: list = field(default_factory=list)
    default_reason: str = ""
    reason: Optional[str] = None        # 담당 B가 채움

    def effective_reason(self) -> str:
        """권고문에 실제로 실릴 근거 문장. LLM이 못 채웠으면 카탈로그의 기본 문장."""
        return (self.reason or "").strip() or self.default_reason

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResponsePlan:
    incident_id: str
    incident_key: Optional[str]
    investigation_id: Optional[str]
    response_status: str         # recommended | recommended_generic | not_applicable
                                  # | deferred | skipped | error
    verdict: str
    severity: str
    verdict_confidence: float
    investigation_confidence: float
    provenance_status: str
    mapping_status: str
    kill_chain: list = field(default_factory=list)
    actions: list = field(default_factory=list)       # list[Action]
    warnings: list = field(default_factory=list)
    summary: Optional[str] = None       # 담당 B가 채움
    analyst_note: Optional[str] = None  # 담당 B가 채움
    remaining_unknowns: list = field(default_factory=list)
    tuning_hint: Optional[str] = None
    errors: list = field(default_factory=list)   # response_status == "error"일 때 사유

    # ↓ 2026-10-04 추가 — render.py 머리말([호스트]/[발생]/[공격 유형])과
    # [근거 추적] 구역, [조사 미완료]/[처리 오류] 사유 표시에 쓴다.
    host: Optional[str] = None                 # contract.initial_seed.get("host")
    occurred_at: Optional[str] = None           # contract.initial_seed.get("trigger_time")
    attack_type: Optional[str] = None           # contract.verdict.attack_type
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)  # cli.py의 evidence_chain(report)
    status_reason: Optional[str] = None         # gate.reason (skipped/deferred/error 사유)

    def action_ids(self) -> List[str]:
        return [a.action_id for a in self.actions]

    def has_actions(self) -> bool:
        return self.response_status in _STATUSES_WITH_ACTIONS and bool(self.actions)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["actions"] = [a.to_dict() if hasattr(a, "to_dict") else a for a in self.actions]
        return data


if __name__ == "__main__":  # 자체 점검: python llm/respond/schema.py
    plan = ResponsePlan(
        incident_id="INC-TEST", incident_key=None, investigation_id="INV-TEST",
        response_status="recommended", verdict="THREAT_CONFIRMED", severity="HIGH",
        verdict_confidence=0.89, investigation_confidence=0.92,
        provenance_status="passed", mapping_status="mapped",
    )
    assert plan.actions == [] and plan.summary is None
    assert plan.host is None and plan.evidence_refs == [] and plan.has_actions() is False
    action = Action(
        action_id="act_01", title="웹셸 파일 격리", target="/var/www/html/shell.php",
        target_source="seed_detail", technique_id="T1505.003", technique_name="Web Shell",
        tactic_name="Persistence", reversible=True, risk="LOW", autonomy="L2",
        autonomy_downgraded_from=None, category="immediate", command_hint=None,
    )
    assert action.reason is None and action.evidence_ids == []
    assert action.effective_reason() == ""
    plan.actions = [action]
    assert plan.action_ids() == ["act_01"] and plan.has_actions() is True
    assert plan.to_dict()["actions"][0]["action_id"] == "act_01"
    print("ok")
