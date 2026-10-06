"""공용 계약 — decide.py(담당 A)가 만들고 llm.py/render.py(담당 B)가 채우는 자료형.

설계 문서 11절 그대로. `reason`/`summary`/`analyst_note`는 담당 A가 None으로 둔 채
넘기고 담당 B의 llm.py가 채운다. 여기서 값을 추측해 넣지 않는다.

2026-10-04 담당 B 동기화: render.py/llm.py/cli.py가 실제로 쓰는 필드·메서드가 없어서
생기는 AttributeError를 막기 위해 아래를 추가했다(내용은 바꾸지 않음, A와 상의 후 적용):
  - ResponsePlan.host / occurred_at / attack_type / evidence_refs / status_reason
  - Action.effective_reason() / Action.to_dict()
  - ResponsePlan.action_ids() / has_actions() / to_dict()

2026-10-06 산출물 확정(팀 합의): 대응권고의 고유 산출물을 조치 단위로 못박았다.
  대시보드가 이미 보여 주는 판정 요약·타임라인·증거·공격 유형과 겹치지 않는, 대응권고만
  만들 수 있는 값은 "조치"와 그 조치에 딸린 다음 일곱 칸이다.
    Action.effective_reason()  왜 이 조치인가    (LLM 문장 / 실패 시 카탈로그 기본 문장)
    Action.rollback             역가능 방법        (카탈로그 고정값)
    Action.command_hint         실제 명령어        (카탈로그 고정값)
    Action.autonomy(+근거)      자동화 등급과 근거 (카탈로그 고정값 + 하향 사유)
    Action.priority             우선순위           (카탈로그 고정값, 1 먼저 → 3 나중)
    Action.side_effects         부작용·영향 범위   (카탈로그 고정값)
    Action.verification         검증 방법          (카탈로그 고정값)
  rollback·side_effects·verification은 **LLM에게 물어보지 않는다**. 되돌리는 방법을
  모델이 지어내면 그대로 운영 사고가 된다(설계 원칙: 코드가 정하고 LLM은 문장만 쓴다).

  ResponsePlan에는 ATT&CK 매핑 근거를 그대로 싣는다 — techniques(기법별 증거 id)와
  attack_data(어떤 ATT&CK 데이터로 매핑했는지). 권고문이 "무슨 근거로 이 기법인가"에
  답할 수 있어야 하고, 대시보드도 같은 값을 쓴다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# ResponsePlan.has_actions()가 쓰는, 조치가 실리는 상태 목록 (models.py와 동일)
_STATUSES_WITH_ACTIONS = ("recommended", "recommended_generic")

# MITRE ATT&CK STIX 원본 주소 틀 — attack_mapping이 기록한 attack_version으로 완성한다.
# 버전 문자열을 코드에 박지 않는다(매핑 단계 manifest.json이 유일한 출처).
ATTACK_STIX_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)


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

    # ↓ 2026-10-06 산출물 확정으로 추가 — 전부 카탈로그가 정한 고정값(LLM이 채우지 않는다)
    priority: int = 2                   # 1 먼저 · 2 보통 · 3 나중 (같은 묶음 안의 실행 순서)
    rollback: str = ""                  # 역가능 방법("되돌릴 수 없음"이면 그렇게 적힌다)
    side_effects: str = ""              # 부작용·영향 범위
    verification: str = ""              # 조치가 제대로 됐는지 확인하는 방법
    autonomy_reason: str = ""           # 이 자율성 등급인 이유(+ 하향됐으면 그 사유까지)
    # ↓ 위 칸 중 LLM이 쓴 것의 이름 목록. 비어 있으면 전부 카탈로그 문장이라는 뜻이다.
    # llm.py가 칸별 검증을 통과한 것만 채운다 — 대시보드가 "LLM 작성" 표시에 쓴다.
    llm_fields: List[str] = field(default_factory=list)
    # ↓ 2026-10-06 추가 — LLM 조치 선택 단계 산출물. 어느 카탈로그 템플릿에서 왔는지(순서
    # 정리·선행조건 검사에 쓴다)와, 이 조치가 사람 승인 없이는 실행되지 않는지(catalog.
    # requires_approval()로 유도. 지금은 항상 True).
    template_id: Optional[str] = None
    requires_approval: bool = True

    def effective_reason(self) -> str:
        """권고문에 실제로 실릴 근거 문장. LLM이 못 채웠으면 카탈로그의 기본 문장."""
        return (self.reason or "").strip() or self.default_reason

    def priority_label(self) -> str:
        """권고문·대시보드에 띄우는 우선순위 라벨 — P1(먼저) ~ P3(나중)."""
        return f"P{self.priority}"

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

    # ↓ 2026-10-06 추가 — ATT&CK 매핑 근거를 권고문·프롬프트·대시보드가 같은 값으로 쓴다
    # techniques: attack_mapping.techniques[] 그대로(technique_id·name·tactic·evidence_ids)
    techniques: List[Dict[str, Any]] = field(default_factory=list)
    # attack_data: 어떤 ATT&CK 데이터로 매핑했는지 — {version, source_url, mapping_method}
    attack_data: Dict[str, Any] = field(default_factory=dict)

    # ↓ 2026-10-06 추가 — 조치 "선택"을 누가 했는지의 기록(설계서 신규: LLM이 조치 목록을
    # 짜고 code가 검문). run_log·대시보드가 "LLM이 뭘 빼고 뭘 더했는지"를 보는 유일한 근거다.
    #   mode               "llm_selected" | "fallback"(선택 단계 자체가 안 되거나 실패)
    #   candidate_ids       이 사건에서 애초에 고를 수 있었던 전체 후보
    #   selected_ids        최종적으로 조치가 된 id
    #   llm_chosen_ids      LLM이 직접 고른 id(코드가 더하기 전)
    #   added_mandatory     LLM이 빠뜨렸는데 code가 최소 필수라서 추가한 id
    #   added_prerequisite  LLM이 고른 조치의 선행조건이라서 code가 추가한 id
    #   capped              한도를 넘어 code가 뺀 id
    #   unknown_ids_dropped LLM이 적었지만 후보에 없어서 버린 id
    #   llm_rejected        LLM이 "왜 안 골랐는지" 적어 보낸 목록 ({action_id, why})
    selection_meta: Dict[str, Any] = field(default_factory=dict)

    def action_ids(self) -> List[str]:
        return [a.action_id for a in self.actions]

    def has_actions(self) -> bool:
        return self.response_status in _STATUSES_WITH_ACTIONS and bool(self.actions)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["actions"] = [a.to_dict() if hasattr(a, "to_dict") else a for a in self.actions]
        return data


def attack_stix_url(version: Optional[str]) -> Optional[str]:
    """attack_version("19.2") → 그 버전의 STIX 원본 주소. 버전을 모르면 None."""
    text = (version or "").strip()
    return ATTACK_STIX_URL_TEMPLATE.format(version=text) if text else None


if __name__ == "__main__":  # 자체 점검: python llm/respond/schema.py
    plan = ResponsePlan(
        incident_id="INC-TEST", incident_key=None, investigation_id="INV-TEST",
        response_status="recommended", verdict="THREAT_CONFIRMED", severity="HIGH",
        verdict_confidence=0.89, investigation_confidence=0.92,
        provenance_status="passed", mapping_status="mapped",
    )
    assert plan.actions == [] and plan.summary is None
    assert plan.host is None and plan.evidence_refs == [] and plan.has_actions() is False
    assert plan.techniques == [] and plan.attack_data == {}
    action = Action(
        action_id="act_01", title="웹셸 파일 격리", target="/var/www/html/shell.php",
        target_source="seed_detail", technique_id="T1505.003", technique_name="Web Shell",
        tactic_name="Persistence", reversible=True, risk="LOW", autonomy="L2",
        autonomy_downgraded_from=None, category="immediate", command_hint=None,
    )
    assert action.reason is None and action.evidence_ids == []
    assert action.effective_reason() == ""
    # 2026-10-06 추가된 산출물 칸의 기본값
    assert action.priority == 2 and action.priority_label() == "P2"
    assert action.rollback == "" and action.side_effects == "" and action.verification == ""
    assert action.autonomy_reason == "" and action.llm_fields == []
    # 2026-10-06 추가 칸의 기본값
    assert action.template_id is None and action.requires_approval is True
    plan.actions = [action]
    assert plan.action_ids() == ["act_01"] and plan.has_actions() is True
    dumped = plan.to_dict()
    assert dumped["actions"][0]["action_id"] == "act_01"
    # 대시보드가 읽는 JSON에 새 칸이 모두 들어가야 한다
    for key in ("priority", "rollback", "side_effects", "verification", "autonomy_reason",
                 "llm_fields"):
        assert key in dumped["actions"][0], key
    assert "techniques" in dumped and "attack_data" in dumped
    assert "selection_meta" in dumped and dumped["selection_meta"] == {}
    assert "template_id" in dumped["actions"][0] and "requires_approval" in dumped["actions"][0]

    assert attack_stix_url("19.2").endswith("enterprise-attack-19.2.json")
    assert attack_stix_url(None) is None and attack_stix_url("  ") is None
    print("ok")
