"""조치 선택 — 설계 문서 6·7절. 카탈로그 + 추출된 엔티티로 ResponsePlan.actions를 채운다.

여기서 만든 Action의 reason, ResponsePlan.summary/analyst_note는 전부 None이다.
그 문장은 담당 B의 llm.py가 채운다 — 여기서는 "뭘 할지"만 정하고 "왜"는 안 쓴다.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from respond.catalog import (  # noqa: E402
    ActionTemplate,
    DEFAULT_FALLBACK_TEMPLATES,
    NO_TARGET_TEMPLATE,
    TECHNIQUE_CATALOG,
    UNCATALOGUED_TECHNIQUE_TEMPLATE,
    fallback_templates_for_rule_name,
    fallback_templates_for_signal_tag,
)
from respond.contract import Contract  # noqa: E402
from respond.entities import Entity, extract_entities, first_of_kind  # noqa: E402
from respond.gate import GateResult  # noqa: E402
from respond.schema import Action, ResponsePlan  # noqa: E402

_DOWNGRADE_WARNING_CODES = ("FALLBACK_VERDICT", "VERDICT_PRINCIPLE_CONFLICT")


def _plan_skeleton(contract: Contract, gate: GateResult) -> ResponsePlan:
    # 2026-10-04 담당 B 동기화: render.py 머리말·사유 표시에 쓰는 필드를 여기서 옮겨 채운다.
    # host/occurred_at은 investigate 쪽 seed 스키마(host, trigger_time)를 그대로 따른다
    # (llm/investigate/agent/incident_input.py 참고). 키가 다르면 이 두 줄만 고치면 된다.
    return ResponsePlan(
        incident_id=contract.incident_id,
        incident_key=contract.incident_key,
        investigation_id=contract.investigation_id,
        response_status=gate.response_status,
        verdict=contract.verdict.verdict,
        severity=contract.verdict.severity,
        verdict_confidence=contract.verdict.confidence,
        investigation_confidence=contract.investigation_confidence,
        provenance_status=contract.provenance_status,
        mapping_status=contract.mapping.mapping_status,
        kill_chain=[dict(step) for step in contract.mapping.kill_chain],
        warnings=[dict(w) for w in contract.mapping.warnings],
        remaining_unknowns=list(contract.remaining_unknowns),
        host=contract.initial_seed.get("host"),
        occurred_at=contract.initial_seed.get("trigger_time"),
        attack_type=contract.verdict.attack_type or None,
        status_reason=gate.reason,
    )


def _resolve_entity(template: ActionTemplate, entities: tuple) -> Optional[Entity]:
    if template.entity_kind is None:
        return None
    return first_of_kind(entities, template.entity_kind)


def _build_action(
    template: ActionTemplate, entity: Optional[Entity], index: int, *,
    technique_id: Optional[str] = None, technique_name: Optional[str] = None,
    tactic_name: Optional[str] = None, evidence_ids: tuple = (),
) -> Action:
    target = entity.value if entity else ""
    target_source = entity.source if entity else "none"
    command_hint = (
        template.command_template.format(target=target)
        if template.command_template and entity else None
    )
    return Action(
        action_id=f"act_{index:02d}",
        title=template.title,
        target=target,
        target_source=target_source,
        technique_id=technique_id,
        technique_name=technique_name,
        tactic_name=tactic_name,
        reversible=template.reversible,
        risk=template.risk,
        autonomy=template.autonomy,
        autonomy_downgraded_from=None,
        category=template.category,
        command_hint=command_hint,
        evidence_ids=list(evidence_ids),
        default_reason=template.default_reason,
    )


def _apply_templates(templates, entities: tuple, actions: list, seen: set, index: int, **meta) -> int:
    """대상이 필요한데 없으면 건너뛰고(5-4절), (제목, 대상)이 중복이면 건너뛴다."""
    for template in templates:
        entity = _resolve_entity(template, entities)
        if template.entity_kind and entity is None:
            continue
        key = (template.title, entity.value if entity else "")
        if key in seen:
            continue
        seen.add(key)
        actions.append(_build_action(template, entity, index, **meta))
        index += 1
    return index


def _ordered_technique_ids(contract: Contract) -> list:
    ids = [step.get("technique_id") for step in contract.mapping.kill_chain if step.get("technique_id")]
    for technique in contract.mapping.techniques:
        tid = technique.get("technique_id")
        if tid and tid not in ids:
            ids.append(tid)
    return list(dict.fromkeys(ids))


def _build_technique_actions(contract: Contract, entities: tuple) -> list:
    actions: list = []
    seen: set = set()
    index = 1
    uncatalogued = False

    for technique_id in _ordered_technique_ids(contract):
        technique = next(
            (t for t in contract.mapping.techniques if t.get("technique_id") == technique_id), None
        )
        if technique is None:
            continue
        templates = TECHNIQUE_CATALOG.get(technique_id)
        if templates is None:
            uncatalogued = True
            continue
        index = _apply_templates(
            templates, entities, actions, seen, index,
            technique_id=technique_id, technique_name=technique.get("technique_name"),
            tactic_name=technique.get("tactic_name"),
            evidence_ids=tuple(technique.get("evidence_ids") or ()),
        )

    if uncatalogued and not actions:
        actions.append(_build_action(UNCATALOGUED_TECHNIQUE_TEMPLATE, None, index))

    return actions


def _signal_tags(contract: Contract) -> tuple:
    detection = contract.initial_seed.get("detection")
    tags = detection.get("signal_tags") if isinstance(detection, dict) else None
    if isinstance(tags, list):
        return tuple(t for t in tags if isinstance(t, str))
    return ()


def _rule_names(contract: Contract) -> list:
    detection = contract.initial_seed.get("detection")
    rules = detection.get("rules") if isinstance(detection, dict) else None
    if not isinstance(rules, list):
        return []
    return [r.get("rule_name") for r in rules if isinstance(r, dict) and r.get("rule_name")]


def _build_fallback_actions(contract: Contract, entities: tuple) -> list:
    actions: list = []
    seen: set = set()
    index = 1

    templates: list = []
    for rule_name in _rule_names(contract):
        templates.extend(fallback_templates_for_rule_name(rule_name))
    for tag in _signal_tags(contract):
        templates.extend(fallback_templates_for_signal_tag(tag))
    if not templates:
        templates = list(DEFAULT_FALLBACK_TEMPLATES)

    index = _apply_templates(templates, entities, actions, seen, index)
    return actions


def _apply_autonomy_downgrade(contract: Contract, actions: list) -> None:
    downgrade = (
        bool(contract.mapping.warning_codes & set(_DOWNGRADE_WARNING_CODES))
        or contract.provenance_status == "incomplete"
    )
    if not downgrade:
        return
    for action in actions:
        if action.autonomy == "L2":
            action.autonomy_downgraded_from = "L2"
            action.autonomy = "L1"


def _renumber(actions: list) -> list:
    ordered = (
        [a for a in actions if a.category == "immediate"]
        + [a for a in actions if a.category == "verify_needed"]
    )
    for position, action in enumerate(ordered, start=1):
        action.action_id = f"act_{position:02d}"
    return ordered


def build_response_plan(contract: Contract, gate: GateResult) -> ResponsePlan:
    plan = _plan_skeleton(contract, gate)

    if gate.response_status == "not_applicable":
        names = list(dict.fromkeys(_rule_names(contract)))
        if names:
            plan.tuning_hint = f"발화 룰 {', '.join(names)} — 임계값·필터 재검토 권장"
        return plan

    if gate.response_status in ("skipped", "deferred"):
        return plan

    if gate.response_status == "error":
        plan.errors.append(gate.reason)
        return plan

    entities = extract_entities(contract)
    if gate.use_technique_catalog:
        actions = _build_technique_actions(contract, entities)
    else:
        actions = _build_fallback_actions(contract, entities)

    if not actions:
        actions = [_build_action(NO_TARGET_TEMPLATE, None, 1)]

    _apply_autonomy_downgrade(contract, actions)
    plan.actions = _renumber(actions)
    return plan


if __name__ == "__main__":  # 자체 점검: python llm/respond/decide.py
    from respond.contract import MappingView, Verdict

    def _contract(**overrides):
        base = dict(
            incident_id="INC-1", incident_key=None, investigation_id="INV-1",
            investigation_status="COMPLETE", provenance_status="passed",
            verdict=Verdict("THREAT_CONFIRMED", 0.89, "HIGH", "웹셸", (), ""),
            investigation_confidence=0.92, remaining_unknowns=(),
            initial_seed={"src_ip": "203.0.113.45"}, tools_called=(),
            mapping=MappingView("mapped", "passed", (
                {"technique_id": "T1505.003", "technique_name": "Web Shell", "tactic_name": "Persistence",
                 "evidence_ids": ["EVID-003"]},
            ), (
                {"step": 1, "technique_id": "T1505.003", "time": "2026-09-14T07:33:20Z"},
            ), ()),
        )
        base.update(overrides)
        return Contract(**base)

    # mapped: T1505.003 → 파일 격리(file_path 필요) + 업로드 경로 차단(url_path 필요) 중
    # initial_seed에 둘 다 없으니 "웹루트 점검"(엔티티 불필요)만 남아야 한다
    plan = build_response_plan(_contract(), GateResult("recommended", "x", True, True))
    assert plan.response_status == "recommended"
    assert [a.title for a in plan.actions] == ["웹루트 내 최근 생성 파일 전수 점검"]
    assert plan.actions[0].reason is None and plan.summary is None

    # 대상(file_path)이 있으면 격리 조치도 생긴다
    seed_with_path = {"src_ip": "203.0.113.45",
                       "detection": {"rules": [{"layer": "system", "detail": {"path": "/var/www/shell.php"}}]}}
    plan2 = build_response_plan(
        _contract(initial_seed=seed_with_path), GateResult("recommended", "x", True, True)
    )
    titles = [a.title for a in plan2.actions]
    assert "웹셸 파일 격리" in titles
    quarantine = next(a for a in plan2.actions if a.title == "웹셸 파일 격리")
    assert quarantine.target == "/var/www/shell.php" and quarantine.technique_id == "T1505.003"

    # recommended_generic: 기법 없이 폴백 카탈로그(rule_name 패턴)로
    generic_contract = _contract(
        mapping=MappingView("no_techniques_matched", "passed", (), (), ()),
        initial_seed={"src_ip": "203.0.113.45",
                      "detection": {"rules": [{"rule_name": "audit_webshell_upload"}]}},
    )
    plan3 = build_response_plan(generic_contract, GateResult("recommended_generic", "x", True, False))
    assert any("웹루트" in a.title for a in plan3.actions)

    # 대상·신호가 전혀 없으면 기본 폴백
    empty_contract = _contract(
        mapping=MappingView("no_techniques_matched", "passed", (), (), ()),
        initial_seed={},
    )
    plan4 = build_response_plan(empty_contract, GateResult("recommended_generic", "x", True, False))
    assert [a.title for a in plan4.actions] == ["담당자 확인 요청"]

    # FALLBACK_VERDICT 경고가 있으면 L2 → L1 하향
    downgraded_contract = _contract(
        initial_seed=seed_with_path,
        mapping=MappingView("mapped", "passed", (
            {"technique_id": "T1505.003", "technique_name": "Web Shell", "tactic_name": "Persistence",
             "evidence_ids": ["EVID-003"]},
        ), ({"step": 1, "technique_id": "T1505.003"},), ({"code": "FALLBACK_VERDICT", "detail": "x"},)),
    )
    plan5 = build_response_plan(downgraded_contract, GateResult("recommended", "x", True, True))
    quarantine5 = next(a for a in plan5.actions if a.title == "웹셸 파일 격리")
    assert quarantine5.autonomy == "L1" and quarantine5.autonomy_downgraded_from == "L2"

    # not_applicable / deferred / error / skipped는 조치 없이 끝
    assert build_response_plan(_contract(), GateResult("not_applicable", "오탐", False, False)).actions == []
    assert build_response_plan(_contract(), GateResult("deferred", "보류", False, False)).actions == []
    assert build_response_plan(_contract(), GateResult("skipped", "미완료", False, False)).actions == []
    err_plan = build_response_plan(_contract(), GateResult("error", "구조 오류", False, False))
    assert err_plan.actions == [] and err_plan.errors == ["구조 오류"]

    print("ok")
