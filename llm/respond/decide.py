"""조치 선택 — 설계 문서 6·7절. 카탈로그 + 추출된 엔티티로 ResponsePlan.actions를 채운다.

여기서 만든 Action의 reason, ResponsePlan.summary/analyst_note는 전부 None이다.
그 문장은 담당 B의 llm.py가 채운다 — 여기서는 "뭘 할지"만 정하고 "왜"는 안 쓴다.

2026-10-06 산출물 확정(팀 합의): 조치마다 카탈로그의 고정값을 그대로 옮겨 싣는다.
  priority(우선순위) · rollback(역가능 방법) · side_effects(부작용·영향 범위)
  · verification(검증 방법) · autonomy_reason(자동화 등급 근거)
  rollback·verification 문장의 "{target}"은 실제 대상으로 채우고, 대상이 없는 조치에서는
  그 문장을 비운다 — 없는 대상으로 명령을 만들지 않는다.
  라벨이 하향되면(7절) autonomy_reason 끝에 하향 사유를 덧붙인다. 권고문에서 "왜 L1인가"가
  "원래 L2였지만 무엇 때문에 내려갔다"까지 보이게 하는 것이 이 단계의 책임이다.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

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
    get_template,
    requires_approval,
)
from respond.contract import Contract  # noqa: E402
from respond.entities import Entity, extract_entities, first_of_kind  # noqa: E402
from respond.gate import GateResult  # noqa: E402
from respond.schema import Action, ResponsePlan, attack_stix_url  # noqa: E402

_DOWNGRADE_WARNING_CODES = ("FALLBACK_VERDICT", "VERDICT_PRINCIPLE_CONFLICT")

# ↓ 2026-10-06 추가 — "LLM이 조치 목록을 짜고 code가 검문"(신규 설계) 전용 자료형·함수.
# 기존 build_response_plan()(아래)은 **한 글자도 바꾸지 않는다** — 선택 단계가 아예 없거나
# 구조째 실패했을 때 쓰는 결정론적 폴백이 이 함수여야 하므로, 지금까지의 동작과 100% 같아야
# 한다.

# LLM 조치 선택이 가져갈 수 있는 한도. mandatory_ids·선행조건으로 추가된 조치는 한도 밖이다
# (최소 필수 조치가 한도 때문에 빠지면 안전망이 안전망이 아니게 된다).
MAX_TOTAL_ACTIONS = 8
MAX_HIGH_RISK_ACTIONS = 1
MAX_IRREVERSIBLE_ACTIONS = 2


@dataclass(frozen=True)
class Candidate:
    """후보 조치 하나 — 아직 action_id가 없다(선택 전이라 몇 번째가 될지 모른다)."""
    template: ActionTemplate
    entity: Optional[Entity]
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic_name: Optional[str] = None
    evidence_ids: tuple = ()


@dataclass(frozen=True)
class CandidatePool:
    """이번 사건에서 고를 수 있는 후보 전체 + 그중 최소 필수(mandatory) id."""
    candidates: Tuple[Candidate, ...]
    mandatory_ids: FrozenSet[str]

    def by_id(self) -> Dict[str, Candidate]:
        return {c.template.template_id: c for c in self.candidates}



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
        # 2026-10-06 추가 — ATT&CK 매핑 근거를 그대로 싣는다(권고문·프롬프트·대시보드 공용).
        techniques=[dict(t) for t in contract.mapping.techniques],
        attack_data=_attack_data(contract),
    )


def _attack_data(contract: Contract) -> dict:
    """어떤 ATT&CK 데이터로 매핑했는지 — 매핑 단계가 적어 준 값만 쓴다.

    버전을 모르면 source_url도 None으로 둔다(주소를 추측해 적지 않는다).
    """
    version = contract.mapping.attack_version
    return {
        "version": version,
        "source_url": attack_stix_url(version),
        "mapping_method": contract.mapping.mapping_method,
        "retrieval_version": contract.mapping.retrieval_version,
    }


def _resolve_entity(template: ActionTemplate, entities: tuple) -> Optional[Entity]:
    if template.entity_kind is None:
        return None
    return first_of_kind(entities, template.entity_kind)


def _fill_target(text: str, entity: Optional[Entity]) -> str:
    """카탈로그 문장의 "{target}"을 실제 대상으로 채운다.

    대상이 없는데 자리표시자가 있으면 **빈 문자열**을 돌려준다 — 없는 대상으로
    되돌리기 명령이나 검증 절차를 지어내지 않는다(5-4절과 같은 원칙).
    """
    if not text:
        return ""
    if "{target}" not in text:
        return text
    return text.format(target=entity.value) if entity else ""


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
        # 2026-10-06 산출물 — 전부 카탈로그 고정값(LLM이 채우지 않는다)
        priority=template.priority,
        rollback=_fill_target(template.rollback, entity),
        side_effects=template.side_effects,
        verification=_fill_target(template.verification, entity),
        autonomy_reason=template.autonomy_reason,
        # 2026-10-06 추가 — 어느 템플릿에서 왔는지(선택 단계 안전망·순서 정리가 씀)
        template_id=template.template_id,
        requires_approval=requires_approval(template.autonomy),
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


# ↓ 2026-10-06 추가 — 위 _apply_templates()와 같은 매칭 규칙(대상 필요한데 없으면 건너뛰고,
# 중복이면 건너뛴다)이지만 Action을 바로 만들지 않고 Candidate로만 모은다. LLM 선택 단계가
# 고르기 전이라 action_id(몇 번째 조치인지)를 아직 모른다. _apply_templates()는 그대로
# 둔다 — build_response_plan()(결정론적 폴백)이 지금까지와 똑같이 동작해야 한다.

def _collect_candidates(templates, entities: tuple, candidates: list, seen: set, **meta) -> None:
    for template in templates:
        entity = _resolve_entity(template, entities)
        if template.entity_kind and entity is None:
            continue
        key = template.template_id
        if key in seen:
            continue
        seen.add(key)
        candidates.append(Candidate(template=template, entity=entity, **meta))


def _collect_technique_candidates(contract: Contract, entities: tuple) -> List[Candidate]:
    candidates: List[Candidate] = []
    seen: set = set()
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
        _collect_candidates(
            templates, entities, candidates, seen,
            technique_id=technique_id, technique_name=technique.get("technique_name"),
            tactic_name=technique.get("tactic_name"),
            evidence_ids=tuple(technique.get("evidence_ids") or ()),
        )

    if uncatalogued and not candidates:
        candidates.append(Candidate(template=UNCATALOGUED_TECHNIQUE_TEMPLATE, entity=None))

    return candidates


def _collect_fallback_candidates(contract: Contract, entities: tuple) -> List[Candidate]:
    candidates: List[Candidate] = []
    seen: set = set()

    templates: list = []
    for rule_name in _rule_names(contract):
        templates.extend(fallback_templates_for_rule_name(rule_name))
    for tag in _signal_tags(contract):
        templates.extend(fallback_templates_for_signal_tag(tag))
    if not templates:
        templates = list(DEFAULT_FALLBACK_TEMPLATES)

    _collect_candidates(templates, entities, candidates, seen)
    return candidates


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


def _downgrade_causes(contract: Contract) -> list:
    """L2 → L1 하향을 일으킨 사유 목록(7절). 비어 있으면 하향하지 않는다."""
    causes: list = []
    codes = sorted(contract.mapping.warning_codes & set(_DOWNGRADE_WARNING_CODES))
    if codes:
        causes.append(f"매핑 경고 {', '.join(codes)}")
    if contract.provenance_status == "incomplete":
        causes.append("원본 추적 불완전(provenance incomplete)")
    return causes


def _apply_autonomy_downgrade(contract: Contract, actions: list) -> None:
    causes = _downgrade_causes(contract)
    if not causes:
        return
    suffix = f". 다만 {' · '.join(causes)} 때문에 자동 실행 대상에서 제외 → L2에서 L1로 하향"
    for action in actions:
        if action.autonomy == "L2":
            action.autonomy_downgraded_from = "L2"
            action.autonomy = "L1"
            # 근거 문장도 같이 고친다 — 안 고치면 "(L2)"라고 적힌 근거가 L1 조치에 남는다
            action.autonomy_reason = (action.autonomy_reason or "").rstrip() + suffix


def _renumber(actions: list) -> list:
    """[즉시 조치] → [확인 필요] 순서로 묶고, 묶음 안에서는 우선순위(1 먼저)대로 정렬한다.

    같은 우선순위면 카탈로그에 적힌 순서를 그대로 둔다(sorted는 안정 정렬).
    """
    def by_priority(group: list) -> list:
        return sorted(group, key=lambda a: a.priority)

    ordered = (
        by_priority([a for a in actions if a.category == "immediate"])
        + by_priority([a for a in actions if a.category == "verify_needed"])
    )
    for position, action in enumerate(ordered, start=1):
        action.action_id = f"act_{position:02d}"
    return ordered


# ======================================================================
# 2026-10-06 추가 — "LLM이 조치 목록을 짜고 code가 검문·안전망·순서 정리" (신규 설계)
#
#   decide.build_candidate_pool()        → select.run_selection_stage() (LLM 호출 1)
#     → select_gate.validate_payload()  → 여기(merge/closure/caps) → finalize_selected_plan()
#     → llm.run_llm_stage() (LLM 호출 2, 7칸 작성 — 안 바뀜)
#
#   build_response_plan()은 아래에서 그대로 둔다 — 선택 단계가 통째로 실패했을 때
#   finalize_selected_plan(..., llm_selected_ids=None)이 쓰는 폴백과 "같은 결과"를
#   내야 하므로(후보 전체 사용), 그 기준이 흔들리면 안 된다.
# ======================================================================

def incident_facts(contract: Contract) -> dict:
    """선택 단계 프롬프트에 싣는 사건 요약 — 조치 자체는 안 들어간다(그건 candidates가 함)."""
    return {
        "incident_id": contract.incident_id,
        "verdict": contract.verdict.verdict,
        "severity": contract.verdict.severity,
        "attack_type": contract.verdict.attack_type or None,
        "host": contract.initial_seed.get("host"),
    }


def build_candidate_pool(contract: Contract, gate: GateResult) -> CandidatePool:
    """LLM이 고를 수 있는 후보 전체. gate.use_llm이 False인 상태(오탐·보류·건너뜀·오류)에는
    쓰지 않는다 — 그런 상태는 조치가 없고 build_response_plan()이 그대로 처리한다."""
    entities = extract_entities(contract)
    if gate.use_technique_catalog:
        candidates = _collect_technique_candidates(contract, entities)
    else:
        candidates = _collect_fallback_candidates(contract, entities)
    if not candidates:
        candidates = [Candidate(template=NO_TARGET_TEMPLATE, entity=None)]
    mandatory_ids = frozenset(c.template.template_id for c in candidates if c.template.mandatory)
    return CandidatePool(candidates=tuple(candidates), mandatory_ids=mandatory_ids)


def apply_mandatory_merge(pool: CandidatePool, selected_ids: Set[str]) -> Tuple[Set[str], List[str]]:
    """LLM이 빠뜨린 최소 필수 조치(mandatory)를 code가 다시 넣는다. 돌려주는 두 번째 값은
    실제로 "추가된" id만(이미 선택돼 있던 mandatory는 추가라고 하지 않는다)."""
    added = sorted(pool.mandatory_ids - selected_ids)
    return set(selected_ids) | pool.mandatory_ids, added


def apply_requires_closure(pool: CandidatePool, ids: Set[str]) -> Tuple[Set[str], List[str]]:
    """선택된 조치의 선행조건(requires)을 전이적으로 채운다.

    선행조건이 이번 사건의 후보 자체에 없으면(그 기법이 안 매핑됐거나 폴백 카탈로그라
    후보에 없음) 그 제약은 무시한다 — 없는 후보를 만들어 내지 않는다.
    """
    by_id = pool.by_id()
    ids = set(ids)
    added: List[str] = []
    changed = True
    while changed:
        changed = False
        for tid in list(ids):
            candidate = by_id.get(tid)
            if candidate is None:
                continue
            for req in candidate.template.requires:
                if req in by_id and req not in ids:
                    ids.add(req)
                    added.append(req)
                    changed = True
    return ids, added


def apply_caps(
    pool: CandidatePool, ids: Set[str], protected_ids: Set[str],
) -> Tuple[Set[str], List[str]]:
    """위험도·총량 한도. protected_ids(최소 필수 + 선행조건으로 채워진 것)는 절대 빼지 않는다
    — LLM이 자유롭게 고른 나머지가 한도를 넘으면 우선순위가 낮은(숫자가 큰) 것부터 뺀다.
    """
    by_id = pool.by_id()
    ids = set(ids)
    dropped: List[str] = []

    def _trim(predicate, cap: int) -> None:
        group = [tid for tid in ids if predicate(by_id[tid].template)]
        over = len(group) - cap
        if over <= 0:
            return
        removable = sorted(
            (tid for tid in group if tid not in protected_ids),
            key=lambda tid: (-by_id[tid].template.priority, tid),
        )
        for tid in removable:
            if over <= 0:
                break
            ids.discard(tid)
            dropped.append(tid)
            over -= 1

    _trim(lambda t: t.risk == "HIGH", MAX_HIGH_RISK_ACTIONS)
    _trim(lambda t: not t.reversible, MAX_IRREVERSIBLE_ACTIONS)
    _trim(lambda t: True, MAX_TOTAL_ACTIONS)

    return ids, dropped


def _order_by_requires_then_priority(actions: List[Action]) -> List[Action]:
    """[즉시 조치] → [확인 필요] 순서는 _renumber()와 같다. 묶음 안에서는 requires(선행조건)로
    하드 순서를 만들고, 그 안에서는 priority(숫자가 작을수록 먼저)로 세부 정렬한다
    (위상 정렬 + 우선순위 타이브레이크 — Kahn 알고리즘에 최소 힙을 쓴다).
    """
    import heapq

    def order_group(group: List[Action]) -> List[Action]:
        by_tid: Dict[str, Action] = {a.template_id: a for a in group if a.template_id}
        no_id = [a for a in group if not a.template_id]
        indegree: Dict[str, int] = {tid: 0 for tid in by_tid}
        edges: Dict[str, List[str]] = {tid: [] for tid in by_tid}
        for tid, action in by_tid.items():
            template = get_template(tid)
            if template is None:
                continue
            for req in template.requires:
                if req in by_tid:
                    edges[req].append(tid)
                    indegree[tid] += 1

        heap = [(by_tid[tid].priority, tid) for tid, deg in indegree.items() if deg == 0]
        heapq.heapify(heap)
        remaining = dict(indegree)
        ordered_ids: List[str] = []
        seen_ids: set = set()
        while heap:
            _, tid = heapq.heappop(heap)
            if tid in seen_ids:
                continue
            seen_ids.add(tid)
            ordered_ids.append(tid)
            for nxt in edges.get(tid, []):
                remaining[nxt] -= 1
                if remaining[nxt] == 0:
                    heapq.heappush(heap, (by_tid[nxt].priority, nxt))

        # requires가 순환을 이루는 경우(설계상 없어야 하지만) 조치를 잃지 않도록 방어적으로
        # 남은 것을 priority로만 정렬해 뒤에 붙인다.
        leftover = sorted(
            (tid for tid in by_tid if tid not in seen_ids),
            key=lambda tid: (by_tid[tid].priority, tid),
        )
        ordered = [by_tid[tid] for tid in ordered_ids] + [by_tid[tid] for tid in leftover]
        ordered += sorted(no_id, key=lambda a: a.priority)
        return ordered

    ordered = (
        order_group([a for a in actions if a.category == "immediate"])
        + order_group([a for a in actions if a.category == "verify_needed"])
    )
    for position, action in enumerate(ordered, start=1):
        action.action_id = f"act_{position:02d}"
    return ordered


def finalize_selected_plan(
    contract: Contract, gate: GateResult, pool: CandidatePool,
    llm_selected_ids: Optional[List[str]] = None, *,
    llm_rejected: Optional[list] = None,
) -> ResponsePlan:
    """선택 단계(LLM 호출 1) 결과로 ResponsePlan을 만든다.

    llm_selected_ids가 None이면 "선택 단계 자체가 실패"한 경우다 — 후보 전체를 쓴다
    (build_response_plan()의 결정론적 동작과 같은 결과). select_gate.validate_payload()가
    이미 "후보에 있는 id만" 걸러서 넘겨주므로, 여기서는 모르는 id를 다시 거르지 않는다 —
    다만 방어적으로 한 번 더 걸러서 selection_meta에 기록한다.
    """
    plan = _plan_skeleton(contract, gate)
    by_id = pool.by_id()
    all_ids = set(by_id)

    if llm_selected_ids is None:
        chosen = set(all_ids)
        llm_chosen_ids: List[str] = []
        unknown_dropped: List[str] = []
        mode = "fallback"
    else:
        llm_chosen_ids = [tid for tid in llm_selected_ids if tid in all_ids]
        unknown_dropped = [tid for tid in llm_selected_ids if tid not in all_ids]
        chosen = set(llm_chosen_ids)
        mode = "llm_selected"

    chosen, added_mandatory = apply_mandatory_merge(pool, chosen)
    chosen, added_prerequisite = apply_requires_closure(pool, chosen)
    protected = pool.mandatory_ids | set(added_prerequisite)
    chosen, capped = apply_caps(pool, chosen, protected)

    actions: List[Action] = []
    for tid in sorted(chosen):  # 임시 순서 — _order_by_requires_then_priority가 다시 정렬한다
        candidate = by_id[tid]
        actions.append(_build_action(
            candidate.template, candidate.entity, 1,
            technique_id=candidate.technique_id, technique_name=candidate.technique_name,
            tactic_name=candidate.tactic_name, evidence_ids=candidate.evidence_ids,
        ))

    if not actions:
        actions = [_build_action(NO_TARGET_TEMPLATE, None, 1)]

    _apply_autonomy_downgrade(contract, actions)
    plan.actions = _order_by_requires_then_priority(actions)
    plan.selection_meta = {
        "mode": mode,
        "candidate_ids": sorted(all_ids),
        "selected_ids": [a.template_id for a in plan.actions],
        "llm_chosen_ids": llm_chosen_ids,
        "added_mandatory": added_mandatory,
        "added_prerequisite": sorted(set(added_prerequisite)),
        "capped": capped,
        "unknown_ids_dropped": sorted(unknown_dropped),
        "llm_rejected": list(llm_rejected or []),
    }
    return plan


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

    # 2026-10-06 산출물 — 카탈로그의 네 칸과 우선순위가 조치에 그대로 실린다
    assert quarantine.priority == 1 and quarantine.priority_label() == "P1"
    assert quarantine.side_effects and quarantine.autonomy_reason
    # rollback·verification의 "{target}"은 실제 대상으로 채워진다
    assert quarantine.rollback == "sudo mv /var/quarantine/$(basename /var/www/shell.php) /var/www/shell.php"
    assert "/var/www/shell.php" in quarantine.verification
    # 대상이 없는 점검 항목은 대상 자리표시자가 든 문장을 비워 둔다(지어내지 않는다)
    checkup = next(a for a in plan2.actions if a.title == "웹루트 내 최근 생성 파일 전수 점검")
    assert checkup.target == "" and "{target}" not in checkup.verification
    assert checkup.rollback and checkup.side_effects
    # 묶음 안에서는 우선순위대로 번호가 붙는다(1 먼저 → 3 나중)
    immediate = [a for a in plan2.actions if a.category == "immediate"]
    assert [a.priority for a in immediate] == sorted(a.priority for a in immediate)
    assert immediate[0].action_id == "act_01"
    # ATT&CK 매핑 근거가 그대로 실린다
    assert plan2.techniques and plan2.techniques[0]["technique_id"] == "T1505.003"
    assert plan2.attack_data["version"] is None  # 매핑이 안 적었으면 꾸며내지 않는다
    assert plan2.attack_data["source_url"] is None

    # attack_version을 매핑이 적어 주면 STIX 원본 주소까지 만들어 싣는다
    versioned = _contract(
        initial_seed=seed_with_path,
        mapping=MappingView("mapped", "passed", (
            {"technique_id": "T1505.003", "technique_name": "Web Shell",
             "tactic_name": "Persistence", "evidence_ids": ["EVID-003"]},
        ), ({"step": 1, "technique_id": "T1505.003"},), (),
            attack_version="19.2", mapping_method="rag_llm"),
    )
    plan_versioned = build_response_plan(versioned, GateResult("recommended", "x", True, True))
    assert plan_versioned.attack_data["version"] == "19.2"
    assert plan_versioned.attack_data["source_url"].endswith("enterprise-attack-19.2.json")
    assert plan_versioned.attack_data["mapping_method"] == "rag_llm"

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
    # 하향되면 등급 근거에 그 사유까지 적힌다 — "왜 L1인가"가 권고문에서 보여야 한다
    assert "FALLBACK_VERDICT" in quarantine5.autonomy_reason
    assert "L2에서 L1로 하향" in quarantine5.autonomy_reason

    # provenance가 incomplete면 경고가 없어도 하향되고, 그 사유가 적힌다
    incomplete = _contract(initial_seed=seed_with_path, provenance_status="incomplete",
                            mapping=MappingView("mapped", "passed", (
                                {"technique_id": "T1505.003", "technique_name": "Web Shell",
                                 "tactic_name": "Persistence", "evidence_ids": ["EVID-003"]},
                            ), ({"step": 1, "technique_id": "T1505.003"},), ()))
    plan6 = build_response_plan(incomplete, GateResult("recommended", "x", True, True))
    quarantine6 = next(a for a in plan6.actions if a.title == "웹셸 파일 격리")
    assert quarantine6.autonomy == "L1" and "provenance incomplete" in quarantine6.autonomy_reason

    # not_applicable / deferred / error / skipped는 조치 없이 끝
    assert build_response_plan(_contract(), GateResult("not_applicable", "오탐", False, False)).actions == []
    assert build_response_plan(_contract(), GateResult("deferred", "보류", False, False)).actions == []
    assert build_response_plan(_contract(), GateResult("skipped", "미완료", False, False)).actions == []
    err_plan = build_response_plan(_contract(), GateResult("error", "구조 오류", False, False))
    assert err_plan.actions == [] and err_plan.errors == ["구조 오류"]

    # ------------------------------------------------------------------
    # 2026-10-06 추가 — "LLM이 조치 목록을 짜고 code가 검문" 단계
    # ------------------------------------------------------------------
    two_tech_contract = _contract(
        initial_seed={"detection": {"rules": [
            {"layer": "system", "detail": {"path": "/var/www/shell.php", "pid": 2051}},
        ]}},
        mapping=MappingView("mapped", "passed", (
            {"technique_id": "T1505.003", "technique_name": "Web Shell", "tactic_name": "Persistence",
             "evidence_ids": ["EVID-003"]},
            {"technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic_name": "Execution",
             "evidence_ids": ["EVID-004"]},
        ), (
            {"step": 1, "technique_id": "T1505.003"}, {"step": 2, "technique_id": "T1059.004"},
        ), ()),
    )
    gate_llm = GateResult("recommended", "x", True, True)
    pool = build_candidate_pool(two_tech_contract, gate_llm)
    cand_ids = {c.template.template_id for c in pool.candidates}
    assert cand_ids == {"T1505_003_QUARANTINE", "T1505_003_WEBROOT_SWEEP",
                         "T1059_004_HISTORY_PRESERVE", "T1059_004_PROCESS_KILL"}
    assert pool.mandatory_ids == {"T1059_004_HISTORY_PRESERVE"}

    # LLM이 프로세스 종료만 고르고 선행조건(이력 보존)을 빠뜨려도 code가 다시 넣고,
    # 이력 보존이 프로세스 종료보다 먼저 오게 정렬한다
    selected_plan = finalize_selected_plan(two_tech_contract, gate_llm, pool,
                                            ["T1059_004_PROCESS_KILL"])
    ids_in_order = [a.template_id for a in selected_plan.actions]
    assert "T1059_004_HISTORY_PRESERVE" in ids_in_order
    assert ids_in_order.index("T1059_004_HISTORY_PRESERVE") < ids_in_order.index("T1059_004_PROCESS_KILL")
    assert selected_plan.selection_meta["mode"] == "llm_selected"
    assert selected_plan.selection_meta["added_mandatory"] == ["T1059_004_HISTORY_PRESERVE"]

    # 선택 단계 자체가 실패(None)하면 build_response_plan()과 같은 조치 집합이 나온다(폴백)
    fallback_plan = finalize_selected_plan(two_tech_contract, gate_llm, pool, None)
    deterministic_plan = build_response_plan(two_tech_contract, gate_llm)
    assert ({a.template_id for a in fallback_plan.actions}
            == {a.template_id for a in deterministic_plan.actions})
    assert fallback_plan.selection_meta["mode"] == "fallback"

    # 후보에 없는 id는 조용히 버려지고 그 사실이 selection_meta에 남는다
    unknown_plan = finalize_selected_plan(two_tech_contract, gate_llm, pool,
                                           ["T1505_003_QUARANTINE", "없는_id"])
    assert "없는_id" in unknown_plan.selection_meta["unknown_ids_dropped"]
    assert "없는_id" not in [a.template_id for a in unknown_plan.actions]

    # apply_mandatory_merge / apply_requires_closure / apply_caps 단위 동작
    assert apply_mandatory_merge(pool, set())[1] == ["T1059_004_HISTORY_PRESERVE"]
    assert apply_mandatory_merge(pool, pool.mandatory_ids)[1] == []  # 이미 있으면 "추가"가 아니다
    closed, added = apply_requires_closure(pool, {"T1059_004_PROCESS_KILL"})
    assert closed == {"T1059_004_PROCESS_KILL", "T1059_004_HISTORY_PRESERVE"}
    assert added == ["T1059_004_HISTORY_PRESERVE"]
    # HIGH 위험 1개 캡 — T1136.001은 전부 HIGH라 세 후보 중 비보호 항목이 깎인다
    acct_contract = _contract(
        initial_seed={"detection": {"rules": [{"layer": "system", "detail": {"user": "evil_admin"}}]}},
        mapping=MappingView("mapped", "passed", (
            {"technique_id": "T1136.001", "technique_name": "Create Account",
             "tactic_name": "Persistence", "evidence_ids": ["EVID-010"]},
        ), ({"step": 1, "technique_id": "T1136.001"},), ()),
    )
    acct_pool = build_candidate_pool(acct_contract, gate_llm)
    high_ids = {c.template.template_id for c in acct_pool.candidates if c.template.risk == "HIGH"}
    assert len(high_ids) >= 2
    capped_ids, dropped = apply_caps(acct_pool, high_ids, protected_ids=set())
    assert len(capped_ids) == MAX_HIGH_RISK_ACTIONS and len(dropped) == len(high_ids) - 1

    print("ok")
