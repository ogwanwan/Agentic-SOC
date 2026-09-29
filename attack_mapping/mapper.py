"""RAG 기반 ATT&CK Mapping의 LLM 판단 단계."""

from __future__ import annotations
from copy import deepcopy
from typing import Any, Mapping, Protocol, Sequence
from .killchain import build_kill_chain

from .prompts import (
    build_mapping_system_prompt,
    build_mapping_user_prompt,
)

from .schema import (
    AttackMappingEntry,
    AttackMappingResult,
    CandidateTechnique,
    MappingDecision,
    MappingUnit,
    SelectionRejection,
    ValidatedSelection,
)

from .schema import (
    AttackMappingEntry,
    CandidateTechnique,
    MappingDecision,
    MappingUnit,
    SelectionRejection,
    ValidatedSelection,
)

from .schema import (
    CandidateTechnique,
    MappingDecision,
    MappingUnit,
    SelectionRejection,
    ValidatedSelection,
)

from .validate import (
    check_case_gate,
    classify_evidence,
    eligibility_index,
    exclusions,
    target_evidence,
    validate_decision,
)

class JsonLLMClient(Protocol):
    """ATT&CK Mapper가 필요로 하는 최소 LLM 인터페이스."""

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        ...


def judge_mapping_unit(
    *,
    llm_client: JsonLLMClient,
    target_evidence: Any,
    candidates: Sequence[Any],
    related_evidence: Sequence[Any] = (),
    contradicting_evidence: Sequence[Any] = (),
    remaining_unknowns: Sequence[Any] = (),
) -> MappingDecision:
    """한 Mapping Unit에 대한 LLM 결정을 공식 MappingDecision으로 파싱한다.

    역할:
        Evidence + Candidate
        → Prompt 생성
        → LLM 호출
        → MappingDecision.from_dict()

    ATT&CK ID / Candidate / Evidence / raw_ref의 의미 검증은
    이후 A 담당 validate_decision()에서 수행한다.
    """

    system_prompt = build_mapping_system_prompt()

    user_prompt = build_mapping_user_prompt(
        target_evidence=target_evidence,
        candidates=candidates,
        related_evidence=related_evidence,
        contradicting_evidence=contradicting_evidence,
        remaining_unknowns=remaining_unknowns,
    )

    raw_decision = llm_client.complete_json(
        system_prompt,
        user_prompt,
    )

    return MappingDecision.from_dict(raw_decision)


def map_mapping_unit(
    *,
    llm_client: JsonLLMClient,
    mapping_unit: Any,
    retrieve_candidates_fn: Any,
    validate_selection_fn: Any,
    related_evidence: Sequence[Any] = (),
    contradicting_evidence: Sequence[Any] = (),
    remaining_unknowns: Sequence[Any] = (),
) -> list[Any]:
    """테스트 대역을 이용한 Mapping Unit 오케스트레이션.

    이 함수는 A/B 실제 구현이 준비되기 전에
    C 흐름을 독립적으로 시험하기 위해 유지한다.

    실제 RAG 경로에서는 이후
    judge_and_validate_mapping_unit()과
    B의 Retriever를 사용한다.
    """

    candidates = list(
        retrieve_candidates_fn(mapping_unit)
    )

    # 후보가 없으면 LLM을 호출하지 않는다.
    if not candidates:
        return []

    decision = judge_mapping_unit(
        llm_client=llm_client,
        target_evidence=mapping_unit,
        candidates=candidates,
        related_evidence=related_evidence,
        contradicting_evidence=contradicting_evidence,
        remaining_unknowns=remaining_unknowns,
    )

    # ABSTAIN은 정상적인 "매핑하지 않음".
    if decision.decision == "ABSTAIN":
        return []

    validated: list[Any] = []

    for selection in decision.selections:
        validated_selection = validate_selection_fn(
            selection
        )

        # 실패한 Selection만 제외한다.
        if validated_selection is None:
            continue

        validated.append(validated_selection)

    return validated


def judge_and_validate_mapping_unit(
    *,
    llm_client: JsonLLMClient,
    mapping_unit: MappingUnit,
    candidates: Sequence[CandidateTechnique],
    catalog: Any,
    eligibility: Mapping[str, Any],
    related_evidence: Sequence[Any] = (),
    contradicting_evidence: Sequence[Any] = (),
    remaining_unknowns: Sequence[Any] = (),
) -> tuple[list[ValidatedSelection], list[SelectionRejection]]:
    """Mapping Unit 하나를 LLM 판단 후 A Validator로 실제 검증한다.

    실제 흐름:

        MappingUnit
            ↓
        CandidateTechnique 목록
            ↓
        Prompt
            ↓
        LLM SELECT / ABSTAIN
            ↓
        MappingDecision
            ↓
        A validate_decision()
            ↓
        ValidatedSelection / SelectionRejection

    후보가 없거나 LLM이 ABSTAIN하면
    정상적으로 빈 결과를 반환한다.
    """

    # 검색 후보가 없다면 LLM을 호출할 이유가 없다.
    if not candidates:
        return [], []

    decision = judge_mapping_unit(
        llm_client=llm_client,
        target_evidence=mapping_unit,
        candidates=candidates,
        related_evidence=related_evidence,
        contradicting_evidence=contradicting_evidence,
        remaining_unknowns=remaining_unknowns,
    )

    # ABSTAIN은 오류가 아니라 정상적인 판단 결과.
    if decision.decision == "ABSTAIN":
        return [], []

    accepted, rejected = validate_decision(
        decision,
        unit=mapping_unit,
        candidate_ids=[
            candidate.technique_id
            for candidate in candidates
        ],
        catalog=catalog,
        eligibility=eligibility,
    )

    return accepted, rejected


def merge_validated_selections(
    selections: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """동일 technique_id의 검증 완료 Selection을 하나로 합친다.

    이 함수는 Fake A/B 기반 C 단위 테스트를 위해 유지한다.

    현재 병합 대상:

    - technique_id
    - evidence_ids
    - reason

    A의 실제 ValidatedSelection을 AttackMappingEntry로 만드는
    공식 RAG 병합 로직은 이후 별도로 구현한다.
    """

    merged: dict[str, dict[str, Any]] = {}

    for selection in selections:
        technique_id = selection.get("technique_id")

        if not isinstance(technique_id, str) or not technique_id.strip():
            raise ValueError(
                "validated selection must have a non-empty technique_id"
            )

        technique_id = technique_id.strip()

        evidence_ids = selection.get(
            "evidence_ids",
            [],
        )

        if not isinstance(evidence_ids, list):
            raise ValueError(
                "validated selection evidence_ids must be a list"
            )

        reason = selection.get(
            "reason",
            "",
        )

        if not isinstance(reason, str):
            raise ValueError(
                "validated selection reason must be a string"
            )

        if technique_id not in merged:
            merged[technique_id] = {
                "technique_id": technique_id,
                "evidence_ids": [],
                "reasons": [],
            }

        target = merged[technique_id]

        for evidence_id in evidence_ids:
            if evidence_id not in target["evidence_ids"]:
                target["evidence_ids"].append(
                    evidence_id
                )

        cleaned_reason = reason.strip()

        if (
            cleaned_reason
            and cleaned_reason not in target["reasons"]
        ):
            target["reasons"].append(
                cleaned_reason
            )

    return list(merged.values())

def judge_and_validate_mapping_unit(
    *,
    llm_client: JsonLLMClient,
    mapping_unit: MappingUnit,
    candidates: Sequence[CandidateTechnique],
    catalog: Any,
    eligibility: Mapping[str, Any],
    related_evidence: Sequence[Any] = (),
    contradicting_evidence: Sequence[Any] = (),
    remaining_unknowns: Sequence[Any] = (),
) -> tuple[list[ValidatedSelection], list[SelectionRejection]]:
    """Mapping Unit 하나를 LLM 판단 후 A Validator로 검증한다.

    흐름:
        Candidate
        → Prompt
        → LLM SELECT / ABSTAIN
        → MappingDecision
        → A validate_decision()
    """

    # 후보 자체가 없으면 LLM을 호출할 이유가 없다.
    if not candidates:
        return [], []

    decision = judge_mapping_unit(
        llm_client=llm_client,
        target_evidence=mapping_unit,
        candidates=candidates,
        related_evidence=related_evidence,
        contradicting_evidence=contradicting_evidence,
        remaining_unknowns=remaining_unknowns,
    )

    # ABSTAIN은 정상적인 "매핑하지 않음"이다.
    if decision.decision == "ABSTAIN":
        return [], []

    accepted, rejected = validate_decision(
        decision,
        unit=mapping_unit,
        candidate_ids=[
            candidate.technique_id
            for candidate in candidates
        ],
        catalog=catalog,
        eligibility=eligibility,
    )

    return accepted, rejected

def build_attack_mapping_entries(
    selections: Sequence[ValidatedSelection],
    *,
    catalog: Any,
) -> list[AttackMappingEntry]:
    """검증 완료 Selection들을 최종 ATT&CK Technique 항목으로 병합한다.

    규칙:
    - 같은 technique_id는 하나의 Entry로 합친다.
    - evidence_ids / raw_refs / times / reasons / flags는 중복 제거한다.
    - name / tactic / parent는 공식 Catalog 값만 사용한다.
    - 같은 Mapping Unit에서 parent와 sub-technique이 함께 선택되면
      sub-technique을 남기고 parent 선택은 제거한다.
    """

    # 같은 Unit에서 parent + sub-technique이 함께 선택된 경우
    # parent 선택을 제거하기 위한 집합.
    suppressed_parents: set[tuple[str, str]] = set()

    for selection in selections:
        parent_id = selection.technique.parent_id

        if parent_id:
            suppressed_parents.add(
                (
                    selection.mapping_unit_id,
                    parent_id,
                )
            )

    filtered: list[ValidatedSelection] = []

    for selection in selections:
        key = (
            selection.mapping_unit_id,
            selection.technique.technique_id,
        )

        if key in suppressed_parents:
            continue

        filtered.append(selection)

    grouped: dict[str, list[ValidatedSelection]] = {}

    for selection in filtered:
        technique_id = selection.technique.technique_id

        grouped.setdefault(
            technique_id,
            [],
        ).append(selection)

    entries: list[AttackMappingEntry] = []

    for technique_id in sorted(grouped):
        group = grouped[technique_id]

        first = group[0]
        technique = first.technique

        if not technique.tactics:
            raise ValueError(
                f"{technique_id} has no ATT&CK tactics"
            )

        # 공식 순서의 첫 tactic을 기존 호환용 대표 tactic으로 사용.
        representative_tactic = technique.tactics[0]

        tactics = [
            tactic.as_dict()
            for tactic in technique.tactics
        ]

        evidence_ids: list[str] = []
        raw_refs: list[str] = []
        times: list[str] = []
        flags: list[str] = []
        selection_reasons = []
        matches = []

        for selection in group:
            for evidence_id in selection.evidence_ids:
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)

            for raw_ref in selection.raw_refs:
                if raw_ref not in raw_refs:
                    raw_refs.append(raw_ref)

            if (
                selection.time is not None
                and selection.time not in times
            ):
                times.append(selection.time)

            for flag in selection.flags:
                if flag not in flags:
                    flags.append(flag)

            selection_reasons.append(
                {
                    "mapping_unit_id": selection.mapping_unit_id,
                    "evidence_ids": list(
                        selection.evidence_ids
                    ),
                    "reason": selection.reason,
                }
            )

            matches.append(
                {
                    "tactic_id": representative_tactic.tactic_id,
                    "tactic_name": representative_tactic.tactic_name,
                    "matched_by": "evidence",
                    "matched_keywords": [],
                    "evidence_ids": list(
                        selection.evidence_ids
                    ),
                    "time": selection.time,
                    "raw_refs": list(
                        selection.raw_refs
                    ),
                }
            )

        parent_technique = None

        if technique.parent_id:
            parent = catalog.lookup(
                technique.parent_id
            )

            if parent is None:
                raise ValueError(
                    f"parent technique not found: "
                    f"{technique.parent_id}"
                )

            parent_technique = {
                "technique_id": parent.technique_id,
                "technique_name": parent.name,
            }

        entry: AttackMappingEntry = {
            "technique_id": technique.technique_id,
            "technique_name": technique.name,
            "tactic_id": representative_tactic.tactic_id,
            "tactic_name": representative_tactic.tactic_name,
            "tactics": tactics,
            "matched_by": ["evidence"],
            "matched_keywords": [],
            "evidence_ids": evidence_ids,
            "raw_refs": raw_refs,
            "times": times,
            "matches": matches,
            "parent_technique": parent_technique,
            "selections": selection_reasons,
            "flags": flags,
        }

        entries.append(entry)

    return entries

def map_investigation(
    investigation_result: Mapping[str, Any],
    *,
    llm_client: JsonLLMClient,
    catalog: Any,
    build_mapping_unit_fn: Any,
    retrieve_candidates_fn: Any,
    retrieval_version: str | None = None,
) -> AttackMappingResult:
    """Investigation 결과 하나를 RAG ATT&CK Mapping으로 처리한다.

    역할 경계:
    - A: 사건 Gate / Evidence 분류 / Selection 검증
    - B: Evidence → MappingUnit / Candidate Retrieval
    - C: LLM 판단 / 결과 병합 / AttackMappingResult 구성

    B 구현이 아직 없어도 build_mapping_unit_fn과
    retrieve_candidates_fn에 테스트 대역을 주입해서
    C 전체 흐름을 검증할 수 있다.
    """

    incident_id = None
    investigation_id = None

    if isinstance(investigation_result, Mapping):
        raw_incident_id = investigation_result.get("incident_id")
        raw_investigation_id = investigation_result.get(
            "investigation_id"
        )

        if isinstance(raw_incident_id, str):
            incident_id = raw_incident_id

        if isinstance(raw_investigation_id, str):
            investigation_id = raw_investigation_id

    manifest = getattr(
        catalog,
        "manifest",
        {},
    )

    if (
        retrieval_version is None
        and isinstance(manifest, Mapping)
    ):
        manifest_retrieval_version = manifest.get(
            "retrieval_version"
        )

        if isinstance(
            manifest_retrieval_version,
            str,
        ):
            retrieval_version = (
                manifest_retrieval_version
            )

    raw_locations = {}

    if isinstance(investigation_result, Mapping):
        value = investigation_result.get(
            "raw_ref_locations",
            {},
        )

        if isinstance(value, Mapping):
            raw_locations = deepcopy(dict(value))

    result: AttackMappingResult = {
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "mapping_status": "error",
        "provenance_status": None,
        "techniques": [],
        "unmatched_evidence_ids": [],
        "excluded_evidence_ids": [],
        "raw_ref_locations": raw_locations,
        "mapping_table_version": None,
        "errors": [],
        "attack_version": getattr(
            catalog,
            "attack_version",
            None,
        ),
        "retrieval_version": retrieval_version,
        "mapping_method": "rag_llm",
        "exclusions": [],
        "rejected_selections": [],
        "retrieval_trace": [],
        "warnings": [],
    }

    # ---------------------------------------------------------
    # 1. A: 사건 단위 Gate
    # ---------------------------------------------------------

    gate = check_case_gate(
        investigation_result
    )

    result["provenance_status"] = (
        gate.provenance_status
    )

    result["warnings"] = [
        deepcopy(item)
        for item in gate.warnings
    ]

    if not gate.proceed:
        result["mapping_status"] = (
            gate.mapping_status or "error"
        )

        result["errors"] = list(
            gate.errors
        )

        return result

    try:
        # -----------------------------------------------------
        # 2. A: Evidence 분류
        # -----------------------------------------------------

        rows = classify_evidence(
            investigation_result
        )

        eligibility = eligibility_index(
            rows
        )

        excluded = exclusions(
            rows
        )

        result["exclusions"] = deepcopy(
            excluded
        )

        result["excluded_evidence_ids"] = [
            item["evidence_id"]
            for item in excluded
        ]

        targets = target_evidence(
            rows
        )

        validated_selections: list[
            ValidatedSelection
        ] = []

        matched_evidence_ids: set[str] = set()

        contradicting = investigation_result.get(
            "contradicting_evidence",
            [],
        )

        if not isinstance(
            contradicting,
            list,
        ):
            contradicting = []

        remaining_unknowns = (
            investigation_result.get(
                "remaining_unknowns",
                [],
            )
        )

        if not isinstance(
            remaining_unknowns,
            list,
        ):
            remaining_unknowns = []

        # -----------------------------------------------------
        # 3. Target Evidence 하나씩 처리
        # -----------------------------------------------------

        for row in targets:
            # B 역할:
            # Evidence → MappingUnit
            unit = build_mapping_unit_fn(
                row.evidence
            )

            if not isinstance(
                unit,
                MappingUnit,
            ):
                raise TypeError(
                    "build_mapping_unit_fn must return "
                    "MappingUnit"
                )

            # B 역할:
            # MappingUnit → Candidate 최대 10개
            candidates = list(
                retrieve_candidates_fn(
                    unit,
                    catalog,
                    limit=10,
                )
            )

            if len(candidates) > 10:
                raise ValueError(
                    "retriever returned more than "
                    "10 candidates"
                )

            if any(
                not isinstance(
                    candidate,
                    CandidateTechnique,
                )
                for candidate in candidates
            ):
                raise TypeError(
                    "retrieve_candidates_fn must "
                    "return CandidateTechnique objects"
                )

            # P0 최소 Retrieval Trace
            result["retrieval_trace"].append(
                {
                    "mapping_unit_id": (
                        unit.mapping_unit_id
                    ),
                    "candidate_ids": [
                        candidate.technique_id
                        for candidate in candidates
                    ],
                }
            )

            # C LLM + A Validator
            accepted, rejected = (
                judge_and_validate_mapping_unit(
                    llm_client=llm_client,
                    mapping_unit=unit,
                    candidates=candidates,
                    catalog=catalog,
                    eligibility=eligibility,
                    related_evidence=(),
                    contradicting_evidence=(
                        contradicting
                    ),
                    remaining_unknowns=(
                        remaining_unknowns
                    ),
                )
            )

            result[
                "rejected_selections"
            ].extend(
                deepcopy(rejected)
            )

            validated_selections.extend(
                accepted
            )

            # 이 Evidence에서 최소 하나라도
            # 최종 Technique이 검증되었는가?
            if accepted:
                matched_evidence_ids.add(
                    row.evidence_id
                )

        # -----------------------------------------------------
        # 4. C: 같은 Technique 병합
        # -----------------------------------------------------

        entries = build_attack_mapping_entries(
            validated_selections,
            catalog=catalog,
        )

        result["techniques"] = entries

        # Target이었지만 최종 Technique을 얻지 못한 Evidence
        result["unmatched_evidence_ids"] = [
            row.evidence_id
            for row in targets
            if row.evidence_id
            not in matched_evidence_ids
        ]

        # -----------------------------------------------------
        # 5. Mapping Status
        # -----------------------------------------------------

        if not entries:
            result["mapping_status"] = (
                "no_techniques_matched"
            )

        elif (
            gate.provenance_status
            == "incomplete"
        ):
            result["mapping_status"] = "partial"

        else:
            result["mapping_status"] = "mapped"

    except Exception as exc:
        # 기술적 실패만 errors에 기록한다.
        # Selection 거부는 위의
        # rejected_selections에 들어간다.
        result["mapping_status"] = "error"
        result["errors"].append(
            f"{type(exc).__name__}: {exc}"
        )

    return result

def build_rag_kill_chain(
    techniques: Sequence[Mapping[str, Any]],
    *,
    catalog: Any,
) -> list[dict[str, Any]]:
    """RAG ATT&CK 결과를 공식 v19 tactic 순서로 Kill Chain 정렬한다.

    기존 build_kill_chain()은 시간 계산과 출력 형식을 재사용한다.
    단, 최종 tactic 순서만 catalog.tactic_order 기준으로 다시 정렬한다.

    Rule 경로의 기존 TACTIC_ORDER는 건드리지 않는다.
    """

    # 기존 Kill Chain 구현을 이용해
    # 대표 시간과 기본 출력 구조를 만든다.
    chain = build_kill_chain(
        list(techniques)
    )

    tactic_order = getattr(
        catalog,
        "tactic_order",
        (),
    )

    tactic_rank = {
        tactic.tactic_id: index
        for index, tactic in enumerate(
            tactic_order
        )
    }

    unknown_rank = len(
        tactic_rank
    )

    # 같은 tactic 내부에서는 기존 build_kill_chain이 계산한
    # 시간 순서를 보존하기 위해 기존 step을 2차 정렬 키로 사용.
    ordered = sorted(
        chain,
        key=lambda item: (
            tactic_rank.get(
                item["tactic_id"],
                unknown_rank,
            ),
            item["step"],
        ),
    )

    # 정렬 후 step을 다시 1부터 부여.
    return [
        {
            **item,
            "step": index,
        }
        for index, item in enumerate(
            ordered,
            start=1,
        )
    ]