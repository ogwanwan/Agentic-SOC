"""RAG 기반 ATT&CK Mapping의 LLM 판단 단계."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from .prompts import (
    build_mapping_system_prompt,
    build_mapping_user_prompt,
)
from .schema import (
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
from .validate import validate_decision

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