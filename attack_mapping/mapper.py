"""RAG 기반 ATT&CK Mapping의 LLM 판단 단계."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Mapping, Protocol, Sequence

from .prompts import (
    build_mapping_system_prompt,
    build_mapping_user_prompt,
)


class JsonLLMClient(Protocol):
    """ATT&CK Mapper가 필요로 하는 최소 LLM 인터페이스."""

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        ...


class MappingDecisionFormatError(ValueError):
    """LLM 응답이 MappingDecision 형식을 지키지 않았을 때 발생."""


def _as_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value

    if is_dataclass(value) and not isinstance(value, type):
        converted = asdict(value)
        if isinstance(converted, Mapping):
            return converted

    raise TypeError(
        f"{label} must be a mapping or dataclass instance"
    )


def _validate_decision_shape(
    raw_decision: Any,
) -> dict[str, Any]:
    """LLM 응답의 최소 구조만 검사한다.

    ATT&CK ID가 실제 존재하는지,
    Candidate 안에 있었는지,
    Evidence/raw_ref가 유효한지는
    A 담당 Validator가 이후에 검사한다.
    """

    decision = _as_mapping(
        raw_decision,
        label="LLM decision",
    )

    decision_type = decision.get("decision")
    selections = decision.get("selections")

    if decision_type not in {"SELECT", "ABSTAIN"}:
        raise MappingDecisionFormatError(
            "decision must be SELECT or ABSTAIN"
        )

    if not isinstance(selections, list):
        raise MappingDecisionFormatError(
            "selections must be a list"
        )

    if decision_type == "ABSTAIN":
        if selections:
            raise MappingDecisionFormatError(
                "ABSTAIN must have an empty selections list"
            )

        return {
            "decision": "ABSTAIN",
            "selections": [],
        }

    if not selections:
        raise MappingDecisionFormatError(
            "SELECT must have at least one selection"
        )

    normalized_selections: list[dict[str, Any]] = []

    for index, selection in enumerate(selections):
        item = _as_mapping(
            selection,
            label=f"selections[{index}]",
        )

        technique_id = item.get("technique_id")
        evidence_ids = item.get("evidence_ids")
        reason = item.get("reason")

        if not isinstance(technique_id, str) or not technique_id.strip():
            raise MappingDecisionFormatError(
                f"selections[{index}].technique_id "
                "must be a non-empty string"
            )

        if (
            not isinstance(evidence_ids, list)
            or not evidence_ids
            or any(
                not isinstance(evidence_id, str)
                or not evidence_id.strip()
                for evidence_id in evidence_ids
            )
        ):
            raise MappingDecisionFormatError(
                f"selections[{index}].evidence_ids "
                "must be a non-empty list of strings"
            )

        if not isinstance(reason, str) or not reason.strip():
            raise MappingDecisionFormatError(
                f"selections[{index}].reason "
                "must be a non-empty string"
            )

        normalized_selections.append(
            {
                "technique_id": technique_id.strip(),
                "evidence_ids": list(evidence_ids),
                "reason": reason.strip(),
            }
        )

    return {
        "decision": "SELECT",
        "selections": normalized_selections,
    }


def judge_mapping_unit(
    *,
    llm_client: JsonLLMClient,
    target_evidence: Any,
    candidates: Sequence[Any],
    related_evidence: Sequence[Any] = (),
    contradicting_evidence: Sequence[Any] = (),
    remaining_unknowns: Sequence[Any] = (),
) -> dict[str, Any]:
    """한 Mapping Unit에 대해 LLM의 SELECT/ABSTAIN 판단을 받는다.

    이 함수는 Technique을 최종 확정하지 않는다.

    여기서는:
      Evidence + Candidate
      → Prompt
      → LLM
      → MappingDecision 형식 확인

    까지만 수행한다.

    Technique ID / Candidate / Evidence / raw_ref의 의미 검증은
    이후 A 담당 Validator가 수행한다.
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

    return _validate_decision_shape(raw_decision)

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
    """Mapping Unit 하나를 Retrieval → LLM → Validation 순서로 처리한다.

    현재 단계에서는 A/B 실제 구현에 직접 의존하지 않는다.

    retrieve_candidates_fn:
        Mapping Unit을 받아 Candidate 목록을 반환하는 테스트 대역.
        나중에 B의 실제 Retriever와 연결한다.

    validate_selection_fn:
        LLM Selection 하나를 받아 검증 결과를 반환하는 테스트 대역.
        나중에 A의 실제 Validator와 연결한다.

    Validator가 None을 반환하면 해당 Selection은 거부된 것으로 본다.
    """

    candidates = list(
        retrieve_candidates_fn(mapping_unit)
    )

    # 검색 후보가 없다면 LLM을 호출할 이유가 없다.
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

    # LLM이 근거 부족으로 보류한 경우 Validator도 호출하지 않는다.
    if decision["decision"] == "ABSTAIN":
        return []

    validated: list[Any] = []

    for selection in decision["selections"]:
        validated_selection = validate_selection_fn(
            selection
        )

        # 실패한 Selection만 버린다.
        if validated_selection is None:
            continue

        validated.append(validated_selection)

    return validated

def merge_validated_selections(
    selections: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """동일 technique_id의 검증 완료 Selection을 하나로 합친다.

    현재 단계에서는 C가 확실히 소유하는 값만 병합한다:
    - technique_id
    - evidence_ids
    - reason

    공식 name / tactic / parent / raw_refs / time 등은
    A의 실제 Validator/Catalog 계약을 받은 뒤 연결한다.
    """

    merged: dict[str, dict[str, Any]] = {}

    for selection in selections:
        technique_id = selection.get("technique_id")

        if not isinstance(technique_id, str) or not technique_id.strip():
            raise ValueError(
                "validated selection must have a non-empty technique_id"
            )

        technique_id = technique_id.strip()

        evidence_ids = selection.get("evidence_ids", [])
        if not isinstance(evidence_ids, list):
            raise ValueError(
                "validated selection evidence_ids must be a list"
            )

        reason = selection.get("reason", "")
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
                target["evidence_ids"].append(evidence_id)

        cleaned_reason = reason.strip()
        if (
            cleaned_reason
            and cleaned_reason not in target["reasons"]
        ):
            target["reasons"].append(cleaned_reason)

    return list(merged.values())