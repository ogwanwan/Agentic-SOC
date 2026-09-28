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