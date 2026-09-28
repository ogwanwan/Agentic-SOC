import pytest

from attack_mapping.mapper import (
    MappingDecisionFormatError,
    judge_mapping_unit,
    map_mapping_unit,
)


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete_json(self, system_prompt, user_prompt):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )
        return self.response


def _target():
    return {
        "mapping_unit_id": "UNIT-EVID-003",
        "evidence_id": "EVID-003",
        "sequence": 3,
        "time": "2026-09-27T10:03:00Z",
        "layer": "audit",
        "event_type": "process_execution",
        "description": (
            "www-data가 sh -c id;whoami;uname -a를 실행함"
        ),
        "raw_refs": ["audit.log:321"],
    }


def _candidates():
    return [
        {
            "technique_id": "T1059.004",
            "name": "Unix Shell",
            "description": "Unix shell command execution",
            "tactics": ["Execution"],
            "rank": 1,
            "sources": ["bm25", "vector"],
        },
        {
            "technique_id": "T1033",
            "name": "System Owner/User Discovery",
            "description": "Identify the current user",
            "tactics": ["Discovery"],
            "rank": 2,
            "sources": ["vector"],
        },
    ]


def test_judge_mapping_unit_supports_multiple_selections():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "sh -c 실행",
                },
                {
                    "technique_id": "T1033",
                    "evidence_ids": ["EVID-003"],
                    "reason": "id/whoami 실행",
                },
            ],
        }
    )

    decision = judge_mapping_unit(
        llm_client=llm,
        target_evidence=_target(),
        candidates=_candidates(),
    )

    assert decision["decision"] == "SELECT"
    assert len(decision["selections"]) == 2
    assert decision["selections"][0]["technique_id"] == "T1059.004"
    assert decision["selections"][1]["technique_id"] == "T1033"
    assert len(llm.calls) == 1


def test_judge_mapping_unit_supports_abstain():
    llm = FakeLLM(
        {
            "decision": "ABSTAIN",
            "selections": [],
        }
    )

    decision = judge_mapping_unit(
        llm_client=llm,
        target_evidence=_target(),
        candidates=_candidates(),
    )

    assert decision == {
        "decision": "ABSTAIN",
        "selections": [],
    }


def test_select_requires_non_empty_selections():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [],
        }
    )

    with pytest.raises(
        MappingDecisionFormatError,
        match="SELECT must have at least one selection",
    ):
        judge_mapping_unit(
            llm_client=llm,
            target_evidence=_target(),
            candidates=_candidates(),
        )


def test_abstain_requires_empty_selections():
    llm = FakeLLM(
        {
            "decision": "ABSTAIN",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "should not exist",
                }
            ],
        }
    )

    with pytest.raises(
        MappingDecisionFormatError,
        match="ABSTAIN must have an empty selections list",
    ):
        judge_mapping_unit(
            llm_client=llm,
            target_evidence=_target(),
            candidates=_candidates(),
        )


def test_invalid_decision_type_is_rejected():
    llm = FakeLLM(
        {
            "decision": "MAYBE",
            "selections": [],
        }
    )

    with pytest.raises(
        MappingDecisionFormatError,
        match="decision must be SELECT or ABSTAIN",
    ):
        judge_mapping_unit(
            llm_client=llm,
            target_evidence=_target(),
            candidates=_candidates(),
        )


def test_missing_selection_reason_is_rejected():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "",
                }
            ],
        }
    )

    with pytest.raises(
        MappingDecisionFormatError,
        match="reason must be a non-empty string",
    ):
        judge_mapping_unit(
            llm_client=llm,
            target_evidence=_target(),
            candidates=_candidates(),
        )


def test_map_mapping_unit_runs_retrieval_llm_and_validator():
    retrieved = []
    validated = []

    def fake_retriever(mapping_unit):
        retrieved.append(mapping_unit["evidence_id"])
        return _candidates()

    def fake_validator(selection):
        validated.append(selection["technique_id"])
        return {
            **selection,
            "validated": True,
        }

    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "sh -c 실행",
                }
            ],
        }
    )

    result = map_mapping_unit(
        llm_client=llm,
        mapping_unit=_target(),
        retrieve_candidates_fn=fake_retriever,
        validate_selection_fn=fake_validator,
    )

    assert retrieved == ["EVID-003"]
    assert validated == ["T1059.004"]
    assert result[0]["technique_id"] == "T1059.004"
    assert result[0]["validated"] is True


def test_map_mapping_unit_does_not_call_llm_when_no_candidates():
    def fake_retriever(mapping_unit):
        return []

    def fake_validator(selection):
        raise AssertionError("validator must not be called")

    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [],
        }
    )

    result = map_mapping_unit(
        llm_client=llm,
        mapping_unit=_target(),
        retrieve_candidates_fn=fake_retriever,
        validate_selection_fn=fake_validator,
    )

    assert result == []
    assert llm.calls == []


def test_map_mapping_unit_does_not_validate_abstain():
    validator_calls = []

    def fake_retriever(mapping_unit):
        return _candidates()

    def fake_validator(selection):
        validator_calls.append(selection)
        return selection

    llm = FakeLLM(
        {
            "decision": "ABSTAIN",
            "selections": [],
        }
    )

    result = map_mapping_unit(
        llm_client=llm,
        mapping_unit=_target(),
        retrieve_candidates_fn=fake_retriever,
        validate_selection_fn=fake_validator,
    )

    assert result == []
    assert validator_calls == []


def test_map_mapping_unit_keeps_successful_selection_when_one_fails():
    def fake_retriever(mapping_unit):
        return _candidates()

    def fake_validator(selection):
        if selection["technique_id"] == "T1033":
            return None

        return {
            **selection,
            "validated": True,
        }

    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "sh -c 실행",
                },
                {
                    "technique_id": "T1033",
                    "evidence_ids": ["EVID-003"],
                    "reason": "id/whoami 실행",
                },
            ],
        }
    )

    result = map_mapping_unit(
        llm_client=llm,
        mapping_unit=_target(),
        retrieve_candidates_fn=fake_retriever,
        validate_selection_fn=fake_validator,
    )

    assert len(result) == 1
    assert result[0]["technique_id"] == "T1059.004"
