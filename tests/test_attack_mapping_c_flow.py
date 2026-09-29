from attack_mapping.mapper import (
    map_mapping_unit,
    merge_validated_selections,
)


class SequenceFakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete_json(self, system_prompt, user_prompt):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )

        if not self.responses:
            raise AssertionError("no fake LLM response left")

        return self.responses.pop(0)


def _unit(evidence_id, description):
    return {
        "mapping_unit_id": f"UNIT-{evidence_id}",
        "evidence_id": evidence_id,
        "sequence": 1,
        "time": "2026-09-27T10:03:00Z",
        "layer": "audit",
        "event_type": "process_execution",
        "description": description,
        "raw_refs": [f"audit.log:{evidence_id[-1]}"],
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


def test_c_flow_maps_multiple_units_and_merges_same_technique():
    units = [
        _unit(
            "EVID-001",
            "www-data가 sh -c id를 실행함",
        ),
        _unit(
            "EVID-002",
            "www-data가 sh -c whoami를 실행함",
        ),
    ]

    llm = SequenceFakeLLM(
        [
            {
                "decision": "SELECT",
                "selections": [
                    {
                        "technique_id": "T1059.004",
                        "evidence_ids": ["EVID-001"],
                        "reason": "sh -c를 이용한 Unix shell 실행",
                    }
                ],
            },
            {
                "decision": "SELECT",
                "selections": [
                    {
                        "technique_id": "T1059.004",
                        "evidence_ids": ["EVID-002"],
                        "reason": "sh -c를 이용한 Unix shell 실행",
                    },
                    {
                        "technique_id": "T1033",
                        "evidence_ids": ["EVID-002"],
                        "reason": "whoami를 이용한 사용자 확인",
                    },
                ],
            },
        ]
    )

    def fake_retriever(mapping_unit):
        return _candidates()

    def fake_validator(selection):
        return selection

    validated = []

    for unit in units:
        validated.extend(
            map_mapping_unit(
                llm_client=llm,
                mapping_unit=unit,
                retrieve_candidates_fn=fake_retriever,
                validate_selection_fn=fake_validator,
            )
        )

    merged = merge_validated_selections(validated)

    by_id = {
        item["technique_id"]: item
        for item in merged
    }

    assert set(by_id) == {
        "T1059.004",
        "T1033",
    }

    assert by_id["T1059.004"]["evidence_ids"] == [
        "EVID-001",
        "EVID-002",
    ]

    assert by_id["T1033"]["evidence_ids"] == [
        "EVID-002",
    ]

    assert len(llm.calls) == 2


def test_c_flow_keeps_abstained_unit_unmapped():
    units = [
        _unit(
            "EVID-001",
            "www-data가 sh -c id를 실행함",
        ),
        _unit(
            "EVID-002",
            "판단하기 어려운 행위",
        ),
    ]

    llm = SequenceFakeLLM(
        [
            {
                "decision": "SELECT",
                "selections": [
                    {
                        "technique_id": "T1059.004",
                        "evidence_ids": ["EVID-001"],
                        "reason": "sh -c 실행",
                    }
                ],
            },
            {
                "decision": "ABSTAIN",
                "selections": [],
            },
        ]
    )

    def fake_retriever(mapping_unit):
        return _candidates()

    def fake_validator(selection):
        return selection

    validated = []

    for unit in units:
        validated.extend(
            map_mapping_unit(
                llm_client=llm,
                mapping_unit=unit,
                retrieve_candidates_fn=fake_retriever,
                validate_selection_fn=fake_validator,
            )
        )

    merged = merge_validated_selections(validated)

    assert len(merged) == 1
    assert merged[0]["technique_id"] == "T1059.004"
    assert merged[0]["evidence_ids"] == ["EVID-001"]