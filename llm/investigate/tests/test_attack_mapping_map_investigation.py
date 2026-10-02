from attack_mapping.mapper import (
    map_investigation,
)
from attack_mapping.schema import (
    CandidateTechnique,
    MappingUnit,
    TacticRef,
    TechniqueRecord,
)


EXECUTION = TacticRef(
    tactic_id="TA0002",
    tactic_name="Execution",
    shortname="execution",
)


COMMAND_INTERPRETER = TechniqueRecord(
    technique_id="T1059",
    stix_id="attack-pattern--command-interpreter",
    name="Command and Scripting Interpreter",
    description="Command interpreter",
    tactics=(EXECUTION,),
    is_subtechnique=False,
    parent_id=None,
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1059/",
)


UNIX_SHELL = TechniqueRecord(
    technique_id="T1059.004",
    stix_id="attack-pattern--unix-shell",
    name="Unix Shell",
    description="Unix shell command execution",
    tactics=(EXECUTION,),
    is_subtechnique=True,
    parent_id="T1059",
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1059/004/",
)


class FakeCatalog:
    attack_version = "19.2"

    manifest = {
        "retrieval_version": "test-retrieval-v1",
    }

    def lookup(self, technique_id):
        records = {
            "T1059": COMMAND_INTERPRETER,
            "T1059.004": UNIX_SHELL,
        }

        return records.get(technique_id)


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete_json(
        self,
        system_prompt,
        user_prompt,
    ):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )

        return self.response


def _investigation(
    *,
    verdict="THREAT_CONFIRMED",
    provenance_status="passed",
):
    return {
        "incident_id": "INC-001",
        "investigation_id": "INV-001",
        "final_verdict": {
            "verdict": verdict,
            "attack_type": "web shell",
            "reasoning": "test",
        },
        "evidence_chain": [
            {
                "evidence_id": "EVID-001",
                "sequence": 1,
                "time": (
                    "2026-09-27T10:00:00Z"
                ),
                "layer": "audit",
                "event_type": (
                    "process_execution"
                ),
                "description": (
                    "www-data가 "
                    "sh -c id를 실행함"
                ),
                "raw_refs": [
                    "audit.log:10",
                ],
            }
        ],
        "contradicting_evidence": [],
        "remaining_unknowns": [],
        "raw_refs": [
            "audit.log:10",
        ],
        "raw_ref_locations": {
            "audit.log:10": [
                "/var/log/audit/audit.log",
            ],
        },
        "tools_called": [
            {
                "raw_refs": [
                    "audit.log:10",
                ],
            }
        ],
        "provenance": {
            "status": provenance_status,
            "seed_raw_refs": [],
            "evidence_without_raw_refs": [],
            "empty_result_evidence": [],
            "ambiguous_raw_refs": {},
            "issues": [],
        },
    }


def _build_mapping_unit(evidence):
    return MappingUnit(
        mapping_unit_id=(
            "UNIT-"
            + evidence["evidence_id"]
        ),
        evidence_id=evidence["evidence_id"],
        sequence=evidence.get("sequence"),
        time=evidence.get("time"),
        layer=evidence.get(
            "layer",
            "",
        ),
        event_type=evidence.get(
            "event_type",
            "",
        ),
        description=evidence.get(
            "description",
            "",
        ),
        raw_refs=tuple(
            evidence["raw_refs"]
        ),
    )


def _retrieve(
    mapping_unit,
    catalog,
    *,
    limit=10,
):
    return [
        CandidateTechnique(
            technique_id="T1059.004",
            name="Unix Shell",
            description=(
                "Unix shell command execution"
            ),
            tactics=(EXECUTION,),
            parent_id="T1059",
            rank=1,
            score=0.95,
            sources=(
                "bm25",
                "vector",
            ),
        )
    ][:limit]


def test_maps_full_investigation():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": (
                        "T1059.004"
                    ),
                    "evidence_ids": [
                        "EVID-001"
                    ],
                    "reason": (
                        "sh -c를 이용한 "
                        "Unix shell 실행"
                    ),
                }
            ],
        }
    )

    result = map_investigation(
        _investigation(),
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            _build_mapping_unit
        ),
        retrieve_candidates_fn=_retrieve,
    )

    assert result["mapping_status"] == (
        "mapped"
    )

    assert result["errors"] == []

    assert len(
        result["techniques"]
    ) == 1

    assert (
        result["techniques"][0]
        ["technique_id"]
        == "T1059.004"
    )

    assert result[
        "unmatched_evidence_ids"
    ] == []

    assert result[
        "excluded_evidence_ids"
    ] == []

    assert result["attack_version"] == (
        "19.2"
    )

    assert result[
        "retrieval_version"
    ] == "test-retrieval-v1"

    assert result["mapping_method"] == (
        "rag_llm"
    )

    assert result["retrieval_trace"] == [
        {
            "mapping_unit_id": (
                "UNIT-EVID-001"
            ),
            "candidate_ids": [
                "T1059.004"
            ],
        }
    ]


def test_false_positive_stops_before_llm():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [],
        }
    )

    def must_not_build(evidence):
        raise AssertionError(
            "builder must not run"
        )

    def must_not_retrieve(
        mapping_unit,
        catalog,
        *,
        limit=10,
    ):
        raise AssertionError(
            "retrieval must not run"
        )

    result = map_investigation(
        _investigation(
            verdict="FALSE_POSITIVE",
        ),
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            must_not_build
        ),
        retrieve_candidates_fn=(
            must_not_retrieve
        ),
    )

    assert result["mapping_status"] == (
        "not_applicable"
    )

    assert llm.calls == []


def test_abstain_marks_evidence_unmatched():
    llm = FakeLLM(
        {
            "decision": "ABSTAIN",
            "selections": [],
        }
    )

    result = map_investigation(
        _investigation(),
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            _build_mapping_unit
        ),
        retrieve_candidates_fn=_retrieve,
    )

    assert result["mapping_status"] == (
        "no_techniques_matched"
    )

    assert result["techniques"] == []

    assert result[
        "unmatched_evidence_ids"
    ] == [
        "EVID-001",
    ]


def test_no_candidates_marks_evidence_unmatched():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [],
        }
    )

    def no_candidates(
        mapping_unit,
        catalog,
        *,
        limit=10,
    ):
        return []

    result = map_investigation(
        _investigation(),
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            _build_mapping_unit
        ),
        retrieve_candidates_fn=(
            no_candidates
        ),
    )

    assert result["mapping_status"] == (
        "no_techniques_matched"
    )

    assert result[
        "unmatched_evidence_ids"
    ] == [
        "EVID-001",
    ]

    assert result[
        "retrieval_trace"
    ] == [
        {
            "mapping_unit_id": (
                "UNIT-EVID-001"
            ),
            "candidate_ids": [],
        }
    ]

    assert llm.calls == []


def test_incomplete_provenance_maps_valid_evidence_as_partial():
    data = _investigation(
        provenance_status="incomplete",
    )

    data["evidence_chain"].append(
        {
            "evidence_id": "EVID-002",
            "sequence": 2,
            "time": (
                "2026-09-27T10:01:00Z"
            ),
            "layer": "audit",
            "event_type": (
                "process_execution"
            ),
            "description": (
                "원본 참조가 없는 증거"
            ),
            "raw_refs": [],
        }
    )

    data["provenance"][
        "evidence_without_raw_refs"
    ] = [
        "EVID-002",
    ]

    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": (
                        "T1059.004"
                    ),
                    "evidence_ids": [
                        "EVID-001"
                    ],
                    "reason": (
                        "Unix shell 실행"
                    ),
                }
            ],
        }
    )

    result = map_investigation(
        data,
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            _build_mapping_unit
        ),
        retrieve_candidates_fn=_retrieve,
    )

    assert result["mapping_status"] == (
        "partial"
    )

    assert result[
        "excluded_evidence_ids"
    ] == [
        "EVID-002",
    ]

    assert result["exclusions"] == [
        {
            "evidence_id": "EVID-002",
            "reasons": [
                "NO_RAW_REFS",
            ],
        }
    ]

    assert len(
        result["techniques"]
    ) == 1