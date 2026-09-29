import json

from attack_mapping.cli import process_file_rag
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

DISCOVERY = TacticRef(
    tactic_id="TA0007",
    tactic_name="Discovery",
    shortname="discovery",
)


COMMAND_INTERPRETER = TechniqueRecord(
    technique_id="T1059",
    stix_id="attack-pattern--command-interpreter",
    name="Command and Scripting Interpreter",
    description="Command and scripting interpreter",
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


USER_DISCOVERY = TechniqueRecord(
    technique_id="T1033",
    stix_id="attack-pattern--user-discovery",
    name="System Owner/User Discovery",
    description="Identify the current user",
    tactics=(DISCOVERY,),
    is_subtechnique=False,
    parent_id=None,
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1033/",
)


SYSTEM_DISCOVERY = TechniqueRecord(
    technique_id="T1082",
    stix_id="attack-pattern--system-discovery",
    name="System Information Discovery",
    description="Discover system information",
    tactics=(DISCOVERY,),
    is_subtechnique=False,
    parent_id=None,
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1082/",
)


class FakeCatalog:
    attack_version = "19.2"

    manifest = {
        "retrieval_version": "fake-b-e2e-v1",
    }

    tactic_order = (
        EXECUTION,
        DISCOVERY,
    )

    def lookup(self, technique_id):
        return {
            "T1059": COMMAND_INTERPRETER,
            "T1059.004": UNIX_SHELL,
            "T1033": USER_DISCOVERY,
            "T1082": SYSTEM_DISCOVERY,
        }.get(technique_id)


class FakeLLM:
    def __init__(self):
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

        return {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": (
                        "sh -c를 이용한 Unix shell "
                        "명령 실행이 확인됨"
                    ),
                },
                {
                    "technique_id": "T1033",
                    "evidence_ids": ["EVID-003"],
                    "reason": (
                        "id와 whoami를 이용한 "
                        "사용자 정보 조회가 확인됨"
                    ),
                },
                {
                    "technique_id": "T1082",
                    "evidence_ids": ["EVID-003"],
                    "reason": (
                        "uname -a를 이용한 "
                        "시스템 정보 조회가 확인됨"
                    ),
                },
            ],
        }


def _investigation():
    return {
        "incident_id": "INC-E2E-001",
        "investigation_id": "INV-E2E-001",
        "final_verdict": {
            "verdict": "THREAT_CONFIRMED",
            "attack_type": "web shell",
            "reasoning": "대표 E2E 테스트",
        },
        "evidence_chain": [
            {
                "evidence_id": "EVID-003",
                "sequence": 3,
                "time": "2026-09-27T10:03:00Z",
                "layer": "audit",
                "event_type": "process_execution",
                "description": (
                    "www-data가 sh -c "
                    "id;whoami;uname -a를 실행함"
                ),
                "raw_refs": [
                    "audit.log:321",
                ],
            }
        ],
        "contradicting_evidence": [],
        "remaining_unknowns": [],
        "raw_refs": [
            "audit.log:321",
        ],
        "raw_ref_locations": {
            "audit.log:321": [
                "/var/log/audit/audit.log",
            ],
        },
        "tools_called": [
            {
                "raw_refs": [
                    "audit.log:321",
                ],
            }
        ],
        "provenance": {
            "status": "passed",
            "seed_raw_refs": [],
            "evidence_without_raw_refs": [],
            "empty_result_evidence": [],
            "ambiguous_raw_refs": {},
            "issues": [],
        },
    }


def fake_build_mapping_unit(evidence):
    return MappingUnit(
        mapping_unit_id=(
            "UNIT-" + evidence["evidence_id"]
        ),
        evidence_id=evidence["evidence_id"],
        sequence=evidence.get("sequence"),
        time=evidence.get("time"),
        layer=evidence.get("layer", ""),
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


def fake_retrieve_candidates(
    mapping_unit,
    catalog,
    *,
    limit=10,
):
    candidates = [
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
            sources=("bm25", "vector"),
        ),
        CandidateTechnique(
            technique_id="T1033",
            name="System Owner/User Discovery",
            description=(
                "Identify the current user"
            ),
            tactics=(DISCOVERY,),
            parent_id=None,
            rank=2,
            score=0.91,
            sources=("bm25", "vector"),
        ),
        CandidateTechnique(
            technique_id="T1082",
            name="System Information Discovery",
            description=(
                "Discover system information"
            ),
            tactics=(DISCOVERY,),
            parent_id=None,
            rank=3,
            score=0.88,
            sources=("vector",),
        ),
    ]

    return candidates[:limit]


def test_fake_b_representative_rag_e2e(
    tmp_path,
):
    investigation_path = (
        tmp_path / "investigation.json"
    )

    investigation_path.write_text(
        json.dumps(
            _investigation(),
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    llm = FakeLLM()

    result = process_file_rag(
        str(investigation_path),
        str(output_dir),
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            fake_build_mapping_unit
        ),
        retrieve_candidates_fn=(
            fake_retrieve_candidates
        ),
    )

    assert result["mapping_status"] == "mapped"
    assert result["errors"] == []

    technique_ids = {
        item["technique_id"]
        for item in result["techniques"]
    }

    assert technique_ids == {
        "T1059.004",
        "T1033",
        "T1082",
    }

    assert result["retrieval_trace"] == [
        {
            "mapping_unit_id": "UNIT-EVID-003",
            "candidate_ids": [
                "T1059.004",
                "T1033",
                "T1082",
            ],
        }
    ]

    assert [
        step["technique_id"]
        for step in result["kill_chain"]
    ] == [
        "T1059.004",
        "T1033",
        "T1082",
    ]

    assert len(llm.calls) == 1

    mapping_path = (
        output_dir
        / "INC-E2E-001_attack_mapping.json"
    )

    final_report_path = (
        output_dir
        / "INC-E2E-001_final_report.json"
    )

    assert mapping_path.exists()
    assert final_report_path.exists()

    mapping = json.loads(
        mapping_path.read_text(
            encoding="utf-8"
        )
    )

    report = json.loads(
        final_report_path.read_text(
            encoding="utf-8"
        )
    )

    assert mapping == result
    assert report["attack_mapping"] == mapping

    assert report["evidence_chain"] == (
        _investigation()["evidence_chain"]
    )