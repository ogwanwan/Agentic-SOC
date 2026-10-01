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
    description="Unix shell execution",
    tactics=(EXECUTION,),
    is_subtechnique=True,
    parent_id="T1059",
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1059/004/",
)


class FakeCatalog:
    attack_version = "19.2"

    manifest = {
        "retrieval_version": "test-rag-v1",
    }

    tactic_order = (
        EXECUTION,
    )

    def lookup(self, technique_id):
        return {
            "T1059": COMMAND_INTERPRETER,
            "T1059.004": UNIX_SHELL,
        }.get(technique_id)


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


def _investigation():
    return {
        "incident_id": "INC-RAG-CLI",
        "investigation_id": "INV-RAG-CLI",
        "final_verdict": {
            "verdict": "THREAT_CONFIRMED",
            "attack_type": "web shell",
            "reasoning": "test",
        },
        "evidence_chain": [
            {
                "evidence_id": "EVID-001",
                "sequence": 1,
                "time": "2026-09-27T10:00:00Z",
                "layer": "audit",
                "event_type": "process_execution",
                "description": (
                    "www-data가 sh -c id를 실행함"
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
            "status": "passed",
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
            description="Unix shell execution",
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


def test_rag_cli_writes_mapping_and_final_report(
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

    out_dir = tmp_path / "out"

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
                        "sh -c Unix shell 실행"
                    ),
                }
            ],
        }
    )

    result = process_file_rag(
        str(investigation_path),
        str(out_dir),
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

    assert result["mapping_method"] == (
        "rag_llm"
    )

    assert result["techniques"][0][
        "technique_id"
    ] == "T1059.004"

    assert result["kill_chain"][0][
        "technique_id"
    ] == "T1059.004"

    mapping_path = (
        out_dir
        / "INC-RAG-CLI_attack_mapping.json"
    )

    report_path = (
        out_dir
        / "INC-RAG-CLI_final_report.json"
    )

    assert mapping_path.exists()
    assert report_path.exists()

    mapping = json.loads(
        mapping_path.read_text(
            encoding="utf-8"
        )
    )

    report = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    assert mapping == result

    assert report[
        "attack_mapping"
    ] == mapping

    assert report[
        "evidence_chain"
    ] == _investigation()[
        "evidence_chain"
    ]


def test_rag_cli_false_positive_skips_llm(
    tmp_path,
):
    data = _investigation()

    data["final_verdict"][
        "verdict"
    ] = "FALSE_POSITIVE"

    investigation_path = (
        tmp_path / "investigation.json"
    )

    investigation_path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"

    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [],
        }
    )

    result = process_file_rag(
        str(investigation_path),
        str(out_dir),
        llm_client=llm,
        catalog=FakeCatalog(),
        build_mapping_unit_fn=(
            _build_mapping_unit
        ),
        retrieve_candidates_fn=_retrieve,
    )

    assert result["mapping_status"] == (
        "not_applicable"
    )

    assert result["techniques"] == []
    assert result["kill_chain"] == []
    assert llm.calls == []