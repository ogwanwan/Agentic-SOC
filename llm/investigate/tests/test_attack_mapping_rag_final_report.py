from copy import deepcopy

from reporting.final_report import build_final_report


def _investigation():
    return {
        "incident_id": "INC-001",
        "investigation_id": "INV-001",
        "final_verdict": {
            "verdict": "THREAT_CONFIRMED",
            "attack_type": "웹셸 업로드 및 명령 실행",
        },
        "evidence_chain": [
            {
                "evidence_id": "EVID-003",
                "description": "www-data가 sh -c id;whoami;uname -a를 실행함",
                "raw_refs": ["audit.log:321"],
            }
        ],
        "attack_timeline": [],
    }


def _rag_mapping():
    return {
        "incident_id": "INC-001",
        "investigation_id": "INV-001",
        "mapping_status": "mapped",
        "provenance_status": "passed",
        "attack_version": "19.2",
        "retrieval_version": "2",
        "mapping_method": "rag_llm",
        "techniques": [
            {
                "technique_id": "T1059.004",
                "technique_name": "Unix Shell",
                "evidence_ids": ["EVID-003"],
                "raw_refs": ["audit.log:321"],
                "reason": "sh -c를 이용한 Unix shell 실행이 확인됨",
            }
        ],
        "kill_chain": [],
        "unmatched_evidence_ids": [],
        "excluded_evidence_ids": [],
        "errors": [],
    }


def test_final_report_contains_rag_mapping():
    investigation = _investigation()
    mapping = _rag_mapping()

    report = build_final_report(
        investigation,
        mapping,
    )

    assert report["attack_mapping"]["mapping_method"] == "rag_llm"
    assert (
        report["attack_mapping"]["techniques"][0]["technique_id"]
        == "T1059.004"
    )


def test_final_report_preserves_investigation_fields():
    investigation = _investigation()

    report = build_final_report(
        investigation,
        _rag_mapping(),
    )

    assert report["incident_id"] == "INC-001"
    assert report["final_verdict"] == investigation["final_verdict"]
    assert report["evidence_chain"] == investigation["evidence_chain"]


def test_final_report_does_not_mutate_investigation():
    investigation = _investigation()
    before = deepcopy(investigation)

    build_final_report(
        investigation,
        _rag_mapping(),
    )

    assert investigation == before


def test_final_report_does_not_share_mapping_objects():
    investigation = _investigation()
    mapping = _rag_mapping()

    report = build_final_report(
        investigation,
        mapping,
    )

    report["attack_mapping"]["techniques"][0]["reason"] = "changed"

    assert (
        mapping["techniques"][0]["reason"]
        == "sh -c를 이용한 Unix shell 실행이 확인됨"
    )