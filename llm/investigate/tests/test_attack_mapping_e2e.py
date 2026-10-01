"""End-to-end check of C's slice: engine (A) -> killchain -> cli -> final_report.

Exercises the full "완료 기준" from the design doc: a THREAT_CONFIRMED
investigation_result, run through the real attack_mapping.cli entry point,
must produce a final_report.json containing final_verdict, evidence_chain,
attack_timeline, attack_mapping.techniques and attack_mapping.kill_chain, with
the kill chain in ATT&CK tactic order across multiple attack stages.

The rule catalog here is a small local stand-in for B's real
attack_mapping/rules/ (developed in parallel); this test never imports it.
"""

import json

from attack_mapping.cli import run
from attack_mapping.schema import TechniqueRule


INITIAL_ACCESS = TechniqueRule(
    technique_id="T1190", technique_name="Exploit Public-Facing Application",
    tactic_id="TA0001", tactic_name="Initial Access",
    evidence_keywords=("업로드 취약점 악용",),
)
EXECUTION = TechniqueRule(
    technique_id="T1059.004", technique_name="Unix Shell",
    tactic_id="TA0002", tactic_name="Execution",
    evidence_keywords=("역방향 셸", "reverse shell"),
)
PERSISTENCE = TechniqueRule(
    technique_id="T1098.004", technique_name="SSH Authorized Keys",
    tactic_id="TA0003", tactic_name="Persistence",
    evidence_keywords=("authorized_keys",),
)
EXFIL = TechniqueRule(
    technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
    tactic_id="TA0010", tactic_name="Exfiltration",
    evidence_keywords=("외부 전송",),
)
ALL_TEST_RULES = (INITIAL_ACCESS, EXECUTION, PERSISTENCE, EXFIL)


def _evidence(eid, sequence, time, description):
    return {
        "evidence_id": eid, "sequence": sequence, "time": time, "layer": "audit",
        "event_type": "process_exec", "description": description,
        "source_log": "audit.log", "raw_refs": [f"audit.log:{sequence}"],
    }


def _multi_stage_investigation():
    return {
        "incident_id": "INC-E2E-001", "investigation_id": "INV-E2E-001",
        "final_verdict": {
            "verdict": "THREAT_CONFIRMED",
            "attack_type": "웹셸을 통한 침투 후 자격 증명 탈취 및 외부 전송",
        },
        "evidence_chain": [
            _evidence("EVID-1", 1, "2026-09-25T10:01:00Z", "업로드 취약점 악용으로 웹셸 생성"),
            _evidence("EVID-2", 2, "2026-09-25T10:05:00Z", "역방향 셸(reverse shell) 연결 확인"),
            _evidence("EVID-3", 3, "2026-09-25T10:10:00Z", "authorized_keys 파일에 공격자 공개키 추가"),
            _evidence("EVID-4", 4, "2026-09-25T10:30:00Z", "수집한 자료를 외부 전송 완료"),
        ],
        "contradicting_evidence": [],
        "attack_timeline": [
            {"time": "2026-09-25T10:01:00Z", "event": "웹셸 업로드"},
            {"time": "2026-09-25T10:30:00Z", "event": "데이터 유출"},
        ],
        "raw_refs": ["audit.log:1", "audit.log:2", "audit.log:3", "audit.log:4"],
        "raw_ref_locations": {f"audit.log:{i}": [f"/synthetic/audit.log:{i}"] for i in range(1, 5)},
        "provenance": {
            "status": "passed", "evidence_without_raw_refs": [],
            "ambiguous_raw_refs": {}, "issues": [],
        },
    }


def test_multi_stage_investigation_produces_ordered_kill_chain_and_full_final_report(tmp_path):
    inv_path = tmp_path / "investigation.json"
    inv_path.write_text(json.dumps(_multi_stage_investigation()), encoding="utf-8")
    out_dir = tmp_path / "out"

    exit_code = run([str(inv_path), "--out-dir", str(out_dir)], rules=ALL_TEST_RULES)
    assert exit_code == 0

    mapping = json.loads((out_dir / "INC-E2E-001_attack_mapping.json").read_text(encoding="utf-8"))
    assert mapping["mapping_status"] == "mapped"
    assert {t["technique_id"] for t in mapping["techniques"]} == {
        "T1190", "T1059.004", "T1098.004", "T1041",
    }

    # Kill chain must follow ATT&CK stage order, not evidence/discovery order:
    # Initial Access -> Execution -> Persistence -> Exfiltration.
    assert [step["technique_id"] for step in mapping["kill_chain"]] == [
        "T1190", "T1059.004", "T1098.004", "T1041",
    ]
    assert [step["step"] for step in mapping["kill_chain"]] == [1, 2, 3, 4]
    assert [step["time"] for step in mapping["kill_chain"]] == [
        "2026-09-25T10:01:00Z", "2026-09-25T10:05:00Z",
        "2026-09-25T10:10:00Z", "2026-09-25T10:30:00Z",
    ]

    final_report = json.loads((out_dir / "INC-E2E-001_final_report.json").read_text(encoding="utf-8"))
    # The doc's 담당 C 완료 기준: all of these must be present in one final_report.json.
    assert "final_verdict" in final_report
    assert "evidence_chain" in final_report and len(final_report["evidence_chain"]) == 4
    assert "attack_timeline" in final_report and final_report["attack_timeline"]
    assert final_report["attack_mapping"]["techniques"] == mapping["techniques"]
    assert final_report["attack_mapping"]["kill_chain"] == mapping["kill_chain"]


def test_inconclusive_investigation_defers_mapping_without_a_kill_chain(tmp_path):
    payload = _multi_stage_investigation()
    payload["final_verdict"] = {"verdict": "INCONCLUSIVE", "attack_type": "unclear"}
    inv_path = tmp_path / "investigation.json"
    inv_path.write_text(json.dumps(payload), encoding="utf-8")
    out_dir = tmp_path / "out"

    exit_code = run([str(inv_path), "--out-dir", str(out_dir)], rules=ALL_TEST_RULES)
    assert exit_code == 0

    mapping = json.loads((out_dir / "INC-E2E-001_attack_mapping.json").read_text(encoding="utf-8"))
    assert mapping["mapping_status"] == "deferred"
    assert mapping["techniques"] == mapping["kill_chain"] == []

    final_report = json.loads((out_dir / "INC-E2E-001_final_report.json").read_text(encoding="utf-8"))
    assert final_report["attack_mapping"]["mapping_status"] == "deferred"
