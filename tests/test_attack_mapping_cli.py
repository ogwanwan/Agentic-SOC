"""Offline tests for C's CLI (attack_mapping/cli.py).

Every test passes an explicit `rules=` fixture to `run()`, so these never touch
`attack_mapping.rules` (B's package, developed in parallel and possibly absent).
`run()`'s default (no `rules` argument) lazily imports B's real ALL_RULES; that
wiring is exercised manually / in the later integration pass, not here.
"""

import json

import pytest

from attack_mapping.cli import run
from attack_mapping.schema import TechniqueRule


SHELL = TechniqueRule(
    technique_id="T1505.003", technique_name="Web Shell",
    tactic_id="TA0003", tactic_name="Persistence",
    attack_type_keywords=("web shell", "웹셸"), evidence_keywords=("webshell", "웹셸"),
)
TEST_RULES = (SHELL,)


def evidence(eid="EVID-001", **changes):
    return {
        "evidence_id": eid, "sequence": 1, "time": "2026-09-25T00:00:00Z",
        "layer": "audit", "event_type": "process_exec", "description": "Webshell observed",
        "source_log": "audit.log", "raw_refs": ["audit.log:11"],
        **changes,
    }


def investigation(**changes):
    return {
        "incident_id": "INC-CLI", "investigation_id": "INV-CLI",
        "final_verdict": {"verdict": "THREAT_CONFIRMED", "attack_type": "Web Shell"},
        "evidence_chain": [evidence()], "attack_timeline": [],
        "raw_refs": ["audit.log:11"], "raw_ref_locations": {"audit.log:11": ["/synthetic/audit.log:11"]},
        "provenance": {"status": "passed", "evidence_without_raw_refs": [], "ambiguous_raw_refs": {}, "issues": []},
        **changes,
    }


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_single_file_writes_attack_mapping_and_final_report(tmp_path, capsys):
    inv_path = _write_json(tmp_path / "inv.json", investigation())
    out_dir = tmp_path / "out"

    exit_code = run([str(inv_path), "--out-dir", str(out_dir)], rules=TEST_RULES)

    assert exit_code == 0
    mapping = json.loads((out_dir / "INC-CLI_attack_mapping.json").read_text(encoding="utf-8"))
    assert mapping["mapping_status"] == "mapped"
    assert [t["technique_id"] for t in mapping["techniques"]] == ["T1505.003"]
    assert mapping["kill_chain"][0]["technique_id"] == "T1505.003"

    final_report = json.loads((out_dir / "INC-CLI_final_report.json").read_text(encoding="utf-8"))
    assert final_report["final_verdict"] == investigation()["final_verdict"]
    assert final_report["evidence_chain"] == investigation()["evidence_chain"]
    assert final_report["attack_mapping"] == mapping

    out = capsys.readouterr().out
    assert "INC-CLI" in out and "T1505.003" in out


def test_all_in_dir_processes_every_json_file(tmp_path, capsys):
    _write_json(tmp_path / "a.json", investigation(incident_id="INC-A", investigation_id="INV-A"))
    _write_json(tmp_path / "b.json", investigation(incident_id="INC-B", investigation_id="INV-B"))
    out_dir = tmp_path / "out"

    exit_code = run(["--all-in-dir", str(tmp_path), "--out-dir", str(out_dir)], rules=TEST_RULES)

    assert exit_code == 0
    assert (out_dir / "INC-A_attack_mapping.json").exists()
    assert (out_dir / "INC-B_attack_mapping.json").exists()
    out = capsys.readouterr().out
    assert "INC-A" in out and "INC-B" in out


def test_false_positive_skips_mapping_but_still_writes_final_report(tmp_path):
    inv_path = _write_json(
        tmp_path / "inv.json",
        investigation(final_verdict={"verdict": "FALSE_POSITIVE", "attack_type": "Web Shell"}),
    )
    out_dir = tmp_path / "out"

    exit_code = run([str(inv_path), "--out-dir", str(out_dir)], rules=TEST_RULES)

    assert exit_code == 0
    mapping = json.loads((out_dir / "INC-CLI_attack_mapping.json").read_text(encoding="utf-8"))
    assert mapping["mapping_status"] == "not_applicable"
    assert mapping["techniques"] == mapping["kill_chain"] == []


def test_malformed_json_file_is_skipped_with_nonzero_exit(tmp_path, capsys):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not valid json", encoding="utf-8")

    exit_code = run([str(bad_path), "--out-dir", str(tmp_path / "out")], rules=TEST_RULES)

    assert exit_code == 1
    assert "bad.json" in capsys.readouterr().err


def test_requires_exactly_one_of_path_or_all_in_dir(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        run([], rules=TEST_RULES)
    assert excinfo.value.code == 2

    inv_path = _write_json(tmp_path / "inv.json", investigation())
    with pytest.raises(SystemExit) as excinfo:
        run([str(inv_path), "--all-in-dir", str(tmp_path)], rules=TEST_RULES)
    assert excinfo.value.code == 2


def test_engine_error_result_is_still_written_and_reported(tmp_path, capsys):
    inv_path = _write_json(tmp_path / "inv.json", {"incident_id": "INC-BAD"})  # missing required fields
    out_dir = tmp_path / "out"

    exit_code = run([str(inv_path), "--out-dir", str(out_dir)], rules=TEST_RULES)

    assert exit_code == 1
    mapping = json.loads((out_dir / "INC-BAD_attack_mapping.json").read_text(encoding="utf-8"))
    assert mapping["mapping_status"] == "error"
    assert mapping["errors"]
    assert "error" in capsys.readouterr().out
