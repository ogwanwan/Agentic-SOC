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


def test_same_incident_keeps_both_investigations(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for index in (1, 2):
        _write_json(inputs / f"{index}.json", investigation(investigation_id=f"INV-{index}"))
    out_dir = tmp_path / "out"

    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out_dir)], rules=TEST_RULES) == 0

    reports = list(out_dir.glob("*_final_report.json"))
    assert len(reports) == 2
    assert {json.loads(path.read_text(encoding="utf-8"))["investigation_id"] for path in reports} == {
        "INV-1", "INV-2",
    }
    for path in reports:
        report = json.loads(path.read_text(encoding="utf-8"))
        mapping_path = path.with_name(path.name.replace("_final_report.json", "_attack_mapping.json"))
        assert json.loads(mapping_path.read_text(encoding="utf-8")) == report["attack_mapping"]


@pytest.mark.parametrize("existing_suffix", ["attack_mapping", "final_report"])
def test_existing_output_is_preserved_across_repeated_runs(tmp_path, existing_suffix):
    inv_path = _write_json(tmp_path / "inv.json", investigation())
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    existing = out_dir / f"INC-CLI_{existing_suffix}.json"
    existing.write_text("previous result", encoding="utf-8")

    for _ in range(2):
        assert run([str(inv_path), "--out-dir", str(out_dir)], rules=TEST_RULES) == 0

    assert existing.read_text(encoding="utf-8") == "previous result"
    for number in (2, 3):
        assert (out_dir / f"INC-CLI__{number}_attack_mapping.json").exists()
        assert (out_dir / f"INC-CLI__{number}_final_report.json").exists()


@pytest.mark.parametrize("payload", [[], [1], None, "invalid", 42, True])
def test_non_object_json_does_not_abort_next_file(tmp_path, capsys, payload):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    _write_json(inputs / "a_bad.json", payload)
    good = investigation()
    _write_json(inputs / "b_good.json", good)
    out_dir = tmp_path / "out"

    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out_dir)], rules=TEST_RULES) == 1

    report = json.loads((out_dir / "INC-CLI_final_report.json").read_text(encoding="utf-8"))
    assert report["evidence_chain"] == good["evidence_chain"]
    assert report["attack_mapping"]["mapping_status"] == "mapped"
    assert not list(out_dir.glob("a_bad_*.json"))
    output = capsys.readouterr()
    assert "a_bad.json" in output.err and "object" in output.err
    assert "Traceback" not in output.err
    assert "INC-CLI" in output.out


@pytest.mark.parametrize("incident_id", [
    "../escaped-proof", "..\\escaped-proof", "nested/child", "nested\\child",
    "CON.txt", "..", "invalid:\x00?*name", "사건-001",
])
def test_output_stays_in_requested_directory(tmp_path, incident_id):
    inv_path = _write_json(tmp_path / "input.json", investigation(incident_id=incident_id))
    out_dir = tmp_path / "requested"

    assert run([str(inv_path), "--out-dir", str(out_dir)], rules=TEST_RULES) == 0

    artifacts = [path for path in tmp_path.rglob("*.json") if path != inv_path]
    assert len(artifacts) == 2
    assert all(path.resolve().parent == out_dir.resolve() for path in artifacts)
    for path in artifacts:
        assert json.loads(path.read_text(encoding="utf-8"))["incident_id"] == incident_id


def test_absolute_incident_path_is_only_used_as_a_filename(tmp_path):
    incident_id = str(tmp_path / "escaped-absolute")
    inv_path = _write_json(tmp_path / "input.json", investigation(incident_id=incident_id))
    out_dir = tmp_path / "requested"

    assert run([str(inv_path), "--out-dir", str(out_dir)], rules=TEST_RULES) == 0

    reports = list(tmp_path.rglob("*_final_report.json"))
    assert len(reports) == 1 and reports[0].parent == out_dir
    assert json.loads(reports[0].read_text(encoding="utf-8"))["incident_id"] == incident_id


def test_sanitized_name_collision_preserves_both_incident_ids(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    ids = ["incident/a", "incident\\a"]
    for index, incident_id in enumerate(ids):
        _write_json(inputs / f"{index}.json", investigation(incident_id=incident_id))
    out_dir = tmp_path / "out"

    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out_dir)], rules=TEST_RULES) == 0

    reports = list(out_dir.glob("*_final_report.json"))
    assert len(reports) == 2
    assert {json.loads(path.read_text(encoding="utf-8"))["incident_id"] for path in reports} == set(ids)
