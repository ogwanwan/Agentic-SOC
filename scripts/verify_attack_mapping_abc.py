"""Offline A/B/C verification with inspectable stage artifacts.

Run from the repository root: python -m scripts.verify_attack_mapping_abc
Uses the real B catalog and the real CLI subprocess (no rules injection).
Exit 1 means at least one assertion failed, including known boundary defects.
Only synthetic data is generated; existing results and application code are untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from agent.models import AgentState, Evidence
from agent.report import build_investigation_result
from attack_mapping.engine import map_investigation, mapping_table_version, match_evidence, match_verdict
from attack_mapping.killchain import build_kill_chain
from attack_mapping.rules import ALL_RULES
from reporting.final_report import build_final_report


ROOT = Path(__file__).resolve().parents[1]
RELATED_TESTS = [
    "tests/test_attack_mapping_engine.py", "tests/test_attack_mapping_initial_access_rules.py",
    "tests/test_attack_mapping_post_exploitation_rules.py", "tests/test_attack_mapping_killchain.py",
    "tests/test_attack_mapping_cli.py", "tests/test_attack_mapping_e2e.py",
    "tests/test_attack_mapping_review_regressions.py",
]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def command(args, log_dir, *, hash_seed="1"):
    log_dir.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, *map(str, args)]
    completed = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONHASHSEED": hash_seed}, timeout=120,
    )
    save(log_dir / "command.json", {"argv": argv, "cwd": str(ROOT), "returncode": completed.returncode})
    (log_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (log_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    return completed


def synthetic_result(folder, case, rows, *, verdict="THREAT_CONFIRMED", attack_type="unlisted",
                     contradicting=(), seed_reference=False, invalid_sequences=(), ambiguous_sequences=()):
    """Build real report output from synthetic state; this does not run an LLM.

    Each row is (description, time, number_of_source_lines). Zero source lines
    simulates an uncited evidence. Command strings are inert log text.
    """
    folder.mkdir(parents=True, exist_ok=True)
    source_path = folder / "synthetic.log"
    state = AgentState(incident_id="INC-" + case.upper(), seed={})
    lines = []
    for sequence, row in enumerate([*rows, *contradicting], start=1):
        description, time, line_count = row
        refs = []
        for part in range(line_count):
            lines.append(f"SYNTHETIC sequence={sequence} part={part + 1} time={time} text={description}")
            ref = f"synthetic.log:{len(lines)}"
            refs.append(ref)
            state.raw_ref_locations[ref] = [f"{source_path.resolve()}:{len(lines)}"]
        if sequence in ambiguous_sequences:
            other = folder / f"ambiguous_{sequence}.log"
            other.write_text("\n".join(lines) + "\n", encoding="utf-8")
            for ref in refs:
                state.raw_ref_locations[ref].append(f"{other.resolve()}:{ref.rsplit(':', 1)[1]}")
        state.raw_refs.extend(refs)
        state.add_evidence(Evidence(
            evidence_id=f"EVID-{sequence:03d}", sequence=sequence, time=time, layer="audit",
            event_type="fixture_observation", description=description, source_log=source_path.name,
            raw_refs=refs,
        ), contradicting=sequence > len(rows))
    if seed_reference:
        lines.append("SYNTHETIC seed observation, no evidence-level citation")
        ref = f"synthetic.log:{len(lines)}"
        state.raw_refs.append(ref)
        state.seed["raw_refs"] = [ref]
        state.raw_ref_locations[ref] = [f"{source_path.resolve()}:{len(lines)}"]
    state.provenance_issues = [
        {"sequence": sequence, "unknown_raw_refs": ["unobserved.log:999"]}
        for sequence in invalid_sequences
    ]
    state.attack_timeline = [{"time": ev.time, "event": ev.description} for ev in state.evidence]
    source_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return build_investigation_result(state, "no_more_evidence", {
        "verdict": verdict, "attack_type": attack_type, "confidence": 0.9,
        "summary": "합성 입력을 사용한 ATT&CK A/B/C 연결 검증",
    }, "INV-" + case.upper())


class Verification:
    def __init__(self, output):
        self.output = output
        self.checks = []
        self.scenarios = []

    def check(self, name, actual, expected):
        passed = actual == expected
        self.checks.append({"name": name, "passed": passed, "expected": expected, "actual": actual})
        if not passed:
            print(f"FAIL {name}: expected={expected!r}, actual={actual!r}", flush=True)
        return passed

    def scenario(self, name, source, status, ids, *, unmatched=(), excluded=(), chain_ids=None):
        folder = self.output / "scenarios" / name
        before = deepcopy(source)
        first_check = len(self.checks)
        save(folder / "01_investigation_result.json", source)
        # These helpers intentionally have no gates. 04_engine_result.json is
        # the authoritative, policy-filtered result consumed by C.
        verdict_hits = match_verdict(source, ALL_RULES)
        evidence_hits = match_evidence(source, ALL_RULES)
        save(folder / "02_verdict_hits_before_gates.json", [asdict(hit) for hit in verdict_hits])
        save(folder / "03_evidence_hits_before_gates.json", [asdict(hit) for hit in evidence_hits])
        mapping = map_investigation(source, ALL_RULES)
        save(folder / "04_engine_result.json", mapping)
        chain = build_kill_chain(mapping["techniques"])
        save(folder / "05_kill_chain.json", chain)
        augmented = {**mapping, "kill_chain": chain}
        report = build_final_report(source, augmented)
        save(folder / "06_final_report.json", report)

        self.check(name + ":status", mapping["mapping_status"], status)
        self.check(name + ":techniques", [t["technique_id"] for t in mapping["techniques"]], sorted(ids))
        self.check(name + ":unmatched", mapping["unmatched_evidence_ids"], list(unmatched))
        self.check(name + ":excluded", mapping["excluded_evidence_ids"], list(excluded))
        self.check(name + ":input_unchanged", source, before)
        # Unknown verdict fails validation before provenance/catalog metadata is
        # accepted; schema explicitly permits None in an error result.
        early_error = name == "unknown_verdict"
        self.check(name + ":provenance_status", mapping["provenance_status"],
                   None if early_error else source["provenance"]["status"])
        self.check(name + ":report_preserves_investigation",
                   {k: v for k, v in report.items() if k != "attack_mapping"}, source)
        self.check(name + ":rule_version", mapping["mapping_table_version"],
                   None if early_error else mapping_table_version(ALL_RULES))
        self.check(name + ":errors_present", bool(mapping["errors"]), status == "error")
        if chain_ids is not None:
            self.check(name + ":kill_chain_order", [s["technique_id"] for s in chain], list(chain_ids))
        self.check(name + ":step_numbers", [s["step"] for s in chain], list(range(1, len(chain) + 1)))

        trace = []
        evidence_by_id = {ev["evidence_id"]: ev for ev in source["evidence_chain"]}
        for technique in mapping["techniques"]:
            for match in technique["matches"]:
                for eid in match["evidence_ids"]:
                    self.check(name + ":citation:" + technique["technique_id"] + ":" + eid,
                               match["raw_refs"], evidence_by_id[eid]["raw_refs"])
                    for ref in match["raw_refs"]:
                        locations = mapping["raw_ref_locations"].get(ref, [])
                        self.check(name + ":location:" + ref, locations, source["raw_ref_locations"].get(ref, []))
                        for location in locations:
                            path, line = location.rsplit(":", 1)
                            text = Path(path).read_text(encoding="utf-8").splitlines()[int(line) - 1]
                            trace.append({"technique_id": technique["technique_id"], "evidence_id": eid,
                                          "raw_ref": ref, "location": location, "raw_text": text})
                            self.check(name + ":physical_line:" + ref,
                                       f"sequence={evidence_by_id[eid]['sequence']} " in text, True)
        save(folder / "07_provenance_trace.json", trace)

        completed = command(["-m", "attack_mapping.cli", folder / "01_investigation_result.json",
                             "--out-dir", folder / "cli"], folder / "cli_process")
        self.check(name + ":default_cli_exit", completed.returncode, 1 if status == "error" else 0)
        stem = source["incident_id"]
        mapping_path = folder / "cli" / f"{stem}_attack_mapping.json"
        report_path = folder / "cli" / f"{stem}_final_report.json"
        self.check(name + ":cli_files_exist", mapping_path.exists() and report_path.exists(), True)
        if mapping_path.exists() and report_path.exists():
            self.check(name + ":cli_mapping_equals_direct", load(mapping_path), augmented)
            self.check(name + ":cli_report_equals_direct", load(report_path), report)
        save(folder / "expected.json", {"mapping_status": status, "technique_ids": sorted(ids),
                                         "unmatched": list(unmatched), "excluded": list(excluded),
                                         "kill_chain": chain_ids})
        row = {"name": name, "mapping_status": mapping["mapping_status"],
               "provenance_status": mapping["provenance_status"], "technique_count": len(mapping["techniques"]),
               "verdict_hits_before_gates": len(verdict_hits), "evidence_hits_before_gates": len(evidence_hits),
               "unmatched": mapping["unmatched_evidence_ids"], "excluded": mapping["excluded_evidence_ids"],
               "passed": all(c["passed"] for c in self.checks[first_check:])}
        self.scenarios.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
        return mapping, chain

    def boundaries(self, base):
        folder = self.output / "boundaries"
        folder.mkdir()
        # Even the deliberately escaped path stays inside this new verification
        # directory. No existing user outputs are targeted.
        batch = folder / "same_incident" / "inputs"
        for index in (1, 2):
            payload = deepcopy(base)
            payload["investigation_id"] = f"INV-REPEAT-{index}"
            save(batch / f"{index}.json", payload)
        out = batch.parent / "out"
        completed = command(["-m", "attack_mapping.cli", "--all-in-dir", batch, "--out-dir", out],
                            batch.parent / "process")
        reports = list(out.glob("*_final_report.json"))
        self.check("boundary:same_incident_keeps_both_investigations", len(reports), 2)
        save(batch.parent / "observation.json", {"exit_code": completed.returncode, "report_count": len(reports),
            "retained_investigations": [load(path)["investigation_id"] for path in reports]})

        bad_batch = folder / "non_object" / "inputs"
        save(bad_batch / "a.json", [])
        save(bad_batch / "b.json", base)
        out = bad_batch.parent / "out"
        completed = command(["-m", "attack_mapping.cli", "--all-in-dir", bad_batch, "--out-dir", out],
                            bad_batch.parent / "process")
        self.check("boundary:non_object_json_does_not_abort_next_file",
                   (out / f"{base['incident_id']}_final_report.json").exists(), True)
        save(bad_batch.parent / "observation.json", {"exit_code": completed.returncode,
             "last_error": completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else None})

        escape = folder / "path_escape"
        payload = deepcopy(base)
        payload["incident_id"] = "../escaped-proof"
        save(escape / "input.json", payload)
        command(["-m", "attack_mapping.cli", escape / "input.json", "--out-dir", escape / "requested"],
                escape / "process")
        self.check("boundary:output_stays_in_requested_directory",
                   not (escape / "escaped-proof_final_report.json").exists(), True)
        save(escape / "observation.json", {
            "requested_directory": str(escape / "requested"),
            "actual_json_files": [str(path.relative_to(escape)) for path in escape.rglob("*.json")
                                  if path.name.endswith(("_attack_mapping.json", "_final_report.json"))],
        })

        time_folder = folder / "timezone"
        payload = synthetic_result(time_folder, "timezones", [
            ("shell.php", "2026-09-26T09:00:00+09:00", 1),
            ("/root/.ssh/authorized_keys", "2026-09-26T01:00:00Z", 1),
        ])
        save(time_folder / "input.json", payload)
        chain = build_kill_chain(map_investigation(payload, ALL_RULES)["techniques"])
        save(time_folder / "actual_kill_chain.json", chain)
        self.check("boundary:timezone_aware_order", [s["technique_id"] for s in chain], ["T1505.003", "T1098.004"])
        payload["evidence_chain"][1]["description"] = "shell.php"
        save(time_folder / "same_technique_input.json", payload)
        chain = build_kill_chain(map_investigation(payload, ALL_RULES)["techniques"])
        save(time_folder / "same_technique_actual.json", chain)
        self.check("boundary:timezone_aware_representative_time", chain[0]["time"], "2026-09-26T09:00:00+09:00")

    def finish(self, metadata):
        failed = [c for c in self.checks if not c["passed"]]
        summary = {**metadata, "scenarios": self.scenarios, "checks": len(self.checks),
                   "passed": len(self.checks) - len(failed), "failed": len(failed),
                   "failures": failed, "fully_passed": not failed}
        save(self.output / "summary.json", summary)
        save(self.output / "checks.json", self.checks)
        report = [
            "# ATT&CK A/B/C 연결 검증 결과", "",
            f"검증 커밋: {metadata['commit']} / Python {metadata['python']}", "",
            f"실제 Catalog: {len(ALL_RULES)}개 규칙. 추가 검증 {len(self.checks)}개 중 "
            f"{len(self.checks) - len(failed)}개 통과, {len(failed)}개 실패.", "",
            "실패가 하나라도 있으면 검증 스크립트는 종료 코드 1을 반환합니다. "
            "기존 pytest 통과와 전체 기능의 무결함을 같은 의미로 취급하지 않습니다.", "",
            "## 실행 방법", "",
            "프로젝트 루트에서 .\\.venv\\Scripts\\python.exe -m scripts.verify_attack_mapping_abc를 실행합니다. "
            "매 실행마다 results 아래 새 폴더를 만들며 기존 결과를 덮어쓰지 않습니다.", "",
            "1. 관련 pytest와 전체 pytest를 별도 프로세스로 실행하고 명령·stdout·stderr를 저장했습니다.",
            "2. 합성 로그의 실제 파일·물리 줄 번호와 Evidence를 만들고, 실제 AgentState와 "
            "build_investigation_result()로 Investigation 출력 계약을 생성했습니다.",
            "3. B의 실제 ALL_RULES를 import하여 A의 match_verdict()/match_evidence() 원시 hit을 저장했습니다. "
            "이 두 helper에는 gate가 없으므로 정책 적용 후 결과는 04_engine_result.json을 봐야 합니다.",
            "4. map_investigation()으로 gate·중복 병합·unmatched/excluded 처리를 검증했습니다. "
            "매칭의 Evidence ID → raw_refs → raw_ref_locations → 합성 파일 실제 줄까지 대조했습니다.",
            "5. C의 build_kill_chain(), build_final_report()를 실행했습니다. 이후 rules 인자를 주입하지 않은 "
            "python -m attack_mapping.cli 하위 프로세스로 같은 입력을 처리하고 JSON 전체를 비교했습니다.",
            "6. 기존 demo_abcd도 새 출력 경로에서 실행했습니다. 실제 정규화·조사 도구·루프가 만든 결과를 "
            "CLI에 연결했으며, LLM만 고정 응답입니다. 원래 INCONCLUSIVE 판정을 그대로 유지했습니다.",
            "7. 별도 새 폴더에서 기존 C 오류의 회귀 여부를 검사했습니다. 경로 이탈 테스트도 이 검증 폴더 안에서만 파일을 만듭니다.", "",
            "## 범위", "",
            "AWS·LLM API·실제 운영 로그를 사용하지 않았습니다. 공격 명령 문자열은 합성 데이터로만 저장하며 "
            "실행하지 않습니다. 이 검증은 모듈 연결과 명시한 fixture의 결과를 확인하며 실제 탐지 정확도나 "
            "운영 환경 전체를 평가하지 않습니다. 구현·규칙을 수정하거나 실패를 xfail로 숨기지 않았습니다.", "",
            "## 단계별 결과", "",
            "| 사건 | provenance | mapping_status | Technique 수 | 결과 |",
            "|---|---|---|---:|---|",
        ]
        for row in self.scenarios:
            report.append(f"| [{row['name']}](scenarios/{row['name']}/04_engine_result.json) | "
                          f"{row['provenance_status']} | {row['mapping_status']} | {row['technique_count']} | "
                          f"{'PASS' if row['passed'] else 'FAIL'} |")
        multi_dir = self.output / "scenarios" / "multistage"
        source = load(multi_dir / "01_investigation_result.json")
        mapping = load(multi_dir / "04_engine_result.json")
        chain = load(multi_dir / "05_kill_chain.json")
        report += ["", "## 다단계 사건의 중간 결과", "",
                   "B의 ALL_RULES → A의 매칭·gate·병합 → C의 Kill Chain → C의 CLI 저장·최종 보고서 순으로 연결했습니다.",
                   "이 사건은 verdict hit 2건 + evidence hit 7건을 Technique 6개로 병합합니다. "
                   "C의 정렬은 Tactic 순서를 우선하고 같은 Tactic 안에서 시간을 비교합니다.", "",
                   "| Evidence | 설명 | 시각 | 매핑 Technique | 원본 참조 |",
                   "|---|---|---|---|---|"]
        for ev in source["evidence_chain"]:
            tids = [t["technique_id"] for t in mapping["techniques"] if ev["evidence_id"] in t["evidence_ids"]]
            report.append(f"| {ev['evidence_id']} | {ev['description']} | {ev['time']} | "
                          f"{', '.join(tids) or 'unmatched'} | {', '.join(ev['raw_refs'])} |")
        report += ["", "반박 Evidence EVID-009에는 failed password 키워드를 넣었지만 T1110을 생성하지 않았습니다. "
                   "EVID-003·004의 웹셸은 T1505.003 한 건으로 합쳐졌고, 두 Evidence와 두 원본 줄을 모두 보존했습니다. "
                   "EVID-002의 원본 2줄도 유지했습니다.", "",
                   "| Step | Tactic | Technique | 대표 시각 | Evidence |", "|---:|---|---|---|---|"]
        for step in chain:
            report.append(f"| {step['step']} | {step['tactic_name']} | {step['technique_id']} | "
                          f"{step['time']} | {', '.join(step['evidence_ids'])} |")
        report += ["", "[입력](scenarios/multistage/01_investigation_result.json) → "
                   "[A 결과](scenarios/multistage/04_engine_result.json) → "
                   "[C Kill Chain](scenarios/multistage/05_kill_chain.json) → "
                   "[실제 CLI 최종 보고서](scenarios/multistage/cli/INC-MULTISTAGE_final_report.json)", "",
                   "[원본 추적표](scenarios/multistage/07_provenance_trace.json)에는 실제 합성 파일에서 읽은 줄 내용까지 남겼습니다.", "",
                   "## provenance가 incomplete인 사건", "",
                   "- EVID-001: 정상 참조가 있는 shell.php 근거 → T1505.003 생성.",
                   "- EVID-002: raw_refs 없음 → 제외.",
                   "- EVID-003: 정상 참조 일부가 남았지만 upstream unknown_raw_refs 오류가 있음 → 제외.",
                   "- EVID-004: 같은 raw_ref에 원본 위치가 둘임 → 제외.",
                   "- EVID-005: 정상 참조가 있지만 Catalog에 없는 heartbeat → unmatched.",
                   "- attack_type에 brute force / reverse shell이 있어도 verdict 단독 hit을 채택하지 않음.",
                   "- 결과: partial, Technique 1개, excluded 3개, unmatched 1개.",
                   "", "[incomplete의 A 결과](scenarios/incomplete/04_engine_result.json)", ""]
        report += ["", "각 사건 폴더의 파일 순서:", "",
                   "- 01: 실제 Investigation 출력 형식의 입력", "- 02, 03: gate 적용 전 개별 매칭",
                   "- 04: A의 최종 매핑 결과", "- 05: C의 Kill Chain", "- 06: C의 최종 보고서",
                   "- 07: Technique부터 합성 원본 줄까지의 추적표", "- cli/: 실제 CLI가 저장한 결과",
                   "- cli_process/: 실행 명령, 종료 코드, stdout, stderr", "",
                   "## 검증 로그와 실패", "",
                   "[관련 pytest](pytest_related/stdout.txt) · [전체 pytest](pytest_full/stdout.txt) · "
                   "[기존 오프라인 데모](upstream_demo/process/stdout.txt) · [전체 검사](checks.json)", ""]
        for item in failed:
            report += [f"- **{item['name']}**: 기대 {item['expected']!r}, 실제 {item['actual']!r}"]
        boundary_checks = [item for item in self.checks if item["name"].startswith("boundary:")]
        report += ["", "기존 C 경계 사례의 현재 검사 결과:", "",
                   f"{len(boundary_checks)}개 중 {sum(item['passed'] for item in boundary_checks)}개 통과.", ""]
        for item in boundary_checks:
            report.append(f"- {'PASS' if item['passed'] else 'FAIL'} **{item['name']}**: "
                          f"기대 {item['expected']!r}, 실제 {item['actual']!r}")
        if not failed:
            report.append("이번 실행에서 실패한 검사는 없습니다.")
        report += ["", "경계 사례 입력·출력·오류는 boundaries/ 아래에 보존되어 있습니다.", ""]
        (self.output / "report.md").write_text("\n".join(report), encoding="utf-8")
        print(f"RESULT {summary['passed']} passed / {summary['failed']} failed; artifacts: {self.output}", flush=True)
        return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, help="New artifact directory; must not exist")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = (args.out_dir or ROOT / "results" / f"attack_mapping_abc_{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    verify = Verification(output)
    metadata = {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "python": platform.python_version(), "created_at_utc": stamp, "output": str(output),
                "mapping_table_version": mapping_table_version(ALL_RULES), "rule_count": len(ALL_RULES)}
    metadata["verifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (output / "verify_attack_mapping_abc.py").write_bytes(Path(__file__).read_bytes())
    save(output / "catalog.json", [asdict(rule) for rule in ALL_RULES])
    save(output / "metadata.json", metadata)
    for label, files in (("pytest_related", RELATED_TESTS), ("pytest_full", [])):
        completed = command(["-m", "pytest", "-q", *files], output / label)
        verify.check(label + ":exit", completed.returncode, 0)
        print(label + ": " + completed.stdout.strip().splitlines()[-1], flush=True)
    verify.check("catalog:unique_techniques", len({r.technique_id for r in ALL_RULES}), 13)
    verify.check("catalog:order_independent_version", mapping_table_version(reversed(ALL_RULES)), metadata["mapping_table_version"])

    def build(name, rows, **kwargs):
        return synthetic_result(output / "scenarios" / name, name, rows, **kwargs)

    multi = build("multistage", [
        ("업로드 취약점 악용", "2026-09-26T10:01:00Z", 1),
        ("reverse shell", "2026-09-26T10:03:00Z", 2),
        ("shell.php", "2026-09-26T10:02:00Z", 1),
        ("Possible PHP Webshell", "2026-09-26T10:04:00Z", 1),
        ("/root/.ssh/authorized_keys", "2026-09-26T10:05:00Z", 1),
        ("tar -czf", "2026-09-26T10:06:00Z", 1),
        ("기존 C2 채널로 curl -T sample.txt 전송", "2026-09-26T10:07:00Z", 1),
        ("fixture heartbeat observed", "2026-09-26T10:08:00Z", 1),
    ], attack_type="Web Shell / reverse shell", contradicting=[("failed password", None, 1)])
    ids = ["T1190", "T1059.004", "T1505.003", "T1098.004", "T1560", "T1041"]
    mapping, chain = verify.scenario("multistage", multi, "mapped", ids, unmatched=["EVID-008"], chain_ids=ids)
    shell = next(t for t in mapping["techniques"] if t["technique_id"] == "T1505.003")
    verify.check("multistage:merged_shell_evidence", shell["evidence_ids"], ["EVID-003", "EVID-004"])
    verify.check("multistage:merged_shell_sources", shell["matched_by"], ["verdict", "evidence"])
    verify.check("multistage:merged_shell_refs", shell["raw_refs"], ["synthetic.log:4", "synthetic.log:5"])
    folder = output / "scenarios" / "multistage"
    command(["-m", "attack_mapping.cli", folder / "01_investigation_result.json", "--out-dir", folder / "cli_repeat"],
            folder / "cli_repeat_process", hash_seed="42")
    verify.check("multistage:separate_process_reproducibility",
                 load(folder / "cli_repeat" / "INC-MULTISTAGE_attack_mapping.json"), {**mapping, "kill_chain": chain})

    partial = build("incomplete", [
        ("shell.php", "2026-09-26T10:01:00Z", 1), ("reverse shell", None, 0),
        ("failed password", None, 1), ("/root/.ssh/authorized_keys", None, 1),
        ("fixture heartbeat observed", None, 1),
    ], attack_type="brute force / reverse shell", invalid_sequences=[3], ambiguous_sequences=[4])
    mapping, _ = verify.scenario("incomplete", partial, "partial", ["T1505.003"],
                                 unmatched=["EVID-005"], excluded=["EVID-002", "EVID-003", "EVID-004"], chain_ids=["T1505.003"])
    verify.check("incomplete:no_verdict_contribution", mapping["techniques"][0]["matched_by"], ["evidence"])

    for name, verdict, expected in (("false_positive", "FALSE_POSITIVE", "not_applicable"),
                                    ("inconclusive", "INCONCLUSIVE", "deferred"),
                                    ("unknown_verdict", "UNKNOWN", "error")):
        payload = build(name, [("shell.php", None, 1)], verdict=verdict, attack_type="Web Shell")
        verify.scenario(name, payload, expected, [], chain_ids=[])
    verify.scenario("unavailable", build("unavailable", [], attack_type="Web Shell"), "deferred", [], chain_ids=[])
    verify.scenario("unmatched", build("unmatched", [("fixture heartbeat", None, 1)]),
                    "no_techniques_matched", [], unmatched=["EVID-001"], chain_ids=[])
    verify.scenario("all_excluded", build("all_excluded", [("shell.php", None, 0)], attack_type="Web Shell"),
                    "no_techniques_matched", [], excluded=["EVID-001"], chain_ids=[])
    mapping, chain = verify.scenario("verdict_only", build("verdict_only", [], attack_type="Web Shell", seed_reference=True),
                                     "mapped", ["T1505.003"], chain_ids=["T1505.003"])
    verify.check("verdict_only:no_invented_citation", mapping["techniques"][0]["raw_refs"], [])
    verify.check("verdict_only:no_invented_time", chain[0]["time"], None)

    catalog_examples = [
        ("T1110", "FAILED PASSWORD"), ("T1078", "브루트포스 성공 후 로그인"),
        ("T1190", "public-facing application exploit"), ("T1505.003", "SHELL.PHP"),
        ("T1595", "path scan"), ("T1059.004", "REVERSE SHELL"), ("T1105", "/usr/bin/wget"),
        ("T1098.004", "/root/.ssh/authorized_keys"), ("T1053.003", "beacon.sh"),
        ("T1136.001", "useradd"), ("T1548.001", "SUID find"), ("T1560", "tar -czf"),
        ("T1041", "기존 C2 채널로 curl -T sample.txt 전송"),
    ]
    payload = build("catalog_coverage", [(text, f"2026-09-26T10:{index:02d}:00Z", 1)
                                        for index, (_, text) in enumerate(catalog_examples, start=1)])
    verify.scenario("catalog_coverage", payload, "mapped", [tid for tid, _ in catalog_examples], chain_ids=[
        "T1595", "T1078", "T1190", "T1059.004", "T1505.003", "T1098.004", "T1053.003",
        "T1136.001", "T1548.001", "T1110", "T1560", "T1105", "T1041",
    ])

    for name, description in (
        ("exfiltration_without_c2", "외부 서버로 전송. C2 연관성은 미확인"),
        ("curl_telnet_option", "curl -t TTYPE=vt100 telnet://example.invalid (known C2 channel)"),
    ):
        verify.scenario(name, build(name, [(description, None, 1)]), "no_techniques_matched", [],
                        unmatched=["EVID-001"], chain_ids=[])
    verify.scenario("mixed_assertions", build("mixed_assertions", [
        ("reverse shell 연결은 확인됐으나 웹셸 실행은 확인되지 않았음", None, 1),
    ]), "mapped", ["T1059.004"], chain_ids=["T1059.004"])

    demo = output / "upstream_demo"
    completed = command(["-m", "scripts.demo_abcd", "--output", demo / "demo.json"], demo / "process")
    verify.check("upstream_demo:exit", completed.returncode, 0)
    if completed.returncode == 0:
        # The original verdict remains INCONCLUSIVE, hence no evidence matches
        # reach C and no synthetic line-format assumptions apply to these refs.
        verify.scenario("upstream_demo", load(demo / "demo.json")["results"][0], "deferred", [], chain_ids=[])

    distinct = output / "batch_distinct"
    save(distinct / "inputs" / "a.json", multi)
    save(distinct / "inputs" / "b.json", load(output / "scenarios" / "false_positive" / "01_investigation_result.json"))
    completed = command(["-m", "attack_mapping.cli", "--all-in-dir", distinct / "inputs", "--out-dir", distinct / "out"],
                        distinct / "process")
    verify.check("batch_distinct:exit", completed.returncode, 0)
    verify.check("batch_distinct:report_count", len(list((distinct / "out").glob("*_final_report.json"))), 2)
    verify.boundaries(multi)
    return verify.finish(metadata)


if __name__ == "__main__":
    raise SystemExit(main())
