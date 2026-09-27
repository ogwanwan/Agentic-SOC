"""main.py [46]: 조사 결과 JSON 저장 직후 ATT&CK 매핑까지 이어지는지 (API 키 불필요).

조사 결과는 agent/report.py의 build_investigation_result()로 만들어, 실제 main.py가
저장하는 것과 같은 형식으로 어택 매핑 팀 규칙(ALL_RULES)을 통과시킨다.
"""
import json

import main
from agent.models import AgentState, Evidence
from agent.report import build_investigation_result


def investigation(verdict="THREAT_CONFIRMED", incident_id="INC-MAIN-01"):
    state = AgentState(incident_id=incident_id, seed={"raw_refs": ["web.log:10", "audit.log:3"]})
    state.raw_refs = ["web.log:10", "audit.log:3"]
    state.raw_ref_locations = {ref: [f"/var/log/{ref}"] for ref in state.raw_refs}
    state.add_evidence(Evidence(
        evidence_id="EVID-001", sequence=1, time="2026-09-27T01:00:05Z", layer="web",
        event_type="http_request", description="203.0.113.7이 shell.php에 cmd= 파라미터로 요청",
        source_log="web.log", raw_refs=["web.log:10"],
    ))
    state.add_evidence(Evidence(
        evidence_id="EVID-002", sequence=2, time="2026-09-27T01:02:00Z", layer="audit",
        event_type="process_exec", description="www-data가 /dev/tcp/203.0.113.7/4444로 역방향 셸 실행",
        source_log="audit.log", raw_refs=["audit.log:3"],
    ))
    return build_investigation_result(
        state, "no_more_evidence", {"verdict": verdict, "attack_type": "웹셸"}, f"INV-{incident_id}",
    )


def test_saved_investigation_is_mapped_into_kill_chain_and_final_report(tmp_path):
    source = investigation()
    saved = main.save_investigation_result(source, str(tmp_path))
    out_dir = tmp_path / "attack_mapping"

    mapping = main.run_attack_mapping(saved, str(out_dir))

    assert mapping["mapping_status"] == "mapped"
    assert [step["technique_id"] for step in mapping["kill_chain"]] == ["T1059.004", "T1505.003"]
    assert sorted(p.name for p in out_dir.iterdir()) == [
        "INC-MAIN-01_attack_mapping.json", "INC-MAIN-01_final_report.json"]
    assert sorted(mapping["output_paths"]) == sorted(str(p) for p in out_dir.iterdir())
    report = json.loads((out_dir / "INC-MAIN-01_final_report.json").read_text(encoding="utf-8"))
    assert {k: v for k, v in report.items() if k != "attack_mapping"} == source
    assert report["attack_mapping"]["kill_chain"] == mapping["kill_chain"]

    text = main.format_attack_mapping(mapping)
    assert "ATT&CK Mapping: mapped" in text
    assert "1. [Execution] T1059.004" in text and "2. [Persistence] T1505.003" in text
    assert "EVID-002" in text


def test_false_positive_is_saved_as_not_applicable(tmp_path):
    saved = main.save_investigation_result(investigation("FALSE_POSITIVE"), str(tmp_path))
    mapping = main.run_attack_mapping(saved, str(tmp_path / "attack_mapping"))
    assert mapping["mapping_status"] == "not_applicable"
    assert mapping["kill_chain"] == []
    assert len(mapping["output_paths"]) == 2
    assert "매핑 안 함" in main.format_attack_mapping(mapping)


def test_reinvestigated_incident_keeps_earlier_mapping_files(tmp_path):
    out_dir = tmp_path / "attack_mapping"
    first = main.run_attack_mapping(main.save_investigation_result(investigation(), str(tmp_path)), str(out_dir))
    second = main.run_attack_mapping(main.save_investigation_result(investigation(), str(tmp_path)), str(out_dir))
    assert len(list(out_dir.iterdir())) == 4
    assert all("__2" not in path for path in first["output_paths"])
    assert all("__2" in path for path in second["output_paths"])


def test_verified_empty_result_evidence_keeps_verdict_mapping(tmp_path):
    # EC2 XML-RPC 사건처럼 기법이 판정 문구로만 붙는 경우, "0건 → 활동 없음" 증거 하나 때문에
    # provenance가 incomplete면 판정 문구 매칭이 꺼져 기법이 0개가 된다. 확인된 0건 증거는 막지 않는다.
    def run(empty_result_call):
        state = AgentState(incident_id="INC-XMLRPC", seed={"raw_refs": ["web.log:1"]})
        state.raw_refs = ["web.log:1"]
        state.add_evidence(Evidence(
            evidence_id="EVID-101", sequence=1, time="2026-09-27T04:31:11Z", layer="web", event_type="web_access",
            description="/xmlrpc.php 경로로 POST 요청 150건", source_log="web.log", raw_refs=["web.log:1"]))
        state.add_evidence(Evidence(
            evidence_id="EVID-102", sequence=2, time=None, layer="network", event_type="none",
            description="network 조회 0건 — 추가 통신 없음", source_log="", empty_result_call=empty_result_call))
        source = build_investigation_result(
            state, "no_more_evidence", {"verdict": "THREAT_CONFIRMED", "attack_type": "웹 인증 무차별 대입"}, "INV-X")
        saved = main.save_investigation_result(source, str(tmp_path))
        return main.run_attack_mapping(saved, str(tmp_path / "attack_mapping"))

    verified = run(2)
    assert verified["provenance_status"] == "passed" and verified["mapping_status"] == "mapped"
    assert [t["technique_id"] for t in verified["techniques"]] == ["T1110"]
    unverified = run(None)
    assert unverified["provenance_status"] == "incomplete"
    assert unverified["mapping_status"] == "no_techniques_matched"


def test_mapping_failure_does_not_stop_main(tmp_path, capsys):
    broken = tmp_path / "broken.json"
    broken.write_text("[]", encoding="utf-8")
    out_dir = tmp_path / "attack_mapping"
    assert main.run_attack_mapping(str(broken), str(out_dir)) is None
    assert "매핑 실패" in capsys.readouterr().out
    assert not out_dir.exists() or not list(out_dir.iterdir())
