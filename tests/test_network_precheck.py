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
    assert filtered_out_hint(0, {"event_type": "x"}, ("event_type",)) == ""
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
