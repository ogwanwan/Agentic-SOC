"""D: incident refs -> tools -> evidence -> JSON report."""
import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from agent.loop import InvestigationAgent
from agent.models import AgentState
from agent.prompts import build_user_prompt
from agent.provenance import references
from agent.tools.log_source import LOCAL_PATH_ENV
from agent.tools.registry import ToolRegistry, ToolSpec, build_default_registry

from tests.test_event_window import WINDOW, local_log, web_line


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for name in [*LOCAL_PATH_ENV.values(), "HOST", "LOG_LOCAL_HOST"]:
        monkeypatch.delenv(name, raising=False)


class ScriptedInvestigator:
    def __init__(self, decisions):
        self.decisions = iter(decisions)
        self.prompts = []

    def reason(self, state, registry, **kwargs):
        self.prompts.append(build_user_prompt(state))
        decision = next(self.decisions)
        return decision(state) if callable(decision) else deepcopy(decision)


def terminate(evidence=None):
    return {"next_action": "terminate", "termination_reason": "no_more_evidence",
            "new_evidence": evidence or [], "final_verdict": {
                "verdict": "INCONCLUSIVE", "confidence": 0.5, "severity": "LOW", "attack_type": "test"}}


def evidence(**kwargs):
    return {"description": "observed log", "layer": "web", "source_log": "web.log",
            "confidence_contribution": 0.2, **kwargs}


def test_seed_and_supporting_contradicting_evidence_reach_reports(tmp_path, monkeypatch):
    path = local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    ref = f"{path}:1"
    seed = {"incident_id": "INC-CD", "host": "web-01", "window": WINDOW,
            "layer": "web", "evidence_refs": [ref], "confidence_initial": 0.3}
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {}}},
        terminate([evidence(raw_ref=ref), evidence(raw_refs=[ref], contradicting=True)]),
    ])
    result = InvestigationAgent(llm, build_default_registry()).run(seed)
    assert result["provenance"]["status"] == "passed"
    assert result["initial_seed"]["evidence_refs"] == [ref]
    assert result["tools_called"][0]["raw_refs"] == [ref]
    assert result["raw_refs"] == [ref]
    for name in ("evidence_chain", "contradicting_evidence"):
        assert result[name][0]["raw_ref"] == ref and result[name][0]["raw_refs"] == [ref]
    assert json.loads(json.dumps(result))["raw_refs"] == [ref]
    assert '"known_raw_refs"' in llm.prompts[-1]


def test_audit_all_lines_survive_a_single_representative_citation(tmp_path, monkeypatch):
    epoch = int(datetime(2026, 9, 21, tzinfo=timezone.utc).timestamp())
    path = local_log(tmp_path, monkeypatch, "audit",
        f'type=SYSCALL msg=audit({epoch}.1:1): pid=5 syscall=59\n'
        f'type=EXECVE msg=audit({epoch}.1:1): argc=1 a0="id"\n')
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {"layers": ["system"]}}},
        terminate([evidence(raw_ref=f"{path}:1", layer="system")]),
    ])
    result = InvestigationAgent(llm, build_default_registry()).run({
        "incident_id": "AUDIT", "host": "web-01", "window": WINDOW})
    assert result["evidence_chain"][0]["raw_refs"] == [f"{path}:1", f"{path}:2"]


@pytest.mark.parametrize("citation", [{"raw_refs": ["invented:1"]}, {"raw_refs": ["source:1", "invented:1"]}])
def test_fabricated_refs_fail_validation_and_do_not_increase_confidence(citation):
    seed = {"incident_id": "BAD", "raw_ref": "source:1", "confidence_initial": 0.3}
    llm = ScriptedInvestigator([terminate([evidence(**citation)])])
    result = InvestigationAgent(llm, ToolRegistry()).run(seed)
    assert result["provenance"]["status"] == "incomplete"
    assert result["statistics"]["confidence_increase"] == 0
    assert "invented:1" not in result["raw_refs"]
    assert "invented:1" not in result["evidence_chain"][0]["raw_refs"]


@pytest.mark.parametrize("citation", [{}, {"raw_refs": "not-a-list"}])
def test_missing_or_malformed_refs_keep_confidence_but_mark_provenance_incomplete(citation):
    # 2026-09-24: LLM이 raw_ref 복사를 빠뜨린 것만으로 기여를 0으로 만들면 판정 재현성이
    # 무너져서, 기여는 반영하고 provenance에만 미완료로 남긴다(지어낸 참조는 위 테스트대로 0).
    seed = {"incident_id": "MISSING", "raw_ref": "source:1", "confidence_initial": 0.3}
    llm = ScriptedInvestigator([terminate([evidence(**citation)])])
    result = InvestigationAgent(llm, ToolRegistry()).run(seed)
    assert result["provenance"]["status"] == "incomplete"
    assert result["statistics"]["confidence_increase"] == pytest.approx(0.2)
    assert result["evidence_chain"][0]["raw_refs"] == []


def test_recited_raw_refs_do_not_count_twice():
    # 2026-09-24: 종료 거부 후 같은 로그를 다시 인용한 evidence로 임계값을 채우던 사례 방지
    seed = {"incident_id": "DUP", "raw_ref": "source:1", "confidence_initial": 0.3}
    llm = ScriptedInvestigator([terminate([evidence(raw_refs=["source:1"]),
                                           evidence(raw_refs=["source:1"], description="same fact again")])])
    result = InvestigationAgent(llm, ToolRegistry()).run(seed)
    assert result["statistics"]["confidence_increase"] == pytest.approx(0.2)
    assert [e["confidence_contribution"] for e in result["evidence_chain"]] == [0.2, 0.0]


def test_legacy_uncited_results_are_not_marked_validated():
    result = InvestigationAgent(ScriptedInvestigator([terminate()]), ToolRegistry()).run({"incident_id": "LEGACY"})
    assert result["provenance"]["status"] == "unavailable"


def test_opaque_external_seed_ref_is_not_rewritten():
    ref = "apache_access.log:88213"
    result = InvestigationAgent(ScriptedInvestigator([terminate([evidence(raw_ref=ref)])]), ToolRegistry()).run({
        "incident_id": "UPSTREAM", "evidence_refs": [ref]})
    assert result["raw_refs"] == [ref]
    assert result["evidence_chain"][0]["raw_ref"] == ref


def test_failed_tool_does_not_discard_already_observed_refs():
    registry = ToolRegistry()
    registry.register(ToolSpec("ok", "", [], handler=lambda args: {"count": 1, "records": [{"raw_ref": "input:1"}]}))
    def fail(args):
        raise OSError("offline")
    registry.register(ToolSpec("fail", "", [], handler=fail))
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "ok"}},
        {"next_action": "call_tool", "tool_call": {"tool_name": "fail"}},
        terminate([evidence(raw_ref="input:1")]),
    ])
    result = InvestigationAgent(llm, registry).run({"incident_id": "RETRY"})
    assert result["raw_refs"] == ["input:1"] and result["provenance"]["status"] == "passed"
    assert result["tools_called"][1]["error"] == "offline"


def _empty_result_run(empty_result_call):
    """도구 1: 결과 있음(input:1), 도구 2: 0건, 도구 3: 실패. 0건 증거가 empty_result_call을 인용."""
    registry = ToolRegistry()
    registry.register(ToolSpec("found", "", [], handler=lambda args: {"count": 1, "records": [{"raw_ref": "input:1"}]}))
    registry.register(ToolSpec("empty", "", [], handler=lambda args: {"count": 0, "records": []}))
    def fail(args):
        raise OSError("offline")
    registry.register(ToolSpec("fail", "", [], handler=fail))
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "found"}},
        {"next_action": "call_tool", "tool_call": {"tool_name": "empty"}},
        {"next_action": "call_tool", "tool_call": {"tool_name": "fail"}},
        terminate([evidence(raw_ref="input:1"),
                   evidence(description="empty 조회 0건 — 후속 활동 없음", confidence_contribution=0.05,
                            empty_result_call=empty_result_call)]),
    ])
    return InvestigationAgent(llm, registry).run({"incident_id": "EMPTY"}), llm


def test_verified_empty_result_evidence_keeps_provenance_passed():
    # 2026-09-27: "조회 0건 → 활동 없음" 증거가 원본 누락으로 세져 provenance가 incomplete가 되던 문제.
    # 성공한 0건 호출로 확인되면 누락이 아니다.
    result, llm = _empty_result_run(2)
    assert result["provenance"]["status"] == "passed"
    assert result["provenance"]["evidence_without_raw_refs"] == []
    empty = result["evidence_chain"][1]
    assert empty["raw_refs"] == [] and empty["empty_result_call"] == 2
    assert result["provenance"]["empty_result_evidence"] == [empty["evidence_id"]]
    assert result["evidence_chain"][0]["empty_result_call"] is None
    assert result["statistics"]["confidence_increase"] == pytest.approx(0.25)  # 기여는 그대로 반영
    assert '"sequence": 2' in llm.prompts[2]  # LLM이 보는 관측에 호출 번호가 있다


@pytest.mark.parametrize("claimed", [1, 3, 9, "x", True])  # 결과 있음 / 실패 / 없는 호출 / 형식 오류
def test_unverified_empty_result_evidence_stays_incomplete(claimed):
    result, _ = _empty_result_run(claimed)
    assert result["provenance"]["status"] == "incomplete"
    empty = result["evidence_chain"][1]
    assert empty["empty_result_call"] is None
    assert result["provenance"]["evidence_without_raw_refs"] == [empty["evidence_id"]]
    assert result["statistics"]["confidence_increase"] == pytest.approx(0.25)


def test_process_tree_refs_and_multiline_groups(tmp_path, monkeypatch):
    epoch = int(datetime(2026, 9, 21, tzinfo=timezone.utc).timestamp())
    path = local_log(tmp_path, monkeypatch, "audit",
        f'type=SYSCALL msg=audit({epoch}.1:1): pid=5 ppid=0 syscall=59\n'
        f'type=EXECVE msg=audit({epoch}.1:1): argc=1 a0="id"\n')
    state = AgentState(incident_id="TREE", seed={})
    agent = InvestigationAgent(None, build_default_registry())
    agent._execute_tool_call(state, {"tool_name": "get_process_tree", "args": {
        "host": "web-01", "pid": 5, "start_time": WINDOW[0], "end_time": WINDOW[1]}})
    assert state.raw_refs == [f"{path}:1", f"{path}:2"]


def test_multilayer_window_tool_satisfies_existing_network_gate(tmp_path, monkeypatch):
    local_log(tmp_path, monkeypatch, "web", web_line(WINDOW[0]))
    local_log(tmp_path, monkeypatch, "network", json.dumps({
        "timestamp": WINDOW[0], "event_type": "http", "src_ip": "192.0.2.10"}))
    decision = terminate()
    decision["termination_reason"] = "confidence_sufficient"
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "fetch_event_logs", "args": {"layers": ["web", "network"]}}},
        decision,
    ])
    result = InvestigationAgent(llm, build_default_registry()).run({
        "incident_id": "MULTI", "window": WINDOW, "host": "web-01", "src_ip": "192.0.2.10", "confidence_initial": 0.9})
    assert result["statistics"]["termination_reason"] == "confidence_sufficient"
    assert not any("종료 거부" in note for note in result["investigation_notes"])
