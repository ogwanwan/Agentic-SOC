"""run_investigation_pipeline(agent/pipeline.py) 통합 테스트.

실제 로그/LLM 없이, 1차 탐지가 만든 사건 파일(tests/fixtures/primary_detection_incidents.jsonl)을
읽어 사건마다 조사 루프가 받은 순서대로 한 번씩 도는지 확인한다(조사 루프 자체 검증은 tests/test_loop.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from agent.incident_input import load_incidents
from agent.pipeline import run_investigation_pipeline
from agent.tools import ToolRegistry

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "primary_detection_incidents.jsonl"


class _ImmediateTerminateLLM:
    """조사 루프 첫 턴에 바로 종료하는 가짜 클라이언트. 받은 사건을 기록한다."""

    def __init__(self) -> None:
        self.seeds = []

    def reason(self, state: Any, tool_registry: Any, **kwargs: Any) -> Dict[str, Any]:
        self.seeds.append(state.seed)
        return {
            "facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [],
            "next_action": "terminate", "tool_call": None,
            "termination_reason": "no_more_evidence", "attack_timeline": [],
            "final_verdict": {
                "verdict": "INCONCLUSIVE", "confidence": state.current_confidence, "severity": "LOW",
                "attack_type": "unknown", "affected_systems": [], "summary": "테스트용 즉시 종료",
            },
            "investigation_notes": [],
        }


def test_pipeline_investigates_incidents_in_given_order() -> None:
    incidents = load_incidents(FIXTURE)
    llm = _ImmediateTerminateLLM()

    results = run_investigation_pipeline(incidents, llm_client=llm, tool_registry=ToolRegistry(), host="web-01")

    assert [r["incident_id"] for r in results] == [i["incident_id"] for i in incidents]
    assert len(llm.seeds) == len(incidents)
    assert all(seed["host"] == "web-01" for seed in llm.seeds)
    # 1차 탐지 탐지 근거(seeds[].evidence_refs)가 조사 결과의 원본 참조로 이어진다
    for incident, result in zip(incidents, results):
        refs = {ref for d in incident["seeds"] for ref in d["evidence_refs"]}
        assert set(result["initial_seed"]["evidence_refs"]) == refs
        assert refs <= set(result["raw_refs"])


def test_result_carries_incident_key_and_snapshot() -> None:
    # 2026-09-28: 1차 탐지 DB 큐는 사건이 커져도 안 바뀌는 incident_key로 사건을 잇는다(incident_id는 바뀜).
    # ATT&CK 매핑·최종 보고서가 initial_seed 안을 뒤지지 않게 결과 최상위에 둔다.
    first, second = load_incidents(FIXTURE)[:2]
    keyed = {**first, "incident_key": "K-3f9a", "updated_at": "2026-09-27T10:00:00Z"}
    results = run_investigation_pipeline([keyed, second], llm_client=_ImmediateTerminateLLM(),
                                         tool_registry=ToolRegistry(), host="web-01")
    assert results[0]["incident_key"] == "K-3f9a"
    assert results[0]["incident_snapshot"] == {"incident_id": first["incident_id"],
                                               "member_count": first["member_count"],
                                               "updated_at": "2026-09-27T10:00:00Z"}
    # 지금 1차 탐지 출력(e9b733c)에는 incident_key가 없다 → null, 연결은 incident_id로
    assert results[1]["incident_key"] is None
    assert results[1]["incident_snapshot"]["updated_at"] is None


class _FailingLLM(_ImmediateTerminateLLM):
    """지정한 사건에서 예외를 내는 가짜 클라이언트."""

    def __init__(self, fail_on: str, error: Exception) -> None:
        super().__init__()
        self.fail_on, self.error = fail_on, error

    def reason(self, state: Any, tool_registry: Any, **kwargs: Any) -> Dict[str, Any]:
        if state.seed["incident_id"] == self.fail_on:
            self.seeds.append(state.seed)
            raise self.error
        return super().reason(state, tool_registry, **kwargs)


def _three_incidents():
    first, second = load_incidents(FIXTURE)[:2]
    third = {"incident_id": "INC-HAND", "src_ip": "192.0.2.10", "trigger_time": "2026-09-21T00:00:00Z"}
    return [first, second, third]


def test_llm_outage_on_one_incident_keeps_others_and_saves_each_immediately() -> None:
    # 2026-09-28 EC2: Gemini 503이 재시도 뒤에도 계속되자 main.py 전체가 멈추고 결과가 0건 저장됐다.
    from agent.llm_errors import LLMUnavailableError

    incidents = _three_incidents()
    llm = _FailingLLM(incidents[1]["incident_id"], LLMUnavailableError("Gemini API 일시 오류(503)"))
    saved = []
    results = run_investigation_pipeline(incidents, llm_client=llm, tool_registry=ToolRegistry(),
                                         host="web-01", on_result=saved.append)

    assert [r["incident_id"] for r in saved] == [i["incident_id"] for i in incidents]  # 세 번째도 조사됨
    assert saved == results
    failed = results[1]
    assert failed["investigation_status"] == "INCOMPLETE"
    assert "503" in failed["incomplete_reason"]
    assert failed["statistics"]["termination_reason"] == "llm_unavailable"
    # 폴백 판정("[자동 폴백 판정")과 구분되는 미완료 판정 — 매핑은 INCONCLUSIVE를 deferred로 둔다
    assert failed["final_verdict"]["verdict"] == "INCONCLUSIVE"
    assert failed["final_verdict"]["reasoning"].startswith("[조사 미완료")
    assert [r["investigation_status"] for r in (results[0], results[2])] == ["COMPLETE", "COMPLETE"]
    assert results[0]["incomplete_reason"] is None


def test_config_error_stops_run_but_finished_incidents_are_already_delivered() -> None:
    # API 키·권한 오류는 사건마다 반복돼도 해결되지 않으므로 전체를 멈춘다. 앞서 끝난 사건은 이미 on_result로 넘어갔다.
    incidents = _three_incidents()
    llm = _FailingLLM(incidents[1]["incident_id"], PermissionError("403 PERMISSION_DENIED"))
    saved = []
    try:
        run_investigation_pipeline(incidents, llm_client=llm, tool_registry=ToolRegistry(),
                                   host="web-01", on_result=saved.append)
    except PermissionError:
        pass
    else:  # pragma: no cover
        raise AssertionError("설정 오류가 올라와야 한다")
    assert [r["incident_id"] for r in saved] == [incidents[0]["incident_id"]]


def test_pipeline_with_no_incidents_returns_empty() -> None:
    assert run_investigation_pipeline([], llm_client=_ImmediateTerminateLLM(), tool_registry=ToolRegistry()) == []
