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


def test_pipeline_with_no_incidents_returns_empty() -> None:
    assert run_investigation_pipeline([], llm_client=_ImmediateTerminateLLM(), tool_registry=ToolRegistry()) == []
