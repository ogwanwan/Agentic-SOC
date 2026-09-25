"""ABCD end-to-end: real files and tools, scripted LLM, no network access."""
import json
import socket

import pytest

from agent.pipeline import run_investigation_pipeline
from agent.provenance import strip_trace_fields
from agent.report import format_text_report
from agent.tools import build_default_registry
from scripts.demo_abcd import LAYERS, ROOT, WINDOW, ScriptedDemoClient, run_demo, sample_environment

EXPECTED_REFS = {
    "web": ["web.txt:1"], "auth": ["auth.txt:1"],
    "audit": ["audit.txt:1", "audit.txt:2"], "network": ["network.jsonl:1"],
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("ABCD offline tests must not connect to the network")
    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(socket.socket, "connect_ex", reject)
    monkeypatch.setattr(socket, "create_connection", reject)


@pytest.mark.parametrize("layers", [(layer,) for layer in LAYERS] + [LAYERS])
def test_real_pipeline_preserves_input_query_evidence_and_report(layers):
    demo = run_demo(layers)
    result = demo["results"][0]
    expected = {ref for layer in layers for ref in EXPECTED_REFS[layer]}
    assert len(demo["seed_input"]) == 4
    assert result["initial_seed"]["evidence_refs"] == [EXPECTED_REFS[layer][0] for layer in layers]
    assert result["initial_seed"]["window"] == WINDOW
    assert result["provenance"]["status"] == "passed"
    assert result["provenance"]["issues"] == []
    assert result["provenance"]["evidence_without_raw_refs"] == []
    assert set(result["raw_refs"]) == expected
    assert set(result["raw_ref_locations"]) == expected
    assert {ref for e in result["evidence_chain"] for ref in e["raw_refs"]} == expected
    assert result["statistics"]["evidence_count"] == len(layers)
    assert result["statistics"]["termination_reason"] == "no_more_evidence"
    assert result["final_verdict"]["verdict"] == "INCONCLUSIVE"
    assert result["statistics"]["confidence_increase"] == 0

    observations = demo["tool_observations"]
    assert all("error" not in call for call in result["tools_called"])
    names = [f"fetch_{layer}_log" for layer in layers]
    if "audit" in layers:
        names.append("get_process_tree")
        tree = next(o["result"] for o in observations if o["tool_name"] == "get_process_tree")
        assert tree["records"][0]["nodes"][0]["raw_refs"] == EXPECTED_REFS["audit"]
        assert tree["records"][0]["nodes"][0]["pid"] == 200
    names += ["fetch_event_logs"] * ((len(layers) + 1) // 2)
    assert [call["tool_name"] for call in result["tools_called"]] == names

    pages = [o for o in observations if o["tool_name"] == "fetch_event_logs"]
    records = [r for page in pages for r in page["result"]["records"]]
    assert len(records) == len(layers)
    assert len({r["raw_ref"] for r in records}) == len(records)
    assert [r["timestamp"] for r in records] == sorted(r["timestamp"] for r in records)
    assert [page["args"]["offset"] for page in pages] == list(range(0, len(layers), 2))
    assert [page["result"]["has_more"] for page in pages] == [True] * (len(pages) - 1) + [False]
    for page in pages:
        assert page["args"]["event"]["window"] == WINDOW
        assert page["args"]["host"] == "web-01"
        assert page["result"]["total_matched"] == len(layers)
        assert page["result"]["errors"] == {}
    original = {r["raw_ref"]: {k: v for k, v in r.items() if k != "_source_type"}
                for r in demo["seed_input"]}
    for observation in observations:
        if observation["tool_name"] == "get_process_tree":
            continue
        for record in observation["result"]["records"]:
            # seed 프롬프트는 추적용 필드(raw_ref_locations 등)를 뺀 사본이라 같은 기준으로 비교
            assert strip_trace_fields(record) == original[record["raw_ref"]]

    # Follow every final report reference back to an actual physical sample line.
    for ref, locations in result["raw_ref_locations"].items():
        name, line = ref.rsplit(":", 1)
        path = ROOT / "examples" / "cd" / name
        assert locations == [path.as_posix() + ":" + line]
        assert path.read_text(encoding="utf-8").splitlines()[int(line) - 1]
    roundtrip = json.loads(json.dumps(result))
    assert roundtrip["raw_ref_locations"] == result["raw_ref_locations"]
    text = format_text_report(result)
    assert all(ref in text for ref in expected)


def test_pipeline_rejects_fabricated_seed_before_investigation():
    class BadSeedClient(ScriptedDemoClient):
        def complete_json(self, system_prompt, user_prompt):
            decision = super().complete_json(system_prompt, user_prompt)
            decision["candidates"][0]["evidence_refs"] = ["invented.log:999"]
            return decision

        def reason(self, *args, **kwargs):
            pytest.fail("Invalid seed must be rejected before investigation")

    with sample_environment(), pytest.raises(ValueError, match="evidence_refs"):
        run_investigation_pipeline("web-01", BadSeedClient(), build_default_registry())


def test_pipeline_marks_fabricated_evidence_incomplete_without_confidence_increase():
    class BadEvidenceClient(ScriptedDemoClient):
        def reason(self, *args, **kwargs):
            decision = super().reason(*args, **kwargs)
            for evidence in decision.get("new_evidence", []):
                evidence["raw_ref"] = "invented.log:999"
                evidence["confidence_contribution"] = 0.9
            return decision

    with sample_environment():
        result = run_investigation_pipeline("web-01", BadEvidenceClient(), build_default_registry(),
                                            max_calls=12)[0]
    assert result["provenance"]["status"] == "incomplete"
    assert result["provenance"]["issues"]
    assert result["statistics"]["confidence_increase"] == 0
    assert "invented.log:999" not in result["raw_refs"]
    assert all(not evidence["raw_refs"] for evidence in result["evidence_chain"])


def test_demo_is_independent_of_existing_environment_and_restores_it(monkeypatch):
    import os
    monkeypatch.setenv("HOST", "different-host")
    monkeypatch.setenv("LOG_LOCAL_HOST", "different-host")
    monkeypatch.setenv("AUTH_LOG_YEAR", "1999")
    monkeypatch.setenv("RAW_LOG_LOCAL_MAX_LINES", "0")
    monkeypatch.setenv("WEB_LOG_LOCAL_PATH", "missing-file.txt")
    before = dict(os.environ)
    assert run_demo()["results"][0]["provenance"]["status"] == "passed"
    assert dict(os.environ) == before
