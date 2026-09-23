"""Offline ABCD pipeline demonstration: python -m scripts.demo_abcd.

Only LLM decisions are scripted. Ingestion, seed validation, the registry,
normalizers, investigation tools, pagination and report generation are real.
"""
from __future__ import annotations

import argparse
import json
import os
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from agent.pipeline import run_investigation_pipeline
from agent.tools import build_default_registry
from agent.tools.log_source import LOCAL_PATH_ENV

ROOT = Path(__file__).resolve().parents[1]
LAYERS = ("web", "auth", "audit", "network")
WINDOW = ["2026-09-21T00:00:00Z", "2026-09-21T00:01:00Z"]
SAMPLES = {"web": "web.txt", "auth": "auth.txt", "audit": "audit.txt", "network": "network.jsonl"}


@contextmanager
def sample_environment():
    """Pin paths, host, year and replay limit; restore the caller's environment."""
    env = {LOCAL_PATH_ENV[layer]: str(ROOT / "examples" / "cd" / name)
           for layer, name in SAMPLES.items()}
    env.update(HOST="web-01", LOG_LOCAL_HOST="web-01", AUTH_LOG_YEAR="2026",
               RAW_LOG_LOCAL_MAX_LINES="30")
    with patch.dict(os.environ, env):
        yield


class ScriptedDemoClient:
    """A repeatable test driver, not a threat detector or external LLM client."""

    def __init__(self, layers=LAYERS):
        self.layers = list(layers)
        self.seed_input = []
        self.observations = []

    def complete_json(self, system_prompt, user_prompt):
        payload = json.loads(user_prompt.split("\n\n", 1)[1])
        self.seed_input = deepcopy(payload["raw_logs"])
        records = [r for r in self.seed_input if r["_source_type"] in self.layers]
        return {"candidates": [{
            "incident_id": "INC-ABCD-DEMO", "host": payload["host"],
            "priority": 1, "window": list(WINDOW), "trigger_time": WINDOW[0],
            "trigger_description": "합성 로그로 A·B·C·D 연결 확인", "confidence_initial": 0.0,
            "evidence_refs": [record["raw_ref"] for record in records],
        }]}

    def reason(self, state, registry, **kwargs):
        evidence = []
        already_cited = {ref for item in state.evidence for ref in item.raw_refs}
        for observation in state.pending_observations:
            self.observations.append(deepcopy(observation))
            for record in observation["result"].get("records", []):
                ref = record.get("raw_ref")
                if not ref or ref in already_cited:  # Tree nodes are tracked by the real loop.
                    continue
                evidence.append({
                    "description": f"{record['layer']} 원본 로그 관측",
                    "layer": record["layer"], "time": record["timestamp"],
                    "source_log": ref.rsplit(":", 1)[0], "raw_ref": ref,
                    "confidence_contribution": 0.0,
                })
                already_cited.add(ref)

        start, end = state.seed["window"]
        common = {"host": state.seed["host"], "start_time": start, "end_time": end}
        steps = [(f"fetch_{layer}_log", common) for layer in self.layers]
        if "audit" in self.layers:
            steps.append(("get_process_tree", {**common, "pid": 200}))
        count = len(state.tool_calls)
        if count < len(steps):
            name, args = steps[count]
        else:
            last = self.observations[-1] if self.observations else None
            page = last["result"] if last and last["tool_name"] == "fetch_event_logs" else None
            if page is not None and not page["has_more"]:
                return {"new_evidence": evidence, "next_action": "terminate",
                        "termination_reason": "no_more_evidence", "final_verdict": {
                            "verdict": "INCONCLUSIVE", "confidence": 0.0, "severity": "UNKNOWN",
                            "attack_type": "offline_demo", "affected_systems": ["web-01"],
                            "summary": "A·B·C·D 데이터 흐름을 확인한 데모입니다.",
                            "reasoning": "LLM 판단은 고정 응답이며 실제 공격 여부는 평가하지 않았습니다.",
                        }}
            name = "fetch_event_logs"
            # The real loop injects the seed's host and window into this tool call.
            args = {"layers": self.layers, "limit": 2,
                    "offset": page["next_offset"] if page is not None else 0}
        return {"new_evidence": evidence, "next_action": "call_tool",
                "tool_call": {"tool_name": name, "args": args}}


def run_demo(layers=LAYERS):
    layers = list(layers)
    if not layers or len(layers) != len(set(layers)) or set(layers) - set(LAYERS):
        raise ValueError("layers must be unique web/auth/audit/network values")
    client = ScriptedDemoClient(layers)
    with sample_environment():
        registry = build_default_registry(exclude=["resolve_ip_geo"])
        names = [f"fetch_{layer}_log" for layer in layers] + ["fetch_event_logs", "get_process_tree"]
        for name in names:
            if registry.get(name).handler.__module__ != f"agent.tools.real.{name}":
                raise RuntimeError(f"{name} is not connected to the real implementation")
        results = run_investigation_pipeline(
            host="web-01", llm_client=client, tool_registry=registry, max_calls=12,
        )
    if len(results) != 1:
        raise RuntimeError("Expected one demo incident")
    result = results[0]
    if (result["provenance"]["status"] != "passed"
            or any("error" in call for call in result["tools_called"])
            or result["statistics"]["evidence_count"] != len(layers)
            or len(result["raw_refs"]) != len(layers) + ("audit" in layers)):
        raise RuntimeError("Demo did not preserve the expected evidence and references")
    return {"mode": "offline_scripted_llm", "seed_input": client.seed_input,
            "tool_observations": client.observations, "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layers", nargs="+", choices=LAYERS, default=list(LAYERS))
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "abcd_demo.json")
    args = parser.parse_args()
    demo = run_demo(args.layers)
    result = demo["results"][0]
    pages = [o["result"] for o in demo["tool_observations"] if o["tool_name"] == "fetch_event_logs"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(demo, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[A] Normalized seed input: {len(demo['seed_input'])} events")
    print(f"[B] Real investigation tools: {len(result['tools_called']) - len(pages)} calls")
    print(f"[C] Incident window query: {sum(p['count'] for p in pages)} events / {len(pages)} pages")
    print(f"[D] Provenance: {result['provenance']['status']} / {len(result['raw_refs'])} raw references")
    print("LLM: scripted offline responses; threat classification not evaluated.")
    print(f"Saved: {args.output.resolve()}")


if __name__ == "__main__":
    main()
