"""A catalog + B hybrid retrieval + C mapping through the default saved-file path."""

import json

from attack_mapping.catalog import AttackCatalog, read_manifest
from attack_mapping.cli import process_file
from attack_mapping.schema import TacticRef, TechniqueRecord


TACTIC = TacticRef("TA0002", "Execution", "execution")


def _catalog(embedding_model="test-vectors"):
    parent = TechniqueRecord(
        "T1059", "attack-pattern--shell-parent", "Command and Scripting Interpreter",
        "Command interpreter execution", (TACTIC,), False, None, ("Linux",),
        "https://attack.mitre.org/techniques/T1059/",
    )
    shell = TechniqueRecord(
        "T1059.004", "attack-pattern--unix-shell", "Unix Shell",
        "Unix shell sh -c command execution", (TACTIC,), True, "T1059", ("Linux",),
        "https://attack.mitre.org/techniques/T1059/004/",
    )
    manifest = {
        "attack_version": "test", "sha256": "a" * 64,
        "retrieval_version": "test-hybrid", "embedding_model": embedding_model,
    }
    return AttackCatalog((parent, shell), (TACTIC,), "test", "a" * 64, manifest)


class FakeEmbedder:
    cache_identity = {"model": "test-vectors", "backend": "fixture"}

    def __init__(self):
        self.document_calls = 0
        self.query_calls = 0

    def encode_documents(self, texts):
        self.document_calls += 1
        return [[1.0, 0.0] for _ in texts]

    def encode_query(self, text):
        self.query_calls += 1
        return [1.0, 0.0]


class FakeLLM:
    def __init__(self):
        self.calls = 0

    def complete_json(self, system_prompt, user_prompt):
        self.calls += 1
        evidence_id = f"EVID-{self.calls:03d}"
        return {"decision": "SELECT", "selections": [{
            "technique_id": "T1059.004", "evidence_ids": [evidence_id],
            "reason": "Observed sh -c Unix shell command",
        }]}


def _investigation(verdict="THREAT_CONFIRMED"):
    evidence = [
        {"evidence_id": "EVID-001", "sequence": 1, "time": "2026-09-29T10:00:00Z",
         "layer": "audit", "event_type": "process_exec", "description": "www-data sh -c id",
         "raw_refs": ["audit.log:11"]},
        {"evidence_id": "EVID-002", "sequence": None, "time": None,
         "layer": "audit", "event_type": "process_exec", "description": "www-data sh -c whoami",
         "raw_refs": ["audit.log:12"]},
    ]
    return {
        "incident_id": "INC-REAL-B", "investigation_id": "INV-REAL-B",
        "final_verdict": {"verdict": verdict, "attack_type": "display only"},
        "evidence_chain": evidence, "contradicting_evidence": [], "remaining_unknowns": [],
        "raw_refs": ["audit.log:11", "audit.log:12"],
        "raw_ref_locations": {
            "audit.log:11": ["/var/log/audit.log"],
            "audit.log:12": ["/var/log/audit.log"],
        },
        "tools_called": [{"raw_refs": ["audit.log:11", "audit.log:12"]}],
        "provenance": {"status": "passed", "seed_raw_refs": [],
                       "evidence_without_raw_refs": [], "empty_result_evidence": [],
                       "ambiguous_raw_refs": {}, "issues": []},
    }


def test_default_path_connects_real_b_hybrid_to_a_and_c(tmp_path):
    source = _investigation()
    path = tmp_path / "investigation.json"
    before = json.dumps(source)
    path.write_text(before, encoding="utf-8")
    embedder, llm = FakeEmbedder(), FakeLLM()

    result = process_file(str(path), out_dir=str(tmp_path / "out"),
                          catalog=_catalog(), embedder=embedder, llm_client=llm,
                          cache_dir=None)

    assert result["mapping_status"] == "mapped" and result["errors"] == []
    assert result["mapping_method"] == "rag_llm"
    assert result["retrieval_version"] == "test-hybrid"
    assert [item["technique_id"] for item in result["techniques"]] == ["T1059.004"]
    assert result["techniques"][0]["evidence_ids"] == ["EVID-001", "EVID-002"]
    assert result["techniques"][0]["raw_refs"] == ["audit.log:11", "audit.log:12"]
    assert len(result["retrieval_trace"]) == 2
    assert all("T1059.004" in trace["candidate_ids"] for trace in result["retrieval_trace"])
    assert embedder.document_calls == 1 and embedder.query_calls == 2
    assert llm.calls == 2
    assert path.read_text(encoding="utf-8") == before
    report = json.loads((tmp_path / "out" / "INC-REAL-B_final_report.json").read_text(encoding="utf-8"))
    assert report["evidence_chain"] == source["evidence_chain"]
    assert report["attack_mapping"] == result


def test_gate_skips_catalog_embedding_and_llm(tmp_path):
    path = tmp_path / "investigation.json"
    path.write_text(json.dumps(_investigation("FALSE_POSITIVE")), encoding="utf-8")
    result = process_file(str(path), out_dir=str(tmp_path / "out"))
    assert result["mapping_status"] == "not_applicable"
    assert result["retrieval_trace"] == [] and result["techniques"] == []
    manifest = read_manifest()
    assert result["attack_version"] == manifest["attack_version"]
    assert result["retrieval_version"] == manifest["retrieval_version"]


def test_no_target_evidence_skips_retrieval_and_preserves_versions(tmp_path):
    source = _investigation()
    for evidence in source["evidence_chain"]:
        evidence["raw_refs"] = []
    path = tmp_path / "investigation.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    embedder, llm = FakeEmbedder(), FakeLLM()
    result = process_file(str(path), out_dir=str(tmp_path / "out"),
                          embedder=embedder, llm_client=llm)
    assert result["mapping_status"] == "no_techniques_matched"
    assert result["excluded_evidence_ids"] == ["EVID-001", "EVID-002"]
    assert embedder.document_calls == embedder.query_calls == llm.calls == 0
    manifest = read_manifest()
    assert result["attack_version"] == manifest["attack_version"]
    assert result["retrieval_version"] == manifest["retrieval_version"]


def test_bad_retrieval_manifest_is_technical_error(tmp_path):
    path = tmp_path / "investigation.json"
    path.write_text(json.dumps(_investigation()), encoding="utf-8")
    result = process_file(str(path), out_dir=str(tmp_path / "out"),
                          catalog=_catalog(embedding_model=None),
                          embedder=FakeEmbedder(), llm_client=FakeLLM())
    assert result["mapping_status"] == "error"
    assert "manifest.embedding_model" in result["errors"][0]
    assert (tmp_path / "out" / "INC-REAL-B_final_report.json").exists()
