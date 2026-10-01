"""B: evidence queries and local BM25 + multilingual embedding + RRF retrieval.

Accepts the design's JSON boundary; shared A schema types are not duplicated.
The caller must apply verdict/provenance gates before creating mapping units.
No catalog/model download, agent import, or rule matching happens at import time.
See docs/ATTACK_RETRIEVAL_HANDOFF.md for the A/B/C integration contract.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[1] / "data/attack/vector_index"
# With 50 results per source, k=60 can bury even rank 1 from only one source.
# k=20 keeps stronger head-rank contrast; configurable and never ID-specific.
DEFAULT_RRF_K = 20
_TOKEN = re.compile(r"--?[A-Za-z][\w-]*|\w+(?:[./:@-]\w+)*")
_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")

# Vocabulary expansion, never an ID lookup table or a forced candidate list.
_EXPANSIONS = (
    (r"무차별\s*대입|비밀번호\s*(?:추측|실패)|반복.{0,12}인증\s*실패", "brute force password guessing authentication"),
    (r"웹\s*셸|웹\s*쉘", "web shell server software component"),
    (r"셸\s*실행|쉘\s*실행|\bsh\s+-c\b|\bbash\b", "unix shell command interpreter"),
    (r"SSH\s*키|\bauthorized_keys\b", "ssh authorized keys account manipulation"),
    (r"\bcron\b|예약\s*작업", "scheduled task job cron"),
    (r"계정\s*생성|\buseradd\b|\badduser\b", "create account local account"),
    (r"권한\s*상승", "privilege escalation"),
    (r"\bsetuid\b|\bsetgid\b", "setuid setgid permissions"),
    (r"유출|외부\s*서버로\s*전송|대용량\s*아웃바운드", "exfiltration outbound transfer alternative protocol"),
    (r"압축|\btar\b|\bgzip\b", "archive collected data compression archive utility"),
    (r"파일\s*삭제|흔적\s*삭제|\brm\s+-[A-Za-z]*f\b", "file deletion indicator removal"),
    (r"사용자\s*확인|\bwhoami\b|\bid\b", "system owner user discovery"),
    (r"시스템\s*정보|\buname\b", "system information discovery"),
    (r"취약점\s*악용", "exploit public facing application"),
    (r"xmlrpc\.php|XML-RPC", "web authentication password guessing brute force"),
)
_EXPANSIONS = tuple((re.compile(pattern, re.IGNORECASE), words) for pattern, words in _EXPANSIONS)
_UPLOAD = re.compile(r"\bcurl\b[^\n;|]*?(?<!\S)(?:-T|--upload-file)(?=\s|=|$)")


class RetrievalError(RuntimeError):
    """An embedding or cache operation failed; do not convert this to ABSTAIN."""


class EmbeddingBackend(Protocol):
    @property
    def cache_identity(self) -> Mapping[str, Any]: ...

    def encode_documents(self, texts: list[str]) -> Sequence[Sequence[float]]: ...

    def encode_query(self, text: str) -> Sequence[float]: ...


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise ValueError(f"{label} must be an integer in 1..{maximum or 'unbounded'}")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def build_mapping_unit(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Copy one already provenance-validated observed evidence, without mutation.

    Structural validation here is not A's provenance validation. No raw reference
    is synthesized, resolved, renumbered, or silently removed.
    """
    if not isinstance(evidence, Mapping):
        raise ValueError("evidence must be an object")
    unit = {"evidence_id": _string(evidence.get("evidence_id"), "evidence_id")}
    sequence = evidence.get("sequence")
    if sequence is not None:
        _integer(sequence, "sequence")
    unit["sequence"] = sequence
    time = evidence.get("time")
    if time is not None and not isinstance(time, str):
        raise ValueError("time must be a string or None")
    unit["time"] = time
    for key in ("layer", "event_type", "description"):
        value = evidence.get(key, "")
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        unit[key] = value
    refs = evidence.get("raw_refs")
    if not isinstance(refs, (list, tuple)) or not refs:
        raise ValueError("raw_refs must be a non-empty list or tuple")
    for ref in refs:
        _string(ref, "raw_refs entry")
    if evidence.get("empty_result_call") is not None:
        raise ValueError("empty-result evidence is not a target mapping unit")
    unit["raw_refs"] = list(refs)
    unit["mapping_unit_id"] = "UNIT-" + unit["evidence_id"]
    return unit


def build_search_query(mapping_unit: Mapping[str, Any]) -> str:
    """Use only observation fields; keep command case, options and arguments."""
    unit = build_mapping_unit(mapping_unit)
    observed = "\n".join(unit[key] for key in ("description", "event_type", "layer"))
    expansions = [words for pattern, words in _EXPANSIONS if pattern.search(observed)]
    if _UPLOAD.search(observed):
        expansions.append("upload file outbound transfer exfiltration alternative protocol")
    return "\n".join([observed, *dict.fromkeys(expansions)])


def _tokens(text: str) -> list[str]:
    # Options are case sensitive (curl -T and -t differ); natural terms are not.
    return [token if token.startswith("-") else token.casefold() for token in _TOKEN.findall(text)]


def _documents(catalog: Iterable[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    if isinstance(catalog, (Mapping, str, bytes)) or not isinstance(catalog, Iterable):
        raise ValueError("catalog must be an iterable of normalized technique objects")
    by_id: dict[str, dict[str, Any]] = {}
    for record in catalog:
        if not isinstance(record, Mapping):
            raise ValueError("catalog entry must be an object")
        for flag in ("revoked", "deprecated", "is_subtechnique"):
            if type(record.get(flag, False)) is not bool:
                raise ValueError(f"catalog {flag} must be boolean")
        if record.get("revoked", False) or record.get("deprecated", False):
            continue
        tid = _string(record.get("technique_id"), "technique_id")
        if not _TECHNIQUE_ID.fullmatch(tid):
            raise ValueError(f"invalid technique_id format: {tid}")
        doc = {"technique_id": tid,
               "name": _string(record.get("name"), "name"),
               "description": _string(record.get("description"), "description"),
               "tactics": deepcopy(record.get("tactics", [])),
               "parent_technique": deepcopy(record.get("parent_technique")),
               "is_subtechnique": record.get("is_subtechnique", "." in tid)}
        if not isinstance(doc["tactics"], list) or any(not isinstance(t, dict) for t in doc["tactics"]):
            raise ValueError("tactics must be a list of objects")
        if doc["parent_technique"] is not None and not isinstance(doc["parent_technique"], dict):
            raise ValueError("parent_technique must be an object or null")
        _canonical(doc)  # Reject non-JSON metadata instead of changing the contract.
        if tid in by_id and doc != by_id[tid]:
            raise ValueError(f"conflicting catalog entries for {tid}")
        by_id[tid] = doc
    return tuple(by_id[tid] for tid in sorted(by_id))


def _document_text(doc: Mapping[str, Any]) -> str:
    # Original official metadata stays in the candidate. Only retrieval text is assembled.
    names = [t.get("tactic_name", t.get("name", "")) for t in doc["tactics"]]
    parent = doc["parent_technique"] or {}
    names.append(parent.get("technique_name", parent.get("name", "")))
    if any(not isinstance(name, str) for name in names):
        raise ValueError("catalog tactic/parent names must be strings")
    return "\n".join([doc["name"], doc["description"], *filter(None, names)])


@dataclass(frozen=True)
class BM25Index:
    documents: tuple[dict[str, Any], ...]
    frequencies: tuple[Counter, ...]
    document_frequencies: Counter
    lengths: tuple[int, ...]
    average_length: float
    k1: float
    b: float


def build_bm25_index(catalog: Iterable[Mapping[str, Any]], *, k1: float = 1.5, b: float = 0.75) -> BM25Index:
    if not math.isfinite(k1) or k1 <= 0 or not math.isfinite(b) or not 0 <= b <= 1:
        raise ValueError("BM25 requires k1 > 0 and b in [0, 1]")
    docs = _documents(catalog)
    frequencies = tuple(Counter(_tokens(_document_text(doc))) for doc in docs)
    df: Counter = Counter()
    for counts in frequencies:
        df.update(counts.keys())
    lengths = tuple(sum(counts.values()) for counts in frequencies)
    return BM25Index(docs, frequencies, df, lengths, sum(lengths) / len(docs) if docs else 0.0, k1, b)


def retrieve_bm25(query: str, index: BM25Index, *, limit: int = 50) -> list[dict[str, Any]]:
    _string(query, "query")
    _integer(limit, "limit")
    terms = set(_tokens(query))
    results = []
    n = len(index.documents)
    for doc, counts, length in zip(index.documents, index.frequencies, index.lengths):
        score = 0.0
        norm = index.k1 * (1 - index.b + index.b * length / (index.average_length or 1))
        for term in sorted(terms & counts.keys()):
            df, tf = index.document_frequencies[term], counts[term]
            idf = math.log1p((n - df + 0.5) / (df + 0.5))
            score += idf * tf * (index.k1 + 1) / (tf + norm)
        if score > 0:
            results.append({"technique_id": doc["technique_id"], "score": score})
    return sorted(results, key=lambda hit: (-hit["score"], hit["technique_id"]))[:limit]


class SentenceTransformerEmbedder:
    """Lazy, local-first SentenceTransformer adapter with E5 retrieval prefixes."""

    def __init__(self, model_name: str = "intfloat/multilingual-e5-small", *, revision: str,
                 local_files_only: bool = True, cache_folder: str | None = None,
                 device: str = "cpu", batch_size: int = 32, max_sequence_length: int = 512,
                 query_prefix: str = "query: ", document_prefix: str = "passage: "):
        self.model_name = _string(model_name, "model_name")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
            raise ValueError("revision must be a pinned 40-character model commit SHA")
        if not isinstance(query_prefix, str) or not isinstance(document_prefix, str):
            raise ValueError("embedding prefixes must be strings")
        if type(local_files_only) is not bool:
            raise ValueError("local_files_only must be boolean")
        self.revision = revision.lower()
        self.local_files_only = local_files_only
        self.cache_folder = cache_folder
        self.device = _string(device, "device")
        self.batch_size = _integer(batch_size, "batch_size")
        self.max_sequence_length = _integer(max_sequence_length, "max_sequence_length")
        self.query_prefix = query_prefix
        self.document_prefix = document_prefix
        self._model = None
        self._loaded_identity = None

    @property
    def cache_identity(self) -> dict[str, Any]:
        return {"backend": "sentence-transformers", "model": self.model_name, "revision": self.revision,
                "query_prefix": self.query_prefix, "document_prefix": self.document_prefix,
                "max_sequence_length": self.max_sequence_length, "device": self.device,
                "normalize_embeddings": True}

    def _encode(self, texts: list[str], prefix: str) -> Sequence[Sequence[float]]:
        if self._model is not None and self._loaded_identity != self.cache_identity:
            raise RetrievalError("Embedding configuration changed after loading; create a new embedder")
        try:
            if self._model is None:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(
                    self.model_name, revision=self.revision, local_files_only=self.local_files_only,
                    cache_folder=self.cache_folder, device=self.device, trust_remote_code=False,
                )
                self._model.max_seq_length = self.max_sequence_length
                self._loaded_identity = self.cache_identity
            return self._model.encode(
                [prefix + text for text in texts], batch_size=self.batch_size,
                normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False, prompt="",
            ).tolist()
        except ImportError as exc:
            raise RetrievalError("Install attack_mapping/requirements-retrieval.txt for real embeddings") from exc
        except Exception as exc:
            raise RetrievalError("Embedding failed; check the pinned model and local model cache") from exc

    def encode_documents(self, texts: list[str]) -> Sequence[Sequence[float]]:
        return self._encode(texts, self.document_prefix)

    def encode_query(self, text: str) -> Sequence[float]:
        return self._encode([text], self.query_prefix)[0]


def _identity(embedder: EmbeddingBackend) -> dict[str, Any]:
    value = embedder.cache_identity
    if not isinstance(value, Mapping):
        raise ValueError("embedder.cache_identity must be a JSON object")
    result = json.loads(_canonical(dict(value)))
    _string(result.get("model"), "embedding model identity")
    return result


def _vectors(rows: Any, count: int, *, dimension: int | None = None) -> tuple[tuple[float, ...], ...]:
    try:
        rows = list(rows)
        if len(rows) != count:
            raise ValueError("embedding row count differs from document count")
        result = []
        for row in rows:
            values = list(row)
            if any(isinstance(x, (str, bytes, bool)) for x in values):
                raise ValueError("embedding values must be numeric")
            values = tuple(float(x) for x in values)
            if not values or any(not math.isfinite(x) for x in values):
                raise ValueError("embedding contains empty/non-finite values")
            if dimension is None:
                dimension = len(values)
            if len(values) != dimension:
                raise ValueError("embedding dimension mismatch")
            norm = math.hypot(*values)
            if not math.isfinite(norm) or norm == 0:
                raise ValueError("embedding has zero or invalid norm")
            result.append(tuple(x / norm for x in values))
        return tuple(result)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RetrievalError(f"Invalid embedding vectors: {exc}") from exc


@dataclass(frozen=True)
class VectorIndex:
    documents: tuple[dict[str, Any], ...]
    vectors: tuple[tuple[float, ...], ...]
    metadata: dict[str, Any]
    cache_hit: bool = False


def _cache_metadata(docs: tuple[dict[str, Any], ...], manifest: Mapping[str, Any],
                    embedder: EmbeddingBackend) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    for name in ("attack_version", "sha256", "retrieval_version", "embedding_model"):
        _string(manifest.get(name), "manifest." + name)
    if not _SHA256.fullmatch(manifest["sha256"]):
        raise ValueError("manifest.sha256 must be a SHA-256 hex digest")
    identity = _identity(embedder)
    if identity["model"] != manifest["embedding_model"]:
        raise ValueError("manifest.embedding_model differs from embedding backend")
    return {"format": 1, "document_text_version": 1, "attack_version": manifest["attack_version"],
            "catalog_sha256": manifest["sha256"].lower(), "document_sha256": _digest(docs),
            "retrieval_version": manifest["retrieval_version"], "embedding": identity}


def _load_vectors(path: Path, docs: tuple[dict[str, Any], ...], metadata: dict[str, Any]) -> VectorIndex | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (ValueError, UnicodeError):
        return None
    except OSError as exc:
        raise RetrievalError("Cannot read local vector cache") from exc
    try:
        if payload["metadata"] != metadata or payload["technique_ids"] != [d["technique_id"] for d in docs]:
            return None
        if payload["vectors_sha256"] != _digest(payload["vectors"]):
            return None
        vectors = _vectors(payload["vectors"], len(docs))
        if type(payload["dimension"]) is not int or payload["dimension"] != (len(vectors[0]) if vectors else 0):
            return None
        return VectorIndex(docs, vectors, metadata, cache_hit=True)
    except (KeyError, TypeError, ValueError, RetrievalError):
        return None


def _save_vectors(path: Path, index: VectorIndex) -> None:
    payload = {"metadata": index.metadata, "technique_ids": [d["technique_id"] for d in index.documents],
               "dimension": len(index.vectors[0]) if index.vectors else 0,
               "vectors": index.vectors, "vectors_sha256": _digest(index.vectors)}
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(_canonical(payload))
        os.replace(temporary, path)
    except OSError as exc:
        raise RetrievalError("Cannot write local vector cache") from exc
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def build_vector_index(catalog: Iterable[Mapping[str, Any]], embedder: EmbeddingBackend, *,
                       manifest: Mapping[str, Any], cache_dir: str | Path | None = DEFAULT_CACHE_DIR) -> VectorIndex:
    docs = _documents(catalog)
    metadata = _cache_metadata(docs, manifest, embedder)
    cache_path = Path(cache_dir) / (_digest(metadata) + ".json") if cache_dir is not None else None
    if cache_path is not None:
        cached = _load_vectors(cache_path, docs, metadata)
        if cached is not None:
            return cached
    try:
        rows = embedder.encode_documents([_document_text(doc) for doc in docs]) if docs else []
    except Exception as exc:
        raise RetrievalError("Document embedding failed; hybrid retrieval is unavailable") from exc
    index = VectorIndex(docs, _vectors(rows, len(docs)), metadata)
    if cache_path is not None:
        _save_vectors(cache_path, index)
    return index


def retrieve_vector(query: str, index: VectorIndex, embedder: EmbeddingBackend, *, limit: int = 50) -> list[dict[str, Any]]:
    _string(query, "query")
    _integer(limit, "limit")
    if _identity(embedder) != index.metadata["embedding"]:
        raise ValueError("query embedder does not match the vector index")
    if not index.documents:
        return []
    try:
        query_vector = embedder.encode_query(query)
    except Exception as exc:
        raise RetrievalError("Query embedding failed; hybrid retrieval is unavailable") from exc
    normalized = _vectors([query_vector], 1, dimension=len(index.vectors[0]))[0]
    hits = [{"technique_id": doc["technique_id"], "score": math.fsum(x * y for x, y in zip(row, normalized))}
            for doc, row in zip(index.documents, index.vectors)]
    return sorted(hits, key=lambda hit: (-hit["score"], hit["technique_id"]))[:limit]


def rrf_merge(bm25_results: Iterable[Mapping[str, Any]], vector_results: Iterable[Mapping[str, Any]], *,
              limit: int = 10, k: int = DEFAULT_RRF_K) -> list[dict[str, Any]]:
    """Fuse ranks (not incomparable scores), counting an ID once per source."""
    _integer(limit, "limit", maximum=10)
    _integer(k, "rrf k")
    merged: dict[str, dict[str, Any]] = {}
    for source, results in (("bm25", bm25_results), ("vector", vector_results)):
        seen: set[str] = set()
        for result in results:
            tid = _string(result.get("technique_id"), "ranked technique_id")
            if tid in seen:
                continue
            seen.add(tid)
            rank = len(seen)
            item = merged.setdefault(tid, {"technique_id": tid, "rrf_score": 0.0,
                                           "sources": [], "retrieval_ranks": {}})
            item["rrf_score"] += 1 / (k + rank)
            item["sources"].append(source)
            item["retrieval_ranks"][source] = rank
    ordered = sorted(merged.values(), key=lambda x: (
        -x["rrf_score"], min(x["retrieval_ranks"].values()), x["technique_id"],
    ))[:limit]
    return [{**item, "rank": rank} for rank, item in enumerate(ordered, 1)]


class HybridRetriever:
    """Build indexes once per worker, then retrieve independently for each unit."""

    def __init__(self, catalog: Iterable[Mapping[str, Any]], *, embedder: EmbeddingBackend,
                 manifest: Mapping[str, Any], cache_dir: str | Path | None = DEFAULT_CACHE_DIR,
                 candidate_pool: int = 50, rrf_k: int = DEFAULT_RRF_K):
        self.candidate_pool = _integer(candidate_pool, "candidate_pool")
        self.rrf_k = _integer(rrf_k, "rrf_k")
        self.bm25_index = build_bm25_index(catalog)
        self.vector_index = build_vector_index(self.bm25_index.documents, embedder,
                                               manifest=manifest, cache_dir=cache_dir)
        self.embedder = embedder
        self._by_id = {d["technique_id"]: d for d in self.bm25_index.documents}

    def retrieve_candidates(self, mapping_unit: Mapping[str, Any], limit: int = 10) -> list[dict[str, Any]]:
        _integer(limit, "limit", maximum=10)
        if self.candidate_pool < limit:
            raise ValueError("candidate_pool must be at least the final limit")
        query = build_search_query(mapping_unit)
        lexical = retrieve_bm25(query, self.bm25_index, limit=self.candidate_pool)
        semantic = retrieve_vector(query, self.vector_index, self.embedder, limit=self.candidate_pool)
        merged = rrf_merge(lexical, semantic, limit=limit, k=self.rrf_k)
        return [{**deepcopy(self._by_id[hit["technique_id"]]), **hit} for hit in merged]


def retrieve_candidates(mapping_unit: Mapping[str, Any], catalog: Iterable[Mapping[str, Any]], limit: int = 10, *,
                        embedder: EmbeddingBackend, manifest: Mapping[str, Any],
                        cache_dir: str | Path | None = DEFAULT_CACHE_DIR) -> list[dict[str, Any]]:
    """One-shot convenience API; use HybridRetriever to avoid rebuilding BM25 per unit."""
    _integer(limit, "limit", maximum=10)
    # Reject a malformed unit before any expensive index construction.
    unit = build_mapping_unit(mapping_unit)
    return HybridRetriever(catalog, embedder=embedder, manifest=manifest,
                           cache_dir=cache_dir).retrieve_candidates(unit, limit)
