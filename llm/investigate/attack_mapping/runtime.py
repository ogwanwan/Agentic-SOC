"""Connect the official ATT&CK catalog and schema to hybrid retrieval."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .catalog import AttackCatalog
from .retrieve import (
    DEFAULT_CACHE_DIR,
    EmbeddingBackend,
    HybridRetriever,
    SentenceTransformerEmbedder,
    build_mapping_unit as build_retrieval_unit,
)
from .schema import CandidateTechnique, MappingUnit


def _retrieval_documents(catalog: AttackCatalog) -> list[dict[str, Any]]:
    """Use only active official records; keep IDs and metadata unchanged."""
    documents = []
    for record in catalog.techniques():
        parent = catalog.lookup(record.parent_id) if record.parent_id else None
        if record.parent_id and parent is None:
            raise ValueError(f"parent technique not found: {record.parent_id}")
        documents.append({
            "technique_id": record.technique_id,
            "name": record.name,
            "description": record.description,
            "tactics": [tactic.as_dict() for tactic in record.tactics],
            "parent_technique": (
                {"technique_id": parent.technique_id, "technique_name": parent.name}
                if parent else None
            ),
            "is_subtechnique": record.is_subtechnique,
            "revoked": record.revoked,
            "deprecated": record.deprecated,
        })
    return documents


class MappingRuntime:
    """Reuse one index across eligible Evidence in a saved investigation."""

    def __init__(
        self,
        catalog: AttackCatalog,
        *,
        embedder: EmbeddingBackend | None = None,
        cache_dir: str | Path | None = DEFAULT_CACHE_DIR,
    ) -> None:
        self.catalog = catalog
        self.manifest = dict(catalog.manifest)
        model = self.manifest.get("embedding_model")
        version = self.manifest.get("retrieval_version")
        if not isinstance(model, str) or not model:
            raise ValueError("manifest.embedding_model must be configured")
        if not isinstance(version, str) or not version:
            raise ValueError("manifest.retrieval_version must be configured")
        if embedder is None:
            revision = self.manifest.get("embedding_revision")
            embedder = SentenceTransformerEmbedder(model, revision=revision)
        self.embedder = embedder
        self.cache_dir = cache_dir
        self._retriever: HybridRetriever | None = None

    @staticmethod
    def build_mapping_unit(evidence: Mapping[str, Any]) -> MappingUnit:
        unit = build_retrieval_unit(evidence)
        return MappingUnit(
            mapping_unit_id=unit["mapping_unit_id"],
            evidence_id=unit["evidence_id"],
            sequence=unit["sequence"],
            time=unit["time"],
            layer=unit["layer"],
            event_type=unit["event_type"],
            description=unit["description"],
            raw_refs=tuple(unit["raw_refs"]),
        )

    def retrieve_candidates(
        self, unit: MappingUnit, catalog: AttackCatalog, *, limit: int = 10
    ) -> list[CandidateTechnique]:
        if catalog is not self.catalog:
            raise ValueError("retrieval catalog differs from validation catalog")
        if self._retriever is None:
            self._retriever = HybridRetriever(
                _retrieval_documents(self.catalog),
                embedder=self.embedder,
                manifest=self.manifest,
                cache_dir=self.cache_dir,
            )
        query_unit = {
            "mapping_unit_id": unit.mapping_unit_id,
            "evidence_id": unit.evidence_id,
            "sequence": unit.sequence,
            "time": unit.time,
            "layer": unit.layer,
            "event_type": unit.event_type,
            "description": unit.description,
            "raw_refs": list(unit.raw_refs),
        }
        hits = self._retriever.retrieve_candidates(query_unit, limit=limit)
        candidates = []
        for hit in hits:
            record = self.catalog.get_active(hit["technique_id"])
            if record is None:
                raise ValueError(f"retriever returned inactive or unknown ID: {hit['technique_id']}")
            candidates.append(CandidateTechnique(
                technique_id=record.technique_id,
                name=record.name,
                description=record.description,
                tactics=record.tactics,
                parent_id=record.parent_id,
                rank=hit["rank"],
                score=hit["rrf_score"],
                sources=tuple(hit["sources"]),
            ))
        return candidates
