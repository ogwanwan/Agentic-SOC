"""Contracts shared by the rule catalog, mapping engine and report consumers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Tuple, TypedDict


TACTIC_ORDER: Tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

MappingStatus = Literal[
    "mapped", "partial", "no_techniques_matched", "not_applicable", "deferred", "error"
]
MatchedBy = Literal["verdict", "evidence"]
ProvenanceStatus = Literal["passed", "incomplete", "unavailable"]


@dataclass(frozen=True)
class TechniqueRule:
    """One technique/tactic keyword rule; catalogs supply a sequence of these.

    Keywords must be tuples of strings. Empty/whitespace keywords are permitted
    in a catalog but never match. No technique catalog is bundled with the engine.
    """

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    attack_type_keywords: Tuple[str, ...] = ()
    evidence_keywords: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("technique_id", "technique_name", "tactic_id", "tactic_name"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be a non-empty, trimmed string")
        for name in ("attack_type_keywords", "evidence_keywords"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(not isinstance(word, str) for word in value):
                raise ValueError(f"{name} must be a tuple of strings")
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")


@dataclass(frozen=True)
class MappingHit:
    """An unmerged rule match. Verdict hits have no invented evidence or refs.

    matched_keywords contains unique strip/casefold-normalized catalog keywords.
    Evidence times and references retain their original strings.
    """

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    matched_by: MatchedBy
    matched_keywords: Tuple[str, ...] = ()
    evidence_ids: Tuple[str, ...] = ()
    time: Optional[str] = None
    raw_refs: Tuple[str, ...] = ()


class Tactic(TypedDict):
    tactic_id: str
    tactic_name: str


class MappingMatch(TypedDict):
    """Keeps each evidence -> refs/time/keywords link intact after merging."""

    tactic_id: str
    tactic_name: str
    matched_by: MatchedBy
    matched_keywords: List[str]
    evidence_ids: List[str]
    time: Optional[str]
    raw_refs: List[str]


class MappedTechnique(TypedDict):
    technique_id: str
    technique_name: str
    # First matched tactic by tactic_id; `tactics` retains all of them.
    tactic_id: str
    tactic_name: str
    tactics: List[Tactic]
    matched_by: List[MatchedBy]
    matched_keywords: List[str]
    evidence_ids: List[str]
    raw_refs: List[str]
    # Unique, non-null input times in encounter order, NOT chronological order.
    times: List[str]
    matches: List[MappingMatch]


class AttackMappingResult(TypedDict):
    """JSON-ready engine output. No Kill Chain or file/report side effects.

    `unmatched_evidence_ids` contains eligible evidence only. Excluded evidence
    is listed separately. `raw_ref_locations` is copied from the investigation;
    references are opaque and are never rewritten or resolved by this engine.
    Nullable metadata is only used when malformed input prevents validation.
    """

    incident_id: Optional[str]
    investigation_id: Optional[str]
    mapping_status: MappingStatus
    provenance_status: Optional[ProvenanceStatus]
    techniques: List[MappedTechnique]
    unmatched_evidence_ids: List[str]
    excluded_evidence_ids: List[str]
    raw_ref_locations: Dict[str, List[str]]
    mapping_table_version: Optional[str]
    errors: List[str]
