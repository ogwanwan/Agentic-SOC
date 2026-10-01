"""Contracts shared by the rule catalog, mapping engine and report consumers.

Rule baseline types (TechniqueRule, MappingHit, MappedTechnique) are unchanged.
RAG types (TechniqueRecord, MappingUnit, CandidateTechnique, MappingDecision,
ValidatedSelection, AttackMappingEntry) are shared by catalog/validate (A),
retrieve (B) and mapper/cli (C). Change them only after agreeing with B and C.
Python 3.10 compatible: optional TypedDict keys use total=False subclasses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, TypedDict


# Rule baseline order (ATT&CK <= v18 names). ATT&CK v19 renamed Defense Evasion
# to Stealth and added Defense Impairment; the official order for the loaded
# catalog is AttackCatalog.tactic_order. Kept as-is for the rule baseline.
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
    # Literal command fragments: case-sensitive options, flexible whitespace.
    evidence_command_keywords: Tuple[str, ...] = ()
    # Require at least one context phrase in the SAME affirmative clause as a hit.
    required_context_keywords: Tuple[str, ...] = ()
    # Explicit denial/uncertainty about these subjects vetoes the context claim.
    context_subject_keywords: Tuple[str, ...] = ()
    allow_verdict_hits: bool = True

    def __post_init__(self) -> None:
        for name in ("technique_id", "technique_name", "tactic_id", "tactic_name"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be a non-empty, trimmed string")
        for name in ("attack_type_keywords", "evidence_keywords", "evidence_command_keywords",
                     "required_context_keywords", "context_subject_keywords"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(not isinstance(word, str) for word in value):
                raise ValueError(f"{name} must be a tuple of strings")
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")
        if not isinstance(self.allow_verdict_hits, bool):
            raise ValueError("allow_verdict_hits must be a bool")


@dataclass(frozen=True)
class MappingHit:
    """An unmerged rule match. Verdict hits have no invented evidence or refs.

    matched_keywords contains unique normalized catalog keywords. Natural-language
    keywords use casefold; command keywords preserve option case.
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


class _AttackMappingResultRequired(TypedDict):
    incident_id: Optional[str]
    investigation_id: Optional[str]
    mapping_status: MappingStatus
    provenance_status: Optional[ProvenanceStatus]
    techniques: List[MappedTechnique]
    unmatched_evidence_ids: List[str]
    excluded_evidence_ids: List[str]
    raw_ref_locations: Dict[str, List[str]]
    # cli.py detects generated artifacts by this key: RAG results keep it (None).
    mapping_table_version: Optional[str]
    # Technical failures only (mapping_status == "error"); cli/main join them as text.
    errors: List[str]


class AttackMappingResult(_AttackMappingResultRequired, total=False):
    """JSON-ready engine output. No Kill Chain or file/report side effects.

    `unmatched_evidence_ids` contains eligible evidence only. Excluded evidence
    is listed separately. `raw_ref_locations` is copied from the investigation;
    references are opaque and are never rewritten or resolved by this engine.
    Nullable metadata is only used when malformed input prevents validation.

    The optional keys below are written by the RAG path only; the rule engine
    output stays valid without them.
    """

    attack_version: Optional[str]         # manifest.json attack_version
    retrieval_version: Optional[str]      # manifest.json retrieval_version (B)
    mapping_method: MappingMethod
    # [{evidence_id, reasons}] for every evidence_chain item that was not a Mapping Unit.
    exclusions: List[Dict[str, Any]]
    rejected_selections: List["SelectionRejection"]
    # [{mapping_unit_id, candidate_ids}] minimal P0 trace; validation depends on it.
    retrieval_trace: List[Dict[str, Any]]
    # Case gate warnings such as FALLBACK_VERDICT, VERDICT_PRINCIPLE_CONFLICT.
    warnings: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# RAG contracts
# ---------------------------------------------------------------------------

MappingMethod = Literal["rag_llm", "rule_baseline", "rule_fallback"]
DecisionKind = Literal["SELECT", "ABSTAIN"]

# Official Enterprise technique/sub-technique ID. No case or whitespace tolerance here;
# validate.normalize_technique_id() is the only place that normalizes LLM output.
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class CatalogError(RuntimeError):
    """ATT&CK catalog missing, corrupted, or inconsistent with manifest.json."""


class InvestigationFormatError(ValueError):
    """investigation_result structure cannot be trusted (mapping_status=error)."""


class DecisionFormatError(ValueError):
    """LLM decision JSON is malformed. Never treat this as ABSTAIN."""


def _require_text(value: Any, name: str, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"{name} must be a {'' if allow_empty else 'non-empty '}string")


def _require_texts(value: Any, name: str) -> None:
    if not isinstance(value, tuple) or any(not isinstance(v, str) or not v for v in value):
        raise ValueError(f"{name} must be a tuple of non-empty strings")


@dataclass(frozen=True)
class TacticRef:
    tactic_id: str        # TA0002
    tactic_name: str      # Execution
    shortname: str        # execution (STIX kill_chain_phases.phase_name)

    def as_dict(self) -> Dict[str, str]:
        return {"tactic_id": self.tactic_id, "tactic_name": self.tactic_name}


@dataclass(frozen=True)
class TechniqueRecord:
    """One ATT&CK technique/sub-technique from the official STIX bundle.

    `description` has citations, markdown links and <code> tags removed for
    retrieval and prompts. Inactive records exist only so validation can explain
    a rejection (revoked_by); they are never retrieval candidates.
    """

    technique_id: str
    stix_id: str
    name: str
    description: str
    tactics: Tuple[TacticRef, ...]      # official matrix order
    is_subtechnique: bool
    parent_id: Optional[str]
    platforms: Tuple[str, ...]
    url: str
    revoked: bool = False
    deprecated: bool = False
    revoked_by: Optional[str] = None    # replacement technique_id, for error messages only

    @property
    def active(self) -> bool:
        return not (self.revoked or self.deprecated)


@dataclass(frozen=True)
class MappingUnit:
    """One mappable observed evidence. Fields are copied from evidence_chain unchanged.

    Convention: mapping_unit_id = "UNIT-" + evidence_id. Never renumber sequence,
    evidence_id or raw_refs; validate.validate_decision() rejects a unit that differs.
    """

    mapping_unit_id: str
    evidence_id: str
    sequence: Optional[int]
    time: Optional[str]
    layer: str
    event_type: str
    description: str
    raw_refs: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.mapping_unit_id, "mapping_unit_id")
        _require_text(self.evidence_id, "evidence_id")
        if self.sequence is not None and (type(self.sequence) is not int or self.sequence < 1):
            raise ValueError("sequence must be a positive integer or None")
        if self.time is not None:
            _require_text(self.time, "time", allow_empty=True)
        for name in ("layer", "event_type", "description"):
            _require_text(getattr(self, name), name, allow_empty=True)
        _require_texts(self.raw_refs, "raw_refs")
        if not self.raw_refs:
            raise ValueError("raw_refs must not be empty for a Mapping Unit")


@dataclass(frozen=True)
class CandidateTechnique:
    """A retrieval result for one Mapping Unit. rank starts at 1."""

    technique_id: str
    name: str
    description: str
    tactics: Tuple[TacticRef, ...]
    parent_id: Optional[str]
    rank: int
    score: float
    sources: Tuple[str, ...]            # subset of ("bm25", "vector")

    def __post_init__(self) -> None:
        if not TECHNIQUE_ID_PATTERN.match(self.technique_id):
            raise ValueError(f"invalid technique_id: {self.technique_id!r}")
        if type(self.rank) is not int or self.rank < 1:
            raise ValueError("rank must be a positive integer")
        _require_texts(self.sources, "sources")


@dataclass(frozen=True)
class Selection:
    """One LLM choice. Only these three fields are read; LLM name/tactic are ignored."""

    technique_id: str
    evidence_ids: Tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class MappingDecision:
    """SELECT with >= 1 selection, or ABSTAIN with none. Anything else is malformed."""

    decision: DecisionKind
    selections: Tuple[Selection, ...] = ()

    def __post_init__(self) -> None:
        if self.decision not in ("SELECT", "ABSTAIN"):
            raise DecisionFormatError(f"decision must be SELECT or ABSTAIN: {self.decision!r}")
        if self.decision == "SELECT" and not self.selections:
            raise DecisionFormatError("SELECT requires at least one selection")
        if self.decision == "ABSTAIN" and self.selections:
            raise DecisionFormatError("ABSTAIN must have no selections")

    @classmethod
    def from_dict(cls, raw: Any) -> "MappingDecision":
        """Parse LLM JSON (already decoded). Structural checks only.

        Semantic problems (unknown ID, empty reason, wrong evidence) are left to
        validate.py so that one bad selection does not discard the others.
        """
        if not isinstance(raw, Mapping):
            raise DecisionFormatError("decision must be a JSON object")
        items = raw.get("selections", [])
        if not isinstance(items, list):
            raise DecisionFormatError("selections must be a list")
        selections = []
        for index, item in enumerate(items):
            path = f"selections[{index}]"
            if not isinstance(item, Mapping):
                raise DecisionFormatError(f"{path} must be an object")
            technique_id, evidence_ids, reason = (
                item.get("technique_id"), item.get("evidence_ids"), item.get("reason", ""))
            if not isinstance(technique_id, str):
                raise DecisionFormatError(f"{path}.technique_id must be a string")
            if not isinstance(evidence_ids, list) or any(not isinstance(e, str) for e in evidence_ids):
                raise DecisionFormatError(f"{path}.evidence_ids must be a list of strings")
            if not isinstance(reason, str):
                raise DecisionFormatError(f"{path}.reason must be a string")
            selections.append(Selection(technique_id, tuple(evidence_ids), reason))
        return cls(raw.get("decision"), tuple(selections))


class SelectionRejection(TypedDict, total=False):
    code: str                   # e.g. INVALID_TECHNIQUE_ID, NOT_IN_CANDIDATES
    mapping_unit_id: str
    value: str                  # technique_id as returned by the LLM
    detail: str
    evidence_id: str
    reasons: List[str]


@dataclass(frozen=True)
class ValidatedSelection:
    """A selection that passed every check. Metadata comes from the catalog and
    refs/time from the evidence, never from the LLM."""

    mapping_unit_id: str
    technique: TechniqueRecord
    evidence_ids: Tuple[str, ...]
    raw_refs: Tuple[str, ...]
    time: Optional[str]
    reason: str
    # e.g. SEED_ONLY_RAW_REFS, TECHNIQUE_ID_NORMALIZED — informational, not a rejection.
    flags: Tuple[str, ...] = ()


class ParentTechnique(TypedDict):
    technique_id: str
    technique_name: str


class SelectionReason(TypedDict):
    mapping_unit_id: str
    evidence_ids: List[str]
    reason: str


class AttackMappingEntry(MappedTechnique, total=False):
    """RAG technique entry. Rule-era keys stay: matched_by=["evidence"],
    matched_keywords=[] so killchain.py and existing readers keep working."""

    parent_technique: Optional[ParentTechnique]
    selections: List[SelectionReason]
    flags: List[str]
