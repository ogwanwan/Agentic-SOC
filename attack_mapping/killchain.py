"""Kill chain assembly: orders A's deduped techniques into ATT&CK tactic stages.

Consumes AttackMappingResult["techniques"] (MappedTechnique dicts) exactly as
produced by attack_mapping.engine.map_investigation. This module never reads
investigation_result or evidence_chain directly, never re-derives a time for a
technique that has none, and never mutates its input.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .schema import TACTIC_ORDER, MappedTechnique

_TACTIC_RANK = {name: rank for rank, name in enumerate(TACTIC_ORDER)}
_UNKNOWN_TACTIC_RANK = len(TACTIC_ORDER)


def _representative_time(technique: MappedTechnique) -> Optional[str]:
    """Earliest recorded time for a technique, or None if every hit was verdict-only."""
    times = technique.get("times") or []
    return min(times) if times else None


def build_kill_chain(techniques: List[MappedTechnique]) -> List[Dict[str, Any]]:
    """Reorder deduped techniques into a step-numbered kill chain.

    Sort key: (1) tactic position in TACTIC_ORDER, unknown tactic names last;
    (2) earliest recorded time ascending, with untimed (verdict-only) techniques
    placed after timed ones within the same tactic. Python's stable sort keeps
    `techniques`' own order (technique_id order, from map_investigation) as the
    tie-breaker, so output is deterministic across repeated runs on the same
    mapping result. A technique_id never appears twice: map_investigation already
    merges every hit for the same technique into one MappedTechnique.
    """
    def sort_key(technique: MappedTechnique):
        rank = _TACTIC_RANK.get(technique["tactic_name"], _UNKNOWN_TACTIC_RANK)
        time = _representative_time(technique)
        return (rank, time is None, time or "")

    ordered = sorted(techniques, key=sort_key)

    return [
        {
            "step": step,
            "tactic_id": technique["tactic_id"],
            "tactic_name": technique["tactic_name"],
            "technique_id": technique["technique_id"],
            "technique_name": technique["technique_name"],
            "time": _representative_time(technique),
            "evidence_ids": list(technique["evidence_ids"]),
        }
        for step, technique in enumerate(ordered, start=1)
    ]
