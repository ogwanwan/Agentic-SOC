"""Kill chain assembly: orders A's deduped techniques into ATT&CK tactic stages.

Consumes AttackMappingResult["techniques"] (MappedTechnique dicts) exactly as
produced by attack_mapping.engine.map_investigation. This module never reads
investigation_result or evidence_chain directly, never re-derives a time for a
technique that has none, and never mutates its input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from primary_detection.normalizer.common.timeparse import normalize_iso

from .schema import TACTIC_ORDER, MappedTechnique

_TACTIC_RANK = {name: rank for rank, name in enumerate(TACTIC_ORDER)}
_UNKNOWN_TACTIC_RANK = len(TACTIC_ORDER)
_UNKNOWN_TIME = datetime.max.replace(tzinfo=timezone.utc)


def _time_sort_key(value: Optional[str]) -> Tuple[int, datetime]:
    """Compare instants in UTC; retain unparseable/absent times after known ones.

    Naive timestamps follow the investigation tools' UTC default. Unparseable
    strings remain in the output, but are not treated as chronological evidence.
    """
    if value is None:
        return (2, _UNKNOWN_TIME)
    try:
        parsed = datetime.fromisoformat(normalize_iso(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (0, parsed.astimezone(timezone.utc))
    except (ValueError, OverflowError):
        return (1, _UNKNOWN_TIME)


def _representative_time(technique: MappedTechnique) -> Optional[str]:
    """Earliest parseable instant in its original spelling, or first invalid time.

    Return None when no hit recorded a time. Equal instants keep encounter order.
    """
    times = technique.get("times") or []
    return min(times, key=_time_sort_key) if times else None


def build_kill_chain(techniques: List[MappedTechnique]) -> List[Dict[str, Any]]:
    """Reorder deduped techniques into a step-numbered kill chain.

    Sort key: (1) tactic position in TACTIC_ORDER, unknown tactic names last;
    (2) earliest recorded instant in UTC, then unparseable times, then untimed
    (verdict-only) techniques within the same tactic. Original time strings are
    preserved in the output. Python's stable sort keeps
    `techniques`' own order (technique_id order, from map_investigation) as the
    tie-breaker, so output is deterministic across repeated runs on the same
    mapping result. A technique_id never appears twice: map_investigation already
    merges every hit for the same technique into one MappedTechnique.
    """
    def sort_key(technique: MappedTechnique):
        rank = _TACTIC_RANK.get(technique["tactic_name"], _UNKNOWN_TACTIC_RANK)
        time = _representative_time(technique)
        return (rank, *_time_sort_key(time))

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
