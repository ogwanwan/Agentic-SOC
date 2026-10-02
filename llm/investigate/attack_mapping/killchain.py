"""Kill chain assembly: orders deduped techniques by observed event chronology.

Consumes AttackMappingResult["techniques"] (MappedTechnique dicts) exactly as
produced by attack_mapping.engine.map_investigation. This module never reads
investigation_result or evidence_chain directly, never re-derives a time for a
technique that has none, and never mutates its input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from agent.tools.time_utils import parse_iso

from .schema import TACTIC_ORDER, MappedTechnique

_TACTIC_RANK = {name: rank for rank, name in enumerate(TACTIC_ORDER)}
_UNKNOWN_TIME = datetime.max.replace(tzinfo=timezone.utc)


def _time_sort_key(value: Optional[str]) -> Tuple[int, datetime]:
    """Compare instants in UTC; retain unparseable/absent times after known ones.

    Naive timestamps follow the investigation tools' UTC default. Unparseable
    strings remain in the output, but are not treated as chronological evidence.
    """
    if value is None:
        return (2, _UNKNOWN_TIME)
    try:
        parsed = parse_iso(value)
        return (0, parsed.astimezone(timezone.utc))
    except (ValueError, OverflowError):
        return (1, _UNKNOWN_TIME)


def _representative_time(technique: MappedTechnique) -> Optional[str]:
    """Earliest parseable instant in its original spelling, or first invalid time.

    Return None when no hit recorded a time. Equal instants keep encounter order.
    """
    times = technique.get("times") or []
    return min(times, key=_time_sort_key) if times else None


def _representative_sequence(
    technique: MappedTechnique, evidence_sequences: Optional[Mapping[str, int]]
) -> Optional[int]:
    """Use the original Evidence sequence; never infer one from an ID or position."""
    if evidence_sequences is None:
        return None
    sequences = [
        sequence
        for evidence_id in technique.get("evidence_ids", [])
        if type(sequence := evidence_sequences.get(evidence_id)) is int and sequence > 0
    ]
    return min(sequences) if sequences else None


def build_kill_chain(
    techniques: List[MappedTechnique],
    *,
    evidence_sequences: Optional[Mapping[str, int]] = None,
    tactic_ranks: Optional[Mapping[str, int]] = None,
) -> List[Dict[str, Any]]:
    """Reorder deduped techniques into a step-numbered kill chain.

    Sort by the earliest observed UTC instant across tactics. Original Evidence
    sequence breaks equal-time ties and orders untimed techniques when supplied.
    Known times precede untimed evidence; unparseable times stay ahead of fully
    untimed entries when neither has a sequence. Tactic order is only a display
    tie-breaker when event time and sequence cannot distinguish techniques;
    input order remains the final stable tie-breaker.
    """
    def sort_key(technique: MappedTechnique):
        time_status, instant = _time_sort_key(_representative_time(technique))
        sequence = _representative_sequence(technique, evidence_sequences)
        tactic_rank = (
            tactic_ranks.get(technique["tactic_id"], len(tactic_ranks))
            if tactic_ranks is not None
            else _TACTIC_RANK.get(technique["tactic_name"], len(_TACTIC_RANK))
        )
        if time_status == 0:
            return (0, instant, sequence if sequence is not None else float("inf"), tactic_rank)
        if sequence is not None:
            return (1, _UNKNOWN_TIME, sequence, tactic_rank)
        return (2 if time_status == 1 else 3, _UNKNOWN_TIME, float("inf"), tactic_rank)

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
