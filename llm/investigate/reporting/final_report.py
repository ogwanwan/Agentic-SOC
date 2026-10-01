"""Merge a finished investigation result with its attack-mapping result.

This is the simplified, current-scope stand-in for the eventual Final Report
Builder (investigation + attack_mapping + response + autonomy). Response and
Autonomy stages do not exist yet, so only the two available artifacts are
combined. It consumes finished JSON-shaped dicts only: it never re-runs the
Investigation Agent or attack_mapping.engine, and never mutates its inputs.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


def build_final_report(
    investigation_result: Dict[str, Any], mapping_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Return a new dict: a copy of investigation_result plus an "attack_mapping" key.

    `mapping_result` is expected to already include the "kill_chain" key (added
    by attack_mapping.killchain.build_kill_chain before this is called) — this
    function does not compute or check for it.
    """
    final_report = deepcopy(investigation_result)
    final_report["attack_mapping"] = deepcopy(mapping_result)
    return final_report
