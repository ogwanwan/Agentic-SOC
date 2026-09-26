"""CLI entry point for ATT&CK Mapping.

    python -m attack_mapping.cli results/사건.json
    python -m attack_mapping.cli --all-in-dir results/ --out-dir results/attack_mapping

For each investigation_result JSON file: runs A's engine.map_investigation()
with B's rule catalog, attaches C's kill chain, writes "<name>_attack_mapping.json"
and "<name>_final_report.json" under --out-dir, and prints a one-line summary.

`attack_mapping/rules/` (B's catalog) is imported lazily inside _load_rules(),
not at module load time, so this module and its tests work before that package
exists, and so tests can inject a small fixture catalog via `run(..., rules=...)`
instead of depending on B's real ALL_RULES.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import engine
from .killchain import build_kill_chain
from .schema import TechniqueRule
from reporting.final_report import build_final_report


def _load_rules() -> Sequence[TechniqueRule]:
    from .rules import ALL_RULES  # deferred import: attack_mapping/rules/ is B's package

    return ALL_RULES


def _investigation_files(path: Optional[str], all_in_dir: Optional[str]) -> List[str]:
    if all_in_dir:
        return sorted(
            os.path.join(all_in_dir, name)
            for name in os.listdir(all_in_dir)
            if name.endswith(".json")
        )
    return [path]


def _output_stem(mapping_result: Dict[str, Any], investigation_result_path: str) -> str:
    stem = mapping_result.get("incident_id") or mapping_result.get("investigation_id")
    if isinstance(stem, str) and stem.strip():
        return stem
    base = os.path.basename(investigation_result_path)
    return base[: -len(".json")] if base.endswith(".json") else base


def process_file(
    investigation_result_path: str, rules: Sequence[TechniqueRule], out_dir: str
) -> Dict[str, Any]:
    """Map one investigation_result file; write its attack_mapping/final_report JSON.

    Returns the kill-chain-augmented mapping result (for the caller's summary line).
    Raises OSError/json.JSONDecodeError if the input file cannot be read or parsed;
    engine.map_investigation() itself never raises (schema/content errors surface
    as mapping_status="error" in the returned dict instead).
    """
    with open(investigation_result_path, "r", encoding="utf-8") as f:
        investigation_result = json.load(f)

    mapping_result = dict(engine.map_investigation(investigation_result, rules))
    mapping_result["kill_chain"] = build_kill_chain(mapping_result["techniques"])

    os.makedirs(out_dir, exist_ok=True)
    stem = _output_stem(mapping_result, investigation_result_path)

    with open(os.path.join(out_dir, f"{stem}_attack_mapping.json"), "w", encoding="utf-8") as f:
        json.dump(mapping_result, f, ensure_ascii=False, indent=2)

    final_report = build_final_report(investigation_result, mapping_result)
    with open(os.path.join(out_dir, f"{stem}_final_report.json"), "w", encoding="utf-8") as f:
        json.dump(final_report, f, ensure_ascii=False, indent=2)

    return mapping_result


def _summary_line(investigation_result_path: str, mapping_result: Dict[str, Any]) -> str:
    label = mapping_result.get("incident_id") or os.path.basename(investigation_result_path)
    status = mapping_result["mapping_status"]
    if status == "error":
        return f"[{label}] mapping_status=error: {'; '.join(mapping_result['errors'])}"
    techniques = ", ".join(
        f"{t['technique_id']} {t['technique_name']}" for t in mapping_result["techniques"]
    )
    return f"[{label}] mapping_status={status} techniques={len(mapping_result['techniques'])}: {techniques}"


def run(argv: Optional[Sequence[str]] = None, rules: Optional[Sequence[TechniqueRule]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attack_mapping.cli")
    parser.add_argument("path", nargs="?", help="investigation_result JSON file")
    parser.add_argument(
        "--all-in-dir", dest="all_in_dir", metavar="DIR",
        help="process every *.json file in DIR instead of a single file",
    )
    parser.add_argument(
        "--out-dir", default="results/attack_mapping",
        help="output directory for attack_mapping.json / final_report.json (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    if bool(args.path) == bool(args.all_in_dir):
        parser.error("provide exactly one of: a file path, or --all-in-dir DIR")

    files = _investigation_files(args.path, args.all_in_dir)
    if not files:
        print(f"no *.json files found in {args.all_in_dir}", file=sys.stderr)
        return 1

    active_rules = rules if rules is not None else _load_rules()
    exit_code = 0
    for investigation_result_path in files:
        try:
            mapping_result = process_file(investigation_result_path, active_rules, args.out_dir)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[{os.path.basename(investigation_result_path)}] skipped: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        print(_summary_line(investigation_result_path, mapping_result))
        if mapping_result["mapping_status"] == "error":
            exit_code = 1
    return exit_code


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
