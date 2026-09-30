"""CLI entry point for ATT&CK Mapping.

    python -m attack_mapping.cli results/사건.json
    python -m attack_mapping.cli --all-in-dir results/ --out-dir results/attack_mapping
    python -m attack_mapping.cli --rule-baseline results/사건.json

By default, each saved investigation runs the official Catalog, hybrid retrieval,
LLM selection and Validator before writing mapping and final-report JSON files.
--rule-baseline selects the previous rule engine for comparison.
Names are sanitized single filename components; existing output pairs are
preserved by adding __2, __3, ... to the stem. IDs inside JSON are unchanged.
Batch input/output directories must differ. Generated artifacts are ignored in
batch input, and JSON (including UTF-8 BOM) is limited to MAX_JSON_DEPTH levels.

Rule definitions are imported only for the explicit baseline. Tests can inject
rule fixtures with `run(..., rules=...)` without changing the RAG default.
"""

from __future__ import annotations

from .mapper import (
    build_rag_kill_chain,
    map_investigation as map_rag_investigation,
)
from .catalog import get_default_catalog, read_manifest
from .retrieve import DEFAULT_CACHE_DIR
from .runtime import MappingRuntime
from .validate import check_case_gate, classify_evidence, target_evidence

import argparse
import json
import os
import re
import sys
from contextlib import ExitStack
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import engine
from .killchain import build_kill_chain
from .schema import CatalogError, TechniqueRule
from reporting.final_report import build_final_report

MAX_JSON_DEPTH = 128


class GeneratedArtifactError(ValueError):
    """An existing mapping/final report is not a fresh investigation input."""


def _print(message: str, *, file=None) -> bool:
    """Keep console encoding limitations from interrupting file processing."""
    stream = file if file is not None else sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    safe = message.encode(encoding, errors="backslashreplace").decode(encoding)
    try:
        print(safe, file=stream, flush=True)
        return True
    except (OSError, ValueError):
        # A closed/broken output stream must not drop the remaining incidents.
        return False


def _validate_input_depth(value: Any) -> None:
    # json.load may accept nesting that recursive report copying cannot handle.
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"investigation JSON exceeds maximum depth {MAX_JSON_DEPTH}")
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)


def _is_generated_artifact(value: Dict[str, Any]) -> bool:
    mapping = value.get("attack_mapping", value)
    return isinstance(mapping, dict) and all(
        key in mapping for key in ("mapping_status", "techniques", "mapping_table_version")
    )


def _load_rules() -> Sequence[TechniqueRule]:
    from .rules import ALL_RULES  # deferred import: attack_mapping/rules/ is B's package

    return ALL_RULES


def _investigation_files(path: Optional[str], all_in_dir: Optional[str]) -> List[str]:
    if all_in_dir:
        return sorted(
            os.path.join(all_in_dir, name)
            for name in os.listdir(all_in_dir)
            if name.lower().endswith(".json") and os.path.isfile(os.path.join(all_in_dir, name))
        )
    return [path]


def _output_stem(mapping_result: Dict[str, Any], investigation_result_path: str) -> str:
    stem = mapping_result.get("incident_id") or mapping_result.get("investigation_id")
    if not isinstance(stem, str) or not stem.strip():
        base = os.path.basename(investigation_result_path)
        stem = base[: -len(".json")] if base.lower().endswith(".json") else base
    # Treat IDs as labels, never as paths (including Windows paths on POSIX).
    stem = re.sub(r"[^\w.-]", "_", stem).strip(" .")
    # Leave room for suffixes within common filesystem component limits.
    stem = stem.encode("utf-8")[:180].decode("utf-8", errors="ignore").rstrip(" .") or "investigation"
    if re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]", stem.split(".")[0], re.IGNORECASE):
        stem = "_" + stem
    return stem


def _output_paths(out_dir: str, stem: str) -> Tuple[str, str]:
    """Choose one unused stem for both artifacts, also across separate runs."""
    number = 1
    while True:
        candidate = stem if number == 1 else f"{stem}__{number}"
        mapping_path = os.path.join(out_dir, f"{candidate}_attack_mapping.json")
        report_path = os.path.join(out_dir, f"{candidate}_final_report.json")
        # lexists also reserves dangling symlinks; never follow an old output.
        if not os.path.lexists(mapping_path) and not os.path.lexists(report_path):
            return mapping_path, report_path
        number += 1


def _write_output_pair(out_dir: str, stem: str, mapping: Dict[str, Any], report: Dict[str, Any]) -> None:
    # Serialize/encode both before reserving paths: invalid values must not leave
    # truncated JSON. Exclusive creation reserves a pair against other writers.
    documents = [json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") for value in (mapping, report)]
    while True:
        paths = _output_paths(out_dir, stem)
        created = []
        try:
            with ExitStack() as stack:
                streams = []
                for path in paths:
                    streams.append(stack.enter_context(open(path, "xb")))
                    created.append(path)
                for stream, document in zip(streams, documents):
                    stream.write(document)
            return
        except BaseException as exc:
            # Only remove files created by this attempt, after closing handles.
            for path in created:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            if not isinstance(exc, FileExistsError):
                raise
            # Another writer took a name between lookup and exclusive creation.
            # Retry using the next free pair instead of dropping the investigation.


def process_file_rule(
    investigation_result_path: str, rules: Sequence[TechniqueRule], out_dir: str
) -> Dict[str, Any]:
    """Map one investigation_result file; write its attack_mapping/final_report JSON.

    Returns the kill-chain-augmented mapping result (for the caller's summary line).
    Raises OSError/ValueError/RecursionError for unsupported input or write failure;
    engine.map_investigation() itself never raises (schema/content errors surface
    as mapping_status="error" in the returned dict instead).
    """
    with open(investigation_result_path, "r", encoding="utf-8-sig") as f:
        investigation_result = json.load(f)
    if not isinstance(investigation_result, dict):
        raise ValueError("investigation_result must be a JSON object")
    _validate_input_depth(investigation_result)
    if _is_generated_artifact(investigation_result):
        raise GeneratedArtifactError("generated ATT&CK artifact; expected an investigation result")

    mapping_result = dict(engine.map_investigation(investigation_result, rules))
    mapping_result["kill_chain"] = build_kill_chain(
        mapping_result["techniques"],
        evidence_sequences=_evidence_sequences(investigation_result),
    )
    final_report = build_final_report(investigation_result, mapping_result)

    os.makedirs(out_dir, exist_ok=True)
    stem = _output_stem(mapping_result, investigation_result_path)
    _write_output_pair(out_dir, stem, mapping_result, final_report)

    return mapping_result


def _evidence_sequences(investigation_result: Dict[str, Any]) -> Dict[str, int]:
    """Keep original investigation order available to Kill Chain builders."""
    chain = investigation_result.get("evidence_chain")
    if not isinstance(chain, list):
        return {}
    sequences: Dict[str, int] = {}
    for evidence in chain:
        if not isinstance(evidence, dict):
            continue
        evidence_id, sequence = evidence.get("evidence_id"), evidence.get("sequence")
        if (isinstance(evidence_id, str) and isinstance(sequence, int)
                and not isinstance(sequence, bool) and sequence > 0):
            sequences.setdefault(evidence_id, sequence)
    return sequences


def process_file_rag(
    investigation_result_path: str,
    out_dir: str,
    *,
    llm_client: Any,
    catalog: Any,
    build_mapping_unit_fn: Any,
    retrieve_candidates_fn: Any,
    retrieval_version: Optional[str] = None,
) -> Dict[str, Any]:
    """RAG 기반 ATT&CK Mapping으로 조사 결과 파일 하나를 처리한다.

    흐름:
        investigation_result JSON
        → mapper.map_investigation()
        → RAG Kill Chain
        → attack_mapping.json
        → final_report.json

    B의 실제 Retrieval이 아직 없어도
    build_mapping_unit_fn / retrieve_candidates_fn을
    주입해서 전체 C 경로를 테스트할 수 있다.
    """

    with open(
        investigation_result_path,
        "r",
        encoding="utf-8-sig",
    ) as f:
        investigation_result = json.load(f)

    if not isinstance(
        investigation_result,
        dict,
    ):
        raise ValueError(
            "investigation_result must be a JSON object"
        )

    _validate_input_depth(
        investigation_result
    )

    if _is_generated_artifact(
        investigation_result
    ):
        raise GeneratedArtifactError(
            "generated ATT&CK artifact; "
            "expected an investigation result"
        )

    mapping_result = dict(
        map_rag_investigation(
            investigation_result,
            llm_client=llm_client,
            catalog=catalog,
            build_mapping_unit_fn=(
                build_mapping_unit_fn
            ),
            retrieve_candidates_fn=(
                retrieve_candidates_fn
            ),
            retrieval_version=(
                retrieval_version
            ),
        )
    )

    # 사건의 Evidence 시각과 sequence로 정렬한다. 공식 tactic은 단계 metadata에 둔다.
    mapping_result["kill_chain"] = (
        build_rag_kill_chain(
            mapping_result["techniques"],
            catalog=catalog,
            evidence_sequences=_evidence_sequences(investigation_result),
        )
    )

    # 기존 Final Report Builder는 그대로 재사용한다.
    final_report = build_final_report(
        investigation_result,
        mapping_result,
    )

    os.makedirs(
        out_dir,
        exist_ok=True,
    )

    stem = _output_stem(
        mapping_result,
        investigation_result_path,
    )

    _write_output_pair(
        out_dir,
        stem,
        mapping_result,
        final_report,
    )

    return mapping_result


def _write_setup_error(
    investigation_result: Dict[str, Any], investigation_result_path: str,
    out_dir: str, gate: Any, exc: Exception, catalog: Any,
) -> Dict[str, Any]:
    """Preserve a technical RAG failure as an inspectable mapping result."""
    locations = investigation_result.get("raw_ref_locations")
    manifest = getattr(catalog, "manifest", {})
    mapping_result: Dict[str, Any] = {
        "incident_id": investigation_result.get("incident_id"),
        "investigation_id": investigation_result.get("investigation_id"),
        "mapping_status": "error",
        "provenance_status": gate.provenance_status,
        "techniques": [],
        "unmatched_evidence_ids": [],
        "excluded_evidence_ids": [],
        "raw_ref_locations": deepcopy(locations) if isinstance(locations, dict) else {},
        "mapping_table_version": None,
        "errors": [f"{type(exc).__name__}: {exc}"],
        "attack_version": getattr(catalog, "attack_version", None),
        "retrieval_version": manifest.get("retrieval_version") if isinstance(manifest, dict) else None,
        "mapping_method": "rag_llm",
        "exclusions": [],
        "rejected_selections": [],
        "retrieval_trace": [],
        "warnings": [deepcopy(item) for item in gate.warnings],
        "kill_chain": [],
    }
    report = build_final_report(investigation_result, mapping_result)
    os.makedirs(out_dir, exist_ok=True)
    _write_output_pair(out_dir, _output_stem(mapping_result, investigation_result_path),
                       mapping_result, report)
    return mapping_result


def _metadata_only_catalog() -> Any:
    """Report configured versions without loading STIX or an embedding model."""
    try:
        manifest = read_manifest()
    except CatalogError:
        manifest = {}
    return SimpleNamespace(attack_version=manifest.get("attack_version"),
                           manifest=manifest, tactic_order=())


def process_file(
    investigation_result_path: str,
    rules: Optional[Sequence[TechniqueRule]] = None,
    out_dir: str = "results/attack_mapping",
    *,
    llm_client: Any = None,
    catalog: Any = None,
    embedder: Any = None,
    cache_dir: Any = DEFAULT_CACHE_DIR,
) -> Dict[str, Any]:
    """Map a saved investigation through RAG; explicit rules select the baseline."""
    if rules is not None:
        return process_file_rule(investigation_result_path, rules, out_dir)

    with open(investigation_result_path, "r", encoding="utf-8-sig") as stream:
        investigation_result = json.load(stream)
    if not isinstance(investigation_result, dict):
        raise ValueError("investigation_result must be a JSON object")
    _validate_input_depth(investigation_result)
    if _is_generated_artifact(investigation_result):
        raise GeneratedArtifactError("generated ATT&CK artifact; expected an investigation result")

    gate = check_case_gate(investigation_result)
    needs_retrieval = gate.proceed
    if needs_retrieval:
        try:
            needs_retrieval = bool(target_evidence(classify_evidence(investigation_result)))
        except Exception:
            # mapper.map_investigation records the input error in its result.
            needs_retrieval = False
    if not needs_retrieval:
        return process_file_rag(
            investigation_result_path, out_dir,
            llm_client=None, catalog=_metadata_only_catalog(),
            build_mapping_unit_fn=None, retrieve_candidates_fn=None,
        )

    try:
        if catalog is None:
            catalog = get_default_catalog()
        runtime = MappingRuntime(catalog, embedder=embedder, cache_dir=cache_dir)
        if llm_client is None:
            from agent.llm_provider import build_llm_client
            llm_client = build_llm_client()
    except Exception as exc:
        return _write_setup_error(investigation_result, investigation_result_path,
                                  out_dir, gate, exc, catalog)

    return process_file_rag(
        investigation_result_path, out_dir,
        llm_client=llm_client, catalog=catalog,
        build_mapping_unit_fn=runtime.build_mapping_unit,
        retrieve_candidates_fn=runtime.retrieve_candidates,
        retrieval_version=runtime.manifest["retrieval_version"],
    )

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
    parser.add_argument("--rule-baseline", action="store_true",
                        help="use the legacy Rule mapping path instead of RAG")
    args = parser.parse_args(argv)

    if bool(args.path) == bool(args.all_in_dir):
        parser.error("provide exactly one of: a file path, or --all-in-dir DIR")

    if args.all_in_dir and os.path.normcase(os.path.realpath(args.all_in_dir)) == os.path.normcase(os.path.realpath(args.out_dir)):
        parser.error("input and output directories must be different")

    try:
        files = _investigation_files(args.path, args.all_in_dir)
    except OSError as exc:
        _print(f"cannot list input directory: {exc}", file=sys.stderr)
        return 1
    if not files:
        _print(f"no *.json files found in {args.all_in_dir}", file=sys.stderr)
        return 1

    from dotenv import load_dotenv
    load_dotenv()  # Same .env lookup and environment precedence as main.py.

    active_rules = rules if rules is not None else (_load_rules() if args.rule_baseline else None)
    exit_code = 0
    processed = 0
    for investigation_result_path in files:
        try:
            mapping_result = process_file(investigation_result_path, active_rules, args.out_dir)
        except GeneratedArtifactError as exc:
            _print(f"[{os.path.basename(investigation_result_path)}] ignored: {exc}", file=sys.stderr)
            continue
        except (OSError, ValueError, RecursionError) as exc:
            _print(f"[{os.path.basename(investigation_result_path)}] skipped: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        processed += 1
        if not _print(_summary_line(investigation_result_path, mapping_result)):
            exit_code = 1
        if mapping_result["mapping_status"] == "error":
            exit_code = 1
    return exit_code if processed else 1


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
