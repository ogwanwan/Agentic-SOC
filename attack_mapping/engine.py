"""Deterministic keyword mapping, separate from the Investigation Agent.

Public entry point: map_investigation(investigation_result, rules=ALL_RULES).
The caller supplies B's catalog; this module imports neither it nor agent code.
Pure match helpers raise ValueError on malformed input and do not apply gates.
The entry point turns validation errors into an empty `error` result.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict
from typing import Any, Dict, List, Tuple

from .schema import AttackMappingResult, MappedTechnique, MappingHit, MappingStatus, TechniqueRule


def _object(value: Any, path: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _string(value: Any, path: str, *, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{path} must be {'a non-empty' if required else 'a'} string")
    return value


def _strings(value: Any, path: str) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list of non-empty strings")
    for item in value:
        _string(item, path, required=True)
    return list(dict.fromkeys(value))


def _rule_json(rule: TechniqueRule) -> str:
    record = asdict(rule)
    for name in ("attack_type_keywords", "evidence_keywords"):
        record[name] = sorted(set(record[name]))
    return json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _prepare_rules(rules: Iterable[TechniqueRule]) -> Tuple[TechniqueRule, ...]:
    if not isinstance(rules, Iterable) or isinstance(rules, (str, bytes, dict)):
        raise ValueError("rules must be an iterable of TechniqueRule objects")
    unique: Dict[str, TechniqueRule] = {}
    technique_names: Dict[str, str] = {}
    tactic_names: Dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, TechniqueRule):
            raise ValueError("rules must contain only TechniqueRule objects")
        for names, identifier, name in (
            (technique_names, rule.technique_id, rule.technique_name),
            (tactic_names, rule.tactic_id, rule.tactic_name),
        ):
            if identifier in names and names[identifier] != name:
                raise ValueError(f"conflicting names for {identifier} in rules")
            names[identifier] = name
        unique[_rule_json(rule)] = rule
    return tuple(unique[key] for key in sorted(unique))


def mapping_table_version(rules: Iterable[TechniqueRule]) -> str:
    """SHA-256 of all rule fields, stable across processes and catalog order.

    Keyword order and exact duplicate rules/keywords do not affect the version.
    The prefix versions this serialization contract, not the upstream ATT&CK DB.
    """
    payload = "[" + ",".join(_rule_json(rule) for rule in _prepare_rules(rules)) + "]"
    return "rules-v1-sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _keywords(texts: List[str], keywords: Tuple[str, ...]) -> Tuple[str, ...]:
    normalized = [text.strip().casefold() for text in texts]
    words = {word.strip().casefold() for word in keywords if word.strip()}
    # Compare fields separately: joining them could manufacture a cross-field hit.
    return tuple(sorted(word for word in words if any(word in text for text in normalized)))


def _verdict_hits(attack_type: str, rules: Tuple[TechniqueRule, ...]) -> List[MappingHit]:
    hits = []
    for rule in rules:
        keywords = _keywords([attack_type], rule.attack_type_keywords)
        if keywords:
            hits.append(MappingHit(
                rule.technique_id, rule.technique_name, rule.tactic_id, rule.tactic_name,
                "verdict", matched_keywords=keywords,
            ))
    return hits


def match_verdict(
    investigation_result: Dict[str, Any], rules: Iterable[TechniqueRule]
) -> List[MappingHit]:
    """Match final_verdict.attack_type only; map_investigation applies policy."""
    data = _object(investigation_result, "investigation_result")
    verdict = _object(data.get("final_verdict"), "final_verdict")
    attack_type = _string(verdict.get("attack_type"), "final_verdict.attack_type")
    return _verdict_hits(attack_type, _prepare_rules(rules))


def _evidence_chain(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    chain = data.get("evidence_chain")
    if not isinstance(chain, list):
        raise ValueError("evidence_chain must be a list")
    result = []
    seen = set()
    for index, item in enumerate(chain):
        path = f"evidence_chain[{index}]"
        evidence = dict(_object(item, path))
        eid = _string(evidence.get("evidence_id"), f"{path}.evidence_id", required=True)
        if eid in seen:
            raise ValueError(f"duplicate evidence_id: {eid}")
        seen.add(eid)
        for name in ("event_type", "description"):
            evidence[name] = _string(evidence.get(name), f"{path}.{name}")
        _string(evidence.get("time"), f"{path}.time")
        evidence["time"] = evidence.get("time")
        sequence = evidence.get("sequence")
        if sequence is not None and (type(sequence) is not int or sequence < 1):
            raise ValueError(f"{path}.sequence must be a positive integer")
        refs = evidence.get("raw_refs")
        # report.py always emits raw_refs. Do not synthesize citations from raw_ref,
        # source_log, top-level raw_refs, prose, or the attack timeline.
        evidence["raw_refs"] = _strings(refs if refs is not None else [], f"{path}.raw_refs")
        result.append(evidence)
    return result


def _evidence_hits(
    chain: List[Dict[str, Any]], rules: Tuple[TechniqueRule, ...]
) -> List[MappingHit]:
    hits = []
    for evidence in chain:
        for rule in rules:
            keywords = _keywords([evidence["event_type"], evidence["description"]], rule.evidence_keywords)
            if keywords:
                hits.append(MappingHit(
                    rule.technique_id, rule.technique_name, rule.tactic_id, rule.tactic_name,
                    "evidence", matched_keywords=keywords, evidence_ids=(evidence["evidence_id"],),
                    time=evidence["time"], raw_refs=tuple(evidence["raw_refs"]),
                ))
    return hits


def match_evidence(
    investigation_result: Dict[str, Any], rules: Iterable[TechniqueRule]
) -> List[MappingHit]:
    """Match evidence_chain only, with no verdict/provenance gate or mutation."""
    data = _object(investigation_result, "investigation_result")
    return _evidence_hits(_evidence_chain(data), _prepare_rules(rules))


def _eligible_evidence(
    chain: List[Dict[str, Any]], provenance: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Consume upstream validation findings; never revalidate source logs."""
    missing = _strings(provenance.get("evidence_without_raw_refs", []), "provenance.evidence_without_raw_refs")
    ambiguous = _object(provenance.get("ambiguous_raw_refs", {}), "provenance.ambiguous_raw_refs")
    issues = provenance.get("issues", [])
    if not isinstance(issues, list):
        raise ValueError("provenance.issues must be a list")
    affected_sequences = set()
    for index, item in enumerate(issues):
        issue = _object(item, f"provenance.issues[{index}]")
        sequence = issue.get("sequence")
        if sequence is not None:
            if type(sequence) is not int or sequence < 1:
                raise ValueError("provenance.issues.sequence must be a positive integer")
            affected_sequences.add(sequence)
    eligible, excluded = [], []
    for evidence in chain:
        if (not evidence["raw_refs"] or evidence["evidence_id"] in missing
                or any(ref in ambiguous for ref in evidence["raw_refs"])
                or evidence.get("sequence") in affected_sequences):
            excluded.append(evidence["evidence_id"])
        else:
            eligible.append(evidence)
    return eligible, excluded


def _merge_hits(hits: List[MappingHit]) -> List[MappedTechnique]:
    techniques: Dict[str, MappedTechnique] = {}
    for hit in dict.fromkeys(hits):
        if hit.technique_id not in techniques:
            techniques[hit.technique_id] = {
                "technique_id": hit.technique_id, "technique_name": hit.technique_name,
                "tactic_id": hit.tactic_id, "tactic_name": hit.tactic_name, "tactics": [],
                "matched_by": [], "matched_keywords": [], "evidence_ids": [],
                "raw_refs": [], "times": [], "matches": [],
            }
        technique = techniques[hit.technique_id]
        tactic = {"tactic_id": hit.tactic_id, "tactic_name": hit.tactic_name}
        if tactic not in technique["tactics"]:
            technique["tactics"].append(tactic)
        for name, values in (
            ("matched_by", [hit.matched_by]), ("matched_keywords", hit.matched_keywords),
            ("evidence_ids", hit.evidence_ids), ("raw_refs", hit.raw_refs),
            ("times", [hit.time] if hit.time is not None else []),
        ):
            technique[name] = list(dict.fromkeys([*technique[name], *values]))
        technique["matches"].append({
            **tactic, "matched_by": hit.matched_by, "matched_keywords": list(hit.matched_keywords),
            "evidence_ids": list(hit.evidence_ids), "time": hit.time, "raw_refs": list(hit.raw_refs),
        })
    for technique in techniques.values():
        technique["tactics"].sort(key=lambda tactic: tactic["tactic_id"])
        technique.update(technique["tactics"][0])
        technique["matched_keywords"].sort()
    return [techniques[key] for key in sorted(techniques)]


def _mapping_status(techniques: List[MappedTechnique], provenance_status: str) -> MappingStatus:
    # No match takes precedence over partial, including when every evidence was excluded.
    if not techniques:
        return "no_techniques_matched"
    return "partial" if provenance_status == "incomplete" else "mapped"


def map_investigation(
    investigation_result: Dict[str, Any], rules: Iterable[TechniqueRule]
) -> AttackMappingResult:
    """Map one completed investigation using an explicitly supplied rule catalog.

    Gate order: FALSE_POSITIVE -> not_applicable; INCONCLUSIVE or unavailable
    provenance -> deferred. Missing provenance is treated as unavailable; unknown
    verdict/status values are errors. Gated results have no unmatched evidence.

    With incomplete provenance, use only cited evidence unflagged by upstream
    findings, and disable verdict hits entirely. At least one hit -> partial;
    zero hits -> no_techniques_matched. Unmatched eligible evidence alone does
    not make a passed result partial. Input dicts are never modified.
    """
    result: AttackMappingResult = {
        "incident_id": None, "investigation_id": None, "mapping_status": "error",
        "provenance_status": None, "techniques": [], "unmatched_evidence_ids": [],
        "excluded_evidence_ids": [], "raw_ref_locations": {},
        "mapping_table_version": None, "errors": [],
    }
    try:
        data = _object(investigation_result, "investigation_result")
        for name in ("incident_id", "investigation_id"):
            result[name] = _string(data.get(name), name, required=True)
        final_verdict = _object(data.get("final_verdict"), "final_verdict")
        verdict = _string(final_verdict.get("verdict"), "final_verdict.verdict", required=True)
        if verdict not in ("THREAT_CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE"):
            raise ValueError(f"unsupported final_verdict.verdict: {verdict}")
        catalog = _prepare_rules(rules)
        result["mapping_table_version"] = mapping_table_version(catalog)
        provenance = _object(data.get("provenance", {}), "provenance")
        status = provenance.get("status", "unavailable")
        if status not in ("passed", "incomplete", "unavailable"):
            raise ValueError("provenance.status must be passed, incomplete or unavailable")
        result["provenance_status"] = status
        if verdict == "FALSE_POSITIVE":
            result["mapping_status"] = "not_applicable"
            return result
        if verdict == "INCONCLUSIVE" or status == "unavailable":
            result["mapping_status"] = "deferred"
            return result

        attack_type = _string(final_verdict.get("attack_type"), "final_verdict.attack_type")
        chain = _evidence_chain(data)
        locations = _object(data.get("raw_ref_locations", {}), "raw_ref_locations")
        copied_locations = {
            _string(ref, "raw_ref_locations key", required=True): _strings(sources, "raw_ref_locations value")
            for ref, sources in locations.items()
        }
        excluded = []
        if status == "incomplete":
            chain, excluded = _eligible_evidence(chain, provenance)
        hits = _evidence_hits(chain, catalog)
        if status == "passed":
            hits = _verdict_hits(attack_type, catalog) + hits
        techniques = _merge_hits(hits)
        matched_ids = {eid for hit in hits for eid in hit.evidence_ids}
        result.update(
            mapping_status=_mapping_status(techniques, status), techniques=techniques,
            unmatched_evidence_ids=[ev["evidence_id"] for ev in chain if ev["evidence_id"] not in matched_ids],
            excluded_evidence_ids=excluded, raw_ref_locations=copied_locations,
        )
    except ValueError as exc:
        result["errors"].append(str(exc))
    return result
