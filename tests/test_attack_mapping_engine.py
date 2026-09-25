"""Offline contract tests for A's engine; rules below are small test fixtures."""

import json
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from agent.models import AgentState, Evidence
from agent.report import build_investigation_result
from attack_mapping.engine import map_investigation, mapping_table_version, match_evidence, match_verdict
from attack_mapping.schema import TACTIC_ORDER, TechniqueRule


SHELL = TechniqueRule(
    technique_id="T1505.003", technique_name="Web Shell",
    tactic_id="TA0003", tactic_name="Persistence",
    attack_type_keywords=("web shell", "웹셸"), evidence_keywords=("webshell", "웹셸"),
)
BRUTE = TechniqueRule(
    technique_id="T1110", technique_name="Brute Force",
    tactic_id="TA0006", tactic_name="Credential Access",
    attack_type_keywords=("무차별 대입", "brute"), evidence_keywords=("ssh_failed",),
)
RULES = (SHELL, BRUTE)


def evidence(eid="EVID-001", **changes):
    return {
        "evidence_id": eid, "sequence": 1, "time": "2026-09-25T00:00:00Z",
        "layer": "audit", "event_type": "process_exec", "description": "Webshell observed",
        "source_log": "audit.log", "raw_ref": "audit.log:11", "raw_refs": ["audit.log:11"],
        **changes,
    }


def investigation(**changes):
    return {
        "incident_id": "INC-MAPPING", "investigation_id": "INV-MAPPING",
        "final_verdict": {"verdict": "THREAT_CONFIRMED", "attack_type": "Web Shell"},
        "evidence_chain": [evidence()], "contradicting_evidence": [],
        "raw_refs": ["audit.log:11"], "raw_ref_locations": {"audit.log:11": ["/synthetic/audit.log:11"]},
        "provenance": {"status": "passed", "evidence_without_raw_refs": [], "ambiguous_raw_refs": {}, "issues": []},
        **changes,
    }


def test_threat_confirmed_merges_verdict_and_evidence_without_mutating_input():
    source = investigation()
    before = deepcopy(source)
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "mapped"
    assert result["provenance_status"] == "passed"
    assert result["incident_id"] == source["incident_id"]
    assert result["investigation_id"] == source["investigation_id"]
    assert result["errors"] == result["unmatched_evidence_ids"] == result["excluded_evidence_ids"] == []
    assert len(result["techniques"]) == 1
    technique = result["techniques"][0]
    assert technique["technique_id"] == SHELL.technique_id
    assert technique["matched_by"] == ["verdict", "evidence"]
    assert technique["matched_keywords"] == ["web shell", "webshell"]
    assert technique["evidence_ids"] == ["EVID-001"]
    assert technique["raw_refs"] == ["audit.log:11"]
    assert technique["times"] == ["2026-09-25T00:00:00Z"]
    assert technique["matches"][0]["evidence_ids"] == technique["matches"][0]["raw_refs"] == []
    assert result["raw_ref_locations"] == source["raw_ref_locations"]
    assert json.loads(json.dumps(result)) == result
    assert source == before
    technique["matches"][1]["raw_refs"].append("output-only:1")
    result["raw_ref_locations"]["audit.log:11"].append("output-only:2")
    assert source == before


@pytest.mark.parametrize("verdict,expected", [("FALSE_POSITIVE", "not_applicable"), ("INCONCLUSIVE", "deferred")])
@pytest.mark.parametrize("status", ["passed", "incomplete", "unavailable"])
def test_verdict_gate_precedes_matching(verdict, expected, status):
    source = investigation(final_verdict={"verdict": verdict, "attack_type": "Web Shell"},
                           provenance={"status": status})
    # Gated inputs do not need a matchable evidence body.
    source["evidence_chain"] = None
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == expected
    assert result["provenance_status"] == status
    assert result["techniques"] == result["unmatched_evidence_ids"] == result["errors"] == []


def test_passed_allows_independent_verdict_and_evidence_techniques():
    source = investigation(final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "SSH 무차별 대입 시도"})
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "mapped"
    assert [item["technique_id"] for item in result["techniques"]] == [BRUTE.technique_id, SHELL.technique_id]
    assert result["techniques"][0]["matched_by"] == ["verdict"]
    assert result["techniques"][0]["evidence_ids"] == result["techniques"][0]["raw_refs"] == []
    assert result["techniques"][1]["matched_by"] == ["evidence"]


def test_incomplete_only_uses_cited_evidence_and_disables_verdict_hits():
    source = investigation(
        final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "SSH 무차별 대입 시도 / Web Shell"},
        provenance={"status": "incomplete"}, evidence_chain=[
            evidence(), evidence("EVID-002", sequence=2, event_type="ssh_failed", raw_refs=[]),
            evidence("EVID-003", sequence=3, event_type="heartbeat", description="unlisted activity", raw_refs=["audit.log:13"]),
        ],
    )
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "partial"
    assert [item["technique_id"] for item in result["techniques"]] == [SHELL.technique_id]
    assert result["techniques"][0]["matched_by"] == ["evidence"]
    assert result["techniques"][0]["matched_keywords"] == ["webshell"]
    assert result["techniques"][0]["evidence_ids"] == ["EVID-001"]
    assert result["unmatched_evidence_ids"] == ["EVID-003"]
    assert result["excluded_evidence_ids"] == ["EVID-002"]


@pytest.mark.parametrize("missing_refs", [None, []])
def test_incomplete_never_falls_back_to_raw_ref_or_global_refs(missing_refs):
    ev = evidence(raw_refs=missing_refs)
    if missing_refs is None:
        del ev["raw_refs"]
    source = investigation(evidence_chain=[ev], provenance={"status": "incomplete"})
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "no_techniques_matched"
    assert result["techniques"] == result["unmatched_evidence_ids"] == []
    assert result["excluded_evidence_ids"] == ["EVID-001"]


@pytest.mark.parametrize("findings", [
    {"evidence_without_raw_refs": ["EVID-002"]},
    {"ambiguous_raw_refs": {"audit.log:12": ["/first/audit.log:12", "/second/audit.log:12"]}},
    {"issues": [{"sequence": 2, "unknown_raw_refs": ["fabricated:5"]}]},
    {"issues": [{"sequence": 2, "error": "invalid reference"}]},
])
def test_incomplete_respects_upstream_findings_even_if_some_refs_remain(findings):
    source = investigation(provenance={"status": "incomplete", **findings}, evidence_chain=[
        evidence(), evidence("EVID-002", sequence=2, raw_refs=["audit.log:12"]),
    ])
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "partial"
    assert result["excluded_evidence_ids"] == ["EVID-002"]
    assert result["techniques"][0]["raw_refs"] == ["audit.log:11"]


@pytest.mark.parametrize("provenance", [{"status": "unavailable"}, {}])
def test_unavailable_provenance_defers(provenance):
    result = map_investigation(investigation(provenance=provenance), RULES)
    assert result["mapping_status"] == "deferred"
    assert result["provenance_status"] == "unavailable"
    assert result["techniques"] == result["unmatched_evidence_ids"] == []


def test_absent_provenance_is_unavailable():
    source = investigation()
    del source["provenance"]
    assert map_investigation(source, RULES)["mapping_status"] == "deferred"


@pytest.mark.parametrize("status", ["passed", "incomplete"])
def test_unmatched_evidence_is_not_an_error(status):
    source = investigation(provenance={"status": status},
                           final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "uncatalogued"},
                           evidence_chain=[evidence(description="uncatalogued activity")])
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "no_techniques_matched"
    assert result["techniques"] == result["errors"] == []
    assert result["unmatched_evidence_ids"] == ["EVID-001"]


def test_unmatched_evidence_alone_does_not_make_passed_mapping_partial():
    source = investigation(evidence_chain=[evidence(), evidence("EVID-002", description="heartbeat")])
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "mapped"
    assert result["unmatched_evidence_ids"] == ["EVID-002"]


def test_merge_preserves_each_evidence_reference_and_time_relationship():
    source = investigation(evidence_chain=[
        evidence(raw_refs=["audit.log:11", "audit.log:12", "audit.log:11"]),
        evidence("EVID-002", sequence=2, description="웹셸", time="2026-09-25T01:00:00+01:00",
                 raw_refs=["audit.log:12", "s3://test-bucket/audit.log:81"]),
    ])
    result = map_investigation(source, [SHELL, SHELL])
    assert len(result["techniques"]) == 1
    technique = result["techniques"][0]
    assert technique["evidence_ids"] == ["EVID-001", "EVID-002"]
    assert technique["raw_refs"] == ["audit.log:11", "audit.log:12", "s3://test-bucket/audit.log:81"]
    assert technique["matched_keywords"] == ["web shell", "webshell", "웹셸"]
    assert technique["times"] == [ev["time"] for ev in source["evidence_chain"]]
    matches = [match for match in technique["matches"] if match["matched_by"] == "evidence"]
    assert len(matches) == 2
    assert matches[0]["evidence_ids"] == ["EVID-001"]
    assert matches[0]["raw_refs"] == ["audit.log:11", "audit.log:12"]
    assert matches[1]["evidence_ids"] == ["EVID-002"]
    assert matches[1]["raw_refs"] == source["evidence_chain"][1]["raw_refs"]


def test_same_technique_under_multiple_tactics_keeps_all_tactics():
    other = replace(SHELL, tactic_id="TA0004", tactic_name="Privilege Escalation")
    result = map_investigation(investigation(), (other, SHELL))
    assert len(result["techniques"]) == 1
    technique = result["techniques"][0]
    assert technique["tactics"] == [
        {"tactic_id": "TA0003", "tactic_name": "Persistence"},
        {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation"},
    ]
    assert technique["tactic_id"] == "TA0003"
    assert {match["tactic_id"] for match in technique["matches"]} == {"TA0003", "TA0004"}


def test_match_helpers_handle_case_whitespace_and_empty_keywords_without_gating():
    rule = replace(SHELL, attack_type_keywords=(" WEB SHELL ", "", " ", "web shell"),
                   evidence_keywords=(" WEBSHELL ", "", "\t", "webshell"))
    source = investigation(provenance={"status": "incomplete"},
                           final_verdict={"verdict": "INCONCLUSIVE", "attack_type": "  web SHELL upload  "},
                           evidence_chain=[evidence(description="  wEbShElL observed  ", time=None)])
    assert match_verdict(source, [rule])[0].matched_keywords == ("web shell",)
    hit = match_evidence(source, [rule])[0]
    assert hit.matched_keywords == ("webshell",)
    assert hit.evidence_ids == ("EVID-001",) and hit.raw_refs == ("audit.log:11",)
    assert hit.time is None
    empty = replace(rule, attack_type_keywords=("", "  "), evidence_keywords=("", "\t"))
    assert match_verdict(source, [empty]) == match_evidence(source, [empty]) == []
    assert map_investigation(source, [rule])["mapping_status"] == "deferred"


def test_event_type_matches_and_fields_do_not_manufacture_cross_field_keywords():
    source = investigation(evidence_chain=[evidence(event_type=" SSH_FAILED ", description="")])
    assert match_evidence(source, [BRUTE])[0].technique_id == BRUTE.technique_id
    rule = replace(SHELL, evidence_keywords=("web shell",))
    assert match_evidence(investigation(evidence_chain=[evidence(event_type="web", description="shell")]), [rule]) == []


def test_contradicting_evidence_timeline_and_source_log_do_not_create_hits():
    source = investigation(final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": "unlisted"},
                           evidence_chain=[evidence(description="heartbeat", source_log="webshell")],
                           contradicting_evidence=[evidence("CONTRA-001")],
                           attack_timeline=[{"time": None, "event": "webshell"}])
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "no_techniques_matched"
    assert result["unmatched_evidence_ids"] == ["EVID-001"]


@pytest.mark.parametrize("status,attack_type,expected", [
    ("passed", "Web Shell", "mapped"), ("passed", "unknown", "no_techniques_matched"),
    ("incomplete", "Web Shell", "no_techniques_matched"),
])
def test_empty_evidence_chain(status, attack_type, expected):
    source = investigation(evidence_chain=[], provenance={"status": status},
                           final_verdict={"verdict": "THREAT_CONFIRMED", "attack_type": attack_type})
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == expected
    assert result["unmatched_evidence_ids"] == result["errors"] == []


def test_empty_catalog_does_not_infer_techniques():
    result = map_investigation(investigation(), [])
    assert result["mapping_status"] == "no_techniques_matched"
    assert result["unmatched_evidence_ids"] == ["EVID-001"]
    assert result["mapping_table_version"] == mapping_table_version([])


@pytest.mark.parametrize("patch,error_path", [
    ({"incident_id": None}, "incident_id"), ({"investigation_id": " "}, "investigation_id"),
    ({"final_verdict": None}, "final_verdict"), ({"final_verdict": {}}, "final_verdict.verdict"),
    ({"final_verdict": {"verdict": "UNKNOWN"}}, "unsupported final_verdict.verdict"),
    ({"final_verdict": {"verdict": ["THREAT_CONFIRMED"]}}, "final_verdict.verdict"),
    ({"final_verdict": {"verdict": "THREAT_CONFIRMED", "attack_type": 123}}, "attack_type"),
    ({"provenance": None}, "provenance"), ({"provenance": {"status": "unknown"}}, "provenance.status"),
    ({"provenance": {"status": []}}, "provenance.status"),
    ({"evidence_chain": None}, "evidence_chain"), ({"evidence_chain": {}}, "evidence_chain"),
    ({"evidence_chain": [None]}, "evidence_chain"),
    ({"evidence_chain": [evidence(evidence_id="")]}, "evidence_id"),
    ({"evidence_chain": [evidence(), evidence()]}, "duplicate evidence_id"),
    ({"evidence_chain": [evidence(description={})]}, "description"),
    ({"evidence_chain": [evidence(event_type=[])]}, "event_type"),
    ({"evidence_chain": [evidence(time=7)]}, "time"),
    ({"evidence_chain": [evidence(sequence=True)]}, "sequence"),
    ({"evidence_chain": [evidence(raw_refs="audit.log:11")]}, "raw_refs"),
    ({"evidence_chain": [evidence(raw_refs=[""])]}, "raw_refs"),
    ({"evidence_chain": [evidence(raw_refs=[123])]}, "raw_refs"),
    ({"raw_ref_locations": []}, "raw_ref_locations"),
    ({"raw_ref_locations": {"audit.log:11": "path"}}, "raw_ref_locations"),
    ({"provenance": {"status": "incomplete", "issues": {}}}, "provenance.issues"),
    ({"provenance": {"status": "incomplete", "issues": [None]}}, "provenance.issues"),
    ({"provenance": {"status": "incomplete", "issues": [{"sequence": []}]}}, "sequence"),
    ({"provenance": {"status": "incomplete", "ambiguous_raw_refs": []}}, "ambiguous_raw_refs"),
    ({"provenance": {"status": "incomplete", "evidence_without_raw_refs": "EVID-001"}}, "evidence_without_raw_refs"),
])
def test_malformed_input_returns_consistent_empty_error_result(patch, error_path):
    source = investigation(**patch)
    before = deepcopy(source)
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "error"
    assert result["techniques"] == result["unmatched_evidence_ids"] == []
    assert len(result["errors"]) == 1 and error_path in result["errors"][0]
    assert source == before


@pytest.mark.parametrize("source", [None, [], "bad input", 42, {}])
def test_invalid_root_input_returns_error(source):
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == "error" and result["errors"]
    assert result["techniques"] == []


def test_match_helpers_raise_validation_errors():
    with pytest.raises(ValueError, match="final_verdict"):
        match_verdict({}, RULES)
    with pytest.raises(ValueError, match="evidence_chain"):
        match_evidence({}, RULES)


@pytest.mark.parametrize("rules", [None, "ALL_RULES", {}, [SHELL, {}], [SHELL, replace(SHELL, technique_name="conflict")]])
def test_invalid_catalog_returns_error(rules):
    result = map_investigation(investigation(), rules)
    assert result["mapping_status"] == "error" and result["errors"]
    assert result["techniques"] == []


def test_rule_is_immutable_and_rejects_mutable_or_malformed_fields():
    with pytest.raises(FrozenInstanceError):
        SHELL.technique_id = "changed"
    for patch in ({"evidence_keywords": ["webshell"]}, {"attack_type_keywords": (None,)},
                  {"technique_id": ""}, {"tactic_name": " Persistence "}, {"notes": None}):
        with pytest.raises(ValueError):
            replace(SHELL, **patch)


def test_version_and_mapping_are_independent_of_rule_order():
    assert mapping_table_version(RULES) == mapping_table_version([BRUTE, SHELL, SHELL])
    assert mapping_table_version([SHELL]) == mapping_table_version([
        replace(SHELL, evidence_keywords=tuple(reversed(SHELL.evidence_keywords)) + ("webshell",)),
    ])
    assert map_investigation(investigation(), RULES) == map_investigation(investigation(), iter(reversed(RULES)))
    for patch in ({"notes": "revised"}, {"evidence_keywords": ("new",)}, {"attack_type_keywords": ("new",)},
                  {"technique_name": "new"}, {"technique_id": "T0000"}, {"tactic_id": "TA0000"}, {"tactic_name": "new"}):
        assert mapping_table_version([SHELL]) != mapping_table_version([replace(SHELL, **patch)])


def test_version_is_stable_across_python_processes():
    code = (
        "from attack_mapping.schema import TechniqueRule; "
        "from attack_mapping.engine import mapping_table_version; "
        f"print(mapping_table_version([{SHELL!r}, {BRUTE!r}]))"
    )
    for seed in ("1", "42"):
        completed = subprocess.run(
            [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True, text=True, check=True,
        )
        assert completed.stdout.strip() == mapping_table_version(RULES)


@pytest.mark.parametrize("incomplete", [False, True])
def test_actual_investigation_report_contract(incomplete):
    state = AgentState(incident_id="INC-CONTRACT", seed={"raw_refs": ["audit.log:1", "audit.log:2"]})
    state.raw_refs = ["audit.log:1", "audit.log:2"]
    state.raw_ref_locations = {ref: [f"/synthetic/{ref}"] for ref in state.raw_refs}
    state.add_evidence(Evidence(
        evidence_id="EVID-001", sequence=1, time=None, layer="audit", event_type="process_exec",
        description="webshell", source_log="audit.log", raw_refs=list(state.raw_refs),
    ))
    if incomplete:
        state.add_evidence(Evidence(
            evidence_id="EVID-002", sequence=2, time=None, layer="auth", event_type="ssh_failed",
            description="unreferenced", source_log="auth.log",
        ))
    source = build_investigation_result(
        state, "no_more_evidence", {"verdict": "THREAT_CONFIRMED", "attack_type": "Web Shell"}, "INV-CONTRACT",
    )
    before = deepcopy(source)
    result = map_investigation(source, RULES)
    assert result["mapping_status"] == ("partial" if incomplete else "mapped")
    assert result["provenance_status"] == source["provenance"]["status"]
    assert result["techniques"][0]["raw_refs"] == state.raw_refs
    assert result["techniques"][0]["times"] == []
    assert result["techniques"][0]["evidence_ids"] == ["EVID-001"]
    assert result["raw_ref_locations"] == source["raw_ref_locations"]
    assert source == before


def test_tactic_order_is_available_to_downstream_without_building_a_killchain():
    assert TACTIC_ORDER == (
        "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    )
    assert "kill_chain" not in map_investigation(investigation(), RULES)
