"""validate.py·schema.py(RAG 계약) 오프라인 테스트.

증거 분류·관문 규칙은 agent/loop.py·provenance.py·report.py의 실제 출력 형식에 맞춘다.
실제 조사 결과 스모크 테스트는 INV_RESULTS_DIR 환경변수가 있을 때만 돈다.
"""

import copy
import glob
import json
import os

import pytest

from attack_mapping.schema import (DecisionFormatError, InvestigationFormatError, MappingDecision,
                                   MappingUnit, Selection)
from attack_mapping.validate import (CONTEXT, EXCLUDED, SEED_ONLY_RAW_REFS, TARGET, check_case_gate,
                                     classify_evidence, eligibility_index, exclusions, target_evidence,
                                     validate_decision, validate_selection)
from tests.attack_stix_fixture import load_test_catalog


def _ev(eid, seq, refs, empty=None, description="d"):
    return {"evidence_id": eid, "sequence": seq, "time": "2026-09-27T10:00:00Z", "layer": "process",
            "event_type": "x", "description": description, "raw_refs": refs, "raw_ref": refs[0] if refs else None,
            "empty_result_call": empty}


BASE = {
    "incident_id": "INC-T", "investigation_id": "INV-T",
    "final_verdict": {"verdict": "THREAT_CONFIRMED", "reasoning": "ok", "attack_type": "웹셸"},
    "raw_refs": ["seed.log:1", "audit.log:10", "audit.log:11", "audit.log:20", "web.log:5"],
    "raw_ref_locations": {"audit.log:10": ["/var/log/audit/audit.log"]},
    "tools_called": [{"sequence": 1, "raw_refs": ["audit.log:10", "audit.log:11", "audit.log:20", "web.log:5"]}],
    "provenance": {"status": "passed", "seed_raw_refs": ["seed.log:1"], "evidence_without_raw_refs": [],
                   "empty_result_evidence": [], "ambiguous_raw_refs": {}, "issues": []},
    "evidence_chain": [_ev("EVID-001", 1, ["audit.log:10", "audit.log:11"])],
    "contradicting_evidence": [],
    "investigation_notes": [],
}


def _case(**prov):
    r = copy.deepcopy(BASE)
    r["provenance"].update(prov)
    return r


def _status(result):
    return {row.evidence_id: (row.status, row.reasons) for row in classify_evidence(result)}


# ---------------------------------------------------------------------------
# 사건 관문
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verdict,expected", [("FALSE_POSITIVE", "not_applicable"), ("INCONCLUSIVE", "deferred")])
def test_gate_non_confirmed(verdict, expected):
    r = copy.deepcopy(BASE)
    r["final_verdict"]["verdict"] = verdict
    gate = check_case_gate(r)
    assert not gate.proceed and gate.mapping_status == expected


@pytest.mark.parametrize("verdict", [None, "", "threat_confirmed", "SUSPICIOUS"])
def test_gate_unknown_verdict_is_error_not_deferred(verdict):
    r = copy.deepcopy(BASE)
    r["final_verdict"]["verdict"] = verdict
    gate = check_case_gate(r)
    assert gate.mapping_status == "error" and gate.errors


def test_gate_missing_provenance_is_deferred_like_rule_engine():
    r = copy.deepcopy(BASE)
    del r["provenance"]
    gate = check_case_gate(r)
    assert (gate.proceed, gate.mapping_status, gate.provenance_status) == (False, "deferred", "unavailable")
    r["final_verdict"]["verdict"] = "FALSE_POSITIVE"
    assert check_case_gate(r).mapping_status == "not_applicable"


def test_gate_structure_errors():
    assert check_case_gate([]).mapping_status == "error"
    assert check_case_gate(_case(status="weird")).mapping_status == "error"
    r = copy.deepcopy(BASE)
    r["evidence_chain"] = None
    assert check_case_gate(r).mapping_status == "error"


def test_gate_unavailable_and_warnings():
    assert check_case_gate(_case(status="unavailable")).mapping_status == "deferred"
    r = copy.deepcopy(BASE)
    r["final_verdict"]["reasoning"] = "[자동 폴백 판정 — LLM이 final_verdict를 제공하지 않아 …] …"
    r["investigation_notes"] = ["⚠ 판정-원칙 불일치: … (최종 판정은 LLM 결과 그대로 둠)"]
    gate = check_case_gate(r)
    assert gate.proceed and gate.provenance_status == "passed"
    assert {w["code"] for w in gate.warnings} == {"FALLBACK_VERDICT", "VERDICT_PRINCIPLE_CONFLICT"}


# ---------------------------------------------------------------------------
# 증거 분류
# ---------------------------------------------------------------------------

def test_clean_evidence_is_target():
    assert _status(BASE)["EVID-001"] == (TARGET, ())


def test_empty_result_is_context_and_missing_refs_excluded():
    r = _case(status="incomplete", evidence_without_raw_refs=["EVID-003"], empty_result_evidence=["EVID-002"])
    r["evidence_chain"] += [_ev("EVID-002", 2, [], empty=1), _ev("EVID-003", 3, [])]
    rows = classify_evidence(r)
    s = {row.evidence_id: (row.status, row.reasons) for row in rows}
    assert s["EVID-002"] == (CONTEXT, ("EMPTY_RESULT",))
    assert s["EVID-003"] == (EXCLUDED, ("NO_RAW_REFS",))
    assert [e.evidence_id for e in target_evidence(rows)] == ["EVID-001"]
    assert exclusions(rows) == [{"evidence_id": "EVID-002", "reasons": ["EMPTY_RESULT"]},
                                {"evidence_id": "EVID-003", "reasons": ["NO_RAW_REFS"]}]


def test_empty_result_is_not_target_even_when_passed():
    r = _case(empty_result_evidence=["EVID-002"])
    r["evidence_chain"].append(_ev("EVID-002", 2, [], empty=1))
    assert _status(r)["EVID-002"][0] == CONTEXT


def test_provenance_issue_is_matched_by_evidence_sequence():
    # 지어낸 참조는 증거 raw_refs에서 이미 빠져 있고 issues에 sequence로만 남는다
    r = _case(status="incomplete", issues=[{"sequence": 1, "unknown_raw_refs": ["audit.log:999"]}])
    assert _status(r)["EVID-001"] == (EXCLUDED, ("PROVENANCE_ISSUE",))


def test_issue_sequence_is_not_tool_call_sequence():
    # empty_result_call=1(도구 호출 번호)은 issues의 증거 sequence와 무관하다
    r = _case(status="incomplete", issues=[{"sequence": 2, "error": "bad ref"}],
              empty_result_evidence=["EVID-002"])
    r["evidence_chain"].append(_ev("EVID-002", 2, [], empty=1))
    r["evidence_chain"].append(_ev("EVID-003", 3, ["audit.log:20"]))
    s = _status(r)
    assert s["EVID-001"][0] == TARGET and s["EVID-003"][0] == TARGET
    assert s["EVID-002"] == (EXCLUDED, ("EMPTY_RESULT", "PROVENANCE_ISSUE"))


def test_ambiguous_ref_excluded_from_provenance_or_locations():
    assert "AMBIGUOUS_RAW_REF" in _status(_case(ambiguous_raw_refs={"audit.log:10": ["a", "b"]}))["EVID-001"][1]
    r = copy.deepcopy(BASE)
    r["raw_ref_locations"]["audit.log:11"] = ["/a/audit.log", "/b/audit.log"]
    assert _status(r)["EVID-001"] == (EXCLUDED, ("AMBIGUOUS_RAW_REF",))


def test_unobserved_ref_excluded():
    r = copy.deepcopy(BASE)
    r["evidence_chain"][0]["raw_refs"].append("audit.log:404")
    assert _status(r)["EVID-001"] == (EXCLUDED, ("UNOBSERVED_RAW_REF",))


def _row(result, eid):
    return eligibility_index(classify_evidence(result))[eid]


def test_seed_only_refs_stay_target_with_flag_without_field():
    # 0928 이전 결과(증거에 seed_only_raw_refs 필드 없음) — tools_called와 seed_raw_refs로 계산
    r = copy.deepcopy(BASE)
    r["evidence_chain"].append(_ev("EVID-002", 2, ["seed.log:1"]))
    row = _row(r, "EVID-002")
    assert (row.status, row.flags, row.seed_only_raw_refs) == (TARGET, (SEED_ONLY_RAW_REFS,), ("seed.log:1",))
    r["tools_called"].append({"sequence": 2, "raw_refs": ["seed.log:1"]})   # 나중 조회에서 관측됨
    assert _row(r, "EVID-002").flags == ()


def test_seed_only_is_per_reference_for_mixed_refs():
    # 도구로 관측된 참조와 seed에만 있는 참조를 함께 인용해도 표시한다(참조 단위 규칙)
    r = copy.deepcopy(BASE)
    r["provenance"]["seed_raw_refs"] = ["seed.log:1", "audit.log:10"]
    r["evidence_chain"].append(_ev("EVID-002", 2, ["audit.log:10", "seed.log:1"]))
    row = _row(r, "EVID-002")
    assert (row.status, row.flags, row.seed_only_raw_refs) == (TARGET, (SEED_ONLY_RAW_REFS,), ("seed.log:1",))
    # seed 참조라도 도구로 관측됐으면 표시하지 않는다
    assert _row(r, "EVID-001").flags == ()


def test_seed_only_field_is_used_as_given():
    # 0928 이후 결과: 조사 코드가 계산한 필드를 그대로 쓴다(다시 계산해 덮어쓰지 않음)
    r = copy.deepcopy(BASE)
    r["evidence_chain"].append({**_ev("EVID-002", 2, ["seed.log:1"]),
                                "supporting_tool_calls": [3], "seed_only_raw_refs": []})
    r["evidence_chain"].append({**_ev("EVID-003", 3, ["audit.log:10", "audit.log:20"]),
                                "supporting_tool_calls": [1], "seed_only_raw_refs": ["audit.log:20"]})
    assert _row(r, "EVID-002").flags == ()
    row = _row(r, "EVID-003")
    assert (row.status, row.flags, row.seed_only_raw_refs) == (TARGET, (SEED_ONLY_RAW_REFS,), ("audit.log:20",))


def test_seed_only_field_must_be_subset_of_raw_refs():
    r = copy.deepcopy(BASE)
    r["evidence_chain"][0]["seed_only_raw_refs"] = ["seed.log:1"]
    with pytest.raises(InvestigationFormatError, match="seed_only_raw_refs"):
        classify_evidence(r)


def test_real_investigation_result_seed_only_contract():
    # 조사 코드(agent/)가 만든 결과 JSON으로 확인 — tests/test_provenance.py의 seed_only 시나리오와 같음.
    # 필드가 있을 때와, 필드를 지워 이전 결과처럼 계산할 때 판정이 같아야 한다.
    from agent.loop import InvestigationAgent
    from agent.tools.registry import ToolRegistry, ToolSpec
    from tests.test_provenance import ScriptedInvestigator, evidence, terminate

    registry = ToolRegistry()
    registry.register(ToolSpec("ok", "", [], handler=lambda args: {
        "count": 2, "records": [{"raw_ref": "input:1"}, {"raw_ref": "seed:2"}]}))
    llm = ScriptedInvestigator([
        {"next_action": "call_tool", "tool_call": {"tool_name": "ok"},
         "new_evidence": [evidence(raw_refs=["seed:2"], description="seed 단서")]},
        terminate([evidence(raw_refs=["input:1"]), evidence(raw_refs=["seed:1"], description="seed만"),
                   evidence(raw_refs=["seed:1", "input:1"], contradicting=True)]),
    ])
    result = InvestigationAgent(llm, registry).run({"incident_id": "SRC", "evidence_refs": ["seed:1", "seed:2"]})
    json.loads(json.dumps(result))                       # 저장된 JSON과 같은 형태

    def flagged(r):
        return {row.evidence_id: row.seed_only_raw_refs for row in classify_evidence(r) if row.flags}

    later, tool, seed_only = result["evidence_chain"]
    contradicting = result["contradicting_evidence"][0]
    expected = {seed_only["evidence_id"]: ("seed:1",), contradicting["evidence_id"]: ("seed:1",)}
    assert flagged(result) == expected
    assert set(expected) == set(result["provenance"]["seed_only_evidence"])
    legacy = copy.deepcopy(result)
    for ev in legacy["evidence_chain"] + legacy["contradicting_evidence"]:
        del ev["seed_only_raw_refs"], ev["supporting_tool_calls"]
    assert flagged(legacy) == expected


def test_seed_only_on_contradicting_evidence_is_context_with_flag():
    r = copy.deepcopy(BASE)
    r["contradicting_evidence"] = [{**_ev("EVID-009", 2, ["seed.log:1"]), "seed_only_raw_refs": ["seed.log:1"]}]
    row = _row(r, "EVID-009")
    assert (row.status, row.flags) == (CONTEXT, (SEED_ONLY_RAW_REFS,))


def test_contradicting_is_context_and_not_listed_as_excluded():
    r = copy.deepcopy(BASE)
    r["contradicting_evidence"] = [_ev("EVID-009", 2, ["web.log:5"])]
    rows = classify_evidence(r)
    assert _status(r)["EVID-009"] == (CONTEXT, ("CONTRADICTING",))
    assert exclusions(rows) == []


@pytest.mark.parametrize("mutate", [
    lambda r: r["evidence_chain"].append(_ev("EVID-001", 2, ["audit.log:20"])),
    lambda r: r["contradicting_evidence"].append(_ev("EVID-001", 2, ["web.log:5"])),
    lambda r: r["evidence_chain"].append(_ev("", 2, ["audit.log:20"])),
    lambda r: r["evidence_chain"].append(_ev("EVID-002", 0, ["audit.log:20"])),
    lambda r: r["evidence_chain"].append(_ev("EVID-002", 2, "audit.log:20")),
    lambda r: r["provenance"].update(issues={"sequence": 1}),
    lambda r: r["tools_called"].append({"sequence": 2, "raw_refs": [None]}),
])
def test_structure_errors_raise(mutate):
    r = copy.deepcopy(BASE)
    mutate(r)
    with pytest.raises(InvestigationFormatError):
        classify_evidence(r)


def test_classify_does_not_mutate_input():
    r = _case(status="incomplete", evidence_without_raw_refs=["EVID-002"])
    r["evidence_chain"].append(_ev("EVID-002", 2, []))
    before = copy.deepcopy(r)
    rows = classify_evidence(r)
    rows[0].evidence["raw_refs"].append("x")            # 분류 결과를 바꿔도 원본은 그대로
    assert r == before


# ---------------------------------------------------------------------------
# schema: LLM 결정 파싱
# ---------------------------------------------------------------------------

def test_decision_from_dict_select_and_abstain():
    d = MappingDecision.from_dict({"decision": "SELECT", "selections": [
        {"technique_id": "T1059.004", "evidence_ids": ["EVID-001"], "reason": "sh -c",
         "technique_name": "LLM이 쓴 이름", "tactic": "무시됨"}]})
    assert d.selections == (Selection("T1059.004", ("EVID-001",), "sh -c"),)
    assert MappingDecision.from_dict({"decision": "ABSTAIN", "selections": []}).selections == ()
    assert MappingDecision.from_dict({"decision": "ABSTAIN"}).decision == "ABSTAIN"


@pytest.mark.parametrize("raw", [
    None, [], {"decision": "select", "selections": []}, {"selections": []},
    {"decision": "SELECT", "selections": []},
    {"decision": "ABSTAIN", "selections": [{"technique_id": "T1033", "evidence_ids": [], "reason": ""}]},
    {"decision": "SELECT", "selections": "T1033"},
    {"decision": "SELECT", "selections": [{"technique_id": 1059, "evidence_ids": [], "reason": ""}]},
    {"decision": "SELECT", "selections": [{"technique_id": "T1033", "evidence_ids": "EVID-001", "reason": ""}]},
])
def test_malformed_decision_is_error_not_abstain(raw):
    with pytest.raises(DecisionFormatError):
        MappingDecision.from_dict(raw)


def test_mapping_unit_requires_refs():
    with pytest.raises(ValueError):
        MappingUnit("UNIT-EVID-001", "EVID-001", 1, None, "process", "x", "d", ())


# ---------------------------------------------------------------------------
# LLM 선택 검증
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def catalog(tmp_path_factory):
    return load_test_catalog(tmp_path_factory.mktemp("attack"))


def _unit(result=BASE, eid="EVID-001"):
    ev = next(e for e in result["evidence_chain"] if e["evidence_id"] == eid)
    return MappingUnit(f"UNIT-{eid}", eid, ev["sequence"], ev["time"], ev["layer"], ev["event_type"],
                       ev["description"], tuple(ev["raw_refs"]))


CANDIDATES = ("T1059.004", "T1033", "T1082", "T1086", "T1099")


def _check(catalog, tid, evidence_ids=("EVID-001",), reason="근거", candidates=CANDIDATES, result=BASE, unit=None):
    return validate_selection(Selection(tid, tuple(evidence_ids), reason), unit=unit or _unit(result),
                              candidate_ids=candidates, catalog=catalog,
                              eligibility=eligibility_index(classify_evidence(result)))


def test_selection_ok_uses_catalog_and_evidence_values(catalog):
    c = _check(catalog, " t1059.004 ")
    assert c.ok and c.technique_id == "T1059.004" and c.errors == []
    s = c.accepted
    assert (s.technique.name, s.technique.parent_id, [t.tactic_name for t in s.technique.tactics]) == \
        ("Unix Shell", "T1059", ["Execution"])
    assert s.raw_refs == ("audit.log:10", "audit.log:11") and s.time == "2026-09-27T10:00:00Z"
    assert s.evidence_ids == ("EVID-001",) and "TECHNIQUE_ID_NORMALIZED" in s.flags


@pytest.mark.parametrize("tid,code", [("T9999", "INVALID_TECHNIQUE_ID"), ("T1059.4", "INVALID_TECHNIQUE_ID"),
                                      ("", "INVALID_TECHNIQUE_ID"), ("T1086", "REVOKED_OR_DEPRECATED"),
                                      ("T1099", "REVOKED_OR_DEPRECATED")])
def test_selection_bad_technique(catalog, tid, code):
    c = _check(catalog, tid, candidates=CANDIDATES + ("T9999",))
    assert not c.ok and code in {e["code"] for e in c.errors}


def test_revoked_detail_names_replacement(catalog):
    err = next(e for e in _check(catalog, "T1086").errors if e["code"] == "REVOKED_OR_DEPRECATED")
    assert "T1059.004" in err["detail"]


def test_selection_outside_candidates_including_parent(catalog):
    c = _check(catalog, "T1033", candidates=["T1059.004"])
    assert not c.ok and [e["code"] for e in c.errors] == ["NOT_IN_CANDIDATES"]
    c = _check(catalog, "T1059", candidates=["T1059.004"])      # 부모로 바꿔 주지 않는다
    assert not c.ok and "NOT_IN_CANDIDATES" in {e["code"] for e in c.errors}


def test_other_units_evidence_cannot_bypass(catalog):
    r = copy.deepcopy(BASE)
    r["evidence_chain"].append(_ev("EVID-002", 2, ["audit.log:20"]))
    c = _check(catalog, "T1033", evidence_ids=["EVID-002"], result=r)
    assert not c.ok
    assert {e["code"] for e in c.errors} == {"EVIDENCE_OUTSIDE_UNIT", "UNIT_EVIDENCE_NOT_CITED"}


def test_extra_evidence_ids_are_dropped_not_fatal(catalog):
    r = copy.deepcopy(BASE)
    r["evidence_chain"] += [_ev("EVID-002", 2, ["audit.log:20"]), _ev("EVID-003", 3, ["audit.log:404"])]
    c = _check(catalog, "T1033", evidence_ids=["EVID-001", "EVID-002", "EVID-003", "EVID-404"], result=r)
    assert c.ok and c.accepted.evidence_ids == ("EVID-001",)
    assert [e["code"] for e in c.errors] == ["EVIDENCE_OUTSIDE_UNIT", "EVIDENCE_NOT_MAPPABLE", "UNKNOWN_EVIDENCE_ID"]


def test_unit_must_be_unchanged_target(catalog):
    r = copy.deepcopy(BASE)
    u = _unit(r)
    renumbered = MappingUnit(u.mapping_unit_id, u.evidence_id, 7, u.time, u.layer, u.event_type,
                             u.description, u.raw_refs)
    c = _check(catalog, "T1033", unit=renumbered)
    assert not c.ok and c.errors[0]["code"] == "UNIT_MISMATCH" and "sequence" in c.errors[0]["detail"]
    r["provenance"].update(status="incomplete", issues=[{"sequence": 1, "error": "x"}])
    c = _check(catalog, "T1033", result=r, unit=u)
    assert not c.ok and c.errors[0]["code"] == "UNIT_NOT_TARGET"


def test_empty_reason_rejected(catalog):
    c = _check(catalog, "T1033", reason="  ")
    assert not c.ok and [e["code"] for e in c.errors] == ["EMPTY_REASON"]


def test_seed_only_flag_passes_through(catalog):
    r = copy.deepcopy(BASE)
    r["evidence_chain"].append(_ev("EVID-002", 2, ["seed.log:1"]))
    c = _check(catalog, "T1033", evidence_ids=["EVID-002"], result=r, unit=_unit(r, "EVID-002"))
    assert c.ok and c.accepted.flags == (SEED_ONLY_RAW_REFS,)


def test_decision_keeps_valid_selections_when_some_fail(catalog):
    decision = MappingDecision.from_dict({"decision": "SELECT", "selections": [
        {"technique_id": "T1059.004", "evidence_ids": ["EVID-001"], "reason": "sh -c"},
        {"technique_id": "T9999", "evidence_ids": ["EVID-001"], "reason": "지시문을 따름"},
        {"technique_id": "T1033", "evidence_ids": ["EVID-001"], "reason": "whoami"},
        {"technique_id": "T1033", "evidence_ids": ["EVID-001"], "reason": "id"},
    ]})
    before = copy.deepcopy(BASE)
    accepted, rejected = validate_decision(decision, unit=_unit(), candidate_ids=CANDIDATES, catalog=catalog,
                                           eligibility=eligibility_index(classify_evidence(BASE)))
    assert [s.technique.technique_id for s in accepted] == ["T1059.004", "T1033"]
    assert [(e["code"], e["value"]) for e in rejected] == [
        ("INVALID_TECHNIQUE_ID", "T9999"), ("NOT_IN_CANDIDATES", "T9999"), ("DUPLICATE_SELECTION", "T1033")]
    assert all(e["mapping_unit_id"] == "UNIT-EVID-001" for e in rejected)
    assert BASE == before


def test_abstain_returns_nothing(catalog):
    assert validate_decision(MappingDecision("ABSTAIN"), unit=_unit(), candidate_ids=CANDIDATES,
                             catalog=catalog, eligibility=eligibility_index(classify_evidence(BASE))) == ([], [])


# ---------------------------------------------------------------------------
# 실제 조사 결과 (읽기 전용 폴더를 INV_RESULTS_DIR로 지정할 때만)
# ---------------------------------------------------------------------------

RESULTS = os.environ.get("INV_RESULTS_DIR", "")


@pytest.mark.skipif(not RESULTS, reason="INV_RESULTS_DIR 미설정")
def test_real_results_smoke():
    paths = glob.glob(os.path.join(RESULTS, "INV-*.json"))
    assert paths
    for path in paths:
        with open(path, encoding="utf-8") as f:
            r = json.load(f)
        gate = check_case_gate(r)
        assert gate.mapping_status in (None, "not_applicable", "deferred"), (path, gate)
        if "provenance" not in r:
            continue
        rows = classify_evidence(r)
        assert len(rows) == len(r["evidence_chain"]) + len(r.get("contradicting_evidence") or [])
        for row in rows:
            if row.status == TARGET:                     # target이면 참조가 있고 모두 등록된 것
                assert row.raw_refs and set(row.raw_refs) <= set(r["raw_refs"]), (path, row.evidence_id)
            if row.evidence_id in r["provenance"].get("empty_result_evidence", []):
                assert row.status != TARGET
