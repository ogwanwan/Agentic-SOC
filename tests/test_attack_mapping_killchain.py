"""Offline unit tests for C's kill chain assembly (attack_mapping/killchain.py).

`technique()` below hand-builds MappedTechnique-shaped dicts directly, matching
attack_mapping/schema.py's fields, so these tests do not depend on B's rule
catalog or on A's engine internals beyond the documented MappedTechnique shape.
"""

from copy import deepcopy

import pytest

from attack_mapping.killchain import build_kill_chain
from attack_mapping.engine import map_investigation
from attack_mapping.schema import TechniqueRule


def technique(technique_id, tactic_name, tactic_id="TA0000", times=(), evidence_ids=(), **overrides):
    base = {
        "technique_id": technique_id,
        "technique_name": f"Name-{technique_id}",
        "tactic_id": tactic_id,
        "tactic_name": tactic_name,
        "tactics": [{"tactic_id": tactic_id, "tactic_name": tactic_name}],
        "matched_by": ["evidence"],
        "matched_keywords": [],
        "evidence_ids": list(evidence_ids),
        "raw_refs": [],
        "times": list(times),
        "matches": [],
    }
    base.update(overrides)
    return base


def test_empty_input_returns_empty_kill_chain():
    assert build_kill_chain([]) == []


def test_orders_by_tactic_stage_before_time():
    exfil = technique("T1041", "Exfiltration", times=["2026-09-25T09:00:00Z"])
    initial_access = technique("T1190", "Initial Access", times=["2026-09-25T10:00:00Z"])

    kill_chain = build_kill_chain([exfil, initial_access])

    assert [step["technique_id"] for step in kill_chain] == ["T1190", "T1041"]
    assert [step["step"] for step in kill_chain] == [1, 2]


def test_orders_by_time_within_the_same_tactic():
    later = technique("T1105", "Command and Control", times=["2026-09-25T10:05:00Z"])
    earlier = technique("T1059.004", "Command and Control", times=["2026-09-25T10:01:00Z"])

    kill_chain = build_kill_chain([later, earlier])

    assert [step["technique_id"] for step in kill_chain] == ["T1059.004", "T1105"]
    assert [step["time"] for step in kill_chain] == ["2026-09-25T10:01:00Z", "2026-09-25T10:05:00Z"]


def test_untimed_verdict_only_technique_sorts_after_timed_ones_in_same_tactic():
    verdict_only = technique("T1110", "Credential Access", times=[], matched_by=["verdict"])
    timed = technique("T1078", "Credential Access", times=["2026-09-25T08:00:00Z"])

    kill_chain = build_kill_chain([verdict_only, timed])

    assert [step["technique_id"] for step in kill_chain] == ["T1078", "T1110"]
    assert kill_chain[1]["time"] is None


def test_unknown_tactic_name_sorts_after_all_known_tactics():
    known = technique("T1560", "Collection", times=["2026-09-25T09:00:00Z"])
    unknown = technique("T9999", "Not A Real Tactic", times=["2026-09-25T00:00:00Z"])

    kill_chain = build_kill_chain([known, unknown])

    assert [step["technique_id"] for step in kill_chain] == ["T1560", "T9999"]


def test_representative_time_is_earliest_of_multiple_times():
    technique_with_times = technique(
        "T1505.003", "Persistence",
        times=["2026-09-25T10:05:00Z", "2026-09-25T10:01:00Z", "2026-09-25T10:03:00Z"],
    )

    kill_chain = build_kill_chain([technique_with_times])

    assert kill_chain[0]["time"] == "2026-09-25T10:01:00Z"


def test_evidence_ids_are_copied_as_a_list_and_input_is_not_mutated():
    source = technique("T1041", "Exfiltration", evidence_ids=("EVID-001", "EVID-002"))
    before = deepcopy(source)

    kill_chain = build_kill_chain([source])

    assert kill_chain[0]["evidence_ids"] == ["EVID-001", "EVID-002"]
    kill_chain[0]["evidence_ids"].append("EVID-003")
    assert source == before


def test_stable_sort_preserves_input_order_for_equal_keys():
    # Same tactic, both untimed: no ordering signal exists, so input order wins.
    first = technique("T1548.001", "Privilege Escalation", times=[])
    second = technique("T1136.001", "Privilege Escalation", times=[])

    assert [s["technique_id"] for s in build_kill_chain([first, second])] == ["T1548.001", "T1136.001"]
    assert [s["technique_id"] for s in build_kill_chain([second, first])] == ["T1136.001", "T1548.001"]


@pytest.mark.parametrize("earlier,later", [
    ("2026-09-26T09:00:00+09:00", "2026-09-26T01:00:00Z"),
    ("2026-09-25T23:00:00-02:00", "2026-09-26T00:30:00-01:00"),
    ("2026-09-26T00:00:00Z", "2026-09-26T00:00:00.100000Z"),
    ("2026-09-26T09:00:00+0900", "2026-09-26T01:00:00+0000"),
    ("2026-09-26T00:00:00", "2026-09-26T00:30:00Z"),
])
def test_timezone_aware_order_and_representative_time(earlier, later):
    early = technique("T1505.003", "Persistence", times=[earlier])
    late = technique("T1098.004", "Persistence", times=[later])
    inputs = [late, early]
    before = deepcopy(inputs)

    chain = build_kill_chain(inputs)
    assert [step["technique_id"] for step in chain] == ["T1505.003", "T1098.004"]
    assert [step["time"] for step in chain] == [earlier, later]
    assert inputs == before

    merged = technique("T1505.003", "Persistence", times=[later, earlier])
    assert build_kill_chain([merged])[0]["time"] == earlier
    assert merged["times"] == [later, earlier]


def test_equal_instants_preserve_input_order_and_original_time_spelling():
    local = "2026-09-26T09:00:00+09:00"
    utc = "2026-09-26T00:00:00Z"
    first = technique("T1505.003", "Persistence", times=[local, utc])
    second = technique("T1098.004", "Persistence", times=[utc])

    chain = build_kill_chain([first, second])

    assert [step["technique_id"] for step in chain] == ["T1505.003", "T1098.004"]
    assert [step["time"] for step in chain] == [local, utc]


def test_unparseable_times_are_retained_but_do_not_override_known_times():
    known_time = "2026-09-26T00:00:00Z"
    invalid = technique("T1098.004", "Persistence", times=["unknown"])
    mixed = technique("T1505.003", "Persistence", times=["", known_time, "unknown"])
    untimed = technique("T1053.003", "Persistence", times=[])
    before = deepcopy([invalid, untimed, mixed])

    chain = build_kill_chain([invalid, untimed, mixed])

    assert [step["technique_id"] for step in chain] == ["T1505.003", "T1098.004", "T1053.003"]
    assert [step["time"] for step in chain] == [known_time, "unknown", None]
    assert [invalid, untimed, mixed] == before


# --- Integration with A's real engine output ---

INITIAL_ACCESS = TechniqueRule(
    technique_id="T1190", technique_name="Exploit Public-Facing Application",
    tactic_id="TA0001", tactic_name="Initial Access",
    evidence_keywords=("업로드 취약점 악용",),
)
PERSISTENCE = TechniqueRule(
    technique_id="T1505.003", technique_name="Web Shell",
    tactic_id="TA0003", tactic_name="Persistence",
    evidence_keywords=("웹셸",),
)
EXFIL = TechniqueRule(
    technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
    tactic_id="TA0010", tactic_name="Exfiltration",
    evidence_keywords=("외부 전송",),
)


def _evidence(eid, time, description):
    return {
        "evidence_id": eid, "sequence": int(eid[-1]), "time": time, "layer": "audit",
        "event_type": "process_exec", "description": description,
        "source_log": "audit.log", "raw_refs": [f"audit.log:{eid}"],
    }


def test_kill_chain_from_real_engine_output_follows_tactic_and_time_order():
    investigation_result = {
        "incident_id": "INC-KC", "investigation_id": "INV-KC",
        "final_verdict": {"verdict": "THREAT_CONFIRMED", "attack_type": "다단계 침투"},
        "evidence_chain": [
            _evidence("EVID-3", "2026-09-25T10:20:00Z", "압축 파일 외부 전송 확인"),
            _evidence("EVID-1", "2026-09-25T10:01:00Z", "업로드 취약점 악용으로 파일 생성"),
            _evidence("EVID-2", "2026-09-25T10:10:00Z", "웹셸 실행 흔적 확인"),
        ],
        "raw_refs": ["audit.log:EVID-1", "audit.log:EVID-2", "audit.log:EVID-3"],
        "raw_ref_locations": {},
        "provenance": {"status": "passed", "evidence_without_raw_refs": [], "ambiguous_raw_refs": {}, "issues": []},
    }

    mapping_result = map_investigation(investigation_result, [INITIAL_ACCESS, PERSISTENCE, EXFIL])
    kill_chain = build_kill_chain(mapping_result["techniques"])

    assert [step["technique_id"] for step in kill_chain] == ["T1190", "T1505.003", "T1041"]
    assert [step["step"] for step in kill_chain] == [1, 2, 3]
    assert kill_chain[0]["time"] == "2026-09-25T10:01:00Z"
