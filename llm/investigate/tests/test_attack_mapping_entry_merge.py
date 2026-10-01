from attack_mapping.mapper import (
    build_attack_mapping_entries,
)
from attack_mapping.schema import (
    TacticRef,
    TechniqueRecord,
    ValidatedSelection,
)


EXECUTION = TacticRef(
    tactic_id="TA0002",
    tactic_name="Execution",
    shortname="execution",
)


COMMAND_INTERPRETER = TechniqueRecord(
    technique_id="T1059",
    stix_id="attack-pattern--command-interpreter",
    name="Command and Scripting Interpreter",
    description="Command interpreter",
    tactics=(EXECUTION,),
    is_subtechnique=False,
    parent_id=None,
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1059/",
)


UNIX_SHELL = TechniqueRecord(
    technique_id="T1059.004",
    stix_id="attack-pattern--unix-shell",
    name="Unix Shell",
    description="Unix shell execution",
    tactics=(EXECUTION,),
    is_subtechnique=True,
    parent_id="T1059",
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1059/004/",
)


class FakeCatalog:
    def lookup(self, technique_id):
        if technique_id == "T1059":
            return COMMAND_INTERPRETER

        if technique_id == "T1059.004":
            return UNIX_SHELL

        return None


def _selection(
    *,
    unit,
    technique,
    evidence_id,
    raw_ref,
    time,
    reason,
):
    return ValidatedSelection(
        mapping_unit_id=unit,
        technique=technique,
        evidence_ids=(evidence_id,),
        raw_refs=(raw_ref,),
        time=time,
        reason=reason,
        flags=(),
    )


def test_merges_same_technique_across_evidence():
    selections = [
        _selection(
            unit="UNIT-EVID-001",
            technique=UNIX_SHELL,
            evidence_id="EVID-001",
            raw_ref="audit.log:10",
            time="2026-09-27T10:00:00Z",
            reason="sh -c 실행",
        ),
        _selection(
            unit="UNIT-EVID-002",
            technique=UNIX_SHELL,
            evidence_id="EVID-002",
            raw_ref="audit.log:20",
            time="2026-09-27T10:01:00Z",
            reason="bash 실행",
        ),
    ]

    result = build_attack_mapping_entries(
        selections,
        catalog=FakeCatalog(),
    )

    assert len(result) == 1

    entry = result[0]

    assert entry["technique_id"] == "T1059.004"
    assert entry["technique_name"] == "Unix Shell"

    assert entry["evidence_ids"] == [
        "EVID-001",
        "EVID-002",
    ]

    assert entry["raw_refs"] == [
        "audit.log:10",
        "audit.log:20",
    ]

    assert entry["times"] == [
        "2026-09-27T10:00:00Z",
        "2026-09-27T10:01:00Z",
    ]

    assert entry["matched_by"] == [
        "evidence",
    ]

    assert entry["matched_keywords"] == []

    assert entry["parent_technique"] == {
        "technique_id": "T1059",
        "technique_name": (
            "Command and Scripting Interpreter"
        ),
    }

    assert len(entry["selections"]) == 2
    assert len(entry["matches"]) == 2


def test_subtechnique_suppresses_parent_in_same_unit():
    selections = [
        _selection(
            unit="UNIT-EVID-003",
            technique=COMMAND_INTERPRETER,
            evidence_id="EVID-003",
            raw_ref="audit.log:30",
            time="2026-09-27T10:03:00Z",
            reason="명령 인터프리터 실행",
        ),
        _selection(
            unit="UNIT-EVID-003",
            technique=UNIX_SHELL,
            evidence_id="EVID-003",
            raw_ref="audit.log:30",
            time="2026-09-27T10:03:00Z",
            reason="Unix shell 실행",
        ),
    ]

    result = build_attack_mapping_entries(
        selections,
        catalog=FakeCatalog(),
    )

    assert len(result) == 1
    assert result[0]["technique_id"] == "T1059.004"


def test_preserves_official_tactic_metadata():
    selection = _selection(
        unit="UNIT-EVID-001",
        technique=UNIX_SHELL,
        evidence_id="EVID-001",
        raw_ref="audit.log:10",
        time="2026-09-27T10:00:00Z",
        reason="sh 실행",
    )

    result = build_attack_mapping_entries(
        [selection],
        catalog=FakeCatalog(),
    )

    entry = result[0]

    assert entry["tactic_id"] == "TA0002"
    assert entry["tactic_name"] == "Execution"

    assert entry["tactics"] == [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
        }
    ]