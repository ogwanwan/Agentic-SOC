from copy import deepcopy

from attack_mapping.mapper import (
    build_rag_kill_chain,
)
from attack_mapping.schema import TacticRef


EXECUTION = TacticRef(
    tactic_id="TA0002",
    tactic_name="Execution",
    shortname="execution",
)

STEALTH = TacticRef(
    tactic_id="TA0005",
    tactic_name="Stealth",
    shortname="defense-evasion",
)

DEFENSE_IMPAIRMENT = TacticRef(
    tactic_id="TA0112",
    tactic_name="Defense Impairment",
    shortname="defense-impairment",
)

CREDENTIAL_ACCESS = TacticRef(
    tactic_id="TA0006",
    tactic_name="Credential Access",
    shortname="credential-access",
)


class FakeCatalog:
    tactic_order = (
        EXECUTION,
        STEALTH,
        DEFENSE_IMPAIRMENT,
        CREDENTIAL_ACCESS,
    )


def _technique(
    *,
    technique_id,
    technique_name,
    tactic_id,
    tactic_name,
    time,
    evidence_id,
):
    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactic_id": tactic_id,
        "tactic_name": tactic_name,
        "tactics": [
            {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
            }
        ],
        "matched_by": [
            "evidence",
        ],
        "matched_keywords": [],
        "evidence_ids": [
            evidence_id,
        ],
        "raw_refs": [
            f"audit.log:{evidence_id}",
        ],
        "times": [
            time,
        ],
        "matches": [],
    }


def test_rag_kill_chain_orders_cross_tactic_events_by_observed_time():
    techniques = [
        _technique(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            time="2026-09-27T10:01:00Z",
            evidence_id="EVID-003",
        ),
        _technique(
            technique_id="T1070.004",
            technique_name="File Deletion",
            tactic_id="TA0005",
            tactic_name="Stealth",
            time="2026-09-27T10:03:00Z",
            evidence_id="EVID-002",
        ),
        _technique(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic_id="TA0002",
            tactic_name="Execution",
            time="2026-09-27T10:00:00Z",
            evidence_id="EVID-001",
        ),
    ]

    result = build_rag_kill_chain(
        techniques,
        catalog=FakeCatalog(),
    )

    assert [
        step["tactic_name"]
        for step in result
    ] == [
        "Execution",
        "Credential Access",
        "Stealth",
    ]

    assert [
        step["technique_id"]
        for step in result
    ] == [
        "T1059.004",
        "T1003",
        "T1070.004",
    ]

    assert [
        step["step"]
        for step in result
    ] == [
        1,
        2,
        3,
    ]


def test_rag_kill_chain_keeps_time_order_inside_same_tactic():
    techniques = [
        _technique(
            technique_id="T1003",
            technique_name="Later Credential Technique",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            time="2026-09-27T10:05:00Z",
            evidence_id="EVID-002",
        ),
        _technique(
            technique_id="T1555",
            technique_name="Earlier Credential Technique",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            time="2026-09-27T10:01:00Z",
            evidence_id="EVID-001",
        ),
    ]

    result = build_rag_kill_chain(
        techniques,
        catalog=FakeCatalog(),
    )

    assert [
        step["technique_id"]
        for step in result
    ] == [
        "T1555",
        "T1003",
    ]


def test_rag_kill_chain_uses_original_sequence_for_equal_or_missing_times():
    techniques = [
        _technique(
            technique_id="T1070.004", technique_name="File Deletion",
            tactic_id="TA0005", tactic_name="Stealth",
            time="2026-09-27T10:00:00Z", evidence_id="EVID-LATE",
        ),
        _technique(
            technique_id="T1003", technique_name="Credential Dumping",
            tactic_id="TA0006", tactic_name="Credential Access",
            time="2026-09-27T10:00:00+00:00", evidence_id="EVID-EARLY",
        ),
        _technique(
            technique_id="T1059.004", technique_name="Unix Shell",
            tactic_id="TA0002", tactic_name="Execution",
            time=None, evidence_id="EVID-UNTIMED-LATE",
        ),
        _technique(
            technique_id="T1555", technique_name="Credentials from Password Stores",
            tactic_id="TA0006", tactic_name="Credential Access",
            time=None, evidence_id="EVID-UNTIMED-EARLY",
        ),
    ]
    sequences = {
        "EVID-LATE": 8, "EVID-EARLY": 2,
        "EVID-UNTIMED-LATE": 11, "EVID-UNTIMED-EARLY": 4,
    }

    result = build_rag_kill_chain(
        techniques, catalog=FakeCatalog(), evidence_sequences=sequences,
    )

    assert [step["technique_id"] for step in result] == [
        "T1003", "T1070.004", "T1555", "T1059.004",
    ]
    assert [step["step"] for step in result] == [1, 2, 3, 4]


def test_rag_kill_chain_uses_tactic_only_for_same_event_ties():
    techniques = [
        _technique(
            technique_id="T1003", technique_name="Credential Dumping",
            tactic_id="TA0006", tactic_name="Credential Access",
            time="2026-09-27T10:00:00Z", evidence_id="EVID-ONE",
        ),
        _technique(
            technique_id="T1059.004", technique_name="Unix Shell",
            tactic_id="TA0002", tactic_name="Execution",
            time="2026-09-27T10:00:00Z", evidence_id="EVID-ONE",
        ),
    ]

    result = build_rag_kill_chain(
        techniques, catalog=FakeCatalog(), evidence_sequences={"EVID-ONE": 3},
    )

    assert [step["technique_id"] for step in result] == ["T1059.004", "T1003"]


def test_rag_kill_chain_does_not_mutate_techniques():
    techniques = [
        _technique(
            technique_id="T1070.004",
            technique_name="File Deletion",
            tactic_id="TA0005",
            tactic_name="Stealth",
            time="2026-09-27T10:00:00Z",
            evidence_id="EVID-001",
        )
    ]

    original = deepcopy(
        techniques
    )

    build_rag_kill_chain(
        techniques,
        catalog=FakeCatalog(),
    )

    assert techniques == original
