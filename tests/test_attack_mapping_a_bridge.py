from attack_mapping.mapper import (
    judge_and_validate_mapping_unit,
)
from attack_mapping.schema import (
    CandidateTechnique,
    MappingUnit,
    TacticRef,
    TechniqueRecord,
)
from attack_mapping.validate import EvidenceEligibility


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete_json(self, system_prompt, user_prompt):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
            }
        )
        return self.response


EXECUTION = TacticRef(
    tactic_id="TA0002",
    tactic_name="Execution",
    shortname="execution",
)

DISCOVERY = TacticRef(
    tactic_id="TA0007",
    tactic_name="Discovery",
    shortname="discovery",
)


UNIX_SHELL = TechniqueRecord(
    technique_id="T1059.004",
    stix_id="attack-pattern--unix-shell",
    name="Unix Shell",
    description="Adversaries may abuse Unix shell commands.",
    tactics=(EXECUTION,),
    is_subtechnique=True,
    parent_id="T1059",
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1059/004/",
)


USER_DISCOVERY = TechniqueRecord(
    technique_id="T1033",
    stix_id="attack-pattern--user-discovery",
    name="System Owner/User Discovery",
    description="Adversaries may attempt to identify the user.",
    tactics=(DISCOVERY,),
    is_subtechnique=False,
    parent_id=None,
    platforms=("Linux",),
    url="https://attack.mitre.org/techniques/T1033/",
)


class FakeCatalog:
    def __init__(self):
        self.records = {
            "T1059.004": UNIX_SHELL,
            "T1033": USER_DISCOVERY,
        }

    def lookup(self, technique_id):
        return self.records.get(technique_id)


def _mapping_unit():
    return MappingUnit(
        mapping_unit_id="UNIT-EVID-003",
        evidence_id="EVID-003",
        sequence=3,
        time="2026-09-27T10:03:00Z",
        layer="audit",
        event_type="process_execution",
        description=(
            "www-data가 sh -c id;whoami;uname -a를 실행함"
        ),
        raw_refs=("audit.log:321",),
    )


def _eligibility():
    evidence = {
        "evidence_id": "EVID-003",
        "sequence": 3,
        "time": "2026-09-27T10:03:00Z",
        "layer": "audit",
        "event_type": "process_execution",
        "description": (
            "www-data가 sh -c id;whoami;uname -a를 실행함"
        ),
        "raw_refs": ["audit.log:321"],
    }

    row = EvidenceEligibility(
        evidence_id="EVID-003",
        sequence=3,
        status="target",
        reasons=(),
        flags=(),
        seed_only_raw_refs=(),
        contradicting=False,
        evidence=evidence,
    )

    return {
        "EVID-003": row,
    }


def _unix_candidate():
    return CandidateTechnique(
        technique_id="T1059.004",
        name="Unix Shell",
        description="Adversaries may abuse Unix shell commands.",
        tactics=(EXECUTION,),
        parent_id="T1059",
        rank=1,
        score=0.95,
        sources=("bm25", "vector"),
    )


def test_real_a_validator_accepts_valid_selection():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "sh -c를 이용한 Unix shell 실행",
                }
            ],
        }
    )

    accepted, rejected = judge_and_validate_mapping_unit(
        llm_client=llm,
        mapping_unit=_mapping_unit(),
        candidates=[_unix_candidate()],
        catalog=FakeCatalog(),
        eligibility=_eligibility(),
    )

    assert len(accepted) == 1
    assert rejected == []

    result = accepted[0]

    assert result.technique.technique_id == "T1059.004"
    assert result.technique.name == "Unix Shell"
    assert result.evidence_ids == ("EVID-003",)
    assert result.raw_refs == ("audit.log:321",)
    assert result.reason == "sh -c를 이용한 Unix shell 실행"


def test_real_a_validator_rejects_candidate_outside_unit_candidates():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1033",
                    "evidence_ids": ["EVID-003"],
                    "reason": "whoami를 이용한 사용자 확인",
                }
            ],
        }
    )

    accepted, rejected = judge_and_validate_mapping_unit(
        llm_client=llm,
        mapping_unit=_mapping_unit(),
        candidates=[_unix_candidate()],
        catalog=FakeCatalog(),
        eligibility=_eligibility(),
    )

    assert accepted == []

    assert any(
        item["code"] == "NOT_IN_CANDIDATES"
        for item in rejected
    )


def test_real_a_validator_rejects_empty_reason():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [
                {
                    "technique_id": "T1059.004",
                    "evidence_ids": ["EVID-003"],
                    "reason": "",
                }
            ],
        }
    )

    accepted, rejected = judge_and_validate_mapping_unit(
        llm_client=llm,
        mapping_unit=_mapping_unit(),
        candidates=[_unix_candidate()],
        catalog=FakeCatalog(),
        eligibility=_eligibility(),
    )

    assert accepted == []

    assert any(
        item["code"] == "EMPTY_REASON"
        for item in rejected
    )


def test_abstain_skips_a_validation_result():
    llm = FakeLLM(
        {
            "decision": "ABSTAIN",
            "selections": [],
        }
    )

    accepted, rejected = judge_and_validate_mapping_unit(
        llm_client=llm,
        mapping_unit=_mapping_unit(),
        candidates=[_unix_candidate()],
        catalog=FakeCatalog(),
        eligibility=_eligibility(),
    )

    assert accepted == []
    assert rejected == []


def test_no_candidates_does_not_call_llm():
    llm = FakeLLM(
        {
            "decision": "SELECT",
            "selections": [],
        }
    )

    accepted, rejected = judge_and_validate_mapping_unit(
        llm_client=llm,
        mapping_unit=_mapping_unit(),
        candidates=[],
        catalog=FakeCatalog(),
        eligibility=_eligibility(),
    )

    assert accepted == []
    assert rejected == []
    assert llm.calls == []