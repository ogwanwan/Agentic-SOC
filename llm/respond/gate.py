"""진입 관문 — 설계 문서 4절. 판정·매핑 상태를 보고 LLM을 부를지 결정한다.

표의 순서가 곧 우선순위다(위에서부터 먼저 걸리는 조건을 적용). 임계값을 새로
만들지 않는다 — 조사·매핑 단계가 이미 내린 판정을 여기서 재심하지 않는다.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from respond.contract import Contract  # noqa: E402

_KNOWN_VERDICTS = ("THREAT_CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE")
_MAPPED_STATUSES = ("mapped", "partial")
_GENERIC_STATUSES = ("no_techniques_matched", "deferred", "error")


@dataclass(frozen=True)
class GateResult:
    response_status: str   # skipped | not_applicable | deferred | recommended
                            # | recommended_generic | error
    reason: str             # 사람이 읽는 사유 (run_log 기록용)
    use_llm: bool            # 이 상태에서 LLM을 부를지
    use_technique_catalog: bool   # True면 6-1 기법 카탈로그, False면 6-2 폴백 카탈로그


def evaluate_gate(contract: Contract) -> GateResult:
    if contract.investigation_status == "INCOMPLETE":
        return GateResult("skipped", "조사가 완료되지 않음(큐가 재조사함)", False, False)

    verdict = contract.verdict.verdict

    if verdict == "FALSE_POSITIVE":
        return GateResult("not_applicable", "오탐으로 판정됨", False, False)

    if verdict == "INCONCLUSIVE":
        return GateResult("deferred", "증거 부족으로 결론 보류", False, False)

    if verdict not in _KNOWN_VERDICTS:
        return GateResult("error", f"알 수 없는 final_verdict.verdict: {verdict!r}", False, False)

    # 이 아래부터는 verdict == THREAT_CONFIRMED
    if contract.provenance_status == "unavailable":
        return GateResult("deferred", "원본 참조 추적 불가(provenance unavailable)", False, False)

    mapping_status = contract.mapping.mapping_status
    if mapping_status in _MAPPED_STATUSES:
        return GateResult("recommended", "위협 확정 + ATT&CK 기법 매핑됨", True, True)

    if mapping_status in _GENERIC_STATUSES:
        return GateResult(
            "recommended_generic", "위협 확정, 기법 매핑 실패/없음 — 폴백 카탈로그 사용", True, False
        )

    if mapping_status == "not_applicable":
        # verdict=THREAT_CONFIRMED인데 매핑은 FALSE_POSITIVE로 본 경우 — 이론상 안 생겨야 함
        return GateResult(
            "error", "verdict=THREAT_CONFIRMED인데 mapping_status=not_applicable", False, False
        )

    return GateResult("error", f"알 수 없는 mapping_status: {mapping_status!r}", False, False)


if __name__ == "__main__":  # 자체 점검: python llm/respond/gate.py
    from respond.contract import MappingView, Verdict

    def _contract(verdict, mapping_status, *, provenance_status="passed",
                  investigation_status="COMPLETE"):
        return Contract(
            incident_id="INC-1", incident_key=None, investigation_id="INV-1",
            investigation_status=investigation_status, provenance_status=provenance_status,
            verdict=Verdict(verdict, 0.8, "HIGH", "x", (), ""),
            investigation_confidence=0.9, remaining_unknowns=(), initial_seed={}, tools_called=(),
            mapping=MappingView(mapping_status, "passed", (), (), ()),
        )

    assert evaluate_gate(_contract("x", "x", investigation_status="INCOMPLETE")).response_status == "skipped"
    assert evaluate_gate(_contract("FALSE_POSITIVE", "not_applicable")).response_status == "not_applicable"
    assert evaluate_gate(_contract("INCONCLUSIVE", "deferred")).response_status == "deferred"
    assert evaluate_gate(_contract("THREAT_CONFIRMED", "mapped", provenance_status="unavailable")).response_status == "deferred"
    r = evaluate_gate(_contract("THREAT_CONFIRMED", "mapped"))
    assert r.response_status == "recommended" and r.use_llm and r.use_technique_catalog
    r = evaluate_gate(_contract("THREAT_CONFIRMED", "no_techniques_matched"))
    assert r.response_status == "recommended_generic" and r.use_llm and not r.use_technique_catalog
    assert evaluate_gate(_contract("WHAT", "mapped")).response_status == "error"
    assert evaluate_gate(_contract("THREAT_CONFIRMED", "???")).response_status == "error"

    print("ok")
