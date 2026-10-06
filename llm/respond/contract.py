"""입력 읽기 — final_report.json의 필드 접근자. 설계 문서 3절.

구조를 신뢰할 수 없으면(필수 필드 없음·타입 오류) ContractError를 던진다.
gate.py가 이를 response_status="error"로 바꾼다. 없는 값은 없는 대로 두고
기본값으로 꾸며내지 않는다 — 대응권고가 근거 없는 사실 위에 서지 않게 하기 위해서다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional


class ContractError(ValueError):
    """final_report.json 구조를 신뢰할 수 없음(response_status=error로 이어짐)."""


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{path}은 객체여야 합니다")
    return value


def _text(value: Any, path: str, *, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ContractError(f"{path}은 문자열이어야 합니다")
    if required and not value.strip():
        raise ContractError(f"{path}은 비어 있지 않은 문자열이어야 합니다")
    return value


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


def _list(value: Any, path: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ContractError(f"{path}은 리스트여야 합니다")
    return value


@dataclass(frozen=True)
class Verdict:
    verdict: str
    confidence: float
    severity: str
    attack_type: str
    affected_systems: tuple
    summary: str


@dataclass(frozen=True)
class MappingView:
    mapping_status: str
    provenance_status: Optional[str]
    techniques: tuple
    kill_chain: tuple
    warnings: tuple
    # 2026-10-06 추가 — 어떤 ATT&CK 데이터로 매핑했는지(권고문 산출물에 그대로 싣는다).
    # attack_mapping(RAG 경로)이 적어 주는 값이고, 룰 경로에서는 없을 수 있어 기본값 None이다.
    attack_version: Optional[str] = None       # manifest.json attack_version (예: "19.2")
    mapping_method: Optional[str] = None       # rag_llm | rule_baseline | rule_fallback
    retrieval_version: Optional[str] = None    # manifest.json retrieval_version

    @property
    def technique_ids(self):
        return frozenset(
            t.get("technique_id") for t in self.techniques if isinstance(t.get("technique_id"), str)
        )

    @property
    def warning_codes(self):
        return frozenset(w.get("code") for w in self.warnings if isinstance(w.get("code"), str))


@dataclass(frozen=True)
class Contract:
    incident_id: str
    incident_key: Optional[str]
    investigation_id: Optional[str]
    investigation_status: str
    provenance_status: str          # investigation_result 최상위 provenance.status
    verdict: Verdict
    investigation_confidence: float
    remaining_unknowns: tuple
    initial_seed: Mapping[str, Any]
    tools_called: tuple
    mapping: MappingView


def read_contract(final_report: Any) -> Contract:
    data = _object(final_report, "final_report")

    incident_id = _text(data.get("incident_id"), "incident_id", required=True)
    incident_key = _text(data.get("incident_key"), "incident_key") or None
    investigation_id = _text(data.get("investigation_id"), "investigation_id") or None
    investigation_status = _text(
        data.get("investigation_status"), "investigation_status", required=True
    )

    provenance = _object(data.get("provenance") or {}, "provenance")
    provenance_status = _text(provenance.get("status"), "provenance.status") or "unavailable"

    final_verdict = _object(data.get("final_verdict"), "final_verdict")
    verdict = Verdict(
        verdict=_text(final_verdict.get("verdict"), "final_verdict.verdict", required=True),
        confidence=_number(final_verdict.get("confidence")),
        severity=_text(final_verdict.get("severity"), "final_verdict.severity") or "UNKNOWN",
        attack_type=_text(final_verdict.get("attack_type"), "final_verdict.attack_type"),
        affected_systems=tuple(
            s for s in _list(final_verdict.get("affected_systems"), "final_verdict.affected_systems")
            if isinstance(s, str)
        ),
        summary=_text(final_verdict.get("summary"), "final_verdict.summary"),
    )

    statistics = _object(data.get("statistics") or {}, "statistics")
    investigation_confidence = _number(statistics.get("investigation_confidence"))

    remaining_unknowns = tuple(
        u for u in _list(data.get("remaining_unknowns"), "remaining_unknowns") if isinstance(u, str)
    )

    initial_seed = _object(data.get("initial_seed") or {}, "initial_seed")

    tools_called = tuple(
        t for t in _list(data.get("tools_called"), "tools_called") if isinstance(t, Mapping)
    )

    attack_mapping = _object(data.get("attack_mapping"), "attack_mapping")
    mapping = MappingView(
        mapping_status=_text(
            attack_mapping.get("mapping_status"), "attack_mapping.mapping_status", required=True
        ),
        provenance_status=_text(
            attack_mapping.get("provenance_status"), "attack_mapping.provenance_status"
        ) or None,
        techniques=tuple(
            t for t in _list(attack_mapping.get("techniques"), "attack_mapping.techniques")
            if isinstance(t, Mapping)
        ),
        kill_chain=tuple(
            s for s in _list(attack_mapping.get("kill_chain"), "attack_mapping.kill_chain")
            if isinstance(s, Mapping)
        ),
        warnings=tuple(
            w for w in _list(attack_mapping.get("warnings"), "attack_mapping.warnings")
            if isinstance(w, Mapping)
        ),
        attack_version=_text(
            attack_mapping.get("attack_version"), "attack_mapping.attack_version") or None,
        mapping_method=_text(
            attack_mapping.get("mapping_method"), "attack_mapping.mapping_method") or None,
        retrieval_version=_text(
            attack_mapping.get("retrieval_version"), "attack_mapping.retrieval_version") or None,
    )

    return Contract(
        incident_id=incident_id, incident_key=incident_key, investigation_id=investigation_id,
        investigation_status=investigation_status, provenance_status=provenance_status,
        verdict=verdict, investigation_confidence=investigation_confidence,
        remaining_unknowns=remaining_unknowns, initial_seed=initial_seed,
        tools_called=tools_called, mapping=mapping,
    )


if __name__ == "__main__":  # 자체 점검: python llm/respond/contract.py
    sample = {
        "incident_id": "INC-1", "investigation_id": "INV-1", "investigation_status": "COMPLETE",
        "provenance": {"status": "passed"},
        "final_verdict": {"verdict": "THREAT_CONFIRMED", "confidence": 0.89, "severity": "HIGH",
                           "attack_type": "웹셸", "affected_systems": ["web"], "summary": "..."},
        "statistics": {"investigation_confidence": 0.92},
        "remaining_unknowns": [], "initial_seed": {"src_ip": "203.0.113.45"},
        "tools_called": [],
        "attack_mapping": {"mapping_status": "mapped", "techniques": [], "kill_chain": [], "warnings": []},
    }
    contract = read_contract(sample)
    assert contract.incident_id == "INC-1"
    # ATT&CK 데이터 출처는 없으면 None으로 두고 꾸며내지 않는다
    assert contract.mapping.attack_version is None and contract.mapping.mapping_method is None
    with_version = dict(sample)
    with_version["attack_mapping"] = dict(sample["attack_mapping"],
                                          attack_version="19.2", mapping_method="rag_llm")
    assert read_contract(with_version).mapping.attack_version == "19.2"
    assert contract.verdict.verdict == "THREAT_CONFIRMED"
    assert contract.investigation_confidence == 0.92

    try:
        read_contract({"incident_id": "INC-2"})
        raise AssertionError("필수 필드 없이도 통과하면 안 됨")
    except ContractError:
        pass

    print("ok")
