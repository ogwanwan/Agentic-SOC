"""ATT&CK 매핑 검증 — 사건 관문, 증거별 매핑 가능 판정, LLM 선택 검증 (담당 A).

역할
  check_case_gate():     사건 단위 관문. verdict·provenance로 매핑 진행 여부를 정한다.
  classify_evidence():   증거마다 target(Mapping Unit) / context(참고 문맥) / excluded를 정한다.
                         C의 mapper가 Unit을 고를 때와 validate_decision()이 검증할 때 같은 결과를 쓴다.
  validate_decision():   LLM 결정 하나(Unit 하나)를 검증한다. 실패한 selection만 빼고 나머지는 유지.

조사 결과(investigation_result)에서 알아야 할 사실 — agent/loop.py·provenance.py·report.py 기준
  - provenance는 사건 전체 요약이다. 증거별 상태는 아래 필드를 조합해야 나온다.
      evidence_without_raw_refs  원본 인용이 없는 증거 id
      empty_result_evidence      코드가 "성공한 0건 조회"로 확인한 증거 id (passed에서도 있을 수 있음)
      ambiguous_raw_refs         {ref: [여러 위치]}
      issues                     [{sequence, error | unknown_raw_refs}] — 증거의 sequence 기준.
                                 empty_result_call의 숫자(도구 호출 sequence)와 다른 번호다.
  - 증거의 raw_refs에는 관측 확인을 통과한 참조만 남는다. LLM이 지어낸 참조는 빠진 채 저장되고
    흔적은 issues에만 남는다 → "raw_refs가 등록됐는가"만 보면 통과해 버리므로 issues로 걸러야 한다.
  - 증거 sequence는 evidence_chain과 contradicting_evidence가 한 번호 공간을 쓴다.
    EVID 번호는 전역 카운터라서 번호로 sequence를 추정하면 안 된다.
  - investigation raw_refs에는 1차 탐지 참조(seed)도 들어 있다. seed에만 있는 참조를 인용한 증거도
    실제 원본 줄이므로 제외하지 않고 SEED_ONLY_RAW_REFS 표시만 붙인다(설계 9.4).
    규칙은 참조 단위: raw_refs 중 도구 결과에서 관측되지 않았고 seed에 있는 참조가 하나라도 있으면 표시.
    0928(a30a52e) 이후 결과는 증거의 seed_only_raw_refs 필드(조사 코드가 계산)를 그대로 쓰고,
    필드가 없는 이전 결과만 tools_called[].raw_refs와 provenance.seed_raw_refs로 같은 규칙을 계산한다.
    조사 쪽 설명: docs/EVIDENCE_REF_SOURCES.md
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

from .schema import (TECHNIQUE_ID_PATTERN, InvestigationFormatError, MappingDecision, MappingUnit,
                     Selection, SelectionRejection, TechniqueRecord, ValidatedSelection)

# ---------------------------------------------------------------------------
# 사건 관문 — 상태 규칙은 기존 engine.map_investigation()과 같다(Rule Baseline과 비교 가능하게)
# ---------------------------------------------------------------------------

FALLBACK_VERDICT_MARKER = "[자동 폴백 판정"
PRINCIPLE_CONFLICT_MARKER = "⚠ 판정-원칙 불일치"
_VERDICTS = ("THREAT_CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE")
_PROVENANCE_STATUSES = ("passed", "incomplete", "unavailable")


@dataclass(frozen=True)
class CaseGate:
    proceed: bool
    mapping_status: Optional[str]          # 진행하지 않을 때의 최종 상태 (not_applicable/deferred/error)
    provenance_status: Optional[str]
    warnings: Tuple[Dict[str, Any], ...] = ()
    errors: Tuple[str, ...] = ()


def check_case_gate(result: Any) -> CaseGate:
    """FALSE_POSITIVE → not_applicable, INCONCLUSIVE·unavailable·provenance 없음 → deferred.
    알 수 없는 verdict·provenance status 같은 구조 오류 → error(조용히 deferred로 넘기지 않는다)."""
    def error(message: str, status: Optional[str] = None) -> CaseGate:
        return CaseGate(False, "error", status, errors=(message,))

    if not isinstance(result, Mapping):
        return error("investigation_result must be an object")
    final_verdict = result.get("final_verdict")
    if not isinstance(final_verdict, Mapping):
        return error("final_verdict must be an object")
    verdict = final_verdict.get("verdict")
    if verdict not in _VERDICTS:
        return error(f"unsupported final_verdict.verdict: {verdict!r}")
    provenance = result.get("provenance", {})
    if not isinstance(provenance, Mapping):
        return error("provenance must be an object")
    status = provenance.get("status", "unavailable")    # 0922 이전 결과처럼 provenance가 없으면 unavailable
    if status not in _PROVENANCE_STATUSES:
        return error(f"unsupported provenance.status: {status!r}")

    if verdict == "FALSE_POSITIVE":
        return CaseGate(False, "not_applicable", status)
    if verdict == "INCONCLUSIVE" or status == "unavailable":
        return CaseGate(False, "deferred", status)
    if not isinstance(result.get("evidence_chain"), list):
        return error("evidence_chain must be a list", status)

    # 판정 품질 경고 — 진행 여부는 팀 정책으로 정한다(지금은 경고만 남기고 진행)
    warnings = []
    if FALLBACK_VERDICT_MARKER in str(final_verdict.get("reasoning", "")):
        warnings.append({"code": "FALLBACK_VERDICT",
                         "detail": "LLM 판정이 아니라 누적 confidence 수치로 만든 폴백 판정"})
    if any(PRINCIPLE_CONFLICT_MARKER in str(n) for n in result.get("investigation_notes") or []):
        warnings.append({"code": "VERDICT_PRINCIPLE_CONFLICT",
                         "detail": "조사 에이전트가 판정-원칙 불일치를 기록함"})
    return CaseGate(True, None, status, tuple(warnings))


# ---------------------------------------------------------------------------
# 증거별 매핑 가능 판정
# ---------------------------------------------------------------------------

TARGET = "target"        # 기법 선택의 직접 근거 = Mapping Unit
CONTEXT = "context"      # LLM 참고 문맥으로만 (0건 증거, 반박 증거)
EXCLUDED = "excluded"    # 매핑에 쓰지 않음

# 이유 코드 → 분류. 한 증거에 여러 이유가 붙으면 EXCLUDED > CONTEXT > TARGET 순으로 이긴다.
REASON_STATUS = {
    "CONTRADICTING": CONTEXT,
    "EMPTY_RESULT": CONTEXT,
    "NO_RAW_REFS": EXCLUDED,
    "PROVENANCE_ISSUE": EXCLUDED,
    "AMBIGUOUS_RAW_REF": EXCLUDED,
    "UNOBSERVED_RAW_REF": EXCLUDED,
}
# 분류를 바꾸지 않는 표시. 결과(ValidatedSelection.flags)에 그대로 전달된다.
SEED_ONLY_RAW_REFS = "SEED_ONLY_RAW_REFS"
_PRIORITY = {TARGET: 0, CONTEXT: 1, EXCLUDED: 2}


@dataclass(frozen=True)
class EvidenceEligibility:
    evidence_id: str
    sequence: Optional[int]
    status: str
    reasons: Tuple[str, ...]
    flags: Tuple[str, ...]
    seed_only_raw_refs: Tuple[str, ...]    # 조사 도구로 관측되지 않은 1차 탐지 참조
    contradicting: bool
    evidence: Mapping[str, Any]            # 원본의 깊은 복사본 — 원본 JSON은 건드리지 않는다

    @property
    def raw_refs(self) -> Tuple[str, ...]:
        return tuple(self.evidence.get("raw_refs") or ())


def _list(value: Any, path: str) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise InvestigationFormatError(f"{path} must be a list")
    return value


def _strings(value: Any, path: str) -> List[str]:
    items = _list(value, path)
    if any(not isinstance(v, str) or not v for v in items):
        raise InvestigationFormatError(f"{path} must contain non-empty strings")
    return items


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise InvestigationFormatError(f"{path} must be an object")
    return value


def _tool_observed_refs(result: Mapping[str, Any]) -> set:
    refs = set()
    for index, call in enumerate(_list(result.get("tools_called"), "tools_called")):
        refs.update(_strings(_mapping(call, f"tools_called[{index}]").get("raw_refs"),
                             f"tools_called[{index}].raw_refs"))
    return refs


def _seed_only_refs(ev: Mapping[str, Any], path: str, refs: List[str],
                    seed_refs: set, tool_observed: set) -> Tuple[str, ...]:
    """증거 필드가 있으면 그대로 쓰고(조사 종료 시점 계산값), 없으면 같은 참조 단위 규칙으로 계산한다."""
    if "seed_only_raw_refs" in ev:
        given = _strings(ev["seed_only_raw_refs"], f"{path}.seed_only_raw_refs")
        if not set(given) <= set(refs):
            raise InvestigationFormatError(f"{path}.seed_only_raw_refs must be a subset of raw_refs")
        return tuple(given)
    return tuple(r for r in refs if r not in tool_observed and r in seed_refs)


def classify_evidence(result: Mapping[str, Any]) -> List[EvidenceEligibility]:
    """evidence_chain + contradicting_evidence를 분류한다. 구조가 깨졌으면 InvestigationFormatError.

    evidence_id 누락·중복은 제외 사유가 아니라 입력 오류다. 중복을 허용하면 Unit을 만든 항목과
    검증 때 조회되는 항목이 달라질 수 있다.
    """
    prov = _mapping(result.get("provenance"), "provenance")
    observed = set(_strings(result.get("raw_refs"), "raw_refs"))
    tool_observed = _tool_observed_refs(result)
    seed_refs = set(_strings(prov.get("seed_raw_refs"), "provenance.seed_raw_refs"))
    without_refs = set(_strings(prov.get("evidence_without_raw_refs"), "provenance.evidence_without_raw_refs"))
    empty_result = set(_strings(prov.get("empty_result_evidence"), "provenance.empty_result_evidence"))
    ambiguous = set(_mapping(prov.get("ambiguous_raw_refs"), "provenance.ambiguous_raw_refs"))
    locations = _mapping(result.get("raw_ref_locations"), "raw_ref_locations")
    ambiguous |= {ref for ref, sources in locations.items() if isinstance(sources, list) and len(sources) > 1}
    issue_sequences = set()
    for index, issue in enumerate(_list(prov.get("issues"), "provenance.issues")):
        sequence = _mapping(issue, f"provenance.issues[{index}]").get("sequence")
        if sequence is not None:
            issue_sequences.add(sequence)

    rows = ([("evidence_chain", e, False) for e in _list(result.get("evidence_chain"), "evidence_chain")]
            + [("contradicting_evidence", e, True)
               for e in _list(result.get("contradicting_evidence"), "contradicting_evidence")])
    seen_ids: set = set()
    out: List[EvidenceEligibility] = []
    for index, (name, raw, contradicting) in enumerate(rows):
        path = f"{name}[{index}]"
        ev = _mapping(raw, path)
        eid = ev.get("evidence_id")
        if not isinstance(eid, str) or not eid:
            raise InvestigationFormatError(f"{path}.evidence_id must be a non-empty string")
        if eid in seen_ids:
            raise InvestigationFormatError(f"duplicate evidence_id: {eid}")
        seen_ids.add(eid)
        sequence = ev.get("sequence")
        if sequence is not None and (type(sequence) is not int or sequence < 1):
            raise InvestigationFormatError(f"{path}.sequence must be a positive integer")
        refs = _strings(ev.get("raw_refs"), f"{path}.raw_refs")

        reasons: List[str] = []
        if contradicting:
            reasons.append("CONTRADICTING")
        if eid in empty_result:
            reasons.append("EMPTY_RESULT")
        elif not refs or eid in without_refs:
            reasons.append("NO_RAW_REFS")
        if sequence is not None and sequence in issue_sequences:
            reasons.append("PROVENANCE_ISSUE")
        if any(r in ambiguous for r in refs):
            reasons.append("AMBIGUOUS_RAW_REF")
        if any(r not in observed for r in refs):
            reasons.append("UNOBSERVED_RAW_REF")
        # 조사 도구로 관측되지 않은 1차 탐지 참조가 하나라도 있으면 표시만 한다(분류는 그대로)
        seed_only = _seed_only_refs(ev, path, refs, seed_refs, tool_observed)
        flags = (SEED_ONLY_RAW_REFS,) if seed_only else ()

        status = max((REASON_STATUS[r] for r in reasons), key=_PRIORITY.__getitem__, default=TARGET)
        out.append(EvidenceEligibility(eid, sequence, status, tuple(reasons), flags, seed_only,
                                       contradicting, copy.deepcopy(dict(ev))))
    return out


def eligibility_index(rows: Iterable[EvidenceEligibility]) -> Dict[str, EvidenceEligibility]:
    return {r.evidence_id: r for r in rows}


def target_evidence(rows: Iterable[EvidenceEligibility]) -> List[EvidenceEligibility]:
    """Mapping Unit이 될 증거. evidence_chain 순서 그대로."""
    return [r for r in rows if r.status == TARGET]


def exclusions(rows: Iterable[EvidenceEligibility]) -> List[Dict[str, Any]]:
    """evidence_chain 중 Unit이 되지 않은 증거와 사유. 반박 증거는 체인 밖이라 넣지 않는다.
    excluded_evidence_ids = [e["evidence_id"] for e in exclusions(rows)]"""
    return [{"evidence_id": r.evidence_id, "reasons": list(r.reasons)}
            for r in rows if not r.contradicting and r.status != TARGET]


# ---------------------------------------------------------------------------
# LLM 선택 검증
# ---------------------------------------------------------------------------

class Catalog(Protocol):
    """catalog.AttackCatalog가 구현한다. 비활성 기법도 revoked/deprecated 표시와 함께 돌려준다."""

    def lookup(self, technique_id: str) -> Optional[TechniqueRecord]: ...


def normalize_technique_id(value: Any) -> str:
    """공백·대소문자만 맞춘다(같은 ID의 표기 차이). 다른 ID로 바꾸는 보정은 하지 않는다."""
    return str(value or "").strip().upper()


# 이 코드가 하나라도 있으면 selection 전체를 버린다. 나머지는 해당 evidence_id만 뺀다.
FATAL_CODES = frozenset({
    "UNIT_NOT_TARGET", "UNIT_MISMATCH", "INVALID_TECHNIQUE_ID", "REVOKED_OR_DEPRECATED",
    "NOT_IN_CANDIDATES", "UNIT_EVIDENCE_NOT_CITED", "EMPTY_REASON",
})


@dataclass
class SelectionCheck:
    ok: bool
    technique_id: str
    accepted: Optional[ValidatedSelection]
    errors: List[SelectionRejection] = field(default_factory=list)


def _unit_errors(unit: MappingUnit, row: Optional[EvidenceEligibility]) -> List[Tuple[str, str]]:
    """Unit이 target 증거를 그대로 옮겼는지 확인한다(sequence·raw_refs 재번호 금지)."""
    if row is None or row.status != TARGET:
        reasons = ", ".join(row.reasons) if row else "evidence_chain에 없음"
        return [("UNIT_NOT_TARGET", f"{unit.evidence_id}: {reasons}")]
    ev = row.evidence
    expected = {"sequence": ev.get("sequence"), "time": ev.get("time"), "layer": ev.get("layer", ""),
                "event_type": ev.get("event_type", ""), "description": ev.get("description", ""),
                "raw_refs": row.raw_refs}
    changed = [name for name, value in expected.items() if getattr(unit, name) != value]
    return [("UNIT_MISMATCH", "원본 증거와 다른 필드: " + ", ".join(changed))] if changed else []


def validate_selection(
    selection: Selection,
    *,
    unit: MappingUnit,
    candidate_ids: Sequence[str],
    catalog: Catalog,
    eligibility: Mapping[str, EvidenceEligibility],
) -> SelectionCheck:
    """selections 배열의 한 항목을 검증한다. 오류는 모두 모아서 돌려준다(개발 중 추적용).

    evidence_ids는 이 Unit의 evidence_id만 인정한다(P0). 다른 증거 id는 target이어도
    EVIDENCE_OUTSIDE_UNIT으로 빼서, 다른 Unit의 후보로 검증을 우회하지 못하게 한다.
    name/tactic/parent는 LLM 값을 쓰지 않고 catalog 레코드를, raw_refs·time은 증거 값을 쓴다.
    """
    raw_id = selection.technique_id
    tid = normalize_technique_id(raw_id)
    errors: List[SelectionRejection] = []

    def err(code: str, detail: str = "", **extra: Any) -> None:
        item: SelectionRejection = {"code": code, "mapping_unit_id": unit.mapping_unit_id, "value": str(raw_id)}
        if detail:
            item["detail"] = detail
        item.update(extra)  # type: ignore[typeddict-item]
        errors.append(item)

    row = eligibility.get(unit.evidence_id)
    for code, detail in _unit_errors(unit, row):
        err(code, detail)

    # 1·2. 형식·카탈로그 존재·revoked/deprecated
    record = catalog.lookup(tid) if TECHNIQUE_ID_PATTERN.match(tid) else None
    if record is None:
        err("INVALID_TECHNIQUE_ID")
    elif record.revoked or record.deprecated:
        err("REVOKED_OR_DEPRECATED",
            "revoked" + (f" → {record.revoked_by}" if record.revoked_by else "") if record.revoked else "deprecated")
    # 3. 이번 Unit의 후보 안에 있었는가 (부모·하위 기법으로 바꿔 주지 않는다)
    if tid not in {normalize_technique_id(c) for c in candidate_ids}:
        err("NOT_IN_CANDIDATES")

    # 4~7. 증거: Unit 증거만 인정. raw_ref 관측·모호성·provenance issue는 classify_evidence가 판정
    cited = False
    for eid in dict.fromkeys(selection.evidence_ids):
        other = eligibility.get(eid)
        if eid == unit.evidence_id:
            cited = True
        elif other is None:
            err("UNKNOWN_EVIDENCE_ID", evidence_id=eid)
        elif other.status != TARGET:
            err("EVIDENCE_NOT_MAPPABLE", evidence_id=eid, reasons=list(other.reasons))
        else:
            err("EVIDENCE_OUTSIDE_UNIT", evidence_id=eid)
    if not cited:
        err("UNIT_EVIDENCE_NOT_CITED", f"evidence_ids에 {unit.evidence_id}가 없음")
    if not selection.reason.strip():
        err("EMPTY_REASON")

    if any(e["code"] in FATAL_CODES for e in errors):
        return SelectionCheck(False, tid, None, errors)
    flags = tuple(row.flags) + (("TECHNIQUE_ID_NORMALIZED",) if tid != raw_id else ())
    accepted = ValidatedSelection(unit.mapping_unit_id, record, (unit.evidence_id,), row.raw_refs,
                                  row.evidence.get("time"), selection.reason.strip(), flags)
    return SelectionCheck(True, tid, accepted, errors)


def validate_decision(
    decision: MappingDecision,
    *,
    unit: MappingUnit,
    candidate_ids: Sequence[str],
    catalog: Catalog,
    eligibility: Mapping[str, EvidenceEligibility],
) -> Tuple[List[ValidatedSelection], List[SelectionRejection]]:
    """Unit 하나의 결정을 검증한다. ABSTAIN은 ([], []). 같은 기법을 두 번 고르면 두 번째는 버린다.

    반환한 거부 목록은 AttackMappingResult.rejected_selections에 넣는다(errors가 아님).
    """
    accepted: List[ValidatedSelection] = []
    rejected: List[SelectionRejection] = []
    seen = set()
    for selection in decision.selections:
        check = validate_selection(selection, unit=unit, candidate_ids=candidate_ids,
                                   catalog=catalog, eligibility=eligibility)
        rejected.extend(check.errors)
        if check.accepted is None:
            continue
        if check.technique_id in seen:
            rejected.append({"code": "DUPLICATE_SELECTION", "mapping_unit_id": unit.mapping_unit_id,
                             "value": selection.technique_id})
            continue
        seen.add(check.technique_id)
        accepted.append(check.accepted)
    return accepted, rejected
