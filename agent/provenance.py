"""원본 추적(D) — raw_ref(원본 파일:줄)를 잃지 않고 전달하고, 증거가 인용한 참조를 검증한다.

역할
  seed·도구 결과에서 "실제로 관측된" 원본 참조를 모으고(observed_*), LLM이 증거에 인용한 참조가
  그 안에 있는지 확인한다(validate_citations). 최종 보고서의 provenance.status를 계산한다.
  참조는 불투명한 문자열로 다룬다 — 1차 탐지가 만든 raw_ref를 고쳐 쓰거나, 문장에서 참조를
  추측하거나, 인용하지 않은 주장에 로그를 몰래 붙이지 않는다.

누가 부르나
  [13-2] agent/seed_generation.py      references()                 seed의 evidence_refs 검증
  [18]·[24]·[37] agent/loop.py         references(), validate_citations(), observed_*()
  [41] agent/report.py                 provenance_report()
  agent/prompts/, agent/seed_prompts.py strip_trace_fields()        LLM에게 보여줄 사본 정리

무엇을 부르나
  없음 (표준 라이브러리만)
"""
from __future__ import annotations

from typing import Any, Dict, List


def references(value: Dict[str, Any], *, seed: bool = False) -> List[str]:
    result = []
    for key in (("raw_ref", "raw_refs", "evidence_refs") if seed else ("raw_ref", "raw_refs")):
        refs = value.get(key)
        if refs is None:
            continue
        if key == "raw_ref":
            refs = [refs]
        if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
            raise ValueError(f"{key} must contain non-empty string references")
        result.extend(refs)
    return list(dict.fromkeys(result))


# LLM 판단에는 쓰이지 않는 추적용 필드. 코드(loop/report)는 도구 결과 원본에서 이 값을
# 읽으므로, LLM에게 보여주는 사본에서만 뺀다 — 절대 경로가 이벤트마다 반복돼 프롬프트가
# 수 배로 커지고(seed 생성 12만 자 이상) 응답이 느려지는 문제가 있었다.
LLM_HIDDEN_KEYS = frozenset({"raw_ref_locations", "raw_lines"})


def strip_trace_fields(value: Any) -> Any:
    """raw_ref/raw_refs(인용용)는 남기고 LLM_HIDDEN_KEYS만 재귀적으로 뺀 사본을 만든다."""
    if isinstance(value, dict):
        return {k: strip_trace_fields(v) for k, v in value.items() if k not in LLM_HIDDEN_KEYS}
    if isinstance(value, list):
        return [strip_trace_fields(v) for v in value]
    return value


def observed_references(result: Dict[str, Any]) -> List[str]:
    return list(observed_reference_groups(result))


def observed_reference_groups(result: Dict[str, Any]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for record in result.get("records", []):
        for item in [record, *record.get("nodes", [])]:
            refs = references(item)
            for ref in refs:
                groups[ref] = list(dict.fromkeys(groups.get(ref, []) + refs))
    return groups


def validate_citations(value: Dict[str, Any], known: List[str]) -> tuple[List[str], List[str]]:
    refs = references(value)
    return [ref for ref in refs if ref in known], [ref for ref in refs if ref not in known]


def observed_locations(result: Dict[str, Any]) -> Dict[str, List[str]]:
    locations: Dict[str, List[str]] = {}
    for record in result.get("records", []):
        for item in [record, *record.get("nodes", [])]:
            for ref, sources in item.get("raw_ref_locations", {}).items():
                locations[ref] = list(dict.fromkeys(locations.get(ref, []) + sources))
    return locations


def provenance_report(state: Any) -> Dict[str, Any]:
    evidence = state.evidence + state.contradicting_evidence
    missing = [e.evidence_id for e in evidence if not e.raw_refs]
    issues = list(state.provenance_issues)
    ambiguous = {ref: sources for ref, sources in state.raw_ref_locations.items() if len(sources) > 1}
    status = "passed" if state.raw_refs else "unavailable"
    if issues or missing or ambiguous:
        status = "incomplete"
    return {"status": status, "raw_ref_count": len(state.raw_refs),
            "seed_raw_refs": references(state.seed, seed=True),
            "evidence_without_raw_refs": missing, "ambiguous_raw_refs": ambiguous, "issues": issues}
