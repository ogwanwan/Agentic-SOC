"""조사 입력 — 1차 탐지가 넘긴 사건(Incident)을 읽어 조사 루프가 쓰는 사건 dict로 바꾼다.

역할
  load_incidents(): 사건 파일(JSON 객체·배열 또는 한 줄에 한 건인 JSONL)을 읽는다.
  to_investigation_seed(): 1차 탐지 Incident(entity·window·seeds·members …)를 조사 루프가 읽는
    필드(src_ip, host, window, trigger_time, evidence_refs, trigger_description …)로 옮긴다.
    조사 루프 안에서는 이 dict를 계속 "seed"라고 부른다(1차 탐지의 seeds[] = 탐지 룰 결과와 다른 뜻).

  1차 탐지 필드 중 바뀔 가능성이 적은 것(incident_id, entity, window, layers, seeds[]의
  reason·evidence_refs·rule_severity·detail)만 쓴다. 어떤 사건을 조사할지(triage_score, priority,
  route, llm_investigate, 조사 상태)는 1차 탐지·사건 저장소 쪽에서 고른 뒤 넘긴다고 보고 여기서는 보지 않는다.
  llm_reason이 있으면 첫 단서로 함께 넘기고, 없어도 동작한다.

누가 부르나
  [4] main.py main()                          → load_incidents()
  [6] agent/pipeline.py run_investigation_pipeline() → to_investigation_seed()

무엇을 부르나
  없음 (표준 라이브러리만)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

SEVERITY_ORDER = ("low", "medium", "high", "critical")
# 프롬프트에 사건 dict가 통째로 들어가므로 1차 탐지 결과는 요약만 싣는다(members는 최대 500개).
MAX_DETECTIONS = 20
MAX_FALLBACK_REFS = 50


def load_incidents(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """사건 파일을 읽어 사건 dict 리스트로 돌려준다. JSON 객체 하나, JSON 배열, JSONL을 받는다."""
    text = Path(path).read_text(encoding="utf-8-sig")
    try:
        data = json.loads(text)
        items = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
    for number, item in enumerate(items, start=1):
        if not isinstance(item, dict) or not item.get("incident_id"):
            raise ValueError(f"{path}: {number}번째 사건에 incident_id가 없습니다")
    return items


def _unique(values: List[Any]) -> List[Any]:
    return list(dict.fromkeys(v for v in values if v))


def _src_ip(entity: Dict[str, Any], detections: List[Dict[str, Any]]) -> Optional[str]:
    """대표 entity가 IP면 그 값, 아니면(pid 사건) 탐지 결과 중 IP entity가 있으면 그 값."""
    for candidate in [entity, *(d.get("entity") or {} for d in detections)]:
        if candidate.get("type") == "src_ip" and candidate.get("value"):
            return str(candidate["value"])
    return None


def _severity(detections: List[Dict[str, Any]]) -> Optional[str]:
    levels = [(d.get("score_parts") or {}).get("rule_severity") for d in detections]
    ranked = [SEVERITY_ORDER.index(level) for level in levels if level in SEVERITY_ORDER]
    return SEVERITY_ORDER[max(ranked)].upper() if ranked else None


def _join_types(join_path: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for edge in join_path:
        if edge.get("join"):
            counts[edge["join"]] = counts.get(edge["join"], 0) + 1
    return counts


# [6] ← agent/pipeline.py [5]에서 사건마다 호출
def to_investigation_seed(incident: Dict[str, Any], host: Optional[str] = None) -> Dict[str, Any]:
    """1차 탐지 Incident → 조사 루프 입력. 이미 조사 입력 형식(entity·seeds 없음)이면 host만 채운다."""
    if "entity" not in incident and "seeds" not in incident:
        # 직접 작성한 사건 파일(scenarios/, tests/test_consistency.py --seed-json)은 그대로 쓴다
        seed = dict(incident)
        if host and not seed.get("host"):
            seed["host"] = host
        return seed

    detections = [d for d in incident.get("seeds") or [] if isinstance(d, dict)]
    entity = incident.get("entity") or {}
    window = list(incident.get("window") or [])
    # 탐지 근거(seeds[].evidence_refs)가 원본 참조다. 탐지 없이 묶인 사건만 members 일부로 대신한다.
    refs = _unique([ref for d in detections for ref in d.get("evidence_refs") or []])
    if not refs:
        refs = _unique(list(incident.get("members") or []))[:MAX_FALLBACK_REFS]
    event_times = sorted(_unique([(d.get("detail") or {}).get("timestamp") for d in detections]))
    reasons = _unique([d.get("reason") for d in detections])

    seed: Dict[str, Any] = {
        "incident_id": incident["incident_id"],
        "host": incident.get("host") or host,
        "src_ip": _src_ip(entity, detections),
        "window": window,
        "trigger_time": event_times[0] if event_times else (window[0] if window else None),
        "evidence_refs": refs,
        "trigger_description": " / ".join(reasons) or "1차 탐지 사건",
        "severity_hint": _severity(detections),
        "detection": {
            "entity": entity,
            "layers": incident.get("layers") or [],
            "member_count": incident.get("member_count"),
            "oversized": incident.get("oversized", False),
            "join_types": _join_types(incident.get("join_path") or []),
            "rules": [
                {
                    "rule_name": d.get("rule_name"),
                    "reason": d.get("reason"),
                    "layer": d.get("layer"),
                    "severity": (d.get("score_parts") or {}).get("rule_severity"),
                    "evidence_refs": d.get("evidence_refs") or [],
                    "detail": d.get("detail") or {},
                }
                for d in detections[:MAX_DETECTIONS]
            ],
        },
    }
    if incident.get("llm_reason"):
        seed["llm_reason"] = incident["llm_reason"]
    if incident.get("incident_key"):
        seed["incident_key"] = incident["incident_key"]
    return seed
