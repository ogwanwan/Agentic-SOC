"""
triage/triage.py — 결정론 스코어 게이트 (④ 트리아지)

결정론 파이프라인이 낸 Incident(correlate/incident.py)에 우선순위 점수를 매겨, 상위만 LLM 조사로
넘기고 나머지는 대시보드/보류로 라우팅한다. 판단이 아니라 정렬·필터 — 같은 입력 → 같은 순위(재현 가능).

점수는 전부 Incident에 이미 있는 필드로만 계산한다(외부 판단/LLM 없음):
  · 심각도   : seed.score_parts.rule_severity 최댓값 (주축)
  · 계층 수  : len(layers)          — 다계층=공격체인 진행 신호
  · 연결 종류: join_path의 join 종류 수 — 계보/교차 연결
  · seed 수  : 소폭 가산(상한)
member_count/oversized 는 점수에 쓰지 않는다("큰 것 ≠ 위험"). 최신성(now 기준)은 재현성과 충돌해 제외.
"""

SEVERITY_SCORE = {"critical": 40, "high": 25, "medium": 10, "low": 3}  # None → 0

# 점수 구간 → (priority, route). LLM 조사는 P1~P2 만.
_ROUTES = (
    (40, "P1", "investigate"),
    (20, "P2", "investigate"),
    (8,  "P3", "dashboard"),
    (0,  "P4", "hold"),
)


def _severity_points(incident):
    best = 0
    for s in incident.get("seeds", []) or []:
        sev = (s.get("score_parts") or {}).get("rule_severity")
        best = max(best, SEVERITY_SCORE.get(sev, 0))
    return best


def triage_score(incident):
    """Incident → (score:int, parts:dict). parts 는 요소별 기여분(왜 이 점수 — XAI)."""
    seeds = incident.get("seeds", []) or []
    parts = {
        "severity": _severity_points(incident),
        "layers": 10 * len(set(incident.get("layers", []) or [])),
        "join_types": 5 * len({e.get("join") for e in incident.get("join_path", []) or []}),
        "seed_count": min(2 * (len(seeds) - 1), 10) if seeds else 0,
    }
    return sum(parts.values()), parts


def route(score):
    """score → (priority, route)."""
    for threshold, priority, dest in _ROUTES:
        if score >= threshold:
            return priority, dest
    return "P4", "hold"


def triage(incidents):
    """Incident 리스트 → triage_score·priority·route·triage_parts 를 덧붙여 점수 내림차순 정렬.

    원본 증거(members/join_path/seeds)는 변형하지 않는다(얕은 복사 후 필드만 추가).
    """
    out = []
    for inc in incidents:
        score, parts = triage_score(inc)
        priority, dest = route(score)
        enriched = dict(inc)
        enriched["triage_score"] = score
        enriched["priority"] = priority
        enriched["route"] = dest
        enriched["triage_parts"] = parts
        out.append(enriched)
    out.sort(key=lambda i: (-i["triage_score"], i.get("incident_id") or ""))
    return out
