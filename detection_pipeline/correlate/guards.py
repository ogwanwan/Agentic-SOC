"""
correlate/guards.py — 오연결 방지 (edge → edge 필터)

edges 를 클러스터로 묶기 '전에' 약한 연결을 거른다.
설계 원칙: "IP만 같거나 시간만 가까운 경우 자동 병합 제한."

현재 규칙:
  1) 중복 edge 제거 (a,b,join 같으면 하나만; 방향 무시)
  2) 자기 자신(a==b) 제거
  3) 약한 join 단독 차단 — WEAK_JOINS 에 든 join 은 탈락(현재 비어 있음)

확장 지점(통합 담당): 한 신호(시간만/IP만)로만 잇는 join 이 생기면 WEAK_JOINS 에 추가하거나,
edge["keys"] 를 보고 신호 개수·강도 기반 규칙을 여기서 강화한다.
"""

# 단독으로는 클러스터 병합을 허용하지 않을 join 이름(예: 향후 "time_only", "ip_only")
WEAK_JOINS = set()

# system_auth 는 pid 단독으로 잇는다(auth.log 에 ses/auid 없음). pid 는 재사용되므로
# 두 이벤트가 이 간격보다 멀면 "같은 세션"이 아니라 다른 시간대의 pid 재사용으로 보고 끊는다.
# (system_auth 링커 설계: "pid 재사용 오연결은 guards 에서 다룬다")
SYSTEM_AUTH_MAX_GAP_SEC = 3600


def _ts_map(events):
    from common.timeparse import parse_utc
    m = {}
    for e in events or []:
        dt = parse_utc(e.get("timestamp"))
        if dt is not None:
            m[e["raw_ref"]] = dt
    return m


def apply_guards(edges, events=None):
    """약한/중복 edge 를 걸러 유효 edge 리스트를 돌려준다."""
    ts = _ts_map(events)
    seen = set()
    out = []
    for e in edges:
        if e["a"] == e["b"]:
            continue
        if e["join"] in WEAK_JOINS:
            continue
        if e["join"] == "system_auth":
            ta, tb = ts.get(e["a"]), ts.get(e["b"])
            if ta is not None and tb is not None and abs((ta - tb).total_seconds()) > SYSTEM_AUTH_MAX_GAP_SEC:
                continue  # pid 재사용(다른 시간대) 오연결 → 끊음
        key = frozenset((e["a"], e["b"])), e["join"]  # 방향 무시 중복 제거
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out
