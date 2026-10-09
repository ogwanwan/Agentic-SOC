import os
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.network import canonical_ip, raw_path_and_query
from common.timeparse import parse_utc
from correlate.registry import register_linker

JOIN = "web_session"
DEFAULT_SECONDS = 120.0


@register_linker
def web_session_edges(events, seconds=DEFAULT_SECONDS):
    """web 이벤트 → 같은 (src_ip, path) 세션의 연속 요청끼리 잇는 edge 리스트.

    같은 출발지 IP가 같은 경로(쿼리 제외)를 호출한 web 이벤트를 시각순 정렬하고,
    연속 요청 간격이 seconds 이내면 서로 잇는다(체인). union-find가 체인을 전이 연결해
    세션 전체가 한 클러스터가 된다. 성능: (src_ip, path) 그룹 내 인접쌍만 보므로 O(n log n).
    """
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError("seconds는 0 이상의 숫자여야 함")
    if seconds < 0:
        raise ValueError("seconds는 0 이상이어야 함")

    # (src_ip, path) 그룹 수집 — src_ip/path/timestamp 중 하나라도 없으면 세션 키 불가 → 제외.
    groups = {}
    for e in events:
        if not isinstance(e, dict) or e.get("layer") != "web":
            continue
        raw_ref = e.get("raw_ref")
        if raw_ref in (None, ""):
            continue
        ip = canonical_ip(e.get("src_ip"))
        ts = parse_utc(e.get("timestamp"))
        path = raw_path_and_query((e.get("layer_data") or {}).get("path"))[0]
        if ip is None or ts is None or not path:
            continue
        groups.setdefault((ip, path), []).append((ts, str(raw_ref)))

    edges = []
    for (ip, path), items in groups.items():
        items.sort(key=lambda p: (p[0], p[1]))
        for (t_prev, ref_prev), (t_cur, ref_cur) in zip(items, items[1:]):
            if ref_prev == ref_cur:
                continue
            gap = (t_cur - t_prev).total_seconds()
            if gap <= seconds:
                edges.append({
                    "a": ref_prev,
                    "b": ref_cur,
                    "join": JOIN,
                    "keys": {"src_ip": ip, "path": path, "dt_sec": round(gap, 3)},
                })
    return edges
