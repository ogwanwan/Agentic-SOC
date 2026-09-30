"""
correlate/links/web_system.py — Apache↔Audit 연결 (담당: 지원)

계층쌍: 웹(apache) ↔ 시스템(audit)
연결 키: 시간 근접 + www-data(uid=33).
  apache 이벤트엔 pid가 없어(웹 계층) IP/pid 조인이 불가하다. 그래서 "같은 시간대에 웹서버
  계정(www-data)이 낸 audit 활동"을 apache 요청과 잇는 진입(entry) edge를 만든다.

역할 경계 (왜 계보를 여기서 안 하나):
  - 이 파일은 apache → audit '진입 edge'만 만든다.
  - PID 계보(PPID→PID)로 자식 프로세스(웹셸→셸→curl)까지 잇는 건 audit_lineage(민혁)가 담당한다.
  - grouping(통합)이 [web_system edge] + [audit_lineage edge]를 합쳐, apache → www-data audit →
    그 자식 프로세스들을 하나의 사건으로 전이(transitive) 연결한다. 여기서 계보를 또 하면 중복.

판정 predicate 는 common/join_keys.web_system_match 를 재사용한다(로직 한 곳, 중복 금지).

edge 계약(전 계층쌍 공통 — 지원이 먼저 제안, 팀 정렬용):
  {
    "a":   "<raw_ref_web>",     # 한쪽 이벤트의 원본 포인터(= XAI 역추적 ID)
    "b":   "<raw_ref_audit>",   # 다른쪽 이벤트
    "join":"web_system",        # 어떤 규칙으로 이었나 → grouping이 join_path에 기록
    "keys":{"dt_sec":..,"uid":..}  # 연결 근거(시간차·uid) → 오연결 방지/디버깅
  }
"""

import os
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from bisect import bisect_left, bisect_right
from datetime import timedelta

from common.join_keys import web_system_match, _parse_ts
from common.schema import get_field
from correlate.registry import register_linker

JOIN = "web_system"


def _dt_sec(a, b):
    """두 이벤트 timestamp 시간차(초). 근거(keys)에 싣는다."""
    return abs((_parse_ts(a["timestamp"]) - _parse_ts(b["timestamp"])).total_seconds())


@register_linker
def web_system_edges(events, seconds=5):
    """events(web+system 혼재) → apache↔audit 진입 edge 리스트.

    web 이벤트마다, 시간 ±seconds 이내이고 uid==www-data(33) 인 audit 이벤트를 후보로 잇는다.
    1:1로 강제하지 않는다 — "묶일 수 있는 후보"는 넉넉히 만들고(코드), "이게 한 공격인가"의
    최종 판정은 grouping/guards·조사 단계에 맡긴다(설계 원칙: 연결≠해석).

    성능: 예전엔 web×system 전수 비교(O(n²), 실로그에서 2억 회)였다. 매칭은 시간 ±seconds
    창이 필수 조건이므로 system 을 시각으로 정렬해두고 web 마다 bisect 로 창 범위만 훑는다.
    창 안 후보에만 web_system_match(uid==33 포함)를 적용 → 결과 edge 는 전수 비교와 동일.

    결정과 근거:
      · www-data(uid 33)만 대상    → apache 요청이 유발하는 건 웹서버 계정 활동. 관리자(root) audit 제외.
      · 시간창 기본 ±5초(파라미터)  → nginx→apache→php-fpm 처리 지연은 흡수하되 넓히면 오연결.
      · 계보 확장은 안 함           → audit_lineage(민혁) 담당. 역할 경계 유지.
    """
    # system 을 (시각, 이벤트) 로 정렬 — 시각 파싱 실패건은 제외(정렬축 없음).
    sys_sorted = sorted(
        ((t, s) for s in events if s.get("layer") == "system"
         for t in (_parse_ts(s["timestamp"]),) if t is not None),
        key=lambda p: p[0],
    )
    sys_times = [t for t, _ in sys_sorted]

    edges = []
    for w in events:
        if w.get("layer") != "web":
            continue
        wt = _parse_ts(w["timestamp"])
        if wt is None:
            continue
        lo = bisect_left(sys_times, wt - timedelta(seconds=seconds))
        hi = bisect_right(sys_times, wt + timedelta(seconds=seconds))
        for _t, s in sys_sorted[lo:hi]:
            if web_system_match(w, s, seconds):   # 시간근접 + uid==33 (join_keys)
                edges.append({
                    "a": w["raw_ref"],
                    "b": s["raw_ref"],
                    "join": JOIN,
                    "keys": {"dt_sec": round(_dt_sec(w, s), 3), "uid": get_field(s, "uid")},
                })
    return edges


if __name__ == "__main__":
    # 최소 데모 (파일 없이)
    web = {"timestamp": "2026-09-11T02:00:03.000Z", "layer": "web",
           "raw_ref": "apache_access.log:10", "src_ip": "1.2.3.4",
           "layer_data": {"method": "POST", "path": "/uploads/shell.php"}}
    audit = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
             "raw_ref": "audit.log:20", "pid": 1301, "ppid": 1200,
             "layer_data": {"uid": 33, "user": "www-data", "comm": "sh"}}
    print(web_system_edges([web, audit]))
