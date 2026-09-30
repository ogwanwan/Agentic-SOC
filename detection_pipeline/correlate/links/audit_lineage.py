"""
correlate/links/audit_lineage.py — Audit 내부 PPID→PID 계보 연결 (담당: 민혁)

계층쌍: 시스템(audit) ↔ 시스템(audit)  — 같은 계층 안의 부모-자식 프로세스
연결 키: ppid→pid 계보.
  audit.log 에는 IP 도, 로그인 세션(ses)도 없다(웹셸은 auid unset). 따라서 "php-fpm 이 sh 를,
  sh 가 curl 을 실행했다"를 이을 유일한 단서는 앞 이벤트의 pid 가 뒤 이벤트의 ppid 로
  이어지는 계보뿐이다(JOIN_RULES["audit_lineage"]).

왜 번호만 비교하면 안 되나:
  pid 는 번호표처럼 재사용된다(종료 후 재할당, 재부팅 시 1부터). 번호만 이으면 아침의 cron 과
  저녁의 웹셸이 부모-자식으로 엮인다. 그래서 common/lineage.build_process_index 가 만드는
  "프로세스 인스턴스"(그 번호를 그 시간 동안 쓴 한 프로세스) 사이의 부모-자식만 edge 로 낸다.
  재부팅 경계(serial 리셋)·같은 부팅 내 재사용(ppid 변경)·시간 역행 부모는 거기서 걸러진다.

역할 경계:
  - 이 파일은 부모→자식 '한 단계' edge 만 만든다. 조상/자손 트리를 여기서 조립하지 않는다.
  - grouping(통합)의 union-find 가 [web_system edge] + [audit_lineage edge] + [system_auth edge]
    를 이어 apache → www-data audit → 자식 프로세스들 → auth 세션을 하나의 사건으로 전이
    (transitive) 연결한다. 여기서 트리를 또 만들면 중복.
  - uid 는 조건으로 쓰지 않는다. sudo(uid 33) → useradd(uid 0) 같은 권한 상승은 정상 계보이면서
    가장 중요한 탐지 신호라, 걸면 잡아야 할 것을 끊는다. www-data 진입 판정은 web_system 담당.

판정 predicate 는 common/join_keys.same_process_lineage 를 재사용한다(로직 한 곳, 중복 금지).
인덱스는 여기서 한 번 만들어 넘긴다 — 두 이벤트만 넘기면 재부팅·재사용을 가를 수 없기 때문.

edge 계약(전 계층쌍 공통):
  {
    "a":   "<raw_ref_parent>",  # 부모 프로세스 이벤트(자식 직전 관측)의 원본 포인터
    "b":   "<raw_ref_child>",   # 자식 프로세스 이벤트(첫 관측)
    "join":"audit_lineage",     # 어떤 규칙으로 이었나 → grouping 이 join_path 에 기록
    "keys":{"parent_pid":..,"child_pid":..,"dt_sec":..}  # 연결 근거 → 오연결 방지/디버깅
  }
"""

import os
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.join_keys import same_process_lineage
from common.lineage import build_process_index, parse_ts
from correlate.registry import register_linker

JOIN = "audit_lineage"


def _parent_event_before(parent_inst, child_inst):
    """부모 인스턴스 관측 중 자식이 태어나기 직전(또는 같은 시각)의 것. 없으면 첫 관측."""
    chosen = None
    for ev in parent_inst.events:
        ts = parse_ts(ev.get("timestamp"))
        if ts is not None and ts <= child_inst.first_seen:
            chosen = ev
        else:
            break
    return chosen if chosen is not None else parent_inst.events[0]


def _dt_sec(parent_ev, child_ev):
    a, b = parse_ts(parent_ev.get("timestamp")), parse_ts(child_ev.get("timestamp"))
    if a is None or b is None:
        return None
    return round((b - a).total_seconds(), 3)


@register_linker
def audit_lineage_edges(events):
    """events(4계층 혼재) → audit 부모→자식 edge 리스트.

    system 이벤트만 골라 프로세스 인스턴스 인덱스를 만들고, 부모가 확인된 인스턴스마다
    (부모 이벤트, 자식 이벤트) 한 쌍을 edge 로 낸다. 입력 순서와 무관하게 같은 결과.

    결정과 근거:
      · 인스턴스 단위 edge   → 같은 프로세스가 여러 번 관측돼도(sh→curl exec 체인) edge 는 1개.
                              부모 쪽 raw_ref 는 자식 직전 관측, 자식 쪽은 첫 관측을 쓴다.
      · raw_ref 없는 이벤트  → edge 계약상 a/b 는 raw_ref 여야 하므로 제외.
      · 부모 미관측(php-fpm 의 부모 1000 등) → edge 없음. 오류 아님(관측 기반이라는 한계).
    """
    systems = [e for e in events if isinstance(e, dict) and e.get("layer") == "system"]
    if not systems:
        return []
    index = build_process_index(systems)

    edges = []
    for key in sorted(index.instances):
        child = index.instances[key]
        parent = index.parent_of(child)
        if parent is None:
            continue
        parent_ev = _parent_event_before(parent, child)
        child_ev = child.events[0]
        if not same_process_lineage(parent_ev, child_ev, index):   # 판정: join_keys 재사용
            continue
        a, b = parent_ev.get("raw_ref"), child_ev.get("raw_ref")
        if not a or not b:
            continue
        edges.append({
            "a": a,
            "b": b,
            "join": JOIN,
            "keys": {
                "parent_pid": parent.pid,
                "child_pid": child.pid,
                "dt_sec": _dt_sec(parent_ev, child_ev),
            },
        })
    return edges


if __name__ == "__main__":
    # 최소 데모 (파일 없이): php-fpm(1200) → sh(1301) → curl(1400)
    php = {"timestamp": "2026-09-11T02:00:00.000Z", "layer": "system", "raw_ref": "audit.log:19",
           "pid": 1200, "ppid": 1000, "layer_data": {"serial": 1, "uid": 33, "comm": "php-fpm"}}
    sh = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system", "raw_ref": "audit.log:20",
          "pid": 1301, "ppid": 1200, "layer_data": {"serial": 2, "uid": 33, "comm": "sh"}}
    curl = {"timestamp": "2026-09-11T02:00:05.000Z", "layer": "system", "raw_ref": "audit.log:21",
            "pid": 1400, "ppid": 1301, "layer_data": {"serial": 3, "uid": 33, "comm": "curl"}}
    for e in audit_lineage_edges([curl, php, sh]):
        print(e)
