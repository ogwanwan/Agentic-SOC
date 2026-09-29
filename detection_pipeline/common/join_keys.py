# common/join_keys.py - 조인키 정의

"""
계층 간 사건을 잇는 조인키 정의

  웹↔네트워크 (apache↔suricata): xff/src_ip + 시간근접
  웹↔시스템   (apache↔audit)   : 시간근접 + www-data + pid 계보
  시스템↔인증 (audit↔auth)     : pid 단독
  웹셸 로컬   (audit 내부)      : ppid→pid 계보
  전 계층 정렬축               : timestamp(UTC)

정의(JOIN_RULES 상수) + 실제 판정(함수)로 나눈다.
③ 사건 묶기가 이 함수들을 가져다 쓴다.
값 접근은 schema.get_field로 상단/ layer_data 어디에 있든 꺼낸다.
"""

import os
import sys as _sys
from datetime import datetime

# 스크립트로 직접 실행돼도 레포 루트를 path 에 올려 top-level 패키지(common)를 찾게 한다.
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.lineage import build_process_index  # noqa: E402
from common.schema import get_field  # noqa: E402
from common.timeparse import normalize_iso  # noqa: E402

# --- 정렬축 -----------------------------------------------------------------
SORT_KEY = "timestamp"   # 전 계층 공통, UTC

# --- 조인 규칙(문서화용 상수) -----------------------------------------------
JOIN_RULES = {
    "web_network":    "xff/src_ip + time_proximity",   # X-Request-ID 정밀조인 불가
    "web_system":     "time_proximity + www-data + pid_lineage",  # saddr 조인 폐기
    "system_auth":    "pid",                            # ses/auid 없음 → pid 단독
    "audit_lineage":  "ppid->pid lineage",              # ses unset → 계보로만 (구 webshell_local)
}

WWW_DATA_UID = 33   # www-data


# --- 시간 파싱 헬퍼 ----------------------------------------------------------
def _parse_ts(iso_str):
    """ISO8601(UTC, 'Z' 허용) → aware datetime."""
    return datetime.fromisoformat(normalize_iso(iso_str))


def time_proximity(ev_a, ev_b, seconds=5):
    """두 이벤트 timestamp가 N초 이내인가."""
    diff = abs((_parse_ts(ev_a["timestamp"]) - _parse_ts(ev_b["timestamp"])).total_seconds())
    return diff <= seconds


# --- 1. 웹↔네트워크 (apache↔suricata) ---------------------------------------
def web_network_match(web_ev, net_ev, seconds=5):
    """실 IP(xff/src_ip)가 같고 시간근접이면 연결.

    suricata의 실IP는 http.xff에서 온 src_ip에 담겨 있어야 함(loopback 아님).
    """
    ip_a = web_ev.get("src_ip")
    ip_b = net_ev.get("src_ip")
    if not ip_a or not ip_b:
        return False
    return ip_a == ip_b and time_proximity(web_ev, net_ev, seconds)


# --- 2. 웹↔시스템 (apache↔audit) --------------------------------------------
def web_system_match(web_ev, sys_ev, seconds=5):
    """시간근접 + www-data(uid=33) + (pid 계보는 별도)로 연결.

    saddr 조인은 폐기(inet SOCKADDR 없음). 여기선 시간+www-data까지 확인하고,
    실제 프로세스 계보는 same_process_lineage로 추가 확인한다.
    """
    if get_field(sys_ev, "uid") != WWW_DATA_UID:
        return False
    return time_proximity(web_ev, sys_ev, seconds)


# --- 3. 시스템↔인증 (audit↔auth) --------------------------------------------
def system_auth_match(sys_ev, auth_ev):
    """pid 단독으로 연결 (ses/auid는 auth.log에 없음)."""
    a = sys_ev.get("pid")
    b = auth_ev.get("pid")
    return a is not None and a == b


# --- 4. 웹셸 로컬 (audit 내부, ppid→pid 계보) --------------------------------
def same_process_lineage(ev_a, ev_b, index=None):
    """두 audit 이벤트가 부모-자식 계보인가 (ses unset이라 계보로만 추적).

    pid==ppid 번호만 보면 재부팅·PID 재사용으로 남남을 잇는 오연결이 난다. 그래서
    common/lineage 의 "프로세스 인스턴스"(그 번호를 그 시간 동안 쓴 한 프로세스) 기준으로
    판정한다. 판정 로직은 여기 한 곳(+ lineage 엔진)에만 둔다.

      index : build_process_index(events) 결과. 사건 묶기처럼 이벤트 전체가 있을 때 넘기면
              재부팅 경계(serial 리셋)·PID 재사용(ppid 변경)·시간 역행까지 걸러진다.
      None  : 두 이벤트만으로 임시 인덱스를 만들어 짝 판정한다(기존 호출 호환).
              시간 역행(부모가 자식보다 늦게 등장)은 걸러지지만, 다른 이벤트를 모르므로
              재부팅·재사용은 가를 수 없다.
    """
    if index is None:
        index = build_process_index([ev_a, ev_b])
    inst_a, inst_b = index.instance_for_event(ev_a), index.instance_for_event(ev_b)
    if inst_a is None or inst_b is None:
        return False
    return inst_a.parent_key == inst_b.key or inst_b.parent_key == inst_a.key


# --- 정렬 --------------------------------------------------------------------
def sort_events(events):
    """전 계층 공통 정렬축(timestamp UTC)으로 정렬."""
    return sorted(events, key=lambda e: e["timestamp"])


if __name__ == "__main__":
    web = {"timestamp": "2026-09-07T15:34:45Z", "src_ip": "54.180.11.0",
           "layer": "web", "layer_data": {}}
    sysev = {"timestamp": "2026-09-07T15:34:47Z", "src_ip": None,
             "pid": 239001, "ppid": 233915, "layer": "system",
             "layer_data": {"uid": 33}}
    child = {"timestamp": "2026-09-07T15:34:48Z", "pid": 240000, "ppid": 239001,
             "layer": "system", "layer_data": {"uid": 33}}

    assert web_system_match(web, sysev)          # 시간근접 + uid 33
    assert same_process_lineage(sysev, child)    # 239001 → 240000 계보
    print("join_keys.py OK")