"""correlate/links/system_auth.py 단위 테스트-지희"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.links.system_auth import system_auth_edges


def _run():
    audit_match = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
                   "raw_ref": "audit.log:20", "pid": 1400, "ppid": 1301,
                   "layer_data": {"uid": 33, "user": "www-data", "comm": "curl"}}
    auth_match = {"timestamp": "2026-09-11T02:00:06.000Z", "layer": "auth",
                  "raw_ref": "auth.log:30", "pid": 1400, "ppid": None,
                  "layer_data": {"event": "sudo_command", "user": "root", "src_user": "www-data"}}
    auth_other_pid = {"timestamp": "2026-09-11T02:00:06.000Z", "layer": "auth",
                      "raw_ref": "auth.log:31", "pid": 9999, "ppid": None,
                      "layer_data": {"event": "sudo_command"}}
    audit_no_pid = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
                    "raw_ref": "audit.log:22", "pid": None, "ppid": None,
                    "layer_data": {"uid": 33}}
    web_ev = {"timestamp": "2026-09-11T02:00:03.000Z", "layer": "web",
              "raw_ref": "apache_access.log:10", "src_ip": "1.2.3.4",
              "pid": 1400, "ppid": None, "layer_data": {}}

    edges = system_auth_edges([audit_match, auth_match, auth_other_pid, audit_no_pid, web_ev])
    pairs = {(e["a"], e["b"]) for e in edges}

    # 1) pid 같으면 연결
    assert ("audit.log:20", "auth.log:30") in pairs, "pid 일치 연결 실패"
    # 2) pid 다르면 제외
    assert ("audit.log:20", "auth.log:31") not in pairs, "pid 불일치 오연결"
    # 3) pid 없는 audit 이벤트는 아무 edge 도 안 낳음
    assert not any(e["a"] == "audit.log:22" for e in edges), "pid 없는 이벤트 오연결"
    # 4) web 계층은 대상이 아님 (system/auth 만 봄)
    assert not any("apache_access.log:10" in (e["a"], e["b"]) for e in edges), "web 계층 오연결"
    # 5) edge 계약 형태 확인
    e = next(x for x in edges if x["b"] == "auth.log:30")
    assert e["join"] == "system_auth" and e["keys"]["pid"] == 1400

    print("test_system_auth OK →", edges)


if __name__ == "__main__":
    _run()
