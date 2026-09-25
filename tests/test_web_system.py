"""correlate/links/web_system.py 단위 테스트 (지원 파트)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.links.web_system import web_system_edges


def _run():
    web = {"timestamp": "2026-09-11T02:00:03.000Z", "layer": "web",
           "raw_ref": "apache_access.log:10", "src_ip": "1.2.3.4",
           "layer_data": {"method": "POST", "path": "/uploads/shell.php"}}
    audit_www = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
                 "raw_ref": "audit.log:20", "pid": 1301, "ppid": 1200,
                 "layer_data": {"uid": 33, "user": "www-data", "comm": "sh"}}
    audit_root = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
                  "raw_ref": "audit.log:21", "pid": 999, "ppid": 1,
                  "layer_data": {"uid": 0, "user": "root", "comm": "cron"}}
    audit_far = {"timestamp": "2026-09-11T02:05:30.000Z", "layer": "system",
                 "raw_ref": "audit.log:22", "pid": 1400, "ppid": 1200,
                 "layer_data": {"uid": 33}}

    edges = web_system_edges([web, audit_www, audit_root, audit_far], seconds=5)
    pairs = {(e["a"], e["b"]) for e in edges}

    # 1) www-data 근접 → 연결
    assert ("apache_access.log:10", "audit.log:20") in pairs, "www-data 근접 연결 실패"
    # 2) root(uid 0) → 제외
    assert ("apache_access.log:10", "audit.log:21") not in pairs, "root audit 오연결"
    # 3) 5분 밖 → 제외
    assert ("apache_access.log:10", "audit.log:22") not in pairs, "시간창 밖 오연결"
    # 4) edge 계약 형태 확인
    e = next(x for x in edges if x["b"] == "audit.log:20")
    assert e["join"] == "web_system" and e["keys"]["uid"] == 33 and "dt_sec" in e["keys"]

    print("test_web_system OK →", edges)


if __name__ == "__main__":
    _run()
