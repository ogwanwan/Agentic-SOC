"""correlate/links/audit_lineage.py 단위 테스트 (민혁 파트).

실행: python correlate/tests/test_audit_lineage.py
엔진(common/lineage.py) 자체 테스트는 tests/test_lineage.py 에 따로 있다. 여기선 edge 계약과
오연결 방지(재부팅·PID 재사용·시간 역행)가 링크 출력에서 지켜지는지만 본다.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.links.audit_lineage import JOIN, audit_lineage_edges
from correlate.registry import LINKERS
from tools.fetch_audit_log import fetch_audit_log

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_AUDIT = os.path.join(REPO, "tools", "sample_audit.log")


def _sys(raw_ref, ts, pid, ppid, serial, uid=33, comm="sh"):
    return {"timestamp": ts, "layer": "system", "raw_ref": raw_ref, "src_ip": None,
            "pid": pid, "ppid": ppid,
            "layer_data": {"serial": serial, "uid": uid, "comm": comm, "syscall": "execve"}}


def _pairs(edges):
    return {(e["a"], e["b"]) for e in edges}


def _run():
    # 0) registry 자동 등록
    assert audit_lineage_edges in LINKERS, "@register_linker 등록 실패"

    # 1) 샘플 audit 로그: php-fpm(1200) → sh(5310), php-fpm → sudo(5320) → useradd(5501)
    events = fetch_audit_log(SAMPLE_AUDIT)
    edges = audit_lineage_edges(events)
    assert _pairs(edges) == {
        ("sample_audit.log:6", "sample_audit.log:11"),    # php-fpm → sh
        ("sample_audit.log:6", "sample_audit.log:16"),    # php-fpm → sudo
        ("sample_audit.log:16", "sample_audit.log:21"),   # sudo → useradd (uid 33 → 0, 권한 상승도 연결)
    }, _pairs(edges)
    for e in edges:                                       # tail(3839)·cron(6000) 은 어디에도 없음
        assert "sample_audit.log:1" not in (e["a"], e["b"]) and "sample_audit.log:26" not in (e["a"], e["b"])

    # 2) edge 계약: a/b 는 raw_ref, join 이름, keys 근거
    e = next(x for x in edges if x["b"] == "sample_audit.log:21")
    assert e["join"] == JOIN == "audit_lineage"
    assert e["keys"]["parent_pid"] == 5320 and e["keys"]["child_pid"] == 5501
    assert isinstance(e["keys"]["dt_sec"], float) and e["keys"]["dt_sec"] > 0
    assert all(isinstance(x["a"], str) and isinstance(x["b"], str) for x in edges)

    # 3) 다른 계층 이벤트가 섞여도 무시, 순서를 섞어도 동일
    mixed = events + [
        {"timestamp": "2026-09-14T23:45:11.000Z", "layer": "web", "raw_ref": "apache_access.log:10",
         "src_ip": "1.2.3.4", "pid": None, "ppid": None, "layer_data": {}},
        {"timestamp": "2026-09-14T23:45:12.000Z", "layer": "auth", "raw_ref": "auth.log:30",
         "src_ip": None, "pid": 5310, "ppid": None, "layer_data": {}},
    ]
    assert audit_lineage_edges(mixed) == edges
    shuffled = list(mixed)
    random.Random(42).shuffle(shuffled)
    assert audit_lineage_edges(shuffled) == edges, "입력 순서에 따라 결과가 달라짐"

    # 4) 재부팅 경계: serial 리셋 후 같은 pid 는 남남
    T = "2026-09-14T23:45:%06.3fZ"
    reboot = [
        _sys("a.log:1", T % 0.0, 1200, 1000, serial=90000, comm="php-fpm"),
        _sys("a.log:2", T % 1.0, 5310, 1200, serial=90001),
        _sys("a.log:3", T % 10.0, 5310, 4000, serial=5, comm="cron"),      # 재부팅 후 재사용
        _sys("a.log:4", T % 11.0, 6001, 5310, serial=6, comm="curl"),
    ]
    p = _pairs(audit_lineage_edges(reboot))
    assert ("a.log:1", "a.log:2") in p and ("a.log:3", "a.log:4") in p, p
    assert ("a.log:2", "a.log:4") not in p and ("a.log:1", "a.log:3") not in p, "재부팅 넘어 오연결"

    # 5) 같은 부팅 내 PID 재사용: 자식은 자기 시각에 살아 있던 인스턴스에만
    reuse = [
        _sys("a.log:1", T % 0.0, 1200, 1000, serial=1, comm="php-fpm"),
        _sys("a.log:2", T % 5.0, 5310, 1200, serial=2, comm="sh"),        # 5310-A
        _sys("a.log:3", T % 6.0, 9001, 5310, serial=3, comm="curl"),      # A 의 자식
        _sys("a.log:4", T % 30.0, 5310, 7000, serial=4, comm="sleep"),    # 5310-B
        _sys("a.log:5", T % 31.0, 9002, 5310, serial=5, comm="cat"),      # B 의 자식
    ]
    p = _pairs(audit_lineage_edges(reuse))
    assert p == {("a.log:1", "a.log:2"), ("a.log:2", "a.log:3"), ("a.log:4", "a.log:5")}, p

    # 6) 시간 역행 부모(자식보다 10초 뒤 첫 등장) → 연결 안 함
    late = [
        _sys("a.log:1", T % 0.0, 5310, 1200, serial=1),
        _sys("a.log:2", T % 10.0, 1200, 1000, serial=2, comm="php-fpm"),
    ]
    assert audit_lineage_edges(late) == [], "시간 역행 부모 오연결"

    # 7) 같은 프로세스의 exec 체인(sh→curl)은 edge 를 늘리지 않고, 부모 raw_ref 는 자식 직전 관측
    chain = [
        _sys("a.log:1", T % 0.0, 1200, 1000, serial=1, comm="php-fpm"),
        _sys("a.log:2", T % 1.0, 5310, 1200, serial=2, comm="sh"),
        _sys("a.log:3", T % 1.5, 5310, 1200, serial=3, comm="curl"),      # 같은 5310 이 curl 로 exec
        _sys("a.log:4", T % 2.0, 9001, 5310, serial=4, comm="wget"),      # 5310 의 자식
    ]
    edges = audit_lineage_edges(chain)
    assert _pairs(edges) == {("a.log:1", "a.log:2"), ("a.log:3", "a.log:4")}, _pairs(edges)

    # 8) system 이벤트가 없으면 빈 리스트
    assert audit_lineage_edges([]) == [] and audit_lineage_edges([mixed[-1]]) == []

    print("test_audit_lineage OK →", audit_lineage_edges(events))


if __name__ == "__main__":
    _run()
