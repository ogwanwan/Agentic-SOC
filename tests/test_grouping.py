"""correlate/grouping.py 통합 테스트 — 이벤트+seed → Incident 조립."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.grouping import correlate


def _run():
    web = {"timestamp": "2026-09-11T02:00:03.000Z", "layer": "web",
           "raw_ref": "apache_access.log:10", "src_ip": "45.9.1.2",
           "layer_data": {"method": "POST", "path": "/uploads/shell.php"}}
    audit_www = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
                 "raw_ref": "audit.log:20", "pid": 1301, "ppid": 1200,
                 "layer_data": {"uid": 33, "user": "www-data", "comm": "sh"}}
    audit_root = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
                  "raw_ref": "audit.log:99", "pid": 999, "ppid": 1,
                  "layer_data": {"uid": 0, "user": "root", "comm": "cron"}}
    seed = {"entity": {"type": "src_ip", "value": "45.9.1.2"},
            "window": ["2026-09-11T02:00:00Z", "2026-09-11T02:01:00Z"], "layer": "web",
            "source": ["sigma"], "reason": "웹셸 업로드", "signal_tags": ["webroot"],
            "evidence_refs": ["apache_access.log:10"]}

    incidents = correlate([web, audit_www, audit_root], [seed])

    # web + www-data audit 이 한 사건으로 묶여야(root는 uid 0이라 edge 없음 → 별도 아님)
    web_sys = [i for i in incidents if set(i["layers"]) == {"web", "system"}]
    assert len(web_sys) == 1, "web↔system 사건 1건 기대: %r" % incidents
    inc = web_sys[0]
    assert set(inc["members"]) == {"apache_access.log:10", "audit.log:20"}, inc["members"]
    assert inc["join_path"] and inc["join_path"][0]["join"] == "web_system"
    assert inc["seeds"] and inc["seeds"][0]["evidence_refs"] == ["apache_access.log:10"]
    assert inc["entity"] == {"type": "src_ip", "value": "45.9.1.2"}
    # root audit 은 아무 edge 없음 → 사건에 안 들어감
    assert "audit.log:99" not in inc["members"]

    print("test_grouping OK →", inc["incident_id"], inc["layers"], inc["members"])


if __name__ == "__main__":
    _run()
