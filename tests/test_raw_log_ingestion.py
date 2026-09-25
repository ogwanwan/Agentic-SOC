"""fetch_recent_raw_logs(agent/raw_log_ingestion.py) 단독 테스트.

실제 AWS 없이, 임시 로그 파일을 <계층>_LOG_LOCAL_PATH로 지정해(tests/_log_files.py)
- audit 소스는 primary_detection.normalizer.tools.fetch_audit_log의 fetch_audit_log()로
  정규화된 이벤트가 되는지 (2026-09-22: audit_parser.py 대신 normalizer 기반으로 교체)
- web 소스는 primary_detection.normalizer.tools.fetch_apache_log의 fetch_apache_log()로
  정규화된 이벤트가 되는지 (2026-09-22: nginx_json_parser.py 대신 apache access.log
  정규화로 교체 — 조사 도구 fetch_web_log.py와 동일 코드)
- network 소스도 primary_detection.normalizer.tools.fetch_network_log의
  fetch_network_log()로 정규화되는지 (2026-09-22: network_parser.py 대신 정규화 함수로 교체
  — 조사 도구 fetch_network_log.py와 동일 코드)
- 여러 source_type(web/auth/audit/network)을 다 훑는지
- 비어 있는 로그 파일은 에러 없이 0건으로 건너뛰는지
- 시각과 무관하게 파일 끝 RAW_LOG_LOCAL_MAX_LINES건만 남기는지 (S3 삭제 뒤 수집은 로컬 파일만 읽는다)
- 각 레코드에 _source_type이 붙는지
를 검증한다.
"""

from __future__ import annotations

import os
import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from tests._log_files import install_log_files, uninstall_log_files

# normalizer 벤더 코드가 import 시점에 load_dotenv()를 호출하는 문제 회피
# (tests/test_fetch_auth_log.py 상단 주석 참고 — 2026-09-22 C 작업으로 이 모듈도
# normalizer.tools.fetch_auth_log/fetch_audit_log를 직접 import하게 되면서 같은
# 영향을 받는다. 2026-09-22 오후: web/network도 같은 이유로 추가됨).
import agent.raw_log_ingestion as _load_dotenv_trigger  # noqa: F401
for _env_name in ("AUTH_LOG_LOCAL_PATH", "AUDIT_LOG_LOCAL_PATH", "WEB_LOG_LOCAL_PATH", "NETWORK_LOG_LOCAL_PATH"):
    os.environ.pop(_env_name, None)


def _install_log(pieces: Dict[str, Dict[str, bytes]]) -> None:
    install_log_files(pieces, layer=None)


def _uninstall_log() -> None:
    uninstall_log_files(['agent.raw_log_ingestion'])


def now_minus_apache(base: datetime, **kwargs) -> str:
    """base - timedelta(**kwargs)를 apache access.log의 %t 형식(ISO8601 UTC, 마이크로초, Z)으로."""
    dt = base - timedelta(**kwargs)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def now_minus_eve(base: datetime, **kwargs) -> str:
    """base - timedelta(**kwargs)를 suricata eve.json의 timestamp 형식(ISO8601 UTC, +0000)으로."""
    dt = base - timedelta(**kwargs)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing() -> None:
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    recent_epoch = int((now - timedelta(minutes=2)).timestamp())
    old_epoch = int((now - timedelta(hours=5)).timestamp())

    audit_prefix = f"raw/source_type=auditd/host=web-01/dt={today}/"
    web_prefix = f"raw/source_type=apache/host=web-01/dt={today}/"
    # auth, network(suricata) 파티션은 아예 데이터 없음 (인프라 미연결 상황 재현)

    audit_text = (
        f'type=SYSCALL msg=audit({recent_epoch}.100:9001): pid=3812 uid=33 comm="sh" key="susp_exec"\n'
        f'type=SYSCALL msg=audit({old_epoch}.100:9000): pid=1234 uid=0 comm="cron" key="sensitive"\n'
    ).encode("utf-8")

    recent_ts = now_minus_apache(now, minutes=2)
    old_ts = now_minus_apache(now, hours=5)
    # 실제 EC2 apache access.log 형식(1차 탐지팀 fetch_apache_log.py 실측 LogFormat) 그대로 재현.
    web_text = (
        '%s r1 77.239.124.213 127.0.0.1 https ogwanwan.shop '
        '"POST /wp-login.php HTTP/1.1" 200 259 566000 21359 "-" "curl/7.0" xff="-"\n'
        '%s r2 9.9.9.9 127.0.0.1 https ogwanwan.shop '
        '"GET /old-request HTTP/1.1" 200 100 50000 21359 "-" "Mozilla/5.0" xff="-"\n'
    ) % (recent_ts, old_ts)
    web_text = web_text.encode("utf-8")

    objects_by_prefix = {
        audit_prefix: {"audit.log": audit_text},
        web_prefix: {"access.log": web_text},
    }

    pieces = (objects_by_prefix)
    _install_log(pieces)
    install_log_files({}, layer="auth")  # auth·network는 빈 로그 파일
    install_log_files({}, layer="network")

    try:
        from agent.raw_log_ingestion import fetch_recent_raw_logs

        records = fetch_recent_raw_logs(host="web-01", minutes=10)

        source_types = {r["_source_type"] for r in records}
        assert source_types == {"audit", "web"}, "데이터가 있는 두 소스만 나와야 한다"

        # 로컬 파일은 시각으로 거르지 않는다 — 5시간 전 이벤트도 파일 끝 N건 안이면 포함
        audit_records = [r for r in records if r["_source_type"] == "audit"]
        assert {r["pid"] for r in audit_records} == {3812, 1234}

        web_records = [r for r in records if r["_source_type"] == "web"]
        assert len(web_records) == 2
        recent = next(r for r in web_records if r["src_ip"] == "77.239.124.213")
        assert recent["path"] == "/wp-login.php"

        os.environ["RAW_LOG_LOCAL_MAX_LINES"] = "1"
        try:
            last_only = fetch_recent_raw_logs(host="web-01", minutes=10, source_types=["web"])
        finally:
            os.environ.pop("RAW_LOG_LOCAL_MAX_LINES", None)
        # 정규화 결과는 시각순이라 "끝 1건"은 가장 최근 요청이다
        assert [r["path"] for r in last_only] == ["/wp-login.php"], "가장 최근 1건만 남아야 한다"

        print("[PASS] test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing")
    finally:
        _uninstall_log()


def test_fetch_recent_raw_logs_structures_network_source() -> None:
    """network 소스도 audit/web/auth와 동일하게 1차 탐지팀 정규화 함수로 구조화되는지 확인한다."""
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    network_prefix = f"raw/source_type=suricata/host=web-01/dt={today}/"

    recent_ts = now_minus_eve(now, minutes=2)
    old_ts = now_minus_eve(now, hours=5)
    # 1차 탐지팀 fetch_network_log.py가 기대하는 suricata eve.json 포맷 그대로 재현.
    network_text = (
        '{"timestamp":"%s","event_type":"alert","src_ip":"127.0.0.1","src_port":51234,'
        '"dest_ip":"10.0.7.236","dest_port":22,"proto":"TCP",'
        '"xff":"77.239.124.213","alert":{"signature":"ET SCAN SSH BruteForce"}}\n'
        '{"timestamp":"%s","event_type":"alert","src_ip":"127.0.0.1","src_port":1,'
        '"dest_ip":"10.0.7.236","dest_port":1,"proto":"TCP",'
        '"xff":"9.9.9.9","alert":{"signature":"old alert"}}\n'
    ) % (recent_ts, old_ts)
    network_text = network_text.encode("utf-8")

    pieces = ({network_prefix: {"eve.json": network_text}})
    _install_log(pieces)

    try:
        from agent.raw_log_ingestion import fetch_recent_raw_logs

        records = fetch_recent_raw_logs(host="web-01", minutes=10, source_types=["network"])

        assert len(records) == 2, "로컬 파일은 시각과 무관하게 파일 끝 N건을 모두 넘긴다"
        record = next(r for r in records if r["signature"] == "ET SCAN SSH BruteForce")
        assert record["_source_type"] == "network"
        assert record["src_ip"] == "77.239.124.213", "xff로 승격된 실 클라이언트 IP여야 한다"
        assert record["signature"] == "ET SCAN SSH BruteForce"
        print("[PASS] test_fetch_recent_raw_logs_structures_network_source")
    finally:
        _uninstall_log()


if __name__ == "__main__":
    test_fetch_recent_raw_logs_merges_multiple_source_types_and_skips_missing()
    test_fetch_recent_raw_logs_structures_network_source()
    print("\n모든 테스트 통과.")
