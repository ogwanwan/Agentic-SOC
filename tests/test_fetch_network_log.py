"""fetch_network_log(agent/tools/real/fetch_network_log.py) 단독 테스트.

실제 AWS 없이, 임시 로그 파일을 <계층>_LOG_LOCAL_PATH로 지정해(tests/_log_files.py)
- eve.json(NDJSON) 이벤트가 구조화되어 반환되는지
- alert_only 필터로 http 등 비-alert 이벤트가 걸러지는지
- src_ip(xff로 승격된 실 클라이언트)/dst_ip/dst_port/protocol 필터가 되는지
  (protocol 대소문자 무관)
- 시간 범위 필터가 되는지
- limit/offset 페이지네이션이 되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

2026-09-22 업데이트: network 계층도 1차 탐지팀 공통 정규화 함수(normalizer/tools/
fetch_network_log.py)를 쓰도록 바뀌었다. 중요한 동작 차이: 1차 탐지팀 정규화 함수는
event_type이 http|alert인 이벤트만 남기고(dns/flow/stats/fileinfo는 버림), 그래서
예전엔 있던 "flow" 이벤트 예시를 "http" 이벤트로 바꿨다. 필드명도 alert_signature
→ signature, 상단 src_ip는 이제 xff 체인으로 "승격"된 실 클라이언트 IP를 뜻한다
(원본 transport src_ip는 layer_data.transport_src_ip에 별도 보존).

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_network_log`로 실행 가능.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any, Dict, List

from tests._log_files import install_log_files, uninstall_log_files

# normalizer 벤더 코드가 import 시점에 load_dotenv()를 호출하는 문제 회피
# (tests/test_fetch_auth_log.py 상단 주석 참고).
#
# 2026-09-22 수정: 예전엔 그냥 `import agent`만 했는데, apache/network 쪽
# load_dotenv()는 normalizer/adapter.py를 거쳐야만 실행돼서 이 시점엔 아직 안
# 됐었다. 그래서 여기서 4개 변수를 지워도, 뒤에서 fetch_network_log를 import하는
# 순간(adapter.py가 그제서야 fetch_apache_log.py/fetch_network_log.py를 처음
# import) load_dotenv()가 다시 실행되면서 NETWORK_LOG_LOCAL_PATH가 .env 값으로
# 재오염됐다 — 로컬 PC 테스트에서 count가 안 맞던 진짜 원인. adapter.py를 미리
# import해서 4개 벤더 파일의 load_dotenv()를 전부 한 번에 끝내놓은 뒤 지운다.
import agent.tools.normalizer_adapter as _load_dotenv_trigger  # noqa: F401
for _env_name in ("AUTH_LOG_LOCAL_PATH", "AUDIT_LOG_LOCAL_PATH", "WEB_LOG_LOCAL_PATH", "NETWORK_LOG_LOCAL_PATH"):
    os.environ.pop(_env_name, None)


def _install_log(pieces: Dict[str, Dict[str, bytes]]) -> None:
    install_log_files(pieces, layer="network")


def _uninstall_log() -> None:
    uninstall_log_files(['agent.tools.real.fetch_network_log'])


def _sample_network_text() -> bytes:
    """alert(SSH 브루트포스 시그니처, xff로 77.239.124.213 승격) 1건 +
    http(정상 요청, xff로 112.148.16.1 승격) 1건 + 시간 범위 밖 alert 1건.
    dns/flow 등 http|alert가 아닌 이벤트는 1차 탐지팀 정규화 함수가 아예 버리므로
    fixture에 포함하지 않는다.
    """
    return (
        b'{"timestamp": "2026-09-13T04:10:00.000000+0000", "event_type": "alert", '
        b'"flow_id": 5001, "src_ip": "127.0.0.1", "src_port": 51234, '
        b'"dest_ip": "10.0.7.236", "dest_port": 22, "proto": "TCP", '
        b'"xff": "77.239.124.213", "alert": {"signature": "ET SCAN SSH BruteForce"}}\n'
        b'{"timestamp": "2026-09-13T04:15:00.000000+0000", "event_type": "http", '
        b'"flow_id": 5002, "src_ip": "127.0.0.1", "src_port": 40000, '
        b'"dest_ip": "10.0.7.236", "dest_port": 53, "proto": "UDP", '
        b'"xff": "112.148.16.1", "http": {"hostname": "ogwanwan.shop", "url": "/", '
        b'"http_method": "GET", "status": 200}}\n'
        b'{"timestamp": "2026-09-13T00:00:00.000000+0000", "event_type": "alert", '
        b'"flow_id": 5003, "src_ip": "127.0.0.1", "src_port": 1, '
        b'"dest_ip": "10.0.7.236", "dest_port": 1, "proto": "tcp", '
        b'"xff": "9.9.9.9", "alert": {"signature": "old alert"}}\n'
    )


def test_fetch_network_log_parses_structured_event() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"eve.json": _sample_network_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T04:00:00Z",
                "end_time": "2026-09-13T05:00:00Z",
            }
        )
        assert result["count"] == 2, "이 시간 범위 안엔 alert 1건 + http 1건"
        alert = next(e for e in result["records"] if e["event_type"] == "alert")
        assert alert["signature"] == "ET SCAN SSH BruteForce"
        assert alert["protocol"] == "TCP"
        assert alert["src_ip"] == "77.239.124.213", "xff로 승격된 실 클라이언트 IP여야 한다"
        print("[PASS] test_fetch_network_log_parses_structured_event")
    finally:
        _uninstall_log()


def test_fetch_network_log_alert_only_and_protocol_filter() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"eve.json": _sample_network_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "alert_only": True,
            }
        )
        assert result["count"] == 2, "alert_only면 http는 빠지고 alert 2건만"

        result_tcp_lower = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "protocol": "tcp",  # 소문자로 줘도 매칭돼야 함
            }
        )
        assert result_tcp_lower["count"] == 2, "TCP 프로토콜(대소문자 무관) 2건(alert 2개, http는 UDP라 제외)"
        print("[PASS] test_fetch_network_log_alert_only_and_protocol_filter")
    finally:
        _uninstall_log()


def test_fetch_network_log_filters_by_src_dst_ip() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"eve.json": _sample_network_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "src_ip": "77.239.124.213",
            }
        )
        assert result["count"] == 1
        assert result["records"][0]["signature"] == "ET SCAN SSH BruteForce"
        print("[PASS] test_fetch_network_log_filters_by_src_dst_ip")
    finally:
        _uninstall_log()


def test_fetch_network_log_pagination() -> None:
    prefix = "raw/source_type=suricata/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"eve.json": _sample_network_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        page1 = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "limit": 2,
                "offset": 0,
            }
        )
        assert page1["count"] == 2
        assert page1["total_matched"] == 3
        assert page1["has_more"] is True

        page2 = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "limit": 2,
                "offset": page1["next_offset"],
            }
        )
        assert page2["count"] == 1
        assert page2["has_more"] is False
        print("[PASS] test_fetch_network_log_pagination")
    finally:
        _uninstall_log()


def test_fetch_network_log_reports_missing_partition() -> None:
    pieces = ({})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_network_log import fetch_network_log

        result = fetch_network_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_fetch_network_log_reports_missing_partition")
    finally:
        _uninstall_log()


if __name__ == "__main__":
    test_fetch_network_log_parses_structured_event()
    test_fetch_network_log_alert_only_and_protocol_filter()
    test_fetch_network_log_filters_by_src_dst_ip()
    test_fetch_network_log_pagination()
    test_fetch_network_log_reports_missing_partition()
    print("\n모든 테스트 통과.")
