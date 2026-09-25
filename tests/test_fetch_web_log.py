"""fetch_web_log(agent/tools/real/fetch_web_log.py) 단독 테스트.

실제 AWS에 붙지 않고, 임시 로그 파일을 <계층>_LOG_LOCAL_PATH로 지정해서(tests/_log_files.py)
- 실제 EC2 apache access.log 형식(공백 구분, req_id 포함)이 구조화되어 반환되는지
- src_ip 필터가 되는지 (client 필드 %a 기준 — apache는 이미 실 클라이언트 IP라 xff 불필요)
- method/path/status_code 필터가 되는지
- 시간 범위 필터가 되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

2026-09-22 업데이트: web 계층도 1차 탐지팀 공통 정규화 함수(normalizer/tools/
fetch_apache_log.py)를 쓰도록 바뀌면서, 정규화 대상 로그가 nginx JSON에서 apache
access.log로 바뀌었다(EC2 SSH 직접 확인 — nginx는 리버스 프록시, apache가 백엔드이고
apache의 access.log가 1차 탐지팀 파서 포맷과 정확히 일치함). 필드명도 uri→path로
바뀌었다.

pytest 없이도 저장소 루트에서 `python -m tests.test_fetch_web_log`로 실행 가능.
"""

from __future__ import annotations

import os
import sys
import types

# normalizer 벤더 코드가 import 시점에 load_dotenv()를 호출하는 문제 회피
# (tests/test_fetch_auth_log.py 상단 주석 참고).
#
# 2026-09-22 수정: 예전엔 그냥 `import agent`만 했는데, 그러면 raw_log_ingestion.py가
# 직접 불러쓰는 auth/audit 쪽 load_dotenv()만 지금 당장 실행되고, apache/network
# 쪽(fetch_apache_log.py/fetch_network_log.py)은 normalizer/adapter.py를 거쳐야만
# import되기 때문에 이 시점엔 아직 안 실행된 상태였다. 그래서 여기서 4개 변수를
# 지워도, 뒤에서 이 테스트 파일이 fetch_web_log를 import하는 순간(adapter.py가
# 그제서야 fetch_apache_log.py/fetch_network_log.py를 처음 import) load_dotenv()가
# "새로 실행"되면서 방금 지운 WEB_LOG_LOCAL_PATH(+다른 변수들까지)가 .env 값으로
# 다시 채워져버렸다 — 이게 로컬 PC에서 count가 안 맞던 진짜 원인이었다.
# adapter.py를 미리 import해서 4개 벤더 파일의 load_dotenv()를 전부 한 번에
# 끝내놓은 다음에 지우면, 그 뒤에 무엇을 import하든 다시 채워지지 않는다.
import agent.tools.normalizer_adapter as _load_dotenv_trigger  # noqa: F401
for _env_name in ("AUTH_LOG_LOCAL_PATH", "AUDIT_LOG_LOCAL_PATH", "WEB_LOG_LOCAL_PATH", "NETWORK_LOG_LOCAL_PATH"):
    os.environ.pop(_env_name, None)
from typing import Any, Dict

from tests._log_files import install_log_files, uninstall_log_files


def _install_log(pieces: Dict[str, Dict[str, bytes]]) -> None:
    install_log_files(pieces, layer="web")


def _uninstall_log() -> None:
    uninstall_log_files(['agent.tools.real.fetch_web_log'])


def _sample_web_text() -> bytes:
    """실제 EC2 apache access.log 형식 그대로 재현(1차 탐지팀 fetch_apache_log.py
    docstring의 실측 LogFormat과 컬럼 단위로 동일): 웹셸 업로드 시도성 요청 1건(04:24) +
    정상 요청 1건(00:01, 시간 범위 밖).
    """
    return (
        b'2026-09-13T04:24:31.733210Z r1 77.239.124.213 127.0.0.1 https ogwanwan.shop '
        b'"POST /wp-admin/install.php?step=1 HTTP/1.0" 200 259 566000 21359 "-" "curl/7.0" xff="-"\n'
        b'2026-09-13T00:01:55.096000Z r2 54.180.11.0 127.0.0.1 https ogwanwan.shop '
        b'"GET / HTTP/1.0" 200 0 1000 21359 "-" "WordPress/6.9.4" xff="-"\n'
    )


def test_fetch_web_log_parses_real_apache_format() -> None:
    prefix = "raw/source_type=apache/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"access.log": _sample_web_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )

        assert result["count"] == 2
        webshell = next(e for e in result["records"] if e["src_ip"] == "77.239.124.213")
        assert webshell["method"] == "POST"
        assert webshell["path"] == "/wp-admin/install.php?step=1"
        assert webshell["status"] == 200
        assert webshell["host"] == "ogwanwan.shop"
        print("[PASS] test_fetch_web_log_parses_real_apache_format")
    finally:
        _uninstall_log()


def test_fetch_web_log_filters_by_src_ip() -> None:
    prefix = "raw/source_type=apache/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"access.log": _sample_web_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "src_ip": "77.239.124.213",
            }
        )
        assert result["count"] == 1
        assert result["records"][0]["method"] == "POST"
        print("[PASS] test_fetch_web_log_filters_by_src_ip")
    finally:
        _uninstall_log()


def test_fetch_web_log_filters_by_method_path_status() -> None:
    prefix = "raw/source_type=apache/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"access.log": _sample_web_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-12-31T23:59:59Z",
                "method": "post",  # 대소문자 무관해야 함
                "path": "install.php",
                "status_code": 200,
            }
        )
        assert result["count"] == 1
        print("[PASS] test_fetch_web_log_filters_by_method_path_status")
    finally:
        _uninstall_log()


def test_fetch_web_log_filters_by_time_range() -> None:
    prefix = "raw/source_type=apache/host=web-01/dt=2026-09-13/"
    pieces = ({prefix: {"access.log": _sample_web_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T04:00:00Z",
                "end_time": "2026-09-13T05:00:00Z",
            }
        )
        assert result["count"] == 1, "00:01:55(정상 요청)는 범위 밖이라 제외되어야 한다"
        assert result["records"][0]["method"] == "POST"
        print("[PASS] test_fetch_web_log_filters_by_time_range")
    finally:
        _uninstall_log()


def test_fetch_web_log_reports_missing_partition() -> None:
    pieces = ({})
    _install_log(pieces)

    try:
        from agent.tools.real.fetch_web_log import fetch_web_log

        result = fetch_web_log(
            {
                "host": "web-01",
                "start_time": "2026-09-13T00:00:00Z",
                "end_time": "2026-09-13T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_fetch_web_log_reports_missing_partition")
    finally:
        _uninstall_log()


if __name__ == "__main__":
    test_fetch_web_log_parses_real_apache_format()
    test_fetch_web_log_filters_by_src_ip()
    test_fetch_web_log_filters_by_method_path_status()
    test_fetch_web_log_filters_by_time_range()
    test_fetch_web_log_reports_missing_partition()
    print("\n모든 테스트 통과.")
