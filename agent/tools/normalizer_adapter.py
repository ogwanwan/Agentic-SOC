"""1차 탐지팀 공통 정규화 어댑터 — 에이전트 코드와 primary_detection/normalizer/ 사이의 유일한 연결 지점.

역할
  원본 로그 텍스트를 임시 파일로 써서 1차 탐지팀 정규화 함수(fetch_apache_log/fetch_auth_log/
  fetch_audit_log/fetch_network_log)에 그대로 넘기고, 결과 이벤트에 원본 추적 정보를 붙인다.
    - raw_ref: 1차 탐지와 같은 "<파일명>:<줄 번호>" (예: auth.log:9190)
    - raw_refs: audit처럼 여러 줄이 한 이벤트면 그 줄 전부
    - raw_ref_locations: 실제 전체 경로
  "같은 raw 로그에 대해 1차 탐지와 조사 도구가 같은 정규화 결과를 낸다"가 완료 기준이라,
  이 파일은 파싱 로직을 갖지 않는다. 1차 탐지팀 코드는 수정하지 않는다.

누가 부르나
  [9]·[34] agent/tools/log_source.py normalize_documents()   → normalize_log_documents()
  tests/test_normalizer_parity.py, scripts/verify_all_tools.py → normalize_auth/audit/web/network()

무엇을 부르나
  primary_detection/normalizer/tools/fetch_apache_log.py, fetch_auth_log.py, fetch_audit_log.py,
  fetch_network_log.py (1차 탐지팀 코드 — vendor_sync_check.py로 원본과 동일성 확인)

참고
  - web은 nginx가 아니라 apache access.log를 쓴다. EC2에서 nginx(리버스 프록시)와 apache(백엔드,
    127.0.0.1:8080)가 같이 떠 있고, apache 로그가 1차 탐지팀 형식과 컬럼 단위로 일치했다.
  - network(suricata) 정규화 함수는 src_ip/event_type/flow_id/signature만 필터로 지원해서, dst_ip·포트·
    프로토콜 필터는 agent/tools/real/fetch_network_log.py가 결과를 받은 뒤 거른다.
  - primary_detection/은 agent/ 밖(저장소 루트)에 두어 "우리 코드가 아님"을 분명히 했다.
  - 로그는 .env의 <계층>_LOG_LOCAL_PATH 파일에서만 읽는다(S3 읽기는 삭제).
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# 1차 탐지팀 정규화 함수 (agent/__init__.py가 import 경로를 준비한다)
from primary_detection.normalizer.tools.fetch_auth_log import fetch_auth_log as _normalize_auth_events
from primary_detection.normalizer.tools.fetch_audit_log import fetch_audit_log as _normalize_audit_events
from primary_detection.normalizer.tools.fetch_apache_log import fetch_apache_log as _normalize_web_events
from primary_detection.normalizer.tools.fetch_network_log import fetch_network_log as _normalize_network_events


# [34] ← log_source.normalize_documents()에서 호출: 원본 텍스트 → 1차 탐지팀 정규화 → 원본 추적 정보 부착
def normalize_log_documents(layer, documents, start, end):
    """C/D source adapter: call the vendored normalizers without changing them.

    Preserve local vendor raw_ref values (basename:line). raw_ref_locations adds the
    absolute file location without replacing the basename references used by primary
    detection. Several documents are concatenated into one staging file and each
    line is mapped back to its own document.
    """
    documents = list(documents)
    if not documents:
        return []
    lines, locations = [], []
    for source, text in documents:
        physical_lines = text.split("\n")
        if physical_lines and physical_lines[-1] == "":
            physical_lines.pop()
        lines.extend(physical_lines)
        locations.extend(f"{source}:{number}" for number in range(1, len(physical_lines) + 1))

    local = len(documents) == 1
    name = Path(documents[0][0]).name.removesuffix(".gz") if local else "source.log"
    functions = {"web": _normalize_web_events, "auth": _normalize_auth_events,
                 "audit": _normalize_audit_events, "network": _normalize_network_events}
    kwargs = {}
    with tempfile.TemporaryDirectory(prefix="soc-normalize-") as staging:
        directory = Path(staging)
        if layer == "auth":
            # Let the vendor interpret yearless syslog using its existing dt/year
            # contract. Narrow incident windows must not depend on today's year.
            partition = re.search(r"(?:^|/)dt=(\d{4}-\d{2}-\d{2})(?:/|$)", documents[0][0])
            if partition:
                directory /= "dt=" + partition.group(1)
            elif not os.environ.get("AUTH_LOG_YEAR"):
                if start.year == end.year:
                    kwargs["year"] = start.year
                elif (end - start).days < 180:
                    directory /= "dt=" + end.date().isoformat()
            directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        events = functions[layer](str(path), **kwargs)

    for event in events:
        prefix, first_line = event["raw_ref"].rsplit(":", 1)
        numbers = event.get("layer_data", {}).get("raw_lines") or [int(first_line)]
        sources = [locations[number - 1] for number in numbers]
        refs = [f"{prefix}:{number}" for number in numbers] if local else sources
        event["raw_ref"] = refs[0]
        event["raw_refs"] = list(dict.fromkeys(refs))
        event["raw_ref_locations"] = {ref: [source] for ref, source in zip(refs, sources)}
    return events


def _local_path(env_name: str) -> str:
    path = os.environ.get(env_name)
    if not path:
        raise ValueError(f"{env_name}가 설정되지 않았습니다 (.env에 로그 파일 경로 필요)")
    return path


# 아래 normalize_* 4개는 계층별로 1차 탐지팀 함수를 필터 인자와 함께 직접 부르는 예전 진입점이다.
# 조사 도구·수집은 normalize_log_documents()를 쓰고, 이 함수들은 정규화 동일성 검증
# (tests/test_normalizer_parity.py)과 scripts/verify_all_tools.py만 쓴다. 로컬 파일을 그대로
# 넘기므로 raw_ref가 실제 로그 파일 이름을 가리킨다.


def normalize_auth(
    host: str,
    start_time: str,
    end_time: str,
    *,
    user: Optional[str] = None,
    src_ip: Optional[str] = None,
    event: Optional[str] = None,
    result: Optional[str] = None,
    year: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_auth_log()를 그대로 호출 — 공통스키마(layer=auth) 이벤트 리스트 반환.

    time_window/user/src_ip/event/result/year 는 1차 탐지팀 fetch_auth_log()의 필터를
    그대로 전달한다(이름·의미 동일, 새로 정의하지 않음).
    """
    return _normalize_auth_events(
        _local_path("AUTH_LOG_LOCAL_PATH"), time_window=[start_time, end_time],
        user=user, src_ip=src_ip, event=event, result=result, year=year,
    )


def normalize_audit(
    host: str,
    start_time: str,
    end_time: str,
    *,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    key: Optional[str] = None,
    session_type: Optional[str] = None,
    exclude_interactive: bool = False,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_audit_log()를 그대로 호출 — 공통스키마(layer=system) 이벤트 리스트 반환."""
    return _normalize_audit_events(
        _local_path("AUDIT_LOG_LOCAL_PATH"), time_window=[start_time, end_time],
        pid=pid, ppid=ppid, key=key, session_type=session_type,
        exclude_interactive=exclude_interactive,
    )


def normalize_web(
    host: str,
    start_time: str,
    end_time: str,
    *,
    src_ip: Optional[str] = None,
    path_pattern: Optional[str] = None,
    status: Optional[int] = None,
    method: Optional[str] = None,
    exclude_self: bool = False,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_apache_log()를 그대로 호출 — 공통스키마(layer=web) 이벤트 리스트 반환.

    WEB_LOG_LOCAL_PATH는 apache의 access.log를 가리켜야 한다(nginx JSON 아님).
    time_window/src_ip/path_pattern/status/method/exclude_self 는 1차 탐지팀
    fetch_apache_log()의 필터를 그대로 전달한다.
    """
    return _normalize_web_events(
        _local_path("WEB_LOG_LOCAL_PATH"), time_window=[start_time, end_time],
        src_ip=src_ip, path_pattern=path_pattern, status=status,
        method=method, exclude_self=exclude_self,
    )


def normalize_network(
    host: str,
    start_time: str,
    end_time: str,
    *,
    src_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    flow_id: Optional[int] = None,
    signature: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """1차 탐지팀 fetch_network_log()를 그대로 호출 — 공통스키마(layer=network) 이벤트 리스트 반환.

    NETWORK_LOG_LOCAL_PATH는 Suricata eve.json(JSONL)을 가리킨다. time_window/src_ip/
    event_type(http|alert)/flow_id/signature 는 1차 탐지팀 fetch_network_log()의 필터를
    그대로 전달한다. dst_ip 등 이 함수가 지원하지 않는 필터는 호출부에서 후처리로 거른다.
    """
    return _normalize_network_events(
        _local_path("NETWORK_LOG_LOCAL_PATH"), time_window=[start_time, end_time],
        src_ip=src_ip, event_type=event_type, flow_id=flow_id, signature=signature,
    )
