"""agent/tools/normalizer_adapter.py — 공통 정규화 함수 어댑터 (A: 공통 모듈 담당)

2026-09-23 C/D 통합: normalize_log_documents()를 추가했다. 기존 normalize_* 공개
함수와 벤더 코드는 유지한다. 사건 조회·수집·조사 도구는 새 진입점에서 동일한 벤더
함수를 호출하고, raw_ref를 보존하면서 raw_refs/raw_ref_locations를 부가 정보로 붙인다.
로그는 `.env`의 `<계층>_LOG_LOCAL_PATH` 파일에서만 읽는다(S3 읽기는 2026-09-25 삭제).

1차 탐지팀(https://github.com/ogwanwan/Agentic-SOC, feature/primary_detection) 저장소의
정규화 코드는 primary_detection/normalizer/{common,tools}/ 아래에 "있는 그대로"(바이트
단위 동일, primary_detection/normalizer/vendor_sync_check.py로 검증) 들여와 있다. 이
파일은 그 코드를 단 한 줄도 고치지 않고, 원본 텍스트를 임시 파일로 넘겨 호출하는
얇은 어댑터다 — 우리(에이전트팀) 코드이지 벤더 코드가
아니라서, 벤더 코드와 달리 agent/ 패키지 안에 그대로 둔다.

*** 2026-09-22 구조 변경: normalizer/ 를 agent/ 밖(primary_detection/)으로 이동 ***
원래 agent/tools/normalizer/{common,tools}/ 에 벤더 코드와 이 adapter.py가 같이
있었는데, 벤더 코드는 "우리 에이전트 코드"가 아니라 "1차 탐지팀 산출물"이라는 게
명확하지 않아 보여서, agent/와 같은 레벨의 primary_detection/normalizer/로 분리했다
(웰시님 지적). 이 파일(우리 팀이 짠 어댑터)만 agent/tools/ 밑에 남기고
normalizer_adapter.py로 이름을 바꿨다. primary_detection/은 파이썬 패키지 이름 규칙상
하이픈을 쓸 수 없어서(import primary_detection 불가) 그 자체를 패키지로 import하지
않는다 — 대신 agent/__init__.py 맨 위에서 primary_detection/ 를 sys.path에 추가해서,
그 밑의 normalizer 패키지를 최상위 패키지처럼(`from normalizer.tools... import ...`)
바로 쓸 수 있게 했다. (벤더 코드 자체도 원래 내부적으로 자기 부모 폴더를 sys.path에
넣어서 common/tools를 최상위 패키지로 찾는 방식이라, 폴더를 어디로 옮기든 벤더 코드
내부 import는 안 깨진다 — 이번 이동으로 실제로 확인됨.)

완료 기준(같은 raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한 정규화 결과를 반환해야 한다)을
지키려면 파싱 로직 자체를 절대 건드리면 안 된다 — 그래서 이 파일은 "소스 선택 + 임시파일 변환"
외에는 아무 로직도 갖지 않는다.

2026-09-22 업데이트: web(apache) 어댑터 추가. EC2 실측(웰시님이 직접 SSH로 확인)으로
nginx(리버스 프록시, 80/443)와 apache(백엔드, 127.0.0.1:8080)가 같이 떠 있고, apache의
access.log가 1차 탐지팀 fetch_apache_log.py가 기대하는 포맷과 컬럼 단위로 정확히
일치하는 것을 확인했다. 그래서 web 계층은 (기존에 쓰던 nginx JSON 로그가 아니라)
apache의 access.log를 정규화 대상으로 삼는다 — auth/audit과 같은 패턴.

2026-09-22 추가 업데이트: network(suricata) 어댑터도 추가했다. 포맷은 이미 호환
확인됨(Suricata eve.json, 우리 팀 network_parser.py와 동일 소스) — auth/audit/web과
같은 패턴. 단, 1차 탐지팀 fetch_network_log() 순수 함수는 src_ip/event_type/flow_id/
signature만 필터로 지원해서(우리 tool 스키마의 dst_ip/src_port/dst_port/protocol은
없음), 그 4개는 agent/tools/real/fetch_network_log.py에서 결과를 받은 뒤 후처리로
거른다(audit의 user/serial 후처리와 동일한 방식).
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# sys.path에 추가해준다 — 그래서 여기선 그 밑의 normalizer 패키지를 최상위
# 패키지처럼 바로 import한다.
from primary_detection.normalizer.tools.fetch_auth_log import fetch_auth_log as _normalize_auth_events
from primary_detection.normalizer.tools.fetch_audit_log import fetch_audit_log as _normalize_audit_events
from primary_detection.normalizer.tools.fetch_apache_log import fetch_apache_log as _normalize_web_events
from primary_detection.normalizer.tools.fetch_network_log import fetch_network_log as _normalize_network_events


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
