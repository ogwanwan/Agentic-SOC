"""fetch_web_log 실제 구현 - 에이전트(LLM)가 조사 중 호출하는 웹(apache access) 로그 조회 도구.

파일명 == 함수명 규칙에 따라 agent/tools/registry.py의 build_default_registry()가
mock_tools.py 대신 이 함수를 자동으로 사용한다. (agent/tools/real/README.md 참고)

역할 분담:
  - 원본 읽기 + 정규화: agent/tools/log_source.load_window_events()
      → normalizer_adapter.normalize_log_documents()
      → primary_detection/normalizer/tools/fetch_apache_log.py (1차 탐지팀 공통 정규화 함수)
    에이전트 자체 파서(구 parsers/nginx_json_parser.py, apache_parser.py)는 쓰지 않는다.
  - 이 파일(에이전트 도구): 도구 인자 해석, 필터, limit/offset 페이지네이션,
    LLM에게 돌려줄 summary/반환 형식.

왜 nginx가 아니라 apache인가: EC2 실측(2026-09-22)으로 nginx(리버스 프록시)와
apache(백엔드, 127.0.0.1:8080)가 같이 떠 있고, apache access.log가 1차 탐지팀
fetch_apache_log.py가 기대하는 포맷과 컬럼 단위로 일치했다. apache 스키마는 "path"
필드를 쓰고 client IP(%a)가 이미 실제 클라이언트라 xff 보정이 필요 없다.

필터 의미:
  - path: 부분 문자열 일치
  - method: 대소문자 무시 일치, status_code: 정수 일치
  - exclude_self: 서버 자신의 공인 IP(1차 탐지팀 SERVER_PUBLIC_IP)에서 온 요청 제외

필요 환경변수: WEB_LOG_LOCAL_PATH(apache access.log) 있으면 로컬 파일,
  없으면 WEB_LOG_BUCKET/S3의 raw/source_type=apache/... 파티션

summary 끝의 [조회 구간 전체 집계]는 페이지와 무관하게 조건에 맞는 전체 요청 기준
메서드·상태코드 계열·서로 다른 경로 수·상위 경로·User-Agent를 준다(원칙 9에 그대로 쓰도록).
EC2 main.py(2026-09-24 INC-xmlrpc-flood)에서 LLM이 records를 직접 세고 해석하다 판정이
흔들려, auth와 같은 방식으로 세는 기준을 코드로 고정했다.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from ..log_source import filtered_out_hint, load_window_events, pagination

TOP_N = 5
MAX_UA_CHARS = 80


def _status_class(status: Any) -> str:
    return f"{status // 100}xx" if isinstance(status, int) else "unknown"


def _top(counter: Counter) -> str:
    return ", ".join(f"{key} {count}건" for key, count in counter.most_common(TOP_N)) or "-"


def _request_stats(records: List[Dict[str, Any]]) -> str:
    methods = Counter(r.get("method") or "-" for r in records)
    statuses = Counter(_status_class(r.get("status")) for r in records)
    paths = Counter(r.get("path") or "-" for r in records)
    # 브라우저 User-Agent는 200자 가까이 돼 summary가 길어진다 — 앞부분만으로 구분에 충분
    agents = Counter((r.get("user_agent") or "-")[:MAX_UA_CHARS] for r in records)
    src_ips = {r.get("src_ip") for r in records if r.get("src_ip")}
    times = sorted(r["timestamp"] for r in records if r.get("timestamp"))
    span = f"{times[0]}~{times[-1]}" if times else "-"
    return (
        f"요청 {len(records)}건(실제 기록 시각 {span}), 출발지 IP {len(src_ips)}개, "
        f"메서드별: {_top(methods)}, 상태코드 계열별: {_top(statuses)}, "
        f"서로 다른 경로 {len(paths)}개, 상위 경로: {_top(paths)}, "
        f"User-Agent 상위: {_top(agents)}"
    )


def _matches(record: Dict[str, Any], args: Dict[str, Any]) -> bool:
    if args.get("src_ip") is not None and record.get("src_ip") != args["src_ip"]:
        return False
    if args.get("method") is not None and str(record.get("method") or "").upper() != str(args["method"]).upper():
        return False
    if args.get("path") is not None and args["path"] not in (record.get("path") or ""):
        return False
    if args.get("status_code") is not None and record.get("status") != int(args["status_code"]):
        return False
    if args.get("exclude_self"):
        from primary_detection.normalizer.tools.fetch_apache_log import SERVER_PUBLIC_IP

        if record.get("src_ip") == SERVER_PUBLIC_IP:
            return False
    return True


def fetch_web_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit, offset = pagination(args)

    loaded = load_window_events("web", host, start_time, end_time)
    matched: List[Dict[str, Any]] = [e for e in loaded["events"] if _matches(e, args)]

    total_matched = len(matched)
    page = matched[offset : offset + limit]
    has_more = offset + len(page) < total_matched
    next_offset = offset + len(page) if has_more else None

    if loaded["error"] == "permission_denied":
        summary = f"{host}의 web 로그 파일 읽기 권한이 없습니다. WEB_LOG_LOCAL_PATH 권한을 확인하세요."
    elif total_matched == 0:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 web 요청을 찾지 못했습니다. "
            "host 이름, 기간, 또는 WEB_LOG_LOCAL_PATH/WEB_LOG_BUCKET 설정을 확인하세요."
        ) + filtered_out_hint(len(loaded["events"]), args, ("src_ip", "method", "path", "status_code", "exclude_self"))
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 web 요청 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, method/path/status/duration_us까지 구조화, "
            "1차 탐지팀 공통 정규화 함수 사용) "
            f"[조회 구간 전체 집계] {_request_stats(matched)}"
        )

    return {
        "count": len(page),
        "summary": summary,
        "records": page,
        "total_matched": total_matched,
        "has_more": has_more,
        "next_offset": next_offset,
        "scanned_objects": loaded["scanned_objects"],
        "invalid_timestamps": loaded["invalid_timestamps"],
        **({"error": loaded["error"]} if loaded["error"] else {}),
    }
