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
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..log_source import load_window_events, pagination


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
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 web 요청 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, method/path/status/duration_us까지 구조화, "
            "1차 탐지팀 공통 정규화 함수 사용)"
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
