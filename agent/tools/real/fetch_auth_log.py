"""fetch_auth_log 실제 구현 - 에이전트(LLM)가 조사 중 호출하는 인증 로그 조회 도구.

파일명 == 함수명 규칙에 따라 agent/tools/registry.py의 build_default_registry()가
mock_tools.py 대신 이 함수를 자동으로 사용한다. (agent/tools/real/README.md 참고)

역할 분담:
  - 원본 읽기 + 정규화: agent/tools/log_source.load_window_events()
      → normalizer_adapter.normalize_log_documents()
      → primary_detection/normalizer/tools/fetch_auth_log.py (1차 탐지팀 공통 정규화 함수)
    같은 raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한 정규화 결과를 내도록,
    파싱은 에이전트 자체 파서(구 parsers/auth_parser.py)가 아니라 공통 정규화 함수에 맡긴다.
    raw_ref/raw_refs/raw_ref_locations(S3 객체별 실제 줄 위치)도 그 경로에서 붙는다.
  - 이 파일(에이전트 도구): 도구 인자 해석, 필터, limit/offset 페이지네이션,
    LLM에게 돌려줄 summary/반환 형식.

필드 주의: 공통 정규화 스키마는 event(ssh_accepted/ssh_failed/ssh_invalid_user/
pam_auth_failure/sudo_command/su_failure 등 세분화된 값)·src_ip·raw_ref를 쓴다.
도구 인자 event_type은 이 event 값과 비교한다.

필요 환경변수: AUTH_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 AUTH_LOG_BUCKET/S3
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..log_source import load_window_events, pagination


def _matches(record: Dict[str, Any], args: Dict[str, Any]) -> bool:
    for key in ("user", "src_ip", "result"):
        if args.get(key) is not None and record.get(key) != args[key]:
            return False
    if args.get("event_type") is not None and record.get("event") != args["event_type"]:
        return False
    return True


def fetch_auth_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit, offset = pagination(args)

    loaded = load_window_events("auth", host, start_time, end_time)
    matched: List[Dict[str, Any]] = [e for e in loaded["events"] if _matches(e, args)]

    total_matched = len(matched)
    page = matched[offset : offset + limit]
    has_more = offset + len(page) < total_matched
    next_offset = offset + len(page) if has_more else None

    if loaded["error"] == "permission_denied":
        summary = f"{host}의 auth 로그 파일 읽기 권한이 없습니다. AUTH_LOG_LOCAL_PATH 권한을 확인하세요."
    elif total_matched == 0:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 인증 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 AUTH_LOG_LOCAL_PATH/AUTH_LOG_BUCKET 설정을 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 인증 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, event/result까지 구조화, "
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
