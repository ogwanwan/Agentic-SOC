"""fetch_audit_log 실제 구현 - 에이전트(LLM)가 조사 중 호출하는 auditd 로그 조회 도구.

파일명 == 함수명 규칙에 따라 agent/tools/registry.py의 build_default_registry()가
mock_tools.py 대신 이 함수를 자동으로 사용한다. (agent/tools/real/README.md 참고)

역할 분담:
  - 원본 읽기 + 정규화: agent/tools/log_source.load_window_events()
      → normalizer_adapter.normalize_log_documents()
      → primary_detection/normalizer/tools/fetch_audit_log.py (1차 탐지팀 공통 정규화 함수)
    멀티라인 이벤트 조립(SYSCALL/EXECVE/PATH…)과 session_type 판정은 공통 정규화 함수가
    한다. 에이전트 자체 파서(구 parsers/audit_parser.py)는 쓰지 않는다.
  - 이 파일(에이전트 도구): 도구 인자 해석, 필터, limit/offset 페이지네이션,
    LLM에게 돌려줄 summary/반환 형식.

필터 의미:
  - event_type: auditd 룰 key와 비교
  - exclude_interactive: session_type == "non_interactive"인 이벤트만 남김
    (관리자 세션뿐 아니라 판정 불가(None)도 제외 — 공통 정규화 함수와 동일한 의미)
  - include_user_cmd=False: USER_CMD 레코드가 포함된 이벤트 제외

필요 환경변수: AUDIT_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 AUDIT_LOG_BUCKET/S3
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..log_source import load_window_events, pagination


def _matches(record: Dict[str, Any], args: Dict[str, Any]) -> bool:
    for key in ("pid", "ppid", "user", "serial"):
        if args.get(key) is not None and record.get(key) != args[key]:
            return False
    if args.get("event_type") is not None and record.get("key") != args["event_type"]:
        return False
    if args.get("exclude_interactive") and record.get("session_type") != "non_interactive":
        return False
    if args.get("include_user_cmd") is False and "USER_CMD" in (record.get("record_types") or []):
        return False
    return True


def fetch_audit_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit, offset = pagination(args)

    loaded = load_window_events("audit", host, start_time, end_time)
    matched: List[Dict[str, Any]] = [e for e in loaded["events"] if _matches(e, args)]

    total_matched = len(matched)
    page = matched[offset : offset + limit]
    has_more = offset + len(page) < total_matched
    next_offset = offset + len(page) if has_more else None

    if loaded["error"] == "permission_denied":
        summary = f"{host}의 audit 로그 파일 읽기 권한이 없습니다. AUDIT_LOG_LOCAL_PATH 권한을 확인하세요."
    elif total_matched == 0:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 audit 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 AUDIT_LOG_LOCAL_PATH/AUDIT_LOG_BUCKET 설정을 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 audit 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, uid/euid/session_type/exec_args까지 구조화, "
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
