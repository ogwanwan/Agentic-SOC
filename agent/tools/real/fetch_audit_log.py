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
  - event_type: auditd 룰 key와 비교(대소문자 무시). 레코드 종류(EXECVE 등)·syscall 이름도 허용
  - exclude_interactive: session_type == "non_interactive"인 이벤트만 남김
    (관리자 세션뿐 아니라 판정 불가(None)도 제외 — 공통 정규화 함수와 동일한 의미)
  - include_user_cmd=False: USER_CMD 레코드가 포함된 이벤트 제외

필요 환경변수: AUDIT_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 AUDIT_LOG_BUCKET/S3
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List

from ..log_source import filtered_out_hint, load_window_events, pagination

FILTER_KEYS = ("pid", "ppid", "user", "serial", "event_type", "exclude_interactive", "include_user_cmd")
TOP_N = 5
# 웹 서버 프로세스 계정. 이 계정이 셸·다운로드를 실행하면 웹셸/원격 코드 실행 신호다(원칙 9 [침해 신호]).
WEB_SERVER_USERS = ("www-data", "apache", "nginx", "http")
SUSPICIOUS_CMD_RE = re.compile(
    r"(\bcurl\b|\bwget\b|\bnc\b|\bncat\b|/dev/tcp|bash -i|sh -c|base64|chmod \+x|python[0-9.]* -c|perl -e|"
    r"crontab|authorized_keys|useradd|/etc/shadow)",
    re.IGNORECASE,
)


def _top(counter: Counter) -> str:
    return ", ".join(f"{key} {count}건" for key, count in counter.most_common(TOP_N)) or "-"


def _command(record: Dict[str, Any]) -> str:
    return str(record.get("exec_args") or record.get("comm") or "")


def audit_rule_check(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """조건에 맞는 전체 이벤트(페이지와 무관) 기준 웹 서버 계정 실행·의심 명령 집계.

    로컬 재현(2026-09-24): audit 307건 중 첫 200건만 받은 실행이 뒤쪽의 www-data `curl | sh`를
    못 보고 "침해 없음"으로 끝냈다(1/3). 전체 기준으로 코드가 세서 summary와 rule_checks로 준다.
    """
    web_exec = [r for r in records if r.get("user") in WEB_SERVER_USERS and _command(r)]
    suspicious = [r for r in records if SUSPICIOUS_CMD_RE.search(_command(r))]
    web_suspicious = [r for r in web_exec if SUSPICIOUS_CMD_RE.search(_command(r))]
    return {
        "rule": "audit_post_exploitation",
        "web_server_exec": len(web_exec),
        "web_server_suspicious": len(web_suspicious),
        "suspicious": len(suspicious),
        "examples": [f"{r.get('user')}: {_command(r)[:80]} ({r.get('raw_ref')})"
                     for r in (web_suspicious or suspicious)[:3]],
    }


def _audit_stats(records: List[Dict[str, Any]], check: Dict[str, Any]) -> str:
    times = sorted(r["timestamp"] for r in records if r.get("timestamp"))
    users = Counter(r.get("user") or "-" for r in records)
    comms = Counter(r.get("comm") or "-" for r in records)
    return (
        f"이벤트 {len(records)}건(실제 기록 시각 {times[0] if times else '-'}~{times[-1] if times else '-'}), "
        f"실행 계정별: {_top(users)}, 명령별: {_top(comms)}. "
        f"[후속 침해 확인] 웹 서버 계정({'/'.join(WEB_SERVER_USERS)}) 실행 {check['web_server_exec']}건 중 "
        f"의심 명령 {check['web_server_suspicious']}건, 전체 의심 명령(curl/wget/sh -c//dev/tcp/crontab 등) "
        f"{check['suspicious']}건"
        + (f" — 예: {' / '.join(check['examples'])}" if check["examples"] else "")
        + ". (페이지와 무관한 전체 기준. 0건이 아니면 user나 pid로 다시 조회해 원본을 확인하십시오)"
    )


def _event_type_matches(record: Dict[str, Any], wanted: Any) -> bool:
    """event_type은 룰 key(exec 등)가 원래 의미지만, LLM이 레코드 종류(EXECVE/SYSCALL/PATH…)나
    syscall 이름(execve)을 넣는 경우도 받아준다. 0918 지속성 시나리오 재검증(2026-09-24)에서
    event_type="EXECVE"로 0건이 나오자 LLM이 "명령 실행 없음"으로 INCONCLUSIVE 판정한 사례가 있었다.
    """
    wanted = str(wanted).lower()
    candidates = [record.get("key"), record.get("syscall"), *(record.get("record_types") or [])]
    return any(str(c).lower() == wanted for c in candidates if c is not None)


def _matches(record: Dict[str, Any], args: Dict[str, Any]) -> bool:
    for key in ("pid", "ppid", "user", "serial"):
        if args.get(key) is not None and record.get(key) != args[key]:
            return False
    if args.get("event_type") is not None and not _event_type_matches(record, args["event_type"]):
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
        ) + filtered_out_hint(len(loaded["events"]), args, FILTER_KEYS)
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 audit 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, uid/euid/session_type/exec_args까지 구조화, "
            "1차 탐지팀 공통 정규화 함수 사용) "
            f"[조회 구간 전체 집계] {_audit_stats(matched, audit_rule_check(matched))}"
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
        "window_total": len(loaded["events"]),  # 필터 전 구간 전체 건수 — 0이면 로그 미확보
        **({"rule_checks": [audit_rule_check(matched)]} if matched else {}),
        **({"error": loaded["error"]} if loaded["error"] else {}),
    }
