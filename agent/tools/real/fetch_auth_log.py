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

summary 끝의 [조회 구간 전체 집계]는 페이지와 무관하게 조건에 맞는 전체 이벤트 기준
로그인 실패 횟수·실패 대상 계정 수·성공 횟수를 준다(원칙 7 Q1에 그대로 쓰도록).

필드 주의: 공통 정규화 스키마는 event(ssh_accepted/ssh_failed/ssh_invalid_user/
pam_auth_failure/sudo_command/su_failure 등 세분화된 값)·src_ip·raw_ref를 쓴다.
도구 인자 event_type은 이 event 값과 비교한다.

필요 환경변수: AUTH_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 AUTH_LOG_BUCKET/S3
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from ..log_source import filtered_out_hint, load_window_events, pagination

# 로그인 "시도" 1회로 세는 event. 실패 1회는 보통 PAM 인증 실패·Failed password·연결 종료
# 3줄로 남는데, LLM이 이를 1회/3회로 제각각 세서 판정이 갈렸다(2026-09-24). 그래서
# 세는 기준을 코드로 고정하고 summary에 숫자로 준다.
FAILED_LOGIN_EVENTS = ("ssh_failed", "ssh_invalid_user")
SUCCESS_LOGIN_EVENTS = ("ssh_accepted",)
# 계정 없이 끊긴 연결·배너 교환 실패 등(공통 정규화 주석: "스캐너 탐침"). ssh_auth_fail_close
# ("authenticating user root ... [preauth]")는 키 전용 서버에서 실제 인증 시도라 탐침으로 보지 않는다.
PROBE_EVENTS = ("ssh_probe", "ssh_disconnect")
AUTH_ATTEMPT_WITHOUT_FAILED = ("ssh_auth_fail_close", "ssh_max_auth")
# 실패 대상 계정 이름은 이만큼만 나열한다. EC2 24시간 조회에서 325개 계정이 전부 summary에
# 들어가 프롬프트가 불필요하게 커졌다(2026-09-24). 개수는 항상 전체 기준이다.
MAX_LISTED_USERS = 20
EMPTY_USER = "(빈 계정명)"
# 원칙 7(로그인 성공 없이 실패만 있는 경우) 기준. investigation.yaml 원칙 7과 같은 값이다.
BRUTEFORCE_FAILURES = 5
BRUTEFORCE_ACCOUNTS = 2


def principle7_check(records: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """출발지 IP 하나로 좁혀진 조회에서, 로그인 성공이 없을 때 원칙 7 판정 기준을 코드로 계산한다.

    EC2(2026-09-25): root 실패 2회·성공 0회인데 LLM이 원칙 7(1~4회·계정 1개 → FALSE_POSITIVE)을
    어기고 THREAT_CONFIRMED로 판정했다. 원칙 9처럼 기준 충족 여부를 summary와 rule_checks로 준다.
    성공이 있으면 Q2/Q3(인증 방식·후속 행위) 판단이 필요해 코드 기준을 내지 않는다.
    """
    src_ips = {r.get("src_ip") for r in records if r.get("src_ip")}
    if len(src_ips) != 1:
        return None
    failed = [r for r in records if r.get("event") in FAILED_LOGIN_EVENTS]
    successes = sum(1 for r in records if r.get("event") in SUCCESS_LOGIN_EVENTS)
    # 실패 0회라도 접속 흔적(스캐너 탐침: 계정 없이 끊긴 연결 등)이 있으면 "시도 없음 = 단발성 이하"로 판정한다.
    # EC2(2026-09-25): ssh_probe 2건뿐인 사건을 규칙이 없어 INCONCLUSIVE로 판정했다.
    probes = [r for r in records if r.get("event") in PROBE_EVENTS]
    if successes or not (failed or probes):
        return None
    if not failed and (len(probes) >= BRUTEFORCE_FAILURES
                       or any(r.get("event") in AUTH_ATTEMPT_WITHOUT_FAILED for r in records)):
        # 탐침이 많거나 키 전용 서버의 인증 시도 흔적이 있으면 코드 기준을 내지 않고 LLM 판단에 맡긴다
        return None
    accounts = len({r.get("user") or EMPTY_USER for r in failed})
    bruteforce = len(failed) >= BRUTEFORCE_FAILURES or accounts >= BRUTEFORCE_ACCOUNTS
    return {
        "rule": "principle_7",
        "src_ip": next(iter(src_ips)),
        "failures": len(failed),
        "accounts": accounts,
        "successes": 0,
        "probes": len(probes),
        "bruteforce": bruteforce,
        "sporadic": not bruteforce,
    }


def _principle7_text(check: Dict[str, Any] | None) -> str:
    if not check:
        return ""
    if check["bruteforce"]:
        verdict = "충족 → THREAT_CONFIRMED(SSH 무차별 대입 시도, 로그인 성공 없음)"
    elif check["failures"] == 0:
        verdict = (f"미충족(로그인 시도 없이 접속만 {check['probes']}건 — 인터넷 스캐너 탐침) → 다른 계층에 "
                   "공격 정황이 없으면 FALSE_POSITIVE")
    else:
        verdict = "미충족(단발성 실패) → 다른 계층에 공격 정황이 없으면 FALSE_POSITIVE"
    return (f" [원칙 7 기준] {check['src_ip']}: 로그인 성공 0회, 실패 {check['failures']}회·계정 {check['accounts']}개 "
            f"(기준: 실패 {BRUTEFORCE_FAILURES}회 이상 또는 계정 {BRUTEFORCE_ACCOUNTS}개 이상) — {verdict}.")


def _login_stats(records: List[Dict[str, Any]]) -> str:
    counts = Counter(r.get("event") for r in records)
    failed = [r for r in records if r.get("event") in FAILED_LOGIN_EVENTS]
    # 스캐너는 "Invalid user  from ..."처럼 빈 계정명으로 시도하기도 한다. 공통 정규화는 이때
    # user 필드를 아예 빼므로, 계정명 없는 실패도 계정 1개로 센다 (EC2 2026-09-24: 실패 1회인데
    # "계정 0개"로 나와 앞뒤가 안 맞았다).
    failed_users = sorted({r.get("user") or EMPTY_USER for r in failed})
    listed = ", ".join(failed_users[:MAX_LISTED_USERS]) or "-"
    if len(failed_users) > MAX_LISTED_USERS:
        listed += f" 외 {len(failed_users) - MAX_LISTED_USERS}개"
    by_event = ", ".join(f"{event} {count}건" for event, count in counts.most_common() if event)
    return (
        f"로그인 실패 {len(failed)}회(ssh_failed+ssh_invalid_user 기준), "
        f"실패 대상 계정 {len(failed_users)}개({listed}), "
        f"로그인 성공 {sum(counts[e] for e in SUCCESS_LOGIN_EVENTS)}회. event별: {by_event}"
    )


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
    check = principle7_check(matched)
    page = matched[offset : offset + limit]
    has_more = offset + len(page) < total_matched
    next_offset = offset + len(page) if has_more else None

    if loaded["error"] == "permission_denied":
        summary = f"{host}의 auth 로그 파일 읽기 권한이 없습니다. AUTH_LOG_LOCAL_PATH 권한을 확인하세요."
    elif total_matched == 0:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 인증 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 AUTH_LOG_LOCAL_PATH/AUTH_LOG_BUCKET 설정을 확인하세요."
        ) + filtered_out_hint(len(loaded["events"]), args, ("user", "src_ip", "result", "event_type"))
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 인증 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, event/result까지 구조화, "
            "1차 탐지팀 공통 정규화 함수 사용) "
            f"[조회 구간 전체 집계] {_login_stats(matched)}"
            f"{_principle7_text(check)}"
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
        **({"rule_checks": [check]} if check else {}),
        **({"error": loaded["error"]} if loaded["error"] else {}),
    }
