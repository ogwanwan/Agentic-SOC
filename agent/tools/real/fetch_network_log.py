"""fetch_network_log 실제 구현 - 에이전트(LLM)가 조사 중 호출하는 네트워크(Suricata eve.json) 조회 도구.

누가 부르나
  [31] agent/tools/registry.py ToolRegistry.call("fetch_network_log", args) ← agent/loop.py [30]
       (LLM이 이 도구를 골랐을 때, 또는 network 사전 조회 [19-1])
  agent/tools/real/fetch_event_logs.py (사건 구간 다계층 조회 때 이 함수를 직접 부른다)

무엇을 부르나
  [33] agent/tools/log_source.py load_window_events("network", ...)  Suricata eve.json 읽기 + 정규화 + 시간창 필터
       → agent/tools/normalizer_adapter.py → primary_detection/normalizer/tools/fetch_network_log.py

파일명 == 함수명 규칙이라 agent/tools/registry.py가 mock_tools.py 대신 이 함수를 자동으로 쓴다.

역할 분담:
  - 원본 읽기 + 정규화: agent/tools/log_source.load_window_events()
      → normalizer_adapter.normalize_log_documents()
      → primary_detection/normalizer/tools/fetch_network_log.py (1차 탐지팀 공통 정규화 함수)
    에이전트 자체 파서(구 parsers/network_parser.py)는 쓰지 않는다.
  - 이 파일(에이전트 도구): 도구 인자 해석, 필터, limit/offset 페이지네이션,
    LLM에게 돌려줄 summary/반환 형식.

필터 의미 (공통 정규화 스키마 필드명으로 변환해서 비교):
  - src_ip: 공통 정규화의 src_ip(XFF로 복원한 실 클라이언트) 또는 transport_src_ip(패킷의
    실제 출발지) 중 하나와 일치. 공통 정규화는 XFF가 없는 alert 이벤트의 src_ip를 비워두기
    때문에, src_ip만 보면 공격자 IP로 거른 inbound alert가 0건이 된다(9/18 자체 파서 대비
    퇴보, 수정).
  - ip: 방향 무관 — src_ip/transport_src_ip/dest_ip 중 하나와 일치. 공격자 IP가 출발지(inbound
    공격)인지 목적지(역방향 셸·유출 등 outbound)인지 모를 때 쓴다. 0918 시나리오
    비교에서 src_ip로만 사전 조회하자 outbound 역방향 셸 alert를 놓쳐 추가했다.
  - dst_ip → dest_ip, src_port → transport_src_port, dst_port → transport_dest_port
  - protocol: 대소문자 무시 일치
  - alert_only: event_type == "alert"인 이벤트만

direction(internal/outbound/inbound)은 계산하지 않는다 — 호스트 IP 사전 등록 단계가
우리 시스템엔 없고, 공통 정규화 스키마에도 그 필드가 없다.

필요 환경변수: NETWORK_LOG_LOCAL_PATH (읽을 Suricata eve.json 경로)
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from ..log_source import filtered_out_hint, load_window_events, pagination

_PORT_FIELDS = {"src_port": "transport_src_port", "dst_port": "transport_dest_port"}
TOP_N = 5


def _top(counter: Counter) -> str:
    return ", ".join(f"{key} {count}건" for key, count in counter.most_common(TOP_N)) or "-"


def _network_stats(records: List[Dict[str, Any]]) -> str:
    """조건에 맞는 전체 이벤트(페이지와 무관) 집계. web/auth 도구와 같은 방식으로, records를 다
    읽지 않아도 규모·경보·목적지를 판단할 수 있게 한다. EC2 xmlrpc 사건에서 150건이
    records로 통째로 LLM에게 가 응답이 잘린 뒤 추가했다."""
    times = sorted(r["timestamp"] for r in records if r.get("timestamp"))
    alerts = Counter(r.get("signature") or "-" for r in records if r.get("event_type") == "alert")
    http = [r for r in records if r.get("event_type") == "http"]
    statuses = Counter(f"{r['status'] // 100}xx" if isinstance(r.get("status"), int) else "-" for r in http)
    paths = Counter(r.get("url_path") or "-" for r in http)
    peers = Counter(f"{r.get('dest_ip')}:{r.get('dest_port')}" for r in records if r.get("dest_ip"))
    return (
        f"이벤트 {len(records)}건(실제 기록 시각 {times[0] if times else '-'}~{times[-1] if times else '-'}), "
        f"종류별: {_top(Counter(r.get('event_type') or '-' for r in records))}, "
        f"alert signature: {_top(alerts)}, "
        f"http 상태코드 계열: {_top(statuses)}, http 상위 경로: {_top(paths)}, "
        f"목적지 상위: {_top(peers)}"
    )


def _matches(record: Dict[str, Any], args: Dict[str, Any]) -> bool:
    if args.get("ip") is not None and args["ip"] not in (
        record.get("src_ip"), record.get("transport_src_ip"), record.get("dest_ip")
    ):
        return False
    if args.get("src_ip") is not None and args["src_ip"] not in (record.get("src_ip"), record.get("transport_src_ip")):
        return False
    if args.get("dst_ip") is not None and record.get("dest_ip") != args["dst_ip"]:
        return False
    for key, field in _PORT_FIELDS.items():
        if args.get(key) is not None and record.get(field) != int(args[key]):
            return False
    if args.get("protocol") is not None and str(record.get("protocol") or "").upper() != str(args["protocol"]).upper():
        return False
    if args.get("alert_only") and record.get("event_type") != "alert":
        return False
    return True


# [32] ← registry.call() [31]에서 호출. 반환 dict는 loop.py [37]로 간다.
def fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit, offset = pagination(args)

    # [33] → log_source.load_window_events(): 파일 읽기 → [34] 1차 탐지팀 정규화 → 구간 안 이벤트
    loaded = load_window_events("network", host, start_time, end_time)
    # [35] 도구 인자로 거르고(_matches), 페이지로 자르고, summary·rule_checks를 만든다
    matched: List[Dict[str, Any]] = [e for e in loaded["events"] if _matches(e, args)]

    total_matched = len(matched)
    page = matched[offset : offset + limit]
    has_more = offset + len(page) < total_matched
    next_offset = offset + len(page) if has_more else None

    if loaded["error"] == "permission_denied":
        summary = f"{host}의 network 로그 파일 읽기 권한이 없습니다. NETWORK_LOG_LOCAL_PATH 권한을 확인하세요."
    elif total_matched == 0:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 네트워크 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 NETWORK_LOG_LOCAL_PATH 설정을 확인하세요."
        ) + filtered_out_hint(len(loaded["events"]), args,
                              ("ip", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "alert_only"))
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 네트워크 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, http 이벤트는 url/method/status/xff까지 포함, "
            "1차 탐지팀 공통 정규화 함수 사용) "
            f"[조회 구간 전체 집계] {_network_stats(matched)}"
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
        **({"error": loaded["error"]} if loaded["error"] else {}),
    }
