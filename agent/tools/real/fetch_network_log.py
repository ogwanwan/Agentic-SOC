"""fetch_network_log 실제 구현 - 에이전트(LLM)가 조사 중 호출하는 네트워크(Suricata eve.json) 조회 도구.

파일명 == 함수명 규칙에 따라 agent/tools/registry.py의 build_default_registry()가
mock_tools.py 대신 이 함수를 자동으로 사용한다. (agent/tools/real/README.md 참고)

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
    퇴보, 2026-09-24 수정).
  - ip: 방향 무관 — src_ip/transport_src_ip/dest_ip 중 하나와 일치. 공격자 IP가 출발지(inbound
    공격)인지 목적지(역방향 셸·유출 등 outbound)인지 모를 때 쓴다. 2026-09-24 0918 시나리오
    비교에서 src_ip로만 사전 조회하자 outbound 역방향 셸 alert를 놓쳐 추가했다.
  - dst_ip → dest_ip, src_port → transport_src_port, dst_port → transport_dest_port
  - protocol: 대소문자 무시 일치
  - alert_only: event_type == "alert"인 이벤트만

direction(internal/outbound/inbound)은 계산하지 않는다 — 호스트 IP 사전 등록 단계가
우리 시스템엔 없고, 공통 정규화 스키마에도 그 필드가 없다.

필요 환경변수: NETWORK_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 NETWORK_LOG_BUCKET/S3
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..log_source import filtered_out_hint, load_window_events, pagination

_PORT_FIELDS = {"src_port": "transport_src_port", "dst_port": "transport_dest_port"}


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


def fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit, offset = pagination(args)

    loaded = load_window_events("network", host, start_time, end_time)
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
            "host 이름, 기간, 또는 NETWORK_LOG_LOCAL_PATH/NETWORK_LOG_BUCKET 설정을 확인하세요."
        ) + filtered_out_hint(len(loaded["events"]), args,
                              ("ip", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "alert_only"))
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={next_offset})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 네트워크 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, http 이벤트는 url/method/status/xff까지 포함, "
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
