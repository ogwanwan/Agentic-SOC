"""
tools/fetch_network_log.py
도구 본체. raw Suricata eve.json(JSONL)을 읽어 조건에 맞는 네트워크(network) 이벤트를
공통스키마 dict 리스트로 반환한다. "가져오기 + 파싱"만 한다.

설계 근거: 'Suricata EC2 로그 파싱·Apache 결합 설계(2026-09-16)'.
  - event_type == http|alert 만 결합 입력으로 선택(dns/flow/stats/fileinfo 는 버림).
  - X-Forwarded-For 체인을 해석해 실 클라이언트(join_src_ip)를 상단 src_ip 로 승격.
    · top-level xff 가 유효하고 http.xff 체인의 구성원이면 그 값 채택.
    · top-level 이 없으면 체인의 마지막 유효 IP 채택.
    · top-level 이 체인과 충돌하면 승격 안 함(src_ip=None, xff_status=conflict).
    · src_ip=127.0.0.1(loopback)은 절대 외부 IP로 승격하지 않는다(전 행 loopback).
  - flow_id/community_id/transport 5튜플/alert.signature/원문 URL 은 layer_data 에 증거로 보존.
  - raw_ref="eve.json:<줄번호>", timestamp 는 UTC. 타임존 없거나 파싱 실패면 버린다(정렬축 없음).

원칙(다른 fetch_*_log 와 동일): 판단/스코어링/LLM 없음. 결정론.
Suricata 신규 Sigma 룰은 없다 — alert.signature 를 교차검증 증거로 쓴다.
"""

import os
import json
from datetime import datetime, timezone

# 스크립트 직접 실행도 되게 레포 루트를 path 에 올린다.
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # dotenv 선택 의존성
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # pragma: no cover
    pass

from tools.base import success, failure
from tools.registry import register
from common.network import canonical_ip, raw_path_and_query
from common.schema import build_event
from tools.log_sources import log_name, open_log_text
from common.timeparse import normalize_iso

SURICATA_LOG_PATH = os.getenv("SURICATA_LOG_PATH", "/var/log/suricata/eve.json")
SENSOR_ID = os.getenv("SURICATA_SENSOR_ID", "suricata_ec2")

_SELECTED_EVENT_TYPES = frozenset({"http", "alert"})


# --- XFF/IP 해석 (설계 문서 로직 이식) ----------------------------------------
def parse_xff_chain(value):
    """XFF 체인 문자열 → (표준화 IP 리스트, status). 한 토큰이라도 무효면 invalid."""
    if not isinstance(value, str) or not value.strip() or value.strip() == "-":
        return [], "missing"
    tokens = [t.strip() for t in value.split(",")]
    if not tokens or any(not t for t in tokens):
        return [], "invalid"
    addrs = [canonical_ip(t) for t in tokens]
    if any(a is None for a in addrs):
        return [], "invalid"
    return addrs, "valid"


def resolve_xff(top_level, nested):
    """top-level xff 와 http.xff 체인을 대조해 실 클라이언트 IP를 고른다."""
    chain, chain_status = parse_xff_chain(nested)
    top_chain, top_status = parse_xff_chain(top_level)
    top = top_chain[0] if top_status == "valid" and len(top_chain) == 1 else None

    selected, resolution, source, status = None, "missing", None, "missing"
    if chain_status == "invalid" or top_status == "invalid" or len(top_chain) > 1:
        status = "invalid"
    elif top is not None:
        if chain_status == "valid" and top not in chain:
            resolution, status = "conflict", "conflict"
        else:
            selected, resolution, source, status = top, "direct", "top_level", "valid"
    elif chain_status == "valid" and chain:
        selected, resolution, source, status = chain[-1], "direct", "nested_last", "valid"

    return {
        "http_xff_raw": nested if isinstance(nested, str) else None,
        "xff_ips": chain,
        "selected": selected,
        "resolution": resolution,
        "selected_from": source,
        "status": status,
    }


# --- 작은 헬퍼 ----------------------------------------------------------------
def _int_or_none(v):
    return v if isinstance(v, int) else None


def _parse_ts(value):
    """ISO8601(타임존 필수) → 'YYYY-MM-DDTHH:MM:SS.ffffffZ'(UTC). 실패/타임존없음 → None."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(normalize_iso(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _iso_to_dt(iso_str):
    if iso_str is None:
        return None
    dt = datetime.fromisoformat(normalize_iso(iso_str))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- 1. EVE 한 행 → 공통스키마 network 이벤트 ---------------------------------
def normalize_row(row, log_name, lineno, sensor_id=SENSOR_ID):
    """EVE dict 한 개 → 공통스키마 dict. http/alert 아니거나 시각 무효면 None(스킵)."""
    et = row.get("event_type")
    if et not in _SELECTED_EVENT_TYPES:
        return None

    ts = _parse_ts(row.get("timestamp"))
    if ts is None:
        return None

    http = row.get("http") if isinstance(row.get("http"), dict) else {}
    alert = row.get("alert") if isinstance(row.get("alert"), dict) else {}
    xff = resolve_xff(row.get("xff"), http.get("xff"))
    src_ip = xff["selected"]  # 승격된 실 클라이언트(None 가능). loopback 은 절대 아님.

    path, query = raw_path_and_query(http.get("url"))

    layer_data = {
        "event_type":   et,
        # alert 증거
        "signature":    alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "category":     alert.get("category"),
        "severity":     alert.get("severity"),
        "action":       alert.get("action"),
        # flow 조인키
        "flow_id":      row.get("flow_id"),
        "community_id": row.get("community_id"),
        "in_iface":     row.get("in_iface"),
        "tx_id":        row.get("tx_id"),
        # http
        "method":       http.get("http_method") or http.get("method"),
        "url":          http.get("url") if isinstance(http.get("url"), str) else None,
        "url_path":     path,
        "url_query":    query,
        "status":       _int_or_none(http.get("status")),
        "http_host":    http.get("hostname"),
        "http_user_agent": http.get("http_user_agent"),
        "http_version": http.get("protocol"),
        # transport 5튜플(원본, 조인 검증용) — loopback 이라 상단 승격 안 함
        "dest_ip":      canonical_ip(row.get("dest_ip")),
        "dest_port":    _int_or_none(row.get("dest_port")),
        "transport_src_ip":   row.get("src_ip"),
        "transport_src_port": _int_or_none(row.get("src_port")),
        "transport_dest_port": _int_or_none(row.get("dest_port")),
        "protocol":     row.get("proto"),
        # XFF 근거 보존
        "xff_raw":        xff["http_xff_raw"],
        "xff_ips":        xff["xff_ips"],
        "xff_resolution": xff["resolution"],
        "xff_status":     xff["status"],
        "sensor_id":    sensor_id,
    }

    return build_event(
        timestamp=ts,
        layer="network",
        raw_ref="%s:%d" % (log_name, lineno),
        src_ip=src_ip,
        layer_data=layer_data,
    )


# --- 2. 필터 매칭 -------------------------------------------------------------
def match_filter(event, filters):
    ld = event["layer_data"]
    tw = filters.get("time_window")
    if tw:
        start, end = tw
        ev_dt = _iso_to_dt(event["timestamp"])
        if start is not None and ev_dt < _iso_to_dt(start):
            return False
        if end is not None and ev_dt > _iso_to_dt(end):
            return False
    if filters.get("src_ip") is not None and event.get("src_ip") != filters["src_ip"]:
        return False
    if filters.get("event_type") is not None and ld.get("event_type") != filters["event_type"]:
        return False
    if filters.get("flow_id") is not None and ld.get("flow_id") != filters["flow_id"]:
        return False
    if filters.get("signature") is not None:
        sig = ld.get("signature") or ""
        if filters["signature"] not in sig:
            return False
    return True


# --- 3. 오케스트레이터(순수 함수) ----------------------------------------------
def fetch_network_log(
    log_path,
    time_window=None,
    src_ip=None,
    event_type=None,
    flow_id=None,
    signature=None,
    sensor_id=SENSOR_ID,
):
    """raw Suricata eve.json 을 읽어 조건에 맞는 network 이벤트를 공통스키마 리스트로 반환.

    필터 전부 optional(log_path만 필수), AND 결합.
      time_window : [start_iso, end_iso] UTC(경계 포함)
      src_ip      : 승격된 실 클라이언트 IP 정확일치
      event_type  : http | alert
      flow_id     : alert↔http 조인용 flow_id(int) 정확일치
      signature   : alert.signature 부분일치
    """
    name = log_name(log_path)
    filters = {
        "time_window": time_window, "src_ip": src_ip, "event_type": event_type,
        "flow_id": flow_id, "signature": signature,
    }
    events = []
    with open_log_text(log_path) as f:  # 평문·.gz 모두
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue  # 깨진 JSON 줄은 건너뛴다
            if not isinstance(row, dict):
                continue
            event = normalize_row(row, name, lineno, sensor_id=sensor_id)
            if event is None:
                continue
            if match_filter(event, filters):
                events.append((event["timestamp"], lineno, event))
    events.sort(key=lambda t: (t[0], t[1]))
    return [e for _, _, e in events]


# --- 4. 도구 등록 -------------------------------------------------------------
@register(
    name="fetch_network_log",
    description=(
        "raw Suricata eve.json(JSONL)을 읽어 조건에 맞는 네트워크(network) 이벤트를 공통스키마로 반환한다. "
        "http/alert 만 선택하고, X-Forwarded-For 체인을 해석해 실 클라이언트를 src_ip 로 승격한다(loopback 승격 금지). "
        "필터: time_window/src_ip/event_type/flow_id/signature. 판단은 하지 않는다(조회 전용)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "log_path": {"type": "string", "description": "eve.json 경로. 생략 시 .env SURICATA_LOG_PATH."},
            "time_window": {"type": "array", "items": {"type": "string"},
                            "description": "[start_iso, end_iso] UTC(경계 포함)."},
            "src_ip": {"type": "string", "description": "승격된 실 클라이언트 IP 정확일치."},
            "event_type": {"type": "string", "enum": ["http", "alert"]},
            "flow_id": {"type": "integer", "description": "alert↔http 조인용 flow_id."},
            "signature": {"type": "string", "description": "alert.signature 부분일치."},
        },
        "required": [],
    },
)
def fetch_network_log_tool(log_path: str = None, **filters) -> dict:
    path = log_path or SURICATA_LOG_PATH
    try:
        events = fetch_network_log(path, **filters)
    except FileNotFoundError:
        return failure("suricata 로그 없음: %s" % path)
    except Exception as exc:
        return failure("suricata 파싱 실패: %s" % exc)
    return success({"count": len(events), "events": events})


# --- 자체 데모: python tools/fetch_network_log.py -----------------------------
if __name__ == "__main__":
    demo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_eve.json")
    if os.path.exists(demo):
        for e in fetch_network_log(demo):
            ld = e["layer_data"]
            print("%s  %-5s src_ip=%-15s %s  %s" % (
                e["timestamp"], ld["event_type"], e["src_ip"],
                ld.get("signature") or (ld.get("method"), ld.get("url_path")),
                "flow=%s" % ld["flow_id"]))
