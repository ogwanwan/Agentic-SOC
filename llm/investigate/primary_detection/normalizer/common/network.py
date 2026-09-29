"""Apache↔Suricata 요청 및 Suricata flow 매칭 공통 로직."""

from __future__ import annotations

import bisect
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from common.timeparse import parse_utc


def canonical_ip(value):
    """유효 IPv4/IPv6를 표준 문자열로 반환한다."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or candidate == "-":
        return None
    if len(candidate) >= 2 and candidate[0] == candidate[-1] == '"':
        candidate = candidate[1:-1].strip()
    if candidate.startswith("["):
        end = candidate.find("]")
        if end < 0:
            return None
        address, suffix = candidate[1:end], candidate[end + 1:]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return None
        candidate = address
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def raw_path_and_query(target):
    """요청 target을 path와 query로 나눈다. 선행 ``//``는 보존한다."""
    if not isinstance(target, str) or not target:
        return None, None
    if target.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(target)
        except ValueError:
            return None, None
        return parsed.path or "/", parsed.query or None
    path, separator, query = target.partition("?")
    path = path.split("#", 1)[0]
    return path, (query.split("#", 1)[0] if separator and query else None)


def normalize_method(value):
    return value.upper() if isinstance(value, str) else value


def normalize_status(value):
    if isinstance(value, bool):
        return value
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return value


@dataclass(frozen=True)
class ApacheRecord:
    timestamp: datetime
    timestamp_text: str
    event: dict
    src_ip: str
    method: object
    path: object
    status: object
    host: object
    request_id: object
    raw_ref: str


class ApacheIndex:
    """Apache 이벤트를 표준 IP와 UTC 시각으로 정렬한 검색 인덱스."""

    def __init__(self, events):
        records = []
        for event in events:
            if not isinstance(event, dict) or event.get("layer") != "web":
                continue
            layer_data = event.get("layer_data")
            timestamp = parse_utc(event.get("timestamp"))
            src_ip = canonical_ip(event.get("src_ip"))
            raw_ref = event.get("raw_ref")
            if (
                not isinstance(layer_data, dict)
                or timestamp is None
                or src_ip is None
                or raw_ref in (None, "")
            ):
                continue
            records.append(ApacheRecord(
                timestamp=timestamp,
                timestamp_text=event["timestamp"],
                event=event,
                src_ip=src_ip,
                method=normalize_method(layer_data.get("method")),
                path=raw_path_and_query(layer_data.get("path"))[0],
                status=normalize_status(layer_data.get("status")),
                host=layer_data.get("host"),
                request_id=layer_data.get("request_id"),
                raw_ref=str(raw_ref),
            ))

        self._by_ip = defaultdict(list)
        for record in records:
            self._by_ip[record.src_ip].append(record)
        self._times_by_ip = {}
        for src_ip, ip_records in self._by_ip.items():
            ip_records.sort(key=lambda item: (item.timestamp, item.raw_ref))
            self._times_by_ip[src_ip] = [item.timestamp for item in ip_records]
        self._all = sorted(records, key=lambda item: (item.timestamp, item.raw_ref))
        self._all_times = [item.timestamp for item in self._all]

    @staticmethod
    def _slice(records, times, timestamp, seconds):
        delta = timedelta(seconds=float(seconds))
        left = bisect.bisect_left(times, timestamp - delta)
        right = bisect.bisect_right(times, timestamp + delta)
        return records[left:right]

    def window(self, src_ip, timestamp, seconds):
        return self._slice(
            self._by_ip.get(src_ip, []),
            self._times_by_ip.get(src_ip, []),
            timestamp,
            seconds,
        )

    def window_without_ip(self, timestamp, seconds):
        return self._slice(self._all, self._all_times, timestamp, seconds)


def network_request(event):
    layer_data = event.get("layer_data", {})
    return {
        "method": normalize_method(layer_data.get("method")),
        "path": layer_data.get("url_path"),
        "status": normalize_status(layer_data.get("status")),
        "host": layer_data.get("http_host"),
    }


def request_matches(record, request):
    return (
        record.method == request["method"]
        and record.path == request["path"]
        and record.status == request["status"]
    )


def present(value):
    return value is not None and value != ""


def flow_key(event):
    layer_data = event.get("layer_data", {})
    sensor_id, flow_id = layer_data.get("sensor_id"), layer_data.get("flow_id")
    if not present(sensor_id) or not present(flow_id):
        return None
    return str(sensor_id), str(flow_id)


def transaction_key(event):
    key = flow_key(event)
    tx_id = event.get("layer_data", {}).get("tx_id")
    return key + (str(tx_id),) if key is not None and present(tx_id) else None


def transport_tuple(event):
    layer_data = event.get("layer_data", {})
    source_ip = canonical_ip(layer_data.get("transport_src_ip"))
    destination_ip = canonical_ip(
        layer_data.get("transport_dest_ip") or layer_data.get("dest_ip")
    )
    destination_port = layer_data.get("transport_dest_port")
    if not present(destination_port):
        destination_port = layer_data.get("dest_port")
    values = (
        source_ip,
        layer_data.get("transport_src_port"),
        destination_ip,
        destination_port,
        layer_data.get("protocol"),
    )
    if any(not present(value) for value in values):
        return None
    return tuple(str(value).lower() for value in values)


def same_transport(left, right):
    if left is None or right is None:
        return False
    src_ip, src_port, dst_ip, dst_port, protocol = right
    return left == right or left == (dst_ip, dst_port, src_ip, src_port, protocol)


def build_http_flow_index(events):
    """Suricata HTTP 이벤트를 transaction 키와 flow 키로 인덱싱한다."""
    exact, by_flow = defaultdict(list), defaultdict(list)
    for event in events:
        layer_data = event.get("layer_data") if isinstance(event, dict) else None
        if (
            not isinstance(layer_data, dict)
            or event.get("layer") != "network"
            or layer_data.get("event_type") != "http"
            or event.get("raw_ref") in (None, "")
        ):
            continue
        key = flow_key(event)
        if key is None:
            continue
        record = {
            "event": event,
            "raw_ref": str(event["raw_ref"]),
            "timestamp": parse_utc(event.get("timestamp")),
            "transport_tuple": transport_tuple(event),
        }
        by_flow[key].append(record)
        tx_key = transaction_key(event)
        if tx_key is not None:
            exact[tx_key].append(record)

    order = lambda record: (
        record["timestamp"] or datetime.min.replace(tzinfo=timezone.utc),
        record["raw_ref"],
    )
    for records in (*exact.values(), *by_flow.values()):
        records.sort(key=order)
    return {"exact": dict(exact), "by_flow": dict(by_flow)}


def find_http_flow_matches(alert, index, fallback_seconds):
    """Alert와 안전하게 연결되는 HTTP record 및 매칭 정보를 반환한다."""
    if isinstance(fallback_seconds, bool) or not isinstance(fallback_seconds, (int, float)):
        raise ValueError("fallback_seconds는 0 이상의 숫자여야 함")
    if fallback_seconds < 0 or not isinstance(alert, dict):
        if fallback_seconds < 0:
            raise ValueError("fallback_seconds는 0 이상이어야 함")
        return []

    alert_time = parse_utc(alert.get("timestamp"))
    tx_key = transaction_key(alert)
    if tx_key is not None:
        records = index.get("exact", {}).get(tx_key, [])
        return [{
            "record": record,
            "match_mode": "sensor_flow_tx",
            "candidate_count": len(records),
            "dt_sec": abs((record["timestamp"] - alert_time).total_seconds())
            if alert_time is not None and record["timestamp"] is not None else None,
        } for record in records]

    key, alert_tuple = flow_key(alert), transport_tuple(alert)
    if key is None or alert_time is None or alert_tuple is None:
        return []
    candidates = []
    for record in index.get("by_flow", {}).get(key, []):
        if record["timestamp"] is None or not same_transport(alert_tuple, record["transport_tuple"]):
            continue
        delta = abs((record["timestamp"] - alert_time).total_seconds())
        if delta <= float(fallback_seconds):
            candidates.append((record, delta))
    if len(candidates) != 1:
        return []
    record, delta = candidates[0]
    return [{
        "record": record,
        "match_mode": "flow_tuple_time_fallback",
        "candidate_count": 1,
        "dt_sec": delta,
    }]
