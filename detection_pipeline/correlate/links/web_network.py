"""Apache↔Suricata HTTP strong edge 생성.

Suricata의 검증된 XFF ``src_ip``와 Apache ``%a``를 표준화해 비교하고, UTC 시각과
method/path/status가 일치하는 유일한 후보만 자동 연결한다.
"""

from common.network import (
    ApacheIndex,
    canonical_ip,
    network_request,
    request_matches,
)
from common.timeparse import parse_utc
from correlate.registry import register_linker


JOIN = "web_network"
DEFAULT_SECONDS = 1.0


@register_linker
def web_network_edges(events, seconds=DEFAULT_SECONDS):
    """검증된 XFF/IP와 요청 정보가 일치하는 유일한 strong edge만 반환한다."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError("seconds는 0 이상의 숫자여야 함")
    if seconds < 0:
        raise ValueError("seconds는 0 이상이어야 함")

    event_list = list(events)
    apache_index = ApacheIndex(event_list)
    network_http = []
    for event in event_list:
        if not isinstance(event, dict) or event.get("layer") != "network":
            continue
        layer_data = event.get("layer_data")
        if (
            not isinstance(layer_data, dict)
            or layer_data.get("event_type") != "http"
            or event.get("raw_ref") in (None, "")
        ):
            continue
        network_http.append(event)
    network_http.sort(
        key=lambda event: (str(event.get("timestamp") or ""), str(event["raw_ref"]))
    )

    edges = []
    for network_event in network_http:
        layer_data = network_event["layer_data"]
        if layer_data.get("xff_status") != "valid":
            continue
        timestamp = parse_utc(network_event.get("timestamp"))
        src_ip = canonical_ip(network_event.get("src_ip"))
        if timestamp is None or src_ip is None:
            continue

        request = network_request(network_event)
        if any(request[key] in (None, "") for key in ("method", "path", "status")):
            continue
        candidates = [
            record
            for record in apache_index.window(src_ip, timestamp, seconds)
            if request_matches(record, request)
        ]
        if len(candidates) != 1:
            continue

        apache = candidates[0]
        dt_sec = abs((apache.timestamp - timestamp).total_seconds())
        edges.append({
            "a": apache.raw_ref,
            "b": str(network_event["raw_ref"]),
            "join": JOIN,
            "keys": {
                "grade": "strong",
                "src_ip": src_ip,
                "dt_sec": round(dt_sec, 6),
                "method": request["method"],
                "path": request["path"],
                "status": request["status"],
                "sensor_id": layer_data.get("sensor_id"),
                "flow_id": layer_data.get("flow_id"),
                "tx_id": layer_data.get("tx_id"),
            },
        })

    unique = {}
    for edge in edges:
        unique[(edge["a"], edge["b"], edge["join"])] = edge
    return [unique[key] for key in sorted(unique)]


__all__ = ["DEFAULT_SECONDS", "web_network_edges"]
