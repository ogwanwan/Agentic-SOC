"""Suricata 내부 Alert↔HTTP 연결.

정확 키는 sensor_id + flow_id + tx_id. Alert에 tx_id가 없을 때만 같은 sensor/flow,
같은 전송 5튜플, 제한된 시간창 안의 유일한 HTTP 후보를 보수적으로 연결한다.
"""

from common.network import build_http_flow_index, find_http_flow_matches, flow_key
from correlate.registry import register_linker


JOIN = "suricata_flow"
DEFAULT_FALLBACK_SECONDS = 5.0


def _edge(alert, http, match_mode, candidate_count, dt_sec):
    layer_data = alert["layer_data"]
    return {
        "a": str(alert["raw_ref"]),
        "b": http["raw_ref"],
        "join": JOIN,
        "keys": {
            "match_mode": match_mode,
            "sensor_id": layer_data.get("sensor_id"),
            "flow_id": layer_data.get("flow_id"),
            "tx_id": layer_data.get("tx_id"),
            "dt_sec": round(dt_sec, 6) if dt_sec is not None else None,
            "candidate_count": candidate_count,
        },
    }


@register_linker
def suricata_flow_edges(events, fallback_seconds=DEFAULT_FALLBACK_SECONDS):
    """정규화된 이벤트에서 Suricata Alert↔HTTP edge를 만든다."""
    index = build_http_flow_index(events)
    alerts = []
    for event in events:
        if not isinstance(event, dict) or event.get("layer") != "network":
            continue
        layer_data = event.get("layer_data")
        if not isinstance(layer_data, dict) or event.get("raw_ref") in (None, ""):
            continue
        if layer_data.get("event_type") == "alert" and flow_key(event) is not None:
            alerts.append(event)
    alerts.sort(key=lambda event: (str(event.get("timestamp") or ""), str(event["raw_ref"])))

    edges = []
    for alert in alerts:
        for match in find_http_flow_matches(alert, index, fallback_seconds):
            edges.append(_edge(
                alert,
                match["record"],
                match["match_mode"],
                match["candidate_count"],
                match["dt_sec"],
            ))

    unique = {}
    for edge in edges:
        unique[(edge["a"], edge["b"], edge["join"])] = edge
    return [unique[key] for key in sorted(unique)]


__all__ = ["DEFAULT_FALLBACK_SECONDS", "suricata_flow_edges"]
