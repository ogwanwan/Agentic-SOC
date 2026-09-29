"""Apache 요청과 Suricata HTTP 이벤트를 보수적으로 연결한다.

Suricata Alert는 먼저 :mod:`detect.suricata_flow`에서 ``sensor_id``와
``flow_id``(가능하면 ``tx_id``까지)로 HTTP 이벤트에 연결된다. 이 모듈은 그
HTTP 이벤트를 Apache 요청과 연결하며, 신뢰 가능한 자동 edge는 ``strong``
등급 한 건만 허용한다.
"""

from __future__ import annotations

import hashlib

from common.network import (
    ApacheIndex,
    canonical_ip,
    network_request,
    request_matches,
)
from common.timeparse import parse_utc


DEFAULT_STRONG_SECONDS = 1.0
DEFAULT_FALLBACK_SECONDS = 2.0
DEFAULT_LONG_DELAY_SECONDS = 900.0


def _validate_windows(strong_seconds, fallback_seconds, long_delay_seconds):
    values = (strong_seconds, fallback_seconds, long_delay_seconds)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in values):
        raise ValueError("correlation window는 숫자여야 함")
    if strong_seconds < 0 or fallback_seconds < strong_seconds:
        raise ValueError("0 <= strong_seconds <= fallback_seconds 이어야 함")
    if long_delay_seconds < fallback_seconds:
        raise ValueError("fallback_seconds <= long_delay_seconds 이어야 함")


def _classify(index, src_ip, timestamp, request, strong_seconds, fallback_seconds,
              long_delay_seconds):
    near_strong = index.window(src_ip, timestamp, strong_seconds)
    exact_strong = [record for record in near_strong if request_matches(record, request)]
    if len(exact_strong) == 1:
        return "strong", "exact_unique_within_strong_window", exact_strong, [
            "src_ip", "method", "path", "status",
        ]
    if len(exact_strong) > 1:
        return "ambiguous_cluster", "exact_multiple_within_strong_window", exact_strong, [
            "src_ip", "method", "path", "status",
        ]

    near_fallback = index.window(src_ip, timestamp, fallback_seconds)
    exact_fallback = [record for record in near_fallback if request_matches(record, request)]
    if exact_fallback:
        reason = "fallback_candidate" if len(exact_fallback) == 1 else "fallback_ambiguous"
        return "context_only", reason, exact_fallback, ["src_ip", "method", "path", "status"]
    if near_strong or near_fallback:
        return "context_only", "ip_time_only_or_request_mismatch", (
            near_strong or near_fallback
        ), ["src_ip"]

    long_candidates = [
        record
        for record in index.window(src_ip, timestamp, long_delay_seconds)
        if request_matches(record, request)
    ]
    if long_candidates:
        return "context_only", "long_delay_exact", long_candidates, [
            "src_ip", "method", "path", "status",
        ]
    return "unmatched", "no_candidate", [], []


def _classify_missing_xff(index, timestamp, request, strong_seconds, fallback_seconds,
                          long_delay_seconds):
    previous = -1.0
    windows = (
        (strong_seconds, "within_strong_window"),
        (fallback_seconds, "within_fallback_window"),
        (long_delay_seconds, "within_long_delay_window"),
    )
    for seconds, label in windows:
        if seconds <= previous:
            continue
        previous = seconds
        exact = [
            record
            for record in index.window_without_ip(timestamp, seconds)
            if request_matches(record, request)
        ]
        if exact:
            cardinality = "unique" if len(exact) == 1 else "multiple"
            return (
                "context_only",
                "xff_missing_exact_%s_%s" % (cardinality, label),
                exact,
                ["method", "path", "status"],
            )
    return "unmatched", "xff_missing_no_candidate", [], []


def _candidate_payload(record, network_timestamp):
    delta_ms = round((record.timestamp - network_timestamp).total_seconds() * 1000, 3)
    return {
        "raw_ref": record.raw_ref,
        "timestamp": record.timestamp_text,
        "src_ip": record.src_ip,
        "request_id": record.request_id,
        "delta_ms": delta_ms,
        "absolute_delta_ms": abs(delta_ms),
    }


def _join_id(raw_refs):
    payload = "\0".join(sorted(set(raw_refs))).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def correlate_http_event(
    event,
    apache_index,
    *,
    strong_seconds=DEFAULT_STRONG_SECONDS,
    fallback_seconds=DEFAULT_FALLBACK_SECONDS,
    long_delay_seconds=DEFAULT_LONG_DELAY_SECONDS,
):
    """Suricata HTTP 이벤트 하나의 Apache 결합 판정을 반환한다."""
    _validate_windows(strong_seconds, fallback_seconds, long_delay_seconds)
    if not isinstance(event, dict):
        raise ValueError("event는 dict여야 함")
    layer_data = event.get("layer_data")
    if event.get("layer") != "network" or not isinstance(layer_data, dict):
        raise ValueError("network 이벤트가 필요함")
    if layer_data.get("event_type") != "http":
        raise ValueError("Suricata HTTP 이벤트가 필요함")

    timestamp = parse_utc(event.get("timestamp"))
    src_ip = canonical_ip(event.get("src_ip"))
    request = network_request(event)
    xff_status = layer_data.get("xff_status")

    if timestamp is None:
        status, reason, candidates, matched_fields = "unmatched", "invalid_timestamp", [], []
    elif src_ip is not None:
        status, reason, candidates, matched_fields = _classify(
            apache_index,
            src_ip,
            timestamp,
            request,
            strong_seconds,
            fallback_seconds,
            long_delay_seconds,
        )
    elif xff_status == "missing":
        status, reason, candidates, matched_fields = _classify_missing_xff(
            apache_index,
            timestamp,
            request,
            strong_seconds,
            fallback_seconds,
            long_delay_seconds,
        )
    else:
        status, reason, candidates, matched_fields = (
            "unmatched", "xff_invalid_or_conflict", [], [],
        )

    payloads = [
        _candidate_payload(candidate, timestamp)
        for candidate in candidates
    ] if timestamp is not None else []
    raw_ref = str(event.get("raw_ref") or "")
    evidence_refs = [raw_ref] if raw_ref else []
    evidence_refs.extend(candidate.raw_ref for candidate in candidates)
    evidence_refs = sorted(set(evidence_refs))
    return {
        "join_id": _join_id(evidence_refs),
        "network_raw_ref": raw_ref or None,
        "join_status": status,
        "join_reason": reason,
        "src_ip": src_ip,
        "network_timestamp": event.get("timestamp"),
        "delta_ms": payloads[0]["delta_ms"] if len(payloads) == 1 else None,
        "candidate_count": len(payloads),
        "matched_fields": matched_fields,
        "xff_resolution": layer_data.get("xff_resolution"),
        "xff_status": xff_status,
        "network_flow": {
            "sensor_id": layer_data.get("sensor_id"),
            "flow_id": layer_data.get("flow_id"),
            "tx_id": layer_data.get("tx_id"),
        },
        "request": request,
        "apache_candidates": payloads,
        "evidence_refs": evidence_refs,
    }


def build_web_network_correlation_index(
    events,
    *,
    strong_seconds=DEFAULT_STRONG_SECONDS,
    fallback_seconds=DEFAULT_FALLBACK_SECONDS,
    long_delay_seconds=DEFAULT_LONG_DELAY_SECONDS,
):
    """정규화 Event 목록에서 Suricata HTTP raw_ref별 결합 결과를 만든다."""
    _validate_windows(strong_seconds, fallback_seconds, long_delay_seconds)
    event_list = list(events)
    apache_index = ApacheIndex(event_list)
    http_events = [
        event
        for event in event_list
        if isinstance(event, dict)
        and event.get("layer") == "network"
        and isinstance(event.get("layer_data"), dict)
        and event["layer_data"].get("event_type") == "http"
        and event.get("raw_ref") not in (None, "")
    ]
    http_events.sort(key=lambda event: (str(event.get("timestamp") or ""), str(event["raw_ref"])))
    return {
        str(event["raw_ref"]): correlate_http_event(
            event,
            apache_index,
            strong_seconds=strong_seconds,
            fallback_seconds=fallback_seconds,
            long_delay_seconds=long_delay_seconds,
        )
        for event in http_events
    }


__all__ = [
    "ApacheIndex",
    "DEFAULT_FALLBACK_SECONDS",
    "DEFAULT_LONG_DELAY_SECONDS",
    "DEFAULT_STRONG_SECONDS",
    "build_web_network_correlation_index",
    "correlate_http_event",
]
