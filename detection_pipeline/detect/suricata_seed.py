"""정규화된 Suricata Alert 이벤트를 공통 Seed로 변환한다.

이 모듈은 파일을 읽거나 쓰지 않는다. ``network.jsonl``에 저장될 것과 동일한
메모리상의 공통 Event 목록을 받아 Seed와 reject 목록을 반환한다.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from common.seed import build_seed, validate as validate_seed
from common.timeparse import normalize_iso
from detect.suricata_flow import (
    build_http_evidence_index,
    find_http_evidence_refs,
)
from detect.web_network_correlation import (
    DEFAULT_FALLBACK_SECONDS as DEFAULT_WEB_FALLBACK_SECONDS,
    DEFAULT_LONG_DELAY_SECONDS as DEFAULT_WEB_LONG_DELAY_SECONDS,
    DEFAULT_STRONG_SECONDS as DEFAULT_WEB_STRONG_SECONDS,
    build_web_network_correlation_index,
)


DEFAULT_WINDOW_SECONDS = 60
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _parse_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp가 비어 있음")
    text = normalize_iso(value)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("timestamp 형식 오류") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp에 timezone이 없음")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _external_ip(value):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not address.is_global:
        return None
    return str(address)


def _representative_ip(event):
    top_level = _external_ip(event.get("src_ip"))
    if top_level is not None:
        return top_level
    layer_data = event.get("layer_data")
    if not isinstance(layer_data, dict):
        return None
    return _external_ip(layer_data.get("transport_src_ip"))


def _severity_value(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _rule_severity(events):
    values = [
        _severity_value(event["layer_data"].get("severity"))
        for event in events
    ]
    values = [value for value in values if value is not None]
    severity = min(values) if values else None
    if severity == 1:
        return "high"
    if severity == 2:
        return "medium"
    return "low"


def _safe_signature(value, signature_id):
    signature = value if isinstance(value, str) else ""
    signature = _CONTROL_CHARS.sub(" ", signature).strip()
    signature = " ".join(signature.split())[:256]
    if signature:
        return signature
    return "signature_id=%s" % signature_id


def _dedupe_key(event, timestamp, entity_ip):
    layer_data = event["layer_data"]
    signature_id = layer_data.get("signature_id")
    sensor_id = layer_data.get("sensor_id") or ""
    flow_id = layer_data.get("flow_id")
    if flow_id is not None:
        return ("flow", str(sensor_id), str(flow_id), str(signature_id))

    minute_bucket = timestamp.replace(second=0, microsecond=0)
    return (
        "fallback",
        str(signature_id),
        entity_ip,
        str(layer_data.get("dest_ip") or ""),
        str(layer_data.get("dest_port") or ""),
        str(layer_data.get("protocol") or ""),
        _format_timestamp(minute_bucket),
    )


def _reject(event, reason, detail=None):
    rejected = {
        "raw_ref": event.get("raw_ref") if isinstance(event, dict) else None,
        "reason": reason,
    }
    if detail:
        rejected["detail"] = detail
    return rejected


def _team_metadata(event, signature_id, web_network_correlations=None):
    """팀 Sigma Seed가 제공하는 계약 밖 보조 필드와 같은 형태를 만든다."""
    layer_data = event["layer_data"]
    detail = {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
    }
    for key in (
        "flow_id", "community_id", "tx_id", "signature", "signature_id",
        "category", "severity", "action", "dest_ip", "dest_port", "protocol",
        "sensor_id",
    ):
        if layer_data.get(key) is not None:
            detail[key] = layer_data[key]
    if web_network_correlations:
        detail["web_network_correlations"] = web_network_correlations
    return {
        "rule_id": str(signature_id),
        "rule_name": "suricata_%s" % signature_id,
        "detail": detail,
    }


def build_suricata_seeds(
    events,
    window_seconds=DEFAULT_WINDOW_SECONDS,
    web_strong_seconds=DEFAULT_WEB_STRONG_SECONDS,
    web_fallback_seconds=DEFAULT_WEB_FALLBACK_SECONDS,
    web_long_delay_seconds=DEFAULT_WEB_LONG_DELAY_SECONDS,
):
    """정규화 Event 목록에서 Suricata Seed와 reject 목록을 만든다.

    반환값은 ``(seeds, rejects)``다. 함수는 입력 순서와 무관하게 같은 결과를
    만들며 파일 시스템에는 접근하지 않는다.
    """
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)):
        raise ValueError("window_seconds는 양수 숫자여야 함")
    if window_seconds <= 0:
        raise ValueError("window_seconds는 양수여야 함")

    events = list(events)
    groups = defaultdict(list)
    rejects = []
    http_evidence_index = build_http_evidence_index(events)
    web_network_index = build_web_network_correlation_index(
        events,
        strong_seconds=web_strong_seconds,
        fallback_seconds=web_fallback_seconds,
        long_delay_seconds=web_long_delay_seconds,
    )

    for event in events:
        if not isinstance(event, dict):
            rejects.append(_reject(event, "invalid_event", "event는 dict여야 함"))
            continue
        layer_data = event.get("layer_data")
        if event.get("layer") != "network" or not isinstance(layer_data, dict):
            continue
        if layer_data.get("event_type") != "alert":
            continue
        if event.get("raw_ref") in (None, ""):
            rejects.append(_reject(event, "missing_raw_ref"))
            continue
        if layer_data.get("signature_id") in (None, ""):
            rejects.append(_reject(event, "missing_signature_id"))
            continue
        try:
            timestamp = _parse_timestamp(event.get("timestamp"))
        except ValueError as exc:
            rejects.append(_reject(event, "invalid_timestamp", str(exc)))
            continue
        entity_ip = _representative_ip(event)
        if entity_ip is None:
            rejects.append(_reject(event, "missing_trusted_entity"))
            continue

        key = _dedupe_key(event, timestamp, entity_ip)
        groups[key].append((timestamp, str(event["raw_ref"]), entity_ip, event))

    seeds = []
    window_delta = timedelta(seconds=float(window_seconds))
    for key in sorted(groups, key=lambda value: tuple(str(part) for part in value)):
        records = sorted(groups[key], key=lambda item: (item[0], item[1]))
        timestamp, _, entity_ip, representative = records[0]
        grouped_events = [record[3] for record in records]
        evidence_refs = {record[1] for record in records}
        web_network_correlations = {}
        for grouped_event in grouped_events:
            http_refs = find_http_evidence_refs(
                grouped_event,
                http_evidence_index,
            )
            evidence_refs.update(http_refs)
            for http_ref in http_refs:
                correlation = web_network_index.get(http_ref)
                if correlation is None:
                    continue
                web_network_correlations[http_ref] = correlation
                if correlation["join_status"] == "strong":
                    evidence_refs.update(correlation["evidence_refs"])
        evidence_refs = sorted(evidence_refs)
        correlations = [
            web_network_correlations[raw_ref]
            for raw_ref in sorted(web_network_correlations)
        ]
        layer_data = representative["layer_data"]
        signature_id = layer_data.get("signature_id")
        signature = _safe_signature(layer_data.get("signature"), signature_id)

        seed = build_seed(
            entity_type="src_ip",
            entity_value=entity_ip,
            window=[
                _format_timestamp(timestamp - window_delta),
                _format_timestamp(timestamp + window_delta),
            ],
            layer="network",
            source=["suricata"],
            reason="Suricata alert: %s" % signature,
            rule_severity=_rule_severity(grouped_events),
            deviation=None,
            layer_count=1,
            signal_tags=[],
            evidence_refs=evidence_refs,
        )
        seed.update(_team_metadata(representative, signature_id, correlations))
        try:
            validate_seed(seed)
        except ValueError as exc:
            rejects.append({
                "raw_ref": evidence_refs[0],
                "evidence_refs": evidence_refs,
                "reason": "seed_validation_failed",
                "detail": str(exc),
            })
            continue
        seeds.append(seed)

    seeds.sort(key=lambda seed: (
        seed["window"][0],
        seed["layer"],
        seed["entity"]["value"],
        seed["reason"],
        tuple(seed["evidence_refs"]),
    ))
    rejects.sort(key=lambda rejected: (
        str(rejected.get("raw_ref") or ""),
        rejected["reason"],
    ))
    return seeds, rejects


__all__ = ["DEFAULT_WINDOW_SECONDS", "build_suricata_seeds"]
