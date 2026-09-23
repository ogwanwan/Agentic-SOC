"""Read original log documents without losing object names or physical line numbers.

Both ingestion and investigation use this adapter around the existing parsers.
It does not implement detection rules or assign security verdicts.
"""
from __future__ import annotations

import os
import gzip
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .normalizer_adapter import normalize_log_documents
from .real._s3_common import daterange
from .time_utils import parse_iso

SOURCE_TYPES = {"web": "apache", "auth": "auth", "audit": "auditd", "network": "suricata"}
LOCAL_PATH_ENV = {key: f"{key.upper()}_LOG_LOCAL_PATH" for key in SOURCE_TYPES}
DEFAULT_BUCKET = "ogwanwan-shop-bucket"


@dataclass(frozen=True)
class LogDocument:
    source: str
    text: str


def read_documents(layer: str, host: str, start: datetime, end: datetime,
                   bucket: str | None = None) -> List[LogDocument]:
    """A configured local file belongs to the host running this collector.

    Set LOG_LOCAL_HOST (or HOST) to reject queries for a different machine.
    S3 documents are scoped by the existing host/date partition convention.
    """
    local_path = os.environ.get(LOCAL_PATH_ENV[layer])
    if local_path:
        configured_host = os.environ.get("LOG_LOCAL_HOST") or os.environ.get("HOST")
        if configured_host and configured_host != host:
            raise ValueError(f"local host mismatch: expected {configured_host}, got {host}")
        path = Path(local_path).resolve()
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as stream:
                text = stream.read()
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
        return [LogDocument(path.as_posix(), text)]

    import boto3

    bucket = bucket or os.environ.get(f"{layer.upper()}_LOG_BUCKET", DEFAULT_BUCKET)
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))
    documents = []
    # Date partitions are UTC even when callers supply a +09:00 window.
    for day in daterange(start.astimezone(timezone.utc), end.astimezone(timezone.utc)):
        prefix = f"raw/source_type={SOURCE_TYPES[layer]}/host={host}/dt={day}/"
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"]
                try:
                    data = body.read()
                    if obj["Key"].endswith(".gz"):
                        data = gzip.decompress(data)
                    text = data.decode("utf-8", errors="replace")
                finally:
                    if hasattr(body, "close"):
                        body.close()
                documents.append(LogDocument(f"s3://{bucket}/{obj['Key']}", text))
    return sorted(documents, key=lambda doc: doc.source)


def normalize_documents(layer: str, documents: Iterable[LogDocument],
                        start: datetime, end: datetime) -> List[Dict[str, Any]]:
    """Flatten the shared primary-detection schema, retaining trace metadata."""
    events = normalize_log_documents(layer, ((doc.source, doc.text) for doc in documents), start, end)
    return [{**{key: value for key, value in event.items() if key != "layer_data"},
             **event.get("layer_data", {})} for event in events]


def event_time(event: Dict[str, Any]) -> datetime | None:
    try:
        return parse_iso(event["timestamp"]).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def query_window(start_time: str, end_time: str) -> tuple[datetime, datetime]:
    if any(not isinstance(value, str) or not value.strip() for value in (start_time, end_time)):
        raise ValueError("window boundaries must be non-empty ISO8601 strings")
    start = parse_iso(start_time).astimezone(timezone.utc)
    end = parse_iso(end_time).astimezone(timezone.utc)
    if end < start:
        raise ValueError("end_time must be greater than or equal to start_time")
    return start, end


def pagination(args: Dict[str, Any]) -> tuple[int, int]:
    values = []
    for name, default in (("limit", 200), ("offset", 0)):
        value = args.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if value < (1 if name == "limit" else 0):
            raise ValueError(f"invalid {name}: {value}")
        values.append(value)
    return values[0], values[1]


def matches(event: Dict[str, Any], args: Dict[str, Any], layer: str) -> bool:
    """Existing per-tool filter meanings; absent join keys never match."""
    if args.get("src_ip") is not None and args["src_ip"] != event.get("src_ip"):
        return False
    network_fields = {"dst_ip": "dest_ip", "src_port": "transport_src_port", "dst_port": "transport_dest_port"}
    for key in ("user", "pid", "ppid", "serial", "result", "dst_ip", "src_port", "dst_port"):
        field = network_fields.get(key, key) if layer == "network" else key
        target = args.get(key)
        if layer == "network" and key in ("src_port", "dst_port") and target is not None:
            target = int(target)
        if target is not None and event.get(field) != target:
            return False
    if args.get("event_type") is not None:
        if event.get({"audit": "key", "auth": "event"}.get(layer, "event_type")) != args["event_type"]:
            return False
    for key in ("method", "protocol"):
        if args.get(key) is not None and str(event.get(key) or "").upper() != str(args[key]).upper():
            return False
    if args.get("path") is not None and args["path"] not in (event.get("path") or ""):
        return False
    if args.get("status_code") is not None and event.get("status") != int(args["status_code"]):
        return False
    if args.get("alert_only") and event.get("event_type") != "alert":
        return False
    if args.get("exclude_interactive") and event.get("session_type") != "non_interactive":
        return False
    if args.get("include_user_cmd") is False and "USER_CMD" in (event.get("record_types") or []):
        return False
    if args.get("exclude_self") and layer == "web":
        from primary_detection.normalizer.tools.fetch_apache_log import SERVER_PUBLIC_IP
        if event.get("src_ip") == SERVER_PUBLIC_IP:
            return False
    return True


def fetch_layer_logs(layer: str, args: Dict[str, Any]) -> Dict[str, Any]:
    start, end = query_window(args["start_time"], args["end_time"])
    limit, offset = pagination(args)
    error = None
    try:
        documents = read_documents(layer, args["host"], start, end)
    except (FileNotFoundError, PermissionError) as exc:
        documents = []
        error = "permission_denied" if isinstance(exc, PermissionError) else "not_found"
    events = normalize_documents(layer, documents, start, end)
    invalid_timestamps = sum(event_time(event) is None for event in events)
    matched = [event for event in events if (ts := event_time(event)) is not None
               and start <= ts <= end and matches(event, args, layer)]
    matched.sort(key=lambda event: (event_time(event), event["raw_ref"]))
    page = matched[offset:offset + limit]
    has_more = offset + len(page) < len(matched)
    summary = f"{args['host']} {layer}: 총 {len(matched)}건 중 {len(page)}건 반환."
    if not documents:
        summary = "데이터를 찾지 못했습니다. host 이름 또는 로컬 파일 경로를 확인하세요."
    if error == "permission_denied":
        summary = "로그 파일 읽기 권한이 없습니다."
    return {"count": len(page), "summary": summary, "records": page,
            "total_matched": len(matched), "has_more": has_more,
            "next_offset": offset + len(page) if has_more else None,
            "scanned_objects": len(documents), "invalid_timestamps": invalid_timestamps,
            **({"error": error} if error else {})}
