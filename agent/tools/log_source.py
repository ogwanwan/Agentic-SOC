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

    Set LOG_LOCAL_HOST to reject queries for a different machine. HOST is not
    used here: main.py uses it as the ingestion target, and synthetic scenario
    seeds (host=web-01) must still read the same local files.
    S3 documents are scoped by the existing host/date partition convention.
    """
    local_path = os.environ.get(LOCAL_PATH_ENV[layer])
    if local_path:
        configured_host = os.environ.get("LOG_LOCAL_HOST")
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


def filtered_out_hint(window_total: int, args: Dict[str, Any], filter_keys: Iterable[str]) -> str:
    """필터 결과가 0건인데 구간 안에는 이벤트가 있을 때 summary에 붙일 안내.

    LLM이 "필터에 안 맞음"을 "그 시간에 활동 없음"으로 읽고 조사를 끝내는 사례가 있었다
    (2026-09-24 지속성 시나리오: audit event_type="EXECVE" 0건 → INCONCLUSIVE).
    """
    if window_total == 0:
        # 필터와 무관하게 구간 자체에 기록이 없음 — 수집 누락·로그 교체일 수 있어 "활동 없음"과 다르다.
        # 로컬 재현(2026-09-24)에서 로그가 없는 날짜의 seed를 LLM이 3/4 FALSE_POSITIVE로 판정했다.
        return (" 이 구간에는 이 계층의 로그 기록 자체가 없습니다(수집 누락·로그 교체 가능). "
                "'활동이 없었다'는 증거로 쓰지 말고 unknowns에 '원본 로그 미확보'로 남기십시오.")
    used = [key for key in filter_keys if args.get(key) is not None]
    if not used:
        return ""
    return (f" 단, 같은 구간에 필터 없이 보면 이벤트가 {window_total}건 있습니다 — 사용한 필터({', '.join(used)})가 "
            "맞지 않았을 수 있으니, 필터를 빼거나 바꿔서 다시 조회한 뒤 판단하십시오.")


def load_window_events(layer: str, host: str, start_time: str, end_time: str) -> Dict[str, Any]:
    """Read one layer and normalize it with primary_detection, keeping only in-window events.

    Tool-specific filters, pagination and summaries belong to agent/tools/real/*.py.
    A missing/unreadable source is reported in "error" instead of looking like 0 events.
    """
    start, end = query_window(start_time, end_time)
    error = None
    try:
        documents = read_documents(layer, host, start, end)
    except (FileNotFoundError, PermissionError) as exc:
        documents = []
        error = "permission_denied" if isinstance(exc, PermissionError) else "not_found"
    events = normalize_documents(layer, documents, start, end)
    invalid_timestamps = sum(event_time(event) is None for event in events)
    in_window = [event for event in events if (ts := event_time(event)) is not None and start <= ts <= end]
    in_window.sort(key=lambda event: (event_time(event), event["raw_ref"]))
    return {"events": in_window, "scanned_objects": len(documents),
            "invalid_timestamps": invalid_timestamps, "error": error}
