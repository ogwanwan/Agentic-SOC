"""Collect seed input through the same parsers and raw references as investigation."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .tools.log_source import (LOCAL_PATH_ENV, SOURCE_TYPES, event_time,
                               normalize_documents, read_documents)

# [7] agent/pipeline.py [6]에서 실행됨. host 기준으로 최근 `minutes`분 raw log를
#     4계층(web/auth/audit/network) 전부 모아서 seed 생성용으로 구조화해 반환
def fetch_recent_raw_logs(host: str, minutes: int = 10,
                          source_types: Optional[List[str]] = None,
                          bucket: Optional[str] = None) -> List[Dict[str, Any]]:
    if minutes <= 0:
        raise ValueError("minutes must be positive")
    source_types = list(SOURCE_TYPES) if source_types is None else source_types
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    all_records = []
    for layer in source_types:
        if layer not in SOURCE_TYPES:
            raise ValueError(f"unknown source type: {layer}")
        # [8] agent/tools/log_source.py의 read_documents() 실행
        #     로컬 파일(WEB_LOG_LOCAL_PATH 등) 또는 S3에서 원본 텍스트를
        #     원본 파일명·줄번호 보존한 채로 그대로 읽어옴 (아직 파싱 전)
        documents = read_documents(layer, host, start, end, bucket=bucket)
        # [9] agent/tools/log_source.py의 normalize_documents() 실행
        #     → 내부에서 agent/tools/normalizer_adapter.py의 normalize_log_documents() 호출
        #     → 다시 그 내부에서 primary_detection/normalizer/tools/fetch_*_log.py
        #       (1차 탐지팀 벤더 코드, 손대지 않고 그대로 호출)로 실제 파싱 수행
        records = normalize_documents(layer, documents, start, end)
        if os.environ.get(LOCAL_PATH_ENV[layer]):
            # Limit complete EVENTS after parsing, retaining original line numbers.
            # Keep the existing local sample replay behavior (no clock filter).
            # (2026-09-23 수정: 예전엔 "원본 텍스트 마지막 30줄"을 자른 뒤 파싱해서
            # network처럼 뒷부분이 dns/flow/stats뿐인 계층은 이벤트가 0건이 되는
            # 버그가 있었음 → 지금은 "파싱까지 끝난 이벤트" 기준으로 자름)
            limit = int(os.environ.get("RAW_LOG_LOCAL_MAX_LINES", "30"))
            if limit < 1:
                raise ValueError("RAW_LOG_LOCAL_MAX_LINES must be positive")
            records = records[-limit:]
        else:
            records = [r for r in records if (ts := event_time(r)) is not None and start <= ts <= end]
        for record in records:
            record["_source_type"] = layer
        all_records.extend(records)
    # 이 반환값은 agent/pipeline.py [6] 호출부가 받아서
    # agent/seed_generation.py [10]으로 그대로 넘김
    return all_records
