"""Collect seed input through the same parsers and raw references as investigation."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .tools.log_source import SOURCE_TYPES, normalize_documents, read_documents

# [7] agent/pipeline.py [6]에서 실행됨. host의 4계층(web/auth/audit/network) 로그 파일 끝부분을
#     모아서 seed 생성용으로 구조화해 반환. minutes는 연도 없는 auth 로그의 연도 추정 구간으로만 쓰인다.
def fetch_recent_raw_logs(host: str, minutes: int = 10,
                          source_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
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
        #     로컬 파일(WEB_LOG_LOCAL_PATH 등)에서 원본 텍스트를
        #     원본 파일명·줄번호 보존한 채로 그대로 읽어옴 (아직 파싱 전)
        documents = read_documents(layer, host, start, end)
        # [9] agent/tools/log_source.py의 normalize_documents() 실행
        #     → 내부에서 agent/tools/normalizer_adapter.py의 normalize_log_documents() 호출
        #     → 다시 그 내부에서 primary_detection/normalizer/tools/fetch_*_log.py
        #       (1차 탐지팀 벤더 코드, 손대지 않고 그대로 호출)로 실제 파싱 수행
        records = normalize_documents(layer, documents, start, end)
        # 파싱까지 끝난 이벤트 중 파일 끝에서 RAW_LOG_LOCAL_MAX_LINES건만 seed 생성에 넘긴다(시각과 무관).
        # 예전엔 "원본 텍스트 마지막 30줄"을 자른 뒤 파싱해서, network처럼 뒷부분이 dns/flow/stats뿐인
        # 계층은 이벤트가 0건이 됐다. 원래 줄 번호는 그대로 유지된다.
        limit = int(os.environ.get("RAW_LOG_LOCAL_MAX_LINES", "30"))
        if limit < 1:
            raise ValueError("RAW_LOG_LOCAL_MAX_LINES must be positive")
        records = records[-limit:]
        for record in records:
            record["_source_type"] = layer
        all_records.extend(records)
    # 이 반환값은 agent/pipeline.py [6] 호출부가 받아서
    # agent/seed_generation.py [10]으로 그대로 넘김
    return all_records
