"""seed 생성용 로그 수집 — 4계층 로그 파일 끝부분을 정규화해 모은다.

역할
  web/auth/audit/network 로그 파일(.env의 <계층>_LOG_LOCAL_PATH)을 읽어 1차 탐지팀 공통 정규화로
  구조화하고, 계층마다 파일 끝 RAW_LOG_LOCAL_MAX_LINES건(기본 30, EC2 .env는 50)만 모은다.
  조사 도구와 같은 읽기·정규화 경로(log_source)를 써서 raw_ref(원본 파일:줄)가 조사 단계와 같다.

누가 부르나
  [6] agent/pipeline.py run_investigation_pipeline()  → fetch_recent_raw_logs()
  scripts/verify_all_tools.py

무엇을 부르나
  [8] agent/tools/log_source.py  read_documents()       로그 파일 원본 텍스트 읽기
  [9] agent/tools/log_source.py  normalize_documents()  → normalizer_adapter → 1차 탐지팀 정규화
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .tools.log_source import SOURCE_TYPES, normalize_documents, read_documents

# [7] ← agent/pipeline.py [6]에서 호출됨
#     minutes는 파일을 시각으로 거르는 데 쓰지 않는다 — 연도 없는 auth 로그의 연도 추정 구간으로만 쓰인다.
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
        # [8] → agent/tools/log_source.py read_documents()
        #     .env의 <계층>_LOG_LOCAL_PATH 파일 원본 텍스트를 파일명과 함께 읽는다 (아직 파싱 전)
        documents = read_documents(layer, host, start, end)
        # [9] → agent/tools/log_source.py normalize_documents()
        #     → agent/tools/normalizer_adapter.py normalize_log_documents()
        #     → primary_detection/normalizer/tools/fetch_*_log.py (1차 탐지팀 코드, 수정 없이 호출)
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
    # → agent/pipeline.py로 돌아가 [10] seed 생성의 입력이 된다
    return all_records
