"""운영 지표 emit — LLM 호출/단계마다 레코드 한 줄을 results/metrics/<날짜>.jsonl 에 붙인다.

파이프라인 흐름은 바꾸지 않는 '부가 기록'이다. 그래서 어떤 실패도 조용히 삼킨다
(지표 기록이 관제를 멈추면 안 된다). 대시보드 '운영 상태' 패널이 이 파일을 읽는다 —
계약(app/page.tsx): run_id · incident_id · stage · provider · model · operation ·
input/output/cache tokens · started_at · duration_ms · retry_count · status · error_type.

토큰이 없는 단계(normalize/detect/correlate)는 토큰 필드가 null 이고 duration 만 남는다.
토큰은 조사/대응 결과의 usage(dict)를 넘기면 평탄화해 채운다.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.abspath(__file__))
METRICS_DIR = os.path.join(_ROOT, "results", "metrics")


def new_run_id() -> str:
    return "run-" + uuid.uuid4().hex[:12]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_record(*, run_id, stage, duration_ms, incident_id=None, provider=None,
                 model=None, operation=None, usage=None, started_at=None,
                 retry_count=0, status="ok", error_type=None) -> dict:
    """계약 모양의 레코드 dict. usage(dict)가 있으면 토큰 필드를 평탄화한다."""
    u = usage or {}
    return {
        "run_id": run_id,
        "incident_id": incident_id,
        "stage": stage,
        "provider": provider,
        "model": model or u.get("model"),
        "operation": operation or stage,
        "input_tokens": u.get("input_tokens"),
        "output_tokens": u.get("output_tokens"),
        "cache_read_tokens": u.get("cache_read_input_tokens"),
        "cache_creation_tokens": u.get("cache_creation_input_tokens"),
        "started_at": started_at,
        "duration_ms": duration_ms,
        "retry_count": retry_count,
        "status": status,
        "error_type": error_type,
    }


def emit_metric(*, metrics_dir=METRICS_DIR, **fields) -> dict:
    """레코드 한 줄을 <metrics_dir>/<UTC 날짜>.jsonl 에 append. 실패는 삼킨다."""
    record = build_record(**fields)
    try:
        os.makedirs(metrics_dir, exist_ok=True)
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with open(os.path.join(metrics_dir, day + ".jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return record


if __name__ == "__main__":  # 자체 점검: python metrics_emit.py
    # 토큰 없는 단계
    r1 = build_record(run_id="run-x", stage="normalize", duration_ms=1200)
    assert r1["input_tokens"] is None and r1["duration_ms"] == 1200
    assert r1["operation"] == "normalize"  # operation 생략 시 stage 로 채움
    # 조사 usage 평탄화
    usage = {"model": "claude-sonnet-5-5", "input_tokens": 120000, "output_tokens": 7000,
             "cache_read_input_tokens": 54000, "cache_creation_input_tokens": 18000}
    r2 = build_record(run_id="run-x", stage="investigation", incident_id="INC-1",
                      operation="investigate", provider="anthropic", usage=usage, duration_ms=166000)
    assert r2["model"] == "claude-sonnet-5-5"
    assert r2["input_tokens"] == 120000 and r2["cache_read_tokens"] == 54000
    assert r2["cache_creation_tokens"] == 18000 and r2["output_tokens"] == 7000
    assert r2["incident_id"] == "INC-1" and r2["status"] == "ok"
    # 실제 append (임시 폴더)
    import tempfile
    d = tempfile.mkdtemp()
    emit_metric(metrics_dir=d, run_id="run-x", stage="respond", incident_id="INC-1", duration_ms=800)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(os.path.join(d, day + ".jsonl"), encoding="utf-8") as fh:
        line = json.loads(fh.readline())
    assert line["stage"] == "respond" and line["incident_id"] == "INC-1"
    print("ok")
