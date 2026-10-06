"""대응 권고 실행 기록 — `results/response/run_log.jsonl` (설계서 9-1).

역할
  사건마다 한 줄(JSON)을 덧붙인다. 권고문 본문에는 안 나오지만 다음을 나중에 확인하는 유일한 근거다.
    - LLM을 불렀는가, 어떤 모델이었는가
    - 응답이 거절돼 기본 문장으로 대체됐는가, 그 사유는 무엇인가
    - 어떤 조치가 왜 폐기됐는가 (대상 검증 실패·기법 환각)
    - 어떤 증거 인용이 지워졌는가

  "조치 대상을 확보하지 못해 조치를 만들지 않았다"(설계서 5-4)도 여기에 남는다 — 권고가 비어 있을 때
  담당자가 "왜 비었는지"를 물으면 이 파일을 본다.

누가 부르나
  respond/cli.py  process_file()  → append_run_log()

형식
  한 줄에 JSON 객체 하나(JSONL). 덧붙이기만 하고 덮어쓰지 않는다.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

RUN_LOG_NAME = "run_log.jsonl"


def build_entry(
    plan: Any,
    *,
    source_path: str,
    selection_report: Optional[Any] = None,
    llm_report: Optional[Any] = None,
    output_paths: Optional[Dict[str, str]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """run_log 한 줄을 만든다. plan이 None이면(입력을 읽지도 못한 경우) 사건 id 없이 오류만 남긴다."""
    entry: Dict[str, Any] = {
        "logged_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source_path,
    }
    if plan is not None:
        entry.update({
            "incident_id": plan.incident_id,
            "incident_key": plan.incident_key,
            "investigation_id": plan.investigation_id,
            "response_status": plan.response_status,
            "verdict": plan.verdict,
            "mapping_status": plan.mapping_status,
            "provenance_status": plan.provenance_status,
            "action_count": len(plan.actions),
            "action_ids": plan.action_ids(),
        })
    # 2026-10-06 추가 — "LLM이 조치 목록을 짜고 code가 검문"(선택 단계)의 기록.
    # plan.selection_meta는 이미 plan.to_dict()/.json에 실리지만, 선택 단계 자체가
    # 어떻게 됐는지(재시도했는지·구조가 깨졌는지)는 SelectionReport에만 있다.
    if selection_report is not None:
        entry["selection"] = selection_report.to_dict()
    if llm_report is not None:
        entry["llm"] = llm_report.to_dict()
    if output_paths:
        entry["outputs"] = output_paths
    if error:
        entry["error"] = error
    return entry


def append_run_log(entry: Dict[str, Any], out_dir: str) -> str:
    """run_log.jsonl에 한 줄 덧붙이고 파일 경로를 반환한다.

    기록 실패가 대응 권고 자체를 멈추지 않도록, 호출하는 쪽에서 예외를 잡는다.
    """
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, RUN_LOG_NAME)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return path
