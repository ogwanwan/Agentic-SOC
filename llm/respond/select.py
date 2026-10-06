"""조치 "선택" 단계 진입점 — 신규 설계(2026-10-06): decide.py가 만든 후보 풀에서
LLM이 이번 사건에 쓸 조치를 고른다(LLM 호출 1). 그 결과를 select_gate.py가 구조만
검문하고, decide.py가 최소 필수 조치·선행조건·캡·순서 정리를 맡는다.

흐름
  decide.build_candidate_pool()
    → run_selection_stage()(여기)       — LLM 호출 1, 구조 오류면 1회 재시도
    → decide.finalize_selected_plan()   — mandatory/requires/caps 적용 + 순서 정리
    → llm.run_llm_stage()               — 7칸 작성(LLM 호출 2) — 안 바뀐다

실패하면 어디로 가나
  이 모듈은 절대 예외를 올리지 않는다. 선택이 통째로 안 되면 (None, report)를 돌려주고,
  호출하는 쪽(cli.py)이 finalize_selected_plan(..., llm_selected_ids=None)으로 넘어가
  build_response_plan()과 같은 결과(후보 전체 사용)를 낸다.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple

_LLM_DIR = str(Path(__file__).resolve().parents[1])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond import investigate_bridge  # noqa: E402
from respond.decide import CandidatePool  # noqa: E402
from respond.prompts import build_selection_system_prompt, build_selection_user_prompt  # noqa: E402
from respond.select_gate import SelectionReport, validate_payload  # noqa: E402

MAX_ATTEMPTS = 2  # 처음 1회 + 구조 오류 시 재시도 1회


def run_selection_stage(
    pool: CandidatePool,
    *,
    incident_facts: dict,
    llm_client: Any = None,
) -> Tuple[Optional[List[str]], SelectionReport]:
    """선택 단계 LLM을 부른다. 첫 번째 반환값이 None이면 호출하는 쪽이 폴백해야 한다."""
    report = SelectionReport()

    client = llm_client
    if client is None:
        try:
            client = investigate_bridge.build_llm_client()
        except Exception as exc:  # 설정 누락·역할 미등록 — 선택 단계를 건너뛴다(폴백)
            report.fallback_reason = f"LLM 클라이언트 준비 실패: {exc}"
            return None, report

    report.llm_model = getattr(client, "model", None)
    system_prompt = build_selection_system_prompt()

    previous_error = ""
    for attempt in range(MAX_ATTEMPTS):
        user_prompt = build_selection_user_prompt(
            pool, incident_facts, previous_error=previous_error)
        try:
            payload = client.complete_json(system_prompt, user_prompt)
            report.llm_called = True
        except Exception as exc:
            report.fallback_reason = f"LLM 호출 실패: {exc}"
            return None, report

        selected = validate_payload(pool, payload, report)
        if selected is not None:
            return selected, report

        previous_error = report.fallback_reason or "알 수 없는 오류"
        if attempt + 1 < MAX_ATTEMPTS:
            report.retry_used = True
            report.notes.append(f"구조 오류로 재시도: {previous_error}")
            report.fallback_reason = None
            report.structurally_valid = False

    return None, report


if __name__ == "__main__":  # 자체 점검: python llm/respond/select.py (가짜 LLM만 씀)
    from respond.catalog import ActionTemplate
    from respond.decide import Candidate

    t1 = ActionTemplate("A", None, True, "LOW", "L2", "immediate", None, "x",
                         template_id="SYN_A", priority=1, rollback="x", side_effects="x",
                         verification="x", autonomy_reason="L2")
    pool = CandidatePool(candidates=(Candidate(t1, None),), mandatory_ids=frozenset())
    facts = {"incident_id": "INC-TEST", "verdict": "THREAT_CONFIRMED", "severity": "HIGH",
             "attack_type": "x", "host": None}

    class _GoodClient:
        model = "stub"

        def complete_json(self, system_prompt, user_prompt):
            return {"actions": ["SYN_A"]}

    selected, report = run_selection_stage(pool, incident_facts=facts, llm_client=_GoodClient())
    assert selected == ["SYN_A"] and report.llm_called and not report.retry_used

    class _OnceBadClient:
        model = "stub"
        calls = 0

        def complete_json(self, system_prompt, user_prompt):
            self.calls += 1
            if self.calls == 1:
                return {"wrong": "shape"}
            return {"actions": ["SYN_A"]}

    client = _OnceBadClient()
    selected2, report2 = run_selection_stage(pool, incident_facts=facts, llm_client=client)
    assert selected2 == ["SYN_A"] and report2.retry_used and client.calls == 2

    class _AlwaysBadClient:
        model = "stub"

        def complete_json(self, system_prompt, user_prompt):
            return {"wrong": "shape"}

    selected3, report3 = run_selection_stage(pool, incident_facts=facts, llm_client=_AlwaysBadClient())
    assert selected3 is None and report3.retry_used  # 재시도까지 다 실패 → 폴백 신호

    class _ExceptionClient:
        model = "stub"

        def complete_json(self, system_prompt, user_prompt):
            raise RuntimeError("API 오류")

    selected4, report4 = run_selection_stage(pool, incident_facts=facts, llm_client=_ExceptionClient())
    assert selected4 is None and "API 오류" in (report4.fallback_reason or "")

    print("ok")
