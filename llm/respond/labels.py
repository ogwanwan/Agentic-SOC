"""사람이 읽는 라벨·설명 문장 — 권고문(txt)과 대시보드(json)가 **같은 문장**을 쓰게 한다.

왜 따로 뺐나 (2026-10-06)
  발표·운영에서 사람이 보는 화면은 대시보드이고, 대시보드는 `<사건>_response.json`을 읽는다.
  그런데 경고 설명·범례·상태 라벨이 render.py 안의 상수로만 있어서 json에는 코드만 들어갔다
  (`{"code": "FALLBACK_VERDICT"}`). 그러면 대시보드가 같은 문장을 다시 작성해야 하고,
  문구가 갈라진다. 특히 아래 두 개는 **설계서가 반드시 표시하라고 한 내용**이다.
    - 4절: FALLBACK_VERDICT 경고의 의미("severity를 그대로 신뢰하지 마십시오")
    - 7절: "L2는 자동화 후보이며 현재 자동 실행하지 않는다"

  그래서 문장을 여기 한 번만 적고
    render.py → 권고문 텍스트를 그릴 때 읽는다
    cli.py    → json을 쓸 때 decorate()로 같은 문장을 함께 싣는다
  양쪽이 갈라질 수 없게 했다.

누가 부르나
  respond/render.py  경고 줄·머리말 상태 라벨·범례
  respond/cli.py     write_outputs() → decorate()
"""

from __future__ import annotations

from typing import Any, Dict, List

# 머리말 오른쪽 상태 표시 (render는 대괄호를 붙여 쓴다)
STATUS_LABELS = {
    "recommended": "확정 · 권고",
    "recommended_generic": "확정 · 일반 권고",
    "not_applicable": "오탐 · 조치 없음",
    "deferred": "보류 · 확인 필요",
    "skipped": "조사 미완료",
    "error": "처리 오류",
}

# 매핑 경고 코드 → 사람이 읽는 설명 (설계서 4절)
WARNING_MESSAGES = {
    "FALLBACK_VERDICT": "판정이 조사 LLM이 아니라 누적 신뢰도로 자동 결정됨 — severity를 그대로 신뢰하지 마십시오",
    "VERDICT_PRINCIPLE_CONFLICT": "판정이 조사 원칙 기준과 어긋남 — 담당자 확인 필요",
}

# 자율성 등급 (설계서 7절). L2 설명의 "현재 자동 실행 안 함"은 줄여 쓰지 말 것.
AUTONOMY_LEGEND = {
    "L0": "담당자 판단",
    "L1": "승인 후 수동 실행",
    "L2": "자동화 후보(현재 자동 실행 안 함)",
}

# 우선순위 — 같은 묶음 안의 실행 순서
PRIORITY_LEGEND = {"1": "먼저", "2": "보통", "3": "나중"}

# 조치 묶음
CATEGORY_LABELS = {"immediate": "즉시 조치", "verify_needed": "확인 필요"}

# 조치 7칸의 라벨 — 대시보드가 같은 이름으로 표시할 수 있게 함께 싣는다
FIELD_LABELS = {
    "target": "대상",
    "reason": "근거",
    "command_hint": "명령",
    "rollback": "원복",
    "side_effects": "영향",
    "verification": "검증",
    "autonomy_reason": "등급",
}

# 명령·원복을 LLM이 쓴 경우의 실행 전 확인 안내
LLM_AUTHORED_NOTICE = (
    "명령·원복 문장은 LLM이 작성했습니다 — 실행 전 대상과 명령을 반드시 확인하십시오."
)

# 매핑이 일부만 확인된 경우의 꼬리말 (설계서 7절 — partial은 L2를 유지하되 반드시 표기)
MAPPING_PARTIAL_SUFFIX = "일부만 확인됨"


def status_label(response_status: str) -> str:
    return STATUS_LABELS.get(response_status, response_status)


def warning_message(warning: Dict[str, Any]) -> str:
    """경고 한 건의 설명 문장. 모르는 코드는 매핑이 준 detail을, 그것도 없으면 코드를 쓴다."""
    code = str(warning.get("code") or "").strip()
    detail = str(warning.get("detail") or "").strip()
    return WARNING_MESSAGES.get(code) or detail or code or "알 수 없는 경고"


def llm_authored_commands(plan: Any) -> bool:
    """사람이 그대로 실행하는 칸(명령·원복) 중 LLM이 쓴 것이 있는가."""
    return any(
        field in (getattr(action, "llm_fields", None) or [])
        for action in getattr(plan, "actions", None) or []
        for field in ("command", "rollback")
    )


def build_display(plan: Any) -> Dict[str, Any]:
    """대시보드가 그대로 쓸 수 있는 라벨·범례 묶음."""
    display: Dict[str, Any] = {
        "status_label": status_label(getattr(plan, "response_status", "")),
        "autonomy_legend": dict(AUTONOMY_LEGEND),
        "priority_legend": dict(PRIORITY_LEGEND),
        "category_labels": dict(CATEGORY_LABELS),
        "field_labels": dict(FIELD_LABELS),
        "llm_authored_commands": llm_authored_commands(plan),
    }
    if display["llm_authored_commands"]:
        display["llm_authored_notice"] = LLM_AUTHORED_NOTICE
    if getattr(plan, "mapping_status", None) == "partial":
        display["mapping_note"] = MAPPING_PARTIAL_SUFFIX
    return display


def decorate(document: Dict[str, Any], plan: Any) -> Dict[str, Any]:
    """json으로 저장할 dict에 사람이 읽는 문장을 채워 넣는다(제자리에서 고친다).

    - warnings[].message — 코드만 있던 경고에 설명 문장을 붙인다
    - display            — 상태 라벨·범례·LLM 작성 안내
    원래 값은 지우지 않는다(코드·detail은 그대로 남는다).
    """
    warnings = document.get("warnings")
    if isinstance(warnings, list):
        for warning in warnings:
            if isinstance(warning, dict) and not warning.get("message"):
                warning["message"] = warning_message(warning)
    document["display"] = build_display(plan)
    return document


if __name__ == "__main__":  # 자체 점검: python llm/respond/labels.py
    assert status_label("recommended") == "확정 · 권고"
    assert status_label("없는상태") == "없는상태"
    assert "신뢰하지 마십시오" in warning_message({"code": "FALLBACK_VERDICT"})
    assert warning_message({"code": "UNKNOWN", "detail": "매핑이 준 설명"}) == "매핑이 준 설명"
    assert warning_message({}) == "알 수 없는 경고"
    assert "현재 자동 실행 안 함" in AUTONOMY_LEGEND["L2"]

    class _Action:
        def __init__(self, fields):
            self.llm_fields = fields

    class _Plan:
        response_status = "recommended"
        mapping_status = "partial"
        actions = [_Action(["reason"]), _Action(["command"])]

    display = build_display(_Plan())
    assert display["llm_authored_commands"] is True
    assert "실행 전 대상과 명령을" in display["llm_authored_notice"]
    assert display["mapping_note"] == "일부만 확인됨"

    class _PlanNoLLM(_Plan):
        mapping_status = "mapped"
        actions = [_Action(["reason"])]

    display2 = build_display(_PlanNoLLM())
    assert display2["llm_authored_commands"] is False
    assert "llm_authored_notice" not in display2 and "mapping_note" not in display2

    doc = decorate({"warnings": [{"code": "FALLBACK_VERDICT", "detail": "누적 confidence"}]},
                    _Plan())
    assert doc["warnings"][0]["code"] == "FALLBACK_VERDICT"          # 원래 값은 남는다
    assert "신뢰하지 마십시오" in doc["warnings"][0]["message"]
    assert doc["display"]["status_label"] == "확정 · 권고"
    print("ok")
