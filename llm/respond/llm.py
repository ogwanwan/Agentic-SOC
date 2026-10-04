"""대응 권고 LLM 호출과 응답 검증 (설계서 8절) — "제안은 좁게, 검증은 꼼꼼하게".

역할
  코드가 이미 확정한 ResponsePlan을 받아, LLM에게 **문장 세 칸만** 채우게 한다.
    ResponsePlan.summary / ResponsePlan.analyst_note / Action.reason
  조치 목록·대상·라벨·기법은 코드(담당 A의 catalog·decide)가 정한 그대로 둔다.
  LLM이 조치를 추가·삭제하거나 없는 증거를 인용하면 코드가 걸러낸다.

  LLM이 실패해도(API 장애·JSON 깨짐·검증 탈락) 권고문은 반드시 나온다 —
  카탈로그가 미리 적어 둔 default_reason으로 대체한다. LLM 장애가 파이프라인을 멈추지 않는다.

검증 규칙 (설계서 8-3)
  1. 조치의 target이 추출된 대상 집합에 실제로 있는가       → 해당 조치 폐기
  2. LLM이 돌려준 action_id 집합 == 입력 집합인가           → 응답 전체 거절(fallback)
  3. 모든 조치에 reason이 있는가                            → 그 조치만 default_reason
  4. reason이 인용한 EVID-*가 evidence_chain에 있는가        → 그 인용만 제거
  5. technique_id가 attack_mapping.techniques[]에 있는가     → 해당 조치 폐기(기법 환각 방지)
  1·5는 LLM을 부르기 전에(코드가 만든 조치 자체를) 보고, 2·3·4는 LLM 응답을 보고 적용한다.

누가 부르나
  respond/cli.py  process_file()  → run_llm_stage()

무엇을 부르나
  respond/prompts/              build_system_prompt(), build_user_prompt()
  respond/investigate_bridge.py build_llm_client(RESPONSE)  — 조사 쪽 클라이언트 재사용
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[1])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond import investigate_bridge  # noqa: E402
from respond.models import Action, ResponsePlan  # noqa: E402
from respond.prompts import build_system_prompt, build_user_prompt  # noqa: E402

# reason 안의 증거 인용 — "EVID-003" 형태
EVIDENCE_REF_RE = re.compile(r"EVID-\d+")
# 인용을 지운 뒤 남는 빈 괄호·연속 공백 정리용
_EMPTY_PAREN_RE = re.compile(r"[(（]\s*[,，、\s]*[)）]")
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")

# reason이 이보다 길면 한 문장 요청을 어긴 것으로 보고 자른다(권고문 줄맞춤이 깨진다)
MAX_REASON_CHARS = 200
MAX_SUMMARY_CHARS = 600


class LLMStageReport:
    """이번 사건에서 LLM 단계에 무슨 일이 있었는지 — run_log.jsonl에 그대로 기록된다.

    권고문 본문에는 안 나오지만, "왜 이 조치가 빠졌는지"를 나중에 확인하는 유일한 근거다.
    """

    def __init__(self) -> None:
        self.llm_called: bool = False
        self.llm_model: Optional[str] = None
        self.used_fallback: bool = False          # default_reason으로 대체했는가
        self.fallback_reason: Optional[str] = None
        self.dropped_actions: List[Dict[str, str]] = []   # 폐기된 조치와 사유
        self.stripped_citations: List[Dict[str, str]] = []  # 제거된 증거 인용
        self.reasons_defaulted: List[str] = []    # default_reason으로 채운 action_id
        self.notes: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "llm_called": self.llm_called,
            "llm_model": self.llm_model,
            "used_fallback": self.used_fallback,
            "fallback_reason": self.fallback_reason,
            "dropped_actions": self.dropped_actions,
            "stripped_citations": self.stripped_citations,
            "reasons_defaulted": self.reasons_defaulted,
            "notes": self.notes,
        }


# ----------------------------------------------------------------------
# LLM 호출 전 검증 — 규칙 1·5 (코드가 만든 조치 자체를 본다)
# ----------------------------------------------------------------------

def validate_actions(
    plan: ResponsePlan,
    *,
    allowed_targets: Optional[Set[str]] = None,
    allowed_technique_ids: Optional[Set[str]] = None,
    report: Optional[LLMStageReport] = None,
) -> ResponsePlan:
    """규칙 1·5 — 대상·기법이 실제 출처에 있는 조치만 남긴다. plan을 제자리에서 고친다.

    allowed_targets      담당 A의 entities.py가 뽑은 조치 대상 집합. None이면 검사하지 않는다
                         (추출 결과를 넘겨받지 못한 경우 — 검사를 건너뛴 사실을 notes에 남긴다).
    allowed_technique_ids attack_mapping.techniques[]의 technique_id 집합. None이면 검사하지 않는다.

    target이 None인 조치(대상 없는 "확인 필요" 항목)는 검사 대상이 아니다 — 지울 값이 없다.
    """
    report = report or LLMStageReport()
    kept: List[Action] = []

    if allowed_targets is None:
        report.notes.append("조치 대상 검증 건너뜀 — 추출된 대상 집합을 받지 못함")
    if allowed_technique_ids is None and any(a.technique_id for a in plan.actions):
        report.notes.append("기법 검증 건너뜀 — 매핑 기법 집합을 받지 못함")

    for action in plan.actions:
        # 규칙 1 — 대상이 실제 추출 결과에 있는가 (대상 없는 점검 항목은 통과)
        if action.target is not None and allowed_targets is not None:
            if action.target not in allowed_targets:
                report.dropped_actions.append({
                    "action_id": action.action_id,
                    "title": action.title,
                    "rule": "target_not_in_sources",
                    "detail": f"조치 대상 {action.target!r}이 추출된 대상 집합에 없음",
                })
                continue
        # 규칙 5 — 기법 환각 방지
        if action.technique_id and allowed_technique_ids is not None:
            if action.technique_id not in allowed_technique_ids:
                report.dropped_actions.append({
                    "action_id": action.action_id,
                    "title": action.title,
                    "rule": "technique_not_mapped",
                    "detail": f"{action.technique_id}이 attack_mapping.techniques[]에 없음",
                })
                continue
        kept.append(action)

    plan.actions = kept
    return plan


# ----------------------------------------------------------------------
# LLM 응답 검증 — 규칙 2·3·4
# ----------------------------------------------------------------------

def _clean_text(value: Any, limit: int) -> Optional[str]:
    """LLM이 준 값이 쓸 수 있는 문자열이면 다듬어서, 아니면 None."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split()).strip()
    if not text:
        return None
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


def strip_unknown_citations(
    text: str, known_evidence_ids: Set[str]
) -> Tuple[str, List[str]]:
    """규칙 4 — reason이 인용한 EVID-* 중 evidence_chain에 없는 것을 지운다.

    문장 자체는 살린다(인용만 틀렸다고 근거 문장을 통째로 버리면 권고문이 빈약해진다).
    인용을 지운 뒤 "( )"처럼 남은 빈 괄호와 겹공백을 정리한다.
    """
    if not EVIDENCE_REF_RE.search(text):
        return text, []

    removed: List[str] = []

    def _replace(match: "re.Match[str]") -> str:
        ref = match.group(0)
        if ref in known_evidence_ids:
            return ref
        removed.append(ref)
        return ""

    cleaned = EVIDENCE_REF_RE.sub(_replace, text)
    if removed:
        cleaned = _EMPTY_PAREN_RE.sub("", cleaned)
        # 인용을 지우면서 생긴 ", )" / "( ," 같은 자투리 정리
        cleaned = re.sub(r"[(（]\s*[,，、]\s*", "(", cleaned)
        cleaned = re.sub(r"\s*[,，、]\s*[)）]", ")", cleaned)
        cleaned = _MULTI_SPACE_RE.sub(" ", cleaned).strip()
        cleaned = re.sub(r"\s+([.。])", r"\1", cleaned)
    return cleaned, removed


def apply_llm_payload(
    plan: ResponsePlan,
    payload: Dict[str, Any],
    *,
    known_evidence_ids: Set[str],
    report: LLMStageReport,
) -> bool:
    """LLM 응답(dict)을 검증해 plan에 반영한다. 응답 전체를 거절하면 False.

    규칙 2 — action_id 집합이 입력과 정확히 같아야 한다. 하나라도 빠지거나 없는 id가 섞이면
    **응답 전체를 버린다**. 일부만 받아들이면 "LLM이 조치를 지운" 결과가 조용히 통과한다.
    """
    if not isinstance(payload, dict):
        report.fallback_reason = "LLM 응답이 JSON 객체가 아님"
        return False

    raw_actions = payload.get("actions")
    if not isinstance(raw_actions, list):
        report.fallback_reason = "LLM 응답에 actions 배열이 없음"
        return False

    returned: Dict[str, Any] = {}
    for item in raw_actions:
        if not isinstance(item, dict):
            report.fallback_reason = "actions 원소가 객체가 아님"
            return False
        action_id = item.get("action_id")
        if not isinstance(action_id, str):
            report.fallback_reason = "actions 원소에 action_id 문자열이 없음"
            return False
        if action_id in returned:
            report.fallback_reason = f"action_id 중복: {action_id}"
            return False
        returned[action_id] = item

    expected = set(plan.action_ids())
    got = set(returned)
    if expected != got:
        missing = sorted(expected - got)
        extra = sorted(got - expected)
        report.fallback_reason = (
            "LLM이 돌려준 action_id 집합이 입력과 다름 "
            f"(빠짐={missing or '-'}, 없는 id={extra or '-'})"
        )
        return False

    # 여기부터는 받아들인다 — 규칙 3·4는 조치 단위로 처리한다
    for action in plan.actions:
        text = _clean_text(returned[action.action_id].get("reason"), MAX_REASON_CHARS)
        if text is None:
            # 규칙 3 — reason이 없거나 빈 문자열이면 그 조치만 기본 문장으로
            action.reason = None
            report.reasons_defaulted.append(action.action_id)
            continue
        # 규칙 4 — 없는 증거 인용 제거
        text, removed = strip_unknown_citations(text, known_evidence_ids)
        for ref in removed:
            report.stripped_citations.append({"action_id": action.action_id, "evidence_id": ref})
        text = text.strip()
        if not text:
            action.reason = None
            report.reasons_defaulted.append(action.action_id)
            continue
        action.reason = text

    summary = _clean_text(payload.get("summary"), MAX_SUMMARY_CHARS)
    if summary:
        summary, removed = strip_unknown_citations(summary, known_evidence_ids)
        for ref in removed:
            report.stripped_citations.append({"action_id": "(summary)", "evidence_id": ref})
        plan.summary = summary.strip() or None

    note = _clean_text(payload.get("analyst_note"), MAX_SUMMARY_CHARS)
    if note:
        note, removed = strip_unknown_citations(note, known_evidence_ids)
        for ref in removed:
            report.stripped_citations.append({"action_id": "(analyst_note)", "evidence_id": ref})
        plan.analyst_note = note.strip() or None

    return True


def apply_fallback(plan: ResponsePlan, report: LLMStageReport) -> None:
    """LLM 없이 카탈로그의 기본 문장으로 채운다(설계서 8-2 — LLM 장애가 파이프라인을 멈추지 않는다).

    Action.reason은 None으로 두고 render가 effective_reason()으로 default_reason을 쓴다.
    summary는 코드가 만들 수 없는 값이라 비워 둔다 — render가 판정·공격 유형 줄로 대신한다.
    """
    report.used_fallback = True
    for action in plan.actions:
        action.reason = None
    plan.analyst_note = None


# ----------------------------------------------------------------------
# 진입점
# ----------------------------------------------------------------------

def run_llm_stage(
    plan: ResponsePlan,
    *,
    evidence_chain: Sequence[Dict[str, Any]] = (),
    allowed_targets: Optional[Set[str]] = None,
    allowed_technique_ids: Optional[Set[str]] = None,
    llm_client: Any = None,
) -> LLMStageReport:
    """조치 검증 → LLM 1회 호출 → 응답 검증 → 실패 시 fallback. plan을 제자리에서 채운다.

    llm_client를 넘기면 그것을 쓰고(테스트·main.py 재사용), 없으면 RESPONSE_* 설정으로 만든다.
    어떤 경우에도 예외를 올리지 않는다 — 권고문은 반드시 나와야 한다.
    """
    report = LLMStageReport()

    # 규칙 1·5 — LLM을 부르기 전에 조치 자체를 거른다
    validate_actions(
        plan,
        allowed_targets=allowed_targets,
        allowed_technique_ids=allowed_technique_ids,
        report=report,
    )

    # 조치가 실리지 않는 상태(오탐·보류·건너뜀)는 LLM을 부르지 않는다 — 고정 문구로 나간다
    if not plan.has_actions():
        report.notes.append(f"LLM 호출 안 함 — response_status={plan.response_status}")
        return report

    known_evidence_ids = {
        str(e.get("evidence_id")) for e in (evidence_chain or []) if e.get("evidence_id")
    }

    client = llm_client
    if client is None:
        try:
            client = investigate_bridge.build_llm_client()
        except Exception as exc:  # 설정 누락·역할 미등록·키 없음 — 권고문은 계속 만든다
            report.fallback_reason = f"LLM 클라이언트 준비 실패: {exc}"
            apply_fallback(plan, report)
            return report

    report.llm_model = getattr(client, "model", None)

    try:
        payload = client.complete_json(
            build_system_prompt(),
            build_user_prompt(plan, list(evidence_chain or [])),
        )
        report.llm_called = True
    except Exception as exc:
        # LLMUnavailableError(일시 오류)·DecisionError(JSON 깨짐·거절)·그 밖의 오류 모두 같은 처리
        try:
            unavailable = investigate_bridge.llm_unavailable_error()
        except Exception:  # pragma: no cover - bridge 자체가 안 되는 환경
            unavailable = ()
        kind = "LLM API 일시 오류" if unavailable and isinstance(exc, unavailable) else "LLM 호출 실패"
        report.fallback_reason = f"{kind}: {exc}"
        apply_fallback(plan, report)
        return report

    if not apply_llm_payload(plan, payload, known_evidence_ids=known_evidence_ids, report=report):
        apply_fallback(plan, report)

    return report
