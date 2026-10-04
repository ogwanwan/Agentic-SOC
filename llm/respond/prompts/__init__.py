"""대응 권고 LLM 프롬프트 조립 (설계서 8절).

역할
  시스템 프롬프트: response.yaml(역할·금지사항·출력 형식·규칙)을 이어 붙인다.
  사용자 프롬프트: **코드가 이미 확정한** 조치 목록 + 판정 요약 + evidence_chain + kill_chain을
  JSON으로 만들어 넘긴다.

  프롬프트에 넣지 않는 것 (설계서 3-1 "안 읽는 것"):
    - evidence_chain[].raw_refs, source_log 같은 원본 추적용 필드
    - tools_called[].result_summary, 조사 reasoning 원문
    - 조치의 target·autonomy·risk·command_hint
      → LLM이 바꿀 수 없게 아예 보여 주지 않는다. 받지 못한 값은 되돌려줄 수도 없다.
  프롬프트가 작아지고, LLM이 검증되지 않은 사실을 끌어올 여지가 줄어든다.

누가 부르나
  respond/llm.py  generate_reasons()  → build_system_prompt(), build_user_prompt()

무엇을 부르나
  response.yaml (같은 폴더)  프롬프트 본문 — 문구를 바꿀 때는 이 파일을 고친다

프롬프트 "내용"(yaml)과 "조립 로직"(이 파일)을 나눠 두어, 문구를 고칠 때 코드를 건드리지 않게 했다
(조사 에이전트 agent/prompts/와 같은 방식).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

_PACKAGE_DIR = Path(__file__).resolve().parent

# 프롬프트에 싣는 증거 개수 상한 — 사건이 커져도 프롬프트가 무한정 길어지지 않게 한다.
MAX_EVIDENCE = 20
MAX_KILL_CHAIN = 15


def _load_yaml(filename: str) -> Dict[str, Any]:
    with open(_PACKAGE_DIR / filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


_spec = _load_yaml("response.yaml")


def _build_system_prompt_template() -> str:
    """response.yaml의 섹션을 이어 붙여 시스템 프롬프트를 만든다.

    출력 스키마에 중괄호가 많아 .format()을 쓰지 않는다(조사 프롬프트와 같은 이유).
    """
    parts = [_spec["role"].strip()]
    parts.append("## 출력 형식")
    parts.append(
        "반드시 아래 JSON 스키마와 동일한 하나의 JSON 객체만 출력하십시오.\n"
        "다른 설명 문장, 마크다운, 코드펜스를 포함하지 마십시오."
    )
    parts.append(_spec["output_schema"].strip())
    parts.append("## 규칙")
    parts.append(_spec["rules"].strip())
    return "\n\n".join(parts) + "\n"


SYSTEM_PROMPT = _build_system_prompt_template()


def build_system_prompt() -> str:
    """사건과 무관하게 항상 같은 시스템 프롬프트 (캐시 효율)."""
    return SYSTEM_PROMPT


def _action_brief(action: Any) -> Dict[str, Any]:
    """LLM에게 보여 줄 조치 한 건 — reason을 쓰는 데 필요한 최소 정보만.

    target·autonomy·risk·command_hint는 **일부러 뺀다**. 보여 주지 않으면 되돌려줄 수도 없고,
    reason 안에 대상 값을 그대로 베껴 적는 일도 줄어든다(환각 IP·경로 방지).
    """
    brief: Dict[str, Any] = {"action_id": action.action_id, "title": action.title}
    if action.technique_id:
        brief["technique"] = f"{action.technique_id} {action.technique_name or ''}".strip()
    if action.tactic_name:
        brief["tactic"] = action.tactic_name
    if action.evidence_ids:
        brief["evidence_ids"] = list(action.evidence_ids)
    # "확인 필요" 묶음인지 알려 주면 reason의 어조가 맞는다(조치 vs 점검)
    brief["category"] = action.category
    return brief


def _evidence_brief(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """evidence_chain 한 줄 — 인용용 id와 사람이 읽을 설명만."""
    return {
        "evidence_id": evidence.get("evidence_id"),
        "time": evidence.get("time"),
        "layer": evidence.get("layer"),
        "description": evidence.get("description"),
    }


def build_user_prompt(plan: Any, evidence_chain: List[Dict[str, Any]]) -> str:
    """코드가 확정한 조치 목록 + 판정 요약 + 증거 + 킬체인을 JSON으로 만든다."""
    payload: Dict[str, Any] = {
        "incident_id": plan.incident_id,
        "verdict": plan.verdict,
        "severity": plan.severity,
        "attack_type": plan.attack_type,
        "host": plan.host,
        "occurred_at": plan.occurred_at,
        # 코드가 이미 고른 조치 — 이 목록을 그대로 두고 reason만 채운다
        "actions": [_action_brief(a) for a in plan.actions],
        "kill_chain": [
            {
                "step": step.get("step"),
                "tactic_name": step.get("tactic_name"),
                "technique_id": step.get("technique_id"),
                "technique_name": step.get("technique_name"),
                "time": step.get("time"),
            }
            for step in (plan.kill_chain or [])[:MAX_KILL_CHAIN]
        ],
        "evidence_chain": [_evidence_brief(e) for e in (evidence_chain or [])[:MAX_EVIDENCE]],
    }
    if plan.remaining_unknowns:
        payload["remaining_unknowns"] = list(plan.remaining_unknowns)

    instruction = (
        "아래는 이미 확정된 사건 판정과 **코드가 선택한 조치 목록**입니다.\n"
        "조치를 추가·삭제하지 말고, 각 action_id에 reason을 채운 JSON만 출력하십시오.\n"
        f"돌려줘야 할 action_id: {', '.join(plan.action_ids()) or '(없음)'}"
    )
    note = (_spec.get("status_notes") or {}).get(plan.response_status)
    if note:
        instruction += "\n\n[이 사건의 상태] " + note.strip()

    return instruction + "\n\n" + json.dumps(payload, ensure_ascii=False, indent=2)
