"""대응 권고 LLM 프롬프트 조립 (설계서 8절).

역할
  시스템 프롬프트: response.yaml(역할·금지사항·출력 형식·규칙)을 이어 붙인다.
  사용자 프롬프트: 사건 판정 + **코드가 이미 확정한 조치 목록** + ATT&CK 매핑 결과
  (기법과 그 기법을 뒷받침한 evidence_ids) + evidence_chain + kill_chain을 JSON으로 넘긴다.

  2026-10-06 확정: LLM이 조치마다 7칸(reason·command·rollback·side_effects·verification·
  autonomy_reason·priority)을 **직접 쓴다**. 그래서 예전처럼 target을 숨기지 않는다 —
  명령을 쓰려면 대상을 알아야 한다. 대신 돌려받은 문장은 llm.py가 칸별로 검증한다
  (입력에 없는 IP·경로를 적으면 그 칸은 버려지고 카탈로그 문장이 나간다).

  **근거는 ATT&CK 매핑 파일에서만 가져온다.** attack_techniques[]에 기법과 evidence_ids를
  실어 주고, 각 조치에는 그 조치가 딸린 기법의 evidence_ids를 함께 준다. reason은 그중
  최소 하나를 인용해야 하고(규칙 6), 목록에 없는 기법·증거를 적으면 그 인용이 지워진다.

  프롬프트에 넣지 않는 것 (설계서 3-1 "안 읽는 것")
    - evidence_chain[].raw_refs, source_log 같은 원본 추적용 필드
    - tools_called[].result_summary, 조사 reasoning 원문
    - 카탈로그가 미리 적어 둔 문장(rollback·side_effects·verification·command_template)
      → 보여 주면 그대로 베껴 적는다. 이 칸들은 LLM이 직접 쓰는 것이 이번 변경의 목적이고,
        카탈로그 문장은 검증에 걸린 칸을 되돌릴 폴백으로만 쓴다(llm.py).

누가 부르나
  respond/llm.py  run_llm_stage()  → build_system_prompt(), build_user_prompt()

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
MAX_TECHNIQUES = 15
# 기법 매칭 근거 키워드는 몇 개만 — 매핑 내부 흔적을 다 보여 줄 필요는 없다
MAX_MATCHED_KEYWORDS = 5

# 조치 명령을 쓸 때 전제로 삼을 환경 — 권고문의 명령이 실제로 돌아가는 곳
ENVIRONMENT = {
    "os": "Linux",
    "shell": "bash",
    "privilege": "sudo 사용 가능",
    "quarantine_dir": "/var/quarantine/",
}


def _load_yaml(filename: str) -> Dict[str, Any]:
    with open(_PACKAGE_DIR / filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


_spec = _load_yaml("response.yaml")
_selection_spec = _load_yaml("selection.yaml")


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


# ----------------------------------------------------------------------
# 2026-10-06 추가 — 조치 "선택" 단계(LLM 호출 1). 7칸 작성(위) 프롬프트와는 독립된
# 시스템/사용자 프롬프트다. 같은 조립 방식(yaml 본문 + 섹션 이어 붙이기)을 그대로 쓴다.
# ----------------------------------------------------------------------

def _build_selection_system_prompt_template() -> str:
    parts = [_selection_spec["role"].strip()]
    parts.append("## 출력 형식")
    parts.append(
        "반드시 아래 JSON 스키마와 동일한 하나의 JSON 객체만 출력하십시오.\n"
        "다른 설명 문장, 마크다운, 코드펜스를 포함하지 마십시오."
    )
    parts.append(_selection_spec["output_schema"].strip())
    parts.append("## 규칙")
    parts.append(_selection_spec["rules"].strip())
    return "\n\n".join(parts) + "\n"


SELECTION_SYSTEM_PROMPT = _build_selection_system_prompt_template()


def build_selection_system_prompt() -> str:
    """선택 단계 시스템 프롬프트 — 사건과 무관하게 항상 같다(캐시 효율)."""
    return SELECTION_SYSTEM_PROMPT


def _candidate_brief(candidate: Any) -> Dict[str, Any]:
    """선택 단계에 보여 줄 후보 한 건. target은 안 보여 준다(이미 코드가 하나로 정함)."""
    from respond.catalog import requires_approval  # 순환 import 방지용 지연 import

    template = candidate.template
    brief: Dict[str, Any] = {
        "candidate_id": template.template_id,
        "title": template.title,
        "category": template.category,
        "fixed": {
            "autonomy": template.autonomy,
            "risk": template.risk,
            "reversible": template.reversible,
            "requires_approval": requires_approval(template.autonomy),
        },
    }
    if candidate.technique_id:
        brief["technique_id"] = candidate.technique_id
        brief["technique_name"] = candidate.technique_name
    if candidate.evidence_ids:
        brief["evidence_ids"] = [str(e) for e in candidate.evidence_ids]
    if template.requires:
        brief["requires"] = list(template.requires)
    return brief


def build_selection_user_prompt(
    pool: Any, incident_facts: Dict[str, Any], *, previous_error: str = "",
) -> str:
    """사건 요약 + 후보 풀을 JSON으로 만든다. previous_error가 있으면 재시도 안내를 덧붙인다."""
    payload: Dict[str, Any] = dict(incident_facts)
    payload["candidates"] = [_candidate_brief(c) for c in pool.candidates]
    payload["mandatory_candidate_ids"] = sorted(pool.mandatory_ids)

    instruction = "이번 사건에 쓸 조치를 candidates 중에서 고르십시오."
    if previous_error:
        instruction = (
            _selection_spec["retry_note"].strip().format(error=previous_error)
            + "\n\n" + instruction
        )
    return instruction + "\n\n" + json.dumps(payload, ensure_ascii=False, indent=2)


def build_system_prompt() -> str:
    """사건과 무관하게 항상 같은 시스템 프롬프트 (캐시 효율)."""
    return SYSTEM_PROMPT


def _action_brief(action: Any) -> Dict[str, Any]:
    """LLM에게 보여 줄 조치 한 건 — 7칸을 쓰는 데 필요한 사실만.

    target을 보여 준다(명령을 쓰려면 필요하다). 대신 `fixed`에 코드가 정한 사실을 함께 주고,
    LLM의 문장이 그 사실과 어긋나면 llm.py가 그 칸을 버린다.
    카탈로그가 적어 둔 문장(rollback·side_effects·verification·command)은 보여 주지 않는다.
    """
    brief: Dict[str, Any] = {
        "action_id": action.action_id,
        "title": action.title,
        # 대상이 없는 점검 항목은 null — 명령·원복을 쓰지 말라는 신호다
        "target": action.target or None,
        "category": action.category,
        "fixed": {
            # 코드가 정한 사실. 바꿀 수 없고, 어긋나는 문장을 쓰면 그 칸이 버려진다.
            "reversible": action.reversible,
            "risk": action.risk,
            "autonomy": action.autonomy,
            "autonomy_downgraded_from": action.autonomy_downgraded_from,
        },
    }
    if action.target_source:
        brief["target_source"] = action.target_source
    if action.technique_id:
        brief["technique_id"] = action.technique_id
    if action.technique_name:
        brief["technique_name"] = action.technique_name
    if action.tactic_name:
        brief["tactic_name"] = action.tactic_name
    if action.evidence_ids:
        # 이 조치의 근거 — reason에 반드시 이 중 하나를 인용해야 한다(규칙 6)
        brief["evidence_ids"] = [str(e) for e in action.evidence_ids]
    return brief


def _technique_brief(technique: Dict[str, Any]) -> Dict[str, Any]:
    """attack_mapping.techniques[] 한 건 — 기법과 그 기법을 뒷받침한 증거·키워드.

    raw_refs·matches 같은 원본 추적용 필드는 싣지 않는다(설계서 3-1 "안 읽는 것").
    """
    brief: Dict[str, Any] = {
        "technique_id": technique.get("technique_id"),
        "technique_name": technique.get("technique_name"),
        "tactic_name": technique.get("tactic_name"),
    }
    evidence_ids = technique.get("evidence_ids")
    if isinstance(evidence_ids, list) and evidence_ids:
        brief["evidence_ids"] = [str(e) for e in evidence_ids]
    keywords = technique.get("matched_keywords")
    if isinstance(keywords, list) and keywords:
        # 매핑이 이 기법을 고른 근거 키워드 — reason을 쓸 때 참고한다
        brief["matched_keywords"] = [str(k) for k in keywords[:MAX_MATCHED_KEYWORDS]]
    return {k: v for k, v in brief.items() if v}


def _evidence_brief(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """evidence_chain 한 줄 — 인용용 id와 사람이 읽을 설명만."""
    return {
        "evidence_id": evidence.get("evidence_id"),
        "time": evidence.get("time"),
        "layer": evidence.get("layer"),
        "description": evidence.get("description"),
    }


def build_user_prompt(plan: Any, evidence_chain: List[Dict[str, Any]]) -> str:
    """사건 판정 + 조치 목록 + ATT&CK 매핑 근거 + 증거를 JSON으로 만든다."""
    payload: Dict[str, Any] = {
        "incident_id": plan.incident_id,
        "verdict": plan.verdict,
        "severity": plan.severity,
        "attack_type": plan.attack_type,
        "host": plan.host,
        "occurred_at": plan.occurred_at,
        "environment": ENVIRONMENT,
        # 코드가 이미 고른 조치 — 이 목록을 그대로 두고 7칸을 채운다
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

    # ATT&CK 매핑 근거 — 기법을 가리킬 때 쓸 수 있는 **유일한** 목록
    techniques = [
        _technique_brief(t) for t in (getattr(plan, "techniques", None) or [])[:MAX_TECHNIQUES]
    ]
    if techniques:
        payload["attack_techniques"] = techniques
    attack_data = getattr(plan, "attack_data", None) or {}
    if attack_data.get("version"):
        payload["attack_data_version"] = attack_data["version"]

    if plan.remaining_unknowns:
        payload["remaining_unknowns"] = list(plan.remaining_unknowns)

    required_evidence = sorted({
        str(e) for action in plan.actions for e in (action.evidence_ids or [])
    })
    instruction = (
        "아래는 이미 확정된 사건 판정과 **코드가 선택한 조치 목록**입니다.\n"
        "조치를 추가·삭제하지 말고, 각 action_id마다 reason·command·rollback·side_effects·\n"
        "verification·autonomy_reason·priority 일곱 칸을 모두 채운 JSON만 출력하십시오.\n"
        f"돌려줘야 할 action_id: {', '.join(plan.action_ids()) or '(없음)'}\n"
        "근거는 attack_techniques와 evidence_chain에서만 가져옵니다 — 각 조치의 reason에는\n"
        "그 조치의 evidence_ids 중 최소 하나를 괄호로 인용해야 합니다."
    )
    if required_evidence:
        instruction += f"\n인용 가능한 증거: {', '.join(required_evidence)}"
    note = (_spec.get("status_notes") or {}).get(plan.response_status)
    if note:
        instruction += "\n\n[이 사건의 상태] " + note.strip()

    return instruction + "\n\n" + json.dumps(payload, ensure_ascii=False, indent=2)
