"""대응 권고 공용 계약 — Action / ResponsePlan (설계서 11절).

역할
  담당 A(결정 로직: contract·gate·entities·catalog·decide)와 담당 B(LLM·출력: llm·render·cli)가
  주고받는 유일한 자료구조다. 담당 A가 ResponsePlan을 완성해서 넘기면, 담당 B는
  summary·analyst_note·actions[].reason 세 칸만 채우고(llm.py) 텍스트로 그린다(render.py).

  LLM이 채우는 칸과 코드가 정하는 칸을 자료구조 수준에서 갈라 둔다:
    코드가 정함 — action_id, title, target, target_source, technique_id, autonomy, risk, …
    LLM이 채움  — ResponsePlan.summary, ResponsePlan.analyst_note, Action.reason
  LLM이 조치를 새로 만들거나 target을 바꾸면 llm.py가 거절한다(설계서 8-3).

누가 부르나
  respond/decide.py (담당 A)   → ResponsePlan·Action 생성
  respond/llm.py    (담당 B)   → reason·summary·analyst_note 채우기
  respond/render.py (담당 B)   → 텍스트 권고문 생성
  respond/cli.py    (담당 B)   → JSON 저장(to_dict)

주의
  Python 3.10 호환(EC2 운영 환경). `list[str]` 같은 내장 제네릭은 3.9+에서 동작하지만
  from __future__ import annotations와 함께 쓴다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# ----------------------------------------------------------------------
# 설계서에서 정한 값 목록 — 문자열을 코드 여기저기 흩지 않으려고 모아 둔다
# ----------------------------------------------------------------------

# 진입 관문(4절)이 정하는 사건 처리 결과
RESPONSE_STATUSES = (
    "recommended",          # THREAT_CONFIRMED + 기법 매핑됨 → 기법 기반 카탈로그
    "recommended_generic",  # THREAT_CONFIRMED + 기법 0개   → 폴백 카탈로그
    "not_applicable",       # FALSE_POSITIVE → 오탐 종결문 + 룰 튜닝 제안
    "deferred",             # INCONCLUSIVE 또는 원본 추적 불가 → 확인 요청문
    "skipped",              # 조사 미완료(INCOMPLETE) → 권고 없음
    "error",                # 입력 구조 오류 → 사유만 기록
)

# 권고문에 조치가 실리는 상태 (나머지는 조치 없이 머리말·안내문만 나간다)
STATUSES_WITH_ACTIONS = ("recommended", "recommended_generic")

AUTONOMY_LEVELS = ("L0", "L1", "L2")
RISK_LEVELS = ("LOW", "MED", "HIGH")

# Action.category — 권고문에서 [즉시 조치] / [확인 필요] 두 묶음으로 나뉜다
CATEGORY_IMMEDIATE = "immediate"
CATEGORY_VERIFY = "verify_needed"

# Action.target_source — 조치 대상을 어디서 꺼냈는지(5-1절 출처 우선순위).
# llm.py가 "LLM이 target을 바꾸지 않았는가"를 검증할 때, render가 근거를 표시할 때 쓴다.
TARGET_SOURCES = (
    "seed_detail",    # initial_seed.detection.rules[].detail (1순위, 코드 추출)
    "seed_src_ip",    # initial_seed.src_ip / host (1순위, 코드 추출)
    "tool_input",     # tools_called[].input (2순위, 실제 조회에 쓴 인자)
)


@dataclass
class Action:
    """권고문에 실리는 조치 한 건.

    target이 None이면 대상이 특정되지 않는 "확인해 보라"는 항목이다(예: UID 0 계정 목록 확인).
    이때는 실행할 명령을 줄 수 없으므로 L0으로 둔다(설계서 5-4·7절).
    """

    action_id: str
    title: str
    # 조치 대상. 대상을 확보하지 못하면 조치를 만들지 않는 것이 원칙(5-4절)이지만,
    # "무엇을 확인하라"는 점검 항목은 대상 없이도 의미가 있어 None을 허용한다.
    target: Optional[str]
    # target이 None이면 출처도 없다
    target_source: Optional[str]
    technique_id: Optional[str]
    technique_name: Optional[str]
    tactic_name: Optional[str]
    reversible: bool
    risk: str                               # LOW | MED | HIGH
    autonomy: str                           # L0 | L1 | L2
    autonomy_downgraded_from: Optional[str] = None  # 하향 전 라벨(7절) — 권고문에 "하향됨" 표시
    category: str = CATEGORY_IMMEDIATE      # immediate | verify_needed
    command_hint: Optional[str] = None      # L1 수동 실행 명령 예시
    evidence_ids: List[str] = field(default_factory=list)
    # LLM 호출 실패·검증 탈락 시 쓸 코드가 미리 적어 둔 근거 문장 (카탈로그가 채운다)
    default_reason: str = ""
    # ↓ LLM이 채우는 유일한 칸
    reason: Optional[str] = None

    def effective_reason(self) -> str:
        """권고문에 실제로 실릴 근거 문장. LLM이 못 채웠으면 카탈로그의 기본 문장."""
        return (self.reason or "").strip() or self.default_reason

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResponsePlan:
    """사건 한 건의 대응 권고 전체. respond/cli.py가 이것을 JSON·텍스트 두 가지로 저장한다."""

    incident_id: str
    response_status: str                    # RESPONSE_STATUSES 중 하나
    verdict: str
    severity: str
    verdict_confidence: float               # final_verdict.confidence (판정 확신도)
    investigation_confidence: float         # statistics.investigation_confidence (증거 누적 신뢰도)
    provenance_status: str                  # 조사 단계 provenance.status
    mapping_status: str                     # attack_mapping.mapping_status
    incident_key: Optional[str] = None
    investigation_id: Optional[str] = None
    host: Optional[str] = None
    occurred_at: Optional[str] = None       # 사건 발생 시각(권고문 머리말)
    attack_type: Optional[str] = None
    kill_chain: List[Dict[str, Any]] = field(default_factory=list)
    actions: List[Action] = field(default_factory=list)
    # attack_mapping.warnings[] 를 그대로 싣는다 (FALLBACK_VERDICT 등 → 머리말 경고 + 라벨 하향)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    # 권고문 [근거 추적] 줄의 재료 — evidence_chain에서 코드가 뽑아 둔 요약
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)
    remaining_unknowns: List[str] = field(default_factory=list)
    tuning_hint: Optional[str] = None       # 오탐일 때 탐지팀에 보낼 룰 튜닝 제안
    # 관문이 건너뛰거나 오류로 끝냈을 때의 사유 (skipped / error)
    status_reason: Optional[str] = None
    # ↓ LLM이 채우는 칸
    summary: Optional[str] = None
    analyst_note: Optional[str] = None

    def action_ids(self) -> List[str]:
        return [a.action_id for a in self.actions]

    def has_actions(self) -> bool:
        return self.response_status in STATUSES_WITH_ACTIONS and bool(self.actions)

    def to_dict(self) -> Dict[str, Any]:
        """대시보드가 읽는 <incident_id>_response.json 본문."""
        data = asdict(self)
        data["actions"] = [a.to_dict() for a in self.actions]
        return data
