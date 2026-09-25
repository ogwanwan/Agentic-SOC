"""조사 상태·증거 데이터 구조 — AgentState, Evidence, Hypothesis, ToolCallRecord, 판정/종료 사유 상수.

역할
  한 사건을 조사하는 동안 쌓이는 facts / 가설 / unknowns / 증거 / 도구 호출 이력 / 신뢰도 변화를
  AgentState 하나에 담는다. 조사 루프는 매 사이클 이 State를 프롬프트로 LLM에게 보여 주고,
  LLM 판단 결과로 갱신한다.

누가 부르나
  [18] agent/loop.py InvestigationAgent.run()   → AgentState(...) 생성
  agent/loop.py _apply_decision()/_execute_tool_call()  → add_evidence, update_confidence, mark_called
  agent/prompts/__init__.py build_user_prompt() → State를 LLM용 JSON으로 변환
  agent/report.py build_investigation_result()  → State를 최종 JSON으로 변환

무엇을 부르나
  표준 라이브러리만 쓴다.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class VerdictType(str, Enum):
    THREAT_CONFIRMED = "THREAT_CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class TerminationReason(str, Enum):
    CONFIDENCE_SUFFICIENT = "confidence_sufficient"
    NO_MORE_EVIDENCE = "no_more_evidence"
    MAX_CALL_REACHED = "max_call_reached"


_evidence_counter = itertools.count(1)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Evidence:
    """조사 중 확보한 증거 하나. 지지/반박 증거 모두 이 클래스로 표현한다."""

    evidence_id: str
    sequence: int
    time: Optional[str]
    layer: str
    event_type: str
    description: str
    source_log: str
    supporting_hypothesis: List[str] = field(default_factory=list)
    contradicting_hypothesis: List[str] = field(default_factory=list)
    confidence_contribution: float = 0.0
    raw_refs: List[str] = field(default_factory=list)

    @classmethod
    def new(cls, sequence: int, **kwargs: Any) -> "Evidence":
        eid = f"EVID-{next(_evidence_counter):03d}"
        return cls(evidence_id=eid, sequence=sequence, **kwargs)


@dataclass
class Hypothesis:
    hyp_id: str
    title: str
    description: str
    confidence: float
    status: str = "active"  # active | confirmed | rejected


@dataclass
class ToolCallRecord:
    sequence: int
    tool_name: str
    input: Dict[str, Any]
    result_count: int
    result_summary: str
    success: bool = True
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now_iso)
    raw_refs: List[str] = field(default_factory=list)
    queried_layers: List[str] = field(default_factory=list)


@dataclass
class ConfidenceStep:
    stage: str
    confidence: float
    reason: str

# [19] ← agent/loop.py [18]에서 사건마다 하나 생성된다
@dataclass
class AgentState:
    """조사 진행 상태 전체를 담는 컨테이너.

    facts / hypotheses / unknowns 는 문서의 Stage 1 산출물에 대응하고,
    evidence / tool_calls / confidence_progression 은 Stage 3 및 반복 결과를 누적한다.
    """

    incident_id: str
    seed: Dict[str, Any]

    facts: List[str] = field(default_factory=list)
    hypotheses: Dict[str, Hypothesis] = field(default_factory=dict)
    unknowns: List[str] = field(default_factory=list)

    evidence: List[Evidence] = field(default_factory=list)
    contradicting_evidence: List[Evidence] = field(default_factory=list)

    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    called_signatures: Set[Tuple[str, Tuple[Tuple[str, Any], ...]]] = field(default_factory=set)

    confidence_progression: List[ConfidenceStep] = field(default_factory=list)
    current_confidence: float = 0.0

    investigated_layers: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    attack_timeline: List[Dict[str, Any]] = field(default_factory=list)

    # 직전 tool call 결과 중 아직 LLM이 해석(증거화)하지 않은 원본 결과.
    # 매 reason() 호출 뒤 loop.py에서 비운다.
    pending_observations: List[Dict[str, Any]] = field(default_factory=list)
    raw_refs: List[str] = field(default_factory=list)
    provenance_issues: List[Dict[str, Any]] = field(default_factory=list)
    raw_ref_groups: Dict[str, List[str]] = field(default_factory=dict)
    raw_ref_locations: Dict[str, List[str]] = field(default_factory=dict)
    # 도구 결과에서 관측된 seed src_ip의 로그인 성공(ssh_accepted) 레코드
    # ({raw_ref, pid, user, timestamp}). 있으면 종료 관문이 후속 행위(audit) 확인을 요구하고,
    # 거부 사유에 ppid=<pid>를 그대로 적어준다 (loop.py strict_termination).
    login_successes: List[Dict[str, Any]] = field(default_factory=list)
    # 시스템이 LLM 대신 실행한 도구 호출(network 사전 조회)의 sequence.
    # 종료 관문의 "서로 다른 도구 2종류" 계산에서는 빼서, LLM이 스스로 2개 계층을 고르게 한다.
    system_call_sequences: List[int] = field(default_factory=list)
    # 도구가 계산한 판정 원칙 기준 중 seed src_ip에 대해 "위협 기준 충족"인 것
    # (예: 원칙 9 인증 대입 POST 10회 이상). 충족인데 FALSE_POSITIVE로 끝내려 하면 관문이 거부한다.
    # 원칙 7(성공 없는 SSH 실패)은 충족·미충족 결과를 모두 담는다(미충족인데 THREAT_CONFIRMED도 거부).
    rule_floors: List[Dict[str, Any]] = field(default_factory=list)
    # 로그 조회 도구가 돌려준 "필터 전 구간 전체 건수"(window_total). 모두 0이면 그 시간대
    # 로그 자체가 없는 것(수집 누락·교체)이라, 관문이 INCONCLUSIVE 외 판정을 거부한다.
    window_totals: List[int] = field(default_factory=list)

    @staticmethod
    def _to_hashable(value: Any) -> Any:
        """dict/list처럼 해싱 불가능한 인자 값도 시그니처에 넣을 수 있도록 변환.

        LLM이 tool 인자로 리스트(예: status_code=[200, 404])나 딕셔너리를 넘기면
        tuple(sorted(args.items()))에서 TypeError: unhashable type이 났었다.
        """
        if isinstance(value, dict):
            return tuple(sorted((k, AgentState._to_hashable(v)) for k, v in value.items()))
        if isinstance(value, (list, tuple, set)):
            return tuple(AgentState._to_hashable(v) for v in value)
        return value
    # ------------------------------------------------------------------
    # 중복 조사 방지
    # ------------------------------------------------------------------
    # 같은 (도구, 인자) 조합이면 같은 서명. 인자에 리스트·딕셔너리가 와도 _to_hashable로 바꿔 해싱한다.
    @staticmethod
    def _signature(tool_name: str, args: Dict[str, Any]) -> Tuple[str, Tuple[Tuple[str, Any], ...]]:
        return (
            tool_name,
            tuple(sorted((k, AgentState._to_hashable(v)) for k, v in args.items())),
        )

    def already_called(self, tool_name: str, args: Dict[str, Any]) -> bool:
        return self._signature(tool_name, args) in self.called_signatures

    def mark_called(self, tool_name: str, args: Dict[str, Any]) -> None:
        self.called_signatures.add(self._signature(tool_name, args))

    # ------------------------------------------------------------------
    # 증거 / 신뢰도 관리
    # ------------------------------------------------------------------
    def add_evidence(self, ev: Evidence, contradicting: bool = False) -> None:
        if contradicting:
            self.contradicting_evidence.append(ev)
        else:
            self.evidence.append(ev)
        self.investigated_layers.add(ev.layer)

    def record_confidence(self, stage: str, reason: str) -> None:
        self.confidence_progression.append(
            ConfidenceStep(stage=stage, confidence=round(self.current_confidence, 3), reason=reason)
        )

    def update_confidence(self, delta: float, stage: str, reason: str) -> None:
        # round: 0.6+0.25 같은 덧셈이 0.8499999…가 되어 임계값 0.85 비교에서 "미달"로 거부되던
        # 부동소수점 오차를 없앤다 (로컬 xmlrpc 재현에서 3회 연속 거부).
        self.current_confidence = round(max(0.0, min(1.0, self.current_confidence + delta)), 6)
        self.record_confidence(stage, reason)
