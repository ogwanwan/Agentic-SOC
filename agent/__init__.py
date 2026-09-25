"""조사 에이전트(Investigation Agent) 패키지 — main.py 등이 `from agent import ...`로 쓰는 공개 목록.

파일별 역할 (실행 순서, 번호는 docs/AGENT_FLOW.md와 각 파일 주석의 [N])
  pipeline.py           [5]~[16]  전체 파이프라인: 수집 → seed 생성 → 사건별 조사
  raw_log_ingestion.py  [7]~[9]   seed 생성용 로그 수집 (파일 끝 N건씩)
  seed_generation.py    [11]~[14] LLM triage로 seed 후보 + 우선순위 (seed_prompts.py = 그 프롬프트)
  loop.py               [17]~[42] 조사 루프(ReAct) + 종료 관문 + 원본 참조 검증
  models.py             [19]      조사 상태(AgentState)·증거 데이터 구조
  gemini_client.py      [20]~[23] LLM 호출 (claude_client.py = Claude 버전)
  prompts/              [21]      조사 프롬프트 (내용은 prompts/investigation.yaml)
  tools/                [29]~[36] 조사 도구 레지스트리와 실제 도구(tools/real/)
  provenance.py                   원본 참조(raw_ref) 전달·검증
  report.py             [41]·[45] 결과 JSON 조립·텍스트 보고서

아래 sys.path 추가는 1차 탐지 코드가 "primary-detection"(하이픈) 폴더에 있던 시절의 것이다. 지금은
폴더가 primary_detection(밑줄)이라 저장소 루트에서 실행하면 그대로 패키지로 import되고, 이 경로는
존재하지 않아 효과가 없다(남아 있어도 무해).
"""

import os as _os
import sys as _sys

_REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_PRIMARY_DETECTION_DIR = _os.path.join(_REPO_ROOT, "primary-detection")
if _PRIMARY_DETECTION_DIR not in _sys.path:
    _sys.path.insert(0, _PRIMARY_DETECTION_DIR)

from .models import (
    AgentState,
    Evidence,
    Hypothesis,
    ToolCallRecord,
    TerminationReason,
    VerdictType,
)
from .tools import ToolRegistry, ToolSpec, ToolValidationError, build_default_registry
from .claude_client import ClaudeClient, ClaudeDecisionError
from .gemini_client import GeminiClient, GeminiDecisionError
from .loop import InvestigationAgent
from .report import build_investigation_result, format_text_report
from .raw_log_ingestion import fetch_recent_raw_logs
from .seed_generation import SeedGenerator
from .pipeline import run_investigation_pipeline

__all__ = [
    "AgentState",
    "Evidence",
    "Hypothesis",
    "ToolCallRecord",
    "TerminationReason",
    "VerdictType",
    "ToolRegistry",
    "ToolSpec",
    "ToolValidationError",
    "build_default_registry",
    "ClaudeClient",
    "ClaudeDecisionError",
    "GeminiClient",
    "GeminiDecisionError",
    "InvestigationAgent",
    "build_investigation_result",
    "format_text_report",
    "fetch_recent_raw_logs",
    "SeedGenerator",
    "run_investigation_pipeline",
]