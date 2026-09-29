"""조사 도구 계층 — LLM이 고른 도구를 실제 로그 조회 함수로 연결·실행한다.

  registry.py            [2]·[29]~[31] ToolRegistry / ToolSpec / build_default_registry
  real/<도구이름>.py     [32]~[35]     실제 조사 도구 (fetch_web/auth/audit/network_log, fetch_event_logs, get_process_tree)
  log_source.py          [33]          로그 파일 읽기 + 정규화 + 시간창 필터 (수집과 도구가 공유)
  normalizer_adapter.py  [34]          1차 탐지팀 정규화 코드(primary_detection/normalizer/)와의 연결 지점
  time_utils.py                        시간 파싱
  mock_tools.py                        실제 구현이 없을 때 쓰는 목업 (테스트·데모용)
"""

from .registry import ToolRegistry, ToolSpec, ToolValidationError, build_default_registry
from .mock_tools import MOCK_HANDLERS

__all__ = [
    "ToolRegistry",
    "ToolSpec",
    "ToolValidationError",
    "build_default_registry",
    "MOCK_HANDLERS",
]
