"""조사 도구 계층 — LLM이 고른 도구를 실제 로그 조회 함수로 연결·실행한다.

  registry.py            [2]·[29]~[31] ToolRegistry / ToolSpec / build_default_registry
  real/<도구이름>.py     [32]~[35]     실제 조사 도구 (fetch_web/auth/audit/network_log, fetch_event_logs, get_process_tree)
  log_source.py          [33]          로그 파일 읽기 + 정규화 + 시간창 필터 (수집과 도구가 공유)
  normalizer_adapter.py  [34]          1차 탐지팀 정규화 코드(저장소 루트 detection_pipeline/tools/)와의 연결 지점
  time_utils.py                        시간 파싱

테스트용 목업 도구는 tests/_mock_tools.py에 있다(운영 코드는 목업을 모른다).
"""

from .registry import MissingToolError, ToolRegistry, ToolSpec, ToolValidationError, build_default_registry

__all__ = [
    "MissingToolError",
    "ToolRegistry",
    "ToolSpec",
    "ToolValidationError",
    "build_default_registry",
]
