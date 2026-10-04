"""조사 에이전트(`llm/investigate/`) 모듈을 가져오는 단 하나의 통로.

역할
  대응 권고는 `llm/respond/`에 있고 조사 에이전트는 `llm/investigate/`에 있어서, 그냥은
  `from agent.llm_provider import ...`가 되지 않는다(서로 다른 최상위 폴더).
  이 파일이 `llm/investigate/`를 sys.path에 올려 `agent.*`를 쓸 수 있게 한다.

  같은 저장소의 `agent/tools/normalizer_adapter.py`가 1차 탐지(`detection_pipeline/`)를 가져올 때
  쓰는 방식과 같다 — **경로는 cwd가 아니라 이 파일의 위치 기준**이라 어디서 실행하든 같다
  (`python -m respond.cli`로 돌리든, main.py가 불러 쓰든).

  재사용하는 것은 LLM 호출에 필요한 최소한이다(설계서 8-2: 새로 만들지 않는다).
    build_llm_client(role)   <역할>_LLM_PROVIDER로 Claude/Gemini 선택
    LLMUnavailableError      재시도 뒤에도 API가 응답하지 않을 때
    load_root_env()          저장소 루트 .env 하나(키·모델 설정)

  설정 이름은 `RESPONSE_` 접두어를 쓴다(`llm/investigate/CLAUDE.md` 설정 이름 규칙).
    RESPONSE_LLM_PROVIDER, RESPONSE_ANTHROPIC_API_KEY, RESPONSE_CLAUDE_MODEL, …

누가 부르나
  respond/llm.py    build_response_llm_client()
  respond/cli.py    load_root_env()

주의
  import는 이 파일 한 곳에서만 한다(다른 파일은 여기를 거친다). 조사 쪽 폴더 구조가 바뀌면
  고칠 곳이 여기 하나다.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# llm/respond/investigate_bridge.py → llm/investigate
_INVESTIGATE_DIR = Path(__file__).resolve().parents[1] / "investigate"

# 대응 권고 LLM 설정 접두어 (RESPONSE_CLAUDE_MODEL 등)
RESPONSE = "RESPONSE"


def _ensure_path() -> None:
    """`llm/investigate/`를 sys.path에 한 번만 올린다."""
    if not _INVESTIGATE_DIR.is_dir():
        raise ImportError(
            f"조사 에이전트 폴더를 찾지 못했습니다: {_INVESTIGATE_DIR}\n"
            "대응 권고는 llm/respond/, 조사 에이전트는 llm/investigate/에 나란히 있어야 합니다."
        )
    path = str(_INVESTIGATE_DIR)
    if path not in sys.path:
        sys.path.insert(0, path)


def load_root_env() -> bool:
    """저장소 루트 .env(키·모델·로그 경로)를 읽는다. 조사·매핑과 같은 파일 하나를 쓴다."""
    _ensure_path()
    from agent.settings import load_root_env as _load  # noqa: E402

    return _load()


def build_llm_client(role: str = RESPONSE) -> Any:
    """<role>_LLM_PROVIDER 설정으로 LLM 클라이언트를 만든다(기본 Claude).

    역할 이름이 조사 쪽 `agent/settings.ROLES`에 아직 없으면 ValueError가 난다.
    그때는 llm.py가 잡아서 "LLM 없이 기본 근거 문장으로 진행"으로 넘어간다 —
    설정이 덜 됐다고 대응 권고 자체가 멈추지는 않는다(설계서 8-2 fallback).
    """
    _ensure_path()
    from agent.llm_provider import build_llm_client as _build  # noqa: E402

    return _build(role)


def llm_unavailable_error() -> type:
    """재시도 뒤에도 LLM API가 일시 오류일 때 올라오는 예외 클래스."""
    _ensure_path()
    from agent.llm_errors import LLMUnavailableError  # noqa: E402

    return LLMUnavailableError
