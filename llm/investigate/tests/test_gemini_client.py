"""GeminiClient 재시도 오프라인 테스트 — 실제 API 없이 가짜 generate_content로 확인한다.

- 일시 오류(503·429·연결 끊김)는 재시도하고, 재시도를 다 써도 계속되면 LLMUnavailableError
  (2026-09-28 EC2: 503 3회 연속 뒤 원래 예외가 그대로 올라가 main.py 전체가 멈췄다)
- 권한·요청 오류(401·400)는 재시도 없이 원래 예외 그대로
"""
from __future__ import annotations

import types

import pytest

errors = pytest.importorskip("google.genai.errors")

from agent.gemini_client import GeminiClient  # noqa: E402
from agent.llm_errors import LLMUnavailableError  # noqa: E402


def _client(monkeypatch, outcomes):
    """outcomes를 순서대로 돌려주거나(예외면 raise) 하는 가짜 generate_content를 단 클라이언트."""
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    calls = []

    def generate_content(**kwargs):
        calls.append(kwargs)
        outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    client = object.__new__(GeminiClient)
    client._client = types.SimpleNamespace(models=types.SimpleNamespace(generate_content=generate_content))
    client.model = "gemini-test"
    return client, calls


def _api_error(code):
    return errors.APIError(code, {"error": {"code": code, "message": "test", "status": "TEST"}})


@pytest.mark.parametrize("error", [_api_error(503), _api_error(429), ConnectionResetError("reset")])
def test_transient_error_after_all_retries_becomes_llm_unavailable(monkeypatch, error):
    client, calls = _client(monkeypatch, [error])
    with pytest.raises(LLMUnavailableError, match="Gemini"):
        client._generate_with_retry("prompt", config=None)
    assert len(calls) == GeminiClient.MAX_ATTEMPTS


def test_transient_error_then_success_returns_response(monkeypatch):
    client, calls = _client(monkeypatch, [_api_error(503), "ok"])
    assert client._generate_with_retry("prompt", config=None) == "ok"
    assert len(calls) == 2


@pytest.mark.parametrize("code", [400, 401, 403])
def test_config_errors_are_raised_without_retry(monkeypatch, code):
    client, calls = _client(monkeypatch, [_api_error(code)])
    with pytest.raises(errors.APIError):
        client._generate_with_retry("prompt", config=None)
    assert len(calls) == 1
