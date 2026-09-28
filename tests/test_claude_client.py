"""ClaudeClient 오프라인 테스트 — 가짜 anthropic 모듈로 실제 API 없이 확인한다.

- 조사 루프가 넘기는 인자(confidence_threshold/force_terminate/gate_rejection_reason)를 받아
  InvestigationAgent가 끝까지 도는지 (예전엔 첫 턴에 TypeError)
- 호출 설정: max_tokens 16000, sampling 인자(temperature 등) 없음, 시스템 프롬프트 캐시 표시, SDK 재시도 설정
- 보내는 인자가 설치된 실제 SDK의 messages.create()가 받는 인자인지 (가짜 클라이언트만으로는
  2026-09-28 EC2의 `temperature` TypeError를 잡지 못했다)
- 출력 한도에서 잘린 응답은 ClaudeDecisionError, 토큰 사용량 누적
- SDK 재시도 뒤 일시 오류(429·529·연결)는 LLMUnavailableError, 권한 오류는 그대로
"""
from __future__ import annotations

import json
import sys
import types
from typing import Any, Dict, List

import pytest

from agent.claude_client import ClaudeClient, ClaudeDecisionError
from agent.llm_errors import LLMUnavailableError
from agent.loop import InvestigationAgent
from agent.tools import build_default_registry


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    # 실행하는 셸에 CLAUDE_MODEL·CLAUDE_EFFORT가 있어도 기본값을 확인할 수 있게 비운다
    for name in ("CLAUDE_MODEL", "CLAUDE_EFFORT"):
        monkeypatch.delenv(name, raising=False)


class FakeStatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"status {status_code}")
        self.status_code = status_code


class FakeConnectionError(Exception):
    pass


class _FakeMessages:
    def __init__(self, replies: List[Any]) -> None:
        self.replies = replies
        self.calls: List[Dict[str, Any]] = []

    def create(self, **kwargs: Any):
        self.calls.append(kwargs)
        reply = self.replies[min(len(self.calls), len(self.replies)) - 1]
        if isinstance(reply, Exception):
            raise reply
        usage = types.SimpleNamespace(input_tokens=100, output_tokens=20,
                                      cache_creation_input_tokens=0, cache_read_input_tokens=80)
        return types.SimpleNamespace(
            content=[types.SimpleNamespace(type="text", text=reply["text"])],
            stop_reason=reply.get("stop_reason", "end_turn"), usage=usage,
        )


def _install_fake_anthropic(monkeypatch, replies):
    created = {}

    class FakeAnthropic:
        def __init__(self, api_key=None, max_retries=None):
            created["api_key"], created["max_retries"] = api_key, max_retries
            self.messages = _FakeMessages(replies)
            created["messages"] = self.messages

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(
        Anthropic=FakeAnthropic, APIStatusError=FakeStatusError, APIConnectionError=FakeConnectionError))
    return created


def _decision(**overrides):
    base = {"facts": [], "hypotheses": [], "unknowns": [], "new_evidence": [], "attack_timeline": [],
            "investigation_notes": [], "next_action": "call_tool",
            "tool_call": {"tool_name": "fetch_auth_log",
                          "args": {"host": "web-01", "start_time": "2026-09-24T00:00:00Z",
                                   "end_time": "2026-09-24T01:00:00Z"}},
            "termination_reason": None, "final_verdict": None}
    base.update(overrides)
    return {"text": json.dumps(base, ensure_ascii=False)}


SEED = {"incident_id": "INC-CLAUDE", "host": "web-01", "trigger_time": "2026-09-24T00:30:00Z",
        "trigger_description": "SSH 로그인 실패", "confidence_initial": 0.6}


def test_claude_client_runs_investigation_loop(monkeypatch):
    verdict = {"verdict": "FALSE_POSITIVE", "confidence": 0.8, "severity": "LOW", "attack_type": "x",
               "affected_systems": [], "summary": "s", "reasoning": "r"}
    terminate = _decision(next_action="terminate", tool_call=None,
                          termination_reason="no_more_evidence", final_verdict=verdict)
    # 두 번째 응답은 코드펜스로 감싼 JSON — 파서가 벗겨내는지도 함께 확인
    replies = [_decision(), {"text": "```json\n" + terminate["text"] + "\n```"}]
    created = _install_fake_anthropic(monkeypatch, replies)
    client = ClaudeClient(api_key="test-key")
    result = InvestigationAgent(client, build_default_registry()).run(SEED)

    assert result["final_verdict"]["verdict"] == "FALSE_POSITIVE"
    assert [t["tool_name"] for t in result["tools_called"]] == ["fetch_auth_log"]
    call = created["messages"].calls[0]
    assert call["max_tokens"] == 16000
    # anthropic SDK 1.x는 sampling 인자를 없앴고(TypeError), claude-sonnet-5도 받지 않는다(400)
    assert not {"temperature", "top_p", "top_k"} & set(call)
    assert "output_config" not in call  # CLAUDE_EFFORT가 없으면 API 기본값
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert created["max_retries"] == ClaudeClient.MAX_RETRIES
    assert client.usage_totals["calls"] == 2 and client.usage_totals["cache_read_input_tokens"] == 160


def test_prose_around_json_is_parsed_in_investigation_loop(monkeypatch):
    # 2026-09-28 첫 실제 실행: Claude 응답을 두 번 연속 "line 1 column 1"로 해석하지 못해 폴백 판정이 났다
    verdict = {"verdict": "INCONCLUSIVE", "confidence": 0.5, "severity": "LOW", "attack_type": "x",
               "affected_systems": [], "summary": "s", "reasoning": "r"}
    terminate = _decision(next_action="terminate", tool_call=None,
                          termination_reason="no_more_evidence", final_verdict=verdict)
    replies = [{"text": "조회 결과를 보고 다음 도구를 고릅니다.\n" + _decision()["text"]},
               {"text": "최종 판단입니다.\n```json\n" + terminate["text"] + "\n```\n이상입니다."}]
    _install_fake_anthropic(monkeypatch, replies)
    result = InvestigationAgent(ClaudeClient(api_key="k"), build_default_registry()).run(SEED)
    assert result["final_verdict"]["reasoning"] == "r"  # 폴백 판정이 아니라 LLM 판정
    assert not any("해석 실패" in n for n in result["investigation_notes"])


def test_unparsable_response_leaves_response_head_in_notes(monkeypatch):
    _install_fake_anthropic(monkeypatch, [{"text": "판단할 근거가 부족합니다. 추가 조회가 필요합니다."}])
    result = InvestigationAgent(ClaudeClient(api_key="k"), build_default_registry()).run(SEED)
    failures = [n for n in result["investigation_notes"] if "해석 실패" in n]
    assert len(failures) == 2 and all("판단할 근거가 부족합니다" in n for n in failures)
    assert result["final_verdict"]["reasoning"].startswith("[자동 폴백 판정")


def test_truncated_response_raises_decision_error(monkeypatch):
    _install_fake_anthropic(monkeypatch, [{"text": '{"facts": ["잘린', "stop_reason": "max_tokens"}])
    with pytest.raises(ClaudeDecisionError, match="출력 한도"):
        ClaudeClient(api_key="k").complete_json("sys", "user")


def test_missing_api_key_is_clear_error(monkeypatch):
    _install_fake_anthropic(monkeypatch, [])
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        ClaudeClient()


def test_model_from_env(monkeypatch):
    _install_fake_anthropic(monkeypatch, [])
    monkeypatch.setenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
    assert ClaudeClient(api_key="k").model == "claude-haiku-4-5-20251001"


def test_effort_from_env_goes_to_output_config(monkeypatch):
    created = _install_fake_anthropic(monkeypatch, [{"text": "{}"}])
    monkeypatch.setenv("CLAUDE_EFFORT", "Medium")
    ClaudeClient(api_key="k").complete_json("sys", "user")
    assert created["messages"].calls[0]["output_config"] == {"effort": "medium"}
    monkeypatch.setenv("CLAUDE_EFFORT", "fast")
    with pytest.raises(ValueError, match="CLAUDE_EFFORT"):
        ClaudeClient(api_key="k")


def test_request_arguments_are_accepted_by_installed_sdk(monkeypatch):
    # 가짜 클라이언트는 어떤 인자든 받아서, SDK가 삭제한 인자(temperature)를 보내도 통과했다.
    # 설치된 실제 anthropic의 messages.create() 시그니처와 대조한다.
    sdk = pytest.importorskip("anthropic")
    import inspect

    from anthropic.resources.messages import Messages

    accepted = set(inspect.signature(Messages.create).parameters)
    monkeypatch.setenv("CLAUDE_EFFORT", "high")
    created = _install_fake_anthropic(monkeypatch, [{"text": "{}"}])
    ClaudeClient(api_key="k").complete_json("sys", "user")
    sent = set(created["messages"].calls[0])
    assert sent <= accepted, f"anthropic {sdk.__version__}가 받지 않는 인자: {sent - accepted}"


@pytest.mark.parametrize("error", [FakeStatusError(529), FakeStatusError(429), FakeStatusError(503),
                                   FakeConnectionError("timeout")])
def test_transient_api_error_becomes_llm_unavailable(monkeypatch, error):
    _install_fake_anthropic(monkeypatch, [error])
    with pytest.raises(LLMUnavailableError, match="Claude API 일시 오류"):
        ClaudeClient(api_key="k").complete_json("sys", "user")


@pytest.mark.parametrize("status", [400, 401, 403])
def test_config_errors_are_raised_as_is(monkeypatch, status):
    # 키·권한·요청 형식 오류는 사건마다 반복돼도 해결되지 않으므로 감싸지 않고 전체 실행을 멈춘다
    _install_fake_anthropic(monkeypatch, [FakeStatusError(status)])
    with pytest.raises(FakeStatusError):
        ClaudeClient(api_key="k").complete_json("sys", "user")
