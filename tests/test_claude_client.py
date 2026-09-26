"""ClaudeClient 오프라인 테스트 — 가짜 anthropic 모듈로 실제 API 없이 확인한다.

- 조사 루프가 넘기는 인자(confidence_threshold/force_terminate/gate_rejection_reason)를 받아
  InvestigationAgent가 끝까지 도는지 (예전엔 첫 턴에 TypeError)
- 호출 설정: max_tokens 8192, temperature 0, 시스템 프롬프트 캐시 표시, SDK 재시도 설정
- 출력 한도에서 잘린 응답은 ClaudeDecisionError, 토큰 사용량 누적
"""
from __future__ import annotations

import json
import sys
import types
from typing import Any, Dict, List

import pytest

from agent.claude_client import ClaudeClient, ClaudeDecisionError
from agent.loop import InvestigationAgent
from agent.tools import build_default_registry


class _FakeMessages:
    def __init__(self, replies: List[Dict[str, Any]]) -> None:
        self.replies = replies
        self.calls: List[Dict[str, Any]] = []

    def create(self, **kwargs: Any):
        self.calls.append(kwargs)
        reply = self.replies[min(len(self.calls), len(self.replies)) - 1]
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

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=FakeAnthropic))
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
    assert call["max_tokens"] == 8192 and call["temperature"] == 0.0
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert created["max_retries"] == ClaudeClient.MAX_RETRIES
    assert client.usage_totals["calls"] == 2 and client.usage_totals["cache_read_input_tokens"] == 160


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
