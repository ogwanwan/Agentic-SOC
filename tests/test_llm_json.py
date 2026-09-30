"""agent/llm_json.py — LLM 응답에서 조사 결정 JSON 꺼내기(Gemini·Claude 공용).

2026-09-28 첫 실제 Claude 실행에서 응답을 두 번 연속 "line 1 column 1"로 해석하지 못해 폴백 판정이 났다.
Claude는 Gemini(response_mime_type)처럼 JSON만 내보내게 강제하는 설정이 없어 앞뒤에 설명 문장이 붙을 수 있다.
"""
import pytest

from agent.llm_json import parse_llm_json

DECISION = '{"next_action": "terminate", "facts": ["a"]}'
EXPECTED = {"next_action": "terminate", "facts": ["a"]}


class DecisionError(Exception):
    pass


@pytest.mark.parametrize("text", [
    DECISION,
    "```json\n" + DECISION + "\n```",
    "조사 결과를 정리하면 다음과 같습니다.\n" + DECISION,                      # 앞에 설명 문장
    "다음은 결정입니다.\n\n```json\n" + DECISION + "\n```\n이상입니다.",      # 중간 코드 블록
    DECISION + "\n\n위 판단은 audit 조회 결과에 근거합니다.",                 # 뒤에 설명 문장
    '{"next_action": "terminate", "facts": ["a",],}',                        # trailing comma
    '{\n- next_action: "terminate",\n"facts": ["a"]\n}',                     # markdown 리스트로 깨진 키
    "설명 {\n\"next_action\": \"terminate\",\n\"facts\": [\"a\",]\n} 끝",      # 설명 + trailing comma
])
def test_decision_json_is_extracted(text):
    assert parse_llm_json(text, DecisionError) == EXPECTED


def test_braces_inside_strings_do_not_break_extraction():
    text = '결정: {"next_action": "call_tool", "note": "raw {x} }"}'
    assert parse_llm_json(text, DecisionError)["note"] == "raw {x} }"


@pytest.mark.parametrize("text", ["판단할 수 없습니다.", "[1, 2, 3]", '{"next_action": "terminate", "facts": [}'])
def test_failure_puts_response_head_on_first_line(text):
    with pytest.raises(DecisionError) as info:
        parse_llm_json(text, DecisionError, label="Claude")
    first_line = str(info.value).splitlines()[0]
    # 조사 루프는 notes에 첫 줄만 남긴다 — 원인을 확인할 수 있게 응답 앞부분이 첫 줄에 있어야 한다
    assert first_line.startswith("Claude 응답을 JSON으로 파싱하지 못했습니다")
    assert "응답 앞부분" in first_line and text.split()[0] in first_line


def test_multiline_response_head_stays_on_one_line():
    text = "첫째 줄 설명\n둘째 줄 설명\n" + "x" * 500
    with pytest.raises(DecisionError) as info:
        parse_llm_json(text, DecisionError)
    first_line = str(info.value).splitlines()[0]
    assert "첫째 줄 설명 둘째 줄 설명" in first_line and len(first_line) < 400
