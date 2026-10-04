"""LLM 응답 검증 테스트 (설계서 8-3) — 담당 B에서 가장 중요한 테스트.

LLM이 조치를 추가·삭제하거나, 대상을 바꾸거나, 없는 증거를 인용하거나, 매핑되지 않은 기법을
들고 오면 코드가 걸러내는지 확인한다. 실제 LLM은 부르지 않는다(FakeLLM).

검증 규칙 (설계서 8-3)
  1. 조치의 target이 추출된 대상 집합에 있는가       → 해당 조치 폐기
  2. LLM이 돌려준 action_id 집합 == 입력 집합인가    → 응답 전체 거절(fallback)
  3. 모든 조치에 reason이 있는가                     → 그 조치만 default_reason
  4. reason이 인용한 EVID-*가 evidence_chain에 있는가 → 그 인용만 제거
  5. technique_id가 attack_mapping.techniques[]에 있는가 → 해당 조치 폐기
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[2])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond.llm import run_llm_stage, strip_unknown_citations  # noqa: E402
from respond.models import CATEGORY_VERIFY  # noqa: E402
from respond.tests._fixtures import (  # noqa: E402
    ALLOWED_TARGETS,
    ALLOWED_TECHNIQUE_IDS,
    EVIDENCE_CHAIN,
    FakeLLM,
    make_action,
    make_plan,
)


def _run(plan, payload=None, *, error=None, **kwargs):
    """공통 실행 — 기본 허용 목록으로 LLM 단계를 돌린다."""
    client = FakeLLM(payload, error=error)
    report = run_llm_stage(
        plan,
        evidence_chain=EVIDENCE_CHAIN,
        allowed_targets=kwargs.pop("allowed_targets", ALLOWED_TARGETS),
        allowed_technique_ids=kwargs.pop("allowed_technique_ids", ALLOWED_TECHNIQUE_IDS),
        llm_client=client,
    )
    return report, client


def _payload_for(plan, reason="확인된 근거입니다."):
    """plan의 조치 전부에 reason을 채운 정상 응답."""
    return {
        "summary": "웹셸이 업로드된 뒤 외부에서 파일을 내려받았습니다.",
        "analyst_note": None,
        "actions": [{"action_id": a.action_id, "reason": reason} for a in plan.actions],
    }


# ----------------------------------------------------------------------
# 정상 경로
# ----------------------------------------------------------------------

class Test정상경로(unittest.TestCase):
    """정상 LLM 응답이 그대로 반영되는지 확인한다."""

    def test_정상_응답은_그대로_반영된다(self):
        plan = make_plan()
        report, client = _run(plan, _payload_for(plan))

        self.assertTrue(report.llm_called)
        self.assertFalse(report.used_fallback)
        self.assertEqual(len(client.calls), 1)
        self.assertTrue(all(a.reason == "확인된 근거입니다." for a in plan.actions))
        self.assertTrue(plan.summary.startswith("웹셸이 업로드된"))

    def test_프롬프트에_target과_라벨은_들어가지_않는다(self):
        """LLM에게 대상·자율성 라벨을 보여 주지 않는다 — 받지 못한 값은 되돌려줄 수도 없다."""
        plan = make_plan()
        _, client = _run(plan, _payload_for(plan))

        user_prompt = client.calls[0]["user"]
        self.assertNotIn("/var/www/html/wp-content/uploads/shell.php", user_prompt)
        self.assertNotIn("203.0.113.45", user_prompt)
        self.assertNotIn("command_hint", user_prompt)
        self.assertNotIn("autonomy", user_prompt)
        # 대신 돌려줘야 할 action_id는 분명히 알려 준다
        self.assertIn("A1", user_prompt)
        self.assertIn("A2", user_prompt)
        self.assertIn("A3", user_prompt)


# ----------------------------------------------------------------------
# 규칙 2 — action_id 집합 불일치는 응답 전체 거절
# ----------------------------------------------------------------------

class Test규칙2_action_id_집합(unittest.TestCase):
    """LLM이 action_id를 추가·삭제·중복하면 응답 전체를 거절한다."""

    def test_규칙2_조치를_추가하면_응답_전체_거절(self):
        plan = make_plan()
        payload = _payload_for(plan)
        payload["actions"].append({"action_id": "A99", "reason": "LLM이 만들어낸 조치"})

        report, _ = _run(plan, payload)

        self.assertTrue(report.used_fallback)
        self.assertIn("A99", report.fallback_reason)
        # 조치 목록 자체는 코드가 정한 그대로 남는다 — LLM이 늘리지 못한다
        self.assertEqual(plan.action_ids(), ["A1", "A2", "A3"])
        # 문장은 전부 기본값으로 — LLM이 쓴 문장은 하나도 남지 않는다
        self.assertTrue(all(a.reason is None for a in plan.actions))
        self.assertIsNone(plan.summary)

    def test_규칙2_조치를_빼먹으면_응답_전체_거절(self):
        plan = make_plan()
        payload = _payload_for(plan)
        payload["actions"] = [item for item in payload["actions"] if item["action_id"] != "A2"]

        report, _ = _run(plan, payload)

        self.assertTrue(report.used_fallback)
        self.assertIn("A2", report.fallback_reason)
        self.assertEqual(plan.action_ids(), ["A1", "A2", "A3"])

    def test_규칙2_같은_id를_두_번_돌려주면_거절(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = {"summary": "요약", "actions": [
            {"action_id": "A1", "reason": "첫 번째"},
            {"action_id": "A1", "reason": "두 번째"},
        ]}

        report, _ = _run(plan, payload)

        self.assertTrue(report.used_fallback)
        self.assertIn("중복", report.fallback_reason)

    def test_규칙2_응답_모양이_깨지면_거절(self):
        bad_payloads = [
            None,
            [],
            {"summary": "요약"},                      # actions 없음
            {"actions": "A1"},                        # actions가 배열이 아님
            {"actions": [{"reason": "id 없음"}]},      # action_id 없음
            {"actions": ["A1"]},                      # 원소가 객체가 아님
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                plan = make_plan(actions=[make_action("A1")])
                report, _ = _run(plan, payload)

                self.assertTrue(report.used_fallback)
                self.assertTrue(report.fallback_reason)


# ----------------------------------------------------------------------
# 규칙 3 — reason 누락은 그 조치만 기본 문장
# ----------------------------------------------------------------------

class Test규칙3_reason_누락(unittest.TestCase):
    """reason이 없거나 빈 문자열이면 그 조치만 default_reason으로 채운다."""

    def test_규칙3_reason이_비면_그_조치만_기본_문장(self):
        plan = make_plan()
        payload = _payload_for(plan)
        payload["actions"][1]["reason"] = "   "      # 공백만

        report, _ = _run(plan, payload)

        self.assertFalse(report.used_fallback)          # 전체 거절은 아니다
        self.assertIn("A2", report.reasons_defaulted)
        self.assertIsNone(plan.actions[1].reason)
        # render가 쓰는 값은 카탈로그의 기본 문장
        self.assertEqual(plan.actions[1].effective_reason(), "같은 IP에서 반복 요청이 관측되었습니다.")
        # 나머지 조치는 LLM 문장 그대로
        self.assertEqual(plan.actions[0].reason, "확인된 근거입니다.")

    def test_규칙3_reason이_문자열이_아니면_기본_문장(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = {"actions": [{"action_id": "A1", "reason": {"text": "객체"}}]}

        report, _ = _run(plan, payload)

        self.assertFalse(report.used_fallback)
        self.assertEqual(report.reasons_defaulted, ["A1"])


# ----------------------------------------------------------------------
# 규칙 4 — 없는 증거 인용은 제거(문장은 살린다)
# ----------------------------------------------------------------------

class Test규칙4_증거인용(unittest.TestCase):
    """reason에서 없는 EVID-* 인용만 제거하고 문장은 살린다."""

    def test_규칙4_없는_증거_인용만_지운다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = {"actions": [
            {"action_id": "A1", "reason": "업로드 직후 실행이 확인됨 (EVID-003, EVID-999)"}
        ]}

        report, _ = _run(plan, payload)

        self.assertFalse(report.used_fallback)
        self.assertNotIn("EVID-999", plan.actions[0].reason)
        self.assertIn("EVID-003", plan.actions[0].reason)          # 있는 인용은 남는다
        self.assertIn("업로드 직후 실행이 확인됨", plan.actions[0].reason)
        self.assertEqual(report.stripped_citations,
                         [{"action_id": "A1", "evidence_id": "EVID-999"}])

    def test_규칙4_인용만_지우면_빈_괄호가_남지_않는다(self):
        text, removed = strip_unknown_citations("업로드가 확인됨 (EVID-999)", {"EVID-003"})

        self.assertEqual(removed, ["EVID-999"])
        self.assertNotIn("(", text)
        self.assertNotIn(")", text)
        self.assertEqual(text, "업로드가 확인됨")

    def test_규칙4_summary의_없는_인용도_지운다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = {
            "summary": "웹셸이 업로드되었습니다 (EVID-404).",
            "actions": [{"action_id": "A1", "reason": "확인됨"}],
        }

        _run(plan, payload)

        self.assertNotIn("EVID-404", plan.summary)

    def test_규칙4_인용만_있던_reason이_비면_기본_문장으로(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = {"actions": [{"action_id": "A1", "reason": "(EVID-999)"}]}

        report, _ = _run(plan, payload)

        self.assertIsNone(plan.actions[0].reason)
        self.assertIn("A1", report.reasons_defaulted)


# ----------------------------------------------------------------------
# 규칙 1·5 — 대상·기법 검증은 LLM을 부르기 전에 (조치 자체를 폐기)
# ----------------------------------------------------------------------

class Test규칙1_5_대상기법검증(unittest.TestCase):
    """LLM 호출 전에 조치의 target과 technique_id를 검증하여 폐기한다."""

    def test_규칙1_추출되지_않은_대상의_조치는_폐기된다(self):
        """LLM이 끼어들기 전에, 코드가 만든 조치부터 대상 출처로 검증한다."""
        plan = make_plan(actions=[
            make_action("A1"),                                   # 정상 대상
            make_action("A2", target="/etc/shadow"),             # 추출된 적 없는 대상
        ])

        report, client = _run(plan, {"actions": [{"action_id": "A1", "reason": "확인됨"}]})

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions[0]["action_id"], "A2")
        self.assertEqual(report.dropped_actions[0]["rule"], "target_not_in_sources")
        # 폐기 뒤 남은 조치만 LLM에게 보낸다 — 응답은 A1만 돌려주면 통과
        self.assertFalse(report.used_fallback)
        self.assertNotIn("A2", client.calls[0]["user"])

    def test_규칙1_대상이_없는_점검_항목은_폐기하지_않는다(self):
        """target=None은 "무엇을 확인하라"는 항목이다 — 지울 대상 값이 없으므로 통과시킨다."""
        plan = make_plan(actions=[
            make_action("A1", target=None, target_source=None, technique_id=None,
                        category=CATEGORY_VERIFY),
        ])

        report, _ = _run(plan, {"actions": [{"action_id": "A1", "reason": "확인 필요"}]})

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions, [])

    def test_규칙5_매핑되지_않은_기법의_조치는_폐기된다(self):
        plan = make_plan(actions=[
            make_action("A1"),
            make_action("A2", technique_id="T1486", technique_name="Data Encrypted for Impact"),
        ])

        report, _ = _run(plan, {"actions": [{"action_id": "A1", "reason": "확인됨"}]})

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions[0]["rule"], "technique_not_mapped")
        self.assertIn("T1486", report.dropped_actions[0]["detail"])

    def test_규칙5_상위기법_조치도_허용된다(self):
        """T1505.003으로 매핑됐으면 상위 T1505 조치도 쓸 수 있다."""
        plan = make_plan(actions=[make_action("A1", technique_id="T1505")])

        report, _ = _run(plan, {"actions": [{"action_id": "A1", "reason": "확인됨"}]})

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions, [])

    def test_허용목록을_못_받으면_검증을_건너뛰되_기록을_남긴다(self):
        plan = make_plan(actions=[make_action("A1", target="/etc/shadow")])

        report, _ = _run(plan, {"actions": [{"action_id": "A1", "reason": "확인됨"}]},
                         allowed_targets=None, allowed_technique_ids=None)

        self.assertEqual(plan.action_ids(), ["A1"])            # 지우지 않는다
        self.assertTrue(any("대상 검증 건너뜀" in note for note in report.notes))
        self.assertTrue(any("기법 검증 건너뜀" in note for note in report.notes))


# ----------------------------------------------------------------------
# LLM 장애 — 파이프라인을 멈추지 않는다 (설계서 8-2)
# ----------------------------------------------------------------------

class TestLLM장애(unittest.TestCase):
    """LLM이 예외를 던져도 권고는 기본 문장으로 나간다."""

    def test_LLM이_예외를_던져도_권고는_기본_문장으로_나간다(self):
        plan = make_plan()
        report, _ = _run(plan, error=RuntimeError("API 503"))

        self.assertTrue(report.used_fallback)
        self.assertIn("API 503", report.fallback_reason)
        self.assertEqual(plan.action_ids(), ["A1", "A2", "A3"])           # 조치는 그대로
        self.assertTrue(plan.actions[0].effective_reason())                 # 기본 문장이 있다

    def test_조치가_없는_상태는_LLM을_부르지_않는다(self):
        """오탐·보류·건너뜀은 고정 문구로 나간다 — 호출 비용과 환각 여지를 둘 다 없앤다."""
        for status in ("not_applicable", "deferred", "skipped", "error"):
            with self.subTest(status=status):
                plan = make_plan(response_status=status, actions=[])
                client = FakeLLM({"actions": []})
                report = run_llm_stage(plan, evidence_chain=EVIDENCE_CHAIN, llm_client=client)

                self.assertEqual(client.calls, [], f"{status}에서 LLM을 불렀다")
                self.assertFalse(report.llm_called)
                self.assertIn(status, report.notes[-1] if report.notes else "")

    def test_조치가_전부_폐기되면_LLM을_부르지_않는다(self):
        plan = make_plan(actions=[make_action("A1", target="/etc/shadow")])
        client = FakeLLM({"actions": []})

        report = run_llm_stage(
            plan,
            evidence_chain=EVIDENCE_CHAIN,
            allowed_targets=ALLOWED_TARGETS,
            allowed_technique_ids=ALLOWED_TECHNIQUE_IDS,
            llm_client=client,
        )

        self.assertEqual(plan.actions, [])
        self.assertEqual(client.calls, [])
        self.assertFalse(report.llm_called)

    def test_너무_긴_reason은_잘린다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = {"actions": [{"action_id": "A1", "reason": "가" * 500}]}

        _run(plan, payload)

        self.assertLessEqual(len(plan.actions[0].reason), 201)        # 200자 + 생략 기호
        self.assertTrue(plan.actions[0].reason.endswith("…"))


if __name__ == "__main__":
    unittest.main()
