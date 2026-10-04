"""권고문 렌더링 테스트 (설계서 9절) — 한글 정렬과 상태별 포맷 3종.

핵심은 한글 표시폭이다. 한글은 고정폭 글꼴에서 2칸을 차지하므로 str.ljust()로 맞추면
한글이 섞인 줄만 밀린다. 눈으로는 잘 안 보여서 테스트로 고정한다.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[2])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond.models import CATEGORY_VERIFY  # noqa: E402
from respond.render import LEGEND_LINES, WIDTH, display_width, pad, render_plan, truncate  # noqa: E402
from respond.tests._fixtures import make_action, make_plan  # noqa: E402


def _overflowing(text: str):
    return [line for line in text.splitlines() if display_width(line) > WIDTH]


# ----------------------------------------------------------------------
# 표시폭 계산
# ----------------------------------------------------------------------

class Test표시폭계산(unittest.TestCase):
    """display_width, pad, truncate 함수의 한글 폭 처리 테스트."""

    def test_표시폭은_한글을_2칸으로_센다(self):
        cases = [
            ("abc", 3),
            ("웹셸", 4),                 # 한글 2글자 = 4칸
            ("웹셸 격리", 9),            # 한글4 + 공백1 + 한글4
            ("T1505.003", 9),
            ("", 0),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(display_width(text), expected)

    def test_len과_표시폭이_다르다는_것을_고정한다(self):
        """이 차이가 ljust()를 쓰면 안 되는 이유다."""
        text = "웹셸 파일 격리"
        self.assertEqual(len(text), 8)            # 글자 수
        self.assertEqual(display_width(text), 14)  # 한글 6자×2 + 공백 2

    def test_pad는_표시폭_기준으로_채운다(self):
        self.assertEqual(display_width(pad("웹셸", 10)), 10)
        self.assertEqual(display_width(pad("abc", 10)), 10)
        # 이미 폭을 넘으면 자르지 않는다(자르는 건 truncate의 일)
        self.assertEqual(pad("웹셸 파일 격리", 4), "웹셸 파일 격리")

    def test_truncate는_표시폭_기준으로_자른다(self):
        out = truncate("웹셸 파일을 격리합니다", 10)
        self.assertLessEqual(display_width(out), 10)
        self.assertTrue(out.endswith("…"))
        # 폭 안에 들어가면 그대로
        self.assertEqual(truncate("웹셸", 10), "웹셸")


# ----------------------------------------------------------------------
# 정식 권고 (recommended)
# ----------------------------------------------------------------------

class Test정식권고(unittest.TestCase):
    """response_status=recommended 상태의 권고문 렌더링 테스트."""

    def test_정식_권고_구역이_모두_나온다(self):
        plan = make_plan(summary="웹셸이 업로드된 뒤 외부 파일을 내려받았습니다.",
                         remaining_unknowns=["www-data 평소 행동 베이스라인이 없음"])
        for action in plan.actions:
            action.reason = "확인된 근거입니다."

        text = render_plan(plan)

        self.assertIn("대응 권고   INC-7d29ffde", text)
        self.assertIn("[확정 · 권고]", text)
        self.assertIn("[공격 흐름]", text)
        self.assertIn("[요약]", text)
        self.assertIn("[즉시 조치] 2건", text)
        self.assertIn("[확인 필요] 1건", text)
        self.assertIn("[근거 추적]", text)
        self.assertIn("[남은 의문]", text)
        self.assertIn("[범례]", text)
        # 설계서 7절이 반드시 명시하라고 한 문구
        self.assertIn("자동화 후보(현재 자동 실행 안 함)", text)
        self.assertTrue(all(display_width(line) <= WIDTH for line in LEGEND_LINES))

    def test_조치의_대상과_근거와_명령이_나온다(self):
        plan = make_plan(actions=[make_action("A1", reason="업로드 직후 실행이 확인됨 (EVID-003)")])
        text = render_plan(plan)

        self.assertIn("대상  /var/www/html/wp-content/uploads/shell.php", text)
        self.assertIn("근거  업로드 직후 실행이 확인됨 (EVID-003)", text)
        self.assertIn("명령  sudo mv <대상> /var/quarantine/", text)
        self.assertIn("[L2 · 가역 · LOW]", text)

    def test_LLM_문장이_없으면_카탈로그_기본_문장을_쓴다(self):
        plan = make_plan(actions=[make_action("A1", reason=None)])
        text = render_plan(plan)

        self.assertIn("근거  업로드 직후 실행이 확인된 파일입니다.", text)

    def test_대상이_없는_조치는_지어내지_않고_없음으로_표시한다(self):
        plan = make_plan(actions=[
            make_action("A1", target=None, target_source=None, technique_id=None,
                        command_hint=None, category="immediate"),
        ])
        text = render_plan(plan)

        self.assertIn("(없음 — 담당자가 범위를 정해 확인)", text)

    def test_하향된_라벨은_이전_값까지_보여_준다(self):
        plan = make_plan(actions=[make_action("A1", autonomy="L1", autonomy_downgraded_from="L2")])
        text = render_plan(plan)

        self.assertIn("[L1←L2 · 가역 · LOW]", text)

    def test_매핑이_partial이면_일부만_확인됨을_표기한다(self):
        """설계서 7절 — partial은 L2를 유지하되 반드시 표기한다."""
        plan = make_plan(mapping_status="partial")
        text = render_plan(plan)

        self.assertIn("partial (일부만 확인됨)", text)

    def test_매핑_경고는_머리말에_경고로_노출된다(self):
        plan = make_plan(warnings=[{"code": "FALLBACK_VERDICT", "detail": "누적 confidence로 판정"}])
        text = render_plan(plan)

        self.assertIn("[경고]", text)
        self.assertIn("FALLBACK_VERDICT", text)
        self.assertIn("그대로 신뢰하지 마십시오", text)

    def test_조치가_하나도_없으면_지어내지_않고_사유를_적는다(self):
        plan = make_plan(actions=[])
        text = render_plan(plan)

        self.assertIn("생성된 조치가 없습니다", text)
        self.assertIn("증거를 보존하고", text)


# ----------------------------------------------------------------------
# 오탐 / 보류 / 건너뜀 (설계서 9-3)
# ----------------------------------------------------------------------

class Test오탐보류건너뜀(unittest.TestCase):
    """response_status가 not_applicable/deferred/skipped/error일 때 렌더링 테스트."""

    def test_오탐은_조치_없이_튜닝_제안만_나온다(self):
        plan = make_plan(
            response_status="not_applicable",
            verdict="FALSE_POSITIVE",
            severity="LOW",
            actions=[],
            summary="정상 cron 요청으로 확인되었습니다.",
            tuning_hint="apache_login_bruteforce 룰 임계값 재검토 권장",
        )
        text = render_plan(plan)

        self.assertIn("[오탐 · 조치 없음]", text)
        self.assertIn("정상 cron 요청으로 확인되었습니다.", text)
        self.assertIn("[탐지팀 참고]", text)
        self.assertIn("apache_login_bruteforce", text)
        # 조치 구역과 범례는 나오지 않는다
        self.assertNotIn("[즉시 조치]", text)
        self.assertNotIn("[범례]", text)

    def test_보류는_확인_필요_목록을_낸다(self):
        plan = make_plan(
            response_status="deferred",
            verdict="INCONCLUSIVE",
            actions=[],
            remaining_unknowns=["행동 베이스라인 확보", "해당 시간대 audit 로그 수집 여부"],
        )
        text = render_plan(plan)

        self.assertIn("[보류 · 확인 필요]", text)
        self.assertIn("[확인 필요]", text)
        self.assertIn("행동 베이스라인 확보", text)
        self.assertIn("해당 시간대 audit 로그 수집 여부", text)

    def test_보류인데_남은_의문이_없으면_안내_문구가_나온다(self):
        plan = make_plan(response_status="deferred", verdict="INCONCLUSIVE", actions=[])
        text = render_plan(plan)

        self.assertIn("담당자가 직접 확인하십시오", text)

    def test_조사_미완료는_사유만_남기고_권고를_만들지_않는다(self):
        plan = make_plan(
            response_status="skipped",
            actions=[],
            status_reason="LLM API 일시 오류로 조사가 끝나지 않았습니다.",
        )
        text = render_plan(plan)

        self.assertIn("[조사 미완료]", text)
        self.assertIn("LLM API 일시 오류", text)
        self.assertIn("조사 큐가 다시 조사한 뒤", text)
        self.assertNotIn("[즉시 조치]", text)

    def test_구조_오류도_사유만_남긴다(self):
        plan = make_plan(response_status="error", actions=[],
                         status_reason="attack_mapping 키가 없습니다.")
        text = render_plan(plan)

        self.assertIn("[처리 오류]", text)
        self.assertIn("attack_mapping 키가 없습니다.", text)


# ----------------------------------------------------------------------
# 줄 폭 — 한글이 섞여도 틀을 넘지 않는다
# ----------------------------------------------------------------------

class Test줄폭제한(unittest.TestCase):
    """모든 상태에서 줄이 WIDTH를 넘지 않는지 확인한다."""

    def test_모든_상태에서_줄이_틀을_넘지_않는다(self):
        cases = [
            ("recommended", {}),
            ("not_applicable", {"actions": [], "tuning_hint": "룰 임계값 재검토 권장"}),
            ("deferred", {"actions": [], "remaining_unknowns": ["행동 베이스라인 확보"]}),
            ("skipped", {"actions": [], "status_reason": "조사 미완료"}),
        ]
        for status, kwargs in cases:
            with self.subTest(status=status):
                plan = make_plan(response_status=status,
                                 summary="웹셸이 업로드된 뒤 외부 파일을 내려받았습니다.",
                                 **kwargs)
                text = render_plan(plan)
                self.assertEqual(_overflowing(text), [])

    def test_긴_한글_문장은_줄바꿈되고_틀을_넘지_않는다(self):
        long_reason = "업로드 직후 같은 파일이 실행된 것이 확인되었고 " * 5
        plan = make_plan(actions=[make_action("A1", reason=long_reason)])

        text = render_plan(plan)

        self.assertEqual(_overflowing(text), [])
        self.assertIn("근거  ", text)

    def test_긴_공백없는_값도_틀을_넘지_않는다(self):
        plan = make_plan(actions=[make_action("A1", target="/var/www/" + "a" * 200 + "/shell.php")])
        text = render_plan(plan)

        self.assertEqual(_overflowing(text), [])

    def test_머리말_구분선은_정확히_틀_폭이다(self):
        text = render_plan(make_plan())
        lines = text.splitlines()

        self.assertEqual(display_width(lines[0]), WIDTH)
        self.assertEqual(set(lines[0]), {"="})


if __name__ == "__main__":
    unittest.main()
