"""LLM 응답 검증 테스트 (설계서 8-3) — 담당 B에서 가장 중요한 테스트.

2026-10-06 확정으로 LLM이 조치마다 일곱 칸(reason·command·rollback·side_effects·
verification·autonomy_reason·priority)을 직접 쓴다. 그 문장이 **사람이 복사해 실행하는
명령**이 되므로, 검증이 뚫리면 그대로 운영 사고가 된다. 실제 LLM은 부르지 않는다(FakeLLM).

검증 규칙
  1. 조치의 target이 추출된 대상 집합에 있는가       → 해당 조치 폐기
  2. LLM이 돌려준 action_id 집합 == 입력 집합인가    → 응답 전체 거절(fallback)
  3. 모든 조치의 모든 칸이 채워졌는가                 → 빈 칸만 카탈로그 문장
  4. 인용한 EVID-*가 evidence_chain에 있는가          → 그 인용만 제거
  5. technique_id가 attack_mapping.techniques[]에 있는가 → 조치 폐기 / 인용 제거
  6. reason이 그 기법의 증거를 인용했는가              → 그 칸만 카탈로그 문장
  7. 입력에 없는 IP·경로를 적지 않았는가              → 그 칸만 카탈로그 문장
  8. 명령·원복에 파괴적 명령이 없는가                  → 그 칸만 카탈로그 문장
  9. 비가역 조치의 원복이 "되돌릴 수 없음"을 말하는가  → 그 칸만 카탈로그 문장
 10. 등급 근거가 코드가 정한 등급을 말하는가           → 그 칸만 카탈로그 문장
 11. priority가 1~3 정수인가                           → 카탈로그 값 유지
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[2])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond.llm import (  # noqa: E402
    destructive_hits,
    run_llm_stage,
    strip_unknown_citations,
    strip_unknown_techniques,
    unknown_tokens,
)
from respond.models import CATEGORY_VERIFY  # noqa: E402
from respond.tests._fixtures import (  # noqa: E402
    ALLOWED_TARGETS,
    ALLOWED_TECHNIQUE_IDS,
    EVIDENCE_CHAIN,
    SRC_IP,
    WEBSHELL_PATH,
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


def _action_payload(action, **overrides):
    """조치 하나에 일곱 칸을 모두 채운 정상 응답 조각.

    reason은 그 조치의 evidence_ids를 인용한다(규칙 6). 명령·원복은 그 조치의 target만 쓴다
    (규칙 7). 등급 근거는 코드가 정한 등급을 그대로 말한다(규칙 10).
    """
    citation = f" ({action.evidence_ids[0]})" if action.evidence_ids else ""
    target = action.target or ""
    item = {
        "action_id": action.action_id,
        "reason": f"업로드 직후 실행이 확인되었습니다{citation}",
        "command": f"sudo mv {target} /var/quarantine/" if target else "웹루트의 최근 생성 파일을 확인합니다",
        "rollback": (f"sudo mv /var/quarantine/shell.php {target}" if action.reversible
                      else "되돌릴 수 없음 — 새 자격증명을 재발급해야 합니다"),
        "side_effects": "해당 파일을 쓰는 정상 기능이 있으면 404가 발생합니다. 파일 1개로 범위가 한정됩니다",
        "verification": "대상이 격리 폴더로 옮겨졌고 해당 요청이 404인지 확인합니다",
        "autonomy_reason": f"가역적이고 범위가 좁아 {action.autonomy} 등급입니다",
        "priority": 1,
    }
    item.update(overrides)
    return item


def _payload_for(plan, **overrides):
    """plan의 조치 전부에 일곱 칸을 채운 정상 응답."""
    return {
        "summary": "웹셸이 업로드된 뒤 외부에서 파일을 내려받았습니다.",
        "analyst_note": None,
        "actions": [_action_payload(a, **overrides) for a in plan.actions],
    }


# ----------------------------------------------------------------------
# 정상 경로
# ----------------------------------------------------------------------

class Test정상경로(unittest.TestCase):
    """정상 LLM 응답이 일곱 칸 모두 반영되는지 확인한다."""

    def test_일곱칸이_모두_반영된다(self):
        plan = make_plan(actions=[make_action("A1")])
        report, client = _run(plan, _payload_for(plan))

        self.assertTrue(report.llm_called)
        self.assertFalse(report.used_fallback)
        self.assertEqual(len(client.calls), 1)

        action = plan.actions[0]
        self.assertIn("업로드 직후 실행이 확인되었습니다", action.reason)
        self.assertIn("/var/quarantine/", action.command_hint)
        self.assertIn("sudo mv /var/quarantine/", action.rollback)
        self.assertIn("404", action.side_effects)
        self.assertIn("격리 폴더", action.verification)
        self.assertIn("L2", action.autonomy_reason)
        self.assertEqual(action.priority, 1)
        # 어떤 칸이 LLM 문장인지 기록된다
        self.assertEqual(set(action.llm_fields), {
            "reason", "command", "rollback", "side_effects", "verification",
            "autonomy_reason", "priority"})
        self.assertEqual(report.field_fallbacks, [])
        self.assertTrue(plan.summary.startswith("웹셸이 업로드된"))

    def test_프롬프트에_대상과_매핑_근거가_들어간다(self):
        """명령을 쓰려면 대상을 알아야 하고, 근거는 매핑에서 가져와야 한다."""
        plan = make_plan()
        _, client = _run(plan, _payload_for(plan))

        user_prompt = client.calls[0]["user"]
        self.assertIn(WEBSHELL_PATH, user_prompt)            # 대상을 보여 준다
        self.assertIn("attack_techniques", user_prompt)       # 매핑 기법 목록
        self.assertIn("EVID-003", user_prompt)                # 인용 가능한 증거
        self.assertIn("quarantine_dir", user_prompt)          # 명령을 쓸 환경
        self.assertIn("A1", user_prompt)

    def test_카탈로그_문장은_프롬프트에_보이지_않는다(self):
        """카탈로그 문장을 보여 주면 그대로 베껴 적는다 — 이 칸들은 LLM이 직접 써야 한다."""
        plan = make_plan(actions=[make_action("A1")])
        _, client = _run(plan, _payload_for(plan))

        user_prompt = client.calls[0]["user"]
        self.assertNotIn("그 파일을 참조하는 정상 기능", user_prompt)   # 카탈로그 side_effects
        self.assertNotIn("sudo mv /var/quarantine/shell.php", user_prompt)  # 카탈로그 rollback


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
        # 문장은 전부 카탈로그 값으로 — LLM이 쓴 문장은 하나도 남지 않는다
        self.assertTrue(all(a.reason is None for a in plan.actions))
        self.assertTrue(all(a.llm_fields == [] for a in plan.actions))
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
# 규칙 3 — 빈 칸은 그 칸만 카탈로그 문장
# ----------------------------------------------------------------------

class Test규칙3_빈칸(unittest.TestCase):
    """칸이 비면 그 칸만 카탈로그 문장으로 두고, 나머지 칸은 LLM 문장을 쓴다."""

    def test_규칙3_reason이_비면_그_칸만_카탈로그_문장(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, reason="   ")      # 공백만

        report, _ = _run(plan, payload)

        self.assertFalse(report.used_fallback)          # 전체 거절은 아니다
        self.assertIn("A1", report.reasons_defaulted)
        self.assertIsNone(plan.actions[0].reason)
        # render가 쓰는 값은 카탈로그의 기본 문장
        self.assertEqual(plan.actions[0].effective_reason(), "업로드 직후 실행이 확인된 파일입니다.")
        # 다른 칸은 LLM 문장이 그대로 들어간다
        self.assertIn("격리 폴더", plan.actions[0].verification)
        self.assertNotIn("reason", plan.actions[0].llm_fields)

    def test_규칙3_설명칸이_비면_카탈로그_문장이_남는다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, side_effects="", verification=None)

        report, _ = _run(plan, payload)

        self.assertIn("그 파일을 참조하는 정상 기능", plan.actions[0].side_effects)   # 카탈로그 값
        self.assertIn("격리 폴더로 이동", plan.actions[0].verification)              # 카탈로그 값
        rejected = {f["field"] for f in report.field_fallbacks}
        self.assertEqual(rejected, {"side_effects", "verification"})

    def test_규칙3_너무_긴_명령은_자르지_않고_버린다(self):
        """잘린 명령을 붙여 넣으면 사고가 난다 — 상한을 넘기면 카탈로그 명령을 쓴다."""
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, command="sudo echo " + "가" * 500)

        report, _ = _run(plan, payload)

        self.assertEqual(plan.actions[0].command_hint, "sudo mv <대상> /var/quarantine/")
        self.assertNotIn("…", plan.actions[0].command_hint)
        self.assertIn("command", [f["field"] for f in report.field_fallbacks])

    def test_규칙3_너무_긴_설명은_잘린다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, side_effects="가" * 500)

        _run(plan, payload)

        self.assertLessEqual(len(plan.actions[0].side_effects), 301)
        self.assertTrue(plan.actions[0].side_effects.endswith("…"))


# ----------------------------------------------------------------------
# 규칙 4·5 — 없는 증거·기법 인용은 제거(문장은 살린다)
# ----------------------------------------------------------------------

class Test규칙4_5_인용검증(unittest.TestCase):
    """없는 EVID-*·T-번호 인용만 제거하고 문장은 살린다."""

    def test_규칙4_없는_증거_인용만_지운다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, reason="업로드 직후 실행이 확인됨 (EVID-003, EVID-999)")

        report, _ = _run(plan, payload)

        self.assertFalse(report.used_fallback)
        self.assertNotIn("EVID-999", plan.actions[0].reason)
        self.assertIn("EVID-003", plan.actions[0].reason)          # 있는 인용은 남는다
        self.assertIn("업로드 직후 실행이 확인됨", plan.actions[0].reason)
        self.assertTrue(any(c.get("evidence_id") == "EVID-999"
                            for c in report.stripped_citations))

    def test_규칙4_인용만_지우면_빈_괄호가_남지_않는다(self):
        text, removed = strip_unknown_citations("업로드가 확인됨 (EVID-999)", {"EVID-003"})

        self.assertEqual(removed, ["EVID-999"])
        self.assertNotIn("(", text)
        self.assertNotIn(")", text)
        self.assertEqual(text, "업로드가 확인됨")

    def test_규칙5_매핑되지_않은_기법_인용을_지운다(self):
        text, removed = strip_unknown_techniques(
            "T1505.003 웹셸이며 T1486 랜섬웨어 단계로 보입니다", {"T1505.003"})

        self.assertEqual(removed, ["T1486"])
        self.assertIn("T1505.003", text)
        self.assertNotIn("T1486", text)

    def test_규칙5_문장_안의_환각_기법은_지워진다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(
            plan, reason="T1486 랜섬웨어 준비 단계로 보입니다 (EVID-003)")

        report, _ = _run(plan, payload)

        self.assertNotIn("T1486", plan.actions[0].reason or "")
        self.assertTrue(any(c.get("technique_id") == "T1486"
                            for c in report.stripped_citations))

    def test_규칙4_summary의_없는_인용도_지운다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan)
        payload["summary"] = "웹셸이 업로드되었습니다 (EVID-404)."

        _run(plan, payload)

        self.assertNotIn("EVID-404", plan.summary)

    def test_규칙4_인용만_있던_reason이_비면_카탈로그_문장으로(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, reason="(EVID-999)")

        report, _ = _run(plan, payload)

        self.assertIsNone(plan.actions[0].reason)
        self.assertIn("A1", report.reasons_defaulted)


# ----------------------------------------------------------------------
# 규칙 6 — 근거는 ATT&CK 매핑 파일에서 가져와야 한다
# ----------------------------------------------------------------------

class Test규칙6_매핑근거(unittest.TestCase):
    """reason이 그 조치의 기법 증거를 인용하지 않으면 카탈로그 문장으로 되돌린다."""

    def test_규칙6_기법_증거를_인용하지_않으면_거절된다(self):
        plan = make_plan(actions=[make_action("A1", evidence_ids=["EVID-003"])])
        payload = _payload_for(plan, reason="웹셸로 보이므로 격리해야 합니다")   # 인용 없음

        report, _ = _run(plan, payload)

        self.assertIsNone(plan.actions[0].reason)       # 카탈로그 문장으로
        self.assertIn("A1", report.reasons_defaulted)
        rule = next(f["rule"] for f in report.field_fallbacks if f["field"] == "reason")
        self.assertEqual(rule, "missing_mapping_evidence")

    def test_규칙6_다른_사건의_증거를_인용해도_거절된다(self):
        """evidence_chain에는 있지만 그 조치의 기법 근거가 아닌 증거."""
        plan = make_plan(actions=[make_action("A1", evidence_ids=["EVID-003"])])
        payload = _payload_for(plan, reason="외부 파일을 내려받았습니다 (EVID-005)")

        report, _ = _run(plan, payload)

        self.assertIsNone(plan.actions[0].reason)
        self.assertIn("A1", report.reasons_defaulted)

    def test_규칙6_매핑_증거가_없는_조치는_인용을_요구하지_않는다(self):
        """폴백 카탈로그로 만든 일반 조치(기법 없음)는 인용할 증거 자체가 없다."""
        plan = make_plan(actions=[
            make_action("A1", technique_id=None, evidence_ids=[], category=CATEGORY_VERIFY),
        ])
        payload = _payload_for(plan, reason="같은 경로에 다른 웹셸이 있을 수 있습니다")

        report, _ = _run(plan, payload)

        self.assertEqual(plan.actions[0].reason, "같은 경로에 다른 웹셸이 있을 수 있습니다")
        self.assertEqual(report.reasons_defaulted, [])


# ----------------------------------------------------------------------
# 규칙 7 — 입력에 없는 IP·경로는 그 칸을 버린다
# ----------------------------------------------------------------------

class Test규칙7_환각대상(unittest.TestCase):
    """LLM이 입력에 없는 IP·경로를 적으면 그 칸을 카탈로그 값으로 되돌린다."""

    def test_규칙7_없는_경로를_적은_명령은_거절된다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, command="sudo mv /var/www/html/other/evil.php /var/quarantine/")

        report, _ = _run(plan, payload)

        self.assertEqual(plan.actions[0].command_hint, "sudo mv <대상> /var/quarantine/")
        rule = next(f["rule"] for f in report.field_fallbacks if f["field"] == "command")
        self.assertEqual(rule, "unknown_target_token")

    def test_규칙7_없는_IP를_적은_명령은_거절된다(self):
        plan = make_plan(actions=[make_action("A2", target=SRC_IP, target_source="seed_src_ip")])
        payload = _payload_for(plan, command="sudo iptables -I INPUT -s 198.51.100.77 -j DROP")

        report, _ = _run(plan, payload)

        self.assertNotIn("198.51.100.77", plan.actions[0].command_hint or "")
        self.assertIn("command", [f["field"] for f in report.field_fallbacks])

    def test_규칙7_조치의_대상과_격리폴더는_허용된다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, command=f"sudo mv {WEBSHELL_PATH} /var/quarantine/")

        report, _ = _run(plan, payload)

        self.assertIn(WEBSHELL_PATH, plan.actions[0].command_hint)
        self.assertEqual(report.field_fallbacks, [])

    def test_규칙7_대상의_상위_디렉터리는_허용된다(self):
        """웹루트 점검처럼 범위를 넓게 적는 경우 — 대상의 상위 경로는 환각이 아니다."""
        self.assertEqual(unknown_tokens("find /var/www/html -newermt", ALLOWED_TARGETS), [])
        # 너무 얕은 경로는 허용하지 않는다
        self.assertEqual(unknown_tokens("find /var -newermt", ALLOWED_TARGETS), ["/var"])

    def test_규칙7_표준_시스템_경로는_허용된다(self):
        for text in ("awk -F: '$3==0' /etc/passwd", "visudo -c /etc/sudoers",
                      "curl http://169.254.169.254/latest/meta-data/"):
            with self.subTest(text=text):
                self.assertEqual(unknown_tokens(text, ALLOWED_TARGETS), [])

    def test_규칙7_summary의_환각_대상도_거절된다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan)
        payload["summary"] = "203.0.113.200에서 공격이 시작되었습니다."

        report, _ = _run(plan, payload)

        self.assertIsNone(plan.summary)
        self.assertIn("summary", [f["field"] for f in report.field_fallbacks])


# ----------------------------------------------------------------------
# 규칙 8 — 파괴적 명령 차단
# ----------------------------------------------------------------------

class Test규칙8_파괴적명령(unittest.TestCase):
    """명령·원복 칸의 파괴적 명령은 그 칸을 버린다 — 사람이 그대로 실행하는 값이다."""

    def test_규칙8_삭제_명령은_거절된다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, command=f"sudo rm -f {WEBSHELL_PATH}")

        report, _ = _run(plan, payload)

        self.assertEqual(plan.actions[0].command_hint, "sudo mv <대상> /var/quarantine/")
        rule = next(f["rule"] for f in report.field_fallbacks if f["field"] == "command")
        self.assertEqual(rule, "destructive_command")

    def test_규칙8_원복칸의_파괴적_명령도_거절된다(self):
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(plan, rollback="sudo shred -u /var/quarantine/shell.php")

        report, _ = _run(plan, payload)

        self.assertIn("sudo mv /var/quarantine/shell.php", plan.actions[0].rollback)  # 카탈로그 값
        self.assertIn("rollback", [f["field"] for f in report.field_fallbacks])

    def test_규칙8_차단_목록(self):
        cases = [
            "sudo rm -rf /var/www/html",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
            "truncate -s 0 /var/log/audit/audit.log",
            "chmod -R 777 /var/www",
            "userdel attacker",
            "sudo iptables -F",
            "systemctl stop auditd",
            "auditctl -D",
            "history -c",
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertTrue(destructive_hits(command), f"{command}를 걸러내지 못했다")

    def test_규칙8_정상_조치_명령은_통과한다(self):
        cases = [
            "sudo mv /var/www/html/uploads/shell.php /var/quarantine/",
            "sudo iptables -I INPUT -s 203.0.113.45 -j DROP",
            "sudo passwd -l attacker",
            "sudo pkill -TERM -P 2051",
            "awk -F: '$3==0' /etc/passwd",
        ]
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(destructive_hits(command), [])

    def test_규칙8_설명칸에서는_단어만으로_거절하지_않는다(self):
        """부작용 설명에 "삭제"라는 낱말이 나오는 것은 막지 않는다 — 실행되는 칸만 본다."""
        plan = make_plan(actions=[make_action("A1")])
        payload = _payload_for(
            plan, side_effects="파일을 삭제하지 않고 옮기므로 rm 과 달리 되돌릴 수 있습니다")

        report, _ = _run(plan, payload)

        self.assertIn("되돌릴 수 있습니다", plan.actions[0].side_effects)
        self.assertEqual(report.field_fallbacks, [])


# ----------------------------------------------------------------------
# 규칙 9·10·11 — 코드가 정한 사실과 어긋나는 문장
# ----------------------------------------------------------------------

class Test규칙9_10_11_사실일치(unittest.TestCase):
    """가역성·자율성 등급·우선순위는 코드가 정한 값이다. 어긋나면 그 칸을 버린다."""

    def test_규칙9_비가역_조치에_되돌리는_절차를_적으면_거절(self):
        plan = make_plan(actions=[
            make_action("A1", reversible=False, rollback="되돌릴 수 없음 — 재발급이 필요합니다"),
        ])
        payload = _payload_for(plan, rollback="sudo mv /var/quarantine/shell.php 원위치로 복원")

        report, _ = _run(plan, payload)

        self.assertEqual(plan.actions[0].rollback, "되돌릴 수 없음 — 재발급이 필요합니다")
        rule = next(f["rule"] for f in report.field_fallbacks if f["field"] == "rollback")
        self.assertEqual(rule, "irreversible_mismatch")

    def test_규칙9_비가역_조치가_되돌릴_수_없음을_말하면_통과(self):
        plan = make_plan(actions=[make_action("A1", reversible=False)])
        payload = _payload_for(
            plan, rollback="되돌릴 수 없음 — 사용자에게 새 비밀번호를 재발급해야 합니다")

        report, _ = _run(plan, payload)

        self.assertIn("되돌릴 수 없음", plan.actions[0].rollback)
        self.assertEqual(report.field_fallbacks, [])

    def test_규칙10_다른_자율성_등급을_주장하면_거절(self):
        plan = make_plan(actions=[make_action("A1", autonomy="L1")])
        payload = _payload_for(plan, autonomy_reason="영향이 작아 자동 실행해도 됩니다(L2)")

        report, _ = _run(plan, payload)

        # 카탈로그 폴백 문장에는 "(L2)"가 들어 있으므로, LLM 문장이 안 들어갔는지로 본다
        self.assertNotIn("자동 실행해도 됩니다", plan.actions[0].autonomy_reason)
        self.assertNotIn("autonomy_reason", plan.actions[0].llm_fields)
        rule = next(f["rule"] for f in report.field_fallbacks
                    if f["field"] == "autonomy_reason")
        self.assertEqual(rule, "autonomy_mismatch")

    def test_규칙10_하향된_조치는_두_등급을_모두_말할_수_있다(self):
        plan = make_plan(actions=[
            make_action("A1", autonomy="L1", autonomy_downgraded_from="L2"),
        ])
        payload = _payload_for(
            plan, autonomy_reason="원래 L2 후보이지만 매핑 경고로 L1로 내려 승인 후 실행합니다")

        report, _ = _run(plan, payload)

        self.assertIn("L1", plan.actions[0].autonomy_reason)
        self.assertEqual(report.field_fallbacks, [])

    def test_규칙11_priority가_범위를_벗어나면_카탈로그_값_유지(self):
        for bad in (0, 4, 99, "P1", 1.5, None, True):
            with self.subTest(priority=bad):
                plan = make_plan(actions=[make_action("A1", priority=2)])
                payload = _payload_for(plan, priority=bad)

                report, _ = _run(plan, payload)

                self.assertEqual(plan.actions[0].priority, 2)
                self.assertIn("priority", [f["field"] for f in report.field_fallbacks])

    def test_규칙11_정상_priority는_반영된다(self):
        plan = make_plan(actions=[make_action("A1", priority=2)])
        payload = _payload_for(plan, priority=3)

        _run(plan, payload)

        self.assertEqual(plan.actions[0].priority, 3)


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

        report, client = _run(plan, {"actions": [
            _action_payload(make_action("A1"))]})

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions[0]["action_id"], "A2")
        self.assertEqual(report.dropped_actions[0]["rule"], "target_not_in_sources")
        # 폐기 뒤 남은 조치만 LLM에게 보낸다 — 응답은 A1만 돌려주면 통과
        self.assertFalse(report.used_fallback)
        self.assertNotIn('"action_id": "A2"', client.calls[0]["user"])

    def test_규칙1_대상이_없는_점검_항목은_폐기하지_않는다(self):
        """target=None은 "무엇을 확인하라"는 항목이다 — 지울 대상 값이 없으므로 통과시킨다."""
        plan = make_plan(actions=[
            make_action("A1", target=None, target_source=None, technique_id=None,
                        evidence_ids=[], category=CATEGORY_VERIFY),
        ])

        report, _ = _run(plan, _payload_for(plan))

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions, [])

    def test_규칙5_매핑되지_않은_기법의_조치는_폐기된다(self):
        plan = make_plan(actions=[
            make_action("A1"),
            make_action("A2", technique_id="T1486", technique_name="Data Encrypted for Impact"),
        ])

        report, _ = _run(plan, {"actions": [_action_payload(make_action("A1"))]})

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions[0]["rule"], "technique_not_mapped")
        self.assertIn("T1486", report.dropped_actions[0]["detail"])

    def test_규칙5_상위기법_조치도_허용된다(self):
        """T1505.003으로 매핑됐으면 상위 T1505 조치도 쓸 수 있다."""
        plan = make_plan(actions=[make_action("A1", technique_id="T1505")])

        report, _ = _run(plan, _payload_for(plan))

        self.assertEqual(plan.action_ids(), ["A1"])
        self.assertEqual(report.dropped_actions, [])

    def test_허용목록을_못_받으면_검증을_건너뛰되_기록을_남긴다(self):
        plan = make_plan(actions=[make_action("A1", target="/etc/shadow")])

        report, _ = _run(plan, _payload_for(plan),
                         allowed_targets=None, allowed_technique_ids=None)

        self.assertEqual(plan.action_ids(), ["A1"])            # 지우지 않는다
        self.assertTrue(any("대상 검증 건너뜀" in note for note in report.notes))
        self.assertTrue(any("기법 검증 건너뜀" in note for note in report.notes))


# ----------------------------------------------------------------------
# LLM 장애 — 파이프라인을 멈추지 않는다 (설계서 8-2)
# ----------------------------------------------------------------------

class TestLLM장애(unittest.TestCase):
    """LLM이 예외를 던져도 권고는 카탈로그 문장으로 나간다."""

    def test_LLM이_예외를_던져도_권고는_카탈로그_문장으로_나간다(self):
        plan = make_plan()
        report, _ = _run(plan, error=RuntimeError("API 503"))

        self.assertTrue(report.used_fallback)
        self.assertIn("API 503", report.fallback_reason)
        self.assertEqual(plan.action_ids(), ["A1", "A2", "A3"])           # 조치는 그대로
        self.assertTrue(plan.actions[0].effective_reason())                 # 기본 문장이 있다
        # 일곱 칸 중 코드가 채운 칸은 그대로 남아 권고문이 비지 않는다
        self.assertTrue(plan.actions[0].rollback)
        self.assertTrue(plan.actions[0].verification)
        self.assertTrue(plan.actions[0].command_hint)
        self.assertEqual(plan.actions[0].llm_fields, [])

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
        payload = _payload_for(plan, reason="가" * 500 + " (EVID-003)")

        _run(plan, payload)

        self.assertLessEqual(len(plan.actions[0].reason or ""), 201)   # 200자 + 생략 기호


if __name__ == "__main__":
    unittest.main()
