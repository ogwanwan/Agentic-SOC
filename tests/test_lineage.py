"""tests/test_lineage.py — common/lineage.py 1단계(인스턴스 분할 + 부모 연결) 오연결 방지 테스트."""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection_pipeline"))

from common.lineage import (  # noqa: E402
    WARN_REPARENTED,
    build_process_index,
)
from common.join_keys import same_process_lineage  # noqa: E402
from common.schema import build_event  # noqa: E402
from tools.fetch_audit_log import fetch_audit_log  # noqa: E402

SAMPLE_AUDIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "detection_pipeline", "samples", "sample_audit.log")


def sys_event(raw_ref, ts, pid, ppid, serial, uid=33, comm="sh", exe="/usr/bin/dash"):
    return build_event(
        timestamp=ts, layer="system", raw_ref=raw_ref, pid=pid, ppid=ppid,
        layer_data={"serial": serial, "uid": uid, "comm": comm, "exe": exe, "syscall": "execve"},
    )


def T(sec, base="2026-09-14T23:45:"):
    """base 분 안의 초 → ISO. T(12.3) == 2026-09-14T23:45:12.300Z"""
    return "%s%06.3fZ" % (base, sec)


class SampleLogLineageTests(unittest.TestCase):
    """테스트 1: 샘플 audit 로그에서 php-fpm(1200) → sh(5310), php-fpm → sudo(5320) → useradd(5501)."""

    @classmethod
    def setUpClass(cls):
        cls.events = fetch_audit_log(SAMPLE_AUDIT)
        cls.index = build_process_index(cls.events)

    def _only(self, pid):
        insts = self.index.instances_of(0, pid)
        self.assertEqual(1, len(insts), "pid %s 는 인스턴스 1개여야 함" % pid)
        return insts[0]

    def test_single_epoch_and_no_skips(self):
        self.assertEqual(1, self.index.epoch_count)
        self.assertEqual(0, self.index.skipped)
        self.assertEqual(6, len(self.index.instances))

    def test_php_fpm_children_are_sh_and_sudo(self):
        php = self._only(1200)
        self.assertEqual([5310, 5320], [c.pid for c in self.index.children_of(php)])
        self.assertIsNone(self.index.parent_of(php), "부모 1000 은 미관측 → 끊김")

    def test_sudo_to_useradd_with_privilege_escalation(self):
        sudo, useradd = self._only(5320), self._only(5501)
        self.assertEqual(sudo.key, useradd.parent_key)
        self.assertEqual([33], sudo.uids)
        self.assertEqual([0], useradd.uids)        # uid 는 조건이 아니므로 상승해도 연결됨

    def test_admin_tail_and_cron_are_unrelated(self):
        tail, cron = self._only(3839), self._only(6000)
        self.assertIsNone(tail.parent_key)
        self.assertIsNone(cron.parent_key)          # ppid 1 은 뿌리
        for inst in (tail, cron):
            self.assertEqual([], self.index.children_of(inst))

    def test_event_maps_to_instance_and_raw_refs_kept(self):
        sh_ev = next(e for e in self.events if e["pid"] == 5310)
        inst = self.index.instance_for_event(sh_ev)
        self.assertEqual((0, 5310, 0), inst.key)
        self.assertEqual(["sample_audit.log:11"], inst.raw_refs)


class RebootBoundaryTests(unittest.TestCase):
    """테스트 2: serial 리셋 전후의 같은 pid 는 다른 epoch, 서로 연결되지 않는다."""

    def test_serial_reset_splits_epochs(self):
        events = [
            sys_event("a.log:1", T(0.0), 1200, 1000, serial=90000, comm="php-fpm"),
            sys_event("a.log:2", T(1.0), 5310, 1200, serial=90001),
            # 재부팅: serial 90001 → 5
            sys_event("a.log:3", T(10.0), 5310, 4000, serial=5, comm="cron"),
            sys_event("a.log:4", T(11.0), 6001, 5310, serial=6, comm="curl"),
        ]
        idx = build_process_index(events)
        self.assertEqual(2, idx.epoch_count)
        self.assertEqual(1, len(idx.instances_of(0, 5310)))
        self.assertEqual(1, len(idx.instances_of(1, 5310)))
        old_sh, new_cron, curl = idx.instances_of(0, 5310)[0], idx.instances_of(1, 5310)[0], idx.instances_of(1, 6001)[0]
        self.assertEqual((0, 1200, 0), old_sh.parent_key)
        self.assertIsNone(new_cron.parent_key, "epoch 1 에 4000 은 미관측")
        self.assertEqual(new_cron.key, curl.parent_key, "curl 은 같은 epoch 의 5310 에만 붙는다")
        self.assertEqual([], idx.children_of(old_sh))

    def test_small_serial_reorder_is_not_a_reboot(self):
        events = [
            sys_event("a.log:1", T(0.0), 1200, 1000, serial=500),
            sys_event("a.log:2", T(0.5), 5310, 1200, serial=498),   # 파서 창 재정렬 수준
        ]
        idx = build_process_index(events)
        self.assertEqual(1, idx.epoch_count)
        self.assertEqual((0, 1200, 0), idx.instances_of(0, 5310)[0].parent_key)


class PidReuseTests(unittest.TestCase):
    """테스트 3: 같은 부팅에서 ppid 가 바뀐 같은 pid 는 두 인스턴스, 자식은 자기 시각의 인스턴스에만."""

    def setUp(self):
        self.events = [
            sys_event("a.log:1", T(0.0), 1200, 1000, serial=1, comm="php-fpm"),
            sys_event("a.log:2", T(5.0), 5310, 1200, serial=2, comm="sh"),        # 인스턴스 A (웹셸)
            sys_event("a.log:3", T(6.0), 9001, 5310, serial=3, comm="curl"),      # A 의 자식
            sys_event("a.log:4", T(30.0), 5310, 7000, serial=4, comm="sleep"),    # 인스턴스 B (재사용)
            sys_event("a.log:5", T(31.0), 9002, 5310, serial=5, comm="cat"),      # B 의 자식
        ]
        self.idx = build_process_index(self.events)

    def test_two_instances_for_reused_pid(self):
        a, b = self.idx.instances_of(0, 5310)
        self.assertEqual((1200, 7000), (a.ppid, b.ppid))
        self.assertEqual((0, 1200, 0), a.parent_key)
        self.assertIsNone(b.parent_key)

    def test_children_bind_to_instance_alive_at_their_time(self):
        a, b = self.idx.instances_of(0, 5310)
        self.assertEqual([9001], [c.pid for c in self.idx.children_of(a)])
        self.assertEqual([9002], [c.pid for c in self.idx.children_of(b)])

    def test_exe_change_is_not_a_split(self):
        events = [
            sys_event("a.log:1", T(0.0), 5310, 1200, serial=1, comm="sh", exe="/usr/bin/dash"),
            sys_event("a.log:2", T(0.1), 5310, 1200, serial=2, comm="curl", exe="/usr/bin/curl"),
        ]
        idx = build_process_index(events)
        insts = idx.instances_of(0, 5310)
        self.assertEqual(1, len(insts))
        self.assertEqual(["sh", "curl"], insts[0].comms)


class ParentSelectionTests(unittest.TestCase):
    """테스트 4·5: 시간 역행 부모는 잇지 않고, init 입양은 같은 인스턴스로 유지."""

    def test_parent_first_seen_far_after_child_is_not_linked(self):
        events = [
            sys_event("a.log:1", T(0.0), 5310, 1200, serial=1),
            sys_event("a.log:2", T(10.0), 1200, 1000, serial=2, comm="php-fpm"),   # 10초 뒤 첫 관측
        ]
        idx = build_process_index(events)
        self.assertIsNone(idx.instances_of(0, 5310)[0].parent_key)

    def test_parent_within_slack_is_linked(self):
        events = [
            sys_event("a.log:1", T(0.0), 5310, 1200, serial=1),
            sys_event("a.log:2", T(1.5), 1200, 1000, serial=2, comm="php-fpm"),    # 2초 이내
        ]
        idx = build_process_index(events)
        self.assertEqual((0, 1200, 0), idx.instances_of(0, 5310)[0].parent_key)

    def test_reparent_to_init_keeps_single_instance(self):
        events = [
            sys_event("a.log:1", T(0.0), 1200, 1000, serial=1, comm="php-fpm"),
            sys_event("a.log:2", T(1.0), 5310, 1200, serial=2, comm="sh"),
            sys_event("a.log:3", T(2.0), 5310, 1, serial=3, comm="nc"),            # 부모 사망 → init 입양
        ]
        idx = build_process_index(events)
        insts = idx.instances_of(0, 5310)
        self.assertEqual(1, len(insts))
        self.assertEqual(1200, insts[0].ppid, "원래 부모를 유지")
        self.assertEqual((0, 1200, 0), insts[0].parent_key)
        self.assertIn(WARN_REPARENTED, insts[0].warnings)

    def test_self_and_root_ppids_have_no_parent(self):
        events = [
            sys_event("a.log:1", T(0.0), 1, 0, serial=1, comm="systemd"),
            sys_event("a.log:2", T(1.0), 6000, 1, serial=2, comm="cron"),
            sys_event("a.log:3", T(2.0), 7, 7, serial=3, comm="weird"),
        ]
        idx = build_process_index(events)
        for pid in (1, 6000, 7):
            self.assertIsNone(idx.instances_of(0, pid)[0].parent_key)


class DeterminismAndInputTests(unittest.TestCase):
    """테스트 7: 입력 순서 무관 + 잘못된 입력 처리."""

    def test_shuffled_input_gives_identical_index(self):
        events = fetch_audit_log(SAMPLE_AUDIT) + [
            sys_event("x.log:1", T(0.0, "2026-09-15T01:00:"), 5310, 1200, serial=3),
            sys_event("x.log:2", T(2.0, "2026-09-15T01:00:"), 9001, 5310, serial=4),
        ]
        expected = build_process_index(events).to_dict()
        for seed in (1, 7, 42):
            shuffled = list(events)
            random.Random(seed).shuffle(shuffled)
            self.assertEqual(expected, build_process_index(shuffled).to_dict())

    def test_non_system_and_invalid_events_are_skipped(self):
        events = [
            build_event(timestamp=T(0.0), layer="web", raw_ref="w:1", src_ip="1.2.3.4", layer_data={}),
            build_event(timestamp="not-a-time", layer="system", raw_ref="a:1", pid=5, ppid=1, layer_data={}),
            build_event(timestamp=T(0.0), layer="system", raw_ref="a:2", pid=None, ppid=1, layer_data={}),
            "garbage",
            sys_event("a.log:3", T(1.0), 5310, 1200, serial=1),
        ]
        idx = build_process_index(events)
        self.assertEqual(4, idx.skipped)
        self.assertEqual(1, len(idx.instances))

    def test_invalid_parameters_raise(self):
        with self.assertRaises(ValueError):
            build_process_index([], serial_reset_slack=-1)
        with self.assertRaises(ValueError):
            build_process_index([], parent_slack_seconds=True)


class SameProcessLineageTests(unittest.TestCase):
    """join_keys.same_process_lineage 가 인스턴스 기준으로 판정하는지 (짝 판정 호환 + index 판정)."""

    def test_pairwise_parent_child_both_directions(self):
        parent = sys_event("a.log:1", T(0.0), 1200, 1000, serial=1, comm="php-fpm")
        child = sys_event("a.log:2", T(1.0), 5310, 1200, serial=2)
        self.assertTrue(same_process_lineage(parent, child))
        self.assertTrue(same_process_lineage(child, parent))

    def test_pairwise_unrelated_and_self(self):
        a = sys_event("a.log:1", T(0.0), 1200, 1000, serial=1)
        b = sys_event("a.log:2", T(1.0), 6000, 1, serial=2)
        self.assertFalse(same_process_lineage(a, b))
        self.assertFalse(same_process_lineage(a, a))

    def test_pairwise_time_reversed_parent_is_rejected(self):
        child = sys_event("a.log:1", T(0.0), 5310, 1200, serial=1)
        late_parent = sys_event("a.log:2", T(10.0), 1200, 1000, serial=2)
        self.assertFalse(same_process_lineage(child, late_parent))

    def test_pairwise_events_without_raw_ref_or_serial(self):
        # join_keys 자체 self-test 와 같은 최소 dict 도 판정돼야 한다
        parent = {"timestamp": "2026-09-07T15:34:47Z", "pid": 239001, "ppid": 233915,
                  "layer": "system", "layer_data": {"uid": 33}}
        child = {"timestamp": "2026-09-07T15:34:48Z", "pid": 240000, "ppid": 239001,
                 "layer": "system", "layer_data": {"uid": 33}}
        self.assertTrue(same_process_lineage(parent, child))

    def test_index_rejects_pid_reuse_across_reboot(self):
        events = [
            sys_event("a.log:1", T(0.0), 1200, 1000, serial=90000, comm="php-fpm"),
            sys_event("a.log:2", T(10.0), 5310, 4000, serial=5, comm="cron"),      # 재부팅 후
            sys_event("a.log:3", T(11.0), 1200, 5310, serial=6, comm="curl"),      # 새 1200, 부모는 새 5310
        ]
        idx = build_process_index(events)
        old_php, new_cron, new_1200 = events
        self.assertFalse(same_process_lineage(old_php, new_cron, idx))
        self.assertFalse(same_process_lineage(new_1200, old_php, idx))
        self.assertTrue(same_process_lineage(new_cron, new_1200, idx))

    def test_index_binds_child_to_instance_alive_at_its_time(self):
        events = [
            sys_event("a.log:1", T(0.0), 1200, 1000, serial=1, comm="php-fpm"),
            sys_event("a.log:2", T(5.0), 5310, 1200, serial=2, comm="sh"),        # 5310-A
            sys_event("a.log:3", T(30.0), 5310, 7000, serial=3, comm="sleep"),    # 5310-B (재사용)
            sys_event("a.log:4", T(31.0), 9002, 5310, serial=4, comm="cat"),      # B 의 자식
        ]
        idx = build_process_index(events)
        _, sh_a, sleep_b, cat = events
        self.assertTrue(same_process_lineage(sleep_b, cat, idx))
        self.assertFalse(same_process_lineage(sh_a, cat, idx), "번호만 보면 True 가 되는 오연결")


if __name__ == "__main__":
    unittest.main()
