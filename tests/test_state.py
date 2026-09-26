"""pipeline/state.py 증분 상태 검증. 실행: python tests/test_state.py"""
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.state import diff_incidents, incident_key, load_state, run_lock, save_state

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


def _inc(iid, end, count=2, ip="1.1.1.1", reason="Config File Access"):
    return {
        "incident_id": iid,
        "entity": {"type": "src_ip", "value": ip},
        "window": ["2026-09-26T11:00:00Z", end],
        "members": ["ap:%d" % i for i in range(count)],
        "member_count": count,
        "seeds": [{"reason": reason}],
    }


def _kinds(emits):
    return [kind for kind, _ in emits]


class DiffIncidentsTest(unittest.TestCase):
    def test_new_then_unchanged(self):
        emits, state = diff_incidents([_inc("INC-a", "2026-09-26T11:10:00Z")], {}, NOW)
        self.assertEqual(_kinds(emits), ["new"])
        emits, state = diff_incidents([_inc("INC-a", "2026-09-26T11:10:00Z")], state, NOW + timedelta(minutes=5))
        self.assertEqual(emits, [])
        self.assertEqual(len(state["incidents"]), 1)

    def test_key_survives_incident_id_change(self):
        # 멤버가 늘거나 로테이트로 raw_ref 가 바뀌어 incident_id 가 달라도 같은 사건
        a = _inc("INC-a", "2026-09-26T11:10:00Z")
        b = _inc("INC-b", "2026-09-26T11:10:00Z")
        self.assertEqual(incident_key(a), incident_key(b))
        self.assertNotEqual(incident_key(a), incident_key(_inc("INC-a", "2026-09-26T11:10:00Z", ip="2.2.2.2")))
        self.assertNotEqual(incident_key(a), incident_key(_inc("INC-a", "2026-09-26T11:10:00Z", reason="x")))

    def test_new_activity_is_update(self):
        _, state = diff_incidents([_inc("INC-a", "2026-09-26T11:10:00Z")], {}, NOW)
        emits, state = diff_incidents([_inc("INC-b", "2026-09-26T11:14:00.5Z", count=3)], state, NOW)
        self.assertEqual(_kinds(emits), ["update"])
        self.assertEqual(state["incidents"][incident_key(emits[0][1])]["incident_id"], "INC-b")

    def test_window_slide_shrink_is_not_update(self):
        # 창이 밀려 오래된 멤버가 빠짐(count 감소, 끝 시각 동일) → 다시 내보내지 않는다
        _, state = diff_incidents([_inc("INC-a", "2026-09-26T11:10:00Z", count=10)], {}, NOW)
        emits, state = diff_incidents([_inc("INC-c", "2026-09-26T11:10:00Z", count=4)], state, NOW)
        self.assertEqual(emits, [])
        # 이후 새 활동이 생기면 count 가 최대치보다 작아도 update
        emits, _ = diff_incidents([_inc("INC-d", "2026-09-26T11:20:00Z", count=6)], state, NOW)
        self.assertEqual(_kinds(emits), ["update"])

    def test_stale_keys_pruned(self):
        _, state = diff_incidents([_inc("INC-a", "2026-09-26T11:10:00Z")], {}, NOW)
        _, state = diff_incidents([], state, NOW + timedelta(hours=25))
        self.assertEqual(state["incidents"], {})

    def test_entity_without_value_falls_back_to_id(self):
        inc = _inc("INC-z", "2026-09-26T11:10:00Z")
        inc["entity"] = {"type": "src_ip", "value": None}
        self.assertEqual(incident_key(inc), "id:INC-z")


class StateFileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_roundtrip_and_corrupt(self):
        self.assertEqual(load_state(self.dir), {})
        _, state = diff_incidents([_inc("INC-a", "2026-09-26T11:10:00Z")], {}, NOW)
        save_state(self.dir, state)
        self.assertEqual(load_state(self.dir), state)
        with open(os.path.join(self.dir, "state.json"), "w") as fh:
            fh.write("{broken")
        self.assertEqual(load_state(self.dir), {})

    def test_lock_acquired(self):
        with run_lock(self.dir) as locked:
            self.assertTrue(locked)


if __name__ == "__main__":
    unittest.main()
