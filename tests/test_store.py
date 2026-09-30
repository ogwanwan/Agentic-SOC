"""store/ incident DB 검증. 실행: python tests/test_store.py"""
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detection_pipeline"))

from pipeline.state import diff_incidents, incident_key, save_state
from store.db import connect, import_state_json, migrate
from store.incidents import get_incident, list_queue, load_state_view, record_run, stats

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def _inc(iid, end, count=2, ip="1.1.1.1", reason="Config File Access", score=39, route="investigate",
         llm=None, **extra):
    inc = {
        "incident_id": iid,
        "entity": {"type": "src_ip", "value": ip},
        "window": ["2026-09-29T11:00:00Z", end],
        "layers": ["web"],
        "members": ["access.log:%d" % i for i in range(count)],
        "member_count": count,
        "oversized": False,
        "join_path": [],
        "seeds": [{"reason": reason}],
        "triage_score": score,
        "priority": "P2" if score >= 30 else "P3",
        "route": route,
        "triage_parts": {"severity": score},
    }
    if llm is not None:
        inc["llm_investigate"] = llm
        inc["llm_reason"] = "reason-%s" % iid
    inc.update(extra)
    return inc


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.conn = connect(os.path.join(self.dir, "soc.db"))
        migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir)

    def _cycle(self, incidents, now=NOW):
        """파이프라인 운영 모드와 같은 순서: DB 상태 읽기 → diff → 저장."""
        state = load_state_view(self.conn, now)
        emits, new_state = diff_incidents(incidents, state, now)
        record_run(self.conn, emits, new_state, now)
        return [kind for kind, _ in emits]

    def _row(self, inc):
        return self.conn.execute("SELECT * FROM incidents WHERE incident_key = ?", (incident_key(inc),)).fetchone()

    def _set_status(self, inc, status, claimed_at=None):
        self.conn.execute("UPDATE incidents SET status = ?, claimed_at = ? WHERE incident_key = ?",
                          (status, claimed_at, incident_key(inc)))

    def test_migrate_twice_is_safe(self):
        migrate(self.conn)
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_new_incident_is_pending_and_queued(self):
        inc = _inc("INC-a", "2026-09-29T11:10:00Z")
        self.assertEqual(self._cycle([inc]), ["new"])
        row = self._row(inc)
        self.assertEqual((row["status"], row["has_update"], row["route"], row["triage_score"]),
                         ("pending", 0, "investigate", 39))
        self.assertEqual([r["incident_key"] for r in list_queue(self.conn)], [incident_key(inc)])

    def test_unchanged_run_keeps_status(self):
        inc = _inc("INC-a", "2026-09-29T11:10:00Z")
        self._cycle([inc])
        self._set_status(inc, "done")
        later = NOW + timedelta(minutes=5)
        self.assertEqual(self._cycle([inc], later), [])
        row = self._row(inc)
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["last_seen"], "2026-09-29T12:05:00Z")  # 추적 필드는 갱신
        self.assertEqual(row["updated_at"], "2026-09-29T12:00:00Z")  # 내용 갱신 시각은 그대로

    def test_update_reopens_done(self):
        self._cycle([_inc("INC-a", "2026-09-29T11:10:00Z")])
        self._set_status(_inc("INC-a", ""), "done", "2026-09-29T12:01:00Z")
        grown = _inc("INC-b", "2026-09-29T11:20:00Z", count=3)
        self.assertEqual(self._cycle([grown], NOW + timedelta(minutes=5)), ["update"])
        row = self._row(grown)
        self.assertEqual((row["status"], row["claimed_at"], row["incident_id"]), ("pending", None, "INC-b"))

    def test_update_flags_investigating(self):
        self._cycle([_inc("INC-a", "2026-09-29T11:10:00Z")])
        self._set_status(_inc("INC-a", ""), "investigating", "2026-09-29T12:01:00Z")
        self._cycle([_inc("INC-b", "2026-09-29T11:20:00Z", count=3)], NOW + timedelta(minutes=5))
        row = self._row(_inc("INC-b", ""))
        self.assertEqual((row["status"], row["has_update"], row["claimed_at"]),
                         ("investigating", 1, "2026-09-29T12:01:00Z"))
        self.assertEqual(list_queue(self.conn), [])

    def test_queue_is_fail_open_and_ordered(self):
        unreviewed = _inc("INC-n", "2026-09-29T11:10:00Z", ip="1.0.0.1", score=39)
        false_pos = _inc("INC-f", "2026-09-29T11:10:00Z", ip="1.0.0.2", score=70, llm=False)
        true_pos = _inc("INC-t", "2026-09-29T11:10:00Z", ip="1.0.0.3", score=50, llm=True)
        dashboard = _inc("INC-d", "2026-09-29T11:10:00Z", ip="1.0.0.4", score=20, route="dashboard")
        self._cycle([unreviewed, false_pos, true_pos, dashboard])
        tie_later = _inc("INC-l", "2026-09-29T11:10:00Z", ip="1.0.0.5", score=39)
        self._cycle([tie_later], NOW + timedelta(minutes=5))
        ids = [r["incident_id"] for r in list_queue(self.conn)]
        # 오탐(false)·dashboard 제외, LLM 미리뷰(NULL) 포함, 점수순, 동점이면 먼저 들어온 것부터
        self.assertEqual(ids, ["INC-t", "INC-n", "INC-l"])

        # 오탐이었던 사건이 update 에서 진짜로 바뀌면 다시 대기열에
        flipped = _inc("INC-f2", "2026-09-29T11:20:00Z", ip="1.0.0.2", score=70, llm=True)
        self._cycle([flipped], NOW + timedelta(minutes=10))
        self.assertEqual(list_queue(self.conn)[0]["incident_id"], "INC-f2")

    def test_stale_key_comes_back_as_new(self):
        inc = _inc("INC-a", "2026-09-29T11:10:00Z")
        self._cycle([inc])
        self._set_status(inc, "done")
        day_later = _inc("INC-a", "2026-09-30T13:00:00Z")
        self.assertEqual(self._cycle([day_later], NOW + timedelta(hours=25)), ["new"])
        self.assertEqual(self._row(inc)["status"], "pending")
        self.assertEqual(stats(self.conn)["total"], 1)  # 행은 새로 생기지 않고 같은 키가 다시 열림

    def test_details_overwritten_and_extra_kept(self):
        self._cycle([_inc("INC-a", "2026-09-29T11:10:00Z", count=2, merged_from=2)])
        self._cycle([_inc("INC-b", "2026-09-29T11:20:00Z", count=3, oversized=True)], NOW + timedelta(minutes=5))
        inc = get_incident(self.conn, incident_key(_inc("INC-b", "")))
        self.assertEqual(inc["members"], ["access.log:0", "access.log:1", "access.log:2"])  # 합치지 않고 최신으로
        self.assertEqual(inc["seeds"], [{"reason": "Config File Access"}])                   # 중복 없이
        self.assertEqual(inc["extra"], {"oversized": True, "triage_parts": {"severity": 39}})
        self.assertIsNone(get_incident(self.conn, "nope"))


class ImportStateJsonTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.conn = connect(os.path.join(self.dir, "soc.db"))
        migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir)

    def test_no_state_file(self):
        self.assertIsNone(import_state_json(self.conn, self.dir))

    def test_imported_keys_are_not_new_and_not_queued(self):
        inc = _inc("INC-a", "2026-09-29T11:10:00Z")
        _, state = diff_incidents([inc], {}, NOW)
        save_state(self.dir, state)

        self.assertEqual(import_state_json(self.conn, self.dir), 1)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "state.json")))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "state.json.migrated")))
        self.assertIsNone(import_state_json(self.conn, self.dir))  # 두 번째는 할 일 없음
        self.assertEqual(list_queue(self.conn), [])                 # 이미 보고된 사건은 대기열에 안 쏟아짐

        # 같은 사건이 다시 보여도 new 가 아니다
        later = NOW + timedelta(minutes=5)
        emits, new_state = diff_incidents([inc], load_state_view(self.conn, later), later)
        self.assertEqual(emits, [])
        # 새 활동이 생기면 update 로 내용이 채워지고 대기열에 들어간다
        grown = _inc("INC-b", "2026-09-29T11:20:00Z", count=3)
        emits, new_state = diff_incidents([grown], load_state_view(self.conn, later), later)
        record_run(self.conn, emits, new_state, later)
        self.assertEqual([kind for kind, _ in emits], ["update"])
        self.assertEqual([r["incident_id"] for r in list_queue(self.conn)], ["INC-b"])


if __name__ == "__main__":
    unittest.main()
