"""run_pipeline.write_emits 실행별 파일 인계 검증. 실행: python tests/test_emit.py"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from run_pipeline import write_emits

NOW = datetime(2026, 9, 26, 7, 49, 15, tzinfo=timezone.utc)


def _inc(iid, ip):
    return {"incident_id": iid, "entity": {"type": "src_ip", "value": ip},
            "window": ["2026-09-26T07:41:00Z", "2026-09-26T07:43:00Z"],
            "members": ["access.log:1"], "member_count": 1, "seeds": [{"reason": "r"}]}


class WriteEmitsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_one_file_per_run_in_date_dir(self):
        path = write_emits(self.dir, [("new", _inc("INC-a", "1.1.1.1")), ("update", _inc("INC-b", "2.2.2.2"))], NOW)
        self.assertEqual(path.parent.name, "2026-09-26")
        self.assertRegex(path.name, r"^074915-[0-9a-f]{12}\.jsonl$")

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([r["emit_type"] for r in rows], ["new", "update"])
        self.assertEqual({r["run_id"] for r in rows}, {path.stem.split("-", 1)[1]})
        self.assertTrue(all(r["emitted_at"] == "2026-09-26T07:49:15Z" and r["incident_key"] for r in rows))

    def test_no_temp_file_left_and_runs_do_not_collide(self):
        a = write_emits(self.dir, [("new", _inc("INC-a", "1.1.1.1"))], NOW)
        b = write_emits(self.dir, [("new", _inc("INC-b", "2.2.2.2"))], NOW)  # 같은 초에 두 번
        self.assertNotEqual(a, b)
        names = sorted(os.listdir(a.parent))
        self.assertEqual(names, sorted([a.name, b.name]))  # .tmp 없이 완성본 2개만


if __name__ == "__main__":
    unittest.main()
