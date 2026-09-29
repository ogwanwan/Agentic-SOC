"""tools/log_sources.py + normalize_all 로테이트·gz·창 필터 검증. 실행: python tests/test_log_sources.py"""
import gzip
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools.fetch_apache_log import fetch_apache_log
from tools.fetch_network_log import fetch_network_log
from tools.log_sources import log_name, resolve_log_files
from tools.normalize import normalize_all


def _sample_lines(name, n):
    with open(os.path.join(ROOT, "tools", name), encoding="utf-8") as fh:
        return [line for line in fh if line.strip()][:n]


class ResolveLogFilesTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for name in ("access.log", "access.log.1", "access.log.2.gz", "access.log.10.gz",
                     "access.log.bak", "other.log"):
            with open(os.path.join(self.dir, name), "w") as fh:
                fh.write("x\n")
        self.base = os.path.join(self.dir, "access.log")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_rotated_siblings_oldest_first(self):
        names = [os.path.basename(p) for p in resolve_log_files(self.base)]
        self.assertEqual(names, ["access.log.10.gz", "access.log.2.gz", "access.log.1", "access.log"])

    def test_mtime_filter_skips_old_rotations(self):
        old = time.time() - 3 * 86400
        for name in ("access.log.10.gz", "access.log.2.gz"):
            os.utime(os.path.join(self.dir, name), (old, old))
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        names = [os.path.basename(p) for p in resolve_log_files(self.base, since_dt=since)]
        self.assertEqual(names, ["access.log.1", "access.log"])

    def test_missing_base_returns_rotated_only(self):
        os.remove(self.base)
        self.assertEqual(os.path.basename(resolve_log_files(self.base)[-1]), "access.log.1")
        self.assertEqual(resolve_log_files(os.path.join(self.dir, "nope", "x.log")), [])

    def test_log_name_strips_gz(self):
        self.assertEqual(log_name("/var/log/apache2/access.log.2.gz"), "access.log.2")
        self.assertEqual(log_name("access.log"), "access.log")


class GzAndRotationReadTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def _write(self, name, lines, gz=False):
        path = os.path.join(self.dir, name)
        opener = gzip.open if gz else open
        with opener(path, "wt", encoding="utf-8", newline="") as fh:
            fh.writelines(lines)
        return path

    def test_apache_gz(self):
        lines = _sample_lines("sample_access.log", 3)
        events = fetch_apache_log(self._write("access.log.2.gz", lines, gz=True))
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e["raw_ref"].startswith("access.log.2:") for e in events))

    def test_network_gz(self):
        lines = _sample_lines("sample_eve.json", 50)
        plain = fetch_network_log(self._write("eve.json", lines))
        gz = fetch_network_log(self._write("eve.json.1.gz", lines, gz=True))
        self.assertGreater(len(plain), 0)
        self.assertEqual([e["timestamp"] for e in plain], [e["timestamp"] for e in gz])

    def test_normalize_reads_rotated_within_window(self):
        lines = _sample_lines("sample_access.log", 5)
        self._write("access.log.1", lines[:3])   # 로테이트 직전 기록
        base = self._write("access.log", lines[3:])
        ts = sorted(e["timestamp"] for e in fetch_apache_log(os.path.join(self.dir, "access.log.1")))
        window = [ts[0], "2099-01-01T00:00:00Z"]

        only_current = normalize_all(apache_path=base, auth_path="-", network_path="-", audit_path="-",
                                     time_window=window)
        with_rotated = normalize_all(apache_path=base, auth_path="-", network_path="-", audit_path="-",
                                     time_window=window, include_rotated=True)
        self.assertEqual(len(only_current), 2)
        self.assertEqual(len(with_rotated), 5)

        # 창 시작을 뒤로 밀면 앞 줄은 걸러진다(각 fetch 의 time_window 필터 재사용)
        narrowed = normalize_all(apache_path=base, auth_path="-", network_path="-", audit_path="-",
                                 time_window=[ts[1], window[1]], include_rotated=True)
        self.assertEqual(len(narrowed), 4)

    def test_unreadable_path_does_not_crash(self):
        # 디렉터리를 파일 경로로 넘김 → OSError(IsADirectory/Permission) 는 경고 후 0건
        events = normalize_all(apache_path=self.dir, auth_path="-", network_path="-", audit_path="-")
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
