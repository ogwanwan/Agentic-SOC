"""
tools/log_sources.py — 로그 파일 찾기·열기 (로테이트·gz 대응)

logrotate 는 파일 이름을 뒤로 민다: access.log → access.log.1 → access.log.2.gz …
주기 실행(예: 5분마다 최근 60분)에서 현재 파일만 읽으면, 로테이트 직후에는 직전 기록이
access.log.1 로 넘어가 있어 창의 대부분을 놓친다. 여기서는 기준 경로와 같은 디렉터리의
로테이트 형제 파일을 찾아, 창 시작 이후에 수정된 파일만 오래된 것부터 돌려준다.

파싱·판단은 하지 않는다(각 fetch_*_log 의 일).
"""

import gzip
import os
import re
from datetime import datetime


def _rotation_number(name, base):
    """base 의 로테이트 형제면 번호(현재 파일=0), 아니면 None. access.log.2.gz → 2"""
    m = re.fullmatch(re.escape(base) + r"(?:\.(\d+))?(?:\.gz)?", name)
    if not m:
        return None
    return int(m.group(1)) if m.group(1) else 0


def resolve_log_files(base_path, since_dt=None):
    """base_path 와 그 로테이트 형제(base.1, base.N.gz) 중 읽을 파일을 오래된 순으로 반환.

    since_dt(aware datetime)가 있으면 mtime 이 그 이후인 파일만 남긴다 — 로테이트된 파일의
    mtime 은 마지막으로 기록된 시각이므로, 이보다 이전이면 창 안의 줄이 있을 수 없다.
    base_path 자체가 없으면(로테이트 직후 새 파일 생성 전 등) 형제만 반환한다.
    """
    directory = os.path.dirname(base_path) or "."
    base = os.path.basename(base_path)
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return []

    found = []
    for name in names:
        rot = _rotation_number(name, base)
        if rot is None:
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        if since_dt is not None:
            mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=since_dt.tzinfo)
            if mtime < since_dt:
                continue
        found.append((rot, path))

    found.sort(key=lambda t: -t[0])  # 번호 큰 것(오래된 것)부터
    return [path for _, path in found]


def open_log_text(path):
    """평문 또는 .gz 를 텍스트로 연다. newline="" 로 원본 줄 경계를 보존한다."""
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def log_name(path):
    """raw_ref 의 파일 부분. .gz 만 뗀다: access.log.2.gz → access.log.2"""
    name = os.path.basename(str(path))
    return name[:-3] if name.endswith(".gz") else name
