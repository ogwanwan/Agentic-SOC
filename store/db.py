"""
store/db.py — incident 보관 DB(SQLite) 접속·스키마·state.json 이전

운영 모드의 "이미 본 사건" 기록(state.json)과 사건 저장을 SQLite 한 파일로 옮긴다. 표준 sqlite3 만 쓰므로
설치할 것이 없다. 조사 에이전트가 같은 파일을 동시에 읽을 수 있게 WAL 모드로 연다.

  incidents        : 사건당 1행(대기열). PK incident_key(pipeline/state.incident_key — 사건이 커져도 안 바뀜)
  incident_details : 사건 상세(1:1). layers·members·seeds·join_path + 나머지 필드는 extra_json

status 는 pending(미조사) → investigating(조사중) → done(완료). 시각은 "YYYY-MM-DDTHH:MM:SSZ" 문자열로
저장한다(형식이 같아 문자열 비교 = 시간 비교).
"""

import os
import sqlite3
from contextlib import contextmanager

from pipeline.state import STATE_FILE, load_state

DB_FILE = "soc.db"
SCHEMA_VERSION = 1

_SCHEMA_V1 = (
    """CREATE TABLE incidents (
        incident_key     TEXT PRIMARY KEY,
        incident_id      TEXT,
        entity_type      TEXT,
        entity_value     TEXT,
        window_start     TEXT,
        window_end       TEXT,
        member_count     INTEGER,
        triage_score     INTEGER,
        priority         TEXT,
        route            TEXT,
        llm_investigate  INTEGER,
        llm_reason       TEXT,
        status           TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'investigating', 'done')),
        has_update       INTEGER NOT NULL DEFAULT 0,
        claimed_at       TEXT,
        updated_at       TEXT,
        first_emitted    TEXT,
        last_emitted     TEXT,
        last_seen        TEXT,
        max_member_count INTEGER NOT NULL DEFAULT 0,
        state_window_end TEXT
    )""",
    "CREATE INDEX idx_incidents_queue ON incidents (status, route)",
    "CREATE INDEX idx_incidents_entity ON incidents (entity_type, entity_value)",
    "CREATE INDEX idx_incidents_last_seen ON incidents (last_seen)",
    """CREATE TABLE incident_details (
        incident_key TEXT PRIMARY KEY REFERENCES incidents (incident_key) ON DELETE CASCADE,
        layers       TEXT,
        members      TEXT,
        seeds        TEXT,
        join_path    TEXT,
        extra_json   TEXT,
        updated_at   TEXT
    )""",
)


def connect(path):
    """DB 를 연다(없으면 만든다). 트랜잭션은 transaction() 으로 직접 연다(isolation_level=None)."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    created = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")    # 파이프라인이 쓰는 동안에도 조사 쪽이 읽을 수 있게
    conn.execute("PRAGMA busy_timeout=5000")   # 잠겨 있으면 바로 실패하지 않고 5초까지 대기
    conn.execute("PRAGMA foreign_keys=ON")
    if created:
        try:
            os.chmod(path, 0o640)              # 사건에 IP·경로·명령어가 들어 있다
        except OSError:
            pass
    return conn


@contextmanager
def transaction(conn):
    """쓰기 트랜잭션. 시작할 때 쓰기 잠금을 잡아(BEGIN IMMEDIATE) 중간에 다른 쓰기와 엇갈리지 않는다."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def migrate(conn):
    """스키마를 최신 버전으로 만든다. 여러 번 불러도 안전하다(PRAGMA user_version 으로 버전 관리)."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError("DB 스키마 버전 %d 이 코드(%d)보다 새롭다 — 코드를 갱신할 것" % (version, SCHEMA_VERSION))
    if version < 1:
        with transaction(conn):
            for stmt in _SCHEMA_V1:
                conn.execute(stmt)
            conn.execute("PRAGMA user_version = 1")
    # 이후 버전이 생기면 여기에 `if version < 2:` 블록을 추가한다


def import_state_json(conn, state_dir):
    """state.json 이 남아 있으면 그 기록을 incidents 로 옮기고 state.json.migrated 로 이름을 바꾼다(한 번만).

    옮긴 행은 route 가 비어 있어 대기열에 들어가지 않는다 — 이미 파일로 보고된 사건이 한꺼번에 조사 대상으로
    쏟아지지 않게. 다음에 새 활동(update)이 생기면 그때 내용이 채워져 대기열에 들어간다.
    반환: 옮긴 행 수. state.json 이 없으면 None.
    """
    path = os.path.join(state_dir, STATE_FILE)
    if not os.path.exists(path):
        return None
    state = load_state(state_dir)   # 깨졌으면 {} (경고는 load_state 가 출력)
    rows = [
        (key, e.get("incident_id"), e.get("first_emitted"), e.get("last_emitted"), e.get("last_seen"),
         e.get("max_member_count", 0), e.get("window_end"), e.get("window_end"))
        for key, e in (state.get("incidents") or {}).items()
    ]
    with transaction(conn):
        conn.executemany(
            """INSERT OR IGNORE INTO incidents
               (incident_key, incident_id, first_emitted, last_emitted, last_seen,
                max_member_count, state_window_end, window_end)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
    os.replace(path, path + ".migrated")
    return len(rows)
