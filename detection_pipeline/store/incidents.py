"""
store/incidents.py — 파이프라인이 사건을 DB 에 쓰고, 대기열·상세를 읽는 함수

중복 판단(new/update)은 pipeline/state.diff_incidents 를 그대로 쓴다. DB 에서 state.json 과 같은 모양의
dict 를 만들어 넘기고(load_state_view), 결과를 한 트랜잭션으로 저장한다(record_run).

상태 규칙 (new/update 로 내보낼 사건에만 적용 — 변화 없는 사건은 status 를 건드리지 않는다):
  행 없음        → 추가, pending
  done          → pending 으로 재오픈 (새 활동이 생겼으니 다시 조사)
  investigating → 상태 유지, has_update=1 (조사를 끝낼 때 이 표시를 보고 다시 pending 으로)
  pending       → 그대로
사건 내용은 합치지 않고 최신 스냅샷으로 덮어쓴다. 5분마다 60분을 다시 분석하므로 합치면 seed·멤버가 중복된다.
"""

import json

from pipeline.state import STATE_TTL, incident_key
from store.db import transaction

# 조사 대기열 — "조사 대상이고, LLM 이 오탐이라 하지 않았고(못 본 것 포함), 아직 미조사"를 점수 높은 순으로.
# llm_investigate 가 NULL(LLM 이 못 봄)이면 1 로 취급해 빠뜨리지 않는다(fail-open).
# 트리아지 필드(LLM 우선순위 등)가 바뀌면 이 두 줄만 고친다.
QUEUE_WHERE = "route = 'investigate' AND COALESCE(llm_investigate, 1) = 1 AND status = 'pending'"
QUEUE_ORDER = "triage_score DESC, updated_at ASC, incident_key ASC"

STATUS_LABELS = {"pending": "미조사", "investigating": "조사중", "done": "완료"}

# incidents / incident_details 컬럼에 들어가는 사건 필드. 나머지(oversized, triage_parts 등)는 extra_json 으로.
_QUEUE_FIELDS = {"incident_id", "entity", "window", "member_count", "triage_score", "priority", "route",
                 "llm_investigate", "llm_reason"}
_DETAIL_FIELDS = ("layers", "members", "seeds", "join_path")


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(value):
    return json.dumps(value, ensure_ascii=False)


def _bool_int(value):
    return None if value is None else int(bool(value))


def load_state_view(conn, now):
    """최근 STATE_TTL(24시간) 안에 본 사건으로 state.json 과 같은 모양의 dict 를 만든다(diff_incidents 입력).

    그보다 오래 안 보인 행은 지우지 않고 남기되 여기서 빼서, 다시 나타나면 new 로 판단되게 한다(기존 동작과 같음).
    """
    cutoff = _iso(now - STATE_TTL)
    rows = conn.execute(
        """SELECT incident_key, incident_id, first_emitted, last_emitted, last_seen,
                  max_member_count, state_window_end
           FROM incidents WHERE last_seen >= ?""",
        (cutoff,),
    )
    incidents = {}
    for r in rows:
        entry = {
            "first_emitted": r["first_emitted"],
            "last_seen": r["last_seen"],
            "incident_id": r["incident_id"],
            "last_emitted": r["last_emitted"],
            "max_member_count": r["max_member_count"],
            "window_end": r["state_window_end"],
        }
        incidents[r["incident_key"]] = {k: v for k, v in entry.items() if v is not None}
    return {"version": 1, "incidents": incidents}


def record_run(conn, emits, new_state, now):
    """diff_incidents 결과를 한 트랜잭션으로 저장한다.

    emits    : [(emit_type, incident)] — 내보낼 사건. 큐 행 upsert(상태 규칙 적용) + 상세 덮어쓰기
    new_state: diff_incidents 가 돌려준 상태 — 이번 실행에서 본 사건의 last_seen 등 갱신(state.json 저장 대체)
    반환: {"new": n, "update": n, "reopened": n, "flagged": n}
    """
    now_iso = _iso(now)
    entries = new_state.get("incidents") or {}
    stats = {"new": 0, "update": 0, "reopened": 0, "flagged": 0}
    emitted = set()
    with transaction(conn):
        for kind, inc in emits:
            key = incident_key(inc)
            emitted.add(key)
            stats[kind] = stats.get(kind, 0) + 1
            prev = conn.execute("SELECT status FROM incidents WHERE incident_key = ?", (key,)).fetchone()
            if prev is not None and prev["status"] == "done":
                stats["reopened"] += 1
            elif prev is not None and prev["status"] == "investigating":
                stats["flagged"] += 1
            _upsert_incident(conn, key, inc, entries.get(key) or {}, now_iso)
            _upsert_details(conn, key, inc, now_iso)
        # 변화 없는 사건: 이번 실행에서 본 것만 추적 필드 갱신(status 는 건드리지 않음)
        for key, e in entries.items():
            if key in emitted or e.get("last_seen") != now_iso:
                continue
            conn.execute(
                """UPDATE incidents SET last_seen = ?, max_member_count = ?, state_window_end = ?
                   WHERE incident_key = ?""",
                (e.get("last_seen"), e.get("max_member_count", 0), e.get("window_end"), key),
            )
    return stats


def _upsert_incident(conn, key, inc, entry, now_iso):
    entity = inc.get("entity") or {}
    window = inc.get("window") or [None, None]
    conn.execute(
        """INSERT INTO incidents
           (incident_key, incident_id, entity_type, entity_value, window_start, window_end, member_count,
            triage_score, priority, route, llm_investigate, llm_reason, status, has_update, updated_at,
            first_emitted, last_emitted, last_seen, max_member_count, state_window_end)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (incident_key) DO UPDATE SET
             incident_id = excluded.incident_id,
             entity_type = excluded.entity_type,
             entity_value = excluded.entity_value,
             window_start = excluded.window_start,
             window_end = excluded.window_end,
             member_count = excluded.member_count,
             triage_score = excluded.triage_score,
             priority = excluded.priority,
             route = excluded.route,
             llm_investigate = excluded.llm_investigate,
             llm_reason = excluded.llm_reason,
             status = CASE WHEN status = 'done' THEN 'pending' ELSE status END,
             has_update = CASE WHEN status = 'investigating' THEN 1 ELSE has_update END,
             claimed_at = CASE WHEN status = 'done' THEN NULL ELSE claimed_at END,
             updated_at = excluded.updated_at,
             first_emitted = COALESCE(first_emitted, excluded.first_emitted),
             last_emitted = excluded.last_emitted,
             last_seen = excluded.last_seen,
             max_member_count = excluded.max_member_count,
             state_window_end = excluded.state_window_end""",
        (key, inc.get("incident_id"), entity.get("type"),
         None if entity.get("value") is None else str(entity.get("value")),
         window[0], window[1], inc.get("member_count", len(inc.get("members") or [])),
         inc.get("triage_score"), inc.get("priority"), inc.get("route"),
         _bool_int(inc.get("llm_investigate")), inc.get("llm_reason"), now_iso,
         entry.get("first_emitted", now_iso), entry.get("last_emitted", now_iso), entry.get("last_seen", now_iso),
         entry.get("max_member_count", 0), entry.get("window_end", window[1])),
    )


def _upsert_details(conn, key, inc, now_iso):
    extra = {k: v for k, v in inc.items() if k not in _QUEUE_FIELDS and k not in _DETAIL_FIELDS}
    values = [_json(inc.get(f)) for f in _DETAIL_FIELDS]
    conn.execute(
        """INSERT INTO incident_details
           (incident_key, layers, members, seeds, join_path, extra_json, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (incident_key) DO UPDATE SET
             layers = excluded.layers, members = excluded.members, seeds = excluded.seeds,
             join_path = excluded.join_path, extra_json = excluded.extra_json, updated_at = excluded.updated_at""",
        (key, *values, _json(extra), now_iso),
    )


# --- 읽기 (socdb.py·조사 쪽) --------------------------------------------------

def list_queue(conn, limit=20):
    """조사 대기열 — 지금 조사해야 할 사건을 급한 순서대로."""
    rows = conn.execute(
        "SELECT * FROM incidents WHERE %s ORDER BY %s LIMIT ?" % (QUEUE_WHERE, QUEUE_ORDER), (limit,)
    )
    return [dict(r) for r in rows]


def get_incident(conn, key):
    """큐 행 + 상세. 상세의 JSON 컬럼은 풀어서 돌려준다. 없으면 None."""
    row = conn.execute("SELECT * FROM incidents WHERE incident_key = ?", (key,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    detail = conn.execute("SELECT * FROM incident_details WHERE incident_key = ?", (key,)).fetchone()
    if detail is not None:
        for field in _DETAIL_FIELDS:
            result[field] = json.loads(detail[field]) if detail[field] is not None else None
        result["extra"] = json.loads(detail["extra_json"]) if detail["extra_json"] else {}
    return result


def stats(conn):
    """상태·우선순위·경로별 사건 수와 대기열 길이."""
    def count_by(column):
        rows = conn.execute("SELECT %s AS k, COUNT(*) AS n FROM incidents GROUP BY %s ORDER BY %s"
                            % (column, column, column))
        return {r["k"]: r["n"] for r in rows}

    return {
        "total": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "queue": conn.execute("SELECT COUNT(*) FROM incidents WHERE %s" % QUEUE_WHERE).fetchone()[0],
        "status": count_by("status"),
        "priority": count_by("priority"),
        "route": count_by("route"),
    }


# --- 조사 큐 소비 (조사 폴러가 씀) -------------------------------------------
# 상태 전이: pending --claim--> investigating --finish--> done
#                                    └ release/stale ──> pending(재시도)
# "SQL 은 store/ 에만" 규칙에 따라 소비자 쪽 쓰기도 여기 둔다.

def claim_incident(conn, key, now_iso):
    """pending 사건을 investigating 으로 선점한다. 성공하면 True.

    이미 다른 폴러가 집었거나 상태가 바뀌었으면 한 행도 안 바뀌어 False(중복 조사 방지)."""
    with transaction(conn):
        cur = conn.execute(
            "UPDATE incidents SET status = 'investigating', claimed_at = ? "
            "WHERE incident_key = ? AND status = 'pending'",
            (now_iso, key),
        )
    return cur.rowcount == 1


def finish_incident(conn, key):
    """조사 완료. 조사 중 새 활동이 붙었으면(has_update) done 대신 pending 으로 재오픈한다."""
    with transaction(conn):
        conn.execute(
            "UPDATE incidents SET "
            "status = CASE WHEN has_update = 1 THEN 'pending' ELSE 'done' END, "
            "has_update = 0, claimed_at = NULL "
            "WHERE incident_key = ? AND status = 'investigating'",
            (key,),
        )


def release_incident(conn, key):
    """조사 실패·미완료 → pending 으로 되돌려 다음 틱에 다시 조사(누락보다 중복)."""
    with transaction(conn):
        conn.execute(
            "UPDATE incidents SET status = 'pending', claimed_at = NULL "
            "WHERE incident_key = ? AND status = 'investigating'",
            (key,),
        )


def reclaim_stale(conn, cutoff_iso):
    """investigating 에 낀 채 오래된(폴러가 도중에 죽음) 사건을 pending 으로 회수. 회수 건수 반환."""
    with transaction(conn):
        cur = conn.execute(
            "UPDATE incidents SET status = 'pending', claimed_at = NULL "
            "WHERE status = 'investigating' AND (claimed_at IS NULL OR claimed_at < ?)",
            (cutoff_iso,),
        )
    return cur.rowcount
