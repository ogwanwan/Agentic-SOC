"""
pipeline/state.py — 주기 실행용 증분 상태 (이미 내보낸 Incident 추적)

주기 실행은 매번 최근 N분을 다시 분석하므로 같은 사건이 실행마다 또 나온다. incident_id 는
members 해시라 사건이 자라거나 로테이트로 raw_ref 파일명이 바뀌면 달라진다. 그래서 dedup 과 같은
기준인 (entity type, entity value, seed 사유 집합)으로 안정 키를 만들어 실행 간에 같은 사건을 알아본다.

  new    : 처음 보는 키
  update : 이미 내보낸 키인데 window 끝이 늦어졌거나(새 활동) 멤버 수가 최대치를 넘었다
  (생략)  : 변화 없음 — 다시 내보내지 않는다

창이 밀리면 오래된 멤버가 빠져 member_count 가 줄 수 있다. 그래서 멤버 수는 지금까지의 최대치와
비교하고, 새 활동 여부는 window 끝 시각으로 판단한다.
"""

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from common.timeparse import normalize_iso
from correlate.dedup import _signature

STATE_FILE = "state.json"
LOCK_FILE = "run.lock"
STATE_TTL = timedelta(hours=24)  # 이 시간 동안 안 보인 키는 상태에서 정리


def incident_key(inc):
    """실행 간 같은 사건을 알아보는 안정 키. entity value 가 없으면 incident_id 로 대신한다."""
    sig = _signature(inc)
    if sig is None:
        return "id:" + str(inc.get("incident_id"))
    ent_type, ent_value, reasons = sig
    text = "|".join([str(ent_type), str(ent_value), "\x1f".join(sorted(str(r) for r in reasons))])
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def _to_dt(iso):
    if not iso:
        return None
    try:
        return datetime.fromisoformat(normalize_iso(iso))
    except ValueError:
        return None


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def diff_incidents(incidents, state, now):
    """이번 실행의 Incident 중 내보낼 것을 고르고 갱신된 상태를 돌려준다.

    반환: (emits, new_state). emits 는 [(emit_type, incident), ...] (입력 순서 유지).
    state 는 load_state() 결과(dict)이며 제자리 수정하지 않는다.
    """
    seen = {k: dict(v) for k, v in (state.get("incidents") or {}).items()}
    now_iso = _iso(now)
    emits = []
    for inc in incidents:
        key = incident_key(inc)
        count = inc.get("member_count", len(inc.get("members", []) or []))
        window = inc.get("window") or [None, None]
        end_dt = _to_dt(window[1])
        prev = seen.get(key)

        if prev is None:
            emit_type = "new"
        else:
            prev_end = _to_dt(prev.get("window_end"))
            later = end_dt is not None and (prev_end is None or end_dt > prev_end)
            grew = count > prev.get("max_member_count", 0)
            emit_type = "update" if (later or grew) else None

        entry = prev or {"first_emitted": now_iso}
        entry["last_seen"] = now_iso
        if emit_type:
            entry["incident_id"] = inc.get("incident_id")
            entry["last_emitted"] = now_iso
            emits.append((emit_type, inc))
        entry["max_member_count"] = max(count, entry.get("max_member_count", 0))
        stored_end = _to_dt(entry.get("window_end"))
        if end_dt is not None and (stored_end is None or end_dt > stored_end):
            entry["window_end"] = window[1]
        seen[key] = entry

    cutoff = now - STATE_TTL
    kept = {k: v for k, v in seen.items() if (_to_dt(v.get("last_seen")) or now) >= cutoff}
    return emits, {"version": 1, "incidents": kept}


def load_state(state_dir):
    """state.json 을 읽는다. 없거나 깨졌으면 빈 상태(모든 사건이 new 로 다시 나감)."""
    path = os.path.join(state_dir, STATE_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        print("[state] 경고: %s 읽기 실패(%s) → 빈 상태로 시작" % (path, exc))
        return {}


def save_state(state_dir, state):
    """임시 파일에 쓰고 os.replace 로 바꿔치기(중간에 죽어도 기존 상태가 깨지지 않게)."""
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, STATE_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False)
    os.replace(tmp, path)


@contextmanager
def run_lock(state_dir):
    """같은 state_dir 로 동시에 두 번 돌지 않게 하는 비차단 잠금. 잠금을 얻으면 True 를 넘긴다.

    Linux 는 fcntl.flock(프로세스가 죽으면 커널이 자동 해제). fcntl 이 없는 Windows 는 잠금 없이
    통과한다(로컬 테스트용 — 운영은 systemd oneshot 이 한 번 더 겹침을 막는다).
    """
    os.makedirs(state_dir, exist_ok=True)
    try:
        import fcntl
    except ImportError:
        yield True
        return
    with open(os.path.join(state_dir, LOCK_FILE), "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
