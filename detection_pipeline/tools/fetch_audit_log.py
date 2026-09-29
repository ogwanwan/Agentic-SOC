"""
tools/fetch_audit_log.py — system(audit) 계층 파서 + 도구 어댑터

raw auditd 로그 → 공통 스키마(system layer) 정규화. "가져오기 + 파싱"만 한다(판단·스코어링 없음).

- 한 이벤트 = 같은 msg=audit(epoch:serial) 을 가진 레코드 묶음(SYSCALL+EXECVE+CWD+PATH+PROCTITLE).
- ENRICHED 포맷(0x1D 뒤 SYSCALL=openat UID="www-data" ...)을 파싱해 이름 해석에 사용.
- EXECVE a<n>, PROCTITLE 의 hex 값을 디코드.
- 주의: str.splitlines() 는 0x1D 를 줄바꿈으로 취급하므로 절대 쓰지 말 것. 파일 반복(iter) 또는 split("\n") 만.
- audit 로그엔 IP가 없다 → src_ip 는 항상 None. 조인키는 pid/ppid.
- session_type 은 SYSCALL 레코드가 있을 때만 interactive / non_interactive 로 판정. 없으면 None(판정 불가).
- serial 은 재부팅 시 리셋되므로 전역 유니크가 아니다. 식별·중복제거 키는 (timestamp, serial) 또는 raw_ref.
- 따옴표로 감싼 값은 평문이다(auditd 는 hex 값에 따옴표를 안 붙임). EXECVE aN·PROCTITLE 모두 따옴표 없는 값만 hex 디코드.
- raw_ref 는 "<파일명>:<SYSCALL 줄번호>", 묶음 전체 줄번호는 layer_data.raw_lines.

도구 계약(다른 fetch_*_log 와 동일):
  fetch_audit_log(log_path, time_window=None, pid=None, ppid=None, key=None,
                  session_type=None, exclude_interactive=False) -> list[dict]
  + @register("fetch_audit_log") 래퍼가 success()/failure() 봉투로 반환.

출력 1건 예시:
{
  "timestamp": "2026-09-13T14:49:02.123Z", "layer": "system", "raw_ref": "audit.log:1201",
  "src_ip": null, "pid": 1301, "ppid": 1200,
  "layer_data": {"serial": 900001, "syscall": "execve", "key": "exec", "exe": "/usr/bin/dash",
                 "comm": "sh", "user": "www-data", "cwd": "/var/www/html",
                 "exec_args": "sh -c curl ...", "success": "yes", "uid": 33, "euid": 33,
                 "session_type": "non_interactive", ...}
}
"""
from __future__ import annotations

import json
import os
import re
import sys

# 스크립트로 직접 실행돼도 레포 루트를 path 에 올려 top-level 패키지(tools/common)를 찾게 한다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime, timezone
from typing import Iterable, Iterator

from common.timeparse import normalize_iso

MSG_RE = re.compile(r"msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")
TYPE_RE = re.compile(r"^type=(?P<type>[A-Z_]+)\s")
KV_RE = re.compile(r'(?P<k>[A-Za-z_][A-Za-z0-9_]*)=(?P<v>"(?:[^"\\]|\\.)*"|\S+)')
ENRICH_SEP = "\x1d"
UNSET = 4294967295
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

# b64(x86_64) 기준. ENRICHED 의 SYSCALL= 이 있으면 그쪽을 우선.
SYSCALL_NAMES_B64 = {
    59: "execve", 322: "execveat", 2: "open", 257: "openat", 1: "write", 85: "creat",
    82: "rename", 264: "renameat", 316: "renameat2", 87: "unlink", 263: "unlinkat",
    86: "link", 265: "linkat", 88: "symlink", 266: "symlinkat", 83: "mkdir", 258: "mkdirat",
    84: "rmdir", 90: "chmod", 91: "fchmod", 268: "fchmodat", 92: "chown", 93: "fchown",
    94: "lchown", 260: "fchownat", 76: "truncate", 77: "ftruncate", 133: "mknod", 259: "mknodat",
    188: "setxattr", 189: "lsetxattr", 190: "fsetxattr", 197: "removexattr", 198: "lremovexattr",
    199: "fremovexattr", 42: "connect", 41: "socket", 49: "bind", 44: "sendto",
}
UID_NAMES = {0: "root", 33: "www-data"}


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _hex_decode(v: str) -> str:
    """hex 인코딩(공백·특수문자 포함 값)을 문자열로. hex 가 아니면 그대로."""
    if HEX_RE.match(v) and len(v) % 2 == 0:
        try:
            return bytes.fromhex(v).decode("utf-8", errors="replace")
        except ValueError:
            return v
    return v


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_line(line: str) -> dict | None:
    """audit.log 한 줄 → {"type", "epoch", "serial", "fields", "enriched"}."""
    line = line.rstrip("\r\n")
    if not line:
        return None
    tm = TYPE_RE.match(line)
    mm = MSG_RE.search(line)
    if not tm or not mm:
        return None
    main, _, enriched = line.partition(ENRICH_SEP)
    raw = {m.group("k"): m.group("v") for m in KV_RE.finditer(main)}
    fields = {k: _unquote(v) for k, v in raw.items()}
    enr = {m.group("k"): _unquote(m.group("v")) for m in KV_RE.finditer(enriched)} if enriched else {}
    rtype = tm.group("type")
    if rtype == "EXECVE":
        for k in list(fields):
            # auditd 는 hex 값에 따옴표를 안 붙인다. "50" 같은 따옴표 평문은 그대로 두고 따옴표 없는 값만 디코드.
            if k[0] == "a" and k[1:].isdigit() and raw[k][:1] != '"':
                fields[k] = _hex_decode(fields[k])
    elif rtype == "PROCTITLE" and "proctitle" in fields and raw["proctitle"][:1] != '"':
        # 단일 인자 프로세스는 proctitle="dd" 처럼 따옴표 평문으로 온다 → hex 로 오인하지 않게 가드
        fields["proctitle"] = _hex_decode(fields["proctitle"]).replace("\x00", " ")
    return {"type": rtype, "epoch": mm.group("epoch"), "serial": int(mm.group("serial")),
            "fields": fields, "enriched": enr}


def _epoch_to_iso(epoch: str) -> str:
    ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _session_type(ses, tty) -> str:
    ses_unset = ses in (None, UNSET)
    tty_none = tty in (None, "(none)")
    return "non_interactive" if (ses_unset and tty_none) else "interactive"


def _assemble_event(serial: int, epoch: str, records: list[dict], line_nos: list[int], source: str) -> dict:
    """같은 serial 의 레코드 묶음 → §5.2 이벤트 1건."""
    by_type: dict[str, list[dict]] = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)

    sc = by_type.get("SYSCALL", [None])[0]
    f = sc["fields"] if sc else {}
    enr = sc["enriched"] if sc else {}
    # SYSCALL 이 없는 이벤트(USER_START, CRED_ACQ 등)도 pid/uid 는 있을 수 있음
    if not sc:
        for r in records:
            if "pid" in r["fields"]:
                f, enr = r["fields"], r["enriched"]
                break

    uid, euid, auid, ses = (_to_int(f.get(k)) for k in ("uid", "euid", "auid", "ses"))
    tty = f.get("tty")
    syscall_num = _to_int(f.get("syscall"))
    syscall = enr.get("SYSCALL")
    if syscall is None and syscall_num is not None:
        syscall = SYSCALL_NAMES_B64.get(syscall_num, str(syscall_num))

    argv: list[str] = []
    ex = by_type.get("EXECVE")
    if ex:
        ef = ex[0]["fields"]
        keys = sorted((k for k in ef if k[0] == "a" and k[1:].isdigit()), key=lambda k: int(k[1:]))
        argv = [ef[k] for k in keys]
    paths = [{"name": p["fields"].get("name"), "nametype": p["fields"].get("nametype"),
              "item": _to_int(p["fields"].get("item"))} for p in by_type.get("PATH", [])]
    # 대표 path: PARENT(디렉터리)가 아닌 항목 우선(CREATE/NORMAL/DELETE = 실제 대상 파일), 없으면 item 0
    ordered_paths = sorted((p for p in paths if p["name"]), key=lambda p: p["item"] or 0)
    primary_path = next((p["name"] for p in ordered_paths if p["nametype"] != "PARENT"),
                        ordered_paths[0]["name"] if ordered_paths else None)
    proctitle = by_type["PROCTITLE"][0]["fields"].get("proctitle") if "PROCTITLE" in by_type else None
    cwd = by_type["CWD"][0]["fields"].get("cwd") if "CWD" in by_type else None

    layer_data = {
        "serial": serial,
        "record_types": sorted(by_type),
        "syscall": syscall,
        "key": f.get("key") if f.get("key") not in (None, "(null)") else None,
        "exe": f.get("exe"),
        "comm": f.get("comm"),
        "user": enr.get("UID") or (UID_NAMES.get(uid) if uid is not None else None),
        "cwd": cwd,
        "exec_args": " ".join(argv) if argv else None,
        "argv": argv or None,
        "proctitle": proctitle,
        "path": primary_path,
        "paths": paths or None,
        "success": f.get("success"),
        "exit": _to_int(f.get("exit")),
        "uid": uid,
        "euid": euid,
        "auid": None if auid in (None, UNSET) else auid,
        "ses": None if ses in (None, UNSET) else ses,
        "tty": tty,
        # session_type 은 SYSCALL 레코드가 있을 때만 판정. AVC/BPF/절단 이벤트처럼 ses·tty 가 애초에 없는
        # 레코드는 "unset" 과 구분이 안 되므로 None(판정 불가)으로 통일한다.
        "session_type": _session_type(ses, tty) if sc else None,
        "arch": enr.get("ARCH") or f.get("arch"),
        "raw_lines": line_nos,
    }
    return {
        "timestamp": _epoch_to_iso(epoch),
        "layer": "system",
        "raw_ref": f"{source}:{line_nos[0]}",
        "src_ip": None,
        "pid": _to_int(f.get("pid")),
        "ppid": _to_int(f.get("ppid")),
        "layer_data": layer_data,
    }


def normalize_lines(lines: Iterable[str], source: str = "audit.log", window: int = 200) -> Iterator[dict]:
    """줄 스트림을 serial 단위로 조립해 이벤트를 순서대로 산출.

    레코드는 거의 항상 연속하지만 약간 섞일 수 있어, 최근 `window` 개 serial 만 보류하고
    그보다 오래된 serial 은 확정(flush)한다.
    """
    pending: dict[int, dict] = {}
    order: list[int] = []
    for line_no, line in enumerate(lines, start=1):
        rec = parse_line(line)
        if rec is None:
            continue
        s = rec["serial"]
        if s not in pending:
            pending[s] = {"epoch": rec["epoch"], "records": [], "lines": []}
            order.append(s)
        pending[s]["records"].append(rec)
        pending[s]["lines"].append(line_no)
        while len(order) > window:
            old = order.pop(0)
            p = pending.pop(old)
            yield _assemble_event(old, p["epoch"], p["records"], p["lines"], source)
    for s in order:
        p = pending[s]
        yield _assemble_event(s, p["epoch"], p["records"], p["lines"], source)


def normalize_file(path: str, source: str | None = None) -> Iterator[dict]:
    """평문 또는 .gz 파일. raw_ref 의 파일명은 basename(.gz 제거)."""
    import gzip
    src = source or path.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".gz")
    # newline="" : \r\n 을 그대로 두고(우리가 rstrip), 0x1D 는 줄 경계로 취급되지 않음
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        yield from normalize_lines(fh, source=src)


# ── 도구 계약: 순수 함수 + 필터 ─────────────────────────────────────────────
def _iso_to_dt(iso: str) -> datetime:
    t = datetime.fromisoformat(normalize_iso(str(iso)))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _parse_window(time_window):
    if not time_window:
        return None, None
    try:
        start, end = time_window
        return _iso_to_dt(start), _iso_to_dt(end)
    except (TypeError, ValueError) as exc:
        raise ValueError("time_window 는 [start_iso, end_iso] 형식이어야 함: %r (%s)" % (time_window, exc)) from None


def fetch_audit_log(log_path: str, time_window=None, pid=None, ppid=None, key=None,
                    session_type=None, exclude_interactive=False) -> list[dict]:
    """raw audit.log(.gz 가능) → 공통 스키마 system 이벤트 리스트(시간·serial 순).

    time_window        : [start_iso, end_iso] 경계 포함. tz 없으면 UTC 로 간주
    pid / ppid         : 정확일치
    key                : auditd 룰 키(exec|webroot|sensitive|cloud_creds) 정확일치
    session_type       : interactive|non_interactive 정확일치
    exclude_interactive: True 면 non_interactive 만 남긴다. interactive(관리자 세션)뿐 아니라
                         session_type=None(SYSCALL 없는 AVC/BPF/절단 이벤트, 판정 불가)도 제외

    주의 — serial 은 전역 유니크가 아니다. auditd 재부팅 시 리셋된다(실파일에서 498738→75 확인).
    이벤트 식별·중복제거·조인 키로는 serial 단독이 아니라 (timestamp, serial) 또는 raw_ref 를 써야 한다.
    """
    start, end = _parse_window(time_window)

    def _ok(e: dict) -> bool:
        ld = e["layer_data"]
        if time_window:
            t = _iso_to_dt(e["timestamp"])
            if (start and t < start) or (end and t > end):
                return False
        if pid is not None and e.get("pid") != pid:
            return False
        if ppid is not None and e.get("ppid") != ppid:
            return False
        if key is not None and ld.get("key") != key:
            return False
        if session_type is not None and ld.get("session_type") != session_type:
            return False
        if exclude_interactive and ld.get("session_type") != "non_interactive":
            return False
        return True

    events = [e for e in normalize_file(log_path) if _ok(e)]
    events.sort(key=lambda e: (e["timestamp"], e["layer_data"]["serial"]))
    return events


try:  # tools 패키지 없이 단독 실행할 땐 등록을 건너뛴다.
    from tools.base import success, failure
    from tools.registry import register

    @register(
        name="fetch_audit_log",
        description=(
            "raw auditd audit.log 를 읽어 조건에 맞는 시스템(system) 이벤트를 공통스키마로 반환한다. "
            "audit 엔 IP가 없어 src_ip 는 None, 조인키는 pid/ppid. "
            "필터: time_window/pid/ppid/key/session_type/exclude_interactive. 조회 전용."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "log_path": {"type": "string", "description": "audit.log 경로(.gz 가능). 생략 시 .env AUDIT_LOG_PATH."},
                "time_window": {"type": "array", "items": {"type": "string"},
                                "description": "[start_iso, end_iso] UTC(경계 포함)."},
                "pid": {"type": "integer"},
                "ppid": {"type": "integer"},
                "key": {"type": "string", "enum": ["exec", "webroot", "sensitive", "cloud_creds"]},
                "session_type": {"type": "string", "enum": ["interactive", "non_interactive"]},
                "exclude_interactive": {"type": "boolean",
                                        "description": "True면 session_type=interactive(관리자 노이즈) 제외."},
            },
            "required": [],
        },
    )
    def fetch_audit_log_tool(log_path: str = None, **filters) -> dict:
        path = log_path or os.getenv("AUDIT_LOG_PATH", "/var/log/audit/audit.log")
        try:
            events = fetch_audit_log(path, **filters)
        except FileNotFoundError:
            return failure("audit 로그 없음: %s" % path)
        except ValueError as exc:            # 잘못된 필터 인자(time_window 형식 등) — 파싱 실패와 구분
            return failure("잘못된 인자: %s" % exc)
        except Exception as exc:
            return failure("audit 파싱 실패: %s" % exc)
        return success({"count": len(events), "events": events})
except Exception:  # pragma: no cover
    pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python tools/fetch_audit_log.py <audit.log> [> normalized.jsonl]")
    for ev in fetch_audit_log(sys.argv[1]):
        sys.stdout.write(json.dumps(ev, ensure_ascii=False) + "\n")
