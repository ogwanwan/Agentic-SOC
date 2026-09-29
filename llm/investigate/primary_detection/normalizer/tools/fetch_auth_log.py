"""
auth_parser.py — raw auth.log → 공통 스키마 이벤트 (layer=auth, JSON Lines)

  parse_line()   한 줄 → 헤더(시각·호스트·프로그램·pid) + 본문. message repeated 풀기
  classify()     프로그램별 본문 패턴 → event 종류 + 필드
  build_event()  공통 스키마 dict 1개 (layer_data 28키 고정, 없으면 null)
  parse_files()  파일·gz·디렉터리 → 이벤트 스트림 (1줄 = 1이벤트)

하지 않는 것: 수상한지 판단(룰의 일), 같은 sshd pid 의 줄을 연결 단위로 묶기·IP 보충(사건 묶기의 일).

사용:
  python3 auth_parser.py /var/log/auth.log* --year 2026 -o events.jsonl --stats
  python3 auth_parser.py ~/logs/auth/dt=2026-09-14/ -o events.jsonl      # 경로의 dt= 로 연도 자동
의존성: Python 3.9+ 표준 라이브러리만
"""
from __future__ import annotations

import gzip
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

LAYER_DATA_KEYS = (
    "host", "program", "event", "result",
    "user", "src_user", "uid", "src_uid", "gid",
    "tty", "session_type", "pwd", "command",
    "method", "invalid_user", "key_type", "key_fp", "rport",
    "pam_service", "reason", "group", "shell", "home",
    "changed_attr", "old_value", "new_value",
    "repeat_count", "message",
)

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

RE_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
RE_RFC = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
RE_REPEAT = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<inner>.*)\]$")
RE_DT = re.compile(r"dt=(\d{4})-(\d\d)-(\d\d)")


# ================================================================ 값 정리
def clean_ip(v):
    if not v:
        return None
    v = v.strip("[]")
    if v.lower().startswith("::ffff:"):
        v = v[7:]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _session_type(tty):
    """tty 가 기록된 줄에서만 계산. pts/N·ttyN → interactive, unknown/none/빈값 → non_interactive"""
    if tty is None:
        return None
    t = tty.replace("/dev/", "")
    return "interactive" if re.match(r"^(pts/\d+|tty\w*)$", t) else "non_interactive"


def _kv(body: str) -> dict:
    """PAM 'logname= uid=33 euid=0 tty= ruser=www-data rhost=  user=root' → dict (빈값은 None)"""
    out = {}
    for m in re.finditer(r"(\w+)=(\S*)", body):
        out[m.group(1)] = m.group(2) or None
    return out


# ================================================================ sshd
SSHD_PATTERNS = [
    ("ssh_accepted", "success", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?"
        r"(?:: (?P<key_type>\S+) (?P<key_fp>\S+))?$")),
    ("ssh_failed", "failure", re.compile(
        r"^Failed (?P<method>\S+) for (?P<inv>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
        r"(?: ssh2)?(?:: .*)?$")),
    ("ssh_invalid_user", "failure", re.compile(
        r"^Invalid user (?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)$")),
    # 인증 단계에서 끝난 연결의 마지막 줄 (키 전용 서버에서도 연결당 1줄)
    ("ssh_auth_fail_close", "failure", re.compile(
        r"^(?:Connection closed by|Disconnected from) (?P<kind>invalid|authenticating) user (?P<user>.*?) "
        r"(?P<ip>\S+) port (?P<port>\d+) \[preauth\]$")),
    ("ssh_auth_fail_close", "failure", re.compile(
        r"^Disconnecting (?P<kind>invalid|authenticating) user (?P<user>.*?) (?P<ip>\S+) port (?P<port>\d+): "
        r"(?P<reason>.*?)(?: \[preauth\])?$")),
    ("ssh_max_auth", "failure", re.compile(
        r"^error: maximum authentication attempts exceeded for (?P<inv>invalid user )?(?P<user>.*?) "
        r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?: \[preauth\])?$")),
    # 계정 없이 끊긴 연결 = 스캐너 탐침
    ("ssh_probe", "failure", re.compile(
        r"^(?:Connection closed by|Disconnected from|Connection reset by) (?P<ip>[0-9A-Fa-f:.]+) "
        r"port (?P<port>\d+)(?: \[preauth\])?$")),
    ("ssh_probe", "failure", re.compile(
        r"^banner exchange: Connection from (?P<ip>\S+) port (?P<port>\d+):.*$")),
    ("ssh_probe", "failure", re.compile(
        r"^(?:error: )?(?:kex_exchange_identification|kex_protocol_error|banner exchange)\b.*$")),
    ("ssh_probe", "failure", re.compile(
        r"^(?:Did not receive identification string from (?P<ip>\S+)(?: port (?P<port>\d+))?"
        r"|Unable to negotiate with (?P<ip2>\S+) port (?P<port2>\d+).*)$")),
    ("ssh_disconnect", "info", re.compile(
        r"^Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)$")),
    ("ssh_disconnect", "info", re.compile(
        r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+):\d+: (?P<reason>.*?)(?: \[preauth\])?$")),
    ("ssh_keys_command", "info", re.compile(
        r"^AuthorizedKeysCommand (?P<command>.*) failed, status (?P<reason>\d+)$")),
    ("sshd_service", "info", re.compile(
        r"^(?:Server listening on .*|Received signal \d+; terminating\.|Received SIGHUP; restarting\.)$")),
]


def classify_sshd(msg: str) -> dict:
    for event, result, rx in SSHD_PATTERNS:
        m = rx.match(msg)
        if not m:
            continue
        g = {k: v for k, v in m.groupdict().items() if v is not None}
        out = {"event": event, "result": result}
        if "user" in g:
            out["user"] = g["user"] or None
        ip = g.get("ip") or g.get("ip2")
        port = g.get("port") or g.get("port2")
        out["_src_ip"] = clean_ip(ip)
        out["rport"] = _int(port)
        for k in ("method", "key_type", "key_fp", "reason", "command"):
            if k in g:
                out[k] = g[k]
        if "kind" in g:
            out["invalid_user"] = g["kind"] == "invalid"
        elif event in ("ssh_failed", "ssh_max_auth"):
            out["invalid_user"] = "inv" in g
        elif event == "ssh_invalid_user":
            out["invalid_user"] = True
        elif event == "ssh_accepted":
            out["invalid_user"] = False
        return out
    return {"event": "ssh_other", "result": "info"}


# ================================================================ PAM
RE_PAM = re.compile(r"^(?P<mod>pam_\w+)\((?P<svc>[^:)]+):(?P<type>\w+)\): (?P<body>.*)$")
RE_PAM_MORE = re.compile(r"^PAM (?P<n>\d+) more authentication failures?; (?P<body>.*)$")
RE_USER_UID = re.compile(r"^(?P<name>[^\s(]*)(?:\(uid=(?P<uid>\d+)\))?$")


def classify_pam(msg: str) -> dict | None:
    m = RE_PAM_MORE.match(msg)
    if m:
        kv = _kv(m.group("body"))
        return {"event": "pam_auth_failure", "result": "failure", "repeat_count": int(m.group("n")),
                "user": kv.get("user"), "src_user": kv.get("ruser") or kv.get("logname"),
                "src_uid": _int(kv.get("uid")), "_src_ip": clean_ip(kv.get("rhost"))}
    m = RE_PAM.match(msg)
    if not m:
        return None
    svc, body = m.group("svc"), m.group("body")
    out = {"pam_service": svc}
    if body.startswith("authentication failure;"):
        kv = _kv(body)
        tty = kv.get("tty")
        out.update(event="pam_auth_failure", result="failure", user=kv.get("user"),
                   src_user=kv.get("ruser") or kv.get("logname"), src_uid=_int(kv.get("uid")),
                   tty=tty if tty is not None else "", _src_ip=clean_ip(kv.get("rhost")))
        return out
    mm = re.match(r"^auth could not identify password for \[(?P<user>[^\]]+)\]$", body)
    if mm:
        out.update(event="pam_auth_failure", result="failure", user=mm.group("user"),
                   reason="could not identify password")
        if svc == "sudo":
            out["src_user"] = mm.group("user")
        return out
    mm = re.match(r"^session opened for user (?P<user>\S+) by (?P<by>\S*)$", body)
    if mm:
        u = RE_USER_UID.match(mm.group("user"))
        b = RE_USER_UID.match(mm.group("by")) if mm.group("by") else None
        out.update(event="pam_session_opened", result="success",
                   user=u.group("name") or None, uid=_int(u.group("uid")))
        if b:
            out.update(src_user=b.group("name") or None, src_uid=_int(b.group("uid")))
        return out
    mm = re.match(r"^session closed for user (?P<user>\S+)$", body)
    if mm:
        out.update(event="pam_session_closed", result="info", user=mm.group("user"))
        return out
    mm = re.match(r"^password changed for (?P<user>\S+)$", body)
    if mm:
        out.update(event="password_changed", result="success", user=mm.group("user"))
        return out
    out.update(event="pam_other", result="info")
    return out


# ================================================================ sudo / su / pkexec
def classify_sudo(msg: str) -> dict:
    m = re.match(r"^\s*(?P<actor>\S+) : (?P<rest>.*)$", msg)
    if not m or not re.search(r"(?:^| ; )(?:TTY|PWD|USER|COMMAND)=", m.group("rest")):
        return {"event": "sudo_other", "result": "info"}
    rest = m.group("rest")
    command = None
    ci = rest.find("COMMAND=")
    if ci >= 0:
        command = rest[ci + len("COMMAND="):]
        rest = rest[:ci].rstrip(" ;")
    parts = [p.strip() for p in rest.split(" ; ") if p.strip()]
    kv, reasons = {}, []
    for p in parts:
        km = re.match(r"^(TTY|PWD|USER|GROUP|ENV|TSID)=(.*)$", p)
        if km:
            kv[km.group(1)] = km.group(2)
        else:
            reasons.append(p)
    reason = " ; ".join(reasons) or None
    return {"event": "sudo_denied" if reason else "sudo_command",
            "result": "failure" if reason else "success",
            "src_user": m.group("actor"), "user": kv.get("USER"), "tty": kv.get("TTY"),
            "pwd": kv.get("PWD"), "command": command, "reason": reason}


SU_PATTERNS = [
    ("su_success", "success", re.compile(r"^\\(to (?P<user>\S+)\\) (?P<actor>\S+) on (?P<tty>\S+)$")),
    ("su_failure", "failure", re.compile(r"^FAILED SU \\(to (?P<user>\S+)\\) (?P<actor>\S+) on (?P<tty>\S+)$")),
    ("su_success", "success", re.compile(r"^Successful su for (?P<user>\S+) by (?P<actor>\S+)$")),
    ("su_failure", "failure", re.compile(r"^FAILED su for (?P<user>\S+) by (?P<actor>\S+)$")),
    ("su_success", "success", re.compile(r"^\\+ (?P<tty>\S+) (?P<actor>[^:\s]+):(?P<user>\S+)$")),
    ("su_failure", "failure", re.compile(r"^- (?P<tty>\S+) (?P<actor>[^:\s]+):(?P<user>\S+)$")),
]


def classify_su(msg: str) -> dict:
    for event, result, rx in SU_PATTERNS:
        m = rx.match(msg)
        if m:
            g = m.groupdict()
            return {"event": event, "result": result, "user": g["user"],
                    "src_user": g["actor"], "tty": g.get("tty")}
    return {"event": "su_other", "result": "info"}


RE_PKEXEC = re.compile(
    r"^(?P<actor>\S+): (?:(?P<ok>Executing command)|Error executing command as another user: (?P<reason>.*?)) "
    r"\[USER=(?P<user>[^\]]*)\] \[TTY=(?P<tty>[^\]]*)\] \[CWD=(?P<pwd>[^\]]*)\] \[COMMAND=(?P<command>.*)\]$")


def classify_pkexec(msg: str) -> dict:
    m = RE_PKEXEC.match(msg)
    if not m:
        return {"event": "pkexec_other", "result": "info"}
    ok = m.group("ok") is not None
    return {"event": "pkexec_command" if ok else "pkexec_denied", "result": "success" if ok else "failure",
            "src_user": m.group("actor"), "user": m.group("user"), "tty": m.group("tty"),
            "pwd": m.group("pwd"), "command": m.group("command"), "reason": m.group("reason")}


# ================================================================ 계정 관리 (shadow-utils)
ACCOUNT_PROGRAMS = {"useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "gpasswd",
                    "passwd", "chpasswd", "chsh", "chfn", "chage", "adduser", "deluser", "newusers"}

ACCOUNT_PATTERNS = [
    ("user_created", "success", re.compile(
        r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]*), "
        r"shell=(?P<shell>[^,]*)(?:, from=.*)?$")),
    ("group_created", "success", re.compile(r"^new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)$")),
    ("group_member_added", "success", re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'$")),
    ("gshadow_member_added", "success", re.compile(r"^add '(?P<user>[^']+)' to shadow group '(?P<group>[^']+)'$")),
    ("group_member_added", "success", re.compile(
        r"^user (?P<user>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)$")),
    ("group_member_removed", "success", re.compile(
        r"^delete '(?P<user>[^']+)' from (?:shadow )?group '(?P<group>[^']+)'$")),
    ("user_modified", "success", re.compile(
        r"^change user '(?P<user>[^']+)' (?P<attr>\S+) from '(?P<old>[^']*)' to '(?P<new>[^']*)'$")),
    ("user_modified", "success", re.compile(
        r"^changed user '(?P<user>[^']+)' (?P<attr>shell) to '(?P<new>[^']*)'$")),
    ("password_changed", "success", re.compile(r"^change user '(?P<user>[^']+)' password$")),
    ("password_changed", "success", re.compile(
        r"^password for '(?P<user>[^']+)' changed by '(?P<actor>[^']+)'$")),
    ("user_deleted", "success", re.compile(r"^delete user '(?P<user>[^']+)'$")),
    ("group_deleted", "success", re.compile(r"^(?:removed group|group) '(?P<group>[^']+)'(?: removed.*)?$")),
]


def classify_account(msg: str) -> dict:
    for event, result, rx in ACCOUNT_PATTERNS:
        m = rx.match(msg)
        if not m:
            continue
        g = m.groupdict()
        out = {"event": event, "result": result, "user": g.get("user"), "group": g.get("group"),
               "src_user": g.get("actor"), "uid": _int(g.get("uid")), "gid": _int(g.get("gid")),
               "home": g.get("home"), "shell": g.get("shell")}
        if event == "user_modified":
            attr = g["attr"]
            out.update(changed_attr=attr, old_value=g.get("old"), new_value=g["new"])
            if attr == "UID":
                out["uid"] = _int(g["new"])
            elif attr == "GID":
                out["gid"] = _int(g["new"])
            elif attr == "shell":
                out["shell"] = g["new"]
            elif attr == "home":
                out["home"] = g["new"]
        return out
    return {"event": "account_other", "result": "info"}


# ================================================================ systemd-logind
def classify_logind(msg: str) -> dict:
    m = re.match(r"^New session (?P<sid>\S+) of user (?P<user>[^\s.]+)\.$", msg)
    if m:
        return {"event": "session_new", "result": "info", "user": m.group("user"), "reason": f"session {m.group('sid')}"}
    m = re.match(r"^Removed session (?P<sid>[^\s.]+)\.$", msg)
    if m:
        return {"event": "session_removed", "result": "info", "reason": f"session {m.group('sid')}"}
    return {"event": "logind_other", "result": "info"}


# ================================================================ 한 줄
def _parse_ts_bsd(g, year, tz):
    mon = MONTHS.get(g["mon"])
    if not mon:
        return None
    hh, mm, ss = map(int, g["time"].split(":"))
    dt = datetime(year, mon, int(g["day"]), hh, mm, ss, tzinfo=tz)
    return dt.astimezone(timezone.utc)


def _year_for(month: int, hint):
    """연도 없는 BSD 헤더의 연도 결정.
    ("dt", y, m): S3 파티션 dt=YYYY-MM-DD 기준. 12월 줄이 1월 파티션에 있으면 전년도, 반대면 다음 해
    ("fixed", y): --year 로 지정
    ("now", y, m): 둘 다 없으면 오늘 기준. 이번 달보다 뒤의 달이면 작년 로그로 본다"""
    kind = hint[0]
    if kind == "fixed":
        return hint[1]
    y, m = hint[1], hint[2]
    if kind == "dt":
        if month - m > 6:
            return y - 1
        if m - month > 6:
            return y + 1
        return y
    return y - 1 if month > m else y


def parse_line(line: str, year_hint, tz) -> dict | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = RE_RFC.match(line)
    if m:
        ts = m.group("ts")
        if re.search(r"[+-]\d{4}$", ts):
            ts = ts[:-2] + ":" + ts[-2:]
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        g = m.groupdict()
    else:
        m = RE_BSD.match(line)
        if not m:
            return {"unmatched": True, "raw": line}
        g = m.groupdict()
        dt = _parse_ts_bsd(g, _year_for(MONTHS[g["mon"]], year_hint), tz)
    msg, repeat = g["msg"], None
    r = RE_REPEAT.match(msg)
    if r:
        msg, repeat = r.group("inner").strip(), int(r.group("n"))
    return {"dt": dt, "host": g["host"], "program": g["prog"], "pid": _int(g["pid"]),
            "message": msg, "repeat_count": repeat}


def classify(program: str, msg: str) -> dict:
    prog = program.lower()
    pam = classify_pam(msg)
    if pam is not None:
        return pam
    if prog in ("sshd", "sshd-session", "sshd-auth"):
        return classify_sshd(msg)
    if prog == "sudo":
        return classify_sudo(msg)
    if prog == "su":
        return classify_su(msg)
    if prog == "pkexec":
        return classify_pkexec(msg)
    if prog in ACCOUNT_PROGRAMS:
        return classify_account(msg)
    if prog == "systemd-logind":
        return classify_logind(msg)
    return {"event": "other", "result": "info"}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def build_event(parsed: dict, ref: str) -> dict:
    c = classify(parsed["program"], parsed["message"])
    src_ip = c.pop("_src_ip", None)
    ld = {k: None for k in LAYER_DATA_KEYS}
    ld.update({k: v for k, v in c.items() if k in ld})
    ld["host"], ld["program"], ld["message"] = parsed["host"], parsed["program"], parsed["message"]
    if parsed["repeat_count"] is not None:
        ld["repeat_count"] = parsed["repeat_count"]
    ld["session_type"] = _session_type(ld["tty"])
    return {"timestamp": _iso(parsed["dt"]), "layer": "auth", "raw_ref": ref, "src_ip": src_ip,
            "pid": parsed["pid"], "ppid": None, "layer_data": ld}


# ================================================================ 스트림
def ref_name(path) -> str:
    """raw_ref 의 파일 부분. .gz 만 뗀다: auth.log.2.gz → auth.log.2, 073525-AbCd.gz → 073525-AbCd"""
    name = Path(path).name
    return name[:-3] if name.endswith(".gz") else name


def normalize_lines(lines, ref: str, year_hint, tz, stats: dict | None = None):
    for no, line in enumerate(lines, 1):
        p = parse_line(line, year_hint, tz)
        if p is None:
            continue
        if stats is not None:
            stats["lines"] = stats.get("lines", 0) + 1
        if p.get("unmatched"):
            if stats is not None:
                stats["unmatched"] = stats.get("unmatched", 0) + 1
                ex = stats.setdefault("unmatched_examples", [])
                if len(ex) < 5:
                    ex.append(f"{ref}:{no}  {p['raw'][:160]}")
            continue
        yield build_event(p, f"{ref}:{no}")


def _file_order(p: Path):
    """오래된 파일부터: auth.log.4.gz → … → auth.log.1 → auth.log. S3 파일(HHMMSS-랜덤.gz)은 이름순."""
    m = re.search(r"\.(\d+)(?:\.gz)?$", p.name)
    rot = int(m.group(1)) if m else 0
    base = re.sub(r"\.\d+(?:\.gz)?$", "", p.name)
    return (str(p.parent), base, -rot)


def iter_files(inputs):
    files = []
    for i in inputs:
        p = Path(i).expanduser()
        if p.is_dir():
            files += [x for x in p.rglob("*") if x.is_file()]
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(i)
    return sorted(set(files), key=_file_order)


def open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def _year_hint(path: Path, year):
    m = RE_DT.search(str(path))
    if m:
        return ("dt", int(m.group(1)), int(m.group(2)))
    if year:
        return ("fixed", year)
    now = datetime.now(timezone.utc)
    return ("now", now.year, now.month)


def parse_files(files, year: int | None = None, tz_name: str = "UTC", stats: dict | None = None):
    """이벤트를 파일 순서(오래된 것부터)·줄 순서대로 흘려보낸다. 메모리에 모으지 않는다."""
    tz = timezone.utc if tz_name.upper() == "UTC" else ZoneInfo(tz_name)
    for f in files:
        with open_text(f) as fh:
            # splitlines() 는 \x1c~\x1e, \x85 같은 문자도 줄바꿈으로 취급해 줄 번호가 원본과 어긋난다
            for ev in normalize_lines(fh.read().split("\n"), ref_name(f), _year_hint(f, year), tz, stats):
                yield ev


def normalize_files(files, year: int | None = None, tz_name: str = "UTC", stats: dict | None = None):
    """테스트·소량용: 전부 모아 시각순 정렬해서 돌려준다."""
    return sorted(parse_files(files, year, tz_name, stats), key=lambda e: e["timestamp"])


# ================================================================ CLI
def _shape(msg: str) -> str:
    """미분류 통계용: 숫자·IP·16진수를 지워 같은 틀끼리 모은다"""
    msg = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", msg)
    msg = re.sub(r"\b[0-9a-fA-F:]{6,}\b", "<hex>", msg)
    return re.sub(r"\d+", "<n>", msg)[:140]


def main(argv=None):
    import argparse
    import json
    import sys
    from collections import Counter

    ap = argparse.ArgumentParser(description="auth.log → 공통 스키마 JSONL")
    ap.add_argument("inputs", nargs="+", help="파일·.gz·디렉터리 (여러 개 가능, '-' 는 stdin)")
    ap.add_argument("-o", "--output", help="출력 JSONL (없으면 stdout)")
    ap.add_argument("--year", type=int, help="BSD 헤더 연도. 경로에 dt=YYYY-MM-DD 가 있으면 그것이 우선")
    ap.add_argument("--tz", default="UTC", help="BSD 헤더 시간대 (EC2 기본 UTC)")
    ap.add_argument("--ref-name", default="stdin", help="stdin 입력일 때 raw_ref 파일 이름")
    ap.add_argument("--stats", action="store_true", help="분포·미분류 Top 20 을 stderr 로")
    a = ap.parse_args(argv)

    stats = {}
    out = open(a.output, "w", encoding="utf-8") if a.output else sys.stdout
    ev_cnt, prog_cnt, other_shapes, days = Counter(), Counter(), Counter(), Counter()
    if a.inputs == ["-"]:
        tz = timezone.utc if a.tz.upper() == "UTC" else ZoneInfo(a.tz)
        now = datetime.now(timezone.utc)
        hint = ("fixed", a.year) if a.year else ("now", now.year, now.month)
        stream = normalize_lines(sys.stdin.read().split("\n"), a.ref_name, hint, tz, stats)
        files = []
    else:
        files = iter_files(a.inputs)
        stream = parse_files(files, a.year, a.tz, stats)
    n = 0
    for ev in stream:
        out.write(json.dumps(ev, ensure_ascii=False) + "\n")
        n += 1
        ld = ev["layer_data"]
        ev_cnt[ld["event"]] += 1
        prog_cnt[ld["program"]] += 1
        days[ev["timestamp"][:10]] += 1
        if ld["event"].endswith("other"):
            other_shapes[f"{ld['program']}: {_shape(ld['message'])}"] += 1
    if a.output:
        out.close()

    if a.stats:
        err = sys.stderr
        unclassified = sum(v for k, v in ev_cnt.items() if k.endswith("other"))
        pct = 100 * (n - unclassified) / n if n else 0
        print(f"[auth_parser] 파일 {len(files)}개 · 줄 {stats.get('lines', 0)} · 이벤트 {n} · "
              f"헤더 불일치 {stats.get('unmatched', 0)} · 분류율 {pct:.1f}%", file=err)
        if files:
            print("[auth_parser] 읽은 순서: " + ", ".join(f.name for f in files), file=err)
        for ex in stats.get("unmatched_examples", []):
            print(f"  헤더 불일치 예: {ex}", file=err)
        print("[auth_parser] 날짜별 이벤트 (UTC):", file=err)
        for d in sorted(days):
            print(f"  {d}  {days[d]}", file=err)
        print("[auth_parser] event 분포:", file=err)
        for k, v in ev_cnt.most_common():
            print(f"  {k:24s} {v}", file=err)
        print("[auth_parser] program 분포: " + ", ".join(f"{k} {v}" for k, v in prog_cnt.most_common()), file=err)
        if other_shapes:
            print("[auth_parser] 미분류 메시지 Top 20 (숫자·IP 는 <n>·<ip>):", file=err)
            for k, v in other_shapes.most_common(20):
                print(f"  {v:6d}  {k}", file=err)


if __name__ == "__main__":
    main()


# ============================================================ 프로젝트 도구 어댑터
# (지원 추가) 팀원 파서 로직은 그대로 두고, normalize/조사에이전트가 쓰도록 얇게 감싼다.
#   - 순수 함수 fetch_auth_log(log_path, ...) -> list[dict]  (normalize 가 호출)
#   - @register fetch_auth_log_tool                          (조사 에이전트가 호출)
#   - 연도(year)는 인자 > .env AUTH_LOG_YEAR > 경로 dt= > 현재연도 순으로 결정.
import os as _os
import sys as _sys
# CLI 단독 실행도 되게, tools 패키지 import 를 위해 레포 루트를 path 에 올린다.
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

try:  # dotenv 선택 의존성
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv()
except Exception:  # pragma: no cover
    pass

from common.timeparse import normalize_iso


def _auth_year_from_env():
    y = _os.getenv("AUTH_LOG_YEAR")
    return int(y) if y and y.isdigit() else None


def _ts_dt(iso_str):
    """ISO8601('...Z') → aware datetime. time_window 비교용(문자열 정밀도 버그 회피)."""
    if not iso_str:
        return None
    try:
        return datetime.fromisoformat(normalize_iso(iso_str))
    except ValueError:
        return None


def fetch_auth_log(log_path, time_window=None, user=None, src_ip=None,
                   event=None, result=None, year=None):
    """raw auth.log 를 읽어 조건에 맞는 인증(auth) 이벤트를 공통스키마 리스트로 반환.

    파싱은 팀원 파서(normalize_files)가 담당. 여기선 필터(AND)만 얹는다.
    연도 생략 시: .env AUTH_LOG_YEAR → 경로 dt= → 현재연도 순으로 결정.
      time_window : [start_iso, end_iso] UTC(경계 포함)
      user/src_ip/event/result : 각 정확일치
    """
    if year is None:
        year = _auth_year_from_env()
    events = normalize_files([Path(log_path)], year=year)

    start_dt = _ts_dt(time_window[0]) if time_window else None
    end_dt = _ts_dt(time_window[1]) if time_window else None

    def _ok(e):
        ld = e["layer_data"]
        if time_window:
            ev_dt = _ts_dt(e["timestamp"])
            if start_dt and ev_dt < start_dt:
                return False
            if end_dt and ev_dt > end_dt:
                return False
        if user is not None and ld.get("user") != user:
            return False
        if src_ip is not None and e.get("src_ip") != src_ip:
            return False
        if event is not None and ld.get("event") != event:
            return False
        if result is not None and ld.get("result") != result:
            return False
        return True

    return [e for e in events if _ok(e)]


try:  # tools 패키지 없이 CLI 단독 실행할 땐 등록을 건너뛴다.
    from tools.base import success, failure
    from tools.registry import register

    @register(
        name="fetch_auth_log",
        description=(
            "raw auth.log 를 읽어 조건에 맞는 인증(auth) 이벤트를 공통스키마로 반환한다. "
            "원격 IP는 top-level src_ip 로 채운다(apache 와 일관). "
            "필터: time_window/user/src_ip/event/result. 연도는 .env AUTH_LOG_YEAR. 조회 전용."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "log_path": {"type": "string", "description": "auth.log 경로. 생략 시 .env AUTH_LOG_PATH."},
                "time_window": {"type": "array", "items": {"type": "string"},
                                "description": "[start_iso, end_iso] UTC(경계 포함)."},
                "user": {"type": "string", "description": "대상 계정 정확일치."},
                "src_ip": {"type": "string", "description": "원격 IP 정확일치."},
                "event": {"type": "string", "description": "이벤트 종류(ssh_failed 등) 정확일치."},
                "result": {"type": "string", "description": "success|failure|info 정확일치."},
            },
            "required": [],
        },
    )
    def fetch_auth_log_tool(log_path: str = None, **filters) -> dict:
        path = log_path or _os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
        try:
            events = fetch_auth_log(path, **filters)
        except FileNotFoundError:
            return failure("auth 로그 없음: %s" % path)
        except Exception as exc:
            return failure("auth 파싱 실패: %s" % exc)
        return success({"count": len(events), "events": events})
except Exception:  # pragma: no cover
    pass