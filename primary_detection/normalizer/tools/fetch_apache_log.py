"""
tools/fetch_apache_log.py
도구 본체. raw Apache access.log 를 직접 읽어 조건에 맞는 웹(web) 이벤트를
공통스키마 dict 리스트로 반환한다. "가져오기 + 파싱"만 한다.

절대 원칙(다른 fetch_*_log 도구와 동일):
  - 판단/스코어링/에이전트화 금지. 결정론적 코드. LLM 호출 없음.
  - 로그 접근·필터는 도구 책임. raw를 통째로 에이전트에 넘기지 않는다.

우리 환경 특징(common/ 결론 + 실 EC2 access.log 포맷 기반):
  - Apache 는 Nginx 뒤(프록시 1개)이고 mod_remoteip 로 실 클라이언트가 복원된다.
    %a = 실 클라이언트, %{c}a = 실제 TCP peer(127.0.0.1, nginx).
  - 상단 조인키 src_ip 는 client 필드(%a, 3번) 기준. → xff 는 안 쓴다:
    xff 99%가 빈값('-')이라 client 가 곧 진짜 요청자, 값 있는 1%도 단일 프록시
    반복 경유라 복원 무의미(오버엔지니어링 회피).
  - 서버 자기 공인 IP(SERVER_PUBLIC_IP, 기본 54.180.11.0)는 wp-cron 자기호출(루프백)
    내부 트래픽 → exclude_self=True 로 집계에서 뺄 수 있다(오탐 방지).
  - timestamp 는 이미 ISO8601 UTC(마이크로초, 'Z') → 그대로 정렬축으로 사용.
  - raw_ref 는 "<파일명>:<줄번호>" (원본 역추적 포인터, XAI의 핵심).

실 EC2 LogFormat (컬럼 순서 — 이 파서가 파싱하는 대상):
  %t(ISO8601 UTC) %{req_id} %a %{c}a %{scheme} %{Host}i "%r" %>s %O %D %P \
  "%{Referer}i" "%{User-Agent}i" xff="%{X-Forwarded-For}i"

  예)
  2026-09-17T16:29:07.723203Z b756cf... 207.46.13.17 127.0.0.1 https ogwanwan.shop \
  "GET /?page_id=11 HTTP/1.0" 503 568 464 21359 "-" "Mozilla/5.0 ... bingbot ..." xff="-"

  컬럼 → 공통스키마 매핑:
    1 timestamp     → top.timestamp (ISO8601 UTC 그대로)
    2 req_id        → layer_data.request_id
    3 %a            → src_ip (실 클라이언트, 집계 키) ★
    4 %{c}a         → (nginx peer, 127.0.0.1) 매핑 안 함
    5 scheme        → layer_data.scheme (http|https)
    6 %{Host}i      → layer_data.host (호스트명 또는 IP 접속)
    7 "%r"          → method / path / (protocol는 스키마에 없어 버림)
    8 %>s           → layer_data.status
    9 %O            → layer_data.bytes (응답 바이트, 헤더 포함)
   10 %D            → layer_data.duration_us (µs)
   11 %P            → (워커 PID) 웹 스키마에 필드 없어 매핑 안 함
   12 "%{Referer}i" → layer_data.referer
   13 "%{User-Agent}i" → layer_data.user_agent
   14 xff="..."     → 미사용(파싱만 하고 버림, client 로 충분)

  ※ 9~11(크기·시간류)은 탐지에 미사용이나 공통스키마 bytes/duration_us 계약을 위해 채운다.
  ※ 컬럼 순서가 바뀌면 아래 _LINE_RE 한 곳만 맞추면 된다.
"""

import os
import re
from datetime import datetime, timezone

# 스크립트로 직접 실행돼도 레포 루트를 path 에 올려 top-level 패키지(tools/common)를 찾게 한다.
# (레포 루트를 루트로, tools/common/detect 를 최상위 패키지로 쓴다)
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # dotenv 는 선택 의존성 — 없어도 도구는 동작한다
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # pragma: no cover
    pass

from tools.base import success, failure
from tools.registry import register
from common.schema import build_event
from common.timeparse import normalize_iso

# 로그 경로 (.env → 기본 Ubuntu Apache 경로)
APACHE_LOG_PATH = os.getenv("APACHE_LOG_PATH", "/var/log/apache2/access.log")
# 서버 자기 공인 IP (.env). exclude_self=True 일 때 이 IP(자기호출)를 집계에서 뺀다.
SERVER_PUBLIC_IP = os.getenv("SERVER_PUBLIC_IP", "54.180.11.0")


# --- 상수 / 정규식 -----------------------------------------------------------
# 큰따옴표 필드(백슬래시 이스케이프 허용): "...\"...\..."
_Q = r'(?:[^"\\]|\\.)*'

# 실 EC2 LogFormat 한 줄. 컬럼은 위 docstring 참조.
_LINE_RE = re.compile(
    r'^(?P<ts>\S+)\s+'                                   # 1 timestamp(ISO8601 UTC)
    r'(?P<rid>\S+)\s+'                                   # 2 request_id
    r'(?P<a>\S+)\s+'                                     # 3 %a  (실 클라이언트)
    r'(?P<ca>\S+)\s+'                                    # 4 %{c}a (nginx peer)
    r'(?P<scheme>\S+)\s+'                                # 5 scheme
    r'(?P<host>\S+)\s+'                                  # 6 Host
    r'"(?P<req>' + _Q + r')"\s+'                         # 7 "%r"
    r'(?P<status>\d{3}|-)\s+'                            # 8 %>s
    r'(?P<bytes>\d+|-)\s+'                               # 9 %O
    r'(?P<dur>\d+|-)\s+'                                 # 10 %D (µs)
    r'(?P<pid>\d+|-)\s+'                                 # 11 %P (워커 PID)
    r'"(?P<referer>' + _Q + r')"\s+'                     # 12 "%{Referer}i"
    r'"(?P<ua>' + _Q + r')"'                             # 13 "%{User-Agent}i"
    r'(?:\s+xff="(?P<xff>' + _Q + r')")?'                # 14 xff="..." (없어도 허용)
    r'\s*$'
)


# --- 작은 헬퍼 ----------------------------------------------------------------
def _dash(value):
    """Apache 의 '빈 값' 표기('-')와 빈 문자열을 None 으로 정규화."""
    if value is None or value == "-" or value == "":
        return None
    return value


def _unescape(value):
    r"""큰따옴표 필드의 최소 이스케이프 복원(\" → ", \\ → \)."""
    if value is None:
        return None
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _to_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_ts(ts):
    """ISO8601 UTC('...Z') 검증 → 유효하면 원문(마이크로초 보존) 반환, 아니면 None."""
    if not ts:
        return None
    s = ts.strip()
    try:
        datetime.fromisoformat(normalize_iso(s))
    except ValueError:
        return None
    return s


def _iso_to_dt(iso_str):
    """ISO8601(UTC, 'Z' 허용) → aware datetime. time_window 비교용."""
    if iso_str is None:
        return None
    dt = datetime.fromisoformat(normalize_iso(iso_str))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _split_request(req):
    """'GET /a?b=1 HTTP/1.0' → (method, path). protocol 은 스키마에 없어 버린다."""
    req = _dash(req)
    if not req:
        return None, None
    parts = req.split(" ")
    method = parts[0] if len(parts) >= 1 else None
    path = parts[1] if len(parts) >= 2 else None
    return method, path


# --- 1. 한 줄 파싱 → 공통스키마 web 이벤트 -------------------------------------
def parse_line(line, log_name="apache_access.log", lineno=0):
    """access.log 한 줄 → 공통스키마 dict. 매칭 실패/시간 없음 시 None(스킵)."""
    m = _LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    g = m.groupdict()

    timestamp = _parse_ts(g["ts"])
    if timestamp is None:
        return None  # 정렬축이 없는 줄은 버린다

    method, path = _split_request(g["req"])

    src_ip = _dash(g.get("a"))  # client 필드(%a) = 실 클라이언트. xff 는 안 쓴다.

    layer_data = {
        "request_id":  _dash(g.get("rid")),
        "method":      method,
        "path":        _unescape(path),
        "status":      _to_int(_dash(g.get("status"))),
        "scheme":      _dash(g.get("scheme")),
        "host":        _dash(g.get("host")),
        "user_agent":  _dash(_unescape(g.get("ua"))),
        "referer":     _dash(_unescape(g.get("referer"))),
        "bytes":       _to_int(_dash(g.get("bytes"))),
        "duration_us": _to_int(_dash(g.get("dur"))),
    }

    return build_event(
        timestamp=timestamp,
        layer="web",
        raw_ref="%s:%d" % (log_name, lineno),
        src_ip=src_ip,
        layer_data=layer_data,
    )


# --- 2. 필터 매칭 -------------------------------------------------------------
def match_filter(event, filters):
    """event 가 filters(AND 결합)를 모두 만족하면 True."""
    ld = event["layer_data"]

    tw = filters.get("time_window")
    if tw:
        start, end = tw
        ev_dt = _iso_to_dt(event["timestamp"])
        if start is not None and ev_dt < _iso_to_dt(start):
            return False
        if end is not None and ev_dt > _iso_to_dt(end):
            return False

    if filters.get("exclude_self") and event.get("src_ip") == SERVER_PUBLIC_IP:
        return False  # 서버 자기호출(wp-cron 루프백) 제외
    if filters.get("src_ip") is not None and event.get("src_ip") != filters["src_ip"]:
        return False
    if filters.get("status") is not None and ld.get("status") != filters["status"]:
        return False
    if filters.get("method") is not None:
        if (ld.get("method") or "").upper() != str(filters["method"]).upper():
            return False
    if filters.get("path_pattern") is not None:
        if ld.get("path") is None or re.search(filters["path_pattern"], ld["path"]) is None:
            return False

    return True


# --- 3. 오케스트레이터(순수 함수) ----------------------------------------------
def fetch_apache_log(
    log_path,
    time_window=None,
    src_ip=None,
    path_pattern=None,
    status=None,
    method=None,
    exclude_self=False,
):
    """raw Apache access.log 를 읽어 조건에 맞는 웹 이벤트를 공통스키마 리스트로 반환.

    필터는 전부 optional(log_path만 필수), 조합은 AND.
      time_window  : [start_iso, end_iso] UTC(경계 포함)
      src_ip       : 실 클라이언트 IP(client 필드 %a) 정확일치
      path_pattern : path 정규식(re.search)
      status       : HTTP 상태코드(int) 정확일치
      method       : HTTP 메서드(대소문자 무시)
      exclude_self : True면 서버 자기 공인 IP(SERVER_PUBLIC_IP) 자기호출 제외
    """
    log_name = os.path.basename(log_path)
    filters = {
        "time_window": time_window,
        "src_ip": src_ip,
        "path_pattern": path_pattern,
        "status": status,
        "method": method,
        "exclude_self": exclude_self,
    }

    events = []
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            event = parse_line(line, log_name=log_name, lineno=lineno)
            if event is None:
                continue
            if match_filter(event, filters):
                events.append((event["timestamp"], lineno, event))

    events.sort(key=lambda t: (t[0], t[1]))  # UTC 시간 → 줄번호
    return [e for _, _, e in events]


# --- 4. 도구 등록 -------------------------------------------------------------
@register(
    name="fetch_apache_log",
    description=(
        "raw Apache access.log 를 읽어 조건에 맞는 웹(web) 이벤트를 공통스키마로 반환한다. "
        "src_ip 는 client 필드(%a, 실 클라이언트) 기준(xff 미사용). "
        "필터: time_window/src_ip/path_pattern/status/method/exclude_self. 판단은 하지 않는다(조회 전용)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "log_path": {"type": "string", "description": "access.log 경로. 생략 시 .env APACHE_LOG_PATH."},
            "time_window": {
                "type": "array",
                "items": {"type": "string"},
                "description": "[start_iso, end_iso] UTC(경계 포함).",
            },
            "src_ip": {"type": "string", "description": "실 클라이언트 IP(client 필드 %a) 정확일치."},
            "path_pattern": {"type": "string", "description": "요청 path 정규식(re.search)."},
            "status": {"type": "integer", "description": "HTTP 상태코드 정확일치."},
            "method": {"type": "string", "description": "HTTP 메서드(대소문자 무시)."},
            "exclude_self": {"type": "boolean", "description": "True면 서버 자기호출(SERVER_PUBLIC_IP) 제외."},
        },
        "required": [],
    },
)
def fetch_apache_log_tool(log_path: str = None, **filters) -> dict:
    path = log_path or APACHE_LOG_PATH
    try:
        events = fetch_apache_log(path, **filters)
    except FileNotFoundError:
        return failure("apache 로그 없음: %s" % path)
    except Exception as exc:  # 파싱 사고도 도구가 삼키지 않고 이유를 알린다
        return failure("apache 파싱 실패: %s" % exc)
    return success({"count": len(events), "events": events})


# --- 자체 데모(파일 없이 in-memory 검증): python tools/fetch_apache_log.py ---
if __name__ == "__main__":
    _SAMPLES = [
        '2026-09-17T16:29:07.723203Z b756cfe873d69e1511017b2e33393d9b 207.46.13.17 127.0.0.1 '
        'https ogwanwan.shop "GET /?page_id=11 HTTP/1.0" 503 568 464 21359 "-" '
        '"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; '
        '+http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36" xff="-"',
        '2026-09-17T16:31:28.987877Z 8871559bfabd63442b65540e4af1a6a1 104.23.223.89 127.0.0.1 '
        'https ogwanwan.shop "GET /wp-admin/install.php?step=1 HTTP/1.0" 503 568 904 21359 "-" '
        '"http://ogwanwan.shop/wp-admin/install.php?step=1" xff="2a06:98c0:3600::103"',
        '2026-09-17T16:36:39.809951Z 98468701d6b0cb996fa2683cb317a0be 64.137.37.166 127.0.0.1 '
        'http 54.180.11.0 "GET /.env HTTP/1.0" 404 455 175 21359 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/116.0.5845.140 Safari/537.36" xff="-"',
        '2026-09-17T16:36:40.852175Z ac2ec7f8f41470a0e8488bbc39043368 64.137.37.166 127.0.0.1 '
        'http 54.180.11.0 "POST / HTTP/1.0" 503 568 1112 21359 "-" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/116.0.5845.140 Safari/537.36" xff="-"',
        # 서버 자기호출(wp-cron): client=54.180.11.0 → exclude_self 로 걸러진다
        '2026-09-17T16:40:00.000000Z 0000000000000000000000000000abcd 54.180.11.0 127.0.0.1 '
        'http 54.180.11.0 "GET /wp-cron.php?doing_wp_cron HTTP/1.0" 200 0 512 21359 "-" '
        '"WordPress/7.1; http://ogwanwan.shop" xff="-"',
    ]
    import json
    for i, s in enumerate(_SAMPLES, 1):
        ev = parse_line(s, lineno=i)
        print(json.dumps(ev, ensure_ascii=False))
    print("--- filter: path_pattern='(install|\\.env)' ---")
    parsed = [parse_line(s, lineno=i) for i, s in enumerate(_SAMPLES, 1)]
    hits = [e for e in parsed if e and match_filter(e, {"path_pattern": r"(install|\.env)"})]
    print("hits:", [(e["src_ip"], e["layer_data"]["path"]) for e in hits])
    print("--- exclude_self: 자기호출(54.180.11.0) 제외 ---")
    kept = [e for e in parsed if e and match_filter(e, {"exclude_self": True})]
    print("전체 %d건 → exclude_self 후 %d건, src_ip=%s" % (
        len([e for e in parsed if e]), len(kept), [e["src_ip"] for e in kept]))
