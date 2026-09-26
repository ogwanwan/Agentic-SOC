"""
tools/normalize.py — ① 정규화 오케스트레이터

파싱(정규화)은 각 fetch_*_log 도구가 담당한다. 이 모듈은 파싱을 다시 하지 않고,
계층별 fetch 를 불러 나온 공통스키마 이벤트를 전 계층 합쳐 timestamp(UTC)로 정렬만
한다. ② 탐지(Sigma 엔진)의 입력(정규화된 이벤트 스트림)을 만드는 코드 단계다.

원칙:
  - "raw → 공통스키마" 로직은 각 fetch_*_log 한 곳에만 존재(중복 파서 금지).
  - 여기서는 fan-out(계층별 호출) + merge + sort 만.
  - 현재 계층: web(apache) + auth + network(suricata) + system(audit) 4계층.

경로는 .env 에서 읽는다: APACHE_LOG_PATH / AUTH_LOG_PATH / SURICATA_LOG_PATH / AUDIT_LOG_PATH
"""

import json
import os
import re
from datetime import datetime, timezone

# 스크립트로 직접 실행돼도 레포 루트를 path 에 올려 top-level 패키지(tools/common)를 찾게 한다.
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # dotenv 선택 의존성
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # pragma: no cover
    pass

# 파싱은 각 도구의 '순수 함수'를 직접 쓴다(@register 래퍼 말고). 현재 계층 4종.
from tools.fetch_apache_log import fetch_apache_log      # web
from tools.fetch_auth_log import fetch_auth_log          # auth
from tools.fetch_network_log import fetch_network_log    # network
from tools.fetch_audit_log import fetch_audit_log        # system
from tools.log_sources import resolve_log_files
from common.timeparse import normalize_iso


def _ts_key(event):
    """timestamp(ISO8601 UTC, 'Z') → datetime. 정밀도 차이에도 정확히 정렬."""
    try:
        return datetime.fromisoformat(normalize_iso(event.get("timestamp") or ""))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _warn(message):
    print("[normalize] 경고: %s" % message, file=_sys.stderr)


def _safe(fetch_fn, path, **kwargs):
    """도구 하나 호출. 도구/경로 없거나 파일을 못 읽으면 빈 리스트(정규화는 안 죽는다).

    파일 없음은 조용히 넘기고, 권한 오류·디렉터리 경로 등 그 밖의 OSError 는 경고를 남긴다
    (운영에서 읽기 권한 누락이 '0건'으로 묻히지 않게).
    """
    if fetch_fn is None or not path:
        return []
    try:
        return fetch_fn(path, **kwargs)
    except FileNotFoundError:
        return []
    except OSError as exc:
        _warn("%s 읽기 실패(%s)" % (path, exc))
        return []


def _fetch_layer(layer, fetch_fn, path, time_window, include_rotated):
    """한 계층 정규화. include_rotated 면 path 의 로테이트 형제까지 읽어 합친다."""
    if not path:
        return []
    kwargs = {"time_window": time_window} if time_window else {}
    if not include_rotated:
        events = _safe(fetch_fn, path, **kwargs)
    else:
        since_dt = _ts_key({"timestamp": time_window[0]}) if time_window else None
        files = resolve_log_files(path, since_dt=since_dt)
        if not files and not resolve_log_files(path):
            _warn("%s 계층 로그 파일 없음 (경로=%s)" % (layer, path))
        events = []
        for file_path in files:
            events += _safe(fetch_fn, file_path, **kwargs)
    if not events and not time_window:
        _warn("%s 계층 이벤트 0건 (경로=%s, 파일·권한 확인)" % (layer, path))
    return events


def normalize_all(
    apache_path=None,
    auth_path=None,
    network_path=None,
    audit_path=None,
    sort=True,
    time_window=None,
    include_rotated=False,
):
    """전 계층 raw 로그 → 공통스키마 이벤트 하나의 리스트로 정규화(fan-out + merge + sort).

    각 경로 생략 시 .env 에서 읽는다. 특정 계층만 넘기면 그 계층만 정규화된다.
    현재 계층: web(apache) + auth + network(suricata) + system(audit).
    time_window    : [start_iso, end_iso] UTC. 각 fetch 의 time_window 필터로 그대로 넘긴다.
    include_rotated: True 면 로테이트 형제(base.1, base.N.gz) 중 창 시작 이후 수정된 파일도 읽는다.
    반환: list[dict] (공통스키마), sort=True면 timestamp(UTC) 오름차순.
    """
    apache_path = apache_path or os.getenv("APACHE_LOG_PATH")
    auth_path = auth_path or os.getenv("AUTH_LOG_PATH")
    network_path = network_path or os.getenv("SURICATA_LOG_PATH")
    audit_path = audit_path or os.getenv("AUDIT_LOG_PATH")

    events = []
    events += _fetch_layer("web", fetch_apache_log, apache_path, time_window, include_rotated)
    events += _fetch_layer("auth", fetch_auth_log, auth_path, time_window, include_rotated)
    events += _fetch_layer("network", fetch_network_log, network_path, time_window, include_rotated)
    events += _fetch_layer("system", fetch_audit_log, audit_path, time_window, include_rotated)

    if sort:
        events.sort(key=_ts_key)  # 전 계층 공통 정렬축 = timestamp(UTC)
    return events


def _next_out_dir(out_root=None, now=None):
    """out/YYYY-MM-DD-NNN 디렉토리를 만들고 생성된 경로를 반환한다."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_root = out_root or os.path.join(repo_root, "out")
    os.makedirs(out_root, exist_ok=True)

    date_text = (now or datetime.now().astimezone()).strftime("%Y-%m-%d")
    name_pattern = re.compile(r"^%s-(\d{3})$" % re.escape(date_text))
    used_numbers = []
    for name in os.listdir(out_root):
        match = name_pattern.match(name)
        if match and os.path.isdir(os.path.join(out_root, name)):
            used_numbers.append(int(match.group(1)))

    number = max(used_numbers, default=0) + 1
    while True:
        result_dir = os.path.join(out_root, "%s-%03d" % (date_text, number))
        try:
            os.mkdir(result_dir)
            return result_dir
        except FileExistsError:
            number += 1


def save_normalized_events(events, out_root=None, now=None):
    """정규화 이벤트를 실행별 디렉토리의 계층별 JSONL 파일로 저장한다."""
    result_dir = _next_out_dir(out_root=out_root, now=now)
    grouped = {}
    for event in events:
        grouped.setdefault(event["layer"], []).append(event)

    counts = {}
    for layer, layer_events in sorted(grouped.items()):
        output_path = os.path.join(result_dir, "%s.jsonl" % layer)
        with open(output_path, "w", encoding="utf-8") as output:
            for event in layer_events:
                output.write(json.dumps(event, ensure_ascii=False) + "\n")
        counts[layer] = len(layer_events)
    return result_dir, counts


if __name__ == "__main__":
    evs = normalize_all()
    by_layer = {}
    for e in evs:
        by_layer[e["layer"]] = by_layer.get(e["layer"], 0) + 1
    print("정규화 이벤트 %d건, 계층별=%s" % (len(evs), by_layer))
    for e in evs[:5]:
        print("  %s  %-7s %s" % (e["timestamp"], e["layer"], e["raw_ref"]))
    result_dir, saved_by_layer = save_normalized_events(evs)
    print("저장 완료: %s (계층별=%s)" % (result_dir, saved_by_layer))
