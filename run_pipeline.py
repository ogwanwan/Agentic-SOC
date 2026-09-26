"""run_pipeline.py — 정규화 → 탐지 → 사건묶기 전체를 실행해 Incident 를 낸다.

detect/run.py 는 seed 까지만 만든다. 이 파일은 그 seed 를 correlate() 에 넣어
Incident 까지 잇는 엔드투엔드 러너다(새 로직 없이 기존 함수 배선만).

예)
  python run_pipeline.py                                  # .env 경로로 4계층 전부
  python run_pipeline.py --audit tools/sample_audit.log   # 특정 계층 경로만 덮어쓰기
  python run_pipeline.py --out-incidents out/incidents.jsonl

운영(주기 실행) 모드 — 최근 N분만 로테이트 파일까지 읽고, 새로 생겼거나 바뀐 사건만 append:
  python run_pipeline.py --since-minutes 60 --state-dir /var/lib/agentic-soc --emit-dir /var/lib/agentic-soc/incidents
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from correlate.grouping import correlate  # noqa: E402
from detect.aggregate import aggregate_seeds  # noqa: E402
from detect.engine import detect  # noqa: E402
from detect.loader import load_rules  # noqa: E402
from detect.suricata_seed import build_suricata_seeds  # noqa: E402
from common.timeparse import normalize_iso  # noqa: E402
from pipeline.state import diff_incidents, incident_key, load_state, run_lock, save_state  # noqa: E402
from tools.normalize import normalize_all  # noqa: E402
from triage.llm_review import llm_review  # noqa: E402
from triage.triage import triage  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apache")
    ap.add_argument("--auth")
    ap.add_argument("--network")
    ap.add_argument("--audit")
    ap.add_argument("--rules", default=str(HERE / "detect" / "rules" / "sigma"), help="Sigma 룰 디렉터리(재귀)")
    ap.add_argument("--window", type=int, default=60, help="seed window 반경(초)")
    ap.add_argument("--min-count", type=int, default=5,
                    help="seed 집계 후 저심각(low/medium) 최소 발생 수(미만이면 버림)")
    ap.add_argument("--no-require-seed", action="store_true",
                    help="탐지 seed 없는 클러스터도 사건으로 낸다(기본: 안 냄)")
    ap.add_argument("--out-incidents", help="Incident JSONL 저장 경로")
    ap.add_argument("--min-priority", choices=["P1", "P2", "P3", "P4"],
                    help="이 우선순위 이상만 출력/저장(예: P2). 미지정 시 전부")
    ap.add_argument("--show", type=int, default=10, help="콘솔에 보여줄 다계층 사건 수")
    ap.add_argument("--since-minutes", type=int,
                    help="최근 N분만 분석(로테이트 파일 포함). 미지정 시 파일 전체")
    ap.add_argument("--now", help="기준 시각 ISO8601(기본: 현재 UTC). 샘플 재현·테스트용")
    ap.add_argument("--state-dir", help="증분 상태 디렉터리. 지정 시 새로 생겼거나 바뀐 사건만 내보내고 LLM 재검토도 그 사건만")
    ap.add_argument("--emit-dir", help="내보낼 사건을 incidents-YYYY-MM-DD.jsonl 로 append 할 디렉터리(--state-dir 필요)")
    args = ap.parse_args()
    if args.emit_dir and not args.state_dir:
        ap.error("--emit-dir 는 --state-dir 와 함께 써야 한다")

    now = datetime.fromisoformat(normalize_iso(args.now)) if args.now else datetime.now(timezone.utc)
    if not args.state_dir:
        return run(args, now)
    with run_lock(args.state_dir) as locked:
        if not locked:
            print(f"[state] 다른 실행이 {args.state_dir} 잠금 중 → 이번 실행 건너뜀")
            return 0
        return run(args, now)


def run(args, now) -> int:
    timing = {}
    started = time.monotonic()

    def lap(stage):
        nonlocal started
        timing[stage] = round(time.monotonic() - started, 2)
        started = time.monotonic()

    # ① 정규화
    time_window = None
    if args.since_minutes:
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
        time_window = [(now - timedelta(minutes=args.since_minutes)).strftime(fmt), now.strftime(fmt)]
        print(f"[normalize] 분석 창 {time_window[0]} ~ {time_window[1]} (로테이트 파일 포함)")
    events = normalize_all(apache_path=args.apache, auth_path=args.auth,
                           network_path=args.network, audit_path=args.audit,
                           time_window=time_window, include_rotated=bool(time_window))
    print(f"[normalize] 이벤트 {len(events)}건, 계층별={dict(Counter(e['layer'] for e in events))}")
    lap("normalize")

    # ② 탐지 → seed
    rules = load_rules(args.rules)
    sigma_seeds = [seed for _ev, _rule, seed in detect(events, rules, args.window)]
    suricata_seeds, _rejects = build_suricata_seeds(events, window_seconds=args.window)
    seeds = sigma_seeds + suricata_seeds
    raw_n = len(seeds)
    seeds = aggregate_seeds(seeds, min_count=args.min_count)
    print(f"[detect] seed {raw_n}건(Sigma {len(sigma_seeds)} + Suricata {len(suricata_seeds)}) "
          f"→ 집계·임계값 후 {len(seeds)}건")
    lap("detect")

    # ③ 사건묶기
    incidents = correlate(events, seeds, require_seed=not args.no_require_seed)
    dist = Counter(len(set(i["layers"])) for i in incidents)
    multi = [i for i in incidents if len(set(i["layers"])) >= 2]
    print(f"[correlate] Incident {len(incidents)}건, 계층수 분포={dict(sorted(dist.items()))}, 다계층(2+)={len(multi)}건")
    lap("correlate")

    # ④ 트리아지 — 결정론 점수 게이트(정렬·라우팅만, 판단 아님)
    incidents = triage(incidents)
    pdist = Counter(i["priority"] for i in incidents)
    pretty = {p: pdist[p] for p in ("P1", "P2", "P3", "P4") if pdist.get(p)}
    print(f"[triage] priority 분포={pretty}")

    if args.state_dir:
        # 운영 모드: 새로 생겼거나 바뀐 사건만 고른 뒤 그 사건만 LLM 재검토(같은 사건 반복 호출 방지)
        if args.min_priority:
            incidents = [i for i in incidents if i["priority"] <= args.min_priority]
            print(f"[triage] --min-priority {args.min_priority} → {len(incidents)}건 남김")
        state = load_state(args.state_dir)
        emits, new_state = diff_incidents(incidents, state, now)
        kinds = Counter(kind for kind, _ in emits)
        print(f"[state] 내보낼 사건 {len(emits)}건(new {kinds.get('new', 0)}, update {kinds.get('update', 0)}), "
              f"추적 중 {len(new_state['incidents'])}건")
        emit_incidents = llm_review([inc for _, inc in emits])
        reviewed = sum(1 for i in emit_incidents if "llm_reason" in i)
        print(f"[triage] LLM 재검토 {reviewed}건(내보낼 사건 중 P1~P2)")
        lap("triage")
        if args.emit_dir and emits:
            path = write_emits(args.emit_dir, emits, now)
            print(f"[emit] {len(emits)}건 추가: {path}")
        save_state(args.state_dir, new_state)  # 쓰기 성공 뒤에 저장 — 도중에 죽으면 다음 실행이 다시 낸다
    else:
        # ④-b 트리아지 뒷단(LLM): 상위(P1~P2) 사건을 경량 LLM(Claude Haiku)으로 재검토 —
        # 점수/정렬 불변, llm_investigate·llm_reason 만 부착. 키 없으면 결정론 결과만 사용(안 죽음).
        incidents = llm_review(incidents)
        reviewed = sum(1 for i in incidents if "llm_reason" in i)
        print(f"[triage] LLM 재검토 {reviewed}건(P1~P2 상위)")

        if args.min_priority:
            # P1 이 최상위 → 'P1' <= 'P2' 문자열 비교로 지정 이상만 유지
            incidents = [i for i in incidents if i["priority"] <= args.min_priority]
            print(f"[triage] --min-priority {args.min_priority} → {len(incidents)}건 남김")
        lap("triage")

    for i in sorted(multi, key=lambda x: -len(x["members"]))[: args.show]:
        joins = sorted({e["join"] for e in i["join_path"]})
        reasons = list({s.get("reason") for s in i.get("seeds", [])})[:3]
        print(f"  {i['incident_id']} layers={sorted(set(i['layers']))} members={len(i['members'])} "
              f"joins={joins} entity={i.get('entity')} seeds={len(i.get('seeds', []))} {reasons}")

    if args.out_incidents:
        Path(args.out_incidents).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_incidents, "w", encoding="utf-8") as fh:
            for i in incidents:
                fh.write(json.dumps(i, ensure_ascii=False) + "\n")
        print(f"[correlate] 저장: {args.out_incidents}")
    print(f"[timing] 단계별 초={timing}, 합계={round(sum(timing.values()), 2)}")
    return 0


def write_emits(emit_dir, emits, now):
    """내보낼 사건을 날짜별 JSONL 에 append. 각 줄에 emit_type·emitted_at·run_id·incident_key 를 붙인다."""
    Path(emit_dir).mkdir(parents=True, exist_ok=True)
    path = Path(emit_dir) / f"incidents-{now.astimezone(timezone.utc):%Y-%m-%d}.jsonl"
    run_id = uuid.uuid4().hex[:12]
    emitted_at = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "a", encoding="utf-8") as fh:
        for kind, inc in emits:
            row = dict(inc, emit_type=kind, emitted_at=emitted_at, run_id=run_id, incident_key=incident_key(inc))
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


if __name__ == "__main__":
    sys.exit(main())
