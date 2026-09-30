"""detect/run.py — ① 정규화(4계층) → ② 탐지 → seed 를 한 번에 실행.

Sigma 룰 매칭과 Suricata Alert 기반 탐지를 함께 수행한다.

예)
  python detect/run.py                                   # .env 경로로 4계층 전부
  python detect/run.py --audit tools/sample_audit.log    # 특정 계층 경로만 덮어쓰기
  python detect/run.py --out-normalized out/n.jsonl --out-seeds out/s.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect.engine import detect  # noqa: E402
from detect.loader import load_rules  # noqa: E402
from detect.suricata_seed import build_suricata_seeds  # noqa: E402
from tools.normalize import normalize_all  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apache")
    ap.add_argument("--auth")
    ap.add_argument("--network")
    ap.add_argument("--audit")
    ap.add_argument("--rules", default=str(HERE / "rules" / "sigma"), help="Sigma 룰 디렉터리(재귀)")
    ap.add_argument("--out-normalized", help="정규화 이벤트 JSONL 저장 경로")
    ap.add_argument("--out-seeds", help="seed JSONL 저장 경로")
    ap.add_argument("--window", type=int, default=60, help="seed window 반경(초)")
    ap.add_argument("--web-strong-window", type=float, default=1.0,
                    help="Apache↔Suricata strong 결합 반경(초)")
    ap.add_argument("--web-fallback-window", type=float, default=2.0,
                    help="Apache↔Suricata fallback 결합 반경(초)")
    ap.add_argument("--web-long-delay-window", type=float, default=900.0,
                    help="Apache↔Suricata 장시간 검토 반경(초)")
    ap.add_argument("--show", type=int, default=3, help="룰별로 콘솔에 보여줄 매칭 예시 수")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    print(f"[rules] {len(rules)}개 로드: " + str(dict(Counter(r.path.parent.name for r in rules))))

    events = normalize_all(apache_path=args.apache, auth_path=args.auth,
                           network_path=args.network, audit_path=args.audit)
    print(f"[normalize] 이벤트 {len(events)}건, 계층별={dict(Counter(e['layer'] for e in events))}")

    if args.out_normalized:
        Path(args.out_normalized).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_normalized, "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"[normalize] 저장: {args.out_normalized}")

    hits: dict[str, list] = defaultdict(list)
    sigma_seeds = []
    for ev, rule, seed in detect(events, rules, args.window):
        hits[rule.name].append(ev)
        sigma_seeds.append(seed)

    suricata_seeds, suricata_rejects = build_suricata_seeds(
        events,
        window_seconds=args.window,
        web_strong_seconds=args.web_strong_window,
        web_fallback_seconds=args.web_fallback_window,
        web_long_delay_seconds=args.web_long_delay_window,
    )
    seeds = sigma_seeds + suricata_seeds

    print(
        f"\n[detect] seed {len(seeds)}건 "
        f"(Sigma {len(sigma_seeds)}건, Suricata {len(suricata_seeds)}건)"
    )
    if suricata_rejects:
        print(f"[detect] Suricata Alert 제외 {len(suricata_rejects)}건")
    for r in rules:
        evs = hits.get(r.name, [])
        if not evs:
            continue
        print(f"  - {r.path.parent.name}/{r.name} [{r.level}]: {len(evs)}건")
        for e in evs[: args.show]:
            ld = e["layer_data"]
            brief = {k: ld[k] for k in ("event", "user", "src_user", "comm", "exec_args", "method", "path", "user_agent")
                     if ld.get(k) is not None}
            print(f"      {e['timestamp']} src_ip={e['src_ip']} pid={e['pid']} {brief} ref={e['raw_ref']}")

    if args.out_seeds:
        Path(args.out_seeds).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_seeds, "w", encoding="utf-8") as fh:
            for s in seeds:
                fh.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"[detect] 저장: {args.out_seeds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
