"""socdb.py — incident DB 확인용 CLI (읽기 전용)

서버에 sqlite3 CLI 가 없어도 DB 상태를 볼 수 있게 한다. DB 를 만들거나 고치지 않는다.

예)
  python socdb.py stats                       # 상태·우선순위·경로별 사건 수, 대기열 길이
  python socdb.py queue -n 20                 # 조사 대기열(급한 순)
  python socdb.py show <incident_key>         # 사건 상세
  python socdb.py --db /tmp/soc/soc.db stats  # 다른 DB (기본: /var/lib/agentic-soc/soc.db)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from store.db import DB_FILE, connect  # noqa: E402
from store.incidents import STATUS_LABELS, get_incident, list_queue, stats  # noqa: E402

DEFAULT_DB = os.path.join("/var/lib/agentic-soc", DB_FILE)


def _label(status):
    return STATUS_LABELS.get(status, status)


def cmd_stats(conn, _args):
    s = stats(conn)
    print(f"사건 {s['total']}건, 조사 대기열 {s['queue']}건")
    print("  상태:", {_label(k): v for k, v in s["status"].items()})
    print("  우선순위:", s["priority"])
    print("  경로:", s["route"])


def cmd_queue(conn, args):
    rows = list_queue(conn, args.n)
    if not rows:
        print("조사 대기열이 비어 있음")
        return
    print(f"{'점수':>4} {'P':<3} {'incident_key':<17} {'대상':<24} {'LLM':<5} 갱신")
    for r in rows:
        llm = {None: "-", 1: "진짜", 0: "오탐"}.get(r["llm_investigate"], "?")
        target = f"{r['entity_type']}:{r['entity_value']}"
        print(f"{r['triage_score'] or 0:>4} {r['priority'] or '-':<3} {r['incident_key']:<17} {target:<24} "
              f"{llm:<5} {r['updated_at']}")
        if r["llm_reason"]:
            print(f"{'':>26}└ {r['llm_reason']}")


def cmd_show(conn, args):
    inc = get_incident(conn, args.key)
    if inc is None:
        print(f"없는 incident_key: {args.key}")
        return 1
    inc["status"] = f"{inc['status']} ({_label(inc['status'])})"
    print(json.dumps(inc, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB, help=f"DB 경로(기본: {DEFAULT_DB})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats", help="상태·우선순위별 사건 수")
    q = sub.add_parser("queue", help="조사 대기열(급한 순)")
    q.add_argument("-n", type=int, default=20, help="보여줄 건수")
    s = sub.add_parser("show", help="사건 상세")
    s.add_argument("key", help="incident_key")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"DB 파일 없음: {args.db} (파이프라인이 운영 모드로 한 번 실행되면 생긴다)")
        return 1
    conn = connect(args.db)
    try:
        return {"stats": cmd_stats, "queue": cmd_queue, "show": cmd_show}[args.cmd](conn, args) or 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
