"""get_process_tree 실제 구현 - audit 이벤트의 pid/ppid로 조상 체인을 추적한다.

파일명 == 함수명 규칙에 따라 agent/tools/real/get_process_tree.py 안의
get_process_tree 함수만 있으면 agent/tools/registry.py의 build_default_registry()가
자동으로 이 함수를 mock_tools.py 대신 사용한다.

*** 2026-09-22 업데이트 (마지막 남은 audit_parser.py 사용처도 공통 정규화 함수로 교체) ***
자체 파서(parsers/audit_parser.py)를 버리고 1차 탐지팀 공통 정규화 함수
(agent/tools/normalizer_adapter.py → normalizer/tools/fetch_audit_log.py)를 쓰도록
교체했다 — fetch_audit_log.py(B)와 완전히 같은 소스를 본다. 이걸로 parsers/audit_parser.py
는 진짜로 아무도 안 부르게 됐다(이제 삭제해도 된다).

*** 2026-09-23 업데이트: build_ancestry_chain()을 parsers/process_tree.py에서 이 파일로 합침 ***
그 함수를 쓰는 곳이 여기 하나뿐이라 별도 폴더(parsers/)로 분리해둘 이유가 없어져서
(parsers/에 남은 게 이 파일 하나였음 — agent/tools/parsers/README.md 참고) 그대로
이 파일 안으로 옮겼다. build_ancestry_chain()이 기대하는 필드(pid/ppid/timestamp/
exe/comm/user/syscall/session_type/raw_ref)는 1차 탐지팀 공통스키마를 펼친(log_source.normalize_documents)
결과에도 전부 그대로 있어서(exe/comm/user/syscall/session_type은 layer_data 안에
있다가 top-level로 펼쳐짐), 로직 자체는 옮기면서도 손댈 필요가 없었다.

*** 주의: "확정된 프로세스 생성 트리"가 아니라 "관측 기반 후보"다 ***
audit 로그에 그 pid의 syscall이 안 찍혀 있으면(로그 보관 기간 밖이거나, 아직 조회
범위에 없으면) 부모를 못 찾는다. PID는 재사용될 수 있어서, 같은 pid라도 시간이
멀리 떨어진 별개의 관측이 잘못 이어질 위험도 있다 — 그래서 이 tool의 결과에는
warnings에 이런 한계를 항상 명시한다.

원본(1차 탐지팀) 대비 단순화한 것: 원본은 boot_id/scope(재부팅 경계) 구분, PID
재사용 방지, 동시 확보된 여러 후보 중 모호성 처리까지 정교하게 했다. 우리는
"가장 최근 관측된 그 pid의 부모를 시간 역순으로 따라간다"는 단순한 버전만
구현한다 — 조사 목적(웹셸이 어떤 프로세스에서 실행됐는지 등)엔 이 정도로도
충분하고, boot_id 같은 정보는 공통스키마에 애초에 없다.

필요 환경변수: fetch_audit_log.py와 동일 (agent/tools/normalizer_adapter.py 문서 참고)
로컬 테스트: .env에 AUDIT_LOG_LOCAL_PATH=sample_audit.log (fetch_audit_log.py와 공유)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..log_source import load_window_events
from ..time_utils import parse_iso

DEFAULT_LOOKBACK_HOURS = 24  # 조상을 찾을 때 얼마나 과거까지 audit 로그를 훑을지
MAX_ANCESTORS = 32


def build_ancestry_chain(
    events: List[Dict[str, Any]],
    target_pid: int,
    max_ancestors: int = MAX_ANCESTORS,
) -> Optional[Dict[str, Any]]:
    """구조화된 audit 이벤트 리스트(pid/ppid/exe/user/timestamp 등)에서, target_pid의
    조상 체인(부모 -> 조부모 -> ...)을 시간 역순으로 추적한다.

    이벤트가 이미 timestamp 오름차순 정렬돼 있다고 가정한다. target_pid가
    하나도 관측 안 됐으면 None을 반환한다.

    (2026-09-23: agent/tools/parsers/process_tree.py에서 이 파일로 이동 — 여기서만
    쓰이는 함수라 별도 폴더로 분리해둘 이유가 없어졌다.)
    """
    # pid별로 관측된 이벤트들을 시간순으로 모아둔다 (부모 찾을 때 "그 시점 이전의
    # 가장 최근 관측"을 써야 하므로).
    by_pid: Dict[int, List[Dict[str, Any]]] = {}
    for e in events:
        pid = e.get("pid")
        if pid is not None:
            by_pid.setdefault(pid, []).append(e)

    target_events = by_pid.get(target_pid)
    if not target_events:
        return None

    # target_pid의 가장 최근 관측을 시작점으로 삼는다.
    leaf = target_events[-1]

    chain: List[Dict[str, Any]] = [leaf]
    visited_pids = {target_pid}
    warnings: List[str] = [
        "PID_REUSE_NOT_RESOLVED",
        "관측된 syscall 기반 추정이며 실시간 프로세스 목록이 아님",
    ]
    stop_reason = "parent_pid_zero"

    current = leaf
    while True:
        ppid = current.get("ppid")
        if ppid is None or ppid == 0:
            stop_reason = "parent_pid_zero"
            break
        if ppid in visited_pids:
            stop_reason = "cycle_detected"
            warnings.append("PID_CYCLE_DETECTED")
            break
        if len(chain) >= max_ancestors:
            stop_reason = "depth_limit"
            warnings.append("ANCESTOR_DEPTH_LIMIT")
            break

        parent_events = by_pid.get(ppid)
        if not parent_events:
            stop_reason = "parent_not_observed"
            warnings.append("PARENT_NOT_OBSERVED_IN_LOG_WINDOW")
            break

        # 현재 노드 시점보다 이전(또는 같은) 시점의 가장 최근 관측을 부모로 삼는다.
        candidates = [p for p in parent_events if (p.get("timestamp") or "") <= (current.get("timestamp") or "")]
        parent = candidates[-1] if candidates else parent_events[0]

        chain.append(parent)
        visited_pids.add(ppid)
        current = parent

    return {
        "target_pid": target_pid,
        "chain": " -> ".join(f"{n.get('exe') or n.get('comm')}({n.get('pid')})" for n in chain),
        "nodes": [
            {
                "pid": n.get("pid"),
                "ppid": n.get("ppid"),
                "timestamp": n.get("timestamp"),
                "exe": n.get("exe"),
                "comm": n.get("comm"),
                "user": n.get("user"),
                "syscall": n.get("syscall"),
                "session_type": n.get("session_type"),
                "raw_ref": n.get("raw_ref"),
                "raw_refs": n.get("raw_refs", []),
                "raw_ref_locations": n.get("raw_ref_locations", {}),
            }
            for n in chain
        ],
        "lineage_status": "inferred" if stop_reason == "parent_pid_zero" else "partial",
        "stop_reason": stop_reason,
        "warnings": warnings,
    }


def get_process_tree(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    pid = int(args["pid"])

    # timestamp(특정 시점) 또는 start_time/end_time(범위) 중 하나로 조회 구간을 잡는다.
    # 아무것도 안 주면 "이 tool이 fetch_audit_log와 같은 소스를 볼 수 있는 최대
    # 범위"(기준 시각부터 DEFAULT_LOOKBACK_HOURS 전까지)로 넓게 잡는다.
    if "start_time" in args and "end_time" in args:
        start_time, end_time = args["start_time"], args["end_time"]
    elif "timestamp" in args:
        anchor = parse_iso(args["timestamp"])
        start_time = (anchor - timedelta(hours=DEFAULT_LOOKBACK_HOURS)).isoformat().replace("+00:00", "Z")
        end_time = args["timestamp"]
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
        start_time = start.isoformat().replace("+00:00", "Z")
        end_time = end.isoformat().replace("+00:00", "Z")

    # fetch_audit_log와 같은 경로(log_source → primary_detection 공통 정규화)로 읽는다.
    # 정규화 결과는 이미 layer_data가 top-level로 펼쳐져 있어 build_ancestry_chain()에 바로 넘긴다.
    loaded = load_window_events("audit", host, start_time, end_time)
    flat_events = loaded["events"]

    if loaded["error"] == "permission_denied":
        summary = f"{host}의 audit 로그 파일 읽기 권한이 없습니다. AUDIT_LOG_LOCAL_PATH 권한을 확인하세요."
        return {"count": 0, "summary": summary, "records": [], "error": loaded["error"]}
    if not flat_events:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 audit 데이터를 찾지 못했습니다. "
            "host 이름, 기간, 또는 AUDIT_LOG_LOCAL_PATH 설정을 확인하세요."
        )
        return {"count": 0, "summary": summary, "records": [],
                **({"error": loaded["error"]} if loaded["error"] else {})}

    chain = build_ancestry_chain(flat_events, target_pid=pid)

    if chain is None:
        summary = f"pid={pid}에 대한 audit 관측 기록을 이 조회 구간에서 찾지 못했습니다."
        return {"count": 0, "summary": summary, "records": []}

    summary = (
        f"pid={pid}의 조상 체인 추적 완료: {chain['chain']} "
        f"(상태: {chain['lineage_status']}, 근거: 관측된 audit syscall 기반 — "
        "확정된 프로세스 생성 트리가 아닌 후보임, 1차 탐지팀 공통 정규화 함수 사용)"
    )

    return {"count": 1, "summary": summary, "records": [chain]}
