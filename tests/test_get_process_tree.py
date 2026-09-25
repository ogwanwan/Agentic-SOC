"""get_process_tree(agent/tools/real/get_process_tree.py) 단독 테스트.

실제 AWS 없이, 임시 로그 파일을 <계층>_LOG_LOCAL_PATH로 지정해(tests/_log_files.py)
- audit 이벤트의 pid/ppid를 따라 조상 체인이 올바른 순서로 추적되는지
  (leaf -> ... -> root, sshd -> bash -> sh -> id)
- 부모가 로그에 없으면(parent_not_observed) 거기서 멈추고 lineage_status="partial"인지
- 관측 자체가 없는 pid를 물어보면 count=0으로 안내되는지
- 오브젝트가 하나도 없을 때의 안내 메시지
가 맞는지 검증한다.

2026-09-22 업데이트: get_process_tree가 자체 파서(parsers/audit_parser.py) 대신
1차 탐지팀 공통 정규화 함수(normalizer/tools/fetch_audit_log.py)를 쓰도록 바뀌었다.
이 fixture(단순 SYSCALL 라인, ENRICHED 0x1d 구분자 없음)도 그대로 통과한다 —
1차 탐지팀 파서가 enriched 파트가 없으면 raw 파트만으로 파싱하도록 설계돼 있어서다.

pytest 없이도 저장소 루트에서 `python -m tests.test_get_process_tree`로 실행 가능.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any, Dict

from tests._log_files import install_log_files, uninstall_log_files

# normalizer 벤더 코드가 import 시점에 load_dotenv()를 호출하는 문제 회피
# (tests/test_fetch_auth_log.py 상단 주석 참고). agent 패키지의 __init__.py가
# raw_log_ingestion을 즉시 import하는데, 2026-09-22 C 작업으로 raw_log_ingestion이
# normalizer.tools.fetch_auth_log를 쓰게 되면서, "agent."로 시작하는 그 무엇을
# import하든(이 파일처럼 get_process_tree만 써도) 전부 이 영향을 받게 됐다.
#
# 2026-09-22 추가 수정: 그런데 `import agent`만으로는 auth/audit 쪽 load_dotenv()만
# 실행되고, apache/network 쪽(fetch_apache_log.py/fetch_network_log.py)은
# normalizer/adapter.py를 거쳐야 처음 import돼서 이 시점엔 아직 실행 전이었다.
# get_process_tree.py도 normalizer/adapter.py를 import하므로(normalize_audit()를
# 쓰려고), 뒤에서 이 테스트가 get_process_tree를 import하는 순간 adapter.py가
# apache/network 벤더 파일들을 처음 import하면서 load_dotenv()가 "새로" 실행되고,
# 방금 지운 AUDIT_LOG_LOCAL_PATH까지 포함해 4개 변수가 .env 값으로 재오염됐다 —
# 로컬 PC 테스트에서 count가 안 맞던 진짜 원인. adapter.py를 미리 import해서 4개
# 벤더 파일의 load_dotenv()를 전부 한 번에 끝내놓은 뒤 지우면 이 문제가 없다.
import agent.tools.normalizer_adapter as _load_dotenv_trigger  # noqa: F401
for _env_name in ("AUTH_LOG_LOCAL_PATH", "AUDIT_LOG_LOCAL_PATH", "WEB_LOG_LOCAL_PATH", "NETWORK_LOG_LOCAL_PATH"):
    os.environ.pop(_env_name, None)


def _install_log(pieces: Dict[str, Dict[str, bytes]]) -> None:
    install_log_files(pieces, layer="audit")


def _uninstall_log() -> None:
    uninstall_log_files(['agent.tools.real.get_process_tree'])


def _sample_audit_chain_text() -> bytes:
    """sshd(1500) -> bash(1600) -> sh(1700) -> id(1800), ppid=1(sshd의 부모)은 로그에 없음."""
    return (
        b'type=SYSCALL msg=audit(1789217000.100:1001): pid=1500 ppid=1 syscall=59 '
        b'success=yes comm="sshd" exe="/usr/sbin/sshd" key="exec"\n'
        b'type=SYSCALL msg=audit(1789217010.100:1002): pid=1600 ppid=1500 syscall=59 '
        b'success=yes comm="bash" exe="/bin/bash" key="exec"\n'
        b'type=SYSCALL msg=audit(1789217020.100:1003): pid=1700 ppid=1600 syscall=59 '
        b'success=yes comm="sh" exe="/bin/sh" key="susp_exec"\n'
        b'type=SYSCALL msg=audit(1789217030.100:1004): pid=1800 ppid=1700 syscall=59 '
        b'success=yes comm="id" exe="/usr/bin/id" key="susp_exec"\n'
    )


def test_get_process_tree_traces_full_chain() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-12/"
    pieces = ({prefix: {"audit.log": _sample_audit_chain_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.get_process_tree import get_process_tree

        result = get_process_tree(
            {
                "host": "web-01",
                "pid": 1800,
                "start_time": "2026-09-12T00:00:00Z",
                "end_time": "2026-09-12T23:59:59Z",
            }
        )

        assert result["count"] == 1
        chain = result["records"][0]
        pids_in_order = [n["pid"] for n in chain["nodes"]]
        assert pids_in_order == [1800, 1700, 1600, 1500], "leaf(1800)부터 root 방향으로 순서대로여야 한다"
        assert chain["nodes"][0]["exe"] == "/usr/bin/id"
        assert chain["nodes"][-1]["exe"] == "/usr/sbin/sshd"
        assert chain["lineage_status"] == "partial", "ppid=1(sshd의 부모)은 로그에 없어서 partial이어야 한다"
        assert chain["stop_reason"] == "parent_not_observed"
        print("[PASS] test_get_process_tree_traces_full_chain")
    finally:
        _uninstall_log()


def test_get_process_tree_pid_not_observed() -> None:
    prefix = "raw/source_type=auditd/host=web-01/dt=2026-09-12/"
    pieces = ({prefix: {"audit.log": _sample_audit_chain_text()}})
    _install_log(pieces)

    try:
        from agent.tools.real.get_process_tree import get_process_tree

        result = get_process_tree(
            {
                "host": "web-01",
                "pid": 99999,
                "start_time": "2026-09-12T00:00:00Z",
                "end_time": "2026-09-12T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "찾지 못했습니다" in result["summary"]
        print("[PASS] test_get_process_tree_pid_not_observed")
    finally:
        _uninstall_log()


def test_get_process_tree_reports_missing_partition() -> None:
    pieces = ({})
    _install_log(pieces)

    try:
        from agent.tools.real.get_process_tree import get_process_tree

        result = get_process_tree(
            {
                "host": "web-01",
                "pid": 1800,
                "start_time": "2026-09-12T00:00:00Z",
                "end_time": "2026-09-12T23:59:59Z",
            }
        )
        assert result["count"] == 0
        assert "host 이름" in result["summary"]
        print("[PASS] test_get_process_tree_reports_missing_partition")
    finally:
        _uninstall_log()


if __name__ == "__main__":
    test_get_process_tree_traces_full_chain()
    test_get_process_tree_pid_not_observed()
    test_get_process_tree_reports_missing_partition()
    print("\n모든 테스트 통과.")