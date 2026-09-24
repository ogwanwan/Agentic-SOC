"""웹셸 업로드 -> 실행 -> 유출 시나리오 (계정/인증 무관, 웹 취약점 기반 공격).

지금까지 검증한 원칙 6/7번은 전부 "계정/인증 관련 사건"만 다뤘다. 이 시나리오는
로그인/sudo가 전혀 등장하지 않는 완전히 다른 공격 벡터라, 전용 판단 원칙이 없는
상태에서 일반 원칙(1번 증거기반조사, 5번 계층간연결)만으로 에이전트가 얼마나
안정적으로 대응하는지 검증하기 위한 것이다.

시나리오 개요:
  1. web: 공격자(198.51.100.77)가 업로드 엔드포인트로 shell.php를 업로드(POST 200)
  2. web: 곧이어 그 파일에 ?cmd= 파라미터로 명령 실행 요청(GET 200) - 웹셸 특유의 패턴
  3. audit: php-fpm(www-data)이 sh -c로 id/whoami/uname을 실행 - PHP 앱이 정상적으로는
     하지 않는 행위(php-fpm이 셸을 스폰하는 것 자체가 강한 침해 신호)
  4. network: 웹서버 -> 공격자 IP 아웃바운드 통신 + Suricata "Possible Webshell" alert

.env의 *_LOG_LOCAL_PATH가 가리키는 로그 파일(에이전트 도구가 실제로 읽는 파일)에 append한다.
"""

import json
from datetime import datetime, timezone

from _log_paths import log_path

ATTACKER_IP = "198.51.100.77"
SERVER_IP = "10.0.7.236"
HOST = "web-01"

# ----------------------------------------------------------------------
# 1. web — 업로드 + 명령 실행 요청
# [2026-09-24] nginx JSON → apache access 포맷으로 변경. web 계층 정규화는 1차 탐지팀
# fetch_apache_log.py가 하며, 그 파서는 실 EC2 apache LogFormat만 읽는다:
#   %t(ISO8601 UTC) %{req_id} %a %{c}a %{scheme} %{Host}i "%r" %>s %O %D %P
#   "%{Referer}i" "%{User-Agent}i" xff="%{X-Forwarded-For}i"
# ----------------------------------------------------------------------
web_lines = [
    f'2026-09-14T18:05:00.000000Z wsh0001 {ATTACKER_IP} 127.0.0.1 https ogwanwan.shop '
    f'"POST /wp-content/uploads/2026/09/shell.php HTTP/1.1" 200 42 31000 1200 "-" "python-requests/2.31.0" xff="-"',
    f'2026-09-14T18:05:05.000000Z wsh0002 {ATTACKER_IP} 127.0.0.1 https ogwanwan.shop '
    f'"GET /wp-content/uploads/2026/09/shell.php?cmd=id;whoami;uname+-a HTTP/1.1" 200 128 45000 1200 '
    f'"-" "python-requests/2.31.0" xff="-"',
]

# ----------------------------------------------------------------------
# 2. audit.log — php-fpm이 셸을 스폰하는 execve 체인 (ENRICHED 포맷)
# ----------------------------------------------------------------------
GS = "\x1d"
# [2026-09-24 수정] 웹셸 명령 요청(18:05:05 UTC) 시각. 예전 값 1789423505는 22:05:05 UTC로
# 4시간 어긋나 web → audit 연결이 시간 구간 조회에서 끊겼다. 다른 시나리오처럼 datetime에서 계산.
EPOCH_BASE = int(datetime(2026, 9, 14, 18, 5, 5, tzinfo=timezone.utc).timestamp())
SERIAL_BASE = 9500

audit_lines = []


def make_execve_pair(serial, epoch, ppid, pid, uid_name, comm, exe, argv):
    syscall_line = (
        f"type=SYSCALL msg=audit({epoch}.001:{serial}): arch=c000003e syscall=59 "
        f"success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=2 ppid={ppid} pid={pid} "
        f"auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 "
        f"tty=(none) ses=4294967295 comm=\"{comm}\" exe=\"{exe}\" subj=unconfined key=\"exec\""
        f"{GS}ARCH=x86_64 SYSCALL=execve AUID=\"unset\" UID=\"{uid_name}\" GID=\"{uid_name}\" "
        f"EUID=\"{uid_name}\" SUID=\"{uid_name}\" FSUID=\"{uid_name}\" EGID=\"{uid_name}\" "
        f"SGID=\"{uid_name}\" FSGID=\"{uid_name}\""
    )
    argv_fields = " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv))
    execve_line = f"type=EXECVE msg=audit({epoch}.001:{serial}): argc={len(argv)} {argv_fields}"
    return [syscall_line, execve_line]


# php-fpm 워커(기존에 떠있는 프로세스, ppid=1로 가정)가 sh를 스폰
audit_lines += make_execve_pair(
    SERIAL_BASE + 1, EPOCH_BASE, ppid=1200, pid=9500,
    uid_name="www-data", comm="sh", exe="/usr/bin/dash",
    argv=["sh", "-c", "id;whoami;uname -a"],
)
# sh가 다시 id, whoami, uname을 자식으로 실행
audit_lines += make_execve_pair(
    SERIAL_BASE + 2, EPOCH_BASE + 1, ppid=9500, pid=9501,
    uid_name="www-data", comm="id", exe="/usr/bin/id", argv=["id"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 3, EPOCH_BASE + 2, ppid=9500, pid=9502,
    uid_name="www-data", comm="whoami", exe="/usr/bin/whoami", argv=["whoami"],
)
audit_lines += make_execve_pair(
    SERIAL_BASE + 4, EPOCH_BASE + 3, ppid=9500, pid=9503,
    uid_name="www-data", comm="uname", exe="/usr/bin/uname", argv=["uname", "-a"],
)

# ----------------------------------------------------------------------
# 3. network.log — 웹서버 -> 공격자 아웃바운드 + alert
# ----------------------------------------------------------------------
network_lines = [
    json.dumps({
        "timestamp": "2026-09-14T18:05:06.000000+0000", "event_type": "flow",
        "src_ip": SERVER_IP, "dest_ip": ATTACKER_IP, "src_port": 44100,
        "dest_port": 8080, "proto": "TCP",
        "flow": {"state": "established", "pkts_toserver": 5, "pkts_toclient": 3},
    }),
    json.dumps({
        "timestamp": "2026-09-14T18:05:06.500000+0000", "event_type": "alert",
        "src_ip": ATTACKER_IP, "dest_ip": SERVER_IP, "src_port": 55002,
        "dest_port": 443, "proto": "TCP",
        "alert": {"signature": "ET WEB_SERVER Possible PHP Webshell Command Execution"},
    }),
]

# ----------------------------------------------------------------------
# append
# ----------------------------------------------------------------------
with open(log_path("web"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(web_lines) + "\n")

with open(log_path("audit"), "a", encoding="utf-8") as f:
    f.write("\n" + "\n".join(audit_lines) + "\n")

with open(log_path("network"), "a", encoding="utf-8") as f:
    f.write("\n".join(network_lines) + "\n")

print("웹셸 시나리오 로그 추가 완료.")
print()
print("test_consistency.py의 SEED를 아래로 교체하세요:")
print(
    """
SEED = {
    "incident_id": "CONSISTENCY-TEST-04",
    "detection_source": "llm_triage",
    "trigger_time": "2026-09-14T18:05:00+00:00",
    "trigger_description": "웹 애플리케이션 업로드 디렉터리에 PHP 파일 업로드 후 곧바로 명령 실행 파라미터로 접근 발생",
    "confidence_initial": 0.65,
    "severity_hint": "HIGH",
    "priority": 1,
    "host": "web-01",
    "src_ip": "198.51.100.77",
    "reasoning": "업로드 디렉터리에 PHP 파일이 생성된 직후 그 파일에 cmd 파라미터로 접근하는 패턴은 웹셸 업로드-실행 공격의 전형적인 시그니처입니다.",
}
"""
)