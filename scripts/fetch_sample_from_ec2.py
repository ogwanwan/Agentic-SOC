"""EC2에서 SSH로 직접 샘플 로그를 받아오는 개발용 편의 스크립트.

*** 이건 운영 코드가 아니다 ***
조사 에이전트는 EC2 안에서 로그 파일(/var/log/...)을 직접 읽는다. 이 스크립트는 로컬 PC에서
개발·재현 시험을 할 때 쓸 샘플 로그(sample_logs/)를 EC2에서 한 번에 받아 오는 개발자 편의 도구다
(ssh 접속 -> sudo tail -> exit -> scp 네 단계를 한 번에). sample_logs/는 실제 트래픽이 들어 있어
저장소에 올리지 않는다.

사용법:
    python scripts/fetch_sample_from_ec2.py                      # audit만 (기존과 동일)
    python scripts/fetch_sample_from_ec2.py --all                # 4계층 전부
    python scripts/fetch_sample_from_ec2.py --lines 1000 --output my_sample.log

전제:
- ssh/scp가 실행 가능한 환경(주로 WSL)에서 실행해야 한다. Windows PowerShell에서
  돌리면 ssh 키 경로가 안 맞아서 실패할 수 있다 (지난번 겪은 문제와 동일).
- ubuntu 계정이 각 로그 파일 읽기용 sudo를 비밀번호 없이 쓸 수 있어야 한다
  (AWS 기본 ubuntu AMI는 보통 이렇게 설정돼 있음). 안 되면 -t 옵션 필요할 수 있음.
- --all의 기본 경로(apache/auth.log/suricata)는 Ubuntu 기본값 + 팀 아키텍처 확인 결과다.
  실제 서버가 다르면 SSH 접속해서 `ls /var/log/apache2/ /var/log/nginx/
  /var/log/suricata/ /var/log/auth.log*`로 확인 후 --web-path 등으로 바꿔주면 된다.

  *** 2026-09-22 업데이트: web 기본 경로를 nginx에서 apache로 변경 ***
  예전엔(이 주석의 옛 버전) "apache는 nginx 뒤에 있어서 src_ip가 항상
  loopback(127.0.0.1)로만 찍힌다"고 여겨서 nginx를 기본으로 썼었다. 그런데 EC2를
  직접 SSH로 확인해보니, 지금은 apache에 mod_remoteip가 설정돼 있어서
  access.log의 %a(client) 필드에 이미 실 클라이언트 IP가 복원되어 찍힌다 —
  1차 탐지팀 fetch_apache_log.py도 바로 이 전제(EC2 실측 기반)로 설계돼 있고,
  실제 access.log 포맷이 그 파서 컬럼 정의와 정확히 일치함을 확인했다. 그래서
  web 계층은 이제 apache access.log를 기본으로 받는다(경로:
  /var/log/apache2/access.log).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Dict, Optional, Tuple


def fetch_sample_via_ssh(
    host: str,
    user: str,
    key_path: str,
    remote_log_path: str,
    lines: int,
    output_path: str,
) -> Optional[str]:
    """ssh로 원격 명령(sudo tail -n N <파일>)을 실행해 결과를 로컬 파일로 저장한다.
    scp로 파일을 통째로 옮기지 않고, ssh 파이프로 필요한 줄 수만 바로 받는다.
    실패하면(경로가 없거나 등) None을 반환한다 — --all 모드에서 하나 실패해도
    나머지는 계속 받기 위함.
    """
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        print(f"[에러] SSH 키를 찾을 수 없습니다: {key_path}")
        print("WSL에서 실행 중인지, 키 경로가 맞는지 확인하세요.")
        sys.exit(1)

    remote_command = f"sudo tail -n {lines} {remote_log_path}"
    ssh_cmd = ["ssh", "-i", key_path, f"{user}@{host}", remote_command]

    print(f"[실행] {' '.join(ssh_cmd)}")
    result = subprocess.run(ssh_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[건너뜀] {remote_log_path} 못 받음: {result.stderr.strip()}")
        return None

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    line_count = len(result.stdout.splitlines())
    print(f"[완료] {output_path}에 {line_count}줄 저장됨")
    return output_path


def fetch_all_layers(
    host: str,
    user: str,
    key_path: str,
    lines: int,
    web_path: str,
    auth_path: str,
    audit_path: str,
    network_path: str,
) -> Dict[str, str]:
    """4계층(web/auth/audit/network) 샘플을 한 번에 받는다.
    반환값: {"web": "sample_apache_web.log", ...} — 실제로 받아진 것만 포함.

    2026-09-22: web 출력 파일명을 sample_web.log -> sample_apache_web.log로 변경.
    기존 sample_logs/sample_web.log(nginx JSON)는 raw_log_ingestion.py의 아직
    안 옮긴 web 수집 branch가 계속 쓰므로, 새로 받는 apache 샘플과 이름이
    겹치면 실수로 덮어쓸 위험이 있다 — 그래서 다른 이름으로 분리한다.
    """
    layers: Tuple[Tuple[str, str, str], ...] = (
        ("web", web_path, "sample_apache_web.log"),
        ("auth", auth_path, "sample_auth.log"),
        ("audit", audit_path, "sample_audit.log"),
        ("network", network_path, "sample_network.log"),
    )

    fetched: Dict[str, str] = {}
    for name, remote_path, output_path in layers:
        result = fetch_sample_via_ssh(host, user, key_path, remote_path, lines, output_path)
        if result:
            fetched[name] = result

    print(f"\n[요약] {len(fetched)}/4개 계층 수집 성공: {list(fetched.keys())}")
    missing = {n for n, _, _ in layers} - set(fetched.keys())
    if missing:
        print(f"[안내] 못 받은 계층: {missing} — 경로가 실제 서버와 다를 수 있습니다. SSH로 확인 후 --{list(missing)[0]}-path로 재시도하세요.")
    return fetched


def main() -> None:
    parser = argparse.ArgumentParser(description="EC2에서 샘플 로그를 SSH로 직접 받아온다 (개발용)")
    parser.add_argument("--host", default=os.environ.get("EC2_HOST", "ogwanwan.shop"))
    parser.add_argument("--user", default=os.environ.get("EC2_USER", "ubuntu"))
    parser.add_argument("--key", default=os.environ.get("EC2_SSH_KEY", "~/.ssh/agentic-soc"))
    parser.add_argument("--lines", type=int, default=500)
    parser.add_argument("--all", action="store_true", help="web/auth/audit/network 4계층 전부 받기")
    # --all 모드 전용 경로 (Ubuntu 기본값 추정 — 실제 서버 확인 후 필요시 조정)
    # 2026-09-22: web 기본을 nginx -> apache로 변경 (mod_remoteip로 실 클라이언트
    # IP가 apache 레벨에서 복원됨을 SSH로 확인 — 파일 상단 docstring 참고)
    parser.add_argument("--web-path", default="/var/log/apache2/access.log")
    parser.add_argument("--auth-path", default="/var/log/auth.log")
    parser.add_argument("--network-path", default="/var/log/suricata/eve.json")
    # --all 아닐 때(단일 파일) 전용
    parser.add_argument("--remote-path", default="/var/log/audit/audit.log")
    parser.add_argument("--output", default="sample_audit.log")
    args = parser.parse_args()

    if args.all:
        fetch_all_layers(
            host=args.host,
            user=args.user,
            key_path=args.key,
            lines=args.lines,
            web_path=args.web_path,
            auth_path=args.auth_path,
            audit_path=args.remote_path,
            network_path=args.network_path,
        )
    else:
        fetch_sample_via_ssh(
            host=args.host,
            user=args.user,
            key_path=args.key,
            remote_log_path=args.remote_path,
            lines=args.lines,
            output_path=args.output,
        )


if __name__ == "__main__":
    main()