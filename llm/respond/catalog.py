"""대응 카탈로그 — 설계 문서 6절.

조치 종류·대상 종류·가역성·위험도·자율성 라벨은 전부 여기 고정값이다. LLM은
이 중 어떤 조치를 쓸지 고르지 않는다(이미 결정된 것만 받는다) — reason 문장만 쓴다.
원칙(6-3절): 삭제보다 격리, 영구보다 TTL, 계정 삭제보다 잠금, 대상이 없으면 그
조치는 애초에 만들지 않는다(decide.py가 처리).

2026-10-06 산출물 확정(팀 합의) — 조치 한 건이 반드시 가져야 하는 7가지
  1. 왜 이 조치인가      default_reason (LLM이 reason으로 덮어씀)
  2. 역가능(rollback) 방법 rollback          ← 추가
  3. 실제 명령어          command_template
  4. 자동화 등급 근거     autonomy_reason   ← 추가
  5. 우선순위             priority          ← 추가
  6. 부작용·영향 범위     side_effects      ← 추가
  7. 검증 방법            verification      ← 추가
  네 칸 모두 **코드가 미리 적어 둔 고정 문장**이다. LLM에게 물어보지 않는다 —
  "되돌리는 방법"과 "부작용"을 모델이 지어내면 그대로 운영 사고가 된다.

  rollback·verification 문장에 "{target}"을 쓰면 decide.py가 실제 대상으로 채운다.
  대상이 없는 조치(점검 항목)에서는 그 문장이 비워진다 — 없는 대상으로 명령을 만들지 않는다.

우선순위(priority) 기준 — 같은 묶음([즉시 조치]/[확인 필요]) 안에서의 실행 순서
  1  먼저  확산 차단·증거 보존처럼 늦으면 증거가 사라지거나 피해가 번지는 조치
  2  보통  기본값. 1을 하고 나서 하는 통상 조치
  3  나중  비가역이거나 영향이 커서 1·2를 확인한 뒤에 하는 조치
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern

# 여러 조치가 같은 문장을 쓰는 경우 — 문구를 한곳에서 관리한다
_RB_NO_CHANGE = "점검만 수행 — 되돌릴 변경이 없음"
_SE_READ_ONLY = "없음 — 읽기 전용 점검이라 시스템 상태를 바꾸지 않음"
_RB_PRESERVE = "보존 사본만 만들므로 되돌릴 변경이 없음(사본을 지우면 원복)"
_SE_PRESERVE = "디스크 사용량이 늘어남. 원본 로그·파일은 변경하지 않음"
_RB_QUARANTINE = "sudo mv /var/quarantine/$(basename {target}) {target}"
_RB_IRREVERSIBLE_PW = "되돌릴 수 없음 — 이전 비밀번호는 복구 불가. 새 비밀번호를 재발급해야 함"


@dataclass(frozen=True)
class ActionTemplate:
    title: str
    entity_kind: Optional[str]     # None이면 엔티티 없이도 조치를 만든다
    reversible: bool
    risk: str                       # LOW | MED | HIGH
    autonomy: str                    # L0 | L1 | L2
    category: str                    # immediate | verify_needed
    command_template: Optional[str]  # "{target}" 자리표시자 포함 가능
    default_reason: str
    # ↓ 2026-10-06 산출물 확정으로 추가된 네 칸 + 우선순위 (모두 코드가 정한 고정값)
    priority: int = 2                # 1 먼저 · 2 보통 · 3 나중
    rollback: str = ""               # 역가능 방법. "{target}" 사용 가능
    side_effects: str = ""           # 부작용·영향 범위
    verification: str = ""           # 조치가 제대로 됐는지 확인하는 방법. "{target}" 사용 가능
    autonomy_reason: str = ""        # 왜 이 자율성 등급인가(L0/L1/L2 근거)
    # ↓ 2026-10-06 추가 — LLM 조치 선택 단계(select.py)가 참조하는 칸
    template_id: str = ""            # 안정적인 조치 id. LLM은 이 id로만 조치를 고른다
    mandatory: bool = False          # True면 LLM이 빼도 code가 다시 넣는다(최소 필수 조치)
    requires: tuple = ()             # 이 조치보다 먼저 와야 하는 template_id들(선행조건)


# --- 6-1. 기법 기반 카탈로그 ---------------------------------------------

TECHNIQUE_CATALOG = {
    "T1595.002": (  # Vulnerability Scanning (Reconnaissance)
        ActionTemplate("소스 IP 임시 차단(TTL 60분)", "ip", True, "LOW", "L2", "immediate",
                        "sudo iptables -I INPUT -s {target} -j DROP", "정찰 단계의 출발지",
                        template_id="T1595_002_IP_BLOCK", priority=1,
                        rollback="sudo iptables -D INPUT -s {target} -j DROP (TTL 60분이 지나면 자동 해제)",
                        side_effects="같은 IP를 공유하는 정상 사용자(NAT·사내 게이트웨이)도 60분간 차단됨",
                        verification="iptables -L INPUT -n | grep {target} 로 규칙 등록을 확인하고, 이후 접근 로그가 끊기는지 본다",
                        autonomy_reason="규칙 삭제로 즉시 원복되고 TTL로 자동 해제되며 영향 범위가 IP 1개로 한정 → 자동화 후보(L2)"),
        ActionTemplate("스캔된 경로 노출 점검", "url_path", True, "LOW", "L2", "verify_needed",
                        None, "스캔 대상이 된 경로",
                        template_id="T1595_002_PATH_CHECK", priority=2, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="{target} 의 응답 코드와 노출되는 정보가 의도된 값인지 확인",
                        autonomy_reason="시스템을 바꾸지 않는 읽기 점검 → 자동화 후보(L2)"),
    ),
    "T1110": (  # Brute Force (Credential Access)
        ActionTemplate("소스 IP 임시 차단(TTL 60분)", "ip", True, "LOW", "L2", "immediate",
                        "sudo iptables -I INPUT -s {target} -j DROP", "무차별 대입 시도의 출발지",
                        template_id="T1110_IP_BLOCK", priority=1,
                        rollback="sudo iptables -D INPUT -s {target} -j DROP (TTL 60분이 지나면 자동 해제)",
                        side_effects="같은 IP를 공유하는 정상 사용자도 60분간 로그인 불가",
                        verification="iptables 규칙 등록 확인 후 해당 IP의 인증 시도가 더 이상 기록되지 않는지 본다",
                        autonomy_reason="규칙 삭제로 즉시 원복되고 영향 범위가 IP 1개로 한정 → 자동화 후보(L2)"),
        ActionTemplate("대상 계정 실패 임계 강화", "user", True, "LOW", "L2", "immediate",
                        None, "무차별 대입 대상 계정",
                        template_id="T1110_THRESHOLD_HARDEN", priority=2,
                        rollback="pam_faillock·fail2ban 설정을 변경 전 백업 값으로 복원",
                        side_effects="해당 사용자가 오타 몇 번으로도 계정이 잠길 수 있음",
                        verification="faillock --user {target} 로 임계값과 실패 카운트가 바뀐 것을 확인",
                        autonomy_reason="설정 백업으로 즉시 복원 가능하고 계정 1개로 범위가 한정 → 자동화 후보(L2)"),
        ActionTemplate("대상 계정 비밀번호 재설정", "user", False, "MED", "L1", "immediate",
                        None, "무차별 대입 대상 계정",
                        template_id="T1110_PASSWORD_RESET", priority=3, rollback=_RB_IRREVERSIBLE_PW,
                        side_effects="그 계정으로 돌던 스크립트·서비스 인증이 즉시 실패. 사용자 업무가 끊김",
                        verification="chage -l {target} 의 최근 변경일을 확인하고, 사용자가 새 비밀번호로 로그인되는지 본다",
                        autonomy_reason="비가역이고 사용자 업무가 끊기므로 담당자 승인이 필요 → 승인 후 수동 실행(L1)"),
    ),
    "T1190": (  # Exploit Public-Facing Application (Initial Access)
        ActionTemplate("해당 엔드포인트 접근 차단", "url_path", True, "MED", "L1", "immediate",
                        None, "취약점이 악용된 엔드포인트",
                        template_id="T1190_ENDPOINT_BLOCK", priority=1,
                        rollback="웹서버 설정에서 추가한 deny 블록을 지우고 reload",
                        side_effects="같은 경로를 쓰는 정상 기능까지 함께 중단됨 — 서비스 영향 가능",
                        verification="{target} 요청이 403으로 응답하고, 정상 경로는 영향이 없는지 확인",
                        autonomy_reason="설정 복원으로 가역이지만 서비스 경로를 끊어 사용자 영향이 있음 → 승인 후 수동 실행(L1)"),
        ActionTemplate("업로드 경로 실행 권한 제거 및 패치 확인", "url_path", True, "MED", "L1",
                        "verify_needed", None, "취약점이 악용된 엔드포인트",
                        template_id="T1190_UPLOAD_PERM_REMOVE", priority=2,
                        rollback="제거한 실행 권한을 변경 전 값으로 복원(chmod 되돌리기)",
                        side_effects="그 경로에서 정상 실행되던 스크립트가 함께 멈출 수 있음",
                        verification="{target} 아래 스크립트가 실행되지 않고, 해당 취약점이 패치된 버전인지 확인",
                        autonomy_reason="웹 서비스 동작에 영향을 주는 권한 변경이라 승인이 필요 → 승인 후 수동 실행(L1)"),
    ),
    "T1505.003": (  # Web Shell (Persistence)
        ActionTemplate(
            "웹셸 파일 격리", "file_path", True, "LOW", "L2", "immediate",
            "sudo mv {target} /var/quarantine/ && sudo chmod 000 /var/quarantine/$(basename {target})",
            "업로드 직후 실행이 확인된 파일",
            template_id="T1505_003_QUARANTINE", priority=1, rollback=_RB_QUARANTINE,
            side_effects="그 파일을 참조하는 정상 기능이 있으면 404가 발생(웹셸이면 영향 없음). 파일 1개로 범위 한정",
            verification="{target} 가 사라지고 /var/quarantine/ 아래에 있는지, 해당 URL 요청이 404인지 확인",
            autonomy_reason="삭제가 아니라 이동이라 원복 가능하고 파일 1개로 범위가 한정 → 자동화 후보(L2)",
        ),
        ActionTemplate("웹루트 내 최근 생성 파일 전수 점검", None, True, "LOW", "L2", "verify_needed",
                        None, "추가 웹셸 잔존 가능성",
                        template_id="T1505_003_WEBROOT_SWEEP", priority=2, rollback=_RB_NO_CHANGE,
                        side_effects="없음 — 읽기 전용 점검. 웹루트가 크면 디스크 I/O가 일시적으로 늘어남",
                        verification="find <웹루트> -type f -newermt '<사건 시각 1시간 전>' 결과에 설명되지 않는 파일이 없는지 확인",
                        autonomy_reason="시스템을 바꾸지 않는 읽기 점검 → 자동화 후보(L2)"),
        ActionTemplate("업로드 경로 실행 권한 차단", "url_path", True, "MED", "L1", "immediate",
                        None, "웹셸이 업로드된 경로",
                        template_id="T1505_003_UPLOAD_BLOCK", priority=2,
                        rollback="웹서버 설정과 디렉터리 권한을 변경 전 값으로 복원한 뒤 reload",
                        side_effects="그 업로드 경로에서 정상 실행되던 기능이 중단될 수 있음",
                        verification="{target} 아래 .php 요청이 실행되지 않고 다운로드·403으로 처리되는지 확인",
                        autonomy_reason="웹 서비스 설정 변경이라 사용자 영향이 생길 수 있음 → 승인 후 수동 실행(L1)"),
    ),
    "T1059.004": (  # Unix Shell (Execution)
        ActionTemplate("실행 명령 이력 보존", None, True, "MED", "L1", "immediate",
                        None, "사후 분석을 위한 증거 보존",
                        template_id="T1059_004_HISTORY_PRESERVE", mandatory=True, priority=1, rollback=_RB_PRESERVE, side_effects=_SE_PRESERVE,
                        verification="보존 사본의 해시를 기록하고, 사건 시각 구간이 누락 없이 들어갔는지 확인",
                        autonomy_reason="원본을 바꾸지 않지만 보존 범위와 보관처를 담당자가 정해야 함 → 승인 후 수동 실행(L1)"),
        ActionTemplate("해당 프로세스(및 자식 프로세스) 종료", "pid", False, "MED", "L1", "immediate",
                        "sudo pkill -TERM -P {target}", "악성 명령을 실행한 프로세스",
                        template_id="T1059_004_PROCESS_KILL", requires=("T1059_004_HISTORY_PRESERVE",), priority=2,
                        rollback="되돌릴 수 없음 — 종료된 프로세스는 복구 불가(정상 서비스였다면 서비스를 재시작해야 함)",
                        side_effects="그 PID가 정상 서비스면 서비스가 중단됨. 자식 프로세스까지 함께 종료됨",
                        verification="ps -p {target} 결과가 비어 있고, 같은 명령이 다시 실행되지 않는지 확인",
                        autonomy_reason="비가역이고 정상 서비스를 끊을 수 있음 → 승인 후 수동 실행(L1)"),
    ),
    "T1105": (  # Ingress Tool Transfer (Command and Control)
        ActionTemplate(
            "반입 파일 격리", "file_path", True, "LOW", "L2", "immediate",
            "sudo mv {target} /var/quarantine/ && sudo chmod 000 /var/quarantine/$(basename {target})",
            "외부에서 내려받은 파일",
            template_id="T1105_QUARANTINE", priority=1, rollback=_RB_QUARANTINE,
            side_effects="정상 파일이었다면 그 파일을 쓰는 작업이 실패(격리 해제로 복원 가능). 파일 1개로 범위 한정",
            verification="{target} 가 사라지고 격리 폴더에 있는지, 같은 파일이 다시 생기지 않는지 확인",
            autonomy_reason="삭제가 아니라 이동이라 원복 가능하고 파일 1개로 범위가 한정 → 자동화 후보(L2)",
        ),
        ActionTemplate("다운로드 출처 IP 아웃바운드 차단", "ip", True, "LOW", "L2", "immediate",
                        "sudo iptables -I OUTPUT -d {target} -j DROP", "도구를 전송한 출처",
                        template_id="T1105_OUTBOUND_BLOCK", priority=1,
                        rollback="sudo iptables -D OUTPUT -d {target} -j DROP",
                        side_effects="그 IP가 정상 외부 서비스(CDN·패키지 미러)면 해당 통신도 함께 끊김",
                        verification="iptables -L OUTPUT -n | grep {target} 확인 후 그 목적지로 새 연결이 생기지 않는지 본다",
                        autonomy_reason="규칙 삭제로 즉시 원복되고 목적지 1개로 범위가 한정 → 자동화 후보(L2)"),
        ActionTemplate("동일 파일 전수 검색", None, True, "LOW", "L2", "verify_needed",
                        None, "다른 호스트에도 같은 파일이 있는지 확인",
                        template_id="T1105_DUPLICATE_SEARCH", priority=2, rollback="검색만 수행 — 되돌릴 변경이 없음",
                        side_effects="없음 — 읽기 전용 검색. 전체 검색 시 디스크 I/O가 늘어남",
                        verification="같은 해시·파일명이 다른 호스트에 남아 있지 않은지 확인",
                        autonomy_reason="시스템을 바꾸지 않는 읽기 검색 → 자동화 후보(L2)"),
    ),
    "T1548.003": (  # Sudo and Sudo Caching (Privilege Escalation)
        ActionTemplate("sudo 로그 보존", None, True, "MED", "L1", "immediate",
                        None, "사후 분석을 위한 증거 보존",
                        template_id="T1548_003_LOG_PRESERVE", mandatory=True, priority=1, rollback=_RB_PRESERVE, side_effects=_SE_PRESERVE,
                        verification="보존 사본에 사건 시각 구간의 sudo 항목이 모두 들어갔는지 확인",
                        autonomy_reason="원본을 바꾸지 않지만 보존 범위와 보관처를 담당자가 정해야 함 → 승인 후 수동 실행(L1)"),
        ActionTemplate("sudoers 변경 여부 확인", None, True, "MED", "L1", "verify_needed",
                        None, "권한 상승 시도 흔적",
                        template_id="T1548_003_SUDOERS_CHECK", priority=1, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="visudo -c 가 통과하고, /etc/sudoers·sudoers.d 의 변경 시각이 사건 시각과 겹치지 않는지 확인",
                        autonomy_reason="읽기 확인이지만 권한 설정 해석에 담당자 판단이 필요 → 승인 후 수동 실행(L1)"),
        ActionTemplate("해당 계정 sudo 권한 회수", "user", True, "MED", "L1", "immediate",
                        None, "sudo를 이용한 권한 상승 시도 계정",
                        template_id="T1548_003_SUDO_REVOKE", requires=("T1548_003_LOG_PRESERVE",), priority=2,
                        rollback="백업한 sudoers.d 파일을 되돌려 권한을 다시 부여",
                        side_effects="그 계정으로 운영 작업을 하던 담당자·배치 작업이 즉시 실패",
                        verification="sudo -l -U {target} 결과에 회수한 권한이 남아 있지 않은지 확인",
                        autonomy_reason="운영 작업이 끊길 수 있어 영향 범위를 먼저 확인해야 함 → 승인 후 수동 실행(L1)"),
    ),
    "T1136.001": (  # Create Account: Local Account (Persistence)
        ActionTemplate("생성된 계정 잠금", "user", True, "HIGH", "L1", "immediate",
                        "sudo passwd -l {target}", "공격자가 생성한 것으로 보이는 계정",
                        template_id="T1136_001_ACCOUNT_LOCK", priority=1, rollback="sudo passwd -u {target} (잠금 해제)",
                        side_effects="정상 계정을 잘못 잠그면 그 사용자·서비스의 로그인이 즉시 불가",
                        verification="passwd -S {target} 상태가 L(locked)이고, 그 계정의 새 세션이 없는지 확인",
                        autonomy_reason="잠금 해제로 가역이지만 사람 계정을 끊어 업무 영향이 큼 → 승인 후 수동 실행(L1)"),
        ActionTemplate("UID 0 계정 전수 점검", None, True, "HIGH", "L1", "verify_needed",
                        None, "추가 관리자 계정 생성 여부 확인",
                        template_id="T1136_001_UID0_SWEEP", priority=2, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="awk -F: '$3==0' /etc/passwd 결과가 알려진 관리자 계정뿐인지 확인",
                        autonomy_reason="읽기 점검이지만 결과 판단에 관리자 계정 목록 대조가 필요 → 승인 후 수동 실행(L1)"),
        ActionTemplate("계정 생성 전후 세션 추적", None, True, "HIGH", "L1", "verify_needed",
                        None, "계정 생성 경로 확인",
                        template_id="T1136_001_SESSION_TRACE", priority=2, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="last·auth 로그에서 계정 생성 직전 로그인 세션의 출처를 특정했는지 확인",
                        autonomy_reason="읽기 추적이지만 추적 범위를 담당자가 정해야 함 → 승인 후 수동 실행(L1)"),
    ),
    "T1098": (  # Account Manipulation (Persistence)
        ActionTemplate("authorized_keys 점검", None, True, "MED", "L1", "verify_needed",
                        None, "SSH 지속성 확보 흔적",
                        template_id="T1098_AUTHKEYS_CHECK", priority=1, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="각 계정의 ~/.ssh/authorized_keys 에 등록된 공개키가 관리 중인 키뿐인지 확인",
                        autonomy_reason="읽기 점검이지만 등록 키 대조를 담당자가 해야 함 → 승인 후 수동 실행(L1)"),
        ActionTemplate("권한 그룹 변경 원복", "user", True, "MED", "L1", "immediate",
                        None, "권한 그룹이 변경된 계정",
                        template_id="T1098_GROUP_REVERT", priority=2,
                        rollback="gpasswd로 변경 전 그룹 구성으로 다시 되돌릴 수 있음",
                        side_effects="원복 과정에서 그 계정의 정상 권한까지 줄어들 수 있음",
                        verification="id {target} 의 그룹 목록이 사건 이전 값과 같은지 확인",
                        autonomy_reason="가역이지만 사건 이전 그룹 구성을 먼저 확인해야 함 → 승인 후 수동 실행(L1)"),
        ActionTemplate("해당 계정 비밀번호 재설정", "user", False, "MED", "L1", "immediate",
                        None, "권한이 조작된 계정",
                        template_id="T1098_PASSWORD_RESET", priority=3, rollback=_RB_IRREVERSIBLE_PW,
                        side_effects="그 계정으로 돌던 스크립트·서비스 인증이 즉시 실패. 사용자 업무가 끊김",
                        verification="chage -l {target} 의 최근 변경일을 확인하고, 사용자가 새 비밀번호로 로그인되는지 본다",
                        autonomy_reason="비가역이고 사용자 업무가 끊기므로 담당자 승인이 필요 → 승인 후 수동 실행(L1)"),
    ),
    "T1070.004": (  # File Deletion (Defense Evasion)
        ActionTemplate("감사 로그 보존", None, True, "HIGH", "L0", "immediate",
                        None, "추가 삭제를 막기 위한 최우선 조치",
                        template_id="T1070_004_AUDIT_PRESERVE", mandatory=True, priority=1, rollback=_RB_PRESERVE, side_effects=_SE_PRESERVE,
                        verification="보존 사본의 해시를 기록하고, 사건 시각 구간이 누락 없이 들어갔는지 확인",
                        autonomy_reason="추가 삭제 전에 즉시 해야 하지만 보관처·보존 범위는 담당자가 정함 → 담당자 판단(L0)"),
        ActionTemplate("삭제된 대상 복구 시도", None, False, "HIGH", "L0", "immediate",
                        None, "흔적 삭제가 확인됨",
                        template_id="T1070_004_RESTORE_ATTEMPT", requires=("T1070_004_AUDIT_PRESERVE", "T1070_004_BACKUP_CHECK"), priority=3,
                        rollback="되돌릴 수 없음 — 복구 작업 자체가 디스크 상태를 바꿈",
                        side_effects="복구 도구가 디스크에 쓰면 남아 있던 삭제 흔적이 덮일 수 있음. 가능하면 사본 이미지에서 작업",
                        verification="복구된 파일의 해시·시각이 사건 이전 백업과 일치하는지 확인",
                        autonomy_reason="비가역이고 증거 보전과 충돌할 수 있어 수행 방식을 담당자가 먼저 정함 → 담당자 판단(L0)"),
        ActionTemplate("백업 무결성 확인", None, True, "HIGH", "L0", "verify_needed",
                        None, "삭제 전 백업 상태 확인",
                        template_id="T1070_004_BACKUP_CHECK", mandatory=True, priority=2, rollback="확인만 수행 — 되돌릴 변경이 없음", side_effects=_SE_READ_ONLY,
                        verification="최근 백업의 체크섬 검증이 통과하고, 사건 이전 시점의 백업이 남아 있는지 확인",
                        autonomy_reason="백업 시스템 접근 권한과 복구 정책 판단이 필요 → 담당자 판단(L0)"),
    ),
}

# 매핑은 됐지만(mapped/partial) 이 카탈로그에 없는 기법일 때 쓰는 최후 조치
UNCATALOGUED_TECHNIQUE_TEMPLATE = ActionTemplate(
    "증거 보존 및 담당자 확인 요청", None, True, "LOW", "L0", "verify_needed",
    None, "카탈로그에 등록되지 않은 기법",
    template_id="UNCATALOGUED_FALLBACK", mandatory=True, priority=1, rollback="보존·확인만 수행 — 되돌릴 변경이 없음", side_effects=_SE_READ_ONLY,
    verification="담당자가 이 기법에 맞는 조치를 정하고 카탈로그(6-1절)에 추가했는지 확인",
    autonomy_reason="카탈로그에 없는 기법이라 코드가 조치를 정할 수 없음 → 담당자 판단(L0)",
)

# 조치 대상을 하나도 못 구했을 때(5-4절)의 최후 한 줄
NO_TARGET_TEMPLATE = ActionTemplate(
    "증거 보존 및 담당자 확인 요청", None, True, "LOW", "L0", "verify_needed",
    None, "조치 대상을 특정할 근거가 없음",
    template_id="NO_TARGET_FALLBACK", mandatory=True, priority=1, rollback="보존·확인만 수행 — 되돌릴 변경이 없음", side_effects=_SE_READ_ONLY,
    verification="담당자가 원본 로그에서 조치 대상(IP·경로·계정)을 특정했는지 확인",
    autonomy_reason="조치 대상을 특정할 근거가 없어 자동 실행 대상이 아님 → 담당자 판단(L0)",
)

# --- 6-2. 폴백 카탈로그(기법이 특정되지 않은 THREAT_CONFIRMED) -----------

_FALLBACK_PATTERNS: tuple = (
    (re.compile(r"webshell|webroot", re.IGNORECASE), (
        ActionTemplate("웹루트 내 최근 생성 파일 전수 점검", None, True, "MED", "L1", "verify_needed",
                        None, "웹셸 의심 탐지 룰 발화",
                        template_id="FB_WEBSHELL_SWEEP", priority=1, rollback=_RB_NO_CHANGE,
                        side_effects="없음 — 읽기 전용 점검. 웹루트가 크면 디스크 I/O가 일시적으로 늘어남",
                        verification="find <웹루트> -type f -newermt '<사건 시각 1시간 전>' 결과에 설명되지 않는 파일이 없는지 확인",
                        autonomy_reason="기법이 특정되지 않아 점검 범위를 담당자가 정해야 함 → 승인 후 수동 실행(L1)"),
        ActionTemplate("의심 경로 격리", "file_path", True, "MED", "L1", "immediate",
                        None, "웹셸 의심 탐지 룰 발화",
                        template_id="FB_WEBSHELL_QUARANTINE", priority=1, rollback=_RB_QUARANTINE,
                        side_effects="정상 파일이면 그 파일을 쓰는 기능이 실패(격리 해제로 복원 가능)",
                        verification="{target} 가 격리 폴더로 이동했고 해당 URL 요청이 404인지 확인",
                        autonomy_reason="기법이 확정되지 않은 상태의 격리라 대상을 사람이 확인해야 함 → 승인 후 수동 실행(L1)"),
    )),
    (re.compile(r"priv_esc|uid0|privileged_group", re.IGNORECASE), (
        ActionTemplate("계정 권한 점검", "user", True, "MED", "L1", "verify_needed",
                        None, "권한 상승 의심 탐지 룰 발화",
                        template_id="FB_PRIVESC_ACCOUNT_CHECK", priority=1, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="id {target} 와 sudo -l -U {target} 결과가 승인된 권한과 같은지 확인",
                        autonomy_reason="권한 해석에 담당자 판단이 필요 → 승인 후 수동 실행(L1)"),
        ActionTemplate("UID 0 계정 목록 확인", None, True, "MED", "L1", "verify_needed",
                        None, "권한 상승 의심 탐지 룰 발화",
                        template_id="FB_PRIVESC_UID0_CHECK", priority=2, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="awk -F: '$3==0' /etc/passwd 결과가 알려진 관리자 계정뿐인지 확인",
                        autonomy_reason="읽기 점검이지만 결과 판단에 관리자 계정 목록 대조가 필요 → 승인 후 수동 실행(L1)"),
    )),
    (re.compile(r"ingress_tool_transfer|reverse_shell", re.IGNORECASE), (
        ActionTemplate("반입 파일 격리", "file_path", True, "LOW", "L2", "immediate",
                        None, "도구 반입/역방향 셸 의심 탐지 룰 발화",
                        template_id="FB_INGRESS_QUARANTINE", priority=1, rollback=_RB_QUARANTINE,
                        side_effects="정상 파일이면 그 파일을 쓰는 작업이 실패(격리 해제로 복원 가능). 파일 1개로 범위 한정",
                        verification="{target} 가 격리 폴더로 이동했고 같은 파일이 다시 생기지 않는지 확인",
                        autonomy_reason="삭제가 아니라 이동이라 원복 가능하고 파일 1개로 범위가 한정 → 자동화 후보(L2)"),
        ActionTemplate("출처 IP 아웃바운드 차단", "ip", True, "LOW", "L2", "immediate",
                        None, "도구 반입/역방향 셸 의심 탐지 룰 발화",
                        template_id="FB_INGRESS_OUTBOUND_BLOCK", priority=1, rollback="sudo iptables -D OUTPUT -d {target} -j DROP",
                        side_effects="그 IP가 정상 외부 서비스면 해당 통신도 함께 끊김",
                        verification="그 목적지로 새 연결이 생기지 않는지 확인",
                        autonomy_reason="규칙 삭제로 즉시 원복되고 목적지 1개로 범위가 한정 → 자동화 후보(L2)"),
    )),
    (re.compile(r"account_created|password_set|persistence", re.IGNORECASE), (
        ActionTemplate("계정 잠금", "user", True, "HIGH", "L1", "immediate",
                        None, "지속성 확보 의심 탐지 룰 발화",
                        template_id="FB_PERSIST_ACCOUNT_LOCK", priority=1, rollback="sudo passwd -u {target} (잠금 해제)",
                        side_effects="정상 계정이면 그 사용자·서비스의 로그인이 즉시 불가",
                        verification="passwd -S {target} 상태가 L(locked)인지 확인",
                        autonomy_reason="사람 계정을 끊어 업무 영향이 커 승인이 필요 → 승인 후 수동 실행(L1)"),
        ActionTemplate("계정 생성/변경 전후 세션 추적", None, True, "HIGH", "L1", "verify_needed",
                        None, "지속성 확보 의심 탐지 룰 발화",
                        template_id="FB_PERSIST_SESSION_TRACE", priority=2, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="auth 로그에서 계정 생성·변경 직전 세션의 출처를 특정했는지 확인",
                        autonomy_reason="읽기 추적이지만 추적 범위를 담당자가 정해야 함 → 승인 후 수동 실행(L1)"),
    )),
    (re.compile(r"anti_forensics|tampering", re.IGNORECASE), (
        ActionTemplate("감사 로그 보존", None, True, "HIGH", "L0", "immediate",
                        None, "흔적 삭제/변조 의심 탐지 룰 발화(최우선)",
                        template_id="FB_ANTIFORENSICS_AUDIT_PRESERVE", mandatory=True, priority=1, rollback=_RB_PRESERVE, side_effects=_SE_PRESERVE,
                        verification="보존 사본의 해시를 기록하고 사건 시각 구간이 누락 없이 들어갔는지 확인",
                        autonomy_reason="추가 삭제 전에 즉시 해야 하지만 보관처를 담당자가 정함 → 담당자 판단(L0)"),
        ActionTemplate("auditd 상태 확인", None, True, "HIGH", "L0", "immediate",
                        None, "흔적 삭제/변조 의심 탐지 룰 발화(최우선)",
                        template_id="FB_ANTIFORENSICS_AUDITD_CHECK", priority=1, rollback="확인만 수행 — 되돌릴 변경이 없음", side_effects=_SE_READ_ONLY,
                        verification="systemctl is-active auditd 와 auditctl -l 결과가 기준 설정과 같은지 확인",
                        autonomy_reason="감사 체계 자체가 꺼졌을 수 있어 담당자가 직접 확인해야 함 → 담당자 판단(L0)"),
    )),
)

_SIGNAL_TAG_CATALOG = {
    "cloud_creds": (
        ActionTemplate("IMDS 접근 이력 확인", None, True, "HIGH", "L0", "verify_needed",
                        None, "클라우드 자격증명 노출 신호",
                        template_id="SIG_CLOUDCREDS_IMDS_CHECK", priority=1, rollback="확인만 수행 — 되돌릴 변경이 없음", side_effects=_SE_READ_ONLY,
                        verification="169.254.169.254 접근 로그에 사건 시각 전후의 비정상 호출이 있는지 확인",
                        autonomy_reason="클라우드 콘솔 권한이 필요하고 조회 범위 판단이 선행돼야 함 → 담당자 판단(L0)"),
        ActionTemplate("클라우드 자격증명 회전", None, False, "HIGH", "L0", "immediate",
                        None, "클라우드 자격증명 노출 신호",
                        template_id="SIG_CLOUDCREDS_ROTATE", priority=2,
                        rollback="되돌릴 수 없음 — 이전 키는 폐기되어 복구 불가. 신규 키를 재배포해야 함",
                        side_effects="그 키를 쓰는 모든 애플리케이션·배치가 재배포 전까지 인증 실패 — 영향 범위가 서비스 전반",
                        verification="이전 키로 호출하면 거부되고 신규 키로는 정상 동작하는지 확인",
                        autonomy_reason="비가역이고 서비스 전반에 영향 → 담당자 판단(L0)"),
    ),
    "sensitive": (
        ActionTemplate("민감 파일 접근 이력 확인", None, True, "MED", "L1", "verify_needed",
                        None, "민감 데이터 접근 신호",
                        template_id="SIG_SENSITIVE_ACCESS_CHECK", priority=1, rollback=_RB_NO_CHANGE, side_effects=_SE_READ_ONLY,
                        verification="그 파일에 접근한 주체·시각이 업무상 허용된 범위인지 확인",
                        autonomy_reason="대상 파일 선정에 담당자 판단이 필요 → 승인 후 수동 실행(L1)"),
    ),
}

DEFAULT_FALLBACK_TEMPLATES = (
    ActionTemplate("소스 IP 임시 차단(TTL 60분)", "ip", True, "LOW", "L2", "immediate",
                    "sudo iptables -I INPUT -s {target} -j DROP", "구체적 신호가 없어 기본 조치만 적용",
                    template_id="DEFAULT_IP_BLOCK", priority=1,
                    rollback="sudo iptables -D INPUT -s {target} -j DROP (TTL 60분이 지나면 자동 해제)",
                    side_effects="같은 IP를 공유하는 정상 사용자도 60분간 차단됨",
                    verification="iptables 규칙 등록을 확인하고 그 IP의 접근 로그가 끊기는지 본다",
                    autonomy_reason="규칙 삭제로 즉시 원복되고 TTL로 자동 해제되며 IP 1개로 범위 한정 → 자동화 후보(L2)"),
    ActionTemplate("담당자 확인 요청", None, True, "LOW", "L0", "verify_needed",
                    None, "구체적 신호가 없어 사람이 직접 확인 필요",
                    template_id="DEFAULT_ANALYST_REQUEST", mandatory=True, priority=2, rollback="확인만 수행 — 되돌릴 변경이 없음", side_effects=_SE_READ_ONLY,
                    verification="담당자가 사건을 확인하고 조치 여부를 기록했는지 확인",
                    autonomy_reason="구체적 신호가 없어 코드가 조치를 정할 수 없음 → 담당자 판단(L0)"),
)


def fallback_templates_for_rule_name(rule_name: str) -> tuple:
    for pattern, templates in _FALLBACK_PATTERNS:
        if pattern.search(rule_name or ""):
            return templates
    return ()


def fallback_templates_for_signal_tag(tag: str) -> tuple:
    return _SIGNAL_TAG_CATALOG.get(tag, ())


def _all_templates() -> tuple:
    """카탈로그에 등록된 모든 템플릿 — 자체 점검에서 빠진 칸을 찾는 데 쓴다."""
    found: list = []
    for templates in TECHNIQUE_CATALOG.values():
        found.extend(templates)
    for _pattern, templates in _FALLBACK_PATTERNS:
        found.extend(templates)
    for templates in _SIGNAL_TAG_CATALOG.values():
        found.extend(templates)
    found.extend(DEFAULT_FALLBACK_TEMPLATES)
    found.extend([UNCATALOGUED_TECHNIQUE_TEMPLATE, NO_TARGET_TEMPLATE])
    return tuple(found)


def requires_approval(autonomy: str) -> bool:
    """이 자율성 등급의 조치가 사람 승인 없이는 실행되지 않는가.

    2026-10-06 결정: 지금은 L0/L1/L2 전부 True(자동 실행 없음) — labels.py의
    AUTONOMY_LEGEND가 말하듯 L2도 "현재 자동 실행 안 함"이다. 나중에 L2 자동 실행을
    열게 되면 이 함수만 고치면 된다(그 판단을 흩어 두지 않기 위해 여기 함수로 뺀다).
    """
    return True


_TEMPLATES_BY_ID = {t.template_id: t for t in _all_templates()}


def get_template(template_id: str):
    """template_id로 ActionTemplate을 찾는다. LLM 선택 단계(select.py)가 쓴다."""
    return _TEMPLATES_BY_ID.get(template_id)


if __name__ == "__main__":  # 자체 점검: python llm/respond/catalog.py
    assert TECHNIQUE_CATALOG["T1505.003"][0].entity_kind == "file_path"
    assert fallback_templates_for_rule_name("audit_webshell_upload")[0].title.startswith("웹루트")
    assert fallback_templates_for_rule_name("something_else") == ()
    assert fallback_templates_for_signal_tag("cloud_creds")[0].risk == "HIGH"
    assert fallback_templates_for_signal_tag("없는태그") == ()

    # 2026-10-06 산출물 확정 — 모든 템플릿이 네 칸과 우선순위를 채웠는지 확인한다.
    # 하나라도 비어 있으면 권고문에 빈 줄이 나가므로 여기서 막는다.
    for template in _all_templates():
        assert template.priority in (1, 2, 3), f"{template.title}: priority={template.priority}"
        for field_name in ("rollback", "side_effects", "verification", "autonomy_reason"):
            value = getattr(template, field_name)
            assert value.strip(), f"{template.title}: {field_name}이 비어 있음"
        # 자율성 등급 근거에는 그 등급이 실제로 적혀 있어야 한다(복사 실수 방지)
        assert template.autonomy in template.autonomy_reason, (
            f"{template.title}: autonomy_reason에 {template.autonomy}가 없음")
        # 대상이 필요 없는 조치에 "{target}" 문장을 쓰면 채울 값이 없다
        if template.entity_kind is None:
            for field_name in ("rollback", "verification", "command_template"):
                value = getattr(template, field_name) or ""
                assert "{target}" not in value, f"{template.title}: {field_name}에 대상 자리표시자"

    # 비가역 조치는 "되돌릴 수 없음"을 반드시 명시한다(권고문에서 가장 중요한 경고)
    for template in _all_templates():
        if not template.reversible:
            assert "되돌릴 수 없음" in template.rollback, f"{template.title}: 비가역 안내 없음"

    # 2026-10-06 추가 — LLM 선택 단계가 참조하는 template_id는 비어 있지 않고 고유해야 한다
    all_ids = [t.template_id for t in _all_templates()]
    assert all(all_ids), "template_id가 빈 템플릿이 있음"
    assert len(all_ids) == len(set(all_ids)), f"template_id가 중복됨: {sorted(all_ids)}"
    id_set = set(all_ids)
    for template in _all_templates():
        for req in template.requires:
            assert req in id_set, f"{template.template_id}: requires에 없는 id {req!r}"
    assert requires_approval("L0") and requires_approval("L1") and requires_approval("L2")
    assert get_template("T1505_003_QUARANTINE") is not None
    assert get_template("없는_id") is None

    print("ok")
