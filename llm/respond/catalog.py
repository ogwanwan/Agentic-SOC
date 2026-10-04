"""대응 카탈로그 — 설계 문서 6절.

조치 종류·대상 종류·가역성·위험도·자율성 라벨은 전부 여기 고정값이다. LLM은
이 중 어떤 조치를 쓸지 고르지 않는다(이미 결정된 것만 받는다) — reason 문장만 쓴다.
원칙(6-3절): 삭제보다 격리, 영구보다 TTL, 계정 삭제보다 잠금, 대상이 없으면 그
조치는 애초에 만들지 않는다(decide.py가 처리).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern


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


# --- 6-1. 기법 기반 카탈로그 ---------------------------------------------

TECHNIQUE_CATALOG = {
    "T1595.002": (  # Vulnerability Scanning (Reconnaissance)
        ActionTemplate("소스 IP 임시 차단(TTL 60분)", "ip", True, "LOW", "L2", "immediate",
                        "sudo iptables -I INPUT -s {target} -j DROP", "정찰 단계의 출발지"),
        ActionTemplate("스캔된 경로 노출 점검", "url_path", True, "LOW", "L2", "verify_needed",
                        None, "스캔 대상이 된 경로"),
    ),
    "T1110": (  # Brute Force (Credential Access)
        ActionTemplate("소스 IP 임시 차단(TTL 60분)", "ip", True, "LOW", "L2", "immediate",
                        "sudo iptables -I INPUT -s {target} -j DROP", "무차별 대입 시도의 출발지"),
        ActionTemplate("대상 계정 실패 임계 강화", "user", True, "LOW", "L2", "immediate",
                        None, "무차별 대입 대상 계정"),
        ActionTemplate("대상 계정 비밀번호 재설정", "user", False, "MED", "L1", "immediate",
                        None, "무차별 대입 대상 계정"),
    ),
    "T1190": (  # Exploit Public-Facing Application (Initial Access)
        ActionTemplate("해당 엔드포인트 접근 차단", "url_path", True, "MED", "L1", "immediate",
                        None, "취약점이 악용된 엔드포인트"),
        ActionTemplate("업로드 경로 실행 권한 제거 및 패치 확인", "url_path", True, "MED", "L1",
                        "verify_needed", None, "취약점이 악용된 엔드포인트"),
    ),
    "T1505.003": (  # Web Shell (Persistence)
        ActionTemplate(
            "웹셸 파일 격리", "file_path", True, "LOW", "L2", "immediate",
            "sudo mv {target} /var/quarantine/ && sudo chmod 000 /var/quarantine/$(basename {target})",
            "업로드 직후 실행이 확인된 파일",
        ),
        ActionTemplate("웹루트 내 최근 생성 파일 전수 점검", None, True, "LOW", "L2", "verify_needed",
                        None, "추가 웹셸 잔존 가능성"),
        ActionTemplate("업로드 경로 실행 권한 차단", "url_path", True, "MED", "L1", "immediate",
                        None, "웹셸이 업로드된 경로"),
    ),
    "T1059.004": (  # Unix Shell (Execution)
        ActionTemplate("해당 프로세스(및 자식 프로세스) 종료", "pid", False, "MED", "L1", "immediate",
                        "sudo pkill -TERM -P {target}", "악성 명령을 실행한 프로세스"),
        ActionTemplate("실행 명령 이력 보존", None, True, "MED", "L1", "immediate",
                        None, "사후 분석을 위한 증거 보존"),
    ),
    "T1105": (  # Ingress Tool Transfer (Command and Control)
        ActionTemplate(
            "반입 파일 격리", "file_path", True, "LOW", "L2", "immediate",
            "sudo mv {target} /var/quarantine/ && sudo chmod 000 /var/quarantine/$(basename {target})",
            "외부에서 내려받은 파일",
        ),
        ActionTemplate("다운로드 출처 IP 아웃바운드 차단", "ip", True, "LOW", "L2", "immediate",
                        "sudo iptables -I OUTPUT -d {target} -j DROP", "도구를 전송한 출처"),
        ActionTemplate("동일 파일 전수 검색", None, True, "LOW", "L2", "verify_needed",
                        None, "다른 호스트에도 같은 파일이 있는지 확인"),
    ),
    "T1548.003": (  # Sudo and Sudo Caching (Privilege Escalation)
        ActionTemplate("sudoers 변경 여부 확인", None, True, "MED", "L1", "verify_needed",
                        None, "권한 상승 시도 흔적"),
        ActionTemplate("해당 계정 sudo 권한 회수", "user", True, "MED", "L1", "immediate",
                        None, "sudo를 이용한 권한 상승 시도 계정"),
        ActionTemplate("sudo 로그 보존", None, True, "MED", "L1", "immediate",
                        None, "사후 분석을 위한 증거 보존"),
    ),
    "T1136.001": (  # Create Account: Local Account (Persistence)
        ActionTemplate("생성된 계정 잠금", "user", True, "HIGH", "L1", "immediate",
                        "sudo passwd -l {target}", "공격자가 생성한 것으로 보이는 계정"),
        ActionTemplate("UID 0 계정 전수 점검", None, True, "HIGH", "L1", "verify_needed",
                        None, "추가 관리자 계정 생성 여부 확인"),
        ActionTemplate("계정 생성 전후 세션 추적", None, True, "HIGH", "L1", "verify_needed",
                        None, "계정 생성 경로 확인"),
    ),
    "T1098": (  # Account Manipulation (Persistence)
        ActionTemplate("권한 그룹 변경 원복", "user", True, "MED", "L1", "immediate",
                        None, "권한 그룹이 변경된 계정"),
        ActionTemplate("authorized_keys 점검", None, True, "MED", "L1", "verify_needed",
                        None, "SSH 지속성 확보 흔적"),
        ActionTemplate("해당 계정 비밀번호 재설정", "user", False, "MED", "L1", "immediate",
                        None, "권한이 조작된 계정"),
    ),
    "T1070.004": (  # File Deletion (Defense Evasion)
        ActionTemplate("삭제된 대상 복구 시도", None, False, "HIGH", "L0", "immediate",
                        None, "흔적 삭제가 확인됨"),
        ActionTemplate("감사 로그 보존", None, True, "HIGH", "L0", "immediate",
                        None, "추가 삭제를 막기 위한 최우선 조치"),
        ActionTemplate("백업 무결성 확인", None, True, "HIGH", "L0", "verify_needed",
                        None, "삭제 전 백업 상태 확인"),
    ),
}

# 매핑은 됐지만(mapped/partial) 이 카탈로그에 없는 기법일 때 쓰는 최후 조치
UNCATALOGUED_TECHNIQUE_TEMPLATE = ActionTemplate(
    "증거 보존 및 담당자 확인 요청", None, True, "LOW", "L0", "verify_needed",
    None, "카탈로그에 등록되지 않은 기법",
)

# 조치 대상을 하나도 못 구했을 때(5-4절)의 최후 한 줄
NO_TARGET_TEMPLATE = ActionTemplate(
    "증거 보존 및 담당자 확인 요청", None, True, "LOW", "L0", "verify_needed",
    None, "조치 대상을 특정할 근거가 없음",
)

# --- 6-2. 폴백 카탈로그(기법이 특정되지 않은 THREAT_CONFIRMED) -----------

_FALLBACK_PATTERNS: tuple = (
    (re.compile(r"webshell|webroot", re.IGNORECASE), (
        ActionTemplate("웹루트 내 최근 생성 파일 전수 점검", None, True, "MED", "L1", "verify_needed",
                        None, "웹셸 의심 탐지 룰 발화"),
        ActionTemplate("의심 경로 격리", "file_path", True, "MED", "L1", "immediate",
                        None, "웹셸 의심 탐지 룰 발화"),
    )),
    (re.compile(r"priv_esc|uid0|privileged_group", re.IGNORECASE), (
        ActionTemplate("계정 권한 점검", "user", True, "MED", "L1", "verify_needed",
                        None, "권한 상승 의심 탐지 룰 발화"),
        ActionTemplate("UID 0 계정 목록 확인", None, True, "MED", "L1", "verify_needed",
                        None, "권한 상승 의심 탐지 룰 발화"),
    )),
    (re.compile(r"ingress_tool_transfer|reverse_shell", re.IGNORECASE), (
        ActionTemplate("반입 파일 격리", "file_path", True, "LOW", "L2", "immediate",
                        None, "도구 반입/역방향 셸 의심 탐지 룰 발화"),
        ActionTemplate("출처 IP 아웃바운드 차단", "ip", True, "LOW", "L2", "immediate",
                        None, "도구 반입/역방향 셸 의심 탐지 룰 발화"),
    )),
    (re.compile(r"account_created|password_set|persistence", re.IGNORECASE), (
        ActionTemplate("계정 잠금", "user", True, "HIGH", "L1", "immediate",
                        None, "지속성 확보 의심 탐지 룰 발화"),
        ActionTemplate("계정 생성/변경 전후 세션 추적", None, True, "HIGH", "L1", "verify_needed",
                        None, "지속성 확보 의심 탐지 룰 발화"),
    )),
    (re.compile(r"anti_forensics|tampering", re.IGNORECASE), (
        ActionTemplate("감사 로그 보존", None, True, "HIGH", "L0", "immediate",
                        None, "흔적 삭제/변조 의심 탐지 룰 발화(최우선)"),
        ActionTemplate("auditd 상태 확인", None, True, "HIGH", "L0", "immediate",
                        None, "흔적 삭제/변조 의심 탐지 룰 발화(최우선)"),
    )),
)

_SIGNAL_TAG_CATALOG = {
    "cloud_creds": (
        ActionTemplate("클라우드 자격증명 회전", None, False, "HIGH", "L0", "immediate",
                        None, "클라우드 자격증명 노출 신호"),
        ActionTemplate("IMDS 접근 이력 확인", None, True, "HIGH", "L0", "verify_needed",
                        None, "클라우드 자격증명 노출 신호"),
    ),
    "sensitive": (
        ActionTemplate("민감 파일 접근 이력 확인", None, True, "MED", "L1", "verify_needed",
                        None, "민감 데이터 접근 신호"),
    ),
}

DEFAULT_FALLBACK_TEMPLATES = (
    ActionTemplate("소스 IP 임시 차단(TTL 60분)", "ip", True, "LOW", "L2", "immediate",
                    "sudo iptables -I INPUT -s {target} -j DROP", "구체적 신호가 없어 기본 조치만 적용"),
    ActionTemplate("담당자 확인 요청", None, True, "LOW", "L0", "verify_needed",
                    None, "구체적 신호가 없어 사람이 직접 확인 필요"),
)


def fallback_templates_for_rule_name(rule_name: str) -> tuple:
    for pattern, templates in _FALLBACK_PATTERNS:
        if pattern.search(rule_name or ""):
            return templates
    return ()


def fallback_templates_for_signal_tag(tag: str) -> tuple:
    return _SIGNAL_TAG_CATALOG.get(tag, ())


if __name__ == "__main__":  # 자체 점검: python llm/respond/catalog.py
    assert TECHNIQUE_CATALOG["T1505.003"][0].entity_kind == "file_path"
    assert fallback_templates_for_rule_name("audit_webshell_upload")[0].title.startswith("웹루트")
    assert fallback_templates_for_rule_name("something_else") == ()
    assert fallback_templates_for_signal_tag("cloud_creds")[0].risk == "HIGH"
    assert fallback_templates_for_signal_tag("없는태그") == ()
    print("ok")
