"""초기 침투·인증·웹 공격 관련 ATT&CK Technique 규칙.

ATT&CK Mapping 단계에서는 LLM을 새로 호출하지 않는다.
Investigation 결과의 final_verdict.attack_type 또는
evidence_chain의 description/event_type에 아래 키워드가 포함되면
해당 Technique 후보로 매핑한다.

주의:
- 단순 정상 행위만으로 공격 Technique을 붙이지 않는다.
- 특히 T1078은 단순 SSH 성공이 아니라 침해된/악용된 계정 사용 정황에만 매핑한다.
- T1190은 단순 HTTP 200/파일 업로드만으로 확정하지 않는다.
"""

from attack_mapping.schema import TechniqueRule


RULES = [
    TechniqueRule(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        attack_type_keywords=(
            "SSH 무차별 대입 시도",
            "무차별 대입",
            "브루트포스",
            "brute force",
            "brute-force",
        ),
        evidence_keywords=(
            "비밀번호 인증 실패",
            "비밀번호 실패",
            "SSH 인증 실패",
            "failed password",
            "패스워드 인증 실패",
        ),
        notes=(
            "SSH 비밀번호 대입/브루트포스 행위. "
            "Investigation에서 THREAT_CONFIRMED된 사건만 Mapping 단계로 들어온다."
        ),
    ),

    TechniqueRule(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        attack_type_keywords=(
            "비밀번호 브루트포스 성공",
            "브루트포스 성공",
            "계정 침해",
            "유효 계정 악용",
            "valid accounts",
        ),
        evidence_keywords=(
            "비밀번호 다회 실패 후 로그인 성공",
            "반복된 비밀번호 인증 실패 후 로그인 성공",
            "브루트포스 성공 후 로그인",
            "실패 후 비밀번호 로그인 성공",
        ),
        notes=(
            "공격자가 유효한 계정으로 실제 로그인한 정황. "
            "단순 Accepted publickey 또는 정상 공개키 로그인만으로는 매핑하지 않는다."
        ),
    ),

    TechniqueRule(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        attack_type_keywords=(
            "웹 취약점 악용",
            "공개 웹 애플리케이션 악용",
            "업로드 취약점 악용",
            "exploit public-facing application",
        ),
        evidence_keywords=(
            "취약한 업로드 기능 악용",
            "업로드 취약점 악용",
            "웹 애플리케이션 취약점 악용",
            "public-facing application exploit",
        ),
        notes=(
            "외부에 노출된 웹 애플리케이션 취약점 악용이 확인된 경우. "
            "단순 POST/HTTP 200 또는 일반 파일 업로드만으로는 매핑하지 않는다."
        ),
    ),

    TechniqueRule(
        technique_id="T1505.003",
        technique_name="Server Software Component: Web Shell",
        tactic_id="TA0003",
        tactic_name="Persistence",
        attack_type_keywords=(
            "웹셸",
            "webshell",
            "web shell",
        ),
        evidence_keywords=(
            "웹셸 업로드",
            "웹셸 실행",
            "shell.php",
            "업로드 후 실행",
            "cmd= 파라미터",
            "Possible PHP Webshell",
            "php webshell",
        ),
        notes=(
            "웹셸 파일 배치 또는 웹셸을 통한 명령 실행이 확인된 경우. "
            "현재 webshell 시나리오의 shell.php 업로드 및 cmd 파라미터 실행을 포함한다."
        ),
    ),

    TechniqueRule(
        technique_id="T1595",
        technique_name="Active Scanning",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        attack_type_keywords=(
            "웹 경로·취약점 스캔",
            "경로·취약점 스캔",
            "웹 경로 스캔",
            "경로 스캔",
            "취약점 스캔",
            "active scanning",
        ),
        evidence_keywords=(
            "서로 다른 경로",
            "다수 경로 스캔",
            "웹 경로 스캔",
            "path scan",
            "vulnerability scan",
        ),
        notes=(
            "다수의 웹 경로 또는 취약점을 능동적으로 탐색한 경우. "
            "단일 404 또는 소량의 정상 요청은 이 규칙만으로 매핑하지 않는다."
        ),
    ),
]