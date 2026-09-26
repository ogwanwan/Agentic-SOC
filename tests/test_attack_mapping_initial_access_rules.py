from attack_mapping.engine import match_evidence, match_verdict
from attack_mapping.rules.initial_access import RULES


def _technique_ids(hits):
    return {hit.technique_id for hit in hits}


def test_ssh_bruteforce_verdict_maps_t1110():
    result = {
        "final_verdict": {
            "attack_type": "SSH 무차별 대입 시도",
        },
        "evidence_chain": [],
    }

    hits = match_verdict(result, RULES)

    assert "T1110" in _technique_ids(hits)


def test_successful_bruteforce_maps_valid_accounts():
    result = {
        "final_verdict": {
            "attack_type": "비밀번호 브루트포스 성공 후 계정 침해",
        },
        "evidence_chain": [],
    }

    hits = match_verdict(result, RULES)

    assert "T1078" in _technique_ids(hits)


def test_normal_publickey_login_does_not_map_valid_accounts():
    result = {
        "final_verdict": {
            "attack_type": "정상 관리자 활동",
        },
        "evidence_chain": [
            {
                "evidence_id": "EVID-001",
                "description": "등록된 공개키를 사용한 정상 SSH 로그인 성공",
                "event_type": "ssh_accepted",
                "time": "2026-09-14T20:30:00Z",
            }
        ],
    }

    hits = match_evidence(result, RULES)

    assert "T1078" not in _technique_ids(hits)


def test_webshell_evidence_maps_t1505_003():
    result = {
        "final_verdict": {"attack_type": "웹셸 공격"},
        "evidence_chain": [
            {
                "evidence_id": "EVID-001",
                "description": "shell.php 업로드 후 cmd= 파라미터로 웹셸 명령 실행",
                "event_type": "webshell_execution",
                "time": "2026-09-14T18:05:05Z",
            }
        ],
    }

    hits = match_evidence(result, RULES)

    assert "T1505.003" in _technique_ids(hits)


def test_public_facing_application_exploit_maps_t1190():
    result = {
        "final_verdict": {
            "attack_type": "웹 취약점 악용을 통한 초기 침투",
        },
        "evidence_chain": [],
    }

    hits = match_verdict(result, RULES)

    assert "T1190" in _technique_ids(hits)


def test_path_scanning_maps_t1595():
    result = {
        "final_verdict": {
            "attack_type": "웹 경로·취약점 스캔",
        },
        "evidence_chain": [],
    }

    hits = match_verdict(result, RULES)

    assert "T1595" in _technique_ids(hits)