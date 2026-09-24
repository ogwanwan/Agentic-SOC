"""원칙 7 Q1(시도 범위)에 LLM이 계산 없이 쓰도록 코드가 주는 값 검증 (2026-09-24).

- auth_lookback_window(): seed 기준 [시각-24h, 시각+1h]
- fetch_auth_log summary의 [조회 구간 전체 집계]: 실패 1회 = ssh_failed/ssh_invalid_user 1건
"""
from agent.prompts import auth_lookback_window
from agent.tools.log_source import LOCAL_PATH_ENV
from agent.tools.real.fetch_auth_log import fetch_auth_log


def test_lookback_window_from_seed():
    seed = {"src_ip": "192.0.2.10", "trigger_time": "2026-09-22T13:26:12.000Z"}
    assert auth_lookback_window(seed) == ["2026-09-21T13:26:12Z", "2026-09-22T14:26:12Z"]
    assert auth_lookback_window({"trigger_time": "2026-09-22T13:26:12Z"}) is None  # src_ip 없음
    assert auth_lookback_window({"src_ip": "192.0.2.10", "trigger_time": "bad"}) is None


def test_summary_counts_one_attempt_once(tmp_path, monkeypatch):
    for key in [*LOCAL_PATH_ENV.values(), "LOG_LOCAL_HOST"]:
        monkeypatch.delenv(key, raising=False)
    lines = []
    for sec in (10, 20):  # 실패 2회, 각각 pam/Failed/연결 종료 3줄
        lines += [
            f"Sep 22 13:26:{sec} web-01 sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.10  user=root",
            f"Sep 22 13:26:{sec + 1} web-01 sshd[1]: Failed password for root from 192.0.2.10 port 4000 ssh2",
            f"Sep 22 13:26:{sec + 2} web-01 sshd[1]: Connection closed by authenticating user root 192.0.2.10 port 4000 [preauth]",
        ]
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("AUTH_LOG_LOCAL_PATH", str(path))
    monkeypatch.setenv("AUTH_LOG_YEAR", "2026")
    result = fetch_auth_log({"host": "web-01", "start_time": "2026-09-22T13:00:00Z",
                             "end_time": "2026-09-22T14:00:00Z", "src_ip": "192.0.2.10"})
    assert "로그인 실패 2회" in result["summary"]
    assert "실패 대상 계정 1개(root)" in result["summary"]
    assert "로그인 성공 0회" in result["summary"]


def test_empty_username_counts_as_one_account(tmp_path, monkeypatch):
    """스캐너의 빈 계정명 시도("Invalid user  from ...")도 실패 대상 계정 1개로 센다."""
    for key in [*LOCAL_PATH_ENV.values(), "LOG_LOCAL_HOST"]:
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "auth.log"
    path.write_text(
        "Sep 24 05:57:03 web-01 sshd[9]: Invalid user  from 192.0.2.20 port 5000\n"
        "Sep 24 05:57:03 web-01 sshd[9]: Connection closed by invalid user  192.0.2.20 port 5000 [preauth]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AUTH_LOG_LOCAL_PATH", str(path))
    monkeypatch.setenv("AUTH_LOG_YEAR", "2026")
    result = fetch_auth_log({"host": "web-01", "start_time": "2026-09-24T05:00:00Z",
                             "end_time": "2026-09-24T06:00:00Z", "src_ip": "192.0.2.20"})
    assert "로그인 실패 1회" in result["summary"]
    assert "실패 대상 계정 1개((빈 계정명))" in result["summary"]
