"""agent/settings.py — 저장소 루트 .env 하나만 읽기와 INVESTIGATION_ 접두어 규칙.

EC2는 저장소 루트 .env 하나를 1차 탐지와 같이 쓴다. 조사 에이전트는 그 파일을 경로로 직접 읽고
(llm/investigate/.env는 무시), LLM 설정은 INVESTIGATION_ 이름만 읽는다.
"""
import os

import pytest

from agent import settings


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    root_env = tmp_path / ".env"
    ignored_env = tmp_path / "llm" / "investigate" / ".env"
    ignored_env.parent.mkdir(parents=True)
    monkeypatch.setattr(settings, "ROOT_ENV_FILE", root_env)
    monkeypatch.setattr(settings, "IGNORED_ENV_FILE", ignored_env)
    monkeypatch.setattr(settings, "_notified", set())
    for name in ("SETTINGS_TEST_ROOT", "SETTINGS_TEST_INV", "CLAUDE_MODEL", "INVESTIGATION_CLAUDE_MODEL",
                 "MAPPING_CLAUDE_MODEL"):
        monkeypatch.delenv(name, raising=False)
    return root_env, ignored_env


def test_repo_root_points_to_repository():
    # llm/investigate/agent/settings.py → 저장소 루트(detection_pipeline/이 있는 곳)
    assert (settings.REPO_ROOT / "detection_pipeline").is_dir()


def test_load_root_env_reads_only_root_file(isolated, capsys, monkeypatch):
    root_env, ignored_env = isolated
    root_env.write_text("SETTINGS_TEST_ROOT=root\n", encoding="utf-8")
    ignored_env.write_text("SETTINGS_TEST_INV=inv\n", encoding="utf-8")
    monkeypatch.chdir(ignored_env.parent)  # 실행 폴더와 무관하게 루트 파일만 읽는다
    assert settings.load_root_env() is True
    assert os.environ.get("SETTINGS_TEST_ROOT") == "root"
    assert "SETTINGS_TEST_INV" not in os.environ
    assert "읽지 않습니다" in capsys.readouterr().out
    monkeypatch.delenv("SETTINGS_TEST_ROOT")


def test_load_root_env_does_not_override_existing_env(isolated, monkeypatch):
    root_env, _ = isolated
    root_env.write_text("SETTINGS_TEST_ROOT=from-file\n", encoding="utf-8")
    monkeypatch.setenv("SETTINGS_TEST_ROOT", "from-process")  # systemd·셸에서 준 값이 우선
    settings.load_root_env()
    assert os.environ["SETTINGS_TEST_ROOT"] == "from-process"


def test_investigation_setting_ignores_legacy_name_and_notifies_once(monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_MODEL", "legacy-secret")
    assert settings.investigation_setting("CLAUDE_MODEL") is None
    assert settings.investigation_setting("CLAUDE_MODEL") is None
    out = capsys.readouterr().out
    assert out.count("CLAUDE_MODEL는 읽지 않습니다") == 1 and "legacy-secret" not in out
    assert "INVESTIGATION_CLAUDE_MODEL" in out and "MAPPING_CLAUDE_MODEL" in out  # 어디로 옮길지 안내
    monkeypatch.setenv("INVESTIGATION_CLAUDE_MODEL", "  claude-haiku-4-5-20251001 ")
    assert settings.investigation_setting("CLAUDE_MODEL") == "claude-haiku-4-5-20251001"
    monkeypatch.setenv("INVESTIGATION_CLAUDE_MODEL", "")
    assert settings.investigation_setting("CLAUDE_MODEL") is None  # 빈 값은 없는 것


def test_role_settings_are_independent(monkeypatch):
    # 조사(INVESTIGATION_)와 매핑(MAPPING_)은 루트 .env를 같이 써도 서로의 값을 읽지 않는다
    monkeypatch.setenv("INVESTIGATION_CLAUDE_MODEL", "claude-sonnet-5")
    assert settings.role_setting(settings.MAPPING, "CLAUDE_MODEL") is None
    monkeypatch.setenv("MAPPING_CLAUDE_MODEL", "claude-haiku-4-5")
    assert settings.role_setting(settings.MAPPING, "CLAUDE_MODEL") == "claude-haiku-4-5"
    assert settings.role_setting(settings.INVESTIGATION, "CLAUDE_MODEL") == "claude-sonnet-5"
    with pytest.raises(ValueError, match="LLM 역할"):
        settings.role_setting("TRIAGE", "CLAUDE_MODEL")  # 트리아지는 llm/triage_review가 직접 읽는다
