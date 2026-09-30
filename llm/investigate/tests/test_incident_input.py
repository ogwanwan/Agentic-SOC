"""agent/incident_input.py — 1차 탐지 사건 파일 읽기와 조사 루프 입력 변환.

tests/fixtures/primary_detection_incidents.jsonl은 1차 탐지 develop(e9b733c)의 run_pipeline.py를
그쪽 합성 샘플 로그(= 저장소 루트 detection_pipeline/samples/)로 실행해 나온 실제 출력이다.
"""
import json

import pytest

from agent.incident_input import MAX_FALLBACK_REFS, load_incidents, to_investigation_seed
from agent.prompts import layer_query_windows
from tests.test_pipeline import FIXTURE


@pytest.fixture
def incidents():
    return {i["incident_id"]: i for i in load_incidents(FIXTURE)}


def test_pid_incident_keeps_detection_refs_and_context(incidents):
    incident = incidents["INC-7d29ffde"]
    seed = to_investigation_seed(incident, host="web-01")
    assert seed["incident_id"] == "INC-7d29ffde"
    assert seed["host"] == "web-01"
    assert seed["src_ip"] is None  # pid 사건: network 사전 조회 대상 아님
    assert seed["window"] == incident["window"]
    assert seed["trigger_time"] == "2026-09-14T23:45:10.122Z"  # 가장 이른 탐지 이벤트 시각
    assert seed["evidence_refs"] == ["sample_audit.log:6", "sample_audit.log:11", "sample_audit.log:16",
                                     "sample_auth.log:5", "sample_audit.log:21"]
    assert seed["severity_hint"] == "CRITICAL"
    assert "Web Process Attempts Privilege Escalation" in seed["trigger_description"]
    detection = seed["detection"]
    assert detection["layers"] == ["auth", "system"]
    assert detection["join_types"] == {"audit_lineage": 3, "system_auth": 1}
    assert detection["rules"][1]["detail"]["exec_args"].startswith("sh -c curl")
    # 원본 목록(members)과 연결 edge(join_path)는 프롬프트 크기 때문에 싣지 않는다
    assert "members" not in seed and "join_path" not in seed and "seeds" not in seed
    assert layer_query_windows(seed) is not None


def test_ip_incident_sets_src_ip(incidents):
    seed = to_investigation_seed(incidents["INC-960a3db8"], host="web-01")
    assert seed["src_ip"] == "64.137.37.166"
    assert seed["evidence_refs"] == ["sample_access.log:3"]
    assert seed["severity_hint"] == "HIGH"
    assert seed["trigger_description"] == "Sensitive / Config File Access (Apache)"
    assert "llm_reason" not in seed  # 1차 탐지 LLM 재검토가 없던 출력


def test_optional_fields_are_passed_when_present(incidents):
    incident = {**incidents["INC-960a3db8"], "llm_reason": "반복 config 접근 — 스캐너 정찰",
                "incident_key": "src_ip:64.137.37.166|web", "updated_at": "2026-09-27T10:00:00Z",
                "host": "web-02"}
    seed = to_investigation_seed(incident, host="web-01")
    assert seed["llm_reason"] == "반복 config 접근 — 스캐너 정찰"
    assert seed["incident_key"] == "src_ip:64.137.37.166|web"
    assert seed["updated_at"] == "2026-09-27T10:00:00Z"
    assert seed["host"] == "web-02"  # 사건에 host가 있으면 그 값을 쓴다


def test_incident_without_detection_falls_back_to_limited_members():
    members = [f"access.log:{n}" for n in range(1, MAX_FALLBACK_REFS + 20)]
    seed = to_investigation_seed({"incident_id": "INC-X", "entity": {"type": "src_ip", "value": "192.0.2.1"},
                                  "window": ["2026-09-21T00:00:00Z", "2026-09-21T00:01:00Z"],
                                  "members": members, "seeds": []})
    assert seed["evidence_refs"] == members[:MAX_FALLBACK_REFS]
    assert seed["trigger_time"] == "2026-09-21T00:00:00Z"
    assert seed["severity_hint"] is None


def test_hand_written_investigation_input_passes_through():
    seed = {"incident_id": "INC-SSH", "src_ip": "192.0.2.1", "trigger_time": "2026-09-21T00:00:00Z"}
    converted = to_investigation_seed(seed, host="web-01")
    assert converted == {**seed, "host": "web-01"}
    assert "host" not in seed  # 입력 사건 dict는 바꾸지 않는다


@pytest.mark.parametrize("writer", [
    lambda items: "\n".join(json.dumps(i) for i in items) + "\n",  # JSONL (1차 탐지 출력)
    lambda items: json.dumps(items),                                # JSON 배열
])
def test_load_incidents_reads_jsonl_and_json_array(tmp_path, writer):
    items = [{"incident_id": "INC-1"}, {"incident_id": "INC-2"}]
    path = tmp_path / "incidents.json"
    path.write_text(writer(items), encoding="utf-8")
    assert load_incidents(path) == items


def test_load_incidents_reads_single_object_and_rejects_missing_id(tmp_path):
    path = tmp_path / "one.json"
    path.write_text(json.dumps({"incident_id": "INC-1"}, indent=2), encoding="utf-8")
    assert load_incidents(path) == [{"incident_id": "INC-1"}]
    path.write_text('{"entity": {}}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="incident_id"):
        load_incidents(path)
