"""테스트용 ResponsePlan 만들기 — 담당 A의 결정 로직 없이 담당 B만 확인하기 위한 고정 데이터.

실제 운영에서는 decide.py가 이 구조를 만든다. 여기서는 llm.py·render.py가 받는 모양만 맞춘다.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from respond.models import CATEGORY_IMMEDIATE, CATEGORY_VERIFY, Action, ResponsePlan

# 설계서 9-2 예시와 같은 사건 (웹셸 업로드 → 도구 반입 → 권한 상승 시도)
WEBSHELL_PATH = "/var/www/html/wp-content/uploads/shell.php"
SRC_IP = "203.0.113.45"


def make_action(
    action_id: str = "A1",
    *,
    title: str = "웹셸 파일 격리",
    target: Optional[str] = WEBSHELL_PATH,
    target_source: Optional[str] = "seed_detail",
    technique_id: Optional[str] = "T1505.003",
    technique_name: Optional[str] = "Web Shell",
    tactic_name: Optional[str] = "Persistence",
    reversible: bool = True,
    risk: str = "LOW",
    autonomy: str = "L2",
    autonomy_downgraded_from: Optional[str] = None,
    category: str = CATEGORY_IMMEDIATE,
    command_hint: Optional[str] = "sudo mv <대상> /var/quarantine/",
    evidence_ids: Optional[List[str]] = None,
    default_reason: str = "업로드 직후 실행이 확인된 파일입니다.",
    reason: Optional[str] = None,
    # 2026-10-06 산출물 확정 — 카탈로그가 채우는 칸. 실제 T1505.003 "웹셸 파일 격리" 값과 같다.
    priority: int = 1,
    rollback: str = "sudo mv /var/quarantine/shell.php <대상>",
    side_effects: str = "그 파일을 참조하는 정상 기능이 있으면 404가 발생(웹셸이면 영향 없음)",
    verification: str = "대상 파일이 격리 폴더로 이동했고 해당 URL 요청이 404인지 확인",
    autonomy_reason: str = "삭제가 아니라 이동이라 원복 가능하고 파일 1개로 범위가 한정 → 자동화 후보(L2)",
    llm_fields: Optional[List[str]] = None,
) -> Action:
    return Action(
        action_id=action_id,
        title=title,
        target=target,
        target_source=target_source,
        technique_id=technique_id,
        technique_name=technique_name,
        tactic_name=tactic_name,
        reversible=reversible,
        risk=risk,
        autonomy=autonomy,
        autonomy_downgraded_from=autonomy_downgraded_from,
        category=category,
        command_hint=command_hint,
        evidence_ids=list(evidence_ids) if evidence_ids is not None else ["EVID-003"],
        default_reason=default_reason,
        reason=reason,
        priority=priority,
        rollback=rollback,
        side_effects=side_effects,
        verification=verification,
        autonomy_reason=autonomy_reason,
        llm_fields=list(llm_fields or []),
    )


def make_plan(
    *,
    response_status: str = "recommended",
    actions: Optional[List[Action]] = None,
    warnings: Optional[List[Dict[str, Any]]] = None,
    remaining_unknowns: Optional[List[str]] = None,
    summary: Optional[str] = None,
    tuning_hint: Optional[str] = None,
    status_reason: Optional[str] = None,
    mapping_status: str = "mapped",
    provenance_status: str = "passed",
    verdict: str = "THREAT_CONFIRMED",
    severity: str = "HIGH",
) -> ResponsePlan:
    if actions is None:
        actions = [
            make_action("A1"),
            make_action(
                "A2",
                title="소스 IP 임시 차단(TTL 60분)",
                target=SRC_IP,
                target_source="seed_src_ip",
                technique_id="T1595.002",
                technique_name="Vulnerability Scanning",
                tactic_name="Reconnaissance",
                command_hint=None,
                evidence_ids=["EVID-005"],
                default_reason="같은 IP에서 반복 요청이 관측되었습니다.",
            ),
            make_action(
                "A3",
                title="웹루트 내 최근 생성 파일 전수 점검",
                target=None,
                target_source=None,
                technique_id=None,
                technique_name=None,
                tactic_name=None,
                autonomy="L0",
                risk="LOW",
                category=CATEGORY_VERIFY,
                command_hint=None,
                evidence_ids=[],
                default_reason="같은 경로에 다른 웹셸이 남아 있을 수 있습니다.",
                priority=2,
                rollback="점검만 수행 — 되돌릴 변경이 없음",
                side_effects="없음 — 읽기 전용 점검이라 시스템 상태를 바꾸지 않음",
                verification="웹루트에서 사건 시각 전후 생성 파일 중 설명되지 않는 것이 없는지 확인",
                autonomy_reason="시스템을 바꾸지 않는 읽기 점검이지만 범위 판단이 필요 → 담당자 판단(L0)",
            ),
        ]
    return ResponsePlan(
        incident_id="INC-7d29ffde",
        incident_key="INC-7d29ffde",
        investigation_id="INV-7d29ffde-20260914-001",
        response_status=response_status,
        verdict=verdict,
        severity=severity,
        verdict_confidence=0.89,
        investigation_confidence=0.92,
        provenance_status=provenance_status,
        mapping_status=mapping_status,
        host="web-01",
        occurred_at="2026-09-14T07:33:20Z",
        attack_type="웹셸 업로드 후 원격 코드 실행",
        kill_chain=[
            {"step": 1, "tactic_name": "Persistence", "technique_id": "T1505.003",
             "technique_name": "Web Shell", "time": "2026-09-14T07:33:20Z"},
            {"step": 2, "tactic_name": "Command and Control", "technique_id": "T1105",
             "technique_name": "Ingress Tool Transfer", "time": "2026-09-14T07:34:12Z"},
        ],
        actions=list(actions),
        warnings=list(warnings or []),
        evidence_refs=[
            {"evidence_id": "EVID-003", "time": "2026-09-14T07:33:20Z", "layer": "web",
             "description": "shell.php 업로드", "raw_refs": ["apache_access.log:900"]},
            {"evidence_id": "EVID-005", "time": "2026-09-14T07:34:12Z", "layer": "system",
             "description": "curl로 x.sh 다운로드", "raw_refs": ["audit.log:21"]},
        ],
        remaining_unknowns=list(remaining_unknowns or []),
        tuning_hint=tuning_hint,
        status_reason=status_reason,
        summary=summary,
        techniques=[
            {"technique_id": "T1505.003", "technique_name": "Web Shell",
             "tactic_name": "Persistence", "evidence_ids": ["EVID-003"]},
            {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer",
             "tactic_name": "Command and Control", "evidence_ids": ["EVID-005"]},
        ],
        attack_data={
            "version": "19.2",
            "source_url": ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                            "master/enterprise-attack/enterprise-attack-19.2.json"),
            "mapping_method": "rag_llm",
            "retrieval_version": "hybrid-bm25-e5-rrf-v1",
        },
    )


# 사건 증거 목록 — 인용 검증(규칙 4)의 허용 목록
EVIDENCE_CHAIN = [
    {"evidence_id": "EVID-003", "time": "2026-09-14T07:33:20Z", "layer": "web",
     "description": "shell.php 업로드 요청이 200으로 응답됨"},
    {"evidence_id": "EVID-005", "time": "2026-09-14T07:34:12Z", "layer": "system",
     "description": "www-data가 curl로 외부 파일을 내려받음"},
]

ALLOWED_TARGETS = {WEBSHELL_PATH, SRC_IP}
ALLOWED_TECHNIQUE_IDS = {"T1505.003", "T1505", "T1595.002", "T1105"}


class FakeLLM:
    """complete_json()만 흉내 내는 가짜 클라이언트 — 실제 API를 부르지 않는다."""

    def __init__(self, payload: Any = None, *, error: Optional[Exception] = None,
                 model: str = "fake-model") -> None:
        self.payload = payload
        self.error = error
        self.model = model
        self.calls: List[Dict[str, str]] = []

    def complete_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        self.calls.append({"system": system_prompt, "user": user_prompt})
        if self.error is not None:
            raise self.error
        return self.payload
