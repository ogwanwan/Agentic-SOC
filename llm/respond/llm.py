"""대응 권고 LLM 호출과 응답 검증 (설계서 8절) — "작성은 LLM, 검증은 코드".

역할
  코드가 이미 확정한 ResponsePlan을 받아, LLM에게 **권고 사항 본문 전체**를 쓰게 한다.
    ResponsePlan.summary / ResponsePlan.analyst_note
    Action: reason / command_hint / rollback / side_effects / verification
            / autonomy_reason / priority    ← 2026-10-06 확정: 7칸 전부 LLM이 쓴다
  조치 목록·대상·기법·자율성 등급(L0/L1/L2)·위험도·가역성은 코드(담당 A의 catalog·decide)가
  정한 그대로 둔다. LLM은 그 사실에 **어긋나지 않는 문장**을 쓰는 것까지가 범위다.

  카탈로그가 미리 적어 둔 문장은 버리지 않는다 — **칸별 폴백**으로 남긴다.
  LLM이 쓴 칸은 검증을 통과했을 때만 교체되고, 통과하지 못한 칸은 카탈로그 문장이 그대로
  나간다(그 사실은 run_log.jsonl에 칸 단위로 기록된다). LLM이 통째로 실패해도(API 장애·
  JSON 깨짐) 권고문은 카탈로그 문장으로 반드시 나온다.

근거는 ATT&CK 매핑 파일에서만 (2026-10-06 확정)
  각 조치의 reason은 그 조치가 딸린 기법의 증거(attack_mapping.techniques[].evidence_ids)를
  최소 하나 인용해야 한다. 인용이 없으면 그 칸은 카탈로그 문장으로 되돌린다(규칙 6).
  매핑에 없는 기법 ID·증거 ID를 적으면 그 인용만 지운다(규칙 4·5).

검증 규칙 (설계서 8-3 + 2026-10-06 추가)
  1. 조치의 target이 추출된 대상 집합에 실제로 있는가       → 해당 조치 폐기
  2. LLM이 돌려준 action_id 집합 == 입력 집합인가           → 응답 전체 거절(fallback)
  3. 모든 조치의 모든 칸이 채워졌는가                        → 빈 칸만 카탈로그 문장
  4. 인용한 EVID-*가 evidence_chain에 있는가                 → 그 인용만 제거
  5. technique_id가 attack_mapping.techniques[]에 있는가     → 조치 폐기(조치의 기법) /
                                                               인용 제거(문장 안의 T-번호)
  6. reason이 그 기법의 증거를 인용했는가                     → 그 칸만 카탈로그 문장
  7. 어떤 칸이든 입력에 없는 IP·경로를 적지 않았는가         → 그 칸만 카탈로그 문장
  8. 명령·원복에 파괴적 명령이 없는가(rm·dd·mkfs·로그 삭제) → 그 칸만 카탈로그 문장
  9. 비가역 조치의 원복이 "되돌릴 수 없음"을 말하는가         → 그 칸만 카탈로그 문장
 10. 등급 근거가 코드가 정한 등급과 같은 등급을 말하는가     → 그 칸만 카탈로그 문장
 11. priority가 1~3 정수인가                                 → 카탈로그 값 유지
  1·5(조치의 기법)는 LLM을 부르기 전에, 나머지는 LLM 응답을 보고 적용한다.

  7·8·9가 이 단계에서 가장 중요하다. 권고문의 명령은 **사람이 그대로 복사해 실행한다** —
  환각 경로 한 줄, rm 한 번이 그대로 운영 사고가 된다.

누가 부르나
  respond/cli.py  process_file()  → run_llm_stage()

무엇을 부르나
  respond/prompts/              build_system_prompt(), build_user_prompt()
  respond/investigate_bridge.py build_llm_client(RESPONSE)  — 조사 쪽 클라이언트 재사용
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[1])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond import investigate_bridge  # noqa: E402
from respond.models import Action, ResponsePlan  # noqa: E402
from respond.prompts import build_system_prompt, build_user_prompt  # noqa: E402

# 문장 안의 증거 인용 — "EVID-003" 형태
EVIDENCE_REF_RE = re.compile(r"EVID-\d+")
# 문장 안의 기법 인용 — "T1505.003" 형태
TECHNIQUE_REF_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# 인용을 지운 뒤 남는 빈 괄호·연속 공백 정리용
_EMPTY_PAREN_RE = re.compile(r"[(（]\s*[,，、\s]*[)）]")
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")

# 길이 상한. 설명 칸은 넘으면 자르고, 명령·원복 칸은 넘으면 **버린다**
# (잘린 명령을 그대로 붙여 넣으면 사고가 난다).
MAX_REASON_CHARS = 200
MAX_FIELD_CHARS = 300
MAX_COMMAND_CHARS = 400
MAX_SUMMARY_CHARS = 600

# ----------------------------------------------------------------------
# 규칙 7 — 입력에 없는 IP·경로 탐지
# ----------------------------------------------------------------------

# IP 탐지에 \b를 쓰면 한글 조사가 붙은 "203.0.113.200에서"를 놓친다(한글도 \w라서
# 경계가 생기지 않는다). 숫자·점만 앞뒤로 막는 전후방 탐색을 쓴다.
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# 절대 경로. "http://host/path"의 슬래시와 $(basename ...) 치환은 경로로 세지 않는다.
_ABS_PATH_RE = re.compile(r"(?<![\w$:/])/(?!/)[A-Za-z0-9._\-/*]+")
# URL — 호스트는 따로 검사하고, 경로 검사에서는 URL 전체를 빼낸다
_URL_HOST_RE = re.compile(r"https?://([^/\s\'\"<>()]+)")
_URL_FULL_RE = re.compile(r"https?://[^\s\'\"<>()]+")

# 카탈로그·운영 표준에 이미 나오는 고정 위치 — 사건 대상이 아니라 조치의 작업 공간이다
_WELL_KNOWN_PREFIXES = (
    "/var/quarantine",      # 격리 폴더
    "/var/log",             # 로그 보존
    "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers", "/etc/audit",
    "/etc/fail2ban", "/etc/pam.d", "/etc/ssh", "/etc/apache2", "/etc/nginx",
    "/dev/null",
    "/proc",                # ps 대신 /proc 확인
    "/tmp/",                # 보존 사본 임시 위치
)
_WELL_KNOWN_IPS = ("169.254.169.254",)   # 클라우드 IMDS
# 디렉터리만 적어도 통과시키는 최소 깊이 — "/var"는 막고 "/var/www/html"은 허용한다
_MIN_ANCESTOR_SEGMENTS = 3

# ----------------------------------------------------------------------
# 규칙 8 — 파괴적 명령 차단 (명령·원복 칸에만 적용)
# ----------------------------------------------------------------------

_DESTRUCTIVE_PATTERNS = (
    (re.compile(r"\brm\b"), "rm — 설계 원칙상 삭제가 아니라 격리를 권고한다"),
    (re.compile(r"\bunlink\b"), "unlink — 파일 삭제"),
    (re.compile(r"\bshred\b"), "shred — 복구 불가 삭제"),
    (re.compile(r"\bdd\s+if="), "dd — 디스크 덮어쓰기"),
    (re.compile(r"\bmkfs"), "mkfs — 파일시스템 초기화"),
    (re.compile(r"\btruncate\b"), "truncate — 파일 비우기"),
    (re.compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*777\b"), "chmod 777 — 전체 권한 개방"),
    (re.compile(r"\buserdel\b|\bgroupdel\b"), "userdel/groupdel — 계정 삭제(잠금을 권고한다)"),
    (re.compile(r"\biptables\s+(?:-F|--flush)"), "iptables -F — 방화벽 규칙 전체 삭제"),
    (re.compile(r"\bsystemctl\s+(?:stop|disable|mask)\s+auditd"), "auditd 중단 — 증거 수집 중단"),
    (re.compile(r"\bauditctl\s+-D"), "auditctl -D — 감사 규칙 전체 삭제"),
    (re.compile(r"\bhistory\s+-c"), "history -c — 명령 이력 삭제"),
    (re.compile(r">\s*/dev/(?:sd|nvme|hd)"), "블록 장치 덮어쓰기"),
    (re.compile(r":\s*\(\s*\)\s*\{"), "포크 폭탄 형태"),
)

# ----------------------------------------------------------------------
# 규칙 9 — 비가역 조치의 원복 칸이 반드시 담아야 하는 표현
# ----------------------------------------------------------------------

_IRREVERSIBLE_MARKERS = ("되돌릴 수 없", "되돌릴수 없", "복구 불가", "복구불가",
                          "불가역", "되돌리기 불가", "원복 불가", "원복할 수 없")

# ----------------------------------------------------------------------
# LLM이 채우는 칸 — (응답 키, Action 속성, 길이 상한, 넘으면 자를지)
# ----------------------------------------------------------------------

LLM_ACTION_FIELDS: Tuple[Tuple[str, str, int, bool], ...] = (
    ("reason", "reason", MAX_REASON_CHARS, True),
    ("command", "command_hint", MAX_COMMAND_CHARS, False),
    ("rollback", "rollback", MAX_COMMAND_CHARS, False),
    ("side_effects", "side_effects", MAX_FIELD_CHARS, True),
    ("verification", "verification", MAX_FIELD_CHARS, True),
    ("autonomy_reason", "autonomy_reason", MAX_FIELD_CHARS, True),
)
# 사람이 그대로 실행하는 칸 — 규칙 8(파괴적 명령)을 여기에만 적용한다
_EXECUTABLE_FIELDS = ("command", "rollback")


class LLMStageReport:
    """이번 사건에서 LLM 단계에 무슨 일이 있었는지 — run_log.jsonl에 그대로 기록된다.

    권고문 본문에는 안 나오지만, "왜 이 칸이 LLM 문장이 아니라 카탈로그 문장인지"를
    나중에 확인하는 유일한 근거다.
    """

    def __init__(self) -> None:
        self.llm_called: bool = False
        self.llm_model: Optional[str] = None
        self.used_fallback: bool = False          # 응답 전체를 버리고 카탈로그 문장을 썼는가
        self.fallback_reason: Optional[str] = None
        self.dropped_actions: List[Dict[str, str]] = []     # 폐기된 조치와 사유
        self.stripped_citations: List[Dict[str, str]] = []  # 제거된 증거·기법 인용
        self.reasons_defaulted: List[str] = []    # reason을 카탈로그 문장으로 둔 action_id
        # 칸 단위로 거절된 내역 — [{action_id, field, rule, detail}]
        self.field_fallbacks: List[Dict[str, str]] = []
        # 칸 단위로 반영된 내역 — {action_id: [field, ...]}
        self.fields_accepted: Dict[str, List[str]] = {}
        self.notes: List[str] = []

    def reject_field(self, action_id: str, field: str, rule: str, detail: str) -> None:
        self.field_fallbacks.append(
            {"action_id": action_id, "field": field, "rule": rule, "detail": detail})

    def accept_field(self, action_id: str, field: str) -> None:
        self.fields_accepted.setdefault(action_id, []).append(field)

    def rejected_fields(self, action_id: str) -> List[str]:
        return [f["field"] for f in self.field_fallbacks if f["action_id"] == action_id]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "llm_called": self.llm_called,
            "llm_model": self.llm_model,
            "used_fallback": self.used_fallback,
            "fallback_reason": self.fallback_reason,
            "dropped_actions": self.dropped_actions,
            "stripped_citations": self.stripped_citations,
            "reasons_defaulted": self.reasons_defaulted,
            "field_fallbacks": self.field_fallbacks,
            "fields_accepted": self.fields_accepted,
            "notes": self.notes,
        }


# ----------------------------------------------------------------------
# LLM 호출 전 검증 — 규칙 1·5 (코드가 만든 조치 자체를 본다)
# ----------------------------------------------------------------------

def validate_actions(
    plan: ResponsePlan,
    *,
    allowed_targets: Optional[Set[str]] = None,
    allowed_technique_ids: Optional[Set[str]] = None,
    report: Optional[LLMStageReport] = None,
) -> ResponsePlan:
    """규칙 1·5 — 대상·기법이 실제 출처에 있는 조치만 남긴다. plan을 제자리에서 고친다.

    allowed_targets      담당 A의 entities.py가 뽑은 조치 대상 집합. None이면 검사하지 않는다
                         (추출 결과를 넘겨받지 못한 경우 — 검사를 건너뛴 사실을 notes에 남긴다).
    allowed_technique_ids attack_mapping.techniques[]의 technique_id 집합. None이면 검사하지 않는다.

    target이 None인 조치(대상 없는 "확인 필요" 항목)는 검사 대상이 아니다 — 지울 값이 없다.
    """
    report = report or LLMStageReport()
    kept: List[Action] = []

    if allowed_targets is None:
        report.notes.append("조치 대상 검증 건너뜀 — 추출된 대상 집합을 받지 못함")
    if allowed_technique_ids is None and any(a.technique_id for a in plan.actions):
        report.notes.append("기법 검증 건너뜀 — 매핑 기법 집합을 받지 못함")

    for action in plan.actions:
        # 규칙 1 — 대상이 실제 추출 결과에 있는가 (대상 없는 점검 항목은 통과)
        # 2026-10-06 버그 수정 — decide.py는 대상 없는 조치의 target을 None이 아니라
        # ""(빈 문자열)로 둔다(_build_action 참고). "is not None"으로 검사하면 그런
        # 점검 항목이 전부 '대상이 추출 집합에 없다'며 드롭됐다(target=''이 어떤
        # allowed_targets에도 없으니까). 대상이 아예 없는 조치는 검사할 대상이 없다는
        # 뜻이므로 빈 문자열도 None과 같이 취급한다(docstring의 원래 의도대로).
        if action.target and allowed_targets is not None:
            if action.target not in allowed_targets:
                report.dropped_actions.append({
                    "action_id": action.action_id,
                    "title": action.title,
                    "rule": "target_not_in_sources",
                    "detail": f"조치 대상 {action.target!r}이 추출된 대상 집합에 없음",
                })
                continue
        # 규칙 5 — 기법 환각 방지
        if action.technique_id and allowed_technique_ids is not None:
            if action.technique_id not in allowed_technique_ids:
                report.dropped_actions.append({
                    "action_id": action.action_id,
                    "title": action.title,
                    "rule": "technique_not_mapped",
                    "detail": f"{action.technique_id}이 attack_mapping.techniques[]에 없음",
                })
                continue
        kept.append(action)

    plan.actions = kept
    return plan


# ----------------------------------------------------------------------
# 칸 하나를 검증하는 데 쓰는 도구들
# ----------------------------------------------------------------------

def _clean_text(value: Any, limit: int, *, truncate: bool = True) -> Optional[str]:
    """LLM이 준 값이 쓸 수 있는 문자열이면 다듬어서, 아니면 None.

    truncate=False면 상한을 넘을 때 자르지 않고 None을 돌려준다(명령·원복 칸).
    """
    if not isinstance(value, str):
        return None
    text = " ".join(value.split()).strip()
    if not text:
        return None
    if len(text) > limit:
        if not truncate:
            return None
        text = text[:limit].rstrip() + "…"
    return text


def _strip_unknown_refs(
    text: str, pattern: "re.Pattern[str]", known: Set[str]
) -> Tuple[str, List[str]]:
    """인용 표시 중 허용 목록에 없는 것을 지운다. 문장 자체는 살린다."""
    if not pattern.search(text):
        return text, []

    removed: List[str] = []

    def _replace(match: "re.Match[str]") -> str:
        ref = match.group(0)
        if ref in known:
            return ref
        removed.append(ref)
        return ""

    cleaned = pattern.sub(_replace, text)
    if removed:
        cleaned = _EMPTY_PAREN_RE.sub("", cleaned)
        # 인용을 지우면서 생긴 ", )" / "( ," 같은 자투리 정리
        cleaned = re.sub(r"[(（]\s*[,，、]\s*", "(", cleaned)
        cleaned = re.sub(r"\s*[,，、]\s*[)）]", ")", cleaned)
        cleaned = _MULTI_SPACE_RE.sub(" ", cleaned).strip()
        cleaned = re.sub(r"\s+([.。])", r"\1", cleaned)
    return cleaned, removed


def strip_unknown_citations(
    text: str, known_evidence_ids: Set[str]
) -> Tuple[str, List[str]]:
    """규칙 4 — 인용한 EVID-* 중 evidence_chain에 없는 것을 지운다.

    문장 자체는 살린다(인용만 틀렸다고 근거 문장을 통째로 버리면 권고문이 빈약해진다).
    인용을 지운 뒤 "( )"처럼 남은 빈 괄호와 겹공백을 정리한다.
    """
    return _strip_unknown_refs(text, EVIDENCE_REF_RE, known_evidence_ids)


def strip_unknown_techniques(
    text: str, known_technique_ids: Set[str]
) -> Tuple[str, List[str]]:
    """규칙 5(문장 안의 인용) — 매핑되지 않은 T-번호를 지운다."""
    return _strip_unknown_refs(text, TECHNIQUE_REF_RE, known_technique_ids)


def unknown_tokens(text: str, allowed_targets: Set[str]) -> List[str]:
    """규칙 7 — 문장에 적힌 IP·절대 경로 중 입력에 없는 것을 찾는다.

    허용하는 것
      - 추출된 조치 대상 그 자체
      - 조치 대상의 상위 디렉터리(최소 3단계: "/var/www/html"은 허용, "/var"는 거절)
      - 카탈로그·운영 표준에 나오는 고정 위치(/var/quarantine, /etc/sudoers, IMDS 주소 …)

    URL은 호스트만 검사하고(도메인 환각 차단) 경로 부분은 검사에서 뺀다 —
    "http://host/latest/meta-data"의 "/latest/..."를 서버 경로로 오해하지 않기 위해서다.
    """
    found: List[str] = []

    for host in _URL_HOST_RE.findall(text):
        host = host.split("@")[-1].split(":")[0]
        if host in allowed_targets or host in _WELL_KNOWN_IPS:
            continue
        found.append(host)
    text = _URL_FULL_RE.sub(" ", text)

    for ip in _IPV4_RE.findall(text):
        if ip in allowed_targets or ip in _WELL_KNOWN_IPS:
            continue
        found.append(ip)

    for path in _ABS_PATH_RE.findall(text):
        candidate = path.rstrip("/.,);")
        if not candidate or candidate in allowed_targets:
            continue
        if candidate.startswith(_WELL_KNOWN_PREFIXES):
            continue
        # 대상의 상위 디렉터리인가 (웹루트 점검처럼 범위를 넓게 적는 경우)
        depth = len([seg for seg in candidate.split("/") if seg])
        if depth >= _MIN_ANCESTOR_SEGMENTS and any(
            target.startswith(candidate.rstrip("/") + "/") for target in allowed_targets
        ):
            continue
        found.append(candidate)

    return sorted(set(found))


def destructive_hits(text: str) -> List[str]:
    """규칙 8 — 명령·원복 칸에 들어가면 안 되는 파괴적 명령을 찾는다."""
    return [label for pattern, label in _DESTRUCTIVE_PATTERNS if pattern.search(text)]


def _validate_field(
    action: Action,
    key: str,
    text: str,
    *,
    allowed_targets: Optional[Set[str]],
    known_evidence_ids: Set[str],
    known_technique_ids: Optional[Set[str]],
    report: LLMStageReport,
) -> Optional[str]:
    """칸 하나를 검증한다. 통과하면 쓸 문장, 거절하면 None(카탈로그 문장을 그대로 둔다)."""
    # 규칙 4·5 — 없는 증거·기법 인용 제거
    text, removed_evidence = strip_unknown_citations(text, known_evidence_ids)
    for ref in removed_evidence:
        report.stripped_citations.append(
            {"action_id": action.action_id, "field": key, "evidence_id": ref})
    if known_technique_ids is not None:
        text, removed_techniques = strip_unknown_techniques(text, known_technique_ids)
        for ref in removed_techniques:
            report.stripped_citations.append(
                {"action_id": action.action_id, "field": key, "technique_id": ref})
    text = text.strip()
    if not text:
        report.reject_field(action.action_id, key, "empty_after_citation_strip",
                             "인용을 지우고 나니 남는 문장이 없음")
        return None

    # 규칙 7 — 입력에 없는 IP·경로
    if allowed_targets is not None:
        unknown = unknown_tokens(text, allowed_targets)
        if unknown:
            report.reject_field(
                action.action_id, key, "unknown_target_token",
                f"입력에 없는 대상 {', '.join(unknown)}을 적음")
            return None

    # 규칙 8 — 파괴적 명령 (사람이 그대로 실행하는 칸에만)
    if key in _EXECUTABLE_FIELDS:
        hits = destructive_hits(text)
        if hits:
            report.reject_field(action.action_id, key, "destructive_command", "; ".join(hits))
            return None

    # 규칙 9 — 비가역 조치의 원복은 "되돌릴 수 없음"을 말해야 한다
    if key == "rollback" and not action.reversible:
        if not any(marker in text for marker in _IRREVERSIBLE_MARKERS):
            report.reject_field(
                action.action_id, key, "irreversible_mismatch",
                "비가역 조치인데 되돌리는 절차를 적었음(되돌릴 수 없음을 명시해야 함)")
            return None

    # 규칙 10 — 등급 근거는 코드가 정한 등급과 같은 등급을 말해야 한다
    if key == "autonomy_reason":
        allowed_levels = {action.autonomy}
        if action.autonomy_downgraded_from:
            allowed_levels.add(action.autonomy_downgraded_from)
        mentioned = set(re.findall(r"\bL[012]\b", text))
        if mentioned - allowed_levels:
            report.reject_field(
                action.action_id, key, "autonomy_mismatch",
                f"코드가 정한 등급은 {action.autonomy}인데 "
                f"{', '.join(sorted(mentioned - allowed_levels))}을 말함")
            return None

    return text


def _has_mapping_evidence(action: Action, reason: Optional[str], report: LLMStageReport) -> bool:
    """규칙 6 — reason이 그 기법의 증거(attack_mapping)를 인용했는가.

    조치에 매핑 증거가 없으면(폴백 카탈로그로 만든 일반 조치) 요구하지 않는다.
    """
    if not action.evidence_ids:
        return True
    if not reason:
        return False
    cited = set(EVIDENCE_REF_RE.findall(reason))
    if cited & {str(e) for e in action.evidence_ids}:
        return True
    report.reject_field(
        action.action_id, "reason", "missing_mapping_evidence",
        f"기법 근거({', '.join(str(e) for e in action.evidence_ids)}) 중 "
        "어느 것도 인용하지 않음")
    return False


# ----------------------------------------------------------------------
# LLM 응답 검증 — 규칙 2·3·4·6·7·8·9·10·11
# ----------------------------------------------------------------------

def apply_llm_payload(
    plan: ResponsePlan,
    payload: Dict[str, Any],
    *,
    known_evidence_ids: Set[str],
    report: LLMStageReport,
    allowed_targets: Optional[Set[str]] = None,
    known_technique_ids: Optional[Set[str]] = None,
) -> bool:
    """LLM 응답(dict)을 검증해 plan에 반영한다. 응답 전체를 거절하면 False.

    규칙 2 — action_id 집합이 입력과 정확히 같아야 한다. 하나라도 빠지거나 없는 id가 섞이면
    **응답 전체를 버린다**. 일부만 받아들이면 "LLM이 조치를 지운" 결과가 조용히 통과한다.

    그 밖의 규칙은 **칸 단위**로 적용한다 — 거절된 칸만 카탈로그 문장이 그대로 남는다.
    """
    if not isinstance(payload, dict):
        report.fallback_reason = "LLM 응답이 JSON 객체가 아님"
        return False

    raw_actions = payload.get("actions")
    if not isinstance(raw_actions, list):
        report.fallback_reason = "LLM 응답에 actions 배열이 없음"
        return False

    returned: Dict[str, Any] = {}
    for item in raw_actions:
        if not isinstance(item, dict):
            report.fallback_reason = "actions 원소가 객체가 아님"
            return False
        action_id = item.get("action_id")
        if not isinstance(action_id, str):
            report.fallback_reason = "actions 원소에 action_id 문자열이 없음"
            return False
        if action_id in returned:
            report.fallback_reason = f"action_id 중복: {action_id}"
            return False
        returned[action_id] = item

    expected = set(plan.action_ids())
    got = set(returned)
    if expected != got:
        missing = sorted(expected - got)
        extra = sorted(got - expected)
        report.fallback_reason = (
            "LLM이 돌려준 action_id 집합이 입력과 다름 "
            f"(빠짐={missing or '-'}, 없는 id={extra or '-'})"
        )
        return False

    # 여기부터는 받아들인다 — 나머지 규칙은 조치·칸 단위로 처리한다
    for action in plan.actions:
        item = returned[action.action_id]
        accepted: List[str] = []

        for key, attribute, limit, truncate in LLM_ACTION_FIELDS:
            raw = _clean_text(item.get(key), limit, truncate=truncate)
            if raw is None:
                # 규칙 3 — 빈 칸(또는 상한을 넘긴 명령)은 카탈로그 문장을 그대로 둔다
                report.reject_field(action.action_id, key, "missing_or_too_long",
                                     "칸이 비었거나 길이 상한을 넘김")
                continue
            text = _validate_field(
                action, key, raw,
                allowed_targets=allowed_targets,
                known_evidence_ids=known_evidence_ids,
                known_technique_ids=known_technique_ids,
                report=report,
            )
            if text is None:
                continue
            # 규칙 6 — reason은 그 기법의 증거를 인용해야 한다
            if key == "reason" and not _has_mapping_evidence(action, text, report):
                continue
            setattr(action, attribute, text)
            accepted.append(key)
            report.accept_field(action.action_id, key)

        # 규칙 11 — priority는 1~3 정수만. 아니면 카탈로그 값을 그대로 둔다
        raw_priority = item.get("priority")
        if isinstance(raw_priority, bool) or not isinstance(raw_priority, int):
            report.reject_field(action.action_id, "priority", "not_an_integer",
                                 f"priority={raw_priority!r}")
        elif raw_priority not in (1, 2, 3):
            report.reject_field(action.action_id, "priority", "out_of_range",
                                 f"priority={raw_priority}")
        else:
            action.priority = raw_priority
            accepted.append("priority")
            report.accept_field(action.action_id, "priority")

        action.llm_fields = accepted
        if "reason" not in accepted:
            # render는 effective_reason()으로 카탈로그 기본 문장을 쓴다
            action.reason = None
            report.reasons_defaulted.append(action.action_id)

    plan.summary = _accept_plan_text(
        payload.get("summary"), "summary",
        known_evidence_ids=known_evidence_ids, allowed_targets=allowed_targets, report=report,
    )
    plan.analyst_note = _accept_plan_text(
        payload.get("analyst_note"), "analyst_note",
        known_evidence_ids=known_evidence_ids, allowed_targets=allowed_targets, report=report,
    )
    return True


def _accept_plan_text(
    value: Any,
    key: str,
    *,
    known_evidence_ids: Set[str],
    allowed_targets: Optional[Set[str]],
    report: LLMStageReport,
) -> Optional[str]:
    """사건 단위 문장(summary·analyst_note) 검증 — 인용 정리 + 규칙 7."""
    text = _clean_text(value, MAX_SUMMARY_CHARS)
    if not text:
        return None
    text, removed = strip_unknown_citations(text, known_evidence_ids)
    for ref in removed:
        report.stripped_citations.append(
            {"action_id": f"({key})", "field": key, "evidence_id": ref})
    text = text.strip()
    if not text:
        return None
    if allowed_targets is not None:
        unknown = unknown_tokens(text, allowed_targets)
        if unknown:
            report.reject_field(f"({key})", key, "unknown_target_token",
                                 f"입력에 없는 대상 {', '.join(unknown)}을 적음")
            return None
    return text


def apply_fallback(plan: ResponsePlan, report: LLMStageReport) -> None:
    """LLM 없이 카탈로그의 고정 문장으로만 권고문을 만든다(설계서 8-2).

    카탈로그 값은 decide.py가 이미 모든 칸에 넣어 두었으므로, 여기서 할 일은
    "LLM이 쓴 칸이 없다"고 표시하는 것뿐이다. Action.reason은 None으로 두고
    render가 effective_reason()으로 default_reason을 쓴다.
    """
    report.used_fallback = True
    for action in plan.actions:
        action.reason = None
        action.llm_fields = []
    plan.analyst_note = None


# ----------------------------------------------------------------------
# 진입점
# ----------------------------------------------------------------------

def run_llm_stage(
    plan: ResponsePlan,
    *,
    evidence_chain: Sequence[Dict[str, Any]] = (),
    allowed_targets: Optional[Set[str]] = None,
    allowed_technique_ids: Optional[Set[str]] = None,
    llm_client: Any = None,
) -> LLMStageReport:
    """조치 검증 → LLM 1회 호출 → 칸별 검증 → 거절된 칸만 카탈로그 문장 유지.

    llm_client를 넘기면 그것을 쓰고(테스트·main.py 재사용), 없으면 RESPONSE_* 설정으로 만든다.
    어떤 경우에도 예외를 올리지 않는다 — 권고문은 반드시 나와야 한다.
    """
    report = LLMStageReport()

    # 규칙 1·5 — LLM을 부르기 전에 조치 자체를 거른다
    validate_actions(
        plan,
        allowed_targets=allowed_targets,
        allowed_technique_ids=allowed_technique_ids,
        report=report,
    )

    # 조치가 실리지 않는 상태(오탐·보류·건너뜀)는 LLM을 부르지 않는다 — 고정 문구로 나간다
    if not plan.has_actions():
        report.notes.append(f"LLM 호출 안 함 — response_status={plan.response_status}")
        return report

    known_evidence_ids = {
        str(e.get("evidence_id")) for e in (evidence_chain or []) if e.get("evidence_id")
    }

    client = llm_client
    if client is None:
        try:
            client = investigate_bridge.build_llm_client()
        except Exception as exc:  # 설정 누락·역할 미등록·키 없음 — 권고문은 계속 만든다
            report.fallback_reason = f"LLM 클라이언트 준비 실패: {exc}"
            apply_fallback(plan, report)
            return report

    report.llm_model = getattr(client, "model", None)

    try:
        payload = client.complete_json(
            build_system_prompt(),
            build_user_prompt(plan, list(evidence_chain or [])),
        )
        report.llm_called = True
    except Exception as exc:
        # LLMUnavailableError(일시 오류)·DecisionError(JSON 깨짐·거절)·그 밖의 오류 모두 같은 처리
        try:
            unavailable = investigate_bridge.llm_unavailable_error()
        except Exception:  # pragma: no cover - bridge 자체가 안 되는 환경
            unavailable = ()
        kind = "LLM API 일시 오류" if unavailable and isinstance(exc, unavailable) else "LLM 호출 실패"
        report.fallback_reason = f"{kind}: {exc}"
        apply_fallback(plan, report)
        return report

    if not apply_llm_payload(
        plan, payload,
        known_evidence_ids=known_evidence_ids,
        report=report,
        allowed_targets=allowed_targets,
        known_technique_ids=allowed_technique_ids,
    ):
        apply_fallback(plan, report)

    return report
