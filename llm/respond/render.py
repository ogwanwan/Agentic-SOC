"""대응 권고문 렌더링 — ResponsePlan(JSON) → 사람이 읽는 텍스트 (설계서 9절).

역할
  `<incident_id>_response.txt`를 만든다. **LLM이 txt 전체를 쓰지 않는다** — 코드가 JSON에서
  그리므로 포맷이 항상 같고, 환각이 끼어들 틈이 없다. LLM이 쓴 문장은 [요약]과 각 조치의
  "근거" 줄에만 들어간다(그것도 검증을 통과한 것만).

  상태별 포맷 3종 (설계서 9-2·9-3):
    recommended / recommended_generic   머리말 + 공격 흐름 + 요약 + 조치 + 근거 추적 + 범례
    not_applicable                      오탐 종결 한 줄 + 탐지 룰 튜닝 제안
    deferred / skipped / error          보류·건너뜀 사유 + 확인 필요 목록

  ⚠ 한글 표시폭: 한글·한자·전각기호는 고정폭 글꼴에서도 2칸을 차지한다. str.ljust()는 글자 수로
  세기 때문에 한글이 섞인 줄이 밀린다. 그래서 unicodedata.east_asian_width()로 표시폭을 계산한다.

누가 부르나
  respond/cli.py  process_file()  → render_plan()
"""

from __future__ import annotations

import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[1])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond.labels import (  # noqa: E402
    AUTONOMY_LEGEND,
    LLM_AUTHORED_NOTICE,
    MAPPING_PARTIAL_SUFFIX,
    STATUS_LABELS,
    WARNING_MESSAGES,
    llm_authored_commands,
    status_label,
    warning_message,
)
from respond.models import CATEGORY_IMMEDIATE, CATEGORY_VERIFY, ResponsePlan  # noqa: E402

# 권고문 가로 폭(고정폭 글꼴 기준 칸 수).
# 설계서 9-2 예시는 틀을 60칸으로 그렸지만, 그 예시의 내용 줄 자체가 60칸을 넘는다
# (신뢰도 줄 81칸, 범례 84칸 — 한글을 2칸으로 세면 그렇다). 80칸 터미널에 들어가는 78칸으로 잡고,
# 가장 긴 두 줄(신뢰도·범례)은 두 줄로 나눈다.
WIDTH = 78
RULE = "=" * WIDTH

# 머리말 오른쪽 상태 표시 — 문장은 labels.py가 가지고 있고 여기서 대괄호만 붙인다
STATUS_TAGS = {status: f"[{label}]" for status, label in STATUS_LABELS.items()}

# 범례는 한 줄에 넣으면 84칸이라 세 줄로 나눈다. "L2는 자동 실행하지 않는다"는 설계서 7절이
# 반드시 명시하라고 한 문구다 — labels.AUTONOMY_LEGEND에서 가져오므로 줄여 쓸 수 없다.
LEGEND_LINES = (
    f"[범례] L0 {AUTONOMY_LEGEND['L0']} · L1 {AUTONOMY_LEGEND['L1']}",
    f"       L2 {AUTONOMY_LEGEND['L2']}",
    "       P1 먼저 · P2 보통 · P3 나중 (같은 묶음 안의 실행 순서)",
)


# ----------------------------------------------------------------------
# 한글 표시폭 계산 — str.ljust() 대신 쓴다
# ----------------------------------------------------------------------

def display_width(text: str) -> int:
    """고정폭 글꼴에서 차지하는 칸 수. 한글·한자·전각기호(W/F)는 2칸, 나머지는 1칸.

    East Asian Ambiguous('A', 예: '·', '—')는 글꼴에 따라 1칸이거나 2칸이다. 여기서는 1칸으로
    센다(UTF-8 터미널·웹 고정폭 글꼴의 일반적인 동작). 대시보드가 CJK 글꼴로 2칸을 쓰면
    그 줄만 한 칸씩 밀리므로, 그 경우 이 함수의 'A' 처리만 바꾸면 된다.
    """
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue  # 결합 문자는 폭을 차지하지 않는다
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def pad(text: str, width: int) -> str:
    """표시폭 기준 왼쪽 정렬 — ljust()의 한글 대응판."""
    return text + " " * max(0, width - display_width(text))


def truncate(text: str, width: int, ellipsis: str = "…") -> str:
    """표시폭 기준으로 자른다. 자르면 끝에 생략 기호를 붙인다."""
    if display_width(text) <= width:
        return text
    limit = width - display_width(ellipsis)
    out = ""
    used = 0
    for char in text:
        char_width = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in ("W", "F") else 1)
        if used + char_width > limit:
            break
        out += char
        used += char_width
    return out + ellipsis


def _wrap(text: str, width: int) -> List[str]:
    """표시폭 기준 줄바꿈. 공백으로 끊고, 한 낱말이 폭을 넘으면 글자 단위로 끊는다."""
    lines: List[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}" if current else word
        if display_width(candidate) <= width:
            current = candidate
            continue
        if current:
            lines.append(current)
        while display_width(word) > width:
            cut = truncate(word, width, ellipsis="")
            lines.append(cut)
            word = word[len(cut):]
        current = word
    if current:
        lines.append(current)
    return lines or [""]


# ----------------------------------------------------------------------
# 머리말
# ----------------------------------------------------------------------

def _header(plan: ResponsePlan) -> List[str]:
    tag = STATUS_TAGS.get(plan.response_status, f"[{status_label(plan.response_status)}]")
    title = f" 대응 권고   {plan.incident_id}"
    gap = max(1, WIDTH - display_width(title) - display_width(tag))
    return [RULE, title + " " * gap + tag, RULE]


def _fact_lines(plan: ResponsePlan) -> List[str]:
    """호스트·공격 유형·판정·신뢰도 — 라벨 폭을 맞춰 세로로 정렬한다."""
    label_width = 10
    lines: List[str] = []

    host = plan.host or "-"
    occurred = plan.occurred_at or "-"
    lines.append(f" {pad('호스트', label_width)}{host}   발생  {occurred}")
    if plan.attack_type:
        lines.append(f" {pad('공격 유형', label_width)}{truncate(plan.attack_type, WIDTH - label_width - 2)}")
    lines.append(f" {pad('판정', label_width)}{plan.verdict} / {plan.severity}")

    lines.append(
        f" {pad('신뢰도', label_width)}"
        f"판정 {plan.verdict_confidence:.2f} / 증거누적 {plan.investigation_confidence:.2f}"
    )

    mapping = plan.mapping_status
    if mapping == "partial":
        # 설계서 7절 — partial은 L2를 유지하되 "일부만 확인됨"을 반드시 표기한다
        mapping += f" ({MAPPING_PARTIAL_SUFFIX})"
    lines.append(
        f" {pad('검증', label_width)}원본 추적 {plan.provenance_status} · 매핑 {mapping}"
    )
    return lines


def _warning_lines(plan: ResponsePlan) -> List[str]:
    """매핑 경고(FALLBACK_VERDICT 등)를 머리말 아래 경고 줄로 노출한다 (설계서 4절)."""
    if not plan.warnings:
        return []
    lines = ["", " [경고]"]
    for warning in plan.warnings:
        code = str(warning.get("code") or "").strip()
        message = warning_message(warning)
        for index, chunk in enumerate(_wrap(f"{code}: {message}" if code else message, WIDTH - 4)):
            lines.append(("  ⚠ " if index == 0 else "    ") + chunk)
    return lines


# ----------------------------------------------------------------------
# 본문 구역
# ----------------------------------------------------------------------

def _kill_chain_lines(plan: ResponsePlan) -> List[str]:
    if not plan.kill_chain:
        return []
    lines = ["", " [공격 흐름]"]
    tactic_width = max((display_width(str(s.get("tactic_name") or "")) for s in plan.kill_chain),
                       default=0)
    tactic_width = min(max(tactic_width, 8), 24)
    tech_id_width = max((len(str(s.get("technique_id") or "")) for s in plan.kill_chain), default=9)
    for index, step in enumerate(plan.kill_chain, start=1):
        number = step.get("step") or index
        tactic = pad(truncate(str(step.get("tactic_name") or "-"), tactic_width), tactic_width)
        tech_id = str(step.get("technique_id") or "-").ljust(tech_id_width)
        time = _hhmmss(step.get("time"))
        prefix = f"  {number}. {tactic} {tech_id} "
        # 기법 이름이 길면 시각 칸을 침범하지 않게 자른다
        available = WIDTH - display_width(prefix) - (len(time) + 1 if time else 0)
        tech_name = truncate(str(step.get("technique_name") or ""), max(4, available))
        row = prefix + tech_name
        if time:
            row = f"{pad(row, WIDTH - len(time) - 1)} {time}"
        lines.append(row.rstrip())
    return lines


def _hhmmss(value: Any) -> str:
    """ISO 시각에서 HH:MM:SS만 꺼낸다. 형식이 다르면 빈 문자열(줄을 깨뜨리지 않는다)."""
    text = str(value or "")
    if "T" in text and len(text) >= 19:
        return text[11:19]
    return ""


def _summary_lines(plan: ResponsePlan) -> List[str]:
    if not plan.summary:
        return []
    lines = ["", " [요약]"]
    lines += ["  " + chunk for chunk in _wrap(plan.summary, WIDTH - 2)]
    return lines


def _autonomy_tag(action: Any) -> str:
    """[P1 · L2 · 가역 · LOW] — 우선순위·자율성·가역성·위험도를 한 칸에 모은다.

    하향된 라벨은 "L1←L2"로 표시해 왜 낮아졌는지 보이게 한다(사유는 아래 "등급" 줄).
    """
    label = action.autonomy
    if action.autonomy_downgraded_from:
        label = f"{action.autonomy}←{action.autonomy_downgraded_from}"
    parts = []
    priority = getattr(action, "priority", None)
    if priority:
        parts.append(f"P{priority}")
    parts += [label, "가역" if action.reversible else "비가역", action.risk]
    return "[" + " · ".join(parts) + "]"


# 조치 한 건에 들어가는 산출물 칸 (2026-10-06 팀 합의). 라벨은 모두 두 글자(표시폭 4칸)로
# 맞춰 두 번째 줄 이후의 들여쓰기가 자동으로 정렬된다. 순서를 바꾸면 권고문 순서가 바뀐다.
#   근거 왜 이 조치인가 · 명령 실제 명령어 · 원복 역가능 방법
#   영향 부작용·영향 범위 · 검증 제대로 됐는지 확인하는 방법 · 등급 자동화 등급 근거
_DETAIL_FIELDS = (
    ("명령", "command_hint"),
    ("원복", "rollback"),
    ("영향", "side_effects"),
    ("검증", "verification"),
    ("등급", "autonomy_reason"),
)


def _action_block(number: int, action: Any, *, with_detail: bool = True) -> List[str]:
    """조치 한 건 — 제목·라벨 + 대상·근거·명령·원복·영향·검증·등급.

    [확인 필요] 묶음도 같은 칸을 모두 낸다(2026-10-06 산출물 확정). 비어 있는 칸은 그 줄을
    아예 내지 않는다 — 지어내지 않고, 빈 줄도 남기지 않는다.
    """
    tag = _autonomy_tag(action)
    prefix = f"  {number}. "
    # 제목이 길면 라벨 칸을 침범하지 않게 자른다
    title = truncate(action.title, max(8, WIDTH - display_width(prefix) - display_width(tag) - 1))
    head = prefix + title
    gap = max(1, WIDTH - display_width(head) - display_width(tag))
    lines = [head + " " * gap + tag]
    if not with_detail:
        return lines

    indent = "     "
    body_width = WIDTH - display_width(indent) - 6

    def _field(label: str, value: str, *, wrap: bool = True) -> None:
        """라벨 한 칸. 길면 줄바꿈하고, 둘째 줄부터는 라벨 폭만큼 들여쓴다."""
        text = (value or "").strip()
        if not text:
            return
        # 명령·원복은 자르지 않고 줄바꿈한다 — 잘린 명령을 그대로 붙여 넣으면 사고가 난다
        chunks = _wrap(text, body_width) if wrap else [truncate(text, body_width)]
        lines.append(f"{indent}{label}  {chunks[0]}")
        lines.extend(f"{indent}      {chunk}" for chunk in chunks[1:])

    if action.target:
        # 대상은 값 하나이므로 잘라서 한 줄로 둔다(줄바꿈하면 경로가 둘로 보인다)
        _field("대상", action.target, wrap=False)
    else:
        # 대상이 없는 조치는 "무엇을 확인하라"는 항목이다 — 지어내지 않고 그대로 알린다
        lines.append(f"{indent}대상  (없음 — 담당자가 범위를 정해 확인)")
    _field("근거", action.effective_reason())
    for label, attribute in _DETAIL_FIELDS:
        _field(label, getattr(action, attribute, "") or "")
    return lines


def _action_lines(plan: ResponsePlan) -> List[str]:
    immediate = [a for a in plan.actions if a.category == CATEGORY_IMMEDIATE]
    verify = [a for a in plan.actions if a.category == CATEGORY_VERIFY]
    lines: List[str] = []
    number = 1

    if immediate:
        lines += ["", f" [즉시 조치] {len(immediate)}건"]
        for action in immediate:
            lines += _action_block(number, action)
            number += 1
    if verify:
        lines += ["", f" [확인 필요] {len(verify)}건"]
        for action in verify:
            lines += _action_block(number, action)
            number += 1
    if not immediate and not verify:
        lines += ["", " [조치] 생성된 조치가 없습니다 — 조치 대상을 확보하지 못했습니다.",
                  "        증거를 보존하고 담당자가 직접 확인하십시오."]
    return lines


def _evidence_lines(plan: ResponsePlan) -> List[str]:
    if not plan.evidence_refs:
        return []
    lines = ["", " [근거 추적]"]
    for ref in plan.evidence_refs:
        evidence_id = str(ref.get("evidence_id") or "-")
        time = _hhmmss(ref.get("time"))
        layer = str(ref.get("layer") or "-")
        description = str(ref.get("description") or "")
        raw = ", ".join(str(r) for r in (ref.get("raw_refs") or []))
        head = f"  {evidence_id:<10}{time:<10}{pad(layer, 8)}"
        tail = display_width(raw) + 1 if raw else 0
        body_width = max(4, WIDTH - display_width(head) - tail)
        row = head + truncate(description, body_width)
        if raw:
            row = f"{pad(row, WIDTH - display_width(raw) - 1)} {raw}"
        lines.append(row.rstrip())
    return lines


def _attack_data_lines(plan: ResponsePlan) -> List[str]:
    """어떤 ATT&CK 데이터로 기법을 매핑했는지 (2026-10-06 산출물 확정).

    전체 주소는 78칸을 넘어 줄이 깨지므로 텍스트 권고문에는 버전과 파일명만 적는다.
    원본 주소는 <사건>_response.json의 attack_data.source_url에 그대로 들어가고,
    대시보드는 그 값을 링크로 띄운다.
    """
    data = getattr(plan, "attack_data", None) or {}
    version = str(data.get("version") or "").strip()
    method = str(data.get("mapping_method") or "").strip()
    source_url = str(data.get("source_url") or "").strip()
    if not (version or method or source_url):
        return []

    head = f"MITRE ATT&CK Enterprise v{version}" if version else "MITRE ATT&CK Enterprise"
    if method:
        head += f" ({method})"
    lines = ["", " [ATT&CK 데이터]", "  " + truncate(head, WIDTH - 2)]
    if source_url:
        # 주소 전체 대신 저장소/파일명만 — 어느 파일인지 사람이 알아볼 수 있으면 충분하다
        tail = source_url.split("attack-stix-data/")[-1]
        if tail.startswith("master/"):
            tail = tail[len("master/"):]
        lines.append("  " + truncate(tail, WIDTH - 2))
    return lines


def _llm_notice_lines(plan: ResponsePlan) -> List[str]:
    """명령·원복 문장을 LLM이 쓴 경우의 실행 전 확인 안내 (2026-10-06).

    조치 7칸을 LLM이 쓰기로 했으므로, 사람이 그대로 복사해 실행하는 두 칸(명령·원복)이
    LLM 문장일 때는 권고문에 그 사실을 적는다. llm.py가 환각 대상·파괴적 명령을 걸러내지만,
    마지막 확인은 사람이 한다.
    """
    if not llm_authored_commands(plan):
        return []
    wrapped = _wrap(LLM_AUTHORED_NOTICE, WIDTH - 9)
    lines = ["", " [확인] " + wrapped[0]]
    lines += ["        " + chunk for chunk in wrapped[1:]]
    return lines


def _unknown_lines(plan: ResponsePlan, title: str = "남은 의문") -> List[str]:
    if not plan.remaining_unknowns:
        return []
    lines = ["", f" [{title}]"]
    for item in plan.remaining_unknowns:
        wrapped = _wrap(str(item), WIDTH - 4)
        lines.append("  - " + wrapped[0])
        lines += ["    " + chunk for chunk in wrapped[1:]]
    return lines


def _note_lines(plan: ResponsePlan) -> List[str]:
    if not plan.analyst_note:
        return []
    lines = ["", " [담당자 참고]"]
    lines += ["  " + chunk for chunk in _wrap(plan.analyst_note, WIDTH - 2)]
    return lines


# ----------------------------------------------------------------------
# 상태별 포맷
# ----------------------------------------------------------------------

def _render_recommended(plan: ResponsePlan) -> List[str]:
    lines = _header(plan) + _fact_lines(plan) + _warning_lines(plan)
    lines += _kill_chain_lines(plan)
    lines += _summary_lines(plan)
    lines += _action_lines(plan)
    lines += _evidence_lines(plan)
    lines += _attack_data_lines(plan)
    lines += _unknown_lines(plan)
    lines += _note_lines(plan)
    lines += _llm_notice_lines(plan)
    lines += [""] + [" " + line for line in LEGEND_LINES] + [RULE]
    return lines


def _render_not_applicable(plan: ResponsePlan) -> List[str]:
    """오탐 종결 — 조치 없음 + 탐지 룰 튜닝 제안 (설계서 9-3)."""
    lines = _header(plan) + _fact_lines(plan) + _warning_lines(plan)
    body = plan.summary or "조사 결과 정상 활동으로 확인되어 대응 조치가 필요하지 않습니다."
    lines += ["", " [판단]"]
    lines += ["  " + chunk for chunk in _wrap(body, WIDTH - 2)]
    if plan.tuning_hint:
        lines += ["", " [탐지팀 참고]"]
        lines += ["  " + chunk for chunk in _wrap(plan.tuning_hint, WIDTH - 2)]
    lines += _note_lines(plan)
    lines += [RULE]
    return lines


def _render_deferred(plan: ResponsePlan) -> List[str]:
    """보류 — 위협 여부 확정 불가. remaining_unknowns를 "확인 필요" 목록으로 낸다 (설계서 9-3)."""
    lines = _header(plan) + _fact_lines(plan) + _warning_lines(plan)
    body = plan.summary or "위협 여부를 확정하지 못했습니다. 아래 항목을 확인한 뒤 재판단이 필요합니다."
    lines += ["", " [판단]"]
    lines += ["  " + chunk for chunk in _wrap(body, WIDTH - 2)]
    lines += _unknown_lines(plan, title="확인 필요")
    if not plan.remaining_unknowns:
        lines += ["", " [확인 필요]", "  - 조사 단계에서 남긴 미확인 항목이 없습니다. 담당자가 직접 확인하십시오."]
    lines += _note_lines(plan)
    lines += [RULE]
    return lines


def _render_skipped(plan: ResponsePlan) -> List[str]:
    """조사 미완료·구조 오류 — 사유만 남기고 권고를 만들지 않는다 (설계서 4절)."""
    lines = _header(plan)
    reason = plan.status_reason or "사유가 기록되지 않았습니다."
    lines += ["", " [사유]"]
    lines += ["  " + chunk for chunk in _wrap(reason, WIDTH - 2)]
    if plan.response_status == "skipped":
        _notice = "조사가 끝나지 않은 사건입니다. 조사 큐가 다시 조사한 뒤 대응 권고가 생성됩니다."
        lines += [""] + ["  " + chunk for chunk in _wrap(_notice, WIDTH - 2)]
    lines += [RULE]
    return lines


_RENDERERS = {
    "recommended": _render_recommended,
    "recommended_generic": _render_recommended,
    "not_applicable": _render_not_applicable,
    "deferred": _render_deferred,
    "skipped": _render_skipped,
    "error": _render_skipped,
}


def render_plan(plan: ResponsePlan) -> str:
    """ResponsePlan → 권고문 텍스트. 모든 줄은 표시폭 기준으로 정렬된다."""
    renderer = _RENDERERS.get(plan.response_status, _render_skipped)
    return "\n".join(line.rstrip() for line in renderer(plan)) + "\n"
