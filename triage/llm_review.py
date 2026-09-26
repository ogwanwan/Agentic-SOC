"""
triage/llm_review.py — 트리아지 뒷단(LLM): 상위 Incident 를 경량 LLM(Claude Haiku)으로 재검토

트리아지는 2단이다: 앞단=결정론 점수(triage.py), 뒷단=LLM 재검토(이 파일). 파이프라인 기본 경로다.
앞단이 상위(P1~P2)로 올린 사건만 한 번의 호출로 Claude Haiku 에 보내
{investigate: bool, reason: 한 줄} 를 받아 각 Incident 에 llm_investigate·llm_reason 로 붙인다.
점수·정렬·priority 는 건드리지 않는다 — 결정론 라우팅이 진실원이고, LLM 은 "왜 봐야 하나" 한 줄과
의견만 얹는다(재현성 유지, 하류 조사 에이전트가 근거를 읽게).

안전장치(옵션 아님, 에러 처리): ANTHROPIC_API_KEY 없거나 호출/파싱 실패 → 한 줄 알리고 결정론
결과만 그대로 통과. 파이프라인은 절대 안 죽는다.

키: ANTHROPIC_API_KEY 를 .env 에서 SDK 가 알아서 읽는다. 이 코드는 키 값을 보지도 출력하지도 않는다.
"""
import json
import os

try:  # dotenv 선택 의존성 — 다른 도구 모듈과 같은 컨벤션
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

MODEL = "claude-haiku-4-5"
MAX_REVIEW = 20                      # 한 번에 검토할 상위 사건 수 상한(토큰·비용 방어)
REVIEW_PRIORITIES = ("P1", "P2")     # LLM 재검토 대상 우선순위

_SYSTEM = (
    "너는 SOC 트리아지 보조자다. 각 사건 요약(결정론 점수·계층·연결·탐지 사유)을 보고 "
    "보안 분석가가 심층 조사(investigate)해야 하는지 true/false 로 판단하고, "
    "그 이유를 한국어 한 줄로 단다. 반드시 JSON 배열만 출력한다: "
    '[{"incident_id": "...", "investigate": true, "reason": "..."}]. 그 외 텍스트 금지.'
)


def _digest(inc):
    """LLM 에 보낼 최소 요약 — 증거 원문/refs 말고 판단에 필요한 필드만(토큰 절약·프라이버시)."""
    return {
        "incident_id": inc.get("incident_id"),
        "score": inc.get("triage_score"),
        "priority": inc.get("priority"),
        "entity": inc.get("entity"),
        "layers": sorted(set(inc.get("layers", []) or [])),
        "joins": sorted({e.get("join") for e in inc.get("join_path", []) or [] if e.get("join")}),
        "detect_reasons": [s.get("reason") for s in inc.get("seeds", []) or [] if s.get("reason")][:5],
        "score_parts": inc.get("triage_parts"),
    }


def _parse(text):
    """관대한 JSON 파싱: 첫 '[' 부터 첫 완결 배열만 디코드(뒤에 설명·[1] 인용 붙어도 무시)."""
    i = text.find("[")
    if i == -1:
        return []
    try:
        arr, _ = json.JSONDecoder().raw_decode(text[i:])
    except ValueError:
        return []
    return arr if isinstance(arr, list) else []


def _default_call(digests):
    """실제 Anthropic 호출. anthropic SDK + ANTHROPIC_API_KEY(.env) 사용, 한 번의 create 호출."""
    import anthropic  # 지연 import: 패키지 미설치·키 없을 때 결정론-only 로 살아남게
    client = anthropic.Anthropic()   # ANTHROPIC_API_KEY 를 SDK 가 env 에서 읽음(값 노출 없음)
    msg = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=_SYSTEM,
        messages=[{"role": "user", "content": json.dumps(digests, ensure_ascii=False)}],
    )
    text = "".join(b.text for b in msg.content if b.type == "text")
    return _parse(text)


def llm_review(incidents, call=None, priorities=REVIEW_PRIORITIES, max_review=MAX_REVIEW):
    """triage() 결과 상위 사건에 llm_investigate(bool)·llm_reason(str) 를 덧붙인다.

    입력은 triage() 가 이미 만든 복사본 리스트라 제자리에서 필드만 추가한다(순서·점수 불변).
    call: 주입 가능한 호출 함수(digests -> [{incident_id,investigate,reason}]). 테스트/대체용.
          None 이면 실제 Haiku 호출. 키 없거나 예외 발생 시 조용히 결정론-only 로 통과.
    """
    targets = [i for i in incidents if i.get("priority") in priorities][:max_review]
    if not targets:
        return incidents
    if call is None:
        if not os.getenv("ANTHROPIC_API_KEY"):
            print("[triage] ANTHROPIC_API_KEY 없음 → LLM 재검토 생략, 결정론 결과만 사용")
            return incidents            # 키 없음 → 안전장치로 결정론-only
        call = _default_call
    try:
        verdicts = call([_digest(i) for i in targets])
    except Exception as exc:             # 네트워크/한도/파싱 실패 → 파이프라인 유지
        print("[triage] LLM 재검토 생략(%s)" % exc)
        return incidents
    by_id = {v.get("incident_id"): v for v in (verdicts or []) if isinstance(v, dict)}
    for inc in targets:
        v = by_id.get(inc.get("incident_id"))
        if v is None:
            continue
        inv = v.get("investigate")
        if isinstance(inv, str):  # "false"/"true" 문자열도 올바로 해석(비어있지않은 문자열=True 방지)
            inv = inv.strip().lower() in ("true", "1", "yes", "y")
        inc["llm_investigate"] = bool(inv)
        inc["llm_reason"] = (v.get("reason") or "").strip()[:200]
    return incidents
