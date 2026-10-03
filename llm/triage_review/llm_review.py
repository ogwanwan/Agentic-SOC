"""
triage/llm_review.py — 트리아지 뒷단(LLM): 상위 Incident 를 경량 LLM(기본 Claude Haiku)으로 재검토

트리아지는 2단이다: 앞단=결정론 점수(triage.py), 뒷단=LLM 재검토(이 파일). 파이프라인 기본 경로다.
앞단이 상위(P1~P2)로 올린 사건만 한 번의 호출로 Claude Haiku 에 보내
{investigate: bool, reason: 한 줄} 를 받아 각 Incident 에 llm_investigate·llm_reason 로 붙인다.
점수·정렬·priority 는 건드리지 않는다 — 결정론 라우팅이 진실원이고, LLM 은 "왜 봐야 하나" 한 줄과
의견만 얹는다(재현성 유지, 하류 조사 에이전트가 근거를 읽게).

안전장치(옵션 아님, 에러 처리): 키 없음·설정 오류·호출/파싱 실패 → 한 줄 알리고 결정론
결과만 그대로 통과. 파이프라인은 절대 안 죽는다.

키: ANTHROPIC_API_KEY 를 .env 에서 SDK 가 알아서 읽는다. 이 코드는 키 값을 보지도 출력하지도 않는다.
모델 설정: 아래 TRIAGE_* 환경변수(루트 .env 를 조사 에이전트와 같이 쓰므로 TRIAGE_ 접두어만 읽는다).
"""
import json
import os

try:  # dotenv 선택 의존성 — 다른 도구 모듈과 같은 컨벤션
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# 모델 설정 — 호출할 때마다 읽는다(.env 만 고쳐 모델/강도를 바꿀 수 있게). 비우면 아래 기본값.
#   TRIAGE_CLAUDE_MODEL  비우면 claude-sonnet-5 (트리아지 비교 평가로 선정: 위협 놓침 0, 일관성 최고)
#   TRIAGE_EFFORT        추론 강도(output_config.effort). 비우면 low
#   TRIAGE_MAX_TOKENS    출력 한도(sonnet-5 는 thinking 토큰도 포함). 비우면 16000
# 키: TRIAGE_ANTHROPIC_API_KEY 먼저, 없으면 공용 ANTHROPIC_API_KEY (단계별 접두어 규약, 값은 출력 안 함).
DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_EFFORT = "low"
DEFAULT_MAX_TOKENS = 16000
API_KEY_ENV_NAMES = ("TRIAGE_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")   # 앞에서부터 값이 있는 첫 이름
MAX_REVIEW = 20                      # 한 번에 검토할 상위 사건 수 상한(토큰·비용 방어)
REVIEW_PRIORITIES = ("P1", "P2")     # LLM 재검토 대상 우선순위

_SYSTEM = (
    "너는 SOC 트리아지 보조자다. 각 사건 요약(점수·계층·연결·탐지 사유)과 evidence(실제 실행 명령어·"
    "요청 원문)를 보고 보안 분석가가 심층 조사(investigate)해야 하는지 true/false 로 판단한다. "
    "evidence 의 실제 명령을 근거로 정상 동작(예: --version 체크, 정상 배포)인지 공격(예: 웹셸 명령·"
    "외부 다운로드·권한상승)인지 가려라. 이유는 한국어 한 줄. 반드시 JSON 배열만 출력한다: "
    '[{"incident_id": "...", "investigate": true, "reason": "..."}]. 그 외 텍스트 금지.'
)

_EVIDENCE_MAX = 6      # 사건당 LLM 에 줄 증거 줄 수
_LINE_MAX = 160        # 증거 한 줄 최대 길이
_FILE_MAX = 3          # 증거 중 파일 이벤트(openat·unlink 등) 줄 상한 — 경로가 줄마다 달라 6줄을 다 채워 명령 줄을 밀어내는 것 방지


def _file_tail(ev):
    """system 파일 이벤트면 "syscall 경로", 아니면 "". 경로가 곧 증거 — 정상 로그 기록과 웹셸 삭제가 같은 줄로 보이던 문제.
    execve 의 path 는 실행 파일이라 args 와 겹쳐서 뺀다."""
    ld = ev.get("layer_data", {}) or {}
    sc, path = ld.get("syscall"), ld.get("path") or (ld.get("paths") or [None])[0]
    if ev.get("layer") == "system" and sc and sc != "execve" and isinstance(path, str):
        return "%s %s" % (sc, path)
    return ""


def _evidence_line(ev):
    """이벤트 → 판단용 한 줄(계층별 핵심 필드). exec_args 가 list 여도 안전 처리."""
    ld = ev.get("layer_data", {}) or {}
    layer = ev.get("layer", "?")
    if layer == "system":
        args = ld.get("exec_args") or ld.get("argv") or ""
        if isinstance(args, (list, tuple)):
            args = " ".join(str(a) for a in args)
        return " ".join(x for x in ("[system]", ld.get("comm") or ld.get("exe") or "", args, _file_tail(ev)) if x)
    if layer == "web":
        return ("[web] %s %s %s" % (ld.get("method", ""), ld.get("path", ""), ld.get("status", ""))).strip()
    if layer == "network":
        return ("[network] %s %s" % (ld.get("method", ""), ld.get("url_path") or ld.get("url", ""))).strip()
    if layer == "auth":
        # 누가(src_user)·무슨 명령(command)을 쳤는지가 sudo 시도 판단의 핵심 — 예전엔 "[auth] None user=root" 만 보였다.
        head = " ".join(x for x in (ld.get("event"), ld.get("method")) if x)
        extra = "".join(" %s=%s" % (k, ld[k]) for k in ("src_user", "command") if ld.get(k))
        return ("[auth] %s user=%s%s" % (head, ld.get("user") or ld.get("invalid_user", ""), extra)).strip()
    return "[%s]" % layer


def _digest(inc, by_ref=None):
    """LLM 에 보낼 요약 + evidence(실제 명령어). by_ref(raw_ref→event) 있으면 원문 명령을 붙인다."""
    d = {
        "incident_id": inc.get("incident_id"),
        "score": inc.get("triage_score"),
        "priority": inc.get("priority"),
        "entity": inc.get("entity"),
        "layers": sorted(set(inc.get("layers", []) or [])),
        "joins": sorted({e.get("join") for e in inc.get("join_path", []) or [] if e.get("join")}),
        "detect_reasons": [s.get("reason") for s in inc.get("seeds", []) or [] if s.get("reason")][:5],
        "score_parts": inc.get("triage_parts"),
    }
    if by_ref:
        refs = []
        for s in inc.get("seeds", []) or []:      # 탐지 근거 줄 우선
            refs += (s.get("evidence_refs") or [])
        refs += (inc.get("members", []) or [])     # 그다음 나머지 멤버
        seen, cmds, files = set(), [], 0
        for r in refs:
            if r in seen:
                continue
            seen.add(r)
            ev = by_ref.get(r)
            if not ev:
                continue
            is_file = bool(_file_tail(ev))
            if is_file and files >= _FILE_MAX:
                continue
            line = _evidence_line(ev)[:_LINE_MAX]
            if line and line not in cmds:
                cmds.append(line)
                files += is_file
            if len(cmds) >= _EVIDENCE_MAX:
                break
        d["evidence"] = cmds
    return d


def _parse(text):
    """관대한 JSON 파싱: 첫 '[' 부터 완결 배열을 디코드(뒤 설명·[1] 인용 무시).

    배열이 잘려(max_tokens 초과 등) 통째로는 못 읽으면, 완결된 {..} 객체만이라도 하나씩 긁어
    살린다(0건으로 전부 버리지 않게 — 배치 일부라도 판정 반영)."""
    i = text.find("[")
    if i == -1:
        return []
    dec = json.JSONDecoder()
    try:
        arr, _ = dec.raw_decode(text[i:])
        if isinstance(arr, list):
            return arr
    except ValueError:
        pass
    # 구제: 잘린 배열에서 완결 객체만 순서대로 추출
    out, s = [], text[i + 1:]
    while True:
        j = s.find("{")
        if j == -1:
            break
        try:
            obj, end = dec.raw_decode(s[j:])
        except ValueError:
            break
        if isinstance(obj, dict):
            out.append(obj)
        s = s[j + end:]
    return out


def _api_key_name():
    """쓸 API 키의 환경변수 이름(TRIAGE_ 전용 → 공용 순서). 둘 다 없으면 None."""
    return next((n for n in API_KEY_ENV_NAMES if (os.getenv(n) or "").strip()), None)


def _settings():
    """TRIAGE_* 환경변수 → 호출 설정(비우면 기본값). 잘못된 숫자는 ValueError(llm_review 가 잡아 결정론-only)."""
    return {
        "model": (os.getenv("TRIAGE_CLAUDE_MODEL") or "").strip() or DEFAULT_MODEL,
        "effort": (os.getenv("TRIAGE_EFFORT") or "").strip().lower() or DEFAULT_EFFORT,
        "max_tokens": int(os.getenv("TRIAGE_MAX_TOKENS") or 0) or DEFAULT_MAX_TOKENS,
    }


def _request(digests, cfg):
    """Anthropic 호출 1회 → {text, truncated, max_tokens}."""
    user = json.dumps(digests, ensure_ascii=False)
    import anthropic  # 지연 import: 패키지 미설치·키 없을 때 결정론-only 로 살아남게
    extra = {"output_config": {"effort": cfg["effort"]}} if cfg["effort"] else {}
    msg = anthropic.Anthropic(api_key=os.getenv(_api_key_name())).messages.create(   # 키 값은 출력 안 함
        model=cfg["model"],
        max_tokens=cfg["max_tokens"],
        system=_SYSTEM,
        messages=[{"role": "user", "content": user}],
        **extra,
    )
    return {"text": "".join(b.text for b in msg.content if b.type == "text"),
            "truncated": msg.stop_reason == "max_tokens", "max_tokens": cfg["max_tokens"]}


def _default_call(digests, cfg=None):
    """실제 LLM 호출 1회 → 판정 리스트. 공급자·모델·추론 강도·출력 한도는 TRIAGE_* 환경변수(_settings)."""
    res = _request(digests, cfg or _settings())
    if res["truncated"]:
        print("[triage] 경고: 출력 한도(%d 토큰)에서 응답이 잘림" % res["max_tokens"])
    return _parse(res["text"])


def llm_review(incidents, events=None, call=None, priorities=REVIEW_PRIORITIES, max_review=MAX_REVIEW):
    """triage() 결과 상위 사건에 llm_investigate(bool)·llm_reason(str) 를 덧붙인다.

    입력은 triage() 가 이미 만든 복사본 리스트라 제자리에서 필드만 추가한다(순서·점수 불변).
    events: 정규화 이벤트 리스트. 주면 raw_ref→명령어를 digest 에 실어 LLM 오탐 판별을 정밀화.
    call: 주입 가능한 호출 함수(digests -> [{incident_id,investigate,reason}]). 테스트/대체용.
          None 이면 TRIAGE_* 설정대로 실제 호출. 키 없거나 예외 발생 시 조용히 결정론-only 로 통과.
    """
    targets = [i for i in incidents if i.get("priority") in priorities][:max_review]
    if not targets:
        return incidents
    if call is None:
        try:
            cfg = _settings()
        except ValueError as exc:       # 설정 오류 → 안전장치로 결정론-only
            print("[triage] LLM 설정 오류(%s) → LLM 재검토 생략, 결정론 결과만 사용" % exc)
            return incidents
        key_name = _api_key_name()
        if not key_name:
            print("[triage] %s 없음 → LLM 재검토 생략, 결정론 결과만 사용" % " / ".join(API_KEY_ENV_NAMES))
            return incidents            # 키 없음 → 안전장치로 결정론-only
        print("[triage] LLM 재검토 모델: %s effort=%s (키: %s)" % (cfg["model"], cfg["effort"] or "-", key_name))
        call = lambda digests: _default_call(digests, cfg)  # noqa: E731
    by_ref = {e["raw_ref"]: e for e in events if e.get("raw_ref")} if events else None
    try:
        verdicts = call([_digest(i, by_ref) for i in targets])
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
