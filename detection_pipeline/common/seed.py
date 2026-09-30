# common/seed.py - seed 스키마

"""
탐지가 만들어 조사 에이전트에 넘긴다.
- entity      : 무엇을 조사하나 (③ 묶기 키 + ⑤ 조사 시작점)
- source/reason/score_parts/signal_tags : 왜 수상한가 (④ 트리아지 재료)
- evidence_refs : 원본 로그 포인터 (⑩ 역추적 · 발표 방어의 핵심, 반드시 채움)

build_seed(...)로 생성하고, validate(seed)로 검사한다.
"""

# --- 상수 -------------------------------------------------------------------
VALID_ENTITY_TYPES = {"src_ip", "pid", "ppid"}   # 조인 방식 결정
VALID_LAYERS = {"web", "network", "system", "auth"}
VALID_SOURCES = {"sigma", "anomaly", "suricata"}  # 탐지 출처 조합
VALID_SIGNAL_TAGS = {"exec", "webroot", "sensitive", "cloud_creds"}


# --- 생성 -------------------------------------------------------------------
def build_seed(entity_type, entity_value, window, layer,
               source, reason,
               rule_severity=None, deviation=None, layer_count=1,
               signal_tags=None, evidence_refs=None):
    """seed dict 1건을 만든다.

    entity_type : "src_ip"|"pid"|"ppid" — 조인 방식 결정
    window      : [start_iso, end_iso] UTC — 조사 시간 범위
    source      : "sigma"/"anomaly"/"suricata" 중 하나 이상의 조합
    evidence_refs: 원본 로그 포인터 리스트 — 비면 안 됨(환각 방지)
    """
    return {
        # ── 무엇을 가리키나 ──
        "entity": {"type": entity_type, "value": str(entity_value)},
        "window": list(window),
        "layer": layer,
        # ── 왜 수상한가 ──
        "source": list(source),
        "reason": reason,
        "score_parts": {
            "rule_severity": rule_severity,   # Sigma/Suricata 룰 기반 탐지(없으면 None)
            "deviation": deviation,           # anomaly일 때 (없으면 None)
            "layer_count": layer_count,       # 걸친 계층 수
        },
        "signal_tags": list(signal_tags) if signal_tags else [],
        # ── 증거 포인터 ──
        "evidence_refs": list(evidence_refs) if evidence_refs else [],
    }


# --- 검증 -------------------------------------------------------------------
def validate(seed):
    """seed dict가 계약을 지키는지 검사. 문제 있으면 ValueError."""
    if not isinstance(seed, dict):
        raise ValueError("seed는 dict여야 함")

    # entity
    ent = seed.get("entity")
    if not isinstance(ent, dict) or "type" not in ent or "value" not in ent:
        raise ValueError("entity{type,value} 필요")
    if ent["type"] not in VALID_ENTITY_TYPES:
        raise ValueError("잘못된 entity.type: %r" % ent["type"])

    # window
    w = seed.get("window")
    if not (isinstance(w, list) and len(w) == 2):
        raise ValueError("window는 [start_iso, end_iso]")

    # layer
    if seed.get("layer") not in VALID_LAYERS:
        raise ValueError("잘못된 layer: %r" % seed.get("layer"))

    # source
    src = seed.get("source")
    if not (isinstance(src, list) and src and set(src) <= VALID_SOURCES):
        raise ValueError("source는 sigma/anomaly/suricata 조합 리스트")

    # score_parts
    sp = seed.get("score_parts")
    if not isinstance(sp, dict) or "layer_count" not in sp:
        raise ValueError("score_parts{layer_count,...} 필요")

    # signal_tags
    tags = seed.get("signal_tags", [])
    if not isinstance(tags, list) or not (set(tags) <= VALID_SIGNAL_TAGS):
        raise ValueError("signal_tags는 %s 부분집합" % VALID_SIGNAL_TAGS)

    # evidence_refs — 반드시 하나 이상 (환각 방지의 핵심)
    refs = seed.get("evidence_refs")
    if not (isinstance(refs, list) and len(refs) >= 1):
        raise ValueError("evidence_refs는 최소 1개 (모든 seed가 원본을 가리켜야 함)")

    return True


if __name__ == "__main__":
    s = build_seed(
        entity_type="src_ip", entity_value="54.180.11.0",
        window=["2026-09-07T15:34:00Z", "2026-09-07T15:36:30Z"],
        layer="web",
        source=["sigma"],
        reason="wp-login.php 무차별 POST",
        rule_severity="high", layer_count=1,
        signal_tags=["webroot"],
        evidence_refs=["apache_access.log:88213", "apache_access.log:88214"],
    )
    assert validate(s)
    print("seed.py OK:", s)
