"""
correlate/dedup.py — 사건 파편 병합 (사건묶기 뒤단계)

union-find 는 raw_ref 연결만 보므로, 같은 스캐너 IP 가 같은 요청을 수백 번 보내면
요청마다 별개 클러스터 → 별개 사건으로 쪼개진다(실 EC2: 한 IP 가 136개 사건).
여기서 **같은 entity + 같은 사유(seed reason 집합)** 인 사건들을 한 건으로 합쳐 조사큐를 줄인다.
클러스터링 로직은 안 건드리고, 결과 Incident 목록만 후처리한다.

병합 시 members/seeds/join_path/layers/window 를 합치고 member_count 는 합산,
`merged_from`(몇 건을 합쳤나)을 남겨 근거를 보존한다(XAI). entity value 가 없으면 병합하지 않는다.
"""

import hashlib

MAX_INCIDENT_MEMBERS = 500


def _signature(inc):
    """병합 키: (entity type, entity value, seed 사유 집합). value 없으면 None."""
    ent = inc.get("entity") or {}
    val = ent.get("value")
    if val is None:
        return None
    reasons = frozenset(s.get("reason") for s in inc.get("seeds", []) or [])
    return (ent.get("type"), val, reasons)


def _merge(group, max_members):
    members = sorted({m for inc in group for m in inc.get("members", []) or []})
    total = sum(inc.get("member_count", len(inc.get("members", []) or [])) for inc in group)
    oversized = bool(max_members) and len(members) > max_members
    if oversized:
        members = members[:max_members]

    seen_e, joins = set(), []
    for inc in group:
        for e in inc.get("join_path", []) or []:
            k = (e.get("a"), e.get("b"), e.get("join"))
            if k not in seen_e:
                seen_e.add(k)
                joins.append(e)
    if max_members:
        joins = joins[:max_members]

    seen_s, seeds = set(), []
    for inc in group:
        for s in inc.get("seeds", []) or []:
            k = (s.get("reason"), tuple(s.get("evidence_refs") or []))
            if k not in seen_s:
                seen_s.add(k)
                seeds.append(s)

    mins = [inc["window"][0] for inc in group if inc.get("window") and inc["window"][0]]
    maxs = [inc["window"][1] for inc in group if inc.get("window") and inc["window"][1]]
    iid = "INC-" + hashlib.sha1("|".join(members).encode("utf-8")).hexdigest()[:8]
    return {
        "incident_id": iid,
        "entity": dict(group[0].get("entity") or {}),
        "window": [min(mins) if mins else None, max(maxs) if maxs else None],
        "layers": sorted({l for inc in group for l in inc.get("layers", []) or []}),
        "members": members,
        "member_count": total,
        "oversized": oversized,
        "join_path": joins,
        "seeds": seeds,
        "merged_from": len(group),
    }


def dedup_incidents(incidents, max_members=MAX_INCIDENT_MEMBERS):
    """같은 (entity, 사유) 사건들을 병합한다. 입력 순서 안정(첫 등장 순서 유지)."""
    groups, order, out = {}, [], []
    for inc in incidents:
        sig = _signature(inc)
        if sig is None:  # entity 불명 → 병합 안 함
            out.append(inc)
            continue
        if sig not in groups:
            groups[sig] = []
            order.append(sig)
        groups[sig].append(inc)
    for sig in order:
        grp = groups[sig]
        out.append(grp[0] if len(grp) == 1 else _merge(grp, max_members))
    return out
