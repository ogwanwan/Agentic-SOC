"""triage/triage.py self-check. 실행: python triage/tests/test_triage.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage.triage import triage, triage_score, route


def _inc(iid, layers, joins, seeds, member_count=None, oversized=False):
    return {
        "incident_id": iid,
        "entity": {"type": "src_ip", "value": "45.9.1.2"},
        "window": ["2026-09-11T02:00:00Z", "2026-09-11T02:01:00Z"],
        "layers": layers,
        "members": [f"x:{i}" for i in range(member_count or len(seeds) or 1)],
        "member_count": member_count if member_count is not None else 1,
        "oversized": oversized,
        "join_path": [{"a": "a", "b": "b", "join": j, "keys": {}} for j in joins],
        "seeds": [{"score_parts": {"rule_severity": sev}} for sev in seeds],
    }


def _run():
    # 1) critical seed → P1 (심각도 지배)
    inc = _inc("c1", ["web"], [], ["critical"])
    score, _ = triage_score(inc)
    assert route(score)[0] == "P1", f"critical→P1 실패: {score}"

    # 2) 4계층 + join 5종 + high → 크게 상승 (P1)
    inc = _inc("c2", ["web", "network", "system", "auth"],
               ["web_network", "suricata_flow", "web_system", "audit_lineage", "system_auth"],
               ["high", "medium"])
    score, parts = triage_score(inc)
    # 30(high) + 18(4계층 체인=6*3) + 15(5종=3*5) + 2(seed 2개) = 65
    assert score == 65, f"가산 합 실패: {score} {parts}"
    assert route(score)[0] == "P1"

    # 3) low 단발·단일계층 → P4 (<8): 3(low) + 10?  단일계층은 +10 → 13 = P3. 계층 0이면 3=P4.
    #    layers 빈 + low seed → 3점 → P4
    inc = _inc("c3", [], [], ["low"])
    score, _ = triage_score(inc)
    assert route(score) == ("P4", "hold"), f"low 단발→P4 실패: {score}"

    # 4) oversized 거대 사건이 member_count 아닌 seed 심각도로 채점되는지
    big_low = _inc("c4", ["system"], ["audit_lineage"], ["low"], member_count=20000, oversized=True)
    small_crit = _inc("c5", ["web"], [], ["critical"], member_count=1)
    assert triage_score(big_low)[0] < triage_score(small_crit)[0], "member_count가 점수에 새어듦"
    # low+1계층 = 3+10=13(P3), member 2만이어도 P1 아님
    assert route(triage_score(big_low)[0])[0] != "P1"

    # 5) 결정론: 같은 입력 두 번 → 동일 점수
    a = triage_score(_inc("c6", ["web", "system"], ["web_system"], ["high"]))[0]
    b = triage_score(_inc("c6", ["web", "system"], ["web_system"], ["high"]))[0]
    assert a == b, "비결정론"

    # 6) triage(): 필드 추가 + 정렬 + 원본 불변
    src = [_inc("lo", ["web"], [], ["low"]), _inc("hi", ["web", "system"], ["web_system"], ["critical"])]
    out = triage(src)
    assert out[0]["incident_id"] == "hi" and out[0]["priority"] == "P1"
    assert out[-1]["priority"] in ("P3", "P4")
    assert all("triage_score" in i and "route" in i and "triage_parts" in i for i in out)
    assert "triage_score" not in src[0], "원본 Incident 변형됨"

    print("test_triage OK →", [(i["incident_id"], i["triage_score"], i["priority"]) for i in out])


if __name__ == "__main__":
    _run()
