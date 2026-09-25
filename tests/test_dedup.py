"""correlate/dedup.py self-check. 실행: python tests/test_dedup.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.dedup import dedup_incidents


def _inc(iid, ip, reason, refs, w0, w1, layers=("web", "network"), member_count=2):
    return {
        "incident_id": iid,
        "entity": {"type": "src_ip", "value": ip},
        "window": [w0, w1],
        "layers": list(layers),
        "members": refs,
        "member_count": member_count,
        "oversized": False,
        "join_path": [{"a": refs[0], "b": refs[-1], "join": "web_network", "keys": {}}],
        "seeds": [{"reason": reason, "evidence_refs": [refs[0]]}],
    }


def _run():
    # 같은 IP+같은 사유 스캐너 3건 → 1건으로 병합
    scan = [
        _inc("a", "1.1.1.1", "Config File Access", ["ap:1", "sur:1"], "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"),
        _inc("b", "1.1.1.1", "Config File Access", ["ap:2", "sur:2"], "2026-01-01T00:00:05Z", "2026-01-01T00:00:06Z"),
        _inc("c", "1.1.1.1", "Config File Access", ["ap:3", "sur:3"], "2026-01-01T00:00:10Z", "2026-01-01T00:00:11Z"),
    ]
    # 다른 사유(같은 IP) → 병합 안 됨
    other = _inc("d", "1.1.1.1", "SQL Injection", ["ap:9", "sur:9"], "2026-01-01T00:01:00Z", "2026-01-01T00:01:01Z")
    # 다른 IP(같은 사유) → 병합 안 됨
    other_ip = _inc("e", "2.2.2.2", "Config File Access", ["ap:8", "sur:8"], "2026-01-01T00:02:00Z", "2026-01-01T00:02:01Z")
    # entity value 없음 → 병합 안 함(그대로)
    noent = _inc("f", None, "Config File Access", ["ap:7", "sur:7"], "2026-01-01T00:03:00Z", "2026-01-01T00:03:01Z")

    out = dedup_incidents(scan + [other, other_ip, noent])
    # 3건 스캐너 → 1, +other +other_ip +noent = 총 4건
    assert len(out) == 4, f"병합 결과 수 실패: {len(out)}"

    merged = next(i for i in out if i.get("merged_from"))
    assert merged["merged_from"] == 3, merged.get("merged_from")
    assert merged["member_count"] == 6, f"member_count 합산 실패: {merged['member_count']}"       # 2*3
    assert merged["members"] == ["ap:1", "ap:2", "ap:3", "sur:1", "sur:2", "sur:3"], merged["members"]
    assert len(merged["seeds"]) == 3, "seed union 실패"                                            # 서로 다른 evidence_refs
    assert merged["window"] == ["2026-01-01T00:00:00Z", "2026-01-01T00:00:11Z"], merged["window"]  # min~max
    assert len(merged["join_path"]) == 3, "join_path union 실패"

    # 병합 안 된 것들은 merged_from 없음(원본 유지)
    assert all("merged_from" not in i for i in out if i["incident_id"] in ("d", "e", "f"))

    # 단일 사건만 있으면 그대로 통과(변형 없음)
    solo = dedup_incidents([other])
    assert len(solo) == 1 and solo[0] is other, "단일 사건 passthrough 실패"

    print("test_dedup OK →", [(i["incident_id"], i.get("merged_from")) for i in out])


if __name__ == "__main__":
    _run()
