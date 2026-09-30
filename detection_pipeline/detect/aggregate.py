"""같은 룰·entity의 seed를 집계하고 저심각 단발 노이즈를 제거한다."""

from __future__ import annotations

from common.timeparse import parse_utc


_THRESHOLD_LEVELS = frozenset({"low", "medium"})


def _merge(seeds):
    merged = dict(seeds[0])
    merged["window"] = list(seeds[0]["window"])
    merged["evidence_refs"] = []
    seen = set()
    for seed in seeds:
        window = seed["window"]
        if window and window[0] is not None and (
            merged["window"][0] is None or window[0] < merged["window"][0]
        ):
            merged["window"][0] = window[0]
        if window and window[1] is not None and (
            merged["window"][1] is None or window[1] > merged["window"][1]
        ):
            merged["window"][1] = window[1]
        for raw_ref in seed.get("evidence_refs", []):
            if raw_ref not in seen:
                seen.add(raw_ref)
                merged["evidence_refs"].append(raw_ref)
    merged["count"] = len(seeds)
    return merged


def _timed_groups(seeds, seconds, min_count, always_keep):
    """시간창 안에서 임계값을 만족하는 겹친 구간을 한 burst로 합친다."""
    records, invalid = [], []
    for order, seed in enumerate(seeds):
        timestamp = parse_utc((seed.get("detail") or {}).get("timestamp"))
        (records if timestamp is not None else invalid).append((timestamp, order, seed))
    records.sort(key=lambda item: (item[0], item[1]))
    required = 1 if always_keep else min_count

    covered = [0] * (len(records) + 1)
    end = 0
    for start in range(len(records)):
        end = max(end, start + 1)
        while end < len(records) and (records[end][0] - records[start][0]).total_seconds() <= seconds:
            end += 1
        if end - start >= required:
            covered[start] += 1
            covered[end] -= 1

    groups, current, active, previous = [], [], 0, None
    for index, (timestamp, _order, seed) in enumerate(records):
        active += covered[index]
        if active and current and (timestamp - previous).total_seconds() > seconds:
            groups.append(current)
            current = []
        if active:
            current.append(seed)
            previous = timestamp
        elif current:
            groups.append(current)
            current, previous = [], None
    if current:
        groups.append(current)
    if always_keep:
        groups.extend([[seed] for _timestamp, _order, seed in invalid])
    return groups


def aggregate_seeds(seeds, min_count: int = 5):
    """룰별 설정이 있으면 해당 시간창·임계값, 없으면 전역 임계값을 적용한다."""
    if isinstance(min_count, bool) or not isinstance(min_count, int) or min_count <= 0:
        raise ValueError("min_count는 양의 정수여야 함")

    groups = {}
    for seed in seeds:
        aggregation = seed.get("aggregation") or {}
        window_seconds = aggregation.get("window_seconds")
        threshold = aggregation.get("min_count", min_count)
        if aggregation and (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or window_seconds <= 0
            or isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or threshold <= 0
        ):
            raise ValueError("aggregation은 양의 window_seconds와 min_count가 필요함")
        entity = seed["entity"]
        key = (
            seed.get("rule_id") or seed["reason"],
            entity["type"],
            entity["value"],
            window_seconds,
            threshold,
        )
        groups.setdefault(key, []).append(seed)

    output = []
    for (_rule, _entity_type, _entity_value, window_seconds, threshold), grouped in groups.items():
        severity = grouped[0].get("score_parts", {}).get("rule_severity")
        always_keep = severity not in _THRESHOLD_LEVELS
        if window_seconds is None:
            if always_keep or len(grouped) >= threshold:
                output.append(_merge(grouped))
            continue
        for burst in _timed_groups(grouped, float(window_seconds), threshold, always_keep):
            output.append(_merge(burst))
    return output


if __name__ == "__main__":
    def seed(second, *, count=5, severity="medium"):
        timestamp = f"2026-09-20T00:00:{second:02d}Z"
        return {
            "entity": {"type": "src_ip", "value": "1.2.3.4"},
            "window": [timestamp, timestamp],
            "layer": "web", "source": ["sigma"], "reason": "login",
            "rule_id": "login", "score_parts": {"rule_severity": severity},
            "detail": {"timestamp": timestamp}, "evidence_refs": [f"access.log:{second}"],
            "aggregation": {"window_seconds": 300, "min_count": count},
        }

    assert aggregate_seeds([seed(i) for i in range(5)])[0]["count"] == 5
    assert aggregate_seeds([seed(i, count=6) for i in range(5)]) == []
    assert aggregate_seeds([seed(0, count=1), seed(1, count=1)])[0]["count"] == 2
    print("ok")
