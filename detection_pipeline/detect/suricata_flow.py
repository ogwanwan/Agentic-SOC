"""Suricata HTTP 이벤트를 Alert의 보조 증거로 연결한다.

``flow_id``는 하나의 네트워크 흐름을 가리킬 뿐 HTTP 트랜잭션 하나를
가리키지는 않는다. 따라서 ``tx_id``가 있으면 sensor/flow/transaction을 모두
일치시키고, ``tx_id``가 없는 Alert에만 보수적인 시간·전송 튜플 폴백을 쓴다.
"""

from __future__ import annotations

from common.network import build_http_flow_index, find_http_flow_matches


DEFAULT_FALLBACK_SECONDS = 5


def build_http_evidence_index(events):
    """정규화된 HTTP 이벤트를 정확 키와 flow 키로 인덱싱한다."""
    return build_http_flow_index(events)


def find_http_evidence_refs(
    alert_event,
    index,
    fallback_seconds=DEFAULT_FALLBACK_SECONDS,
):
    """Alert에 안전하게 연결할 수 있는 HTTP ``raw_ref`` 목록을 반환한다.

    tx_id가 있으면 정확 일치만 허용한다. tx_id가 없을 때는 같은 sensor/flow,
    같은 전송 튜플, 시간 차 이내인 HTTP 후보가 정확히 한 건일 때만 연결한다.
    """
    return sorted({
        match["record"]["raw_ref"]
        for match in find_http_flow_matches(alert_event, index, fallback_seconds)
    })


__all__ = [
    "DEFAULT_FALLBACK_SECONDS",
    "build_http_evidence_index",
    "find_http_evidence_refs",
]
