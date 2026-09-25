"""도구·수집·프롬프트가 함께 쓰는 ISO8601 시간 파싱 유틸.

2026-09-15: 실제 EC2 배포 중 Suricata의 콜론 없는 UTC 오프셋("+0000")을
Python 3.10에서 못 읽는 버그를 여기서 고쳤다 (Python 3.11+는 원래 읽을 수 있음).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# Suricata 등 일부 소스는 UTC 오프셋을 "+0000"처럼 콜론 없이 준다. Python 3.11+의
# datetime.fromisoformat()은 이 형식도 읽지만, 3.10(예: EC2 기본 python3)은 못 읽고
# ValueError를 던진다 — 실제 EC2 배포 중 이 문제로 죽는 것을 발견해서 추가했다.
_OFFSET_NO_COLON_RE = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_iso(value: str) -> datetime:
    """'2026-09-09T10:05:45Z' 또는 '...+0000'(콜론 없음) 같은 문자열을
    timezone-aware datetime으로 변환. Python 3.10에서도 동작하도록
    콜론 없는 오프셋은 콜론을 끼워넣어 정규화한다.
    """
    cleaned = value.replace("Z", "+00:00")
    cleaned = _OFFSET_NO_COLON_RE.sub(r"\1:\2", cleaned)
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt