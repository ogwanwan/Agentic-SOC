"""공통 ISO8601 타임스탬프 파서.

`datetime.fromisoformat` 은 Python 3.10 에서 'Z' 접미사와 콜론 없는 오프셋(+0000)을
못 읽는다(3.11+ 만 됨). EC2 는 3.10, 로컬은 3.14 라 파서를 각 파일에 복붙하면
이 차이가 조용히 미탐으로 샌다 → 정규화는 여기 한 곳에서만 한다.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_OFFSET_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def normalize_iso(text: str) -> str:
    """ISO8601 문자열의 'Z'·콜론 없는 오프셋(+0000)을 fromisoformat(3.10) 이 읽는 형태로.

    문자열만 손본다(파싱하지 않음). 각 호출부가 자기 계약(예외/None/원문)대로 이어서 쓴다.
    """
    s = text.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return _OFFSET_NO_COLON.sub(r"\1:\2", s)


def parse_utc(value):
    """ISO8601 → UTC aware datetime. tz 없음/형식 오류/빈 값이면 None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(normalize_iso(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


if __name__ == "__main__":  # 자체 점검: python common/timeparse.py
    assert normalize_iso("2026-09-18T00:19:42.486162+0000") == "2026-09-18T00:19:42.486162+00:00"
    assert normalize_iso("2026-09-18T00:19:42Z") == "2026-09-18T00:19:42+00:00"
    assert normalize_iso("2026-09-18T09:19:42+0900") == "2026-09-18T09:19:42+09:00"
    assert parse_utc("2026-09-18T09:19:42+0900").hour == 0          # +0900 → UTC
    assert parse_utc("2026-09-18T00:19:42.486162Z").tzinfo == timezone.utc
    assert parse_utc("2026-09-18T00:19:42") is None                 # tz 없음
    assert parse_utc("nope") is None and parse_utc("") is None and parse_utc(None) is None
    print("ok")
