# tools/base.py — 도구 반환값 표준 래퍼
"""
모든 @register 도구는 결과를 success()/failure()로 감싸 반환한다.
오케스트레이터·에이전트가 성공/실패를 '형식'으로 구분하기 위한 최소 계약
(안전장치의 '반환 형식' 검사가 이 모양을 본다).

  success(data)        -> {"ok": True,  "data": data, "error": None}
  failure(error, data) -> {"ok": False, "data": data, "error": "<사유>"}

data 는 도구별 payload(dict). 판단/스코어링은 하지 않는다(도구는 결정론).
"""


def success(data=None):
    """도구 성공. data(payload)를 표준 봉투에 담아 반환."""
    return {"ok": True, "data": data, "error": None}


def failure(error, data=None):
    """도구 실패. 프로세스를 죽이지 않고 사유를 실어 되돌린다(§9 예외 격리)."""
    return {"ok": False, "data": data, "error": str(error)}
