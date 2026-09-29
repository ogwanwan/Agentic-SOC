"""
correlate/registry.py — 링크(계층쌍 연결) 등록소

각 links/<pair>.py 는 자기 edge 함수를 @register_linker 로 등록만 하면 된다.
grouping 이 이 목록을 순회해 전 계층쌍 edge 를 모은다.
→ 담당자는 grouping 을 안 건드리고 자기 파일만 추가하면 됨(병합 충돌 방지).
"""

# 등록된 링크 함수들: 각 함수는 edges(events) -> list[edge] 시그니처.
LINKERS = []


def register_linker(fn):
    """edge 함수를 등록. links/<pair>.py 의 edge 함수 위에 @register_linker 를 붙인다."""
    if fn not in LINKERS:
        LINKERS.append(fn)
    return fn
