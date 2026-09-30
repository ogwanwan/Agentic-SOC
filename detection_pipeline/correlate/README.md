# ③ correlate — 사건 묶기 (이벤트 + seed → Incident)

> 관련: [common/](../common/README.md), [detect/](../detect/README.md), [triage/](../triage/README.md)

## 한 줄 요약
흩어진 이벤트들을 계층 간 **연결(edge)** 로 이어 한 **사건(Incident)** 으로 묶는다.
탐지 seed를 앵커로, 웹→시스템→인증까지 이어진 **공격 체인**을 하나로 합쳐 트리아지·조사로 넘긴다.

파이프라인 위치:
```
정규화 → ② 탐지(seed) → [③ 사건묶기: edge 수집 → 오연결 방지 → 클러스터 → Incident] → ④ 트리아지 → 조사
```

---

## 파일

| 파일 | 역할 |
|---|---|
| [`grouping.py`](grouping.py) | **총괄.** links 자동 로드 → edge 수집 → guards → 클러스터 → Incident |
| [`registry.py`](registry.py) | **링크 등록소.** `@register_linker` 로 연결기 등록(`LINKERS`) |
| [`links/`](links/) | **계층쌍 연결기 5종.** 각자 edge 함수만 추가하면 자동 합류 |
| [`guards.py`](guards.py) | **오연결 방지.** 약한 edge·시간차 큰 pid 재사용 등을 거름 |
| [`incident.py`](incident.py) | **출력 계약.** 클러스터 하나를 Incident dict로 조립 |
| [`dedup.py`](dedup.py) | **파편 병합.** 같은 (entity, 사유) 로 쪼개진 사건을 한 건으로 합침(스캐너 반복요청) |

### 연결기(links/) — 계층쌍마다 하나
| 파일 | 계층쌍 | 근거 | 담당 |
|---|---|---|---|
| [`web_system.py`](links/web_system.py) | 웹(apache) ↔ 시스템(audit) | www-data uid + 시간 근접 | 지원 |
| [`web_network.py`](links/web_network.py) | 웹(apache) ↔ 네트워크(suricata) | XFF/src_ip + 시각 | — |
| [`system_auth.py`](links/system_auth.py) | 시스템(audit) ↔ 인증(auth) | 같은 pid | 지희 |
| [`audit_lineage.py`](links/audit_lineage.py) | 시스템 내부(audit) | ppid→pid 계보 | 민혁 |
| [`suricata_flow.py`](links/suricata_flow.py) | 네트워크 내부(suricata) | sensor+flow(+tx) id | — |

---

## 흐름 (`grouping.correlate`)

```
correlate(events, seeds, require_seed, max_members=500)   # run_pipeline 은 require_seed=True 로 호출
  1) links/ 자동 로드 → 각 연결기가 edge 생성       edge = {a: raw_ref, b: raw_ref, join, keys}
  2) guards.apply_guards(edges)                     약한/의심 연결 제거(오연결 방지)
  3) union-find 로 edge 연결된 raw_ref 를 클러스터로
  4) 클러스터마다 걸린 seed 수집 → build_incident   → Incident
     (require_seed=True 면 탐지 앵커 없는 blob 은 사건화 안 함)
  5) dedup_incidents: 같은 (entity, 사유) 파편 사건 병합    merged_from 에 병합 수 기록
     (실 EC2: 사건 285→61, 조사큐 278→54. 스캐너 IP 하나가 136→1)
```

### edge 계약 (연결기가 반환하는 것)
```json
{"a": "apache_access.log:10", "b": "audit.log:20", "join": "web_system", "keys": {"uid": 33, "dt_sec": 1.1}}
```
`a`·`b` = 이을 두 이벤트의 raw_ref, `join` = 계층쌍 이름, `keys` = 이은 근거(XAI).

### Incident (출력) — 자세한 필드는 [`incident.py`](incident.py) / [triage/HANDOFF.md](../triage/HANDOFF.md)
`incident_id · entity · window · layers · members(raw_ref) · member_count · oversized · join_path · seeds`

---

## 연결기 추가하는 법
`links/<pair>.py` 하나 만들고 edge 함수에 `@register_linker` 만 붙이면 `grouping` 이 자동으로 합류시킨다
(**grouping.py 는 안 건드림**):
```python
from correlate.registry import register_linker
JOIN = "my_pair"

@register_linker
def my_pair_edges(events):
    # ... 계층 A·B 이벤트를 조인키로 매칭
    return [{"a": a_ref, "b": b_ref, "join": JOIN, "keys": {...}}]
```

---

## 참고 사항
- **`require_seed`** — 탐지 seed가 하나도 안 걸린 클러스터(계보만으로 뭉친 blob)는 사건으로 안 냄.
  탐지 근거 없는 프로세스 트리가 사건 목록을 채우는 것 방지. **운영(`run_pipeline`) 기본은 `True`**,
  함수 자체 기본값은 `False`(edge만 보는 데모/단독 실행용).
- **`max_members=500` 상한** — 브루트포스가 계보 타고 2만 건 뭉치면 통째로 6MB → 트리아지 입력 불가.
  넘으면 members/join_path 를 잘라 싣고 `oversized=True`, 실제 총수는 `member_count` 로 남김.
  `incident_id` 는 자르기 **전** 전체 멤버로 계산 → 같은 클러스터면 id 안 흔들림.
- **guards 핵심** — `WEAK_JOINS`, `SYSTEM_AUTH_MAX_GAP_SEC`(pid 재사용으로 엉뚱하게 이어지는 것 방지).
- **조인키 규칙 정의는 [`common/join_keys.py`](../common/join_keys.py)**, 실제 매칭 로직은 여기 links/ + `common/network·lineage`.
- **suricata_flow 혼동 주의** — 여기 것은 **사건묶기 측 edge 생성**. [`detect/suricata_flow.py`](../detect/suricata_flow.py) 는 탐지 측 증거 보강. 역할 다름.
