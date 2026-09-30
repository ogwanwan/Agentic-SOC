# ② detect — 탐지 (이벤트 → seed)

> 관련: [common/](../common/README.md), [correlate/](../correlate/README.md), [triage/](../triage/README.md)

## 한 줄 요약
정규화된 공통 이벤트를 **룰과 매칭**해 "수상한 것"을 [seed](../common/seed.py)로 만든다.
Sigma 룰 매칭(범용) + Suricata Alert 변환(네트워크) 두 갈래. **판단은 안 함 — 규칙에 걸리면 seed.**

파이프라인 위치:
```
정규화 → [② 탐지: 룰 매칭 → seed] → ③ 사건묶기 → ④ 트리아지 → 조사
```

---

## 파일

| 파일 | 역할 |
|---|---|
| [`loader.py`](loader.py) | **Sigma 룰 로더.** `detect/rules/sigma/**/*.yml` → `Rule` 객체 목록. 이벤트는 모름 |
| [`engine.py`](engine.py) | **Sigma 최소 매칭 엔진.** 이벤트 × Rule → seed |
| [`suricata_seed.py`](suricata_seed.py) | **Suricata Alert → seed** 변환(네트워크 계층 탐지) |
| [`suricata_flow.py`](suricata_flow.py) | Suricata HTTP를 Alert의 **보조 증거**(evidence_refs)로 연결 |
| [`web_network_correlation.py`](web_network_correlation.py) | Apache↔Suricata HTTP **보수적 연결**(탐지 측 증거 보강) |
| [`aggregate.py`](aggregate.py) | 같은 룰·entity seed **집계 + 저심각 단발 노이즈 제거** |
| [`run.py`](run.py) | 정규화→탐지→seed 를 한 번에 실행(단독 진입점) |

---

## 흐름

```
Sigma 룰(.yml) ──loader──▶ Rule 목록 ┐
                                     ├─engine.detect(events, rules, window)─▶ seed (Sigma)
정규화 이벤트 ───────────────────────┘
정규화 이벤트(Suricata Alert) ─suricata_seed.build_suricata_seeds─▶ seed (Suricata)

  두 seed 합침 ─aggregate.aggregate_seeds(min_count)─▶ 집계·임계값 통과한 seed → ③ 사건묶기
```

### 핵심 함수
- **`engine.detect(events, rules, window)`** — 제너레이터, `(event, rule, seed)` 를 yield. 룰 매칭된 것마다 seed.
  - `get_field` (common) 3단 조회로 룰 필드를 이벤트에서 찾음.
  - `routed()` — 룰의 logsource(product/service) → 계층 매핑. 계층 안 맞으면 매칭 스킵.
  - `make_seed()` → `build_seed(...)`, `rule_severity = rule.level`.
- **`suricata_seed.build_suricata_seeds(events, window_seconds)`** → `(seeds, rejects)`. Alert 심각도 → `rule_severity`.
- **`aggregate.aggregate_seeds(seeds, min_count)`** — 같은 룰+entity 를 묶고, **저심각(low/medium) 단발**이
  `min_count` 미만이면 버림(노이즈 컷). critical/high 는 단발도 보존.

---

## 룰 추가하는 법
`detect/rules/sigma/**/*.yml` 에 Sigma 룰 파일을 넣으면 `loader` 가 자동 로드. 엔진/파이프라인은 안 건드림.
- `logsource` 의 product/service 가 계층 라우팅(`routed`)에 맞아야 매칭됨.
- `level`(critical/high/medium/low)이 트리아지 심각도 점수의 원천이 되니 신중히.

---

## 참고 사항
- **출력은 seed** — 스키마는 [`common/seed.py`](../common/seed.py). 이후 단계는 seed만 본다.
- **`run.py` vs `run_pipeline.py`** — `run.py` 는 **seed 까지만**(탐지 단독 확인용). 사건·트리아지까지 전체는
  루트 [`run_pipeline.py`](../run_pipeline.py).
- **두 종류의 suricata_flow 혼동 주의** — 여기 [`detect/suricata_flow.py`](suricata_flow.py) 는 **탐지 측**
  (Alert에 HTTP 증거 붙이기). [`correlate/links/suricata_flow.py`](../correlate/links/suricata_flow.py) 는
  **사건묶기 측**(Alert↔HTTP edge 생성). 이름만 같고 역할 다름.
- **시각 파싱은 `common/timeparse` 경유**(3.10 fromisoformat 함정).
