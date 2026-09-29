# common — 공통 토대 (스키마·조인키·파서 유틸)

> 관련: [detect/](../detect/README.md), [correlate/](../correlate/README.md), [triage/](../triage/README.md)

## 한 줄 요약
모든 단계(정규화·탐지·사건묶기)가 함께 쓰는 **약속(스키마)과 공통 로직**을 모아둔 곳.
여기 있는 계약(이벤트 모양·seed 모양·조인키 규칙)을 각 파트가 지키면 서로 맞물린다.

> ⚠️ 이 파일들은 **실 EC2 로그를 직접 확인해서 나온 결론**이다. 임의로 바꾸지 말고, 바꿔야 하면 팀 합의.

---

## 파일

| 파일 | 역할 |
|---|---|
| [`schema.py`](schema.py) | **공통 이벤트 스키마 계약.** 모든 `fetch_*_log` 도구가 이 모양의 dict를 반환 |
| [`seed.py`](seed.py) | **seed 스키마 계약.** 탐지가 만들어 트리아지·조사로 넘기는 단위 |
| [`join_keys.py`](join_keys.py) | **계층 간 조인키 규칙 정의**(무엇을 근거로 이을지). 실제 조립은 network/lineage·correlate/links |
| [`network.py`](network.py) | Apache↔Suricata **HTTP·flow 매칭** 공통 로직(IP 표준화·요청 매칭·flow 키) |
| [`lineage.py`](lineage.py) | audit(system) 내부 **PPID→PID 프로세스 계보** 조립 |
| [`timeparse.py`](timeparse.py) | 공통 **ISO8601 시각 파서**(Python 3.10 `fromisoformat` 함정 우회) |

---

## 핵심 계약 1 — 공통 이벤트 (`schema.py`)

모든 파서 출력은 이 모양이다. **조인키는 최상단, 계층별 세부는 `layer_data` 안**:
```json
{
  "timestamp": "2026-09-11T02:00:03.000Z",   // UTC ISO8601
  "layer":     "web",                          // web | network | system | auth
  "raw_ref":   "apache_access.log:10",         // 원본 역추적 포인터 (파일:줄)
  "src_ip":    "45.9.1.2",                     // ┐
  "pid":       1200,                           // ├ 조인키(계층을 잇는 열쇠) — 최상단
  "ppid":      1,                              // ┘
  "layer_data": { ... }                        // 계층별 세부(LAYER_DATA_KEYS 로 계층마다 허용 키 고정)
}
```
- `build_event(...)` 로 만들고 `validate(...)` 로 검사.
- **`get_field(event, name)` 3단 조회:** 최상단 → `layer_data.<name>`(점 표기) → `layer_data` 안. 탐지 엔진이 룰 필드를 이걸로 찾는다.
- 상수: `VALID_LAYERS`, `REQUIRED_TOP`, `JOIN_KEYS`(src_ip·pid·ppid), `LAYER_DATA_KEYS`(계층별 허용 키).

## 핵심 계약 2 — seed (`seed.py`)

탐지가 "수상하다"고 판단한 단위. **③ 묶기 키 + ④ 트리아지 재료 + ⑤ 조사 시작점**을 담는다:
```json
{
  "entity":       {"type": "src_ip", "value": "45.9.1.2"},  // 무엇을 조사하나(묶기 키)
  "window":       ["min_ts", "max_ts"],
  "layer":        "web",
  "source":       "sigma",                                   // sigma | anomaly | suricata
  "reason":       "Web Process Writes Executable Script...",
  "score_parts":  {"rule_severity": "critical", ...},        // ④ 트리아지 심각도 원천
  "signal_tags":  ["T1505.003"],
  "evidence_refs":["audit.log:6"]                            // 근거 raw_ref
}
```
`build_seed(...)` / `validate(...)`. 상수: `VALID_ENTITY_TYPES`, `VALID_SOURCES`, `VALID_SIGNAL_TAGS`.

## 핵심 계약 3 — 조인키 (`join_keys.py`)
계층을 **무엇을 근거로 잇는지**의 정의만 둔다(실제 edge 조립은 `correlate/links/`):

| 조인 | 근거 |
|---|---|
| 웹↔네트워크 (apache↔suricata) | `src_ip`(XFF/클라이언트) + 시간 근접 |
| 웹↔시스템 (apache↔audit) | `www-data` uid + 시간 근접 |
| 시스템↔인증 (audit↔auth) | 같은 `pid` |
| 웹셸 로컬 (audit 내부) | `ppid→pid` 프로세스 계보 |

---

## 참고 사항
- **네임스페이스 패키지** — `__init__.py` 없음. 레포 루트에서 실행하며 `from common.schema import ...` 로 임포트.
- **`timeparse` 왜 있나** — Python 3.10 `datetime.fromisoformat` 이 `'Z'` 접미사와 콜론 없는 오프셋(`+0000`)을
  못 읽는다. 실 EC2가 그 형식이라 여기서 흡수. **시각 파싱은 반드시 `timeparse` 경유.**
- **바꾸면 파급 큼** — 이 계약들은 파서·탐지·묶기·트리아지가 전부 의존. 필드 추가/이름 변경은 전 파트 합의 후.
