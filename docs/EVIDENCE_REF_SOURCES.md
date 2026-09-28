# 조사 결과 증거 출처 필드 안내 (ATT&CK 매핑 담당용)

반영: `feature/Agentic-SOC-Investigation-Agent` 커밋 `a30a52e` (2026-09-28)

조사 에이전트 결과 JSON(`investigation_result`)에 **필드만 추가**했습니다.
기존 필드, 판정(`final_verdict`), 신뢰도, `provenance.status`는 바뀌지 않았습니다.

## 1. 왜 추가했나

1차 탐지가 넘긴 참조(`initial_seed.evidence_refs`)도 조사 결과의 `raw_refs`에 "관측됨"으로 들어갑니다.
그래서 조사 에이전트가 그 원본을 **도구로 직접 확인했는지**는 지금까지 `tools_called[].raw_refs`와
비교해 매핑 쪽에서 추정해야 했습니다. 이제 증거마다 코드가 계산해서 넣어 줍니다.

## 2. 추가된 필드

### 2-1. 증거마다 (`evidence_chain[]`, `contradicting_evidence[]`)

| 필드 | 뜻 |
|---|---|
| `supporting_tool_calls` | 이 증거의 `raw_refs`를 결과에서 실제로 관측한 도구 호출 번호 목록 (`tools_called[].sequence`, 오름차순) |
| `seed_only_raw_refs` | 이 증거의 `raw_refs` 중 **1차 탐지에만 있고 어떤 도구 결과에서도 관측되지 않은** 참조 |

- LLM이 적는 값이 아니라 조사 종료 시점에 코드가 계산합니다.
- 증거를 먼저 적고 나중 도구 호출에서 같은 참조가 관측되면 `seed_only_raw_refs`에서 빠집니다.
- network 사전 조회(코드가 첫 턴 전에 실행하는 `fetch_network_log`)도 도구 호출로 칩니다.
- "조회 결과 0건" 증거(`raw_refs: []`)는 `supporting_tool_calls`가 코드가 확인한 그 0건 호출 번호입니다
  (`empty_result_call`과 같음). 확인에 실패한 0건 증거는 `[]`입니다.

### 2-2. 사건 요약 (`provenance`)

| 필드 | 뜻 |
|---|---|
| `seed_only_evidence` | `seed_only_raw_refs`가 하나라도 있는 증거의 `evidence_id` 목록 (반박 증거 포함) |

`provenance.status` 계산에는 넣지 않습니다. 1차 탐지 참조도 실제 원본 로그 줄이기 때문입니다.

## 3. JSON 예시

웹셸 → 권한 상승 사건(합성 예시). 1차 탐지가 audit 4줄과 auth 1줄을 넘겼고,
조사 에이전트는 audit을 두 번 조회했지만 auth는 조회하지 않은 경우입니다.

```json
{
  "incident_id": "INC-7d29ffde",
  "initial_seed": {
    "evidence_refs": ["sample_audit.log:6", "sample_audit.log:11", "sample_audit.log:16", "sample_auth.log:5"]
  },
  "tools_called": [
    {"sequence": 1, "tool_name": "fetch_audit_log", "input": {"pid": 1200},
     "raw_refs": ["sample_audit.log:6", "sample_audit.log:7", "sample_audit.log:8"]},
    {"sequence": 2, "tool_name": "fetch_audit_log", "input": {"ppid": 1200},
     "raw_refs": ["sample_audit.log:11", "sample_audit.log:12", "sample_audit.log:16", "sample_audit.log:17"]},
    {"sequence": 3, "tool_name": "fetch_network_log", "input": {"ip": "203.0.113.50"},
     "raw_refs": []}
  ],
  "evidence_chain": [
    {
      "evidence_id": "EVID-001", "sequence": 1, "layer": "audit", "event_type": "file_write",
      "description": "웹 서버 계정(www-data)이 /var/www/html/wp-content/plugins/.../is.php를 생성함",
      "raw_refs": ["sample_audit.log:6", "sample_audit.log:7", "sample_audit.log:8"],
      "empty_result_call": null,
      "supporting_tool_calls": [1],
      "seed_only_raw_refs": []
    },
    {
      "evidence_id": "EVID-002", "sequence": 2, "layer": "audit", "event_type": "process_execution",
      "description": "is.php의 자식 프로세스가 sh -c curl ... -o is.php, sudo su를 실행함",
      "raw_refs": ["sample_audit.log:11", "sample_audit.log:12", "sample_audit.log:16", "sample_audit.log:17"],
      "empty_result_call": null,
      "supporting_tool_calls": [2],
      "seed_only_raw_refs": []
    },
    {
      "evidence_id": "EVID-003", "sequence": 3, "layer": "auth", "event_type": "account_created",
      "description": "로그인 가능한 계정(svcbackup) 생성 이벤트가 기록됨",
      "raw_refs": ["sample_auth.log:5"],
      "empty_result_call": null,
      "supporting_tool_calls": [],
      "seed_only_raw_refs": ["sample_auth.log:5"]
    },
    {
      "evidence_id": "EVID-004", "sequence": 4, "layer": "network", "event_type": "no_activity",
      "description": "fetch_network_log 조회 결과 0건 — 203.0.113.50과의 통신 기록 없음",
      "raw_refs": [],
      "empty_result_call": 3,
      "supporting_tool_calls": [3],
      "seed_only_raw_refs": []
    }
  ],
  "contradicting_evidence": [],
  "provenance": {
    "status": "passed",
    "seed_raw_refs": ["sample_audit.log:6", "sample_audit.log:11", "sample_audit.log:16", "sample_auth.log:5"],
    "evidence_without_raw_refs": [],
    "empty_result_evidence": ["EVID-004"],
    "seed_only_evidence": ["EVID-003"],
    "ambiguous_raw_refs": {},
    "issues": []
  }
}
```

읽는 법:
- EVID-001·002: 1차 탐지 참조(`:6`, `:11`, `:16`)를 audit 조회(1, 2번 호출)로 다시 관측했습니다 → `seed_only_raw_refs: []`.
  audit은 여러 줄이 한 이벤트라 같은 이벤트의 나머지 줄(`:7`, `:8` …)도 `raw_refs`에 함께 들어 있습니다.
- EVID-003: `sample_auth.log:5`는 1차 탐지에만 있고 auth를 조회하지 않아 도구로 확인되지 않았습니다 →
  `seed_only_raw_refs`에 들어가고 `provenance.seed_only_evidence`에 EVID-003이 있습니다. 그래도 `status`는 `passed`입니다.
- EVID-004: 0건 증거. `supporting_tool_calls`가 그 0건 호출(3번)입니다.

## 4. 매핑에서 쓰는 방법

| 증거 상태 | 매핑 처리 |
|---|---|
| `seed_only_raw_refs: []`이고 `raw_refs` 있음 | 일반 매핑 대상(target) |
| `seed_only_raw_refs`에 값 있음 | **제외하지 않고 target**으로 두되 "조사 도구로 재확인되지 않음" 표시 |
| `raw_refs: []`이고 `empty_result_call` 있음 | 0건 증거 → 기법 선택 근거가 아니라 참고 문맥(context) |
| `contradicting_evidence`의 항목 | 참고 문맥(context) |

`provenance.issues`, `evidence_without_raw_refs`, `ambiguous_raw_refs`로 걸러내는 기존 규칙은 그대로 적용합니다.

## 5. 이 필드가 없는 이전 결과

2026-09-28 이전에 만든 결과 JSON에는 이 필드가 없습니다. 그때는 아래처럼 직접 계산해 주세요.
규칙은 **참조 단위**입니다 — 증거의 참조 중 seed에만 있는 것이 **하나라도** 있으면 표시합니다
(예: `[audit.log:6(도구 관측), auth.log:5(seed에만 있음)]`를 인용한 증거도 표시 대상).
"모든 참조가 seed 참조일 때만"으로 계산하면 결과 파일 형식에 따라 판정이 달라지니 주의해 주세요.

```python
seed_refs = set(result["provenance"].get("seed_raw_refs") or [])
tool_refs = {ref for call in result.get("tools_called") or [] for ref in call.get("raw_refs") or []}

def seed_only(evidence):
    return [r for r in evidence.get("raw_refs") or [] if r not in tool_refs and r in seed_refs]
```

참고: "1차 탐지 참조를 도구로 확인하라"는 종료 관문 (g)(커밋 `8213a2c`, 2026-09-27 21:15:53 KST = 12:15:53 UTC)와
(h)(`95bcb50`, 21:24:55 KST = 12:24:55 UTC) 전후로 결과가 다릅니다. 결과 파일명의 시각은 **UTC**입니다.
커밋 시각 경계로 자르지 말고 결과별로 구분해 주세요(`INC-7d29ffde` 기준):

| 결과 | 구분 |
|---|---|
| `T115708`, `T120704` | (g) 도입 전 — seed만 인용한 증거가 많음 |
| `T121505` | (g) 커밋 48초 전(경계). 첫 도구는 `fetch_audit_log(pid=1200)` |
| `T122331`, `T122929` | (h) 도입 후 |

## 6. 사건 연결 키 — `incident_key`

결과 JSON 최상위에 사건 연결 키를 추가했습니다(2026-09-28).

```json
{
  "incident_id": "INC-7d29ffde",
  "incident_key": "K-3f9a",
  "incident_snapshot": {"incident_id": "INC-7d29ffde", "member_count": 5, "updated_at": "2026-09-27T10:00:00Z"},
  "investigation_id": "INV-INC-7d29ffde-20260928-001"
}
```

- `incident_key`: 1차 탐지 DB의 안정 키(사건이 커져도 안 바뀜). `incident_id`는 사건이 커지면 바뀝니다.
  **매핑·최종 보고서는 `incident_key`로 사건을 잇고, `null`이면 `incident_id`를 씁니다.**
  지금 1차 탐지 출력(사건 파일)에는 `incident_key`가 없어 `null`입니다. 1차 탐지 DB 연결(2026-09-30) 뒤 채워집니다.
- `incident_snapshot`: 어느 판의 사건을 조사했는지(사건이 커져 재조사할 때 이전 결과와 구분). `updated_at`은 DB 연결 전까지 `null`.
- 같은 값이 `initial_seed.incident_key`에도 있지만 최상위 값을 써 주세요.
- 결과 **파일명**은 아직 `<investigation_id>_<UTC시각>.json` 그대로입니다. 파일명 규칙에 기대지 말고 JSON 필드로 이어 주세요.

## 관련 코드

- `agent/provenance.py` — `evidence_ref_sources()`, `provenance_report()`
- `agent/report.py` — `build_investigation_result()`
- `tests/test_provenance.py` — `test_evidence_ref_sources_mark_seed_only_refs_without_changing_status`,
  `test_empty_result_evidence_is_supported_by_its_verified_call`
- `agent/incident_input.py` — `to_investigation_seed()`가 `incident_key`·`updated_at`을 넘김
- `tests/test_pipeline.py` — `test_result_carries_incident_key_and_snapshot`
