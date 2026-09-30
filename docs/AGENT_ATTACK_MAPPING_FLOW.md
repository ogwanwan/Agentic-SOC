# 조사 에이전트 + ATT&CK 매핑 전체 동작 흐름

`python main.py` 한 번이 로그 수집부터 조사, ATT&CK 매핑, 최종 보고서 저장까지 어떤 순서로 도는지 정리한 문서다.
조사 단계 내부(도구 선택, 종료 관문 등)의 세부 순서는 [AGENT_FLOW.md](AGENT_FLOW.md)에 있고, 이 문서는 전체 흐름과
**조사 결과가 매핑으로 넘어가는 연결부**를 다룬다.

- 기준: `feature/investigation-attack-mapping` (개인 저장소 `integrate-attack-mapping`), 2026-09-27
- 현재 `attack-mapping-final` 흐름은 문서 끝의 2026-09-30 기록을 참고한다. 위 기준의 본문은 이전 Rule 경로 기록이다.
- 코드 주석의 `[1]`~`[46]` 번호는 AGENT_FLOW.md와 같다. 매핑 내부(`attack_mapping/`)는 어택 매핑 팀 코드라 번호 주석이 없고, 이 문서에서는 함수 이름으로 따라간다.

---

## 1. 한눈에 보기

```
python main.py
 │
 ├─ [2]~[4]  준비: 도구 레지스트리 · LLM 클라이언트 · 파이프라인 실행
 │
 ├─ 조사 단계 (agent/)  ── LLM 사용 ──────────────────────────────────────────────
 │   ├─ [6]   로그 수집             raw_log_ingestion.py → 1차 탐지팀 정규화(primary_detection/normalizer)
 │   ├─ [10]  조사할 사건(seed) 고르기   seed_generation.py (LLM 1회)
 │   └─ [16]  seed마다 조사 루프        loop.py (LLM 판단 ↔ 도구 실행 반복, 종료 관문)
 │            └─ [41] 조사 결과 JSON    report.py build_investigation_result()
 │
 ├─ [45] 텍스트 보고서 출력 + 조사 결과 JSON 저장
 │         → results/investigation_agent/<investigation_id>_<UTC시각>.json
 │
 └─ [46] ATT&CK 매핑 (attack_mapping/, reporting/)  ── LLM 사용 안 함, 규칙 기반 ───
     main.run_attack_mapping(저장한 파일 경로)
      └─ attack_mapping/cli.py  process_file(경로, ALL_RULES, results/attack_mapping)
          ├─ ① JSON 읽기·형식 검사
          ├─ ② engine.map_investigation()     판정·provenance 게이트 → 증거 선별 → 규칙 매칭 → 기법별 병합
          ├─ ③ killchain.build_kill_chain()    전술 순서 + 시각 순서로 정렬
          ├─ ④ reporting/final_report.py build_final_report()   조사 결과 + 매핑 결과 합치기
          └─ ⑤ 파일 2개 저장
               → results/attack_mapping/<incident_id>_attack_mapping.json
               → results/attack_mapping/<incident_id>_final_report.json
```

핵심은 두 가지다.

- **조사 단계는 LLM이 판단하고, 매핑 단계는 LLM을 부르지 않는다.** 매핑은 조사 결과 JSON의 문장을 규칙 키워드와 비교하는 결정적(deterministic) 처리다. 같은 조사 결과 파일이면 매핑 결과는 항상 같다.
- **매핑은 저장된 파일을 입력으로 받는다.** 메모리의 dict를 넘기지 않으므로 `python -m attack_mapping.cli <파일>`로 나중에 다시 돌려도 결과가 같다.

---

## 2. 폴더와 역할

| 위치 | 담당 | 역할 |
|---|---|---|
| `primary_detection/normalizer/` | 1차 탐지팀 (복사본, 수정 금지) | 서로 다른 로그 형식을 같은 이벤트 형식으로 정규화 |
| `agent/` | 조사 에이전트 | 로그 수집 → seed 생성 → 조사 루프 → 조사 결과 JSON |
| `attack_mapping/` | 어택 매핑 팀 | 매핑 엔진(`engine.py`, `matching.py`), 규칙 카탈로그(`rules/`), Kill Chain(`killchain.py`), CLI(`cli.py`) |
| `reporting/` | 어택 매핑 팀 | 최종 보고서 합치기. 이후 대응(Response) 단계 결과도 여기서 합칠 예정이라 최상위에 둔다 |
| `main.py` | 조사 에이전트 | 전체 실행 진입점. 조사 결과 저장 직후 `run_attack_mapping()`으로 매핑 연결 |
| `results/investigation_agent/` | (git 제외) | 조사 결과 JSON, 조사 쪽 데모 출력 |
| `results/attack_mapping/` | (git 제외) | 매핑 결과 JSON, 최종 보고서 JSON |

의존 방향은 한쪽이다: `main.py`만 `agent`와 `attack_mapping`을 둘 다 import한다. **`agent/`는 `attack_mapping/`을 모르고**, `attack_mapping/`도 `agent/`를 import하지 않는다(파일 형식으로만 연결).

---

## 3. 조사 단계 요약 (`agent/`)

세부는 [AGENT_FLOW.md](AGENT_FLOW.md). 여기서는 매핑에 영향을 주는 부분만 적는다.

| 단계 | 하는 일 | 매핑과의 관계 |
|---|---|---|
| [6] 로그 수집 | `.env`의 `<계층>_LOG_LOCAL_PATH` 4계층(web/auth/audit/network) 파일 끝 N건을 정규화. 각 이벤트에 `raw_ref`(예: `audit.log:511`) | `raw_ref`가 끝까지 전달돼 매핑 결과의 `raw_refs`가 된다 |
| [10] seed 생성 | LLM이 조사할 사건 후보와 우선순위를 고른다 | 사건 하나 = 조사 결과 1개 = 매핑 결과 1쌍 |
| [16]~[40] 조사 루프 | LLM이 도구를 골라 조회하고, 결과를 보고 증거(evidence)를 기록, 종료 관문을 통과하면 판정 | 증거의 `description`·`event_type`, 판정의 `attack_type`이 **매핑 규칙이 읽는 문장**이다 |
| [24] 증거 반영 | 증거가 인용한 `raw_refs`가 실제 관측된 참조인지 검증(provenance). "조회 0건" 증거는 `empty_result_call`이 성공한 0건 호출인지 확인 | provenance 상태가 매핑 게이트를 정한다(5장) |
| [41] 결과 JSON | `evidence_chain`, `final_verdict`, `provenance`, `raw_ref_locations` 등 | 매핑 엔진의 입력(4장) |

---

## 4. 연결부: 매핑이 읽는 조사 결과 필드

`attack_mapping/engine.py`는 조사 결과 JSON에서 아래 필드만 읽는다. 이 필드의 이름·자료형을 바꾸면 매핑이 `error`가 되므로 **두 팀이 함께 바꿔야 한다.**

| 필드 | 매핑에서 쓰는 곳 |
|---|---|
| `incident_id`, `investigation_id` | 필수(비어 있으면 `error`). 출력 파일 이름은 `incident_id` 기준 |
| `final_verdict.verdict` | 게이트: `THREAT_CONFIRMED` / `FALSE_POSITIVE` / `INCONCLUSIVE` 외에는 `error` |
| `final_verdict.attack_type` | **판정 문구 매칭**(`matched_by: "verdict"`). provenance가 `passed`일 때만 사용 |
| `evidence_chain[]` | **증거 매칭**(`matched_by: "evidence"`) |
| └ `evidence_id` | 매핑 결과·Kill Chain에서 근거로 표시. 중복이면 `error` |
| └ `event_type`, `description` | 규칙 키워드와 비교하는 문장 |
| └ `time` | 기법의 시각, Kill Chain 정렬·대표 시각 |
| └ `raw_refs` | 기법의 원본 참조로 복사(다시 검증하지 않음) |
| └ `sequence` | provenance `issues`에 걸린 증거를 찾을 때 |
| `provenance.status` | 게이트: `passed` / `incomplete` / `unavailable` |
| `provenance.evidence_without_raw_refs`, `ambiguous_raw_refs`, `issues` | `incomplete`일 때 제외할 증거 |
| `raw_ref_locations` | 매핑 결과에 그대로 복사 |

**읽지 않는 것**: `contradicting_evidence`(반박 증거), `attack_timeline`(타임라인), `hypothesis`, `tools_called`, `evidence_chain[].empty_result_call` 등. 그래서 **타임라인에만 있고 증거에 없는 행위는 매핑되지 않는다**(7장).

---

## 5. 매핑 단계 (`attack_mapping/`, `reporting/`)

### ① 읽기·형식 검사 — `cli.process_file()`

- 파일을 UTF-8(BOM 허용)로 읽는다. 최상위가 JSON 객체가 아니거나 너무 깊으면(128단계 초과) 예외 → `main.py`가 "매핑 실패"만 출력하고 다음 사건으로 넘어간다(조사 JSON은 이미 저장됨).
- 이미 매핑 결과인 파일(`mapping_status`·`techniques`·`mapping_table_version`이 있는 JSON)이 들어오면 거부한다(재처리 방지).

### ② 매핑 엔진 — `engine.map_investigation(조사 결과, ALL_RULES)`

**게이트** (위에서부터 먼저 걸리는 것):

| 조건 | `mapping_status` | 기법 |
|---|---|---|
| 필수 필드 누락·형식 오류 | `error` | 없음, `errors`에 사유 |
| `verdict = FALSE_POSITIVE` | `not_applicable` | 없음 (오탐이라 붙이지 않음) |
| `verdict = INCONCLUSIVE` 또는 provenance `unavailable` | `deferred` | 없음 (판단 보류) |
| provenance `passed` | 기법이 있으면 `mapped`, 없으면 `no_techniques_matched` | 판정 문구 + 모든 증거 |
| provenance `incomplete` | 기법이 있으면 `partial`, 없으면 `no_techniques_matched` | **원본 참조가 확인된 증거만**, 판정 문구 매칭 **꺼짐** |

`incomplete`일 때 제외되는 증거(`excluded_evidence_ids`): `raw_refs`가 비었거나, `evidence_without_raw_refs`에 있거나, 모호한 참조를 인용했거나, `provenance.issues`에 걸린 `sequence`의 증거.

**규칙 매칭** — 규칙 하나(`TechniqueRule`)는 기법 ID·이름, 전술 ID·이름과 키워드 묶음으로 되어 있다(`attack_mapping/rules/`, 현재 13개).

| 규칙 필드 | 비교 대상 | 방식 |
|---|---|---|
| `attack_type_keywords` | `final_verdict.attack_type` | 대소문자 무시 부분 문자열 |
| `evidence_keywords` | 증거 `description`, `event_type` | 대소문자 무시 부분 문자열 |
| `evidence_command_keywords` | 증거 `description`, `event_type` | **대소문자 구분**, 명령 경계 확인(`curl -T` ≠ `curl -t`), `--help` 뒤는 무시 |
| `required_context_keywords` | 같은 문장 조각 | 이 문맥이 **같은 긍정 절**에 있어야 매칭(예: T1041은 "C2 채널" 문맥 필수) |
| `context_subject_keywords` | 증거 전체 | 이 주제를 부정하는 절이 있으면 그 증거는 매칭 안 함 |
| `allow_verdict_hits` | — | `False`면 판정 문구로는 붙지 않음(T1041) |

문장은 쉼표·마침표·"but", "~으나", "~지만", "~없고" 등에서 절로 나눈다. **부정·미확인 표현**("없음", "확인되지 않음", "미확인", "not" 등)이 있는 절의 키워드는 쓰지 않는다. 예를 들어 "reverse shell은 확인됐으나 웹셸 실행은 확인되지 않았음"에서는 웹셸 기법이 붙지 않는다.

**병합** — 같은 기법의 매칭(판정 문구·여러 증거)을 하나로 합친다. 기법마다 `matched_by`, `matched_keywords`, `evidence_ids`, `raw_refs`, `times`, `matches`(증거별 연결 유지)를 가진다. 결과에는 `mapping_table_version`(규칙 전체의 SHA-256)이 붙어, 어떤 규칙으로 매핑했는지 추적할 수 있다.

### ③ Kill Chain — `killchain.build_kill_chain(techniques)`

1. **전술 순서**: Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command and Control → Exfiltration → Impact. 모르는 전술은 맨 뒤.
2. 같은 전술 안에서는 **가장 이른 시각**(UTC로 환산해 비교, 시간대 없는 시각은 UTC로 간주) 순. 해석 못 하는 시각은 그 뒤, 시각이 없는 기법(판정 문구로만 붙은 기법)은 맨 뒤.
3. 각 단계: `step`, `tactic_id/name`, `technique_id/name`, `time`(원래 표기 그대로), `evidence_ids`.

### ④ 최종 보고서 — `reporting/final_report.build_final_report()`

조사 결과 JSON을 깊은 복사한 뒤 `attack_mapping` 키에 ②+③ 결과를 넣는다. 원래 조사 필드는 바꾸지 않는다.

### ⑤ 저장 — `cli._write_output_pair()`

- `results/attack_mapping/<incident_id>_attack_mapping.json`과 `_final_report.json`을 **쌍으로** 만든다.
- 같은 사건을 다시 조사하면 `__2`, `__3` …을 붙여 이전 파일을 보존한다.
- `incident_id`는 파일 이름 하나로 정리한다(`/`, `\` 등은 `_`로, 폴더 밖 저장 방지).

---

## 6. 출력

### 폴더

```
results/
├── investigation_agent/
│   └── INV-<incident_id>-<날짜>-001_<UTC시각>.json     조사 결과 (원본)
└── attack_mapping/
    ├── <incident_id>_attack_mapping.json               매핑 결과 + kill_chain
    └── <incident_id>_final_report.json                 조사 결과 전체 + "attack_mapping"
```

두 폴더의 파일은 이름만으로는 짝이 맞지 않는다. 파일 안의 `investigation_id`로 연결한다.

### 콘솔 (`main.py`)

조사 보고서 아래에 매핑 결과가 붙는다(유출 합성 시나리오 예시).

```
ATT&CK Mapping: mapped — 매핑 완료
  1. [Collection] T1560 Archive Collected Data (2026-09-14T20:30:05.001Z) ← EVID-006, EVID-007
  [저장] results/attack_mapping/CONSISTENCY-TEST-05_attack_mapping.json
  [저장] results/attack_mapping/CONSISTENCY-TEST-05_final_report.json
```

`incomplete`로 제외한 증거가 있으면 `원본 참조 미확인으로 제외한 증거: …` 줄이 추가된다.

### 매핑 결과 JSON (`_attack_mapping.json`)

```json
{
  "incident_id": "CONSISTENCY-TEST-05",
  "investigation_id": "INV-CONSISTENCY-TEST-05-20260927-001",
  "mapping_status": "mapped",
  "provenance_status": "passed",
  "techniques": [{
    "technique_id": "T1560", "technique_name": "Archive Collected Data",
    "tactic_id": "TA0009", "tactic_name": "Collection",
    "matched_by": ["evidence"],
    "matched_keywords": ["site_backup.tar.gz", "tar -czf", "민감 디렉터리 압축"],
    "evidence_ids": ["EVID-006", "EVID-007"],
    "raw_refs": ["sample_audit.log:511", "sample_audit.log:512", "sample_audit.log:513", "sample_audit.log:514"],
    "times": ["2026-09-14T20:30:05.001Z", "2026-09-14T20:30:20.001Z"],
    "matches": ["… 증거별 매칭 기록 …"]
  }],
  "unmatched_evidence_ids": ["EVID-004", "EVID-005"],
  "excluded_evidence_ids": [],
  "raw_ref_locations": {"…": ["…"]},
  "mapping_table_version": "rules-v2-sha256:…",
  "errors": [],
  "kill_chain": [{"step": 1, "tactic_name": "Collection", "technique_id": "T1560", "time": "2026-09-14T20:30:05.001Z", "evidence_ids": ["EVID-006", "EVID-007"], "…": "…"}]
}
```

`unmatched_evidence_ids`는 매핑 대상이었지만 어떤 규칙에도 맞지 않은 증거다. 규칙 공백을 찾을 때 이 목록을 본다.

---

## 7. 조사 결과가 매핑 결과를 바꾸는 지점

매핑은 조사 결과의 **문장**을 규칙 키워드와 비교하므로, 조사 쪽 동작이 매핑 결과를 직접 바꾼다. 2026-09-27 통합 검증에서 확인하고 조사 쪽에서 맞춘 것:

| 조사 쪽 동작 | 매핑에 미치는 영향 | 조사 쪽 대응 |
|---|---|---|
| "조회 0건 → 활동 없음" 증거는 인용할 원본 줄이 없음 | provenance `incomplete` → `partial`, 판정 문구 매칭 꺼짐 → 판정 문구로만 붙는 기법(예: XML-RPC 대입 T1110)이 0개 | 증거에 `empty_result_call`(0건 도구 호출 번호)을 적고, 코드가 성공한 0건 호출인지 확인하면 누락으로 세지 않음 |
| LLM이 여러 공격 단계를 한 증거로 요약("tar 압축 및 curl 전송, 이후 삭제") | 명령 키워드(`tar -czf` 등)가 사라져 기법 누락 | 프롬프트: 공격 단계마다 증거 하나, 명령은 인자까지 원문 그대로 |
| 행위를 타임라인에만 적음 | 매핑은 타임라인을 읽지 않음 → 누락 | 프롬프트: 증거에 없는 행위를 타임라인에만 적지 않음 |
| 반박 증거(`contradicting_evidence`) | 매핑 대상 아님 | — |
| 증거 `time` | Kill Chain 시각. LLM이 반복 행위의 첫/마지막 시각 중 무엇을 적느냐에 따라 타임라인 시각과 다를 수 있음 | — |

조사 쪽 프롬프트(`agent/prompts/investigation.yaml`)나 증거 기록 규칙을 바꿀 때는 매핑까지 돌려서 확인한다(9장).

---

## 8. 알려진 한계

- **규칙 공백**: 유출 기법은 C2 문맥이 필요한 T1041뿐이라 일반 외부 업로드는 Exfiltration 단계가 비어 있고, 웹 서버 계정의 셸 실행(T1059.004), 정보 수집(T1033/T1082), 파일 삭제(T1070.004) 등이 붙지 않는다. 상세와 보완 요청은 [ATTACK_MAPPING_INTEGRATION_FEEDBACK_20260927.md](ATTACK_MAPPING_INTEGRATION_FEEDBACK_20260927.md) 4장.
- **LLM 문장 의존**: 같은 사건이라도 LLM 표현("명령 실행" vs "명령어 실행")에 따라 기법이 붙거나 빠질 수 있다. 장기적으로는 조사 도구가 코드로 계산한 기준값(`rule_checks`)을 결과 JSON에 남겨 구조화된 값으로 매핑하는 방안을 제안해 두었다(같은 문서 5-3).
- **대응 단계 미연결**: `build_final_report()`는 지금 `attack_mapping/cli.py` 안에서 불린다. 대응(Response) 단계가 생기면 `main.py`가 모든 단계를 마친 뒤 부르도록 옮기는 것을 팀과 정한다.

---

## 9. 실행과 검증

```bash
python main.py                                            # 전체: 조사 → 저장 → 매핑 → 최종 보고서 (LLM 필요)
python -m attack_mapping.cli results/investigation_agent/<파일>.json          # 저장된 조사 결과 하나만 다시 매핑
python -m attack_mapping.cli --all-in-dir results/investigation_agent         # 전체 다시 매핑 (결과는 results/attack_mapping/)

python -m pytest -q                                       # 오프라인 전체 (API 키 불필요)
python -m pytest -q tests/test_main_attack_mapping.py     # main.py ↔ 매핑 연결
python -m pytest -q tests/test_provenance.py              # 원본 참조·0건 증거 확인
python -m scripts.verify_attack_mapping_abc               # 어택 매핑 A/B/C 통합 검증 (실제 규칙)
```

변경할 때 확인할 것:

| 바꾸는 것 | 함께 돌릴 것 |
|---|---|
| 조사 결과 JSON 필드(`agent/report.py`) | `tests/test_main_attack_mapping.py`, `tests/test_attack_mapping_engine.py::test_actual_investigation_report_contract` |
| 조사 프롬프트·증거 기록 규칙 | 오프라인 테스트 + 실제 LLM으로 시나리오 조사 후 매핑 결과 확인(`scenarios/README.md`) |
| 매핑 규칙(`attack_mapping/rules/`) | `tests/test_attack_mapping_*`, `tests/test_main_attack_mapping.py`, `verify_attack_mapping_abc` |
| provenance 규칙(`agent/loop.py`, `agent/provenance.py`) | `tests/test_provenance.py`, `tests/test_main_attack_mapping.py` |

---

## [0928 희진 기록] 현재 흐름 (브랜치 `integrate-attack-mapping-rag`)

위 본문은 2026-09-27 `feature/investigation-attack-mapping`(`a1e60ce`) 기준 기록이라 그대로 둔다.
그 뒤 조사 쪽이 `feature/Agentic-SOC-Investigation-Agent`(개인 `integrate-investigation`)에서 바뀌었고
(`d802dbb`에서 매핑 삭제, `1e81525`에서 로그 수집·seed 생성 제거, `166e83f`에서 텍스트 보고서 제거),
0928에 그 최신(`051dda7`) 위에 매핑을 되살려 다시 연결했다. 지금 실제로 도는 순서는 아래와 같다.

```
python main.py <사건 파일>              사건 파일 = 1차 탐지 Incident JSONL 또는 직접 작성한 사건 JSON
 │
 ├─ [2]~[4]  준비: 도구 레지스트리 · LLM 클라이언트 · agent/incident_input.py load_incidents()
 │
 ├─ 조사 단계 (agent/)  ── LLM 사용 ─────────────────────────────────────────────
 │   ├─ incident_input.to_investigation_seed()   1차 탐지 Incident → 조사 입력
 │   │                                           (src_ip·window·evidence_refs·detection 요약·incident_key)
 │   ├─ [5] pipeline → loop                      network 사전 조회, 종료 관문 (a)~(h)
 │   │                                           ((g) 1차 탐지 참조 계층 미조회, (h) 1차 탐지 룰별 원본 미확인 — 0927 추가)
 │   └─ report.build_investigation_result()      결과 JSON
 │        + 증거별 supporting_tool_calls·seed_only_raw_refs, provenance.seed_only_evidence (a30a52e)
 │        + 최상위 incident_key·incident_snapshot (051dda7)
 │
 ├─ [45] save_investigation_result()  → results/investigation_agent/<investigation_id>_<UTC시각>.json
 │
 └─ [46] run_attack_mapping(저장 경로) → attack_mapping/cli.py process_file(경로, ALL_RULES, results/attack_mapping)
          ── LLM 사용 안 함(Rule 매핑) ──
          engine.map_investigation → killchain.build_kill_chain → reporting.build_final_report
          → results/attack_mapping/<incident_id>_attack_mapping.json, _final_report.json (재조사면 __2, __3 …)
```

본문과 달라진 점:

| 본문 위치 | 지금 |
|---|---|
| 1장 `[6]` 로그 수집, `[7]`~`[15]` seed 생성 | 없음. 사건을 찾고 고르는 일은 1차 탐지가 하고, 조사는 사건 파일을 받는다 |
| 6장 콘솔 | 조사 텍스트 보고서와 매핑 상세 출력(`format_attack_mapping`)이 없다. 저장 경로와 사건별 한 줄만 나온다 |
| 4장 매핑이 읽는 필드 | 그대로. 새 필드(`seed_only_raw_refs`, `supporting_tool_calls`, `incident_key`)는 Rule 엔진이 읽지 않는다. RAG 쪽 `validate.py`가 `seed_only_raw_refs`를 읽는다 |
| 5장 매핑 단계 | 그대로(Rule 경로). RAG 전환 중이며 담당 A의 `catalog.py`·`validate.py`·`schema.py`만 들어와 있고 아직 `main.py`에서 쓰지 않는다 |
| 사건 식별 | 매핑 결과·최종 보고서와 사건은 최상위 `incident_key`, `null`이면 `incident_id`로 잇는다(지금 Rule 경로의 파일명은 여전히 `incident_id` 기준) |

콘솔 예시:

```
--- 저장된 조사 결과 JSON 1건 ---
  results/investigation_agent/INV-INC-7d29ffde-20260928-001_20260928T101500Z.json
    ATT&CK 매핑: mapped (기법 2개: T1059.004, T1505.003)

--- 저장된 ATT&CK 매핑·최종 보고서 JSON 2건 ---
  results/attack_mapping/INC-7d29ffde_attack_mapping.json
  results/attack_mapping/INC-7d29ffde_final_report.json
```

관련 문서: [RAG A·B·C 협업 규칙](ATTACK_MAPPING_RAG_ABC_COLLABORATION.md), [담당 A 인계](ATTACK_MAPPING_A_CATALOG_VALIDATION_20260928.md), [증거 출처 필드](EVIDENCE_REF_SOURCES.md)

## [0930 통합 기록] 현재 `attack-mapping-final` 흐름

1. `main.py`가 Investigation의 `on_result` 콜백마다 조사 JSON을 먼저 저장한다.
2. 저장한 파일을 `attack_mapping.cli.process_file()`에 전달한다. 기본 경로는 RAG다.
3. A의 사건 관문·Evidence 분류를 통과한 증거만 B의 `HybridRetriever`가 BM25·Embedding·RRF로 검색한다.
   `attack_mapping/runtime.py`가 A의 공식 Catalog·Schema와 B 검색 결과를 연결한다.
4. C의 Mapper가 후보 안에서 LLM SELECT/ABSTAIN을 받고 A Validator로 개별 Selection을 검증한다.
   검증된 Technique만 병합하고 Evidence의 시각·sequence 순으로 Kill Chain을 만든다.
   공식 전술 순서는 사건 순서가 완전히 같을 때만 표시 순서를 정한다.
5. `results/attack_mapping/`에 매핑 JSON과 원본 조사 결과를 보존한 Final Report JSON을 분리해 저장한다.
   기술적 매핑 오류도 `mapping_status=error`로 기록하며 다음 사건 조사는 계속된다.

저장된 조사 JSON은 `python -m attack_mapping.cli <파일>`로 재매핑한다. 이전 규칙 비교는
`python -m attack_mapping.cli --rule-baseline <파일>`로 실행한다. 공식 STIX와 고정 모델 revision은
각각 `scripts.fetch_attack_catalog`, `scripts.fetch_attack_embedding`으로 명시적으로 준비한다.
CLI도 `.env`를 로드하며, 실제 모델·Claude API를 사용한 합성 사건 연결 결과는
[B 인계 문서](ATTACK_RETRIEVAL_HANDOFF.md)의 실제 모델·API 확인 기록에 있다.
