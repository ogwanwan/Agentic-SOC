# ATT&CK 매핑 RAG 전환 — 담당 A(Catalog·Schema·Validation) 인계 (2026-09-28)

받는 사람: 어택 매핑 담당 B(Retrieval), 담당 C(LLM Mapper·CLI·Final Report), 팀 전체
작성: 담당 A (희진)
브랜치: 개인 레포 `zhrldnpftl/WHS4-Agentic-SOC-Investigation-Agent`의 `integrate-attack-mapping-rag`
(조사 에이전트 최신 `integrate-investigation` = `051dda7` 위에 매핑 코드를 되살리고 A 작업을 올림.
팀 레포 반영 브랜치는 확인 후 정해서 알려 드립니다. B·C는 이 브랜치의 `attack_mapping/schema.py`를 계약 기준으로 써 주세요.)

## 1. 요약

- 공식 **MITRE ATT&CK Enterprise v19.2**(2026-08-05 공개, MITRE 최신)를 카탈로그로 붙였습니다. 활성 기법 697개(기법 222 + 하위 기법 475), 전술 15개입니다. 설계 17.2의 대표 기법 9개는 모두 활성 상태로 들어 있습니다.
- B·C가 같이 쓰는 **공통 자료형(schema.py)**, **카탈로그 조회(catalog.py)**, **사건 관문·증거 분류·LLM 선택 검증(validate.py)**을 만들었습니다.
- STIX 원본(54MB)은 **git에 올리지 않습니다.** 각자 스크립트로 한 번 받으면 되고(2장), `manifest.json`의 sha256으로 모두 같은 파일인지 확인합니다.
- **꼭 알아야 할 변경이 하나 있습니다.** ATT&CK v19에서 `Defense Evasion`이 `Stealth`로 이름이 바뀌었고 `Defense Impairment`(TA0112)가 새로 생겼습니다. 현재 Kill Chain 정렬 기준(`TACTIC_ORDER`)은 구버전이라 C의 확인이 필요합니다(5장 ①).
- 기존 Rule 경로(`engine.py`, `matching.py`, `rules/`, `killchain.py`, `cli.py`)는 **수정하지 않았습니다.** 전체 오프라인 테스트 394개 통과(조사 138 + 매핑 256), 1개 skip(Python 3.10).

## 2. 처음 한 번: ATT&CK 파일 받기

```bash
python -m pip install -r requirements.txt          # 새 의존성 없음 (표준 라이브러리만 사용)
python -m scripts.fetch_attack_catalog              # manifest에 고정된 19.2를 받아 sha256 확인
# → 확인 완료: ATT&CK 19.2, 활성 기법 697개, 전술 15개, sha256 dc1639caa550…
```

| 명령 | 언제 | 네트워크 |
|---|---|---|
| `python -m scripts.fetch_attack_catalog` | 새로 clone했을 때 (팀원 PC, EC2) | GitHub에서 공개 파일 1개 받기 |
| `… --verify` | 파일이 맞는지만 확인 | 없음 |
| `… --from-file <경로>` | 인터넷이 막힌 곳(EC2 등)에 다른 PC에서 받은 파일을 넣을 때 | 없음 |
| `… --version X.Y` / `--latest` | ATT&CK 버전을 올릴 때 (담당 A만) | 받기 + manifest 갱신 |

- 받은 파일은 `data/attack/enterprise-attack.json`에 놓이며 `.gitignore`에 들어 있습니다. git에는 `data/attack/manifest.json`만 올라갑니다.
- sha256이나 버전이 manifest와 다르면 파일을 설치하지 않고 실패로 끝납니다. 기존 파일도 건드리지 않습니다.
- 받은 파일이 없어도 오프라인 테스트는 모두 돕니다. 테스트는 합성 STIX(`tests/attack_stix_fixture.py`)를 쓰고, 실제 파일 검사 1개만 파일이 있을 때 추가로 실행됩니다.
- 로드 시간은 약 1.3초, 최대 메모리는 약 256MB입니다. 한 프로세스에서는 `get_default_catalog()`로 한 번만 로드해 주세요.

### manifest.json 키 담당

```json
{
  "attack_version": "19.2", "domain": "enterprise-attack", "stix_file": "enterprise-attack.json",
  "source_url": "…/enterprise-attack-19.2.json", "downloaded_at": "2026-09-28",
  "sha256": "dc1639ca…", "size_bytes": 53835637, "catalog_parser_version": "1",
  "active_technique_count": 697, "tactic_count": 15,
  "retrieval_version": null, "embedding_model": null
}
```

- `retrieval_version` 위의 키는 **A가 관리**합니다. 버전을 올릴 때 스크립트가 이 키들만 다시 씁니다.
- `retrieval_version`, `embedding_model`, 그 밖의 인덱스 설정 키는 **B가 채워 주세요.** A의 스크립트는 이 키들을 읽고 그대로 보존합니다.
- 코드에는 `"19.2"`를 적지 않습니다. 버전은 실행할 때 `catalog.attack_version`(= manifest 값이며, 파일 속 `x_mitre_version`과 일치하는지 로드할 때 확인)으로 읽습니다.

## 3. 공통 계약 — `attack_mapping/schema.py`

기존 Rule용 자료형은 그대로 두고 아래를 **추가**했습니다. dataclass는 모두 `frozen=True`입니다. 바꿔야 할 필드가 있으면 코드를 고치기 전에 A와 먼저 맞춰 주세요.

| 자료형 | 만드는 쪽 → 쓰는 쪽 | 핵심 |
|---|---|---|
| `TechniqueRecord`, `TacticRef` | catalog(A) → B·C | 공식 ID·이름·정리된 설명·전술(공식 순서)·부모·플랫폼·revoked/deprecated·revoked_by |
| `MappingUnit` | B(또는 C) → A 검증 | 증거 필드를 **그대로** 복사. `mapping_unit_id = "UNIT-" + evidence_id`. raw_refs는 비어 있으면 안 됨 |
| `CandidateTechnique` | B → C·A | `technique_id, name, description, tactics, parent_id, rank(1부터), score, sources` |
| `Selection`, `MappingDecision` | C가 LLM JSON을 파싱 → A 검증 | `MappingDecision.from_dict(dict)`: SELECT는 1개 이상, ABSTAIN은 0개. 형식이 깨지면 `DecisionFormatError`를 냄(**ABSTAIN으로 처리하지 말 것**). LLM이 보낸 name/tactic은 읽지 않음 |
| `ValidatedSelection` | A 검증 → C 병합 | 이름·전술·부모는 카탈로그 값, raw_refs·time은 증거 값. `flags`에 참고 표시 |
| `SelectionRejection` | A 검증 → 결과 JSON | `{code, mapping_unit_id, value, detail?, evidence_id?, reasons?}` |
| `AttackMappingEntry` | C 병합 → 결과 JSON | 기존 `MappedTechnique` + `parent_technique`, `selections`(Unit별 이유), `flags` |
| `AttackMappingResult` | C → 결과 JSON | 기존 키 + 선택 키 `attack_version, retrieval_version, mapping_method, exclusions, rejected_selections, retrieval_trace, warnings` |
| `CatalogError`, `InvestigationFormatError`, `DecisionFormatError` | — | 모두 `mapping_status = "error"`로 처리. 조사 결과는 이미 저장돼 있으므로 사라지지 않음 |

호환을 위해 지켜 주세요(C):
- `AttackMappingEntry`에도 `matched_by = ["evidence"]`, `matched_keywords = []`를 넣어 주세요. `killchain.py`와 기존 결과 읽는 코드가 그대로 동작합니다.
- 결과에 `mapping_table_version` 키를 남겨 주세요(값은 `None`). `cli.py`가 이 키로 "이미 만든 결과 파일"을 구분합니다.
- `errors`는 **문자열 목록**으로 유지하고 기술적 실패에만 씁니다. `cli.py:180`과 `main.py:118`이 문자열로 이어 붙여 출력합니다. 선택 거부는 `rejected_selections`에 넣어 주세요.

## 4. 사용법

### 4.1 B — `catalog.py`

```python
from attack_mapping.catalog import get_default_catalog
catalog = get_default_catalog()
catalog.techniques()        # 검색 문서 대상: 활성 697개, ID 순. revoked/deprecated는 이미 빠져 있음
catalog.fingerprint         # = manifest sha256. 인덱스에 저장해 두고 다르면 인덱스를 다시 만들 것
catalog.attack_version      # "19.2"
record.description          # (Citation: …), 마크다운 링크, <code> 태그를 제거한 설명
record.platforms            # ("Linux", "macOS", …) — Linux 우선 같은 순위 조정은 P1 검토
```

### 4.2 C — `validate.py` 호출 순서

```python
from attack_mapping.validate import (check_case_gate, classify_evidence, eligibility_index,
                                     target_evidence, exclusions, validate_decision)

gate = check_case_gate(result)                  # proceed / mapping_status / provenance_status / warnings / errors
if not gate.proceed: ...                        # not_applicable · deferred · error → 검색·LLM 호출 없이 종료
rows = classify_evidence(result)                # InvestigationFormatError → error
index = eligibility_index(rows)
for row in target_evidence(rows):               # 이 증거들만 Mapping Unit이 된다
    unit = …                                    # row.evidence의 필드를 그대로 복사
    candidates = …                              # B
    decision = MappingDecision.from_dict(llm_json)   # DecisionFormatError → error
    accepted, rejected = validate_decision(decision, unit=unit,
        candidate_ids=[c.technique_id for c in candidates], catalog=catalog, eligibility=index)

excluded_evidence_ids = [e["evidence_id"] for e in exclusions(rows)]   # exclusions도 결과에 저장
```

`classify_evidence()`의 증거 분류:

| 분류 | 사유 코드 | 조건 |
|---|---|---|
| target | — | Mapping Unit이 됨 |
| context | `EMPTY_RESULT` | `provenance.empty_result_evidence`에 있음(**passed여도** Unit이 안 됨) |
| context | `CONTRADICTING` | 반박 증거. 체인 밖이라 `excluded_evidence_ids`에는 넣지 않음 |
| excluded | `NO_RAW_REFS` | raw_refs가 비었거나 `evidence_without_raw_refs`에 있음 |
| excluded | `PROVENANCE_ISSUE` | `provenance.issues[].sequence` = 증거 sequence(도구 호출 번호가 아님) |
| excluded | `AMBIGUOUS_RAW_REF` | `ambiguous_raw_refs` 또는 `raw_ref_locations`에서 위치가 2개 이상 |
| excluded | `UNOBSERVED_RAW_REF` | 최상위 `raw_refs`에 없는 참조 |
| (표시만) | `SEED_ONLY_RAW_REFS` | 인용한 참조 중 **1차 탐지(seed)에만 있고 조사 도구로 관측되지 않은 참조가 하나라도** 있음(참조 단위). 증거의 `seed_only_raw_refs` 필드가 있으면 그 값을 쓰고, 없는 이전 결과는 `tools_called[].raw_refs`·`provenance.seed_raw_refs`로 같은 규칙을 계산. **분류는 바뀌지 않음**(5장 ③). 해당 참조는 `row.seed_only_raw_refs` |

증거의 `supporting_tool_calls`(그 증거의 참조를 관측한 도구 호출 번호)는 판정에 쓰지 않고 schema에도 넣지 않았습니다. 최종 보고서에서 필요하면 `evidence_chain`에서 바로 읽으면 됩니다.

**사건 연결 키**: 결과 JSON과 사건은 **최상위 `incident_key`로 잇고, `null`이면 `incident_id`**를 씁니다(`initial_seed.incident_key`가 아니라 최상위 값). `incident_key`는 1차 탐지 DB의 안정 키로 2026-09-30 DB 연결 뒤 채워지며, 지금 사건 파일 결과는 모두 `null`입니다. 결과 파일명(`<investigation_id>_<UTC시각>.json`) 규칙에 기대지 말아 주세요(C: 매핑 결과·최종 보고서의 사건 식별에 적용).

`excluded_evidence_ids`는 "evidence_chain 중 Unit이 되지 않은 증거"이고, 사유는 `exclusions`에 있습니다. `unmatched_evidence_ids`는 "Unit이었지만 최종 기법이 없는 증거"입니다. 두 목록을 섞지 말아 주세요.

`validate_decision()`의 거부 코드(★는 selection 전체를 버림, 나머지는 해당 evidence_id만 뺌):

| 코드 | 의미 |
|---|---|
| ★ `UNIT_NOT_TARGET` / `UNIT_MISMATCH` | Unit 증거가 target이 아님 / Unit 필드가 원본 증거와 다름(sequence·raw_refs 재번호 등) |
| ★ `INVALID_TECHNIQUE_ID` | 형식이 틀렸거나 카탈로그에 없음(T9999 등) |
| ★ `REVOKED_OR_DEPRECATED` | 폐기된 기법. detail에 대체 ID를 적지만 **자동으로 바꾸지 않음** |
| ★ `NOT_IN_CANDIDATES` | 이 Unit의 후보에 없음. 부모나 하위 기법으로 바꿔 주지 않음 |
| ★ `UNIT_EVIDENCE_NOT_CITED` | evidence_ids에 이 Unit의 증거가 없음 |
| ★ `EMPTY_REASON` | 선택 이유가 비어 있음 |
| `EVIDENCE_OUTSIDE_UNIT` / `EVIDENCE_NOT_MAPPABLE` / `UNKNOWN_EVIDENCE_ID` | 다른 Unit의 증거 / 매핑 불가 증거 / 없는 증거 id |
| `DUPLICATE_SELECTION` | 같은 Unit에서 같은 기법을 두 번 고름 → 두 번째를 버림 |

기법 ID의 공백·대소문자(` t1059.004 `)는 맞춰 주되, 결과의 `flags`에 `TECHNIQUE_ID_NORMALIZED`를 남깁니다. 다른 ID로 바꾸는 보정은 하지 않습니다.

## 5. 설계 문서와 다르게 간 것 · 팀이 정할 것

| # | 내용 | A의 추천 / 현재 구현 | 누구와 |
|---|---|---|---|
| ① | **v19 전술 변경**: `Defense Evasion` → `Stealth`(TA0005), `Defense Impairment`(TA0112) 신설. `T1070.004 File Deletion`, `T1562`, `T1036` 등이 `stealth`. 지금 `killchain.py`는 14개짜리 `TACTIC_ORDER`로 정렬하므로 이 기법들이 "알 수 없는 전술"이 되어 **맨 뒤로 밀림** | RAG 경로의 Kill Chain은 `catalog.tactic_order`로 정렬. `TACTIC_ORDER`는 Rule 기준이라 그대로 둠(`test_attack_mapping_engine.py`가 값을 고정해서 검사함) | C |
| ② | 여러 전술을 가진 기법의 대표 전술(예: `T1078`은 4개). 기존 engine은 tactic_id 순 첫 번째(TA0001) | `tactics`는 공식 순서로 모두 보존. 대표 전술 규칙은 C가 정함 | C |
| ③ | **seed 참조만 인용한 증거**: 조사 쪽 초안은 제외했지만, 실제 웹셸 합성 시나리오 결과 1건에서 핵심 증거 4개(php 쓰기, `sh -c`, `sudo su`, `useradd`)가 모두 이 경우였음 → 제외하면 기법이 모두 사라짐 | 설계 9.4대로 **제외하지 않고** `SEED_ONLY_RAW_REFS` 표시. 조사 쪽 관문 (g)(h) 도입 전 결과. 이후 결과는 seed_only 필드로 표시됨(7장) | 팀 |
| ④ | provenance가 없는 결과(0922 이전 형식) | 기존 engine과 같이 `deferred`. 알 수 없는 verdict·status는 `error` | 팀 |
| ⑤ | 폴백 판정(`[자동 폴백 판정`)·판정-원칙 충돌(`⚠ 판정-원칙 불일치`) 사건 | 지금은 진행하고 `warnings`에만 기록. mapped로 둘지 deferred로 둘지 팀 정책 필요 | 팀 |
| ⑥ | 설계 10.1은 거부된 ID를 `errors`에 dict로 넣음 | `errors`는 문자열 유지, 거부는 `rejected_selections`(3장) | C |
| ⑦ | selection의 evidence_ids 범위 | P0는 **해당 Unit 증거만** 인정. 다른 Unit 후보로 검증을 우회하지 못하게 하기 위함. 프롬프트에도 "evidence_ids에는 Target Evidence id만"을 적어 주세요 | C |
| ⑧ | 후보 목록이 있어야 검증할 수 있음 | P0에서 최소 `retrieval_trace = [{mapping_unit_id, candidate_ids}]` 저장 | B·C |
| ⑨ | 같은 증거에서 부모와 하위 기법이 함께 선택됨(예: `T1059`+`T1059.004`) | 병합할 때 하위 기법만 남기기 제안 | C |
| ⑩ | Sigma ATT&CK Tag | 1차 탐지 Incident에는 `signal_tags`(webroot, exec 등)만 있고 ATT&CK 태그가 없음. 설계의 `initial_seed.attack_tags`는 **존재하지 않는 필드**. P1로 미루거나 1차 탐지팀에 요청 | 팀 |

## 6. 실제 조사 결과로 확인한 것

조사 에이전트 저장소의 `results/investigation_agent/INV-*.json` 34개(합성 시나리오·반복 측정 결과)에 관문과 증거 분류를 적용했습니다(읽기 전용, 결과 파일은 수정하지 않음).

- 관문: 진행 22, deferred 8(INCONCLUSIVE, provenance 없는 옛 결과 포함), not_applicable 4, error 0
- 진행한 22건의 evidence_chain: target 66, context 5(모두 0건 증거), excluded 4(모두 `NO_RAW_REFS`, 0923 incomplete 결과), seed 참조 표시 4(모두 아래 `T120704`)
- target 증거는 모두 raw_refs가 있고 전부 최상위 `raw_refs`에 등록돼 있음. 0건 증거가 target이 된 경우 없음
- 34개 모두 증거 출처 필드(`a30a52e`)가 생기기 전 결과라서, seed 표시는 참조 단위 규칙으로 계산한 값입니다.

웹셸 합성 시나리오(`INC-7d29ffde`) 결과는 조사 쪽 종료 관문 (g)(h) 도입 전후로 성격이 다릅니다. 파일명 시각은 **UTC**이고, 커밋 시각으로 자르지 않고 결과별로 구분합니다.

| 결과 | 구분 | 매핑 관문 · 증거 |
|---|---|---|
| `T115708` | (g) 도입 전 | INCONCLUSIVE → deferred |
| `T120704` | (g) 도입 전 — web·auth만 조회하고 audit 미조회 | target 5, 그중 seed 참조 표시 4 (5장 ③) |
| `T121505` | 경계 — (g) 커밋(`8213a2c`, 12:15:53 UTC)보다 48초 앞. 첫 도구는 `fetch_audit_log(pid=1200)` | target 3, seed 표시 0 |
| `T122331`, `T122929` | (h)(`95bcb50`, 12:24:55 UTC) 도입 후 | target 5 / 6, seed 표시 0 |

## 7. 조사 에이전트 요청 사항 — 처리됨

조사 브랜치(개인 `integrate-investigation`, 팀 `feature/Agentic-SOC-Investigation-Agent`)에 반영·push 완료. 기준 커밋 `051dda7`. 자세한 설명은 조사 쪽 `docs/EVIDENCE_REF_SOURCES.md`.

1. **seed가 audit 참조인데 audit을 조회하지 않고 끝나는 경우 — 처리됨(추가 작업 없음)**. 조사 쪽에 이미 strict 종료 관문 두 개가 있습니다.
   - (g) 1차 탐지 참조를 인용했는데 그 계층을 한 번도 조회하지 않으면 거부 (`8213a2c`, 2026-09-27 21:15 KST)
   - (h) 1차 탐지 룰마다 원본을 도구로 확인하지 않았고 unknowns에도 남기지 않으면 거부 (`95bcb50`, 21:24 KST)
   - 5장 ③의 `T120704`는 (g) 도입 전 실행이고, 이후 결과는 첫 도구가 audit 조회입니다(6장 표).
2. **증거별 출처 필드 — 처리됨** (`a30a52e`, 안내 문서 `a5c55dd`).
   - `evidence_chain[]`·`contradicting_evidence[]` 각 증거
     - `supporting_tool_calls`: 이 증거의 raw_refs를 관측한 `tools_called[].sequence` 목록(network 사전 조회 포함, 0건 증거는 코드가 확인한 `empty_result_call`, 확인 실패면 `[]`)
     - `seed_only_raw_refs`: raw_refs 중 seed에만 있고 어떤 도구 결과에서도 관측되지 않은 참조
   - `provenance.seed_only_evidence`: `seed_only_raw_refs`가 있는 증거 id 목록(반박 증거 포함). `provenance.status`에는 반영하지 않음(표시용)
   - 계산 기준은 조사 종료 시점의 전체 도구 호출이라, 증거를 적은 뒤에 도구로 확인된 참조는 seed_only에서 빠집니다.
3. **결과 최상위 연결 키 — 처리됨** (`051dda7`): `incident_key`(없으면 `null`), `incident_snapshot {incident_id, member_count, updated_at}`. 연결 규칙은 4.2 끝의 "사건 연결 키" 참고.

## 8. 검증과 미검증 범위

실행한 것 (Windows, Python 3.10.x — EC2와 같은 3.10):

```bash
python -m pytest -q                                             # 394 passed(조사 138 + 매핑 256), 1 skipped
python -m pytest -q tests/test_attack_catalog.py tests/test_attack_validate.py
INV_RESULTS_DIR=<조사 결과 폴더> python -m pytest -q tests/test_attack_validate.py   # 실제 결과 스모크 포함
python -m scripts.fetch_attack_catalog && python -m scripts.fetch_attack_catalog --verify
```

- 합성 STIX 테스트: 활성/비활성 구분, 부모·하위 기법 교차 확인, 공식 전술 순서, 설명 정리, sha256·버전 불일치, 활성 ID 중복, 부모 없는 하위 기법, 알 수 없는 전술, manifest의 B 키 보존, 검증 실패 시 기존 파일 유지
- 검증 테스트: 관문 상태, 분류 사유 6가지, issue sequence와 도구 호출 번호 혼동 방지, 입력 불변, LLM 결정 형식 오류, 거부 코드 전체, 여러 selection 중 일부만 실패, ABSTAIN
- seed 표시: 필드 있음 / 필드 없음(이전 결과) / 도구 관측·seed 참조 혼합 / 나중 조회로 관측 / 반박 증거 / 필드가 raw_refs 밖을 가리킴(형식 오류). 조사 코드(`InvestigationAgent`)가 실제로 만든 결과 JSON으로 필드 있음·없음 판정이 같은지도 확인

아직 확인하지 않은 것:
- `retrieve.py`(B)와 `mapper.py`(C)가 아직 없어서, RAG 전체 E2E는 돌리지 않았습니다. 이 인계의 계약은 대역 없이 합성 데이터로만 검증했습니다.
- EC2에서의 파일 받기·로드(메모리 약 256MB)는 확인하지 않았습니다.
- 실제 카탈로그로 확인한 것은 로드·ID·전술 조회까지입니다. 검색 품질은 B의 범위입니다.

## 9. 바뀐 파일

| 파일 | 내용 |
|---|---|
| `attack_mapping/schema.py` | RAG 자료형·예외 추가. `AttackMappingResult`에 선택 키 추가(`total=False` 상속, 3.10 호환). 기존 자료형·`TACTIC_ORDER` 값은 그대로 |
| `attack_mapping/catalog.py` (새 파일) | STIX 파싱·검증·조회 |
| `attack_mapping/validate.py` (새 파일) | 사건 관문·증거 분류·선택 검증 |
| `scripts/fetch_attack_catalog.py` (새 파일) | 받기·검증·버전 올리기 |
| `data/attack/manifest.json` (새 파일) | 19.2 고정 |
| `.gitignore` | `data/attack/enterprise-attack.json` 제외 |
| `tests/attack_stix_fixture.py`, `tests/test_attack_catalog.py`, `tests/test_attack_validate.py` (새 파일) | 오프라인 테스트 |
