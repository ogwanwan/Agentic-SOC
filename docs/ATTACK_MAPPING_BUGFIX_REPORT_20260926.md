# ATT&CK 보고서 생성·시간 정렬 버그 수정 보고서

기존 연결 검증에서 발견한 **버그 4종을 수정했고, 그 버그 때문에 실패했던 검사 5개가 모두 통과했습니다.** 같은 사건을 여러 번 조사해도 결과를 보존하며, 잘못된 입력 이후에도 다음 파일을 처리하고, 출력 폴더를 벗어나지 않으며, 시간대를 반영해 사건 시각을 비교합니다.

| 항목 | 내용 |
| --- | --- |
| 작업 브랜치 | `feature/ATT&CK-test` |
| 기준 커밋 | `67d0a472a9d19deb01b4429b8c2e1d45779aeda0` |
| 검증 환경 | Windows, Python 3.14.6, 저장소 `.venv` |
| Git 반영 | 기준 커밋 위의 로컬 미커밋 수정. 이번 작업의 커밋·push는 하지 않음 |
| 수정 코드 | [cli.py](../attack_mapping/cli.py), [killchain.py](../attack_mapping/killchain.py) |
| 회귀 테스트 | [CLI 테스트](../tests/test_attack_mapping_cli.py), [Kill Chain 테스트](../tests/test_attack_mapping_killchain.py) |
| 이전 결과 | [수정 전 검증 보고서](../results/attack_mapping_abc_20260926T142707000598Z/report.md) |
| 수정 후 근거 | [검증 요약 JSON](../results/attack_mapping_bugfix_20260926/verification/summary.json), [개별 검사 결과](../results/attack_mapping_bugfix_20260926/verification/checks.json) |

여기서 A/B/C는 ATT&CK 모듈의 역할 구분입니다. A는 분류 엔진, B는 공격 기법 규칙표, C는 Kill Chain·최종 보고서·CLI 저장을 담당합니다. 이번 문제는 C의 입력 처리, 저장, 정렬에 있었습니다.

**1. 같은 사건의 조사 결과가 덮어써지는 문제**

발생 위치는 `attack_mapping/cli.py`의 `_output_stem()`과 `process_file()`입니다. 이전에는 조사 ID가 달라도 사건 ID가 같으면 동일한 파일명을 만들고, `open(..., "w")`로 저장했습니다. 두 번째 조사가 첫 번째 조사 보고서를 덮어쓰므로 최종 파일은 하나만 남았습니다.

예를 들어 `INC-MULTISTAGE` 사건을 `INV-REPEAT-1`, `INV-REPEAT-2` 두 번 조사하면 두 조사 모두 `INC-MULTISTAGE_final_report.json`에 저장됐습니다.

수정 후에는 `_output_paths()`가 매핑 결과와 최종 보고서 **두 경로 모두 비어 있는 이름**을 고릅니다. 기존 파일이 있으면 `__2`, `__3` 순으로 번호를 붙입니다. 이미 있는 파일을 다시 쓰지 않도록 파일 생성 모드도 `"x"`로 바꿨습니다.

```text
첫 번째 조사 → INC-MULTISTAGE_final_report.json
두 번째 조사 → INC-MULTISTAGE__2_final_report.json
```

매핑 JSON에도 같은 번호를 사용합니다. 두 파일 중 하나만 이미 있어도 그 이름은 건너뜁니다. 별도 CLI 실행을 반복하거나, 서로 다른 ID를 파일명으로 정리한 결과가 같아져도 기존 파일을 보존합니다. 번호는 저장 충돌을 구분하기 위한 것이며 조사 ID를 대신하지 않습니다. 원래 사건 ID·조사 ID는 JSON 안에 그대로 남습니다.

실제 재검증에서 **보고서 2개와 조사 ID 2개 모두 보존**됐습니다. [실제 관찰 결과](../results/attack_mapping_bugfix_20260926/verification/boundaries/same_incident/observation.json)

**2. 잘못된 JSON 하나 때문에 이후 파일 처리가 중단되는 문제**

발생 경로는 `attack_mapping/cli.py`의 `process_file()` → `reporting/final_report.py`의 `build_final_report()`입니다. JSON 문법이 맞더라도 내용이 `[]`이면 조사 결과에 필요한 객체 형태가 아닙니다. A 엔진은 이를 `error`로 돌려줬지만, C는 원래의 배열을 그대로 보고서 생성 함수에 넘겼습니다.

보고서 생성 함수는 객체를 받는 계약에 따라 `final_report["attack_mapping"] = ...`를 수행합니다. 배열에는 이 작업을 할 수 없어 `TypeError`가 발생했고, 기존 CLI의 예외 처리 대상에도 포함되지 않아 다음 파일까지 중단됐습니다.

수정 후에는 **JSON을 읽은 직후 최상위 값이 객체인지 확인**합니다. 배열·문자열·숫자·불리언·`null`은 파일명과 이유를 표준 오류에 남기고 건너뜁니다. 다음 정상 파일은 계속 처리하되, 입력 실패가 있었으므로 전체 종료 코드는 `1`을 유지합니다.

```text
a.json = []        → [a.json] skipped: investigation_result must be a JSON object
b.json = 정상 입력 → 매핑 결과와 최종 보고서 저장
전체 종료 코드    → 1
```

객체 형태이지만 필수 필드가 빠진 입력은 기존대로 엔진의 `mapping_status=error` 결과를 저장합니다. 객체가 아닌 입력에는 불완전한 출력 파일을 만들지 않습니다. 정상 객체의 최종 보고서 조립도 파일 저장 전에 완료하도록 순서를 옮겼습니다.

실제 재검증에서 **오류를 기록하면서 다음 파일의 보고서가 생성**됐습니다. [오류 기록](../results/attack_mapping_bugfix_20260926/verification/boundaries/non_object/observation.json), [다음 파일의 최종 보고서](../results/attack_mapping_bugfix_20260926/verification/boundaries/non_object/out/INC-MULTISTAGE_final_report.json)

**3. 지정한 출력 폴더를 벗어나 저장되는 문제**

발생 위치는 `attack_mapping/cli.py`의 `_output_stem()`과 저장 경로 조립 부분입니다. 이전에는 `incident_id`를 그대로 경로에 붙였습니다. `incident_id="../escaped-proof"`이면 `requested/../escaped-proof_final_report.json`이 되어 `requested`의 상위 폴더에 저장됐습니다.

수정 후에는 사건 ID를 **경로가 아닌 파일 이름 하나로 정리**합니다. 슬래시·역슬래시·콜론·제어 문자 등은 `_`로 바꾸고, 이름 양끝의 점·공백, Windows 예약 이름, 빈 이름과 긴 이름도 처리합니다. 한글 ID는 유지하며, UTF-8 기준 이름 본문을 최대 180바이트로 제한해 결과 접미사 공간을 남깁니다.

```text
입력 ID         : ../escaped-proof
수정 전 저장 위치: requested/../escaped-proof_final_report.json
수정 후 저장 위치: requested/_escaped-proof_final_report.json
JSON 안의 ID    : ../escaped-proof  (원문 보존)
```

이름 변환으로 충돌이 생기면 1번의 번호 정책을 적용합니다. 기존 경로가 심볼릭 링크인 경우에도 사용 중인 이름으로 취급합니다.

실제 재검증에서 **두 결과 파일 모두 요청한 출력 폴더 안에 생성**됐습니다. 회귀 테스트에서는 역슬래시, 절대 경로, Windows 예약 이름과 변환 후 이름 충돌도 확인했습니다. [실제 저장 위치](../results/attack_mapping_bugfix_20260926/verification/boundaries/path_escape/observation.json)

**4. 시간대가 섞이면 순서와 대표 시각을 잘못 선택하는 문제**

발생 위치는 `attack_mapping/killchain.py`의 `_representative_time()`과 `build_kill_chain()`입니다. 이전에는 `min(times)`와 문자열 정렬을 사용했습니다. 문자열의 글자 순서가 실제 시각 순서와 항상 같지는 않습니다.

| 원래 표기 | UTC로 환산한 실제 시각 | 올바른 순서 |
| --- | --- | --- |
| `2026-09-26T09:00:00+09:00` | `2026-09-26T00:00:00Z` | 먼저 |
| `2026-09-26T01:00:00Z` | `2026-09-26T01:00:00Z` | 나중 |

이전 코드에서는 글자상 `01:00`이 `09:00`보다 앞서므로 두 번째를 먼저 선택했습니다. 이 로직이 기법 간 정렬과 같은 기법의 대표 시각 선택에 모두 사용되어 검사 2개가 실패했습니다.

수정 후에는 `_time_sort_key()`에서 시각을 파싱하고 **UTC로 환산한 값으로 비교**합니다. 기존 공통 `normalize_iso()`를 재사용해 `Z`와 `+0900` 같은 표기를 처리하며, 공유 정규화 코드는 수정하지 않았습니다. 보고서에는 선택된 시각의 원래 문자열을 남깁니다.

다음 동작도 명시적으로 유지·정의했습니다.

- 공격 단계 순서를 먼저 적용하고, 같은 단계 안에서 시각을 비교합니다.
- 같은 실제 시각은 입력 순서를 유지합니다. UTC 표기로 일괄 덮어쓰지 않습니다.
- 시간대가 없는 시각은 기존 조사 도구와 같이 UTC로 간주합니다.
- 해석할 수 있는 시각을 우선합니다. 해석 불가 문자열만 있으면 첫 원문을 남기고, 같은 단계의 유효 시각 뒤에 배치합니다. 시각 자체가 없는 기법은 그 뒤에 둡니다.
- 원래 `times`, 증거 ID, 원본 참조는 수정하지 않습니다.

실제 재검증에서 **T1505.003 → T1098.004 순서**가 되었고, 여러 증거가 같은 기법으로 합쳐진 경우에도 **대표 시각은 `2026-09-26T09:00:00+09:00`**으로 올바르게 선택됐습니다. [기법 간 순서](../results/attack_mapping_bugfix_20260926/verification/boundaries/timezone/actual_kill_chain.json), [대표 시각](../results/attack_mapping_bugfix_20260926/verification/boundaries/timezone/same_technique_actual.json)

수정 전에는 새로 추가한 핵심 회귀 사례 13개를 먼저 실행해 **11개 실패·2개 통과**를 확인했습니다. 기존 버그와 추가 입력 변형을 직접 재현한 결과이며, 원래 연결 검증의 5개 실패 검사와는 서로 다른 검사 묶음입니다. [수정 전 회귀 결과 XML](../results/attack_mapping_bugfix_20260926/regression_before.xml)

수정 후 검증 결과는 다음과 같습니다. 아래 검사 묶음은 일부 겹치므로 개수를 더해서 해석하지 않습니다.

| 검증 | 결과 | 근거 |
| --- | --- | --- |
| CLI·Kill Chain·E2E 집중 테스트 | 43개 통과 | [결과 XML](../results/attack_mapping_bugfix_20260926/regression_after.xml) |
| ATT&CK 관련 pytest 전체 | 134개 통과 | [실행 로그](../results/attack_mapping_bugfix_20260926/verification/pytest_related/stdout.txt) |
| 프로젝트 전체 오프라인 pytest | 261개 통과 | [실행 로그](../results/attack_mapping_bugfix_20260926/verification/pytest_full/stdout.txt) |
| 기존 A/B/C 연결 검증 | 249개 통과, 실패 0개, 종료 코드 0 | [검증 요약](../results/attack_mapping_bugfix_20260926/verification/summary.json) |
| 기존 ABCD 데모 | 종료 코드 0, provenance passed | [실행 로그](../results/attack_mapping_bugfix_20260926/verification/upstream_demo/process/stdout.txt) |
| 변경 내용 공백 검사 | `git diff --check` 통과 | 로컬 작업 트리 검사 |

원래 실패했던 검사와 수정 후 결과의 대응은 다음과 같습니다.

| 기존 검사 이름 | 수정 전 | 수정 후 |
| --- | --- | --- |
| `boundary:same_incident_keeps_both_investigations` | 보고서 1개 | 보고서 2개 |
| `boundary:non_object_json_does_not_abort_next_file` | 다음 파일 처리 중단 | 다음 정상 파일 처리 완료 |
| `boundary:output_stays_in_requested_directory` | 상위 폴더에 저장 | 지정 폴더 안에 저장 |
| `boundary:timezone_aware_order` | T1098.004 → T1505.003 | T1505.003 → T1098.004 |
| `boundary:timezone_aware_representative_time` | `2026-09-26T01:00:00Z` | `2026-09-26T09:00:00+09:00` |

실행한 명령은 다음과 같습니다. 프로젝트 루트에서 실행했습니다.

```powershell
# 수정 전: 핵심 회귀 사례 13개 재현
.\.venv\Scripts\python.exe -m pytest -q tests/test_attack_mapping_cli.py::test_same_incident_keeps_both_investigations tests/test_attack_mapping_cli.py::test_non_object_json_does_not_abort_next_file "tests/test_attack_mapping_cli.py::test_output_stays_in_requested_directory[../escaped-proof]" tests/test_attack_mapping_killchain.py::test_timezone_aware_order_and_representative_time --junitxml=results/attack_mapping_bugfix_20260926/regression_before.xml

# 수정 후: CLI·Kill Chain·E2E 집중 검증
.\.venv\Scripts\python.exe -m pytest -q tests/test_attack_mapping_cli.py tests/test_attack_mapping_killchain.py tests/test_attack_mapping_e2e.py --junitxml=results/attack_mapping_bugfix_20260926/regression_after.xml

# 수정 후: 관련/전체 pytest, 실제 CLI, 기존 데모, 원래 실패 사례를 함께 검증
.\.venv\Scripts\python.exe -m scripts.verify_attack_mapping_abc --out-dir results/attack_mapping_bugfix_20260926/verification

git diff --check
```

마지막 검증 스크립트의 `--out-dir`은 새 경로여야 합니다. 다시 실행할 때는 다른 이름을 주거나 옵션을 생략해 자동으로 새 폴더를 생성하세요. 수정 전 코드가 필요한 첫 번째 명령은 현재 수정된 코드에서는 동일한 실패를 재현하지 않습니다.

이번 실행에서는 기존 `scripts/verify_attack_mapping_abc.py`를 변경하지 않았습니다. SHA-256은 `c3631d057a7c87f02c7a5f3a711786698441ad6fbaf2de94aa1d0fb7313ea39d`로 유지됐습니다. 이 스크립트가 생성하는 `verification/report.md`에는 수정 전 버그 설명이 고정 문구로 남아 있으므로, 수정 후 판정은 위의 `summary.json`·`checks.json`과 이 보고서를 기준으로 확인해야 합니다. `summary.json`의 커밋 값은 기준 HEAD이며, 미커밋 수정의 내용 자체를 나타내지는 않습니다. [검증한 변경분](../results/attack_mapping_bugfix_20260926/worktree.patch), [작업 파일 해시](../results/attack_mapping_bugfix_20260926/fix_metadata.json)를 함께 남겼습니다.

ATT&CK 분류 규칙, A 엔진의 gate·provenance 정책, 출력 JSON 스키마는 그대로 유지했습니다. `schema.py`, `reporting/final_report.py`, 공유 벤더 정규화 코드는 수정하지 않았습니다. 기존 검증 보고서도 덮어쓰지 않았습니다.

이 검증은 합성 데이터와 고정 LLM 응답을 사용하는 오프라인 검증입니다. AWS·실제 LLM API 호출이나 실제 운영 탐지 정확도 평가는 포함하지 않았습니다. Python 3.10용 시간 표기 정규화는 기존 함수를 재사용했지만 실제 실행 환경은 3.14.6이며, 다른 운영체제 실행은 확인하지 않았습니다. 또한 결과 파일 두 개를 저장하는 작업 전체가 하나의 트랜잭션인 것은 아니므로, 디스크 오류나 동시 프로세스 간 저장 경쟁에서는 일부 파일만 남을 수 있습니다. 기존 파일 덮어쓰기는 배타적 생성으로 방지합니다.
