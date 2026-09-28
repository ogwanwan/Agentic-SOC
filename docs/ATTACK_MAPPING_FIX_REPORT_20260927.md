# ATT&CK 매핑 추가 버그 수정 보고서

[추가 점검](ATTACK_MAPPING_REVIEW_20260927.md)에서 재현한 F1~F6을 수정했습니다. 명령어의 의미와 부정 문맥을 구분하고, C2 근거가 부족한 유출 매핑을 제한했으며, 입력·출력 장애가 다음 사건 처리를 중단시키지 않도록 보완했습니다.

최종 검증은 **전체 오프라인 pytest 301개 통과, ATT&CK 관련 pytest 174개 통과, A/B/C 연결 검사 297개 통과·0개 실패**입니다. ATT&CK 관련 테스트는 전체 테스트의 부분집합이며 두 수를 합산하지 않습니다. ABCD 오프라인 데모도 통과했습니다.

| 작업 기준 | 내용 |
| --- | --- |
| 날짜 / 환경 | 2026-09-27 KST, Windows, Python 3.14.6, 저장소 `.venv` |
| 브랜치 / 기준 HEAD | `feature/ATT&CK-test` / `67d0a472a9d19deb01b4429b8c2e1d45779aeda0` |
| 검증 대상 | 위 HEAD에 이전 수정과 이번 수정이 포함된 **미커밋 작업 트리** |
| 반영 상태 | 로컬 코드·테스트·문서 수정 완료. 이번 작업의 커밋·push 없음 |
| 이전 작업 | 파일명 보호·중복 저장 보존·비객체 JSON 격리·UTC 정렬 수정 유지 |
| 증빙 | [최종 검증 요약](../results/attack_mapping_fix_20260927/verification_final/summary.json), [연결 검증 보고서](../results/attack_mapping_fix_20260927/verification_final/report.md), [수정 파일·해시 기록](../results/attack_mapping_fix_20260927/fix_manifest.json) |

## 1. 어디서 발생했고 어떻게 고쳤는가

### F1. `curl -t`와 `curl -T`를 같은 명령으로 취급

이전 [engine.py](../attack_mapping/engine.py)의 `_keywords()`는 자연어와 명령어 모두에 `casefold()`를 적용했습니다. 이 때문에 서로 다른 옵션을 같은 키워드로 비교했습니다.

[matching.py](../attack_mapping/matching.py)를 추가해 자연어 검색과 명령어 비교를 분리했습니다. 자연어는 대소문자를 무시하지만, `evidence_command_keywords`는 명령어와 옵션의 대소문자를 보존하고 연속 공백을 허용합니다. 명령어 경계도 검사해 `myuseradd`나 더 긴 옵션의 일부가 일치하는 것을 제한합니다.

`curl -t`는 C2 문맥이 있어도 T1041을 만들지 않습니다. `curl -T`와 `curl --upload-file`은 별도의 C2 조건까지 충족해야 T1041 후보가 됩니다. `matched_keywords`에도 `curl -T`의 대문자를 유지합니다. 관련 명령어 규칙을 옮기는 과정에서 `wget http://…`와 `wget https://…`의 기존 매칭도 함께 검증했습니다. 옵션 의미의 기준은 [curl 공식 문서](https://curl.se/docs/manpage.html)입니다.

### F2. 부정·미확인·도움말에 적힌 행동까지 실제 행동으로 매핑

이전 엔진은 증거 설명 안에 키워드가 있는지만 검사했습니다. 따라서 “reverse shell 연결은 확인됐으나 웹셸 실행은 확인되지 않았음”에서 두 기법을 모두 붙였습니다.

[matching.py](../attack_mapping/matching.py)는 문장 부호와 일부 한국어·영어 연결 표현으로 절을 나누고, 등록된 부정·미확인 표현이 있는 절을 제외합니다. 명령어 뒤의 `--help`, `-h`, `--version`도 명령 실행 근거에서 제외합니다. 설명에서 해당 행동을 명시적으로 부정했으면 `event_type`의 이름만으로 이를 다시 추가하지 않습니다.

이제 위 혼합 문장은 확인된 T1059.004만 남기며, `useradd --help`는 계정 생성으로 매핑하지 않습니다. 반면 `failed password`와 “SSH 인증 실패”는 공격 시도의 근거가 될 수 있으므로 `failed`·“실패”를 일괄 부정어로 처리하지 않습니다. 이 동작은 정해진 표현을 검사하는 방식이며 모든 자연어의 의미를 해석하는 것은 아닙니다.

### F3. C2 근거 없이 외부 전송만으로 T1041 부여

이전 [post_exploitation.py](../attack_mapping/rules/post_exploitation.py)의 T1041 규칙은 `curl -T`, “외부 서버로 전송” 같은 표현 하나만으로 일치했습니다. [MITRE의 T1041 정의](https://attack.mitre.org/techniques/T1041/)에 필요한 C2 채널과의 관계를 확인하지 않았습니다.

T1041은 이제 **동일 증거의 같은 필드·같은 긍정 절에 전송 행동과 등록된 C2 관계 표현이 함께 있을 때** 후보를 생성합니다. 예를 들어 “기존 C2 채널을 통해 curl -T를 사용해 외부 서버로 전송”은 조건을 충족합니다. 다른 증거·다른 절에서 C2 표현을 빌려오지 않고, 해당 증거가 C2 연관성을 부정·미확인으로 기술하면 제외합니다. 최종 판정의 `attack_type`만으로 T1041을 만들지도 않습니다.

조건이 부족한 증거는 다른 기법으로 임의 치환하지 않습니다. 이 증거에 일치하는 다른 규칙도 없으면 `unmatched_evidence_ids`에 남습니다. 이후 기존 provenance 검증과 판정 정책을 그대로 적용하므로 키워드 일치 자체가 최종 채택을 보장하지 않습니다.

### F4. 콘솔 출력 오류·깊은 JSON으로 배치 중단

이전 [cli.py](../attack_mapping/cli.py)의 요약 출력은 파일별 예외 처리 밖에 있어 CP949에서 이모지를 출력하면 다음 사건까지 누락됐습니다. 깊은 JSON은 최종 보고서 복사 중 `RecursionError`가 발생해 같은 문제가 생겼습니다.

콘솔에서 표현할 수 없는 문자는 이스케이프해 출력하고, 콘솔 자체의 쓰기 오류도 다음 파일 처리를 막지 않게 했습니다. JSON은 복사 전에 반복 방식으로 깊이를 검사합니다. 루트를 0으로 센 최대 허용 깊이는 `MAX_JSON_DEPTH=128`입니다. 한계를 넘거나 JSON 파싱 자체에서 재귀 오류가 나면 해당 파일을 실패로 기록하고 다음 파일을 처리합니다. 배치에 처리 실패가 있으면 종료 코드 1을 반환합니다.

실제 CP949 CLI 하위 프로세스, 600·1,500단계 중첩 입력, 콘솔 쓰기 오류 모사에서 다음 정상 사건의 보고서가 저장되는 것을 확인했습니다.

### F5. `.JSON` 파일이 배치 대상에서 빠짐

이전 `_investigation_files()`는 소문자 `.json`만 선택했습니다. 이제 확장자를 소문자로 비교하고 실제 파일 여부도 확인합니다. `a.json`과 `b.JSON`을 함께 처리하며 `directory.json`이라는 폴더는 입력에서 제외합니다. 읽기 인코딩을 `utf-8-sig`로 바꿔 UTF-8 BOM이 있는 JSON도 허용했습니다.

### F6. 생성한 결과물을 조사 입력으로 다시 처리

이전 CLI는 같은 입출력 폴더를 허용하고 모든 JSON을 재처리해 반복 실행마다 불필요한 보고서를 생성했습니다.

배치의 `--all-in-dir`와 `--out-dir`가 같은 실제 경로이면 작업 전에 사용법 오류로 종료합니다(종료 코드 2). 생성물이 다른 입력 폴더에 섞인 경우에도 매핑 결과의 구조를 확인해 건너뜁니다. 파일명 접미사만으로 제외하지 않으므로 `source_final_report.json`이라는 이름의 정상 조사 입력은 처리합니다. 생성물만 있어 실제 조사 입력을 하나도 처리하지 못하면 종료 코드 1입니다.

## 2. 저장과 검증 보고서도 함께 보완

| 문제 | 수정 | 확인한 결과 |
| --- | --- | --- |
| 보고서 저장 중 실패하면 불완전한 두 파일이 남음 | 두 문서를 먼저 직렬화하고 두 경로를 배타적으로 연 뒤 저장. 처리 가능한 예외가 나면 이번 시도에서 만든 파일만 정리 | 최종 파일 열기·쓰기 단계의 ENOSPC 모사에서 이전 파일 보존, 새 불완전 파일 제거, 다음 사건 처리 |
| 같은 사건을 동시에 저장하면 한쪽이 충돌로 실패 | 배타적 생성의 `FileExistsError`를 잡아 다음 빈 이름으로 재시도 | 두 저장 호출의 이름 선택 시점을 맞춘 테스트에서 조사 2건과 대응하는 매핑·보고서 쌍 모두 보존 |
| 검증 Markdown에 과거의 고정된 실패 설명 잔존 | [검증 스크립트](../scripts/verify_attack_mapping_abc.py)가 실제 검사 결과로 경계 사례 상태·개수를 출력 | 최종 JSON과 Markdown 모두 실패 0개로 일치 |

두 파일을 한 번에 확정하는 파일시스템 트랜잭션은 아닙니다. 프로세스 강제 종료·전원 차단·정리 권한 상실까지 완전 복구하는 기능은 포함하지 않습니다.

## 3. 규칙 계약과 호출부 변화

[TechniqueRule](../attack_mapping/schema.py)에 아래 기본값이 있는 필드를 추가했습니다. 기존 위치 인자 순서를 유지하기 위해 `notes` 뒤에 배치했습니다.

| 필드 | 자료형 / 기본값 | 동작 |
| --- | --- | --- |
| `evidence_command_keywords` | `Tuple[str, ...]` / `()` | 대소문자를 보존하는 명령어 조각 |
| `required_context_keywords` | `Tuple[str, ...]` / `()` | 증거 매칭 시 같은 긍정 절에서 함께 요구하는 문구 중 하나 |
| `context_subject_keywords` | `Tuple[str, ...]` / `()` | 증거 설명에서 부정·미확인되면 해당 규칙을 제외할 문맥 주제 |
| `allow_verdict_hits` | `bool` / `True` | 최종 판정 문구만으로 후보 생성 허용 여부. T1041은 `False` |

기존 자연어 `evidence_keywords`와 명령어 키워드는 후보 생성에서 OR 관계이며, 문맥 조건은 추가 AND 조건입니다. `required_context_keywords`는 증거 매칭용이므로 판정 단독 매칭도 제한하려면 `allow_verdict_hits=False`를 설정해야 합니다.

새 필드를 규칙 해시에 포함하고 직렬화 버전을 `rules-v2-sha256:`으로 변경했습니다. 규칙 순서·중복 키워드가 달라도 같은 해시이며, 명령어 옵션의 대소문자나 조건이 바뀌면 다른 해시입니다. 최종 해시 전체는 [검증 요약](../results/attack_mapping_fix_20260927/verification_final/summary.json)에 기록했습니다. 이는 MITRE 데이터베이스 버전 번호가 아닙니다.

조사 입력 JSON, Evidence ID, 원본 참조, 시각 문자열은 보존합니다. `main.py`에 자동 호출을 추가하지 않았으며 실행 방식은 여전히 **조사 결과 JSON → ATT&CK CLI → 최종 보고서**입니다.

## 4. 검증 방법과 증빙

[추가 회귀 테스트](../tests/test_attack_mapping_review_regressions.py)는 실제 `ALL_RULES`를 사용합니다. 최초 수정 전에는 당시 작성한 32개 사례 중 29개가 실패했고, 구현 후 저장 장애·동시 실행·기존 wget 동작 보존 사례 등을 더해 최종 40개가 모두 통과했습니다. 처음과 마지막 테스트 집합의 크기가 다르므로 동일 집합의 성공률 비교로 해석하지 않습니다. [수정 전 JUnit 기록](../results/attack_mapping_fix_20260927/regression_before.xml)도 보존했습니다.

기존 T1041 양성 예제에는 새 규칙의 전제인 C2 근거를 명시했습니다. 동시에 **C2 근거가 없는 원래 형태가 매칭되지 않아야 한다는 별도 음성 테스트**를 추가했습니다. 통합 검증에도 C2 없는 유출·Telnet 옵션·혼합 부정 문맥 사례를 넣었습니다.

최종 실행 명령:

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_attack_mapping_abc --out-dir results/attack_mapping_fix_20260927/verification_final
```

이 경로에는 이미 증빙이 있으므로 재실행할 때는 새로운 `--out-dir`를 지정합니다. 기본값을 사용해도 매 실행마다 새 폴더를 만듭니다.

| 검증 | 최종 결과 | 근거 |
| --- | --- | --- |
| ATT&CK 관련 pytest | 174 passed | [stdout](../results/attack_mapping_fix_20260927/verification_final/pytest_related/stdout.txt) |
| 전체 오프라인 pytest | 301 passed | [stdout](../results/attack_mapping_fix_20260927/verification_final/pytest_full/stdout.txt) |
| ABCD 오프라인 데모 | 성공 | [stdout](../results/attack_mapping_fix_20260927/verification_final/upstream_demo/process/stdout.txt) |
| 실제 Catalog·엔진·CLI·보고서·원본 참조 연결 검사 | 297 passed / 0 failed | [전체 검사](../results/attack_mapping_fix_20260927/verification_final/checks.json) |

## 5. 남은 범위

부정 문맥·명령어·C2 관계 검사는 등록된 표현과 절 경계를 사용하는 보수적인 규칙입니다. 임의의 자연어, 이중 부정, 모든 셸 옵션 배치, 여러 문장에 나뉜 인과관계를 완전히 해석하지 않습니다. 표현에 따라 실제 행동을 놓치거나 잘못 연결할 가능성이 남으므로 운영 정확도는 별도 데이터로 평가해야 합니다.

이번 검증은 합성 입력과 장애 모사를 사용한 오프라인 검증입니다. 실제 AWS·LLM API·운영 로그, 다른 OS·Python 버전에서의 실행, 실제 디스크 고갈·전원 장애는 검증하지 않았습니다. 로그의 명령 문자열을 실행하지 않았습니다.
