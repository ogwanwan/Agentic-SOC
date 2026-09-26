# ATT&CK 매핑 추가 점검 결과

> 후속 작업에서 아래 F1~F6와 저장·호환성 문제를 수정했습니다.
> 현재 수정 상태와 검증 결과는 [추가 수정 보고서](ATTACK_MAPPING_FIX_REPORT_20260927.md)를 참고하세요.
> 아래 본문·행 번호·관찰 결과는 **수정 전 점검 기록**으로 보존합니다.

기존에 수정한 4종의 버그는 재검증을 통과했습니다. 다만 추가 입력을 사용하자 **공격 기법을 잘못 붙이거나, 일부 파일을 누락하거나, 배치 처리가 중단되는 문제**가 재현됐습니다. 기존 테스트 통과만으로 매핑 정확도와 모든 입력 처리를 보장할 수는 없습니다.

이번 작업은 추가 점검입니다. 제품 코드와 기존 테스트는 변경하지 않았으며, 재현 스크립트·합성 입력·출력·이 문서를 추가했습니다. 아래 수정 방향은 제안이며 아직 적용하지 않았습니다.

| 점검 기준 | 내용 |
| --- | --- |
| 브랜치 / 기준 HEAD | `feature/ATT&CK-test` / `67d0a472a9d19deb01b4429b8c2e1d45779aeda0` |
| 실제 대상 | 이전 버그 수정이 미커밋 상태로 포함된 작업 트리 |
| 실행 환경 | Windows, 저장소 `.venv`, Python 3.14.6 |
| 기존 검증 재실행 | ATT&CK 관련 pytest 134개, 전체 오프라인 pytest 261개, 연결 검사 249개 모두 통과 |
| 추가 점검 | 실제 Catalog·엔진·CLI, 실제 조사 보고서 형식의 합성 입력, 입력 형태 변형 140개, 출력 장애·동시 쓰기 모사 |
| 실행하지 않은 것 | AWS·LLM API, 운영 로그 조사, 합성 로그에 적힌 명령어 실행 |

**우선 수정할 문제와 재현 근거**

| 번호 | 문제 | 실제 관찰 결과 | 영향 |
| --- | --- | --- | --- |
| F1 | 명령어 옵션의 대소문자 구분 소실 | `curl -t`에도 `T1041` 부여 | 업로드가 아닌 명령을 유출 기법으로 분류 |
| F2 | 행동의 부정·미확인 문맥 무시 | “웹셸 실행은 확인되지 않았음”에도 `T1505.003` 부여 | 실제 확인된 공격에 확인되지 않은 기법이 추가됨 |
| F3 | T1041의 C2 조건 미확인 | C2 연관성 미확인인 외부 전송에도 `T1041` 부여 | 확보한 근거보다 구체적인 공격 방법으로 분류 |
| F4 | 일부 예외에서 배치 전체 중단 | CP949 출력 오류·깊은 JSON에서 다음 정상 파일 미처리 | 파일 하나의 문제로 뒤의 사건 처리 누락 |
| F5 | 대문자 확장자 누락 | `a.json`, `b.JSON` 중 하나만 처리하면서 종료 코드 0 | 일부 조사 결과가 알림 없이 빠짐 |
| F6 | 입력·출력 폴더가 같으면 생성물을 재처리 | 두 번째 실행에서 보고서 수 1개 → 4개, 오류 결과 포함 | 중복·불필요한 오류 보고서 누적 |

**F1 — 명령어 옵션 대소문자를 보존해야 합니다.**

발생 위치: [engine.py](../attack_mapping/engine.py)의 `_keywords()` 79~83행, [post_exploitation.py](../attack_mapping/rules/post_exploitation.py)의 T1041 규칙 185~200행.

엔진은 자연어와 명령어를 구분하지 않고 입력과 키워드에 `casefold()`를 적용합니다. 규칙에 등록된 `curl -T`가 `curl -t`로 바뀌므로 서로 다른 옵션이 일치합니다.

합성 로그 문자열 `curl -t TTYPE=vt100 telnet://example.invalid/`를 실제 엔진에 전달했을 때 `mapping_status=mapped`, `technique_id=T1041`, `matched_keywords=["curl -t"]`가 나왔습니다. 대문자 `-T`를 사용한 대조 사례도 같은 키워드를 기록했습니다. curl 공식 문서에서 `-t`는 Telnet 옵션, `-T`는 파일 업로드 옵션이므로 구별해야 합니다. [curl -t 설명](https://curl.se/docs/manpage.html#-t), [curl -T 설명](https://curl.se/docs/manpage.html#-T)

수정 방향: 자연어 검색의 대소문자 무시와 명령어·옵션 매칭을 분리하고, 옵션은 원래 대소문자를 유지한 토큰으로 비교해야 합니다. 모든 키워드를 일괄적으로 대소문자 구분으로 바꾸면 기존 자연어 규칙에 영향을 줄 수 있습니다.

근거: [재현 입력](../results/attack_mapping_review_20260927/edge_cases/curl_telnet_option/input.json), [실제 매핑](../results/attack_mapping_review_20260927/edge_cases/curl_telnet_option/mapping.json).

**F2 — 공격이 확인된 사건이어도 개별 행동의 부정 문맥은 구분해야 합니다.**

발생 위치: [engine.py](../attack_mapping/engine.py)의 `_keywords()`와 `_evidence_hits()` 136~150행. 조건은 현재 부분 문자열 포함 여부입니다.

단순 부정문뿐 아니라 실제 공격과 미확인 행동을 함께 적은 문장으로도 확인했습니다.

| 증거 설명 | 실제 부여한 기법 | 문제 |
| --- | --- | --- |
| `reverse shell 연결은 확인됐으나 웹셸 실행은 확인되지 않았음` | T1059.004, T1505.003 | 웹셸 실행을 부정했는데 웹셸 기법까지 부여 |
| `reverse shell 연결 후 useradd --help 실행만 확인. 계정 생성은 없었음` | T1059.004, T1136.001 | 도움말 조회를 실제 계정 생성으로 분류 |

사건 전체가 `THREAT_CONFIRMED`라는 사실만으로 그 문장에 언급된 모든 행동이 수행된 것은 아닙니다. 별도의 `contradicting_evidence` 목록은 기존대로 매칭에서 제외됩니다. 여기서 확인한 문제는 **지지 증거 한 문장에 확인된 행동과 부정된 행동이 함께 들어오는 경우**입니다.

수정 방향: 행동별 확인 여부·성공 여부를 구조화하거나, 기법 후보와 확정 매핑을 구분해야 합니다. 문장에 “없음”이 있다는 이유만으로 그 문장의 모든 공격을 제외하는 방식은 적절하지 않습니다.

근거: [웹셸 사례의 입력](../results/attack_mapping_review_20260927/mixed_context/webshell/input.json), [웹셸 매핑](../results/attack_mapping_review_20260927/mixed_context/webshell/mapping.json), [계정 생성 매핑](../results/attack_mapping_review_20260927/mixed_context/account/mapping.json).

**F3 — 외부 전송만으로 T1041을 확정하는 규칙은 근거가 부족합니다.**

발생 위치: [post_exploitation.py](../attack_mapping/rules/post_exploitation.py)의 T1041 규칙 185~207행.

`외부 서버로 전송. C2 통신과의 연관성은 확인되지 않았음`이라는 증거도 `T1041`로 매핑됐습니다. 이 규칙은 `curl -T`, `외부 서버로 전송`, `데이터 유출` 등의 표현 중 하나만 있어도 일치합니다.

MITRE의 T1041은 기존 명령·제어(C2) 채널을 통해 데이터를 유출하는 기법입니다. 외부 전송 사실만으로 해당 채널과의 관계까지 확인되지는 않습니다. 따라서 이 사례에서는 T1041에 필요한 근거가 충족되지 않았다는 것이 이번 검토 판단입니다. [MITRE T1041 정의](https://attack.mitre.org/techniques/T1041/)

수정 방향: C2 채널과 전송의 관계를 추가 조건으로 확인하고, 정보가 부족하면 기법을 확정하지 않도록 해야 합니다. 다른 기법 ID로 일괄 교체하는 것도 피해야 합니다.

근거: [재현 입력](../results/attack_mapping_review_20260927/edge_cases/transfer_without_c2_evidence/input.json), [실제 매핑](../results/attack_mapping_review_20260927/edge_cases/transfer_without_c2_evidence/mapping.json).

**F4 — 일부 출력·입력 예외가 파일 단위로 격리되지 않습니다.**

발생 위치: [cli.py](../attack_mapping/cli.py)의 `run()` 143~150행, [final_report.py](../reporting/final_report.py)의 `build_final_report()` 25행.

첫 번째 사례는 `PYTHONIOENCODING=cp949`를 명시한 Windows 호환성 실험입니다. 첫 사건 ID에 이모지가 있으면 JSON 저장은 끝나지만, 예외 처리 블록 밖의 `print(_summary_line(...))`에서 `UnicodeEncodeError`가 발생합니다. 두 번째 정상 사건의 파일은 생성되지 않았습니다. 같은 입력을 UTF-8 출력 설정으로 실행하면 두 파일 모두 처리했습니다. 현재 모든 실행 환경에서 발생한다는 뜻은 아니며, CP949처럼 해당 문자를 표현하지 못하는 출력 환경에서 재현됩니다.

두 번째 사례는 외부 입력 경계 실험입니다. 정상 조사 객체에 중첩 배열 600단계인 추가 필드를 넣으면 JSON 읽기는 성공하지만 최종 보고서의 `deepcopy()`에서 `RecursionError`가 발생합니다. CLI는 이 예외를 처리하지 않아 다음 정상 사건도 누락됩니다. 이는 조사 에이전트의 일반 출력에서 발생했다고 확인한 사례는 아닙니다.

수정 방향: 콘솔 출력 실패가 사건 처리를 중단시키지 않게 하고, 파일 읽기·보고서 생성에서 처리할 입력 한계와 예외를 명시해야 합니다. 배치에서는 해당 파일의 실패를 기록하고 다음 입력을 계속 처리하는 계약을 유지하는 것이 좋습니다.

근거: [CP949 실행 로그](../results/attack_mapping_review_20260927/edge_cases/console_encoding/process_cp949/process.json), [UTF-8 대조 로그](../results/attack_mapping_review_20260927/edge_cases/console_encoding/process_utf-8/process.json), [깊은 JSON 실행 로그](../results/attack_mapping_review_20260927/edge_cases/deep_json/process.json).

**F5 — `.JSON` 확장자는 배치에서 알림 없이 제외됩니다.**

발생 위치: [cli.py](../attack_mapping/cli.py)의 `_investigation_files()` 39~45행.

`name.endswith(".json")`만 검사하므로 `b.JSON`을 목록에 넣지 않습니다. 유효한 조사 파일 `a.json`, `b.JSON`을 함께 넣었을 때 보고서는 `a.json`에 해당하는 하나만 생성됐으며 종료 코드는 `0`이었습니다. 특히 Windows에서 확장자를 대소문자 구분 없이 다루는 사용자에게 처리 완료로 오인될 수 있습니다.

수정 방향: 확장자를 대소문자 구분 없이 비교하고 실제 파일인지 확인해야 합니다. 처리 대상·제외 대상 개수를 출력하면 누락 확인에도 도움이 됩니다.

근거: [배치 실행 로그](../results/attack_mapping_review_20260927/edge_cases/uppercase_extension/process.json), [입력 폴더](../results/attack_mapping_review_20260927/edge_cases/uppercase_extension/inputs).

**F6 — 같은 입력·출력 폴더를 반복 사용하면 결과를 다시 입력으로 읽습니다.**

발생 위치: [cli.py](../attack_mapping/cli.py)의 `_investigation_files()`와 `run()` 136~145행.

`--all-in-dir`와 `--out-dir`에 같은 폴더를 주는 것을 허용하지만, 생성한 `*_attack_mapping.json`, `*_final_report.json`을 다음 실행에서 제외하지 않습니다. 원본 조사 파일 하나로 첫 실행은 최종 보고서 한 개를 만들었습니다. 두 번째 실행에서는 이전 매핑 파일을 조사 입력으로 읽어 오류 보고서를 만들고, 이전 최종 보고서와 원본 조사 파일도 다시 처리하여 최종 보고서가 총 네 개가 됐습니다.

기존 기본값처럼 입력 폴더와 출력 하위 폴더가 분리되어 있으면 이 재현 조건에 해당하지 않습니다. 이번 문제는 동일 폴더를 사용하거나 생성물을 입력 폴더에 섞는 경우입니다.

수정 방향: 같은 입출력 폴더를 명확히 금지하거나, 생성물과 조사 입력을 구별하는 목록·형식 기준을 도입해야 합니다. 파일명만으로 제외할 경우 실제 조사 파일을 잘못 제외하지 않도록 해야 합니다.

근거: [첫 실행](../results/attack_mapping_review_20260927/edge_cases/shared_input_output/first/process.json), [두 번째 실행](../results/attack_mapping_review_20260927/edge_cases/shared_input_output/second/process.json).

**호환성·규칙 범위와 기존 한계도 별도로 확인했습니다.**

| 항목 | 관찰 결과 | 해석 |
| --- | --- | --- |
| UTF-8 BOM | `Unexpected UTF-8 BOM`으로 해당 입력을 건너뜀. 다음 정상 파일은 처리 | 외부 편집기로 저장한 JSON과의 호환성 문제. 현재 조사 에이전트의 저장 형식에는 BOM이 없음 |
| 명령 표현 변형 | `curl --upload-file`은 미매칭, `curl -T`는 매칭 | 현재 키워드 목록의 커버리지 제한. 같은 업로드 옵션 표현을 동일하게 처리하지 못함. 이것이 곧 T1041 확정 근거라는 뜻은 아님 |
| 저장 도중 장애 | 최종 보고서 쓰기 중 ENOSPC를 모사하면 완성된 매핑 JSON과 깨진 최종 JSON이 남음 | 이전 수정 보고서에 기재한 두 파일 저장의 비원자성 재확인. 실제 디스크를 채우지는 않았음 |
| 동시 저장 | 같은 이름을 선택하도록 두 호출의 타이밍을 맞추면 하나는 성공, 하나는 `FileExistsError`; 조사 보고서 하나만 저장 | 이전에 기재한 동시 실행 한계 재확인. 기존 파일 덮어쓰기는 발생하지 않음 |
| 검증 보고서 고정 문구 | JSON 요약은 실패 0개이나 자동 생성 Markdown 본문에 “5개 실패” 설명이 남음 | 이전부터 알려진 검증 스크립트 문서 생성 문제. 현 상태 판단에는 `summary.json`·`checks.json` 사용 |

추가 관찰의 전체 원문은 [observations.json](../results/attack_mapping_review_20260927/edge_cases/observations.json)에 있습니다. 동시 저장 사례는 재현 시 어떤 호출이 먼저 저장될지는 달라질 수 있지만, 저장 성공 1개·충돌 1개라는 결과를 관찰했습니다.

제품 코드의 입력 검증에서는 별도로 140개 필드·자료형 변형을 엔진과 Kill Chain에 전달했습니다. 결과는 `error` 118개, `mapped` 16개, `deferred` 2개, `no_techniques_matched` 4개이며 처리되지 않은 예외는 없었습니다. 이 수치는 예외 발생 여부를 확인한 것이며 각 변형에 대한 매핑 의미가 모두 맞다는 검증은 아닙니다.

기존 검증의 재실행 근거: [전체 pytest 로그](../results/attack_mapping_review_20260927/baseline/pytest_full/stdout.txt), [연결 검증 요약](../results/attack_mapping_review_20260927/baseline/summary.json). 기존 4종 버그에 해당하는 검사 5개는 이번에도 모두 통과했습니다.

재현 명령은 다음과 같습니다. 프로젝트 루트에서 실행했습니다.

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_attack_mapping_abc --out-dir results/attack_mapping_review_20260927/baseline
.\.venv\Scripts\python.exe results/attack_mapping_review_20260927/recheck.py
.\.venv\Scripts\python.exe results/attack_mapping_review_20260927/recheck_mixed_context.py
```

[주 재현 스크립트](../results/attack_mapping_review_20260927/recheck.py)는 관찰값을 저장하는 도구입니다. 종료 코드 0은 재현 절차가 완료됐다는 뜻이며 제품에 문제가 없다는 뜻은 아닙니다. 다시 실행할 때는 `--out-dir`에 새 경로를 지정해야 합니다. [혼합 문맥 재현 스크립트](../results/attack_mapping_review_20260927/recheck_mixed_context.py)는 기존 자료 보호를 위해 `mixed_context` 폴더가 이미 있으면 실행을 중단합니다. [검증 대상 파일 해시](../results/attack_mapping_review_20260927/edge_cases/metadata.json)도 남겼습니다.

매핑 정확도 관련 F1~F3와 배치 누락·중단 관련 F4~F5를 우선 개선할 것을 권합니다. 이번 점검 결과는 합성 사례에서 확인한 동작이며, 실제 운영 데이터에서의 발생 빈도나 탐지율·오탐률은 측정하지 않았습니다. 코드 수정, 커밋, push는 이번 추가 점검에 포함하지 않았습니다.
