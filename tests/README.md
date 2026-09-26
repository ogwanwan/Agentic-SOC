# 테스트 실행 안내

처음 받는 팀원은 [A·B·C·D 통합 안내](../docs/ABCD_TEST_GUIDE.md)의 설치 순서대로 실행하세요.
모든 명령은 **프로젝트 루트**에서 실행합니다. Python 3.10 이상이 필요합니다.

## 가장 짧은 실행 방법

가상환경을 활성화한 뒤:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m scripts.demo_abcd
```

전체 테스트는 AWS/LLM API를 호출하지 않습니다. `.env`도 필요하지 않습니다.
설치 시에는 패키지 다운로드 연결이 필요합니다. `pytest.ini`가 실제 Gemini를 호출하는
`test_consistency.py`를 자동 실행 대상에서 제외합니다.

ABCD 연결만 집중해서 확인하려면:

```bash
python -m pytest -v tests/test_abcd_pipeline.py tests/test_cd_normalizer_integration.py tests/test_event_window.py tests/test_provenance.py
```

## 무엇을 확인하는가

| 파일 | 확인 내용 |
| --- | --- |
| `test_abcd_pipeline.py` | 실제 수집 → seed 생성·검증 → B 도구·프로세스 조회 → C 페이지 조회 → D 최종 보고서. 단일 계층 4개/4계층 통합, 모사 S3, 가짜 참조 거부, 환경변수 복원 |
| `test_cd_normalizer_integration.py` | A의 벤더 직접 호출과 입력 수집/B 개별 도구/C 사건 조회 결과 비교. audit 분할 객체, gzip, 원본 위치·모호성 |
| `test_normalizer_parity.py` | 기존 A 어댑터 API와 벤더 결과 비교. `_run()`을 위 통합 테스트에서 호출하므로 전체 pytest에도 포함 |
| `test_event_window.py` | C의 시간 양끝·시간대·연도 경계·필터·전역 페이지·입력 오류·파일 누락/권한 |
| `test_provenance.py` | D의 seed/지지·반박 증거/JSON·텍스트 참조 유지, audit 여러 줄, 미등록 참조, 도구 실패 이후 참조 유지 |
| `test_fetch_*_log.py`, `test_get_process_tree.py` | B의 계층별 필터와 프로세스 연결 |
| `test_raw_log_ingestion.py`, `test_seed_generation.py` | 로그 수집과 사건 후보 우선순위 |
| `test_pipeline.py` | 여러 seed가 우선순위대로 조사에 전달되는지 검사 |
| `test_loop.py` | 종료 조건·중복 호출 방지·최대 호출 수·도구 오류 처리 |
| `test_attack_mapping_cli.py` | ATT&CK 결과 저장, 같은 사건의 여러 조사·반복 실행 보존, 비객체 JSON 뒤의 배치 처리, 출력 폴더 이탈·파일명 충돌 방지 |
| `test_attack_mapping_killchain.py` | 공격 단계 우선 정렬, UTC 환산 순서·대표 시각, 동일 시각의 안정 정렬, 원래 시각·입력 보존 |
| `test_attack_mapping_e2e.py` | ATT&CK 매핑 → Kill Chain → CLI 저장 → 최종 보고서 연결 |
| `test_attack_mapping_review_regressions.py` | 실제 Catalog의 명령어 대소문자·부정/도움말·C2 조건, CP949/콘솔 장애·깊은 JSON·BOM·대문자 확장자, 생성물 재입력 차단, 저장 장애 정리·동시 저장 재시도 |

ATT&CK 저장·입력·시간대 회귀 사례의 발생 원인과 수정 전후 결과는
[버그 수정 보고서](../docs/ATTACK_MAPPING_BUGFIX_REPORT_20260926.md)를 참고하세요.
후속 점검에서 발견한 매핑 오분류·배치 처리 문제의 수정은
[추가 수정 보고서](../docs/ATTACK_MAPPING_FIX_REPORT_20260927.md)에 정리했습니다.
실제 Catalog·조사 출력 형식·CLI를 연결한 검증 자료는 다음 명령으로 새 폴더에 생성할 수 있습니다.

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_attack_mapping_abc
```

이 명령은 관련/전체 오프라인 pytest와 ABCD 데모를 포함합니다. `--out-dir`을 지정하면
아직 존재하지 않는 경로를 사용해야 하며, 검사 실패 시 종료 코드 1을 반환합니다.

`test_abcd_pipeline.py`는 네트워크 연결을 차단한 상태에서 실행합니다. LLM 응답만
고정해 같은 순서로 조사하도록 하고, 로그 처리 함수나 조사 도구의 결과를 성공값으로
대체하지 않습니다. S3 테스트는 서비스 응답만 모사하고 객체 읽기 이후 처리는 그대로 실행합니다.

## 실제 LLM 평가와의 차이

오프라인 테스트 통과는 데이터 흐름과 코드 동작을 확인한 결과입니다. 실제 공격 탐지율,
오탐/미탐, 모델 응답 안정성을 측정한 결과는 아닙니다.

실제 모델을 사용하려면 `requirements.txt` 설치 및 `.env` 설정 후 `python main.py`를 실행합니다.
판정 일관성을 반복 측정하는 기존 수동 스크립트는 다음과 같습니다.

```bash
python -m tests.test_consistency --runs 8
```

이 명령은 실제 API 사용량이 발생합니다. 해당 스크립트의 seed와 로그 설정을 사용할
시나리오에 맞추세요. 이번 ABCD 오프라인 검증에서는 실행하지 않았습니다.

새 코드 테스트는 `test_`로 시작하는 함수로 작성해 `python -m pytest -q`에 포함시키세요.
API 호출이 필요한 수동 평가와 오프라인 회귀 테스트를 구분해 유지합니다.
