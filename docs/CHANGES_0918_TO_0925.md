# 0918 → 0925 변경 정리: 에이전트 도구 복구, C/D 통합, 공통 정규화 연동

작성: 2026-09-24 ~ 09-25 (B: 조사 에이전트/도구 담당)
기준 커밋: `b72c1e4` (0918, 재현성 검증을 마친 마지막 버전) → 이 문서와 함께 커밋되는 버전

## 1. 요약

- **무슨 일이 있었나**: 0923에 C/D(지윤) 브랜치와 머지하는 과정에서 `agent/tools/real/fetch_*_log.py`
  네 개가 한 줄짜리 위임 함수로 바뀌었다. 도구별 필터·요약·반환 형식이 공용 함수 하나로 합쳐졌고,
  에이전트 자체 파서(`agent/tools/parsers/`)도 삭제됐다. 여기에 로컬 host 검사, raw_ref 인용 검증 같은
  새 규칙이 함께 들어오면서 LLM 판정 재현성이 크게 떨어졌다.
- **이번에 한 일**:
  1. 에이전트 도구를 0918 구조(도구마다 필터·페이지네이션·summary를 직접 가짐)로 되살렸다.
  2. 파싱은 1차 탐지팀 공통 정규화(`primary_detection/normalizer`)를 호출하도록 유지했다.
  3. C/D의 사건 구간 조회(`fetch_event_logs`)와 raw_ref 추적 기능은 그대로 살렸다.
  4. 재현성을 무너뜨린 원인 7가지를 찾아 고쳤다.
- **검증**: 단위 테스트 97개 통과, 오프라인 ABCD 데모 통과, 실제 Gemini 재현성(데이터 유출 시나리오)
  3/3 THREAT_CONFIRMED, `main.py` 수집부터 보고서까지 전체 실행 성공.

## 2. 커밋 이력

| 커밋 | 작성 | 내용 |
|---|---|---|
| `b72c1e4` | 희진 (0918) | 재현성 검증을 마친 기준 버전. 에이전트 자체 파서 사용 |
| `cb5005d` | 희진 (0923) | 도구 파싱을 1차 탐지팀 공통 정규화로 교체, `agent/tools/parsers/` 삭제 |
| `8acaa75` | 지윤 (C/D) | 사건 구간 조회(`fetch_event_logs`), raw_ref 추적(`provenance.py`), `log_source.py` 추가. `fetch_*_log.py`를 한 줄 위임으로 변경 |
| `6f02eb6` | 머지 | 위 두 브랜치 머지. 이때 `fetch_*_log.py`는 C/D 쪽(한 줄 위임) 버전으로 정해짐 |
| `4358d10` | 지윤 (0923) | ABCD 통합 테스트·실행 안내(문서, 테스트, 스크립트만) |
| (이번 커밋) | 희진 (0924) | 이 문서의 내용 |

지윤님 커밋 `4358d10`의 파일(문서·테스트·스크립트·`.env.example`)은 이번 작업에서 거의 바꾸지 않았다.
바꾼 테스트 두 곳은 6장에 적었다.

## 3. 전체 실행 순서

코드 주석의 `[번호]`와 맞춰 적었다.

### 3.1 실제 운영: `python main.py`

```
[1]  main.py                               main()
[2]    agent/tools/registry.py               build_default_registry(exclude=["resolve_ip_geo"])
                                               agent/tools/real/<도구이름>.py 안의 같은 이름 함수를 자동 연결,
                                               없으면 mock_tools.py로 대체
[3]    main.py                               build_llm_client()  → agent/gemini_client.py GeminiClient
[4-5]  agent/pipeline.py                     run_investigation_pipeline()
[6-7]    agent/raw_log_ingestion.py            fetch_recent_raw_logs()        계층별 최근 로그 수집
[8]        agent/tools/log_source.py             read_documents()              로컬 파일 또는 S3 원본 읽기
[9]        agent/tools/log_source.py             normalize_documents()
             agent/tools/normalizer_adapter.py     normalize_log_documents()
               primary_detection/normalizer/tools/fetch_{apache,auth,audit,network}_log()
                                                   1차 탐지팀 공통 정규화 (코드 수정 없이 그대로 호출)
[10-14]  agent/seed_generation.py              SeedGenerator.generate()       LLM이 조사 후보(seed) 선정
           agent/seed_prompts.py                 build_seed_user_prompt()      (추적용 필드는 뺀 사본을 보냄)
           agent/gemini_client.py                complete_json()               (503/429 재시도)
           agent/provenance.py                   references()                  seed가 인용한 raw_ref가 입력에 있는지 검증
[16-17]  agent/loop.py                         InvestigationAgent.run()       seed마다 반복
[18]       agent/models.py                       AgentState
[20-23]    agent/gemini_client.py                reason()
             agent/prompts/__init__.py             build_system_prompt() + investigation.yaml
                                                   build_user_prompt()
[24]       agent/loop.py                         _apply_decision()             증거·가설 기록
             agent/provenance.py                   validate_citations()         raw_ref 인용 검증
[25-26]    agent/loop.py                         종료 판단 (confidence 관문 / 호출 상한 8회)
[27-30]    agent/loop.py                         _execute_tool_call() → registry.call()
             agent/tools/real/<도구>.py            4장 참고
               agent/tools/log_source.py           load_window_events()         [8]~[9]와 같은 경로
[41]       agent/report.py                       build_investigation_result()
[43]   agent/pipeline.py                     결과 리스트 반환
[45]   main.py                               format_text_report(), save_investigation_result() → results/*.json
```

### 3.2 재현성 테스트: `python -m tests.test_consistency --runs 8`

수집과 seed 생성([6]~[14])을 건너뛴다. 파일 안에 적어 둔 `SEED`로 `InvestigationAgent.run()`([17])부터
시작한다. 시나리오 로그는 `scenarios/generate_*.py`가 `.env`의 `*_LOG_LOCAL_PATH` 파일에 덧붙인다(9장).

### 3.3 도구 한 번 호출할 때의 경로

```
loop._execute_tool_call()
 → registry.call(name, args)             인자 검사(validate_args) 후 handler 실행
   → agent/tools/real/fetch_auth_log.py  fetch_auth_log(args)
       pagination(args)                   limit/offset 검사
       load_window_events("auth", host, start_time, end_time)   ← agent/tools/log_source.py
         query_window()                   시간 구간 검사
         read_documents()                 원본 읽기 (파일 없음/권한 없음은 error로 표시)
         normalize_documents()            공통 정규화 + layer_data를 top-level로 펼침
         구간 밖·시각 불명 이벤트 제외, (시각, raw_ref) 순 정렬
       _matches(record, args)             이 도구 고유의 필터
       page 자르기, summary 작성, 반환
 ← loop: 결과의 raw_ref/raw_refs/raw_ref_locations를 state에 누적(provenance), pending_observations에 저장
```

## 4. 에이전트 도구 (`agent/tools/real/`) 상세

### 4.1 구조 원칙

- **도구 파일(`agent/tools/real/*.py`)의 역할**: 인자 해석, 도구별 필터, limit/offset 페이지네이션,
  LLM에게 줄 summary와 반환 형식. 0918과 같은 구조로, 각 도구가 자기 로직을 직접 가진다.
- **`agent/tools/log_source.py`의 역할**: 원본 읽기, 공통 정규화 호출, 시간 구간 자르기만 한다.
  0923 머지본에 있던 "모든 계층 필터를 한 함수에서 처리하던 `matches()`와 `fetch_layer_logs()`"는
  삭제하고, 그 필터 로직을 각 도구 파일의 `_matches()`로 되돌렸다.
- **파싱**: 에이전트 자체 파서를 쓰지 않는다. 1차 탐지와 에이전트 도구가 같은 원본에 대해 같은 정규화
  결과를 내야 한다는 완료 기준 때문이다.

### 4.2 공통 반환 형식

```
{count, summary, records, total_matched, has_more, next_offset,
 scanned_objects, invalid_timestamps, error(있을 때만)}
```
records의 각 이벤트에는 `raw_ref`, `raw_refs`, `raw_ref_locations`(원본 파일/S3 객체의 실제 줄 위치)가 붙는다.
`error`는 `not_found` 또는 `permission_denied`이며, 로그를 못 읽은 경우를 "0건 조회"와 구분하려고 둔다.

### 4.3 도구별 비교 (0918 → 현재)

| 도구 | 0918 (`b72c1e4`) | 현재 | 필터 의미 (현재) |
|---|---|---|---|
| `fetch_web_log` | `parsers/nginx_json_parser.py` (nginx JSON) | 공통 정규화 `fetch_apache_log` (apache access) | `src_ip` 일치, `method` 대소문자 무시, `path` 부분 일치(쿼리 포함), `status_code` 정수 일치, `exclude_self`는 서버 자기 IP 제외 |
| `fetch_auth_log` | `parsers/auth_parser.py` | 공통 정규화 `fetch_auth_log` | `user`/`src_ip`/`result` 일치, `event_type`은 결과의 `event` 값과 비교 |
| `fetch_audit_log` | `parsers/audit_parser.py` | 공통 정규화 `fetch_audit_log` | `pid`/`ppid`/`user`/`serial` 일치, `event_type`은 auditd 룰 `key`와 비교, `exclude_interactive`는 `session_type == non_interactive`만 남김, `include_user_cmd=False`는 USER_CMD 포함 이벤트 제외 |
| `fetch_network_log` | `parsers/network_parser.py` (flow 포함) | 공통 정규화 `fetch_network_log` (http/alert만) | `src_ip`는 `src_ip` 또는 `transport_src_ip` 중 하나와 일치(5장 7번), `dst_ip`→`dest_ip`, `src_port`/`dst_port`→`transport_*_port`, `protocol` 대소문자 무시, `alert_only`는 alert만 |
| `get_process_tree` | 자체 파서 + `parsers/process_tree.py` | 공통 정규화 + `build_ancestry_chain()`을 이 파일로 이동 | 조상 추적 로직은 0918과 같음. 파일 없음/권한 없음을 예외 대신 summary·error로 반환하도록 수정 |
| `fetch_event_logs` | 없음 | C/D에서 추가 | 사건 window 또는 timestamp±초로 여러 계층을 한 번에 조회. 내부에서 위 4개 도구를 호출하고, 계층별 `filters`는 그 도구가 받는 인자만 허용 |
| `resolve_ip_geo` | 목업 | 목업(변경 없음) | `main.py`와 `test_consistency.py` 모두 제외 |

0918 대비 기능 차이:
- `include_user_cmd` 기본값 True(sudo 기록 누락 방지)는 결과가 같다. 공통 정규화가 USER_CMD만 있는 이벤트도 원래 포함한다.
- 권한 에러 처리와 limit/offset 페이지네이션은 그대로 있다.
- 없어진 정보는 network flow 이벤트(`bytes_toserver` 등)뿐이다. 공통 정규화가 flow 이벤트를 버리기 때문이며, 프롬프트를 이에 맞췄다(8장).

### 4.4 필드 이름 변경 (자체 파서 → 공통 정규화)

| 계층 | 0918 필드 | 현재 필드 |
|---|---|---|
| auth | `event_type` (ssh_login/sudo/pam) | `event` (ssh_accepted/ssh_failed/ssh_invalid_user/pam_session_opened/sudo_command 등) |
| auth | `auth_method` | `method` (password/publickey) |
| audit | `target_file` | `path`(대표 경로), `paths`(전체) |
| audit | — | `exe`, `comm`, `argv`, `proctitle`, `cwd`, `record_types` 추가 |
| network | `alert_signature` | `signature` (+ `category`, `severity`, `signature_id`) |
| network | `src_ip` = 패킷 출발지 | `src_ip` = XFF로 복원한 실제 클라이언트(없으면 None), 패킷 출발지는 `transport_src_ip` |
| network | flow 이벤트, `bytes_toserver` | 없음 (http/alert만) |
| web | `uri`, `xff` (nginx JSON) | `path`(쿼리 포함), `status`, `method`, `user_agent`, `request_id`, `duration_us` (apache) |
| 공통 | `raw_log_ref` | `raw_ref`, `raw_refs`, `raw_ref_locations` |

## 5. 재현성이 무너진 원인과 수정

0923 상태에서 시나리오 로그를 9/18 도구와 현재 도구에 똑같이 넣어 비교해서 찾았다.

| # | 원인 | 영향 | 수정 |
|---|---|---|---|
| 1 | `log_source.read_documents()`가 로컬 파일을 읽을 때 host를 `LOG_LOCAL_HOST` 또는 `HOST`와 비교. `.env`의 `HOST=ip-10-0-7-236`과 시나리오 seed의 `web-01`이 달라 거부 | **모든 도구 호출이 `local host mismatch` 에러** | `LOG_LOCAL_HOST`만 검사. `HOST`는 `main.py`의 수집 대상(S3 파티션 이름)으로만 쓴다 |
| 2 | `loop.py`가 raw_ref를 빠뜨리거나 형식이 틀린 증거의 신뢰도 기여를 0으로 만듦 | LLM이 raw_ref를 정확히 복사했는지에 따라 confidence가 실행마다 달라짐 | 빠뜨림/형식 오류는 기여를 반영하고 provenance에만 기록. 없는 참조를 지어낸 경우와 위치가 모호한 경우만 0 유지 |
| 3 | 웹셸 시나리오가 nginx JSON을 생성, 공통 정규화는 apache만 읽음 | web 계층 0건 | 시나리오를 apache 형식으로 변경 |
| 4 | 시나리오 생성기가 `sample_web.log`/`sample_network.log`에 쓰는데 `.env`는 다른 파일을 가리킴 | 도구가 시나리오 로그를 전혀 못 봄 | `scenarios/_log_paths.py` 추가. 생성기 5개가 `.env`의 `*_LOG_LOCAL_PATH`에 씀 |
| 5 | 공통 정규화가 flow 이벤트를 버리고 `alert_signature` 이름이 바뀜. 프롬프트는 옛 필드를 확인하라고 지시 | 유출 판단 근거를 못 찾음 | 프롬프트 원칙 8로 `signature` + audit 전송 명령 + `dest_ip` 기준 판단 (8장) |
| 6 | 도구 설명이 옛 필드(`target_file`, `ssh_login` 등)를 안내 | LLM이 없는 필드를 찾음 | `registry.py` 도구 설명을 실제 반환 필드에 맞춤 |
| 7 | 공통 정규화는 XFF가 없는 alert의 `src_ip`를 비움 | 공격자 IP로 거른 inbound alert가 0건 (0918에서는 잡힘) | `fetch_network_log`의 `src_ip` 필터를 `transport_src_ip`까지 비교 |

조사 경로 보완도 함께 했다. 테스트 중 LLM이 로그인 세션 pid로 audit을 조회해 0건이 나오는 경우가 있었다.
그래서 도구 설명과 원칙 5에 "세션에서 실행된 명령은 `ppid=<세션 pid>`, 외부로 나간 통신은 `dst_ip`로
조회"하라는 안내를 넣었다.

## 6. 지윤(C/D) 코드와 합친 내용

**그대로 유지한 것**
- `fetch_event_logs`: 사건 구간 여러 계층 조회. 계층별 조회는 이제 에이전트 도구를 직접 호출한다.
- `agent/provenance.py`와 `loop.py`의 raw_ref 누적·인용 검증, 보고서의 `provenance` 섹션,
  `raw_ref_locations`(S3 객체별 실제 줄 위치).
- `log_source.read_documents()`의 S3 UTC 날짜 파티션 처리, gzip 처리, 객체 정렬.
- seed 생성 시 `evidence_refs` 검증, `window` 필드.
- 지윤님 테스트 전체(`test_abcd_pipeline`, `test_cd_normalizer_integration`, `test_event_window`,
  `test_provenance`)와 `scripts/demo_abcd.py`.

**조정한 것** (지윤님 확인 필요)
- `log_source.py`: `fetch_layer_logs()`/`matches()` 삭제, `load_window_events()` 추가 (4.1).
  host 검사에서 `HOST` 제외 (5장 1번). `docs/C_D_IMPLEMENTATION.md`의 해당 문단도 수정.
- `loop.py`: raw_ref 누락 시 신뢰도 기여 처리 변경 (5장 2번).
  - `tests/test_provenance.py`: "누락/형식 오류도 confidence 증가 0"을 검사하던 테스트를 둘로 나눴다.
    "지어낸 참조는 0"과 "누락/형식 오류는 반영하되 provenance incomplete"를 각각 검사한다.
- `tests/test_abcd_pipeline.py`: seed 프롬프트에서 추적용 필드를 빼게 되어(8장), "seed 입력과 도구 결과가
  같은가" 비교 전에 도구 결과에도 같은 필드를 빼도록 한 줄 수정. 두 경로의 정규화 결과가 같은지 확인한다는
  테스트 의도는 그대로다.
- `fetch_event_logs`의 `filters`: 예전에는 모든 계층 필터 키를 아무 계층에나 허용했다. 이제는 계층별로
  그 도구가 받는 인자만 허용하고, 다른 키가 오면 `ValueError`를 낸다.

## 7. 1차 탐지팀 공통 정규화(`primary_detection/normalizer`) 연동

- **위치**: `primary_detection/normalizer/{common,tools}/`. 1차 탐지팀 저장소 코드를 바이트 단위로 그대로
  가져왔고, `primary_detection/normalizer/vendor_sync_check.py`로 원본과 같은지 검사한다.
  **이 폴더는 수정하지 않는다.** 현재 기준은 1차 탐지팀 `feature/primary-detection`의 `b300d41`(09-23)이다(15장).
- **호출 경로**: `agent/tools/log_source.normalize_documents()` → `agent/tools/normalizer_adapter.normalize_log_documents()`
  → `fetch_apache_log` / `fetch_auth_log` / `fetch_audit_log` / `fetch_network_log`.
  어댑터가 원본 텍스트(여러 S3 객체 포함)를 임시 파일로 합쳐 넘기고, 돌아온 raw_ref를 실제 객체·줄 위치로
  되돌려 `raw_refs`, `raw_ref_locations`를 붙인다.
- **정규화가 제공하지 않는 필터**(`user`, `serial`, `dst_ip`, 포트 등)는 에이전트 도구의 `_matches()`가 처리한다.
- `normalizer_adapter.py`의 `normalize_auth()`/`normalize_audit()`/`normalize_web()`/`normalize_network()`는
  도구에서 더 이상 쓰지 않는다. `tests/test_normalizer_parity.py`와 `scripts/verify_all_tools.py`만 쓴다.

## 8. 프롬프트 변경

### 8.1 조사 프롬프트 (`agent/prompts/investigation.yaml`)

날짜별로 덧붙였던 `[2026-09-1x 추가]` 주석을 없애고, 같은 내용을 제자리에 합쳐 다시 썼다.
**판단 기준과 수치(confidence 구간 ±0.20~0.30 / ±0.10~0.15 / ±0.05, INCONCLUSIVE 0.45~0.60,
Q1~Q3 판정 조합)는 바꾸지 않았다.**

| 원칙 | 변경 |
|---|---|
| 1 증거 기반 조사 | severity_hint/confidence_initial은 힌트일 뿐이라는 규칙을 본문에 합침 |
| 2 동적 도구 선택 | 원칙 5에 붙어 있던 "trigger_description 단서로 첫 도구 고르기"를 이리로 옮김 |
| 4 종료 판단 | "도구 2종류" → "계층(도구) 2종류", "fetch_network_log 1회" → "network 계층 1회" (`fetch_event_logs`로 network를 본 경우도 인정하는 loop 동작과 맞춤) |
| 5 계층 간 연결 | auth→audit은 `ppid`, 아웃바운드는 `dst_ip`로 조회하라는 안내 추가 |
| 6 권한 사용(sudo) | 제목 명확화. 유출/network 문단은 원칙 8로 분리. INCONCLUSIVE confidence 범위는 rules로 이동 |
| 7 계정/인증 | 공통 정규화 필드(`event`, `method`) 읽는 법, `pam_session_opened`를 로그인 시도로 세지 말 것 |
| **8 데이터 유출·외부 통신 (신규)** | 원칙 6에 덧붙어 있던 백업 위장·Suricata alert 판단을 독립. flow/`bytes_toserver`가 없으므로 `signature` + audit 전송 명령 + `dest_ip` 일치로 판단 |
| rules | [응답 형식]/[도구 사용]/[증거 기록]/[confidence 산정]/[판정과 confidence의 일관성]으로 묶음. INCONCLUSIVE 범위 규칙이 두 곳에 있던 것을 하나로 합침 |

`output_schema`의 reasoning 설명은 "원칙 6~8번"을 가리키도록 바꿨다.

### 8.2 LLM 입력 크기 줄이기

- `agent/provenance.py`에 `strip_trace_fields()`를 추가했다. LLM에게 보여주는 사본에서만 `raw_ref_locations`,
  `raw_lines`를 뺀다. 코드(loop/report/검증)는 도구 결과 원본을 쓰므로 추적 기능에는 영향이 없다.
- seed 생성 프롬프트: 약 12만 7천 자 → 약 7만 4천 자. 0918은 약 1만 7천 자였다. 수집 건수가
  37 → 98건으로 늘어난 영향이 크다.
- 조사 프롬프트의 `raw_observations_since_last_turn`에도 같은 처리를 적용했다.

### 8.3 Gemini 호출 재시도 (`agent/gemini_client.py`)

503(서버 과부하)과 429(요청 한도)만 최대 3번 다시 시도한다. 429는 서버가 알려준 retryDelay를 따르고,
그 외에는 15초 → 30초 → 60초 간격으로 기다린다. 전에는 503 한 번에 `main.py` 전체가 종료됐다.

## 9. 시나리오 (`scenarios/`)

- `_log_paths.py` (신규): `.env`의 `*_LOG_LOCAL_PATH`를 우선 쓰고, 없으면 `sample_logs/` 기본 경로를 쓴다.
- `generate_webshell_scenario.py`: web 로그를 apache access 형식으로 생성.
- 나머지 4개 생성기: 쓰는 파일 경로만 `_log_paths.log_path()`로 변경.
- `scenarios/README.md`: 위 내용과 형식 규칙 반영.

## 10. 설정 (`.env`)

| 변수 | 의미 | 권장 |
|---|---|---|
| `HOST` | `main.py`의 수집 대상 = S3 파티션 `host=` 값 | 실제 EC2 hostname (`ip-10-0-7-236`) |
| `LOG_LOCAL_HOST` | 로컬 파일이 속한 서버. 채우면 다른 host의 로컬 조회를 막음 | 로컬 파일로 테스트할 때는 **비워 둠** |
| `*_LOG_LOCAL_PATH` | 계층별 로컬 로그 파일. 있으면 S3 대신 사용 | web은 apache access.log를 가리켜야 함 |

## 11. 검증 결과 (2026-09-24)

| 항목 | 결과 |
|---|---|
| `python -m pytest` | 97개 통과 |
| `python -m scripts.demo_abcd` (오프라인 ABCD) | 수집 → seed → 조사 도구 → 구간 조회 → provenance passed |
| 시나리오 5종 도구 직접 호출 | web 2건, auth 12건, audit 18건, network alert 3건 (수정 전 web 0건, 모든 호출 host 에러) |
| `test_consistency` 데이터 유출 시나리오 (Gemini) | 수정 전 1회 INCONCLUSIVE → 수정 후 **3/3 THREAT_CONFIRMED**, confidence 0.95~1.00 |
| `python main.py` (Gemini, 로컬 sample_logs) | 수집 98건 → seed 1건(SSH 브루트포스) → 조사 → 보고서 저장까지 완료. 503을 재시도로 넘김 |

## 12. 남은 과제

1. **재현성 본검증**: 시나리오 5종 + 수동 seed 2종을 각각 `--runs 8`로 다시 측정해야 0918 표와 비교할 수
   있다. 지금은 유출 시나리오 3회만 확인했다.
2. ~~중복 증거로 confidence 부풀리기~~, ~~로그인 성공 없는 브루트포스 판정 흔들림~~ → 14장에서 해결.
3. **seed 생성 실패**: LLM이 입력에 없는 raw_ref를 인용하면 `seed_generation.py`가 `ValueError`를 내서
   seed 생성 전체가 실패한다. 해당 후보만 버리는 방식을 검토한다.
4. **옛 구조를 설명하는 README**: `README.md`, `agent/README.md`, `agent/tools/README.md`,
   `agent/tools/real/README.md`에 삭제된 `parsers/` 설명이 남아 있다.
5. 14장 수정 이후 다른 시나리오(유출·웹셸 등)는 아직 다시 검증하지 않았다.

## 13. 변경 파일 목록 (이번 커밋, `4358d10` 대비)

| 파일 | 변경 |
|---|---|
| `agent/tools/real/fetch_{web,auth,audit,network}_log.py` | 에이전트 도구 복구 (4장) |
| `agent/tools/real/get_process_tree.py` | `load_window_events()` 사용, 에러 처리, 쓰지 않던 함수 삭제 |
| `agent/tools/real/fetch_event_logs.py` | 계층별 에이전트 도구 호출, 계층별 필터 검사 |
| `agent/tools/log_source.py` | `load_window_events()` 추가, 필터 함수 삭제, host 검사 수정 |
| `agent/tools/registry.py` | 도구 설명을 실제 필드에 맞춤 |
| `agent/loop.py` | raw_ref 누락 시 기여 처리 |
| `agent/provenance.py` | `strip_trace_fields()` 추가 |
| `agent/prompts/investigation.yaml` | 프롬프트 재구성, 원칙 8 추가 |
| `agent/prompts/__init__.py`, `agent/seed_prompts.py` | LLM 입력에서 추적용 필드 제외 |
| `agent/gemini_client.py` | 503/429 재시도 |
| `agent/raw_log_ingestion.py`, `agent/seed_generation.py` | 실행 순서 설명 주석 |
| `scenarios/*` | 로그 경로·web 형식 (9장) |
| `tests/test_provenance.py`, `tests/test_abcd_pipeline.py` | 6장 참고 |
| `docs/C_D_IMPLEMENTATION.md` | host 검사 문단 |
| `docs/CHANGES_0918_TO_0925.md` | 이 문서 |

## 14. 추가 수정: SSH 실패 전용 사건의 판정 흔들림 (0924 오후)

### 증상
같은 seed(`INC-SSH-BRUTE`: 171.235.42.109 → root SSH 로그인 실패, 성공 없음)로 조사를 반복하면
판정이 INCONCLUSIVE / FALSE_POSITIVE / THREAT_CONFIRMED로 갈렸다. C/D 병합 전(0918 코드)에도 같은
흔들림이 있었으므로 병합과 무관하게 원래 있던 문제다. 병합 직후에 THREAT_CONFIRMED가 나온 것은
host 검사 에러로 도구 호출이 낭비되고 종료가 거부된 뒤 LLM이 confidence를 부풀린 영향이었다(5장 1번).

### 원인
1. 원칙 7이 "실패와 성공이 섞인" 경우만 다뤄, 실패만 있는 경우의 판정 기준이 없었다.
2. 이 IP는 9시간 동안 10회 실패했지만 seed는 마지막 1회만 가리킨다. LLM이 1~2시간만 조회해 매번
   "1회 실패"로 봤다. 24시간 조회하라고 지시해도 시각 계산을 하지 않았다.
3. 실패 1회가 로그 3줄(PAM 인증 실패, Failed password, 연결 종료)로 남아 LLM이 1회/3회로 제각각 셌다.
4. 종료가 거부되면 "confidence를 재평가하라"는 안내에 따라 같은 사실을 다시 evidence로 만들어 임계값을 채웠다.
5. `test_consistency.py`만 `resolve_ip_geo` 목업을 LLM에게 노출했다.

### 수정
| 파일 | 내용 |
|---|---|
| `agent/prompts/investigation.yaml` 원칙 7 | 실패만 있고 성공이 없는 경우: 같은 src_ip 실패 5회 이상 또는 계정 2개 이상 → THREAT_CONFIRMED("SSH 무차별 대입 시도", severity LOW~MEDIUM, confidence 0.75~0.85, "침해 없음" 명시). 1~4회·단일 계정 → FALSE_POSITIVE. 이 경우 INCONCLUSIVE 금지 (팀 판정 정책) |
| `agent/prompts/__init__.py` | seed에 src_ip가 있으면 `auth_lookback_window`([기준 시각-24h, +1h])를 코드가 계산해 user prompt에 넣음. 원칙 7 Q1은 이 값을 그대로 쓰도록 지시 |
| `agent/tools/real/fetch_auth_log.py` | summary 끝에 `[조회 구간 전체 집계] 로그인 실패 N회(ssh_failed+ssh_invalid_user 기준), 실패 대상 계정 M개, 로그인 성공 K회` 추가. 원칙 7은 이 숫자를 그대로 쓰도록 지시 |
| `agent/loop.py` | 이미 인용된 raw_ref만 다시 인용한 evidence는 신뢰도 기여 0 |
| 종료 거부 안내 (`prompts/__init__.py`, 원칙 4) | "재평가해 제출" → "더 볼 계층이 없으면 no_more_evidence로 종료, 부풀리기 금지" |
| `tests/test_consistency.py` | `resolve_ip_geo` 제외 (`main.py`와 동일 조건) |
| 테스트 | `tests/test_auth_q1_inputs.py`(조회 구간, 실패 횟수 집계), `test_provenance.py`(중복 인용) 추가. 총 100개 통과 |

### 결과 (같은 seed, Gemini 5회씩)
| 단계 | 판정 분포 | confidence |
|---|---|---|
| 수정 전 | INCONCLUSIVE 3, FALSE_POSITIVE 2 (60%) | 0.50~0.90 (표준편차 0.169) |
| 원칙 7 규칙만 추가 | THREAT_CONFIRMED 3, FALSE_POSITIVE 2 (60%) | 0.75~0.85 (0.040) |
| 조회 구간·집계를 코드가 제공 | **THREAT_CONFIRMED 5 (100%)** | 0.80~0.85 (0.024) |

교훈: 날짜 계산이나 로그 줄 세기처럼 **정답이 정해진 계산은 LLM에게 맡기지 말고 코드가 해서 숫자로 건넨다.**
LLM에게는 그 숫자를 판정 규칙에 대입하는 일만 남긴다.

## 15. 1차 탐지팀 공통 정규화 사본 갱신 (0924, 1차 탐지팀 동의)

### 증상
EC2에서 `fetch_network_log`가 항상 0건을 반환했다(에러·시각 불명 표시 없음). web/auth/audit은 정상.

### 원인
- 우리 사본은 1차 탐지팀의 09-23 수정 이전 버전이었다. 옛 코드는 시각을 `value.replace("Z", "+00:00")` 후
  `datetime.fromisoformat()`으로 읽는다.
- Suricata는 시각을 `2026-09-22T13:35:35.722646+0000`처럼 콜론 없는 오프셋으로 쓴다.
  `fromisoformat()`은 Python 3.11부터 이 형식을 읽지만 **EC2의 Python 3.10은 못 읽는다.**
- 시각 파싱에 실패한 이벤트는 정규화 단계(`fetch_network_log.py`의 `if ts is None: return None`)에서 버려져,
  에이전트 도구까지 오지 못했다. 로컬(Python 3.13)에서는 문제가 드러나지 않았다.
- web(`...Z`), auth(syslog), audit(epoch)은 형식이 달라 영향이 없었다.
- 1차 탐지팀은 09-23에 `common/timeparse.py`의 `normalize_iso()`로 이미 고쳤다(로컬 3.14, EC2 3.10 차이를 발견).
  즉 EC2에서 1차 탐지는 network를 읽고 에이전트는 0건을 받아 **완료 기준이 깨진 상태**였다.

### 수정
- 1차 탐지팀 `feature/primary-detection` `b300d41`(09-23)에서 10개 파일을 **내용 수정 없이** 복사:
  `common/schema.py`, `common/timeparse.py`(신규), `common/network.py`(신규), `tools/base.py`, `tools/registry.py`,
  `tools/normalize.py`, `tools/fetch_{apache,auth,audit,network}_log.py`. git blob 해시로 원본과 동일함을 확인.
- 1차 탐지팀 쪽 변경 내용은 리팩터링(시각 파싱을 `normalize_iso()`로, IP/경로 처리를 `common/network.py`로 이동)이며,
  실제 동작 차이는 콜론 없는 오프셋 처리뿐이다.
- `vendor_sync_check.py`: 새 파일 2개를 비교 목록에 추가, 줄바꿈(CRLF/LF)만 다른 경우는 같은 파일로 판정
  (Windows 체크아웃 때 전부 "내용 다름"으로 나와 실제 갱신 여부를 알 수 없었음).

### 확인
| 항목 | 결과 |
|---|---|
| `vendor_sync_check.py` | 10개 파일 모두 원본과 동일 |
| Suricata 로그 정규화 (http 8건 포함) | Python 3.10: 0건 → **8건**, Python 3.13: 8건 |
| 완료 기준: 같은 원본을 1차 탐지 함수 / 에이전트 도구에 넣은 결과 | web 500, auth 500, audit 105, network 8건 모두 동일 |
| `pytest` | 100개 통과 |

EC2에서는 `git pull` 후 `fetch_network_log` 건수가 0이 아닌지 확인한다.

**EC2 확인 (0924)**: Python 3.10.12에서 `test_normalizer_parity` OK(network 3건),
`verify_all_tools`에서 `fetch_network_log` 391건. 수정 전에는 0건이었다.

## 16. 조기 종료와 웹 판정 보강 (0924 저녁)

### 증상
EC2 `main.py`(seed `INC-xmlrpc-flood`: 129.222.213.124 → `/xmlrpc.php` POST 31회, 전부 503)에서 LLM이
`fetch_web_log` **1회만** 호출하고 `no_more_evidence`로 끝냈다. 판정은 FALSE_POSITIVE였다.
- network·auth·audit을 한 번도 보지 않았다. src_ip seed의 network 확인 규칙은 `confidence_sufficient`
  종료에만 적용돼서, 결과에 "network 확인 없이 종료" 경고만 남았다.
- 근거는 "User-Agent가 Jetpack/WordPress.com이다", "503으로 차단됐다"였다. User-Agent는 요청자가 마음대로
  적는 값이고, 503은 차단이 아니라 서버가 처리하지 못했다는 뜻이다.
- 리포트의 `Investigation Confidence 0.75`는 LLM이 적은 판정 확신도였다. 실제 증거 누적 신뢰도는 0.45였다.

network 도구 자체는 정상이었다(`verify_all_tools` 391건). 문제는 LLM이 도구를 고르지 않은 것이었다.

재실행에서도 같은 양상이었다. `INC-SSH-PROBE`(44.220.185.209, invalid user 1회)는 `fetch_auth_log` 1회 후
`no_more_evidence`로 끝났다. 프롬프트로 "도구 하나로 끝내지 말라"고 해도, `no_more_evidence`에는 코드
관문이 없어서 막을 수 없었다. 같은 실행에서 auth 집계가 "실패 1회, 실패 대상 계정 0개"로 나왔다. 빈 계정명
(`Invalid user  from ...`)은 공통 정규화가 `user` 필드를 빼기 때문이다. 텍스트 리포트는 증거마다 원본 줄
번호 수십 개를 바로 아래 찍어 읽기 어려웠다.

### 수정
| 파일 | 내용 |
|---|---|
| `agent/loop.py` | `network_precheck=True`면 seed에 src_ip가 있을 때 첫 LLM 턴 **전에** 코드가 `fetch_network_log(src_ip, seed 구간 ±30분)`를 실행하고, 결과를 첫 턴 관측으로 넣는다(`network_precheck_args()`). LLM 호출 수는 그대로이고, 도구 호출 1회로 센다. 종료 관문 (c)는 "network 조회를 **시도**했는가"로 완화했다. 데이터 소스 장애로 실패해도 종료할 수 있게 하기 위해서다 |
| `agent/loop.py` (종료 관문) | 관문 조건을 `_termination_rejections()`로 정리. `strict_termination=True`면 **`no_more_evidence`에도 관문 적용**: 도구를 1종류만 시도했는데 등록된 로그 도구 중 안 본 것이 남아 있으면 거부한다(연속 2회 거부 시 기존처럼 강제 종료 턴). 등록된 도구를 다 써봤으면 승인한다. 로그인 성공 후 audit 확인 조건은 아래 비교 절 참고 |
| `main.py`, `agent/pipeline.py` | `main.py`가 `network_precheck=True`, `strict_termination=True`로 실행한다. `pipeline`/`InvestigationAgent` 기본값은 False로 두어, 도구 1회 후 `no_more_evidence`로 끝나도록 짠 기존 단위 테스트와 C/D 데모(`demo_abcd`, `test_abcd_pipeline`)의 각본을 유지 |
| `agent/tools/real/fetch_web_log.py` | summary 끝에 `[조회 구간 전체 집계]` 추가: 요청 수, 실제 기록 시각, 출발지 IP 수, 메서드별, 상태코드 계열(2xx/4xx/5xx)별, 서로 다른 경로 수, 상위 경로 5개, User-Agent 상위 5개(80자까지). auth와 같이 세는 기준을 코드로 고정 |
| `agent/tools/real/fetch_auth_log.py` | 실패 대상 계정 이름은 20개까지만 나열(개수는 전체 기준). EC2 24시간 조회에서 325개가 전부 들어가 프롬프트가 커졌다. 계정명 없는 실패는 `(빈 계정명)` 계정 1개로 센다 |
| `agent/prompts/investigation.yaml` | **원칙 9 신설 (웹 요청 반복·스캔)**. User-Agent는 정상 근거가 아니다. 5xx는 차단이 아니다. 인증·XML-RPC 엔드포인트에 같은 src_ip의 POST가 10회 이상이면 THREAT_CONFIRMED("웹 인증 무차별 대입/XML-RPC 남용 시도", LOW~MEDIUM, 0.75~0.85). 서로 다른 경로 20개 이상이고 4xx가 과반이면 "웹 경로·취약점 스캔". 그 미만이면 FALSE_POSITIVE. 성공 정황(관리자 경로 2xx, 업로드 후 실행, 웹 프로세스의 셸 실행)이 있으면 HIGH 이상으로 올리고 audit/auth를 확인한다. 원칙 4에는 사전 조회 결과를 반영하라는 지시와, 도구 1개로 no_more_evidence를 내기 전 원칙 6~9의 확인 항목을 점검하라는 지시를 추가 |
| `agent/report.py` | 텍스트 리포트에 판정(verdict·severity·attack_type) 줄 추가. `Verdict Confidence`(LLM 판정 확신도)와 `Investigation Confidence`(`statistics.investigation_confidence`, 증거 누적 신뢰도)를 나눠 표시. Findings에는 `[원본 N줄]`만 적고, 원본 위치는 맨 아래 `Raw References`에 모은다. 10개 이하는 원문 그대로 적고, 그보다 많으면 `access.log:343-345, 348-359`처럼 범위로 묶는다(`compact_refs()`). 전체 목록은 JSON에 그대로 있다 |
| `tests/test_consistency.py`, `scripts/local_e2e_test.py` | main.py와 같은 조건(`local_e2e_test`는 자체 로컬 도구에 `ip` 인자가 없어 사전 조회 제외) |
| 테스트 | `tests/test_network_precheck.py` 8개 추가(사전 조회 구간, 첫 턴 전 실행, 기본값 꺼짐·src_ip 없으면 생략, 실패한 network 조회도 관문 통과, 도구 1종류 no_more_evidence 거부, 도구가 1개뿐이면 승인, 원본 참조 압축, web 집계). `test_auth_q1_inputs.py`에 빈 계정명 테스트 추가. `test_loop.py` 리포트 문구 갱신. 이후 비교 실행 중 추가한 관문 테스트(사전 조회는 도구 수에서 제외, 로그인 성공 후 audit 요구) 포함 총 113개 통과 |

### 0918 시나리오 비교 (로컬, Gemini, 각 3회)
"0918에는 도구를 4개씩 썼다"는 차이를 확인하려고 0918 합성 시나리오를 지금 코드로 다시 돌렸다.
`--legacy`는 0918과 같은 조건(사전 조회·강화된 종료 관문 없음)이다. 조사 루프와 종료 관문은 0918과 거의
같았고, 도구 수 차이의 주원인은 사건의 성격이었다. 0918 시나리오는 로그인 성공 → 명령 실행 → 외부 통신으로
이어지는 다단계 공격이었고, EC2의 xmlrpc 요청 폭주·invalid user 1회는 다음 계층으로 이어질 단서가 없다.

비교 중 사전 조회를 처음 구현한 방식의 문제 3가지를 발견해 고쳤다.

| 발견 | 원인 | 수정 |
|---|---|---|
| 03(브루트포스 → 역방향 셸)에서 Metasploit alert 누락 | 사전 조회가 `src_ip=공격자`로만 거름. 역방향 셸은 서버 → 공격자 방향이라 0건이었고, LLM은 network를 "이미 봤다"고 여겨 다시 조회하지 않음 | `fetch_network_log`에 방향 무관 `ip` 필터 추가, 사전 조회에 사용. 원칙 4에 "새 외부 IP가 나오면 network 재조회" 추가 |
| 03에서 audit(로그인 후 명령) 없이 종료 | network alert + auth로 신뢰도가 먼저 참 | 종료 관문 (e): seed src_ip의 로그인 성공(`ssh_accepted`)이 보이면 audit을 시도하기 전까지 종료 거부. 거부 사유에 `ppid=<세션 sshd pid>`를 적어줌. audit의 `user`는 실행 계정(sudo 뒤 root)이라 `user=ubuntu`로는 0건이 나오던 문제 대응. 도구 설명에도 명시 |
| 04(웹셸)에서 audit 없이 2개로 종료 | 사전 조회가 "도구 2종류"에 포함돼 LLM은 web 1개만 고르고도 관문 통과 | "도구 2종류"는 LLM이 직접 고른 호출만 센다(`state.system_call_sequences`). network 확인 조건 (c)는 사전 조회도 인정 |

최종 결과 (수정 후 strict = `main.py` 조건):

| 시나리오 | strict 판정 | strict 도구 흐름 (3회 모두 동일) | legacy(0918 조건) |
|---|---|---|---|
| 03 브루트포스 → 역방향 셸 | THREAT_CONFIRMED 3/3, conf 1.00 | network(alert 1) → auth(7) → audit(ppid=9110, 3) | 3/3 TC, 도구 2~3개(1회는 network 미확인) |
| 04 웹셸 업로드 → 명령 실행 | THREAT_CONFIRMED 3/3, conf 0.95~1.00 | network(alert 1) → web(2) → audit(www-data 셸 4) | 3/3 TC, 도구 2~3개(1회는 network 미확인) |
| 05 민감 디렉터리 압축 → 외부 전송 | THREAT_CONFIRMED 3/3, conf 0.95 | network(1) → auth(1) → audit(3) | 3/3 TC, 도구 3개 |

strict는 세 시나리오 모두 3회 동일하게 3개 계층을 연결했다. legacy는 판정은 같지만 network를 건너뛰는 실행이 있었다.

#### 시나리오 데이터 버그 (0918부터 있던 것)
- `generate_synthetic_scenario.py`(03): audit epoch `1789413007`이 19:10 UTC로 로그인(16:10)보다 3시간 늦었다 → `1789402207`.
- `generate_webshell_scenario.py`(04): audit epoch `1789423505`가 22:05 UTC로 웹 요청(18:05)보다 4시간 늦었다 →
  다른 시나리오처럼 `datetime`에서 계산.
- 두 시나리오 모두 사건 시간 구간으로 조회하면 audit이 0건이라, 계층 연결이 끊긴 상태로 검증되고 있었다.

#### `tests/test_consistency.py` 옵션 추가
- `--seed-json <파일>`: 시나리오 SEED를 파일로 넘김(상수 수정 불필요).
- `--legacy`: 0918 조건(`network_precheck=False`, `strict_termination=False`)으로 실행.
- `InvestigationAgent`/`run_investigation_pipeline`의 `require_second_tool` 옵션 이름을 `strict_termination`으로 바꿨다
  (관문 (d)(e)를 함께 켬).

### 0918 검증 seed 전체 재검증 (8종)
0918에 재현성을 검증한 seed 8종을 전부 다시 돌렸다. 합성 시나리오(03~07)는 `scenarios/`로 만든 로그를,
수동 seed(01, 02, INC-001)는 `b72c1e4`의 `sample_logs`를 임시 폴더에 꺼내 `*_LOG_LOCAL_PATH`로 가리켜 썼다
(지금 `sample_logs`는 0922에 교체돼 09-14 데이터가 없다). 0918 기록은 커밋 메시지·README·이력의
`consistency_results.json`에서 가져왔다.

| seed | 유형 | 0918 판정 | 0918 도구 | 지금 판정 (마지막 수정 후) | 지금 도구 흐름 |
|---|---|---|---|---|---|
| 01 | ubuntu sudo로 /etc/passwd 접근 (정상) | FP 8/8 | 2 | FP 4/4 | auth → audit (2) |
| 02 | invalid user 1회 후 공개키 로그인 (애매) | FP 7/8 | 3 | FP 4/4 | network(0) → auth → audit(0) (3) |
| 03 | 브루트포스 성공 → 역방향 셸 | TC 8/8 (수정 후) | - | TC 3/3 | network → auth → audit (3) |
| 04 | 웹셸 업로드 → 명령 실행 | TC 8/8 | - | TC 3/3 | network → web → audit (3) |
| 05 | 민감 디렉터리 압축 → 외부 전송 | TC 8/8, 4/4 | - | TC 3/3 | network → auth → audit (3) |
| 06 | SUID find 권한 상승 (src_ip 없음) | TC 7/8 | - | TC 3/3 | auth → audit (2) |
| 07 | authorized_keys·crontab·계정 생성 (audit만) | TC 8/8 | - | TC 3/3 | audit → auth 또는 network (2) |
| INC-001 | 외부 공개키 로그인 후 sudo 점검 (정상) | FP 8/8 | 3 (auth→audit→network) | FP 3/3 | network → auth → audit (3) |

판정은 8종 모두 0918과 같은 방향으로, 반복 실행에서 이탈이 없었다(0918은 02·06에서 1회씩 이탈).
도구 호출 수도 0918과 같은 2~3회이며, 사건이 여러 계층에 걸치면 그 계층을 모두 연결한다.
0918의 "도구 4개"는 특정 실행의 값이었고, 저장된 결과 파일 기준으로 0918도 2~3회였다.

한계: 반복 횟수가 3~4회로 0918(8회)보다 적다. 0918 web 샘플은 nginx JSON이라 지금 apache 정규화로 읽히지
않아 01/02/INC-001은 web 계층 없이 돌렸다(세 seed 모두 web 단서가 없는 사건이다).

#### 이 재검증에서 추가로 고친 것
| 발견 | 수정 |
|---|---|
| 07: LLM이 `fetch_audit_log`에 `event_type="EXECVE"`(레코드 종류)를 넣어 0건 → "명령 실행 없음"으로 INCONCLUSIVE | `event_type`을 룰 key뿐 아니라 레코드 종류(EXECVE/SYSCALL…)·syscall 이름과도 대소문자 무시로 비교 |
| 필터 때문에 0건인데 LLM이 "활동 없음"으로 해석 | 4개 도구 공통: 필터 결과가 0건인데 구간 안에 이벤트가 있으면 summary에 "필터 없이 N건 있음, 필터를 바꿔 다시 조회" 안내 (`log_source.filtered_out_hint()`) |
| 02: 공개키 로그인 + 단발 실패인데 audit 기록이 없어 FP/INCONCLUSIVE/TC로 갈림 (0918 audit 샘플은 15:20:49 1초 분량뿐이라 02 사건 시각에 기록이 없음) | 원칙 7: invalid user 1회 후 다른 계정 공개키 로그인은 Q1 정상. Q1 정상 + Q2 공개키이고 세션 audit이 0건이면 FALSE_POSITIVE(0.80~0.85), audit 부재는 unknowns에 기록 |
| 01: 사유가 다른 거부 2회((d) → (b))를 "연속 2회"로 세어 강제 종료 → seed의 audit을 안 봄 | 강제 종료는 **같은 사유**(숫자 제외 비교)로 연속 2회 거부될 때만. 거부 안내에 "도구 수·audit 미확인 사유는 종료 사유를 바꿔도 다시 거부되니 도구부터 호출" 추가 |
| Gemini 호출 중 SSL EOF, WinError 10053으로 조사 1건이 통째로 실패 | `gemini_client._generate_with_retry()`가 연결 오류(`OSError`, `httpx.TransportError`)도 5·10·15초 간격으로 재시도 |

### EC2 첫 실행에서 발견한 응답 잘림 (`9b5991e` 이후)
EC2 `main.py`에서 xmlrpc 사건(103.82.158.245, POST 109건)을 조사하던 중 LLM이 evidence에 raw_ref 109개를
전부 옮겨 적다가 출력 한도(`max_output_tokens=2000`)에서 응답이 잘렸다. JSON 파싱 실패 예외가 그대로 올라가
`main.py` 전체가 멈췄다.

| 수정 | 내용 |
|---|---|
| `agent/gemini_client.py` | `max_output_tokens` 2000 → 8192 |
| `investigation.yaml` 증거 기록 규칙 | raw_refs는 evidence당 대표 10개까지, 전체 건수는 description에 숫자로. audit 다중 줄 이벤트는 raw_ref 하나만 적어도 시스템이 나머지 줄을 연결(기존 동작) |
| `agent/loop.py` `_safe_reason()` | LLM 응답 해석 실패(`...DecisionError`)는 1회 재시도, 또 실패하면 그 사건만 폴백 판정으로 마무리하고 다음 seed 조사를 계속. API 키·권한 같은 다른 예외는 그대로 올린다. 폴백 판정 summary에 실제 중단 사유를 적음 |
| 테스트 | `test_unparseable_llm_response_falls_back_instead_of_crashing` 추가. 총 114개 통과. 웹셸 시나리오 2회 재확인(TC 2/2, network → web → audit) |

### EC2 두 번째 실행 후 보완 (`7676a6d` 이후)
EC2 `main.py`(INC-XMLRPC-BRUTE, 103.82.158.245, POST 150건 전부 503)는 끝까지 실행됐고 원칙 9대로
THREAT_CONFIRMED가 나왔다. 결과를 검토하며 아래를 고쳤다.

| 발견 | 수정 |
|---|---|
| 거부 → web 조회 → 거부가 "같은 사유 연속 2회"(숫자만 다름)로 세어져 강제 종료 | 거부 사이에 새 도구를 실행하면 연속 거부 횟수를 초기화 |
| 거부 사유 "도구 1종류만 사용됨"이 무엇을 볼지 알려주지 않음 | (b)(d) 거부 사유에 아직 안 본 도구와 확인 목적을 적음(예: `fetch_audit_log`: 웹 서버 프로세스의 셸·다운로드 실행 확인) |
| 같은 요청 150건이 network·web evidence로 두 번 +0.25 반영 | 원칙: 다른 계층의 같은 행위는 "교차 확인"으로 ±0.05, 새 사실이 있을 때만 기준대로 |
| 타임라인 시작이 seed 시각(08:11)으로, 실제 첫 요청(07:52)과 다름 | 원칙: 타임라인은 도구 summary의 "실제 기록 시각"을 사용 |
| 사전 조회가 150건 전부를 LLM에게 넘김 | 사전 조회는 `limit=20`. `fetch_network_log` summary에 전체 집계(종류별, alert signature, http 상태코드·경로, 목적지, 실제 기록 시각) 추가. 집계에 경보가 있는데 records에 없으면 `alert_only`로 재조회하도록 원칙 4에 명시 |

로컬 재현(EC2 샘플의 143.105.155.9, xmlrpc POST 81건, 전부 2xx, Jetpack User-Agent)에서 LLM이 원칙 9를
어기고 "Jetpack 정상 연동"으로 FALSE_POSITIVE를 내는 실행이 반복됐다(3/3 → 문구 보강 후에도 1/3~1/4).

| 수정 | 내용 |
|---|---|
| 원칙 9 | xmlrpc는 로그인 실패에도 200을 주므로 2xx는 정상·성공 근거가 아님. 인증 대입 기준은 응답 코드·User-Agent와 무관. 정상 서비스로 보려면 IP 소유를 확인한 도구 결과가 필요 |
| `fetch_web_log` | src_ip로 거른 조회면 `[원칙 9 기준]` 충족/미충족을 코드가 계산해 summary에 적고, `rule_checks`로도 반환 (SSH 실패 횟수와 같은 방식) |
| 종료 관문 (f) | `strict_termination`에서 seed src_ip가 원칙 9 기준을 충족했는데 FALSE_POSITIVE로 끝내려 하면 거부. 끝까지 FALSE_POSITIVE면 판정은 바꾸지 않고 "⚠ 판정-원칙 불일치"를 기록 |
| `models.update_confidence` | 0.6+0.25가 0.8499…가 되어 임계값 0.85에 "미달"로 거부되던 부동소수점 오차 제거(반올림) |

결과: 로컬 xmlrpc seed 4/4 THREAT_CONFIRMED(network → web → audit/auth). 회귀 확인: 04 웹셸 2/2,
03 브루트포스 2/2(도구 흐름 동일). 테스트 118개 통과.

### 남은 확인
- EC2에서 `python3 main.py`를 다시 실행해 위 보완이 실제 트래픽에서 동작하는지 확인한다.
- 8종 각각 `--runs 8`로 0918과 같은 횟수의 재측정(무료 한도 고려해 하루에 나눠서).
- (선택) Jetpack/Automattic 공개 IP 대역을 조회하는 도구를 두면 "진짜 Jetpack 연동"을 판정할 수 있다. 지금은 IP 소유를 확인할 방법이 없어 원칙 9는 횟수 기준만 쓴다.
- 원칙 9의 기준값(POST 10회, 경로 20개)은 팀 판정 정책으로 정한 값이다. 실제 로그 분포를 보고 조정할 수 있다.

## 17. 실제 트래픽 재현성 확인과 미검증 사례 점검 (0924 밤)

16장 이후 커밋: `96c1295`(EC2 두 번째 실행 보완, 16장 마지막 절 내용) → `aca56b9`(이 장의 수정).

### EC2 실제 트래픽 재현성 (`96c1295` 기준)
EC2에서 `git pull` 후 xmlrpc 사건 seed를 `tests.test_consistency --runs 5`로 반복했다.

| seed | 판정 | 신뢰도 | 도구 흐름 |
|---|---|---|---|
| INC-XMLRPC-BRUTE (103.82.158.245, `/xmlrpc.php` POST, 전부 503) | THREAT_CONFIRMED 5/5 | 표준편차 0.024 | network(사전 조회) → web → audit |

16장 증상(web 1회 후 FALSE_POSITIVE)이 실제 트래픽에서 재현되지 않았다.

참고: 첫 시도는 seed 파일을 이름순 glob으로 골라 다른 사건을 돌렸다. 가장 최근 파일(`os.path.getmtime`)로 고르면 된다.

#### network 사전 조회는 매번 실행되는가
seed에 `src_ip`가 있으면 사건 종류와 관계없이 첫 LLM 턴 전에 한 번 실행된다. src_ip가 없는 seed(06·07 등 호스트 내부 사건)는 건너뛴다.
- 비용: 도구 호출 1회. LLM 호출 수는 늘지 않는다. 결과는 대표 20건과 전체 집계로 줄여서 넘긴다.
- 0건이어도 쓸모가 있다. "해당 IP의 network 경보·외부 통신 없음"이 확인된 사실이 되고, 종료 관문 (c)를 통과한다.
- LLM이 고른 도구 수(관문 (b))에는 포함하지 않는다. 사전 조회만으로 "도구 2종류"를 채우지 못하게 하기 위해서다.

### 아직 확인하지 않았던 사례 점검 (로컬, Gemini, 각 3~4회)
지금까지 검증은 SSH·xmlrpc·0918 합성 시나리오 위주였다. 로컬 `sample_logs`(09-22 실제 웹 트래픽)의 다른 사건과
일부러 만든 어려운 사례로 확인했다.

| seed | 사건 | 결과 | 평가 |
|---|---|---|---|
| INC-WPLOGIN-LOCAL (206.189.44.36) | 24초 동안 `/wp-login.php` POST 다수 | TC 3/3, MEDIUM, 0.80~0.90 | 원칙 9대로. 문제 없음 |
| INC-WPPROBE-LOCAL (198.235.24.136) | 11초 동안 WordPress 관리 경로 7건 | FP 3/3, LOW, 0.80~0.90 | 경로 20개 미만이라 원칙 9 기준 미충족 → FP로 일관. 1회는 근거에 User-Agent("공인 보안 스캐너")를 인용함(판정에는 영향 없음, 원칙 9는 UA를 근거로 쓰지 말라고 함) |
| INC-GITCONFIG-LOCAL (142.93.207.53) | `/.git/config` 반복 요청(404) 8건 | TC 3/3, LOW, 0.80~0.87 | 일관되지만 원칙 9 수치 기준(경로 20개)만 보면 FP다. LLM은 "민감 파일 노출 탐색"으로 봤다. **팀 정책 결정 필요** |
| INC-XMLRPC-MISSING (143.105.155.9) | seed 구간(09-20)에 로그 파일 자체가 없음 | **FP 3/4**, INCONCLUSIVE 1/4 | ✗ 로그를 못 본 것을 "활동 없음"으로 해석 |
| INC-XMLRPC-HIDDEN (203.0.113.50) | xmlrpc POST 30건 + 그 뒤 audit에 www-data `curl ... \| sh` (`scratchpad/hidden_webshell.py`로 생성) | 앞쪽 audit 105건: TC 3/3 HIGH~CRITICAL. 앞쪽 audit 200건 이상: **1/3이 MEDIUM** | ✗ audit 도구가 한 번에 200건만 돌려줘서 뒤쪽 웹셸 실행을 못 봄 |

실패 두 가지를 고쳤다.

### 수정 (`aca56b9`)
| 파일 | 내용 |
|---|---|
| `agent/tools/log_source.py` | `filtered_out_hint()`: 필터 전 구간 전체가 0건이면 "이 구간에는 이 계층의 로그 기록 자체가 없음(수집 누락·로그 교체 가능). 활동 없음의 증거로 쓰지 말고 unknowns에 '원본 로그 미확보'로 남길 것"을 안내 |
| `fetch_web_log` / `fetch_auth_log` / `fetch_network_log` / `fetch_audit_log` | 반환값에 `window_total`(필터 전 구간 전체 건수) 추가 |
| `agent/tools/real/fetch_audit_log.py` | `audit_rule_check()`: 페이지(limit)와 관계없이 조건에 맞는 전체 이벤트에서 웹 서버 계정(www-data/apache/nginx/http) 실행 수, 그중 의심 명령 수, 전체 의심 명령 수(curl·wget·nc·`/dev/tcp`·`bash -i`·`sh -c`·base64·`chmod +x`·`python -c`·`perl -e`·crontab·authorized_keys·useradd·`/etc/shadow`)를 센다. summary에 `[조회 구간 전체 집계]`(건수, 실제 기록 시각, 계정·명령 상위 5개)와 `[후속 침해 확인]`(예시 3건과 raw_ref)으로 붙이고 `rule_checks`로도 반환 |
| `agent/loop.py` `_verdict_conflicts()` | 종료 관문(strict)에서 판정이 코드 계산 결과와 어긋나면 거부. (1) 도구가 돌려준 `window_total`이 모두 0인데 INCONCLUSIVE가 아님. (2) 원칙 9 기준 충족인데 FALSE_POSITIVE(16장 (f)를 이 함수로 옮김). (3) audit에 웹 서버 계정 의심 명령이 있는데 FALSE_POSITIVE이거나 severity가 HIGH/CRITICAL이 아님. 끝까지 어긋나면 판정은 그대로 두고 "⚠ 판정-원칙 불일치"를 notes에 남김 |
| `agent/models.py` | `AgentState.window_totals` 추가 |
| `agent/prompts/investigation.yaml` | 원칙 1: 조회 구간 로그 자체가 0건이면 "활동 없음"이 아니라 데이터 공백이고 INCONCLUSIVE. 원칙 9 [침해 신호]: audit summary의 `[후속 침해 확인]` 집계를 사용하고, 웹 서버 계정 의심 명령이 있으면 THREAT_CONFIRMED·HIGH 이상 |
| `main.py` | 원본 JSON 전체를 콘솔에 출력하지 않는다(팀원 의견: `results/`에 저장됨). 각 보고서 아래에 `[참고 자료] 원본 조사 결과 JSON: results/...json`, 끝에 저장 파일 목록을 표시 |
| 테스트 | `tests/test_network_precheck.py`에 데이터 공백 관문, audit 전체 집계·관문 테스트 추가. 총 120개 통과 |

### 수정 후 재검증 (0925, `fd92cf8` 기준)
0924에는 Gemini 무료 한도(429)로 중단했고, 0925에 18장 수정까지 반영된 코드로 다시 돌렸다.

| seed | 수정 전 | 수정 후 (각 4회) |
|---|---|---|
| INC-XMLRPC-MISSING (로그 없는 날짜) | FP 3/4, INCONCLUSIVE 1/4 | **INCONCLUSIVE 4/4**, 신뢰도 0.45~0.50. 관문 거부 없이 LLM이 "로그 기록 자체가 없음" 안내를 따름 |
| INC-XMLRPC-HIDDEN (audit 200건 뒤 www-data `curl \| sh`) | 1/3이 MEDIUM | **THREAT_CONFIRMED 4/4, CRITICAL 3·HIGH 1**, 신뢰도 0.85~0.95 |

숨은 웹셸 4회차는 audit을 필터 없이 `limit=50`으로 조회해 받은 레코드에 www-data 명령이 없었지만, summary의
`[후속 침해 확인]` 전체 집계로 웹셸 실행을 보고 HIGH로 판정했다. 나머지 3회는 `user=www-data`로 좁혀 2건을 직접 확인했다.
세 도구 모두 18장의 계층별 구간 그대로 조회했다.

재현 방법(`sample_logs` 원복 필수). seed JSON과 `hidden_webshell.py`는 저장소에 넣지 않은 로컬 실험 파일이다
(seed 내용은 위 표의 IP·구간과 같다).

```bash
python -m tests.test_consistency --runs 4 --seed-json seedMISSING.json   # 기대: INCONCLUSIVE 4/4
python scratchpad/hidden_webshell.py 200                                 # audit 200건 뒤에 웹셸 실행 추가
python -m tests.test_consistency --runs 4 --seed-json seedHIDDEN.json    # 기대: THREAT_CONFIRMED + HIGH 이상 4/4
rm -r sample_logs && cp -r sample_logs_orig sample_logs                  # 원복 (아래 "저장소 정리" 참고)
```

### 남은 과제 (팀 결정 포함)
| 항목 | 상태 |
|---|---|
| 위 두 seed 재검증 | 0925 완료 (위 표) |
| `/.git/config` 같은 민감 파일 탐색을 TC로 볼지 FP로 볼지 | **팀 결정 필요**. 지금은 LLM이 일관되게 TC(LOW)로 판정하지만 원칙 9 수치 기준과 다르다. 정하면 원칙 9에 "민감 파일 경로" 항목으로 명시 |
| 타임라인 시작 시각 | 원칙으로 "실제 기록 시각"을 쓰라고 했지만 여전히 seed 시각을 쓰는 실행이 있다. 코드로 보정할지 결정 필요 |
| Jetpack/Automattic IP 대역 확인 도구 | 선택 (16장 참고) |
| 8종 seed `--runs 8` 재측정 | 무료 한도를 고려해 나눠서 |
| `seed_generation`의 unknown refs ValueError, README 정리 | 이후 |

### 저장소 정리 (0925)
| 대상 | 처리 | 이유 |
|---|---|---|
| `sample_logs/` | git 추적 중단, `.gitignore` 추가. 로컬 파일은 유지 | EC2 실제 트래픽(외부 IP, 운영 도메인)이 들어 있음 — `AGENTS.md`의 "실제 운영 로그 커밋 금지". 과거 커밋 이력에는 남아 있다(이력 재작성은 하지 않음) |
| `consistency_results.json` | 삭제, `.gitignore` 추가 | 0918 측정 결과 파일. 코드가 읽지 않고, `test_consistency`의 기본 출력이라 다시 생겨도 올라가지 않게 함 |
| `requirements-dev.txt` | `requirements.txt`에 합치고 삭제 (`pytest` 한 줄 추가) | EC2에서 `pip install -r requirements.txt` 한 번으로 테스트까지 돌릴 수 있게 함 |

`sample_logs`를 git에서 빼면서 실험 후 원복은 `git checkout HEAD -- sample_logs` 대신 로컬 백업
`sample_logs_orig/`(역시 `.gitignore`)를 쓴다. 절차는 `scenarios/README.md`에 있다.
`tests/`, `pytest.ini`, `examples/`, `scenarios/`, `scripts/`는 EC2 검증에 쓰므로 1차 탐지·ATT&CK 매핑과
통합이 끝난 뒤 최종 정리 때 삭제한다.

`.env.example`도 EC2 운영 기준으로 정리했다. 로그 경로 기본값은 `/var/log/...`이고, 로컬 샘플 경로와
`AUTH_LOG_YEAR`는 주석 안내로 뒀다. S3 설정(AWS 키·버킷)과 `RAW_LOG_WINDOW_MINUTES`는 쓰지 않아 맨 아래 주석으로
옮겼다. 로그 파일 경로를 쓰면 seed 생성은 시각과 무관하게 계층별 파일 끝 `RAW_LOG_LOCAL_MAX_LINES`(50)건을 보고,
`RAW_LOG_WINDOW_MINUTES`는 S3 모드에서만 쓰인다. `HOST`는 비워 두면 `main.py`가 `web-01`을 쓴다.

## 18. EC2 실행 결과 반영: SSH 판정 기준 코드화와 계층별 조회 구간 (0925)

커밋: `8069134`(원칙 7·audit·IP 필터 안내) → `fd92cf8`(계층별 조회 구간) → `7e7adab`(SSH 탐침 규칙) →
`d99b664`(기준과 같은 판정의 신뢰도 면제, 강제 종료 판정 유지).

### 증상 (EC2 `main.py`, INC-SSH-BRUTE)
92.118.39.50 → root SSH 로그인 실패 2회, 성공 0회. auth 도구 집계는 정확했다("실패 2회, 계정 1개, 성공 0회").
1. **판정 오류**: 원칙 7(실패 1~4회·계정 1개 → FALSE_POSITIVE)을 어기고 THREAT_CONFIRMED(LOW)로 판정했다.
   종료 관문이 신뢰도 0.78로 한 번 거부하자, audit을 조회해 "침해 없음"을 위협 쪽 증거로 쌓아 0.88을 채웠다.
   원칙 9(웹)는 코드가 기준을 계산하지만 원칙 7은 프롬프트에만 의존하고 있었다.
2. **audit 의심 명령 과다**: LLM이 audit을 24시간 무필터로 조회(3728건, 결과 JSON 114KB)했고,
   `[후속 침해 확인]`에 "의심 명령 245건"이 나왔다. 대부분 cron의 `sh -c`와 EC2 Instance Connect
   (`sshd -o AuthorizedKeysCommand .../eic_run_authorized_keys`, `authorized_keys` 패턴에 걸림)였다.
3. **network 사전 조회 안내 혼동**: IP로 거른 0건에 "필터를 빼고 다시 조회하라"는 안내가 붙어,
   LLM이 notes에 "네트워크 재확인 고려"를 남겼다.
4. **조회 구간이 실행마다 다름**: auth(24시간)만 코드가 정하고 나머지는 LLM이 정했다. audit 24시간 무필터,
   web은 seed 구간(수 초~수십 분)만 보는 식이었다.

### 수정
| 파일 | 내용 |
|---|---|
| `fetch_auth_log.py` | `principle7_check()`: IP 하나로 거른 조회에서 로그인 성공이 없으면 원칙 7 기준(실패 5회 이상 또는 계정 2개 이상)을 계산해 summary `[원칙 7 기준]`과 `rule_checks`로 반환. 성공이 있으면 Q2/Q3 판단이 필요해 내지 않는다 |
| `loop.py` `_verdict_conflicts()` | 원칙 7 기준 충족인데 FALSE_POSITIVE, 또는 미충족(단발성)이고 다른 위협 기준(원칙 9, 웹 서버 계정 의심 명령)도 없는데 THREAT_CONFIRMED면 종료 거부. 원칙 7은 충족·미충족을 모두 `state.rule_floors`에 기록 |
| `fetch_audit_log.py` | 전체 의심 명령에서 `sh -c`를 빼고 EC2 Instance Connect를 제외. 웹 서버 계정은 셸 실행 자체를 의심으로 센다(`sh -c id`도 포함). `authorized_keys` 백도어 추가는 계속 잡는다 |
| `log_source.filtered_out_hint()` | IP 필터(`ip`/`src_ip`/`dest_ip`)로만 0건이면 "구간 전체 N건은 다른 대상의 이벤트, 해당 IP의 활동 없음으로 기록"으로 안내 |
| `prompts/__init__.py` `layer_query_windows()` | seed 사건 구간 기준 계층별 첫 조회 구간을 계산해 user prompt `query_windows`로 제공: web 앞뒤 1시간, audit 30분 전~1시간 후, network 앞뒤 30분(사전 조회와 동일), auth 24시간 전~1시간 후(src_ip 있을 때) |
| `investigation.yaml` | 원칙 2: 각 계층 첫 호출은 `query_windows` 그대로, 다른 구간은 두 번째 호출부터 실제 기록 시각을 근거로. audit은 넓은 구간 무필터 조회 금지, 집계를 먼저 보고 ppid/user로 좁힘. 원칙 7: `[원칙 7 기준]`을 따르고 "root 대상"·"preauth" 같은 표현은 횟수 기준을 바꾸지 않음. 원칙 9: 첫 web 조회는 `query_windows` 구간 |
| 테스트 | 원칙 7 계산·관문 양방향, audit 정상 명령 제외, IP 필터 안내, 계층별 구간 계산. 총 125개 통과 |

### 결과
| 확인 | 결과 |
|---|---|
| EC2 INC-SSH-BRUTE, `8069134` | FALSE_POSITIVE 3/3 (수정 전 THREAT_CONFIRMED), 신뢰도 0.80~0.85 |
| EC2 INC-SSH-BRUTE, `fd92cf8` | FALSE_POSITIVE 3/3, 신뢰도 0.85~0.90. 세 번 모두 코드가 준 구간 그대로 조회: network 앞뒤 30분(0건), auth 24시간(7건), audit 30분 전~1시간 후(50건, 수정 전 24시간 3728건), web 앞뒤 1시간(0건) |
| 로컬 INC-XMLRPC-LOCAL, `fd92cf8` | THREAT_CONFIRMED 2/2. 두 번 모두 같은 구간·조건: web 앞뒤 1시간 `src_ip`(82건, 수정 전 seed 구간 81건), audit `user=www-data`(0건) |
| 로컬 로그 누락·숨은 웹셸, `fd92cf8` | INCONCLUSIVE 4/4, THREAT_CONFIRMED(HIGH 이상) 4/4 — 17장 재검증 표 참고 |

EC2 1회차는 network 사전 조회와 auth만 보고 끝났다(같은 사유 연속 거부 후 강제 종료로 추정). 로그인 성공이 없는
사건이라 판정에는 영향이 없다.

### 추가: SSH 접속 탐침 사건 (`7e7adab`, `d99b664`)
EC2 `main.py`의 다음 사건 INC-SSH-PROBE-01(45.239.159.94)은 auth 2건이 모두 `ssh_probe`(계정 없이 끊긴 연결)였다.
원칙 7에 "실패 0회" 규칙이 없어 INCONCLUSIVE(0.55)로 판정됐다.

| 발견 | 수정 |
|---|---|
| 실패 0회·접속 흔적만 있는 경우 규칙 없음 → INCONCLUSIVE | `principle7_check()`: 실패 0회이고 `ssh_probe`/`ssh_disconnect`만 1~4건이면 "스캐너 탐침, 다른 공격 정황 없으면 FALSE_POSITIVE". 탐침 5건 이상이거나 `ssh_auth_fail_close`/`ssh_max_auth`가 있으면 기준을 내지 않는다 — `authenticating user root ... [preauth]`는 키 전용 서버에서 실제 인증 시도라 탐침으로 세면 무차별 대입을 놓친다. 관문은 원칙 7 기준이 계산된 사건의 INCONCLUSIVE도 거부(원칙 7: 실패만 있는 경우 INCONCLUSIVE 금지). 원칙 7 프롬프트에 탐침 규칙 추가 |
| 수정 후 3회 중 1회 THREAT_CONFIRMED: LLM이 FALSE_POSITIVE로 5회 종료 요청했으나 신뢰도 0.80 < 0.85로 모두 거부 → 도구를 더 부르다(5회) 강제 종료 턴에서 판정을 새로 쓰며 뒤집힘 | `_rule_determined_verdict()`: 도구 기준으로 판정이 정해지는 경우(로그 미확보 → INCONCLUSIVE, 원칙 9·웹 서버 계정 의심 명령 → TC, 원칙 7만 있으면 무차별 대입 TC/단발성·탐침 FP) LLM 판정이 그와 같으면 신뢰도 미달로는 거부하지 않음(도구 수·network 조건은 유지). `_settle_forced_verdict()`: 강제 종료 턴 판정이 원칙과 어긋나면 그 전에 LLM이 낸 원칙에 맞는 판정을 사용(코드가 판정을 새로 만들지는 않음) |

| 확인 (EC2, 각 3회) | 판정 | 도구 호출 |
|---|---|---|
| 수정 전 (`main.py` 1회) | INCONCLUSIVE | 3 |
| `7e7adab` (탐침 규칙) | FALSE_POSITIVE 2, THREAT_CONFIRMED 1 | 3~5 |
| `d99b664` (신뢰도 면제·강제 종료 판정 유지) | **FALSE_POSITIVE 3/3**, 신뢰도 0.80~0.85 | 3 |

테스트: 탐침 계산·예외, INCONCLUSIVE 거부, 기준과 같은 판정의 신뢰도 면제, 강제 종료 판정 유지. 총 127개 통과.

## 19. S3 삭제·주석/문서 정리·프롬프트 정합성 정리 (0925 오후)

커밋: `796cb25`(S3 삭제) → `9b3d471`(주석·문서, 실행 코드 변경 없음) → `5770318`(프롬프트 설명서) →
`24f5962`(이전 도구 결과 요약 유지) → `dce17fb`(프롬프트 규칙 충돌 2건 정리).

| 커밋 | 내용 | 확인 |
|---|---|---|
| `796cb25` | S3 읽기 코드 삭제(`_s3_common.py`, `log_source`·`normalizer_adapter`의 S3 분기, `boto3`). 로그 경로 미설정은 설정 오류로 알림. 테스트는 가짜 S3 대신 임시 로그 파일(`tests/_log_files.py`) | 로컬·EC2 테스트 124개, EC2 `verify_all_tools` 4계층 통과 |
| `9b3d471` | 모든 에이전트 파일 상단에 역할/누가 부르나/무엇을 부르나, 흐름 번호 `[1]`~`[45]` 주석, 날짜·이름 표시 제거. `docs/AGENT_FLOW.md` 신설, README 재작성 | 주석·docstring을 뺀 코드 구조가 이전과 동일함을 자동 비교로 확인, EC2 테스트 124개 |
| `5770318` | `docs/PROMPT_GUIDE.md` 신설 — 원칙별 지시·생긴 이유·코드 뒷받침 | — |
| `24f5962` | **이전 도구 결과 요약 유지**: 도구 결과 원문은 직후 한 턴만 보여 LLM이 판정 근거 숫자를 다시 볼 수 없었음(같은 조회는 차단). `already_called_tools`에 결과 건수·요약(자르지 않음)·사전 조회 표시 추가, 원칙 3에 "이전 결과는 summary로, 새 증거는 방금 받은 결과에서만" 명시. 프롬프트는 도구 3개 기준 턴당 약 +0.9~1.6천 자 | 로컬 xmlrpc TC 2/2, EC2 SSH 실패 FP 3/3·탐침 FP 3/3(신뢰도 0.85 고정), 도구 3회 |
| `dce17fb` | **규칙 충돌 정리 A1**: "0건은 증거가 아니다" ↔ 신뢰도 표 "통신 없음 확인 ±0.05" 충돌 → 실제 동작에 맞춰 "0건은 참조 없이 조회 조건을 적은 약한 신호(±0.05)로 한 번만". **A2**: 판정이 도구 계산 기준과 같으면 신뢰도 미달도 승인하는 코드 동작을 원칙 4에 명시 | 로컬 xmlrpc TC 2/2·로그 누락 INCONCLUSIVE 2/2, EC2 SSH 실패 FP 3/3·탐침 FP 3/3 (도구 2~3회) |

### 검토 후 보류한 것
| 항목 | 판단 |
|---|---|
| ②안 — 새 도구 결과가 없는 턴(거부 직후·강제 종료)의 증거는 신뢰도에 반영하지 않기 | **보류.** EC2 탐침 3회를 확인한 결과 참조 없는 증거 1~2개는 모두 "조회 결과 0건"을 해석한 정상 증거였고, 거부 뒤 새 관측 없이 같은 사실을 다시 적어 신뢰도를 채운 사례는 없었다. 신뢰도 계산을 바꾸는 변경이라 모델 결정 후 전체 재검증 때 다시 본다 |
| 프롬프트 정합성 정리 B′ — 코드와 중복된 판정 기준 숫자(실패 5회·계정 2개·POST 10회·경로 20개, 조회 구간)를 yaml에 자리 표시로 두고 코드 상수로 자동 채움 | **다음에 할 것.** 처음 안(yaml에서 숫자 삭제)은 IP 하나로 거르지 않은 조회에서 LLM의 판단 근거를 없애므로 채택하지 않음. 조립 결과가 글자 단위로 같으면 LLM 재검증 불필요. 회의에서 기준값을 바꾸면 먼저 적용, 아니면 통합 후. 설계는 `PROMPT_GUIDE.md` 9장 |
| 정합성 정리 C — 여러 곳에 반복된 문장(거부 대응, 증거 중복 금지, Q1~Q3 기록 방식) 한 곳으로 | **필요 시.** 판정을 흔든 사례가 없고 일부 반복은 효과가 있음. 프롬프트 대개편 때 함께 |
| `ClaudeClient` 버그 — `reason()`이 루프 인자를 받지 않아 Claude 전환 시 첫 턴 TypeError, 출력 한도 2000 | Claude 전환 결정 후 수정 |
