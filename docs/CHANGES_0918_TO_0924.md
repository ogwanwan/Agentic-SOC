# 0918 → 0924 변경 정리: 에이전트 도구 복구, C/D 통합, 공통 정규화 연동

작성: 2026-09-24 (B: 조사 에이전트/도구 담당)
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
  **이 폴더는 수정하지 않는다.**
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
| `docs/CHANGES_0918_TO_0924.md` | 이 문서 |

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
