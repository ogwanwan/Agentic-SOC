# Agentic-SOC

## 2026-09-23: A·B 공통 정규화와 C·D 기능 통합

현재 조사 브랜치의 공통 정규화 코드를 유지하면서 사건 시간 구간 조회(`fetch_event_logs`)와
원본 참조 추적·검증을 연결했습니다. 웹 로그는 Apache 형식을 사용하며,
1차 탐지가 만든 로컬 `raw_ref`는 그대로 유지하고 `raw_ref_locations`에 실제 경로를 기록합니다.

- [A·B·C·D 통합 테스트와 쉬운 설명](docs/ABCD_TEST_GUIDE.md) — 팀원용 실행 순서, 예상 결과, 파일별 역할
- [C·D 사용법과 병합 내용](docs/C_D_IMPLEMENTATION.md)
- 오프라인 검증: `pip install -r requirements.txt` → `python -m pytest -q`
- 전체 파이프라인 데모: `python -m scripts.demo_abcd` → `results/abcd_demo.json`
- 사건 조회 데모: `python -m scripts.demo_event_window` → `results/cd_demo.json`

| 역할 | 쉽게 말하면 |
| --- | --- |
| A: 공통 정규화 | 서로 다른 로그를 같은 형식으로 번역 |
| B: 조사 도구 | A의 번역기를 사용하는 계층별 검색 도구 |
| C: 사건 구간 조회 | 사건이 일어난 시간대의 로그를 모아 시간순으로 조회 |
| D: 원본 추적 | 원본 파일·줄 번호를 증거와 최종 보고서까지 유지·검증 |

오프라인 검증에는 `.env`, AWS 계정, LLM API 키가 필요 없습니다. 로그 처리·조회·검증은
실제 코드를 사용하고, LLM 판단 응답과 S3 서비스 응답만 테스트용으로 대체합니다.


"에이전트개발-9/9" 문서의 조사 에이전트 설계를 파이썬으로 구현한 것입니다.
Triage/감지 에이전트가 파이프라인에서 빠지면서, raw log를 직접 받아 LLM이
스스로 seed를 생성하고 우선순위를 매긴 뒤 심층 조사까지 하는 구조로 확장했습니다.

> **2026-09-22~23 업데이트**: 조사 도구(auth/audit/web/network/get_process_tree)와
> seed 생성 단계(raw_log_ingestion.py)가 전부 각자 자체 파서 대신 **1차 탐지팀의
> 공통 정규화 함수**를 쓰도록 교체됐고, 그 결과 자체 파서 폴더(`agent/tools/parsers/`)는
> 삭제됐습니다. 현재 A/B/C/D의 연결 방식과 검증 결과는
> [`docs/ABCD_TEST_GUIDE.md`](docs/ABCD_TEST_GUIDE.md), C/D의 상세 계약과 통합 내역은
> [`docs/C_D_IMPLEMENTATION.md`](docs/C_D_IMPLEMENTATION.md)를 참고하세요.

## 전체 흐름 (한눈에)

```
Raw Log 수집 (agent/raw_log_ingestion.py)
      ↓
Seed 생성 - 경량 LLM Triage (agent/seed_generation.py + seed_prompts.py)
      ↓
우선순위 판단 (같은 곳, priority로 정렬)
      ↓
심층 조사 루프 - Agent Loop (agent/loop.py, 충분할 때까지 반복)
   판단(agent/prompts.py) → Tool 호출(agent/tools/) → 증거 반영 → 종료 판단
      ↓
보고서 출력 (agent/report.py)
```

`main.py` 하나로 이 전체 흐름을 실행합니다: `python main.py`

## 폴더 구조

```
Agentic-SOC/
├── agent/                               ← 우리 에이전트 코드
│   ├── __init__.py            # 패키지 진입점
│   ├── loop.py                # Agent Loop 총괄 + 제어(중복/max_call/실패처리/종료판단)
│   ├── models.py              # State / Evidence 관리 (AgentState, Evidence, Hypothesis)
│   ├── prompts.py             # 조사 루프 시스템 프롬프트 (계층 간 IP/pid/시간 연결 원칙 포함)
│   ├── seed_prompts.py        # seed 생성(경량 triage) 전용 프롬프트
│   ├── seed_generation.py     # SeedGenerator — raw log에서 seed 후보 + 우선순위 추출
│   ├── raw_log_ingestion.py   # 최근 N분 raw log를 4계층(web/auth/audit/network) 수집
│   │                          #   4계층 전부 normalizer_adapter/primary_detection.normalizer 경유
│   ├── provenance.py        # raw_ref 전달·인용 검증(D)
│   ├── pipeline.py            # raw log → seed → 우선순위 → 심층조사 전체 연결
│   ├── claude_client.py       # Claude API 클라이언트
│   ├── gemini_client.py       # Gemini API 클라이언트 (기본값, 무료 티어 가능)
│   ├── report.py              # 최종 investigation_result 조립 + 텍스트 리포트 변환
│   └── tools/
│       ├── __init__.py
│       ├── registry.py            # Tool 연결·실행 계층 (ToolRegistry, build_default_registry)
│       ├── mock_tools.py          # 실제 구현 전 로컬 테스트용 목업 핸들러
│       ├── normalizer_adapter.py  # 1차 탐지팀 정규화 함수용 S3/로컬 소스 선택 어댑터 (우리 코드)
│       ├── log_source.py          # 수집·조회 공용 읽기/필터/페이지 처리
│       ├── time_utils.py          # parse_iso() 등 시간 파싱 공용 유틸
│       ├── real/                  # 조사 도구 본체 (파일명 = 도구명이면 자동 연결)
│       │   ├── README.md
│       │   ├── _s3_common.py          # S3 읽기 공용 헬퍼 (list_and_read_text 등)
│       │   ├── fetch_web_log.py       # apache access.log, 공용 log_source 경유
│       │   ├── fetch_auth_log.py      # auth.log(syslog), 공용 log_source 경유
│       │   ├── fetch_audit_log.py     # auditd raw 텍스트, 공용 log_source 경유
│       │   ├── fetch_network_log.py   # Suricata eve.json, 공용 log_source 경유
│       │   ├── fetch_event_logs.py    # 사건 window로 여러 계층 조회(C)
│       │   ├── get_process_tree.py    # audit pid/ppid로 조상 체인 추적, 같은 공통 정규화 함수 사용
│       │   │                          #   + build_ancestry_chain() 헬퍼도 이 파일 안에 있음
│       │   └── resolve_ip_geo.py      # IP 지리정보 실제 구현 (외부 API, 현재 기본 제외)
├── primary_detection/                   ← 1차 탐지팀 산출물 (우리 코드 아님, 절대 직접 수정 금지)
│   └── normalizer/
│       ├── common/schema.py           # 1차 탐지팀 공통 스키마 (build_event 등)
│       ├── tools/                     # fetch_auth_log/fetch_audit_log/fetch_apache_log/fetch_network_log
│       │                              #   (1차 탐지팀 정규화 순수 함수, 바이트 단위 그대로 벤더링)
│       ├── samples/                   # 패리티 테스트용 1차 탐지팀 원본 샘플 로그
│       └── vendor_sync_check.py       # 1차 탐지팀 저장소와 바이트 단위로 같은지 확인하는 스크립트
├── backend/                # 기존 Flask 백엔드 (건드리지 않음)
├── sample_logs/             # 로컬 테스트용 샘플 (EC2에서 SSH로 받아온 실제 로그)
│   ├── sample_apache_web.log      # web 계층 기본 샘플 (apache 포맷)
│   ├── sample_auth.log / sample_audit.log / sample_network.log
├── scripts/                 # 개발용 보조 스크립트 (프로덕션 코드 아님)
│   ├── demo_abcd.py             # raw 입력 → seed → 실제 조사 도구 → 최종 보고서
│   ├── demo_event_window.py     # C/D 사건 조회 데모
│   ├── fetch_sample_from_ec2.py  # SSH로 EC2에서 4계층 샘플 로그를 한 번에 받아오는 스크립트
│   ├── verify_all_tools.py       # 5개 조사 도구 + raw_log_ingestion을 로컬 샘플로 한 번에 점검
│   └── local_e2e_test.py         # (구버전) 초기 검증용 스크립트, 지금은 real/ tool로 대체됨
├── docs/
│   ├── ABCD_TEST_GUIDE.md        # 팀원용 테스트와 A/B/C/D 쉬운 설명
│   └── C_D_IMPLEMENTATION.md    # C/D 인터페이스·제약·통합 내용
├── tests/
│   ├── test_abcd_pipeline.py    # 단일/4계층·S3 모사·잘못된 참조를 전체 흐름에서 검증
│   ├── test_cd_normalizer_integration.py # 수집·B 도구·C 조회와 벤더 결과 비교
│   ├── test_event_window.py     # 사건 시간 범위·필터·페이지
│   ├── test_provenance.py       # 원본 참조 유지·검증
│   ├── test_normalizer_parity.py # adapter 결과 == 1차 탐지팀 벤더 코드 직접 호출 결과 (완료 기준 검증)
│   ├── test_fetch_auth_log.py    # fetch_auth_log 파싱/필터링 검증 (가짜 S3)
│   ├── test_fetch_audit_log.py   # fetch_audit_log 파싱/필터링 검증 (가짜 S3)
│   ├── test_fetch_web_log.py     # fetch_web_log(apache) 파싱/필터링 검증 (가짜 S3)
│   ├── test_fetch_network_log.py # fetch_network_log(suricata) 파싱/필터링 검증 (가짜 S3)
│   ├── test_get_process_tree.py  # get_process_tree 조상 체인 추적 검증 (가짜 S3)
│   ├── test_loop.py              # Agent Loop 전체 흐름 검증 (FakeLLMClient)
│   ├── test_seed_generation.py   # SeedGenerator 우선순위 정렬 검증
│   ├── test_raw_log_ingestion.py # fetch_recent_raw_logs 4계층 수집 검증
│   └── test_pipeline.py          # 전체 파이프라인 통합 검증
├── main.py                 # 실행 진입점
├── .env.example             # .env로 복사해서 실제 키/경로를 채워 넣는 템플릿
├── .gitignore                # .env, .venv/, __pycache__/, sample_*.log 등 제외
└── requirements.txt
```

| 원래 역할 분담 문서 항목 | 위치 |
| --- | --- |
| Agent Loop 총괄 | `agent/loop.py` (`InvestigationAgent.run`) |
| State / Evidence 관리 | `agent/models.py` (`AgentState`, `Evidence`, `Hypothesis`) |
| Tool 연결·실행 계층 | `agent/tools/` (`ToolRegistry`, `build_default_registry`) |
| Agent 판단·Prompt | `agent/prompts.py` + `agent/claude_client.py`(Claude) / `agent/gemini_client.py`(Gemini) |
| Agent 제어 + 최종 산출물 | `agent/loop.py`의 종료/중복/실패 처리 + `agent/report.py` |
| 보고서 출력 | `agent/report.py` (`build_investigation_result`, `format_text_report`) |
| (추가) raw log 수집 · seed 생성 | `agent/raw_log_ingestion.py`, `agent/seed_generation.py`, `agent/seed_prompts.py` |
| (추가) 전체 파이프라인 연결 | `agent/pipeline.py` (`run_investigation_pipeline`) |
| (추가) 공통 정규화 함수(A) | `agent/tools/normalizer_adapter.py` + `primary_detection/normalizer/` (상세: [통합 안내](docs/ABCD_TEST_GUIDE.md)) |
| (추가) 조사 도구(B) | `agent/tools/real/fetch_*.py`, `get_process_tree.py` — 전부 normalizer_adapter 경유 |
| (추가) 사건 구간 조회(C) | `agent/tools/real/fetch_event_logs.py` + `agent/tools/log_source.py` |
| (추가) 원본 참조 검증(D) | `agent/provenance.py` + `seed_generation.py`, `loop.py`, `report.py` |

## 설치 및 실행

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
cp .env.example .env
```

`.env`에 최소 이 항목들을 채웁니다:

```
GEMINI_API_KEY=발급받은_키          # Google AI Studio 무료 티어
HOST=web-01                        # S3 파티션의 host= 값과 일치해야 함
RAW_LOG_WINDOW_MINUTES=10
```

그리고 아래처럼 실행:

```bash
# 단위/통합 테스트 (API 키/AWS 불필요)
python -m pip install -r requirements.txt
python -m pytest -q                 # 전체 오프라인 테스트
python -m scripts.demo_abcd         # 실제 도구를 연결한 A/B/C/D 데모
python -m tests.test_normalizer_parity   # 완료 기준(1차 탐지와 동일한 정규화 결과) 직접 검증
python -m tests.test_loop
python -m tests.test_fetch_auth_log
python -m tests.test_fetch_audit_log
python -m tests.test_fetch_web_log
python -m tests.test_fetch_network_log
python -m tests.test_get_process_tree
python -m tests.test_seed_generation
python -m tests.test_raw_log_ingestion
python -m tests.test_pipeline

# 실제 실행 (진짜 Gemini API 호출)
python main.py
```

## AWS 없이 로컬 샘플로 실제 tool을 테스트하는 방법

AWS access key가 아직 없어도, `agent/tools/real/fetch_*.py` 4개 + `get_process_tree.py`는
**환경변수로 로컬 파일 경로를 지정하면 S3 대신 그 파일을 읽습니다.** 나중에
S3 키가 생기면 이 환경변수 줄만 지우면 코드 수정 없이 그대로 S3 모드로 전환됩니다.

```bash
# 1) EC2에서 4계층 샘플 로그 받기 (SSH 필요, 개발용 편의 스크립트)
python scripts/fetch_sample_from_ec2.py --all
```

`.env`에 추가 (`.env.example`에 이미 기본값으로 들어있음):

```
WEB_LOG_LOCAL_PATH=sample_logs/sample_apache_web.log   # ← apache 포맷! nginx 아님 (아래 주의 참고)
AUTH_LOG_LOCAL_PATH=sample_logs/sample_auth.log
AUDIT_LOG_LOCAL_PATH=sample_logs/sample_audit.log
NETWORK_LOG_LOCAL_PATH=sample_logs/sample_network.log
AUTH_LOG_YEAR=2026               # 연도 없는 auth 샘플의 실제 연도
LOG_LOCAL_HOST=web-01            # 로컬 파일이 속한 수집 서버
RAW_LOG_LOCAL_MAX_LINES=10       # 계층별 마지막 완성 이벤트 수(audit 여러 줄 = 한 이벤트)
```

이 상태로 `python main.py`를 실행하면, `agent/raw_log_ingestion.py`와
`agent/tools/real/fetch_*.py`가 S3 대신 이 로컬 파일들을 읽어서 진짜
Gemini API + 진짜 EC2 로그로 seed 생성부터 보고서 생성까지 끝까지 검증할 수
있습니다.

`WEB_LOG_LOCAL_PATH`는 공통 정규화 함수가 지원하는 **Apache access.log 형식**을
가리켜야 합니다. 현재는 seed 수집과 조사 도구 모두 같은 파일·정규화 함수를 사용합니다.
로컬 수집은 오래된 샘플도 재생하도록 현재 시각 필터를 생략하지만, 조사 도구는 요청한
사건 구간을 항상 적용합니다. `AUTH_LOG_YEAR`는 auth 로그의 실제 연도로 설정하세요.
형식·시간·경로 점검 방법은 [통합 안내](docs/ABCD_TEST_GUIDE.md)에 있습니다.

빠르게 5개 조사 도구 + raw_log_ingestion 전체를 한 번에 점검하려면:

```bash
python scripts/verify_all_tools.py
```

## LLM 연결

`agent/gemini_client.py`의 `GeminiClient`와 `agent/claude_client.py`의
`ClaudeClient`는 **완전히 동일한 인터페이스**(`.reason(state, tool_registry)`,
`.complete_json(system_prompt, user_prompt)`)를 제공하므로 서로 갈아끼울 수
있습니다. `agent/prompts.py`/`agent/seed_prompts.py`의 프롬프트는 모델에
종속되지 않는 순수 텍스트라 그대로 재사용됩니다.

기본값은 Gemini(`gemini-3.5-flash-lite`, 무료 티어)이고, `main.py`는
`LLM_PROVIDER=anthropic` 환경변수로 Claude로 전환할 수 있습니다.

무료 티어는 분당 토큰 한도가 있고, Google 서버가 일시적으로 과부하(503
UNAVAILABLE)일 때도 있습니다 — 이건 우리 코드 문제가 아니라 몇 분 뒤
재시도하면 보통 해결됩니다. `RAW_LOG_LOCAL_MAX_LINES`로 페이로드를 줄이거나
`InvestigationAgent(max_calls=...)`를 너무 크게 잡지 않는 것으로 조절합니다.

## 동작 방식 (설계 메모)

### raw log → seed 생성
`agent/raw_log_ingestion.py`가 4계층 raw log를 공통 함수로 정규화합니다.
`agent/seed_generation.py`의 `SeedGenerator`는 원본 참조가 붙은 정규화 로그를
LLM에게 넘기고, "조사할 가치가 있는 후보"를 우선순위와 함께 뽑아옵니다.
입력에 참조가 있으면 후보의 `evidence_refs`도 실제 입력의 참조를 인용해야 합니다.
후보가 0개일 수도, 여러 개일 수도 있습니다. `agent/pipeline.py`가 우선순위
순서대로 각 seed를 `InvestigationAgent.run()`에 넘깁니다.

### 심층 조사 루프
문서의 Stage 1(현황 파악) / Stage 2(증거 결정) / Stage 3(도구 호출)은
개념적으로는 분리돼 있지만, 실제 LLM 호출은 **사이클당 1회**로 묶었습니다.
매 호출마다 LLM이 facts/hypotheses/unknowns를 갱신하고, 동시에 다음 행동
(`call_tool` 또는 `terminate`)까지 결정하는 ReAct 스타일 루프입니다.

```
seed 입력
  ↓
LLM 판단 (facts/hypotheses/unknowns 갱신 + 다음 행동 결정)  ─┐
  ↓                                                          │
call_tool? → Tool 실행 → 결과를 pending_observations에 저장 ─┘ (반복)
  ↓
terminate? → 최종 investigation_result 생성
```

### tool 설계 원칙 — "파싱은 최소한만, 의미 해석은 전부 LLM"
`agent/tools/real/`의 조사 도구 모두 동일한 철학입니다. 실제 정규화(로그
텍스트 → 구조화된 이벤트)는 1차 탐지팀 공통 함수(`primary_detection/normalizer/`)가
하고, tool은 그 위에서 필터링·페이지네이션만 담당합니다 — uid/session_type 같은
의미 해석은 tool도 정규화 함수도 하지 않고 전부 LLM 몫입니다. 이렇게 해야
정규화 스키마가 나중에 바뀌어도(1차 탐지팀 쪽에서) tool 코드를 거의 안
고쳐도 됩니다.

### 계층 간 연결
`agent/prompts.py`에 "한 계층에서 IP/시간을 확인했으면 다음 도구 호출 시
그 IP/시간대를 조건으로 그대로 써서 사건을 연결하라"는 원칙이 명시돼
있습니다 (audit↔auth는 pid로, web→audit/network는 같은 src_ip·시간대로).
별도의 "조인 엔진" 코드 없이 LLM의 판단으로 여러 계층의 사실을 하나의
공격 시나리오로 엮습니다.

## 종료 조건 (3가지 중 하나)

1. `confidence_sufficient` — LLM이 신뢰도가 충분하다고 판단해 `terminate` 반환
2. `no_more_evidence` — LLM이 더 조사할 로그가 없다고 판단해 `terminate` 반환
3. `max_call_reached` — `InvestigationAgent(max_calls=...)`에 설정한 호출 상한 도달

## 제어 로직

- **중복 조사 방지**: 동일 `(tool_name, args)` 조합은 `AgentState.already_called()`로
  걸러져 실제 도구가 다시 호출되지 않습니다.
- **실패 처리**: 도구 호출 예외는 `tool_calls`에 `success=False`로 기록되고 조사는
  계속됩니다.

## 실제 팀원 구현과 연결하는 방법

`agent/tools/real/`에 파일명·함수명이 도구 이름과 똑같은 파일을 넣으면
`build_default_registry()`가 자동으로 그 함수를 사용합니다. 우선순위:

1. `build_default_registry(handlers={...})`로 명시적으로 넘긴 함수
2. `agent/tools/real/<도구이름>.py` 안의 동일한 이름의 함수 — **자동 탐색**
3. `mock_tools.py`의 목업 (1, 2 둘 다 없을 때 폴백)
4. `exclude`에 이름이 있으면 위 셋 다 건너뛰고 아예 등록 안 함

파일명이나 함수명이 하나라도 다르면 에러 없이 조용히 목업으로 폴백하니,
추가한 뒤 아래로 확인하는 걸 권장합니다.

```python
from agent import build_default_registry
registry = build_default_registry()
print(registry.get("fetch_auth_log").handler)  # agent.tools.real.fetch_auth_log 쪽이어야 성공
```

## 보고서 출력 형식

`agent/report.py`가 만드는 것:

- `build_investigation_result(state, ...)` — `evidence_chain`, `attack_timeline`,
  `confidence_progression`, `final_verdict`, `remaining_unknowns` 등을 포함한 JSON
- `format_text_report(result)` — 위 JSON을 사람이 읽는 텍스트로 변환

```
INVESTIGATION RESULT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident INC-SSH-BF-01

Initial Hypothesis
SSH 브루트포스 공격 후 시스템 침입 시도

Investigation Findings
E1 [Auth] 77.239.124.213 IP로부터 발생한 399건의 인증 로그 분석 결과, 모든 시도가 실패

Timeline
04:07:24 첫 번째 SSH 브루트포스 시도 감지
04:23:46 마지막 인증 실패 시도 기록

Provisional Conclusion
외부 IP(77.239.124.213)가 브루트포스를 시도했으나 시스템 침해로 이어지지 않았습니다.

Supporting Evidence 1
Contradicting Evidence 0
Unresolved 없음

Investigation Confidence 0.95
```

- `E1, E2...`와 `[Auth]/[Audit]/[Apache]/[Suricata]` 라벨은 `sequence` 순서와
  `source_log` 문자열에서 자동으로 매깁니다.
- `Provisional Conclusion`은 `final_verdict.summary`에 LLM이 직접 쓰는 1~2문장입니다.
- `Unresolved`는 종료 시점의 `state.unknowns`를 그대로 노출합니다.

## 인프라 관련 알아둘 것

- S3의 `raw/source_type=auditd/...` 안 파일은 NDJSON이 아니라 **정규화 이전
  raw 텍스트** 그대로입니다 (인프라팀 정규화 파이프라인 미완성 상태로 확인, 2026-09-13).
- EC2에 apache2와 nginx가 둘 다 있고, nginx가 앞단 리버스 프록시입니다.
  **(2026-09-22 정정)** 예전엔 "apache 로그의 src_ip가 항상 loopback이라 web
  계층은 nginx를 써야 한다"고 알고 있었는데, EC2를 직접 SSH로 확인한 결과 지금은
  apache에 **mod_remoteip**가 설정돼 있어서 apache의 access.log에도 이미 실
  클라이언트 IP가 복원되어 찍힙니다. 그래서 web 계층 조사 도구는 이제 apache의
  access.log를 정규화 대상으로 씁니다(1차 탐지팀 파서 포맷과 컬럼 단위로 일치함을
  확인함).
- EC2의 S3 쓰기 전용 역할(`ogwanwan-shop-log-writer`)은 `s3:ListBucket` 권한이
  없어서 `aws s3 ls`가 항상 `AccessDenied`가 납니다 — 별도 읽기용 자격 증명 필요.

## 아직 남은 것

- **AWS access key 발급 대기 중** — 나오면 `.env`에서 `*_LOCAL_PATH` 줄들만
  지우면 코드 수정 없이 S3 모드로 전환됨
- **`resolve_ip_geo` 미구현** — 현재 `main.py`에서 `exclude`로 제외 중
  (`get_process_tree`는 2026-09-22부로 실제 구현 완료돼서 더 이상 제외 대상 아님)
- (완료) ~~`raw_log_ingestion.py`의 web/network 수집 미이전~~ — 2026-09-22에
  audit/auth와 동일한 패턴으로 정규화 함수로 교체 완료. 자체 파서(`parsers/` 폴더
  전체)는 더 이상 존재하지 않음(마지막 남은 `process_tree.py`도
  `get_process_tree.py` 안으로 합침). 자세한 내용은
  [통합 안내](docs/ABCD_TEST_GUIDE.md) 참고.
- **Confidence 산정 방식 4가지 결정사항** — 현재는 "LLM이 매 사이클
  `confidence_contribution`을 직접 산정 → 시스템이 누적 합산" 방식.
  종료 임계값은 `InvestigationAgent(confidence_threshold=...)`로 조절
- **Validator 재조사 훅** — 이번 개발 범위에서는 미구현
- **계층 간 연결 로직 실증 필요** — 원칙은 `agent/prompts.py`에 구현돼
  있으나, 단일 계층만으로 결론이 나는 샘플에서는 발동 여부가 확인되지 않음.
  여러 계층이 동시에 필요한 시나리오로 재검증 필요
