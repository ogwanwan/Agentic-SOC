# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

공통 작업 규칙(동시 편집, Git 반영, 커밋 대상)은 [AGENTS.md](AGENTS.md)를 먼저 따른다. 이 파일은 코드 구조와 동작 설명이다.

## What this is

Agentic-SOC: LLM 기반 SOC(보안관제) 파이프라인을 만드는 팀 프로젝트. **완전히 다른 에이전트가 서로 다른 브랜치에 있고, 조사 에이전트만도 여러 브랜치에서 병렬로 발전 중이다** — 작업 전 반드시 `git branch --show-current`로 확인할 것.

- **1차 탐지 에이전트** (`main` / `feature/agent`, `feature/primary-detection`): Apache+auth 로그를 IP별로 집계해 `malicious_bot`/`benign_bot`/`human`/`undetermined`로 분류하고, 조사가 필요한 IP만 골라 조사 에이전트로 넘긴다. 공통 정규화(`primary_detection/normalizer`)의 원본이 여기 있다.
- **조사 에이전트(Investigation Agent)** — 여러 브랜치에 존재:
  - `feature/Agentic-SOC-Investigation-Agent` (**이 문서가 다루는 브랜치**). 개인 저장소의 `integrate-investigation`과 같은 내용으로 유지한다.
  - `feature/agent-final` — 같은 `cb5005d`에서 갈라진 자매 브랜치. 0924 이후의 provenance·재현성 수정(아래 "상태와 신뢰도", "종료 관문")이 **없다**. raw_ref 미인용 시 신뢰도 기여를 0으로 만드는 이전 규칙을 쓴다. 이 브랜치의 변경을 그쪽으로 자동 전파하지 않는다.

브랜치마다 폴더 구조와 세부 로직이 다르므로, 한쪽에서 읽은 코드/동작 지식을 다른 쪽에 그대로 적용하면 안 된다. 0918 이후 이 브랜치의 변경 이력과 검증 결과는 [docs/CHANGES_0918_TO_0924.md](docs/CHANGES_0918_TO_0924.md)에 있다.

## Commands

```bash
# 오프라인 검증 — API 키/AWS/.env 불필요
pip install -r requirements-dev.txt
python -m pytest -q                                 # 전체 오프라인 테스트
python -m pytest tests/test_loop.py::test_name       # 단일 테스트
python -m pytest -q tests/test_network_precheck.py   # 사전 조회·종료 관문·도구 집계
python -m scripts.demo_abcd                          # 실제 도구를 연결한 A/B/C/D 데모 → results/abcd_demo.json
python -m scripts.demo_event_window                  # C/D 사건 조회 데모 → results/cd_demo.json
python -m scripts.verify_all_tools                   # 조사 도구 + raw_log_ingestion 로컬 샘플 일괄 점검
python -m tests.test_normalizer_parity                # 1차 탐지팀 정규화 결과와 동일성 검증

# 실제 LLM 실행
pip install -r requirements.txt
cp .env.example .env                                  # 키/경로 채워넣기 (Windows: Copy-Item .env.example .env)
python main.py                                         # 기본 Gemini. LLM_PROVIDER=anthropic 로 Claude 전환
python -m tests.test_consistency --runs 8              # 실제 API로 판정 재현성 반복 측정 (수동, 과금 발생)
python -m tests.test_consistency --runs 4 --seed-json seed.json   # 임의 seed 파일로 반복 측정
python -m tests.test_consistency --runs 4 --legacy     # 0918 조건(사전 조회·강화 관문 없음)으로 비교
```

주의:
- `pytest.ini`가 `tests/test_consistency.py`를 자동 실행에서 제외한다(실제 API 호출).
- `No module named agent`/`scripts` 에러가 나면 저장소 루트에서 `python -m ...` 형태로 실행했는지 확인한다.
- `main.py`는 보고서만 콘솔에 출력하고, 원본 investigation_result JSON은 `results/<investigation_id>_<UTC시각>.json`에 저장한 뒤 파일명을 표시한다.
- EC2 운영 환경은 Python 3.10이다. 시각 파싱처럼 버전에 따라 동작이 다른 부분은 3.10에서 확인한다.

## Architecture

### 전체 흐름
```
raw log (S3 또는 로컬 샘플 파일)
  → agent/raw_log_ingestion.py        4계층(web/auth/audit/network) 정규화 수집
  → agent/seed_generation.py          경량 LLM triage로 "조사할 사건" 후보 + 우선순위 추출 (SeedGenerator)
  → agent/pipeline.py                 우선순위 순서로 각 seed를 조사 루프에 투입 (run_investigation_pipeline)
  → agent/loop.py                     ReAct 루프: 매 사이클 LLM 호출 1회로 facts/hypotheses/evidence
                                       갱신 + 다음 행동(call_tool | terminate) 동시 결정 (InvestigationAgent.run)
  → agent/report.py                   최종 investigation_result JSON + 텍스트 리포트
```
`main.py`가 이 전체를 한 번에 실행한다(`max_calls=8`, `confidence_threshold=0.85`, `network_precheck=True`, `strict_termination=True`). `pipeline`/`InvestigationAgent`의 두 플래그 기본값은 False라서, 데모(`demo_abcd`)와 기존 단위 테스트는 0918과 같은 느슨한 조건으로 돈다. 운영 동작을 확인할 때는 플래그를 켠 조건인지 확인할 것.

### 정규화(A) — `primary_detection/normalizer/`는 우리 코드가 아니다
1차 탐지팀이 만든 공통 정규화 코드가 이 저장소에 vendor(복사)되어 있다. **내용 수정 금지** — 갱신은 1차 탐지팀 원본을 그대로 다시 복사하는 방식으로만 한다. 조사 에이전트는 이걸 직접 import하지 않고 `agent/tools/normalizer_adapter.py`를 거친다. `primary_detection/normalizer/vendor_sync_check.py`로 원본과의 동일성을 확인한다.

### Tool 계층 (B) — `agent/tools/`
- `log_source.py`: 원본 읽기·정규화·시간창 필터(`load_window_events()`), 페이지네이션, 0건 안내(`filtered_out_hint()`) 같은 공용 부분.
- `real/fetch_web_log.py`, `fetch_auth_log.py`, `fetch_audit_log.py`, `fetch_network_log.py`: 각 도구가 **자기 필터·페이지네이션·summary를 직접 가진다**(0918 구조 복원). 한 줄짜리 `fetch_layer_logs()` 위임 구조로 되돌리지 않는다. 삭제된 `agent/tools/parsers/`도 복구하지 않는다.
- `real/fetch_event_logs.py`(C: 사건 시간 구간 다계층 조회), `real/get_process_tree.py`.

도구 반환값의 약속(LLM과 종료 관문이 의존함):
- `summary`에 `[조회 구간 전체 집계]`: limit으로 자른 페이지와 무관하게 조건에 맞는 전체 이벤트 기준으로 코드가 센 값(건수, 실제 기록 시각, 상위 항목). LLM이 records를 직접 세지 않게 하기 위한 것이다.
- `window_total`: 필터 전 조회 구간 전체 건수. 0이면 "활동 없음"이 아니라 로그 미확보다.
- `rule_checks`: 판정 원칙 기준을 코드가 계산한 결과. web은 `principle_9`(인증·XML-RPC POST 10회 이상, 경로 20개 이상+4xx 과반), audit은 `audit_post_exploitation`(웹 서버 계정의 의심 명령 실행). auth는 `rule_checks` 없이 summary의 SSH 실패 집계(횟수·대상 계정 수)로 원칙 7을 뒷받침한다.
- `fetch_network_log`의 `ip` 필터는 방향 무관(src·dest 모두 매칭)이다. 역방향 셸(서버 → 공격자)을 잡기 위해서다.
- audit의 `user` 필터는 **실행 계정**이다(sudo 뒤에는 root). 로그인 세션을 따라가려면 `ppid`를 쓴다.

`agent/tools/registry.py::build_default_registry()`가 7개 도구(`fetch_event_logs`, `fetch_web_log`, `fetch_auth_log`, `fetch_audit_log`, `fetch_network_log`, `get_process_tree`, `resolve_ip_geo`)를 등록한다. 실제 구현은 **파일명 = 함수명 = 도구명** 규칙으로 `agent/tools/real/<도구이름>.py`에서 자동 탐색되고, 없으면 `mock_tools.py`의 목업으로 **에러 없이 조용히** 폴백한다. 새 도구를 연결한 뒤에는 `registry.get(name).handler`로 실제 함수가 붙었는지 확인할 것. `resolve_ip_geo`는 `main.py`에서 `exclude`로 빠져 있다.

### 상태와 신뢰도 — `agent/models.py`, `agent/loop.py`
- `AgentState`가 facts/hypotheses/evidence/tool_calls/raw_refs를 누적한다. 동일 `(tool_name, args)` 재호출은 `already_called()`로 차단된다.
- `current_confidence`는 LLM이 각 evidence에 매긴 `confidence_contribution`을 루프가 직접 가감한다(반박 증거면 음수, 6자리 반올림).
- **이 브랜치의 provenance 규칙** (`_apply_decision()`):
  - raw_ref 누락·형식 오류 → 기여는 **반영**하고 provenance만 미완료로 기록.
  - 관측되지 않은 참조(`unknown_refs`), 위치가 모호한 참조 → 기여 0.
  - 이미 인용된 raw_ref만 다시 인용한 증거 → 기여 0(같은 사실 중복 반영 차단).
  - audit 다중 줄 이벤트는 raw_ref 하나만 인용해도 같은 이벤트의 나머지 줄이 자동으로 연결된다(`raw_ref_groups`).
- `update_confidence`가 반올림하는 이유: 0.6+0.25=0.8499…가 임계값 0.85에 미달로 거부되던 버그.

### 조사 루프와 종료 관문 — `agent/loop.py`
- **network 사전 조회** (`network_precheck=True`): seed에 src_ip가 있으면 첫 LLM 턴 전에 코드가 `fetch_network_log(ip=src_ip, seed 구간 ±30분, limit=20)`를 실행해 첫 관측으로 넣는다. LLM 호출 수는 늘지 않는다. 이 호출은 `state.system_call_sequences`에 기록되어 "LLM이 고른 도구 수"에서 빠진다.
- 종료 사유: `confidence_sufficient`, `no_more_evidence`, `max_call_reached`.
- **종료 관문** (`_termination_rejections()`, strict 조건은 `strict_termination=True`일 때):
  - (a) `confidence_sufficient`인데 실제 confidence가 threshold 미만
  - (b) LLM이 고른 서로 다른 도구가 1종류 이하
  - (c) seed에 src_ip가 있는데 network 조회를 한 번도 시도하지 않음(사전 조회 포함, 실패해도 시도로 인정)
  - (d) strict: `no_more_evidence`인데 도구를 1종류만 시도했고 안 본 로그 도구가 남음
  - (e) strict: seed src_ip의 로그인 성공(`ssh_accepted`)이 보이는데 audit을 시도하지 않음. 거부 사유에 `ppid=<sshd pid>`를 적어준다
  - 판정-원칙 충돌 (`_verdict_conflicts()`, strict): 조회한 모든 계층의 `window_total`이 0인데 INCONCLUSIVE가 아님 / 원칙 9 기준 충족인데 FALSE_POSITIVE / audit에 웹 서버 계정 의심 명령이 있는데 FALSE_POSITIVE이거나 severity가 HIGH 미만
  - 거부 사유에는 아직 안 본 도구와 확인 목적이 적힌다(`UNTRIED_TOOL_PURPOSE`).
- **강제 종료**: 같은 사유(숫자 제외 비교)로 연속 2회 거부될 때만 강제 종료 턴으로 전환한다. 거부 사이에 새 도구가 실행되면 횟수를 초기화한다. 강제 종료 후에도 판정-원칙 충돌이 남으면 판정은 바꾸지 않고 notes에 "⚠ 판정-원칙 불일치"를 남긴다.
- `max_call_reached` 시 판정만 요청하는 마무리 턴을 1회 추가하고, 그래도 `final_verdict`가 없으면 `_derive_fallback_verdict()`가 confidence 수치로 폴백 판정을 만든다.
- LLM 응답 해석 실패(`...DecisionError`)는 `_safe_reason()`이 1회 재시도하고, 또 실패하면 그 사건만 폴백 판정으로 마무리하고 다음 seed를 계속 조사한다. API 키·권한 오류는 그대로 올린다.

### 원본 추적/Provenance (D) — `agent/provenance.py`
evidence의 `raw_refs`(예: `auth.log:15`, `s3://bucket/key:20`)는 `references()`/`validate_citations()`로 `state.raw_refs`(seed+도구 결과에서 실제 관측된 참조 집합)와 대조된다. 최종 보고서의 `provenance.status`(`passed`/`incomplete`/`unavailable`)는 "참조가 유효했는가"의 검증이지 "판정이 맞는가"의 검증이 아니다. 텍스트 리포트는 Findings에 `[원본 N줄]`만 적고, 원본 위치는 맨 아래 `Raw References`에 범위로 묶어 보여준다(`compact_refs()`).

### 프롬프트 — `agent/prompts/` (패키지), `agent/seed_prompts.py`
조사 루프 시스템 프롬프트는 `agent/prompts/investigation.yaml`에 있고 `agent/prompts/__init__.py`가 조립한다(auth 24시간 조회창 `auth_lookback_window` 자동 주입 포함). 판정 재현성을 위한 원칙 중 코드 관문과 짝을 이루는 것:
- 원칙 1: 조회 구간 로그 자체가 0건이면 데이터 공백 → INCONCLUSIVE.
- 원칙 4: 사전 조회 결과 반영, 새 외부 IP가 나오면 network 재조회, 집계에 경보가 있는데 records에 없으면 `alert_only`로 재조회.
- 원칙 7: SSH 판정 하한선(실패 5회 이상 또는 계정 2개 이상 → 무차별 대입 시도로 THREAT_CONFIRMED 등), invalid user 1회 후 공개키 로그인은 정상.
- 원칙 9: 웹 요청 반복·스캔. User-Agent와 5xx/2xx 응답은 정상 근거가 아니다. 도구 summary의 `[원칙 9 기준]`과 audit `[후속 침해 확인]` 결과를 쓴다.

프롬프트의 판정 기준을 바꿀 때는 `fetch_*_log`의 `rule_checks` 계산과 `_verdict_conflicts()`를 함께 맞출 것 — 한쪽만 바꾸면 관문이 LLM의 판정을 계속 거부한다. Seed 생성용 프롬프트는 `seed_prompts.py`에 따로 있다.

### LLM 클라이언트 — `agent/gemini_client.py`, `agent/claude_client.py`
`GeminiClient`(기본값, 무료 티어)와 `ClaudeClient`는 동일 인터페이스(`.reason(state, tool_registry, ...)`, `.complete_json(...)`)라 `LLM_PROVIDER` 환경변수로 교체할 수 있다. Gemini는 `max_output_tokens=8192`이고, 503과 연결 오류(`OSError`, `httpx.TransportError`)를 5·10·15초 간격으로 재시도한다. 무료 티어의 일일 요청 제한(429)과 간헐적 503은 코드 문제가 아니다 — 반복 측정(`test_consistency`)은 한도를 고려해 나눠 돌린다.

### 로컬 개발용 우회
`.env`에 `<계층>_LOG_LOCAL_PATH`를 지정하면 S3 대신 `sample_logs/*.log`를 읽는다(값을 지우면 S3 모드). 로컬 파일은 `LOG_LOCAL_HOST` 환경변수로만 host를 검증한다(`HOST`는 `main.py`의 수집 대상 이름일 뿐이다 — 합성 시나리오 seed의 host와 충돌하지 않게 하기 위한 설계). 연도 없는 auth syslog 샘플에는 `AUTH_LOG_YEAR`가 필요하다. `scenarios/`의 스크립트들은 `sample_logs/`에 공격 시나리오를 append한다 — **`sample_logs/`는 git으로 추적되므로 실험 후 반드시 `git checkout HEAD -- sample_logs`로 원복**해야 한다.

### 건드리지 않는 영역
- `primary_detection/normalizer/` — 1차 탐지팀 산출물 (위 참조)
- `backend/` — 기존 Flask 백엔드 자리. 에이전트 개발 범위에서는 미사용.
