# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Agentic-SOC: LLM 기반 SOC(보안관제) 파이프라인을 만드는 팀 프로젝트. **완전히 다른 에이전트가 서로 다른 브랜치에 있고, 조사 에이전트만도 여러 브랜치에서 병렬로 발전 중이다** — 작업 전 반드시 `git branch --show-current`로 확인할 것.

- **1차 탐지 에이전트** (`main` / `feature/agent`): 루트 바로 아래 `agent/`, `tools/`만 있는 작은 코드베이스. Claude(Anthropic)로 Apache+auth 로그를 IP별로 집계해 `malicious_bot`/`benign_bot`/`human`/`undetermined`로 분류하고, 조사가 필요한 IP만 골라 조사 에이전트로 넘긴다.
- **조사 에이전트(Investigation Agent)** — 여러 브랜치에 존재:
  - `feature/agent-final` (**이 문서가 다루는 브랜치**, 현재 체크아웃 상태)
  - `feature/Agentic-SOC-Investigation-Agent` — 같은 `cb5005d`에서 갈라진 자매 브랜치. 2026-09-24 provenance/재현성 관련 추가 수정(raw_ref 미인용 시 신뢰도는 유지하되 provenance만 `incomplete` 표시, 같은 raw_ref 재인용 시 신뢰도 중복 반영 차단, auth 24시간 조회창을 프롬프트에 자동 주입하는 `auth_lookback_window`)이 이 브랜치에는 **없다** — `feature/agent-final`은 그 이전 단계의 더 단순한 규칙(raw_ref 미인용 시 신뢰도 기여를 그냥 0으로 만듦)을 쓴다. 두 브랜치 중 어느 쪽이 최신 "정답"인지는 코드만으로 판단하지 말고 확인 후 진행할 것.

세 브랜치는 폴더 구조와 세부 로직이 겹치지 않거나 미묘하게 다르므로, 한쪽에서 읽은 코드/동작 지식을 다른 쪽에 그대로 적용하면 안 된다.

## Commands (`feature/agent-final` 기준)

```bash
# 오프라인 검증 — API 키/AWS/.env 불필요
pip install -r requirements-dev.txt
python -m pytest -q                                 # 전체 오프라인 테스트
python -m pytest tests/test_loop.py::test_name       # 단일 테스트
python -m pytest -v tests/test_abcd_pipeline.py tests/test_cd_normalizer_integration.py tests/test_event_window.py tests/test_provenance.py  # A/B/C/D 연결만
python -m scripts.demo_abcd                          # 실제 도구를 연결한 A/B/C/D 데모 → results/abcd_demo.json
python -m scripts.demo_event_window                  # C/D 사건 조회 데모 → results/cd_demo.json
python -m scripts.verify_all_tools                   # 조사 도구 5개 + raw_log_ingestion 로컬 샘플 일괄 점검
python -m tests.test_normalizer_parity                # 1차 탐지팀 정규화 결과와 동일성(완료 기준) 검증

# 실제 LLM 실행
pip install -r requirements.txt
cp .env.example .env                                  # 키/경로 채워넣기 (Windows: Copy-Item .env.example .env)
python main.py                                         # 기본 Gemini. LLM_PROVIDER=anthropic 로 Claude 전환
python -m tests.test_consistency --runs 8              # 실제 API로 판정 재현성 반복 측정 (수동, 과금 발생)
```

주의: `pytest.ini`가 `tests/test_consistency.py`를 자동 실행에서 제외한다(실제 API 호출). `No module named agent`/`scripts` 에러가 나면 저장소 루트에서 `python -m ...` 형태로 실행했는지 확인한다.

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
`main.py`가 이 전체를 한 번에 실행한다. `agent/README.md`, 루트 `README.md`에 역할별 모듈 대응표가 있다(README.md는 세 브랜치에서 내용이 동일함을 확인함).

### 정규화(A) — `primary_detection/normalizer/`는 우리 코드가 아니다
1차 탐지팀이 만든 공통 정규화 코드가 이 저장소에 그대로 vendor(복사)되어 있다. **직접 수정 금지.** 조사 에이전트는 이걸 직접 import하지 않고 반드시 `agent/tools/normalizer_adapter.py`를 거친다 — 이게 유일한 연결 지점이다. `primary_detection/normalizer/vendor_sync_check.py`로 원본과 바이트 단위 동일성을 확인할 수 있다.

### Tool 계층 — `agent/tools/log_source.py` + `agent/tools/registry.py`
`agent/tools/log_source.py`가 정규화·시간창 필터링·필터 매칭을 전부 담당하는 공용 함수 `fetch_layer_logs(layer, args)`를 제공한다. `agent/tools/real/fetch_web_log.py`, `fetch_auth_log.py`, `fetch_network_log.py`는 이제 이 함수를 그대로 호출하는 **한 줄짜리 얇은 wrapper**다(예: `fetch_auth_log(args) -> fetch_layer_logs("auth", args)`). `fetch_audit_log.py`, `get_process_tree.py`, `fetch_event_logs.py`(C: 사건 시간 구간 조회)만 계층 고유 로직(프로세스 계보 추적, 다계층 동시 조회 등)이 더 있다.

`agent/tools/registry.py::build_default_registry()`가 7개 도구(`fetch_event_logs`, `fetch_web_log`, `fetch_auth_log`, `fetch_audit_log`, `fetch_network_log`, `get_process_tree`, `resolve_ip_geo`)를 등록한다. 각 도구의 실제 구현은 **파일명 = 함수명 = 도구명** 규칙으로 `agent/tools/real/<도구이름>.py`에 있으면 자동 탐색되고, 없으면 `mock_tools.py`의 목업으로 **에러 없이 조용히** 폴백한다. 새 도구를 연결한 뒤에는 반드시 `registry.get(name).handler`를 찍어 실제 함수가 붙었는지 확인해야 한다. `resolve_ip_geo`는 `main.py`에서 아직 `exclude`로 빠져 있다.

### 상태와 신뢰도 — `agent/models.py`, `agent/loop.py`
- `AgentState`가 facts/hypotheses/evidence/tool_calls/raw_refs를 누적한다. 동일 `(tool_name, args)` 재호출은 `already_called()`로 차단된다.
- `current_confidence`는 LLM이 각 evidence에 매긴 `confidence_contribution`을 루프가 직접 가감한다(반박 증거면 음수).
- **이 브랜치의 provenance 규칙(단순 버전)**: evidence에 `raw_ref`가 하나도 없으면 `confidence_contribution`을 무조건 0으로 만들고 `state.notes`에 기록한다 (`_apply_decision()` in `agent/loop.py`). 자매 브랜치(`feature/Agentic-SOC-Investigation-Agent`)에는 "raw_ref 없어도 기여는 반영하고 provenance만 incomplete로 표시", "같은 raw_ref 재인용은 중복 반영 차단" 같은 더 정교한 규칙이 추가돼 있는데 여기엔 없다 — 혼동하지 말 것.
- 종료 사유는 셋 중 하나: `confidence_sufficient`, `no_more_evidence`, `max_call_reached`.
- **종료 관문(게이트)**: `confidence_sufficient`로 끝내려 해도 (a) 실제 confidence가 threshold 미만이거나 (b) 서로 다른 도구를 1종류 이하만 썼거나 (c) seed에 src_ip가 있는데 `fetch_network_log`를 한 번도 안 썼으면 거부하고 계속 조사시킨다. 같은 사유로 연속 2회 거부되면 강제 종료 턴으로 전환한다. `no_more_evidence` 종료는 이 게이트를 거치지 않는다(의도적 설계).
- `max_call_reached` 시 도구 호출 없이 판정만 요청하는 마무리 턴을 1회 추가 실행하고, 그래도 `final_verdict`가 없으면 `_derive_fallback_verdict()`가 confidence 수치만으로 기계적 폴백 판정을 만든다.

### 원본 추적/Provenance (D) — `agent/provenance.py`
evidence의 `raw_refs`(예: `auth.log:15`, `s3://bucket/key:20`)는 `references()`/`validate_citations()`로 `state.raw_refs`(seed+도구 결과에서 실제 관측된 참조 집합)와 대조된다. 존재하지 않는 참조를 지어내면(`unknown_refs`) 기여가 0이 되고, 위치가 모호한 참조(`raw_ref_locations`에 항목이 2개 이상)도 0이 된다. 최종 보고서의 `provenance.status`(`passed`/`incomplete`/`unavailable`)는 "참조가 유효했는가"의 검증이지 "판정 문장이 사실인가"의 검증이 아니다.

### 프롬프트 — `agent/prompts/` (패키지), `agent/seed_prompts.py`
조사 루프 시스템 프롬프트의 내용은 `agent/prompts/investigation.yaml`에 있고 `agent/prompts/__init__.py`가 조립한다. 이 브랜치의 investigation.yaml에는 "원칙 7"에 SSH 브루트포스 판정 재현성을 위해 코드가 아니라 프롬프트 레벨에서 넣은 하한선 규칙이 있다(다수 시도+비밀번호 인증만으로도 일정 조건이면 THREAT_CONFIRMED로 확정). 프롬프트 내용을 바꿀 때는 이 규칙과 충돌하지 않는지 확인할 것. Seed 생성용 프롬프트(`seed_prompts.py`)는 별도 파일로 남아 있다.

### LLM 클라이언트 — `agent/gemini_client.py`, `agent/claude_client.py`
`GeminiClient`(기본값, 무료 티어)와 `ClaudeClient`는 동일 인터페이스(`.reason(state, tool_registry, ...)`, `.complete_json(...)`)라 `LLM_PROVIDER` 환경변수로 서로 교체 가능하다. 무료 Gemini 티어는 일일 요청 500회 제한과 간헐적 503(UNAVAILABLE)이 있다 — 코드 문제가 아니다.

### 로컬 개발용 우회
`.env`에 `<계층>_LOG_LOCAL_PATH`를 지정하면 S3 대신 `sample_logs/*.log`를 읽는다(값을 지우면 코드 수정 없이 S3 모드로 전환). 로컬 파일은 `LOG_LOCAL_HOST` 환경변수로만 host를 검증한다(`HOST`는 `main.py`의 수집 대상 이름일 뿐이고 이 검사엔 안 쓰인다 — 합성 시나리오 seed의 host와 충돌하지 않게 하기 위한 설계). 연도 없는 auth syslog 샘플을 쓰려면 `AUTH_LOG_YEAR`가 필요하다. `scenarios/`의 스크립트들은 `sample_logs/`에 공격 시나리오를 append해 재현성 테스트용 로그를 만든다 — **`sample_logs/`는 git으로 추적되므로 실험 후 반드시 `git checkout HEAD -- sample_logs`로 원복**해야 한다.

### 건드리지 않는 영역
- `primary_detection/normalizer/` — 1차 탐지팀 산출물 (위 참조)
- `backend/` — 기존 Flask 백엔드 자리. 에이전트 개발 범위에서는 미사용.
