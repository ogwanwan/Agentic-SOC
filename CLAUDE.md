# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

공통 작업 규칙(동시 편집, Git 반영, 커밋 대상)은 [AGENTS.md](AGENTS.md)를 먼저 따른다. 이 파일은 코드 구조와 동작 설명이다.

## What this is

Agentic-SOC: LLM 기반 SOC(보안관제) 파이프라인을 만드는 팀 프로젝트. **완전히 다른 에이전트가 서로 다른 브랜치에 있고, 조사 에이전트만도 여러 브랜치에서 병렬로 발전 중이다** — 작업 전 반드시 `git branch --show-current`로 확인할 것.

- **1차 탐지 에이전트** (`main` / `feature/agent`, `feature/primary-detection`): Apache+auth 로그를 IP별로 집계해 `malicious_bot`/`benign_bot`/`human`/`undetermined`로 분류하고, 조사가 필요한 IP만 골라 조사 에이전트로 넘긴다. 공통 정규화(`primary_detection/normalizer`)의 원본이 여기 있다.
- **조사 에이전트 + ATT&CK 매핑 통합** — 개인 저장소 `integrate-attack-mapping-rag` (**이 문서가 다루는 브랜치**, 2026-09-28~). 조사 에이전트 최신(`integrate-investigation` = 팀 `feature/Agentic-SOC-Investigation-Agent`, `051dda7`) 위에 `d802dbb`에서 지운 ATT&CK 매핑(`attack_mapping/`, `reporting/`, 매핑 테스트·문서)을 `a1e60ce`에서 되살리고, `main.py`에 매핑 연결을 다시 붙이고, RAG 전환 담당 A 작업을 올렸다. 조사 코드 수정은 조사 브랜치에서 하고 이 브랜치로 merge해 온다(`d802dbb`의 삭제는 이미 이 브랜치 이력에 있어서 그 뒤 조사 커밋을 merge해도 매핑 파일이 지워지지 않는다). 개인 저장소에만 올리고 팀 저장소에는 반영하지 않는다. 옛 팀 브랜치 `feature/investigation-attack-mapping`(`a1e60ce`)은 그대로 둔다.
- **조사 에이전트(Investigation Agent)** — 여러 브랜치에 존재:
  - `feature/Agentic-SOC-Investigation-Agent` (조사 에이전트 단독 기준). 개인 저장소의 `integrate-investigation`과 같은 내용으로 유지한다. `d802dbb`에서 ATT&CK 매핑을 지웠으므로 이 브랜치를 그대로 받아(fast-forward) 매핑 브랜치에 덮지 않는다.
  - `feature/agent-final` — 같은 `cb5005d`에서 갈라진 자매 브랜치. 0924 이후의 provenance·재현성 수정(아래 "상태와 신뢰도", "종료 관문")이 **없다**. raw_ref 미인용 시 신뢰도 기여를 0으로 만드는 이전 규칙을 쓴다. 이 브랜치의 변경을 그쪽으로 자동 전파하지 않는다.

브랜치마다 폴더 구조와 세부 로직이 다르므로, 한쪽에서 읽은 코드/동작 지식을 다른 쪽에 그대로 적용하면 안 된다. 0918 이후 이 브랜치의 변경 이력과 검증 결과는 [docs/CHANGES_0918_TO_0925.md](docs/CHANGES_0918_TO_0925.md)에 있다.

이 브랜치는 **개인 저장소(`zhrldnpftl/WHS4-Agentic-SOC-Investigation-Agent`) 기준으로만** 작업한다. 팀 저장소(`ogwanwan/Agentic-SOC`)는 다른 팀원이 쓰고 있어 건드리지 않는다. 개인 저장소의 `integrate-attack-mapping`(`a1e60ce`)은 0927 작업물로 따로 남겨 두고 이 브랜치와 합치지 않는다.
Git 원격 이름은 작업 폴더마다 다르다(조사 폴더: `origin` = 개인 저장소, `upstream` = 팀 저장소 / 매핑 통합 폴더: `origin` = 개인 저장소, `team` = 팀 저장소). push 전에 `git remote -v`로 확인할 것. 어느 폴더든 팀 저장소 push 주소는 `DISABLED`로 막아 두고, 사용자가 팀 저장소 push를 요청할 때만 잠깐 복구했다가 다시 막는다.

## Commands

```bash
# 오프라인 검증 — API 키/AWS/.env 불필요
pip install -r requirements.txt                      # 테스트용 pytest 포함 (requirements-dev.txt는 합쳐짐)
python -m pytest -q                                 # 전체 오프라인 테스트
python -m pytest tests/test_loop.py::test_name       # 단일 테스트
python -m pytest -q tests/test_network_precheck.py   # 사전 조회·종료 관문·도구 집계
python -m scripts.demo_abcd                          # 실제 도구를 연결한 A/B/C/D 데모 → results/investigation_agent/abcd_demo.json
python -m scripts.demo_event_window                  # C/D 사건 조회 데모 → results/investigation_agent/cd_demo.json
python -m scripts.verify_all_tools                   # 조사 도구 로컬 샘플 일괄 점검
python -m tests.test_normalizer_parity                # 1차 탐지팀 정규화 결과와 동일성 검증
python -m attack_mapping.cli results/investigation_agent/<파일>.json   # 저장된 조사 결과만 다시 ATT&CK 매핑 (--all-in-dir results/investigation_agent 로 일괄)
python -m scripts.verify_attack_mapping_abc           # 어택 매핑 A/B/C(Rule) 통합 검증 → results/attack_mapping_abc_<시각>/
python -m scripts.fetch_attack_catalog                # 공식 ATT&CK STIX(git 미추적, 54MB)를 manifest 버전·sha256대로 받기 (--verify: 네트워크 없이 확인)

# 실제 LLM 실행
cp .env.example .env                                  # 키/경로 채워넣기 (Windows: Copy-Item .env.example .env)
python main.py <사건 파일>                             # 기본 Gemini. LLM_PROVIDER=anthropic 로 Claude 전환. 사건 파일 = 1차 탐지 Incident JSONL 또는 사건 JSON
python -m tests.test_consistency --runs 8              # 실제 API로 판정 재현성 반복 측정 (수동, 과금 발생)
python -m tests.test_consistency --runs 4 --seed-json seed.json   # 임의 seed 파일로 반복 측정
python -m tests.test_consistency --runs 4 --legacy     # 0918 조건(사전 조회·강화 관문 없음)으로 비교
```

주의:
- `pytest.ini`가 `tests/test_consistency.py`를 자동 실행에서 제외한다(실제 API 호출).
- `No module named agent`/`scripts` 에러가 나면 저장소 루트에서 `python -m ...` 형태로 실행했는지 확인한다.
- `main.py`는 보고서를 콘솔에 출력하지 않는다. investigation_result JSON을 `results/investigation_agent/<investigation_id>_<UTC시각>.json`에 저장하고, 저장 직후 그 파일로 ATT&CK 매핑을 돌려 `results/attack_mapping/<incident_id>_attack_mapping.json`·`_final_report.json`을 만든다(같은 사건 재조사는 `__2`, `__3` …). 콘솔에는 저장 경로와 사건별 매핑 상태 한 줄만 표시한다.
- EC2 운영 환경은 Python 3.10이다. 시각 파싱처럼 버전에 따라 동작이 다른 부분은 3.10에서 확인한다.

## Architecture

### 전체 흐름
```
사건 파일 (1차 탐지 Incident JSONL 또는 직접 작성한 사건 JSON) — main.py <사건 파일>
  → agent/incident_input.py           load_incidents() 읽기, to_investigation_seed()로 조사 루프 입력(src_ip·window·
                                       trigger_time·evidence_refs·detection 요약)으로 변환
  → agent/pipeline.py                 받은 순서대로 각 사건을 조사 루프에 투입 (run_investigation_pipeline)
  → agent/loop.py                     ReAct 루프: 매 사이클 LLM 호출 1회로 facts/hypotheses/evidence
                                       갱신 + 다음 행동(call_tool | terminate) 동시 결정 (InvestigationAgent.run)
  → agent/report.py                   최종 investigation_result JSON (main.py가 results/investigation_agent/에 저장)
  → main.run_attack_mapping()          [46] 저장된 JSON 파일 → attack_mapping/cli.py process_file()
                                       (엔진 + rules/ ALL_RULES + killchain → reporting/final_report.py)
```
코드 주석의 `[1]`~`[45]` 흐름 번호와 단계별 설명은 [docs/AGENT_FLOW.md](docs/AGENT_FLOW.md)에 있다(`[7]`~`[15]`는 삭제된 수집·seed 생성 단계라 비어 있음). `[46]` 매핑 연결과 매핑 내부 흐름은 [docs/AGENT_ATTACK_MAPPING_FLOW.md](docs/AGENT_ATTACK_MAPPING_FLOW.md) 맨 아래 "0928 기록"에 있다(본문은 0927 기준). `main.py`가 이 전체를 한 번에 실행한다(`max_calls=8`, `confidence_threshold=0.85`, `network_precheck=True`, `strict_termination=True`). `pipeline`/`InvestigationAgent`의 두 플래그 기본값은 False라서, 데모(`demo_abcd`)와 기존 단위 테스트는 0918과 같은 느슨한 조건으로 돈다. 운영 동작을 확인할 때는 플래그를 켠 조건인지 확인할 것.

### 정규화(A) — `primary_detection/normalizer/`는 우리 코드가 아니다
1차 탐지팀이 만든 공통 정규화 코드가 이 저장소에 vendor(복사)되어 있다. **내용 수정 금지** — 갱신은 1차 탐지팀 원본을 그대로 다시 복사하는 방식으로만 한다. 조사 에이전트는 이걸 직접 import하지 않고 `agent/tools/normalizer_adapter.py`를 거친다. `primary_detection/normalizer/vendor_sync_check.py`로 원본과의 동일성을 확인한다.

### Tool 계층 (B) — `agent/tools/`
- `log_source.py`: 원본 읽기·정규화·시간창 필터(`load_window_events()`), 페이지네이션, 0건 안내(`filtered_out_hint()`) 같은 공용 부분.
- `real/fetch_web_log.py`, `fetch_auth_log.py`, `fetch_audit_log.py`, `fetch_network_log.py`: 각 도구가 **자기 필터·페이지네이션·summary를 직접 가진다**(0918 구조 복원). 한 줄짜리 `fetch_layer_logs()` 위임 구조로 되돌리지 않는다. 삭제된 `agent/tools/parsers/`도 복구하지 않는다.
- `real/fetch_event_logs.py`(C: 사건 시간 구간 다계층 조회), `real/get_process_tree.py`.

도구 반환값의 약속(LLM과 종료 관문이 의존함):
- `summary`에 `[조회 구간 전체 집계]`: limit으로 자른 페이지와 무관하게 조건에 맞는 전체 이벤트 기준으로 코드가 센 값(건수, 실제 기록 시각, 상위 항목). LLM이 records를 직접 세지 않게 하기 위한 것이다.
- `window_total`: 필터 전 조회 구간 전체 건수. 0이면 "활동 없음"이 아니라 로그 미확보다.
- `rule_checks`: 판정 원칙 기준을 코드가 계산한 결과. web은 `principle_9`(인증·XML-RPC POST 10회 이상, 경로 20개 이상+4xx 과반), audit은 `audit_post_exploitation`(웹 서버 계정의 셸·의심 명령 실행, cron `sh -c`·EC2 Instance Connect 제외), auth는 `principle_7`(IP 하나로 거르고 로그인 성공이 없을 때: 실패 5회 이상 또는 계정 2개 이상 → 무차별 대입, 1~4회·1계정 → 단발성, 실패 0회·`ssh_probe` 1~4건 → 스캐너 탐침).
- `fetch_network_log`의 `ip` 필터는 방향 무관(src·dest 모두 매칭)이다. 역방향 셸(서버 → 공격자)을 잡기 위해서다. `ip`/`src_ip`/`dst_ip`에 IP가 아닌 값(도메인)이 오면 `ValueError`로 알린다(조용한 0건 방지, 실패 호출로 LLM에게 전달).
- audit의 `user` 필터는 **실행 계정**이다(sudo 뒤에는 root). 로그인 세션을 따라가려면 `ppid`를 쓴다.

`agent/tools/registry.py::build_default_registry()`가 7개 도구(`fetch_event_logs`, `fetch_web_log`, `fetch_auth_log`, `fetch_audit_log`, `fetch_network_log`, `get_process_tree`, `resolve_ip_geo`)를 등록한다. 실제 구현은 **파일명 = 함수명 = 도구명** 규칙으로 `agent/tools/real/<도구이름>.py`에서 자동 탐색되고, 없으면 `mock_tools.py`의 목업으로 **에러 없이 조용히** 폴백한다. 새 도구를 연결한 뒤에는 `registry.get(name).handler`로 실제 함수가 붙었는지 확인할 것. `resolve_ip_geo`는 `main.py`에서 `exclude`로 빠져 있다.

### 상태와 신뢰도 — `agent/models.py`, `agent/loop.py`
- `AgentState`가 facts/hypotheses/evidence/tool_calls/raw_refs를 누적한다. 동일 `(tool_name, args)` 재호출은 `already_called()`로 차단된다.
- `current_confidence`는 LLM이 각 evidence에 매긴 `confidence_contribution`을 루프가 직접 가감한다(반박 증거면 음수, 6자리 반올림).
- **이 브랜치의 provenance 규칙** (`_apply_decision()`):
  - raw_ref 누락·형식 오류 → 기여는 **반영**하고 provenance만 미완료로 기록.
  - 관측되지 않은 참조(`unknown_refs`), 위치가 모호한 참조 → 기여 0.
  - 이미 인용된 raw_ref만 다시 인용한 증거 → 기여 0(같은 사실 중복 반영 차단).
  - "조회 0건 → 활동 없음" 증거는 LLM이 `empty_result_call`에 도구 호출 sequence를 적고, `_verified_empty_call()`이 그 호출이 성공한 0건이면 원본 누락으로 세지 않는다(`provenance.empty_result_evidence`). 확인 실패(없는 번호·실패한 호출·결과가 있던 호출)는 누락으로 세고 **기여 0**, `provenance.issues`에 `unverified_empty_result_call` 기록 — 호출하지 않은 fetch_auth_log의 "0건"을 없는 번호로 인용해 임계값을 채운 실제 사례(0927) 때문. 번호를 아예 안 적은 경우는 raw_ref 누락처럼 기여 반영. LLM이 인용할 수 있게 `pending_observations`에 `sequence`를 넣는다.
  - audit 다중 줄 이벤트는 raw_ref 하나만 인용해도 같은 이벤트의 나머지 줄이 자동으로 연결된다(`raw_ref_groups`).
- `update_confidence`가 반올림하는 이유: 0.6+0.25=0.8499…가 임계값 0.85에 미달로 거부되던 버그.

### 조사 루프와 종료 관문 — `agent/loop.py`
- **network 사전 조회** (`network_precheck=True`): seed에 src_ip가 있으면 첫 LLM 턴 전에 코드가 `fetch_network_log(ip=src_ip, seed 구간 ±30분, limit=20)`를 실행해 첫 관측으로 넣는다. LLM 호출 수는 늘지 않는다. 이 호출은 `state.system_call_sequences`에 기록되어 "LLM이 고른 도구 수"에서 빠진다.
- 종료 사유: `confidence_sufficient`, `no_more_evidence`, `max_call_reached`.
- **종료 관문** (`_termination_rejections()`, strict 조건은 `strict_termination=True`일 때):
  - (a) `confidence_sufficient`인데 실제 confidence가 threshold 미만 — 단, 판정이 도구 기준으로 정해지는 판정(`_rule_determined_verdict()`)과 같으면 면제
  - (b) LLM이 고른 서로 다른 도구가 1종류 이하
  - (c) seed에 src_ip가 있는데 network 조회를 한 번도 시도하지 않음(사전 조회 포함, 실패해도 시도로 인정)
  - (d) strict: `no_more_evidence`인데 도구를 1종류만 시도했고 안 본 로그 도구가 남음
  - (e) strict: seed src_ip의 로그인 성공(`ssh_accepted`)이 보이는데 audit을 시도하지 않음. 거부 사유에 `ppid=<sshd pid>`를 적어준다
  - (f) strict: audit 명령 인자에 나온 공인 IP를 network로 조회하지 않음
  - (g) strict: 증거가 인용한 1차 탐지 참조(`detection.rules[].evidence_refs`)를 도구 결과에서 관측하지 않았고 그 계층(system = audit)을 도구로 한 번도 조회하지 않음(`_unverified_detection_refs()`). 조회 시도만 해도 인정. 계층을 알 수 없는 참조(직접 작성한 사건)는 보지 않는다. 1차 탐지 Incident 첫 실제 실행에서 LLM이 detection의 명령 인자를 그대로 증거로 옮겨 audit 없이 확정한 사례 때문
  - (h) strict: 1차 탐지 룰(`detection.rules`) 중 탐지 근거 참조를 도구 결과에서 하나도 관측하지 못했고 `unknowns`에 룰 이름·참조도 없는 것이 있음(`_unverified_detection_rules()`). 사유에 룰 이름·계층·pid/ppid 안내. (g) 수정 뒤 재실행에서 sudo 자식인 useradd(계정 생성) 룰 2개를 확인하지 않고 끝낸 사례 때문
  - 판정-원칙 충돌 (`_verdict_conflicts()`, strict): 조회한 모든 계층의 `window_total`이 0인데 INCONCLUSIVE가 아님 / 원칙 9 기준 충족인데 FALSE_POSITIVE / audit에 웹 서버 계정 의심 명령이 있는데 FALSE_POSITIVE이거나 severity가 HIGH 미만 / 원칙 7 무차별 대입인데 FALSE_POSITIVE·INCONCLUSIVE / 원칙 7 단발성·탐침이고 다른 위협 기준이 없는데 THREAT_CONFIRMED·INCONCLUSIVE
  - 거부 사유에는 아직 안 본 도구와 확인 목적이 적힌다(`UNTRIED_TOOL_PURPOSE`).
- **강제 종료**: 같은 사유(숫자 제외 비교)로 연속 2회 거부될 때만 강제 종료 턴으로 전환한다. 거부 사이에 새 도구가 실행되면 횟수를 초기화한다. 강제 종료 턴에서 LLM이 원칙과 어긋나게 판정을 뒤집으면 앞서 LLM이 낸 원칙에 맞는 판정을 쓴다(`_settle_forced_verdict()`). 그래도 충돌이 남으면 판정은 바꾸지 않고 notes에 "⚠ 판정-원칙 불일치"를 남긴다.
- `max_call_reached` 시 판정만 요청하는 마무리 턴을 1회 추가하고, 그래도 `final_verdict`가 없으면 `_derive_fallback_verdict()`가 confidence 수치로 폴백 판정을 만든다.
- LLM 응답 해석 실패(`...DecisionError`)는 `_safe_reason()`이 1회 재시도하고, 또 실패하면 그 사건만 폴백 판정으로 마무리하고 다음 seed를 계속 조사한다. API 키·권한 오류는 그대로 올린다.

### 원본 추적/Provenance (D) — `agent/provenance.py`
evidence의 `raw_refs`(예: `auth.log:15`)는 `references()`/`validate_citations()`로 `state.raw_refs`(seed+도구 결과에서 실제 관측된 참조 집합)와 대조된다. 최종 보고서의 `provenance.status`(`passed`/`incomplete`/`unavailable`)는 "참조가 유효했는가"의 검증이지 "판정이 맞는가"의 검증이 아니다. 증거마다 코드가 계산한 `supporting_tool_calls`(그 raw_refs를 관측한 도구 호출 sequence, 0건 증거는 `empty_result_call`)와 `seed_only_raw_refs`(1차 탐지 참조 중 어떤 도구 결과에서도 관측되지 않은 것)가 붙고, `provenance.seed_only_evidence`에 해당 증거 id가 모인다(`evidence_ref_sources()`). seed 참조도 실제 원본 줄이라 status에는 반영하지 않는다 — ATT&CK 매핑이 "도구로 재확인되지 않은 증거"를 표시하는 데 쓴다(매핑 담당용 안내: [docs/EVIDENCE_REF_SOURCES.md](docs/EVIDENCE_REF_SOURCES.md)). 사람이 읽는 텍스트 보고서는 만들지 않는다(0927 제거) — 최종 보고서는 이후 단계(ATT&CK 매핑·대응 권고) 결과까지 합쳐 따로 만든다.

### 사건 입력 — `agent/incident_input.py`
사건을 찾고 고르는 일(로그 수집·Sigma 탐지·사건 묶기·triage)은 1차 탐지(팀 저장소 `develop`의 `run_pipeline.py`)가 한다. 0927에 조사 에이전트 자체의 로그 수집(`raw_log_ingestion.py`)과 LLM seed 생성(`seed_generation.py`, `seed_prompts.py`)을 삭제했다.
- `to_investigation_seed()`는 1차 탐지 필드 중 바뀔 가능성이 적은 것(`incident_id`, `entity`, `window`, `layers`, `seeds[]`의 `reason`·`evidence_refs`·`rule_severity`·`detail`)만 쓴다. `triage_score`·`priority`·`route`·`llm_investigate`는 사건을 고르는 값이라 보지 않고, `llm_reason`은 있으면 넘긴다. `incident_key`(사건이 커져도 안 바뀌는 안정 키)·`updated_at`도 있으면 넘기고, 결과 JSON 최상위 `incident_key`(없으면 null)와 `incident_snapshot {incident_id, member_count, updated_at}`으로 옮겨진다 — ATT&CK 매핑·최종 보고서는 `incident_key`(null이면 `incident_id`)로 사건을 잇는다. `entity`·`seeds`가 없는 dict(직접 작성한 사건, `test_consistency --seed-json`)는 그대로 쓴다.
- `members`(최대 500개)·`join_path` 원본은 프롬프트에 사건 dict가 통째로 들어가므로 싣지 않고 `detection` 요약만 싣는다.
- 1차 탐지 Incident에는 host가 없어 `.env`의 `HOST`로 채운다. 조사 루프 안에서는 이 dict를 계속 `seed`라고 부른다(1차 탐지의 `seeds[]` = 탐지 룰 결과와 다른 뜻).
- 테스트 고정 데이터 `tests/fixtures/primary_detection_incidents.jsonl`은 1차 탐지 `develop`(`e9b733c`)을 그쪽 샘플 로그(= `primary_detection/normalizer/samples/`)로 실행한 실제 출력이다. 1차 탐지 출력 형식이 바뀌면 다시 만들 것.
- 조사 대상 선택·순서·조사 상태 관리(DB 또는 파일)는 1차 탐지와 통합할 때 정한다. 지금은 파일의 모든 사건을 적힌 순서대로 조사한다.

### 프롬프트 — `agent/prompts/` (패키지)
조사 루프 시스템 프롬프트는 `agent/prompts/investigation.yaml`에 있고 `agent/prompts/__init__.py`가 조립한다(계층별 첫 조회 구간 `query_windows`와 auth 24시간 조회창 `auth_lookback_window`를 코드가 계산해 주입). 판정 재현성을 위한 원칙 중 코드 관문과 짝을 이루는 것:
- 원칙 1: 조회 구간 로그 자체가 0건이면 데이터 공백 → INCONCLUSIVE.
- 원칙 4: 사전 조회 결과 반영, 새 외부 IP가 나오면 network 재조회, 집계에 경보가 있는데 records에 없으면 `alert_only`로 재조회.
- 원칙 2: 각 계층 첫 조회는 `query_windows` 구간 그대로(web 앞뒤 1시간, audit 30분 전~1시간 후, network 앞뒤 30분, auth 24시간 전~1시간 후). audit 넓은 구간 무필터 조회 금지.
- 원칙 7: SSH 판정 기준(도구 summary의 `[원칙 7 기준]`을 따름), invalid user 1회 후 공개키 로그인은 정상.
- 원칙 9: 웹 요청 반복·스캔. User-Agent와 5xx/2xx 응답은 정상 근거가 아니다. 도구 summary의 `[원칙 9 기준]`과 audit `[후속 침해 확인]` 결과를 쓴다.

프롬프트의 판정 기준을 바꿀 때는 `fetch_*_log`의 `rule_checks` 계산과 `_verdict_conflicts()`를 함께 맞출 것 — 한쪽만 바꾸면 관문이 LLM의 판정을 계속 거부한다.

### LLM 클라이언트 — `agent/gemini_client.py`, `agent/claude_client.py`
`GeminiClient`(기본값, 무료 티어)와 `ClaudeClient`는 같은 인터페이스(`.reason(state, tool_registry, confidence_threshold, force_terminate, gate_rejection_reason)`, `.complete_json()`)·같은 설정(출력 8192, temperature 0)이라 `LLM_PROVIDER` 환경변수로 교체한다. Claude는 `CLAUDE_MODEL`(기본 `claude-sonnet-5`), SDK `max_retries`로 429·529·연결 오류 재시도, 시스템 프롬프트 캐시 표시, `usage_totals`에 토큰 누적(오프라인 테스트 `tests/test_claude_client.py`, 실제 API 재현성은 미검증). Gemini는 `max_output_tokens=8192`이고, 503과 연결 오류(`OSError`, `httpx.TransportError`)를 5·10·15초 간격으로 재시도한다. 무료 티어의 일일 요청 제한(429)과 간헐적 503은 코드 문제가 아니다 — 반복 측정(`test_consistency`)은 한도를 고려해 나눠 돌린다.

### 로컬 개발용 우회
로그는 `.env`의 계층별 로그 경로(`APACHE/AUTH/AUDIT/SURICATA_LOG_PATH` — 1차 탐지와 같은 이름, 0927에 `*_LOG_LOCAL_PATH`에서 변경, `log_source.LOCAL_PATH_ENV`) 파일에서만 읽는다(S3 읽기 코드는 삭제됨, 경로가 없으면 설정 오류). 로컬 개발은 이 경로를 `sample_logs/*.log`로 둔다. 로컬 파일은 `LOG_LOCAL_HOST` 환경변수로만 host를 검증한다(`HOST`는 `main.py`의 수집 대상 이름일 뿐이다 — 합성 시나리오 seed의 host와 충돌하지 않게 하기 위한 설계). 연도 없는 auth syslog 샘플에는 `AUTH_LOG_YEAR`가 필요하다. `scenarios/`의 스크립트들은 `sample_logs/`에 공격 시나리오를 append한다. `sample_logs/`는 EC2 실제 트래픽이 들어 있어 **git으로 추적하지 않는다**(`.gitignore`) — 실험 전에 `sample_logs_orig/`로 백업해 두고 실험 후 그 백업으로 원복한다(`scenarios/README.md`). 새로 clone한 저장소에는 샘플이 없으니 `scripts/fetch_sample_from_ec2.py`로 받거나 팀원에게 받는다.

### ATT&CK 매핑 — `attack_mapping/`, `reporting/` (어택 매핑 팀 코드)
작업 전에 [docs/ATTACK_MAPPING_RAG_ABC_COLLABORATION.md](docs/ATTACK_MAPPING_RAG_ABC_COLLABORATION.md)(RAG 전환과 담당 A·B·C 협업 규칙)를 먼저 읽는다.
- 지금 `main.py`가 쓰는 것은 LLM을 부르지 않는 **Rule 매핑**이다: `final_verdict.attack_type`과 `evidence_chain`의 `description`/`event_type`을 `attack_mapping/rules/`의 키워드와 비교한다. 따라서 LLM이 쓴 문장 표현이 매핑 결과를 좌우한다.
- 게이트: FALSE_POSITIVE → `not_applicable`, INCONCLUSIVE 또는 provenance `unavailable` → `deferred`, provenance `incomplete` → `evidence_without_raw_refs`·`ambiguous_raw_refs`·`issues`에 걸린 증거를 빼고 verdict 매칭도 끈 `partial`.
- 연결은 `main.py`의 `run_attack_mapping()`만 한다. 메모리 dict가 아니라 **저장된 파일 경로**를 넘겨 CLI 재실행과 결과를 같게 하고, 매핑 예외(OSError/ValueError/RecursionError)는 출력만 하고 다음 사건으로 넘어간다. `agent/`는 `attack_mapping/`을 import하지 않는다.
- `reporting/`은 최상위에 둔다: 이후 대응(Response) 단계 결과까지 합칠 최종 보고서 자리라서 `attack_mapping/` 아래에 두면 의존 방향이 꼬인다.
- `report.py`의 결과 JSON 필드(evidence_chain의 `evidence_id`·`sequence`·`time`·`raw_refs`·`seed_only_raw_refs`, `provenance`, `raw_ref_locations`, `final_verdict.attack_type`, 최상위 `incident_key`)를 바꾸면 매핑 입력 검증에 걸린다. `tests/test_main_attack_mapping.py`, `tests/test_attack_mapping_engine.py::test_actual_investigation_report_contract`, `tests/test_attack_validate.py::test_real_investigation_result_seed_only_contract`로 확인할 것. 사건 연결 키는 최상위 `incident_key`, `null`이면 `incident_id`.
- RAG 전환(진행 중): 담당 A의 `catalog.py`(공식 STIX 19.2, `data/attack/manifest.json`으로 버전·sha256 고정), `validate.py`(사건 관문·증거 target/context/excluded 분류·LLM 선택 검증), `schema.py`의 RAG 자료형이 있다. B(`retrieve.py`)·C(`mapper.py`)는 아직 없다. ATT&CK v19는 `Defense Evasion`이 `Stealth`로 바뀌고 `Defense Impairment`가 생겨 규칙용 `TACTIC_ORDER`와 공식 순서(`catalog.tactic_order`)가 다르다. 계약과 팀 합의 사항은 [docs/ATTACK_MAPPING_A_CATALOG_VALIDATION_20260928.md](docs/ATTACK_MAPPING_A_CATALOG_VALIDATION_20260928.md).

### 건드리지 않는 영역
- `primary_detection/normalizer/` — 1차 탐지팀 산출물 (위 참조)
- `attack_mapping/`, `reporting/` — 어택 매핑 팀 산출물. 담당 A·B·C 경계는 [RAG A·B·C 협업 문서](docs/ATTACK_MAPPING_RAG_ABC_COLLABORATION.md)를 따른다
