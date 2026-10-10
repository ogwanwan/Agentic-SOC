# Agentic SOC

서버 로그를 자동으로 지켜보며 공격을 탐지하고, 조사·판정부터 대응 권고까지 이어서 처리하는 **Agent 기반 보안관제(SOC) 시스템**.

보통 보안관제는 쏟아지는 경보를 사람이 하나하나 열어 "진짜 공격인가"를 판단해야 한다. Agentic SOC는 이 일을 자동화한다 — 수만 줄 로그 속에서 공격 흔적을 찾아 사건으로 묶고, **AI 에이전트가 분석가처럼 원본 로그를 다시 뒤져 위협 여부를 판정**한 뒤, 필요한 조치까지 권고한다. 판정은 지어내지 않고 **실제 로그를 근거로** 하므로, "왜 이렇게 판단했는지"를 로그 줄까지 되짚을 수 있다.

```text
로그 4종 ─▶ [탐지] 정규화→탐지→사건묶기→트리아지 ──큐(soc.db)──▶ [조사] LLM 판정 ─▶ [ATT&CK 매핑] ─▶ [대응 권고] ─▶ 대시보드
            (결정론 · 5분 자동)                                    (큐 폴러 · LLM)
```

탐지와 조사는 **별도 프로세스**이고 **DB 큐로만 연결**된다. 탐지는 빠르게 큐를 채우고, 조사는 LLM이라 느리므로 큐에서 자기 속도로 꺼내 처리한다.

📌 링크된 세부 문서는 **`develop` 브랜치**에 있다(`main` 은 코드만 포함)

---

## 준비 · 실행 · 테스트

Python 3.10 이상, 저장소 루트 기준.

```bash
# 준비
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt                       # 탐지·트리아지
cp .env.example .env                                  # 아래 형태로 채우기 (.env 는 커밋 금지)
```

`.env` 는 아래 형태로 채운다(전체 변수는 [.env.example](.env.example) 참고).

```dotenv
# ── 로그 경로 (실 배포 기준 예시) ─────────────────
APACHE_LOG_PATH=/var/log/apache2/access.log
AUTH_LOG_PATH=/var/log/auth.log
AUDIT_LOG_PATH=/var/log/audit/audit.log
SURICATA_LOG_PATH=/var/log/suricata/eve.json
SERVER_PUBLIC_IP="서버 공인 IP"                #자기호출 제외용

# ── Claude API 키 ────────────────────────────────
# 공용 키 하나면 모든 단계가 이 키를 쓴다
ANTHROPIC_API_KEY=sk-ant-your-key-here

# (선택) 역할별 키 — 결제자가 다르거나 단계별 비용을 나눠 보려면 따로 넣는다
# 비우면 위 공용 키로 넘어간다
TRIAGE_ANTHROPIC_API_KEY=sk-ant-your-triage-key
MAPPING_ANTHROPIC_API_KEY=sk-ant-your-mapping-key
INVESTIGATION_ANTHROPIC_API_KEY=sk-ant-your-investigation-key
RESPONSE_ANTHROPIC_API_KEY=sk-ant-your-response-key

# ── 역할별 모델 (선택, 비우면 claude-sonnet-5-5) ──
TRIAGE_CLAUDE_MODEL=claude-sonnet-5-5
MAPPING_CLAUDE_MODEL=claude-sonnet-5-5
INVESTIGATION_CLAUDE_MODEL=claude-sonnet-5-5
```

> `.env` 는 커밋 금지(이미 `.gitignore`). 키 값은 코드가 읽기만 하고 출력하지 않는다.

```bash
# 조사·매핑까지 쓸 때 (추가)
pip install -r llm/investigate/requirements.txt       # 조사 에이전트·RAG (torch 등)
cd llm/investigate
python -m scripts.fetch_attack_catalog                # ATT&CK STIX 19.2 내려받기
python -m scripts.fetch_attack_embedding              # 임베딩 모델 준비
cd ../..
```

```bash
# ① 탐지 — 로그를 보고 사건을 만들어 큐에 적재
python -u run_pipeline.py --out-incidents out/incidents.jsonl                   # 수동(콘솔·파일 출력)
python -u run_pipeline.py --since-minutes 60 --state-dir /var/lib/agentic-soc   # 운영(큐 적재)

# ② 조사 — 큐에서 사건을 꺼내 LLM이 판정 (별도 실행)
python -u run_investigation_queue.py --state-dir /var/lib/agentic-soc --limit 20

# 큐 / 결과 확인
python socdb.py --db /var/lib/agentic-soc/soc.db stats     # 큐 통계
python socdb.py --db /var/lib/agentic-soc/soc.db queue     # 대기열
```

서버에서 탐지를 5분마다 자동 실행하는 방법은 [detection_pipeline/deploy/DEPLOY.md](detection_pipeline/deploy/DEPLOY.md)에 있다.

---

## 폴더 구조

```text
agentic-soc/
├── run_pipeline.py              # ① 탐지 실행기 (정규화→탐지→사건묶기→트리아지→큐)
├── run_investigation_queue.py   # ② 조사 큐 폴러 (큐 pending → 조사 → 매핑 → 대응 → done)
├── socdb.py                     # 큐/DB 확인 CLI (읽기 전용)
├── .env.example                 # 환경변수 예시 (.env 는 Git 제외)
│
├── detection_pipeline/          # ① 결정론 탐지
│   ├── common/                  #   공통 계약: schema·seed·join_keys·timeparse·network·lineage
│   ├── tools/                   #   파서 4종(fetch_*_log) + normalize + log_sources
│   ├── detect/                  #   Sigma 엔진·집계·Suricata seed  (rules/sigma/{apache,auth,audit})
│   ├── correlate/               #   연결→guard→Incident→dedup  (links/ 계층쌍 링커 5종)
│   ├── triage/                  #   결정론 점수·우선순위 P1~P4
│   ├── store/                   #   Incident DB(SQLite) — 큐·상태
│   └── deploy/                  #   systemd service·timer, 배포 문서
│
└── llm/                         # ② LLM 층 — 결정론 결과에 판단만 덧붙임
    ├── triage_review/           #   상위 사건 오탐 재검토(llm_review)
    ├── investigate/             #   조사 에이전트 (agent/·attack_mapping/)
    └── respond/                 #   대응 권고
```

조사 에이전트는 공통 정규화 코드(`detection_pipeline/tools/`)를 복사하지 않고 원본을 그대로 불러 쓴다. 조사 쪽 작업에서는 이 코드를 **수정하지 않는다**. 대시보드는 별도 레포(Next.js)에서 조사 결과 JSON으로 연결한다.

---

## 스택

| 영역 | 사용 |
| --- | --- |
| 언어 | Python 3.10+ |
| 탐지 | Sigma 룰 · Suricata(IDS) 연계 · SQLite(사건 DB·큐) |
| LLM | Anthropic Claude (sonnet 5.5) — 트리아지·조사·매핑·대응 |
| RAG (매핑) | BM25 + sentence-transformers(multilingual-e5-small) · MITRE ATT&CK STIX 19.2 |
| 운영 | systemd timer(5분 자동 탐지) · Ubuntu / EC2 |
| 대시보드 | Next.js (별도 레포) |

---
## LLM 설정 (역할별)

> ⚠️ 추후 수정 예정 — 모델·선정 이유는 비교 평가 정리 후 채운다.

LLM을 쓰는 단계는 넷이고, `.env`에서 **접두어**로 역할마다 따로 설정한다(한 단계를 바꿔도 나머지는 그대로). 역할 전용 키(`<접두어>ANTHROPIC_API_KEY`)가 비면 공용 `ANTHROPIC_API_KEY`로 폴백한다.

| 단계 | 접두어 | 모듈 | 모델 | 선정 이유 | 전용 키 |
| --- | --- | --- | --- | --- | --- |
| 트리아지 오탐 재검토 | `TRIAGE_` | `llm/triage_review` | _(추후)_ | _(추후)_ | `TRIAGE_ANTHROPIC_API_KEY` |
| 조사 에이전트 | `INVESTIGATION_` | `llm/investigate` | _(추후)_ | _(추후)_ | `INVESTIGATION_ANTHROPIC_API_KEY` |
| ATT&CK 매핑 | `MAPPING_` | `llm/investigate/attack_mapping` | _(추후)_ | _(추후)_ | `MAPPING_ANTHROPIC_API_KEY` |
| 대응 권고 | `RESPONSE_` | `llm/respond` | _(추후)_ | _(추후)_ | `RESPONSE_ANTHROPIC_API_KEY` |

자세한 변수·기본값은 [.env.example](.env.example) 참고.

---

## 탐지 파이프라인 (Detection Pipeline)

EC2 로그 4종을 보고 공격 신호를 찾아 사건으로 묶고 우선순위를 매겨 큐에 적재한다. 전 과정이 **결정론**이라 같은 입력이면 항상 같은 사건·같은 순위가 나온다(LLM은 상위 사건 오탐 재검토에만 쓴다).

```text
로그 4종 (Apache·auth·Suricata·auditd)
  → ① 정규화     공통 Event (raw_ref · UTC 정렬, 교체 로그 .1·.gz 포함)
  → ② 탐지       Sigma 28룰 + Suricata 알림 → Seed (빈도 집계)
  → ③ 사건 묶기   계층 간 연결 → Incident (보수적 묶기 · 중복 병합)
  → ④ 트리아지    결정론 점수 → P1~P4 → DB 큐(상위만 조사로)
```

| 단계 | 하는 일 | 산출 |
| --- | --- | --- |
| ① 정규화 | 로그 4종(web·auth·network·system)을 **공통 Event**로 변환. 교체 로그(`.1`·`.gz`)도 읽고 UTC로 정렬. 모든 Event는 원본 위치 `raw_ref`를 가진다 | 공통 Event |
| ② 탐지 | **Sigma 룰 28개** + Suricata 알림으로 Event에서 공격 신호(Seed)를 찾는다. 저심각 룰은 빈도 임계값 미만이면 노이즈로 버린다 | Seed (근거 `evidence_refs` 포함) |
| ③ 사건 묶기 | 계층 간 연결(IP·시간·프로세스 계보)로 흩어진 Seed를 **하나의 사건**으로 묶는다. 애매한 후보는 안 묶는다(보수적). 같은 사건은 병합 | Incident (대상·구간·멤버·근거) |
| ④ 트리아지 | 사건이 가진 사실(심각도·계층수·연결 종류·탐지 수)만으로 점수 → 우선순위 **P1~P4**. 상위(P1·P2)만 조사로, 나머지는 대시보드/보류. 상위는 경량 LLM이 오탐 재검토 | 우선순위 + DB 큐 적재 |

- **결정론이 진실원.** 같은 입력 → 같은 점수·순위. 어제 P1이던 게 오늘 P3로 바뀌지 않는다.
- **증거 포인터 필수.** 근거(`evidence_refs`) 없는 사건은 만들지 않는다(환각 방지).
- **트리아지는 "진짜 공격이냐"를 판단하지 않는다.** 순위 매기기 + 하위 걸러내기만 하고, 판정은 조사 에이전트 몫이다.

계층별 파서는 아래와 같고, 모든 파서는 같은 모양의 Event를 반환한다(조인키 `src_ip`/`pid`/`ppid`는 top-level, 계층 고유값은 `layer_data`).

| 계층 | 입력 | src_ip 출처 | 탐지 |
| --- | --- | --- | --- |
| web | Apache access.log | client(`%a`) | apache 룰 6개 |
| auth | auth.log (syslog) | 원격 IP | auth 룰 10개 |
| network | Suricata eve.json | XFF 실 클라이언트 | Suricata alert(IDS) |
| system | auditd audit.log(.gz) | 없음(pid/ppid 조인) | audit 룰 12개 |

---

## 조사 에이전트 (Investigation Agent)

1차 탐지가 큐에 넘긴 사건마다, LLM이 로그 조회 도구를 골라 가며 원본 로그를 다시 확인하고 **`THREAT_CONFIRMED`(위협) / `FALSE_POSITIVE`(오탐) / `INCONCLUSIVE`(판단 보류)**로 판정한다. 어떤 사건을 조사할지는 1차 탐지가 정하고, 에이전트는 받은 사건만 조사한다. 판정 결과는 ATT&CK 매핑의 입력이 된다.

```text
사건 입력(1차 탐지 Incident)
  → 조사 루프:  LLM 판단 → 도구 실행(로그 재조회) → 결과 관찰   (반복, 도구 최대 8회)
                종료 관문을 통과해야 종료
  → 조사 결과 JSON:  판정 · 증거 사슬 · 원본 참조 검증  → ATT&CK 매핑으로
```

- **같은 증거면 같은 판정.** 판정 기준을 "이 조건이면 이 판정" 조합표(아래 9원칙)로 쓰고, LLM은 체크리스트처럼 적용한다.
- **LLM은 제안, 코드가 확인.** 무엇을 조회하고 어떻게 판정할지는 LLM이 제안하고, 조회 실행·숫자 세기(로그인 실패 수·웹셸 신호 등)·조기 종료 차단은 코드가 한다.
- **증거는 원본 위치(`raw_ref`)를 가진다.** 실제 조회하지 않은 줄을 인용하면 신뢰도에 반영하지 않는다(환각 방지).

**판정 원칙 (9개)** — 각 원칙은 실제 실행에서 나온 오판 때문에 생겼고, 코드가 뒷받침하는 원칙은 LLM이 어겨도 도구가 숫자를 대신 세거나 종료 관문이 막는다.

| # | 원칙 | 핵심 |
| --- | --- | --- |
| 1 | 증거 기반 | 근거는 도구로 관찰한 사실뿐. 1차 탐지 심각도·사유는 단서일 뿐 원본 재확인. 로그 없으면 "활동 없음"이 아니라 판단 보류 |
| 2 | 동적 도구 선택 | 단서에 맞는 도구부터(웹→web, 로그인→auth, 명령→audit). audit을 넓은 구간 무필터로 조회 금지 |
| 3 | 상태 관리 | 같은 조회 반복 안 함(과거 로그는 불변) |
| 4 | 종료 판단 | 신뢰도 충분 + 도구 2종류 이상 + IP 있으면 network 확인해야 종료 |
| 5 | 계층 간 연결 | 한 계층의 IP·시간·pid를 다음 조회 조건으로(로그인 pid → audit ppid) |
| 6 | sudo 사건 | sudo audit만으로 위협 판정 안 함(정상도 연다). auth로 로그인 정황 확인 |
| 7 | SSH 인증 | 시도 범위·인증 강도·후속 행위 조합. 실패 5회 이상 또는 계정 2개 이상 = 무차별 대입 |
| 8 | 데이터 유출 | 민감 디렉터리 압축 → 외부 전송은 강한 유출 신호. "백업일 수도"로 낮추지 않음 |
| 9 | 웹 반복·스캔 | POST 10회 이상 = 대입, 경로 20개 이상 & 4xx 과반 = 스캔. 웹서버 계정의 셸·의심 명령 = 위협 |

조사 도구 6종(web·auth·audit·network·전계층·프로세스 계보)은 1차 탐지의 정규화 코드를 그대로 불러 써서 같은 로그를 같은 Event로 읽는다.

---

## ATT&CK 매핑 (Attack Mapping)

조사 에이전트가 사건 조사를 완료하면, 검증된 Evidence를 **MITRE Enterprise ATT&CK 19.2** Technique에 RAG로 매핑한다(활성 Technique 697개 대상). 공식 STIX 원본은 Git에 올리지 않고 실행 환경에서 별도로 내려받는다. 결과(판정 + 매핑)는 최종 보고서로 저장돼 대응·대시보드의 입력이 된다.

```text
조사 결과 Evidence
  → 사건·Evidence 검증
  → BM25 + multilingual-E5 검색 → RRF로 후보 최대 10개
  → 매핑 LLM이 SELECT / ABSTAIN → 공식 ATT&CK Catalog로 검증
  → Technique 병합 · Kill Chain 생성
  → 매핑 JSON + Final Report
```

- 오탐 사건은 `not_applicable`, 판단 보류 사건은 `deferred`로 처리하고, 매핑 가능한 Evidence만 후보 검색·검증에 쓴다.
- 매핑 LLM은 조사와 별도로 `MAPPING_*` 설정을 쓴다.
- 결과는 `results/attack_mapping/`에 `<incident_id>_attack_mapping.json`(Technique+Kill Chain), `<incident_id>_final_report.json`(조사+매핑)으로 저장된다.

---

## 대응 권고 (Response)

ATT&CK 매핑까지 끝난 최종 보고서를 입력으로 **즉시 조치 / 확인 필요** 대응 권고를 만든다. 조치 대상(차단할 IP·격리할 웹셸 파일 등)은 **코드가 결정론으로** 고르고, LLM은 사유·요약 문장만 채운다(환각 방지). 각 조치에는 원복 방법·영향 범위·자동화 등급(L1/L2)을 함께 적는다. 조사 큐 폴러가 조사·매핑 뒤 이어서 실행하며 `RESPONSE_*` 설정을 쓴다. 결과는 `results/response/`에 저장된다.
