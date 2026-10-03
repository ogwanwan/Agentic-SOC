# Agentic SOC

EC2 웹 서버의 로그를 보고 공격을 **탐지**해 사건(Incident)으로 묶고, LLM **조사 에이전트**가 사건마다 원본 로그를 다시 조회하며 위협 여부를 판정하는 보안관제 파이프라인이다. 탐지·사건 묶기·점수는 **결정론**(같은 입력 → 같은 결과)이고, LLM은 결정론 결과에 판단만 덧붙인다. 모든 판단은 원본 로그 줄(`raw_ref`)로 역추적된다.

```text
[탐지 — detection_pipeline]                         [조사 — llm/investigate]
로그 4종 → 정규화 Event → Sigma/Suricata Seed        큐에서 사건을 하나씩 꺼내
  → 빈도 집계 → 계층 간 연결 → Incident               도구로 로그를 재조회하며 LLM이 판정
  → 트리아지(P1~P4 + 상위 LLM 재검토)        ──▶      → 결과 JSON
  → DB 큐(soc.db)에 pending 으로 적재          큐       (탐지는 자동 5분 타이머, 조사는 큐 폴러)
```

탐지와 조사는 **별도 프로세스**이고 **DB 큐(`soc.db`)로만 연결**된다(함수 호출 없음). 탐지는 빠르게 큐를 채우고, 조사는 LLM이라 느리므로 큐에서 자기 속도로 꺼내 처리한다.

---

## 폴더 구조

```text
agentic-soc/
├── run_pipeline.py              # ① 탐지 실행기 (정규화→탐지→사건묶기→트리아지→큐)
├── run_investigation_queue.py   # ② 조사 큐 폴러 (큐 pending → 조사 에이전트 → done)
├── socdb.py                     # 큐/DB 확인 CLI (읽기 전용)
├── .env.example                 # 환경변수 예시 (.env 는 Git 제외)
├── requirements.txt
│
├── detection_pipeline/          # ① 결정론 탐지
│   ├── common/                  #   공통 계약: schema·seed·join_keys·timeparse·network·lineage
│   ├── tools/                   #   파서 4종(fetch_*_log) + normalize + log_sources + registry/base
│   ├── detect/                  #   Sigma 엔진·집계·Suricata seed  (rules/sigma/{apache,auth,audit})
│   ├── correlate/               #   연결→guard→Incident→dedup  (links/ 계층쌍 링커 5종)
│   ├── triage/                  #   결정론 점수·우선순위 P1~P4
│   ├── pipeline/                #   주기 실행 증분 상태(new/update)·실행 잠금
│   ├── store/                   #   Incident DB(SQLite) — 큐·상태
│   ├── deploy/                  #   systemd service·timer, 배포 문서
│   └── samples/                 #   4계층 샘플 로그
│
├── llm/                         # ② LLM 층 — 결정론 결과에 판단만 덧붙임
│   ├── triage_review/           #   상위 사건 오탐 재검토(llm_review) — 경량 모델
│   ├── investigate/             #   조사 에이전트 (agent/·attack_mapping/·reporting/ …)
│   └── respond/                 #   대응 (예정)
│
├── tests/                       # 통합 테스트
└── docs/                        # 작업 정리·설정 가이드
```

- **1차 탐지 상세**(파서·룰·조인·Apache-Suricata 결합·함정)는 [CLAUDE.md](CLAUDE.md)와 `detection_pipeline/` 각 모듈 주석에 있다.
- **조사 에이전트**는 자체 문서가 있다: [llm/investigate/CLAUDE.md](llm/investigate/CLAUDE.md), [llm/investigate/README.md](llm/investigate/README.md). 공통 정규화 코드(`llm/investigate/primary_detection/normalizer/`)는 탐지팀 산출물을 vendor(복사)한 것으로 **수정하지 않는다**.
- **ATT&CK 매핑**은 조사 에이전트 하위(`llm/investigate/attack_mapping/`)에서 진행한다.
- **대시보드**는 별도 레포(Next.js)에서 진행하며, 조사 결과 JSON으로 연결한다.

---

## 실행

Python 3.10 이상, 저장소 루트 기준.

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env                                 # 로그 경로·키 채우기 (.env 는 커밋 금지)
```

**① 탐지** — 로그를 보고 사건을 만들어 큐에 적재
```bash
# 수동(큐 미사용, 콘솔·파일 출력만)
python -u run_pipeline.py --out-incidents out/incidents.jsonl

# 운영(큐 적재) — 최근 60분의 새·바뀐 사건만 soc.db 에 pending 으로
python -u run_pipeline.py --since-minutes 60 --state-dir /var/lib/agentic-soc
```

**② 조사** — 큐에서 사건을 꺼내 LLM이 판정 (별도 실행)
```bash
python -u run_investigation_queue.py --state-dir /var/lib/agentic-soc --limit 20
```

**큐/결과 확인**
```bash
python socdb.py --db /var/lib/agentic-soc/soc.db stats   # 큐 통계
python socdb.py --db /var/lib/agentic-soc/soc.db queue    # 대기열
```

서버에서 탐지를 5분마다 자동 실행하는 방법은 [detection_pipeline/deploy/DEPLOY.md](detection_pipeline/deploy/DEPLOY.md)에 있다.

---

## LLM 설정 (역할별)

LLM을 쓰는 단계는 셋이고 `.env`에서 **접두어**로 역할마다 따로 설정한다(한 단계를 바꿔도 나머지는 그대로).

| 접두어 | 단계 | 위치 | 모델 등급 |
| --- | --- | --- | --- |
| `TRIAGE_` | 트리아지 오탐 재검토 | `llm/triage_review` | 경량 |
| `MAPPING_` | ATT&CK 매핑 | `llm/investigate/attack_mapping` | 경량 |
| `INVESTIGATION_` | 조사 에이전트 | `llm/investigate` | 고성능 |

- 역할 전용 키(`<접두어>ANTHROPIC_API_KEY`)가 비어 있으면 공용 `ANTHROPIC_API_KEY`를 쓴다. 결제자가 다르면 역할별 키를 따로 넣는다.
- 자세한 변수·기본값은 [.env.example](.env.example)과 [docs/LLM-역할별-설정-가이드.md](docs/LLM-역할별-설정-가이드.md) 참고.

---

## 계층별 파서 (탐지 입력)

| 계층 | 파일 | 입력 | src_ip 출처 | 탐지 |
| --- | --- | --- | --- | --- |
| web | `fetch_apache_log.py` | Apache access.log | client(`%a`) | apache 룰 6개 |
| auth | `fetch_auth_log.py` | auth.log (syslog) | 원격 IP | auth 룰 10개 |
| network | `fetch_network_log.py` | Suricata eve.json | XFF 실 클라이언트 | Suricata alert(IDS) |
| system | `fetch_audit_log.py` | auditd audit.log(.gz) | 없음(조인키 pid/ppid) | audit 룰 12개 |

모든 파서는 같은 모양의 dict를 반환한다. 조인키(`src_ip`/`pid`/`ppid`)는 top-level, 계층 고유값은 `layer_data`. 계약은 `detection_pipeline/common/schema.py`.

---

## 테스트

```bash
PYTHONIOENCODING=utf-8 python -m unittest discover -s tests -p 'test_*.py'
PYTHONIOENCODING=utf-8 python tests/test_full_pipeline.py        # 탐지 전체 + 합성 4계층 체인
python tests/test_investigation_queue.py                          # 조사 큐 폴러 상태 전이
```

`test_full_pipeline.py`는 `.env`(또는 `*_LOG_PATH`)의 로그를 읽는다 — 없으면 이벤트 0건으로 실패한다. `tests/`의 스크립트형 테스트는 개별 실행도 된다(예: `python tests/test_grouping.py`). 조사 에이전트 자체 테스트는 `cd llm/investigate && python -m pytest -q`.

---

## 알아둘 것

- **결정론이 진실원**: 탐지·사건묶기·점수는 결정론. LLM은 순서·점수를 바꾸지 않고 판단만 덧붙인다.
- **증거 포인터 필수**: 모든 Event는 `raw_ref`, 모든 Seed는 `evidence_refs`를 가진다(환각 방지). 근거 없는 사건은 만들지 않는다.
- **fail-open**: 키 없음·LLM 오류·권한 오류에도 결정론 결과로 계속 간다. 누락보다 중복(죽으면 다음 실행이 다시 보고).
- **Python 3.10 호환**: ISO 시각 파싱은 `common/timeparse`를 거친다(3.10은 `Z`·`+0000` 미지원).
- **audit 주의**: `str.splitlines()` 금지(0x1D 구분자가 쪼개짐). serial은 재부팅 시 리셋되어 유니크 아님.
- **web 계층**: Apache가 nginx 뒤 단일 프록시라 `%a`가 실 클라이언트(XFF 미사용).
