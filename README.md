# Agentic SOC — 1차 탐지

Apache, Auth, Suricata, Audit 로그를 공통 Event로 정규화하고, 탐지 근거가 있는 사건(Incident)을 만들어 우선순위를 매기는 파이프라인이다. 탐지·사건 묶기·점수는 결정론이고, 상위 사건에만 LLM(Claude Haiku)이 조사 필요 여부를 한 줄로 덧붙인다. 심층 조사는 이 단계의 범위 밖이다.

```text
4계층 실로그 → 정규화 Event → Sigma/Suricata Seed → 빈도 집계
             → 계층 간 연결 → Seed가 있는 Incident → 파편 병합(dedup)
             → 트리아지(점수 P1~P4 + 상위 LLM 재검토) → JSONL
```

운영 진입점은 `run_pipeline.py`다. `tools/normalize.py`는 정규화까지만, `detect/run.py`는 Seed 생성까지만 실행한다. 서버에서 5분마다 자동 실행하는 방법은 [deploy/DEPLOY.md](deploy/DEPLOY.md)에 있다.

---

## 폴더 구조

```text
agentic-soc/
├── run_pipeline.py                 # 정규화 → 탐지 → 집계 → 사건 묶기 → JSONL
├── .env.example                    # 환경변수 예시(.env는 Git 제외)
├── requirements.txt                # Python 의존성
├── common/
│   ├── schema.py                   # 정규화 Event 계약
│   ├── seed.py                     # 탐지 Seed 계약과 검증
│   ├── join_keys.py                # 계층 간 조인키 정의
│   ├── lineage.py                  # PID 재사용을 고려한 audit 계보
│   ├── network.py                  # Apache/Suricata 요청·flow 매칭 공통 로직
│   └── timeparse.py                # Python 3.10 호환 UTC 시각 파싱
├── tools/
│   ├── fetch_apache_log.py         # Apache → web Event
│   ├── fetch_auth_log.py           # auth.log → auth Event
│   ├── fetch_network_log.py        # Suricata eve.json → network Event
│   ├── fetch_audit_log.py          # audit.log → system Event
│   ├── normalize.py                # 4계층 Event 병합·정렬(분석 창·로테이트 파일 선택)
│   ├── log_sources.py              # 로테이트 파일(.1, .N.gz) 찾기·gz 열기
│   ├── base.py                     # 도구 응답 형식
│   ├── registry.py                 # 도구 등록소
│   └── sample_*                    # 4계층 테스트 로그
├── detect/
│   ├── loader.py                   # Sigma 룰 로딩·조건 사전 컴파일
│   ├── engine.py                   # 계층별 Sigma 매칭·Seed 생성
│   ├── aggregate.py                # 빈도 집계·임계값 적용
│   ├── suricata_seed.py            # Suricata Alert → Seed
│   ├── suricata_flow.py            # Alert↔HTTP 증거 연결
│   ├── web_network_correlation.py  # Suricata HTTP↔Apache 상관분석
│   ├── run.py                      # 정규화 → Seed까지만 실행
│   └── rules/sigma/
│       ├── apache/                 # Apache 룰 6개
│       ├── auth/                   # Auth 룰 10개
│       └── audit/                  # Audit 룰 12개
├── correlate/
│   ├── grouping.py                 # Linker edge 수집·클러스터·Incident 생성
│   ├── guards.py                   # 중복·시간차 오연결 방지
│   ├── incident.py                 # Incident 출력 형식·멤버 제한
│   ├── dedup.py                    # 같은 entity·사유 사건 병합
│   ├── registry.py                 # Linker 등록소
│   ├── links/
│   │   ├── web_network.py          # web↔network
│   │   ├── suricata_flow.py        # Alert↔HTTP
│   │   ├── web_system.py           # web↔system
│   │   ├── audit_lineage.py        # system 내부 부모↔자식
│   │   └── system_auth.py          # system↔auth
├── triage/
│   ├── triage.py                   # 결정론 점수·우선순위(P1~P4)
│   └── llm_review.py               # 상위 사건 LLM 재검토(키 없으면 생략)
├── pipeline/
│   └── state.py                    # 주기 실행 증분 상태(new/update 판정)·실행 잠금
├── deploy/                         # systemd service·timer, 서버 배포 문서
└── tests/
    ├── test_engine.py              # 조건 컴파일·계층별 룰 인덱싱
    ├── test_full_pipeline.py       # 파이프라인 출력·합성 4계층 공격 체인
    ├── test_lineage.py             # PID 재사용·재부팅 경계
    ├── test_suricata_seed.py       # Suricata Seed 계약·flow
    └── test_web_network_correlation.py # Apache/Suricata 결합
```

## 계층별 파서

| 계층 | 파일 | 입력 | src_ip 출처 | 탐지 룰 |
| --- | --- | --- | --- | --- |
| web | `fetch_apache_log.py` | Apache access.log | client(`%a`) | apache 6개 |
| auth | `fetch_auth_log.py` | auth.log (syslog) | 원격 IP | auth 10개 |
| network | `fetch_network_log.py` | Suricata eve.json | XFF 실 클라이언트 | 없음(IDS) |
| system | `fetch_audit_log.py` | auditd audit.log (.gz 가능) | 없음(IP 없음, 조인키 pid/ppid) | audit 12개 |

- **network는 Sigma 룰이 없다** — IDS라 Suricata 자체 `alert`를 증거로 쓴다.
- **system(audit)은 serial 단위 조립** — 한 이벤트 = 같은 `msg=audit(epoch:serial)` 레코드 묶음. `raw_ref` 는 `파일:SYSCALL 줄번호`, 묶음 전체 줄번호는 `layer_data.raw_lines`.

---

## 설치 및 실행

Python 3.10 이상에서 저장소 루트 기준으로 실행한다. EC2/WSL 예시:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Windows PowerShell에서는 활성화 명령으로 `.venv\Scripts\Activate.ps1`을 사용한다. `.env`의 경로와 설정은 실행 환경에 맞게 변경한다. EC2 실로그 예시:

```dotenv
APACHE_LOG_PATH=/var/log/apache2/access.log
AUTH_LOG_PATH=/var/log/auth.log
SURICATA_LOG_PATH=/var/log/suricata/eve.json
AUDIT_LOG_PATH=/var/log/audit/audit.log
SERVER_PUBLIC_IP=<서버 공인 IP>
AUTH_LOG_YEAR=2026
```

`AUTH_LOG_YEAR`는 연도가 없는 BSD 형식 auth 로그에 사용한다. `.env`는 Git에 포함되지 않는다. 각 로그 파일의 읽기 권한을 확인한다. 경로가 비어 있거나 파일이 없으면 해당 계층은 이벤트 0건으로 진행될 수 있으므로 실행 후 계층별 건수를 확인한다.

실로그(`.env`의 경로 사용):

```bash
python -u run_pipeline.py --out-incidents out/incidents.jsonl
```

샘플 로그(`.env`의 경로를 실행 옵션으로 덮어씀):

```bash
python -u run_pipeline.py \
  --apache tools/sample_access.log \
  --auth tools/sample_auth.log \
  --network tools/sample_eve.json \
  --audit tools/sample_audit.log \
  --out-incidents out/sample_incidents.jsonl
```

`[normalize]` 계층별 이벤트 수, `[detect]` 원본/집계 Seed 수, `[correlate]` Incident 수와 계층 수 분포를 출력한다. `--out-incidents`를 지정하면 한 줄에 Incident 한 건씩 저장하며, 같은 경로로 재실행하면 파일을 덮어쓴다. 지정하지 않으면 콘솔 통계만 출력한다.

| 옵션 | 의미 |
| --- | --- |
| `--apache`, `--auth`, `--network`, `--audit` | 해당 계층 로그 경로를 실행 시 덮어쓰기 |
| `--rules` | Sigma 룰 디렉터리 변경 |
| `--window` | 개별 Seed의 시간 반경(기본 60초) |
| `--min-count` | 룰별 설정이 없는 low/medium Seed의 최소 탐지 수(기본 5) |
| `--no-require-seed` | 탐지 Seed가 없는 연결 클러스터도 Incident로 출력 |
| `--min-priority` | 지정 우선순위 이상만 저장(예: `P2`) |
| `--show` | 콘솔에 보여줄 다계층 Incident 수(기본 10) |
| `--since-minutes` | 최근 N분만 분석. 로테이트 파일(`.1`, `.N.gz`) 중 창 시작 이후 수정된 파일도 읽음 |
| `--now` | 분석 기준 시각(기본 현재 UTC). 샘플 재현·테스트용 |
| `--state-dir` | 증분 상태 디렉터리. 지정하면 새로 생겼거나 바뀐 사건만 고르고, LLM 재검토도 그 사건에만 함 |
| `--emit-dir` | 고른 사건을 `incidents-YYYY-MM-DD.jsonl`에 append(`--state-dir` 필요) |

서버 주기 실행 예(샘플 로그로 재현하려면 `--now 2026-09-18T00:00:00Z --since-minutes 7200`):

```bash
python -u run_pipeline.py --since-minutes 60 --state-dir /var/lib/agentic-soc --emit-dir /var/lib/agentic-soc/incidents
```

같은 명령을 다시 실행하면 이미 낸 사건은 다시 나오지 않는다. 각 줄의 `emit_type`은 `new` 또는 `update`이고, 실행 간 같은 사건은 `incident_key`로 알아본다. 자세한 내용은 [deploy/DEPLOY.md](deploy/DEPLOY.md).

`python tools/normalize.py`는 정규화까지만, `python detect/run.py --out-seeds out/seeds.jsonl`는 원본 Seed 생성까지만 실행한다. `detect/run.py` 전용 `--web-strong-window` 등의 옵션은 `run_pipeline.py`에 적용되지 않는다.

---

## 공통 스키마 (계약)

모든 파서는 **같은 모양의 dict**를 반환한다.
```json
{
  "timestamp": "…Z",        // ISO8601 UTC — 전 계층 정렬축
  "layer": "web|network|system|auth",
  "raw_ref": "파일:줄번호",  // 원본 역추적 포인터
  "src_ip": "…",            // ┐ 조인키(top-level): 계층을 넘나들며 사건을 잇는다
  "pid": null, "ppid": null, // ┘
  "layer_data": { … }       // 계층마다 다른 고유 필드
}
```
- **조인키(src_ip/pid/ppid)는 top-level, 계층 고유값은 layer_data.** 계층별 키는 `common/schema.py`.
- 새 파서를 붙일 때 **도구 계약**: `fetch_<계층>_log(log_path, …) -> list[dict]` + `@register` + `success/failure`.

## 탐지부터 사건 묶기까지

1. `detect/loader.py`가 Apache 6개, Auth 10개, Audit 12개, 총 28개 Sigma 룰을 읽고 조건을 한 번 컴파일한다. Network는 Sigma 룰 대신 Suricata Alert를 사용한다.
2. `detect/engine.py`가 계층에 맞는 룰만 검사해 Sigma Seed를 만들고, `detect/suricata_seed.py`가 Suricata Alert Seed를 만든다.
3. `detect/aggregate.py`가 같은 룰·entity의 Seed를 집계한다. 일반 로그인 POST는 같은 IP에서 5분 내 20회 이상일 때 발화한다. Hydra User-Agent 탐지는 단발도 유지한다. 룰별 임계값이 없으면 low/medium Seed에 `--min-count`(기본 5)를 적용하고 high/critical Seed는 단발도 유지한다.
4. `correlate/links/`의 5개 Linker가 web↔network, Suricata flow, web↔system, audit 부모·자식, system↔auth 연결을 만든다. `guards.py`가 중복 및 과도한 시간차의 system↔auth 연결을 제거한다.
5. `correlate/grouping.py`가 연결된 이벤트를 클러스터로 묶고 Seed의 `evidence_refs`로 탐지 근거를 연결한다. 운영 기본값 `require_seed=True`는 Seed가 없는 클러스터를 Incident로 내보내지 않는다. 연결되지 않은 Seed도 원본 이벤트가 있으면 별도 Incident로 보존한다.

Incident에는 `entity`(조사 대상), `window`(시간 범위), `layers`(관계 계층), `members`(원본 로그 위치), `join_path`(연결 근거), `seeds`(탐지 근거)가 들어간다. 500건을 넘는 사건의 `members`와 `join_path`는 출력 시 제한하며 전체 멤버 수는 `member_count`, 잘림 여부는 `oversized`에 남긴다.

## Apache–Suricata 결합

Suricata Alert는 먼저 `sensor_id + flow_id + tx_id`로 같은 Suricata HTTP 이벤트에 연결된다.
`tx_id`가 없을 때만 같은 flow·전송 튜플·±5초 안의 유일한 HTTP 이벤트를 보수적으로 사용한다.
이후 HTTP 이벤트의 XFF 기반 `src_ip`와 Apache `%a`를 표준 IP로 비교하고, UTC 시각과
`method/path/status`를 함께 사용해 다음 등급으로 판정한다.

| 등급 | 기본 조건 | seed 처리 |
| --- | --- | --- |
| `strong` | 동일 IP, ±1초, method/path/status 일치, 후보 1건 | Apache `raw_ref`를 `evidence_refs`에 자동 편입 |
| `ambiguous_cluster` | strong 조건 후보가 여러 건 | 후보만 보존, 자동 편입 안 함 |
| `context_only` | ±2초 fallback, 요청 필드 불일치, ±900초 장시간 정확 후보, XFF 결측 후보 | 상세 메타데이터로만 보존 |
| `unmatched` | 후보 없음, timestamp 오류, XFF invalid/conflict | 미결합 사유 보존 |

XFF가 없는 경우 IP 독립 검증이 불가능하므로 `strong`으로 승격하지 않는다. XFF가
`invalid` 또는 `conflict`이면 IP 없는 fallback도 수행하지 않는다. 판정 결과는 Suricata
seed의 `detail.web_network_correlations`에 기록된다.

기본 결합 창은 `detect/run.py`의 `--web-strong-window`, `--web-fallback-window`,
`--web-long-delay-window`로 조정할 수 있다. 이 값은 seed 자체의 `--window`와 독립적이다.

## 테스트 및 실로그 검증

Linux/WSL/EC2에서:

```bash
PYTHONIOENCODING=utf-8 python -m unittest discover -s tests -p 'test_*.py'
PYTHONIOENCODING=utf-8 python tests/test_full_pipeline.py
```

Windows PowerShell에서는 먼저 `$env:PYTHONIOENCODING = 'utf-8'`을 설정한 뒤 `python -m unittest discover -s tests -p 'test_*.py'`를 실행한다. `test_full_pipeline.py`는 설정된 로그를 읽고 코드 안의 합성 4계층 웹셸 체인을 추가 검증한다. 운영의 빈도 집계와 `require_seed=True`는 위의 `run_pipeline.py` 명령으로 확인한다. `test_full_pipeline.py`는 `.env`(또는 `*_LOG_PATH` 환경변수)가 없으면 이벤트 0건으로 실패한다. `tests/`의 스크립트형 테스트는 개별 실행도 된다(예: `python tests/test_grouping.py`).

로컬 및 EC2 Python 3.10에서 테스트 51개가 통과했다. EC2 실로그 실행에서는 정규화 이벤트 102,889건 → 원본 Seed 1,928건 → 집계 Seed 87건 → Incident 33건을 확인했다. 해당 데이터에서 전체 실행 시간은 약 56초였다. 로그 양과 시점에 따라 수치는 달라진다.

## 알아둘 것 / 남은 것

- **엔진 필드 탐색**: `get_field`는 top-level → 점 경로(`layer_data.x`) → 접두어 없는 이름(`layer_data` 폴백) 순.
  apache 룰은 접두어 없이, auth·audit 룰은 점 경로로 쓴다. 새 룰은 점 경로 권장.
- **logsource 라우팅**: `product/service` 로 layer 를 정한다(`linux/auditd`→system, `linux/auth`→auth, `apache`→web). category 는 무시.
- **web 계층 주의**: Apache가 nginx 뒤라 `%a`가 실 클라이언트다(XFF 미사용, 단일 프록시 환경).
- **system(audit) 주의**: `str.splitlines()` 는 ENRICHED 구분자 0x1D 를 줄바꿈으로 취급해 레코드가 쪼개진다. 파일 반복 또는 `split("\n")` 만 쓴다.
- **audit session_type**: SYSCALL 레코드가 있을 때만 `interactive`/`non_interactive` 로 판정, 없으면 `None`(판정 불가). `exclude_interactive=True` 는 `non_interactive` 만 남긴다.
- **audit serial 은 유니크가 아니다**: 재부팅 시 리셋된다(실파일 498738→75). 식별·중복제거 키는 `(timestamp, serial)` 또는 `raw_ref`.
- **time_window**: tz 없는 ISO 시각은 UTC 로 간주한다. 형식 오류는 도구 봉투 `failure("잘못된 인자: …")` 로 돌아온다(파싱 실패와 구분).
- **후속 과제**: SSH 브루트포스 관련 약 2만 건 규모의 클러스터는 현재 출력 멤버만 500건으로 제한한다. 사건 자체를 시간창 단위로 분할하는 작업은 남아 있다.

