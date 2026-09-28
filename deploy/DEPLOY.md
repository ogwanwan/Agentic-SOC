# 서버 배포 — 5분 주기 자동 탐지

로그가 쌓이는 EC2(Ubuntu)에 파이프라인을 올리고, systemd timer로 5분마다 실행한다.
매번 **최근 60분**을 다시 분석하고, **새로 생겼거나 바뀐 Incident만** incident DB(SQLite, `soc.db`)에 저장한다. 조사 에이전트는 DB의 조사 대기열에서 사건을 꺼내 간다. 전환 기간 동안 실행별 JSONL 파일도 함께 쓴다.

```text
agentic-soc.timer (5분마다)
  └─ agentic-soc.service (oneshot, soc 계정)
       └─ run_pipeline.py --since-minutes 60 --state-dir /var/lib/agentic-soc --emit-dir /var/lib/agentic-soc/incidents
            ├─ 로그 4종 + 로테이트 파일(.1, .N.gz) 중 최근 60분만 정규화
            ├─ 탐지 → 사건 묶기 → 트리아지
            ├─ DB(soc.db)와 비교해 new/update만 선택 → 그 사건만 LLM 재검토
            ├─ incidents/YYYY-MM-DD/HHMMSS-<run_id>.jsonl 저장 (--emit-dir, 보고할 사건이 있을 때만)
            └─ soc.db 에 저장 (한 트랜잭션)
```

## 왜 이 방식인가

- **최근 60분 재분석**: 링크 시간창은 ±1~5초, 빈도 집계는 300초라서 60분이면 실행 경계에 걸친 사건도 다음 실행에서 온전히 잡힌다.
- **로테이트 파일 포함**: 자정 무렵 logrotate가 `auth.log`를 `auth.log.1`로 넘긴 직후에도 직전 기록을 놓치지 않는다. 창 시작 이후에 수정된 파일만 연다.
- **systemd timer**: 이전 실행이 안 끝났으면 다음 실행이 겹쳐 뜨지 않고, 출력이 journald에 남으며, CPU·메모리 제한을 걸 수 있다.

## 1. 계정과 코드

```bash
sudo useradd --system --home /opt/agentic-soc --shell /usr/sbin/nologin soc
sudo git clone <저장소 URL> /opt/agentic-soc
cd /opt/agentic-soc
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R root:soc /opt/agentic-soc      # 코드는 soc가 읽기만
```

Python 3.10 이상이 필요하다(`python3 --version`).

## 2. 설정 파일

```bash
sudo mkdir -p /etc/agentic-soc
sudo cp deploy/agentic-soc.env.example /etc/agentic-soc/env
sudo chown root:soc /etc/agentic-soc/env
sudo chmod 0640 /etc/agentic-soc/env
sudoedit /etc/agentic-soc/env                 # 경로, SERVER_PUBLIC_IP, ANTHROPIC_API_KEY
```

- 값 뒤에 인라인 주석을 붙이지 않는다(systemd는 주석까지 값으로 읽는다).
- `AUTH_LOG_YEAR`는 **비워 둔다**. 고정하면 새해부터 auth 시각이 1년 어긋난다.
- `/opt/agentic-soc/.env`는 만들지 않는다. 만들어도 systemd 환경변수가 우선하지만, 설정이 두 군데로 나뉜다.

## 3. 로그 읽기 권한

`soc` 계정이 네 로그를 **로테이트 후 새로 생긴 파일까지** 계속 읽을 수 있어야 한다. 먼저 현재 상태를 본다.

```bash
ls -l /var/log/auth.log* /var/log/apache2/access.log* /var/log/suricata/eve.json* /var/log/audit/
```

| 로그 | 기본 권한(Ubuntu) | 조치 |
| --- | --- | --- |
| auth.log | `syslog:adm 640` | 없음 (서비스가 `adm` 그룹으로 실행됨) |
| apache access.log | `root:adm 640` | 없음 |
| audit.log | `root:root 600`, 디렉터리 `700` | 아래 auditd 설정 |
| eve.json | 설치 방식에 따라 다름 | 아래 ACL |

auditd는 파일을 새로 만들 때 권한을 다시 설정하므로 ACL 대신 auditd 설정으로 그룹을 준다.

```bash
sudo sed -i 's/^log_group = .*/log_group = adm/' /etc/audit/auditd.conf
sudo chgrp adm /var/log/audit && sudo chmod 750 /var/log/audit
sudo service auditd restart                   # systemctl restart는 auditd에서 거부될 수 있다
```

Suricata는 디렉터리에 **기본(default) ACL**을 걸어야 로테이트로 새로 생기는 파일에도 권한이 이어진다.

```bash
sudo setfacl -m u:soc:rx /var/log/suricata
sudo setfacl -m u:soc:r /var/log/suricata/eve.json*
sudo setfacl -d -m u:soc:r /var/log/suricata
```

확인은 반드시 `soc` 계정으로 한다.

```bash
for f in /var/log/auth.log /var/log/apache2/access.log /var/log/suricata/eve.json /var/log/audit/audit.log; do
  sudo -u soc head -c1 "$f" >/dev/null && echo "OK  $f" || echo "NO  $f"
done
```

권한이 없으면 파이프라인은 멈추지 않고 `[normalize] 경고: … 읽기 실패(Permission denied)`를 남기고 해당 계층을 0건으로 처리한다.

## 4. 시간대

auth.log의 BSD 형식 시각(`Sep 14 23:50:02`)은 UTC로 해석한다. 서버 시간대가 UTC인지 확인한다(EC2 Ubuntu 기본값은 UTC).

```bash
timedatectl | grep "Time zone"
```

## 5. 서비스 등록

```bash
sudo cp deploy/agentic-soc.service deploy/agentic-soc.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start agentic-soc.service      # 한 번 수동 실행
journalctl -u agentic-soc -n 30 --no-pager    # 계층별 건수·[timing]·[state] 확인
sudo systemctl enable --now agentic-soc.timer
systemctl list-timers agentic-soc.timer       # 다음 실행 시각
```

첫 실행 로그에서 확인할 것:
- `[normalize] 이벤트 N건, 계층별={…}`에 4개 계층이 모두 있는지
- `[normalize] 경고`가 없는지
- `[timing] 합계`가 5분(300초)보다 충분히 짧은지. `TimeoutStartSec=240`을 넘기면 실행이 강제 종료된다.

## 6. 결과 읽기와 조사 에이전트 인계

### incident DB (`/var/lib/agentic-soc/soc.db`)

첫 운영 실행에서 자동으로 만들어진다(설치할 것 없음, 파이썬 내장 sqlite3). 예전 `state.json`이 있으면 그 기록을 DB로 옮기고 `state.json.migrated`로 이름을 바꾼다. 옮긴 사건은 대기열에 넣지 않고, 다음에 새 활동이 생기면 들어온다.

| 테이블 | 내용 |
| --- | --- |
| `incidents` | 사건당 1행(PK `incident_key`). 점수·우선순위·경로·LLM 판단·조사 상태(`status`: `pending` 미조사 / `investigating` 조사중 / `done` 완료) |
| `incident_details` | 사건 상세(1:1). `layers`, `members`, `seeds`, `join_path`, 나머지 필드는 `extra_json` |

파이프라인이 새 활동(update)을 저장할 때: 완료된 사건은 미조사로 다시 열고, 조사중인 사건은 상태를 두고 `has_update=1`만 표시한다. 변화 없는 사건의 상태는 건드리지 않는다.

조사 대기열 조건(`store/incidents.py`의 `QUEUE_WHERE`·`QUEUE_ORDER`): 조사 대상(`route='investigate'`)이고 LLM이 오탐이라 하지 않았으며(LLM이 못 본 사건 포함) 미조사인 사건을 점수 높은 순, 동점이면 먼저 들어온 순.

```bash
cd /opt/agentic-soc
sudo -u soc .venv/bin/python socdb.py stats            # 상태·우선순위별 사건 수, 대기열 길이
sudo -u soc .venv/bin/python socdb.py queue -n 20      # 조사 대기열(급한 순)
sudo -u soc .venv/bin/python socdb.py show <incident_key>
```

SQL로 직접 보려면 `sudo apt install sqlite3` 후 `sqlite3 /var/lib/agentic-soc/soc.db`.

> **수동 실행은 서비스 계정으로.** `sudo python run_pipeline.py …`처럼 root로 실행하면 `soc.db-wal` 등이 root 소유로 생겨, 이후 5분 실행이 DB에 쓰지 못한다. 수동 실행은 `sudo systemctl start agentic-soc.service`로 한다.

### 실행별 JSONL 파일 (전환 기간 병행)

실행 1회당 파일 1개가 날짜(UTC) 폴더에 생긴다. 보고할 사건이 없는 실행은 파일을 만들지 않는다.

```text
/var/lib/agentic-soc/incidents/
└── 2026-09-26/
    ├── 074915-12d5605ecf1a.jsonl     # 실행 시각(UTC HHMMSS)-run_id
    └── 081005-a3f9c1e27b44.jsonl
```

```bash
ls -R /var/lib/agentic-soc/incidents/ | tail
cat /var/lib/agentic-soc/incidents/$(date -u +%F)/*.jsonl
```

**조사 에이전트 인계 규칙**
- `*.jsonl` 파일만 가져간다. 점(`.`)으로 시작하는 `.….tmp` 파일은 쓰는 중인 임시 파일이므로 무시한다.
- 파일은 임시 이름으로 다 쓴 뒤 한 번에 이름을 바꿔 나타나므로, 보이는 `*.jsonl`은 항상 완성된 파일이다.
- 한번 생긴 파일은 파이프라인이 다시 고치지 않는다. 같은 날짜 폴더 안에서 파일 이름순이 곧 시간순이다.
- 처리한 파일은 에이전트가 다른 폴더로 옮기거나 지워서 중복 처리를 막는다. 어디까지 처리했는지 따로 기억하는 방식도 가능하다.

한 줄이 Incident 한 건이다. 기존 Incident 필드에 다음 필드가 추가된다.

| 필드 | 의미 |
| --- | --- |
| `emit_type` | `new`: 처음 보는 사건 / `update`: 이미 낸 사건에 새 활동(window 끝이 늦어짐)이 생김 |
| `incident_key` | 실행 간 같은 사건을 가리키는 안정 키(entity + 탐지 사유). `incident_id`는 멤버가 늘면 바뀐다 |
| `emitted_at` | 이 줄을 쓴 실행의 기준 시각(UTC) |
| `run_id` | 실행 식별자 |

같은 사건의 최신 상태는 같은 `incident_key`를 가진 가장 최근 파일의 줄이다. 공격이 계속되면 5분마다 `update`가 담긴 파일이 새로 생길 수 있다.

## 7. 운영

| 작업 | 명령 |
| --- | --- |
| 실행 기록 | `journalctl -u agentic-soc --since "1 hour ago"` |
| 일시 중지 / 재개 | `sudo systemctl stop agentic-soc.timer` / `start` |
| 코드 업데이트 | `cd /opt/agentic-soc && sudo git pull && sudo .venv/bin/pip install -r requirements.txt` (타이머는 그대로) |
| DB 확인 | `socdb.py stats` / `queue` / `show <incident_key>` (6절) |
| 상태 초기화 | 타이머를 멈추고 `soc.db`, `soc.db-wal`, `soc.db-shm`을 다른 곳으로 옮김 → 다음 실행에서 최근 60분 사건이 전부 `new`로 다시 나감(조사 상태도 사라짐) |
| 결과 보관 정리 | `sudo find /var/lib/agentic-soc/incidents -name '*.jsonl' -mtime +30 -delete && sudo find /var/lib/agentic-soc/incidents -mindepth 1 -type d -empty -delete` |

24시간 동안 다시 보이지 않은 사건은 DB에 남되, 다시 나타나면 `new`로 판단된다(예전 state.json의 24시간 정리와 같은 동작).

## 알려진 한계

- **audit 계보**: 60분보다 오래 떠 있는 부모 프로세스는 분석 창 밖이라 부모·자식 연결이 끊길 수 있다. web↔system 연결은 uid 33 기준이라 영향이 적다.
- **쓰다 만 줄**: 실행 순간 파일 끝에 쓰이는 중인 줄이나 audit 이벤트는 다음 실행에서 다시 읽혀 `update`로 보정된다.
- **raw_ref 파일명**: 로테이트 후에는 같은 줄이 `access.log:120`에서 `access.log.1:120`으로 바뀐다. 과거 결과의 `members`를 원본에서 찾을 때는 로테이트된 파일도 봐야 한다.
- **매번 전체 파싱**: 창 안 이벤트만 남기지만, 파싱은 현재 파일 전체를 한다. `[timing]`에서 normalize가 병목으로 드러나면 파일별 오프셋 체크포인트를 도입한다.
- **같은 서버에서 실행**: 서버가 장악되면 로그와 결과가 함께 조작될 수 있다. 장기적으로는 로그를 별도 수집 서버로 보내 그곳에서 실행하는 구성을 검토한다.
