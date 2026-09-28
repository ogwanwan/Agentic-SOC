# incident 보관 DB 전환 작업 정리 — state.json·실행별 파일 → SQLite

| 항목 | 내용 |
| --- | --- |
| 작성 | 이민혁 |
| 작업일 | 2026-09-29 |
| 브랜치 | `develop` |
| 커밋 | (커밋 전) |
| 서버 상태 | 미반영. `git pull` 후 다음 5분 실행에서 DB가 자동으로 생성된다 |
| 기준 문서 | 트리아지 보완 계획 (지원 작성) — `incidents` / `incident_details` 테이블, 상태 흐름, fail-open 쿼리 |

---

## 1. 요약

운영 모드(5분마다 최근 60분 분석)의 결과 저장 위치를 **SQLite DB 한 파일**(`/var/lib/agentic-soc/soc.db`)로 바꿨다. 이 DB는 트리아지 보완 계획의 **조사 대기열** 역할을 한다. 조사 에이전트는 여기서 "지금 조사해야 할 사건"을 급한 순서대로 꺼낸다.

- 1차 탐지 ①~④(정규화 → 탐지 → 사건 묶기 → 트리아지)는 **수정하지 않았다.**
- 바뀐 곳은 두 군데다.
  - "이미 본 사건" 비교 대상: `state.json` → DB
  - 결과 저장: 실행별 jsonl 파일 → DB. jsonl은 전환 기간 동안 함께 쓴다.
- 운영 모드가 아닐 때(수동 실행)의 동작은 그대로다.
- 추가로 설치할 것이 없다(파이썬 내장 `sqlite3`).

```text
 ┌──────────────── 1차 탐지 (5분마다) ────────────────┐
 │ ① 로그 읽기 → ② 탐지 → ③ 사건 묶기 → ④ 점수 매기기   │ ← 그대로
 │ ⑤ DB와 비교해 새 사건·새 활동 사건만 선택            │ ← state.json 대신 DB
 │ ⑥ LLM 오탐 체크(P1·P2)                            │ ← 그대로
 │ ⑦ jsonl 저장(--emit-dir) → DB 저장(한 트랜잭션)     │ ← DB 저장 추가
 └───────────────────────────┬────────────────────────┘
                             ▼
              ┌──────────── soc.db ─────────────┐
              │ incidents        (대기열: 점수, 상태) │
              │ incident_details (사건 상세)         │
              └──────────────┬──────────────────┘
                             ▼
               [조사 에이전트] 급한 사건부터 꺼내 조사 (다음 단계)
```

---

## 2. 작업 전 상태와 문제

- `state.json`은 "이미 보고한 사건"을 기억하고, 결과는 실행마다 jsonl 파일로 쌓였다. 이 결과를 가져가는 쪽은 없었다.
- 조사 에이전트가 붙으려면 다음이 필요한데, 파일 방식으로는 어렵다.
  - **조사 상태 관리**: 미조사/조사중/완료. 파이프라인과 조사 에이전트가 **같은 사건의 상태를 동시에** 바꿀 수 있어서, 파일로 하면 나중에 쓴 쪽이 앞의 변경을 덮어쓴다.
  - **사건의 최신 상태 조회**: 파일 방식에서는 같은 `incident_key`를 여러 파일에서 찾아 최신 줄을 골라야 한다.
  - **급한 순서대로 꺼내기**: 파일에는 점수로 정렬된 대기열이 없다.
- 같은 EC2에서 조사 에이전트를 돌릴 계획이라, 서버 프로그램이 필요 없는 SQLite를 택했다.

---

## 3. 트리아지 보완 계획 대비 변경점

계획의 목적(급한 순서로, 중복 없이, 빠짐없이 조사)과 상태 흐름은 그대로 구현했다. 구현하면서 정하거나 보완한 부분은 다음과 같다.

| 계획 | 구현 | 이유 |
| --- | --- | --- |
| 대기열 쿼리가 ①(`COALESCE`)과 맨 아래(`llm_investigate=1`) 두 가지 | **①로 통일** + 동점이면 먼저 들어온 순 | 맨 아래 쿼리대로면 LLM이 못 본 사건이 빠진다(fail-open 원칙과 모순) |
| update 시 members·seeds **합치기** | **최신 내용으로 덮어쓰기** | 5분마다 60분을 다시 분석해서, 합치면 같은 seed가 쌓이고 로그 교체 뒤 같은 줄이 두 번 들어간다 |
| "update 오면" (기준 없음) | 1차 탐지가 **새 활동**으로 판단했을 때만 (`diff_incidents`의 new/update) | 변화 없는 사건도 매번 분석되므로, 기준이 없으면 완료 사건이 5분마다 다시 열린다 |
| 조사중이면 "플래그만" | `has_update` 컬럼 추가 | 플래그를 둘 자리가 필요 |
| 상태 값 한글(미조사/조사중/완료) | `pending`/`investigating`/`done`으로 저장, `socdb.py` 화면에서 한글 표시 | 코드·쿼리의 문자열 오타와 인코딩 문제 방지 |
| 상세 4컬럼 | 4컬럼 + `extra_json` | `oversized`(멤버 목록이 잘렸는지), `triage_parts`(점수 근거) 등 4컬럼에 없는 필드 보존 |
| `entity`, `window` 한 컬럼씩 | 각각 두 컬럼 (type/value, start/end) | IP별·시간별 조회용 |
| (없음) | "이미 본 사건" 추적 컬럼 5개 | `state.json`이 하던 new/update 판단을 DB가 대신함 |

**이번에 구현하지 않은 것**
- **조사 큐 함수**(사건 꺼내기, 완료, 실패 반환, 30분 회수): 담당을 팀과 상의한 뒤 결정한다(10절). 필요한 컬럼(`status`, `claimed_at`, `has_update`)은 테이블에 미리 있다.
- **원문 로그 줄 보관**: 후속 과제(10절).

---

## 4. DB 구조

- 파일: `<state-dir>/soc.db`. 서버에서는 `/var/lib/agentic-soc/soc.db`이고, WAL 모드라 옆에 `soc.db-wal`, `soc.db-shm`이 생긴다.
- 시각은 모두 `YYYY-MM-DDTHH:MM:SSZ`(UTC) 문자열이다. 형식이 같아서 문자열 비교가 곧 시간 비교다.
- 스키마 버전은 `PRAGMA user_version`으로 관리한다(현재 1). 나중에 컬럼이 늘면 코드가 자동으로 갱신한다.

### `incidents` — 사건당 1행, 조사 대기열

| 컬럼 | 뜻 |
| --- | --- |
| `incident_key` (PK) | 안정 키 = hash(entity + 탐지 사유). 사건이 커져도 안 바뀐다 (`pipeline/state.incident_key`) |
| `incident_id` | 참고용. 멤버 해시라 사건이 커지면 바뀐다 |
| `entity_type`, `entity_value` | 조사 대상 (예: `src_ip` / `20.201.77.247`, `pid` / `1200`) |
| `window_start`, `window_end` | 사건 시간 범위 |
| `member_count` | 묶인 이벤트 수 |
| `triage_score`, `priority`, `route` | 트리아지 결과 (점수, P1~P4, investigate/dashboard/hold) |
| `llm_investigate` | 1=진짜 / 0=오탐 / NULL=LLM이 못 봄(대기열에 포함) |
| `llm_reason` | LLM 근거 한 줄 |
| `status` | `pending`(미조사) / `investigating`(조사중) / `done`(완료) |
| `has_update` | 조사중에 새 활동이 들어왔다는 표시 |
| `claimed_at` | 조사 시작 시각 (30분 회수용, 조사 쪽에서 기록) |
| `updated_at` | 사건 내용이 마지막으로 갱신된 시각 (동점 정렬 기준) |
| `first_emitted`, `last_emitted`, `last_seen`, `max_member_count`, `state_window_end` | "이미 본 사건" 추적용 (예전 `state.json` 내용) |

### `incident_details` — 사건 상세 (`incident_key`로 1:1)

| 컬럼 | 뜻 |
| --- | --- |
| `layers` | 사건이 걸친 계층 (JSON) |
| `members` | 묶인 이벤트의 raw_ref 목록 (JSON) |
| `seeds` | 걸린 탐지들 (JSON) |
| `join_path` | 왜 묶였나 (JSON) |
| `extra_json` | 위 컬럼과 대기열 테이블에 없는 나머지 필드 (`oversized`, `triage_parts`, `merged_from` 등. 트리아지에 새 필드가 생겨도 여기에 보관) |

---

## 5. 동작 규칙

### 5-1. 파이프라인이 저장할 때의 상태 규칙
새 사건 또는 새 활동이 있는 사건(new/update)에만 적용한다. **변화 없는 사건은 상태를 건드리지 않는다**(추적 컬럼 `last_seen` 등만 갱신).

| 기존 상태 | 결과 |
| --- | --- |
| 행 없음 | 추가, `pending` |
| `done` | `pending`으로 **재오픈** (새 활동이 생겼으니 다시 조사) |
| `investigating` | 상태 유지, **`has_update=1`** |
| `pending` | 그대로 |

사건 내용(점수, LLM 판단, 상세)은 매번 최신 값으로 덮어쓴다. 그래서 LLM이 오탐(0)이라 했던 사건이 update에서 진짜(1)로 바뀌면 자연스럽게 대기열에 다시 들어온다.

### 5-2. 조사 대기열 조건
`store/incidents.py`의 `QUEUE_WHERE`, `QUEUE_ORDER` 두 상수에만 있다.

```sql
WHERE route = 'investigate' AND COALESCE(llm_investigate, 1) = 1 AND status = 'pending'
ORDER BY triage_score DESC, updated_at ASC, incident_key ASC
```

- `COALESCE(llm_investigate, 1)`: LLM이 못 본 사건(NULL)을 1로 취급해 빠뜨리지 않는다(fail-open).
- 트리아지 쪽에서 LLM 우선순위 필드가 생기면 이 두 줄만 바꾸면 된다.

### 5-3. 24시간 규칙 (기존과 같음)
24시간 동안 다시 보이지 않은 사건은 DB에 남아 있지만, 다시 나타나면 `new`로 판단된다. 이미 행이 있으므로 새 행이 생기지 않고 5-1 규칙대로 다시 열린다.

### 5-4. 기존 `state.json` 이전
- 첫 운영 실행 때 `state.json`이 있으면 그 기록을 `incidents`로 옮기고 파일 이름을 `state.json.migrated`로 바꾼다.
- 옮긴 행은 `route`가 비어 있어서 **대기열에 들어가지 않는다.** 이미 jsonl로 보고된 사건이 한꺼번에 조사 대상으로 쏟아지지 않게 하기 위해서다.
- 다음에 새 활동(update)이 생기면 그때 내용이 채워져 대기열에 들어간다.

### 5-5. 저장 순서
```text
LLM 재검토 (트랜잭션 밖 — 네트워크를 기다리는 동안 DB를 잠그지 않음)
  → jsonl 저장 (--emit-dir)
  → DB 저장 (record_run, 한 트랜잭션)
```
DB를 마지막에 커밋하므로, 도중에 죽으면 다음 실행이 같은 사건을 다시 보고한다. 누락 대신 중복이 생기는 쪽을 택했고, 기존 원칙과 같다.

---

## 6. 코드 변경

### 새로 만든 파일
| 파일 | 역할 |
| --- | --- |
| `store/db.py` | `connect(path)`: WAL, busy_timeout 5초, 새 파일은 권한 0640<br>`transaction(conn)`: `BEGIN IMMEDIATE` 쓰기 트랜잭션<br>`migrate(conn)`: 테이블 생성, 여러 번 불러도 안전<br>`import_state_json(conn, state_dir)`: 5-4 |
| `store/incidents.py` | `load_state_view(conn, now)`: DB에서 `state.json`과 같은 모양의 dict를 만든다. 그래서 `diff_incidents`를 수정 없이 재사용한다<br>`record_run(conn, emits, new_state, now)`: 5-1 규칙으로 저장<br>`list_queue`, `get_incident`, `stats`: 읽기 전용 조회<br>`QUEUE_WHERE`, `QUEUE_ORDER`, `STATUS_LABELS` 상수 |
| `socdb.py` | DB 확인용 CLI (읽기 전용) |
| `tests/test_store.py` | DB 테스트 10개 |

SQL은 `store/` 안에만 있다. 테이블이 바뀌어도 다른 코드는 고칠 필요가 없다.

### 수정한 파일
| 파일 | 변경 |
| --- | --- |
| `run_pipeline.py` | 운영 모드에서 `load_state`/`save_state` 대신 `connect`·`migrate`·`import_state_json`·`load_state_view`·`record_run`을 사용한다. `--db` 옵션을 추가했다(기본 `<state-dir>/soc.db`). 로그에 `[db]` 줄과 `[timing]`의 `db` 단계가 추가된다 |
| `.gitignore` | `*.db`, `*.db-wal`, `*.db-shm` (로컬 테스트 DB가 커밋되지 않게) |
| `deploy/DEPLOY.md` | 6절에 DB 설명·`socdb.py` 사용법 추가, 7절 운영표 갱신 |

**수정하지 않은 파일**
- `pipeline/state.py`: `incident_key`, `diff_incidents`, `run_lock`을 그대로 재사용한다. `load_state`/`save_state`는 `state.json` 이전과 테스트에 쓰인다.
- 탐지·사건 묶기·트리아지 코드

---

## 7. 사용법

### 운영 방식 (서버 systemd 명령, 변경 없음)
```bash
python -u run_pipeline.py --since-minutes 60 \
    --state-dir /var/lib/agentic-soc --emit-dir /var/lib/agentic-soc/incidents
```
실행 로그 예:
```text
[state] 내보낼 사건 2건(new 2, update 0), 추적 중 2건
[emit] 2건 저장: …/incidents/2026-09-18/000000-5704548bb468.jsonl
[db] 저장 …/soc.db: new 2, update 0 (재오픈 0, 조사중 표시 0)
```

### DB 확인
```bash
python socdb.py stats                  # 상태·우선순위·경로별 사건 수, 대기열 길이
python socdb.py queue -n 20            # 조사 대기열 (급한 순)
python socdb.py show <incident_key>    # 사건 상세
python socdb.py --db <경로> stats       # 다른 DB (기본: /var/lib/agentic-soc/soc.db)
```
```text
사건 2건, 조사 대기열 2건
  상태: {'미조사': 2}
  우선순위: {'P1': 1, 'P2': 1}
  경로: {'investigate': 2}
```

### 로컬에서 운영 모드 재현
```bash
python run_pipeline.py --apache tools/sample_access.log --auth tools/sample_auth.log \
    --network tools/sample_eve.json --audit tools/sample_audit.log \
    --since-minutes 10080 --now 2026-09-18T00:00:00Z \
    --state-dir /tmp/soc --emit-dir /tmp/soc/incidents
python socdb.py --db /tmp/soc/soc.db queue
```

---

## 8. 서버 반영 절차

```bash
cp /var/lib/agentic-soc/state.json ~/state.json.bak            # (선택) 백업
cd ~/agentic-soc && git pull
.venv/bin/python -c "import sqlite3; print(sqlite3.sqlite_version)"   # 3.24 이상이어야 함
sudo systemctl start agentic-soc.service                        # 바로 한 번 실행 (또는 다음 5분 대기)
journalctl -u agentic-soc.service -n 30 --no-pager              # [db] 줄 확인
ls -l /var/lib/agentic-soc/                                     # soc.db, state.json.migrated
.venv/bin/python socdb.py stats
```

- **SQLite 버전**: 사건 저장에 쓰는 upsert(`ON CONFLICT … DO UPDATE`)는 SQLite 3.24 이상이 필요하다. Ubuntu 22.04 이상이면 충족한다.
- **수동 실행은 서비스 계정으로**: `sudo python run_pipeline.py …`처럼 root로 실행하면 `soc.db-wal` 등이 root 소유로 생긴다. 그러면 이후 5분 실행이 DB에 쓰지 못한다. 수동 실행은 `systemctl start`로 한다.
- systemd 서비스 파일은 고칠 필요가 없다. DB는 기존 상태 폴더(`/var/lib/agentic-soc`)에 생긴다.

---

## 9. 테스트

| 테스트 | 결과 |
| --- | --- |
| `tests/test_store.py` (새로 추가, 10개) | 통과 |
| 기존 unittest 전체 (`python -m unittest discover tests`) | 69개 통과 |
| `tests/test_full_pipeline.py` | 로컬에 `.env`가 없으면 이벤트 0건으로 실패한다(작업 전부터 그랬다). 샘플 로그 경로를 환경변수로 주면 전부 통과 |
| `tests/test_triage.py`, `tests/test_dedup.py` | 통과 |
| 로컬 종단 (7절 명령을 두 번 실행) | 1회차 new 2건이 DB와 jsonl에 같은 수로 저장됨. 2회차(5분 뒤)는 저장 0건, 상태 변화 없음 |

`test_store.py`가 확인하는 것:
- 테이블 생성을 두 번 해도 안전하다(WAL 모드 확인 포함)
- 새 사건은 `pending`이고 대기열에 들어간다
- 변화 없는 실행에서는 상태가 그대로이고, `last_seen`만 갱신된다
- `done`인 사건에 update가 오면 `pending`으로 재오픈되고 `claimed_at`이 비워진다
- `investigating`인 사건에 update가 오면 상태는 유지되고 `has_update=1`이 된다
- 대기열: LLM 미리뷰(NULL)는 포함되고 오탐(0)과 dashboard는 제외된다. 점수순이고 동점이면 먼저 들어온 순이다. 오탐에서 진짜로 바뀌면 다시 들어온다
- 24시간 지난 사건은 `new`로 다시 열리고, 행은 새로 생기지 않는다
- 상세는 합치지 않고 최신으로 덮어쓰며, `extra_json`에 나머지 필드가 보존된다
- `state.json` 이전: 옮긴 사건은 `new`로 다시 나가지 않고 대기열에도 없으며, update가 오면 대기열에 들어간다

---

## 10. 남은 과제 (팀 논의 필요)

| 우선순위 | 과제 | 내용 |
| --- | --- | --- |
| **높음** | 조사 큐 함수 담당 결정 | 사건 꺼내기·완료·실패 반환·30분 회수 함수를 DB 쪽에서 만들지, 조사 에이전트 쪽에서 만들지 정해야 한다. 어느 쪽이든 아래 "지켜야 할 규칙"을 따라야 한다 |
| **높음** | 트리아지 필드 합의 | DB는 `triage_score`, `priority`, `route`, `llm_investigate`, `llm_reason`을 읽는다. 트리아지 보완 계획은 "LLM은 P1·P2만, 점수는 안 매김"인데, 분담표는 "LLM으로 전체에서 우선순위"다. LLM이 순위나 새 필드를 내면 이름을 알려주면 `QUEUE_WHERE`/`QUEUE_ORDER`만 바꾼다. 새 필드는 그 전까지 `extra_json`에 보관된다 |
| 중간 | 트리아지 보완 계획 문서 갱신 | 맨 아래 대기열 쿼리를 fail-open(①)으로, update 시 "합치기"를 "덮어쓰기"로 맞춘다 |
| 중간 | 원문 로그 줄 보관 | 아래 설명 참고 |
| 낮음 | jsonl 병행 종료 | 조사 에이전트가 DB를 읽기 시작하면 `--emit-dir`를 빼서 jsonl 출력을 끈다 |
| 낮음 | DB 보관 정책·백업 | 사건 행은 지금은 지우지 않는다. 크기를 보고 오래된 완료 사건 정리와 주기 백업(`VACUUM INTO`)을 정한다 |

### 조사 큐 함수가 지켜야 할 규칙
- 꺼낼 때는 `UPDATE … SET status='investigating', claimed_at=? WHERE incident_key=? AND status='pending'`으로 **조건부로 바꾼다.** 바뀐 행이 1개일 때만 조사한다. 그래야 두 워커가 같은 사건을 가져가지 않는다.
- 완료는 **내가 가져간 건**(`claimed_at` 일치)일 때만 한다. 30분 회수 뒤 늦게 끝난 워커가 덮어쓰는 것을 막는다.
- 완료할 때 `has_update=1`이면 `done` 대신 `pending`으로 되돌리고 표시를 지운다. 조사 중에 들어온 새 활동(예: 404 → 200 성공)을 놓치지 않기 위해서다.
- `investigating`인 채로 30분이 지나면 `pending`으로 되돌린다.
- 쓰기는 `store.db.transaction()`(BEGIN IMMEDIATE)으로 짧게 하고, LLM 호출은 트랜잭션 밖에서 한다.

### 원문 로그 줄 보관 (후속)
`members`의 `access.log:1895` 같은 raw_ref는 이벤트의 신원이 아니라 **"그 파일의 몇 번째 줄"이라는 위치**다. 그래서 다음 문제가 있다.
- 로그가 교체되면 같은 줄이 `access.log.1:1895`로 바뀐다. 이때 `access.log:1895`를 열면 **다른 요청이 나온다**(조용히 틀린 증거).
- audit.log는 크기 기준으로 교체되어 하루에도 여러 번 밀린다. 보관 기간(access 14일, audit 6회 교체)이 지나거나 공격자가 로그를 지우면 원문이 사라진다.

사건을 저장할 때 원문 줄을 DB에 복사하는 테이블(`incident_evidence`)을 추가할 계획이다. 실행 중 교체에도 정확한 줄을 찾도록 읽은 파일의 inode를 추적한다. 그 전까지는 raw_ref로 원본을 볼 때 교체된 파일(`access.log.1`, `.2.gz` 등)까지 확인해야 한다.
