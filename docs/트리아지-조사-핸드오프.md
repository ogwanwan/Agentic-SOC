# 트리아지 → 조사 에이전트 핸드오프 계약

> 넘기는 쪽: 정규화·탐지·트리아지 파트 / 받는 쪽: 조사(Investigate) 에이전트 파트
> 관련: [triage/README.md](README.md), [correlate/incident.py](../correlate/incident.py)

트리아지가 조사 에이전트에게 넘기는 것 = **아래 3개 세트**. 셋이 한 짝이다.

| # | 넘기는 것 | 없으면 |
|---|---|---|
| 1 | **사건(Incident) 스트림** — 우선순위 붙은 사건 목록(JSONL) | 뭘 볼지 모름 |
| 2 | **raw_ref → 원문 조회 도구** — 에이전트가 raw_ref로 원본 로그 줄을 받아옴 | 증거(명령어·페이로드) 못 봄 → 조사 불가 |
| 3 | **필드 스키마** — 이 문서 | 필드 뜻 모름 |

> 조사 입력 = **JSONL 파일 하나**(배치·실시간 동일). 사건엔 raw_ref **포인터만** 담고(파일 작게 유지),
> 실제 원문은 에이전트가 **도구로 조회**한다(원본 로그 접근은 그 도구가 담당 — 조사 팀이 서버를 직접 뒤지지 않음).

---

## 세트 1 — 사건 스트림 (JSONL, 한 줄 = 사건 1건)

`run_pipeline.py --out-incidents out/incidents.jsonl` 이 내는 파일. 점수 내림차순 정렬.

- **넘기는 범위:** `route == "investigate"`(= **P1·P2**)만. P3·P4는 대시보드/보류로 우리가 보관(조사 대상 아님).
- 실시간 전환 후엔 이 스트림이 **새로 생기거나 갱신된 사건**만 흘러오게 될 예정(중복 조사 방지).

### 사건 1건 전체 모양 (P1 예시)
```json
{
  "incident_id": "INC-7d29ffde",
  "entity":      {"type": "pid", "value": "1200"},
  "window":      ["2026-09-11T02:00:00Z", "2026-09-11T02:04:30Z"],
  "layers":      ["auth", "system"],
  "members":     ["audit.log:6", "audit.log:16", "auth.log:30"],
  "member_count": 5,
  "oversized":   false,
  "join_path": [
    {"a": "audit.log:6",  "b": "auth.log:30",  "join": "system_auth",   "keys": {"pid": 1200}},
    {"a": "audit.log:6",  "b": "audit.log:16", "join": "audit_lineage", "keys": {"parent_pid": 1200, "child_pid": 5320}}
  ],
  "seeds": [
    {"reason": "Web Process Writes Executable Script Into Webroot",
     "layer": "system", "source": "sigma",
     "score_parts": {"rule_severity": "critical"},
     "signal_tags": ["T1505.003"],
     "evidence_refs": ["audit.log:6"]}
  ],
  "triage_score": 70,
  "priority":     "P1",
  "route":        "investigate",
  "triage_parts": {"severity": 50, "layers": 6, "join_types": 6, "seed_count": 8},
  "llm_investigate": true,
  "llm_reason": "웹루트에 스크립트 기록 후 계정 생성 — 웹셸→권한상승 체인"
}
```

### 필드별 — 조사 에이전트가 하는 일
| 필드 | 조사 에이전트가 하는 일 |
|---|---|
| `priority` / `route` | **조사 대상 선별.** `route=="investigate"`만 판다 |
| `entity` `{type,value}` | **조사 축(pivot).** 이 IP/PID 중심으로 로그 확장 조회 |
| `window` `[min,max]` | **시간 경계**(UTC). 이 사이 원본만 조회 |
| `layers` | 어느 **계층 로그**를 볼지 |
| `seeds[].reason` + `score_parts.rule_severity` | **조사 출발점.** 무슨 탐지가 왜 떴나 |
| `seeds[].signal_tags` | **공격 기법**(MITRE 등) 힌트 — 다음에 뭘 볼지 |
| `members[]` (raw_ref) | **원본 역추적.** 각 raw_ref로 원본 로그 줄 열어 실제 명령어·페이로드 확인 |
| `join_path[]` `{a,b,join,keys}` | **공격 스토리.** a→b 연결·keys(pid/uid/시간차)로 체인 재구성 |
| `seeds[].evidence_refs` | 그 탐지의 **근거 줄** 바로 열기 |
| `triage_parts` + `llm_reason` | **왜 우선순위 높은지** 요약 — 맥락 빨리 파악 |
| `oversized` / `member_count` | `oversized=true`면 members가 잘린 것 → 원본 **추가 조회** 필요 |

> 조사 흐름: `entity`+`window`로 범위 → `seeds`로 "뭐 떴나" → raw_ref로 **원본 열어 증거 확인** →
> `join_path`로 **체인 스토리** → **"진짜 공격인가" 판정**(트리아지가 안 하는 그 일).

---

## 세트 2 — raw_ref → 원문 조회 도구

`members`/`evidence_refs`/`join_path.a·b` 는 전부 **`"<파일명>:<줄번호>"` 포인터**다(1-base).
실제 명령어·페이로드는 사건 안에 **안 담는다**(용량 — 2만 줄이면 6MB). 대신 조사 에이전트가
**raw_ref를 넣으면 원문 로그 줄을 돌려주는 도구**를 쓴다. 원본 로그 접근은 그 도구가 담당하므로
조사 팀이 서버를 직접 뒤질 필요 없다.

- **형식:** `"apache_access.log:10"` = 그 로그 파일의 10번째 줄.
- **합의 사항(팀 간):**
  - 파일명 → 실제 경로 매핑(예: `audit.log` → `/var/log/audit/audit.log`) — 도구가 이걸 안다.
  - **줄번호 안정성:** 파일은 append만 하므로 평상시 줄번호 안정. **로그 로테이션**(파일이
    `.1`로 밀리고 다시 1번 줄부터 시작) 때만 예전 raw_ref가 어긋난다. 짧은 실행이면 사실상 무시 가능.
    장기 실행 시엔 도구가 (a) 로테이션 전 원문 캡처 또는 (b) 세대 파일(`access.log.1`)까지 탐색으로 처리.

---

## 세트 3 — 필드 스키마
이 문서의 표 + [triage/README.md](README.md)(점수·라우팅 근거). 특히 `entity`/`window`/`seeds.reason`/`join_path`/raw_ref 읽는 법.

---

## 안 넘기는 것
우리 내부 코드, 정규화 이벤트 버퍼, seed 원본 데이터 — 사건 안에 조사에 필요한 만큼 다 들어있다.

## 조사 팀과 확정할 것 (open)
- [x] 스트림 전달 방식: **JSONL 파일** (배치·실시간 동일. 실시간은 append + offset tail). DB는 우리 내부용, 조사엔 안 보임.
- [x] 증거 전달: **raw_ref 포인터만** 넘기고 에이전트가 **도구로 원문 조회** (임베드 안 함).
- [ ] raw_ref → 원본 파일 경로 매핑 표 (조회 도구가 알아야 함)
- [ ] `route=="investigate"`(P1·P2)만 받을지, 전부 받고 그쪽에서 필터할지
- [ ] `llm_investigate=false` 인 P1·P2 사건 처리(우리 LLM이 "안 봐도 됨" 한 것) — 그래도 조사할지
