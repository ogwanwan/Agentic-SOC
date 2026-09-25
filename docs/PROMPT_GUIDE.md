# 조사 프롬프트 설명서

조사 에이전트가 LLM에게 보내는 프롬프트가 **어떻게 구성되고, 각 원칙이 무엇을 지시하며, 왜 생겼는지**를
정리한 문서다. 전체 실행 흐름은 [AGENT_FLOW.md](AGENT_FLOW.md), 변경 경위는 [CHANGES_0918_TO_0924.md](CHANGES_0918_TO_0924.md).

- 프롬프트 본문: `agent/prompts/investigation.yaml`
- 조립 코드: `agent/prompts/__init__.py` (`build_system_prompt`, `build_user_prompt`)
- seed 생성 프롬프트(별도): `agent/seed_prompts.py`

---

## 1. 한 턴에 LLM이 받는 것

조사 루프는 매 턴 LLM을 한 번 부르고, 그때 **시스템 프롬프트 + 사용자 프롬프트** 두 개를 보낸다.

```
[시스템 프롬프트]  ← 매 턴 같음 (investigation.yaml)
  role                      당신은 누구이고 무엇을 하는가
  ## 핵심 원칙 1~9          판정 기준과 조사 방법
  ## 강제 종료 턴 안내       forced_termination_notice
  ## 사용 가능한 도구        registry.schema_text() — 도구 이름·설명·인자
  ## 출력 형식              output_schema — 반드시 이 JSON으로 답하라
  규칙:                     rules — 응답 형식, 증거 기록, 신뢰도 산정

[사용자 프롬프트]  ← 매 턴 바뀜 (build_user_prompt)
  지금까지의 조사 상태(JSON) + 코드가 계산한 값 + (있으면) 직전 종료 거부 사유
```

LLM은 매 턴 **"지금까지 알게 된 것 정리 + 다음 행동(도구 호출 또는 종료)"**을 JSON 하나로 답한다.
원칙 번호(특히 6~9)는 `output_schema`의 `reasoning`과 `rules`에서 참조하므로 번호를 바꿀 때는 함께 맞춘다.

### 사용자 프롬프트에 들어가는 값

| 필드 | 내용 | 누가 채우나 |
|---|---|---|
| `seed` | 조사할 사건 (incident_id, src_ip, window, trigger_description …) | seed 생성 / 1차 탐지 |
| `current_facts`, `current_hypotheses`, `current_unknowns` | LLM이 지난 턴까지 정리한 사실·가설·모르는 것 | LLM (루프가 보관) |
| `confirmed_evidence`, `contradicting_evidence` | 지금까지 채택된 지지·반박 증거 | 루프 (원본 참조 검증 후) |
| `current_confidence`, `confidence_threshold`, `confidence_threshold_reached` | 증거 누적 신뢰도와 종료 임계값(0.85) | 루프 |
| `already_called_tools` | 이미 부른 도구+인자 (중복 금지) | 루프 |
| `raw_observations_since_last_turn` | **방금 실행한 도구의 결과** (이번 턴에 해석할 것) | 도구 |
| `known_raw_refs` | 지금까지 관측된 원본 참조 목록 (증거에 인용 가능한 것) | 루프 |
| `provenance_issues` | 잘못 인용한 참조 기록 | 루프 |
| `query_windows` | 계층별 첫 조회 구간 | **코드 계산** |
| `auth_lookback_window` | auth 24시간 조회 구간 | **코드 계산** |
| `previous_termination_rejected`, `rejection_reason` | 직전 종료 요청이 거부됐으면 그 사유 | 종료 관문 |
| `forced_termination` | 도구 없이 판정만 하라는 마지막 턴 | 루프 |

---

## 2. 역할 (role)

> 2차 심층 조사를 수행하는 조사 에이전트. seed를 받아 여러 계층 로그를 연결해 공격이 어디까지 진행됐는지
> 복원한다. **같은 증거가 주어지면 언제나 같은 판정** — 느낌이 아니라 원칙을 체크리스트처럼 적용한다.

"체크리스트처럼"이 이 프롬프트 전체의 방향이다. 판정 재현성(같은 사건을 여러 번 돌려도 같은 결과)이
프로젝트의 핵심 평가 기준이라, 원칙들은 대부분 "이 조건이면 이 판정"처럼 조합표 형태로 쓰여 있다.

---

## 3. 원칙별 설명

각 원칙마다 **무엇을 지시하나 → 왜 생겼나 → 코드가 어떻게 뒷받침하나**를 적었다.
"코드 뒷받침"이 있는 원칙은 LLM이 어겨도 종료 관문이 막거나 도구가 숫자를 대신 계산해 준다.

### 원칙 1. 증거 기반 조사

**지시**
- 가설을 세우고 로그로 검증한다. 반박 증거도 찾는다(확증 편향 금지).
- 판단 근거는 **도구 결과에서 관찰된 사실뿐**이다.
  - "이 구간에는 로그 기록 자체가 없습니다"는 "활동 없음"이 아니라 **로그 미확보** → INCONCLUSIVE.
  - IP 평판("악성으로 알려진 IP")은 그걸 조회하는 도구가 없으면 말하지 않는다. 행위로만 판단한다.
  - 도구 결과에 없는 지명·조직명·평판을 만들어내지 않는다.
  - seed의 `severity_hint`, `confidence_initial`은 힌트일 뿐 근거가 아니다.

**왜 생겼나**
- **severity_hint 오염**: 0918에 실제 자동 생성 seed(INC-001)로 반복 실행했더니, seed의 초기 추정치가
  최종 판정을 끌고 가서 같은 증거로 재현성이 50%까지 떨어졌다. "힌트일 뿐"을 명시해 100%로 회복했다.
- **IP 평판 지어내기**: 평판 조회 도구가 없는데 "악성 IP로 알려진"처럼 쓰는 사례를 막는다.
- **로그 미확보**: 로그가 없는 날짜의 seed를 LLM이 "활동 없음"으로 읽고 4번 중 3번 FALSE_POSITIVE로 판정했다.

**코드 뒷받침**
- 도구가 `window_total`(필터 전 구간 전체 건수)을 돌려주고, 0이면 summary에 "로그 기록 자체가 없음"을 붙인다.
- 조회한 모든 계층이 0건이면 종료 관문이 INCONCLUSIVE 외 판정을 거부한다.

### 원칙 2. 동적 도구 선택

**지시**
- 모든 로그를 다 보지 말고, 부족한 증거에 맞는 도구만 고른다.
- 첫 도구는 seed 단서로: 웹 단서(URI·업로드·메서드) → `fetch_web_log`, 인증 단서(SSH·로그인) → `fetch_auth_log`.
- **조회 구간**: 각 계층의 첫 호출은 `query_windows` 구간을 그대로 쓴다(web ±1시간, audit -30분~+1시간,
  network ±30분, auth 24시간). 다른 구간은 두 번째 호출부터 실제 기록 시각을 근거로 바꾼다.
- audit은 넓은 구간을 필터 없이 조회하지 않는다. 먼저 `[후속 침해 확인]` 집계를 보고, 원본이 필요하면
  `ppid`·`user`로 좁힌다.

**왜 생겼나**
- 웹 사건에 auth부터 보고 "증거 없음"으로 끝내는 식의 잘못된 첫 도구 선택을 막으려는 것.
- 조회 구간을 LLM에게 맡겼더니 실행마다 달랐다. 예: EC2에서 audit을 24시간 무필터로 조회해 3728건
  (대부분 cron 등 정상 명령)을 받았고, web은 seed 구간 11초만 보기도 했다.

**코드 뒷받침**
- `layer_query_windows()`가 구간을 계산해 `query_windows`로 넣는다(원칙 문장만으로는 LLM이 1~2시간만 보는 일이 반복됐다).
- audit 도구의 `[후속 침해 확인]`은 페이지와 무관하게 전체를 센다.

### 원칙 3. 상태 관리

**지시**: `already_called_tools`에 있는 도구+인자 조합은 다시 부르지 않는다. 같은 계층을 다시 볼 때는 구간이나 필터를 바꾼다.

**왜 / 코드**: 같은 조회를 반복하며 도구 호출 횟수(최대 8)를 낭비하는 것을 막는다. 루프가 같은 조합을
실제로 차단한다(`AgentState.already_called`) — 원칙을 어겨도 실행되지 않고 notes에 "중복 호출 스킵"이 남는다.

### 원칙 4. 종료 판단

**지시**
- 종료는 두 가지: `confidence_sufficient`(추가 조사가 결론을 바꾸지 않음), `no_more_evidence`(볼 로그가 없음).
- `confidence_sufficient` 승인 조건: 신뢰도 ≥ 임계값, 서로 다른 도구 2종류 이상, src_ip가 있으면 network 확인.
- **network 사전 조회**: src_ip가 있으면 시스템이 첫 턴 전에 network를 조회해 둔다(대표 20건 + 전체 집계).
  집계에 경보가 있는데 records에 없으면 `alert_only`로 다시 조회한다. 다른 계층에서 새 외부 IP·시간대가 나오면 network를 다시 본다.
- `no_more_evidence`는 "seed 단서 계층을 확인했고 더 얻을 사실이 없다"는 뜻. 도구 1종류만 보고는 쓸 수 없다.
- 거부되면(`previous_termination_rejected`) 같은 상태로 다시 종료를 요청하지 말고, 도구를 더 부르거나
  no_more_evidence로 판정한다. **임계값을 채우려고 이미 기록한 사실을 증거로 다시 만들거나 기여도를 부풀리지 않는다.**

**왜 생겼나**
- LLM이 도구 1개(web 또는 auth)만 보고 끝내는 조사가 EC2에서 반복됐다(xmlrpc 사건, SSH 탐침 사건).
- 거부된 뒤 LLM이 같은 사실을 새 증거로 다시 적어 신뢰도를 채우는 일이 있었다.

**코드 뒷받침**: 종료 관문(`_termination_rejections`)이 조건을 실제로 검사하고, 사전 조회는 코드가 직접 실행하며,
같은 원본 참조를 다시 인용한 증거는 신뢰도에 반영하지 않는다. 자세한 조건은 [AGENT_FLOW.md 3장](AGENT_FLOW.md).

### 원칙 5. 계층 간 연결

**지시**: 계층별로 따로 결론 내지 말고 한 공격 시나리오로 엮는다. 한 계층에서 얻은 IP·시간·프로세스를 다음 조회 조건으로 쓴다.
- auth → audit: 로그인 세션의 sshd pid로 `fetch_audit_log(ppid=<pid>)` — 세션에서 실행한 명령은 그 pid의 자식이다.
- web → audit/network: 같은 src_ip·시간대.
- 서버에서 외부로 나간 통신: `dst_ip=<외부 IP>` (외부 IP를 src_ip로 넣으면 아웃바운드가 안 잡힌다).

**왜 생겼나**: "조인 엔진" 코드 없이 LLM이 계층을 연결하도록 한 설계. 0918 시나리오 비교에서 audit을
`user=ubuntu`로 조회해 0건이 나왔는데, audit의 `user`는 실행 계정(sudo 뒤에는 root)이라 세션 명령이 빠졌다.

**코드 뒷받침**: 로그인 성공이 보이는데 audit을 안 보면 종료 관문이 거부하고 사유에 `ppid=<sshd pid>`를 적어 준다.
network 사전 조회는 방향 무관 `ip` 필터를 써서 역방향 셸도 잡는다.

### 원칙 6. 권한 사용(sudo) 사건과 audit 단독 증거의 함정

**지시**
- "sudo로 /etc/passwd·/etc/shadow에 접근" audit 이벤트만으로 위협 판정하지 않는다. sudo는 실행될 때마다
  /etc/passwd를 여는 게 정상이다. 반드시 auth로 그 계정·시간대의 로그인 정황을 확인한다.
- "외부 IP에서 접속"도 그 자체로는 위협이 아니다(관리자 원격 접속은 정상).
- 정상 신호(반복 실패 없이 정상 인증, 읽기 위주 sudo 명령)와 침해 신호(로그인 전 반복 실패, 이례적 패턴,
  세션 내 유출·역방향 셸·계정 추가)로 판단한다. 둘 다 불명확하면 INCONCLUSIVE + 무엇을 더 봐야 하는지 unknowns에.

**왜 생겼나**: 0918 검증 seed 01("ubuntu 계정이 sudo로 /etc/passwd 접근" — 정상 관리 행위)을 위협으로 오판하는 것을
막기 위한 원칙. 현재 이 seed는 FALSE_POSITIVE로 일관되게 나온다.

**코드 뒷받침**: 없음(프롬프트 판단). audit 도구의 `[후속 침해 확인]` 집계가 참고 자료가 된다.

### 원칙 7. 계정·인증(SSH) 사건의 판단 절차

**지시**: 세 질문에 각각 답하고 그 조합으로 판정한다.
- **Q1 시도 범위**: 로그인 실패 몇 회, 계정 몇 개? — `auth_lookback_window`(24시간) 구간을 그대로 조회하고,
  횟수는 직접 세지 말고 summary의 집계를 쓴다(실패 1회 = ssh_failed 또는 ssh_invalid_user 1건).
- **Q2 인증 강도**: 성공한 로그인이 공개키인가 비밀번호인가?
- **Q3 후속 행위**: 로그인 후 행위가 정상 업무 수준인가?

| 조합 | 판정 |
|---|---|
| Q1 정상(1건/1계정) + Q2 공개키 + Q3 정상 | FALSE_POSITIVE |
| invalid user 1회 후 다른 계정 공개키 로그인 | Q1 정상으로 본다 |
| Q1 정상 + 공개키인데 세션 audit 0건 | FALSE_POSITIVE(0.80~0.85), audit 부재는 unknowns |
| Q1 침해(다수 시도/계정) + Q2 비밀번호 로그인 성공 | THREAT_CONFIRMED (후속 행위 없어도) |
| 로그인 성공 없음 — 실패 5회 이상 또는 계정 2개 이상 | THREAT_CONFIRMED "SSH 무차별 대입 시도" (LOW~MEDIUM) |
| 로그인 성공 없음 — 실패 1~4회, 계정 1개 | FALSE_POSITIVE (단발성 실패) |
| 로그인 성공 없음 — 실패 0회, 접속 흔적(ssh_probe)만 | FALSE_POSITIVE (스캐너 탐침) |
| 일부 신호만 침해 방향 | THREAT_CONFIRMED 또는 INCONCLUSIVE, 근거 명시 |
| Q1~Q3 중 답할 데이터가 없음 | INCONCLUSIVE |

로그인 성공이 없는 경우는 **INCONCLUSIVE 금지** — 필요한 사실은 auth 도구로 모두 확인할 수 있다.
Q1~Q3의 답은 그 답을 준 도구 결과 턴에 한 번씩만 증거로 적고, "Q1~Q3를 종합하면…" 같은 요약 증거는 만들지 않는다.

**왜 생겼나**
- SSH 실패만 있는 사건이 같은 seed에서 INCONCLUSIVE/FALSE_POSITIVE/THREAT_CONFIRMED로 갈렸다(60%) →
  실패만 있는 경우의 규칙을 넣어 5/5로 고정.
- LLM이 실패 1회를 PAM 실패·연결 종료까지 합쳐 1회/3회로 제각각 셌다 → 세는 기준을 코드로 고정.
- seed 02(invalid user 1회 후 공개키 로그인)가 FP/INCONCLUSIVE/TC로 갈렸다 → "invalid user 후 공개키는 Q1 정상" 추가.
- EC2에서 root 실패 2회를 LLM이 "root 대상"이라는 이유로 THREAT_CONFIRMED로 판정했다 → `[원칙 7 기준]`을 코드가 계산.
- EC2에서 접속만 하고 끊은 탐침(실패 0회)이 규칙이 없어 INCONCLUSIVE → 탐침 규칙 추가.

**코드 뒷받침**: `fetch_auth_log`가 IP 하나로 거른 조회에서 로그인 성공이 없으면 `[원칙 7 기준]`
(무차별 대입 / 단발성 / 탐침)을 계산해 summary와 `rule_checks`로 준다. 종료 관문이 기준과 다른 판정을 거부하고,
기준과 같은 판정은 신뢰도 숫자가 모자라도 승인한다. 로그인 성공이 있는 경우(Q2·Q3가 필요한 경우)는 코드 기준을 내지 않는다.

### 원칙 8. 데이터 유출·외부 통신 판단

**지시**
- 민감 디렉터리를 압축해 외부로 전송(curl -T, scp, rsync, nc 등)하면 강한 유출 신호다. "정상 백업일 수 있다"는
  가능성만으로 신뢰도를 낮추지 않는다(백업 절차와 일치한다는 근거가 있어야 한다).
- network의 Suricata alert signature는 그 자체로 이례적 통신이다. network 도구는 전송 바이트 수를 주지 않으므로
  "전송량이 없다"는 이유로 유출 가능성을 낮추지 않는다. audit 전송 명령의 목적지와 network의 dest_ip가 일치하는지 본다.

**왜 생겼나**: 0918 시나리오 05(민감 디렉터리 압축 → 외부 업로드 → 흔적 삭제)를 "백업일 수 있다", "명확한 유출
트래픽 없음"으로 약하게 판정하는 것을 막기 위한 원칙. 1차 탐지팀 정규화는 flow 이벤트(바이트 수)를 버리고
http/alert만 남긴다는 데이터 한계도 여기서 설명한다.

**코드 뒷받침**: network 도구 summary의 `[조회 구간 전체 집계]`가 alert signature와 목적지를 전체 기준으로 보여 준다.

### 원칙 9. 웹 요청 반복·스캔 사건의 판단 절차

**지시**
- 횟수는 summary의 집계를 쓰고, src_ip로 거른 조회면 `[원칙 9 기준]` 결과를 그대로 대입한다.
- 해석 규칙: **User-Agent는 정상 근거가 아니다**(요청자가 마음대로 적는 값). **5xx는 차단이 아니다**(서버가 처리 못함).
  **/xmlrpc.php는 로그인에 실패해도 200**을 준다 — 2xx는 정상 연동·인증 성공의 근거가 아니다.

| 조건 (같은 src_ip) | 판정 |
|---|---|
| 인증·원격호출 엔드포인트(xmlrpc, wp-login, 로그인 경로)에 POST 10회 이상 | THREAT_CONFIRMED "웹 인증 무차별 대입/XML-RPC 남용 시도" (LOW~MEDIUM) |
| 서로 다른 경로 20개 이상 + 4xx 과반 | THREAT_CONFIRMED "웹 경로·취약점 스캔" (LOW) |
| 위 기준 미만 + 침해 신호 없음 | FALSE_POSITIVE |
| **[침해 신호]** audit `[후속 침해 확인]`에 웹 서버 계정의 셸·의심 명령 | THREAT_CONFIRMED, severity **HIGH 이상** |

필요한 사실은 web 도구로 모두 확인할 수 있으므로 침해 신호가 없는 한 INCONCLUSIVE 금지.

**왜 생겼나**
- EC2 xmlrpc 사건(POST 31회, 전부 503)을 LLM이 web 1회만 보고 "User-Agent가 Jetpack이다", "503으로 차단됐다"는
  이유로 FALSE_POSITIVE로 판정했다.
- 로컬 재현(POST 81회, 전부 200, Jetpack UA)에서 원칙을 알고도 "Jetpack 정상 연동"으로 FP를 내는 실행이 반복됐다.
- audit이 200건을 넘으면 뒤쪽에 숨은 웹셸 실행(www-data `curl | sh`)을 못 보고 MEDIUM으로 약하게 판정했다.

**코드 뒷받침**: `fetch_web_log`가 `[원칙 9 기준]`을, `fetch_audit_log`가 `[후속 침해 확인]`을 계산하고,
종료 관문이 기준 충족인데 FP인 판정, 웹셸 신호가 있는데 HIGH 미만인 판정을 거부한다.

---

## 4. 강제 종료 턴 안내 (forced_termination_notice)

`forced_termination: true`면 최대 조사 횟수에 도달했거나 같은 사유로 종료가 연속 거부된 마지막 턴이다.
도구를 부를 수 없고, `final_verdict`를 반드시 채워야 한다. 증거가 부족하면 INCONCLUSIVE + 이유와 남은 unknowns.

코드 쪽 안전장치: 이 턴에서 LLM이 판정을 원칙과 어긋나게 뒤집으면, 앞서 LLM이 낸 원칙에 맞는 판정을 쓴다.
그래도 판정이 없으면 누적 신뢰도로 폴백 판정을 만든다.

---

## 5. 출력 형식 (output_schema)

LLM은 매 턴 이 JSON 하나로 답한다.

| 필드 | 의미 |
|---|---|
| `facts`, `hypotheses`, `unknowns` | 누적 최신본 (매 턴 전체를 다시 적음) |
| `new_evidence[]` | 이번 턴에 새로 확인한 증거. `raw_refs`(원본 참조), `confidence_contribution`, `contradicting` |
| `next_action` | `call_tool` 또는 `terminate` |
| `tool_call` | 부를 도구와 인자 (call_tool일 때) |
| `termination_reason` | `confidence_sufficient` / `no_more_evidence` (terminate일 때) |
| `attack_timeline` | 종료할 때만, 실제 기록 시각 순서 |
| `final_verdict` | verdict, confidence, severity, attack_type, affected_systems, summary(보고서 첫 줄), reasoning(원칙 6~9 중 무엇을 확인했는지) |
| `investigation_notes` | 추가 조사 제안 등 |

---

## 6. 규칙 (rules)

### 응답 형식
- 도구 호출 턴에는 `termination_reason`·`final_verdict`를 null로, 종료 턴에는 `tool_call`을 null로.
- 타임라인 시각은 seed의 trigger_time이 아니라 **도구 결과의 실제 기록 시각**. 반복 행위는 집계의 "실제 기록 시각 A~B"로 시작·끝 두 줄.
  - 왜: EC2 xmlrpc 보고서의 타임라인이 seed 시각(08:11)으로 나왔는데 실제 첫 요청은 07:52였다.
- `summary`는 보고서 첫 줄에 쓸 자연스러운 1~2문장, `reasoning`은 확인한 원칙 항목을 체크리스트처럼.

### 증거 기록
- **한 관찰 사실은 조사 전체에서 한 번만** 증거로 기록한다. "지금까지를 종합하면…" 같은 요약 증거 금지.
- `raw_refs`는 도구 결과의 원문을 그대로, **증거당 대표 10개까지**. 전체 건수는 description에 숫자로.
  - 왜: xmlrpc 사건에서 LLM이 raw_ref 109개를 옮겨 적다 출력 한도에 걸려 응답이 잘렸고 main.py 전체가 멈췄다.
- audit 여러 줄 이벤트는 raw_ref 하나만 적어도 시스템이 나머지 줄을 연결한다. `known_raw_refs`에 없는 참조를 만들지 않는다.
- 조회 결과 0건은 원본 참조가 없으므로 증거가 아니라 unknowns/notes에.
- `contradicting`은 "현재 주요 가설을 약화시키는가"다. "정상이었다"가 자동으로 반박은 아니다(가설이 "정상 관리 행위"면 지지).

### 신뢰도 산정 (confidence_contribution)
같은 유형의 신호는 항상 같은 크기로 — 재현성을 위해.

| 신호 | 크기 |
|---|---|
| 강한 신호 (브루트포스 성공, 악성 명령 실행, 대량 유출) | ±0.20~0.30 |
| 중간 신호 (정상 인증 방식 확인, 의심 파일 접근) | ±0.10~0.15 |
| 약한 신호 (통신 없음 확인, 단일 정상 로그인) | ±0.05 |
| 다른 계층이 같은 행위를 기록 (교차 확인, 예: 같은 요청이 web과 Suricata에) | ±0.05 |

- 방금 관찰한 도구 결과만 근거로 하고, 이미 반영한 증거를 다시 세지 않는다.
- 반박 증거도 양수로 적는다(시스템이 빼 준다).
- 왜 교차 확인 ±0.05: 같은 요청 150건이 network·web 증거로 두 번 +0.25씩 반영돼 신뢰도가 부풀었다.

### 판정과 신뢰도의 일관성
- INCONCLUSIVE면 confidence 0.45~0.60. 반대로 0.45~0.60이면 반드시 INCONCLUSIVE(확정 판정 금지).
- "정상 쪽으로 기운다"는 느낌만으로 0.5~0.6대에 확정 판정을 붙이지 않는다 — 방향성과 확정성은 다르다.

---

## 7. 원칙과 코드의 대응 — 바꿀 때 함께 고칠 곳

| 원칙 | 프롬프트 | 코드 (숫자 계산) | 코드 (종료 관문) |
|---|---|---|---|
| 1 로그 미확보 | 원칙 1 | 도구 `window_total`, `log_source.filtered_out_hint()` | `loop._verdict_conflicts()` |
| 2 조회 구간 | 원칙 2 | `prompts.layer_query_windows()` | — |
| 4 종료 조건·사전 조회 | 원칙 4 | `loop.network_precheck_args()` | `loop._termination_rejections()` |
| 5 로그인 후 audit | 원칙 5 | — | `_termination_rejections()` (e) |
| 7 SSH | 원칙 7 | `fetch_auth_log.principle7_check()` | `_verdict_conflicts()`, `_rule_determined_verdict()` |
| 9 웹 | 원칙 9 | `fetch_web_log.principle9_check()`, `fetch_audit_log.audit_rule_check()` | `_verdict_conflicts()`, `_rule_determined_verdict()` |
| 증거 중복·원본 참조 | rules | `provenance.validate_citations()` | `loop._apply_decision()` |

**원칙의 기준값(예: 실패 5회, POST 10회, 경로 20개)을 바꿀 때는 yaml 문장과 도구의 상수를 같이 바꿔야 한다.**
한쪽만 바꾸면 LLM은 yaml대로 판정하고 관문은 코드 기준으로 거부해서, 조사가 강제 종료까지 끌려간다.

---

## 8. seed 생성 프롬프트 (`agent/seed_prompts.py`) — 참고

조사 프롬프트와 별개로, 로그 더미에서 조사할 사건을 고르는 경량 triage용 프롬프트다.
1차 탐지팀이 seed를 만들어 주게 되면 빠질 예정이라 yaml로 옮기지 않았다.

| 원칙 | 내용 |
|---|---|
| 1 | 로그에 실제로 나타난 내용만 근거로 |
| 2 | 후보는 0개일 수 있다 — 억지로 만들지 않는다 |
| 3 | 같은 원인의 여러 줄은 한 후보로 (같은 IP 실패 24회 = 후보 1개) |
| 4 | priority는 후보끼리의 상대 순위 (1이 가장 급함) |
| 5 | confidence_initial은 초기 추정치, 과신 금지 (보통 0.3~0.7) |
| 6 | evidence_refs는 입력 로그의 raw_ref 원문 그대로 — 코드가 실제 입력과 대조해 없는 참조면 멈춘다 |

---

## 9. 알려진 한계와 정책 결정이 필요한 것

- 원칙 6·8은 코드 뒷받침이 없어 LLM 판단에 의존한다(0918 seed로는 일관된 결과).
- 원칙 9의 기준값(POST 10회, 경로 20개)은 팀 판정 정책으로 정한 값이다. 실제 로그 분포를 보고 조정할 수 있다.
- `/.git/config` 같은 민감 파일 탐색(8건, 404)은 원칙 9 수치로는 FALSE_POSITIVE지만 LLM은 일관되게 THREAT_CONFIRMED(LOW)로 판정한다 — 팀 정책 결정 후 원칙 9에 명시할 것.
- "Jetpack 정상 연동" 같은 판단은 IP 소유를 확인하는 도구가 없어서 할 수 없다(현재는 횟수 기준만).
