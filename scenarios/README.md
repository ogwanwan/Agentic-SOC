# scenarios/

조사 에이전트의 판정 재현성을 검증하기 위해 만든 합성(synthetic) 로그 생성 스크립트
모음입니다. 실제 EC2 서버를 건드리지 않고, `sample_logs/*.log`에 특정 공격 시나리오에
해당하는 줄을 append하는 방식으로 동작합니다.

[2026-09-24] append 대상은 `.env`의 `*_LOG_LOCAL_PATH`가 가리키는 파일입니다
(`_log_paths.py`, 에이전트 도구가 실제로 읽는 파일과 같음). 예전처럼 `sample_web.log`/
`sample_network.log`에 고정으로 쓰면, `.env`가 `sample_apache_web.log`/`sample_network_recent.log`를
가리킬 때 도구가 시나리오 로그를 전혀 보지 못했습니다. 시나리오 seed의 host는 `web-01`이며,
`.env`에 `LOG_LOCAL_HOST`를 다른 값으로 두면 로컬 파일 조회가 거부되니 비워 두세요
(`HOST`는 검사에 쓰지 않습니다).

## 사용 흐름

1. (처음 한 번) 깨끗한 원본을 백업: `cp -r sample_logs sample_logs_orig`
2. 원하는 시나리오 스크립트 실행 → `sample_logs/*.log`에 로그 추가 + 콘솔에 `SEED` 딕셔너리 출력
3. 출력된 `SEED`를 JSON 파일로 저장해 `--seed-json`으로 넘기거나 `tests/test_consistency.py`에 붙여넣기
   (**`incident_id`가 의도한 시나리오와 일치하는지 꼭 확인** — 다른 시나리오로 착각하고 돌린 사고가 있었음)
4. `python -m tests.test_consistency --runs 8 --seed-json seed.json`으로 재현성 검증
5. 검증 끝나면 반드시 원본으로 복구: `rm -r sample_logs && cp -r sample_logs_orig sample_logs`
   (Windows PowerShell: `Remove-Item -Recurse sample_logs; Copy-Item -Recurse sample_logs_orig sample_logs`)

[2026-09-25] `sample_logs/`는 EC2 실제 트래픽이 들어 있어 git 추적에서 뺐습니다(`.gitignore`).
이제 `git checkout HEAD -- sample_logs`로는 복구되지 않으니 위의 `sample_logs_orig` 백업을 쓰세요.
샘플이 없으면 `scripts/fetch_sample_from_ec2.py`로 받거나 팀원에게 받으세요.

## 시나리오 목록

| 스크립트 | incident_id | 시나리오 | 판정 방향 | 재현성(n=8) |
|---|---|---|---|---|
| `generate_synthetic_scenario.py` | `CONSISTENCY-TEST-03` | 비밀번호 브루트포스(6회 실패 후 성공) → wget/chmod/리버스셸 실행 | THREAT_CONFIRMED | 88% |
| `generate_webshell_scenario.py` | `CONSISTENCY-TEST-04` | PHP 웹셸 업로드 → `?cmd=` 파라미터로 명령 실행 | THREAT_CONFIRMED | 100% |
| `generate_exfiltration_scenario.py` | `CONSISTENCY-TEST-05` | 정상 로그인 후 민감 디렉터리 압축 → 외부 업로드 → 흔적 삭제 | THREAT_CONFIRMED | 검증 중(API 한도로 2/8만 확보) |
| `generate_privesc_scenario.py` | `CONSISTENCY-TEST-06` | SUID `find` 악용 → euid=0 전환 → `/etc/shadow` 열람 (network 계층 없음) | 검증 예정 | 파서 검증만 완료 |
| `generate_persistence_scenario.py` | `CONSISTENCY-TEST-07` | authorized_keys 백도어 + crontab 등록 + 계정 생성 (audit 계층만) | 검증 예정 | 파서 검증만 완료 |

기존에 프롬프트/코드로 검증한 다른 두 시나리오(`ubuntu` 계정 sudo 접근=정상,
계정 탐색 후 로그인=애매)는 `tests/test_consistency.py`의 `SEED`를 직접 손으로 채워서
검증했고 별도 생성 스크립트는 없습니다.

## 새 시나리오를 추가할 때

각 스크립트는 동일한 패턴을 따릅니다:

1. `datetime`으로 정확한 사건 시각을 명시하고 `.timestamp()`로 epoch를 계산합니다
   (**손으로 epoch 숫자를 어림잡아 넣지 마세요** — `generate_exfiltration_scenario.py`
   초기 버전에서 7시간 어긋난 사고가 있었습니다).
2. `auth.log`는 syslog 형식(`Sep 14 20:30:00 ...`) 그대로 작성합니다.
3. `audit.log`는 ENRICHED 포맷(`type=SYSCALL ... key="exec"` + `\x1d` + `ARCH=... AUID="..."` 등)을
   그대로 재현해야 1차 탐지팀 공통 정규화(`primary_detection/normalizer/tools/fetch_audit_log.py`)가
   정상 파싱합니다.
4. web 로그는 **apache access 포맷**으로 씁니다(nginx JSON은 공통 정규화가 읽지 못해 0건이 됨):
   `<ISO8601 UTC> <req_id> <client_ip> 127.0.0.1 https <Host> "<METHOD> <path> HTTP/1.1" <status> <bytes> <dur_us> <pid> "<referer>" "<ua>" xff="-"`
5. network 로그는 Suricata eve.json 필드명을 그대로 씁니다. 공통 정규화는 **http/alert 이벤트만**
   읽고 flow 이벤트(`bytes_toserver` 등)는 버리므로, 판정에 필요한 신호는 alert(`alert.signature`)로
   넣으세요. **`src_ip`/`dest_ip` 방향을 실제 트래픽 방향과 일치시키세요.**
6. 로그를 만든 뒤에는 **API를 호출하기 전에 반드시 도구를 직접 호출해 `count`를 확인**하세요:
   ```powershell
   python -c "from agent.tools.real.fetch_audit_log import fetch_audit_log; import os; os.environ['AUDIT_LOG_LOCAL_PATH']='sample_logs/sample_audit.log'; r = fetch_audit_log({'host':'web-01','start_time':'...','end_time':'...'}); print(r['count'])"
   ```
   이 확인 없이 바로 `tests/test_consistency.py`를 돌리면, 도구가 증거를 못 찾아서 나오는
   결과와 프롬프트/판단 로직 자체의 문제를 구분하기 어렵습니다.

## 알려진 제약

- Gemini 무료 티어(`gemini-3.5-flash-lite`)는 **일일 요청 한도 500회**가 있습니다.
  시나리오당 8회 재현성 검증에 도구 호출까지 포함하면 회당 2~4회 API 호출이 나가서,
  하루에 검증할 수 있는 시나리오 수가 제한됩니다. 한도는 UTC 자정 기준으로 리셋됩니다.