# C·D 구현 및 팀 연동 안내

> **S3 읽기 코드는 삭제됐다.** 로그는 `.env`의 `<계층>_LOG_LOCAL_PATH` 파일(EC2는 `/var/log/...`)에서만 읽는다. 아래의 S3 객체·`s3://` 참조·S3 모사 테스트 설명은 기록으로만 남아 있고 현재 코드에는 해당하지 않는다. 현재 동작 흐름은 [AGENT_FLOW.md](AGENT_FLOW.md).

처음 테스트하는 팀원은 [A·B·C·D 통합 테스트와 쉬운 설명](ABCD_TEST_GUIDE.md)을 먼저 본다.
전체 연결 데모는 `python -m scripts.demo_abcd`이며, 수집 → seed → 실제 B/C 도구 → D 보고서까지 실행한다.

통합 작업 브랜치: `codex/merge-cd-investigation`
병합 대상: `feature/Agentic-SOC-Investigation-Agent` (`cb5005d`, 2026-09-23 A/B 작업 포함)

최신 조사 브랜치의 A/B 공통 정규화에 C/D 기능을 병합했다. 기존 C/D 이력(`8acaa75`)과
사용자가 변경한 문서 이력(`5cd8d2e`)도 병합 커밋의 부모 이력으로 보존한다.
첨부 역할표의 C(사건 Window 조회), D(raw_ref 전달·검증)를 구현했다.
탐지 규칙, 위협 분류 기준, 외부 LLM 모델은 변경하지 않았다.

## 실행해 보기

저장소 루트에서 Python 3.10 이상을 사용한다. 아래 검증과 데모에는 API 키가 필요 없다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m scripts.demo_event_window
```

데모는 `examples/cd/`의 합성 로그 4계층을 조회하고 `results/cd_demo.json`을 만든다.
총 4개 이벤트, 원본 5줄(audit 2줄 포함)의 참조가 유지되는 것을 확인할 수 있다.
데모의 판단 응답은 고정 Python 객체이며 실제 위협 판정 성능을 검증하는 용도가 아니다.
운영 실행에는 기존 `requirements.txt`와 `.env` 설정을 사용한다.

## C: 사건 event/window → 원본 로그 조회

새 도구는 `agent/tools/real/fetch_event_logs.py`의 `fetch_event_logs()`다.
`build_default_registry()`에 등록되어 Python 코드와 조사 LLM 모두 호출할 수 있다.

```python
import os
from agent.tools import build_default_registry

os.environ["WEB_LOG_LOCAL_PATH"] = "examples/cd/web.txt"
os.environ["AUTH_LOG_LOCAL_PATH"] = "examples/cd/auth.txt"
os.environ["LOG_LOCAL_HOST"] = "web-01"

registry = build_default_registry()
page = registry.call("fetch_event_logs", {
    "host": "web-01",
    "window": ["2026-09-21T09:00:00+09:00", "2026-09-21T09:01:00+09:00"],
    "layers": ["web", "auth"],
    "filters": {
        "web": {"src_ip": "192.0.2.10"},
        "auth": {"user": "demo"},
    },
    "limit": 100,
    "offset": 0,
})
print(page["records"])
# has_more=True이면 같은 조건에서 offset=next_offset으로 후속 페이지 조회
```

지원 입력은 다음과 같다.

| 입력 | 의미 |
| --- | --- |
| `window: [start, end]` | 명시한 사건 구간. 양 끝 시각을 포함한다. |
| `event: {window: [...]}` | 1차 탐지 seed의 window를 그대로 사용한다. |
| `event: {timestamp: ...}` | 이벤트 시각 전후 각 300초. `before_seconds`, `after_seconds`로 조절한다. |
| `event: {trigger_time: ...}` | 기존 조사 seed의 시각도 지원한다. |
| `layers` | web/auth/audit/network. system은 audit 별칭이다. |
| `filters` | 계층별 IP, 사용자, PID 등의 조건. system 계층 조건은 audit 키로 지정한다. |

명시적 `window`가 `event.window`보다 우선한다. 계층 생략 시 `event.layer`를 사용하고,
그것도 없으면 4계층을 조회한다. 시간만 주면 해당 호스트·시간의 문맥 로그를 조회하며,
`event.entity`나 IP를 자동 필터로 쓰지 않는다. 필요한 조건은 `filters`로 명시한다.
HTTP 로그의 `host`는 웹 도메인일 수 있으므로 수집 서버 `host`는 별도 필수 입력이다.

내부 흐름은 다음과 같다.

1. 구간·페이지 인자를 검증하고 ISO 시각을 UTC로 변환한다. 시간대 없는 시각은 기존 정책대로 UTC다.
2. `log_source.read_documents()`가 `.env`의 `<계층>_LOG_LOCAL_PATH` 파일을 읽는다.
3. `normalizer_adapter.normalize_log_documents()`가 1차 탐지팀의 공통 정규화 함수를 호출한다.
   정규화된 필드를 펼치고 원본 위치를 붙인 뒤, 시간과 계층별 조건으로 필터링한다.
4. 계층별 결과를 시간순으로 합쳐 전역 페이지를 반환한다. 계층마다 offset을 적용하지 않는다.

응답에는 `records`, `count`, `total_matched`, `has_more`, `next_offset`,
`layer_counts`, `window`, `partial`, `errors`가 들어 있다. 파일이 없거나 읽기 권한이 없으면
해당 계층의 `not_found`/`permission_denied`와 `partial=True`를 반환한다.
날짜 없는 로그는 사건 구간에 속한다고 확인할 수 없어 제외한다.
네트워크·AWS 서비스 예외 등은 기존 루프의 도구 실패 처리로 전달된다.

연도가 없는 auth syslog는 공통 모듈의 year/dt 계약을 사용한다. 원본 dt 파티션이나
AUTH_LOG_YEAR 설정을 우선하며, 없으면 같은 해의 사건 구간에서는 해당 연도, 짧은 연도 경계
구간에서는 종료 날짜의 dt 힌트를 전달한다. 여러 해의 로그가 섞인 파일은 여전히 모호할 수 있다.

기존 `fetch_web_log`, `fetch_auth_log`, `fetch_audit_log`, `fetch_network_log`의 호출 방식은
유지했다. 네 도구는 동일한 소스·참조 어댑터로 연결된다. 프로세스 트리도 같은 참조를 사용한다.

## D: raw_ref 보존과 검증

```text
파일/S3 객체의 실제 줄
  → 기존 파서 + 원본 참조
  → seed.evidence_refs / 도구 records.raw_refs
  → AgentState의 참조 목록
  → Evidence.raw_refs
  → evidence_chain / contradicting_evidence / tools_called / JSON·텍스트 보고서
```

| 필드 | 역할 |
| --- | --- |
| `raw_ref` | 이벤트를 대표하는 원본 참조 한 개 |
| `raw_refs` | 이벤트·증거를 구성하는 전체 원본 참조 목록 |
| `seed.evidence_refs` | 1차 탐지가 선택한 근거 참조. 원문 그대로 유지 |
| `result.raw_refs` | seed와 실제 도구 결과에서 확보한 참조 전체 |
| `result.provenance` | 누락·알 수 없는 참조에 대한 검증 결과 |
| `result.raw_ref_locations` | 원본 참조에 대응하는 실제 파일/객체 위치 목록 |

로컬 `raw_ref`는 공통 정규화가 만든 `파일명:줄 번호`를 그대로 사용한다. 예를 들어
`auth.log:15`를 `/var/log/auth.log:15`로 덮어쓰지 않는다. 정확한 원본 위치는 별도로 남긴다.

```json
{
  "raw_ref": "auth.log:15",
  "raw_refs": ["auth.log:15"],
  "raw_ref_locations": {"auth.log:15": ["/var/log/auth.log:15"]}
}
```

S3는 임시 파일을 삭제한 뒤에도 찾을 수 있도록 `s3://bucket/key:줄 번호`를 사용한다.
여러 객체를 합쳐 정규화한 경우에도 실제 객체별 줄 번호로 되돌려 기록한다. 빈 줄과 파싱 실패
줄을 포함한 원본 번호를 유지하고, 필터·정렬·페이지 처리 뒤에 다시 매기지 않는다.

Audit 이벤트 조립은 공통 모듈에 맡긴다. 모듈이 반환한 `layer_data.raw_lines`의 모든 줄을
`raw_refs`와 실제 위치로 보존하고, 모델이 대표 참조만 인용해도 전체 그룹을 복원한다.
ENRICHED의 `\x1d`를 줄바꿈으로 오해하지 않으며, 객체 사이에 나뉜 audit 이벤트도 추적한다.
이전 독립 C/D 구현의 `(epoch, serial)` 자체 그룹핑은 제거했다. 현재 벤더 모듈은 보류 중인
serial을 기준으로 조립하므로 가까운 구간에서 serial이 재사용되면 합쳐질 수 있다. 이 동작은
1차 탐지와의 정규화 동일성을 위해 유지했으며, 수정 시 양쪽이 같은 벤더 버전을 사용해야 한다.

`agent/provenance.py`는 참조를 불투명한 문자열로 취급한다. 따라서 외부 탐지기가
`apache_access.log:88213` 같은 형식을 주면 경로를 임의로 바꾸지 않는다.
프롬프트에도 참조 인용을 요구하지만, 보존·검증 자체는 Python이 수행한다.

- seed 생성: 입력 로그에 참조가 있으면 후보에도 실제 입력에서 가져온 `evidence_refs`가 필수다.
  누락·가짜 참조는 `ValueError`로 차단한다.
- 조사 증거: 확보한 참조에 없는 값은 채택하지 않고 `provenance.issues`에 기록한다.
  잘못된 참조 또는 참조 없는 증거는 추적 가능한 조사에서 신뢰도를 증가시키지 않는다.
- 지지·반박 증거 모두 같은 규칙을 적용하며, 도구 실패나 관찰 버퍼 초기화 뒤에도 참조 목록은 남는다.
- 기존 참조 없는 입력도 실행 가능하지만 검증 성공으로 표시하지 않는다.

검증 상태 `passed`는 참조 전달·인용 검사를 통과했다는 의미다. `incomplete`는 누락 또는
잘못된 참조가 있고, `unavailable`은 검증할 참조가 없다. 이 상태는 보안 판정의 진위를
증명하지 않으며, 모델의 최종 verdict를 자동 변경하지 않는다. 외부 seed 참조의 파일 실존이나
증거 문장의 의미까지 검증하지는 않는다. 원본 파일의 교체·로그 회전에 대비한 불변 저장 또는
해시 검증은 별도 저장소 정책이 필요하다.

## A·B 통합에서 유지한 내용

- `primary_detection/normalizer/`는 대상 브랜치 `cb5005d`와 동일하게 유지했다.
- 삭제된 `agent/tools/parsers/`를 되살리지 않았다. 실제 파싱은 공통 함수가 담당한다.
- 웹은 Apache access 형식, 인증은 `event`/`src_ip`, 네트워크는 `signature`/`dest_ip` 등
  최신 필드명을 사용한다. 필터도 같은 필드에 대응한다.
- 네트워크 공통 모듈이 선택하는 http/alert 이벤트와 XFF 기반 src_ip 정책을 유지했다.
  기존 독립 C/D 데모의 flow 이벤트와 nginx JSON 예제는 새 계약에 맞게 변경했다.
- 기존 프로세스 트리 함수는 이동된 `real/get_process_tree.py`에 그대로 두고 참조 전달만 연결했다.
- 기존 `normalize_auth/audit/web/network` API의 완전 일치 테스트를 유지했다. 추가 메타데이터를
  제외하면 사건 조회·수집 결과의 모든 정규화 필드와 raw_ref도 벤더 직접 호출 결과와 같다.

외부 1차 탐지 seed의 `window`, `layer`, `evidence_refs`를 사용할 수 있다. 이를
`InvestigationAgent.run()`에 직접 넘길 때는 기존 계약의 `incident_id`와 수집 서버 `host`도
붙인다. `entity.value`로 조건을 좁히려면 계층별 `filters`를 명시한다.

## 검증 범위와 운영 메모

`tests/test_event_window.py`: 단일·다중 계층, 시간 양끝, 시간대, 연도 경계, 전역 페이지,
잘못된 인자, 파일 누락·권한, S3 객체 위치, audit 여러 줄 조립.

`tests/test_provenance.py`: 네 계층 수집/조회 정규화 동일성, seed→증거→JSON/텍스트,
반박 증거, 가짜/누락 참조, 프로세스 트리, 도구 실패 뒤 참조 유지, 기존 종료 관문 연동.
`tests/test_cd_normalizer_integration.py`: 네 계층 모두 벤더 직접 호출과 수집/조회 결과의
정규화 필드·raw_ref 동일성, 기존 A/B 어댑터 검사, S3 객체 간 audit 조립, gzip 원본 위치,
최종 보고서까지 실제 위치 전달을 검증한다. B의 개별 조회 도구도 동일성 비교에 포함한다.
최초 병합 시 88개였고, `tests/test_abcd_pipeline.py`의 전체 연결 검사 9개를 추가한 뒤
2026-09-23 새 가상환경에서 전체 97개가 통과했다. 단일/4계층, S3 모사(분할 audit·gzip),
가짜 seed/증거 참조 거부, 환경 설정 독립성을 포함한다.
기존 테스트도 함께 실행한다. `pytest.ini`는 오프라인 tests만 수집하고 실제 API를 쓰는
수동 재현성 스크립트 `tests/test_consistency.py`를 제외한다.

로컬 소스의 기존 샘플 재생 동작(현재 시각 필터 생략)은 수집 단계에 유지했다.
`RAW_LOG_LOCAL_MAX_LINES`는 참조와 audit 조립을 보존하기 위해 마지막 N개 **완성 이벤트**를
뜻하도록 바뀌었다. 사건 조회는 로컬 파일에도 항상 명시한 시간 구간을 적용한다.
로컬 파일은 한 수집 서버에 속한다고 가정하며 `LOG_LOCAL_HOST` 설정으로
다른 호스트 요청을 차단할 수 있다. `HOST`는 main.py의 수집 대상 이름이라 이 검사에
쓰지 않는다(합성 시나리오 seed의 host=web-01과 충돌하던 문제). S3는 host 파티션으로 구분한다.

조회는 기존처럼 파일/선택한 S3 객체를 읽고 메모리에서 필터링한다. 고정된 원본에서는 페이지
순서가 안정적이지만 조회 사이 로그 내용이 바뀌면 offset도 달라질 수 있다. 대규모 로그의
인덱싱과 조회 스냅샷은 이번 C/D 구현 범위에 포함하지 않았다.

동일한 basename 참조가 서로 다른 실제 경로에 대응하면 `ambiguous_raw_refs`로 표시하고
검증 상태를 incomplete로 둔다. 모호한 참조로는 신뢰도를 높이지 않는다.
