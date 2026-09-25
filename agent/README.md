# agent/

조사 에이전트(Investigation Agent) 패키지 본체입니다. 역할 분담 문서의 5개 항목이
아래 모듈에 각각 대응합니다.

| 역할 | 모듈 |
| --- | --- |
| Agent Loop 총괄 | `loop.py` (`InvestigationAgent`) |
| State / Evidence 관리 | `models.py` (`AgentState`, `Evidence`, `Hypothesis`) |
| Tool 연결·실행 계층 | `tools/` (`ToolRegistry`, `ToolSpec`, `build_default_registry`) — 자세한 건 [tools/README.md](tools/README.md) |
| Agent 판단·Prompt | `prompts.py`, `claude_client.py` (Claude), `gemini_client.py` (Gemini) |
| Agent 제어 + 최종 산출물 | `loop.py` 내 종료/중복/실패 처리 + `report.py` |
| 보고서 출력 | `report.py` (`build_investigation_result`) |

Triage가 파이프라인에서 빠지면서 추가된 전(前) 단계:

| 역할 | 모듈 |
| --- | --- |
| raw log 수집 | `raw_log_ingestion.py` (`fetch_recent_raw_logs`) |
| seed 생성(경량 triage) | `seed_prompts.py`, `seed_generation.py` (`SeedGenerator`) |
| 전체 파이프라인 연결 | `pipeline.py` (`run_investigation_pipeline`) |

## 로그 정규화는 여기서 직접 안 합니다

`raw_log_ingestion.py`(seed 생성용 raw 수집)와 `tools/real/*.py`(조사 도구) 둘 다
로그를 자기가 직접 파싱하지 않고, 1차 탐지팀이 만든 공통 정규화 함수를 가져다 씁니다.
그 함수들은 `agent/` 밖의 레포 루트 `primary_detection/normalizer/`에 있고,
`agent/tools/normalizer_adapter.py`가 그걸 가져다 쓰는 유일한 연결 지점입니다.
왜 이렇게 나눴는지는 [docs/normalizer-migration.md](../docs/normalizer-migration.md)에
정리돼 있습니다. (자체 파서 폴더 `tools/parsers/`는 완전히 없어졌습니다 —
마지막 남은 헬퍼 `process_tree.py`도 `tools/real/get_process_tree.py` 안으로 합쳤습니다.)

## 실행

```bash
python main.py
```

`.env`에 필요한 값은 `.env.example` 참고. 테스트는 [tests/README.md](../tests/README.md).
