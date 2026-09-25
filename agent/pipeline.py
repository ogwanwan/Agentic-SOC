"""전체 조사 파이프라인 — raw log 수집 → seed(조사할 사건) 생성 → 우선순위 순 심층 조사.

역할
  조사 에이전트 한 번 실행의 뼈대. 로그를 모으고, LLM triage로 조사할 사건 후보를 뽑고,
  우선순위 순서대로 사건마다 InvestigationAgent(조사 루프)를 돌려 결과를 모은다.

누가 부르나
  [4]  main.py main()                      → run_investigation_pipeline()
  tests/test_pipeline.py, tests/test_abcd_pipeline.py, scripts/demo_abcd.py

무엇을 부르나
  [6]  agent/raw_log_ingestion.py  fetch_recent_raw_logs()   4계층 로그 파일 끝부분 수집
  [10] agent/seed_generation.py    SeedGenerator.generate()   LLM triage로 seed 후보 + 우선순위
  [16] agent/loop.py               InvestigationAgent.run()   seed 하나를 끝까지 조사

1차 탐지팀이 seed를 만들어 폴더에 넣는 방식으로 바뀌면 [6]·[10]은 "seed 폴더 읽기"로 대체되고,
[16] 조사 루프는 그대로 쓴다.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .loop import InvestigationAgent
from .raw_log_ingestion import fetch_recent_raw_logs
from .seed_generation import SeedGenerator

# [5] ← main.py [4]에서 호출됨
def run_investigation_pipeline(
    host: str,
    llm_client: Any,
    tool_registry: Any,
    minutes: int = 10,
    max_seeds: Optional[int] = None,
    max_calls: int = 8,
    confidence_threshold: float = 0.85,
    seed_generator: Optional[SeedGenerator] = None,
    network_precheck: bool = False,
    strict_termination: bool = False,
) -> List[Dict[str, Any]]:
    """전체 파이프라인을 한 번 돌린다.

    1. host의 4계층 로그 파일 끝부분(RAW_LOG_LOCAL_MAX_LINES건씩)을 모음
       (minutes는 연도 없는 auth 로그의 연도 추정 구간으로만 쓰인다)
    2. seed_generator(기본: llm_client와 동일한 모델)가 후보 seed를 뽑고 우선순위 정렬
    3. 우선순위 순서대로 (max_seeds개까지) 각 seed를 InvestigationAgent.run()에 넣어 심층 조사
    4. 각 조사 결과(investigation_result)를 우선순위 순서 그대로 리스트로 반환

    seed_generator를 따로 넘기면(예: 더 가벼운 모델의 GeminiClient) triage 단계와
    조사 단계에 서로 다른 모델을 쓸 수 있다. 안 넘기면 llm_client를 그대로 재사용한다.
    """
    # [6] → agent/raw_log_ingestion.py fetch_recent_raw_logs()
    #     4계층 로그를 공통 정규화한 이벤트 리스트를 받는다 (각 이벤트에 raw_ref = 원본 파일:줄)
    raw_logs = fetch_recent_raw_logs(host=host, minutes=minutes)

    # [10] → agent/seed_generation.py SeedGenerator.generate()
    # [15] ← LLM이 고른 seed 후보들이 우선순위(priority 오름차순)로 정렬되어 돌아온다
    generator = seed_generator or SeedGenerator(llm_client)
    seeds = generator.generate(raw_logs, host=host)

    if max_seeds is not None:
        seeds = seeds[:max_seeds]

    results: List[Dict[str, Any]] = []
    # [16] → agent/loop.py InvestigationAgent.run(seed) — seed마다 새 조사 루프를 만들어 끝까지 조사
    for seed in seeds:
        agent = InvestigationAgent(
            llm_client,
            tool_registry,
            max_calls=max_calls,
            confidence_threshold=confidence_threshold,
            network_precheck=network_precheck,  # src_ip seed는 network를 코드가 먼저 조회 (loop.py 참고)
            strict_termination=strict_termination,  # 조기 종료 관문 강화 (loop.py _termination_rejections)
        )
        results.append(agent.run(seed))  # [42] ← 조사 결과 JSON(dict) 하나
    # [43] → main.py [44]로 사건별 결과 리스트를 돌려준다
    return results