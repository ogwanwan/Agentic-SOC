"""seed 생성(경량 LLM triage) — 수집한 로그에서 "조사할 사건" 후보와 우선순위를 뽑는다.

역할
  정규화된 로그 더미를 LLM에게 보여 주고 조사할 가치가 있는 후보(seed)를 받는다. 후보가
  인용한 원본 참조(evidence_refs)가 실제 입력 로그에 있는지 코드로 확인한 뒤 우선순위 순으로 돌려준다.
  1차 탐지팀이 seed를 만들어 주게 되면 이 단계는 필요 없어진다.

누가 부르나
  [10] agent/pipeline.py run_investigation_pipeline() → SeedGenerator(llm).generate()

무엇을 부르나
  [12] agent/seed_prompts.py  build_seed_user_prompt()   seed용 프롬프트 만들기
  [13-1] llm_client.complete_json()                      gemini_client.py / claude_client.py
  agent/provenance.py references()                       evidence_refs 검증

llm_client는 .complete_json(system_prompt, user_prompt)만 있으면 되므로 GeminiClient·ClaudeClient
둘 다 쓸 수 있고, 조사 단계와 다른(더 가벼운) 모델 인스턴스를 넘겨도 된다.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .seed_prompts import SEED_SYSTEM_PROMPT, build_seed_user_prompt
from .provenance import references

# [11] ← agent/pipeline.py [10]에서 생성·호출됨
class SeedGenerator:
    def __init__(self, llm_client: Any) -> None:
        self.llm_client = llm_client

    def generate(self, raw_logs: List[Dict[str, Any]], host: str) -> List[Dict[str, Any]]:
        """raw_logs를 스캔해서 seed 후보 리스트를 우선순위(priority 오름차순)로 정렬해 반환.
        candidates가 없으면 빈 리스트를 반환한다 (이상 없음으로 처리).
        """
        if not raw_logs:
            return []

        # [12] → agent/seed_prompts.py build_seed_user_prompt() — 로그 더미를 프롬프트로 만든다
        user_prompt = build_seed_user_prompt(raw_logs, host)
        # [13-1] → LLM 호출 (gemini_client.py / claude_client.py complete_json) — {"candidates": [...]}
        decision = self.llm_client.complete_json(SEED_SYSTEM_PROMPT, user_prompt)
        candidates = decision.get("candidates") or []
        # [13-2] 원본 참조 검증 (D: 원본 추적) — 후보의 evidence_refs가 [7]~[9]에서 실제로 읽은
        # raw_logs의 raw_ref인지 agent/provenance.py references()로 대조한다. 없는 참조를 인용하면
        # ValueError로 멈춘다 — LLM이 관측되지 않은 로그로 seed를 지어내는 것을 이 단계에서 막는다.
        # (조사 단계에서 loop.py가 validate_citations()로 하는 것과 같은 검사)
        known = {ref for record in raw_logs for ref in references(record)}
        for candidate in candidates:
            refs = references(candidate, seed=True)
            if known and (not refs or set(refs) - known):
                raise ValueError("seed evidence_refs must cite references from the input logs")
            if refs:
                candidate["evidence_refs"] = refs
        # priority가 없거나 이상한 값이면 가장 낮은 우선순위(맨 뒤)로 보낸다.
        candidates.sort(key=lambda c: c.get("priority", 999))

        # [14] → agent/pipeline.py [15]로 우선순위 순 seed 리스트를 돌려준다
        return candidates
