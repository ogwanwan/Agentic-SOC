"""LLM 클라이언트 공통 예외 — 클라이언트(Gemini/Claude)와 조사 루프가 함께 쓴다.

역할
  재시도 뒤에도 LLM API가 일시 오류(서버 과부하·요청 한도·연결 끊김·시간 초과)로 응답하지 않을 때
  각 클라이언트가 원래 SDK 예외를 이 예외로 감싸 올린다. 조사 루프는 이 예외면 그 사건만
  "조사 미완료(INCOMPLETE)"로 저장하고 다음 사건을 계속 조사한다. API 키·권한·요청 형식 오류(401·403·400)는
  감싸지 않고 그대로 올려 전체 실행을 멈춘다 — 설정을 고쳐야 하는 문제라 계속 돌려도 모두 실패한다.

누가 부르나
  agent/gemini_client.py, agent/claude_client.py   → raise LLMUnavailableError
  agent/loop.py InvestigationAgent.run()            → except LLMUnavailableError
"""


class LLMUnavailableError(Exception):
    """재시도 후에도 LLM API가 일시 오류로 응답하지 않음. 그 사건만 조사 미완료로 끝낸다."""
