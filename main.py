"""조사 에이전트 실행 진입점 — `python main.py`.

역할
  .env 설정을 읽고, 도구 레지스트리와 LLM 클라이언트를 만든 뒤 전체 조사 파이프라인
  (로그 수집 → 조사할 사건(seed) 고르기 → 사건별 조사 → 보고서)을 한 번 실행한다.
  결과는 콘솔에 텍스트 보고서로 보여 주고, 원본 JSON은 results/에 저장한다.

누가 부르나
  사람이 직접 실행한다 (EC2: `python3 main.py`).

무엇을 부르나
  [2] agent/tools/registry.py   build_default_registry()   조사 도구 목록 만들기
  [3] agent/gemini_client.py    GeminiClient()             LLM 클라이언트 (LLM_PROVIDER=anthropic이면 claude_client.py)
  [4] agent/pipeline.py         run_investigation_pipeline() 전체 파이프라인 실행
  [45] agent/report.py          format_text_report()       JSON → 사람이 읽는 텍스트 보고서

실행 준비
  1. `pip install -r requirements.txt`
  2. .env에 GEMINI_API_KEY(또는 LLM_PROVIDER=anthropic + ANTHROPIC_API_KEY)
  3. .env에 계층별 로그 파일 경로(WEB/AUTH/AUDIT/NETWORK_LOG_LOCAL_PATH)와 HOST(수집 서버 이름)
     — EC2라면 /var/log/... 경로 (.env.example 참고)

결과 저장
  텍스트 보고서는 따로 저장하지 않는다. format_text_report()가 JSON으로 언제든 다시 만들 수
  있어서 JSON만 "원본"으로 results/<investigation_id>_<UTC시각>.json에 보관한다.
  전체 동작 흐름은 docs/AGENT_FLOW.md 참고.
"""

import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

from agent import ClaudeClient, GeminiClient, build_default_registry, run_investigation_pipeline
from agent.report import format_text_report

load_dotenv()  # .env 파일에서 GEMINI_API_KEY / ANTHROPIC_API_KEY / HOST 등을 읽어온다

RESULTS_DIR = "results"


def build_llm_client():
    """LLM_PROVIDER 환경변수로 Gemini/Claude를 선택한다. 기본값은 gemini."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider == "anthropic":
        return ClaudeClient()  # ANTHROPIC_API_KEY 환경변수 필요
    if provider == "gemini":
        return GeminiClient()  # GEMINI_API_KEY 환경변수 필요 (무료 티어 가능)
    raise ValueError(f"알 수 없는 LLM_PROVIDER입니다: {provider} (gemini 또는 anthropic만 지원)")


def save_investigation_result(result: dict, output_dir: str = RESULTS_DIR) -> str:
    """조사 결과(investigation_result JSON)를 파일로 저장하고 저장된 경로를 반환한다.

    파일명은 {investigation_id}_{저장시각 UTC}.json 형태다. investigation_id만으로는
    같은 incident가 재조사될 경우 파일명이 겹칠 수 있어(build_investigation_result()가
    날짜 기준 "-001" 고정 접미사를 붙이는 방식이라 하루에 여러 번 조사되면 동일해짐),
    저장 시각(초 단위)을 추가로 붙여 항상 고유하게 만든다.
    """
    os.makedirs(output_dir, exist_ok=True)

    investigation_id = result.get("investigation_id") or result.get("incident_id", "UNKNOWN")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{investigation_id}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return filepath


def main() -> None:
    # 조사 결과·seed에 기록되는 수집 서버 이름 (EC2: `hostname` 결과)
    host = os.environ.get("HOST") or "web-01"  # .env에 HOST= 로 비워 둔 경우도 기본값 사용

    # [2] → agent/tools/registry.py build_default_registry()
    #     agent/tools/real/ 폴더에서 "파일명 == 함수명"인 도구를 자동으로 찾아 등록한다.
    #     resolve_ip_geo는 구현은 있지만 지금 우선순위가 아니라서 뺀다.
    tool_registry = build_default_registry(exclude=["resolve_ip_geo"])
    # [3] → LLM 클라이언트 생성 (위 build_llm_client: 기본 Gemini, LLM_PROVIDER=anthropic이면 Claude)
    llm_client = build_llm_client()

    # [4] → agent/pipeline.py run_investigation_pipeline() — 수집·seed 생성·조사를 모두 여기서 한다
    # [44] ← 사건별 조사 결과(JSON dict) 리스트를 돌려받는다
    results = run_investigation_pipeline(
        host=host,
        llm_client=llm_client,
        tool_registry=tool_registry,
        max_calls=8,
        confidence_threshold=0.85,
        # 도구 1개만 보고 끝나는 조사를 막는 설정 (agent/loop.py 참고)
        network_precheck=True,      # seed에 src_ip가 있으면 network를 코드가 먼저 조회
        strict_termination=True,    # 종료 관문 강화 + 판정이 도구 계산 기준과 어긋나면 종료 거부
    )

    if not results:
        print(f"{host}의 최근 로그에서 조사할 만한 seed 후보가 없었습니다.")
        return

    # [45] 결과 출력·저장 → agent/report.py format_text_report()로 텍스트 보고서를 만들어 출력하고,
    #      원본 JSON은 results/에 저장해 콘솔에는 파일명만 참고 자료로 보여 준다.
    saved_paths = []
    for i, result in enumerate(results, start=1):
        saved_path = save_investigation_result(result)
        saved_paths.append(saved_path)
        print(f"\n{'='*10} 조사 {i}/{len(results)} — {result['incident_id']} {'='*10}")
        print(format_text_report(result))
        print(f"\n[참고 자료] 원본 조사 결과 JSON: {saved_path}")

    print(f"\n--- 저장된 조사 결과 JSON {len(saved_paths)}건 ---")
    for path in saved_paths:
        print(f"  {path}")


# [1] 시작점 — `python main.py`로 실행하면 main()이 불린다
if __name__ == "__main__":
    main()