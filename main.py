"""조사 에이전트 실행 진입점 — `python main.py <사건 파일>`.

역할
  1차 탐지가 넘긴 사건(Incident) 파일을 읽고, 도구 레지스트리와 LLM 클라이언트를 만든 뒤
  사건마다 조사를 끝까지 실행한다(사건 파일 읽기 → 사건별 조사 → 결과 JSON → ATT&CK 매핑).
  결과 JSON은 results/investigation_agent/에 저장하고, 저장한 파일로 바로 ATT&CK 매핑을 돌린다.
  콘솔에는 저장한 파일 경로와 사건별 매핑 상태 한 줄만 보여 준다.
  사건을 찾고 고르는 일(로그 수집·탐지·사건 묶기·우선순위)은 1차 탐지가 한다.

누가 부르나
  사람이 직접 실행한다 (EC2: `python3 main.py <사건 파일>`).

무엇을 부르나
  [2] agent/tools/registry.py   build_default_registry()   조사 도구 목록 만들기
  [3] agent/gemini_client.py    GeminiClient()             LLM 클라이언트 (LLM_PROVIDER=anthropic이면 claude_client.py)
  [4] agent/incident_input.py   load_incidents()           사건 파일 읽기 (JSON 객체·배열 또는 JSONL)
  [5] agent/pipeline.py         run_investigation_pipeline() 사건별 조사
  [45] main.py                  save_investigation_result() 결과 JSON 저장
  [46] attack_mapping/cli.py    process_file()             저장된 조사 JSON → ATT&CK 매핑·Kill Chain·최종 보고서

실행 준비
  1. `pip install -r requirements.txt`
  2. .env에 GEMINI_API_KEY(또는 LLM_PROVIDER=anthropic + ANTHROPIC_API_KEY)
  3. .env에 계층별 로그 파일 경로(APACHE/AUTH/AUDIT/SURICATA_LOG_PATH)와 HOST(수집 서버 이름)
     — EC2라면 /var/log/... 경로 (.env.example 참고). 조사 도구가 원본 로그를 다시 읽을 때 쓴다.
  4. 사건 파일: 1차 탐지 출력(한 줄에 Incident 한 건인 JSONL) 또는 직접 작성한 사건 JSON

결과 저장
  사건마다 results/investigation_agent/<investigation_id>_<UTC시각>.json에 보관한다.
  저장 직후 그 파일로 ATT&CK 매핑을 돌려 results/attack_mapping/에
  <incident_id>_attack_mapping.json과 <incident_id>_final_report.json을 만든다
  (`python -m attack_mapping.cli`와 같은 처리, 같은 사건이면 __2, __3 …).
  매핑이 실패해도 조사 결과 JSON은 이미 저장돼 있어 CLI로 매핑만 다시 돌릴 수 있다.
  사람이 읽는 텍스트 보고서는 만들지 않는다 — 최종 보고서(final_report.json)는 조사 결과에
  매핑 결과를 붙인 JSON이고, 이후 대응 권고 결과도 여기에 합친다.
  전체 동작 흐름은 docs/AGENT_FLOW.md, 매핑 연결부는 docs/AGENT_ATTACK_MAPPING_FLOW.md 참고.
"""

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

from agent import ClaudeClient, GeminiClient, build_default_registry, load_incidents, run_investigation_pipeline
from attack_mapping.cli import process_file
from attack_mapping.rules import ALL_RULES

load_dotenv()  # .env 파일에서 GEMINI_API_KEY / ANTHROPIC_API_KEY / HOST 등을 읽어온다

RESULTS_DIR = "results"
# 단계별 결과 폴더: 이후 단계(ATT&CK 매핑 등)가 붙으면 results/ 아래에 단계별 폴더를 나란히 둔다
INVESTIGATION_DIR = os.path.join(RESULTS_DIR, "investigation_agent")
ATTACK_MAPPING_DIR = os.path.join(RESULTS_DIR, "attack_mapping")


def build_llm_client():
    """LLM_PROVIDER 환경변수로 Gemini/Claude를 선택한다. 기본값은 gemini."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider == "anthropic":
        return ClaudeClient()  # ANTHROPIC_API_KEY 환경변수 필요
    if provider == "gemini":
        return GeminiClient()  # GEMINI_API_KEY 환경변수 필요 (무료 티어 가능)
    raise ValueError(f"알 수 없는 LLM_PROVIDER입니다: {provider} (gemini 또는 anthropic만 지원)")


def save_investigation_result(result: dict, output_dir: str = INVESTIGATION_DIR) -> str:
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


def run_attack_mapping(saved_path: str, output_dir: str = ATTACK_MAPPING_DIR) -> Optional[dict]:
    """[46] 저장된 조사 결과 JSON 파일로 ATT&CK 매핑을 실행하고 매핑 결과를 반환한다.

    메모리의 dict가 아니라 저장된 파일을 넘겨, 나중에 CLI로 다시 돌린 결과와 같게 한다.
    매핑 결과에는 "kill_chain"과 이번에 만든 파일 경로 "output_paths"가 붙는다.
    매핑이 실패해도 조사 결과는 이미 저장돼 있으므로 안내만 하고 None을 반환한다
    (다음 사건 조사·매핑은 계속된다). 지금은 Rule 매핑(ALL_RULES)이다 — RAG 매핑은 전환 중.
    """
    before = set(os.listdir(output_dir)) if os.path.isdir(output_dir) else set()
    try:
        mapping_result = process_file(saved_path, ALL_RULES, output_dir)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"[ATT&CK] 매핑 실패 — 조사 결과 JSON은 저장됨({saved_path}): {exc}")
        return None
    created = sorted(set(os.listdir(output_dir)) - before)
    mapping_result["output_paths"] = [os.path.join(output_dir, name) for name in created]
    return mapping_result


def mapping_summary(mapping_result: Optional[dict]) -> str:
    """사건별 매핑 상태 한 줄. 자세한 내용은 매핑 결과·최종 보고서 JSON에 있다."""
    if mapping_result is None:
        return "ATT&CK 매핑: 실패(위 안내 참고)"
    status = mapping_result["mapping_status"]
    if status == "error":
        return f"ATT&CK 매핑: error — {'; '.join(mapping_result['errors'])}"
    ids = ", ".join(step["technique_id"] for step in mapping_result.get("kill_chain", []))
    return f"ATT&CK 매핑: {status} (기법 {len(mapping_result['techniques'])}개{': ' + ids if ids else ''})"


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="1차 탐지 사건 파일을 읽어 사건마다 조사한다.")
    parser.add_argument("incidents", help="사건 파일 경로 (JSON 객체·배열 또는 한 줄에 한 건인 JSONL)")
    args = parser.parse_args(argv)

    # 조사 결과·사건에 기록되는 수집 서버 이름 (EC2: `hostname` 결과). 1차 탐지 Incident에는 host가 없다.
    host = os.environ.get("HOST") or "web-01"  # .env에 HOST= 로 비워 둔 경우도 기본값 사용

    # [4] → agent/incident_input.py load_incidents() — 파일 형식 오류는 LLM 클라이언트를 만들기 전에 알린다
    incidents = load_incidents(args.incidents)
    if not incidents:
        print(f"{args.incidents}에 조사할 사건이 없습니다.")
        return

    # [2] → agent/tools/registry.py build_default_registry()
    #     agent/tools/real/ 폴더에서 "파일명 == 함수명"인 도구를 자동으로 찾아 등록한다.
    #     resolve_ip_geo는 구현은 있지만 지금 우선순위가 아니라서 뺀다.
    tool_registry = build_default_registry(exclude=["resolve_ip_geo"])
    # [3] → LLM 클라이언트 생성 (위 build_llm_client: 기본 Gemini, LLM_PROVIDER=anthropic이면 Claude)
    llm_client = build_llm_client()

    # [5] → agent/pipeline.py run_investigation_pipeline() — 사건을 받은 순서대로 조사한다
    # [44] ← 사건별 조사 결과(JSON dict) 리스트를 돌려받는다
    results = run_investigation_pipeline(
        incidents,
        host=host,
        llm_client=llm_client,
        tool_registry=tool_registry,
        max_calls=8,
        confidence_threshold=0.85,
        # 도구 1개만 보고 끝나는 조사를 막는 설정 (agent/loop.py 참고)
        network_precheck=True,      # 사건에 src_ip가 있으면 network를 코드가 먼저 조회
        strict_termination=True,    # 종료 관문 강화 + 판정이 도구 계산 기준과 어긋나면 종료 거부
    )

    # [45] 결과 저장 → 사건마다 결과 JSON을 results/investigation_agent/에 저장한다
    # [46] 저장된 JSON으로 바로 ATT&CK 매핑 → results/attack_mapping/에 매핑 결과·최종 보고서 저장
    saved = []
    mapping_paths = []
    for result in results:
        saved_path = save_investigation_result(result)
        mapping_result = run_attack_mapping(saved_path)
        saved.append((saved_path, mapping_summary(mapping_result)))
        if mapping_result is not None:
            mapping_paths.extend(mapping_result["output_paths"])

    print(f"\n--- 저장된 조사 결과 JSON {len(saved)}건 ---")
    for path, summary in saved:
        print(f"  {path}\n    {summary}")
    print(f"\n--- 저장된 ATT&CK 매핑·최종 보고서 JSON {len(mapping_paths)}건 ---")
    for path in mapping_paths:
        print(f"  {path}")


# [1] 시작점 — `python main.py <사건 파일>`로 실행하면 main()이 불린다
if __name__ == "__main__":
    main()