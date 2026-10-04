"""대응 권고 실행 진입점 — `python -m respond.cli <final_report.json>` (설계서 9·10절).

역할
  ATT&CK 매핑까지 끝난 최종 보고서 하나를 읽어 권고문을 만든다.
      results/attack_mapping/<incident_id>_final_report.json
        → results/response/<incident_id>_response.json   기계용(대시보드 정렬·필터)
          results/response/<incident_id>_response.txt    사람용(대시보드가 그대로 출력)
          results/response/run_log.jsonl                 LLM 호출·검증·폐기된 조치

  매핑 코드를 건드리지 않고 매핑 결과 파일만 읽는다(설계서 2절 A안).

담당 A 모듈과의 연결 — 2026-10-04 실제 시그니처로 갱신
  처음 설계했던 build_response_plan(report)/extract_targets(report) 한 줄짜리 호출은
  A의 실제 구현과 맞지 않았다(아래가 A의 실제 함수들):

      respond/contract.py  read_contract(final_report: dict) -> Contract
      respond/gate.py       evaluate_gate(contract: Contract) -> GateResult
      respond/decide.py    build_response_plan(contract: Contract, gate: GateResult) -> ResponsePlan
          관문(4절)·대상 추출(5절)·카탈로그(6절)·자율성 라벨과 하향 규칙(7절)까지 적용한
          ResponsePlan을 돌려준다. summary·analyst_note·actions[].reason은 비워 둔다(LLM이 채움).
      respond/entities.py  extract_entities(contract: Contract) -> tuple[Entity, ...]
          5절 출처(seed detail·src_ip·tool_input)에서 뽑은 조치 대상 엔티티.
          entity.value 집합을 llm.py가 "조치의 target이 실제 출처에 있는가"(검증 규칙 1)에 쓴다.

  증거 목록(evidence_chain)·기법 집합(technique_ids)은 입력 보고서에서 이 파일이 직접 읽어
  plan.evidence_refs에 넣는다 — A가 따로 넘기지 않아도 된다.

누가 부르나
  사람이 직접: python -m respond.cli results/attack_mapping/INC-xxxx_final_report.json
  나중에 main.py(설계서 2절 A안): respond.cli.process_file(<final_report 경로>)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# respond/ 패키지를 절대 경로로 import하기 위해 llm/ 디렉터리를 sys.path에 올린다
_LLM_DIR = str(Path(__file__).resolve().parents[1])
if _LLM_DIR not in sys.path:
    sys.path.insert(0, _LLM_DIR)

from respond import investigate_bridge, run_log  # noqa: E402
from respond.llm import LLMStageReport, run_llm_stage  # noqa: E402
from respond.models import ResponsePlan  # noqa: E402
from respond.render import render_plan  # noqa: E402

DEFAULT_OUT_DIR = os.path.join("results", "response")

# 담당 A 모듈이 아직 없을 때 보여 줄 안내
_MISSING_DECISION_MODULES = (
    "결정 로직 모듈을 찾지 못했습니다 — respond/contract.py의 read_contract(), "
    "respond/gate.py의 evaluate_gate(), respond/decide.py의 build_response_plan(), "
    "respond/entities.py의 extract_entities()가 필요합니다(담당 A).\n"
    "    네 함수가 준비되면 이 CLI는 그대로 동작합니다. "
    "LLM·렌더링(담당 B)만 따로 확인하려면 tests/test_respond_llm_guard.py, "
    "tests/test_respond_render.py를 실행하십시오."
)


class DecisionModulesMissing(RuntimeError):
    """담당 A의 결정 로직 모듈이 아직 없을 때."""


def _load_decision_functions() -> Tuple[Any, Any, Any, Any]:
    """담당 A 모듈을 늦게 import한다 — 없어도 llm.py·render.py는 단독으로 테스트할 수 있게."""
    try:
        from respond.contract import read_contract  # type: ignore[attr-defined]
        from respond.decide import build_response_plan  # type: ignore[attr-defined]
        from respond.entities import extract_entities  # type: ignore[attr-defined]
        from respond.gate import evaluate_gate  # type: ignore[attr-defined]
    except ImportError as exc:
        raise DecisionModulesMissing(f"{_MISSING_DECISION_MODULES}\n    (원인: {exc})") from exc
    return read_contract, evaluate_gate, build_response_plan, extract_entities


# ----------------------------------------------------------------------
# 입력 읽기 / 출력 경로
# ----------------------------------------------------------------------

def load_final_report(path: str) -> Dict[str, Any]:
    """final_report.json을 읽는다. 최상위가 객체가 아니면 오류."""
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)
    if not isinstance(report, dict):
        raise ValueError(f"최종 보고서가 JSON 객체가 아닙니다: {path}")
    return report


def technique_ids(report: Dict[str, Any]) -> Set[str]:
    """attack_mapping.techniques[]의 technique_id 집합 — 기법 환각 검증(규칙 5)에 쓴다."""
    mapping = report.get("attack_mapping") or {}
    found: Set[str] = set()
    for technique in mapping.get("techniques") or []:
        if isinstance(technique, dict) and isinstance(technique.get("technique_id"), str):
            found.add(technique["technique_id"])
        parent = (technique or {}).get("parent_technique") if isinstance(technique, dict) else None
        if isinstance(parent, dict) and isinstance(parent.get("technique_id"), str):
            # 하위 기법(T1505.003)으로 매핑됐을 때 상위 기법(T1505) 조치도 허용한다
            found.add(parent["technique_id"])
    return found


def evidence_chain(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """증거 목록(반증 포함) — 프롬프트 재료이자 인용 검증(규칙 4)의 허용 목록."""
    chain = [e for e in (report.get("evidence_chain") or []) if isinstance(e, dict)]
    chain += [e for e in (report.get("contradicting_evidence") or []) if isinstance(e, dict)]
    return chain


def _output_stem(plan: Optional[ResponsePlan], source_path: str) -> str:
    """파일명 앞부분. 사건 id를 경로가 아닌 라벨로만 쓴다(매핑 cli.py와 같은 규칙)."""
    stem = (plan.incident_id if plan is not None else None) or ""
    if not stem.strip():
        base = os.path.basename(source_path)
        stem = base[: -len(".json")] if base.lower().endswith(".json") else base
    stem = re.sub(r"[^\w.-]", "_", stem).strip(" .")
    stem = stem.encode("utf-8")[:180].decode("utf-8", errors="ignore").rstrip(" .") or "response"
    if re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]", stem.split(".")[0], re.IGNORECASE):
        stem = "_" + stem
    return stem


def _reserve_output_paths(out_dir: str, stem: str) -> Tuple[str, str]:
    """재조사로 같은 사건이 다시 와도 앞 결과를 덮지 않는다(매핑과 같은 __2·__3 규칙)."""
    number = 1
    while True:
        candidate = stem if number == 1 else f"{stem}__{number}"
        json_path = os.path.join(out_dir, f"{candidate}_response.json")
        text_path = os.path.join(out_dir, f"{candidate}_response.txt")
        if not os.path.lexists(json_path) and not os.path.lexists(text_path):
            return json_path, text_path
        number += 1


def write_outputs(plan: ResponsePlan, out_dir: str, source_path: str) -> Dict[str, str]:
    """권고문 JSON·TXT를 함께 쓴다. 둘 다 만들어진 뒤에야 저장이 끝난 것으로 본다."""
    os.makedirs(out_dir, exist_ok=True)
    document = json.dumps(plan.to_dict(), ensure_ascii=False, indent=2)
    text = render_plan(plan)
    while True:
        json_path, text_path = _reserve_output_paths(out_dir, _output_stem(plan, source_path))
        try:
            with open(json_path, "x", encoding="utf-8") as f:
                f.write(document)
        except FileExistsError:
            continue  # 다른 실행이 같은 이름을 먼저 가져감 — 다음 번호로
        try:
            with open(text_path, "x", encoding="utf-8") as f:
                f.write(text)
        except FileExistsError:
            os.remove(json_path)
            continue
        return {"json": json_path, "txt": text_path}


# ----------------------------------------------------------------------
# 진입점
# ----------------------------------------------------------------------

def process_file(
    final_report_path: str,
    out_dir: str = DEFAULT_OUT_DIR,
    *,
    llm_client: Any = None,
) -> Dict[str, Any]:
    """최종 보고서 한 건 → 권고문 JSON·TXT. 만들어진 파일 경로가 담긴 dict를 돌려준다.

    llm_client를 넘기면 그것을 쓴다(main.py가 RESPONSE_* 클라이언트를 한 번만 만들어 재사용).
    LLM 실패는 여기서 멈추지 않는다 — 기본 근거 문장으로 권고문이 나간다.
    """
    report = load_final_report(final_report_path)
    read_contract, evaluate_gate, build_response_plan, extract_entities = _load_decision_functions()

    contract = read_contract(report)
    gate = evaluate_gate(contract)
    plan: ResponsePlan = build_response_plan(contract, gate)
    # schema.ResponsePlan은 evidence_refs를 채우지 않는다(A는 contract까지만 안다) —
    # 원본 evidence_chain은 여기서 직접 읽어서 붙인다. render.py의 [근거 추적] 구역이 이걸 쓴다.
    plan.evidence_refs = evidence_chain(report)
    targets: Set[str] = {entity.value for entity in extract_entities(contract)}

    llm_report: LLMStageReport = run_llm_stage(
        plan,
        evidence_chain=evidence_chain(report),
        allowed_targets=targets,
        allowed_technique_ids=technique_ids(report),
        llm_client=llm_client,
    )

    outputs = write_outputs(plan, out_dir, final_report_path)

    try:
        run_log.append_run_log(
            run_log.build_entry(
                plan,
                source_path=final_report_path,
                llm_report=llm_report,
                output_paths=outputs,
            ),
            out_dir,
        )
    except OSError as exc:  # 기록 실패가 권고문을 무효로 만들지는 않는다
        print(f"[respond] run_log 기록 실패(권고문은 저장됨): {exc}")

    return {
        "incident_id": plan.incident_id,
        "response_status": plan.response_status,
        "action_count": len(plan.actions),
        "used_fallback": llm_report.used_fallback,
        "output_paths": outputs,
    }


def summary_line(result: Dict[str, Any]) -> str:
    """사건별 한 줄 요약 — main.py가 매핑처럼 콘솔에 찍을 때 쓴다."""
    note = " (LLM 미사용·기본 문장)" if result.get("used_fallback") else ""
    return (f"대응 권고: {result['response_status']} "
            f"(조치 {result['action_count']}건){note}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="ATT&CK 매핑까지 끝난 최종 보고서를 읽어 대응 권고문을 만든다.")
    parser.add_argument("final_report", help="results/attack_mapping/<사건>_final_report.json 경로")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="권고문 저장 폴더 (기본: %(default)s)")
    parser.add_argument("--no-llm", action="store_true",
                        help="LLM을 부르지 않고 카탈로그 기본 문장만 쓴다(오프라인 확인용)")
    args = parser.parse_args(argv)

    # 저장소 루트 .env 하나에서 RESPONSE_* 설정을 읽는다(조사·매핑과 같은 파일)
    investigate_bridge.load_root_env()

    client: Any = None
    if args.no_llm:
        class _Disabled:
            model = "(사용 안 함)"

            def complete_json(self, system_prompt: str, user_prompt: str):
                raise RuntimeError("--no-llm 지정")

        client = _Disabled()

    try:
        result = process_file(args.final_report, args.out_dir, llm_client=client)
    except DecisionModulesMissing as exc:
        print(f"[respond] {exc}")
        raise SystemExit(2)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[respond] 최종 보고서를 읽지 못했습니다: {exc}")
        try:
            run_log.append_run_log(
                run_log.build_entry(None, source_path=args.final_report, error=str(exc)),
                args.out_dir,
            )
        except OSError:
            pass
        raise SystemExit(1)

    print(f"[respond] {result['incident_id']}: {summary_line(result)}")
    for label, path in result["output_paths"].items():
        print(f"  {label}: {path}")


if __name__ == "__main__":
    main()
