"""agent/tools/normalizer_adapter.py(A: 공통 모듈 담당) 패리티 테스트.

완료 기준: "같은 Raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한 정규화 결과를
반환해야 한다." 조사 에이전트는 같은 저장소의 1차 탐지 원본
detection_pipeline/tools/*.py 를 복사본 없이 직접 import하므로, 이 테스트는 그 정규화
코드 자체가 아니라 "adapter가 1차 탐지 코드를 안 건드리고 그대로 호출하는지"를 검증한다.

2026-09-22 업데이트: web(apache)/network(suricata)도 추가해서 4개 계층
(auth/audit/web/network) 전부 커버한다 — E/F 작업으로 adapter.py에
normalize_web()/normalize_network()가 추가된 뒤로도 이 패리티 테스트가
auth/audit만 검증하고 있던 걸 뒤늦게 채움. 이걸로 A(공통 모듈)/B(조사 도구)
담당의 완료 기준이 4계층 전부에 대해 실제로 증명된다.

검증:
  로컬 모드: adapter.normalize_auth/normalize_audit/normalize_web/normalize_network
  결과가 1차 탐지 원본의 fetch_auth_log()/fetch_audit_log()/fetch_apache_log()/
  fetch_network_log()를 같은 샘플 파일에 직접 호출한 결과와 완전히 동일해야
  한다(raw_ref 포함). 샘플은 detection_pipeline/samples/를 쓴다.

pytest 없이도 llm/investigate/에서 `python -m tests.test_normalizer_parity`로 실행 가능.
"""

from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# llm/investigate/tests → 저장소 루트/detection_pipeline/samples
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(REPO_ROOT)), "detection_pipeline", "samples")
WIDE_WINDOW = ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"]


def _run() -> None:
    os.environ["AUTH_LOG_PATH"] = os.path.join(SAMPLES, "sample_auth.log")
    os.environ["AUDIT_LOG_PATH"] = os.path.join(SAMPLES, "sample_audit.log")
    os.environ["APACHE_LOG_PATH"] = os.path.join(SAMPLES, "sample_access.log")
    os.environ["SURICATA_LOG_PATH"] = os.path.join(SAMPLES, "sample_eve.json")

    from agent.tools.normalizer_adapter import (
        normalize_auth,
        normalize_audit,
        normalize_web,
        normalize_network,
    )
    # adapter import가 detection_pipeline/을 sys.path에 올리고 원본 위치를 확인한 뒤라 tools.*가 원본이다
    from tools.fetch_auth_log import fetch_auth_log as vendor_fetch_auth
    from tools.fetch_audit_log import fetch_audit_log as vendor_fetch_audit
    from tools.fetch_apache_log import fetch_apache_log as vendor_fetch_web
    from tools.fetch_network_log import fetch_network_log as vendor_fetch_network

    # --- auth ---
    direct_auth = vendor_fetch_auth(os.environ["AUTH_LOG_PATH"], time_window=WIDE_WINDOW)
    via_adapter_auth = normalize_auth("web-01", WIDE_WINDOW[0], WIDE_WINDOW[1])
    assert len(direct_auth) > 0, "샘플 auth 로그에서 이벤트가 하나도 안 나오면 샘플/파서가 깨진 것"
    assert direct_auth == via_adapter_auth, (
        f"auth 패리티 실패: 직접 호출 {len(direct_auth)}건 vs adapter {len(via_adapter_auth)}건"
    )

    # --- audit ---
    direct_audit = vendor_fetch_audit(os.environ["AUDIT_LOG_PATH"], time_window=WIDE_WINDOW)
    via_adapter_audit = normalize_audit("web-01", WIDE_WINDOW[0], WIDE_WINDOW[1])
    assert len(direct_audit) > 0, "샘플 audit 로그에서 이벤트가 하나도 안 나오면 샘플/파서가 깨진 것"
    assert direct_audit == via_adapter_audit, (
        f"audit 패리티 실패: 직접 호출 {len(direct_audit)}건 vs adapter {len(via_adapter_audit)}건"
    )

    # --- web(apache) ---
    direct_web = vendor_fetch_web(os.environ["APACHE_LOG_PATH"], time_window=WIDE_WINDOW)
    via_adapter_web = normalize_web("web-01", WIDE_WINDOW[0], WIDE_WINDOW[1])
    assert len(direct_web) > 0, "샘플 apache 로그에서 이벤트가 하나도 안 나오면 샘플/파서가 깨진 것"
    assert direct_web == via_adapter_web, (
        f"web 패리티 실패: 직접 호출 {len(direct_web)}건 vs adapter {len(via_adapter_web)}건"
    )

    # --- network(suricata) ---
    direct_network = vendor_fetch_network(os.environ["SURICATA_LOG_PATH"], time_window=WIDE_WINDOW)
    via_adapter_network = normalize_network("web-01", WIDE_WINDOW[0], WIDE_WINDOW[1])
    assert len(direct_network) > 0, "샘플 suricata 로그에서 이벤트가 하나도 안 나오면 샘플/파서가 깨진 것"
    assert direct_network == via_adapter_network, (
        f"network 패리티 실패: 직접 호출 {len(direct_network)}건 vs adapter {len(via_adapter_network)}건"
    )

    print(
        f"OK: auth {len(direct_auth)}건, audit {len(direct_audit)}건, "
        f"web {len(direct_web)}건, network {len(direct_network)}건 — "
        "adapter가 4계층 전부 1차 탐지 원본과 완전 동일"
    )


if __name__ == "__main__":
    sys.path.insert(0, REPO_ROOT)
    _run()
