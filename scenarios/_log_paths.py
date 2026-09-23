"""시나리오 생성기들이 로그를 append할 파일 경로를 정한다.

[2026-09-24] 예전엔 생성기마다 sample_logs/sample_web.log·sample_network.log에 고정으로
썼는데, .env의 *_LOG_LOCAL_PATH가 다른 파일(sample_apache_web.log, sample_network_recent.log
등)을 가리키고 있으면 에이전트 도구가 시나리오 로그를 전혀 못 보는 문제가 있었다.
그래서 에이전트 도구와 똑같이 .env의 *_LOG_LOCAL_PATH를 우선 쓰고, 없을 때만 기본값을 쓴다.
"""

import os

try:  # dotenv는 선택 의존성 — 없으면 이미 설정된 환경변수만 본다
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

DEFAULTS = {
    "web": "sample_logs/sample_apache_web.log",
    "auth": "sample_logs/sample_auth.log",
    "audit": "sample_logs/sample_audit.log",
    "network": "sample_logs/sample_network.log",
}


def log_path(layer: str) -> str:
    return os.environ.get(f"{layer.upper()}_LOG_LOCAL_PATH") or DEFAULTS[layer]
