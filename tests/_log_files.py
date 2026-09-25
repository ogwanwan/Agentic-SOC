"""테스트용 로그 파일 설치 도우미.

조사 도구는 `.env`의 `<계층>_LOG_LOCAL_PATH`가 가리키는 파일만 읽는다(S3 읽기는 2026-09-25 삭제).
테스트는 `{"<조각 이름>": {"<파일 이름>": bytes}}` 형태로 로그 조각을 넘기면, 계층별로 임시 폴더에
하나의 파일로 합쳐 쓰고 해당 환경변수를 그 파일로 설정한다. 조각 이름의 `source_type=<종류>`로
계층을 정하고(예: `raw/source_type=auditd/...`), 조각이 없으면 `layer`로 빈 파일을 만든다.
raw_ref가 `audit.log:3`처럼 실제 파일 이름으로 나오도록, 첫 조각의 파일 이름을 그대로 쓴다.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from typing import Dict, Iterable, Optional

SOURCE_TO_LAYER = {"apache": "web", "auth": "auth", "auditd": "audit", "suricata": "network"}
DEFAULT_NAME = {"web": "access.log", "auth": "auth.log", "audit": "audit.log", "network": "eve.json"}
LOG_ENVS = tuple(f"{layer.upper()}_LOG_LOCAL_PATH" for layer in DEFAULT_NAME)

_installed_dirs = []


def clear_log_envs() -> None:
    for name in LOG_ENVS:
        os.environ.pop(name, None)


def install_log_files(pieces: Dict[str, Dict[str, bytes]], layer: Optional[str] = None) -> None:
    """조각들을 계층별 파일로 합쳐 쓰고 `<계층>_LOG_LOCAL_PATH`를 설정한다."""
    by_layer: Dict[str, list] = {}
    for piece in sorted(pieces):
        match = re.search(r"source_type=([^/]+)", piece)
        piece_layer = SOURCE_TO_LAYER.get(match.group(1)) if match else layer
        for name in sorted(pieces[piece]):
            by_layer.setdefault(piece_layer, []).append((name, pieces[piece][name]))
    if layer and layer not in by_layer:
        by_layer[layer] = []
    for piece_layer, chunks in by_layer.items():
        directory = tempfile.mkdtemp(prefix="soc-test-log-")
        _installed_dirs.append(directory)
        name = chunks[0][0] if chunks else DEFAULT_NAME[piece_layer]
        data = b"".join(chunk if chunk.endswith(b"\n") else chunk + b"\n" for _, chunk in chunks)
        path = os.path.join(directory, name)
        with open(path, "wb") as f:
            f.write(data)
        os.environ[f"{piece_layer.upper()}_LOG_LOCAL_PATH"] = path


def uninstall_log_files(modules: Iterable[str] = ()) -> None:
    import sys

    clear_log_envs()
    while _installed_dirs:
        shutil.rmtree(_installed_dirs.pop(), ignore_errors=True)
    for module in modules:
        sys.modules.pop(module, None)
