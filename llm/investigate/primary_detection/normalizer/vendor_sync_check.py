"""1차 탐지팀 저장소(feature/primary-detection)와 이 폴더(primary_detection/normalizer/)의
벤더 코드가 여전히 바이트 단위로 동일한지 확인하는 스크립트.

정규화 로직은 여기서 수정하면 안 된다 — 완료 기준("같은 raw 로그에 대해 1차 탐지와
에이전트 도구가 동일한 정규화 결과를 반환해야 한다")이 깨진다. 1차 탐지팀이 파서를
고치면, 이 스크립트로 최신 버전과 diff를 확인하고 그대로 다시 복사해오면 된다.

(2026-09-22: agent/tools/normalizer/ 에서 레포 루트의 primary_detection/normalizer/로
이동했다 — "1차 탐지팀 산출물"이지 "에이전트 코드"가 아니라는 걸 폴더 구조로 명확히
하기 위함. agent/tools/normalizer_adapter.py 문서 참고.)

사용법:
  python primary_detection/normalizer/vendor_sync_check.py
  (선택) python primary_detection/normalizer/vendor_sync_check.py --repo-url <다른 URL> --branch <다른 브랜치>
"""
from __future__ import annotations

import argparse
import filecmp
import os
import subprocess
import sys
import tempfile

DEFAULT_REPO_URL = "https://github.com/ogwanwan/Agentic-SOC.git"
DEFAULT_BRANCH = "feature/primary-detection"

# (벤더 위치, 원본 저장소 내 경로) 쌍
VENDORED_FILES = [
    ("common/schema.py", "common/schema.py"),
    # 2026-09-24: 1차 탐지팀 b300d41(09-23)에서 시각 파싱·IP/경로 처리가 이 두 파일로 분리됨
    ("common/timeparse.py", "common/timeparse.py"),
    ("common/network.py", "common/network.py"),
    ("tools/base.py", "tools/base.py"),
    ("tools/registry.py", "tools/registry.py"),
    ("tools/normalize.py", "tools/normalize.py"),
    ("tools/fetch_apache_log.py", "tools/fetch_apache_log.py"),
    ("tools/fetch_auth_log.py", "tools/fetch_auth_log.py"),
    ("tools/fetch_network_log.py", "tools/fetch_network_log.py"),
    ("tools/fetch_audit_log.py", "tools/fetch_audit_log.py"),
]

HERE = os.path.dirname(os.path.abspath(__file__))


def _same_content(a: str, b: str) -> bool:
    """줄바꿈(CRLF/LF)만 다른 경우는 같은 파일로 본다.

    Windows에서 git이 체크아웃할 때 CRLF로 바꾸는 경우가 있어, 바이트 비교만 하면
    내용이 같은데도 전부 "내용 다름"으로 나와 실제 갱신 여부를 알 수 없었다(2026-09-24).
    """
    if filecmp.cmp(a, b, shallow=False):
        return True
    with open(a, "rb") as fa, open(b, "rb") as fb:
        return fa.read().replace(b"\r\n", b"\n") == fb.read().replace(b"\r\n", b"\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    ap.add_argument("--branch", default=DEFAULT_BRANCH)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["git", "clone", "--branch", args.branch, "--single-branch", "--depth", "1", args.repo_url, tmp],
            check=True,
        )

        mismatches = []
        for vendored_rel, source_rel in VENDORED_FILES:
            vendored_path = os.path.join(HERE, vendored_rel)
            source_path = os.path.join(tmp, source_rel)
            if not os.path.exists(source_path):
                mismatches.append(f"원본에서 사라짐: {source_rel}")
                continue
            if not os.path.exists(vendored_path):
                mismatches.append(f"벤더 쪽에 없음: {vendored_rel}")
                continue
            if not _same_content(vendored_path, source_path):
                mismatches.append(f"내용 다름: {vendored_rel} != {source_rel}")

        if mismatches:
            print("불일치 발견 — 1차 탐지팀 코드가 갱신됐을 수 있습니다. 확인 후 다시 복사하세요:")
            for m in mismatches:
                print(f"  - {m}")
            return 1

        print(f"OK: {len(VENDORED_FILES)}개 파일 전부 {args.repo_url}@{args.branch} 와 동일 (줄바꿈 차이 무시)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
