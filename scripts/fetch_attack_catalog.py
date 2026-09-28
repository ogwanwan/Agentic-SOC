"""공식 MITRE ATT&CK Enterprise STIX 파일 받기·검증 (담당 A).

enterprise-attack.json(약 54MB)은 git에 올리지 않는다. manifest.json(git 추적)에 적힌
버전·sha256과 같은 파일을 받아 data/attack/에 둔다.

    python -m scripts.fetch_attack_catalog                 # manifest에 고정된 버전을 받아 sha256 확인 (팀원·EC2)
    python -m scripts.fetch_attack_catalog --verify        # 네트워크 없이 기존 파일만 확인
    python -m scripts.fetch_attack_catalog --from-file F   # 다른 곳에서 받은 파일을 복사해 확인 (EC2 오프라인)
    python -m scripts.fetch_attack_catalog --version 19.3  # 버전 올리기: 받고 manifest 갱신 (담당 A)
    python -m scripts.fetch_attack_catalog --latest        # MITRE index.json의 최신 버전으로 올리기

네트워크 요청은 GitHub(raw.githubusercontent.com)에서 공개 파일을 내려받는 것뿐이다.
버전을 올리면 manifest의 A 키만 바꾸고 B의 키(retrieval_version, embedding_model 등)는 보존한다.
카탈로그가 바뀌면 B의 검색 인덱스를 다시 만들어야 한다.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from attack_mapping.catalog import (CATALOG_PARSER_VERSION, DEFAULT_MANIFEST_PATH, DEFAULT_STIX_PATH,
                                    load_catalog, sha256_file)
from attack_mapping.schema import CatalogError

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
VERSION_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
               "enterprise-attack/enterprise-attack-{version}.json")
DOMAIN = "enterprise-attack"
TIMEOUT = 120


def _download(url: str, dest: Path) -> None:
    print(f"다운로드: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "Agentic-SOC attack-catalog-fetch"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response, open(dest, "wb") as out:
        shutil.copyfileobj(response, out, 1 << 20)


def latest_version() -> str:
    with urllib.request.urlopen(INDEX_URL, timeout=TIMEOUT) as response:
        index = json.load(response)
    for collection in index.get("collections", []):
        if collection.get("name") == "Enterprise ATT&CK":
            return collection["versions"][0]["version"]
    raise CatalogError("MITRE index.json에 Enterprise ATT&CK이 없습니다")


def _read_manifest_raw(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_manifest(path: Path, updates: Dict[str, Any]) -> Dict[str, Any]:
    """A 키만 갱신하고 나머지(B의 키)는 그대로 둔다."""
    manifest = _read_manifest_raw(path)
    manifest.update(updates)
    manifest.setdefault("retrieval_version", None)
    manifest.setdefault("embedding_model", None)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return manifest


def _install(source: Path, stix_path: Path, manifest_path: Path) -> None:
    """source를 manifest 기준으로 검증한 뒤에만 제자리에 둔다. 실패하면 기존 파일을 건드리지 않는다."""
    load_catalog(source, manifest_path)                      # sha256·버전·파싱 확인
    stix_path.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != stix_path.resolve():
        tmp = stix_path.with_suffix(".json.tmp")
        shutil.copyfile(source, tmp)
        os.replace(tmp, stix_path)


def fetch_pinned(stix_path: Path, manifest_path: Path) -> None:
    manifest = _read_manifest_raw(manifest_path)
    url = manifest.get("source_url")
    if not url:
        raise CatalogError("manifest.json에 source_url이 없습니다. --version으로 먼저 받으세요")
    stix_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=stix_path.parent) as tmpdir:
        tmp = Path(tmpdir) / "download.json"
        _download(url, tmp)
        _install(tmp, stix_path, manifest_path)


def update_version(version: str, stix_path: Path, manifest_path: Path, today: Optional[str] = None) -> Dict[str, Any]:
    url = VERSION_URL.format(version=version)
    stix_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=stix_path.parent) as tmpdir:
        tmp = Path(tmpdir) / "download.json"
        _download(url, tmp)
        return adopt_file(tmp, version, url, stix_path, manifest_path, today)


def adopt_file(source: Path, version: str, url: str, stix_path: Path, manifest_path: Path,
               today: Optional[str] = None) -> Dict[str, Any]:
    """새 파일을 기준으로 manifest의 A 키를 다시 쓴다. 파일 속 버전이 요청 버전과 다르면 거부."""
    digest = sha256_file(source)
    previous = _read_manifest_raw(manifest_path)
    probe = {**previous, "attack_version": version, "sha256": digest}
    with tempfile.TemporaryDirectory() as tmpdir:
        probe_path = Path(tmpdir) / "manifest.json"
        probe_path.write_text(json.dumps(probe), encoding="utf-8")
        catalog = load_catalog(source, probe_path)          # 파일 속 x_mitre_version == version 확인
    stix_path.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != stix_path.resolve():
        tmp = stix_path.with_suffix(".json.tmp")
        shutil.copyfile(source, tmp)
        os.replace(tmp, stix_path)
    manifest = write_manifest(manifest_path, {
        "attack_version": version, "domain": DOMAIN, "stix_file": stix_path.name, "source_url": url,
        "downloaded_at": today or datetime.now(timezone.utc).strftime("%Y-%m-%d"), "sha256": digest,
        "size_bytes": stix_path.stat().st_size, "catalog_parser_version": CATALOG_PARSER_VERSION,
        "active_technique_count": len(catalog), "tactic_count": len(catalog.tactic_order),
    })
    if previous.get("sha256") not in (None, digest):
        print("카탈로그가 바뀌었습니다: 담당 B의 검색 인덱스를 다시 만들어야 합니다.")
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", action="store_true", help="네트워크 없이 기존 파일만 확인")
    mode.add_argument("--from-file", type=Path, help="이미 받은 파일을 복사해 확인")
    mode.add_argument("--version", help="이 버전으로 올리고 manifest 갱신")
    mode.add_argument("--latest", action="store_true", help="MITRE 최신 버전으로 올리고 manifest 갱신")
    parser.add_argument("--stix-path", type=Path, default=DEFAULT_STIX_PATH)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            catalog = load_catalog(args.stix_path, args.manifest)
        elif args.from_file:
            _install(args.from_file, args.stix_path, args.manifest)
            catalog = load_catalog(args.stix_path, args.manifest)
        elif args.version or args.latest:
            update_version(args.version or latest_version(), args.stix_path, args.manifest)
            catalog = load_catalog(args.stix_path, args.manifest)
        else:
            fetch_pinned(args.stix_path, args.manifest)
            catalog = load_catalog(args.stix_path, args.manifest)
    except (CatalogError, OSError, ValueError) as exc:
        print(f"실패: {exc}", file=sys.stderr)
        return 1
    print(f"확인 완료: ATT&CK {catalog.attack_version}, 활성 기법 {len(catalog)}개, "
          f"전술 {len(catalog.tactic_order)}개, sha256 {catalog.sha256[:12]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
