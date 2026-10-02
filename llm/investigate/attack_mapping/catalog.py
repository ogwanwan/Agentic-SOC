"""공식 MITRE ATT&CK Enterprise STIX 카탈로그 (담당 A).

data/attack/enterprise-attack.json(git 미추적, 약 54MB)을 읽어 기법 조회표를 만든다.
파일은 scripts/fetch_attack_catalog.py로 받고, manifest.json(git 추적)의 sha256과
attack_version으로 모든 환경이 같은 파일을 쓰는지 확인한다. 버전 문자열은 코드에 두지 않는다.

- 검색 후보: techniques() — revoked/deprecated 제외, ID 정렬 (B의 인덱스 입력)
- 검증 조회: lookup() — 비활성 항목도 돌려준다(거부 사유에 revoked_by를 적기 위해)
- 전술 순서: tactic_order — 공식 matrix 순서. v19부터 Defense Evasion → Stealth,
  Defense Impairment(TA0112) 추가로 schema.TACTIC_ORDER(규칙 기준)와 다르다.

카탈로그가 모호하거나 manifest와 다르면 조용히 넘기지 않고 CatalogError를 낸다.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .schema import TECHNIQUE_ID_PATTERN, CatalogError, TacticRef, TechniqueRecord

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "attack"
DEFAULT_STIX_PATH = DATA_DIR / "enterprise-attack.json"
DEFAULT_MANIFEST_PATH = DATA_DIR / "manifest.json"

# 이 모듈의 파싱 규칙 버전. 규칙을 바꾸면 올리고 manifest에도 기록한다.
CATALOG_PARSER_VERSION = "1"
# manifest에서 A가 쓰는 키. retrieval_version, embedding_model 등 B의 키는 읽고 보존만 한다.
MANIFEST_CATALOG_KEYS = (
    "attack_version", "domain", "stix_file", "source_url", "downloaded_at", "sha256",
    "size_bytes", "catalog_parser_version", "active_technique_count", "tactic_count",
)

PathLike = Union[str, Path]

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?://|/)[^)]*\)")
_TAG = re.compile(r"</?code>")
_SPACES = re.compile(r"[ \t]+")


def clean_description(text: str) -> str:
    """검색·프롬프트용 설명. 인용 표시·마크다운 링크·<code> 태그만 제거하고 문장은 그대로 둔다."""
    text = _TAG.sub("", _MD_LINK.sub(r"\1", _CITATION.sub("", text)))
    lines = [_SPACES.sub(" ", line).strip() for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def sha256_file(path: PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_manifest(path: PathLike = DEFAULT_MANIFEST_PATH) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        raise CatalogError(f"manifest.json이 없습니다: {path}") from None
    except (OSError, ValueError) as exc:
        raise CatalogError(f"manifest.json을 읽을 수 없습니다: {path}: {exc}") from None
    if not isinstance(manifest, dict):
        raise CatalogError("manifest.json은 객체여야 합니다")
    for key in ("attack_version", "sha256"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            raise CatalogError(f"manifest.json에 {key}가 없습니다")
    return manifest


def _inactive(obj: Dict[str, Any]) -> bool:
    return bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))


def _attack_ref(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    refs = [r for r in obj.get("external_references") or [] if r.get("source_name") == "mitre-attack"]
    return refs[0] if refs else None


def _only(objects: List[Dict[str, Any]], kind: str) -> Dict[str, Any]:
    active = [o for o in objects if not _inactive(o)]
    if len(active) != 1:
        raise CatalogError(f"활성 {kind} 객체가 1개가 아닙니다({len(active)}개)")
    return active[0]


def parse_bundle(bundle: Any) -> Tuple[str, Tuple[TacticRef, ...], Tuple[TechniqueRecord, ...]]:
    """STIX bundle → (ATT&CK 버전, 공식 전술 순서, 전체 기법 레코드). 파일 입출력 없음."""
    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise CatalogError("STIX bundle 형식이 아닙니다(objects 없음)")
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    by_stix_id: Dict[str, Dict[str, Any]] = {}
    for obj in bundle["objects"]:
        if isinstance(obj, dict) and isinstance(obj.get("type"), str):
            by_type.setdefault(obj["type"], []).append(obj)
            if isinstance(obj.get("id"), str):
                by_stix_id[obj["id"]] = obj

    version = _only(by_type.get("x-mitre-collection", []), "x-mitre-collection").get("x_mitre_version")
    if not isinstance(version, str) or not version:
        raise CatalogError("x-mitre-collection에 x_mitre_version이 없습니다")

    tactics_by_stix: Dict[str, TacticRef] = {}
    for obj in by_type.get("x-mitre-tactic", []):
        ref = _attack_ref(obj)
        if _inactive(obj) or ref is None:
            continue
        tactics_by_stix[obj["id"]] = TacticRef(ref["external_id"], obj["name"], obj["x_mitre_shortname"])
    matrix = _only(by_type.get("x-mitre-matrix", []), "x-mitre-matrix")
    try:
        tactic_order = tuple(tactics_by_stix[ref] for ref in matrix.get("tactic_refs") or [])
    except KeyError as exc:
        raise CatalogError(f"matrix가 알 수 없는 전술을 참조합니다: {exc}") from None
    if not tactic_order:
        raise CatalogError("matrix에 전술 순서가 없습니다")
    by_shortname = {t.shortname: t for t in tactic_order}
    rank = {t.shortname: i for i, t in enumerate(tactic_order)}

    parent_of: Dict[str, str] = {}
    revoked_by: Dict[str, str] = {}
    for rel in by_type.get("relationship", []):
        if _inactive(rel):
            continue
        if rel.get("relationship_type") == "subtechnique-of":
            parent_of[rel["source_ref"]] = rel["target_ref"]
        elif rel.get("relationship_type") == "revoked-by":
            revoked_by[rel["source_ref"]] = rel["target_ref"]

    def external_id(stix_id: str) -> Optional[str]:
        target = by_stix_id.get(stix_id)
        ref = _attack_ref(target) if target else None
        return ref["external_id"] if ref else None

    records = []
    for obj in by_type.get("attack-pattern", []):
        ref = _attack_ref(obj)
        tid = ref.get("external_id") if ref else None
        if not isinstance(tid, str) or not TECHNIQUE_ID_PATTERN.match(tid):
            raise CatalogError(f"공식 ATT&CK ID가 없는 attack-pattern: {obj.get('id')}")
        active = not _inactive(obj)
        shortnames = [p.get("phase_name") for p in obj.get("kill_chain_phases") or []
                      if p.get("kill_chain_name") == "mitre-attack"]
        unknown = [s for s in shortnames if s not in by_shortname]
        if active and (unknown or not shortnames):
            raise CatalogError(f"{tid}: 공식 전술에 없는 kill_chain_phases {unknown or shortnames}")
        tactics = tuple(by_shortname[s] for s in sorted(set(shortnames) - set(unknown), key=rank.get))

        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = None
        if is_sub:
            prefix = tid.split(".")[0]
            parent_id = external_id(parent_of[obj["id"]]) if obj["id"] in parent_of else None
            if active and parent_id != prefix:
                raise CatalogError(f"{tid}: subtechnique-of 부모({parent_id})가 ID 접두어와 다릅니다")
            parent_id = parent_id or prefix
        elif "." in tid:
            raise CatalogError(f"{tid}: 하위 기법 ID인데 x_mitre_is_subtechnique가 아닙니다")

        records.append(TechniqueRecord(
            technique_id=tid, stix_id=obj["id"], name=obj.get("name", ""),
            description=clean_description(obj.get("description") or ""), tactics=tactics,
            is_subtechnique=is_sub, parent_id=parent_id,
            platforms=tuple(obj.get("x_mitre_platforms") or ()), url=ref.get("url", ""),
            revoked=bool(obj.get("revoked")), deprecated=bool(obj.get("x_mitre_deprecated")),
            revoked_by=external_id(revoked_by[obj["id"]]) if obj["id"] in revoked_by else None,
        ))
    return version, tactic_order, tuple(records)


class AttackCatalog:
    """불변 조회표. 같은 프로세스에서는 get_default_catalog()로 한 번만 로드한다."""

    def __init__(self, records: Iterable[TechniqueRecord], tactic_order: Tuple[TacticRef, ...],
                 attack_version: str, sha256: str, manifest: Optional[Dict[str, Any]] = None):
        self.attack_version = attack_version
        self.sha256 = sha256
        self.tactic_order = tactic_order
        self.manifest = dict(manifest or {})
        self._tactics = {t.tactic_id: t for t in tactic_order}
        self._by_id: Dict[str, TechniqueRecord] = {}
        for record in records:
            known = self._by_id.get(record.technique_id)
            if known is not None and known.active and record.active:
                raise CatalogError(f"활성 기법 ID가 중복됩니다: {record.technique_id}")
            # 같은 ID의 비활성·활성 항목이 함께 있으면 활성 항목을 조회 결과로 쓴다
            if known is None or (record.active and not known.active):
                self._by_id[record.technique_id] = record
        self._active = tuple(r for _, r in sorted(self._by_id.items()) if r.active)

    @property
    def fingerprint(self) -> str:
        """B의 인덱스 호환성 키. 카탈로그 파일이 바뀌면 인덱스를 다시 만들어야 한다."""
        return self.sha256

    def __len__(self) -> int:
        return len(self._active)

    def techniques(self) -> Tuple[TechniqueRecord, ...]:
        return self._active

    def lookup(self, technique_id: str) -> Optional[TechniqueRecord]:
        """정확한 ID로 조회(정규화 없음). 비활성 기법도 revoked/deprecated 표시와 함께 돌려준다."""
        return self._by_id.get(technique_id)

    def get_active(self, technique_id: str) -> Optional[TechniqueRecord]:
        record = self._by_id.get(technique_id)
        return record if record is not None and record.active else None

    def status(self, technique_id: str) -> str:
        record = self._by_id.get(technique_id)
        if record is None:
            return "unknown"
        return "revoked" if record.revoked else "deprecated" if record.deprecated else "active"

    def parent(self, technique_id: str) -> Optional[TechniqueRecord]:
        record = self._by_id.get(technique_id)
        return self._by_id.get(record.parent_id) if record and record.parent_id else None

    def tactic(self, tactic_id: str) -> Optional[TacticRef]:
        return self._tactics.get(tactic_id)


def load_catalog(stix_path: Optional[PathLike] = None, manifest_path: Optional[PathLike] = None,
                 *, verify_sha256: bool = True) -> AttackCatalog:
    """manifest를 먼저 읽고 sha256 → JSON 파싱 → 파일 속 버전과 manifest 버전 비교 순서로 확인한다."""
    stix_path = Path(stix_path or DEFAULT_STIX_PATH)
    manifest = read_manifest(manifest_path or DEFAULT_MANIFEST_PATH)
    if not stix_path.is_file():
        raise CatalogError(f"ATT&CK STIX 파일이 없습니다: {stix_path} "
                           "(python -m scripts.fetch_attack_catalog 로 받으세요)")
    digest = sha256_file(stix_path) if verify_sha256 else manifest["sha256"]
    if digest != manifest["sha256"]:
        raise CatalogError(f"STIX 파일 sha256이 manifest와 다릅니다: {digest} != {manifest['sha256']}")
    try:
        with open(stix_path, encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, ValueError) as exc:
        raise CatalogError(f"STIX 파일을 읽을 수 없습니다: {exc}") from None
    try:
        version, tactic_order, records = parse_bundle(bundle)
    except (KeyError, TypeError, AttributeError) as exc:
        raise CatalogError(f"STIX 객체 형식이 예상과 다릅니다: {exc!r}") from None
    if version != manifest["attack_version"]:
        raise CatalogError(f"파일의 ATT&CK 버전 {version}이 manifest의 {manifest['attack_version']}와 다릅니다")
    return AttackCatalog(records, tactic_order, version, digest, manifest)


@lru_cache(maxsize=1)
def get_default_catalog() -> AttackCatalog:
    return load_catalog()


def lookup_technique(technique_id: str, catalog: Optional[AttackCatalog] = None) -> Optional[TechniqueRecord]:
    return (catalog or get_default_catalog()).lookup(technique_id)
