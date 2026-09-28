"""catalog.py·fetch_attack_catalog 오프라인 테스트 (합성 STIX). 실제 파일 테스트는 파일이 있을 때만 돈다."""

import json

import pytest

from attack_mapping.catalog import DEFAULT_MANIFEST_PATH, DEFAULT_STIX_PATH, clean_description, load_catalog
from attack_mapping.schema import CatalogError
from scripts import fetch_attack_catalog as fetch
from tests.attack_stix_fixture import VERSION, make_bundle, relationship, technique, write_catalog


@pytest.fixture
def catalog(tmp_path):
    return load_catalog(*write_catalog(tmp_path))


def test_load_reads_version_and_hash_from_manifest(tmp_path):
    stix, manifest = write_catalog(tmp_path)
    c = load_catalog(stix, manifest)
    assert c.attack_version == VERSION
    assert c.fingerprint == json.loads(manifest.read_text())["sha256"]


def test_active_techniques_exclude_revoked_and_deprecated(catalog):
    ids = [t.technique_id for t in catalog.techniques()]
    assert ids == sorted(ids)
    assert "T1086" not in ids and "T1099" not in ids
    assert len(catalog) == 9


def test_lookup_returns_inactive_with_reason(catalog):
    revoked = catalog.lookup("T1086")
    assert revoked.revoked and not revoked.active and revoked.revoked_by == "T1059.004"
    assert catalog.status("T1086") == "revoked"
    assert catalog.status("T1099") == "deprecated"
    assert catalog.get_active("T1086") is None
    assert catalog.lookup("T9999") is None and catalog.status("T9999") == "unknown"
    assert catalog.lookup("t1059.004") is None      # 정확한 ID만. 정규화는 validate 담당


def test_subtechnique_parent_and_tactics(catalog):
    unix = catalog.lookup("T1059.004")
    assert unix.is_subtechnique and unix.parent_id == "T1059"
    assert catalog.parent("T1059.004").name == "Command and Scripting Interpreter"
    assert [t.tactic_id for t in unix.tactics] == ["TA0002"]
    # 여러 전술은 STIX 순서가 아니라 공식 matrix 순서
    assert [t.tactic_name for t in catalog.lookup("T1078").tactics] == ["Persistence", "Stealth"]
    assert [t.tactic_name for t in catalog.tactic_order] == ["Execution", "Persistence", "Stealth", "Discovery"]
    assert catalog.tactic("TA0005").tactic_name == "Stealth"


def test_description_is_cleaned(catalog):
    text = catalog.lookup("T1059.004").description
    assert text == "Adversaries may abuse sh and bash for execution.\n\nSecond paragraph."
    assert clean_description("a (Citation: X Y) b") == "a b"


def test_hash_mismatch_is_rejected(tmp_path):
    stix, manifest = write_catalog(tmp_path, sha256="0" * 64)
    with pytest.raises(CatalogError, match="sha256"):
        load_catalog(stix, manifest)
    assert load_catalog(stix, manifest, verify_sha256=False).attack_version == VERSION


def test_manifest_version_must_match_file(tmp_path):
    with pytest.raises(CatalogError, match="버전"):
        load_catalog(*write_catalog(tmp_path, manifest_version="19.2"))


def test_missing_files(tmp_path):
    stix, manifest = write_catalog(tmp_path)
    with pytest.raises(CatalogError, match="manifest"):
        load_catalog(stix, tmp_path / "none.json")
    stix.unlink()
    with pytest.raises(CatalogError, match="fetch_attack_catalog"):
        load_catalog(stix, manifest)


@pytest.mark.parametrize("mutate,message", [
    (lambda objs: objs.append(technique("T1033", "Dup", ["discovery"])), "중복"),
    (lambda objs: objs.append(technique("T1082.001", "Orphan", ["discovery"], sub=True)), "부모"),
    (lambda objs: objs.append(technique("T1111", "Bad", ["nope"])), "전술"),
    (lambda objs: objs.append(technique("T1112.001", "NotSub", ["discovery"])), "x_mitre_is_subtechnique"),
    (lambda objs: objs.append(relationship("subtechnique-of", "T1070.004", "T1059")), "부모"),
])
def test_inconsistent_catalog_is_rejected(tmp_path, mutate, message):
    bundle = make_bundle()
    mutate(bundle["objects"])
    with pytest.raises(CatalogError, match=message):
        load_catalog(*write_catalog(tmp_path, bundle))


def test_revoked_duplicate_does_not_shadow_active(tmp_path):
    bundle = make_bundle()
    old = technique("T1033", "Old Owner Discovery", ["discovery"], revoked=True)
    old["id"] = "attack-pattern--T1033-old"
    bundle["objects"].insert(0, old)
    c = load_catalog(*write_catalog(tmp_path, bundle))
    assert c.lookup("T1033").active and c.lookup("T1033").name == "System Owner/User Discovery"


# ---------------------------------------------------------------------------
# fetch_attack_catalog (네트워크 없이)
# ---------------------------------------------------------------------------

def test_adopt_file_writes_catalog_keys_and_keeps_retrieval_keys(tmp_path):
    source, _ = write_catalog(tmp_path)
    dest_dir = tmp_path / "data"
    dest_dir.mkdir()
    manifest_path = dest_dir / "manifest.json"
    manifest_path.write_text(json.dumps({"retrieval_version": "2", "embedding_model": "m", "index": {"k": 1}}))
    manifest = fetch.adopt_file(source, VERSION, "https://example.invalid/x.json",
                                dest_dir / "enterprise-attack.json", manifest_path, today="2026-09-28")
    assert manifest["retrieval_version"] == "2" and manifest["embedding_model"] == "m"
    assert manifest["index"] == {"k": 1}
    assert manifest["attack_version"] == VERSION and manifest["active_technique_count"] == 9
    assert manifest["tactic_count"] == 4 and manifest["downloaded_at"] == "2026-09-28"
    assert load_catalog(dest_dir / "enterprise-attack.json", manifest_path).attack_version == VERSION


def test_adopt_file_rejects_wrong_version(tmp_path):
    source, _ = write_catalog(tmp_path)
    dest = tmp_path / "data" / "enterprise-attack.json"
    with pytest.raises(CatalogError, match="버전"):
        fetch.adopt_file(source, "19.2", "u", dest, tmp_path / "data" / "manifest.json")
    assert not dest.exists()


def test_from_file_installs_only_matching_file(tmp_path):
    good, manifest = write_catalog(tmp_path)
    dest = tmp_path / "out" / "enterprise-attack.json"
    assert fetch.main(["--from-file", str(good), "--stix-path", str(dest), "--manifest", str(manifest)]) == 0
    assert dest.read_bytes() == good.read_bytes()
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(make_bundle("9.9")))
    dest.write_bytes(b"keep")
    assert fetch.main(["--from-file", str(bad), "--stix-path", str(dest), "--manifest", str(manifest)]) == 1
    assert dest.read_bytes() == b"keep"                  # 검증 실패 시 기존 파일 유지


def test_verify_mode(tmp_path, capsys):
    stix, manifest = write_catalog(tmp_path)
    assert fetch.main(["--verify", "--stix-path", str(stix), "--manifest", str(manifest)]) == 0
    assert "활성 기법 9개" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 실제 카탈로그 (scripts.fetch_attack_catalog로 받은 뒤에만)
# ---------------------------------------------------------------------------

REPRESENTATIVE = ["T1110.001", "T1505.003", "T1059.004", "T1098.004", "T1560.001",
                  "T1048.003", "T1070.004", "T1033", "T1082"]


@pytest.mark.skipif(not DEFAULT_STIX_PATH.is_file(), reason="data/attack/enterprise-attack.json 없음")
def test_real_catalog_matches_manifest():
    manifest = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))
    c = load_catalog()
    assert c.attack_version == manifest["attack_version"]
    assert len(c) == manifest["active_technique_count"]
    assert len(c.tactic_order) == manifest["tactic_count"]
    for tid in REPRESENTATIVE:                           # 설계 17.2 대표 기법
        assert c.status(tid) == "active", tid
    assert all(t.tactics for t in c.techniques())
    assert all(t.parent_id and c.get_active(t.parent_id) for t in c.techniques() if t.is_subtechnique)
