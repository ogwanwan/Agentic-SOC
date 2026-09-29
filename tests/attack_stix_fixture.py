"""오프라인 테스트용 합성 ATT&CK STIX bundle. 실제 파일(약 54MB)·네트워크 없이 catalog를 만든다.

기법 ID·이름은 실제 ATT&CK과 같게 두었지만 설명·관계 일부는 테스트용으로 줄였다.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.1-test"

TACTICS = [  # (TA id, name, shortname) — 공식 matrix 순서
    ("TA0002", "Execution", "execution"),
    ("TA0003", "Persistence", "persistence"),
    ("TA0005", "Stealth", "stealth"),
    ("TA0007", "Discovery", "discovery"),
]


def _ref(external_id: str, path: str) -> List[Dict[str, Any]]:
    return [{"source_name": "mitre-attack", "external_id": external_id,
             "url": f"https://attack.mitre.org/{path}/{external_id.replace('.', '/')}"},
            {"source_name": "Some Paper", "description": "citation"}]


def technique(tid: str, name: str, phases: List[str], *, sub: bool = False, revoked: bool = False,
              deprecated: bool = False, description: str = "") -> Dict[str, Any]:
    return {
        "type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
        "description": description or f"Adversaries may use {name}.",
        "external_references": _ref(tid, "techniques"),
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases],
        "x_mitre_is_subtechnique": sub, "revoked": revoked, "x_mitre_deprecated": deprecated,
        "x_mitre_platforms": ["Linux", "macOS"],
    }


def relationship(kind: str, source: str, target: str) -> Dict[str, Any]:
    return {"type": "relationship", "id": f"relationship--{kind}-{source}-{target}",
            "relationship_type": kind, "source_ref": f"attack-pattern--{source}",
            "target_ref": f"attack-pattern--{target}"}


def make_bundle(version: str = VERSION) -> Dict[str, Any]:
    objects: List[Dict[str, Any]] = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK",
         "x_mitre_version": version},
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "name": "Enterprise ATT&CK",
         "tactic_refs": [f"x-mitre-tactic--{t[2]}" for t in TACTICS]},
    ]
    objects += [{"type": "x-mitre-tactic", "id": f"x-mitre-tactic--{short}", "name": name,
                 "x_mitre_shortname": short, "external_references": _ref(ta, "tactics")}
                for ta, name, short in TACTICS]
    objects += [
        technique("T1059", "Command and Scripting Interpreter", ["execution"]),
        technique("T1059.004", "Unix Shell", ["execution"], sub=True,
                  description="Adversaries may abuse <code>sh</code> and [bash](https://attack.mitre.org/x) "
                              "for execution.(Citation: DieNet Bash)\n\n\n\nSecond  paragraph."),
        technique("T1505", "Server Software Component", ["persistence"]),
        technique("T1505.003", "Web Shell", ["persistence"], sub=True),
        technique("T1033", "System Owner/User Discovery", ["discovery"]),
        technique("T1082", "System Information Discovery", ["discovery"]),
        technique("T1070", "Indicator Removal", ["stealth"]),
        technique("T1070.004", "File Deletion", ["stealth"], sub=True),
        technique("T1078", "Valid Accounts", ["stealth", "persistence"]),  # 순서를 일부러 뒤집음
        technique("T1086", "PowerShell", ["execution"], revoked=True),
        technique("T1099", "Timestomp", ["stealth"], deprecated=True),
        relationship("subtechnique-of", "T1059.004", "T1059"),
        relationship("subtechnique-of", "T1505.003", "T1505"),
        relationship("subtechnique-of", "T1070.004", "T1070"),
        relationship("revoked-by", "T1086", "T1059.004"),
        relationship("uses", "T1033", "T1082"),
    ]
    return {"type": "bundle", "id": "bundle--1", "objects": objects}


def write_catalog(directory: Path, bundle: Optional[Dict[str, Any]] = None,
                  *, manifest_version: Optional[str] = None, sha256: Optional[str] = None,
                  extra_manifest: Optional[Dict[str, Any]] = None) -> Tuple[Path, Path]:
    """bundle과 그에 맞는 manifest를 써서 (stix_path, manifest_path)를 돌려준다."""
    bundle = bundle if bundle is not None else make_bundle()
    stix_path, manifest_path = directory / "enterprise-attack.json", directory / "manifest.json"
    data = json.dumps(bundle).encode("utf-8")
    stix_path.write_bytes(data)
    version = next((o["x_mitre_version"] for o in bundle["objects"] if o["type"] == "x-mitre-collection"), VERSION)
    manifest = {"attack_version": manifest_version or version,
                "sha256": sha256 or hashlib.sha256(data).hexdigest(), **(extra_manifest or {})}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return stix_path, manifest_path


def load_test_catalog(directory: Path):
    from attack_mapping.catalog import load_catalog
    return load_catalog(*write_catalog(directory))
