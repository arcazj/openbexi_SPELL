"""Fail-closed entry contract for the isolated Python runtime/debugger release."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"V191-SOURCE-001", "V191-ISOLATION-001", "V191-DEBUG-001", "V191-DURABILITY-001",
            "V191-PROCEDURES-001", "V191-DSS-001", "V191-UI-001", "V191-RELEASE-001"}


def validate(root: Path = ROOT) -> dict:
    entry = json.loads((root / "contracts/v19.1/entry_gate.json").read_bytes())
    policy = json.loads((root / "contracts/v19.1/release_policy.json").read_bytes())
    expected = {"schema_version": "spell.v191.entry-gate/1", "release_tag": "v0.19.1",
        "scope": "LOCAL_SIMULATOR_PYTHON_RUNTIME_AND_DEBUGGER", "owner_authorized": True,
        "operational_authorization": False, "full_language_compatibility_claim": False,
        "dss_validation_required": True}
    if any(type(entry.get(key)) is not type(value) or entry.get(key) != value for key, value in expected.items()):
        raise ValueError("v0.19.1 entry identity or authority differs")
    if sorted(entry.get("requirements", [])) != sorted(REQUIRED):
        raise ValueError("v0.19.1 proof requirements differ")
    predecessor = subprocess.check_output(["git", "rev-parse", "v0.19.0^{commit}"], cwd=root, text=True).strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", predecessor, "HEAD"], cwd=root, check=True)
    if entry.get("predecessor_commit") != predecessor or any(policy.get(key) != entry[key]
            for key in ("release_tag", "scope", "predecessor_commit", "operational_authorization", "dss_validation_required")):
        raise ValueError("v0.19.1 entry/release binding differs")
    if policy.get("product_version") != "0.19.1" or policy.get("legacy_system_qualified") is not False:
        raise ValueError("v0.19.1 release authority differs")
    previous = json.loads(subprocess.check_output(["git", "show", "v0.19.0:contracts/v19/release_policy.json"], cwd=root))
    if policy.get("reference_inputs") != previous["reference_inputs"]:
        raise ValueError("mandatory source inventory changed")
    for row in policy["reference_inputs"]:
        if hashlib.sha256((root / row["path"]).read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError("mandatory source bytes changed")
    record = (root / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.19.1_Pre-Implementation.md").read_text(encoding="utf-8")
    if not all(identity in record for identity in REQUIRED):
        raise ValueError("v0.19.1 entry proof requirements missing")
    return {"gate": "V191-GATE-0A", "decision": "PASS", "requirements": len(REQUIRED),
            "reference_inputs": len(policy["reference_inputs"]), "product_acceptance": False}


if __name__ == "__main__":
    print(json.dumps(validate(), sort_keys=True))
