"""Fail-closed v0.16 entry scope and source-reference validation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "V16-LANG-001", "V16-LANG-002", "V16-RUNNER-001", "V16-UI-001",
    "V16-SESSION-001", "V16-SESSION-002", "V16-DOC-001", "V16-RELEASE-001",
}


def validate(root: Path = ROOT) -> dict:
    data = json.loads((root / "contracts/v16/entry_gate.json").read_bytes())
    if (data.get("schema_version") != "spell.v16.entry-gate/1"
            or data.get("release_tag") != "v0.16.0" or data.get("owner_authorized") is not True
            or data.get("scope") != "LOCAL_SIMULATOR_LANGUAGE_AND_MANUAL_WORKSPACE"
            or data.get("operational_authorization") is not False
            or data.get("full_language_compatibility_claim") is not False
            or set(data.get("requirements", [])) != REQUIRED
            or len(data["requirements"]) != len(REQUIRED)):
        raise ValueError("v0.16 entry identity, scope or authority differs")
    predecessor = subprocess.check_output(
        ["git", "rev-parse", "v0.15.0^{commit}"], cwd=root, text=True).strip()
    if predecessor != data["predecessor_commit"]:
        raise ValueError("accepted predecessor differs")
    subprocess.run(["git", "merge-base", "--is-ancestor", predecessor, "HEAD"],
                   cwd=root, check=True)
    policy = json.loads((root / "contracts/v16/release_policy.json").read_bytes())
    if (policy["release_tag"] != data["release_tag"] or policy["scope"] != data["scope"]
            or policy["predecessor_commit"] != predecessor
            or policy["operational_authorization"] is not False
            or policy["legacy_system_qualified"] is not False):
        raise ValueError("entry/release policy mismatch")
    previous = json.loads(subprocess.check_output(
        ["git", "show", "v0.15.0:contracts/v15/release_policy.json"], cwd=root))
    if policy["reference_inputs"] != previous["reference_inputs"]:
        raise ValueError("mandatory source inventory changed")
    for row in policy["reference_inputs"]:
        if hashlib.sha256((root / row["path"]).read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError("mandatory source bytes changed")
    record = (root / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/releases/SPELL_v0.16_Pre-Implementation.md").read_text(encoding="utf-8")
    if not all(identity in record for identity in REQUIRED):
        raise ValueError("entry proof requirements missing")
    return {"gate": "V16-GATE-0A", "decision": "PASS", "requirements": len(REQUIRED),
            "reference_inputs": len(policy["reference_inputs"]), "product_acceptance": False}


if __name__ == "__main__":
    print(json.dumps(validate(), sort_keys=True))
