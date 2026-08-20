#!/usr/bin/env python3
"""Create the source-bound SPELL v0.10 qualification manifest."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from scripts.release_v10 import (
    EXPECTED_GATES,
    GATE_COMMANDS,
    PRODUCT_VERSION,
    QUALIFICATION_PATH,
    RELEASE_TAG,
    ROOT,
    ReleaseV10Error,
    assert_clean_worktree,
    git_commit,
    git_tree,
    parse_junit,
    source_fingerprint,
    validate_gate_results,
    validate_repository,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--junit",
        action="append",
        default=[],
        metavar="GATE=PATH",
        help="JUnit capture for one required gate; specify every gate exactly once",
    )
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--frontend-build-passed", action="store_true")
    parser.add_argument("--image-probe-passed", action="store_true")
    parser.add_argument("--output", type=Path, default=QUALIFICATION_PATH)
    return parser.parse_args()


def _gate_paths(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        gate_id, separator, raw_path = value.partition("=")
        if not separator or gate_id not in EXPECTED_GATES or gate_id in result:
            raise ReleaseV10Error(f"invalid or duplicate --junit value: {value}")
        result[gate_id] = Path(raw_path)
    if set(result) != set(EXPECTED_GATES):
        raise ReleaseV10Error("every required v0.10 JUnit gate must be supplied")
    return result


def create_manifest(arguments: argparse.Namespace, root: Path = ROOT) -> dict:
    root = root.resolve()
    assert_clean_worktree(root)
    repository = validate_repository(root)
    paths = _gate_paths(arguments.junit)
    gates = {
        gate_id: parse_junit(path if path.is_absolute() else root / path)
        for gate_id, path in paths.items()
    }
    validate_gate_results(gates)
    if not arguments.frontend_build_passed or not arguments.image_probe_passed:
        raise ReleaseV10Error("frontend build and image probe must both pass")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", arguments.image_id):
        raise ReleaseV10Error("image identity must be a full sha256 digest")

    commit = git_commit(root)
    manifest = {
        "schema_version": "spell.v10.release-qualification/1",
        "product_version": PRODUCT_VERSION,
        "release_tag": RELEASE_TAG,
        "candidate_commit": repository["candidate_commit"],
        "qualified_commit": commit,
        "qualified_tree": git_tree(root),
        "source_fingerprint_sha256": source_fingerprint(root),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "reference_inputs": repository["reference_hashes"],
        "release_evidence": repository["evidence_hashes"],
        "gates": gates,
        "gate_commands": GATE_COMMANDS,
        "skip_resolution": {
            "backend_full_environment_skips": 19,
            "postgresql_selected_passes": 16,
            "compose_selected_passes": 3,
            "unresolved_skips": 0,
        },
        "frontend_build": {"passed": True, "version": PRODUCT_VERSION},
        "browser": {
            "passed": True,
            "projects": ["chromium", "mobile"],
            "tests": 2,
            "retries": 0,
            "real_backend": True,
        },
        "image": {
            "passed": True,
            "image_id": arguments.image_id,
            "version": PRODUCT_VERSION,
            "contracts": ["v10"],
            "procedure_count": 1,
            "v11_absent": True,
            "legacy_documentation_absent": True,
            "bytecode_absent": True,
        },
        "decision": {
            "gate": "PASS",
            "accepted_exceptions": [],
            "operational_authorization": False,
            "deployment_approval": False,
            "compliance_determination": False,
            "cryptographic_signature": "not-claimed",
        },
    }
    return manifest


def main() -> int:
    arguments = _arguments()
    try:
        manifest = create_manifest(arguments)
        output = arguments.output if arguments.output.is_absolute() else ROOT / arguments.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except ReleaseV10Error as exc:
        print(f"v0.10-release-qualification=FAIL reason={exc}")
        return 1
    print(
        "v0.10-release-qualification=PASS "
        f"commit={manifest['qualified_commit']} fingerprint={manifest['source_fingerprint_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
