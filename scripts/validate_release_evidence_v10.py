#!/usr/bin/env python3
"""Validate SPELL v0.10 qualification, package, and annotated tag evidence."""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v10 import (
    GATE_COMMANDS,
    PACKAGE_PATH,
    PRODUCT_VERSION,
    QUALIFICATION_PATH,
    RELEASE_MANIFEST_PATH,
    RELEASE_TAG,
    ROOT,
    SIDECAR_PATH,
    ReleaseV10Error,
    _assert_ancestor,
    _git,
    archive_bytes,
    git_commit,
    git_tree,
    load_policy,
    package_content_manifest,
    package_files,
    sha256_bytes,
    sha256_file,
    source_fingerprint,
    validate_gate_results,
    validate_repository,
)


@dataclass(frozen=True)
class ValidationResult:
    qualified_commit: str
    source_fingerprint_sha256: str
    package_sha256: str | None
    tag_object: str | None


QUALIFICATION_KEYS = {
    "schema_version",
    "product_version",
    "release_tag",
    "candidate_commit",
    "qualified_commit",
    "qualified_tree",
    "source_fingerprint_sha256",
    "generated_at_utc",
    "reference_inputs",
    "release_evidence",
    "gates",
    "gate_commands",
    "skip_resolution",
    "frontend_build",
    "browser",
    "image",
    "decision",
}


def _load_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseV10Error(f"{label} is missing or invalid") from exc
    if not isinstance(value, dict):
        raise ReleaseV10Error(f"{label} must be a JSON object")
    return value


def validate_qualification(root: Path = ROOT) -> dict:
    root = root.resolve()
    repository = validate_repository(root)
    manifest = _load_json(root / QUALIFICATION_PATH, "v0.10 release qualification")
    if set(manifest) != QUALIFICATION_KEYS:
        raise ReleaseV10Error("v0.10 qualification fields differ")
    if (
        manifest["schema_version"] != "spell.v10.release-qualification/1"
        or manifest["product_version"] != PRODUCT_VERSION
        or manifest["release_tag"] != RELEASE_TAG
        or manifest["candidate_commit"] != repository["candidate_commit"]
    ):
        raise ReleaseV10Error("v0.10 qualification identity differs")
    _assert_ancestor(root, manifest["qualified_commit"])
    if git_tree(root, manifest["qualified_commit"]) != manifest["qualified_tree"]:
        raise ReleaseV10Error("qualified tree differs from the recorded commit")
    if source_fingerprint(root) != manifest["source_fingerprint_sha256"]:
        raise ReleaseV10Error("qualified source fingerprint differs")
    if manifest["reference_inputs"] != repository["reference_hashes"]:
        raise ReleaseV10Error("qualified reference inventory differs")
    if manifest["release_evidence"] != repository["evidence_hashes"]:
        raise ReleaseV10Error("qualified evidence inventory differs")
    validate_gate_results(manifest["gates"])
    if manifest["gate_commands"] != GATE_COMMANDS:
        raise ReleaseV10Error("v0.10 qualification command inventory differs")
    if manifest["skip_resolution"] != {
        "backend_full_environment_skips": 19,
        "postgresql_selected_passes": 16,
        "compose_selected_passes": 3,
        "unresolved_skips": 0,
    }:
        raise ReleaseV10Error("v0.10 environment skip resolution differs")
    if manifest["frontend_build"] != {"passed": True, "version": PRODUCT_VERSION}:
        raise ReleaseV10Error("v0.10 frontend build evidence differs")
    if manifest["browser"] != {
        "passed": True,
        "projects": ["chromium", "mobile"],
        "tests": 2,
        "retries": 0,
        "real_backend": True,
    }:
        raise ReleaseV10Error("v0.10 browser evidence differs")
    image = manifest["image"]
    if (
        set(image)
        != {
            "passed",
            "image_id",
            "version",
            "contracts",
            "procedure_count",
            "v11_absent",
            "legacy_documentation_absent",
            "bytecode_absent",
        }
        or image["passed"] is not True
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["image_id"])
        or image["version"] != PRODUCT_VERSION
        or image["contracts"] != ["v10"]
        or image["procedure_count"] != 1
        or image["v11_absent"] is not True
        or image["legacy_documentation_absent"] is not True
        or image["bytecode_absent"] is not True
    ):
        raise ReleaseV10Error("v0.10 image evidence differs")
    if manifest["decision"] != {
        "gate": "PASS",
        "accepted_exceptions": [],
        "operational_authorization": False,
        "deployment_approval": False,
        "compliance_determination": False,
        "cryptographic_signature": "not-claimed",
    }:
        raise ReleaseV10Error("v0.10 qualification decision differs")
    return manifest


def _validate_package(root: Path, qualification: dict) -> tuple[dict, str]:
    manifest = _load_json(root / RELEASE_MANIFEST_PATH, "v0.10 release manifest")
    expected_keys = {
        "schema_version",
        "product_version",
        "release_tag",
        "qualification_sha256",
        "qualified_commit",
        "source_fingerprint_sha256",
        "package_input_commit",
        "package_input_tree",
        "package_path",
        "package_sha256",
        "sidecar_path",
        "sidecar_sha256",
        "file_count",
        "content_manifest_sha256",
        "reproducible_builds",
        "legacy_documentation_packaged",
        "v11_packaged",
        "decision",
    }
    if set(manifest) != expected_keys:
        raise ReleaseV10Error("v0.10 release manifest fields differ")
    if (
        manifest["schema_version"] != "spell.v10.release-manifest/1"
        or manifest["product_version"] != PRODUCT_VERSION
        or manifest["release_tag"] != RELEASE_TAG
        or manifest["qualification_sha256"] != sha256_file(root / QUALIFICATION_PATH)
        or manifest["qualified_commit"] != qualification["qualified_commit"]
        or manifest["source_fingerprint_sha256"] != qualification["source_fingerprint_sha256"]
        or manifest["package_path"] != PACKAGE_PATH.as_posix()
        or manifest["sidecar_path"] != SIDECAR_PATH.as_posix()
        or manifest["reproducible_builds"] != 2
        or manifest["legacy_documentation_packaged"] is not False
        or manifest["v11_packaged"] is not False
        or manifest["decision"] != "PASS"
    ):
        raise ReleaseV10Error("v0.10 release manifest identity differs")
    _assert_ancestor(root, manifest["package_input_commit"])
    if git_tree(root, manifest["package_input_commit"]) != manifest["package_input_tree"]:
        raise ReleaseV10Error("package input tree differs")
    package = root / PACKAGE_PATH
    sidecar = root / SIDECAR_PATH
    if not package.is_file() or not sidecar.is_file():
        raise ReleaseV10Error("v0.10 package or sidecar is missing")
    package_digest = sha256_file(package)
    if package_digest != manifest["package_sha256"]:
        raise ReleaseV10Error("v0.10 package hash differs")
    expected_sidecar = f"{package_digest}  {PACKAGE_PATH.name}\n".encode("ascii")
    if sidecar.read_bytes() != expected_sidecar or sha256_bytes(expected_sidecar) != manifest["sidecar_sha256"]:
        raise ReleaseV10Error("v0.10 package sidecar differs")
    paths = package_files(root)
    rebuilt = archive_bytes(root, paths)
    if rebuilt != package.read_bytes():
        raise ReleaseV10Error("v0.10 package is not reproducible from tracked inputs")
    if manifest["file_count"] != len(paths) or manifest["content_manifest_sha256"] != package_content_manifest(root, paths):
        raise ReleaseV10Error("v0.10 package content manifest differs")
    with tarfile.open(package, mode="r:gz") as archive:
        names = archive.getnames()
    if any(name.startswith(("SPELL_DOCUMENTATION/", "contracts/v11/", "artifacts/v0.11/")) for name in names):
        raise ReleaseV10Error("forbidden legacy or v0.11 path entered package")
    return manifest, package_digest


def tag_message(release_manifest: dict) -> str:
    return (
        "SPELL v0.10.0\n\n"
        "Decision: ACCEPTED\n"
        "Gate: PASS\n"
        "Accepted exceptions: None\n"
        "Operational authorization: None\n"
        "Deployment approval: None\n"
        "Compliance determination: None\n"
        "Cryptographic signature: Not claimed\n"
        f"Qualified commit: {release_manifest['qualified_commit']}\n"
        f"Source fingerprint: {release_manifest['source_fingerprint_sha256']}\n"
        f"Package SHA-256: {release_manifest['package_sha256']}\n"
    )


def _validate_tag(root: Path, release_manifest: dict) -> str:
    object_type = str(_git(root, "cat-file", "-t", f"refs/tags/{RELEASE_TAG}"))
    if object_type != "tag":
        raise ReleaseV10Error("v0.10 release tag must be annotated")
    target = str(_git(root, "rev-parse", f"refs/tags/{RELEASE_TAG}^{{commit}}"))
    if target != git_commit(root):
        raise ReleaseV10Error("v0.10 release tag does not target current release HEAD")
    message = str(_git(root, "tag", "-l", "--format=%(contents)", RELEASE_TAG))
    if message.strip() != tag_message(release_manifest).strip():
        raise ReleaseV10Error("v0.10 annotated tag message differs")
    secondary = str(_git(root, "tag", "-l", "v0.10"))
    if secondary:
        raise ReleaseV10Error("secondary v0.10 tag is forbidden")
    return str(_git(root, "rev-parse", f"refs/tags/{RELEASE_TAG}"))


def validate_release_evidence_v10(
    root: Path = ROOT,
    *,
    require_package: bool = True,
    require_tag: bool = False,
) -> ValidationResult:
    root = root.resolve()
    qualification = validate_qualification(root)
    package_digest: str | None = None
    tag_object: str | None = None
    if require_package:
        release_manifest, package_digest = _validate_package(root, qualification)
        if require_tag:
            tag_object = _validate_tag(root, release_manifest)
    elif require_tag:
        raise ReleaseV10Error("tag validation requires package validation")
    return ValidationResult(
        qualified_commit=qualification["qualified_commit"],
        source_fingerprint_sha256=qualification["source_fingerprint_sha256"],
        package_sha256=package_digest,
        tag_object=tag_object,
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without-package", action="store_true")
    parser.add_argument("--require-tag", action="store_true")
    parser.add_argument("--print-tag-message", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.print_tag_message:
            release_manifest = _load_json(ROOT / RELEASE_MANIFEST_PATH, "v0.10 release manifest")
            print(tag_message(release_manifest), end="")
            return 0
        result = validate_release_evidence_v10(
            require_package=not arguments.without_package,
            require_tag=arguments.require_tag,
        )
    except ReleaseV10Error as exc:
        print(f"v0.10-release-evidence=FAIL reason={exc}")
        return 1
    print(
        "v0.10-release-evidence=PASS "
        f"qualified_commit={result.qualified_commit} "
        f"package_sha256={result.package_sha256 or 'not-required'} "
        f"tag_object={result.tag_object or 'not-required'}"
    )
    return 0


validate_release_evidence = validate_release_evidence_v10


if __name__ == "__main__":
    raise SystemExit(main())
