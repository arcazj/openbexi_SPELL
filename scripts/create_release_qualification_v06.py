#!/usr/bin/env python3
"""Create the canonical SPELL v0.6.0 release-qualification manifest."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import validate_release_evidence_v06 as release  # noqa: E402
from scripts.build_reproducible_v06 import product_package_sha256_v06  # noqa: E402
from scripts.source_fingerprint_v06 import source_fingerprint_v06  # noqa: E402


MANIFEST_RELATIVE = Path("artifacts/v0.6") / release.MANIFEST_NAME
WORK_PACKAGE_EVIDENCE_PATHS = frozenset(
    path
    for path in release.CANONICAL_EVIDENCE_PATHS
    if path.startswith("artifacts/v0.6/work-package/")
)
FINAL_EVIDENCE_PATHS = release.CANONICAL_EVIDENCE_PATHS - WORK_PACKAGE_EVIDENCE_PATHS


class ReleaseQualificationProductionError(release.ReleaseEvidenceError):
    """Raised when the canonical release manifest cannot be produced."""


@dataclass(frozen=True)
class QualifiedSourceV06:
    commit: str
    tree: str
    parent: str
    candidate_commit: str
    candidate_delta_paths: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseQualificationProductionV06:
    path: str
    sha256: str
    qualified_source_commit: str
    source_fingerprint_sha256: str
    product_package_sha256: str
    evidence_fingerprint_sha256: str
    tag_message_fields: tuple[str, ...]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseQualificationProductionError(message)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    try:
        return release._mapping(value, label)
    except release.ReleaseEvidenceError as exc:
        raise ReleaseQualificationProductionError(str(exc)) from exc


def _read_mapping(root: Path, relative: str, label: str) -> dict[str, Any]:
    return _mapping(release.read_strict_json(root / relative, label), label)


def _sha256_file(root: Path, relative: str, label: str) -> str:
    path = release._regular_relative(root, relative, label)
    return release.sha256_bytes(path.read_bytes())


def _assert_tag_absent(root: Path, ref: str) -> None:
    result = release._run_git(
        root,
        ["show-ref", "--verify", "--hash", ref],
        accepted=(0, 1, 128),
    )
    _require(
        result.returncode != 0 and result.stdout == b"",
        f"release manifest must be created before tag exists: {ref}",
    )


def _validate_generation_paths(
    *,
    tracked_evidence: Sequence[str],
    changed_paths: Sequence[str],
    untracked_paths: Sequence[str],
    candidate_delta_paths: Sequence[str],
    manifest_present: bool,
) -> None:
    _require(
        list(tracked_evidence) == sorted(WORK_PACKAGE_EVIDENCE_PATHS),
        "qualified source must commit exactly the canonical work-package evidence",
    )
    _require(not changed_paths, "release-manifest production requires no tracked working-tree changes")
    expected_untracked = set(FINAL_EVIDENCE_PATHS)
    if manifest_present:
        expected_untracked.add(MANIFEST_RELATIVE.as_posix())
    _require(
        set(untracked_paths) == expected_untracked
        and len(untracked_paths) == len(expected_untracked),
        "pre-manifest untracked inventory must contain only complete canonical final evidence",
    )
    _require(
        list(candidate_delta_paths) == sorted(set(candidate_delta_paths)),
        "candidate-to-qualified-source paths must be sorted and unique",
    )
    for path in candidate_delta_paths:
        release._safe_relative(path, "candidate-to-qualified-source path")
        _require(
            release._allowed_candidate_path(path),
            f"qualified source contains an unauthorized candidate delta: {path}",
        )


def _assert_generation_git_state(
    root: Path,
    *,
    manifest_present: bool,
) -> QualifiedSourceV06:
    _assert_tag_absent(root, release.RELEASE_TAG_REF)
    _assert_tag_absent(root, release.FORBIDDEN_ALIAS_REF)
    commit = release._git_line(root, ["rev-parse", "HEAD"], "qualified source HEAD")
    tree = release._git_line(root, ["rev-parse", "HEAD^{tree}"], "qualified source tree")
    parent = release._git_line(root, ["rev-parse", "HEAD^"], "qualified source parent")
    candidate_commit = release.candidate_source_commit(root)
    ancestry = release._run_git(
        root,
        ["merge-base", "--is-ancestor", candidate_commit, commit],
        accepted=(0, 1),
    )
    _require(ancestry.returncode == 0, "candidate is not an ancestor of source freeze")
    gate_ancestry = release._run_git(
        root,
        ["merge-base", "--is-ancestor", release.GATE_0A_COMMIT, commit],
        accepted=(0, 1),
    )
    _require(gate_ancestry.returncode == 0, "Gate 0A is not an ancestor of source freeze")
    candidate_delta = sorted(
        release._git_name_list(
            root,
            ["diff", "--name-only", "-z", candidate_commit, commit],
            "candidate-to-qualified-source delta",
        )
    )
    tracked_evidence = sorted(
        release._git_name_list(
            root,
            ["ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "artifacts/v0.6"],
            "qualified source evidence tree",
        )
    )
    changed = sorted(
        release._git_name_list(
            root,
            ["diff", "--name-only", "-z", "HEAD", "--"],
            "tracked working-tree delta",
        )
    )
    untracked = sorted(
        release._git_name_list(
            root,
            ["ls-files", "--others", "--exclude-standard", "-z"],
            "untracked pre-manifest inventory",
        )
    )
    _validate_generation_paths(
        tracked_evidence=tracked_evidence,
        changed_paths=changed,
        untracked_paths=untracked,
        candidate_delta_paths=candidate_delta,
        manifest_present=manifest_present,
    )
    for package_path in release.RELEASE_PACKAGE_PATHS:
        _require(
            not (root / package_path).exists(),
            "release qualification must be created before package publication",
        )
    return QualifiedSourceV06(
        commit, tree, parent, candidate_commit, tuple(candidate_delta)
    )


def _work_package_and_toolchain(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = _read_mapping(root, release.WORK_PACKAGE_PATH, "candidate qualification")
    toolchain = _mapping(candidate.get("toolchain"), "candidate toolchain")
    work_package = {
        "evidence_path": release.WORK_PACKAGE_PATH,
        "evidence_sha256": _sha256_file(
            root, release.WORK_PACKAGE_PATH, "candidate qualification"
        ),
        "validator_path": release.WORK_PACKAGE_VALIDATOR,
        "validator_sha256": _sha256_file(
            root, release.WORK_PACKAGE_VALIDATOR, "candidate validator"
        ),
        "candidate_commit": release.candidate_source_commit(root),
    }
    return work_package, toolchain


def _validate_final_toolchain_transition(
    candidate: Mapping[str, Any], final: Mapping[str, Any]
) -> None:
    candidate_keys = {
        "python", "docker", "node", "npm", "playwright", "chromium",
        "files_sha256", "qualification_image_id",
    }
    final_keys = {
        "python", "docker", "node", "npm", "playwright", "chromium",
        "files_sha256", "candidate_qualification_image_id",
        "final_qualification_image_id",
    }
    release._exact_keys(candidate, candidate_keys, "candidate toolchain")
    release._exact_keys(final, final_keys, "final toolchain")
    for key in ("python", "docker", "node", "npm", "playwright", "chromium", "files_sha256"):
        _require(
            final.get(key) == candidate.get(key),
            f"final toolchain immutable binding differs: {key}",
        )
    _require(
        final.get("candidate_qualification_image_id")
        == candidate.get("qualification_image_id"),
        "final toolchain candidate image binding differs",
    )
    for key in ("candidate_qualification_image_id", "final_qualification_image_id"):
        image_id = final.get(key)
        _require(
            isinstance(image_id, str)
            and release.IMAGE_ID_RE.fullmatch(image_id) is not None,
            f"final toolchain {key} is invalid",
        )


def _gate_0b(root: Path) -> dict[str, Any]:
    return {
        "scope_path": release.GATE_0B_SCOPE,
        "scope_sha256": _sha256_file(root, release.GATE_0B_SCOPE, "Gate 0B scope"),
        "document_path": release.GATE_0B_DOCUMENT,
        "document_sha256": _sha256_file(
            root, release.GATE_0B_DOCUMENT, "Gate 0B document"
        ),
        "validator_path": release.GATE_0B_VALIDATOR,
        "validator_sha256": _sha256_file(
            root, release.GATE_0B_VALIDATOR, "Gate 0B validator"
        ),
        "success_marker": release.GATE_0B_MARKER,
    }


def _final_qualification(
    root: Path,
) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    summary = _read_mapping(
        root, release.FINAL_QUALIFICATION_PATH, "final qualification summary"
    )
    suites = _mapping(summary.get("suites"), "final qualification suites")
    binding = {
        "path": release.FINAL_QUALIFICATION_PATH,
        "sha256": _sha256_file(
            root, release.FINAL_QUALIFICATION_PATH, "final qualification summary"
        ),
    }
    return binding, suites, summary


def _sbom(root: Path, source_fingerprint: str) -> dict[str, Any]:
    directory_relative = "artifacts/v0.6/sbom"
    checksum_relative = f"{directory_relative}/SHA256SUMS"
    checksum_path = release._regular_relative(root, checksum_relative, "SBOM checksums")
    checksums = release._parse_sha256sums(checksum_path, set(release.SBOM_FILES))
    inventories: dict[str, dict[str, str]] = {}
    for name in release.SBOM_FILES:
        relative = f"{directory_relative}/{name}"
        path = release._regular_relative(root, relative, f"SBOM {name}")
        digest = release.sha256_bytes(path.read_bytes())
        _require(digest == checksums[name], f"SBOM checksum differs while producing manifest: {name}")
        inventory = _mapping(release.read_strict_json(path, f"SBOM {name}"), f"SBOM {name}")
        metadata = _mapping(inventory.get("metadata"), f"SBOM {name}.metadata")
        subject = _mapping(metadata.get("component"), f"SBOM {name}.metadata.component")
        properties = metadata.get("properties")
        _require(isinstance(properties, list), f"SBOM {name} properties are missing")
        image_ids = [
            item.get("value")
            for item in properties
            if isinstance(item, dict) and item.get("name") == release.SBOM_IMAGE_PROPERTY
        ]
        _require(
            len(image_ids) == 1 and isinstance(image_ids[0], str),
            f"SBOM {name} image identity is missing or ambiguous",
        )
        subject_name = subject.get("name")
        _require(isinstance(subject_name, str), f"SBOM {name} subject is invalid")
        inventories[name] = {
            "sha256": digest,
            "subject": subject_name,
            "image_id": image_ids[0],
        }
    return {
        "directory": directory_relative,
        "checksum_manifest": checksum_relative,
        "checksum_manifest_sha256": release.sha256_bytes(checksum_path.read_bytes()),
        "inventories": inventories,
        "source_fingerprint_sha256": source_fingerprint,
    }


def _supply_chain(root: Path, source_fingerprint: str) -> dict[str, Any]:
    relative = "artifacts/v0.6/supply-chain.json"
    capture = _read_mapping(root, relative, "supply-chain capture")
    metrics = _mapping(capture.get("metrics"), "supply-chain metrics")
    return {
        "capture": relative,
        "sha256": _sha256_file(root, relative, "supply-chain capture"),
        "test_id": capture.get("test_id"),
        "passed": capture.get("passed"),
        "source_fingerprint_sha256": source_fingerprint,
        "critical_finding_count": metrics.get("critical_finding_count"),
        "high_finding_count": metrics.get("high_finding_count"),
        "unlocked_input_count": metrics.get("unlocked_input_count"),
        "accepted_v05_artifacts_unchanged": capture.get(
            "accepted_v05_artifacts_unchanged"
        ),
        "accepted_v05_release": capture.get("accepted_v05_release"),
    }


def _evidence(root: Path) -> dict[str, Any]:
    files = release.canonical_evidence_files(root, root / "artifacts/v0.6")
    declarations = {
        relative: release.sha256_bytes(path.read_bytes())
        for relative, path in files.items()
    }
    return {
        "files": declarations,
        "evidence_fingerprint_sha256": release.evidence_fingerprint_v06(files),
    }


def _tag_policy() -> dict[str, Any]:
    return {
        "tag_name": release.RELEASE_TAG,
        "tag_ref": release.RELEASE_TAG_REF,
        "object_type": "tag",
        "target_policy": "CURRENT_RELEASE_HEAD",
        "package_path": release.RELEASE_PACKAGE_PATH,
        "sidecar_path": release.RELEASE_PACKAGE_SIDECAR_PATH,
        "required_static_markers": [
            "Owner: JC Arcaz",
            "Decision: ACCEPTED",
            "Gate 0B: PASS",
            "Accepted exceptions: None",
            "Operational authorization: None",
            "Compliance determination: None",
            "Cryptographic signature: Not claimed",
        ],
        "required_dynamic_fields": list(release.RELEASE_TAG_DYNAMIC_FIELDS),
    }


def _validate_manifest_components(root: Path, manifest: Mapping[str, Any]) -> None:
    release.validate_release_manifest_shape(manifest)
    release.validate_version_metadata(root)
    source = _mapping(manifest["qualified_source"], "qualified_source")
    release.validate_toolchain(root, _mapping(manifest["toolchain"], "toolchain"))
    release.validate_work_package(root, _mapping(manifest["work_package"], "work_package"))
    release.validate_gate_0b(root, _mapping(manifest["gate_0b"], "gate_0b"))
    release.validate_v05_unchanged(root, _mapping(manifest["inherited_v05"], "inherited_v05"))
    suites = _mapping(manifest["final_suites"], "final_suites")
    release.validate_final_qualification(
        root,
        _mapping(manifest["final_qualification"], "final_qualification"),
        qualified_source_commit=str(source["commit"]),
        qualified_source_tree=str(source["tree"]),
        source_fingerprint=str(source["source_fingerprint_sha256"]),
        product_package_sha256=str(source["product_package_sha256"]),
        work_package=_mapping(manifest["work_package"], "work_package"),
        gate_0b=_mapping(manifest["gate_0b"], "gate_0b"),
        toolchain=_mapping(manifest["toolchain"], "toolchain"),
        final_suites=suites,
    )
    release.validate_final_suites(root, suites, str(source["source_fingerprint_sha256"]))
    release.validate_sbom(
        root,
        _mapping(manifest["sbom"], "sbom"),
        str(source["source_fingerprint_sha256"]),
    )
    release.validate_supply_chain(
        root,
        _mapping(manifest["supply_chain"], "supply_chain"),
        str(source["source_fingerprint_sha256"]),
    )
    release.validate_evidence_inventory(
        root,
        root / "artifacts/v0.6",
        _mapping(manifest["evidence"], "evidence"),
    )
    release.validate_teardown(_mapping(manifest["teardown"], "teardown"))
    release.validate_tag_policy(_mapping(manifest["tag_policy"], "tag_policy"))


def build_release_qualification_v06(root: Path) -> dict[str, Any]:
    source_root = root.resolve()
    manifest_path = source_root / MANIFEST_RELATIVE
    source = _assert_generation_git_state(
        source_root, manifest_present=manifest_path.exists()
    )
    source_fingerprint = source_fingerprint_v06(source_root)
    product_package = product_package_sha256_v06(source_root)
    work_package, candidate_toolchain = _work_package_and_toolchain(source_root)
    gate_0b = _gate_0b(source_root)
    final_binding, final_suites, final_summary = _final_qualification(source_root)
    final_toolchain = _mapping(
        final_summary.get("toolchain"), "final qualification toolchain"
    )
    _validate_final_toolchain_transition(candidate_toolchain, final_toolchain)
    evidence = _evidence(source_root)
    manifest = {
        "schema_version": release.SCHEMA_VERSION,
        "product_version": release.PRODUCT_VERSION,
        "scope_profile": release.SCOPE_PROFILE,
        "decision": {
            "owner": "JC Arcaz",
            "release_status": "READY_FOR_ANNOTATED_TAG",
            "accepted_exceptions": [],
            "operational_authorization": False,
            "compliance_determination": False,
            "cryptographic_signature_claimed": False,
        },
        "qualified_source": {
            "commit": source.commit,
            "tree": source.tree,
            "parent": source.parent,
            "candidate_commit": source.candidate_commit,
            "gate_0a_commit": release.GATE_0A_COMMIT,
            "candidate_delta_paths": list(source.candidate_delta_paths),
            "source_fingerprint_sha256": source_fingerprint,
            "product_package_sha256": product_package,
        },
        "work_package": work_package,
        "gate_0b": gate_0b,
        "toolchain": final_toolchain,
        "final_qualification": final_binding,
        "final_suites": final_suites,
        "inherited_v05": {
            "classification": "ACCEPTED_RELEASE_BASELINE_NOT_DIRECT_V06_PROOF",
            "supports": ["release-lineage", "compatibility", "toolchain"],
            "direct_v06_proof": False,
            "accepted_tag_ref": release.V05_TAG_REF,
            "accepted_tag_object": release.V05_TAG_OBJECT,
            "accepted_commit": release.V05_COMMIT,
            "accepted_artifact_tree": release.V05_ARTIFACT_TREE,
            "accepted_archive_path": release.V05_ARCHIVE_RELATIVE,
            "accepted_archive_sha256": release.V05_ARCHIVE_SHA256,
            "accepted_sidecar_path": release.V05_SIDECAR_RELATIVE,
            "accepted_sidecar_sha256": release.V05_SIDECAR_SHA256,
            "accepted_tag_archive_claim": release.V05_TAG_ARCHIVE_CLAIM,
        },
        "sbom": _sbom(source_root, source_fingerprint),
        "supply_chain": _supply_chain(source_root, source_fingerprint),
        "evidence": evidence,
        "teardown": {
            "qualification_resources_torn_down": True,
            "runtime_test_resources_torn_down": True,
            "supply_chain_resources_torn_down": True,
            "sbom_resources_torn_down": True,
            "temporary_evidence_removed": True,
            "secrets_retained": False,
        },
        "tag_policy": _tag_policy(),
        "overall_pass": True,
    }
    _require(
        final_summary.get("work_package") == work_package,
        "final qualification does not bind the current work package",
    )
    _require(
        final_summary.get("gate_0b") == gate_0b,
        "final qualification does not bind the current Gate 0B",
    )
    _validate_manifest_components(source_root, manifest)
    _require(
        source_fingerprint_v06(source_root) == source_fingerprint,
        "source changed while release qualification was assembled",
    )
    _require(
        product_package_sha256_v06(source_root) == product_package,
        "product package bytes changed while release qualification was assembled",
    )
    after = _assert_generation_git_state(
        source_root, manifest_present=manifest_path.exists()
    )
    _require(after == source, "qualified source Git state changed during manifest assembly")
    return manifest


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(manifest, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def create_release_qualification_v06(
    root: Path,
) -> ReleaseQualificationProductionV06:
    source_root = root.resolve()
    output = source_root / MANIFEST_RELATIVE
    manifest = build_release_qualification_v06(source_root)
    raw = _manifest_bytes(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    _require(
        not release.path_has_link_or_reparse_v06(source_root, output.parent),
        "release qualification output directory must not be a link or reparse point",
    )
    _require(
        not release.path_has_link_or_reparse_v06(source_root, output),
        "release qualification output must not be a link or reparse point",
    )
    if output.exists():
        _require(output.is_file(), "release qualification output is not a regular file")
        _require(
            output.read_bytes() == raw,
            "refusing to replace a different release qualification manifest",
        )
    else:
        temporary = output.with_name(f".{output.name}.tmp-{uuid.uuid4().hex}")
        try:
            with temporary.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    after = _assert_generation_git_state(source_root, manifest_present=True)
    source = _mapping(manifest["qualified_source"], "qualified_source")
    _require(
        after.commit == source["commit"] and after.tree == source["tree"],
        "qualified source changed while release manifest was published",
    )
    return ReleaseQualificationProductionV06(
        path=MANIFEST_RELATIVE.as_posix(),
        sha256=release.sha256_bytes(raw),
        qualified_source_commit=str(source["commit"]),
        source_fingerprint_sha256=str(source["source_fingerprint_sha256"]),
        product_package_sha256=str(source["product_package_sha256"]),
        evidence_fingerprint_sha256=str(
            _mapping(manifest["evidence"], "evidence")["evidence_fingerprint_sha256"]
        ),
        tag_message_fields=tuple(release.RELEASE_TAG_DYNAMIC_FIELDS),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    result = create_release_qualification_v06(args.root)
    print(
        json.dumps(
            {
                "schema_version": release.SCHEMA_VERSION,
                "manifest_path": result.path,
                "manifest_sha256": result.sha256,
                "qualified_source_commit": result.qualified_source_commit,
                "source_fingerprint_sha256": result.source_fingerprint_sha256,
                "product_package_sha256": result.product_package_sha256,
                "evidence_fingerprint_sha256": result.evidence_fingerprint_sha256,
                "tag_message_fields": list(result.tag_message_fields),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
