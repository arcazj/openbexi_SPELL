#!/usr/bin/env python3
"""Validate the exact accepted v0.8 baseline consumed by v0.9 gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v08 import path_has_link_or_reparse_v08


V08_TAG_REF = "refs/tags/v0.8.0"
V08_TAG_OBJECT = "0dcf4f539fd1a9036fe4db4bc159cde04c35cfae"
V08_RAW_TAG_SHA256 = (
    "c609c25cb8987222df0b143f71aa792140171acffd454e31a760c16fb263eede"
)
V08_RELEASE_COMMIT = "d6e01222de3bf52013279e48a099b6ae7ded121d"
V08_QUALIFIED_SOURCE_COMMIT = "d80c4d43969018633bc17650a23412b7274e58ea"
V08_CANDIDATE_COMMIT = "f9c90fe8d6fd593bd9db4ed55f35d56ee3165e8c"
V08_ARTIFACT_TREE = "899dd791fbfd5aa8720c3ce836d5cc2208bac6b9"
V08_SOURCE_FINGERPRINT = (
    "6eafe23737e266f0038930703656eb569b5e321d718dfef218a1448c3b2f5268"
)
V08_EVIDENCE_FINGERPRINT = (
    "6a8f5446aeee9084ef58c9ec2323d6e1d2f8e957cb07e21f46ab9300fab5b1ae"
)
V08_PRODUCT_PACKAGE_SHA256 = (
    "c6f835a5fcc6289408493e68d866493b882bf00139a83ea3709283745a1a4554"
)
V08_WORK_PACKAGE_EVIDENCE_SHA256 = (
    "5fdfa848edf1bdfa8b3b2a161e4dc2c1a356a95cfc424e0e079e5719b1d046d7"
)
V08_ARCHIVE_RELATIVE = "artifacts/v0.8/openbexi-spell-v0.8.0.tar.gz"
V08_ARCHIVE_SHA256 = (
    "87cd104d3c7a92764b3b848a0424f8fddb8522e0b7d8ae6e93310b2ce7e42deb"
)
V08_SIDECAR_RELATIVE = f"{V08_ARCHIVE_RELATIVE}.sha256"
V08_SIDECAR_TEXT = f"{V08_ARCHIVE_SHA256}  openbexi-spell-v0.8.0.tar.gz\n"
V08_SIDECAR_SHA256 = (
    "1527927c7f767a460de3bcd4df127db1be38b58084f2ec73f164389b9660c817"
)
V08_TAG_ARCHIVE_CLAIM = f"Final archive SHA-256: {V08_ARCHIVE_SHA256}"

V08_TAGGED_BLOBS: dict[str, dict[str, str]] = {
    "SPELL_v0.8_Release.md": {
        "object_id": "dc95ef566dd3ea57f7f12b1a0fb5d0eff703675a",
        "sha256": "37735796cd6b3ee968950c447382aea4ede28255244e772975b06d12ee5592cd",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.8-gate-0b.json"
    ): {
        "object_id": "05b7d733e094e7f0a6b68f18654aef3e96e782f0",
        "sha256": "0e3e3fc2eea47d243f67cdc802a14d93e9053c1cf4f75fc1ab0c300392d36d0c",
    },
    "artifacts/v0.8/release-qualification.json": {
        "object_id": "0d9564e0d3621251d4646d806009cbde782f9387",
        "sha256": "82e90f0d3a9481423d948d83559bde56ff332833f14ab2d01a8089ebf6a5e50e",
    },
    V08_ARCHIVE_RELATIVE: {
        "object_id": "8fc3ae351c838dd808b88baa8b21788ad350061e",
        "sha256": V08_ARCHIVE_SHA256,
    },
    V08_SIDECAR_RELATIVE: {
        "object_id": "229577bcb23f586b922930d76088bd0ad95b1b58",
        "sha256": V08_SIDECAR_SHA256,
    },
}

V08_REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Gate 0B: PASS",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
    "Cryptographic signature: Not claimed",
    f"Release commit: {V08_RELEASE_COMMIT}",
    f"Qualified source commit: {V08_QUALIFIED_SOURCE_COMMIT}",
    f"Candidate implementation commit: {V08_CANDIDATE_COMMIT}",
    f"Source fingerprint: {V08_SOURCE_FINGERPRINT}",
    f"Evidence fingerprint: {V08_EVIDENCE_FINGERPRINT}",
    f"Product package SHA-256: {V08_PRODUCT_PACKAGE_SHA256}",
    f"Work-package evidence SHA-256: {V08_WORK_PACKAGE_EVIDENCE_SHA256}",
    V08_TAG_ARCHIVE_CLAIM,
)


class AcceptedV08ReleaseError(ValueError):
    """Raised when the accepted v0.8 release bindings differ."""


@dataclass(frozen=True)
class AcceptedV08Release:
    archive_path: str
    archive_sha256: str
    sidecar_path: str
    sidecar_sha256: str
    tag_ref: str
    tag_object: str
    raw_tag_object_sha256: str
    tag_commit: str
    qualified_source_commit: str
    candidate_commit: str
    artifact_tree: str
    tag_archive_claim: str
    tagged_blobs: dict[str, dict[str, str]]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptedV08ReleaseError(message)


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_REPLACE_REF_BASE",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _run_git(
    root: Path,
    *arguments: str,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcceptedV08ReleaseError(
            f"accepted v0.8 Git binding cannot be inspected: {exc}"
        ) from exc
    _require(
        result.returncode in accepted_returncodes,
        "accepted v0.8 Git binding cannot be inspected",
    )
    return result


def _git(root: Path, *arguments: str) -> bytes:
    return _run_git(root, *arguments).stdout


def _ascii_line(payload: bytes, label: str) -> str:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptedV08ReleaseError(f"{label} is not ASCII") from exc
    _require(len(lines) == 1 and bool(lines[0]), f"{label} is not one line")
    return lines[0]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_external_file(root: Path, relative: str, label: str) -> bytes:
    path = root / relative
    _require(
        path.is_file() and not path_has_link_or_reparse_v08(root, path),
        f"accepted v0.8 {label} is missing or unsafe",
    )
    return path.read_bytes()


def _validate_raw_tag(raw_tag: bytes) -> None:
    _require(
        _sha256_bytes(raw_tag) == V08_RAW_TAG_SHA256,
        "accepted v0.8 raw tag object SHA-256 differs",
    )
    framed = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    _require(
        hashlib.sha1(framed).hexdigest() == V08_TAG_OBJECT,
        "accepted v0.8 tag object ID differs from its raw bytes",
    )
    headers, separator, message = raw_tag.partition(b"\n\n")
    _require(bool(separator), "accepted v0.8 tag lacks a message boundary")
    _require(
        headers.splitlines()[:3]
        == [
            f"object {V08_RELEASE_COMMIT}".encode("ascii"),
            b"type commit",
            b"tag v0.8.0",
        ],
        "accepted v0.8 tag headers differ",
    )
    try:
        message_lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptedV08ReleaseError(
            "accepted v0.8 tag message is not strict UTF-8"
        ) from exc
    for marker in V08_REQUIRED_TAG_MARKERS:
        _require(
            message_lines.count(marker) == 1,
            f"accepted v0.8 tag marker differs: {marker}",
        )


def _tagged_blob(root: Path, relative: str, expected: dict[str, str]) -> bytes:
    object_id = expected["object_id"]
    expected_tree_entry = f"100644 blob {object_id}\t{relative}\0".encode("utf-8")
    _require(
        _git(root, "ls-tree", "-z", V08_RELEASE_COMMIT, "--", relative)
        == expected_tree_entry,
        f"accepted v0.8 tagged tree entry differs: {relative}",
    )
    resolved = _ascii_line(
        _git(
            root,
            "rev-parse",
            "--verify",
            f"{V08_RELEASE_COMMIT}:{relative}",
        ),
        f"accepted v0.8 tagged blob {relative}",
    )
    _require(
        resolved == object_id,
        f"accepted v0.8 tagged blob ID differs: {relative}",
    )
    object_type = _ascii_line(
        _git(root, "cat-file", "-t", object_id),
        f"accepted v0.8 tagged object {relative}",
    )
    _require(
        object_type == "blob",
        f"accepted v0.8 tagged object is not a blob: {relative}",
    )
    payload = _git(root, "cat-file", "blob", object_id)
    _require(
        _sha256_bytes(payload) == expected["sha256"],
        f"accepted v0.8 tagged blob SHA-256 differs: {relative}",
    )
    return payload


def _validate_archive_pair(archive: bytes, sidecar: bytes, label: str) -> None:
    _require(
        _sha256_bytes(archive) == V08_ARCHIVE_SHA256,
        f"accepted v0.8 {label} archive SHA-256 differs",
    )
    _require(
        sidecar == V08_SIDECAR_TEXT.encode("ascii"),
        f"accepted v0.8 {label} sidecar bytes differ",
    )
    _require(
        _sha256_bytes(sidecar) == V08_SIDECAR_SHA256,
        f"accepted v0.8 {label} sidecar SHA-256 differs",
    )


def validate_accepted_v08_release(root: Path) -> AcceptedV08Release:
    source_root = root.resolve()
    workspace_archive = _read_external_file(
        source_root, V08_ARCHIVE_RELATIVE, "archive"
    )
    workspace_sidecar = _read_external_file(
        source_root, V08_SIDECAR_RELATIVE, "sidecar"
    )
    _validate_archive_pair(workspace_archive, workspace_sidecar, "workspace")

    tag_object = _ascii_line(
        _git(source_root, "show-ref", "--verify", "--hash", V08_TAG_REF),
        "accepted v0.8 tag ref",
    )
    _require(tag_object == V08_TAG_OBJECT, "accepted v0.8 tag object differs")
    _require(
        _git(source_root, "cat-file", "-t", tag_object) == b"tag\n",
        "accepted v0.8 tag is not annotated",
    )
    _validate_raw_tag(_git(source_root, "cat-file", "tag", tag_object))

    tag_commit = _ascii_line(
        _git(source_root, "rev-parse", "--verify", f"{V08_TAG_REF}^{{commit}}"),
        "accepted v0.8 peeled release commit",
    )
    _require(
        tag_commit == V08_RELEASE_COMMIT,
        "accepted v0.8 tag target differs",
    )
    release_parent = _ascii_line(
        _git(source_root, "rev-parse", "--verify", f"{V08_RELEASE_COMMIT}^"),
        "accepted v0.8 release parent",
    )
    _require(
        release_parent == V08_QUALIFIED_SOURCE_COMMIT,
        "accepted v0.8 release parent differs",
    )
    artifact_tree = _ascii_line(
        _git(
            source_root,
            "rev-parse",
            "--verify",
            f"{V08_RELEASE_COMMIT}:artifacts/v0.8",
        ),
        "accepted v0.8 artifact tree",
    )
    _require(
        artifact_tree == V08_ARTIFACT_TREE,
        "accepted v0.8 artifact tree differs",
    )
    _require(
        _run_git(
            source_root,
            "merge-base",
            "--is-ancestor",
            V08_CANDIDATE_COMMIT,
            V08_QUALIFIED_SOURCE_COMMIT,
            accepted_returncodes=(0, 1),
        ).returncode
        == 0,
        "accepted v0.8 candidate ancestry differs",
    )

    tagged_payloads = {
        relative: _tagged_blob(source_root, relative, expected)
        for relative, expected in V08_TAGGED_BLOBS.items()
    }
    tagged_archive = tagged_payloads[V08_ARCHIVE_RELATIVE]
    tagged_sidecar = tagged_payloads[V08_SIDECAR_RELATIVE]
    _validate_archive_pair(tagged_archive, tagged_sidecar, "tagged")
    _require(
        workspace_archive == tagged_archive,
        "accepted v0.8 workspace archive differs from tagged bytes",
    )
    _require(
        workspace_sidecar == tagged_sidecar,
        "accepted v0.8 workspace sidecar differs from tagged bytes",
    )

    return AcceptedV08Release(
        archive_path=V08_ARCHIVE_RELATIVE,
        archive_sha256=V08_ARCHIVE_SHA256,
        sidecar_path=V08_SIDECAR_RELATIVE,
        sidecar_sha256=V08_SIDECAR_SHA256,
        tag_ref=V08_TAG_REF,
        tag_object=V08_TAG_OBJECT,
        raw_tag_object_sha256=V08_RAW_TAG_SHA256,
        tag_commit=V08_RELEASE_COMMIT,
        qualified_source_commit=V08_QUALIFIED_SOURCE_COMMIT,
        candidate_commit=V08_CANDIDATE_COMMIT,
        artifact_tree=V08_ARTIFACT_TREE,
        tag_archive_claim=V08_TAG_ARCHIVE_CLAIM,
        tagged_blobs={key: dict(value) for key, value in V08_TAGGED_BLOBS.items()},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    result: dict[str, Any] = asdict(validate_accepted_v08_release(args.root))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
