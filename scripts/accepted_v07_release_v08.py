#!/usr/bin/env python3
"""Validate the exact accepted v0.7 baseline consumed by v0.8 gates."""

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


V07_TAG_REF = "refs/tags/v0.7.0"
V07_TAG_OBJECT = "70e4d46a46d158dee3c63ec37a5d1922b3b61668"
V07_RAW_TAG_SHA256 = (
    "dfa9c0c68cd3c9f3a64768392c001a66b1641e31dcae1ffd5bf2c40197838cae"
)
V07_RELEASE_COMMIT = "cf18e9d887ba0476cbcc3d8194e321332a3ae864"
V07_QUALIFIED_SOURCE_COMMIT = "6ac43c5be7670ead09de821578cc6c6a680af109"
V07_CANDIDATE_COMMIT = "82b497227aff097db9d4c3ff56adf56d76d892ca"
V07_SOURCE_FINGERPRINT = (
    "a04e158843acf2da08696e647d16f8f72f6dd329dd807daeb381f85911b817fb"
)
V07_EVIDENCE_FINGERPRINT = (
    "7fe2a643ed335c4057aaac0976de6f1ef944543aae6ca53e9e71b7a5cffcb718"
)
V07_PRODUCT_PACKAGE_SHA256 = (
    "fc9fb26fcb5cea7518f43064beb3ebb40a298c5ec31b93663fd27b0cabcc6633"
)
V07_WORK_PACKAGE_EVIDENCE_SHA256 = (
    "04176843f3769786e8ffb068bb3fd60048aae90b258a365657a7cb0b1d3d6e20"
)
V07_ARCHIVE_RELATIVE = "artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz"
V07_ARCHIVE_SHA256 = (
    "90761e0b42cc6f88313380cb72c752437a17f8fe300b8f65c02b865dcbe71aa2"
)
V07_SIDECAR_RELATIVE = f"{V07_ARCHIVE_RELATIVE}.sha256"
V07_SIDECAR_TEXT = f"{V07_ARCHIVE_SHA256}  openbexi-spell-v0.7.0.tar.gz\n"
V07_SIDECAR_SHA256 = (
    "c35a6d2451e45f9a36fd9a90af47f5f02d5eb58608905e4c77f9cc0b6a95fe7b"
)
V07_TAG_ARCHIVE_CLAIM = f"Final archive SHA-256: {V07_ARCHIVE_SHA256}"

V07_TAGGED_BLOBS: dict[str, dict[str, str]] = {
    "SPELL_v0.7_Release.md": {
        "object_id": "d1f1f249e5999d1a4a63b665edeaa70ea7139bb4",
        "sha256": "455a0dc8a572b941b0d7f4546f800500e1f59a91aba2333407dd9348d4dba979",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.7-gate-0b.json"
    ): {
        "object_id": "7522110cfe6e2ac07de09879bb0e47ec5aacd116",
        "sha256": "8b8a6985bf4942d6554f9c10b0d2eaf0cab7cd84adcbea170f00eef87249f28f",
    },
    "artifacts/v0.7/release-qualification.json": {
        "object_id": "821f004641e58a38573d978a4da5bac9acb0e2cf",
        "sha256": "e32e6fd025a8bb22af6a0e93151110f934b29df0a86004eae168e19fde42a70a",
    },
    V07_ARCHIVE_RELATIVE: {
        "object_id": "1dee6392f5c86f01801c71b4093169a7337f514b",
        "sha256": V07_ARCHIVE_SHA256,
    },
    V07_SIDECAR_RELATIVE: {
        "object_id": "28fc25b561460663f2a51726dbfea50bd79423fe",
        "sha256": V07_SIDECAR_SHA256,
    },
}

V07_REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Gate 0B: PASS",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
    "Cryptographic signature: Not claimed",
    f"Release commit: {V07_RELEASE_COMMIT}",
    f"Qualified source commit: {V07_QUALIFIED_SOURCE_COMMIT}",
    f"Candidate implementation commit: {V07_CANDIDATE_COMMIT}",
    f"Source fingerprint: {V07_SOURCE_FINGERPRINT}",
    f"Evidence fingerprint: {V07_EVIDENCE_FINGERPRINT}",
    f"Product package SHA-256: {V07_PRODUCT_PACKAGE_SHA256}",
    f"Work-package evidence SHA-256: {V07_WORK_PACKAGE_EVIDENCE_SHA256}",
    V07_TAG_ARCHIVE_CLAIM,
)


class AcceptedV07ReleaseError(ValueError):
    """Raised when the accepted v0.7 release bindings differ."""


@dataclass(frozen=True)
class AcceptedV07Release:
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
    tag_archive_claim: str
    tagged_blobs: dict[str, dict[str, str]]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptedV07ReleaseError(message)


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
        raise AcceptedV07ReleaseError(
            f"accepted v0.7 Git binding cannot be inspected: {exc}"
        ) from exc
    _require(
        result.returncode in accepted_returncodes,
        "accepted v0.7 Git binding cannot be inspected",
    )
    return result


def _git(root: Path, *arguments: str) -> bytes:
    return _run_git(root, *arguments).stdout


def _ascii_line(payload: bytes, label: str) -> str:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptedV07ReleaseError(f"{label} is not ASCII") from exc
    _require(len(lines) == 1 and bool(lines[0]), f"{label} is not one line")
    return lines[0]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_external_file(root: Path, relative: str, label: str) -> bytes:
    path = root / relative
    _require(
        path.is_file() and not path_has_link_or_reparse_v08(root, path),
        f"accepted v0.7 {label} is missing or unsafe",
    )
    return path.read_bytes()


def _validate_raw_tag(raw_tag: bytes) -> None:
    _require(
        _sha256_bytes(raw_tag) == V07_RAW_TAG_SHA256,
        "accepted v0.7 raw tag object SHA-256 differs",
    )
    framed = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    _require(
        hashlib.sha1(framed).hexdigest() == V07_TAG_OBJECT,
        "accepted v0.7 tag object ID differs from its raw bytes",
    )
    headers, separator, message = raw_tag.partition(b"\n\n")
    _require(bool(separator), "accepted v0.7 tag lacks a message boundary")
    _require(
        headers.splitlines()[:3]
        == [
            f"object {V07_RELEASE_COMMIT}".encode("ascii"),
            b"type commit",
            b"tag v0.7.0",
        ],
        "accepted v0.7 tag headers differ",
    )
    try:
        message_lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptedV07ReleaseError(
            "accepted v0.7 tag message is not strict UTF-8"
        ) from exc
    for marker in V07_REQUIRED_TAG_MARKERS:
        _require(
            message_lines.count(marker) == 1,
            f"accepted v0.7 tag marker differs: {marker}",
        )


def _tagged_blob(root: Path, relative: str, expected: dict[str, str]) -> bytes:
    object_id = expected["object_id"]
    expected_tree_entry = f"100644 blob {object_id}\t{relative}\0".encode("utf-8")
    _require(
        _git(root, "ls-tree", "-z", V07_RELEASE_COMMIT, "--", relative)
        == expected_tree_entry,
        f"accepted v0.7 tagged tree entry differs: {relative}",
    )
    resolved = _ascii_line(
        _git(
            root,
            "rev-parse",
            "--verify",
            f"{V07_RELEASE_COMMIT}:{relative}",
        ),
        f"accepted v0.7 tagged blob {relative}",
    )
    _require(
        resolved == object_id,
        f"accepted v0.7 tagged blob ID differs: {relative}",
    )
    object_type = _ascii_line(
        _git(root, "cat-file", "-t", object_id),
        f"accepted v0.7 tagged object {relative}",
    )
    _require(
        object_type == "blob",
        f"accepted v0.7 tagged object is not a blob: {relative}",
    )
    payload = _git(root, "cat-file", "blob", object_id)
    _require(
        _sha256_bytes(payload) == expected["sha256"],
        f"accepted v0.7 tagged blob SHA-256 differs: {relative}",
    )
    return payload


def _validate_archive_pair(archive: bytes, sidecar: bytes, label: str) -> None:
    _require(
        _sha256_bytes(archive) == V07_ARCHIVE_SHA256,
        f"accepted v0.7 {label} archive SHA-256 differs",
    )
    _require(
        sidecar == V07_SIDECAR_TEXT.encode("ascii"),
        f"accepted v0.7 {label} sidecar bytes differ",
    )
    _require(
        _sha256_bytes(sidecar) == V07_SIDECAR_SHA256,
        f"accepted v0.7 {label} sidecar SHA-256 differs",
    )


def validate_accepted_v07_release(root: Path) -> AcceptedV07Release:
    source_root = root.resolve()
    workspace_archive = _read_external_file(
        source_root, V07_ARCHIVE_RELATIVE, "archive"
    )
    workspace_sidecar = _read_external_file(
        source_root, V07_SIDECAR_RELATIVE, "sidecar"
    )
    _validate_archive_pair(workspace_archive, workspace_sidecar, "workspace")

    tag_object = _ascii_line(
        _git(source_root, "show-ref", "--verify", "--hash", V07_TAG_REF),
        "accepted v0.7 tag ref",
    )
    _require(tag_object == V07_TAG_OBJECT, "accepted v0.7 tag object differs")
    _require(
        _git(source_root, "cat-file", "-t", tag_object) == b"tag\n",
        "accepted v0.7 tag is not annotated",
    )
    _validate_raw_tag(_git(source_root, "cat-file", "tag", tag_object))

    tag_commit = _ascii_line(
        _git(source_root, "rev-parse", "--verify", f"{V07_TAG_REF}^{{commit}}"),
        "accepted v0.7 peeled release commit",
    )
    _require(
        tag_commit == V07_RELEASE_COMMIT,
        "accepted v0.7 tag target differs",
    )
    release_parent = _ascii_line(
        _git(source_root, "rev-parse", "--verify", f"{V07_RELEASE_COMMIT}^"),
        "accepted v0.7 release parent",
    )
    _require(
        release_parent == V07_QUALIFIED_SOURCE_COMMIT,
        "accepted v0.7 release parent differs",
    )
    _require(
        _run_git(
            source_root,
            "merge-base",
            "--is-ancestor",
            V07_CANDIDATE_COMMIT,
            V07_QUALIFIED_SOURCE_COMMIT,
            accepted_returncodes=(0, 1),
        ).returncode
        == 0,
        "accepted v0.7 candidate ancestry differs",
    )

    tagged_payloads = {
        relative: _tagged_blob(source_root, relative, expected)
        for relative, expected in V07_TAGGED_BLOBS.items()
    }
    tagged_archive = tagged_payloads[V07_ARCHIVE_RELATIVE]
    tagged_sidecar = tagged_payloads[V07_SIDECAR_RELATIVE]
    _validate_archive_pair(tagged_archive, tagged_sidecar, "tagged")
    _require(
        workspace_archive == tagged_archive,
        "accepted v0.7 workspace archive differs from tagged bytes",
    )
    _require(
        workspace_sidecar == tagged_sidecar,
        "accepted v0.7 workspace sidecar differs from tagged bytes",
    )

    return AcceptedV07Release(
        archive_path=V07_ARCHIVE_RELATIVE,
        archive_sha256=V07_ARCHIVE_SHA256,
        sidecar_path=V07_SIDECAR_RELATIVE,
        sidecar_sha256=V07_SIDECAR_SHA256,
        tag_ref=V07_TAG_REF,
        tag_object=V07_TAG_OBJECT,
        raw_tag_object_sha256=V07_RAW_TAG_SHA256,
        tag_commit=V07_RELEASE_COMMIT,
        qualified_source_commit=V07_QUALIFIED_SOURCE_COMMIT,
        candidate_commit=V07_CANDIDATE_COMMIT,
        tag_archive_claim=V07_TAG_ARCHIVE_CLAIM,
        tagged_blobs={key: dict(value) for key, value in V07_TAGGED_BLOBS.items()},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    result: dict[str, Any] = asdict(validate_accepted_v07_release(args.root))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
