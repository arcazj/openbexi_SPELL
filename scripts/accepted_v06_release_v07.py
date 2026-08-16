#!/usr/bin/env python3
"""Validate the exact accepted v0.6 baseline consumed by v0.7 gates."""

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

from scripts.source_fingerprint_v07 import path_has_link_or_reparse_v07


V06_TAG_REF = "refs/tags/v0.6.0"
V06_TAG_OBJECT = "b6dc64dc8fb6cfe9845f454904a078ec6f3c0919"
V06_RAW_TAG_SHA256 = (
    "b08b3e66b0018a6f559b696cdd478b639f5ecbabc750b9049c85a8f8a17dd8a4"
)
V06_RELEASE_COMMIT = "05ec783a6e54a76e0548bdd536c18538f6bff51b"
V06_QUALIFIED_SOURCE_COMMIT = "8d9db4b6acc443ca6309cdfb12b5d4f9b2fef213"
V06_CANDIDATE_COMMIT = "0ea26105e72d7830de4a265989ed7d9074ffbe09"
V06_SOURCE_FINGERPRINT = (
    "3c0245d5f9716969ef04dcf114bb8448a883f18dc801d8ccbcee06396363d3e1"
)
V06_EVIDENCE_FINGERPRINT = (
    "33e05aca329c5b3d66ebf1184327c1482294599ce7874b9d625de38365447376"
)
V06_PRODUCT_PACKAGE_SHA256 = (
    "50bb87ef5dec937c259d1082ba77990a1e34cadd509c7559190969b79bde6cac"
)
V06_WORK_PACKAGE_EVIDENCE_SHA256 = (
    "16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538"
)
V06_ARCHIVE_RELATIVE = "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz"
V06_ARCHIVE_SHA256 = (
    "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
)
V06_SIDECAR_RELATIVE = f"{V06_ARCHIVE_RELATIVE}.sha256"
V06_SIDECAR_TEXT = f"{V06_ARCHIVE_SHA256}  openbexi-spell-v0.6.0.tar.gz\n"
V06_SIDECAR_SHA256 = (
    "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
)
V06_TAG_ARCHIVE_CLAIM = f"Final archive SHA-256: {V06_ARCHIVE_SHA256}"

V06_TAGGED_BLOBS: dict[str, dict[str, str]] = {
    "SPELL_v0.6_Release.md": {
        "object_id": "c265d6bdb77d71c286d169205d0de35e4c0fdcff",
        "sha256": "9eb9121470f7cdf097f55917bdcead7748b0257209ff8adfa957d7ca1bb4a7da",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.6-gate-0b.json"
    ): {
        "object_id": "ae71f4b678ea24148f3f4441aa5c22100458bab2",
        "sha256": "0deef3794c7dd34ef9995f95d33f2688aebfa198b96579e655273603555205bc",
    },
    "artifacts/v0.6/release-qualification.json": {
        "object_id": "968fff577d936ca3ce27990fb338e9e20f5a2fdd",
        "sha256": "cbff6f30fca8708260a0a94bf60f3834455dee9cfa2021b5ae4dd2ec83b4c98f",
    },
    V06_ARCHIVE_RELATIVE: {
        "object_id": "e748945e218057ae14351b88d5e25d59ca043289",
        "sha256": V06_ARCHIVE_SHA256,
    },
    V06_SIDECAR_RELATIVE: {
        "object_id": "0563fda5c3227de831eaeef1ef1c6e67f5bc0835",
        "sha256": V06_SIDECAR_SHA256,
    },
}

V06_REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Gate 0B: PASS",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
    "Cryptographic signature: Not claimed",
    f"Release commit: {V06_RELEASE_COMMIT}",
    f"Qualified source commit: {V06_QUALIFIED_SOURCE_COMMIT}",
    f"Candidate implementation commit: {V06_CANDIDATE_COMMIT}",
    f"Source fingerprint: {V06_SOURCE_FINGERPRINT}",
    f"Evidence fingerprint: {V06_EVIDENCE_FINGERPRINT}",
    f"Product package SHA-256: {V06_PRODUCT_PACKAGE_SHA256}",
    f"Work-package evidence SHA-256: {V06_WORK_PACKAGE_EVIDENCE_SHA256}",
    V06_TAG_ARCHIVE_CLAIM,
)


class AcceptedV06ReleaseError(ValueError):
    """Raised when the accepted v0.6 release bindings differ."""


@dataclass(frozen=True)
class AcceptedV06Release:
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
        raise AcceptedV06ReleaseError(message)


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
        raise AcceptedV06ReleaseError(
            f"accepted v0.6 Git binding cannot be inspected: {exc}"
        ) from exc
    _require(
        result.returncode in accepted_returncodes,
        "accepted v0.6 Git binding cannot be inspected",
    )
    return result


def _git(root: Path, *arguments: str) -> bytes:
    return _run_git(root, *arguments).stdout


def _ascii_line(payload: bytes, label: str) -> str:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptedV06ReleaseError(f"{label} is not ASCII") from exc
    _require(len(lines) == 1 and bool(lines[0]), f"{label} is not one line")
    return lines[0]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_external_file(root: Path, relative: str, label: str) -> bytes:
    path = root / relative
    _require(
        path.is_file() and not path_has_link_or_reparse_v07(root, path),
        f"accepted v0.6 {label} is missing or unsafe",
    )
    return path.read_bytes()


def _validate_raw_tag(raw_tag: bytes) -> None:
    _require(
        _sha256_bytes(raw_tag) == V06_RAW_TAG_SHA256,
        "accepted v0.6 raw tag object SHA-256 differs",
    )
    framed = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    _require(
        hashlib.sha1(framed).hexdigest() == V06_TAG_OBJECT,
        "accepted v0.6 tag object ID differs from its raw bytes",
    )
    headers, separator, message = raw_tag.partition(b"\n\n")
    _require(bool(separator), "accepted v0.6 tag lacks a message boundary")
    _require(
        headers.splitlines()[:3]
        == [
            f"object {V06_RELEASE_COMMIT}".encode("ascii"),
            b"type commit",
            b"tag v0.6.0",
        ],
        "accepted v0.6 tag headers differ",
    )
    try:
        message_lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AcceptedV06ReleaseError(
            "accepted v0.6 tag message is not strict UTF-8"
        ) from exc
    for marker in V06_REQUIRED_TAG_MARKERS:
        _require(
            message_lines.count(marker) == 1,
            f"accepted v0.6 tag marker differs: {marker}",
        )


def _tagged_blob(root: Path, relative: str, expected: dict[str, str]) -> bytes:
    object_id = expected["object_id"]
    expected_tree_entry = f"100644 blob {object_id}\t{relative}\0".encode("utf-8")
    _require(
        _git(root, "ls-tree", "-z", V06_RELEASE_COMMIT, "--", relative)
        == expected_tree_entry,
        f"accepted v0.6 tagged tree entry differs: {relative}",
    )
    resolved = _ascii_line(
        _git(
            root,
            "rev-parse",
            "--verify",
            f"{V06_RELEASE_COMMIT}:{relative}",
        ),
        f"accepted v0.6 tagged blob {relative}",
    )
    _require(
        resolved == object_id,
        f"accepted v0.6 tagged blob ID differs: {relative}",
    )
    object_type = _ascii_line(
        _git(root, "cat-file", "-t", object_id),
        f"accepted v0.6 tagged object {relative}",
    )
    _require(
        object_type == "blob",
        f"accepted v0.6 tagged object is not a blob: {relative}",
    )
    payload = _git(root, "cat-file", "blob", object_id)
    _require(
        _sha256_bytes(payload) == expected["sha256"],
        f"accepted v0.6 tagged blob SHA-256 differs: {relative}",
    )
    return payload


def _validate_archive_pair(archive: bytes, sidecar: bytes, label: str) -> None:
    _require(
        _sha256_bytes(archive) == V06_ARCHIVE_SHA256,
        f"accepted v0.6 {label} archive SHA-256 differs",
    )
    _require(
        sidecar == V06_SIDECAR_TEXT.encode("ascii"),
        f"accepted v0.6 {label} sidecar bytes differ",
    )
    _require(
        _sha256_bytes(sidecar) == V06_SIDECAR_SHA256,
        f"accepted v0.6 {label} sidecar SHA-256 differs",
    )


def validate_accepted_v06_release(root: Path) -> AcceptedV06Release:
    source_root = root.resolve()
    workspace_archive = _read_external_file(
        source_root, V06_ARCHIVE_RELATIVE, "archive"
    )
    workspace_sidecar = _read_external_file(
        source_root, V06_SIDECAR_RELATIVE, "sidecar"
    )
    _validate_archive_pair(workspace_archive, workspace_sidecar, "workspace")

    tag_object = _ascii_line(
        _git(source_root, "show-ref", "--verify", "--hash", V06_TAG_REF),
        "accepted v0.6 tag ref",
    )
    _require(tag_object == V06_TAG_OBJECT, "accepted v0.6 tag object differs")
    _require(
        _git(source_root, "cat-file", "-t", tag_object) == b"tag\n",
        "accepted v0.6 tag is not annotated",
    )
    _validate_raw_tag(_git(source_root, "cat-file", "tag", tag_object))

    tag_commit = _ascii_line(
        _git(source_root, "rev-parse", "--verify", f"{V06_TAG_REF}^{{commit}}"),
        "accepted v0.6 peeled release commit",
    )
    _require(
        tag_commit == V06_RELEASE_COMMIT,
        "accepted v0.6 tag target differs",
    )
    release_parent = _ascii_line(
        _git(source_root, "rev-parse", "--verify", f"{V06_RELEASE_COMMIT}^"),
        "accepted v0.6 release parent",
    )
    _require(
        release_parent == V06_QUALIFIED_SOURCE_COMMIT,
        "accepted v0.6 release parent differs",
    )
    _require(
        _run_git(
            source_root,
            "merge-base",
            "--is-ancestor",
            V06_CANDIDATE_COMMIT,
            V06_QUALIFIED_SOURCE_COMMIT,
            accepted_returncodes=(0, 1),
        ).returncode
        == 0,
        "accepted v0.6 candidate ancestry differs",
    )

    tagged_payloads = {
        relative: _tagged_blob(source_root, relative, expected)
        for relative, expected in V06_TAGGED_BLOBS.items()
    }
    tagged_archive = tagged_payloads[V06_ARCHIVE_RELATIVE]
    tagged_sidecar = tagged_payloads[V06_SIDECAR_RELATIVE]
    _validate_archive_pair(tagged_archive, tagged_sidecar, "tagged")
    _require(
        workspace_archive == tagged_archive,
        "accepted v0.6 workspace archive differs from tagged bytes",
    )
    _require(
        workspace_sidecar == tagged_sidecar,
        "accepted v0.6 workspace sidecar differs from tagged bytes",
    )

    return AcceptedV06Release(
        archive_path=V06_ARCHIVE_RELATIVE,
        archive_sha256=V06_ARCHIVE_SHA256,
        sidecar_path=V06_SIDECAR_RELATIVE,
        sidecar_sha256=V06_SIDECAR_SHA256,
        tag_ref=V06_TAG_REF,
        tag_object=V06_TAG_OBJECT,
        raw_tag_object_sha256=V06_RAW_TAG_SHA256,
        tag_commit=V06_RELEASE_COMMIT,
        qualified_source_commit=V06_QUALIFIED_SOURCE_COMMIT,
        candidate_commit=V06_CANDIDATE_COMMIT,
        tag_archive_claim=V06_TAG_ARCHIVE_CLAIM,
        tagged_blobs={key: dict(value) for key, value in V06_TAGGED_BLOBS.items()},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    result: dict[str, Any] = asdict(validate_accepted_v06_release(args.root))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
