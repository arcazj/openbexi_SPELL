#!/usr/bin/env python3
"""Validate the external accepted v0.5 archive pair used by v0.6 gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v06 import path_has_link_or_reparse_v06


V05_TAG_REF = "refs/tags/v0.5.0"
V05_TAG_OBJECT = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
V05_COMMIT = "e7b6bb9428833437e0160040541eb840deee7cca"
V05_ARCHIVE_RELATIVE = "artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz"
V05_ARCHIVE_SHA256 = "cec956dd89da4c978ad5036c2a7854ff31284123d6193838f26c4298c50f6241"
V05_SIDECAR_RELATIVE = f"{V05_ARCHIVE_RELATIVE}.sha256"
V05_SIDECAR_TEXT = f"{V05_ARCHIVE_SHA256}  openbexi-spell-v0.5.0.tar.gz\n"
V05_SIDECAR_SHA256 = "215ee4e79fd53fccd04e6ff7d854d9a8d03f074f507d6fbf233926be9e817279"
V05_TAG_ARCHIVE_CLAIM = f"Final archive SHA-256: {V05_ARCHIVE_SHA256}"


class AcceptedV05ReleaseError(ValueError):
    """Raised when the accepted external v0.5 release pair differs."""


@dataclass(frozen=True)
class AcceptedV05Release:
    archive_path: str
    archive_sha256: str
    sidecar_path: str
    sidecar_sha256: str
    tag_ref: str
    tag_object: str
    tag_commit: str
    tag_archive_claim: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptedV05ReleaseError(message)


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


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    _require(result.returncode == 0, "accepted v0.5 Git binding cannot be inspected")
    return result.stdout


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_accepted_v05_release(root: Path) -> AcceptedV05Release:
    source_root = root.resolve()
    archive = source_root / V05_ARCHIVE_RELATIVE
    sidecar = source_root / V05_SIDECAR_RELATIVE
    for path, label in ((archive, "archive"), (sidecar, "sidecar")):
        _require(
            path.is_file()
            and not path_has_link_or_reparse_v06(source_root, path),
            f"accepted v0.5 {label} is missing or unsafe",
        )
    _require(
        _sha256_file(archive) == V05_ARCHIVE_SHA256,
        "accepted v0.5 archive SHA-256 differs",
    )
    sidecar_bytes = sidecar.read_bytes()
    _require(
        sidecar_bytes == V05_SIDECAR_TEXT.encode("ascii"),
        "accepted v0.5 sidecar bytes differ",
    )
    _require(
        hashlib.sha256(sidecar_bytes).hexdigest() == V05_SIDECAR_SHA256,
        "accepted v0.5 sidecar SHA-256 differs",
    )

    tag_object = _git(source_root, "show-ref", "--verify", "--hash", V05_TAG_REF).decode(
        "ascii"
    ).strip()
    _require(tag_object == V05_TAG_OBJECT, "accepted v0.5 tag object differs")
    _require(
        _git(source_root, "cat-file", "-t", tag_object) == b"tag\n",
        "accepted v0.5 tag is not annotated",
    )
    tag_commit = _git(source_root, "rev-parse", f"{V05_TAG_REF}^{{commit}}").decode(
        "ascii"
    ).strip()
    _require(tag_commit == V05_COMMIT, "accepted v0.5 tag target differs")
    raw_tag = _git(source_root, "cat-file", "tag", tag_object)
    claim = V05_TAG_ARCHIVE_CLAIM.encode("ascii")
    claim_lines = [line for line in raw_tag.splitlines() if line.startswith(b"Final archive SHA-256:")]
    _require(
        claim_lines == [claim],
        "accepted v0.5 tag final-archive claim differs",
    )
    return AcceptedV05Release(
        archive_path=V05_ARCHIVE_RELATIVE,
        archive_sha256=V05_ARCHIVE_SHA256,
        sidecar_path=V05_SIDECAR_RELATIVE,
        sidecar_sha256=V05_SIDECAR_SHA256,
        tag_ref=V05_TAG_REF,
        tag_object=V05_TAG_OBJECT,
        tag_commit=V05_COMMIT,
        tag_archive_claim=V05_TAG_ARCHIVE_CLAIM,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(asdict(validate_accepted_v05_release(args.root)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
