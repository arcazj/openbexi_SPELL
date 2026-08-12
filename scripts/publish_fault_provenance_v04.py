#!/usr/bin/env python3
"""Atomically retain validated v0.4 fault raw and runtime evidence corpora."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import uuid
from pathlib import Path


class PublicationError(RuntimeError):
    pass


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _snapshot(root: Path, label: str) -> dict[str, tuple[int, str]]:
    if not root.is_dir() or root.is_symlink():
        raise PublicationError(f"{label} is missing or unsafe")
    files: dict[str, tuple[int, str]] = {}
    for entry in root.rglob("*"):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            raise PublicationError(f"{label} contains a symlink: {relative}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise PublicationError(f"{label} contains an unsafe entry: {relative}")
        digest = hashlib.sha256()
        size = 0
        with entry.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
        files[relative] = (size, digest.hexdigest())
    if not files:
        raise PublicationError(f"{label} is empty")
    return files


def _copy_exact(source: Path, destination: Path, snapshot: dict[str, tuple[int, str]]) -> None:
    destination.mkdir(parents=True)
    for relative in sorted(snapshot):
        source_path = source / Path(relative)
        destination_path = destination / Path(relative)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        with source_path.open("rb") as reader, destination_path.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
    if _snapshot(destination, "staged fault provenance") != snapshot:
        raise PublicationError("staged fault provenance differs from its source")


def publish_fault_provenance_v04(
    raw_source: Path,
    runtime_source: Path,
    destination: Path,
    *,
    replace: bool,
) -> None:
    if raw_source.is_symlink() or runtime_source.is_symlink() or destination.is_symlink():
        raise PublicationError("fault provenance paths cannot be symlinks")
    raw_source = raw_source.resolve()
    runtime_source = runtime_source.resolve()
    destination = destination.resolve()
    if raw_source == runtime_source:
        raise PublicationError("raw and runtime provenance sources must be distinct")
    for source in (raw_source, runtime_source):
        if _is_relative_to(destination, source) or _is_relative_to(source, destination):
            raise PublicationError("provenance destination overlaps a source corpus")
    raw_snapshot = _snapshot(raw_source, "raw fault provenance source")
    runtime_snapshot = _snapshot(runtime_source, "runtime fault provenance source")
    if (
        len(raw_snapshot) != 55
        or "fault-gate-raw.json" not in raw_snapshot
        or any("/" in relative for relative in raw_snapshot)
    ):
        raise PublicationError("raw fault provenance source differs from the exact 55-file corpus")
    if set(path.split("/", 1)[0] for path in runtime_snapshot) != {
        "artifacts",
        "runtime-fault-evidence.json",
    }:
        raise PublicationError("runtime fault provenance source differs from the exact corpus")
    if "runtime-fault-evidence.json" not in runtime_snapshot:
        raise PublicationError("runtime fault provenance source lacks its manifest")

    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise PublicationError("provenance destination parent is unsafe")
    if destination.exists() and not replace:
        raise PublicationError("canonical fault provenance already exists")
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise PublicationError("canonical fault provenance path is unsafe")

    token = uuid.uuid4().hex
    staging = parent / f".fault-gate-stage-{token}"
    backup = parent / f".fault-gate-backup-{token}"
    installed = False
    backed_up = False
    try:
        _copy_exact(raw_source, staging / "raw", raw_snapshot)
        _copy_exact(runtime_source, staging / "runtime", runtime_snapshot)
        if _snapshot(raw_source, "raw fault provenance source") != raw_snapshot:
            raise PublicationError("raw fault provenance changed during publication")
        if _snapshot(runtime_source, "runtime fault provenance source") != runtime_snapshot:
            raise PublicationError("runtime fault provenance changed during publication")
        if destination.exists():
            os.replace(destination, backup)
            backed_up = True
        os.replace(staging, destination)
        installed = True
        if (
            _snapshot(destination / "raw", "retained raw fault provenance")
            != raw_snapshot
            or _snapshot(destination / "runtime", "retained runtime fault provenance")
            != runtime_snapshot
        ):
            raise PublicationError("retained fault provenance differs after installation")
        backed_up = False
    except Exception as publication_error:
        try:
            if installed and destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            if backed_up and backup.is_dir() and not backup.is_symlink():
                os.replace(backup, destination)
                backed_up = False
        except Exception as rollback_error:
            raise PublicationError(
                "fault provenance publication failed and rollback failed; "
                f"recovery state retained at {backup}: {rollback_error}"
            ) from publication_error
        raise
    finally:
        if staging.is_dir() and not staging.is_symlink():
            shutil.rmtree(staging)
        if not backed_up and backup.is_dir() and not backup.is_symlink():
            shutil.rmtree(backup)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-source", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    try:
        publish_fault_provenance_v04(
            args.raw_source,
            args.runtime_source,
            args.destination,
            replace=args.replace,
        )
    except (OSError, PublicationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
