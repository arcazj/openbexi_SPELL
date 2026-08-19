"""Exact local builder provenance for immutable v0.9 procedure bundles."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


BASE_IMAGE_REFERENCE = (
    "python:3.13-slim@sha256:"
    "eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280"
)
BUILDER_IDENTITY = "spell-v09-dual-network-none-builder/1"
DESCRIPTOR_SCHEMA = "spell.bundle-toolchain/1"
MAX_TOOLCHAIN_FILE_BYTES = 2_000_000
MAX_TOOLCHAIN_FILES = 1_000
MAX_TOOLCHAIN_TOTAL_BYTES = 32_000_000
EXPECTED_PYTHON_VERSION = "3.13.14"
EXPECTED_PYTHON_ABI = "cpython-313"
EXPECTED_OS_RELEASE = {"ID": "debian", "VERSION_ID": "13"}
_TOOLCHAIN_STATIC_FILES = (
    "compose.yaml",
    "backend/Dockerfile",
    "backend/requirements.hashes.lock",
    "contracts/v10/language_reference_example_matrix.json",
)
_TOOLCHAIN_EXCLUDED_DIRECTORIES = frozenset({"tests", "__pycache__"})

_LOCK_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)\s*\\\s*$"
)


def _is_reparse(metadata: os.stat_result) -> bool:
    attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attribute and getattr(metadata, "st_file_attributes", 0) & attribute)


def _safe_regular_bytes(repository: Path, relative: str) -> bytes:
    path = repository.joinpath(*relative.split("/"))
    current = repository
    for part in relative.split("/")[:-1]:
        current /= part
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            raise RuntimeError(f"builder toolchain path is invalid: {relative}")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or before.st_size > MAX_TOOLCHAIN_FILE_BYTES
    ):
        raise RuntimeError(f"builder toolchain file is invalid: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"builder toolchain file cannot be opened: {relative}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"builder toolchain file changed before read: {relative}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_TOOLCHAIN_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_TOOLCHAIN_FILE_BYTES:
                raise RuntimeError(f"builder toolchain file is too large: {relative}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        or total != before.st_size
    ):
        raise RuntimeError(f"builder toolchain file changed while reading: {relative}")
    return b"".join(chunks)


def toolchain_files(root: Path | None = None) -> tuple[str, ...]:
    repository = Path(__file__).absolute().parents[1] if root is None else root.absolute()
    backend = repository / "backend"
    backend_metadata = backend.lstat()
    if not stat.S_ISDIR(backend_metadata.st_mode) or _is_reparse(backend_metadata):
        raise RuntimeError("builder backend source directory is invalid")
    discovered: list[str] = list(_TOOLCHAIN_STATIC_FILES)
    stack = [backend]
    while stack:
        directory = stack.pop()
        children = sorted(directory.iterdir(), key=lambda item: item.name.encode("utf-8"))
        for child in children:
            metadata = child.lstat()
            if _is_reparse(metadata) or stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(
                    f"builder source path is invalid: {child.relative_to(repository).as_posix()}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                if child.name not in _TOOLCHAIN_EXCLUDED_DIRECTORIES:
                    stack.append(child)
                continue
            if child.suffix == ".py":
                if not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeError(
                        f"builder source file is invalid: {child.relative_to(repository).as_posix()}"
                    )
                discovered.append(child.relative_to(repository).as_posix())
    result = tuple(sorted(set(discovered), key=lambda item: item.encode("utf-8")))
    if len(result) > MAX_TOOLCHAIN_FILES:
        raise RuntimeError("builder toolchain file count exceeds its bound")
    return result


def _locked_requirements(raw: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        match = _LOCK_REQUIREMENT.fullmatch(line)
        if match is None:
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if name in result:
            raise RuntimeError(f"duplicate locked requirement: {name}")
        result[name] = match.group(2)
    if not result:
        raise RuntimeError("builder requirements lock contains no exact requirements")
    return dict(sorted(result.items()))


def _runtime_environment(lock: dict[str, str]) -> dict[str, Any]:
    python = {
        "abi_tag": sys.implementation.cache_tag,
        "implementation": sys.implementation.name,
        "version": ".".join(str(item) for item in sys.version_info[:3]),
    }
    if (
        python["implementation"] != "cpython"
        or python["version"] != EXPECTED_PYTHON_VERSION
        or python["abi_tag"] != EXPECTED_PYTHON_ABI
    ):
        raise RuntimeError("bundle builder Python runtime differs from the pinned image")

    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    except OSError as exc:
        raise RuntimeError("bundle builder OS identity is unavailable") from exc
    actual_os = {key: os_release.get(key) for key in sorted(EXPECTED_OS_RELEASE)}
    if actual_os != EXPECTED_OS_RELEASE:
        raise RuntimeError("bundle builder OS differs from the pinned image")

    installed: dict[str, str] = {}
    for name, expected in lock.items():
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"locked builder package is unavailable: {name}") from exc
        if actual != expected:
            raise RuntimeError(f"locked builder package version differs: {name}")
        installed[name] = actual
    return {"installed_requirements": installed, "os_release": actual_os, "python": python}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def toolchain_descriptor(root: Path | None = None) -> dict[str, Any]:
    repository = Path(__file__).absolute().parents[1] if root is None else root.absolute()
    root_metadata = repository.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or _is_reparse(root_metadata):
        raise RuntimeError("builder repository root is invalid")
    files: list[dict[str, Any]] = []
    raw_by_path: dict[str, bytes] = {}
    total_bytes = 0
    for relative in toolchain_files(repository):
        raw = _safe_regular_bytes(repository, relative)
        total_bytes += len(raw)
        if total_bytes > MAX_TOOLCHAIN_TOTAL_BYTES:
            raise RuntimeError("builder toolchain byte total exceeds its bound")
        raw_by_path[relative] = raw
        files.append(
            {
                "byte_length": len(raw),
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    dockerfile_from = next(
        (
            line.strip().split(maxsplit=1)[1]
            for line in raw_by_path["backend/Dockerfile"].decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ),
        None,
    )
    if dockerfile_from != BASE_IMAGE_REFERENCE:
        raise RuntimeError("bundle builder base image differs from the Dockerfile FROM")
    lock = _locked_requirements(raw_by_path["backend/requirements.hashes.lock"])
    runtime = _runtime_environment(lock)
    return {
        "base_image": BASE_IMAGE_REFERENCE,
        "builder_identity": BUILDER_IDENTITY,
        "files": files,
        "runtime": runtime,
        "schema_version": DESCRIPTOR_SCHEMA,
    }


def toolchain_digest(root: Path | None = None) -> str:
    return hashlib.sha256(_canonical(toolchain_descriptor(root))).hexdigest()


__all__ = [
    "BASE_IMAGE_REFERENCE",
    "BUILDER_IDENTITY",
    "DESCRIPTOR_SCHEMA",
    "EXPECTED_OS_RELEASE",
    "EXPECTED_PYTHON_ABI",
    "EXPECTED_PYTHON_VERSION",
    "MAX_TOOLCHAIN_FILES",
    "MAX_TOOLCHAIN_TOTAL_BYTES",
    "toolchain_files",
    "toolchain_descriptor",
    "toolchain_digest",
]
