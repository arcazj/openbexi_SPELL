"""Bounded filesystem protocol primitives for isolated bundle builders."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from .development_domain import DevelopmentCorruptionError, DevelopmentLimitError


MAX_PROTOCOL_FILE_BYTES = 100 * 1024 * 1024
MAX_PROTOCOL_DIRECTORY_ENTRIES = 16
MAX_PROTOCOL_DIRECTORY_BYTES = 400 * 1024 * 1024


def _is_reparse(metadata: os.stat_result) -> bool:
    attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attribute and getattr(metadata, "st_file_attributes", 0) & attribute)


def require_protocol_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise DevelopmentCorruptionError(f"{label} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DevelopmentCorruptionError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
        raise DevelopmentCorruptionError(f"{label} is not a regular directory")
    return path


def read_protocol_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int = MAX_PROTOCOL_FILE_BYTES,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise DevelopmentCorruptionError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
        raise DevelopmentCorruptionError(f"{label} is not a regular file")
    if before.st_size > maximum_bytes:
        raise DevelopmentLimitError(f"{label} exceeds its byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DevelopmentCorruptionError(f"{label} cannot be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise DevelopmentCorruptionError(f"{label} changed before read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise DevelopmentLimitError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        or total != before.st_size
    ):
        raise DevelopmentCorruptionError(f"{label} changed while reading")
    return b"".join(chunks)


def atomic_protocol_write(
    path: Path,
    raw: bytes,
    *,
    label: str,
    replace: bool = False,
    maximum_bytes: int = MAX_PROTOCOL_FILE_BYTES,
) -> None:
    if len(raw) > maximum_bytes:
        raise DevelopmentLimitError(f"{label} exceeds its byte limit")
    require_protocol_directory(path.parent, f"{label} directory")
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short protocol write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if not replace and path.exists():
            raise DevelopmentCorruptionError(f"{label} already exists")
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def protocol_inventory(path: Path, label: str) -> tuple[Path, ...]:
    directory = require_protocol_directory(path, label)
    try:
        entries = tuple(sorted(directory.iterdir(), key=lambda item: item.name))
    except OSError as exc:
        raise DevelopmentCorruptionError(f"{label} cannot be enumerated") from exc
    if len(entries) > MAX_PROTOCOL_DIRECTORY_ENTRIES:
        raise DevelopmentLimitError(f"{label} contains too many entries")
    total = 0
    for entry in entries:
        try:
            metadata = entry.lstat()
        except FileNotFoundError:
            # Atomic producers rename temporary files while readers enumerate.
            continue
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise DevelopmentCorruptionError(f"{label} contains an invalid entry")
        total += metadata.st_size
        if total > MAX_PROTOCOL_DIRECTORY_BYTES:
            raise DevelopmentLimitError(f"{label} exceeds its byte limit")
    return entries


__all__ = [
    "MAX_PROTOCOL_DIRECTORY_BYTES",
    "MAX_PROTOCOL_DIRECTORY_ENTRIES",
    "MAX_PROTOCOL_FILE_BYTES",
    "atomic_protocol_write",
    "protocol_inventory",
    "read_protocol_file",
    "require_protocol_directory",
]
