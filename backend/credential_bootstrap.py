"""Provision the one-use gateway key, drop privileges, and exec the API."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Mapping, MutableMapping, Optional, Sequence


SOURCE_DIRECTORY = Path("/run/spell-driver-client-source")
RUNTIME_DIRECTORY = Path("/run/spell-driver-client")
SERVICE_UID = 10001
SERVICE_GID = 10001
MAX_CREDENTIAL_BYTES = 65_536
SOURCE_FILES = {
    "ca.crt": 0o644,
    "client.crt": 0o644,
    "client.key": 0o400,
}
RUNTIME_FILES = {name: 0o400 for name in SOURCE_FILES}
_STAGED_SUFFIX = ".spell-bootstrap"


def _driver_enabled(environment: Mapping[str, str]) -> bool:
    value = environment.get("SPELL_DRIVER_ENABLED", "false").strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError("SPELL_DRIVER_ENABLED must be true or false")


def _require_directory(
    path: Path,
    *,
    uid: Optional[int],
    gid: Optional[int],
    mode: int,
) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"credential directory is missing: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"credential path must be a directory: {path}")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"credential directory mode is invalid: {path}")
    if uid is not None and metadata.st_uid != uid:
        raise ValueError(f"credential directory owner is invalid: {path}")
    if gid is not None and metadata.st_gid != gid:
        raise ValueError(f"credential directory group is invalid: {path}")


def _read_bounded_regular_file(
    path: Path,
    *,
    uid: Optional[int],
    gid: Optional[int],
    mode: int,
) -> bytearray:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"credential must be a regular file: {path}")
        if stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError(f"credential file mode is invalid: {path}")
        if uid is not None and metadata.st_uid != uid:
            raise ValueError(f"credential file owner is invalid: {path}")
        if gid is not None and metadata.st_gid != gid:
            raise ValueError(f"credential file group is invalid: {path}")
        if metadata.st_size < 1 or metadata.st_size > MAX_CREDENTIAL_BYTES:
            raise ValueError(f"credential file size is invalid: {path}")
        content = bytearray()
        while len(content) <= MAX_CREDENTIAL_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_CREDENTIAL_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if not content or len(content) > MAX_CREDENTIAL_BYTES:
            raise ValueError(f"credential file size is invalid: {path}")
        return content
    finally:
        os.close(descriptor)


def read_source_credentials(
    source_directory: Path,
    *,
    source_uid: Optional[int] = 0,
    source_gid: Optional[int] = 0,
) -> dict[str, bytearray]:
    """Read an exact, root-owned source bundle without following links."""

    _require_directory(
        source_directory, uid=source_uid, gid=source_gid, mode=0o700
    )
    entries = {entry.name for entry in source_directory.iterdir()}
    if entries != set(SOURCE_FILES):
        raise ValueError("credential source must contain exactly the expected files")
    loaded: dict[str, bytearray] = {}
    try:
        for name, mode in SOURCE_FILES.items():
            loaded[name] = _read_bounded_regular_file(
                source_directory / name,
                uid=source_uid,
                gid=source_gid,
                mode=mode,
            )
        return loaded
    except BaseException:
        clear_credentials(loaded)
        raise


def _write_staged_file(
    path: Path,
    content: bytearray,
    *,
    uid: Optional[int],
    gid: Optional[int],
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o400)
    try:
        view = memoryview(content)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        if uid is not None and gid is not None:
            os.fchown(descriptor, uid, gid)
    finally:
        os.close(descriptor)


def install_runtime_credentials(
    credentials: Mapping[str, bytearray],
    runtime_directory: Path,
    *,
    runtime_uid: Optional[int] = SERVICE_UID,
    runtime_gid: Optional[int] = SERVICE_GID,
) -> None:
    """Atomically install a complete runtime bundle before the API can start."""

    if set(credentials) != set(RUNTIME_FILES):
        raise ValueError("runtime credential bundle is incomplete")
    _require_directory(
        runtime_directory, uid=runtime_uid, gid=runtime_gid, mode=0o700
    )
    allowed = set(RUNTIME_FILES) | {
        f"{name}{_STAGED_SUFFIX}" for name in RUNTIME_FILES
    }
    entries = {entry.name for entry in runtime_directory.iterdir()}
    if not entries.issubset(allowed):
        raise ValueError("runtime credential directory contains unexpected entries")

    staged: list[tuple[Path, Path]] = []
    for name in RUNTIME_FILES:
        destination = runtime_directory / name
        temporary = runtime_directory / f"{name}{_STAGED_SUFFIX}"
        for candidate in (temporary, destination):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
            except IsADirectoryError as exc:
                raise ValueError("runtime credential entry must not be a directory") from exc
        _write_staged_file(
            temporary,
            credentials[name],
            uid=runtime_uid,
            gid=runtime_gid,
        )
        staged.append((temporary, destination))

    for temporary, destination in staged:
        os.replace(temporary, destination)

    for name, mode in RUNTIME_FILES.items():
        metadata = (runtime_directory / name).lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError("installed runtime credential metadata is invalid")
        if runtime_uid is not None and metadata.st_uid != runtime_uid:
            raise ValueError("installed runtime credential owner is invalid")
        if runtime_gid is not None and metadata.st_gid != runtime_gid:
            raise ValueError("installed runtime credential group is invalid")


def clear_credentials(credentials: MutableMapping[str, bytearray]) -> None:
    for content in credentials.values():
        content[:] = b"\x00" * len(content)
        content.clear()
    credentials.clear()


def _linux_capabilities_are_empty() -> bool:
    status = Path("/proc/self/status")
    if not status.is_file():
        return True
    values: dict[str, str] = {}
    for line in status.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"CapPrm", "CapEff", "CapAmb"}:
            values[key] = value.strip()
    return values == {
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapAmb": "0000000000000000",
    }


def drop_privileges(*, uid: int = SERVICE_UID, gid: int = SERVICE_GID) -> None:
    """Permanently drop every process identity and verify capabilities are gone."""

    if os.name != "posix":
        raise RuntimeError("the credential bootstrap requires a POSIX runtime")
    if os.geteuid() == 0:
        os.setgroups([])
        if hasattr(os, "setresgid"):
            os.setresgid(gid, gid, gid)
        else:
            os.setgid(gid)
        if hasattr(os, "setresuid"):
            os.setresuid(uid, uid, uid)
        else:
            os.setuid(uid)
    identities = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    if identities != (uid, uid, gid, gid) or os.getgroups():
        raise RuntimeError("backend service identity was not permanently constrained")
    if hasattr(os, "getresuid") and os.getresuid() != (uid, uid, uid):
        raise RuntimeError("backend saved UID remains privileged")
    if hasattr(os, "getresgid") and os.getresgid() != (gid, gid, gid):
        raise RuntimeError("backend saved GID remains privileged")
    if not _linux_capabilities_are_empty():
        raise RuntimeError("backend capabilities remain after the privilege drop")


def main(argv: Optional[Sequence[str]] = None) -> int:
    command = list(sys.argv[1:] if argv is None else argv)
    if not command:
        raise ValueError("backend bootstrap requires an application command")

    if _driver_enabled(os.environ):
        credentials = read_source_credentials(SOURCE_DIRECTORY)
        try:
            install_runtime_credentials(credentials, RUNTIME_DIRECTORY)
        finally:
            clear_credentials(credentials)

    drop_privileges()
    os.execvp(command[0], command)
    raise RuntimeError("backend application exec unexpectedly returned")


if __name__ == "__main__":
    raise SystemExit(main())
