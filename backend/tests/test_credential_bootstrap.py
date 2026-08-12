from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from backend import credential_bootstrap as bootstrap


pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="credential metadata is enforced by the Linux image"
)


def _source_bundle(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    values = {
        "ca.crt": b"test-ca-certificate",
        "client.crt": b"test-client-certificate",
        "client.key": b"test-client-private-key",
    }
    for name, content in values.items():
        candidate = path / name
        candidate.write_bytes(content)
        candidate.chmod(bootstrap.SOURCE_FILES[name])


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_runtime_key_can_be_reprovisioned_without_mutating_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    runtime = tmp_path / "runtime"
    _source_bundle(source)
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    uid, gid = os.getuid(), os.getgid()
    before = {name: _digest(source / name) for name in bootstrap.SOURCE_FILES}

    credentials = bootstrap.read_source_credentials(
        source, source_uid=uid, source_gid=gid
    )
    try:
        bootstrap.install_runtime_credentials(
            credentials, runtime, runtime_uid=uid, runtime_gid=gid
        )
    finally:
        bootstrap.clear_credentials(credentials)

    assert set(path.name for path in runtime.iterdir()) == set(bootstrap.RUNTIME_FILES)
    assert all(
        stat.S_IMODE((runtime / name).stat().st_mode) == 0o400
        for name in bootstrap.RUNTIME_FILES
    )
    (runtime / "client.key").unlink()

    credentials = bootstrap.read_source_credentials(
        source, source_uid=uid, source_gid=gid
    )
    try:
        bootstrap.install_runtime_credentials(
            credentials, runtime, runtime_uid=uid, runtime_gid=gid
        )
    finally:
        bootstrap.clear_credentials(credentials)

    assert (runtime / "client.key").read_bytes() == b"test-client-private-key"
    assert {name: _digest(source / name) for name in bootstrap.SOURCE_FILES} == before


@pytest.mark.parametrize("mutation", ["missing", "unexpected", "symlink", "oversized"])
def test_source_bundle_rejects_non_exact_or_unsafe_entries(
    tmp_path: Path, mutation: str
) -> None:
    source = tmp_path / "source"
    _source_bundle(source)
    if mutation == "missing":
        (source / "client.crt").unlink()
    elif mutation == "unexpected":
        (source / "unexpected").write_bytes(b"x")
    elif mutation == "symlink":
        (source / "client.key").unlink()
        (source / "client.key").symlink_to(source / "ca.crt")
    else:
        (source / "client.key").chmod(0o600)
        (source / "client.key").write_bytes(
            b"x" * (bootstrap.MAX_CREDENTIAL_BYTES + 1)
        )
        (source / "client.key").chmod(0o400)

    with pytest.raises((OSError, ValueError)):
        bootstrap.read_source_credentials(
            source, source_uid=os.getuid(), source_gid=os.getgid()
        )


def test_privilege_drop_clears_groups_before_permanent_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
    monkeypatch.setattr(bootstrap.os, "setgroups", lambda groups: calls.append(("groups", groups)))
    monkeypatch.setattr(
        bootstrap.os,
        "setresgid",
        lambda real, effective, saved: calls.append(("gid", real, effective, saved)),
    )
    monkeypatch.setattr(
        bootstrap.os,
        "setresuid",
        lambda real, effective, saved: calls.append(("uid", real, effective, saved)),
    )
    monkeypatch.setattr(bootstrap.os, "getuid", lambda: bootstrap.SERVICE_UID)
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: bootstrap.SERVICE_UID)
    monkeypatch.setattr(bootstrap.os, "getgid", lambda: bootstrap.SERVICE_GID)
    monkeypatch.setattr(bootstrap.os, "getegid", lambda: bootstrap.SERVICE_GID)
    monkeypatch.setattr(bootstrap.os, "getgroups", lambda: [])
    monkeypatch.setattr(
        bootstrap.os,
        "getresuid",
        lambda: (bootstrap.SERVICE_UID,) * 3,
    )
    monkeypatch.setattr(
        bootstrap.os,
        "getresgid",
        lambda: (bootstrap.SERVICE_GID,) * 3,
    )
    monkeypatch.setattr(bootstrap, "_linux_capabilities_are_empty", lambda: True)

    # Preserve a root observation for the first branch after replacing geteuid above.
    observations = iter((0, bootstrap.SERVICE_UID))
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: next(observations))
    bootstrap.drop_privileges()

    assert calls == [
        ("groups", []),
        ("gid", bootstrap.SERVICE_GID, bootstrap.SERVICE_GID, bootstrap.SERVICE_GID),
        ("uid", bootstrap.SERVICE_UID, bootstrap.SERVICE_UID, bootstrap.SERVICE_UID),
    ]
