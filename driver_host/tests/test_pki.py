from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from driver_host import pki


pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="PKI ownership is enforced by the Linux image"
)


def _tree_digest(directory: Path) -> dict[str, str]:
    return {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(directory.iterdir())
    }


def test_initializer_reuses_complete_valid_bundle_without_rotation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client = tmp_path / "client"
    server = tmp_path / "server"
    bundle = pki.generate_bundle()
    uid, gid = os.getuid(), os.getgid()
    pki.write_split_bundle(
        bundle,
        client,
        server,
        client_uid=uid,
        client_gid=gid,
        server_uid=uid,
        server_gid=gid,
    )
    before = (_tree_digest(client), _tree_digest(server))

    result = pki.main(
        [
            "--client-dir",
            str(client),
            "--server-dir",
            str(server),
            "--client-uid",
            str(uid),
            "--client-gid",
            str(gid),
            "--server-uid",
            str(uid),
            "--server-gid",
            str(gid),
        ]
    )

    assert result == 0
    assert (_tree_digest(client), _tree_digest(server)) == before
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "client_fingerprint": bundle.client_fingerprint,
        "server_fingerprint": bundle.server_fingerprint,
    }
    assert stat.S_IMODE((client / "client.key").stat().st_mode) == 0o400


def test_initializer_rejects_partial_or_tampered_existing_bundle(tmp_path: Path) -> None:
    client = tmp_path / "client"
    server = tmp_path / "server"
    bundle = pki.generate_bundle()
    uid, gid = os.getuid(), os.getgid()
    pki.write_split_bundle(
        bundle,
        client,
        server,
        client_uid=uid,
        client_gid=gid,
        server_uid=uid,
        server_gid=gid,
    )
    (client / "client.crt").write_bytes(bundle.server_certificate)
    (client / "client.crt").chmod(0o644)

    with pytest.raises(ValueError, match="failed validation"):
        pki.existing_split_bundle_fingerprints(
            client,
            server,
            client_uid=uid,
            client_gid=gid,
            server_uid=uid,
            server_gid=gid,
        )

    (client / "client.crt").unlink()
    with pytest.raises(ValueError, match="incomplete"):
        pki.existing_split_bundle_fingerprints(
            client,
            server,
            client_uid=uid,
            client_gid=gid,
            server_uid=uid,
            server_gid=gid,
        )


def test_writer_rejects_explicit_symlink_output_directory(tmp_path: Path) -> None:
    client_target = tmp_path / "client-target"
    client_target.mkdir()
    client_link = tmp_path / "client-link"
    client_link.symlink_to(client_target, target_is_directory=True)

    with pytest.raises(ValueError, match="must not be a symlink"):
        pki.write_split_bundle(
            pki.generate_bundle(),
            client_link,
            tmp_path / "server",
            client_uid=os.getuid(),
            client_gid=os.getgid(),
            server_uid=os.getuid(),
            server_gid=os.getgid(),
        )
