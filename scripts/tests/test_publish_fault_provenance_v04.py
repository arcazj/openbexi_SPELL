from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import publish_fault_provenance_v04 as publisher


def _sources(tmp_path: Path) -> tuple[Path, Path]:
    raw = tmp_path / "raw-source"
    runtime = tmp_path / "runtime-source"
    raw.mkdir()
    runtime.joinpath("artifacts").mkdir(parents=True)
    (raw / "fault-gate-raw.json").write_text("raw-report\n", encoding="utf-8")
    for index in range(54):
        (raw / f"artifact-{index:02d}.txt").write_text(
            f"raw-{index}\n", encoding="utf-8"
        )
    (runtime / "runtime-fault-evidence.json").write_text(
        "runtime-manifest\n", encoding="utf-8"
    )
    (runtime / "artifacts/evidence.json").write_text(
        "runtime-evidence\n", encoding="utf-8"
    )
    return raw, runtime


def test_atomic_fault_provenance_publication_copies_exact_bytes(tmp_path: Path) -> None:
    raw, runtime = _sources(tmp_path)
    destination = tmp_path / "provenance/fault-gate"

    publisher.publish_fault_provenance_v04(
        raw, runtime, destination, replace=False
    )

    assert publisher._snapshot(destination / "raw", "raw") == publisher._snapshot(
        raw, "raw source"
    )
    assert publisher._snapshot(
        destination / "runtime", "runtime"
    ) == publisher._snapshot(runtime, "runtime source")
    assert {item.name for item in destination.iterdir()} == {"raw", "runtime"}
    assert not list(destination.parent.glob(".fault-gate-*"))


def test_fault_provenance_replace_is_explicit_and_atomic(tmp_path: Path) -> None:
    raw, runtime = _sources(tmp_path)
    destination = tmp_path / "provenance/fault-gate"
    publisher.publish_fault_provenance_v04(raw, runtime, destination, replace=False)
    original = (destination / "raw/fault-gate-raw.json").read_bytes()
    (raw / "fault-gate-raw.json").write_bytes(b"replacement\n")

    with pytest.raises(publisher.PublicationError, match="already exists"):
        publisher.publish_fault_provenance_v04(
            raw, runtime, destination, replace=False
        )
    assert (destination / "raw/fault-gate-raw.json").read_bytes() == original

    publisher.publish_fault_provenance_v04(raw, runtime, destination, replace=True)
    assert (destination / "raw/fault-gate-raw.json").read_bytes() == b"replacement\n"


def test_fault_provenance_replace_rolls_back_on_install_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, runtime = _sources(tmp_path)
    destination = tmp_path / "provenance/fault-gate"
    publisher.publish_fault_provenance_v04(raw, runtime, destination, replace=False)
    original = (destination / "raw/fault-gate-raw.json").read_bytes()
    (raw / "fault-gate-raw.json").write_bytes(b"replacement\n")
    real_replace = os.replace
    calls = 0

    def fail_install(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected install failure")
        real_replace(source, target)

    monkeypatch.setattr(publisher.os, "replace", fail_install)
    with pytest.raises(OSError, match="injected install failure"):
        publisher.publish_fault_provenance_v04(
            raw, runtime, destination, replace=True
        )

    assert (destination / "raw/fault-gate-raw.json").read_bytes() == original
    assert not list(destination.parent.glob(".fault-gate-*"))


def test_fault_provenance_preserves_backup_when_rollback_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, runtime = _sources(tmp_path)
    destination = tmp_path / "provenance/fault-gate"
    publisher.publish_fault_provenance_v04(raw, runtime, destination, replace=False)
    original = (destination / "raw/fault-gate-raw.json").read_bytes()
    (raw / "fault-gate-raw.json").write_bytes(b"replacement\n")
    real_replace = os.replace
    calls = 0

    def fail_install_and_rollback(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected install failure")
        if calls == 3:
            raise OSError("injected rollback failure")
        real_replace(source, target)

    monkeypatch.setattr(publisher.os, "replace", fail_install_and_rollback)
    with pytest.raises(publisher.PublicationError, match="rollback failed"):
        publisher.publish_fault_provenance_v04(
            raw, runtime, destination, replace=True
        )

    backups = list(destination.parent.glob(".fault-gate-backup-*"))
    assert len(backups) == 1
    assert (backups[0] / "raw/fault-gate-raw.json").read_bytes() == original
    assert not list(destination.parent.glob(".fault-gate-stage-*"))


def test_fault_provenance_rejects_extra_raw_file_and_symlink(tmp_path: Path) -> None:
    raw, runtime = _sources(tmp_path)
    destination = tmp_path / "provenance/fault-gate"
    (raw / "orphan.txt").write_text("orphan\n", encoding="utf-8")
    with pytest.raises(publisher.PublicationError, match="55-file corpus"):
        publisher.publish_fault_provenance_v04(raw, runtime, destination, replace=False)

    (raw / "orphan.txt").unlink()
    link = runtime / "artifacts/linked.json"
    try:
        link.symlink_to(runtime / "artifacts/evidence.json")
    except OSError:
        pytest.skip("the test filesystem does not permit symbolic links")
    with pytest.raises(publisher.PublicationError, match="symlink"):
        publisher.publish_fault_provenance_v04(raw, runtime, destination, replace=False)
