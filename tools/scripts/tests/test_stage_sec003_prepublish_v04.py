from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

from scripts import stage_sec003_prepublish_v04 as stage
from scripts import collect_regression_v04 as regression


SOURCE = "a" * 64


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> stage.Inputs:
    root = tmp_path / "root"
    source_capture = (
        root
        / "artifacts"
        / "v0.4"
        / ".qualification"
        / "runtime-captures"
        / SOURCE
    )
    frontend = source_capture / "regression" / "frontend-dist"
    (frontend / "assets").mkdir(parents=True)
    (frontend / "index.html").write_text("<main>v0.4</main>\n", encoding="utf-8")
    (frontend / "assets/app.js").write_text("console.log('v0.4')\n", encoding="utf-8")
    snapshot = stage._snapshot_tree(
        frontend,
        label="test frontend",
        bounds=stage.FRONTEND_BOUNDS,
        secret_tokens=(),
    )
    _write_json(
        frontend.parent / "run.json",
        {
            "schema_version": "spell.v04.regression-run/1",
            "source_fingerprint_before_sha256": SOURCE,
            "source_fingerprint_after_sha256": SOURCE,
            "frontend_build": {
                "file_count": len(snapshot.files),
                "sha256": stage._frontend_digest(snapshot),
            },
        },
    )

    browser_provenance = root / "artifacts" / "v0.4" / "provenance" / "browser"
    browser_provenance.mkdir(parents=True)
    for name in stage.BROWSER_PROVENANCE_NAMES:
        _write_json(browser_provenance / name, {})
    browser_storage = root / "artifacts" / "v0.4" / "browser-storage.json"
    _write_json(
        browser_storage,
        {
            "schema_version": "spell.v04.browser-storage/1",
            "source_fingerprint_sha256": SOURCE,
        },
    )
    desktop = root / "artifacts" / "v0.4" / "driver-projection-desktop.png"
    mobile = root / "artifacts" / "v0.4" / "driver-projection-mobile.png"
    desktop.write_bytes(stage.PNG_SIGNATURE + b"desktop")
    mobile.write_bytes(stage.PNG_SIGNATURE + b"mobile")

    sboms = root / "artifacts" / "v0.4" / "sbom"
    sboms.mkdir()
    checksum_lines = []
    for name in sorted(stage.SBOM_NAMES):
        path = sboms / name
        _write_json(path, {"bomFormat": "CycloneDX", "name": name})
        checksum_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    (sboms / "SHA256SUMS").write_text(
        "\n".join(checksum_lines) + "\n", encoding="ascii"
    )

    runtime = source_capture / "fault-runtime"
    (runtime / "artifacts").mkdir(parents=True)
    _write_json(runtime / "runtime-fault-evidence.json", {"source": SOURCE})
    (runtime / "artifacts/evidence.txt").write_text("runtime evidence\n", encoding="utf-8")

    destination = tmp_path / "delivery" / "prepublish"
    destination.parent.mkdir()
    inputs = stage.Inputs(
        root=root,
        destination=destination,
        source_fingerprint=SOURCE,
        frontend_bundle=frontend,
        browser_provenance=browser_provenance,
        browser_storage=browser_storage,
        desktop_screenshot=desktop,
        mobile_screenshot=mobile,
        sbom_directory=sboms,
        runtime_captures=runtime,
    )
    monkeypatch.setattr(stage, "source_fingerprint_v04", lambda _root: SOURCE)
    monkeypatch.setattr(
        stage, "validate_regression_capture_v04", lambda _root, _capture: {}
    )
    monkeypatch.setattr(
        stage, "validate_browser_provenance_v04", lambda _root, _source: {}
    )
    monkeypatch.setattr(stage, "validate_sboms_v04", lambda _root, _source: ())
    monkeypatch.setattr(stage, "load_runtime_input", lambda *_args, **_kwargs: object())
    return inputs


def test_build_and_validate_exact_atomic_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)

    built = stage.build_prepublish(inputs)
    validated = stage.validate_prepublish(inputs)

    assert built == validated
    assert built["schema_version"] == stage.SCHEMA_VERSION
    assert built["source_fingerprint_sha256"] == SOURCE
    assert built["category_count"] == 5
    assert set(built["categories"]) == set(stage.CATEGORIES)
    assert {path.name for path in inputs.destination.iterdir()} == set(stage.CATEGORIES)
    assert {
        path.name for path in (inputs.destination / "sboms").iterdir()
    } == stage.SBOM_NAMES
    assert {
        path.name for path in (inputs.destination / "screenshots").iterdir()
    } == stage.SCREENSHOT_NAMES
    assert (
        inputs.destination / "runtime_captures" / "runtime-fault-evidence.json"
    ).read_bytes() == (
        inputs.runtime_captures / "runtime-fault-evidence.json"
    ).read_bytes()
    assert not list(inputs.destination.parent.glob(".sec003-stage-*"))


def test_validate_rejects_extra_output_and_sbom_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    stage.build_prepublish(inputs)
    (inputs.destination / "screenshots/unexpected.png").write_bytes(
        stage.PNG_SIGNATURE + b"unexpected"
    )
    with pytest.raises(stage.PrepublishError, match="screenshots"):
        stage.validate_prepublish(inputs)

    (inputs.sbom_directory / "unexpected.txt").write_text("extra\n", encoding="utf-8")
    with pytest.raises(stage.PrepublishError, match="SBOM source directory"):
        stage._prepare_inputs(inputs)


def test_secret_rejection_happens_before_destination_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    (inputs.frontend_bundle / "assets/app.js").write_text(
        f"const leaked = '{'spell-v04-service-secret-' + SOURCE}';\n",
        encoding="utf-8",
    )

    with pytest.raises(stage.PrepublishError, match="credential-like material"):
        stage.build_prepublish(inputs)

    assert not os.path.lexists(inputs.destination)
    assert not list(inputs.destination.parent.glob(".sec003-stage-*"))


def test_stale_frontend_binding_and_source_alias_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    run_path = inputs.frontend_bundle.parent / "run.json"
    run = json.loads(run_path.read_text(encoding="utf-8"))
    run["source_fingerprint_after_sha256"] = "b" * 64
    _write_json(run_path, run)
    with pytest.raises(stage.PrepublishError, match="source binding is stale"):
        stage._prepare_inputs(inputs)

    alias = stage.Inputs(
        **{
            **inputs.__dict__,
            "frontend_bundle": tmp_path / "other-frontend",
        }
    )
    with pytest.raises(stage.PrepublishError, match="canonical source-bound"):
        stage._assert_canonical_inputs(alias)


def test_incomplete_fabricated_regression_manifest_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(regression, "source_fingerprint_v04", lambda _root: SOURCE)
    monkeypatch.setattr(
        stage, "validate_regression_capture_v04", regression.validate_capture
    )

    with pytest.raises(
        stage.PrepublishError,
        match="frontend regression provenance is invalid: regression product version differs",
    ):
        stage._prepare_inputs(inputs)


def test_symlink_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    link = inputs.frontend_bundle / "assets/linked.js"
    try:
        link.symlink_to(inputs.frontend_bundle / "assets/app.js")
    except OSError:
        pytest.skip("the test filesystem does not permit symbolic links")
    with pytest.raises(stage.PrepublishError, match="symlink or reparse point"):
        stage._prepare_inputs(inputs)


def test_windows_reparse_metadata_is_rejected() -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG,
        st_file_attributes=stage.REPARSE_POINT,
    )
    assert stage._is_reparse(metadata) is True


def test_failed_atomic_install_removes_owned_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        stage.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("injected install failure")),
    )

    with pytest.raises(OSError, match="injected install failure"):
        stage.build_prepublish(inputs)

    assert not os.path.lexists(inputs.destination)
    assert not list(inputs.destination.parent.glob(".sec003-stage-*"))


def test_staging_and_publication_fit_legacy_windows_path_budget() -> None:
    capture_parent = (
        PureWindowsPath(r"C:\projects\openbexi_spell")
        / "artifacts"
        / "v0.4"
        / ".qualification"
        / "runtime-captures"
        / ("f" * 64)
    )
    staging = capture_parent / f".sec003-stage-{'s' * 32}"
    published = capture_parent / f"sec003-prepublish-{'r' * 32}"
    category = PureWindowsPath("runtime_captures") / "artifacts"
    longest_file = category / "runtime-v04-scope-002.host-powershell.json"

    assert staging.parent == published.parent
    assert len(str(staging)) == 185
    assert len(str(staging / "browser_storage")) == 201
    assert len(str(staging / category)) == 212 < 248
    assert len(str(staging / longest_file)) == 255
    assert len(str(staging / longest_file)) <= len(str(published / longest_file)) < 260
