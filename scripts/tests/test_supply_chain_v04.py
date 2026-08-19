from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import (
    build_reproducible_v04,
    driver_package_lifecycle,
    inspect_image_archive_v04,
    supply_chain_v04,
    validate_cyclonedx_v04,
)


ROOT = Path(__file__).resolve().parents[2]
PLATFORM = "oci-compose-linux-amd64"
PRIVATE_KEY_FIXTURE = (
    b"-----BEGIN "
    + b"PRIVATE KEY-----\n"
    + b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
    + b"-----END "
    + b"PRIVATE KEY-----\n"
)


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return buffer.getvalue()


def _layer_tar_with_root_directory(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        directory = tarfile.TarInfo(".")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, content in files.items():
            data = io.BytesIO(content)
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, data)
    return buffer.getvalue()


def _write_image_archive(
    path: Path,
    image_id: str,
    layer_files: dict[str, bytes],
    *,
    layout: str = "legacy",
) -> None:
    digest = image_id.removeprefix("sha256:")
    if layout == "legacy":
        config_name = digest + ".json"
        layer_name = "1" * 64 + "/layer.tar"
    elif layout == "oci":
        config_name = f"blobs/sha256/{digest}"
        layer_name = "blobs/sha256/" + "1" * 64
    else:
        raise ValueError(f"unknown image archive test layout: {layout}")
    manifest = json.dumps(
        [{"Config": config_name, "Layers": [layer_name]}]
    ).encode("utf-8")
    outer = _tar_bytes(
        {
            "manifest.json": manifest,
            config_name: b"{}",
            layer_name: _tar_bytes(layer_files),
        }
    )
    path.write_bytes(outer)


def _operation_fixture(root: Path, stage: str, certainty: str) -> tuple[bytes, bytes]:
    driver_package_lifecycle._write_fixture(root, stage, certainty)
    return (
        (root / driver_package_lifecycle.JOURNAL_NAME).read_bytes(),
        (root / driver_package_lifecycle.OPERATIONS_NAME).read_bytes(),
    )


def _inspection_document(image_ids: dict[str, str] | None = None) -> dict[str, object]:
    images = image_ids or {
        "backend": "sha256:" + "b" * 64,
        "driver": "sha256:" + "d" * 64,
        "frontend": "sha256:" + "e" * 64,
        "proxy": "sha256:" + "f" * 64,
    }
    return {
        "schema_version": "spell.v04.image-inspection/1",
        "image_names": ["backend", "driver", "frontend", "proxy"],
        "image_ids": images,
        "compose_dependency_image_ids": {
            "pki_init": "sha256:" + "a" * 64,
            "postgres": "sha256:" + "c" * 64,
        },
        "compose_dependency_configured_references": {
            "pki_init": "sha256:" + "a" * 64,
            "postgres": "postgres@example.invalid@sha256:" + "c" * 64,
        },
        "compose_dependency_image_count": 2,
        "scanned_image_count": 6,
        "scanned_layer_count": 6,
        "layer_scan_failure_count": 0,
        "scanned_file_count": 1,
        "secret_file_count": 0,
        "pdf_file_count": 0,
        "manual_text_file_count": 0,
        "legacy_archive_count": 0,
        "runtime_journal_count": 0,
        "runtime_generator_count": 0,
        "hardening_failure_count": 0,
    }


def test_current_v04_inputs_are_version_hash_and_image_locked() -> None:
    result = supply_chain_v04.validate_locks(ROOT)
    assert result.lock_input_count >= 5
    assert result.python_package_count > 4
    assert result.node_package_count > 1
    assert result.image_input_count > 4
    assert result.release_tool_count == 6
    assert result.protobuf_version == "7.35.1"
    assert result.grpc_version == "1.82.1"
    assert result.tls_version == "50.0.0"

    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert compose.count(supply_chain_v04.LOCAL_COMPOSE_BUILD_IMAGE) == 3
    assert supply_chain_v04.COMPOSE_IMAGE.findall(compose).count(
        supply_chain_v04.LOCAL_COMPOSE_BUILD_IMAGE
    ) == len(supply_chain_v04.LOCAL_COMPOSE_BUILD_SERVICES)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value["tools"][0].update({"unexpected": True}),
        lambda value: value["tools"][-1].update({"base_directory": "ProgramFiles"}),
        lambda value: value["tools"][-1].update({"archive_sha256": "0" * 64}),
        lambda value: value["tools"].pop(),
    ],
)
def test_release_toolchain_parser_rejects_schema_or_python_lock_drift(mutation) -> None:
    value = json.loads(
        (ROOT / "scripts/release-toolchain-v04.json").read_text(encoding="utf-8")
    )
    candidate = deepcopy(value)
    mutation(candidate)
    with pytest.raises(ValueError, match="toolchain"):
        supply_chain_v04._validate_release_toolchain(candidate)


@pytest.mark.skipif(os.name != "nt", reason="PowerShell release host contract")
@pytest.mark.parametrize("corruption", ["duplicate", "non-finite"])
def test_executable_toolchain_assertion_rejects_ambiguous_json(
    tmp_path: Path, corruption: str
) -> None:
    text = (ROOT / "scripts/release-toolchain-v04.json").read_text(encoding="utf-8")
    if corruption == "duplicate":
        text = text.replace(
            '"host_platform":',
            '"host_platform":"shadowed","host_platform":',
            1,
        )
    else:
        text = text.replace("{", '{"non_finite":NaN,', 1)
    lock = tmp_path / "toolchain.json"
    lock.write_text(text, encoding="utf-8")

    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "scripts/assert_release_toolchain_v04.ps1"),
            "-LockPath",
            str(lock),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode != 0
    assert "invalid strict JSON" in completed.stdout


def test_python_lock_parser_rejects_an_exact_version_without_hash(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.hashes.lock"
    lock.write_text("protobuf==7.35.1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unrecognized|unterminated"):
        supply_chain_v04._locked_requirements(lock)


@pytest.mark.parametrize(
    "raw",
    [
        '{"bomFormat":"CycloneDX","bomFormat":"shadowed"}',
        '{"bomFormat":"CycloneDX","version":NaN}',
    ],
)
def test_cyclonedx_validator_rejects_ambiguous_json_before_schema_validation(
    raw: str,
) -> None:
    with pytest.raises(validate_cyclonedx_v04.CycloneDxValidationError):
        validate_cyclonedx_v04.parse_document(raw, "synthetic inventory")


@pytest.mark.parametrize("corruption", ["duplicate", "non-finite", "extra-field"])
def test_driver_package_profile_rejects_ambiguous_or_unknown_json(
    tmp_path: Path, corruption: str
) -> None:
    source = ROOT / "scripts/driver-package-v04.json"
    text = source.read_text(encoding="utf-8")
    if corruption == "duplicate":
        text = text.replace(
            '"schema_version":',
            '"schema_version":"duplicate","schema_version":',
            1,
        )
    elif corruption == "non-finite":
        text = text.replace('"default_enabled": false', '"default_enabled": NaN', 1)
    else:
        value = json.loads(text)
        value["unexpected"] = True
        text = json.dumps(value)
    profile = tmp_path / "profile.json"
    profile.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="JSON|profile"):
        driver_package_lifecycle.load_profile(profile)


@pytest.mark.parametrize("corruption", ["duplicate", "non-finite", "extra-field"])
def test_driver_package_state_rejects_ambiguous_or_unknown_json(
    tmp_path: Path, corruption: str
) -> None:
    driver_package_lifecycle.install(tmp_path, platform_id=PLATFORM)
    state_path = tmp_path / driver_package_lifecycle.STATE_NAME
    original = state_path.read_bytes()
    text = original.decode("utf-8")
    if corruption == "duplicate":
        text = text.replace(
            '"schema_version":',
            '"schema_version":"duplicate","schema_version":',
            1,
        )
    elif corruption == "non-finite":
        text = text.replace('"enabled":false', '"enabled":NaN', 1)
    else:
        value = json.loads(text)
        value["unexpected"] = True
        text = json.dumps(value)
    state_path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="JSON|state"):
        driver_package_lifecycle.transition(tmp_path, "enable")
    assert state_path.read_text(encoding="utf-8") == text


def test_layer_archive_scanner_finds_forbidden_material_in_lower_layers(
    tmp_path: Path,
) -> None:
    image_id = "sha256:" + "2" * 64
    archive = tmp_path / "image.tar"
    _write_image_archive(
        archive,
        image_id,
        {"app/deleted-later.key": b"synthetic private material"},
    )
    result = inspect_image_archive_v04.inspect_archive(archive, image_id)
    assert result["scanned_layer_count"] == 1
    assert result["scanned_file_count"] == 1
    assert result["secret_file_count"] == 1


def test_layer_archive_scanner_accepts_docker29_oci_save_layout(tmp_path: Path) -> None:
    image_id = "sha256:" + "4" * 64
    archive = tmp_path / "image.tar"
    _write_image_archive(
        archive,
        image_id,
        {"app/server.py": b"print('ok')"},
        layout="oci",
    )
    result = inspect_image_archive_v04.inspect_archive(archive, image_id)
    assert result["scanned_layer_count"] == 1
    assert result["scanned_file_count"] == 1
    assert result["secret_file_count"] == 0


def test_layer_archive_scanner_skips_non_file_layer_members(tmp_path: Path) -> None:
    image_id = "sha256:" + "5" * 64
    archive = tmp_path / "image.tar"
    digest = image_id.removeprefix("sha256:")
    layer_name = "blobs/sha256/" + "1" * 64
    manifest = json.dumps(
        [{"Config": f"blobs/sha256/{digest}", "Layers": [layer_name]}]
    ).encode("utf-8")
    archive.write_bytes(
        _tar_bytes(
            {
                "manifest.json": manifest,
                f"blobs/sha256/{digest}": b"{}",
                layer_name: _layer_tar_with_root_directory(
                    {"app/server.py": b"print('ok')"}
                ),
            }
        )
    )
    result = inspect_image_archive_v04.inspect_archive(archive, image_id)
    assert result["scanned_layer_count"] == 1
    assert result["scanned_file_count"] == 1


def test_layer_archive_scanner_finds_real_private_key_blocks(tmp_path: Path) -> None:
    image_id = "sha256:" + "6" * 64
    archive = tmp_path / "image.tar"
    _write_image_archive(
        archive,
        image_id,
        {"usr/share/doc/example.txt": PRIVATE_KEY_FIXTURE},
        layout="oci",
    )
    result = inspect_image_archive_v04.inspect_archive(archive, image_id)
    assert result["secret_file_count"] == 1


def test_layer_archive_scanner_ignores_marker_constants_and_binary_akia(
    tmp_path: Path,
) -> None:
    image_id = "sha256:" + "7" * 64
    archive = tmp_path / "image.tar"
    _write_image_archive(
        archive,
        image_id,
        {
            "usr/local/lib/python3.13/site-packages/pkg.py": (
                b"MARKER = b'-----BEGIN "
                + b"OPENSSH PRIVATE KEY-----'\n"
            ),
            "usr/lib/libexample.so": b"\0\1" + b"AKIA" + b"ABCDEFGHIJKLMNOP\2\3",
        },
        layout="oci",
    )
    result = inspect_image_archive_v04.inspect_archive(archive, image_id)
    assert result["secret_file_count"] == 0


def test_layer_archive_scanner_rejects_traversal_members(tmp_path: Path) -> None:
    image_id = "sha256:" + "3" * 64
    archive = tmp_path / "image.tar"
    _write_image_archive(archive, image_id, {"../../escape": b"unsafe"})
    with pytest.raises(ValueError, match="unsafe layer member path"):
        inspect_image_archive_v04.inspect_archive(archive, image_id)


def test_product_package_inspection_is_prepublish_and_scans_decompressed_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = tmp_path / "backend" / "app.py"
    product.parent.mkdir()
    product.write_bytes(b"print('deterministic product')\n")
    monkeypatch.setattr(
        build_reproducible_v04,
        "product_files_v04",
        lambda root: [product],
    )
    monkeypatch.setattr(
        supply_chain_v04,
        "source_fingerprint_v04",
        lambda root: "1" * 64,
    )

    result = supply_chain_v04.inspect_product_package_inputs_v04(tmp_path)

    assert not (tmp_path / "artifacts/v0.4/tests").exists()
    assert result["source_fingerprint_sha256"] == "1" * 64
    assert result["product_input_file_count"] == 1
    assert result["product_package_file_count"] == 1
    assert result["product_scanned_file_count"] == 2
    assert result["product_input_byte_count"] == result["product_package_member_byte_count"]
    assert len(result["product_package_sha256"]) == 64


@pytest.mark.parametrize(
    ("relative", "content", "message"),
    [
        ("backend/operator-manual.txt", b"manual", "manual text"),
        ("backend/service.key", b"synthetic", "secret-bearing"),
        (
            "backend/app.py",
            PRIVATE_KEY_FIXTURE,
            "high-confidence secret material",
        ),
    ],
)
def test_product_package_inspection_rejects_manual_or_credential_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    content: bytes,
    message: str,
) -> None:
    product = tmp_path / relative
    product.parent.mkdir(parents=True)
    product.write_bytes(content)
    monkeypatch.setattr(
        build_reproducible_v04,
        "product_files_v04",
        lambda root: [product],
    )
    monkeypatch.setattr(
        supply_chain_v04,
        "source_fingerprint_v04",
        lambda root: "1" * 64,
    )
    with pytest.raises(ValueError, match=message):
        supply_chain_v04.inspect_product_package_inputs_v04(tmp_path)


def test_product_package_inspection_ignores_private_key_marker_constants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = tmp_path / "backend" / "app.py"
    product.parent.mkdir()
    product.write_bytes(b"CANARY = '-----BEGIN " + b"PRIVATE KEY-----'\n")
    monkeypatch.setattr(
        build_reproducible_v04,
        "product_files_v04",
        lambda root: [product],
    )
    monkeypatch.setattr(
        supply_chain_v04,
        "source_fingerprint_v04",
        lambda root: "1" * 64,
    )
    result = supply_chain_v04.inspect_product_package_inputs_v04(tmp_path)
    assert result["product_input_file_count"] == 1


def test_product_package_inspection_rejects_source_bound_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = b"spell-v04-service-secret-" + b"1" * 64
    product = tmp_path / "backend" / "app.py"
    product.parent.mkdir()
    product.write_bytes(b"value = " + canary)
    monkeypatch.setattr(
        build_reproducible_v04,
        "product_files_v04",
        lambda root: [product],
    )
    monkeypatch.setattr(
        supply_chain_v04,
        "source_fingerprint_v04",
        lambda root: "1" * 64,
    )
    with pytest.raises(ValueError, match="forbidden marker"):
        supply_chain_v04.inspect_product_package_inputs_v04(
            tmp_path, forbidden_marker=canary
        )


def test_image_inspection_report_requires_fresh_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "image-inspection.json"
    path.write_text(json.dumps(_inspection_document()), encoding="utf-8")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    assert supply_chain_v04._load_inspection(path, expected)["scanned_image_count"] == 6

    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="hash differs from the fresh host report"):
        supply_chain_v04._load_inspection(path, expected)
    path.unlink()
    with pytest.raises(FileNotFoundError):
        supply_chain_v04._load_inspection(path, expected)


def test_image_inspection_report_rejects_missing_digest_binding(tmp_path: Path) -> None:
    path = tmp_path / "image-inspection.json"
    path.write_text(json.dumps(_inspection_document()), encoding="utf-8")

    with pytest.raises(ValueError, match="expected hash is invalid"):
        supply_chain_v04._load_inspection(path, "")


def test_sc003_rejects_substituted_report_image_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected_ids = {
        "backend": "sha256:" + "b" * 64,
        "proxy": "sha256:" + "f" * 64,
        "frontend": "sha256:" + "e" * 64,
        "driver": "sha256:" + "d" * 64,
    }
    substituted = dict(expected_ids)
    substituted["backend"] = "sha256:" + "9" * 64
    path = tmp_path / "image-inspection.json"
    path.write_text(json.dumps(_inspection_document(substituted)), encoding="utf-8")
    expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        supply_chain_v04,
        "source_fingerprint_v04",
        lambda root: "1" * 64,
    )
    monkeypatch.setattr(
        supply_chain_v04,
        "validate_sboms_v04",
        lambda root, source: tuple(
            expected_ids[name.partition(".")[0]]
            for name in supply_chain_v04.SBOM_FILES
        ),
    )

    with pytest.raises(ValueError, match="identities differ from current SBOM inputs"):
        supply_chain_v04.probe_sc_003(tmp_path, path, expected_hash)


@pytest.mark.parametrize(
    "line",
    [
        "--index-url https://example.invalid/simple",
        "package>=1.0",
        "-r another-lock.txt",
        "package==1.0",
        "--hash=sha256:" + "a" * 64,
    ],
)
def test_python_lock_parser_rejects_every_unrecognized_or_unpinned_line(
    tmp_path: Path, line: str
) -> None:
    lock = tmp_path / "requirements.hashes.lock"
    lock.write_text(f"{line}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unrecognized|unterminated"):
        supply_chain_v04._locked_requirements(lock)


def test_driver_package_installs_disabled_and_enables_only_bundled_simulator(
    tmp_path: Path,
) -> None:
    result = driver_package_lifecycle.install(tmp_path, platform_id=PLATFORM)
    assert result.applied
    state = json.loads(
        (tmp_path / driver_package_lifecycle.STATE_NAME).read_text(encoding="utf-8")
    )
    assert state["enabled"] is False
    assert state["active_service"] is None

    enabled = driver_package_lifecycle.transition(tmp_path, "enable")
    state = json.loads(
        (tmp_path / driver_package_lifecycle.STATE_NAME).read_text(encoding="utf-8")
    )
    assert enabled.applied
    assert state["enabled"] is True
    assert state["active_service"] == "spell-driver"


def test_enable_refuses_retained_uncertain_operation(tmp_path: Path) -> None:
    driver_package_lifecycle.install(tmp_path, platform_id=PLATFORM)
    _operation_fixture(tmp_path, "RECONCILING", "EFFECT_UNKNOWN")
    result = driver_package_lifecycle.transition(tmp_path, "enable")
    assert result.applied is False
    state = json.loads(
        (tmp_path / driver_package_lifecycle.STATE_NAME).read_text(encoding="utf-8")
    )
    assert state["enabled"] is False
    assert state["active_service"] is None


@pytest.mark.parametrize("missing_field", ["operation_id", "tombstone"])
def test_transition_refuses_terminal_evidence_without_identity_or_tombstone(
    tmp_path: Path, missing_field: str
) -> None:
    driver_package_lifecycle.install(tmp_path, platform_id=PLATFORM)
    driver_package_lifecycle._write_fixture(tmp_path, "SETTLED", "NO_EFFECT")
    evidence_path = tmp_path / driver_package_lifecycle.OPERATIONS_NAME
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["operations"][0].pop(missing_field)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    result = driver_package_lifecycle.transition(tmp_path, "uninstall")
    assert result.applied is False
    assert (tmp_path / driver_package_lifecycle.CREDENTIAL_NAME).is_file()


@pytest.mark.parametrize("action", ["enable", "disable", "upgrade", "rollback", "uninstall"])
@pytest.mark.parametrize(
    ("stage", "certainty"),
    [
        ("REQUESTED", "NO_EFFECT"),
        ("ACCEPTED", "NO_EFFECT"),
        ("DISPATCHED", "EFFECT_POSSIBLE"),
        ("RECONCILING", "EFFECT_CONFIRMED"),
        ("RECONCILING", "EFFECT_POSSIBLE"),
        ("RECONCILING", "EFFECT_UNKNOWN"),
        ("SETTLED", "EFFECT_POSSIBLE"),
        ("SETTLED", "EFFECT_UNKNOWN"),
        ("UNRECOGNIZED_STAGE", "NO_EFFECT"),
        ("SETTLED", "UNRECOGNIZED_CERTAINTY"),
    ],
)
def test_unsafe_package_transitions_refuse_without_changing_evidence_or_secret(
    tmp_path: Path, action: str, stage: str, certainty: str
) -> None:
    driver_package_lifecycle.install(tmp_path, platform_id=PLATFORM)
    if action != "enable":
        driver_package_lifecycle.transition(tmp_path, "enable")
    journal, operations = _operation_fixture(tmp_path, stage, certainty)
    state_before = (tmp_path / driver_package_lifecycle.STATE_NAME).read_bytes()
    result = driver_package_lifecycle.transition(
        tmp_path,
        action,
        target_version="0.4.1-test" if action == "upgrade" else None,
    )
    assert result.applied is False
    assert (tmp_path / driver_package_lifecycle.STATE_NAME).read_bytes() == state_before
    assert (tmp_path / driver_package_lifecycle.JOURNAL_NAME).read_bytes() == journal
    assert (tmp_path / driver_package_lifecycle.OPERATIONS_NAME).read_bytes() == operations
    assert (tmp_path / driver_package_lifecycle.CREDENTIAL_NAME).is_file()
    audit = (tmp_path / driver_package_lifecycle.AUDIT_NAME).read_text(encoding="utf-8")
    assert f'"action":"{action}"' in audit
    assert '"applied":false' in audit


@pytest.mark.parametrize("action", ["enable", "disable", "upgrade", "rollback", "uninstall"])
@pytest.mark.parametrize("certainty", ["NO_EFFECT", "EFFECT_CONFIRMED"])
def test_terminal_package_transitions_preserve_records_and_remove_secret_only_on_uninstall(
    tmp_path: Path, action: str, certainty: str
) -> None:
    driver_package_lifecycle.install(tmp_path, platform_id=PLATFORM)
    if action != "enable":
        driver_package_lifecycle.transition(tmp_path, "enable")
    journal, operations = _operation_fixture(tmp_path, "SETTLED", certainty)
    result = driver_package_lifecycle.transition(
        tmp_path,
        action,
        target_version="0.4.1-test" if action == "upgrade" else None,
    )
    assert result.applied is True
    assert (tmp_path / driver_package_lifecycle.JOURNAL_NAME).read_bytes() == journal
    assert (tmp_path / driver_package_lifecycle.OPERATIONS_NAME).read_bytes() == operations
    assert (tmp_path / driver_package_lifecycle.CREDENTIAL_NAME).exists() is (action != "uninstall")
    state = json.loads(
        (tmp_path / driver_package_lifecycle.STATE_NAME).read_text(encoding="utf-8")
    )
    assert state["enabled"] is (action == "enable")
    if action == "enable":
        assert state["installed"] is True
        assert state["active_service"] == "spell-driver"
    elif action == "disable":
        assert state["installed"] is True
        assert state["package_version"] == "0.4.0"
    elif action == "upgrade":
        assert state["installed"] is True
        assert state["package_version"] == "0.4.1-test"
    elif action == "rollback":
        assert state["installed"] is False
        assert state["package_version"] == "0.3.0"
        assert state["prior_profile"]["driver_enabled"] is False
    else:
        assert state["installed"] is False


def test_lifecycle_qualification_executes_all_declared_state_cases() -> None:
    result = driver_package_lifecycle.qualify(ROOT)
    assert result["test_id"] == "V04-SC-006"
    assert result["metrics"]["platform_profile_count"] == 1
    assert result["metrics"]["enable_case_count"] == 13
    assert result["metrics"]["terminal_case_count"] == 10
    assert result["metrics"]["unsafe_refusal_case_count"] == 50
    assert result["metrics"]["failed_case_count"] == 0


def test_v04_release_entry_points_are_version_isolated_and_fail_closed() -> None:
    audit = (ROOT / "scripts/audit_supply_chain_v04.ps1").read_text(encoding="utf-8")
    sbom = (ROOT / "scripts/generate_sbom_v04.ps1").read_text(encoding="utf-8")
    package = (ROOT / "scripts/package_release_v04.ps1").read_text(encoding="utf-8")
    assert "supply-chain-v04.Dockerfile" in audit
    assert "& $ScoutExe cves" in audit
    assert "& $DockerExe" in audit
    assert '"artifacts/v0.4"' in sbom and '"sbom"' in sbom
    assert "validate_release_evidence_v04.py" in package
    assert 'package_build_count = 3' in package
    for content in (audit, sbom, package):
        assert "source_fingerprint.py --root" not in content
        assert "artifacts/v0.3" not in content


def test_sbom_generation_uses_real_offline_schema_validation_and_negative_test() -> None:
    dockerfile = (ROOT / "scripts/supply-chain-v04.Dockerfile").read_text(
        encoding="utf-8"
    )
    validator = (ROOT / "scripts/validate_cyclonedx_v04.py").read_text(
        encoding="utf-8"
    )
    generator = (ROOT / "scripts/generate_sbom_v04.ps1").read_text(
        encoding="utf-8"
    )
    requirements = (ROOT / "scripts/supply-chain-requirements.txt").read_text(
        encoding="utf-8"
    )
    assert "cyclonedx-python-lib[json-validation]==11.11.0" in requirements
    assert "AS sbom-validator" in dockerfile
    assert "validate_cyclonedx_v04.py self-test" in dockerfile
    assert "JsonStrictValidator" in validator
    assert "invalid-tampered-type" in validator
    assert "MissingOptionalDependencyException" in validator
    assert "--target sbom-validator" in generator
    assert "--network none" in generator
    assert "--read-only" in generator
    assert "--mount $validatorMount" in generator
    assert "dst=/validation,readonly" in generator
    assert "$_ -and $_.name -ne $fingerprintProperty" in generator
    assert "$existingLicenses = @($matches[0].licenses | Where-Object { $_ })" in generator
    assert "negative_tamper_rejected" in generator


def test_gate5_entry_points_clean_all_run_scoped_docker_resources() -> None:
    for name in (
        "audit_supply_chain_v04.ps1",
        "collect_supply_chain_v04.ps1",
        "generate_sbom_v04.ps1",
        "inspect_release_v04.ps1",
        "package_release_v04.ps1",
    ):
        content = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "release_docker_resources_v04.ps1" in content, name
        assert "Remove-V04RunDockerResources" in content, name
        assert "retained_shared_image_ids" in content, name
    collector = (ROOT / "scripts/collect_supply_chain_v04.ps1").read_text(
        encoding="utf-8"
    )
    assert "--name $container" in collector
    assert "Gate 5 collector failed and cleanup also failed" in collector
    assert "$originalFailure.Exception" in collector


def test_sc004_retains_provenance_across_container_exit_and_cleans_volume() -> None:
    collector = (ROOT / "scripts/collect_supply_chain_v04.ps1").read_text(
        encoding="utf-8"
    )
    sc004 = collector.split('if ($TestId -eq "V04-SC-004") {', 1)[1].split(
        'if ($TestId -eq "V04-SC-006") {', 1
    )[0]
    assert "volume create --label" in sc004
    assert (
        '--mount "type=volume,source=$provenanceVolume,target=/provenance"'
        in sc004
    )
    assert "--provenance-output /provenance/sc004" in sc004
    assert ":/tmp/supply-provenance" not in sc004
    assert 'cp "${container}:/provenance/sc004/."' in sc004
    assert "copyContainer" not in sc004
    assert "Remove-SupplyRunVolumes $runVolumes.ToArray()" in collector
    assert '@("volume", "rm", $volume)' in collector
    assert '$failures.Add("cannot remove run volume $volume")' in collector
    assert '$failures.Add("run volume remains: $volume")' in collector


def test_sc006_collector_executes_the_delivered_real_compose_lifecycle() -> None:
    collector = (ROOT / "scripts/collect_supply_chain_v04.ps1").read_text(
        encoding="utf-8"
    )
    assert "driver_compose_lifecycle_v04.py" in collector
    assert "--driver-image-a" in collector
    assert "--driver-image-b" in collector
    assert "--pki-image" in collector
    assert "$env:SPELL_RELEASE_PYTHON_EXE" in collector
    assert "py -3.9" not in collector
    assert "driver_package_lifecycle.py --root /workspace qualify" not in collector


def test_v04_release_scripts_invoke_hash_verified_tool_paths() -> None:
    assertion = (ROOT / "scripts/assert_release_toolchain_v04.ps1").read_text(
        encoding="utf-8"
    )
    assert "$env:SPELL_RELEASE_DOCKER_EXE" in assertion
    assert "$env:SPELL_RELEASE_COMPOSE_EXE" in assertion
    assert "$env:SPELL_RELEASE_SBOM_EXE" in assertion
    assert "$env:SPELL_RELEASE_SCOUT_EXE" in assertion
    assert "$env:SPELL_RELEASE_PYTHON_EXE" in assertion
    for name in (
        "audit_supply_chain_v04.ps1",
        "collect_fault_gate_v04.ps1",
        "collect_supply_chain_v04.ps1",
        "generate_sbom_v04.ps1",
        "inspect_release_v04.ps1",
        "package_release_v04.ps1",
    ):
        content = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "& $DockerExe" in content, name
        assert "& docker" not in content, name


def test_sc003_scans_saved_image_layers_and_rejects_all_root_principals() -> None:
    inspection = (ROOT / "scripts/inspect_release_v04.ps1").read_text(
        encoding="utf-8"
    )
    scanner = (ROOT / "scripts/inspect_image_archive_v04.py").read_text(
        encoding="utf-8"
    )
    assert "image save --output" in inspection
    assert "manifest.json" in scanner
    assert "tarfile.open" in scanner
    assert "scanned_layer_count" in inspection
    assert "docker export" not in inspection
    assert "^0+$" in inspection
    assert '$principal -ieq "root"' in inspection


def test_sc003_rebuilds_exact_sbom_subjects_and_binds_the_fresh_report() -> None:
    inspection = (ROOT / "scripts/inspect_release_v04.ps1").read_text(
        encoding="utf-8"
    )
    for dockerfile in (
        'Dockerfile = "backend/Dockerfile"',
        'Dockerfile = "driver_host/Dockerfile"',
        'Dockerfile = "proxy/Dockerfile"',
        'Target = "frontend-build"',
    ):
        assert dockerfile in inspection
    assert "$imageDefinitions.GetEnumerator()" in inspection
    assert "$runTags = @($probeTag, $pkiTag, $postgresTag)" in inspection
    assert "image identity differs from the SC002 SBOM" in inspection
    assert "$runImageIds.Add($rebuiltImage)" in inspection
    assert "foreach ($path in @($reportPath, $reportStaging))" in inspection
    assert "Remove-Item -LiteralPath $path -Force" in inspection
    assert "$reportStaging" in inspection
    assert "Move-Item -LiteralPath $reportStaging -Destination $reportPath" in inspection
    assert "--mount $reportMount" in inspection
    assert "dst=/inspection/image-inspection.json,readonly" in inspection
    assert "--inspection-report-sha256 $reportSha256" in inspection
    assert "/workspace/artifacts/v0.4/.qualification/image-inspection.json" not in inspection


def test_final_package_publication_preserves_or_replaces_the_complete_pair() -> None:
    package = (ROOT / "scripts/package_release_v04.ps1").read_text(encoding="utf-8")
    assert "existing v0.4 package publication is incomplete" in package
    assert "$backupRelease" in package and "$backupSidecar" in package
    assert "published v0.4 package pair failed final verification" in package
    assert "package input changed immediately before v0.4 publication" in package
