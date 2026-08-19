from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts import qualify_faults_v04 as faults
ROOT = Path(__file__).resolve().parents[2]
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def current_source() -> str:
    return faults.source_fingerprint_v04(ROOT)


@pytest.fixture(autouse=True)
def freeze_source_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    source = faults.source_fingerprint_v04(ROOT)
    monkeypatch.setattr(faults, "source_fingerprint_v04", lambda _root: source)


def _sec003_metrics(source: str) -> dict[str, object]:
    return {
        "canary_location_count": 5,
        "canary_leak_count": 0,
        "canary_sha256": hashlib.sha256(
            f"spell-v04-service-secret-{source}".encode("ascii")
        ).hexdigest(),
        "scanned_file_count": 10,
        "category_scanned_byte_count": 80,
        "scanned_byte_count": 100,
        "category_file_counts": {
            "frontend_bundle": 1,
            "browser_storage": 1,
            "screenshots": 1,
            "sboms": 4,
            "runtime_captures": 1,
        },
        "source_fingerprint_sha256": source,
        "product_input_file_count": 1,
        "product_package_file_count": 1,
        "product_scanned_file_count": 2,
        "product_input_byte_count": 10,
        "product_package_member_byte_count": 10,
        "product_scanned_byte_count": 20,
        "product_package_byte_count": 30,
        "product_package_sha256": "1" * 64,
        "product_secret_file_count": 0,
        "product_pdf_file_count": 0,
        "product_manual_text_file_count": 0,
        "product_legacy_archive_count": 0,
        "product_runtime_journal_count": 0,
        "product_forbidden_marker_count": 0,
    }


def _runtime_metrics(test_id: str) -> dict[str, object]:
    values: dict[str, dict[str, object]] = {
        "V04-SCOPE-002": {
            "accepted_telemetry_execution_count": 1,
            "telemetry_event_count": 1,
            "health_baseline_observation_count": 1,
            "execution_correlated_rpc_delta": 0,
            "context_delta": 0,
            "binding_delta": 0,
            "operation_delta": 0,
            "journal_delta": 0,
        },
        "V04-MIG-004": {
            "dialect_count": 2,
            "postgres_backup_restore_count": 1,
            "postgres_snapshot_mismatch_count": 0,
            "truth_state_count": 6,
            "unsafe_rollback_refusal_count": 1,
            "unsafe_rollback_evidence_loss_count": 0,
            "safe_rollback_count": 1,
            "v03_snapshot_mismatch_count": 0,
            "enabled_driver_profile_count": 0,
            "v03_simulator_execution_count": 1,
            "duplicate_effect_count": 0,
        },
        "V04-SEC-002": {
            "prior_credential_epoch": 1,
            "new_credential_epoch": 2,
            "profile_revision_delta": 1,
            "rotation_audit_count": 1,
            "rotation_outbox_count": 1,
            "current_credential_status": "UNIMPLEMENTED",
            "old_credential_status": "UNAVAILABLE",
            "ca_changed": True,
            "client_certificate_changed": True,
            "configuration_digest_drift_count": 0,
            "credential_reference_drift_count": 0,
            "prior_trust_fingerprint_count": 1,
            "new_trust_fingerprint_count": 1,
            "retained_prior_trust_fingerprint_count": 0,
            "unexpected_new_trust_fingerprint_count": 0,
            "old_credential_rejection_count": 1,
            "trust_set_expansion_count": 0,
            "post_rotation_ready_observation_count": 1,
            "post_rotation_stale_observation_count": 0,
            "ready_after_rotation": True,
            "ready_credential_epoch": 2,
        },
        "V04-SEC-004": {
            "reflection_status": "UNIMPLEMENTED",
            "direct_administration_status": "UNIMPLEMENTED",
            "jwt_without_mtls_status": "UNAVAILABLE",
            "unauthorized_metadata_status": "FAILED_PRECONDITION",
            "proxy_route_http_status": 404,
            "safe_audit_reason_count": 4,
            "unsafe_echo_count": 0,
        },
        "V04-BOUND-002": {
            "nominal_captured_frame_count": 1,
            "fault_captured_frame_count": 1,
            "nominal_endpoint_tuple_count": 1,
            "fault_endpoint_tuple_count": 1,
            "nominal_unapproved_endpoint_count": 0,
            "fault_unapproved_endpoint_count": 0,
            "nominal_capture_truncated": False,
            "fault_capture_truncated": False,
            "connection_log_unapproved_endpoint_count": 0,
        },
        "V04-ISO-003": {
            "injection_count": 2,
            "unchanged_non_driver_container_observation_count": 6,
            "non_driver_liveness_failure_count": 0,
            "worker_progress_failure_count": 0,
            "degraded_or_stale_observation_count": 2,
            "recovery_count": 2,
            "recovery_failure_count": 0,
        },
        "V04-ISO-004": {
            "driver_listener_reachable": True,
            "backend_to_driver_reachable": True,
            "reverse_api_reachable": False,
            "database_reachable": False,
            "proxy_reachable": False,
            "host_alias_reachable": False,
            "loopback_api_reachable": False,
            "loopback_proxy_reachable": False,
            "test_net_reachable": False,
            "unapproved_route_count": 0,
        },
        "V04-REC-005": {
            "phase_count": 3,
            "operation_case_count": 3,
            "duplicate_effect_count": 0,
            "resend_count": 0,
            "unreconstructable_count": 0,
            "audit_outbox_mismatch_count": 0,
            "commit_publish_violation_count": 0,
            "final_disposition_count": 3,
        },
    }
    return {
        **values[test_id],
        "host_powershell_sha256": "e" * 64,
        "host_powershell_version": "5.1.22621.2506",
        "host_python_sha256": (
            "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1"
        ),
        "host_python_version": "3.13.14",
        "host_docker_sha256": (
            "5c077f7e830dd07109dd062b99c0ad9154714a2a5baf4ec3dcbd44ff9545972d"
        ),
        "host_docker_version": "29.7.2",
        "host_compose_sha256": (
            "b71712f27e422b55f27305d0d4b040d11e9e07fc8bc296f52475c1883f934326"
        ),
        "host_compose_version": "v5.3.1",
    }


def _fixture_images() -> dict[str, str]:
    return {
        role: "sha256:" + f"{index:x}" * 64
        for index, role in enumerate(sorted(faults.RAW_REPORT_IMAGE_ROLES), start=1)
    }


def _runtime_document(
    images: dict[str, str],
    source: str | None = None,
    host_tools: dict[str, tuple[str, str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    source = source or current_source()
    host_tools = host_tools or {
        "python": (
            "C:/Users/test/AppData/Local/OpenBEXI/release-toolchain/"
            "python-3.13.14-embed-amd64/python.exe",
            "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1",
            "3.13.14",
        ),
        "docker-cli": (
            "C:/Program Files/Docker/Docker/resources/bin/docker.exe",
            "5c077f7e830dd07109dd062b99c0ad9154714a2a5baf4ec3dcbd44ff9545972d",
            "29.7.2",
        ),
        "docker-compose": (
            "C:/Program Files/Docker/Docker/resources/cli-plugins/docker-compose.exe",
            "b71712f27e422b55f27305d0d4b040d11e9e07fc8bc296f52475c1883f934326",
            "v5.3.1",
        ),
    }
    if set(host_tools) != {"python", "docker-cli", "docker-compose"}:
        raise ValueError("host tool fixture set differs")
    python_path, python_sha256, python_version = host_tools["python"]
    docker_path, docker_sha256, docker_version = host_tools["docker-cli"]
    compose_path, compose_sha256, compose_version = host_tools["docker-compose"]
    commands: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    results: dict[str, object] = {}
    payloads: dict[str, bytes] = {}
    for test_id in sorted(faults.RUNTIME_CAPTURE_IDS):
        command_id = f"runtime-{test_id.casefold()}"
        stdout_id = f"{command_id}.stdout"
        stderr_id = f"{command_id}.stderr"
        evidence_id = f"{command_id}.evidence"
        tool_id = f"{command_id}.host-powershell"
        python_tool_id = f"{command_id}.host-python"
        docker_tool_id = f"{command_id}.host-docker"
        compose_tool_id = f"{command_id}.host-compose"
        powershell_path = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        assertions = [{"id": "live-composed-probe-passed", "passed": True}]
        metrics = _runtime_metrics(test_id)
        metrics.update(
            {
                "host_python_sha256": python_sha256,
                "host_python_version": python_version,
                "host_docker_sha256": docker_sha256,
                "host_docker_version": docker_version,
                "host_compose_sha256": compose_sha256,
                "host_compose_version": compose_version,
            }
        )
        canonical = faults._canonical_json(
            {"test_id": test_id, "assertions": assertions, "metrics": metrics}
        ) + b"\n"
        for artifact_id, suffix, kind, data in (
            (stdout_id, "json", "command-stdout", canonical),
            (stderr_id, "txt", "command-stderr", b""),
            (evidence_id, "json", "test-evidence", canonical),
            (
                tool_id,
                "json",
                "runtime-json",
                faults._canonical_json(
                    {
                        "path": powershell_path,
                        "sha256": metrics["host_powershell_sha256"],
                        "version": metrics["host_powershell_version"],
                    }
                )
                + b"\n",
            ),
            (
                python_tool_id,
                "json",
                "runtime-json",
                faults._canonical_json(
                    {
                        "path": python_path,
                        "sha256": metrics["host_python_sha256"],
                        "version": metrics["host_python_version"],
                    }
                )
                + b"\n",
            ),
            (
                docker_tool_id,
                "json",
                "runtime-json",
                faults._canonical_json(
                    {
                        "path": docker_path,
                        "sha256": metrics["host_docker_sha256"],
                        "version": metrics["host_docker_version"],
                    }
                )
                + b"\n",
            ),
            (
                compose_tool_id,
                "json",
                "runtime-json",
                faults._canonical_json(
                    {
                        "path": compose_path,
                        "sha256": metrics["host_compose_sha256"],
                        "version": metrics["host_compose_version"],
                    }
                )
                + b"\n",
            ),
        ):
            relative = f"artifacts/{artifact_id}.{suffix}"
            artifacts.append(
                {
                    "id": artifact_id,
                    "path": relative,
                    "kind": kind,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
            payloads[relative] = data
        commands.append(
            {
                "id": command_id,
                "test_id": test_id,
                "executor": "host-powershell",
                "argv": [
                    powershell_path,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    "scripts/collect_fault_runtime_v04.ps1",
                    "-RuntimeProbe",
                    test_id,
                ],
                "exit_code": 0,
                "stdout_artifact_id": stdout_id,
                "stderr_artifact_id": stderr_id,
                "evidence_artifact_id": evidence_id,
                "environment_keys": list(
                    faults.RUNTIME_COMMAND_ENVIRONMENT_KEYS[test_id]
                ),
                "started_at": "2026-07-19T20:58:00Z",
                "finished_at": "2026-07-19T20:59:00Z",
            }
        )
        results[test_id] = {
            "test_id": test_id,
            "assertions": assertions,
            "metrics": metrics,
            "command_ids": [command_id],
            "artifact_ids": [
                stdout_id,
                stderr_id,
                evidence_id,
                tool_id,
                python_tool_id,
                docker_tool_id,
                compose_tool_id,
            ],
        }
    return (
        {
            "schema_version": faults.RUNTIME_INPUT_SCHEMA_VERSION,
            "captured_at": "2026-07-19T21:00:00Z",
            "run_id": "a" * 32,
            "source_fingerprint_sha256": source,
            "complete": True,
            "source_frozen": True,
            "images": images,
            "compose": {
                "project_name": "spell-v04-runtime",
                "container_ids": {
                    role: f"{index:x}" * 64
                    for index, role in enumerate(
                        ("backend", "driver", "postgres", "proxy"), start=8
                    )
                },
            },
            "commands": commands,
            "artifacts": artifacts,
            "results": results,
        },
        payloads,
    )


def write_runtime_input(
    tmp_path: Path,
    images: dict[str, str],
    source: str | None = None,
) -> Path:
    document, payloads = _runtime_document(images, source)
    runtime_root = tmp_path / "runtime-input"
    for relative, data in payloads.items():
        target = runtime_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o444)
    path = runtime_root / "runtime-fault-evidence.json"
    path.write_bytes(faults._canonical_json(document) + b"\n")
    path.chmod(0o444)
    return path


def rewrite_runtime_document(path: Path, document: dict[str, Any]) -> None:
    path.chmod(0o644)
    path.write_bytes(faults._canonical_json(document) + b"\n")
    path.chmod(0o444)


def read_runtime_document(path: Path) -> dict[str, Any]:
    value = faults._strict_json(path.read_text(encoding="utf-8"), "fixture")
    assert isinstance(value, dict)
    return value


def write_release_toolchain_lock(
    tmp_path: Path,
    mutate: Any,
) -> Path:
    lock = faults._strict_json(
        (ROOT / "scripts/release-toolchain-v04.json").read_text(encoding="utf-8"),
        "fixture release toolchain lock",
    )
    assert isinstance(lock, dict)
    mutate(lock)
    lock_root = tmp_path / "lock-root"
    lock_path = lock_root / "scripts/release-toolchain-v04.json"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_bytes(faults._canonical_json(lock) + b"\n")
    return lock_root


def valid_report(
    source: str | None = None,
    images: dict[str, str] | None = None,
    host_tools: dict[str, tuple[str, str, str]] | None = None,
    *,
    preliminary: bool = False,
) -> dict[str, Any]:
    source = source or current_source()
    images = images or _fixture_images()
    runtime_document, _ = _runtime_document(images, source, host_tools)
    runtime_sha256 = hashlib.sha256(
        faults._canonical_json(runtime_document) + b"\n"
    ).hexdigest()
    runtime_tool_metrics: dict[str, str] = {}
    if host_tools is not None:
        for tool_name, metric_prefix in (
            ("python", "host_python"),
            ("docker-cli", "host_docker"),
            ("docker-compose", "host_compose"),
        ):
            _, sha256, version = host_tools[tool_name]
            runtime_tool_metrics[f"{metric_prefix}_sha256"] = sha256
            runtime_tool_metrics[f"{metric_prefix}_version"] = version
    commands: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    results: dict[str, object] = {}
    for test_id, binding in faults.RAW_EVIDENCE_BINDINGS.items():
        if test_id == "V04-SCOPE-002":
            metrics: dict[str, object] = {
                **_runtime_metrics(test_id),
                **runtime_tool_metrics,
                "runtime_input_sha256": runtime_sha256,
            }
        elif test_id in faults.RUNTIME_CAPTURE_IDS:
            metrics = {
                **_runtime_metrics(test_id),
                **runtime_tool_metrics,
                "runtime_input_sha256": runtime_sha256,
            }
        elif test_id == "V04-SEC-003":
            metrics = _sec003_metrics(source)
        else:
            metrics = {"probe_count": 1}
        machine_output = {
            "test_id": test_id,
            "source_fingerprint_sha256": source,
            "assertions": [{"id": "source-bound-probe-passed", "passed": True}],
            "metrics": metrics,
        }
        canonical = faults._canonical_json(machine_output) + b"\n"
        payloads = (
            (binding.stdout_artifact_id, "command-stdout", canonical),
            (binding.stderr_artifact_id, "command-stderr", b""),
            (binding.evidence_artifact_id, "test-evidence", canonical),
        )
        artifact_ids: list[str] = []
        for artifact_id, kind, data in payloads:
            artifacts.append(faults._artifact_record(artifact_id, kind, data))
            artifact_ids.append(artifact_id)
        commands.append(
            {
                "id": binding.command_id,
                "test_id": test_id,
                "executor": binding.executor,
                "argv": list(binding.argv),
                "exit_code": 0,
                "stdout_artifact_id": binding.stdout_artifact_id,
                "stderr_artifact_id": binding.stderr_artifact_id,
                "evidence_artifact_id": binding.evidence_artifact_id,
                "environment_keys": list(binding.environment_keys),
            }
        )
        results[test_id] = {
            **machine_output,
            "command_ids": [binding.command_id],
            "artifact_ids": artifact_ids,
        }
    report: dict[str, Any] = {
        "schema_version": faults.RAW_REPORT_SCHEMA_VERSION,
        "captured_at": "2026-07-19T21:30:00Z",
        "run_id": "a" * 32,
        "source_fingerprint_sha256": source,
        "complete": True,
        "preliminary": preliminary,
        "source_frozen": not preliminary,
        "images": images,
        "commands": commands,
        "artifacts": artifacts,
        "results": results,
        "runtime_input_sha256": runtime_sha256,
    }
    report["report_binding_sha256"] = faults.raw_report_binding(report)
    return report


def _artifact_payload(report: dict[str, Any], artifact_id: str) -> bytes:
    for test_id, binding in faults.RAW_EVIDENCE_BINDINGS.items():
        if artifact_id == binding.stderr_artifact_id:
            return b""
        if artifact_id in {
            binding.stdout_artifact_id,
            binding.evidence_artifact_id,
        }:
            result = report["results"][test_id]
            machine_output = {
                key: result[key]
                for key in (
                    "test_id",
                    "source_fingerprint_sha256",
                    "assertions",
                    "metrics",
                )
            }
            return faults._canonical_json(machine_output) + b"\n"
    raise AssertionError(f"unknown artifact id: {artifact_id}")


def write_report(tmp_path: Path, report: dict[str, Any]) -> Path:
    for artifact in report["artifacts"]:
        target = tmp_path / Path(artifact["path"]).name
        target.write_bytes(_artifact_payload(report, artifact["id"]))
    path = tmp_path / "fault-gate-raw.json"
    path.write_bytes(faults._canonical_json(report) + b"\n")
    return path


def observed_images(report: dict[str, Any], **replacements: str) -> dict[str, str]:
    return {**report["images"], **replacements}


def test_complete_raw_report_validates_and_extracts_every_assigned_id(
    tmp_path: Path,
) -> None:
    report = valid_report()
    loaded = faults.load_raw_report(
        write_report(tmp_path, report),
        ROOT,
        artifact_directory=tmp_path,
        observed_image_ids=observed_images(report),
        runtime_input_path=write_runtime_input(tmp_path, report["images"]),
    )

    assert set(loaded["validated_results"]) == faults.ASSIGNED_IDS
    assert len(loaded["validated_results"]) == 18
    assert len(loaded["commands"]) == 18
    assert len(loaded["artifacts"]) == 54
    for result in loaded["validated_results"].values():
        assert set(result) == {
            "test_id",
            "source_fingerprint_sha256",
            "assertions",
            "metrics",
        }
    extracted = {
        test_id: faults._extract_raw_result(loaded, test_id)
        for test_id in faults.ASSIGNED_IDS
    }
    assert {
        result["metrics"]["raw_report_sha256"] for result in extracted.values()
    } == {hashlib.sha256((tmp_path / "fault-gate-raw.json").read_bytes()).hexdigest()}
    assert {
        result["metrics"]["raw_report_run_id"] for result in extracted.values()
    } == {report["run_id"]}
    for test_id in faults.RUNTIME_CAPTURE_IDS:
        metrics = extracted[test_id]["metrics"]
        assert metrics["runtime_schema_version"] == faults.RUNTIME_INPUT_SCHEMA_VERSION
        assert metrics["runtime_run_id"] == report["run_id"]
        assert metrics["host_python_path"].endswith(
            "python-3.13.14-embed-amd64/python.exe"
        )


def test_raw_report_rejects_stale_source_even_with_recomputed_binding(
    tmp_path: Path,
) -> None:
    report = valid_report()
    report["source_fingerprint_sha256"] = "0" * 64
    for result in report["results"].values():
        result["source_fingerprint_sha256"] = "0" * 64
    report["report_binding_sha256"] = faults.raw_report_binding(report)

    with pytest.raises(faults.ProbeError, match="stale source fingerprint"):
        faults.load_raw_report(
            write_report(tmp_path, report),
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


def test_raw_report_rejects_incomplete_result_set_before_extraction(
    tmp_path: Path,
) -> None:
    report = valid_report()
    path = write_report(tmp_path, report)
    del report["results"]["V04-API-003"]
    report["report_binding_sha256"] = faults.raw_report_binding(report)
    path.write_bytes(faults._canonical_json(report) + b"\n")

    with pytest.raises(faults.ProbeError, match="exactly all assigned IDs"):
        faults.load_raw_report(
            path,
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


@pytest.mark.parametrize(
    "unsafe_argv",
    (
        ["--password=must-not-be-recorded"],
        ["--password", "must-not-be-recorded"],
    ),
)
def test_raw_report_rejects_secret_bearing_recorded_argv(
    tmp_path: Path, unsafe_argv: list[str]
) -> None:
    report = valid_report()
    report["commands"][0]["argv"].extend(unsafe_argv)
    report["report_binding_sha256"] = faults.raw_report_binding(report)

    with pytest.raises(faults.ProbeError, match="command argv is unsafe"):
        faults.load_raw_report(
            write_report(tmp_path, report),
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


def test_raw_report_rejects_artifact_tamper(tmp_path: Path) -> None:
    report = valid_report()
    path = write_report(tmp_path, report)
    first = tmp_path / Path(report["artifacts"][0]["path"]).name
    first.write_bytes(first.read_bytes() + b"tampered")

    with pytest.raises(faults.ProbeError, match="artifact size differs"):
        faults.load_raw_report(
            path,
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


def test_raw_report_rejects_mutation_without_matching_binding(tmp_path: Path) -> None:
    report = valid_report()
    report["results"]["V04-ISO-004"]["metrics"]["probe_count"] = 2

    with pytest.raises(faults.ProbeError, match="binding digest differs"):
        faults.load_raw_report(
            write_report(tmp_path, report),
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


def test_raw_report_rejects_nonqualification_image_substitution(
    tmp_path: Path,
) -> None:
    report = valid_report()
    with pytest.raises(faults.ProbeError, match="independent observations"):
        faults.load_raw_report(
            write_report(tmp_path, report),
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(
                report, backend="sha256:" + "f" * 64
            ),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


def test_raw_report_rejects_preliminary_capture_by_default(tmp_path: Path) -> None:
    report = valid_report(preliminary=True)
    with pytest.raises(faults.ProbeError, match="not a frozen-source final capture"):
        faults.load_raw_report(
            write_report(tmp_path, report),
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
        )


def test_explicit_preliminary_read_validates_and_extracts_all_assigned_ids(
    tmp_path: Path,
) -> None:
    report = valid_report(preliminary=True)
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    path = write_report(raw_root, report)
    loaded = faults.load_raw_report(
        path,
        ROOT,
        artifact_directory=raw_root,
        observed_image_ids=observed_images(report),
        runtime_input_path=write_runtime_input(tmp_path / "runtime", report["images"]),
        expected_preliminary=True,
        require_exact_artifact_directory=True,
    )

    assert loaded["preliminary"] is True
    assert loaded["source_frozen"] is False
    extracted = {
        test_id: faults._extract_raw_result(loaded, test_id)
        for test_id in faults.ASSIGNED_IDS
    }
    assert set(extracted) == faults.ASSIGNED_IDS
    assert len(extracted) == 18
    assert all(
        result["metrics"]["raw_report_preliminary"] is True
        and result["metrics"]["raw_report_source_frozen"] is False
        for result in extracted.values()
    )


@pytest.mark.parametrize(
    ("preliminary", "source_frozen", "expected_preliminary", "message"),
    (
        (False, True, True, "not an unfrozen-source preliminary capture"),
        (True, True, True, "not an unfrozen-source preliminary capture"),
        (False, False, False, "not a frozen-source final capture"),
    ),
)
def test_raw_report_read_requires_the_exact_selected_disposition(
    tmp_path: Path,
    preliminary: bool,
    source_frozen: bool,
    expected_preliminary: bool,
    message: str,
) -> None:
    report = valid_report()
    report["preliminary"] = preliminary
    report["source_frozen"] = source_frozen
    report["report_binding_sha256"] = faults.raw_report_binding(report)

    with pytest.raises(faults.ProbeError, match=message):
        faults.load_raw_report(
            write_report(tmp_path, report),
            ROOT,
            artifact_directory=tmp_path,
            observed_image_ids=observed_images(report),
            runtime_input_path=write_runtime_input(tmp_path, report["images"]),
            expected_preliminary=expected_preliminary,
        )


def _raw_cli_arguments(*mode_arguments: str) -> list[str]:
    observed = _observed_args()
    images = dict(item.split("=", 1) for item in observed)
    arguments = [
        "qualify_faults_v04.py",
        "--qualification-image-id",
        images["qualification"],
        "--runtime-input",
        "runtime-fault-evidence.json",
    ]
    for item in observed:
        arguments.extend(("--observed-image", item))
    arguments.extend(mode_arguments)
    return arguments


def test_raw_capture_cli_requires_an_explicit_disposition(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        _raw_cli_arguments(
            "--capture-raw-report",
            "fault-gate-raw.json",
            "--prepublish-root",
            "/prepublish",
        ),
    )

    assert faults.main() == 1
    assert (
        "requires exactly one of --final or --preliminary"
        in capsys.readouterr().err
    )


@pytest.mark.parametrize(
    ("switches", "expected"),
    (((), False), (("--preliminary",), True)),
)
def test_raw_read_cli_defaults_final_and_requires_opt_in_for_preliminary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    switches: tuple[str, ...],
    expected: bool,
) -> None:
    observed: dict[str, bool] = {}

    def fake_load_raw_report(*_args: object, **kwargs: object) -> dict[str, Any]:
        observed["expected_preliminary"] = bool(kwargs["expected_preliminary"])
        return {
            "schema_version": faults.RAW_REPORT_SCHEMA_VERSION,
            "source_fingerprint_sha256": current_source(),
            "report_binding_sha256": "a" * 64,
            "preliminary": expected,
            "source_frozen": not expected,
            "validated_results": {test_id: {} for test_id in faults.ASSIGNED_IDS},
            "commands": [{} for _ in faults.ASSIGNED_IDS],
            "artifacts": [{} for _ in range(len(faults.ASSIGNED_IDS) * 3)],
            "images": _fixture_images(),
        }

    monkeypatch.setattr(faults, "load_raw_report", fake_load_raw_report)
    monkeypatch.setattr(
        sys,
        "argv",
        _raw_cli_arguments(
            "--validate-raw-report",
            "fault-gate-raw.json",
            "--artifact-directory",
            ".",
            *switches,
        ),
    )

    assert faults.main() == 0
    assert observed == {"expected_preliminary": expected}
    output = json.loads(capsys.readouterr().out)
    assert output["preliminary"] is expected
    assert output["source_frozen"] is (not expected)


def _observed_args() -> list[str]:
    return [
        f"{role}=sha256:{index:x}" + f"{index:x}" * 63
        for index, role in enumerate(sorted(faults.RAW_REPORT_IMAGE_ROLES), start=1)
    ]


def test_observed_image_parser_requires_exact_distinct_role_map() -> None:
    parsed = faults.parse_observed_image_ids(_observed_args())
    assert set(parsed) == faults.RAW_REPORT_IMAGE_ROLES
    with pytest.raises(faults.ProbeError, match="incomplete"):
        faults.parse_observed_image_ids(_observed_args()[:-1])
    with pytest.raises(faults.ProbeError, match="duplicated"):
        faults.parse_observed_image_ids(_observed_args() + [_observed_args()[0]])
    with pytest.raises(faults.ProbeError, match="unknown or invalid role"):
        faults.parse_observed_image_ids(
            _observed_args()[:-1] + ["unknown=sha256:" + "f" * 64]
        )
    aliased = _observed_args()
    aliased[1] = aliased[1].split("=", 1)[0] + "=" + aliased[0].split("=", 1)[1]
    with pytest.raises(faults.ProbeError, match="distinct across roles"):
        faults.parse_observed_image_ids(aliased)


def test_runtime_input_validates_exact_generated_eight_result_corpus(
    tmp_path: Path,
) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)

    runtime = faults.load_runtime_input(
        path,
        expected_source=current_source(),
        expected_images=images,
    )

    assert set(runtime.results) == faults.RUNTIME_CAPTURE_IDS
    assert len(runtime.results) == 8
    assert runtime.run_id == "a" * 32
    assert runtime.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("test_id", sorted(faults.RUNTIME_CAPTURE_IDS))
def test_runtime_probe_consumes_generated_live_payload_and_focused_supplement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    test_id: str,
) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)
    monkeypatch.setenv("SPELL_FAULT_RUN_ID", "a" * 32)
    monkeypatch.setenv(
        "SPELL_FAULT_IMAGE_BINDING_SHA256",
        faults.runtime_image_binding_sha256(images),
    )
    monkeypatch.setattr(
        faults,
        "_run_pytest",
        lambda nodes, root: {
            "pytest_passed_count": len(nodes),
            "pytest_stdout_sha256": "b" * 64,
            "pytest_stderr_sha256": "c" * 64,
        },
    )

    result = faults._probe_runtime_bound(test_id, ROOT, path)

    for key, value in _runtime_metrics(test_id).items():
        assert result["metrics"][key] == value
    assert result["metrics"]["runtime_input_sha256"] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    assert result["metrics"]["pytest_passed_count"] == len(
        faults.FAULT_TEST_NODES[test_id]
    )


def test_runtime_input_rejects_detached_result_evidence(tmp_path: Path) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)
    document = read_runtime_document(path)
    document["results"]["V04-SCOPE-002"]["metrics"][
        "health_baseline_observation_count"
    ] = 2
    rewrite_runtime_document(path, document)

    with pytest.raises(faults.ProbeError, match="canonical command evidence"):
        faults.load_runtime_input(
            path, expected_source=current_source(), expected_images=images
        )


def test_runtime_input_rejects_orphan_artifact_tree_entry(tmp_path: Path) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)
    orphan = path.parent / "artifacts/orphan.txt"
    orphan.write_text("orphan", encoding="utf-8")
    orphan.chmod(0o444)

    with pytest.raises(faults.ProbeError, match="artifact tree differs"):
        faults.load_runtime_input(
            path, expected_source=current_source(), expected_images=images
        )


def test_runtime_input_rejects_extra_root_entry(tmp_path: Path) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)
    orphan = path.parent / "orphan.txt"
    orphan.write_text("orphan", encoding="utf-8")
    orphan.chmod(0o444)

    with pytest.raises(faults.ProbeError, match="root differs from the exact corpus"):
        faults.load_runtime_input(
            path, expected_source=current_source(), expected_images=images
        )


def test_runtime_input_rejects_inconsistent_command_timestamps(tmp_path: Path) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)
    document = read_runtime_document(path)
    document["commands"][0]["finished_at"] = "2026-07-19T21:01:00Z"
    rewrite_runtime_document(path, document)

    with pytest.raises(faults.ProbeError, match="timestamps are inconsistent"):
        faults.load_runtime_input(
            path, expected_source=current_source(), expected_images=images
        )


def test_runtime_input_rejects_locked_python_substitution(tmp_path: Path) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)

    def substitute_python(lock: dict[str, Any]) -> None:
        python = next(item for item in lock["tools"] if item["name"] == "python")
        python["sha256"] = "0" * 64

    lock_root = write_release_toolchain_lock(tmp_path, substitute_python)
    with pytest.raises(faults.ProbeError, match="host Python differs"):
        faults.load_runtime_input(
            path,
            expected_source=current_source(),
            expected_images=images,
            release_toolchain_root=lock_root,
        )


def test_runtime_input_rejects_locked_docker_compose_swap(tmp_path: Path) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)

    def swap_tools(lock: dict[str, Any]) -> None:
        tools = {item["name"]: item for item in lock["tools"]}
        docker = tools["docker-cli"]
        compose = tools["docker-compose"]
        docker["relative_path"], compose["relative_path"] = (
            compose["relative_path"],
            docker["relative_path"],
        )
        docker["sha256"], compose["sha256"] = compose["sha256"], docker["sha256"]

    lock_root = write_release_toolchain_lock(tmp_path, swap_tools)
    with pytest.raises(faults.ProbeError, match="host Docker path differs"):
        faults.load_runtime_input(
            path,
            expected_source=current_source(),
            expected_images=images,
            release_toolchain_root=lock_root,
        )


def test_runtime_input_independently_rejects_secret_bearing_artifact(
    tmp_path: Path,
) -> None:
    images = _fixture_images()
    path = write_runtime_input(tmp_path, images)
    document = read_runtime_document(path)
    artifact = next(
        item for item in document["artifacts"] if item["kind"] == "command-stderr"
    )
    target = path.parent / artifact["path"]
    secret_bytes = b"Authorization: Bearer must-not-leak\n"
    target.chmod(0o644)
    target.write_bytes(secret_bytes)
    target.chmod(0o444)
    artifact["bytes"] = len(secret_bytes)
    artifact["sha256"] = hashlib.sha256(secret_bytes).hexdigest()
    rewrite_runtime_document(path, document)

    with pytest.raises(faults.ProbeError, match="credential-like material"):
        faults.load_runtime_input(
            path, expected_source=current_source(), expected_images=images
        )


def test_runtime_readonly_check_accepts_readonly_mount_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "mount-owned.json"
    path.write_text("{}", encoding="utf-8")

    class ReadonlyMount:
        f_flag = getattr(faults.os, "ST_RDONLY", 1)

    monkeypatch.setattr(faults.os, "statvfs", lambda _: ReadonlyMount(), raising=False)
    faults._runtime_readonly_file(path, "mount-owned fixture")


def test_raw_child_environment_is_minimal_and_per_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@ambient/db")
    monkeypatch.setenv("PYTHONPATH", "ambient-python-path")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy")
    monkeypatch.setenv("SPELL_MIGRATION_TEST_DATABASE_URL", "postgresql://migration")
    monkeypatch.setenv("SPELL_FAULT_RUN_ID", "wrong-ambient-run")
    monkeypatch.setenv("SPELL_FAULT_IMAGE_BINDING_SHA256", "0" * 64)
    runtime_environment = {
        "DATABASE_URL": faults.CANONICAL_WRAPPER_DATABASE_URL,
        "SPELL_FAULT_RUN_ID": "a" * 32,
        "SPELL_FAULT_IMAGE_BINDING_SHA256": "b" * 64,
    }

    unbound = faults._raw_child_environment(
        faults.RAW_EVIDENCE_BINDINGS["V04-API-002"], runtime_environment
    )
    assert unbound["DATABASE_URL"] == "sqlite:///:memory:"
    assert "postgresql://user:password@ambient/db" not in unbound.values()
    assert "PYTHONPATH" not in unbound
    assert "HTTPS_PROXY" not in unbound
    assert not any(key.startswith("SPELL_") for key in unbound)

    migration = faults._raw_child_environment(
        faults.RAW_EVIDENCE_BINDINGS["V04-MIG-002"], runtime_environment
    )
    assert migration["DATABASE_URL"] == "sqlite:///:memory:"
    assert migration["SPELL_MIGRATION_TEST_DATABASE_URL"] == "postgresql://migration"
    assert "SPELL_FAULT_RUN_ID" not in migration

    live = faults._raw_child_environment(
        faults.RAW_EVIDENCE_BINDINGS["V04-SCOPE-002"], runtime_environment
    )
    assert {
        key: live[key]
        for key in (
            "SPELL_FAULT_RUN_ID",
            "SPELL_FAULT_IMAGE_BINDING_SHA256",
        )
    } == {
        "SPELL_FAULT_RUN_ID": "a" * 32,
        "SPELL_FAULT_IMAGE_BINDING_SHA256": "b" * 64,
    }
    assert live["DATABASE_URL"] == "sqlite:///:memory:"
    assert "SPELL_MIGRATION_TEST_DATABASE_URL" not in live


def write_prepublish_corpus(tmp_path: Path) -> Path:
    root = tmp_path / "prepublish"
    payloads = {
        "frontend_bundle/app.js": b"bundle",
        "browser_storage/storage.json": b"{}",
        "screenshots/desktop.png": b"png",
        "runtime_captures/runtime.json": b"{}",
        "sboms/backend.cdx.json": b"{}",
        "sboms/driver.cdx.json": b"{}",
        "sboms/frontend.cdx.json": b"{}",
        "sboms/proxy.cdx.json": b"{}",
    }
    for relative, data in payloads.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def product_metrics(source: str) -> dict[str, object]:
    return {
        key: value
        for key, value in _sec003_metrics(source).items()
        if key.startswith("product_") or key == "source_fingerprint_sha256"
    }


def test_sec003_scans_exact_prepublish_categories_and_product_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepublish = write_prepublish_corpus(tmp_path)
    source = current_source()
    expected_canary = f"spell-v04-service-secret-{source}".encode("ascii")

    def inspect(root: Path, *, forbidden_marker: bytes | None = None):
        assert root == ROOT
        assert forbidden_marker == expected_canary
        return product_metrics(source)

    monkeypatch.setattr(faults, "inspect_product_package_inputs_v04", inspect)
    result = faults._probe_sec_003(ROOT, prepublish)
    metrics = result["metrics"]
    assert set(metrics["category_file_counts"]) == faults.SEC003_PREPUBLISH_CATEGORIES
    assert metrics["category_file_counts"]["sboms"] == 4
    assert metrics["scanned_file_count"] == 10
    assert metrics["scanned_byte_count"] == (
        metrics["category_scanned_byte_count"]
        + metrics["product_scanned_byte_count"]
    )
    faults.SEMANTIC_VALIDATORS["V04-SEC-003"](
        metrics, "V04-SEC-003.metrics", source
    )


def test_sec003_rejects_extra_category_wrong_sbom_and_canary_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = current_source()
    monkeypatch.setattr(
        faults,
        "inspect_product_package_inputs_v04",
        lambda *_args, **_kwargs: product_metrics(source),
    )
    extra = write_prepublish_corpus(tmp_path / "extra")
    (extra / "reports").mkdir()
    with pytest.raises(faults.ProbeError, match="category set differs"):
        faults._probe_sec_003(ROOT, extra)

    wrong_sbom = write_prepublish_corpus(tmp_path / "sbom")
    (wrong_sbom / "sboms/backend.cdx.json").rename(
        wrong_sbom / "sboms/unexpected.cdx.json"
    )
    with pytest.raises(faults.ProbeError, match="exact four named SBOMs"):
        faults._probe_sec_003(ROOT, wrong_sbom)

    leaked = write_prepublish_corpus(tmp_path / "leak")
    canary = f"spell-v04-service-secret-{source}".encode("ascii")
    (leaked / "runtime_captures/runtime.json").write_bytes(canary)
    with pytest.raises(faults.ProbeError, match="runtime_captures/runtime.json"):
        faults._probe_sec_003(ROOT, leaked)


def test_sec003_rejects_symlinked_corpus_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepublish = write_prepublish_corpus(tmp_path)
    target = prepublish / "frontend_bundle/app.js"
    link = prepublish / "frontend_bundle/linked.js"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("the test filesystem does not permit symbolic links")
    source = current_source()
    monkeypatch.setattr(
        faults,
        "inspect_product_package_inputs_v04",
        lambda *_args, **_kwargs: product_metrics(source),
    )
    with pytest.raises(faults.ProbeError, match="contains a symlink"):
        faults._probe_sec_003(ROOT, prepublish)


def test_powershell_collector_produces_validates_and_extracts_strict_v2() -> None:
    collector = (ROOT / "scripts/collect_fault_gate_v04.ps1").read_text(
        encoding="utf-8"
    )

    assert "V04-API-002" in collector
    assert "V04-API-003" in collector
    assert "CaptureRawReport" in collector
    assert "[switch]$Preliminary" in collector
    assert "--capture-raw-report" in collector
    assert "--validate-raw-report" in collector
    assert 'if ($Preliminary) { $arguments += "--preliminary" }' in collector
    assert '$captureArguments += "--preliminary"' in collector
    assert '$captureArguments += "--final"' in collector
    assert "--observed-image" in collector
    assert "--prepublish-root" in collector
    assert "--runtime-input" in collector
    assert "dst=/runtime-input,readonly" in collector
    assert "runtime fault input must be the exact SEC003 runtime_captures corpus" in collector
    assert "Test-PathOverlap" in collector
    assert "Assert-NoReparseTraversal" in collector
    assert "fresh fault-gate run directory already exists" in collector
    assert "network create --internal" in collector
    assert "POSTGRES_HOST_AUTH_METHOD=trust" in collector
    assert "SPELL_MIGRATION_TEST_DATABASE_URL" in collector
    assert "container ls --all" in collector
    assert "network ls --filter" in collector
    assert "cleanup verification failed" in collector
    assert "publish_fault_provenance_v04.py" in collector
    assert "artifacts/v0.4/provenance/fault-gate" in collector
    assert "ReplaceProvenance" in collector
    assert "preliminary fault capture must not replace canonical provenance" in collector
    assert "if (-not $Preliminary)" in collector
    assert "if ($Preliminary) {\n    return\n  }\n  $publisherArguments" in collector
    assert '"--replace"' in collector
    for role in faults.RAW_REPORT_IMAGE_ROLES:
        assert role in collector
    assert "docker build" not in collector
    assert "docker compose" not in collector


def test_sec003_canonical_command_binds_read_only_prepublish_location() -> None:
    binding = faults.RAW_EVIDENCE_BINDINGS["V04-SEC-003"]
    assert binding.argv[-2:] == ("--prepublish-root", "/prepublish")
    source = (ROOT / "scripts/qualify_faults_v04.py").read_text(encoding="utf-8")
    assert "actual_argv = [sys.executable, *evidence.argv[1:]]" in source


def test_runtime_commands_bind_manifest_and_only_named_identity_environment() -> None:
    assert faults.RUNTIME_COMMAND_ENVIRONMENT_KEYS["V04-SEC-002"] == (
        "DATABASE_URL",
        "SPELL_RUNTIME_CONTEXT_FILE",
        "SPELL_RUNTIME_OPERATOR_TOKEN",
    )
    for test_id in faults.RUNTIME_CAPTURE_IDS:
        binding = faults.RAW_EVIDENCE_BINDINGS[test_id]
        assert binding.argv[-2:] == (
            "--runtime-input",
            "/runtime-input/runtime-fault-evidence.json",
        )
        assert binding.environment_keys == (
            "DATABASE_URL",
            "SPELL_FAULT_RUN_ID",
            "SPELL_FAULT_IMAGE_BINDING_SHA256",
        )
    assert all(
        binding.environment_keys[0] == "DATABASE_URL"
        for binding in faults.RAW_EVIDENCE_BINDINGS.values()
    )
