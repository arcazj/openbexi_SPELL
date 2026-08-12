from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from scripts import (
    build_reproducible_v04,
    supply_provenance_v04,
    validate_release_evidence_v04,
)
from scripts.source_fingerprint_v04 import (
    FINGERPRINT_FILES,
    FINGERPRINT_TREES,
    source_fingerprint_v04,
)


class V04ReleaseFrameworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for tree in FINGERPRINT_TREES:
            path = self.root / tree
            path.mkdir(parents=True)
            (path / "fingerprint-input.txt").write_text(
                f"v0.4 source tree: {tree}\n", encoding="utf-8"
            )
        for name in build_reproducible_v04.INCLUDE_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"v0.4 root input: {name}\n", encoding="utf-8")

        required_assets = {
            "contracts/spell/driver/v1/driver.proto": b'syntax = "proto3";\n',
            "contracts/spell_driver_v1.pb": b"deterministic descriptor\0",
            "spell/driver/v1/driver_pb2.py": b"# generated Python\n",
            "spell/driver/v1/driver_pb2.pyi": b"# generated typing\n",
            "spell/driver/v1/driver_pb2_grpc.py": b"# generated gRPC\n",
        }
        for name, content in required_assets.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        toolchain_lock = self.root / "scripts/release-toolchain-v04.json"
        toolchain_lock.write_bytes(
            (
                Path(__file__).resolve().parents[2]
                / "scripts/release-toolchain-v04.json"
            ).read_bytes()
        )
        for name in (
            "frontend/package-lock.json",
            "frontend/playwright.config.ts",
        ):
            path = self.root / name
            path.write_text(f"browser configuration: {name}\n", encoding="utf-8")
        (self.root / "frontend/product.png").write_bytes(b"product image")

        (self.root / "artifacts/v0.3").mkdir(parents=True)
        (self.root / "artifacts/v0.3/qualification.json").write_text(
            '{"product_version":"0.3.0"}\n', encoding="utf-8"
        )
        (self.root / "SPELL-DOCUMENTATION").mkdir()
        (self.root / "SPELL-DOCUMENTATION/legacy-manual.pdf").write_bytes(b"pdf")
        (self.root / "SPELL-COTS-legacy.zip").write_bytes(b"legacy archive")

        self.browser_binding = self._write_browser_provenance()
        self._write_gate_reports()
        self._write_sboms()
        self._write_supply_provenance()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_browser_provenance(self) -> dict[str, object]:
        from scripts import qualify_browser_v04 as browser
        from scripts.tests import test_qualify_browser_v04 as browser_fixtures

        lock_path = self.root / "scripts/release-toolchain-v04.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        program_files = self.root / "Program Files"
        local_app_data = self.root / "LocalAppData"
        bases = {"ProgramFiles": program_files, "LocalAppData": local_app_data}
        required = {
            "docker-cli": ("docker_cli", b"fixture-docker-cli"),
            "docker-compose": ("docker_compose", b"fixture-docker-compose"),
            "python": ("python", b"fixture-python"),
        }
        executable_paths: dict[str, Path] = {}
        for entry in lock["tools"]:
            selected = required.get(entry["name"])
            if selected is None:
                continue
            key, data = selected
            path = bases[entry["base_directory"]].joinpath(
                *entry["relative_path"].split("/")
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            executable_paths[key] = path
        lock_path.write_text(json.dumps(lock, sort_keys=True) + "\n", encoding="utf-8")
        self._browser_environment = mock.patch.dict(
            "os.environ",
            {
                "ProgramFiles": str(program_files),
                "LocalAppData": str(local_app_data),
            },
            clear=False,
        )
        self._browser_environment.start()
        self.addCleanup(self._browser_environment.stop)

        source = source_fingerprint_v04(self.root)
        capture = self.root / "artifacts/v0.4/browser"
        for project in ("desktop", "mobile"):
            browser_fixtures._write_observation(self.root, project, source)
            browser_fixtures._write_fault_observation(self.root, project, source)
            screenshot = (
                self.root / f"artifacts/v0.4/driver-projection-{project}.png"
            )
            (capture / screenshot.name).write_bytes(screenshot.read_bytes())
            screenshot.unlink()
        return browser.publish_browser_provenance_v04(
            self.root,
            capture,
            run_id=browser_fixtures.RUN_ID,
            started_at_utc="2026-07-19T12:00:00.000Z",
            finished_at_utc="2026-07-19T12:01:00.000Z",
            executable_paths=executable_paths,
            replace=False,
        )

    def _metrics(self, test_id: str, fingerprint: str) -> dict[str, object]:
        metrics: dict[str, object] = {}
        if test_id == "V04-SCOPE-001":
            metrics = {"rpc_count": 9, "future_service_count": 0, "untyped_payload_count": 0}
        elif test_id == "V04-SCOPE-002":
            metrics = {
                "accepted_telemetry_execution_count": 1,
                "telemetry_event_count": 1,
                "health_baseline_observation_count": 1,
                "execution_correlated_rpc_delta": 0,
                "context_delta": 0,
                "binding_delta": 0,
                "operation_delta": 0,
                "journal_delta": 0,
            }
        elif test_id == "V04-MIG-004":
            metrics = {
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
            }
        elif test_id == "V04-SEC-002":
            metrics = {
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
            }
        elif test_id == "V04-SEC-004":
            metrics = {
                "reflection_status": "UNIMPLEMENTED",
                "direct_administration_status": "UNIMPLEMENTED",
                "jwt_without_mtls_status": "UNAVAILABLE",
                "unauthorized_metadata_status": "FAILED_PRECONDITION",
                "proxy_route_http_status": 404,
                "safe_audit_reason_count": 4,
                "unsafe_echo_count": 0,
            }
        elif test_id == "V04-BOUND-002":
            metrics = {
                "nominal_captured_frame_count": 1,
                "fault_captured_frame_count": 1,
                "nominal_endpoint_tuple_count": 1,
                "fault_endpoint_tuple_count": 1,
                "nominal_unapproved_endpoint_count": 0,
                "fault_unapproved_endpoint_count": 0,
                "connection_log_unapproved_endpoint_count": 0,
                "nominal_capture_truncated": False,
                "fault_capture_truncated": False,
            }
        elif test_id == "V04-ISO-003":
            metrics = {
                "injection_count": 2,
                "unchanged_non_driver_container_observation_count": 6,
                "non_driver_liveness_failure_count": 0,
                "worker_progress_failure_count": 0,
                "degraded_or_stale_observation_count": 2,
                "recovery_count": 2,
                "recovery_failure_count": 0,
            }
        elif test_id == "V04-ISO-004":
            metrics = {
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
            }
        elif test_id == "V04-REC-005":
            metrics = {
                "phase_count": 3,
                "operation_case_count": 3,
                "duplicate_effect_count": 0,
                "resend_count": 0,
                "unreconstructable_count": 0,
                "audit_outbox_mismatch_count": 0,
                "commit_publish_violation_count": 0,
                "final_disposition_count": 3,
            }
        elif test_id == "V04-SEC-003":
            package_sha256 = build_reproducible_v04.product_package_sha256_v04(
                self.root
            )
            metrics = {
                "canary_location_count": 5,
                "canary_leak_count": 0,
                "canary_sha256": hashlib.sha256(
                    f"spell-v04-service-secret-{fingerprint}".encode("ascii")
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
                "source_fingerprint_sha256": fingerprint,
                "product_input_file_count": 1,
                "product_package_file_count": 1,
                "product_scanned_file_count": 2,
                "product_input_byte_count": 10,
                "product_package_member_byte_count": 10,
                "product_scanned_byte_count": 20,
                "product_package_byte_count": 20,
                "product_package_sha256": package_sha256,
                "product_secret_file_count": 0,
                "product_pdf_file_count": 0,
                "product_manual_text_file_count": 0,
                "product_legacy_archive_count": 0,
                "product_runtime_journal_count": 0,
                "product_forbidden_marker_count": 0,
            }
        elif test_id == "V04-UI-003":
            metrics = {
                "desktop_viewport_count": 1,
                "mobile_viewport_count": 1,
                "axe_serious_finding_count": 0,
                "axe_critical_finding_count": 0,
                "keyboard_failure_count": 0,
                "overflow_failure_count": 0,
            }
        elif test_id == "V04-REG-001":
            metrics = {
                "v03_suite_count": 8,
                "v03_suite_failure_count": 0,
                "v03_changed_default_count": 0,
            }
        elif test_id == "V04-PERF-001":
            metrics = {
                "sample_count": 1_000,
                "duration_seconds": 10.0,
                "achieved_rate_per_second": 100.0,
                "p95_ms": 49.0,
                "max_ms": 240.0,
                "error_count": 0,
            }
        elif test_id == "V04-PERF-002":
            metrics = {
                "operation_count": 1_000,
                "duration_seconds": 50.0,
                "achieved_rate_per_second": 20.0,
                "acceptance_p95_ms": 249.0,
                "terminal_p95_ms": 499.0,
                "duplicate_effect_count": 0,
                "stuck_operation_count": 0,
                "error_count": 0,
            }
        elif test_id == "V04-PERF-003":
            metrics = {
                "cancellation_count": 100,
                "cancel_p95_ms": 499.0,
                "cancel_max_ms": 999.0,
                "restart_count": 25,
                "readiness_max_ms": 4_999.0,
                "reconciliation_max_ms": 4_999.0,
                "target_certainty_change_count": 0,
                "duplicate_effect_count": 0,
                "stuck_operation_count": 0,
                "error_count": 0,
            }
        elif test_id == "V04-PERF-004":
            metrics = {
                "operation_count": 12_000,
                "duration_seconds": 600.0,
                "achieved_rate_per_second": 20.0,
                "loss_count": 0,
                "duplicate_effect_count": 0,
                "stuck_operation_count": 0,
                "crash_count": 0,
                "post_warmup_growth_mib": 32.0,
                "post_warmup_slope_mib_per_minute": 2.0,
            }
        elif test_id == "V04-SC-001":
            metrics = {
                "lock_input_count": 4,
                "audit_tool_count": 3,
                "unlocked_input_count": 0,
                "critical_finding_count": 0,
                "high_finding_count": 0,
                "audited_image_count": 4,
                "audited_image_ids": {
                    "backend": "sha256:" + "b" * 64,
                    "driver": "sha256:" + "e" * 64,
                    "frontend": "sha256:" + "d" * 64,
                    "proxy": "sha256:" + "c" * 64,
                },
                "compose_dependency_audited_image_count": 2,
                "compose_dependency_audited_image_ids": {
                    "pki_init": "sha256:" + "a" * 64,
                    "postgres": "sha256:" + "f" * 64,
                },
            }
        elif test_id == "V04-SC-002":
            metrics = {
                "sbom_count": 4,
                "distinct_image_count": 4,
                "image_names": ["backend", "driver", "frontend", "proxy"],
                "schema_validation_count": 4,
                "schema_validator": "cyclonedx-python-lib/11.11.0 JsonStrictValidator",
                "negative_tamper_rejected": True,
            }
        elif test_id == "V04-SC-003":
            metrics = {
                "scanned_file_count": 100,
                "secret_file_count": 0,
                "pdf_file_count": 0,
                "manual_text_file_count": 0,
                "legacy_archive_count": 0,
                "runtime_journal_count": 0,
                "runtime_generator_count": 0,
                "hardening_failure_count": 0,
                "layer_scan_failure_count": 0,
                "scanned_image_count": 6,
                "scanned_layer_count": 24,
                "inspected_image_ids": {
                    "backend": "sha256:" + "b" * 64,
                    "driver": "sha256:" + "e" * 64,
                    "frontend": "sha256:" + "d" * 64,
                    "proxy": "sha256:" + "c" * 64,
                },
                "compose_dependency_inspected_image_count": 2,
                "compose_dependency_inspected_image_ids": {
                    "pki_init": "sha256:" + "a" * 64,
                    "postgres": "sha256:" + "f" * 64,
                },
                "inspection_report_sha256": "9" * 64,
                "product_package_sha256": (
                    build_reproducible_v04.product_package_sha256_v04(self.root)
                ),
            }
        elif test_id == "V04-SC-004":
            package_sha256 = build_reproducible_v04.product_package_sha256_v04(
                self.root
            )
            descriptor_sha256 = "d" * 64
            generation_manifest_sha256 = "f" * 64
            binding = hashlib.sha256(
                (
                    fingerprint
                    + "\0"
                    + descriptor_sha256
                    + "\0"
                    + generation_manifest_sha256
                    + "\0"
                    + package_sha256
                ).encode("ascii")
            ).hexdigest()
            metrics = {
                "generation_build_count": 2,
                "generation_process_count": 2,
                "generation_byte_identical": True,
                "package_build_count": 2,
                "package_process_count": 2,
                "package_byte_identical": True,
                "distinct_build_process_count": 2,
                "generation_source_fingerprint_sha256": fingerprint,
                "package_source_fingerprint_sha256": fingerprint,
                "descriptor_sha256": descriptor_sha256,
                "generation_manifest_sha256": generation_manifest_sha256,
                "generation_evidence_sha256": binding,
                "package_evidence_sha256": binding,
                "package_sha256": package_sha256,
            }
        elif test_id == "V04-SC-005":
            metrics = {
                "artifact_root": "artifacts/v0.4",
                "v03_evidence_file_count": 0,
                "v03_overwrite_count": 0,
                "generated_browser_image_count": 0,
                "product_asset_count": 1,
                "generated_contract_asset_count": 4,
            }
        elif test_id == "V04-SC-006":
            metrics = {
                "lifecycle_engine": "docker-compose-v2",
                "runtime_platform": "linux/amd64",
                "runtime_transition_matrix_executed": True,
                "locked_tool_paths_confirmed": True,
                "platform_profile_count": 1,
                "install_case_count": 15,
                "enable_case_count": 12,
                "disable_case_count": 12,
                "upgrade_case_count": 12,
                "rollback_case_count": 12,
                "uninstall_case_count": 12,
                "terminal_case_count": 10,
                "unsafe_refusal_case_count": 50,
                "runtime_transition_case_count": 60,
                "unique_project_count": 15,
                "exact_image_confirmation_count": 30,
                "docker_command_count": 100,
                "mutating_docker_command_count": 30,
                "failed_case_count": 0,
            }
        if test_id in {"V04-UI-001", "V04-UI-002", "V04-UI-003", "V04-UI-004"}:
            metrics.update(self.browser_binding)
        if test_id in validate_release_evidence_v04.FAULT_RAW_TEST_IDS:
            metrics.update(
                {
                    "raw_report_schema_version": (
                        validate_release_evidence_v04.RAW_REPORT_SCHEMA_VERSION
                    ),
                    "raw_report_run_id": "a" * 32,
                    "raw_report_sha256": "b" * 64,
                    "raw_report_binding_sha256": "c" * 64,
                }
            )
        if test_id in validate_release_evidence_v04.RUNTIME_BOUND_TEST_IDS:
            metrics.update(
                {
                    "runtime_schema_version": (
                        validate_release_evidence_v04.RUNTIME_INPUT_SCHEMA_VERSION
                    ),
                    "runtime_run_id": "a" * 32,
                    "runtime_input_sha256": "e" * 64,
                    "host_powershell_path": (
                        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
                    ),
                    "host_powershell_sha256": "f" * 64,
                    "host_powershell_version": "5.1.22621.2506",
                    "host_python_path": "C:/release-tools/python.exe",
                    "host_python_sha256": "1" * 64,
                    "host_python_version": "3.12.10",
                    "host_docker_path": "C:/Program Files/Docker/docker.exe",
                    "host_docker_sha256": "2" * 64,
                    "host_docker_version": "29.7.2",
                    "host_compose_path": "C:/Program Files/Docker/docker-compose.exe",
                    "host_compose_sha256": "3" * 64,
                    "host_compose_version": "v5.3.1",
                }
            )
        return metrics

    def _test_result(self, test_id: str, fingerprint: str) -> dict[str, object]:
        metrics = self._metrics(test_id, fingerprint)
        evidence_path = (
            self.root
            / validate_release_evidence_v04.TEST_EVIDENCE_DIRECTORY
            / f"{test_id}.json"
        )
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence = {
            "schema_version": validate_release_evidence_v04.TEST_EVIDENCE_SCHEMA_VERSION,
            "product_version": "0.4.0",
            "scope_profile": validate_release_evidence_v04.SCOPE_PROFILE,
            "test_id": test_id,
            "source": {"fingerprint_sha256": fingerprint},
            "started_at": "2026-07-18T12:00:00+00:00",
            "finished_at": "2026-07-18T12:00:01+00:00",
            "executed": True,
            "passed": True,
            "environment": {"runner": "release-framework-test-fixture"},
            "commands": [
                {
                    "argv": ["python", "-m", "unittest", test_id],
                    "return_code": 0,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                }
            ],
            "assertions": [{"id": f"{test_id}-assertion", "passed": True}],
            "metrics": metrics,
        }
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
        )
        return {
            "test_id": test_id,
            "passed": True,
            "evidence_path": evidence_path.relative_to(self.root).as_posix(),
            "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            "assertions": {
                "total": 1,
                "passed": 1,
                "failed": 0,
                "skipped": 0,
                "errors": 0,
            },
            "metrics": metrics,
        }

    def _write_gate_reports(self) -> None:
        fingerprint = source_fingerprint_v04(self.root)
        preserved_supply_metrics: dict[str, dict[str, object]] = {}
        for test_id in supply_provenance_v04.SUPPORTED_TEST_IDS:
            evidence_path = (
                self.root
                / validate_release_evidence_v04.TEST_EVIDENCE_DIRECTORY
                / f"{test_id}.json"
            )
            if not evidence_path.is_file():
                continue
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            metrics = evidence.get("metrics")
            if isinstance(metrics, dict) and "supply_provenance_schema_version" in metrics:
                preserved_supply_metrics[test_id] = metrics
        for gate_id, relative in validate_release_evidence_v04.GATE_REPORTS.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            tests = []
            for test_id in sorted(validate_release_evidence_v04.GATE_TEST_IDS[gate_id]):
                result = self._test_result(test_id, fingerprint)
                preserved = preserved_supply_metrics.get(test_id)
                if preserved is not None:
                    evidence_path = self.root / result["evidence_path"]
                    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                    evidence["metrics"] = preserved
                    evidence_path.write_text(
                        json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
                    )
                    result["metrics"] = preserved
                    result["evidence_sha256"] = hashlib.sha256(
                        evidence_path.read_bytes()
                    ).hexdigest()
                tests.append(result)
            report = {
                "schema_version": validate_release_evidence_v04.EVIDENCE_SCHEMA_VERSION,
                "product_version": "0.4.0",
                "scope_profile": validate_release_evidence_v04.SCOPE_PROFILE,
                "gate_id": gate_id,
                "source": {"fingerprint_sha256": fingerprint},
                "overall_pass": True,
                "acceptance_complete": False,
                "waivers": [],
                "open_findings": {"critical": 0, "high": 0},
                "tests": tests,
            }
            path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

    def _write_sboms(
        self,
        *,
        fingerprint: str | None = None,
        image_ids: dict[str, str] | None = None,
    ) -> None:
        fingerprint = fingerprint or source_fingerprint_v04(self.root)
        image_ids = image_ids or {}
        directory = self.root / validate_release_evidence_v04.SBOM_DIRECTORY
        directory.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []
        for index, name in enumerate(validate_release_evidence_v04.SBOM_FILES):
            image_id = image_ids.get(name, "sha256:" + chr(ord("b") + index) * 64)
            inventory = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "container",
                        "name": validate_release_evidence_v04.SBOM_SUBJECTS[name],
                        "version": image_id,
                    },
                    "properties": [
                        {
                            "name": validate_release_evidence_v04.SBOM_SOURCE_FINGERPRINT_PROPERTY,
                            "value": fingerprint,
                        },
                        {
                            "name": validate_release_evidence_v04.SBOM_IMAGE_ID_PROPERTY,
                            "value": image_id,
                        },
                    ],
                },
                "components": [
                    {
                        "type": "library",
                        "name": component,
                        "licenses": [{"license": {"id": "Apache-2.0"}}],
                    }
                    for component in sorted(
                        validate_release_evidence_v04.SBOM_REQUIRED_COMPONENTS[name]
                    )
                ],
            }
            path = directory / name
            path.write_text(json.dumps(inventory, sort_keys=True) + "\n", encoding="utf-8")
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
        (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")

    def _read_report(self, gate_id: str) -> tuple[Path, dict[str, object]]:
        path = self.root / validate_release_evidence_v04.GATE_REPORTS[gate_id]
        return path, json.loads(path.read_text(encoding="utf-8"))

    def _replace_test_metrics(
        self, test_id: str, mutate: Callable[[dict[str, object]], None]
    ) -> None:
        gate_id = next(
            gate
            for gate, ids in validate_release_evidence_v04.GATE_TEST_IDS.items()
            if test_id in ids
        )
        report_path, report = self._read_report(gate_id)
        result = next(item for item in report["tests"] if item["test_id"] == test_id)
        evidence_path = self.root / result["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        mutate(evidence["metrics"])
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
        )
        result["metrics"] = evidence["metrics"]
        result["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        report_path.write_text(
            json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _supply_tools(self, test_id: str) -> dict[str, dict[str, str]]:
        lock = json.loads(
            (self.root / "scripts/release-toolchain-v04.json").read_text(
                encoding="utf-8"
            )
        )
        by_name = {tool["name"]: tool for tool in lock["tools"]}
        bases = {
            "ProgramFiles": "C:/Program Files",
            "LocalAppData": "C:/Users/fixture/AppData/Local",
        }
        return {
            name: {
                "path": f"{bases[by_name[name]['base_directory']]}/{by_name[name]['relative_path']}",
                "sha256": by_name[name]["sha256"],
                "version": lock["versions"][supply_provenance_v04.TOOL_VERSION_KEYS[name]],
            }
            for name in sorted(supply_provenance_v04.REQUIRED_TOOLS[test_id])
        }

    def _sc006_ledger(
        self,
        source: str,
        run_id: str,
        images: dict[str, str],
        tools: dict[str, dict[str, str]],
    ) -> dict[str, object]:
        cases: list[dict[str, object]] = []
        for action_index, action in enumerate(
            ("enable", "disable", "upgrade", "rollback", "uninstall"), start=1
        ):
            unsafe_project = f"spellv04q-{action_index:024x}"
            terminal_index = 0
            for case_index, (stage, certainty, expected) in enumerate(
                (
                    ("SETTLED", "EFFECT_CONFIRMED", True),
                    ("SETTLED", "NO_EFFECT", True),
                    ("REQUESTED", "NO_EFFECT", False),
                    ("ACCEPTED", "NO_EFFECT", False),
                    ("DISPATCHED", "EFFECT_POSSIBLE", False),
                    ("RECONCILING", "EFFECT_CONFIRMED", False),
                    ("RECONCILING", "EFFECT_POSSIBLE", False),
                    ("RECONCILING", "EFFECT_UNKNOWN", False),
                    ("SETTLED", "EFFECT_POSSIBLE", False),
                    ("SETTLED", "EFFECT_UNKNOWN", False),
                    ("UNRECOGNIZED_STAGE", "NO_EFFECT", False),
                    ("SETTLED", "UNRECOGNIZED_CERTAINTY", False),
                ),
                start=1,
            ):
                if expected:
                    terminal_index += 1
                    project = f"spellv04q-{(100 + action_index * 2 + terminal_index):024x}"
                else:
                    project = unsafe_project
                case_id = f"{action}-{case_index:02d}-{stage}-{certainty}"
                before = hashlib.sha256(f"{case_id}:before".encode("ascii")).hexdigest()
                after = (
                    hashlib.sha256(f"{case_id}:after".encode("ascii")).hexdigest()
                    if expected
                    else before
                )
                evidence = hashlib.sha256(f"{case_id}:evidence".encode("ascii")).hexdigest()
                cases.append(
                    {
                        "case_id": case_id,
                        "action": action,
                        "stage": stage,
                        "certainty": certainty,
                        "expected_applied": expected,
                        "observed_applied": expected,
                        "reason": "transition-applied" if expected else "transition-refused",
                        "project_name": project,
                        "before_state_sha256": before,
                        "after_state_sha256": after,
                        "before_evidence_sha256": evidence,
                        "after_evidence_sha256": evidence,
                        "driver_image_before": (
                            images["driver_b"]
                            if expected and action == "rollback"
                            else images["driver_a"]
                        ),
                        "driver_image_after": (
                            images["driver_b"]
                            if expected and action == "upgrade"
                            else images["driver_a"]
                        ),
                        "pki_image_id": images["pki_init"],
                        "cleanup_verified": True,
                    }
                )
        return {
            "schema_version": "spell.v04.sc006-lifecycle-ledger/1",
            "run_id": run_id,
            "source_fingerprint_sha256": source,
            "images": images,
            "tools": tools,
            "cases": cases,
            "summary": {
                "case_count": 60,
                "failed_case_count": 0,
                "terminal_case_count": 10,
                "unsafe_refusal_case_count": 50,
                "unique_project_count": 15,
            },
        }

    def _write_supply_provenance(self) -> None:
        source = source_fingerprint_v04(self.root)
        gate_reports = {
            gate_id: self._read_report(gate_id)
            for gate_id in validate_release_evidence_v04.GATE_REPORTS
        }
        for ordinal, test_id in enumerate(
            sorted(supply_provenance_v04.SUPPORTED_TEST_IDS), start=1
        ):
            run_id = f"{ordinal:032x}"
            raw = self.root / "supply-raw" / supply_provenance_v04.DIRECTORY_NAMES[test_id]
            raw.mkdir(parents=True)
            tools = self._supply_tools(test_id)
            evidence_path = (
                self.root
                / validate_release_evidence_v04.TEST_EVIDENCE_DIRECTORY
                / f"{test_id}.json"
            )
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            if test_id == "V04-SC-001":
                clean_pip = [{"name": "fixture", "version": "1.0", "vulns": []}]
                for name in supply_provenance_v04.SC001_FILES:
                    path = raw / name
                    if name.startswith("pip-audit-"):
                        value: object = clean_pip
                    elif name.startswith("scout-"):
                        value = {"version": "2.1.0", "runs": [{"results": []}]}
                    elif name == "npm-audit.json":
                        value = {
                            "auditReportVersion": 2,
                            "vulnerabilities": {},
                            "metadata": {"vulnerabilities": {"high": 0, "critical": 0}},
                        }
                    elif name == "starlette-policy.json":
                        value = {
                            "passed": True,
                            "policy": "security/starlette_exposure_policy.json",
                            "violation_count": 0,
                        }
                    elif name == "python-tools.json":
                        value = {"pip_audit": "2.10.0", "python": "3.13.14"}
                    else:
                        value = {"node": "v22.0.0", "npm": "10.0.0"}
                    path.write_bytes(supply_provenance_v04._canonical_json(value))
                images = {
                    "audit": "sha256:" + "9" * 64,
                    "backend": "sha256:" + "b" * 64,
                    "driver": "sha256:" + "e" * 64,
                    "frontend": "sha256:" + "d" * 64,
                    "pki_init": "sha256:" + "a" * 64,
                    "postgres": "sha256:" + "f" * 64,
                    "proxy": "sha256:" + "c" * 64,
                }
            elif test_id == "V04-SC-003":
                images = {
                    "backend": "sha256:" + "b" * 64,
                    "driver": "sha256:" + "e" * 64,
                    "frontend": "sha256:" + "d" * 64,
                    "pki_init": "sha256:" + "a" * 64,
                    "postgres": "sha256:" + "f" * 64,
                    "probe": "sha256:" + "9" * 64,
                    "proxy": "sha256:" + "c" * 64,
                }
                report = {
                    "schema_version": "spell.v04.image-inspection/1",
                    "image_ids": {key: images[key] for key in ("backend", "driver", "frontend", "proxy")},
                    "compose_dependency_image_ids": {
                        key: images[key] for key in ("pki_init", "postgres")
                    },
                    **{
                        key: 0
                        for key in (
                            "secret_file_count",
                            "pdf_file_count",
                            "manual_text_file_count",
                            "legacy_archive_count",
                            "runtime_journal_count",
                            "runtime_generator_count",
                            "hardening_failure_count",
                            "layer_scan_failure_count",
                        )
                    },
                }
                report_bytes = supply_provenance_v04._canonical_json(report)
                (raw / "image-inspection.json").write_bytes(report_bytes)
                evidence["metrics"]["inspection_report_sha256"] = hashlib.sha256(
                    report_bytes
                ).hexdigest()
            elif test_id == "V04-SC-004":
                images = {"generator": "sha256:" + "9" * 64}
                for index in (1, 2):
                    child = {
                        "schema_version": "spell.v04.independent-build/1",
                        "process_id": 100 + index,
                        "source_fingerprint_sha256": source,
                        "descriptor_sha256": evidence["metrics"]["descriptor_sha256"],
                        "generation_manifest_sha256": evidence["metrics"]["generation_manifest_sha256"],
                        "package_sha256": evidence["metrics"]["package_sha256"],
                        "product_path_count": 1,
                    }
                    (raw / f"independent-build-{index}.json").write_bytes(
                        supply_provenance_v04._canonical_json(child)
                    )
            else:
                images = {
                    "driver_a": "sha256:" + "1" * 64,
                    "driver_b": "sha256:" + "2" * 64,
                    "pki_init": "sha256:" + "3" * 64,
                }
                (raw / "lifecycle-cases.json").write_bytes(
                    supply_provenance_v04._canonical_json(
                        self._sc006_ledger(source, run_id, images, tools)
                    )
                )
            collector_result = {
                "test_id": test_id,
                "source_fingerprint_sha256": source,
                "assertions": evidence["assertions"],
                "metrics": evidence["metrics"],
            }
            provenance_metrics = supply_provenance_v04.stage_supply_corpus(
                self.root,
                test_id=test_id,
                run_id=run_id,
                source=source,
                input_directory=raw,
                result=collector_result,
                execution_images=images,
                host_tools=tools,
            )
            evidence["metrics"].update(provenance_metrics)
            evidence_path.write_text(
                json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
            )
            canonical = supply_provenance_v04.canonical_directory(self.root, test_id)
            supply_provenance_v04.copy_validated_corpus(
                supply_provenance_v04.staged_directory(
                    self.root, source, test_id, run_id
                ),
                canonical,
            )
            gate_id = next(
                gate
                for gate, ids in validate_release_evidence_v04.GATE_TEST_IDS.items()
                if test_id in ids
            )
            _, gate_report = gate_reports[gate_id]
            gate_result = next(
                item for item in gate_report["tests"] if item["test_id"] == test_id
            )
            gate_result["metrics"] = evidence["metrics"]
            gate_result["evidence_sha256"] = hashlib.sha256(
                evidence_path.read_bytes()
            ).hexdigest()
        for path, report in gate_reports.values():
            path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

    def _write_fault_provenance(self) -> None:
        from scripts import qualify_faults_v04 as faults
        from scripts.tests import test_qualify_faults_v04 as fault_fixtures

        source = source_fingerprint_v04(self.root)
        images = fault_fixtures._fixture_images()
        lock = json.loads(
            (self.root / "scripts/release-toolchain-v04.json").read_text(
                encoding="utf-8"
            )
        )
        tools = {entry["name"]: entry for entry in lock["tools"]}
        bases = {
            "ProgramFiles": "C:/Program Files",
            "LocalAppData": "C:/Users/test/AppData/Local",
        }
        version_keys = {
            "python": "host_python",
            "docker-cli": "docker_cli",
            "docker-compose": "docker_compose",
        }
        host_tools = {
            name: (
                f"{bases[tools[name]['base_directory']]}/{tools[name]['relative_path']}",
                tools[name]["sha256"],
                lock["versions"][version_key],
            )
            for name, version_key in version_keys.items()
        }
        runtime_document, runtime_payloads = fault_fixtures._runtime_document(
            images, source, host_tools
        )
        runtime_root = (
            self.root
            / validate_release_evidence_v04.FAULT_RUNTIME_PROVENANCE_DIRECTORY
        )
        for relative, data in runtime_payloads.items():
            path = runtime_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        runtime_path = runtime_root / "runtime-fault-evidence.json"
        runtime_path.write_bytes(faults._canonical_json(runtime_document) + b"\n")

        report = fault_fixtures.valid_report(source, images, host_tools)
        sec_evidence = json.loads(
            (
                self.root
                / validate_release_evidence_v04.TEST_EVIDENCE_DIRECTORY
                / "V04-SEC-003.json"
            ).read_text(encoding="utf-8")
        )
        report["results"]["V04-SEC-003"]["metrics"] = {
            key: value
            for key, value in sec_evidence["metrics"].items()
            if not key.startswith("raw_report_")
        }
        for artifact in report["artifacts"]:
            data = fault_fixtures._artifact_payload(report, artifact["id"])
            artifact["sha256"] = hashlib.sha256(data).hexdigest()
            artifact["bytes"] = len(data)
        report["report_binding_sha256"] = faults.raw_report_binding(report)
        raw_root = self.root / validate_release_evidence_v04.FAULT_RAW_PROVENANCE_DIRECTORY
        raw_root.mkdir(parents=True, exist_ok=True)
        for artifact in report["artifacts"]:
            (raw_root / Path(artifact["path"]).name).write_bytes(
                fault_fixtures._artifact_payload(report, artifact["id"])
            )
        raw_path = raw_root / "fault-gate-raw.json"
        raw_path.write_bytes(faults._canonical_json(report) + b"\n")

        loaded = faults.load_raw_report(
            raw_path,
            self.root,
            artifact_directory=raw_root,
            observed_image_ids=images,
            runtime_input_path=runtime_path,
            require_runtime_readonly=False,
            require_exact_artifact_directory=True,
        )
        extracted = {
            test_id: faults._extract_raw_result(loaded, test_id)
            for test_id in faults.ASSIGNED_IDS
        }
        gate_reports = {
            gate_id: self._read_report(gate_id)
            for gate_id in validate_release_evidence_v04.GATE_REPORTS
        }
        for test_id, result in extracted.items():
            evidence_path = (
                self.root
                / validate_release_evidence_v04.TEST_EVIDENCE_DIRECTORY
                / f"{test_id}.json"
            )
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["metrics"] = result["metrics"]
            evidence["assertions"] = result["assertions"]
            evidence_path.write_text(
                json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
            )
            gate_id = next(
                gate
                for gate, ids in validate_release_evidence_v04.GATE_TEST_IDS.items()
                if test_id in ids
            )
            _, gate_report = gate_reports[gate_id]
            gate_result = next(
                item for item in gate_report["tests"] if item["test_id"] == test_id
            )
            gate_result["metrics"] = result["metrics"]
            gate_result["assertions"] = {
                "total": len(result["assertions"]),
                "passed": len(result["assertions"]),
                "failed": 0,
                "skipped": 0,
                "errors": 0,
            }
            gate_result["evidence_sha256"] = hashlib.sha256(
                evidence_path.read_bytes()
            ).hexdigest()
        for path, report_value in gate_reports.values():
            path.write_text(
                json.dumps(report_value, sort_keys=True) + "\n", encoding="utf-8"
            )

    def test_fingerprint_covers_all_v04_trees_and_root_lock_inputs(self) -> None:
        self.assertIn(
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_g0.py",
            FINGERPRINT_FILES,
        )
        self.assertIn(
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_compatibility.py",
            FINGERPRINT_FILES,
        )
        original = source_fingerprint_v04(self.root)
        inputs = [self.root / tree / "fingerprint-input.txt" for tree in FINGERPRINT_TREES]
        inputs.extend(self.root / name for name in FINGERPRINT_FILES)
        for path in inputs:
            with self.subTest(path=path.relative_to(self.root).as_posix()):
                content = path.read_bytes()
                path.write_bytes(content + b"changed")
                self.assertNotEqual(source_fingerprint_v04(self.root), original)
                path.write_bytes(content)
                self.assertEqual(source_fingerprint_v04(self.root), original)
        (self.root / "artifacts/v0.3/qualification.json").write_text(
            '{"changed":true}\n', encoding="utf-8"
        )
        self.assertEqual(source_fingerprint_v04(self.root), original)

    def test_v04_package_image_cannot_invoke_v03_builder_or_artifact_path(self) -> None:
        root = Path(__file__).resolve().parents[2]
        dockerfile = (root / "scripts/package-v04.Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/build_reproducible_v04.py", dockerfile)
        self.assertIn("artifacts/v0.4/openbexi-spell-v0.4.tar.gz", dockerfile)
        self.assertNotIn("build_reproducible.py\"", dockerfile)
        self.assertNotIn("artifacts/v0.3", dockerfile)
        self.assertIn("USER 10003:10003", dockerfile)
        dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("artifacts/v0.3", dockerignore.splitlines())
        self.assertIn("artifacts/**/*.tar.gz", dockerignore.splitlines())

    def test_validates_all_five_gates_74_ids_and_four_distinct_sboms(self) -> None:
        self._write_fault_provenance()
        result = validate_release_evidence_v04.validate_release_evidence_v04(self.root)
        self.assertEqual(
            result.validated_gate_ids,
            tuple(validate_release_evidence_v04.GATE_REPORTS),
        )
        self.assertEqual(len(result.validated_test_ids), 74)
        self.assertEqual(len(set(result.sbom_image_ids)), 4)

    def test_final_validation_requires_retained_fault_provenance(self) -> None:
        preliminary = validate_release_evidence_v04.validate_release_evidence_v04(
            self.root, preliminary=True
        )
        self.assertEqual(len(preliminary.validated_test_ids), 74)
        with self.assertRaisesRegex(ValueError, "fault provenance root is missing"):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_final_validation_requires_retained_browser_provenance(self) -> None:
        self._write_fault_provenance()
        browser_root = self.root / "artifacts/v0.4/provenance/browser"
        for path in browser_root.iterdir():
            path.unlink()
        browser_root.rmdir()
        with self.assertRaisesRegex(ValueError, "retained browser provenance is invalid"):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_final_validation_rejects_browser_binding_substitution(self) -> None:
        self._write_fault_provenance()
        self._replace_test_metrics(
            "V04-UI-001",
            lambda metrics: metrics.__setitem__(
                "browser_manifest_sha256", "9" * 64
            ),
        )
        with self.assertRaisesRegex(
            ValueError,
            "V04-UI-001 final metrics differ from retained browser provenance",
        ):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_final_validation_rejects_retained_raw_tamper(self) -> None:
        self._write_fault_provenance()
        raw_root = self.root / validate_release_evidence_v04.FAULT_RAW_PROVENANCE_DIRECTORY
        artifact = next(
            path for path in raw_root.iterdir() if path.name.endswith(".stdout.txt")
        )
        artifact.write_bytes(artifact.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ValueError, "retained fault provenance is invalid"):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_final_validation_rejects_retained_extra_and_symlink_entries(self) -> None:
        self._write_fault_provenance()
        runtime_root = (
            self.root
            / validate_release_evidence_v04.FAULT_RUNTIME_PROVENANCE_DIRECTORY
        )
        (runtime_root / "orphan.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "retained fault provenance is invalid"):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

        (runtime_root / "orphan.json").unlink()
        raw_root = (
            self.root / validate_release_evidence_v04.FAULT_RAW_PROVENANCE_DIRECTORY
        )
        target = next(
            path for path in raw_root.iterdir() if path.name.endswith(".stderr.txt")
        )
        link = raw_root / "linked.txt"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("the test filesystem does not permit symbolic links")
        with self.assertRaisesRegex(ValueError, "retained fault provenance is invalid"):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_final_validation_rejects_consistent_raw_hash_substitution(self) -> None:
        self._write_fault_provenance()
        for test_id in validate_release_evidence_v04.FAULT_RAW_TEST_IDS:
            self._replace_test_metrics(
                test_id,
                lambda metrics: metrics.__setitem__("raw_report_sha256", "9" * 64),
            )

        with self.assertRaisesRegex(
            ValueError, "final metrics differ from retained raw extraction"
        ):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_rejects_fault_result_without_raw_extraction_provenance(self) -> None:
        def remove_raw(metrics: dict[str, object]) -> None:
            for key in (
                "raw_report_schema_version",
                "raw_report_run_id",
                "raw_report_sha256",
                "raw_report_binding_sha256",
            ):
                metrics.pop(key)

        self._replace_test_metrics("V04-CON-001", remove_raw)
        with self.assertRaisesRegex(ValueError, "raw_report_schema_version differs"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

    def test_rejects_cross_result_raw_runtime_and_tool_substitution(self) -> None:
        self._replace_test_metrics(
            "V04-CON-001",
            lambda metrics: metrics.__setitem__("raw_report_sha256", "9" * 64),
        )
        with self.assertRaisesRegex(ValueError, "one exact raw v2 report"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        self._replace_test_metrics(
            "V04-ISO-004",
            lambda metrics: metrics.__setitem__("runtime_input_sha256", "9" * 64),
        )
        with self.assertRaisesRegex(ValueError, "one exact runtime/tool identity"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        for test_id in validate_release_evidence_v04.RUNTIME_BOUND_TEST_IDS:
            self._replace_test_metrics(
                test_id,
                lambda metrics: metrics.__setitem__("runtime_run_id", "9" * 32),
            )
        with self.assertRaisesRegex(ValueError, "raw report and runtime input run IDs differ"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        self._replace_test_metrics(
            "V04-REC-005",
            lambda metrics: metrics.__setitem__(
                "host_python_path", "C:/substituted/python.exe"
            ),
        )
        with self.assertRaisesRegex(ValueError, "one exact runtime/tool identity"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

    def test_rejects_sec002_without_live_rotation_observations(self) -> None:
        cases = (
            ("prior_trust_fingerprint_count", 0),
            ("new_trust_fingerprint_count", 0),
            ("retained_prior_trust_fingerprint_count", 1),
            ("unexpected_new_trust_fingerprint_count", 1),
            ("old_credential_rejection_count", 0),
            ("post_rotation_ready_observation_count", 0),
            ("post_rotation_stale_observation_count", 1),
        )
        for key, value in cases:
            with self.subTest(metric=key):
                self._write_gate_reports()
                self._replace_test_metrics(
                    "V04-SEC-002",
                    lambda metrics, key=key, value=value: metrics.__setitem__(
                        key, value
                    ),
                )
                with self.assertRaisesRegex(ValueError, key):
                    validate_release_evidence_v04.validate_gate_evidence_v04(
                        self.root
                    )

    def test_rejects_sc003_product_package_substitution(self) -> None:
        report_path, report = self._read_report("V04-GATE-5")
        result = next(
            item for item in report["tests"] if item["test_id"] == "V04-SC-003"
        )
        evidence_path = self.root / result["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["metrics"]["product_package_sha256"] = "8" * 64
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
        )
        result["metrics"]["product_package_sha256"] = "8" * 64
        result["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(
            ValueError, "V04-SC-003 inspected product package differs from V04-SC-004"
        ):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_rejects_sec003_product_package_substitution(self) -> None:
        report_path, report = self._read_report("V04-GATE-2")
        result = next(
            item for item in report["tests"] if item["test_id"] == "V04-SEC-003"
        )
        evidence_path = self.root / result["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["metrics"]["product_package_sha256"] = "8" * 64
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
        )
        result["metrics"]["product_package_sha256"] = "8" * 64
        result["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(
            ValueError, "V04-SEC-003 inspected product package differs from V04-SC-004"
        ):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_rejects_sec003_missing_prepublish_scan_category(self) -> None:
        report_path, report = self._read_report("V04-GATE-2")
        result = next(
            item for item in report["tests"] if item["test_id"] == "V04-SEC-003"
        )
        evidence_path = self.root / result["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        del evidence["metrics"]["category_file_counts"]["runtime_captures"]
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
        )
        result["metrics"] = evidence["metrics"]
        result["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(
            ValueError, "category_file_counts differs from the prepublish scan set"
        ):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_rejects_v03_stale_and_duplicate_key_evidence(self) -> None:
        path, report = self._read_report("V04-GATE-1")
        report["product_version"] = "0.3.0"
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not v0.4"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        path, report = self._read_report("V04-GATE-1")
        report["source_artifacts"] = ["artifacts/v0.3/qualification.json"]
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "forbidden v0.3 evidence"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        (self.root / "frontend/fingerprint-input.txt").write_text("stale\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match current"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        path.write_text(
            '{"product_version":"0.4.0","product_version":"0.4.0"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

    def test_rejects_incomplete_ids_and_passing_flags_without_semantics(self) -> None:
        path, report = self._read_report("V04-GATE-1")
        report["tests"] = report["tests"][:-1]  # type: ignore[index]
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "test-ID evidence is incomplete"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        path, report = self._read_report("V04-GATE-4")
        perf = next(  # type: ignore[union-attr]
            item
            for item in report["tests"]  # type: ignore[union-attr]
            if item["test_id"] == "V04-PERF-001"
        )
        perf["metrics"]["p95_ms"] = 50.1  # type: ignore[index]
        evidence_path = self.root / str(perf["evidence_path"])
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["metrics"]["p95_ms"] = 50.1
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        perf["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exceeds 50 ms"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

    def test_gate_results_are_bound_to_structured_executed_evidence(self) -> None:
        path, report = self._read_report("V04-GATE-1")
        result = report["tests"][0]  # type: ignore[index]
        evidence_path = self.root / str(result["evidence_path"])
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["executed"] = False
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        result["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "was not executed"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        evidence_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match its test evidence file"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

        self._write_gate_reports()
        path, report = self._read_report("V04-GATE-3")
        report["tests"][0]["assertions"]["failed"] = 1  # type: ignore[index]
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "assertion accounting"):
            validate_release_evidence_v04.validate_gate_evidence_v04(self.root)

    def test_rejects_missing_stale_duplicate_and_ambiguous_sboms(self) -> None:
        driver = self.root / validate_release_evidence_v04.SBOM_DIRECTORY / "driver.cdx.json"
        driver.unlink()
        with self.assertRaisesRegex(ValueError, "exact four-image"):
            validate_release_evidence_v04.validate_sboms_v04(self.root)

        duplicate_id = "sha256:" + "b" * 64
        self._write_sboms(image_ids={"driver.cdx.json": duplicate_id})
        with self.assertRaisesRegex(ValueError, "not distinct"):
            validate_release_evidence_v04.validate_sboms_v04(self.root)

        self._write_sboms(fingerprint="0" * 64)
        with self.assertRaisesRegex(ValueError, "fingerprint is stale"):
            validate_release_evidence_v04.validate_sboms_v04(self.root)

        self._write_sboms()
        driver.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            validate_release_evidence_v04.validate_sboms_v04(self.root)

        self._write_sboms()
        inventory = json.loads(driver.read_text(encoding="utf-8"))
        inventory["components"][0].pop("licenses")
        driver.write_text(json.dumps(inventory), encoding="utf-8")
        manifest = driver.parent / "SHA256SUMS"
        checksums = {
            line.partition("  ")[2]: line.partition("  ")[0]
            for line in manifest.read_text(encoding="ascii").splitlines()
        }
        checksums[driver.name] = hashlib.sha256(driver.read_bytes()).hexdigest()
        manifest.write_text(
            "".join(f"{checksums[name]}  {name}\n" for name in validate_release_evidence_v04.SBOM_FILES),
            encoding="ascii",
        )
        with self.assertRaisesRegex(ValueError, "has no license"):
            validate_release_evidence_v04.validate_sboms_v04(self.root)

    def test_package_keeps_product_and_generated_contract_assets_only_in_v04(self) -> None:
        screenshot = self.root / "frontend/test-results/generated-browser.png"
        screenshot.parent.mkdir(parents=True)
        screenshot.write_bytes(b"generated screenshot")
        normalization_tool = (
            self.root
            / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/normalize_lrm244.py"
        )
        normalization_tool.write_text("# source-derived normalization tool\n", encoding="utf-8")
        retained_fault = (
            self.root
            / "artifacts/v0.4/provenance/fault-gate/raw/fault-gate-raw.json"
        )
        retained_fault.parent.mkdir(parents=True)
        retained_fault.write_text("retained runtime evidence\n", encoding="utf-8")
        output = self.root / build_reproducible_v04.DEFAULT_OUTPUT
        digest = build_reproducible_v04.build_reproducible_v04(self.root, output)
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), digest)
        self.assertTrue(output.with_name(output.name + ".sha256").is_file())
        with tarfile.open(output, mode="r:gz") as archive:
            names = set(archive.getnames())
        self.assertIn("frontend/product.png", names)
        self.assertIn("SPELL_v0.4_Release.md", names)
        self.assertIn(
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_g0.py",
            names,
        )
        self.assertNotIn(
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/normalize_lrm244.py",
            names,
        )
        for name in build_reproducible_v04.REQUIRED_GENERATED_CONTRACT_ASSETS:
            self.assertIn(name, names)
        self.assertNotIn("frontend/test-results/generated-browser.png", names)
        self.assertFalse(any(name.startswith("artifacts/v0.3/") for name in names))
        self.assertFalse(
            any(name.startswith("artifacts/v0.4/provenance/") for name in names)
        )
        self.assertNotIn("artifacts/v0.4/driver-projection-desktop.png", names)
        self.assertNotIn("artifacts/v0.4/driver-projection-mobile.png", names)
        self.assertFalse(any(name.casefold().endswith(".pdf") for name in names))
        self.assertFalse(any(name.casefold().endswith(".zip") for name in names))

    def test_nonfingerprinted_package_input_drift_invalidates_sc004_binding(self) -> None:
        self.assertNotIn("README.md", FINGERPRINT_FILES)
        source = source_fingerprint_v04(self.root)
        readme = self.root / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "release drift\n", encoding="utf-8")
        self.assertEqual(source_fingerprint_v04(self.root), source)
        with self.assertRaisesRegex(ValueError, "product package hash differs from V04-SC-004"):
            validate_release_evidence_v04.validate_release_evidence_v04(self.root)

    def test_rejects_manual_archive_secret_journal_and_outside_output(self) -> None:
        cases = {
            "backend/operator-manual.txt": "manual text",
            "backend/legacy.zip": "archive",
            "backend/private.key": "secret-bearing",
            "driver_host/var/driver.sqlite": "generated journal",
            "driver_host/driver-journal.bin": "generated journal",
        }
        for relative, message in cases.items():
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"forbidden")
                with self.assertRaisesRegex(ValueError, message):
                    build_reproducible_v04.release_files_v04(self.root)
                path.unlink()
        secret_content = self.root / "backend/leaked-value.txt"
        secret_content.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----")
        paths = build_reproducible_v04.release_files_v04(self.root)
        with self.assertRaisesRegex(ValueError, "secret material"):
            build_reproducible_v04._archive_bytes_v04(self.root, paths)
        secret_content.unlink()
        disguised_secret = self.root / "frontend/leaked-value.bin"
        disguised_secret.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----")
        paths = build_reproducible_v04.release_files_v04(self.root)
        with self.assertRaisesRegex(ValueError, "secret material"):
            build_reproducible_v04._archive_bytes_v04(self.root, paths)
        disguised_secret.unlink()
        with self.assertRaisesRegex(ValueError, "under artifacts/v0.4"):
            build_reproducible_v04.build_reproducible_v04(
                self.root, self.root / "openbexi-spell-v0.4.tar.gz"
            )

    def test_rejects_non_byte_identical_builds_without_publishing(self) -> None:
        output = self.root / build_reproducible_v04.DEFAULT_OUTPUT
        expected = build_reproducible_v04._archive_bytes_v04(
            self.root, build_reproducible_v04.product_files_v04(self.root)
        )
        with mock.patch.object(
            build_reproducible_v04,
            "_archive_bytes_v04",
            side_effect=[expected, b"first archive", b"second archive", expected],
        ):
            with self.assertRaisesRegex(ValueError, "not byte-identical"):
                build_reproducible_v04.build_reproducible_v04(self.root, output)
        self.assertFalse(output.exists())
        self.assertFalse(output.with_name(output.name + ".sha256").exists())


if __name__ == "__main__":
    unittest.main()
