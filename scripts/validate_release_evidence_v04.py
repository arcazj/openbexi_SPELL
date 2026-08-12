"""Validate v0.4 Gate 1-5 evidence and four-image SBOM inputs.

This module validates supplied evidence. It does not execute tests, generate
evidence, or record release acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v04 import source_fingerprint_v04


PRODUCT_VERSION = "0.4.0"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
EVIDENCE_SCHEMA_VERSION = "spell.v04.gate-evidence/1"
TEST_EVIDENCE_SCHEMA_VERSION = "spell.v04.test-evidence/1"
EVIDENCE_DIRECTORY = Path("artifacts/v0.4")
TEST_EVIDENCE_DIRECTORY = EVIDENCE_DIRECTORY / "tests"
FAULT_PROVENANCE_DIRECTORY = EVIDENCE_DIRECTORY / "provenance" / "fault-gate"
FAULT_RAW_PROVENANCE_DIRECTORY = FAULT_PROVENANCE_DIRECTORY / "raw"
FAULT_RUNTIME_PROVENANCE_DIRECTORY = FAULT_PROVENANCE_DIRECTORY / "runtime"
SUPPLY_PROVENANCE_DIRECTORY = EVIDENCE_DIRECTORY / "provenance" / "supply"
BROWSER_PROVENANCE_TEST_IDS = frozenset(
    {"V04-UI-001", "V04-UI-002", "V04-UI-003", "V04-UI-004"}
)
BROWSER_PROVENANCE_METRIC_KEYS = frozenset(
    {
        "browser_provenance_schema_version",
        "browser_run_id",
        "browser_manifest_sha256",
        "browser_corpus_binding_sha256",
        "browser_qualification_image_id",
        "browser_docker_sha256",
        "browser_compose_sha256",
        "browser_node_sha256",
        "browser_executable_sha256",
    }
)
GATE_REPORTS = {
    f"V04-GATE-{number}": EVIDENCE_DIRECTORY / f"gate-{number}.json"
    for number in range(1, 6)
}


def _ids(prefix: str, count: int) -> frozenset[str]:
    return frozenset(f"V04-{prefix}-{number:03d}" for number in range(1, count + 1))


# Primary allocation follows the five approved gate descriptions. Every
# approved catalog ID must appear exactly once across these reports.
GATE_TEST_IDS = {
    "V04-GATE-1": frozenset().union(
        _ids("DOC", 3),
        {"V04-BOUND-001"},
        _ids("SCOPE", 2),
        _ids("CON", 5),
        _ids("CTX", 2),
        _ids("CFG", 4),
        _ids("CAP", 2),
        _ids("LIFE", 4),
        _ids("MIG", 4),
        {"V04-SEC-004"},
    ),
    "V04-GATE-2": frozenset().union(
        {"V04-BOUND-002"},
        _ids("ISO", 4),
        {"V04-SEC-001", "V04-SEC-002", "V04-SEC-003"},
        _ids("DEAD", 4),
        _ids("OP", 6),
        _ids("JRN", 3),
        _ids("REC", 7),
    ),
    "V04-GATE-3": frozenset().union(
        _ids("API", 3), _ids("UI", 4), _ids("REG", 1)
    ),
    "V04-GATE-4": _ids("PERF", 4),
    "V04-GATE-5": _ids("SC", 6),
}
EXPECTED_TEST_IDS = frozenset().union(*GATE_TEST_IDS.values())

SBOM_DIRECTORY = EVIDENCE_DIRECTORY / "sbom"
SBOM_FILES = (
    "backend.cdx.json",
    "proxy.cdx.json",
    "frontend.cdx.json",
    "driver.cdx.json",
)
SBOM_SUBJECTS = {
    "backend.cdx.json": "openbexi_spell-backend:0.4",
    "proxy.cdx.json": "openbexi_spell-proxy:0.4",
    "frontend.cdx.json": "openbexi_spell-frontend:0.4",
    "driver.cdx.json": "openbexi_spell-driver:0.4",
}
SBOM_REQUIRED_COMPONENTS = {
    "backend.cdx.json": {
        "fastapi",
        "grpcio",
        "protobuf",
        "psycopg",
        "pydantic",
        "sqlalchemy",
        "uvicorn",
    },
    "proxy.cdx.json": {"nginx"},
    "frontend.cdx.json": {
        "@reduxjs/toolkit",
        "echarts",
        "lucide-react",
        "react",
        "react-dom",
        "react-redux",
    },
    "driver.cdx.json": {"grpcio", "protobuf"},
}
SBOM_SOURCE_FINGERPRINT_PROPERTY = "openbexi:source-fingerprint-sha256"
SBOM_IMAGE_ID_PROPERTY = "openbexi:scanned-image-id"

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
RAW_REPORT_SCHEMA_VERSION = "spell.v04.fault-gate-raw/2"
RUNTIME_INPUT_SCHEMA_VERSION = "spell.v04.fault-runtime-input/1"
FAULT_RAW_TEST_IDS = frozenset(
    {
        "V04-SCOPE-002",
        "V04-CON-001",
        "V04-CON-002",
        "V04-CON-003",
        "V04-MIG-002",
        "V04-MIG-004",
        "V04-SEC-004",
        "V04-BOUND-002",
        "V04-ISO-003",
        "V04-ISO-004",
        "V04-SEC-002",
        "V04-SEC-003",
        "V04-DEAD-004",
        "V04-JRN-001",
        "V04-REC-003",
        "V04-REC-005",
        "V04-API-002",
        "V04-API-003",
    }
)
RUNTIME_BOUND_TEST_IDS = frozenset(
    {
        "V04-SCOPE-002",
        "V04-MIG-004",
        "V04-SEC-002",
        "V04-SEC-004",
        "V04-BOUND-002",
        "V04-ISO-003",
        "V04-ISO-004",
        "V04-REC-005",
    }
)
FORBIDDEN_ACCEPTANCE_CLAIMS = {
    "release_accepted",
    "acceptance_recorded",
    "operationally_approved",
    "compliance_approved",
}


@dataclass(frozen=True)
class ReleaseEvidenceValidationV04:
    source_fingerprint_sha256: str
    evidence_fingerprint_sha256: str
    validated_gate_ids: tuple[str, ...]
    validated_test_ids: tuple[str, ...]
    sbom_image_ids: tuple[str, ...]


def parse_json_document_v04(text: str, label: str) -> Any:
    """Parse standards-compliant JSON and reject duplicate object keys."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} contains duplicate object key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains non-finite JSON number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _integer(mapping: dict[str, Any], key: str, label: str) -> int:
    value = mapping.get(key)
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label}.{key} must be an integer",
    )
    return value


def _number(mapping: dict[str, Any], key: str, label: str) -> float:
    value = mapping.get(key)
    _require(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value),
        f"{label}.{key} must be a finite number",
    )
    return float(value)


def _zero(mapping: dict[str, Any], key: str, label: str) -> None:
    _require(_integer(mapping, key, label) == 0, f"{label}.{key} must be zero")


def _sha256(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    _require(
        isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None,
        f"{label}.{key} must be a lowercase SHA-256 digest",
    )
    return value


def _validate_runtime_tool_metrics(metrics: dict[str, Any], label: str) -> None:
    for key in (
        "host_powershell_sha256",
        "host_python_sha256",
        "host_docker_sha256",
        "host_compose_sha256",
    ):
        _sha256(metrics, key, label)
    for key in (
        "host_powershell_version",
        "host_python_version",
        "host_docker_version",
        "host_compose_version",
    ):
        value = metrics.get(key)
        _require(
            isinstance(value, str)
            and 0 < len(value) <= 128
            and not any(character.isspace() for character in value),
            f"{label}.{key} is invalid",
        )


def _absolute_executable_path(
    metrics: dict[str, Any],
    key: str,
    expected_names: set[str],
    label: str,
) -> str:
    value = metrics.get(key)
    _require(isinstance(value, str) and bool(value), f"{label}.{key} is invalid")
    windows_path = PureWindowsPath(value)
    posix_path = PurePosixPath(value)
    name = (
        windows_path.name.casefold()
        if windows_path.is_absolute()
        else posix_path.name.casefold()
    )
    _require(
        (windows_path.is_absolute() or posix_path.is_absolute())
        and name in expected_names,
        f"{label}.{key} is not an absolute expected executable path",
    )
    return value


def _reject_disallowed_claims(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_ACCEPTANCE_CLAIMS and item is True:
                raise ValueError(f"{label} makes a forbidden acceptance claim: {key}")
            _reject_disallowed_claims(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_disallowed_claims(item, label)
    elif isinstance(value, str):
        normalized = value.replace("\\", "/").casefold()
        if "artifacts/v0.3" in normalized:
            raise ValueError(f"{label} references forbidden v0.3 evidence")


def _utc_timestamp(value: Any, label: str) -> datetime:
    _require(isinstance(value, str) and bool(value), f"{label} must be an ISO timestamp")
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO timestamp") from exc
    _require(observed.tzinfo is not None, f"{label} must include a UTC offset")
    _require(
        observed.utcoffset() is not None and observed.utcoffset().total_seconds() == 0,
        f"{label} must be UTC",
    )
    return observed


def _validate_test_evidence_file(
    root: Path,
    result: dict[str, Any],
    expected_id: str,
    source: str,
) -> tuple[dict[str, Any], int]:
    label = f"{expected_id}.evidence"
    expected_relative = TEST_EVIDENCE_DIRECTORY / f"{expected_id}.json"
    relative_value = result.get("evidence_path")
    _require(
        relative_value == expected_relative.as_posix(),
        f"{expected_id}.evidence_path must use the exact v0.4 test evidence path",
    )
    path = root / expected_relative
    evidence = _load_object(path, "test evidence")
    actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _require(
        result.get("evidence_sha256") == actual_digest,
        f"{expected_id}.evidence_sha256 does not match its test evidence file",
    )
    _reject_disallowed_claims(evidence, label)
    _require(
        evidence.get("schema_version") == TEST_EVIDENCE_SCHEMA_VERSION,
        f"{label} schema version differs",
    )
    _require(evidence.get("product_version") == PRODUCT_VERSION, f"{label} version differs")
    _require(evidence.get("scope_profile") == SCOPE_PROFILE, f"{label} scope differs")
    _require(evidence.get("test_id") == expected_id, f"{label} test ID differs")
    _require(evidence.get("executed") is True, f"{label} was not executed")
    _require(evidence.get("passed") is True, f"{label} did not pass")
    evidence_source = _mapping(evidence.get("source"), f"{label}.source")
    _require(
        evidence_source.get("fingerprint_sha256") == source,
        f"{label} source fingerprint is stale",
    )
    started = _utc_timestamp(evidence.get("started_at"), f"{label}.started_at")
    finished = _utc_timestamp(evidence.get("finished_at"), f"{label}.finished_at")
    _require(finished >= started, f"{label} finished before it started")

    environment = _mapping(evidence.get("environment"), f"{label}.environment")
    _require(
        isinstance(environment.get("runner"), str) and bool(environment["runner"]),
        f"{label}.environment.runner is required",
    )
    commands = evidence.get("commands")
    _require(isinstance(commands, list) and bool(commands), f"{label}.commands is empty")
    for index, command_value in enumerate(commands):
        command_label = f"{label}.commands[{index}]"
        command = _mapping(command_value, command_label)
        argv = command.get("argv")
        _require(
            isinstance(argv, list)
            and bool(argv)
            and all(isinstance(item, str) and 0 < len(item) <= 1024 for item in argv),
            f"{command_label}.argv is invalid",
        )
        _require(
            _integer(command, "return_code", command_label) == 0,
            f"{command_label} did not exit successfully",
        )
        _sha256(command, "stdout_sha256", command_label)
        _sha256(command, "stderr_sha256", command_label)

    assertions = evidence.get("assertions")
    _require(
        isinstance(assertions, list) and bool(assertions),
        f"{label}.assertions is empty",
    )
    assertion_ids: set[str] = set()
    for index, assertion_value in enumerate(assertions):
        assertion_label = f"{label}.assertions[{index}]"
        assertion = _mapping(assertion_value, assertion_label)
        assertion_id = assertion.get("id")
        _require(
            isinstance(assertion_id, str) and bool(assertion_id),
            f"{assertion_label}.id is required",
        )
        _require(assertion_id not in assertion_ids, f"{label} has duplicate assertion IDs")
        assertion_ids.add(assertion_id)
        _require(assertion.get("passed") is True, f"{assertion_label} did not pass")

    metrics = _mapping(evidence.get("metrics"), f"{label}.metrics")
    _require(metrics == result.get("metrics"), f"{label} metrics differ from the gate report")
    return metrics, len(assertions)


def _validate_measured_rate(
    metrics: dict[str, Any],
    label: str,
    count_key: str,
    minimum_count: int,
    minimum_rate: float,
) -> None:
    count = _integer(metrics, count_key, label)
    duration = _number(metrics, "duration_seconds", label)
    achieved = _number(metrics, "achieved_rate_per_second", label)
    _require(count >= minimum_count, f"{label}.{count_key} is below threshold")
    _require(duration > 0, f"{label}.duration_seconds must be positive")
    recomputed = count / duration
    _require(
        achieved >= minimum_rate and abs(achieved - recomputed) <= 0.01,
        f"{label} achieved rate is below threshold or inconsistent",
    )


def _validate_perf_001(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_measured_rate(metrics, label, "sample_count", 1_000, 100.0)
    p95 = _number(metrics, "p95_ms", label)
    maximum = _number(metrics, "max_ms", label)
    _require(0 <= p95 <= 50.0, f"{label}.p95_ms exceeds 50 ms")
    _require(p95 <= maximum <= 250.0, f"{label}.max_ms exceeds 250 ms")
    _zero(metrics, "error_count", label)


def _validate_perf_002(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_measured_rate(metrics, label, "operation_count", 1_000, 20.0)
    _require(
        0 <= _number(metrics, "acceptance_p95_ms", label) <= 250.0,
        f"{label}.acceptance_p95_ms exceeds 250 ms",
    )
    _require(
        0 <= _number(metrics, "terminal_p95_ms", label) <= 500.0,
        f"{label}.terminal_p95_ms exceeds 500 ms",
    )
    for key in ("duplicate_effect_count", "stuck_operation_count", "error_count"):
        _zero(metrics, key, label)


def _validate_perf_003(metrics: dict[str, Any], label: str, _: str) -> None:
    _require(
        _integer(metrics, "cancellation_count", label) >= 100,
        f"{label}.cancellation_count is below threshold",
    )
    cancel_p95 = _number(metrics, "cancel_p95_ms", label)
    cancel_max = _number(metrics, "cancel_max_ms", label)
    _require(0 <= cancel_p95 <= 500.0, f"{label}.cancel_p95_ms exceeds 500 ms")
    _require(cancel_p95 <= cancel_max <= 1_000.0, f"{label}.cancel_max_ms exceeds 1 s")
    _require(
        _integer(metrics, "restart_count", label) >= 25,
        f"{label}.restart_count is below threshold",
    )
    for key in ("readiness_max_ms", "reconciliation_max_ms"):
        _require(
            0 <= _number(metrics, key, label) <= 5_000.0,
            f"{label}.{key} exceeds 5 s",
        )
    for key in (
        "target_certainty_change_count",
        "duplicate_effect_count",
        "stuck_operation_count",
        "error_count",
    ):
        _zero(metrics, key, label)


def _validate_perf_004(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_measured_rate(metrics, label, "operation_count", 12_000, 20.0)
    _require(
        _number(metrics, "duration_seconds", label) >= 600.0,
        f"{label}.duration_seconds is below ten minutes",
    )
    for key in (
        "loss_count",
        "duplicate_effect_count",
        "stuck_operation_count",
        "crash_count",
    ):
        _zero(metrics, key, label)
    _require(
        0 <= _number(metrics, "post_warmup_growth_mib", label) <= 32.0,
        f"{label}.post_warmup_growth_mib exceeds 32 MiB",
    )
    _require(
        0 <= _number(metrics, "post_warmup_slope_mib_per_minute", label) <= 2.0,
        f"{label}.post_warmup_slope_mib_per_minute exceeds 2 MiB/min",
    )


def _validate_scope_001(metrics: dict[str, Any], label: str, _: str) -> None:
    _require(_integer(metrics, "rpc_count", label) == 9, f"{label}.rpc_count must be nine")
    _zero(metrics, "future_service_count", label)
    _zero(metrics, "untyped_payload_count", label)


def _validate_scope_002(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    _require(
        _integer(metrics, "accepted_telemetry_execution_count", label) == 1,
        f"{label}.accepted_telemetry_execution_count must be one",
    )
    _require(
        _integer(metrics, "telemetry_event_count", label) == 1,
        f"{label}.telemetry_event_count must be one",
    )
    _require(
        _integer(metrics, "health_baseline_observation_count", label) >= 1,
        f"{label}.health_baseline_observation_count is below threshold",
    )
    for key in (
        "execution_correlated_rpc_delta",
        "context_delta",
        "binding_delta",
        "operation_delta",
        "journal_delta",
    ):
        _zero(metrics, key, label)


def _validate_mig_004(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    expected_counts = {
        "dialect_count": 2,
        "postgres_backup_restore_count": 1,
        "truth_state_count": 6,
        "safe_rollback_count": 1,
        "v03_simulator_execution_count": 1,
    }
    for key, expected in expected_counts.items():
        _require(
            _integer(metrics, key, label) == expected,
            f"{label}.{key} must be {expected}",
        )
    _require(
        _integer(metrics, "unsafe_rollback_refusal_count", label) >= 1,
        f"{label}.unsafe_rollback_refusal_count is below threshold",
    )
    for key in (
        "postgres_snapshot_mismatch_count",
        "unsafe_rollback_evidence_loss_count",
        "v03_snapshot_mismatch_count",
        "enabled_driver_profile_count",
        "duplicate_effect_count",
    ):
        _zero(metrics, key, label)


def _validate_sec_002(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    _require(
        _integer(metrics, "prior_credential_epoch", label) == 1,
        f"{label}.prior_credential_epoch must be one",
    )
    _require(
        _integer(metrics, "new_credential_epoch", label) == 2,
        f"{label}.new_credential_epoch must be two",
    )
    for key in ("profile_revision_delta", "rotation_audit_count", "rotation_outbox_count"):
        _require(_integer(metrics, key, label) == 1, f"{label}.{key} must be one")
    _require(
        metrics.get("current_credential_status") == "UNIMPLEMENTED",
        f"{label}.current_credential_status differs",
    )
    _require(
        metrics.get("old_credential_status") == "UNAVAILABLE",
        f"{label}.old_credential_status differs",
    )
    for key in ("ca_changed", "client_certificate_changed", "ready_after_rotation"):
        _require(metrics.get(key) is True, f"{label}.{key} must be true")
    for key in (
        "configuration_digest_drift_count",
        "credential_reference_drift_count",
        "retained_prior_trust_fingerprint_count",
        "unexpected_new_trust_fingerprint_count",
        "trust_set_expansion_count",
        "post_rotation_stale_observation_count",
    ):
        _zero(metrics, key, label)
    for key in (
        "prior_trust_fingerprint_count",
        "new_trust_fingerprint_count",
        "old_credential_rejection_count",
        "post_rotation_ready_observation_count",
    ):
        _require(
            _integer(metrics, key, label) >= 1,
            f"{label}.{key} is below threshold",
        )
    _require(
        _integer(metrics, "ready_credential_epoch", label) == 2,
        f"{label}.ready_credential_epoch must be two",
    )


def _validate_sec_004(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    _require(
        metrics.get("reflection_status") == "UNIMPLEMENTED",
        f"{label}.reflection_status differs",
    )
    _require(
        metrics.get("direct_administration_status") == "UNIMPLEMENTED",
        f"{label}.direct_administration_status differs",
    )
    _require(
        metrics.get("jwt_without_mtls_status") == "UNAVAILABLE",
        f"{label}.jwt_without_mtls_status differs",
    )
    _require(
        metrics.get("unauthorized_metadata_status")
        in {"UNAUTHENTICATED", "PERMISSION_DENIED", "FAILED_PRECONDITION"},
        f"{label}.unauthorized_metadata_status differs",
    )
    _require(
        _integer(metrics, "proxy_route_http_status", label) in {404, 405},
        f"{label}.proxy_route_http_status must be 404 or 405",
    )
    _require(
        _integer(metrics, "safe_audit_reason_count", label) >= 4,
        f"{label}.safe_audit_reason_count is below threshold",
    )
    _zero(metrics, "unsafe_echo_count", label)


def _validate_bound_002(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    for key in (
        "nominal_captured_frame_count",
        "fault_captured_frame_count",
        "nominal_endpoint_tuple_count",
        "fault_endpoint_tuple_count",
    ):
        _require(_integer(metrics, key, label) >= 1, f"{label}.{key} is empty")
    for key in (
        "nominal_unapproved_endpoint_count",
        "fault_unapproved_endpoint_count",
        "connection_log_unapproved_endpoint_count",
    ):
        _zero(metrics, key, label)
    for key in ("nominal_capture_truncated", "fault_capture_truncated"):
        _require(metrics.get(key) is False, f"{label}.{key} must be false")


def _validate_iso_003(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    _require(
        _integer(metrics, "injection_count", label) == 2,
        f"{label}.injection_count must be two",
    )
    _require(
        _integer(metrics, "unchanged_non_driver_container_observation_count", label) >= 6,
        f"{label}.unchanged_non_driver_container_observation_count is below threshold",
    )
    _require(
        _integer(metrics, "degraded_or_stale_observation_count", label) == 2,
        f"{label}.degraded_or_stale_observation_count must be two",
    )
    _require(
        _integer(metrics, "recovery_count", label) == 2,
        f"{label}.recovery_count must be two",
    )
    for key in (
        "non_driver_liveness_failure_count",
        "worker_progress_failure_count",
        "recovery_failure_count",
    ):
        _zero(metrics, key, label)


def _validate_iso_004(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    for key in ("driver_listener_reachable", "backend_to_driver_reachable"):
        _require(metrics.get(key) is True, f"{label}.{key} must be true")
    for key in (
        "reverse_api_reachable",
        "database_reachable",
        "proxy_reachable",
        "host_alias_reachable",
        "loopback_api_reachable",
        "loopback_proxy_reachable",
        "test_net_reachable",
    ):
        _require(metrics.get(key) is False, f"{label}.{key} must be false")
    _zero(metrics, "unapproved_route_count", label)


def _validate_rec_005(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_runtime_tool_metrics(metrics, label)
    for key in ("phase_count", "operation_case_count", "final_disposition_count"):
        _require(_integer(metrics, key, label) == 3, f"{label}.{key} must be three")
    for key in (
        "duplicate_effect_count",
        "resend_count",
        "unreconstructable_count",
        "audit_outbox_mismatch_count",
        "commit_publish_violation_count",
    ):
        _zero(metrics, key, label)


def _validate_sec_003(metrics: dict[str, Any], label: str, source: str) -> None:
    _require(
        _integer(metrics, "canary_location_count", label) >= 1,
        f"{label}.canary_location_count is below threshold",
    )
    _zero(metrics, "canary_leak_count", label)
    expected_canary_sha256 = hashlib.sha256(
        f"spell-v04-service-secret-{source}".encode("ascii")
    ).hexdigest()
    _require(
        _sha256(metrics, "canary_sha256", label) == expected_canary_sha256,
        f"{label}.canary_sha256 is stale for the source fingerprint",
    )

    categories = _mapping(
        metrics.get("category_file_counts"), f"{label}.category_file_counts"
    )
    expected_categories = {
        "frontend_bundle",
        "browser_storage",
        "screenshots",
        "sboms",
        "runtime_captures",
    }
    _require(
        set(categories) == expected_categories,
        f"{label}.category_file_counts differs from the prepublish scan set",
    )
    for category in sorted(expected_categories - {"sboms"}):
        _require(
            _integer(categories, category, f"{label}.category_file_counts") >= 1,
            f"{label}.category_file_counts.{category} is below threshold",
        )
    _require(
        _integer(categories, "sboms", f"{label}.category_file_counts") == 4,
        f"{label}.category_file_counts.sboms must be four",
    )

    product_inputs = _integer(metrics, "product_input_file_count", label)
    product_members = _integer(metrics, "product_package_file_count", label)
    product_scanned = _integer(metrics, "product_scanned_file_count", label)
    _require(
        product_inputs >= 1,
        f"{label}.product_input_file_count is below threshold",
    )
    _require(
        product_members == product_inputs,
        f"{label} product package member count differs from inspected inputs",
    )
    _require(
        product_scanned == product_inputs + product_members,
        f"{label}.product_scanned_file_count is inconsistent",
    )
    category_files = sum(
        _integer(categories, category, f"{label}.category_file_counts")
        for category in sorted(expected_categories)
    )
    _require(
        _integer(metrics, "scanned_file_count", label)
        == category_files + product_scanned,
        f"{label}.scanned_file_count is inconsistent",
    )

    input_bytes = _integer(metrics, "product_input_byte_count", label)
    member_bytes = _integer(metrics, "product_package_member_byte_count", label)
    scanned_bytes = _integer(metrics, "product_scanned_byte_count", label)
    _require(input_bytes >= 1, f"{label}.product_input_byte_count is below threshold")
    _require(
        member_bytes == input_bytes,
        f"{label} product package member bytes differ from inspected inputs",
    )
    _require(
        scanned_bytes == input_bytes + member_bytes,
        f"{label}.product_scanned_byte_count is inconsistent",
    )
    category_bytes = _integer(metrics, "category_scanned_byte_count", label)
    _require(
        _integer(metrics, "scanned_byte_count", label)
        == category_bytes + scanned_bytes,
        f"{label}.scanned_byte_count is inconsistent",
    )
    _require(
        _integer(metrics, "product_package_byte_count", label) >= 1,
        f"{label}.product_package_byte_count is below threshold",
    )
    _sha256(metrics, "product_package_sha256", label)
    _require(
        _sha256(metrics, "source_fingerprint_sha256", label) == source,
        f"{label} product-package source fingerprint is stale",
    )
    for key in (
        "product_secret_file_count",
        "product_pdf_file_count",
        "product_manual_text_file_count",
        "product_legacy_archive_count",
        "product_runtime_journal_count",
        "product_forbidden_marker_count",
    ):
        _zero(metrics, key, label)


def _validate_ui_003(metrics: dict[str, Any], label: str, _: str) -> None:
    _require(
        _integer(metrics, "desktop_viewport_count", label) >= 1,
        f"{label}.desktop_viewport_count is below threshold",
    )
    _require(
        _integer(metrics, "mobile_viewport_count", label) >= 1,
        f"{label}.mobile_viewport_count is below threshold",
    )
    for key in (
        "axe_serious_finding_count",
        "axe_critical_finding_count",
        "keyboard_failure_count",
        "overflow_failure_count",
    ):
        _zero(metrics, key, label)


def _validate_reg_001(metrics: dict[str, Any], label: str, _: str) -> None:
    _require(
        _integer(metrics, "v03_suite_count", label) >= 1,
        f"{label}.v03_suite_count is below threshold",
    )
    _zero(metrics, "v03_suite_failure_count", label)
    _zero(metrics, "v03_changed_default_count", label)


def _validate_supply_provenance_metrics(metrics: dict[str, Any], label: str) -> None:
    _require(
        metrics.get("supply_provenance_schema_version")
        == "spell.v04.supply-provenance/1",
        f"{label}.supply_provenance_schema_version differs",
    )
    run_id = metrics.get("supply_provenance_run_id")
    _require(
        isinstance(run_id, str) and RUN_ID_PATTERN.fullmatch(run_id) is not None,
        f"{label}.supply_provenance_run_id is invalid",
    )
    _sha256(metrics, "supply_provenance_manifest_sha256", label)
    _sha256(metrics, "supply_provenance_corpus_sha256", label)
    _require(
        _integer(metrics, "supply_provenance_file_count", label) >= 2,
        f"{label}.supply_provenance_file_count is below threshold",
    )


def _validate_sc_001(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_supply_provenance_metrics(metrics, label)
    _require(
        _integer(metrics, "lock_input_count", label) >= 1,
        f"{label}.lock_input_count is below threshold",
    )
    _require(
        _integer(metrics, "audit_tool_count", label) >= 1,
        f"{label}.audit_tool_count is below threshold",
    )
    for key in ("unlocked_input_count", "critical_finding_count", "high_finding_count"):
        _zero(metrics, key, label)
    _require(
        _integer(metrics, "audited_image_count", label) == 4,
        f"{label}.audited_image_count must be four",
    )
    audited_images = _mapping(metrics.get("audited_image_ids"), f"{label}.audited_image_ids")
    _require(
        set(audited_images) == {"backend", "driver", "frontend", "proxy"}
        and all(
            isinstance(image_id, str)
            and IMAGE_ID_PATTERN.fullmatch(image_id) is not None
            for image_id in audited_images.values()
        ),
        f"{label}.audited_image_ids must bind the exact four-image set",
    )
    _require(
        _integer(metrics, "compose_dependency_audited_image_count", label) == 2,
        f"{label} must audit two Compose dependency images",
    )
    dependency_images = _mapping(
        metrics.get("compose_dependency_audited_image_ids"),
        f"{label}.compose_dependency_audited_image_ids",
    )
    _require(
        set(dependency_images) == {"pki_init", "postgres"}
        and all(
            isinstance(image_id, str)
            and IMAGE_ID_PATTERN.fullmatch(image_id) is not None
            for image_id in dependency_images.values()
        ),
        f"{label}.compose_dependency_audited_image_ids differs",
    )


def _validate_sc_002(metrics: dict[str, Any], label: str, _: str) -> None:
    _require(_integer(metrics, "sbom_count", label) == 4, f"{label}.sbom_count must be four")
    _require(
        _integer(metrics, "distinct_image_count", label) == 4,
        f"{label}.distinct_image_count must be four",
    )
    _require(
        metrics.get("image_names") == ["backend", "driver", "frontend", "proxy"],
        f"{label}.image_names must name the exact four-image set",
    )
    _require(
        _integer(metrics, "schema_validation_count", label) == 4,
        f"{label}.schema_validation_count must be four",
    )
    _require(
        metrics.get("schema_validator")
        == "cyclonedx-python-lib/11.11.0 JsonStrictValidator",
        f"{label}.schema_validator differs",
    )
    _require(
        metrics.get("negative_tamper_rejected") is True,
        f"{label}.negative_tamper_rejected must be true",
    )


def _validate_sc_003(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_supply_provenance_metrics(metrics, label)
    _require(
        _integer(metrics, "scanned_file_count", label) >= 1,
        f"{label}.scanned_file_count is below threshold",
    )
    for key in (
        "secret_file_count",
        "pdf_file_count",
        "manual_text_file_count",
        "legacy_archive_count",
        "runtime_journal_count",
        "runtime_generator_count",
        "hardening_failure_count",
        "layer_scan_failure_count",
    ):
        _zero(metrics, key, label)
    inspected_images = _mapping(
        metrics.get("inspected_image_ids"), f"{label}.inspected_image_ids"
    )
    _require(
        set(inspected_images) == {"backend", "driver", "frontend", "proxy"}
        and all(
            isinstance(image_id, str)
            and IMAGE_ID_PATTERN.fullmatch(image_id) is not None
            for image_id in inspected_images.values()
        ),
        f"{label}.inspected_image_ids must bind the exact four-image set",
    )
    _sha256(metrics, "inspection_report_sha256", label)
    _sha256(metrics, "product_package_sha256", label)
    _require(
        _integer(metrics, "scanned_image_count", label) == 6,
        f"{label}.scanned_image_count must cover four subjects and two dependencies",
    )
    _require(
        _integer(metrics, "scanned_layer_count", label) >= 6,
        f"{label}.scanned_layer_count is below the image count",
    )
    _require(
        _integer(metrics, "compose_dependency_inspected_image_count", label) == 2,
        f"{label} must inspect two Compose dependency images",
    )
    dependency_images = _mapping(
        metrics.get("compose_dependency_inspected_image_ids"),
        f"{label}.compose_dependency_inspected_image_ids",
    )
    _require(
        set(dependency_images) == {"pki_init", "postgres"}
        and all(
            isinstance(image_id, str)
            and IMAGE_ID_PATTERN.fullmatch(image_id) is not None
            for image_id in dependency_images.values()
        ),
        f"{label}.compose_dependency_inspected_image_ids differs",
    )


def _validate_sc_004(metrics: dict[str, Any], label: str, source: str) -> None:
    _validate_supply_provenance_metrics(metrics, label)
    _require(
        _integer(metrics, "generation_build_count", label) >= 2,
        f"{label}.generation_build_count is below threshold",
    )
    _require(
        _integer(metrics, "generation_process_count", label) >= 2,
        f"{label}.generation_process_count is below threshold",
    )
    _require(
        metrics.get("generation_byte_identical") is True,
        f"{label}.generation_byte_identical must be true",
    )
    _require(
        _integer(metrics, "package_build_count", label) >= 2,
        f"{label}.package_build_count is below threshold",
    )
    _require(
        _integer(metrics, "package_process_count", label) >= 2,
        f"{label}.package_process_count is below threshold",
    )
    _require(
        _integer(metrics, "distinct_build_process_count", label) >= 2,
        f"{label} generation/package builds were not process independent",
    )
    _require(
        metrics.get("package_byte_identical") is True,
        f"{label}.package_byte_identical must be true",
    )
    _require(
        _sha256(metrics, "generation_source_fingerprint_sha256", label) == source,
        f"{label} generation source fingerprint is stale",
    )
    _require(
        _sha256(metrics, "package_source_fingerprint_sha256", label) == source,
        f"{label} package source fingerprint is stale",
    )
    descriptor = _sha256(metrics, "descriptor_sha256", label)
    generation_manifest = _sha256(metrics, "generation_manifest_sha256", label)
    package_sha256 = _sha256(metrics, "package_sha256", label)
    generation_evidence = _sha256(metrics, "generation_evidence_sha256", label)
    package_evidence = _sha256(metrics, "package_evidence_sha256", label)
    _require(
        generation_evidence == package_evidence,
        f"{label} generation/package evidence bindings differ",
    )
    expected_binding = hashlib.sha256(
        (
            source
            + "\0"
            + descriptor
            + "\0"
            + generation_manifest
            + "\0"
            + package_sha256
        ).encode("ascii")
    ).hexdigest()
    _require(
        generation_evidence == expected_binding,
        f"{label} generation/package evidence binding is invalid",
    )


def _validate_sc_005(metrics: dict[str, Any], label: str, _: str) -> None:
    _require(
        metrics.get("artifact_root") == "artifacts/v0.4",
        f"{label}.artifact_root must be artifacts/v0.4",
    )
    for key in (
        "v03_evidence_file_count",
        "v03_overwrite_count",
        "generated_browser_image_count",
    ):
        _zero(metrics, key, label)
    _require(
        _integer(metrics, "product_asset_count", label) >= 1,
        f"{label}.product_asset_count is below threshold",
    )
    _require(
        _integer(metrics, "generated_contract_asset_count", label) >= 1,
        f"{label}.generated_contract_asset_count is below threshold",
    )


def _validate_sc_006(metrics: dict[str, Any], label: str, _: str) -> None:
    _validate_supply_provenance_metrics(metrics, label)
    _require(
        metrics.get("lifecycle_engine") == "docker-compose-v2",
        f"{label}.lifecycle_engine must identify the real Compose lifecycle",
    )
    _require(
        metrics.get("runtime_platform") == "linux/amd64",
        f"{label}.runtime_platform differs from the declared platform",
    )
    _require(
        metrics.get("runtime_transition_matrix_executed") is True,
        f"{label} did not execute the runtime transition matrix",
    )
    _require(
        metrics.get("locked_tool_paths_confirmed") is True,
        f"{label} did not use hash-locked Docker and Compose executable paths",
    )
    platform_count = _integer(metrics, "platform_profile_count", label)
    _require(
        platform_count >= 1,
        f"{label}.platform_profile_count is below threshold",
    )
    for key in (
        "install_case_count",
        "enable_case_count",
        "disable_case_count",
        "upgrade_case_count",
        "rollback_case_count",
        "uninstall_case_count",
    ):
        _require(_integer(metrics, key, label) >= 1, f"{label}.{key} is below threshold")
    _require(
        _integer(metrics, "install_case_count", label) >= platform_count * 15,
        f"{label} does not use isolated projects for the full lifecycle matrix",
    )
    for key in (
        "enable_case_count",
        "disable_case_count",
        "upgrade_case_count",
        "rollback_case_count",
        "uninstall_case_count",
    ):
        _require(
            _integer(metrics, key, label) >= platform_count * 12,
            f"{label}.{key} does not cover terminal and uncertain states",
        )
    _require(
        _integer(metrics, "terminal_case_count", label) >= platform_count * 10,
        f"{label}.terminal_case_count is below the platform/state threshold",
    )
    _require(
        _integer(metrics, "unsafe_refusal_case_count", label) >= platform_count * 50,
        f"{label}.unsafe_refusal_case_count is below the platform/state threshold",
    )
    runtime_count = _integer(metrics, "runtime_transition_case_count", label)
    _require(
        runtime_count
        == _integer(metrics, "terminal_case_count", label)
        + _integer(metrics, "unsafe_refusal_case_count", label),
        f"{label}.runtime_transition_case_count is inconsistent",
    )
    _require(
        _integer(metrics, "unique_project_count", label)
        == _integer(metrics, "install_case_count", label),
        f"{label} reused a Compose project",
    )
    for key in (
        "exact_image_confirmation_count",
        "docker_command_count",
        "mutating_docker_command_count",
    ):
        _require(_integer(metrics, key, label) > 0, f"{label}.{key} is empty")
    _zero(metrics, "failed_case_count", label)


SemanticValidator = Callable[[dict[str, Any], str, str], None]
SEMANTIC_VALIDATORS: dict[str, SemanticValidator] = {
    "V04-SCOPE-001": _validate_scope_001,
    "V04-SCOPE-002": _validate_scope_002,
    "V04-MIG-004": _validate_mig_004,
    "V04-SEC-002": _validate_sec_002,
    "V04-SEC-003": _validate_sec_003,
    "V04-SEC-004": _validate_sec_004,
    "V04-BOUND-002": _validate_bound_002,
    "V04-ISO-003": _validate_iso_003,
    "V04-ISO-004": _validate_iso_004,
    "V04-REC-005": _validate_rec_005,
    "V04-UI-003": _validate_ui_003,
    "V04-REG-001": _validate_reg_001,
    "V04-PERF-001": _validate_perf_001,
    "V04-PERF-002": _validate_perf_002,
    "V04-PERF-003": _validate_perf_003,
    "V04-PERF-004": _validate_perf_004,
    "V04-SC-001": _validate_sc_001,
    "V04-SC-002": _validate_sc_002,
    "V04-SC-003": _validate_sc_003,
    "V04-SC-004": _validate_sc_004,
    "V04-SC-005": _validate_sc_005,
    "V04-SC-006": _validate_sc_006,
}


def _load_object(path: Path, kind: str) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"required v0.4 {kind} is missing: {path.as_posix()}")
    try:
        value = parse_json_document_v04(path.read_text(encoding="utf-8"), path.as_posix())
    except UnicodeDecodeError as exc:
        raise ValueError(f"v0.4 {kind} is not UTF-8: {path.as_posix()}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"v0.4 {kind} is not an object: {path.as_posix()}")
    return value


def _validate_test_result(
    root: Path, result: Any, expected_id: str, source: str
) -> dict[str, Any]:
    label = expected_id
    value = _mapping(result, label)
    _require(value.get("test_id") == expected_id, f"{label} test ID differs")
    _require(value.get("passed") is True, f"{label} did not pass")
    metrics, executed_assertion_count = _validate_test_evidence_file(
        root, value, expected_id, source
    )
    assertions = _mapping(value.get("assertions"), f"{label}.assertions")
    total = _integer(assertions, "total", f"{label}.assertions")
    passed = _integer(assertions, "passed", f"{label}.assertions")
    failed = _integer(assertions, "failed", f"{label}.assertions")
    skipped = _integer(assertions, "skipped", f"{label}.assertions")
    errors = _integer(assertions, "errors", f"{label}.assertions")
    _require(total > 0, f"{label} has no executed assertions")
    _require(
        passed == total and failed == skipped == errors == 0,
        f"{label} assertion accounting is not a complete pass",
    )
    _require(
        total == executed_assertion_count,
        f"{label} assertion accounting differs from its test evidence file",
    )
    validator = SEMANTIC_VALIDATORS.get(expected_id)
    if validator is not None:
        validator(metrics, f"{label}.metrics", source)
    return metrics


def validate_product_package_binding_v04(
    root: Path, expected_sha256: Any, label: str = "V04-SC-004"
) -> str:
    """Require the current product-only package to match the SC004 result."""

    if not isinstance(expected_sha256, str) or SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise ValueError(f"{label}.package_sha256 is not a SHA-256 digest")
    from scripts.build_reproducible_v04 import product_package_sha256_v04

    current = product_package_sha256_v04(root.resolve())
    _require(
        current == expected_sha256,
        f"current product package hash differs from {label}",
    )
    return current


def validate_gate_evidence_v04(
    root: Path,
    *,
    preliminary: bool = False,
) -> tuple[str, str]:
    """Validate exact Gate 1-5 reports and return source/evidence digests."""

    source_root = root.resolve()
    expected_source = source_fingerprint_v04(source_root)
    evidence_digest = hashlib.sha256()
    observed_test_ids: set[str] = set()
    sec003_package_sha256: str | None = None
    sc003_package_sha256: str | None = None
    sc004_package_sha256: str | None = None
    fault_raw_bindings: dict[str, tuple[str, str, str, str]] = {}
    runtime_bindings: dict[str, tuple[str, ...]] = {}

    for gate_id, relative_path in GATE_REPORTS.items():
        path = source_root / relative_path
        report = _load_object(path, "gate evidence")
        _reject_disallowed_claims(report, gate_id)
        _require(
            report.get("schema_version") == EVIDENCE_SCHEMA_VERSION,
            f"{gate_id} schema version differs",
        )
        _require(
            report.get("product_version") == PRODUCT_VERSION,
            f"{gate_id} product version is not v0.4",
        )
        _require(
            report.get("scope_profile") == SCOPE_PROFILE,
            f"{gate_id} scope profile differs",
        )
        _require(report.get("gate_id") == gate_id, f"{gate_id} report identity differs")
        _require(report.get("overall_pass") is True, f"{gate_id} did not pass")
        _require(
            report.get("acceptance_complete") is False,
            f"{gate_id} must not claim release acceptance",
        )
        _require(report.get("waivers") == [], f"{gate_id} contains a waiver")
        findings = _mapping(report.get("open_findings"), f"{gate_id}.open_findings")
        _zero(findings, "critical", f"{gate_id}.open_findings")
        _zero(findings, "high", f"{gate_id}.open_findings")
        source = _mapping(report.get("source"), f"{gate_id}.source")
        fingerprint = source.get("fingerprint_sha256")
        _require(
            fingerprint == expected_source,
            f"{gate_id} source fingerprint does not match current v0.4 source",
        )

        tests = report.get("tests")
        _require(isinstance(tests, list), f"{gate_id}.tests must be an array")
        indexed: dict[str, Any] = {}
        for result in tests:
            value = _mapping(result, f"{gate_id}.tests entry")
            test_id = value.get("test_id")
            _require(isinstance(test_id, str), f"{gate_id} contains a test without an ID")
            _require(test_id not in indexed, f"{gate_id} contains duplicate test ID: {test_id}")
            indexed[test_id] = result
        expected_ids = GATE_TEST_IDS[gate_id]
        _require(
            set(indexed) == expected_ids,
            f"{gate_id} test-ID evidence is incomplete or unexpected",
        )
        _require(
            observed_test_ids.isdisjoint(indexed),
            f"{gate_id} reuses a test ID from another gate",
        )
        for test_id in sorted(expected_ids):
            metrics = _validate_test_result(
                source_root, indexed[test_id], test_id, expected_source
            )
            if not preliminary and test_id in FAULT_RAW_TEST_IDS:
                _require(
                    metrics.get("raw_report_schema_version")
                    == RAW_REPORT_SCHEMA_VERSION,
                    f"{test_id}.metrics.raw_report_schema_version differs",
                )
                raw_run_id = metrics.get("raw_report_run_id")
                _require(
                    isinstance(raw_run_id, str)
                    and RUN_ID_PATTERN.fullmatch(raw_run_id) is not None,
                    f"{test_id}.metrics.raw_report_run_id is invalid",
                )
                fault_raw_bindings[test_id] = (
                    RAW_REPORT_SCHEMA_VERSION,
                    raw_run_id,
                    _sha256(metrics, "raw_report_sha256", f"{test_id}.metrics"),
                    _sha256(
                        metrics,
                        "raw_report_binding_sha256",
                        f"{test_id}.metrics",
                    ),
                )
            if not preliminary and test_id in RUNTIME_BOUND_TEST_IDS:
                _require(
                    metrics.get("runtime_schema_version")
                    == RUNTIME_INPUT_SCHEMA_VERSION,
                    f"{test_id}.metrics.runtime_schema_version differs",
                )
                runtime_run_id = metrics.get("runtime_run_id")
                _require(
                    isinstance(runtime_run_id, str)
                    and RUN_ID_PATTERN.fullmatch(runtime_run_id) is not None,
                    f"{test_id}.metrics.runtime_run_id is invalid",
                )
                powershell_path = _absolute_executable_path(
                    metrics,
                    "host_powershell_path",
                    {"powershell.exe", "pwsh.exe", "powershell", "pwsh"},
                    f"{test_id}.metrics",
                )
                python_path = _absolute_executable_path(
                    metrics,
                    "host_python_path",
                    {"python.exe", "python", "python3", "python3.12"},
                    f"{test_id}.metrics",
                )
                docker_path = _absolute_executable_path(
                    metrics,
                    "host_docker_path",
                    {"docker.exe", "docker"},
                    f"{test_id}.metrics",
                )
                compose_path = _absolute_executable_path(
                    metrics,
                    "host_compose_path",
                    {"docker-compose.exe", "docker-compose"},
                    f"{test_id}.metrics",
                )
                runtime_bindings[test_id] = (
                    RUNTIME_INPUT_SCHEMA_VERSION,
                    runtime_run_id,
                    _sha256(metrics, "runtime_input_sha256", f"{test_id}.metrics"),
                    powershell_path,
                    _sha256(metrics, "host_powershell_sha256", f"{test_id}.metrics"),
                    str(metrics["host_powershell_version"]),
                    python_path,
                    _sha256(metrics, "host_python_sha256", f"{test_id}.metrics"),
                    str(metrics["host_python_version"]),
                    docker_path,
                    _sha256(metrics, "host_docker_sha256", f"{test_id}.metrics"),
                    str(metrics["host_docker_version"]),
                    compose_path,
                    _sha256(metrics, "host_compose_sha256", f"{test_id}.metrics"),
                    str(metrics["host_compose_version"]),
                )
            if test_id == "V04-SEC-003":
                sec003_package_sha256 = str(metrics["product_package_sha256"])
            if test_id == "V04-SC-003":
                sc003_package_sha256 = str(metrics["product_package_sha256"])
            if test_id == "V04-SC-004":
                sc004_package_sha256 = str(metrics["package_sha256"])
        observed_test_ids.update(indexed)

        relative_name = relative_path.as_posix()
        evidence_digest.update(relative_name.encode("utf-8"))
        evidence_digest.update(b"\0")
        evidence_digest.update(path.read_bytes())
        evidence_digest.update(b"\0")

    _require(
        observed_test_ids == EXPECTED_TEST_IDS,
        "validated v0.4 Gate 1-5 test-ID set is incomplete",
    )
    if not preliminary:
        _require(
            set(fault_raw_bindings) == FAULT_RAW_TEST_IDS
            and len(set(fault_raw_bindings.values())) == 1,
            "fault-owned final results do not bind one exact raw v2 report",
        )
        _require(
            set(runtime_bindings) == RUNTIME_BOUND_TEST_IDS
            and len(set(runtime_bindings.values())) == 1,
            "runtime-backed final results do not bind one exact runtime/tool identity",
        )
        raw_binding = next(iter(fault_raw_bindings.values()))
        runtime_binding = next(iter(runtime_bindings.values()))
        _require(
            raw_binding[1] == runtime_binding[1],
            "raw report and runtime input run IDs differ",
        )
    _require(sec003_package_sha256 is not None, "V04-SEC-003 package binding is missing")
    _require(sc003_package_sha256 is not None, "V04-SC-003 package binding is missing")
    _require(sc004_package_sha256 is not None, "V04-SC-004 package binding is missing")
    _require(
        sc003_package_sha256 == sc004_package_sha256,
        "V04-SC-003 inspected product package differs from V04-SC-004",
    )
    _require(
        sec003_package_sha256 == sc004_package_sha256,
        "V04-SEC-003 inspected product package differs from V04-SC-004",
    )
    validate_product_package_binding_v04(source_root, sc004_package_sha256)
    return expected_source, evidence_digest.hexdigest()


def validate_fault_provenance_v04(
    root: Path,
    expected_source: str,
) -> dict[str, dict[str, Any]]:
    """Revalidate the retained exact raw/runtime corpora and extracted results."""

    from scripts import qualify_faults_v04 as faults

    source_root = root.resolve()
    provenance_root = source_root / FAULT_PROVENANCE_DIRECTORY
    raw_root = source_root / FAULT_RAW_PROVENANCE_DIRECTORY
    runtime_root = source_root / FAULT_RUNTIME_PROVENANCE_DIRECTORY
    for path, label in (
        (provenance_root, "fault provenance root"),
        (raw_root, "fault raw provenance root"),
        (runtime_root, "fault runtime provenance root"),
    ):
        _require(path.is_dir() and not path.is_symlink(), f"{label} is missing or unsafe")
    entries = tuple(provenance_root.iterdir())
    _require(
        {entry.name for entry in entries} == {"raw", "runtime"}
        and all(entry.is_dir() and not entry.is_symlink() for entry in entries),
        "fault provenance root differs from the exact raw/runtime corpus",
    )
    raw_path = raw_root / "fault-gate-raw.json"
    runtime_path = runtime_root / "runtime-fault-evidence.json"
    raw_document = _load_object(raw_path, "retained fault raw report")
    images = _mapping(raw_document.get("images"), "retained fault raw report.images")
    try:
        report = faults.load_raw_report(
            raw_path,
            source_root,
            artifact_directory=raw_root,
            observed_image_ids=images,
            runtime_input_path=runtime_path,
            require_runtime_readonly=False,
            require_exact_artifact_directory=True,
        )
    except faults.ProbeError as exc:
        raise ValueError(f"retained fault provenance is invalid: {exc}") from exc
    _require(
        report["source_fingerprint_sha256"] == expected_source,
        "retained fault provenance source fingerprint is stale",
    )
    extracted = {
        test_id: faults._extract_raw_result(report, test_id)
        for test_id in sorted(FAULT_RAW_TEST_IDS)
    }
    for test_id, result in extracted.items():
        evidence = _load_object(
            source_root / TEST_EVIDENCE_DIRECTORY / f"{test_id}.json",
            f"{test_id} canonical test evidence",
        )
        _require(
            evidence.get("metrics") == result["metrics"],
            f"{test_id} final metrics differ from retained raw extraction",
        )
        _require(
            evidence.get("assertions") == result["assertions"],
            f"{test_id} final assertions differ from retained raw extraction",
        )
    return extracted


def validate_supply_provenance_v04(
    root: Path,
    expected_source: str,
) -> dict[str, dict[str, Any]]:
    """Revalidate the exact canonical supply corpora against final test results."""

    from scripts.supply_provenance_v04 import (
        DIRECTORY_NAMES,
        SUPPORTED_TEST_IDS,
        validate_supply_corpus,
    )

    source_root = root.resolve()
    provenance_root = source_root / SUPPLY_PROVENANCE_DIRECTORY
    _require(
        provenance_root.is_dir() and not provenance_root.is_symlink(),
        "supply provenance root is missing or unsafe",
    )
    entries = tuple(provenance_root.iterdir())
    _require(
        {entry.name for entry in entries}
        == {DIRECTORY_NAMES[test_id] for test_id in SUPPORTED_TEST_IDS}
        and all(entry.is_dir() and not entry.is_symlink() for entry in entries),
        "supply provenance root differs from the exact SC001/003/004/006 corpus",
    )
    validated: dict[str, dict[str, Any]] = {}
    for test_id in sorted(SUPPORTED_TEST_IDS):
        evidence = _load_object(
            source_root / TEST_EVIDENCE_DIRECTORY / f"{test_id}.json",
            f"{test_id} canonical test evidence",
        )
        metrics = _mapping(evidence.get("metrics"), f"{test_id}.metrics")
        assertions = evidence.get("assertions")
        _require(isinstance(assertions, list), f"{test_id}.assertions is invalid")
        run_id = metrics.get("supply_provenance_run_id")
        _require(
            isinstance(run_id, str) and RUN_ID_PATTERN.fullmatch(run_id) is not None,
            f"{test_id}.metrics.supply_provenance_run_id is invalid",
        )
        result = {
            "test_id": test_id,
            "source_fingerprint_sha256": expected_source,
            "assertions": assertions,
            "metrics": metrics,
        }
        try:
            value = validate_supply_corpus(
                source_root,
                provenance_root / DIRECTORY_NAMES[test_id],
                expected_test_id=test_id,
                expected_source=expected_source,
                expected_result=result,
                expected_run_id=run_id,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(f"retained {test_id} supply provenance is invalid: {exc}") from exc
        validated[test_id] = value
    return validated


def validate_browser_provenance_results_v04(
    root: Path,
    expected_source: str,
) -> dict[str, Any]:
    """Bind every canonical browser result to one retained browser corpus."""

    from scripts import qualify_browser_v04 as browser

    try:
        binding = browser.validate_browser_provenance_v04(root, expected_source)
    except browser.BrowserQualificationError as exc:
        raise ValueError(f"retained browser provenance is invalid: {exc}") from exc
    _require(
        set(binding) == BROWSER_PROVENANCE_METRIC_KEYS,
        "retained browser provenance binding shape differs",
    )
    for test_id in sorted(BROWSER_PROVENANCE_TEST_IDS):
        evidence = _load_object(
            root / TEST_EVIDENCE_DIRECTORY / f"{test_id}.json",
            f"{test_id} canonical test evidence",
        )
        metrics = _mapping(evidence.get("metrics"), f"{test_id}.metrics")
        observed = {key: metrics.get(key) for key in BROWSER_PROVENANCE_METRIC_KEYS}
        _require(
            observed == binding,
            f"{test_id} final metrics differ from retained browser provenance",
        )
    return binding


def validate_sboms_v04(root: Path, expected_source: str | None = None) -> tuple[str, ...]:
    """Validate the exact distinct backend/proxy/frontend/driver SBOM set."""

    source_root = root.resolve()
    expected_source = expected_source or source_fingerprint_v04(source_root)
    directory = source_root / SBOM_DIRECTORY
    if not directory.is_dir() or directory.is_symlink():
        raise FileNotFoundError("required v0.4 SBOM directory is missing")

    discovered = {path.name for path in directory.glob("*.cdx.json") if path.is_file()}
    _require(
        discovered == set(SBOM_FILES),
        "v0.4 SBOM directory does not contain the exact four-image inventory set",
    )
    manifest_path = directory / "SHA256SUMS"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise FileNotFoundError("required v0.4 SBOM checksum manifest is missing")
    try:
        lines = manifest_path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("v0.4 SBOM checksum manifest is not ASCII") from exc
    manifest: dict[str, str] = {}
    for line in lines:
        checksum, separator, name = line.partition("  ")
        if (
            separator != "  "
            or SHA256_PATTERN.fullmatch(checksum) is None
            or name in manifest
        ):
            raise ValueError("v0.4 SBOM checksum manifest has an invalid entry")
        manifest[name] = checksum
    _require(
        set(manifest) == set(SBOM_FILES),
        "v0.4 SBOM checksum manifest does not name the exact four inventories",
    )

    image_ids: list[str] = []
    subject_names: list[str] = []
    for name in SBOM_FILES:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"required v0.4 SBOM inventory is missing: {name}")
        inventory = _load_object(path, "SBOM inventory")
        _reject_disallowed_claims(inventory, name)
        _require(
            inventory.get("bomFormat") == "CycloneDX"
            and inventory.get("specVersion") in {"1.4", "1.5", "1.6"}
            and inventory.get("version") == 1,
            f"v0.4 SBOM inventory header is invalid: {name}",
        )
        components = inventory.get("components")
        _require(
            isinstance(components, list) and bool(components),
            f"v0.4 SBOM inventory is empty: {name}",
        )
        _require(
            all(
                isinstance(component, dict)
                and isinstance(component.get("name"), str)
                and bool(component["name"])
                for component in components
            ),
            f"v0.4 SBOM inventory has an invalid component: {name}",
        )
        component_names = {component["name"].casefold() for component in components}
        missing = SBOM_REQUIRED_COMPONENTS[name] - component_names
        _require(
            not missing,
            f"v0.4 SBOM inventory is missing required components for {name}: "
            + ", ".join(sorted(missing)),
        )
        for required_name in SBOM_REQUIRED_COMPONENTS[name]:
            matching = [
                component
                for component in components
                if component["name"].casefold() == required_name
            ]
            _require(
                len(matching) == 1,
                f"v0.4 SBOM required component is ambiguous: {name}: {required_name}",
            )
            licenses = matching[0].get("licenses")
            _require(
                isinstance(licenses, list)
                and bool(licenses)
                and all(
                    isinstance(item, dict)
                    and (
                        isinstance(item.get("expression"), str)
                        and bool(item["expression"])
                        or isinstance(item.get("license"), dict)
                        and any(
                            isinstance(item["license"].get(key), str)
                            and bool(item["license"][key])
                            for key in ("id", "name")
                        )
                    )
                    for item in licenses
                ),
                f"v0.4 SBOM required component has no license: {name}: {required_name}",
            )
        metadata = _mapping(inventory.get("metadata"), f"{name}.metadata")
        subject = _mapping(metadata.get("component"), f"{name}.metadata.component")
        subject_name = subject.get("name")
        image_id = subject.get("version")
        _require(
            subject.get("type") == "container"
            and subject_name == SBOM_SUBJECTS[name]
            and isinstance(image_id, str)
            and IMAGE_ID_PATTERN.fullmatch(image_id) is not None,
            f"v0.4 SBOM inventory subject is invalid: {name}",
        )
        properties = metadata.get("properties")
        _require(isinstance(properties, list), f"v0.4 SBOM source binding is missing: {name}")
        fingerprint_values = [
            item.get("value")
            for item in properties
            if isinstance(item, dict)
            and item.get("name") == SBOM_SOURCE_FINGERPRINT_PROPERTY
        ]
        image_values = [
            item.get("value")
            for item in properties
            if isinstance(item, dict) and item.get("name") == SBOM_IMAGE_ID_PROPERTY
        ]
        _require(
            fingerprint_values == [expected_source],
            f"v0.4 SBOM source fingerprint is stale: {name}",
        )
        _require(
            image_values == [image_id],
            f"v0.4 SBOM image identity binding is invalid: {name}",
        )
        actual_checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        _require(
            actual_checksum == manifest[name],
            f"v0.4 SBOM checksum does not match inventory: {name}",
        )
        subject_names.append(str(subject_name))
        image_ids.append(str(image_id))

    _require(len(set(subject_names)) == 4, "v0.4 SBOM subjects are not distinct")
    _require(len(set(image_ids)) == 4, "v0.4 SBOM image identities are not distinct")
    return tuple(image_ids)


def validate_release_evidence_v04(
    root: Path,
    *,
    preliminary: bool = False,
) -> ReleaseEvidenceValidationV04:
    source_root = root.resolve()
    source, evidence = validate_gate_evidence_v04(
        source_root, preliminary=preliminary
    )
    image_ids = validate_sboms_v04(source_root, source)
    sc001 = _load_object(
        source_root / TEST_EVIDENCE_DIRECTORY / "V04-SC-001.json",
        "V04-SC-001 test evidence",
    )
    sc001_metrics = _mapping(sc001.get("metrics"), "V04-SC-001.metrics")
    audited_images = _mapping(
        sc001_metrics.get("audited_image_ids"), "V04-SC-001.metrics.audited_image_ids"
    )
    sc003 = _load_object(
        source_root / TEST_EVIDENCE_DIRECTORY / "V04-SC-003.json",
        "V04-SC-003 test evidence",
    )
    sc003_metrics = _mapping(sc003.get("metrics"), "V04-SC-003.metrics")
    inspected_images = _mapping(
        sc003_metrics.get("inspected_image_ids"),
        "V04-SC-003.metrics.inspected_image_ids",
    )
    audited_dependencies = _mapping(
        sc001_metrics.get("compose_dependency_audited_image_ids"),
        "V04-SC-001.metrics.compose_dependency_audited_image_ids",
    )
    inspected_dependencies = _mapping(
        sc003_metrics.get("compose_dependency_inspected_image_ids"),
        "V04-SC-003.metrics.compose_dependency_inspected_image_ids",
    )
    inventoried_images = {
        name.partition(".")[0]: image_id
        for name, image_id in zip(SBOM_FILES, image_ids)
    }
    _require(
        audited_images == inventoried_images,
        "V04-SC-001 audited image identities differ from the SBOM inputs",
    )
    _require(
        inspected_images == inventoried_images,
        "V04-SC-003 inspected image identities differ from the SBOM inputs",
    )
    _require(
        audited_dependencies == inspected_dependencies,
        "V04-SC-001/003 Compose dependency image identities differ",
    )
    validate_supply_provenance_v04(source_root, source)
    if not preliminary:
        validate_browser_provenance_results_v04(source_root, source)
        validate_fault_provenance_v04(source_root, source)
    return ReleaseEvidenceValidationV04(
        source_fingerprint_sha256=source,
        evidence_fingerprint_sha256=evidence,
        validated_gate_ids=tuple(GATE_REPORTS),
        validated_test_ids=tuple(sorted(EXPECTED_TEST_IDS)),
        sbom_image_ids=image_ids,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--preliminary",
        action="store_true",
        help="validate canonical gate evidence before retained fault provenance is published",
    )
    args = parser.parse_args()
    result = validate_release_evidence_v04(
        args.root.resolve(), preliminary=args.preliminary
    )
    print(
        json.dumps(
            {
                "source_fingerprint_sha256": result.source_fingerprint_sha256,
                "evidence_fingerprint_sha256": result.evidence_fingerprint_sha256,
                "validated_gate_ids": list(result.validated_gate_ids),
                "validated_test_count": len(result.validated_test_ids),
                "validated_sbom_image_count": len(result.sbom_image_ids),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
