#!/usr/bin/env python3
"""Source-bound Gate 1-2 contract, fault, and secret qualification probes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v04 import source_fingerprint_v04
from scripts.supply_chain_v04 import inspect_product_package_inputs_v04
from scripts.validate_release_evidence_v04 import SEMANTIC_VALIDATORS


CONTRACT_IDS = {"V04-CON-001", "V04-CON-002", "V04-CON-003"}
FAULT_TEST_NODES: dict[str, tuple[str, ...]] = {
    "V04-SCOPE-002": (
        "backend/tests/test_procedure_parser.py::test_parser_creates_ir_without_executing_source",
        "backend/tests/test_driver_api.py::test_browser_facing_driver_handlers_have_no_synchronous_driver_call_path",
        "backend/tests/test_driver_isolation.py::test_spawned_worker_has_no_driver_product_call_path_or_credential_argument",
    ),
    "V04-SEC-002": (
        "backend/tests/test_driver_persistence.py::test_credential_rotation_is_fenced_source_bound_and_atomically_audited",
        "backend/tests/test_driver_persistence.py::test_credential_rotation_refuses_an_unfenced_host_generation",
        "backend/tests/test_driver_gateway.py::test_rotated_epoch_and_persisted_profile_digest_drive_the_next_handshake",
    ),
    "V04-MIG-002": (
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_sqlite_database_without_record_drift",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
    ),
    "V04-MIG-004": (
        "backend/tests/test_backup_rollback.py",
    ),
    "V04-SEC-004": (
        "backend/tests/test_driver_mtls.py::test_ambiguous_raw_wire_is_rejected_before_dispatch_or_journal_effect",
        "scripts/tests/test_runtime_fault_probe_v04.py::test_projection_probe_fails_closed_without_bearer_environment",
    ),
    "V04-BOUND-002": (
        "backend/tests/test_driver_isolation.py::test_compose_statically_isolates_and_hardens_the_driver",
        "scripts/tests/test_runtime_fault_probe_v04.py::test_projection_observation_uses_internal_fixed_url_and_never_returns_token",
    ),
    "V04-ISO-003": (
        "driver_host/tests/test_process_faults.py::test_unresponsive_host_is_killed_after_grace_and_acceptance_stays_reconciling",
        "backend/tests/test_driver_process_faults.py::test_api_process_crash_at_project_commit_is_atomic_and_reconstructable",
    ),
    "V04-ISO-004": (
        "backend/tests/test_driver_isolation.py::test_compose_statically_isolates_and_hardens_the_driver",
        "backend/tests/test_driver_isolation.py::test_spawned_worker_has_no_driver_product_call_path_or_credential_argument",
    ),
    "V04-CON-003": (
        "driver_host/tests/test_wire.py",
        "backend/tests/test_driver_mtls.py::test_ambiguous_raw_wire_is_rejected_before_dispatch_or_journal_effect",
    ),
    "V04-DEAD-004": (
        "driver_host/tests/test_process_faults.py::test_unresponsive_host_is_killed_after_grace_and_acceptance_stays_reconciling",
    ),
    "V04-JRN-001": (
        "driver_host/tests/test_process_faults.py::test_process_crash_boundaries_preserve_persist_before_effect_and_no_resend",
        "backend/tests/test_driver_process_faults.py::test_api_process_crash_at_project_commit_is_atomic_and_reconstructable",
    ),
    "V04-REC-003": (
        "driver_host/tests/test_process_faults.py::test_process_crash_boundaries_preserve_persist_before_effect_and_no_resend",
        "backend/tests/test_driver_process_faults.py::test_api_process_crash_preserves_durable_dispatch_boundary",
        "backend/tests/test_driver_process_faults.py::test_api_process_crash_at_project_commit_is_atomic_and_reconstructable",
    ),
    "V04-REC-005": (
        "backend/tests/test_driver_gateway.py::test_poll_task_survives_storage_outage_and_resumes_observation_without_restart",
        "backend/tests/test_driver_process_faults.py::test_api_process_crash_at_project_commit_is_atomic_and_reconstructable",
    ),
    "V04-API-003": (
        "backend/tests/test_api_execution.py::test_unsigned_identity_headers_cannot_elevate_a_viewer",
        "backend/tests/test_api_execution.py::test_revision_and_idempotency_guards",
        "backend/tests/test_api_execution.py::test_creation_is_idempotent_and_websocket_replays_versioned_events",
        "backend/tests/test_api_execution.py::test_established_websocket_closes_when_credential_expires",
        "backend/tests/test_driver_persistence.py::test_competing_reconciliation_commits_one_authoritative_public_result",
    ),
    "V04-API-002": (
        "backend/tests/test_driver_api.py::test_driver_projection_is_authenticated_read_only_and_disabled_by_default",
        "backend/tests/test_driver_stream.py::test_driver_websocket_is_authenticated_ordered_replay_only_and_deduplicated",
        "backend/tests/test_driver_api.py::test_browser_facing_driver_handlers_have_no_synchronous_driver_call_path",
    ),
}
ASSIGNED_IDS = {
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
RUNTIME_CAPTURE_IDS = {
    "V04-SCOPE-002",
    "V04-MIG-004",
    "V04-SEC-002",
    "V04-SEC-004",
    "V04-BOUND-002",
    "V04-ISO-003",
    "V04-ISO-004",
    "V04-REC-005",
}
RUNTIME_COMMAND_ENVIRONMENT_KEYS = {
    "V04-SCOPE-002": (
        "DATABASE_URL",
        "SPELL_RUNTIME_CONTEXT_FILE",
        "SPELL_RUNTIME_OPERATOR_TOKEN",
    ),
    "V04-MIG-004": ("DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE"),
    "V04-SEC-002": (
        "DATABASE_URL",
        "SPELL_RUNTIME_CONTEXT_FILE",
        "SPELL_RUNTIME_OPERATOR_TOKEN",
    ),
    "V04-SEC-004": (
        "SPELL_RUNTIME_CONTEXT_FILE",
        "SPELL_RUNTIME_JWT_SECRET",
        "SPELL_RUNTIME_OPERATOR_TOKEN",
    ),
    "V04-BOUND-002": ("SPELL_RUNTIME_CONTEXT_FILE",),
    "V04-ISO-003": (
        "SPELL_RUNTIME_CONTEXT_FILE",
        "SPELL_RUNTIME_OPERATOR_TOKEN",
    ),
    "V04-ISO-004": ("SPELL_RUNTIME_CONTEXT_FILE",),
    "V04-REC-005": ("DATABASE_URL", "SPELL_RUNTIME_CONTEXT_FILE"),
}

RAW_REPORT_SCHEMA_VERSION = "spell.v04.fault-gate-raw/2"
RUNTIME_INPUT_SCHEMA_VERSION = "spell.v04.fault-runtime-input/1"
RAW_REPORT_MAX_BYTES = 16 * 1024 * 1024
RAW_ARTIFACT_MAX_BYTES = 1024 * 1024 * 1024
RAW_REPORT_IMAGE_ROLES = {
    "backend",
    "driver",
    "generator",
    "pki_init",
    "postgres",
    "proxy",
    "qualification",
}
SEC003_PREPUBLISH_CATEGORIES = {
    "frontend_bundle",
    "browser_storage",
    "screenshots",
    "sboms",
    "runtime_captures",
}
SEC003_SBOM_FILENAMES = {
    "backend.cdx.json",
    "driver.cdx.json",
    "frontend.cdx.json",
    "proxy.cdx.json",
}
RAW_REPORT_BINDING_FIELDS = (
    "schema_version",
    "captured_at",
    "run_id",
    "source_fingerprint_sha256",
    "complete",
    "preliminary",
    "source_frozen",
    "images",
    "commands",
    "artifacts",
    "results",
    "runtime_input_sha256",
)
RAW_REPORT_KEYS = {*RAW_REPORT_BINDING_FIELDS, "report_binding_sha256"}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
COMMAND_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
ARTIFACT_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
UNSAFE_RECORDED_ARG_PATTERN = re.compile(
    r"(?i)(?:authorization:\s*bearer\s+|(?:password|private[-_]?key|secret|token)=.+)"
)
SENSITIVE_RECORDED_ARG_FLAGS = frozenset(
    {
        "--authorization",
        "--bearer-token",
        "--client-key",
        "--password",
        "--private-key",
        "--secret",
        "--token",
    }
)
UNSAFE_RECORDED_STRING_PATTERNS = (
    re.compile(r"(?i)-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----"),
    re.compile(r"(?i)authorization:\s*bearer\s+\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)://[^/@\s:]+:[^/@\s]+@"),
)
UNSAFE_ARTIFACT_BYTE_PATTERNS = (
    re.compile(rb"(?i)-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----"),
    re.compile(rb"(?i)authorization:\s*bearer\s+\S+"),
    re.compile(rb"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(rb"(?i)://[^/@\s:]+:[^/@\s]+@"),
    re.compile(
        rb"(?i)(?:password|private[-_]?key|client[-_]?key|secret|token)"
        rb"[\"']?\s*[:=]\s*[\"']?[^\s\"',}]+"
    ),
)
SENSITIVE_KEY_SUFFIXES = (
    "_password",
    "_private_key",
    "_client_key",
    "_secret",
    "_token",
)
ARTIFACT_KINDS = {
    "command-stderr",
    "command-stdout",
    "packet-capture",
    "postgres-dump",
    "runtime-json",
    "service-log",
    "test-output",
    "test-evidence",
}
RAW_CHILD_ENVIRONMENT_BASELINE = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TZ",
    "WINDIR",
}
CANONICAL_WRAPPER_DATABASE_URL = "sqlite:///:memory:"


@dataclass(frozen=True)
class RawEvidenceBinding:
    test_id: str
    command_id: str
    stdout_artifact_id: str
    stderr_artifact_id: str
    evidence_artifact_id: str
    executor: str
    argv: tuple[str, ...]
    environment_keys: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeInputBinding:
    sha256: str
    run_id: str
    source_fingerprint_sha256: str
    images: dict[str, str]
    results: dict[str, dict[str, Any]]
    host_powershell_path: str
    host_powershell_sha256: str
    host_powershell_version: str
    host_python_path: str
    host_python_sha256: str
    host_python_version: str
    host_docker_path: str
    host_docker_sha256: str
    host_docker_version: str
    host_compose_path: str
    host_compose_sha256: str
    host_compose_version: str


def _raw_evidence_binding(test_id: str) -> RawEvidenceBinding:
    stem = test_id.casefold()
    command_id = f"probe-{stem}"
    argv = (
        "python",
        "scripts/qualify_faults_v04.py",
        test_id,
        "--root",
        "/qualification-source",
    )
    if test_id == "V04-SEC-003":
        argv += ("--prepublish-root", "/prepublish")
    if test_id in RUNTIME_CAPTURE_IDS:
        argv += (
            "--runtime-input",
            "/runtime-input/runtime-fault-evidence.json",
        )
    environment_keys: list[str] = ["DATABASE_URL"]
    if test_id == "V04-MIG-002":
        environment_keys.append("SPELL_MIGRATION_TEST_DATABASE_URL")
    if test_id in RUNTIME_CAPTURE_IDS:
        environment_keys.extend(
            ("SPELL_FAULT_RUN_ID", "SPELL_FAULT_IMAGE_BINDING_SHA256")
        )
    return RawEvidenceBinding(
        test_id=test_id,
        command_id=command_id,
        stdout_artifact_id=f"{command_id}.stdout",
        stderr_artifact_id=f"{command_id}.stderr",
        evidence_artifact_id=f"{command_id}.evidence",
        executor="qualification",
        argv=argv,
        environment_keys=tuple(environment_keys),
    )


RAW_EVIDENCE_BINDINGS = {
    test_id: _raw_evidence_binding(test_id) for test_id in sorted(ASSIGNED_IDS)
}


class ProbeError(RuntimeError):
    pass


def parse_observed_image_ids(values: Iterable[str]) -> dict[str, str]:
    """Parse one independently observed exact image ID for every raw role."""

    observed: dict[str, str] = {}
    for item in values:
        if not isinstance(item, str):
            raise ProbeError("observed image binding must be text")
        role, separator, image_id = item.partition("=")
        if (
            separator != "="
            or role not in RAW_REPORT_IMAGE_ROLES
            or not image_id
        ):
            raise ProbeError("observed image binding has an unknown or invalid role")
        if role in observed:
            raise ProbeError(f"observed image role is duplicated: {role}")
        if IMAGE_ID_PATTERN.fullmatch(image_id) is None:
            raise ProbeError(f"observed image ID is invalid: {role}")
        observed[role] = image_id
    if set(observed) != RAW_REPORT_IMAGE_ROLES:
        missing = sorted(RAW_REPORT_IMAGE_ROLES - set(observed))
        raise ProbeError(
            "observed image role set is incomplete; " f"missing={missing!r}"
        )
    if len(set(observed.values())) != len(RAW_REPORT_IMAGE_ROLES):
        raise ProbeError("observed image IDs must be distinct across roles")
    return dict(sorted(observed.items()))


def runtime_image_binding_sha256(images: dict[str, str]) -> str:
    """Bind the exact role-to-image mapping supplied to live fault capture."""

    return _sha256(_canonical_json(dict(sorted(images.items()))))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _strict_json(text: str, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ProbeError(f"{label} contains duplicate object key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ProbeError(f"{label} contains non-finite JSON number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProbeError(f"{label} is not strict JSON") from exc


def _locked_release_tool(
    root: Path,
    name: str,
    version_key: str,
) -> tuple[str, str, str]:
    lock_path = root / "scripts/release-toolchain-v04.json"
    if not lock_path.is_file() or lock_path.is_symlink():
        raise ProbeError("release toolchain lock is missing or unsafe")
    try:
        lock = _strict_json(lock_path.read_text(encoding="utf-8"), "release toolchain lock")
    except UnicodeDecodeError as exc:
        raise ProbeError("release toolchain lock is not UTF-8") from exc
    if not isinstance(lock, dict) or lock.get("schema_version") != "spell.v04.release-toolchain/1":
        raise ProbeError("release toolchain lock schema differs")
    tools = lock.get("tools")
    versions = lock.get("versions")
    if not isinstance(tools, list) or not isinstance(versions, dict):
        raise ProbeError("release toolchain lock structure differs")
    matches = [item for item in tools if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        raise ProbeError(f"release toolchain lock entry differs: {name}")
    tool = matches[0]
    relative = tool.get("relative_path")
    sha256 = tool.get("sha256")
    version = versions.get(version_key)
    if (
        tool.get("base_directory") not in {"LocalAppData", "ProgramFiles"}
        or not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or not isinstance(sha256, str)
        or SHA256_PATTERN.fullmatch(sha256) is None
        or not isinstance(version, str)
        or not version
    ):
        raise ProbeError(f"release toolchain lock binding differs: {name}")
    return relative, sha256, version


def _validate_locked_tool_binding(
    binding: tuple[str, str, str],
    contract: tuple[str, str, str],
    *,
    base_directory: str,
    label: str,
) -> None:
    path, sha256, version = binding
    relative, expected_sha256, expected_version = contract
    normalized = path.replace("\\", "/").rstrip("/")
    relative_normalized = relative.replace("\\", "/").strip("/")
    if not normalized.casefold().endswith("/" + relative_normalized.casefold()):
        raise ProbeError(f"{label} path differs from the release toolchain lock")
    prefix = normalized[: -(len(relative_normalized) + 1)].rstrip("/")
    if base_directory == "LocalAppData":
        base_matches = prefix.casefold().endswith("/appdata/local")
    else:
        base_matches = PureWindowsPath(prefix).name.casefold() == "program files"
    if not base_matches or sha256 != expected_sha256 or version != expected_version:
        raise ProbeError(f"{label} differs from the release toolchain lock")


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        raise ProbeError(
            f"{label} keys differ; missing={missing!r} unexpected={unexpected!r}"
        )


def _lower_key(value: str) -> str:
    return value.casefold().replace("-", "_")


def _reject_secret_material(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _lower_key(key)
            if normalized in {
                "authorization",
                "client_key",
                "jwt_token",
                "password",
                "private_key",
                "secret",
                "token",
            } or normalized.endswith(SENSITIVE_KEY_SUFFIXES):
                raise ProbeError(f"{label} contains forbidden secret-bearing key: {key}")
            _reject_secret_material(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_material(item, f"{label}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in UNSAFE_RECORDED_STRING_PATTERNS):
            raise ProbeError(f"{label} contains credential-like material")


def _runtime_readonly_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ProbeError(f"{label} is missing or unsafe")
    if not path.stat().st_mode & 0o222:
        return
    statvfs = getattr(os, "statvfs", None)
    readonly_flag = getattr(os, "ST_RDONLY", 1)
    if statvfs is not None:
        try:
            if statvfs(path).f_flag & readonly_flag:
                return
        except OSError:
            pass
    raise ProbeError(f"{label} is not read-only")


def _scan_runtime_artifact(path: Path, label: str, source: str) -> None:
    canary = f"spell-v04-service-secret-{source}".encode("ascii")
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            window = tail + chunk
            if canary in window or any(
                pattern.search(window) for pattern in UNSAFE_ARTIFACT_BYTE_PATTERNS
            ):
                raise ProbeError(f"{label} contains credential-like material")
            tail = window[-512:]


def load_runtime_input(
    path: Path,
    *,
    expected_source: str,
    expected_images: dict[str, str] | None = None,
    require_environment_binding: bool = False,
    require_readonly: bool = True,
    release_toolchain_root: Path = ROOT,
) -> RuntimeInputBinding:
    """Load and verify one immutable, source-bound live fault capture."""

    if path.name != "runtime-fault-evidence.json":
        raise ProbeError("runtime input must use the canonical filename")
    if require_readonly:
        _runtime_readonly_file(path, "runtime input")
    elif not path.is_file() or path.is_symlink():
        raise ProbeError("runtime input is missing or unsafe")
    size = path.stat().st_size
    if size <= 0 or size > RAW_REPORT_MAX_BYTES:
        raise ProbeError("runtime input size is outside the bounded range")
    payload = path.read_bytes()
    try:
        document = _strict_json(payload.decode("utf-8"), "runtime input")
    except UnicodeDecodeError as exc:
        raise ProbeError("runtime input is not UTF-8") from exc
    if not isinstance(document, dict):
        raise ProbeError("runtime input must be an object")
    _exact_keys(
        document,
        {
            "schema_version",
            "captured_at",
            "run_id",
            "source_fingerprint_sha256",
            "complete",
            "source_frozen",
            "images",
            "compose",
            "commands",
            "artifacts",
            "results",
        },
        "runtime input",
    )
    if document["schema_version"] != RUNTIME_INPUT_SCHEMA_VERSION:
        raise ProbeError("runtime input schema version differs")
    if document["complete"] is not True or document["source_frozen"] is not True:
        raise ProbeError("runtime input is incomplete or not source-frozen")
    captured_at = document["captured_at"]
    if not isinstance(captured_at, str) or not captured_at:
        raise ProbeError("runtime input captured_at is invalid")
    try:
        observed_at = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProbeError("runtime input captured_at is not an ISO timestamp") from exc
    if observed_at.utcoffset() is None or observed_at.utcoffset().total_seconds() != 0:
        raise ProbeError("runtime input captured_at must be UTC")
    run_id = document["run_id"]
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise ProbeError("runtime input run_id is invalid")
    source = document["source_fingerprint_sha256"]
    if source != expected_source:
        raise ProbeError("runtime input has a stale source fingerprint")

    images = document["images"]
    if (
        not isinstance(images, dict)
        or set(images) != RAW_REPORT_IMAGE_ROLES
        or any(
            not isinstance(image_id, str)
            or IMAGE_ID_PATTERN.fullmatch(image_id) is None
            for image_id in images.values()
        )
        or len(set(images.values())) != len(RAW_REPORT_IMAGE_ROLES)
    ):
        raise ProbeError("runtime input image binding is incomplete or invalid")
    images = dict(sorted(images.items()))
    if expected_images is not None and images != expected_images:
        raise ProbeError("runtime input image IDs differ from independent observations")
    if require_environment_binding:
        if os.environ.get("SPELL_FAULT_RUN_ID") != run_id:
            raise ProbeError("runtime input run ID differs from the bound environment")
        if os.environ.get("SPELL_FAULT_IMAGE_BINDING_SHA256") != (
            runtime_image_binding_sha256(images)
        ):
            raise ProbeError("runtime input image map differs from the bound environment")

    compose = document["compose"]
    if not isinstance(compose, dict):
        raise ProbeError("runtime input compose binding must be an object")
    _exact_keys(compose, {"project_name", "container_ids"}, "runtime input compose")
    project_name = compose["project_name"]
    if (
        not isinstance(project_name, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_name) is None
    ):
        raise ProbeError("runtime input compose project name is invalid")
    container_ids = compose["container_ids"]
    expected_container_roles = {"backend", "driver", "postgres", "proxy"}
    if (
        not isinstance(container_ids, dict)
        or set(container_ids) != expected_container_roles
        or any(
            not isinstance(container_id, str)
            or CONTAINER_ID_PATTERN.fullmatch(container_id) is None
            for container_id in container_ids.values()
        )
        or len(set(container_ids.values())) != len(expected_container_roles)
    ):
        raise ProbeError("runtime input compose container binding is invalid")

    runtime_root = path.parent
    artifact_root = runtime_root / "artifacts"
    if not runtime_root.is_dir() or runtime_root.is_symlink():
        raise ProbeError("runtime input root is missing or unsafe")
    runtime_entries = tuple(runtime_root.iterdir())
    if (
        {entry.name for entry in runtime_entries}
        != {"runtime-fault-evidence.json", "artifacts"}
        or any(entry.is_symlink() for entry in runtime_entries)
    ):
        raise ProbeError("runtime input root differs from the exact corpus")
    if not artifact_root.is_dir() or artifact_root.is_symlink():
        raise ProbeError("runtime input artifact root is missing or unsafe")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ProbeError("runtime input artifacts must be a nonempty array")
    artifacts_by_id: dict[str, dict[str, Any]] = {}
    artifact_files: dict[str, Path] = {}
    artifact_paths: set[str] = set()
    for value in artifacts:
        if not isinstance(value, dict):
            raise ProbeError("runtime input artifact must be an object")
        _exact_keys(value, {"id", "path", "kind", "sha256", "bytes"}, "runtime input artifact")
        artifact_id = value["id"]
        relative = value["path"]
        if (
            not isinstance(artifact_id, str)
            or ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None
            or artifact_id in artifacts_by_id
        ):
            raise ProbeError("runtime input artifact ID is invalid or duplicated")
        if (
            not isinstance(relative, str)
            or not relative.startswith("artifacts/")
            or relative.endswith("/")
            or "\\" in relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in artifact_paths
        ):
            raise ProbeError("runtime input artifact path is unsafe or duplicated")
        if value["kind"] not in ARTIFACT_KINDS:
            raise ProbeError(f"runtime input artifact kind is invalid: {relative}")
        if (
            not isinstance(value["sha256"], str)
            or SHA256_PATTERN.fullmatch(value["sha256"]) is None
            or type(value["bytes"]) is not int
            or not 0 <= value["bytes"] <= RAW_ARTIFACT_MAX_BYTES
        ):
            raise ProbeError(f"runtime input artifact metadata is invalid: {relative}")
        parts = Path(relative).parts
        actual = runtime_root.joinpath(*parts)
        for parent in actual.parents:
            if parent == runtime_root:
                break
            if parent.is_symlink():
                raise ProbeError(f"runtime input artifact parent is unsafe: {relative}")
        if require_readonly:
            _runtime_readonly_file(actual, f"runtime input artifact {relative}")
        elif not actual.is_file() or actual.is_symlink():
            raise ProbeError(f"runtime input artifact is missing or unsafe: {relative}")
        if actual.stat().st_size != value["bytes"]:
            raise ProbeError(f"runtime input artifact size differs: {relative}")
        if _file_sha256(actual) != value["sha256"]:
            raise ProbeError(f"runtime input artifact digest differs: {relative}")
        _scan_runtime_artifact(actual, f"runtime input artifact {relative}", source)
        artifacts_by_id[artifact_id] = value
        artifact_files[artifact_id] = actual
        artifact_paths.add(relative)

    expected_files = {Path(relative) for relative in artifact_paths}
    expected_directories = {
        parent
        for relative in expected_files
        for parent in relative.parents
        if parent != Path(".") and parent != Path("artifacts")
    }
    observed_files: set[Path] = set()
    observed_directories: set[Path] = set()
    for entry in artifact_root.rglob("*"):
        relative = entry.relative_to(runtime_root)
        if entry.is_symlink():
            raise ProbeError(f"runtime input artifact tree contains a symlink: {relative}")
        if entry.is_file():
            observed_files.add(relative)
        elif entry.is_dir():
            observed_directories.add(relative)
        else:
            raise ProbeError(f"runtime input artifact tree contains an unsafe entry: {relative}")
    if observed_files != expected_files or observed_directories != expected_directories:
        raise ProbeError("runtime input artifact tree differs from the exact manifest")

    commands = document["commands"]
    if not isinstance(commands, list) or len(commands) != len(RUNTIME_CAPTURE_IDS):
        raise ProbeError("runtime input commands differ from the exact command set")
    commands_by_id: dict[str, dict[str, Any]] = {}
    host_powershell_path: str | None = None
    for value in commands:
        if not isinstance(value, dict):
            raise ProbeError("runtime input command must be an object")
        _exact_keys(
            value,
            {
                "id",
                "test_id",
                "executor",
                "argv",
                "exit_code",
                "stdout_artifact_id",
                "stderr_artifact_id",
                "evidence_artifact_id",
                "environment_keys",
                "started_at",
                "finished_at",
            },
            "runtime input command",
        )
        command_id = value["id"]
        test_id = value["test_id"]
        argv = value["argv"]
        environment_keys = value["environment_keys"]
        command_times: list[datetime] = []
        for key in ("started_at", "finished_at"):
            timestamp = value[key]
            if not isinstance(timestamp, str) or not timestamp:
                raise ProbeError(f"runtime input command {key} is invalid")
            try:
                command_time = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ProbeError(f"runtime input command {key} is invalid") from exc
            if (
                command_time.utcoffset() is None
                or command_time.utcoffset().total_seconds() != 0
            ):
                raise ProbeError(f"runtime input command {key} must be UTC")
            command_times.append(command_time)
        if command_times[1] < command_times[0] or command_times[1] > observed_at:
            raise ProbeError("runtime input command timestamps are inconsistent")
        expected_command_id = (
            f"runtime-{test_id.casefold()}" if isinstance(test_id, str) else ""
        )
        expected_argv_tail = [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "scripts/collect_fault_runtime_v04.ps1",
            "-RuntimeProbe",
            test_id,
        ]
        if (
            not isinstance(command_id, str)
            or COMMAND_ID_PATTERN.fullmatch(command_id) is None
            or command_id in commands_by_id
            or not isinstance(test_id, str)
            or test_id not in RUNTIME_CAPTURE_IDS
            or command_id != expected_command_id
            or value["executor"] != "host-powershell"
        ):
            raise ProbeError("runtime input command identity is invalid or duplicated")
        if (
            not isinstance(argv, list)
            or not argv
            or any(
                not isinstance(item, str)
                or not 0 < len(item) <= 1024
                or UNSAFE_RECORDED_ARG_PATTERN.search(item)
                or item.casefold() in SENSITIVE_RECORDED_ARG_FLAGS
                for item in argv
            )
            or len(argv) != 7
            or argv[1:] != expected_argv_tail
        ):
            raise ProbeError(f"runtime input command argv differs or is unsafe: {command_id}")
        executable = argv[0]
        executable_path = PureWindowsPath(executable)
        if not (
            executable_path.is_absolute()
            and executable_path.name.casefold() in {"powershell.exe", "pwsh.exe"}
        ) and not (
            PurePosixPath(executable).is_absolute()
            and PurePosixPath(executable).name.casefold() in {"powershell", "pwsh"}
        ):
            raise ProbeError(f"runtime input command executable is not an absolute PowerShell path: {command_id}")
        if host_powershell_path is None:
            host_powershell_path = executable
        elif executable != host_powershell_path:
            raise ProbeError("runtime input commands used different PowerShell executables")
        if (
            not isinstance(environment_keys, list)
            or environment_keys != sorted(set(environment_keys))
            or any(
                not isinstance(key, str)
                or (
                    key != "DATABASE_URL"
                    and re.fullmatch(r"SPELL_[A-Z0-9_]{1,120}", key) is None
                )
                for key in environment_keys
            )
            or environment_keys != list(RUNTIME_COMMAND_ENVIRONMENT_KEYS[test_id])
        ):
            raise ProbeError(f"runtime input command environment keys are invalid: {command_id}")
        if type(value["exit_code"]) is not int or value["exit_code"] != 0:
            raise ProbeError(f"runtime input command did not pass: {command_id}")
        stdout_id = value["stdout_artifact_id"]
        stderr_id = value["stderr_artifact_id"]
        evidence_id = value["evidence_artifact_id"]
        if (
            stdout_id not in artifacts_by_id
            or stderr_id not in artifacts_by_id
            or evidence_id not in artifacts_by_id
            or len({stdout_id, stderr_id, evidence_id}) != 3
            or artifacts_by_id[stdout_id]["kind"] != "command-stdout"
            or artifacts_by_id[stderr_id]["kind"] != "command-stderr"
            or artifacts_by_id[evidence_id]["kind"] != "test-evidence"
        ):
            raise ProbeError(f"runtime input command artifacts differ: {command_id}")
        commands_by_id[command_id] = value

    results = document["results"]
    if not isinstance(results, dict) or set(results) != RUNTIME_CAPTURE_IDS:
        raise ProbeError("runtime input results differ from the exact live result set")
    command_owners: set[str] = set()
    artifact_owners: set[str] = set()
    host_tool_binding: tuple[str, str, str] | None = None
    host_python_binding: tuple[str, str, str] | None = None
    host_docker_binding: tuple[str, str, str] | None = None
    host_compose_binding: tuple[str, str, str] | None = None
    validated_results: dict[str, dict[str, Any]] = {}
    for test_id in sorted(RUNTIME_CAPTURE_IDS):
        value = results[test_id]
        label = f"runtime input result {test_id}"
        if not isinstance(value, dict):
            raise ProbeError(f"{label} must be an object")
        _exact_keys(
            value,
            {"test_id", "assertions", "metrics", "command_ids", "artifact_ids"},
            label,
        )
        if value["test_id"] != test_id:
            raise ProbeError(f"{label} test ID differs")
        assertions = value["assertions"]
        if not isinstance(assertions, list) or not assertions:
            raise ProbeError(f"{label} assertions must be a nonempty array")
        assertion_ids: set[str] = set()
        for assertion in assertions:
            if not isinstance(assertion, dict):
                raise ProbeError(f"{label} assertion must be an object")
            _exact_keys(assertion, {"id", "passed"}, f"{label} assertion")
            assertion_id = assertion["id"]
            if (
                not isinstance(assertion_id, str)
                or not 0 < len(assertion_id) <= 256
                or assertion_id in assertion_ids
                or assertion["passed"] is not True
            ):
                raise ProbeError(f"{label} assertion is invalid, duplicated, or failed")
            assertion_ids.add(assertion_id)
        metrics = value["metrics"]
        if not isinstance(metrics, dict):
            raise ProbeError(f"{label} metrics must be an object")
        validator = SEMANTIC_VALIDATORS.get(test_id)
        if validator is None:
            raise ProbeError(f"{label} has no semantic validator")
        try:
            validator(metrics, f"{test_id}.runtime_metrics", source)
        except ValueError as exc:
            raise ProbeError(str(exc)) from exc
        host_sha256 = metrics.get("host_powershell_sha256")
        host_version = metrics.get("host_powershell_version")
        python_sha256 = metrics.get("host_python_sha256")
        python_version = metrics.get("host_python_version")
        docker_sha256 = metrics.get("host_docker_sha256")
        docker_version = metrics.get("host_docker_version")
        compose_sha256 = metrics.get("host_compose_sha256")
        compose_version = metrics.get("host_compose_version")
        if (
            not isinstance(host_sha256, str)
            or SHA256_PATTERN.fullmatch(host_sha256) is None
            or not isinstance(host_version, str)
            or not 0 < len(host_version) <= 128
            or any(character.isspace() for character in host_version)
        ):
            raise ProbeError(f"{label} host PowerShell binding is invalid")
        if (
            not isinstance(python_sha256, str)
            or SHA256_PATTERN.fullmatch(python_sha256) is None
            or not isinstance(python_version, str)
            or not 0 < len(python_version) <= 128
            or any(character.isspace() for character in python_version)
        ):
            raise ProbeError(f"{label} host Python binding is invalid")
        for tool_name, tool_sha256, tool_version in (
            ("Docker", docker_sha256, docker_version),
            ("Compose", compose_sha256, compose_version),
        ):
            if (
                not isinstance(tool_sha256, str)
                or SHA256_PATTERN.fullmatch(tool_sha256) is None
                or not isinstance(tool_version, str)
                or not 0 < len(tool_version) <= 128
                or any(character.isspace() for character in tool_version)
            ):
                raise ProbeError(f"{label} host {tool_name} binding is invalid")
        command_ids = value["command_ids"]
        artifact_ids = value["artifact_ids"]
        expected_command_ids = [f"runtime-{test_id.casefold()}"]
        if (
            not isinstance(command_ids, list)
            or command_ids != expected_command_ids
            or len(command_ids) != len(set(command_ids))
            or any(
                command_id not in commands_by_id
                or commands_by_id[command_id]["test_id"] != test_id
                or command_id in command_owners
                for command_id in command_ids
            )
        ):
            raise ProbeError(f"{label} command ownership is invalid")
        required_command_artifacts = {
            artifact_id
            for command_id in command_ids
            for artifact_id in (
                commands_by_id[command_id]["stdout_artifact_id"],
                commands_by_id[command_id]["stderr_artifact_id"],
                commands_by_id[command_id]["evidence_artifact_id"],
            )
        }
        if (
            not isinstance(artifact_ids, list)
            or not artifact_ids
            or len(artifact_ids) != len(set(artifact_ids))
            or not required_command_artifacts.issubset(artifact_ids)
            or any(
                artifact_id not in artifacts_by_id or artifact_id in artifact_owners
                for artifact_id in artifact_ids
            )
        ):
            raise ProbeError(f"{label} artifact ownership is invalid")
        command = commands_by_id[expected_command_ids[0]]
        tool_artifact_id = f"runtime-{test_id.casefold()}.host-powershell"
        if (
            tool_artifact_id not in artifact_ids
            or artifacts_by_id[tool_artifact_id]["kind"] != "runtime-json"
        ):
            raise ProbeError(f"{label} lacks its host PowerShell inspection artifact")
        tool_payload = artifact_files[tool_artifact_id].read_bytes()
        try:
            tool_document = _strict_json(
                tool_payload.decode("utf-8"), f"{label} host PowerShell artifact"
            )
        except UnicodeDecodeError as exc:
            raise ProbeError(f"{label} host PowerShell artifact is not UTF-8") from exc
        expected_tool_document = {
            "path": command["argv"][0],
            "sha256": host_sha256,
            "version": host_version,
        }
        if (
            tool_document != expected_tool_document
            or tool_payload != _canonical_json(expected_tool_document) + b"\n"
        ):
            raise ProbeError(f"{label} host PowerShell artifact differs")
        current_host_binding = (command["argv"][0], host_sha256, host_version)
        if host_tool_binding is None:
            host_tool_binding = current_host_binding
        elif current_host_binding != host_tool_binding:
            raise ProbeError("runtime input results bind different host PowerShell tools")
        python_artifact_id = f"runtime-{test_id.casefold()}.host-python"
        if (
            python_artifact_id not in artifact_ids
            or artifacts_by_id[python_artifact_id]["kind"] != "runtime-json"
        ):
            raise ProbeError(f"{label} lacks its host Python inspection artifact")
        python_payload = artifact_files[python_artifact_id].read_bytes()
        try:
            python_document = _strict_json(
                python_payload.decode("utf-8"), f"{label} host Python artifact"
            )
        except UnicodeDecodeError as exc:
            raise ProbeError(f"{label} host Python artifact is not UTF-8") from exc
        if not isinstance(python_document, dict):
            raise ProbeError(f"{label} host Python artifact must be an object")
        _exact_keys(
            python_document,
            {"path", "sha256", "version"},
            f"{label} host Python artifact",
        )
        python_path = python_document["path"]
        if not isinstance(python_path, str):
            raise ProbeError(f"{label} host Python path is invalid")
        windows_python = PureWindowsPath(python_path)
        posix_python = PurePosixPath(python_path)
        python_name = (
            windows_python.name.casefold()
            if windows_python.is_absolute()
            else posix_python.name.casefold()
        )
        if not (
            (windows_python.is_absolute() or posix_python.is_absolute())
            and re.fullmatch(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", python_name)
        ):
            raise ProbeError(f"{label} host Python path is invalid")
        expected_python_document = {
            "path": python_path,
            "sha256": python_sha256,
            "version": python_version,
        }
        if (
            python_document != expected_python_document
            or python_payload != _canonical_json(expected_python_document) + b"\n"
        ):
            raise ProbeError(f"{label} host Python artifact differs")
        current_python_binding = (python_path, python_sha256, python_version)
        if host_python_binding is None:
            host_python_binding = current_python_binding
        elif current_python_binding != host_python_binding:
            raise ProbeError("runtime input results bind different host Python tools")
        for suffix, expected_sha256, expected_version, expected_names in (
            (
                "host-docker",
                docker_sha256,
                docker_version,
                {"docker.exe", "docker"},
            ),
            (
                "host-compose",
                compose_sha256,
                compose_version,
                {"docker-compose.exe", "docker-compose"},
            ),
        ):
            tool_id = f"runtime-{test_id.casefold()}.{suffix}"
            if (
                tool_id not in artifact_ids
                or artifacts_by_id[tool_id]["kind"] != "runtime-json"
            ):
                raise ProbeError(f"{label} lacks its {suffix} inspection artifact")
            tool_bytes = artifact_files[tool_id].read_bytes()
            try:
                tool_value = _strict_json(
                    tool_bytes.decode("utf-8"), f"{label} {suffix} artifact"
                )
            except UnicodeDecodeError as exc:
                raise ProbeError(f"{label} {suffix} artifact is not UTF-8") from exc
            if not isinstance(tool_value, dict):
                raise ProbeError(f"{label} {suffix} artifact must be an object")
            _exact_keys(
                tool_value,
                {"path", "sha256", "version"},
                f"{label} {suffix} artifact",
            )
            tool_path = tool_value["path"]
            if not isinstance(tool_path, str):
                raise ProbeError(f"{label} {suffix} path is invalid")
            windows_tool = PureWindowsPath(tool_path)
            posix_tool = PurePosixPath(tool_path)
            tool_name = (
                windows_tool.name.casefold()
                if windows_tool.is_absolute()
                else posix_tool.name.casefold()
            )
            if not (
                (windows_tool.is_absolute() or posix_tool.is_absolute())
                and tool_name in expected_names
            ):
                raise ProbeError(f"{label} {suffix} path is invalid")
            expected_value = {
                "path": tool_path,
                "sha256": expected_sha256,
                "version": expected_version,
            }
            if (
                tool_value != expected_value
                or tool_bytes != _canonical_json(expected_value) + b"\n"
            ):
                raise ProbeError(f"{label} {suffix} artifact differs")
            current_binding = (tool_path, expected_sha256, expected_version)
            if suffix == "host-docker":
                if host_docker_binding is None:
                    host_docker_binding = current_binding
                elif current_binding != host_docker_binding:
                    raise ProbeError("runtime input results bind different host Docker tools")
            else:
                if host_compose_binding is None:
                    host_compose_binding = current_binding
                elif current_binding != host_compose_binding:
                    raise ProbeError("runtime input results bind different host Compose tools")
        command_owners.update(command_ids)
        artifact_owners.update(artifact_ids)
        expected_machine_output = {
            "test_id": test_id,
            "assertions": assertions,
            "metrics": metrics,
        }
        canonical_evidence = _canonical_json(expected_machine_output) + b"\n"
        for command_id in command_ids:
            command = commands_by_id[command_id]
            evidence_id = command["evidence_artifact_id"]
            stdout_id = command["stdout_artifact_id"]
            stderr_id = command["stderr_artifact_id"]
            if (
                artifact_files[evidence_id].read_bytes() != canonical_evidence
                or artifact_files[stdout_id].read_bytes() != canonical_evidence
                or artifact_files[stderr_id].read_bytes() != b""
            ):
                raise ProbeError(f"{label} differs from canonical command evidence")
        validated_results[test_id] = value
    if command_owners != set(commands_by_id):
        raise ProbeError("runtime input contains unowned commands")
    if artifact_owners != set(artifacts_by_id):
        raise ProbeError("runtime input contains unowned artifacts")
    _reject_secret_material(document, "runtime input")
    if (
        host_tool_binding is None
        or host_python_binding is None
        or host_docker_binding is None
        or host_compose_binding is None
    ):
        raise ProbeError("runtime input host tool bindings are missing")
    _validate_locked_tool_binding(
        host_python_binding,
        _locked_release_tool(release_toolchain_root, "python", "host_python"),
        base_directory="LocalAppData",
        label="runtime input host Python",
    )
    _validate_locked_tool_binding(
        host_docker_binding,
        _locked_release_tool(release_toolchain_root, "docker-cli", "docker_cli"),
        base_directory="ProgramFiles",
        label="runtime input host Docker",
    )
    _validate_locked_tool_binding(
        host_compose_binding,
        _locked_release_tool(
            release_toolchain_root, "docker-compose", "docker_compose"
        ),
        base_directory="ProgramFiles",
        label="runtime input host Compose",
    )
    return RuntimeInputBinding(
        sha256=_sha256(payload),
        run_id=run_id,
        source_fingerprint_sha256=source,
        images=images,
        results=validated_results,
        host_powershell_path=host_tool_binding[0],
        host_powershell_sha256=host_tool_binding[1],
        host_powershell_version=host_tool_binding[2],
        host_python_path=host_python_binding[0],
        host_python_sha256=host_python_binding[1],
        host_python_version=host_python_binding[2],
        host_docker_path=host_docker_binding[0],
        host_docker_sha256=host_docker_binding[1],
        host_docker_version=host_docker_binding[2],
        host_compose_path=host_compose_binding[0],
        host_compose_sha256=host_compose_binding[1],
        host_compose_version=host_compose_binding[2],
    )


def raw_report_binding(report: dict[str, Any]) -> str:
    """Return the deterministic binding over every substantive raw-report field."""

    try:
        bound = {key: report[key] for key in RAW_REPORT_BINDING_FIELDS}
    except KeyError as exc:
        raise ProbeError(f"raw report is missing binding field: {exc.args[0]}") from exc
    return _sha256(_canonical_json(bound))


def _validate_result(
    test_id: str,
    value: Any,
    *,
    source: str,
    machine_output: dict[str, Any],
) -> dict[str, Any]:
    label = f"raw report result {test_id}"
    if not isinstance(value, dict):
        raise ProbeError(f"{label} must be an object")
    _exact_keys(
        value,
        {
            "test_id",
            "source_fingerprint_sha256",
            "assertions",
            "metrics",
            "command_ids",
            "artifact_ids",
        },
        label,
    )
    if value["test_id"] != test_id:
        raise ProbeError(f"{label} has the wrong test_id")
    if value["source_fingerprint_sha256"] != source:
        raise ProbeError(f"{label} has a stale source fingerprint")

    assertions = value["assertions"]
    if not isinstance(assertions, list) or not assertions:
        raise ProbeError(f"{label} assertions must be a nonempty array")
    observed_assertions: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, dict):
            raise ProbeError(f"{label} assertion must be an object")
        _exact_keys(assertion, {"id", "passed"}, f"{label} assertion")
        assertion_id = assertion["id"]
        if (
            not isinstance(assertion_id, str)
            or not assertion_id
            or len(assertion_id) > 256
            or assertion_id in observed_assertions
        ):
            raise ProbeError(f"{label} assertion id is invalid or duplicated")
        if assertion["passed"] is not True:
            raise ProbeError(f"{label} assertion did not pass: {assertion_id}")
        observed_assertions.add(assertion_id)

    metrics = value["metrics"]
    if not isinstance(metrics, dict):
        raise ProbeError(f"{label} metrics must be an object")
    try:
        _canonical_json(metrics)
    except (TypeError, ValueError) as exc:
        raise ProbeError(f"{label} metrics are not finite JSON") from exc
    validator = SEMANTIC_VALIDATORS.get(test_id)
    if validator is not None:
        try:
            validator(metrics, f"{test_id}.metrics", source)
        except ValueError as exc:
            raise ProbeError(str(exc)) from exc

    binding = RAW_EVIDENCE_BINDINGS[test_id]
    expected_command_ids = [binding.command_id]
    if value["command_ids"] != expected_command_ids:
        raise ProbeError(f"{label} command_ids differ from the canonical binding")
    expected_artifact_ids = [
        binding.stdout_artifact_id,
        binding.stderr_artifact_id,
        binding.evidence_artifact_id,
    ]
    if value["artifact_ids"] != expected_artifact_ids:
        raise ProbeError(f"{label} artifact_ids differ from the canonical binding")
    substantive = {
        "test_id": value["test_id"],
        "source_fingerprint_sha256": value["source_fingerprint_sha256"],
        "assertions": value["assertions"],
        "metrics": value["metrics"],
    }
    if substantive != machine_output:
        raise ProbeError(f"{label} differs from its machine command output")
    _reject_secret_material(value, label)
    return substantive


def load_raw_report(
    path: Path,
    root: Path,
    *,
    artifact_directory: Path,
    observed_image_ids: dict[str, str],
    runtime_input_path: Path,
    expected_preliminary: bool = False,
    require_runtime_readonly: bool = True,
    require_exact_artifact_directory: bool = False,
) -> dict[str, Any]:
    """Load one complete all-ID report in the explicitly selected disposition."""

    if type(expected_preliminary) is not bool:
        raise ProbeError("raw report disposition selector must be boolean")
    if not path.is_file() or path.is_symlink():
        raise ProbeError(f"raw report is missing or unsafe: {path}")
    size = path.stat().st_size
    if size <= 0 or size > RAW_REPORT_MAX_BYTES:
        raise ProbeError("raw report size is outside the bounded range")
    raw_report_bytes = path.read_bytes()
    try:
        text = raw_report_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeError("raw report is not UTF-8") from exc
    report = _strict_json(text, "raw report")
    if not isinstance(report, dict):
        raise ProbeError("raw report must be an object")
    _exact_keys(report, RAW_REPORT_KEYS, "raw report")
    if report["schema_version"] != RAW_REPORT_SCHEMA_VERSION:
        raise ProbeError("raw report schema version differs")
    if report["complete"] is not True:
        raise ProbeError("raw report is incomplete")
    if expected_preliminary:
        if report["preliminary"] is not True or report["source_frozen"] is not False:
            raise ProbeError("raw report is not an unfrozen-source preliminary capture")
    elif report["preliminary"] is not False or report["source_frozen"] is not True:
        raise ProbeError("raw report is not a frozen-source final capture")

    captured_at = report["captured_at"]
    if not isinstance(captured_at, str) or not captured_at:
        raise ProbeError("raw report captured_at is invalid")
    try:
        observed_at = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProbeError("raw report captured_at is not an ISO timestamp") from exc
    if observed_at.utcoffset() is None or observed_at.utcoffset().total_seconds() != 0:
        raise ProbeError("raw report captured_at must be UTC")
    if not isinstance(report["run_id"], str) or not RUN_ID_PATTERN.fullmatch(
        report["run_id"]
    ):
        raise ProbeError("raw report run_id must be 32 lowercase hexadecimal characters")

    source = source_fingerprint_v04(root)
    if report["source_fingerprint_sha256"] != source:
        raise ProbeError("raw report has a stale source fingerprint")

    images = report["images"]
    if not isinstance(images, dict) or set(images) != RAW_REPORT_IMAGE_ROLES:
        raise ProbeError("raw report does not bind the exact required image-role set")
    if any(
        not isinstance(image_id, str)
        or IMAGE_ID_PATTERN.fullmatch(image_id) is None
        for image_id in images.values()
    ):
        raise ProbeError("raw report contains an invalid image ID")
    if (
        not isinstance(observed_image_ids, dict)
        or set(observed_image_ids) != RAW_REPORT_IMAGE_ROLES
        or any(
            not isinstance(image_id, str)
            or IMAGE_ID_PATTERN.fullmatch(image_id) is None
            for image_id in observed_image_ids.values()
        )
    ):
        raise ProbeError("independently observed image map is incomplete or invalid")
    if images != observed_image_ids:
        raise ProbeError("raw report image IDs differ from independent observations")

    runtime = load_runtime_input(
        runtime_input_path,
        expected_source=source,
        expected_images=observed_image_ids,
        require_readonly=require_runtime_readonly,
        release_toolchain_root=root,
    )
    if report["run_id"] != runtime.run_id:
        raise ProbeError("raw report run ID differs from its runtime input")
    if (
        not isinstance(report["runtime_input_sha256"], str)
        or SHA256_PATTERN.fullmatch(report["runtime_input_sha256"]) is None
        or report["runtime_input_sha256"] != runtime.sha256
    ):
        raise ProbeError("raw report runtime input binding differs")

    binding = report["report_binding_sha256"]
    if not isinstance(binding, str) or SHA256_PATTERN.fullmatch(binding) is None:
        raise ProbeError("raw report binding digest is invalid")
    if binding != raw_report_binding(report):
        raise ProbeError("raw report binding digest differs")

    artifacts = report["artifacts"]
    expected_artifact_kinds = {
        artifact_id: kind
        for evidence in RAW_EVIDENCE_BINDINGS.values()
        for artifact_id, kind in (
            (evidence.stdout_artifact_id, "command-stdout"),
            (evidence.stderr_artifact_id, "command-stderr"),
            (evidence.evidence_artifact_id, "test-evidence"),
        )
    }
    if not isinstance(artifacts, list) or len(artifacts) != len(
        expected_artifact_kinds
    ):
        raise ProbeError("raw report artifacts do not match the canonical evidence count")
    if not artifact_directory.is_dir() or artifact_directory.is_symlink():
        raise ProbeError("raw report artifact directory is missing or unsafe")
    artifact_by_id: dict[str, dict[str, Any]] = {}
    artifact_paths: set[str] = set()
    artifact_files: dict[str, Path] = {}
    artifact_prefix = "artifacts/v0.4/.qualification/runtime-captures/"
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ProbeError("raw report artifact must be an object")
        _exact_keys(
            artifact,
            {"id", "path", "kind", "sha256", "bytes"},
            "raw report artifact",
        )
        artifact_id = artifact["id"]
        if (
            not isinstance(artifact_id, str)
            or ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None
            or artifact_id in artifact_by_id
            or artifact_id not in expected_artifact_kinds
        ):
            raise ProbeError("raw report artifact id is invalid, duplicated, or unexpected")
        artifact_by_id[artifact_id] = artifact
        artifact_path = artifact["path"]
        if (
            not isinstance(artifact_path, str)
            or not artifact_path.startswith(artifact_prefix)
            or "\\" in artifact_path
            or ".." in Path(artifact_path).parts
            or artifact_path in artifact_paths
        ):
            raise ProbeError("raw report artifact path is unsafe or duplicated")
        artifact_paths.add(artifact_path)
        if (
            artifact["kind"] not in ARTIFACT_KINDS
            or artifact["kind"] != expected_artifact_kinds[artifact_id]
        ):
            raise ProbeError(f"raw report artifact kind is invalid: {artifact_path}")
        if (
            not isinstance(artifact["sha256"], str)
            or SHA256_PATTERN.fullmatch(artifact["sha256"]) is None
        ):
            raise ProbeError(f"raw report artifact digest is invalid: {artifact_path}")
        if (
            not isinstance(artifact["bytes"], int)
            or isinstance(artifact["bytes"], bool)
            or artifact["bytes"] < 0
            or artifact["bytes"] > RAW_ARTIFACT_MAX_BYTES
        ):
            raise ProbeError(f"raw report artifact byte count is invalid: {artifact_path}")
        relative_artifact = Path(artifact_path.removeprefix(artifact_prefix))
        suffix = ".json" if artifact["kind"] == "test-evidence" else ".txt"
        if (
            len(relative_artifact.parts) != 1
            or relative_artifact.name != f"{artifact_id}{suffix}"
        ):
            raise ProbeError(f"raw report artifact must be a flat capture: {artifact_path}")
        captured_artifact = artifact_directory / relative_artifact
        if not captured_artifact.is_file() or captured_artifact.is_symlink():
            raise ProbeError(f"raw report artifact is missing or unsafe: {artifact_path}")
        if captured_artifact.stat().st_size != artifact["bytes"]:
            raise ProbeError(f"raw report artifact size differs: {artifact_path}")
        if _file_sha256(captured_artifact) != artifact["sha256"]:
            raise ProbeError(f"raw report artifact digest differs: {artifact_path}")
        artifact_files[artifact_id] = captured_artifact

    if set(artifact_by_id) != set(expected_artifact_kinds):
        raise ProbeError("raw report artifact IDs differ from the canonical binding table")
    if require_exact_artifact_directory:
        expected_names = {path.name, *(item.name for item in artifact_files.values())}
        directory_entries = tuple(artifact_directory.iterdir())
        if (
            {entry.name for entry in directory_entries} != expected_names
            or any(not entry.is_file() or entry.is_symlink() for entry in directory_entries)
        ):
            raise ProbeError("raw report directory differs from the exact manifested corpus")

    commands = report["commands"]
    if not isinstance(commands, list) or len(commands) != len(RAW_EVIDENCE_BINDINGS):
        raise ProbeError("raw report commands do not match the canonical evidence count")
    commands_by_test: dict[str, dict[str, Any]] = {}
    machine_outputs: dict[str, dict[str, Any]] = {}
    for command in commands:
        if not isinstance(command, dict):
            raise ProbeError("raw report command must be an object")
        _exact_keys(
            command,
            {
                "id",
                "test_id",
                "executor",
                "argv",
                "exit_code",
                "stdout_artifact_id",
                "stderr_artifact_id",
                "evidence_artifact_id",
                "environment_keys",
            },
            "raw report command",
        )
        test_id = command["test_id"]
        if test_id not in RAW_EVIDENCE_BINDINGS or test_id in commands_by_test:
            raise ProbeError("raw report command test ID is invalid or duplicated")
        expected = RAW_EVIDENCE_BINDINGS[test_id]
        if not isinstance(command["argv"], list) or any(
            not isinstance(item, str)
            or UNSAFE_RECORDED_ARG_PATTERN.search(item)
            or item.casefold() in SENSITIVE_RECORDED_ARG_FLAGS
            for item in command["argv"]
        ):
            raise ProbeError(f"raw report command argv is unsafe: {expected.command_id}")
        if (
            command["id"] != expected.command_id
            or command["executor"] != expected.executor
            or command["argv"] != list(expected.argv)
            or command["stdout_artifact_id"] != expected.stdout_artifact_id
            or command["stderr_artifact_id"] != expected.stderr_artifact_id
            or command["evidence_artifact_id"] != expected.evidence_artifact_id
            or command["environment_keys"] != list(expected.environment_keys)
        ):
            raise ProbeError(f"raw report command differs from canonical binding: {test_id}")
        if type(command["exit_code"]) is not int or command["exit_code"] != 0:
            raise ProbeError(f"raw report command did not pass: {expected.command_id}")

        stdout = artifact_files[expected.stdout_artifact_id].read_bytes()
        stderr = artifact_files[expected.stderr_artifact_id].read_bytes()
        evidence_bytes = artifact_files[expected.evidence_artifact_id].read_bytes()
        if max(len(stdout), len(stderr), len(evidence_bytes)) > RAW_REPORT_MAX_BYTES:
            raise ProbeError(f"raw report command output is oversized: {expected.command_id}")
        try:
            stdout_text = stdout.decode("utf-8")
            stderr_text = stderr.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProbeError(
                f"raw report command output is not UTF-8: {expected.command_id}"
            ) from exc
        _reject_secret_material(stdout_text, f"{expected.command_id} stdout")
        _reject_secret_material(stderr_text, f"{expected.command_id} stderr")
        machine_output = _strict_json(stdout_text, f"{expected.command_id} stdout")
        if not isinstance(machine_output, dict):
            raise ProbeError(f"raw report command stdout is not an object: {test_id}")
        _exact_keys(
            machine_output,
            {"test_id", "source_fingerprint_sha256", "assertions", "metrics"},
            f"{expected.command_id} stdout",
        )
        canonical_evidence = _canonical_json(machine_output) + b"\n"
        if stdout != canonical_evidence:
            raise ProbeError(f"raw report command stdout is not canonical: {test_id}")
        if evidence_bytes != canonical_evidence:
            raise ProbeError(f"raw report evidence differs from command stdout: {test_id}")
        commands_by_test[test_id] = command
        machine_outputs[test_id] = machine_output

    if set(commands_by_test) != ASSIGNED_IDS:
        raise ProbeError("raw report command IDs differ from the canonical binding table")

    results = report["results"]
    if not isinstance(results, dict) or set(results) != ASSIGNED_IDS:
        missing = sorted(ASSIGNED_IDS - set(results) if isinstance(results, dict) else ASSIGNED_IDS)
        unexpected = sorted(set(results) - ASSIGNED_IDS if isinstance(results, dict) else set())
        raise ProbeError(
            "raw report must contain exactly all assigned IDs; "
            f"missing={missing!r} unexpected={unexpected!r}"
        )
    validated = {
        test_id: _validate_result(
            test_id,
            results[test_id],
            source=source,
            machine_output=machine_outputs[test_id],
        )
        for test_id in sorted(ASSIGNED_IDS)
    }
    for test_id in sorted(RUNTIME_CAPTURE_IDS):
        raw_metrics = validated[test_id]["metrics"]
        live_metrics = runtime.results[test_id]["metrics"]
        if any(raw_metrics.get(key) != value for key, value in live_metrics.items()):
            raise ProbeError(f"raw report result differs from runtime input: {test_id}")
        if raw_metrics.get("runtime_input_sha256") != runtime.sha256:
            raise ProbeError(f"raw report result lacks runtime binding: {test_id}")

    _reject_secret_material(report, "raw report")
    return {
        **report,
        "validated_results": validated,
        "_validated_raw_report_sha256": _sha256(raw_report_bytes),
        "_validated_runtime": runtime,
    }


def _extract_raw_result(report: dict[str, Any], test_id: str) -> dict[str, Any]:
    result = report["validated_results"][test_id]
    metrics = dict(result["metrics"])
    raw_provenance = {
        "raw_report_schema_version": report["schema_version"],
        "raw_report_run_id": report["run_id"],
        "raw_report_sha256": report["_validated_raw_report_sha256"],
        "raw_report_binding_sha256": report["report_binding_sha256"],
        "raw_report_preliminary": report["preliminary"],
        "raw_report_source_frozen": report["source_frozen"],
    }
    overlap = set(metrics) & set(raw_provenance)
    if overlap:
        raise ProbeError(f"raw extraction metric collision: {sorted(overlap)!r}")
    metrics.update(raw_provenance)
    if test_id in RUNTIME_CAPTURE_IDS:
        runtime = report["_validated_runtime"]
        assert isinstance(runtime, RuntimeInputBinding)
        runtime_provenance = {
            "runtime_schema_version": RUNTIME_INPUT_SCHEMA_VERSION,
            "runtime_run_id": runtime.run_id,
            "runtime_input_sha256": runtime.sha256,
            "host_powershell_path": runtime.host_powershell_path,
            "host_powershell_sha256": runtime.host_powershell_sha256,
            "host_powershell_version": runtime.host_powershell_version,
            "host_python_path": runtime.host_python_path,
            "host_python_sha256": runtime.host_python_sha256,
            "host_python_version": runtime.host_python_version,
            "host_docker_path": runtime.host_docker_path,
            "host_docker_sha256": runtime.host_docker_sha256,
            "host_docker_version": runtime.host_docker_version,
            "host_compose_path": runtime.host_compose_path,
            "host_compose_sha256": runtime.host_compose_sha256,
            "host_compose_version": runtime.host_compose_version,
        }
        for key, value in runtime_provenance.items():
            if key in metrics and metrics[key] != value:
                raise ProbeError(f"runtime extraction metric differs: {test_id}.{key}")
            metrics[key] = value
    return {**result, "metrics": metrics}


def _result(
    test_id: str,
    assertion_ids: Iterable[str],
    metrics: dict[str, Any],
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    assertions = tuple(assertion_ids)
    if not assertions or len(assertions) != len(set(assertions)):
        raise ProbeError("probe assertions must be nonempty and unique")
    json.dumps(metrics, sort_keys=True, allow_nan=False)
    return {
        "test_id": test_id,
        "source_fingerprint_sha256": source_fingerprint_v04(root),
        "assertions": [
            {"id": assertion_id, "passed": True} for assertion_id in assertions
        ],
        "metrics": metrics,
    }


def _descriptor_file(path: Path):
    from google.protobuf import descriptor_pb2

    descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(path.read_bytes())
    matches = [item for item in descriptor_set.file if item.name.endswith("driver.proto")]
    if len(matches) != 1:
        raise ProbeError("generated descriptor does not contain exactly one driver.proto")
    return matches[0]


def _probe_con_001(root: Path) -> dict[str, Any]:
    from scripts import generate_driver_contract

    generated_runs: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="spell-contract-one-") as first_dir:
        with tempfile.TemporaryDirectory(prefix="spell-contract-two-") as second_dir:
            roots = (Path(first_dir), Path(second_dir))
            outputs = tuple(generate_driver_contract._generate(item) for item in roots)
            generate_driver_contract._compare(outputs[0], outputs[1])
            generate_driver_contract._check_or_write(outputs[0], roots[0], False)
            for output_root, run in zip(roots, outputs):
                generated_runs.append(
                    {
                        path.relative_to(output_root).as_posix(): _sha256(
                            path.read_bytes()
                        )
                        for path in run
                    }
                )
            if generated_runs[0] != generated_runs[1]:
                raise ProbeError("offline contract generations differ")
            descriptor_path = roots[0] / generate_driver_contract.DESCRIPTOR_RELATIVE
            descriptor = _descriptor_file(descriptor_path)
            field_count = sum(
                len(message.field) for message in descriptor.message_type
            )
            enum_value_count = sum(
                len(enum.value) for enum in descriptor.enum_type
            )

    return _result(
        "V04-CON-001",
        (
            "pinned-generator-produced-two-offline-runs",
            "all-generated-files-are-byte-identical",
            "committed-generated-files-match-the-pinned-output",
            "descriptor-field-and-enum-identities-are-accounted",
        ),
        {
            "offline_generation_count": 2,
            "generated_file_count_per_run": len(generated_runs[0]),
            "generated_sha256": generated_runs[0],
            "descriptor_sha256": generated_runs[0][
                "contracts/spell_driver_v1.pb"
            ],
            "message_count": len(descriptor.message_type),
            "field_count": field_count,
            "enum_count": len(descriptor.enum_type),
            "enum_value_count": enum_value_count,
        },
        root=root,
    )


def _compile_descriptor(proto_text: str):
    from google.protobuf import descriptor_pb2
    import grpc_tools
    from grpc_tools import protoc

    with tempfile.TemporaryDirectory(prefix="spell-contract-variant-") as directory:
        root = Path(directory)
        proto = root / "spell/driver/v1/driver.proto"
        proto.parent.mkdir(parents=True)
        proto.write_text(proto_text, encoding="utf-8")
        descriptor = root / "variant.pb"
        result = protoc.main(
            [
                "grpc_tools.protoc",
                f"--proto_path={root}",
                f"--proto_path={Path(grpc_tools.__file__).parent / '_proto'}",
                f"--descriptor_set_out={descriptor}",
                "--include_source_info",
                "spell/driver/v1/driver.proto",
            ]
        )
        if result != 0 or not descriptor.is_file():
            raise ProbeError("contract variant did not compile")
        descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(
            descriptor.read_bytes()
        )
        if len(descriptor_set.file) != 1:
            raise ProbeError("contract variant generated an unexpected descriptor set")
        return descriptor_set.file[0]


def _contract_manifest(file_descriptor: Any) -> dict[str, Any]:
    return {
        "package": file_descriptor.package,
        "services": {
            service.name: {
                method.name: (
                    method.input_type,
                    method.output_type,
                    method.client_streaming,
                    method.server_streaming,
                )
                for method in service.method
            }
            for service in file_descriptor.service
        },
        "messages": {
            message.name: {
                field.number: (
                    field.name,
                    field.type,
                    field.type_name,
                    field.label,
                )
                for field in message.field
            }
            for message in file_descriptor.message_type
        },
        "enums": {
            enum.name: {value.number: value.name for value in enum.value}
            for enum in file_descriptor.enum_type
        },
    }


def _minor_compatible(baseline: Any, candidate: Any) -> bool:
    old = _contract_manifest(baseline)
    new = _contract_manifest(candidate)
    if old["package"] != new["package"] or old["services"] != new["services"]:
        return False
    for message, old_fields in old["messages"].items():
        if message not in new["messages"]:
            return False
        if any(new["messages"][message].get(number) != value for number, value in old_fields.items()):
            return False
    for enum, old_values in old["enums"].items():
        if enum not in new["enums"] or new["enums"][enum] != old_values:
            return False
    return True


def _contains_untyped_payload(file_descriptor: Any) -> bool:
    return any(
        field.type_name
        in {
            ".google.protobuf.Any",
            ".google.protobuf.Struct",
            ".google.protobuf.Value",
        }
        or (field.type == field.TYPE_MESSAGE and field.type_name.endswith("Entry"))
        for message in file_descriptor.message_type
        for field in message.field
    )


def _probe_con_002(root: Path) -> dict[str, Any]:
    source = (root / "contracts/spell/driver/v1/driver.proto").read_text(
        encoding="utf-8"
    )
    baseline = _compile_descriptor(source)
    variants = {
        "additive_field": source.replace(
            "message HealthRequest {\n  RequestIdentity identity = 1;\n}",
            "message HealthRequest {\n  RequestIdentity identity = 1;\n  string additive_minor_probe = 99;\n}",
        ),
        "field_reuse": source.replace(
            "uint32 major = 1;", "uint32 reused_major_semantics = 1;", 1
        ),
        "field_type_change": source.replace(
            "uint32 major = 1;", "string major = 1;", 1
        ),
        "enum_renumber": source.replace(
            "RPC_METHOD_HEALTH = 2;", "RPC_METHOD_HEALTH = 19;", 1
        ),
        "service_change": source.replace(
            "rpc Health(HealthRequest) returns (HealthResponse);",
            "rpc FutureHealth(HealthRequest) returns (HealthResponse);",
            1,
        ),
        "major_package_change": source.replace(
            "package spell.driver.v1;", "package spell.driver.v2;", 1
        ),
    }
    observed = {
        name: _minor_compatible(baseline, _compile_descriptor(value))
        for name, value in variants.items()
    }
    expected = {
        "additive_field": True,
        "field_reuse": False,
        "field_type_change": False,
        "enum_renumber": False,
        "service_change": False,
        "major_package_change": False,
    }
    if observed != expected:
        raise ProbeError(f"compatibility matrix differs: {observed!r}")
    untyped_source = source.replace(
        'syntax = "proto3";',
        'syntax = "proto3";\nimport "google/protobuf/any.proto";',
        1,
    ).replace(
        "message HealthRequest {\n  RequestIdentity identity = 1;\n}",
        "message HealthRequest {\n  RequestIdentity identity = 1;\n  google.protobuf.Any unsafe_payload = 99;\n}",
    )
    untyped_descriptor = _compile_descriptor(untyped_source)
    if not _contains_untyped_payload(untyped_descriptor):
        raise ProbeError("untyped payload compatibility case was not detected")

    from driver_host.service import DriverInfrastructureService
    from spell.driver.v1 import driver_pb2

    service = DriverInfrastructureService(object(), object())
    valid = driver_pb2.RequestIdentity(
        contract_version=driver_pb2.ContractVersion(major=1, minor=0),
        server_profile_id="local-synthetic",
        driver_host_generation="host-generation",
        host_profile_digest="a" * 64,
        operation_id="operation",
        attempt_id="attempt",
        attempt_number=1,
        correlation_id="correlation",
        deadline_unix_ms=1,
        credential_epoch=1,
    )
    service.config = type(
        "Config",
        (),
        {
            "server_profile_id": "local-synthetic",
            "host_profile_digest": "a" * 64,
            "credential_epoch": 1,
            "driver_host_generation": "host-generation",
        },
    )()
    service._read_identity(valid)
    incompatible_version_count = 0
    for major, minor in ((2, 0), (1, 1)):
        changed = driver_pb2.RequestIdentity()
        changed.CopyFrom(valid)
        changed.contract_version.major = major
        changed.contract_version.minor = minor
        try:
            service._read_identity(changed)
        except ValueError:
            incompatible_version_count += 1
    if incompatible_version_count != 2:
        raise ProbeError("incompatible runtime contract versions were accepted")

    return _result(
        "V04-CON-002",
        (
            "approved-additive-minor-field-is-compatible",
            "field-reuse-and-semantic-type-change-are-rejected",
            "enum-renumbering-and-service-change-are-rejected",
            "major-and-unsupported-minor-runtime-versions-are-rejected",
            "untyped-payload-policy-is-explicitly-enforced",
        ),
        {
            "matrix_case_count": len(observed) + incompatible_version_count + 1,
            "compatible_case_count": sum(observed.values()),
            "rejected_case_count": sum(not value for value in observed.values())
            + incompatible_version_count,
            "incompatible_runtime_version_count": incompatible_version_count,
            "baseline_untyped_payload_count": int(
                _contains_untyped_payload(baseline)
            ),
            "rejected_untyped_payload_case_count": int(
                _contains_untyped_payload(untyped_descriptor)
            ),
            "matrix": observed,
        },
        root=root,
    )


def _run_pytest(nodes: tuple[str, ...], root: Path) -> dict[str, int]:
    command = [sys.executable, "-m", "pytest", "-q", *nodes]
    completed = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    if completed.returncode != 0 or " skipped" in completed.stdout:
        raise ProbeError(
            "focused fault tests failed: "
            + (completed.stdout + completed.stderr)[-4_000:]
        )
    import re

    match = re.search(r"(\d+) passed", completed.stdout)
    if match is None:
        raise ProbeError("focused fault tests reported no passing tests")
    return {
        "pytest_passed_count": int(match.group(1)),
        "pytest_stdout_sha256": _sha256(completed.stdout.encode("utf-8")),
        "pytest_stderr_sha256": _sha256(completed.stderr.encode("utf-8")),
    }


def _probe_con_003(root: Path) -> dict[str, Any]:
    from google.protobuf.message import DecodeError

    from driver_host.wire import (
        MAX_FIELD_OCCURRENCES,
        MAX_MESSAGE_BYTES,
        MAX_WIRE_DEPTH,
        validate_protobuf_wire,
    )
    from spell.driver.v1 import driver_pb2

    cases = 0

    def rejected(data: bytes, descriptor: Any, **kwargs: Any) -> None:
        nonlocal cases
        cases += 1
        try:
            validate_protobuf_wire(data, descriptor, **kwargs)
        except DecodeError:
            return
        raise ProbeError("malformed protobuf case was accepted")

    rejected(b"\x0a\x08short", driver_pb2.HealthRequest.DESCRIPTOR)
    rejected(
        b"x" * (MAX_MESSAGE_BYTES + 1), driver_pb2.HealthRequest.DESCRIPTOR
    )
    rejected(
        b"",
        driver_pb2.HealthRequest.DESCRIPTOR,
        depth=MAX_WIRE_DEPTH + 1,
    )
    repeated_unknown = b"\x98\x06\x00" * (MAX_FIELD_OCCURRENCES + 1)
    rejected(repeated_unknown, driver_pb2.HealthRequest.DESCRIPTOR)
    rejected(b"\x10\xe7\x07", driver_pb2.DetachExecutionRequest.DESCRIPTOR)
    first = driver_pb2.RequestIdentity(server_profile_id="first").SerializeToString()
    second = driver_pb2.RequestIdentity(server_profile_id="second").SerializeToString()
    encoded = (
        b"\x0a" + bytes([len(first)]) + first + b"\x0a" + bytes([len(second)]) + second
    )
    rejected(encoded, driver_pb2.HealthRequest.DESCRIPTOR)

    pytest_metrics = _run_pytest(FAULT_TEST_NODES["V04-CON-003"], root)
    return _result(
        "V04-CON-003",
        (
            "malformed-truncated-and-oversized-wire-fails-closed",
            "nesting-and-field-occurrence-bounds-are-enforced",
            "conflicting-duplicates-and-unknown-enums-are-rejected",
            "secure-loopback-proves-no-dispatch-journal-or-unsafe-echo",
        ),
        {
            "fuzz_case_count": cases,
            "accepted_malformed_case_count": 0,
            "max_message_bytes": MAX_MESSAGE_BYTES,
            "max_wire_depth": MAX_WIRE_DEPTH,
            "max_field_occurrences": MAX_FIELD_OCCURRENCES,
            **pytest_metrics,
        },
        root=root,
    )


def _probe_focused(test_id: str, root: Path) -> dict[str, Any]:
    nodes = FAULT_TEST_NODES.get(test_id)
    if not nodes:
        raise ProbeError(f"{test_id} has no completed focused probe")
    metrics = _run_pytest(nodes, root)
    return _result(
        test_id,
        ("all-source-bound-focused-fault-tests-passed",),
        metrics,
        root=root,
    )


def _probe_runtime_bound(
    test_id: str,
    root: Path,
    runtime_input_path: Path,
) -> dict[str, Any]:
    source = source_fingerprint_v04(root)
    runtime = load_runtime_input(
        runtime_input_path,
        expected_source=source,
        require_environment_binding=True,
        release_toolchain_root=root,
    )
    live_result = runtime.results[test_id]
    focused_metrics = _run_pytest(FAULT_TEST_NODES[test_id], root)
    overlap = set(live_result["metrics"]) & set(focused_metrics)
    if overlap:
        raise ProbeError(
            f"{test_id} runtime and focused metric names overlap: {sorted(overlap)!r}"
        )
    assertion_ids = [
        f"runtime-{assertion['id']}" for assertion in live_result["assertions"]
    ]
    assertion_ids.append("all-source-bound-focused-fault-tests-passed")
    return _result(
        test_id,
        assertion_ids,
        {
            **live_result["metrics"],
            **focused_metrics,
            "runtime_input_sha256": runtime.sha256,
        },
        root=root,
    )


def _sec003_prepublish_files(
    prepublish_root: Path,
) -> dict[str, tuple[Path, ...]]:
    if not prepublish_root.is_dir() or prepublish_root.is_symlink():
        raise ProbeError("SEC003 prepublish root is missing or unsafe")
    entries = tuple(prepublish_root.iterdir())
    if any(path.is_symlink() or not path.is_dir() for path in entries):
        raise ProbeError("SEC003 prepublish root must contain only category directories")
    if {path.name for path in entries} != SEC003_PREPUBLISH_CATEGORIES:
        raise ProbeError("SEC003 prepublish root category set differs")

    files_by_category: dict[str, tuple[Path, ...]] = {}
    for category in sorted(SEC003_PREPUBLISH_CATEGORIES):
        category_root = prepublish_root / category
        files: list[Path] = []
        for path in sorted(category_root.rglob("*")):
            if path.is_symlink():
                raise ProbeError(
                    f"SEC003 prepublish category contains a symlink: {category}"
                )
            if path.is_dir():
                continue
            if not path.is_file():
                raise ProbeError(
                    f"SEC003 prepublish category contains an unsafe entry: {category}"
                )
            files.append(path)
        if not files:
            raise ProbeError(f"secret scan category is missing: {category}")
        files_by_category[category] = tuple(files)

    sbom_names = {
        path.relative_to(prepublish_root / "sboms").as_posix()
        for path in files_by_category["sboms"]
    }
    if sbom_names != SEC003_SBOM_FILENAMES:
        raise ProbeError("secret scan requires the exact four named SBOMs")
    return files_by_category


def _probe_sec_003(root: Path, prepublish_root: Path) -> dict[str, Any]:
    source = source_fingerprint_v04(root)
    expected_canary = f"spell-v04-service-secret-{source}"
    canary = os.environ.get("SPELL_V04_SECRET_SCAN_CANARY", expected_canary)
    if canary != expected_canary:
        raise ProbeError("secret-scan canary is stale for the source fingerprint")
    files_by_category = _sec003_prepublish_files(prepublish_root)
    files = tuple(
        path
        for category in sorted(files_by_category)
        for path in files_by_category[category]
    )
    category_counts = {
        category: len(paths) for category, paths in files_by_category.items()
    }

    canary_bytes = canary.encode("ascii")
    leak_paths: list[str] = []
    category_scanned_bytes = 0
    for path in files:
        data = path.read_bytes()
        category_scanned_bytes += len(data)
        if canary_bytes in data:
            leak_paths.append(path.relative_to(prepublish_root).as_posix())
    if leak_paths:
        raise ProbeError("secret canary leaked into: " + ", ".join(leak_paths))
    try:
        product_metrics = inspect_product_package_inputs_v04(
            root, forbidden_marker=canary_bytes
        )
    except (OSError, ValueError) as exc:
        raise ProbeError("deterministic product-package secret scan failed") from exc
    if product_metrics.get("source_fingerprint_sha256") != source:
        raise ProbeError("product-package inspection source fingerprint differs")
    return _result(
        "V04-SEC-003",
        (
            "every-required-secret-scan-category-is-present",
            "service-canary-is-absent-from-every-scanned-byte-stream",
            "frontend-browser-screenshot-sbom-and-runtime-capture-categories-are-bound",
            "deterministic-product-inputs-and-decompressed-package-are-clean",
        ),
        {
            "canary_location_count": len(SEC003_PREPUBLISH_CATEGORIES),
            "canary_leak_count": 0,
            "canary_sha256": _sha256(canary_bytes),
            "scanned_file_count": (
                len(files) + int(product_metrics["product_scanned_file_count"])
            ),
            "category_scanned_byte_count": category_scanned_bytes,
            "scanned_byte_count": (
                category_scanned_bytes
                + int(product_metrics["product_scanned_byte_count"])
            ),
            "category_file_counts": category_counts,
            **product_metrics,
        },
        root=root,
    )


def run_probe(
    test_id: str,
    root: Path,
    *,
    prepublish_root: Path | None = None,
    runtime_input_path: Path | None = None,
) -> dict[str, Any]:
    if test_id not in RUNTIME_CAPTURE_IDS and runtime_input_path is not None:
        raise ProbeError("runtime input is valid only for live runtime probes")
    if test_id == "V04-CON-001":
        return _probe_con_001(root)
    if test_id == "V04-CON-002":
        return _probe_con_002(root)
    if test_id == "V04-CON-003":
        return _probe_con_003(root)
    if test_id == "V04-SEC-003":
        if prepublish_root is None:
            raise ProbeError("V04-SEC-003 requires an explicit prepublish root")
        return _probe_sec_003(root, prepublish_root)
    if test_id in RUNTIME_CAPTURE_IDS:
        if runtime_input_path is None:
            raise ProbeError(f"{test_id} requires an explicit runtime input")
        return _probe_runtime_bound(test_id, root, runtime_input_path)
    return _probe_focused(test_id, root)


def _artifact_record(
    artifact_id: str, kind: str, data: bytes
) -> dict[str, Any]:
    suffix = ".json" if kind == "test-evidence" else ".txt"
    return {
        "id": artifact_id,
        "path": (
            "artifacts/v0.4/.qualification/runtime-captures/"
            f"{artifact_id}{suffix}"
        ),
        "kind": kind,
        "sha256": _sha256(data),
        "bytes": len(data),
    }


def _raw_child_environment(
    evidence: RawEvidenceBinding,
    runtime_environment: dict[str, str],
) -> dict[str, str]:
    child_environment = {
        key: value
        for key, value in os.environ.items()
        if key in RAW_CHILD_ENVIRONMENT_BASELINE
    }
    missing_environment: list[str] = []
    for key in evidence.environment_keys:
        if key in runtime_environment:
            child_environment[key] = runtime_environment[key]
        elif os.environ.get(key):
            child_environment[key] = os.environ[key]
        else:
            missing_environment.append(key)
    if missing_environment:
        raise ProbeError(f"canonical wrapper environment is missing: {evidence.test_id}")
    return child_environment


def capture_raw_report(
    path: Path,
    root: Path,
    *,
    observed_image_ids: dict[str, str],
    prepublish_root: Path,
    runtime_input_path: Path,
    final: bool,
) -> dict[str, Any]:
    """Execute every canonical wrapper and create one complete bound report."""

    path = path.resolve()
    root = root.resolve()
    prepublish_root = prepublish_root.resolve()
    artifact_directory = path.parent
    if path.name != "fault-gate-raw.json":
        raise ProbeError("raw capture report must be named fault-gate-raw.json")
    if not artifact_directory.is_dir() or artifact_directory.is_symlink():
        raise ProbeError("raw capture directory is missing or unsafe")
    if path.exists() or path.is_symlink():
        raise ProbeError("raw capture report already exists")
    if root != Path("/qualification-source").resolve():
        raise ProbeError("raw capture must execute from /qualification-source")
    if prepublish_root != Path("/prepublish").resolve():
        raise ProbeError("raw capture must inspect the canonical /prepublish mount")
    if runtime_input_path != Path("/runtime-input/runtime-fault-evidence.json"):
        raise ProbeError("raw capture must consume the canonical runtime input mount")
    if (
        not isinstance(observed_image_ids, dict)
        or set(observed_image_ids) != RAW_REPORT_IMAGE_ROLES
        or any(
            not isinstance(image_id, str)
            or IMAGE_ID_PATTERN.fullmatch(image_id) is None
            for image_id in observed_image_ids.values()
        )
        or len(set(observed_image_ids.values())) != len(RAW_REPORT_IMAGE_ROLES)
    ):
        raise ProbeError("raw capture requires every independently observed image ID")
    _sec003_prepublish_files(prepublish_root)

    source = source_fingerprint_v04(root)
    runtime = load_runtime_input(
        runtime_input_path,
        expected_source=source,
        expected_images=observed_image_ids,
        release_toolchain_root=root,
    )
    runtime_environment = {
        "DATABASE_URL": CANONICAL_WRAPPER_DATABASE_URL,
        "SPELL_FAULT_RUN_ID": runtime.run_id,
        "SPELL_FAULT_IMAGE_BINDING_SHA256": runtime_image_binding_sha256(
            observed_image_ids
        ),
    }
    commands: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    results: dict[str, dict[str, Any]] = {}
    created_paths: list[Path] = []
    try:
        for test_id, evidence in RAW_EVIDENCE_BINDINGS.items():
            child_environment = _raw_child_environment(
                evidence, runtime_environment
            )
            actual_argv = [sys.executable, *evidence.argv[1:]]
            completed = subprocess.run(
                actual_argv,
                cwd=root,
                capture_output=True,
                timeout=900,
                env=child_environment,
            )
            if (
                type(completed.returncode) is not int
                or completed.returncode != 0
                or not isinstance(completed.stdout, bytes)
                or not isinstance(completed.stderr, bytes)
            ):
                raise ProbeError(f"canonical wrapper failed: {test_id}")
            try:
                stdout_text = completed.stdout.decode("utf-8")
                stderr_text = completed.stderr.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProbeError(f"canonical wrapper output is not UTF-8: {test_id}") from exc
            machine_output = _strict_json(stdout_text, f"{test_id} wrapper stdout")
            if not isinstance(machine_output, dict):
                raise ProbeError(f"canonical wrapper output is not an object: {test_id}")
            _exact_keys(
                machine_output,
                {"test_id", "source_fingerprint_sha256", "assertions", "metrics"},
                f"{test_id} wrapper stdout",
            )
            if (
                machine_output["test_id"] != test_id
                or machine_output["source_fingerprint_sha256"] != source
            ):
                raise ProbeError(f"canonical wrapper output identity differs: {test_id}")
            canonical_evidence = _canonical_json(machine_output) + b"\n"
            if completed.stdout != canonical_evidence:
                raise ProbeError(f"canonical wrapper stdout is not canonical: {test_id}")
            _reject_secret_material(stdout_text, f"{test_id} wrapper stdout")
            _reject_secret_material(stderr_text, f"{test_id} wrapper stderr")

            payloads = (
                (evidence.stdout_artifact_id, "command-stdout", completed.stdout),
                (evidence.stderr_artifact_id, "command-stderr", completed.stderr),
                (evidence.evidence_artifact_id, "test-evidence", canonical_evidence),
            )
            artifact_ids: list[str] = []
            for artifact_id, kind, data in payloads:
                record = _artifact_record(artifact_id, kind, data)
                target = artifact_directory / Path(record["path"]).name
                with target.open("xb") as stream:
                    stream.write(data)
                created_paths.append(target)
                artifacts.append(record)
                artifact_ids.append(artifact_id)

            commands.append(
                {
                    "id": evidence.command_id,
                    "test_id": test_id,
                    "executor": evidence.executor,
                    "argv": list(evidence.argv),
                    "exit_code": completed.returncode,
                    "stdout_artifact_id": evidence.stdout_artifact_id,
                    "stderr_artifact_id": evidence.stderr_artifact_id,
                    "evidence_artifact_id": evidence.evidence_artifact_id,
                    "environment_keys": list(evidence.environment_keys),
                }
            )
            results[test_id] = {
                **machine_output,
                "command_ids": [evidence.command_id],
                "artifact_ids": artifact_ids,
            }

        if source_fingerprint_v04(root) != source:
            raise ProbeError("source changed during raw fault capture")
        runtime_after = load_runtime_input(
            runtime_input_path,
            expected_source=source,
            expected_images=observed_image_ids,
            release_toolchain_root=root,
        )
        if runtime_after.sha256 != runtime.sha256:
            raise ProbeError("runtime input changed during raw fault capture")
        report: dict[str, Any] = {
            "schema_version": RAW_REPORT_SCHEMA_VERSION,
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "run_id": runtime.run_id,
            "source_fingerprint_sha256": source,
            "complete": True,
            "preliminary": not final,
            "source_frozen": final,
            "images": dict(sorted(observed_image_ids.items())),
            "commands": commands,
            "artifacts": artifacts,
            "results": results,
            "runtime_input_sha256": runtime.sha256,
        }
        report["report_binding_sha256"] = raw_report_binding(report)
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(_canonical_json(report).decode("utf-8") + "\n")
        created_paths.append(path)
        load_raw_report(
            path,
            root,
            artifact_directory=artifact_directory,
            observed_image_ids=observed_image_ids,
            runtime_input_path=runtime_input_path,
            expected_preliminary=not final,
            require_exact_artifact_directory=True,
        )
        for created in created_paths:
            created.chmod(0o444)
        return report
    except Exception:
        for created in reversed(created_paths):
            try:
                created.chmod(0o644)
                created.unlink()
            except OSError:
                pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("test_id", nargs="?", choices=sorted(ASSIGNED_IDS))
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--capture-raw-report",
        type=Path,
        help="execute all canonical probes and create one all-ID raw report",
    )
    parser.add_argument(
        "--raw-report",
        type=Path,
        help="extract one ID from a complete all-ID raw report; final is the default",
    )
    parser.add_argument(
        "--validate-raw-report",
        type=Path,
        help="validate a complete all-ID raw report; final is the default",
    )
    parser.add_argument(
        "--qualification-image-id",
        help="exact sha256 image ID of the qualification executor",
    )
    parser.add_argument(
        "--observed-image",
        action="append",
        default=[],
        metavar="ROLE=SHA256_ID",
        help="independently observed exact image binding; repeat for all seven roles",
    )
    parser.add_argument(
        "--artifact-directory",
        type=Path,
        help="read-only directory containing the report's manifested raw artifacts",
    )
    parser.add_argument(
        "--prepublish-root",
        type=Path,
        help="read-only SEC003 corpus with the exact five category directories",
    )
    parser.add_argument(
        "--runtime-input",
        type=Path,
        help="immutable live fault manifest and its exact manifested artifact tree",
    )
    parser.add_argument(
        "--final",
        action="store_true",
        help="capture an explicitly frozen-source final raw report",
    )
    parser.add_argument(
        "--preliminary",
        action="store_true",
        help=(
            "capture or read an explicitly preliminary, source-unfrozen raw report; "
            "final reads remain the default"
        ),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        raw_modes = tuple(
            path
            for path in (
                args.capture_raw_report,
                args.raw_report,
                args.validate_raw_report,
            )
            if path is not None
        )
        if len(raw_modes) > 1:
            raise ProbeError("raw capture, extraction, and validation modes are exclusive")
        if args.final and args.preliminary:
            raise ProbeError("--final and --preliminary are mutually exclusive")
        observed_image_ids: dict[str, str] | None = None
        if raw_modes:
            if (
                not isinstance(args.qualification_image_id, str)
                or IMAGE_ID_PATTERN.fullmatch(args.qualification_image_id) is None
            ):
                raise ProbeError(
                    "raw report modes require an exact qualification image ID"
                )
            observed_image_ids = parse_observed_image_ids(args.observed_image)
            if (
                observed_image_ids["qualification"]
                != args.qualification_image_id
            ):
                raise ProbeError(
                    "qualification image ID differs from the observed image map"
                )
            if args.runtime_input is None:
                raise ProbeError("raw report modes require a runtime input")
        elif args.qualification_image_id is not None:
            raise ProbeError("qualification image ID is valid only in raw report modes")
        elif args.observed_image:
            raise ProbeError("observed image bindings are valid only in raw report modes")

        if args.capture_raw_report is not None:
            if args.test_id is not None:
                raise ProbeError("test_id is forbidden in raw report capture mode")
            if args.artifact_directory is not None:
                raise ProbeError(
                    "artifact directory is inferred in raw report capture mode"
                )
            if args.prepublish_root is None:
                raise ProbeError("raw report capture requires a prepublish root")
            if not args.final and not args.preliminary:
                raise ProbeError(
                    "raw report capture requires exactly one of --final or --preliminary"
                )
            raw_path = args.capture_raw_report
            if not raw_path.is_absolute():
                raw_path = root / raw_path
            assert observed_image_ids is not None
            report = capture_raw_report(
                raw_path,
                root,
                observed_image_ids=observed_image_ids,
                prepublish_root=args.prepublish_root.resolve(),
                runtime_input_path=args.runtime_input,
                final=args.final,
            )
            result = {
                "schema_version": report["schema_version"],
                "source_fingerprint_sha256": report[
                    "source_fingerprint_sha256"
                ],
                "report_binding_sha256": report["report_binding_sha256"],
                "preliminary": report["preliminary"],
                "source_frozen": report["source_frozen"],
                "result_count": len(report["results"]),
                "command_count": len(report["commands"]),
                "artifact_count": len(report["artifacts"]),
                "image_count": len(report["images"]),
            }
        elif args.validate_raw_report is not None or args.raw_report is not None:
            if args.artifact_directory is None:
                raise ProbeError("raw report read modes require an artifact directory")
            if args.prepublish_root is not None:
                raise ProbeError("prepublish root is valid only for capture or SEC003")
            if args.final:
                raise ProbeError("--final is valid only in raw report capture mode")
            raw_path = args.validate_raw_report or args.raw_report
            assert raw_path is not None
            if not raw_path.is_absolute():
                raw_path = root / raw_path
            assert observed_image_ids is not None
            report = load_raw_report(
                raw_path,
                root,
                artifact_directory=args.artifact_directory.resolve(),
                observed_image_ids=observed_image_ids,
                runtime_input_path=args.runtime_input,
                expected_preliminary=args.preliminary,
                require_exact_artifact_directory=True,
            )
            if args.validate_raw_report is not None:
                if args.test_id is not None:
                    raise ProbeError("test_id is forbidden in raw report validation mode")
                result = {
                    "schema_version": report["schema_version"],
                    "source_fingerprint_sha256": report[
                        "source_fingerprint_sha256"
                    ],
                    "report_binding_sha256": report["report_binding_sha256"],
                    "preliminary": report["preliminary"],
                    "source_frozen": report["source_frozen"],
                    "result_count": len(report["validated_results"]),
                    "command_count": len(report["commands"]),
                    "artifact_count": len(report["artifacts"]),
                    "image_count": len(report["images"]),
                }
            else:
                if args.test_id is None:
                    raise ProbeError("test_id is required for raw report extraction")
                result = _extract_raw_result(report, args.test_id)
        else:
            if args.artifact_directory is not None:
                raise ProbeError("artifact directory is valid only in raw report modes")
            if args.final:
                raise ProbeError("--final is valid only in raw report capture mode")
            if args.preliminary:
                raise ProbeError("--preliminary is valid only in raw report modes")
            if args.test_id is None:
                raise ProbeError("test_id is required")
            if args.test_id == "V04-SEC-003":
                if args.prepublish_root is None:
                    raise ProbeError("V04-SEC-003 requires a prepublish root")
                prepublish_root = args.prepublish_root.resolve()
            else:
                if args.prepublish_root is not None:
                    raise ProbeError("prepublish root is valid only for V04-SEC-003")
                prepublish_root = None
            runtime_input_path = args.runtime_input
            if runtime_input_path is not None and not runtime_input_path.is_absolute():
                runtime_input_path = root / runtime_input_path
            result = run_probe(
                args.test_id,
                root,
                prepublish_root=prepublish_root,
                runtime_input_path=runtime_input_path,
            )
    except (OSError, ValueError, ProbeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
