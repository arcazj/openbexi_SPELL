#!/usr/bin/env python3
"""Validate or inspect the immutable SPELL v0.8 candidate qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.accepted_v07_release_v08 import (  # noqa: E402
    V07_ARCHIVE_RELATIVE,
    V07_ARCHIVE_SHA256,
    V07_SIDECAR_RELATIVE,
    V07_SIDECAR_SHA256,
    V07_TAG_ARCHIVE_CLAIM,
    V07_TAG_OBJECT,
    validate_accepted_v07_release,
)

DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts" / "v0.8" / "work-package"
MANIFEST_NAME = "qualification.json"
SCHEMA_NAME = "schema.json"
SCHEMA_VERSION = "spell.v08.candidate-qualification/1"
PRODUCT_VERSION = "0.8.0-candidate"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE"
GATE_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_MARKER = "V08-GATE-0A OWNER-APPROVAL: APPROVED"
GATE_SCOPE_PATH = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "scopes/v0.8-gate-0a.json"
)
GATE_DOC_PATH = "SPELL_v0.8_Pre-Implementation.md"
GATE_VALIDATOR_PATH = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
    "validate_v08_gate_0a.py"
)
GATE_TEST_PATH = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
    "test_validate_v08_gate_0a.py"
)
CONTRACT_PATHS = (
    "contracts/v08/manifest.json",
    "contracts/v08/typed_values.json",
    "contracts/v08/catalog_uri_dependency.json",
    "contracts/v08/dictionary_exchange.json",
    "contracts/v08/data_containers.json",
    "contracts/v08/shared_data.json",
    "contracts/v08/virtual_files.json",
    "contracts/v08/data_api_authorization.json",
    "contracts/v08/migration_recovery.json",
)
TOOLCHAIN_PATHS = (
    "scripts/release-toolchain-v04.json",
    "scripts/qualification-v08.Dockerfile",
    "scripts/qualification-v08.Dockerfile.dockerignore",
    "frontend/package-lock.json",
    "artifacts/v0.8/work-package/schema.json",
)
V07_TAG = "v0.7.0"
GATE_0A_COMMIT = "451c065740e7b6501f86094d9be79578b30b1591"

WORK_PACKAGE_TEST_IDS: dict[str, tuple[str, ...]] = {
    "V08-DATA-001": (
        "V08-DATA-001-UNIT", "V08-DATA-001-TYPE-MATRIX", "V08-DATA-001-SERIALIZATION",
        "V08-DATA-001-CORRUPTION", "V08-DATA-001-SECURITY",
    ),
    "V08-DATA-002": (
        "V08-DATA-002-UNIT", "V08-DATA-002-CONTRACT", "V08-DATA-002-GRAPH",
        "V08-DATA-002-RECOVERY", "V08-DATA-002-SECURITY",
    ),
    "V08-DATA-003": (
        "V08-DATA-003-UNIT", "V08-DATA-003-COMPATIBILITY-GOLDEN", "V08-DATA-003-IMPORT-EXPORT",
        "V08-DATA-003-CORRUPTION-RECOVERY", "V08-DATA-003-SECURITY",
    ),
    "V08-DATA-004": (
        "V08-DATA-004-UNIT", "V08-DATA-004-MATRIX", "V08-DATA-004-INTEGRATION",
        "V08-DATA-004-RECOVERY", "V08-DATA-004-SECURITY",
    ),
    "V08-DATA-005": (
        "V08-DATA-005-UNIT", "V08-DATA-005-INTEGRATION", "V08-DATA-005-RACE",
        "V08-DATA-005-RECOVERY", "V08-DATA-005-SECURITY",
    ),
    "V08-DATA-006": (
        "V08-DATA-006-UNIT", "V08-DATA-006-INTEGRATION", "V08-DATA-006-PATH-SECURITY",
        "V08-DATA-006-QUOTA-ATOMICITY", "V08-DATA-006-RECOVERY",
    ),
    "V08-DATA-007": (
        "V08-DATA-007-CONTRACT", "V08-DATA-007-AUTHORIZATION", "V08-DATA-007-IDEMPOTENCY-RACE",
        "V08-DATA-007-AUDIT-OUTBOX", "V08-DATA-007-SECURITY",
    ),
    "V08-DATA-008": (
        "V08-DATA-008-SCHEMA", "V08-DATA-008-SQLITE",
        "V08-DATA-008-POSTGRES", "V08-DATA-008-BACKUP-RESTORE",
        "V08-DATA-008-MIGRATION-ROLLBACK",
    ),
    "V08-DATA-009": (
        "V08-DATA-009-SEMANTIC-GOLDEN", "V08-DATA-009-INTEGRATION",
        "V08-DATA-009-FAULT-RECOVERY", "V08-DATA-009-LOAD",
        "V08-DATA-009-SECURITY",
    ),
}
TEST_IDS = tuple(value for values in WORK_PACKAGE_TEST_IDS.values() for value in values)

SUITE_PATHS = {
    "backend_sqlite": "tests/backend-sqlite.xml",
    "backend_postgresql": "tests/backend-postgresql.xml",
    "backend_docker_host": "tests/backend-docker-host.xml",
    "backend_v08_soak": "tests/backend-v08-soak.json",
    "driver_host": "tests/driver-host.xml",
    "tooling": "tests/tooling.xml",
    "frontend_vitest": "tests/frontend-vitest.xml",
    "frontend_build": "tests/frontend-build.json",
    "frontend_playwright_mocked": "tests/frontend-playwright-mocked.xml",
    "frontend_playwright_live": "tests/frontend-playwright-live.xml",
}
SUITE_KINDS = {
    "backend_sqlite": "python",
    "backend_postgresql": "python",
    "backend_docker_host": "python",
    "backend_v08_soak": "soak",
    "driver_host": "python",
    "tooling": "python",
    "frontend_vitest": "javascript",
    "frontend_build": "build",
    "frontend_playwright_mocked": "javascript",
    "frontend_playwright_live": "javascript",
}
SOAK_ITERATIONS = 5
SOAK_NODES = (
    "backend/tests/test_data_api_v08.py::test_catalog_container_and_shared_routes_are_closed_and_cursored",
    "backend/tests/test_data_catalog_v08.py::test_dependency_closure_is_immutable_bounded_and_deterministic",
    "backend/tests/test_data_containers_v08.py::test_admission_assertion_survives_generation_advance_and_checkpoint_is_atomic",
    "backend/tests/test_data_values_v08.py::test_canonical_golden_is_stable_and_uses_no_ascii_escape_for_valid_text",
    "backend/tests/test_dictionary_exchange_v08.py::test_db_snapshot_round_trips_as_stable_canonical_non_executing_bytes",
    "backend/tests/test_shared_data_v08.py::test_shared_cas_enumeration_replay_and_evidence",
    "backend/tests/test_virtual_files_v08.py::test_revisioned_atomic_file_lifecycle_and_idempotency",
)
BROWSER_ARTIFACT_PATHS = (
    "browser/desktop-as-run-report.png",
    "browser/desktop-v03-validation.png",
    "browser/mobile-durable-prompt.png",
    "browser/telemetry-observation-desktop.png",
    "browser/telemetry-observation-mobile.png",
    "browser/telemetry-observation-desktop.json",
    "browser/telemetry-observation-mobile.json",
)
PYTHON_PREFIXES = {
    "backend_sqlite": "backend/tests/",
    "backend_postgresql": "backend/tests/",
    "backend_docker_host": "backend/tests/test_driver_isolation.py::",
    "driver_host": "driver_host/tests/",
    "tooling": "scripts/tests/",
}

SQLITE_ALLOWED_SKIPS = {
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
    "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
    "backend/tests/test_data_migration_recovery_v08.py::test_v0007_postgresql_schema_and_fingerprint_match_sqlite_contract",
    "backend/tests/test_condition_service_v07.py::test_postgresql_database_clock_advances_inside_one_transaction",
    "backend/tests/test_data_catalog_v08.py::test_catalog_dependency_graph_is_verified_on_postgresql",
    "backend/tests/test_data_containers_v08.py::test_two_owners_can_use_the_same_container_id_on_postgresql",
    "backend/tests/test_data_migration_recovery_v08.py::test_postgresql_backup_reconstructs_exact_isolated_manual_target",
    "backend/tests/test_dictionary_exchange_v08.py::test_two_owners_can_use_the_same_dictionary_id_on_postgresql",
    "backend/tests/test_migrations.py::test_v0007_postgresql_preflight_fails_closed_before_ddl",
    "backend/tests/test_shared_data_v08.py::test_two_owners_can_use_the_same_namespace_id_on_postgresql",
    "backend/tests/test_shared_data_v08.py::test_postgresql_latest_revision_reconstruction_uses_parent_row_locks",
}
TOOLING_ALLOWED_SKIPS = {
    "scripts/tests/test_qualify_release_v04.py::test_cleanup_inspection_distinguishes_absence_from_transport_failure",
    "scripts/tests/test_qualify_release_v04.py::test_stop_exact_tree_rejects_children_of_a_reused_root_pid",
    "scripts/tests/test_qualify_release_v04.py::test_stop_exact_tree_preserves_descendant_first_cleanup",
    "scripts/tests/test_qualify_release_v04.py::test_plan_only_executes_without_starting_the_release_gate",
    "scripts/tests/test_qualify_release_v05.py::test_v05_final_runner_parses_as_powershell",
    "scripts/tests/test_qualify_release_v06.py::test_v06_final_runner_parses_as_powershell",
    "scripts/tests/test_qualify_release_v07.py::test_v07_final_runner_parses_as_powershell",
    "scripts/tests/test_qualify_release_v08.py::test_v08_final_runner_parses_as_powershell",
    "scripts/tests/test_release_v05.py::test_v05_package_publication_fault_rolls_back_executably",
    "scripts/tests/test_release_v06.py::test_v06_package_publication_fault_rolls_back_executably",
    "scripts/tests/test_release_v07.py::test_v07_package_publication_fault_rolls_back_executably",
    "scripts/tests/test_release_v08.py::test_v08_package_publication_fault_rolls_back_executably",
    "scripts/tests/test_supply_chain_v04.py::test_executable_toolchain_assertion_rejects_ambiguous_json[duplicate]",
    "scripts/tests/test_supply_chain_v04.py::test_executable_toolchain_assertion_rejects_ambiguous_json[non-finite]",
}
# These are synthetic scanner canaries embedded in legacy tooling test names.
# They are data, not credentials, and may occur exactly once in the tooling
# inventory and its matching JUnit capture.
TOOLING_SYNTHETIC_NODES = (
    "scripts/tests/test_seed_driver_projection_v04.py::"
    "test_local_database_guard_rejects_nonqualification_targets["
    "postgresql+psycopg://spell:secret@example.com:5432/spell]",
    "scripts/tests/test_seed_driver_projection_v04.py::"
    "test_local_database_guard_rejects_nonqualification_targets["
    "postgresql+psycopg://spell:secret@localhost:5432/production]",
    "scripts/tests/test_supply_chain_v04.py::"
    "test_product_package_inspection_rejects_manual_or_credential_material["
    "backend/app.py------BEGIN "
    "PRIVATE KEY-----\\n"
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\n"
    "-----END PRIVATE KEY-----\\n-high-confidence secret material]",
)
V06_PRIVATE_KEY_CANARY = "-----BEGIN " + "PRIVATE KEY-----"
V06_SECRET_SCANNER_CANARY_NODES = {
    f"backend/tests/test_ir_v06.py::test_prompt_secret_material_is_rejected_without_echo[{V06_PRIVATE_KEY_CANARY}\\nredacted]",
    "backend/tests/test_ir_v06.py::test_prompt_secret_material_is_rejected_without_echo[https://operator:plaintext@example.invalid/path]",
    f"backend/tests/test_ir_v06.py::test_action_and_startproc_secrets_are_rejected_without_echo[{V06_PRIVATE_KEY_CANARY}\\nredacted]",
    "backend/tests/test_ir_v06.py::test_action_and_startproc_secrets_are_rejected_without_echo[postgresql://operator:plaintext@example.invalid/app]",
}
REROUTED_TOOLING_TESTS = {
    "scripts/tests/test_release_v05.py::test_current_v05_product_package_fingerprint_is_constructible": "v0.5.0-export",
    "scripts/tests/test_validate_release_evidence_v05.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication": "v0.5.0-export",
    "scripts/tests/test_validate_release_evidence_v05.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar": "locked-windows-host",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_archive_sidecar_and_tag_claim_are_exact": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz-archive SHA-256 differs]": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_external_pair_rejects_byte_mutation[artifacts/v0.5/openbexi-spell-v0.5.0.tar.gz.sha256-sidecar bytes differ]": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v05_release_v06.py::test_accepted_v05_tag_claim_rejects_raw_object_mutation": "locked-windows-host-current-root",
    "scripts/tests/test_validate_release_evidence_v06.py::test_v06_inherited_v05_binding_includes_external_archive_sidecar_and_tag": "locked-windows-host-current-root",
    "scripts/tests/test_validate_candidate_evidence_v06.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic": "locked-windows-host-current-root",
    "scripts/tests/test_release_v06.py::test_current_v06_product_package_fingerprint_is_constructible": "v0.6.0-export",
    "scripts/tests/test_validate_release_evidence_v06.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication": "v0.6.0-export",
    "scripts/tests/test_validate_release_evidence_v06.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar": "locked-windows-host",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_tag_blobs_archive_and_sidecar_are_exact": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz-workspace archive SHA-256 differs]": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_external_pair_rejects_byte_mutation[artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256-workspace sidecar bytes differ]": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_raw_tag_mutation": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_rejects_tagged_blob_payload_mutation": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v06_release_v07.py::test_accepted_v06_cli_emits_one_canonical_json_object": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v06_release_v07.py::test_v07_powershell_assertion_is_parseable_and_reuses_canonical_validator": "locked-windows-host-current-root",
    "scripts/tests/test_validate_candidate_evidence_v07.py::test_v07_candidate_runner_parses_as_powershell": "locked-windows-host",
    "scripts/tests/test_validate_release_evidence_v07.py::test_v07_inherited_v06_binding_includes_external_archive_sidecar_and_tag": "locked-windows-host-current-root",
    "scripts/tests/test_qualification_image_v07.py::test_v07_qualification_baseline_inputs_exist_as_regular_files": "v0.7.0-export",
    "scripts/tests/test_source_fingerprint_v07.py::test_v07_source_fingerprint_includes_gate_0a_and_contract_inputs": "v0.7.0-export",
    "scripts/tests/test_validate_candidate_evidence_v07.py::test_candidate_schema_and_runner_are_version_scoped_and_atomic": "v0.7.0-export",
    "scripts/tests/test_release_v07.py::test_current_v07_product_package_fingerprint_is_constructible": "v0.7.0-export",
    "scripts/tests/test_validate_release_evidence_v07.py::test_repository_release_validation_is_positive_or_fails_closed_before_publication": "v0.7.0-export",
    "scripts/tests/test_validate_release_evidence_v07.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar": "locked-windows-host",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_tag_blobs_archive_and_sidecar_are_exact": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_external_pair_rejects_byte_mutation[artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz-workspace archive SHA-256 differs]": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_external_pair_rejects_byte_mutation[artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256-workspace sidecar bytes differ]": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_rejects_raw_tag_mutation": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_rejects_tagged_blob_payload_mutation": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v07_release_v08.py::test_accepted_v07_cli_emits_one_canonical_json_object": "locked-windows-host-current-root",
    "scripts/tests/test_accepted_v07_release_v08.py::test_v08_powershell_assertion_is_parseable_and_reuses_canonical_validator": "locked-windows-host-current-root",
    "scripts/tests/test_validate_candidate_evidence_v08.py::test_v08_candidate_runner_parses_as_powershell": "locked-windows-host",
    "scripts/tests/test_validate_release_evidence_v08.py::test_v08_inherited_v07_binding_includes_external_archive_sidecar_and_tag": "locked-windows-host-current-root",
    "scripts/tests/test_validate_release_evidence_v08.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar": "locked-windows-host",
}
REAL_DATA_BROWSER_TEST_FRAGMENT = (
    "reads every v0.8 data family through the loopback boundary"
)
REAL_DATA_TEST_IDS = (
    "V08-DATA-009-INTEGRATION",
    "V08-DATA-009-SECURITY",
)

SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}")
PROJECT_RE = re.compile(r"spell-v08-candidate-[0-9a-f]{32}")
MAX_JSON = 4 * 1024 * 1024
MAX_XML = 64 * 1024 * 1024
MAX_NODES = 10_000
SECRET_PATTERNS = {
    "private_key": re.compile(b"-----BEGIN " + rb"(?:RSA |EC |OPENSSH )?" + b"PRIVATE KEY-----"),
    "jwt": re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"),
    "credential_url": re.compile(rb"(?:postgresql|https?)://[^\s/:@]{1,128}:[^\s/@]{8,128}@"),
    "qualification_secret": re.compile(rb"v08-candidate-(?:pg|jwt)-[0-9a-f]{16,}"),
}


class CandidateEvidenceError(ValueError):
    """Candidate evidence is malformed, incomplete, or not source-bound."""


@dataclass(frozen=True)
class JUnitResult:
    statuses: Mapping[str, str]
    passed: int
    skipped: int
    failures: int
    errors: int
    subtests: int
    duration_seconds: float


@dataclass(frozen=True)
class CandidateEvidenceValidation:
    source_commit: str
    suite_count: int
    identity_count: int
    test_count: int
    evidence_sha256: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateEvidenceError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CandidateEvidenceError(f"non-finite JSON value: {value}")


def read_json(path: Path, label: str, *, maximum: int = MAX_JSON) -> dict[str, Any]:
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    raw = path.read_bytes()
    _require(0 < len(raw) <= maximum, f"{label} has an invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateEvidenceError(f"{label} is not strict UTF-8 JSON") from exc
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    _require(0 < len(raw) <= MAX_JSON, f"{label} has an invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateEvidenceError(f"{label} is not strict UTF-8 JSON") from exc
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _exact(value: Mapping[str, Any], keys: Iterable[str], label: str) -> None:
    expected = set(keys)
    _require(set(value) == expected, f"{label} fields differ: expected {sorted(expected)!r}, got {sorted(value)!r}")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    _require(len(value) <= 4096 and "\x00" not in value, f"{label} is unbounded")
    return value


def _integer(value: Any, label: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, f"{label} must be a non-negative integer")
    return value


def _number(value: Any, label: str) -> float:
    _require(isinstance(value, (int, float)) and not isinstance(value, bool), f"{label} must be numeric")
    result = float(value)
    _require(math.isfinite(result) and result >= 0.0, f"{label} must be finite and non-negative")
    return result


def _relative(value: Any, label: str) -> str:
    text = _string(value, label)
    path = PurePosixPath(text)
    _require(not path.is_absolute() and ".." not in path.parts and "\\" not in text, f"{label} is unsafe")
    return text


def _regular(root: Path, relative: str, label: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CandidateEvidenceError(f"{label} escapes its root") from exc
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    return path


def inventory_sha256(nodes: Sequence[str]) -> str:
    return sha256_bytes("".join(f"{node}\n" for node in sorted(nodes)).encode("utf-8"))


def _python_node(classname: str, name: str, label: str) -> str:
    parts = classname.replace("\\", "/").split(".")
    indexes = [index for index, part in enumerate(parts) if part.startswith("test_")]
    _require(bool(indexes), f"{label} testcase class is not a Python test module")
    index = indexes[-1]
    node = "/".join(parts[: index + 1]) + ".py"
    if parts[index + 1 :]:
        node += "::" + "::".join(parts[index + 1 :])
    return node + "::" + name


def _javascript_node(suite: str, classname: str, name: str) -> str:
    values = [value.replace("\\", "/").strip() for value in (suite, classname, name) if value.strip()]
    return "::".join(values)


def parse_junit(path: Path, label: str, kind: str) -> JUnitResult:
    _require(kind in {"python", "javascript"}, f"{label} JUnit kind is invalid")
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    raw = path.read_bytes()
    _require(0 < len(raw) <= MAX_XML, f"{label} has an invalid size")
    lowered = raw.lower()
    _require(b"<!doctype" not in lowered and b"<!entity" not in lowered, f"{label} contains XML declarations")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise CandidateEvidenceError(f"{label} is invalid XML") from exc
    _require(root.tag in {"testsuite", "testsuites"}, f"{label} has an invalid root")
    statuses: dict[str, str] = {}
    passed = skipped = failures = errors = reported = direct = 0
    duration = 0.0

    for suite in root.iter("testsuite"):
        direct_cases = suite.findall("testcase")
        if not direct_cases:
            continue
        suite_name = suite.get("name", "")
        suite_hostname = suite.get("hostname", "")
        javascript_scope = suite_hostname if suite_hostname in {"chromium", "mobile"} else suite_name
        tests = suite.get("tests")
        _require(tests is not None and tests.isdigit() and int(tests) >= len(direct_cases), f"{label} testcase aggregate differs")
        reported += int(tests)
        direct += len(direct_cases)
        expected_counts = {
            "skipped": sum(case.find("skipped") is not None for case in direct_cases),
            "failures": sum(case.find("failure") is not None for case in direct_cases),
            "errors": sum(case.find("error") is not None for case in direct_cases),
        }
        for attribute, expected in expected_counts.items():
            value = suite.get(attribute, "0")
            _require(value.isdigit() and int(value) == expected, f"{label} {attribute} aggregate differs")
        for case in direct_cases:
            classname = _string(case.get("classname"), f"{label} testcase classname")
            name = _string(case.get("name"), f"{label} testcase name")
            children = [child.tag for child in case if child.tag in {"skipped", "failure", "error"}]
            _require(len(children) <= 1, f"{label} testcase status is ambiguous")
            status = children[0] if children else "passed"
            node = _python_node(classname, name, label) if kind == "python" else _javascript_node(javascript_scope, classname, name)
            _require(node not in statuses, f"{label} contains duplicate testcase {node}")
            statuses[node] = status
            if status == "passed": passed += 1
            elif status == "skipped": skipped += 1
            elif status == "failure": failures += 1
            else: errors += 1
            case_time = case.get("time", "0")
            try:
                parsed_time = float(case_time)
            except ValueError as exc:
                raise CandidateEvidenceError(f"{label} testcase time is invalid") from exc
            _require(math.isfinite(parsed_time) and parsed_time >= 0.0, f"{label} testcase time is invalid")
            duration += parsed_time
    _require(0 < len(statuses) <= MAX_NODES, f"{label} testcase inventory is invalid")
    return JUnitResult(statuses, passed, skipped, failures, errors, reported - direct, duration)


def junit_document(path: Path, kind: str) -> dict[str, Any]:
    result = parse_junit(path, path.name, kind)
    nodes = sorted(result.statuses)
    return {
        "collected_nodes": nodes,
        "inventory_sha256": inventory_sha256(nodes),
        "test_count": len(nodes),
        "subtest_count": result.subtests,
        "passed_count": result.passed,
        "skipped_count": result.skipped,
        "failure_count": result.failures,
        "error_count": result.errors,
        "duration_seconds": round(result.duration_seconds, 6),
        "skipped_nodes": sorted(node for node, status in result.statuses.items() if status == "skipped"),
    }


def _git(root: Path, arguments: Sequence[str], *, binary: bool = False) -> bytes | str:
    environment = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", *arguments], cwd=root,
            env=environment, capture_output=True, check=False,
        )
    except OSError as exc:
        raise CandidateEvidenceError("Git validation could not run") from exc
    detail = completed.stderr.decode("utf-8", "replace").strip()
    _require(completed.returncode == 0, f"git {' '.join(arguments)} failed: {detail}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as exc:
        raise CandidateEvidenceError("Git emitted non-ASCII identity output") from exc


def _git_blob(root: Path, commit: str, path: str) -> bytes:
    return _git(root, ["cat-file", "blob", f"{commit}:{path}"], binary=True)  # type: ignore[return-value]


def _tree_fingerprint(root: Path, commit: str, pathspec: str | None = None) -> str:
    arguments = ["ls-tree", "-r", "-z", "--full-tree", commit]
    if pathspec:
        arguments += ["--", pathspec]
    return sha256_bytes(_git(root, arguments, binary=True))  # type: ignore[arg-type]


def _is_product_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if not parts or any(part in {"tests", "e2e", "artifacts", "docs", "__pycache__"} for part in parts):
        return False
    if path.startswith("NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/"):
        return False
    return parts[0] in {
        "backend", "frontend", "driver_host", "procedures", "proxy", "security",
        "spell", "scripts", "contracts",
    } or path in {"compose.yaml", "pyproject.toml", ".dockerignore", ".env.example"}


def fingerprints(root: Path, commit: str) -> dict[str, str]:
    _require(SHA1_RE.fullmatch(commit) is not None, "source commit is invalid")
    listing = _git(root, ["ls-tree", "-r", "-z", "--full-tree", commit], binary=True)  # type: ignore[assignment]
    digest = hashlib.sha256()
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if not _is_product_path(path):
            continue
        fields = metadata.split()
        _require(len(fields) == 3 and fields[1] == b"blob", "product tree contains an unsupported entry")
        blob = _git(root, ["cat-file", "blob", fields[2].decode("ascii")], binary=True)  # type: ignore[assignment]
        digest.update(raw_path + b"\0" + blob + b"\0")
    return {
        "source_fingerprint_sha256": sha256_bytes(listing),
        "product_fingerprint_sha256": digest.hexdigest(),
    }


def _select(statuses: Mapping[str, str], fragments: Sequence[str], label: str) -> list[str]:
    selected = sorted(node for node, status in statuses.items() if status == "passed" and any(fragment.casefold() in node.casefold() for fragment in fragments))
    _require(bool(selected), f"{label} has no passing concrete proof")
    return selected


def expected_work_packages(results: Mapping[str, JUnitResult]) -> dict[str, Any]:
    backend = results["backend_postgresql"].statuses
    mocked = results["frontend_playwright_mocked"].statuses
    live = results["frontend_playwright_live"].statuses
    selectors: dict[str, tuple[str, Sequence[str]]] = {
        "V08-DATA-001-UNIT": ("backend_postgresql", ["explicit_native_construction_and_inert_decode_are_lossless"]),
        "V08-DATA-001-TYPE-MATRIX": ("backend_postgresql", ["type_matrix_round_trips_exact_canonical_bytes"]),
        "V08-DATA-001-SERIALIZATION": ("backend_postgresql", ["canonical_golden_is_stable", "contract_integer_wire_form_crosses_32_bit"]),
        "V08-DATA-001-CORRUPTION": ("backend_postgresql", ["stored_digest_is_verified_before_decode", "strict_decoder_rejects_duplicate"]),
        "V08-DATA-001-SECURITY": ("backend_postgresql", ["invalid_values_fail_with_safe_outcome", "typed_values_are_closed_bounded_canonical_and_non_executable"]),
        "V08-DATA-002-UNIT": ("backend_postgresql", ["local_catalog_uri_is_exact_canonical"]),
        "V08-DATA-002-CONTRACT": ("backend_postgresql", ["catalog_uris_and_dependency_graph_cannot_escape"]),
        "V08-DATA-002-GRAPH": ("backend_postgresql", ["dependency_closure_is_immutable_bounded_and_deterministic"]),
        "V08-DATA-002-RECOVERY": ("backend_postgresql", ["dependency_closure_rejects_missing_digest_cycle"]),
        "V08-DATA-002-SECURITY": ("backend_postgresql", ["authorization_is_exact_deny_by_default", "cursor_is_opaque_tamper_evident"]),
        "V08-DATA-003-UNIT": ("backend_postgresql", ["db_snapshot_round_trips_as_stable_canonical_non_executing_bytes"]),
        "V08-DATA-003-COMPATIBILITY-GOLDEN": ("backend_postgresql", ["import_retains_exact_source_bytes"]),
        "V08-DATA-003-IMPORT-EXPORT": (
            "backend_postgresql",
            [
                "imp_has_explicit_ordered_upsert_and_delete_records_only",
                "runtime_dictionary_load_and_save_are_revision_pinned_file_round_trips",
            ],
        ),
        "V08-DATA-003-CORRUPTION-RECOVERY": (
            "backend_postgresql",
            [
                "strict_parser_rejects_duplicate",
                "value_and_document_digests_are_both_verified",
                "dictionary_mutations_recover_without_reimport_or_rewrite",
            ],
        ),
        "V08-DATA-003-SECURITY": (
            "backend_postgresql",
            [
                "closed_world_documents_entries",
                "duplicate_identity_case_collision",
                "dictionary_import_slow_stream_exhausts_one_end_to_end_deadline",
            ],
        ),
        "V08-DATA-004-UNIT": (
            "backend_postgresql",
            [
                "runtime_mapping_preserves_declared_types_and_stable_identities",
                "runtime_mapping_accepts_exact_typed_envelopes_without_coercion",
            ],
        ),
        "V08-DATA-004-MATRIX": ("backend_postgresql", ["data_containers_freeze_args_ivars_types_cas_and_restart"]),
        "V08-DATA-004-INTEGRATION": (
            "backend_postgresql",
            [
                "v08_argument_contract_rejects_before_execution_creation",
                "admission_and_checkpoint_share_execution_transactions",
                "container_mutation_replay_and_evidence_are_atomic",
            ],
        ),
        "V08-DATA-004-RECOVERY": (
            "backend_postgresql",
            [
                "committed_procedure_mutation_does_not_replay_under_new_generation",
                "runtime_does_not_conflate_settlements_across_worker_generations",
                "new_generation_uses_recovery_only_after_commit_delivery_crash",
                "container_mutations_recover_without_reexecution",
            ],
        ),
        "V08-DATA-004-SECURITY": ("backend_postgresql", ["runtime_container_ownership_and_args_immutability_are_constrained", "arguments_are_immutable_after_admission"]),
        "V08-DATA-005-UNIT": ("backend_postgresql", ["shared_cas_enumeration_replay_and_evidence"]),
        "V08-DATA-005-INTEGRATION": (
            "backend_postgresql",
            [
                "shared_data_is_authorized_revisioned_atomic_and_race_closed",
                "procedure_shared_owner_is_implicit_and_scope_is_execution_only",
                "runtime_shared_create_and_list_derive_execution_owner",
                "catalog_container_and_shared_routes_are_closed_and_cursored",
            ],
        ),
        "V08-DATA-005-RACE": ("backend_postgresql", ["shared_cas_enumeration_replay_and_evidence"]),
        "V08-DATA-005-RECOVERY": (
            "backend_postgresql",
            [
                "shared_clear_bound_and_namespace_tombstone",
                "shared_mutation_families_recover_each_committed_revision",
            ],
        ),
        "V08-DATA-005-SECURITY": ("backend_postgresql", ["shared_authorization_precedes_namespace_lookup", "shared_digest_corruption_fails_closed"]),
        "V08-DATA-006-UNIT": ("backend_postgresql", ["revisioned_atomic_file_lifecycle_and_idempotency"]),
        "V08-DATA-006-INTEGRATION": (
            "backend_postgresql",
            [
                "file_api_streaming_lifecycle_and_replay",
                "runtime_file_results_are_primitive",
                "file_handle_variable_references_are_closed_typed_and_resolved",
                "worker_resolves_file_handle_reference_by_exact_typed_lookup",
                "compiled_file_handle_workflow_executes_through_worker_and_runtime",
                "file_handle_token_is_transient_and_never_persisted_or_projected",
            ],
        ),
        "V08-DATA-006-PATH-SECURITY": (
            "backend_postgresql",
            [
                "virtual_paths_reject_host_ambiguous_forms",
                "supervisor_rejects_cross_handle_substitution_from_worker",
                "committed_object_link_substitution_never_reaches_outside_content",
                "hard_link_substitution_is_rejected_by_final_handle_link_count",
                "stage_name_symlink_swap_cannot_finalize_outside_or_wrong_identity",
                "retained_root_handle_blocks_or_survives_root_path_replacement",
            ],
        ),
        "V08-DATA-006-QUOTA-ATOMICITY": (
            "backend_postgresql",
            [
                "concurrent_near_quota_preparation_admits_only_one_durable_reservation",
                "restart_releases_abandoned_reservation_before_removing_stage",
                "writable_handle_reserves_worst_case_quota_before_stage_and_consumes",
            ],
        ),
        "V08-DATA-006-RECOVERY": (
            "backend_postgresql",
            [
                "recovery_removes_temporary_and_quarantines_orphan",
                "post_finalize_failure_leaves_no_visible_head",
                "file_mutations_recover_and_transient_handles_are_generation_stale",
                "resumed_file_handle_from_prior_generation_fails_stale_before_request",
            ],
        ),
        "V08-DATA-007-CONTRACT": ("backend_postgresql", ["data_api_is_deny_by_default_strict_idempotent_and_audited"]),
        "V08-DATA-007-AUTHORIZATION": ("backend_postgresql", ["data_api_authorizes_before_reading_mutation_body"]),
        "V08-DATA-007-IDEMPOTENCY-RACE": ("backend_postgresql", ["mutations_require_exact_session_and_idempotency_bindings", "file_write_idempotency_binds_encoding"]),
        "V08-DATA-007-AUDIT-OUTBOX": ("backend_postgresql", ["settlement_and_evidence_are_database_authoritative", "container_mutation_replay_and_evidence_are_atomic"]),
        "V08-DATA-007-SECURITY": (
            "backend_postgresql",
            [
                "json_mutations_reject_duplicates_unknown_fields",
                "public_api_has_no_virtual_root_provisioning_route",
                "catalog_container_and_shared_routes_are_closed_and_cursored",
            ],
        ),
        "V08-DATA-008-SCHEMA": ("backend_postgresql", ["creates_exact_fifteen_tables", "migration_is_additive_backend_parity"]),
        "V08-DATA-008-SQLITE": ("backend_postgresql", ["schema_activation_is_exact_atomic_and_idempotent"]),
        "V08-DATA-008-POSTGRES": ("backend_postgresql", ["postgresql_schema_and_fingerprint_match_sqlite_contract"]),
        "V08-DATA-008-BACKUP-RESTORE": (
            "backend_postgresql",
            [
                "backup_round_trip_preserves_dictionary_state_source_provenance_and_files",
                "backup_rejects_virtual_omissions_extras_changes_and_corrupt_objects",
                "backup_owns_quiescence_and_rejects_rehashed_internal_corruption",
                "backup_virtual_limits_are_enforced_per_root_not_per_bundle",
                "database_member_hashing_streams_past_the_legacy_256_mib_cap",
                "startup_integrity_rejects_durable_pending_settlement",
                "backup_rejects_durable_pending_settlement",
                "integrity_rejects_rehashed_invalid_semantic_state",
                "application_startup_rejects_rehashed_invalid_semantic_state",
                "backup_rejects_rehashed_invalid_semantic_state",
                "postgresql_restore_contract_requires_a_separately_named_manual_target",
                "postgresql_backup_reconstructs_exact_isolated_manual_target",
            ],
        ),
        "V08-DATA-008-MIGRATION-ROLLBACK": (
            "backend_postgresql",
            [
                "empty_unactivated_rollback_is_exact",
                "data_rollback_rejects_activation_records",
                "startup_integrity_rejects_durable_pending_settlement",
                "application_startup_rejects_rehashed_invalid_semantic_state",
            ],
        ),
        "V08-DATA-009-SEMANTIC-GOLDEN": ("backend_postgresql", ["manifest_has_exact_nine_packages_45_ids", "parser_selects_v08_and_preserves_legacy"]),
        "V08-DATA-009-INTEGRATION": ("frontend_playwright_mocked", ["operates the bounded data workspace"]),
        "V08-DATA-009-FAULT-RECOVERY": (
            "backend_postgresql",
            [
                "stale_runtime_completion_cannot_cross_generation_fence",
                "post_finalize_failure_leaves_no_visible_head",
                "recovery_contract_lists_every_procedure_mutator",
                "generic_recovery_rejects_different_operation_or_family",
                "dictionary_mutations_recover_without_reimport_or_rewrite",
                "container_mutations_recover_without_reexecution",
                "shared_mutation_families_recover_each_committed_revision",
                "file_mutations_recover_and_transient_handles_are_generation_stale",
                "resumed_file_handle_from_prior_generation_fails_stale_before_request",
            ],
        ),
        "V08-DATA-009-LOAD": (
            "backend_postgresql",
            [
                "catalog_container_and_shared_routes_are_closed_and_cursored",
                "dictionary_import_slow_stream_exhausts_one_end_to_end_deadline",
                "concurrent_near_quota_preparation_admits_only_one_durable_reservation",
            ],
        ),
        "V08-DATA-009-SECURITY": ("frontend_playwright_mocked", ["operates the bounded data workspace"]),
    }
    suite_statuses = {
        "backend_postgresql": backend,
        "frontend_playwright_mocked": mocked,
    }
    identities: dict[str, Any] = {}
    for identity in TEST_IDS:
        suite, fragments = selectors[identity]
        nodes = _select(suite_statuses[suite], fragments, identity)
        identities[identity] = {
            "proofs": [{"suite": suite, "node": node} for node in nodes],
            "passed_count": len(nodes),
            "skipped_count": 0,
        }
    real_data_nodes = _select(
        live,
        [REAL_DATA_BROWSER_TEST_FRAGMENT],
        "real data-service browser proof",
    )
    for identity in REAL_DATA_TEST_IDS:
        proof = identities[identity]
        proof["proofs"].extend(
            {"suite": "frontend_playwright_live", "node": node}
            for node in real_data_nodes
        )
        proof["passed_count"] = len(proof["proofs"])
    return {
        package: {"test_ids": {identity: identities[identity] for identity in identities_for_package}}
        for package, identities_for_package in WORK_PACKAGE_TEST_IDS.items()
    }


def work_package_document(junit_specs: Sequence[str]) -> dict[str, Any]:
    results: dict[str, JUnitResult] = {}
    for spec in junit_specs:
        try:
            suite, kind, raw_path = spec.split("=", 2)
        except ValueError as exc:
            raise CandidateEvidenceError("--junit must be SUITE=KIND=PATH") from exc
        _require(suite not in results, f"duplicate --junit suite: {suite}")
        results[suite] = parse_junit(Path(raw_path), suite, kind)
    _require(
        set(results)
        >= {
            "backend_postgresql",
            "driver_host",
            "frontend_vitest",
            "frontend_playwright_mocked",
            "frontend_playwright_live",
        },
        "identity mapping suite set is incomplete",
    )
    return expected_work_packages(results)


def _validate_suite(evidence_root: Path, suite_id: str, value: Any) -> tuple[dict[str, Any], JUnitResult | None]:
    suite = _mapping(value, f"suites.{suite_id}")
    common = {
        "kind", "capture", "collected_nodes", "inventory_sha256", "test_count",
        "subtest_count", "passed_count", "skipped_count", "failure_count",
        "error_count", "duration_seconds", "network_mode",
    }
    _exact(suite, common, f"suites.{suite_id}")
    _require(suite["kind"] == SUITE_KINDS[suite_id], f"{suite_id} kind differs")
    _require(suite["capture"] == SUITE_PATHS[suite_id], f"{suite_id} capture differs")
    path = _regular(evidence_root, suite["capture"], f"{suite_id} capture")
    nodes = suite["collected_nodes"]
    _require(isinstance(nodes, list) and 0 < len(nodes) <= MAX_NODES and all(isinstance(node, str) and node for node in nodes), f"{suite_id} nodes are invalid")
    _require(nodes == sorted(set(nodes)), f"{suite_id} nodes are not an exact sorted inventory")
    _require(suite["inventory_sha256"] == inventory_sha256(nodes), f"{suite_id} inventory digest differs")
    if suite_id == "frontend_build":
        build = read_json(path, "frontend build capture")
        _exact(build, {"command", "exit_code", "package_lock_sha256", "output_files", "passed"}, "frontend build capture")
        _require(build["command"] == "npm run build" and build["exit_code"] == 0 and build["passed"] is True, "frontend build failed")
        output_files = build["output_files"]
        _require(isinstance(output_files, list) and bool(output_files), "frontend build output inventory is empty")
        previous = ""
        for index, item_value in enumerate(output_files):
            item = _mapping(item_value, f"frontend build output {index}")
            _exact(item, {"path", "bytes", "sha256"}, f"frontend build output {index}")
            output_path = _relative(item["path"], f"frontend build output {index}.path")
            _require(output_path.startswith("dist/") and output_path > previous, "frontend build outputs are not sorted and bounded")
            previous = output_path
            _require(_integer(item["bytes"], f"frontend build output {index}.bytes") > 0, "frontend build output is empty")
            _require(SHA256_RE.fullmatch(str(item["sha256"])) is not None, "frontend build output hash is invalid")
        _require(nodes == ["frontend::npm-run-build"], "frontend build inventory differs")
        result = None
        expected = (1, 0, 1, 0, 0, 0)
    elif suite_id == "backend_v08_soak":
        soak = read_json(path, "backend v0.8 soak capture")
        _exact(soak, {"profile", "iterations", "nodes", "runs", "passed"}, "backend v0.8 soak capture")
        _require(soak["profile"] == "v08-cross-feature-replay-soak" and soak["iterations"] == SOAK_ITERATIONS and soak["passed"] is True, "backend v0.8 soak did not pass")
        _require(soak["nodes"] == nodes == list(SOAK_NODES), "backend v0.8 soak inventory differs")
        runs = soak["runs"]
        _require(isinstance(runs, list) and len(runs) == SOAK_ITERATIONS, "backend v0.8 soak run count differs")
        for index, run_value in enumerate(runs, 1):
            run = _mapping(run_value, f"backend v0.8 soak run {index}")
            _exact(run, {"iteration", "exit_code", "duration_seconds"}, f"backend v0.8 soak run {index}")
            _require(run["iteration"] == index and run["exit_code"] == 0, f"backend v0.8 soak run {index} failed")
            _require(_number(run["duration_seconds"], f"backend v0.8 soak run {index} duration") < 300.0, "backend v0.8 soak iteration exceeded its bound")
        result = None
        expected = (
            SOAK_ITERATIONS * len(nodes),
            0,
            SOAK_ITERATIONS * len(nodes),
            0,
            0,
            0,
        )
    else:
        result = parse_junit(path, f"{suite_id} capture", SUITE_KINDS[suite_id])
        _require(nodes == sorted(result.statuses), f"{suite_id} collection/JUnit bijection differs")
        expected = (len(result.statuses), result.subtests, result.passed, result.skipped, result.failures, result.errors)
    observed = tuple(_integer(suite[key], f"{suite_id}.{key}") for key in ("test_count", "subtest_count", "passed_count", "skipped_count", "failure_count", "error_count"))
    _require(observed == expected, f"{suite_id} summary differs from its capture")
    _require(_number(suite["duration_seconds"], f"{suite_id}.duration_seconds") < 3600.0, f"{suite_id} duration exceeds the candidate bound")
    _require(suite["failure_count"] == 0 and suite["error_count"] == 0, f"{suite_id} has failures")
    if suite_id == "backend_sqlite":
        assert result is not None
        skips = {node for node, status in result.statuses.items() if status == "skipped"}
        _require(skips == SQL_TOLERANT_SKIPS(result.statuses), "SQLite skip set differs")
    elif suite_id == "tooling":
        assert result is not None
        skips = {node for node, status in result.statuses.items() if status == "skipped"}
        _require(skips == TOOLING_ALLOWED_SKIPS, "tooling platform skip set differs")
        _require(
            all(nodes.count(node) == 1 and result.statuses.get(node) == "passed" for node in TOOLING_SYNTHETIC_NODES),
            "tooling synthetic scanner canary inventory differs",
        )
    elif suite_id not in {"frontend_build", "backend_v08_soak"}:
        _require(suite["skipped_count"] == 0, f"{suite_id} contains skipped tests")
    prefix = PYTHON_PREFIXES.get(suite_id)
    if prefix:
        _require(all(node.startswith(prefix) for node in nodes), f"{suite_id} inventory contains a foreign node")
    return suite, result


def SQL_TOLERANT_SKIPS(statuses: Mapping[str, str]) -> set[str]:
    # Older candidate sources may not yet contain every PostgreSQL migration node;
    # when present, the exact bounded set is still required.
    return set(statuses) & SQLITE_ALLOWED_SKIPS


def _validate_work_packages(value: Any, results: Mapping[str, JUnitResult]) -> None:
    packages = _mapping(value, "work_packages")
    _require(tuple(packages) == tuple(WORK_PACKAGE_TEST_IDS), "work package order or inventory differs")
    expected = expected_work_packages(results)
    _require(packages == expected, "45-ID expanded concrete proof mapping differs")
    for package, identities in WORK_PACKAGE_TEST_IDS.items():
        actual = _mapping(packages[package]["test_ids"], f"{package}.test_ids")
        _require(tuple(actual) == identities, f"{package} planned identity order differs")
        for identity, proof in actual.items():
            _require(proof["skipped_count"] == 0 and proof["passed_count"] == len(proof["proofs"]) > 0, f"{identity} is not fully passing")


def _validate_source(root: Path, value: Any) -> tuple[str, dict[str, str]]:
    source = _mapping(value, "source")
    _exact(source, {"commit", "tree", "parent", "source_fingerprint_sha256", "product_fingerprint_sha256"}, "source")
    commit = _string(source["commit"], "source.commit")
    tree = _string(source["tree"], "source.tree")
    parent = _string(source["parent"], "source.parent")
    _require(all(SHA1_RE.fullmatch(item) for item in (commit, tree, parent)), "source Git identity is invalid")
    _require(_git(root, ["rev-parse", "--verify", f"{commit}^{{commit}}"]), "source commit is unavailable")
    _require(_git(root, ["rev-parse", f"{commit}^{{tree}}"] ) == tree, "source tree differs")
    parents = str(_git(root, ["show", "-s", "--format=%P", commit])).split()
    _require(
        len(parents) == 1 and parents[0] == parent == GATE_0A_COMMIT,
        "source must have the exact Gate 0A commit as its sole parent",
    )
    _require(subprocess.run(["git", "--no-replace-objects", "merge-base", "--is-ancestor", "v0.7.0", commit], cwd=root).returncode == 0, "v0.7.0 is not an ancestor of source")
    observed = fingerprints(root, commit)
    _require(source["source_fingerprint_sha256"] == observed["source_fingerprint_sha256"], "source fingerprint differs")
    _require(source["product_fingerprint_sha256"] == observed["product_fingerprint_sha256"], "product fingerprint differs")
    return commit, observed


def _validate_gate_contracts(root: Path, commit: str, gate_value: Any, contracts_value: Any) -> None:
    gate = _mapping(gate_value, "gate_0a")
    _exact(gate, {"gate_id", "status", "validator_output", "owner_marker", "files_sha256"}, "gate_0a")
    _require(gate["gate_id"] == "V08-GATE-0A" and gate["status"] == "PASS", "Gate 0A did not pass")
    _require(gate["validator_output"] == GATE_MARKER and gate["owner_marker"] == OWNER_MARKER, "Gate 0A marker differs")
    gate_files = _mapping(gate["files_sha256"], "gate_0a.files_sha256")
    expected_paths = (
        GATE_SCOPE_PATH,
        GATE_DOC_PATH,
        GATE_VALIDATOR_PATH,
        GATE_TEST_PATH,
    )
    _require(tuple(gate_files) == expected_paths, "Gate 0A file inventory differs")
    for path in expected_paths:
        _require(gate_files[path] == sha256_bytes(_git_blob(root, commit, path)), f"Gate 0A hash differs: {path}")
    doc = _git_blob(root, commit, GATE_DOC_PATH).decode("utf-8")
    _require(OWNER_MARKER in doc.splitlines(), "Gate 0A owner marker is absent")
    scope = _json_bytes(_git_blob(root, commit, GATE_SCOPE_PATH), "Gate 0A scope")
    planned = scope.get("proposed_work_packages")
    _require(isinstance(planned, list) and len(planned) == 9, "Gate 0A planned package inventory differs")
    observed_gate_ids: dict[str, tuple[str, ...]] = {}
    for entry in planned:
        record = _mapping(entry, "Gate 0A planned work package")
        package_id = _string(record.get("work_package_id"), "Gate 0A work_package_id")
        test_ids = record.get("planned_test_ids")
        _require(isinstance(test_ids, list) and all(isinstance(item, str) for item in test_ids), "Gate 0A planned test IDs are invalid")
        observed_gate_ids[package_id] = tuple(test_ids)
    _require(observed_gate_ids == WORK_PACKAGE_TEST_IDS, "Gate 0A 45-ID plan differs from the compiled candidate contract")

    contracts = _mapping(contracts_value, "contracts")
    _exact(contracts, {"manifest_schema", "files_sha256"}, "contracts")
    _require(contracts["manifest_schema"] == "spell.v08.contract-manifest/1", "contract manifest schema differs")
    files = _mapping(contracts["files_sha256"], "contracts.files_sha256")
    _require(tuple(files) == CONTRACT_PATHS, "contract file inventory differs")
    for path in CONTRACT_PATHS:
        _require(files[path] == sha256_bytes(_git_blob(root, commit, path)), f"contract hash differs: {path}")
    contract_manifest = _json_bytes(_git_blob(root, commit, CONTRACT_PATHS[0]), "v0.8 contract manifest")
    _require(contract_manifest.get("work_packages") == list(WORK_PACKAGE_TEST_IDS), "contract work package inventory differs")


def _validate_toolchain(root: Path, commit: str, value: Any) -> None:
    toolchain = _mapping(value, "toolchain")
    _exact(toolchain, {"python", "docker", "node", "npm", "playwright", "chromium", "files_sha256", "qualification_image_id"}, "toolchain")
    _require(toolchain["python"] == "3.13.14", "locked Python version differs")
    for name in ("docker", "node", "npm", "playwright", "chromium"):
        _string(toolchain[name], f"toolchain.{name}")
    _require(IMAGE_RE.fullmatch(str(toolchain["qualification_image_id"])) is not None, "qualification image ID is invalid")
    files = _mapping(toolchain["files_sha256"], "toolchain.files_sha256")
    _require(tuple(files) == TOOLCHAIN_PATHS, "toolchain file inventory differs")
    for path in TOOLCHAIN_PATHS:
        _require(files[path] == sha256_bytes(_git_blob(root, commit, path)), f"toolchain hash differs: {path}")


def _validate_database(value: Any) -> None:
    database = _mapping(value, "database")
    _exact(database, {"application_name", "migration_name", "distinct_names", "both_environment_variables_bound", "postgresql_zero_skips", "network_internal", "host_port_published", "postgres_image_id"}, "database")
    _require(database == {
        **database,
        "application_name": "spell_test", "migration_name": "spell_migration_test",
        "distinct_names": True, "both_environment_variables_bound": True,
        "postgresql_zero_skips": True, "network_internal": True,
        "host_port_published": False,
    }, "database isolation contract differs")
    _require(IMAGE_RE.fullmatch(str(database["postgres_image_id"])) is not None, "PostgreSQL image ID is invalid")


def _validate_skip_contract(value: Any, tooling: JUnitResult) -> None:
    contract = _mapping(value, "historical_platform_skips")
    _exact(contract, {"classification", "skipped_nodes", "rerouted_tests", "mapped_test_ids_skipped", "accepted_failures"}, "historical_platform_skips")
    _require(contract["classification"] == "EXPLICIT_PLATFORM_SKIPS_AND_EXECUTED_SOURCE_SCOPED_REROUTES", "skip classification differs")
    skips = sorted(node for node, status in tooling.statuses.items() if status == "skipped")
    _require(len(skips) == len(TOOLING_ALLOWED_SKIPS), "tooling platform skip cardinality differs")
    expected_skips = [
        {
            "node": node,
            "reason": (
                "WINDOWS_POWERSHELL_HOST_CONTRACT_NOT_APPLICABLE_IN_LOCKED_LINUX_IMAGE"
                if "supply_chain_v04" in node
                else "POWERSHELL_UNAVAILABLE_IN_LOCKED_LINUX_IMAGE"
                if "release_v05" in node
                or "release_v06" in node
                or "release_v07" in node
                or "release_v08" in node
                or "qualify_release_v04" in node
                or "qualify_release_v05" in node
                or "qualify_release_v08" in node
                else "OPERATING_SYSTEM_SPECIFIC_CONTRACT_NOT_APPLICABLE_IN_LOCKED_LINUX_IMAGE"
            ),
        }
        for node in skips
    ]
    _require(contract["skipped_nodes"] == expected_skips, "tooling skip record differs from JUnit")
    rerouted = contract["rerouted_tests"]
    _require(isinstance(rerouted, list), "rerouted_tests must be an array")
    expected = [{"node": node, "execution_source": source, "status": "passed"} for node, source in REROUTED_TOOLING_TESTS.items()]
    _require(rerouted == expected, "historical/tool reroute contract differs")
    _require(contract["mapped_test_ids_skipped"] == [] and contract["accepted_failures"] == [], "candidate evidence contains a waiver or accepted failure")


def _validate_assurance(value: Any, packages: Mapping[str, Any], suites: Mapping[str, Any]) -> None:
    assurance = _mapping(value, "assurance")
    _exact(assurance, {"fault_recovery", "security", "concurrency", "performance"}, "assurance")
    suffixes = {
        "fault_recovery": ("RECOVERY", "FAULT-RECOVERY"),
        "security": ("SECURITY",),
        "concurrency": ("RACE",),
    }
    flattened = {identity for package in packages.values() for identity in package["test_ids"]}
    identity_owners = {
        identity: package
        for package, identities in WORK_PACKAGE_TEST_IDS.items()
        for identity in identities
    }
    for family, endings in suffixes.items():
        record = _mapping(assurance[family], f"assurance.{family}")
        _exact(record, {"test_ids", "proof_count", "all_pass"}, f"assurance.{family}")
        expected_ids = sorted(identity for identity in flattened if identity.endswith(endings))
        _require(record["test_ids"] == expected_ids and record["all_pass"] is True, f"assurance.{family} differs")
        expected_count = sum(
            len(
                packages[identity_owners[identity]]["test_ids"][identity][
                    "proofs"
                ]
            )
            for identity in expected_ids
        )
        _require(record["proof_count"] == expected_count, f"assurance.{family} proof count differs")
    performance = _mapping(assurance["performance"], "assurance.performance")
    _exact(performance, {"profile", "suite_duration_seconds", "total_duration_seconds", "maximum_suite_seconds", "replay_inventory_bijection", "soak_iterations", "all_pass"}, "assurance.performance")
    _require(performance["profile"] == "BOUNDED_CANDIDATE_QUALIFICATION" and performance["all_pass"] is True, "performance profile did not pass")
    durations = {suite: suites[suite]["duration_seconds"] for suite in SUITE_PATHS}
    _require(performance["suite_duration_seconds"] == durations, "performance suite durations differ")
    total = round(sum(float(value) for value in durations.values()), 6)
    _require(abs(float(performance["total_duration_seconds"]) - total) < 0.000001, "performance total duration differs")
    _require(_number(performance["maximum_suite_seconds"], "performance.maximum_suite_seconds") == 900.0, "performance bound differs")
    _require(all(float(value) < 900.0 for value in durations.values()), "candidate suite exceeded its performance bound")
    _require(performance["replay_inventory_bijection"] is True, "replay inventory bijection did not pass")
    _require(_integer(performance["soak_iterations"], "performance.soak_iterations") == SOAK_ITERATIONS, "candidate soak iteration count differs")


def _validate_immutability(root: Path, commit: str, value: Any) -> None:
    record = _mapping(value, "v0_7_immutability")
    _exact(
        record,
        {
            "baseline_tag",
            "baseline_tree_fingerprint_sha256",
            "source_tree_fingerprint_sha256",
            "git_diff_empty",
            "accepted_archive_path",
            "accepted_archive_sha256",
            "accepted_sidecar_path",
            "accepted_sidecar_sha256",
            "accepted_tag_object",
            "accepted_tag_archive_claim",
        },
        "v0_7_immutability",
    )
    _require(record["baseline_tag"] == V07_TAG and record["git_diff_empty"] is True, "v0.7 immutability declaration differs")
    try:
        accepted = validate_accepted_v07_release(root)
    except ValueError as exc:
        raise CandidateEvidenceError(str(exc)) from exc
    _require(
        record["accepted_archive_path"] == V07_ARCHIVE_RELATIVE
        and record["accepted_archive_sha256"] == V07_ARCHIVE_SHA256
        and record["accepted_sidecar_path"] == V07_SIDECAR_RELATIVE
        and record["accepted_sidecar_sha256"] == V07_SIDECAR_SHA256
        and record["accepted_tag_object"] == V07_TAG_OBJECT
        and record["accepted_tag_archive_claim"] == V07_TAG_ARCHIVE_CLAIM
        and accepted.archive_sha256 == V07_ARCHIVE_SHA256,
        "accepted external v0.7 release binding differs",
    )
    baseline = _tree_fingerprint(root, V07_TAG, "artifacts/v0.7")
    source = _tree_fingerprint(root, commit, "artifacts/v0.7")
    _require(baseline == source, "tracked v0.7 artifacts changed")
    _require(record["baseline_tree_fingerprint_sha256"] == baseline and record["source_tree_fingerprint_sha256"] == source, "v0.7 artifact fingerprint differs")
    diff = subprocess.run(["git", "--no-replace-objects", "diff", "--quiet", V07_TAG, commit, "--", "artifacts/v0.7"], cwd=root)
    _require(diff.returncode == 0, "v0.7 artifact Git diff is not empty")


def _scan_secret(path: Path, label: str) -> None:
    data = path.read_bytes()
    def structured_canary(value: str) -> bool:
        normalized = value.replace("\\", "/")
        if "::" in value:
            module, test_name = value.split("::", 1)
            module = module.replace("\\", "/")
            if "/" not in module:
                module = module.replace(".", "/")
            if not module.endswith(".py"):
                module += ".py"
            if f"{module}::{test_name}" in V06_SECRET_SCANNER_CANARY_NODES:
                return True
        return any(
            module in normalized and test_name in normalized
            for module, test_name in (
                ("test_seed_driver_projection_v04", "test_local_database_guard_rejects_nonqualification_targets"),
                ("test_supply_chain_v04", "test_product_package_inspection_rejects_manual_or_credential_material"),
                ("test_validate_candidate_evidence_v07", "test_secret_material_scan_"),
                ("test_validate_candidate_evidence_v08", "test_secret_scan_allows_only_structured_legacy_canary_names"),
                ("test_validate_release_evidence_v07", "test_tooling_secret_"),
                ("test_validate_release_evidence_v07", "test_tooling_suite_requires_the_exact_secret_canary_nodes"),
                ("test_validate_release_evidence_v07", "test_tooling_xml_enforces_builder_token_patterns_outside_exempt_names"),
            )
        )

    if path.suffix.casefold() == ".xml":
        try:
            document = ET.fromstring(data)
        except ET.ParseError as exc:
            raise CandidateEvidenceError(f"{label} is invalid XML during secret scan") from exc
        for case in document.iter("testcase"):
            combined = f"{case.get('classname', '')}::{case.get('name', '')}"
            if structured_canary(combined):
                case.set("name", "STRUCTURED_SYNTHETIC_SECRET_SCANNER_CANARY")
        data = ET.tostring(document, encoding="utf-8")
    elif path.suffix.casefold() == ".json":
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CandidateEvidenceError(f"{label} is invalid JSON during secret scan") from exc

        def sanitize(item: Any) -> Any:
            if isinstance(item, str) and structured_canary(item):
                return "STRUCTURED_SYNTHETIC_SECRET_SCANNER_CANARY"
            if isinstance(item, list):
                return [sanitize(child) for child in item]
            if isinstance(item, dict):
                return {key: sanitize(child) for key, child in item.items()}
            return item

        data = json.dumps(sanitize(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    for name, pattern in SECRET_PATTERNS.items():
        _require(pattern.search(data) is None, f"{label} contains credential-like material ({name})")


def _validate_real_telemetry_browser_artifacts(
    evidence_root: Path,
    *,
    source: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    teardown: Mapping[str, Any],
) -> None:
    project_match = PROJECT_RE.fullmatch(str(teardown["project"]))
    _require(project_match is not None, "teardown project identity differs")
    run_id = str(teardown["project"]).removeprefix("spell-v08-candidate-")
    observations: list[Mapping[str, Any]] = []
    for profile in ("desktop", "mobile"):
        relative = f"browser/telemetry-observation-{profile}.json"
        observation = _mapping(
            read_json(evidence_root / relative, f"real telemetry {profile} observation"),
            f"real telemetry {profile} observation",
        )
        _exact(
            observation,
            {
                "schema_version",
                "scope_profile",
                "run_id",
                "source_fingerprint_sha256",
                "project",
                "source_test",
                "context_id",
                "runtime",
                "assertions",
                "screenshot",
            },
            f"real telemetry {profile} observation",
        )
        _require(
            observation["schema_version"]
            == "spell.v07.telemetry-browser-observation/1"
            and observation["scope_profile"] == "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
            and observation["run_id"] == run_id
            and observation["source_fingerprint_sha256"]
            == source["source_fingerprint_sha256"]
            and observation["project"] == profile
            and observation["source_test"]
            == "frontend/e2e/telemetry-observation-real.spec.ts"
            and observation["context_id"] == "v08-telemetry-synthetic-context",
            f"real telemetry {profile} identity differs",
        )
        runtime = _mapping(observation["runtime"], f"real telemetry {profile} runtime")
        _exact(
            runtime,
            {
                "node_version",
                "npm_version",
                "playwright_version",
                "browser_name",
                "browser_version",
                "project",
                "stack_image_ids",
            },
            f"real telemetry {profile} runtime",
        )
        for name in ("node_version", "playwright_version", "browser_version"):
            _string(runtime[name], f"real telemetry {profile} runtime.{name}")
        _require(
            runtime["npm_version"] == toolchain["npm"]
            and runtime["browser_name"] == "chromium"
            and runtime["project"] == ("chromium" if profile == "desktop" else "mobile"),
            f"real telemetry {profile} runtime identity differs",
        )
        stack = _mapping(
            runtime["stack_image_ids"],
            f"real telemetry {profile} stack image identities",
        )
        _exact(
            stack,
            {"backend", "driver", "pki_init", "postgres", "proxy", "qualification"},
            f"real telemetry {profile} stack image identities",
        )
        _require(
            all(IMAGE_RE.fullmatch(str(value)) is not None for value in stack.values())
            and stack["qualification"] == toolchain["qualification_image_id"],
            f"real telemetry {profile} stack image identity differs",
        )
        assertions = _mapping(
            observation["assertions"], f"real telemetry {profile} assertions"
        )
        _exact(
            assertions,
            {
                "driver_time",
                "item_ids",
                "quality",
                "validity",
                "freshness",
                "alarm",
                "cursor_websocket",
                "accessibility_blocking_findings",
                "overflow_failures",
                "mutation_control_count",
            },
            f"real telemetry {profile} assertions",
        )
        _require(
            assertions
            == {
                "driver_time": True,
                "item_ids": [
                    "TM.POWER.BUS_VOLTAGE",
                    "TM.POWER.SAFE_MODE",
                    "TM.THERMAL.MODE",
                ],
                "quality": "GOOD",
                "validity": "VALID",
                "freshness": "FRESH",
                "alarm": True,
                "cursor_websocket": True,
                "accessibility_blocking_findings": 0,
                "overflow_failures": 0,
                "mutation_control_count": 0,
            },
            f"real telemetry {profile} assertions differ",
        )
        screenshot = _mapping(
            observation["screenshot"], f"real telemetry {profile} screenshot"
        )
        _exact(screenshot, {"path", "sha256"}, f"real telemetry {profile} screenshot")
        screenshot_path = f"browser/telemetry-observation-{profile}.png"
        _require(
            screenshot["path"] == screenshot_path
            and screenshot["sha256"]
            == sha256_bytes((evidence_root / screenshot_path).read_bytes()),
            f"real telemetry {profile} screenshot binding differs",
        )
        observations.append(observation)
    _require(
        observations[0]["runtime"]["stack_image_ids"]
        == observations[1]["runtime"]["stack_image_ids"],
        "real telemetry browser projects used different stack images",
    )


def validate_candidate_evidence(root: Path, evidence_root: Path) -> CandidateEvidenceValidation:
    root = root.resolve()
    evidence_root = evidence_root.resolve()
    _require(evidence_root.is_dir() and not evidence_root.is_symlink(), "evidence root is missing or unsafe")
    manifest_path = _regular(evidence_root, MANIFEST_NAME, "candidate manifest")
    schema_path = _regular(evidence_root, SCHEMA_NAME, "candidate schema")
    manifest = read_json(manifest_path, "candidate manifest")
    schema = read_json(schema_path, "candidate schema")
    _require(schema.get("$id") == "https://openbexi.example/schemas/spell-v08-candidate-qualification-1.json", "candidate schema identity differs")
    _exact(manifest, {"schema_version", "product_version", "scope_profile", "source", "gate_0a", "contracts", "toolchain", "database", "suites", "work_packages", "assurance", "historical_platform_skips", "v0_7_immutability", "secret_scan", "artifacts", "teardown", "overall_pass"}, "candidate manifest")
    _require(manifest["schema_version"] == SCHEMA_VERSION and manifest["product_version"] == PRODUCT_VERSION and manifest["scope_profile"] == SCOPE_PROFILE, "candidate identity differs")
    _require(manifest["overall_pass"] is True, "candidate qualification did not pass")

    commit, _ = _validate_source(root, manifest["source"])
    _validate_gate_contracts(root, commit, manifest["gate_0a"], manifest["contracts"])
    _validate_toolchain(root, commit, manifest["toolchain"])
    _validate_database(manifest["database"])
    suites = _mapping(manifest["suites"], "suites")
    _require(tuple(suites) == tuple(SUITE_PATHS), "suite order or inventory differs")
    parsed: dict[str, JUnitResult] = {}
    for suite_id in SUITE_PATHS:
        _, result = _validate_suite(evidence_root, suite_id, suites[suite_id])
        if result is not None:
            parsed[suite_id] = result
    _require(set(parsed["backend_sqlite"].statuses) == set(parsed["backend_postgresql"].statuses), "SQLite/PostgreSQL backend inventories differ")
    host_nodes = set(parsed["backend_docker_host"].statuses)
    _require(host_nodes == set(parsed["backend_postgresql"].statuses) & {
        "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
        "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    }, "host Docker test inventory differs")
    _validate_work_packages(manifest["work_packages"], parsed)
    _validate_skip_contract(manifest["historical_platform_skips"], parsed["tooling"])
    _validate_assurance(manifest["assurance"], manifest["work_packages"], suites)
    _validate_immutability(root, commit, manifest["v0_7_immutability"])

    artifacts = _mapping(manifest["artifacts"], "artifacts")
    expected_artifacts = {SCHEMA_NAME, *SUITE_PATHS.values(), *BROWSER_ARTIFACT_PATHS}
    _require(set(artifacts) == expected_artifacts, "artifact inventory differs")
    for relative in sorted(expected_artifacts):
        path = _regular(evidence_root, relative, f"artifact {relative}")
        _require(artifacts[relative] == sha256_bytes(path.read_bytes()), f"artifact hash differs: {relative}")
        _scan_secret(path, f"artifact {relative}")
    secret_scan = _mapping(manifest["secret_scan"], "secret_scan")
    _exact(secret_scan, {"scanner", "files_scanned", "findings", "waivers", "passed"}, "secret_scan")
    _require(secret_scan == {"scanner": "validate_candidate_evidence_v08.py/bounded-patterns-1", "files_scanned": len(expected_artifacts), "findings": [], "waivers": [], "passed": True}, "secret scan declaration differs")
    _scan_secret(manifest_path, "candidate manifest")

    teardown = _mapping(manifest["teardown"], "teardown")
    _exact(teardown, {"project", "resources_torn_down", "runtime_processes_stopped", "image_tags_removed", "scratch_removed"}, "teardown")
    _require(PROJECT_RE.fullmatch(str(teardown["project"])) is not None, "teardown project identity differs")
    _require(all(teardown[key] is True for key in ("resources_torn_down", "runtime_processes_stopped", "image_tags_removed", "scratch_removed")), "qualification teardown is incomplete")
    _validate_real_telemetry_browser_artifacts(
        evidence_root,
        source=manifest["source"],
        toolchain=manifest["toolchain"],
        teardown=teardown,
    )
    return CandidateEvidenceValidation(
        source_commit=commit, suite_count=len(suites), identity_count=len(TEST_IDS),
        test_count=sum(int(suite["test_count"]) for suite in suites.values()),
        evidence_sha256=sha256_bytes(manifest_path.read_bytes()),
    )


def result_json(value: Any, *, preserve_order: bool = False) -> str:
    return json.dumps(
        value,
        sort_keys=not preserve_order,
        separators=(",", ":"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--evidence-root", type=Path, default=None)
    parser.add_argument("--junit-summary", type=Path)
    parser.add_argument("--junit-kind", choices=("python", "javascript"))
    parser.add_argument("--identity-map", action="store_true")
    parser.add_argument("--junit", action="append", default=[])
    parser.add_argument("--fingerprints", metavar="COMMIT")
    parser.add_argument("--tree-fingerprint", nargs=2, metavar=("COMMIT", "PATH"))
    args = parser.parse_args()
    try:
        if args.junit_summary:
            _require(args.junit_kind is not None, "--junit-kind is required")
            result: Any = junit_document(args.junit_summary, args.junit_kind)
        elif args.identity_map:
            result = work_package_document(args.junit)
        elif args.fingerprints:
            result = fingerprints(args.root.resolve(), args.fingerprints)
        elif args.tree_fingerprint:
            result = {"sha256": _tree_fingerprint(args.root.resolve(), args.tree_fingerprint[0], args.tree_fingerprint[1])}
        else:
            evidence_root = args.evidence_root or args.root / "artifacts" / "v0.8" / "work-package"
            validated = validate_candidate_evidence(args.root, evidence_root)
            result = {
                "gate": "PASS", "schema_version": SCHEMA_VERSION,
                "source_commit": validated.source_commit,
                "suites": validated.suite_count, "test_ids": validated.identity_count,
                "tests": validated.test_count, "evidence_sha256": validated.evidence_sha256,
            }
        print(result_json(result, preserve_order=args.identity_map))
        return 0
    except (CandidateEvidenceError, OSError) as exc:
        print(f"candidate evidence validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
