#!/usr/bin/env python3
"""Validate or inspect the immutable SPELL v0.7 candidate qualification evidence."""

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

from scripts.accepted_v06_release_v07 import (  # noqa: E402
    V06_ARCHIVE_RELATIVE,
    V06_ARCHIVE_SHA256,
    V06_SIDECAR_RELATIVE,
    V06_SIDECAR_SHA256,
    V06_TAG_ARCHIVE_CLAIM,
    V06_TAG_OBJECT,
    validate_accepted_v06_release,
)

DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts" / "v0.7" / "work-package"
MANIFEST_NAME = "qualification.json"
SCHEMA_NAME = "schema.json"
SCHEMA_VERSION = "spell.v07.candidate-qualification/1"
PRODUCT_VERSION = "0.7.0-candidate"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
GATE_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_MARKER = "V07-GATE-0A OWNER-APPROVAL: APPROVED"
GATE_SCOPE_PATH = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "scopes/v0.7-gate-0a.json"
)
GATE_DOC_PATH = "SPELL_v0.7_Pre-Implementation.md"
GATE_VALIDATOR_PATH = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
    "validate_v07_gate_0a.py"
)
CONTRACT_PATHS = (
    "contracts/v07/manifest.json",
    "contracts/v07/time_and_sample_identity.json",
    "contracts/v07/condition_engine.json",
    "contracts/v07/waitfor_and_scheduling.json",
    "contracts/v07/resource_and_lookup_reads.json",
    "contracts/v07/limits_and_alarm_state.json",
    "contracts/v07/cursor_streams.json",
)
TOOLCHAIN_PATHS = (
    "scripts/release-toolchain-v04.json",
    "scripts/qualification-v07.Dockerfile",
    "scripts/qualification-v07.Dockerfile.dockerignore",
    "frontend/package-lock.json",
    "artifacts/v0.7/work-package/schema.json",
)
V06_TAG = "v0.6.0"

WORK_PACKAGE_TEST_IDS: dict[str, tuple[str, ...]] = {
    "V07-OBS-001": (
        "V07-OBS-001-UNIT", "V07-OBS-001-CONTRACT", "V07-OBS-001-CLOCK",
        "V07-OBS-001-RECOVERY", "V07-OBS-001-SECURITY",
    ),
    "V07-OBS-002": (
        "V07-OBS-002-UNIT", "V07-OBS-002-INTEGRATION", "V07-OBS-002-ATOMIC",
        "V07-OBS-002-QUALITY", "V07-OBS-002-SECURITY",
    ),
    "V07-OBS-003": (
        "V07-OBS-003-UNIT", "V07-OBS-003-MATRIX", "V07-OBS-003-CLOCK",
        "V07-OBS-003-RECOVERY", "V07-OBS-003-SECURITY",
    ),
    "V07-OBS-004": (
        "V07-OBS-004-UNIT", "V07-OBS-004-INTEGRATION", "V07-OBS-004-CLOCK",
        "V07-OBS-004-RACE", "V07-OBS-004-RECOVERY",
    ),
    "V07-OBS-005": (
        "V07-OBS-005-UNIT", "V07-OBS-005-INTEGRATION", "V07-OBS-005-CLOCK",
        "V07-OBS-005-RACE", "V07-OBS-005-RECOVERY",
    ),
    "V07-OBS-006": (
        "V07-OBS-006-UNIT", "V07-OBS-006-INTEGRATION", "V07-OBS-006-BOUNDARY",
        "V07-OBS-006-RECOVERY", "V07-OBS-006-SECURITY",
    ),
    "V07-OBS-007": (
        "V07-OBS-007-UNIT", "V07-OBS-007-MATRIX", "V07-OBS-007-QUALITY",
        "V07-OBS-007-RECOVERY", "V07-OBS-007-SECURITY",
    ),
    "V07-OBS-008": (
        "V07-OBS-008-UNIT", "V07-OBS-008-INTEGRATION",
        "V07-OBS-008-BACKPRESSURE", "V07-OBS-008-RECONNECT",
        "V07-OBS-008-SECURITY",
    ),
    "V07-OBS-009": (
        "V07-OBS-009-SEMANTIC-GOLDEN", "V07-OBS-009-BROWSER",
        "V07-OBS-009-ACCESSIBILITY", "V07-OBS-009-FAULT-RECOVERY",
        "V07-OBS-009-LOAD-SECURITY",
    ),
}
TEST_IDS = tuple(value for values in WORK_PACKAGE_TEST_IDS.values() for value in values)

SUITE_PATHS = {
    "backend_sqlite": "tests/backend-sqlite.xml",
    "backend_postgresql": "tests/backend-postgresql.xml",
    "backend_docker_host": "tests/backend-docker-host.xml",
    "backend_v07_soak": "tests/backend-v07-soak.json",
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
    "backend_v07_soak": "soak",
    "driver_host": "python",
    "tooling": "python",
    "frontend_vitest": "javascript",
    "frontend_build": "build",
    "frontend_playwright_mocked": "javascript",
    "frontend_playwright_live": "javascript",
}
SOAK_ITERATIONS = 5
SOAK_NODES = (
    "backend/tests/test_condition_service_v07.py::test_telemetry_schedule_pins_true_evidence_and_fires_one_occurrence",
    "backend/tests/test_observation_api.py::test_observation_read_load_is_bounded_authorized_and_nonmutating",
    "backend/tests/test_observation_repository.py::test_collector_uses_current_then_restart_cursor_next_without_duplicates",
    "backend/tests/test_supervisor_v06_runtime.py::test_concurrent_command_delivery_queues_one_application_revision",
    "backend/tests/test_supervisor_v07_runtime.py::test_restart_between_next_request_and_result_reuses_the_durable_anchor",
    "backend/tests/test_v06_operator_workspace.py::test_cross_feature_application_reservation_prevents_lost_update",
    "backend/tests/test_v06_operator_workspace.py::test_prompt_controller_loss_grace_starts_at_loss_and_reacquire_clears_it",
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
    "backend/tests/test_condition_service_v07.py::test_postgresql_database_clock_advances_inside_one_transaction",
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
    "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
}
TOOLING_ALLOWED_SKIPS = {
    "scripts/tests/test_qualify_release_v04.py::test_cleanup_inspection_distinguishes_absence_from_transport_failure",
    "scripts/tests/test_qualify_release_v04.py::test_stop_exact_tree_rejects_children_of_a_reused_root_pid",
    "scripts/tests/test_qualify_release_v04.py::test_stop_exact_tree_preserves_descendant_first_cleanup",
    "scripts/tests/test_qualify_release_v04.py::test_plan_only_executes_without_starting_the_release_gate",
    "scripts/tests/test_qualify_release_v05.py::test_v05_final_runner_parses_as_powershell",
    "scripts/tests/test_qualify_release_v06.py::test_v06_final_runner_parses_as_powershell",
    "scripts/tests/test_qualify_release_v07.py::test_v07_final_runner_parses_as_powershell",
    "scripts/tests/test_release_v05.py::test_v05_package_publication_fault_rolls_back_executably",
    "scripts/tests/test_release_v06.py::test_v06_package_publication_fault_rolls_back_executably",
    "scripts/tests/test_release_v07.py::test_v07_package_publication_fault_rolls_back_executably",
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
    "scripts/tests/test_validate_release_evidence_v07.py::test_require_tag_validates_real_annotated_object_target_markers_and_sidecar": "locked-windows-host",
}
REAL_TELEMETRY_BROWSER_TEST_FRAGMENT = (
    "renders real telemetry observations and cursor stream without mutation controls"
)
REAL_TELEMETRY_TEST_IDS = (
    "V07-OBS-002-INTEGRATION",
    "V07-OBS-002-QUALITY",
    "V07-OBS-007-QUALITY",
    "V07-OBS-008-INTEGRATION",
    "V07-OBS-009-BROWSER",
    "V07-OBS-009-ACCESSIBILITY",
)

SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}")
PROJECT_RE = re.compile(r"spell-v07-candidate-[0-9a-f]{32}")
MAX_JSON = 4 * 1024 * 1024
MAX_XML = 64 * 1024 * 1024
MAX_NODES = 10_000
SECRET_PATTERNS = {
    "private_key": re.compile(b"-----BEGIN " + rb"(?:RSA |EC |OPENSSH )?" + b"PRIVATE KEY-----"),
    "jwt": re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"),
    "credential_url": re.compile(rb"(?:postgresql|https?)://[^\s/:@]{1,128}:[^\s/@]{8,128}@"),
    "qualification_secret": re.compile(rb"v07-candidate-(?:pg|jwt)-[0-9a-f]{16,}"),
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
    driver = results["driver_host"].statuses
    vitest = results["frontend_vitest"].statuses
    mocked = results["frontend_playwright_mocked"].statuses
    live = results["frontend_playwright_live"].statuses
    selectors: dict[str, tuple[str, Sequence[str]]] = {
        "V07-OBS-001-UNIT": ("driver_host", ["clock_sources_provenance_regression"]),
        "V07-OBS-001-CONTRACT": ("backend_postgresql", ["time_and_sample_contract_is_typed"]),
        "V07-OBS-001-CLOCK": ("driver_host", ["service_time_current_next_gap_deadline"]),
        "V07-OBS-001-RECOVERY": ("backend_postgresql", ["poll_task_survives_storage_outage", "collector_uses_current_then_restart"]),
        "V07-OBS-001-SECURITY": ("driver_host", ["observation_rpc_uses_the_same_strict_raw_wire_boundary"]),
        "V07-OBS-002-UNIT": ("backend_postgresql", ["scalar_values_have_exact_types", "sample_identity_and_driver_authored"]),
        "V07-OBS-002-INTEGRATION": ("backend_postgresql", ["client_maps_time_and_atomic_sample", "repository_get_tm_current"]),
        "V07-OBS-002-ATOMIC": ("backend_postgresql", ["atomic_sample_gap_resynchronization", "uint64_source_sequence_round_trips_without_sqlite_precision_loss", "repository_get_tm_next_replay_uses_the_persisted_deadline", "repository_get_tm_next_deadline_wins_when_replay_returns_at_deadline", "repository_get_tm_next_stops_when_execution_is_cancelled"]),
        "V07-OBS-002-QUALITY": ("backend_postgresql", ["time_and_freshness_transitions", "sample_acceptability_matrix"]),
        "V07-OBS-002-SECURITY": ("backend_postgresql", ["client_fails_closed_on_scalar_oneof", "bundled_catalog_mismatch_is_rejected_before_projection"]),
        "V07-OBS-003-UNIT": ("backend_postgresql", ["typed_scalar_wire_round_trip", "plan_round_trip_binds_identity", "condition_evidence_cursors_are_lossless_json_decimal_strings"]),
        "V07-OBS-003-MATRIX": ("backend_postgresql", ["numeric_tolerance_and_tm_to_tm", "sample_acceptability_matrix"]),
        "V07-OBS-003-CLOCK": ("backend_postgresql", ["verify_zero_retry_delay_timeout", "postgresql_database_clock_advances_inside_one_transaction", "late_true_snapshot_cannot_satisfy_verify_wait_or_schedule", "verify_may_settle_a_complete_predeadline_snapshot_after_evaluation_delay", "evaluation_settlement_drives_retry_settlement_and_claim_times"]),
        "V07-OBS-003-RECOVERY": ("backend_postgresql", ["verify_is_idempotent_retries", "condition_evidence_cursors_are_lossless_json_decimal_strings", "commits_result_before_delivery"]),
        "V07-OBS-003-SECURITY": ("backend_postgresql", ["plan_validation_is_closed_world", "condition_engine_is_bounded_atomic"]),
        "V07-OBS-004-UNIT": ("backend_postgresql", ["waitfor_and_schedule_preserve_deadlines"]),
        "V07-OBS-004-INTEGRATION": ("backend_postgresql", ["procedure_runtime_drives_verify_and_wait", "waitfor_remains_paused"]),
        "V07-OBS-004-CLOCK": ("backend_postgresql", ["relative_and_absolute_waits_settle", "postgresql_database_clock_advances_inside_one_transaction", "database_clock_regression_fails_closed_without_moving_deadline", "same_epoch_restart_uses_persisted_monotonic_deadline", "epoch_change_rebases_from_immutable_utc_deadline", "late_true_snapshot_cannot_satisfy_verify_wait_or_schedule", "evaluation_settlement_drives_retry_settlement_and_claim_times"]),
        "V07-OBS-004-RACE": ("backend_postgresql", ["execution_interrupt_accepts_a_concurrent_cas_winner", "late_true_snapshot_cannot_satisfy_verify_wait_or_schedule"]),
        "V07-OBS-004-RECOVERY": ("backend_postgresql", ["wait_interrupt_resume_preserves", "telemetry_wait_restart_reuses"]),
        "V07-OBS-005-UNIT": ("backend_postgresql", ["waitfor_and_schedule_preserve_deadlines", "telemetry_schedule_cursors_are_lossless_json_decimal_strings"]),
        "V07-OBS-005-INTEGRATION": ("backend_postgresql", ["telemetry_schedule_pins_true_evidence", "telemetry_schedule_create_list_get_cancel_is_controller_bound"]),
        "V07-OBS-005-CLOCK": ("backend_postgresql", ["schedule_cancel_deadline_and_argument_security", "postgresql_database_clock_advances_inside_one_transaction", "late_true_snapshot_cannot_satisfy_verify_wait_or_schedule", "evaluation_settlement_drives_retry_settlement_and_claim_times"]),
        "V07-OBS-005-RACE": ("backend_postgresql", ["recovery_loop_and_occurrence_bound_starter", "claimed_schedule_recovers", "late_true_snapshot_cannot_satisfy_verify_wait_or_schedule"]),
        "V07-OBS-005-RECOVERY": ("backend_postgresql", ["claimed_schedule_recovers", "persisted_terminal_states_are_not_rewritten", "telemetry_schedule_cursors_are_lossless_json_decimal_strings"]),
        "V07-OBS-006-UNIT": ("backend_postgresql", ["catalog_digest_and_result_order", "catalog_identity_exposes_only_finite"]),
        "V07-OBS-006-INTEGRATION": ("backend_postgresql", ["exact_resource_memory_and_tmtc_reads", "catalog_reads_preserve_safe_outcomes"]),
        "V07-OBS-006-BOUNDARY": ("backend_postgresql", ["memory_reads_are_exact_checked", "tmtc_lookup_has_no_wildcard"]),
        "V07-OBS-006-RECOVERY": ("backend_postgresql", ["bundled_catalog_is_deterministic"]),
        "V07-OBS-006-SECURITY": ("backend_postgresql", ["resource_read_is_exact_digest_pinned", "bundled_reads_are_exact_bounded_and_read_only"]),
        "V07-OBS-007-UNIT": ("backend_postgresql", ["limit_contract_requires_canonical"]),
        "V07-OBS-007-MATRIX": ("backend_postgresql", ["is_alarmed_returns_deterministic", "no_sample_alarm_is_indeterminate_and_read_only"]),
        "V07-OBS-007-QUALITY": ("backend_postgresql", ["alarm_quality_freshness_and_gap_matrix", "no_sample_disabled_limits"]),
        "V07-OBS-007-RECOVERY": ("backend_postgresql", ["real_driver_sample_can_be_evaluated", "atomic_sample_gap_resynchronization"]),
        "V07-OBS-007-SECURITY": ("backend_postgresql", ["alarm_uses_the_limit_telemetry_digest", "bundled_reads_are_exact_bounded_and_read_only", "no_sample_alarm_is_indeterminate_and_read_only"]),
        "V07-OBS-008-UNIT": ("backend_postgresql", ["cursor_stream_is_separate_durable", "projection_cursor_uses_bigint_and_crosses_int32_boundary"]),
        "V07-OBS-008-INTEGRATION": ("backend_postgresql", ["observation_websocket_replays_strings"]),
        "V07-OBS-008-BACKPRESSURE": ("backend_postgresql", ["observation_websocket_forces_resync_on_client_queue_overflow"]),
        "V07-OBS-008-RECONNECT": ("frontend_vitest", ["refreshes ordered projection events", "resynchronizes a sequence gap"]),
        "V07-OBS-008-SECURITY": ("frontend_vitest", ["invalidates authentication on 4401"]),
        "V07-OBS-009-SEMANTIC-GOLDEN": ("backend_postgresql", ["manifest_has_exact_nine_packages", "parser_selects_v07_and_canonicalizes"]),
        "V07-OBS-009-BROWSER": ("frontend_playwright_mocked", ["distinguishes every bounded driver fault state"]),
        "V07-OBS-009-ACCESSIBILITY": ("frontend_playwright_mocked", ["distinguishes every bounded driver fault state"]),
        "V07-OBS-009-FAULT-RECOVERY": ("backend_postgresql", ["restart_between_next_request_and_result", "repository_get_tm_next_replay_uses_the_persisted_deadline", "repository_get_tm_next_stops_when_execution_is_cancelled", "repository_get_tm_next_cancellation_wins_when_replay_returns_a_sample", "durable_execution_cancellation_probe_tracks_terminal_state", "poll_task_survives_storage_outage", "recovery_loop_and_occurrence_bound_starter"]),
        "V07-OBS-009-LOAD-SECURITY": ("backend_postgresql", ["observation_read_load_is_bounded_authorized_and_nonmutating"]),
    }
    suite_statuses = {
        "backend_postgresql": backend,
        "driver_host": driver,
        "frontend_vitest": vitest,
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
    real_telemetry_nodes = _select(
        live,
        [REAL_TELEMETRY_BROWSER_TEST_FRAGMENT],
        "real telemetry browser proof",
    )
    for identity in REAL_TELEMETRY_TEST_IDS:
        proof = identities[identity]
        proof["proofs"].extend(
            {"suite": "frontend_playwright_live", "node": node}
            for node in real_telemetry_nodes
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
    elif suite_id == "backend_v07_soak":
        soak = read_json(path, "backend v0.7 soak capture")
        _exact(soak, {"profile", "iterations", "nodes", "runs", "passed"}, "backend v0.7 soak capture")
        _require(soak["profile"] == "v07-cross-feature-replay-soak" and soak["iterations"] == SOAK_ITERATIONS and soak["passed"] is True, "backend v0.7 soak did not pass")
        _require(soak["nodes"] == nodes == list(SOAK_NODES), "backend v0.7 soak inventory differs")
        runs = soak["runs"]
        _require(isinstance(runs, list) and len(runs) == SOAK_ITERATIONS, "backend v0.7 soak run count differs")
        for index, run_value in enumerate(runs, 1):
            run = _mapping(run_value, f"backend v0.7 soak run {index}")
            _exact(run, {"iteration", "exit_code", "duration_seconds"}, f"backend v0.7 soak run {index}")
            _require(run["iteration"] == index and run["exit_code"] == 0, f"backend v0.7 soak run {index} failed")
            _require(_number(run["duration_seconds"], f"backend v0.7 soak run {index} duration") < 300.0, "backend v0.7 soak iteration exceeded its bound")
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
    elif suite_id not in {"frontend_build", "backend_v07_soak"}:
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
    _require(len(parents) == 1 and parents[0] == parent, "source must have exactly one bound parent")
    _require(subprocess.run(["git", "--no-replace-objects", "merge-base", "--is-ancestor", "v0.6.0", commit], cwd=root).returncode == 0, "v0.6.0 is not an ancestor of source")
    observed = fingerprints(root, commit)
    _require(source["source_fingerprint_sha256"] == observed["source_fingerprint_sha256"], "source fingerprint differs")
    _require(source["product_fingerprint_sha256"] == observed["product_fingerprint_sha256"], "product fingerprint differs")
    return commit, observed


def _validate_gate_contracts(root: Path, commit: str, gate_value: Any, contracts_value: Any) -> None:
    gate = _mapping(gate_value, "gate_0a")
    _exact(gate, {"gate_id", "status", "validator_output", "owner_marker", "files_sha256"}, "gate_0a")
    _require(gate["gate_id"] == "V07-GATE-0A" and gate["status"] == "PASS", "Gate 0A did not pass")
    _require(gate["validator_output"] == GATE_MARKER and gate["owner_marker"] == OWNER_MARKER, "Gate 0A marker differs")
    gate_files = _mapping(gate["files_sha256"], "gate_0a.files_sha256")
    expected_paths = (GATE_SCOPE_PATH, GATE_DOC_PATH, GATE_VALIDATOR_PATH)
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
    _require(contracts["manifest_schema"] == "spell.v07.contract-manifest/1", "contract manifest schema differs")
    files = _mapping(contracts["files_sha256"], "contracts.files_sha256")
    _require(tuple(files) == CONTRACT_PATHS, "contract file inventory differs")
    for path in CONTRACT_PATHS:
        _require(files[path] == sha256_bytes(_git_blob(root, commit, path)), f"contract hash differs: {path}")
    contract_manifest = _json_bytes(_git_blob(root, commit, CONTRACT_PATHS[0]), "v0.7 contract manifest")
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
                or "qualify_release_v04" in node
                or "qualify_release_v05" in node
                or "qualify_release_v07" in node
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
    record = _mapping(value, "v0_6_immutability")
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
        "v0_6_immutability",
    )
    _require(record["baseline_tag"] == V06_TAG and record["git_diff_empty"] is True, "v0.6 immutability declaration differs")
    try:
        accepted = validate_accepted_v06_release(root)
    except ValueError as exc:
        raise CandidateEvidenceError(str(exc)) from exc
    _require(
        record["accepted_archive_path"] == V06_ARCHIVE_RELATIVE
        and record["accepted_archive_sha256"] == V06_ARCHIVE_SHA256
        and record["accepted_sidecar_path"] == V06_SIDECAR_RELATIVE
        and record["accepted_sidecar_sha256"] == V06_SIDECAR_SHA256
        and record["accepted_tag_object"] == V06_TAG_OBJECT
        and record["accepted_tag_archive_claim"] == V06_TAG_ARCHIVE_CLAIM
        and accepted.archive_sha256 == V06_ARCHIVE_SHA256,
        "accepted external v0.6 release binding differs",
    )
    baseline = _tree_fingerprint(root, V06_TAG, "artifacts/v0.6")
    source = _tree_fingerprint(root, commit, "artifacts/v0.6")
    _require(baseline == source, "tracked v0.6 artifacts changed")
    _require(record["baseline_tree_fingerprint_sha256"] == baseline and record["source_tree_fingerprint_sha256"] == source, "v0.6 artifact fingerprint differs")
    diff = subprocess.run(["git", "--no-replace-objects", "diff", "--quiet", V06_TAG, commit, "--", "artifacts/v0.6"], cwd=root)
    _require(diff.returncode == 0, "v0.6 artifact Git diff is not empty")


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
                ("test_validate_candidate_evidence_v06", "test_secret_material_scan_"),
                ("test_validate_candidate_evidence_v07", "test_secret_scan_allows_only_structured_legacy_canary_names"),
                ("test_validate_release_evidence_v06", "test_tooling_secret_"),
                ("test_validate_release_evidence_v06", "test_tooling_suite_requires_the_exact_secret_canary_nodes"),
                ("test_validate_release_evidence_v06", "test_tooling_xml_enforces_builder_token_patterns_outside_exempt_names"),
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
    run_id = str(teardown["project"]).removeprefix("spell-v07-candidate-")
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
            and observation["scope_profile"] == SCOPE_PROFILE
            and observation["run_id"] == run_id
            and observation["source_fingerprint_sha256"]
            == source["source_fingerprint_sha256"]
            and observation["project"] == profile
            and observation["source_test"]
            == "frontend/e2e/telemetry-observation-real.spec.ts"
            and observation["context_id"] == "v07-telemetry-synthetic-context",
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
    _require(schema.get("$id") == "https://openbexi.example/schemas/spell-v07-candidate-qualification-1.json", "candidate schema identity differs")
    _exact(manifest, {"schema_version", "product_version", "scope_profile", "source", "gate_0a", "contracts", "toolchain", "database", "suites", "work_packages", "assurance", "historical_platform_skips", "v0_6_immutability", "secret_scan", "artifacts", "teardown", "overall_pass"}, "candidate manifest")
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
    _validate_immutability(root, commit, manifest["v0_6_immutability"])

    artifacts = _mapping(manifest["artifacts"], "artifacts")
    expected_artifacts = {SCHEMA_NAME, *SUITE_PATHS.values(), *BROWSER_ARTIFACT_PATHS}
    _require(set(artifacts) == expected_artifacts, "artifact inventory differs")
    for relative in sorted(expected_artifacts):
        path = _regular(evidence_root, relative, f"artifact {relative}")
        _require(artifacts[relative] == sha256_bytes(path.read_bytes()), f"artifact hash differs: {relative}")
        _scan_secret(path, f"artifact {relative}")
    secret_scan = _mapping(manifest["secret_scan"], "secret_scan")
    _exact(secret_scan, {"scanner", "files_scanned", "findings", "waivers", "passed"}, "secret_scan")
    _require(secret_scan == {"scanner": "validate_candidate_evidence_v07.py/bounded-patterns-1", "files_scanned": len(expected_artifacts), "findings": [], "waivers": [], "passed": True}, "secret scan declaration differs")
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
            evidence_root = args.evidence_root or args.root / "artifacts" / "v0.7" / "work-package"
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
