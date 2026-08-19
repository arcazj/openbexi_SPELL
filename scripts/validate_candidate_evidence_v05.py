#!/usr/bin/env python3
"""Validate the immutable V05-IR-001 candidate qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts" / "v0.5" / "work-package"
MANIFEST_NAME = "qualification.json"
SCHEMA_VERSION = "spell.v05.candidate-qualification/1"
PRODUCT_VERSION = "0.5.0-candidate"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"

IMPLEMENTATION_COMMIT = "aefa658ce01d49a7879d0471b50425ac3bcf9e2d"
IMPLEMENTATION_TREE = "958c43e867228b536fd21c0da59d5530e9fe155b"
IMPLEMENTATION_PARENT = "d13397f51241c6bac10289ea21b69aafff66b1fb"
IMPLEMENTATION_BLOBS = {
    "backend/ir_v03.py": "87f202e9e3ff192e348c2aea9f7009ea7fc95841",
    "backend/procedure_parser.py": "cf6fdf5645d3818e8b7b2c7abdca796d4d1c506b",
    "backend/supervisor.py": "6b903d97c7777cd163b776fe5c0a2bebc1c2721c",
    "backend/tests/test_driver_isolation.py": "d829838cbd1b0186adb7a075e9c9edfb661c321c",
    "backend/tests/test_ir_boundaries.py": "750b3640615e6aa19d3d40914f966cccb63e59d8",
    "backend/tests/test_ir_v03.py": "e142c9b67dadbad71d62207542a7c395f896f9c6",
    "backend/tests/test_procedure_parser.py": "a9f3c22d2362e83d810b4476d2435407ca2a01ab",
    "backend/tests/test_worker_expressions.py": "fe97a2f57e7ec85093b893526030afbfeff59fb3",
    "backend/worker.py": "513fb00afea31b948e6cdcfed3c2911c2eff42e5",
}
DOCUMENTATION_BRIDGE_COMMIT = "05a1c89c21b500270476b172d86d0758945d23d7"
DOCUMENTATION_BRIDGE_TREE = "cd7bfba486e319c1a3aeebaee84770c405346c27"
DOCUMENTATION_BRIDGE_BLOBS = {
    "PROJECT_ROADMAP.md": "831095cdda5e08cde2500952bcab77591b9e7031",
    "PROMPT_History.md": "d53d69daa2484e4c5039eaf87290945fbce09265",
    "Test_and_Integration.md": "de9e57b93fed73dc971b164d98f7d32be2d3f2f2",
    "VERSION_TIMELINE.md": "d4e804b1a007f6780057d3df1120f07799585abb",
}
QUALIFICATION_COMMIT = "ef26e53f5ecccabef1fff03ec86d71b0c93edd2b"
QUALIFICATION_TREE = "f646a40bcd70ec9ebc28f3ebf3783e54c1c8f9a1"
QUALIFICATION_PARENT = DOCUMENTATION_BRIDGE_COMMIT
QUALIFICATION_CORRECTION = {
    "path": "backend/tests/test_driver_isolation.py",
    "blob": "60ed5164ffe190ccbb5cee91ffe619eba7c8c9c2",
    "sha256": "d0eca2c56705068027b910991719971838d5f84033806f9a0ff9de0f7b3e0756",
}

# The validator's success summary intentionally retains the implementation identity.
CANDIDATE_COMMIT = IMPLEMENTATION_COMMIT
CANDIDATE_TREE = IMPLEMENTATION_TREE
CANDIDATE_PARENT = IMPLEMENTATION_PARENT
CANDIDATE_BLOBS = IMPLEMENTATION_BLOBS

TOOLCHAIN_LOCK_PATH = "scripts/release-toolchain-v04.json"
TOOLCHAIN_LOCK_SHA256 = (
    "c8aa471e4747acdbb631eb6df55d60a7c27c5a96264a7febc37a4143879b6def"
)
PYTHON_VERSION = "3.13.14"
PYTHON_SHA256 = "ef8f51028ac5329641985112f8efb1c2d4c47c86b8011ddf7e6fae21e2b4e5a1"
QUALIFICATION_DOCKERFILE_PATH = "scripts/qualification-v05.Dockerfile"
QUALIFICATION_DOCKERFILE_SHA256 = (
    "2b37374bf1f93ce8a184eb11e376715cf670558a229f57ed17c3089b6a931996"
)
QUALIFICATION_DOCKERIGNORE_PATH = "scripts/qualification-v05.Dockerfile.dockerignore"
QUALIFICATION_DOCKERIGNORE_SHA256 = (
    "ff2ebffc0b2654455ebe68b2a62a1e11ec9baca6982bda022c6ac30d397daa6f"
)
EXTERNAL_MANUAL_DIRECTORY = "SPELL-DOCUMENTATION"
EXTERNAL_MANUAL_LEDGER_PATH = "SPELL_DOCUMENTATION_REVIEW.md"
EXTERNAL_MANUAL_LEDGER_SHA256 = (
    "78c419f898bbc719e9e1134f8e57aa0352a07cd2b4d21644658f3f74237c56ad"
)
EXTERNAL_MANUALS = {
    "SPELL - Build Manual - 2.4.4.pdf": "6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6",
    "SPELL - Development Environment Manual - 2.4.4.pdf": "cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81",
    "SPELL - Driver Development Manual - 2.4.4.pdf": "057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5",
    "SPELL - GUI User Manual - 2.4.4.pdf": "1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6",
    "SPELL - Language Reference - 2.4.4.pdf": "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3",
    "SPELL - Server Manual - 2.4.4.pdf": "ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9",
    "SPELL-GUI-4.0.2-Build-Instructions.pdf": "5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6",
}
TOOLING_SYNTHETIC_NODES = (
    "scripts/tests/test_seed_driver_projection_v04.py::"
    "test_local_database_guard_rejects_nonqualification_targets["
    "postgresql+psycopg://spell:secret@example.com:5432/spell]",
    "scripts/tests/test_seed_driver_projection_v04.py::"
    "test_local_database_guard_rejects_nonqualification_targets["
    "postgresql+psycopg://spell:secret@localhost:5432/production]",
    "scripts/tests/test_supply_chain_v04.py::"
    "test_product_package_inspection_rejects_manual_or_credential_material["
    "backend/app.py------BEGIN PRIVATE KEY-----\\n"
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\n"
    "-----END PRIVATE KEY-----\\n-high-confidence secret material]",
)

INHERITED_SOURCE_FINGERPRINT = (
    "46949e783e85b72e68f70d1607c6d44bb5234586c248888b2bd4a3d2cf06f17d"
)
INHERITED_RUN_PATH = (
    "artifacts/v0.4/.qualification/runtime-captures/"
    + INHERITED_SOURCE_FINGERPRINT
    + "/regression/run.json"
)
INHERITED_CLASSIFICATION = "INHERITED_SUPPORT_ONLY_NOT_DIRECT_V05_PROOF"
INHERITED_SUPPORTS = ["compatibility", "browser", "performance"]

ARTIFACT_PATHS = {
    "backend_sqlite": "tests/backend-sqlite.xml",
    "backend_postgresql": "tests/backend-postgresql.xml",
    "driver_host": "tests/driver-host.xml",
    "tooling": "tests/tooling.xml",
}
SUITE_PREFIXES = {
    "backend_sqlite": "backend/tests/",
    "backend_postgresql": "backend/tests/",
    "driver_host": "driver_host/tests/",
    "tooling": "scripts/tests/",
}
EXPECTED_INVENTORIES = {
    "backend_sqlite": (
        269,
        "802b3aa602e209cca204a4d17e1e71eb65cec408d59f575b0b3269d2424d771b",
    ),
    "backend_postgresql": (
        269,
        "802b3aa602e209cca204a4d17e1e71eb65cec408d59f575b0b3269d2424d771b",
    ),
    "driver_host": (
        77,
        "fa97a356d4d76ed4650e04f73785b02ffe3f4b4d5c3655869c0a9ba2d7aff66a",
    ),
    "tooling": (
        334,
        "328ecc2e76375a745ad007e1e15eba14652a4e7d23064fe77640c342fa8f7098",
    ),
}
EXPECTED_SUBTEST_COUNTS = {
    "backend_sqlite": 0,
    "backend_postgresql": 0,
    "driver_host": 0,
    "tooling": 36,
}

SQLITE_ALLOWED_SKIPS = {
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
    "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
}
POSTGRESQL_MIGRATION_NODES = {
    node for node in SQLITE_ALLOWED_SKIPS if "test_migrations.py::test_" in node
}

IDENTITY_IDS = (
    "V05-IR-001-UNIT",
    "V05-IR-001-PARSER",
    "V05-IR-001-SUPERVISOR",
    "V05-IR-001-WORKER",
    "V05-IR-001-COMPAT",
    "V05-IR-001-ADVERSARIAL",
)
IDENTITY_CARDINALITIES = {
    "V05-IR-001-UNIT": 9,
    "V05-IR-001-PARSER": 4,
    "V05-IR-001-SUPERVISOR": 9,
    "V05-IR-001-WORKER": 7,
    "V05-IR-001-COMPAT": 8,
    "V05-IR-001-ADVERSARIAL": 38,
}

SHA256_RE = re.compile(r"[0-9a-f]{64}")
SHA1_RE = re.compile(r"[0-9a-f]{40}")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
PROJECT_RE = re.compile(r"spell-v05-candidate-[0-9a-f]{32}")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024


class CandidateEvidenceError(ValueError):
    """Raised when candidate evidence cannot be accepted."""


@dataclass(frozen=True)
class JUnitResult:
    statuses: Mapping[str, str]
    passed: int
    skipped: int
    failures: int
    errors: int
    subtests: int = 0


@dataclass(frozen=True)
class CandidateEvidenceValidation:
    candidate_commit: str
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
        if key in result:
            raise CandidateEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CandidateEvidenceError(f"non-finite JSON value: {value}")


def read_strict_json(path: Path, label: str) -> dict[str, Any]:
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    raw = path.read_bytes()
    _require(0 < len(raw) <= MAX_JSON_BYTES, f"{label} has an invalid size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateEvidenceError(f"{label} is not strict UTF-8 JSON") from exc
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual = set(value)
    missing = sorted(expected_set - actual)
    extra = sorted(actual - expected_set)
    _require(not missing, f"{label} is missing keys: {', '.join(missing)}")
    _require(not extra, f"{label} has unauthorized keys: {', '.join(extra)}")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0,
        f"{label} must be a non-negative integer",
    )
    return value


def _safe_relative_path(value: Any, label: str) -> str:
    text = _string(value, label)
    path = PurePosixPath(text)
    _require(
        not path.is_absolute()
        and bool(path.parts)
        and ".." not in path.parts
        and "\\" not in text,
        f"{label} is not a safe POSIX relative path",
    )
    return text


def _regular_relative(root: Path, relative: str, label: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CandidateEvidenceError(f"{label} escapes its evidence root") from exc
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    return path


def inventory_sha256(nodes: Sequence[str]) -> str:
    payload = "".join(f"{node}\n" for node in sorted(nodes)).encode("utf-8")
    return sha256_bytes(payload)


def _node_to_case_key(node: str) -> tuple[str, str]:
    parts = node.split("::")
    _require(len(parts) >= 2, f"invalid collected node ID: {node}")
    path = parts[0]
    _require(path.endswith(".py"), f"invalid collected Python path: {node}")
    module = path[:-3].replace("/", ".")
    classname = ".".join((module, *parts[1:-1]))
    return classname, parts[-1]


def _case_to_node(classname: Any, name: Any, label: str) -> str:
    _require(bool(classname) and bool(name), f"{label} contains an unnamed testcase")
    class_parts = str(classname).split(".")
    module_indexes = [
        index for index, part in enumerate(class_parts) if part.startswith("test_")
    ]
    _require(bool(module_indexes), f"{label} testcase class is not a test module")
    module_index = module_indexes[-1]
    node = "/".join(class_parts[: module_index + 1]) + ".py"
    if class_parts[module_index + 1 :]:
        node += "::" + "::".join(class_parts[module_index + 1 :])
    return node + f"::{name}"


def parse_junit(
    path: Path, label: str, *, expected_subtests: int = 0
) -> JUnitResult:
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    raw = path.read_bytes()
    _require(0 < len(raw) <= MAX_XML_BYTES, f"{label} has an invalid size")
    lowered = raw.lower()
    _require(b"<!doctype" not in lowered, f"{label} contains a DTD")
    _require(b"<!entity" not in lowered, f"{label} contains an entity declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise CandidateEvidenceError(f"{label} is not valid XML") from exc
    _require(root.tag in {"testsuite", "testsuites"}, f"{label} has an invalid root")

    statuses: dict[str, str] = {}
    passed = skipped = failures = errors = 0
    for case in root.iter("testcase"):
        classname = case.get("classname")
        name = case.get("name")
        node = _case_to_node(classname, name, label)
        children = [child.tag for child in case if child.tag in {"skipped", "failure", "error"}]
        _require(len(children) <= 1, f"{label} testcase has ambiguous status: {node}")
        status = children[0] if children else "passed"
        _require(node not in statuses, f"{label} contains a duplicate testcase: {node}")
        statuses[node] = status
        if status == "passed":
            passed += 1
        elif status == "skipped":
            skipped += 1
        elif status == "failure":
            failures += 1
        else:
            errors += 1

    _require(bool(statuses), f"{label} contains no testcases")
    reported_test_total = 0
    direct_case_total = 0
    for suite in root.iter("testsuite"):
        direct = suite.findall("testcase")
        if direct:
            reported = suite.get("tests")
            _require(
                reported is not None
                and reported.isdigit()
                and int(reported) >= len(direct),
                f"{label} suite testcase aggregate is invalid",
            )
            reported_test_total += int(reported)
            direct_case_total += len(direct)
            for attribute, element in (
                ("skipped", "skipped"),
                ("failures", "failure"),
                ("errors", "error"),
            ):
                value = suite.get(attribute)
                expected = sum(case.find(element) is not None for case in direct)
                _require(
                    value is not None and value.isdigit() and int(value) == expected,
                    f"{label} suite {attribute} aggregate differs",
                )
    subtests = reported_test_total - direct_case_total
    _require(
        subtests == expected_subtests,
        f"{label} suite subtest aggregate differs",
    )
    return JUnitResult(statuses, passed, skipped, failures, errors, subtests)


def expected_identity_map(backend_nodes: Sequence[str]) -> dict[str, list[str]]:
    nodes = set(backend_nodes)

    def exact(*values: str) -> set[str]:
        missing = sorted(set(values) - nodes)
        _require(not missing, f"candidate identity inventory is missing: {missing!r}")
        return set(values)

    def contains(value: str) -> set[str]:
        selected = {node for node in nodes if value in node}
        _require(bool(selected), f"candidate identity selector is empty: {value}")
        return selected

    unit = contains("backend/tests/test_ir_v03.py::test_v05_ir_001_unit_")
    parser = exact(
        "backend/tests/test_ir_v03.py::test_v05_ir_001_unit_accepts_complete_parser_golden_ir_without_rewriting_input",
        "backend/tests/test_ir_boundaries.py::test_parser_postvalidation_rejects_invalid_compiler_output",
        "backend/tests/test_procedure_parser.py::test_parser_creates_ir_without_executing_source",
        "backend/tests/test_procedure_parser.py::test_v03_compiles_typed_control_flow_and_local_calls_to_flat_ir",
    )
    supervisor = exact(
        "backend/tests/test_ir_boundaries.py::test_initial_start_accepts_a_valid_first_prompt",
        "backend/tests/test_ir_boundaries.py::test_supervisor_rejects_tampered_ir_before_generation_or_process_allocation",
        "backend/tests/test_ir_boundaries.py::test_rejection_audit_failure_still_prevents_worker_allocation",
    ) | contains(
        "backend/tests/test_ir_boundaries.py::test_persisted_row_mutations_fail_closed_before_worker_allocation["
    )
    worker = exact(
        "backend/tests/test_ir_v03.py::test_v05_ir_001_worker_facing_validation_rejects_unsized_steps",
    ) | contains(
        "backend/tests/test_ir_boundaries.py::test_worker_rejects_ir_before_started_ack_checkpoint_prompt_or_effect["
    ) | contains(
        "backend/tests/test_worker_expressions.py::test_expression_evaluator_rejects_invalid_runtime_ir["
    )
    compat = exact(
        "backend/tests/test_ir_v03.py::test_v05_ir_001_unit_accepts_complete_parser_golden_ir_without_rewriting_input",
        "backend/tests/test_ir_v03.py::test_v05_ir_001_compat_validates_recovery_checkpoint_without_byte_changes",
        "backend/tests/test_ir_boundaries.py::test_initial_start_accepts_a_valid_first_prompt",
        "backend/tests/test_procedure_parser.py::test_parser_creates_ir_without_executing_source",
        "backend/tests/test_procedure_parser.py::test_v03_compiles_typed_control_flow_and_local_calls_to_flat_ir",
        "backend/tests/test_v03_execution.py::test_typed_variables_survive_prompt_crash_and_recovery",
        "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_sqlite_database_without_record_drift",
        "backend/tests/test_worker_expressions.py::test_worker_restores_checkpointed_variables_at_recovery_step",
    )
    adversarial = (
        contains("backend/tests/test_ir_v03.py::test_v05_ir_001_adversarial_")
        | contains("backend/tests/test_ir_boundaries.py::test_supervisor_rejects_")
        | contains(
            "backend/tests/test_ir_boundaries.py::test_persisted_row_mutations_fail_closed_before_worker_allocation["
        )
        | contains("backend/tests/test_ir_boundaries.py::test_rejection_audit_failure_")
        | contains("backend/tests/test_ir_boundaries.py::test_worker_rejects_ir_before_")
        | exact(
            "backend/tests/test_ir_v03.py::test_v05_ir_001_worker_facing_validation_rejects_unsized_steps"
        )
    )
    result = {
        "V05-IR-001-UNIT": sorted(unit),
        "V05-IR-001-PARSER": sorted(parser),
        "V05-IR-001-SUPERVISOR": sorted(supervisor),
        "V05-IR-001-WORKER": sorted(worker),
        "V05-IR-001-COMPAT": sorted(compat),
        "V05-IR-001-ADVERSARIAL": sorted(adversarial),
    }
    for identity, expected_count in IDENTITY_CARDINALITIES.items():
        _require(
            len(result[identity]) == expected_count,
            f"{identity} exact candidate node count differs",
        )
    return result


def validate_suite(
    suite_id: str,
    suite: Mapping[str, Any],
    result: JUnitResult,
) -> list[str]:
    _exact_keys(
        suite,
        (
            "capture",
            "collected_nodes",
            "inventory_sha256",
            "test_count",
            "subtest_count",
            "passed_count",
            "skipped_count",
            "failure_count",
            "error_count",
            "network_mode",
        ),
        f"suites.{suite_id}",
    )
    _require(suite["capture"] == ARTIFACT_PATHS[suite_id], f"{suite_id} capture differs")
    raw_nodes = suite["collected_nodes"]
    _require(isinstance(raw_nodes, list), f"{suite_id} collected_nodes must be a list")
    nodes = [_string(node, f"{suite_id} collected node") for node in raw_nodes]
    _require(len(set(nodes)) == len(nodes), f"{suite_id} collected_nodes contains duplicates")
    _require(nodes == sorted(nodes), f"{suite_id} collected_nodes is not ordinally sorted")
    prefix = SUITE_PREFIXES[suite_id]
    _require(all(node.startswith(prefix) for node in nodes), f"{suite_id} contains a foreign node")
    expected_count, expected_digest = EXPECTED_INVENTORIES[suite_id]
    _require(len(nodes) == expected_count, f"{suite_id} candidate inventory count differs")
    digest = inventory_sha256(nodes)
    _require(digest == expected_digest, f"{suite_id} candidate inventory digest differs")
    _require(suite["inventory_sha256"] == digest, f"{suite_id} manifest inventory digest differs")

    expected_keys = {_node_to_case_key(node) for node in nodes}
    _require(set(result.statuses) == set(nodes), f"{suite_id} JUnit/inventory bijection differs")
    _require(len(expected_keys) == len(nodes), f"{suite_id} testcase key inventory is ambiguous")
    _require(_integer(suite["test_count"], f"{suite_id}.test_count") == len(nodes), f"{suite_id} test count differs")
    _require(
        _integer(suite["subtest_count"], f"{suite_id}.subtest_count")
        == EXPECTED_SUBTEST_COUNTS[suite_id]
        == result.subtests,
        f"{suite_id} subtest count differs",
    )
    for key, actual in (
        ("passed_count", result.passed),
        ("skipped_count", result.skipped),
        ("failure_count", result.failures),
        ("error_count", result.errors),
    ):
        _require(_integer(suite[key], f"{suite_id}.{key}") == actual, f"{suite_id} {key} differs")
    _require(result.failures == 0 and result.errors == 0, f"{suite_id} contains a failure or error")
    if suite_id in {"backend_sqlite", "driver_host", "tooling"}:
        _require(suite["network_mode"] == "none", f"{suite_id} network mode differs")
    else:
        _require(suite["network_mode"] == "internal", "PostgreSQL network mode differs")
        _require(result.skipped == 0, "PostgreSQL backend suite contains a skip")
    if suite_id == "backend_sqlite":
        skipped = {node for node, status in result.statuses.items() if status == "skipped"}
        _require(skipped == SQLITE_ALLOWED_SKIPS, "SQLite backend skip set differs")
    return nodes


def validate_database(database: Mapping[str, Any], postgres: JUnitResult) -> None:
    _exact_keys(
        database,
        (
            "application_name",
            "migration_name",
            "distinct_names",
            "both_environment_variables_bound",
            "postgresql_zero_skips",
            "network_internal",
            "host_port_published",
            "postgres_image_id",
        ),
        "database",
    )
    application = _string(database["application_name"], "database.application_name")
    migration = _string(database["migration_name"], "database.migration_name")
    _require(application == "spell_test", "application qualification database differs")
    _require(migration == "spell_migration_test", "migration qualification database differs")
    _require(application != migration, "application and migration databases are not distinct")
    _require(database["distinct_names"] is True, "distinct database assertion is absent")
    _require(
        database["both_environment_variables_bound"] is True,
        "both PostgreSQL environment variables were not bound",
    )
    _require(database["postgresql_zero_skips"] is True, "PostgreSQL zero-skip assertion is absent")
    _require(postgres.skipped == 0, "PostgreSQL JUnit contains a skip")
    _require(database["network_internal"] is True, "PostgreSQL network was not internal")
    _require(database["host_port_published"] is False, "PostgreSQL published a host port")
    _require(IMAGE_ID_RE.fullmatch(str(database["postgres_image_id"])) is not None, "PostgreSQL image ID is invalid")
    for node in POSTGRESQL_MIGRATION_NODES:
        _require(postgres.statuses.get(node) == "passed", f"PostgreSQL migration node did not pass: {node}")


def validate_identities(
    identities: Mapping[str, Any],
    backend_nodes: Sequence[str],
    sqlite: JUnitResult,
    postgres: JUnitResult,
) -> None:
    _require(set(identities) == set(IDENTITY_IDS), "V05 identity set differs")
    expected = expected_identity_map(backend_nodes)
    for identity in IDENTITY_IDS:
        value = _mapping(identities[identity], f"identities.{identity}")
        _exact_keys(
            value,
            ("nodes", "environments", "passed_count", "skipped_count"),
            f"identities.{identity}",
        )
        _require(value["nodes"] == expected[identity], f"{identity} exact node mapping differs")
        _require(value["environments"] == ["sqlite", "postgresql"], f"{identity} environments differ")
        observed = [
            suite.statuses.get(node)
            for suite in (sqlite, postgres)
            for node in expected[identity]
        ]
        _require(all(status == "passed" for status in observed), f"{identity} did not pass without skips")
        _require(value["passed_count"] == len(observed), f"{identity} passed count differs")
        _require(value["skipped_count"] == 0, f"{identity} contains a waiver or skip")


def _run_git(root: Path, arguments: Sequence[str]) -> bytes:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_REPLACE_REF_BASE",
    ):
        environment.pop(name, None)
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C", "LANG": "C"})
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidateEvidenceError("candidate Git validation could not run") from exc
    _require(completed.returncode == 0, f"candidate Git query failed: {' '.join(arguments)}")
    return completed.stdout


def _git_line(root: Path, arguments: Sequence[str], label: str) -> str:
    raw = _run_git(root, arguments)
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise CandidateEvidenceError(f"{label} is not ASCII") from exc
    _require(len(lines) == 1 and bool(lines[0]), f"{label} did not return one line")
    return lines[0]


def validate_implementation_candidate_git(
    root: Path, candidate: Mapping[str, Any]
) -> None:
    _exact_keys(
        candidate,
        ("commit", "tree", "parent", "changed_paths"),
        "implementation_candidate",
    )
    _require(
        candidate["commit"] == IMPLEMENTATION_COMMIT,
        "implementation candidate commit differs",
    )
    _require(
        candidate["tree"] == IMPLEMENTATION_TREE,
        "implementation candidate tree differs",
    )
    _require(
        candidate["parent"] == IMPLEMENTATION_PARENT,
        "implementation candidate parent differs",
    )
    changed = candidate["changed_paths"]
    _require(
        isinstance(changed, list),
        "implementation_candidate.changed_paths must be a list",
    )
    observed: dict[str, str] = {}
    for index, item_value in enumerate(changed):
        label = f"implementation_candidate.changed_paths[{index}]"
        item = _mapping(item_value, label)
        _exact_keys(item, ("path", "blob"), label)
        path = _safe_relative_path(item["path"], "implementation changed path")
        blob = _string(item["blob"], "implementation changed blob")
        _require(
            SHA1_RE.fullmatch(blob) is not None,
            "implementation changed blob ID is invalid",
        )
        _require(path not in observed, "implementation changed path is duplicated")
        observed[path] = blob
    _require(
        observed == IMPLEMENTATION_BLOBS,
        "implementation candidate changed path/blob binding differs",
    )

    _require(
        _git_line(root, ["cat-file", "-t", IMPLEMENTATION_COMMIT], "implementation type")
        == "commit",
        "implementation object is not a commit",
    )
    _require(
        _git_line(
            root,
            ["rev-parse", f"{IMPLEMENTATION_COMMIT}^{{tree}}"],
            "implementation tree",
        )
        == IMPLEMENTATION_TREE,
        "implementation Git tree differs",
    )
    _require(
        _git_line(
            root,
            ["rev-parse", f"{IMPLEMENTATION_COMMIT}^"],
            "implementation parent",
        )
        == IMPLEMENTATION_PARENT,
        "implementation Git parent differs",
    )
    diff_paths = _run_git(
        root,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", IMPLEMENTATION_COMMIT],
    ).decode("utf-8").splitlines()
    _require(
        diff_paths == sorted(IMPLEMENTATION_BLOBS),
        "implementation Git changed-path inventory differs",
    )
    for path, blob in IMPLEMENTATION_BLOBS.items():
        actual = _git_line(
            root,
            ["rev-parse", f"{IMPLEMENTATION_COMMIT}:{path}"],
            f"implementation blob {path}",
        )
        _require(actual == blob, f"implementation Git blob differs: {path}")


def _validate_commit_diff(
    root: Path,
    *,
    commit: str,
    tree: str,
    parent: str,
    blobs: Mapping[str, str],
    label: str,
) -> None:
    _require(
        _git_line(root, ["cat-file", "-t", commit], f"{label} type") == "commit",
        f"{label} object is not a commit",
    )
    _require(
        _git_line(root, ["rev-parse", f"{commit}^{{tree}}"], f"{label} tree") == tree,
        f"{label} Git tree differs",
    )
    _require(
        _git_line(root, ["rev-parse", f"{commit}^"], f"{label} parent") == parent,
        f"{label} Git parent differs",
    )
    paths = _run_git(
        root,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
    ).decode("utf-8").splitlines()
    _require(paths == sorted(blobs), f"{label} Git changed-path inventory differs")
    for path, blob in blobs.items():
        actual = _git_line(
            root, ["rev-parse", f"{commit}:{path}"], f"{label} blob {path}"
        )
        _require(actual == blob, f"{label} Git blob differs: {path}")


def validate_qualification_source_git(
    root: Path, qualification: Mapping[str, Any]
) -> None:
    _exact_keys(
        qualification,
        ("commit", "tree", "parent", "correction"),
        "qualification_source",
    )
    _require(
        qualification["commit"] == QUALIFICATION_COMMIT,
        "qualification source commit differs",
    )
    _require(
        qualification["tree"] == QUALIFICATION_TREE,
        "qualification source tree differs",
    )
    _require(
        qualification["parent"] == QUALIFICATION_PARENT,
        "qualification source parent differs",
    )
    correction = _mapping(
        qualification["correction"], "qualification_source.correction"
    )
    _exact_keys(
        correction,
        ("path", "blob", "sha256"),
        "qualification_source.correction",
    )
    _require(
        correction == QUALIFICATION_CORRECTION,
        "qualification correction binding differs",
    )

    _validate_commit_diff(
        root,
        commit=DOCUMENTATION_BRIDGE_COMMIT,
        tree=DOCUMENTATION_BRIDGE_TREE,
        parent=IMPLEMENTATION_COMMIT,
        blobs=DOCUMENTATION_BRIDGE_BLOBS,
        label="documentation bridge",
    )
    _validate_commit_diff(
        root,
        commit=QUALIFICATION_COMMIT,
        tree=QUALIFICATION_TREE,
        parent=QUALIFICATION_PARENT,
        blobs={QUALIFICATION_CORRECTION["path"]: QUALIFICATION_CORRECTION["blob"]},
        label="qualification source",
    )
    correction_bytes = _run_git(
        root,
        ["cat-file", "blob", f"{QUALIFICATION_COMMIT}:{QUALIFICATION_CORRECTION['path']}"],
    )
    _require(
        sha256_bytes(correction_bytes) == QUALIFICATION_CORRECTION["sha256"],
        "qualification correction content hash differs",
    )
    ancestry = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "merge-base",
            "--is-ancestor",
            QUALIFICATION_COMMIT,
            "HEAD",
        ],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    _require(
        ancestry.returncode == 0,
        "qualification source commit is not an ancestor of HEAD",
    )


def parse_external_manual_ledger(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateEvidenceError("external-manual ledger is not UTF-8") from exc
    pattern = re.compile(
        r"^\|\s*`(?P<name>[^`\r\n]+\.pdf)`\s*\|[^|\r\n]*\|"
        r"[^|\r\n]*\|\s*`(?P<sha>[0-9a-f]{64})`\s*\|",
        re.MULTILINE,
    )
    observed: dict[str, str] = {}
    for match in pattern.finditer(text):
        name = match.group("name")
        _require(name not in observed, "external-manual ledger contains a duplicate PDF")
        observed[name] = match.group("sha")
    _require(observed == EXTERNAL_MANUALS, "external-manual ledger inventory differs")
    return observed


def validate_external_manuals(
    root: Path, external: Mapping[str, Any]
) -> None:
    _exact_keys(
        external,
        ("directory", "ledger_path", "ledger_sha256", "files"),
        "toolchain.external_manuals",
    )
    _require(
        external["directory"] == EXTERNAL_MANUAL_DIRECTORY,
        "external-manual directory differs",
    )
    _require(
        external["ledger_path"] == EXTERNAL_MANUAL_LEDGER_PATH,
        "external-manual ledger path differs",
    )
    _require(
        external["ledger_sha256"] == EXTERNAL_MANUAL_LEDGER_SHA256,
        "external-manual ledger hash binding differs",
    )
    files = _mapping(external["files"], "toolchain.external_manuals.files")
    _require(files == EXTERNAL_MANUALS, "external-manual manifest map differs")

    ledger_raw = _run_git(
        root,
        ["cat-file", "blob", f"{QUALIFICATION_COMMIT}:{EXTERNAL_MANUAL_LEDGER_PATH}"],
    )
    _require(
        sha256_bytes(ledger_raw) == EXTERNAL_MANUAL_LEDGER_SHA256,
        "committed external-manual ledger hash differs",
    )
    _require(
        parse_external_manual_ledger(ledger_raw) == EXTERNAL_MANUALS,
        "committed external-manual ledger map differs",
    )

    manual_root = root / EXTERNAL_MANUAL_DIRECTORY
    _require(
        manual_root.is_dir() and not manual_root.is_symlink(),
        "external-manual directory is missing or unsafe",
    )
    entries = list(manual_root.iterdir())
    _require(
        all(path.is_file() and not path.is_symlink() for path in entries),
        "external-manual directory contains a non-regular entry",
    )
    _require(
        {path.name for path in entries} == set(EXTERNAL_MANUALS),
        "external-manual local inventory differs",
    )
    for name, expected in EXTERNAL_MANUALS.items():
        _require(
            sha256_bytes((manual_root / name).read_bytes()) == expected,
            f"external-manual local hash differs: {name}",
        )


def validate_toolchain(root: Path, toolchain: Mapping[str, Any]) -> None:
    _exact_keys(
        toolchain,
        (
            "lock_path",
            "lock_sha256",
            "python_version",
            "python_sha256",
            "qualification_dockerfile_path",
            "qualification_dockerfile_sha256",
            "qualification_dockerignore_path",
            "qualification_dockerignore_sha256",
            "qualification_image_id",
            "external_manuals",
        ),
        "toolchain",
    )
    _require(toolchain["lock_path"] == TOOLCHAIN_LOCK_PATH, "toolchain lock path differs")
    _require(toolchain["lock_sha256"] == TOOLCHAIN_LOCK_SHA256, "toolchain lock hash differs")
    _require(toolchain["python_version"] == PYTHON_VERSION, "locked Python version differs")
    _require(toolchain["python_sha256"] == PYTHON_SHA256, "locked Python hash differs")
    _require(
        toolchain["qualification_dockerfile_path"] == QUALIFICATION_DOCKERFILE_PATH,
        "qualification Dockerfile path differs",
    )
    _require(
        toolchain["qualification_dockerfile_sha256"] == QUALIFICATION_DOCKERFILE_SHA256,
        "qualification Dockerfile hash differs",
    )
    _require(
        toolchain["qualification_dockerignore_path"]
        == QUALIFICATION_DOCKERIGNORE_PATH,
        "qualification Dockerfile ignore path differs",
    )
    _require(
        toolchain["qualification_dockerignore_sha256"]
        == QUALIFICATION_DOCKERIGNORE_SHA256,
        "qualification Dockerfile ignore hash differs",
    )
    _require(IMAGE_ID_RE.fullmatch(str(toolchain["qualification_image_id"])) is not None, "qualification image ID is invalid")
    lock_path = root / TOOLCHAIN_LOCK_PATH
    _require(sha256_bytes(lock_path.read_bytes()) == TOOLCHAIN_LOCK_SHA256, "live toolchain lock hash differs")
    dockerfile_path = root / QUALIFICATION_DOCKERFILE_PATH
    _require(
        dockerfile_path.is_file()
        and not dockerfile_path.is_symlink()
        and sha256_bytes(dockerfile_path.read_bytes()) == QUALIFICATION_DOCKERFILE_SHA256,
        "live qualification Dockerfile hash differs",
    )
    dockerignore_path = root / QUALIFICATION_DOCKERIGNORE_PATH
    _require(
        dockerignore_path.is_file()
        and not dockerignore_path.is_symlink()
        and sha256_bytes(dockerignore_path.read_bytes())
        == QUALIFICATION_DOCKERIGNORE_SHA256,
        "live qualification Dockerfile ignore hash differs",
    )
    validate_external_manuals(
        root,
        _mapping(toolchain["external_manuals"], "toolchain.external_manuals"),
    )
    lock = read_strict_json(lock_path, "release toolchain lock")
    _require(lock.get("schema_version") == "spell.v04.release-toolchain/1", "release toolchain lock schema differs")
    tools = lock.get("tools")
    _require(isinstance(tools, list), "release toolchain tools are missing")
    python_entries = [item for item in tools if isinstance(item, dict) and item.get("name") == "python"]
    _require(len(python_entries) == 1, "release toolchain Python entry is ambiguous")
    python_entry = python_entries[0]
    _require(python_entry.get("sha256") == PYTHON_SHA256, "release toolchain Python entry hash differs")
    _require(lock.get("versions", {}).get("host_python") == PYTHON_VERSION, "release toolchain Python entry version differs")
    base = os.environ.get("LOCALAPPDATA")
    _require(bool(base), "LOCALAPPDATA is unavailable for locked Python validation")
    executable = Path(str(base)) / str(python_entry.get("relative_path", ""))
    _require(executable.is_file() and not executable.is_symlink(), "locked Python executable is missing or unsafe")
    _require(sha256_bytes(executable.read_bytes()) == PYTHON_SHA256, "locked Python executable hash differs")
    try:
        version = subprocess.run(
            [str(executable), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidateEvidenceError("locked Python executable could not run") from exc
    _require(version.returncode == 0, "locked Python executable failed")
    _require(version.stdout.decode("ascii").strip() == f"Python {PYTHON_VERSION}", "locked Python runtime version differs")


def validate_inherited_v04(root: Path, inherited: Mapping[str, Any]) -> None:
    _exact_keys(
        inherited,
        (
            "classification",
            "supports",
            "result_path",
            "result_sha256",
            "source_fingerprint_sha256",
            "direct_v05_proof",
        ),
        "inherited_v04",
    )
    _require(inherited["classification"] == INHERITED_CLASSIFICATION, "inherited evidence classification differs")
    _require(inherited["supports"] == INHERITED_SUPPORTS, "inherited evidence support scope differs")
    _require(inherited["result_path"] == INHERITED_RUN_PATH, "inherited regression path differs")
    _require(inherited["source_fingerprint_sha256"] == INHERITED_SOURCE_FINGERPRINT, "inherited source fingerprint differs")
    _require(inherited["direct_v05_proof"] is False, "inherited v0.4 evidence is misclassified as direct v0.5 proof")
    run_path = root.joinpath(*PurePosixPath(INHERITED_RUN_PATH).parts)
    run = read_strict_json(run_path, "inherited v0.4 regression run")
    run_hash = sha256_bytes(run_path.read_bytes())
    _require(inherited["result_sha256"] == run_hash, "inherited regression run hash differs")
    _require(run.get("schema_version") == "spell.v04.regression-run/1", "inherited regression schema differs")
    _require(run.get("product_version") == "0.4.0", "inherited regression product version differs")
    _require(run.get("source_fingerprint_before_sha256") == INHERITED_SOURCE_FINGERPRINT, "inherited regression starting source differs")
    _require(run.get("source_fingerprint_after_sha256") == INHERITED_SOURCE_FINGERPRINT, "inherited regression ending source differs")
    runtime = _mapping(run.get("runtime"), "inherited regression runtime")
    _require(runtime.get("qualification_python") == "Python 3.13.14", "inherited regression Python differs")
    _require(runtime.get("isolated_runtime_resources_torn_down") is True, "inherited regression teardown is unverified")
    commands = _mapping(run.get("commands"), "inherited regression commands")
    _require(bool(commands), "inherited regression commands are missing")
    _require(
        all(isinstance(value, dict) and value.get("return_code") == 0 for value in commands.values()),
        "inherited regression contains a failed command",
    )
    captures = _mapping(run.get("captures"), "inherited regression captures")
    run_root = run_path.parent
    for name, digest in captures.items():
        _require(isinstance(name, str) and SHA256_RE.fullmatch(str(digest)) is not None, "inherited capture binding is invalid")
        capture = _regular_relative(run_root, _safe_relative_path(name, "inherited capture"), "inherited capture")
        _require(sha256_bytes(capture.read_bytes()) == digest, f"inherited capture hash differs: {name}")


def _scan_secret_bytes(payload: bytes, label: str) -> None:
    lowered = payload.lower()
    for marker in (
        b"postgresql+psycopg://",
        b"v05-candidate-pg-",
        b"authorization: bearer ",
    ):
        _require(
            marker not in lowered,
            f"candidate evidence contains forbidden secret material: {label}",
        )
    _require(
        re.search(
            rb"-----begin (?:rsa |ec |openssh )?private key-----",
            lowered,
        )
        is None,
        f"candidate evidence contains private-key material: {label}",
    )


def _parse_manifest_bytes(manifest_raw: bytes) -> dict[str, Any]:
    _require(
        0 < len(manifest_raw) <= MAX_JSON_BYTES,
        "candidate qualification manifest has an invalid size",
    )
    try:
        value = json.loads(
            manifest_raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateEvidenceError(
            "candidate qualification manifest is not strict UTF-8 JSON"
        ) from exc
    _require(
        isinstance(value, dict),
        "candidate qualification manifest must be a JSON object",
    )
    return value


def _scan_manifest_secrets(manifest_raw: bytes) -> None:
    manifest = _parse_manifest_bytes(manifest_raw)
    try:
        tooling_nodes = manifest["suites"]["tooling"]["collected_nodes"]
    except (KeyError, TypeError) as exc:
        raise CandidateEvidenceError(
            "candidate manifest synthetic tooling node location is missing"
        ) from exc
    _require(
        isinstance(tooling_nodes, list),
        "candidate manifest tooling collected_nodes must be a list",
    )

    counts = {node: 0 for node in TOOLING_SYNTHETIC_NODES}

    def visit(value: Any, path: tuple[Any, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                _scan_secret_bytes(key.encode("utf-8"), MANIFEST_NAME)
                visit(child, (*path, key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, index))
        elif isinstance(value, str):
            permitted_location = (
                len(path) == 4
                and path[:3] == ("suites", "tooling", "collected_nodes")
                and isinstance(path[3], int)
            )
            if permitted_location and value in counts:
                counts[value] += 1
            else:
                _scan_secret_bytes(value.encode("utf-8"), MANIFEST_NAME)

    visit(manifest, ())
    _require(
        all(count == 1 for count in counts.values()),
        "candidate manifest must contain each synthetic tooling node exactly once",
    )


def _xml_attribute_value(value: str) -> bytes:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .encode("utf-8")
    )


def _scan_tooling_xml_secrets(path: Path, raw: bytes) -> None:
    lowered = raw.lower()
    _require(b"<!doctype" not in lowered, "tooling JUnit contains a DTD")
    _require(
        b"<!entity" not in lowered,
        "tooling JUnit contains an entity declaration",
    )
    try:
        parser = ET.XMLParser(
            target=ET.TreeBuilder(insert_comments=True, insert_pis=True)
        )
        root = ET.fromstring(raw, parser=parser)
    except ET.ParseError as exc:
        raise CandidateEvidenceError("tooling JUnit is not valid XML") from exc

    counts = {node: 0 for node in TOOLING_SYNTHETIC_NODES}
    for element in root.iter():
        if not isinstance(element.tag, str):
            if element.text:
                _scan_secret_bytes(element.text.encode("utf-8"), path.as_posix())
            if element.tail:
                _scan_secret_bytes(element.tail.encode("utf-8"), path.as_posix())
            continue

        permitted_name = False
        if element.tag == "testcase":
            node = _case_to_node(
                element.get("classname"), element.get("name"), "tooling JUnit"
            )
            if node in counts:
                counts[node] += 1
                permitted_name = True
        _scan_secret_bytes(element.tag.encode("utf-8"), path.as_posix())
        for attribute, value in element.attrib.items():
            _scan_secret_bytes(attribute.encode("utf-8"), path.as_posix())
            if not (permitted_name and attribute == "name"):
                _scan_secret_bytes(value.encode("utf-8"), path.as_posix())
        if element.text:
            _scan_secret_bytes(element.text.encode("utf-8"), path.as_posix())
        if element.tail:
            _scan_secret_bytes(element.tail.encode("utf-8"), path.as_posix())

    _require(
        all(count == 1 for count in counts.values()),
        "tooling JUnit must contain each synthetic testcase exactly once",
    )

    scanned = raw
    for node in TOOLING_SYNTHETIC_NODES:
        name = node.rsplit("::", 1)[1]
        attribute = b'name="' + _xml_attribute_value(name) + b'"'
        _require(
            scanned.count(attribute) == 1,
            "tooling JUnit synthetic testcase name is not uniquely anchored",
        )
        scanned = scanned.replace(attribute, b'name=""', 1)
    _scan_secret_bytes(scanned, path.as_posix())


def _validate_no_secret_material(
    manifest_raw: bytes, artifact_paths: Sequence[Path]
) -> None:
    _scan_manifest_secrets(manifest_raw)
    for path in artifact_paths:
        raw = path.read_bytes()
        if path.name == "tooling.xml":
            _scan_tooling_xml_secrets(path, raw)
        else:
            _scan_secret_bytes(raw, path.as_posix())


def validate_candidate_evidence(
    root: Path,
    evidence_root: Path | None = None,
    *,
    check_git: bool = True,
    check_toolchain: bool = True,
    check_inherited: bool = True,
) -> CandidateEvidenceValidation:
    root = root.resolve()
    evidence_root = (evidence_root or (root / DEFAULT_EVIDENCE_ROOT.relative_to(ROOT))).resolve()
    _require(evidence_root.is_dir() and not evidence_root.is_symlink(), "candidate evidence root is missing or unsafe")
    manifest_path = evidence_root / MANIFEST_NAME
    manifest = read_strict_json(manifest_path, "candidate qualification manifest")
    _exact_keys(
        manifest,
        (
            "schema_version",
            "product_version",
            "scope_profile",
            "implementation_candidate",
            "qualification_source",
            "toolchain",
            "database",
            "suites",
            "identities",
            "inherited_v04",
            "artifacts",
            "teardown",
            "overall_pass",
        ),
        "manifest",
    )
    _require(manifest["schema_version"] == SCHEMA_VERSION, "candidate evidence schema differs")
    _require(manifest["product_version"] == PRODUCT_VERSION, "candidate product marker differs")
    _require(manifest["scope_profile"] == SCOPE_PROFILE, "candidate scope profile differs")
    _require(manifest["overall_pass"] is True, "candidate qualification did not pass")

    candidate = _mapping(
        manifest["implementation_candidate"], "implementation_candidate"
    )
    qualification = _mapping(
        manifest["qualification_source"], "qualification_source"
    )
    if check_git:
        validate_implementation_candidate_git(root, candidate)
        validate_qualification_source_git(root, qualification)
    else:
        _require(
            candidate.get("commit") == IMPLEMENTATION_COMMIT,
            "implementation candidate commit differs",
        )
        _require(
            candidate.get("tree") == IMPLEMENTATION_TREE,
            "implementation candidate tree differs",
        )
        _require(
            candidate.get("parent") == IMPLEMENTATION_PARENT,
            "implementation candidate parent differs",
        )
        _require(
            qualification.get("commit") == QUALIFICATION_COMMIT,
            "qualification source commit differs",
        )
        _require(
            qualification.get("tree") == QUALIFICATION_TREE,
            "qualification source tree differs",
        )
        _require(
            qualification.get("parent") == QUALIFICATION_PARENT,
            "qualification source parent differs",
        )
        _require(
            qualification.get("correction") == QUALIFICATION_CORRECTION,
            "qualification correction binding differs",
        )

    toolchain = _mapping(manifest["toolchain"], "toolchain")
    if check_toolchain:
        validate_toolchain(root, toolchain)

    artifacts = _mapping(manifest["artifacts"], "artifacts")
    _require(set(artifacts) == set(ARTIFACT_PATHS.values()), "candidate artifact set differs")
    artifact_files: dict[str, Path] = {}
    for relative, digest in artifacts.items():
        _safe_relative_path(relative, "candidate artifact path")
        _require(SHA256_RE.fullmatch(str(digest)) is not None, f"candidate artifact hash is invalid: {relative}")
        path = _regular_relative(evidence_root, relative, f"candidate artifact {relative}")
        _require(sha256_bytes(path.read_bytes()) == digest, f"candidate artifact hash differs: {relative}")
        artifact_files[relative] = path
    expected_files = {MANIFEST_NAME, *ARTIFACT_PATHS.values()}
    discovered: set[str] = set()
    for path in evidence_root.rglob("*"):
        _require(not path.is_symlink(), "candidate evidence contains a symlink")
        if path.is_file():
            discovered.add(path.relative_to(evidence_root).as_posix())
    _require(discovered == expected_files, "candidate evidence file inventory differs")

    suites = _mapping(manifest["suites"], "suites")
    _require(set(suites) == set(ARTIFACT_PATHS), "candidate suite set differs")
    junit: dict[str, JUnitResult] = {}
    inventories: dict[str, list[str]] = {}
    for suite_id, relative in ARTIFACT_PATHS.items():
        junit[suite_id] = parse_junit(
            artifact_files[relative],
            suite_id,
            expected_subtests=EXPECTED_SUBTEST_COUNTS[suite_id],
        )
        inventories[suite_id] = validate_suite(
            suite_id,
            _mapping(suites[suite_id], f"suites.{suite_id}"),
            junit[suite_id],
        )
    _require(
        inventories["backend_sqlite"] == inventories["backend_postgresql"],
        "SQLite and PostgreSQL backend inventories differ",
    )

    validate_database(_mapping(manifest["database"], "database"), junit["backend_postgresql"])
    validate_identities(
        _mapping(manifest["identities"], "identities"),
        inventories["backend_sqlite"],
        junit["backend_sqlite"],
        junit["backend_postgresql"],
    )
    if check_inherited:
        validate_inherited_v04(root, _mapping(manifest["inherited_v04"], "inherited_v04"))

    teardown = _mapping(manifest["teardown"], "teardown")
    _exact_keys(
        teardown,
        (
            "project",
            "resources_torn_down",
            "runtime_proxy_stopped",
            "runtime_test_resources_torn_down",
            "image_tags_removed",
        ),
        "teardown",
    )
    _require(PROJECT_RE.fullmatch(str(teardown["project"])) is not None, "candidate teardown project differs")
    for key in (
        "resources_torn_down",
        "runtime_proxy_stopped",
        "runtime_test_resources_torn_down",
        "image_tags_removed",
    ):
        _require(teardown[key] is True, f"candidate teardown assertion is false: {key}")

    manifest_raw = manifest_path.read_bytes()
    _validate_no_secret_material(manifest_raw, list(artifact_files.values()))
    return CandidateEvidenceValidation(
        candidate_commit=CANDIDATE_COMMIT,
        suite_count=len(suites),
        identity_count=len(IDENTITY_IDS),
        test_count=sum(result.passed + result.skipped for result in junit.values()),
        evidence_sha256=sha256_bytes(manifest_raw),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--evidence-root", type=Path)
    args = parser.parse_args(argv)
    result = validate_candidate_evidence(args.root, args.evidence_root)
    print(
        json.dumps(
            {
                "gate": "PASS",
                "candidate_commit": result.candidate_commit,
                "suite_count": result.suite_count,
                "identity_count": result.identity_count,
                "test_count": result.test_count,
                "evidence_sha256": result.evidence_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
