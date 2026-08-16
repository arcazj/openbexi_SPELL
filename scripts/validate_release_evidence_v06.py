#!/usr/bin/env python3
"""Validate the bounded SPELL v0.6.0 final release evidence and tag."""

from __future__ import annotations

import argparse
import ast
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

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - compatibility for the legacy dev venv
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v06 import (  # noqa: E402
    is_link_or_reparse_v06,
    path_has_link_or_reparse_v06,
)
from scripts.accepted_v05_release_v06 import (  # noqa: E402
    V05_ARCHIVE_RELATIVE,
    V05_ARCHIVE_SHA256,
    V05_SIDECAR_RELATIVE,
    V05_SIDECAR_SHA256,
    V05_TAG_ARCHIVE_CLAIM,
    validate_accepted_v05_release,
)

DEFAULT_EVIDENCE_ROOT = ROOT / "artifacts" / "v0.6"
MANIFEST_NAME = "release-qualification.json"
SCHEMA_VERSION = "spell.v06.release-qualification/1"
PRODUCT_VERSION = "0.6.0"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"

# The Gate 0A and accepted v0.5 identities are immutable governance inputs.
# Candidate and final-source identities are intentionally read from evidence at
# validation time because they do not exist until the corresponding freeze.
GATE_0A_COMMIT = "f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1"
V05_TAG_REF = "refs/tags/v0.5.0"
V05_TAG_OBJECT = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
V05_COMMIT = "e7b6bb9428833437e0160040541eb840deee7cca"
V05_ARTIFACT_TREE = "27542ec5db41ff29ba2af62824c8d39f442b95e8"
V05_EXTERNAL_RELEASE_BINDING = {
    "archive_sha256": V05_ARCHIVE_SHA256,
    "sidecar_sha256": V05_SIDECAR_SHA256,
    "tag_object": V05_TAG_OBJECT,
    "tag_archive_claim": V05_TAG_ARCHIVE_CLAIM,
}

RELEASE_TAG = "v0.6.0"
RELEASE_TAG_REF = "refs/tags/v0.6.0"
FORBIDDEN_ALIAS_REF = "refs/tags/v0.6"
RELEASE_TAG_TITLE = "SPELL v0.6.0"
RELEASE_PACKAGE_PATH = "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz"
RELEASE_PACKAGE_SIDECAR_PATH = f"{RELEASE_PACKAGE_PATH}.sha256"
RELEASE_PACKAGE_PATHS = frozenset(
    {RELEASE_PACKAGE_PATH, RELEASE_PACKAGE_SIDECAR_PATH}
)
RELEASE_TAG_DYNAMIC_FIELDS = (
    "Release commit",
    "Qualified source commit",
    "Candidate implementation commit",
    "Source fingerprint",
    "Evidence fingerprint",
    "Product package SHA-256",
    "Work-package evidence SHA-256",
    "Final archive SHA-256",
)
WORK_PACKAGE_PATH = "artifacts/v0.6/work-package/qualification.json"
WORK_PACKAGE_VALIDATOR = "scripts/validate_candidate_evidence_v06.py"
GATE_0B_SCOPE = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "scopes/v0.6-gate-0b.json"
)
GATE_0B_DOCUMENT = "SPELL_v0.6_Gate_0B.md"
GATE_0B_VALIDATOR = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
    "validate_v06_gate_0b.py"
)
GATE_0B_MARKER = (
    "gate=PASS work_packages=9 identities=45 failed=0 skipped=0 "
    "claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED"
)

FINAL_SUITE_IDS = (
    "backend_sqlite",
    "backend_postgresql",
    "backend_docker_host",
    "driver_host",
    "tooling",
    "frontend_unit",
    "frontend_build",
    "browser_mocked",
    "browser_real",
)
FINAL_QUALIFICATION_PATH = "artifacts/v0.6/final/qualification.json"
CANONICAL_EVIDENCE_PATHS = frozenset(
    {
        WORK_PACKAGE_PATH,
        "artifacts/v0.6/work-package/schema.json",
        "artifacts/v0.6/work-package/tests/backend-sqlite.xml",
        "artifacts/v0.6/work-package/tests/backend-postgresql.xml",
        "artifacts/v0.6/work-package/tests/backend-docker-host.xml",
        "artifacts/v0.6/work-package/tests/backend-v06-soak.json",
        "artifacts/v0.6/work-package/tests/driver-host.xml",
        "artifacts/v0.6/work-package/tests/tooling.xml",
        "artifacts/v0.6/work-package/tests/frontend-vitest.xml",
        "artifacts/v0.6/work-package/tests/frontend-build.json",
        "artifacts/v0.6/work-package/tests/frontend-playwright-mocked.xml",
        "artifacts/v0.6/work-package/tests/frontend-playwright-live.xml",
        "artifacts/v0.6/work-package/browser/desktop-as-run-report.png",
        "artifacts/v0.6/work-package/browser/desktop-v03-validation.png",
        "artifacts/v0.6/work-package/browser/mobile-durable-prompt.png",
        FINAL_QUALIFICATION_PATH,
        "artifacts/v0.6/final/tests/backend-sqlite.xml",
        "artifacts/v0.6/final/tests/backend-postgresql.xml",
        "artifacts/v0.6/final/tests/backend-docker-host.xml",
        "artifacts/v0.6/final/tests/driver-host.xml",
        "artifacts/v0.6/final/tests/tooling.xml",
        "artifacts/v0.6/final/tests/frontend-unit.json",
        "artifacts/v0.6/final/tests/frontend-build.json",
        "artifacts/v0.6/final/tests/browser-mocked.xml",
        "artifacts/v0.6/final/tests/browser-real.xml",
        "artifacts/v0.6/sbom/backend.cdx.json",
        "artifacts/v0.6/sbom/driver.cdx.json",
        "artifacts/v0.6/sbom/frontend.cdx.json",
        "artifacts/v0.6/sbom/proxy.cdx.json",
        "artifacts/v0.6/sbom/SHA256SUMS",
        "artifacts/v0.6/supply-chain.json",
    }
)
JUNIT_SUITE_IDS = (
    "backend_sqlite",
    "backend_postgresql",
    "backend_docker_host",
    "driver_host",
    "tooling",
    "browser_mocked",
    "browser_real",
)
ZERO_SKIP_SUITE_IDS = (
    "backend_postgresql",
    "backend_docker_host",
    "driver_host",
    "tooling",
    "frontend_unit",
    "browser_mocked",
    "browser_real",
)
FINAL_SUBTEST_COUNTS = {
    "backend_sqlite": 0,
    "backend_postgresql": 0,
    "backend_docker_host": 0,
    "driver_host": 0,
    "tooling": 36,
    "frontend_unit": 0,
    "browser_mocked": 0,
    "browser_real": 0,
}
SQLITE_ALLOWED_SKIPS = (
    "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
    "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
    "backend/tests/test_migrations.py::test_migrations_create_fresh_postgresql_schema_and_are_idempotent",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v02_postgresql_database",
    "backend/tests/test_migrations.py::test_migrations_upgrade_populated_v03_postgresql_database_without_record_drift",
    "backend/tests/test_migrations.py::test_failed_postgresql_migration_rolls_back_and_remains_pending",
)

SBOM_FILES = (
    "backend.cdx.json",
    "driver.cdx.json",
    "frontend.cdx.json",
    "proxy.cdx.json",
)
SBOM_SUBJECTS = {
    "backend.cdx.json": "openbexi_spell-backend:0.6",
    "driver.cdx.json": "openbexi_spell-driver:0.6",
    "frontend.cdx.json": "openbexi_spell-frontend:0.6",
    "proxy.cdx.json": "openbexi_spell-proxy:0.6",
}
SBOM_REQUIRED_COMPONENTS = {
    "backend.cdx.json": {
        "fastapi", "grpcio", "protobuf", "psycopg", "pydantic", "sqlalchemy", "uvicorn"
    },
    "driver.cdx.json": {"grpcio", "protobuf"},
    "frontend.cdx.json": {
        "@reduxjs/toolkit", "echarts", "lucide-react", "react", "react-dom", "react-redux"
    },
    "proxy.cdx.json": {"nginx"},
}
SBOM_SOURCE_PROPERTY = "openbexi:source-fingerprint-sha256"
SBOM_IMAGE_PROPERTY = "openbexi:scanned-image-id"

ALLOWED_CANDIDATE_DELTA = {
    ".dockerignore",
    ".env.example",
    ".gitignore",
    "README.md",
    "PROVENANCE.md",
    "PROJECT_ROADMAP.md",
    "PROMPT_History.md",
    "SPELL_v0.6_Gate_0B.md",
    "SPELL_v0.6_Release.md",
    "Test_and_Integration.md",
    "VERSION_TIMELINE.md",
    "backend/__init__.py",
    "backend/version.py",
    "frontend/package-lock.json",
    "frontend/package.json",
    "frontend/README.md",
    "pyproject.toml",
    GATE_0B_SCOPE,
    GATE_0B_VALIDATOR,
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v06_gate_0b.py"
    ),
    "scripts/audit_supply_chain_v06.ps1",
    "scripts/build_reproducible_v06.py",
    "scripts/create_release_qualification_v06.py",
    "scripts/generate_sbom_v06.ps1",
    "scripts/package-v04.Dockerfile.dockerignore",
    "scripts/package-v06.Dockerfile",
    "scripts/package_release_v06.ps1",
    "scripts/qualification-v06.Dockerfile",
    "scripts/qualification-v06.Dockerfile.dockerignore",
    "scripts/qualify_candidate_v06.ps1",
    "scripts/qualify_release_v06.ps1",
    "scripts/source_fingerprint_v06.py",
    "scripts/tests/test_qualify_release_v06.py",
    "scripts/tests/test_create_release_qualification_v06.py",
    "scripts/tests/test_release_v06.py",
    "scripts/tests/test_validate_candidate_evidence_v06.py",
    "scripts/tests/test_validate_release_evidence_v06.py",
    WORK_PACKAGE_VALIDATOR,
    "scripts/validate_release_evidence_v06.py",
}
ALLOWED_CANDIDATE_DELTA.update(
    {
        "PROJECT_ROADMAP.md",
        "PROMPT_History.md",
        "Test_and_Integration.md",
        "VERSION_TIMELINE.md",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024
CANONICAL_XML_DECLARATION = b'<?xml version="1.0" encoding="utf-8"?>'
SECRET_MARKERS = (
    b"postgresql+psycopg://",
    b"authorization: bearer ",
    b"-----begin private key-----",
    b"-----begin rsa private key-----",
    b"-----begin ec private key-----",
    b"-----begin openssh private key-----",
)
TAGGER_HEADER_RE = re.compile(
    br"tagger [^\x00-\x20<>](?:[^\x00-\x1f<>]*[^\x00-\x20<>])? "
    br"<[^<>\x00-\x20@]+@[^<>\x00-\x20@]+> [0-9]+ "
    br"[+-](?:0[0-9]|1[0-4])[0-5][0-9]"
)
TAG_SIGNATURE_HEADER_RE = re.compile(
    br"(?i)^(?:gpgsig(?:-sha256)?|sshsig|signature)(?:[ \t]|$)"
)
TAG_SIGNATURE_MARKERS = (
    b"-----begin pgp signature-----",
    b"-----begin ssh signature-----",
)
TOOLING_SECRET_CANARY_NODES = (
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
TOOLING_SECRET_CANARY_PAYLOADS = (
    b"postgresql+psycopg://spell:secret@example.com:5432/spell",
    b"postgresql+psycopg://spell:secret@localhost:5432/production",
    (
        b"-----BEGIN PRIVATE KEY-----\\n"
        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\n"
        b"-----END PRIVATE KEY-----\\n"
    ),
)
_TOOLING_MANIFEST_MUTATION_TEST = (
    "scripts/tests/test_validate_candidate_evidence_v05.py::"
    "test_secret_material_scan_rejects_manifest_location_count_and_nearby_mutations"
)


def _final_tooling_manifest_mutation_nodes() -> tuple[str, ...]:
    nodes = TOOLING_SECRET_CANARY_NODES
    manifests = (
        {"suites": {"tooling": {"collected_nodes": list(nodes[:-1])}}},
        {"suites": {"tooling": {"collected_nodes": [*nodes, nodes[0]]}}},
        {
            "suites": {"tooling": {"collected_nodes": []}},
            "wrong_path": list(nodes),
        },
        {
            "suites": {"tooling": {"collected_nodes": list(nodes)}},
            "extra_node": nodes[0],
        },
        {
            "suites": {
                "tooling": {
                    "collected_nodes": [nodes[0] + "-tampered", *nodes[1:]]
                }
            }
        },
    )
    return tuple(
        _TOOLING_MANIFEST_MUTATION_TEST
        + "["
        + json.dumps(manifest, separators=(",", ":"))
        + "]"
        for manifest in manifests
    )


FINAL_TOOLING_SECRET_TESTCASE_NODES = (
    *TOOLING_SECRET_CANARY_NODES,
    *_final_tooling_manifest_mutation_nodes(),
)
V06_PRIVATE_KEY_CANARY = "-----BEGIN " + "PRIVATE KEY-----"
V06_AWS_ACCESS_KEY_CANARY = "AKIA" + "ABCDEFGHIJKLMNOP"
BACKEND_SECRET_CANARY_NODES = (
    "backend/tests/test_ir_v06.py::"
    "test_prompt_secret_material_is_rejected_without_echo["
    f"{V06_PRIVATE_KEY_CANARY}\\nredacted]",
    "backend/tests/test_ir_v06.py::"
    "test_action_and_startproc_secrets_are_rejected_without_echo["
    f"{V06_PRIVATE_KEY_CANARY}\\nredacted]",
    "backend/tests/test_ir_v06.py::"
    "test_action_and_startproc_secrets_are_rejected_without_echo["
    f"{V06_AWS_ACCESS_KEY_CANARY}]",
)
TOOLING_CAPTURE_PATHS = frozenset(
    {
        "artifacts/v0.6/work-package/tests/tooling.xml",
        "artifacts/v0.6/final/tests/tooling.xml",
    }
)
BACKEND_SECRET_CAPTURE_PATHS = frozenset(
    {
        "artifacts/v0.6/work-package/tests/backend-postgresql.xml",
        "artifacts/v0.6/work-package/tests/backend-sqlite.xml",
        "artifacts/v0.6/final/tests/backend-postgresql.xml",
        "artifacts/v0.6/final/tests/backend-sqlite.xml",
    }
)


class ReleaseEvidenceError(ValueError):
    """Raised when final v0.6 evidence cannot be accepted."""


@dataclass(frozen=True)
class TestCaptureResult:
    nodes: Mapping[str, str]
    passed: int
    skipped: int
    failures: int
    errors: int
    subtests: int


@dataclass(frozen=True)
class ReleaseEvidenceValidationV06:
    source_fingerprint_sha256: str
    evidence_fingerprint_sha256: str
    product_package_sha256: str
    qualified_source_commit: str
    release_head_commit: str
    validated_suite_ids: tuple[str, ...]
    validated_test_count: int
    validated_subtest_count: int
    sbom_image_ids: tuple[str, ...]
    work_package_evidence_sha256: str
    tag_object_id: str | None = None
    tagged_commit: str | None = None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseEvidenceError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReleaseEvidenceError(f"non-finite JSON value: {value}")


def parse_strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError(f"{label} is not strict UTF-8 JSON") from exc


def read_strict_json(
    path: Path,
    label: str,
    *,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> Any:
    _require(
        path.is_file() and not is_link_or_reparse_v06(path),
        f"{label} is missing or unsafe",
    )
    raw = path.read_bytes()
    _require(0 < len(raw) <= maximum_bytes, f"{label} has an invalid size")
    return parse_strict_json(raw, label)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual = set(value)
    missing = sorted(expected_set - actual)
    extra = sorted(actual - expected_set)
    _require(not missing, f"{label} is missing keys: {', '.join(missing)}")
    _require(not extra, f"{label} has unauthorized keys: {', '.join(extra)}")


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        f"{label} must be an integer >= {minimum}",
    )
    return value


def _string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    _require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} is not a lowercase SHA-256")
    return value


def _sha1(value: Any, label: str) -> str:
    _require(isinstance(value, str) and SHA1_RE.fullmatch(value) is not None, f"{label} is not a Git SHA-1")
    return value


def _safe_relative(value: Any, label: str) -> str:
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
        raise ReleaseEvidenceError(f"{label} escapes its root") from exc
    _require(
        path.is_file() and not path_has_link_or_reparse_v06(root, path),
        f"{label} is missing or unsafe",
    )
    return path


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_REPLACE_REF_BASE",
    ):
        environment.pop(key, None)
    environment.update(
        {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANG": "C"}
    )
    return environment


def _run_git(
    root: Path,
    arguments: Sequence[str],
    *,
    accepted: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseEvidenceError(f"cannot run Git {' '.join(arguments)}") from exc
    if result.returncode not in accepted:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise ReleaseEvidenceError(
            f"Git {' '.join(arguments)} failed ({result.returncode}): {detail}"
        )
    return result


def _git_line(root: Path, arguments: Sequence[str], label: str) -> str:
    try:
        lines = _run_git(root, arguments).stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError(f"{label} is not ASCII") from exc
    _require(len(lines) == 1 and bool(lines[0]), f"{label} did not produce one line")
    return lines[0]


def _git_name_list(root: Path, arguments: Sequence[str], label: str) -> list[str]:
    raw = _run_git(root, arguments).stdout
    _require(raw.endswith(b"\0") or raw == b"", f"{label} is not NUL terminated")
    values = raw.split(b"\0")
    if values and values[-1] == b"":
        values.pop()
    try:
        names = [value.decode("utf-8") for value in values]
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError(f"{label} contains a non-UTF-8 path") from exc
    _require(len(names) == len(set(names)), f"{label} contains a duplicate path")
    return names


def _git_blob_bytes(root: Path, commit: str, relative: str, label: str) -> bytes:
    path = _safe_relative(relative, label)
    object_id = _git_line(
        root,
        ["rev-parse", f"{commit}:{path}"],
        f"{label} Git blob",
    )
    _require(
        _git_line(root, ["cat-file", "-t", object_id], f"{label} Git object type")
        == "blob",
        f"{label} is not a Git blob",
    )
    return _run_git(root, ["cat-file", "blob", object_id]).stdout


def candidate_source_commit(root: Path) -> str:
    """Return the late-bound implementation freeze recorded by candidate evidence."""

    path = _regular_relative(root, WORK_PACKAGE_PATH, "candidate qualification")
    candidate = _mapping(
        read_strict_json(path, "candidate qualification"),
        "candidate qualification",
    )
    source = _mapping(candidate.get("source"), "candidate qualification source")
    return _sha1(source.get("commit"), "candidate qualification source commit")


def _junit_node(classname: Any, name: Any, label: str) -> str:
    _require(bool(classname) and bool(name), f"{label} contains an unnamed testcase")
    class_parts = str(classname).split(".")
    module_indexes = [
        index for index, part in enumerate(class_parts) if part.startswith("test_")
    ]
    if module_indexes:
        module_index = module_indexes[-1]
        node = "/".join(class_parts[: module_index + 1]) + ".py"
        if class_parts[module_index + 1 :]:
            node += "::" + "::".join(class_parts[module_index + 1 :])
        return node + f"::{name}"
    # Playwright classnames are normalized by project and are not Python modules.
    return f"{classname}::{name}"


def parse_junit(
    path: Path,
    label: str,
    *,
    expected_subtests: int = 0,
) -> TestCaptureResult:
    _require(
        path.is_file() and not is_link_or_reparse_v06(path),
        f"{label} is missing or unsafe",
    )
    raw = path.read_bytes()
    _require(0 < len(raw) <= MAX_XML_BYTES, f"{label} has an invalid size")
    lowered = raw.lower()
    _require(b"<!doctype" not in lowered, f"{label} contains a DTD")
    _require(b"<!entity" not in lowered, f"{label} contains an entity declaration")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ReleaseEvidenceError(f"{label} is not valid XML") from exc
    _require(root.tag in {"testsuite", "testsuites"}, f"{label} has an invalid root")
    nodes: dict[str, str] = {}
    passed = skipped = failures = errors = 0
    for case in root.iter("testcase"):
        node = _junit_node(case.get("classname"), case.get("name"), label)
        children = [child.tag for child in case if child.tag in {"skipped", "failure", "error"}]
        _require(len(children) <= 1, f"{label} testcase has an ambiguous result: {node}")
        status = children[0] if children else "passed"
        _require(node not in nodes, f"{label} contains a duplicate testcase: {node}")
        nodes[node] = status
        duration = case.get("time")
        if duration is not None:
            try:
                seconds = float(duration)
            except ValueError as exc:
                raise ReleaseEvidenceError(f"{label} contains an invalid testcase time") from exc
            _require(math.isfinite(seconds) and seconds >= 0, f"{label} contains an invalid testcase time")
        if status == "passed":
            passed += 1
        elif status == "skipped":
            skipped += 1
        elif status == "failure":
            failures += 1
        else:
            errors += 1
    _require(bool(nodes), f"{label} contains no testcases")
    reported_test_total = 0
    direct_case_total = 0
    for suite in root.iter("testsuite"):
        direct = suite.findall("testcase")
        if not direct:
            continue
        reported = suite.get("tests")
        _require(
            reported is not None
            and reported.isdigit()
            and int(reported) >= len(direct),
            f"{label} suite testcase aggregate is invalid",
        )
        reported_test_total += int(reported)
        direct_case_total += len(direct)
        expected = {
            "skipped": sum(case.find("skipped") is not None for case in direct),
            "failures": sum(case.find("failure") is not None for case in direct),
            "errors": sum(case.find("error") is not None for case in direct),
        }
        for attribute, count in expected.items():
            value = suite.get(attribute)
            _require(value is not None and value.isdigit() and int(value) == count, f"{label} suite {attribute} aggregate differs")
    subtests = reported_test_total - direct_case_total
    _require(
        subtests == expected_subtests,
        f"{label} suite subtest aggregate differs",
    )
    return TestCaptureResult(nodes, passed, skipped, failures, errors, subtests)


def parse_vitest(path: Path, label: str) -> TestCaptureResult:
    value = _mapping(read_strict_json(path, label, maximum_bytes=MAX_EVIDENCE_FILE_BYTES), label)
    expected_keys = {
        "numTotalTestSuites", "numPassedTestSuites", "numFailedTestSuites", "numPendingTestSuites",
        "numTotalTests", "numPassedTests", "numFailedTests", "numPendingTests", "numTodoTests",
        "snapshot", "startTime", "success", "testResults",
    }
    _exact_keys(value, expected_keys, label)
    totals = {
        key: _integer(value.get(key), f"{label}.{key}")
        for key in expected_keys
        if key.startswith("num")
    }
    _require(value.get("success") is True, f"{label} did not pass")
    _require(totals["numTotalTests"] > 0, f"{label} contains no tests")
    _require(totals["numPassedTests"] == totals["numTotalTests"], f"{label} did not pass every test")
    for key in ("numFailedTests", "numPendingTests", "numTodoTests", "numFailedTestSuites", "numPendingTestSuites"):
        _require(totals[key] == 0, f"{label}.{key} must be zero")
    _require(totals["numPassedTestSuites"] == totals["numTotalTestSuites"], f"{label} did not pass every suite")
    results = value.get("testResults")
    _require(isinstance(results, list) and bool(results), f"{label}.testResults is invalid")
    nodes: dict[str, str] = {}
    for suite in results:
        suite_value = _mapping(suite, f"{label}.testResults[]")
        _require(suite_value.get("status") == "passed", f"{label} contains a non-passing suite")
        assertions = suite_value.get("assertionResults")
        _require(isinstance(assertions, list) and bool(assertions), f"{label} suite has no assertions")
        for assertion in assertions:
            item = _mapping(assertion, f"{label}.assertionResults[]")
            name = _string(item.get("fullName"), f"{label} assertion fullName")
            _require(item.get("status") == "passed", f"{label} assertion did not pass: {name}")
            node = f"{suite_value.get('name', '')}::{name}"
            _require(node not in nodes, f"{label} contains a duplicate assertion: {node}")
            nodes[node] = "passed"
    _require(len(nodes) == totals["numTotalTests"], f"{label} assertion count differs")
    return TestCaptureResult(nodes, len(nodes), 0, 0, 0, 0)


def validate_frontend_build(
    root: Path,
    suite: Mapping[str, Any],
    source_fingerprint: str,
) -> int:
    _exact_keys(
        suite,
        ("kind", "capture", "sha256", "passed", "dist_file_count", "dist_sha256"),
        "final_suites.frontend_build",
    )
    _require(suite.get("kind") == "frontend-build", "frontend build kind differs")
    relative = _safe_relative(suite.get("capture"), "frontend build capture")
    _require(relative == "artifacts/v0.6/final/tests/frontend-build.json", "frontend build capture path differs")
    path = _regular_relative(root, relative, "frontend build capture")
    _require(sha256_bytes(path.read_bytes()) == _sha256(suite.get("sha256"), "frontend build hash"), "frontend build capture hash differs")
    _require(suite.get("passed") is True, "frontend build did not pass")
    file_count = _integer(suite.get("dist_file_count"), "frontend build dist_file_count", minimum=1)
    dist_sha = _sha256(suite.get("dist_sha256"), "frontend build dist_sha256")
    capture = _mapping(read_strict_json(path, "frontend build capture"), "frontend build capture")
    _exact_keys(
        capture,
        (
            "schema_version", "product_version", "source_fingerprint_sha256", "command",
            "return_code", "passed", "dist_file_count", "dist_sha256",
        ),
        "frontend build capture",
    )
    _require(capture.get("schema_version") == "spell.v06.frontend-build/1", "frontend build schema differs")
    _require(capture.get("product_version") == PRODUCT_VERSION, "frontend build product version differs")
    _require(capture.get("source_fingerprint_sha256") == source_fingerprint, "frontend build source fingerprint differs")
    _require(capture.get("command") == ["npm", "run", "build"], "frontend build command differs")
    _require(capture.get("return_code") == 0 and capture.get("passed") is True, "frontend build result differs")
    _require(capture.get("dist_file_count") == file_count, "frontend build file count differs")
    _require(capture.get("dist_sha256") == dist_sha, "frontend build dist hash differs")
    return 0


def _validate_version_assignments(path: Path, expected: Mapping[str, str], label: str) -> None:
    _require(
        path.is_file() and not is_link_or_reparse_v06(path),
        f"{label} is missing or unsafe",
    )
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise ReleaseEvidenceError(f"{label} cannot be parsed") from exc
    observed: dict[str, list[Any]] = {key: [] for key in expected}
    for node in ast.walk(tree):
        name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name, value = node.target.id, node.value
        if name in observed and value is not None:
            try:
                observed[name].append(ast.literal_eval(value))
            except (ValueError, TypeError):
                observed[name].append(object())
    for key, value in expected.items():
        _require(observed[key] == [value], f"{label} {key} differs or is ambiguous")


def validate_version_metadata(root: Path) -> None:
    pyproject_path = root / "pyproject.toml"
    _require(
        pyproject_path.is_file() and not is_link_or_reparse_v06(pyproject_path),
        "pyproject.toml is missing or unsafe",
    )
    try:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseEvidenceError("pyproject.toml is invalid") from exc
    _require(pyproject.get("project", {}).get("version") == PRODUCT_VERSION, "Python project version differs")
    supply = pyproject.get("tool", {}).get("spell", {}).get("supply-chain", {})
    _require(supply.get("release_artifact_root") == "artifacts/v0.6", "v0.6 artifact root differs")
    _require(supply.get("release_toolchain_lock") == "scripts/release-toolchain-v04.json", "inherited toolchain lock differs")
    package = _mapping(read_strict_json(root / "frontend/package.json", "frontend package"), "frontend package")
    lock = _mapping(read_strict_json(root / "frontend/package-lock.json", "frontend package lock"), "frontend package lock")
    _require(package.get("version") == PRODUCT_VERSION, "frontend package version differs")
    _require(lock.get("version") == PRODUCT_VERSION, "frontend lock version differs")
    _require(lock.get("packages", {}).get("", {}).get("version") == PRODUCT_VERSION, "frontend lock root package version differs")
    _validate_version_assignments(root / "backend/version.py", {"PRODUCT_VERSION": PRODUCT_VERSION}, "backend version")
    _validate_version_assignments(root / "backend/__init__.py", {"__version__": PRODUCT_VERSION}, "backend package")
    _validate_version_assignments(root / "driver_host/config.py", {"implementation_version": "0.4.0"}, "driver host config")
    _validate_version_assignments(root / "backend/driver_gateway.py", {"EXPECTED_IMPLEMENTATION_VERSION": "0.4.0"}, "driver gateway")
    for relative in ("driver_host/Dockerfile", "driver_host/pki.Dockerfile"):
        path = root / relative
        _require(
            path.is_file() and not is_link_or_reparse_v06(path),
            f"{relative} is missing or unsafe",
        )
        lines = path.read_text(encoding="utf-8").splitlines()
        _require(lines.count("ARG SPELL_PACKAGE_VERSION=0.4.0") == 1, f"{relative} retained driver package version differs")
        _require("ARG SPELL_PACKAGE_VERSION=0.6.0" not in lines, f"{relative} incorrectly advances driver identity")


def _allowed_candidate_path(path: str) -> bool:
    return path in ALLOWED_CANDIDATE_DELTA or path.startswith("artifacts/v0.6/work-package/")


def validate_release_closeout_paths(
    paths: Sequence[str],
    *,
    require_package: bool = False,
) -> None:
    package_paths: set[str] = set()
    for path in paths:
        _require(
            path.startswith("artifacts/v0.6/"),
            f"release closeout changes source outside canonical v0.6 evidence: {path}",
        )
        _require(
            "/.qualification/" not in f"/{path}/",
            f"release closeout commits scratch evidence: {path}",
        )
        if path.endswith((".tar.gz", ".tar.gz.sha256")):
            _require(
                path in RELEASE_PACKAGE_PATHS,
                f"release closeout commits a noncanonical package output: {path}",
            )
            package_paths.add(path)
    _require(
        package_paths == RELEASE_PACKAGE_PATHS
        if require_package
        else not package_paths or package_paths == RELEASE_PACKAGE_PATHS,
        "release closeout must commit the canonical package and sidecar together",
    )


def validate_committed_release_package(root: Path, release_head: str) -> str:
    package_raw = _git_blob_bytes(
        root, release_head, RELEASE_PACKAGE_PATH, "v0.6.0 release package"
    )
    sidecar_raw = _git_blob_bytes(
        root, release_head, RELEASE_PACKAGE_SIDECAR_PATH, "v0.6.0 package sidecar"
    )
    package_path = _regular_relative(
        root, RELEASE_PACKAGE_PATH, "v0.6.0 release package"
    )
    sidecar_path = _regular_relative(
        root, RELEASE_PACKAGE_SIDECAR_PATH, "v0.6.0 package sidecar"
    )
    _require(
        package_path.read_bytes() == package_raw,
        "v0.6.0 release package differs from the release commit",
    )
    _require(
        sidecar_path.read_bytes() == sidecar_raw,
        "v0.6.0 package sidecar differs from the release commit",
    )
    archive_sha = sha256_bytes(package_raw)
    try:
        sidecar = sidecar_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError("v0.6.0 package sidecar is not ASCII") from exc
    _require(
        sidecar == f"{archive_sha}  {package_path.name}\n",
        "v0.6.0 package sidecar differs",
    )
    return archive_sha


def validate_source_git(
    root: Path,
    source: Mapping[str, Any],
    *,
    require_package: bool = False,
) -> tuple[str, str]:
    _exact_keys(
        source,
        (
            "commit", "tree", "parent", "candidate_commit", "gate_0a_commit",
            "candidate_delta_paths",
            "source_fingerprint_sha256", "product_package_sha256",
        ),
        "qualified_source",
    )
    commit = _sha1(source.get("commit"), "qualified_source.commit")
    tree = _sha1(source.get("tree"), "qualified_source.tree")
    parent = _sha1(source.get("parent"), "qualified_source.parent")
    candidate_commit = candidate_source_commit(root)
    _require(
        source.get("candidate_commit") == candidate_commit,
        "qualified source candidate binding differs",
    )
    _require(
        source.get("gate_0a_commit") == GATE_0A_COMMIT,
        "qualified source Gate 0A binding differs",
    )
    _sha256(source.get("source_fingerprint_sha256"), "qualified source fingerprint")
    _sha256(source.get("product_package_sha256"), "qualified product package hash")
    _require(_git_line(root, ["rev-parse", f"{commit}^{{tree}}"], "qualified source tree") == tree, "qualified source Git tree differs")
    _require(
        _git_line(root, ["rev-parse", f"{commit}^"], "qualified source parent")
        == parent,
        "qualified source Git parent differs",
    )
    ancestry = _run_git(root, ["merge-base", "--is-ancestor", candidate_commit, commit], accepted=(0, 1))
    _require(ancestry.returncode == 0, "candidate is not an ancestor of qualified source")
    gate_ancestry = _run_git(
        root,
        ["merge-base", "--is-ancestor", GATE_0A_COMMIT, commit],
        accepted=(0, 1),
    )
    _require(gate_ancestry.returncode == 0, "Gate 0A is not an ancestor of qualified source")
    actual_delta = sorted(_git_name_list(root, ["diff", "--name-only", "-z", candidate_commit, commit], "candidate delta"))
    declared_delta = source.get("candidate_delta_paths")
    _require(isinstance(declared_delta, list) and all(isinstance(path, str) for path in declared_delta), "qualified source delta list is invalid")
    _require(declared_delta == sorted(declared_delta) and len(declared_delta) == len(set(declared_delta)), "qualified source delta list is not sorted and unique")
    for path in declared_delta:
        _safe_relative(path, "qualified source delta path")
        _require(_allowed_candidate_path(path), f"unauthorized candidate-to-qualified-source path: {path}")
    _require(actual_delta == declared_delta, "candidate-to-qualified-source delta differs")
    head = _git_line(root, ["rev-parse", "HEAD"], "release HEAD")
    head_ancestry = _run_git(root, ["merge-base", "--is-ancestor", commit, head], accepted=(0, 1))
    _require(head_ancestry.returncode == 0, "qualified source is not an ancestor of release HEAD")
    closeout = _git_name_list(
        root,
        ["diff", "--name-only", "-z", commit, head],
        "release evidence delta",
    )
    validate_release_closeout_paths(closeout, require_package=require_package)
    if require_package:
        validate_committed_release_package(root, head)
    status = _run_git(root, ["status", "--porcelain", "-z", "--untracked-files=all"]).stdout
    _require(status == b"", "final release validation requires a clean worktree")
    return commit, head


def validate_v05_unchanged(root: Path, inherited: Mapping[str, Any]) -> None:
    _exact_keys(
        inherited,
        (
            "classification", "supports", "direct_v06_proof", "accepted_tag_ref",
            "accepted_tag_object", "accepted_commit", "accepted_artifact_tree",
            "accepted_archive_path", "accepted_archive_sha256",
            "accepted_sidecar_path", "accepted_sidecar_sha256",
            "accepted_tag_archive_claim",
        ),
        "inherited_v05",
    )
    _require(inherited.get("classification") == "ACCEPTED_RELEASE_BASELINE_NOT_DIRECT_V06_PROOF", "v0.5 evidence classification differs")
    _require(inherited.get("supports") == ["release-lineage", "compatibility", "toolchain"], "v0.5 support scope differs")
    _require(inherited.get("direct_v06_proof") is False, "v0.5 evidence is misclassified as direct v0.6 proof")
    expected = {
        "accepted_tag_ref": V05_TAG_REF,
        "accepted_tag_object": V05_TAG_OBJECT,
        "accepted_commit": V05_COMMIT,
        "accepted_artifact_tree": V05_ARTIFACT_TREE,
        "accepted_archive_path": V05_ARCHIVE_RELATIVE,
        "accepted_archive_sha256": V05_ARCHIVE_SHA256,
        "accepted_sidecar_path": V05_SIDECAR_RELATIVE,
        "accepted_sidecar_sha256": V05_SIDECAR_SHA256,
        "accepted_tag_archive_claim": V05_TAG_ARCHIVE_CLAIM,
    }
    for key, value in expected.items():
        _require(inherited.get(key) == value, f"inherited_v05.{key} differs")
    try:
        validate_accepted_v05_release(root)
    except ValueError as exc:
        raise ReleaseEvidenceError(str(exc)) from exc
    _require(_git_line(root, ["show-ref", "--verify", "--hash", V05_TAG_REF], V05_TAG_REF) == V05_TAG_OBJECT, "v0.5.0 tag moved")
    _require(_git_line(root, ["rev-parse", "HEAD:artifacts/v0.5"], "HEAD v0.5 artifact tree") == V05_ARTIFACT_TREE, "accepted v0.5 artifacts changed in release HEAD")
    _require(_git_line(root, ["rev-parse", f"{V05_COMMIT}:artifacts/v0.5"], "tagged v0.5 artifact tree") == V05_ARTIFACT_TREE, "accepted v0.5 tag artifact tree differs")
    diff = _run_git(root, ["diff", "--quiet", V05_COMMIT, "--", "artifacts/v0.5"], accepted=(0, 1))
    _require(diff.returncode == 0, "accepted v0.5 artifacts have a working-tree change")
    status = _run_git(
        root,
        ["status", "--porcelain", "-z", "--untracked-files=all", "--", "artifacts/v0.5"],
    ).stdout
    _require(status == b"", "accepted v0.5 artifacts have an untracked change")


def canonical_evidence_files(root: Path, evidence_root: Path) -> dict[str, Path]:
    _require(
        evidence_root.is_dir()
        and not path_has_link_or_reparse_v06(root, evidence_root),
        "v0.6 evidence root is missing or unsafe",
    )
    files: dict[str, Path] = {}
    for path in evidence_root.rglob("*"):
        relative_evidence = path.relative_to(evidence_root)
        relative_root = path.relative_to(root).as_posix()
        if path_has_link_or_reparse_v06(root, path):
            raise ReleaseEvidenceError(
                f"v0.6 evidence contains a link or reparse point: {relative_root}"
            )
        if ".qualification" in relative_evidence.parts:
            continue
        if not path.is_file():
            continue
        if relative_evidence.as_posix() == MANIFEST_NAME:
            continue
        if path.name.startswith("."):
            raise ReleaseEvidenceError(f"v0.6 canonical evidence contains a temporary file: {relative_root}")
        if path.name.endswith((".tar.gz", ".tar.gz.sha256")):
            _require(
                relative_root in RELEASE_PACKAGE_PATHS,
                f"v0.6 evidence contains a noncanonical package output: {relative_root}",
            )
            continue
        _require(path.stat().st_size <= MAX_EVIDENCE_FILE_BYTES, f"v0.6 evidence file is oversized: {relative_root}")
        files[relative_root] = path
    _require(
        set(files) == CANONICAL_EVIDENCE_PATHS,
        "canonical v0.6 evidence file inventory differs",
    )
    return dict(sorted(files.items()))


def evidence_fingerprint_v06(files: Mapping[str, Path]) -> str:
    digest = hashlib.sha256()
    for relative, path in sorted(files.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _scan_secret_bytes(payload: bytes, label: str) -> None:
    lowered = payload.lower()
    for marker in SECRET_MARKERS:
        _require(
            marker not in lowered,
            f"canonical evidence contains forbidden secret material: {label}",
        )
    # Use the builder's source-of-truth patterns so evidence and package scans
    # cannot drift on high-confidence token formats.
    from scripts.build_reproducible_v06 import SECRET_PATTERNS

    for pattern in SECRET_PATTERNS:
        _require(
            pattern.search(payload) is None,
            f"canonical evidence contains forbidden secret material: {label}",
        )


def _structured_junit_scanner_input(
    relative: str,
    raw: bytes,
    *,
    expected_nodes: tuple[str, ...],
    capture_label: str,
) -> bytes:
    _require(
        0 < len(raw) <= MAX_XML_BYTES,
        f"canonical {capture_label} evidence has an invalid size: {relative}",
    )
    _require(
        raw.startswith(CANONICAL_XML_DECLARATION),
        f"canonical {capture_label} evidence must use the exact UTF-8 XML declaration: {relative}",
    )
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError(
            f"canonical {capture_label} evidence is not strict UTF-8: {relative}"
        ) from exc
    lowered = raw.lower()
    _require(
        b"<!doctype" not in lowered,
        f"canonical {capture_label} evidence contains a DTD: {relative}",
    )
    _require(
        b"<!entity" not in lowered,
        f"canonical {capture_label} evidence contains an entity declaration: {relative}",
    )
    xml_body = raw[len(CANONICAL_XML_DECLARATION) :]
    _require(
        b"<!--" not in xml_body,
        f"canonical {capture_label} evidence contains a comment: {relative}",
    )
    _require(
        b"<?" not in xml_body,
        f"canonical {capture_label} evidence contains a processing instruction: {relative}",
    )
    try:
        parser = ET.XMLParser(
            target=ET.TreeBuilder(insert_comments=True, insert_pis=True)
        )
        root = ET.fromstring(raw, parser=parser)
    except ET.ParseError as exc:
        raise ReleaseEvidenceError(
            f"canonical {capture_label} evidence is not valid XML: {relative}"
        ) from exc
    _require(
        root.tag in {"testsuite", "testsuites"},
        f"canonical {capture_label} evidence has an invalid root: {relative}",
    )
    parents = {
        id(child): parent
        for parent in root.iter()
        if isinstance(parent.tag, str)
        for child in list(parent)
    }
    counts = {node: 0 for node in expected_nodes}
    scanner_chunks = [CANONICAL_XML_DECLARATION]

    def scan(payload: bytes) -> None:
        _scan_secret_bytes(payload, relative)
        scanner_chunks.append(payload)

    for element in root.iter():
        if not isinstance(element.tag, str):
            if element.text:
                scan(element.text.encode("utf-8"))
            if element.tail:
                scan(element.tail.encode("utf-8"))
            continue
        permitted_name = False
        parent = parents.get(id(element))
        if (
            element.tag == "testcase"
            and parent is not None
            and parent.tag == "testsuite"
        ):
            node = _junit_node(
                element.get("classname"), element.get("name"), relative
            )
            if node in counts:
                counts[node] += 1
                permitted_name = True
        scan(element.tag.encode("utf-8"))
        for attribute, value in element.attrib.items():
            scan(attribute.encode("utf-8"))
            if not (permitted_name and attribute == "name"):
                scan(value.encode("utf-8"))
        if element.text:
            scan(element.text.encode("utf-8"))
        if element.tail:
            scan(element.tail.encode("utf-8"))
    _require(
        all(count == 1 for count in counts.values()),
        f"canonical {capture_label} secret-testcase inventory differs: {relative}",
    )
    return b"\0".join(scanner_chunks)


def _secret_scannable_evidence(relative: str, raw: bytes) -> bytes:
    if relative == WORK_PACKAGE_PATH:
        # The candidate validator parses this manifest and its exact tooling inventory.
        return b""
    if relative in TOOLING_CAPTURE_PATHS:
        return _structured_junit_scanner_input(
            relative,
            raw,
            expected_nodes=FINAL_TOOLING_SECRET_TESTCASE_NODES,
            capture_label="tooling",
        )
    if relative in BACKEND_SECRET_CAPTURE_PATHS:
        return _structured_junit_scanner_input(
            relative,
            raw,
            expected_nodes=BACKEND_SECRET_CANARY_NODES,
            capture_label="backend",
        )
    return raw


def validate_evidence_inventory(
    root: Path,
    evidence_root: Path,
    evidence: Mapping[str, Any],
) -> tuple[str, dict[str, Path]]:
    _exact_keys(evidence, ("files", "evidence_fingerprint_sha256"), "evidence")
    declared = _mapping(evidence.get("files"), "evidence.files")
    files = canonical_evidence_files(root, evidence_root)
    _require(set(declared) == set(files), "canonical v0.6 evidence file inventory differs")
    for relative, path in files.items():
        _safe_relative(relative, "canonical evidence path")
        digest = _sha256(declared.get(relative), f"evidence.files[{relative}]")
        raw = path.read_bytes()
        _require(sha256_bytes(raw) == digest, f"canonical evidence hash differs: {relative}")
        _scan_secret_bytes(_secret_scannable_evidence(relative, raw), relative)
    fingerprint = evidence_fingerprint_v06(files)
    _require(fingerprint == _sha256(evidence.get("evidence_fingerprint_sha256"), "evidence fingerprint"), "evidence fingerprint differs")
    return fingerprint, files


def validate_work_package(
    root: Path,
    work: Mapping[str, Any],
) -> str:
    _exact_keys(
        work,
        ("evidence_path", "evidence_sha256", "validator_path", "validator_sha256", "candidate_commit"),
        "work_package",
    )
    _require(work.get("evidence_path") == WORK_PACKAGE_PATH, "work-package evidence path differs")
    _require(work.get("validator_path") == WORK_PACKAGE_VALIDATOR, "work-package validator path differs")
    candidate_commit = candidate_source_commit(root)
    _require(work.get("candidate_commit") == candidate_commit, "work-package candidate differs")
    evidence_path = _regular_relative(root, WORK_PACKAGE_PATH, "work-package evidence")
    validator_path = _regular_relative(root, WORK_PACKAGE_VALIDATOR, "work-package validator")
    evidence_hash = sha256_bytes(evidence_path.read_bytes())
    _require(evidence_hash == _sha256(work.get("evidence_sha256"), "work-package evidence hash"), "work-package evidence hash differs")
    _require(sha256_bytes(validator_path.read_bytes()) == _sha256(work.get("validator_sha256"), "work-package validator hash"), "work-package validator hash differs")
    from scripts.validate_candidate_evidence_v06 import validate_candidate_evidence

    result = validate_candidate_evidence(root, root / "artifacts/v0.6/work-package")
    _require(result.source_commit == candidate_commit, "candidate validator returned a different commit")
    _require(result.suite_count == 10 and result.identity_count == 45, "candidate validator result cardinality differs")
    _require(result.evidence_sha256 == evidence_hash, "candidate validator evidence hash differs")
    return evidence_hash


def validate_gate_0b(root: Path, gate: Mapping[str, Any]) -> None:
    _exact_keys(
        gate,
        (
            "scope_path", "scope_sha256", "document_path", "document_sha256",
            "validator_path", "validator_sha256", "success_marker",
        ),
        "gate_0b",
    )
    expected_paths = {
        "scope_path": GATE_0B_SCOPE,
        "document_path": GATE_0B_DOCUMENT,
        "validator_path": GATE_0B_VALIDATOR,
    }
    for key, value in expected_paths.items():
        _require(gate.get(key) == value, f"gate_0b.{key} differs")
    for path_key, hash_key in (
        ("scope_path", "scope_sha256"),
        ("document_path", "document_sha256"),
        ("validator_path", "validator_sha256"),
    ):
        path = _regular_relative(root, str(gate[path_key]), f"Gate 0B {path_key}")
        _require(sha256_bytes(path.read_bytes()) == _sha256(gate.get(hash_key), f"gate_0b.{hash_key}"), f"Gate 0B {path_key} hash differs")
    _require(gate.get("success_marker") == GATE_0B_MARKER, "Gate 0B success marker differs")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    try:
        result = subprocess.run(
            [sys.executable, str(root / GATE_0B_VALIDATOR)],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseEvidenceError("Gate 0B validator could not run") from exc
    _require(result.returncode == 0, "Gate 0B validator did not pass")
    _require(result.stderr == b"", "Gate 0B validator wrote stderr on success")
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError("Gate 0B validator output is not strict UTF-8") from exc
    _require(lines == [GATE_0B_MARKER], "Gate 0B validator success output differs")


def validate_toolchain(root: Path, toolchain: Mapping[str, Any]) -> None:
    expected = {
        "python", "docker", "node", "npm", "playwright", "chromium",
        "files_sha256", "candidate_qualification_image_id",
        "final_qualification_image_id",
    }
    _exact_keys(toolchain, expected, "toolchain")
    candidate = _mapping(
        read_strict_json(root / WORK_PACKAGE_PATH, "candidate qualification"),
        "candidate qualification",
    )
    candidate_toolchain = _mapping(candidate.get("toolchain"), "candidate toolchain")
    _exact_keys(
        candidate_toolchain,
        {
            "python", "docker", "node", "npm", "playwright", "chromium",
            "files_sha256", "qualification_image_id",
        },
        "candidate toolchain",
    )
    for key in ("python", "docker", "node", "npm", "playwright", "chromium", "files_sha256"):
        _require(toolchain.get(key) == candidate_toolchain.get(key), f"toolchain immutable binding differs: {key}")
    _require(
        toolchain.get("candidate_qualification_image_id")
        == candidate_toolchain.get("qualification_image_id"),
        "candidate qualification image binding differs",
    )
    for key in ("candidate_qualification_image_id", "final_qualification_image_id"):
        value = toolchain.get(key)
        _require(
            isinstance(value, str) and IMAGE_ID_RE.fullmatch(value) is not None,
            f"toolchain {key} is invalid",
        )


def _validate_suite_manifest(
    suite_id: str,
    suite: Mapping[str, Any],
    root: Path,
    source_fingerprint: str,
) -> tuple[TestCaptureResult | None, int]:
    if suite_id == "frontend_build":
        return None, validate_frontend_build(root, suite, source_fingerprint)
    _exact_keys(
        suite,
        (
            "kind", "capture", "sha256", "test_count", "subtest_count", "passed_count",
            "skipped_count", "failure_count", "error_count", "allowed_skipped_nodes",
        ),
        f"final_suites.{suite_id}",
    )
    expected_kind = "vitest-json" if suite_id == "frontend_unit" else "junit"
    _require(suite.get("kind") == expected_kind, f"{suite_id} capture kind differs")
    extension = "json" if suite_id == "frontend_unit" else "xml"
    expected_path = f"artifacts/v0.6/final/tests/{suite_id.replace('_', '-')}.{extension}"
    relative = _safe_relative(suite.get("capture"), f"{suite_id} capture")
    _require(relative == expected_path, f"{suite_id} capture path differs")
    path = _regular_relative(root, relative, f"{suite_id} capture")
    _require(sha256_bytes(path.read_bytes()) == _sha256(suite.get("sha256"), f"{suite_id} capture hash"), f"{suite_id} capture hash differs")
    expected_subtests = FINAL_SUBTEST_COUNTS[suite_id]
    result = (
        parse_vitest(path, suite_id)
        if suite_id == "frontend_unit"
        else parse_junit(path, suite_id, expected_subtests=expected_subtests)
    )
    counts = {
        "test_count": len(result.nodes),
        "subtest_count": result.subtests,
        "passed_count": result.passed,
        "skipped_count": result.skipped,
        "failure_count": result.failures,
        "error_count": result.errors,
    }
    for key, actual in counts.items():
        _require(_integer(suite.get(key), f"final_suites.{suite_id}.{key}") == actual, f"{suite_id} {key} differs")
    _require(result.failures == 0 and result.errors == 0, f"{suite_id} contains a failure or error")
    allowed = suite.get("allowed_skipped_nodes")
    _require(isinstance(allowed, list) and all(isinstance(node, str) for node in allowed), f"{suite_id} allowed skip list is invalid")
    actual_skips = sorted(node for node, status in result.nodes.items() if status == "skipped")
    expected_skips = list(SQLITE_ALLOWED_SKIPS) if suite_id == "backend_sqlite" else []
    _require(allowed == expected_skips, f"{suite_id} declared skip allowlist differs")
    _require(actual_skips == sorted(expected_skips), f"{suite_id} actual skip set differs")
    if suite_id == "tooling":
        _require(
            all(node in result.nodes for node in TOOLING_SECRET_CANARY_NODES),
            "tooling secret-canary node inventory differs",
        )
    if suite_id in {"browser_mocked", "browser_real"}:
        _require(
            any(node.startswith("browser_chromium.") for node in result.nodes)
            and any(node.startswith("browser_mobile.") for node in result.nodes),
            f"{suite_id} does not prove both desktop and mobile projects",
        )
        required_fragment = (
            "operator-workspace.spec.ts::operates the dense v0.6 workspace"
            if suite_id == "browser_mocked"
            else "integration.spec.ts::controls a durable prompt workflow"
        )
        _require(
            any(required_fragment in node for node in result.nodes),
            f"{suite_id} lacks its accessibility/operator acceptance workflow",
        )
    if suite_id in ZERO_SKIP_SUITE_IDS:
        _require(result.skipped == 0, f"{suite_id} contains a skip")
    return result, len(result.nodes)


def validate_final_suites(
    root: Path,
    suites_value: Any,
    source_fingerprint: str,
) -> tuple[int, dict[str, TestCaptureResult]]:
    suites = _mapping(suites_value, "final_suites")
    _require(tuple(suites) == FINAL_SUITE_IDS, "final suite order or inventory differs")
    results: dict[str, TestCaptureResult] = {}
    test_count = 0
    for suite_id in FINAL_SUITE_IDS:
        result, count = _validate_suite_manifest(
            suite_id,
            _mapping(suites[suite_id], f"final_suites.{suite_id}"),
            root,
            source_fingerprint,
        )
        if result is not None:
            results[suite_id] = result
        test_count += count
    sqlite_nodes = set(results["backend_sqlite"].nodes)
    postgres_nodes = set(results["backend_postgresql"].nodes)
    docker_host_nodes = set(results["backend_docker_host"].nodes)
    _require(
        not (postgres_nodes & docker_host_nodes)
        and postgres_nodes | docker_host_nodes == sqlite_nodes,
        "PostgreSQL plus host-Docker backend inventories do not biject to SQLite",
    )
    _require(
        docker_host_nodes
        == {
            "backend/tests/test_driver_isolation.py::test_created_compose_driver_has_runtime_isolation_controls",
            "backend/tests/test_driver_isolation.py::test_backend_restart_reuses_same_epoch_with_no_worker_credential_access",
        },
        "host-Docker final backend inventory differs",
    )
    return test_count, results


def validate_final_qualification(
    root: Path,
    binding: Mapping[str, Any],
    *,
    qualified_source_commit: str,
    qualified_source_tree: str,
    source_fingerprint: str,
    product_package_sha256: str,
    work_package: Mapping[str, Any],
    gate_0b: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    final_suites: Mapping[str, Any],
) -> None:
    _exact_keys(binding, ("path", "sha256"), "final_qualification")
    _require(binding.get("path") == FINAL_QUALIFICATION_PATH, "final qualification path differs")
    path = _regular_relative(root, FINAL_QUALIFICATION_PATH, "final qualification summary")
    _require(
        sha256_bytes(path.read_bytes())
        == _sha256(binding.get("sha256"), "final qualification summary hash"),
        "final qualification summary hash differs",
    )
    summary = _mapping(
        read_strict_json(path, "final qualification summary"),
        "final qualification summary",
    )
    _exact_keys(
        summary,
        (
            "schema_version", "product_version", "scope_profile", "qualified_source",
            "source_fingerprint_sha256", "product_package_sha256", "work_package", "gate_0b",
            "toolchain", "suites", "teardown", "accepted_v05_release",
            "accepted_exceptions", "overall_pass",
        ),
        "final qualification summary",
    )
    _require(
        summary.get("schema_version") == "spell.v06.final-qualification/1",
        "final qualification summary schema differs",
    )
    _require(summary.get("product_version") == PRODUCT_VERSION, "final qualification product version differs")
    _require(summary.get("scope_profile") == SCOPE_PROFILE, "final qualification scope profile differs")
    _require(summary.get("overall_pass") is True, "final qualification summary did not pass")
    _require(summary.get("accepted_exceptions") == [], "final qualification summary contains an exception")
    _require(
        _mapping(summary.get("accepted_v05_release"), "final qualification accepted_v05_release")
        == V05_EXTERNAL_RELEASE_BINDING,
        "final qualification accepted v0.5 release binding differs",
    )
    _require(
        summary.get("qualified_source")
        == {"commit": qualified_source_commit, "tree": qualified_source_tree},
        "final qualification source binding differs",
    )
    _require(
        summary.get("source_fingerprint_sha256") == source_fingerprint,
        "final qualification source fingerprint differs",
    )
    _require(
        summary.get("product_package_sha256") == product_package_sha256,
        "final qualification product package fingerprint differs",
    )
    _require(summary.get("work_package") == work_package, "final qualification work-package binding differs")
    _require(summary.get("gate_0b") == gate_0b, "final qualification Gate 0B binding differs")
    _require(summary.get("toolchain") == toolchain, "final qualification toolchain binding differs")
    _require(summary.get("suites") == final_suites, "final qualification suite declarations differ")
    teardown = _mapping(summary.get("teardown"), "final qualification teardown")
    _exact_keys(
        teardown,
        (
            "qualification_resources_torn_down", "runtime_test_resources_torn_down",
            "temporary_evidence_removed", "secrets_retained",
        ),
        "final qualification teardown",
    )
    for key in (
        "qualification_resources_torn_down",
        "runtime_test_resources_torn_down",
        "temporary_evidence_removed",
    ):
        _require(teardown.get(key) is True, f"final qualification teardown.{key} must be true")
    _require(teardown.get("secrets_retained") is False, "final qualification teardown.secrets_retained must be false")


def _parse_sha256sums(path: Path, expected_names: set[str]) -> dict[str, str]:
    _require(
        path.is_file() and not is_link_or_reparse_v06(path),
        "SBOM SHA256SUMS is missing or unsafe",
    )
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError("SBOM SHA256SUMS is not ASCII") from exc
    manifest: dict[str, str] = {}
    for line in lines:
        digest, separator, name = line.partition("  ")
        _require(separator == "  " and SHA256_RE.fullmatch(digest) is not None and name not in manifest, "SBOM SHA256SUMS has an invalid entry")
        _safe_relative(name, "SBOM checksum name")
        _require("/" not in name, "SBOM checksum name must be a basename")
        manifest[name] = digest
    _require(set(manifest) == expected_names, "SBOM SHA256SUMS inventory differs")
    return manifest


def validate_sbom(
    root: Path,
    sbom: Mapping[str, Any],
    source_fingerprint: str,
) -> tuple[str, ...]:
    _exact_keys(
        sbom,
        ("directory", "checksum_manifest", "checksum_manifest_sha256", "inventories", "source_fingerprint_sha256"),
        "sbom",
    )
    _require(sbom.get("directory") == "artifacts/v0.6/sbom", "SBOM directory differs")
    _require(sbom.get("checksum_manifest") == "artifacts/v0.6/sbom/SHA256SUMS", "SBOM checksum path differs")
    _require(sbom.get("source_fingerprint_sha256") == source_fingerprint, "SBOM declared source fingerprint differs")
    directory = root / "artifacts/v0.6/sbom"
    _require(
        directory.is_dir() and not path_has_link_or_reparse_v06(root, directory),
        "SBOM directory is missing or unsafe",
    )
    discovered = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and not is_link_or_reparse_v06(path)
    }
    _require(discovered == {*SBOM_FILES, "SHA256SUMS"}, "SBOM directory inventory differs")
    checksum_path = directory / "SHA256SUMS"
    _require(sha256_bytes(checksum_path.read_bytes()) == _sha256(sbom.get("checksum_manifest_sha256"), "SBOM checksum manifest hash"), "SBOM checksum manifest hash differs")
    checksums = _parse_sha256sums(checksum_path, set(SBOM_FILES))
    declarations = _mapping(sbom.get("inventories"), "sbom.inventories")
    _require(tuple(declarations) == SBOM_FILES, "SBOM declared inventory order or set differs")
    image_ids: list[str] = []
    for name in SBOM_FILES:
        path = directory / name
        raw = path.read_bytes()
        _require(sha256_bytes(raw) == checksums[name], f"SBOM checksum differs: {name}")
        declaration = _mapping(declarations[name], f"sbom.inventories.{name}")
        _exact_keys(declaration, ("sha256", "subject", "image_id"), f"sbom.inventories.{name}")
        _require(declaration.get("sha256") == checksums[name], f"SBOM declaration hash differs: {name}")
        _require(declaration.get("subject") == SBOM_SUBJECTS[name], f"SBOM declaration subject differs: {name}")
        image_id = _string(declaration.get("image_id"), f"SBOM image ID {name}")
        _require(IMAGE_ID_RE.fullmatch(image_id) is not None, f"SBOM image ID is invalid: {name}")
        inventory = _mapping(parse_strict_json(raw, f"SBOM {name}"), f"SBOM {name}")
        _require(inventory.get("bomFormat") == "CycloneDX" and inventory.get("specVersion") in {"1.4", "1.5", "1.6"} and inventory.get("version") == 1, f"SBOM header differs: {name}")
        components = inventory.get("components")
        _require(isinstance(components, list) and bool(components), f"SBOM is empty: {name}")
        component_names = {
            str(component.get("name")).casefold()
            for component in components
            if isinstance(component, dict) and isinstance(component.get("name"), str)
        }
        _require(SBOM_REQUIRED_COMPONENTS[name] <= component_names, f"SBOM required components are missing: {name}")
        for required in SBOM_REQUIRED_COMPONENTS[name]:
            matches = [component for component in components if isinstance(component, dict) and str(component.get("name", "")).casefold() == required]
            _require(len(matches) == 1 and isinstance(matches[0].get("licenses"), list) and bool(matches[0]["licenses"]), f"SBOM component license is missing or ambiguous: {name}: {required}")
        metadata = _mapping(inventory.get("metadata"), f"SBOM {name}.metadata")
        subject = _mapping(metadata.get("component"), f"SBOM {name}.metadata.component")
        _require(subject.get("type") == "container" and subject.get("name") == SBOM_SUBJECTS[name] and subject.get("version") == image_id, f"SBOM subject differs: {name}")
        properties = metadata.get("properties")
        _require(isinstance(properties, list), f"SBOM source binding is missing: {name}")
        sources = [item.get("value") for item in properties if isinstance(item, dict) and item.get("name") == SBOM_SOURCE_PROPERTY]
        images = [item.get("value") for item in properties if isinstance(item, dict) and item.get("name") == SBOM_IMAGE_PROPERTY]
        _require(sources == [source_fingerprint] and images == [image_id], f"SBOM source/image binding differs: {name}")
        image_ids.append(image_id)
    _require(len(set(image_ids)) == 4, "SBOM image identities are not distinct")
    return tuple(image_ids)


def validate_supply_chain(
    root: Path,
    supply: Mapping[str, Any],
    source_fingerprint: str,
) -> None:
    _exact_keys(
        supply,
        (
            "capture", "sha256", "test_id", "passed", "source_fingerprint_sha256",
            "critical_finding_count", "high_finding_count", "unlocked_input_count",
            "accepted_v05_artifacts_unchanged", "accepted_v05_release",
        ),
        "supply_chain",
    )
    expected_path = "artifacts/v0.6/supply-chain.json"
    _require(supply.get("capture") == expected_path, "supply-chain capture path differs")
    _require(supply.get("test_id") == "V06-SC-001" and supply.get("passed") is True, "supply-chain result did not pass")
    _require(supply.get("source_fingerprint_sha256") == source_fingerprint, "supply-chain source fingerprint differs")
    for key in ("critical_finding_count", "high_finding_count", "unlocked_input_count"):
        _require(_integer(supply.get(key), f"supply_chain.{key}") == 0, f"supply_chain.{key} must be zero")
    _require(supply.get("accepted_v05_artifacts_unchanged") is True, "supply-chain audit did not preserve v0.5 artifacts")
    _require(
        _mapping(supply.get("accepted_v05_release"), "supply_chain.accepted_v05_release")
        == V05_EXTERNAL_RELEASE_BINDING,
        "supply-chain accepted v0.5 release binding differs",
    )
    path = _regular_relative(root, expected_path, "supply-chain capture")
    _require(sha256_bytes(path.read_bytes()) == _sha256(supply.get("sha256"), "supply-chain capture hash"), "supply-chain capture hash differs")
    capture = _mapping(read_strict_json(path, "supply-chain capture"), "supply-chain capture")
    _exact_keys(
        capture,
        (
            "schema_version", "product_version", "scope_profile", "test_id", "passed",
            "source_fingerprint_sha256", "inherited_audit_engine", "assertions", "metrics",
            "accepted_v05_artifacts_unchanged", "accepted_v05_release",
        ),
        "supply-chain capture",
    )
    _require(capture.get("schema_version") == "spell.v06.supply-chain/1", "supply-chain schema differs")
    _require(capture.get("product_version") == PRODUCT_VERSION and capture.get("scope_profile") == SCOPE_PROFILE, "supply-chain product/scope differs")
    _require(capture.get("test_id") == "V06-SC-001" and capture.get("passed") is True, "supply-chain capture did not pass")
    _require(capture.get("source_fingerprint_sha256") == source_fingerprint, "supply-chain capture source differs")
    _require(capture.get("accepted_v05_artifacts_unchanged") is True, "supply-chain capture changed v0.5 artifacts")
    _require(
        _mapping(capture.get("accepted_v05_release"), "supply-chain capture accepted_v05_release")
        == V05_EXTERNAL_RELEASE_BINDING
        and capture.get("accepted_v05_release") == supply.get("accepted_v05_release"),
        "supply-chain capture accepted v0.5 release binding differs",
    )
    assertions = capture.get("assertions")
    _require(isinstance(assertions, list) and bool(assertions), "supply-chain assertions are missing")
    _require(all(isinstance(item, dict) and item.get("passed") is True for item in assertions), "supply-chain capture contains a failed assertion")
    metrics = _mapping(capture.get("metrics"), "supply-chain metrics")
    for key in ("critical_finding_count", "high_finding_count", "unlocked_input_count"):
        value = _integer(metrics.get(key), f"supply-chain metrics.{key}")
        _require(value == 0 and supply.get(key) == value, f"supply-chain {key} differs or is nonzero")
    _require(_integer(metrics.get("audited_image_count"), "supply-chain audited_image_count") == 4, "supply-chain did not audit four product images")
    _require(_integer(metrics.get("compose_dependency_audited_image_count"), "supply-chain dependency image count") == 2, "supply-chain did not audit two dependency images")


def validate_teardown(teardown: Mapping[str, Any]) -> None:
    _exact_keys(
        teardown,
        (
            "qualification_resources_torn_down", "runtime_test_resources_torn_down",
            "supply_chain_resources_torn_down", "sbom_resources_torn_down",
            "temporary_evidence_removed", "secrets_retained",
        ),
        "teardown",
    )
    for key in (
        "qualification_resources_torn_down", "runtime_test_resources_torn_down",
        "supply_chain_resources_torn_down", "sbom_resources_torn_down",
        "temporary_evidence_removed",
    ):
        _require(teardown.get(key) is True, f"teardown.{key} must be true")
    _require(teardown.get("secrets_retained") is False, "teardown.secrets_retained must be false")


def validate_tag_policy(policy: Mapping[str, Any]) -> None:
    _exact_keys(
        policy,
        (
            "tag_name", "tag_ref", "object_type", "target_policy", "package_path",
            "sidecar_path", "required_static_markers", "required_dynamic_fields",
        ),
        "tag_policy",
    )
    expected = {
        "tag_name": RELEASE_TAG,
        "tag_ref": RELEASE_TAG_REF,
        "object_type": "tag",
        "target_policy": "CURRENT_RELEASE_HEAD",
        "package_path": RELEASE_PACKAGE_PATH,
        "sidecar_path": RELEASE_PACKAGE_SIDECAR_PATH,
        "required_static_markers": [
            "Owner: JC Arcaz",
            "Decision: ACCEPTED",
            "Gate 0B: PASS",
            "Accepted exceptions: None",
            "Operational authorization: None",
            "Compliance determination: None",
            "Cryptographic signature: Not claimed",
        ],
        "required_dynamic_fields": list(RELEASE_TAG_DYNAMIC_FIELDS),
    }
    _require(dict(policy) == expected, "release tag policy differs")


def create_release_tag_message_v06(
    policy: Mapping[str, Any],
    *,
    release_head: str,
    qualified_source: str,
    candidate_commit: str,
    source_fingerprint: str,
    evidence_fingerprint: str,
    product_package_sha256: str,
    work_package_sha256: str,
    final_archive_sha256: str,
) -> str:
    validate_tag_policy(policy)
    values = {
        "Release commit": _sha1(release_head, "tag-message release commit"),
        "Qualified source commit": _sha1(
            qualified_source, "tag-message qualified source"
        ),
        "Candidate implementation commit": _sha1(
            candidate_commit, "tag-message candidate implementation commit"
        ),
        "Source fingerprint": _sha256(
            source_fingerprint, "tag-message source fingerprint"
        ),
        "Evidence fingerprint": _sha256(
            evidence_fingerprint, "tag-message evidence fingerprint"
        ),
        "Product package SHA-256": _sha256(
            product_package_sha256, "tag-message product package hash"
        ),
        "Work-package evidence SHA-256": _sha256(
            work_package_sha256, "tag-message work-package evidence hash"
        ),
        "Final archive SHA-256": _sha256(
            final_archive_sha256, "tag-message final archive hash"
        ),
    }
    markers = [
        *policy["required_static_markers"],
        *(
            f"{field}: {values[field]}"
            for field in policy["required_dynamic_fields"]
        ),
    ]
    _require(len(markers) == 15, "release tag marker cardinality differs")
    return RELEASE_TAG_TITLE + "\n\n" + "\n".join(markers) + "\n"


def validate_release_tag_message_v06(raw: bytes, expected: str) -> None:
    try:
        message = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError("v0.6.0 tag message is not strict UTF-8") from exc
    _require(
        message == expected,
        "v0.6.0 tag message differs from the exact ordered release record",
    )


def _release_tag_message_from_object(raw: bytes, release_head: str) -> bytes:
    headers, separator, message = raw.partition(b"\n\n")
    _require(bool(separator), "v0.6.0 tag lacks a message boundary")
    lowered = raw.lower()
    _require(
        not any(marker in lowered for marker in TAG_SIGNATURE_MARKERS),
        "v0.6.0 tag carries an unclaimed cryptographic signature",
    )
    header_lines = headers.split(b"\n")
    _require(
        not any(TAG_SIGNATURE_HEADER_RE.match(line) for line in header_lines),
        "v0.6.0 tag carries an unclaimed cryptographic signature",
    )
    _require(
        len(header_lines) == 4
        and header_lines[:3]
        == [
            f"object {release_head}".encode("ascii"),
            b"type commit",
            b"tag v0.6.0",
        ]
        and TAGGER_HEADER_RE.fullmatch(header_lines[3]) is not None,
        "v0.6.0 tag headers differ",
    )
    try:
        header_lines[3].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseEvidenceError("v0.6.0 tagger header is not UTF-8") from exc
    return message


def validate_release_tag(
    root: Path,
    policy: Mapping[str, Any],
    *,
    release_head: str,
    qualified_source: str,
    candidate_commit: str,
    source_fingerprint: str,
    evidence_fingerprint: str,
    product_package_sha256: str,
    work_package_sha256: str,
) -> tuple[str, str]:
    validate_tag_policy(policy)
    alias = _run_git(
        root,
        ["show-ref", "--verify", "--hash", FORBIDDEN_ALIAS_REF],
        accepted=(0, 1, 128),
    )
    _require(
        alias.returncode != 0 and alias.stdout == b"",
        "forbidden lightweight or secondary v0.6 tag exists",
    )
    object_id = _git_line(root, ["show-ref", "--verify", "--hash", RELEASE_TAG_REF], RELEASE_TAG_REF)
    _require(_git_line(root, ["cat-file", "-t", object_id], "v0.6.0 tag type") == "tag", "v0.6.0 is not annotated")
    raw = _run_git(root, ["cat-file", "tag", object_id]).stdout
    message = _release_tag_message_from_object(raw, release_head)
    archive_sha = validate_committed_release_package(root, release_head)
    expected_message = create_release_tag_message_v06(
        policy,
        release_head=release_head,
        qualified_source=qualified_source,
        candidate_commit=candidate_commit,
        source_fingerprint=source_fingerprint,
        evidence_fingerprint=evidence_fingerprint,
        product_package_sha256=product_package_sha256,
        work_package_sha256=work_package_sha256,
        final_archive_sha256=archive_sha,
    )
    validate_release_tag_message_v06(message, expected_message)
    tagged = _git_line(root, ["rev-parse", f"{RELEASE_TAG_REF}^{{commit}}"], "v0.6.0 tagged commit")
    _require(tagged == release_head, "v0.6.0 tag does not target release HEAD")
    return object_id, tagged


def validate_release_manifest_shape(manifest: Mapping[str, Any]) -> None:
    _exact_keys(
        manifest,
        (
            "schema_version", "product_version", "scope_profile", "decision", "qualified_source",
            "work_package", "gate_0b", "toolchain", "final_qualification", "final_suites", "inherited_v05",
            "sbom", "supply_chain", "evidence", "teardown", "tag_policy", "overall_pass",
        ),
        "release manifest",
    )
    _require(manifest.get("schema_version") == SCHEMA_VERSION, "release evidence schema differs")
    _require(manifest.get("product_version") == PRODUCT_VERSION, "release product version differs")
    _require(manifest.get("scope_profile") == SCOPE_PROFILE, "release scope profile differs")
    _require(manifest.get("overall_pass") is True, "release qualification did not pass")
    decision = _mapping(manifest.get("decision"), "decision")
    _exact_keys(
        decision,
        (
            "owner", "release_status", "accepted_exceptions", "operational_authorization",
            "compliance_determination", "cryptographic_signature_claimed",
        ),
        "decision",
    )
    _require(decision.get("owner") == "JC Arcaz", "release decision owner differs")
    _require(decision.get("release_status") == "READY_FOR_ANNOTATED_TAG", "release decision status differs")
    _require(decision.get("accepted_exceptions") == [], "release contains an accepted exception")
    for key in ("operational_authorization", "compliance_determination", "cryptographic_signature_claimed"):
        _require(decision.get(key) is False, f"release decision {key} must be false")


def validate_release_evidence(
    root: Path,
    evidence_root: Path | None = None,
    *,
    require_tag: bool = False,
    require_package: bool = True,
) -> ReleaseEvidenceValidationV06:
    source_root = root.resolve()
    canonical_root = (evidence_root or (source_root / "artifacts/v0.6")).resolve()
    _require(canonical_root == (source_root / "artifacts/v0.6").resolve(), "release evidence root must be canonical artifacts/v0.6")
    manifest_path = canonical_root / MANIFEST_NAME
    manifest = _mapping(read_strict_json(manifest_path, "release qualification manifest"), "release qualification manifest")
    validate_release_manifest_shape(manifest)
    validate_version_metadata(source_root)

    qualified_source, release_head = validate_source_git(
        source_root,
        _mapping(manifest["qualified_source"], "qualified_source"),
        require_package=require_package or require_tag,
    )
    from scripts.source_fingerprint_v06 import source_fingerprint_v06
    from scripts.build_reproducible_v06 import product_package_sha256_v06

    source_fingerprint = source_fingerprint_v06(source_root)
    declared_source = manifest["qualified_source"]["source_fingerprint_sha256"]
    _require(source_fingerprint == declared_source, "current v0.6 source fingerprint differs")
    product_package = product_package_sha256_v06(source_root)
    _require(product_package == manifest["qualified_source"]["product_package_sha256"], "current product package fingerprint differs")

    validate_toolchain(source_root, _mapping(manifest["toolchain"], "toolchain"))
    work_package_sha = validate_work_package(source_root, _mapping(manifest["work_package"], "work_package"))
    validate_gate_0b(source_root, _mapping(manifest["gate_0b"], "gate_0b"))
    validate_v05_unchanged(source_root, _mapping(manifest["inherited_v05"], "inherited_v05"))
    suites = _mapping(manifest["final_suites"], "final_suites")
    validate_final_qualification(
        source_root,
        _mapping(manifest["final_qualification"], "final_qualification"),
        qualified_source_commit=qualified_source,
        qualified_source_tree=manifest["qualified_source"]["tree"],
        source_fingerprint=source_fingerprint,
        product_package_sha256=product_package,
        work_package=_mapping(manifest["work_package"], "work_package"),
        gate_0b=_mapping(manifest["gate_0b"], "gate_0b"),
        toolchain=_mapping(manifest["toolchain"], "toolchain"),
        final_suites=suites,
    )
    test_count, suite_results = validate_final_suites(
        source_root, suites, source_fingerprint
    )
    subtest_count = sum(result.subtests for result in suite_results.values())
    sbom_ids = validate_sbom(source_root, _mapping(manifest["sbom"], "sbom"), source_fingerprint)
    validate_supply_chain(source_root, _mapping(manifest["supply_chain"], "supply_chain"), source_fingerprint)
    evidence_fingerprint, _ = validate_evidence_inventory(
        source_root, canonical_root, _mapping(manifest["evidence"], "evidence")
    )
    validate_teardown(_mapping(manifest["teardown"], "teardown"))
    policy = _mapping(manifest["tag_policy"], "tag_policy")
    validate_tag_policy(policy)
    tag_object = tagged_commit = None
    if require_tag:
        tag_object, tagged_commit = validate_release_tag(
            source_root,
            policy,
            release_head=release_head,
            qualified_source=qualified_source,
            candidate_commit=str(manifest["qualified_source"]["candidate_commit"]),
            source_fingerprint=source_fingerprint,
            evidence_fingerprint=evidence_fingerprint,
            product_package_sha256=product_package,
            work_package_sha256=work_package_sha,
        )
    return ReleaseEvidenceValidationV06(
        source_fingerprint_sha256=source_fingerprint,
        evidence_fingerprint_sha256=evidence_fingerprint,
        product_package_sha256=product_package,
        qualified_source_commit=qualified_source,
        release_head_commit=release_head,
        validated_suite_ids=FINAL_SUITE_IDS,
        validated_test_count=test_count,
        validated_subtest_count=subtest_count,
        sbom_image_ids=sbom_ids,
        work_package_evidence_sha256=work_package_sha,
        tag_object_id=tag_object,
        tagged_commit=tagged_commit,
    )


def validate_release_evidence_v06(
    root: Path,
    evidence_root: Path | None = None,
    *,
    require_tag: bool = False,
    require_package: bool = True,
) -> ReleaseEvidenceValidationV06:
    """Backward-compatible versioned entry point used by the package builder."""

    return validate_release_evidence(
        root,
        evidence_root,
        require_tag=require_tag,
        require_package=require_package,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--require-tag", action="store_true")
    args = parser.parse_args(argv)
    result = validate_release_evidence(
        args.root,
        args.evidence_root,
        require_tag=args.require_tag,
    )
    print(
        json.dumps(
            {
                "gate": "PASS",
                "product_version": PRODUCT_VERSION,
                "qualified_source_commit": result.qualified_source_commit,
                "release_head_commit": result.release_head_commit,
                "source_fingerprint_sha256": result.source_fingerprint_sha256,
                "evidence_fingerprint_sha256": result.evidence_fingerprint_sha256,
                "product_package_sha256": result.product_package_sha256,
                "validated_suite_count": len(result.validated_suite_ids),
                "validated_test_count": result.validated_test_count,
                "validated_subtest_count": result.validated_subtest_count,
                "validated_sbom_image_count": len(result.sbom_image_ids),
                "tag_object_id": result.tag_object_id,
                "tagged_commit": result.tagged_commit,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
