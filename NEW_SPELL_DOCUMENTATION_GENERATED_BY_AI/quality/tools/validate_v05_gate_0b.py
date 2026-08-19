#!/usr/bin/env python3
"""Validate SPELL v0.5 Gate 0B and its immutable qualification inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


DOC_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = DOC_ROOT.parent
SCOPE_PATH = (
    DOC_ROOT
    / "requirements"
    / "compatibility"
    / "scopes"
    / "v0.5-gate-0b.json"
)
GATE_DOCUMENT_PATH = WORKSPACE_ROOT / "SPELL_v0.5_Gate_0B.md"
EVIDENCE_PATH = WORKSPACE_ROOT / "artifacts/v0.5/work-package/qualification.json"
EVIDENCE_VALIDATOR_PATH = WORKSPACE_ROOT / "scripts/validate_candidate_evidence_v05.py"

SCOPE_SHA256 = "f98d50498ef8caf7304ad2e027f0eb8f03c02b486d8ec871f6ca95cc28987248"
EVIDENCE_SHA256 = "86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9"
BASELINE_TAG_REF = "refs/tags/v0.4.0"
BASELINE_TAG_OBJECT = "86390c90e8d5f96f872be43274cbc9d789a34c2d"
BASELINE_TAG_SHA256 = "ae7030aa54ad9c69761ae764c4edd2535b47ae842a2f4f5b4c20aad859fca663"
BASELINE_COMMIT = "4546d313a2d8f50504b2bc602d56b3b459ca7597"
GATE_0A_COMMIT = "d13397f51241c6bac10289ea21b69aafff66b1fb"
GATE_0A_TREE = "0aa6bcf78e0f42d39f8fae795bcc5a2ba34cb3c9"
CANDIDATE_COMMIT = "aefa658ce01d49a7879d0471b50425ac3bcf9e2d"
CANDIDATE_TREE = "958c43e867228b536fd21c0da59d5530e9fe155b"
QUALIFICATION_COMMIT = "ef26e53f5ecccabef1fff03ec86d71b0c93edd2b"
QUALIFICATION_PARENT = "05a1c89c21b500270476b172d86d0758945d23d7"
QUALIFICATION_TREE = "f646a40bcd70ec9ebc28f3ebf3783e54c1c8f9a1"
QUALIFICATION_CORRECTION = {
    "path": "backend/tests/test_driver_isolation.py",
    "status": "M",
    "blob": "60ed5164ffe190ccbb5cee91ffe619eba7c8c9c2",
    "sha256": "d0eca2c56705068027b910991719971838d5f84033806f9a0ff9de0f7b3e0756",
}

IDENTITY_IDS = [
    "V05-IR-001-UNIT",
    "V05-IR-001-PARSER",
    "V05-IR-001-SUPERVISOR",
    "V05-IR-001-WORKER",
    "V05-IR-001-COMPAT",
    "V05-IR-001-ADVERSARIAL",
]

BASELINE_FILES = {
    "SPELL_v0.4_Release.md": (
        "6c3288a3a83d679e82713f09613a640117817fc9cbd05fdf4853a5db64202aa8"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "COMPATIBILITY_LEDGER.json"
    ): "f1d4e20383c81a1109e93b39e2aac04f04b2366e91eae613170488a6acf8458f",
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.4.json"
    ): "2de37c751c084fad96d1bf1c3842deab57bb697920d0cc0bc15b206a46aee1f5",
}

GATE_0A_FILES = {
    "SPELL_v0.5_Pre-Implementation.md": {
        "blob": "24e765d0e6507efb8e6c48ce5493d5f951cbf1a8",
        "sha256": "6a66c9cdafa98bf4647149a24f200cac992346f69222e0c7bae54e7e1e3b7630",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.5-gate-0a.json"
    ): {
        "blob": "94ee01dba224450982a1354df26f1b1c5087fd9d",
        "sha256": "ce7bcb626d22f6e7ff03a3b019d3e388afc71b666d4bbc1178290e486f7b15a7",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v05_gate_0a.py"
    ): {
        "blob": "12a50c5a8bb94a95ce9a0e69edfe3e84c0e8d7a2",
        "sha256": "b814a8d61a80c107c94f2c7ed61188073c997dbf1d1a723a45a0f0be79773d40",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v05_gate_0a.py"
    ): {
        "blob": "3e816e899d5867ca1c90bd1795572e66b268f0d5",
        "sha256": "c9dca6428fa9655198e1ffc99b3f8aab178ef4e3d3cbe71b7abfe285d9c20860",
    },
}

CANDIDATE_PATHS = [
    {
        "path": "backend/ir_v03.py",
        "status": "A",
        "blob": "87f202e9e3ff192e348c2aea9f7009ea7fc95841",
        "sha256": "2726774ed5873e0c0c1eeaffa7b3713c708ac7f61a6fa93e544a8dbc8c79963c",
    },
    {
        "path": "backend/procedure_parser.py",
        "status": "M",
        "blob": "cf6fdf5645d3818e8b7b2c7abdca796d4d1c506b",
        "sha256": "69df9a20e068368a5e9d48c95d157c2fb6740352a53683ed52cf1cad681719be",
    },
    {
        "path": "backend/supervisor.py",
        "status": "M",
        "blob": "6b903d97c7777cd163b776fe5c0a2bebc1c2721c",
        "sha256": "5e731f1a64170b0e891f91511c3cab3cb68614a5f8b92d557b33bd623fde9b04",
    },
    {
        "path": "backend/tests/test_driver_isolation.py",
        "status": "M",
        "blob": "d829838cbd1b0186adb7a075e9c9edfb661c321c",
        "sha256": "4e59af01b1e34f003e4b813356495d9928ac3a0160b401ed144a352afca4b5de",
    },
    {
        "path": "backend/tests/test_ir_boundaries.py",
        "status": "A",
        "blob": "750b3640615e6aa19d3d40914f966cccb63e59d8",
        "sha256": "6067392eea3b8fbd7038042c7b082ad16afdff98b5546128356ae60c912a57f0",
    },
    {
        "path": "backend/tests/test_ir_v03.py",
        "status": "A",
        "blob": "e142c9b67dadbad71d62207542a7c395f896f9c6",
        "sha256": "5ba90700aa243707da70e42a1fec091b4da19a83417c68e424963cbb11aa41af",
    },
    {
        "path": "backend/tests/test_procedure_parser.py",
        "status": "M",
        "blob": "a9f3c22d2362e83d810b4476d2435407ca2a01ab",
        "sha256": "38f5c536f5665b216c4ccbc88fd4ae941ce945c93eea64acac18df38cbdc6d4f",
    },
    {
        "path": "backend/tests/test_worker_expressions.py",
        "status": "M",
        "blob": "fe97a2f57e7ec85093b893526030afbfeff59fb3",
        "sha256": "43a8b44044ad99862f1df1d4fe920fc1d8a12c62ca65d021008b33b14727195d",
    },
    {
        "path": "backend/worker.py",
        "status": "M",
        "blob": "513fb00afea31b948e6cdcfed3c2911c2eff42e5",
        "sha256": "f7ccbcb149df6a551ffd6106e97cc381cf0fbb0ff995dd3c5ce5dd528375fcf5",
    },
]

EXPECTED_SCOPE: dict[str, Any] = {
    "schema_version": "ng-spell-v05-gate-0b-scope/1",
    "gate_id": "V05-GATE-0B",
    "status": "PASS",
    "target_increment": "v0.5",
    "target_release": "v0.5.0",
    "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    "decision": {
        "owner": "JC Arcaz",
        "decision_date": "2026-08-13",
        "authorization": "V05_IR_001_RELEASE_CLOSEOUT_ONLY",
        "owner_request": (
            "execute 1, 2, 3, 4, 5. when done finish up and tag v0.5."
        ),
        "tag_resolution": (
            "REQUESTED_V0_5_RESOLVES_TO_ANNOTATED_SEMVER_TAG_V0_5_0"
        ),
        "precondition": "V05_IR_001_CANDIDATE_QUALIFICATION_PASS",
    },
    "immutable_inputs": {
        "accepted_v0_4_0": {
            "tag_ref": BASELINE_TAG_REF,
            "tag_object_type": "tag",
            "tag_object_id": BASELINE_TAG_OBJECT,
            "raw_tag_object_sha256": BASELINE_TAG_SHA256,
            "peeled_commit": BASELINE_COMMIT,
            "tagged_files_sha256": BASELINE_FILES,
        },
        "gate_0a": {
            "commit": GATE_0A_COMMIT,
            "parent": BASELINE_COMMIT,
            "tree": GATE_0A_TREE,
            "files": GATE_0A_FILES,
        },
        "candidate": {
            "commit": CANDIDATE_COMMIT,
            "parent": GATE_0A_COMMIT,
            "tree": CANDIDATE_TREE,
            "changed_paths": CANDIDATE_PATHS,
        },
        "qualification_source": {
            "commit": QUALIFICATION_COMMIT,
            "parent": QUALIFICATION_PARENT,
            "tree": QUALIFICATION_TREE,
            "classification": "TEST_COMPATIBILITY_CORRECTION_ONLY",
            "correction": QUALIFICATION_CORRECTION,
            "product_behavior_changed": False,
            "implementation_identity_changed": False,
            "scope_expanded": False,
        },
    },
    "qualified_work_package": {
        "work_package_id": "V05-IR-001",
        "title": "Existing v0.3 IR fail-closed validation hardening",
        "status": "IMPLEMENTED",
        "accepted_ir_version": "0.3",
        "release_disposition": "QUALIFIED_FOR_RELEASE_CLOSEOUT",
        "identity_results": IDENTITY_IDS,
        "qualification_contract": {
            "manifest_path": "artifacts/v0.5/work-package/qualification.json",
            "manifest_schema": "spell.v05.candidate-qualification/1",
            "manifest_sha256": EVIDENCE_SHA256,
            "validator_path": "scripts/validate_candidate_evidence_v05.py",
            "python_version": "3.13.14",
            "suite_ids": [
                "backend_sqlite",
                "backend_postgresql",
                "driver_host",
                "tooling",
            ],
            "postgresql_environment_variables": [
                "SPELL_TEST_DATABASE_URL",
                "SPELL_MIGRATION_TEST_DATABASE_URL",
            ],
            "postgresql_zero_skips": True,
            "identity_environments": ["sqlite", "postgresql"],
            "waivers_allowed": False,
        },
        "compatibility_delta": {
            "accepted_ir_versions": ["0.3"],
            "new_ir_versions": [],
            "claimed_construct_ids": [],
            "claimed_artifact_ids": [],
            "compatibility_ledger_rows_added": 0,
            "v0_4_scope_rows_changed": 0,
        },
    },
    "release_closeout_authorization": {
        "status": "AUTHORIZED",
        "release_version": "0.5.0",
        "tag_name": "v0.5.0",
        "tag_object_type": "annotated",
        "permitted_actions": [
            "RECORD_V05_IR_001_IMPLEMENTED",
            "PUBLISH_CANONICAL_QUALIFICATION_EVIDENCE_AND_HASHES",
            "UPDATE_RELEASE_VERSION_PROVENANCE_HISTORY_AND_TEST_RECORDS",
            "SET_PRODUCT_VERSION_METADATA_TO_0_5_0",
            "CREATE_DETERMINISTIC_RELEASE_PACKAGE_AND_SUPPLY_CHAIN_EVIDENCE",
            "COMMIT_RELEASE_CLOSEOUT",
            "CREATE_ANNOTATED_V0_5_0_TAG",
        ],
        "additional_product_work_authorized": False,
    },
    "claims": {
        "v0_4_release_accepted": True,
        "gate_0a_immutable_authorization_verified": True,
        "v05_ir_001_implemented": True,
        "release_closeout_authorized": True,
        "v0_5_release_accepted_by_gate": False,
        "new_language_surface_claimed": False,
        "new_public_contract_claimed": False,
        "operational_authorization": False,
        "deployment_approval": False,
        "compliance_determination": False,
        "cryptographic_signature_verified": False,
    },
    "explicit_exclusions": [
        "V0_5_SCOPE_BEYOND_V05_IR_001",
        "SECOND_PRODUCT_WORK_PACKAGE",
        "NEW_LANGUAGE_CONSTRUCTS_OR_COMPATIBILITY_ARTIFACTS",
        "IR_VERSION_CHANGE_OR_MIGRATION",
        "PERSISTED_IR_REWRITE",
        "UNRESTRICTED_PYTHON_OR_SOURCE_EXECUTION",
        "PUBLIC_API_DATABASE_SCHEMA_FRONTEND_DEPENDENCY_OR_DRIVER_CONTRACT_CHANGE",
        "DRIVER_GCS_SPACECRAFT_OR_EXTERNAL_EFFECT_ROUTING",
        "LIGHTWEIGHT_OR_SECONDARY_V0_5_TAG",
        "DEPLOYMENT_OPERATIONAL_COMPLIANCE_OR_SIGNATURE_CLAIM",
    ],
}

REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
)
DOCUMENT_MARKERS = (
    "Owner request: `execute 1, 2, 3, 4, 5. when done finish up and tag v0.5.`",
    "Release closeout authorization: `V05_IR_001_RELEASE_CLOSEOUT_ONLY`",
    "Broader v0.5 product work authorized: No",
    "Release acceptance by Gate 0B: No",
    "| Work-package evidence SHA-256 | `86fd7847829b91ea0c2e2328eb9385bae51be8510b3b299e2ff58e49c998c9e9` |",
    (
        "gate=PASS work_packages=1 identities=6 failed=0 skipped=0 "
        "claimed_constructs=0 claimed_artifacts=0 release_closeout=AUTHORIZED"
    ),
)
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class DuplicateJSONKeyError(ValueError):
    pass


class ValidationCommandError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> Any:
    raise ValueError(f"non-finite JSON value: {value}")


def strict_json_bytes(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def read_json(path: Path = SCOPE_PATH, maximum_bytes: int = 1_048_576) -> Any:
    if path.is_symlink():
        raise ValueError(f"JSON path is a symlink: {path}")
    raw = path.read_bytes()
    if len(raw) > maximum_bytes:
        raise ValueError(f"JSON exceeds {maximum_bytes} bytes: {path}")
    return strict_json_bytes(raw)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _format_keys(keys: Iterable[Any]) -> str:
    return ", ".join(sorted(repr(key) for key in keys))


def exact_value_errors(actual: Any, expected: Any, path: str = "scope") -> list[str]:
    if type(actual) is not type(expected):
        return [
            f"{path} type differs: expected {type(expected).__name__}, "
            f"got {type(actual).__name__}"
        ]
    if isinstance(expected, dict):
        errors: list[str] = []
        missing = expected.keys() - actual.keys()
        extra = actual.keys() - expected.keys()
        if missing:
            errors.append(f"{path} missing keys: {_format_keys(missing)}")
        if extra:
            errors.append(f"{path} has unauthorized keys: {_format_keys(extra)}")
        for key in sorted(expected.keys() & actual.keys()):
            errors.extend(exact_value_errors(actual[key], expected[key], f"{path}.{key}"))
        return errors
    if isinstance(expected, list):
        errors = []
        if len(actual) != len(expected):
            errors.append(f"{path} length differs: expected {len(expected)}, got {len(actual)}")
        for index, (item, expected_item) in enumerate(zip(actual, expected)):
            errors.extend(exact_value_errors(item, expected_item, f"{path}[{index}]"))
        return errors
    if actual != expected:
        return [f"{path} value differs"]
    return []


def validate_scope(payload: Any) -> list[str]:
    return exact_value_errors(payload, EXPECTED_SCOPE)


def _git_environment() -> dict[str, str]:
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
    environment.update(
        {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANG": "C"}
    )
    return environment


def run_git(arguments: list[str], workspace_root: Path = WORKSPACE_ROOT) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=workspace_root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationCommandError(f"cannot run git {' '.join(arguments)}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise ValidationCommandError(
            f"git {' '.join(arguments)} failed ({result.returncode}): {detail}"
        )
    return result.stdout


def _single_ascii_line(raw: bytes, label: str) -> str:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ValidationCommandError(f"{label} is not ASCII") from exc
    if len(lines) != 1 or not lines[0]:
        raise ValidationCommandError(f"{label} did not return exactly one line")
    return lines[0]


def validate_tag_payload(raw_tag: bytes) -> list[str]:
    errors: list[str] = []
    if sha256_bytes(raw_tag) != BASELINE_TAG_SHA256:
        errors.append("v0.4.0 raw tag object SHA-256 differs")
    git_object = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    if hashlib.sha1(git_object).hexdigest() != BASELINE_TAG_OBJECT:
        errors.append("v0.4.0 tag object ID does not match its raw bytes")
    headers, separator, message = raw_tag.partition(b"\n\n")
    if not separator:
        return errors + ["v0.4.0 tag object lacks a message boundary"]
    expected_headers = [
        f"object {BASELINE_COMMIT}".encode("ascii"),
        b"type commit",
        b"tag v0.4.0",
    ]
    if headers.splitlines()[:3] != expected_headers:
        errors.append("v0.4.0 tag headers differ")
    try:
        lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return errors + ["v0.4.0 tag message is not strict UTF-8"]
    for marker in REQUIRED_TAG_MARKERS:
        if lines.count(marker) != 1:
            errors.append(f"v0.4.0 tag marker {marker!r} must occur exactly once")
    return errors


def validate_commit_payload(raw: bytes, tree: str, parent: str, label: str) -> list[str]:
    errors: list[str] = []
    headers = raw.partition(b"\n\n")[0].splitlines()
    tree_lines = [line for line in headers if line.startswith(b"tree ")]
    parent_lines = [line for line in headers if line.startswith(b"parent ")]
    if tree_lines != [f"tree {tree}".encode("ascii")]:
        errors.append(f"{label} tree binding differs")
    if parent_lines != [f"parent {parent}".encode("ascii")]:
        errors.append(f"{label} must have exactly the bound single parent")
    return errors


def parse_name_status_z(raw: bytes) -> list[dict[str, str]]:
    fields = raw.split(b"\0")
    if not fields or fields[-1] != b"":
        raise ValueError("candidate name-status output is not NUL terminated")
    fields.pop()
    if len(fields) % 2:
        raise ValueError("candidate name-status output has an incomplete pair")
    results: list[dict[str, str]] = []
    for index in range(0, len(fields), 2):
        status = fields[index].decode("ascii")
        path = fields[index + 1].decode("utf-8")
        if status not in {"A", "M", "D"}:
            raise ValueError(f"unsupported candidate change status: {status}")
        results.append({"status": status, "path": path})
    return results


def _validate_blob(commit: str, path: str, binding: dict[str, str], root: Path) -> list[str]:
    errors: list[str] = []
    spec = f"{commit}:{path}"
    object_type = _single_ascii_line(run_git(["cat-file", "-t", spec], root), spec)
    if object_type != "blob":
        return [f"immutable path is not a blob: {spec}"]
    blob = _single_ascii_line(run_git(["rev-parse", spec], root), spec)
    if blob != binding["blob"]:
        errors.append(f"immutable blob ID differs: {path}")
    raw = run_git(["cat-file", "blob", spec], root)
    if sha256_bytes(raw) != binding["sha256"]:
        errors.append(f"immutable blob SHA-256 differs: {path}")
    return errors


def _validate_gate_0a_scope(raw: bytes) -> list[str]:
    try:
        payload = strict_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"immutable Gate 0A scope is not strict JSON: {exc}"]
    errors: list[str] = []
    facts = {
        "schema_version": "ng-spell-v05-gate-0a-scope/1",
        "gate_id": "V05-GATE-0A",
        "status": "PASS",
        "target_release": "v0.5.0",
    }
    if not isinstance(payload, dict):
        return ["immutable Gate 0A scope is not an object"]
    for key, value in facts.items():
        if payload.get(key) != value:
            errors.append(f"immutable Gate 0A scope {key} differs")
    decision = payload.get("decision")
    if not isinstance(decision, dict) or decision.get("authorization") != "V05-IR-001_ONLY":
        errors.append("immutable Gate 0A authorization differs")
    work = payload.get("authorized_work_package")
    if not isinstance(work, dict):
        errors.append("immutable Gate 0A work package is missing")
    else:
        if work.get("work_package_id") != "V05-IR-001":
            errors.append("immutable Gate 0A work-package ID differs")
        if work.get("planned_test_ids") != IDENTITY_IDS:
            errors.append("immutable Gate 0A identity catalog differs")
    return errors


def validate_git_bindings(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    errors: list[str] = []
    try:
        tag_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", BASELINE_TAG_REF], workspace_root),
            BASELINE_TAG_REF,
        )
        if tag_ref != BASELINE_TAG_OBJECT:
            errors.append("v0.4.0 tag ref differs")
        if _single_ascii_line(run_git(["cat-file", "-t", BASELINE_TAG_OBJECT], workspace_root), "tag type") != "tag":
            errors.append("v0.4.0 is not an annotated tag")
        errors.extend(validate_tag_payload(run_git(["cat-file", "tag", BASELINE_TAG_OBJECT], workspace_root)))
        peeled = _single_ascii_line(
            run_git(["rev-parse", "--verify", f"{BASELINE_TAG_REF}^{{commit}}"], workspace_root),
            "peeled v0.4.0",
        )
        if peeled != BASELINE_COMMIT:
            errors.append("v0.4.0 peeled commit differs")
        for path, expected_sha in BASELINE_FILES.items():
            raw = run_git(["cat-file", "blob", f"{BASELINE_COMMIT}:{path}"], workspace_root)
            if sha256_bytes(raw) != expected_sha:
                errors.append(f"accepted baseline blob SHA-256 differs: {path}")

        gate_raw = run_git(["cat-file", "commit", GATE_0A_COMMIT], workspace_root)
        errors.extend(validate_commit_payload(gate_raw, GATE_0A_TREE, BASELINE_COMMIT, "Gate 0A commit"))
        for path, binding in GATE_0A_FILES.items():
            errors.extend(_validate_blob(GATE_0A_COMMIT, path, binding, workspace_root))
        gate_scope_path = (
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
            "scopes/v0.5-gate-0a.json"
        )
        gate_scope = run_git(["cat-file", "blob", f"{GATE_0A_COMMIT}:{gate_scope_path}"], workspace_root)
        errors.extend(_validate_gate_0a_scope(gate_scope))

        candidate_raw = run_git(["cat-file", "commit", CANDIDATE_COMMIT], workspace_root)
        errors.extend(validate_commit_payload(candidate_raw, CANDIDATE_TREE, GATE_0A_COMMIT, "candidate commit"))
        actual_changes = parse_name_status_z(
            run_git(
                ["diff-tree", "--no-commit-id", "--name-status", "-r", "-z", CANDIDATE_COMMIT],
                workspace_root,
            )
        )
        expected_changes = [
            {"status": item["status"], "path": item["path"]} for item in CANDIDATE_PATHS
        ]
        if actual_changes != expected_changes:
            errors.append("candidate changed-path set, status, or ordering differs")
        for item in CANDIDATE_PATHS:
            errors.extend(_validate_blob(CANDIDATE_COMMIT, item["path"], item, workspace_root))
        qualification_raw = run_git(
            ["cat-file", "commit", QUALIFICATION_COMMIT], workspace_root
        )
        errors.extend(
            validate_commit_payload(
                qualification_raw,
                QUALIFICATION_TREE,
                QUALIFICATION_PARENT,
                "qualification source commit",
            )
        )
        qualification_changes = parse_name_status_z(
            run_git(
                [
                    "diff-tree",
                    "--no-commit-id",
                    "--name-status",
                    "-r",
                    "-z",
                    QUALIFICATION_COMMIT,
                ],
                workspace_root,
            )
        )
        expected_qualification_change = [
            {
                "status": QUALIFICATION_CORRECTION["status"],
                "path": QUALIFICATION_CORRECTION["path"],
            }
        ]
        if qualification_changes != expected_qualification_change:
            errors.append("qualification source changed-path set differs")
        errors.extend(
            _validate_blob(
                QUALIFICATION_COMMIT,
                QUALIFICATION_CORRECTION["path"],
                QUALIFICATION_CORRECTION,
                workspace_root,
            )
        )
        ancestry = subprocess.run(
            ["git", "--no-replace-objects", "merge-base", "--is-ancestor", QUALIFICATION_COMMIT, "HEAD"],
            cwd=workspace_root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        if ancestry.returncode != 0:
            errors.append("qualification source commit is not an ancestor of HEAD")
    except (ValidationCommandError, ValueError, UnicodeDecodeError) as exc:
        errors.append(str(exc))
    return errors


def validate_evidence_payload(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["qualification evidence is not an object"]
    expected_top = {
        "schema_version", "product_version", "scope_profile", "implementation_candidate",
        "qualification_source", "toolchain", "database", "suites", "identities",
        "inherited_v04", "artifacts", "teardown", "overall_pass",
    }
    if set(payload) != expected_top:
        errors.append("qualification evidence top-level key set differs")
    expected_scalars = {
        "schema_version": "spell.v05.candidate-qualification/1",
        "product_version": "0.5.0-candidate",
        "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
        "overall_pass": True,
    }
    for key, value in expected_scalars.items():
        if type(payload.get(key)) is not type(value) or payload.get(key) != value:
            errors.append(f"qualification evidence {key} differs")
    candidate = payload.get("implementation_candidate")
    if not isinstance(candidate, dict):
        errors.append("qualification implementation-candidate binding is missing")
    else:
        for key, value in {
            "commit": CANDIDATE_COMMIT,
            "tree": CANDIDATE_TREE,
            "parent": GATE_0A_COMMIT,
        }.items():
            if candidate.get(key) != value:
                errors.append(f"qualification candidate {key} differs")
        expected_paths = [{"path": item["path"], "blob": item["blob"]} for item in CANDIDATE_PATHS]
        if candidate.get("changed_paths") != expected_paths:
            errors.append("qualification candidate changed-path bindings differ")
    qualification = payload.get("qualification_source")
    expected_qualification = {
        "commit": QUALIFICATION_COMMIT,
        "tree": QUALIFICATION_TREE,
        "parent": QUALIFICATION_PARENT,
        "correction": {
            "path": QUALIFICATION_CORRECTION["path"],
            "blob": QUALIFICATION_CORRECTION["blob"],
            "sha256": QUALIFICATION_CORRECTION["sha256"],
        },
    }
    if qualification != expected_qualification:
        errors.append("qualification source binding differs")
    toolchain = payload.get("toolchain")
    if not isinstance(toolchain, dict) or toolchain.get("python_version") != "3.13.14":
        errors.append("qualification did not use locked CPython 3.13.14")
    database = payload.get("database")
    if not isinstance(database, dict):
        errors.append("qualification database evidence is missing")
    else:
        for flag in (
            "distinct_names", "both_environment_variables_bound", "postgresql_zero_skips"
        ):
            if database.get(flag) is not True:
                errors.append(f"qualification database flag is not true: {flag}")
        application = database.get("application_name")
        migration = database.get("migration_name")
        if not isinstance(application, str) or not application or not isinstance(migration, str) or not migration:
            errors.append("qualification database names are missing")
        elif application == migration:
            errors.append("qualification application and migration databases are not isolated")
    suites = payload.get("suites")
    expected_suites = {"backend_sqlite", "backend_postgresql", "driver_host", "tooling"}
    if not isinstance(suites, dict) or set(suites) != expected_suites:
        errors.append("qualification suite catalog differs")
    identities = payload.get("identities")
    if not isinstance(identities, dict) or set(identities) != set(IDENTITY_IDS):
        errors.append("qualification identity catalog differs")
    else:
        for identity in IDENTITY_IDS:
            result = identities[identity]
            if not isinstance(result, dict):
                errors.append(f"qualification identity result is not an object: {identity}")
                continue
            nodes = result.get("nodes")
            if not isinstance(nodes, list) or not nodes or not all(isinstance(node, str) and node for node in nodes):
                errors.append(f"qualification identity has no concrete nodes: {identity}")
            elif len(nodes) != len(set(nodes)):
                errors.append(f"qualification identity has duplicate nodes: {identity}")
            if result.get("environments") != ["sqlite", "postgresql"]:
                errors.append(f"qualification identity environments differ: {identity}")
            passed = result.get("passed_count")
            if type(passed) is not int or passed <= 0:
                errors.append(f"qualification identity has no passing tests: {identity}")
            if type(result.get("skipped_count")) is not int or result.get("skipped_count") != 0:
                errors.append(f"qualification identity has skipped tests: {identity}")
    return errors


def validate_evidence_summary(payload: Any, evidence_sha256: str) -> list[str]:
    expected_keys = {"gate", "candidate_commit", "suite_count", "identity_count", "test_count", "evidence_sha256"}
    if not isinstance(payload, dict):
        return ["candidate-evidence validator output is not an object"]
    errors: list[str] = []
    if set(payload) != expected_keys:
        errors.append("candidate-evidence validator output key set differs")
    for key, value in {
        "gate": "PASS", "candidate_commit": CANDIDATE_COMMIT, "suite_count": 4,
        "identity_count": 6, "evidence_sha256": evidence_sha256,
    }.items():
        if type(payload.get(key)) is not type(value) or payload.get(key) != value:
            errors.append(f"candidate-evidence validator output {key} differs")
    test_count = payload.get("test_count")
    if type(test_count) is not int or test_count <= 0:
        errors.append("candidate-evidence validator output test_count is not positive")
    if not HEX_64.fullmatch(str(payload.get("evidence_sha256", ""))):
        errors.append("candidate-evidence validator output evidence_sha256 is malformed")
    return errors


def run_evidence_validator(
    workspace_root: Path = WORKSPACE_ROOT,
    evidence_path: Path | None = None,
    validator_path: Path | None = None,
) -> list[str]:
    evidence = evidence_path or workspace_root / "artifacts/v0.5/work-package/qualification.json"
    validator = validator_path or workspace_root / "scripts/validate_candidate_evidence_v05.py"
    errors: list[str] = []
    for path, label in ((evidence, "qualification evidence"), (validator, "candidate-evidence validator")):
        if path.is_symlink() or not path.is_file():
            return [f"{label} is missing, not regular, or a symlink: {path}"]
    try:
        raw = evidence.read_bytes()
    except OSError as exc:
        return [f"cannot read qualification evidence: {exc}"]
    if len(raw) > 1_048_576:
        return ["qualification evidence exceeds 1048576 bytes"]
    digest = sha256_bytes(raw)
    if digest != EVIDENCE_SHA256:
        errors.append("qualification evidence byte SHA-256 differs")
    try:
        payload = strict_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"qualification evidence is not strict JSON: {exc}"]
    errors.extend(validate_evidence_payload(payload))
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME"):
        environment.pop(name, None)
    try:
        result = subprocess.run(
            [sys.executable, str(validator), "--root", str(workspace_root)],
            cwd=workspace_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return errors + [f"cannot run candidate-evidence validator: {exc}"]
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:1000]
        return errors + [f"candidate-evidence validator failed ({result.returncode}): {detail}"]
    if result.stderr:
        errors.append("candidate-evidence validator wrote stderr on success")
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return errors + ["candidate-evidence validator output is not strict UTF-8"]
    if len(lines) != 1:
        return errors + ["candidate-evidence validator must emit exactly one success line"]
    try:
        summary = strict_json_bytes(lines[0].encode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return errors + [f"candidate-evidence validator output is not strict JSON: {exc}"]
    errors.extend(validate_evidence_summary(summary, digest))
    return errors


def validate_gate_document(path: Path = GATE_DOCUMENT_PATH) -> list[str]:
    if path.is_symlink() or not path.is_file():
        return ["Gate 0B document is missing, not regular, or a symlink"]
    try:
        lines = path.read_bytes().decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return [f"cannot read Gate 0B document as strict UTF-8: {exc}"]
    errors: list[str] = []
    first = next((line for line in lines if line.strip()), None)
    if first != "# SPELL v0.5 Gate 0B Release Closeout":
        errors.append("Gate 0B heading is not the document title")
    for marker in DOCUMENT_MARKERS:
        if lines.count(marker) != 1:
            errors.append(f"Gate 0B document marker {marker!r} must occur exactly once")
    return errors


def _summary(payload: Any, valid: bool) -> dict[str, Any]:
    constructs = artifacts = work_packages = identities = 0
    if isinstance(payload, dict):
        work = payload.get("qualified_work_package")
        if isinstance(work, dict):
            work_packages = 1
            ids = work.get("identity_results")
            if isinstance(ids, list):
                identities = len(ids)
            delta = work.get("compatibility_delta")
            if isinstance(delta, dict):
                if isinstance(delta.get("claimed_construct_ids"), list):
                    constructs = len(delta["claimed_construct_ids"])
                if isinstance(delta.get("claimed_artifact_ids"), list):
                    artifacts = len(delta["claimed_artifact_ids"])
    return {
        "gate": "PASS" if valid else "FAIL",
        "work_packages": work_packages,
        "identities": identities,
        "failed": 0 if valid else 1,
        "skipped": 0,
        "claimed_constructs": constructs,
        "claimed_artifacts": artifacts,
        "release_closeout": "AUTHORIZED" if valid else "DENIED",
    }


def validate_repository(
    scope_path: Path = SCOPE_PATH,
    workspace_root: Path = WORKSPACE_ROOT,
) -> tuple[list[str], dict[str, Any]]:
    try:
        raw_scope = scope_path.read_bytes()
        payload = strict_json_bytes(raw_scope)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors = [f"cannot load Gate 0B scope: {exc}"]
        return errors, _summary(None, False)
    errors = validate_scope(payload)
    if scope_path.is_symlink():
        errors.append("Gate 0B scope is a symlink")
    if sha256_bytes(raw_scope) != SCOPE_SHA256:
        errors.append("Gate 0B scope byte SHA-256 differs")
    errors.extend(validate_git_bindings(workspace_root))
    errors.extend(run_evidence_validator(workspace_root))
    errors.extend(validate_gate_document(workspace_root / "SPELL_v0.5_Gate_0B.md"))
    return errors, _summary(payload, not errors)


def main() -> int:
    errors, summary = validate_repository()
    marker = (
        f"gate={summary['gate']} work_packages={summary['work_packages']} "
        f"identities={summary['identities']} failed={summary['failed']} "
        f"skipped={summary['skipped']} claimed_constructs={summary['claimed_constructs']} "
        f"claimed_artifacts={summary['claimed_artifacts']} "
        f"release_closeout={summary['release_closeout']}"
    )
    print(marker)
    if errors:
        for error in errors[:100]:
            print(f"ERROR: {error[:1000]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
