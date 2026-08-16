#!/usr/bin/env python3
"""Validate the evidence-bound SPELL v0.6 Gate 0B closeout decision."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


DOC_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = DOC_ROOT.parent
SCOPE_PATH = (
    DOC_ROOT
    / "requirements"
    / "compatibility"
    / "scopes"
    / "v0.6-gate-0b.json"
)
GATE_DOCUMENT_PATH = WORKSPACE_ROOT / "SPELL_v0.6_Gate_0B.md"
RELEASE_DOCUMENT_PATH = WORKSPACE_ROOT / "SPELL_v0.6_Release.md"
EVIDENCE_PATH = WORKSPACE_ROOT / "artifacts/v0.6/work-package/qualification.json"
EVIDENCE_VALIDATOR_PATH = WORKSPACE_ROOT / "scripts/validate_candidate_evidence_v06.py"
ACTIVATION_LOCK_RELATIVE = Path(
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/"
    ".v0.6-gate-0b-activation.lock"
)

SCHEMA_VERSION = "ng-spell-v06-gate-0b-scope/1"
EVIDENCE_SCHEMA = "spell.v06.candidate-qualification/1"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
GATE_0A_COMMIT = "f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1"
GATE_0A_PARENT = "e7b6bb9428833437e0160040541eb840deee7cca"
GATE_0A_TREE = "8a75227ad372a819159be7ac276b6d90f0d95c82"
GATE_0A_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_MARKER = "V06-GATE-0A OWNER-APPROVAL: APPROVED"
OWNER_REQUEST = (
    "you have the explicit owner approval for the exact V06-OP-001..009 gate, "
    "please finish up v0.6 asap"
)

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 4 * 1024 * 1024

GATE_RECORD_MARKERS = (
    "<!-- V06_GATE_0B_ACTIVATION_RECORD_BEGIN -->",
    "<!-- V06_GATE_0B_ACTIVATION_RECORD_END -->",
)
GATE_PACKAGE_MARKERS = (
    "<!-- V06_GATE_0B_PACKAGE_DISPOSITIONS_BEGIN -->",
    "<!-- V06_GATE_0B_PACKAGE_DISPOSITIONS_END -->",
)
GATE_FINDING_MARKERS = (
    "<!-- V06_GATE_0B_CURRENT_FINDING_BEGIN -->",
    "<!-- V06_GATE_0B_CURRENT_FINDING_END -->",
)
RELEASE_RECORD_MARKERS = (
    "<!-- V06_RELEASE_CONDITIONAL_RECORD_BEGIN -->",
    "<!-- V06_RELEASE_CONDITIONAL_RECORD_END -->",
)
RELEASE_EVIDENCE_MARKERS = (
    "<!-- V06_RELEASE_EVIDENCE_BINDINGS_BEGIN -->",
    "<!-- V06_RELEASE_EVIDENCE_BINDINGS_END -->",
)
RELEASE_FINDING_MARKERS = (
    "<!-- V06_RELEASE_CURRENT_FINDING_BEGIN -->",
    "<!-- V06_RELEASE_CURRENT_FINDING_END -->",
)

WORK_PACKAGE_TEST_IDS: dict[str, tuple[str, ...]] = {
    "V06-OP-001": (
        "V06-OP-001-UNIT", "V06-OP-001-INTEGRATION",
        "V06-OP-001-RECOVERY", "V06-OP-001-UI", "V06-OP-001-SECURITY",
    ),
    "V06-OP-002": (
        "V06-OP-002-UNIT", "V06-OP-002-INTEGRATION", "V06-OP-002-RACE",
        "V06-OP-002-RECOVERY", "V06-OP-002-SECURITY",
    ),
    "V06-OP-003": (
        "V06-OP-003-UNIT", "V06-OP-003-MATRIX", "V06-OP-003-RACE",
        "V06-OP-003-RECOVERY", "V06-OP-003-SECURITY",
    ),
    "V06-OP-004": (
        "V06-OP-004-UNIT", "V06-OP-004-INTEGRATION", "V06-OP-004-RACE",
        "V06-OP-004-RECOVERY", "V06-OP-004-UI",
    ),
    "V06-OP-005": (
        "V06-OP-005-UNIT", "V06-OP-005-INTEGRATION", "V06-OP-005-CLOCK",
        "V06-OP-005-RACE", "V06-OP-005-RECOVERY",
    ),
    "V06-OP-006": (
        "V06-OP-006-UNIT", "V06-OP-006-INTEGRATION", "V06-OP-006-UI",
        "V06-OP-006-RECOVERY", "V06-OP-006-SECURITY",
    ),
    "V06-OP-007": (
        "V06-OP-007-UNIT", "V06-OP-007-INTEGRATION", "V06-OP-007-RACE",
        "V06-OP-007-RECOVERY", "V06-OP-007-SECURITY",
    ),
    "V06-OP-008": (
        "V06-OP-008-UNIT", "V06-OP-008-INTEGRATION", "V06-OP-008-GRAPH",
        "V06-OP-008-RECOVERY", "V06-OP-008-SECURITY",
    ),
    "V06-OP-009": (
        "V06-OP-009-DESKTOP", "V06-OP-009-MOBILE",
        "V06-OP-009-ACCESSIBILITY", "V06-OP-009-FAULT-RECOVERY",
        "V06-OP-009-SECURITY",
    ),
}
TEST_IDS = tuple(item for values in WORK_PACKAGE_TEST_IDS.values() for item in values)

SUITE_IDS = (
    "backend_sqlite",
    "backend_postgresql",
    "backend_docker_host",
    "backend_v06_soak",
    "driver_host",
    "tooling",
    "frontend_vitest",
    "frontend_build",
    "frontend_playwright_mocked",
    "frontend_playwright_live",
)

GATE_FILES = {
    "SPELL_v0.6_Pre-Implementation.md": {
        "blob": "4fa5daeca3e8a559d1d910b523cda0c835f834a2",
        "sha256": "497be88039af17c13df5250a4300167a8b0c650d63cbc428a1d0132b1cc4d128",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.6-gate-0a.json"
    ): {
        "blob": "85003defc614d3737d899adbd907f83890ed32ad",
        "sha256": "e76c3100de505cb2768bc0c6e424c54d04576ce4064d4444e0423c2c717b0b6c",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v06_gate_0a.py"
    ): {
        "blob": "70f63e45bfc63d48c0339dac922fe613b031ec4c",
        "sha256": "a0e5486ccdb48e4f7891808ac079a82ade4088d5b57ac86c6ae183106b266996",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v06_gate_0a.py"
    ): {
        "blob": "fb8cade9725c953f3bb5131cb02dae0622a71683",
        "sha256": "8c13bda16f2d77b4713049f3a55e5b11a2281a0d50c02e3cd5a3a9e08575b649",
    },
}

CONTRACT_FILES = {
    "contracts/v06/manifest.json": (
        "a183253143632b0ed87adec0bcf1e2af74ebd22f",
        "40ba27d85797fbc84a90f98a7878521d1092dcd618aaae991b059b027ecc5ac6",
    ),
    "contracts/v06/command_state.json": (
        "d4661fca083fe016de3ffa6a3bbf98676b6f76c5",
        "9f3a461a8893ba23bf9a7cb7fc3c6c6b8d6799069156af83b0b9d0ce25a78225",
    ),
    "contracts/v06/prompt_behavior.json": (
        "3cbb5b85b2547cfb626647c0d256709bc34f695a",
        "118c32f13fa7155f45614a9e3fc71056dd97ec5aa6de1c2a200fb87523bdf381",
    ),
    "contracts/v06/schedule_behavior.json": (
        "497c6ab138314fa1845af2351d56c521870db775",
        "3388f0c802ec36b68c759de133a12ea10b5b83fd20ccf5d5f89e48a04b15129a",
    ),
    "contracts/v06/inspection_and_actions.json": (
        "5bc866aa6ae18e4e01f48a061d761b93bcf6462a",
        "71a0ca90c3aa8e581f49895982099d3aa4315dff09c0cb8e27f5eccda4cf3966",
    ),
    "contracts/v06/startproc_behavior.json": (
        "cfbdd2005f8bfc04cf836736e45ba5e52cd2b8f5",
        "c78fbee4def5860f04a74c37c6800d1f9ad9a58f0980550bef0ae00b9722a81f",
    ),
    "contracts/v06/lease_modes.json": (
        "780eeaab53ed784eaed7fa3da953005e01eef331",
        "10411be382239c1c480c9f331d988f45aad2ecd40be49135bf9f96259ec9b586",
    ),
}

BASELINE = {
    "tag_ref": "refs/tags/v0.5.0",
    "tag_object_type": "tag",
    "tag_object_id": "a1b277d74d2fb19062ca3e4388e9104d45c50ec4",
    "raw_tag_object_sha256": "6c642ec6f7461db9fdce2347ca6ab493686430d5bd36218a4c0306b1b70ba48f",
    "peeled_release_commit": GATE_0A_PARENT,
    "qualified_source_commit": "2f31e6a011b8aad63b29bd55780c37c1b68712f1",
    "tagged_files_sha256": {
        "SPELL_v0.5_Release.md": (
            "055da745f54da76da097741e84dc15725d0584f54a20b499e658fbcfd9f85a4e"
        ),
        (
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
            "scopes/v0.5-gate-0b.json"
        ): "f98d50498ef8caf7304ad2e027f0eb8f03c02b486d8ec871f6ca95cc28987248",
        "artifacts/v0.5/release-qualification.json": (
            "fe66fa5c232b063f8920f6087a49205754e6fa75fdefb1a105383b6f528e48ba"
        ),
    },
}

NEW_TABLES = (
    "operator_contexts",
    "procedure_catalog_entries",
    "procedure_catalog_revisions",
    "execution_operator_states",
    "controller_leases",
    "monitor_subscriptions",
    "controller_handovers",
    "operator_requests",
    "operator_audit_events",
    "operator_commands",
    "operator_prompts",
    "operator_prompt_attempts",
    "inspection_edit_operations",
    "operator_breakpoints",
    "operator_user_actions",
    "operator_user_action_invocations",
    "procedure_schedules",
    "schedule_occurrences",
    "startproc_operations",
    "parent_child_links",
)

API_ROUTE_MARKERS = (
    '"/api/v1/contexts"',
    '"/api/v1/master"',
    '"/api/v1/executions/{execution_id}/control"',
    '"/api/v1/executions/{execution_id}/monitors"',
    '"/api/v1/executions/{execution_id}/handovers"',
    '"/api/v1/executions/{execution_id}/commands"',
    '"/api/v1/prompts/{prompt_id}/responses"',
    '"/api/v1/schedules"',
    '"/api/v1/executions/{execution_id}/workspace-view"',
    '"/api/v1/executions/{execution_id}/inspection/edits"',
    '"/api/v1/executions/{execution_id}/console-operations"',
    '"/api/v1/executions/{execution_id}/actions"',
    '"/api/v1/executions/{execution_id}/relationships"',
    '"/api/v1/executions/{execution_id}/startproc-operations"',
    '"/api/v1/executions/{execution_id}/breakpoints"',
)

ROUTE_FAMILIES = (
    "CONTEXTS_AND_SETTINGS",
    "CATALOG_HISTORY_AND_MASTER",
    "EXECUTION_OPERATOR_SNAPSHOT_AND_CONTROL",
    "MONITORS_AND_HANDOVERS",
    "DURABLE_COMMANDS_AND_TYPED_PROMPTS",
    "SCHEDULES",
    "WORKSPACE_VIEWS_SEARCH_INSPECTION_EDITS_AND_CONSOLE",
    "USER_ACTIONS",
    "RELATIONSHIPS_STARTPROC_AND_BREAKPOINTS",
    "REDACTED_AS_RUN_REPORT",
)

CLOSEOUT_ACTIONS = (
    "RECORD_V06_OP_001_THROUGH_V06_OP_009_IMPLEMENTED",
    "PUBLISH_CANONICAL_FINAL_QUALIFICATION_EVIDENCE_AND_HASHES",
    "UPDATE_RELEASE_VERSION_PROVENANCE_HISTORY_AND_TEST_RECORDS",
    "CREATE_VERSION_SCOPED_SBOMS_AND_SUPPLY_CHAIN_EVIDENCE",
    "CREATE_DETERMINISTIC_V0_6_RELEASE_PACKAGE",
    "COMMIT_RELEASE_CLOSEOUT",
    "CREATE_ONE_ANNOTATED_V0_6_0_TAG",
)

REQUIRED_REBINDINGS = (
    "/immutable_inputs/candidate/binding_status",
    "/immutable_inputs/candidate/commit",
    "/immutable_inputs/candidate/tree",
    "/immutable_inputs/candidate/changed_paths",
    "/qualification_contract/status",
    "/qualification_contract/manifest_sha256",
    "/qualification_contract/validator_success_shape/source_commit",
    "/reviewed_surface_delta/review_status",
)

REQUIRED_TRANSITIONS = {
    "/status": "PASS",
    "/decision/authorization": "V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY",
    "/immutable_inputs/candidate/binding_status": "BOUND",
    "/qualification_contract/status": "PASS",
    "/reviewed_surface_delta/review_status": "REVIEWED_AND_QUALIFIED",
    "/release_closeout_authorization/status": "AUTHORIZED",
    "/qualified_work_packages/*/status": "IMPLEMENTED_AND_QUALIFIED",
}

EXCLUSIONS = (
    "SCOPE_BEYOND_V06_OP_001_THROUGH_V06_OP_009",
    "NON_LOCAL_NON_SYNTHETIC_CUI_CLASSIFIED_PRODUCTION_OR_OPERATIONAL_DATA",
    "LIVE_DRIVER_GCS_SPACECRAFT_TELEMETRY_TELECOMMAND_OR_EXTERNAL_EFFECT_ROUTING",
    "ARBITRARY_PYTHON_SOURCE_EXPRESSION_FUNCTION_OR_SHELL_EXECUTION",
    "UNBOUNDED_CONSOLE_OR_UNSAFE_SHARED_DATA_EDIT",
    "ARBITRARY_ASYNCHRONOUS_OR_NON_ALLOWLISTED_USER_ACTIONS",
    "HARD_KILL_OR_CLEAN_EXTERNAL_STATE_INFERENCE",
    "MUTABLE_LIBRARY_RESOLUTION_OR_UNBOUNDED_PARENT_CHILD_GRAPH",
    "BROAD_LEGACY_LANGUAGE_API_DATABASE_DRIVER_OR_OPERATIONAL_COMPATIBILITY_CLAIM",
    "LIGHTWEIGHT_SECONDARY_OR_V0_6_ALIAS_TAG",
    "DEPLOYMENT_OPERATIONAL_COMPLIANCE_OR_CRYPTOGRAPHIC_SIGNATURE_CLAIM",
)

REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Gate 0B: PASS",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
    "Cryptographic signature: Not claimed",
)


class GateValidationError(ValueError):
    """A Gate 0B input is malformed, incomplete, or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GateValidationError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise GateValidationError(f"non-finite JSON value: {value}")


def strict_json_bytes(raw: bytes, label: str = "JSON") -> dict[str, Any]:
    _require(len(raw) <= MAX_JSON_BYTES, f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateValidationError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def read_json(path: Path, label: str) -> dict[str, Any]:
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    return strict_json_bytes(path.read_bytes(), label)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _normalized_document(path: Path, label: str) -> tuple[str, str]:
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateValidationError(f"{label} is not strict UTF-8") from exc
    newline = "\r\n" if b"\r\n" in raw else "\n"
    normalized = text.replace("\r\n", "\n")
    _require("\r" not in normalized, f"{label} has mixed or invalid newlines")
    return normalized, newline


def _marked_body(
    text: str,
    markers: tuple[str, str],
    label: str,
) -> str:
    begin, end = markers
    _require(text.count(begin) == 1, f"{label} begin marker differs")
    _require(text.count(end) == 1, f"{label} end marker differs")
    start = text.index(begin) + len(begin)
    finish = text.index(end)
    _require(start < finish, f"{label} marker order differs")
    return text[start:finish].strip("\n")


def _replace_marked_body(
    text: str,
    markers: tuple[str, str],
    body: str,
    label: str,
    *,
    blank_before_end: bool = False,
) -> str:
    _marked_body(text, markers, label)
    begin, end = markers
    start = text.index(begin) + len(begin)
    finish = text.index(end)
    separator = "\n\n" if blank_before_end else "\n"
    return f"{text[:start]}\n{body.strip(chr(10))}{separator}{text[finish:]}"


def _gate_record_body(scope: Mapping[str, Any]) -> str:
    state = scope["status"]
    candidate = scope["immutable_inputs"]["candidate"]
    qualification = scope["qualification_contract"]
    if state == "PASS":
        gate_status = "`PASS`; exact v0.6 release closeout authorized"
        candidate_value = (
            f"Commit `{candidate['commit']}`; tree `{candidate['tree']}`; "
            f"sole parent `{candidate['parent']}`"
        )
        evidence_value = (
            f"`{qualification['manifest_path']}`; SHA-256 "
            f"`{qualification['manifest_sha256']}`"
        )
        decision = "V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY"
        authorization = "AUTHORIZED"
    else:
        gate_status = "`PENDING_CANDIDATE`; no release closeout authorization yet"
        candidate_value = "Pending source freeze"
        evidence_value = (
            "Pending at `artifacts/v0.6/work-package/qualification.json`"
        )
        decision = "PENDING_CANONICAL_V06_CANDIDATE_QUALIFICATION"
        authorization = "NOT_YET_AUTHORIZED"
    return "\n".join(
        (
            "## Document Control",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Version target | SPELL v0.6.0 |",
            "| Gate | `V06-GATE-0B` |",
            f"| Gate status | {gate_status} |",
            "| Record date | 2026-08-15 |",
            "| Accepted product baseline | Annotated tag `v0.5.0`; release commit `e7b6bb9428833437e0160040541eb840deee7cca` |",
            "| Gate 0A authorization | Commit `f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1`; `V06-OP-001` through `V06-OP-009` |",
            f"| Candidate source | {candidate_value} |",
            f"| Canonical candidate evidence | {evidence_value} |",
            "| Required result inventory | Nine work packages; 45 exact test identities; zero mapped skips, failures, accepted failures, or waivers |",
            "| Release tag requested | One annotated semantic-version tag: `v0.6.0` |",
            "| Project owner | JC Arcaz |",
            "",
            f"Owner request: `{OWNER_REQUEST}`",
            "",
            f"Gate 0B decision: `{decision}`",
            "",
            f"Release closeout authorization: `{authorization}`",
            "",
            "Release acceptance by Gate 0B: No",
            "",
            "Operational authorization: None",
        )
    )


def _gate_package_body(state: str) -> str:
    if state == "PASS":
        return (
            "All nine exact work packages are `IMPLEMENTED_AND_QUALIFIED`. "
            "Every listed identity has one or more concrete passing proof nodes; "
            "no mapped identity is skipped, failed, accepted as failed, or waived."
        )
    return (
        "Each package remains `PENDING_QUALIFICATION`. On Gate 0B activation, every row\n"
        "must change to `IMPLEMENTED_AND_QUALIFIED` and every listed identity must have\n"
        "one or more concrete passing proof nodes."
    )


def _gate_finding_body(state: str) -> str:
    if state == "PASS":
        return (
            "`V06-GATE-0B PASS` authorizes release closeout for exactly "
            "`V06-OP-001` through `V06-OP-009`. It does not itself accept the "
            "release, authorize deployment or operational use, or make a compliance "
            "or cryptographic-signature claim."
        )
    return (
        "`V06-GATE-0B PENDING_CANDIDATE` records the exact release-closeout contract but\n"
        "does not authorize closeout. Candidate freeze, canonical evidence, independent\n"
        "validation, 45 passing identities, and reviewed delta binding remain required."
    )


def _release_record_body(scope: Mapping[str, Any]) -> str:
    state = scope["status"]
    candidate = scope["immutable_inputs"]["candidate"]
    if state == "PASS":
        record_state = "`CONDITIONAL_FINAL_CLOSEOUT`; this document is not yet an acceptance claim"
        gate_state = "`PASS`"
        candidate_commit = f"`{candidate['commit']}`"
    else:
        record_state = "`CONDITIONAL_PENDING`; this document is not an acceptance claim"
        gate_state = "`PENDING_CANDIDATE`"
        candidate_commit = "Pending"
    return "\n".join(
        (
            "## Record Status",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Version | SPELL v0.6.0 |",
            "| Release name | Durable Operator Workspace and Procedure Composition |",
            f"| Record state | {record_state} |",
            "| Scope | `V06-OP-001` through `V06-OP-009` only |",
            "| Accepted baseline | SPELL v0.5.0, annotated tag `v0.5.0` |",
            "| Gate 0A | `PASS` at commit `f6eba8be0f7ca9e2f1d466aea66902152fb1bbc1` |",
            f"| Gate 0B | {gate_state} |",
            f"| Candidate source commit | {candidate_commit} |",
            "| Final qualified source commit | Pending |",
            "| Release commit | Pending |",
            "| Release tag | Pending annotated tag `v0.6.0` |",
            "| Accepted exceptions | None proposed; final evidence must contain no accepted failure or waiver |",
            "| Operational authorization | None |",
            "| Compliance determination | None |",
            "| Cryptographic signature | Not claimed |",
            "| Project owner | JC Arcaz |",
            "",
            f"Owner request: `{OWNER_REQUEST}`",
            "",
            "Release decision: `PENDING_FINAL_EVIDENCE_RELEASE_COMMIT_AND_ANNOTATED_TAG`",
        )
    )


def _release_evidence_body(scope: Mapping[str, Any], scope_sha256: str) -> str:
    state = scope["status"]
    qualification = scope["qualification_contract"]
    candidate_value = (
        f"`PASS`; SHA-256 `{qualification['manifest_sha256']}`"
        if state == "PASS"
        else "Pending"
    )
    gate_value = (
        f"`PASS`; SHA-256 `{scope_sha256}`"
        if state == "PASS"
        else "Pending activation"
    )
    return "\n".join(
        (
            "The following values must be inserted only after their canonical producers and",
            "independent validators pass:",
            "",
            "| Evidence | Required canonical location | Current value |",
            "| --- | --- | --- |",
            f"| Candidate qualification | `artifacts/v0.6/work-package/qualification.json` | {candidate_value} |",
            f"| Gate 0B machine scope | `.../scopes/v0.6-gate-0b.json` | {gate_value} |",
            "| Final qualification | `artifacts/v0.6/final/qualification.json` | Pending |",
            "| Release qualification manifest | `artifacts/v0.6/release-qualification.json` | Pending |",
            "| Backend SBOM | `artifacts/v0.6/sbom/backend.cdx.json` | Pending |",
            "| Frontend SBOM | `artifacts/v0.6/sbom/frontend.cdx.json` | Pending |",
            "| Driver SBOM | `artifacts/v0.6/sbom/driver.cdx.json` | Pending |",
            "| Proxy SBOM | `artifacts/v0.6/sbom/proxy.cdx.json` | Pending |",
            "| Supply-chain result | `artifacts/v0.6/supply-chain.json` | Pending |",
            "| Deterministic archive | `artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz` | Pending |",
            "| Archive sidecar | `artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256` | Pending |",
            "| Release commit | Git commit | Pending |",
            "| Annotated tag object | `refs/tags/v0.6.0` | Pending |",
        )
    )


def _release_finding_body(state: str) -> str:
    if state == "PASS":
        return (
            "Gate 0B has passed for the exact nine-package v0.6 candidate, but SPELL "
            "v0.6.0 is not yet accepted by this record. Final qualification, supply-chain "
            "evidence, deterministic packaging, the release commit, annotated tag, and "
            "strict post-tag verification remain pending."
        )
    return (
        "SPELL v0.6.0 is not yet accepted by this record. Gate 0B activation, final\n"
        "qualification, supply-chain evidence, deterministic packaging, the release\n"
        "commit, annotated tag, and strict post-tag verification remain pending."
    )


def render_activation_documents(
    gate_path: Path,
    release_path: Path,
    scope: Mapping[str, Any],
) -> tuple[bytes, bytes]:
    _exact(scope["status"], "PASS", "activation document state")
    scope_sha256 = sha256_bytes(canonical_scope_bytes(scope))
    gate_text, gate_newline = _normalized_document(gate_path, "Gate 0B document")
    release_text, release_newline = _normalized_document(
        release_path, "v0.6 release document"
    )
    for markers, body, label in (
        (GATE_RECORD_MARKERS, _gate_record_body(scope), "Gate 0B activation record"),
        (GATE_PACKAGE_MARKERS, _gate_package_body("PASS"), "Gate 0B package dispositions"),
        (GATE_FINDING_MARKERS, _gate_finding_body("PASS"), "Gate 0B current finding"),
    ):
        gate_text = _replace_marked_body(gate_text, markers, body, label)
    for markers, body, label in (
        (RELEASE_RECORD_MARKERS, _release_record_body(scope), "release conditional record"),
        (RELEASE_EVIDENCE_MARKERS, _release_evidence_body(scope, scope_sha256), "release evidence bindings"),
        (RELEASE_FINDING_MARKERS, _release_finding_body("PASS"), "release current finding"),
    ):
        release_text = _replace_marked_body(
            release_text,
            markers,
            body,
            label,
            blank_before_end=markers == RELEASE_EVIDENCE_MARKERS,
        )
    return (
        gate_text.replace("\n", gate_newline).encode("utf-8"),
        release_text.replace("\n", release_newline).encode("utf-8"),
    )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], keys: Iterable[str], label: str) -> None:
    expected = set(keys)
    actual = set(value)
    _require(actual == expected, f"{label} keys differ: {sorted(actual ^ expected)!r}")


def _exact(value: Any, expected: Any, label: str) -> None:
    _require(type(value) is type(expected) and value == expected, f"{label} differs")


def _bounded_path(value: Any, label: str) -> str:
    _require(isinstance(value, str) and value and "\\" not in value, f"{label} is invalid")
    path = PurePosixPath(value)
    _require(not path.is_absolute() and ".." not in path.parts, f"{label} is unsafe")
    _require(path.as_posix() == value, f"{label} is not canonical")
    return value


def _validate_decision(scope: Mapping[str, Any], state: str) -> None:
    decision = _mapping(scope["decision"], "decision")
    _exact_keys(
        decision,
        {
            "owner", "decision_date", "authorization", "owner_request",
            "gate_0a_owner_approval_reaffirmed", "tag_resolution", "precondition",
        },
        "decision",
    )
    _exact(decision["owner"], "JC Arcaz", "decision.owner")
    _exact(decision["decision_date"], "2026-08-15", "decision.decision_date")
    _exact(decision["owner_request"], OWNER_REQUEST, "decision.owner_request")
    _exact(
        decision["gate_0a_owner_approval_reaffirmed"], True,
        "decision.gate_0a_owner_approval_reaffirmed",
    )
    _exact(
        decision["tag_resolution"],
        "REQUESTED_V0_6_RESOLVES_TO_ONE_ANNOTATED_SEMVER_TAG_V0_6_0",
        "decision.tag_resolution",
    )
    _exact(
        decision["precondition"],
        "CANONICAL_V06_CANDIDATE_QUALIFICATION_AND_GATE_0B_VALIDATOR_PASS",
        "decision.precondition",
    )
    expected = (
        "PENDING_V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT"
        if state == "PENDING_CANDIDATE"
        else "V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY"
    )
    _exact(decision["authorization"], expected, "decision.authorization")


def _validate_immutable_inputs(scope: Mapping[str, Any], state: str) -> None:
    inputs = _mapping(scope["immutable_inputs"], "immutable_inputs")
    _exact_keys(inputs, {"accepted_v0_5_0", "gate_0a", "candidate"}, "immutable_inputs")
    _exact(inputs["accepted_v0_5_0"], BASELINE, "accepted v0.5.0 binding")

    gate = _mapping(inputs["gate_0a"], "immutable_inputs.gate_0a")
    _exact_keys(
        gate,
        {"commit", "parent", "tree", "validator_output", "owner_marker", "files", "contracts"},
        "immutable_inputs.gate_0a",
    )
    _exact(gate["commit"], GATE_0A_COMMIT, "Gate 0A commit")
    _exact(gate["parent"], GATE_0A_PARENT, "Gate 0A parent")
    _exact(gate["tree"], GATE_0A_TREE, "Gate 0A tree")
    _exact(gate["validator_output"], GATE_0A_MARKER, "Gate 0A marker")
    _exact(gate["owner_marker"], OWNER_MARKER, "Gate 0A owner marker")
    _exact(gate["files"], GATE_FILES, "Gate 0A file bindings")
    expected_contracts = {
        path: {"blob": values[0], "sha256": values[1]}
        for path, values in CONTRACT_FILES.items()
    }
    _exact(gate["contracts"], expected_contracts, "Gate 0A contract bindings")

    candidate = _mapping(inputs["candidate"], "immutable_inputs.candidate")
    _exact_keys(
        candidate,
        {"binding_status", "commit", "parent", "tree", "changed_paths"},
        "immutable_inputs.candidate",
    )
    _exact(candidate["parent"], GATE_0A_COMMIT, "candidate.parent")
    if state == "PENDING_CANDIDATE":
        _exact(candidate["binding_status"], "PENDING_SOURCE_FREEZE", "candidate.binding_status")
        _exact(candidate["commit"], None, "candidate.commit")
        _exact(candidate["tree"], None, "candidate.tree")
        _exact(candidate["changed_paths"], [], "candidate.changed_paths")
        return
    _exact(candidate["binding_status"], "BOUND", "candidate.binding_status")
    _require(HEX40.fullmatch(str(candidate["commit"])) is not None, "candidate.commit is invalid")
    _require(HEX40.fullmatch(str(candidate["tree"])) is not None, "candidate.tree is invalid")
    paths = candidate["changed_paths"]
    _require(isinstance(paths, list) and bool(paths), "candidate.changed_paths is empty")
    previous = ""
    for index, raw in enumerate(paths):
        item = _mapping(raw, f"candidate.changed_paths[{index}]")
        _exact_keys(item, {"path", "status", "blob", "sha256"}, f"candidate changed path {index}")
        path = _bounded_path(item["path"], f"candidate changed path {index}")
        _require(path > previous, "candidate changed paths are not unique and sorted")
        previous = path
        _require(item["status"] in {"A", "M"}, f"candidate changed path status is unsupported: {path}")
        _require(HEX40.fullmatch(str(item["blob"])) is not None, f"candidate blob is invalid: {path}")
        _require(HEX64.fullmatch(str(item["sha256"])) is not None, f"candidate hash is invalid: {path}")


def _validate_qualification_contract(scope: Mapping[str, Any], state: str) -> None:
    contract = _mapping(scope["qualification_contract"], "qualification_contract")
    _exact_keys(
        contract,
        {
            "status", "manifest_path", "manifest_schema", "manifest_sha256",
            "validator_path", "validator_success_shape", "python_version", "suite_ids",
            "postgresql_environment_variables", "mapped_test_ids_skipped",
            "accepted_failures", "waivers", "waivers_allowed",
        },
        "qualification_contract",
    )
    _exact(contract["manifest_path"], "artifacts/v0.6/work-package/qualification.json", "manifest path")
    _exact(contract["manifest_schema"], EVIDENCE_SCHEMA, "manifest schema")
    _exact(contract["validator_path"], "scripts/validate_candidate_evidence_v06.py", "validator path")
    _exact(contract["python_version"], "3.13.14", "qualification Python")
    _exact(contract["suite_ids"], list(SUITE_IDS), "qualification suite inventory")
    _exact(
        contract["postgresql_environment_variables"],
        ["SPELL_TEST_DATABASE_URL", "SPELL_MIGRATION_TEST_DATABASE_URL"],
        "PostgreSQL environment contract",
    )
    for key in ("mapped_test_ids_skipped", "accepted_failures", "waivers"):
        _exact(contract[key], [], f"qualification_contract.{key}")
    _exact(contract["waivers_allowed"], False, "qualification_contract.waivers_allowed")
    success = _mapping(contract["validator_success_shape"], "validator_success_shape")
    _exact_keys(
        success,
        {"gate", "schema_version", "source_commit", "suites", "test_ids", "tests_minimum"},
        "validator_success_shape",
    )
    _exact(success["gate"], "PASS", "validator success gate")
    _exact(success["schema_version"], EVIDENCE_SCHEMA, "validator success schema")
    _exact(success["suites"], 10, "validator success suite count")
    _exact(success["test_ids"], 45, "validator success identity count")
    _exact(success["tests_minimum"], 1, "validator success test minimum")
    candidate = _mapping(scope["immutable_inputs"], "immutable_inputs")["candidate"]
    if state == "PENDING_CANDIDATE":
        _exact(contract["status"], "PENDING_CANONICAL_EVIDENCE", "qualification status")
        _exact(contract["manifest_sha256"], None, "qualification manifest hash")
        _exact(success["source_commit"], None, "validator success source")
    else:
        _exact(contract["status"], "PASS", "qualification status")
        _require(HEX64.fullmatch(str(contract["manifest_sha256"])) is not None, "qualification manifest hash is invalid")
        _exact(success["source_commit"], candidate["commit"], "validator success source")


def _validate_packages(scope: Mapping[str, Any], state: str) -> None:
    packages = scope["qualified_work_packages"]
    _require(isinstance(packages, list) and len(packages) == 9, "work-package inventory differs")
    expected_status = "PENDING_QUALIFICATION" if state == "PENDING_CANDIDATE" else "IMPLEMENTED_AND_QUALIFIED"
    observed_ids: list[str] = []
    observed_tests: list[str] = []
    for index, raw in enumerate(packages):
        package = _mapping(raw, f"qualified_work_packages[{index}]")
        _exact_keys(package, {"work_package_id", "status", "test_ids"}, f"work package {index}")
        package_id = package["work_package_id"]
        _require(package_id in WORK_PACKAGE_TEST_IDS, f"unknown work package: {package_id!r}")
        observed_ids.append(package_id)
        _exact(package["status"], expected_status, f"{package_id}.status")
        _exact(package["test_ids"], list(WORK_PACKAGE_TEST_IDS[package_id]), f"{package_id}.test_ids")
        observed_tests.extend(package["test_ids"])
    _exact(observed_ids, list(WORK_PACKAGE_TEST_IDS), "work-package order")
    _exact(observed_tests, list(TEST_IDS), "45-ID inventory")
    _require(len(set(observed_tests)) == 45, "45-ID inventory contains duplicates")


def _validate_reviewed_delta(scope: Mapping[str, Any], state: str) -> None:
    delta = _mapping(scope["reviewed_surface_delta"], "reviewed_surface_delta")
    _exact_keys(
        delta,
        {"review_status", "internal_ir", "operator_api", "database_schema", "dependencies_and_driver", "compatibility_ledger"},
        "reviewed_surface_delta",
    )
    expected_review = "PENDING_CANDIDATE_BINDING_AND_QUALIFICATION" if state == "PENDING_CANDIDATE" else "REVIEWED_AND_QUALIFIED"
    _exact(delta["review_status"], expected_review, "reviewed_surface_delta.review_status")

    ir = _mapping(delta["internal_ir"], "reviewed_surface_delta.internal_ir")
    _exact_keys(
        ir,
        {"accepted_persisted_version_preserved", "accepted_v0_5_ir_blob", "accepted_v0_5_ir_sha256", "new_internal_version", "new_internal_file", "opt_in_constructs", "v0_3_serialized_bytes_must_remain_unchanged", "public_legacy_language_compatibility_claimed"},
        "internal IR delta",
    )
    _exact(ir["accepted_persisted_version_preserved"], "0.3", "accepted IR version")
    _exact(ir["accepted_v0_5_ir_blob"], "87f202e9e3ff192e348c2aea9f7009ea7fc95841", "accepted IR blob")
    _exact(ir["accepted_v0_5_ir_sha256"], "2726774ed5873e0c0c1eeaffa7b3713c708ac7f61a6fa93e544a8dbc8c79963c", "accepted IR hash")
    _exact(ir["new_internal_version"], "0.6", "new internal IR version")
    _exact(ir["new_internal_file"], "backend/ir_v06.py", "new internal IR file")
    _exact(ir["opt_in_constructs"], ["TYPED_PROMPT", "STATIC_USER_ACTION", "STARTPROC", "OPERATOR_SAFE_POINT_METADATA"], "internal IR opt-in constructs")
    _exact(ir["v0_3_serialized_bytes_must_remain_unchanged"], True, "IR 0.3 byte preservation")
    _exact(ir["public_legacy_language_compatibility_claimed"], False, "legacy compatibility claim")

    api = _mapping(delta["operator_api"], "reviewed_surface_delta.operator_api")
    _exact_keys(api, {"api_version", "classification", "route_families", "strict_request_schema_file", "service_boundary_file", "broad_public_api_compatibility_claimed"}, "operator API delta")
    _exact(api["api_version"], "v1", "operator API version")
    _exact(api["classification"], "ADDITIVE_LOCAL_OPERATOR_WORKSPACE_ROUTES_WITH_STRICT_MUTATION_SCHEMAS", "operator API classification")
    _exact(api["route_families"], list(ROUTE_FAMILIES), "operator API route family inventory")
    _exact(api["strict_request_schema_file"], "backend/schemas.py", "strict request schema file")
    _exact(api["service_boundary_file"], "backend/operator_service.py", "operator service boundary")
    _exact(api["broad_public_api_compatibility_claimed"], False, "public API compatibility claim")

    database = _mapping(delta["database_schema"], "reviewed_surface_delta.database_schema")
    _exact_keys(database, {"migration_version", "migration_file", "new_tables", "existing_tables_rewritten_by_migration", "sqlite_and_postgresql_required", "rollback_and_upgrade_proof_required", "broad_database_compatibility_claimed"}, "database schema delta")
    _exact(database["migration_version"], "0004_operator_workspace", "migration version")
    _exact(database["migration_file"], "backend/migrations/versions/v0004_operator_workspace.py", "migration file")
    _exact(database["new_tables"], list(NEW_TABLES), "migration table inventory")
    _exact(database["existing_tables_rewritten_by_migration"], [], "existing table rewrite declaration")
    _exact(database["sqlite_and_postgresql_required"], True, "database dialect requirement")
    _exact(database["rollback_and_upgrade_proof_required"], True, "migration proof requirement")
    _exact(database["broad_database_compatibility_claimed"], False, "database compatibility claim")

    dependency = _mapping(delta["dependencies_and_driver"], "reviewed_surface_delta.dependencies_and_driver")
    _exact(dependency, {"new_runtime_dependencies": [], "driver_implementation_version": "0.4.0", "live_driver_or_external_effect_route_added": False, "driver_contract_change_claimed": False}, "dependency and driver delta")
    compatibility = _mapping(delta["compatibility_ledger"], "reviewed_surface_delta.compatibility_ledger")
    _exact(compatibility, {"claimed_construct_ids": [], "claimed_artifact_ids": [], "compatibility_ledger_rows_added": 0, "v0_5_scope_rows_changed": 0, "broad_compatibility_claimed": False}, "compatibility ledger delta")


def _validate_closeout_and_claims(scope: Mapping[str, Any], state: str) -> None:
    closeout = _mapping(scope["release_closeout_authorization"], "release_closeout_authorization")
    _exact_keys(closeout, {"status", "release_version", "tag_name", "tag_object_type", "permitted_actions_after_pass", "additional_product_work_authorized"}, "release closeout authorization")
    _exact(closeout["status"], "PENDING_GATE_0B_PASS" if state == "PENDING_CANDIDATE" else "AUTHORIZED", "release closeout status")
    _exact(closeout["release_version"], "0.6.0", "release closeout version")
    _exact(closeout["tag_name"], "v0.6.0", "release tag")
    _exact(closeout["tag_object_type"], "annotated", "release tag type")
    _exact(closeout["permitted_actions_after_pass"], list(CLOSEOUT_ACTIONS), "permitted closeout action inventory")
    _exact(closeout["additional_product_work_authorized"], False, "additional product work authorization")

    activation = _mapping(scope["activation_requirements"], "activation_requirements")
    _exact_keys(activation, {"required_rebindings", "required_status_transitions", "candidate_validator_must_pass", "all_45_mapped_test_ids_must_pass", "mapped_test_id_skips_allowed", "waivers_allowed"}, "activation requirements")
    _exact(activation["required_rebindings"], list(REQUIRED_REBINDINGS), "required rebinding inventory")
    _exact(activation["required_status_transitions"], REQUIRED_TRANSITIONS, "status transition inventory")
    _exact(activation["candidate_validator_must_pass"], True, "candidate validator requirement")
    _exact(activation["all_45_mapped_test_ids_must_pass"], True, "45-ID pass requirement")
    _exact(activation["mapped_test_id_skips_allowed"], False, "mapped skip policy")
    _exact(activation["waivers_allowed"], False, "waiver policy")

    claims = _mapping(scope["claims"], "claims")
    _exact_keys(claims, {"v0_5_release_accepted", "gate_0a_immutable_authorization_verified", "v0_6_work_packages_implemented", "v0_6_candidate_qualified", "release_closeout_authorized", "v0_6_release_accepted_by_gate", "broad_language_or_compatibility_claimed", "operational_authorization", "deployment_approval", "compliance_determination", "cryptographic_signature_verified"}, "claims")
    _exact(claims["v0_5_release_accepted"], True, "v0.5 release claim")
    _exact(claims["gate_0a_immutable_authorization_verified"], True, "Gate 0A verification claim")
    implemented = state == "PASS"
    for key in ("v0_6_work_packages_implemented", "v0_6_candidate_qualified", "release_closeout_authorized"):
        _exact(claims[key], implemented, f"claims.{key}")
    for key in ("v0_6_release_accepted_by_gate", "broad_language_or_compatibility_claimed", "operational_authorization", "deployment_approval", "compliance_determination", "cryptographic_signature_verified"):
        _exact(claims[key], False, f"claims.{key}")

    _exact(scope["explicit_exclusions"], list(EXCLUSIONS), "explicit exclusion inventory")


def validate_scope(scope: Any) -> str:
    scope = _mapping(scope, "scope")
    _exact_keys(
        scope,
        {
            "schema_version", "gate_id", "status", "target_increment",
            "target_release", "scope_profile", "decision", "immutable_inputs",
            "qualification_contract", "qualified_work_packages",
            "reviewed_surface_delta", "release_closeout_authorization",
            "activation_requirements", "claims", "explicit_exclusions",
        },
        "scope",
    )
    _exact(scope["schema_version"], SCHEMA_VERSION, "scope schema")
    _exact(scope["gate_id"], "V06-GATE-0B", "gate identity")
    _require(scope["status"] in {"PENDING_CANDIDATE", "PASS"}, "gate status is invalid")
    state = scope["status"]
    _exact(scope["target_increment"], "v0.6", "target increment")
    _exact(scope["target_release"], "v0.6.0", "target release")
    _exact(scope["scope_profile"], SCOPE_PROFILE, "scope profile")
    _validate_decision(scope, state)
    _validate_immutable_inputs(scope, state)
    _validate_qualification_contract(scope, state)
    _validate_packages(scope, state)
    _validate_reviewed_delta(scope, state)
    _validate_closeout_and_claims(scope, state)
    return state


def _git(root: Path, arguments: Sequence[str], *, binary: bool = False) -> bytes | str:
    environment = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_REPLACE_REF_BASE"):
        environment.pop(name, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    result = subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    _require(result.returncode == 0, f"Git command failed: {' '.join(arguments)}")
    if binary:
        return result.stdout
    try:
        return result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise GateValidationError("Git identity output is not ASCII") from exc


def _git_blob(root: Path, commit: str, path: str) -> tuple[str, bytes]:
    listing = str(_git(root, ["ls-tree", commit, "--", path]))
    fields = listing.split()
    _require(len(fields) == 4 and fields[1] == "blob" and fields[3] == path, f"Git blob is absent or ambiguous: {path}")
    raw = _git(root, ["cat-file", "blob", fields[2]], binary=True)
    assert isinstance(raw, bytes)
    return fields[2], raw


def _validate_commit(root: Path, commit: str, tree: str, parent: str, label: str) -> None:
    raw = _git(root, ["cat-file", "commit", commit], binary=True)
    assert isinstance(raw, bytes)
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    trees = [line[5:].decode("ascii") for line in headers if line.startswith(b"tree ")]
    parents = [line[7:].decode("ascii") for line in headers if line.startswith(b"parent ")]
    _exact(trees, [tree], f"{label} tree")
    _exact(parents, [parent], f"{label} parent")


def _validate_baseline(root: Path) -> None:
    ref_type = _git(root, ["cat-file", "-t", BASELINE["tag_ref"]])
    _exact(ref_type, "tag", "v0.5.0 tag object type")
    object_id = _git(root, ["rev-parse", BASELINE["tag_ref"]])
    _exact(object_id, BASELINE["tag_object_id"], "v0.5.0 tag object")
    raw_tag = _git(root, ["cat-file", "tag", object_id], binary=True)
    assert isinstance(raw_tag, bytes)
    _exact(sha256_bytes(raw_tag), BASELINE["raw_tag_object_sha256"], "v0.5.0 raw tag hash")
    peeled = _git(root, ["rev-parse", f"{BASELINE['tag_ref']}^{{}}"])
    _exact(peeled, GATE_0A_PARENT, "v0.5.0 peeled commit")
    text = raw_tag.decode("utf-8")
    for marker in REQUIRED_TAG_MARKERS:
        _require(text.splitlines().count(marker) == 1, f"v0.5.0 tag marker differs: {marker}")
    for path, digest in BASELINE["tagged_files_sha256"].items():
        _, raw = _git_blob(root, GATE_0A_PARENT, path)
        _exact(sha256_bytes(raw), digest, f"v0.5.0 tagged file hash: {path}")


def _validate_gate_0a(root: Path) -> None:
    _validate_commit(root, GATE_0A_COMMIT, GATE_0A_TREE, GATE_0A_PARENT, "Gate 0A")
    for path, binding in GATE_FILES.items():
        blob, raw = _git_blob(root, GATE_0A_COMMIT, path)
        _exact(blob, binding["blob"], f"Gate 0A blob: {path}")
        _exact(sha256_bytes(raw), binding["sha256"], f"Gate 0A hash: {path}")
    for path, (expected_blob, digest) in CONTRACT_FILES.items():
        blob, raw = _git_blob(root, GATE_0A_COMMIT, path)
        _exact(blob, expected_blob, f"Gate 0A contract blob: {path}")
        _exact(sha256_bytes(raw), digest, f"Gate 0A contract hash: {path}")

    _, gate_doc = _git_blob(root, GATE_0A_COMMIT, "SPELL_v0.6_Pre-Implementation.md")
    _require(OWNER_MARKER in gate_doc.decode("utf-8").splitlines(), "Gate 0A owner marker is absent")
    _, scope_raw = _git_blob(root, GATE_0A_COMMIT, next(path for path in GATE_FILES if path.endswith("v0.6-gate-0a.json")))
    gate_scope = strict_json_bytes(scope_raw, "committed Gate 0A scope")
    _exact(gate_scope.get("status"), "PASS", "committed Gate 0A status")
    mechanics = _mapping(gate_scope.get("approval_mechanics"), "committed Gate 0A approval mechanics")
    _exact(mechanics.get("pass_validator_marker"), GATE_0A_MARKER, "committed Gate 0A validator marker")
    _exact(mechanics.get("required_owner_approval_marker"), OWNER_MARKER, "committed Gate 0A owner marker")
    _exact(mechanics.get("authorized_work_package_ids"), list(WORK_PACKAGE_TEST_IDS), "committed Gate 0A package authorization")
    packages = gate_scope.get("proposed_work_packages")
    _require(isinstance(packages, list) and len(packages) == 9, "committed Gate 0A package inventory differs")
    for index, package in enumerate(packages):
        item = _mapping(package, f"committed Gate 0A package {index}")
        package_id = list(WORK_PACKAGE_TEST_IDS)[index]
        _exact(item.get("work_package_id"), package_id, f"committed Gate 0A package {index} identity")
        _exact(item.get("status"), "IMPLEMENTATION_AUTHORIZED", f"committed Gate 0A {package_id} status")
        _exact(item.get("planned_test_ids"), list(WORK_PACKAGE_TEST_IDS[package_id]), f"committed Gate 0A {package_id} test IDs")

    _, manifest_raw = _git_blob(root, GATE_0A_COMMIT, "contracts/v06/manifest.json")
    manifest = strict_json_bytes(manifest_raw, "committed v0.6 contract manifest")
    _exact(manifest.get("work_packages"), list(WORK_PACKAGE_TEST_IDS), "contract work-package inventory")
    matrix_paths = [f"contracts/v06/{item['file']}" for item in manifest.get("matrices", [])]
    _exact(matrix_paths, list(CONTRACT_FILES)[1:], "contract matrix inventory")


def parse_name_status_z(raw: bytes) -> list[tuple[str, str]]:
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    _require(len(parts) % 2 == 0, "candidate diff has a malformed name-status stream")
    result: list[tuple[str, str]] = []
    for index in range(0, len(parts), 2):
        try:
            status = parts[index].decode("ascii")
            path = parts[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GateValidationError("candidate diff contains invalid text") from exc
        _require(status in {"A", "M"}, f"candidate diff contains unsupported status: {status}")
        _bounded_path(path, "candidate diff path")
        result.append((status, path))
    _require(result == sorted(set(result), key=lambda item: item[1]), "candidate diff is not unique and sorted")
    return result


def _blob_json(root: Path, commit: str, path: str, label: str) -> dict[str, Any]:
    _, raw = _git_blob(root, commit, path)
    return strict_json_bytes(raw, label)


def _validate_dependency_delta(root: Path, candidate: str) -> None:
    _, base_pyproject = _git_blob(root, GATE_0A_COMMIT, "pyproject.toml")
    _, candidate_pyproject = _git_blob(root, candidate, "pyproject.toml")
    base_toml = tomllib.loads(base_pyproject.decode("utf-8"))
    candidate_toml = tomllib.loads(candidate_pyproject.decode("utf-8"))
    for key in ("dependencies", "optional-dependencies"):
        _exact(candidate_toml.get("project", {}).get(key), base_toml.get("project", {}).get(key), f"Python runtime dependency delta: {key}")

    base_lock = _blob_json(root, GATE_0A_COMMIT, "frontend/package-lock.json", "Gate 0A frontend lock")
    candidate_lock = _blob_json(root, candidate, "frontend/package-lock.json", "candidate frontend lock")
    for key in ("dependencies", "devDependencies"):
        base = _mapping(base_lock.get("packages"), "Gate 0A package-lock packages").get("", {}).get(key)
        current = _mapping(candidate_lock.get("packages"), "candidate package-lock packages").get("", {}).get(key)
        _exact(current, base, f"frontend dependency delta: {key}")


def _migration_new_tables(raw: bytes) -> tuple[str, ...]:
    tree = ast.parse(raw.decode("utf-8"), filename="v0004_operator_workspace.py")
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assignments[node.targets[0].id] = node.value
    version = assignments.get("VERSION")
    _require(isinstance(version, ast.Constant) and version.value == "0004_operator_workspace", "migration version differs")
    new_tables = assignments.get("NEW_TABLES")
    _require(isinstance(new_tables, ast.Tuple), "migration NEW_TABLES is not a literal tuple")
    names: list[str] = []
    for item in new_tables.elts:
        _require(isinstance(item, ast.Name), "migration NEW_TABLES contains a non-name")
        names.append(item.id)
    return tuple(names)


def _validate_candidate_git(root: Path, scope: Mapping[str, Any]) -> None:
    candidate = scope["immutable_inputs"]["candidate"]
    commit = candidate["commit"]
    _validate_commit(root, commit, candidate["tree"], GATE_0A_COMMIT, "candidate")
    raw_diff = _git(root, ["diff-tree", "--no-commit-id", "--name-status", "-r", "-z", GATE_0A_COMMIT, commit], binary=True)
    assert isinstance(raw_diff, bytes)
    observed = parse_name_status_z(raw_diff)
    declared = [(item["status"], item["path"]) for item in candidate["changed_paths"]]
    _exact(observed, declared, "candidate changed-path inventory")
    for item in candidate["changed_paths"]:
        blob, raw = _git_blob(root, commit, item["path"])
        _exact(blob, item["blob"], f"candidate changed-path blob: {item['path']}")
        _exact(sha256_bytes(raw), item["sha256"], f"candidate changed-path hash: {item['path']}")

    for path, binding in GATE_FILES.items():
        blob, raw = _git_blob(root, commit, path)
        _exact(blob, binding["blob"], f"candidate preserved Gate 0A blob: {path}")
        _exact(sha256_bytes(raw), binding["sha256"], f"candidate preserved Gate 0A hash: {path}")
    for path, (expected_blob, digest) in CONTRACT_FILES.items():
        blob, raw = _git_blob(root, commit, path)
        _exact(blob, expected_blob, f"candidate preserved contract blob: {path}")
        _exact(sha256_bytes(raw), digest, f"candidate preserved contract hash: {path}")

    blob, ir03 = _git_blob(root, commit, "backend/ir_v03.py")
    _exact(blob, "87f202e9e3ff192e348c2aea9f7009ea7fc95841", "candidate IR 0.3 blob")
    _exact(sha256_bytes(ir03), "2726774ed5873e0c0c1eeaffa7b3713c708ac7f61a6fa93e544a8dbc8c79963c", "candidate IR 0.3 hash")
    _, ir06 = _git_blob(root, commit, "backend/ir_v06.py")
    _require('\nIR_VERSION = "0.6"\n' in ir06.decode("utf-8"), "candidate internal IR 0.6 identity differs")

    _, app = _git_blob(root, commit, "backend/app.py")
    app_text = app.decode("utf-8")
    for marker in API_ROUTE_MARKERS:
        _require(marker in app_text, f"candidate operator API route is absent: {marker}")
    _, schemas = _git_blob(root, commit, "backend/schemas.py")
    schemas_text = schemas.decode("utf-8")
    _require("class StrictRequest(BaseModel):" in schemas_text and "extra=\"forbid\"" in schemas_text, "candidate strict request schema boundary differs")
    _git_blob(root, commit, "backend/operator_service.py")

    _, migration = _git_blob(root, commit, "backend/migrations/versions/v0004_operator_workspace.py")
    _exact(_migration_new_tables(migration), NEW_TABLES, "candidate migration table inventory")
    _validate_dependency_delta(root, commit)

    _, gateway = _git_blob(root, commit, "backend/driver_gateway.py")
    _, host_config = _git_blob(root, commit, "driver_host/config.py")
    _require('EXPECTED_IMPLEMENTATION_VERSION = "0.4.0"' in gateway.decode("utf-8"), "driver gateway version changed")
    _require('implementation_version: str = "0.4.0"' in host_config.decode("utf-8"), "driver host version changed")


def _validate_manifest_contract(manifest: Mapping[str, Any], candidate: str) -> None:
    _exact(manifest.get("schema_version"), EVIDENCE_SCHEMA, "candidate evidence schema")
    _exact(manifest.get("product_version"), "0.6.0-candidate", "candidate evidence product version")
    _exact(manifest.get("scope_profile"), SCOPE_PROFILE, "candidate evidence scope profile")
    _exact(manifest.get("overall_pass"), True, "candidate evidence overall result")
    source = _mapping(manifest.get("source"), "candidate evidence source")
    _exact(source.get("commit"), candidate, "candidate evidence source commit")
    suites = _mapping(manifest.get("suites"), "candidate evidence suites")
    _exact(tuple(suites), SUITE_IDS, "candidate evidence suite inventory")
    packages = _mapping(manifest.get("work_packages"), "candidate evidence work packages")
    _exact(tuple(packages), tuple(WORK_PACKAGE_TEST_IDS), "candidate evidence package inventory")
    for package, identities in WORK_PACKAGE_TEST_IDS.items():
        result = _mapping(packages[package], f"candidate evidence {package}")
        test_ids = _mapping(result.get("test_ids"), f"candidate evidence {package}.test_ids")
        _exact(tuple(test_ids), identities, f"candidate evidence {package} identity inventory")
        for identity in identities:
            proof = _mapping(test_ids[identity], f"candidate evidence {identity}")
            _exact_keys(proof, {"proofs", "passed_count", "skipped_count"}, f"candidate evidence {identity}")
            _require(isinstance(proof["proofs"], list) and bool(proof["proofs"]), f"candidate evidence {identity} has no proof")
            _exact(proof["passed_count"], len(proof["proofs"]), f"candidate evidence {identity} pass count")
            _exact(proof["skipped_count"], 0, f"candidate evidence {identity} skip count")
    historical = _mapping(manifest.get("historical_platform_skips"), "candidate evidence skip record")
    _exact(historical.get("mapped_test_ids_skipped"), [], "mapped identity skip record")
    _exact(historical.get("accepted_failures"), [], "accepted failure record")
    scan = _mapping(manifest.get("secret_scan"), "candidate evidence secret scan")
    _exact(scan.get("waivers"), [], "candidate evidence secret-scan waivers")


def _run_candidate_validator(
    root: Path,
    evidence: Path,
    validator: Path,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    _require(platform.python_version() == "3.13.14", "Gate 0B PASS requires locked CPython 3.13.14")
    _require(evidence.is_file() and not evidence.is_symlink(), "canonical candidate evidence is missing or unsafe")
    _require(validator.is_file() and not validator.is_symlink(), "candidate validator is missing or unsafe")
    raw = evidence.read_bytes()
    digest = sha256_bytes(raw)
    manifest = strict_json_bytes(raw, "canonical candidate evidence")

    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME"):
        environment.pop(name, None)
    result = subprocess.run(
        [sys.executable, str(validator), "--root", str(root)],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        check=False,
    )
    _require(result.returncode == 0, "candidate-evidence validator did not pass")
    _require(result.stderr == b"", "candidate-evidence validator wrote stderr on success")
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise GateValidationError("candidate-evidence validator output is not UTF-8") from exc
    _require(len(lines) == 1, "candidate-evidence validator did not emit exactly one line")
    summary = strict_json_bytes(lines[0].encode("utf-8"), "candidate-evidence validator output")
    _exact_keys(summary, {"gate", "schema_version", "source_commit", "suites", "test_ids", "tests", "evidence_sha256"}, "candidate-evidence validator output")
    _exact(summary["gate"], "PASS", "candidate-evidence validator gate")
    _exact(summary["schema_version"], EVIDENCE_SCHEMA, "candidate-evidence validator schema")
    _require(HEX40.fullmatch(str(summary["source_commit"])) is not None, "candidate-evidence validator source is invalid")
    _exact(summary["suites"], 10, "candidate-evidence validator suite count")
    _exact(summary["test_ids"], 45, "candidate-evidence validator identity count")
    _require(type(summary["tests"]) is int and summary["tests"] >= 1, "candidate-evidence validator test count is invalid")
    _exact(summary["evidence_sha256"], digest, "candidate-evidence validator digest")
    _validate_manifest_contract(manifest, summary["source_commit"])
    return manifest, summary, digest


def run_evidence_validator(root: Path, scope: Mapping[str, Any]) -> None:
    evidence = root / scope["qualification_contract"]["manifest_path"]
    validator = root / scope["qualification_contract"]["validator_path"]
    _, summary, digest = _run_candidate_validator(root, evidence, validator)
    candidate = scope["immutable_inputs"]["candidate"]["commit"]
    _exact(digest, scope["qualification_contract"]["manifest_sha256"], "canonical candidate evidence hash")
    _exact(summary["source_commit"], candidate, "candidate-evidence validator source")


def _candidate_changed_paths(
    root: Path,
    parent: str,
    commit: str,
) -> list[dict[str, str]]:
    raw_diff = _git(
        root,
        ["diff-tree", "--no-commit-id", "--name-status", "-r", "-z", parent, commit],
        binary=True,
    )
    assert isinstance(raw_diff, bytes)
    changes = parse_name_status_z(raw_diff)
    _require(bool(changes), "candidate commit has no changed paths")
    result: list[dict[str, str]] = []
    for status, path in changes:
        blob, raw = _git_blob(root, commit, path)
        result.append(
            {
                "path": path,
                "status": status,
                "blob": blob,
                "sha256": sha256_bytes(raw),
            }
        )
    return result


def activate_scope_bindings(
    pending_scope: Mapping[str, Any],
    *,
    candidate_commit: str,
    candidate_tree: str,
    changed_paths: Sequence[Mapping[str, str]],
    evidence_sha256: str,
) -> dict[str, Any]:
    _exact(validate_scope(pending_scope), "PENDING_CANDIDATE", "activation source state")
    _require(HEX40.fullmatch(candidate_commit) is not None, "activation candidate commit is invalid")
    _require(HEX40.fullmatch(candidate_tree) is not None, "activation candidate tree is invalid")
    _require(HEX64.fullmatch(evidence_sha256) is not None, "activation evidence hash is invalid")
    scope = copy.deepcopy(dict(pending_scope))
    scope["status"] = "PASS"
    scope["decision"]["authorization"] = (
        "V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY"
    )
    scope["immutable_inputs"]["candidate"] = {
        "binding_status": "BOUND",
        "commit": candidate_commit,
        "parent": GATE_0A_COMMIT,
        "tree": candidate_tree,
        "changed_paths": [dict(item) for item in changed_paths],
    }
    qualification = scope["qualification_contract"]
    qualification["status"] = "PASS"
    qualification["manifest_sha256"] = evidence_sha256
    qualification["validator_success_shape"]["source_commit"] = candidate_commit
    for package in scope["qualified_work_packages"]:
        package["status"] = "IMPLEMENTED_AND_QUALIFIED"
    scope["reviewed_surface_delta"]["review_status"] = "REVIEWED_AND_QUALIFIED"
    scope["release_closeout_authorization"]["status"] = "AUTHORIZED"
    for key in (
        "v0_6_work_packages_implemented",
        "v0_6_candidate_qualified",
        "release_closeout_authorized",
    ):
        scope["claims"][key] = True
    _exact(validate_scope(scope), "PASS", "prepared activation state")
    return scope


def canonical_scope_bytes(scope: Mapping[str, Any]) -> bytes:
    validate_scope(scope)
    return (json.dumps(scope, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def prepare_activation(root: Path, scope_path: Path) -> dict[str, Any]:
    pending = read_json(scope_path, "pending Gate 0B scope")
    _exact(validate_scope(pending), "PENDING_CANDIDATE", "activation source state")
    evidence = root / pending["qualification_contract"]["manifest_path"]
    validator = root / pending["qualification_contract"]["validator_path"]
    _, summary, digest = _run_candidate_validator(root, evidence, validator)
    candidate = summary["source_commit"]
    _exact(str(_git(root, ["rev-parse", "HEAD"])), candidate, "activation HEAD")
    _exact(
        str(_git(root, ["status", "--porcelain", "--untracked-files=no"])),
        "",
        "activation tracked worktree",
    )
    tree = str(_git(root, ["rev-parse", f"{candidate}^{{tree}}"] ))
    _validate_commit(root, candidate, tree, GATE_0A_COMMIT, "activation candidate")
    changed_paths = _candidate_changed_paths(root, GATE_0A_COMMIT, candidate)
    activated = activate_scope_bindings(
        pending,
        candidate_commit=candidate,
        candidate_tree=tree,
        changed_paths=changed_paths,
        evidence_sha256=digest,
    )
    _validate_candidate_git(root, activated)
    run_evidence_validator(root, activated)
    return activated


def _write_atomic(path: Path, payload: bytes, token: str) -> None:
    temporary = path.with_name(f".{path.name}.activation-{token}.tmp")
    _require(not temporary.exists() and not temporary.is_symlink(), "activation temporary path exists")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def apply_activation(
    root: Path,
    scope_path: Path,
    proposal_path: Path,
) -> dict[str, Any]:
    canonical_scope = (
        root
        / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
        / "requirements"
        / "compatibility"
        / "scopes"
        / "v0.6-gate-0b.json"
    ).resolve()
    _exact(scope_path.resolve(), canonical_scope, "activation canonical scope path")
    _require(
        proposal_path.is_file() and not proposal_path.is_symlink(),
        "activation proposal is missing or unsafe",
    )
    proposal_raw = proposal_path.read_bytes()
    proposal = strict_json_bytes(proposal_raw, "activation proposal")
    _exact(validate_scope(proposal), "PASS", "activation proposal state")
    prepared = prepare_activation(root, scope_path)
    prepared_raw = canonical_scope_bytes(prepared)
    _exact(proposal, prepared, "activation proposal bindings")
    _exact(proposal_raw, prepared_raw, "activation proposal canonical bytes")

    candidate = prepared["immutable_inputs"]["candidate"]["commit"]
    target_paths = (
        scope_path,
        root / "SPELL_v0.6_Gate_0B.md",
        root / "SPELL_v0.6_Release.md",
    )
    for target in target_paths:
        _require(target.is_file() and not target.is_symlink(), "activation target is missing or unsafe")
    targets = tuple(target.resolve() for target in target_paths)
    for target in targets:
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise GateValidationError("activation target escapes the repository") from exc
        relative = target.relative_to(root).as_posix()
        _, committed = _git_blob(root, candidate, relative)
        _exact(target.read_bytes(), committed, f"activation target differs from candidate: {relative}")

    gate_raw, release_raw = render_activation_documents(targets[1], targets[2], prepared)
    replacements = {
        targets[0]: prepared_raw,
        targets[1]: gate_raw,
        targets[2]: release_raw,
    }
    originals = {path: path.read_bytes() for path in replacements}
    lock = (root / ACTIVATION_LOCK_RELATIVE).resolve()
    _require(lock.parent == canonical_scope.parent, "activation lock path escapes scope directory")
    lock_descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    token = uuid.uuid4().hex
    try:
        with os.fdopen(lock_descriptor, "w", encoding="ascii", newline="\n") as stream:
            lock_descriptor = -1
            stream.write(f"{token}\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            for path, payload in replacements.items():
                _write_atomic(path, payload, token)
            state, activated = validate_repository(scope_path, root)
            _exact(state, "PASS", "applied activation repository state")
            _exact(activated, prepared, "applied activation scope")
            validate_release_document(targets[2], prepared)
        except BaseException:
            rollback_errors: list[str] = []
            for path, payload in originals.items():
                try:
                    _write_atomic(path, payload, f"rollback-{token}")
                except Exception as exc:
                    rollback_errors.append(f"{path}: {exc}")
            if rollback_errors:
                raise GateValidationError(
                    "activation failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                )
            raise
    finally:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        if lock.exists() or lock.is_symlink():
            lock.unlink()

    return {
        "activation": "APPLIED",
        "candidate_commit": candidate,
        "evidence_sha256": prepared["qualification_contract"]["manifest_sha256"],
        "scope_sha256": sha256_bytes(prepared_raw),
        "gate_document_sha256": sha256_bytes(gate_raw),
        "release_document_sha256": sha256_bytes(release_raw),
    }


def validate_gate_document(
    path: Path,
    state: str,
    scope: Mapping[str, Any] | None = None,
) -> None:
    text, _ = _normalized_document(path, "Gate 0B document")
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), "")
    _exact(first, "# SPELL v0.6 Gate 0B Release Closeout", "Gate 0B document heading")
    common = (
        f"Owner request: `{OWNER_REQUEST}`",
        "Release acceptance by Gate 0B: No",
        "Operational authorization: None",
    )
    if state == "PENDING_CANDIDATE":
        state_markers = (
            "Gate 0B decision: `PENDING_CANONICAL_V06_CANDIDATE_QUALIFICATION`",
            "Release closeout authorization: `NOT_YET_AUTHORIZED`",
        )
    else:
        state_markers = (
            "Gate 0B decision: `V06_OP_001_THROUGH_V06_OP_009_RELEASE_CLOSEOUT_ONLY`",
            "Release closeout authorization: `AUTHORIZED`",
        )
    for marker in (*common, *state_markers):
        _require(lines.count(marker) == 1, f"Gate 0B document marker differs: {marker}")
    if scope is not None:
        for markers, expected, label in (
            (GATE_RECORD_MARKERS, _gate_record_body(scope), "Gate 0B activation record"),
            (GATE_PACKAGE_MARKERS, _gate_package_body(state), "Gate 0B package dispositions"),
            (GATE_FINDING_MARKERS, _gate_finding_body(state), "Gate 0B current finding"),
        ):
            _exact(_marked_body(text, markers, label), expected, label)


def validate_release_document(path: Path, scope: Mapping[str, Any]) -> None:
    text, _ = _normalized_document(path, "v0.6 release document")
    state = scope["status"]
    _exact(
        next((line for line in text.splitlines() if line.strip()), ""),
        "# SPELL v0.6.0 Release Record",
        "v0.6 release document heading",
    )
    scope_sha256 = sha256_bytes(canonical_scope_bytes(scope))
    for markers, expected, label in (
        (RELEASE_RECORD_MARKERS, _release_record_body(scope), "release conditional record"),
        (RELEASE_EVIDENCE_MARKERS, _release_evidence_body(scope, scope_sha256), "release evidence bindings"),
        (RELEASE_FINDING_MARKERS, _release_finding_body(state), "release current finding"),
    ):
        _exact(_marked_body(text, markers, label), expected, label)


def validate_repository(scope_path: Path = SCOPE_PATH, root: Path = WORKSPACE_ROOT) -> tuple[str, dict[str, Any]]:
    root = root.resolve()
    scope = read_json(scope_path, "Gate 0B scope")
    state = validate_scope(scope)
    _validate_baseline(root)
    _validate_gate_0a(root)
    validate_gate_document(root / "SPELL_v0.6_Gate_0B.md", state, scope)
    validate_release_document(root / "SPELL_v0.6_Release.md", scope)
    if state == "PASS":
        _validate_candidate_git(root, scope)
        run_evidence_validator(root, scope)
    return state, scope


def marker(state: str) -> str:
    return (
        f"gate={'PASS' if state == 'PASS' else 'PENDING'} "
        "work_packages=9 identities=45 failed=0 skipped=0 "
        "claimed_constructs=0 claimed_artifacts=0 "
        f"release_closeout={'AUTHORIZED' if state == 'PASS' else 'DENIED'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--scope", type=Path, default=None)
    activation = parser.add_mutually_exclusive_group()
    activation.add_argument(
        "--prepare-activation",
        type=Path,
        metavar="OUTPUT",
        help=(
            "validate canonical candidate evidence and write a new, noncanonical "
            "fully bound scope proposal; never overwrites the canonical scope"
        ),
    )
    activation.add_argument(
        "--apply-activation",
        type=Path,
        metavar="PROPOSAL",
        help=(
            "verify a canonical prepared proposal and atomically activate the "
            "canonical scope, Gate 0B record, and conditional release record"
        ),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    scope = args.scope or (
        root
        / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
        / "requirements"
        / "compatibility"
        / "scopes"
        / "v0.6-gate-0b.json"
    )
    try:
        if args.prepare_activation is not None:
            output = args.prepare_activation.resolve()
            _require(output != scope.resolve(), "activation output must not replace the canonical scope")
            _require(not output.exists() and not output.is_symlink(), "activation output already exists or is unsafe")
            _require(output.parent.is_dir() and not output.parent.is_symlink(), "activation output parent is missing or unsafe")
            activated = prepare_activation(root, scope)
            payload = canonical_scope_bytes(activated)
            with output.open("xb") as stream:
                stream.write(payload)
            print(
                json.dumps(
                    {
                        "activation": "READY",
                        "candidate_commit": activated["immutable_inputs"]["candidate"]["commit"],
                        "evidence_sha256": activated["qualification_contract"]["manifest_sha256"],
                        "output": str(output),
                        "scope_sha256": sha256_bytes(payload),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if args.apply_activation is not None:
            result = apply_activation(root, scope, args.apply_activation.resolve())
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        state, _ = validate_repository(scope, root)
        print(marker(state))
        return 0 if state == "PASS" else 2
    except (GateValidationError, OSError, subprocess.SubprocessError, tomllib.TOMLDecodeError) as exc:
        print(
            "gate=FAIL work_packages=0 identities=0 failed=1 skipped=0 "
            "claimed_constructs=0 claimed_artifacts=0 release_closeout=DENIED"
        )
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
