#!/usr/bin/env python3
"""Validate the evidence-bound SPELL v0.7 Gate 0B closeout decision."""

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
    / "v0.7-gate-0b.json"
)
GATE_DOCUMENT_PATH = WORKSPACE_ROOT / "SPELL_v0.7_Gate_0B.md"
RELEASE_DOCUMENT_PATH = WORKSPACE_ROOT / "SPELL_v0.7_Release.md"
EVIDENCE_PATH = WORKSPACE_ROOT / "artifacts/v0.7/work-package/qualification.json"
EVIDENCE_VALIDATOR_PATH = WORKSPACE_ROOT / "scripts/validate_candidate_evidence_v07.py"
ACTIVATION_LOCK_RELATIVE = Path(
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/scopes/"
    ".v0.7-gate-0b-activation.lock"
)

SCHEMA_VERSION = "ng-spell-v07-gate-0b-scope/1"
EVIDENCE_SCHEMA = "spell.v07.candidate-qualification/1"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
GATE_0A_COMMIT = "07c19437d28bc32a88d9970a4104d6c0fde53073"
GATE_0A_PARENT = "05ec783a6e54a76e0548bdd536c18538f6bff51b"
GATE_0A_TREE = "ad9487e0ba32c9a42fbbdaa1f9e7bce964674680"
GATE_0A_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_MARKER = "V07-GATE-0A OWNER-APPROVAL: APPROVED"
OWNER_REQUEST = (
    "resume and finish up asap v0.6 asap and move forward to finis up v0.7 "
    "asap. you have all aprrovals."
)

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 4 * 1024 * 1024

GATE_RECORD_MARKERS = (
    "<!-- V07_GATE_0B_ACTIVATION_RECORD_BEGIN -->",
    "<!-- V07_GATE_0B_ACTIVATION_RECORD_END -->",
)
GATE_PACKAGE_MARKERS = (
    "<!-- V07_GATE_0B_PACKAGE_DISPOSITIONS_BEGIN -->",
    "<!-- V07_GATE_0B_PACKAGE_DISPOSITIONS_END -->",
)
GATE_FINDING_MARKERS = (
    "<!-- V07_GATE_0B_CURRENT_FINDING_BEGIN -->",
    "<!-- V07_GATE_0B_CURRENT_FINDING_END -->",
)
RELEASE_RECORD_MARKERS = (
    "<!-- V07_RELEASE_CONDITIONAL_RECORD_BEGIN -->",
    "<!-- V07_RELEASE_CONDITIONAL_RECORD_END -->",
)
RELEASE_EVIDENCE_MARKERS = (
    "<!-- V07_RELEASE_EVIDENCE_BINDINGS_BEGIN -->",
    "<!-- V07_RELEASE_EVIDENCE_BINDINGS_END -->",
)
RELEASE_FINDING_MARKERS = (
    "<!-- V07_RELEASE_CURRENT_FINDING_BEGIN -->",
    "<!-- V07_RELEASE_CURRENT_FINDING_END -->",
)

WORK_PACKAGE_TEST_IDS: dict[str, tuple[str, ...]] = {
    "V07-OBS-001": (
        "V07-OBS-001-UNIT", "V07-OBS-001-CONTRACT",
        "V07-OBS-001-CLOCK", "V07-OBS-001-RECOVERY", "V07-OBS-001-SECURITY",
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
        "V07-OBS-008-UNIT", "V07-OBS-008-INTEGRATION", "V07-OBS-008-BACKPRESSURE",
        "V07-OBS-008-RECONNECT", "V07-OBS-008-SECURITY",
    ),
    "V07-OBS-009": (
        "V07-OBS-009-SEMANTIC-GOLDEN", "V07-OBS-009-BROWSER",
        "V07-OBS-009-ACCESSIBILITY", "V07-OBS-009-FAULT-RECOVERY",
        "V07-OBS-009-LOAD-SECURITY",
    ),
}
TEST_IDS = tuple(item for values in WORK_PACKAGE_TEST_IDS.values() for item in values)

SUITE_IDS = (
    "backend_sqlite",
    "backend_postgresql",
    "backend_docker_host",
    "backend_v07_soak",
    "driver_host",
    "tooling",
    "frontend_vitest",
    "frontend_build",
    "frontend_playwright_mocked",
    "frontend_playwright_live",
)

GATE_FILES = {
    "SPELL_v0.7_Pre-Implementation.md": {
        "blob": "b497089a21807eadcc8b78c6491ad6b0f4d7bc49",
        "sha256": "b09ebd5505923f9321c523ed9c82bbe51f58ddb56c98f90f5d8ddc056da9fead",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.7-gate-0a.json"
    ): {
        "blob": "4c08129e6dbefe71f374754e7bd6aad63e170f77",
        "sha256": "af669f150a9bf8c2878f1692629cba78818ba1e4eecf3d16d8159d63d0eec710",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v07_gate_0a.py"
    ): {
        "blob": "bb92f56e0145fd3bef52a879c78b5cd107b9a8dd",
        "sha256": "4411a41291256a59f58d0a0ad9175fcbaac27aedf96d6b6dbd35675028be193d",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v07_gate_0a.py"
    ): {
        "blob": "9af52ceca2152e4576d41a5a0e427c5f073bb490",
        "sha256": "c414de6b4cb959bd31551635d5c4fb636152776ff6c3369b8b1e02afce23b27f",
    },
}

CONTRACT_FILES = {
    "contracts/v07/manifest.json": (
        "3d372b76742cd72007b7fe780b275bb5a1adcb76",
        "df1c8060cf6ec8259d2949ac6ec14f7aebca7ceba041bb274fdbec6c354d1a7d",
    ),
    "contracts/v07/time_and_sample_identity.json": (
        "845f4fc90dd88730db6de10ff43b7a9d389de32d",
        "08a36552d311c6cb6297a493197480a5fbe2df0153ac4e4c63ddf9c0d66d58cd",
    ),
    "contracts/v07/condition_engine.json": (
        "69110362c02950c9b2792db72d2c75a19995b0ae",
        "5373bbe93f0b19656cd266dc0341f03df11e02e4e7a1038e8b64ff30a253ef1b",
    ),
    "contracts/v07/waitfor_and_scheduling.json": (
        "b83821ed27ef9104ef293734cca176ccae354f42",
        "53cfb3d168765495ee46b2383dfd14dca79154ac59eed3fd857953cf14119f79",
    ),
    "contracts/v07/resource_and_lookup_reads.json": (
        "c6f6ec515992d113b546a6ab8d54c6f7a6b52d48",
        "07c93d6960f312eb8c31832f455ae874ac6b54b05cbc85df038f5acd8be16eb8",
    ),
    "contracts/v07/limits_and_alarm_state.json": (
        "92204d500d1fb50c7bf4a0770affee51f1989e97",
        "e42c7da301fb340f0e8cada67806a620194802f77658bc8029df2857a0cf4977",
    ),
    "contracts/v07/cursor_streams.json": (
        "099258734583e8d4c9fc6bdc0d9c921751a9c6c8",
        "e18f62e3cb949ddeab7c0533712d0f6666f6b9eef59b78e6255bd3c963a41c8d",
    ),
}

BASELINE = {
    "tag_ref": "refs/tags/v0.6.0",
    "tag_object_type": "tag",
    "tag_object_id": "b6dc64dc8fb6cfe9845f454904a078ec6f3c0919",
    "raw_tag_object_sha256": "b08b3e66b0018a6f559b696cdd478b639f5ecbabc750b9049c85a8f8a17dd8a4",
    "peeled_release_commit": GATE_0A_PARENT,
    "qualified_source_commit": "8d9db4b6acc443ca6309cdfb12b5d4f9b2fef213",
    "tagged_files_sha256": {
        "SPELL_v0.6_Release.md": (
            "9eb9121470f7cdf097f55917bdcead7748b0257209ff8adfa957d7ca1bb4a7da"
        ),
        (
            "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
            "scopes/v0.6-gate-0b.json"
        ): "0deef3794c7dd34ef9995f95d33f2688aebfa198b96579e655273603555205bc",
        "artifacts/v0.6/release-qualification.json": (
            "cbff6f30fca8708260a0a94bf60f3834455dee9cfa2021b5ae4dd2ec83b4c98f"
        ),
    },
}

MIGRATION_TABLES = {
    "0005_observation_projection": (
        "observation_streams",
        "observation_freshness_policies",
        "driver_time_observations",
        "driver_time_heads",
        "telemetry_samples",
        "telemetry_item_heads",
        "telemetry_source_cursors",
        "telemetry_gaps",
        "telemetry_limit_sets",
        "telemetry_limit_heads",
        "telemetry_alarm_observations",
        "telemetry_alarm_heads",
        "observation_outbox",
    ),
    "0006_observation_conditions": (
        "condition_plans",
        "condition_evaluations",
        "condition_evaluation_samples",
        "verify_operations",
        "waitfor_operations",
        "telemetry_condition_schedules",
        "telemetry_schedule_occurrences",
    ),
}

CONDITION_MIGRATION_MODELS = (
    "ConditionPlanRecord",
    "ConditionEvaluationRecord",
    "ConditionEvaluationSample",
    "VerifyOperation",
    "WaitForOperation",
    "TelemetryConditionSchedule",
    "TelemetryScheduleOccurrence",
)

API_ROUTE_MARKERS = (
    '"/api/v1/observation-catalog"',
    '"/api/v1/resources/{resource_id}"',
    '"/api/v1/memory-lookup"',
    '"/api/v1/tmtc-lookup"',
    '"/api/v1/observation-limits/{item_id}"',
    '"/api/v1/telemetry/snapshot"',
    '"/api/v1/telemetry/{item_id}/limits"',
    '"/api/v1/telemetry/{item_id}/alarm"',
    '"/api/v1/telemetry-events/ws"',
)

ROUTE_FAMILIES = (
    "OBSERVATION_CATALOG_AND_TYPED_RESOURCE_LOOKUPS",
    "TELEMETRY_SNAPSHOT_LIMIT_AND_ALARM_READS",
    "CURSOR_STREAMS_AND_GAP_RESYNCHRONIZATION",
    "DECLARATIVE_VERIFY_AND_WAITFOR",
    "TELEMETRY_CONDITION_SCHEDULING",
    "READ_ONLY_FRONTEND_OBSERVATION_PROJECTION",
)

CLOSEOUT_ACTIONS = (
    "RECORD_V07_OBS_001_THROUGH_V07_OBS_009_IMPLEMENTED",
    "PUBLISH_CANONICAL_FINAL_QUALIFICATION_EVIDENCE_AND_HASHES",
    "UPDATE_RELEASE_VERSION_PROVENANCE_HISTORY_AND_TEST_RECORDS",
    "CREATE_VERSION_SCOPED_SBOMS_AND_SUPPLY_CHAIN_EVIDENCE",
    "CREATE_DETERMINISTIC_V0_7_RELEASE_PACKAGE",
    "COMMIT_RELEASE_CLOSEOUT",
    "CREATE_ONE_ANNOTATED_V0_7_0_TAG",
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
    "/decision/authorization": "V07_OBS_001_THROUGH_V07_OBS_009_RELEASE_CLOSEOUT_ONLY",
    "/immutable_inputs/candidate/binding_status": "BOUND",
    "/qualification_contract/status": "PASS",
    "/reviewed_surface_delta/review_status": "REVIEWED_AND_QUALIFIED",
    "/release_closeout_authorization/status": "AUTHORIZED",
    "/qualified_work_packages/*/status": "IMPLEMENTED_AND_QUALIFIED",
}

EXCLUSIONS = (
    "SCOPE_BEYOND_V07_OBS_001_THROUGH_V07_OBS_009",
    "NON_LOCAL_NON_SYNTHETIC_CUI_CLASSIFIED_PRODUCTION_OR_OPERATIONAL_DATA",
    "LIVE_GCS_SPACECRAFT_MISSION_NETWORK_TELEMETRY_TELECOMMAND_OR_EXTERNAL_EFFECT_ROUTE",
    "HOST_CLOCK_REPRESENTED_AS_DRIVER_OR_GCS_TIME_OR_HIDDEN_TIME_UNCERTAINTY",
    "TELEMETRY_RESOURCE_LOOKUP_LIMIT_OR_ALARM_MUTATION",
    "ARBITRARY_CODE_SOURCE_EXPRESSION_FUNCTION_SHELL_OR_GENERIC_FILTER_EVALUATION",
    "UNBOUNDED_QUERY_SUBSCRIPTION_BUFFER_CURSOR_RETRY_OR_CONDITION_GRAPH",
    "CONTINUITY_ACROSS_UNACKNOWLEDGED_GAP_OR_SUCCESS_FROM_STALE_INVALID_MISSING_OR_UNCERTAIN_DATA",
    "UNREVIEWED_IR_LANGUAGE_API_SCHEMA_DEPENDENCY_MIGRATION_OR_COMPATIBILITY_CHANGE",
    "IMPLEMENTATION_OUTSIDE_EXACT_AUTHORIZED_WORK_PACKAGE_AND_CONTRACT_BOUNDARIES",
    "LIGHTWEIGHT_SECONDARY_OR_V0_7_ALIAS_TAG",
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
        gate_status = "`PASS`; exact v0.7 release closeout authorized"
        candidate_value = (
            f"Commit `{candidate['commit']}`; tree `{candidate['tree']}`; "
            f"sole parent `{candidate['parent']}`"
        )
        evidence_value = (
            f"`{qualification['manifest_path']}`; SHA-256 "
            f"`{qualification['manifest_sha256']}`"
        )
        decision = "V07_OBS_001_THROUGH_V07_OBS_009_RELEASE_CLOSEOUT_ONLY"
        authorization = "AUTHORIZED"
    else:
        gate_status = "`PENDING_CANDIDATE`; no release closeout authorization yet"
        candidate_value = "Pending source freeze"
        evidence_value = (
            "Pending at `artifacts/v0.7/work-package/qualification.json`"
        )
        decision = "PENDING_CANONICAL_V07_CANDIDATE_QUALIFICATION"
        authorization = "NOT_YET_AUTHORIZED"
    return "\n".join(
        (
            "## Document Control",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Version target | SPELL v0.7.0 |",
            "| Gate | `V07-GATE-0B` |",
            f"| Gate status | {gate_status} |",
            "| Record date | 2026-08-16 |",
            f"| Accepted product baseline | Annotated tag `v0.6.0`; release commit `{GATE_0A_PARENT}` |",
            f"| Gate 0A authorization | Commit `{GATE_0A_COMMIT}`; `V07-OBS-001` through `V07-OBS-009` |",
            f"| Candidate source | {candidate_value} |",
            f"| Canonical candidate evidence | {evidence_value} |",
            "| Required result inventory | Nine work packages; 45 exact test identities; zero mapped skips, failures, accepted failures, or waivers |",
            "| Release tag requested | One annotated semantic-version tag: `v0.7.0` |",
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
            "`V07-GATE-0B PASS` authorizes release closeout for exactly "
            "`V07-OBS-001` through `V07-OBS-009`. It does not itself accept the "
            "release, authorize deployment or operational use, or make a compliance "
            "or cryptographic-signature claim."
        )
    return (
        "`V07-GATE-0B PENDING_CANDIDATE` records the exact release-closeout contract but\n"
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
            "| Version | SPELL v0.7.0 |",
            "| Release name | Read-Only Observation and Condition Engine |",
            f"| Record state | {record_state} |",
            "| Scope | `V07-OBS-001` through `V07-OBS-009` only |",
            "| Accepted baseline | SPELL v0.6.0, annotated tag `v0.6.0` |",
            f"| Gate 0A | `PASS` at commit `{GATE_0A_COMMIT}` |",
            f"| Gate 0B | {gate_state} |",
            f"| Candidate source commit | {candidate_commit} |",
            "| Final qualified source commit | Pending |",
            "| Release commit | Pending |",
            "| Release tag | Pending annotated tag `v0.7.0` |",
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
            f"| Candidate qualification | `artifacts/v0.7/work-package/qualification.json` | {candidate_value} |",
            f"| Gate 0B machine scope | `.../scopes/v0.7-gate-0b.json` | {gate_value} |",
            "| Final qualification | `artifacts/v0.7/final/qualification.json` | Pending |",
            "| Release qualification manifest | `artifacts/v0.7/release-qualification.json` | Pending |",
            "| Backend SBOM | `artifacts/v0.7/sbom/backend.cdx.json` | Pending |",
            "| Frontend SBOM | `artifacts/v0.7/sbom/frontend.cdx.json` | Pending |",
            "| Driver SBOM | `artifacts/v0.7/sbom/driver.cdx.json` | Pending |",
            "| Proxy SBOM | `artifacts/v0.7/sbom/proxy.cdx.json` | Pending |",
            "| Supply-chain result | `artifacts/v0.7/supply-chain.json` | Pending |",
            "| Deterministic archive | `artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz` | Pending |",
            "| Archive sidecar | `artifacts/v0.7/openbexi-spell-v0.7.0.tar.gz.sha256` | Pending |",
            "| Release commit | Git commit | Pending |",
            "| Annotated tag object | `refs/tags/v0.7.0` | Pending |",
        )
    )


def _release_finding_body(state: str) -> str:
    if state == "PASS":
        return (
            "Gate 0B has passed for the exact nine-package v0.7 candidate, but SPELL "
            "v0.7.0 is not yet accepted by this record. Final qualification, supply-chain "
            "evidence, deterministic packaging, the release commit, annotated tag, and "
            "strict post-tag verification remain pending."
        )
    return (
        "SPELL v0.7.0 is not yet accepted by this record. Gate 0B activation, final\n"
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
        release_path, "v0.7 release document"
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
    _exact(decision["decision_date"], "2026-08-16", "decision.decision_date")
    _exact(decision["owner_request"], OWNER_REQUEST, "decision.owner_request")
    _exact(
        decision["gate_0a_owner_approval_reaffirmed"], True,
        "decision.gate_0a_owner_approval_reaffirmed",
    )
    _exact(
        decision["tag_resolution"],
        "REQUESTED_V0_7_RESOLVES_TO_ONE_ANNOTATED_SEMVER_TAG_V0_7_0",
        "decision.tag_resolution",
    )
    _exact(
        decision["precondition"],
        "CANONICAL_V07_CANDIDATE_QUALIFICATION_AND_GATE_0B_VALIDATOR_PASS",
        "decision.precondition",
    )
    expected = (
        "PENDING_V07_OBS_001_THROUGH_V07_OBS_009_RELEASE_CLOSEOUT"
        if state == "PENDING_CANDIDATE"
        else "V07_OBS_001_THROUGH_V07_OBS_009_RELEASE_CLOSEOUT_ONLY"
    )
    _exact(decision["authorization"], expected, "decision.authorization")


def _validate_immutable_inputs(scope: Mapping[str, Any], state: str) -> None:
    inputs = _mapping(scope["immutable_inputs"], "immutable_inputs")
    _exact_keys(inputs, {"accepted_v0_6_0", "gate_0a", "candidate"}, "immutable_inputs")
    _exact(inputs["accepted_v0_6_0"], BASELINE, "accepted v0.6.0 binding")

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
    _exact(contract["manifest_path"], "artifacts/v0.7/work-package/qualification.json", "manifest path")
    _exact(contract["manifest_schema"], EVIDENCE_SCHEMA, "manifest schema")
    _exact(contract["validator_path"], "scripts/validate_candidate_evidence_v07.py", "validator path")
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
        {
            "review_status", "internal_ir", "driver_contract",
            "observation_api", "database_schema", "dependencies",
            "compatibility_ledger",
        },
        "reviewed_surface_delta",
    )
    expected_review = "PENDING_CANDIDATE_BINDING_AND_QUALIFICATION" if state == "PENDING_CANDIDATE" else "REVIEWED_AND_QUALIFIED"
    _exact(delta["review_status"], expected_review, "reviewed_surface_delta.review_status")

    ir = _mapping(delta["internal_ir"], "reviewed_surface_delta.internal_ir")
    _exact_keys(ir, {
        "accepted_persisted_versions_preserved", "accepted_ir_bindings",
        "new_internal_version", "new_internal_file", "opt_in_constructs",
        "legacy_serialized_bytes_must_remain_unchanged",
        "public_legacy_language_compatibility_claimed",
    }, "internal IR delta")
    _exact(ir["accepted_persisted_versions_preserved"], ["0.3", "0.6"], "accepted IR versions")
    _exact(ir["accepted_ir_bindings"], {
        "backend/ir_v03.py": {
            "blob": "87f202e9e3ff192e348c2aea9f7009ea7fc95841",
            "sha256": "2726774ed5873e0c0c1eeaffa7b3713c708ac7f61a6fa93e544a8dbc8c79963c",
        },
        "backend/ir_v06.py": {
            "blob": "6a03742e6ca4828c35dcb0908f0ffe2ad3cc3f53",
            "sha256": "ce4228f7a29f45a0e18b5d78d431d664b33b7ad4374af3c6712c8f39cb234e73",
        },
    }, "accepted IR bindings")
    _exact(ir["new_internal_version"], "0.7", "new internal IR version")
    _exact(ir["new_internal_file"], "backend/ir_v07.py", "new internal IR file")
    _exact(ir["opt_in_constructs"], ["GET_TM", "VERIFY", "WAIT_FOR"], "internal IR opt-in constructs")
    _exact(ir["legacy_serialized_bytes_must_remain_unchanged"], True, "legacy IR byte preservation")
    _exact(ir["public_legacy_language_compatibility_claimed"], False, "legacy compatibility claim")

    driver = _mapping(delta["driver_contract"], "reviewed_surface_delta.driver_contract")
    _exact(driver, {
        "protocol_file": "contracts/spell/driver/v1/driver.proto",
        "accepted_protocol_blob": "deaab2ab77b3b66b2f24813174fde5739d2af8f2",
        "accepted_protocol_sha256": "893005380ab1c51a2e5f35babe3fe5a58baf41fd9ce53cc56d0c220af7f84a80",
        "legacy_service": "DriverInfrastructureService",
        "legacy_unary_rpc_count": 9,
        "additive_service": "DriverObservationService",
        "additive_rpc_names": ["GetTime", "GetTM"],
        "legacy_protocol_declarations_must_remain_byte_identical": True,
        "legacy_handshake_bytes_must_remain_compatible": True,
        "read_only": True,
    }, "driver contract delta")

    api = _mapping(delta["observation_api"], "reviewed_surface_delta.observation_api")
    _exact(api, {
        "api_version": "v1",
        "classification": "ADDITIVE_LOCAL_READ_ONLY_OBSERVATION_ROUTES_AND_CURSOR_STREAM",
        "route_families": list(ROUTE_FAMILIES),
        "service_boundary_files": [
            "backend/observation_read_service.py",
            "backend/condition_service.py",
        ],
        "read_only_observation_boundary": True,
        "arbitrary_expression_evaluation": False,
        "broad_public_api_compatibility_claimed": False,
    }, "observation API delta")

    database = _mapping(delta["database_schema"], "reviewed_surface_delta.database_schema")
    _exact(database, {
        "migration_versions": list(MIGRATION_TABLES),
        "migration_files": [
            "backend/migrations/versions/v0005_observation_projection.py",
            "backend/migrations/versions/v0006_observation_conditions.py",
        ],
        "new_tables_by_migration": {
            key: list(value) for key, value in MIGRATION_TABLES.items()
        },
        "existing_tables_rewritten_by_migrations": [],
        "sqlite_and_postgresql_required": True,
        "rollback_and_upgrade_proof_required": True,
        "broad_database_compatibility_claimed": False,
    }, "database schema delta")

    dependency = _mapping(delta["dependencies"], "reviewed_surface_delta.dependencies")
    _exact(dependency, {
        "new_python_runtime_dependencies": [],
        "new_frontend_runtime_dependencies": [],
        "driver_implementation_version": "0.4.0",
        "live_driver_or_external_effect_route_added": False,
    }, "dependency delta")
    compatibility = _mapping(delta["compatibility_ledger"], "reviewed_surface_delta.compatibility_ledger")
    _exact(compatibility, {"claimed_construct_ids": [], "claimed_artifact_ids": [], "compatibility_ledger_rows_added": 0, "v0_6_scope_rows_changed": 0, "broad_compatibility_claimed": False}, "compatibility ledger delta")


def _validate_closeout_and_claims(scope: Mapping[str, Any], state: str) -> None:
    closeout = _mapping(scope["release_closeout_authorization"], "release_closeout_authorization")
    _exact_keys(closeout, {"status", "release_version", "tag_name", "tag_object_type", "permitted_actions_after_pass", "additional_product_work_authorized"}, "release closeout authorization")
    _exact(closeout["status"], "PENDING_GATE_0B_PASS" if state == "PENDING_CANDIDATE" else "AUTHORIZED", "release closeout status")
    _exact(closeout["release_version"], "0.7.0", "release closeout version")
    _exact(closeout["tag_name"], "v0.7.0", "release tag")
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
    _exact_keys(claims, {"v0_6_release_accepted", "gate_0a_immutable_authorization_verified", "v0_7_work_packages_implemented", "v0_7_candidate_qualified", "release_closeout_authorized", "v0_7_release_accepted_by_gate", "broad_language_or_compatibility_claimed", "operational_authorization", "deployment_approval", "compliance_determination", "cryptographic_signature_verified"}, "claims")
    _exact(claims["v0_6_release_accepted"], True, "v0.6 release claim")
    _exact(claims["gate_0a_immutable_authorization_verified"], True, "Gate 0A verification claim")
    implemented = state == "PASS"
    for key in ("v0_7_work_packages_implemented", "v0_7_candidate_qualified", "release_closeout_authorized"):
        _exact(claims[key], implemented, f"claims.{key}")
    for key in ("v0_7_release_accepted_by_gate", "broad_language_or_compatibility_claimed", "operational_authorization", "deployment_approval", "compliance_determination", "cryptographic_signature_verified"):
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
    _exact(scope["gate_id"], "V07-GATE-0B", "gate identity")
    _require(scope["status"] in {"PENDING_CANDIDATE", "PASS"}, "gate status is invalid")
    state = scope["status"]
    _exact(scope["target_increment"], "v0.7", "target increment")
    _exact(scope["target_release"], "v0.7.0", "target release")
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
    _exact(ref_type, "tag", "v0.6.0 tag object type")
    object_id = _git(root, ["rev-parse", BASELINE["tag_ref"]])
    _exact(object_id, BASELINE["tag_object_id"], "v0.6.0 tag object")
    raw_tag = _git(root, ["cat-file", "tag", object_id], binary=True)
    assert isinstance(raw_tag, bytes)
    _exact(sha256_bytes(raw_tag), BASELINE["raw_tag_object_sha256"], "v0.6.0 raw tag hash")
    peeled = _git(root, ["rev-parse", f"{BASELINE['tag_ref']}^{{}}"])
    _exact(peeled, GATE_0A_PARENT, "v0.6.0 peeled commit")
    text = raw_tag.decode("utf-8")
    for marker in REQUIRED_TAG_MARKERS:
        _require(text.splitlines().count(marker) == 1, f"v0.6.0 tag marker differs: {marker}")
    for path, digest in BASELINE["tagged_files_sha256"].items():
        _, raw = _git_blob(root, GATE_0A_PARENT, path)
        _exact(sha256_bytes(raw), digest, f"v0.6.0 tagged file hash: {path}")


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

    _, gate_doc = _git_blob(root, GATE_0A_COMMIT, "SPELL_v0.7_Pre-Implementation.md")
    _require(OWNER_MARKER in gate_doc.decode("utf-8").splitlines(), "Gate 0A owner marker is absent")
    _, scope_raw = _git_blob(root, GATE_0A_COMMIT, next(path for path in GATE_FILES if path.endswith("v0.7-gate-0a.json")))
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

    _, manifest_raw = _git_blob(root, GATE_0A_COMMIT, "contracts/v07/manifest.json")
    manifest = strict_json_bytes(manifest_raw, "committed v0.7 contract manifest")
    _exact(manifest.get("work_packages"), list(WORK_PACKAGE_TEST_IDS), "contract work-package inventory")
    matrix_paths = [f"contracts/v07/{item['file']}" for item in manifest.get("matrices", [])]
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


def _migration_new_tables(raw: bytes, version_value: str) -> tuple[str, ...]:
    tree = ast.parse(raw.decode("utf-8"), filename=f"v{version_value}.py")
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assignments[node.targets[0].id] = node.value
    version = assignments.get("VERSION")
    _require(
        isinstance(version, ast.Constant) and version.value == version_value,
        "migration version differs",
    )
    new_tables = assignments.get("NEW_TABLES")
    _require(isinstance(new_tables, ast.Tuple), "migration NEW_TABLES is not a literal tuple")
    names: list[str] = []
    for item in new_tables.elts:
        _require(isinstance(item, ast.Name), "migration NEW_TABLES contains a non-name")
        names.append(item.id)
    return tuple(names)


def _condition_migration_models(raw: bytes) -> tuple[str, ...]:
    tree = ast.parse(raw.decode("utf-8"), filename="v0006_observation_conditions.py")
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assignments[node.targets[0].id] = node.value

    version = assignments.get("VERSION")
    _require(
        isinstance(version, ast.Constant) and version.value == "0006_observation_conditions",
        "condition migration version differs",
    )
    new_tables = assignments.get("NEW_TABLES")
    expected_new_tables = ast.parse(
        "tuple(table for table in metadata.sorted_tables if table.name != Execution.__tablename__)",
        mode="eval",
    ).body
    _require(
        new_tables is not None
        and ast.dump(new_tables, include_attributes=False)
        == ast.dump(expected_new_tables, include_attributes=False),
        "condition migration inventory binding differs",
    )

    anchor = ast.parse("Execution.__table__.to_metadata(metadata)", mode="eval").body
    anchor_calls = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Expr)
        and ast.dump(node.value, include_attributes=False)
        == ast.dump(anchor, include_attributes=False)
    ]
    _require(len(anchor_calls) == 1, "condition migration execution anchor differs")

    loops = [node for node in tree.body if isinstance(node, ast.For)]
    _require(len(loops) == 1, "condition migration model loop differs")
    loop = loops[0]
    _require(
        isinstance(loop.target, ast.Name)
        and loop.target.id == "source"
        and isinstance(loop.iter, ast.Tuple)
        and len(loop.body) == 1,
        "condition migration model loop differs",
    )
    expected_body = ast.parse("source.to_metadata(metadata)", mode="eval").body
    _require(
        isinstance(loop.body[0], ast.Expr)
        and ast.dump(loop.body[0].value, include_attributes=False)
        == ast.dump(expected_body, include_attributes=False),
        "condition migration model copy differs",
    )
    names: list[str] = []
    for item in loop.iter.elts:
        _require(
            isinstance(item, ast.Attribute)
            and item.attr == "__table__"
            and isinstance(item.value, ast.Name),
            "condition migration model inventory contains a non-table",
        )
        names.append(item.value.id)
    result = tuple(names)
    _exact(result, CONDITION_MIGRATION_MODELS, "condition migration model inventory")
    return result


def _service_body(proto: str, service: str) -> str:
    match = re.search(rf"service\s+{re.escape(service)}\s*\{{(?P<body>.*?)\n\}}", proto, re.S)
    _require(match is not None, f"driver service is absent: {service}")
    return match.group("body")


def _rpc_names(service_body: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\brpc\s+([A-Za-z][A-Za-z0-9_]*)\s*\(", service_body))


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

    for path, binding in scope["reviewed_surface_delta"]["internal_ir"]["accepted_ir_bindings"].items():
        blob, raw = _git_blob(root, commit, path)
        _exact(blob, binding["blob"], f"candidate preserved legacy IR blob: {path}")
        _exact(sha256_bytes(raw), binding["sha256"], f"candidate preserved legacy IR hash: {path}")
    _, ir07 = _git_blob(root, commit, "backend/ir_v07.py")
    _require('\nIR_VERSION = "0.7"\n' in ir07.decode("utf-8"), "candidate internal IR 0.7 identity differs")

    _, accepted_proto = _git_blob(root, GATE_0A_COMMIT, "contracts/spell/driver/v1/driver.proto")
    _, candidate_proto = _git_blob(root, commit, "contracts/spell/driver/v1/driver.proto")
    accepted_proto_text = accepted_proto.decode("utf-8")
    candidate_proto_text = candidate_proto.decode("utf-8")
    accepted_legacy = _service_body(accepted_proto_text, "DriverInfrastructureService")
    candidate_legacy = _service_body(candidate_proto_text, "DriverInfrastructureService")
    _exact(candidate_legacy, accepted_legacy, "legacy nine-RPC service bytes")
    _exact(len(_rpc_names(candidate_legacy)), 9, "legacy infrastructure RPC count")
    legacy_start = "enum RpcMethod {"
    observation_start = "enum ObservationResultCode {"
    _require(legacy_start in accepted_proto_text, "accepted legacy protocol declarations are absent")
    _require(
        legacy_start in candidate_proto_text and observation_start in candidate_proto_text,
        "candidate protocol declaration boundary is absent",
    )
    accepted_legacy_declarations = accepted_proto_text[
        accepted_proto_text.index(legacy_start):
    ].rstrip("\n")
    candidate_legacy_declarations = candidate_proto_text[
        candidate_proto_text.index(legacy_start):candidate_proto_text.index(observation_start)
    ].rstrip("\n")
    _exact(
        candidate_legacy_declarations,
        accepted_legacy_declarations,
        "legacy protocol declaration bytes",
    )
    _exact(
        _rpc_names(_service_body(candidate_proto_text, "DriverObservationService")),
        ("GetTime", "GetTM"),
        "additive observation RPC inventory",
    )

    _, app = _git_blob(root, commit, "backend/app.py")
    app_text = app.decode("utf-8")
    for marker in API_ROUTE_MARKERS:
        _require(marker in app_text, f"candidate observation API route is absent: {marker}")
    for path in scope["reviewed_surface_delta"]["observation_api"]["service_boundary_files"]:
        _git_blob(root, commit, path)

    migration_paths = scope["reviewed_surface_delta"]["database_schema"]["migration_files"]
    _, projection = _git_blob(root, commit, migration_paths[0])
    _exact(
        _migration_new_tables(projection, "0005_observation_projection"),
        MIGRATION_TABLES["0005_observation_projection"],
        "observation projection migration table inventory",
    )
    _, conditions = _git_blob(root, commit, migration_paths[1])
    _exact(
        _condition_migration_models(conditions),
        CONDITION_MIGRATION_MODELS,
        "condition migration model inventory",
    )
    _, models = _git_blob(root, commit, "backend/condition_models.py")
    model_text = models.decode("utf-8")
    for table in MIGRATION_TABLES["0006_observation_conditions"]:
        _require(f'__tablename__ = "{table}"' in model_text, f"condition migration table is absent: {table}")
    _validate_dependency_delta(root, commit)

    _, gateway = _git_blob(root, commit, "backend/driver_gateway.py")
    _, host_config = _git_blob(root, commit, "driver_host/config.py")
    _require('EXPECTED_IMPLEMENTATION_VERSION = "0.4.0"' in gateway.decode("utf-8"), "driver gateway version changed")
    _require('implementation_version: str = "0.4.0"' in host_config.decode("utf-8"), "driver host version changed")


def _validate_manifest_contract(manifest: Mapping[str, Any], candidate: str) -> None:
    _exact(manifest.get("schema_version"), EVIDENCE_SCHEMA, "candidate evidence schema")
    _exact(manifest.get("product_version"), "0.7.0-candidate", "candidate evidence product version")
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
        "V07_OBS_001_THROUGH_V07_OBS_009_RELEASE_CLOSEOUT_ONLY"
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
        "v0_7_work_packages_implemented",
        "v0_7_candidate_qualified",
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
        / "v0.7-gate-0b.json"
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
        root / "SPELL_v0.7_Gate_0B.md",
        root / "SPELL_v0.7_Release.md",
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
    _exact(first, "# SPELL v0.7 Gate 0B Release Closeout", "Gate 0B document heading")
    common = (
        f"Owner request: `{OWNER_REQUEST}`",
        "Release acceptance by Gate 0B: No",
        "Operational authorization: None",
    )
    if state == "PENDING_CANDIDATE":
        state_markers = (
            "Gate 0B decision: `PENDING_CANONICAL_V07_CANDIDATE_QUALIFICATION`",
            "Release closeout authorization: `NOT_YET_AUTHORIZED`",
        )
    else:
        state_markers = (
            "Gate 0B decision: `V07_OBS_001_THROUGH_V07_OBS_009_RELEASE_CLOSEOUT_ONLY`",
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
    text, _ = _normalized_document(path, "v0.7 release document")
    state = scope["status"]
    _exact(
        next((line for line in text.splitlines() if line.strip()), ""),
        "# SPELL v0.7.0 Release Record",
        "v0.7 release document heading",
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
    validate_gate_document(root / "SPELL_v0.7_Gate_0B.md", state, scope)
    validate_release_document(root / "SPELL_v0.7_Release.md", scope)
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
        / "v0.7-gate-0b.json"
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
