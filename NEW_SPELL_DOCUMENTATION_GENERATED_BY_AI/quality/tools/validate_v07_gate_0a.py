#!/usr/bin/env python3
"""Validate the accepted SPELL v0.7 Gate 0A authorization and v0.6.0 baseline."""

from __future__ import annotations

import hashlib
import json
import os
import stat
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
    / "v0.7-gate-0a.json"
)
PROPOSAL_PATH = "SPELL_v0.7_Pre-Implementation.md"
CONTRACT_DIRECTORY = "contracts/v07"

TAG_REF = "refs/tags/v0.6.0"
TAG_OBJECT_ID = "b6dc64dc8fb6cfe9845f454904a078ec6f3c0919"
RAW_TAG_OBJECT_SHA256 = (
    "b08b3e66b0018a6f559b696cdd478b639f5ecbabc750b9049c85a8f8a17dd8a4"
)
PEELED_RELEASE_COMMIT = "05ec783a6e54a76e0548bdd536c18538f6bff51b"
QUALIFIED_SOURCE_COMMIT = "8d9db4b6acc443ca6309cdfb12b5d4f9b2fef213"
CANDIDATE_COMMIT = "0ea26105e72d7830de4a265989ed7d9074ffbe09"
SOURCE_FINGERPRINT_SHA256 = (
    "3c0245d5f9716969ef04dcf114bb8448a883f18dc801d8ccbcee06396363d3e1"
)
EVIDENCE_FINGERPRINT_SHA256 = (
    "33e05aca329c5b3d66ebf1184327c1482294599ce7874b9d625de38365447376"
)
PRODUCT_PACKAGE_SHA256 = (
    "50bb87ef5dec937c259d1082ba77990a1e34cadd509c7559190969b79bde6cac"
)
WORK_PACKAGE_EVIDENCE_SHA256 = (
    "16bfa10273d8934c297d20535b848df9396c4d6e9b2382f41d3bedd7b76fc538"
)
ARCHIVE_PATH = "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz"
ARCHIVE_SHA256 = "b2d2bb30fe3ec781d8dcca434d3f0b90f8f31e2a776331c5ef20b36c8ae2864c"
SIDECAR_PATH = "artifacts/v0.6/openbexi-spell-v0.6.0.tar.gz.sha256"
SIDECAR_SHA256 = "7240872d3058796e7496eb9f0a44b44295a1246c6c991545aae4fb9b2ec23520"
SIDECAR_BYTES = (
    f"{ARCHIVE_SHA256}  openbexi-spell-v0.6.0.tar.gz\n".encode("ascii")
)

TAGGED_BLOBS: dict[str, dict[str, str]] = {
    "SPELL_v0.6_Release.md": {
        "object_id": "c265d6bdb77d71c286d169205d0de35e4c0fdcff",
        "sha256": "9eb9121470f7cdf097f55917bdcead7748b0257209ff8adfa957d7ca1bb4a7da",
    },
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.6-gate-0b.json"
    ): {
        "object_id": "ae71f4b678ea24148f3f4441aa5c22100458bab2",
        "sha256": "0deef3794c7dd34ef9995f95d33f2688aebfa198b96579e655273603555205bc",
    },
    "artifacts/v0.6/release-qualification.json": {
        "object_id": "968fff577d936ca3ce27990fb338e9e20f5a2fdd",
        "sha256": "cbff6f30fca8708260a0a94bf60f3834455dee9cfa2021b5ae4dd2ec83b4c98f",
    },
    ARCHIVE_PATH: {
        "object_id": "e748945e218057ae14351b88d5e25d59ca043289",
        "sha256": ARCHIVE_SHA256,
    },
    SIDECAR_PATH: {
        "object_id": "0563fda5c3227de831eaeef1ef1c6e67f5bc0835",
        "sha256": SIDECAR_SHA256,
    },
}

CONTRACTS_SHA256 = {
    "manifest.json": "df1c8060cf6ec8259d2949ac6ec14f7aebca7ceba041bb274fdbec6c354d1a7d",
    "time_and_sample_identity.json": "08a36552d311c6cb6297a493197480a5fbe2df0153ac4e4c63ddf9c0d66d58cd",
    "condition_engine.json": "5373bbe93f0b19656cd266dc0341f03df11e02e4e7a1038e8b64ff30a253ef1b",
    "waitfor_and_scheduling.json": "53cfb3d168765495ee46b2383dfd14dca79154ac59eed3fd857953cf14119f79",
    "resource_and_lookup_reads.json": "07c93d6960f312eb8c31832f455ae874ac6b54b05cbc85df038f5acd8be16eb8",
    "limits_and_alarm_state.json": "e42c7da301fb340f0e8cada67806a620194802f77658bc8029df2857a0cf4977",
    "cursor_streams.json": "e18f62e3cb949ddeab7c0533712d0f6666f6b9eef59b78e6255bd3c963a41c8d",
}

REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Gate 0B: PASS",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
    "Cryptographic signature: Not claimed",
    f"Release commit: {PEELED_RELEASE_COMMIT}",
    f"Qualified source commit: {QUALIFIED_SOURCE_COMMIT}",
    f"Candidate implementation commit: {CANDIDATE_COMMIT}",
    f"Source fingerprint: {SOURCE_FINGERPRINT_SHA256}",
    f"Evidence fingerprint: {EVIDENCE_FINGERPRINT_SHA256}",
    f"Product package SHA-256: {PRODUCT_PACKAGE_SHA256}",
    f"Work-package evidence SHA-256: {WORK_PACKAGE_EVIDENCE_SHA256}",
    f"Final archive SHA-256: {ARCHIVE_SHA256}",
)

PASS_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_APPROVAL_MARKER = "V07-GATE-0A OWNER-APPROVAL: APPROVED"
OWNER_REQUEST = (
    "resume and finish up asap v0.6 asap and move forward to finis up v0.7 "
    "asap. you have all aprrovals."
)

WORK_PACKAGES = [
    {
        "work_package_id": "V07-OBS-001",
        "title": "Typed simulator driver time and provenance",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "DETERMINISTIC_SIMULATOR_DRIVER_TIME_SOURCE_PROVENANCE_UNCERTAINTY_"
            "SKEW_AND_EXPLICIT_HOST_FALLBACK"
        ),
        "planned_test_ids": [
            "V07-OBS-001-UNIT",
            "V07-OBS-001-CONTRACT",
            "V07-OBS-001-CLOCK",
            "V07-OBS-001-RECOVERY",
            "V07-OBS-001-SECURITY",
        ],
    },
    {
        "work_package_id": "V07-OBS-002",
        "title": "Typed GetTM samples and atomic raw/engineering projection",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "SIMULATOR_GETTM_CURRENT_NEXT_ATOMIC_SAMPLE_IDENTITY_RAW_ENGINEERING_"
            "METADATA_ACQUISITION_RECEIVE_TIME_SOURCE_VALIDITY_QUALITY_FRESHNESS_"
            "AND_SEQUENCE"
        ),
        "planned_test_ids": [
            "V07-OBS-002-UNIT",
            "V07-OBS-002-INTEGRATION",
            "V07-OBS-002-ATOMIC",
            "V07-OBS-002-QUALITY",
            "V07-OBS-002-SECURITY",
        ],
    },
    {
        "work_package_id": "V07-OBS-003",
        "title": "Bounded declarative Verify condition engine",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "TYPED_VERIFY_NESTED_AND_OR_DOCUMENTED_COMPARISONS_TOLERANCE_RETRIES_"
            "TIMEOUT_DELAY_COMPOSITE_RESULT_AND_TM_TO_TM_WITHOUT_CODE_EVALUATION"
        ),
        "planned_test_ids": [
            "V07-OBS-003-UNIT",
            "V07-OBS-003-MATRIX",
            "V07-OBS-003-CLOCK",
            "V07-OBS-003-RECOVERY",
            "V07-OBS-003-SECURITY",
        ],
    },
    {
        "work_package_id": "V07-OBS-004",
        "title": "Deterministic telemetry WaitFor",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "RELATIVE_ABSOLUTE_AND_TM_WAITFOR_WITH_MONOTONIC_DEADLINES_QUALITY_"
            "FRESHNESS_CANCELLATION_DISCONNECT_AND_ONE_DURABLE_OUTCOME"
        ),
        "planned_test_ids": [
            "V07-OBS-004-UNIT",
            "V07-OBS-004-INTEGRATION",
            "V07-OBS-004-CLOCK",
            "V07-OBS-004-RACE",
            "V07-OBS-004-RECOVERY",
        ],
    },
    {
        "work_package_id": "V07-OBS-005",
        "title": "Telemetry-conditioned durable procedure scheduling",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "QUALITY_AND_FRESHNESS_GATED_TELEMETRY_SCHEDULES_WITH_DURABLE_"
            "IDENTITY_CANCELLATION_RESTART_RECOVERY_AND_EXACTLY_ONE_START_OUTCOME"
        ),
        "planned_test_ids": [
            "V07-OBS-005-UNIT",
            "V07-OBS-005-INTEGRATION",
            "V07-OBS-005-CLOCK",
            "V07-OBS-005-RACE",
            "V07-OBS-005-RECOVERY",
        ],
    },
    {
        "work_package_id": "V07-OBS-006",
        "title": "Typed simulator resource and lookup reads",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "BOUNDED_TYPED_SIMULATOR_GETRESOURCE_MEMORYLOOKUP_AND_TMTCLOOKUP_"
            "CATALOG_QUERY_READS_WITH_NO_GENERIC_STRING_FILTER_OR_MUTATION"
        ),
        "planned_test_ids": [
            "V07-OBS-006-UNIT",
            "V07-OBS-006-INTEGRATION",
            "V07-OBS-006-BOUNDARY",
            "V07-OBS-006-RECOVERY",
            "V07-OBS-006-SECURITY",
        ],
    },
    {
        "work_package_id": "V07-OBS-007",
        "title": "Read-only telemetry limits and alarm state",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "READ_ONLY_GETLIMITS_AND_ISALARMED_WITH_SAMPLE_IDENTITY_QUALITY_"
            "FRESHNESS_SEQUENCE_AND_NO_LIMIT_OR_ALARM_MUTATION"
        ),
        "planned_test_ids": [
            "V07-OBS-007-UNIT",
            "V07-OBS-007-MATRIX",
            "V07-OBS-007-QUALITY",
            "V07-OBS-007-RECOVERY",
            "V07-OBS-007-SECURITY",
        ],
    },
    {
        "work_package_id": "V07-OBS-008",
        "title": "Durable telemetry snapshot and cursor streams",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "AUTHORIZATION_SCOPED_SNAPSHOT_CURSOR_STREAMS_WITH_CONTIGUOUS_"
            "SEQUENCE_GAP_RESYNCHRONIZATION_BACKPRESSURE_CANCELLATION_"
            "DISCONNECT_AND_RESTART"
        ),
        "planned_test_ids": [
            "V07-OBS-008-UNIT",
            "V07-OBS-008-INTEGRATION",
            "V07-OBS-008-BACKPRESSURE",
            "V07-OBS-008-RECONNECT",
            "V07-OBS-008-SECURITY",
        ],
    },
    {
        "work_package_id": "V07-OBS-009",
        "title": "Cross-feature read-only observation acceptance",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "INTEGRATED_TIME_GETTM_VERIFY_WAITFOR_SCHEDULE_RESOURCE_LOOKUP_LIMIT_"
            "ALARM_STREAM_SEMANTIC_BROWSER_ACCESSIBILITY_LOAD_FAULT_RECOVERY_AND_"
            "SECURITY_ACCEPTANCE"
        ),
        "planned_test_ids": [
            "V07-OBS-009-SEMANTIC-GOLDEN",
            "V07-OBS-009-BROWSER",
            "V07-OBS-009-ACCESSIBILITY",
            "V07-OBS-009-FAULT-RECOVERY",
            "V07-OBS-009-LOAD-SECURITY",
        ],
    },
]

EXPECTED_SCOPE: dict[str, Any] = {
    "schema_version": "ng-spell-v07-gate-0a-scope/1",
    "gate_id": "V07-GATE-0A",
    "status": "PASS",
    "target_increment": "v0.7",
    "target_release": "v0.7.0",
    "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    "decision": {
        "owner": "JC Arcaz",
        "proposal_date": "2026-08-16",
        "approval_date": "2026-08-16",
        "authorization": "V07_OBS_001_THROUGH_V07_OBS_009",
        "owner_request": OWNER_REQUEST,
        "precondition": "ANNOTATED_V0_6_0_ACCEPTED_RELEASE_TAG_VERIFIED",
        "owner_approval_recorded": True,
    },
    "approval_mechanics": {
        "pass_validator_marker": PASS_MARKER,
        "required_owner_approval_marker": OWNER_APPROVAL_MARKER,
        "required_marker_location": (
            "STANDALONE_LINE_IN_SPELL_V0_7_PRE_IMPLEMENTATION_MD"
        ),
        "marker_present": True,
        "required_scope_status_after_approval": "PASS",
        "required_authorization_after_approval": (
            "EXPLICIT_BOUNDED_WORK_PACKAGE_ID_LIST"
        ),
        "authorized_work_package_ids": [
            f"V07-OBS-{index:03d}" for index in range(1, 10)
        ],
        "automatic_approval_from_request_or_tool_success": False,
    },
    "accepted_baseline": {
        "tag_ref": TAG_REF,
        "tag_object_type": "tag",
        "tag_object_id": TAG_OBJECT_ID,
        "raw_tag_object_sha256": RAW_TAG_OBJECT_SHA256,
        "peeled_release_commit": PEELED_RELEASE_COMMIT,
        "qualified_source_commit": QUALIFIED_SOURCE_COMMIT,
        "candidate_commit": CANDIDATE_COMMIT,
        "source_fingerprint_sha256": SOURCE_FINGERPRINT_SHA256,
        "evidence_fingerprint_sha256": EVIDENCE_FINGERPRINT_SHA256,
        "product_package_sha256": PRODUCT_PACKAGE_SHA256,
        "work_package_evidence_sha256": WORK_PACKAGE_EVIDENCE_SHA256,
        "tagged_blobs": TAGGED_BLOBS,
        "accepted_artifact_pair": {
            "archive_path": ARCHIVE_PATH,
            "archive_sha256": ARCHIVE_SHA256,
            "sidecar_path": SIDECAR_PATH,
            "sidecar_sha256": SIDECAR_SHA256,
            "sidecar_ascii": SIDECAR_BYTES.decode("ascii").rstrip("\n"),
        },
    },
    "authorization_contracts": {
        "directory": CONTRACT_DIRECTORY,
        "matrix_count": 6,
        "file_count": 7,
        "files_sha256": CONTRACTS_SHA256,
    },
    "compatibility_delta": {
        "accepted_ir_versions": ["0.3"],
        "new_ir_versions": [],
        "claimed_construct_ids": [],
        "claimed_artifact_ids": [],
        "compatibility_ledger_rows_added": 0,
        "v0_6_scope_rows_changed": 0,
    },
    "proposed_work_packages": WORK_PACKAGES,
    "claims": {
        "v0_6_release_accepted": True,
        "v0_7_program_proposed": True,
        "v0_7_implementation_authorized": True,
        "v0_7_implementation_claimed_by_gate": False,
        "v0_7_release_accepted": False,
        "observation_constructs_implemented": False,
        "product_artifacts_implemented": False,
        "operational_authorization": False,
        "deployment_approval": False,
        "compliance_determination": False,
        "cryptographic_signature_verified": False,
    },
    "explicit_exclusions": [
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
        "IMPLEMENTATION_RELEASE_DEPLOYMENT_OPERATIONAL_COMPLIANCE_OR_SIGNATURE_CLAIM",
    ],
}

POST_BASELINE_ONLY_PATHS = (
    PROPOSAL_PATH,
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.7-gate-0a.json"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v07_gate_0a.py"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v07_gate_0a.py"
    ),
    "backend/tests/test_v07_contract_matrices.py",
    *(f"{CONTRACT_DIRECTORY}/{name}" for name in CONTRACTS_SHA256),
)


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object contains a duplicate key."""


class GitValidationError(RuntimeError):
    """Raised when a required Git query cannot be completed exactly."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> Any:
    raise ValueError(f"non-finite JSON value: {value}")


def parse_strict_json(raw: bytes, label: str, maximum_bytes: int) -> Any:
    if len(raw) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
    text = raw.decode("utf-8")
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def read_json(path: Path = SCOPE_PATH) -> Any:
    return parse_strict_json(path.read_bytes(), "Gate 0A scope", 512 * 1024)


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
            errors.append(
                f"{path} length differs: expected {len(expected)}, got {len(actual)}"
            )
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            errors.extend(
                exact_value_errors(actual_item, expected_item, f"{path}[{index}]")
            )
        return errors
    if actual != expected:
        return [f"{path} value differs"]
    return []


def _scope_summary(payload: Any, valid: bool) -> dict[str, Any]:
    proposed = authorized = claimed_constructs = claimed_artifacts = 0
    if isinstance(payload, dict):
        packages = payload.get("proposed_work_packages")
        if isinstance(packages, list):
            proposed = len(packages)
        mechanics = payload.get("approval_mechanics")
        if isinstance(mechanics, dict):
            ids = mechanics.get("authorized_work_package_ids")
            if isinstance(ids, list):
                authorized = len(ids)
        delta = payload.get("compatibility_delta")
        if isinstance(delta, dict):
            constructs = delta.get("claimed_construct_ids")
            artifacts = delta.get("claimed_artifact_ids")
            if isinstance(constructs, list):
                claimed_constructs = len(constructs)
            if isinstance(artifacts, list):
                claimed_artifacts = len(artifacts)
    return {
        "gate": "PASS" if valid else "FAIL",
        "authorized_work_packages": authorized,
        "proposed_work_packages": proposed,
        "claimed_constructs": claimed_constructs,
        "claimed_artifacts": claimed_artifacts,
    }


def validate_scope_payload(payload: Any) -> tuple[list[str], dict[str, Any]]:
    errors = exact_value_errors(payload, EXPECTED_SCOPE)
    return errors, _scope_summary(payload, not errors)


def validate_scope(payload: Any) -> list[str]:
    return validate_scope_payload(payload)[0]


def validate_tag_payload(raw_tag: bytes) -> list[str]:
    errors: list[str] = []
    if sha256_bytes(raw_tag) != RAW_TAG_OBJECT_SHA256:
        errors.append("v0.6.0 raw tag object SHA-256 differs")
    git_object = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    if hashlib.sha1(git_object).hexdigest() != TAG_OBJECT_ID:
        errors.append("v0.6.0 tag object ID does not match its raw bytes")
    headers, separator, message = raw_tag.partition(b"\n\n")
    if not separator:
        errors.append("v0.6.0 tag object lacks a message boundary")
        return errors
    expected_prefix = [
        f"object {PEELED_RELEASE_COMMIT}".encode("ascii"),
        b"type commit",
        b"tag v0.6.0",
    ]
    if headers.splitlines()[:3] != expected_prefix:
        errors.append("v0.6.0 tag object headers differ")
    try:
        message_lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        errors.append("v0.6.0 tag message is not strict UTF-8")
        return errors
    for marker in REQUIRED_TAG_MARKERS:
        count = message_lines.count(marker)
        if count != 1:
            errors.append(
                f"v0.6.0 tag marker {marker!r} occurs {count} times, expected 1"
            )
    return errors


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
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def run_git(
    arguments: list[str],
    workspace_root: Path = WORKSPACE_ROOT,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=workspace_root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitValidationError(f"cannot run git {' '.join(arguments)}: {exc}") from exc
    if result.returncode not in accepted_returncodes:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise GitValidationError(
            f"git {' '.join(arguments)} failed ({result.returncode}): {detail}"
        )
    return result


def _single_ascii_line(payload: bytes, label: str) -> str:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitValidationError(f"{label} is not ASCII") from exc
    if len(lines) != 1 or not lines[0]:
        raise GitValidationError(f"{label} did not return exactly one line")
    return lines[0]


def _validate_tagged_blob(
    relative_path: str,
    expected: dict[str, str],
    workspace_root: Path = WORKSPACE_ROOT,
) -> tuple[list[str], bytes | None]:
    errors: list[str] = []
    expected_id = expected["object_id"]
    expected_record = (
        f"100644 blob {expected_id}\t{relative_path}\0".encode("utf-8")
    )
    listing = run_git(
        ["ls-tree", "-z", PEELED_RELEASE_COMMIT, "--", relative_path],
        workspace_root,
    ).stdout
    if listing != expected_record:
        errors.append(f"tagged baseline tree entry differs: {relative_path}")
    resolved = _single_ascii_line(
        run_git(
            ["rev-parse", "--verify", f"{PEELED_RELEASE_COMMIT}:{relative_path}"],
            workspace_root,
        ).stdout,
        f"tagged blob ID for {relative_path}",
    )
    if resolved != expected_id:
        errors.append(f"tagged baseline blob ID differs: {relative_path}")
    object_type = _single_ascii_line(
        run_git(["cat-file", "-t", expected_id], workspace_root).stdout,
        f"tagged object type for {relative_path}",
    )
    if object_type != "blob":
        errors.append(f"tagged baseline object is not a blob: {relative_path}")
        return errors, None
    payload = run_git(["cat-file", "blob", expected_id], workspace_root).stdout
    if sha256_bytes(payload) != expected["sha256"]:
        errors.append(f"tagged baseline blob SHA-256 differs: {relative_path}")
    return errors, payload


def validate_archive_sidecar(
    archive: bytes,
    sidecar: bytes,
    label: str,
) -> list[str]:
    errors: list[str] = []
    if sha256_bytes(archive) != ARCHIVE_SHA256:
        errors.append(f"{label} archive SHA-256 differs")
    if sha256_bytes(sidecar) != SIDECAR_SHA256:
        errors.append(f"{label} sidecar SHA-256 differs")
    if sidecar != SIDECAR_BYTES:
        errors.append(f"{label} sidecar bytes differ")
    return errors


def _read_regular_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} is not a non-symlink regular file")
    if metadata.st_size > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
    return path.read_bytes()


def validate_contract_directory(
    directory: Path | None = None,
) -> list[str]:
    root = directory or (WORKSPACE_ROOT / CONTRACT_DIRECTORY)
    errors: list[str] = []
    try:
        metadata = root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return ["v0.7 contract directory is not a non-symlink directory"]
        names = sorted(item.name for item in root.iterdir())
    except OSError as exc:
        return [f"cannot inspect v0.7 contract directory: {exc}"]
    expected_names = sorted(CONTRACTS_SHA256)
    if names != expected_names:
        errors.append(
            "v0.7 contract directory inventory differs: "
            f"expected {expected_names!r}, got {names!r}"
        )
    for name, expected_sha256 in CONTRACTS_SHA256.items():
        path = root / name
        try:
            raw = _read_regular_file(path, 512 * 1024, f"v0.7 contract {name}")
            payload = parse_strict_json(raw, f"v0.7 contract {name}", 512 * 1024)
            if not isinstance(payload, dict):
                errors.append(f"v0.7 contract is not a JSON object: {name}")
            if sha256_bytes(raw) != expected_sha256:
                errors.append(f"v0.7 contract SHA-256 differs: {name}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"cannot validate v0.7 contract {name}: {exc}")
    return errors


def validate_git_baseline(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    errors: list[str] = []
    try:
        initial_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", TAG_REF], workspace_root).stdout,
            TAG_REF,
        )
        if initial_ref != TAG_OBJECT_ID:
            errors.append("refs/tags/v0.6.0 does not name the accepted tag object")
        object_type = _single_ascii_line(
            run_git(["cat-file", "-t", TAG_OBJECT_ID], workspace_root).stdout,
            "v0.6.0 tag object type",
        )
        if object_type != "tag":
            errors.append("v0.6.0 is not an annotated tag object")
        raw_tag = run_git(["cat-file", "tag", TAG_OBJECT_ID], workspace_root).stdout
        errors.extend(validate_tag_payload(raw_tag))
        peeled = _single_ascii_line(
            run_git(
                ["rev-parse", "--verify", f"{TAG_REF}^{{commit}}"], workspace_root
            ).stdout,
            "v0.6.0 peeled release commit",
        )
        if peeled != PEELED_RELEASE_COMMIT:
            errors.append("v0.6.0 peeled release commit differs")
        parent = _single_ascii_line(
            run_git(
                ["rev-parse", "--verify", f"{PEELED_RELEASE_COMMIT}^"],
                workspace_root,
            ).stdout,
            "v0.6.0 release parent",
        )
        if parent != QUALIFIED_SOURCE_COMMIT:
            errors.append("v0.6.0 release parent is not the qualified source commit")
        for ancestor, descendant, label in (
            (PEELED_RELEASE_COMMIT, "HEAD", "accepted v0.6.0 release commit"),
            (CANDIDATE_COMMIT, QUALIFIED_SOURCE_COMMIT, "v0.6 candidate commit"),
        ):
            result = run_git(
                ["merge-base", "--is-ancestor", ancestor, descendant],
                workspace_root,
                accepted_returncodes=(0, 1),
            )
            if result.returncode != 0:
                errors.append(f"{label} has invalid ancestry")

        tagged_payloads: dict[str, bytes] = {}
        for relative_path, expected in TAGGED_BLOBS.items():
            blob_errors, payload = _validate_tagged_blob(
                relative_path, expected, workspace_root
            )
            errors.extend(blob_errors)
            if payload is not None:
                tagged_payloads[relative_path] = payload
        if ARCHIVE_PATH in tagged_payloads and SIDECAR_PATH in tagged_payloads:
            errors.extend(
                validate_archive_sidecar(
                    tagged_payloads[ARCHIVE_PATH],
                    tagged_payloads[SIDECAR_PATH],
                    "tagged v0.6.0",
                )
            )

        try:
            workspace_archive = _read_regular_file(
                workspace_root / ARCHIVE_PATH, 256 * 1024 * 1024, "v0.6 archive"
            )
            workspace_sidecar = _read_regular_file(
                workspace_root / SIDECAR_PATH, 1024, "v0.6 archive sidecar"
            )
            errors.extend(
                validate_archive_sidecar(
                    workspace_archive, workspace_sidecar, "workspace v0.6.0"
                )
            )
            if tagged_payloads.get(ARCHIVE_PATH) != workspace_archive:
                errors.append("workspace v0.6 archive differs from accepted tagged blob")
            if tagged_payloads.get(SIDECAR_PATH) != workspace_sidecar:
                errors.append("workspace v0.6 sidecar differs from accepted tagged blob")
        except (OSError, ValueError) as exc:
            errors.append(f"cannot validate workspace v0.6 artifact pair: {exc}")

        for relative_path in POST_BASELINE_ONLY_PATHS:
            listing = run_git(
                [
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "-z",
                    PEELED_RELEASE_COMMIT,
                    "--",
                    relative_path,
                ],
                workspace_root,
            ).stdout
            if any(listing.split(b"\0")):
                errors.append(
                    f"v0.7 Gate 0A path unexpectedly exists in v0.6.0: {relative_path}"
                )
            current_path = workspace_root / Path(relative_path)
            if not current_path.is_file() or current_path.is_symlink():
                errors.append(
                    f"v0.7 Gate 0A path is missing or not a regular file: {relative_path}"
                )
        final_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", TAG_REF], workspace_root).stdout,
            f"final {TAG_REF}",
        )
        if final_ref != initial_ref:
            errors.append("refs/tags/v0.6.0 changed during validation")
    except GitValidationError as exc:
        errors.append(str(exc))
    return errors


def validate_document_lines(lines: list[str]) -> list[str]:
    errors: list[str] = []
    title = "# SPELL v0.7 Pre-Implementation Gate 0A"
    first_nonempty = next((line for line in lines if line.strip()), None)
    if first_nonempty != title or lines.count(title) != 1:
        errors.append("SPELL v0.7 Gate 0A title differs")
    required_lines = (
        "| Gate status | `PASS`; `V07-OBS-001` through `V07-OBS-009` are authorized |",
        "| Owner approval date | 2026-08-16 |",
        f"| Owner request | `{OWNER_REQUEST}` |",
        "| Authorized work packages | `V07-OBS-001` through `V07-OBS-009` |",
        "| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_SIMULATOR` |",
        "`V07-GATE-0A PASS` authorizes implementation of exactly `V07-OBS-001` through",
        "`V07-OBS-009`. It claims zero implemented constructs and zero implemented",
        PASS_MARKER,
        OWNER_APPROVAL_MARKER,
    )
    for marker in required_lines:
        count = lines.count(marker)
        if count != 1:
            errors.append(
                f"accepted Gate 0A marker {marker!r} occurs {count} times, expected 1"
            )
    for index in range(1, 10):
        work_package_id = f"V07-OBS-{index:03d}"
        if not any(line.startswith(f"| `{work_package_id}` |") for line in lines):
            errors.append(f"proposal table is missing {work_package_id}")
    for name, digest in CONTRACTS_SHA256.items():
        marker = f"| `contracts/v07/{name}` | `{digest}` |"
        if lines.count(marker) != 1:
            errors.append(f"proposal contract binding differs: {name}")
    return errors


def validate_document(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    path = workspace_root / PROPOSAL_PATH
    try:
        raw = _read_regular_file(path, 256 * 1024, "SPELL v0.7 Gate 0A record")
        lines = raw.decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"cannot read SPELL v0.7 Gate 0A record: {exc}"]
    return validate_document_lines(lines)


def validate_repository(
    scope_path: Path = SCOPE_PATH,
    workspace_root: Path = WORKSPACE_ROOT,
) -> tuple[list[str], dict[str, Any]]:
    try:
        payload = read_json(scope_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors = [f"cannot load Gate 0A scope: {exc}"]
        return errors, _scope_summary(None, False)
    errors, summary = validate_scope_payload(payload)
    errors.extend(validate_git_baseline(workspace_root))
    errors.extend(validate_contract_directory(workspace_root / CONTRACT_DIRECTORY))
    errors.extend(validate_document(workspace_root))
    summary["gate"] = "PASS" if not errors else "FAIL"
    return errors, summary


def main() -> int:
    errors, summary = validate_repository()
    if errors:
        print(
            "gate=FAIL "
            f"authorized_work_packages={summary['authorized_work_packages']} "
            f"proposed_work_packages={summary['proposed_work_packages']} "
            f"claimed_constructs={summary['claimed_constructs']} "
            f"claimed_artifacts={summary['claimed_artifacts']}"
        )
        for error in errors[:50]:
            print(f"ERROR: {error}", file=sys.stderr)
        if len(errors) > 50:
            print(f"ERROR: {len(errors) - 50} additional errors omitted", file=sys.stderr)
        return 1
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
