#!/usr/bin/env python3
"""Validate the accepted SPELL v0.6 Gate 0A scope and v0.5.0 baseline."""

from __future__ import annotations

import hashlib
import json
import os
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
    / "v0.6-gate-0a.json"
)
PROPOSAL_PATH = "SPELL_v0.6_Pre-Implementation.md"

TAG_REF = "refs/tags/v0.5.0"
TAG_OBJECT_ID = "a1b277d74d2fb19062ca3e4388e9104d45c50ec4"
RAW_TAG_OBJECT_SHA256 = (
    "6c642ec6f7461db9fdce2347ca6ab493686430d5bd36218a4c0306b1b70ba48f"
)
PEELED_RELEASE_COMMIT = "e7b6bb9428833437e0160040541eb840deee7cca"
QUALIFIED_SOURCE_COMMIT = "2f31e6a011b8aad63b29bd55780c37c1b68712f1"

TAGGED_FILES_SHA256 = {
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
}

REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Gate 0B: PASS",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
    f"Release commit: {PEELED_RELEASE_COMMIT}",
    f"Qualified source commit: {QUALIFIED_SOURCE_COMMIT}",
)

PASS_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)
OWNER_APPROVAL_MARKER = "V06-GATE-0A OWNER-APPROVAL: APPROVED"
POST_BASELINE_ONLY_PATHS = (
    PROPOSAL_PATH,
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.6-gate-0a.json"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v06_gate_0a.py"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v06_gate_0a.py"
    ),
)

WORK_PACKAGES = [
    {
        "work_package_id": "V06-OP-001",
        "title": (
            "Context, catalog, stable multi-instance history, and Master workspace"
        ),
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "LOCAL_CONTEXT_ATTACHMENT_IMMUTABLE_CATALOG_PROPERTIES_HISTORY_"
            "STABLE_INSTANCE_IDENTITY_AND_MASTER_VIEW"
        ),
        "planned_test_ids": [
            "V06-OP-001-UNIT",
            "V06-OP-001-INTEGRATION",
            "V06-OP-001-RECOVERY",
            "V06-OP-001-UI",
            "V06-OP-001-SECURITY",
        ],
    },
    {
        "work_package_id": "V06-OP-002",
        "title": (
            "C/M/B modes and durable control lease, fencing, and reacquisition"
        ),
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "EXCLUSIVE_CONTROLLER_READ_ONLY_MONITOR_BACKGROUND_MODE_DURABLE_"
            "LEASE_FENCING_DISCONNECT_PAUSE_AND_EXPLICIT_REACQUISITION"
        ),
        "planned_test_ids": [
            "V06-OP-002-UNIT",
            "V06-OP-002-INTEGRATION",
            "V06-OP-002-RACE",
            "V06-OP-002-RECOVERY",
            "V06-OP-002-SECURITY",
        ],
    },
    {
        "work_package_id": "V06-OP-003",
        "title": "Procedure command and safe-point state matrix",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "RUN_STEP_STEP_OVER_PAUSE_SKIP_GOTO_RELOAD_BACKGROUND_STOP_ABORT_"
            "RECOVER_WITH_EXPLICIT_KILL_REJECTION_AND_EFFECT_CERTAINTY"
        ),
        "planned_test_ids": [
            "V06-OP-003-UNIT",
            "V06-OP-003-MATRIX",
            "V06-OP-003-RACE",
            "V06-OP-003-RECOVERY",
            "V06-OP-003-SECURITY",
        ],
    },
    {
        "work_package_id": "V06-OP-004",
        "title": "Typed durable Prompt family",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "DOCUMENTED_TYPED_PROMPTS_VALIDATION_DEFAULTS_WARNING_TIMERS_COMMIT_"
            "RESET_ABORT_SETTINGS_ONE_DURABLE_OUTCOME_AND_CONTROLLER_LOSS_RECOVERY"
        ),
        "planned_test_ids": [
            "V06-OP-004-UNIT",
            "V06-OP-004-INTEGRATION",
            "V06-OP-004-RACE",
            "V06-OP-004-RECOVERY",
            "V06-OP-004-UI",
        ],
    },
    {
        "work_package_id": "V06-OP-005",
        "title": "Durable relative and absolute procedure schedules",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "LOCAL_CLOCK_RELATIVE_AND_ABSOLUTE_SCHEDULE_IDENTITY_VALIDATION_"
            "CANCELLATION_ONE_START_OUTCOME_AND_RESTART_RECOVERY"
        ),
        "planned_test_ids": [
            "V06-OP-005-UNIT",
            "V06-OP-005-INTEGRATION",
            "V06-OP-005-CLOCK",
            "V06-OP-005-RACE",
            "V06-OP-005-RECOVERY",
        ],
    },
    {
        "work_package_id": "V06-OP-006",
        "title": (
            "Procedure views, navigation, breakpoints, inspection, and safe edits"
        ),
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "SOURCE_TEXT_AS_RUN_SUPPORT_LOG_OUTLINE_SEARCH_NESTED_NAVIGATION_"
            "BREAKPOINT_RUN_TO_LINE_TYPED_INSPECTION_SAFE_STATE_EDITS_AND_"
            "BOUNDED_NON_EVALUATING_CONSOLE"
        ),
        "planned_test_ids": [
            "V06-OP-006-UNIT",
            "V06-OP-006-INTEGRATION",
            "V06-OP-006-UI",
            "V06-OP-006-RECOVERY",
            "V06-OP-006-SECURITY",
        ],
    },
    {
        "work_package_id": "V06-OP-007",
        "title": "Durable named allowlisted user actions",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "NAMED_VERSIONED_ALLOWLISTED_SAFE_POINT_ACTIONS_WITH_DURABLE_IDENTITY_"
            "AUDIT_AND_NO_ARBITRARY_ASYNCHRONOUS_PYTHON"
        ),
        "planned_test_ids": [
            "V06-OP-007-UNIT",
            "V06-OP-007-INTEGRATION",
            "V06-OP-007-RACE",
            "V06-OP-007-RECOVERY",
            "V06-OP-007-SECURITY",
        ],
    },
    {
        "work_package_id": "V06-OP-008",
        "title": "Immutable StartProc parent-child composition",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "IMMUTABLE_LIBRARY_RESOLUTION_DURABLE_STARTPROC_PARENT_CHILD_"
            "IDENTITY_DEPTH_CYCLE_CRASH_AND_RESTART_RULES"
        ),
        "planned_test_ids": [
            "V06-OP-008-UNIT",
            "V06-OP-008-INTEGRATION",
            "V06-OP-008-GRAPH",
            "V06-OP-008-RECOVERY",
            "V06-OP-008-SECURITY",
        ],
    },
    {
        "work_package_id": "V06-OP-009",
        "title": "Cross-feature desktop and mobile operator acceptance",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "capability_boundary": (
            "INTEGRATED_DESKTOP_MOBILE_ACCESSIBILITY_COMPETING_CONTROL_PROMPT_"
            "SCHEDULE_INSPECTION_ACTION_COMPOSITION_FAULT_RECOVERY_AND_SECURITY_"
            "ACCEPTANCE"
        ),
        "planned_test_ids": [
            "V06-OP-009-DESKTOP",
            "V06-OP-009-MOBILE",
            "V06-OP-009-ACCESSIBILITY",
            "V06-OP-009-FAULT-RECOVERY",
            "V06-OP-009-SECURITY",
        ],
    },
]

EXPECTED_SCOPE: dict[str, Any] = {
    "schema_version": "ng-spell-v06-gate-0a-scope/1",
    "gate_id": "V06-GATE-0A",
    "status": "PASS",
    "target_increment": "v0.6",
    "target_release": "v0.6.0",
    "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    "decision": {
        "owner": "JC Arcaz",
        "proposal_date": "2026-08-15",
        "approval_date": "2026-08-15",
        "authorization": "V06_OP_001_THROUGH_V06_OP_009",
        "owner_request": "finish up v0.6",
        "precondition": "ANNOTATED_V0_5_0_ACCEPTED_RELEASE_TAG_VERIFIED",
        "owner_approval_recorded": True,
    },
    "approval_mechanics": {
        "pass_validator_marker": PASS_MARKER,
        "required_owner_approval_marker": OWNER_APPROVAL_MARKER,
        "required_marker_location": (
            "STANDALONE_LINE_IN_SPELL_V0_6_PRE_IMPLEMENTATION_MD"
        ),
        "marker_present": True,
        "required_scope_status_after_approval": "PASS",
        "required_authorization_after_approval": (
            "EXPLICIT_BOUNDED_WORK_PACKAGE_ID_LIST"
        ),
        "authorized_work_package_ids": [
            "V06-OP-001",
            "V06-OP-002",
            "V06-OP-003",
            "V06-OP-004",
            "V06-OP-005",
            "V06-OP-006",
            "V06-OP-007",
            "V06-OP-008",
            "V06-OP-009",
        ],
        "automatic_approval_from_REQUEST_OR_TOOL_SUCCESS": False,
    },
    "accepted_baseline": {
        "tag_ref": TAG_REF,
        "tag_object_type": "tag",
        "tag_object_id": TAG_OBJECT_ID,
        "raw_tag_object_sha256": RAW_TAG_OBJECT_SHA256,
        "peeled_release_commit": PEELED_RELEASE_COMMIT,
        "qualified_source_commit": QUALIFIED_SOURCE_COMMIT,
        "tagged_files_sha256": TAGGED_FILES_SHA256,
    },
    "compatibility_delta": {
        "accepted_ir_versions": ["0.3"],
        "new_ir_versions": [],
        "claimed_construct_ids": [],
        "claimed_artifact_ids": [],
        "compatibility_ledger_rows_added": 0,
        "v0_5_scope_rows_changed": 0,
    },
    "proposed_work_packages": WORK_PACKAGES,
    "claims": {
        "v0_5_release_accepted": True,
        "v0_6_program_proposed": True,
        "v0_6_implementation_authorized": True,
        "v0_6_implementation_claimed_by_gate": False,
        "v0_6_release_accepted": False,
        "new_language_surface_claimed": False,
        "operational_authorization": False,
        "deployment_approval": False,
        "compliance_determination": False,
        "cryptographic_signature_verified": False,
    },
    "explicit_exclusions": [
        "SCOPE_BEYOND_V06_OP_001_THROUGH_V06_OP_009",
        "NON_LOCAL_NON_SYNTHETIC_CUI_CLASSIFIED_OR_PRODUCTION_DATA",
        "LIVE_DRIVER_GCS_SPACECRAFT_TELEMETRY_TELECOMMAND_OR_EXTERNAL_EFFECT_ROUTING",
        "ARBITRARY_PYTHON_SOURCE_EXPRESSION_FUNCTION_EVALUATION_OR_SHELL_EXECUTION",
        "UNBOUNDED_INSPECTION_CONSOLE_OR_UNSAFE_VARIABLE_SHARED_DATA_EDIT",
        "ARBITRARY_ASYNCHRONOUS_OR_NON_ALLOWLISTED_USER_ACTIONS",
        "HARD_KILL_OR_CLEAN_EXTERNAL_STATE_INFERENCE_AFTER_SKIP_STOP_ABORT_OR_FAILURE",
        "MUTABLE_LIBRARY_RESOLUTION_OR_UNBOUNDED_PARENT_CHILD_GRAPH",
        "UNREVIEWED_IR_LANGUAGE_API_SCHEMA_DEPENDENCY_OR_COMPATIBILITY_CHANGE",
        "IMPLEMENTATION_OUTSIDE_EXACT_AUTHORIZED_WORK_PACKAGE_CONTRACTS",
        "DEPLOYMENT_OPERATIONAL_COMPLIANCE_OR_CRYPTOGRAPHIC_SIGNATURE_CLAIM",
    ],
}


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


def read_json(path: Path = SCOPE_PATH) -> Any:
    """Read bounded strict UTF-8 JSON, rejecting duplicate/non-finite values."""

    raw = path.read_bytes()
    if len(raw) > 512 * 1024:
        raise ValueError("Gate 0A scope exceeds 512 KiB")
    text = raw.decode("utf-8")
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _format_keys(keys: Iterable[Any]) -> str:
    return ", ".join(sorted((repr(key) for key in keys)))


def exact_value_errors(
    actual: Any,
    expected: Any,
    path: str = "scope",
) -> list[str]:
    """Return a path-oriented exact-type, exact-key, and exact-order diff."""

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
            errors.extend(
                exact_value_errors(actual[key], expected[key], f"{path}.{key}")
            )
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
    proposed = 0
    authorized = 0
    claimed_constructs = 0
    claimed_artifacts = 0
    if isinstance(payload, dict):
        packages = payload.get("proposed_work_packages")
        if isinstance(packages, list):
            proposed = len(packages)
        mechanics = payload.get("approval_mechanics")
        if isinstance(mechanics, dict):
            package_ids = mechanics.get("authorized_work_package_ids")
            if isinstance(package_ids, list):
                authorized = len(package_ids)
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
    """Validate immutable annotated-tag bytes independently of mutable refs."""

    errors: list[str] = []
    if sha256_bytes(raw_tag) != RAW_TAG_OBJECT_SHA256:
        errors.append("v0.5.0 raw tag object SHA-256 differs")

    git_object = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    if hashlib.sha1(git_object).hexdigest() != TAG_OBJECT_ID:
        errors.append("v0.5.0 tag object ID does not match its raw bytes")

    headers, separator, message = raw_tag.partition(b"\n\n")
    if not separator:
        errors.append("v0.5.0 tag object lacks a message boundary")
        return errors
    expected_prefix = [
        f"object {PEELED_RELEASE_COMMIT}".encode("ascii"),
        b"type commit",
        b"tag v0.5.0",
    ]
    if headers.splitlines()[:3] != expected_prefix:
        errors.append("v0.5.0 tag object headers differ")
    try:
        message_lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        errors.append("v0.5.0 tag message is not strict UTF-8")
        return errors
    for marker in REQUIRED_TAG_MARKERS:
        count = message_lines.count(marker)
        if count != 1:
            errors.append(
                f"v0.5.0 tag marker {marker!r} occurs {count} times, expected 1"
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
            timeout=15,
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


def _validate_tagged_file(
    relative_path: str,
    expected_sha256: str,
    workspace_root: Path,
) -> list[str]:
    errors: list[str] = []
    object_spec = f"{PEELED_RELEASE_COMMIT}:{relative_path}"
    object_type = _single_ascii_line(
        run_git(["cat-file", "-t", object_spec], workspace_root).stdout,
        f"tagged object type for {relative_path}",
    )
    if object_type != "blob":
        errors.append(f"tagged baseline path is not a blob: {relative_path}")
        return errors
    tagged_bytes = run_git(["cat-file", "blob", object_spec], workspace_root).stdout
    if sha256_bytes(tagged_bytes) != expected_sha256:
        errors.append(f"tagged baseline SHA-256 differs: {relative_path}")
    return errors


def validate_git_baseline(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    """Validate the accepted tag, ancestry, immutable blobs, and new paths."""

    errors: list[str] = []
    try:
        initial_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", TAG_REF], workspace_root).stdout,
            TAG_REF,
        )
        if initial_ref != TAG_OBJECT_ID:
            errors.append("refs/tags/v0.5.0 does not name the accepted tag object")

        object_type = _single_ascii_line(
            run_git(["cat-file", "-t", TAG_OBJECT_ID], workspace_root).stdout,
            "v0.5.0 tag object type",
        )
        if object_type != "tag":
            errors.append("v0.5.0 is not an annotated tag object")
        raw_tag = run_git(["cat-file", "tag", TAG_OBJECT_ID], workspace_root).stdout
        errors.extend(validate_tag_payload(raw_tag))

        peeled = _single_ascii_line(
            run_git(
                ["rev-parse", "--verify", f"{TAG_REF}^{{commit}}"], workspace_root
            ).stdout,
            "v0.5.0 peeled release commit",
        )
        if peeled != PEELED_RELEASE_COMMIT:
            errors.append("v0.5.0 peeled release commit differs")
        if (
            run_git(
                ["merge-base", "--is-ancestor", PEELED_RELEASE_COMMIT, "HEAD"],
                workspace_root,
                accepted_returncodes=(0, 1),
            ).returncode
            != 0
        ):
            errors.append("accepted v0.5.0 release commit is not an ancestor of HEAD")
        if (
            run_git(
                [
                    "merge-base",
                    "--is-ancestor",
                    QUALIFIED_SOURCE_COMMIT,
                    PEELED_RELEASE_COMMIT,
                ],
                workspace_root,
                accepted_returncodes=(0, 1),
            ).returncode
            != 0
        ):
            errors.append("qualified v0.5 source is not an ancestor of release commit")

        for relative_path, expected_sha256 in TAGGED_FILES_SHA256.items():
            errors.extend(
                _validate_tagged_file(relative_path, expected_sha256, workspace_root)
            )

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
                    f"v0.6 Gate 0A path unexpectedly exists in v0.5.0: {relative_path}"
                )
            current_path = workspace_root / Path(relative_path)
            if not current_path.is_file() or current_path.is_symlink():
                errors.append(
                    f"v0.6 Gate 0A path is missing or not a regular file: {relative_path}"
                )

        final_ref = _single_ascii_line(
            run_git(["show-ref", "--verify", "--hash", TAG_REF], workspace_root).stdout,
            f"final {TAG_REF}",
        )
        if final_ref != initial_ref:
            errors.append("refs/tags/v0.5.0 changed during validation")
    except GitValidationError as exc:
        errors.append(str(exc))
    return errors


def validate_document_lines(lines: list[str]) -> list[str]:
    """Validate the exact accepted document and owner-approval markers."""

    errors: list[str] = []
    title = "# SPELL v0.6 Pre-Implementation Gate 0A"
    first_nonempty = next((line for line in lines if line.strip()), None)
    if first_nonempty != title or lines.count(title) != 1:
        errors.append("SPELL v0.6 Gate 0A title differs")

    required_lines = (
        "| Gate status | `PASS`; `V06-OP-001` through `V06-OP-009` are authorized |",
        "| Owner approval date | 2026-08-15 |",
        "| Authorized work packages | `V06-OP-001` through `V06-OP-009` |",
        "| Scope profile | `LOCAL_SYNTHETIC_NON_CUI_SIMULATOR` |",
        "`V06-GATE-0A PASS` authorizes implementation of exactly `V06-OP-001` through",
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
        work_package_id = f"V06-OP-{index:03d}"
        if not any(line.startswith(f"| `{work_package_id}` |") for line in lines):
            errors.append(f"proposal table is missing {work_package_id}")
    return errors


def validate_document(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    path = workspace_root / PROPOSAL_PATH
    if path.is_symlink():
        return ["SPELL v0.6 Gate 0A record is a symlink"]
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [f"cannot read SPELL v0.6 Gate 0A record: {exc}"]
    if len(raw) > 256 * 1024:
        return ["SPELL v0.6 Gate 0A record exceeds 256 KiB"]
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return ["SPELL v0.6 Gate 0A record is not strict UTF-8"]
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
