#!/usr/bin/env python3
"""Validate the exact SPELL v0.5 Gate 0A authorization and baseline."""

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
    / "v0.5-gate-0a.json"
)

TAG_REF = "refs/tags/v0.4.0"
TAG_OBJECT_ID = "86390c90e8d5f96f872be43274cbc9d789a34c2d"
RAW_TAG_OBJECT_SHA256 = (
    "ae7030aa54ad9c69761ae764c4edd2535b47ae842a2f4f5b4c20aad859fca663"
)
PEELED_COMMIT = "4546d313a2d8f50504b2bc602d56b3b459ca7597"

TAGGED_FILES_SHA256 = {
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

REQUIRED_TAG_MARKERS = (
    "Owner: JC Arcaz",
    "Decision: ACCEPTED",
    "Accepted exceptions: None",
    "Operational authorization: None",
    "Compliance determination: None",
)

POST_BASELINE_ONLY_PATHS = (
    "SPELL_v0.5_Pre-Implementation.md",
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
        "scopes/v0.5-gate-0a.json"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "validate_v05_gate_0a.py"
    ),
    (
        "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/"
        "test_validate_v05_gate_0a.py"
    ),
)

DOCUMENT_MARKERS = {
    "SPELL_v0.5_Pre-Implementation.md": (
        "# SPELL v0.5 Pre-Implementation Gate 0A"
    ),
    "Test_and_Integration.md": "## Version 0.5 Gate 0A Test Plan",
}
ROADMAP_PATH = "PROJECT_ROADMAP.md"
ROADMAP_V05_HEADING = "### v0.5 - Core Language And Deterministic Runtime"
ROADMAP_GATE_HEADING = "#### Current Gate 0A Authorization"
NEWEST_DOCUMENT_HEADINGS = {
    "PROMPT_History.md": (
        "## 2026-08-12 - v0.4.0 Accepted And v0.5 Gate 0A Opened"
    ),
    "VERSION_TIMELINE.md": "## 2026-08-12 - v0.5 Gate 0A",
}
DATED_HEADING_PATTERN = re.compile(r"^## [0-9]{4}-[0-9]{2}-[0-9]{2} - ")

EXPECTED_SCOPE: dict[str, Any] = {
    "schema_version": "ng-spell-v05-gate-0a-scope/1",
    "gate_id": "V05-GATE-0A",
    "status": "PASS",
    "target_increment": "v0.5",
    "target_release": "v0.5.0",
    "scope_profile": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    "decision": {
        "owner": "JC Arcaz",
        "decision_date": "2026-08-12",
        "authorization": "V05-IR-001_ONLY",
        "owner_request": "finish up v0.4 and star v0.5",
        "precondition": "ANNOTATED_V0_4_0_ACCEPTED_RELEASE_TAG_VERIFIED",
    },
    "accepted_baseline": {
        "tag_ref": TAG_REF,
        "tag_object_type": "tag",
        "tag_object_id": TAG_OBJECT_ID,
        "raw_tag_object_sha256": RAW_TAG_OBJECT_SHA256,
        "peeled_commit": PEELED_COMMIT,
        "tagged_files_sha256": TAGGED_FILES_SHA256,
    },
    "compatibility_delta": {
        "accepted_ir_versions": ["0.3"],
        "new_ir_versions": [],
        "claimed_construct_ids": [],
        "claimed_artifact_ids": [],
        "compatibility_ledger_rows_added": 0,
        "v0_4_scope_rows_changed": 0,
    },
    "authorized_work_package": {
        "work_package_id": "V05-IR-001",
        "title": "Existing v0.3 IR fail-closed validation hardening",
        "status": "IMPLEMENTATION_AUTHORIZED",
        "accepted_ir_version": "0.3",
        "authorized_changes": [
            "STRICT_IR_0_3_VALIDATOR_AND_CANONICALIZER",
            "PARSER_OUTPUT_POSTVALIDATION",
            "SUPERVISOR_PERSISTED_IR_PREFLIGHT_BEFORE_GENERATION_OR_PROCESS",
            "WORKER_IR_VERSION_AND_PAYLOAD_PREFLIGHT_BEFORE_WORKER_STARTED",
            "PERSISTED_IR_BYTE_PRESERVATION_WITHOUT_MIGRATION",
            "ADVERSARIAL_AND_GOLDEN_FAIL_CLOSED_TESTS",
        ],
        "failure_boundary": (
            "INVALID_IR_REJECTED_AND_AUDITED_BEFORE_WORKER_PROCESS_CREATION_"
            "WORKER_STARTED_OR_EFFECT"
        ),
        "persistence_policy": "VALIDATE_WITHOUT_REWRITING_STORED_IR_BYTES",
        "planned_test_ids": [
            "V05-IR-001-UNIT",
            "V05-IR-001-PARSER",
            "V05-IR-001-SUPERVISOR",
            "V05-IR-001-WORKER",
            "V05-IR-001-COMPAT",
            "V05-IR-001-ADVERSARIAL",
        ],
    },
    "claims": {
        "v0_4_release_accepted": True,
        "v0_5_implementation_authorized": True,
        "v0_5_implementation_claimed_by_gate": False,
        "v0_5_release_accepted": False,
        "new_language_surface_claimed": False,
        "operational_authorization": False,
        "deployment_approval": False,
        "compliance_determination": False,
        "cryptographic_signature_verified": False,
    },
    "explicit_exclusions": [
        "V0_5_SCOPE_BEYOND_V05_IR_001",
        "NEW_LANGUAGE_CONSTRUCTS_OR_COMPATIBILITY_ARTIFACTS",
        "IR_VERSION_CHANGE_OR_MIGRATION",
        "PERSISTED_IR_REWRITE",
        "UNRESTRICTED_PYTHON_OR_SOURCE_EXECUTION",
        "PUBLIC_API_DATABASE_SCHEMA_FRONTEND_OR_DEPENDENCY_CHANGE",
        "DRIVER_GCS_SPACECRAFT_OR_EXTERNAL_EFFECT_ROUTING",
        "DEPLOYMENT_OPERATIONAL_OR_COMPLIANCE_CLAIM",
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
    """Read strict UTF-8 JSON, rejecting duplicate keys and non-finite values."""

    raw = path.read_bytes()
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
    """Return a bounded path-oriented diff with exact types and key sets."""

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
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected)
        ):
            errors.extend(
                exact_value_errors(
                    actual_item,
                    expected_item,
                    f"{path}[{index}]",
                )
            )
        return errors
    if actual != expected:
        return [f"{path} value differs"]
    return []


def _scope_summary(payload: Any, valid: bool) -> dict[str, Any]:
    work_packages = 0
    claimed_constructs = 0
    claimed_artifacts = 0
    if isinstance(payload, dict):
        if isinstance(payload.get("authorized_work_package"), dict):
            work_packages = 1
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
        "work_packages": work_packages,
        "claimed_constructs": claimed_constructs,
        "claimed_artifacts": claimed_artifacts,
    }


def validate_scope_payload(payload: Any) -> tuple[list[str], dict[str, Any]]:
    errors = exact_value_errors(payload, EXPECTED_SCOPE)
    return errors, _scope_summary(payload, not errors)


def validate_scope(payload: Any) -> list[str]:
    """Compatibility wrapper for callers that need only scope errors."""

    return validate_scope_payload(payload)[0]


def validate_tag_payload(raw_tag: bytes) -> list[str]:
    """Validate the immutable annotated-tag payload independently of Git refs."""

    errors: list[str] = []
    if sha256_bytes(raw_tag) != RAW_TAG_OBJECT_SHA256:
        errors.append("v0.4.0 raw tag object SHA-256 differs")

    git_object = b"tag " + str(len(raw_tag)).encode("ascii") + b"\0" + raw_tag
    if hashlib.sha1(git_object).hexdigest() != TAG_OBJECT_ID:
        errors.append("v0.4.0 tag object ID does not match its raw bytes")

    headers, separator, message = raw_tag.partition(b"\n\n")
    if not separator:
        errors.append("v0.4.0 tag object lacks a message boundary")
        return errors
    header_lines = headers.splitlines()
    expected_prefix = [
        f"object {PEELED_COMMIT}".encode("ascii"),
        b"type commit",
        b"tag v0.4.0",
    ]
    if header_lines[:3] != expected_prefix:
        errors.append("v0.4.0 tag object headers differ")
    try:
        message_lines = message.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        errors.append("v0.4.0 tag message is not strict UTF-8")
        return errors
    for marker in REQUIRED_TAG_MARKERS:
        count = message_lines.count(marker)
        if count != 1:
            errors.append(
                f"v0.4.0 tag marker {marker!r} occurs {count} times, expected 1"
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
    """Run a fixed Git query without shell interpretation or replace objects."""

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
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GitValidationError(f"{label} is not ASCII") from exc
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise GitValidationError(f"{label} did not return exactly one line")
    return lines[0]


def _validate_tagged_file(
    relative_path: str,
    expected_sha256: str,
    workspace_root: Path,
) -> list[str]:
    errors: list[str] = []
    object_spec = f"{PEELED_COMMIT}:{relative_path}"
    object_type = _single_ascii_line(
        run_git(["cat-file", "-t", object_spec], workspace_root).stdout,
        f"tagged object type for {relative_path}",
    )
    if object_type != "blob":
        errors.append(f"tagged baseline path is not a blob: {relative_path}")
        return errors
    tagged_bytes = run_git(
        ["cat-file", "blob", object_spec], workspace_root
    ).stdout
    actual_sha256 = sha256_bytes(tagged_bytes)
    if actual_sha256 != expected_sha256:
        errors.append(f"tagged baseline SHA-256 differs: {relative_path}")

    current_path = workspace_root / Path(relative_path)
    if current_path.is_symlink():
        errors.append(f"working baseline path is a symlink: {relative_path}")
        return errors
    try:
        current_bytes = current_path.read_bytes()
    except OSError as exc:
        errors.append(f"cannot read working baseline path {relative_path}: {exc}")
        return errors
    if current_bytes != tagged_bytes:
        errors.append(
            f"working baseline bytes differ from accepted v0.4.0: {relative_path}"
        )
    if sha256_bytes(current_bytes) != expected_sha256:
        errors.append(f"working baseline SHA-256 differs: {relative_path}")
    return errors


def validate_git_baseline(
    workspace_root: Path = WORKSPACE_ROOT,
) -> list[str]:
    """Validate the annotated tag, its ancestry, and immutable baseline blobs."""

    errors: list[str] = []
    try:
        tag_ref_value = _single_ascii_line(
            run_git(
                ["show-ref", "--verify", "--hash", TAG_REF], workspace_root
            ).stdout,
            TAG_REF,
        )
        if tag_ref_value != TAG_OBJECT_ID:
            errors.append("refs/tags/v0.4.0 does not name the accepted tag object")

        object_type = _single_ascii_line(
            run_git(["cat-file", "-t", TAG_OBJECT_ID], workspace_root).stdout,
            "v0.4.0 tag object type",
        )
        if object_type != "tag":
            errors.append("v0.4.0 is not an annotated tag object")
        raw_tag = run_git(
            ["cat-file", "tag", TAG_OBJECT_ID], workspace_root
        ).stdout
        errors.extend(validate_tag_payload(raw_tag))

        peeled = _single_ascii_line(
            run_git(
                ["rev-parse", "--verify", f"{TAG_REF}^{{commit}}"],
                workspace_root,
            ).stdout,
            "v0.4.0 peeled commit",
        )
        if peeled != PEELED_COMMIT:
            errors.append("v0.4.0 peeled commit differs")
        commit_type = _single_ascii_line(
            run_git(["cat-file", "-t", PEELED_COMMIT], workspace_root).stdout,
            "v0.4.0 peeled object type",
        )
        if commit_type != "commit":
            errors.append("v0.4.0 peeled object is not a commit")

        ancestry = run_git(
            ["merge-base", "--is-ancestor", PEELED_COMMIT, "HEAD"],
            workspace_root,
            accepted_returncodes=(0, 1),
        )
        if ancestry.returncode != 0:
            errors.append("accepted v0.4.0 commit is not an ancestor of HEAD")

        for relative_path, expected_sha256 in TAGGED_FILES_SHA256.items():
            errors.extend(
                _validate_tagged_file(
                    relative_path,
                    expected_sha256,
                    workspace_root,
                )
            )

        for relative_path in POST_BASELINE_ONLY_PATHS:
            listing = run_git(
                ["ls-tree", "-r", "--name-only", "-z", PEELED_COMMIT, "--", relative_path],
                workspace_root,
            ).stdout
            names = [name for name in listing.split(b"\0") if name]
            if names:
                errors.append(
                    f"Gate 0A path unexpectedly exists in accepted v0.4.0: {relative_path}"
                )
            current_path = workspace_root / Path(relative_path)
            if not current_path.is_file() or current_path.is_symlink():
                errors.append(
                    f"Gate 0A path is missing or not a regular file: {relative_path}"
                )

        final_ref_value = _single_ascii_line(
            run_git(
                ["show-ref", "--verify", "--hash", TAG_REF], workspace_root
            ).stdout,
            f"final {TAG_REF}",
        )
        if final_ref_value != tag_ref_value:
            errors.append("refs/tags/v0.4.0 changed during validation")
    except GitValidationError as exc:
        errors.append(str(exc))
    return errors


def _read_controlled_document(
    relative_path: str,
    workspace_root: Path,
) -> tuple[list[str], list[str]]:
    path = workspace_root / Path(relative_path)
    if path.is_symlink():
        return [], [f"controlled document is a symlink: {relative_path}"]
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [], [f"cannot read controlled document {relative_path}: {exc}"]
    try:
        return raw.decode("utf-8").splitlines(), []
    except UnicodeDecodeError:
        return [], [f"controlled document is not strict UTF-8: {relative_path}"]


def validate_document_lines(documents: dict[str, list[str]]) -> list[str]:
    """Validate exact marker placement in an already decoded document set."""

    errors: list[str] = []
    for relative_path, marker in DOCUMENT_MARKERS.items():
        lines = documents.get(relative_path)
        if lines is None:
            errors.append(f"controlled document was not supplied: {relative_path}")
            continue
        count = lines.count(marker)
        if count != 1:
            errors.append(
                f"document marker {marker!r} occurs {count} times in {relative_path}"
            )
        if relative_path == "SPELL_v0.5_Pre-Implementation.md":
            first_nonempty = next((line for line in lines if line.strip()), None)
            if first_nonempty != marker:
                errors.append("SPELL v0.5 Gate 0A heading is not the document title")

    roadmap_lines = documents.get(ROADMAP_PATH)
    if roadmap_lines is None:
        errors.append(f"controlled document was not supplied: {ROADMAP_PATH}")
    else:
        starts = [
            index
            for index, line in enumerate(roadmap_lines)
            if line == ROADMAP_V05_HEADING
        ]
        if len(starts) != 1:
            errors.append("roadmap must contain exactly one v0.5 section")
        else:
            start = starts[0]
            end = next(
                (
                    index
                    for index in range(start + 1, len(roadmap_lines))
                    if roadmap_lines[index].startswith("### ")
                ),
                len(roadmap_lines),
            )
            count = roadmap_lines[start:end].count(ROADMAP_GATE_HEADING)
            if count != 1:
                errors.append(
                    "roadmap v0.5 section must contain exactly one current Gate 0A authorization"
                )

    for relative_path, expected_heading in NEWEST_DOCUMENT_HEADINGS.items():
        lines = documents.get(relative_path)
        if lines is None:
            errors.append(f"controlled document was not supplied: {relative_path}")
            continue
        dated_headings = [line for line in lines if DATED_HEADING_PATTERN.match(line)]
        if not dated_headings:
            errors.append(f"controlled document has no dated entry: {relative_path}")
        elif dated_headings[0] != expected_heading:
            errors.append(f"newest dated entry differs in {relative_path}")
        if lines.count(expected_heading) != 1:
            errors.append(
                f"newest Gate 0A heading must occur exactly once in {relative_path}"
            )
    return errors


def validate_document_markers(
    workspace_root: Path = WORKSPACE_ROOT,
) -> list[str]:
    relative_paths = (
        *DOCUMENT_MARKERS.keys(),
        ROADMAP_PATH,
        *NEWEST_DOCUMENT_HEADINGS.keys(),
    )
    documents: dict[str, list[str]] = {}
    errors: list[str] = []
    for relative_path in dict.fromkeys(relative_paths):
        lines, read_errors = _read_controlled_document(
            relative_path, workspace_root
        )
        errors.extend(read_errors)
        if not read_errors:
            documents[relative_path] = lines
    errors.extend(validate_document_lines(documents))
    return errors


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
    errors.extend(validate_document_markers(workspace_root))
    summary["gate"] = "PASS" if not errors else "FAIL"
    return errors, summary


def main() -> int:
    errors, summary = validate_repository()
    if errors:
        print(
            "gate=FAIL "
            f"work_packages={summary['work_packages']} "
            f"claimed_constructs={summary['claimed_constructs']} "
            f"claimed_artifacts={summary['claimed_artifacts']}"
        )
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("gate=PASS work_packages=1 claimed_constructs=0 claimed_artifacts=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
