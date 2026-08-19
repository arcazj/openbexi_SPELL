#!/usr/bin/env python3
"""Validate the bounded SPELL v0.9 Development Environment Gate 0A."""

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
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from scripts.accepted_v08_release_v09 import (  # noqa: E402
    AcceptedV08ReleaseError,
    V08_ARCHIVE_RELATIVE,
    V08_ARCHIVE_SHA256,
    V08_ARTIFACT_TREE,
    V08_CANDIDATE_COMMIT,
    V08_EVIDENCE_FINGERPRINT,
    V08_PRODUCT_PACKAGE_SHA256,
    V08_QUALIFIED_SOURCE_COMMIT,
    V08_RAW_TAG_SHA256,
    V08_RELEASE_COMMIT,
    V08_SIDECAR_RELATIVE,
    V08_SIDECAR_SHA256,
    V08_SIDECAR_TEXT,
    V08_SOURCE_FINGERPRINT,
    V08_TAGGED_BLOBS,
    V08_TAG_OBJECT,
    V08_TAG_REF,
    V08_WORK_PACKAGE_EVIDENCE_SHA256,
    validate_accepted_v08_release,
)
from scripts.source_fingerprint_v08 import path_has_link_or_reparse_v08  # noqa: E402


SCOPE_PATH = (
    DOC_ROOT
    / "requirements"
    / "compatibility"
    / "scopes"
    / "v0.9-gate-0a.json"
)
PROPOSAL_PATH = "SPELL_v0.9_Pre-Implementation.md"
CONTRACT_DIRECTORY = "contracts/v09"
LEDGER_PATH = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "COMPATIBILITY_LEDGER.json"
)

SCOPE_SHA256 = "c333f458bfb3eb965f59f6d2718eb317bf79c716b89596d746e30b72f6fb8e00"
V08_RAW_TAG_BYTES = 954
V08_RELEASE_TREE = "9f89c60e59711a6555e67e6ab81bfe74c3b29c41"
V08_QUALIFIED_SOURCE_PARENT = "02c35e063125715703922494daa42bbfb7b7154b"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT"
SCOPE_QUALIFIER = "LOCAL_SYNTHETIC_NON_CUI_ONLY"
AUTHORIZATION_BOUNDARY = "V09_DEV_001_THROUGH_V09_DEV_009"
OWNER_REQUEST = "start and complete asap V0.9"
OWNER_APPROVAL_MARKER = "V09-GATE-0A OWNER-APPROVAL: APPROVED"
PASS_MARKER = (
    "gate=PASS authorized_work_packages=9 proposed_work_packages=9 "
    "claimed_constructs=0 claimed_artifacts=0"
)

CONTRACTS_SHA256 = {
    "collaboration_history.json": "fd7c0b5d6ee82ed57b9d23ac816428503987482ff6a53d29a941099b2308ed32",
    "dictionary_catalog_authoring.json": "30976e5b93d40437ed42b2e38371b39603ae81b82be3a703e453083d30b5a090",
    "immutable_bundles.json": "232ab4a2094db8ee1a7bf840401a153b297f9c6e5d3c1924cb0c44e63889637e",
    "import_export_external_changes.json": "6faf3897cdd2baecf193320c42f273c925e783acfeec9bc8fffcda3af039efbd",
    "language_services.json": "628abeade69458149217bd30f5fff8f5810c708fc11eb08ba0d3a1c4379cf97a",
    "manifest.json": "ce27b6b7d84ffbb3663ebee85befa89d1a765adfe2fc5fab7de24401e0d6c6de",
    "project_workspace.json": "1972deab80d78fde2760004fd0a545b62dd2cbc530ea2a12ee29f2d81f32745c",
    "promotion_registry.json": "1e98e28770047af36899c1db6b4db1355f70503ffd030f155f1de680d83f6972",
    "semantic_checks.json": "8cb4fc54b147e54a77d615bd3070068de2f70729d9887664df26557bbf8b8a66",
}

MATRIX_PACKAGES = {
    "project_workspace.json": "V09-DEV-001",
    "language_services.json": "V09-DEV-002",
    "dictionary_catalog_authoring.json": "V09-DEV-003",
    "semantic_checks.json": "V09-DEV-004",
    "import_export_external_changes.json": "V09-DEV-005",
    "collaboration_history.json": "V09-DEV-006",
    "immutable_bundles.json": "V09-DEV-007",
    "promotion_registry.json": "V09-DEV-008",
}

EXPECTED_TEST_IDS = {
    "V09-DEV-001": [
        "V09-DEV-001-CONTRACT",
        "V09-DEV-001-PROJECT-LIFECYCLE",
        "V09-DEV-001-WORKSPACE-RACE",
        "V09-DEV-001-BROWSER",
        "V09-DEV-001-SECURITY",
    ],
    "V09-DEV-002": [
        "V09-DEV-002-PARSER-GOLDEN",
        "V09-DEV-002-EDITOR",
        "V09-DEV-002-COMPLETION",
        "V09-DEV-002-NON-EXECUTION",
        "V09-DEV-002-DETERMINISM",
    ],
    "V09-DEV-003": [
        "V09-DEV-003-SCHEMA",
        "V09-DEV-003-DICTIONARY",
        "V09-DEV-003-CATALOG",
        "V09-DEV-003-REFERENCE",
        "V09-DEV-003-SECURITY",
    ],
    "V09-DEV-004": [
        "V09-DEV-004-UNIT",
        "V09-DEV-004-PROJECT-CHECK",
        "V09-DEV-004-CANCELLATION",
        "V09-DEV-004-PROBLEMS",
        "V09-DEV-004-RECOVERY",
    ],
    "V09-DEV-005": [
        "V09-DEV-005-IMPORT-EXPORT",
        "V09-DEV-005-EXTERNAL-CHANGE",
        "V09-DEV-005-CASE-CONFLICT",
        "V09-DEV-005-PATH-SECURITY",
        "V09-DEV-005-PROVENANCE",
    ],
    "V09-DEV-006": [
        "V09-DEV-006-HISTORY",
        "V09-DEV-006-DIFF",
        "V09-DEV-006-CONFLICT",
        "V09-DEV-006-COLLABORATION-RACE",
        "V09-DEV-006-SECURITY",
    ],
    "V09-DEV-007": [
        "V09-DEV-007-CANONICALIZATION",
        "V09-DEV-007-REPRODUCIBILITY",
        "V09-DEV-007-TAMPER",
        "V09-DEV-007-RETENTION",
        "V09-DEV-007-SECURITY",
    ],
    "V09-DEV-008": [
        "V09-DEV-008-STATE-MACHINE",
        "V09-DEV-008-AUTHORIZATION",
        "V09-DEV-008-TRANSACTION-AUDIT",
        "V09-DEV-008-ROLLBACK-WITHDRAWAL",
        "V09-DEV-008-PINNING",
    ],
    "V09-DEV-009": [
        "V09-DEV-009-SEMANTIC-GOLDEN",
        "V09-DEV-009-INTEGRATION",
        "V09-DEV-009-BROWSER-MATRIX",
        "V09-DEV-009-OFFLINE-PACKAGE",
        "V09-DEV-009-FAULT-RECOVERY",
    ],
}

EXPECTED_PACKAGE_DETAILS = {
    "V09-DEV-001": (
        "Project workspace and separate web surface",
        "SEPARATE_DEVELOPMENT_HTML_SERVER_MANAGED_PROJECT_WORKSPACE_MANIFEST_RESOURCE_LIFECYCLE_OPTIMISTIC_CONCURRENCY_AND_NO_RUNTIME_CONTROL_COUPLING",
    ),
    "V09-DEV-002": (
        "Non-executing procedure language services",
        "PURE_CAPABILITY_ISOLATED_PARSER_EDITOR_LANGUAGE_SERVICES_TEXT_ONLY_SNIPPETS_DETERMINISTIC_DIAGNOSTICS_AND_NO_EXECUTION_NETWORK_DRIVER_OR_GCS_IMPORTS",
    ),
    "V09-DEV-003": (
        "Dictionary and catalog authoring",
        "VERSIONED_DICTIONARY_EDITOR_PINNED_TM_TC_CATALOG_VIEWS_METADATA_FORMS_TYPED_REFERENCES_AND_TEXT_ONLY_GENERATION_WITH_NO_RUNTIME_PUBLICATION",
    ),
    "V09-DEV-004": (
        "Project semantic checks and Problems",
        "PARSER_BASED_FILE_FOLDER_PROJECT_CHANGED_SET_CHECKS_CANCELLABLE_PROGRESS_STABLE_PROBLEMS_REPORTS_LIBRARY_REPARSE_AND_CHECK_ON_SAVE",
    ),
    "V09-DEV-005": (
        "Safe import, export, and external-change handling",
        "BOUNDED_BROWSER_IMPORT_EXPORT_PROVENANCE_EXTERNAL_CHANGE_CASE_RENAME_PATH_ARCHIVE_CONFLICT_HANDLING_AND_NO_HOST_OR_NETWORK_AUTHORITY",
    ),
    "V09-DEV-006": (
        "Provider-neutral local history and collaboration",
        "PROVIDER_NEUTRAL_SERVER_MANAGED_LOCAL_HISTORY_DIFF_EXPLICIT_CONFLICT_RESOLUTION_ADVISORY_COLLABORATION_AND_NO_REMOTE_CREDENTIALS_OR_NETWORK",
    ),
    "V09-DEV-007": (
        "Immutable validated procedure bundles",
        "DATABASE_BACKED_CANONICAL_IMMUTABLE_SHA256_VALIDATED_DATA_ONLY_BUNDLES_REPRODUCIBILITY_TAMPER_REJECTION_RETENTION_AND_NO_SIGNATURE_CLAIM",
    ),
    "V09-DEV-008": (
        "Local simulator promotion registry",
        "DISTINCT_SUBJECT_ADMIN_REVIEW_APPROVAL_LOCAL_SIMULATOR_PROMOTION_ROLLBACK_WITHDRAWAL_AUDIT_OUTBOX_AND_EXECUTION_SCHEDULE_PINNING",
    ),
    "V09-DEV-009": (
        "Cross-feature development acceptance",
        "CROSS_FEATURE_SEMANTIC_BROWSER_ACCESSIBILITY_WINDOWS_LINUX_CONTAINER_OFFLINE_PACKAGE_FAULT_RECOVERY_AND_SECURITY_ACCEPTANCE",
    ),
}

EXTERNAL_AUTHORITIES = {
    "SPELL-DOCUMENTATION/SPELL - Development Environment Manual - 2.4.4.pdf": {
        "sha256": "cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81",
        "size": 2433068,
    },
    "SPELL-DOCUMENTATION/SPELL - Language Reference - 2.4.4.pdf": {
        "sha256": "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3",
        "size": 2284568,
    },
}

TRACKED_SOURCE_INPUTS = {
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/SOURCE_AUTHORITY.md": {
        "object_id": "02234ec4081c5c0d2b5978b6ce96db889c6c42b6",
        "sha256": "259f762bd37e9fe5e6ce5d581c3036cda88c8c2d3da2c399f4870c43c48026a8",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_SOURCE_INVENTORY.json": {
        "object_id": "657583a72d351ee422358112923df7c38aaaf841",
        "sha256": "5c51f1b06f45003cadfe417e9bffc559b381f1e8a20e2bc9c6f7fc160c09c0b7",
    },
    LEDGER_PATH: {
        "object_id": "202612855cbcf59b501044338db203e5250335b2",
        "sha256": "f1d4e20383c81a1109e93b39e2aac04f04b2366e91eae613170488a6acf8458f",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_RECONCILIATION.json": {
        "object_id": "b3719152779ff6d4e09521d4bb498ffbe4446d8b",
        "sha256": "62c8ad5f678ba313330c35d437d0821c5b097955712860a7e7de697d5327bb85",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/V04_COMPATIBILITY_TECHNICAL_REVIEW.json": {
        "object_id": "9e27acf313503719affb674b1f595055212c554a",
        "sha256": "65a0be691ae96814f3fd295ef28f35cd2e17e19ab7b604b45688f89aecc9ed29",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/tools/validate_compatibility.py": {
        "object_id": "bb42e45f3ba4f2fcf8c9ba67d466cf6192694803",
        "sha256": "deacb9961e9e93f87ef63d27c8791ddc12e387da267b06cd73f9325a0cbe3320",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/SYSTEM_REQUIREMENTS.md": {
        "object_id": "f2112b5f52a9554477662463000554396e43432a",
        "sha256": "0ded4e16d27f9fe780e02ae3bed874853380dd67cf3a06bb3af2250e899723b4",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/procedures/AUTHORING_AND_GIT.md": {
        "object_id": "9a282be9b09c4b92146bcacc73add8e7c45c5907",
        "sha256": "6a881c86f7fc42b758a4a2d837f416f60a0bd142e0c386a2cb8b07563599efe6",
    },
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/architecture/decisions/ADR-005-git-promotion-and-immutable-bundles.md": {
        "object_id": "1c8b5f793a4f7ad37f4728bf8ce79be8ecd77fcc",
        "sha256": "02ecbfc339fe9eb16dbcbda042db53f38345e982101863889957f51dff96618a",
    },
}

EXPECTED_DEPLOYMENT_MATRIX = {
    "web_entry_path": "/development.html",
    "frontend_image": "existing frontend image",
    "new_image_authorized": False,
    "sbom_images": ["backend", "driver", "frontend", "proxy"],
    "host_platform": "Windows",
    "container_platform": "pinned Linux containers",
    "browser_projects": ["Chromium Desktop Chrome", "Chromium Pixel 7"],
}

EXPECTED_CLAIMS = {
    "v0_8_release_accepted": True,
    "v0_9_program_proposed": True,
    "v0_9_implementation_authorized": True,
    "v0_9_implementation_claimed_by_gate": False,
    "v0_9_release_accepted": False,
    "development_constructs_implemented": False,
    "product_artifacts_implemented": False,
    "new_container_images_implemented": False,
    "operational_authorization": False,
    "deployment_approval": False,
    "compliance_determination": False,
    "cryptographic_signature_verified": False,
}


class DuplicateJSONKeyError(ValueError):
    """Raised when strict JSON contains a duplicate key."""


class GitValidationError(RuntimeError):
    """Raised when Git object inspection cannot complete exactly."""


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
    return json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} is not a non-symlink regular file")
    if path_has_link_or_reparse_v08(WORKSPACE_ROOT, path):
        raise ValueError(f"{label} has a link or reparse-point component")
    if metadata.st_size > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes")
    return path.read_bytes()


def read_json(path: Path = SCOPE_PATH) -> Any:
    return parse_strict_json(
        _read_regular_file(path, 512 * 1024, "v0.9 Gate 0A scope"),
        "v0.9 Gate 0A scope",
        512 * 1024,
    )


def _selection_digest(artifact_ids: Iterable[str]) -> str:
    values = list(artifact_ids)
    if len(values) != len(set(values)):
        raise ValueError("selection contains duplicate artifact IDs")
    raw = "".join(f"{value}\n" for value in sorted(values)).encode("ascii")
    return sha256_bytes(raw)


def _flatten_groups(groups: dict[str, list[str]]) -> list[str]:
    return [artifact_id for values in groups.values() for artifact_id in values]


def _scope_summary(payload: Any, valid: bool) -> dict[str, Any]:
    packages = payload.get("proposed_work_packages", []) if isinstance(payload, dict) else []
    approval = payload.get("approval_mechanics", {}) if isinstance(payload, dict) else {}
    authorized = approval.get("authorized_work_package_ids", []) if isinstance(approval, dict) else []
    compatibility = payload.get("compatibility_authorization", {}) if isinstance(payload, dict) else {}
    claimed_constructs = compatibility.get("claimed_construct_ids", []) if isinstance(compatibility, dict) else []
    claimed_artifacts = compatibility.get("claimed_artifact_ids", []) if isinstance(compatibility, dict) else []
    return {
        "gate": "PASS" if valid else "FAIL",
        "authorized_work_packages": len(authorized) if isinstance(authorized, list) else -1,
        "proposed_work_packages": len(packages) if isinstance(packages, list) else -1,
        "claimed_constructs": len(claimed_constructs) if isinstance(claimed_constructs, list) else -1,
        "claimed_artifacts": len(claimed_artifacts) if isinstance(claimed_artifacts, list) else -1,
    }


def _expect(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _expected_baseline() -> dict[str, Any]:
    sidecar_ascii = V08_SIDECAR_TEXT.rstrip("\n")
    return {
        "tag_ref": V08_TAG_REF,
        "tag_object_type": "tag",
        "tag_object_id": V08_TAG_OBJECT,
        "raw_tag_object_sha256": V08_RAW_TAG_SHA256,
        "raw_tag_object_bytes": V08_RAW_TAG_BYTES,
        "peeled_release_commit": V08_RELEASE_COMMIT,
        "release_tree": V08_RELEASE_TREE,
        "qualified_source_commit": V08_QUALIFIED_SOURCE_COMMIT,
        "candidate_commit": V08_CANDIDATE_COMMIT,
        "artifact_tree": V08_ARTIFACT_TREE,
        "source_fingerprint_sha256": V08_SOURCE_FINGERPRINT,
        "evidence_fingerprint_sha256": V08_EVIDENCE_FINGERPRINT,
        "product_package_sha256": V08_PRODUCT_PACKAGE_SHA256,
        "work_package_evidence_sha256": V08_WORK_PACKAGE_EVIDENCE_SHA256,
        "tagged_blobs": V08_TAGGED_BLOBS,
        "accepted_artifact_pair": {
            "archive_path": V08_ARCHIVE_RELATIVE,
            "archive_sha256": V08_ARCHIVE_SHA256,
            "sidecar_path": V08_SIDECAR_RELATIVE,
            "sidecar_sha256": V08_SIDECAR_SHA256,
            "sidecar_bytes": len(V08_SIDECAR_TEXT.encode("ascii")),
            "sidecar_ascii": sidecar_ascii,
        },
    }


def _expected_packages() -> list[dict[str, Any]]:
    return [
        {
            "work_package_id": package_id,
            "title": EXPECTED_PACKAGE_DETAILS[package_id][0],
            "status": "IMPLEMENTATION_AUTHORIZED",
            "capability_boundary": EXPECTED_PACKAGE_DETAILS[package_id][1],
            "planned_test_ids": EXPECTED_TEST_IDS[package_id],
        }
        for package_id in EXPECTED_TEST_IDS
    ]


def validate_scope_payload(payload: Any) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["Gate 0A scope is not a JSON object"], _scope_summary(payload, False)
    expected_top_keys = {
        "schema_version",
        "gate_id",
        "status",
        "target_increment",
        "target_release",
        "scope_profile",
        "scope_qualifier_confirmation",
        "decision",
        "approval_mechanics",
        "accepted_baseline",
        "source_authorities",
        "authorization_contracts",
        "compatibility_authorization",
        "deployment_matrix",
        "identity_and_duties",
        "proposed_work_packages",
        "claims",
        "explicit_exclusions",
    }
    _expect(errors, set(payload) == expected_top_keys, "Gate 0A top-level keys differ")
    scalar_values = {
        "schema_version": "ng-spell-v09-gate-0a-scope/1",
        "gate_id": "V09-GATE-0A",
        "status": "PASS",
        "target_increment": "v0.9",
        "target_release": "v0.9.0",
        "scope_profile": SCOPE_PROFILE,
        "scope_qualifier_confirmation": SCOPE_QUALIFIER,
    }
    for key, value in scalar_values.items():
        _expect(errors, type(payload.get(key)) is type(value), f"scope {key} type differs")
        _expect(errors, payload.get(key) == value, f"scope {key} value differs")

    decision = payload.get("decision")
    expected_decision = {
        "owner": "JC Arcaz",
        "proposal_date": "2026-08-18",
        "approval_date": "2026-08-18",
        "authorization": AUTHORIZATION_BOUNDARY,
        "owner_request": OWNER_REQUEST,
        "precondition": "ANNOTATED_V0_8_0_ACCEPTED_RELEASE_TAG_VERIFIED",
        "owner_approval_recorded": True,
    }
    _expect(errors, decision == expected_decision, "scope owner decision differs")

    package_ids = list(EXPECTED_TEST_IDS)
    approval = payload.get("approval_mechanics")
    expected_approval = {
        "pass_validator_marker": PASS_MARKER,
        "required_owner_approval_marker": OWNER_APPROVAL_MARKER,
        "required_marker_location": "STANDALONE_LINE_IN_SPELL_V0_9_PRE_IMPLEMENTATION_MD",
        "marker_present": True,
        "required_scope_status_after_approval": "PASS",
        "required_authorization_after_approval": "EXPLICIT_BOUNDED_WORK_PACKAGE_ID_LIST",
        "authorized_work_package_ids": package_ids,
        "automatic_approval_from_request_or_tool_success": False,
    }
    _expect(errors, approval == expected_approval, "scope approval mechanics differ")
    _expect(errors, payload.get("accepted_baseline") == _expected_baseline(), "accepted v0.8 baseline binding differs")
    _expect(
        errors,
        payload.get("source_authorities")
        == {"external_files": EXTERNAL_AUTHORITIES, "tracked_inputs": TRACKED_SOURCE_INPUTS},
        "source authority bindings differ",
    )
    _expect(
        errors,
        payload.get("authorization_contracts")
        == {
            "directory": CONTRACT_DIRECTORY,
            "matrix_count": 8,
            "file_count": 9,
            "files_sha256": CONTRACTS_SHA256,
        },
        "authorization contract bindings differ",
    )
    _expect(errors, payload.get("deployment_matrix") == EXPECTED_DEPLOYMENT_MATRIX, "four-image deployment matrix differs")
    _expect(
        errors,
        payload.get("identity_and_duties")
        == {
            "author_role": "operator",
            "administrative_decision_role": "admin",
            "author_subject_must_differ_from_review_approve_promote_subject": True,
        },
        "identity and separation-of-duties contract differs",
    )
    _expect(errors, payload.get("proposed_work_packages") == _expected_packages(), "exact 9x5 work-package plan differs")
    _expect(errors, payload.get("claims") == EXPECTED_CLAIMS, "zero-implementation Gate claims differ")

    compatibility = payload.get("compatibility_authorization")
    if not isinstance(compatibility, dict):
        errors.append("compatibility authorization is not an object")
    else:
        reviewed_groups = compatibility.get("reviewed_artifact_ids_by_work_package")
        authorized_groups = compatibility.get("implementation_authorized_artifact_ids_by_work_package")
        negative = compatibility.get("negative_only_artifact_ids")
        if not isinstance(reviewed_groups, dict) or not isinstance(authorized_groups, dict) or not isinstance(negative, list):
            errors.append("compatibility allocation structures differ")
        else:
            reviewed = _flatten_groups(reviewed_groups)
            authorized = _flatten_groups(authorized_groups)
            try:
                _expect(errors, list(reviewed_groups) == package_ids[:6], "reviewed compatibility package order differs")
                _expect(errors, list(authorized_groups) == package_ids[:6], "authorized compatibility package order differs")
                _expect(errors, len(reviewed) == len(set(reviewed)) == 164, "reviewed DEV244 cardinality differs")
                _expect(errors, len(negative) == len(set(negative)) == 20, "negative-only DEV244 cardinality differs")
                _expect(errors, len(authorized) == len(set(authorized)) == 144, "authorized DEV244 cardinality differs")
                _expect(errors, set(authorized) == set(reviewed) - set(negative), "authorized DEV244 set is not reviewed minus negative-only")
                _expect(errors, _selection_digest(reviewed) == "3de9055f35bffc1f7065f2dad452dcbb32e937a0335bdf6ff129c69869ed738e", "reviewed DEV244 digest differs")
                _expect(errors, _selection_digest(negative) == "f1f199ea5a8facbed6bf8226578665c22f6b1de9cfdb4004e72cb167249f7bcb", "negative-only DEV244 digest differs")
                _expect(errors, _selection_digest(authorized) == "22138ab7f4895da9a71af310f85722cff200b7b7693b2f3e0833758fa34fa270", "authorized DEV244 digest differs")
            except (UnicodeEncodeError, ValueError) as exc:
                errors.append(f"cannot validate compatibility allocation: {exc}")
        expected_scalar = {
            "source": LEDGER_PATH,
            "hash_serialization": "globally sorted unique ASCII artifact IDs joined by LF with one final LF",
            "reviewed_artifact_id_count": 164,
            "reviewed_artifact_ids_sha256": "3de9055f35bffc1f7065f2dad452dcbb32e937a0335bdf6ff129c69869ed738e",
            "negative_only_artifact_ids_sha256": "f1f199ea5a8facbed6bf8226578665c22f6b1de9cfdb4004e72cb167249f7bcb",
            "implementation_authorized_artifact_id_count": 144,
            "implementation_authorized_artifact_ids_sha256": "22138ab7f4895da9a71af310f85722cff200b7b7693b2f3e0833758fa34fa270",
            "accepted_persisted_ir_versions": ["0.3", "0.6", "0.7", "0.8"],
            "planned_internal_ir_version": "0.9",
            "claimed_construct_ids": [],
            "claimed_artifact_ids": [],
            "compatibility_ledger_rows_added": 0,
            "v0_8_scope_rows_changed": 0,
            "unlisted_artifact_authorized": False,
            "negative_only_artifact_authorized": False,
        }
        for key, value in expected_scalar.items():
            _expect(errors, compatibility.get(key) == value, f"compatibility {key} differs")
        strengthened = compatibility.get("strengthened_equivalence")
        _expect(
            errors,
            strengthened
            == {
                "import": "bounded browser upload to server quarantine; no caller host path, remote checkout, or network fetch",
                "history": "provider-neutral immutable server-managed local history; no Git, SVN, CVS, or remote credentials",
                "diff": "bounded server-computed source, metadata, dependency, and validation delta",
                "conflict": "revision-bound explicit text, rename, case, metadata, and dependency resolution followed by validation",
            },
            "strengthened legacy equivalents differ",
        )
    exclusions = payload.get("explicit_exclusions")
    _expect(errors, isinstance(exclusions, list) and len(exclusions) == 15, "explicit exclusion inventory differs")
    if isinstance(exclusions, list):
        _expect(errors, len(exclusions) == len(set(exclusions)), "explicit exclusions contain duplicates")
    summary = _scope_summary(payload, not errors)
    return errors, summary


def validate_scope(payload: Any) -> list[str]:
    return validate_scope_payload(payload)[0]


def _common_contract_errors(payload: Any, name: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return [f"v0.9 contract is not an object: {name}"]
    expected = {
        "release": "v0.9.0",
        "status": "gate_0a_accepted",
        "scope_profile": SCOPE_PROFILE,
        "scope_qualifier_confirmation": SCOPE_QUALIFIER,
        "authorization_boundary": AUTHORIZATION_BOUNDARY,
        "implementation_claim": False,
        "normative_effect": "accepted_planning_contract_only",
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            errors.append(f"v0.9 contract {name} {key} differs")
    return errors


def validate_contract_directory(directory: Path | None = None) -> list[str]:
    root = directory or (WORKSPACE_ROOT / CONTRACT_DIRECTORY)
    errors: list[str] = []
    try:
        metadata = root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return ["v0.9 contract directory is not a non-symlink directory"]
        names = sorted(item.name for item in root.iterdir())
    except OSError as exc:
        return [f"cannot inspect v0.9 contract directory: {exc}"]
    if names != sorted(CONTRACTS_SHA256):
        errors.append("v0.9 contract directory inventory differs")
    payloads: dict[str, dict[str, Any]] = {}
    for name, expected_sha in CONTRACTS_SHA256.items():
        try:
            raw = _read_regular_file(root / name, 1024 * 1024, f"v0.9 contract {name}")
            if sha256_bytes(raw) != expected_sha:
                errors.append(f"v0.9 contract SHA-256 differs: {name}")
            payload = parse_strict_json(raw, f"v0.9 contract {name}", 1024 * 1024)
            errors.extend(_common_contract_errors(payload, name))
            if isinstance(payload, dict):
                payloads[name] = payload
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"cannot validate v0.9 contract {name}: {exc}")
    manifest = payloads.get("manifest.json")
    if manifest is None:
        return errors
    package_ids = list(EXPECTED_TEST_IDS)
    definitions = manifest.get("work_package_definitions")
    expected_definitions = []
    for package_id in package_ids:
        definition: dict[str, Any] = {
            "id": package_id,
            "title": EXPECTED_PACKAGE_DETAILS[package_id][0],
            "test_ids": EXPECTED_TEST_IDS[package_id],
        }
        if package_id == "V09-DEV-009":
            definition["cross_feature_contracts"] = list(MATRIX_PACKAGES)
        else:
            definition["contract_file"] = next(
                name for name, value in MATRIX_PACKAGES.items() if value == package_id
            )
        expected_definitions.append(definition)
    _expect(errors, manifest.get("matrix_count") == 8, "manifest matrix count differs")
    _expect(errors, manifest.get("file_count") == 9, "manifest file count differs")
    _expect(errors, manifest.get("work_packages") == package_ids, "manifest work-package order differs")
    _expect(errors, definitions == expected_definitions, "manifest exact 9x5 definitions differ")
    all_test_ids = [value for values in EXPECTED_TEST_IDS.values() for value in values]
    _expect(errors, len(all_test_ids) == len(set(all_test_ids)) == 45, "authoritative qualification IDs are not exact 9x5")
    _expect(errors, manifest.get("qualification_identity_authority") == "work_package_definitions.test_ids", "manifest qualification identity authority differs")
    _expect(errors, manifest.get("deployment_matrix") == EXPECTED_DEPLOYMENT_MATRIX, "manifest four-image boundary differs")
    claims = manifest.get("claims")
    _expect(errors, isinstance(claims, dict) and claims and all(value == [] for value in claims.values()), "manifest contains an implementation or evidence claim")
    nonclaims = manifest.get("safety_nonclaims")
    _expect(errors, isinstance(nonclaims, dict) and nonclaims and all(value is False for value in nonclaims.values()), "manifest safety nonclaims differ")
    declared = manifest.get("matrices")
    declared_map = {item.get("file"): item for item in declared} if isinstance(declared, list) and all(isinstance(item, dict) for item in declared) else {}
    _expect(errors, set(declared_map) == set(MATRIX_PACKAGES), "manifest matrix inventory differs")
    for name, package_id in MATRIX_PACKAGES.items():
        matrix = payloads.get(name)
        if matrix is None:
            continue
        _expect(errors, matrix.get("work_package_id") == package_id, f"{name} work-package binding differs")
        _expect(errors, matrix.get("cross_feature_work_package_id") == "V09-DEV-009", f"{name} cross-feature binding differs")
        _expect(errors, matrix.get("qualification_test_ids") == EXPECTED_TEST_IDS[package_id], f"{name} qualification IDs differ")
        declaration = declared_map.get(name)
        expected_declaration = {
            "file": name,
            "sha256": CONTRACTS_SHA256[name],
            "contract_id": matrix.get("contract_id"),
            "schema_version": matrix.get("schema_version"),
            "work_package_id": package_id,
        }
        _expect(errors, declaration == expected_declaration, f"manifest declaration differs: {name}")
    return errors


def validate_compatibility_selection(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    errors: list[str] = []
    try:
        scope = read_json(workspace_root / SCOPE_PATH.relative_to(WORKSPACE_ROOT))
        compatibility = scope["compatibility_authorization"]
        reviewed = _flatten_groups(compatibility["reviewed_artifact_ids_by_work_package"])
        raw = _read_regular_file(workspace_root / LEDGER_PATH, 8 * 1024 * 1024, "compatibility ledger")
        ledger = parse_strict_json(raw, "compatibility ledger", 8 * 1024 * 1024)
        rows = ledger.get("rows") if isinstance(ledger, dict) else None
        if not isinstance(rows, list):
            return ["compatibility ledger rows are not a list"]
        dev_rows: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            artifact_id = row.get("ArtifactId")
            if isinstance(artifact_id, str) and artifact_id.startswith("CMP-DEV244-"):
                if artifact_id in dev_rows:
                    errors.append(f"compatibility ledger duplicates {artifact_id}")
                dev_rows[artifact_id] = row
        _expect(errors, len(dev_rows) == 164, "compatibility ledger does not contain exactly 164 DEV244 rows")
        _expect(errors, set(reviewed) == set(dev_rows), "Gate allocation does not cover the exact DEV244 ledger inventory")
        for artifact_id, row in dev_rows.items():
            if row.get("SourceHash") != EXTERNAL_AUTHORITIES[
                "SPELL-DOCUMENTATION/SPELL - Development Environment Manual - 2.4.4.pdf"
            ]["sha256"]:
                errors.append(f"DEV244 source hash differs: {artifact_id}")
            if row.get("Status") != "DispositionApproved":
                errors.append(f"DEV244 source status differs: {artifact_id}")
            if row.get("TargetIncrement") != "Deferred" or row.get("Disposition") != "EXCLUDE":
                errors.append(f"historical DEV244 disposition differs: {artifact_id}")
    except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"cannot validate DEV244 compatibility allocation: {exc}")
    return errors


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
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANG": "C"})
    return environment


def run_git(arguments: list[str], workspace_root: Path = WORKSPACE_ROOT, accepted_returncodes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=workspace_root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitValidationError(f"Git inspection failed: {exc}") from exc
    if result.returncode not in accepted_returncodes:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitValidationError(f"git {' '.join(arguments)} failed: {detail}")
    return result


def _single_ascii_line(payload: bytes, label: str) -> str:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise GitValidationError(f"{label} is not ASCII") from exc
    if len(lines) != 1 or not lines[0]:
        raise GitValidationError(f"{label} is not one non-empty line")
    return lines[0]


def validate_git_baseline(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    errors: list[str] = []
    try:
        accepted = validate_accepted_v08_release(workspace_root)
        _expect(errors, accepted.tag_commit == V08_RELEASE_COMMIT, "accepted v0.8 release commit differs")
        release_tree = _single_ascii_line(
            run_git(["rev-parse", f"{V08_RELEASE_COMMIT}^{{tree}}"], workspace_root).stdout,
            "accepted v0.8 release tree",
        )
        _expect(errors, release_tree == V08_RELEASE_TREE, "accepted v0.8 release tree differs")
        qualified = _single_ascii_line(
            run_git(["rev-list", "--parents", "-n", "1", V08_QUALIFIED_SOURCE_COMMIT], workspace_root).stdout,
            "accepted v0.8 qualified-source ancestry",
        ).split()
        _expect(errors, qualified == [V08_QUALIFIED_SOURCE_COMMIT, V08_QUALIFIED_SOURCE_PARENT], "accepted v0.8 qualified-source parent differs")
        ancestor = run_git(
            ["merge-base", "--is-ancestor", V08_RELEASE_COMMIT, "HEAD"],
            workspace_root,
            accepted_returncodes=(0, 1),
        )
        _expect(errors, ancestor.returncode == 0, "accepted v0.8 release is not an ancestor of HEAD")
        for relative, expected in TRACKED_SOURCE_INPUTS.items():
            object_id = _single_ascii_line(
                run_git(["rev-parse", "--verify", f"{V08_RELEASE_COMMIT}:{relative}"], workspace_root).stdout,
                f"accepted source object {relative}",
            )
            _expect(errors, object_id == expected["object_id"], f"accepted source object ID differs: {relative}")
            raw = run_git(["cat-file", "blob", object_id], workspace_root).stdout
            _expect(errors, sha256_bytes(raw) == expected["sha256"], f"accepted source object SHA-256 differs: {relative}")
        for relative, expected in EXTERNAL_AUTHORITIES.items():
            raw = _read_regular_file(workspace_root / relative, int(expected["size"]), f"external authority {relative}")
            _expect(errors, len(raw) == expected["size"], f"external authority size differs: {relative}")
            _expect(errors, sha256_bytes(raw) == expected["sha256"], f"external authority SHA-256 differs: {relative}")
    except (AcceptedV08ReleaseError, GitValidationError, OSError, ValueError) as exc:
        errors.append(f"cannot validate accepted v0.8 baseline: {exc}")
    return errors


def validate_document_lines(lines: list[str]) -> list[str]:
    errors: list[str] = []
    title = "# SPELL v0.9 Pre-Implementation Gate 0A"
    first_nonempty = next((line for line in lines if line.strip()), None)
    _expect(errors, first_nonempty == title and lines.count(title) == 1, "SPELL v0.9 Gate 0A title differs")
    required_lines = (
        "| Gate status | `PASS`; `V09-DEV-001` through `V09-DEV-009` are authorized |",
        "| Owner approval date | 2026-08-18 |",
        f"| Owner request | `{OWNER_REQUEST}` |",
        "| Authorized work packages | `V09-DEV-001` through `V09-DEV-009` |",
        f"| Scope profile | `{SCOPE_PROFILE}` |",
        f"| Scope qualifier confirmation | `{SCOPE_QUALIFIER}` |",
        "| Development entry path | `/development.html` in the existing frontend image |",
        f"| Raw tag-object SHA-256 | `{V08_RAW_TAG_SHA256}` |",
        f"| Accepted `artifacts/v0.8` tree | `{V08_ARTIFACT_TREE}` |",
        OWNER_APPROVAL_MARKER,
        PASS_MARKER,
    )
    for marker in required_lines:
        _expect(errors, lines.count(marker) == 1, f"Gate document marker differs: {marker}")
    for package_id in EXPECTED_TEST_IDS:
        _expect(errors, sum(line.startswith(f"| `{package_id}` |") for line in lines) == 1, f"Gate document work-package row differs: {package_id}")
    for name, digest in CONTRACTS_SHA256.items():
        marker = f"| `contracts/v09/{name}` | `{digest}` |"
        _expect(errors, lines.count(marker) == 1, f"Gate document contract binding differs: {name}")
    _expect(errors, not any("PENDING_CONTRACT_SHA256" in line for line in lines), "Gate document contains a pending contract hash")
    return errors


def validate_document(workspace_root: Path = WORKSPACE_ROOT) -> list[str]:
    try:
        raw = _read_regular_file(workspace_root / PROPOSAL_PATH, 512 * 1024, "SPELL v0.9 Gate 0A record")
        return validate_document_lines(raw.decode("utf-8", errors="strict").splitlines())
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"cannot read SPELL v0.9 Gate 0A record: {exc}"]


def validate_repository(scope_path: Path = SCOPE_PATH, workspace_root: Path = WORKSPACE_ROOT) -> tuple[list[str], dict[str, Any]]:
    try:
        raw_scope = _read_regular_file(scope_path, 512 * 1024, "v0.9 Gate 0A scope")
        payload = parse_strict_json(raw_scope, "v0.9 Gate 0A scope", 512 * 1024)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"cannot load Gate 0A scope: {exc}"], _scope_summary(None, False)
    errors, summary = validate_scope_payload(payload)
    if sha256_bytes(raw_scope) != SCOPE_SHA256:
        errors.append("v0.9 Gate 0A scope raw SHA-256 differs")
    errors.extend(validate_git_baseline(workspace_root))
    errors.extend(validate_contract_directory(workspace_root / CONTRACT_DIRECTORY))
    errors.extend(validate_compatibility_selection(workspace_root))
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
        for error in errors[:75]:
            print(f"ERROR: {error}", file=sys.stderr)
        if len(errors) > 75:
            print(f"ERROR: {len(errors) - 75} additional errors omitted", file=sys.stderr)
        return 1
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
