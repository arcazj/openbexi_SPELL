"""Gate 0A tests for the nine SPELL v0.9 planning-contract files.

These tests validate planning inputs only. They deliberately make no assertion
that a v0.9 runtime, migration, route, image, or qualification result exists.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "v09"
LEDGER_PATH = (
    ROOT
    / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI"
    / "requirements"
    / "compatibility"
    / "COMPATIBILITY_LEDGER.json"
)

SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_DEVELOPMENT_ENVIRONMENT"
SCOPE_QUALIFIER = "LOCAL_SYNTHETIC_NON_CUI_ONLY"
AUTHORIZATION_BOUNDARY = "V09_DEV_001_THROUGH_V09_DEV_009"
COMMON_ENVELOPE = {
    "release": "v0.9.0",
    "status": "gate_0a_accepted",
    "scope_profile": SCOPE_PROFILE,
    "scope_qualifier_confirmation": SCOPE_QUALIFIER,
    "authorization_boundary": AUTHORIZATION_BOUNDARY,
    "implementation_claim": False,
    "normative_effect": "accepted_planning_contract_only",
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

MATRIX_FILES = {
    "project_workspace.json": "V09-DEV-001",
    "language_services.json": "V09-DEV-002",
    "dictionary_catalog_authoring.json": "V09-DEV-003",
    "semantic_checks.json": "V09-DEV-004",
    "import_export_external_changes.json": "V09-DEV-005",
    "collaboration_history.json": "V09-DEV-006",
    "immutable_bundles.json": "V09-DEV-007",
    "promotion_registry.json": "V09-DEV-008",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(name: str) -> dict[str, Any]:
    payload = json.loads(
        (CONTRACT_ROOT / name).read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {value}")
        ),
    )
    assert isinstance(payload, dict)
    return payload


def selection_digest(values: list[str]) -> str:
    assert len(values) == len(set(values))
    serialized = "".join(f"{value}\n" for value in sorted(values)).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()


def test_exact_inventory_manifest_hashes_and_common_gate_envelope() -> None:
    assert {path.name for path in CONTRACT_ROOT.iterdir()} == {
        "manifest.json",
        *MATRIX_FILES,
    }
    manifest = load("manifest.json")
    assert manifest["matrix_count"] == 8
    assert manifest["file_count"] == 9
    assert manifest["hash_algorithm"] == "sha256"
    for key, value in COMMON_ENVELOPE.items():
        assert manifest[key] == value

    declared = {item["file"]: item for item in manifest["matrices"]}
    assert set(declared) == set(MATRIX_FILES)
    for filename, package_id in MATRIX_FILES.items():
        raw = (CONTRACT_ROOT / filename).read_bytes()
        matrix = load(filename)
        assert hashlib.sha256(raw).hexdigest() == declared[filename]["sha256"]
        assert declared[filename] == {
            "file": filename,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "contract_id": matrix["contract_id"],
            "schema_version": matrix["schema_version"],
            "work_package_id": package_id,
        }
        for key, value in COMMON_ENVELOPE.items():
            assert matrix[key] == value
        assert matrix["work_package_id"] == package_id
        assert matrix["cross_feature_work_package_id"] == "V09-DEV-009"


def test_exact_nine_work_packages_and_45_authoritative_test_ids() -> None:
    manifest = load("manifest.json")
    package_ids = list(EXPECTED_TEST_IDS)
    definitions = manifest["work_package_definitions"]
    assert manifest["work_packages"] == package_ids
    assert [item["id"] for item in definitions] == package_ids
    assert {
        item["id"]: item["test_ids"] for item in definitions
    } == EXPECTED_TEST_IDS
    all_test_ids = [test_id for values in EXPECTED_TEST_IDS.values() for test_id in values]
    assert len(all_test_ids) == len(set(all_test_ids)) == 45
    assert manifest["qualification_identity_authority"] == (
        "work_package_definitions.test_ids"
    )
    assert manifest["cross_feature_qualification_work_package_id"] == "V09-DEV-009"
    for filename, package_id in MATRIX_FILES.items():
        assert load(filename)["qualification_test_ids"] == EXPECTED_TEST_IDS[package_id]


def test_all_164_dev244_rows_are_allocated_and_negative_only_is_not_authorized() -> None:
    manifest = load("manifest.json")
    compatibility = manifest["compatibility_authorization"]
    reviewed_groups = compatibility["reviewed_artifact_ids_by_work_package"]
    authorized_groups = compatibility[
        "implementation_authorized_artifact_ids_by_work_package"
    ]
    assert list(reviewed_groups) == [f"V09-DEV-{index:03d}" for index in range(1, 7)]
    assert list(authorized_groups) == list(reviewed_groups)
    reviewed = [value for values in reviewed_groups.values() for value in values]
    authorized = [value for values in authorized_groups.values() for value in values]
    negative = compatibility["negative_only_artifact_ids"]
    assert len(reviewed) == len(set(reviewed)) == 164
    assert len(negative) == len(set(negative)) == 20
    assert len(authorized) == len(set(authorized)) == 144
    assert set(authorized) == set(reviewed) - set(negative)
    assert not set(authorized) & set(negative)
    assert compatibility["reviewed_artifact_id_count"] == 164
    assert compatibility["negative_only_artifact_id_count"] == 20
    assert compatibility["implementation_authorized_artifact_id_count"] == 144
    assert selection_digest(reviewed) == compatibility["reviewed_artifact_ids_sha256"]
    assert selection_digest(negative) == compatibility["negative_only_artifact_ids_sha256"]
    assert selection_digest(authorized) == compatibility[
        "implementation_authorized_artifact_ids_sha256"
    ]
    assert compatibility["unlisted_artifact_authorized"] is False
    assert compatibility["negative_only_artifact_authorized"] is False

    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    dev_rows = {
        row["ArtifactId"]: row
        for row in ledger["rows"]
        if row["ArtifactId"].startswith("CMP-DEV244-")
    }
    assert len(dev_rows) == 164
    assert set(reviewed) == set(dev_rows)
    assert all(row["Status"] == "DispositionApproved" for row in dev_rows.values())
    assert all(row["TargetIncrement"] == "Deferred" for row in dev_rows.values())
    assert all(row["Disposition"] == "EXCLUDE" for row in dev_rows.values())


def test_manifest_keeps_four_image_boundary_and_zero_implementation_claims() -> None:
    manifest = load("manifest.json")
    deployment = manifest["deployment_matrix"]
    assert deployment == {
        "web_entry_path": "/development.html",
        "frontend_image": "existing frontend image",
        "new_image_authorized": False,
        "sbom_images": ["backend", "driver", "frontend", "proxy"],
        "host_platform": "Windows",
        "container_platform": "pinned Linux containers",
        "browser_projects": ["Chromium Desktop Chrome", "Chromium Pixel 7"],
    }
    assert all(value == [] for value in manifest["claims"].values())
    assert all(value is False for value in manifest["safety_nonclaims"].values())
    assert manifest["identity_and_duties"] == {
        "author_role": "operator",
        "administrative_decision_role": "admin",
        "author_subject_must_differ_from_review_approve_promote_subject": True,
    }


def test_workspace_is_separate_revision_bound_and_runtime_isolated() -> None:
    matrix = load("project_workspace.json")
    surface = matrix["web_surface"]
    assert surface["entry_path"] == "/development.html"
    assert surface["operator_entry_path"] == "/index.html"
    assert surface["separate_document_entry"] is True
    assert surface["operator_console_tab"] is False
    assert surface["runtime_control_components_imported"] is False
    assert surface["shared_mutable_frontend_store"] is False
    rules = matrix["workspace_rules"]
    assert rules["server_managed"] is True
    assert rules["expected_workspace_revision_required"] is True
    assert rules["last_writer_wins"] is False
    assert rules["host_path_disclosed"] is False
    assert rules["symlink_or_reparse_traversal"] is False
    mutation = matrix["mutation_contract"]
    assert mutation["actor_role"] == "operator"
    assert mutation["runtime_catalog_mutation"] is False
    assert mutation["execution_or_schedule_mutation"] is False
    limits = matrix["limits"]
    assert limits["maximum_resource_bytes"] == 16 * 1024 * 1024
    assert limits["maximum_project_bytes"] == 64 * 1024 * 1024


def test_language_dictionary_and_semantic_services_are_data_only_and_nonexecuting() -> None:
    language = load("language_services.json")
    boundary = language["service_boundary"]
    assert boundary["engine"] == "bounded parser and static compiler only"
    assert boundary["network_enabled"] is False
    assert boundary["procedure_imports_executed"] is False
    assert boundary["source_eval_or_exec"] is False
    assert boundary["expression_evaluation"] is False
    assert boundary["host_process_launch"] is False
    assert boundary["python_interpreter_configuration"] is False
    assert language["templates_and_snippets"]["template_language_execution"] is False

    dictionary = load("dictionary_catalog_authoring.json")
    assert dictionary["dictionary_editor"]["source_execution"] is False
    assert dictionary["dictionary_editor"]["host_path_parameter"] is False
    assert dictionary["catalog_views"]["network_resolution"] is False
    assert dictionary["catalog_views"]["telecommand_send_effect"] is False
    assert dictionary["project_metadata"]["forms_mutate_runtime_catalog"] is False

    semantic = load("semantic_checks.json")
    assert semantic["check_scopes"] == ["FILE", "FOLDER", "PROJECT", "CHANGED_SET"]
    job = semantic["job_contract"]
    assert job["cancellation_cooperative_and_bounded"] is True
    assert job["progress_monotonic"] is True
    assert job["partial_results_authoritative"] is False
    assert job["stale_workspace_result_published"] is False
    assert semantic["problems_projection"]["stable_diagnostic_ids"] is True
    assert semantic["problems_projection"]["check_on_save_cancellable"] is True
    assert semantic["library_cache"]["reparse_explicitly_supported"] is True
    assert all(value is False for value in semantic["non_execution"].values())


def test_import_history_and_conflicts_are_bounded_local_and_provider_neutral() -> None:
    exchange = load("import_export_external_changes.json")
    transport = exchange["transport"]
    assert transport["host_path_parameter"] is False
    assert transport["remote_url_parameter"] is False
    assert transport["network_fetch"] is False
    archive = exchange["archive_contract"]
    for key in (
        "duplicate_paths",
        "casefold_collisions",
        "absolute_or_parent_paths",
        "symlink_hardlink_reparse_or_device_entries",
        "encrypted_entries",
        "nested_archives",
        "unknown_entry_type",
    ):
        assert archive[key] == "REJECTED"
    assert exchange["import_transaction"]["all_or_nothing"] is True
    assert exchange["import_transaction"]["partial_import"] is False
    assert exchange["external_change_detection"]["silent_refresh_or_overwrite"] is False

    history = load("collaboration_history.json")
    provider = history["provider_boundary"]
    assert provider["model"] == "provider-neutral server-managed local history"
    assert provider["git_remote"] is False
    assert provider["svn_or_cvs_remote"] is False
    assert provider["network_access"] is False
    assert provider["browser_repository_credentials"] is False
    assert history["history_revision"]["immutable_after_commit"] is True
    assert history["history_revision"]["force_rewrite"] is False
    assert history["diff_contract"]["text_diff"] is True
    assert history["diff_contract"]["dependency_impact"] is True
    assert history["conflict_rules"]["three_way_base_required"] is True
    assert history["conflict_rules"]["silent_automerge"] is False
    assert history["conflict_rules"]["lost_update"] is False


def test_bundles_are_canonical_database_immutable_and_reproducible() -> None:
    matrix = load("immutable_bundles.json")
    builder = matrix["builder_boundary"]
    assert builder["source_execution"] is False
    assert builder["procedure_import_execution"] is False
    assert builder["driver_or_gcs_access"] is False
    assert builder["dependency_fetch"] is False
    assert builder["output_storage"] == "authoritative database blob and manifest rows"
    canonical = matrix["canonical_archive"]
    assert canonical["path_order"] == "ascending UTF-8 byte order"
    assert canonical["duplicate_or_casefold_path"] == "REJECTED"
    assert canonical["digest_algorithm"] == "SHA-256"
    assert "not embedded in the bytes it hashes" in canonical["digest_envelope"]
    assert "bundle_digest" not in matrix["manifest_required_fields"]
    immutable = matrix["database_immutability"]
    assert immutable["primary_identity"] == "bundle_digest"
    assert immutable["digest_location"] == "external atomic database envelope"
    assert immutable["bytes_sha256_equals_identity"] is True
    assert immutable["insert_if_absent_only"] is True
    assert immutable["update_bytes"] is False
    assert immutable["manifest_and_bytes_commit_atomically"] is True
    verification = matrix["verification"]
    assert verification["same_inputs_same_digest"] is True
    assert verification["independent_reproduction_required"] is True
    assert verification["cryptographic_signature_present"] is False
    assert verification["cryptographic_signature_verified"] is False


def test_promotion_is_distinct_subject_local_simulator_only_and_digest_pinned() -> None:
    matrix = load("promotion_registry.json")
    assert matrix["scope"] == {
        "environment": "local-simulator",
        "additional_environment": False,
        "live_gcs": False,
        "spacecraft": False,
        "mission_network": False,
        "telecommand_or_driver_mutation": False,
    }
    assert matrix["states"] == [
        "CANDIDATE",
        "APPROVED",
        "PROMOTED",
        "SUPERSEDED",
        "WITHDRAWN",
    ]
    transitions = {
        (item["from"], item["operation"], item["to"])
        for item in matrix["allowed_transitions"]
    }
    assert transitions == {
        ("CANDIDATE", "APPROVE", "APPROVED"),
        ("APPROVED", "PROMOTE", "PROMOTED"),
        ("PROMOTED", "SUPERSEDE", "SUPERSEDED"),
        ("APPROVED", "WITHDRAW", "WITHDRAWN"),
        ("PROMOTED", "WITHDRAW", "WITHDRAWN"),
        ("SUPERSEDED", "ROLLBACK_PROMOTE", "PROMOTED"),
    }
    duties = matrix["separation_of_duties"]
    assert duties["author_role"] == "operator"
    assert duties["review_approve_promote_role"] == "admin"
    assert duties["author_subject_must_differ_from_administrative_decision_subject"] is True
    assert duties["self_review_or_self_promotion"] is False
    assert matrix["admission"]["existing_bundle_required"] is True
    assert matrix["admission"]["bundle_digest_recomputed"] is True
    assert matrix["admission"]["promotion_rebuilds_bundle"] is False
    assert matrix["transaction"]["decision_registry_audit_and_outbox_atomic"] is True
    runtime = matrix["runtime_admission"]
    assert runtime["v0_9_authoring_managed_new_start_resolves_promoted_digest_only"] is True
    assert runtime["workspace_source"] is False
    assert runtime["history_revision_source"] is False
    assert runtime["unpromoted_v0_9_authored_procedure_available_to_runtime"] is False
    assert matrix["pinning"]["execution_pins_bundle_digest_at_create"] is True
    assert matrix["pinning"]["schedule_pins_bundle_digest_at_create"] is True
    assert matrix["pinning"]["later_promotion_retargets_execution"] is False
    assert matrix["pinning"]["later_promotion_retargets_schedule"] is False


def test_cross_matrix_review_bundle_promotion_chain_is_closed() -> None:
    history = load("collaboration_history.json")
    bundle = load("immutable_bundles.json")
    promotion = load("promotion_registry.json")
    assert history["collaboration"]["author_role"] == "operator"
    assert history["collaboration"]["review_role"] == "admin"
    assert history["collaboration"]["review_subject_must_differ_from_author_subject"] is True
    assert "distinct-subject admin history-revision review" in bundle[
        "builder_boundary"
    ]["input"]
    assert bundle["builder_boundary"]["output_initial_state"] == "CANDIDATE"
    assert bundle["database_immutability"]["primary_identity"] == "bundle_digest"
    assert promotion["admission"]["review_record_verified"] is True
    assert promotion["admission"]["bundle_digest_recomputed"] is True
    assert promotion["rollback"]["overwrite_bundle"] is False
    assert promotion["rollback"]["rewrite_history"] is False


@pytest.mark.parametrize("filename", ["manifest.json", *MATRIX_FILES])
def test_no_contract_claims_runtime_conformance_or_release_acceptance(filename: str) -> None:
    payload = load(filename)
    assert payload["implementation_claim"] is False
    assert payload["normative_effect"] == "accepted_planning_contract_only"
    if "nonclaims" in payload:
        assert all(value is False for value in payload["nonclaims"].values())
