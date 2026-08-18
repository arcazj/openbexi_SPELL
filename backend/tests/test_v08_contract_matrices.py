from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "v08"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE"
AUTHORIZATION_BOUNDARY = "V08_DATA_001_THROUGH_V08_DATA_009"
WORK_PACKAGES = [f"V08-DATA-{index:03d}" for index in range(1, 10)]
MATRIX_FILES = {
    "typed_values.json",
    "catalog_uri_dependency.json",
    "dictionary_exchange.json",
    "data_containers.json",
    "shared_data.json",
    "virtual_files.json",
    "data_api_authorization.json",
    "migration_recovery.json",
}
EXPECTED_TEST_IDS = {
    "V08-DATA-001": [
        "V08-DATA-001-UNIT",
        "V08-DATA-001-TYPE-MATRIX",
        "V08-DATA-001-SERIALIZATION",
        "V08-DATA-001-CORRUPTION",
        "V08-DATA-001-SECURITY",
    ],
    "V08-DATA-002": [
        "V08-DATA-002-UNIT",
        "V08-DATA-002-CONTRACT",
        "V08-DATA-002-GRAPH",
        "V08-DATA-002-RECOVERY",
        "V08-DATA-002-SECURITY",
    ],
    "V08-DATA-003": [
        "V08-DATA-003-UNIT",
        "V08-DATA-003-COMPATIBILITY-GOLDEN",
        "V08-DATA-003-IMPORT-EXPORT",
        "V08-DATA-003-CORRUPTION-RECOVERY",
        "V08-DATA-003-SECURITY",
    ],
    "V08-DATA-004": [
        "V08-DATA-004-UNIT",
        "V08-DATA-004-MATRIX",
        "V08-DATA-004-INTEGRATION",
        "V08-DATA-004-RECOVERY",
        "V08-DATA-004-SECURITY",
    ],
    "V08-DATA-005": [
        "V08-DATA-005-UNIT",
        "V08-DATA-005-INTEGRATION",
        "V08-DATA-005-RACE",
        "V08-DATA-005-RECOVERY",
        "V08-DATA-005-SECURITY",
    ],
    "V08-DATA-006": [
        "V08-DATA-006-UNIT",
        "V08-DATA-006-INTEGRATION",
        "V08-DATA-006-PATH-SECURITY",
        "V08-DATA-006-QUOTA-ATOMICITY",
        "V08-DATA-006-RECOVERY",
    ],
    "V08-DATA-007": [
        "V08-DATA-007-CONTRACT",
        "V08-DATA-007-AUTHORIZATION",
        "V08-DATA-007-IDEMPOTENCY-RACE",
        "V08-DATA-007-AUDIT-OUTBOX",
        "V08-DATA-007-SECURITY",
    ],
    "V08-DATA-008": [
        "V08-DATA-008-SCHEMA",
        "V08-DATA-008-SQLITE",
        "V08-DATA-008-POSTGRES",
        "V08-DATA-008-BACKUP-RESTORE",
        "V08-DATA-008-MIGRATION-ROLLBACK",
    ],
    "V08-DATA-009": [
        "V08-DATA-009-SEMANTIC-GOLDEN",
        "V08-DATA-009-INTEGRATION",
        "V08-DATA-009-FAULT-RECOVERY",
        "V08-DATA-009-LOAD",
        "V08-DATA-009-SECURITY",
    ],
}


def load(name: str) -> dict:
    return json.loads((CONTRACT_ROOT / name).read_text(encoding="utf-8"))


def test_manifest_binds_exact_inventory_hashes_scope_and_nonclaims() -> None:
    manifest = load("manifest.json")
    assert manifest["schema_version"] == "spell.v08.contract-manifest/1"
    assert manifest["contract_id"] == "V08-CONTRACT-MANIFEST"
    assert manifest["release"] == "v0.8.0"
    assert manifest["status"] == "gate_0a_accepted"
    assert manifest["scope_profile"] == SCOPE_PROFILE
    assert manifest["authorization_boundary"] == AUTHORIZATION_BOUNDARY
    assert manifest["implementation_claim"] is False
    assert manifest["normative_effect"] == "accepted_planning_contract_only"
    assert manifest["work_packages"] == WORK_PACKAGES
    assert manifest["matrix_count"] == 8
    assert manifest["file_count"] == 9
    assert manifest["hash_algorithm"] == "sha256"
    assert {item["file"] for item in manifest["matrices"]} == MATRIX_FILES
    assert {path.name for path in CONTRACT_ROOT.glob("*.json")} == MATRIX_FILES | {
        "manifest.json"
    }
    assert manifest["cross_feature_qualification_work_package_id"] == "V08-DATA-009"
    assert all(value == [] for value in manifest["claims"].values())
    assert all(value is False for value in manifest["safety_nonclaims"].values())

    for item in manifest["matrices"]:
        path = CONTRACT_ROOT / item["file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
        matrix = load(item["file"])
        assert matrix["contract_id"] == item["contract_id"]
        assert matrix["schema_version"] == item["schema_version"]
        assert matrix["work_package_id"] == item["work_package_id"]
        assert matrix["release"] == "v0.8.0"
        assert matrix["status"] == "gate_0a_accepted"
        assert matrix["scope_profile"] == SCOPE_PROFILE
        assert matrix["authorization_boundary"] == AUTHORIZATION_BOUNDARY
        assert matrix["implementation_claim"] is False
        assert matrix["normative_effect"] == "accepted_planning_contract_only"
        assert matrix["cross_feature_work_package_id"] == "V08-DATA-009"


def test_manifest_has_exact_nine_packages_45_ids_and_compatibility_selection() -> None:
    manifest = load("manifest.json")
    definitions = manifest["work_package_definitions"]
    assert [item["id"] for item in definitions] == WORK_PACKAGES
    assert {item["id"]: item["test_ids"] for item in definitions} == EXPECTED_TEST_IDS
    test_ids = [test_id for item in definitions for test_id in item["test_ids"]]
    assert len(test_ids) == len(set(test_ids)) == 45

    matrix_ids = {
        matrix["work_package_id"]: matrix["qualification_test_ids"]
        for matrix in (load(name) for name in MATRIX_FILES)
    }
    assert matrix_ids == {
        package: EXPECTED_TEST_IDS[package] for package in WORK_PACKAGES[:8]
    }

    compatibility = manifest["compatibility_authorization"]
    by_package = compatibility["reviewed_artifact_ids_by_work_package"]
    assert list(by_package) == WORK_PACKAGES[:6]
    assert [len(by_package[package]) for package in WORK_PACKAGES[:6]] == [
        6,
        24,
        18,
        14,
        33,
        40,
    ]
    artifact_ids = [item for values in by_package.values() for item in values]
    assert len(artifact_ids) == len(set(artifact_ids)) == 135
    payload = "".join(f"{item}\n" for item in sorted(artifact_ids)).encode("ascii")
    assert compatibility["reviewed_artifact_id_count"] == 135
    assert compatibility["reviewed_artifact_ids_sha256"] == hashlib.sha256(
        payload
    ).hexdigest()
    assert compatibility["reviewed_artifact_ids_sha256"] == (
        "2f59a5b185720d5707dd81ebfa6a9554eaec3dc067fba742f90342a94ff9f8e4"
    )
    negative_only = compatibility["negative_only_artifact_ids"]
    assert negative_only == [
        "CMP-LRM244-FUNCTION-CANDIDATE-CLEARSHAREDDATASCOPE"
    ]
    assert compatibility["negative_only_artifact_id_count"] == 1
    negative_payload = "".join(f"{item}\n" for item in negative_only).encode("ascii")
    assert compatibility["negative_only_artifact_ids_sha256"] == hashlib.sha256(
        negative_payload
    ).hexdigest()
    authorized_by_package = compatibility[
        "implementation_authorized_artifact_ids_by_work_package"
    ]
    assert list(authorized_by_package) == WORK_PACKAGES[:6]
    assert [len(authorized_by_package[package]) for package in WORK_PACKAGES[:6]] == [
        6,
        24,
        18,
        14,
        32,
        40,
    ]
    authorized_ids = sorted(
        item for values in authorized_by_package.values() for item in values
    )
    assert len(authorized_ids) == 134
    assert set(authorized_ids) == set(artifact_ids) - set(negative_only)
    authorized_payload = "".join(f"{item}\n" for item in authorized_ids).encode(
        "ascii"
    )
    assert compatibility["implementation_authorized_artifact_id_count"] == 134
    assert compatibility["implementation_authorized_artifact_ids_sha256"] == hashlib.sha256(
        authorized_payload
    ).hexdigest()
    assert compatibility["implementation_authorized_artifact_ids_sha256"] == (
        "ec133a9f2c1eb44586be52f663e67cb178e913c0a788b6e1283f7cc3b24bbbe6"
    )
    assert compatibility["unlisted_artifact_authorized"] is False
    assert compatibility["negative_only_artifact_authorized"] is False


def test_typed_values_are_closed_bounded_canonical_and_non_executable() -> None:
    matrix = load("typed_values.json")
    assert matrix["envelope"]["closed_world"] is True
    assert matrix["envelope"]["exactly_one_type"] is True
    assert {item["id"] for item in matrix["primitive_types"]} == {
        "NULL",
        "BOOLEAN",
        "INT64",
        "UINT64",
        "DECIMAL",
        "FINITE_DOUBLE",
        "STRING",
        "BYTES",
        "UTC_DATETIME",
        "REL_DURATION",
    }
    assert {item["id"] for item in matrix["composite_types"]} == {"LIST", "MAP"}
    assert matrix["limits"]["maximum_depth"] == 8
    assert matrix["limits"]["maximum_total_nodes"] == 4096
    assert matrix["limits"]["maximum_serialized_utf8_bytes"] == 1048576
    assert matrix["serialization"]["implicit_conversion"] is False
    assert matrix["serialization"]["text_evaluation"] is False
    assert matrix["serialization"]["python_object_deserialization"] is False
    assert matrix["persistence"]["corruption_outcome"] == "CORRUPT_VALUE"


def test_catalog_uris_and_dependency_graph_cannot_escape_or_resolve_networks() -> None:
    matrix = load("catalog_uri_dependency.json")
    assert {item["id"] for item in matrix["catalog_kinds"]} == {
        "SCDB",
        "GDB",
        "PROC",
        "MMD",
        "USER_DICTIONARY",
    }
    uri = matrix["local_uri"]
    assert uri["allowed_schemes"] == ["spell+local"]
    assert uri["authority_component_allowed"] is False
    assert {"file", "http", "https", "gcs", "javascript"} <= set(
        uri["forbidden_schemes"]
    )
    assert matrix["dependency_identity"]["late_binding"] is False
    assert matrix["dependency_identity"]["floating_revision"] is False
    assert matrix["graph_limits"]["maximum_closure_nodes"] == 1024
    legacy = {item["input_scheme"]: item for item in matrix["legacy_uri_mappings"]}
    assert set(legacy) == {"mmd", "usr"}
    assert all(item["network_resolution"] is False for item in legacy.values())
    assert all("pinned content_digest" in item["requires"] for item in legacy.values())
    assert matrix["publication_transaction"]["overwrite_published_revision"] is False
    assert matrix["publication_transaction"]["partial_publication"] is False
    assert all(value is False for value in matrix["nonclaims"].values())


def test_dictionary_exchange_is_atomic_round_trippable_and_non_executable() -> None:
    matrix = load("dictionary_exchange.json")
    assert {item["id"] for item in matrix["formats"]} == {"DB", "IMP"}
    operations = {item["id"]: item for item in matrix["compatibility_operations"]}
    assert set(operations) == {
        "CreateDictionary",
        "LoadDictionary",
        "SaveDictionary",
    }
    assert operations["CreateDictionary"]["accepted_formats"] == ["DB"]
    assert operations["LoadDictionary"]["accepted_formats"] == ["DB", "IMP"]
    assert "complete expected-revision replacement" in operations["LoadDictionary"][
        "effect"
    ]
    assert "UPSERT and DELETE" in operations["LoadDictionary"]["effect"]
    assert operations["SaveDictionary"]["host_path_write"] is False
    assert matrix["document_envelope"]["closed_world"] is True
    assert set(matrix["source_provenance"]["required_fields"]) == {
        "original_media_type",
        "original_byte_length",
        "original_bytes_sha256",
        "canonical_document_sha256",
        "actor_principal_id",
        "caller_binding_kind",
        "caller_binding_digest",
        "received_at_database_time",
    }
    assert "exact bounded source bytes" in matrix["source_provenance"][
        "original_bytes_rule"
    ]
    imp = matrix["imp_record_contract"]
    assert imp["allowed_operations"] == ["UPSERT", "DELETE"]
    assert "value" in imp["upsert_required_fields"]
    assert "value" in imp["delete_forbidden_fields"]
    assert imp["duplicate_target_outcome"] == "DUPLICATE_ENTRY_TARGET"
    assert "ordinal canonical entry_id order" in imp["deterministic_order"]
    assert matrix["caller_binding"]["procedure_runtime_http_session_required"] is False
    assert matrix["import_transaction"]["partial_import"] is False
    assert matrix["import_transaction"]["implicit_type_conversion"] is False
    assert "audit-outbox" in matrix["import_transaction"]["atomicity_rule"]
    assert "round_trip_rule" in matrix["export_snapshot"]
    forbidden = " ".join(matrix["forbidden_content"]).lower()
    assert "eval" in forbidden and "network" in forbidden and "gcs" in forbidden
    assert matrix["corruption_and_recovery"]["corrupt_source_outcome"] == (
        "CORRUPT_DOCUMENT"
    )


def test_data_containers_freeze_args_ivars_types_cas_and_restart() -> None:
    matrix = load("data_containers.json")
    kinds = {item["id"]: item for item in matrix["container_kinds"]}
    assert set(kinds) == {"LOCAL", "ARGS", "IVARS", "DATA_CONTAINER"}
    assert kinds["ARGS"]["mutable"] is False
    assert kinds["IVARS"]["mutable"] is True
    assert matrix["variable_contract"]["implicit_conversion"] is False
    assert matrix["variable_contract"]["expression_value"] is False
    assert matrix["declared_type_mapping"] == {
        "BOOLEAN": "BOOLEAN",
        "LONG": "INT64",
        "FLOAT": "FINITE_DOUBLE",
        "STRING": "STRING",
        "DATETIME": "UTC_DATETIME",
        "RELTIME": "REL_DURATION",
        "mapping_rule": matrix["declared_type_mapping"]["mapping_rule"],
    }
    operations = {item["id"]: item for item in matrix["operation_matrix"]}
    assert set(operations) == {"CREATE", "READ", "SET", "DELETE", "ENUMERATE"}
    assert operations["CREATE"]["kinds"] == ["DATA_CONTAINER"]
    assert "ARGS" not in operations["SET"]["kinds"]
    assert "ARGS" not in operations["DELETE"]["kinds"]
    assert matrix["runtime_container_provisioning"]["public_create"] is False
    assert "compare-and-set" in matrix["data_container_rules"][1]
    assert "latest fully committed checkpoint" in matrix["ivars_rules"][2]
    assert "v0.8-created invocation" in matrix["args_rules"][2]
    assert "v0.6 and v0.7" in matrix["args_rules"][-1]


def test_shared_data_is_authorized_revisioned_atomic_and_race_closed() -> None:
    matrix = load("shared_data.json")
    assert {item["id"] for item in matrix["namespace_scopes"]} == {
        "PROJECT",
        "CONTEXT",
        "EXECUTION",
    }
    assert matrix["namespace_contract"]["default_policy"] == "DENY"
    assert {item["id"] for item in matrix["operations"]} == {
        "CREATE_NAMESPACE",
        "LIST_NAMESPACES",
        "GET",
        "ENUMERATE",
        "PUT",
        "DELETE",
        "CLEAR",
        "DELETE_NAMESPACE",
    }
    operations = {item["id"]: item for item in matrix["operations"]}
    assert "expected namespace revision" in operations["PUT"]["preconditions"]
    assert "expected entry revision or explicit create revision zero" in operations[
        "PUT"
    ]["preconditions"]
    assert "expected namespace revision" in operations["DELETE"]["preconditions"]
    assert "expected entry revision" in operations["DELETE"]["preconditions"]
    assert "expected namespace revision" in operations["CLEAR"]["preconditions"]
    cas = matrix["compare_and_set"]
    assert cas["required_for_every_mutation"] is True
    assert cas["blind_overwrite"] is False
    assert cas["last_writer_wins"] is False
    assert matrix["clear_transaction"]["partial_clear"] is False
    assert matrix["recovery"]["audit_failure"] == "roll back the data mutation"
    assert all(value is False for value in matrix["nonclaims"].values())


def test_virtual_files_enforce_roots_paths_quotas_atomicity_and_no_execution() -> None:
    matrix = load("virtual_files.json")
    assert {item["id"] for item in matrix["virtual_roots"]} == {
        "PROCEDURE_DATA",
        "PROJECT_DATA",
        "EXECUTION_SCRATCH",
    }
    assert all(item["executable"] is False for item in matrix["virtual_roots"])
    assert matrix["root_provisioning"]["public_create_or_retarget"] is False
    assert matrix["root_provisioning"]["host_path_returned_to_client"] is False
    compatibility_types = {
        item["id"]: item for item in matrix["compatibility_types"]
    }
    assert set(compatibility_types) == {"File", "FileHandle"}
    assert compatibility_types["File"]["host_path_exposed"] is False
    assert compatibility_types["FileHandle"]["client_serializable"] is False
    operations = {item["id"]: item for item in matrix["operations"]}
    assert {
        "READ",
        "LIST",
        "OPEN_FILE",
        "CLOSE_FILE",
        "CREATE_DIRECTORY",
        "WRITE",
        "DELETE",
    } == set(operations)
    assert operations["OPEN_FILE"]["compatibility_function"] == "OpenFile"
    assert operations["CLOSE_FILE"]["compatibility_function"] == "CloseFile"
    assert operations["READ"]["compatibility_function"] == "ReadFile"
    assert operations["WRITE"]["compatibility_function"] == "WriteFile"
    handle = matrix["file_handle"]
    assert handle["modes"] == ["READ", "WRITE", "READ_WRITE", "APPEND"]
    assert handle["states"] == ["OPEN", "CLOSED"]
    assert handle["exactly_one_caller_binding_required"] is True
    assert handle["procedure_runtime_http_session_required"] is False
    assert set(handle["caller_binding_alternatives"]) == {
        "HTTP_MUTATION",
        "PROCEDURE_RUNTIME",
    }
    assert "nonnegative byte offset" in handle["cursor"]
    assert "pre-restart tokens return STALE_HANDLE" in handle["restart_rule"]
    assert set(matrix["file_properties"]["properties"]) == {
        "basename",
        "dirname",
        "filename",
        "exists",
        "isdir",
        "isfile",
        "isOpen",
        "canRead",
        "canWrite",
    }
    assert "already-validated virtual path" in matrix["file_properties"][
        "lexical_rule"
    ]
    path = matrix["path_contract"]
    assert path["relative_only"] is True
    assert path["host_path_disclosure"] is False
    forbidden = " ".join(path["forbidden"]).lower()
    assert ".. segment" in forbidden and "reparse point" in forbidden
    quotas = matrix["quotas"]
    assert quotas["maximum_file_bytes"] == 16777216
    assert quotas["maximum_depth"] == 32
    atomic = matrix["atomic_write"]
    assert atomic["same_root_temporary"] is True
    assert atomic["verify_length_and_digest_before_commit"] is True
    assert atomic["partial_visibility"] is False
    capabilities = " ".join(matrix["forbidden_capabilities"]).lower()
    assert "path escape" in capabilities and "execute" in capabilities
    assert "network" in capabilities and "gcs" in capabilities


def test_data_api_is_deny_by_default_strict_idempotent_and_audited() -> None:
    matrix = load("data_api_authorization.json")
    boundary = matrix["api_boundary"]
    assert boundary["base_path"] == "/api/v1/data"
    assert boundary["browser_to_driver_route"] is False
    assert boundary["browser_to_database_route"] is False
    assert boundary["generic_query_or_expression_endpoint"] is False
    assert {item["id"] for item in matrix["resource_families"]} == {
        "CATALOGS",
        "DICTIONARIES",
        "CONTAINERS",
        "SHARED",
        "FILES",
    }
    families = {item["id"]: item for item in matrix["resource_families"]}
    assert "PUBLISH" in families["CATALOGS"]["operations"]
    assert "CREATE" in families["CONTAINERS"]["operations"]
    assert {
        "CREATE_NAMESPACE",
        "LIST_NAMESPACES",
        "DELETE_NAMESPACE",
    } <= set(families["SHARED"]["operations"])
    assert "public API cannot create" in families["FILES"]["root_provisioning"]
    assert [item["role"] for item in matrix["role_floor"]] == [
        "viewer",
        "operator",
        "admin",
    ]
    viewer = next(item for item in matrix["role_floor"] if item["role"] == "viewer")
    assert viewer["mutations"] is False
    mutation = matrix["mutation_contract"]
    assert {
        "X-Spell-Session-Id",
        "X-Spell-Client-Instance-Key-Id",
    } <= set(mutation["required_headers"])
    assert mutation["expected_revision_required"] is True
    assert mutation["strict_schema_required"] is True
    assert mutation["audit_outbox_required"] is True
    assert mutation["blind_retry"] is False
    assert mutation["last_writer_wins"] is False
    binding = matrix["request_binding_contract"]
    assert binding["identity_or_role_authority"] is False
    assert binding["registry_lookup_required"] is False
    procedure = matrix["procedure_service_boundary"]
    assert procedure["http_jwt_or_request_binding_headers_required"] is False
    assert "worker_generation" in procedure["required_binding"]
    assert "deterministic_request_id" in procedure["required_binding"]
    limits = matrix["transport_limits"]
    assert limits["default_json_request_bytes"] == 1048576
    assert limits["dictionary_import_request_bytes"] == 16777216
    assert limits["virtual_file_write_request_bytes"] == 16777216
    assert limits["chunked_or_unknown_length_body"] == "REJECTED"
    assert "original authoritative" in matrix["idempotency"][
        "same_identity_same_digest"
    ]
    idempotency = matrix["idempotency"]
    assert idempotency["states"] == ["PENDING", "COMMITTED"]
    assert idempotency["maximum_client_retry_window_seconds"] == 3600
    assert idempotency["maximum_settlement_records"] == 100000
    assert idempotency["settlement_eviction_or_key_reuse"] is False
    assert "exact bounded request session binding" in idempotency["identity"]
    assert "exact bounded client-instance key binding" in idempotency["identity"]
    assert "disable all data mutations" in idempotency["cap_outcome"]
    order = matrix["authorization_order"]
    assert next(index for index, step in enumerate(order) if "X-Spell-Session-Id" in step) < next(
        index for index, step in enumerate(order) if "idempotency settlement" in step
    )
    assert next(
        index
        for index, step in enumerate(order)
        if "X-Spell-Client-Instance-Key-Id" in step
    ) < next(index for index, step in enumerate(order) if "idempotency settlement" in step)
    audit_outbox = matrix["audit_outbox"]
    assert "commit atomically" in audit_outbox["commit_rule"]
    assert audit_outbox["maximum_audit_records"] == 1000000
    assert audit_outbox["maximum_outbox_records"] == 1000000
    assert audit_outbox["record_eviction"] is False
    assert "disable all data mutations" in audit_outbox["cap_outcome"]
    assert all(value is False for value in matrix["nonclaims"].values())


def test_migration_is_additive_backend_parity_backup_bound_and_rollback_safe() -> None:
    matrix = load("migration_recovery.json")
    migration = matrix["migration"]
    assert migration["id"] == "0007_data_local_service"
    assert migration["requires"] == "0006_observation_conditions"
    assert migration["additive"] is True
    assert migration["sqlite_supported"] is True
    assert migration["postgresql_supported"] is True
    assert migration["existing_v07_table_mutation"] is False
    assert len(matrix["tables"]) == len(set(matrix["tables"])) == 15
    assert "data_schema_fingerprints" in matrix["tables"]
    fingerprint = matrix["schema_fingerprint_record"]
    assert fingerprint["table"] == "data_schema_fingerprints"
    assert "does not add, remove, or alter" in fingerprint["persistence_rule"]
    assert "v0.7 schema_migrations table" in fingerprint["persistence_rule"]
    parity = matrix["backend_parity"]
    assert parity["database_specific_skip_as_proof"] is False
    assert parity["cross_backend_golden_required"] is True
    assert matrix["backup_restore"]["overwrite_live_target"] is False
    assert matrix["backup_restore"]["partial_restore"] is False
    assert matrix["backup_restore"]["postgresql_manual_activation_required"] is True
    assert "separately named isolated database" in matrix["backup_restore"][
        "postgresql_activation"
    ]
    assert "does not authorize database rename" in matrix["backup_restore"][
        "postgresql_activation"
    ]
    rollback = matrix["rollback_policy"]
    assert "exactly the fifteen v0.8 tables" in rollback[
        "empty_unactivated_v08_schema"
    ]
    assert "activated false" in rollback["empty_unactivated_v08_schema"]
    assert "every other v0.8 table has zero rows" in rollback[
        "empty_unactivated_v08_schema"
    ]
    assert rollback["later_migration_present"] == "REJECTED"
    assert rollback["record_drift"] == "REJECTED"
    assert all(value is False for value in matrix["nonclaims"].values())
