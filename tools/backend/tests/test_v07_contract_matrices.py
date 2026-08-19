from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "v07"
WORK_PACKAGES = [f"V07-OBS-{index:03d}" for index in range(1, 10)]
MATRIX_FILES = {
    "time_and_sample_identity.json",
    "condition_engine.json",
    "waitfor_and_scheduling.json",
    "resource_and_lookup_reads.json",
    "limits_and_alarm_state.json",
    "cursor_streams.json",
}
EXPECTED_TEST_IDS = {
    "V07-OBS-001": [
        "V07-OBS-001-UNIT",
        "V07-OBS-001-CONTRACT",
        "V07-OBS-001-CLOCK",
        "V07-OBS-001-RECOVERY",
        "V07-OBS-001-SECURITY",
    ],
    "V07-OBS-002": [
        "V07-OBS-002-UNIT",
        "V07-OBS-002-INTEGRATION",
        "V07-OBS-002-ATOMIC",
        "V07-OBS-002-QUALITY",
        "V07-OBS-002-SECURITY",
    ],
    "V07-OBS-003": [
        "V07-OBS-003-UNIT",
        "V07-OBS-003-MATRIX",
        "V07-OBS-003-CLOCK",
        "V07-OBS-003-RECOVERY",
        "V07-OBS-003-SECURITY",
    ],
    "V07-OBS-004": [
        "V07-OBS-004-UNIT",
        "V07-OBS-004-INTEGRATION",
        "V07-OBS-004-CLOCK",
        "V07-OBS-004-RACE",
        "V07-OBS-004-RECOVERY",
    ],
    "V07-OBS-005": [
        "V07-OBS-005-UNIT",
        "V07-OBS-005-INTEGRATION",
        "V07-OBS-005-CLOCK",
        "V07-OBS-005-RACE",
        "V07-OBS-005-RECOVERY",
    ],
    "V07-OBS-006": [
        "V07-OBS-006-UNIT",
        "V07-OBS-006-INTEGRATION",
        "V07-OBS-006-BOUNDARY",
        "V07-OBS-006-RECOVERY",
        "V07-OBS-006-SECURITY",
    ],
    "V07-OBS-007": [
        "V07-OBS-007-UNIT",
        "V07-OBS-007-MATRIX",
        "V07-OBS-007-QUALITY",
        "V07-OBS-007-RECOVERY",
        "V07-OBS-007-SECURITY",
    ],
    "V07-OBS-008": [
        "V07-OBS-008-UNIT",
        "V07-OBS-008-INTEGRATION",
        "V07-OBS-008-BACKPRESSURE",
        "V07-OBS-008-RECONNECT",
        "V07-OBS-008-SECURITY",
    ],
    "V07-OBS-009": [
        "V07-OBS-009-SEMANTIC-GOLDEN",
        "V07-OBS-009-BROWSER",
        "V07-OBS-009-ACCESSIBILITY",
        "V07-OBS-009-FAULT-RECOVERY",
        "V07-OBS-009-LOAD-SECURITY",
    ],
}


def load(name: str) -> dict:
    return json.loads((CONTRACT_ROOT / name).read_text(encoding="utf-8"))


def matrix_test_ids(matrix: dict) -> dict[str, list[str]]:
    if "work_package_test_ids" in matrix:
        return matrix["work_package_test_ids"]
    return {matrix["work_package_id"]: matrix["qualification_test_ids"]}


def test_manifest_binds_exact_planning_inventory_and_hashes() -> None:
    manifest = load("manifest.json")
    assert manifest["schema_version"] == "spell.v07.contract-manifest/1"
    assert manifest["contract_id"] == "V07-CONTRACT-MANIFEST"
    assert manifest["release"] == "v0.7.0"
    assert manifest["status"] == "gate_0a_accepted"
    assert manifest["implementation_claim"] is False
    assert manifest["normative_effect"] == "accepted_planning_contract_only"
    assert manifest["work_packages"] == WORK_PACKAGES
    assert manifest["hash_algorithm"] == "sha256"
    assert {item["file"] for item in manifest["matrices"]} == MATRIX_FILES
    assert manifest["cross_feature_qualification_work_package_id"] == "V07-OBS-009"
    assert {path.name for path in CONTRACT_ROOT.glob("*.json")} == MATRIX_FILES | {
        "manifest.json"
    }

    claimed = manifest["claims"]
    assert all(value == [] for value in claimed.values())

    for item in manifest["matrices"]:
        path = CONTRACT_ROOT / item["file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
        matrix = load(item["file"])
        assert matrix["contract_id"] == item["contract_id"]
        assert matrix["schema_version"] == item["schema_version"]
        assert matrix["work_package_id"] == item["work_package_id"]
        assert matrix.get("additional_work_package_ids", []) == item.get(
            "additional_work_package_ids", []
        )
        assert matrix["release"] == "v0.7.0"
        assert matrix["status"] == "gate_0a_accepted"
        assert matrix["implementation_claim"] is False
        assert matrix["normative_effect"] == "accepted_planning_contract_only"
        assert matrix["cross_feature_work_package_id"] == "V07-OBS-009"


def test_manifest_has_exact_nine_packages_and_45_planned_test_ids() -> None:
    definitions = load("manifest.json")["work_package_definitions"]
    assert [item["id"] for item in definitions] == WORK_PACKAGES
    assert {item["id"]: item["test_ids"] for item in definitions} == EXPECTED_TEST_IDS
    all_test_ids = [test_id for item in definitions for test_id in item["test_ids"]]
    assert len(all_test_ids) == 45
    assert len(set(all_test_ids)) == 45

    matrix_ids: dict[str, list[str]] = {}
    for name in MATRIX_FILES:
        matrix_ids.update(matrix_test_ids(load(name)))
    assert matrix_ids == {
        package: EXPECTED_TEST_IDS[package] for package in WORK_PACKAGES[:8]
    }


def test_time_and_sample_contract_is_typed_atomic_and_lifecycle_compatible() -> None:
    matrix = load("time_and_sample_identity.json")
    boundary = matrix["service_boundary"]
    assert boundary["rpcs"] == ["GetTime", "GetTM"]
    assert boundary["mutability"] == "READ_ONLY"
    assert boundary["lifecycle_operation_created"] is False
    assert boundary["driver_effect_journal_entry_created"] is False
    assert boundary["v04_driver_infrastructure_service_changed"] is False
    assert boundary["v04_lifecycle_rpc_numbers_changed"] is False
    assert boundary["v04_lifecycle_event_stream_changed"] is False

    get_time = matrix["get_time"]
    assert set(get_time["clock_sources"]) == {
        "SIMULATOR_GCS_TIME",
        "SIMULATOR",
        "HOST_FALLBACK",
    }
    assert "GCS" not in get_time["clock_sources"]
    assert any("outside this gate" in rule for rule in get_time["source_rules"])

    scalar = matrix["scalar_value"]
    assert set(scalar["types"]) == {
        "BOOLEAN",
        "INT64",
        "UINT64",
        "FINITE_DOUBLE",
        "STRING",
        "BYTES",
    }
    assert scalar["json_rules"]["INT64"] == "canonical base-10 string"
    assert {item["id"] for item in matrix["get_tm_modes"]} == {"CURRENT", "NEXT"}
    next_mode = next(item for item in matrix["get_tm_modes"] if item["id"] == "NEXT")
    assert "strictly greater" in next_mode["success"]
    assert "never returns CURRENT" in next_mode["sequence_rule"]

    sample = matrix["telemetry_sample"]
    assert {"raw_value", "engineering_value", "quality", "validity", "freshness"} <= set(
        sample["required_fields"]
    )
    assert "one locked simulator sample" in sample["atomicity_rule"]


def test_condition_engine_is_bounded_atomic_and_cannot_dispatch_effects() -> None:
    matrix = load("condition_engine.json")
    assert matrix["plan_contract"]["arbitrary_code_execution"] is False
    assert matrix["plan_contract"]["generic_expression_strings"] is False
    assert {item["id"] for item in matrix["node_types"]} == {
        "PREDICATE",
        "AND",
        "OR",
    }
    assert set(matrix["comparisons"]) == {"EQ", "NE", "LT", "LE", "GT", "GE"}
    assert "same committed telemetry snapshot cursor" in matrix["atomic_sampling"]["unit"]
    assert "never combined" in matrix["atomic_sampling"]["retry"]
    assert matrix["result_contract"]["external_effect_dispatch"] is False
    assert "cannot authorize or dispatch" in matrix["result_contract"][
        "external_effect_rule"
    ]


def test_waitfor_and_schedule_preserve_deadlines_evidence_and_one_outcome() -> None:
    matrix = load("waitfor_and_scheduling.json")
    wait = matrix["waitfor"]
    assert {item["id"] for item in wait["types"]} == {
        "RELATIVE",
        "ABSOLUTE",
        "TELEMETRY_CONDITION",
    }
    assert set(wait["terminal_states"]).issubset(set(wait["states"]))
    assert "downtime never extends" in wait["restart_rule"]
    assert "Exactly one terminal outcome" in wait["settlement_rule"]

    schedule = matrix["telemetry_schedule"]
    assert schedule["extends_v06_schedule"] is True
    assert schedule["v06_relative_absolute_semantics_changed"] is False
    assert set(schedule["terminal_states"]).issubset(set(schedule["states"]))
    assert "at most one" in schedule["fire_rule"]
    assert "Exactly one" in schedule["one_outcome_rule"]
    assert any(item["id"] == "FIRE_VS_RESTART" for item in schedule["races"])


def test_resource_and_lookup_contract_is_bounded_read_only_and_non_generic() -> None:
    matrix = load("resource_and_lookup_reads.json")
    boundary = matrix["service_boundary"]
    assert boundary["mutability"] == "READ_ONLY"
    assert boundary["live_mission_route"] is False
    assert boundary["legacy_adapter_route"] is False
    assert boundary["generic_query_language"] is False
    assert boundary["arbitrary_filter_string"] is False
    assert {item["id"] for item in matrix["operations"]} == {
        "GetResource",
        "MemoryLookup",
        "TMTCLookup",
    }
    assert all(item["maximum_results"] <= 128 for item in matrix["operations"])
    forbidden = " ".join(matrix["forbidden_effects"]).lower()
    assert "memory write" in forbidden
    assert "telecommand" in forbidden
    assert "lifecycle mutation" in forbidden


def test_limits_and_alarm_matrix_never_clears_on_missing_evidence() -> None:
    matrix = load("limits_and_alarm_state.json")
    boundary = matrix["service_boundary"]
    assert boundary["mutability"] == "READ_ONLY"
    assert boundary["external_effect_dispatch"] is False
    assert boundary["alarm_acknowledgement"] is False
    assert {item["id"] for item in matrix["limit_bands"]} == {
        "HARD_LOW",
        "SOFT_LOW",
        "SOFT_HIGH",
        "HARD_HIGH",
    }
    evaluation = {item["sample_state"]: item["result"] for item in matrix["evaluation_matrix"]}
    assert evaluation["INVALID_OR_UNKNOWN_VALIDITY"] == "INDETERMINATE"
    assert evaluation["STALE_OR_UNKNOWN_FRESHNESS"] == "INDETERMINATE"
    assert evaluation["GAPPED_OR_UNSYNCHRONIZED"] == "INDETERMINATE"
    result = matrix["is_alarmed_result"]
    assert "never NOT_ALARMED" in result["no_sample_rule"]
    assert "never invent a clear" in matrix["transition_projection"]["restart"]


def test_cursor_stream_is_separate_durable_bounded_and_resynchronizable() -> None:
    matrix = load("cursor_streams.json")
    identity = matrix["stream_identity"]
    assert identity["stream"] == "driver.observation"
    assert identity["v04_lifecycle_stream"] == "driver.lifecycle"
    assert identity["shares_v04_lifecycle_outbox"] is False
    assert identity["shares_v04_lifecycle_cursor"] is False
    assert "repeatable committed view" in matrix["snapshot_contract"]["consistency"]
    assert {item["id"] for item in matrix["event_types"]} >= {
        "telemetry.sample_observed",
        "telemetry.freshness_changed",
        "telemetry.gap_detected",
        "driver.time_observed",
        "stream.resync_required",
    }
    assert matrix["backpressure"]["silent_drop"] is False
    assert {item["reason"] for item in matrix["cursor_outcomes"]} == {
        "SEQUENCE_AHEAD_OF_AUTHORITY",
        "CURSOR_UNAVAILABLE",
        "REPLAY_LIMIT_EXCEEDED",
        "CLIENT_QUEUE_OVERFLOW",
        "STREAM_EPOCH_CHANGED",
        "SOURCE_SEQUENCE_GAP",
    }
    assert any("same-epoch available cursor" in rule for rule in matrix["reconnect_restart"])
