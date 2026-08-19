from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts" / "v06"
WORK_PACKAGES = [f"V06-OP-{index:03d}" for index in range(1, 10)]
MATRIX_FILES = {
    "command_state.json",
    "inspection_and_actions.json",
    "lease_modes.json",
    "prompt_behavior.json",
    "schedule_behavior.json",
    "startproc_behavior.json",
}
EXECUTION_STATES = {
    "REQUESTED",
    "VALIDATING",
    "ADMISSION_PENDING",
    "LOADING",
    "PAUSED",
    "RUNNING",
    "WAITING",
    "PROMPT",
    "INTERRUPTED",
    "SUSPENDED",
    "RECOVERING",
    "STOPPING",
    "FINISHED",
    "ABORTED",
    "ERROR",
}


def load(name: str) -> dict:
    return json.loads((CONTRACT_ROOT / name).read_text(encoding="utf-8"))


def test_manifest_has_exact_accepted_gate_contract_inventory() -> None:
    manifest = load("manifest.json")
    assert manifest["schema_version"] == "spell.v06.contract-manifest/1"
    assert manifest["release"] == "v0.6.0"
    assert manifest["status"] == "gate_0a_accepted"
    assert manifest["implementation_claim"] is False
    assert manifest["normative_effect"] == "accepted_planning_contract_only"
    assert manifest["work_packages"] == WORK_PACKAGES
    assert {item["file"] for item in manifest["matrices"]} == MATRIX_FILES
    assert manifest["cross_feature_qualification_work_package_id"] == "V06-OP-009"

    for item in manifest["matrices"]:
        matrix = load(item["file"])
        assert matrix["contract_id"] == item["contract_id"]
        assert matrix["schema_version"] == item["schema_version"]
        assert matrix["work_package_id"] == item["work_package_id"]
        assert matrix["release"] == "v0.6.0"
        assert matrix["status"] == "gate_0a_accepted"
        assert matrix["implementation_claim"] is False
        assert matrix["normative_effect"] == "accepted_planning_contract_only"
        assert matrix["cross_feature_work_package_id"] == "V06-OP-009"


def test_command_matrix_is_total_and_rejects_kill() -> None:
    matrix = load("command_state.json")
    assert set(matrix["execution_states"]) == EXECUTION_STATES
    commands = {item["id"]: item for item in matrix["commands"]}
    assert set(commands) == {
        "RUN",
        "STEP",
        "STEP_OVER",
        "PAUSE",
        "SKIP",
        "GOTO",
        "RELOAD",
        "BACKGROUND",
        "STOP",
        "ABORT",
        "RECOVER",
        "KILL",
    }
    for command in commands.values():
        allowed = set(command["allowed_states"])
        rejected = set(command["rejected_states"])
        assert allowed.isdisjoint(rejected)
        assert allowed | rejected == EXECUTION_STATES
        assert command["existing_external_effect_certainty"] == "PRESERVE"
    kill = commands["KILL"]
    assert not kill["allowed_states"]
    assert set(kill["rejected_states"]) == EXECUTION_STATES
    assert kill["clean_external_state_claim"] is False


def test_lease_modes_make_monitor_structurally_read_only() -> None:
    matrix = load("lease_modes.json")
    modes = {item["id"]: item for item in matrix["ownership_modes"]}
    assert set(modes) == {"C", "M", "B"}
    assert modes["C"]["lease_required"] is True
    assert modes["M"]["runtime_mutation"] == "FORBIDDEN"
    assert modes["M"]["prompt_response"] == "FORBIDDEN"
    assert modes["B"]["controller_count"] == "ZERO"
    assert set(matrix["lease_states"]) == {
        "ACTIVE",
        "RELEASED",
        "EXPIRED",
        "REVOKED",
        "TRANSFERRED",
    }
    assert len(matrix["required_lease_fields"]) == len(set(matrix["required_lease_fields"]))


def test_prompt_family_and_single_settlement_are_explicit() -> None:
    matrix = load("prompt_behavior.json")
    prompt_types = {item["id"] for item in matrix["prompt_types"]}
    assert prompt_types == {
        "OK",
        "CANCEL",
        "OK_CANCEL",
        "YES",
        "NO",
        "YES_NO",
        "ALPHA",
        "NUM",
        "DATE",
        "LIST",
    }
    assert matrix["prompt_states"] == ["CREATED", "OPEN", "SETTLED"]
    assert set(matrix["validation_profiles"]) == {
        "FIXED_CHOICE",
        "TEXT",
        "NUMBER",
        "DATE",
        "LIST",
    }
    raw = json.dumps(matrix, sort_keys=True)
    assert "exactly one" in raw.lower() or "one winning" in raw.lower()
    assert "CONTROLLER_LOST" in raw


def test_schedule_contract_is_one_shot_and_restart_stable() -> None:
    matrix = load("schedule_behavior.json")
    assert {item["id"] for item in matrix["schedule_types"]} == {"RELATIVE", "ABSOLUTE"}
    assert {item["id"] for item in matrix["explicitly_deferred_types"]} == {
        "TELEMETRY_CONDITION",
        "RECURRING",
    }
    assert matrix["clock_policy"]["authority"] == "database UTC time"
    assert "never add restart downtime" in matrix["clock_policy"]["restart"]
    assert set(matrix["terminal_states"]).issubset(set(matrix["states"]))


def test_inspection_actions_and_startproc_forbid_code_execution() -> None:
    inspection = load("inspection_and_actions.json")
    assert set(inspection["execution_states"]) == EXECUTION_STATES
    assert {item["id"] for item in inspection["views"]} == {
        "SOURCE",
        "TEXT",
        "AS_RUN",
        "SUPPORT_LOG",
        "OUTLINE",
        "SEARCH",
        "NESTED_PROCEDURE",
    }
    assert {
        "EXPRESSION_EVALUATION",
        "FUNCTION_EVALUATION",
        "PROCEDURE_SCOPE_SHELL",
        "ARBITRARY_PYTHON",
        "IMPORT",
        "FILE_IO",
        "NETWORK_IO",
        "PROCESS_CONTROL",
    } == set(inspection["console_forbidden_capabilities"])

    startproc = load("startproc_behavior.json")
    assert startproc["limits"]["maximum_depth"] == 8
    assert len(startproc["mode_matrix"]) == 8
    assert len({item["id"] for item in startproc["mode_matrix"]}) == 8
    assert startproc["cycle_policy"]["effect"] == (
        "No child ExecutionId or capacity reservation is created."
    )
    assert {"expressions", "callables", "source evaluation"}.issubset(
        set(startproc["argument_policy"]["forbidden"])
    )
