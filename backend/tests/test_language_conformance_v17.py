from __future__ import annotations

import json
import multiprocessing
import queue
import time
from copy import deepcopy
from pathlib import Path

import pytest

from backend.language_conformance_v16 import CASES as V16_CASES
from backend.language_conformance_v17 import (
    CASES, CASESET_SHA256, ALL_SELECTION, COVERAGE_PATH, canonical_bytes, digest,
    coverage_contract, evaluate_fixed_case, execute_selection, expected_image_runner_proof,
    qualify, run_case, validate_report,
)
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError
from backend.ir_v17 import V17ValidationError, validate_ir_v17
from scripts.generate_reference_runner_v17 import OUTPUT, render
from .test_worker_v06 import _next, _start_worker


@pytest.fixture(scope="module")
def complete_report() -> dict:
    return qualify()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_actual_worker_and_closed_runner_agree(case: dict, complete_report: dict) -> None:
    observed = next(row for row in complete_report["cases"] if row["id"] == case["id"])
    assert evaluate_fixed_case(case) == observed


def test_closed_source_registry_preserves_v16_and_inventory() -> None:
    assert CASES[:len(V16_CASES)] == V16_CASES
    assert digest(canonical_bytes(CASES)) == CASESET_SHA256
    contract = coverage_contract()
    assert json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) == contract
    assert len(contract["rows"]) == 763
    assert len({row["id"] for row in contract["rows"]}) == 763
    assert all(not row["whole_artifact_supported"] for row in contract["rows"])
    assert sum(row["status"] == "ADAPTED" for row in contract["rows"]) == 195
    rows = {row["id"]: row for row in contract["rows"]}
    assert rows["CMP-LRM244-SYNTAX-IMPORT"]["gap_reasons"] == ["MISSING_IMPLEMENTATION"]
    assert rows["CMP-LRM244-ERRATUM-PROMPT-FAILURE-MODIFIERS"]["gap_reasons"] == ["MANUAL_CONFLICT"]
    assert rows["CMP-LRM244-FUNCTION-PROMPT"]["gap_reasons"] == ["MISSING_PROOF"]
    assert rows["CMP-LRM244-MODIFIER-NOTIFY"]["gap_reasons"] == ["MISSING_PROOF"]
    assert rows["CMP-LRM244-MODIFIER-NOTIFY"]["implementation"] == "NOT_ASSESSED"
    assert any(row["implementation"] == "NOT_ASSESSED" for row in contract["rows"])


def test_report_observations_qualify_only_complete_explicit_scopes(complete_report: dict) -> None:
    validate_report(complete_report)
    assert complete_report["evidence_kind"] == "REAL_WORKER_AND_PARSER"
    assert {row["id"] for row in complete_report["qualified_scopes"]} == {"V17-CORE", "V17-DISPLAY-PROMPT"}
    assert complete_report["full_compatibility"] is False
    single = qualify("v17-prompt-number")
    assert single["qualified_scopes"] == []


@pytest.mark.parametrize("mutation", ["full", "scope", "missing", "source", "registry", "coverage", "value-type", "prompt-type", "prompt-default", "prompt-missing", "gap-counts", "extra"])
def test_report_rejects_inflated_or_forged_proof(complete_report: dict, mutation: str) -> None:
    report = deepcopy(complete_report)
    prompt = next(row for row in report["cases"] if row["id"] == "v17-prompt-number")
    if mutation == "full": report["full_compatibility"] = True
    elif mutation == "scope": report["qualified_scopes"][0]["whole_artifact_supported"] = True
    elif mutation == "missing": report["cases"].pop()
    elif mutation == "source": report["cases"][0]["source_sha256"] = "0" * 64
    elif mutation == "registry": report["cases_sha256"] = "0" * 64
    elif mutation == "coverage": report["coverage_sha256"] = "0" * 64
    elif mutation == "value-type": prompt["variables"]["answer"] = "2.5"
    elif mutation == "prompt-type": prompt["prompts"][0]["prompt_type"] = "ALPHA"
    elif mutation == "prompt-default": prompt["prompts"][0]["default"] = "2.5"
    elif mutation == "prompt-missing": prompt["prompts"] = []
    elif mutation == "gap-counts": report["gap_reason_counts"]["MISSING_IMPLEMENTATION"] = 0
    else: report["unproved"] = True
    with pytest.raises(ValueError, match="stale, missing or unproved"):
        validate_report(report)


def test_require_full_is_a_failure_even_when_bounded_profile_passes(monkeypatch, complete_report) -> None:
    from scripts import qualify_language_v17
    monkeypatch.setattr(qualify_language_v17, "qualify", lambda _: complete_report)
    monkeypatch.setattr("sys.argv", ["qualify_language_v17", "--require-full"])
    assert qualify_language_v17.main() == 2


@pytest.mark.parametrize("selection", [195, 195 + len(V16_CASES), ALL_SELECTION])
def test_generated_runner_executes_closed_selection_in_actual_worker(monkeypatch, selection) -> None:
    # Frozen v17 generator remains executable as the bundled runner evolves.
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(render())
    assert procedure.ir_version == "0.17" and len(procedure.steps) == 7
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened", timeout=5)
    control.put({"type": "prompt_response", "prompt_id": opened["prompt_id"], "response": selection})
    terminal, seen = _next(output, lambda item: item.get("kind") == "terminal", timeout=30)
    thread.join(timeout=1)
    assert terminal["state"] == "completed" and not thread.is_alive()
    report = next(effect["payload"] for item in seen if item.get("kind") == "step_commit"
                  for effect in item["effects"] if effect["event_type"] == "procedure.language_check_completed")
    assert report["cases_sha256"] == CASESET_SHA256
    assert report["evidence_kind"] == "BOUNDED_PRODUCTION_HELPERS"
    assert len(report["cases"]) == (len(CASES) if selection == ALL_SELECTION else 1)
    assert [row["example_number"] for row in report["adaptations"]] == (list(range(1, 196)) if selection == ALL_SELECTION else [])


@pytest.mark.parametrize("mutation", ["registry", "selection-bool", "selection-large", "arbitrary-source", "target", "ir-version"])
def test_closed_ir_rejects_forged_registry_or_source(mutation) -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(render())
    steps = deepcopy(list(procedure.steps))
    step = next(row for row in steps if row["type"] == "language_check")
    version = "0.17"
    if mutation == "registry": step["cases_sha256"] = "0" * 64
    elif mutation == "selection-bool": step["selection"] = True
    elif mutation == "selection-large": step["selection"] = ALL_SELECTION + 1
    elif mutation == "arbitrary-source": step["source"] = "eval('1+1')"
    elif mutation == "target": step["target"] = "selected_index"
    else: version = "0.16"
    with pytest.raises(ValueError): validate_ir_v17(version, steps)


def test_prompt_projection_preserves_atomic_binding_and_resume_checkpoint() -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source('answer = Prompt("Rate", NUM)\nDisplay("settled")\n')
    steps = list(procedure.steps)
    prompt = next(step for step in steps if step["type"] == "prompt")
    assert prompt["response_target_declaration"] is True
    assert not any(step["type"] == "variable_set" and step.get("name") == "answer" for step in steps)
    position = prompt["index"]
    before = validate_ir_v17("0.17", steps, start_step=position, resume_prompt_id="open", resume_prompt_step=position, checkpoint_variables={})
    assert before.checkpoint_variables == {}
    after = validate_ir_v17("0.17", steps, start_step=position + 1, checkpoint_variables={"answer": 2.5})
    assert after.checkpoint_variables == {"answer": 2.5}
    with pytest.raises(ValueError): validate_ir_v17("0.17", steps, start_step=position, checkpoint_variables={"answer": 0.0})
    with pytest.raises(ValueError): validate_ir_v17("0.17", steps, start_step=position + 1, checkpoint_variables={})


@pytest.mark.parametrize("field,value", [("level", []), ("level", {}), ("message", {}), ("message", 42), ("type", [])])
def test_malformed_display_ir_fails_with_bounded_validation_error(field, value) -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source('Display("")\n')
    steps = deepcopy(list(procedure.steps))
    steps[0][field] = value
    with pytest.raises(ValueError): validate_ir_v17("0.17", steps)


@pytest.mark.parametrize("field,value", [("response_target_type", []), ("response_target_type", "int"),
    ("response_target_declaration", 1), ("response_target", {}), ("prompt_type", [])])
def test_malformed_prompt_ir_fails_with_bounded_validation_error(field, value) -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source('answer = Prompt("Rate", NUM)\nDisplay("settled")\n')
    steps = deepcopy(list(procedure.steps))
    steps[0][field] = value
    with pytest.raises(ValueError): validate_ir_v17("0.17", steps)


def test_multiple_atomic_prompt_projections_map_original_resume_indexes() -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        'first = Prompt("First", NUM)\nsecond = Prompt("Second", ALPHA)\nDisplay("settled")\n')
    steps = list(procedure.steps)
    second = [step for step in steps if step["type"] == "prompt"][1]["index"]
    validated = validate_ir_v17("0.17", steps, start_step=second, resume_prompt_id="second-open",
        resume_prompt_step=second, expected_total_steps=len(steps), checkpoint_variables={"first": 2.5})
    assert validated.steps == steps
    assert validated.checkpoint_variables == {"first": 2.5}
    after = validate_ir_v17("0.17", steps, start_step=second + 1,
        checkpoint_variables={"first": 2.5, "second": "ready"})
    assert after.variable_types == {"first": "float", "second": "str"}
    with pytest.raises(ValueError):
        validate_ir_v17("0.17", steps, start_step=second, resume_prompt_id="second-open",
            resume_prompt_step=second + 1, checkpoint_variables={"first": 2.5})


@pytest.mark.parametrize("seconds", [86400, 86401, 604800])
def test_native_warning_projection_preserves_seven_day_bound_and_legacy_limit(seconds) -> None:
    from backend.ir_v06 import validate_ir_v06
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        f'Prompt("Long warning", Timeout={seconds})\n')
    assert procedure.ir_version == "0.17"
    steps = list(procedure.steps)
    original = deepcopy(steps)
    validated = validate_ir_v17("0.17", steps)
    assert steps == original and validated.steps == original
    assert validated.steps[0]["warning_delay_seconds"] == float(seconds)
    assert validated.steps[0]["response_timeout_seconds"] is None
    legacy = deepcopy(steps)
    legacy[0].pop("prompt_profile")
    if seconds == 86400:
        assert validate_ir_v06("0.6", legacy).steps[0]["warning_delay_seconds"] == 86400.0
    else:
        with pytest.raises(ValueError): validate_ir_v06("0.6", legacy)


def test_native_warning_over_seven_days_is_rejected_before_projection() -> None:
    with pytest.raises(ProcedureValidationError) as caught:
        ProcedureCatalog.__new__(ProcedureCatalog).validate_source('Prompt("Too long", Timeout=604801)\n')
    assert caught.value.diagnostics[0].code == "SPELL935"
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source('Prompt("Limit", Timeout=604800)\n')
    steps = deepcopy(list(procedure.steps))
    steps[0]["warning_delay_seconds"] = 604801.0
    with pytest.raises(ValueError): validate_ir_v17("0.17", steps)


@pytest.mark.parametrize("mutation", ["malformed-integer-node", "overdeep-core-structure"])
def test_real_worker_bounds_core_preflight_errors_before_effects(mutation) -> None:
    from backend.worker import worker_main
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        'value = 2 ** 3\nDisplay("must not run")\n')
    steps = deepcopy(list(procedure.steps))
    expression = steps[0]["expression"]
    if mutation == "malformed-integer-node":
        expression["unexpected"] = True
    else:
        for _ in range(140):
            expression = {"expr": "unary", "operator": "+", "operand": expression}
        steps[0]["expression"] = expression
    context = multiprocessing.get_context("spawn")
    control, output = context.Queue(), context.Queue()
    process = context.Process(target=worker_main, args=("invalid-core-preflight", 1, "0.17",
        steps, 0, "conformance", None, {}, control, output, None, None, False))
    messages = []
    process.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                message = output.get(timeout=0.2)
            except queue.Empty:
                if not process.is_alive():
                    break
                continue
            messages.append(message)
            if message.get("kind") == "terminal":
                break
        process.join(timeout=1)
        assert not process.is_alive() and process.exitcode == 0
        assert messages[-1]["kind"] == "terminal" and messages[-1]["state"] == "failed"
        rejections = [message for message in messages if message.get("kind") == "event"]
        assert len(rejections) == 1
        assert rejections[0]["event_type"] == "worker.ir_rejected"
        assert rejections[0]["payload"]["code"] == "IR_VALIDATION_FAILED"
        assert len(rejections[0]["payload"]["path"]) <= 160
        assert len(rejections[0]["payload"]["message"]) <= 240
        assert not any(message.get("kind") in {"step_commit", "prompt_opened", "safe_point"} for message in messages)
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        control.close()
        output.close()


def test_runner_execution_is_independent_of_source_manual_inventory(monkeypatch) -> None:
    import backend.language_conformance_v16 as inherited
    monkeypatch.setattr(inherited, "INVENTORY_PATH", Path("/absent/manual-inventory.json"))
    _summary, effects = execute_selection(ALL_SELECTION)
    payload = effects[0]["payload"]
    assert payload["full_compatibility"] is False
    assert expected_image_runner_proof()["direct_and_boundary_cases"] == len(payload["cases"])
    assert sum(row["variant_count"] for row in payload["adaptations"]) == 257


@pytest.mark.parametrize("selection", [-1, True, 1.0, "1", ALL_SELECTION + 1])
def test_runner_selection_is_not_arbitrary_code(selection) -> None:
    with pytest.raises(ValueError, match="closed registry"): execute_selection(selection)
