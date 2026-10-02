from __future__ import annotations

import json
import multiprocessing
import time
from copy import deepcopy
from pathlib import Path

import pytest

from backend.language_conformance_v16 import (
    CASES, COVERAGE_PATH, coverage_contract, qualify, run_case, source_inventory, validate_report,
    evaluate_fixed_case, execute_selection,
)
from backend.procedure_parser import ProcedureCatalog, ProcedureValidationError
from scripts.generate_reference_runner_v10 import ALL_INDEX, DIRECT_CASES, OUTPUT, render
from .test_worker_v06 import _next, _start_worker


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_direct_source_and_rejection_oracles(case: dict) -> None:
    result = run_case(case)
    assert result["passed"] is True
    assert result["source_sha256"] == case["source_sha256"]
    assert evaluate_fixed_case(case) == result


def test_inventory_covers_every_source_artifact_without_claiming_full_support() -> None:
    contract = coverage_contract()
    assert json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) == contract
    assert {row["id"] for row in contract["rows"]} == {row["ArtifactId"] for row in source_inventory()}
    assert len(contract["rows"]) == 763
    assert contract["full_compatibility"] is False
    assert sum(row["status"] == "ADAPTED" for row in contract["rows"]) == 195
    by_id = {row["id"]: row for row in contract["rows"]}
    assert by_id["CMP-LRM244-SYNTAX-IMPORT"]["status"] == "GAP"
    assert by_id["CMP-LRM244-FUNCTION-DISPLAY"]["status"] == "PARTIAL"
    assert len(contract["defaults"]["typical_values"]) == 21


@pytest.fixture(scope="module")
def complete_report() -> dict:
    return qualify()


def test_complete_report_validates(complete_report: dict) -> None:
    validate_report(complete_report)


@pytest.mark.parametrize("mutation", ["full", "counts", "missing", "case-source", "logs", "rejection", "selection", "extra", "default-count"])
def test_report_validator_rejects_forged_or_stale_claims(complete_report: dict, mutation: str) -> None:
    report = deepcopy(complete_report)
    if mutation == "full":
        report["full_compatibility"] = True
    elif mutation == "counts":
        report["coverage_counts"]["GAP"] = 0
    elif mutation == "missing":
        report["cases"].pop()
    elif mutation == "case-source":
        report["cases"][0]["source_sha256"] = "0" * 64
    elif mutation == "logs":
        report["cases"][0]["logs"] = []
    elif mutation == "rejection":
        report["cases"][-1]["diagnostic"] = None
    elif mutation == "selection":
        report["selection"] = "scalar-inference"
    elif mutation == "default-count":
        report["unqualified_default_count"] = 0
    else:
        report["unproved"] = True
    with pytest.raises(ValueError, match="stale, missing or unproved"):
        validate_report(report)


@pytest.mark.parametrize("source", [
    'if False:\n    value = 2\nDisplay("later")\n',
    'def create():\n    value = 2\ncreate()\nDisplay("later")\n',
    'def WARNING():\n    Display("shadow")\nWARNING()\n',
    'Display("text", **{})\n',
    'a, b = 1, 2\nDisplay("text")\n',
    'value = value + 1\nDisplay("text")\n',
])
def test_inference_and_display_keep_source_boundaries(source: str) -> None:
    with pytest.raises(ProcedureValidationError):
        ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source)


def test_cli_full_support_gate_fails_even_when_profile_passes(monkeypatch: pytest.MonkeyPatch, complete_report: dict) -> None:
    from scripts import qualify_language_v16
    monkeypatch.setattr(qualify_language_v16, "qualify", lambda _: complete_report)
    monkeypatch.setattr("sys.argv", ["qualify_language_v16", "--require-full"])
    assert qualify_language_v16.main() == 2


@pytest.mark.parametrize("selection", [195, ALL_INDEX], ids=["individual-direct", "run-all"])
def test_generated_procedure_executes_direct_cases_and_reports_gaps(monkeypatch: pytest.MonkeyPatch, selection: int) -> None:
    assert OUTPUT.read_text(encoding="ascii") == render()
    procedure = ProcedureCatalog(OUTPUT.parent).get("language_reference_244")
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened", timeout=5)
    control.put({"type": "prompt_response", "prompt_id": opened["prompt_id"], "response": selection})
    terminal, seen = _next(output, lambda item: item.get("kind") == "terminal", timeout=10)
    thread.join(timeout=1)
    assert terminal["state"] == "completed"
    assert not thread.is_alive()
    effects = [effect for message in seen if message.get("kind") == "step_commit" for effect in message.get("effects", [])]
    messages = [effect["payload"]["message"] for effect in effects if effect["event_type"] == "procedure.log"]
    report = next(effect["payload"] for effect in effects if effect["event_type"] == "procedure.language_check_completed")
    expected = DIRECT_CASES if selection == ALL_INDEX else DIRECT_CASES[:1]
    assert [case["id"] for case in report["cases"]] == [case["id"] for case in expected]
    assert all(case["passed"] for case in report["cases"])
    assert report["full_compatibility"] is False
    assert any("full support: false" in message for message in messages)
    examples = [example["example_number"] for example in report["adaptations"]]
    assert examples == (list(range(1, 196)) if selection == ALL_INDEX else [])


@pytest.mark.parametrize("mutation", ["digest", "selection-type", "selection-negative", "selection-large", "expression", "target", "extra", "index"])
def test_closed_ir_rejects_tampering(mutation: str) -> None:
    from backend.ir_v16 import validate_ir_v16, V16ValidationError
    procedure = ProcedureCatalog(OUTPUT.parent).get("language_reference_244")
    steps = deepcopy(list(procedure.steps))
    step = next(s for s in steps if s["type"] == "language_check")
    if mutation == "digest":
        step["cases_sha256"] = "0" * 64
    elif mutation == "selection-type":
        step["selection"] = True
    elif mutation == "selection-negative":
        step["selection"] = -1
    elif mutation == "selection-large":
        step["selection"] = ALL_INDEX + 1
    elif mutation == "expression":
        step["selection"] = {"expr": "call", "name": "eval"}
    elif mutation == "target":
        step["target"] = "selected_index"
    elif mutation == "index":
        step["index"] = 200
    else:
        step["source"] = "untrusted"
    with pytest.raises(V16ValidationError.__bases__[0]):
        validate_ir_v16("0.16", steps)


@pytest.mark.parametrize("selection", [-1, ALL_INDEX + 1, True, 1.0, "1"])
def test_runtime_selection_is_closed(selection) -> None:
    with pytest.raises(ValueError, match="closed registry"):
        execute_selection(selection)


def test_selection_checkpoint_can_resume_after_worker_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    procedure = ProcedureCatalog(OUTPUT.parent).get("language_reference_244")
    position = next(s["index"] for s in procedure.steps if s["type"] == "language_check")
    checkpoint = {"selected_index": ALL_INDEX, "example_number": ALL_INDEX + 1, "result": "not run"}
    # Kill a real isolated worker while it awaits the durable safe-point ack.
    from backend.worker import worker_main
    context = multiprocessing.get_context("spawn")
    control_queue, output_queue = context.Queue(), context.Queue()
    process = context.Process(target=worker_main, args=("lost-check", 1, procedure.ir_version,
        list(procedure.steps), position, "recover", None, checkpoint, control_queue, output_queue, None, None, True))
    process.start()
    try:
        deadline = time.monotonic() + 10
        while True:
            assert time.monotonic() < deadline
            message = output_queue.get(timeout=2)
            if message.get("kind") == "safe_point":
                assert message["step_index"] == position
                break
        process.terminate()
        process.join(timeout=2)
        assert not process.is_alive() and process.exitcode != 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        control_queue.close()
        output_queue.close()
    reports = []
    for generation in range(2):
        thread, _control, output = _start_worker(monkeypatch, procedure, start_step=position,
            checkpoint_variables=checkpoint, execution_id=f"recovery-{generation}")
        terminal, seen = _next(output, lambda item: item.get("kind") == "terminal", timeout=10)
        thread.join(timeout=1)
        assert terminal["state"] == "completed" and not thread.is_alive()
        reports.append(next(effect["payload"] for message in seen if message.get("kind") == "step_commit"
            for effect in message["effects"] if effect["event_type"] == "procedure.language_check_completed"))
    assert reports[0] == reports[1]


def test_runtime_closed_checks_need_no_manual_or_generated_documentation(monkeypatch: pytest.MonkeyPatch) -> None:
    import backend.language_conformance_v16 as module
    monkeypatch.setattr(module, "INVENTORY_PATH", Path("/absent/source-inventory.json"))
    summary, effects = execute_selection(ALL_INDEX)
    report = effects[0]["payload"]
    assert len(report["cases"]) == 32
    assert len(report["adaptations"]) == 195
    assert sum(item["variant_count"] for item in report["adaptations"]) == 257
    assert report["full_compatibility"] is False


def test_runtime_failure_does_not_contaminate_fresh_run() -> None:
    cases = {case["id"]: case for case in CASES}
    assert run_case(cases["runtime-division-error"])["terminal"] == "failed"
    assert run_case(cases["recovery-fresh-run"])["variables"] == {"value": 3.0}
