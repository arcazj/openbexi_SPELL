from __future__ import annotations

from copy import deepcopy
import json

import pytest

from backend import language_conformance_v17 as previous
from backend import language_conformance_v18 as current
from backend.procedure_parser import ProcedureCatalog
from scripts.generate_reference_runner_v18 import OUTPUT, render
from .test_worker_v06 import _next, _start_worker


@pytest.fixture(scope="module")
def complete_report():
    return current.qualify()


@pytest.mark.parametrize("case", current.CASES, ids=lambda case: case["id"])
def test_real_workers_and_isolated_service_helpers_agree(case, complete_report):
    result = next(item for item in complete_report["cases"] if item["id"] == case["id"])
    assert current.evaluate_fixed_case(case) == result


def test_registry_preserves_every_previous_case_and_reason():
    assert current.CASES[:len(previous.CASES)] == previous.CASES
    assert previous.CASESET_SHA256 == "57c865149f4ca70a9fa21d2cc7ffc47fa73ab30d79ae15bbae74f21e2e9f2e35"
    assert json.loads(current.COVERAGE_PATH.read_bytes()) == current.coverage_contract()
    before = {row["id"]: row for row in previous.coverage_contract()["rows"]}
    after = {row["id"]: row for row in current.coverage_contract()["rows"]}
    assert len(after) == 763
    for identity, row in before.items():
        assert set(row["gap_reasons"]) <= set(after[identity]["gap_reasons"])
        assert not after[identity]["whole_artifact_supported"]
    assert "MISSING_IMPLEMENTATION" in after["CMP-LRM244-SYNTAX-IMPORT"]["gap_reasons"]
    assert "MANUAL_CONFLICT" in after["CMP-LRM244-ERRATUM-PROMPT-FAILURE-MODIFIERS"]["gap_reasons"]


def test_full_report_requires_every_closed_obligation(complete_report):
    current.validate_report(complete_report)
    assert complete_report["full_compatibility"] is False
    assert complete_report["evidence_kind"] == "REAL_WORKER_AND_VALIDATED_SIMULATOR_SERVICE"
    assert {scope["id"] for scope in complete_report["qualified_scopes"]} == {"V17-CORE", "V17-DISPLAY-PROMPT", "V18-NATIVE-TELECOMMAND"}
    assert current.qualify("v18-built-literal-arguments")["qualified_scopes"] == []


@pytest.mark.parametrize("mutation", ["argument-value", "argument-type", "normalized-modifier", "provider-calls", "loaded-only", "failure-disposition", "scope", "missing", "registry", "full"])
def test_report_rejects_mutated_command_or_support_evidence(complete_report, mutation):
    report = deepcopy(complete_report)
    case = next(row for row in report["cases"] if row["id"] == "v18-built-literal-arguments")
    command = case["telecommands"][0]
    if mutation == "argument-value": command["planned_arguments"][0][0]["value"] = 2.0
    elif mutation == "argument-type": command["planned_arguments"][0][0]["value_type"] = "LONG"
    elif mutation == "normalized-modifier": command["effective_modifiers"][0]["timeout_ms"] = 1
    elif mutation == "provider-calls": command["provider_call_count"] = 0
    elif mutation == "loaded-only":
        row = next(row for row in report["cases"] if row["id"] == "v18-load-only-is-not-execution")
        row["telecommands"][0]["execution_succeeded"] = True
    elif mutation == "failure-disposition":
        row = next(row for row in report["cases"] if row["id"] == "v18-verification-failure-stops")
        row["telecommands"][0]["dispositions"] = ["VERIFIED"]
    elif mutation == "scope": report["qualified_scopes"][-1]["whole_artifact_supported"] = True
    elif mutation == "missing": report["cases"].pop()
    elif mutation == "registry": report["cases_sha256"] = "0" * 64
    else: report["full_compatibility"] = True
    with pytest.raises(ValueError, match="stale, missing or unproved"):
        current.validate_report(report)


@pytest.mark.parametrize("mutation", ["built-argument", "effective-modifier"])
def test_actual_production_observation_mutation_fails_independent_oracle(monkeypatch, mutation):
    original = current._command_observation
    def altered(request, result):
        observed = original(request, result)
        if mutation == "built-argument": observed["planned_arguments"][0][0]["value"] = 2.0
        else: observed["effective_modifiers"][0]["timeout_ms"] = 1
        return observed
    monkeypatch.setattr(current, "_command_observation", altered)
    case = next(case for case in current.CASES if case["id"] == "v18-built-literal-arguments")
    with pytest.raises(ValueError, match="oracle differs"):
        current.run_case(case)


@pytest.mark.parametrize("mutation", ["result-value", "result-digest", "step-index"])
def test_actual_worker_settlement_mutation_fails_service_result_binding(monkeypatch, mutation):
    original = current._validate_settlement_effect
    def altered(effect, result, step_index):
        tampered = deepcopy(effect)
        if mutation == "result-value": tampered["payload"]["execution_succeeded"] = False
        elif mutation == "result-digest": tampered["payload"]["result_digest"] = "0" * 64
        else: tampered["payload"]["step_index"] += 1
        original(tampered, result, step_index)
    monkeypatch.setattr(current, "_validate_settlement_effect", altered)
    case = next(case for case in current.CASES if case["id"] == "v18-built-literal-arguments")
    with pytest.raises(ValueError, match="settlement effect differs"):
        current.run_case(case)


def test_generated_run_all_uses_isolated_service_proof_without_outer_dispatch(monkeypatch):
    assert "# @language-profile spell-lrm244-conformance/0.18" in render()
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(render())
    assert procedure.ir_version == "0.18" and len(procedure.steps) == 7
    thread, control, output = _start_worker(monkeypatch, procedure)
    prompt, _ = _next(output, lambda item: item.get("kind") == "prompt_opened", timeout=5)
    control.put({"type": "prompt_response", "prompt_id": prompt["prompt_id"], "response": current.ALL_SELECTION})
    terminal, messages = _next(output, lambda item: item.get("kind") == "terminal", timeout=30)
    thread.join(timeout=1)
    assert terminal["state"] == "completed" and not thread.is_alive()
    assert not any(item.get("kind") == "telecommand_requested" for item in messages)
    payload = next(effect["payload"] for item in messages if item.get("kind") == "step_commit"
                   for effect in item["effects"] if effect["event_type"] == "procedure.language_check_completed")
    assert payload["evidence_kind"] == "ISOLATED_PRODUCTION_HELPERS_NO_OUTER_DISPATCH"
    assert len(payload["cases"]) == len(current.CASES)
    assert len(payload["adaptations"]) == 195
    assert sum(row["variant_count"] for row in payload["adaptations"]) == 257


def test_require_full_stays_unsatisfied(monkeypatch, complete_report):
    from scripts import qualify_language_v18
    monkeypatch.setattr(qualify_language_v18, "qualify", lambda _: complete_report)
    monkeypatch.setattr("sys.argv", ["qualify_language_v18", "--require-full"])
    assert qualify_language_v18.main() == 2
