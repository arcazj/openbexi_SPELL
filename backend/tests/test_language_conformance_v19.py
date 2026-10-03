from __future__ import annotations

from copy import deepcopy
import json
import time

import pytest

from backend import language_conformance_v18 as previous
from backend import language_conformance_v19 as current
from backend.language_observation_fixture_v19 import ObservationFixture
from backend.procedure_parser import ProcedureCatalog
from scripts.generate_reference_runner_v19 import OUTPUT, render
from .test_worker_v06 import _next, _start_worker


@pytest.fixture(scope="module")
def complete_report():
    return current.qualify()


@pytest.mark.parametrize("case", current.CASES, ids=lambda case: case["id"])
def test_real_workers_match_independent_source_and_service_oracles(case, complete_report):
    observed = next(row for row in complete_report["cases"] if row["id"] == case["id"])
    assert current.evaluate_fixed_case(case) == observed


def test_inherited_registry_and_unresolved_reference_obligations_are_preserved():
    assert current.CASES[:len(previous.CASES)] == previous.CASES
    assert previous.CASESET_SHA256 == "bbfb3c2782ea796ddebe8a9e4337afe728f306eb781c49ef2e0b88e90864caae"
    assert json.loads(current.COVERAGE_PATH.read_bytes()) == current.coverage_contract()
    before = {row["id"]: row for row in previous.coverage_contract()["rows"]}
    after = {row["id"]: row for row in current.coverage_contract()["rows"]}
    assert len(after) == 763
    for identity, row in before.items():
        assert set(row["gap_reasons"]) <= set(after[identity]["gap_reasons"])
        assert not after[identity]["whole_artifact_supported"]


def test_full_report_requires_every_observation_and_command_obligation(complete_report):
    current.validate_report(complete_report)
    assert complete_report["case_count"] == 148
    assert complete_report["direct_count"] == 112
    assert complete_report["rejection_count"] == 36
    assert complete_report["full_compatibility"] is False
    assert {row["id"] for row in complete_report["qualified_scopes"]} == {
        "V17-CORE", "V17-DISPLAY-PROMPT", "V18-NATIVE-TELECOMMAND", "V19-OBSERVATION-COMMAND"}


@pytest.mark.parametrize("mutation", ["value", "outcome", "typed-variable", "wait", "missing", "registry", "whole-artifact", "full"])
def test_report_rejects_mutated_observation_or_support_evidence(complete_report, mutation):
    report = deepcopy(complete_report)
    case = next(row for row in report["cases"] if row["id"] == "v19-observation-prompt-confirm-command")
    if mutation == "value": case["observations"][0]["value"] = 123.0
    elif mutation == "outcome": case["observations"][0]["outcome"] = "NOT_AVAILABLE"
    elif mutation == "typed-variable": case["variables"]["reading"] = True
    elif mutation == "wait":
        row = next(row for row in report["cases"] if row["id"] == "v19-condition-wait-timeout-no-command")
        row["observations"][0]["outcome"] = "SATISFIED"
    elif mutation == "missing": report["cases"].pop()
    elif mutation == "registry": report["cases_sha256"] = "0" * 64
    elif mutation == "whole-artifact": report["qualified_scopes"][-1]["whole_artifact_supported"] = True
    else: report["full_compatibility"] = True
    with pytest.raises(ValueError, match="stale, missing or unproved"):
        current.validate_report(report)


def test_mutated_actual_service_value_fails_the_independent_oracle(monkeypatch):
    original = ObservationFixture.resolve
    def altered(self, request):
        result = original(self, request)
        if request["operation"] == "GET_TM" and result["outcome"] == "OK":
            result["value"] = 123.0
        return result
    monkeypatch.setattr(ObservationFixture, "resolve", altered)
    with pytest.raises(ValueError, match="oracle differs|source oracle|differ from the oracle"):
        current.run_case(current.NEW_CASES[0])


def test_actual_worker_command_is_rejected_when_independent_guard_is_false(monkeypatch):
    # Spawned workers import their original evaluator. Only the qualification
    # observer's independent guard decision is changed at the service boundary.
    from backend import worker, telecommand_runtime_v11
    calls = []
    monkeypatch.setattr(worker, "evaluate_expression", lambda _expression, _variables: False)
    def forbidden_dispatch(*args, **kwargs):
        calls.append(args)
        pytest.fail("a false authoritative guard reached the simulator service")
    monkeypatch.setattr(telecommand_runtime_v11, "execute_preflight", forbidden_dispatch)
    with pytest.raises(ValueError, match="telecommand request bypassed its authoritative guard"):
        current.run_case(current.NEW_CASES[0])
    assert calls == []


def test_condition_wait_outcomes_remain_strict_with_real_scheduling_delay(monkeypatch):
    from backend.condition_service import ConditionService
    reconcile = ConditionService.reconcile_wait
    def delayed(self, *args, **kwargs):
        time.sleep(0.03)
        return reconcile(self, *args, **kwargs)
    monkeypatch.setattr(ConditionService, "reconcile_wait", delayed)
    for identity, outcome, commands in [
        ("v19-condition-wait-command", "SATISFIED", 1),
        ("v19-condition-wait-timeout-no-command", "TIMED_OUT", 0),
    ]:
        case = next(row for row in current.NEW_CASES if row["id"] == identity)
        observed = current.run_case(case)
        assert current.evaluate_fixed_case(case) == observed
        assert observed["observations"] == [{"operation":"WAIT_FOR", "outcome":outcome, "value":None}]
        assert len(observed["telecommands"]) == commands


@pytest.mark.parametrize("mutation", ["request", "outcome", "bool-index", "source"])
def test_mutated_actual_worker_effect_fails_service_binding(monkeypatch, mutation):
    original = current._validate_observation_effect
    def altered(effect, request, result, step_index):
        changed = deepcopy(effect)
        if mutation == "request": changed["payload"]["request_id"] = "forged"
        elif mutation == "outcome": changed["payload"]["outcome"] = "FALSE"
        elif mutation == "bool-index": changed["payload"]["step_index"] = True
        else: changed["source"] = "untrusted"
        original(changed, request, result, step_index)
    monkeypatch.setattr(current, "_validate_observation_effect", altered)
    with pytest.raises(ValueError, match="observation effect differs"):
        current.run_case(current.NEW_CASES[0])


def test_generated_runner_uses_isolated_services_without_outer_requests(monkeypatch):
    assert OUTPUT.read_bytes() == render().encode("ascii")
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(render())
    assert procedure.ir_version == "0.19" and len(procedure.steps) == 7
    thread, control, output = _start_worker(monkeypatch, procedure)
    prompt, _ = _next(output, lambda item: item.get("kind") == "prompt_opened", timeout=5)
    control.put({"type": "prompt_response", "prompt_id": prompt["prompt_id"], "response": current.ALL_SELECTION})
    terminal, messages = _next(output, lambda item: item.get("kind") == "terminal", timeout=30)
    thread.join(timeout=1)
    assert terminal["state"] == "completed" and not thread.is_alive()
    assert not any(item.get("kind") in {"telecommand_requested", "observation_requested"} for item in messages)
    payload = next(effect["payload"] for item in messages if item.get("kind") == "step_commit"
                   for effect in item["effects"] if effect["event_type"] == "procedure.language_check_completed")
    assert payload["evidence_kind"] == "ISOLATED_PRODUCTION_HELPERS_NO_OUTER_DISPATCH"
    assert len(payload["cases"]) == 148 and len(payload["adaptations"]) == 195
    assert sum(row["variant_count"] for row in payload["adaptations"]) == 257


def test_require_full_remains_unfulfilled(monkeypatch, complete_report):
    from scripts import qualify_language_v19
    monkeypatch.setattr(qualify_language_v19, "qualify", lambda _case: complete_report)
    monkeypatch.setattr("sys.argv", ["qualify_language_v19", "--require-full"])
    assert qualify_language_v19.main() == 2
