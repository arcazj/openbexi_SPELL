"""Closed observation, native Prompt/core and simulator command conformance.

Qualification drives separate real workers across the production request/result
validation and deterministic simulator service boundary. Configured DSS run-all
uses isolated inner workers with parent-brokered actual binary CMD/TLM.
Durable supervisor authority, clocks and recovery have separate API/browser proofs.
"""
from __future__ import annotations

import json
import multiprocessing
import queue
import time
from collections import Counter
from typing import Any

from . import language_conformance_v17 as inherited
from . import language_conformance_v18 as previous
from .language_conformance_v16 import _case, canonical_bytes, digest, ROOT, SOURCE_SHA256
from .language_observation_fixture_v19 import condition, ITEM_ID

COVERAGE_PATH = ROOT / "contracts/v19/language_coverage.json"
REPORT_SCHEMA = "spell.v19.language-conformance/1"
CATALOG_PROFILES = tuple(sorted((
    ("dss_command_catalog_v19", "0.11"),
    ("language_reference_244", "0.19"),
    ("observation_command_v19", "0.19"),
    ("observation_decision_v19", "0.19"),
    ("observation_wait_v19", "0.19"),
    ("native_command_branch_v18", "0.18"),
    ("native_command_default_v18", "0.18"),
    ("prompt_workflow_v17", "0.17"),
    ("telecommand_modes_v18", "0.11"),
    ("tutorial_core_v18", "0.17"),
)))


def _tc(*names: str, selector: str = "name", arguments: Any = None,
        modifiers: dict | None = None, load_only: bool = False, planned_arguments: list | None = None,
        effective: list | None = None, mode: str = "SIMPLE", grouped: bool = False,
        verified: bool = False, calls: int | None = None) -> dict:
    return {"selector": selector, "command_names": list(names),
        "arguments": {} if arguments is None else arguments, "modifiers": modifiers or {},
        "outcome": "SETTLED", "successful": not load_only, "execution_succeeded": not load_only,
        "verification_succeeded": verified,
        "planned_arguments": planned_arguments or [[] for _ in names],
        "effective_modifiers": effective or [_effective(**{key: value for key, value in (modifiers or {}).items() if key not in {"group", "block", "per_command"}}) for _ in names],
        "plan_mode": mode, "grouped_transport": grouped,
        "provider_call_count": calls if calls is not None else len(names) * (2 if load_only else (6 if verified else 5)),
        "dispositions": ["LOADED_ONLY" if load_only else ("VERIFIED" if verified else "EXECUTED_UNVERIFIED")] * len(names),
        "onboard_execution": ["NOT_ATTEMPTED" if load_only else "SUCCEEDED"] * len(names)}


def _effective(**overrides) -> dict:
    return {"time": None, "release_time": None, "load_only": False, "confirm": False,
        "confirm_critical": False, "timeout_ms": 60000, "additional_info": {}, "send_delay_ms": 0,
        "verification": [], "adjust_limits": False, "delay_ms": 0, "tolerance": 0.0,
        "on_failure": "CANCEL", "prompt_user": True, **overrides}


def _argument(name: str, value, kind: str = "FLOAT", form: str = "ENG", radix: str = "DEC", encoded: str | None = None) -> dict:
    return {"name": name, "value_type": kind, "value_format": form, "radix": radix,
        "value": value, "encoded": str(value) if encoded is None else encoded}


def _new_case(identity: str, source: str, *, variables: dict | None = None, logs: list | None = None,
              prompts: list | None = None, confirmations: tuple[str, ...] = (), commands: list | None = None,
              built: tuple[str, ...] = (), diagnostic: str | None = None,
              terminal: str = "completed", ir_version: str = "0.19", artifacts: tuple[str, ...] = (),
              provider: str = "nominal", failure_answers: tuple[str, ...] = (),
              observations: list | None = None, observation_input: str = "nominal") -> dict:
    case = _case("v19-" + identity, source, variables=variables, logs=logs,
        diagnostic=diagnostic, terminal=terminal, artifacts=("FUNCTION-SEND", *artifacts))
    case.update(prompts=prompts or [], confirmations=list(confirmations), expected_telecommands=commands or [],
        expected_built_commands=list(built), expected_ir_version=ir_version,
        provider=provider, failure_answers=list(failure_answers),
        expected_observations=observations or [], observation_input=observation_input)
    return case


_HEADER = "# @language-profile spell-lrm244-conformance/0.19\n"
_READ = f'reading: float = 0.0\nGetTM({ITEM_ID!r}, target=reading, scalar_type="float")\n'
# These cases verify result semantics against the full committed satellite
# snapshot; they do not assert a sub-100ms database response guarantee.
_VERIFY = f'status: str = ""\nVerify(condition={condition()!r}, target=status, timeout=1.0)\n'
_READ_FLOW = (_HEADER + 'reading: float = 0.0\nstatus: str = ""\nanswer: str = ""\n'
    + _READ.split('\n', 1)[1] + _VERIFY.split('\n', 1)[1] + 'WaitFor(seconds=0.001)\n'
    'if status == "TRUE" and reading >= 27.5:\n'
    '    answer = Prompt("Run simulated command?", YES_NO)\n'
    '    if answer == "YES":\n'
    '        Send(command="CMDNAME", Confirm=True)\n'
    '        Display("simulated command completed")\n'
    '    else:\n        Display("no command requested")\n'
    'else:\n    Display("condition not met")\n')


def _obs(operation: str, outcome: str, value=None) -> dict:
    return {"operation": operation, "outcome": outcome, "value": value}


_POSITIVE_OBSERVATIONS = [_obs("GET_TM", "OK", 28.0), _obs("VERIFY", "TRUE"),
                          _obs("WAIT_FOR", "SATISFIED")]
def _direct_wait_source(timeout: float) -> str:
    return (_HEADER + f'WaitFor(condition={condition()!r}, timeout={timeout!r})\n'
            'Send(command="CMDNAME")\nDisplay("wait completed")\n')

NEW_CASES = (
    _new_case("observation-prompt-confirm-command", _READ_FLOW,
        variables={"reading": 28.0, "status": "TRUE", "answer": "YES"},
        logs=[("simulated command completed", "info")],
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", "YES")],
        confirmations=("YES",), observations=_POSITIVE_OBSERVATIONS,
        commands=[_tc("CMDNAME", modifiers={"confirm": True}, effective=[_effective(confirm=True)])],
        artifacts=("FUNCTION-GETTM", "FUNCTION-VERIFY", "FUNCTION-WAITFOR", "FUNCTION-PROMPT")),
    _new_case("observation-native-no", _READ_FLOW,
        variables={"reading": 28.0, "status": "TRUE", "answer": "NO"},
        logs=[("no command requested", "info")], observations=_POSITIVE_OBSERVATIONS,
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", "NO")]),
    _new_case("observation-native-abort", _READ_FLOW,
        variables={"reading": 28.0, "status": "TRUE", "answer": ""}, terminal="aborted",
        observations=_POSITIVE_OBSERVATIONS,
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", None, outcome="CANCELLED")]),
    _new_case("observation-confirmation-no", _READ_FLOW,
        variables={"reading": 28.0, "status": "TRUE", "answer": "YES"}, terminal="failed",
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", "YES")],
        confirmations=("NO",), observations=_POSITIVE_OBSERVATIONS),
    _new_case("observation-false-decision", _READ_FLOW, observation_input="low",
        variables={"reading": 14.0, "status": "FALSE", "answer": ""}, logs=[("condition not met", "info")],
        observations=[_obs("GET_TM", "OK", 14.0), _obs("VERIFY", "FALSE"), _obs("WAIT_FOR", "SATISFIED")]),
    *tuple(_new_case("read-rejects-" + kind, _HEADER + _READ + 'Send(command="CMDNAME")\n',
        observation_input=kind, terminal="failed", variables={"reading": 0.0},
        observations=[_obs("GET_TM", outcome)], artifacts=("FUNCTION-GETTM",))
        for kind, outcome in (("missing", "NOT_AVAILABLE"), ("stale", "NOT_AVAILABLE"),
            ("invalid", "NOT_AVAILABLE"), ("bad-quality", "NOT_AVAILABLE"),
            ("gap", "NOT_AVAILABLE"), ("policy", "NOT_AVAILABLE"))),
    _new_case("clock-indeterminate-no-command", _READ_FLOW, observation_input="clock",
        variables={"reading": 28.0, "status": "INDETERMINATE", "answer": ""},
        logs=[("condition not met", "info")], observations=[_obs("GET_TM", "OK", 28.0),
            _obs("VERIFY", "INDETERMINATE"), _obs("WAIT_FOR", "SATISFIED")]),
    _new_case("verify-overwrites-prior-true", _HEADER + 'status: str = "TRUE"\n'
        + f'Verify(condition={condition()!r}, target=status, timeout=1.0)\n'
        + 'if status == "TRUE":\n    Send(command="CMDNAME")\n'
        + 'else:\n    Display("verification is indeterminate")\n',
        observation_input="stale", variables={"status": "INDETERMINATE"},
        logs=[("verification is indeterminate", "info")],
        observations=[_obs("VERIFY", "INDETERMINATE")], artifacts=("FUNCTION-VERIFY",)),
    _new_case("condition-wait-command", _direct_wait_source(1.0), observations=[_obs("WAIT_FOR", "SATISFIED")],
        commands=[_tc("CMDNAME")], logs=[("wait completed", "info")], artifacts=("FUNCTION-WAITFOR",)),
    _new_case("condition-wait-timeout-no-command", _direct_wait_source(0.02), observation_input="low",
        terminal="failed", observations=[_obs("WAIT_FOR", "TIMED_OUT")], artifacts=("FUNCTION-WAITFOR",)),
    _new_case("read-controls-bounded-loop", _HEADER + _READ
        + 'total = 0\nfor i in range(2):\n    total = total + 1\n'
        + 'if reading >= 27.5 and total == 2:\n    Send(command="CMDNAME")\n',
        variables={"reading": 28.0, "total": 2, "i": 1}, observations=[_obs("GET_TM", "OK", 28.0)],
        commands=[_tc("CMDNAME")]),
    _new_case("read-native-built-command", _HEADER + _READ
        + 'command = BuildTC("CMDNAME")\nthreshold = 2 ** 4\n'
        + 'if reading > threshold:\n    Send(command=command)\n',
        variables={"reading": 28.0, "threshold": 16}, observations=[_obs("GET_TM", "OK", 28.0)],
        built=("CMDNAME",), commands=[_tc("CMDNAME", selector="item")]),
    _new_case("reject-observation-dynamic-command", _HEADER + _READ
        + 'answer = Prompt("Command", ALPHA)\nSend(command=answer)\n', diagnostic="SPELL938"),
    _new_case("reject-observation-dynamic-argument", _HEADER + _READ
        + 'Send(command="CMDNAME", args=[["ARG1", reading]])\n', diagnostic="SPELL914"),
    _new_case("reject-observation-data-mixture", _HEADER + _READ
        + 'answer = Prompt("Proceed", YES_NO)\nDataContainer("CONTAINER.A", schema_revision=1)\n',
        diagnostic="SPELL937"),
)
CASES = previous.CASES + NEW_CASES
CASESET_SHA256 = digest(canonical_bytes(CASES))
ALL_SELECTION = 195 + len(CASES)


def expected_image_runner_proof() -> dict:
    return {"ir_version": "0.19", "steps": 7, "direct_and_boundary_cases": len(CASES),
        "adapted_examples": 195, "adapted_variants": 257, "full_compatibility": False,
        "cases_sha256": CASESET_SHA256, "decision": "PASS"}


def _expected_result(case: dict) -> dict:
    base = previous._expected_result(case)
    if case in NEW_CASES:
        base.update(ir_version=case["expected_ir_version"] if case["expected_diagnostic"] is None else None,
            telecommands=case["expected_telecommands"], built_commands=case["expected_built_commands"],
            confirmations=case["confirmations"], failure_answers=case["failure_answers"],
            observations=case["expected_observations"])
    return base


def _compile(case: dict):
    from .procedure_parser import ProcedureCatalog, ProcedureValidationError
    if case not in NEW_CASES or len(case["source"].encode("utf-8")) > 20_000:
        raise ValueError("case is outside the closed v0.19 registry")
    try:
        procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"], case["id"] + ".spell.py")
    except ProcedureValidationError as exc:
        if exc.diagnostics[0].code != case["expected_diagnostic"]:
            raise ValueError(f"{case['id']}: unexpected diagnostic {exc.diagnostics[0].code}") from exc
        return None
    if case["expected_diagnostic"] is not None or procedure.ir_version != case["expected_ir_version"]:
        raise ValueError(f"{case['id']}: source acceptance or IR version differs")
    return procedure


def _command_observation(request: dict, result: dict) -> dict:
    from .telecommand_runtime_v11 import validate_result_payload
    actual = validate_result_payload(request, result)
    elements = actual["checkpoint"]["elements"]
    return {"selector": request["selector"]["kind"], "command_names": [item["command_name"] for item in elements],
        "arguments": request["arguments"], "modifiers": request["modifiers"],
        "planned_arguments": [item["command"]["arguments"] for item in request["plan"]["elements"]],
        "effective_modifiers": [item["effective_modifiers"] for item in request["plan"]["elements"]],
        "plan_mode": request["plan"]["mode"], "grouped_transport": request["plan"]["grouped_transport"],
        **{key: actual[key] for key in ("outcome", "successful", "execution_succeeded", "verification_succeeded")},
        "provider_call_count": actual["checkpoint"]["provider_call_count"],
        "dispositions": [item["disposition"] for item in elements],
        "onboard_execution": [item["onboard_execution"] for item in elements]}


def _built_name(step: dict, values: dict) -> str:
    from .telecommand_runtime_v11 import ITEM_PREFIX, build_item_checkpoint_for_step
    expected = build_item_checkpoint_for_step(step, values)
    actual = values.get(step["target"])
    if actual != expected or type(actual) is not str or not actual.startswith(ITEM_PREFIX):
        raise ValueError("built command checkpoint differs from production construction")
    return json.loads(actual[len(ITEM_PREFIX):])["name"]


def _observed(case: dict, procedure, terminal: str | None, values: dict, logs: list,
              prompts: list, commands: list, built: list, confirmations: list, failure_answers: list,
              observations: list) -> dict:
    actual = inherited._observed_result(case, terminal, values, logs, prompts)
    actual.update(ir_version=procedure.ir_version, telecommands=commands, built_commands=built,
        confirmations=confirmations, failure_answers=failure_answers, observations=observations)
    if canonical_bytes(actual) != canonical_bytes(_expected_result(case)):
        raise ValueError(f"{case['id']}: real simulator request/result or typed source oracle differs")
    return actual


def _provider(case: dict, preflight):
    """Closed external simulator inputs; observed results never come from an oracle."""
    from .telecommand_v11 import DeterministicScriptedProvider, ElementStage, ProviderStep
    if case["provider"] == "nominal": return None
    identity = preflight.plan.elements[0].element_id
    if case["provider"] == "reject_transport":
        return DeterministicScriptedProvider([ProviderStep(ElementStage.TRANSPORT, "REJECTED", identity)])
    if case["provider"] == "fail_verification":
        return DeterministicScriptedProvider([ProviderStep(stage, outcome, identity) for stage, outcome in (
            (ElementStage.TRANSPORT, "ACCEPTED"), (ElementStage.LOADING, "LOADED"),
            (ElementStage.RELEASE, "RELEASED"), (ElementStage.ACKNOWLEDGEMENT, "ACKNOWLEDGED"),
            (ElementStage.ONBOARD_EXECUTION, "SUCCEEDED"), (ElementStage.VERIFICATION, "FAILED"))])
    raise ValueError("unknown closed provider fixture")


def _validate_settlement_effect(effect: dict, result: dict, step_index: int) -> None:
    expected = {"event_type": "procedure.telecommand_settled", "source": "telecommand-runtime",
        "severity": "info", "payload": {**result, "step_index": step_index}}
    if canonical_bytes(effect) != canonical_bytes(expected):
        raise ValueError("worker settlement effect differs from validated simulator result")


def _validate_observation_effect(effect: dict, request: dict, result: dict, step_index: int) -> None:
    expected = {"event_type": "procedure.observation_settled", "source": "worker",
        "severity": "info", "payload": {"request_id": request["request_id"],
            "operation": request["operation"], "outcome": result["outcome"], "step_index": step_index}}
    if canonical_bytes(effect) != canonical_bytes(expected):
        raise ValueError("worker observation effect differs from validated service result")


def run_case(case: dict) -> dict:
    if case in previous.CASES:
        return previous.run_case(case)
    from .worker import worker_main
    from .ir_v07 import observation_request_for_step
    from .language_observation_fixture_v19 import ObservationFixture, observation_summary
    from .runtime_composition_v19 import OBSERVATION_STEP_TYPES, observation_checkpoint_variables
    from .telecommand_runtime_v11 import confirmation_prompt_id, failure_prompt_id, prepare_send_request, validate_send_request, execute_preflight
    procedure = _compile(case)
    if procedure is None:
        return _expected_result(case)
    context = multiprocessing.get_context("spawn")
    control, output = context.Queue(), context.Queue()
    process = context.Process(target=worker_main, args=(case["id"], 1, procedure.ir_version,
        list(procedure.steps), 0, "conformance", None, {}, control, output, None, None, False))
    values, logs, prompts, commands, built, confirmations = {}, [], [], [], [], []
    failure_answers, results, result_steps = [], [], []
    observations, observation_results = [], {}
    fixture = ObservationFixture(case["observation_input"])
    committed_observations = 0
    terminal, committed_commands = None, 0
    process.start()
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            try:
                message = output.get(timeout=0.2)
            except queue.Empty:
                if not process.is_alive(): break
                continue
            kind = message.get("kind")
            if kind == "prompt_opened":
                step = procedure.steps[message["step_index"]]
                if step["type"] == "prompt":
                    ordinal = len(prompts)
                    if ordinal >= len(case["prompts"]): raise ValueError("unexpected native prompt")
                    prompts.append({key: message.get(key) for key in inherited.PROMPT_OBSERVATIONS})
                    settlement = case["prompts"][ordinal]["settlements"][0]
                elif step["type"] == "send_tc":
                    if results and message["prompt_id"] == failure_prompt_id(case["id"], step["index"], results[-1]["result_digest"]):
                        answer = case["failure_answers"][len(failure_answers)]
                        failure_answers.append(answer)
                        control.put({"type": "prompt_settlement", "prompt_id": message["prompt_id"],
                            "settlement_id": "case-failure-" + str(len(failure_answers)), "command_id": None,
                            "outcome": "ANSWERED", "response": answer})
                        continue
                    ordinal = len(confirmations)
                    if ordinal >= len(case["confirmations"]): raise ValueError("unexpected command confirmation")
                    _request, _service, preflight = prepare_send_request(case["id"], step["index"], step, values)
                    if message["prompt_id"] != confirmation_prompt_id(case["id"], step["index"], preflight.plan.plan_digest):
                        raise ValueError("confirmation identity differs from production plan")
                    if message.get("choices") != ["YES", "NO"] or message.get("default") != "NO":
                        raise ValueError("confirmation policy differs")
                    answer = case["confirmations"][ordinal]
                    confirmations.append(answer)
                    settlement = {"outcome": "ANSWERED", "response": answer}
                else: raise ValueError("unexpected prompt source")
                control.put({"type": "prompt_settlement", "prompt_id": message["prompt_id"],
                    "settlement_id": f"case-settlement-{len(prompts)}-{len(confirmations)}", "command_id": None, **settlement})
            elif kind == "observation_requested":
                from .worker import evaluate_expression
                step = procedure.steps[message["step_index"]]
                if step.get("guard") is not None and not evaluate_expression(step["guard"], values):
                    raise ValueError("observation request bypassed its authoritative guard")
                request = observation_request_for_step(case["id"], step)
                incoming = {key: value for key, value in message.items() if key not in {"kind", "generation"}}
                if canonical_bytes(incoming) != canonical_bytes(request) or step["index"] in observation_results:
                    raise ValueError("worker observation request identity differs or repeats")
                result = fixture.resolve(request)
                observations.append(observation_summary(request, result))
                observation_results[step["index"]] = (request, result)
                control.put({"type": "observation_result", **result})
            elif kind == "telecommand_requested":
                from .worker import evaluate_expression
                step = procedure.steps[message["step_index"]]
                if step.get("guard") is not None and evaluate_expression(step["guard"], values) is not True:
                    raise ValueError("telecommand request bypassed its authoritative guard")
                request, service, preflight = validate_send_request(case["id"], step["index"], step, values,
                    {key: value for key, value in message.items() if key not in {"kind", "generation"}})
                result = execute_preflight(request, service, preflight,
                    confirmation_actor="conformance-operator" if preflight.confirmation_required else None,
                    provider=_provider(case, preflight))
                results.append(result)
                result_steps.append(step["index"])
                commands.append(_command_observation(request, result))
                control.put({"type": "telecommand_result", **result})
            elif kind == "step_commit":
                step = procedure.steps[message["step_index"]]
                effects = message.get("effects", [])
                if step["type"] in OBSERVATION_STEP_TYPES:
                    completed = {"event_type": "step.completed", "source": "worker",
                        "severity": "info", "payload": {"step_index": step["index"],
                            "line": step["line"], "step_type": step["type"],
                            "skipped": step["index"] not in observation_results}}
                    if step["index"] in observation_results:
                        request, result = observation_results[step["index"]]
                        expected_values = observation_checkpoint_variables(step, values, result)
                        if (canonical_bytes(message["variables"]) != canonical_bytes(expected_values)
                                or len(effects) != 2 or canonical_bytes(effects[1]) != canonical_bytes(completed)):
                            raise ValueError("worker observation checkpoint differs from validated service result")
                        _validate_observation_effect(effects[0], request, result, step["index"])
                        committed_observations += 1
                    elif (canonical_bytes(effects) != canonical_bytes([completed])
                          or canonical_bytes(message["variables"]) != canonical_bytes(values)):
                        raise ValueError("guarded-off observation fabricated a checkpoint")
                values = message["variables"]
                logs.extend([effect["payload"]["message"], effect["severity"]] for effect in effects if effect.get("event_type") == "procedure.log")
                if any(effect.get("event_type") == "procedure.telecommand_built" for effect in effects):
                    built.append(_built_name(step, values))
                for effect in effects:
                    if effect.get("event_type") == "procedure.telecommand_settled":
                        if committed_commands >= len(results) or step["index"] != result_steps[committed_commands]:
                            raise ValueError("worker settlement effect lacks its exact original request step")
                        _validate_settlement_effect(effect, results[committed_commands], step["index"])
                        committed_commands += 1
            elif kind == "terminal":
                terminal = message["state"]
                break
        process.join(timeout=1)
        expected_commits = len(commands) - (1 if case["provider"] == "fail_verification" else 0)
        expected_observation_commits = sum(row["operation"] == "VERIFY" or
            row["outcome"] in {"OK", "SATISFIED"} for row in observations)
        if (process.is_alive() or process.exitcode != 0 or committed_commands != expected_commits
                or committed_observations != expected_observation_commits):
            raise ValueError(f"{case['id']}: worker or command settlement did not finish cleanly")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        control.close()
        output.close()
        fixture.close()
    return _observed(case, procedure, terminal, values, logs, prompts, commands, built, confirmations, failure_answers, observations)


def evaluate_fixed_case(case: dict) -> dict:
    """No broker messages or durable dispatch: isolated deterministic helpers only."""
    if case in previous.CASES:
        return previous.evaluate_fixed_case(case)
    from .worker import ExpressionEvaluationError, evaluate_expression
    from .ir_v07 import observation_request_for_step
    from .language_observation_fixture_v19 import ObservationFixture, observation_summary
    from .runtime_composition_v19 import OBSERVATION_STEP_TYPES, observation_checkpoint_variables
    from .prompt_v17 import NativePromptError, native_prompt_result
    from .telecommand_runtime_v11 import (TelecommandRuntimeError, build_item_checkpoint_for_step,
        confirmation_prompt_id, prepare_send_request, execute_preflight, result_failure_policy)
    procedure = _compile(case)
    if procedure is None: return _expected_result(case)
    if len(procedure.steps) > 4096: raise ValueError("closed fixture exceeds its instruction bound")
    values, logs, prompts, commands, built, confirmations = {}, [], [], [], [], []
    failure_answers = []
    observations = []
    fixture = ObservationFixture(case["observation_input"])
    terminal = "completed"
    try:
        for step in procedure.steps:
            if step["type"] not in {"variable_set", "display", "log", "prompt", "build_tc", "send_tc", *OBSERVATION_STEP_TYPES}:
                raise ValueError("closed fixture contains an unsupported effect")
            if step.get("guard") is not None and not evaluate_expression(step["guard"], values): continue
            kind = step["type"]
            if kind == "variable_set":
                value = evaluate_expression(step["expression"], values)
                values[step["name"]] = float(value) if step["declared_type"] == "float" else value
            elif kind in {"display", "log"}:
                value = evaluate_expression(step["message"], values)
                if type(value) is not str or (kind == "log" and not value): raise ExpressionEvaluationError("invalid log text")
                logs.append([value, step["level"]])
            elif kind == "prompt":
                ordinal = len(prompts)
                fields = {key: step[key] for key in inherited.PROMPT_OBSERVATIONS}
                fields["question"] = evaluate_expression(step["question"], values)
                prompts.append(fields)
                settlement = case["prompts"][ordinal]["settlements"][0]
                if settlement["outcome"] == "CANCELLED":
                    terminal = "aborted"
                    break
                answer = native_prompt_result(step, settlement)
                if "response_target" in step: values[step["response_target"]] = answer
            elif kind == "build_tc":
                values[step["target"]] = build_item_checkpoint_for_step(step, values)
                built.append(_built_name(step, values))
            elif kind in OBSERVATION_STEP_TYPES:
                request = observation_request_for_step(case["id"], step)
                result = fixture.resolve(request)
                observations.append(observation_summary(request, result))
                values = observation_checkpoint_variables(step, values, result)
            else:
                request, service, preflight = prepare_send_request(case["id"], step["index"], step, values)
                if preflight.confirmation_required:
                    answer = case["confirmations"][len(confirmations)]
                    confirmations.append(answer)
                    if answer != "YES":
                        terminal = "failed"
                        break
                    request, service, preflight = prepare_send_request(case["id"], step["index"], step, values,
                        confirmation={"prompt_id": confirmation_prompt_id(case["id"], step["index"], preflight.plan.plan_digest)})
                result = execute_preflight(request, service, preflight,
                    confirmation_actor="conformance-operator" if preflight.confirmation_required else None,
                    provider=_provider(case, preflight))
                commands.append(_command_observation(request, result))
                policy = result_failure_policy(request, result)
                if policy and policy["uncertain"]:
                    terminal = "failed"
                    break
                if policy and policy["prompt_user"]:
                    answer = case["failure_answers"][len(failure_answers)]
                    failure_answers.append(answer)
                    if answer != "YES":
                        terminal = "failed"
                        break
                elif policy and policy["action"] == "ABORT":
                    terminal = "failed"
                    break
    except (ExpressionEvaluationError, NativePromptError, TelecommandRuntimeError, ValueError):
        terminal = "failed"
    finally:
        fixture.close()
    return _observed(case, procedure, terminal, values, logs, prompts, commands, built, confirmations, failure_answers, observations)


def execute_selection(selection: int) -> tuple[str, list[dict]]:
    from .reference_examples_v10 import execute_reference_example
    if type(selection) is not int or not 0 <= selection <= ALL_SELECTION:
        raise ValueError("language selection is outside the closed registry")
    if selection < 195: return inherited.execute_selection(selection)
    selected = CASES if selection == ALL_SELECTION else (CASES[selection - 195],)
    cases = [evaluate_fixed_case(case) for case in selected]
    examples = []
    if selection == ALL_SELECTION:
        for number in range(1, 196):
            result = execute_reference_example(number)
            if not result.passed or any(proof.status != "PASS" for proof in result.variant_proofs):
                raise ValueError("reference adaptation oracle failed")
            examples.append({"example_number": number, "status": result.status,
                "variant_count": len(result.variant_proofs), "evidence_digest": result.evidence_digest})
    summary = f"Language checks: {len(cases)} PASS; {len(examples)} adaptations; full support: false"
    payload = {"schema_version": "spell.v19.language-check-result/1", "selection": selection,
        "cases_sha256": CASESET_SHA256, "evidence_kind": "ISOLATED_PRODUCTION_HELPERS_NO_OUTER_DISPATCH",
        "full_compatibility": False, "cases": cases, "adaptations": examples,
        "unqualified_artifacts_remain": True, "summary": summary}
    if len(canonical_bytes(payload)) > 192_000: raise ValueError("language report exceeds its bound")
    return summary, [{"event_type": "procedure.language_check_completed", "source": "simulator", "severity": "info", "payload": payload}]


def coverage_contract() -> dict:
    contract = previous.coverage_contract()
    contract = json.loads(canonical_bytes(contract))
    contract.update(schema_version="spell.v19.language-coverage/1", cases_sha256=CASESET_SHA256,
        inherited_v18_cases_sha256=previous.CASESET_SHA256)
    by_id = {row["id"]: row for row in contract["rows"]}
    for case in NEW_CASES:
        if digest(case["source"].encode("utf-8")) != case["source_sha256"]: raise ValueError("new source identity differs")
        for identity in case["artifacts"]:
            if identity not in by_id: raise ValueError("new artifact identity is absent from manual inventory")
            row = by_id[identity]
            row["checks"].append(case["id"])
            if case["expected_diagnostic"] is None:
                row.update(status="PARTIAL", implementation="BOUNDED_IMPLEMENTATION", whole_artifact_supported=False)
                row["gap_reasons"] = sorted(set(row["gap_reasons"]) | {"MISSING_PROOF"})
    contract["scopes"].append({"id": "V19-OBSERVATION-COMMAND", "description": "Exact bounded target-based GetTM/Verify/WaitFor, native prompt/core and literal simulator command sources listed here; real workers, repository resolver, durable condition service and v19 quality filter.",
        "source_sha256": SOURCE_SHA256, "manual_pages": "17-23, 36-59, 68, 70-72",
        "proof_kind": "EXPLICIT_BOUNDED_SOURCE_AND_SIMULATOR_SERVICE_OBLIGATIONS",
        "checks": [case["id"] for case in NEW_CASES],
        "excludes": ["dynamic identifiers or command operands", "native observation return objects and full modifiers", "external command transport", "data/file/environment mixtures", "SKIP/GOTO", "acquisition-time freshness, supervisor recovery and evolving timer scheduling (separate API/browser proofs)"]})
    contract["remaining_work"] = [
        "Qualify each entire manual artifact before marking it SUPPORTED.",
        "Observation snapshots and native values may guard literal commands; dynamic operands and other service combinations remain restricted.",
        "Collections, dynamic typing, general Python, external drivers and unresolved manual conflicts remain gaps."]
    return contract


def _report(results: list, contract: dict, selection: str) -> dict:
    selected = {result["id"] for result in results}
    return {"schema_version": REPORT_SCHEMA, "release": "v0.19.0", "source_sha256": SOURCE_SHA256,
        "coverage_sha256": digest(canonical_bytes(contract)), "cases_sha256": CASESET_SHA256,
        "selection": selection, "profile_result": "PASS", "full_compatibility": False, "artifact_count": 763,
        "coverage_counts": dict(sorted(Counter(row["status"] for row in contract["rows"]).items())),
        "gap_reason_counts": dict(sorted(Counter(reason for row in contract["rows"] for reason in row["gap_reasons"]).items())),
        "cases": results, "case_count": len(results), "direct_count": sum(row["mode"] == "DIRECT_SOURCE" for row in results),
        "rejection_count": sum(row["mode"] == "EXPECTED_REJECTION" for row in results), "unqualified_default_count": 19,
        "evidence_kind": "REAL_WORKER_AND_VALIDATED_SIMULATOR_SERVICE",
        "qualified_scopes": [{**scope, "status": "SUPPORTED", "whole_artifact_supported": False}
            for scope in contract["scopes"] if scope["checks"] and set(scope["checks"]) <= selected],
        "scope": "Fixed local source and deterministic service cases only; durable authority, recovery and timer proofs are separate. Full SPELL support remains incomplete."}


def qualify(case_id: str | None = None) -> dict:
    contract = coverage_contract()
    if not COVERAGE_PATH.is_file() or json.loads(COVERAGE_PATH.read_bytes()) != contract:
        raise ValueError("v0.19 coverage contract is stale")
    selected = [case for case in CASES if case_id is None or case["id"] == case_id]
    if not selected: raise ValueError("unknown conformance case")
    return _report([run_case(case) for case in selected], contract, case_id or "ALL")


def validate_report(report: dict) -> None:
    contract = coverage_contract()
    if COVERAGE_PATH.stat().st_size > 1_000_000 or json.loads(COVERAGE_PATH.read_bytes()) != contract:
        raise ValueError("language coverage contract differs from current source")
    if len(canonical_bytes(report)) > 1_000_000 or canonical_bytes(report) != canonical_bytes(_report([_expected_result(case) for case in CASES], contract, "ALL")):
        raise ValueError("language evidence has stale, missing or unproved results")
