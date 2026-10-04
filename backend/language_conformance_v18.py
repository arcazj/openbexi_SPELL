"""Closed native Prompt/core/Display and simulator telecommand conformance.

Qualification drives separate real workers across the production request/result
validation and deterministic simulator service boundary. Interactive run-all
uses isolated service objects: it never dispatches an outer procedure command.
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
from .language_conformance_v16 import _case, canonical_bytes, digest, ROOT, SOURCE_SHA256
from .worker_process import WorkerProcess

COVERAGE_PATH = ROOT / "contracts/v18/language_coverage.json"
REPORT_SCHEMA = "spell.v18.language-conformance/1"
CATALOG_PROFILES = (
    ("language_reference_244", "0.18"),
    ("native_command_branch_v18", "0.18"),
    ("native_command_default_v18", "0.18"),
    ("prompt_workflow_v17", "0.17"),
    ("telecommand_modes_v18", "0.11"),
    ("tutorial_core_v18", "0.17"),
)


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
              terminal: str = "completed", ir_version: str = "0.18", artifacts: tuple[str, ...] = (),
              provider: str = "nominal", failure_answers: tuple[str, ...] = ()) -> dict:
    case = _case("v18-" + identity, source, variables=variables, logs=logs,
        diagnostic=diagnostic, terminal=terminal, artifacts=("FUNCTION-SEND", *artifacts))
    case.update(prompts=prompts or [], confirmations=list(confirmations), expected_telecommands=commands or [],
        expected_built_commands=list(built), expected_ir_version=ir_version,
        provider=provider, failure_answers=list(failure_answers))
    return case


_BRANCH = ('command = BuildTC("CMDNAME")\nmask = 2 ** 3 | 1\n'
    'answer = Prompt("Run simulated command?", YES_NO)\n'
    'if answer == "YES" and mask & 1 == 1:\n    Send(command=command)\n    Display("command completed")\n'
    'else:\n    Display("no command requested")\n')
_NUMERIC = ('threshold = 2 ** 2\nanswer = Prompt("Command threshold", NUM)\n'
    'if answer >= threshold:\n    Send(command="CMDNAME")\n    Display("threshold met")\n'
    'else:\n    Display("below threshold; no command requested")\n')
_CONFIRMED = ('answer = Prompt("Prepare command?", YES_NO)\n'
    'if answer == "YES":\n    Send(command="CMDNAME", Confirm=True)\n    Display("confirmed command completed")\n')
_DEFAULT = ('answer = Prompt("Send only with YES", YES_NO, Default="NO", Timeout=5*SECOND)\n'
    'if answer == "YES":\n    Send(command="CMDNAME")\n    Display("command completed")\n'
    'else:\n    Display("no command requested")\n')


def _rejected_command(*, prompt_user: bool) -> dict:
    return {**_tc("CMDNAME", modifiers={"on_failure": "CONTINUE", "prompt_user": prompt_user}),
        "successful": False, "execution_succeeded": False, "provider_call_count": 1,
        "dispositions": ["TRANSPORT_REJECTED"], "onboard_execution": ["NOT_ATTEMPTED"]}


def _verification_failure() -> dict:
    return {**_tc("CMDNAME", modifiers={"verification": [["TM1", "eq", 1]], "on_failure": "CONTINUE", "prompt_user": False},
        effective=[_effective(verification=[{"channel": "TM1", "operator": "eq", "expected": 1, "tolerance": None, "timeout_ms": None}], on_failure="CONTINUE", prompt_user=False)]),
        "successful": False, "provider_call_count": 6, "dispositions": ["VERIFICATION_FAILED"]}

NEW_CASES = (
    _new_case("native-yes-built-command", _BRANCH, variables={"answer": "YES", "mask": 9},
        logs=[("command completed", "info")], built=("CMDNAME",), commands=[_tc("CMDNAME", selector="item")],
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", "YES")], artifacts=("FUNCTION-BUILDTC", "FUNCTION-PROMPT", "SYNTAX-IF-ELIF-ELSE")),
    _new_case("native-no-no-dispatch", _BRANCH, variables={"answer": "NO", "mask": 9},
        logs=[("no command requested", "info")], built=("CMDNAME",),
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", "NO")], artifacts=("FUNCTION-PROMPT",)),
    _new_case("native-cancel-no-dispatch", _BRANCH, variables={"mask": 9}, terminal="aborted", built=("CMDNAME",),
        prompts=[inherited._prompt("Run simulated command?", "YES_NO", None, outcome="CANCELLED")], artifacts=("FUNCTION-PROMPT",)),
    _new_case("numeric-guard-sends", _NUMERIC, variables={"answer": 5.0, "threshold": 4},
        logs=[("threshold met", "info")], commands=[_tc("CMDNAME")],
        prompts=[inherited._prompt("Command threshold", "NUM", "5")], artifacts=("CONSTANT-PROMPT-TYPE-NUM", "OPERATOR-PYTHON-POWER")),
    _new_case("numeric-guard-skips", _NUMERIC, variables={"answer": 2.5, "threshold": 4},
        logs=[("below threshold; no command requested", "info")],
        prompts=[inherited._prompt("Command threshold", "NUM", "2.5")], artifacts=("CONSTANT-PROMPT-TYPE-NUM",)),
    _new_case("native-plus-command-confirmation", _CONFIRMED, variables={"answer": "YES"},
        logs=[("confirmed command completed", "info")], confirmations=("YES",),
        prompts=[inherited._prompt("Prepare command?", "YES_NO", "YES")],
        commands=[_tc("CMDNAME", modifiers={"confirm": True})], artifacts=("MODIFIER-CONFIRM",)),
    _new_case("command-confirmation-denied", _CONFIRMED, variables={"answer": "YES"}, terminal="failed", confirmations=("NO",),
        prompts=[inherited._prompt("Prepare command?", "YES_NO", "YES")], artifacts=("MODIFIER-CONFIRM",)),
    _new_case("default-no-policy-declaration", _DEFAULT, variables={"answer": "NO"},
        logs=[("no command requested", "info")], prompts=[inherited._prompt("Send only with YES", "YES_NO", "NO", default="NO", timeout=5.0)],
        artifacts=("FUNCTION-PROMPT", "OUTCOME-PROMPT-TIMEOUT")),
    _new_case("direct-command-empty-display", 'Send(command="CMDNAME")\nDisplay("")\n',
        logs=[("", "info")], commands=[_tc("CMDNAME")], artifacts=("FUNCTION-DISPLAY",)),
    _new_case("built-literal-arguments", 'power = 2 ** 3\ncommand = BuildTC("CMDNAME", args=[["ARG1", 1.0]])\nSend(command=command)\nDisplay("built argument")\n',
        variables={"power": 8}, logs=[("built argument", "info")], built=("CMDNAME",),
        commands=[_tc("CMDNAME", selector="item", planned_arguments=[[_argument("ARG1", 1.0, encoded="1")]])], artifacts=("FUNCTION-BUILDTC",)),
    _new_case("load-only-is-not-execution", 'power = 2 ** 3\nSend(command="CMDNAME", LoadOnly=True)\nDisplay("loaded only")\n',
        variables={"power": 8}, logs=[("loaded only", "info")],
        commands=[_tc("CMDNAME", modifiers={"load_only": True}, load_only=True)], artifacts=("MODIFIER-LOADONLY",)),
    _new_case("sequential-group", 'power = 2 ** 3\nSend(group=["CMD1", "CMD2"])\nDisplay("group completed")\n',
        variables={"power": 8}, logs=[("group completed", "info")], commands=[_tc("CMD1", "CMD2", selector="group", mode="GROUP")]),
    _new_case("inherited-direct-send", 'Send(command="CMDNAME")\nDisplay("direct completed")\n',
        logs=[("direct completed", "info")], commands=[_tc("CMDNAME")], ir_version="0.11"),
    _new_case("sequence-expansion", 'Send(sequence="SEQNAME")\n', ir_version="0.11",
        commands=[_tc("CMD1", "CMD2", "CMD3", mode="SEQUENCE")]),
    _new_case("block-group-transport", 'Send(group=["CMD1", "CMD2"], Block=True)\n', ir_version="0.11",
        commands=[_tc("CMD1", "CMD2", selector="group", modifiers={"block": True}, mode="BLOCK", calls=9)]),
    _new_case("group-shared-transport", 'Send(group=["CMD1", "CMD2"], Group=True)\n', ir_version="0.11",
        commands=[_tc("CMD1", "CMD2", selector="group", modifiers={"group": True}, mode="GROUP", grouped=True, calls=9)]),
    _new_case("critical-confirmation", 'Send(command="TC.SIMULATOR.RESET", ConfirmCritical=True)\n', ir_version="0.11", confirmations=("YES",),
        commands=[_tc("TC.SIMULATOR.RESET", modifiers={"confirm_critical": True}, planned_arguments=[[_argument("FORCE", False, "BOOLEAN", encoded="false")]])]),
    _new_case("absolute-command-time", 'Send(command="CMDNAME", Time="2008/04/10 10:30:00")\n', ir_version="0.11",
        commands=[_tc("CMDNAME", modifiers={"time": "2008/04/10 10:30:00"}, effective=[_effective(time="2008-04-10T10:30:00Z")])]),
    _new_case("relative-release-intent", 'Send(command="CMDNAME", ReleaseTime=NOW + 30*MINUTE)\n', ir_version="0.11",
        commands=[_tc("CMDNAME", modifiers={"release_time": "NOW+1800s"})]),
    _new_case("bounded-delay-and-timeout", 'Send(command="CMDNAME", Timeout=1*MINUTE, SendDelay=2*SECOND, Delay=1*SECOND)\n', ir_version="0.11",
        commands=[_tc("CMDNAME", modifiers={"timeout_seconds": 60, "send_delay_seconds": 2, "verification_delay_seconds": 1},
            effective=[_effective(timeout_ms=60000, send_delay_ms=2000, delay_ms=1000)])]),
    _new_case("literal-radix-format", 'Send(command="CMDNAME", args=[["ARG2", 0xFF, {ValueType: LONG, ValueFormat: RAW, Radix: HEX}]])\n', ir_version="0.11",
        commands=[_tc("CMDNAME", arguments=[["ARG2", 255, {"ValueType": "LONG", "ValueFormat": "RAW", "Radix": "HEX"}]],
            planned_arguments=[[_argument("ARG2", 255, "LONG", "RAW", "HEX", "0xFF")]])]),
    _new_case("additional-driver-info", 'Send(command="CMDNAME", addInfo={"purpose": "qualification"})\n', ir_version="0.11",
        commands=[_tc("CMDNAME", modifiers={"additional_info": {"purpose": "qualification"}})]),
    _new_case("verification-success", 'Send(command="CMDNAME", verify=[["TM1", eq, 10.0, {Tolerance: 0.1, Timeout: 20}]], AdjLimits=True)\n', ir_version="0.11",
        commands=[_tc("CMDNAME", modifiers={"verification": [["TM1", "eq", 10.0, {"Tolerance": 0.1, "Timeout": 20}]], "adjust_limits": True},
            effective=[_effective(verification=[{"channel": "TM1", "operator": "eq", "expected": 10.0, "tolerance": 0.1, "timeout_ms": 20000}], adjust_limits=True)], verified=True)]),
    _new_case("per-command-override", 'Send(group=["CMD1", "CMD2"], Timeout=20, PerCommand={"1": {"Timeout": 30, "on_failure": "ABORT", "prompt_user": False}})\n', ir_version="0.11",
        commands=[_tc("CMD1", "CMD2", selector="group", mode="GROUP",
            modifiers={"timeout_seconds": 20, "per_command": {"1": {"timeout_seconds": 30, "on_failure": "ABORT", "prompt_user": False}}},
            effective=[_effective(timeout_ms=20000), _effective(timeout_ms=30000, on_failure="ABORT", prompt_user=False)])]),
    _new_case("successful-failure-policy", 'Send(command="CMDNAME", OnFailure=CONTINUE, PromptUser=False)\n', ir_version="0.11",
        commands=[_tc("CMDNAME", modifiers={"on_failure": "CONTINUE", "prompt_user": False})]),
    _new_case("transport-rejection-continue", 'Send(command="CMDNAME", OnFailure=CONTINUE, PromptUser=False)\nDisplay("continued after known rejection")\n', ir_version="0.11",
        provider="reject_transport", logs=[("continued after known rejection", "info")], commands=[_rejected_command(prompt_user=False)]),
    _new_case("transport-rejection-prompt-user", 'Send(command="CMDNAME", OnFailure=CONTINUE, PromptUser=True)\nDisplay("operator allowed continuation")\n', ir_version="0.11",
        provider="reject_transport", failure_answers=("YES",), logs=[("operator allowed continuation", "info")], commands=[_rejected_command(prompt_user=True)]),
    _new_case("verification-failure-stops", 'Send(command="CMDNAME", verify=[["TM1", eq, 1]], OnFailure=CONTINUE, PromptUser=False)\nDisplay("must not appear")\n', ir_version="0.11",
        provider="fail_verification", terminal="failed", commands=[_verification_failure()]),
    _new_case("reject-native-command-selector", 'answer = Prompt("Command name", ALPHA)\nSend(command=answer)\n',
        diagnostic="SPELL938"),
    _new_case("reject-native-command-argument", 'answer = Prompt("Argument", NUM)\nSend(command="CMDNAME", args=[["ARG1", answer]])\n',
        diagnostic="SPELL914"),
    _new_case("reject-mixed-data-service", 'answer = Prompt("Proceed", YES_NO)\nSend(command="CMDNAME")\nDataContainer("CONTAINER.A", schema_revision=1)\n',
        diagnostic="SPELL937"),
    _new_case("reject-nested-language-service", 'result = ""\nanswer = Prompt("Proceed", YES_NO)\nSend(command="CMDNAME")\nLanguageCheck(0, profile="0.18", target=result)\n',
        diagnostic="SPELL937"),
)
CASES = inherited.CASES + NEW_CASES
CASESET_SHA256 = digest(canonical_bytes(CASES))
ALL_SELECTION = 195 + len(CASES)


def expected_image_runner_proof() -> dict:
    return {"ir_version": "0.18", "steps": 7, "direct_and_boundary_cases": len(CASES),
        "adapted_examples": 195, "adapted_variants": 257, "full_compatibility": False,
        "cases_sha256": CASESET_SHA256, "decision": "PASS"}


def _expected_result(case: dict) -> dict:
    base = inherited._expected_result(case)
    if case in NEW_CASES:
        base.update(ir_version=case["expected_ir_version"] if case["expected_diagnostic"] is None else None,
            telecommands=case["expected_telecommands"], built_commands=case["expected_built_commands"],
            confirmations=case["confirmations"], failure_answers=case["failure_answers"])
    return base


def _compile(case: dict):
    from .procedure_parser import ProcedureCatalog, ProcedureValidationError
    if case not in NEW_CASES or len(case["source"].encode("utf-8")) > 20_000:
        raise ValueError("case is outside the closed v0.18 registry")
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
              prompts: list, commands: list, built: list, confirmations: list, failure_answers: list) -> dict:
    actual = inherited._observed_result(case, terminal, values, logs, prompts)
    actual.update(ir_version=procedure.ir_version, telecommands=commands, built_commands=built,
        confirmations=confirmations, failure_answers=failure_answers)
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


def run_case(case: dict) -> dict:
    if case in inherited.CASES:
        return inherited.run_case(case)
    from .worker import worker_main
    from .telecommand_runtime_v11 import confirmation_prompt_id, failure_prompt_id, prepare_send_request, validate_send_request, execute_preflight
    procedure = _compile(case)
    if procedure is None:
        return _expected_result(case)
    context = multiprocessing.get_context("spawn")
    control, output = context.Queue(), context.Queue()
    process = WorkerProcess(context.Process(target=worker_main, args=(case["id"], 1, procedure.ir_version,
        list(procedure.steps), 0, "conformance", None, {}, control, output, None, None, False)))
    values, logs, prompts, commands, built, confirmations = {}, [], [], [], [], []
    failure_answers, results, result_steps = [], [], []
    terminal, committed_commands = None, 0
    process.start()
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            try:
                message = output.get(timeout=0.2)
            except queue.Empty:
                if process.is_alive():
                    continue
                # The child may have flushed and exited after get timed out.
                # Consume its real tail before declaring the channel exhausted.
                try:
                    message = output.get_nowait()
                except queue.Empty:
                    break
            if time.monotonic() >= deadline:
                break
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
            elif kind == "telecommand_requested":
                step = procedure.steps[message["step_index"]]
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
                values = message["variables"]
                step = procedure.steps[message["step_index"]]
                effects = message.get("effects", [])
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
        if process.is_alive() or process.exitcode != 0 or committed_commands != expected_commits:
            raise ValueError(f"{case['id']}: worker or command settlement did not finish cleanly")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        control.close()
        output.close()
    return _observed(case, procedure, terminal, values, logs, prompts, commands, built, confirmations, failure_answers)


def evaluate_fixed_case(case: dict) -> dict:
    """No broker messages or durable dispatch: isolated deterministic helpers only."""
    if case in inherited.CASES:
        return inherited.evaluate_fixed_case(case)
    from .worker import ExpressionEvaluationError, evaluate_expression
    from .prompt_v17 import NativePromptError, native_prompt_result
    from .telecommand_runtime_v11 import (TelecommandRuntimeError, build_item_checkpoint_for_step,
        confirmation_prompt_id, prepare_send_request, execute_preflight, result_failure_policy)
    procedure = _compile(case)
    if procedure is None: return _expected_result(case)
    if len(procedure.steps) > 4096: raise ValueError("closed fixture exceeds its instruction bound")
    values, logs, prompts, commands, built, confirmations = {}, [], [], [], [], []
    failure_answers = []
    terminal = "completed"
    try:
        for step in procedure.steps:
            if step["type"] not in {"variable_set", "display", "log", "prompt", "build_tc", "send_tc"}:
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
    except (ExpressionEvaluationError, NativePromptError, TelecommandRuntimeError):
        terminal = "failed"
    return _observed(case, procedure, terminal, values, logs, prompts, commands, built, confirmations, failure_answers)


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
    payload = {"schema_version": "spell.v18.language-check-result/1", "selection": selection,
        "cases_sha256": CASESET_SHA256, "evidence_kind": "ISOLATED_PRODUCTION_HELPERS_NO_OUTER_DISPATCH",
        "full_compatibility": False, "cases": cases, "adaptations": examples,
        "unqualified_artifacts_remain": True, "summary": summary}
    if len(canonical_bytes(payload)) > 192_000: raise ValueError("language report exceeds its bound")
    return summary, [{"event_type": "procedure.language_check_completed", "source": "simulator", "severity": "info", "payload": payload}]


def coverage_contract() -> dict:
    contract = inherited.coverage_contract()
    contract = json.loads(canonical_bytes(contract))
    contract.update(schema_version="spell.v18.language-coverage/1", cases_sha256=CASESET_SHA256,
        inherited_v17_cases_sha256=inherited.CASESET_SHA256)
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
    contract["scopes"].append({"id": "V18-NATIVE-TELECOMMAND", "description": "Exact native prompt/core/Display and literal simulator command source cases listed here; real worker and validated simulator service requests/results.",
        "source_sha256": SOURCE_SHA256, "manual_pages": "17-23, 47-55, 68, 70-72",
        "proof_kind": "EXPLICIT_BOUNDED_SOURCE_AND_SIMULATOR_SERVICE_OBLIGATIONS",
        "checks": [case["id"] for case in NEW_CASES],
        "excludes": ["native answers in command operands", "external command transport", "data/file/environment/observation mixtures", "durable supervisor recovery and real timer scheduling (separate API/browser proofs)"]})
    contract["remaining_work"] = [
        "Qualify each entire manual artifact before marking it SUPPORTED.",
        "Native values may guard literal commands; dynamic command operands and other service combinations remain restricted.",
        "Collections, dynamic typing, general Python, external drivers and unresolved manual conflicts remain gaps."]
    return contract


def _report(results: list, contract: dict, selection: str) -> dict:
    selected = {result["id"] for result in results}
    return {"schema_version": REPORT_SCHEMA, "release": "v0.18.0", "source_sha256": SOURCE_SHA256,
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
        raise ValueError("v0.18 coverage contract is stale")
    selected = [case for case in CASES if case_id is None or case["id"] == case_id]
    if not selected: raise ValueError("unknown conformance case")
    return _report([run_case(case) for case in selected], contract, case_id or "ALL")


def validate_report(report: dict) -> None:
    contract = coverage_contract()
    if COVERAGE_PATH.stat().st_size > 1_000_000 or json.loads(COVERAGE_PATH.read_bytes()) != contract:
        raise ValueError("language coverage contract differs from current source")
    if len(canonical_bytes(report)) > 1_000_000 or canonical_bytes(report) != canonical_bytes(_report([_expected_result(case) for case in CASES], contract, "ALL")):
        raise ValueError("language evidence has stale, missing or unproved results")
