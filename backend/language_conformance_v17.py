"""Versioned direct-source proof, bounded runner checks and honest language gaps.

Reports are observations from separate real workers. The interactive runner
uses shared production expression/settlement helpers over the same fixed source
registry; it does not simulate a supervisor clock or claim recovery evidence.
"""
from __future__ import annotations

import json
import multiprocessing
import queue
import time
from collections import Counter
from typing import Any

from .language_conformance_v16 import (
    CASES as V16_CASES, ROOT, SOURCE_SHA256, INVENTORY_SHA256, PREFIX,
    _case, canonical_bytes, digest, source_inventory,
)
from .language_cases_core_v17 import CASES as CORE_CASES
from .worker_process import WorkerProcess

COVERAGE_PATH = ROOT / "contracts/v17/language_coverage.json"
REPORT_SCHEMA = "spell.v17.language-conformance/1"
PROMPT_OBSERVATIONS = ("question", "prompt_type", "choices", "default", "list_mode",
                       "warning_delay_seconds", "response_timeout_seconds", "no_controller_grace_seconds")


def _prompt(question: str, prompt_type: str, response: Any, *, choices: list | None = None,
            mode: str | None = None, default: Any = None, warning: float | None = None,
            timeout: float | None = None, outcome: str = "ANSWERED") -> dict[str, Any]:
    fixed = {"OK": ["OK"], "CANCEL": ["CANCEL"], "OK_CANCEL": ["OK", "CANCEL"],
             "YES": ["YES"], "NO": ["NO"], "YES_NO": ["YES", "NO"]}
    return {"observed": {"question": question, "prompt_type": prompt_type,
        "choices": fixed.get(prompt_type, []) if choices is None else choices,
        "default": default, "list_mode": mode, "warning_delay_seconds": warning,
        "response_timeout_seconds": timeout, "no_controller_grace_seconds": None},
        "settlements": [{"outcome": outcome, "response": response}]}


def _prompt_case(identity: str, source: str, prompt: dict, *, result: Any = None,
                 artifacts: tuple[str, ...] = (), terminal: str = "completed") -> dict:
    case = _case("v17-prompt-" + identity, source,
        variables={} if terminal != "completed" or result is None else {"answer": result},
        logs=[("settled", "info")] if terminal == "completed" else [], terminal=terminal,
        artifacts=("FUNCTION-PROMPT", "TYPE-PROMPTRESULT", *artifacts))
    case["prompts"] = [prompt]
    case["absent_variables"] = ["answer"] if terminal != "completed" else []
    return case


PROMPT_CASES = tuple(
    _prompt_case(name.lower().replace("_", "-"), f'answer = Prompt("Choice", {name})\nDisplay("settled")\n',
        _prompt("Choice", name, response), result=response,
        artifacts=("CONSTANT-PROMPT-TYPE-" + name.replace("_", "-"),))
    for name, response in (("OK", "OK"), ("CANCEL", "CANCEL"), ("OK_CANCEL", "CANCEL"),
                           ("YES", "YES"), ("NO", "NO"), ("YES_NO", "NO"))
) + (
    _prompt_case("default-type", 'Prompt("Ready")\nDisplay("settled")\n', _prompt("Ready", "OK", "OK")),
    _prompt_case("alpha", 'answer = Prompt("Note", Type=ALPHA)\nDisplay("settled")\n',
        _prompt("Note", "ALPHA", "nominal"), result="nominal", artifacts=("CONSTANT-PROMPT-TYPE-ALPHA",)),
    _prompt_case("number", 'answer = Prompt("Rate", NUM)\nDisplay("settled")\n',
        _prompt("Rate", "NUM", "2.5"), result=2.5, artifacts=("CONSTANT-PROMPT-TYPE-NUM",)),
    _prompt_case("date", 'answer = Prompt("Date", DATE)\nDisplay("settled")\n',
        _prompt("Date", "DATE", "2026-10-02"), result="2026-10-02", artifacts=("CONSTANT-PROMPT-TYPE-DATE",)),
    _prompt_case("list-key", 'answer = Prompt("Route", ["A:Primary", "B:Backup"], Type=LIST)\nDisplay("settled")\n',
        _prompt("Route", "LIST", "B", choices=[{"key": "A", "label": "Primary"}, {"key": "B", "label": "Backup"}], mode="KEY"),
        result="B", artifacts=("CONSTANT-PROMPT-TYPE-LIST",)),
    _prompt_case("list-numeric-key", 'answer = Prompt("Route", ["1:Primary", "2:Backup"], Type=LIST)\nDisplay("settled")\n',
        _prompt("Route", "LIST", "2", choices=[{"key": "1", "label": "Primary"}, {"key": "2", "label": "Backup"}], mode="KEY"), result="2"),
    _prompt_case("list-index", 'answer = Prompt("Route", ["Primary", "Backup"], Type=LIST|NUM)\nDisplay("settled")\n',
        _prompt("Route", "LIST", 1, choices=["Primary", "Backup"], mode="INDEX"), result=1,
        artifacts=("SYNTAX-PROMPT-LIST-NUM",)),
    _prompt_case("list-value", 'answer = Prompt("Route", ["Primary", "Backup"], Type=LIST|ALPHA)\nDisplay("settled")\n',
        _prompt("Route", "LIST", "Backup", choices=[{"value": "Primary", "label": "Primary"}, {"value": "Backup", "label": "Backup"}], mode="VALUE"),
        result="Backup", artifacts=("SYNTAX-PROMPT-LIST-ALPHA",)),
    _prompt_case("default-deadline-declaration", 'answer = Prompt("Route", ["A :Primary", "B :Backup"], Type=LIST, Default="A", Timeout=1*MINUTE)\nDisplay("settled")\n',
        _prompt("Route", "LIST", "A", choices=[{"key": "A", "label": "Primary"}, {"key": "B", "label": "Backup"}],
                mode="KEY", default="A", timeout=60.0), result="A", artifacts=("OUTCOME-PROMPT-TIMEOUT",)),
    _prompt_case("warning-only-declaration", 'answer = Prompt("Continue", Type=YES_NO, Timeout=1*MINUTE)\nDisplay("settled")\n',
        _prompt("Continue", "YES_NO", "YES", warning=60.0), result="YES", artifacts=("OUTCOME-PROMPT-TIMEOUT",)),
    _prompt_case("zero-timeout", 'answer = Prompt("Continue", Type=YES_NO, Default="NO", Timeout=0)\nDisplay("settled")\n',
        _prompt("Continue", "YES_NO", "YES"), result="YES", artifacts=("OUTCOME-PROMPT-TIMEOUT",)),
    _prompt_case("default-without-timeout", 'answer = Prompt("Continue", Type=YES_NO, Default="NO")\nDisplay("settled")\n',
        _prompt("Continue", "YES_NO", "YES"), result="YES"),
    _prompt_case("cancel-no-result", 'answer = Prompt("Continue", Type=YES_NO)\nDisplay("must not appear")\n',
        _prompt("Continue", "YES_NO", None, outcome="CANCELLED"), terminal="aborted"),
    _case("v17-display-empty", 'Display("")\n', logs=[("", "info")], artifacts=("FUNCTION-DISPLAY",)),
    _case("v17-display-dynamic-empty", 'message = ""\nDisplay(message, Severity=WARNING)\n',
          variables={"message": ""}, logs=[("", "warning")], artifacts=("FUNCTION-DISPLAY", "MODIFIER-SEVERITY")),
    _case("v17-display-whitespace", 'Display("  ", ERROR)\n', logs=[("  ", "error")], artifacts=("FUNCTION-DISPLAY",)),
)

CASES = V16_CASES + CORE_CASES + PROMPT_CASES
CASESET_SHA256 = digest(canonical_bytes(CASES))
ALL_SELECTION = 195 + len(CASES)
MAX_RUNTIME_REPORT_BYTES = 192_000


def expected_image_runner_proof() -> dict[str, Any]:
    return {"ir_version": "0.17", "steps": 7, "direct_and_boundary_cases": len(CASES),
        "adapted_examples": 195, "adapted_variants": 257, "full_compatibility": False,
        "cases_sha256": CASESET_SHA256, "decision": "PASS"}


def coverage_contract() -> dict[str, Any]:
    from .language_conformance_v16 import coverage_contract as old_contract
    inherited = old_contract()
    bindings: dict[str, list[dict]] = {}
    for case in CASES:
        if digest(case["source"].encode("utf-8")) != case["source_sha256"]:
            raise ValueError("case source identity differs")
        for identity in case["artifacts"]:
            bindings.setdefault(identity, []).append(case)
    inventory = source_inventory()
    if set(bindings) - {item["ArtifactId"] for item in inventory} or len({case["id"] for case in CASES}) != len(CASES):
        raise ValueError("language case or artifact identity is invalid")
    rows = []
    for old in inherited["rows"]:
        cases = bindings.get(old["id"], [])
        positive = [case for case in cases if case["expected_diagnostic"] is None]
        # Display's section documents Severity, not the generic Notify modifier.
        # Its inherited rejection is a source boundary, not proof that a
        # documented Notify form is missing from every applicable service.
        rejected = [case for case in cases if case["expected_diagnostic"] is not None
                    and not (old["id"] == PREFIX + "MODIFIER-NOTIFY" and case["id"] == "reject-silent-display")]
        if old["kind"] == "Example":
            status, implementation, reasons = "ADAPTED", "SIMULATOR_ADAPTATION", ["MISSING_PROOF"]
        elif old["kind"] == "SourceErratum":
            status, implementation, reasons = "GAP", "NOT_ASSESSED", ["MANUAL_CONFLICT"]
        elif positive:
            status, implementation = "PARTIAL", "BOUNDED_IMPLEMENTATION"
            reasons = (["MISSING_IMPLEMENTATION"] if rejected else []) + ["MISSING_PROOF"]
        elif rejected:
            status, implementation, reasons = "GAP", "EXPLICITLY_UNIMPLEMENTED", ["MISSING_IMPLEMENTATION"]
        else:
            status = "PARTIAL" if old["status"] == "PARTIAL" else "GAP"
            implementation = "BOUNDED_IMPLEMENTATION" if status == "PARTIAL" else "NOT_ASSESSED"
            reasons = ["MISSING_PROOF"]
        rows.append({"id": old["id"], "kind": old["kind"], "name": old["name"], "pages": old["pages"],
            "status": status, "implementation": implementation, "gap_reasons": reasons,
            "checks": [case["id"] for case in cases], "whole_artifact_supported": False})
    return {"schema_version": "spell.v17.language-coverage/1", "source_sha256": SOURCE_SHA256,
        "inventory_sha256": INVENTORY_SHA256, "cases_sha256": CASESET_SHA256,
        "inherited_v16_cases_sha256": digest(canonical_bytes(V16_CASES)),
        "artifact_count": 763, "full_compatibility": False, "rows": rows,
        "gap_reasons": {
            "MISSING_IMPLEMENTATION": "A rejection is explicitly mapped to a documented form; a successful rejection test does not implement it. Undocumented call combinations prove boundaries only.",
            "MISSING_PROOF": "The complete manual artifact has no direct conformance proof; implementation may be bounded or not assessed.",
            "MANUAL_CONFLICT": "Contradictory manual statements need an explicit interpretation and proof for that scope."},
        "scopes": [
            {"id": "V17-CORE", "description": "Exact scalar, operator, branch and literal range source cases listed here; fixed scalar types, finite numbers and bounded loops.",
             "source_sha256": SOURCE_SHA256, "manual_pages": "17-23", "proof_kind": "EXPLICIT_BOUNDED_SOURCE_OBLIGATIONS",
             "checks": [case["id"] for case in CORE_CASES], "excludes": ["dynamic type changes", "collections", "general Python evaluation",
                 "IR0.17 mixed with earlier data, argument, file, environment or telecommand service profiles"]},
            {"id": "V17-DISPLAY-PROMPT", "description": "Exact native Display/Prompt declarations, answered typed results and cancellation cases listed here; scripted external settlements.",
             "source_sha256": SOURCE_SHA256, "manual_pages": "68, 70-72", "proof_kind": "EXPLICIT_BOUNDED_SOURCE_OBLIGATIONS",
             "checks": [case["id"] for case in PROMPT_CASES], "excludes": ["supervisor deadline scheduling", "durable recovery", "external GUI/driver parity",
                 "IR0.17 mixed with earlier data, argument, file, environment or telecommand service profiles"]}],
        "manual_decisions": [{"source_pages": "71-72, 116-117", "decision": "Section 4.12: positive Timeout without Default warns and keeps waiting; zero waits indefinitely.",
            "scope": "Native Prompt in IR0.17; earlier lowercase project forms keep their contract.",
            "remaining_reason": "MANUAL_CONFLICT"}],
        "defaults": {**inherited["defaults"], "direct_default_checks": ["display-default", "v17-prompt-default-type"],
            "unqualified_defaults_remain_gaps": True},
        "remaining_work": ["Qualify each whole manual artifact before marking it SUPPORTED.",
            "Implement known collection, function, import and dynamic-type gaps.",
            "Qualify IR0.17 combinations with earlier data, argument, file, environment and telecommand services; existing service Display retains its prior nonempty-log bounds.",
            "Qualify service modifiers, external drivers and every unresolved manual conflict."]}


def _expected_result(case: dict) -> dict:
    return {"id": case["id"], "source_sha256": case["source_sha256"],
        "mode": "EXPECTED_REJECTION" if case["expected_diagnostic"] else "DIRECT_SOURCE",
        "diagnostic": case["expected_diagnostic"], "terminal": None if case["expected_diagnostic"] else case["expected_terminal"],
        "variables": case["expected_variables"], "logs": case["expected_logs"],
        "prompts": [prompt["observed"] for prompt in case.get("prompts", [])],
        "absent_variables": case.get("absent_variables", []), "passed": True}


def _compile(case: dict):
    from .procedure_parser import ProcedureCatalog, ProcedureValidationError
    if case not in CASES or len(case["source"].encode("utf-8")) > 20_000:
        raise ValueError("case is outside the closed source registry")
    try:
        procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"], case["id"] + ".spell.py")
    except ProcedureValidationError as exc:
        if exc.diagnostics[0].code != case["expected_diagnostic"]:
            raise ValueError(f"{case['id']}: unexpected diagnostic {exc.diagnostics[0].code}") from exc
        return None
    if case["expected_diagnostic"] is not None:
        raise ValueError(f"{case['id']}: source was unexpectedly accepted")
    return procedure


def _observed_result(case: dict, terminal: str | None, variables: dict, logs: list, prompts: list) -> dict:
    if terminal != case["expected_terminal"] or logs != case["expected_logs"] or prompts != [p["observed"] for p in case.get("prompts", [])] or any(
        type(variables.get(key)) is not type(value) or variables.get(key) != value for key, value in case["expected_variables"].items()
    ) or any(name in variables for name in case.get("absent_variables", [])):
        raise ValueError(f"{case['id']}: observed terminal/variables/logs/prompts differ from the oracle")
    result = _expected_result(case)
    result.update(terminal=terminal, variables={key: variables[key] for key in case["expected_variables"]}, logs=logs, prompts=prompts)
    return result


def run_case(case: dict) -> dict:
    """Real isolated worker execution; the caller supplies external settlements."""
    from .worker import worker_main
    procedure = _compile(case)
    if procedure is None:
        return _expected_result(case)
    context = multiprocessing.get_context("spawn")
    control, output = context.Queue(), context.Queue()
    process = WorkerProcess(context.Process(target=worker_main, args=(case["id"], 1, procedure.ir_version,
        list(procedure.steps), 0, "conformance", None, {}, control, output, None, None, False)))
    process.start()
    terminal, variables, logs, prompts = None, {}, [], []
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            try:
                item = output.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                if process.is_alive():
                    continue
                # The child may have flushed and exited after get timed out.
                # Consume its real tail before declaring the channel exhausted.
                try:
                    item = output.get_nowait()
                except queue.Empty:
                    break
            if time.monotonic() >= deadline:
                break
            if item.get("kind") == "prompt_opened":
                ordinal = len(prompts)
                if ordinal >= len(case.get("prompts", [])):
                    raise ValueError("worker opened an unexpected prompt")
                prompts.append({key: item.get(key) for key in PROMPT_OBSERVATIONS})
                for attempt, settlement in enumerate(case["prompts"][ordinal]["settlements"]):
                    control.put({"type": "prompt_settlement", "prompt_id": item["prompt_id"],
                        "settlement_id": f"conformance-{ordinal}-{attempt}", "command_id": None, **settlement})
            elif item.get("kind") == "step_commit":
                variables = item["variables"]
                logs.extend([effect["payload"]["message"], effect["severity"]]
                    for effect in item.get("effects", []) if effect.get("event_type") == "procedure.log")
            elif item.get("kind") == "terminal":
                terminal = item["state"]
                break
        process.join(timeout=1)
        if process.is_alive() or process.exitcode != 0:
            raise ValueError(f"{case['id']}: worker did not exit cleanly")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        control.close()
        output.close()
    return _observed_result(case, terminal, variables, logs, prompts)


def evaluate_fixed_case(case: dict) -> dict:
    """Bounded helper execution, independent from the real-worker producer."""
    from .worker import ExpressionEvaluationError, evaluate_expression
    from .prompt_v17 import NativePromptError, native_prompt_result, normalize_native_prompt_response
    procedure = _compile(case)
    if procedure is None:
        return _expected_result(case)
    if len(procedure.steps) > 4096:
        raise ValueError("fixed source instruction count exceeds its bound")
    values, logs, prompts, terminal = {}, [], [], "completed"
    try:
        for step in procedure.steps:
            if step["type"] not in {"variable_set", "log", "display", "prompt"}:
                raise ValueError("closed source contains an unsupported effect")
            if "guard" in step and not evaluate_expression(step["guard"], values):
                continue
            if step["type"] == "variable_set":
                value = evaluate_expression(step["expression"], values)
                values[step["name"]] = float(value) if step["declared_type"] == "float" else value
            elif step["type"] in {"log", "display"}:
                message = evaluate_expression(step["message"], values)
                if type(message) is not str or (step["type"] == "log" and not message):
                    raise ExpressionEvaluationError("invalid message value")
                logs.append([message, step["level"]])
            else:
                ordinal = len(prompts)
                if ordinal >= len(case.get("prompts", [])) or "prompt_profile" not in step:
                    raise ValueError("prompt is outside the closed native registry")
                observed = {key: step[key] for key in PROMPT_OBSERVATIONS}
                observed["question"] = evaluate_expression(step["question"], values)
                prompts.append(observed)
                settlements = case["prompts"][ordinal]["settlements"]
                if len(settlements) != 1:
                    raise ValueError("fixed prompt settlement count differs")
                settlement = settlements[0]
                if settlement["outcome"] == "CANCELLED":
                    terminal = "aborted"
                    break
                normalize_native_prompt_response(step, settlement["response"])
                if "response_target" in step:
                    values[step["response_target"]] = native_prompt_result(step, settlement)
    except (ExpressionEvaluationError, NativePromptError):
        terminal = "failed"
    return _observed_result(case, terminal, values, logs, prompts)


def execute_selection(selection: int) -> tuple[str, list[dict]]:
    from .reference_examples_v10 import execute_reference_example
    if type(selection) is not int or not 0 <= selection <= ALL_SELECTION:
        raise ValueError("language selection is outside the closed registry")
    if selection < 195:
        result = execute_reference_example(selection + 1)
        if not result.passed:
            raise ValueError("adaptation oracle failed")
        return result.summary, [{"event_type": "procedure.reference_example_completed", "source": "simulator",
            "severity": "info", "payload": result.as_event_payload()}]
    selected = CASES if selection == ALL_SELECTION else (CASES[selection - 195],)
    cases = [evaluate_fixed_case(case) for case in selected]
    examples = []
    if selection == ALL_SELECTION:
        for number in range(1, 196):
            result = execute_reference_example(number)
            if not result.passed or any(proof.status != "PASS" for proof in result.variant_proofs):
                raise ValueError("adaptation oracle failed")
            examples.append({"example_number": number, "status": result.status,
                "variant_count": len(result.variant_proofs), "evidence_digest": result.evidence_digest})
    summary = f"Language checks: {len(cases)} PASS; {len(examples)} adaptations; full support: false"
    payload = {"schema_version": "spell.v17.language-check-result/1", "selection": selection,
        "cases_sha256": CASESET_SHA256, "evidence_kind": "BOUNDED_PRODUCTION_HELPERS",
        "full_compatibility": False, "cases": cases, "adaptations": examples,
        "unqualified_artifacts_remain": True, "summary": summary}
    if len(canonical_bytes(payload)) > MAX_RUNTIME_REPORT_BYTES:
        raise ValueError("language report exceeds its bound")
    return summary, [{"event_type": "procedure.language_check_completed", "source": "simulator", "severity": "info", "payload": payload}]


def _report(results: list[dict], contract: dict, selection: str) -> dict:
    selected_ids = {result["id"] for result in results}
    return {"schema_version": REPORT_SCHEMA, "release": "v0.17.0", "source_sha256": SOURCE_SHA256,
        "coverage_sha256": digest(canonical_bytes(contract)), "cases_sha256": CASESET_SHA256,
        "selection": selection, "profile_result": "PASS", "full_compatibility": False,
        "artifact_count": 763, "coverage_counts": dict(sorted(Counter(row["status"] for row in contract["rows"]).items())),
        "gap_reason_counts": dict(sorted(Counter(reason for row in contract["rows"] for reason in row["gap_reasons"]).items())),
        "cases": results, "case_count": len(results), "direct_count": sum(row["mode"] == "DIRECT_SOURCE" for row in results),
        "rejection_count": sum(row["mode"] == "EXPECTED_REJECTION" for row in results),
        "unqualified_default_count": 19, "evidence_kind": "REAL_WORKER_AND_PARSER",
        "qualified_scopes": [{**scope, "status": "SUPPORTED", "whole_artifact_supported": False}
            for scope in contract["scopes"] if scope["checks"] and set(scope["checks"]) <= selected_ids],
        "scope": "Fixed local source cases only. Runtime deadline scheduling, recovery and browser evidence are qualified separately; full SPELL support remains incomplete."}


def qualify(case_id: str | None = None) -> dict:
    contract = coverage_contract()
    if not COVERAGE_PATH.is_file() or json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) != contract:
        raise ValueError("v0.17 language coverage contract is stale")
    selected = [case for case in CASES if case_id is None or case["id"] == case_id]
    if not selected:
        raise ValueError("unknown conformance case")
    return _report([run_case(case) for case in selected], contract, case_id or "ALL")


def validate_report(report: dict) -> None:
    """Check closed identities/oracles; release capture independently proves execution."""
    contract = coverage_contract()
    if COVERAGE_PATH.stat().st_size > 1_000_000 or json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) != contract:
        raise ValueError("language coverage contract does not match current source")
    if len(canonical_bytes(report)) > 1_000_000 or canonical_bytes(report) != canonical_bytes(_report([_expected_result(case) for case in CASES], contract, "ALL")):
        raise ValueError("language evidence has stale, missing or unproved results")
