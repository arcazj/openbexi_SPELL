"""Source-bound SPELL 2.4.4 coverage and real-worker conformance checks.

Coverage is deliberately not the test pass rate. An expected rejection proves
the restricted parser boundary, while the corresponding language feature stays
a GAP. The original 195 examples remain separately labelled adaptations.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import queue
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
INVENTORY_SHA256 = "4271e41cc4da39ad715fd7db3fb1205c3beff2ca2f12f3482c322f2db34c8d6b"
INVENTORY_PATH = ROOT / "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/COMPATIBILITY_SOURCE_INVENTORY.json"
COVERAGE_PATH = ROOT / "contracts/v16/language_coverage.json"
REPORT_SCHEMA = "spell.v16.language-conformance/1"
PREFIX = "CMP-LRM244-"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _case(case_id: str, source: str, *, variables: dict[str, Any] | None = None,
          logs: list[tuple[str, str]] | None = None, artifacts: tuple[str, ...] = (),
          diagnostic: str | None = None, terminal: str = "completed") -> dict[str, Any]:
    return {"id": case_id, "source": source, "source_sha256": digest(source.encode("utf-8")),
            "expected_variables": variables or {}, "expected_logs": [list(v) for v in logs or []],
            "expected_diagnostic": diagnostic, "expected_terminal": terminal,
            "artifacts": [PREFIX + value for value in artifacts]}


# New clean-room fixtures exercise documented behavior, not copied manual bodies.
CASES = (
    _case("scalar-inference", 'count = 12\nvoltage = 2.5\nenabled = True\nname = "simulator"\nDisplay(name)\n',
          variables={"count": 12, "voltage": 2.5, "enabled": True, "name": "simulator"},
          logs=[("simulator", "info")], artifacts=("SYNTAX-DYNAMIC-ASSIGNMENT", "TYPE-INTEGER", "TYPE-FLOAT", "TYPE-BOOLEAN", "TYPE-STRING")),
    _case("arithmetic", 'value = (12 + 4) * 3 - 5\nratio = 9 / 2\nremainder = 17 % 5\nDisplay("arithmetic")\n',
          variables={"value": 43, "ratio": 4.5, "remainder": 2}, logs=[("arithmetic", "info")],
          artifacts=("OPERATOR-PYTHON-ADD", "OPERATOR-PYTHON-SUBTRACT", "OPERATOR-PYTHON-MULTIPLY", "OPERATOR-PYTHON-DIVIDE", "OPERATOR-PYTHON-MODULUS")),
    _case("boolean-and-comparison", 'enabled = True and not False\nvalid = 2 < 3 and 3 <= 3 and 4 > 3 and 4 >= 4 and 2 == 2 and 2 != 3\nchoice = False or enabled\nDisplay("boolean")\n',
          variables={"enabled": True, "valid": True, "choice": True}, logs=[("boolean", "info")],
          artifacts=tuple("OPERATOR-PYTHON-" + v for v in ("AND", "OR", "NOT", "EQUAL", "NOT-EQUAL", "LESS", "LESS-EQUAL", "GREATER", "GREATER-EQUAL"))),
    _case("short-circuit", 'valid = False and (1 / 0 > 0)\nready = True or (1 / 0 > 0)\nDisplay("short circuit")\n',
          variables={"valid": False, "ready": True}, logs=[("short circuit", "info")]),
    _case("comments-and-continuation", '"""Source comment."""\n# line comment\nvalue = 8 + \\\n    3\nmessage = ("local "\n           + "simulator")\nDisplay(message,\n        Severity=INFORMATION)\n',
          variables={"value": 11, "message": "local simulator"}, logs=[("local simulator", "info")],
          artifacts=("SYNTAX-DOCSTRING-COMMENT", "SYNTAX-LINE-COMMENT", "SYNTAX-MULTILINE-BACKSLASH", "SYNTAX-MULTILINE-COMMA", "SYNTAX-MULTILINE-STRING-PLUS", "OPERATOR-STRING-CONCAT")),
    _case("case-sensitive-names", 'value = 2\nValue = 7\nDisplay("case sensitive")\n',
          variables={"value": 2, "Value": 7}, logs=[("case sensitive", "info")], artifacts=("SYNTAX-CASE-SENSITIVE-NAMES",)),
    _case("conditional", 'choice = 2\nresult = "unset"\nif choice == 1:\n    result = "first"\nelif choice == 2:\n    result = "second"\nelse:\n    result = "last"\nDisplay(result)\n',
          variables={"result": "second"}, logs=[("second", "info")], artifacts=("SYNTAX-IF-ELIF-ELSE", "SYNTAX-INDENTED-BLOCK")),
    _case("bounded-range", 'total = 0\nfor item in range(2, 8, 2):\n    total += item\nDisplay("range")\n',
          variables={"total": 12}, logs=[("range", "info")], artifacts=("SYNTAX-FOR-IN", "METHOD-CONVERSION-RANGE")),
    _case("reverse-range", 'total = 0\nfor item in range(5, 0, -2):\n    total += item\nDisplay("reverse")\n',
          variables={"total": 9}, logs=[("reverse", "info")]),
    _case("local-function", 'message = "local call"\ndef emit():\n    Display(message)\nemit()\n',
          logs=[("local call", "info")], artifacts=("SYNTAX-FUNCTION-DEFINITION",)),
    _case("display-default", 'Display("default severity")\n', logs=[("default severity", "info")],
          artifacts=("FUNCTION-DISPLAY", "MODIFIER-SEVERITY")),
    _case("display-positional", 'Display("warning severity", WARNING)\n', logs=[("warning severity", "warning")]),
    _case("display-keyword", 'Display("error severity", Severity=ERROR)\n', logs=[("error severity", "error")],
          artifacts=("SYNTAX-KEYWORD-MODIFIER",)),
    _case("integer-literals", 'hexadecimal = 0x2A\nbinary = 0b101010\nDisplay("integer literals")\n',
          variables={"hexadecimal": 42, "binary": 42}, logs=[("integer literals", "info")],
          artifacts=("SYNTAX-INTEGER-BINARY", "SYNTAX-INTEGER-HEXADECIMAL")),
    _case("runtime-division-error", 'value = 1 / 0\nDisplay("must not appear")\n', terminal="failed"),
    _case("recovery-fresh-run", 'value = 6 / 2\nDisplay("recovered")\n', variables={"value": 3.0}, logs=[("recovered", "info")]),
    _case("reject-type-change", 'value = 1\nvalue = "changed"\nDisplay(value)\n', diagnostic="SPELL310"),
    _case("reject-branch-declaration", 'if True:\n    value = 1\nDisplay("unreachable")\n', diagnostic="SPELL308"),
    _case("reject-import", 'import os\nDisplay("unreachable")\n', diagnostic="SPELL103", artifacts=("SYNTAX-IMPORT",)),
    _case("reject-while", 'while True:\n    Display("unbounded")\n', diagnostic="SPELL103", artifacts=("SYNTAX-WHILE",)),
    _case("reject-list", 'value = [1, 2]\nDisplay("unreachable")\n', diagnostic="SPELL705", artifacts=("SYNTAX-LIST-LITERAL", "TYPE-LIST")),
    _case("reject-dictionary", 'value = {"key": 2}\nDisplay("unreachable")\n', diagnostic="SPELL705", artifacts=("SYNTAX-DICTIONARY-LITERAL", "TYPE-DICTIONARY")),
    _case("reject-function-arguments", 'def emit(value):\n    Display(value)\nemit("text")\n', diagnostic="SPELL202"),
    _case("reject-exception-syntax", 'try:\n    Display("text")\nexcept Exception:\n    Display("failure")\n', diagnostic="SPELL103", artifacts=("SYNTAX-TRY-EXCEPT-DRIVER",)),
    _case("reject-silent-display", 'Display("must remain visible", Notify=False)\n', diagnostic="SPELL921", artifacts=("MODIFIER-NOTIFY",)),
    _case("reject-display-duplicate", 'Display("text", WARNING, Severity=ERROR)\n', diagnostic="SPELL922"),
    _case("reject-display-invalid-severity", 'Display("text", Severity="WARNING")\n', diagnostic="SPELL923"),
    _case("reject-display-missing-text", 'Display()\n', diagnostic="SPELL920"),
    _case("reject-display-type", 'Display(42)\n', diagnostic="SPELL706"),
    _case("reject-severity-shadow", 'WARNING = 1\nDisplay("text", WARNING)\n', diagnostic="SPELL309"),
    _case("reject-attribute", 'Display("text".upper())\n', diagnostic="SPELL705", artifacts=("METHOD-STRING-UPPER",)),
    _case("reject-source-evaluation", 'value = eval("1+1")\nDisplay("unreachable")\n', diagnostic="SPELL705"),
)


def source_inventory() -> list[dict[str, Any]]:
    data = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    sources = [v for v in data["sources"] if v["source_code"] == "LRM244"]
    if len(sources) != 1 or sources[0]["source_hash"] != SOURCE_SHA256:
        raise ValueError("Language Reference source identity changed")
    rows = sources[0]["artifacts"]
    if len(rows) != 763 or len({r["ArtifactId"] for r in rows}) != 763:
        raise ValueError("Language Reference inventory is incomplete")
    if digest(canonical_bytes(rows)) != INVENTORY_SHA256:
        raise ValueError("Language Reference inventory identity changed")
    return rows


def coverage_contract() -> dict[str, Any]:
    from .procedure_parser import ProcedureCatalog
    bindings: dict[str, list[dict[str, Any]]] = {}
    for case in CASES:
        for identity in case["artifacts"]:
            bindings.setdefault(identity, []).append(case)
    rows = []
    for item in source_inventory():
        identity, kind, name = item["ArtifactId"], item["Kind"], item["PublicName"]
        cases = bindings.get(identity, [])
        if kind == "Example":
            disposition, reason = "ADAPTED", "EXAMPLE_ADAPTATION"
        elif cases and any(c["expected_diagnostic"] is None for c in cases):
            disposition, reason = "PARTIAL", "BOUNDED_DIRECT_SOURCE"
        elif kind == "Function" and name in ProcedureCatalog._step_calls:
            disposition, reason = "PARTIAL", "RESTRICTED_SERVICE_SIGNATURE"
        elif kind == "SourceErratum":
            disposition, reason = "GAP", "MANUAL_CONFLICT"
        else:
            disposition, reason = "GAP", "NO_COMPLETE_DIRECT_ORACLE"
        rows.append({"id": identity, "kind": kind, "name": name, "pages": item["Pages"],
                     "status": disposition, "reason": reason, "checks": [c["id"] for c in cases]})
    unknown = set(bindings) - {r["id"] for r in rows}
    if unknown:
        raise ValueError(f"conformance bindings absent from source inventory: {sorted(unknown)}")
    return {"schema_version": "spell.v16.language-coverage/1", "source_sha256": SOURCE_SHA256,
            "inventory_sha256": digest(canonical_bytes(source_inventory())), "full_compatibility": False,
            "artifact_count": len(rows), "rows": rows,
            "reasons": {
                "EXAMPLE_ADAPTATION": "Existing simulator semantic oracle; not direct language conformance.",
                "BOUNDED_DIRECT_SOURCE": "Direct source checks cover a bounded subset; the whole artifact is not claimed.",
                "RESTRICTED_SERVICE_SIGNATURE": "Restricted local service exists; documented signatures, modifiers and returns are not fully qualified.",
                "MANUAL_CONFLICT": "Source erratum requires an explicit compatibility decision and complete tests.",
                "NO_COMPLETE_DIRECT_ORACLE": "Missing direct conformance proof. Expected rejection checks remain language gaps."},
            "defaults": {"source_pages": "114-115", "spacecraft_configuration_dependent": True,
                "typical_values": {"AdjLimits": True, "Automatic": True, "Block": False,
                    "Blocking": True, "Confirm": False, "HandleError": False, "IgnoreCase": False,
                    "Notify": False, "OnFailure": "ABORT|SKIP|REPEAT|CANCEL", "PromptUser": True,
                    "OnTrue": "NOACTION", "OnFalse": "NOACTION", "Verify.OnFalse": "ABORT|SKIP|REPEAT|CANCEL",
                    "Retries": 2, "Severity": "INFORMATION", "GetTM.Timeout": 30,
                    "Tolerance": 0.0, "Prompt.Type": "OK", "ValueFormat": "ENG", "Visible": True, "Wait": False},
                "direct_default_checks": ["display-default"],
                "unqualified_defaults_remain_gaps": True,
                "conflicts": ["HandleError pp30/114", "Notify pp110/114", "Verify.OnFalse pp41/114"]},
            "remaining_work": ["Complete scalar/collection/method and function-return syntax.",
                "Qualify documented service signatures, modifiers, defaults, failures and recovery combinations.",
                "Resolve source conflicts and qualify each external driver separately."]}


def _expected_result(case: dict[str, Any]) -> dict[str, Any]:
    return {"id": case["id"], "source_sha256": case["source_sha256"],
            "mode": "EXPECTED_REJECTION" if case["expected_diagnostic"] else "DIRECT_SOURCE",
            "diagnostic": case["expected_diagnostic"],
            "terminal": None if case["expected_diagnostic"] else case["expected_terminal"],
            "variables": case["expected_variables"], "logs": case["expected_logs"], "passed": True}


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """Compile fixed source, then execute its exact data-only IR in a real worker."""
    from .procedure_parser import ProcedureCatalog, ProcedureValidationError
    from .worker import worker_main
    try:
        procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"], case["id"] + ".spell.py")
    except ProcedureValidationError as exc:
        actual = exc.diagnostics[0].code
        if actual != case["expected_diagnostic"]:
            raise ValueError(f"{case['id']}: unexpected diagnostic {actual}") from exc
        return _expected_result(case)
    if case["expected_diagnostic"] is not None:
        raise ValueError(f"{case['id']}: unsupported source was unexpectedly accepted")
    context = multiprocessing.get_context("spawn")
    control, output = context.Queue(), context.Queue()
    process = context.Process(target=worker_main, args=(case["id"], 1, procedure.ir_version,
        list(procedure.steps), 0, "conformance", None, {}, control, output, None, None, False))
    process.start()
    terminal, variables, logs = None, {}, []
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            try:
                item = output.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                if not process.is_alive():
                    break
                continue
            if item.get("kind") == "step_commit":
                variables = item["variables"]
                logs.extend([e["payload"]["message"], e["severity"]]
                    for e in item.get("effects", []) if e.get("event_type") == "procedure.log")
            if item.get("kind") == "terminal":
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
    expected = case["expected_variables"]
    if terminal != case["expected_terminal"] or logs != case["expected_logs"] or any(
        type(variables.get(k)) is not type(v) or variables.get(k) != v for k, v in expected.items()
    ):
        raise ValueError(f"{case['id']}: source execution did not satisfy its terminal/variable/log oracle")
    result = _expected_result(case)
    result["terminal"] = terminal
    result["variables"] = {k: variables[k] for k in expected}
    result["logs"] = logs
    return result


def evaluate_fixed_case(case: dict[str, Any]) -> dict[str, Any]:
    """Execute fixed pure source inside the isolated worker using its evaluator.

    There are no nested worker processes, supervisor operations or caller-supplied
    source. The qualification producer independently executes the same cases in
    separate real workers and compares the complete results.
    """
    from .procedure_parser import ProcedureCatalog, ProcedureValidationError
    from .worker import ExpressionEvaluationError, evaluate_expression
    if case not in CASES or len(case["source"].encode("utf-8")) > 10_000:
        raise ValueError("case is outside the closed source registry")
    try:
        procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"], case["id"] + ".spell.py")
    except ProcedureValidationError as exc:
        if exc.diagnostics[0].code != case["expected_diagnostic"]:
            raise ValueError("closed source diagnostic differs") from exc
        return _expected_result(case)
    if case["expected_diagnostic"] is not None or len(procedure.steps) > 128:
        raise ValueError("closed source acceptance or instruction bound differs")
    values, logs, terminal = {}, [], "completed"
    try:
        for step in procedure.steps:
            if step["type"] not in {"variable_set", "log", "display"}:
                raise ValueError("closed source contains an effectful instruction")
            if "guard" in step and not evaluate_expression(step["guard"], values):
                continue
            if step["type"] == "variable_set":
                value = evaluate_expression(step["expression"], values)
                values[step["name"]] = float(value) if step["declared_type"] == "float" else value
            else:
                message = evaluate_expression(step["message"], values)
                if type(message) is not str or (step["type"] == "log" and not message):
                    raise ExpressionEvaluationError("Log message must be nonempty text")
                logs.append([message, step["level"]])
    except ExpressionEvaluationError:
        terminal = "failed"
    if terminal != case["expected_terminal"] or logs != case["expected_logs"] or any(
        type(values.get(k)) is not type(v) or values.get(k) != v for k, v in case["expected_variables"].items()
    ):
        raise ValueError("closed source execution oracle failed")
    result = _expected_result(case)
    result.update(terminal=terminal, variables={k: values[k] for k in case["expected_variables"]}, logs=logs)
    return result


def execute_selection(selection: int) -> tuple[str, list[dict[str, Any]]]:
    """One bounded checkpoint: old example, direct/rejection case, or complete suite."""
    from .reference_examples_v10 import execute_reference_example
    if type(selection) is not int or not 0 <= selection <= 195 + len(CASES):
        raise ValueError("language selection is outside the closed registry")
    if selection < 195:
        result = execute_reference_example(selection + 1)
        if not result.passed:
            raise ValueError("reference adaptation oracle failed")
        return result.summary, [{"event_type": "procedure.reference_example_completed", "source": "simulator",
                                "severity": "info", "payload": result.as_event_payload()}]
    selected = CASES if selection == 195 + len(CASES) else (CASES[selection - 195],)
    cases = [evaluate_fixed_case(case) for case in selected]
    examples = []
    if selection == 195 + len(CASES):
        for number in range(1, 196):
            result = execute_reference_example(number)
            if not result.passed or any(proof.status != "PASS" for proof in result.variant_proofs):
                raise ValueError("reference adaptation oracle failed")
            examples.append({"example_number": number, "status": result.status,
                             "variant_count": len(result.variant_proofs), "evidence_digest": result.evidence_digest})
    summary = f"Language checks: {len(cases)} PASS; {len(examples)} adaptations; full support: false"
    payload = {"schema_version": "spell.v16.language-check-result/1", "selection": selection,
               "full_compatibility": False, "cases": cases, "adaptations": examples,
               "unqualified_artifacts_remain": True, "summary": summary}
    if len(canonical_bytes(payload)) > 64_000:
        raise ValueError("language check report exceeds its bound")
    return summary, [{"event_type": "procedure.language_check_completed", "source": "simulator",
                      "severity": "info", "payload": payload}]


def qualify(case_id: str | None = None) -> dict[str, Any]:
    contract = coverage_contract()
    if not COVERAGE_PATH.is_file() or json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) != contract:
        raise ValueError("v0.16 language coverage contract is stale")
    selected = [case for case in CASES if case_id is None or case["id"] == case_id]
    if not selected:
        raise ValueError("unknown conformance case")
    results = [run_case(case) for case in selected]
    return {"schema_version": REPORT_SCHEMA, "release": "v0.16.0", "source_sha256": SOURCE_SHA256,
            "coverage_sha256": digest(canonical_bytes(contract)), "selection": case_id or "ALL",
            "profile_result": "PASS", "full_compatibility": False, "artifact_count": 763,
            "coverage_counts": dict(sorted(Counter(r["status"] for r in contract["rows"]).items())),
            "cases": results, "case_count": len(results),
            "direct_count": sum(r["mode"] == "DIRECT_SOURCE" for r in results),
            "rejection_count": sum(r["mode"] == "EXPECTED_REJECTION" for r in results),
            "unqualified_default_count": 20,
            "scope": "Local simulator; successful boundary tests do not close compatibility gaps."}


def validate_report(report: dict[str, Any]) -> None:
    """Independently recompute all identities, outcomes and coverage counts.

    Release evidence must additionally bind this producer output to its frozen
    source and command digest. No report format can attest that it was executed
    solely by looking at a self-supplied JSON result.
    """
    contract = coverage_contract()
    if COVERAGE_PATH.stat().st_size > 1_000_000 or json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) != contract:
        raise ValueError("language coverage contract does not match current source")
    if len(canonical_bytes(report)) > 1_000_000:
        raise ValueError("language evidence exceeds its byte limit")
    expected = {"schema_version": REPORT_SCHEMA, "release": "v0.16.0", "source_sha256": SOURCE_SHA256,
        "coverage_sha256": digest(canonical_bytes(contract)), "selection": "ALL", "profile_result": "PASS",
        "full_compatibility": False, "artifact_count": 763,
        "coverage_counts": dict(sorted(Counter(r["status"] for r in contract["rows"]).items())),
        "cases": [_expected_result(case) for case in CASES], "case_count": len(CASES),
        "direct_count": sum(c["expected_diagnostic"] is None for c in CASES),
        "rejection_count": sum(c["expected_diagnostic"] is not None for c in CASES),
        "unqualified_default_count": 20,
        "scope": "Local simulator; successful boundary tests do not close compatibility gaps."}
    if canonical_bytes(report) != canonical_bytes(expected):
        raise ValueError("language evidence has stale, missing or unproved results")
