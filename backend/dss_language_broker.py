"""Closed parent-owned DSS language requests; never accepts source or credentials."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

PROFILE = "0.19"
REQUEST_SCHEMA = "spell.dss.language-request/1"
RESULT_SCHEMA = "spell.dss.language-result/1"
MAX_RESULT_BYTES = 4_000_000
_VALIDATION_SCOPE = ContextVar("dss_language_validation_scope", default=None)


@contextmanager
def validation_operation():
    """One freshly verified reference registry per bounded validation operation.

Nested validators reuse that registry; success and failure both discard it.
No registry survives into another operation or masks a later contract change.
"""
    if _VALIDATION_SCOPE.get() is not None:
        yield
        return
    token = _VALIDATION_SCOPE.set({})
    try:
        yield
    finally:
        _VALIDATION_SCOPE.reset(token)


def _reference_registry():
    from .reference_examples_v10 import ReferenceExampleRegistry
    scope = _VALIDATION_SCOPE.get()
    if scope is None:
        return ReferenceExampleRegistry.from_contract()
    if "registry" not in scope:
        scope["registry"] = ReferenceExampleRegistry.from_contract()
    return scope["registry"]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _registry():
    from . import language_conformance_v19
    return language_conformance_v19


def request_for_selection(execution_id: str, step_index: int, selection: int) -> dict:
    registry = _registry()
    if (type(execution_id) is not str or not 0 < len(execution_id) <= 200
            or type(step_index) is not int or not 0 <= step_index < 10000
            or type(selection) is not int or not 0 <= selection <= registry.ALL_SELECTION):
        raise ValueError("DSS language request identity or selection is invalid")
    material = {"schema_version":REQUEST_SCHEMA, "execution_id":execution_id,
        "step_index":step_index, "profile":PROFILE, "selection":selection,
        "cases_sha256":registry.CASESET_SHA256}
    return {**material, "request_id":str(uuid.uuid5(uuid.NAMESPACE_URL,
        "openbexi:dss-language:" + digest(material)))}


def validate_request(raw: Any, *, execution_id: str, step_index: int, selection: int) -> dict:
    expected = request_for_selection(execution_id, step_index, selection)
    if type(raw) is not dict or canonical(raw) != canonical(expected):
        raise ValueError("DSS language request differs from the authoritative closed selection")
    return expected


def selected_subjects(request: dict) -> tuple[str, ...]:
    verified = validate_request(request, execution_id=request.get("execution_id"),
        step_index=request.get("step_index"), selection=request.get("selection"))
    registry = _registry()
    selection = verified["selection"]
    examples = tuple(f"adaptation:{number:03}" for number in range(1, 196))
    cases = tuple("case:" + case["id"] for case in registry.CASES)
    if selection == registry.ALL_SELECTION:
        return cases + examples
    return (examples[selection],) if selection < 195 else (cases[selection - 195],)


@validation_operation()
def subject_binding(subject: str) -> dict:
    registry = _registry()
    if subject.startswith("case:"):
        matches = [case for case in registry.CASES if subject == "case:" + case["id"]]
        if len(matches) != 1:
            raise ValueError("unknown closed DSS source case")
        case = matches[0]
        return {"subject":subject, "source_sha256":case["source_sha256"],
            "oracle_sha256":digest(registry._expected_result(case))}
    if subject.startswith("adaptation:") and subject[11:].isdigit():
        number = int(subject[11:])
        if subject != f"adaptation:{number:03}" or not 1 <= number <= 195:
            raise ValueError("unknown closed DSS reference adaptation")
        contracts = _reference_registry()
        contract = contracts.contract(number)
        return {"subject":subject, "source_sha256":contract.body_span_sha256,
            "oracle_sha256":digest({"example_number":number,
                "variants":[row.variant_id for row in contracts.variant_contract(number).variants]})}
    raise ValueError("unknown closed DSS language subject")


def case_execution_id(request: dict, subject: str) -> str:
    if subject not in selected_subjects(request):
        raise ValueError("DSS language subject is outside the requested selection")
    return str(uuid.uuid5(uuid.UUID(request["request_id"]), subject))


@validation_operation()
def validate_subject_result(subject: str, result: Any) -> dict:
    binding = subject_binding(subject)
    if type(result) is not dict or set(result) != {"subject", "binding", "semantic", "dss_evidence"}:
        raise ValueError("DSS subject result fields differ")
    if result["subject"] != subject or canonical(result["binding"]) != canonical(binding):
        raise ValueError("DSS subject result source binding differs")
    if subject.startswith("case:"):
        registry = _registry()
        case = next(case for case in registry.CASES if subject == "case:" + case["id"])
        if canonical(result["semantic"]) != canonical(registry._expected_result(case)):
            raise ValueError(subject + ": actual DSS source outcome differs from its oracle")
    else:
        number = int(subject[11:])
        semantic = result["semantic"]
        contract = _reference_registry().variant_contract(number)
        if (type(semantic) is not dict or semantic.get("example_number") != number
                or semantic.get("status") != "PASS" or not semantic.get("assertions")
                or any(row.get("passed") is not True for row in semantic["assertions"])
                or [row.get("variant_id") for row in semantic.get("variant_proofs", [])]
                    != [row.variant_id for row in contract.variants]
                or any(row.get("status") != "PASS" or not row.get("assertion_ids")
                    or not row.get("trace_sequences") for row in semantic["variant_proofs"])):
            raise ValueError(subject + ": actual DSS adaptation or variant proof is incomplete")
    evidence = result["dss_evidence"]
    if (type(evidence) is not dict or evidence.get("mode") != "ACTUAL_DSS_DRIVER"
            or type(evidence.get("scenario_id")) is not str or not evidence["scenario_id"]
            or type(evidence.get("epoch")) is not str or not evidence["epoch"]
            or type(evidence.get("capture_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", evidence["capture_sha256"]) is None):
        raise ValueError("DSS subject has no actual driver execution binding")
    if set(evidence) not in ({"mode", "scenario_id", "epoch", "capture_sha256"},
            {"mode", "scenario_id", "epoch", "capture_sha256", "capture"}):
        raise ValueError("DSS subject evidence fields differ")
    if "capture" in evidence and digest(evidence["capture"]) != evidence["capture_sha256"]:
        raise ValueError("DSS subject raw capture digest differs")
    return result


@validation_operation()
def compact_subject_result(result: dict) -> dict:
    """Worker IPC carries semantic proof and capture identity, never raw packet archives."""
    checked = validate_subject_result(result["subject"], result)
    return {**checked, "dss_evidence":{key:value for key,value in checked["dss_evidence"].items()
        if key != "capture"}}


@validation_operation()
def result_for_request(request: dict, results: list[dict]) -> dict:
    subjects = selected_subjects(request)
    if type(results) is not list or [row.get("subject") for row in results] != list(subjects):
        raise ValueError("DSS language results omit, reorder or duplicate selected subjects")
    checked = [compact_subject_result(validate_subject_result(subject, row)) for subject, row in zip(subjects, results)]
    material = {"schema_version":RESULT_SCHEMA, "request":request, "results":checked,
        "full_compatibility":False}
    if len(canonical(material)) > MAX_RESULT_BYTES:
        raise ValueError("DSS language report exceeds its bound")
    return {**material, "result_sha256":digest(material)}


@validation_operation()
def validate_result(request: dict, raw: Any) -> dict:
    if type(raw) is not dict or set(raw) != {"schema_version", "request", "results", "full_compatibility", "result_sha256"}:
        raise ValueError("DSS language result envelope differs")
    expected = result_for_request(request, raw["results"])
    if canonical(raw) != canonical(expected):
        raise ValueError("DSS language result request/hash binding differs")
    return expected


@validation_operation()
def worker_effects(request: dict, raw: dict) -> tuple[str, list[dict]]:
    checked = validate_result(request, raw)
    if request["selection"] < 195:
        semantic = checked["results"][0]["semantic"]
        summary = f"Example {semantic['example_number']}: PASS ({len(semantic['assertions'])}/{len(semantic['assertions'])} assertions)"
        return summary, [{"event_type":"procedure.reference_example_completed", "source":"simulator",
            "severity":"info", "payload":{**semantic, "passed":True, "summary":summary,
                "dss_request_id":request["request_id"], "dss_result_sha256":checked["result_sha256"]}}]
    cases = [row["semantic"] for row in checked["results"] if row["subject"].startswith("case:")]
    examples = [{"example_number":row["semantic"]["example_number"], "status":"PASS",
        "variant_count":len(row["semantic"]["variant_proofs"]), "evidence_digest":row["semantic"]["evidence_digest"]}
        for row in checked["results"] if row["subject"].startswith("adaptation:")]
    summary = f"Language checks: {len(cases)} PASS; {len(examples)} adaptations; full support: false"
    payload = {"schema_version":"spell.v19.language-check-result/1", "selection":request["selection"],
        "cases_sha256":request["cases_sha256"], "evidence_kind":"ACTUAL_DSS_DRIVER",
        "full_compatibility":False, "cases":cases, "adaptations":examples,
        "unqualified_artifacts_remain":True, "summary":summary,
        "dss_request_id":request["request_id"], "dss_result_sha256":checked["result_sha256"]}
    return summary, [{"event_type":"procedure.language_check_completed", "source":"simulator",
        "severity":"info", "payload":payload}]
