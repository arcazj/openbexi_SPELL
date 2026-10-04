"""Supervisor-owned closed language dispatch and authoritative checkpoints."""
from __future__ import annotations

import threading
from sqlalchemy import select

from .dss_language_broker import (canonical, digest, request_for_selection, validate_request,
    selected_subjects, subject_binding, result_for_request, validate_subject_result, compact_subject_result, worker_effects,
    validation_operation)
from .dss_language_ledger import LanguageLedger
from .migrations.versions.v0011_dss_language_ledger import language_cases
from .worker import evaluate_expression


def _authoritative_request(execution, incoming=None):
    index = execution.current_step
    if (execution.ir_version != "0.19" or type(index) is not int
            or not 0 <= index < len(execution.steps)):
        raise ValueError("DSS language request has no current closed instruction")
    step = execution.steps[index]
    if step["type"] != "language_check":
        raise ValueError("DSS language request substitutes another instruction")
    if step.get("guard") is not None and evaluate_expression(step["guard"], execution.variables) is not True:
        raise ValueError("DSS language request bypasses its authoritative guard")
    expected = request_for_selection(execution.id, index, evaluate_expression(step["selection"], execution.variables))
    if incoming is not None:
        validate_request(incoming, execution_id=execution.id, step_index=index, selection=expected["selection"])
    return expected


def _active(supervisor, execution_id, handle, request):
    with supervisor._lock, supervisor.session_factory() as session:
        if (supervisor._closed or handle.intentional_stop
                or supervisor._workers.get(execution_id) is not handle):
            raise ValueError("DSS language worker is no longer current")
        execution = supervisor._require_worker_epoch(session, execution_id, handle.generation)
        if execution is None or execution.state not in {"running", "waiting"}:
            raise ValueError("DSS language dispatch is not authorized in the current execution state")
        _authoritative_request(execution, request)
        return execution.context_id


def handle_request(supervisor, execution_id, handle, message):
    if getattr(supervisor, "dss_runtime", None) is None:
        raise ValueError("actual DSS runtime is unavailable")
    incoming = {key:value for key,value in message.items() if key not in {"kind", "generation"}}
    _active(supervisor, execution_id, handle, incoming)
    key = (execution_id, incoming["request_id"], handle.generation)
    with supervisor._lock:
        active = getattr(supervisor, "_dss_language_requests", None)
        if active is None:
            active = supervisor._dss_language_requests = set()
        if key in active:
            return
        active.add(key)
    threading.Thread(target=_resolve, args=(supervisor, execution_id, handle, incoming),
                     name="dss-language-" + execution_id[:8], daemon=True).start()


def _resolve(supervisor, execution_id, handle, request):
    key = (execution_id, request["request_id"], handle.generation)
    subject = None
    executor = None
    try:
        from .dss_language_executor import DssLanguageExecutor
        context_id = _active(supervisor, execution_id, handle, request)
        executor = DssLanguageExecutor(supervisor, request, context_id,
            authorize=lambda: _active(supervisor, execution_id, handle, request))
        ledger = LanguageLedger(supervisor.session_factory)
        results = []
        for subject in selected_subjects(request):
            _active(supervisor, execution_id, handle, request)
            result = ledger.reserve(request, subject)
            if result is None:
                result = executor.execute(subject)
                ledger.settle(request, subject, result)
            results.append(compact_subject_result(result))
        result = result_for_request(request, results)
        _active(supervisor, execution_id, handle, request)
        supervisor.append_event(execution_id, "procedure.dss_language_completed",
            {"request_id":request["request_id"], "result_sha256":result["result_sha256"],
             "subjects":[row["subject"] for row in results]}, source="supervisor",
            worker_generation=handle.generation)
        handle.control.put({"type":"language_case_result", "request_id":request["request_id"],
            "outcome":"SETTLED", "result":result})
    except Exception as exc:
        error = f"{subject or 'selection'}: {type(exc).__name__}: {exc}".replace("\n", " ")[:1000]
        try:
            from .dss_language_diagnostics import failure
            diagnostic = failure(executor) if executor is not None else None
        except Exception as diagnostic_error:
            # Diagnostics cannot replace the original failure or settle an intent.
            diagnostic = {"schema_version":"openbexi.dss.language-failure/1",
                "unavailable_reason":type(diagnostic_error).__name__[:80]}
        try:
            supervisor.append_event(execution_id, "procedure.dss_language_failed",
                {"request_id":request.get("request_id"), "subject":subject, "error":error, "diagnostic":diagnostic},
                source="supervisor", severity="error", worker_generation=handle.generation)
        finally:
            handle.control.put({"type":"language_case_result", "request_id":request.get("request_id"),
                "outcome":"FAILED", "error":error})
    finally:
        with supervisor._lock:
            supervisor._dss_language_requests.discard(key)


@validation_operation()
def validate_checkpoint(supervisor, session, execution, message, variables):
    """A worker cannot manufacture a passed case or a target variable update."""
    if getattr(supervisor, "dss_runtime", None) is None or execution.ir_version != "0.19":
        return
    step = execution.steps[message["step_index"]]
    if step["type"] != "language_check":
        return
    skipped = step.get("guard") is not None and evaluate_expression(step["guard"], variables) is not True
    complete = {"event_type":"step.completed", "source":"worker", "severity":"info",
        "payload":{"step_index":step["index"], "line":step["line"], "step_type":step["type"], "skipped":skipped}}
    expected_variables = dict(variables)
    if skipped:
        expected_effects = [complete]
    else:
        request = _authoritative_request(execution)
        subjects = selected_subjects(request)
        actual_subjects = session.scalars(select(language_cases.c.subject).where(
            language_cases.c.request_id == request["request_id"]).limit(len(subjects)+1)).all()
        if len(actual_subjects) != len(subjects) or set(actual_subjects) != set(subjects):
            raise ValueError("DSS checkpoint durable subject set differs from its closed selection")
        rows = []
        # Raw packet/worker captures are large. Keep at most four results live,
        # retaining the original transaction, every hash, and source order.
        for start in range(0,len(subjects),4):
            chunk = subjects[start:start+4]
            records = session.execute(select(language_cases).where(
                language_cases.c.request_id == request["request_id"], language_cases.c.subject.in_(chunk))).mappings().all()
            if len(records) != len(chunk) or {row["subject"] for row in records} != set(chunk):
                raise ValueError("DSS checkpoint durable result chunk is incomplete")
            by_subject = {row["subject"]:row for row in records}
            for subject in chunk:
                row = by_subject[subject]
                if (row["state"] != "SETTLED" or row["execution_id"] != execution.id
                        or canonical(row["request"]) != canonical(request) or row["request_hash"] != digest(request)
                        or row["binding_hash"] != digest(subject_binding(subject))
                        or row["result_hash"] != digest(row["result"])):
                    raise ValueError("DSS checkpoint lacks a source-bound durable case settlement")
                rows.append(compact_subject_result(validate_subject_result(subject, row["result"])))
            # Drop references before the next database fetch, including `row`.
            del records, by_subject, row
        result = result_for_request(request, rows)
        summary, effects = worker_effects(request, result)
        expected_variables[step["target"]] = summary
        expected_effects = [*effects, complete]
    if (canonical(message["variables"]) != canonical(expected_variables)
            or canonical(message.get("effects")) != canonical(expected_effects)):
        raise ValueError("DSS language checkpoint differs from authoritative cases or prior variables")
