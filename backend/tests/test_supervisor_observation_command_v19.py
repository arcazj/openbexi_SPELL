"""V19-RUNTIME-001 / V19-RECOVERY-001: durable observation authority."""
from __future__ import annotations

import copy
import queue
import threading

import pytest
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from backend.condition_engine import QualityFreshnessPolicy
from backend.ir_v07 import observation_request_for_step
from backend.models import Event, Execution
from backend.supervisor import ConflictError, WorkerHandle
from backend.tests.test_ir_v07 import _condition
from backend.tests.test_supervisor_v07_runtime import _AnchorProvider
from backend.tests.test_supervisor_v11_runtime import _ordinary_fixture, _ordinary_step_commit


SOURCE = "reading: int = 0\nGetTM('TM.COUNT', target=reading, scalar_type='int')\nif reading > 5:\n    Send(command='CMDNAME')\n"
EVIDENCE = {"validity": "VALID", "quality": "GOOD", "freshness": "FRESH",
            "synchronization_state": "COMPLETE", "freshness_policy_revision": "v07-r1"}


class Runtime:
    policy = QualityFreshnessPolicy("simulator-default", "v07-r1")

    def __init__(self, result=None):
        self.result = result or {"outcome": "OK", "value": 12, "evidence": EVIDENCE}
        self.requests = []

    def resolve(self, request):
        self.requests.append(copy.deepcopy(request))
        return copy.deepcopy(self.result)


def fixture(source=SOURCE, *, current_step=1, variables=None, runtime=None):
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(
        source, current_step=current_step, variables=variables or {"ARGS": {}, "reading": 0})
    assert procedure.ir_version == "0.19"
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        execution.ir_version, execution.state = "0.19", "waiting"
        session.commit()
    supervisor.observation_runtime = runtime or Runtime()
    supervisor.observation_anchor_provider = _AnchorProvider()
    supervisor._observation_requests = set()
    return supervisor, sessions, procedure, execution_id


def request_result(supervisor, procedure, execution_id, *, index=1, handle=None):
    handle = handle or supervisor._workers[execution_id]
    request = observation_request_for_step(execution_id, procedure.steps[index])
    supervisor._handle_observation_request(execution_id, handle, request)
    result = handle.control.get(timeout=3)
    assert result["type"] == "observation_result"
    return request, {key: value for key, value in result.items() if key != "type"}


def commit(procedure, request, result, variables, *, skipped=False):
    message = _ordinary_step_commit(procedure, request["step_index"], variables)
    message["effects"][0]["payload"]["skipped"] = skipped
    if not skipped:
        message["effects"].insert(0, {"event_type": "procedure.observation_settled",
            "source": "worker", "severity": "info", "payload": {
                "request_id": request["request_id"], "operation": request["operation"],
                "outcome": result["outcome"], "step_index": request["step_index"]}})
    return message


@pytest.mark.parametrize("forgery", ["value", "type", "unrelated", "missing_effect", "wrong_effect", "no_result", "bool_effect", "bool_index", "invalid_effect", "result_index"])
def test_observation_checkpoint_binds_exact_result_full_variables_and_effect(forgery):
    supervisor, sessions, procedure, execution_id = fixture()
    request, result = request_result(supervisor, procedure, execution_id)
    message = commit(procedure, request, result, {"ARGS": {}, "reading": 12})
    if forgery == "value": message["variables"]["reading"] = 13
    if forgery == "type": message["variables"]["reading"] = 12.0
    if forgery == "unrelated": message["variables"]["forged"] = True
    if forgery == "missing_effect": message["effects"].pop(0)
    if forgery == "wrong_effect": message["effects"][0]["payload"]["outcome"] = "NOT_AVAILABLE"
    if forgery == "bool_effect": message["effects"][0]["payload"]["step_index"] = True
    if forgery == "bool_index": message["step_index"] = True
    if forgery == "invalid_effect": message["effects"] = None
    if forgery == "no_result":
        with sessions() as session:
            session.delete(session.scalar(select(Event).where(Event.event_type == "procedure.observation_result")))
            session.commit()
    if forgery == "result_index":
        with sessions() as session:
            event = session.scalar(select(Event).where(Event.event_type == "procedure.observation_result"))
            event.payload = {**event.payload, "step_index": True}
            flag_modified(event, "payload")
            session.commit()
    with pytest.raises(ConflictError):
        supervisor._commit_step(execution_id, 7, message)
    with sessions() as session:
        row = session.get(Execution, execution_id)
        assert row.current_step == 1 and row.variables["reading"] == 0


@pytest.mark.parametrize("patch", [{"freshness": "STALE"}, {"quality": "BAD"}, {"validity": "INVALID"},
    {"synchronization_state": "GAPPED"}, {"freshness_policy_revision": "wrong"}, {"quality": None}])
def test_unacceptable_read_cannot_advance_using_a_prior_successful_target(patch):
    runtime = Runtime({"outcome": "OK", "value": 12, "evidence": {**EVIDENCE, **patch}})
    supervisor, sessions, procedure, execution_id = fixture(runtime=runtime, variables={"ARGS": {}, "reading": 99})
    request, result = request_result(supervisor, procedure, execution_id)
    assert result["outcome"] == "NOT_AVAILABLE" and "value" not in result
    with pytest.raises(ConflictError, match="outcome"):
        supervisor._commit_step(execution_id, 7, commit(procedure, request, result, {"ARGS": {}, "reading": 99}))
    with sessions() as session:
        assert session.get(Execution, execution_id).current_step == 1
        assert not session.scalar(select(Event).where(Event.event_type == "procedure.telecommand_requested"))


@pytest.mark.parametrize("outcome", ["FALSE", "INDETERMINATE", "TIMED_OUT", "CANCELLED", "REJECTED"])
def test_verify_failure_replaces_prior_true_and_protected_command_dependency(outcome):
    source = f"verdict: str = 'TRUE'\nVerify(condition={_condition()!r}, target=verdict)\nif verdict == 'TRUE':\n    Send(command='CMDNAME')\n"
    supervisor, sessions, procedure, execution_id = fixture(source, variables={"ARGS": {}, "verdict": "TRUE"}, runtime=Runtime({"outcome": outcome}))
    request, result = request_result(supervisor, procedure, execution_id)
    with pytest.raises(ConflictError):
        supervisor._commit_step(execution_id, 7, commit(procedure, request, result, {"ARGS": {}, "verdict": "TRUE"}))
    assert supervisor._commit_step(execution_id, 7, commit(procedure, request, result, {"ARGS": {}, "verdict": outcome}))
    with sessions() as session:
        assert session.get(Execution, execution_id).variables["verdict"] == outcome


@pytest.mark.parametrize("state", ["ready", "paused", "aborting", "aborted", "failed", "completed", "recovery_required"])
def test_observation_admission_requires_active_state_without_intent(state):
    supervisor, sessions, procedure, execution_id = fixture()
    with sessions() as session:
        session.get(Execution, execution_id).state = state
        session.commit()
    with pytest.raises(ConflictError):
        request_result(supervisor, procedure, execution_id)
    with sessions() as session:
        assert session.scalars(select(Event)).all() == []


def test_guarded_false_observation_cannot_request_or_mutate_skipped_target():
    source = "reading: int = 0\nif False:\n    GetTM('TM.COUNT', target=reading, scalar_type='int')\nSend(command='CMDNAME')\n"
    supervisor, sessions, procedure, execution_id = fixture(source, current_step=2, variables={"ARGS": {}, "reading": 0, "__spell_branch_0": False})
    request = observation_request_for_step(execution_id, procedure.steps[2])
    with pytest.raises(ConflictError):
        supervisor._handle_observation_request(execution_id, supervisor._workers[execution_id], request)
    variables = {"ARGS": {}, "reading": 0, "__spell_branch_0": False}
    forged = commit(procedure, request, {}, {**variables, "reading": 12}, skipped=True)
    with pytest.raises(ConflictError): supervisor._commit_step(execution_id, 7, forged)
    assert supervisor._commit_step(execution_id, 7, commit(procedure, request, {}, variables, skipped=True))


def test_observation_request_cannot_substitute_boolean_for_literal_numeric_parameter():
    source = SOURCE.replace("scalar_type='int')", "scalar_type='int', timeout_seconds=1)")
    supervisor, sessions, procedure, execution_id = fixture(source)
    request = observation_request_for_step(execution_id, procedure.steps[1])
    request["parameters"]["timeout_seconds"] = True
    with pytest.raises(ConflictError, match="types differ"):
        supervisor._handle_observation_request(execution_id, supervisor._workers[execution_id], request)
    with sessions() as session:
        assert session.scalars(select(Event)).all() == []


@pytest.mark.parametrize("observation", ["WaitFor(seconds=0)", "GetTM('TM.COUNT', target=reading, scalar_type='int')"])
def test_prior_pure_checkpoint_cannot_change_observation_only_guard_before_unconditional_send(observation):
    source = f"reading: int = 0\ngate: bool = True\nLog('before observation')\nif gate:\n    {observation}\nSend(command='CMDNAME')\n"
    supervisor, sessions, procedure, execution_id = fixture(source, current_step=2, variables={"ARGS": {}, "reading": 0, "gate": True})
    with pytest.raises(ConflictError, match="dependency checkpoint"):
        supervisor._commit_step(execution_id, 7, _ordinary_step_commit(procedure, 2, {"ARGS": {}, "reading": 0, "gate": False}))
    with sessions() as session:
        row = session.get(Execution, execution_id)
        assert row.current_step == 2 and row.variables["gate"] is True


def test_prior_pure_checkpoint_cannot_forge_effectful_language_selection():
    from backend.runtime_composition_v19 import telecommand_dependency_variables
    source = "selected_index: int = 0\nresult: str = ''\nLog('before selection')\nLanguageCheck(selected_index, profile='0.19', target=result)\n"
    supervisor, sessions, procedure, execution_id = fixture(source, current_step=2,
        variables={"ARGS": {}, "selected_index": 0, "result": ""})
    assert "selected_index" in telecommand_dependency_variables(list(procedure.steps))
    with pytest.raises(ConflictError, match="dependency checkpoint"):
        supervisor._commit_step(execution_id, 7, _ordinary_step_commit(procedure, 2,
            {"ARGS": {}, "selected_index": 1, "result": ""}))
    with sessions() as session:
        assert session.get(Execution, execution_id).variables["selected_index"] == 0


def test_next_result_recovery_reuses_durable_anchor_deadline_and_exact_snapshot():
    source = SOURCE.replace("scalar_type='int')", "scalar_type='int', mode='NEXT', timeout_seconds=3)")
    runtime = Runtime()
    supervisor, sessions, procedure, execution_id = fixture(source, runtime=runtime)
    request, first = request_result(supervisor, procedure, execution_id)
    persisted = runtime.requests[0]
    assert int(persisted["deadline_at_unix_ns"]) - int(persisted["requested_at_unix_ns"]) == 3_000_000_000
    with sessions() as session:
        row = session.get(Execution, execution_id)
        assert row.current_step == 1 and row.variables["reading"] == 0
        row.worker_generation = 8
        session.commit()
    recovered = WorkerHandle(object(), queue.Queue(), queue.Queue(), 8)
    supervisor._workers[execution_id] = recovered
    runtime.result = {"outcome": "OK", "value": 999, "evidence": EVIDENCE}
    _, replayed = request_result(supervisor, procedure, execution_id, handle=recovered)
    assert first == replayed and len(runtime.requests) == 1
    assert len(supervisor.observation_anchor_provider.calls) == 1
    assert not supervisor._commit_step(execution_id, 7, commit(procedure, request, first, {"ARGS": {}, "reading": 12}))
    assert supervisor._commit_step(execution_id, 8, commit(procedure, request, first, {"ARGS": {}, "reading": 12}))


@pytest.mark.parametrize("boundary", ["abort", "generation"])
def test_late_result_is_fenced_before_publication_or_checkpoint(boundary):
    started, release = threading.Event(), threading.Event()
    class Blocking(Runtime):
        def resolve(self, request):
            started.set()
            assert release.wait(timeout=5)
            return super().resolve(request)
    supervisor, sessions, procedure, execution_id = fixture(runtime=Blocking())
    handle = supervisor._workers[execution_id]
    request = observation_request_for_step(execution_id, procedure.steps[1])
    supervisor._handle_observation_request(execution_id, handle, request)
    assert started.wait(timeout=2)
    with sessions() as session:
        row = session.get(Execution, execution_id)
        if boundary == "abort": row.state = "aborting"
        else: row.worker_generation = 8
        session.commit()
    release.set()
    import time
    deadline = time.monotonic() + 3
    while supervisor._observation_requests and time.monotonic() < deadline: time.sleep(0.01)
    assert not supervisor._observation_requests and handle.control.empty()
    with sessions() as session:
        assert not session.scalar(select(Event).where(Event.event_type == "procedure.observation_result"))
        assert session.get(Execution, execution_id).current_step == 1
