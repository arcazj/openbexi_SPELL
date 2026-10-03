"""V19-RUNTIME-001 / V19-RECOVERY-001 through committed services and workers."""
from __future__ import annotations

from dataclasses import replace
import time

import pytest
from sqlalchemy import select

from backend.models import Event
from backend.observation_domain import GetTMMode, Quality, Validity
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution
from backend.tests.test_ir_v07 import _condition
from backend.tests.test_observation_api import seed_observation
from backend.tests.test_observation_repository import BASE_NS, CATALOG_DIGEST, sample
from backend.tests.test_prompt_telecommand_api_v18 import _finish_answer, _counts
from backend.tests.test_v11_operator_integration import _install_dispatch_spy, _wait_for_open_prompt, _acquire_control


READ = "reading: float = 0.0\nGetTM('TM.POWER.BUS_VOLTAGE', target=reading, scalar_type='float')\n"


def condition(value=27.0):
    plan = _condition()
    plan["root"]["left"].update(item_id="TM.POWER.BUS_VOLTAGE", catalog_digest=CATALOG_DIGEST)
    plan["root"]["right"]["value"]["value"] = value
    return plan


@pytest.fixture
def procedures_dir(procedures_dir):
    sources = {
        "read": READ + "answer = Prompt('Use the committed reading?', YES_NO)\nWaitFor(seconds=0)\nif reading >= 27.0 and answer == 'YES':\n    Send(command='CMDNAME')\nDisplay(answer)\n",
        "reread": READ + "answer = Prompt('Read again?', YES_NO)\nGetTM('TM.POWER.BUS_VOLTAGE', target=reading, scalar_type='float')\nif reading >= 27.0:\n    Send(command='CMDNAME')\n",
        "missing": "reading: bool = True\nGetTM('TM.POWER.SAFE_MODE', target=reading, scalar_type='bool')\nSend(command='CMDNAME')\n",
        "verify": f"verdict: str = 'TRUE'\nVerify(condition={condition()!r}, target=verdict)\nif verdict == 'TRUE':\n    Send(command='CMDNAME')\n",
        "wait_timeout": f"WaitFor(condition={condition(99.0)!r}, timeout=0.1)\nSend(command='CMDNAME')\n",
        "next_timeout": "reading: float = 28.0\nGetTM('TM.POWER.BUS_VOLTAGE', target=reading, scalar_type='float', mode='NEXT', timeout_seconds=0.1)\nSend(command='CMDNAME')\n",
        "next": "reading: float = 0.0\nGetTM('TM.POWER.BUS_VOLTAGE', target=reading, scalar_type='float', mode='NEXT', timeout_seconds=60)\nif reading >= 29.0:\n    Send(command='CMDNAME')\n",
    }
    for name, source in sources.items():
        (procedures_dir / f"v19_{name}.spell.py").write_text(source, encoding="utf-8")
    return procedures_dir


def seeded(client):
    repository = client.app.state.observation_repository
    repository._clock_ns = lambda: BASE_NS + 200_000_000
    generations, _ = seed_observation(client)
    return repository, generations


def events(client, execution_id, kind):
    with client.app.state.session_factory() as session:
        return session.scalars(select(Event).where(Event.execution_id == execution_id, Event.event_type == kind).order_by(Event.sequence)).all()


def wait_request(client, execution_id):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        requested = events(client, execution_id, "procedure.observation_requested")
        if requested: return requested[0].payload
        time.sleep(0.02)
    raise AssertionError("worker did not publish its observation request")


def control(client, execution_id, snapshot, headers, lease, command):
    response = client.post(f"/api/v1/executions/{execution_id}/commands", headers=headers, json={
        "type": command, "expected_execution_revision": snapshot["execution"]["revision"],
        "reason": "v19 observation boundary", "idempotency_key": "v19-" + command,
        "lease_id": lease["id"], "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "session_id": headers["X-Spell-Session-Id"],
        "client_instance_key_id": headers["X-Spell-Client-Instance-Key-Id"],
    })
    assert response.status_code == 202, response.text
    return response.json()["command"]


@pytest.mark.parametrize("change_after_read", [False, True])
def test_committed_read_is_a_snapshot_across_native_prompt_and_wait(client, operator_headers, viewer_headers, monkeypatch, change_after_read):
    repository, generations = seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_read")
    snapshot, _ = _wait_for_open_prompt(client, execution_id, viewer_headers)
    assert snapshot["execution"]["variables"]["reading"] == 28.0
    if change_after_read:
        repository.ingest_sample(sample(generations, sequence=2, engineering=5.0, observation_number=9191), mode=GetTMMode.CURRENT, resynchronized=True)
        assert repository.mark_stale(now_unix_ns=BASE_NS + 10**15) > 0
    _finish_answer(client, execution_id, snapshot, operator_headers)
    finished = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert finished["execution"]["variables"]["reading"] == 28.0
    assert len(calls) == 1 and set(_counts(client, execution_id).values()) == {1}
    results = events(client, execution_id, "procedure.observation_result")
    assert [(row.payload["operation"], row.payload["outcome"]) for row in results] == [("GET_TM", "OK"), ("WAIT_FOR", "SATISFIED")]


@pytest.mark.parametrize("failure", ["stale", "bad_quality", "invalid", "missing"])
def test_committed_unacceptable_read_never_reaches_command(client, operator_headers, viewer_headers, monkeypatch, failure):
    repository, generations = seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    if failure == "stale": repository.mark_stale(now_unix_ns=BASE_NS + 10**15)
    elif failure in {"bad_quality", "invalid"}:
        value = sample(generations, sequence=2, engineering=28.0, observation_number=9192)
        value = replace(value, quality=Quality.BAD) if failure == "bad_quality" else replace(value, validity=Validity.INVALID)
        repository.ingest_sample(value, mode=GetTMMode.CURRENT, resynchronized=True)
    execution_id = create_execution(client, operator_headers, "v19_missing" if failure == "missing" else "v19_read")
    wait_for_state(client, execution_id, viewer_headers, {"failed"}, timeout=15)
    result = events(client, execution_id, "procedure.observation_result")[0].payload
    assert result["outcome"] == "NOT_AVAILABLE" and "value" not in result
    assert calls == [] and set(_counts(client, execution_id).values()) == {0}


def test_second_stale_read_cannot_reuse_prior_success_after_prompt(client, operator_headers, viewer_headers, monkeypatch):
    repository, _ = seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_reread")
    snapshot, _ = _wait_for_open_prompt(client, execution_id, viewer_headers)
    repository.mark_stale(now_unix_ns=BASE_NS + 10**15)
    _finish_answer(client, execution_id, snapshot, operator_headers)
    finished = wait_for_state(client, execution_id, viewer_headers, {"failed"}, timeout=15)
    assert finished["execution"]["variables"]["reading"] == 28.0
    assert [row.payload["outcome"] for row in events(client, execution_id, "procedure.observation_result")] == ["OK", "NOT_AVAILABLE"]
    assert calls == [] and set(_counts(client, execution_id).values()) == {0}


@pytest.mark.parametrize("case,expected", [("fresh", "TRUE"), ("false", "FALSE"), ("stale", "INDETERMINATE")])
def test_verify_condition_service_overwrites_prior_true_before_command_branch(client, operator_headers, viewer_headers, monkeypatch, case, expected):
    repository, generations = seeded(client)
    if case == "false": repository.ingest_sample(sample(generations, sequence=2, engineering=5.0, observation_number=9193), mode=GetTMMode.CURRENT, resynchronized=True)
    if case == "stale": repository.mark_stale(now_unix_ns=BASE_NS + 10**15)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_verify")
    finished = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert finished["execution"]["variables"]["verdict"] == expected
    assert len(calls) == int(expected == "TRUE")
    result = events(client, execution_id, "procedure.observation_result")[0].payload
    assert result["outcome"] == expected and result["evidence"]["verify_id"]


@pytest.mark.parametrize("procedure,outcome", [("wait_timeout", "TIMED_OUT"), ("next_timeout", "DEADLINE_EXCEEDED")])
def test_real_wait_and_next_deadlines_stop_before_command(client, operator_headers, viewer_headers, monkeypatch, procedure, outcome):
    seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_" + procedure)
    wait_for_state(client, execution_id, viewer_headers, {"failed"}, timeout=15)
    assert events(client, execution_id, "procedure.observation_result")[0].payload["outcome"] == outcome
    assert calls == [] and set(_counts(client, execution_id).values()) == {0}


def test_next_crash_recovery_keeps_original_anchor_and_deadline_then_sends_once(client, operator_headers, viewer_headers, monkeypatch):
    repository, generations = seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_next")
    original = wait_request(client, execution_id)
    supervisor = client.app.state.supervisor
    wait_for_state(client, execution_id, viewer_headers, {"waiting"})
    # The product's injected-crash command is intentionally unavailable while
    # waiting. Terminate the real test worker to exercise unexpected process loss.
    worker = supervisor._workers[execution_id].process
    worker.terminate()
    worker.join(timeout=5)
    assert not worker.is_alive()
    stopped = wait_for_state(client, execution_id, viewer_headers, {"recovery_required"})
    supervisor.command_ack_timeout_seconds = 30
    supervisor.issue_command(execution_id, command_type="recover", expected_revision=stopped["execution"]["revision"],
        actor="pytest-operator", role="operator", reason="resume anchored read", idempotency_key="v19-recover", payload={}, correlation_id=None)
    wait_for_state(client, execution_id, viewer_headers, {"waiting"}, timeout=35)
    assert events(client, execution_id, "procedure.observation_requested")[0].payload == original
    repository.ingest_sample(sample(generations, sequence=2, engineering=29.0, observation_number=9194), mode=GetTMMode.CURRENT, resynchronized=True)
    finished = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert finished["execution"]["variables"]["reading"] == 29.0
    assert len(events(client, execution_id, "procedure.observation_requested")) == 1
    assert len(events(client, execution_id, "procedure.observation_result")) == 1
    assert len(calls) == 1 and set(_counts(client, execution_id).values()) == {1}


def test_abort_during_next_wait_never_assigns_or_dispatches_later_command(client, operator_headers, viewer_headers, monkeypatch):
    repository, generations = seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_next")
    wait_request(client, execution_id)
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"waiting"})
    headers, lease = _acquire_control(client, operator_headers, execution_id, snapshot, "v19-abort")
    control(client, execution_id, snapshot, headers, lease, "ABORT")
    stopped = wait_for_state(client, execution_id, viewer_headers, {"aborted"}, timeout=15)
    repository.ingest_sample(sample(generations, sequence=2, engineering=29.0, observation_number=9195), mode=GetTMMode.CURRENT, resynchronized=True)
    assert stopped["execution"]["variables"]["reading"] == 0.0
    assert stopped["execution"]["current_step"] == 1
    assert calls == [] and set(_counts(client, execution_id).values()) == {0}


def test_paused_next_result_remains_a_snapshot_until_explicit_resume(client, operator_headers, viewer_headers, monkeypatch):
    repository, generations = seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    execution_id = create_execution(client, operator_headers, "v19_next")
    original = wait_request(client, execution_id)
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"waiting"})
    headers, lease = _acquire_control(client, operator_headers, execution_id, snapshot, "v19-pause")
    control(client, execution_id, snapshot, headers, lease, "PAUSE")
    paused = wait_for_state(client, execution_id, viewer_headers, {"paused"}, timeout=15)
    repository.ingest_sample(sample(generations, sequence=2, engineering=29.0, observation_number=9196), mode=GetTMMode.CURRENT, resynchronized=True)
    deadline = time.monotonic() + 5
    while not events(client, execution_id, "procedure.observation_result") and time.monotonic() < deadline: time.sleep(0.02)
    assert len(events(client, execution_id, "procedure.observation_result")) == 1
    paused = wait_for_state(client, execution_id, viewer_headers, {"paused"})
    assert paused["execution"]["variables"]["reading"] == 0.0 and calls == []
    control(client, execution_id, paused, headers, lease, "RUN")
    finished = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=15)
    assert finished["execution"]["variables"]["reading"] == 29.0
    assert len(calls) == 1 and events(client, execution_id, "procedure.observation_requested")[0].payload == original
