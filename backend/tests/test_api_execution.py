from __future__ import annotations

from pathlib import Path
import os
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from backend.app import create_app
from backend.config import Settings
from backend.database import Base, create_database as create_test_database
from backend.models import Command, Event, Execution

from .conftest import wait_for_state


def create_execution(client: TestClient, headers: dict[str, str], procedure_id: str) -> str:
    response = client.post(
        "/api/v1/executions",
        headers=headers,
        json={
            "procedure_id": procedure_id,
            "context_id": "simulator",
            "reason": "pytest",
            "idempotency_key": f"create-{procedure_id}",
        },
    )
    assert response.status_code == 202, response.text
    return response.json()["execution"]["id"]


def test_auth_catalog_and_complete_as_run(
    client: TestClient, viewer_headers: dict[str, str], operator_headers: dict[str, str]
) -> None:
    assert client.get("/api/v1/procedures").status_code == 401
    procedures = client.get("/api/v1/procedures", headers=viewer_headers)
    assert procedures.status_code == 200
    assert {item["id"] for item in procedures.json()["items"]} == {
        "integration",
        "pause",
        "recovery",
    }

    execution_id = create_execution(client, operator_headers, "integration")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    prompt = snapshot["active_prompt"]
    response = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=operator_headers,
        json={
            "value": "yes",
            "expected_revision": snapshot["execution"]["revision"],
            "reason": "pytest acknowledgement",
            "idempotency_key": "prompt-once",
        },
    )
    assert response.status_code == 202, response.text
    same_response = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=operator_headers,
        json={
            "value": "yes",
            "expected_revision": snapshot["execution"]["revision"],
            "reason": "pytest acknowledgement",
            "idempotency_key": "prompt-once",
        },
    )
    assert same_response.status_code == 202
    conflicting_response = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=operator_headers,
        json={
            "value": "yes",
            "expected_revision": snapshot["execution"]["revision"],
            "reason": "changed reason",
            "idempotency_key": "prompt-once",
        },
    )
    assert conflicting_response.status_code == 409
    current = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()
    competing_response = client.post(
        f"/api/v1/prompts/{prompt['id']}/responses",
        headers=operator_headers,
        json={
            "value": "yes",
            "expected_revision": current["execution"]["revision"],
            "reason": "competing response after reservation",
            "idempotency_key": "prompt-competing",
        },
    )
    assert competing_response.status_code == 409
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    assert completed["execution"]["current_step"] == completed["execution"]["total_steps"]
    assert completed["telemetry"][0]["payload"]["quality"] == "simulated"

    events = client.get(
        f"/api/v1/executions/{execution_id}/events", headers=viewer_headers
    ).json()["items"]
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert all(event["schema_version"] == "0.2" for event in events)
    report = client.get(
        f"/api/v1/executions/{execution_id}/report", headers=viewer_headers
    )
    assert report.status_code == 200
    assert report.json()["state"] == "completed"
    assert report.json()["summary"]["completed_steps"] == 5
    assert len(report.json()["integrity"]["digest"]) == 64
    prompt_commands = [
        command for command in completed["commands"] if command["type"] == "prompt_response"
    ]
    assert len(prompt_commands) == 1
    assert prompt_commands[0]["status"] == "completed"


def test_prompt_crash_interrupts_then_recovers_from_checkpoint(
    client: TestClient,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
    admin_headers: dict[str, str],
) -> None:
    execution_id = create_execution(client, operator_headers, "recovery")
    prompting = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    first_prompt_id = prompting["active_prompt"]["id"]
    assert prompting["execution"]["current_step"] == 1
    crash = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=admin_headers,
        json={
            "type": "simulate_crash",
            "expected_revision": prompting["execution"]["revision"],
            "reason": "exercise recovery",
            "idempotency_key": "crash-once",
        },
    )
    assert crash.status_code == 202, crash.text
    assert client.get("/api/v1/health").json()["status"] == "ok"
    recovery_required = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}
    )
    assert recovery_required["active_prompt"] is None
    assert recovery_required["execution"]["current_step"] == 1

    recover = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "recover",
            "expected_revision": recovery_required["execution"]["revision"],
            "reason": "restart from checkpoint",
            "idempotency_key": "recover-once",
        },
    )
    assert recover.status_code == 202, recover.text
    replayed = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    assert replayed["active_prompt"]["id"] != first_prompt_id
    assert replayed["execution"]["worker_generation"] == 2
    assert replayed["execution"]["current_step"] == 1

    answer = client.post(
        f"/api/v1/prompts/{replayed['active_prompt']['id']}/responses",
        headers=operator_headers,
        json={
            "value": "recover",
            "expected_revision": replayed["execution"]["revision"],
            "reason": "complete recovered prompt",
            "idempotency_key": "answer-recovered",
        },
    )
    assert answer.status_code == 202, answer.text
    wait_for_state(client, execution_id, viewer_headers, {"completed"})

    event_types = [
        item["event_type"]
        for item in client.get(
            f"/api/v1/executions/{execution_id}/events", headers=viewer_headers
        ).json()["items"]
    ]
    assert "prompt.interrupted" in event_types
    assert event_types.count("prompt.opened") == 2
    committed_logs = [
        item
        for item in client.get(
            f"/api/v1/executions/{execution_id}/events", headers=viewer_headers
        ).json()["items"]
        if item["event_type"] == "procedure.log"
        and item["payload"]["message"] == "checkpoint before prompt"
    ]
    assert len(committed_logs) == 1


@pytest.mark.parametrize("pause_before_crash", [False, True], ids=["running", "paused"])
def test_crash_recovery_from_each_non_prompt_worker_state(
    client: TestClient,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
    admin_headers: dict[str, str],
    pause_before_crash: bool,
) -> None:
    execution_id = create_execution(client, operator_headers, "pause")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"running"})
    if pause_before_crash:
        pause = client.post(
            f"/api/v1/executions/{execution_id}/commands",
            headers=operator_headers,
            json={
                "type": "pause",
                "expected_revision": snapshot["execution"]["revision"],
                "reason": "reach paused crash boundary",
                "idempotency_key": "pause-before-crash",
            },
        )
        assert pause.status_code == 202, pause.text
        snapshot = wait_for_state(client, execution_id, viewer_headers, {"paused"})

    crash = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=admin_headers,
        json={
            "type": "simulate_crash",
            "expected_revision": snapshot["execution"]["revision"],
            "reason": f"exercise {snapshot['execution']['state']} recovery",
            "idempotency_key": "crash-at-worker-boundary",
        },
    )
    assert crash.status_code == 202, crash.text
    recoverable = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}
    )
    assert client.get("/api/v1/health").json()["status"] == "ok"

    recover = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "recover",
            "expected_revision": recoverable["execution"]["revision"],
            "reason": "resume from committed checkpoint",
            "idempotency_key": "recover-worker-boundary",
        },
    )
    assert recover.status_code == 202, recover.text
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    messages = [
        event["payload"]["message"]
        for event in completed["events"]
        if event["event_type"] == "procedure.log"
    ]
    assert messages.count("before wait") == 1
    assert messages.count("after wait") == 1


def test_revision_and_idempotency_guards(
    client: TestClient, viewer_headers: dict[str, str], operator_headers: dict[str, str]
) -> None:
    execution_id = create_execution(client, operator_headers, "recovery")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    body = {
        "type": "abort",
        "expected_revision": snapshot["execution"]["revision"],
        "reason": "end test",
        "idempotency_key": "abort-once",
    }
    first = client.post(
        f"/api/v1/executions/{execution_id}/commands", headers=operator_headers, json=body
    )
    assert first.status_code == 202, first.text
    wait_for_state(client, execution_id, viewer_headers, {"aborted"})
    repeated = client.post(
        f"/api/v1/executions/{execution_id}/commands", headers=operator_headers, json=body
    )
    assert repeated.status_code == 202
    assert repeated.json()["command"]["id"] == first.json()["command"]["id"]
    conflicting_retry = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={**body, "reason": "changed request content"},
    )
    assert conflicting_retry.status_code == 409

    aborted = wait_for_state(client, execution_id, viewer_headers, {"aborted"})
    assert aborted["active_prompt"] is None
    event_types = [item["event_type"] for item in aborted["events"]]
    assert "prompt.cancelled" in event_types
    terminal_sequence = next(
        item["sequence"]
        for item in aborted["events"]
        if item["event_type"] == "execution.state_changed"
        and item["payload"]["state"] == "aborted"
    )
    assert not any(
        item["sequence"] > terminal_sequence
        and item["event_type"] in {"procedure.log", "telemetry.sample"}
        for item in aborted["events"]
    )
    deadline = time.monotonic() + 3
    while execution_id in client.app.state.supervisor._workers and time.monotonic() < deadline:
        time.sleep(0.02)
    assert execution_id not in client.app.state.supervisor._workers

    stale = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={**body, "idempotency_key": "different", "expected_revision": 0},
    )
    assert stale.status_code == 409


def test_creation_is_idempotent_and_websocket_replays_versioned_events(
    client: TestClient, viewer_headers: dict[str, str], operator_headers: dict[str, str]
) -> None:
    execution_id = create_execution(client, operator_headers, "recovery")
    duplicate = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "recovery",
            "context_id": "simulator",
            "reason": "pytest",
            "idempotency_key": "create-recovery",
        },
    )
    assert duplicate.status_code == 202
    assert duplicate.json()["execution"]["id"] == execution_id
    conflict = client.post(
        "/api/v1/executions",
        headers=operator_headers,
        json={
            "procedure_id": "recovery",
            "context_id": "simulator",
            "reason": "different request content",
            "idempotency_key": "create-recovery",
        },
    )
    assert conflict.status_code == 409
    wait_for_state(client, execution_id, viewer_headers, {"prompting"})

    snapshot = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()
    worker_started = next(
        item for item in snapshot["events"] if item["event_type"] == "worker.started"
    )
    assert worker_started["payload"]["pid"] != os.getpid()

    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence=0",
        subprotocols=["spell-auth", "test-token"],
    ) as websocket:
        first = websocket.receive_json()
        assert first["sequence"] == 1
        assert first["schema_version"] == "0.2"

    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence={first['sequence']}",
        subprotocols=["spell-auth", "test-token"],
    ) as websocket:
        resumed = websocket.receive_json()
        assert resumed["sequence"] == first["sequence"] + 1

    latest = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()["last_sequence"]
    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence={latest}",
        subprotocols=["spell-auth", "test-token"],
    ) as idle_websocket:
        assert idle_websocket.receive_json()["event_type"] == "stream.keepalive"

    try:
        with client.websocket_connect(
            f"/api/v1/ws?execution_id={execution_id}",
            subprotocols=["spell-auth", "wrong-token"],
        ):
            raise AssertionError("unauthenticated websocket should not connect")
    except WebSocketDisconnect as exc:
        assert exc.code == 4401

    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence=999999",
        subprotocols=["spell-auth", "test-token"],
    ) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.resync_required"


def test_pause_and_resume_are_worker_acknowledged(
    client: TestClient, viewer_headers: dict[str, str], operator_headers: dict[str, str]
) -> None:
    execution_id = create_execution(client, operator_headers, "pause")
    running = wait_for_state(client, execution_id, viewer_headers, {"running"})
    pause = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "pause",
            "expected_revision": running["execution"]["revision"],
            "reason": "verify pause",
            "idempotency_key": "pause-once",
        },
    )
    assert pause.status_code == 202, pause.text
    paused = wait_for_state(client, execution_id, viewer_headers, {"paused"})
    resume = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "resume",
            "expected_revision": paused["execution"]["revision"],
            "reason": "verify resume",
            "idempotency_key": "resume-once",
        },
    )
    assert resume.status_code == 202, resume.text
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    assert completed["execution"]["current_step"] == 3


def test_control_plane_restart_requires_explicit_recovery(
    tmp_path: Path,
    procedures_dir: Path,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
) -> None:
    database_url = os.getenv(
        "SPELL_TEST_DATABASE_URL", f"sqlite:///{(tmp_path / 'restart.db').as_posix()}"
    )
    if os.getenv("SPELL_TEST_DATABASE_URL"):
        engine, _ = create_test_database(database_url)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        engine.dispose()
    settings = Settings(
        database_url=database_url,
        procedures_dir=procedures_dir,
        dev_auth_token="test-token",
        websocket_replay_limit=1000,
        websocket_queue_size=64,
        websocket_keepalive_seconds=0.1,
    )
    with TestClient(create_app(settings)) as first_client:
        execution_id = create_execution(first_client, operator_headers, "recovery")
        original = wait_for_state(first_client, execution_id, viewer_headers, {"prompting"})
        prompt_id = original["active_prompt"]["id"]

    with TestClient(create_app(settings)) as restarted_client:
        orphaned = wait_for_state(
            restarted_client, execution_id, viewer_headers, {"recovery_required"}
        )
        assert orphaned["active_prompt"]["id"] == prompt_id
        rejected_response = restarted_client.post(
            f"/api/v1/prompts/{prompt_id}/responses",
            headers=operator_headers,
            json={
                "value": "recover",
                "expected_revision": orphaned["execution"]["revision"],
                "reason": "must recover worker first",
                "idempotency_key": "premature-response",
            },
        )
        assert rejected_response.status_code == 409
        recover = restarted_client.post(
            f"/api/v1/executions/{execution_id}/commands",
            headers=operator_headers,
            json={
                "type": "recover",
                "expected_revision": orphaned["execution"]["revision"],
                "reason": "recover after supervisor restart",
                "idempotency_key": "restart-recovery",
            },
        )
        assert recover.status_code == 202, recover.text
        reopened = wait_for_state(restarted_client, execution_id, viewer_headers, {"prompting"})
        assert reopened["active_prompt"]["id"] == prompt_id
        answer = restarted_client.post(
            f"/api/v1/prompts/{prompt_id}/responses",
            headers=operator_headers,
            json={
                "value": "recover",
                "expected_revision": reopened["execution"]["revision"],
                "reason": "complete durable prompt",
                "idempotency_key": "durable-prompt-response",
            },
        )
        assert answer.status_code == 202, answer.text
        wait_for_state(restarted_client, execution_id, viewer_headers, {"completed"})


def test_step_persistence_failure_rolls_back_effects_checkpoint_and_publication(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="atomic",
            procedure_name="Atomic",
            procedure_hash="0" * 64,
            procedure_source='Log("effect")\n',
            steps=[{"index": 0, "type": "log", "line": 1, "message": "effect", "level": "info"}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="atomic-create",
            total_steps=1,
            state="running",
            revision=1,
            worker_generation=7,
        )
        session.add(execution)
        session.commit()
        execution_id = execution.id

    original_add_event = supervisor._add_event
    calls = 0

    def fail_during_transaction(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("forced persistence failure")
        return original_add_event(*args, **kwargs)

    published: list[dict] = []
    monkeypatch.setattr(supervisor, "_add_event", fail_during_transaction)
    monkeypatch.setattr(supervisor.hub, "publish", lambda _execution_id, event: published.append(event))
    message = {
        "step_index": 0,
        "next_step": 1,
        "prompt_resolution": None,
        "effects": [
            {
                "event_type": "procedure.log",
                "source": "procedure",
                "severity": "info",
                "payload": {"message": "effect", "step_index": 0},
            },
            {
                "event_type": "step.completed",
                "source": "worker",
                "severity": "info",
                "payload": {"step_index": 0},
            },
        ],
    }
    with pytest.raises(RuntimeError, match="forced persistence failure"):
        supervisor._commit_step(execution_id, 7, message)

    with session_factory() as session:
        stored = session.get(Execution, execution_id)
        events = session.scalars(select(Event).where(Event.execution_id == execution_id)).all()
        assert stored.current_step == 0
        assert stored.next_sequence == 1
        assert events == []
    assert published == []


def test_creation_persists_auto_start_before_worker_spawn_failure(
    client: TestClient,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = client.app.state.supervisor

    def fail_spawn(*_args, **_kwargs):
        raise RuntimeError("forced spawn failure")

    monkeypatch.setattr(supervisor, "_spawn_worker", fail_spawn)
    request = {
        "procedure_id": "recovery",
        "context_id": "simulator",
        "reason": "verify atomic create and start",
        "idempotency_key": "create-with-spawn-failure",
    }
    first = client.post("/api/v1/executions", headers=operator_headers, json=request)
    assert first.status_code == 202, first.text
    execution_id = first.json()["execution"]["id"]
    snapshot = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()
    assert snapshot["execution"]["state"] == "recovery_required"
    start_commands = [item for item in snapshot["commands"] if item["type"] == "start"]
    assert len(start_commands) == 1
    assert start_commands[0]["status"] == "failed"

    repeated = client.post("/api/v1/executions", headers=operator_headers, json=request)
    assert repeated.status_code == 202
    assert repeated.json()["execution"]["id"] == execution_id
    assert repeated.json()["execution"]["state"] == "recovery_required"


def test_recover_spawn_failure_has_a_durable_failed_outcome(
    client: TestClient,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = create_execution(client, operator_headers, "recovery")
    prompting = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    crash = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=admin_headers,
        json={
            "type": "simulate_crash",
            "expected_revision": prompting["execution"]["revision"],
            "reason": "prepare failed recovery spawn",
            "idempotency_key": "crash-before-failed-recover",
        },
    )
    assert crash.status_code == 202, crash.text
    recoverable = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}
    )

    def fail_spawn(*_args, **_kwargs):
        raise RuntimeError("forced recovery spawn failure")

    monkeypatch.setattr(client.app.state.supervisor, "_spawn_worker", fail_spawn)
    recover = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "recover",
            "expected_revision": recoverable["execution"]["revision"],
            "reason": "verify failed recovery dispatch",
            "idempotency_key": "failed-recover-spawn",
        },
    )
    assert recover.status_code == 202, recover.text
    failed = wait_for_state(client, execution_id, viewer_headers, {"recovery_required"})
    recover_commands = [item for item in failed["commands"] if item["type"] == "recover"]
    assert len(recover_commands) == 1
    assert recover_commands[0]["status"] == "failed"
    assert "forced recovery spawn failure" in recover_commands[0]["result"]["error"]


def test_late_terminal_worker_state_fails_pending_control_without_regression(
    client: TestClient,
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="terminal-race",
            procedure_name="Terminal race",
            procedure_hash="1" * 64,
            procedure_source='Wait(0)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 0}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="terminal-race-create",
            total_steps=1,
            current_step=1,
            state="pausing",
            revision=4,
            worker_generation=1,
        )
        session.add(execution)
        session.flush()
        command = Command(
            execution_id=execution.id,
            command_type="pause",
            idempotency_key="terminal-race-pause",
            expected_revision=3,
            actor="pytest-operator",
            role="operator",
            reason="race with completion",
            request_payload={"request": {}, "_request_hash": "test"},
        )
        session.add(command)
        session.commit()
        execution_id = execution.id
        command_id = command.id

    supervisor._set_worker_state(execution_id, "completed")

    with session_factory() as session:
        stored_execution = session.get(Execution, execution_id)
        stored_command = session.get(Command, command_id)
        assert stored_execution.state == "completed"
        assert stored_command.status == "failed"
        assert stored_command.result_payload["error"] == (
            "worker reached completed before command dispatch"
        )
