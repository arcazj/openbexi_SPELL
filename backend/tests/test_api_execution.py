from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import queue
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from backend.app import create_app
from backend.auth import AuthConfig, issue_local_dev_token
from backend.config import Settings
from backend.database import Base, create_database as create_test_database
from backend.models import Command, Event, Execution
from backend.supervisor import ConflictError, WorkerHandle

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
    assert all(event["schema_version"] == "0.3" for event in events)
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


def test_unsigned_identity_headers_cannot_elevate_a_viewer(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    spoofed = {
        **viewer_headers,
        "X-Dev-Actor": "spoofed.admin",
        "X-Dev-Role": "admin",
    }
    response = client.post(
        "/api/v1/executions",
        headers=spoofed,
        json={
            "procedure_id": "integration",
            "context_id": "simulator",
            "reason": "role spoof regression",
            "idempotency_key": "viewer-cannot-elevate",
        },
    )
    assert response.status_code == 403


def test_validation_endpoint_is_structured_transient_and_size_bounded(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    before = client.get("/api/v1/executions", headers=viewer_headers).json()["items"]
    valid = client.post(
        "/api/v1/procedures/validate",
        headers=viewer_headers,
        json={
            "source_name": "submitted.spell.py",
            "source": (
                "count: int = 1\n"
                "if count == 1:\n"
                "    Log('validated')\n"
            ),
        },
    )
    assert valid.status_code == 200
    assert valid.json()["valid"] is True
    assert valid.json()["subset_version"] == "spell-restricted-ast/0.3"
    assert valid.json()["variables"] == {"count": "int"}
    assert len(valid.json()["sha256"]) == 64

    invalid = client.post(
        "/api/v1/procedures/validate",
        headers=viewer_headers,
        json={"source": "import os\nLog('unsafe')\n"},
    )
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
    diagnostic = invalid.json()["diagnostics"][0]
    assert diagnostic["code"].startswith("SPELL")
    assert diagnostic["severity"] == "error"
    assert diagnostic["line"] == 1
    assert isinstance(diagnostic["column"], int)

    oversized = client.post(
        "/api/v1/procedures/validate",
        headers=viewer_headers,
        json={"source": "x" * 100_001},
    )
    assert oversized.status_code == 422
    after = client.get("/api/v1/executions", headers=viewer_headers).json()["items"]
    assert after == before


def test_validation_endpoint_rejects_deep_expression_without_a_500(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    source = "value: int = " + "1+" * 1_500 + "1\nLog('ok')\n"

    response = client.post(
        "/api/v1/procedures/validate",
        headers=viewer_headers,
        json={"source_name": "deep.spell.py", "source": source},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["steps"] == []
    assert body["diagnostics"][0]["code"] == "SPELL003"
    assert body["diagnostics"][0]["severity"] == "error"


def test_validation_endpoint_rejects_unpaired_unicode_without_a_500(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/procedures/validate",
        headers={**viewer_headers, "Content-Type": "application/json"},
        content=json.dumps(
            {"source_name": "unicode.spell.py", "source": "Log('\ud800')\n"},
            ensure_ascii=True,
        ),
    )

    assert response.status_code == 422
    body = response.json()
    assert body["detail"][0]["type"] == "string_unicode"
    assert "input" not in body["detail"][0]

    escaped = client.post(
        "/api/v1/procedures/validate",
        headers=viewer_headers,
        json={"source_name": "escaped.spell.py", "source": r"Log('\ud800')" + "\n"},
    )
    assert escaped.status_code == 200
    escaped_body = escaped.json()
    assert escaped_body["valid"] is False
    assert len(escaped_body["sha256"]) == 64
    assert escaped_body["diagnostics"][0]["code"] == "SPELL716"


def test_prompt_response_schema_enforces_the_parser_choice_width(
    client: TestClient, operator_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/prompts/not-open/responses",
        headers=operator_headers,
        json={
            "value": "x" * 201,
            "expected_revision": 0,
            "reason": "verify prompt response width",
            "idempotency_key": "oversized-prompt-response",
        },
    )

    assert response.status_code == 422


def test_execution_persists_the_exact_source_used_for_hash_and_ir(
    client: TestClient,
    operator_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = client.app.state.catalog
    parsed = catalog.get("integration")
    parsed.path.write_text('Log("changed after validation")\n', encoding="utf-8")
    monkeypatch.setattr(catalog, "get", lambda procedure_id: parsed)

    execution_id = create_execution(client, operator_headers, "integration")

    with client.app.state.session_factory() as session:
        execution = session.get(Execution, execution_id)
        assert execution is not None
        assert execution.procedure_source == parsed.source
        assert execution.procedure_source != parsed.path.read_text(encoding="utf-8")
        assert execution.procedure_hash == hashlib.sha256(
            execution.procedure_source.encode("utf-8")
        ).hexdigest()
        assert execution.steps == list(parsed.steps)


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
    assert recovery_required["active_prompt"]["id"] == first_prompt_id
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
    assert replayed["active_prompt"]["id"] == first_prompt_id
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
    assert "prompt.interrupted" not in event_types
    assert event_types.count("prompt.opened") == 1
    assert event_types.count("prompt.reopened") == 1
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
    websocket_token = viewer_headers["Authorization"].removeprefix("Bearer ")
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
        subprotocols=["spell-auth", websocket_token],
    ) as websocket:
        first = websocket.receive_json()
        assert first["sequence"] == 1
        assert first["schema_version"] == "0.3"

    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence={first['sequence']}",
        subprotocols=["spell-auth", websocket_token],
    ) as websocket:
        resumed = websocket.receive_json()
        assert resumed["sequence"] == first["sequence"] + 1

    latest = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()["last_sequence"]
    with client.websocket_connect(
        f"/api/v1/ws?execution_id={execution_id}&after_sequence={latest}",
        subprotocols=["spell-auth", websocket_token],
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
        subprotocols=["spell-auth", websocket_token],
    ) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.resync_required"


def test_established_websocket_closes_when_credential_expires(
    client: TestClient,
    auth_config: AuthConfig,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
) -> None:
    execution_id = create_execution(client, operator_headers, "recovery")
    wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    latest = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()["last_sequence"]
    short_lived_token = issue_local_dev_token(
        auth_config,
        subject="expiring-websocket-viewer",
        role="viewer",
        peer_host="127.0.0.1",
        lifetime_seconds=2,
    )

    started = time.monotonic()
    try:
        with client.websocket_connect(
            f"/api/v1/ws?execution_id={execution_id}&after_sequence={latest}",
            subprotocols=["spell-auth", short_lived_token],
        ) as websocket:
            assert websocket.accepted_subprotocol == "spell-auth"
            while True:
                websocket.receive_json()
    except WebSocketDisconnect as exc:
        assert exc.code == 4401
        assert exc.reason == "websocket credentials expired"
    assert time.monotonic() - started < 3


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
    auth_config: AuthConfig,
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
        websocket_replay_limit=1000,
        websocket_queue_size=64,
        websocket_keepalive_seconds=0.1,
    )
    with TestClient(create_app(settings, auth_config=auth_config)) as first_client:
        execution_id = create_execution(first_client, operator_headers, "recovery")
        original = wait_for_state(first_client, execution_id, viewer_headers, {"prompting"})
        prompt_id = original["active_prompt"]["id"]

    with TestClient(create_app(settings, auth_config=auth_config)) as restarted_client:
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
        "variables": {},
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


def test_dispatch_failure_retries_atomic_command_settlement(
    client: TestClient,
    operator_headers: dict[str, str],
    viewer_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="dispatch-retry",
            procedure_name="Dispatch retry",
            procedure_hash="6" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="dispatch-retry-create",
            total_steps=1,
            state="running",
            revision=4,
            worker_generation=1,
        )
        session.add(execution)
        session.commit()
        execution_id = execution.id

    original_set_state = supervisor._set_state
    attempts = 0
    recovery_lock_available: list[bool] = []

    def fail_first_settlement(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            def probe_lock() -> None:
                acquired = supervisor._lock.acquire(timeout=0.5)
                recovery_lock_available.append(acquired)
                if acquired:
                    supervisor._lock.release()

            probe = threading.Thread(target=probe_lock)
            probe.start()
            probe.join(timeout=1)
            assert not probe.is_alive()
            raise RuntimeError("forced transient settlement outage")
        return original_set_state(*args, **kwargs)

    monkeypatch.setattr(supervisor, "_set_state", fail_first_settlement)
    response = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "pause",
            "expected_revision": 4,
            "reason": "verify retry after dispatch failure",
            "idempotency_key": "dispatch-retry-pause",
        },
    )
    assert response.status_code == 202, response.text
    assert attempts == 2
    assert recovery_lock_available == [True]
    snapshot = client.get(
        f"/api/v1/executions/{execution_id}/snapshot", headers=viewer_headers
    ).json()
    assert snapshot["execution"]["state"] == "recovery_required"
    command = next(
        item for item in snapshot["commands"] if item["type"] == "pause"
    )
    assert command["status"] == "failed"
    assert "worker is unavailable" in command["result"]["error"]


def test_live_nonconsuming_worker_triggers_command_ack_watchdog(
    client: TestClient,
    operator_headers: dict[str, str],
    viewer_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = client.app.state.supervisor
    supervisor.command_ack_timeout_seconds = 0.05
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="ack-timeout",
            procedure_name="ACK timeout",
            procedure_hash="7" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="ack-timeout-create",
            total_steps=1,
            state="running",
            revision=2,
            worker_generation=3,
        )
        session.add(execution)
        session.commit()
        execution_id = execution.id

    class FakeQueue:
        def __init__(self):
            self.messages: list[dict] = []
            self.closed = False

        def put(self, message: dict) -> None:
            self.messages.append(message)

        def close(self) -> None:
            self.closed = True

        def cancel_join_thread(self) -> None:
            return None

    class LiveProcess:
        def __init__(self):
            self.alive = True
            self.exitcode: int | None = None
            self.terminated = False
            self.closed = False

        def is_alive(self) -> bool:
            return self.alive

        def terminate(self) -> None:
            self.terminated = True
            self.alive = False
            self.exitcode = -15

        def kill(self) -> None:
            self.alive = False
            self.exitcode = -9

        def join(self, timeout: float | None = None) -> None:
            assert timeout is not None

        def close(self) -> None:
            self.closed = True

    process = LiveProcess()
    control = FakeQueue()
    output = FakeQueue()
    handle = WorkerHandle(process=process, control=control, output=output, generation=3)
    with supervisor._lock:
        supervisor._workers[execution_id] = handle

    original_set_state = supervisor._set_state
    watchdog_lock_available: list[bool] = []

    def observe_watchdog_settlement(*args, **kwargs):
        def probe_lock() -> None:
            acquired = supervisor._lock.acquire(timeout=0.5)
            watchdog_lock_available.append(acquired)
            if acquired:
                supervisor._lock.release()

        probe = threading.Thread(target=probe_lock)
        probe.start()
        probe.join(timeout=1)
        assert not probe.is_alive()
        return original_set_state(*args, **kwargs)

    monkeypatch.setattr(supervisor, "_set_state", observe_watchdog_settlement)

    response = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "pause",
            "expected_revision": 2,
            "reason": "verify bounded ACK timeout",
            "idempotency_key": "ack-timeout-pause",
        },
    )
    assert response.status_code == 202, response.text
    snapshot = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}, timeout=2
    )
    assert process.terminated and process.closed
    assert watchdog_lock_available == [True]
    assert control.messages == [
        {"type": "pause", "command_id": response.json()["command"]["id"]}
    ]
    command = next(
        item for item in snapshot["commands"] if item["type"] == "pause"
    )
    assert command["status"] == "failed"
    assert "did not acknowledge pause command" in command["result"]["error"]
    assert any(
        event["event_type"] == "worker.command_ack_timeout"
        for event in snapshot["events"]
    )


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


def test_consumer_persistence_failure_stops_worker_and_requires_recovery(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="consumer-failure",
            procedure_name="Consumer failure",
            procedure_hash="2" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="consumer-failure-create",
            total_steps=1,
            state="pausing",
            revision=2,
            worker_generation=9,
        )
        session.add(execution)
        session.flush()
        command = Command(
            execution_id=execution.id,
            command_type="pause",
            idempotency_key="consumer-failure-pause",
            expected_revision=1,
            actor="pytest-operator",
            role="operator",
            reason="exercise consumer failure recovery",
            request_payload={"request": {}, "_request_hash": "test"},
        )
        session.add(command)
        session.commit()
        execution_id = execution.id
        command_id = command.id

    class FakeQueue:
        def __init__(self, messages: list[dict] | None = None):
            self._messages: queue.Queue = queue.Queue()
            for message in messages or []:
                self._messages.put(message)
            self.closed = False

        def get(self, timeout: float):
            return self._messages.get(timeout=timeout)

        def close(self) -> None:
            self.closed = True

        def cancel_join_thread(self) -> None:
            return None

    class FakeProcess:
        def __init__(self):
            self.alive = True
            self.exitcode: int | None = None
            self.terminated = False
            self.closed = False
            self.join_timeouts: list[float | None] = []

        def is_alive(self) -> bool:
            return self.alive

        def join(self, timeout: float | None = None) -> None:
            self.join_timeouts.append(timeout)
            if timeout is None:
                raise AssertionError("monitor attempted an unbounded process join")

        def terminate(self) -> None:
            self.terminated = True
            self.alive = False
            self.exitcode = -15

        def kill(self) -> None:
            self.alive = False
            self.exitcode = -9

        def close(self) -> None:
            self.closed = True

    output = FakeQueue(
        [
            {
                "kind": "event",
                "generation": 9,
                "event_type": "worker.persistence_probe",
                "payload": {},
            }
        ]
    )
    control = FakeQueue()
    process = FakeProcess()
    handle = WorkerHandle(process=process, control=control, output=output, generation=9)
    with supervisor._lock:
        supervisor._workers[execution_id] = handle

    original_append_event = supervisor.append_event
    original_set_state = supervisor._set_state
    recovery_transition_attempts = 0

    def fail_probe_event(
        event_execution_id: str, event_type: str, *args, **kwargs
    ):
        if event_type == "worker.persistence_probe":
            raise RuntimeError("forced consumer persistence failure")
        return original_append_event(event_execution_id, event_type, *args, **kwargs)

    def fail_first_recovery_transition(*args, **kwargs):
        nonlocal recovery_transition_attempts
        recovery_transition_attempts += 1
        if recovery_transition_attempts == 1:
            raise RuntimeError("forced transient recovery persistence failure")
        return original_set_state(*args, **kwargs)

    monkeypatch.setattr(supervisor, "append_event", fail_probe_event)
    monkeypatch.setattr(supervisor, "_set_state", fail_first_recovery_transition)
    monitor = threading.Thread(
        target=supervisor._monitor_worker, args=(execution_id, handle), daemon=True
    )
    consumer = threading.Thread(
        target=supervisor._consume_worker, args=(execution_id, handle), daemon=True
    )
    monitor.start()
    consumer.start()
    consumer.join(timeout=2)
    monitor.join(timeout=3)

    assert not consumer.is_alive()
    assert not monitor.is_alive()
    assert recovery_transition_attempts == 2
    assert handle.failure_signal.is_set()
    assert "forced consumer persistence failure" in (handle.failure_detail or "")
    assert process.terminated
    assert process.closed
    assert process.join_timeouts and all(timeout is not None for timeout in process.join_timeouts)
    assert control.closed and output.closed
    assert execution_id not in supervisor._workers

    with session_factory() as session:
        stored_execution = session.get(Execution, execution_id)
        stored_command = session.get(Command, command_id)
        events = session.scalars(
            select(Event).where(Event.execution_id == execution_id).order_by(Event.sequence)
        ).all()
        assert stored_execution.state == "recovery_required"
        assert stored_command.status == "failed"
        assert "forced consumer persistence failure" in stored_command.result_payload["error"]
        assert [event.event_type for event in events].count("command.failed") == 1
        assert [event.event_type for event in events].count("worker.consumer_failed") == 1


def test_restart_fails_every_accepted_control_command(client: TestClient) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    command_types = ("start", "pause", "resume", "abort", "recover")
    with session_factory() as session:
        execution = Execution(
            procedure_id="restart-pending",
            procedure_name="Restart pending commands",
            procedure_hash="3" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="restart-pending-create",
            total_steps=1,
            state="running",
            revision=6,
            worker_generation=1,
        )
        session.add(execution)
        session.flush()
        for command_type in command_types:
            session.add(
                Command(
                    execution_id=execution.id,
                    command_type=command_type,
                    idempotency_key=f"restart-pending-{command_type}",
                    expected_revision=5,
                    actor="pytest-operator",
                    role="operator",
                    reason="verify restart command settlement",
                    request_payload={"request": {}, "_request_hash": "test"},
                )
            )
        session.commit()
        execution_id = execution.id

    supervisor.reconcile_orphaned_executions()
    supervisor.reconcile_orphaned_executions()

    with session_factory() as session:
        stored_execution = session.get(Execution, execution_id)
        commands = session.scalars(
            select(Command).where(Command.execution_id == execution_id)
        ).all()
        failed_events = session.scalars(
            select(Event).where(
                Event.execution_id == execution_id,
                Event.event_type == "command.failed",
            )
        ).all()
        assert stored_execution.state == "recovery_required"
        assert {command.command_type for command in commands} == set(command_types)
        assert all(command.status == "failed" for command in commands)
        assert all(command.completed_at is not None for command in commands)
        assert all(
            command.result_payload["error"]
            == "supervisor restarted before command completion"
            for command in commands
        )
        assert {event.payload["command_id"] for event in failed_events} == {
            command.id for command in commands
        }


def test_orderly_shutdown_kills_stubborn_worker_and_settles_command(
    client: TestClient,
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="shutdown-pending",
            procedure_name="Shutdown pending command",
            procedure_hash="5" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="shutdown-pending-create",
            total_steps=1,
            state="pausing",
            revision=2,
            worker_generation=1,
        )
        session.add(execution)
        session.flush()
        command = Command(
            execution_id=execution.id,
            command_type="pause",
            idempotency_key="shutdown-pending-pause",
            expected_revision=1,
            actor="pytest-operator",
            role="operator",
            reason="verify orderly shutdown settlement",
            request_payload={"request": {}, "_request_hash": "test"},
        )
        session.add(command)
        session.commit()
        execution_id = execution.id
        command_id = command.id

    class FakeQueue:
        def __init__(self):
            self.closed = False

        def close(self) -> None:
            self.closed = True

        def cancel_join_thread(self) -> None:
            return None

    class StubbornProcess:
        def __init__(self):
            self.alive = True
            self.terminated = False
            self.killed = False
            self.closed = False
            self.join_timeouts: list[float | None] = []

        def is_alive(self) -> bool:
            return self.alive

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True
            self.alive = False

        def join(self, timeout: float | None = None) -> None:
            self.join_timeouts.append(timeout)

        def close(self) -> None:
            self.closed = True

    process = StubbornProcess()
    control = FakeQueue()
    output = FakeQueue()
    handle = WorkerHandle(process=process, control=control, output=output, generation=1)
    with supervisor._lock:
        supervisor._workers[execution_id] = handle

    supervisor.close()

    assert process.terminated and process.killed and process.closed
    assert process.join_timeouts == [2, 2]
    assert control.closed and output.closed
    assert execution_id not in supervisor._workers
    with session_factory() as session:
        stored_execution = session.get(Execution, execution_id)
        stored_command = session.get(Command, command_id)
        assert stored_execution.state == "recovery_required"
        assert stored_command.status == "failed"
        assert stored_command.completed_at is not None
        assert (
            stored_command.result_payload["error"]
            == "supervisor stopped before command completion"
        )


def test_terminal_transition_settles_every_accepted_control_command(
    client: TestClient,
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    command_types = ("start", "pause", "resume", "abort", "recover")
    with session_factory() as session:
        execution = Execution(
            procedure_id="terminal-pending",
            procedure_name="Terminal pending commands",
            procedure_hash="4" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="terminal-pending-create",
            total_steps=1,
            state="aborting",
            revision=6,
            worker_generation=1,
        )
        session.add(execution)
        session.flush()
        commands: dict[str, Command] = {}
        for command_type in command_types:
            command = Command(
                execution_id=execution.id,
                command_type=command_type,
                idempotency_key=f"terminal-pending-{command_type}",
                expected_revision=5,
                actor="pytest-operator",
                role="operator",
                reason="verify terminal command settlement",
                request_payload={"request": {}, "_request_hash": "test"},
            )
            commands[command_type] = command
            session.add(command)
        session.commit()
        execution_id = execution.id
        abort_command_id = commands["abort"].id

    supervisor._set_state(
        execution_id, "aborted", source="worker", command_id=abort_command_id
    )

    with session_factory() as session:
        stored_commands = session.scalars(
            select(Command).where(Command.execution_id == execution_id)
        ).all()
        by_type = {command.command_type: command for command in stored_commands}
        assert by_type["abort"].status == "completed"
        assert all(
            by_type[command_type].status == "failed"
            for command_type in command_types
            if command_type != "abort"
        )
        assert all(command.completed_at is not None for command in stored_commands)


@pytest.mark.parametrize(
    "timeout_seconds",
    [0.0, -1.0, float("nan"), float("inf"), float("-inf")],
)
def test_settings_reject_invalid_command_ack_timeout(
    tmp_path: Path, timeout_seconds: float
) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        Settings(
            database_url=f"sqlite:///{(tmp_path / 'invalid-timeout.db').as_posix()}",
            procedures_dir=tmp_path,
            websocket_replay_limit=1000,
            websocket_queue_size=64,
            websocket_keepalive_seconds=0.1,
            command_ack_timeout_seconds=timeout_seconds,
        )


def test_intentionally_stopped_worker_is_generation_fenced(client: TestClient) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="stopped-worker-fence",
            procedure_name="Stopped worker fence",
            procedure_hash="8" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="stopped-worker-fence-create",
            total_steps=1,
            state="recovery_required",
            revision=3,
            worker_generation=4,
        )
        session.add(execution)
        session.commit()
        execution_id = execution.id

    handle = WorkerHandle(
        process=object(),
        control=object(),
        output=object(),
        generation=4,
        intentional_stop=True,
    )
    with supervisor._lock:
        supervisor._workers[execution_id] = handle
    try:
        assert not supervisor._worker_message_is_current(
            execution_id,
            handle,
            {"kind": "event", "generation": 4},
        )
    finally:
        with supervisor._lock:
            supervisor._workers.pop(execution_id, None)


def test_concurrent_event_commits_publish_in_sequence(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = client.app.state.supervisor
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="ordered-publication",
            procedure_name="Ordered publication",
            procedure_hash="9" * 64,
            procedure_source="",
            steps=[],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="ordered-publication-create",
            total_steps=0,
            state="running",
        )
        session.add(execution)
        session.commit()
        execution_id = execution.id

    first_publish_started = threading.Event()
    second_published = threading.Event()
    published_sequences: list[int] = []

    def delayed_publish(_execution_id: str, event: dict) -> None:
        if event["sequence"] == 1:
            first_publish_started.set()
            second_published.wait(timeout=0.5)
        published_sequences.append(event["sequence"])
        if event["sequence"] == 2:
            second_published.set()

    monkeypatch.setattr(supervisor.hub, "publish", delayed_publish)
    errors: list[BaseException] = []

    def append(event_type: str) -> None:
        try:
            supervisor.append_event(execution_id, event_type, {}, source="pytest")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(target=append, args=("publication.first",))
    second = threading.Thread(target=append, args=("publication.second",))
    first.start()
    assert first_publish_started.wait(timeout=1)
    second.start()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert published_sequences == [1, 2]
    with session_factory() as session:
        sequences = list(
            session.scalars(
                select(Event.sequence)
                .where(Event.execution_id == execution_id)
                .order_by(Event.sequence)
            ).all()
        )
    assert sequences == [1, 2]


def test_command_watchdog_retires_promptly_after_settlement(client: TestClient) -> None:
    supervisor = client.app.state.supervisor
    supervisor.command_ack_timeout_seconds = 2.0
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        execution = Execution(
            procedure_id="retiring-watchdog",
            procedure_name="Retiring watchdog",
            procedure_hash="a" * 64,
            procedure_source='Wait(1)\n',
            steps=[{"index": 0, "type": "wait", "line": 1, "seconds": 1}],
            context_id="simulator",
            created_by="pytest",
            creation_idempotency_key="retiring-watchdog-create",
            total_steps=1,
            state="pausing",
            revision=2,
            worker_generation=1,
        )
        session.add(execution)
        session.flush()
        command = Command(
            execution_id=execution.id,
            command_type="pause",
            idempotency_key="retiring-watchdog-pause",
            expected_revision=1,
            actor="pytest-operator",
            role="operator",
            reason="verify prompt watchdog retirement",
            request_payload={"request": {}, "_request_hash": "test"},
        )
        session.add(command)
        session.commit()
        execution_id = execution.id
        command_id = command.id

    handle = WorkerHandle(
        process=object(), control=object(), output=object(), generation=1
    )
    watchdog = supervisor._arm_command_watchdog(execution_id, command_id, handle)
    supervisor._complete_command(command_id, {"state": "paused", "revision": 2})
    watchdog.join(timeout=0.5)

    assert not watchdog.is_alive()


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/api/v1/executions",
            {
                "procedure_id": "integration",
                "context_id": "simulator",
                "reason": "reject oversized creation key",
            },
        ),
        (
            "/api/v1/executions/missing/commands",
            {
                "type": "pause",
                "expected_revision": 0,
                "reason": "reject oversized command key",
            },
        ),
        (
            "/api/v1/prompts/missing/responses",
            {
                "value": "yes",
                "expected_revision": 0,
                "reason": "reject oversized response key",
            },
        ),
    ],
)
def test_idempotency_header_is_bounded_before_database_write(
    client: TestClient,
    operator_headers: dict[str, str],
    path: str,
    payload: dict,
) -> None:
    headers = {**operator_headers, "X-Idempotency-Key": "x" * 201}
    response = client.post(path, headers=headers, json=payload)

    assert response.status_code == 422


def test_direct_supervisor_entry_points_bound_idempotency_keys(
    client: TestClient,
) -> None:
    supervisor = client.app.state.supervisor
    procedure = client.app.state.catalog.get("integration")
    oversized = "x" * 201

    with pytest.raises(ConflictError, match="must not exceed 200"):
        supervisor.create_execution(
            procedure=procedure,
            actor="pytest-operator",
            role="operator",
            reason="reject direct creation key",
            idempotency_key=oversized,
        )
    with pytest.raises(ConflictError, match="must not exceed 200"):
        supervisor.respond_to_prompt(
            prompt_id="missing",
            response="yes",
            expected_revision=0,
            idempotency_key=oversized,
            actor="pytest-operator",
            role="operator",
            reason="reject direct response key",
            correlation_id=None,
        )
