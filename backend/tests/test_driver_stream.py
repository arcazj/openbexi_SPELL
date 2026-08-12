from __future__ import annotations

import time
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.auth import AuthConfig, issue_local_dev_token
from backend.driver_domain import DEFAULT_DRIVER_PROFILE_ID
from backend.driver_models import DriverOutboxEvent
from backend.driver_repository import DriverValidationError


def _token(headers: dict[str, str]) -> str:
    return headers["Authorization"].removeprefix("Bearer ")


def _append_profile_event(client: TestClient, marker: int) -> dict[str, Any]:
    repository = client.app.state.driver_repository
    current = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
    repository.configure_profile_enabled(
        DEFAULT_DRIVER_PROFILE_ID,
        not bool(current["enabled"]),
        actor="pytest-driver-stream",
        correlation_id=str(UUID(int=marker)),
    )
    return repository.replay_driver_events(after_sequence=0, limit=100)["items"][-1]


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_keys(item) for item in value)) if value else set()
    return set()


def _expect_resync_close(websocket, reason: str, authority: int) -> None:
    frame = websocket.receive_json()
    assert frame == {
        "event_type": "stream.resync_required",
        "stream": "driver.lifecycle",
        "payload": {
            "reason": reason,
            "authoritative_sequence": authority,
        },
    }
    with pytest.raises(WebSocketDisconnect) as closed:
        websocket.receive_json()
    assert closed.value.code == 4409
    assert closed.value.reason == "snapshot resynchronization required"


def test_repository_replays_committed_outbox_with_stable_cursor_and_metadata(
    client: TestClient,
) -> None:
    repository = client.app.state.driver_repository
    assert repository.driver_event_cursor() == {
        "first_sequence": None,
        "last_sequence": 0,
    }

    first = _append_profile_event(client, 701)
    second = _append_profile_event(client, 702)
    replay = repository.replay_driver_events(
        after_sequence=first["sequence"], limit=10
    )

    assert replay["cursor_available"] is True
    assert replay["first_sequence"] == first["sequence"]
    assert replay["last_sequence"] == second["sequence"]
    assert replay["items"] == [second]
    assert second["sequence"] > first["sequence"]
    assert second["schema_version"] == "spell.driver.event/1"
    assert second["actor"] == "pytest-driver-stream"
    assert second["correlation_id"] == str(UUID(int=702))
    assert second["operation_id"] is None
    assert second["attempt_id"] is None

    for after, limit in (
        (-1, 1),
        (True, 1),
        (9_223_372_036_854_775_808, 1),
        (0, 0),
        (0, 10_002),
    ):
        with pytest.raises(DriverValidationError):
            repository.replay_driver_events(after_sequence=after, limit=limit)


def test_driver_websocket_is_authenticated_ordered_replay_only_and_deduplicated(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    first = _append_profile_event(client, 711)
    second = _append_profile_event(client, 712)
    token = _token(viewer_headers)
    repository = client.app.state.driver_repository
    original_replay = repository.replay_driver_events
    subscribed_before_replay = False

    def replay_after_subscription(*, after_sequence: int, limit: int):
        nonlocal subscribed_before_replay
        with client.app.state.hub._lock:
            subscribed_before_replay = bool(
                client.app.state.hub._subscribers.get("driver.lifecycle")
            )
        return original_replay(after_sequence=after_sequence, limit=limit)

    repository.replay_driver_events = replay_after_subscription

    try:
        with client.websocket_connect(
            "/api/v1/driver-events/ws?after_sequence=0",
            subprotocols=["spell-auth", token],
        ) as websocket:
            replay = [websocket.receive_json(), websocket.receive_json()]
            assert [item["sequence"] for item in replay] == [
                first["sequence"],
                second["sequence"],
            ]
            assert all(item["event_id"] for item in replay)
            assert not {
                "driver_target",
                "target",
                "endpoint",
                "credential_reference",
                "ca_path",
                "cert_path",
                "key_path",
                "secret",
            }.intersection(_keys(replay))
    finally:
        repository.replay_driver_events = original_replay
    assert subscribed_before_replay is True

    latest = int(second["sequence"])
    with client.websocket_connect(
        f"/api/v1/driver-events/ws?after_sequence={latest}",
        subprotocols=["spell-auth", token],
    ) as websocket:
        live = _append_profile_event(client, 713)
        client.app.state.hub.publish("driver.lifecycle", live)
        client.app.state.hub.publish("driver.lifecycle", live)
        assert websocket.receive_json()["sequence"] == live["sequence"]
        keepalive = websocket.receive_json()
        assert keepalive["event_type"] == "stream.keepalive"
        assert keepalive["last_sequence"] == live["sequence"]

    with pytest.raises(WebSocketDisconnect) as rejected:
        with client.websocket_connect(
            "/api/v1/driver-events/ws",
            subprotocols=["spell-auth", "wrong-token"],
        ):
            raise AssertionError("invalid driver websocket credentials were accepted")
    assert rejected.value.code == 4401


def test_driver_websocket_forces_resync_for_ahead_unavailable_limit_and_overflow(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    first = _append_profile_event(client, 721)
    second = _append_profile_event(client, 722)
    authority = int(second["sequence"])
    token = _token(viewer_headers)

    with client.websocket_connect(
        f"/api/v1/driver-events/ws?after_sequence={authority + 1}",
        subprotocols=["spell-auth", token],
    ) as websocket:
        _expect_resync_close(websocket, "sequence_ahead_of_authority", authority)

    object.__setattr__(client.app.state.settings, "websocket_replay_limit", 1)
    try:
        with client.websocket_connect(
            "/api/v1/driver-events/ws?after_sequence=0",
            subprotocols=["spell-auth", token],
        ) as websocket:
            _expect_resync_close(websocket, "replay_limit_exceeded", authority)
    finally:
        object.__setattr__(client.app.state.settings, "websocket_replay_limit", 1000)

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        row = session.get(DriverOutboxEvent, int(first["sequence"]))
        assert row is not None
        session.delete(row)
        session.commit()
    with client.websocket_connect(
        f"/api/v1/driver-events/ws?after_sequence={first['sequence']}",
        subprotocols=["spell-auth", token],
    ) as websocket:
        _expect_resync_close(websocket, "cursor_unavailable", authority)

    original_subscribe = client.app.state.hub.subscribe

    def subscribe_overflowed(topic: str):
        subscription = original_subscribe(topic)
        subscription.overflowed = True
        return subscription

    client.app.state.hub.subscribe = subscribe_overflowed
    try:
        with client.websocket_connect(
            f"/api/v1/driver-events/ws?after_sequence={authority}",
            subprotocols=["spell-auth", token],
        ) as websocket:
            _expect_resync_close(websocket, "client_queue_overflow", authority)
    finally:
        client.app.state.hub.subscribe = original_subscribe


def test_driver_websocket_closes_at_token_expiry(
    client: TestClient,
    auth_config: AuthConfig,
) -> None:
    short_lived_token = issue_local_dev_token(
        auth_config,
        subject="expiring-driver-stream-viewer",
        role="viewer",
        peer_host="127.0.0.1",
        lifetime_seconds=2,
    )

    started = time.monotonic()
    try:
        with client.websocket_connect(
            "/api/v1/driver-events/ws?after_sequence=0",
            subprotocols=["spell-auth", short_lived_token],
        ) as websocket:
            assert websocket.accepted_subprotocol == "spell-auth"
            while True:
                websocket.receive_json()
    except WebSocketDisconnect as closed:
        assert closed.code == 4401
        assert closed.reason == "websocket credentials expired"
    assert time.monotonic() - started < 3
