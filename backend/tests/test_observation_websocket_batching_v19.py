"""Real websocket replay stays authoritative while redundant wake-ups are bounded."""
from contextlib import contextmanager
import asyncio
import threading
import time

import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from backend.auth import decode_token, issue_local_dev_token
from backend.observation_domain import GetTMMode
from backend.observation_models import ObservationOutboxEvent
from backend.observation_repository import OBSERVATION_STREAM
from backend.tests.test_observation_api import seed_observation, token
from backend.tests.test_observation_repository import sample


@pytest.fixture
def stream(client):
    # Isolate notification scheduling; the real API, repository, outbox and
    # EventHub remain in use. No production collector is involved in this test.
    client.portal.call(client.app.state.observation_runtime.close)
    generation, _ = seed_observation(client)
    repository = client.app.state.observation_repository
    client.app.state.hub.queue_size = 512
    return client, repository, generation, repository.stream_cursor("simulator")


@contextmanager
def connected(stream, headers, *, after=None, epoch=None, context="simulator"):
    client, _, _, cursor = stream
    with client.websocket_connect(
        "/api/v1/telemetry-events/ws",
        params={"context_id": context,
                "stream_epoch": epoch or cursor["stream_epoch"],
                "after_sequence": cursor["last_sequence"] if after is None else after},
        subprotocols=["spell-auth", token(headers)],
    ) as websocket:
        yield websocket


def burst(client, count):
    def publish():
        for index in range(count):
            # A forged envelope is only a wake-up, never a trusted data frame.
            client.app.state.hub.publish(OBSERVATION_STREAM, {
                "event_id": f"untrusted-{index}", "projection_sequence": "999999",
                "stream_epoch": "untrusted", "event_type": "forged",
            })
    client.portal.call(publish)


def append_sample(stream, sequence):
    _, repository, generation, _ = stream
    repository.ingest_sample(sample(generation, sequence=sequence,
        engineering=28.0 + sequence / 10, observation_number=28000 + sequence),
        mode=GetTMMode.NEXT)


def expected_since(stream, after):
    _, repository, _, cursor = stream
    return repository.replay("simulator", stream_epoch=cursor["stream_epoch"],
        after_sequence=int(after), limit=1000)["items"]


def expect_close(websocket, code, reason):
    with pytest.raises(WebSocketDisconnect) as closed:
        websocket.receive_json()
    assert (closed.value.code, closed.value.reason) == (code, reason)


@pytest.mark.parametrize("wakeups,reads", [(100, 1), (201, 3)])
def test_stale_wakeups_use_bounded_reads_without_emitting_untrusted_frames(
    stream, viewer_headers, monkeypatch, wakeups, reads,
):
    client, repository, _, cursor = stream
    before = expected_since(stream, 0)
    original, calls = repository.replay, []

    def replay(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    with connected(stream, viewer_headers) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        monkeypatch.setattr(repository, "replay", replay)
        burst(client, wakeups)
        keepalive = websocket.receive_json()
        assert keepalive["event_type"] == "stream.keepalive"
        assert keepalive["last_sequence"] == cursor["last_sequence"]
        assert len(calls) == reads
        assert all(args == ("simulator",) and kwargs == {
            "stream_epoch": cursor["stream_epoch"],
            "after_sequence": int(cursor["last_sequence"]), "limit": 1001,
        } for args, kwargs in calls)
    assert original("simulator", stream_epoch=cursor["stream_epoch"],
        after_sequence=0, limit=1000)["items"] == before


def test_concurrent_commit_after_read_is_delivered_once_in_committed_order(
    stream, viewer_headers, monkeypatch,
):
    client, repository, _, cursor = stream
    original = repository.replay
    captured, release = threading.Event(), threading.Event()
    calls = []

    def replay(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(kwargs["after_sequence"])
        if len(calls) == 1:
            captured.set()
            assert release.wait(5), "test did not release the captured read"
        return result

    with connected(stream, viewer_headers) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        monkeypatch.setattr(repository, "replay", replay)
        try:
            burst(client, 100)
            assert captured.wait(3)
            append_sample(stream, 2)
            append_sample(stream, 3)
            expected = original("simulator", stream_epoch=cursor["stream_epoch"],
                after_sequence=int(cursor["last_sequence"]), limit=1000)["items"]
            assert expected
            burst(client, 100)
        finally:
            release.set()
        actual = [websocket.receive_json() for _ in expected]
        assert actual == expected
        assert [int(row["projection_sequence"]) for row in actual] == list(range(
            int(cursor["last_sequence"]) + 1,
            int(cursor["last_sequence"]) + len(actual) + 1))
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        assert calls == [int(cursor["last_sequence"])] * 2


def test_real_queue_overflow_is_not_hidden_by_draining_wakeups(
    stream, viewer_headers,
):
    client, _, _, cursor = stream
    client.app.state.hub.queue_size = 64
    with connected(stream, viewer_headers) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        burst(client, 100)
        frame = websocket.receive_json()
        assert frame["event_type"] == "stream.resync_required"
        assert frame["data"] == {
            "reason": "CLIENT_QUEUE_OVERFLOW",
            "authoritative_stream_epoch": cursor["stream_epoch"],
            "authoritative_sequence": cursor["last_sequence"],
        }
        expect_close(websocket, 4409, "snapshot resynchronization required")


def test_all_cursor_and_replay_reads_allow_event_loop_progress(
    stream, viewer_headers, monkeypatch,
):
    client, repository, _, _ = stream
    async def event_loop():
        return asyncio.get_running_loop(), threading.get_ident()
    loop, loop_thread = client.portal.call(event_loop)
    calls = []

    def observe(name, original):
        def read(*args, **kwargs):
            progressed = threading.Event()
            loop.call_soon_threadsafe(progressed.set)
            assert threading.get_ident() != loop_thread
            assert progressed.wait(3), "repository read blocked the API event loop"
            calls.append(name)
            return original(*args, **kwargs)
        return read

    monkeypatch.setattr(repository, "stream_cursor", observe("cursor", repository.stream_cursor))
    monkeypatch.setattr(repository, "replay", observe("replay", repository.replay))
    with connected(stream, viewer_headers) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        assert calls == ["cursor", "cursor", "replay", "cursor"]
        burst(client, 100)
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        assert calls[4:] == ["cursor", "replay", "cursor"]


def test_epoch_rotation_during_offloaded_read_requires_resync(
    stream, viewer_headers, monkeypatch,
):
    client, repository, _, _ = stream
    original = repository.replay
    entered, release = threading.Event(), threading.Event()

    def replay(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    with connected(stream, viewer_headers) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        monkeypatch.setattr(repository, "replay", replay)
        try:
            burst(client, 100)
            assert entered.wait(3)
            current = repository.rotate_stream_epoch("simulator")
        finally:
            release.set()
        frame = websocket.receive_json()
        assert frame["event_type"] == "stream.resync_required"
        assert frame["data"] == {
            "reason": "STREAM_EPOCH_CHANGED",
            "authoritative_stream_epoch": current["stream_epoch"],
            "authoritative_sequence": current["last_sequence"],
        }
        expect_close(websocket, 4409, "snapshot resynchronization required")
        assert current["stream_epoch"] != stream[3]["stream_epoch"]


@pytest.mark.parametrize("boundary", ["initial", "replay", "keepalive", "overflow"])
def test_token_expiry_during_offloaded_read_emits_no_late_frame(
    stream, auth_config, monkeypatch, boundary,
):
    client, repository, _, _ = stream
    access_token = issue_local_dev_token(auth_config, subject="expiring-observation",
        role="viewer", peer_host="127.0.0.1", lifetime_seconds=2)
    expires = decode_token(auth_config, access_token).expires_at
    headers = {"Authorization": f"Bearer {access_token}"}

    def finish_after_expiry(original):
        def read(*args, **kwargs):
            result = original(*args, **kwargs)
            # The wait deliberately crosses the actual signed credential's
            # expiry, not a production timeout or freshness-policy change.
            threading.Event().wait(max(0, expires - time.time()) + 0.02)
            return result
        return read

    if boundary == "initial":
        monkeypatch.setattr(repository, "stream_cursor", finish_after_expiry(repository.stream_cursor))
        with pytest.raises(WebSocketDisconnect) as closed:
            with connected(stream, headers):
                raise AssertionError("expired handshake was accepted")
        assert closed.value.code == 4401
        return
    with connected(stream, headers) as websocket:
        assert websocket.receive_json()["event_type"] == "stream.keepalive"
        if boundary == "replay":
            append_sample(stream, 2)
            monkeypatch.setattr(repository, "replay", finish_after_expiry(repository.replay))
            burst(client, 100)
        else:
            monkeypatch.setattr(repository, "stream_cursor", finish_after_expiry(repository.stream_cursor))
            if boundary == "overflow":
                burst(client, 600)
        expect_close(websocket, 4401, "websocket credentials expired")


@pytest.mark.parametrize("reason", ["SEQUENCE_AHEAD_OF_AUTHORITY", "CURSOR_UNAVAILABLE", "REPLAY_LIMIT_EXCEEDED"])
def test_authoritative_cursor_and_replay_bounds_are_preserved(
    stream, viewer_headers, reason,
):
    client, repository, _, cursor = stream
    after = 0
    if reason == "SEQUENCE_AHEAD_OF_AUTHORITY":
        after = int(cursor["last_sequence"]) + 1
    elif reason == "CURSOR_UNAVAILABLE":
        with client.app.state.session_factory() as session:
            row = session.scalar(select(ObservationOutboxEvent).where(
                ObservationOutboxEvent.stream_epoch == cursor["stream_epoch"],
                ObservationOutboxEvent.projection_sequence == 1))
            assert row is not None
            session.delete(row)
            session.commit()
    else:
        object.__setattr__(client.app.state.settings, "websocket_replay_limit", 1)
    with connected(stream, viewer_headers, after=after) as websocket:
        frame = websocket.receive_json()
        assert frame["event_type"] == "stream.resync_required"
        assert frame["data"]["reason"] == reason
        assert frame["data"]["authoritative_stream_epoch"] == cursor["stream_epoch"]
        expect_close(websocket, 4409, "snapshot resynchronization required")


def test_context_authority_is_not_bypassed_by_offloaded_reads(stream, viewer_headers):
    with pytest.raises(WebSocketDisconnect) as closed:
        with connected(stream, viewer_headers, context="missing-context"):
            raise AssertionError("unknown context was accepted")
    assert (closed.value.code, closed.value.reason) == (4404, "observation stream not found")
