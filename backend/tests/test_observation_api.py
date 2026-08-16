from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from starlette.websockets import WebSocketDisconnect

from backend.driver_domain import GenerationTuple
from backend.driver_models import DriverOutboxEvent
from backend.driver_repository import DEFAULT_PROFILE_DIGEST, DEFAULT_PROFILE_ID
from backend.observation_domain import (
    ClockSource,
    DriverTimeObservation,
    GetTMMode,
    Quality,
    Validity,
)
from backend.observation_models import ObservationOutboxEvent
from backend.tests.test_observation_repository import (
    BASE_NS,
    CATALOG_DIGEST,
    CONTEXT_DIGEST,
    capabilities,
    sample,
)


def token(headers: dict[str, str]) -> str:
    return headers["Authorization"].removeprefix("Bearer ")


def seed_observation(client: TestClient) -> tuple[GenerationTuple, int]:
    drivers = client.app.state.driver_repository
    session_factory = client.app.state.session_factory
    host_id = str(UUID(int=7501))
    context_generation_id = str(UUID(int=7502))
    drivers.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="pytest-observation-api",
        correlation_id=str(UUID(int=7510)),
    )
    drivers.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        contract_version="1.0",
        implementation_version="0.7.0-test",
        capabilities=capabilities(),
        actor="pytest-observation-api",
        correlation_id=str(UUID(int=7511)),
    )
    drivers.record_host_state(
        host_id,
        "READY",
        expected_revision=0,
        actor="pytest-observation-api",
        correlation_id=str(UUID(int=7512)),
        observed_at=datetime.now(timezone.utc),
    )
    context = drivers.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id="simulator",
        context_generation_id=context_generation_id,
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest=CONTEXT_DIGEST,
        actor="pytest-observation-api",
        correlation_id=str(UUID(int=7513)),
    )
    drivers.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest-observation-api",
        correlation_id=str(UUID(int=7514)),
        observed_at=datetime.now(timezone.utc),
    )
    with session_factory() as session:
        lifecycle_event_count = int(
            session.scalar(select(func.count()).select_from(DriverOutboxEvent))
            or 0
        )
    generations = GenerationTuple(
        server_profile_id="local-synthetic",
        driver_host_generation=host_id,
        host_profile_digest=DEFAULT_PROFILE_DIGEST,
        context_id="simulator",
        context_generation=context_generation_id,
        context_binding_digest=CONTEXT_DIGEST,
    )
    observations = client.app.state.observation_repository
    observations.record_time(
        DriverTimeObservation(
            observation_id=str(UUID(int=7520)),
            generations=GenerationTuple(
                server_profile_id=generations.server_profile_id,
                driver_host_generation=generations.driver_host_generation,
                host_profile_digest=generations.host_profile_digest,
            ),
            time_unix_ns=BASE_NS,
            acquired_at_unix_ns=BASE_NS,
            clock_source=ClockSource.SIMULATOR,
            provenance="bundled-deterministic-simulator-clock",
            uncertainty_ns=1_000_000,
            quality=Quality.GOOD,
            validity=Validity.VALID,
        ),
        context_generation_id=context_generation_id,
    )
    observations.ingest_sample(
        sample(
            generations,
            sequence=1,
            engineering=28.0,
            observation_number=7521,
        ),
        mode=GetTMMode.CURRENT,
        resynchronized=True,
    )
    return generations, lifecycle_event_count


def test_observation_read_apis_are_typed_authenticated_and_stream_isolated(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    generations, lifecycle_before = seed_observation(client)
    driver_time = client.get("/api/v1/driver-time", headers=viewer_headers)
    assert driver_time.status_code == 200
    assert driver_time.json()["driver_time"]["context_generation_id"] == (
        generations.context_generation
    )
    assert isinstance(driver_time.json()["driver_time"]["time_unix_ns"], str)

    response = client.get("/api/v1/telemetry/snapshot", headers=viewer_headers)
    assert response.status_code == 200
    snapshot = response.json()
    assert snapshot["schema_version"] == "spell.driver.observation.snapshot/1"
    assert snapshot["stream"] == "driver.observation"
    assert snapshot["context_id"] == "simulator"
    assert snapshot["synchronization_state"] == "COMPLETE"
    assert isinstance(snapshot["through_sequence"], str)
    assert snapshot["items"][0]["engineering_value"] == {
        "type": "FINITE_DOUBLE",
        "value": 28.0,
    }
    assert snapshot["items"][0]["alarm"]["boolean_value"] is False

    limits = client.get(
        "/api/v1/telemetry/TM.POWER.BUS_VOLTAGE/limits",
        params={"catalog_digest": CATALOG_DIGEST},
        headers=viewer_headers,
    )
    assert limits.status_code == 200
    assert limits.json()["limits"]["bands"]["HARD_HIGH"]["threshold"]["value"] == 32.0
    alarm = client.get(
        "/api/v1/telemetry/TM.POWER.BUS_VOLTAGE/alarm",
        headers=viewer_headers,
    )
    assert alarm.status_code == 200
    assert alarm.json()["alarm"]["state"] == "NOT_ALARMED"

    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == (
            lifecycle_before
        )

    unauthenticated = client.get("/api/v1/telemetry/snapshot")
    assert unauthenticated.status_code == 401


def test_observation_catalog_reads_preserve_safe_outcomes_and_authentication(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    identity_response = client.get(
        "/api/v1/observation-catalog", headers=viewer_headers
    )
    assert identity_response.status_code == 200
    identity = identity_response.json()
    assert identity["mutability"] == "READ_ONLY"

    pins = {
        "catalog_id": identity["catalog_id"],
        "catalog_digest": identity["catalog_digest"],
    }
    resource = client.get(
        "/api/v1/resources/SIMULATOR.MODE",
        params={**pins, "resource_type": "CONFIGURATION"},
        headers=viewer_headers,
    )
    assert resource.status_code == 200
    assert resource.json()["outcome"] == "OK"

    read_limits = client.get(
        "/api/v1/observation-limits/TM.POWER.BUS_VOLTAGE",
        params=pins,
        headers=viewer_headers,
    )
    assert read_limits.status_code == 200
    assert read_limits.json()["outcome"] == "OK"
    durable_limits = client.get(
        "/api/v1/telemetry/TM.POWER.BUS_VOLTAGE/limits",
        params={"catalog_digest": CATALOG_DIGEST},
        headers=viewer_headers,
    )
    assert read_limits.json()["entries"][0]["limit_set_id"] == (
        durable_limits.json()["limits"]["limit_set_id"]
    )

    bounded = client.get(
        "/api/v1/memory-lookup",
        params={
            **pins,
            "memory_region_id": "SIMULATOR.TELEMETRY",
            "maximum_entries": 129,
        },
        headers=viewer_headers,
    )
    assert bounded.status_code == 200
    assert bounded.json()["outcome"] == "INVALID_ARGUMENT"
    assert bounded.json()["reason"] == "INVALID_MAXIMUM_ENTRIES"

    ambiguous = client.get(
        "/api/v1/tmtc-lookup",
        params={
            **pins,
            "direction": "TM",
            "item_id": "TM.POWER.SAFE_MODE",
            "qualified_name": "SIM.POWER.SAFE_MODE",
            "maximum_entries": 1,
        },
        headers=viewer_headers,
    )
    assert ambiguous.status_code == 200
    assert ambiguous.json()["outcome"] == "INVALID_ARGUMENT"

    unauthenticated = client.get("/api/v1/observation-catalog")
    assert unauthenticated.status_code == 401


def test_observation_websocket_replays_strings_and_requires_epoch_resync(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    seed_observation(client)
    snapshot = client.get(
        "/api/v1/telemetry/snapshot", headers=viewer_headers
    ).json()
    stream_epoch = snapshot["stream_epoch"]
    expected_count = int(snapshot["through_sequence"])
    access_token = token(viewer_headers)

    with client.websocket_connect(
        "/api/v1/telemetry-events/ws",
        params={
            "context_id": "simulator",
            "stream_epoch": stream_epoch,
            "after_sequence": 0,
        },
        subprotocols=["spell-auth", access_token],
    ) as websocket:
        events = [websocket.receive_json() for _ in range(expected_count)]
        assert [item["projection_sequence"] for item in events] == [
            str(value) for value in range(1, expected_count + 1)
        ]
        assert all(item["stream"] == "driver.observation" for item in events)
        keepalive = websocket.receive_json()
        assert keepalive["event_type"] == "stream.keepalive"
        assert keepalive["last_sequence"] == str(expected_count)

    with client.websocket_connect(
        "/api/v1/telemetry-events/ws",
        params={
            "context_id": "simulator",
            "stream_epoch": str(UUID(int=9999)),
            "after_sequence": 0,
        },
        subprotocols=["spell-auth", access_token],
    ) as websocket:
        frame = websocket.receive_json()
        assert frame["event_type"] == "stream.resync_required"
        assert frame["data"] == {
            "reason": "STREAM_EPOCH_CHANGED",
            "authoritative_stream_epoch": stream_epoch,
            "authoritative_sequence": str(expected_count),
        }
        with pytest.raises(WebSocketDisconnect) as closed:
            websocket.receive_json()
        assert closed.value.code == 4409

    with pytest.raises(WebSocketDisconnect) as rejected:
        with client.websocket_connect(
            "/api/v1/telemetry-events/ws",
            params={
                "context_id": "simulator",
                "stream_epoch": stream_epoch,
            },
            subprotocols=["spell-auth", "invalid"],
        ):
            raise AssertionError("invalid telemetry websocket token was accepted")
    assert rejected.value.code == 4401


def test_observation_websocket_forces_resync_on_client_queue_overflow(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    seed_observation(client)
    snapshot = client.get(
        "/api/v1/telemetry/snapshot", headers=viewer_headers
    ).json()
    authority = snapshot["through_sequence"]
    stream_epoch = snapshot["stream_epoch"]
    original_subscribe = client.app.state.hub.subscribe

    def subscribe_overflowed(topic: str):
        subscription = original_subscribe(topic)
        subscription.overflowed = True
        return subscription

    client.app.state.hub.subscribe = subscribe_overflowed
    try:
        with client.websocket_connect(
            "/api/v1/telemetry-events/ws",
            params={
                "context_id": "simulator",
                "stream_epoch": stream_epoch,
                "after_sequence": authority,
            },
            subprotocols=["spell-auth", token(viewer_headers)],
        ) as websocket:
            frame = websocket.receive_json()
            assert frame == {
                "schema_version": "spell.driver.observation.event/1",
                "stream": "driver.observation",
                "event_type": "stream.resync_required",
                "stream_epoch": stream_epoch,
                "data": {
                    "reason": "CLIENT_QUEUE_OVERFLOW",
                    "authoritative_stream_epoch": stream_epoch,
                    "authoritative_sequence": authority,
                },
            }
            with pytest.raises(WebSocketDisconnect) as closed:
                websocket.receive_json()
            assert closed.value.code == 4409
    finally:
        client.app.state.hub.subscribe = original_subscribe


def test_observation_read_load_is_bounded_authorized_and_nonmutating(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    seed_observation(client)
    repository = client.app.state.observation_repository
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        events_before = int(
            session.scalar(select(func.count()).select_from(ObservationOutboxEvent))
            or 0
        )

    def read(index: int) -> tuple[str, str]:
        operation = index % 4
        if operation == 0:
            result = repository.snapshot("simulator")
            return "snapshot", result["through_sequence"]
        if operation == 1:
            result = repository.driver_time("simulator")
            return "time", result["quality"]
        if operation == 2:
            result = repository.get_limits("TM.POWER.BUS_VOLTAGE", CATALOG_DIGEST)
            return "limits", result["limit_revision"]
        result = repository.is_alarmed("simulator", "TM.POWER.BUS_VOLTAGE")
        return "alarm", result["state"]

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(read, range(128)))

    assert len(results) == 128
    assert set(results) == {
        ("snapshot", str(events_before)),
        ("time", "GOOD"),
        ("limits", "v07-r1"),
        ("alarm", "NOT_ALARMED"),
    }
    with session_factory() as session:
        assert int(
            session.scalar(select(func.count()).select_from(ObservationOutboxEvent))
            or 0
        ) == events_before

    for path in (
        "/api/v1/driver-time?context_id=simulator",
        "/api/v1/telemetry/snapshot?context_id=simulator",
        "/api/v1/telemetry/TM.POWER.BUS_VOLTAGE/alarm?context_id=simulator",
    ):
        response = client.get(path)
        assert response.status_code == 401
        assert "bundled-deterministic-simulator" not in response.text
