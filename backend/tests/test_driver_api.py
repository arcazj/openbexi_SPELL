from __future__ import annotations

import asyncio
import ast
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient

from backend.driver_domain import DEFAULT_DRIVER_PROFILE_ID


DRIVER_PATHS = {
    "/api/v1/drivers",
    "/api/v1/drivers/{driver_id}",
    "/api/v1/driver-contexts",
    "/api/v1/driver-contexts/{context_id}/generations/{context_generation}",
    "/api/v1/driver-bindings",
    "/api/v1/driver-bindings/{driver_binding_id}",
    "/api/v1/driver-operations/{operation_id}",
}
DRIVER_REST_HANDLERS = {
    "list_drivers",
    "get_driver",
    "list_driver_contexts",
    "get_driver_context_generation",
    "list_driver_bindings",
    "get_driver_binding",
    "get_driver_operation",
}


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(map(_keys, value.values())))
    if isinstance(value, list):
        return set().union(*(map(_keys, value))) if value else set()
    return set()


def test_driver_projection_is_authenticated_read_only_and_disabled_by_default(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    assert client.get("/api/v1/drivers").status_code == 401

    response = client.get("/api/v1/drivers", headers=viewer_headers)
    assert response.status_code == 200, response.text
    assert response.json()["next_cursor"] is None
    assert response.json()["items"] == [
        {
            "id": "local-synthetic-simulator",
            "server_profile_id": "local-synthetic",
            "logical_driver_id": "bundled-deterministic-simulator",
            "simulator": True,
            "enabled": False,
            "current_host_generation_id": None,
            "host_generation_number": None,
            "state": "DISABLED",
            "ready": False,
            "contract_package": "spell.driver.v1",
            "contract_version": None,
            "implementation_version": None,
            "configuration_schema_version": "spell.driver.host-profile/1",
            "configuration_digest": (
                "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
            ),
            "credential_epoch": 1,
            "capabilities": [],
            "capacity": {
                "max_contexts_per_host": 1,
                "contexts_in_use": 0,
                "max_attachments_per_context": 1,
                "max_lifecycle_operations_per_host": 8,
                "lifecycle_operations_per_host_in_use": 0,
                "max_lifecycle_operations_per_context": 8,
            },
            "last_observed_at": None,
            "revision": 0,
            "stale": False,
            "staleness": "UNKNOWN",
        }
    ]
    assert not {
        "driver_target",
        "target",
        "endpoint",
        "credential_reference",
        "ca_path",
        "cert_path",
        "key_path",
        "secret",
    }.intersection(_keys(response.json()))

    for path in ("/api/v1/driver-contexts", "/api/v1/driver-bindings"):
        empty = client.get(path, headers=viewer_headers)
        assert empty.status_code == 200
        assert empty.json() == {"items": [], "next_cursor": None}

    mutation = client.post(
        "/api/v1/drivers/local-synthetic-simulator",
        headers=viewer_headers,
        json={"enabled": True},
    )
    assert mutation.status_code == 405
    unchanged = client.get("/api/v1/drivers", headers=viewer_headers).json()
    assert unchanged["items"][0]["enabled"] is False


def test_driver_projection_has_exact_get_surface_and_bounded_queries(
    client: TestClient,
    viewer_headers: dict[str, str],
) -> None:
    schema = client.get("/openapi.json").json()
    assert DRIVER_PATHS.issubset(schema["paths"])
    for path in DRIVER_PATHS:
        assert set(schema["paths"][path]) == {"get"}

    for query in ("limit=0", "limit=101", "cursor=not-base64"):
        response = client.get(f"/api/v1/drivers?{query}", headers=viewer_headers)
        assert response.status_code == 422
        assert "not-base64" not in response.text

    oversized = "x" * 101
    response = client.get(f"/api/v1/drivers/{oversized}", headers=viewer_headers)
    assert response.status_code == 422
    assert oversized not in response.text

    missing = (
        "/api/v1/drivers/missing",
        "/api/v1/driver-contexts/missing/generations/1",
        "/api/v1/driver-bindings/missing",
        "/api/v1/driver-operations/missing",
    )
    for path in missing:
        response = client.get(path, headers=viewer_headers)
        assert response.status_code == 404


def test_app_relays_only_committed_driver_outbox_events_on_fixed_hub_topic(
    client: TestClient,
) -> None:
    repository = client.app.state.driver_repository
    hub = client.app.state.hub
    deliveries: list[tuple[str, dict[str, Any]]] = []
    original_publish = hub.publish
    hub.publish = lambda topic, event: deliveries.append((topic, event))
    try:
        repository.configure_profile_enabled(
            DEFAULT_DRIVER_PROFILE_ID,
            True,
            actor="pytest-runtime",
            correlation_id=str(UUID(int=500)),
        )
        pending = repository.pending_outbox()
        assert len(pending) == 1
        assert asyncio.run(client.app.state.driver_gateway._publish_outbox_once()) == 1
    finally:
        hub.publish = original_publish

    assert repository.pending_outbox() == []
    assert len(deliveries) == 1
    topic, event = deliveries[0]
    assert topic == "driver.lifecycle"
    assert event["sequence"] == pending[0]["sequence"]
    assert event["event_id"] == pending[0]["event_id"]
    assert event["event_type"] == "driver.profile_enabled"


def test_browser_facing_driver_handlers_have_no_synchronous_driver_call_path() -> None:
    tree = ast.parse(
        (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
    )
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert DRIVER_REST_HANDLERS <= set(functions)
    for name in DRIVER_REST_HANDLERS:
        handler = functions[name]
        assert isinstance(handler, ast.FunctionDef)
        referenced_names = {
            node.id for node in ast.walk(handler) if isinstance(node, ast.Name)
        }
        assert "driver_repository" in referenced_names
        assert "driver_gateway" not in referenced_names
        assert "DriverClient" not in referenced_names

    websocket = functions["websocket_driver_events"]
    assert isinstance(websocket, ast.AsyncFunctionDef)
    referenced_names = {
        node.id for node in ast.walk(websocket) if isinstance(node, ast.Name)
    }
    assert {"driver_repository", "hub"} <= referenced_names
    assert "driver_gateway" not in referenced_names
    assert "DriverClient" not in referenced_names
