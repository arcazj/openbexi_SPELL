from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.language_conformance_v18 import CATALOG_PROFILES
from backend.operator_models import OperatorPrompt
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution, fenced_prompt_request
from backend.tests.test_v11_operator_integration import _wait_for_open_prompt


@pytest.fixture
def procedures_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "procedures"


def _answer(client, operator_headers, viewer_headers, identity, value, ordinal):
    snapshot, _ = _wait_for_open_prompt(client, identity, viewer_headers)
    headers, body = fenced_prompt_request(client, operator_headers, identity, snapshot,
        value=value, reason="catalog procedure proof", idempotency_key=f"catalog-answer-{ordinal}")
    response = client.post(f"/api/v1/prompts/{snapshot['active_prompt']['id']}/responses", headers=headers, json=body)
    assert response.status_code == 202, response.text
    return snapshot["active_prompt"]["id"], headers, body


def _events(client, identity, headers):
    response = client.get(f"/api/v1/executions/{identity}/events", headers=headers)
    assert response.status_code == 200
    return response.json()["items"]


def test_exact_reviewed_catalog_profiles(client, viewer_headers):
    response = client.get("/api/v1/procedures", headers=viewer_headers)
    assert response.status_code == 200
    assert [(row["id"], row["version"]) for row in response.json()["items"]] == list(CATALOG_PROFILES)


@pytest.mark.parametrize("answer", ["YES", "NO"])
def test_bundled_native_branch_uses_actual_separate_command_confirmation(client, operator_headers, viewer_headers, answer):
    identity = create_execution(client, operator_headers, "native_command_branch_v18")
    first, headers, body = _answer(client, operator_headers, viewer_headers, identity, answer, 1)
    if answer == "YES":
        _, confirmation = _wait_for_open_prompt(client, identity, viewer_headers, excluding={first})
        response = client.post(f"/api/v1/prompts/{confirmation['id']}/responses", headers=headers,
            json={**body, "expected_prompt_revision": confirmation["revision"], "idempotency_key": "catalog-confirmation"})
        assert response.status_code == 202, response.text
        assert first != confirmation["id"]
    completed = wait_for_state(client, identity, viewer_headers, {"completed"})
    assert completed["execution"]["variables"]["answer"] == answer
    events = _events(client, identity, viewer_headers)
    requested = [row for row in events if row["event_type"] == "procedure.telecommand_requested"]
    results = [row for row in events if row["event_type"] == "procedure.telecommand_result"]
    assert len(requested) == len(results) == (1 if answer == "YES" else 0)
    if results:
        assert results[0]["payload"]["execution_succeeded"] is True
        assert results[0]["payload"]["checkpoint"]["provider_call_count"] == 5


def test_bundled_default_is_settled_by_server_without_a_command(client, operator_headers, viewer_headers):
    identity = create_execution(client, operator_headers, "native_command_default_v18")
    snapshot = wait_for_state(client, identity, viewer_headers, {"prompting"})
    prompt_id = snapshot["active_prompt"]["id"]
    with client.app.state.session_factory() as session:
        session.get(OperatorPrompt, prompt_id).response_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    client.app.state.operator_service.reconcile_prompt_timers()
    completed = wait_for_state(client, identity, viewer_headers, {"completed"})
    assert completed["execution"]["variables"]["answer"] == "NO"
    assert not any(row["event_type"].startswith("procedure.telecommand_") for row in _events(client, identity, viewer_headers))
    with client.app.state.session_factory() as session:
        prompt = session.get(OperatorPrompt, prompt_id)
        assert prompt.settlement_outcome == "ANSWERED" and prompt.settled_value == "NO"


def test_bundled_modes_execute_direct_item_and_load_only_distinctly(client, operator_headers, viewer_headers):
    identity = create_execution(client, operator_headers, "telecommand_modes_v18")
    wait_for_state(client, identity, viewer_headers, {"completed"})
    events = _events(client, identity, viewer_headers)
    requests = [row["payload"] for row in events if row["event_type"] == "procedure.telecommand_requested"]
    results = [row["payload"] for row in events if row["event_type"] == "procedure.telecommand_result"]
    assert [row["selector"]["kind"] for row in requests] == ["name", "item", "name"]
    assert requests[1]["plan"]["elements"][0]["command"]["arguments"][0]["value"] == 1.0
    assert [row["checkpoint"]["provider_call_count"] for row in results] == [5, 5, 2]
    assert [row["execution_succeeded"] for row in results] == [True, True, False]
    assert results[-1]["checkpoint"]["elements"][0]["disposition"] == "LOADED_ONLY"


def test_bundled_core_tutorial_has_typed_values_and_empty_display(client, operator_headers, viewer_headers):
    identity = create_execution(client, operator_headers, "tutorial_core_v18")
    snapshot = wait_for_state(client, identity, viewer_headers, {"completed"})
    variables = snapshot["execution"]["variables"]
    assert {key: variables[key] for key in ("total", "power", "mask", "label")} == {
        "total": 12, "power": 32, "mask": 3, "label": "core checks passed"}
    assert all(type(variables[key]) is int for key in ("total", "power", "mask"))
    events = _events(client, identity, viewer_headers)
    assert "" in [row["payload"]["message"] for row in events if row["event_type"] == "procedure.log"]
    assert not any(row["event_type"].startswith("procedure.telecommand_") for row in events)
