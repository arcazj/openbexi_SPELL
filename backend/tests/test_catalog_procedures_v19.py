from __future__ import annotations

from pathlib import Path
import pytest

from backend.language_conformance_v19 import CATALOG_PROFILES
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution
from backend.tests.test_catalog_procedures_v18 import _answer, _events
from backend.tests.test_observation_command_api_v19 import seeded
from backend.tests.test_prompt_telecommand_api_v18 import _counts
from backend.tests.test_v11_operator_integration import _wait_for_open_prompt, _install_dispatch_spy


@pytest.fixture
def procedures_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "procedures"


def test_exact_current_catalog_profiles(client, viewer_headers):
    response = client.get("/api/v1/procedures", headers=viewer_headers)
    assert response.status_code == 200
    assert [(row["id"], row["version"]) for row in response.json()["items"]] == list(CATALOG_PROFILES)


@pytest.mark.parametrize("answer", ["YES", "NO"])
def test_bundled_observation_requires_native_and_separate_command_decisions(client, operator_headers, viewer_headers, monkeypatch, answer):
    seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    identity = create_execution(client, operator_headers, "observation_command_v19")
    first, headers, body = _answer(client, operator_headers, viewer_headers, identity, answer, 1)
    if answer == "YES":
        snapshot, confirmation = _wait_for_open_prompt(client, identity, viewer_headers, excluding={first})
        assert confirmation["id"] != first
        response = client.post(f"/api/v1/prompts/{confirmation['id']}/responses", headers=headers,
            json={**body, "expected_prompt_revision": confirmation["revision"],
                  "idempotency_key": "observation-catalog-confirmation"})
        assert response.status_code == 202, response.text
    completed = wait_for_state(client, identity, viewer_headers, {"completed"})
    variables = completed["execution"]["variables"]
    assert variables["reading"] == 28.0 and type(variables["reading"]) is float
    assert variables["status"] == "TRUE" and variables["answer"] == answer
    assert len(calls) == (1 if answer == "YES" else 0)
    assert set(_counts(client, identity).values()) == {len(calls)}
    results = [row["payload"] for row in _events(client, identity, viewer_headers)
               if row["event_type"] == "procedure.observation_result"]
    assert [(row["operation"], row["outcome"]) for row in results] == [
        ("GET_TM", "OK"), ("VERIFY", "TRUE"), ("WAIT_FOR", "SATISFIED")]


def test_bundled_false_verification_overwrites_prior_true_and_requests_no_command(client, operator_headers, viewer_headers, monkeypatch):
    seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    identity = create_execution(client, operator_headers, "observation_decision_v19")
    completed = wait_for_state(client, identity, viewer_headers, {"completed"})
    assert completed["execution"]["variables"]["status"] == "FALSE"
    assert calls == [] and set(_counts(client, identity).values()) == {0}


def test_bundled_wait_timeout_prevents_a_following_command(client, operator_headers, viewer_headers, monkeypatch):
    seeded(client)
    calls = _install_dispatch_spy(monkeypatch)
    identity = create_execution(client, operator_headers, "observation_wait_v19")
    wait_for_state(client, identity, viewer_headers, {"failed"})
    results = [row["payload"] for row in _events(client, identity, viewer_headers)
               if row["event_type"] == "procedure.observation_result"]
    assert [(row["operation"], row["outcome"]) for row in results] == [("WAIT_FOR", "TIMED_OUT")]
    assert calls == [] and set(_counts(client, identity).values()) == {0}
