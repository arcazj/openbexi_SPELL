"""Nondefault inherited menu answers remain authoritative before the DSS broker."""
from pathlib import Path

import pytest
from sqlalchemy import select

from backend.models import Event, Execution
from backend.tests.conftest import wait_for_state
from backend.tests.test_api_execution import create_execution, fenced_prompt_request
from backend.tests.test_supervisor_v11_runtime import (
    _ordinary_fixture, _ordinary_step_commit, _settled_yes_no_prompt,
)
from backend.supervisor import ConflictError


RUNNER = Path(__file__).resolve().parents[2] / "procedures/language_reference_244.spell.py"


@pytest.fixture
def procedures_dir(tmp_path):
    directory = tmp_path / "procedures"
    directory.mkdir()
    (directory / RUNNER.name).write_bytes(RUNNER.read_bytes())
    return directory


@pytest.mark.parametrize("tamper", [None, "target", "bool-target", "unrelated", "settlement", "response", "outcome", "durable-bool", "durable-range", "unsettled"])
def test_nonzero_menu_checkpoint_requires_exact_durable_index_and_full_map(tamper):
    prior = {"ARGS": {}, "selected_index": 0, "example_number": 1, "result": "not run"}
    supervisor, sessions, procedure, execution_id = _ordinary_fixture(RUNNER.read_text(), current_step=3, variables=prior)
    step = procedure.steps[3]
    assert procedure.ir_version == "0.19" and step["response_target"] == "selected_index"
    prompt, resolution = _settled_yes_no_prompt(execution_id, 3, step["question"])
    prompt.prompt_type, prompt.input_kind, prompt.list_mode = "LIST", "LIST", "INDEX"
    prompt.options, prompt.default_value, prompt.settled_value = step["choices"], 0, 291
    resolution["response"] = 291
    variables = {**prior, "selected_index": 291}
    if tamper == "target": variables["selected_index"] = 292
    elif tamper == "bool-target": variables["selected_index"] = True
    elif tamper == "unrelated": variables["result"] = "forged"
    elif tamper == "settlement": resolution["settlement_id"] = "00000000-0000-0000-0000-000000000000"
    elif tamper == "response": resolution["response"] = 292
    elif tamper == "outcome": resolution["outcome"] = "CANCELLED"
    elif tamper == "durable-bool": prompt.settled_value = resolution["response"] = variables["selected_index"] = True
    elif tamper == "durable-range": prompt.settled_value = resolution["response"] = variables["selected_index"] = 344
    elif tamper == "unsettled": prompt.state = "OPEN"
    with sessions() as session:
        session.get(Execution, execution_id).ir_version = "0.19"
        session.add(prompt)
        session.commit()
    commit = _ordinary_step_commit(procedure, 3, variables, prompt_resolution=resolution)
    assert supervisor._commit_step(execution_id, 6, commit) is False
    if tamper:
        with pytest.raises(ConflictError): supervisor._commit_step(execution_id, 7, commit)
    else:
        assert supervisor._commit_step(execution_id, 7, commit)
        assert supervisor._commit_step(execution_id, 7, commit) is False
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        assert execution.variables == (prior if tamper else variables)
        assert execution.current_step == (3 if tamper else 4)
        events = list(session.scalars(select(Event)))
        assert sum(event.event_type == "prompt.answered" for event in events) == (0 if tamper else 1)
        assert not any(event.event_type in {"procedure.telecommand_requested", "procedure.language_case_requested"} for event in events)


def test_public_api_nonzero_runner_selection_reaches_protected_language_step_once(client, operator_headers, viewer_headers):
    # This API proof exercises the actual worker and durable prompt service;
    # physical DSS transport is qualified separately by the live delivery gate.
    execution_id = create_execution(client, operator_headers, "language_reference_244")
    snapshot = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    headers, body = fenced_prompt_request(client, operator_headers, execution_id, snapshot,
        value=291, idempotency_key="nonzero-menu", reason="authoritative nonzero menu")
    url = f"/api/v1/prompts/{snapshot['active_prompt']['id']}/responses"
    first = client.post(url, headers=headers, json=body)
    assert first.status_code == 202, first.text
    repeated = client.post(url, headers=headers, json=body)
    assert repeated.status_code == 202, repeated.text
    assert repeated.json()["prompt"]["settlement"]["id"] == first.json()["prompt"]["settlement"]["id"]
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"}, timeout=20)
    variables = completed["execution"]["variables"]
    assert type(variables["selected_index"]) is int and variables["selected_index"] == 291
    assert variables["example_number"] == 292
    with client.app.state.session_factory() as session:
        events = list(session.scalars(select(Event).where(Event.execution_id == execution_id)))
        assert sum(event.event_type == "prompt.answered" for event in events) == 1
        assert sum(event.event_type == "procedure.language_check_completed" for event in events) == 1
        assert not any(event.event_type == "worker.consumer_failed" for event in events)
