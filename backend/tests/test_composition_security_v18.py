"""Independent authority checks for the composed native/TC runtime."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from backend.models import Event, Execution
from backend.prompt_v17 import PROMPT_PROFILE
from backend.supervisor import ConflictError
from backend.telecommand_runtime_v11 import confirmation_prompt_id, prepare_send_request
from backend.tests.test_supervisor_composition_v18 import _fixture
from backend.tests.test_supervisor_v11_runtime import _result, _settled_yes_no_prompt


@pytest.mark.parametrize("state", [
    "ready", "starting", "paused", "pausing", "aborting", "aborted", "recovering",
    "recovery_required", "failed", "completed",
])
def test_current_worker_cannot_dispatch_new_command_from_nonexecuting_state(state: str) -> None:
    supervisor, sessions, _, execution_id = _fixture()
    handle = supervisor._workers[execution_id]
    with sessions() as session:
        execution = session.get(Execution, execution_id)
        request = prepare_send_request(execution_id, 0, execution.steps[0], execution.variables)[0]
        execution.state = state
        session.commit()
    rejected = False
    try:
        supervisor._handle_telecommand_request(execution_id, handle, request)
    except ConflictError:
        rejected = True
    if not rejected:
        # Drain the bounded simulator thread before reporting the failure.
        result = _result(handle.control)
    else:
        result = None
    with sessions() as session:
        events = [event.event_type for event in session.scalars(select(Event)).all()]
    assert rejected, f"state={state}, result={result['outcome'] if result else None}, events={events}"
    assert events == []


def test_durable_native_prompt_policy_cannot_authorize_a_command_confirmation() -> None:
    supervisor, sessions, procedure, execution_id = _fixture(
        'Send(command="CMDNAME", Confirm=True)\nPrompt("After")\n')
    unsigned = prepare_send_request(execution_id, 0, procedure.steps[0], {})[0]
    prompt_id = confirmation_prompt_id(execution_id, 0, unsigned["plan"]["plan_digest"])
    prompt, _ = _settled_yes_no_prompt(execution_id, 0,
        f"Confirm deterministic simulator telecommand plan {unsigned['plan']['plan_id']}", prompt_id=prompt_id)
    prompt.default_value = "NO"
    prompt.settings_snapshot = {"PROMPT_PROFILE": PROMPT_PROFILE}
    request = prepare_send_request(execution_id, 0, procedure.steps[0], {},
        confirmation={"prompt_id": prompt_id})[0]
    with sessions() as session:
        session.add(prompt)
        session.commit()
    with pytest.raises(ConflictError, match="native prompt policy"):
        supervisor._handle_telecommand_request(execution_id, supervisor._workers[execution_id], request)
    with sessions() as session:
        assert session.scalars(select(Event)).all() == []
