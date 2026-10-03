"""V19-RUNTIME-001: existing controller authority cannot bypass observations."""
from __future__ import annotations

import uuid

import pytest

from backend.operator_service import OperatorAuthorizationError, OperatorValidationError, OperatorConflictError
from backend.operator_models import OperatorCommand
from backend.runtime_composition_v19 import telecommand_dependency_variables
from backend.synthetic_control import profile
from backend.serialization import execution_dict
from backend.models import Execution
from backend.tests.test_observation_command_api_v19 import READ, seeded
from backend.tests.test_operator_composition_v18 import _proof
from backend.tests.test_v11_operator_integration import _acquire_control, _wait_for_open_prompt


@pytest.fixture
def controlled(client, operator_headers, viewer_headers):
    seeded(client)
    source = READ + "question = 'Use this reading?'\nanswer = Prompt(question, YES_NO)\nif reading >= 27.0 and answer == 'YES':\n    Send(command='CMDNAME')\n"
    procedure = client.app.state.catalog.validate_source(source, "v19-operator.spell.py")
    execution = client.app.state.supervisor.create_execution(procedure, actor="pytest-operator", role="operator",
        reason="observation authority", idempotency_key="v19-operator", automatic=True)
    snapshot, _ = _wait_for_open_prompt(client, execution.id, viewer_headers)
    headers, lease = _acquire_control(client, operator_headers, execution.id, snapshot, "v19-control")
    return execution.id, snapshot, headers, lease


@pytest.mark.parametrize("name,value,declared", [("reading", 99.0, "FINITE_DECIMAL"), ("question", "Other?", "STRING"), ("answer", "YES", "STRING")])
def test_observation_and_native_command_dependencies_are_not_inspection_editable(client, controlled, name, value, declared):
    execution_id, snapshot, headers, lease = controlled
    with pytest.raises(OperatorAuthorizationError, match="telecommand dependencies"):
        client.app.state.operator_service.edit_inspection(execution_id, path="variables." + name, scope="LOCAL_VARIABLE",
            declared_type=declared, value=value, expected_value_revision=snapshot["execution"]["revision"],
            expected_execution_revision=snapshot["execution"]["revision"], idempotency_key="v19-edit-" + name,
            reason="prove protected observation inputs", **_proof(headers, lease))
    execution = client.app.state.supervisor.get_execution(execution_id)
    assert {"reading", "question", "answer"} <= telecommand_dependency_variables(execution.steps)
    assert execution.variables == snapshot["execution"]["variables"]


@pytest.mark.parametrize("command,line", [("SKIP", None), ("GOTO", 2), ("GOTO", 6)])
def test_operator_cannot_skip_or_jump_in_observation_profile(client, controlled, command, line):
    execution_id, snapshot, headers, lease = controlled
    proof = _proof(headers, lease)
    proof["controller_lease_id"] = proof.pop("lease_id")
    target = {} if line is None else {"line": line, "source_digest": snapshot["execution"]["procedure_hash"]}
    with pytest.raises(OperatorValidationError, match="OBSERVATION_NAVIGATION_FORBIDDEN"):
        client.app.state.operator_service.accept_operator_command(execution_id, command, snapshot["execution"]["revision"],
            idempotency_key="v19-navigation-" + str(line), role="operator", reason="no observation bypass", target=target, **proof)
    assert client.app.state.supervisor.get_execution(execution_id).current_step == snapshot["execution"]["current_step"]


@pytest.mark.parametrize("command", ["SKIP", "GOTO"])
def test_reserved_navigation_cannot_bypass_admission_on_settlement(client, controlled, command):
    execution_id, snapshot, _, _ = controlled
    index = snapshot["execution"]["current_step"]
    with client.app.state.session_factory() as session:
        reserved = OperatorCommand(execution_id=execution_id, command_type=command, state="APPLYING",
            idempotency_key="forged-navigation", request_digest="a" * 64, expected_execution_revision=snapshot["execution"]["revision"],
            safe_point="REQUIRED", actor="pytest-operator", role="operator", reason="settlement boundary proof",
            correlation_id=str(uuid.uuid4()), target={"target_step": index + 1})
        session.add(reserved)
        session.commit()
        command_id = reserved.id
    with pytest.raises(OperatorConflictError, match="OBSERVATION_NAVIGATION_FORBIDDEN"):
        client.app.state.operator_service.settle_operator_command_application(command_id, current_step=index + 1)
    assert client.app.state.supervisor.get_execution(execution_id).current_step == index
    with client.app.state.session_factory() as session:
        assert session.get(OperatorCommand, command_id).state == "APPLYING"


@pytest.mark.parametrize("patch", [{"control_fencing_token": 999}, {"session_id": "wrong-session"}, {"source_digest": "0" * 64}])
def test_observation_control_requires_original_source_and_current_lease(client, controlled, patch):
    execution_id, snapshot, headers, lease = controlled
    body = {"operation": "ABORT", "operation_id": str(uuid.uuid4()), "source_digest": snapshot["execution"]["procedure_hash"],
        "expected_execution_revision": snapshot["execution"]["revision"], "reason": "control proof",
        "lease_id": lease["id"], "expected_lease_revision": lease["revision"], "control_fencing_token": lease["control_fencing_token"],
        "session_id": headers["X-Spell-Session-Id"], "client_instance_key_id": headers["X-Spell-Client-Instance-Key-Id"], **patch}
    response = client.post(f"/api/v1/legacy-control/executions/{execution_id}/operations", headers=headers, json=body)
    assert response.status_code in {403, 409}, response.text
    assert client.app.state.supervisor.get_execution(execution_id).state == "prompting"


def test_observation_control_extension_adds_no_command_or_external_authority():
    contract = profile()
    assert contract["execution_ir_versions"][-1] == "0.19"
    assert contract["extension_schema"] == "spell.v19.control-extension/1"
    assert contract["commands"] == {"RUN": "RUN", "STEP": "STEP", "PAUSE": "PAUSE", "ABORT": "ABORT", "RETURN_TO_READ_ONLY": "STOP"}
    assert contract["legacy_protocol_implemented"] is False


@pytest.mark.parametrize("state,expected", [
    ("paused", {"run", "step", "step_over", "abort", "stop", "background"}),
    ("waiting", {"pause", "abort", "stop", "background"}),
    ("prompting", {"pause", "abort", "stop"}),
    ("completed", {"reload"}), ("aborting", set()),
])
def test_serialized_v19_actions_follow_server_matrix_and_exclude_navigation(state, expected):
    execution = Execution(id="actions", procedure_id="actions", procedure_name="Actions", procedure_hash="a" * 64,
        ir_version="0.19", context_id="simulator", state=state, steps=[], variables={}, next_sequence=1)
    assert set(execution_dict(execution)["allowed_actions"]) == expected
    execution.ir_version = "0.18"
    assert "allowed_actions" not in execution_dict(execution)
