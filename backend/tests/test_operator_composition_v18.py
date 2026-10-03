from __future__ import annotations

import uuid

import pytest

from backend.operator_service import OperatorAuthorizationError, OperatorConflictError, OperatorValidationError
from backend.runtime_composition_v18 import telecommand_dependency_variables
from backend.synthetic_control import profile
from backend.tests.test_v11_operator_integration import _wait_for_open_prompt, _acquire_control


@pytest.fixture
def controlled(client, operator_headers, viewer_headers):
    source = "item = BuildTC('CMDNAME')\nquestion = 'Proceed?'\nanswer = 'NO'\nanswer = Prompt(question, YES_NO)\nif answer == 'YES':\n    Send(command=item)\n"
    procedure = client.app.state.catalog.validate_source(source, "operator-composition.spell.py")
    execution = client.app.state.supervisor.create_execution(procedure, actor="pytest-operator", role="operator",
        reason="native command authority", idempotency_key="operator-composition", automatic=True)
    snapshot, _ = _wait_for_open_prompt(client, execution.id, viewer_headers)
    headers, lease = _acquire_control(client, operator_headers, execution.id, snapshot, "composition")
    yield execution.id, snapshot, headers, lease


def _proof(headers, lease):
    return {"actor": "pytest-operator", "lease_id": lease["id"], "expected_lease_revision": lease["revision"],
            "control_fencing_token": lease["control_fencing_token"], "holder_session_id": headers["X-Spell-Session-Id"],
            "client_instance_key_id": headers["X-Spell-Client-Instance-Key-Id"]}


@pytest.mark.parametrize("name,value", [("question", "Different question"), ("answer", "YES"), ("item", "CMD1")])
def test_operator_cannot_edit_native_answer_question_or_built_item_dependencies(client, controlled, name, value):
    execution_id, snapshot, headers, lease = controlled
    with pytest.raises(OperatorAuthorizationError, match="telecommand dependencies"):
        client.app.state.operator_service.edit_inspection(execution_id, path="variables." + name, scope="LOCAL_VARIABLE",
            declared_type="STRING", value=value, expected_value_revision=snapshot["execution"]["revision"],
            expected_execution_revision=snapshot["execution"]["revision"], idempotency_key="edit-" + name,
            reason="prove dependency immutability", **_proof(headers, lease))
    execution = client.app.state.supervisor.get_execution(execution_id)
    assert execution.variables[name] == snapshot["execution"]["variables"][name]
    assert {"answer", "question", "item"} <= telecommand_dependency_variables(execution.steps)


def test_operator_backward_goto_rejected_before_native_command_reentry(client, controlled):
    execution_id, snapshot, headers, lease = controlled
    proof = _proof(headers, lease)
    proof["controller_lease_id"] = proof.pop("lease_id")
    with pytest.raises(OperatorValidationError, match="backward GOTO"):
        client.app.state.operator_service.accept_operator_command(execution_id, "GOTO", snapshot["execution"]["revision"],
            idempotency_key="backward-composition", role="operator", reason="prove no replay",
            target={"line": 2, "source_digest": snapshot["execution"]["procedure_hash"]}, **proof)


@pytest.mark.parametrize("patch", [{"control_fencing_token": 999}, {"session_id": "different-session"}, {"source_digest": "0" * 64}])
def test_composed_compatibility_control_requires_current_fencing_and_source(client, controlled, patch):
    execution_id, snapshot, headers, lease = controlled
    body = {"operation": "ABORT", "operation_id": str(uuid.uuid4()), "source_digest": snapshot["execution"]["procedure_hash"],
            "expected_execution_revision": snapshot["execution"]["revision"], "reason": "prove bounded composition control",
            "lease_id": lease["id"], "expected_lease_revision": lease["revision"], "control_fencing_token": lease["control_fencing_token"],
            "session_id": headers["X-Spell-Session-Id"], "client_instance_key_id": headers["X-Spell-Client-Instance-Key-Id"], **patch}
    response = client.post(f"/api/v1/legacy-control/executions/{execution_id}/operations", headers=headers, json=body)
    assert response.status_code in {403, 409}, response.text
    assert client.app.state.supervisor.get_execution(execution_id).state == "prompting"


def test_composed_control_extension_exposes_no_new_command_or_connectivity():
    contract = profile()
    assert "0.18" in contract["execution_ir_versions"]
    assert contract["extension_schema"] == "spell.v19.control-extension/1"
    assert contract["commands"] == {"RUN": "RUN", "STEP": "STEP", "PAUSE": "PAUSE", "ABORT": "ABORT", "RETURN_TO_READ_ONLY": "STOP"}
    assert contract["legacy_protocol_implemented"] is False
