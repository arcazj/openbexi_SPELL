from __future__ import annotations

import pytest

from backend.procedure_parser import ProcedureCatalog
from backend.telecommand_runtime_v11 import (
    ITEM_PREFIX,
    confirmation_prompt_id,
    execute_preflight,
    failure_prompt_id,
    prepare_send_request,
    uncertain_replay_result,
    validate_send_request,
)
from backend.telecommand_v11 import (
    DeterministicScriptedProvider,
    ElementStage,
    ProviderStep,
)

from .test_worker_v06 import _next, _start_worker


def _procedure(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "worker-v11.spell.py"
    )


def _request(message: dict) -> dict:
    return {
        key: value
        for key, value in message.items()
        if key not in {"kind", "generation"}
    }


def _transport_rejected_result(request, service, preflight):
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(
                ElementStage.TRANSPORT,
                "REJECTED",
                preflight.plan.elements[0].element_id,
            )
        ]
    )
    return execute_preflight(
        request,
        service,
        preflight,
        confirmation_actor=(
            "test-operator" if preflight.confirmation_required else None
        ),
        provider=provider,
    )


@pytest.mark.parametrize(
    "source, selector_kind",
    [
        ("Send(command='CMDNAME')\n", "name"),
        ("tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n", "item"),
    ],
)
def test_worker_executes_both_example_60_forms_through_supervisor_boundary(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    selector_kind: str,
) -> None:
    execution_id = f"worker-example-60-{selector_kind}"
    procedure = _procedure(source)
    thread, control, output = _start_worker(
        monkeypatch, procedure, execution_id=execution_id
    )
    requested, seen = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    commits = [item for item in seen if item.get("kind") == "step_commit"]
    variables = commits[-1]["variables"] if commits else {}
    if selector_kind == "item":
        assert variables["tc_item"].startswith(ITEM_PREFIX)
    request, service, preflight = validate_send_request(
        execution_id,
        requested["step_index"],
        procedure.steps[requested["step_index"]],
        variables,
        _request(requested),
    )
    assert request["selector"]["kind"] == selector_kind
    result = execute_preflight(request, service, preflight)
    control.put({"type": "telecommand_result", **result})

    terminal, after = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)
    all_messages = [*seen, *after]

    assert not thread.is_alive()
    assert terminal["state"] == "completed"
    settlement = next(
        effect
        for message in all_messages
        if message.get("kind") == "step_commit"
        for effect in message.get("effects", [])
        if effect.get("event_type") == "procedure.telecommand_settled"
    )
    assert settlement["payload"]["outcome"] == "SETTLED"
    assert settlement["payload"]["checkpoint"]["elements"][0][
        "onboard_execution"
    ] == "SUCCEEDED"


def test_worker_requires_durable_confirmation_before_requesting_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = "worker-v11-confirm"
    procedure = _procedure("Send(command='CMDNAME', Confirm=True)\n")
    thread, control, output = _start_worker(
        monkeypatch, procedure, execution_id=execution_id
    )
    opened, before = _next(output, lambda item: item.get("kind") == "prompt_opened")
    assert opened["prompt_type"] == "YES_NO"
    assert not any(item.get("kind") == "telecommand_requested" for item in before)
    control.put(
        {
            "type": "prompt_settlement",
            "prompt_id": opened["prompt_id"],
            "settlement_id": "confirmation-settlement",
            "outcome": "ANSWERED",
            "value": "YES",
        }
    )
    requested, during = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        execution_id,
        requested["step_index"],
        procedure.steps[requested["step_index"]],
        {},
        _request(requested),
    )
    assert request["confirmation"] == {
        "prompt_id": opened["prompt_id"],
    }
    result = execute_preflight(
        request,
        service,
        preflight,
        confirmation_actor="test-operator",
    )
    control.put({"type": "telecommand_result", **result})
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert terminal["state"] == "completed"
    assert any(item.get("state") == "prompting" for item in [*before, *during])


def test_worker_fails_closed_on_uncertain_replay_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = "worker-v11-uncertain"
    procedure = _procedure("Send(command='CMDNAME')\n")
    thread, control, output = _start_worker(
        monkeypatch, procedure, execution_id=execution_id
    )
    requested, seen = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        execution_id,
        0,
        procedure.steps[0],
        {},
        _request(requested),
    )
    result = uncertain_replay_result(request, service, preflight)
    control.put({"type": "telecommand_result", **result})
    terminal, after = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert terminal["state"] == "failed"
    assert any(
        item.get("event_type") == "procedure.error"
        and "TC_OPERATION_NOT_SUCCESSFUL" in item["payload"]["error"]
        for item in [*seen, *after]
    )


def test_worker_reuses_durable_confirmation_settlement_after_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = "worker-v11-confirm-recovery"
    procedure = _procedure("Send(command='CMDNAME', Confirm=True)\n")
    _, _, initial_preflight = prepare_send_request(
        execution_id, 0, procedure.steps[0], {}
    )
    prompt_id = confirmation_prompt_id(
        execution_id, 0, initial_preflight.plan.plan_digest
    )
    settlement = {
        "prompt_id": prompt_id,
        "settlement_id": "recovered-confirmation-settlement",
        "outcome": "ANSWERED",
        "response": "YES",
        "command_id": None,
    }
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        execution_id=execution_id,
        resume_prompt_id=prompt_id,
        resume_settlement=settlement,
    )
    requested, seen = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    assert not any(item.get("kind") == "prompt_opened" for item in seen)
    request, service, preflight = validate_send_request(
        execution_id,
        0,
        procedure.steps[0],
        {},
        _request(requested),
    )
    assert request["confirmation"] == {"prompt_id": prompt_id}
    result = execute_preflight(
        request, service, preflight, confirmation_actor="test-operator"
    )
    control.put({"type": "telecommand_result", **result})
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert terminal["state"] == "completed"


def test_worker_rejects_backward_goto_that_would_reenter_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = "worker-v11-no-reentry"
    procedure = _procedure("Send(command='CMDNAME')\nLog('after')\n")
    thread, control, output = _start_worker(
        monkeypatch, procedure, execution_id=execution_id
    )
    requested, _ = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        execution_id, 0, procedure.steps[0], {}, _request(requested)
    )
    control.put(
        {
            "type": "telecommand_result",
            **execute_preflight(request, service, preflight),
        }
    )
    control.put({"type": "pause", "command_id": "pause-after-send"})
    _next(
        output,
        lambda item: item.get("kind") == "state" and item.get("state") == "paused",
    )
    control.put({"type": "goto", "command_id": "reenter", "target_step": 0})
    rejected, _ = _next(
        output,
        lambda item: item.get("kind") == "command_rejected"
        and item.get("command_id") == "reenter",
    )
    control.put({"type": "abort", "command_id": "abort"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert rejected["code"] == "TC_REENTRY_FORBIDDEN"
    assert not thread.is_alive()


def test_worker_rejects_inspection_edits_to_opaque_command_items(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "tc_item = BuildTC('CMDNAME')\n"
        "Prompt('hold', type='OK')\n"
        "Send(command=tc_item)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    opened, seen = _next(output, lambda item: item.get("kind") == "prompt_opened")
    variables = [
        item["variables"] for item in seen if item.get("kind") == "step_commit"
    ][-1]
    assert variables["tc_item"].startswith(ITEM_PREFIX)
    control.put(
        {
            "type": "inspection_edit",
            "edit_id": "replace-command-item",
            "execution_revision": 7,
            "scope": "LOCAL_VARIABLE",
            "path": "variables.tc_item",
            "declared_type": "STRING",
            "variables": {**variables, "tc_item": "CMD1"},
        }
    )
    rejected, _ = _next(
        output, lambda item: item.get("kind") == "inspection_edit_applied"
    )
    control.put({"type": "abort", "command_id": "stop-after-edit"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert rejected["outcome"] == "REJECTED"
    assert rejected["code"] == "INSPECTION_EDIT_INVALID"
    assert rejected["variables"]["tc_item"].startswith(ITEM_PREFIX)
    assert not thread.is_alive()


def test_worker_rejects_inspection_edits_to_command_selector_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "tc_name: str = 'CMDNAME'\n"
        "Prompt('hold', type='OK')\n"
        "Send(command=tc_name)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    _, seen = _next(output, lambda item: item.get("kind") == "prompt_opened")
    variables = [
        item["variables"] for item in seen if item.get("kind") == "step_commit"
    ][-1]
    control.put(
        {
            "type": "inspection_edit",
            "edit_id": "replace-command-selector",
            "execution_revision": 7,
            "scope": "LOCAL_VARIABLE",
            "path": "variables.tc_name",
            "declared_type": "STRING",
            "variables": {**variables, "tc_name": "CMD2"},
        }
    )
    rejected, _ = _next(
        output, lambda item: item.get("kind") == "inspection_edit_applied"
    )
    control.put({"type": "abort", "command_id": "stop-after-edit"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert rejected["outcome"] == "REJECTED"
    assert rejected["code"] == "INSPECTION_EDIT_INVALID"
    assert rejected["variables"]["tc_name"] == "CMDNAME"
    assert not thread.is_alive()


def test_worker_rejects_user_actions_targeting_command_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "tc_name: str = 'CMDNAME'\n"
        "Prompt('hold', type='OK')\n"
        "Send(command=tc_name)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    _next(output, lambda item: item.get("kind") == "prompt_opened")
    control.put(
        {
            "type": "user_action",
            "invocation_id": "replace-command-selector",
            "handler": [
                {
                    "op": "SET_LITERAL",
                    "name": "tc_name",
                    "declared_type": "str",
                    "value": "CMD2",
                }
            ],
        }
    )
    rejected, _ = _next(
        output, lambda item: item.get("kind") == "user_action_settled"
    )
    control.put({"type": "abort", "command_id": "stop-after-action"})
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert rejected["outcome"] == "REJECTED"
    assert rejected["code"] == "USER_ACTION_TARGET_INVALID"
    assert rejected["variables"]["tc_name"] == "CMDNAME"
    assert not thread.is_alive()


def test_worker_applies_noninteractive_cancel_without_claiming_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "Send(command='CMDNAME', OnFailure=CANCEL, PromptUser=False)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, seen = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        "execution-v06", 0, procedure.steps[0], {}, _request(requested)
    )
    control.put(
        {
            "type": "telecommand_result",
            **_transport_rejected_result(request, service, preflight),
        }
    )
    terminal, after = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    commits = [item for item in [*seen, *after] if item.get("kind") == "step_commit"]
    settlement = next(
        effect
        for effect in commits[-1]["effects"]
        if effect.get("event_type") == "procedure.telecommand_settled"
    )
    assert terminal["state"] == "completed"
    assert settlement["payload"]["successful"] is False
    assert settlement["payload"]["checkpoint"]["elements"][0][
        "disposition"
    ] == "TRANSPORT_REJECTED"


def test_worker_applies_noninteractive_abort_as_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "Send(command='CMDNAME', OnFailure=ABORT, PromptUser=False)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, seen = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        "execution-v06", 0, procedure.steps[0], {}, _request(requested)
    )
    control.put(
        {
            "type": "telecommand_result",
            **_transport_rejected_result(request, service, preflight),
        }
    )
    terminal, after = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert terminal["state"] == "failed"
    assert any(
        item.get("event_type") == "procedure.error"
        and "TC_OPERATION_ABORTED" in item["payload"]["error"]
        for item in [*seen, *after]
    )


def test_worker_continue_policy_executes_later_group_elements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "Send(group=['CMD1', 'CMD2'], OnFailure=CONTINUE, PromptUser=False)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        "execution-v06", 0, procedure.steps[0], {}, _request(requested)
    )
    first, second = preflight.plan.elements
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(ElementStage.TRANSPORT, "REJECTED", first.element_id),
            ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", second.element_id),
            ProviderStep(ElementStage.LOADING, "LOADED", second.element_id),
            ProviderStep(ElementStage.RELEASE, "RELEASED", second.element_id),
            ProviderStep(
                ElementStage.ACKNOWLEDGEMENT,
                "ACKNOWLEDGED",
                second.element_id,
            ),
            ProviderStep(
                ElementStage.ONBOARD_EXECUTION,
                "SUCCEEDED",
                second.element_id,
            ),
        ]
    )
    result = execute_preflight(request, service, preflight, provider=provider)
    control.put({"type": "telecommand_result", **result})
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert terminal["state"] == "completed"
    assert [
        element["disposition"] for element in result["checkpoint"]["elements"]
    ] == ["TRANSPORT_REJECTED", "EXECUTED_UNVERIFIED"]


@pytest.mark.parametrize(
    "response, expected_state",
    [("YES", "completed"), ("NO", "failed")],
)
def test_worker_failure_prompt_is_bound_to_the_result_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    response: str,
    expected_state: str,
) -> None:
    procedure = _procedure("Send(command='CMDNAME', OnFailure=CANCEL)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    request, service, preflight = validate_send_request(
        "execution-v06", 0, procedure.steps[0], {}, _request(requested)
    )
    result = _transport_rejected_result(request, service, preflight)
    control.put({"type": "telecommand_result", **result})
    opened, _ = _next(output, lambda item: item.get("kind") == "prompt_opened")
    assert opened["prompt_id"] == failure_prompt_id(
        request["execution_id"], 0, result["result_digest"]
    )
    control.put(
        {
            "type": "prompt_settlement",
            "prompt_id": opened["prompt_id"],
            "settlement_id": f"failure-{response.lower()}",
            "outcome": "ANSWERED",
            "value": response,
        }
    )
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert terminal["state"] == expected_state


def test_worker_recovers_failure_prompt_after_initial_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = "worker-v11-confirmed-failure-recovery"
    procedure = _procedure(
        "Send(command='CMDNAME', Confirm=True, OnFailure=CANCEL)\n"
    )
    unsigned, service, preflight = prepare_send_request(
        execution_id, 0, procedure.steps[0], {}
    )
    confirm_id = confirmation_prompt_id(
        execution_id, 0, preflight.plan.plan_digest
    )
    request, service, preflight = prepare_send_request(
        execution_id,
        0,
        procedure.steps[0],
        {},
        confirmation={"prompt_id": confirm_id},
    )
    result = _transport_rejected_result(request, service, preflight)
    resume_id = failure_prompt_id(execution_id, 0, result["result_digest"])
    settlement = {
        "prompt_id": resume_id,
        "settlement_id": "recovered-failure-settlement",
        "outcome": "ANSWERED",
        "response": "YES",
        "command_id": None,
    }
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        execution_id=execution_id,
        resume_prompt_id=resume_id,
        resume_settlement=settlement,
    )
    requested, seen = _next(
        output, lambda item: item.get("kind") == "telecommand_requested"
    )
    assert _request(requested)["confirmation"] == {"prompt_id": confirm_id}
    assert not any(item.get("kind") == "prompt_opened" for item in seen)
    control.put({"type": "telecommand_result", **result})
    terminal, after = _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)

    assert terminal["state"] == "completed"
    assert not any(item.get("kind") == "prompt_opened" for item in after)
