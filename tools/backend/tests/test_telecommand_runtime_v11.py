from __future__ import annotations

import json

import pytest

from backend.procedure_parser import ProcedureCatalog
from backend.telecommand_runtime_v11 import (
    ITEM_PREFIX,
    TelecommandRuntimeError,
    build_item_checkpoint_for_step,
    execute_preflight,
    prepare_send_request,
    result_failure_policy,
    result_payload,
    uncertain_replay_result,
    validate_result_payload,
    validate_send_request,
)
from backend.telecommand_v11 import (
    DeterministicScriptedProvider,
    ElementStage,
    ProviderStep,
)

from .test_v11_command_corpus import COMMAND_CORPUS


def _procedure(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "telecommand-runtime-v11.spell.py"
    )


def _run_case(case_id: str, source: str):
    procedure = _procedure(source)
    variables: dict[str, object] = {}
    results = []
    for step_index, step in enumerate(procedure.steps):
        if step["type"] == "variable_set":
            variables[step["name"]] = step["expression"]["value"]
        elif step["type"] == "build_tc":
            variables[step["target"]] = build_item_checkpoint_for_step(
                step, variables
            )
        elif step["type"] == "send_tc":
            request, service, preflight = prepare_send_request(
                f"execution-{case_id}", step_index, step, variables
            )
            result = execute_preflight(
                request,
                service,
                preflight,
                confirmation_actor=(
                    "test-operator" if preflight.confirmation_required else None
                ),
            )
            results.append(validate_result_payload(request, result))
    return variables, results


@pytest.mark.parametrize("case_id, source", COMMAND_CORPUS, ids=lambda value: value)
def test_all_documented_command_statements_execute_through_the_closed_runtime(
    case_id: str, source: str
) -> None:
    variables, results = _run_case(case_id, source)

    if "BuildTC" in source:
        built = [value for value in variables.values() if isinstance(value, str)]
        assert any(value.startswith(ITEM_PREFIX) for value in built)
    for result in results:
        assert result["outcome"] == "SETTLED"
        assert result["checkpoint"]["state"] == "SETTLED"
        assert all(
            element["disposition"]
            in {"LOADED_ONLY", "EXECUTED_UNVERIFIED", "VERIFIED"}
            for element in result["checkpoint"]["elements"]
        )


def test_example_60_literal_and_item_forms_produce_distinct_bound_requests() -> None:
    literal = _procedure("Send(command='CMDNAME')\n")
    literal_request, _, _ = prepare_send_request(
        "example-60-literal", 0, literal.steps[0], {}
    )
    item = _procedure("tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n")
    variables = {"tc_item": ""}
    variables["tc_item"] = build_item_checkpoint_for_step(item.steps[1], variables)
    item_request, _, _ = prepare_send_request(
        "example-60-item", 2, item.steps[2], variables
    )

    assert literal_request["selector"] == {"kind": "name", "value": "CMDNAME"}
    assert item_request["selector"]["kind"] == "item"
    assert literal_request["request_digest"] != item_request["request_digest"]


def test_built_item_and_worker_request_tampering_fail_closed() -> None:
    procedure = _procedure("tc_item = BuildTC('CMDNAME')\nSend(command=tc_item)\n")
    variables = {"tc_item": ""}
    encoded = build_item_checkpoint_for_step(procedure.steps[1], variables)
    payload = json.loads(encoded[len(ITEM_PREFIX) :])
    payload["name"] = "CMD1"
    variables["tc_item"] = ITEM_PREFIX + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )
    with pytest.raises(TelecommandRuntimeError, match="digest"):
        prepare_send_request("tampered-item", 2, procedure.steps[2], variables)

    variables["tc_item"] = encoded
    request, _, _ = prepare_send_request(
        "tampered-request", 2, procedure.steps[2], variables
    )
    request["arguments"] = {"ARG1": 5.0}
    with pytest.raises(TelecommandRuntimeError, match="authoritative"):
        validate_send_request(
            "tampered-request", 2, procedure.steps[2], variables, request
        )

    variables["tc_item"] = "CMD1"
    with pytest.raises(TelecommandRuntimeError, match="opaque telecommand item"):
        prepare_send_request("redirected-item", 2, procedure.steps[2], variables)


def test_replayed_unsettled_intent_becomes_uncertain_without_dispatch() -> None:
    procedure = _procedure("Send(command='CMDNAME')\n")
    request, service, preflight = prepare_send_request(
        "replayed-intent", 0, procedure.steps[0], {}
    )

    result = uncertain_replay_result(request, service, preflight)

    assert result["outcome"] == "UNCERTAIN"
    assert result["successful"] is False
    assert result["checkpoint"]["provider_call_count"] == 0
    assert result["checkpoint"]["elements"][0]["effect_certainty"] == "EFFECT_UNKNOWN"


def test_failure_policy_uses_the_winning_action_prompt_setting() -> None:
    procedure = _procedure(
        "Send(group=['CMD1', 'CMD2'], OnFailure=CONTINUE, PromptUser=True, "
        "PerCommand={'1': {'on_failure': 'ABORT', 'prompt_user': False}})\n"
    )
    request, service, preflight = prepare_send_request(
        "mixed-failure-policy", 0, procedure.steps[0], {}
    )
    first, second = preflight.plan.elements
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(ElementStage.TRANSPORT, "REJECTED", first.element_id),
            ProviderStep(ElementStage.TRANSPORT, "REJECTED", second.element_id),
        ]
    )
    result = execute_preflight(request, service, preflight, provider=provider)

    assert result_failure_policy(request, result) == {
        "action": "ABORT",
        "failed_element_ids": [first.element_id, second.element_id],
        "prompt_user": False,
        "uncertain": False,
    }


def test_failure_policy_never_allows_unknown_effect_to_continue() -> None:
    procedure = _procedure(
        "Send(command='CMDNAME', verify=[['TM1', eq, 1]], "
        "OnFailure=CONTINUE, PromptUser=False)\n"
    )
    request, service, preflight = prepare_send_request(
        "unknown-verification-effect", 0, procedure.steps[0], {}
    )
    element_id = preflight.plan.elements[0].element_id
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", element_id),
            ProviderStep(ElementStage.LOADING, "LOADED", element_id),
            ProviderStep(ElementStage.RELEASE, "RELEASED", element_id),
            ProviderStep(ElementStage.ACKNOWLEDGEMENT, "ACKNOWLEDGED", element_id),
            ProviderStep(ElementStage.ONBOARD_EXECUTION, "SUCCEEDED", element_id),
            ProviderStep(ElementStage.VERIFICATION, "FAILED", element_id),
        ]
    )
    result = execute_preflight(request, service, preflight, provider=provider)

    assert result_failure_policy(request, result)["uncertain"] is True


def test_failure_policy_treats_active_cancellation_after_transport_as_uncertain() -> None:
    procedure = _procedure(
        "Send(command='CMDNAME', OnFailure=CONTINUE, PromptUser=False)\n"
    )
    request, service, preflight = prepare_send_request(
        "cancelled-after-transport", 0, procedure.steps[0], {}
    )
    element_id = preflight.plan.elements[0].element_id
    snapshot = service.start(preflight)
    snapshot = service.advance(
        snapshot,
        DeterministicScriptedProvider(
            [ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", element_id)]
        ),
    )
    cancelled = service.cancel(snapshot, reason="operator cancellation")
    result = result_payload(request, cancelled)

    assert result_failure_policy(request, result)["uncertain"] is True
