from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from backend.telecommand_v11 import (
    BuildTC,
    ConfirmationRequired,
    DeterministicClock,
    DeterministicScriptedProvider,
    DeterministicTelemetryEvaluator,
    Disposition,
    EffectCertainty,
    ElementStage,
    ExpansionMode,
    OperationState,
    ProviderScriptError,
    ProviderStep,
    Send,
    SendRequest,
    SimulatedProviderCrash,
    TelecommandCatalog,
    TelecommandContractError,
    TelecommandService,
    TelecommandValidationError,
    TelemetryFixture,
    default_catalog_path,
    default_execution_contract_path,
    load_execution_contract,
    parse_modifiers,
)


@pytest.fixture(scope="module")
def catalog() -> TelecommandCatalog:
    return TelecommandCatalog.load()


def _plan(
    catalog: TelecommandCatalog,
    operation_id: str = "test-operation",
    **request: object,
) -> tuple[TelecommandService, object]:
    service = TelecommandService(catalog)
    preflight = service.preflight(SendRequest(operation_id=operation_id, **request))
    return service, preflight


def _remaining_nominal_steps(plan, *, start_stage: ElementStage) -> list[ProviderStep]:
    element = plan.elements[0]
    order = [
        (ElementStage.TRANSPORT, "ACCEPTED"),
        (ElementStage.LOADING, "LOADED"),
        (ElementStage.RELEASE, "RELEASED"),
        (ElementStage.ACKNOWLEDGEMENT, "ACKNOWLEDGED"),
        (ElementStage.ONBOARD_EXECUTION, "SUCCEEDED"),
    ]
    selected = False
    result: list[ProviderStep] = []
    for stage, outcome in order:
        selected = selected or stage is start_stage
        if selected:
            result.append(ProviderStep(stage, outcome, element.element_id))
    return result


def _rewrite_checkpoint(checkpoint: dict, **changes: object) -> dict:
    body = {key: value for key, value in checkpoint.items() if key != "checkpoint_digest"}
    body.update(changes)
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return {**body, "checkpoint_digest": hashlib.sha256(encoded).hexdigest()}


def test_default_contracts_are_hash_pinned_closed_and_simulator_only(
    catalog: TelecommandCatalog,
) -> None:
    policy, policy_digest = load_execution_contract()

    assert catalog.digest == hashlib.sha256(default_catalog_path().read_bytes()).hexdigest()
    assert policy_digest == hashlib.sha256(
        default_execution_contract_path().read_bytes()
    ).hexdigest()
    assert catalog.simulator_only is True
    assert catalog.live_dispatch is False
    assert policy["rules"]["automatic_resend"] is False
    assert policy["rules"]["transport_success_implies_execution_success"] is False
    assert policy["rules"]["load_only_is_execution_success"] is False


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("CMDNAME", None),
        ("CMD1", None),
        ("CMD2", None),
        ("CMD3", None),
        (
            "TCNAME",
            [
                ["ARG1", 1.0],
                ["ARG2", 255, {"ValueType": "LONG", "ValueFormat": "RAW", "Radix": "HEX"}],
            ],
        ),
        ("TC.SIMULATOR.RESET", None),
        ("TC.SIMULATOR.SET_MODE", {"MODE": "SAFE"}),
    ],
)
def test_every_catalog_command_builds_with_typed_corpus_arguments(
    catalog: TelecommandCatalog, name: str, args: object
) -> None:
    item = BuildTC(name, args, catalog=catalog)

    assert item.name == name
    assert item.catalog_digest == catalog.digest
    assert len(item.item_digest) == 64
    assert all(argument.value_type in {"LONG", "FLOAT", "STRING", "BOOLEAN", "TIME"} for argument in item.arguments)
    if name == "TCNAME":
        assert item.arguments[0].value == 1.0
        assert item.arguments[1].encoded == "0xFF"


def test_example_60_name_and_prebuilt_item_forms_execute_independently(
    catalog: TelecommandCatalog,
) -> None:
    direct = Send(operation_id="example-60-name", command="CMDNAME", catalog=catalog)
    item = BuildTC("CMDNAME", catalog=catalog)
    prebuilt = Send(operation_id="example-60-item", command=item, catalog=catalog)

    assert direct.successful and prebuilt.successful
    assert direct.elements[0].command_name == "CMDNAME"
    assert prebuilt.elements[0].command_name == "CMDNAME"
    assert direct.plan.operation_id != prebuilt.plan.operation_id


@pytest.mark.parametrize(
    "action, code",
    [
        (lambda c: BuildTC("MISSING", catalog=c), "TC_COMMAND_UNKNOWN"),
        (lambda c: BuildTC("TCNAME", {"ARG1": 1.0}, catalog=c), "TC_ARGUMENT_REQUIRED"),
        (
            lambda c: BuildTC("TCNAME", {"ARG1": True, "ARG2": 1}, catalog=c),
            "TC_ARGUMENT_TYPE",
        ),
        (
            lambda c: BuildTC("TCNAME", {"ARG1": 1.0, "ARG2": 65536}, catalog=c),
            "TC_ARGUMENT_RANGE",
        ),
        (
            lambda c: BuildTC("CMDNAME", {"UNKNOWN": 1}, catalog=c),
            "TC_ARGUMENT_UNKNOWN",
        ),
        (
            lambda c: BuildTC("CMDNAME", [["ARG2", 1], ["ARG2", 2]], catalog=c),
            "TC_ARGUMENT_DUPLICATE",
        ),
        (
            lambda c: BuildTC(
                "CMDNAME", {"ARG2": {"value": 1, "ValueType": "STRING"}}, catalog=c
            ),
            "TC_ARGUMENT_TYPE",
        ),
        (
            lambda c: BuildTC(
                "TC.SIMULATOR.SET_MODE", {"MODE": "X" * 257}, catalog=c
            ),
            "TC_ARGUMENT_RANGE",
        ),
    ],
)
def test_invalid_catalog_arguments_fail_closed(
    catalog: TelecommandCatalog, action, code: str
) -> None:
    with pytest.raises(TelecommandValidationError) as captured:
        action(catalog)
    assert captured.value.code == code


def test_catalog_rejects_unknown_fields_duplicate_keys_and_nonfinite_json(
    catalog: TelecommandCatalog, tmp_path: Path
) -> None:
    payload = json.loads(default_catalog_path().read_text(encoding="utf-8"))
    payload["unexpected"] = True
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TelecommandContractError, match="unknown field unexpected"):
        TelecommandCatalog.load(unknown)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
    with pytest.raises(TelecommandContractError, match="duplicate object key"):
        TelecommandCatalog.load(duplicate)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"schema_version":NaN}', encoding="utf-8")
    with pytest.raises(TelecommandContractError, match="non-finite"):
        TelecommandCatalog.load(nonfinite)


def test_execution_contract_fails_closed_if_a_safety_rule_changes(tmp_path: Path) -> None:
    payload = json.loads(default_execution_contract_path().read_text(encoding="utf-8"))
    payload["rules"]["automatic_resend"] = True
    changed = tmp_path / "execution.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(TelecommandContractError, match="safety rules"):
        load_execution_contract(changed)


def test_sequence_and_group_expansion_is_stable_and_duplicate_safe(
    catalog: TelecommandCatalog,
) -> None:
    first_service, first = _plan(
        catalog, "duplicate-sequence", sequence="SEQ.DUPLICATE"
    )
    _, second = _plan(catalog, "duplicate-sequence", sequence="SEQ.DUPLICATE")
    _, group = _plan(catalog, "duplicate-group", group=["CMD1", "CMD1", "CMD2"])

    assert first.plan.mode is ExpansionMode.SEQUENCE
    assert [item.command.name for item in first.plan.elements] == ["CMD1", "CMD1", "CMD2"]
    assert len({item.element_id for item in first.plan.elements}) == 3
    assert [item.element_id for item in first.plan.elements] == [
        item.element_id for item in second.plan.elements
    ]
    assert group.plan.mode is ExpansionMode.GROUP
    assert len({item.element_id for item in group.plan.elements}) == 3
    assert first_service.catalog.digest == catalog.digest


def test_plain_group_grouped_transport_and_block_are_observably_distinct(
    catalog: TelecommandCatalog,
) -> None:
    _, plain = _plan(catalog, "plain-group", group=["CMD1", "CMD2", "CMD3"])
    grouped_service, grouped = _plan(
        catalog,
        "grouped-transport",
        group=["CMD1", "CMD2", "CMD3"],
        modifiers={"group": True},
    )
    block_service, blocked = _plan(
        catalog, "block-transport", group=["CMD1", "CMD2", "CMD3"], block=True
    )

    assert len({item.transport_unit_id for item in plain.plan.elements}) == 3
    assert len({item.transport_unit_id for item in grouped.plan.elements}) == 1
    assert len({item.transport_unit_id for item in blocked.plan.elements}) == 1
    assert plain.plan.mode is ExpansionMode.GROUP
    assert grouped.plan.mode is ExpansionMode.GROUP
    assert blocked.plan.mode is ExpansionMode.BLOCK

    for service, preflight in ((grouped_service, grouped), (block_service, blocked)):
        provider = DeterministicScriptedProvider.nominal(preflight.plan)
        result = service.run(service.start(preflight), provider)
        transport_calls = [call for call in provider.calls if call.stage is ElementStage.TRANSPORT]
        assert result.successful
        assert len(transport_calls) == 1
        assert all("TRANSPORT" in item.provider_detail for item in result.elements)


def test_global_item_and_per_command_modifier_precedence(
    catalog: TelecommandCatalog,
) -> None:
    first = BuildTC("CMD1", modifiers={"timeout_ms": 5_000}, catalog=catalog)
    _, preflight = _plan(
        catalog,
        "modifier-precedence",
        group=[first, "CMD2", "CMD3"],
        modifiers={
            "timeout_seconds": 60,
            "send_delay_seconds": 2,
            "per_command": {"1": {"timeout_seconds": 10}},
        },
    )
    elements = preflight.plan.elements

    assert [item.effective_modifiers.timeout_ms for item in elements] == [5_000, 10_000, 60_000]
    assert all(item.effective_modifiers.send_delay_ms == 2_000 for item in elements)
    assert elements[0].modifier_sources["timeout_ms"] == "PER_COMMAND"
    assert elements[1].modifier_sources["timeout_ms"] == "PER_COMMAND"
    assert elements[2].modifier_sources["timeout_ms"] == "GLOBAL"


def test_time_release_delay_load_and_verification_intents_are_explicit(
    catalog: TelecommandCatalog,
) -> None:
    _, preflight = _plan(
        catalog,
        "intent-surface",
        command="TCNAME",
        args=[["ARG1", 1.0], ["ARG2", 255, {"Radix": "HEX"}]],
        modifiers={
            "time": "NOW+1800s",
            "release_time": "2008/04/10 10:30:00",
            "send_delay_seconds": 60,
            "verification_delay_seconds": 10,
            "verification": [["TM1", "eq", 10.0, {"Tolerance": 0.1, "Timeout": 20}]],
            "tolerance": 0.5,
            "adjust_limits": True,
            "prompt_user": False,
        },
    )
    intent = preflight.plan.elements[0].effective_modifiers

    assert intent.time == "NOW+1800s"
    assert intent.release_time == "2008-04-10T10:30:00Z"
    assert intent.send_delay_ms == 60_000
    assert intent.delay_ms == 10_000
    assert intent.verification[0].tolerance == 0.1
    assert intent.verification[0].timeout_ms == 20_000
    assert intent.tolerance == 0.5
    assert intent.adjust_limits is True


def test_time_and_send_delay_advance_the_logical_clock_before_transport(
    catalog: TelecommandCatalog,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    service = TelecommandService(catalog, clock=clock)
    preflight = service.preflight(
        SendRequest(
            "scheduled-transport",
            command="CMDNAME",
            modifiers={
                "time": "NOW+10s",
                "send_delay_seconds": 5,
                "timeout_seconds": 60,
            },
        )
    )
    provider = DeterministicScriptedProvider.nominal(preflight.plan)

    dispatched = service.advance(service.start(preflight), provider)
    timing = dispatched.elements[0].timing_detail

    assert clock.now == "2026-01-01T00:00:15.000Z"
    assert timing["requested_transport_due_at"] == clock.now
    assert timing["stage_times"]["TRANSPORT"] == clock.now
    assert timing["waits"]["TRANSPORT"]["duration_ms"] == 15_000
    assert timing["deadline_at"] == "2026-01-01T00:01:15.000Z"
    assert len(provider.calls) == 1


def test_group_keeps_catalog_order_when_later_element_has_earlier_time(
    catalog: TelecommandCatalog,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    service = TelecommandService(catalog, clock=clock)
    preflight = service.preflight(
        SendRequest(
            "scheduled-order",
            group=["CMD1", "CMD2"],
            modifiers={
                "timeout_seconds": 60,
                "per_command": {
                    "0": {"time": "NOW+20s"},
                    "1": {"time": "NOW+5s"},
                },
            },
        )
    )
    provider = DeterministicScriptedProvider.nominal(preflight.plan)
    result = service.run(service.start(preflight), provider)
    first, second = result.elements

    assert result.successful
    assert first.timing_detail["stage_times"]["TRANSPORT"] == (
        "2026-01-01T00:00:20.000Z"
    )
    assert second.timing_detail["stage_times"]["TRANSPORT"] == (
        "2026-01-01T00:00:20.000Z"
    )
    assert [call.element_id for call in provider.calls if call.stage is ElementStage.TRANSPORT] == [
        first.element_id,
        second.element_id,
    ]


def test_release_time_gates_release_after_loading_without_real_wait(
    catalog: TelecommandCatalog,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    service = TelecommandService(catalog, clock=clock)
    preflight = service.preflight(
        SendRequest(
            "release-gate",
            command="CMDNAME",
            modifiers={"release_time": "NOW+1800s", "timeout_seconds": 60},
        )
    )
    provider = DeterministicScriptedProvider.nominal(preflight.plan)
    snapshot = service.start(preflight)
    snapshot = service.advance(snapshot, provider)
    snapshot = service.advance(snapshot, provider)
    assert snapshot.elements[0].loading == "LOADED"
    assert clock.now == "2026-01-01T00:00:00.000Z"

    snapshot = service.advance(snapshot, provider)
    assert snapshot.elements[0].release == "RELEASED"
    assert clock.now == "2026-01-01T00:30:00.000Z"
    assert snapshot.elements[0].timing_detail["release_due_at"] == clock.now
    assert snapshot.elements[0].timing_detail["deadline_at"] == (
        "2026-01-01T00:31:00.000Z"
    )
    assert snapshot.elements[0].timing_detail["waits"]["RELEASE"]["duration_ms"] == (
        1_800_000
    )


@pytest.mark.parametrize(
    ("duration_ms", "expected_disposition"),
    [(1_000, Disposition.PENDING), (1_001, Disposition.TIMED_OUT)],
)
def test_per_element_timeout_has_an_exact_logical_boundary(
    catalog: TelecommandCatalog,
    duration_ms: int,
    expected_disposition: Disposition,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    service = TelecommandService(catalog, clock=clock)
    preflight = service.preflight(
        SendRequest(
            f"timeout-boundary-{duration_ms}",
            command="CMDNAME",
            modifiers={"timeout_ms": 1_000},
        )
    )
    element_id = preflight.plan.elements[0].element_id
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(
                ElementStage.TRANSPORT,
                "ACCEPTED",
                element_id,
                duration_ms=duration_ms,
            )
        ]
    )
    result = service.advance(service.start(preflight), provider)

    assert result.elements[0].disposition is expected_disposition
    assert result.elements[0].transport == "ACCEPTED"
    if expected_disposition is Disposition.TIMED_OUT:
        assert result.state is OperationState.SETTLED
        assert result.elements[0].loading == "NOT_ATTEMPTED"
        assert result.elements[0].effect_certainty is EffectCertainty.EFFECT_UNKNOWN
        assert result.successful is False
        assert service.advance(result, provider) is result
        assert len(provider.calls) == 1
    else:
        assert result.elements[0].next_stage is ElementStage.LOADING


def test_grouped_transport_applies_each_elements_timeout_independently(
    catalog: TelecommandCatalog,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    service = TelecommandService(catalog, clock=clock)
    preflight = service.preflight(
        SendRequest(
            "group-timeout",
            group=["CMD1", "CMD2"],
            modifiers={
                "group": True,
                "timeout_seconds": 5,
                "per_command": {"0": {"timeout_seconds": 1}},
            },
        )
    )
    first, second = preflight.plan.elements
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(
                ElementStage.TRANSPORT,
                "ACCEPTED",
                first.transport_unit_id,
                duration_ms=1_001,
            ),
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

    result = service.run(service.start(preflight), provider)

    assert result.elements[0].disposition is Disposition.TIMED_OUT
    assert result.elements[1].disposition is Disposition.EXECUTED_UNVERIFIED
    assert result.successful is False
    assert len(
        [call for call in provider.calls if call.stage is ElementStage.TRANSPORT]
    ) == 1
    provider.assert_consumed()


@pytest.mark.parametrize(
    ("tolerance", "expected_disposition"),
    [(0.5, Disposition.VERIFIED), (0.1, Disposition.VERIFICATION_FAILED)],
)
def test_delayed_verification_uses_global_tolerance_in_deterministic_evaluator(
    catalog: TelecommandCatalog,
    tolerance: float,
    expected_disposition: Disposition,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    evaluator = DeterministicTelemetryEvaluator({"TM1": 10.4})
    service = TelecommandService(
        catalog, clock=clock, telemetry_evaluator=evaluator
    )
    preflight = service.preflight(
        SendRequest(
            f"tolerance-{tolerance}",
            command="CMDNAME",
            modifiers={
                "verification": [["TM1", "eq", 10.0]],
                "verification_delay_seconds": 5,
                "tolerance": tolerance,
                "timeout_seconds": 1,
            },
        )
    )
    provider = DeterministicScriptedProvider.nominal(
        preflight.plan, include_verification=False
    )
    result = service.run(service.start(preflight), provider)
    item = result.elements[0]

    assert item.disposition is expected_disposition
    assert item.onboard_execution == "SUCCEEDED"
    assert item.timing_detail["waits"]["VERIFICATION"]["duration_ms"] == 5_000
    assert item.timing_detail["stage_times"]["VERIFICATION"] == (
        "2026-01-01T00:00:05.000Z"
    )
    assert evaluator.calls[0]["conditions"][0]["tolerance"] == tolerance
    assert len(provider.calls) == 5
    provider.assert_consumed()


def test_verification_condition_timeout_is_indeterminate_without_resend(
    catalog: TelecommandCatalog,
) -> None:
    clock = DeterministicClock("2026-01-01T00:00:00Z")
    evaluator = DeterministicTelemetryEvaluator(
        {"TM1": TelemetryFixture(10, available_after_ms=21_000)}
    )
    service = TelecommandService(
        catalog, clock=clock, telemetry_evaluator=evaluator
    )
    preflight = service.preflight(
        SendRequest(
            "verification-timeout",
            command="CMDNAME",
            modifiers={
                "verification": [["TM1", "eq", 10, {"Timeout": 20}]],
                "timeout_seconds": 60,
            },
        )
    )
    provider = DeterministicScriptedProvider.nominal(
        preflight.plan, include_verification=False
    )
    result = service.run(service.start(preflight), provider)

    assert result.elements[0].verification == "INDETERMINATE"
    assert result.elements[0].disposition is Disposition.UNCERTAIN
    assert evaluator.calls[0]["conditions"][0]["state"] == "TIMED_OUT"
    assert clock.now == "2026-01-01T00:00:20.000Z"
    assert all(call.stage is not ElementStage.VERIFICATION for call in provider.calls)


@pytest.mark.parametrize(
    ("allow_adjustment", "expected_disposition"),
    [(True, Disposition.VERIFIED), (False, Disposition.VERIFICATION_FAILED)],
)
def test_adjust_limits_intent_has_deterministic_capability_outcome(
    catalog: TelecommandCatalog,
    allow_adjustment: bool,
    expected_disposition: Disposition,
) -> None:
    evaluator = DeterministicTelemetryEvaluator(
        {"TM1": 10}, allow_limit_adjustment=allow_adjustment
    )
    service = TelecommandService(catalog, telemetry_evaluator=evaluator)
    preflight = service.preflight(
        SendRequest(
            f"adjust-limits-{allow_adjustment}",
            command="CMDNAME",
            modifiers={
                "verification": [["TM1", "eq", 10]],
                "adjust_limits": True,
            },
        )
    )
    provider = DeterministicScriptedProvider.nominal(
        preflight.plan, include_verification=False
    )
    result = service.run(service.start(preflight), provider)

    assert result.elements[0].disposition is expected_disposition
    assert evaluator.calls[0]["limits_adjusted"] is allow_adjustment
    native = result.elements[0].provider_detail["VERIFICATION"]["native"]
    if allow_adjustment:
        assert native["limits_adjusted"] is True
    else:
        assert native["reason"] == "LIMIT_ADJUSTMENT_UNAVAILABLE"


@pytest.mark.parametrize(
    "modifiers",
    [
        {"load_only": True, "verification": [["TM1", "eq", 1]]},
        {"load_only": True, "release_time": "2026-08-19T12:00:00Z"},
        {"adjust_limits": True},
        {"on_failure": "RESEND"},
        {"unknown": True},
    ],
)
def test_modifier_conflicts_and_unsupported_resend_fail_closed(
    catalog: TelecommandCatalog, modifiers: dict
) -> None:
    service = TelecommandService(catalog)
    with pytest.raises(TelecommandValidationError):
        service.preflight(
            SendRequest("invalid-modifiers", command="CMDNAME", modifiers=modifiers)
        )


@pytest.mark.parametrize(
    "modifier",
    [
        {"Timeout": 1 << 5000},
        {"Time": 1 << 5000},
        {"Tolerance": 1 << 5000},
    ],
)
def test_public_modifier_api_rejects_oversized_numbers_without_raw_overflow(
    catalog: TelecommandCatalog, modifier: dict[str, int]
) -> None:
    with pytest.raises(TelecommandValidationError):
        TelecommandService(catalog).preflight(
            SendRequest(
                operation_id="oversized-public-modifier",
                command="CMDNAME",
                modifiers=modifier,
            )
        )


def test_nested_secret_like_additional_information_is_rejected(
    catalog: TelecommandCatalog,
) -> None:
    with pytest.raises(TelecommandValidationError) as captured:
        parse_modifiers(
            {"additional_info": {"meta": {"api_token": "do-not-store"}}},
            catalog.limits,
        )
    assert captured.value.code == "TC_SECRET_REJECTED"


def test_secret_like_provider_detail_is_rejected_before_dispatch_script_use(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "provider-secret", command="CMDNAME")
    element_id = preflight.plan.elements[0].element_id

    with pytest.raises(TelecommandValidationError) as captured:
        DeterministicScriptedProvider(
            [
                ProviderStep(
                    ElementStage.TRANSPORT,
                    "ACCEPTED",
                    element_id,
                    detail={"nested": {"credential": "forbidden"}},
                )
            ]
        )
    assert captured.value.code == "TC_SECRET_REJECTED"
    assert service.start(preflight).provider_call_count == 0


def test_critical_preflight_requires_bound_explicit_confirmation(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(
        catalog, "critical-confirmation", command="TC.SIMULATOR.RESET"
    )
    provider = DeterministicScriptedProvider.nominal(preflight.plan)

    with pytest.raises(ConfirmationRequired) as captured:
        service.start(preflight)
    assert captured.value.challenge == preflight.plan.confirmation_challenge
    assert provider.calls == []

    confirmation = service.confirm(preflight, actor="operator-1", reason="approved simulation")
    invalid = replace(confirmation, actor="operator-2")
    with pytest.raises(TelecommandValidationError, match="does not bind"):
        service.start(preflight, invalid)
    assert provider.calls == []

    result = service.run(service.start(preflight, confirmation), provider)
    assert result.confirmed_by == "operator-1"
    assert result.successful


def test_forged_preflight_cannot_remove_critical_confirmation(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(
        catalog, "forged-critical-preflight", command="TC.SIMULATOR.RESET"
    )
    forged = replace(
        preflight,
        plan=replace(preflight.plan, confirmation_required=False),
    )

    with pytest.raises(TelecommandValidationError, match="not registered"):
        service.start(forged)
    assert "forged-critical-preflight" not in service._operations


def test_transport_loading_release_ack_execution_and_verification_do_not_collapse(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(
        catalog,
        "separate-stages",
        command="CMDNAME",
        modifiers={"verification": [["TM1", "eq", 1]]},
    )
    provider = DeterministicScriptedProvider.nominal(preflight.plan)
    snapshot = service.start(preflight)

    assert snapshot.state is OperationState.ACCEPTED
    assert snapshot.elements[0].transport == "NOT_ATTEMPTED"
    snapshot = service.advance(snapshot, provider)
    assert snapshot.state is OperationState.DISPATCHED
    assert snapshot.elements[0].transport == "ACCEPTED"
    assert snapshot.elements[0].loading == "NOT_ATTEMPTED"
    assert snapshot.elements[0].onboard_execution == "NOT_ATTEMPTED"
    assert snapshot.successful is False
    snapshot = service.advance(snapshot, provider)
    assert snapshot.elements[0].loading == "LOADED"
    assert snapshot.elements[0].release == "NOT_ATTEMPTED"
    snapshot = service.run(snapshot, provider)

    assert snapshot.elements[0].release == "RELEASED"
    assert snapshot.elements[0].acknowledgement == "ACKNOWLEDGED"
    assert snapshot.elements[0].onboard_execution == "SUCCEEDED"
    assert snapshot.elements[0].verification == "PASSED"
    assert snapshot.elements[0].disposition is Disposition.VERIFIED
    assert snapshot.elements[0].effect_certainty is EffectCertainty.EFFECT_CONFIRMED
    assert snapshot.successful


def test_load_only_is_loaded_but_never_execution_success(
    catalog: TelecommandCatalog,
) -> None:
    result = Send(
        operation_id="load-only",
        command="CMDNAME",
        catalog=catalog,
        LoadOnly=True,
    )
    item = result.elements[0]

    assert result.state is OperationState.SETTLED
    assert item.transport == "ACCEPTED"
    assert item.loading == "LOADED"
    assert item.release == "NOT_REQUESTED"
    assert item.onboard_execution == "NOT_ATTEMPTED"
    assert item.disposition is Disposition.LOADED_ONLY
    assert item.effect_certainty is EffectCertainty.NO_EFFECT
    assert result.execution_succeeded is False
    assert result.successful is False


def test_cancellation_before_and_after_transport_preserves_certainty(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "cancel-before", command="CMDNAME")
    provider = DeterministicScriptedProvider.nominal(preflight.plan)
    before = service.cancel(service.start(preflight), reason="operator cancelled")
    assert before.elements[0].disposition is Disposition.CANCELLED
    assert before.elements[0].effect_certainty is EffectCertainty.NO_EFFECT
    assert provider.calls == []

    service, preflight = _plan(catalog, "cancel-after", command="CMDNAME")
    provider = DeterministicScriptedProvider.nominal(preflight.plan)
    dispatched = service.advance(service.start(preflight), provider)
    after = service.cancel(dispatched, reason="operator cancelled after transport")
    assert after.elements[0].transport == "ACCEPTED"
    assert after.elements[0].disposition is Disposition.CANCELLED
    assert after.elements[0].effect_certainty is EffectCertainty.EFFECT_UNKNOWN
    assert len(provider.calls) == 1


def test_crash_boundary_recovers_by_reconciliation_without_transport_resend(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "crash-transport", command="CMDNAME")
    element_id = preflight.plan.elements[0].element_id
    steps = _remaining_nominal_steps(preflight.plan, start_stage=ElementStage.TRANSPORT)
    steps[0] = replace(steps[0], crash_after=True, detail={"receipt": "transport-1"})
    provider = DeterministicScriptedProvider(steps)
    checkpoint = service.start(preflight).as_checkpoint()

    with pytest.raises(SimulatedProviderCrash):
        service.advance(service.get_operation("crash-transport"), provider)
    assert [(call.element_id, call.stage) for call in provider.calls] == [
        (element_id, ElementStage.TRANSPORT)
    ]

    recovered_service = TelecommandService(catalog)
    recovered = recovered_service.recover(preflight.plan, checkpoint)
    assert recovered.state is OperationState.RECONCILING
    reconciled = recovered_service.reconcile(recovered, provider)
    assert reconciled.elements[0].transport == "ACCEPTED"
    assert reconciled.elements[0].loading == "NOT_ATTEMPTED"
    result = recovered_service.run(reconciled, provider)

    assert result.successful
    assert sum(call.stage is ElementStage.TRANSPORT for call in provider.calls) == 1
    assert provider.reconciliation_calls == [(preflight.plan.plan_id, element_id)]


def test_crash_after_loading_reconciles_the_exact_pending_stage(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "crash-loading", command="CMDNAME")
    element_id = preflight.plan.elements[0].element_id
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", element_id),
            ProviderStep(ElementStage.LOADING, "LOADED", element_id, crash_after=True),
            ProviderStep(ElementStage.RELEASE, "RELEASED", element_id),
            ProviderStep(ElementStage.ACKNOWLEDGEMENT, "ACKNOWLEDGED", element_id),
            ProviderStep(ElementStage.ONBOARD_EXECUTION, "SUCCEEDED", element_id),
        ]
    )
    after_transport = service.advance(service.start(preflight), provider)
    checkpoint = after_transport.as_checkpoint()
    with pytest.raises(SimulatedProviderCrash):
        service.advance(after_transport, provider)

    recovered_service = TelecommandService(catalog)
    recovered = recovered_service.recover(preflight.plan, checkpoint)
    reconciled = recovered_service.reconcile(recovered, provider)
    assert reconciled.elements[0].transport == "ACCEPTED"
    assert reconciled.elements[0].loading == "LOADED"
    assert recovered_service.run(reconciled, provider).successful
    assert [call.stage for call in provider.calls].count(ElementStage.LOADING) == 1


def test_unknown_reconciliation_stays_uncertain_and_cannot_resend(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "unknown-reconciliation", command="CMDNAME")
    element_id = preflight.plan.elements[0].element_id
    provider = DeterministicScriptedProvider(
        [ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", element_id, crash_after=True)],
        reconciliation_mode="UNKNOWN",
    )
    checkpoint = service.start(preflight).as_checkpoint()
    with pytest.raises(SimulatedProviderCrash):
        service.advance(service.get_operation("unknown-reconciliation"), provider)

    recovered_service = TelecommandService(catalog)
    recovered = recovered_service.recover(preflight.plan, checkpoint)
    uncertain = recovered_service.reconcile(recovered, provider)

    assert uncertain.state is OperationState.RECONCILING
    assert uncertain.elements[0].transport == "UNCERTAIN"
    assert uncertain.elements[0].effect_certainty is EffectCertainty.EFFECT_UNKNOWN
    with pytest.raises(TelecommandValidationError) as captured:
        recovered_service.advance(uncertain, provider)
    assert captured.value.code == "TC_RECONCILIATION_REQUIRED"
    assert len(provider.calls) == 1


def test_explicit_transport_uncertainty_is_not_inferred_as_success(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "uncertain-transport", command="CMDNAME")
    element_id = preflight.plan.elements[0].element_id
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(
                ElementStage.TRANSPORT,
                "UNCERTAIN",
                element_id,
                detail={"native_status": "response_lost"},
            )
        ]
    )
    result = service.run(service.start(preflight), provider)

    assert result.state is OperationState.SETTLED
    assert result.elements[0].transport == "UNCERTAIN"
    assert result.elements[0].loading == "NOT_ATTEMPTED"
    assert result.elements[0].disposition is Disposition.UNCERTAIN
    assert result.successful is False
    assert result.elements[0].provider_detail["TRANSPORT"]["native"] == {
        "native_status": "response_lost"
    }


def test_verification_failure_keeps_onboard_execution_evidence_separate(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(
        catalog,
        "verification-failed",
        command="CMDNAME",
        modifiers={"verification": [["TM1", "eq", 1]]},
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
    result = service.run(service.start(preflight), provider)

    assert result.elements[0].onboard_execution == "SUCCEEDED"
    assert result.elements[0].verification == "FAILED"
    assert result.elements[0].disposition is Disposition.VERIFICATION_FAILED
    assert result.elements[0].effect_certainty is EffectCertainty.EFFECT_UNKNOWN
    assert result.execution_succeeded is True
    assert result.successful is False


def test_failure_continues_only_when_explicit_and_never_resends(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(
        catalog,
        "continue-without-resend",
        group=["CMD1", "CMD2"],
        modifiers={"on_failure": "CONTINUE"},
    )
    first, second = preflight.plan.elements
    provider = DeterministicScriptedProvider(
        [
            ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", first.element_id),
            ProviderStep(ElementStage.LOADING, "FAILED", first.element_id),
            ProviderStep(ElementStage.TRANSPORT, "ACCEPTED", second.element_id),
            ProviderStep(ElementStage.LOADING, "LOADED", second.element_id),
            ProviderStep(ElementStage.RELEASE, "RELEASED", second.element_id),
            ProviderStep(ElementStage.ACKNOWLEDGEMENT, "ACKNOWLEDGED", second.element_id),
            ProviderStep(ElementStage.ONBOARD_EXECUTION, "SUCCEEDED", second.element_id),
        ]
    )
    result = service.run(service.start(preflight), provider)

    assert result.elements[0].disposition is Disposition.LOAD_FAILED
    assert result.elements[1].disposition is Disposition.EXECUTED_UNVERIFIED
    assert result.successful is False
    assert len({(call.element_id, call.stage) for call in provider.calls}) == len(provider.calls)
    assert all(call.outcome != "RESEND" for call in provider.calls)


def test_operation_identity_is_idempotent_and_conflicts_fail_closed(
    catalog: TelecommandCatalog,
) -> None:
    service = TelecommandService(catalog)
    request = SendRequest("idempotent-send", command="CMDNAME")
    first = service.preflight(request)
    second = service.preflight(request)
    assert first.plan.plan_digest == second.plan.plan_digest
    assert service.start(first) is service.start(second)

    provider = DeterministicScriptedProvider.nominal(first.plan)
    result = service.run(service.get_operation("idempotent-send"), provider)
    repeated = service.start(first)
    assert repeated is result
    assert len(provider.calls) == 5

    with pytest.raises(TelecommandValidationError) as captured:
        service.preflight(SendRequest("idempotent-send", command="CMD1"))
    assert captured.value.code == "TC_IDEMPOTENCY_CONFLICT"
    assert len(provider.calls) == 5


def test_forged_current_snapshot_cannot_rewind_and_resend_transport(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "forged-snapshot", command="CMDNAME")
    before = service.start(preflight)
    first_provider = DeterministicScriptedProvider.nominal(preflight.plan)
    after_transport = service.advance(before, first_provider)
    forged = replace(after_transport, elements=before.elements)
    fresh_provider = DeterministicScriptedProvider.nominal(preflight.plan)

    with pytest.raises(TelecommandValidationError) as captured:
        service.advance(forged, fresh_provider)
    assert captured.value.code == "TC_SNAPSHOT_INVALID"
    assert fresh_provider.calls == []
    assert service.get_operation("forged-snapshot").elements[0].transport == "ACCEPTED"


def test_recovery_revalidates_plan_and_cannot_suppress_confirmation(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(
        catalog, "forged-recovery-plan", command="TC.SIMULATOR.RESET"
    )
    confirmation = service.confirm(preflight, actor="operator-1", reason="approved")
    checkpoint = service.start(preflight, confirmation).as_checkpoint()
    forged = replace(preflight.plan, confirmation_required=False)

    with pytest.raises(TelecommandValidationError) as captured:
        TelecommandService(catalog).recover(forged, checkpoint)
    assert captured.value.code == "TC_PLAN_INVALID"

    missing_evidence = _rewrite_checkpoint(checkpoint, confirmed_by=None)
    with pytest.raises(TelecommandValidationError) as captured:
        TelecommandService(catalog).recover(preflight.plan, missing_evidence)
    assert captured.value.code == "TC_CHECKPOINT_INVALID"


def test_provider_script_mismatch_fails_without_stage_inference(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "script-mismatch", command="CMDNAME")
    element_id = preflight.plan.elements[0].element_id
    provider = DeterministicScriptedProvider(
        [ProviderStep(ElementStage.LOADING, "LOADED", element_id)]
    )
    snapshot = service.start(preflight)

    with pytest.raises(ProviderScriptError):
        service.advance(snapshot, provider)
    current = service.get_operation("script-mismatch")
    assert current.revision == 0
    assert current.elements[0].transport == "NOT_ATTEMPTED"
    assert provider.calls == []


def test_checkpoint_digest_and_state_machine_coherence_fail_closed(
    catalog: TelecommandCatalog,
) -> None:
    service, preflight = _plan(catalog, "checkpoint-validation", command="CMDNAME")
    checkpoint = service.start(preflight).as_checkpoint()
    recovery = TelecommandService(catalog)

    tampered = dict(checkpoint)
    tampered["state"] = "SETTLED"
    with pytest.raises(TelecommandValidationError, match="digest is invalid"):
        recovery.recover(preflight.plan, tampered)

    impossible = _rewrite_checkpoint(checkpoint, state="SETTLED")
    with pytest.raises(TelecommandValidationError, match="settled checkpoint"):
        recovery.recover(preflight.plan, impossible)

    impossible_element = json.loads(json.dumps(checkpoint))
    impossible_element["elements"][0]["transport"] = "ACCEPTED"
    impossible_element["elements"][0]["next_stage"] = "ONBOARD_EXECUTION"
    impossible_element = _rewrite_checkpoint(
        impossible_element, elements=impossible_element["elements"]
    )
    with pytest.raises(TelecommandValidationError, match="impossible"):
        recovery.recover(preflight.plan, impossible_element)
