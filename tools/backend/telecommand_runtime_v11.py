"""Durable worker/supervisor boundary for v0.11 telecommand simulation.

The worker may construct opaque catalog items and request an operation, but it
never owns a provider.  The supervisor recomputes this closed request from the
authoritative IR/checkpoint before persisting and dispatching it.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Mapping

from .telecommand_v11 import (
    BuildTC,
    CommandItem,
    Confirmation,
    DeterministicScriptedProvider,
    ExecutionSnapshot,
    Preflight,
    SendRequest,
    TelecommandCatalog,
    TelecommandService,
    default_catalog,
)


REQUEST_SCHEMA_VERSION = "spell.v11.telecommand-request/1"
RESULT_SCHEMA_VERSION = "spell.v11.telecommand-result/1"
ITEM_SCHEMA_VERSION = "spell.v11.telecommand-item/1"
ITEM_PREFIX = "spell-tc-item-v11:"
MAX_RUNTIME_JSON_BYTES = 512_000

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "openbexi-spell:v0.11:telecommand-request"
)
_OPERATION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "openbexi-spell:v0.11:telecommand-operation"
)


class TelecommandRuntimeError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _reject(path: str, message: str, code: str = "TC_RUNTIME_INVALID") -> None:
    raise TelecommandRuntimeError(code, path, message)


def _canonical(value: Any, path: str = "$") -> Any:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise TelecommandRuntimeError(
            "TC_RUNTIME_INVALID", path, "value must be finite canonical JSON"
        ) from exc
    if len(encoded) > MAX_RUNTIME_JSON_BYTES:
        _reject(path, "runtime payload exceeds its byte bound", "TC_RUNTIME_BOUNDS")
    return json.loads(encoded.decode("ascii"))


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _exact(value: Any, required: set[str], optional: set[str], path: str) -> None:
    if type(value) is not dict:
        _reject(path, "value must be an object")
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        _reject(path, f"missing field {sorted(missing)[0]}")
    if unknown:
        _reject(path, f"unknown field {sorted(unknown)[0]}")


def _resolve_reference(reference: Any, variables: Mapping[str, Any], path: str) -> str:
    if type(reference) is str and reference:
        return reference
    if (
        type(reference) is not dict
        or set(reference) != {"expr", "name"}
        or reference.get("expr") not in {"variable", "telecommand_item"}
        or type(reference.get("name")) is not str
    ):
        _reject(path, "reference is not a direct string variable")
    name = reference["name"]
    value = variables.get(name)
    if type(value) is not str or not value:
        _reject(path, f"variable {name!r} has no string checkpoint value")
    return value


def _item_spec(
    item: CommandItem,
    *,
    args: Any,
    modifiers: Mapping[str, Any],
    origin_target: str,
    origin_step_index: int,
) -> dict[str, Any]:
    body = {
        "schema_version": ITEM_SCHEMA_VERSION,
        "name": item.name,
        "args": _canonical(args, "$.item.args"),
        "modifiers": _canonical(dict(modifiers), "$.item.modifiers"),
        "catalog_digest": item.catalog_digest,
        "item_digest": item.item_digest,
        "origin_target": origin_target,
        "origin_step_index": origin_step_index,
    }
    return {**body, "envelope_digest": _digest(body)}


def encode_built_item(
    command: str,
    args: Any,
    modifiers: Mapping[str, Any],
    *,
    origin_target: str,
    origin_step_index: int,
    catalog: TelecommandCatalog | None = None,
) -> str:
    if type(origin_target) is not str or not origin_target or type(origin_step_index) is not int:
        _reject("$.item.origin", "command item origin is invalid")
    selected_catalog = catalog or default_catalog()
    item = BuildTC(command, args, modifiers=modifiers, catalog=selected_catalog)
    payload = _item_spec(
        item,
        args=args,
        modifiers=modifiers,
        origin_target=origin_target,
        origin_step_index=origin_step_index,
    )
    return ITEM_PREFIX + json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _decode_item_spec(
    value: Any,
    *,
    catalog: TelecommandCatalog,
    path: str,
) -> tuple[CommandItem, dict[str, Any]]:
    if type(value) is str and value.startswith(ITEM_PREFIX):
        try:
            payload = json.loads(value[len(ITEM_PREFIX) :])
        except (RecursionError, TypeError, ValueError) as exc:
            raise TelecommandRuntimeError(
                "TC_COMMAND_ITEM_INVALID", path, "command item JSON is invalid"
            ) from exc
    elif type(value) is dict:
        payload = value
    else:
        _reject(path, "command item is invalid", "TC_COMMAND_ITEM_INVALID")
    _exact(
        payload,
        {
            "schema_version",
            "name",
            "args",
            "modifiers",
            "catalog_digest",
            "item_digest",
            "origin_target",
            "origin_step_index",
            "envelope_digest",
        },
        set(),
        path,
    )
    if payload["schema_version"] != ITEM_SCHEMA_VERSION:
        _reject(path, "command item schema is unsupported", "TC_COMMAND_ITEM_INVALID")
    envelope_body = {
        key: value for key, value in payload.items() if key != "envelope_digest"
    }
    if (
        type(payload["envelope_digest"]) is not str
        or payload["envelope_digest"] != _digest(envelope_body)
    ):
        _reject(path, "command item envelope digest is invalid", "TC_COMMAND_ITEM_INVALID")
    if payload["catalog_digest"] != catalog.digest:
        _reject(path, "command item catalog digest changed", "TC_COMMAND_ITEM_INVALID")
    if type(payload["item_digest"]) is not str or _HEX_DIGEST.fullmatch(
        payload["item_digest"]
    ) is None:
        _reject(path, "command item digest is invalid", "TC_COMMAND_ITEM_INVALID")
    if (
        type(payload["origin_target"]) is not str
        or not payload["origin_target"]
        or type(payload["origin_step_index"]) is not int
        or payload["origin_step_index"] < 0
    ):
        _reject(path, "command item origin is invalid", "TC_COMMAND_ITEM_INVALID")
    item = BuildTC(
        payload["name"],
        payload["args"],
        modifiers=payload["modifiers"],
        catalog=catalog,
    )
    if item.item_digest != payload["item_digest"]:
        _reject(path, "command item content does not match its digest", "TC_COMMAND_ITEM_INVALID")
    return item, _canonical(payload, path)


def build_item_checkpoint_for_step(
    step: Mapping[str, Any],
    variables: Mapping[str, Any],
    *,
    catalog: TelecommandCatalog | None = None,
) -> str:
    if type(step) is not dict or step.get("type") != "build_tc":
        _reject("$.step", "BuildTC runtime requires a build_tc step")
    command = _resolve_reference(step.get("command"), variables, "$.step.command")
    return encode_built_item(
        command,
        step.get("arguments", {}),
        step.get("modifiers", {}),
        origin_target=step["target"],
        origin_step_index=step["index"],
        catalog=catalog,
    )


def _selector_value(
    reference: Any,
    variables: Mapping[str, Any],
    catalog: TelecommandCatalog,
    path: str,
) -> tuple[str | CommandItem, dict[str, Any]]:
    resolved = _resolve_reference(reference, variables, path)
    item_reference = (
        type(reference) is dict and reference.get("expr") == "telecommand_item"
    )
    if item_reference:
        if not resolved.startswith(ITEM_PREFIX):
            _reject(
                path,
                "opaque telecommand item checkpoint was replaced",
                "TC_COMMAND_ITEM_INVALID",
            )
        item, spec = _decode_item_spec(resolved, catalog=catalog, path=path)
        if spec["origin_target"] != reference.get("name"):
            _reject(
                path,
                "telecommand item origin does not match its IR target",
                "TC_COMMAND_ITEM_INVALID",
            )
        return item, {"kind": "item", "value": spec}
    if resolved.startswith(ITEM_PREFIX):
        _reject(
            path,
            "opaque telecommand item requires an item-bound IR reference",
            "TC_COMMAND_ITEM_INVALID",
        )
    return resolved, {"kind": "name", "value": resolved}


def _service_request(
    *,
    operation_id: str,
    selector_kind: str,
    selected: Any,
    arguments: Any,
    modifiers: Mapping[str, Any],
) -> SendRequest:
    raw_modifiers = dict(modifiers)
    block = raw_modifiers.pop("block", False)
    if selector_kind == "command":
        return SendRequest(
            operation_id=operation_id,
            command=selected,
            args=arguments,
            modifiers=raw_modifiers,
            block=block,
        )
    if selector_kind == "sequence":
        return SendRequest(
            operation_id=operation_id,
            sequence=selected,
            modifiers=raw_modifiers,
            block=block,
        )
    if selector_kind == "group":
        return SendRequest(
            operation_id=operation_id,
            group=selected,
            modifiers=raw_modifiers,
            block=block,
        )
    _reject("$.selector.kind", "selector kind is invalid")


def confirmation_prompt_id(
    execution_id: str, step_index: int, plan_digest: str
) -> str:
    if (
        type(execution_id) is not str
        or not execution_id
        or type(step_index) is not int
        or step_index < 0
        or type(plan_digest) is not str
        or _HEX_DIGEST.fullmatch(plan_digest) is None
    ):
        _reject("$.confirmation", "confirmation plan identity is invalid")
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "openbexi-spell:telecommand-confirmation:"
            f"{execution_id}:{step_index}:{plan_digest}",
        )
    )


def failure_prompt_id(
    execution_id: str, step_index: int, result_digest: str
) -> str:
    if (
        type(execution_id) is not str
        or not execution_id
        or type(step_index) is not int
        or step_index < 0
        or type(result_digest) is not str
        or _HEX_DIGEST.fullmatch(result_digest) is None
    ):
        _reject("$.failure_prompt", "failure result identity is invalid")
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "openbexi-spell:telecommand-failure:"
            f"{execution_id}:{step_index}:{result_digest}",
        )
    )


def failure_prompt_question(result_digest: str) -> str:
    if type(result_digest) is not str or _HEX_DIGEST.fullmatch(result_digest) is None:
        _reject("$.failure_prompt", "failure result digest is invalid")
    return (
        "Continue procedure after unsuccessful deterministic simulator "
        f"telecommand result {result_digest[:16]}?"
    )


def prepare_send_request(
    execution_id: str,
    step_index: int,
    step: Mapping[str, Any],
    variables: Mapping[str, Any],
    *,
    confirmation: Mapping[str, Any] | None = None,
    catalog: TelecommandCatalog | None = None,
) -> tuple[dict[str, Any], TelecommandService, Preflight]:
    if type(execution_id) is not str or not execution_id:
        _reject("$.execution_id", "execution identity is invalid")
    if type(step_index) is not int or step_index < 0:
        _reject("$.step_index", "step index is invalid")
    if type(step) is not dict or step.get("type") != "send_tc":
        _reject("$.step", "Send runtime requires a send_tc step")
    selector = step.get("selector")
    _exact(selector, {"kind", "value"}, set(), "$.step.selector")
    selector_kind = selector["kind"]
    selected: Any
    selector_spec: dict[str, Any]
    selected_value = selector["value"]
    selected_catalog = catalog or default_catalog()
    if selector_kind == "command":
        selected, selector_spec = _selector_value(
            selected_value, variables, selected_catalog, "$.step.selector.value"
        )
    elif selector_kind == "sequence":
        selected = _resolve_reference(
            selected_value, variables, "$.step.selector.value"
        )
        selector_spec = {"kind": "name", "value": selected}
    elif selector_kind == "group":
        if type(selected_value) is not list or not selected_value:
            _reject("$.step.selector.value", "group selector is invalid")
        selected = []
        specs = []
        for index, reference in enumerate(selected_value):
            item, spec = _selector_value(
                reference,
                variables,
                selected_catalog,
                f"$.step.selector.value[{index}]",
            )
            selected.append(item)
            specs.append(spec)
        selector_spec = {"kind": "group", "value": specs}
    else:
        _reject("$.step.selector.kind", "selector kind is invalid")

    operation_id = "tc-op-" + uuid.uuid5(
        _OPERATION_NAMESPACE, f"{execution_id}:{step_index}"
    ).hex
    request_id = str(
        uuid.uuid5(_REQUEST_NAMESPACE, f"{execution_id}:{step_index}")
    )
    arguments = _canonical(step.get("arguments", {}), "$.step.arguments")
    modifiers = _canonical(step.get("modifiers", {}), "$.step.modifiers")
    service = TelecommandService(selected_catalog)
    preflight = service.preflight(
        _service_request(
            operation_id=operation_id,
            selector_kind=selector_kind,
            selected=selected,
            arguments=arguments,
            modifiers=modifiers,
        )
    )
    if confirmation is not None:
        _exact(
            confirmation,
            {"prompt_id"},
            set(),
            "$.confirmation",
        )
        if not all(type(confirmation[name]) is str and confirmation[name] for name in confirmation):
            _reject("$.confirmation", "confirmation identity is invalid")
        confirmation = _canonical(dict(confirmation), "$.confirmation")
    if preflight.confirmation_required:
        if confirmation is not None and confirmation["prompt_id"] != confirmation_prompt_id(
            execution_id, step_index, preflight.plan.plan_digest
        ):
            _reject(
                "$.confirmation.prompt_id",
                "confirmation prompt does not bind this telecommand plan",
                "TC_CONFIRMATION_INVALID",
            )
    elif confirmation is not None:
        _reject(
            "$.confirmation",
            "confirmation evidence is not valid for an unconfirmed plan",
            "TC_CONFIRMATION_INVALID",
        )
    body = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": request_id,
        "operation_id": operation_id,
        "execution_id": execution_id,
        "step_index": step_index,
        "selector_kind": selector_kind,
        "selector": selector_spec,
        "arguments": arguments,
        "modifiers": modifiers,
        "confirmation": confirmation,
        "catalog_digest": preflight.plan.catalog_digest,
        "policy_digest": preflight.plan.policy_digest,
        "plan": preflight.plan.as_dict(),
    }
    payload = {**body, "request_digest": _digest(body)}
    return _canonical(payload, "$request"), service, preflight


def validate_send_request(
    execution_id: str,
    step_index: int,
    step: Mapping[str, Any],
    variables: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    catalog: TelecommandCatalog | None = None,
) -> tuple[dict[str, Any], TelecommandService, Preflight]:
    _exact(
        payload,
        {
            "schema_version",
            "request_id",
            "operation_id",
            "execution_id",
            "step_index",
            "selector_kind",
            "selector",
            "arguments",
            "modifiers",
            "confirmation",
            "catalog_digest",
            "policy_digest",
            "plan",
            "request_digest",
        },
        set(),
        "$request",
    )
    if payload.get("schema_version") != REQUEST_SCHEMA_VERSION:
        _reject("$request.schema_version", "request schema is unsupported")
    expected, service, preflight = prepare_send_request(
        execution_id,
        step_index,
        step,
        variables,
        confirmation=payload.get("confirmation"),
        catalog=catalog,
    )
    if _canonical(dict(payload), "$request") != expected:
        _reject(
            "$request",
            "request differs from authoritative IR or checkpoint variables",
            "TC_RUNTIME_TAMPERED",
        )
    return expected, service, preflight


def confirmation_for_preflight(
    service: TelecommandService,
    preflight: Preflight,
    *,
    actor: str | None,
    reason: str,
) -> Confirmation | None:
    if not preflight.confirmation_required:
        return None
    if type(actor) is not str or not actor:
        _reject(
            "$.confirmation",
            "durable operator confirmation is required",
            "TC_CONFIRMATION_REQUIRED",
        )
    return service.confirm(preflight, actor=actor, reason=reason)


def result_payload(
    request: Mapping[str, Any],
    snapshot: ExecutionSnapshot,
    *,
    outcome: str = "SETTLED",
) -> dict[str, Any]:
    if outcome not in {"SETTLED", "UNCERTAIN"}:
        _reject("$.outcome", "telecommand result outcome is invalid")
    checkpoint = snapshot.as_checkpoint()
    body = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_id": request["request_id"],
        "operation_id": request["operation_id"],
        "request_digest": request["request_digest"],
        "plan_digest": snapshot.plan.plan_digest,
        "outcome": outcome,
        "successful": snapshot.successful,
        "execution_succeeded": snapshot.execution_succeeded,
        "verification_succeeded": snapshot.verification_succeeded,
        "checkpoint": checkpoint,
    }
    return _canonical({**body, "result_digest": _digest(body)}, "$result")


def validate_result_payload(
    request: Mapping[str, Any], payload: Mapping[str, Any]
) -> dict[str, Any]:
    _exact(
        payload,
        {
            "schema_version",
            "request_id",
            "operation_id",
            "request_digest",
            "plan_digest",
            "outcome",
            "successful",
            "execution_succeeded",
            "verification_succeeded",
            "checkpoint",
            "result_digest",
        },
        set(),
        "$result",
    )
    detached = _canonical(dict(payload), "$result")
    claimed = detached.pop("result_digest")
    if type(claimed) is not str or claimed != _digest(detached):
        _reject("$result.result_digest", "result digest is invalid", "TC_RESULT_INVALID")
    for name in ("request_id", "operation_id", "request_digest"):
        if detached[name] != request[name]:
            _reject(f"$result.{name}", "result identity differs", "TC_RESULT_INVALID")
    if detached["plan_digest"] != request["plan"]["plan_digest"]:
        _reject("$result.plan_digest", "result plan differs", "TC_RESULT_INVALID")
    if detached["schema_version"] != RESULT_SCHEMA_VERSION or detached["outcome"] not in {
        "SETTLED",
        "UNCERTAIN",
    }:
        _reject("$result", "result schema or outcome is invalid", "TC_RESULT_INVALID")
    if any(type(detached[name]) is not bool for name in (
        "successful",
        "execution_succeeded",
        "verification_succeeded",
    )):
        _reject("$result", "result flags are invalid", "TC_RESULT_INVALID")
    service, preflight = preflight_from_request(request)
    recovered = service.recover(preflight.plan, detached["checkpoint"])
    derived = {
        "successful": recovered.successful,
        "execution_succeeded": recovered.execution_succeeded,
        "verification_succeeded": recovered.verification_succeeded,
    }
    if any(detached[name] != value for name, value in derived.items()):
        _reject(
            "$result",
            "result flags contradict the validated checkpoint",
            "TC_RESULT_INVALID",
        )
    if detached["outcome"] == "SETTLED" and not recovered.settled:
        _reject(
            "$result.outcome",
            "settled result has a nonterminal checkpoint",
            "TC_RESULT_INVALID",
        )
    if detached["outcome"] == "UNCERTAIN" and (
        recovered.settled
        or not any(
            item.effect_certainty.value in {"EFFECT_POSSIBLE", "EFFECT_UNKNOWN"}
            for item in recovered.elements
        )
    ):
        _reject(
            "$result.outcome",
            "uncertain result lacks a nonterminal uncertain checkpoint",
            "TC_RESULT_INVALID",
        )
    return {**detached, "result_digest": claimed}


def result_failure_policy(
    request: Mapping[str, Any], payload: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Return the authoritative procedure-level policy for a terminal result."""

    result = validate_result_payload(request, payload)
    accepted = {"LOADED_ONLY", "EXECUTED_UNVERIFIED", "VERIFIED"}
    checkpoint_elements = result["checkpoint"]["elements"]
    failed_indexes = [
        index
        for index, element in enumerate(checkpoint_elements)
        if element["disposition"] not in accepted
        and element["disposition"] != "CANCELLED"
    ]
    if not failed_indexes and all(
        element["disposition"] in accepted for element in checkpoint_elements
    ):
        return None
    uncertain = result["outcome"] != "SETTLED" or any(
        element["disposition"] == "UNCERTAIN"
        or (
            element["disposition"] not in accepted
            and element["effect_certainty"]
            in {"EFFECT_POSSIBLE", "EFFECT_UNKNOWN"}
        )
        for element in checkpoint_elements
    )
    if not failed_indexes:
        failed_indexes = [
            index
            for index, element in enumerate(checkpoint_elements)
            if element["disposition"] not in accepted
        ]
    priority = {"CONTINUE": 0, "CANCEL": 1, "ABORT": 2}
    actions = [
        request["plan"]["elements"][index]["effective_modifiers"]["on_failure"]
        for index in failed_indexes
    ]
    action = max(actions, key=priority.__getitem__) if actions else "ABORT"
    winning_indexes = [
        index
        for index in failed_indexes
        if request["plan"]["elements"][index]["effective_modifiers"][
            "on_failure"
        ]
        == action
    ]
    prompt_user = bool(winning_indexes) and all(
        request["plan"]["elements"][index]["effective_modifiers"]["prompt_user"]
        for index in winning_indexes
    )
    return {
        "action": action,
        "failed_element_ids": [
            checkpoint_elements[index]["element_id"] for index in failed_indexes
        ],
        "prompt_user": prompt_user,
        "uncertain": uncertain,
    }


def preflight_from_request(
    request: Mapping[str, Any],
    *,
    catalog: TelecommandCatalog | None = None,
) -> tuple[TelecommandService, Preflight]:
    selected_catalog = catalog or default_catalog()
    selector_kind = request.get("selector_kind")
    selector = request.get("selector")
    if type(selector) is not dict:
        _reject("$request.selector", "request selector is invalid")
    if selector_kind == "command":
        if selector.get("kind") == "name":
            selected: Any = selector.get("value")
        elif selector.get("kind") == "item":
            selected, _ = _decode_item_spec(
                selector.get("value"),
                catalog=selected_catalog,
                path="$request.selector.value",
            )
        else:
            _reject("$request.selector", "command selector is invalid")
    elif selector_kind == "sequence":
        if selector.get("kind") != "name":
            _reject("$request.selector", "sequence selector is invalid")
        selected = selector.get("value")
    elif selector_kind == "group":
        if selector.get("kind") != "group" or type(selector.get("value")) is not list:
            _reject("$request.selector", "group selector is invalid")
        selected = []
        for index, item in enumerate(selector["value"]):
            if type(item) is not dict or item.get("kind") not in {"name", "item"}:
                _reject(f"$request.selector.value[{index}]", "group item is invalid")
            if item["kind"] == "name":
                selected.append(item.get("value"))
            else:
                built, _ = _decode_item_spec(
                    item.get("value"),
                    catalog=selected_catalog,
                    path=f"$request.selector.value[{index}].value",
                )
                selected.append(built)
    else:
        _reject("$request.selector_kind", "request selector kind is invalid")
    service = TelecommandService(selected_catalog)
    preflight = service.preflight(
        _service_request(
            operation_id=request.get("operation_id"),
            selector_kind=selector_kind,
            selected=selected,
            arguments=request.get("arguments"),
            modifiers=request.get("modifiers") or {},
        )
    )
    if preflight.plan.as_dict() != request.get("plan"):
        _reject(
            "$request.plan",
            "request plan does not match its canonical preflight",
            "TC_RUNTIME_TAMPERED",
        )
    return service, preflight


def execute_preflight(
    request: Mapping[str, Any],
    service: TelecommandService,
    preflight: Preflight,
    *,
    confirmation_actor: str | None = None,
    confirmation_reason: str = "approved by durable supervisor prompt",
    provider: DeterministicScriptedProvider | None = None,
) -> dict[str, Any]:
    confirmation = confirmation_for_preflight(
        service,
        preflight,
        actor=confirmation_actor,
        reason=confirmation_reason,
    )
    snapshot = service.start(preflight, confirmation)
    selected_provider = provider or DeterministicScriptedProvider.nominal(
        preflight.plan
    )
    settled = service.run(snapshot, selected_provider)
    return result_payload(request, settled)


def uncertain_replay_result(
    request: Mapping[str, Any],
    service: TelecommandService,
    preflight: Preflight,
    *,
    confirmation_actor: str | None = None,
    confirmation_reason: str = "approved by durable supervisor prompt",
) -> dict[str, Any]:
    confirmation = confirmation_for_preflight(
        service,
        preflight,
        actor=confirmation_actor,
        reason=confirmation_reason,
    )
    accepted = service.start(preflight, confirmation)
    recovered = service.recover(preflight.plan, accepted.as_checkpoint())
    provider = DeterministicScriptedProvider([], reconciliation_mode="UNKNOWN")
    uncertain = service.reconcile(recovered, provider)
    return result_payload(request, uncertain, outcome="UNCERTAIN")


__all__ = [
    "ITEM_PREFIX",
    "REQUEST_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "TelecommandRuntimeError",
    "build_item_checkpoint_for_step",
    "confirmation_prompt_id",
    "confirmation_for_preflight",
    "encode_built_item",
    "execute_preflight",
    "failure_prompt_id",
    "failure_prompt_question",
    "prepare_send_request",
    "preflight_from_request",
    "result_failure_policy",
    "result_payload",
    "uncertain_replay_result",
    "validate_result_payload",
    "validate_send_request",
]
