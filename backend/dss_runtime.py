"""Parent-only actual DSS provider. No credential or endpoint enters worker IR."""
from __future__ import annotations

import hashlib
import time
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from types import MappingProxyType, SimpleNamespace
from typing import Any

from dss.catalog import DATABASE_DIGEST, DATABASE_REVISION
from dss.packets import decode_tm
from spell.driver.dss.v1 import dss_pb2
from spell.driver.v1 import driver_pb2
from .telecommand_v11 import ElementStage, ProviderOutcome, ReconciliationReport, SendModifiers, TypedArgument, _resolve_clock_expression, _encode_argument


class DssRuntimeError(RuntimeError):
    pass


def captured_observation_epochs(session: Any, result: dict[str, Any]) -> frozenset[str]:
    """Recover immutable physical epochs from durable read/evaluation evidence."""
    evidence = result.get("evidence") or {}
    if result.get("operation") == "GET_TM":
        if evidence.get("source_id") != "dss-GENERIC" or type(evidence.get("source_epoch")) is not str:
            raise DssRuntimeError("DSS observation dependency has no captured physical epoch")
        return frozenset({evidence["source_epoch"]})
    from .condition_models import ConditionEvaluationRecord
    from .observation_models import TelemetrySample
    evaluation_id = evidence.get("terminal_evaluation_id") or evidence.get("last_evaluation_id")
    evaluation = session.get(ConditionEvaluationRecord, evaluation_id) if type(evaluation_id) is str else None
    if evaluation is None or not evaluation.consumed_sample_ids:
        raise DssRuntimeError("DSS condition dependency has no durable sample epoch")
    samples = [session.get(TelemetrySample, sample_id) for sample_id in evaluation.consumed_sample_ids]
    if any(sample is None or sample.source_id != "dss-GENERIC" for sample in samples):
        raise DssRuntimeError("DSS condition dependency sample source differs")
    return frozenset(sample.source_epoch for sample in samples)


def _argument(value: dict[str, Any]) -> Any:
    fields = {"LONG": "integer_value", "FLOAT": "float_value", "BOOLEAN": "boolean_value", "STRING": "string_value", "TIME": "string_value"}
    kind = value["value_type"]
    return dss_pb2.Argument(**{key: value[key] for key in ("name", "value_type", "value_format", "radix", "encoded")}, **{fields[kind]: value["value"]})


def _expected(value: Any) -> Any:
    kind, field = {bool: ("BOOLEAN", "boolean_value"), int: ("LONG", "integer_value"), float: ("FLOAT", "float_value"), str: ("STRING", "string_value")}[type(value)]
    return dss_pb2.Argument(value_type=kind, **{field: value})


class DssRuntime:
    def __init__(self, gateway: Any):
        self.gateway = gateway

    def _identity(self, context_id: str | None = None) -> Any:
        generations = getattr(self.gateway, "dss_observation_generations", self.gateway.observation_generations)
        available = generations()
        generation = available["host"]
        if context_id is not None:
            generation = next((item for item in available["contexts"] if item.context_id == context_id), None)
            if generation is None:
                raise DssRuntimeError("DSS context is not admitted")
        return driver_pb2.ObservationRequestIdentity(
            contract_version=driver_pb2.ContractVersion(major=1, minor=0),
            server_profile_id=generation.server_profile_id,
            driver_host_generation=generation.driver_host_generation,
            host_profile_digest=generation.host_profile_digest,
            context_id=generation.context_id or "",
            context_generation=generation.context_generation or "",
            context_binding_digest=generation.context_binding_digest or "",
            observation_id=str(uuid.uuid4()), correlation_id="dss-runtime",
            credential_epoch=available["credential_epoch"], deadline_unix_ns=time.time_ns() + 5_000_000_000)

    def health(self, context_id: str | None = None, *, allow_stale: bool = False) -> dict[str, Any]:
        if context_id is not None:
            self._identity(context_id)
        result = self.gateway.dss_call("Health", dss_pb2.HealthRequest(identity=self._identity()))
        if (not result.ready and not allow_stale) or result.database_digest != DATABASE_DIGEST or result.database_revision != DATABASE_REVISION or result.satellite_id != "GENERIC":
            raise DssRuntimeError("DSS shared database or telemetry readiness differs")
        return {name: getattr(result, name) for name in ("database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id", "state_revision", "tm_sequence", "simulation_time_ns", "clock_epoch_unix_ns", "dynamics_tick")}

    def evidence(self, epoch: str, sequence: int = 0, operation_id: str = "", packet_sha256: str = "") -> list[dict[str, Any]]:
        result = self.gateway.dss_call("PacketEvidence", dss_pb2.PacketEvidenceRequest(identity=self._identity(), satellite_epoch=epoch, sequence=sequence, operation_id=operation_id, packet_sha256=packet_sha256))
        values = []
        for packet in result.packets:
            raw = bytes(packet.packet)
            body = decode_tm(raw)
            if hashlib.sha256(raw).hexdigest() != packet.packet_sha256 or body["satellite_epoch"] != epoch or body["database_digest"] != DATABASE_DIGEST:
                raise DssRuntimeError("DSS decoded packet evidence differs")
            if sequence and body["tm_sequence"] != sequence:
                raise DssRuntimeError("DSS packet sequence differs")
            if operation_id and body.get("operation_id") != operation_id:
                raise DssRuntimeError("DSS packet operation differs")
            if packet_sha256 and packet.packet_sha256 != packet_sha256:
                raise DssRuntimeError("DSS packet digest selector differs")
            values.append({"packet": raw, "packet_sha256": packet.packet_sha256, "topic": packet.topic, "partition": packet.partition, "offset": packet.offset, "received_unix_ns": packet.received_unix_ns, "body": body})
        return values

    def await_packet(self, epoch: str, packet_sha256: str, *, timeout_seconds: float = 5.0) -> list[dict[str, Any]]:
        """Join one DSS outbox identity to actual durable Kafka consumption."""
        if type(packet_sha256) is not str or len(packet_sha256) != 64 or not 0 < timeout_seconds <= 30:
            raise DssRuntimeError("DSS exact packet wait is outside its bound")
        deadline = time.monotonic() + timeout_seconds
        while True:
            packets = self.evidence(epoch, packet_sha256=packet_sha256)
            if packets:
                return packets
            if time.monotonic() >= deadline:
                raise DssRuntimeError("DSS packet was not consumed before the evidence deadline")
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))

    def await_evidence(self, epoch: str, sequence: int, operation_id: str = "", *, timeout_seconds: float = 5.0) -> list[dict[str, Any]]:
        """Wait for the exact caused telemetry packet to be durably consumed."""
        if type(sequence) is not int or sequence <= 0 or not 0 < timeout_seconds <= 30:
            raise DssRuntimeError("DSS evidence wait is outside its bound")
        deadline = time.monotonic() + timeout_seconds
        while True:
            packets = self.evidence(epoch, sequence, operation_id)
            if any(item["topic"] == "openbexi.GENERIC.tm" for item in packets):
                return packets
            if time.monotonic() >= deadline:
                raise DssRuntimeError("DSS caused telemetry was not consumed before the evidence deadline")
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))

    def provider(self, request: dict[str, Any], preflight: Any, *, procedure_id: str, context_id: str, authorize: Any = None, dispatch_lock: Any = None, observation_epochs: frozenset[str] = frozenset()) -> "DssProvider":
        return DssProvider(self, request, preflight, procedure_id, context_id, authorize, dispatch_lock, observation_epochs)

    def latest_telemetry(self, context_id: str | None = None) -> dict[str, Any]:
        health = self.health(context_id)
        values = self.evidence(health["satellite_epoch"], health["tm_sequence"])
        value = next((item for item in values if item["topic"] == "openbexi.GENERIC.tm"), None)
        if value is None:
            raise DssRuntimeError("DSS current telemetry packet is unavailable")
        return value["body"]

    def reference_command(self, name: str, args: dict[str, Any] | list[dict[str, Any]], *, execution_id: str,
        procedure_id: str, operation_id: str, context_id: str, scenario_id: str | None = None,
        authorize: Any = None, modifiers: dict[str, Any] | None = None) -> dict[str, Any]:
        """Closed parent-authored reference mapping; never arbitrary worker dispatch."""
        from dss.catalog import SatelliteDatabase, canonical, validate_command
        from .telecommand_v11 import VerificationIntent
        if name not in {"DSS.REFERENCE.SEND", "DSS.REFERENCE.SET_GROUND"}:
            raise DssRuntimeError("reference command mapping is not admitted")
        commands = args if type(args) is list else [args]
        if not 1 <= len(commands) <= 16 or any(type(item) is not dict for item in commands):
            raise DssRuntimeError("reference command list is invalid")
        original = dict(modifiers or {})
        allowed = {"load_only", "time_tag", "release_time", "time_tag_seconds", "release_time_seconds",
            "send_delay_seconds", "timeout_seconds", "confirm", "confirm_critical", "group", "block",
            "monitoring", "sequence", "post_verify", "adjust_limits", "prompt_user", "additional_information",
            "argument_source", "resolved_from", "supplied_as"}
        if set(original) - allowed:
            raise DssRuntimeError("reference command modifier is not declared")
        for key in {"load_only", "confirm", "confirm_critical", "group", "block", "post_verify", "adjust_limits", "prompt_user"} & set(original):
            if type(original[key]) is not bool:
                raise DssRuntimeError("reference Boolean modifier has the wrong type")
        for key in {"send_delay_seconds", "timeout_seconds", "time_tag_seconds", "release_time_seconds"} & set(original):
            if type(original[key]) not in {float, int} or not 0 <= original[key] <= 86_400:
                raise DssRuntimeError("reference duration is outside its closed bound")
        def timing(key):
            value = original.get(key)
            if value is None:
                seconds = original.get(key + "_seconds")
                return None if seconds is None else f"NOW+{seconds}s"
            if type(value) is not dict:
                raise DssRuntimeError("reference timing intent is invalid")
            if value.get("kind") == "NOW_PLUS_DURATION":
                return f"NOW+{value['seconds']}s"
            if value.get("kind") == "ABSOLUTE_STRING":
                return datetime.strptime(value["value"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
            raise DssRuntimeError("reference timing intent is unknown")
        effective = SendModifiers(load_only=bool(original.get("load_only", False)), time=timing("time_tag"),
            release_time=timing("release_time"), send_delay_ms=int(original.get("send_delay_seconds", 0) * 1000),
            timeout_ms=int(original.get("timeout_seconds", 60) * 1000),
            verification=((VerificationIntent("TMparam3", "lt", 10.5),) if original.get("post_verify") else ()))
        if not 0 <= effective.send_delay_ms <= 3_600_000 or not 0 < effective.timeout_ms <= 3_600_000:
            raise DssRuntimeError("reference timing duration exceeds bounds")
        definition = SatelliteDatabase.load().command(name)
        known = {item["name"]: item for item in definition["arguments"]}
        elements = []
        mode = "BLOCK" if original.get("block") else "GROUP" if original.get("group") else "SEQUENTIAL"
        group_id = "reference-group-" + hashlib.sha256(operation_id.encode()).hexdigest()[:24]
        for index, supplied in enumerate(commands):
            if set(supplied) - set(known):
                raise DssRuntimeError("reference command has unknown arguments")
            arguments = []
            for key, item in known.items():
                if key not in supplied and not item.get("has_default"):
                    if item["required"]:
                        raise DssRuntimeError("reference command argument is missing")
                    continue
                value = supplied.get(key, item.get("default"))
                kind = item["value_type"]
                if kind == "FLOAT" and type(value) in {float, int}:
                    value = float(value)
                encoded = _encode_argument(value, kind, "DEC")
                arguments.append(TypedArgument(key, kind, "ENG", "DEC", value, encoded))
            material = [argument.as_dict() for argument in arguments]
            validate_command(name, material)
            digest = hashlib.sha256(canonical({"name": name, "arguments": material, "database_digest": DATABASE_DIGEST})).hexdigest()
            element_id = "reference-" + hashlib.sha256(f"{operation_id}:{index}".encode()).hexdigest()[:32]
            command = SimpleNamespace(name=name, arguments=tuple(arguments), item_digest=digest)
            elements.append(SimpleNamespace(element_id=element_id, transport_unit_id=(group_id if mode in {"GROUP", "BLOCK"} else element_id), command=command, effective_modifiers=effective))
        plan = SimpleNamespace(plan_id="plan-" + hashlib.sha256((operation_id + execution_id).encode()).hexdigest(), operation_id=operation_id, elements=tuple(elements))
        provider = self.provider({"execution_id": execution_id}, SimpleNamespace(plan=plan), procedure_id=procedure_id, context_id=context_id, authorize=authorize)
        if scenario_id is not None and provider.identity["scenario_id"] != scenario_id:
            raise DssRuntimeError("reference command scenario differs")
        stages, transported = [], set()
        expected = {ElementStage.TRANSPORT: "ACCEPTED", ElementStage.LOADING: "LOADED", ElementStage.RELEASE: "RELEASED", ElementStage.ACKNOWLEDGEMENT: "ACKNOWLEDGED", ElementStage.ONBOARD_EXECUTION: "SUCCEEDED", ElementStage.VERIFICATION: "PASSED"}
        for element in elements:
            selected = [ElementStage.TRANSPORT, ElementStage.LOADING]
            if not effective.load_only:
                selected.extend([ElementStage.RELEASE, ElementStage.ACKNOWLEDGEMENT, ElementStage.ONBOARD_EXECUTION])
                if effective.verification:
                    selected.append(ElementStage.VERIFICATION)
            for stage in selected:
                provider_id = element.element_id
                if stage is ElementStage.TRANSPORT:
                    if element.transport_unit_id in transported:
                        continue
                    transported.add(element.transport_unit_id)
                    provider_id = element.transport_unit_id
                outcome = provider.perform(plan.plan_id, provider_id, stage)
                stages.append({"element_id": provider_id, "stage": stage.value, "outcome": outcome.outcome, "detail": dict(outcome.detail)})
                if outcome.outcome != expected[stage]:
                    raise DssRuntimeError("reference command did not achieve its declared disposition")
        return {"operation_id": operation_id, "element_id": elements[0].element_id, "stages": stages,
            "actual_mode": mode, "executed_count": 0 if effective.load_only else len(elements),
            "load_only": effective.load_only, "reference_mapping": original}


class DssProvider:
    def __init__(self, runtime: DssRuntime, request: dict[str, Any], preflight: Any, procedure_id: str, context_id: str, authorize: Any = None, dispatch_lock: Any = None, observation_epochs: frozenset[str] = frozenset()):
        self.runtime, self.request, self.plan = runtime, request, preflight.plan
        self.procedure_id, self.context_id = procedure_id, context_id
        self.identity = runtime.health(context_id)
        if observation_epochs and observation_epochs != frozenset({self.identity["satellite_epoch"]}):
            raise DssRuntimeError("DSS command guard observation belongs to a retired satellite epoch")
        self.calls: list[dict[str, Any]] = []
        self._journal: dict[str, dict[str, ProviderOutcome]] = {}
        self._started = time.monotonic()
        self._loaded: dict[str, int] = {}
        self._authorize = authorize or (lambda: True)
        self._dispatch_lock = dispatch_lock or nullcontext()

    def perform(self, plan_id: str, element_id: str, stage: ElementStage) -> ProviderOutcome:
        if self._authorize() is False:
            raise DssRuntimeError("DSS execution authority is no longer active")
        if plan_id != self.plan.plan_id:
            raise DssRuntimeError("DSS plan identity differs")
        elements = [item for item in self.plan.elements if item.element_id == element_id or (stage is ElementStage.TRANSPORT and item.transport_unit_id == element_id)]
        if not elements:
            raise DssRuntimeError("DSS element is not in the authoritative plan")
        element = elements[0]
        modifiers = element.effective_modifiers
        started = time.monotonic()
        fields = {name: self.identity[name] for name in ("database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id")}
        fields.update(operation_id=self.plan.operation_id, procedure_id=self.procedure_id, execution_id=self.request["execution_id"], plan_id=plan_id, element_id=element_id, stage=stage.value, command_name=element.command.name, command_digest=element.command.item_digest)
        extra: dict[str, Any] = {}
        if stage in {ElementStage.TRANSPORT, ElementStage.RELEASE}:
            anchor = self.identity["simulation_time_ns"]
            clock_epoch = self.identity["clock_epoch_unix_ns"]
            clock_expression = modifiers.time if stage is ElementStage.TRANSPORT else modifiers.release_time
            resolved = _resolve_clock_expression(clock_expression, (clock_epoch + anchor) // 1_000_000)
            target = anchor + modifiers.send_delay_ms * 1_000_000 if stage is ElementStage.TRANSPORT else self._loaded.get(element_id, anchor) + modifiers.delay_ms * 1_000_000
            if resolved is not None:
                target = max(target, resolved * 1_000_000 - clock_epoch)
            extra["scheduling"] = dss_pb2.Scheduling(target_sim_time_ns=max(0, target), anchor_sim_time_ns=anchor,
                clock_epoch_unix_ns=clock_epoch, send_delay_ms=modifiers.send_delay_ms, delay_ms=modifiers.delay_ms,
                **({"time": modifiers.time} if modifiers.time is not None else {}),
                **({"release_time": modifiers.release_time} if modifiers.release_time is not None else {}))
        if len(elements) > 1:
            extra["elements"] = [dss_pb2.CommandElement(element_id=item.element_id, command_name=item.command.name, command_digest=item.command.item_digest, arguments=[_argument(arg.as_dict()) for arg in item.command.arguments]) for item in elements]
        if stage is ElementStage.VERIFICATION:
            extra["verification"] = [dss_pb2.Verification(channel=intent.channel, operator=intent.operator, expected=_expected(intent.expected), **({"tolerance": intent.tolerance} if intent.tolerance is not None else {}), **({"timeout_ms": intent.timeout_ms} if intent.timeout_ms is not None else {})) for intent in modifiers.verification]
            extra["tolerance"] = modifiers.tolerance
        with self._dispatch_lock:
            identity = self.runtime._identity(self.context_id)
            if self._authorize() is False:
                raise DssRuntimeError("DSS execution authority changed before command dispatch")
            result = self.runtime.gateway.dss_call("CommandStage", dss_pb2.CommandStageRequest(identity=identity, **fields,
                arguments=[_argument(arg.as_dict()) for arg in element.command.arguments], **extra), authorize=self._authorize)
        if result.status != "SETTLED":
            raise DssRuntimeError("DSS command dispatch is uncertain")
        raw = bytes(result.acknowledgement_packet)
        ack = decode_tm(raw)
        if hashlib.sha256(raw).hexdigest() != result.acknowledgement_packet_sha256 or any(ack.get(name) != value for name, value in fields.items()):
            raise DssRuntimeError("DSS acknowledgement does not bind its command")
        if stage is ElementStage.LOADING:
            self._loaded[element_id] = ack["simulation_time_ns"]
        evidence = []
        if stage in {ElementStage.ONBOARD_EXECUTION, ElementStage.VERIFICATION} and ack["outcome"] in {"SUCCEEDED", "PASSED"}:
            deadline = time.monotonic() + min(5.0, modifiers.timeout_ms / 1000)
            while time.monotonic() < deadline:
                evidence = [item for item in self.runtime.evidence(self.identity["satellite_epoch"], ack["tm_sequence"]) if item["topic"] == "openbexi.GENERIC.tm" and item["body"]["state_revision"] >= ack["state_revision"]]
                if evidence:
                    break
                time.sleep(0.025)
            if not evidence:
                raise DssRuntimeError("DSS command has no decoded Kafka telemetry evidence")
        detail = {"provider": "dss-cortex-kafka", "database_digest": DATABASE_DIGEST, "satellite_epoch": self.identity["satellite_epoch"], "scenario_id": self.identity["scenario_id"], "state_revision": ack["state_revision"], "tm_sequence": ack["tm_sequence"], "simulation_time_ns": ack["simulation_time_ns"], "dynamics_tick": ack["dynamics_tick"], "command_packet_sha256": result.command_packet_sha256, "acknowledgement_packet_sha256": result.acknowledgement_packet_sha256, "telemetry": [{key: item[key] for key in ("packet_sha256", "topic", "partition", "offset")} for item in evidence]}
        outcome = ProviderOutcome(stage, ack["outcome"], MappingProxyType(detail), min(86_400_000, int((time.monotonic() - started) * 1000)))
        self._journal.setdefault(element_id, {})[stage.value] = outcome
        self.calls.append({"plan_id": plan_id, "element_id": element_id, "stage": stage.value, "outcome": outcome.outcome, "detail": detail})
        return outcome

    def reconcile(self, plan_id: str, element_id: str) -> ReconciliationReport:
        # Never dispatch on recovery. The outer durable supervisor intent governs
        # reconciliation; an absent locally observed acknowledgement stays unknown.
        known = self._journal.get(element_id, {}) if plan_id == self.plan.plan_id else {}
        return ReconciliationReport(bool(known), MappingProxyType(dict(known)), MappingProxyType({"provider": "dss-cortex-kafka", "certainty": "JOURNALED" if known else "UNKNOWN"}))
