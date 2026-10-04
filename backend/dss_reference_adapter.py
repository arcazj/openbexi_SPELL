"""Declared reference adaptations backed by actual DSS CMD/TLM where applicable.

The original local language/file/operator examples still execute their bounded
handlers. Logical reference timestamps and source-form labels are preserved as
adaptation semantics; actual packet times and physical mappings are separate
evidence and are never presented as native execution of the manual snippets.
"""
from __future__ import annotations

import json
from pathlib import Path
import time
import uuid

from . import reference_examples_v10 as reference

CONTRACT = Path(__file__).resolve().parents[1] / "contracts/dss/reference_adapters_v19.json"


class DssReferenceSimulator(reference._Simulator):
    def __init__(self, executor, state):
        super().__init__()
        self.executor, self.state = executor, state
        contract = json.loads(CONTRACT.read_bytes())
        self.operations = contract["operations"]
        self.aliases = contract["telemetry_aliases"]

    def record(self, operation, inputs, output, *, variant_id=None):
        if operation not in self.operations:
            raise ValueError("reference operation lacks a reviewed DSS mapping: " + operation)
        self.executor.authorize()
        if operation == "SetGroundParameter":
            if inputs != {"name":"TMparam", "value":23}:
                raise ValueError("ground parameter adaptation is outside the closed mapping")
            self._command("DSS.REFERENCE.SET_GROUND", {"PARAMETER":"TMparam", "VALUE":23.0}, {})
        return super().record(operation, inputs, output, variant_id=variant_id)

    def _command(self, name, arguments, modifiers):
        operation_id = str(uuid.uuid5(uuid.UUID(self.state["scenario_id"]),
            "reference-wire:" + str(len(self.executor.reference_mappings))))
        result = self.executor.runtime.reference_command(name, arguments,
            execution_id=self.state["scenario_id"], procedure_id="language_reference_244",
            operation_id=operation_id, context_id=self.executor.context_id,
            scenario_id=self.state["scenario_id"], authorize=self.executor.authorize,
            modifiers=modifiers)
        self.executor.reference_mappings.append({"logical_trace_sequence":len(self.trace) + 1,
            "physical_command":name, "arguments":arguments, "modifiers":modifiers, "actual":result})

    def get_tm(self, name, *, raw=False, extended=False, wait=False, timeout=None):
        if name not in self.aliases:
            raise ValueError("reference telemetry alias is undeclared: " + name)
        self.executor.authorize()
        before = self.executor.runtime.latest_telemetry(self.executor.context_id)
        if wait:
            state = self.executor._http("/state")
            if not state["running"]:
                self.executor._http("/control", {"action":"STEP", "expected_epoch":state["epoch"],
                    "expected_revision":state["revision"], "ticks":1})
        deadline = time.monotonic() + 5
        while True:
            body = self.executor.runtime.latest_telemetry(self.executor.context_id)
            if body["satellite_epoch"] != self.state["epoch"]:
                raise ValueError("reference telemetry crossed a DSS epoch")
            if not wait or body["tm_sequence"] > before["tm_sequence"]:
                break
            if time.monotonic() >= deadline:
                raise ValueError("reference next-sample request did not receive actual DSS telemetry")
            time.sleep(0.025)
        item = next((row for row in body["items"] if row["item_id"] == self.aliases[name]["item_id"]), None)
        if item is None or item["validity"] != "VALID" or item["quality"] != "GOOD":
            raise ValueError("reference telemetry has no valid decoded DSS sample")
        self.executor.reference_reads.append({"logical_trace_sequence":len(self.trace)+1,"item_id":name,
            "tm_sequence":body["tm_sequence"],"source_epoch":body["satellite_epoch"],
            "field":"raw" if raw else "engineering","selected_value":item["raw" if raw else "engineering"]})
        prior = self.telemetry[name]
        for field, packet_field in (("eng","engineering"), ("raw","raw")):
            value = item[packet_field]["value"]
            # The original ground-parameter adaptation uses an integer. This
            # declared exact conversion does not fabricate or round a sample.
            if type(prior[field]) is int and type(value) is float and value.is_integer():
                value = int(value)
            prior[field] = value
        return super().get_tm(name, raw=raw, extended=extended, wait=wait, timeout=timeout)

    def send(self, commands, *, variant_id=None, source_form=None, **modifiers):
        commands = [dict(command) for command in commands]
        if not 1 <= len(commands) <= 16 or any(command.get("item_id") != "TC.SIMULATOR.RESET" for command in commands):
            raise ValueError("reference command selector is outside its declared mapping")
        self._command("DSS.REFERENCE.SEND", [command["arguments"] for command in commands], modifiers)
        return super().send(commands, variant_id=variant_id, source_form=source_form, **modifiers)


def execute_adaptation(number, executor, state):
    registry = reference.ReferenceExampleRegistry.from_contract()
    simulator = DssReferenceSimulator(executor, state)
    execution = reference._Execution(registry.contract(number), registry.variant_contract(number), simulator)
    reference._HANDLERS[execution.contract.handler_family](execution)
    reference._exercise_variant_contract(execution)
    result = execution.finish()
    if not result.passed:
        raise ValueError(f"adaptation:{number:03}: actual DSS-backed assertions failed")
    return result.as_dict()
