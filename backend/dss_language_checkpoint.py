"""Parent-owned state for the closed DSS source-case worker, without execution or I/O."""
from __future__ import annotations

from .dss_language_broker import canonical


class ClosedCaseCheckpoints:
    def __init__(self, steps):
        self.steps = steps
        self.cursor = 0
        self.variables = {}

    def admit(self, message):
        index = message.get("step_index")
        if (type(index) is not int or index != self.cursor or not 0 <= index < len(self.steps)
                or type(message.get("generation")) is not int or message["generation"] != 1):
            raise ValueError("DSS inner message is outside its authoritative source cursor")
        step = self.steps[index]
        kind = message["kind"]
        expected = {"observation_requested":{"get_tm", "verify", "wait_for"},
            "telecommand_requested":{"send_tc"}, "prompt_opened":{"prompt", "send_tc"}}
        if kind in expected and step["type"] not in expected[kind]:
            raise ValueError("DSS inner request substitutes another source instruction")
        return step

    def commit(self, message, *, settlement=None, observation_result=None):
        from .worker import evaluate_expression
        from .prompt_v17 import PROMPT_PROFILE, native_prompt_result
        from .runtime_composition_v19 import observation_checkpoint_variables
        from .telecommand_runtime_v11 import build_item_checkpoint_for_step
        step = self.admit(message)
        if type(message.get("next_step")) is not int or message["next_step"] != self.cursor + 1:
            raise ValueError("DSS inner checkpoint is not contiguous")
        values = dict(self.variables)
        enabled = True if step.get("guard") is None else evaluate_expression(step["guard"], values)
        if type(enabled) is not bool:
            raise ValueError("DSS inner source guard is not Boolean")
        complete = {"event_type":"step.completed", "source":"worker", "severity":"info",
            "payload":{"step_index":self.cursor, "line":step["line"], "step_type":step["type"], "skipped":not enabled}}
        effects = message.get("effects")
        if (type(effects) is not list or not effects or canonical(effects[-1]) != canonical(complete)
                or sum(row.get("event_type") == "step.completed" for row in effects) != 1):
            raise ValueError("DSS inner source completion evidence differs")
        if not enabled:
            if len(effects) != 1 or message.get("prompt_resolution") is not None:
                raise ValueError("DSS skipped source instruction manufactured an effect")
        elif step["type"] == "variable_set":
            value = evaluate_expression(step["expression"], values)
            values[step["name"]] = float(value) if step["declared_type"] == "float" and type(value) is int else value
        elif step["type"] == "build_tc":
            values[step["target"]] = build_item_checkpoint_for_step(step, values)
        elif step["type"] == "prompt":
            if settlement is None or settlement.get("outcome") != "ANSWERED":
                raise ValueError("DSS inner prompt checkpoint has no authoritative answer")
            response = message.get("prompt_resolution")
            keys = ("prompt_id", "settlement_id", "outcome", "response")
            if type(response) is not dict or canonical({key:response.get(key) for key in keys}) != canonical({key:settlement.get(key) for key in keys}):
                raise ValueError("DSS inner prompt checkpoint substituted its settlement")
            if "response_target" in step:
                value = native_prompt_result(step, settlement) if step.get("prompt_profile") == PROMPT_PROFILE else settlement["response"]
                if step.get("prompt_profile") != PROMPT_PROFILE and type(value) is not int:
                    raise ValueError("DSS inner legacy prompt target is not an index")
                values[step["response_target"]] = value
        elif step["type"] in {"get_tm", "verify", "wait_for"}:
            if observation_result is None:
                raise ValueError("DSS inner observation checkpoint has no authoritative result")
            values = observation_checkpoint_variables(step, values, observation_result)
        elif step["type"] not in {"log", "display", "send_tc"}:
            raise ValueError("DSS inner source instruction has no reviewed checkpoint semantics")
        if canonical(message.get("variables")) != canonical(values):
            raise ValueError("DSS inner full variable checkpoint differs from its authoritative source")
        self.variables = values
        self.cursor += 1
        return dict(values)
