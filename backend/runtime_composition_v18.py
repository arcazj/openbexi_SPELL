"""Runtime authority dependencies for bounded native/telecommand composition."""
from __future__ import annotations

from typing import Any

from .ir_v11 import telecommand_dependency_variables as legacy_dependencies
from .prompt_v17 import PROMPT_PROFILE


def telecommand_dependency_variables(steps: Any) -> frozenset[str]:
    """Include reads that define a native answer controlling a command branch.

    Prior instruction streams contain no native bindings and retain the exact
    v0.11 closure. These private dependency records never become runtime IR.
    """
    if type(steps) is not list:
        return frozenset()
    bindings = [
        {"type": "variable_set", "name": step["response_target"],
         "expression": {"question": step.get("question"), "default": step.get("default")},
         "guard": step.get("guard")}
        for step in steps
        if type(step) is dict and step.get("prompt_profile") == PROMPT_PROFILE
        and type(step.get("response_target")) is str
    ]
    return legacy_dependencies([*steps, *bindings])
