from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable

import pytest

import backend.worker as worker_module
from backend.ir_v07 import canonicalize_observation_result
from backend.procedure_parser import ProcedureCatalog


def _condition() -> dict:
    return {
        "condition_plan_id": "plan.power",
        "root": {
            "type": "PREDICATE",
            "node_id": "bus-ok",
            "operator": "GE",
            "left": {
                "kind": "TELEMETRY",
                "item_id": "TM.POWER.BUS",
                "catalog_digest": "a" * 64,
                "scalar_type": "FINITE_DOUBLE",
                "value_field": "ENGINEERING",
            },
            "right": {
                "kind": "LITERAL",
                "value": {"type": "FINITE_DOUBLE", "value": 27.5},
            },
        },
    }


def _procedure(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "worker-v07.spell.py"
    )


def _start_worker(monkeypatch: pytest.MonkeyPatch, procedure, *, execution_id="execution-v07"):
    control: queue.Queue[dict[str, Any]] = queue.Queue()
    output: queue.Queue[dict[str, Any]] = queue.Queue()
    monkeypatch.setattr(worker_module, "_replace_worker_environment", lambda: None)
    thread = threading.Thread(
        target=worker_module.worker_main,
        args=(
            execution_id,
            3,
            procedure.ir_version,
            list(procedure.steps),
            0,
            "start-command",
            None,
            {},
            control,
            output,
            None,
            None,
            False,
        ),
        daemon=True,
    )
    thread.start()
    return thread, control, output


def _next(
    output: queue.Queue[dict[str, Any]],
    predicate: Callable[[dict[str, Any]], bool],
    timeout: float = 3,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        try:
            message = output.get(timeout=0.05)
        except queue.Empty:
            continue
        seen.append(message)
        if predicate(message):
            return message, seen
    raise AssertionError(f"worker message not received; seen={seen!r}")


def _request(message: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in message.items()
        if key not in {"kind", "generation"}
    }


def test_get_tm_result_is_committed_through_the_normal_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "reading: float = 0.0\n"
        "GetTM('TM.POWER.BUS', target=reading, scalar_type='float')\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(output, lambda item: item.get("kind") == "observation_requested")
    request = _request(requested)
    result = canonicalize_observation_result(
        request, {"outcome": "OK", "value": 28.25, "evidence": {"sample_id": "a" * 64}}
    )
    control.put({"type": "observation_result", **result})
    committed, _ = _next(
        output,
        lambda item: item.get("kind") == "step_commit" and item.get("step_index") == 1,
    )
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")

    assert committed["variables"]["reading"] == 28.25
    assert terminal["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_verify_persists_typed_terminal_state_in_declared_string_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "status: str = ''\n"
        f"Verify(condition={_condition()!r}, target=status, timeout=10)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(output, lambda item: item.get("kind") == "observation_requested")
    request = _request(requested)
    assert request["operation"] == "VERIFY"
    control.put(
        {
            "type": "observation_result",
            **canonicalize_observation_result(
                request,
                {
                    "outcome": "INDETERMINATE",
                    "evidence": {"reason": "sample is stale"},
                },
            ),
        }
    )
    committed, _ = _next(
        output,
        lambda item: item.get("kind") == "step_commit" and item.get("step_index") == 1,
    )
    assert committed["variables"]["status"] == "INDETERMINATE"
    _next(output, lambda item: item.get("kind") == "terminal")
    thread.join(timeout=1)


def test_waitfor_remains_paused_while_a_result_arrives_and_resumes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure("WaitFor(seconds=0.1)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested, _ = _next(output, lambda item: item.get("kind") == "observation_requested")
    request = _request(requested)
    control.put({"type": "pause", "command_id": "pause-1"})
    _next(
        output,
        lambda item: item.get("kind") == "state" and item.get("state") == "paused",
    )
    control.put(
        {
            "type": "observation_result",
            **canonicalize_observation_result(request, {"outcome": "SATISFIED"}),
        }
    )
    with pytest.raises(queue.Empty):
        output.get(timeout=0.1)
    control.put({"type": "resume", "command_id": "resume-1"})
    committed, _ = _next(output, lambda item: item.get("kind") == "step_commit")
    assert committed["next_step"] == 1
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "completed"
    thread.join(timeout=1)


def test_waiting_observation_is_abortable_without_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure("WaitFor(seconds=60)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    _next(output, lambda item: item.get("kind") == "observation_requested")
    control.put({"type": "abort", "command_id": "abort-1"})
    terminal, _ = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "aborted"
    thread.join(timeout=1)
    assert not thread.is_alive()
