from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from typing import Any, Callable

import pytest

import backend.worker as worker_module
from backend.ir_v08 import (
    canonicalize_data_result,
    data_request_id,
    file_handle_reference,
)
from backend.procedure_parser import ProcedureCatalog


def _procedure(source: str):
    return ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        source, "worker-v08.spell.py"
    )


def _start_worker(
    monkeypatch: pytest.MonkeyPatch,
    procedure,
    *,
    durable_arguments: dict[str, Any] | None = None,
    generation: int = 4,
    start_step: int = 0,
    checkpoint_variables: dict[str, Any] | None = None,
):
    control: queue.Queue[dict[str, Any]] = queue.Queue()
    output: queue.Queue[dict[str, Any]] = queue.Queue()
    monkeypatch.setattr(worker_module, "_replace_worker_environment", lambda: None)
    thread = threading.Thread(
        target=worker_module.worker_main,
        args=(
            "execution-v08",
            generation,
            procedure.ir_version,
            list(procedure.steps),
            start_step,
            "start-command",
            None,
            checkpoint_variables or {},
            control,
            output,
            None,
            durable_arguments,
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
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        try:
            message = output.get(timeout=0.05)
        except queue.Empty:
            continue
        seen.append(message)
        if predicate(message):
            return message
    raise AssertionError(f"worker message not received; seen={seen!r}")


def _request(message: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in message.items()
        if key not in {"kind", "generation"}
    }


def test_data_result_is_checkpointed_only_after_exact_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "value: str = ''\n"
        "GetSharedData('scope', 'key', target=value, scalar_type='str')\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested = _next(output, lambda item: item.get("kind") == "data_requested")
    request = _request(requested)
    assert request["operation"] == "SHARED_GET"

    control.put(
        {
            "type": "data_result",
            **canonicalize_data_result(
                request,
                {"outcome": "OK", "value": "settled", "revision": "3"},
            ),
        }
    )
    committed = _next(
        output,
        lambda item: item.get("kind") == "step_commit"
        and item.get("step_index") == 1,
    )
    terminal = _next(output, lambda item: item.get("kind") == "terminal")

    assert committed["variables"]["value"] == "settled"
    assert terminal["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_v08_arguments_are_immutable_after_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure("DataContainer('CONTAINER.A', schema_revision=1)\n")
    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        durable_arguments={"input": 1},
    )
    requested = _next(output, lambda item: item.get("kind") == "data_requested")
    request = _request(requested)

    control.put(
        {
            "type": "inspection_edit",
            "edit_id": "edit-v08-args",
            "scope": "ARGS",
            "path": "ARGS.input",
            "declared_type": "INTEGER",
            "variables": {"ARGS": {"input": 2}},
        }
    )
    rejected = _next(
        output,
        lambda item: item.get("kind") == "inspection_edit_applied",
    )
    assert rejected["outcome"] == "REJECTED"
    assert rejected["variables"] == {"ARGS": {"input": 1}}

    control.put(
        {
            "type": "data_result",
            **canonicalize_data_result(
                request,
                {
                    "outcome": "OK",
                    "value": "spell-data-handle-v1.test",
                    "revision": 1,
                },
            ),
        }
    )
    terminal = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_mismatched_result_is_rejected_before_valid_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure("DataContainer('CONTAINER.A', schema_revision=1)\n")
    thread, control, output = _start_worker(monkeypatch, procedure)
    requested = _next(output, lambda item: item.get("kind") == "data_requested")
    request = _request(requested)
    valid = canonicalize_data_result(
        request,
        {
            "outcome": "OK",
            "value": "spell-data-handle-v1.test",
            "revision": 1,
        },
    )
    control.put({"type": "data_result", **dict(valid, request_id="wrong")})
    rejected = _next(output, lambda item: item.get("kind") == "command_rejected")
    assert rejected["code"] == "DATA_RESULT_INVALID"
    control.put({"type": "data_result", **valid})
    terminal = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_worker_resolves_file_handle_reference_by_exact_typed_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "handle: str = ''\n"
        "OpenFile('PROJECT_DATA', 'runtime.txt', mode='WRITE', revision=0, target=handle)\n"
        "WriteFile(handle=handle, content='through worker')\n"
        "CloseFile(handle)\n"
    )
    thread, control, output = _start_worker(monkeypatch, procedure)

    opened = _request(_next(output, lambda item: item.get("kind") == "data_requested"))
    assert opened["operation"] == "OPEN_FILE"
    token = "opaque-runtime-file-handle"
    control.put(
        {
            "type": "data_result",
            **canonicalize_data_result(
                opened, {"outcome": "OK", "value": token, "revision": 0}
            ),
        }
    )

    written = _request(_next(output, lambda item: item.get("kind") == "data_requested"))
    assert written["operation"] == "WRITE_FILE"
    marker = written["parameters"]["handle"]
    assert marker == {
        "schema_version": "spell.v08.file-handle-reference/1",
        "value_type": "FileHandle",
        "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "execution_id": "execution-v08",
        "worker_generation": 4,
        "creator_request_id": opened["request_id"],
        "state": "OPEN",
    }
    assert token not in json.dumps(written, sort_keys=True)
    assert written["parameters"]["content"] == "through worker"
    control.put(
        {
            "type": "data_result",
            **canonicalize_data_result(written, {"outcome": "OK"}),
        }
    )

    closed = _request(_next(output, lambda item: item.get("kind") == "data_requested"))
    assert closed["operation"] == "CLOSE_FILE"
    assert closed["parameters"] == {"handle": marker}
    control.put(
        {
            "type": "data_result",
            **canonicalize_data_result(
                closed, {"outcome": "OK", "revision": 1}
            ),
        }
    )
    committed = _next(
        output,
        lambda item: item.get("kind") == "step_commit"
        and item.get("step_index") == 3,
    )
    assert committed["variables"]["handle"] == {**marker, "state": "CLOSED"}
    assert token not in json.dumps(committed, sort_keys=True)
    terminal = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "completed"
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_resumed_file_handle_from_prior_generation_fails_stale_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedure = _procedure(
        "handle: str = ''\n"
        "content: str = ''\n"
        "OpenFile('PROJECT_DATA', 'runtime.txt', mode='READ', revision=1, target=handle)\n"
        "ReadFile(handle=handle, target=content)\n"
    )
    marker = file_handle_reference(
        "prior-generation-token",
        execution_id="execution-v08",
        worker_generation=4,
        creator_request_id=data_request_id("execution-v08", 2),
    )
    thread, _control, output = _start_worker(
        monkeypatch,
        procedure,
        generation=5,
        start_step=3,
        checkpoint_variables={"handle": marker, "content": ""},
    )
    rejected = _next(
        output,
        lambda item: item.get("event_type") == "procedure.error",
    )
    assert "STALE_HANDLE" in rejected["payload"]["error"]
    terminal = _next(output, lambda item: item.get("kind") == "terminal")
    assert terminal["state"] == "failed"
    assert not any(
        item.get("kind") == "data_requested"
        for item in list(output.queue)
    )
    thread.join(timeout=1)
    assert not thread.is_alive()
