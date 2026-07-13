from __future__ import annotations

import queue
import os
import time
import uuid
from multiprocessing.queues import Queue
from typing import Any


def worker_main(
    execution_id: str,
    generation: int,
    steps: list[dict[str, Any]],
    start_step: int,
    start_command_id: str,
    resume_prompt_id: str | None,
    control: Queue,
    output: Queue,
) -> None:
    """Execute validated IR in a spawned process. Source code never enters this process."""

    def send(kind: str, **fields: Any) -> None:
        output.put({"kind": kind, "generation": generation, **fields})

    send(
        "event",
        event_type="worker.started",
        source="worker",
        payload={"generation": generation, "start_step": start_step, "pid": os.getpid()},
    )
    send("state", state="running", command_id=start_command_id)

    def wait_for_control(block: bool = False, timeout: float = 0.0) -> dict[str, Any] | None:
        try:
            return control.get(block=block, timeout=timeout if block else None)
        except queue.Empty:
            return None

    def handle_control(message: dict[str, Any] | None) -> str | None:
        if message is None:
            return None
        command_type = message["type"]
        command_id = message["command_id"]
        if command_type == "abort":
            send("state", state="aborted", command_id=command_id)
            send("terminal", state="aborted")
            return "abort"
        if command_type == "pause":
            send("state", state="paused", command_id=command_id)
            while True:
                followup = wait_for_control(block=True, timeout=0.25)
                if followup is None:
                    continue
                if followup["type"] == "resume":
                    send("state", state="running", command_id=followup["command_id"])
                    return "resume"
                if followup["type"] == "abort":
                    send("state", state="aborted", command_id=followup["command_id"])
                    send("terminal", state="aborted")
                    return "abort"
        return None

    for step_index in range(start_step, len(steps)):
        if handle_control(wait_for_control()) == "abort":
            return
        step = steps[step_index]
        effects: list[dict[str, Any]] = []
        prompt_resolution: dict[str, Any] | None = None
        send(
            "event",
            event_type="step.started",
            source="worker",
            payload={"step_index": step_index, "line": step["line"], "step_type": step["type"]},
        )

        if step["type"] == "log":
            effects.append(
                {
                    "event_type": "procedure.log",
                    "source": "procedure",
                    "severity": step["level"],
                    "payload": {"message": step["message"], "step_index": step_index},
                }
            )
        elif step["type"] == "telemetry":
            effects.append(
                {
                    "event_type": "telemetry.sample",
                    "source": "simulator",
                    "severity": "info",
                    "payload": {
                        "channel": step["channel"],
                        "value": step["value"],
                        "unit": step.get("unit"),
                        "quality": "simulated",
                        "step_index": step_index,
                    },
                },
            )
        elif step["type"] == "wait":
            remaining = float(step["seconds"])
            while remaining > 0:
                started = time.monotonic()
                result = handle_control(wait_for_control(block=True, timeout=min(0.05, remaining)))
                elapsed = time.monotonic() - started
                if result == "abort":
                    return
                if result != "resume":
                    remaining = max(0.0, remaining - elapsed)
        elif step["type"] == "prompt":
            prompt_id = resume_prompt_id or str(uuid.uuid4())
            resume_prompt_id = None
            send(
                "prompt_opened",
                prompt_id=prompt_id,
                step_index=step_index,
                question=step["question"],
                choices=step["choices"],
                default=step["default"],
            )
            send("state", state="prompting")
            while True:
                message = wait_for_control(block=True, timeout=0.25)
                if message is None:
                    continue
                if message["type"] == "abort":
                    send("state", state="aborted", command_id=message["command_id"])
                    send("terminal", state="aborted")
                    return
                if message["type"] == "pause":
                    if handle_control(message) == "abort":
                        return
                    send("state", state="prompting")
                    continue
                if message["type"] == "prompt_response" and message.get("prompt_id") == prompt_id:
                    prompt_resolution = {
                        "prompt_id": prompt_id,
                        "response": message["response"],
                        "command_id": message["command_id"],
                    }
                    break

        effects.append(
            {
                "event_type": "step.completed",
                "source": "worker",
                "severity": "info",
                "payload": {
                    "step_index": step_index,
                    "line": step["line"],
                    "step_type": step["type"],
                },
            }
        )
        send(
            "step_commit",
            step_index=step_index,
            next_step=step_index + 1,
            effects=effects,
            prompt_resolution=prompt_resolution,
        )
        if prompt_resolution is not None:
            send("state", state="running")

    send("state", state="completed")
    send("terminal", state="completed")
