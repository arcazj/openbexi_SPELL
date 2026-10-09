"""Operator protocol for a source-bound script executed by the isolated service."""
from __future__ import annotations

import queue
import os
import time
import uuid
from collections import deque

from .native_python import IR_VERSION, MAX_JOB_SECONDS, validate_ir
from .native_python_protocol import PythonClient, TERMINAL


def run(execution_id, generation, steps, start_step, start_command_id, checkpoint_variables,
        control, output, configuration, *, safe_point_ack_required=True):
    def send(kind, **fields):
        output.put({"kind": kind, "generation": generation, **fields})

    def event(event_type, payload, severity="info"):
        send("event", event_type=event_type, payload=payload, severity=severity, source="python-runtime")

    def rejected(message, detail):
        send("command_rejected", command_id=message.get("command_id"),
             command_type=str(message.get("type", "")).upper(),
             code="PYTHON_COMMAND_UNSUPPORTED", detail=detail)

    client = None
    terminal = False
    pending = deque()
    applied = {}
    offsets = {"stdout": 0, "stderr": 0}
    tails = {"stdout": "", "stderr": ""}
    line_counts = {"stdout": 0, "stderr": 0}
    awaiting = None
    control_loss = None
    breakpoints = []
    debug_sequence = 0
    current_line = 1
    try:
        validated = validate_ir(IR_VERSION, steps, start_step=start_step, checkpoint_variables=checkpoint_variables)
        if start_step != 0:
            raise ValueError("Python scripts cannot replay a completed or interrupted execution")
        if configuration is None:
            raise ValueError("the isolated Python runtime is not configured")
        event("worker.started", {"generation": generation, "start_step": 0, "pid": os.getpid()})
        send("state", state="running", command_id=start_command_id)
        token = str(uuid.uuid4())
        send("safe_point", safe_point_token=token, safe_point_kind="WAIT_BOUNDARY",
             step_index=0, line=1, lexical_frame_id="root", reachability_id="root:step:0",
             effect_certainty="NO_EFFECT")
        if safe_point_ack_required:
            deadline = time.monotonic() + 10
            while True:
                if time.monotonic() > deadline:
                    raise ValueError("Python admission safe point was not acknowledged")
                try:
                    message = control.get(timeout=0.25)
                except queue.Empty:
                    continue
                if message.get("type") == "safe_point_ack" and message.get("safe_point_token") == token:
                    breakpoints = message.get("python_breakpoints", [])
                    break
                pending.append(message)
        client = PythonClient(configuration, execution_id, generation, validated.steps[0],
                              start_paused=True, breakpoints=breakpoints)
        event("step.started", {"step_index": 0, "line": 1, "step_type": "python_script"})
        event("procedure.python_started", {"source_sha256": steps[0]["source_sha256"],
              "runtime_profile": steps[0]["runtime_profile"], "request_id": client.id})
        deadline = time.monotonic() + MAX_JOB_SECONDS + 5
        last_safe_point = time.monotonic()

        def application(message, state):
            fields = {"command_id": message.get("command_id"), "state": state.lower()}
            applied[message.get("command_id")] = fields
            # The supervisor owns command settlement and the abort cleanup barrier.
            if state == "COMPLETED":
                # Completion becomes visible only after the result checkpoint.
                send("command_applied", command_id=message.get("command_id"),
                     result={"state": "COMPLETED"}, effect_certainty="NO_EFFECT")
            else:
                send("state", **fields)

        def logs(value, final=False):
            for stream in offsets:
                text = tails[stream] + value[stream][offsets[stream]:]
                offsets[stream] = len(value[stream])
                lines = text.split("\n")
                tails[stream] = lines.pop()
                if final and tails[stream]:
                    lines.append(tails[stream])
                    tails[stream] = ""
                for line in lines[:max(0, 1000 - line_counts[stream])]:
                    line_counts[stream] += 1
                    event("procedure.log", {"step_index": 0, "line": 1,
                          "message": line[:8192], "stream": stream},
                          "error" if stream == "stderr" else "info")

        while time.monotonic() < deadline:
            if safe_point_ack_required and time.monotonic() - last_safe_point >= 0.25:
                send("safe_point", safe_point_token=str(uuid.uuid4()), safe_point_kind="WAIT_BOUNDARY",
                     step_index=0, line=current_line, lexical_frame_id="root", reachability_id="root:step:0",
                     effect_certainty="NO_EFFECT")
                last_safe_point = time.monotonic()
            try:
                message = pending.popleft() if pending else control.get(timeout=0.02)
            except queue.Empty:
                message = None
            if message is not None:
                kind = message.get("type")
                identity = message.get("command_id")
                if identity in applied:
                    fields = applied[identity]
                    if fields["state"] == "aborted":
                        send("state", **fields, replayed=True)
                    else:
                        # A duplicate delivery acknowledges the same operation;
                        # it must not move a later breakpoint pause to RUNNING.
                        send("command_applied", command_id=identity,
                             result={"state": fields["state"].upper()}, effect_certainty="NO_EFFECT")
                elif kind == "safe_point_ack":
                    if "python_breakpoints" in message:
                        client.configure(message["python_breakpoints"])
                elif kind in {"pause", "resume", "run", "step", "step_over", "abort", "stop", "control_loss"}:
                    if awaiting is not None:
                        if message.get("command_id") != awaiting[1].get("command_id") or kind == "control_loss":
                            pending.append(message)
                    else:
                        action = {"pause": "PAUSE", "control_loss": "PAUSE", "resume": "RESUME",
                                  "run": "RUN_TO_LINE" if message.get("target_line") else "RESUME",
                                  "step": "STEP", "step_over": "STEP_OVER",
                                  "abort": "ABORT", "stop": "ABORT"}[kind]
                        if "python_breakpoints" in message:
                            client.configure(message["python_breakpoints"])
                        revision = client.command(action, target_line=message.get("target_line"))
                        awaiting = (revision, message, action)
                        if kind == "control_loss":
                            control_loss = message
                else:
                    rejected(message, "Python scripts support Run, Pause, Step, Step Over, Stop and Abort; editing and replay are unavailable")
            value = client.poll()
            if value is None:
                continue
            logs(value, value["state"] in TERMINAL)
            new_debug_stop = value["debug"]["sequence"] > debug_sequence
            if new_debug_stop:
                debug_sequence = value["debug"]["sequence"]
                current_line = value["debug"]["line"]
                send("safe_point", safe_point_token=str(uuid.uuid4()), safe_point_kind="BEFORE_STATEMENT",
                     step_index=0, line=current_line, lexical_frame_id="root", reachability_id="root:step:0",
                     effect_certainty="NO_EFFECT")
                if awaiting is None:
                    send("state", state="paused")
            if value["state"] in TERMINAL:
                # Keep the worker alive until the supervisor has persisted every
                # preceding output event. Its monitor's exit grace is shorter
                # than a slow database can take to drain a large log queue.
                if safe_point_ack_required:
                    barrier = str(uuid.uuid4())
                    send("safe_point", safe_point_token=barrier, safe_point_kind="WAIT_BOUNDARY",
                         step_index=0, line=current_line, lexical_frame_id="root", reachability_id="root:step:0",
                         effect_certainty="NO_EFFECT")
                    barrier_deadline = time.monotonic() + 30
                    while time.monotonic() < barrier_deadline:
                        try:
                            delivery = control.get(timeout=0.25)
                        except queue.Empty:
                            continue
                        if delivery.get("type") == "safe_point_ack":
                            if delivery.get("safe_point_token") == barrier:
                                break
                        else:
                            pending.append(delivery)
                    else:
                        raise ValueError("Python output persistence was not acknowledged")
                event("procedure.python_result", {"request_id": client.id, "state": value["state"],
                      "source_sha256": steps[0]["source_sha256"], "exit_code": value["exit_code"],
                      "error_code": value["error_code"], "stdout_lines": line_counts["stdout"],
                      "stderr_lines": line_counts["stderr"]}, "info" if value["state"] == "COMPLETED" else "error")
                finishing_controls = list(pending)
                pending.clear()
                if awaiting is not None:
                    finishing_controls.append(awaiting[1])
                    awaiting = None
                cancelled = False
                for delivery in finishing_controls:
                    identity = delivery.get("command_id")
                    if identity in applied:
                        continue
                    if delivery.get("type") in {"abort", "stop"}:
                        application(delivery, "ABORTED")
                        cancelled = True
                    elif delivery.get("type") in {"step", "step_over", "run", "resume"} and value["state"] == "COMPLETED":
                        application(delivery, "COMPLETED")
                    elif delivery.get("type") == "control_loss":
                        send("control_loss_applied", delivery_id=delivery.get("delivery_id") or delivery.get("lease_id"),
                             lease_id=delivery.get("lease_id"), fencing_token=delivery.get("fencing_token"),
                             safe_point_step=0, replayed=False)
                    else:
                        rejected(delivery, "Python execution finished before the requested control boundary")
                if cancelled:
                    terminal = True
                    send("terminal", state="aborted")
                    return
            if awaiting is not None and value["control_revision"] >= awaiting[0] and (
                    awaiting[2] != "ABORT" or value["state"] in TERMINAL):
                _, message, action = awaiting
                if action == "PAUSE" and value["state"] == "PAUSED":
                    if value["debug"]["reason"] == "pause":
                        current_line = None
                    if control_loss is not None:
                        send("control_loss_applied", delivery_id=control_loss.get("delivery_id") or control_loss.get("lease_id"),
                             lease_id=control_loss.get("lease_id"), fencing_token=control_loss.get("fencing_token"),
                             safe_point_step=0, replayed=False)
                        send("state", state="paused")
                        control_loss = None
                    else:
                        application(message, "PAUSED")
                    send("safe_point", safe_point_token=str(uuid.uuid4()), safe_point_kind="WAIT_BOUNDARY",
                         step_index=0, line=current_line, lexical_frame_id="root", reachability_id="root:step:0",
                         effect_certainty="NO_EFFECT")
                    if current_line is None:
                        event("procedure.python_paused", {**value["debug"], "source_sha256": steps[0]["source_sha256"]})
                elif action in {"RESUME", "RUN_TO_LINE"} and value["state"] == "RUNNING":
                    application(message, value["state"])
                elif action in {"RESUME", "RUN_TO_LINE"} and value["state"] == "PAUSED":
                    application(message, "PAUSED")
                elif action in {"STEP", "STEP_OVER"} and value["state"] == "PAUSED" and value["debug"]["control_revision"] >= awaiting[0]:
                    application(message, "PAUSED")
                elif action in {"STEP", "STEP_OVER"} and value["state"] == "RUNNING":
                    # Acknowledge the armed stepping mode so Pause/Abort can
                    # interrupt a long call; its eventual stop is a new event.
                    application(message, "RUNNING")
                elif value["state"] in TERMINAL and action == "ABORT":
                    application(message, "ABORTED")
                else:
                    rejected(message, "Python execution finished before the requested control boundary")
                awaiting = None
            if new_debug_stop:
                # FIFO delivery records the position and settles state/control
                # before this event asks the browser to refresh its projection.
                event("procedure.python_paused", {**value["debug"], "source_sha256": steps[0]["source_sha256"]})
            if value["state"] not in TERMINAL:
                continue
            terminal = True
            if value["state"] == "COMPLETED":
                variables = {"python_completed": True, "python_exit_code": 0,
                             "python_stdout_lines": line_counts["stdout"], "python_stderr_lines": line_counts["stderr"]}
                send("step_commit", step_index=0, next_step=1, prompt_resolution=None, variables=variables,
                     effects=[{"event_type": "step.completed", "source": "python-runtime", "severity": "info",
                               "payload": {"step_index": 0, "line": 1, "step_type": "python_script", "skipped": False}}])
                state = "completed"
            else:
                state = "aborted" if value["state"] == "ABORTED" else "failed"
            send("state", state=state)
            send("terminal", state=state)
            return
        raise ValueError("isolated Python runtime did not return within its bounded lifetime")
    except Exception as exc:
        event("procedure.error", {"step_index": 0, "line": 1, "error": str(exc)[:512]}, "error")
        send("state", state="failed")
        send("terminal", state="failed")
    finally:
        if client is not None:
            try:
                if not terminal:
                    client.command("ABORT")
            finally:
                # Removing the request fences cancellation; the runner never retries it.
                client.close()
