"""Bounded file protocol between trusted workers and the isolated Python runner."""
from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from pathlib import Path

from .development_bundle_protocol import atomic_protocol_write, read_protocol_file, require_protocol_directory
from .development_domain import DevelopmentCorruptionError
from .native_python import (LANGUAGE_PROFILE, PYTHON_VERSION, MAX_OUTPUT_BYTES, MAX_PROTOCOL_BYTES, breakpoint_lines,
                            MAX_JOB_SECONDS, MAX_RUN_SECONDS, canonical, script_step)

REQUEST_SCHEMA = "spell.python-request/2"
RESPONSE_SCHEMA = "spell.python-response/2"
READY_SCHEMA = "spell.python-ready/2"
TERMINAL = frozenset({"COMPLETED", "FAILED", "ABORTED", "TIMED_OUT", "OUTPUT_LIMIT"})
STATES = TERMINAL | {"QUEUED", "RUNNING", "PAUSED"}
READY = {"schema_version": READY_SCHEMA, "profile": LANGUAGE_PROFILE,
         "python_version": PYTHON_VERSION, "max_run_seconds": MAX_RUN_SECONDS,
         "max_output_bytes": MAX_OUTPUT_BYTES, "isolation": "network-none-chroot-unprivileged/1",
         "debugger": "source-main-thread/1"}


def validate_breakpoints(lines, source):
    if (type(lines) is not list or len(lines) > 2048
            or any(type(line) is not int for line in lines)
            or lines != sorted(set(lines)) or not set(lines) <= set(breakpoint_lines(source))):
        raise ValueError("Python breakpoint lines are invalid")
    return lines


def read_json(path: Path, *, mutable: bool = False) -> dict:
    # Only status/control/heartbeat frames may be atomically replaced. An inode
    # switch between lstat and open is legitimate for those frames; retry a
    # bounded number of times, retaining all primitive checks on each attempt.
    # In-place rewrites, symlinks, noncanonical JSON and immutable-file changes
    # remain corruption. Binding and monotonicity checks still apply in poll().
    for attempt in range(4):
        try:
            raw = read_protocol_file(path, label="Python runtime protocol", maximum_bytes=MAX_PROTOCOL_BYTES)
            break
        except DevelopmentCorruptionError as exc:
            if not mutable or str(exc) != "Python runtime protocol changed before read" or attempt == 3:
                raise
    value = json.loads(raw)
    if type(value) is not dict or canonical(value) != raw:
        raise ValueError("Python protocol must be a canonical object")
    return value


def write_json(path: Path, value: dict, *, replace: bool = False) -> None:
    raw = canonical(value)
    if len(raw) > MAX_PROTOCOL_BYTES:
        raise ValueError("Python protocol exceeds its size bound")
    atomic_protocol_write(path, raw, label="Python runtime protocol", replace=replace,
                          maximum_bytes=MAX_PROTOCOL_BYTES)


def validate_request(value: dict, request_id: str) -> dict:
    fields = {"schema_version", "request_id", "execution_id", "generation", "step",
              "created_at_ms", "expires_at_ms", "arguments", "timeout_seconds", "debug"}
    if type(value) is not dict or set(value) != fields or value["schema_version"] != REQUEST_SCHEMA:
        raise ValueError("Python request fields differ")
    if value["request_id"] != request_id or uuid.UUID(request_id).hex != request_id:
        raise ValueError("Python request identity differs")
    if type(value["execution_id"]) is not str or str(uuid.UUID(value["execution_id"])) != value["execution_id"]:
        raise ValueError("Python execution identity is invalid")
    if type(value["generation"]) is not int or value["generation"] < 1:
        raise ValueError("Python generation is invalid")
    args = value["arguments"]
    if type(args) is not list or len(args) > 16 or any(type(arg) is not str or len(arg) > 256 or "\x00" in arg for arg in args):
        raise ValueError("Python arguments exceed their bounds")
    timeout = value["timeout_seconds"]
    if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0.1 <= timeout <= MAX_RUN_SECONDS:
        raise ValueError("Python timeout exceeds its bound")
    created, expires = value["created_at_ms"], value["expires_at_ms"]
    if (type(created) is not int or type(expires) is not int
            or expires - created != MAX_JOB_SECONDS * 1000 or created > int(time.time() * 1000) + 1000
            or int(time.time() * 1000) > expires):
        raise ValueError("Python request deadline differs or has expired")
    step = value["step"]
    if type(step) is not dict or canonical(step) != canonical(script_step(step.get("source"), step.get("source_name"))):
        raise ValueError("Python request script differs")
    debug = value["debug"]
    if type(debug) is not dict or set(debug) != {"start_paused", "breakpoints"} or type(debug["start_paused"]) is not bool:
        raise ValueError("Python debugger admission differs")
    validate_breakpoints(debug["breakpoints"], step["source"])
    return value


class PythonClient:
    def __init__(self, configuration: dict, execution_id: str, generation: int, step: dict,
                 *, arguments: list[str] | None = None, timeout_seconds: float = MAX_RUN_SECONDS,
                 start_paused: bool = False, breakpoints: list[int] | None = None):
        if type(configuration) is not dict or set(configuration) != {"requests", "responses"}:
            raise ValueError("the isolated Python runtime is not configured")
        self.requests = require_protocol_directory(Path(configuration["requests"]), "Python requests")
        self.responses = require_protocol_directory(Path(configuration["responses"]), "Python responses")
        if self.requests == self.responses:
            raise ValueError("Python protocol directories must differ")
        if read_json(self.responses / "ready.json") != READY:
            raise ValueError("the isolated Python runtime is unavailable or incompatible")
        now = int(time.time() * 1000)
        self.id = uuid.uuid4().hex
        self.request = validate_request({"schema_version": REQUEST_SCHEMA, "request_id": self.id,
            "execution_id": execution_id, "generation": generation, "step": step,
            "created_at_ms": now, "expires_at_ms": now + MAX_JOB_SECONDS * 1000,
            "arguments": [] if arguments is None else arguments, "timeout_seconds": timeout_seconds,
            "debug": {"start_paused": start_paused, "breakpoints": breakpoints or []}}, self.id)
        self.digest = hashlib.sha256(canonical(self.request)).hexdigest()
        self.command_revision = 0
        self.debug_revision = 0
        self.breakpoints = self.request["debug"]["breakpoints"]
        self.last = None
        self.last_heartbeat = 0.0
        self.heartbeat()
        write_json(self.requests / (self.id + ".request.json"), self.request)

    def heartbeat(self) -> None:
        now = time.monotonic()
        if now - self.last_heartbeat >= 0.5:
            write_json(self.requests / (self.id + ".heartbeat.json"), {
                "request_id": self.id, "request_sha256": self.digest,
                "at_ms": int(time.time() * 1000)}, replace=True)
            self.last_heartbeat = now

    def configure(self, lines: list[int]) -> None:
        validate_breakpoints(lines, self.request["step"]["source"])
        if lines == self.breakpoints:
            return
        self.debug_revision += 1
        write_json(self.requests / (self.id + ".debug.json"), {
            "request_id": self.id, "request_sha256": self.digest,
            "revision": self.debug_revision, "breakpoints": lines}, replace=True)
        self.breakpoints = list(lines)

    def command(self, action: str, *, target_line: int | None = None) -> int:
        if action not in {"PAUSE", "RESUME", "STEP", "STEP_OVER", "RUN_TO_LINE", "ABORT"}:
            raise ValueError("Python control is invalid")
        if action == "RUN_TO_LINE":
            validate_breakpoints([target_line], self.request["step"]["source"])
        elif target_line is not None:
            raise ValueError("Python control target is invalid")
        self.command_revision += 1
        write_json(self.requests / (self.id + ".control.json"), {
            "request_id": self.id, "request_sha256": self.digest,
            "revision": self.command_revision, "action": action, "target_line": target_line,
            "breakpoints": self.breakpoints}, replace=True)
        return self.command_revision

    def poll(self) -> dict | None:
        self.heartbeat()
        path = self.responses / (self.id + ".response.json")
        if not path.exists():
            return None
        value = read_json(path, mutable=True)
        fields = {"schema_version", "request_id", "request_sha256", "state", "revision",
                  "control_revision", "stdout", "stderr", "exit_code", "error_code", "debug"}
        if (set(value) != fields or value["schema_version"] != RESPONSE_SCHEMA
                or value["request_id"] != self.id or value["request_sha256"] != self.digest
                or type(value["state"]) is not str or value["state"] not in STATES
                or type(value["revision"]) is not int or value["revision"] < 1
                or type(value["control_revision"]) is not int
                or not 0 <= value["control_revision"] <= self.command_revision
                or type(value["stdout"]) is not str or type(value["stderr"]) is not str
                or len(value["stdout"].encode()) + len(value["stderr"].encode()) > MAX_OUTPUT_BYTES * 3
                or (value["exit_code"] is not None and type(value["exit_code"]) is not int)
                or type(value["error_code"]) is not str or len(value["error_code"]) > 80):
            raise ValueError("Python response binding or fields differ")
        debug = value["debug"]
        if (type(debug) is not dict or set(debug) != {"line", "reason", "sequence", "control_revision"}
                or type(debug["sequence"]) is not int or debug["sequence"] < 0
                or type(debug["control_revision"]) is not int
                or not 0 <= debug["control_revision"] <= value["control_revision"]
                or debug["reason"] not in {None, "entry", "breakpoint", "step", "step_over", "run_to_line", "pause"}
                or (debug["line"] is not None and (type(debug["line"]) is not int
                    or debug["line"] not in breakpoint_lines(self.request["step"]["source"])))):
            raise ValueError("Python debugger response differs")
        if value["state"] == "COMPLETED" and value["exit_code"] != 0:
            raise ValueError("Python success requires exit status zero")
        if self.last is not None:
            if value["revision"] < self.last["revision"]:
                raise ValueError("Python response revision moved backwards")
            if (value["control_revision"] < self.last["control_revision"]
                    or debug["sequence"] < self.last["debug"]["sequence"]):
                raise ValueError("Python debugger revision moved backwards")
            if value["revision"] == self.last["revision"] and value != self.last:
                raise ValueError("Python response changed without a new revision")
            for stream in ("stdout", "stderr"):
                if not value[stream].startswith(self.last[stream]):
                    raise ValueError("Python output was rewritten")
            if self.last["state"] in TERMINAL and value != self.last:
                raise ValueError("Python terminal result was rewritten")
        self.last = value
        return value

    def close(self) -> None:
        for directory, suffix in ((self.requests, ".request.json"), (self.requests, ".control.json"),
                                  (self.requests, ".debug.json"),
                                  (self.requests, ".heartbeat.json"),
                                  (self.responses, ".response.json")):
            (directory / (self.id + suffix)).unlink(missing_ok=True)
