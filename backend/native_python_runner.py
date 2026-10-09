"""Network-none service owning disposable, unprivileged CPython executions."""
from __future__ import annotations

import ctypes
import codecs
import hashlib
import json
import os
import re
import selectors
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

from .native_python import MAX_JOB_SECONDS, MAX_OUTPUT_BYTES, PYTHON_VERSION, canonical, breakpoint_lines
from .native_python_protocol import READY, RESPONSE_SCHEMA, read_json, validate_request, validate_breakpoints, write_json
from .development_bundle_protocol import require_protocol_directory

JAIL_TMP = Path("/opt/spell-python/tmp")
PROTOCOL_UID = 10001
CHILD_UID = 20000


def protocol_write(path: Path, value: dict) -> None:
    # Publish complete 0600 frames owned by the backend's protocol identity.
    os.seteuid(PROTOCOL_UID)
    try:
        write_json(path, value, replace=True)
    finally:
        os.seteuid(0)


def signal_children(action=signal.SIGKILL) -> None:
    """Also remove descendants that deliberately left their original process group."""
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            uid = next(line for line in (path / "status").read_text().splitlines() if line.startswith("Uid:"))
            if int(uid.split()[1]) == CHILD_UID:
                os.kill(int(path.name), action)
        except (OSError, StopIteration, ValueError):
            continue


def kill_children() -> None:
    signal_children()


def protocol_read(path: Path, *, mutable: bool = False) -> dict:
    os.seteuid(PROTOCOL_UID)
    try:
        return read_json(path, mutable=mutable)
    finally:
        os.seteuid(0)


def protocol_inventory(directory: Path, label: str) -> tuple[Path, ...]:
    entries = tuple(directory.iterdir())
    if len(entries) > 64:
        raise ValueError(f"{label} exceeds its 64-file bound")
    total = 0
    for entry in entries:
        try:
            metadata = entry.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2_000_000:
            raise ValueError(f"{label} contains an invalid entry")
        total += metadata.st_size
    if total > 16 * 1024 * 1024:
        raise ValueError(f"{label} exceeds its byte bound")
    return entries


def run_request(request: dict, request_path: Path, responses: Path) -> None:
    identity = request["request_id"]
    workspace = JAIL_TMP / identity
    digest = hashlib.sha256(canonical(request)).hexdigest()
    frame = {"schema_version": RESPONSE_SCHEMA, "request_id": identity, "request_sha256": digest,
             "state": "RUNNING", "revision": 0, "control_revision": 0, "stdout": "", "stderr": "",
             "exit_code": None, "error_code": "",
             "debug": {"line": None, "reason": None, "sequence": 0, "control_revision": 0}}
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    decoders = {stream: codecs.getincrementaldecoder("utf-8")(errors="replace") for stream in streams}
    process = None
    ready_read = ready_write = None
    debug_parent = debug_child = None
    debug_buffer = bytearray()
    debug_revision = 0
    valid_lines = set(breakpoint_lines(request["step"]["source"]))
    debug_path = request_path.with_name(identity + ".debug.json")
    selector = selectors.DefaultSelector()
    control_path = request_path.with_name(identity + ".control.json")
    last_publish = 0.0
    active_elapsed = 0.0
    last_tick = time.monotonic()
    job_deadline = last_tick + MAX_JOB_SECONDS
    forced_state = None

    def publish():
        nonlocal last_publish
        frame["revision"] += 1
        protocol_write(responses / (identity + ".response.json"), frame)
        last_publish = time.monotonic()

    try:
        workspace.mkdir(mode=0o700)
        (workspace / "tmp").mkdir(mode=0o700)
        source = workspace / request["step"]["source_name"]
        source.write_bytes(request["step"]["source"].encode("utf-8"))
        source.chmod(0o444)
        os.chown(workspace, CHILD_UID, CHILD_UID)
        os.chown(workspace / "tmp", CHILD_UID, CHILD_UID)
        publish()
        ready_read, ready_write = os.pipe()
        debug_parent, debug_child = socket.socketpair()
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "/app/backend/native_python_child.py",
            identity, source.name, str(ready_write), str(debug_child.fileno()), *request["arguments"]], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
            pass_fds=(ready_write, debug_child.fileno()),
            env={"PATH": "/usr/local/bin", "LANG": "C.UTF-8", "TZ": "UTC"})
        os.close(ready_write)
        ready_write = None
        debug_child.close()
        debug_child = None
        if not select.select([ready_read], [], [], 2)[0] or os.read(ready_read, 5) != b"ready":
            raise RuntimeError("Python child isolation was not acknowledged")
        os.close(ready_read)
        ready_read = None
        def debug_send(action, revision=0, target_line=None, breakpoints=None):
            debug_parent.sendall(canonical({"action": action, "revision": revision,
                "target_line": target_line, "breakpoints": request["debug"]["breakpoints"]
                if breakpoints is None else breakpoints}) + b"\n")
        debug_send("ENTRY" if request["debug"]["start_paused"] else "RUN")
        debug_parent.setblocking(False)
        for stream in streams:
            handle = getattr(process, stream)
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_READ, stream)
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            debug_stopped = False
            if frame["state"] != "PAUSED":
                active_elapsed += now - last_tick
            last_tick = now
            if debug_path.exists():
                settings = protocol_read(debug_path, mutable=True)
                if (set(settings) != {"request_id", "request_sha256", "revision", "breakpoints"}
                        or settings["request_id"] != identity or settings["request_sha256"] != digest
                        or type(settings["revision"]) is not int or settings["revision"] < 1):
                    raise ValueError("Python debugger configuration binding differs")
                validate_breakpoints(settings["breakpoints"], request["step"]["source"])
                if settings["revision"] > debug_revision:
                    debug_send("CONFIG", breakpoints=settings["breakpoints"])
                    debug_revision = settings["revision"]
            if control_path.exists():
                control = protocol_read(control_path, mutable=True)
                if (set(control) != {"request_id", "request_sha256", "revision", "action", "target_line", "breakpoints"}
                        or control["request_id"] != identity or control["request_sha256"] != digest
                        or type(control["revision"]) is not int or control["revision"] < 1
                        or control["action"] not in {"PAUSE", "RESUME", "STEP", "STEP_OVER", "RUN_TO_LINE", "ABORT"}):
                    raise ValueError("Python control binding differs")
                validate_breakpoints(control["breakpoints"], request["step"]["source"])
                if control["action"] == "RUN_TO_LINE":
                    validate_breakpoints([control["target_line"]], request["step"]["source"])
                elif control["target_line"] is not None:
                    raise ValueError("Python control target differs")
                if control["revision"] > frame["control_revision"]:
                    action = control["action"]
                    if process.poll() is None:
                        if action == "PAUSE":
                            signal_children(signal.SIGSTOP)
                            if frame["state"] != "PAUSED":
                                frame["debug"]["line"] = None
                                frame["debug"]["reason"] = "pause"
                            frame["state"] = "PAUSED"
                            # A signal pause can interrupt C code; line stepping
                            # subsequently stops at the next traced source line.
                        elif action in {"RESUME", "STEP", "STEP_OVER", "RUN_TO_LINE"}:
                            debug_send("RUN" if action == "RESUME" else action,
                                control["revision"], control["target_line"], control["breakpoints"])
                            signal_children(signal.SIGCONT)
                            frame["state"] = "RUNNING"
                        else:
                            forced_state = "ABORTED"
                            kill_children()
                    frame["control_revision"] = control["revision"]
                    publish()
            if select.select([debug_parent], [], [], 0)[0]:
                chunk = debug_parent.recv(8192)
                debug_buffer.extend(chunk)
                if len(debug_buffer) > 65536:
                    raise ValueError("Python debugger transport exceeds its bound")
                while b"\n" in debug_buffer:
                    raw, _, remaining = debug_buffer.partition(b"\n")
                    debug_buffer[:] = remaining
                    stopped = json.loads(raw)
                    if (type(stopped) is not dict or set(stopped) != {"sequence", "line", "reason", "control_revision"}
                            or type(stopped["sequence"]) is not int or stopped["sequence"] != frame["debug"]["sequence"] + 1
                            or type(stopped["line"]) is not int or stopped["line"] not in valid_lines
                            or stopped["reason"] not in {"entry", "breakpoint", "step", "step_over", "run_to_line"}
                            or type(stopped["control_revision"]) is not int
                            or not 0 <= stopped["control_revision"] <= frame["control_revision"]):
                        raise ValueError("Python debugger stop binding differs")
                    signal_children(signal.SIGSTOP)
                    frame["state"] = "PAUSED"
                    frame["debug"] = stopped
                    debug_stopped = True
            if (not request_path.exists() or int(time.time() * 1000) > request["expires_at_ms"]
                    or now > job_deadline
                    or active_elapsed > request["timeout_seconds"]):
                forced_state = "TIMED_OUT" if request_path.exists() else "ABORTED"
                frame["error_code"] = "PYTHON_TIMEOUT" if forced_state == "TIMED_OUT" else "PYTHON_CANCELLED"
                kill_children()
            heartbeat_path = request_path.with_name(identity + ".heartbeat.json")
            heartbeat = protocol_read(heartbeat_path, mutable=True) if heartbeat_path.exists() else None
            if (heartbeat is None or set(heartbeat) != {"request_id", "request_sha256", "at_ms"}
                    or heartbeat["request_id"] != identity or heartbeat["request_sha256"] != digest
                    or type(heartbeat["at_ms"]) is not int
                    or not -1000 <= int(time.time() * 1000) - heartbeat["at_ms"] <= 3000):
                forced_state = "ABORTED"
                frame["error_code"] = "PYTHON_WORKER_LOST"
                kill_children()
            for key, _ in selector.select(0.02):
                # Drain output produced before the stop before publishing it.
                # The byte quota bounds this drain, including a hostile writer.
                for _ in range(64):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 8192)
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        break
                    remaining = MAX_OUTPUT_BYTES - sum(len(value) for value in streams.values())
                    accepted = chunk[:max(0, remaining)]
                    streams[key.data].extend(accepted)
                    frame[key.data] += decoders[key.data].decode(accepted)
                    if len(chunk) > remaining or sum(value.count(b"\n") for value in streams.values()) > 1000:
                        forced_state = "OUTPUT_LIMIT"
                        frame["error_code"] = "PYTHON_OUTPUT_LIMIT"
                        kill_children()
                        break
            if process.poll() is not None:
                kill_children()
            if debug_stopped or now - last_publish > 0.1:
                publish()
        process.wait(timeout=2)
        frame["exit_code"] = process.returncode
        frame["state"] = forced_state or ("COMPLETED" if process.returncode == 0 else "FAILED")
        if frame["state"] == "FAILED":
            frame["error_code"] = "PYTHON_NONZERO_EXIT"
    except Exception:
        frame["state"] = "FAILED"
        frame["error_code"] = "PYTHON_RUNNER_FAILURE"
    finally:
        kill_children()
        for descriptor in (ready_read, ready_write):
            if descriptor is not None:
                os.close(descriptor)
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
        selector.close()
        for handle in (debug_parent, debug_child):
            if handle is not None:
                handle.close()
        for stream in streams:
            frame[stream] += decoders[stream].decode(b"", final=True)
        # Source and temporary files are confined to this exact owned job directory.
        if workspace.parent != JAIL_TMP or re.fullmatch(r"[0-9a-f]{32}", workspace.name) is None:
            raise RuntimeError("Python cleanup directory differs")
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=False)
        publish()


def main() -> None:
    requests = require_protocol_directory(Path(os.environ["SPELL_PYTHON_REQUEST_DIR"]), "Python requests")
    responses = require_protocol_directory(Path(os.environ["SPELL_PYTHON_RESPONSE_DIR"]), "Python responses")
    if requests == responses or os.getuid() != 0 or sys.version.split()[0] != PYTHON_VERSION:
        raise RuntimeError("Python runner identity or version differs")
    if "--healthcheck" in sys.argv:
        if protocol_read(responses / "ready.json") != READY:
            raise RuntimeError("Python runner is not ready")
        return
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError("Python runner cannot own orphaned children")
    protocol_write(responses / "ready.json", READY)
    handled = set()
    while True:
        for response in protocol_inventory(responses, "Python responses"):
            match = re.fullmatch(r"([0-9a-f]{32})\.response\.json", response.name)
            try:
                if (match is not None and not (requests / (match[1] + ".request.json")).exists()
                        and time.time() - response.stat().st_mtime > 5):
                    response.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        for path in protocol_inventory(requests, "Python requests"):
            match = re.fullmatch(r"([0-9a-f]{32})\.request\.json", path.name)
            if match is None or path.name in handled:
                continue
            try:
                request = validate_request(protocol_read(path), match[1])
            except (OSError, ValueError):
                handled.add(path.name)
                continue
            existing = responses / (match[1] + ".response.json")
            if existing.exists():
                # A service restart never re-executes a previously claimed script.
                frame = protocol_read(existing)
                if frame["state"] in {"RUNNING", "PAUSED", "QUEUED"}:
                    frame.update(state="FAILED", error_code="PYTHON_RUNNER_RESTARTED",
                                 exit_code=None, revision=frame["revision"] + 1)
                    protocol_write(existing, frame)
            else:
                run_request(request, path, responses)
            handled.add(path.name)
        current = {path.name for path in requests.glob("*.request.json")}
        handled.intersection_update(current)
        # Reap adopted descendants after removing their unprivileged identity.
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        time.sleep(0.02)


if __name__ == "__main__":
    main()
