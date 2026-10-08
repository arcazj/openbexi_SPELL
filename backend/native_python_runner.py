"""Network-none service owning disposable, unprivileged CPython executions."""
from __future__ import annotations

import ctypes
import codecs
import hashlib
import os
import re
import selectors
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from .native_python import MAX_JOB_SECONDS, MAX_OUTPUT_BYTES, PYTHON_VERSION, canonical
from .native_python_protocol import READY, RESPONSE_SCHEMA, read_json, validate_request, write_json
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
             "exit_code": None, "error_code": ""}
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    decoders = {stream: codecs.getincrementaldecoder("utf-8")(errors="replace") for stream in streams}
    process = None
    ready_read = ready_write = None
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
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "/app/backend/native_python_child.py",
            identity, source.name, str(ready_write), *request["arguments"]], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
            pass_fds=(ready_write,),
            env={"PATH": "/usr/local/bin", "LANG": "C.UTF-8", "TZ": "UTC"})
        os.close(ready_write)
        ready_write = None
        if not select.select([ready_read], [], [], 2)[0] or os.read(ready_read, 5) != b"ready":
            raise RuntimeError("Python child isolation was not acknowledged")
        os.close(ready_read)
        ready_read = None
        for stream in streams:
            handle = getattr(process, stream)
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_READ, stream)
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if frame["state"] != "PAUSED":
                active_elapsed += now - last_tick
            last_tick = now
            if control_path.exists():
                control = protocol_read(control_path, mutable=True)
                if (set(control) != {"request_id", "request_sha256", "revision", "action"}
                        or control["request_id"] != identity or control["request_sha256"] != digest
                        or type(control["revision"]) is not int or control["revision"] < 1
                        or control["action"] not in {"PAUSE", "RESUME", "ABORT"}):
                    raise ValueError("Python control binding differs")
                if control["revision"] > frame["control_revision"]:
                    action = control["action"]
                    if process.poll() is None:
                        if action == "PAUSE":
                            signal_children(signal.SIGSTOP)
                            frame["state"] = "PAUSED"
                        elif action == "RESUME":
                            signal_children(signal.SIGCONT)
                            frame["state"] = "RUNNING"
                        else:
                            forced_state = "ABORTED"
                            kill_children()
                    frame["control_revision"] = control["revision"]
                    publish()
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
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                remaining = MAX_OUTPUT_BYTES - sum(len(value) for value in streams.values())
                accepted = chunk[:max(0, remaining)]
                streams[key.data].extend(accepted)
                frame[key.data] += decoders[key.data].decode(accepted)
                if len(chunk) > remaining:
                    forced_state = "OUTPUT_LIMIT"
                    frame["error_code"] = "PYTHON_OUTPUT_LIMIT"
                    kill_children()
                if sum(value.count(b"\n") for value in streams.values()) > 1000:
                    forced_state = "OUTPUT_LIMIT"
                    frame["error_code"] = "PYTHON_OUTPUT_LIMIT"
                    kill_children()
            if process.poll() is not None:
                kill_children()
            if now - last_publish > 0.1:
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
