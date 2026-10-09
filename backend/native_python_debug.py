"""Jailed main-thread debugger. Its transport accepts no evaluation or host access.

This file alone is installed in the immutable stdlib jail. The trusted runner
validates every received frame; submitted Python remains untrusted, including
its debugging metadata. Process isolation is provided outside this tracer.
"""
from __future__ import annotations

import json
import os
import runpy
import select
import socket
import sys


def main():
    descriptor, filename = int(sys.argv[1]), sys.argv[2]
    channel = socket.socket(fileno=descriptor)
    channel.set_inheritable(False)
    script_pid = os.getpid()
    buffer = bytearray()
    breaks = set()
    mode = "RUN"
    revision = 0
    sequence = 0
    target = None
    anchor = None

    def receive(block=False):
        while b"\n" not in buffer:
            if not block and not select.select([channel], [], [], 0)[0]:
                return None
            chunk = channel.recv(8192)
            if not chunk:
                os._exit(125)  # Never execute past a lost debugger transport.
            buffer.extend(chunk)
            if len(buffer) > 65536:
                os._exit(125)
        raw, _, remaining = buffer.partition(b"\n")
        buffer[:] = remaining
        return json.loads(raw)

    def apply(message, frame):
        nonlocal breaks, mode, revision, target, anchor
        if "breakpoints" in message:
            breaks = set(message["breakpoints"])
        if message["action"] != "CONFIG":
            mode = message["action"]
            revision = message["revision"]
            target = message.get("target_line")
            anchor = frame

    initial = receive(True)
    apply(initial, None)

    def trace(frame, event, arg):
        nonlocal mode, sequence, anchor
        if os.getpid() != script_pid:
            # A forked child must not share the parent's debugger channel.
            channel.close()
            sys.settrace(None)
            return None
        if frame.f_code.co_filename != filename:
            return None
        if event != "line":
            return trace
        while (message := receive()) is not None:
            apply(message, frame)
        line = frame.f_lineno
        parents = frame
        while parents is not None and parents is not anchor:
            parents = parents.f_back
        reason = ("entry" if mode == "ENTRY" else
                  "step" if mode == "STEP" else
                  "step_over" if mode == "STEP_OVER" and (frame is anchor or parents is None) else
                  "run_to_line" if mode == "RUN_TO_LINE" and line == target else
                  "breakpoint" if line in breaks else None)
        if reason:
            sequence += 1
            channel.sendall((json.dumps({"sequence": sequence, "line": line,
                "reason": reason, "control_revision": revision}, separators=(",", ":")) + "\n").encode())
            # The runner stops all descendants after this notification. This
            # thread cannot execute the selected source line until continued.
            while True:
                message = receive(True)
                apply(message, frame)
                if message["action"] != "CONFIG":
                    break
        return trace

    sys.argv = [filename, *sys.argv[3:]]
    sys.settrace(trace)
    try:
        runpy.run_path(filename, run_name="__main__")
    finally:
        sys.settrace(None)
        channel.close()


if __name__ == "__main__":
    main()
