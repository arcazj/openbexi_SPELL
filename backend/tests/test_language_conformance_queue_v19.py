"""Real worker tails remain authoritative across parent scheduling delays."""
from copy import deepcopy
import importlib
import multiprocessing
import os
import queue
import time
from types import SimpleNamespace

import pytest


CASES = ((16, "local-function"), (17, "local-function"),
         (18, "v18-native-yes-built-command"),
         (19, "v19-observation-prompt-confirm-command"))


class TerminalGateOutput:
    def __init__(self, output, reached, release, outcome):
        self.output, self.reached, self.release, self.outcome = output, reached, release, outcome

    def put(self, message):
        if self.outcome == "changed-log" and message.get("kind") == "step_commit":
            message = deepcopy(message)
            for effect in message.get("effects", []):
                if effect.get("event_type") == "procedure.log":
                    effect["payload"]["message"] = "deliberately changed worker log"
        if message.get("kind") == "terminal":
            self.reached.set()
            if not self.release.wait(10):
                raise RuntimeError("test parent did not release the terminal gate")
            if self.outcome == "no-terminal":
                return
            self.output.put(message)
            if self.outcome == "crash":
                self.output.close()
                self.output.join_thread()
                os._exit(7)
            return
        self.output.put(message)


def gated_worker(args, reached, release, outcome):
    from backend.worker import worker_main
    args = list(args)
    args[9] = TerminalGateOutput(args[9], reached, release, outcome)
    worker_main(*args)


@pytest.mark.parametrize("version,identity", CASES, ids=["v16", "v17", "v18", "v19"])
@pytest.mark.parametrize("outcome", ["completed", "no-terminal", "crash", "changed-log"])
def test_real_worker_tail_after_empty_and_exit_preserves_oracle(monkeypatch, version, identity, outcome):
    module = importlib.import_module(f"backend.language_conformance_v{version}")
    case = next(row for row in module.CASES if row["id"] == identity)
    context = multiprocessing.get_context("spawn")
    reached, release = context.Event(), context.Event()
    processes, channels, scheduling, tail = [], [], [], []
    started = time.monotonic()
    bound = 15 if version == 16 else 20

    class Context:
        def Queue(self):
            channel = context.Queue()
            channels.append(channel)
            if len(channels) == 2:
                original_get, original_nowait = channel.get, channel.get_nowait
                def get(*args, **kwargs):
                    try:
                        return original_get(*args, **kwargs)
                    except queue.Empty:
                        if reached.is_set() and not scheduling:
                            # The get genuinely expired while terminal output
                            # was gated. Model the parent being descheduled
                            # before it checks whether the child is still alive.
                            scheduling.append(time.monotonic() - started)
                            release.set()
                            processes[0].join(timeout=max(0, bound - (time.monotonic() - started)))
                            assert not processes[0].is_alive()
                        raise
                def nowait():
                    message = original_nowait()
                    tail.append(message)
                    return message
                channel.get, channel.get_nowait = get, nowait
            return channel

        def Process(self, *, target, args):
            from backend.worker import worker_main
            assert target is worker_main
            process = context.Process(target=gated_worker, args=(args, reached, release, outcome))
            processes.append(process)
            return process

    monkeypatch.setattr(module, "multiprocessing", SimpleNamespace(get_context=lambda method: Context()))
    try:
        if outcome == "completed":
            assert module.run_case(case) == module._expected_result(case)
        else:
            with pytest.raises(ValueError, match="oracle|cleanly"):
                module.run_case(case)
        assert len(scheduling) == 1 and scheduling[0] < bound
        assert len(processes) == 1 and not processes[0].is_alive()
        assert processes[0].exitcode == (7 if outcome == "crash" else 0)
        if outcome == "no-terminal":
            assert tail == []  # A truly exhausted queue cannot manufacture success.
        else:
            assert tail == [{"kind":"terminal", "generation":1, "state":"completed"}]
    finally:
        release.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)


@pytest.mark.parametrize("version,identity,request_kind", [
    (18, "v18-native-yes-built-command", "telecommand_requested"),
    (19, "v19-observation-prompt-confirm-command", "observation_requested"),
])
def test_expired_observer_does_not_dispatch_a_returned_service_request(monkeypatch, version, identity, request_kind):
    from backend import telecommand_runtime_v11
    from backend.language_observation_fixture_v19 import ObservationFixture
    module = importlib.import_module(f"backend.language_conformance_v{version}")
    case = next(row for row in module.CASES if row["id"] == identity)
    context = multiprocessing.get_context("spawn")
    channels, requests, services, processes = [], [], [], []
    elapsed_offset = [0]

    class Context:
        def Queue(self):
            channel = context.Queue()
            channels.append(channel)
            if len(channels) == 2:
                original = channel.get
                def get(*args, **kwargs):
                    message = original(*args, **kwargs)
                    if message.get("kind") == request_kind:
                        requests.append(message)
                        # Model scheduling across the original deadline after
                        # a real worker message arrives, before interpretation.
                        elapsed_offset[0] = 21
                    return message
                channel.get = get
            return channel

        def Process(self, **kwargs):
            process = context.Process(**kwargs)
            processes.append(process)
            return process

    def forbidden(*args, **kwargs):
        services.append(True)
        pytest.fail("an expired observer dispatched a service request")

    monkeypatch.setattr(module, "multiprocessing", SimpleNamespace(get_context=lambda method: Context()))
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: time.monotonic() + elapsed_offset[0]))
    monkeypatch.setattr(telecommand_runtime_v11, "execute_preflight", forbidden)
    monkeypatch.setattr(ObservationFixture, "resolve", forbidden)
    with pytest.raises(ValueError, match="did not finish cleanly"):
        module.run_case(case)
    assert len(requests) == 1 and not services
    assert len(processes) == 1 and not processes[0].is_alive()
