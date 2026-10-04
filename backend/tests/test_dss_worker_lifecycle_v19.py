"""Real spawned children retain truthful exits across concurrent parent observers."""
from __future__ import annotations

from functools import wraps
import gc
import multiprocessing
from multiprocessing import connection
import os
import signal
import threading
import weakref

import pytest

from backend import supervisor as supervisor_module
from backend.tests import test_dss_prompt_authority_v19 as authority
from backend.tests.worker_lifecycle_support import _exit_child, _gated_child, _sleeping_child
from backend.worker_process import WorkerProcess

# Use the same actual public API source and unchanged nonzero-selection oracle.
procedures_dir = authority.procedures_dir


def _thread(target, errors):
    def run():
        try:
            target()
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _finish(process):
    if process._process._closed:
        return
    if process._process.pid is not None:
        if process.is_alive():
            process.terminate()
        process.join(timeout=3)
        assert not process.is_alive()
    process.close()
    assert process._process._closed


def _hold_real_reap(monkeypatch, target, owner):
    """Hold only an actual OS exit result before CPython publishes its cache."""
    held, release = threading.Event(), threading.Event()
    result = {}

    def pause(code):
        result["exitcode"] = code
        result["cached_returncode"] = target["popen"].returncode
        result["sentinel_ready"] = bool(connection.wait([target["sentinel"]], timeout=0))
        if os.name != "nt":
            result["pid_gone"] = not os.path.exists(f"/proc/{target['pid']}")
        held.set()
        if not release.wait(5):
            result["release_timeout"] = True
            raise AssertionError("owned real reaper was not released")

    if os.name == "nt":
        import _winapi
        original = _winapi.GetExitCodeProcess

        def actual_get_exit(handle):
            code = original(handle)
            if (target.get("popen") is not None and handle == int(target["popen"]._handle)
                    and owner() and code != _winapi.STILL_ACTIVE and not held.is_set()):
                pause(code)
            return code
        monkeypatch.setattr(_winapi, "GetExitCodeProcess", actual_get_exit)
    else:
        original = os.waitpid

        def actual_waitpid(pid, flags):
            returned = original(pid, flags)
            if (pid == target.get("pid") and returned[0] == pid
                    and owner() and not held.is_set()):
                pause(os.waitstatus_to_exitcode(returned[1]))
            return returned
        monkeypatch.setattr(os, "waitpid", actual_waitpid)
    return held, release, result


def test_actual_terminal_and_monitor_reaper_preserve_nonzero_public_api_oracle(
    client, operator_headers, viewer_headers, monkeypatch,
):
    target, errors = {}, []
    consumer_done, monitor_done = threading.Event(), threading.Event()
    join_entered, join_finished = threading.Event(), threading.Event()
    held, release, observed = _hold_real_reap(monkeypatch, target,
        lambda: threading.current_thread() is target.get("monitor_thread"))
    original_start, original_join = WorkerProcess.start, WorkerProcess.join
    original_consume = supervisor_module.Supervisor._consume_worker
    original_monitor = supervisor_module.Supervisor._monitor_worker
    original_current = supervisor_module.Supervisor._worker_message_is_current
    original_state = authority.wait_for_state

    def start(process):
        result = original_start(process)
        if process.name.startswith("spell-"):
            assert not target, "expected exactly one actual supervised worker"
            target.update(process=process, popen=process._process._popen,
                pid=process.pid, sentinel=process.sentinel)
        return result

    @wraps(original_consume)
    def consume(self, execution_id, handle):
        target["consumer_thread"] = threading.current_thread()
        try:
            return original_consume(self, execution_id, handle)
        finally:
            consumer_done.set()

    @wraps(original_monitor)
    def monitor(self, execution_id, handle):
        target["monitor_thread"] = threading.current_thread()
        try:
            return original_monitor(self, execution_id, handle)
        finally:
            monitor_done.set()

    def current(self, execution_id, handle, message):
        accepted = original_current(self, execution_id, handle, message)
        if accepted and message.get("kind") == "terminal":
            assert held.wait(3), "monitor must own the real child reap"
        return accepted

    def join(process, timeout=None):
        is_terminal = (process is target.get("process") and timeout == 2
            and threading.current_thread() is target.get("consumer_thread"))
        if is_terminal:
            join_entered.set()
        try:
            return original_join(process, timeout)
        finally:
            if is_terminal:
                join_finished.set()

    def state(*args, **kwargs):
        snapshot = original_state(*args, **kwargs)
        if snapshot["execution"]["state"] == "completed":
            # Observe all actual terminal handling before the unchanged oracle;
            # do not replace a result or retry an API request.
            assert consumer_done.wait(5)
            assert monitor_done.wait(5)
        return snapshot

    def release_after_contending_observer():
        try:
            assert held.wait(5)
            assert join_entered.wait(3)
            assert not join_finished.wait(0.05)
            assert observed["exitcode"] == 0
            assert observed["cached_returncode"] is None
            assert observed["sentinel_ready"] is True
            if os.name != "nt":
                assert observed["pid_gone"] is True
        finally:
            release.set()

    monkeypatch.setattr(WorkerProcess, "start", start)
    monkeypatch.setattr(WorkerProcess, "join", join)
    monkeypatch.setattr(supervisor_module.Supervisor, "_consume_worker", consume)
    monkeypatch.setattr(supervisor_module.Supervisor, "_monitor_worker", monitor)
    monkeypatch.setattr(supervisor_module.Supervisor, "_worker_message_is_current", current)
    monkeypatch.setattr(authority, "wait_for_state", state)
    coordinator = _thread(release_after_contending_observer, errors)
    try:
        authority.test_public_api_nonzero_runner_selection_reaches_protected_language_step_once(
            client, operator_headers, viewer_headers)
        assert join_finished.is_set() and not errors
        assert not observed.get("release_timeout")
    finally:
        release.set()
        coordinator.join(timeout=5)
        assert not coordinator.is_alive()
        for name in ("consumer_thread", "monitor_thread"):
            thread = target.get(name)
            if thread is not None:
                thread.join(timeout=5)
                assert not thread.is_alive()
    assert target["process"]._process._closed


def test_actual_implicit_start_cleanup_shares_reaper_publication_lock(monkeypatch):
    context = multiprocessing.get_context("spawn")
    started, finish = context.Event(), context.Event()
    first = WorkerProcess(context.Process(target=_gated_child, args=(started, finish)))
    second = WorkerProcess(context.Process(target=_exit_child))
    first.start()
    target = {"popen": first._process._popen, "pid": first.pid, "sentinel": first.sentinel}
    owner = {}
    held, release, observed = _hold_real_reap(monkeypatch, target,
        lambda: threading.current_thread() is owner.get("thread"))
    errors, threads = [], []
    entered, complete = threading.Event(), threading.Event()

    def reap():
        owner["thread"] = threading.current_thread()
        first.join(timeout=3)

    def spawn():
        entered.set()
        second.start()  # The real CPython _cleanup polls the first raw child.
        complete.set()

    try:
        assert started.wait(3)
        threads.append(_thread(reap, errors))
        finish.set()
        assert held.wait(3)
        threads.append(_thread(spawn, errors))
        assert entered.wait(3)
        assert not complete.wait(0.05)
        assert second._process.pid is None
        assert observed["exitcode"] == 0 and observed["cached_returncode"] is None
        release.set()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        assert complete.is_set() and not errors
        second.join(timeout=3)
        assert first.exitcode == second.exitcode == 0
    finally:
        release.set()
        finish.set()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        _finish(second)
        _finish(first)


def test_genuine_consumer_exception_still_creates_durable_worker_failure(
    client, operator_headers, viewer_headers, monkeypatch,
):
    from sqlalchemy import select
    from backend.models import Event
    recovered = threading.Event()
    target = {}
    original_reject = supervisor_module.Supervisor._reject_raw_file_handle_worker_message
    original_recover = supervisor_module.Supervisor._recover_worker_loss
    original_state = authority.wait_for_state

    def reject(self, execution_id, generation, message):
        result = original_reject(self, execution_id, generation, message)
        if message.get("kind") == "terminal":
            target["execution_id"] = execution_id
            raise RuntimeError("deliberate terminal consumer diagnostic")
        return result

    def recover(self, *args, **kwargs):
        try:
            return original_recover(self, *args, **kwargs)
        finally:
            recovered.set()

    def state(*args, **kwargs):
        snapshot = original_state(*args, **kwargs)
        if snapshot["execution"]["state"] == "completed":
            assert recovered.wait(5)
        return snapshot

    monkeypatch.setattr(supervisor_module.Supervisor, "_reject_raw_file_handle_worker_message", reject)
    monkeypatch.setattr(supervisor_module.Supervisor, "_recover_worker_loss", recover)
    monkeypatch.setattr(authority, "wait_for_state", state)
    with pytest.raises(AssertionError, match="deliberate terminal consumer diagnostic"):
        authority.test_public_api_nonzero_runner_selection_reaches_protected_language_step_once(
            client, operator_headers, viewer_headers)
    with client.app.state.session_factory() as session:
        failures = session.scalars(select(Event).where(
            Event.execution_id == target["execution_id"], Event.event_type == "worker.consumer_failed"
        )).all()
        assert [event.payload["error"] for event in failures] == [
            "worker consumer failed while handling a message: RuntimeError: deliberate terminal consumer diagnostic"]
    assert target["execution_id"] not in client.app.state.supervisor._workers


def test_actual_close_finishes_before_another_spawn_reads_child_registry(monkeypatch):
    context = multiprocessing.get_context("spawn")
    first = WorkerProcess(context.Process(target=_exit_child))
    second = WorkerProcess(context.Process(target=_exit_child))
    first.start()
    assert connection.wait([first.sentinel], timeout=3)
    # Do not join: leave the actual dead raw child in CPython's child registry.
    from multiprocessing import process as process_module
    assert first._process in process_module._children
    closing, release = threading.Event(), threading.Event()
    entered, spawned = threading.Event(), threading.Event()
    original_close = first._process._popen.close

    def close():
        closing.set()
        assert release.wait(5)
        return original_close()

    def spawn():
        entered.set()
        second.start()
        spawned.set()

    monkeypatch.setattr(first._process._popen, "close", close)
    errors, threads = [], []
    try:
        threads.append(_thread(first.close, errors))
        assert closing.wait(3)
        threads.append(_thread(spawn, errors))
        assert entered.wait(3)
        assert not spawned.wait(0.05)
        release.set()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        assert spawned.is_set() and not errors
        assert first._process._closed
        assert first._process not in process_module._children
        second.join(timeout=3)
        assert second.exitcode == 0
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        _finish(second)
        _finish(first)


def test_actual_live_wait_timeout_and_closed_process_semantics_remain_truthful():
    context = multiprocessing.get_context("spawn")
    started, finish = context.Event(), context.Event()
    process = WorkerProcess(context.Process(target=_gated_child, args=(started, finish), name="owned-live"))
    assert process.name == "owned-live" and process.pid is None
    assert process.is_alive() is False and process.exitcode is None
    with pytest.raises(AssertionError):
        process.join(timeout=0)
    with pytest.raises(ValueError):
        _ = process.sentinel
    process.start()
    try:
        assert started.wait(3)
        process.join(timeout=0.02)
        assert process.is_alive() is True and process.exitcode is None
        assert not connection.wait([process.sentinel], timeout=0)
        with pytest.raises(ValueError):
            process.close()
        finish.set()
        process.join(timeout=3)
        assert not process.is_alive() and process.exitcode == 0
    finally:
        finish.set()
        _finish(process)
    for operation in (process.is_alive, lambda: process.join(0), lambda: process.sentinel):
        with pytest.raises(ValueError):
            operation()


@pytest.mark.parametrize("exitcode", [0, 7])
def test_actual_exit_status_is_not_replaced_by_lifecycle_synchronization(exitcode):
    context = multiprocessing.get_context("spawn")
    process = WorkerProcess(context.Process(target=_exit_child, args=(exitcode,)))
    process.start()
    try:
        process.join(timeout=3)
        assert process.exitcode == exitcode
        assert not process.is_alive()
    finally:
        _finish(process)


@pytest.mark.parametrize("action", ["terminate", "kill"])
def test_actual_abnormal_termination_remains_abnormal(action):
    context = multiprocessing.get_context("spawn")
    started = context.Event()
    process = WorkerProcess(context.Process(target=_sleeping_child, args=(started,)))
    process.start()
    try:
        assert started.wait(3)
        getattr(process, action)()
        process.join(timeout=3)
        expected = -signal.SIGTERM if action == "terminate" or os.name == "nt" else -signal.SIGKILL
        assert process.exitcode == expected and not process.is_alive()
    finally:
        _finish(process)


def test_joined_process_disposes_native_sentinel_without_cyclic_gc():
    context = multiprocessing.get_context("spawn")
    was_enabled = gc.isenabled()
    gc.disable()
    process = WorkerProcess(context.Process(target=_exit_child))
    try:
        process.start()
        process.join(timeout=3)
        assert process.exitcode == 0
        sentinel = process.sentinel
        raw_ref, popen_ref = weakref.ref(process._process), weakref.ref(process._process._popen)
        # The existing conformance runners rely on ordinary disposal after join.
        del process
        assert raw_ref() is None and popen_ref() is None
        if os.name == "nt":
            import _winapi
            with pytest.raises(OSError):
                _winapi.WaitForSingleObject(sentinel, 0)
        else:
            with pytest.raises(OSError) as failure:
                os.fstat(sentinel)
            assert failure.value.errno == 9
    finally:
        if "process" in locals():
            _finish(process)
        if was_enabled:
            gc.enable()


def test_raw_context_start_failure_and_cleanup_are_preserved():
    class FailedStart:
        def __init__(self):
            self.calls = []

        def start(self):
            self.calls.append("start")
            raise RuntimeError("injected actual context start failure")

        def is_alive(self):
            self.calls.append("is_alive")
            return False

        def close(self):
            self.calls.append("close")

    raw = FailedStart()
    process = WorkerProcess(raw)
    with pytest.raises(RuntimeError, match="context start failure"):
        process.start()
    assert process.is_alive() is False
    process.close()
    assert raw.calls == ["start", "is_alive", "close"]
