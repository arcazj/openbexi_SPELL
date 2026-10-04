"""Real lock/SQL/commit delays remain distinguishable and contain no payloads."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import threading
import time
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from backend.observation_diagnostics import RepositoryTimings, OPERATIONS, _Measurement, MAX_COUNT
from backend.observation_domain import GapBounds, GetTMResult, ObservationResultCode
from backend.observation_service import ObservationRuntime
from backend.tests.test_driver_client_observation import generations


def records(caplog):
    return [json.loads(record.args[0]) for record in caplog.records
            if record.name == "backend.observation_diagnostics"]


def test_blocked_repository_lock_is_separate_from_sql_and_commit(caplog):
    database = create_engine("sqlite://")
    timings = RepositoryTimings(slow_seconds=0)
    entered = threading.Event()
    class ObservedLock:
        def __init__(self):
            self.lock = threading.RLock()
        def __enter__(self):
            entered.set()
            return self.lock.__enter__()
        def __exit__(self, *args):
            return self.lock.__exit__(*args)
    lock = ObservedLock()
    def operation():
        with timings.operation("ingest", lock, sessionmaker(database)) as session:
            assert session.scalar(text("SELECT 1")) == 1
            session.commit()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with lock.lock:
            future = pool.submit(operation)
            assert entered.wait(2)
            time.sleep(0.08)
            assert not future.done()
        future.result(timeout=2)
    report, = records(caplog)
    assert report["lock_wait_ms"] >= 70
    assert report["sql_count"] == 1
    assert report["sql_max_ms"] < report["lock_wait_ms"]
    assert report["commit_ms"] < report["lock_wait_ms"]
    assert report["sql_template_sha256"] == hashlib.sha256(b"SELECT 1").hexdigest()
    database.dispose()


def test_actual_slow_sql_and_commit_are_measured_without_statement_or_binds(caplog):
    database = create_engine("sqlite://")
    @event.listens_for(database, "connect")
    def connect(connection, _record):
        def delayed(value):
            time.sleep(0.04)
            return value
        connection.create_function("diagnostic_delay", 1, delayed)
    @event.listens_for(database, "commit")
    def slow_commit(_connection):
        time.sleep(0.05)
    timings = RepositoryTimings(slow_seconds=0)
    with timings.operation("gap", threading.RLock(), sessionmaker(database)) as session:
        assert session.scalar(text("SELECT diagnostic_delay(:private)"),
                              {"private":"credential-and-telemetry-secret"}) == "credential-and-telemetry-secret"
        session.commit()
    report, = records(caplog)
    assert report["sql_count"] == 1
    assert report["sql_total_ms"] >= 35
    assert report["sql_max_ms"] >= 35
    assert report["commit_ms"] >= 45
    assert report["lock_held_ms"] >= report["sql_total_ms"] + report["commit_ms"]
    assert report["lock_wait_ms"] < report["sql_max_ms"]
    assert "credential-and-telemetry-secret" not in caplog.text
    assert "diagnostic_delay" not in caplog.text
    assert set(report) == {"operation", "failed", "lock_wait_ms", "lock_held_ms", "sql_count",
                           "sql_total_ms", "sql_max_ms", "sql_template_sha256", "commit_ms"}
    database.dispose()


def test_diagnostics_are_silent_when_healthy_and_bounded_per_operation(caplog):
    database = create_engine("sqlite://")
    clock = [100.0]
    timings = RepositoryTimings(clock=lambda:clock[0])
    factory = sessionmaker(database)
    def operation(name, elapsed):
        with timings.operation(name, threading.RLock(), factory):
            clock[0] += elapsed
    operation("clock", 0.1)
    assert records(caplog) == []
    operation("clock", 0.3)
    operation("clock", 0.3)
    assert len(records(caplog)) == 1
    clock[0] += 30
    operation("clock", 0.3)
    assert len(records(caplog)) == 2
    for name in OPERATIONS:
        operation(name, 0.3)
    assert set(timings._next_report) == OPERATIONS
    assert len(records(caplog)) == len(OPERATIONS) + 1
    with pytest.raises(ValueError, match="unknown"):
        operation("unbounded-dynamic-name", 1)
    measurement = _Measurement(lambda:clock[0])
    measurement.sql_count = MAX_COUNT
    context = SimpleNamespace(observation_timing_start=0)
    measurement.after_sql(None, None, "SELECT 1", None, context, False)
    assert measurement.sql_count == MAX_COUNT
    database.dispose()


@pytest.mark.parametrize("fault", ["report", "listener"])
def test_diagnostic_failure_preserves_primary_error_and_releases_lock(monkeypatch, caplog, fault):
    database = create_engine("sqlite://")
    timings = RepositoryTimings(slow_seconds=0)
    lock = threading.RLock()
    def broken(*args, **kwargs):
        raise RuntimeError("diagnostic-private-failure")
    if fault == "report":
        monkeypatch.setattr(timings, "_report", broken)
    else:
        monkeypatch.setattr(_Measurement, "before_sql", broken)
    with pytest.raises(ValueError, match="authoritative primary failure"):
        with timings.operation("snapshot", lock, sessionmaker(database)) as session:
            assert session.scalar(text("SELECT 1")) == 1
            raise ValueError("authoritative primary failure")
    with ThreadPoolExecutor(max_workers=1) as pool:
        def reacquire():
            with lock:
                return True
        assert pool.submit(reacquire).result(timeout=2)
    assert "diagnostic-private-failure" not in caplog.text
    database.dispose()


def test_gap_commit_metric_measures_same_single_durable_call():
    generation = generations(context=True)
    calls = []
    bounds = GapBounds("epoch", 4, 8)
    def record_gap(*args, **kwargs):
        calls.append((args, kwargs))
    repository = SimpleNamespace(record_gap=record_gap)
    runtime = ObservationRuntime(repository, get_tm=lambda query:GetTMResult(ObservationResultCode.GAP, gap=bounds))
    cursor = {"synchronization_state":"COMPLETE", "source_epoch":"epoch", "after_source_sequence":1,
              "source_id":"source", "item_id":"TM.POWER.BUS_VOLTAGE"}
    assert asyncio.run(runtime._collect_item(generation, cursor["item_id"], 1, cursor=cursor)) == 0
    assert calls == [((generation,), {"source_id":"source", "item_id":cursor["item_id"], "bounds":bounds})]
    assert runtime._collection_metrics["gap_commit"]["calls"] == 1
    assert (generation.context_generation, cursor["item_id"]) in runtime._force_current
