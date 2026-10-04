"""Bounded timing metadata; never retain SQL text, binds, or observations."""
from contextlib import contextmanager
import hashlib
import json
import logging
import threading
import time

from sqlalchemy import event


LOGGER = logging.getLogger(__name__)
OPERATIONS = frozenset({"ingest", "gap", "clock", "snapshot", "stale", "publish"})
MAX_COUNT = 1_000_000_000
MAX_MILLISECONDS = 86_400_000.0
MAX_LISTENERS = 16


def _milliseconds(seconds):
    return round(min(MAX_MILLISECONDS, max(0.0, seconds * 1000)), 3)


class _Measurement:
    def __init__(self, clock):
        self.clock = clock
        self.sql_count = 0
        self.sql_seconds = 0.0
        self.sql_max = 0.0
        self.sql_template_sha256 = None
        self.commit_seconds = 0.0
        self.commit_started = None
        self.listeners = []

    def _listen(self, target, name, callback):
        # Diagnostic listeners must never affect transaction outcomes.
        def safe(*args):
            try:
                callback(*args)
            except Exception:
                pass
        if len(self.listeners) >= MAX_LISTENERS:
            return
        event.listen(target, name, safe)
        self.listeners.append((target, name, safe))

    def install(self, session):
        def after_begin(_session, _transaction, connection):
            self._listen(connection, "before_cursor_execute", self.before_sql)
            self._listen(connection, "after_cursor_execute", self.after_sql)
        self._listen(session, "after_begin", after_begin)
        self._listen(session, "before_commit", self.before_commit)
        self._listen(session, "after_commit", self.after_commit)

    def before_sql(self, _connection, _cursor, _statement, _parameters, context, _many):
        context.observation_timing_start = self.clock()

    def after_sql(self, _connection, _cursor, statement, _parameters, context, _many):
        elapsed = max(0.0, self.clock() - context.observation_timing_start)
        self.sql_count = min(MAX_COUNT, self.sql_count + 1)
        self.sql_seconds += elapsed
        if elapsed >= self.sql_max:
            self.sql_max = elapsed
            self.sql_template_sha256 = hashlib.sha256(statement.encode("utf-8")).hexdigest()

    def before_commit(self, _session):
        self.commit_started = self.clock()

    def after_commit(self, _session):
        if self.commit_started is not None:
            self.commit_seconds += max(0.0, self.clock() - self.commit_started)
            self.commit_started = None

    def close(self):
        if self.commit_started is not None:
            self.commit_seconds += max(0.0, self.clock() - self.commit_started)
            self.commit_started = None
        for target, name, callback in reversed(self.listeners):
            try:
                event.remove(target, name, callback)
            except Exception:
                pass
        self.listeners.clear()


class RepositoryTimings:
    """Measure the existing lock/session scope without altering its behavior."""

    def __init__(self, *, clock=time.monotonic, slow_seconds=0.25, interval_seconds=30.0):
        self.clock = clock
        self.slow_seconds = slow_seconds
        self.interval_seconds = interval_seconds
        self._next_report = {}
        self._report_lock = threading.Lock()

    @contextmanager
    def operation(self, name, lock, factory):
        if name not in OPERATIONS:
            raise ValueError("unknown observation timing operation")
        started = self.clock()
        acquired = None
        released = None
        measurement = _Measurement(self.clock)
        failed = True
        try:
            with lock:
                acquired = self.clock()
                try:
                    with factory() as session:
                        try:
                            measurement.install(session)
                        except Exception:
                            pass
                        try:
                            yield session
                        finally:
                            try:
                                measurement.close()
                            except Exception:
                                pass
                    failed = False
                finally:
                    released = self.clock()
        finally:
            # Logging is outside the repository lock, including on failure.
            try:
                self._report(name, started, acquired, released, measurement, failed)
            except Exception:
                pass

    def _report(self, name, started, acquired, released, measurement, failed):
        now = self.clock()
        if acquired is None or released is None or now - started < self.slow_seconds:
            return
        with self._report_lock:
            if now < self._next_report.get(name, 0.0):
                return
            self._next_report[name] = now + self.interval_seconds
        LOGGER.warning("observation repository delayed: %s", json.dumps({
            "operation": name, "failed": failed,
            "lock_wait_ms": _milliseconds(acquired - started),
            "lock_held_ms": _milliseconds(released - acquired),
            "sql_count": measurement.sql_count,
            "sql_total_ms": _milliseconds(measurement.sql_seconds),
            "sql_max_ms": _milliseconds(measurement.sql_max),
            "sql_template_sha256": measurement.sql_template_sha256,
            # Includes the session's final flush, if any, and database COMMIT.
            "commit_ms": _milliseconds(measurement.commit_seconds),
        }, sort_keys=True))
