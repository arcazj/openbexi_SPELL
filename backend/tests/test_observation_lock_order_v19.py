"""Real PostgreSQL lock ordering prevents snapshot/freshness alarm deadlocks."""
import os
import threading

import pytest
from sqlalchemy import event, select, text

from backend.database import create_database
from backend.driver_models import DriverContextGeneration
from backend.observation_domain import GetTMMode
from backend.observation_models import ObservationStream
from backend.observation_repository import ObservationRepository
from backend.tests import test_observation_repository as fixtures
from backend.tests.test_observation_repository import observation_store, sample
from backend.tests.migration_support import reset_test_database


@pytest.mark.skipif(not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
                   reason="dedicated PostgreSQL migration database not configured")
def test_freshness_sweep_waits_for_context_before_stream_and_alarm_fk(monkeypatch, request):
    url = os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"]
    engine, _ = create_database(url)
    reset_test_database(engine)
    engine.dispose()
    monkeypatch.setattr(fixtures, "create_database", lambda _: create_database(url))
    repository, sessions, generations, clock = request.getfixturevalue("observation_store")
    repository.ingest_sample(
        sample(generations, sequence=1, engineering=28.0, observation_number=7491),
        mode=GetTMMode.CURRENT, resynchronized=True,
    )
    clock[0] += 10_000_000_000
    other = ObservationRepository(sessions, clock_ns=lambda: clock[0])
    reached_lock = threading.Event()
    errors, result = [], []
    bind = sessions.kw["bind"]
    def on_query(_connection, _cursor, statement, _parameters, _context, _many):
        if (threading.current_thread().name == "freshness-sweep-proof"
                and "FOR UPDATE" in statement and "FROM driver_context_generations" in statement):
            reached_lock.set()
    def after_query(_connection, _cursor, statement, _parameters, _context, _many):
        if (threading.current_thread().name == "freshness-sweep-proof"
                and "FOR UPDATE" in statement and "FROM observation_streams" in statement):
            reached_lock.set()
    event.listen(bind, "before_cursor_execute", on_query)
    event.listen(bind, "after_cursor_execute", after_query)
    def sweep():
        try:
            result.append(other.mark_stale())
        except Exception as exc:
            errors.append(exc)
    thread = threading.Thread(target=sweep, name="freshness-sweep-proof")
    try:
        with sessions.begin() as session:
            session.scalar(select(DriverContextGeneration)
                .where(DriverContextGeneration.id == generations.context_generation).with_for_update())
            thread.start()
            assert reached_lock.wait(5), "sweep never reached a row-lock request"
            # It must wait on our context, leaving the stream available. The old
            # implementation held this stream then needed our context for its FK.
            session.execute(text("SET LOCAL lock_timeout = '1000ms'"))
            stream = session.scalar(select(ObservationStream)
                .where(ObservationStream.context_generation_id == generations.context_generation)
                .with_for_update(nowait=True))
            assert stream is not None
        thread.join(8)
        assert not thread.is_alive() and errors == [] and result == [1]
        snapshot = repository.snapshot("simulator")
        assert snapshot["items"][0]["freshness"] == "STALE"
    finally:
        thread.join(10)
        event.remove(bind, "before_cursor_execute", on_query)
        event.remove(bind, "after_cursor_execute", after_query)
