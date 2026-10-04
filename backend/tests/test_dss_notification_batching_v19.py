"""Bound notification bookkeeping without changing durable observation history."""
import asyncio
from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select

from backend import observation_service
from backend.observation_domain import GetTMMode
from backend.observation_models import ObservationOutboxEvent, ObservationStream
from backend.observation_repository import ObservationNotFoundError, ObservationValidationError
from backend.observation_service import ObservationRuntime
from backend.tests.test_observation_repository import observation_store, sample


BASE = datetime(2026, 10, 4, tzinfo=timezone.utc)


def prepare(store, count=100, *, dss=True):
    repository, factory, generation, _ = store
    repository.ingest_sample(sample(generation, sequence=1, engineering=28.0,
        observation_number=25001), mode=GetTMMode.CURRENT, resynchronized=True)
    for row in repository.pending_outbox():
        repository.mark_outbox_published(row["event_id"], published_at=BASE)
    ids = []
    with factory() as session:
        stream = session.scalar(select(ObservationStream))
        for index in range(count):
            # Deliberately reverse ID order: publish order is the existing
            # creation order, while row locks use a stable sorted-ID order.
            event_id = f"notification-{count-index:04d}"
            repository._emit(session, stream, event_type="telemetry.sample_observed",
                aggregate_type="telemetry_sample", aggregate_id=f"sample-{index}",
                data={"ordinal": index}, created_at=BASE+timedelta(microseconds=index),
                event_id=event_id)
            ids.append(event_id)
        session.commit()
    repository.dss_enabled = dss
    return repository, factory, ids


def stored(factory):
    with factory() as session:
        return {row.id: {column.name: getattr(row, column.name)
            for column in ObservationOutboxEvent.__table__.columns}
            for row in session.scalars(select(ObservationOutboxEvent))}


def acknowledged(factory, ids):
    rows = stored(factory)
    return [key for key in ids if rows[key]["published_at"] is not None]


@pytest.mark.parametrize("dss, commits", [(True, 7), (False, 100)])
def test_ordered_hundred_notifications_preserve_history_and_exact_completion_times(
    observation_store, monkeypatch, dss, commits,
):
    repository, factory, ids = prepare(observation_store, dss=dss)
    before, calls, batches, transactions, statements, times = stored(factory), [], [], [], [], []
    original = repository.mark_outbox_published_batch

    def batch(entries):
        batches.append(entries.copy())
        return original(entries)

    def now(_timezone):
        value = BASE + timedelta(seconds=10, microseconds=len(times))
        times.append(value)
        return value

    def publisher(_topic, envelope):
        calls.append(envelope)
        row = before[envelope["event_id"]]
        assert envelope == {**row["payload"],
            "created_at": row["created_at"].replace(tzinfo=timezone.utc).isoformat(),
            "projection_sequence": str(row["projection_sequence"])}

    monkeypatch.setattr(repository, "mark_outbox_published_batch", batch)
    monkeypatch.setattr(observation_service, "datetime", SimpleNamespace(now=now))
    database = factory.kw["bind"]
    def on_commit(_connection):
        transactions.append(True)
    def on_sql(_connection, _cursor, sql, _params, _context, _many):
        statements.append(sql)
    event.listen(database, "commit", on_commit)
    event.listen(database, "before_cursor_execute", on_sql)
    try:
        assert asyncio.run(ObservationRuntime(repository, publisher=publisher).publish_once()) == 100
    finally:
        event.remove(database, "commit", on_commit)
        event.remove(database, "before_cursor_execute", on_sql)
    assert [entry["event_id"] for entry in calls] == ids
    assert len(transactions) == commits
    if dss:
        assert [len(entries) for entries in batches] == [16]*6+[4]
        selects = [sql for sql in statements if "WHERE observation_outbox.id IN" in sql]
        assert len(selects) == 7
        assert all("ORDER BY observation_outbox.id" in sql and "observation_outbox.payload" not in sql for sql in selects)
    else:
        assert batches == []
    after = stored(factory)
    assert set(after) == set(before)
    for index, key in enumerate(ids):
        assert after[key]["published_at"].replace(tzinfo=timezone.utc) == times[index]
        assert after[key]["delivery_attempts"] == 1
        for field in before[key]:
            if field not in {"published_at", "delivery_attempts"}:
                assert after[key][field] == before[key][field]
    # A repeated acknowledgement cannot move timestamps or increment attempts.
    repository.mark_outbox_published_batch([(key, BASE+timedelta(days=1)) for key in ids[:16]])
    assert stored(factory) == after


def test_callback_failure_flushes_only_successful_prefix_and_replays_failed_event(observation_store):
    repository, factory, ids = prepare(observation_store, count=30)
    calls, failure = [], RuntimeError("publisher failed")
    def publisher(_topic, envelope):
        calls.append(envelope["event_id"])
        if len(calls) == 20:
            raise failure
    runtime = ObservationRuntime(repository, publisher=publisher)
    with pytest.raises(RuntimeError) as caught:
        asyncio.run(runtime.publish_once())
    assert caught.value is failure
    assert acknowledged(factory, ids) == ids[:19]
    assert calls == ids[:20]
    replay = []
    runtime.publisher = lambda _topic, envelope: replay.append(envelope["event_id"])
    assert asyncio.run(runtime.publish_once()) == 11
    assert replay == ids[19:]


def test_callback_cancellation_flushes_successful_prefix_and_leaves_uncertain_callback_pending(observation_store):
    repository, factory, ids = prepare(observation_store, count=30)
    async def scenario():
        started, calls = asyncio.Event(), []
        async def publisher(_topic, envelope):
            calls.append(envelope["event_id"])
            if len(calls) == 20:
                started.set()
                await asyncio.Event().wait()
        task = asyncio.create_task(ObservationRuntime(repository, publisher=publisher).publish_once())
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert calls == ids[:20]
        assert acknowledged(factory, ids) == ids[:19]
    asyncio.run(scenario())


def test_cancellation_joins_inflight_flush_even_after_repeated_cancel(observation_store, monkeypatch):
    repository, factory, ids = prepare(observation_store, count=30)
    original = repository.mark_outbox_published_batch
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def blocked(entries):
        entered.set()
        assert release.wait(3)
        try:
            return original(entries)
        finally:
            finished.set()
    monkeypatch.setattr(repository, "mark_outbox_published_batch", blocked)
    async def scenario():
        calls = []
        task = asyncio.create_task(ObservationRuntime(repository,
            publisher=lambda _topic, envelope: calls.append(envelope["event_id"])).publish_once())
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            assert not finished.is_set()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            assert finished.is_set()
            assert calls == ids[:16]
            assert acknowledged(factory, ids) == ids[:16]
        finally:
            release.set()
    asyncio.run(scenario())


def test_failed_batch_is_not_retried_by_cleanup_and_replays_stable_ids(observation_store, monkeypatch):
    repository, factory, ids = prepare(observation_store, count=40)
    original, batches, callbacks = repository.mark_outbox_published_batch, [], []
    failure = RuntimeError("transaction unavailable")
    def fail_second(entries):
        batches.append(entries.copy())
        if len(batches) == 2:
            raise failure
        return original(entries)
    monkeypatch.setattr(repository, "mark_outbox_published_batch", fail_second)
    runtime = ObservationRuntime(repository,
        publisher=lambda _topic, envelope: callbacks.append(envelope["event_id"]))
    with pytest.raises(RuntimeError) as caught:
        asyncio.run(runtime.publish_once())
    assert caught.value is failure
    assert len(batches) == 2
    assert callbacks == ids[:32]
    assert acknowledged(factory, ids) == ids[:16]
    monkeypatch.setattr(repository, "mark_outbox_published_batch", original)
    callbacks.clear()
    assert asyncio.run(runtime.publish_once()) == 24
    assert callbacks == ids[16:]
    assert all(stored(factory)[key]["delivery_attempts"] == 1 for key in ids)


def test_commit_failure_rolls_back_flushed_acknowledgements_and_replays_exact_ids(observation_store):
    repository, factory, ids = prepare(observation_store, count=20)
    before, calls, flushed = stored(factory), [], []
    failure = RuntimeError("commit rejected after update flush")
    def fail_commit(session):
        session.flush()
        values = session.execute(select(ObservationOutboxEvent.published_at,
            ObservationOutboxEvent.delivery_attempts).where(
                ObservationOutboxEvent.id.in_(ids[:16]))).all()
        assert len(values) == 16
        assert all(at is not None and attempts == 1 for at, attempts in values)
        flushed.append(True)
        raise failure
    event.listen(factory.class_, "before_commit", fail_commit)
    runtime = ObservationRuntime(repository,
        publisher=lambda _topic, envelope: calls.append(envelope["event_id"]))
    try:
        with pytest.raises(RuntimeError) as caught:
            asyncio.run(runtime.publish_once())
        assert caught.value is failure
    finally:
        event.remove(factory.class_, "before_commit", fail_commit)
    assert flushed == [True]
    assert calls == ids[:16]
    assert stored(factory) == before
    calls.clear()
    assert asyncio.run(runtime.publish_once()) == 20
    assert calls == ids
    assert acknowledged(factory, ids) == ids


@pytest.mark.parametrize("cancel", [False, True])
def test_prefix_persistence_failure_preserves_primary_callback_failure(observation_store, monkeypatch, cancel):
    repository, factory, ids = prepare(observation_store, count=10)
    failure = asyncio.CancelledError() if cancel else RuntimeError("original callback failure")
    calls, batches = [], []
    def publisher(_topic, envelope):
        calls.append(envelope["event_id"])
        if len(calls) == 4:
            raise failure
    def fail_flush(entries):
        batches.append(entries)
        raise RuntimeError("cleanup persistence failed")
    monkeypatch.setattr(repository, "mark_outbox_published_batch", fail_flush)
    with pytest.raises(type(failure)) as caught:
        asyncio.run(ObservationRuntime(repository, publisher=publisher).publish_once())
    assert caught.value is failure
    assert [[key for key, _at in entries] for entries in batches] == [ids[:3]]
    assert acknowledged(factory, ids) == []


@pytest.mark.parametrize("bad", ["missing", "invalid", "duplicate", "oversize", "timestamp"])
def test_invalid_late_acknowledgement_cannot_partially_mark_events(observation_store, bad):
    repository, factory, ids = prepare(observation_store, count=20)
    before = stored(factory)
    entries = [(key, BASE) for key in ids[:15]]
    entries.append(("missing-event" if bad == "missing" else "bad id" if bad == "invalid" else ids[0] if bad == "duplicate" else ids[15], None if bad == "timestamp" else BASE))
    if bad == "oversize":
        entries.append((ids[16], BASE))
    with pytest.raises(ObservationNotFoundError if bad == "missing" else ObservationValidationError):
        repository.mark_outbox_published_batch(entries)
    assert stored(factory) == before
