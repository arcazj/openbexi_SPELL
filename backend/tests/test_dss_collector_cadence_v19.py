"""DSS NEXT polling keeps up without dropping history or extending freshness."""
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from backend import observation_service
from backend.observation_domain import GetTMMode, GetTMResult, SampleIdentity, ObservationResultCode, sample_id_for
from backend.observation_models import ObservationOutboxEvent, TelemetryGap, TelemetrySample
from backend.observation_repository import ObservationRepository
from backend.observation_service import ObservationRuntime
from backend.tests.test_dss_collector_lifecycle_v19 import unavailable_time
from backend.tests.test_observation_batching_v19 import populate
from backend.tests.test_observation_repository import observation_store
from driver_host.tests.test_dss_transport import engine


def install_clock(monkeypatch, now, sleep):
    # Replace only the collector's module references, not asyncio's event-loop
    # clock or sleep used by unrelated tasks/real repository worker threads.
    monkeypatch.setattr(observation_service, "time", SimpleNamespace(
        monotonic=lambda: now[0], time_ns=lambda: int(now[0] * 1_000_000_000)))
    monkeypatch.setattr(observation_service, "asyncio", SimpleNamespace(
        sleep=sleep, gather=asyncio.gather, to_thread=asyncio.to_thread,
        create_task=asyncio.create_task, shield=asyncio.shield,
        CancelledError=asyncio.CancelledError))


@pytest.mark.parametrize("bursts", [False, True])
def test_continuous_22_item_next_history_stays_fresh_beyond_legacy_lag_threshold(
    observation_store, engine, monkeypatch, bursts,
):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    bases = populate(repository, generation, clock, engine, dss=True)
    assert len(bases) == 22
    base_ns = bases[0].acquired_at_unix_ns
    now = [0.0]
    # One physical publication each second, plus two immediate command-caused
    # publications. They remain separate sequential observations, never skipped.
    publications = sorted([float(i) for i in range(66)] + ([18.15, 18.4] if bursts else []))
    goal = len(publications)
    base_by_item = {value.sample_identity.item_id: value for value in bases}
    received, queries, sleeps, errors = [], [], [], []
    store_lock = threading.Lock()
    original_ingest = repository._ingest_sample_in_session

    def advance(seconds):
        now[0] += seconds
        clock[0] = base_ns + round(now[0] * 1_000_000_000)

    def ingest(session, value, **kwargs):
        # Deterministic 0.89-second full cohort cost models serialized storage
        # work. The real repository still persists every item/cursor/alarm in
        # the cohort commit and applies its unchanged acquisition freshness.
        with store_lock:
            result = original_ingest(session, value, **kwargs)
            advance(0.89 / 22)
            received.append((value.sample_identity.item_id,
                value.sample_identity.source_sequence, value.sample_identity.sample_id,
                (clock[0] - value.acquired_at_unix_ns) / 1_000_000_000))
            return result

    monkeypatch.setattr(repository, "_ingest_sample_in_session", ingest)
    monkeypatch.setattr(repository, "_database_now", lambda session:
        datetime.fromtimestamp(clock[0] / 1_000_000_000, tz=timezone.utc))

    async def get_tm(query):
        assert query.mode is GetTMMode.NEXT
        assert query.generations == generation
        sequence = query.after_source_sequence + 1
        assert 2 <= sequence <= goal
        acquired = publications[sequence - 1]
        assert acquired <= query.deadline_unix_ns / 1_000_000_000
        if now[0] < acquired:
            advance(acquired - now[0])
        original = base_by_item[query.item_id]
        identity = original.sample_identity
        queries.append((query.item_id, sequence))
        return GetTMResult(ObservationResultCode.OK, sample=replace(original,
            observation_id=query.observation_id,
            sample_identity=SampleIdentity(sample_id_for(identity.source_id,
                identity.source_epoch, query.item_id, sequence), query.item_id,
                identity.source_id, identity.source_epoch, sequence),
            acquired_at_unix_ns=base_ns + round(acquired * 1_000_000_000)))

    async def sleep(delay):
        if errors:
            raise errors[0]
        sleeps.append(delay)
        advance(delay)
        if len(received) == (goal - 1) * 22:
            runtime._closing = True
        await asyncio.sleep(0)

    install_clock(monkeypatch, now, sleep)
    runtime = ObservationRuntime(repository,
        generation_provider=lambda: {"host": replace(generation, context_id="",
            context_generation="", context_binding_digest=""),
            "contexts": (generation,), "credential_epoch": 1},
        get_time=unavailable_time, get_tm=get_tm, item_ids=tuple(base_by_item))
    original_collect = runtime.collect_once
    async def collect():
        try:
            return await original_collect()
        except Exception as exc:
            errors.append(exc)
            raise
    monkeypatch.setattr(runtime, "collect_once", collect)
    async def bounded_run():
        await asyncio.wait_for(runtime._run_collector(), 30)
    asyncio.run(bounded_run())
    assert now[0] >= 65
    assert all(delay == 0 for delay in sleeps)
    assert len(sleeps) == goal - 1
    assert all(age < 5 for _, _, _, age in received)
    for item_id in base_by_item:
        assert [seq for item, seq in queries if item == item_id] == list(range(2, goal + 1))
    with factory() as session:
        rows = session.scalars(select(TelemetrySample)
            .where(TelemetrySample.context_generation_id == generation.context_generation)).all()
        events = session.scalars(select(ObservationOutboxEvent).where(
            ObservationOutboxEvent.event_type == "telemetry.sample_observed")).all()
        assert session.scalar(select(TelemetryGap)) is None
    # Audit every immutable admission once, rather than opening one extra test
    # read transaction per sample inside the bounded collector run. A later
    # healthy head cannot conceal an earlier gapped/stale admission.
    expected = {(value.sample_identity.item_id, value.sample_identity.source_sequence,
        value.sample_identity.sample_id) for value in bases}
    expected.update((item, sequence, identity) for item, sequence, identity, _ in received)
    assert len(expected) == len(rows) == len(events) == goal * 22
    assert {(row.item_id, row.source_sequence, row.id) for row in rows} == expected
    assert all(row.freshness == "FRESH" for row in rows)
    assert {(row.payload["data"]["item_id"], int(row.payload["data"]["source_sequence"]),
        row.payload["data"]["sample_id"]) for row in events} == expected
    assert all(row.payload["data"]["freshness"] == "FRESH"
        and row.payload["data"]["synchronization_state"] == "COMPLETE" for row in events)
    for item_id in base_by_item:
        assert sorted(row.source_sequence for row in rows if row.item_id == item_id) == list(range(1, goal + 1))
    # Independent old cadence counterfactual: the same work plus unconditional
    # 200ms sleep accumulates stale heads, even without a reset or packet loss.
    old_time, old_max_age = 0.0, 0.0
    for acquired in publications[1:]:
        old_time = max(old_time, acquired) + 0.89
        old_max_age = max(old_max_age, old_time - acquired)
        old_time += 0.2
    assert old_max_age > 5


@pytest.mark.parametrize("case", ["legacy", "empty", "clock_only", "failed_after_progress"])
def test_collector_keeps_backoff_without_successful_dss_sample_progress(monkeypatch, case):
    now, sleeps, calls = [0.0], [], []
    runtime = ObservationRuntime(SimpleNamespace(dss_enabled=case != "legacy"))

    async def collect():
        calls.append(now[0])
        runtime._collected_samples = 22 if case in {"legacy", "failed_after_progress"} else 0
        now[0] += 0.9
        if case == "failed_after_progress":
            raise ValueError("peer rejected after another item committed")
        return 1 if case == "clock_only" else runtime._collected_samples

    async def sleep(delay):
        sleeps.append(delay)
        now[0] += delay
        if len(calls) == 3:
            runtime._closing = True
        await asyncio.sleep(0)

    install_clock(monkeypatch, now, sleep)
    monkeypatch.setattr(runtime, "collect_once", collect)
    asyncio.run(runtime._run_collector())
    assert sleeps == [0.2] * 3
    assert calls == pytest.approx([0.0, 1.1, 2.2])


@pytest.mark.parametrize("duration, expected_sleep", [(0.05, 0.15), (0.9, 0.0)])
def test_successful_dss_cadence_yields_and_cancels_without_another_cohort(monkeypatch, duration, expected_sleep):
    async def scenario():
        now, calls, sleeps = [0.0], [], []
        runtime = ObservationRuntime(SimpleNamespace(dss_enabled=True))
        sleeping = asyncio.Event()

        async def collect():
            calls.append(True)
            now[0] += duration
            runtime._collected_samples = 22
            return 22

        async def sleep(delay):
            sleeps.append(delay)
            sleeping.set()
            await asyncio.Event().wait()

        install_clock(monkeypatch, now, sleep)
        monkeypatch.setattr(runtime, "collect_once", collect)
        task = asyncio.create_task(runtime._run_collector())
        await asyncio.wait_for(sleeping.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert calls == [True]
        assert sleeps == pytest.approx([expected_sleep])
    asyncio.run(scenario())
