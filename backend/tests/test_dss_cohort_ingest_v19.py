"""Real DSS cohorts commit atomically without dropping samples or weakening fences."""
import asyncio
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import threading
from uuid import UUID

import pytest
from sqlalchemy import event, inspect, select
from sqlalchemy.orm.attributes import flag_modified

from backend import observation_repository as repository_module
from backend.driver_models import DriverContextGeneration
from backend.observation_domain import (
    DriverTelemetrySample, GapBounds, GetTMMode, GetTMResult, GetTimeResult, ItemIdentity,
    ObservationError, ObservationResultCode, Quality, SampleIdentity,
    ScalarKind, ScalarValue, Validity, sample_id_for,
)
from backend.observation_models import (
    DriverTimeHead, DriverTimeObservation, ObservationOutboxEvent, ObservationStream,
    TelemetryAlarmHead, TelemetryAlarmObservation, TelemetryGap, TelemetryItemHead,
    TelemetrySample, TelemetrySourceCursor,
)
from backend.observation_repository import (
    DssSampleAdmission, ObservationConflictError, ObservationRepository,
    ObservationStaleGenerationError, ObservationValidationError,
)
from backend.observation_service import ObservationRuntime
from backend.tests.test_dss_clock_epoch_v19 import clock_value
from backend.tests.test_dss_observation_profile_v19 import dss_sample
from backend.tests.test_observation_repository import observation_store
from dss.catalog import TELEMETRY_ITEMS
from dss.packets import decode_tm
from driver_host.tests.test_dss_transport import engine


TABLES = (TelemetrySample, TelemetryItemHead, TelemetrySourceCursor,
    TelemetryAlarmObservation, TelemetryAlarmHead, TelemetryGap,
    ObservationOutboxEvent, ObservationStream, DriverTimeObservation, DriverTimeHead)


def history(factory):
    with factory() as session:
        return {model.__tablename__: [dict(row) for row in session.execute(
            select(model.__table__).order_by(*model.__table__.primary_key.columns)
        ).mappings()] for model in TABLES}


def configured(store):
    _, factory, generation, clock = store
    return ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True), factory, generation, clock


def packet_samples(generation, clock, engine):
    """Use an actual encoded/decoded DSS packet as the independent 22-item input."""
    body = decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
    clock[0] = body["acquired_at_unix_ns"] + 1000
    definitions = {row["item_id"]: row for row in TELEMETRY_ITEMS}
    values = []
    for index, item in enumerate(sorted(body["items"], key=lambda row: row["item_id"])):
        name, epoch, sequence = item["item_id"], body["satellite_epoch"], body["tm_sequence"]
        definition = definitions[name]
        values.append(DriverTelemetrySample(str(UUID(int=51000 + index)), generation,
            SampleIdentity(sample_id_for("dss-GENERIC", epoch, name, sequence), name,
                "dss-GENERIC", epoch, sequence),
            ItemIdentity(name, definition["qualified_name"], definition["catalog_digest"]),
            ScalarValue(ScalarKind(item["raw"]["type"]), item["raw"]["value"]),
            ScalarValue(ScalarKind(item["engineering"]["type"]), item["engineering"]["value"]),
            definition["description"], definition["unit"], body["acquired_at_unix_ns"],
            "SIMULATOR", "dss-dynamics-clock", 1000,
            Validity(item["validity"]), Quality(item["quality"]), item["quality_reason"]))
    assert len(values) == 22 and {value.sample_identity.item_id for value in values} == set(definitions)
    return tuple(values)


def frame(values, sequence, *, epoch=None):
    return tuple(replace(value, observation_id=str(UUID(int=52000 + sequence * 128 + index)),
        sample_identity=SampleIdentity(sample_id_for("dss-GENERIC", epoch or value.sample_identity.source_epoch,
            value.sample_identity.item_id, sequence), value.sample_identity.item_id, "dss-GENERIC",
            epoch or value.sample_identity.source_epoch, sequence)) for index, value in enumerate(values))


def admissions(values, mode=GetTMMode.CURRENT, resynchronized=True):
    return tuple(DssSampleAdmission(value, mode, resynchronized) for value in values)


@contextmanager
def commits(factory):
    calls = []
    def committed(_connection): calls.append(True)
    database = factory.kw["bind"]
    event.listen(database, "commit", committed)
    try:
        yield calls
    finally:
        event.remove(database, "commit", committed)


def runtime_for(repository, generation, values, clock, *, missing=None):
    by_item = {value.sample_identity.item_id: value for value in values}
    missing_items = {missing} if isinstance(missing, str) else set(missing or ())
    requests = []
    async def get_tm(query):
        requests.append(query)
        if query.item_id in missing_items:
            return GetTMResult(ObservationResultCode.NOT_AVAILABLE,
                error=ObservationError(ObservationResultCode.NOT_AVAILABLE, "declared missing item"))
        return GetTMResult(ObservationResultCode.OK,
            sample=replace(by_item[query.item_id], observation_id=query.observation_id))
    observed_clock = clock_value(generation, clock[0], epoch=values[0].sample_identity.source_epoch)
    runtime = ObservationRuntime(repository,
        generation_provider=lambda: {"host": observed_clock.generations,
            "contexts": (generation,), "credential_epoch": 1},
        get_time=lambda _query: GetTimeResult(ObservationResultCode.OK, observation=observed_clock),
        get_tm=get_tm, item_ids=tuple(by_item))
    return runtime, requests


def test_full_22_item_cohort_has_one_commit_and_no_post_commit_projection(observation_store, engine, monkeypatch):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    monkeypatch.setattr(repository, "_sample_projection", lambda *_:
        pytest.fail("DSS completion must not open an unused post-commit projection"))
    with commits(factory) as actual:
        assert repository.ingest_samples(admissions(values)) == 22
    assert actual == [True]
    stored = history(factory)
    assert len(stored["telemetry_samples"]) == len(stored["telemetry_item_heads"]) == 22
    assert len(stored["telemetry_alarm_observations"]) == len(stored["telemetry_alarm_heads"]) == 22
    assert {row["id"] for row in stored["telemetry_samples"]} == {v.sample_identity.sample_id for v in values}
    assert not stored["telemetry_gaps"]


def test_single_and_atomic_admission_have_exact_complete_history_parity(tmp_path, engine, monkeypatch):
    # Warm the actual ORM update default, reproducing the order of the full
    # candidate suite. Clock inputs are supplied in a local event, not by
    # modifying SQLAlchemy's cached ColumnDefault callable.
    warm = tmp_path / "warm"
    warm.mkdir()
    fixture = observation_store.__wrapped__(warm)
    try:
        repository, _, generation, clock = configured(next(fixture))
        repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT, resynchronized=True)
    finally:
        fixture.close()
    histories, projections, commit_counts = [], [], []
    body_values = None
    for batch in (False, True):
        directory = tmp_path / str(batch)
        directory.mkdir()
        fixture = observation_store.__wrapped__(directory)
        repository, factory, generation, clock = configured(next(fixture))
        if body_values is None:
            body_values = packet_samples(generation, clock, engine)
        else:
            clock[0] = body_values[0].acquired_at_unix_ns + 1000
        values = body_values
        ids = iter(range(60000, 65000))
        with monkeypatch.context() as patch:
            patch.setattr(repository_module.uuid, "uuid4", lambda: UUID(int=next(ids)))
            patch.setattr(repository, "_database_now", lambda _session:
                datetime.fromtimestamp(clock[0] / 1_000_000_000, timezone.utc))
            def freeze_inputs(session, _context, _instances):
                now = datetime.fromtimestamp(clock[0] / 1_000_000_000, timezone.utc)
                for row in session.new:
                    if type(row) in TABLES:
                        for name in ("created_at", "updated_at"):
                            if hasattr(row, name) and getattr(row, name) is None:
                                setattr(row, name, now)
                for row in session.dirty:
                    if (type(row) is ObservationStream and session.is_modified(row)
                            and not inspect(row).attrs.updated_at.history.has_changes()):
                        row.updated_at = now
                        flag_modified(row, "updated_at")
            event.listen(factory.class_, "before_flush", freeze_inputs)
            try:
                with commits(factory) as actual:
                    for members, mode, resync in ((values, GetTMMode.CURRENT, True),
                            (frame(values, 2), GetTMMode.NEXT, False),
                            (frame(values, 4), GetTMMode.NEXT, False),
                            (frame(values, 4), GetTMMode.CURRENT, True)):
                        if batch:
                            assert repository.ingest_samples(admissions(members, mode, resync)) == 22
                        else:
                            for value in members:
                                repository.ingest_sample(value, mode=mode,
                                    resynchronized=resync, include_projection=False)
                commit_counts.append(len(actual))
                histories.append(history(factory))
                projections.append(repository.snapshot("simulator")["items"])
            finally:
                event.remove(factory.class_, "before_flush", freeze_inputs)
                fixture.close()
    assert commit_counts == [88, 4]
    assert histories[0] == histories[1]
    assert projections[0] == projections[1]
    assert len(histories[1]["telemetry_samples"]) == 66
    assert len(histories[1]["telemetry_gaps"]) == 22
    assert all(row["state"] == "RESOLVED" for row in histories[1]["telemetry_gaps"])
    assert all(row["expected_sequence"] == 3 and row["observed_sequence"] == 4
        for row in histories[1]["telemetry_gaps"])
    for value in values:
        assert sorted(row["source_sequence"] for row in histories[1]["telemetry_samples"]
            if row["item_id"] == value.sample_identity.item_id) == [1, 2, 4]


@pytest.mark.parametrize("mutation", ["list", "empty", "overflow", "entry_dict", "sample_dict",
    "mode_string", "resync_integer", "mixed_epoch", "mixed_context", "duplicate_item",
    "duplicate_sample", "duplicate_observation", "wrong_catalog", "legacy_repository"])
def test_malformed_cohort_is_rejected_before_any_database_work(observation_store, engine, mutation):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    rows = admissions(values)
    if mutation == "list": rows = list(rows)
    elif mutation == "empty": rows = ()
    elif mutation == "overflow": rows = (rows[0],) * 129
    elif mutation == "entry_dict": rows = (*rows[:-1], {"sample": values[-1]})
    elif mutation == "sample_dict": rows = (*rows[:-1], replace(rows[-1], sample={}))
    elif mutation == "mode_string": rows = (*rows[:-1], replace(rows[-1], mode="CURRENT"))
    elif mutation == "resync_integer": rows = (*rows[:-1], replace(rows[-1], resynchronized=1))
    elif mutation == "mixed_epoch": rows = (*rows[:-1], admissions(frame(values[-1:], 1, epoch="epoch-" + "b" * 64))[0])
    elif mutation == "mixed_context": rows = (*rows[:-1], replace(rows[-1],
        sample=replace(values[-1], generations=replace(generation, context_id="another-context"))))
    elif mutation == "duplicate_item": rows = (*rows[:-1], admissions(frame(values[:1], 2))[0])
    elif mutation == "duplicate_sample": rows = (*rows[:-1], replace(rows[0],
        sample=replace(values[0], observation_id=str(UUID(int=59000)))))
    elif mutation == "duplicate_observation": rows = (*rows[:-1], replace(rows[-1],
        sample=replace(values[-1], observation_id=values[0].observation_id)))
    elif mutation == "wrong_catalog": rows = (*rows[:-1], replace(rows[-1], sample=replace(values[-1],
        item_identity=replace(values[-1].item_identity, catalog_digest="f" * 64))))
    else: repository = observation_store[0]
    before, statements = history(factory), []
    def sql(*_): statements.append(True)
    database = factory.kw["bind"]
    event.listen(database, "before_cursor_execute", sql)
    try:
        with pytest.raises((ObservationValidationError, ObservationConflictError)):
            repository.ingest_samples(rows)
    finally:
        event.remove(database, "before_cursor_execute", sql)
    assert not statements
    assert history(factory) == before


@pytest.mark.parametrize("failure", ["same_epoch_payload", "new_epoch_observation_reuse"])
def test_final_member_conflict_rolls_back_every_member_and_preserves_clock(observation_store, engine, failure):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    repository.ingest_sample(values[-1], mode=GetTMMode.CURRENT, resynchronized=True)
    repository.record_time(clock_value(generation, clock[0], epoch=values[0].sample_identity.source_epoch),
        context_generation_id=generation.context_generation)
    before = history(factory)
    if failure == "same_epoch_payload":
        conflicting = (*values[:-1], replace(values[-1], quality_reason="different-content-for-existing-identity"))
    else:
        # The first new-epoch member retires the old clock/head and emits its
        # retirement event. A last-member identity conflict must undo all of it.
        new_values = frame(values, 1, epoch="epoch-" + "b" * 64)
        conflicting = (*new_values[:-1], replace(new_values[-1], observation_id=values[-1].observation_id))
    with pytest.raises(ObservationConflictError, match="reused"):
        repository.ingest_samples(admissions(conflicting))
    assert history(factory) == before
    assert repository.snapshot("simulator")["driver_time"]["source_epoch"] == values[0].sample_identity.source_epoch


def test_commit_failure_after_all_22_flushed_rows_is_atomic_and_retry_is_idempotent(observation_store, engine):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    before, flushed = history(factory), []
    def fail(session):
        session.flush()
        assert len(session.scalars(select(TelemetrySample)).all()) == 22
        assert len(session.scalars(select(TelemetryAlarmObservation)).all()) == 22
        assert len(session.scalars(select(ObservationOutboxEvent)).all()) >= 44
        flushed.append(True)
        raise RuntimeError("deliberate cohort commit failure")
    event.listen(factory.class_, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="deliberate cohort commit failure"):
            repository.ingest_samples(admissions(values))
    finally:
        event.remove(factory.class_, "before_commit", fail)
    assert flushed == [True] and history(factory) == before
    assert repository.ingest_samples(admissions(values)) == 22
    accepted = history(factory)
    assert repository.ingest_samples(admissions(values)) == 22
    assert history(factory) == accepted


@pytest.mark.parametrize("mutation", ["retired_epoch", "retired_context"])
def test_batch_retains_epoch_and_context_fences_without_partial_history(observation_store, engine, mutation):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    repository.ingest_samples(admissions(values))
    next_values = frame(values, 2)
    if mutation == "retired_epoch":
        repository.ingest_samples(admissions(frame(values, 1, epoch="epoch-" + "b" * 64)))
    else:
        with factory() as session:
            context = session.get(DriverContextGeneration, generation.context_generation)
            context.state, context.ready = "FAILED", False
            session.commit()
    before = history(factory)
    with pytest.raises(ObservationConflictError):
        repository.ingest_samples(admissions(next_values))
    assert history(factory) == before


@pytest.mark.parametrize("kind", ["bad_quality", "invalid", "stale", "policy", "source_gap"])
def test_negative_sample_metadata_is_retained_not_filtered_or_upgraded(observation_store, engine, kind):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    changes = {"bad_quality": {"quality": Quality.BAD}, "invalid": {"validity": Validity.INVALID},
        "stale": {"acquired_at_unix_ns": clock[0] - 10_000_000_000},
        "policy": {"quality": Quality.UNKNOWN, "quality_reason": "DSS_POLICY_REVISION_MISMATCH"},
        "source_gap": {"quality": Quality.UNKNOWN, "quality_reason": "DSS_SOURCE_GAP"}}[kind]
    values = tuple(replace(value, **changes) for value in values)
    assert repository.ingest_samples(admissions(values)) == 22
    stored = history(factory)
    assert len(stored["telemetry_samples"]) == len(stored["telemetry_alarm_observations"]) == 22
    for row, value in zip(sorted(stored["telemetry_samples"], key=lambda r:r["item_id"]), values):
        assert row["quality"] == value.quality.value and row["validity"] == value.validity.value
        assert row["quality_reason"] == value.quality_reason
        assert row["freshness"] == ("STALE" if kind == "stale" else "FRESH")
    assert all(row["state"] == "INDETERMINATE" for row in stored["telemetry_alarm_observations"])


@pytest.mark.parametrize("success_count", [22, 21, 1])
def test_collector_commits_actual_ok_subset_once_then_admits_matching_clock(observation_store, engine, monkeypatch, success_count):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    missing = {value.sample_identity.item_id for value in values[success_count:]}
    runtime, requests = runtime_for(repository, generation, values, clock, missing=missing)
    order, original = [], repository.record_time
    def record_time(value, **kwargs):
        rows = history(factory)["telemetry_samples"]
        assert len(rows) == success_count
        assert {row["item_id"] for row in rows} == {v.sample_identity.item_id for v in values} - missing
        order.append("clock-after-complete-durable-subset")
        return original(value, **kwargs)
    monkeypatch.setattr(repository, "record_time", record_time)
    with commits(factory) as actual:
        assert asyncio.run(runtime.collect_once()) == success_count + 1
    assert actual == [True, True] and len(requests) == 22
    assert runtime._collected_samples == success_count
    assert order == ["clock-after-complete-durable-subset"]
    assert repository.snapshot("simulator")["driver_time"]["source_epoch"] == values[0].sample_identity.source_epoch


def test_cohort_allows_distinct_real_per_item_sequences_without_skipping_history(observation_store, engine):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    members = tuple(frame((value,), index + 1)[0] for index, value in enumerate(values))
    assert repository.ingest_samples(admissions(members)) == 22
    stored = history(factory)
    expected = {(value.sample_identity.item_id, value.sample_identity.source_sequence,
        value.sample_identity.sample_id) for value in members}
    assert {(row["item_id"], row["source_sequence"], row["id"])
        for row in stored["telemetry_samples"]} == expected
    assert {row["source_sequence"] for row in stored["telemetry_item_heads"]} == set(range(1, 23))
    assert not stored["telemetry_gaps"]


@pytest.mark.parametrize("code", [ObservationResultCode.GAP, ObservationResultCode.STALE_GENERATION])
def test_collector_records_gap_or_epoch_retry_after_ok_subset_without_second_rpc(observation_store, engine, code):
    repository, factory, generation, clock = configured(observation_store)
    initial = packet_samples(generation, clock, engine)
    repository.ingest_samples(admissions(initial))
    values = frame(initial, 2)
    runtime, _ = runtime_for(repository, generation, values, clock)
    special, recovered = initial[0].sample_identity.item_id, initial[1].sample_identity.item_id
    runtime._force_current.add((generation.context_generation, recovered))
    by_item, requests = {v.sample_identity.item_id: v for v in values}, []
    async def get_tm(query):
        requests.append(query)
        if query.item_id == special:
            assert query.mode is GetTMMode.NEXT and query.after_source_sequence == 1
            if code is ObservationResultCode.GAP:
                return GetTMResult(code, gap=GapBounds(initial[0].sample_identity.source_epoch, 3, 3))
            return GetTMResult(code, error=ObservationError(code, "declared epoch transition"))
        return GetTMResult(ObservationResultCode.OK,
            sample=replace(by_item[query.item_id], observation_id=query.observation_id))
    runtime.get_tm = get_tm
    assert asyncio.run(runtime.collect_once()) == 22
    assert len(requests) == len({query.item_id for query in requests}) == 22
    assert runtime._force_current == {(generation.context_generation, special)}
    assert runtime._collected_samples == 21
    stored = history(factory)
    assert len(stored["telemetry_samples"]) == 43
    heads = {row["item_id"]: row for row in stored["telemetry_item_heads"]}
    assert heads[special]["source_sequence"] == 1
    assert heads[special]["synchronization_state"] == ("GAPPED" if code is ObservationResultCode.GAP else "COMPLETE")
    assert all(heads[name]["source_sequence"] == 2 for name in heads if name != special)
    assert len(stored["telemetry_gaps"]) == (1 if code is ObservationResultCode.GAP else 0)
    if code is ObservationResultCode.GAP:
        assert stored["telemetry_gaps"][0]["expected_sequence"] == 2
        assert stored["telemetry_gaps"][0]["observed_sequence"] == 3
    assert repository.snapshot("simulator")["driver_time"]["source_epoch"] == initial[0].sample_identity.source_epoch


def test_rpc_exception_joins_every_peer_without_admission_clock_or_progress(observation_store, engine, monkeypatch):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    runtime, _ = runtime_for(repository, generation, values, clock)
    original_flags = {(generation.context_generation, v.sample_identity.item_id) for v in values}
    runtime._force_current.update(original_flags)
    monkeypatch.setattr(repository, "ingest_samples", lambda *_:
        pytest.fail("a failed RPC cohort must not enter database admission"))
    monkeypatch.setattr(repository, "record_time", lambda *_a, **_k:
        pytest.fail("a failed RPC cohort must not admit its clock"))
    before, requests, finished = history(factory), [], []
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        by_item = {v.sample_identity.item_id: v for v in values}
        first, last = values[0].sample_identity.item_id, values[-1].sample_identity.item_id
        async def get_tm(query):
            requests.append(query)
            if query.item_id == first:
                await entered.wait()
                raise RuntimeError("actual RPC failed before cohort admission")
            if query.item_id == last:
                entered.set()
                await release.wait()
                finished.append(query.item_id)
            return GetTMResult(ObservationResultCode.OK,
                sample=replace(by_item[query.item_id], observation_id=query.observation_id))
        runtime.get_tm = get_tm
        task = asyncio.create_task(runtime.collect_once())
        try:
            await asyncio.wait_for(entered.wait(), 5)
            await asyncio.sleep(0)
            assert not task.done()
        finally:
            release.set()
            with pytest.raises(RuntimeError, match="actual RPC failed"):
                await asyncio.wait_for(task, 5)
        assert finished == [last]
    asyncio.run(scenario())
    assert len(requests) == 22 and runtime._collected_samples == 0
    assert runtime._force_current == original_flags
    assert history(factory) == before


def test_rejected_cohort_does_not_admit_clock_or_clear_recovery_flags(observation_store, engine, monkeypatch):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    runtime, requests = runtime_for(repository, generation, values, clock)
    expected_flags = {(generation.context_generation, value.sample_identity.item_id) for value in values}
    runtime._force_current.update(expected_flags)
    def fail(session):
        session.flush()
        assert len(session.scalars(select(TelemetrySample)).all()) == 22
        raise RuntimeError("cohort commit rejected")
    monkeypatch.setattr(repository, "record_time", lambda *_a, **_k:
        pytest.fail("clock cannot be admitted after a rejected cohort"))
    before = history(factory)
    event.listen(factory.class_, "before_commit", fail)
    try:
        with pytest.raises(RuntimeError, match="cohort commit rejected"):
            asyncio.run(runtime.collect_once())
    finally:
        event.remove(factory.class_, "before_commit", fail)
    assert len(requests) == 22 and runtime._collected_samples == 0
    assert runtime._force_current == expected_flags
    assert history(factory) == before


def test_cancelled_collector_joins_real_blocked_batch_and_never_admits_clock(observation_store, engine, monkeypatch):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    runtime, requests = runtime_for(repository, generation, values, clock)
    entered, release, committed = threading.Event(), threading.Event(), threading.Event()
    def block(session):
        session.flush()
        assert len(session.scalars(select(TelemetrySample)).all()) == 22
        entered.set()
        assert release.wait(5), "test cleanup failed to release the actual database thread"
    def done(_session): committed.set()
    monkeypatch.setattr(repository, "record_time", lambda *_a, **_k:
        pytest.fail("cancelled collection must not admit its clock"))
    async def scenario():
        task = asyncio.create_task(runtime.collect_once())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and not committed.is_set()
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        assert committed.is_set()
    event.listen(factory.class_, "before_commit", block)
    event.listen(factory.class_, "after_commit", done)
    try:
        asyncio.run(scenario())
    finally:
        release.set()
        event.remove(factory.class_, "before_commit", block)
        event.remove(factory.class_, "after_commit", done)
    assert len(requests) == 22 and runtime._collected_samples == 0
    stored = history(factory)
    assert len(stored["telemetry_samples"]) == 22 and not stored["driver_time_observations"]


def test_batch_keeps_five_second_acquisition_freshness_and_all_history(observation_store, engine):
    repository, factory, generation, clock = configured(observation_store)
    values = packet_samples(generation, clock, engine)
    repository.ingest_samples(admissions(values))
    clock[0] += 5_000_002_000
    assert repository.mark_stale() == 22
    snapshot = repository.snapshot("simulator")
    assert len(snapshot["items"]) == 22 and all(row["freshness"] == "STALE" for row in snapshot["items"])
    stored = history(factory)
    assert {row["id"] for row in stored["telemetry_samples"]} == {value.sample_identity.sample_id for value in values}
    observed = [row for row in stored["observation_outbox"] if row["event_type"] == "telemetry.sample_observed"]
    assert len(observed) == 22 and all(row["payload"]["data"]["freshness"] == "FRESH" for row in observed)
