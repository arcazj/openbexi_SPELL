"""Bound projection reads by current heads while retaining atomic sample semantics."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select

from backend.observation_domain import DriverTelemetrySample, GetTMMode, GetTMResult, ItemIdentity, ObservationError, ObservationResultCode, Quality, SampleIdentity, ScalarKind, ScalarValue, Validity
from backend.observation_models import TelemetryItemHead, TelemetrySample
from backend.observation_repository import ObservationRepository
from backend.observation_service import ObservationRuntime
from backend.tests.test_dss_collector_lifecycle_v19 import unavailable_time
from backend.tests.test_dss_clock_epoch_v19 import clock_value
from backend.tests.test_dss_observation_profile_v19 import dss_sample
from backend.tests.test_observation_repository import observation_store, sample
from backend.tests.test_driver_client_observation import generations
from dss.catalog import TELEMETRY_ITEMS
from dss.packets import decode_tm
from driver_host.tests.test_dss_transport import engine


def populate(repository, generation, clock, engine, *, dss):
    if not dss:
        values = [("TM.POWER.BUS_VOLTAGE", 28.0), ("TM.POWER.SAFE_MODE", False), ("TM.THERMAL.MODE", "NOMINAL")]
        samples = [sample(generation, item_id=name, sequence=1, engineering=value, observation_number=20100+i)
                   for i, (name,value) in enumerate(values)]
    else:
        body = decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
        clock[0] = body["acquired_at_unix_ns"] + 1000
        samples = []
        for i, item in enumerate(body["items"]):
            metadata = next(row for row in TELEMETRY_ITEMS if row["item_id"] == item["item_id"])
            from backend.observation_domain import sample_id_for
            identity = SampleIdentity(sample_id_for("dss-GENERIC", body["satellite_epoch"], item["item_id"], body["tm_sequence"]),
                item["item_id"], "dss-GENERIC", body["satellite_epoch"], body["tm_sequence"])
            samples.append(DriverTelemetrySample(str(20100+i), generation, identity,
                ItemIdentity(item["item_id"], metadata["qualified_name"], metadata["catalog_digest"]),
                ScalarValue(ScalarKind(item["raw"]["type"]), item["raw"]["value"]),
                ScalarValue(ScalarKind(item["engineering"]["type"]), item["engineering"]["value"]),
                metadata["description"], metadata["unit"], body["acquired_at_unix_ns"], "SIMULATOR",
                "dss-dynamics-clock", 1000, Validity(item["validity"]), Quality(item["quality"]), item["quality_reason"]))
    for value in samples:
        repository.ingest_sample(value, mode=GetTMMode.CURRENT, resynchronized=True)
    return samples


@pytest.mark.parametrize("dss", [False, True])
def test_snapshot_batches_current_heads_with_complete_projection_parity(observation_store, engine, dss):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=dss)
    values = populate(repository, generation, clock, engine, dss=dss)
    # Preserve the previous per-item projection as an independent payload oracle.
    with factory() as session:
        heads = session.scalars(select(TelemetryItemHead).where(
            TelemetryItemHead.context_generation_id == generation.context_generation).order_by(TelemetryItemHead.item_id)).all()
        expected = [repository._sample_projection(session, session.get(TelemetrySample, head.sample_id)) for head in heads]
        material = {column.name:getattr(session.get(TelemetrySample, heads[0].sample_id), column.name)
                    for column in TelemetrySample.__table__.columns}
    # Retained rows are deliberately outside the current-head keys. Increasing
    # their count must neither widen results nor add per-sample reads.
    with factory() as session:
        session.execute(TelemetrySample.__table__.insert(), [
            {**material, "id":f"{i+30000:064x}", "observation_id":f"retained-{i}",
             "source_epoch":"retained-epoch", "source_sequence":i+1}
            for i in range(1000)])
        session.commit()
    statements = []
    database = factory.kw["bind"]
    def record(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)
    event.listen(database, "before_cursor_execute", record)
    try:
        snapshot = repository.snapshot("simulator")
    finally:
        event.remove(database, "before_cursor_execute", record)
    assert snapshot["items"] == expected
    assert len(snapshot["items"]) == (22 if dss else 3)
    assert len(statements) <= 12
    assert snapshot["synchronization_state"] == "COMPLETE"
    assert [row["item_id"] for row in snapshot["items"]] == sorted(row["item_id"] for row in snapshot["items"])
    # Freshness/alarm changes remain visible through the same batched path.
    clock[0] += 10_000_000_000
    repository.mark_stale()
    with factory() as session:
        after = [repository._sample_projection(session, session.get(TelemetrySample, value.sample_identity.sample_id)) for value in values]
    assert repository.snapshot("simulator")["items"] == sorted(after, key=lambda row:row["item_id"])


def test_batched_snapshot_holds_epoch_fence_until_all_items_are_projected(observation_store, monkeypatch):
    _, factory, generation, clock = observation_store
    repository = ObservationRepository(factory, clock_ns=lambda: clock[0], dss_enabled=True)
    old = dss_sample(generation, clock)
    repository.ingest_sample(old, mode=GetTMMode.CURRENT, resynchronized=True)
    repository.ingest_sample(dss_sample(generation, clock, item_id="TM.POWER.SAFE_MODE", number=20501), mode=GetTMMode.CURRENT, resynchronized=True)
    repository.record_time(clock_value(generation, clock[0]), context_generation_id=generation.context_generation)
    started, release, changed = threading.Event(), threading.Event(), threading.Event()
    original = repository._sample_dict
    def blocked(value, head):
        if threading.current_thread().name.startswith("snapshot-reader"):
            started.set()
            assert release.wait(3)
        return original(value, head)
    monkeypatch.setattr(repository, "_sample_dict", blocked)
    def reset():
        repository.ingest_sample(dss_sample(generation, clock, epoch="epoch-"+"b"*64, number=20502), mode=GetTMMode.CURRENT, resynchronized=True)
        changed.set()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="snapshot-reader") as reader, ThreadPoolExecutor(max_workers=1) as writer:
        pending = reader.submit(repository.snapshot, "simulator")
        assert started.wait(3)
        mutation = writer.submit(reset)
        try:
            assert not changed.wait(0.03)
        finally:
            release.set()
        before = pending.result(timeout=3)
        mutation.result(timeout=3)
    assert {row["source_epoch"] for row in before["items"]} == {old.sample_identity.source_epoch}
    assert before["driver_time"]["source_epoch"] == old.sample_identity.source_epoch
    after = repository.snapshot("simulator")
    assert after["driver_time"] is None
    assert after["synchronization_state"] == "GAPPED"
    assert next(row for row in after["items"] if row["item_id"] == "TM.POWER.SAFE_MODE")["freshness"] == "STALE"


def test_collector_reads_cursors_once_and_keeps_per_item_modes_and_first_source():
    calls, queries = [], []
    context = generations(context=True)
    rows = [{"item_id":"first", "source_id":"a", "source_epoch":"epoch-a", "after_source_sequence":7, "synchronization_state":"COMPLETE"},
            {"item_id":"first", "source_id":"z", "source_epoch":"epoch-z", "after_source_sequence":90, "synchronization_state":"COMPLETE"},
            {"item_id":"gap", "source_id":"a", "source_epoch":"epoch-a", "after_source_sequence":8, "synchronization_state":"GAPPED"}]
    def cursors(identity):
        calls.append(identity)
        return rows
    async def get_tm(query):
        queries.append(query)
        return GetTMResult(ObservationResultCode.NOT_AVAILABLE,
            error=ObservationError(ObservationResultCode.NOT_AVAILABLE, "no next sample"))
    runtime = ObservationRuntime(SimpleNamespace(dss_enabled=True, restart_cursors=cursors),
        generation_provider=lambda:{"host":generations(),"contexts":(context,),"credential_epoch":1},
        get_time=unavailable_time, get_tm=get_tm, item_ids=("first","gap","absent"))
    assert asyncio.run(runtime.collect_once()) == 0
    assert calls == [context.context_generation]
    assert [(q.item_id,q.mode,q.source_epoch,q.after_source_sequence) for q in queries] == [
        ("first",GetTMMode.NEXT,"epoch-a",7),("gap",GetTMMode.CURRENT,"",0),("absent",GetTMMode.CURRENT,"",0)]
    assert runtime._collection_metrics["result_codes"] == {"NOT_AVAILABLE":3}
