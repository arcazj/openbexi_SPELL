"""Index-only migration preserves retained events and physical epoch authority."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import event, inspect, select, text
from sqlalchemy.dialects import sqlite

import backend.migrations as migrations
from backend.migrations.versions import v0012_dss_epoch_index as migration
from backend.observation_domain import GetTMMode
from backend.observation_models import ObservationOutboxEvent, ObservationStream
from backend.observation_repository import ObservationConflictError, ObservationRepository
from backend.tests.migration_support import run_migrations
from backend.tests.test_dss_observation_profile_v19 import dss_sample
from backend.tests.test_observation_repository import observation_store

EPOCH_A = "epoch-" + "a" * 64
EPOCH_B = "epoch-" + "b" * 64


@pytest.fixture
def predecessor_store(request, monkeypatch):
    with monkeypatch.context() as scope:
        scope.setattr(migrations, "MIGRATIONS", tuple(row for row in migrations.MIGRATIONS if row.VERSION < "0012"))
        store = request.getfixturevalue("observation_store")
    return store


def retained_history(store, count=6000):
    _, sessions, generation, clock = store
    repository = ObservationRepository(sessions, clock_ns=lambda: clock[0], dss_enabled=True)
    repository.ingest_sample(dss_sample(generation, clock), mode=GetTMMode.CURRENT, resynchronized=True)
    with sessions.begin() as session:
        stream = session.scalar(select(ObservationStream).where(
            ObservationStream.context_generation_id == generation.context_generation))
        stream_id, stream_epoch, first = stream.id, stream.stream_epoch, stream.last_sequence
        rows = [{"id": f"epoch-index-history-{index}", "stream_id":stream_id,"stream_epoch":stream_epoch,
                 "projection_sequence":first+index+1,"event_type":"telemetry.sample_observed",
                 "aggregate_type":"telemetry_sample","aggregate_id":str(index),
                 "payload":{"retained":index,"bytes":"x"*512},"delivery_attempts":0,
                 "created_at":datetime(2026,10,3,tzinfo=timezone.utc)} for index in range(count)]
        session.execute(ObservationOutboxEvent.__table__.insert(), rows)
        stream.last_sequence += count
        before = list(session.execute(select(ObservationOutboxEvent.id, ObservationOutboxEvent.payload)
                                     .order_by(ObservationOutboxEvent.id)))
    return repository, stream_id, stream_epoch, before


def assert_upgrade_and_authority(store, monkeypatch, *, rollback=False):
    _, sessions, generation, clock = store
    engine = sessions.kw["bind"]
    repository, stream_id, stream_epoch, before = retained_history(store)
    assert migrations.database_version(engine) == migration.REQUIRED_PREDECESSOR
    if rollback:
        with monkeypatch.context() as scope:
            scope.setattr(migration,"verify",lambda _conn:(_ for _ in ()).throw(RuntimeError("injected post-DDL failure")))
            with pytest.raises(RuntimeError,match="post-DDL"):
                run_migrations(engine)
        assert migrations.database_version(engine) == migration.REQUIRED_PREDECESSOR
        assert migration.INDEX_NAME not in {row["name"] for row in inspect(engine).get_indexes("observation_outbox")}
    assert run_migrations(engine) == (migration.VERSION,)
    assert run_migrations(engine) == ()
    with sessions() as session:
        migration.verify(session.connection())
        assert list(session.execute(select(ObservationOutboxEvent.id,ObservationOutboxEvent.payload)
                                    .order_by(ObservationOutboxEvent.id))) == before
        assert repository._dss_epoch(session,stream_id) == EPOCH_A
    repository.ingest_sample(dss_sample(generation,clock,epoch=EPOCH_B,number=22002),
                             mode=GetTMMode.CURRENT,resynchronized=True)
    with sessions() as session:
        assert repository._dss_epoch(session,stream_id) == EPOCH_B
    with pytest.raises(ObservationConflictError,match="retired"):
        repository.ingest_sample(dss_sample(generation,clock,sequence=2,number=22003),
                                 mode=GetTMMode.CURRENT,resynchronized=True)
    return repository,stream_id,stream_epoch


@pytest.mark.parametrize("rollback",[False,True])
def test_sqlite_epoch_index_upgrade_preserves_history_and_fences_retired_epoch(predecessor_store,monkeypatch,rollback):
    repository,stream_id,stream_epoch = assert_upgrade_and_authority(predecessor_store,monkeypatch,rollback=rollback)
    statement=repository._dss_epoch_query(stream_id,stream_epoch)
    compiled=statement.compile(dialect=sqlite.dialect(),compile_kwargs={"literal_binds":True})
    with repository.session_factory() as session:
        plan=session.execute(text("EXPLAIN QUERY PLAN "+str(compiled))).all()
    assert any(migration.INDEX_NAME in row[3] for row in plan)
    assert not any("TEMP B-TREE" in row[3] for row in plan)


@pytest.mark.parametrize("drift",["missing","predicate","quoted-whitespace","columns"])
def test_epoch_index_repeat_rejects_missing_or_changed_definition(observation_store,drift):
    engine=observation_store[1].kw["bind"]
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX "+migration.INDEX_NAME)
        if drift!="missing":
            columns="stream_id,stream_epoch" if drift=="columns" else "stream_id,stream_epoch,projection_sequence"
            predicate=migration.PREDICATE if drift=="columns" else "event_type='telemetry.sample_observed'"
            if drift=="quoted-whitespace":
                predicate=migration.PREDICATE.replace("dss-GENERIC","dss- GENERIC")
            connection.exec_driver_sql(f"CREATE INDEX {migration.INDEX_NAME} ON observation_outbox ({columns}) WHERE {predicate}")
    with pytest.raises(RuntimeError,match="DSS epoch index"):
        run_migrations(engine)


def test_actual_epoch_lookup_uses_static_predicates_and_bound_stream_identity(observation_store):
    repository,stream_id,stream_epoch,_ = retained_history(observation_store,20)
    queries=[]
    engine=repository.session_factory.kw["bind"]
    def capture(_connection,_cursor,statement,parameters,_context,_many):
        if "FROM observation_outbox" in statement:
            queries.append((statement,parameters))
    event.listen(engine,"before_cursor_execute",capture)
    try:
        with repository.session_factory() as session:
            assert repository._dss_epoch(session,stream_id)==EPOCH_A
    finally:
        event.remove(engine,"before_cursor_execute",capture)
    assert len(queries)==1
    sql,parameters=queries[0]
    assert "event_type = 'telemetry.source_epoch_changed'" in sql
    assert "aggregate_id = 'dss-GENERIC'" in sql
    assert stream_id not in sql and stream_epoch not in sql
    assert stream_id in parameters and stream_epoch in parameters
