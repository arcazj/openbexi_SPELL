"""Retained replay survives removal of its exact duplicate cursor index.

The same identities run on a temporary SQLite database or, when configured,
the dedicated PostgreSQL migration database. Never use the application DB.
"""
import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import event, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.elements import TextClause

import backend.migrations as migrations
from backend.database import create_database
from backend.migrations.versions import v0013_observation_outbox_index as migration
from backend.observation_models import ObservationOutboxEvent
from backend.tests import test_observation_repository as fixtures
from backend.tests.migration_support import reset_test_database, run_migrations
from backend.tests.test_observation_epoch_index_v19 import retained_history
from backend.tests.test_observation_repository import observation_store


@pytest.fixture
def predecessor_store(request, monkeypatch):
    url = os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL")
    if url:
        parsed = make_url(url)
        assert parsed.get_backend_name() == "postgresql"
        assert parsed.database == "spell_migration_test"
        engine, _ = create_database(url)
        reset_test_database(engine)
        engine.dispose()
        monkeypatch.setattr(fixtures, "create_database", lambda _: create_database(url))
    with monkeypatch.context() as scope:
        scope.setattr(migrations, "MIGRATIONS", tuple(
            row for row in migrations.MIGRATIONS if row.VERSION <= migration.REQUIRED_PREDECESSOR
        ))
        store = request.getfixturevalue("observation_store")
    try:
        yield store
    finally:
        if url:
            reset_test_database(store[1].kw["bind"])


def _history(engine):
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(
            select(ObservationOutboxEvent.__table__).order_by(ObservationOutboxEvent.id)
        ).mappings()]


def _indexes(engine):
    rows = inspect(engine).get_indexes("observation_outbox")
    for row in rows:
        # Reflection creates a new TextClause for a SQLite partial predicate
        # each time. Compare its exact SQL rather than Python object identity;
        # retain all other index fields and every predicate character.
        if "dialect_options" in row:
            row["dialect_options"] = {
                key: str(value) if isinstance(value, TextClause) else value
                for key, value in row["dialect_options"].items()
            }
    return {row["name"]: row for row in rows}


def _seed(store):
    repository, stream_id, epoch, _ = retained_history(store, count=512)
    engine = store[1].kw["bind"]
    # Preserve publication timestamps and attempts as well as payload/cursors.
    with engine.begin() as connection:
        connection.execute(ObservationOutboxEvent.__table__.update().where(
            ObservationOutboxEvent.id == "epoch-index-history-3"
        ).values(delivery_attempts=2, published_at=datetime(2026, 10, 4, tzinfo=timezone.utc)))
    before = _history(engine)
    replay = repository.replay("simulator", stream_epoch=epoch, after_sequence=0, limit=1000)
    return engine, repository, stream_id, epoch, before, replay


def _assert_unique_replay_plan(engine, repository, epoch):
    queries = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if ("FROM observation_outbox" in statement
                and "ORDER BY observation_outbox.projection_sequence" in statement):
            queries.append((statement, parameters))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        window = repository.replay("simulator", stream_epoch=epoch,
                                   after_sequence=500, limit=8)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert len(queries) == 1 and len(window["items"]) == 8
    sql, parameters = queries[0]
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.exec_driver_sql("ANALYZE observation_outbox")
            plan = connection.exec_driver_sql("EXPLAIN (FORMAT JSON) " + sql, parameters).scalar_one()[0]

            def nodes(row):
                yield row
                for child in row.get("Plans", []):
                    yield from nodes(child)

            assert any(row.get("Index Name") == migration.UNIQUE_NAME
                       for row in nodes(plan["Plan"]))
        else:
            backing = []
            for row in connection.exec_driver_sql("PRAGMA index_list('observation_outbox')"):
                if row[2] == 1 and row[3] == "u":
                    name = row[1]
                    columns = [item[2] for item in connection.exec_driver_sql(
                        "PRAGMA index_info('" + name.replace("'", "''") + "')")]
                    if columns == migration.COLUMNS:
                        backing.append(name)
            assert len(backing) == 1
            plan = connection.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, parameters).all()
            assert any(backing[0] in row[3] for row in plan)
            assert not any("TEMP B-TREE" in row[3] for row in plan)


def test_upgrade_downgrade_preserves_history_unique_cursor_and_actual_replay(predecessor_store):
    engine, repository, stream_id, epoch, before, replay = _seed(predecessor_store)
    old_indexes = _indexes(engine)
    assert migration.INDEX_NAME in old_indexes
    assert migrations.database_version(engine) == migration.REQUIRED_PREDECESSOR
    assert run_migrations(engine) == (migration.VERSION,)
    assert run_migrations(engine) == ()
    assert migrations.database_version(engine) == migration.VERSION
    assert _indexes(engine) == {name: row for name, row in old_indexes.items()
                                if name != migration.INDEX_NAME}
    assert _history(engine) == before
    assert repository.replay("simulator", stream_epoch=epoch,
                             after_sequence=0, limit=1000) == replay
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            duplicate = dict(before[0], id="duplicate-cursor-must-fail")
            connection.execute(ObservationOutboxEvent.__table__.insert(), duplicate)
    assert _history(engine) == before
    _assert_unique_replay_plan(engine, repository, epoch)

    with engine.begin() as connection:
        migration.downgrade(connection)
    assert migrations.database_version(engine) == migration.REQUIRED_PREDECESSOR
    assert _indexes(engine) == old_indexes
    assert _history(engine) == before
    assert repository.replay("simulator", stream_epoch=epoch,
                             after_sequence=0, limit=1000) == replay
    assert run_migrations(engine) == (migration.VERSION,)
    assert run_migrations(engine) == ()
    assert _history(engine) == before


def test_failed_upgrade_rolls_back_actual_index_drop_and_migration_marker(predecessor_store, monkeypatch):
    engine, _, _, _, before, _ = _seed(predecessor_store)
    old_indexes = _indexes(engine)

    def fail_after_drop(connection):
        assert migration.INDEX_NAME not in {row["name"] for row in inspect(connection).get_indexes("observation_outbox")}
        raise RuntimeError("injected post-drop failure")

    with monkeypatch.context() as scope:
        scope.setattr(migration, "verify", fail_after_drop)
        with pytest.raises(RuntimeError, match="post-drop failure"):
            run_migrations(engine)
    assert migrations.database_version(engine) == migration.REQUIRED_PREDECESSOR
    assert _indexes(engine) == old_indexes
    assert _history(engine) == before
    assert run_migrations(engine) == (migration.VERSION,)


@pytest.mark.parametrize("drift", ["missing", "columns", "predicate"])
def test_upgrade_rejects_unexpected_duplicate_index_definition(predecessor_store, drift):
    engine, _, _, _, before, _ = _seed(predecessor_store)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX " + migration.INDEX_NAME)
        if drift != "missing":
            columns = "stream_id,stream_epoch" if drift == "columns" else ",".join(migration.COLUMNS)
            predicate = " WHERE published_at IS NULL" if drift == "predicate" else ""
            connection.exec_driver_sql("CREATE INDEX " + migration.INDEX_NAME
                                       + " ON observation_outbox (" + columns + ")" + predicate)
    with pytest.raises(RuntimeError, match="replay index"):
        run_migrations(engine)
    assert migrations.database_version(engine) == migration.REQUIRED_PREDECESSOR
    assert _history(engine) == before


def test_repeat_migration_rejects_reintroduced_redundant_index(predecessor_store):
    engine, _, _, _, before, _ = _seed(predecessor_store)
    run_migrations(engine)
    with engine.begin() as connection:
        migration.replay_index.create(connection, checkfirst=False)
    with pytest.raises(RuntimeError, match="redundant observation outbox"):
        run_migrations(engine)
    assert _history(engine) == before


def test_downgrade_refuses_later_migration_without_changing_history(predecessor_store):
    engine, _, _, _, before, _ = _seed(predecessor_store)
    run_migrations(engine)
    with engine.begin() as connection:
        connection.execute(migrations.schema_migrations.insert().values(
            version="9999_future", applied_at=datetime(2026, 10, 4, tzinfo=timezone.utc)))
    with pytest.raises(RuntimeError, match="exact migration head"):
        with engine.begin() as connection:
            migration.downgrade(connection)
    assert migration.INDEX_NAME not in _indexes(engine)
    assert _history(engine) == before
