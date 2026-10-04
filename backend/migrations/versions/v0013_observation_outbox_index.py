"""Remove only the replay index duplicated by the durable unique cursor."""
from sqlalchemy import BigInteger, Column, Index, MetaData, String, Table, inspect, text

VERSION = "0013_observation_outbox_index"
REQUIRED_PREDECESSOR = "0012_dss_epoch_index"
INDEX_NAME = "ix_observation_outbox_replay"
UNIQUE_NAME = "uq_observation_outbox_cursor"
COLUMNS = ["stream_id", "stream_epoch", "projection_sequence"]

metadata = MetaData()
outbox = Table("observation_outbox", metadata,
    Column("stream_id", String(128)), Column("stream_epoch", String(128)),
    Column("projection_sequence", BigInteger))
replay_index = Index(INDEX_NAME, *(outbox.c[name] for name in COLUMNS))


def _require_unique_cursor(connection):
    if connection.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("unsupported observation outbox-index database")
    constraints = [row for row in inspect(connection).get_unique_constraints(outbox.name)
                   if row["name"] == UNIQUE_NAME]
    if len(constraints) != 1 or constraints[0]["column_names"] != COLUMNS:
        raise RuntimeError("observation outbox unique cursor differs")
    if connection.dialect.name == "postgresql":
        # A named constraint alone is not enough if its backing index is invalid.
        valid = connection.scalar(text("""
            SELECT i.indisunique AND i.indisvalid AND i.indisready
                   AND i.indpred IS NULL AND i.indexprs IS NULL
            FROM pg_constraint c JOIN pg_index i ON i.indexrelid = c.conindid
            WHERE c.conrelid = 'observation_outbox'::regclass
              AND c.conname = :name AND c.contype = 'u'
        """), {"name": UNIQUE_NAME})
        if valid is not True:
            raise RuntimeError("observation outbox unique cursor index is invalid")


def _duplicate(connection):
    return [row for row in inspect(connection).get_indexes(outbox.name)
            if row["name"] == INDEX_NAME]


def _require_duplicate(connection):
    rows = _duplicate(connection)
    if len(rows) != 1:
        raise RuntimeError("observation outbox replay index is missing")
    row = rows[0]
    options = row.get("dialect_options", {})
    if (row["column_names"] != COLUMNS or row.get("unique") not in {False, 0}
            or row.get("column_sorting") or row.get("include_columns")
            or options.get(connection.dialect.name + "_where") is not None
            or options.get("postgresql_include")
            or options.get("postgresql_using", "btree") != "btree"):
        raise RuntimeError("observation outbox replay index definition differs")


def upgrade(connection):
    if not connection.scalar(text("SELECT 1 FROM schema_migrations WHERE version=:v"),
                             {"v": REQUIRED_PREDECESSOR}):
        raise RuntimeError("observation outbox-index predecessor is missing")
    _require_unique_cursor(connection)
    _require_duplicate(connection)
    replay_index.drop(connection, checkfirst=False)
    verify(connection)


def verify(connection):
    _require_unique_cursor(connection)
    if _duplicate(connection):
        raise RuntimeError("redundant observation outbox replay index remains")


def downgrade(connection):
    """Restore the previous index and history marker in the caller's transaction.

    No rows or other indexes change. Refuse later/unknown migrations; callers
    must stop application traffic and keep this transaction atomic.
    """
    from backend.migrations import MIGRATIONS, _migration_lock, schema_migrations

    _migration_lock(connection)
    applied = set(connection.execute(schema_migrations.select()).scalars())
    required = {item.VERSION for item in MIGRATIONS if item.VERSION <= VERSION}
    if VERSION not in applied or applied != required:
        raise RuntimeError("observation outbox-index downgrade requires its exact migration head")
    verify(connection)
    replay_index.create(connection, checkfirst=False)
    _require_duplicate(connection)
    connection.execute(schema_migrations.delete().where(schema_migrations.c.version == VERSION))
