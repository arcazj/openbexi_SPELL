"""Bounded current-epoch lookup without scanning retained observation history."""
import re

from sqlalchemy import BigInteger, Column, Index, MetaData, String, Table, inspect, text

VERSION = "0012_dss_epoch_index"
REQUIRED_PREDECESSOR = "0011_dss_language_ledger"
INDEX_NAME = "ix_observation_dss_epoch"
PREDICATE = "event_type = 'telemetry.source_epoch_changed' AND aggregate_id = 'dss-GENERIC'"
metadata = MetaData()
outbox = Table("observation_outbox", metadata,
    Column("stream_id", String(128)), Column("stream_epoch", String(128)),
    Column("projection_sequence", BigInteger))
epoch_index = Index(INDEX_NAME, outbox.c.stream_id, outbox.c.stream_epoch, outbox.c.projection_sequence,
    sqlite_where=text(PREDICATE), postgresql_where=text(PREDICATE))


def _predicate(value):
    # PostgreSQL reflection adds grouping parentheses and text casts. The
    # comparison still binds both exact case-sensitive static string constants.
    parts = re.split(r"('(?:[^']|'')*')", str(value))
    return "".join(part if index % 2 else re.sub(r"\s+|[()]|::text", "", part)
                   for index, part in enumerate(parts))


def upgrade(connection):
    if connection.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("unsupported DSS epoch-index database")
    if not connection.scalar(text("SELECT 1 FROM schema_migrations WHERE version=:v"), {"v": REQUIRED_PREDECESSOR}):
        raise RuntimeError("DSS epoch-index predecessor is missing")
    if any(row["name"] == INDEX_NAME for row in inspect(connection).get_indexes(outbox.name)):
        raise RuntimeError("DSS epoch index already exists before its migration")
    epoch_index.create(connection, checkfirst=False)
    verify(connection)


def verify(connection):
    rows = [row for row in inspect(connection).get_indexes(outbox.name) if row["name"] == INDEX_NAME]
    if len(rows) != 1:
        raise RuntimeError("DSS epoch index is missing")
    row = rows[0]
    actual = row.get("dialect_options", {}).get(connection.dialect.name + "_where")
    if (row["column_names"] != ["stream_id", "stream_epoch", "projection_sequence"]
            or row.get("unique") not in {False, 0} or actual is None
            or _predicate(actual) != _predicate(PREDICATE)):
        raise RuntimeError("DSS epoch index definition differs")
