"""Durable v0.7 condition, WaitFor, and telemetry-schedule schema.

Deadline rows carry both their immutable database-time deadline and the
monotonic clock correlation used to survive wall-clock adjustment and process
restart without extending the accepted timeout.
"""

from __future__ import annotations

from sqlalchemy import MetaData, inspect
from sqlalchemy.engine import Connection

from backend.condition_models import (
    ConditionEvaluationRecord,
    ConditionEvaluationSample,
    ConditionPlanRecord,
    TelemetryConditionSchedule,
    TelemetryScheduleOccurrence,
    VerifyOperation,
    WaitForOperation,
)
from backend.models import Execution


VERSION = "0006_observation_conditions"
REQUIRED_PREDECESSOR_TABLES = frozenset({"observation_streams", "telemetry_samples"})

metadata = MetaData()
Execution.__table__.to_metadata(metadata)
for source in (
    ConditionPlanRecord.__table__,
    ConditionEvaluationRecord.__table__,
    ConditionEvaluationSample.__table__,
    VerifyOperation.__table__,
    WaitForOperation.__table__,
    TelemetryConditionSchedule.__table__,
    TelemetryScheduleOccurrence.__table__,
):
    source.to_metadata(metadata)

NEW_TABLES = tuple(
    table for table in metadata.sorted_tables if table.name != Execution.__tablename__
)


def upgrade(connection: Connection) -> None:
    """Add condition tables only after the accepted observation projection."""

    present = set(inspect(connection).get_table_names())
    missing = REQUIRED_PREDECESSOR_TABLES - present
    if missing:
        raise RuntimeError(
            "v0.7 condition migration requires observation projection tables: "
            + ", ".join(sorted(missing))
        )
    for table in NEW_TABLES:
        table.create(connection, checkfirst=True)


__all__ = [
    "NEW_TABLES",
    "REQUIRED_PREDECESSOR_TABLES",
    "VERSION",
    "metadata",
    "upgrade",
]
