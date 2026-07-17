from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.engine import Connection


VERSION = "0002_execution_variables"


def upgrade(connection: Connection) -> None:
    columns = {column["name"] for column in inspect(connection).get_columns("executions")}
    dialect = connection.dialect.name
    if "ir_version" not in columns:
        connection.exec_driver_sql(
            "ALTER TABLE executions ADD COLUMN ir_version VARCHAR(20) "
            "NOT NULL DEFAULT '0.2'"
        )
    if "variables" not in columns:
        json_default = "'{}'::json" if dialect == "postgresql" else "'{}'"
        connection.exec_driver_sql(
            "ALTER TABLE executions ADD COLUMN variables JSON "
            f"NOT NULL DEFAULT {json_default}"
        )
