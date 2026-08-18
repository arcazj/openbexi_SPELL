from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 30_000
MAXIMUM_SQLITE_BUSY_TIMEOUT_MS = 30_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


def create_database(
    database_url: str,
    *,
    sqlite_busy_timeout_ms: int = DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
):
    is_sqlite = database_url.startswith("sqlite")
    is_file_sqlite = (
        database_url.startswith("sqlite:///")
        and database_url != "sqlite:///:memory:"
    )
    if is_file_sqlite:
        Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    if (
        type(sqlite_busy_timeout_ms) is not int
        or not 1 <= sqlite_busy_timeout_ms <= MAXIMUM_SQLITE_BUSY_TIMEOUT_MS
    ):
        raise ValueError("sqlite_busy_timeout_ms must be between 1 and 30000")
    connect_args = (
        {
            "check_same_thread": False,
            "timeout": sqlite_busy_timeout_ms / 1000.0,
        }
        if is_sqlite
        else {}
    )
    engine = create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)
    if is_sqlite:

        @event.listens_for(engine, "connect")
        def configure_sqlite(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute(f"PRAGMA busy_timeout={sqlite_busy_timeout_ms}")
                cursor.execute("PRAGMA foreign_keys=ON")
                if is_file_sqlite:
                    cursor.execute("PRAGMA synchronous=NORMAL")
            finally:
                cursor.close()

        # Journal mode is database-wide and persistent. Set it once during engine
        # bootstrap instead of requesting an exclusive mode transition whenever
        # the pool opens another DBAPI connection.
        if is_file_sqlite:
            with engine.connect() as connection:
                connection.exec_driver_sql("PRAGMA journal_mode=WAL")

    factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
    return engine, factory


def begin_mutation_write(session: Session) -> None:
    """Start the backend's bounded write transaction before any durable read."""

    connection = session.connection()
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    elif connection.dialect.name == "postgresql":
        connection.exec_driver_sql("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        connection.exec_driver_sql("SET LOCAL lock_timeout = '5000ms'")
        connection.exec_driver_sql("SET LOCAL statement_timeout = '30000ms'")


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
