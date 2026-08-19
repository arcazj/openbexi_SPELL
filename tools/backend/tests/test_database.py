from __future__ import annotations

from sqlalchemy import text

from backend.database import create_database


def test_sqlite_runtime_connection_policy_is_bounded_and_concurrent(tmp_path) -> None:
    engine, _ = create_database(f"sqlite:///{(tmp_path / 'runtime.db').as_posix()}")
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("PRAGMA busy_timeout")) == 30_000
            assert connection.scalar(text("PRAGMA foreign_keys")) == 1
            assert connection.scalar(text("PRAGMA journal_mode")) == "wal"
            assert connection.scalar(text("PRAGMA synchronous")) == 1
    finally:
        engine.dispose()
