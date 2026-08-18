from __future__ import annotations

import tempfile
from pathlib import Path

from sqlalchemy.engine import Engine

from backend.migrations import run_migrations as run_product_migrations


def trusted_test_backup_directory(engine: Engine) -> Path:
    database = engine.url.database
    if engine.dialect.name == "sqlite" and database not in {None, "", ":memory:"}:
        root = Path(database).resolve(strict=False).parent
    else:
        root = Path(tempfile.gettempdir()).resolve() / "openbexi-spell-test-backups"
    target = root / "v0007-preflight"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    return target


def run_migrations(engine: Engine) -> tuple[str, ...]:
    return run_product_migrations(
        engine,
        v0007_backup_directory=trusted_test_backup_directory(engine),
    )


__all__ = ["run_migrations", "trusted_test_backup_directory"]
