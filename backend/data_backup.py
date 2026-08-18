"""Bounded, digest-bound backup and isolated restore for v0.8 local data."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Protocol
from uuid import uuid4

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.engine import Connection, Engine, make_url

from .data_models import (
    virtual_files,
    verify_data_integrity,
    verify_persisted_schema_fingerprint,
)
from .data_values import TypedValueError, strict_json_loads
from .migrations import MIGRATIONS, database_version, run_migrations
from .virtual_file_service import (
    MAXIMUM_FILE_BYTES as MAXIMUM_VIRTUAL_FILE_BYTES,
    MAXIMUM_ROOT_BYTES as MAXIMUM_VIRTUAL_ROOT_BYTES,
    MAXIMUM_ROOT_NODES as MAXIMUM_VIRTUAL_REFERENCES_PER_ROOT,
    VirtualFileError,
    validate_virtual_path,
)


BACKUP_SCHEMA_VERSION = "spell.data.backup/1"
DATABASE_MEMBER = "database.sqlite"
POSTGRES_CATALOG_MEMBER = "postgresql/catalog.json"
POSTGRES_CATALOG_SCHEMA_VERSION = "spell.data.postgresql-copy/1"
MANIFEST_MEMBER = "manifest.json"
MAXIMUM_BACKUP_METADATA_BYTES = 67_108_864
BACKUP_STREAM_CHUNK_BYTES = 1_048_576
_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9._-]+\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POSTGRES_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")


class DataBackupError(RuntimeError):
    pass


class BackupCorruptionError(DataBackupError):
    pass


class UnsafeRestoreError(DataBackupError):
    pass


class VirtualFileBackupProvider(Protocol):
    """Trusted root-scoped access to the committed content-addressed store."""

    def inventory(self) -> Iterable[tuple[str, str]]: ...

    def read(
        self, storage_root_id: str, virtual_path: str, content_digest: str
    ) -> bytes: ...


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _resolved_existing_directory(
    value: Path | str,
    *,
    label: str,
    error_type: type[DataBackupError],
) -> Path:
    lexical = Path(value).absolute()
    try:
        metadata = lexical.lstat()
    except OSError as exc:
        raise error_type(f"{label} is not a non-symlink directory") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise error_type(f"{label} is not a non-symlink directory")
    return lexical.resolve(strict=True)


def _resolved_new_directory(
    value: Path | str,
    *,
    exists_message: str,
    error_type: type[DataBackupError],
) -> Path:
    lexical = Path(value).absolute()
    try:
        lexical.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise error_type(exists_message) from exc
    else:
        raise error_type(exists_message)
    return lexical.resolve(strict=False)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _regular_file_metadata(
    path: Path, label: str, *, maximum_bytes: int | None = None
) -> tuple[int, str]:
    metadata = path.lstat()
    if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise BackupCorruptionError(f"{label} is not a non-symlink regular file")
    if maximum_bytes is not None and metadata.st_size > maximum_bytes:
        raise BackupCorruptionError(f"{label} exceeds its byte limit")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
            or (
                metadata.st_ino
                and opened.st_ino
                and (opened.st_dev, opened.st_ino)
                != (metadata.st_dev, metadata.st_ino)
            )
        ):
            raise BackupCorruptionError(f"{label} changed before it was read")
        while True:
            chunk = stream.read(BACKUP_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if maximum_bytes is not None and total > maximum_bytes:
                raise BackupCorruptionError(f"{label} exceeds its byte limit")
            digest.update(chunk)
        completed = os.fstat(stream.fileno())
    if (
        total != opened.st_size
        or completed.st_size != opened.st_size
        or completed.st_mtime_ns != opened.st_mtime_ns
    ):
        raise BackupCorruptionError(f"{label} changed while it was read")
    return total, digest.hexdigest()


def _regular_bytes(path: Path, maximum_bytes: int, label: str) -> bytes:
    size, expected_digest = _regular_file_metadata(
        path, label, maximum_bytes=maximum_bytes
    )
    payload = path.read_bytes()
    if len(payload) != size or _sha256(payload) != expected_digest:
        raise BackupCorruptionError(f"{label} changed while it was read")
    return payload


def _validate_database_virtual_path(value: Any) -> str:
    try:
        return validate_virtual_path(value)
    except VirtualFileError as exc:
        raise BackupCorruptionError("virtual-file database path is invalid") from exc


def _database_time(connection: Connection) -> str:
    value = connection.exec_driver_sql("SELECT CURRENT_TIMESTAMP").scalar_one()
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DataBackupError("database returned an invalid UTC timestamp") from exc
    else:
        raise DataBackupError("database returned an unsupported timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _aggregate_digest(
    inventory: list[dict[str, Any]], file_sha256: Mapping[str, str]
) -> str:
    payload = bytearray()
    for item in inventory:
        path = item["path"]
        payload.extend(path.encode("ascii"))
        payload.extend(b"\0")
        payload.extend(str(item["size"]).encode("ascii"))
        payload.extend(b"\0")
        payload.extend(file_sha256[path].encode("ascii"))
        payload.extend(b"\n")
    return _sha256(bytes(payload))


def canonical_backup_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    expected_fields = {
        "schema_version",
        "migration_head",
        "database_backend",
        "created_at_database_time",
        "file_inventory",
        "file_sha256",
        "aggregate_sha256",
    }
    if type(manifest) is not dict or set(manifest) != expected_fields:
        raise BackupCorruptionError("backup manifest fields differ")
    try:
        raw = json.dumps(
            manifest,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BackupCorruptionError("backup manifest is not canonical JSON") from exc
    if len(raw) > MAXIMUM_BACKUP_METADATA_BYTES:
        raise BackupCorruptionError("backup manifest exceeds its byte limit")
    return raw


def _canonical_postgresql_catalog_bytes(catalog: Mapping[str, Any]) -> bytes:
    if type(catalog) is not dict or set(catalog) != {
        "schema_version",
        "tables",
        "virtual_references",
    }:
        raise BackupCorruptionError("PostgreSQL backup catalog fields differ")
    try:
        raw = json.dumps(
            catalog,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BackupCorruptionError(
            "PostgreSQL backup catalog is not canonical JSON"
        ) from exc
    if len(raw) > MAXIMUM_BACKUP_METADATA_BYTES:
        raise BackupCorruptionError("PostgreSQL backup catalog exceeds its byte limit")
    return raw


def _connection_migration_head(connection: Connection) -> str | None:
    if "schema_migrations" not in inspect(connection).get_table_names():
        return None
    versions = set(
        connection.exec_driver_sql("SELECT version FROM schema_migrations").scalars()
    )
    known = tuple(migration.VERSION for migration in MIGRATIONS)
    if versions.difference(known):
        raise BackupCorruptionError("database migration ledger contains unknown rows")
    indexes = [index for index, version in enumerate(known) if version in versions]
    expected = set(known[: max(indexes, default=-1) + 1])
    if versions != expected:
        raise BackupCorruptionError("database migration ledger is not an exact prefix")
    return next((version for version in reversed(known) if version in versions), None)


def _postgresql_table_specs(connection: Connection) -> list[dict[str, Any]]:
    inspector = inspect(connection)
    names = sorted(inspector.get_table_names(schema="public"))
    if not names or any(_POSTGRES_IDENTIFIER.fullmatch(name) is None for name in names):
        raise BackupCorruptionError("PostgreSQL table inventory is invalid")
    specs: list[dict[str, Any]] = []
    for name in names:
        columns = []
        for column in inspector.get_columns(name, schema="public"):
            column_name = column.get("name")
            if (
                type(column_name) is not str
                or _POSTGRES_IDENTIFIER.fullmatch(column_name) is None
            ):
                raise BackupCorruptionError("PostgreSQL column identity is invalid")
            columns.append(
                {
                    "default": (
                        None
                        if column.get("default") is None
                        else str(column.get("default"))
                    ),
                    "name": column_name,
                    "nullable": bool(column.get("nullable")),
                    "type": str(column.get("type")),
                }
            )
        primary = inspector.get_pk_constraint(name, schema="public")
        primary_columns = primary.get("constrained_columns") or []
        if (
            not columns
            or not primary_columns
            or any(type(item) is not str for item in primary_columns)
        ):
            raise BackupCorruptionError(
                "PostgreSQL backup tables require explicit primary keys"
            )
        foreign_keys = []
        for item in inspector.get_foreign_keys(name, schema="public"):
            options = item.get("options") or {}
            foreign_keys.append(
                {
                    "columns": list(item.get("constrained_columns") or []),
                    "name": item.get("name"),
                    "ondelete": options.get("ondelete"),
                    "onupdate": options.get("onupdate"),
                    "referred_columns": list(item.get("referred_columns") or []),
                    "referred_schema": item.get("referred_schema") or "public",
                    "referred_table": item.get("referred_table"),
                }
            )
        unique_constraints = [
            {
                "columns": list(item.get("column_names") or []),
                "name": item.get("name"),
            }
            for item in inspector.get_unique_constraints(name, schema="public")
        ]
        checks = [
            {"name": item.get("name"), "sql": str(item.get("sqltext"))}
            for item in inspector.get_check_constraints(name, schema="public")
        ]
        indexes = [
            {
                "columns": list(item.get("column_names") or []),
                "name": item.get("name"),
                "unique": bool(item.get("unique")),
            }
            for item in inspector.get_indexes(name, schema="public")
            if not item.get("duplicates_constraint")
        ]
        specs.append(
            {
                "checks": sorted(checks, key=lambda item: (str(item["name"]), item["sql"])),
                "columns": columns,
                "foreign_keys": sorted(
                    foreign_keys,
                    key=lambda item: (
                        str(item["name"]),
                        tuple(item["columns"]),
                    ),
                ),
                "indexes": sorted(indexes, key=lambda item: str(item["name"])),
                "name": name,
                "primary_key": {
                    "columns": list(primary_columns),
                    "name": primary.get("name"),
                },
                "unique_constraints": sorted(
                    unique_constraints, key=lambda item: str(item["name"])
                ),
            }
        )
    return specs


def _quote_postgresql(connection: Connection, value: str) -> str:
    if _POSTGRES_IDENTIFIER.fullmatch(value) is None:
        raise BackupCorruptionError("PostgreSQL identifier is invalid")
    return connection.dialect.identifier_preparer.quote_identifier(value)


def _postgresql_copy_statement(
    connection: Connection, table: Mapping[str, Any], *, outgoing: bool
) -> str:
    table_name = _quote_postgresql(connection, table["name"])
    columns = [item["name"] for item in table["columns"]]
    quoted_columns = ",".join(_quote_postgresql(connection, item) for item in columns)
    if outgoing:
        primary = table["primary_key"]["columns"]
        order = ",".join(_quote_postgresql(connection, item) for item in primary)
        return (
            f"COPY (SELECT {quoted_columns} FROM {table_name} ORDER BY {order}) "
            "TO STDOUT WITH (FORMAT BINARY)"
        )
    return f"COPY {table_name} ({quoted_columns}) FROM STDIN WITH (FORMAT BINARY)"


def _postgresql_copy_out(
    connection: Connection,
    table: Mapping[str, Any],
    destination: Path | None = None,
) -> tuple[int, str]:
    driver = connection.connection.driver_connection
    digest = hashlib.sha256()
    total = 0
    target = None
    try:
        if destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            target = destination.open("xb")
        with driver.cursor() as cursor:
            with cursor.copy(
                _postgresql_copy_statement(connection, table, outgoing=True)
            ) as copy:
                while True:
                    chunk = copy.read()
                    if not chunk:
                        break
                    total += len(chunk)
                    digest.update(chunk)
                    if target is not None:
                        target.write(chunk)
        if target is not None:
            target.flush()
            os.fsync(target.fileno())
        return total, digest.hexdigest()
    finally:
        if target is not None:
            target.close()


def _postgresql_copy_in(
    connection: Connection,
    table: Mapping[str, Any],
    source: Path,
    *,
    expected_size: int,
    expected_digest: str,
) -> None:
    metadata = source.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BackupCorruptionError(
            "PostgreSQL table dump is not a non-symlink regular file"
        )
    driver = connection.connection.driver_connection
    digest = hashlib.sha256()
    total = 0
    with source.open("rb") as incoming:
        opened = os.fstat(incoming.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
            or (
                metadata.st_ino
                and opened.st_ino
                and (opened.st_dev, opened.st_ino)
                != (metadata.st_dev, metadata.st_ino)
            )
        ):
            raise BackupCorruptionError(
                "PostgreSQL table dump changed before it was read"
            )
        with driver.cursor() as cursor:
            with cursor.copy(
                _postgresql_copy_statement(connection, table, outgoing=False)
            ) as copy:
                while True:
                    chunk = incoming.read(BACKUP_STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    digest.update(chunk)
                    copy.write(chunk)
        completed = os.fstat(incoming.fileno())
    if (
        total != opened.st_size
        or completed.st_size != opened.st_size
        or completed.st_mtime_ns != opened.st_mtime_ns
        or total != expected_size
        or digest.hexdigest() != expected_digest
    ):
        raise BackupCorruptionError("PostgreSQL table dump changed while it was read")


def _postgresql_table_member(table_name: str) -> str:
    if _POSTGRES_IDENTIFIER.fullmatch(table_name) is None:
        raise BackupCorruptionError("PostgreSQL table identity is invalid")
    return f"postgresql/tables/{table_name}.copy"


def _virtual_reference_catalog(
    references: Mapping[tuple[str, str], tuple[str, int]],
) -> list[dict[str, Any]]:
    return [
        {
            "byte_length": byte_length,
            "content_digest": digest,
            "storage_root_id": root_id,
            "virtual_path": virtual_path,
        }
        for (root_id, digest), (virtual_path, byte_length) in sorted(
            references.items()
        )
    ]


def _fsync_file(path: Path) -> None:
    with path.open("r+b") as stream:
        os.fsync(stream.fileno())


def _write_member(
    destination: Path,
    payload: bytes,
    *,
    maximum_bytes: int = MAXIMUM_VIRTUAL_FILE_BYTES,
    label: str = "virtual-file content",
) -> int:
    if type(payload) is not bytes:
        raise DataBackupError(f"{label} is not bytes")
    if len(payload) > maximum_bytes:
        raise DataBackupError(f"{label} exceeds its byte limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as outgoing:
        outgoing.write(payload)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    return len(payload)


def _snapshot_sqlite(engine: Engine, destination: Path) -> None:
    raw_connection = engine.raw_connection()
    target = sqlite3.connect(destination)
    try:
        driver_connection = getattr(raw_connection, "driver_connection", None)
        if driver_connection is None:
            driver_connection = raw_connection.connection
        driver_connection.backup(target)
        if target.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise BackupCorruptionError("SQLite snapshot integrity check failed")
        target.commit()
    finally:
        target.close()
        raw_connection.close()
    _fsync_file(destination)


def _virtual_member(storage_root_id: str, content_digest: str) -> str:
    try:
        root_bytes = storage_root_id.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        root_bytes = b""
    if (
        type(storage_root_id) is not str
        or storage_root_id in {".", ".."}
        or not 1 <= len(root_bytes) <= 128
        or _SAFE_SEGMENT.fullmatch(storage_root_id) is None
        or type(content_digest) is not str
        or _DIGEST.fullmatch(content_digest) is None
    ):
        raise BackupCorruptionError("virtual-file database identity is invalid")
    return f"virtual-files/{storage_root_id}/{content_digest}"


def _virtual_member_identity(member: str) -> tuple[str, str]:
    if type(member) is not str or not member.startswith("virtual-files/"):
        raise BackupCorruptionError("virtual-file backup member is invalid")
    parts = member.split("/")
    if len(parts) != 3 or _virtual_member(parts[1], parts[2]) != member:
        raise BackupCorruptionError("virtual-file backup member is invalid")
    return parts[1], parts[2]


def _enforce_virtual_root_bounds(
    root_id: str,
    counts: dict[str, int],
    byte_totals: dict[str, int],
    byte_length: int,
    *,
    label: str,
) -> None:
    count = counts.get(root_id, 0) + 1
    total = byte_totals.get(root_id, 0) + byte_length
    if count > MAXIMUM_VIRTUAL_REFERENCES_PER_ROOT:
        raise BackupCorruptionError(f"{label} count exceeds its per-root limit")
    if total > MAXIMUM_VIRTUAL_ROOT_BYTES:
        raise BackupCorruptionError(f"{label} bytes exceed their per-root limit")
    counts[root_id] = count
    byte_totals[root_id] = total


def _virtual_references(
    connection: Connection,
) -> dict[tuple[str, str], tuple[str, int]]:
    rows = connection.execution_options(stream_results=True).execute(
        select(
            virtual_files.c.root_id,
            virtual_files.c.virtual_path,
            virtual_files.c.content_digest,
            virtual_files.c.byte_length,
        )
        .where(
            virtual_files.c.node_type == "FILE",
            virtual_files.c.tombstoned.is_(False),
        )
        .order_by(
            virtual_files.c.root_id,
            virtual_files.c.content_digest,
            virtual_files.c.virtual_path,
            virtual_files.c.revision,
        )
    )
    references: dict[tuple[str, str], tuple[str, int]] = {}
    counts: dict[str, int] = {}
    byte_totals: dict[str, int] = {}
    for root_id, virtual_path, content_digest, byte_length in rows:
        _virtual_member(root_id, content_digest)
        _validate_database_virtual_path(virtual_path)
        if type(byte_length) is not int or not 0 <= byte_length <= MAXIMUM_VIRTUAL_FILE_BYTES:
            raise BackupCorruptionError("virtual-file database length is invalid")
        identity = (root_id, content_digest)
        previous = references.get(identity)
        if previous is not None and previous[1] != byte_length:
            raise BackupCorruptionError(
                "one virtual content digest has conflicting database lengths"
            )
        if previous is None:
            references[identity] = (virtual_path, byte_length)
            _enforce_virtual_root_bounds(
                root_id,
                counts,
                byte_totals,
                byte_length,
                label="virtual-file reference",
            )
    return references


def _provider_inventory(
    provider: VirtualFileBackupProvider | None,
) -> frozenset[tuple[str, str]]:
    if provider is None:
        return frozenset()
    try:
        raw_inventory = provider.inventory()
    except Exception as exc:
        raise DataBackupError("virtual-file provider inventory failed") from exc
    identities: set[tuple[str, str]] = set()
    counts: dict[str, int] = {}
    byte_totals: dict[str, int] = {}
    try:
        for item in raw_inventory:
            if type(item) is not tuple or len(item) != 2:
                raise DataBackupError(
                    "virtual-file provider inventory is not root-scoped"
                )
            root_id, content_digest = item
            _virtual_member(root_id, content_digest)
            if item in identities:
                raise DataBackupError("virtual-file provider inventory is duplicated")
            identities.add(item)
            _enforce_virtual_root_bounds(
                root_id,
                counts,
                byte_totals,
                0,
                label="virtual-file provider inventory",
            )
    except DataBackupError:
        raise
    except Exception as exc:
        raise DataBackupError("virtual-file provider inventory failed") from exc
    return frozenset(identities)


def _verify_sqlite_database(
    path: Path,
    expected_head: str,
    *,
    virtual_file_reader=None,
) -> dict[tuple[str, str], tuple[str, int]]:
    uri = f"sqlite:///{path.as_posix()}"
    engine = create_engine(uri)
    try:
        with engine.connect() as connection:
            if connection.exec_driver_sql("PRAGMA integrity_check").scalar_one() != "ok":
                raise BackupCorruptionError("backup database integrity check failed")
            verify_persisted_schema_fingerprint(connection)
            references = _virtual_references(connection)
            verify_data_integrity(
                connection, virtual_file_reader=virtual_file_reader
            )
        if database_version(engine) != expected_head:
            raise BackupCorruptionError("backup migration head differs")
    except BackupCorruptionError:
        raise
    except Exception as exc:
        raise BackupCorruptionError("backup database verification failed") from exc
    finally:
        engine.dispose()
    return references


def create_sqlite_backup(
    engine: Engine,
    destination_directory: Path | str,
    *,
    virtual_file_provider: VirtualFileBackupProvider | None = None,
) -> dict[str, Any]:
    """Create one database-locked snapshot and its exact referenced file set."""

    if engine.dialect.name != "sqlite":
        raise DataBackupError("SQLite backup requires a SQLite engine")
    destination = _resolved_new_directory(
        destination_directory,
        exists_message="backup destination already exists",
        error_type=DataBackupError,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.tmp-{uuid4().hex}"
    temporary.mkdir(mode=0o700)
    try:
        database_member = temporary / DATABASE_MEMBER
        seen: set[str] = set()
        with engine.connect() as source:
            try:
                source.exec_driver_sql("BEGIN IMMEDIATE")
            except DBAPIError as exc:
                raise DataBackupError(
                    "backup could not acquire the bounded SQLite write-quiescence lock"
                ) from exc
            try:
                migration_head = _connection_migration_head(source)
                if migration_head != "0007_data_local_service":
                    raise DataBackupError(
                        "backup requires the complete v0.8 migration head"
                    )
                verify_persisted_schema_fingerprint(source)
                references = _virtual_references(source)
                expected_identities = frozenset(references)
                if _provider_inventory(virtual_file_provider) != expected_identities:
                    raise DataBackupError(
                        "virtual-file provider inventory differs from the database snapshot"
                    )
                _snapshot_sqlite(engine, database_member)
                for (root_id, content_digest), (
                    virtual_path,
                    expected_length,
                ) in sorted(references.items()):
                    assert virtual_file_provider is not None
                    try:
                        payload = virtual_file_provider.read(
                            root_id, virtual_path, content_digest
                        )
                    except Exception as exc:
                        raise DataBackupError(
                            "referenced virtual-file content is unavailable"
                        ) from exc
                    if (
                        type(payload) is not bytes
                        or len(payload) != expected_length
                        or _sha256(payload) != content_digest
                    ):
                        raise DataBackupError(
                            "referenced virtual-file content differs from the database"
                        )
                    member = _virtual_member(root_id, content_digest)
                    seen.add(member)
                    _write_member(temporary / member, payload)
                verify_data_integrity(
                    source,
                    virtual_file_reader=(
                        virtual_file_provider.read
                        if virtual_file_provider is not None
                        else None
                    ),
                )
                if _provider_inventory(virtual_file_provider) != expected_identities:
                    raise DataBackupError(
                        "virtual-file provider changed during the locked snapshot"
                    )
                created_at_database_time = _database_time(source)
            finally:
                source.rollback()

        member_paths = [DATABASE_MEMBER, *sorted(seen)]
        inventory: list[dict[str, Any]] = []
        file_sha256: dict[str, str] = {}
        for member in member_paths:
            size, digest = _regular_file_metadata(
                temporary / member, f"backup member {member}"
            )
            inventory.append({"path": member, "size": size})
            file_sha256[member] = digest
        manifest = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "migration_head": migration_head,
            "database_backend": "sqlite",
            "created_at_database_time": created_at_database_time,
            "file_inventory": inventory,
            "file_sha256": file_sha256,
            "aggregate_sha256": _aggregate_digest(inventory, file_sha256),
        }
        manifest_path = temporary / MANIFEST_MEMBER
        with manifest_path.open("xb") as stream:
            stream.write(canonical_backup_manifest_bytes(manifest))
            stream.flush()
            os.fsync(stream.fileno())
        verify_backup_bundle(temporary)
        temporary.rename(destination)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def create_postgresql_backup(
    engine: Engine,
    destination_directory: Path | str,
    *,
    virtual_file_provider: VirtualFileBackupProvider | None = None,
) -> dict[str, Any]:
    """Create an exact binary-COPY backup under a bounded database write lock."""

    if engine.dialect.name != "postgresql":
        raise DataBackupError("PostgreSQL backup requires a PostgreSQL engine")
    destination = _resolved_new_directory(
        destination_directory,
        exists_message="backup destination already exists",
        error_type=DataBackupError,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.tmp-{uuid4().hex}"
    temporary.mkdir(mode=0o700)
    try:
        table_members: list[str] = []
        virtual_members: list[str] = []
        with engine.connect() as source:
            try:
                source.exec_driver_sql(
                    "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
                )
                source.exec_driver_sql("SET LOCAL lock_timeout = '5000ms'")
                source.exec_driver_sql("SET LOCAL statement_timeout = '30000ms'")
                names = sorted(inspect(source).get_table_names(schema="public"))
                if not names:
                    raise DataBackupError("PostgreSQL source has no public tables")
                lock_targets = ",".join(
                    _quote_postgresql(source, name) for name in names
                )
                source.exec_driver_sql(
                    f"LOCK TABLE {lock_targets} IN SHARE MODE"
                )
            except DBAPIError as exc:
                raise DataBackupError(
                    "backup could not acquire the bounded PostgreSQL write-quiescence lock"
                ) from exc
            try:
                migration_head = _connection_migration_head(source)
                if migration_head != "0007_data_local_service":
                    raise DataBackupError(
                        "backup requires the complete v0.8 migration head"
                    )
                verify_persisted_schema_fingerprint(source)
                table_specs = _postgresql_table_specs(source)
                if [item["name"] for item in table_specs] != names:
                    raise BackupCorruptionError(
                        "PostgreSQL table inventory changed before quiescence"
                    )
                references = _virtual_references(source)
                expected_identities = frozenset(references)
                if _provider_inventory(virtual_file_provider) != expected_identities:
                    raise DataBackupError(
                        "virtual-file provider inventory differs from the database snapshot"
                    )

                for table in table_specs:
                    member = _postgresql_table_member(table["name"])
                    _postgresql_copy_out(source, table, temporary / member)
                    table_members.append(member)

                for (root_id, content_digest), (
                    virtual_path,
                    expected_length,
                ) in sorted(references.items()):
                    assert virtual_file_provider is not None
                    try:
                        payload = virtual_file_provider.read(
                            root_id, virtual_path, content_digest
                        )
                    except Exception as exc:
                        raise DataBackupError(
                            "referenced virtual-file content is unavailable"
                        ) from exc
                    if (
                        type(payload) is not bytes
                        or len(payload) != expected_length
                        or _sha256(payload) != content_digest
                    ):
                        raise DataBackupError(
                            "referenced virtual-file content differs from the database"
                        )
                    member = _virtual_member(root_id, content_digest)
                    _write_member(temporary / member, payload)
                    virtual_members.append(member)

                verify_data_integrity(
                    source,
                    virtual_file_reader=(
                        virtual_file_provider.read
                        if virtual_file_provider is not None
                        else None
                    ),
                )
                if _provider_inventory(virtual_file_provider) != expected_identities:
                    raise DataBackupError(
                        "virtual-file provider changed during the locked snapshot"
                    )
                created_at_database_time = _database_time(source)
                catalog = {
                    "schema_version": POSTGRES_CATALOG_SCHEMA_VERSION,
                    "tables": table_specs,
                    "virtual_references": _virtual_reference_catalog(references),
                }
                _write_member(
                    temporary / POSTGRES_CATALOG_MEMBER,
                    _canonical_postgresql_catalog_bytes(catalog),
                    maximum_bytes=MAXIMUM_BACKUP_METADATA_BYTES,
                    label="PostgreSQL backup catalog",
                )
            finally:
                source.rollback()

        member_paths = [
            POSTGRES_CATALOG_MEMBER,
            *sorted(table_members),
            *sorted(virtual_members),
        ]
        inventory: list[dict[str, Any]] = []
        file_sha256: dict[str, str] = {}
        for member in member_paths:
            size, digest = _regular_file_metadata(
                temporary / member, f"backup member {member}"
            )
            inventory.append({"path": member, "size": size})
            file_sha256[member] = digest
        manifest = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "migration_head": migration_head,
            "database_backend": "postgresql",
            "created_at_database_time": created_at_database_time,
            "file_inventory": inventory,
            "file_sha256": file_sha256,
            "aggregate_sha256": _aggregate_digest(inventory, file_sha256),
        }
        manifest_path = temporary / MANIFEST_MEMBER
        with manifest_path.open("xb") as stream:
            stream.write(canonical_backup_manifest_bytes(manifest))
            stream.flush()
            os.fsync(stream.fileno())
        verify_backup_bundle(temporary)
        temporary.rename(destination)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _manifest_from_bundle(directory: Path) -> tuple[dict[str, Any], bytes]:
    raw = _regular_bytes(
        directory / MANIFEST_MEMBER,
        MAXIMUM_BACKUP_METADATA_BYTES,
        "backup manifest",
    )
    try:
        payload = strict_json_loads(
            raw, maximum_bytes=MAXIMUM_BACKUP_METADATA_BYTES
        )
    except TypedValueError as exc:
        raise BackupCorruptionError("backup manifest JSON is invalid") from exc
    if type(payload) is not dict:
        raise BackupCorruptionError("backup manifest is not an object")
    if canonical_backup_manifest_bytes(payload) != raw:
        raise BackupCorruptionError("backup manifest bytes are not canonical")
    return payload, raw


def _postgresql_catalog_from_bundle(directory: Path) -> dict[str, Any]:
    raw = _regular_bytes(
        directory / POSTGRES_CATALOG_MEMBER,
        MAXIMUM_BACKUP_METADATA_BYTES,
        "PostgreSQL backup catalog",
    )
    try:
        payload = strict_json_loads(
            raw, maximum_bytes=MAXIMUM_BACKUP_METADATA_BYTES
        )
    except TypedValueError as exc:
        raise BackupCorruptionError("PostgreSQL backup catalog JSON is invalid") from exc
    if type(payload) is not dict or _canonical_postgresql_catalog_bytes(payload) != raw:
        raise BackupCorruptionError("PostgreSQL backup catalog bytes differ")
    if payload["schema_version"] != POSTGRES_CATALOG_SCHEMA_VERSION:
        raise BackupCorruptionError("PostgreSQL backup catalog schema differs")
    tables = payload["tables"]
    references = payload["virtual_references"]
    if type(tables) is not list or type(references) is not list:
        raise BackupCorruptionError("PostgreSQL backup catalog inventory differs")
    previous = ""
    for table in tables:
        if type(table) is not dict or set(table) != {
            "checks",
            "columns",
            "foreign_keys",
            "indexes",
            "name",
            "primary_key",
            "unique_constraints",
        }:
            raise BackupCorruptionError("PostgreSQL table contract fields differ")
        name = table["name"]
        if (
            type(name) is not str
            or _POSTGRES_IDENTIFIER.fullmatch(name) is None
            or name <= previous
        ):
            raise BackupCorruptionError("PostgreSQL table contract order differs")
        previous = name
        columns = table["columns"]
        primary = table["primary_key"]
        if (
            type(columns) is not list
            or not columns
            or type(primary) is not dict
            or set(primary) != {"columns", "name"}
            or type(primary["columns"]) is not list
            or not primary["columns"]
        ):
            raise BackupCorruptionError("PostgreSQL table column contract differs")
        column_names: list[str] = []
        for column in columns:
            if type(column) is not dict or set(column) != {
                "default",
                "name",
                "nullable",
                "type",
            }:
                raise BackupCorruptionError("PostgreSQL column contract fields differ")
            column_name = column["name"]
            if (
                type(column_name) is not str
                or _POSTGRES_IDENTIFIER.fullmatch(column_name) is None
                or column_name in column_names
                or type(column["nullable"]) is not bool
                or type(column["type"]) is not str
                or not column["type"]
                or (
                    column["default"] is not None
                    and type(column["default"]) is not str
                )
            ):
                raise BackupCorruptionError("PostgreSQL column contract value differs")
            column_names.append(column_name)
        if any(item not in column_names for item in primary["columns"]):
            raise BackupCorruptionError("PostgreSQL primary key contract differs")
        for collection in (
            table["checks"],
            table["foreign_keys"],
            table["indexes"],
            table["unique_constraints"],
        ):
            if type(collection) is not list:
                raise BackupCorruptionError(
                    "PostgreSQL constraint contract inventory differs"
                )
    expected_reference_identities: set[tuple[str, str]] = set()
    previous_identity: tuple[str, str] | None = None
    counts: dict[str, int] = {}
    byte_totals: dict[str, int] = {}
    for item in references:
        if type(item) is not dict or set(item) != {
            "byte_length",
            "content_digest",
            "storage_root_id",
            "virtual_path",
        }:
            raise BackupCorruptionError("PostgreSQL virtual reference fields differ")
        identity = (item["storage_root_id"], item["content_digest"])
        _virtual_member(*identity)
        _validate_database_virtual_path(item["virtual_path"])
        if (
            type(item["byte_length"]) is not int
            or not 0 <= item["byte_length"] <= MAXIMUM_VIRTUAL_FILE_BYTES
            or (previous_identity is not None and identity <= previous_identity)
        ):
            raise BackupCorruptionError("PostgreSQL virtual reference value differs")
        previous_identity = identity
        expected_reference_identities.add(identity)
        _enforce_virtual_root_bounds(
            identity[0],
            counts,
            byte_totals,
            item["byte_length"],
            label="PostgreSQL virtual reference",
        )
    return payload


def verify_backup_bundle(directory: Path | str) -> dict[str, Any]:
    """Fail closed unless an isolated backup directory is exact and complete."""

    root = _resolved_existing_directory(
        directory,
        label="backup bundle",
        error_type=BackupCorruptionError,
    )
    manifest, _ = _manifest_from_bundle(root)
    if manifest["schema_version"] != BACKUP_SCHEMA_VERSION:
        raise BackupCorruptionError("backup manifest schema version differs")
    backend = manifest["database_backend"]
    if backend not in {"sqlite", "postgresql"}:
        raise BackupCorruptionError("backup backend is unsupported")
    if manifest["migration_head"] != "0007_data_local_service":
        raise BackupCorruptionError("backup migration head differs")
    try:
        datetime.strptime(
            manifest["created_at_database_time"], "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    except (TypeError, ValueError) as exc:
        raise BackupCorruptionError("backup database time is invalid") from exc

    inventory = manifest["file_inventory"]
    digests = manifest["file_sha256"]
    if type(inventory) is not list or type(digests) is not dict:
        raise BackupCorruptionError("backup file inventory shape differs")
    expected_paths: list[str] = []
    virtual_counts: dict[str, int] = {}
    virtual_byte_totals: dict[str, int] = {}
    for item in inventory:
        if type(item) is not dict or set(item) != {"path", "size"}:
            raise BackupCorruptionError("backup inventory entry shape differs")
        path = item["path"]
        size = item["size"]
        if type(path) is not str or type(size) is not int or size < 0:
            raise BackupCorruptionError("backup inventory entry value differs")
        if path.startswith("virtual-files/"):
            root_id, _ = _virtual_member_identity(path)
            if size > MAXIMUM_VIRTUAL_FILE_BYTES:
                raise BackupCorruptionError(
                    "backup virtual-file member exceeds its byte limit"
                )
            _enforce_virtual_root_bounds(
                root_id,
                virtual_counts,
                virtual_byte_totals,
                size,
                label="backup virtual-file member",
            )
        elif backend == "sqlite" and path != DATABASE_MEMBER:
            raise BackupCorruptionError("backup inventory path is unauthorized")
        elif backend == "postgresql" and path != POSTGRES_CATALOG_MEMBER:
            match = re.fullmatch(r"postgresql/tables/([a-z_][a-z0-9_]{0,62})\.copy", path)
            if match is None:
                raise BackupCorruptionError("backup inventory path is unauthorized")
        expected_paths.append(path)
    ordered_paths = (
        [DATABASE_MEMBER]
        + sorted(path for path in expected_paths if path.startswith("virtual-files/"))
        if backend == "sqlite"
        else [POSTGRES_CATALOG_MEMBER]
        + sorted(path for path in expected_paths if path.startswith("postgresql/tables/"))
        + sorted(path for path in expected_paths if path.startswith("virtual-files/"))
    )
    if expected_paths != ordered_paths or len(expected_paths) != len(set(expected_paths)):
        raise BackupCorruptionError("backup inventory order or uniqueness differs")
    if set(digests) != set(expected_paths):
        raise BackupCorruptionError("backup digest inventory differs")
    if any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in digests.values()):
        raise BackupCorruptionError("backup member digest value differs")

    actual_paths: list[str] = []
    actual_directories: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if _is_link_or_reparse(info):
            raise BackupCorruptionError("backup bundle contains a symbolic link")
        if stat.S_ISREG(info.st_mode) and relative != MANIFEST_MEMBER:
            actual_paths.append(relative)
        elif stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
        elif not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
            raise BackupCorruptionError("backup bundle contains a special file")
    if sorted(actual_paths) != sorted(expected_paths):
        raise BackupCorruptionError("backup member inventory differs")
    expected_directories: set[str] = set()
    for member in expected_paths:
        parent = PurePosixPath(member).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    if actual_directories != expected_directories:
        raise BackupCorruptionError("backup directory inventory differs")

    by_path = {item["path"]: item for item in inventory}
    for path in expected_paths:
        maximum = None
        if path.startswith("virtual-files/"):
            maximum = MAXIMUM_VIRTUAL_FILE_BYTES
        elif path == POSTGRES_CATALOG_MEMBER:
            maximum = MAXIMUM_BACKUP_METADATA_BYTES
        size, digest = _regular_file_metadata(
            root / path,
            f"backup member {path}",
            maximum_bytes=maximum,
        )
        if size != by_path[path]["size"] or digest != digests[path]:
            raise BackupCorruptionError(f"backup member digest differs: {path}")
    if _aggregate_digest(inventory, digests) != manifest["aggregate_sha256"]:
        raise BackupCorruptionError("backup aggregate digest differs")

    if backend == "sqlite":
        def read_virtual_file(
            storage_root_id: str, _virtual_path: str, content_digest: str
        ) -> bytes:
            return _regular_bytes(
                root / _virtual_member(storage_root_id, content_digest),
                MAXIMUM_VIRTUAL_FILE_BYTES,
                "backup virtual-file member",
            )

        references = _verify_sqlite_database(
            root / DATABASE_MEMBER,
            manifest["migration_head"],
            virtual_file_reader=read_virtual_file,
        )
        database_members = {
            DATABASE_MEMBER,
            *(
                _virtual_member(root_id, content_digest)
                for root_id, content_digest in references
            ),
        }
    else:
        catalog = _postgresql_catalog_from_bundle(root)
        database_members = {
            POSTGRES_CATALOG_MEMBER,
            *(
                _postgresql_table_member(table["name"])
                for table in catalog["tables"]
            ),
            *(
                _virtual_member(
                    item["storage_root_id"], item["content_digest"]
                )
                for item in catalog["virtual_references"]
            ),
        }
    if set(expected_paths) != database_members:
        raise BackupCorruptionError(
            "backup member inventory differs from its database catalog"
        )
    return manifest


def restore_sqlite_backup(
    bundle_directory: Path | str, isolated_target_directory: Path | str
) -> dict[str, Any]:
    """Reconstruct a verified isolated target; never activate or overwrite it."""

    source = _resolved_existing_directory(
        bundle_directory,
        label="backup bundle",
        error_type=BackupCorruptionError,
    )
    manifest = verify_backup_bundle(source)
    target = _resolved_new_directory(
        isolated_target_directory,
        exists_message="isolated restore target already exists",
        error_type=UnsafeRestoreError,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".{target.name}.tmp-{uuid4().hex}"
    try:
        shutil.copytree(source, temporary, symlinks=False)
        verify_backup_bundle(temporary)
        temporary.rename(target)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def validate_postgresql_restore_target(
    active_database_url: str, isolated_database_url: str
) -> dict[str, Any]:
    """Validate planning only; PostgreSQL activation remains an explicit manual act."""

    active = make_url(active_database_url)
    isolated = make_url(isolated_database_url)
    if active.get_backend_name() != "postgresql" or isolated.get_backend_name() != "postgresql":
        raise UnsafeRestoreError("PostgreSQL restore requires PostgreSQL URLs")
    if not active.database or not isolated.database or active.database == isolated.database:
        raise UnsafeRestoreError("PostgreSQL restore target must be a separately named database")
    if (active.host, active.port or 5432) != (isolated.host, isolated.port or 5432):
        raise UnsafeRestoreError("PostgreSQL isolated target must use the verified local server")
    if (
        _POSTGRES_IDENTIFIER.fullmatch(active.database) is None
        or _POSTGRES_IDENTIFIER.fullmatch(isolated.database) is None
        or isolated.database in {"postgres", "template0", "template1"}
    ):
        raise UnsafeRestoreError("PostgreSQL restore database identity is invalid")
    return {
        "active_database": active.database,
        "isolated_database": isolated.database,
        "manual_activation_required": True,
        "automatic_swap_authorized": False,
    }


def _postgresql_load_order(tables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name = {table["name"]: table for table in tables}
    dependencies = {
        name: {
            item["referred_table"]
            for item in table["foreign_keys"]
            if item["referred_schema"] == "public"
            and item["referred_table"] in by_name
            and item["referred_table"] != name
        }
        for name, table in by_name.items()
    }
    ordered: list[dict[str, Any]] = []
    while dependencies:
        ready = sorted(name for name, needed in dependencies.items() if not needed)
        if not ready:
            raise BackupCorruptionError(
                "PostgreSQL restore dependency graph contains a cycle"
            )
        for name in ready:
            ordered.append(by_name[name])
            del dependencies[name]
        for needed in dependencies.values():
            needed.difference_update(ready)
    return ordered


def restore_postgresql_backup(
    bundle_directory: Path | str,
    active_database_url: str,
    isolated_database_url: str,
) -> dict[str, Any]:
    """Reconstruct and verify a new database without activating or swapping it."""

    plan = validate_postgresql_restore_target(
        active_database_url, isolated_database_url
    )
    source = _resolved_existing_directory(
        bundle_directory,
        label="backup bundle",
        error_type=BackupCorruptionError,
    )
    manifest = verify_backup_bundle(source)
    if manifest["database_backend"] != "postgresql":
        raise UnsafeRestoreError("PostgreSQL restore requires a PostgreSQL bundle")
    catalog = _postgresql_catalog_from_bundle(source)
    inventory_by_path = {
        item["path"]: item for item in manifest["file_inventory"]
    }
    member_digests = manifest["file_sha256"]
    isolated_url = make_url(isolated_database_url)
    admin_url = isolated_url.set(database="postgres")
    admin_engine = create_engine(
        admin_url.render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
        pool_pre_ping=True,
    )
    isolated_engine: Engine | None = None
    created = False
    migration_backup_directory = (
        source.parent / f".{source.name}.restore-migration-{uuid4().hex}"
    )
    try:
        with admin_engine.connect() as admin:
            active_exists = admin.exec_driver_sql(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (plan["active_database"],),
            ).scalar_one_or_none()
            isolated_exists = admin.exec_driver_sql(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (plan["isolated_database"],),
            ).scalar_one_or_none()
            if active_exists != 1:
                raise UnsafeRestoreError("active PostgreSQL database is unavailable")
            if isolated_exists is not None:
                raise UnsafeRestoreError(
                    "isolated PostgreSQL restore target already exists"
                )
            target_name = _quote_postgresql(admin, plan["isolated_database"])
            admin.exec_driver_sql(f"CREATE DATABASE {target_name} TEMPLATE template0")
            created = True

        isolated_engine = create_engine(
            isolated_url.render_as_string(hide_password=False), pool_pre_ping=True
        )
        migration_backup_directory.mkdir(mode=0o700)
        run_migrations(
            isolated_engine,
            v0007_backup_directory=migration_backup_directory,
        )
        expected_tables = catalog["tables"]
        expected_references = {
            (item["storage_root_id"], item["content_digest"]): (
                item["virtual_path"],
                item["byte_length"],
            )
            for item in catalog["virtual_references"]
        }

        def read_virtual_file(
            storage_root_id: str, _virtual_path: str, content_digest: str
        ) -> bytes:
            return _regular_bytes(
                source / _virtual_member(storage_root_id, content_digest),
                MAXIMUM_VIRTUAL_FILE_BYTES,
                "backup virtual-file member",
            )

        with isolated_engine.begin() as target:
            actual_tables = _postgresql_table_specs(target)
            if actual_tables != expected_tables:
                raise BackupCorruptionError(
                    "isolated PostgreSQL schema differs from the source catalog"
                )
            quoted_tables = ",".join(
                _quote_postgresql(target, table["name"])
                for table in expected_tables
            )
            target.exec_driver_sql(
                f"TRUNCATE TABLE {quoted_tables} RESTART IDENTITY CASCADE"
            )
            for table in _postgresql_load_order(expected_tables):
                member = _postgresql_table_member(table["name"])
                _postgresql_copy_in(
                    target,
                    table,
                    source / member,
                    expected_size=inventory_by_path[member]["size"],
                    expected_digest=member_digests[member],
                )

            if _connection_migration_head(target) != manifest["migration_head"]:
                raise BackupCorruptionError(
                    "restored PostgreSQL migration head differs"
                )
            verify_persisted_schema_fingerprint(target)
            restored_references = _virtual_references(target)
            if restored_references != expected_references:
                raise BackupCorruptionError(
                    "restored PostgreSQL virtual references differ"
                )
            verify_data_integrity(
                target, virtual_file_reader=read_virtual_file
            )
            for table in expected_tables:
                member = _postgresql_table_member(table["name"])
                restored_size, restored_digest = _postgresql_copy_out(target, table)
                if (
                    restored_size != inventory_by_path[member]["size"]
                    or restored_digest != member_digests[member]
                ):
                    raise BackupCorruptionError(
                        f"restored PostgreSQL table bytes differ: {table['name']}"
                    )

        if database_version(isolated_engine) != manifest["migration_head"]:
            raise BackupCorruptionError("verified PostgreSQL restore head differs")
        return {**plan, "manifest": manifest}
    except Exception:
        if isolated_engine is not None:
            isolated_engine.dispose()
        if created:
            try:
                with admin_engine.connect() as admin:
                    admin.exec_driver_sql(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = %s AND pid <> pg_backend_pid()",
                        (plan["isolated_database"],),
                    )
                    target_name = _quote_postgresql(
                        admin, plan["isolated_database"]
                    )
                    admin.exec_driver_sql(f"DROP DATABASE {target_name}")
            except Exception:
                pass
        raise
    finally:
        if isolated_engine is not None:
            isolated_engine.dispose()
        admin_engine.dispose()
        shutil.rmtree(migration_backup_directory, ignore_errors=True)


__all__ = [
    "BACKUP_SCHEMA_VERSION",
    "BackupCorruptionError",
    "DATABASE_MEMBER",
    "DataBackupError",
    "MANIFEST_MEMBER",
    "UnsafeRestoreError",
    "canonical_backup_manifest_bytes",
    "create_postgresql_backup",
    "create_sqlite_backup",
    "restore_postgresql_backup",
    "restore_sqlite_backup",
    "validate_postgresql_restore_target",
    "verify_backup_bundle",
]
