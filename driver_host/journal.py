"""Bounded private SQLite idempotency journal for simulator lifecycle effects."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

from .config import JournalConfig
from .domain import (
    AttemptRecord,
    Certainty,
    Effect,
    ErrorCode,
    GenerationIdentity,
    HookAction,
    HookLayer,
    HookOutcome,
    HookTraceRecord,
    Method,
    OperationCommand,
    OperationRecord,
    Result,
    SafeFailure,
    Stage,
)


SCHEMA_VERSION = "spell.driver.journal/1"
PRESENCE_MARKER_SCHEMA = "spell.driver.journal-presence/1"
MAX_RECORD_BYTES = 64 * 1024
_STAGE_ORDER = {
    Stage.REQUESTED: 0,
    Stage.ACCEPTED: 1,
    Stage.DISPATCHED: 2,
    Stage.RECONCILING: 3,
    Stage.SETTLED: 4,
}


class JournalError(RuntimeError):
    pass


class JournalConflictError(JournalError):
    pass


class JournalCapacityError(JournalError):
    pass


class JournalIntegrityError(JournalError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _checksum(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _failure_to_dict(value: Optional[SafeFailure]) -> Optional[dict[str, object]]:
    if value is None:
        return None
    return {
        "code": value.code.value,
        "message": value.message,
        "retryable": value.retryable,
    }


def _failure_from_dict(value: Optional[dict[str, object]]) -> Optional[SafeFailure]:
    if value is None:
        return None
    return SafeFailure(
        code=ErrorCode(str(value["code"])),
        message=str(value["message"]),
        retryable=bool(value["retryable"]),
    )


def _identity_to_dict(value: GenerationIdentity) -> dict[str, str]:
    return value.canonical()


def _identity_from_dict(value: dict[str, object]) -> GenerationIdentity:
    return GenerationIdentity(**{key: str(item) for key, item in value.items()})


def _trace_to_dict(value: HookTraceRecord) -> dict[str, object]:
    return {
        "sequence": value.sequence,
        "hook_id": value.hook_id,
        "layer": value.layer.value,
        "action": value.action.value,
        "outcome": value.outcome.value,
        "started_unix_ms": value.started_unix_ms,
        "completed_unix_ms": value.completed_unix_ms,
        "error": _failure_to_dict(value.error),
        "identity": _identity_to_dict(value.identity) if value.identity is not None else None,
        "operation_id": value.operation_id,
        "attempt_id": value.attempt_id,
        "stage": value.stage.value,
        "certainty": value.certainty.value if value.certainty is not None else None,
    }


def _trace_from_dict(value: dict[str, object]) -> HookTraceRecord:
    identity = value.get("identity")
    certainty = value.get("certainty")
    return HookTraceRecord(
        sequence=int(value["sequence"]),
        hook_id=str(value["hook_id"]),
        layer=HookLayer(str(value["layer"])),
        action=HookAction(str(value["action"])),
        outcome=HookOutcome(str(value["outcome"])),
        started_unix_ms=int(value["started_unix_ms"]),
        completed_unix_ms=int(value["completed_unix_ms"]),
        error=_failure_from_dict(value.get("error")),
        identity=_identity_from_dict(identity) if identity is not None else None,
        operation_id=str(value.get("operation_id", "")),
        attempt_id=str(value.get("attempt_id", "")),
        stage=Stage(str(value.get("stage", Stage.DISPATCHED.value))),
        certainty=Certainty(str(certainty)) if certainty is not None else None,
    )


def _attempt_to_dict(value: AttemptRecord) -> dict[str, object]:
    return {
        "operation_id": value.operation_id,
        "method": value.method.value,
        "identity": _identity_to_dict(value.identity),
        "attempt_id": value.attempt_id,
        "attempt_number": value.attempt_number,
        "request_digest": value.request_digest,
        "effect": value.effect.value,
        "stage": value.stage.value,
        "certainty": value.certainty.value if value.certainty is not None else None,
        "result": value.result.value,
        "error": _failure_to_dict(value.error),
        "requested_unix_ms": value.requested_unix_ms,
        "accepted_unix_ms": value.accepted_unix_ms,
        "dispatched_unix_ms": value.dispatched_unix_ms,
        "settled_unix_ms": value.settled_unix_ms,
        "hook_traces": [_trace_to_dict(item) for item in value.hook_traces],
        "lifecycle_reason": value.lifecycle_reason,
        "replaced_driver_binding_id": value.replaced_driver_binding_id,
    }


def _attempt_from_dict(value: dict[str, object]) -> AttemptRecord:
    certainty_value = value.get("certainty")
    return AttemptRecord(
        operation_id=str(value["operation_id"]),
        method=Method(str(value["method"])),
        identity=_identity_from_dict(value["identity"]),
        attempt_id=str(value["attempt_id"]),
        attempt_number=int(value["attempt_number"]),
        request_digest=str(value["request_digest"]),
        effect=Effect(str(value["effect"])),
        stage=Stage(str(value["stage"])),
        certainty=Certainty(str(certainty_value)) if certainty_value is not None else None,
        result=Result(str(value["result"])),
        error=_failure_from_dict(value.get("error")),
        requested_unix_ms=int(value["requested_unix_ms"]),
        accepted_unix_ms=int(value["accepted_unix_ms"]),
        dispatched_unix_ms=int(value["dispatched_unix_ms"]),
        settled_unix_ms=int(value["settled_unix_ms"]),
        hook_traces=tuple(_trace_from_dict(item) for item in value["hook_traces"]),
        lifecycle_reason=str(value.get("lifecycle_reason", "")),
        replaced_driver_binding_id=str(
            value.get("replaced_driver_binding_id", "")
        ),
    )


class OperationJournal:
    """Durable attempt history; records are never evicted or re-executed."""

    def __init__(
        self,
        path: str | Path,
        generation: str,
        limits: JournalConfig,
        *,
        create: bool = True,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self.path = Path(path)
        self._presence_path = self.path.with_name(f"{self.path.name}.required")
        self.generation = generation
        self.limits = limits
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._lock = threading.RLock()
        if self.path.is_symlink() or self._presence_path.is_symlink():
            raise JournalIntegrityError("journal path must not be a symlink")
        if self.path.exists() and not self.path.is_file():
            raise JournalIntegrityError("journal path must be a regular file")
        if self._presence_path.exists() and not self._presence_path.is_file():
            raise JournalIntegrityError("journal presence marker must be a regular file")
        if not self.path.exists() and self._presence_path.exists():
            raise JournalIntegrityError("required journal is missing")
        if not self.path.exists() and not create:
            raise JournalIntegrityError("required journal is missing")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.path,
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure()
            self._initialize()
            self.verify()
            self._ensure_presence_marker()
        except Exception:
            self._connection.close()
            raise

    def _presence_bytes(self) -> bytes:
        return (
            _canonical_json(
                {
                    "journal_name": self.path.name,
                    "schema_version": PRESENCE_MARKER_SCHEMA,
                }
            )
            + "\n"
        ).encode("ascii")

    def _ensure_presence_marker(self) -> None:
        expected = self._presence_bytes()
        if self._presence_path.exists():
            try:
                observed = self._presence_path.read_bytes()
            except OSError as exc:
                raise JournalIntegrityError("journal presence marker is unreadable") from exc
            if observed != expected:
                raise JournalIntegrityError("journal presence marker differs")
            return
        try:
            descriptor = os.open(
                self._presence_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            self._ensure_presence_marker()
            return
        except OSError as exc:
            raise JournalIntegrityError("journal presence marker cannot be created") from exc
        try:
            with os.fdopen(descriptor, "wb") as marker:
                marker.write(expected)
                marker.flush()
                os.fsync(marker.fileno())
        except Exception:
            try:
                self._presence_path.unlink()
            except OSError:
                pass
            raise

    def _configure(self) -> None:
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = DELETE")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute("PRAGMA fullfsync = ON")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        self._connection.execute("PRAGMA temp_store = MEMORY")

    def _initialize(self) -> None:
        with self._transaction():
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS journal_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS journal_generations (
                    driver_host_generation TEXT PRIMARY KEY,
                    registered_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operation_attempts (
                    operation_id TEXT NOT NULL,
                    attempt_id TEXT PRIMARY KEY,
                    attempt_number INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_checksum TEXT NOT NULL,
                    UNIQUE(operation_id, attempt_number)
                );
                CREATE INDEX IF NOT EXISTS ix_operation_attempts_operation
                    ON operation_attempts(operation_id, attempt_number);
                CREATE TABLE IF NOT EXISTS operation_transitions (
                    attempt_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    certainty TEXT,
                    result TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    occurred_unix_ms INTEGER NOT NULL,
                    transition_checksum TEXT NOT NULL,
                    PRIMARY KEY(attempt_id, sequence),
                    FOREIGN KEY(attempt_id) REFERENCES operation_attempts(attempt_id)
                );
                """
            )
            metadata = dict(
                self._connection.execute(
                    "SELECT key, value FROM journal_metadata"
                ).fetchall()
            )
            if not metadata:
                self._connection.execute(
                    "INSERT INTO journal_metadata(key, value) VALUES (?, ?)",
                    ("schema_version", SCHEMA_VERSION),
                )
            else:
                # Early v0.4 development journals bound the whole file to one
                # host generation. Preserve that generation while upgrading to
                # a ledger that can fence and reconcile across host restarts.
                legacy_generation = metadata.pop("driver_host_generation", None)
                if metadata != {"schema_version": SCHEMA_VERSION}:
                    raise JournalIntegrityError("journal metadata differs")
                if legacy_generation is not None:
                    self._connection.execute(
                        "DELETE FROM journal_metadata WHERE key = ?",
                        ("driver_host_generation",),
                    )
                    self._connection.execute(
                        """
                        INSERT OR IGNORE INTO journal_generations(
                            driver_host_generation, registered_unix_ms
                        ) VALUES (?, ?)
                        """,
                        (legacy_generation, self._clock_ms()),
                    )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO journal_generations(
                    driver_host_generation, registered_unix_ms
                ) VALUES (?, ?)
                """,
                (self.generation, self._clock_ms()),
            )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise JournalIntegrityError("journal transaction could not begin") from exc
        try:
            yield
        except sqlite3.Error as exc:
            try:
                self._connection.rollback()
            except sqlite3.Error:
                pass
            raise JournalIntegrityError("journal transaction failed") from exc
        except Exception:
            self._connection.rollback()
            raise
        else:
            try:
                self._connection.commit()
            except sqlite3.Error as exc:
                try:
                    self._connection.rollback()
                except sqlite3.Error:
                    pass
                raise JournalIntegrityError("journal transaction did not commit") from exc

    def _database_bytes(self) -> int:
        page_count = int(self._connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(self._connection.execute("PRAGMA page_size").fetchone()[0])
        return page_count * page_size

    def _check_capacity(self) -> None:
        count = int(
            self._connection.execute("SELECT COUNT(*) FROM operation_attempts").fetchone()[0]
        )
        if count >= self.limits.max_entries:
            raise JournalCapacityError("journal entry capacity is exhausted")
        if self._database_bytes() + 8192 > self.limits.max_bytes:
            raise JournalCapacityError("journal byte capacity is exhausted")

    def _enforce_capacity_after_write(self) -> None:
        count = int(
            self._connection.execute("SELECT COUNT(*) FROM operation_attempts").fetchone()[0]
        )
        if count > self.limits.max_entries or self._database_bytes() > self.limits.max_bytes:
            raise JournalCapacityError("journal write exceeded its durable capacity")

    def _load_attempt(self, attempt_id: str) -> Optional[AttemptRecord]:
        row = self._connection.execute(
            "SELECT record_json, record_checksum FROM operation_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            return None
        if _checksum(row["record_json"]) != row["record_checksum"]:
            raise JournalIntegrityError("attempt checksum mismatch")
        try:
            return _attempt_from_dict(json.loads(row["record_json"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise JournalIntegrityError("attempt record is malformed") from exc

    def _write_record(self, value: AttemptRecord, evidence: str) -> None:
        record_json = _canonical_json(_attempt_to_dict(value))
        if len(record_json.encode("ascii")) > MAX_RECORD_BYTES:
            raise JournalCapacityError("attempt record exceeds the bounded size")
        self._connection.execute(
            """
            UPDATE operation_attempts
               SET stage = ?, record_json = ?, record_checksum = ?
             WHERE attempt_id = ?
            """,
            (value.stage.value, record_json, _checksum(record_json), value.attempt_id),
        )
        sequence = int(
            self._connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM operation_transitions WHERE attempt_id = ?",
                (value.attempt_id,),
            ).fetchone()[0]
        )
        transition = {
            "attempt_id": value.attempt_id,
            "sequence": sequence,
            "stage": value.stage.value,
            "certainty": value.certainty.value if value.certainty is not None else None,
            "result": value.result.value,
            "evidence": evidence,
            "occurred_unix_ms": self._clock_ms(),
        }
        transition_json = _canonical_json(transition)
        self._connection.execute(
            """
            INSERT INTO operation_transitions(
                attempt_id, sequence, stage, certainty, result, evidence,
                occurred_unix_ms, transition_checksum
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transition["attempt_id"],
                transition["sequence"],
                transition["stage"],
                transition["certainty"],
                transition["result"],
                transition["evidence"],
                transition["occurred_unix_ms"],
                _checksum(transition_json),
            ),
        )
        self._enforce_capacity_after_write()

    def accept(self, command: OperationCommand) -> tuple[AttemptRecord, bool]:
        """Persist an intent before dispatch; return (record, was_duplicate)."""

        with self._lock, self._transaction():
            if command.identity.driver_host_generation != self.generation:
                raise JournalConflictError("attempt belongs to another host generation")
            duplicate = self._load_attempt(command.attempt_id)
            if duplicate is not None:
                if (
                    duplicate.operation_id != command.operation_id
                    or duplicate.method != command.method
                    or duplicate.request_digest != command.request_digest
                    or duplicate.attempt_number != command.attempt_number
                    or duplicate.identity != command.identity
                ):
                    raise JournalConflictError("attempt identity conflicts with durable intent")
                return duplicate, True
            prior_rows = self._connection.execute(
                "SELECT attempt_id FROM operation_attempts WHERE operation_id = ? ORDER BY attempt_number",
                (command.operation_id,),
            ).fetchall()
            if prior_rows:
                prior = self._load_attempt(prior_rows[-1]["attempt_id"])
                assert prior is not None
                if (
                    prior.method != command.method
                    or prior.request_digest != command.request_digest
                    or command.attempt_number != prior.attempt_number + 1
                    or prior.stage is not Stage.SETTLED
                    or prior.certainty is not Certainty.NO_EFFECT
                ):
                    raise JournalConflictError("operation retry is not authorized by durable no-effect proof")
            elif command.attempt_number != 1:
                raise JournalConflictError("first operation attempt must have attempt number one")
            self._check_capacity()
            now = self._clock_ms()
            requested = AttemptRecord(
                operation_id=command.operation_id,
                method=command.method,
                identity=command.identity,
                attempt_id=command.attempt_id,
                attempt_number=command.attempt_number,
                request_digest=command.request_digest,
                effect=command.effect,
                stage=Stage.REQUESTED,
                certainty=None,
                result=Result.RECONCILIATION_REQUIRED,
                error=None,
                requested_unix_ms=now,
                lifecycle_reason=command.lifecycle_reason,
                replaced_driver_binding_id=command.replaced_driver_binding_id,
            )
            record_json = _canonical_json(_attempt_to_dict(requested))
            self._connection.execute(
                """
                INSERT INTO operation_attempts(
                    operation_id, attempt_id, attempt_number, method,
                    request_digest, stage, record_json, record_checksum
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    command.operation_id,
                    command.attempt_id,
                    command.attempt_number,
                    command.method.value,
                    command.request_digest,
                    requested.stage.value,
                    record_json,
                    _checksum(record_json),
                ),
            )
            self._write_record(requested, "request-recorded")
            accepted = requested.evolve(stage=Stage.ACCEPTED, accepted_unix_ms=self._clock_ms())
            self._write_record(accepted, "intent-durable")
            return accepted, False

    def _evolve(
        self,
        attempt_id: str,
        stage: Stage,
        certainty: Optional[Certainty],
        result: Result,
        error: Optional[SafeFailure],
        evidence: str,
        **timestamps: int,
    ) -> AttemptRecord:
        with self._lock, self._transaction():
            current = self._load_attempt(attempt_id)
            if current is None:
                raise KeyError("operation attempt not found")
            if _STAGE_ORDER[stage] < _STAGE_ORDER[current.stage]:
                raise JournalConflictError("operation stage cannot regress")
            if current.stage is Stage.SETTLED and (
                stage is not Stage.SETTLED
                or certainty != current.certainty
                or result != current.result
                or error != current.error
            ):
                raise JournalConflictError("settled operation disposition is immutable")
            if stage is Stage.SETTLED and certainty not in {
                Certainty.NO_EFFECT,
                Certainty.EFFECT_CONFIRMED,
            }:
                raise JournalConflictError("uncertain effects must remain reconciling")
            if current.stage is Stage.ACCEPTED:
                valid = stage is Stage.DISPATCHED or (
                    stage is Stage.SETTLED and certainty is Certainty.NO_EFFECT
                )
                if not valid:
                    raise JournalConflictError("accepted attempt has an invalid next disposition")
            elif current.stage is Stage.DISPATCHED:
                if stage not in {Stage.DISPATCHED, Stage.RECONCILING, Stage.SETTLED}:
                    raise JournalConflictError("dispatched attempt has an invalid next stage")
            elif current.stage is Stage.RECONCILING:
                if stage not in {Stage.RECONCILING, Stage.SETTLED}:
                    raise JournalConflictError("reconciling attempt has an invalid next stage")
                if (
                    current.certainty is Certainty.EFFECT_UNKNOWN
                    and certainty is Certainty.EFFECT_POSSIBLE
                ):
                    raise JournalConflictError("certainty cannot regress from unknown to possible")
            updated = current.evolve(
                stage=stage,
                certainty=certainty,
                result=result,
                error=error,
                **timestamps,
            )
            self._write_record(updated, evidence)
            return updated

    def mark_dispatched(self, attempt_id: str) -> AttemptRecord:
        return self._evolve(
            attempt_id,
            Stage.DISPATCHED,
            Certainty.EFFECT_POSSIBLE,
            Result.RECONCILIATION_REQUIRED,
            None,
            "dispatch-authorized",
            dispatched_unix_ms=self._clock_ms(),
        )

    def append_trace(self, attempt_id: str, trace: HookTraceRecord) -> AttemptRecord:
        with self._lock, self._transaction():
            current = self._load_attempt(attempt_id)
            if current is None:
                raise KeyError("operation attempt not found")
            if current.stage is Stage.SETTLED:
                raise JournalConflictError("settled attempt cannot accept another hook trace")
            expected_sequence = len(current.hook_traces) + 1
            if trace.sequence != expected_sequence:
                raise JournalConflictError("hook trace sequence is not contiguous")
            if (
                trace.identity != current.identity
                or trace.operation_id != current.operation_id
                or trace.attempt_id != current.attempt_id
                or trace.stage != current.stage
                or trace.certainty != current.certainty
            ):
                raise JournalConflictError("hook trace identity or effect evidence differs")
            updated = current.evolve(hook_traces=(*current.hook_traces, trace))
            self._write_record(updated, f"hook-trace-{trace.sequence}")
            return updated

    def settle(
        self,
        attempt_id: str,
        certainty: Certainty,
        result: Result,
        error: Optional[SafeFailure] = None,
    ) -> AttemptRecord:
        return self._evolve(
            attempt_id,
            Stage.SETTLED,
            certainty,
            result,
            error,
            "result-durable",
            settled_unix_ms=self._clock_ms(),
        )

    def reconcile(
        self,
        attempt_id: str,
        certainty: Certainty,
        error: Optional[SafeFailure],
    ) -> AttemptRecord:
        if certainty not in {Certainty.EFFECT_POSSIBLE, Certainty.EFFECT_UNKNOWN}:
            raise ValueError("reconciling certainty must remain possible or unknown")
        return self._evolve(
            attempt_id,
            Stage.RECONCILING,
            certainty,
            Result.RECONCILIATION_REQUIRED,
            error,
            "reconciliation-required",
        )

    def list_attempts_chronologically(self) -> Tuple[AttemptRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT attempt_id FROM operation_attempts
                 ORDER BY json_extract(record_json, '$.accepted_unix_ms'), operation_id, attempt_number
                """
            ).fetchall()
            attempts = tuple(self._load_attempt(row["attempt_id"]) for row in rows)
            if any(item is None for item in attempts):
                raise JournalIntegrityError("operation attempt disappeared")
            return tuple(item for item in attempts if item is not None)

    def retirement_witness(
        self,
        *,
        fenced_generation: str,
        canonical_operation_ids: set[str],
    ) -> str:
        """Authorize later secure removal without deleting evidence here."""

        with self._lock:
            registered = {
                row[0]
                for row in self._connection.execute(
                    "SELECT driver_host_generation FROM journal_generations"
                ).fetchall()
            }
            if fenced_generation not in registered:
                raise JournalConflictError("fenced generation is not registered")
            if fenced_generation == self.generation:
                raise JournalConflictError("the active host generation cannot retire")
            operations = tuple(
                operation
                for operation in self.list_operations()
                if any(
                    attempt.identity.driver_host_generation == fenced_generation
                    for attempt in operation.attempts
                )
            )
            if any(
                any(
                    attempt.identity.driver_host_generation != fenced_generation
                    for attempt in operation.attempts
                )
                for operation in operations
            ):
                raise JournalConflictError("one operation crosses host generations")
            actual_ids = {item.operation_id for item in operations}
            if actual_ids != canonical_operation_ids:
                raise JournalConflictError("canonical operation set does not cover the journal")
            for operation in operations:
                current = operation.attempts[-1]
                settled = current.stage is Stage.SETTLED
                latched = current.stage is Stage.RECONCILING and current.certainty in {
                    Certainty.EFFECT_POSSIBLE,
                    Certainty.EFFECT_UNKNOWN,
                }
                if not settled and not latched:
                    raise JournalConflictError("accepted work is not settled or durably latched")
            payload = {
                "schema_version": SCHEMA_VERSION,
                "driver_host_generation": fenced_generation,
                "operation_ids": sorted(actual_ids),
            }
            return _checksum(_canonical_json(payload))

    def get_operation(self, operation_id: str) -> OperationRecord:
        with self._lock:
            rows = self._connection.execute(
                "SELECT attempt_id FROM operation_attempts WHERE operation_id = ? ORDER BY attempt_number",
                (operation_id,),
            ).fetchall()
            if not rows:
                raise KeyError("operation not found")
            attempts = tuple(self._load_attempt(row["attempt_id"]) for row in rows)
            if any(item is None for item in attempts):
                raise JournalIntegrityError("operation attempt disappeared")
            typed_attempts = tuple(item for item in attempts if item is not None)
            current = typed_attempts[-1]
            return OperationRecord(
                operation_id=operation_id,
                method=current.method,
                identity=current.identity,
                current_attempt_id=current.attempt_id,
                attempts=typed_attempts,
            )

    def get_attempt(self, attempt_id: str) -> Optional[AttemptRecord]:
        with self._lock:
            return self._load_attempt(attempt_id)

    def list_operations(self) -> Tuple[OperationRecord, ...]:
        with self._lock:
            ids = tuple(
                row[0]
                for row in self._connection.execute(
                    "SELECT DISTINCT operation_id FROM operation_attempts ORDER BY operation_id"
                ).fetchall()
            )
            return tuple(self.get_operation(operation_id) for operation_id in ids)

    def verify(self) -> None:
        with self._lock:
            quick_check = self._connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick_check != "ok":
                raise JournalIntegrityError("SQLite journal integrity check failed")
            if self._connection.execute("PRAGMA foreign_key_check").fetchall():
                raise JournalIntegrityError("journal foreign-key integrity check failed")
            rows = self._connection.execute(
                "SELECT attempt_id, record_json, record_checksum FROM operation_attempts"
            ).fetchall()
            generations = {
                row[0]
                for row in self._connection.execute(
                    "SELECT driver_host_generation FROM journal_generations"
                ).fetchall()
            }
            if self.generation not in generations:
                raise JournalIntegrityError("active journal generation is not registered")
            records: dict[str, AttemptRecord] = {}
            for row in rows:
                if _checksum(row["record_json"]) != row["record_checksum"]:
                    raise JournalIntegrityError("attempt checksum mismatch")
                try:
                    parsed = _attempt_from_dict(json.loads(row["record_json"]))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise JournalIntegrityError("attempt record is malformed") from exc
                if parsed.attempt_id != row["attempt_id"]:
                    raise JournalIntegrityError("attempt row identity differs from its record")
                if parsed.identity.driver_host_generation not in generations:
                    raise JournalIntegrityError("attempt references an unknown host generation")
                records[parsed.attempt_id] = parsed
            transitions = self._connection.execute(
                """
                SELECT attempt_id, sequence, stage, certainty, result, evidence,
                       occurred_unix_ms, transition_checksum
                  FROM operation_transitions
                 ORDER BY attempt_id, sequence
                """
            ).fetchall()
            expected: dict[str, int] = {}
            last: dict[str, tuple[Stage, Optional[Certainty], Result]] = {}
            prior: dict[str, tuple[Stage, Optional[Certainty]]] = {}
            for row in transitions:
                sequence = expected.get(row["attempt_id"], 1)
                if row["sequence"] != sequence:
                    raise JournalIntegrityError("transition sequence is not contiguous")
                expected[row["attempt_id"]] = sequence + 1
                value = {
                    "attempt_id": row["attempt_id"],
                    "sequence": row["sequence"],
                    "stage": row["stage"],
                    "certainty": row["certainty"],
                    "result": row["result"],
                    "evidence": row["evidence"],
                    "occurred_unix_ms": row["occurred_unix_ms"],
                }
                if _checksum(_canonical_json(value)) != row["transition_checksum"]:
                    raise JournalIntegrityError("transition checksum mismatch")
                try:
                    stage = Stage(row["stage"])
                    certainty = Certainty(row["certainty"]) if row["certainty"] else None
                    result = Result(row["result"])
                except ValueError as exc:
                    raise JournalIntegrityError("transition enum value is invalid") from exc
                previous = prior.get(row["attempt_id"])
                if previous is not None:
                    previous_stage, previous_certainty = previous
                    if _STAGE_ORDER[stage] < _STAGE_ORDER[previous_stage]:
                        raise JournalIntegrityError("transition stage regresses")
                    if (
                        previous_certainty is Certainty.EFFECT_UNKNOWN
                        and certainty is Certainty.EFFECT_POSSIBLE
                    ):
                        raise JournalIntegrityError("transition certainty regresses")
                    if previous_stage is Stage.SETTLED and (
                        stage is not Stage.SETTLED or certainty != previous_certainty
                    ):
                        raise JournalIntegrityError("settled transition was rewritten")
                prior[row["attempt_id"]] = (stage, certainty)
                last[row["attempt_id"]] = (stage, certainty, result)
            if set(records) != set(last):
                raise JournalIntegrityError("attempt and transition cardinality differs")
            for attempt_id, record in records.items():
                if last[attempt_id] != (record.stage, record.certainty, record.result):
                    raise JournalIntegrityError("last transition differs from attempt projection")

    def close(self) -> None:
        with self._lock:
            self._connection.close()
