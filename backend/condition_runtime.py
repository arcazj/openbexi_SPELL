"""Standalone v0.7 condition runtime assembly.

This module adapts committed observation snapshots to the pure condition model,
resolves procedure observation envelopes, and runs restart reconciliation.  It
does not register routes, migrations, models, or supervisor callbacks.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from decimal import Decimal, ROUND_CEILING
from typing import Any, Callable, Mapping, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .condition_engine import (
    ConditionContractError,
    ConditionPlan,
    ConditionSnapshot,
    QualityFreshnessPolicy,
    SampleEvidence,
    ScalarType,
    TypedScalar,
    sample_id_for,
)
from .condition_models import (
    TelemetryConditionSchedule,
    VERIFY_TERMINAL_STATES,
    VerifyOperation,
    WAIT_TERMINAL_STATES,
    WaitForOperation,
)
from .condition_service import (
    ConditionService,
    ConditionServiceConflictError,
    ExecutionStarter,
)
from .ir_v07 import (
    REQUEST_SCHEMA_VERSION,
    canonicalize_observation_anchor,
    canonicalize_observation_result,
    unavailable_observation_result,
)
from .models import Execution
from .observation_repository import (
    ObservationClockError,
    ObservationConflictError,
    ObservationNotFoundError,
    ObservationRepositoryError,
    ObservationStaleGenerationError,
    ObservationValidationError,
)


MAX_SNAPSHOT_ITEMS = 128
MAX_CURSOR = 2**63 - 1
MAX_UINT64 = 2**64 - 1
MAX_RECOVERY_ERRORS = 32
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"0|[1-9][0-9]*\Z")


class ConditionRuntimeError(RuntimeError):
    pass


class ConditionRuntimeContractError(ConditionRuntimeError):
    pass


class ObservationSnapshotRepository(Protocol):
    def snapshot(self, context_id: str) -> Mapping[str, Any]: ...

    def replay(
        self,
        context_id: str,
        *,
        stream_epoch: str,
        after_sequence: int,
        limit: int,
    ) -> Mapping[str, Any]: ...


class ExecutionContextResolver(Protocol):
    def __call__(self, execution_id: str) -> str: ...


class GetTMResolver(Protocol):
    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class CancellationProbe(Protocol):
    def __call__(self, execution_id: str, worker_generation: int) -> bool: ...


class DurableExecutionCancellationProbe:
    """Read the authoritative execution state for a blocking observation call."""

    _CANCELLED_STATES = frozenset({"aborting", "aborted", "completed", "failed"})

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    def __call__(self, execution_id: str, worker_generation: int) -> bool:
        execution_id = _identifier(execution_id, "execution_id")
        if type(worker_generation) is not int or worker_generation <= 0:
            raise ConditionRuntimeContractError("worker_generation must be positive")
        with self.session_factory() as session:
            execution = session.execute(
                select(Execution.state, Execution.worker_generation).where(
                    Execution.id == execution_id
                )
            ).one_or_none()
        return (
            execution is None
            or execution.state in self._CANCELLED_STATES
            or execution.worker_generation != worker_generation
        )


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ConditionRuntimeContractError(
            f"{label} must be a bounded ASCII identifier"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ConditionRuntimeContractError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _cursor(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        number = int(value)
    else:
        raise ConditionRuntimeContractError(f"{label} must be a canonical cursor")
    if number < (1 if positive else 0) or number > MAX_CURSOR:
        raise ConditionRuntimeContractError(f"{label} is outside the cursor bound")
    return number


def _source_cursor(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        number = int(value)
    else:
        raise ConditionRuntimeContractError(f"{label} must be a canonical UINT64")
    if number < (1 if positive else 0) or number > MAX_UINT64:
        raise ConditionRuntimeContractError(f"{label} is outside the UINT64 bound")
    return number


def _detached_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConditionRuntimeContractError(f"{label} must be an object")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(encoded) > 1_000_000:
            raise ConditionRuntimeContractError(f"{label} exceeds the byte bound")
        return json.loads(encoded.decode("ascii"))
    except ConditionRuntimeContractError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise ConditionRuntimeContractError(f"{label} must be finite JSON data") from exc


class DurableOperationContextResolver:
    """Resolve a durable condition operation to its observation context."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        execution_context_resolver: ExecutionContextResolver,
    ) -> None:
        self.session_factory = session_factory
        self.execution_context_resolver = execution_context_resolver

    def __call__(self, operation_kind: str, operation_id: str) -> str:
        operation_kind = str(operation_kind).upper()
        _digest(operation_id, "operation_id")
        with self.session_factory() as session:
            if operation_kind == "VERIFY":
                row = session.get(VerifyOperation, operation_id)
                execution_id = row.request_scope if row is not None else None
                context_id = (
                    self.execution_context_resolver(execution_id)
                    if execution_id is not None
                    else None
                )
            elif operation_kind == "WAITFOR":
                row = session.get(WaitForOperation, operation_id)
                context_id = (
                    self.execution_context_resolver(row.execution_id)
                    if row is not None
                    else None
                )
            elif operation_kind == "SCHEDULE":
                row = session.get(TelemetryConditionSchedule, operation_id)
                context_id = row.context_id if row is not None else None
            else:
                raise ConditionRuntimeContractError("unsupported condition operation kind")
        if context_id is None:
            raise ConditionRuntimeContractError("durable condition operation is unavailable")
        return _identifier(context_id, "context_id")


class CommittedObservationSnapshotProvider:
    """Convert one committed repository snapshot into one atomic condition view."""

    def __init__(
        self,
        repository: ObservationSnapshotRepository,
        operation_context_resolver: Callable[[str, str], str],
        *,
        expected_policy_revision: str,
        maximum_clock_uncertainty_ns: int = 1_000_000_000,
    ) -> None:
        self.repository = repository
        self.operation_context_resolver = operation_context_resolver
        self.expected_policy_revision = _identifier(
            expected_policy_revision, "expected_policy_revision"
        )
        if (
            type(maximum_clock_uncertainty_ns) is not int
            or maximum_clock_uncertainty_ns < 0
        ):
            raise ConditionRuntimeContractError(
                "maximum_clock_uncertainty_ns must be nonnegative"
            )
        self.maximum_clock_uncertainty_ns = maximum_clock_uncertainty_ns

    def __call__(
        self,
        *,
        operation_kind: str,
        operation_id: str,
        condition_plan: ConditionPlan,
        after_snapshot_cursor: int,
    ) -> ConditionSnapshot:
        if not isinstance(condition_plan, ConditionPlan):
            raise ConditionRuntimeContractError("condition plan must be typed")
        context_id = self.operation_context_resolver(operation_kind, operation_id)
        return self.capture(context_id, after_snapshot_cursor=after_snapshot_cursor)

    def capture(
        self, context_id: str, *, after_snapshot_cursor: int = 0
    ) -> ConditionSnapshot:
        context_id = _identifier(context_id, "context_id")
        after_snapshot_cursor = _cursor(
            after_snapshot_cursor, "after_snapshot_cursor"
        )
        raw = _detached_mapping(self.repository.snapshot(context_id), "snapshot")
        required = {
            "schema_version",
            "stream",
            "stream_epoch",
            "through_sequence",
            "snapshot_at_database_time",
            "context_id",
            "context_generation_id",
            "source_epochs",
            "items",
            "driver_time",
            "synchronization_state",
        }
        if set(raw) != required:
            raise ConditionRuntimeContractError(
                "repository snapshot has an unknown or missing field"
            )
        if raw["schema_version"] != "spell.driver.observation.snapshot/1":
            raise ConditionRuntimeContractError("repository snapshot schema mismatch")
        if raw["stream"] != "driver.observation" or raw["context_id"] != context_id:
            raise ConditionRuntimeContractError("repository snapshot identity mismatch")
        _identifier(raw["stream_epoch"], "snapshot.stream_epoch")
        _identifier(raw["context_generation_id"], "snapshot.context_generation_id")
        cursor = _cursor(raw["through_sequence"], "snapshot.through_sequence")
        if cursor < after_snapshot_cursor:
            raise ConditionRuntimeContractError(
                "repository snapshot cursor regressed below durable progress"
            )
        items = raw["items"]
        if not isinstance(items, list) or len(items) > MAX_SNAPSHOT_ITEMS:
            raise ConditionRuntimeContractError("repository snapshot item bound exceeded")
        synchronization_state = raw["synchronization_state"]
        if synchronization_state not in {"COMPLETE", "GAPPED", "NO_SAMPLE"}:
            raise ConditionRuntimeContractError(
                "repository snapshot synchronization state is invalid"
            )
        clock_acceptable = self._clock_acceptable(raw["driver_time"])
        evidence: list[SampleEvidence] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ConditionRuntimeContractError(
                    f"snapshot.items[{index}] must be an object"
                )
            item_sync = item.get("synchronization_state")
            if item_sync not in {"COMPLETE", "GAPPED", "NO_SAMPLE"}:
                raise ConditionRuntimeContractError(
                    f"snapshot.items[{index}] synchronization state is invalid"
                )
            freshness = item.get("freshness")
            if item.get("freshness_policy_revision") != self.expected_policy_revision:
                freshness = "UNKNOWN"
            evidence.append(
                SampleEvidence(
                    sample_id=_digest(item.get("sample_id"), f"snapshot.items[{index}].sample_id"),
                    item_id=_identifier(item.get("item_id"), f"snapshot.items[{index}].item_id"),
                    catalog_digest=_digest(
                        item.get("catalog_digest"),
                        f"snapshot.items[{index}].catalog_digest",
                    ),
                    source_id=_identifier(
                        item.get("source_id"), f"snapshot.items[{index}].source_id"
                    ),
                    source_epoch=_identifier(
                        item.get("source_epoch"),
                        f"snapshot.items[{index}].source_epoch",
                    ),
                    source_sequence=_source_cursor(
                        item.get("source_sequence"),
                        f"snapshot.items[{index}].source_sequence",
                        positive=True,
                    ),
                    snapshot_cursor=cursor,
                    raw_value=TypedScalar.from_dict(
                        item.get("raw_value"), path=f"snapshot.items[{index}].raw_value"
                    ),
                    engineering_value=TypedScalar.from_dict(
                        item.get("engineering_value"),
                        path=f"snapshot.items[{index}].engineering_value",
                    ),
                    unit=item.get("unit"),
                    validity=item.get("validity"),
                    quality=item.get("quality"),
                    freshness=freshness,
                    synchronized=item_sync == "COMPLETE",
                    has_gap=item_sync == "GAPPED",
                    clock_acceptable=clock_acceptable,
                )
            )
        return ConditionSnapshot(
            snapshot_cursor=cursor,
            samples=tuple(evidence),
            synchronized=synchronization_state in {"COMPLETE", "NO_SAMPLE"},
            has_gap=synchronization_state == "GAPPED",
            clock_acceptable=clock_acceptable,
        )

    def _clock_acceptable(self, driver_time: Any) -> bool:
        if not isinstance(driver_time, dict):
            return False
        try:
            uncertainty = _cursor(
                driver_time.get("uncertainty_ns"), "driver_time.uncertainty_ns"
            )
        except ConditionRuntimeContractError:
            return False
        return (
            driver_time.get("validity") == "VALID"
            and driver_time.get("quality") == "GOOD"
            and uncertainty <= self.maximum_clock_uncertainty_ns
        )


class RepositoryGetTMResolver:
    """Resolve procedure GetTM solely from the committed observation projection."""

    def __init__(
        self,
        repository: ObservationSnapshotRepository,
        execution_context_resolver: ExecutionContextResolver,
        *,
        known_item_ids: frozenset[str] | None = None,
        poll_seconds: float = 0.05,
        replay_limit: int = 256,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time_ns: Callable[[], int] = time.time_ns,
        sleeper: Callable[[float], None] = time.sleep,
        cancellation_probe: CancellationProbe | None = None,
    ) -> None:
        if (
            type(poll_seconds) not in {int, float}
            or not math.isfinite(poll_seconds)
            or not 0 < poll_seconds <= 10
        ):
            raise ConditionRuntimeContractError(
                "GetTM poll interval must be positive and at most 10 seconds"
            )
        if type(replay_limit) is not int or not 1 <= replay_limit <= 1_000:
            raise ConditionRuntimeContractError("GetTM replay limit is invalid")
        if known_item_ids is not None:
            if not isinstance(known_item_ids, frozenset):
                raise ConditionRuntimeContractError("known_item_ids must be immutable")
            for item_id in known_item_ids:
                _identifier(item_id, "known_item_id")
        self.repository = repository
        self.execution_context_resolver = execution_context_resolver
        self.known_item_ids = known_item_ids
        self.poll_seconds = float(poll_seconds)
        self.replay_limit = replay_limit
        self._monotonic = monotonic
        self._wall_time_ns = wall_time_ns
        self._sleep = sleeper
        self.cancellation_probe = cancellation_probe

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            if request.get("operation") != "GET_TM":
                raise ConditionRuntimeContractError("resolver only accepts GET_TM")
            parameters = request.get("parameters")
            if not isinstance(parameters, Mapping) or set(parameters) != {
                "item_id",
                "scalar_type",
                "field",
                "mode",
                "timeout_seconds",
            }:
                raise ConditionRuntimeContractError("GET_TM parameters are invalid")
            item_id = _identifier(parameters["item_id"], "GET_TM item_id")
            if parameters["field"] not in {"RAW", "ENGINEERING"}:
                raise ConditionRuntimeContractError("GET_TM field is invalid")
            if parameters["scalar_type"] not in {"float", "int", "bool", "str"}:
                raise ConditionRuntimeContractError("GET_TM scalar type is invalid")
            if self.known_item_ids is not None and item_id not in self.known_item_ids:
                return self._failure("NOT_FOUND", "ITEM_NOT_FOUND")
            context_id = _identifier(
                self.execution_context_resolver(request["execution_id"]),
                "context_id",
            )
            if parameters["mode"] == "CURRENT":
                return self._current(request, context_id)
            if parameters["mode"] == "NEXT":
                return self._next(request, context_id)
            raise ConditionRuntimeContractError("GET_TM mode is invalid")
        except ObservationClockError:
            return self._failure("CLOCK_UNCERTAIN", "CLOCK_UNCERTAIN")
        except ObservationStaleGenerationError:
            return self._failure("STALE_GENERATION", "STALE_GENERATION")
        except ObservationNotFoundError:
            return self._failure("STALE_GENERATION", "CONTEXT_GENERATION_UNAVAILABLE")
        except (ObservationConflictError, ObservationValidationError):
            return self._failure("CONTRACT_MISMATCH", "PROJECTION_CONTRACT_MISMATCH")
        except ObservationRepositoryError:
            return self._failure("INTERNAL", "OBSERVATION_REPOSITORY_FAILED")
        except (ConditionRuntimeContractError, ConditionContractError):
            return self._failure("CONTRACT_MISMATCH", "GET_TM_CONTRACT_MISMATCH")
        except Exception:
            return self._failure("INTERNAL", "GET_TM_INTERNAL")

    def _current(
        self, request: Mapping[str, Any], context_id: str
    ) -> Mapping[str, Any]:
        snapshot = _detached_mapping(self.repository.snapshot(context_id), "snapshot")
        self._snapshot_identity(snapshot, context_id)
        item_id = request["parameters"]["item_id"]
        items = snapshot.get("items")
        if not isinstance(items, list) or len(items) > MAX_SNAPSHOT_ITEMS:
            raise ConditionRuntimeContractError("snapshot items are invalid")
        selected = next(
            (item for item in items if isinstance(item, dict) and item.get("item_id") == item_id),
            None,
        )
        if selected is None:
            return self._failure("NOT_AVAILABLE", "CURRENT_SAMPLE_UNAVAILABLE")
        return self._sample_result(
            request,
            selected,
            context_id=context_id,
            context_generation_id=snapshot["context_generation_id"],
            stream_epoch=snapshot["stream_epoch"],
            projection_sequence=_cursor(
                snapshot["through_sequence"], "snapshot.through_sequence"
            ),
            projection_time=snapshot.get("snapshot_at_database_time"),
            anchor=None,
        )

    def _next(
        self, request: Mapping[str, Any], context_id: str
    ) -> Mapping[str, Any]:
        anchor = request.get("anchor")
        if not isinstance(anchor, Mapping) or anchor.get("status") == "UNAVAILABLE":
            code = anchor.get("error_code") if isinstance(anchor, Mapping) else None
            return self._failure("NOT_AVAILABLE", code or "NEXT_ANCHOR_UNAVAILABLE")
        if anchor.get("context_id") != context_id:
            return self._failure("STALE_GENERATION", "CONTEXT_GENERATION_CHANGED")
        anchor_generation = _identifier(
            anchor.get("context_generation_id"), "anchor.context_generation_id"
        )
        stream_epoch = _identifier(anchor.get("stream_epoch"), "anchor.stream_epoch")
        item_id = request["parameters"]["item_id"]
        source_id = _identifier(anchor.get("source_id"), "anchor.source_id")
        source_epoch = _identifier(anchor.get("source_epoch"), "anchor.source_epoch")
        after_source_sequence = _source_cursor(
            anchor.get("source_sequence"), "anchor.source_sequence", positive=True
        )
        scan_cursor = _cursor(
            anchor.get("projection_sequence"), "anchor.projection_sequence"
        )
        timeout = request["parameters"]["timeout_seconds"]
        if (
            type(timeout) not in {int, float}
            or not math.isfinite(timeout)
            or not 0 < timeout <= 3_600
        ):
            raise ConditionRuntimeContractError("GET_TM timeout is invalid")
        requested_at_unix_ns = _source_cursor(
            request.get("requested_at_unix_ns"), "requested_at_unix_ns"
        )
        deadline_at_unix_ns = _source_cursor(
            request.get("deadline_at_unix_ns"), "deadline_at_unix_ns", positive=True
        )
        wall_now = self._wall_time_ns()
        if type(wall_now) is not int or wall_now < requested_at_unix_ns:
            return self._failure("CLOCK_UNCERTAIN", "GET_TM_DEADLINE_CLOCK_REGRESSED")
        if wall_now >= deadline_at_unix_ns:
            return self._deadline_failure(anchor, scan_cursor)
        deadline = self._monotonic() + (
            (deadline_at_unix_ns - wall_now) / 1_000_000_000
        )
        worker_generation: int | None = None
        if self.cancellation_probe is not None:
            worker_generation = request.get("resolver_generation")
            if type(worker_generation) is not int or worker_generation <= 0:
                raise ConditionRuntimeContractError(
                    "GET_TM resolver generation is invalid"
                )
        while True:
            stopped = self._next_boundary_failure(
                request,
                anchor,
                scan_cursor,
                requested_at_unix_ns=requested_at_unix_ns,
                deadline_at_unix_ns=deadline_at_unix_ns,
                monotonic_deadline=deadline,
                worker_generation=worker_generation,
            )
            if stopped is not None:
                return stopped
            fence = _detached_mapping(
                self.repository.snapshot(context_id), "NEXT generation fence"
            )
            stopped = self._next_boundary_failure(
                request,
                anchor,
                scan_cursor,
                requested_at_unix_ns=requested_at_unix_ns,
                deadline_at_unix_ns=deadline_at_unix_ns,
                monotonic_deadline=deadline,
                worker_generation=worker_generation,
            )
            if stopped is not None:
                return stopped
            self._snapshot_identity(fence, context_id)
            if fence["context_generation_id"] != anchor_generation:
                return self._failure(
                    "STALE_GENERATION", "CONTEXT_GENERATION_CHANGED"
                )
            if fence["stream_epoch"] != stream_epoch:
                return self._gap(anchor, "STREAM_EPOCH_CHANGED")
            replay = _detached_mapping(
                self.repository.replay(
                    context_id,
                    stream_epoch=stream_epoch,
                    after_sequence=scan_cursor,
                    limit=self.replay_limit,
                ),
                "observation replay",
            )
            stopped = self._next_boundary_failure(
                request,
                anchor,
                scan_cursor,
                requested_at_unix_ns=requested_at_unix_ns,
                deadline_at_unix_ns=deadline_at_unix_ns,
                monotonic_deadline=deadline,
                worker_generation=worker_generation,
            )
            if stopped is not None:
                return stopped
            if replay.get("stream_epoch") != stream_epoch or replay.get("epoch_matches") is not True:
                return self._gap(anchor, "STREAM_EPOCH_CHANGED")
            if replay.get("cursor_available") is not True:
                return self._gap(
                    anchor,
                    "PROJECTION_CURSOR_UNAVAILABLE",
                    {
                        "first_available_projection_sequence": replay.get(
                            "first_sequence"
                        ),
                        "last_available_projection_sequence": replay.get(
                            "last_sequence"
                        ),
                    },
                )
            events = replay.get("items")
            if not isinstance(events, list) or len(events) > self.replay_limit:
                raise ConditionRuntimeContractError("observation replay items are invalid")
            for event in events:
                if not isinstance(event, dict):
                    raise ConditionRuntimeContractError("observation event is invalid")
                event_cursor = _cursor(
                    event.get("projection_sequence"), "event.projection_sequence", positive=True
                )
                if event_cursor <= scan_cursor:
                    raise ConditionRuntimeContractError("observation replay did not advance")
                scan_cursor = event_cursor
                data = event.get("data")
                if not isinstance(data, dict) or data.get("item_id") != item_id:
                    continue
                if data.get("context_generation_id") != anchor_generation:
                    return self._failure(
                        "STALE_GENERATION", "CONTEXT_GENERATION_CHANGED"
                    )
                if event.get("event_type") == "telemetry.gap_detected":
                    if (
                        data.get("source_id") == source_id
                        and data.get("source_epoch") == source_epoch
                    ):
                        return self._gap(anchor, "SOURCE_SEQUENCE_GAP", data)
                    continue
                if event.get("event_type") != "telemetry.sample_observed":
                    continue
                if data.get("source_id") != source_id:
                    return self._gap(anchor, "SOURCE_ID_CHANGED", data)
                if data.get("source_epoch") != source_epoch:
                    return self._gap(anchor, "SOURCE_EPOCH_CHANGED", data)
                sequence = _source_cursor(
                    data.get("source_sequence"), "sample.source_sequence", positive=True
                )
                if sequence <= after_source_sequence:
                    continue
                if sequence != after_source_sequence + 1:
                    return self._gap(anchor, "SOURCE_SEQUENCE_GAP", data)
                sample_result = self._sample_result(
                    request,
                    data,
                    context_id=context_id,
                    context_generation_id=anchor_generation,
                    stream_epoch=stream_epoch,
                    projection_sequence=event_cursor,
                    projection_time=event.get("created_at"),
                    anchor=anchor,
                )
                stopped = self._next_boundary_failure(
                    request,
                    anchor,
                    scan_cursor,
                    requested_at_unix_ns=requested_at_unix_ns,
                    deadline_at_unix_ns=deadline_at_unix_ns,
                    monotonic_deadline=deadline,
                    worker_generation=worker_generation,
                )
                return stopped if stopped is not None else sample_result
            stopped = self._next_boundary_failure(
                request,
                anchor,
                scan_cursor,
                requested_at_unix_ns=requested_at_unix_ns,
                deadline_at_unix_ns=deadline_at_unix_ns,
                monotonic_deadline=deadline,
                worker_generation=worker_generation,
            )
            if stopped is not None:
                return stopped
            now = self._monotonic()
            remaining = deadline - now
            if remaining <= 0:
                return self._deadline_failure(anchor, scan_cursor)
            self._sleep(min(self.poll_seconds, remaining))

    def _next_boundary_failure(
        self,
        request: Mapping[str, Any],
        anchor: Mapping[str, Any],
        scan_cursor: int,
        *,
        requested_at_unix_ns: int,
        deadline_at_unix_ns: int,
        monotonic_deadline: float,
        worker_generation: int | None,
    ) -> Mapping[str, Any] | None:
        def clock_failure() -> Mapping[str, Any] | None:
            wall_now = self._wall_time_ns()
            monotonic_now = self._monotonic()
            if type(wall_now) is not int or wall_now < requested_at_unix_ns:
                return self._failure(
                    "CLOCK_UNCERTAIN", "GET_TM_DEADLINE_CLOCK_REGRESSED"
                )
            if monotonic_now >= monotonic_deadline or wall_now >= deadline_at_unix_ns:
                return self._deadline_failure(anchor, scan_cursor)
            return None

        stopped = clock_failure()
        if stopped is not None:
            return stopped
        if self.cancellation_probe is not None:
            if worker_generation is None:
                raise ConditionRuntimeContractError(
                    "GET_TM resolver generation is invalid"
                )
            if self.cancellation_probe(request["execution_id"], worker_generation):
                return self._failure("CANCELLED", "GET_TM_CANCELLED")
            # The durable generation probe may block long enough to consume the
            # remaining request budget, so deadline-check it before any read wins.
            return clock_failure()
        return None

    @classmethod
    def _deadline_failure(
        cls, anchor: Mapping[str, Any], scan_cursor: int
    ) -> Mapping[str, Any]:
        return cls._failure(
            "DEADLINE_EXCEEDED",
            "GET_TM_DEADLINE_EXCEEDED",
            evidence={
                "anchor": dict(anchor),
                "last_scanned_projection_sequence": str(scan_cursor),
            },
        )

    @staticmethod
    def _snapshot_identity(snapshot: Mapping[str, Any], context_id: str) -> None:
        if (
            snapshot.get("schema_version") != "spell.driver.observation.snapshot/1"
            or snapshot.get("stream") != "driver.observation"
            or snapshot.get("context_id") != context_id
        ):
            raise ConditionRuntimeContractError("snapshot identity is invalid")
        _identifier(snapshot.get("context_generation_id"), "snapshot.context_generation_id")
        _identifier(snapshot.get("stream_epoch"), "snapshot.stream_epoch")

    def _sample_result(
        self,
        request: Mapping[str, Any],
        sample: Mapping[str, Any],
        *,
        context_id: str,
        context_generation_id: str,
        stream_epoch: str,
        projection_sequence: int,
        projection_time: Any,
        anchor: Mapping[str, Any] | None,
    ) -> Mapping[str, Any]:
        parameters = request["parameters"]
        if sample.get("context_generation_id") != context_generation_id:
            return self._failure("STALE_GENERATION", "CONTEXT_GENERATION_CHANGED")
        item_id = _identifier(sample.get("item_id"), "sample.item_id")
        if item_id != parameters["item_id"]:
            raise ConditionRuntimeContractError("sample item identity mismatch")
        source_id = _identifier(sample.get("source_id"), "sample.source_id")
        source_epoch = _identifier(sample.get("source_epoch"), "sample.source_epoch")
        source_sequence = _source_cursor(
            sample.get("source_sequence"), "sample.source_sequence", positive=True
        )
        sample_id = _digest(sample.get("sample_id"), "sample.sample_id")
        if sample_id != sample_id_for(source_id, source_epoch, item_id, source_sequence):
            raise ConditionRuntimeContractError("sample identity digest mismatch")
        raw = TypedScalar.from_dict(sample.get("raw_value"), path="sample.raw_value")
        engineering = TypedScalar.from_dict(
            sample.get("engineering_value"), path="sample.engineering_value"
        )
        selected = raw if parameters["field"] == "RAW" else engineering
        accepted_types = {
            "float": frozenset({ScalarType.FINITE_DOUBLE}),
            "int": frozenset({ScalarType.INT64, ScalarType.UINT64}),
            "bool": frozenset({ScalarType.BOOLEAN}),
            "str": frozenset({ScalarType.STRING}),
        }.get(parameters["scalar_type"])
        if accepted_types is None or selected.scalar_type not in accepted_types:
            return self._failure(
                "CONTRACT_MISMATCH",
                "SCALAR_TYPE_MISMATCH",
                evidence={
                    "item_id": item_id,
                    "sample_id": sample_id,
                    "declared_scalar_type": parameters["scalar_type"],
                    "observed_scalar_type": selected.scalar_type.value,
                },
            )
        catalog_digest = _digest(sample.get("catalog_digest"), "sample.catalog_digest")
        synchronization_state = sample.get("synchronization_state")
        if synchronization_state not in {"COMPLETE", "GAPPED", "NO_SAMPLE"}:
            raise ConditionRuntimeContractError("sample synchronization state is invalid")
        evidence: dict[str, Any] = {
            "mode": parameters["mode"],
            "field": parameters["field"],
            "declared_scalar_type": parameters["scalar_type"],
            "context_id": context_id,
            "context_generation_id": context_generation_id,
            "stream_epoch": stream_epoch,
            "projection_sequence": str(projection_sequence),
            "projection_time": projection_time,
            "sample_id": sample_id,
            "observation_id": sample.get("observation_id"),
            "item_id": item_id,
            "qualified_name": sample.get("qualified_name"),
            "catalog_digest": catalog_digest,
            "source_id": source_id,
            "source_epoch": source_epoch,
            "source_sequence": str(source_sequence),
            "raw_value": raw.as_dict(),
            "engineering_value": engineering.as_dict(),
            "selected_value": selected.as_dict(),
            "description": sample.get("description"),
            "unit": sample.get("unit"),
            "acquired_at_unix_ns": sample.get("acquired_at_unix_ns"),
            "received_at_unix_ns": sample.get("received_at_unix_ns"),
            "received_at": sample.get("received_at"),
            "source": sample.get("source"),
            "clock_provenance": sample.get("clock_provenance"),
            "clock_uncertainty_ns": sample.get("clock_uncertainty_ns"),
            "validity": sample.get("validity"),
            "quality": sample.get("quality"),
            "quality_reason": sample.get("quality_reason"),
            "freshness": sample.get("freshness"),
            "freshness_policy_revision": sample.get("freshness_policy_revision"),
            "synchronization_state": synchronization_state,
        }
        if anchor is not None:
            evidence["anchor"] = dict(anchor)
        return {"outcome": "OK", "value": selected.value, "evidence": evidence}

    @staticmethod
    def _failure(
        outcome: str,
        error_code: str,
        *,
        evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "outcome": outcome,
            "error_code": error_code,
            "error_message": "committed telemetry read did not produce a value",
        }
        if evidence is not None:
            result["evidence"] = dict(evidence)
        return result

    @classmethod
    def _gap(
        cls,
        anchor: Mapping[str, Any],
        reason: str,
        observed: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {"anchor": dict(anchor), "reason": reason}
        if observed is not None:
            evidence["observed"] = dict(observed)
        return cls._failure("GAP", "OBSERVATION_GAP", evidence=evidence)


class ConditionRecoveryLoop:
    """Small stoppable loop that reconciles durable unfinished operations."""

    def __init__(
        self,
        service: ConditionService,
        *,
        interval_seconds: float = 0.25,
        batch_limit: int = 100,
    ) -> None:
        if (
            type(interval_seconds) not in {int, float}
            or not math.isfinite(interval_seconds)
            or interval_seconds < 0.01
            or interval_seconds > 60
        ):
            raise ConditionRuntimeContractError(
                "recovery interval must be between 0.01 and 60 seconds"
            )
        if type(batch_limit) is not int or not 1 <= batch_limit <= 500:
            raise ConditionRuntimeContractError("recovery batch limit is invalid")
        self.service = service
        self.interval_seconds = float(interval_seconds)
        self.batch_limit = batch_limit
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._settled = 0
        self._error_count = 0
        self._last_error_code: str | None = None
        self.execution_lifecycle = (
            ConditionExecutionLifecycle(service)
            if hasattr(service, "session_factory")
            else None
        )

    def reconcile_once(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        error_codes: list[str] = []
        if self.execution_lifecycle is not None:
            try:
                self.execution_lifecycle.reconcile_execution_states(
                    limit=self.batch_limit
                )
            except Exception:
                error_codes.append("EXECUTION_LIFECYCLE_RECOVERY_FAILED")
        for name, callback in (
            ("verifies", self.service.recover_verifies),
            ("waits", self.service.recover_waits),
            ("schedules", self.service.recover_telemetry_schedules),
        ):
            try:
                results = callback(limit=self.batch_limit)
                counts[name] = len(results)
            except Exception:
                counts[name] = 0
                error_codes.append(f"{name.upper()}_RECOVERY_FAILED")
        with self._lock:
            self._cycles += 1
            self._settled += sum(counts.values())
            self._error_count = min(
                MAX_RECOVERY_ERRORS, self._error_count + len(error_codes)
            )
            if error_codes:
                self._last_error_code = error_codes[-1]
        return counts

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="spell-condition-recovery",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        with self._lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self._cycles,
                "reconciled_operations": self._settled,
                "bounded_error_count": self._error_count,
                "last_error_code": self._last_error_code,
            }

    def _run(self) -> None:
        while not self._stop.is_set():
            self.reconcile_once()
            self._stop.wait(self.interval_seconds)


class ConditionExecutionLifecycle:
    """Apply execution pause/resume/abort to its durable condition operations."""

    def __init__(self, service: ConditionService) -> None:
        if not hasattr(service, "session_factory"):
            raise ConditionRuntimeContractError(
                "condition service does not expose durable sessions"
            )
        self.service = service
        self.session_factory = service.session_factory

    def interrupt_execution(self, execution_id: str) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        wait_ids = self._wait_ids(execution_id, {"CREATED", "WAITING"})
        waits = [
            self._apply_wait(wait_id, {"CREATED", "WAITING"}, "interrupt_wait")
            for wait_id in wait_ids
        ]
        return self._result(execution_id, "INTERRUPT", waits, [])

    def resume_execution(self, execution_id: str) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        wait_ids = self._wait_ids(execution_id, {"INTERRUPTED"})
        waits = [
            self._apply_wait(wait_id, {"INTERRUPTED"}, "resume_wait")
            for wait_id in wait_ids
        ]
        return self._result(execution_id, "RESUME", waits, [])

    def cancel_execution(self, execution_id: str) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        wait_ids = self._wait_ids(
            execution_id,
            {
                "CREATED",
                "WAITING",
                "INTERRUPTED",
            },
        )
        verify_ids = self._verify_ids(execution_id)
        waits = [
            self._apply_wait(
                wait_id,
                {"CREATED", "WAITING", "INTERRUPTED"},
                "cancel_wait",
            )
            for wait_id in wait_ids
        ]
        verifies = [self._cancel_verify(verify_id) for verify_id in verify_ids]
        return self._result(execution_id, "CANCEL", waits, verifies)

    def reconcile_execution_states(self, *, limit: int = 100) -> int:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ConditionRuntimeContractError(
                "execution lifecycle limit must be 1 through 500"
            )
        with self.session_factory() as session:
            wait_execution_ids = session.scalars(
                select(WaitForOperation.execution_id)
                .where(WaitForOperation.state.not_in(tuple(WAIT_TERMINAL_STATES)))
                .distinct()
                .limit(limit)
            ).all()
            remaining = max(0, limit - len(wait_execution_ids))
            verify_scopes = (
                session.scalars(
                    select(VerifyOperation.request_scope)
                    .where(
                        VerifyOperation.state.not_in(
                            tuple(VERIFY_TERMINAL_STATES)
                        )
                    )
                    .distinct()
                    .limit(remaining)
                ).all()
                if remaining
                else []
            )
            execution_ids = sorted(set(wait_execution_ids) | set(verify_scopes))[
                :limit
            ]
            states = {
                execution_id: state
                for execution_id, state in session.execute(
                    select(Execution.id, Execution.state).where(
                        Execution.id.in_(execution_ids)
                    )
                ).all()
            }
        reconciled = 0
        for execution_id in execution_ids:
            state = states.get(execution_id)
            if state in {"completed", "aborted", "failed"}:
                reconciled += self.cancel_execution(execution_id)["affected_count"]
            elif state in {"paused", "pausing", "recovery_required"}:
                reconciled += self.interrupt_execution(execution_id)[
                    "affected_count"
                ]
            elif state in {
                "starting",
                "running",
                "resuming",
                "recovering",
                "waiting",
                "prompting",
            }:
                reconciled += self.resume_execution(execution_id)["affected_count"]
        return reconciled

    def _wait_ids(self, execution_id: str, states: set[str]) -> list[str]:
        with self.session_factory() as session:
            return list(
                session.scalars(
                    select(WaitForOperation.id)
                    .where(
                        WaitForOperation.execution_id == execution_id,
                        WaitForOperation.state.in_(tuple(sorted(states))),
                    )
                    .order_by(WaitForOperation.created_at, WaitForOperation.id)
                ).all()
            )

    def _verify_ids(self, execution_id: str) -> list[str]:
        with self.session_factory() as session:
            return list(
                session.scalars(
                    select(VerifyOperation.id)
                    .where(
                        VerifyOperation.request_scope == execution_id,
                        VerifyOperation.state.not_in(tuple(VERIFY_TERMINAL_STATES)),
                    )
                    .order_by(VerifyOperation.created_at, VerifyOperation.id)
                ).all()
            )

    def _apply_wait(
        self, wait_id: str, actionable_states: set[str], method_name: str
    ) -> dict[str, Any]:
        for _attempt in range(32):
            current = self.service.get_wait(wait_id)
            if current["state"] in WAIT_TERMINAL_STATES:
                return current
            if current["state"] not in actionable_states:
                return current
            try:
                return getattr(self.service, method_name)(
                    wait_id, expected_revision=current["revision"]
                )
            except ConditionServiceConflictError:
                continue
        raise ConditionRuntimeError("WaitFor lifecycle CAS did not converge")

    def _cancel_verify(self, verify_id: str) -> dict[str, Any]:
        for _attempt in range(32):
            current = self.service.get_verify(verify_id)
            if current["state"] in VERIFY_TERMINAL_STATES:
                return current
            try:
                return self.service.cancel_verify(
                    verify_id, expected_revision=current["revision"]
                )
            except ConditionServiceConflictError:
                continue
        raise ConditionRuntimeError("Verify lifecycle CAS did not converge")

    @staticmethod
    def _result(
        execution_id: str,
        action: str,
        waits: list[dict[str, Any]],
        verifies: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "execution_id": execution_id,
            "action": action,
            "waits": waits,
            "verifies": verifies,
            "affected_count": len(waits) + len(verifies),
        }


class ConditionProcedureRuntime:
    """Resolve canonical ``ir_v07`` observation requests through durability."""

    def __init__(
        self,
        service: ConditionService,
        *,
        policy: QualityFreshnessPolicy,
        get_tm_resolver: GetTMResolver | None = None,
        wait_retry_interval_seconds: float = 0.25,
        resolver_poll_seconds: float = 0.05,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(policy, QualityFreshnessPolicy):
            raise ConditionRuntimeContractError("runtime policy must be pinned and typed")
        for value, label in (
            (wait_retry_interval_seconds, "wait retry interval"),
            (resolver_poll_seconds, "resolver poll interval"),
        ):
            if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
                raise ConditionRuntimeContractError(f"{label} must be finite and nonnegative")
        self.service = service
        self.policy = policy
        self.get_tm_resolver = get_tm_resolver
        self.wait_retry_interval_seconds = float(wait_retry_interval_seconds)
        self.resolver_poll_seconds = float(resolver_poll_seconds)
        self._sleep = sleeper

    def interrupt_execution(self, execution_id: str) -> dict[str, Any]:
        return ConditionExecutionLifecycle(self.service).interrupt_execution(execution_id)

    def resume_execution(self, execution_id: str) -> dict[str, Any]:
        return ConditionExecutionLifecycle(self.service).resume_execution(execution_id)

    def cancel_execution(self, execution_id: str) -> dict[str, Any]:
        return ConditionExecutionLifecycle(self.service).cancel_execution(execution_id)

    def resolve(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        canonical = self._request(request)
        operation = canonical["operation"]
        try:
            if operation == "GET_TM":
                raw = self._resolve_get_tm(canonical)
            elif operation == "VERIFY":
                raw = self._resolve_verify(canonical)
            else:
                raw = self._resolve_wait(canonical)
            return canonicalize_observation_result(canonical, raw)
        except Exception:
            return unavailable_observation_result(
                canonical, "CONDITION_RUNTIME_RESOLUTION_FAILED"
            )

    @staticmethod
    def _request(request: Mapping[str, Any]) -> dict[str, Any]:
        result = _detached_mapping(request, "observation request")
        base = {
            "schema_version",
            "request_id",
            "execution_id",
            "step_index",
            "operation",
            "parameters",
        }
        optional = {
            "anchor",
            "requested_at_unix_ns",
            "deadline_at_unix_ns",
            "request_digest",
            "resolver_generation",
        }
        if set(result) - base - optional or not base <= set(result):
            raise ConditionRuntimeContractError("observation request fields are invalid")
        if result["schema_version"] != REQUEST_SCHEMA_VERSION:
            raise ConditionRuntimeContractError("observation request schema mismatch")
        _identifier(result["request_id"], "request_id")
        _identifier(result["execution_id"], "execution_id")
        if type(result["step_index"]) is not int or result["step_index"] < 0:
            raise ConditionRuntimeContractError("step_index is invalid")
        if result["operation"] not in {"GET_TM", "VERIFY", "WAIT_FOR"}:
            raise ConditionRuntimeContractError("observation operation is invalid")
        if not isinstance(result["parameters"], dict):
            raise ConditionRuntimeContractError("observation parameters must be an object")
        anchored_fields = {
            "anchor",
            "requested_at_unix_ns",
            "deadline_at_unix_ns",
            "request_digest",
        }
        anchored = bool(anchored_fields & set(result))
        if anchored and not anchored_fields <= set(result):
            raise ConditionRuntimeContractError(
                "observation anchor, deadline, and request digest must be present together"
            )
        if anchored:
            if (
                result["operation"] != "GET_TM"
                or result["parameters"].get("mode") != "NEXT"
            ):
                raise ConditionRuntimeContractError("only GET_TM NEXT may carry an anchor")
            base = {
                key: value
                for key, value in result.items()
                if key not in {"anchor", "request_digest", "resolver_generation"}
            }
            resolver_generation = result.get("resolver_generation")
            if resolver_generation is not None and (
                type(resolver_generation) is not int or resolver_generation <= 0
            ):
                raise ConditionRuntimeContractError(
                    "observation resolver generation is invalid"
                )
            raw_anchor = result["anchor"]
            context_id = (
                raw_anchor.get("context_id")
                if isinstance(raw_anchor, dict) and raw_anchor.get("status") != "UNAVAILABLE"
                else "unavailable"
            )
            try:
                canonical_anchor = canonicalize_observation_anchor(
                    base, context_id, raw_anchor
                )
            except Exception as exc:
                raise ConditionRuntimeContractError(
                    "observation anchor is invalid"
                ) from exc
            anchored_request = {**base, "anchor": canonical_anchor}
            requested_at = _source_cursor(
                result["requested_at_unix_ns"], "requested_at_unix_ns"
            )
            deadline_at = _source_cursor(
                result["deadline_at_unix_ns"], "deadline_at_unix_ns", positive=True
            )
            timeout_ns = int(
                (
                    Decimal(str(result["parameters"]["timeout_seconds"]))
                    * Decimal(1_000_000_000)
                ).to_integral_value(rounding=ROUND_CEILING)
            )
            if deadline_at - requested_at != timeout_ns:
                raise ConditionRuntimeContractError(
                    "observation deadline does not match the request timeout"
                )
            expected_digest = hashlib.sha256(
                json.dumps(
                    anchored_request,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
            ).hexdigest()
            if result["request_digest"] != expected_digest:
                raise ConditionRuntimeContractError(
                    "observation request digest does not bind its anchor"
                )
        return result

    def _resolve_get_tm(self, request: dict[str, Any]) -> Mapping[str, Any]:
        if self.get_tm_resolver is None:
            return unavailable_observation_result(
                request, "GET_TM_RESOLVER_UNAVAILABLE"
            )
        result = self.get_tm_resolver(request)
        if not isinstance(result, Mapping):
            raise ConditionRuntimeContractError("GET_TM resolver returned no mapping")
        return result

    def _resolve_verify(self, request: dict[str, Any]) -> dict[str, Any]:
        parameters = request["parameters"]
        if set(parameters) != {
            "condition",
            "delay_seconds",
            "timeout_seconds",
            "retry_count",
            "retry_interval_seconds",
        }:
            raise ConditionRuntimeContractError("VERIFY parameters are invalid")
        plan = ConditionPlan.from_dict(parameters["condition"])
        result = self.service.verify(
            plan=plan,
            policy=self.policy,
            delay_seconds=parameters["delay_seconds"],
            timeout_seconds=parameters["timeout_seconds"],
            retry_count=parameters["retry_count"],
            retry_interval_seconds=parameters["retry_interval_seconds"],
            start_snapshot_cursor=0,
            request_scope=request["execution_id"],
            idempotency_key=request["request_id"],
        )
        result = self._drive(
            result,
            terminal={
                "TRUE",
                "FALSE",
                "INDETERMINATE",
                "TIMED_OUT",
                "CANCELLED",
                "REJECTED",
                "FAILED",
            },
            reconcile=lambda: self.service.reconcile_verify(result["verify_id"]),
        )
        state = result["state"]
        outcome = state if state != "FAILED" else "REJECTED"
        raw: dict[str, Any] = {
            "outcome": outcome,
            "evidence": self._verify_evidence(result),
        }
        if state == "FAILED":
            raw.update(
                error_code="VERIFY_RUNTIME_FAILED",
                error_message="durable Verify could not be evaluated",
            )
        return raw

    def _resolve_wait(self, request: dict[str, Any]) -> dict[str, Any]:
        parameters = request["parameters"]
        target_fields = {"seconds", "at", "condition"} & set(parameters)
        if len(target_fields) != 1:
            raise ConditionRuntimeContractError("WAIT_FOR target is invalid")
        plan: ConditionPlan | None = None
        policy: QualityFreshnessPolicy | None = None
        timeout: Any = None
        if "seconds" in parameters and set(parameters) == {"seconds"}:
            wait_type = "RELATIVE"
            target = parameters["seconds"]
            retry_count = 0
            retry_interval = 0
        elif "at" in parameters and set(parameters) == {"at"}:
            wait_type = "ABSOLUTE"
            target = parameters["at"]
            retry_count = 0
            retry_interval = 0
        elif "condition" in parameters and set(parameters) == {
            "condition",
            "timeout_seconds",
        }:
            wait_type = "TELEMETRY_CONDITION"
            target = None
            timeout = parameters["timeout_seconds"]
            plan = ConditionPlan.from_dict(parameters["condition"])
            policy = self.policy
            retry_count, retry_interval = self._wait_retry_budget(timeout)
        else:
            raise ConditionRuntimeContractError("WAIT_FOR parameters are invalid")
        result = self.service.create_wait(
            execution_id=request["execution_id"],
            statement_id=f"statement-{request['step_index']}",
            wait_type=wait_type,
            target=target,
            idempotency_key=request["request_id"],
            plan=plan,
            policy=policy,
            start_snapshot_cursor=0,
            timeout_seconds=timeout,
            retry_count=retry_count,
            retry_interval_seconds=retry_interval,
        )
        wait_id = result["wait_id"]
        result = self._drive(
            result,
            terminal={"SATISFIED", "TIMED_OUT", "CANCELLED", "FAILED"},
            reconcile=lambda: self.service.reconcile_wait(wait_id),
        )
        raw: dict[str, Any] = {
            "outcome": result["state"],
            "evidence": self._wait_evidence(result),
        }
        if result["state"] == "FAILED":
            raw.update(
                error_code="WAITFOR_RUNTIME_FAILED",
                error_message="durable WaitFor could not be evaluated",
            )
        return raw

    def _wait_retry_budget(self, timeout: Any) -> tuple[int, Decimal]:
        seconds = Decimal(str(timeout))
        if not seconds.is_finite() or seconds <= 0:
            raise ConditionRuntimeContractError("WAIT_FOR timeout is invalid")
        timeout_ns = seconds * Decimal(1_000_000_000)
        if timeout_ns != timeout_ns.to_integral_value():
            raise ConditionRuntimeContractError(
                "WAIT_FOR timeout exceeds nanosecond precision"
            )
        if self.wait_retry_interval_seconds == 0:
            return 1_000, Decimal(0)
        configured = Decimal(str(self.wait_retry_interval_seconds))
        configured_ns = configured * Decimal(1_000_000_000)
        if configured_ns != configured_ns.to_integral_value():
            raise ConditionRuntimeContractError(
                "WAIT_FOR polling interval exceeds nanosecond precision"
            )
        minimum_ns = (timeout_ns / Decimal(1_001)).to_integral_value(
            rounding=ROUND_CEILING
        )
        interval_ns = max(configured_ns, minimum_ns)
        attempts = min(
            1_001,
            max(
                1,
                int((timeout_ns / interval_ns).to_integral_value(rounding=ROUND_CEILING)),
            ),
        )
        return attempts - 1, interval_ns / Decimal(1_000_000_000)

    def _drive(
        self,
        result: dict[str, Any],
        *,
        terminal: set[str],
        reconcile: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        while result.get("state") not in terminal:
            self._sleep(self.resolver_poll_seconds)
            result = reconcile()
        return result

    @staticmethod
    def _verify_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: result.get(key)
            for key in (
                "verify_id",
                "revision",
                "condition_plan_id",
                "condition_plan_digest",
                "quality_freshness_policy_id",
                "quality_freshness_policy_revision",
                "attempt_count",
                "start_snapshot_cursor",
                "last_snapshot_cursor",
                "deadline_at_database_time",
                "last_evaluation_id",
                "final_result",
                "failure_code",
            )
        }

    @staticmethod
    def _wait_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: result.get(key)
            for key in (
                "wait_id",
                "revision",
                "wait_type",
                "original_target",
                "canonical_target",
                "condition_plan_id",
                "condition_plan_digest",
                "quality_freshness_policy_id",
                "quality_freshness_policy_revision",
                "attempt_count",
                "start_snapshot_cursor",
                "last_snapshot_cursor",
                "deadline_at_database_time",
                "last_evaluation_id",
                "terminal_evaluation_id",
                "terminal_result",
                "failure_code",
            )
        }


class OccurrenceBoundExecutionStarter:
    """Normalize an occurrence-idempotent execution creator for ConditionService."""

    def __init__(self, create_or_find: ExecutionStarter) -> None:
        if not callable(create_or_find):
            raise ConditionRuntimeContractError("execution creator must be callable")
        self.create_or_find = create_or_find

    def __call__(
        self,
        *,
        occurrence_id: str,
        schedule: Mapping[str, Any],
        condition_evidence: Mapping[str, Any],
    ) -> Any:
        _digest(occurrence_id, "occurrence_id")
        if schedule.get("occurrence_id") != occurrence_id:
            raise ConditionRuntimeContractError("schedule occurrence identity mismatch")
        if condition_evidence.get("composite_result") != "TRUE":
            raise ConditionRuntimeContractError(
                "schedule execution requires committed TRUE evidence"
            )
        return self.create_or_find(
            occurrence_id=occurrence_id,
            schedule=_detached_mapping(schedule, "schedule"),
            condition_evidence=_detached_mapping(
                condition_evidence, "condition evidence"
            ),
        )


__all__ = [
    "CancellationProbe",
    "CommittedObservationSnapshotProvider",
    "ConditionProcedureRuntime",
    "ConditionExecutionLifecycle",
    "ConditionRecoveryLoop",
    "ConditionRuntimeContractError",
    "ConditionRuntimeError",
    "DurableExecutionCancellationProbe",
    "DurableOperationContextResolver",
    "ExecutionContextResolver",
    "GetTMResolver",
    "ObservationSnapshotRepository",
    "OccurrenceBoundExecutionStarter",
    "RepositoryGetTMResolver",
]
