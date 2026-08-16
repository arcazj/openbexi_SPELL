"""Durable v0.7 Verify, WaitFor, and telemetry-condition scheduling.

The service has no browser, driver, worker, or operator-service dependency.  A
snapshot provider supplies one committed ``ConditionSnapshot`` per attempt and
the occurrence-bound execution starter is responsible for idempotently creating
or finding an execution for the supplied occurrence identifier.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping, Protocol

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from .condition_engine import (
    ConditionEvaluation,
    ConditionPlan,
    ConditionSnapshot,
    QualityFreshnessPolicy,
    TruthValue,
    evaluate_condition,
)
from .condition_models import (
    ConditionEvaluationRecord,
    ConditionEvaluationSample,
    ConditionPlanRecord,
    SCHEDULE_TERMINAL_STATES,
    TelemetryConditionSchedule,
    TelemetryScheduleOccurrence,
    VERIFY_TERMINAL_STATES,
    VerifyOperation,
    WAIT_TERMINAL_STATES,
    WaitForOperation,
)


MAX_TIMEOUT_SECONDS = Decimal(604_800)
MAX_WAIT_SECONDS = Decimal(31_536_000)
MAX_RETRIES = 1_000
MAX_RECOVERY_BATCH = 500
MAX_JSON_BYTES = 65_536
MAX_JSON_DEPTH = 8
MAX_JSON_ITEMS = 1_024
MAX_DISPATCH_ATTEMPTS = 32
MAX_MONOTONIC_NS = (1 << 63) - 1

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_SECRET_KEYS = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "clientsecret",
        "credential",
        "password",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "token",
    }
)


class ConditionServiceError(RuntimeError):
    pass


class ConditionServiceValidationError(ConditionServiceError):
    pass


class ConditionServiceConflictError(ConditionServiceError):
    pass


class ConditionServiceNotFoundError(ConditionServiceError):
    pass


class _ClockCorrelationError(ConditionServiceError):
    pass


class SnapshotProvider(Protocol):
    def __call__(
        self,
        *,
        operation_kind: str,
        operation_id: str,
        condition_plan: ConditionPlan,
        after_snapshot_cursor: int,
    ) -> ConditionSnapshot: ...


class ExecutionStarter(Protocol):
    def __call__(
        self,
        *,
        occurrence_id: str,
        schedule: Mapping[str, Any],
        condition_evidence: Mapping[str, Any],
    ) -> str | Mapping[str, Any] | object: ...


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ConditionServiceValidationError(f"{label} must be a bounded ASCII identifier")
    return value


def _idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise ConditionServiceValidationError("idempotency_key is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ConditionServiceValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _duration_ns(
    value: Any,
    label: str,
    *,
    maximum: Decimal = MAX_TIMEOUT_SECONDS,
) -> int:
    if isinstance(value, bool) or type(value) not in {str, int, float, Decimal}:
        raise ConditionServiceValidationError(f"{label} must be a bounded duration")
    try:
        seconds = Decimal(str(value))
    except InvalidOperation as exc:
        raise ConditionServiceValidationError(f"{label} is not a duration") from exc
    if not seconds.is_finite() or seconds < 0 or seconds > maximum:
        raise ConditionServiceValidationError(f"{label} is outside its bound")
    nanoseconds = seconds * Decimal(1_000_000_000)
    if nanoseconds != nanoseconds.to_integral_value():
        raise ConditionServiceValidationError(f"{label} exceeds nanosecond precision")
    return int(nanoseconds)


def _add_ns(value: datetime, nanoseconds: int) -> datetime:
    # Database timestamps are microsecond precision. Ceiling avoids an early deadline.
    return value + timedelta(microseconds=(nanoseconds + 999) // 1_000)


def _datetime_delta_ns(later: datetime, earlier: datetime) -> int:
    delta = _utc(later) - _utc(earlier)
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _checked_monotonic_add(value: int, nanoseconds: int) -> int:
    result = value + nanoseconds
    if result > MAX_MONOTONIC_NS:
        raise _ClockCorrelationError("monotonic deadline exceeds the durable integer bound")
    return result


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return _utc(value).isoformat().replace("+00:00", "Z") if value is not None else None


def _derive_monotonic_epoch() -> str:
    configured = os.getenv("SPELL_MONOTONIC_EPOCH", "").strip()
    if configured:
        return configured
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as handle:
            boot_id = handle.read().strip()
        if boot_id:
            return boot_id
    except (OSError, UnicodeError):
        pass
    estimated_boot_decasecond = (time.time_ns() - time.monotonic_ns()) // 10_000_000_000
    return hashlib.sha256(
        f"{os.name}:{estimated_boot_decasecond}".encode("ascii")
    ).hexdigest()


_DEFAULT_MONOTONIC_EPOCH = _derive_monotonic_epoch()


def _default_monotonic_epoch() -> str:
    return _DEFAULT_MONOTONIC_EPOCH


def _parse_absolute(value: Any, now: datetime) -> tuple[str, datetime]:
    if not isinstance(value, str) or _ABSOLUTE_TIME.fullmatch(value) is None:
        raise ConditionServiceValidationError(
            "absolute target must be RFC 3339 with an explicit UTC offset"
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ConditionServiceValidationError("absolute target is invalid") from exc
    target = parsed.astimezone(timezone.utc)
    fraction = re.search(r"\.(\d+)", value)
    if fraction and len(fraction.group(1)) > 6 and any(
        digit != "0" for digit in fraction.group(1)[6:]
    ):
        target += timedelta(microseconds=1)
    if abs((target - now).total_seconds()) > float(MAX_WAIT_SECONDS):
        raise ConditionServiceValidationError("absolute target is outside the one-year bound")
    return target.isoformat().replace("+00:00", "Z"), target


def _validate_json(value: Any, *, path: str = "arguments") -> Any:
    item_count = 0

    def walk(item: Any, depth: int, current: str) -> Any:
        nonlocal item_count
        if depth > MAX_JSON_DEPTH:
            raise ConditionServiceValidationError(f"{current} exceeds the depth bound")
        item_count += 1
        if item_count > MAX_JSON_ITEMS:
            raise ConditionServiceValidationError(f"{path} exceeds the item bound")
        if item is None or type(item) in {bool, int}:
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise ConditionServiceValidationError(f"{current} must be finite")
            return item
        if isinstance(item, str):
            if len(item.encode("utf-8")) > 4_096:
                raise ConditionServiceValidationError(f"{current} exceeds the text bound")
            return item
        if isinstance(item, list):
            return [walk(child, depth + 1, f"{current}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 128:
                    raise ConditionServiceValidationError(f"{current} has an invalid key")
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if normalized in _SECRET_KEYS:
                    raise ConditionServiceValidationError(
                        "secret material is not accepted in schedule arguments"
                    )
                result[key] = walk(child, depth + 1, f"{current}.{key}")
            return result
        raise ConditionServiceValidationError(f"{current} is not a JSON literal")

    normalized = walk(value, 0, path)
    encoded = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ConditionServiceValidationError(f"{path} exceeds the encoded byte bound")
    return normalized


@dataclass(frozen=True)
class _ClockReading:
    database_time: datetime
    monotonic_ns: int
    monotonic_epoch: str


@dataclass(frozen=True)
class _StoredEvaluation:
    record: ConditionEvaluationRecord
    result: dict[str, Any]
    clock: _ClockReading
    snapshot_clock: _ClockReading


class ConditionService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        snapshot_provider: SnapshotProvider,
        execution_starter: ExecutionStarter | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        monotonic_epoch_provider: Callable[[], str] = _default_monotonic_epoch,
    ) -> None:
        self.session_factory = session_factory
        self.snapshot_provider = snapshot_provider
        self.execution_starter = execution_starter
        self._monotonic_ns = monotonic_ns
        self._monotonic_epoch_provider = monotonic_epoch_provider
        self._lock = threading.RLock()

    @staticmethod
    def _database_now(session: Session) -> datetime:
        clock = (
            func.clock_timestamp()
            if session.get_bind().dialect.name == "postgresql"
            else func.current_timestamp()
        )
        value = session.execute(select(clock)).scalar_one()
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        return _utc(value)

    def _clock_reading(self, session: Session) -> _ClockReading:
        database_time = self._database_now(session)
        monotonic_ns = self._monotonic_ns()
        monotonic_epoch = self._monotonic_epoch_provider()
        if type(monotonic_ns) is not int or not 0 <= monotonic_ns <= MAX_MONOTONIC_NS:
            raise _ClockCorrelationError("monotonic clock returned an invalid value")
        if (
            not isinstance(monotonic_epoch, str)
            or not 1 <= len(monotonic_epoch) <= 128
            or not monotonic_epoch.isascii()
            or any(ord(character) < 33 or ord(character) > 126 for character in monotonic_epoch)
        ):
            raise _ClockCorrelationError("monotonic epoch provider returned an invalid value")
        return _ClockReading(database_time, monotonic_ns, monotonic_epoch)

    @staticmethod
    def _clock_failure_time(row: Any) -> datetime:
        candidates = [
            _utc(value)
            for value in (
                row.created_at,
                row.updated_at,
                row.clock_anchor_database_time,
            )
            if value is not None
        ]
        return max(candidates)

    @staticmethod
    def _new_clock_fields(
        clock: _ClockReading, deadline_at: datetime
    ) -> dict[str, Any]:
        remaining_ns = max(0, _datetime_delta_ns(deadline_at, clock.database_time))
        return {
            "deadline_monotonic_ns": _checked_monotonic_add(
                clock.monotonic_ns, remaining_ns
            ),
            "clock_anchor_monotonic_ns": clock.monotonic_ns,
            "clock_anchor_database_time": clock.database_time,
            "monotonic_epoch": clock.monotonic_epoch,
        }

    @staticmethod
    def _validate_clock_correlation(row: Any, clock: _ClockReading) -> None:
        if (
            type(row.deadline_monotonic_ns) is not int
            or type(row.clock_anchor_monotonic_ns) is not int
            or not 0 <= row.clock_anchor_monotonic_ns <= row.deadline_monotonic_ns
            or row.deadline_monotonic_ns > MAX_MONOTONIC_NS
            or not isinstance(row.monotonic_epoch, str)
            or not 1 <= len(row.monotonic_epoch) <= 128
            or not row.monotonic_epoch.isascii()
        ):
            raise _ClockCorrelationError("persisted clock correlation is invalid")
        last_database_time = max(
            _utc(row.created_at),
            _utc(row.updated_at),
            _utc(row.clock_anchor_database_time),
        )
        if clock.database_time < last_database_time:
            raise _ClockCorrelationError("database clock regressed")
        if (
            clock.monotonic_epoch == row.monotonic_epoch
            and clock.monotonic_ns < row.clock_anchor_monotonic_ns
        ):
            raise _ClockCorrelationError("monotonic clock regressed within its epoch")

    def _synchronize_clock(
        self,
        session: Session,
        model: Any,
        row: Any,
        clock: _ClockReading,
        *,
        allowed_states: set[str],
    ) -> Any:
        self._validate_clock_correlation(row, clock)
        if clock.monotonic_epoch == row.monotonic_epoch:
            return row
        clock_fields = self._new_clock_fields(clock, _utc(row.deadline_at))
        row = self._cas_progress(
            session,
            model,
            row,
            allowed_states=allowed_states,
            values={**clock_fields, "updated_at": clock.database_time},
        )
        if row.monotonic_epoch != clock.monotonic_epoch:
            raise _ClockCorrelationError("monotonic epoch rebase lost its durable race")
        return row

    @staticmethod
    def _deadline_reached(row: Any, clock: _ClockReading) -> bool:
        if clock.monotonic_epoch != row.monotonic_epoch:
            raise _ClockCorrelationError("deadline checked against an uncorrelated epoch")
        return clock.monotonic_ns >= row.deadline_monotonic_ns

    @staticmethod
    def _target_reached(row: Any, target: datetime, clock: _ClockReading) -> bool:
        if clock.monotonic_epoch != row.monotonic_epoch:
            raise _ClockCorrelationError("retry checked against an uncorrelated epoch")
        offset_ns = max(
            0,
            _datetime_delta_ns(target, _utc(row.clock_anchor_database_time)),
        )
        target_monotonic_ns = _checked_monotonic_add(
            row.clock_anchor_monotonic_ns, offset_ns
        )
        return clock.monotonic_ns >= target_monotonic_ns

    @staticmethod
    def _next_attempt_clock_values(
        row: Any, clock: _ClockReading, requested_delay_ns: int
    ) -> dict[str, Any]:
        remaining_ns = max(0, row.deadline_monotonic_ns - clock.monotonic_ns)
        delay_ns = min(requested_delay_ns, remaining_ns)
        return {
            "next_attempt_at": _add_ns(clock.database_time, delay_ns),
            "clock_anchor_monotonic_ns": clock.monotonic_ns,
            "clock_anchor_database_time": clock.database_time,
            "monotonic_epoch": clock.monotonic_epoch,
            "updated_at": clock.database_time,
        }

    @staticmethod
    def _validate_policy(policy: QualityFreshnessPolicy) -> QualityFreshnessPolicy:
        if not isinstance(policy, QualityFreshnessPolicy):
            raise ConditionServiceValidationError("policy must be a pinned typed policy")
        return policy

    def _register_plan(
        self, session: Session, plan: ConditionPlan, now: datetime
    ) -> ConditionPlanRecord:
        if not isinstance(plan, ConditionPlan):
            raise ConditionServiceValidationError("plan must be a validated ConditionPlan")
        existing = session.get(ConditionPlanRecord, plan.condition_plan_id)
        if existing is not None:
            if (
                existing.plan_digest != plan.condition_plan_digest
                or existing.canonical_plan != plan.as_dict()
            ):
                raise ConditionServiceConflictError(
                    "ConditionPlanId already binds a different immutable plan"
                )
            return existing
        digest_owner = session.scalar(
            select(ConditionPlanRecord).where(
                ConditionPlanRecord.plan_digest == plan.condition_plan_digest
            )
        )
        if digest_owner is not None and digest_owner.id != plan.condition_plan_id:
            raise ConditionServiceConflictError(
                "ConditionPlanDigest already binds a different ConditionPlanId"
            )
        record = ConditionPlanRecord(
            id=plan.condition_plan_id,
            plan_digest=plan.condition_plan_digest,
            schema_version="spell.v07.condition-plan/1",
            canonical_plan=plan.as_dict(),
            created_at=now,
        )
        session.add(record)
        session.flush()
        return record

    def register_plan(self, plan: ConditionPlan) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            now = self._database_now(session)
            record = self._register_plan(session, plan, now)
            session.commit()
            return self._plan_dict(record)

    def get_plan(self, condition_plan_id: str) -> dict[str, Any]:
        condition_plan_id = _identifier(condition_plan_id, "condition_plan_id")
        with self.session_factory() as session:
            record = session.get(ConditionPlanRecord, condition_plan_id)
            if record is None:
                raise ConditionServiceNotFoundError("condition plan not found")
            return self._plan_dict(record)

    @staticmethod
    def _plan_dict(record: ConditionPlanRecord) -> dict[str, Any]:
        return {
            "condition_plan_id": record.id,
            "condition_plan_digest": record.plan_digest,
            "schema_version": record.schema_version,
            "canonical_plan": dict(record.canonical_plan),
            "created_at_database_time": _iso(record.created_at),
        }

    @staticmethod
    def _load_plan(record: ConditionPlanRecord) -> ConditionPlan:
        plan = ConditionPlan.from_dict(record.canonical_plan)
        if plan.condition_plan_digest != record.plan_digest:
            raise ConditionServiceConflictError("stored condition plan digest mismatch")
        return plan

    def _evaluate_attempt(
        self,
        session: Session,
        *,
        operation_kind: str,
        operation_id: str,
        attempt_number: int,
        plan_record: ConditionPlanRecord,
        policy: QualityFreshnessPolicy,
        after_snapshot_cursor: int,
        not_before_clock: _ClockReading,
    ) -> _StoredEvaluation:
        evaluation_id = _canonical_digest(
            {
                "operation_kind": operation_kind,
                "operation_id": operation_id,
                "attempt_number": attempt_number,
                "condition_plan_digest": plan_record.plan_digest,
                "policy_id": policy.policy_id,
                "policy_revision": policy.policy_revision,
            }
        )
        existing = session.get(ConditionEvaluationRecord, evaluation_id)
        if existing is not None:
            clock = self._clock_reading(session)
            if (
                clock.database_time < _utc(existing.settled_at)
                or clock.database_time < not_before_clock.database_time
                or (
                    clock.monotonic_epoch == not_before_clock.monotonic_epoch
                    and clock.monotonic_ns < not_before_clock.monotonic_ns
                )
            ):
                raise _ClockCorrelationError(
                    "clock correlation regressed while replaying an evaluation"
                )
            return _StoredEvaluation(
                existing, self._evaluation_payload(existing), clock, clock
            )
        plan = self._load_plan(plan_record)
        started = self._database_now(session)
        if started < not_before_clock.database_time:
            raise _ClockCorrelationError("database clock regressed before evaluation")
        snapshot = self.snapshot_provider(
            operation_kind=operation_kind,
            operation_id=operation_id,
            condition_plan=plan,
            after_snapshot_cursor=after_snapshot_cursor,
        )
        if not isinstance(snapshot, ConditionSnapshot):
            raise ConditionServiceValidationError(
                "snapshot_provider must return ConditionSnapshot"
            )
        if snapshot.snapshot_cursor < after_snapshot_cursor:
            raise ConditionServiceConflictError(
                "snapshot cursor regressed below the durable operation cursor"
            )
        snapshot_clock = self._clock_reading(session)
        if (
            snapshot_clock.database_time < started
            or snapshot_clock.database_time < not_before_clock.database_time
            or (
                snapshot_clock.monotonic_epoch == not_before_clock.monotonic_epoch
                and snapshot_clock.monotonic_ns < not_before_clock.monotonic_ns
            )
        ):
            raise _ClockCorrelationError(
                "clock correlation regressed while acquiring a snapshot"
            )
        result = evaluate_condition(plan, snapshot, policy)
        settled_clock = self._clock_reading(session)
        if (
            settled_clock.database_time < started
            or settled_clock.database_time < not_before_clock.database_time
            or (
                settled_clock.monotonic_epoch == not_before_clock.monotonic_epoch
                and settled_clock.monotonic_ns < not_before_clock.monotonic_ns
            )
        ):
            raise _ClockCorrelationError("clock correlation regressed during evaluation")
        record = ConditionEvaluationRecord(
            id=evaluation_id,
            plan_id=plan.condition_plan_id,
            plan_digest=plan.condition_plan_digest,
            policy_id=policy.policy_id,
            policy_revision=policy.policy_revision,
            operation_kind=operation_kind,
            operation_id=operation_id,
            attempt_number=attempt_number,
            snapshot_cursor=result.snapshot_cursor,
            composite_result=result.composite_result.value,
            leaf_results=[leaf.as_dict() for leaf in result.leaf_results],
            consumed_sample_ids=list(result.consumed_sample_ids),
            reason=result.reason,
            result_digest=result.result_digest,
            started_at=started,
            settled_at=settled_clock.database_time,
        )
        session.add(record)
        for ordinal, sample_id in enumerate(result.consumed_sample_ids):
            session.add(
                ConditionEvaluationSample(
                    evaluation_id=evaluation_id,
                    ordinal=ordinal,
                    sample_id=sample_id,
                )
            )
        session.flush()
        return _StoredEvaluation(
            record, self._evaluation_payload(record), settled_clock, snapshot_clock
        )

    @staticmethod
    def _evaluation_payload(record: ConditionEvaluationRecord) -> dict[str, Any]:
        return {
            "schema_version": "spell.v07.condition-attempt-result/1",
            "condition_plan_id": record.plan_id,
            "condition_plan_digest": record.plan_digest,
            "quality_freshness_policy_id": record.policy_id,
            "quality_freshness_policy_revision": record.policy_revision,
            "snapshot_cursor": str(record.snapshot_cursor),
            "composite_result": record.composite_result,
            "leaf_results": list(record.leaf_results),
            "consumed_sample_ids": list(record.consumed_sample_ids),
            "reason": record.reason,
            "result_digest": record.result_digest,
            "attempt_number": record.attempt_number,
            "started_at_database_time": _iso(record.started_at),
            "settled_at_database_time": _iso(record.settled_at),
        }

    @staticmethod
    def _policy_from_row(row: Any) -> QualityFreshnessPolicy:
        return QualityFreshnessPolicy(row.policy_id, row.policy_revision)

    @staticmethod
    def _cas_progress(
        session: Session,
        model: Any,
        row: Any,
        *,
        allowed_states: set[str],
        values: dict[str, Any],
    ) -> Any:
        expected_revision = row.revision
        with session.no_autoflush:
            claimed = session.execute(
                update(model)
                .where(
                    model.id == row.id,
                    model.revision == expected_revision,
                    model.state.in_(tuple(allowed_states)),
                )
                .values(revision=expected_revision + 1, **values)
            )
        row_id = row.id
        if claimed.rowcount != 1:
            session.rollback()
        else:
            session.expire(row)
            session.commit()
        session.expire_all()
        winner = session.get(model, row_id)
        if winner is None:
            raise ConditionServiceNotFoundError("durable operation disappeared")
        return winner

    def verify(
        self,
        *,
        plan: ConditionPlan,
        policy: QualityFreshnessPolicy,
        delay_seconds: str | int | float | Decimal = 0,
        timeout_seconds: str | int | float | Decimal = 0,
        retry_count: int = 0,
        retry_interval_seconds: str | int | float | Decimal = 0,
        start_snapshot_cursor: int = 0,
        request_scope: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        policy = self._validate_policy(policy)
        request_scope = _identifier(request_scope, "request_scope")
        idempotency_key = _idempotency_key(idempotency_key)
        delay_ns = _duration_ns(delay_seconds, "delay_seconds")
        timeout_ns = _duration_ns(timeout_seconds, "timeout_seconds")
        retry_interval_ns = _duration_ns(
            retry_interval_seconds, "retry_interval_seconds"
        )
        if type(retry_count) is not int or not 0 <= retry_count <= MAX_RETRIES:
            raise ConditionServiceValidationError("retry_count is outside its bound")
        if type(start_snapshot_cursor) is not int or start_snapshot_cursor < 0:
            raise ConditionServiceValidationError("start_snapshot_cursor must be nonnegative")
        request = {
            "condition_plan_id": plan.condition_plan_id,
            "condition_plan_digest": plan.condition_plan_digest,
            "quality_freshness_policy_id": policy.policy_id,
            "quality_freshness_policy_revision": policy.policy_revision,
            "delay_ns": delay_ns,
            "timeout_ns": timeout_ns,
            "retry_count": retry_count,
            "retry_interval_ns": retry_interval_ns,
            "start_snapshot_cursor": start_snapshot_cursor,
            "request_scope": request_scope,
        }
        request_digest = _canonical_digest(request)
        operation_id = _canonical_digest(
            {"kind": "VERIFY", "scope": request_scope, "idempotency_key": idempotency_key}
        )
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(VerifyOperation).where(
                    VerifyOperation.request_scope == request_scope,
                    VerifyOperation.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise ConditionServiceConflictError(
                        "idempotency key was used for another Verify request"
                    )
                existing_id = existing.id
            else:
                clock = self._clock_reading(session)
                now = clock.database_time
                self._register_plan(session, plan, now)
                deadline = _add_ns(now, timeout_ns)
                row = VerifyOperation(
                    id=operation_id,
                    revision=0,
                    request_scope=request_scope,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    plan_id=plan.condition_plan_id,
                    plan_digest=plan.condition_plan_digest,
                    policy_id=policy.policy_id,
                    policy_revision=policy.policy_revision,
                    state="CREATED",
                    delay_ns=delay_ns,
                    timeout_ns=timeout_ns,
                    retry_count=retry_count,
                    retry_interval_ns=retry_interval_ns,
                    attempt_count=0,
                    start_snapshot_cursor=start_snapshot_cursor,
                    next_attempt_at=_add_ns(now, delay_ns),
                    deadline_at=deadline,
                    **self._new_clock_fields(clock, deadline),
                    final_result={},
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
                session.commit()
                existing_id = row.id
        return self.reconcile_verify(existing_id)

    def get_verify(self, verify_id: str) -> dict[str, Any]:
        verify_id = _digest(verify_id, "verify_id")
        with self.session_factory() as session:
            row = session.get(VerifyOperation, verify_id)
            if row is None:
                raise ConditionServiceNotFoundError("Verify operation not found")
            return self._verify_dict(row)

    def reconcile_verify(self, verify_id: str) -> dict[str, Any]:
        verify_id = _digest(verify_id, "verify_id")
        with self._lock, self.session_factory() as session:
            row = session.get(VerifyOperation, verify_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("Verify operation not found")
            if row.state in VERIFY_TERMINAL_STATES:
                return self._verify_dict(row)
            try:
                clock = self._clock_reading(session)
                row = self._synchronize_clock(
                    session,
                    VerifyOperation,
                    row,
                    clock,
                    allowed_states={"CREATED", "DELAYED", "RETRY_WAIT"},
                )
            except _ClockCorrelationError:
                session.rollback()
                row = session.get(VerifyOperation, verify_id, with_for_update=True)
                if row is None or row.state in VERIFY_TERMINAL_STATES:
                    return self._verify_dict(row) if row is not None else {}
                return self._settle_verify(
                    session,
                    row,
                    "FAILED",
                    self._clock_failure_time(row),
                    failure_code="CLOCK_CORRELATION_INVALID",
                )
            now = clock.database_time
            if self._deadline_reached(row, clock):
                return self._settle_verify(
                    session, row, "TIMED_OUT", now, failure_code="ORIGINAL_DEADLINE_REACHED"
                )
            if not self._target_reached(row, _utc(row.next_attempt_at), clock):
                wanted = "DELAYED" if row.attempt_count == 0 else "RETRY_WAIT"
                if row.state != wanted:
                    row = self._cas_progress(
                        session,
                        VerifyOperation,
                        row,
                        allowed_states={"CREATED", "DELAYED", "RETRY_WAIT"},
                        values={"state": wanted, "updated_at": now},
                    )
                return self._verify_dict(row)
            plan_record = session.get(ConditionPlanRecord, row.plan_id)
            if plan_record is None or plan_record.plan_digest != row.plan_digest:
                return self._settle_verify(
                    session, row, "FAILED", now, failure_code="PINNED_PLAN_MISSING"
                )
            try:
                stored = self._evaluate_attempt(
                    session,
                    operation_kind="VERIFY",
                    operation_id=row.id,
                    attempt_number=row.attempt_count + 1,
                    plan_record=plan_record,
                    policy=self._policy_from_row(row),
                    after_snapshot_cursor=(
                        row.last_snapshot_cursor
                        if row.last_snapshot_cursor is not None
                        else row.start_snapshot_cursor
                    ),
                    not_before_clock=clock,
                )
            except _ClockCorrelationError:
                session.rollback()
                row = session.get(VerifyOperation, verify_id, with_for_update=True)
                if row is None or row.state in VERIFY_TERMINAL_STATES:
                    return self._verify_dict(row) if row is not None else {}
                return self._settle_verify(
                    session,
                    row,
                    "FAILED",
                    self._clock_failure_time(row),
                    failure_code="CLOCK_CORRELATION_INVALID",
                )
            except Exception:
                session.rollback()
                row = session.get(VerifyOperation, verify_id, with_for_update=True)
                if row is None or row.state in VERIFY_TERMINAL_STATES:
                    return self._verify_dict(row) if row is not None else {}
                now = self._database_now(session)
                return self._settle_verify(
                    session, row, "FAILED", now, failure_code="SNAPSHOT_OR_EVALUATION_FAILED"
                )
            try:
                row = self._synchronize_clock(
                    session,
                    VerifyOperation,
                    row,
                    stored.clock,
                    allowed_states={"CREATED", "DELAYED", "RETRY_WAIT"},
                )
            except _ClockCorrelationError:
                session.rollback()
                row = session.get(VerifyOperation, verify_id, with_for_update=True)
                if row is None or row.state in VERIFY_TERMINAL_STATES:
                    return self._verify_dict(row) if row is not None else {}
                return self._settle_verify(
                    session,
                    row,
                    "FAILED",
                    self._clock_failure_time(row),
                    failure_code="CLOCK_CORRELATION_INVALID",
                )
            row.attempt_count += 1
            row.last_evaluation_id = stored.record.id
            row.last_snapshot_cursor = stored.record.snapshot_cursor
            result = stored.record.composite_result
            settled_at = _utc(stored.record.settled_at)
            if self._deadline_reached(row, stored.snapshot_clock):
                return self._settle_verify(
                    session,
                    row,
                    "TIMED_OUT",
                    settled_at,
                    evaluation=stored,
                    failure_code="ORIGINAL_DEADLINE_REACHED",
                )
            if result == "TRUE":
                return self._settle_verify(
                    session, row, "TRUE", settled_at, evaluation=stored
                )
            if result == "REJECTED":
                return self._settle_verify(
                    session,
                    row,
                    "REJECTED",
                    settled_at,
                    evaluation=stored,
                    failure_code="PLAN_REJECTED",
                )
            if row.attempt_count > row.retry_count:
                return self._settle_verify(
                    session, row, result, settled_at, evaluation=stored
                )
            row = self._cas_progress(
                session,
                VerifyOperation,
                row,
                allowed_states={"CREATED", "DELAYED", "RETRY_WAIT"},
                values={
                    "state": "RETRY_WAIT",
                    "attempt_count": row.attempt_count,
                    "last_evaluation_id": row.last_evaluation_id,
                    "last_snapshot_cursor": row.last_snapshot_cursor,
                    **self._next_attempt_clock_values(
                        row, stored.clock, row.retry_interval_ns
                    ),
                },
            )
            return self._verify_dict(row)

    def _settle_verify(
        self,
        session: Session,
        row: VerifyOperation,
        state: str,
        now: datetime,
        *,
        evaluation: _StoredEvaluation | None = None,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        expected_revision = row.revision
        final = {
            "state": state,
            "condition_plan_id": row.plan_id,
            "condition_plan_digest": row.plan_digest,
            "quality_freshness_policy_id": row.policy_id,
            "quality_freshness_policy_revision": row.policy_revision,
            "attempt_count": row.attempt_count,
            "started_at_database_time": _iso(row.created_at),
            "settled_at_database_time": _iso(now),
            "snapshot_cursor": str(
                row.last_snapshot_cursor
                if row.last_snapshot_cursor is not None
                else row.start_snapshot_cursor
            ),
            "evaluation": evaluation.result if evaluation else None,
            "failure_code": failure_code,
        }
        with session.no_autoflush:
            claimed = session.execute(
                update(VerifyOperation)
                .where(
                    VerifyOperation.id == row.id,
                    VerifyOperation.revision == expected_revision,
                    VerifyOperation.state.not_in(tuple(VERIFY_TERMINAL_STATES)),
                )
                .values(
                    state=state,
                    revision=expected_revision + 1,
                    attempt_count=row.attempt_count,
                    last_evaluation_id=row.last_evaluation_id,
                    last_snapshot_cursor=row.last_snapshot_cursor,
                    final_result=final,
                    failure_code=failure_code,
                    updated_at=now,
                    settled_at=now,
                )
            )
        if claimed.rowcount != 1:
            session.rollback()
        else:
            session.expire(row)
            session.commit()
        session.expire_all()
        winner = session.get(VerifyOperation, row.id)
        if winner is None:
            raise ConditionServiceNotFoundError("Verify operation disappeared")
        return self._verify_dict(winner)

    def cancel_verify(self, verify_id: str, *, expected_revision: int) -> dict[str, Any]:
        verify_id = _digest(verify_id, "verify_id")
        with self._lock, self.session_factory() as session:
            row = session.get(VerifyOperation, verify_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("Verify operation not found")
            if row.state in VERIFY_TERMINAL_STATES:
                return self._verify_dict(row)
            if row.revision != expected_revision:
                raise ConditionServiceConflictError("Verify revision conflict")
            return self._settle_verify(
                session, row, "CANCELLED", self._database_now(session), failure_code="CANCELLED"
            )

    @staticmethod
    def _verify_dict(row: VerifyOperation) -> dict[str, Any]:
        return {
            "verify_id": row.id,
            "revision": row.revision,
            "state": row.state,
            "condition_plan_id": row.plan_id,
            "condition_plan_digest": row.plan_digest,
            "quality_freshness_policy_id": row.policy_id,
            "quality_freshness_policy_revision": row.policy_revision,
            "delay_ns": row.delay_ns,
            "timeout_ns": row.timeout_ns,
            "retry_count": row.retry_count,
            "retry_interval_ns": row.retry_interval_ns,
            "attempt_count": row.attempt_count,
            "start_snapshot_cursor": str(row.start_snapshot_cursor),
            "last_snapshot_cursor": (
                str(row.last_snapshot_cursor)
                if row.last_snapshot_cursor is not None
                else None
            ),
            "next_attempt_at_database_time": _iso(row.next_attempt_at),
            "deadline_at_database_time": _iso(row.deadline_at),
            "last_evaluation_id": row.last_evaluation_id,
            "final_result": dict(row.final_result),
            "failure_code": row.failure_code,
            "created_at_database_time": _iso(row.created_at),
            "updated_at_database_time": _iso(row.updated_at),
            "settled_at_database_time": _iso(row.settled_at),
        }

    def create_wait(
        self,
        *,
        execution_id: str,
        statement_id: str,
        wait_type: str,
        target: str | int | float | Decimal | None,
        idempotency_key: str,
        plan: ConditionPlan | None = None,
        policy: QualityFreshnessPolicy | None = None,
        start_snapshot_cursor: int = 0,
        timeout_seconds: str | int | float | Decimal | None = None,
        retry_count: int = 0,
        retry_interval_seconds: str | int | float | Decimal = 0,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        statement_id = _identifier(statement_id, "statement_id")
        wait_type = _identifier(str(wait_type).upper(), "wait_type")
        if wait_type not in {"RELATIVE", "ABSOLUTE", "TELEMETRY_CONDITION"}:
            raise ConditionServiceValidationError("unsupported WaitFor type")
        idempotency_key = _idempotency_key(idempotency_key)
        if type(start_snapshot_cursor) is not int or start_snapshot_cursor < 0:
            raise ConditionServiceValidationError("start_snapshot_cursor must be nonnegative")
        if type(retry_count) is not int or not 0 <= retry_count <= MAX_RETRIES:
            raise ConditionServiceValidationError("retry_count is outside its bound")
        retry_interval_ns = _duration_ns(
            retry_interval_seconds, "retry_interval_seconds"
        )
        with self._lock, self.session_factory() as session:
            clock = self._clock_reading(session)
            now = clock.database_time
            condition_timeout_ns: int | None = None
            if wait_type == "RELATIVE":
                if plan is not None or policy is not None or timeout_seconds is not None:
                    raise ConditionServiceValidationError("RELATIVE wait cannot include condition fields")
                duration_ns = _duration_ns(target, "target", maximum=MAX_WAIT_SECONDS)
                original_target = {"duration_ns": duration_ns}
                deadline = _add_ns(now, duration_ns)
                canonical_target = _iso(deadline)
            elif wait_type == "ABSOLUTE":
                if plan is not None or policy is not None or timeout_seconds is not None:
                    raise ConditionServiceValidationError("ABSOLUTE wait cannot include condition fields")
                canonical_target, deadline = _parse_absolute(target, now)
                original_target = {"rfc3339": target}
            else:
                if target is not None:
                    raise ConditionServiceValidationError(
                        "TELEMETRY_CONDITION target is the immutable plan and must be omitted"
                    )
                if not isinstance(plan, ConditionPlan) or policy is None:
                    raise ConditionServiceValidationError(
                        "TELEMETRY_CONDITION requires a plan and pinned policy"
                    )
                policy = self._validate_policy(policy)
                if timeout_seconds is None:
                    raise ConditionServiceValidationError(
                        "TELEMETRY_CONDITION requires a bounded timeout"
                    )
                timeout_ns = _duration_ns(timeout_seconds, "timeout_seconds")
                condition_timeout_ns = timeout_ns
                original_target = {
                    "condition_plan_id": plan.condition_plan_id,
                    "condition_plan_digest": plan.condition_plan_digest,
                }
                deadline = _add_ns(now, timeout_ns)
                canonical_target = plan.condition_plan_digest
            request = {
                "execution_id": execution_id,
                "statement_id": statement_id,
                "wait_type": wait_type,
                "original_target": original_target,
                "condition_timeout_ns": condition_timeout_ns,
                "plan_digest": plan.condition_plan_digest if plan else None,
                "policy_id": policy.policy_id if policy else None,
                "policy_revision": policy.policy_revision if policy else None,
                "start_snapshot_cursor": start_snapshot_cursor,
                "retry_count": retry_count,
                "retry_interval_ns": retry_interval_ns,
            }
            request_digest = _canonical_digest(request)
            existing = session.scalar(
                select(WaitForOperation).where(
                    WaitForOperation.execution_id == execution_id,
                    WaitForOperation.statement_id == statement_id,
                    WaitForOperation.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise ConditionServiceConflictError(
                        "idempotency key was used for another WaitFor request"
                    )
                return self._wait_dict(existing)
            if plan is not None:
                self._register_plan(session, plan, now)
            wait_id = _canonical_digest(
                {
                    "kind": "WAITFOR",
                    "execution_id": execution_id,
                    "statement_id": statement_id,
                    "idempotency_key": idempotency_key,
                }
            )
            row = WaitForOperation(
                id=wait_id,
                revision=0,
                execution_id=execution_id,
                statement_id=statement_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                wait_type=wait_type,
                original_target=original_target,
                canonical_target=canonical_target,
                state="CREATED",
                plan_id=plan.condition_plan_id if plan else None,
                plan_digest=plan.condition_plan_digest if plan else None,
                policy_id=policy.policy_id if policy else None,
                policy_revision=policy.policy_revision if policy else None,
                start_snapshot_cursor=start_snapshot_cursor,
                retry_count=retry_count,
                retry_interval_ns=retry_interval_ns,
                attempt_count=0,
                next_attempt_at=now,
                deadline_at=deadline,
                **self._new_clock_fields(clock, deadline),
                terminal_result={},
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            return self._wait_dict(row)

    def get_wait(self, wait_id: str) -> dict[str, Any]:
        wait_id = _digest(wait_id, "wait_id")
        with self.session_factory() as session:
            row = session.get(WaitForOperation, wait_id)
            if row is None:
                raise ConditionServiceNotFoundError("WaitFor operation not found")
            return self._wait_dict(row)

    def reconcile_wait(self, wait_id: str) -> dict[str, Any]:
        wait_id = _digest(wait_id, "wait_id")
        with self._lock, self.session_factory() as session:
            row = session.get(WaitForOperation, wait_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("WaitFor operation not found")
            if row.state in WAIT_TERMINAL_STATES or row.state == "INTERRUPTED":
                return self._wait_dict(row)
            try:
                clock = self._clock_reading(session)
                row = self._synchronize_clock(
                    session,
                    WaitForOperation,
                    row,
                    clock,
                    allowed_states={"CREATED", "WAITING"},
                )
            except _ClockCorrelationError:
                session.rollback()
                row = session.get(WaitForOperation, wait_id, with_for_update=True)
                if row is None or row.state in WAIT_TERMINAL_STATES:
                    return self._wait_dict(row) if row is not None else {}
                return self._settle_wait(
                    session,
                    row,
                    "FAILED",
                    self._clock_failure_time(row),
                    failure_code="CLOCK_CORRELATION_INVALID",
                )
            now = clock.database_time
            if row.wait_type in {"RELATIVE", "ABSOLUTE"}:
                deadline_reached = (
                    now >= _utc(row.deadline_at)
                    if row.wait_type == "ABSOLUTE"
                    else self._deadline_reached(row, clock)
                )
                if deadline_reached:
                    return self._settle_wait(session, row, "SATISFIED", now)
                if row.state != "WAITING":
                    row = self._cas_progress(
                        session,
                        WaitForOperation,
                        row,
                        allowed_states={"CREATED", "WAITING"},
                        values={"state": "WAITING", "updated_at": now},
                    )
                return self._wait_dict(row)
            if self._deadline_reached(row, clock):
                return self._settle_wait(
                    session, row, "TIMED_OUT", now, failure_code="ORIGINAL_DEADLINE_REACHED"
                )
            if not self._target_reached(row, _utc(row.next_attempt_at), clock):
                if row.state != "WAITING":
                    row = self._cas_progress(
                        session,
                        WaitForOperation,
                        row,
                        allowed_states={"CREATED", "WAITING"},
                        values={"state": "WAITING", "updated_at": now},
                    )
                return self._wait_dict(row)
            if row.attempt_count > row.retry_count:
                row = self._cas_progress(
                    session,
                    WaitForOperation,
                    row,
                    allowed_states={"CREATED", "WAITING"},
                    values={
                        "state": "WAITING",
                        **self._next_attempt_clock_values(
                            row,
                            clock,
                            row.deadline_monotonic_ns - clock.monotonic_ns,
                        ),
                    },
                )
                return self._wait_dict(row)
            plan_record = session.get(ConditionPlanRecord, row.plan_id)
            if plan_record is None or plan_record.plan_digest != row.plan_digest:
                return self._settle_wait(
                    session, row, "FAILED", now, failure_code="PINNED_PLAN_MISSING"
                )
            try:
                stored = self._evaluate_attempt(
                    session,
                    operation_kind="WAITFOR",
                    operation_id=row.id,
                    attempt_number=row.attempt_count + 1,
                    plan_record=plan_record,
                    policy=self._policy_from_row(row),
                    after_snapshot_cursor=(
                        row.last_snapshot_cursor
                        if row.last_snapshot_cursor is not None
                        else row.start_snapshot_cursor
                    ),
                    not_before_clock=clock,
                )
            except _ClockCorrelationError:
                session.rollback()
                row = session.get(WaitForOperation, wait_id, with_for_update=True)
                if row is None or row.state in WAIT_TERMINAL_STATES:
                    return self._wait_dict(row) if row is not None else {}
                return self._settle_wait(
                    session,
                    row,
                    "FAILED",
                    self._clock_failure_time(row),
                    failure_code="CLOCK_CORRELATION_INVALID",
                )
            except Exception:
                session.rollback()
                row = session.get(WaitForOperation, wait_id, with_for_update=True)
                if row is None or row.state in WAIT_TERMINAL_STATES:
                    return self._wait_dict(row) if row is not None else {}
                return self._settle_wait(
                    session,
                    row,
                    "FAILED",
                    self._database_now(session),
                    failure_code="SNAPSHOT_OR_EVALUATION_FAILED",
                )
            try:
                row = self._synchronize_clock(
                    session,
                    WaitForOperation,
                    row,
                    stored.clock,
                    allowed_states={"CREATED", "WAITING"},
                )
            except _ClockCorrelationError:
                session.rollback()
                row = session.get(WaitForOperation, wait_id, with_for_update=True)
                if row is None or row.state in WAIT_TERMINAL_STATES:
                    return self._wait_dict(row) if row is not None else {}
                return self._settle_wait(
                    session,
                    row,
                    "FAILED",
                    self._clock_failure_time(row),
                    failure_code="CLOCK_CORRELATION_INVALID",
                )
            row.attempt_count += 1
            row.last_evaluation_id = stored.record.id
            row.last_snapshot_cursor = stored.record.snapshot_cursor
            settled_at = _utc(stored.record.settled_at)
            if self._deadline_reached(row, stored.clock):
                return self._settle_wait(
                    session,
                    row,
                    "TIMED_OUT",
                    settled_at,
                    evaluation=stored,
                    failure_code="ORIGINAL_DEADLINE_REACHED",
                )
            if stored.record.composite_result == "TRUE":
                return self._settle_wait(
                    session, row, "SATISFIED", settled_at, evaluation=stored
                )
            if stored.record.composite_result == "REJECTED":
                return self._settle_wait(
                    session,
                    row,
                    "FAILED",
                    settled_at,
                    evaluation=stored,
                    failure_code="CONDITION_REJECTED",
                )
            row = self._cas_progress(
                session,
                WaitForOperation,
                row,
                allowed_states={"CREATED", "WAITING"},
                values={
                    "state": "WAITING",
                    "attempt_count": row.attempt_count,
                    "last_evaluation_id": row.last_evaluation_id,
                    "last_snapshot_cursor": row.last_snapshot_cursor,
                    **self._next_attempt_clock_values(
                        row,
                        stored.clock,
                        (
                            row.retry_interval_ns
                            if row.attempt_count <= row.retry_count
                            else row.deadline_monotonic_ns
                            - stored.clock.monotonic_ns
                        ),
                    ),
                },
            )
            return self._wait_dict(row)

    def _settle_wait(
        self,
        session: Session,
        row: WaitForOperation,
        state: str,
        now: datetime,
        *,
        evaluation: _StoredEvaluation | None = None,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        expected_revision = row.revision
        terminal = {
            "state": state,
            "wait_id": row.id,
            "wait_revision": expected_revision + 1,
            "execution_id": row.execution_id,
            "statement_id": row.statement_id,
            "wait_type": row.wait_type,
            "original_target": dict(row.original_target),
            "canonical_target": row.canonical_target,
            "created_at_database_time": _iso(row.created_at),
            "deadline_at_database_time": _iso(row.deadline_at),
            "condition_plan_digest": row.plan_digest,
            "quality_freshness_policy_id": row.policy_id,
            "start_snapshot_cursor": str(row.start_snapshot_cursor),
            "attempt_count": row.attempt_count,
            "evaluation": evaluation.result if evaluation else None,
            "failure_code": failure_code,
            "settled_at_database_time": _iso(now),
        }
        with session.no_autoflush:
            claimed = session.execute(
                update(WaitForOperation)
                .where(
                    WaitForOperation.id == row.id,
                    WaitForOperation.revision == expected_revision,
                    WaitForOperation.state.not_in(tuple(WAIT_TERMINAL_STATES)),
                )
                .values(
                    state=state,
                    revision=expected_revision + 1,
                    attempt_count=row.attempt_count,
                    last_evaluation_id=row.last_evaluation_id,
                    last_snapshot_cursor=row.last_snapshot_cursor,
                    terminal_evaluation_id=(evaluation.record.id if evaluation else None),
                    terminal_result=terminal,
                    failure_code=failure_code,
                    updated_at=now,
                    settled_at=now,
                )
            )
        if claimed.rowcount != 1:
            session.rollback()
        else:
            session.expire(row)
            session.commit()
        session.expire_all()
        winner = session.get(WaitForOperation, row.id)
        if winner is None:
            raise ConditionServiceNotFoundError("WaitFor operation disappeared")
        return self._wait_dict(winner)

    def interrupt_wait(self, wait_id: str, *, expected_revision: int) -> dict[str, Any]:
        return self._transition_wait(wait_id, expected_revision, "INTERRUPTED")

    def resume_wait(self, wait_id: str, *, expected_revision: int) -> dict[str, Any]:
        result = self._transition_wait(wait_id, expected_revision, "WAITING")
        return self.reconcile_wait(wait_id) if result["state"] == "WAITING" else result

    def _transition_wait(
        self, wait_id: str, expected_revision: int, target_state: str
    ) -> dict[str, Any]:
        wait_id = _digest(wait_id, "wait_id")
        with self._lock, self.session_factory() as session:
            row = session.get(WaitForOperation, wait_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("WaitFor operation not found")
            if row.state in WAIT_TERMINAL_STATES:
                return self._wait_dict(row)
            if row.revision != expected_revision:
                raise ConditionServiceConflictError("WaitFor revision conflict")
            if target_state == "INTERRUPTED" and row.state not in {"CREATED", "WAITING"}:
                return self._wait_dict(row)
            if target_state == "WAITING" and row.state != "INTERRUPTED":
                return self._wait_dict(row)
            now = self._database_now(session)
            claimed = session.execute(
                update(WaitForOperation)
                .where(
                    WaitForOperation.id == row.id,
                    WaitForOperation.revision == expected_revision,
                    WaitForOperation.state == row.state,
                )
                .values(
                    state=target_state,
                    revision=expected_revision + 1,
                    updated_at=now,
                )
            )
            if claimed.rowcount != 1:
                session.rollback()
            else:
                session.commit()
            session.expire_all()
            winner = session.get(WaitForOperation, row.id)
            if winner is None:
                raise ConditionServiceNotFoundError("WaitFor operation disappeared")
            return self._wait_dict(winner)

    def cancel_wait(self, wait_id: str, *, expected_revision: int) -> dict[str, Any]:
        wait_id = _digest(wait_id, "wait_id")
        with self._lock, self.session_factory() as session:
            row = session.get(WaitForOperation, wait_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("WaitFor operation not found")
            if row.state in WAIT_TERMINAL_STATES:
                return self._wait_dict(row)
            if row.revision != expected_revision:
                raise ConditionServiceConflictError("WaitFor revision conflict")
            return self._settle_wait(
                session, row, "CANCELLED", self._database_now(session), failure_code="CANCELLED"
            )

    def fail_wait(
        self, wait_id: str, *, expected_revision: int, failure_code: str
    ) -> dict[str, Any]:
        wait_id = _digest(wait_id, "wait_id")
        failure_code = _identifier(failure_code, "failure_code")
        with self._lock, self.session_factory() as session:
            row = session.get(WaitForOperation, wait_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("WaitFor operation not found")
            if row.state in WAIT_TERMINAL_STATES:
                return self._wait_dict(row)
            if row.revision != expected_revision:
                raise ConditionServiceConflictError("WaitFor revision conflict")
            return self._settle_wait(
                session, row, "FAILED", self._database_now(session), failure_code=failure_code
            )

    @staticmethod
    def _wait_dict(row: WaitForOperation) -> dict[str, Any]:
        return {
            "wait_id": row.id,
            "revision": row.revision,
            "execution_id": row.execution_id,
            "statement_id": row.statement_id,
            "wait_type": row.wait_type,
            "original_target": dict(row.original_target),
            "canonical_target": row.canonical_target,
            "state": row.state,
            "condition_plan_id": row.plan_id,
            "condition_plan_digest": row.plan_digest,
            "quality_freshness_policy_id": row.policy_id,
            "quality_freshness_policy_revision": row.policy_revision,
            "start_snapshot_cursor": str(row.start_snapshot_cursor),
            "last_snapshot_cursor": (
                str(row.last_snapshot_cursor)
                if row.last_snapshot_cursor is not None
                else None
            ),
            "retry_count": row.retry_count,
            "retry_interval_ns": row.retry_interval_ns,
            "attempt_count": row.attempt_count,
            "next_attempt_at_database_time": _iso(row.next_attempt_at),
            "deadline_at_database_time": _iso(row.deadline_at),
            "last_evaluation_id": row.last_evaluation_id,
            "terminal_evaluation_id": row.terminal_evaluation_id,
            "terminal_result": dict(row.terminal_result),
            "failure_code": row.failure_code,
            "created_at_database_time": _iso(row.created_at),
            "updated_at_database_time": _iso(row.updated_at),
            "settled_at_database_time": _iso(row.settled_at),
        }

    def create_telemetry_schedule(
        self,
        *,
        plan: ConditionPlan,
        policy: QualityFreshnessPolicy,
        start_snapshot_cursor: int,
        timeout_seconds: str | int | float | Decimal,
        retry_count: int,
        retry_interval_seconds: str | int | float | Decimal,
        controller_execution_id: str,
        procedure_catalog_id: str,
        procedure_revision: int,
        bundle_digest: str,
        context_id: str,
        arguments: dict[str, Any],
        automatic: bool,
        background_allowed: bool,
        visible: bool,
        created_by: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        policy = self._validate_policy(policy)
        if type(start_snapshot_cursor) is not int or start_snapshot_cursor < 0:
            raise ConditionServiceValidationError("start_snapshot_cursor must be nonnegative")
        timeout_ns = _duration_ns(timeout_seconds, "timeout_seconds")
        retry_interval_ns = _duration_ns(
            retry_interval_seconds, "retry_interval_seconds"
        )
        if type(retry_count) is not int or not 0 <= retry_count <= MAX_RETRIES:
            raise ConditionServiceValidationError("retry_count is outside its bound")
        controller_execution_id = _identifier(
            controller_execution_id, "controller_execution_id"
        )
        procedure_catalog_id = _identifier(procedure_catalog_id, "procedure_catalog_id")
        context_id = _identifier(context_id, "context_id")
        created_by = _identifier(created_by, "created_by")
        idempotency_key = _idempotency_key(idempotency_key)
        bundle_digest = _digest(bundle_digest, "bundle_digest")
        if type(procedure_revision) is not int or procedure_revision < 1:
            raise ConditionServiceValidationError("procedure_revision must be positive")
        if any(type(value) is not bool for value in (automatic, background_allowed, visible)):
            raise ConditionServiceValidationError("schedule flags must be boolean")
        if automatic and not background_allowed:
            raise ConditionServiceValidationError(
                "automatic telemetry schedule requires BackgroundAllowed"
            )
        arguments = _validate_json(arguments)
        if not isinstance(arguments, dict) or len(arguments) > 64:
            raise ConditionServiceValidationError("schedule arguments exceed their map bound")
        arguments_digest = _canonical_digest(arguments)
        request = {
            "condition_plan_id": plan.condition_plan_id,
            "condition_plan_digest": plan.condition_plan_digest,
            "policy_id": policy.policy_id,
            "policy_revision": policy.policy_revision,
            "start_snapshot_cursor": start_snapshot_cursor,
            "timeout_ns": timeout_ns,
            "retry_count": retry_count,
            "retry_interval_ns": retry_interval_ns,
            "controller_execution_id": controller_execution_id,
            "procedure_catalog_id": procedure_catalog_id,
            "procedure_revision": procedure_revision,
            "bundle_digest": bundle_digest,
            "context_id": context_id,
            "arguments_digest": arguments_digest,
            "automatic": automatic,
            "background_allowed": background_allowed,
            "visible": visible,
            "created_by": created_by,
        }
        request_digest = _canonical_digest(request)
        schedule_id = _canonical_digest(
            {"kind": "TELEMETRY_SCHEDULE", "created_by": created_by, "idempotency_key": idempotency_key}
        )
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(TelemetryConditionSchedule).where(
                    TelemetryConditionSchedule.created_by == created_by,
                    TelemetryConditionSchedule.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise ConditionServiceConflictError(
                        "idempotency key was used for another telemetry schedule"
                    )
                return self._schedule_dict(existing)
            clock = self._clock_reading(session)
            now = clock.database_time
            self._register_plan(session, plan, now)
            deadline = _add_ns(now, timeout_ns)
            row = TelemetryConditionSchedule(
                id=schedule_id,
                revision=0,
                created_by=created_by,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                state="PENDING",
                plan_id=plan.condition_plan_id,
                plan_digest=plan.condition_plan_digest,
                policy_id=policy.policy_id,
                policy_revision=policy.policy_revision,
                start_snapshot_cursor=start_snapshot_cursor,
                retry_count=retry_count,
                retry_interval_ns=retry_interval_ns,
                attempt_count=0,
                next_attempt_at=now,
                deadline_at=deadline,
                **self._new_clock_fields(clock, deadline),
                controller_execution_id=controller_execution_id,
                procedure_catalog_id=procedure_catalog_id,
                procedure_revision=procedure_revision,
                bundle_digest=bundle_digest,
                context_id=context_id,
                arguments=arguments,
                arguments_digest=arguments_digest,
                automatic=automatic,
                background_allowed=background_allowed,
                visible=visible,
                dispatch_attempts=0,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            return self._schedule_dict(row)

    def get_telemetry_schedule(self, schedule_id: str) -> dict[str, Any]:
        schedule_id = _digest(schedule_id, "schedule_id")
        with self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id)
            if row is None:
                raise ConditionServiceNotFoundError("telemetry schedule not found")
            return self._schedule_dict(row)

    def list_telemetry_schedules(
        self,
        *,
        controller_execution_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ConditionServiceValidationError("limit must be 1 through 500")
        if controller_execution_id is not None:
            controller_execution_id = _identifier(
                controller_execution_id, "controller_execution_id"
            )
        with self.session_factory() as session:
            query = select(TelemetryConditionSchedule)
            if controller_execution_id is not None:
                query = query.where(
                    TelemetryConditionSchedule.controller_execution_id
                    == controller_execution_id
                )
            rows = session.scalars(
                query.order_by(
                    TelemetryConditionSchedule.created_at.desc(),
                    TelemetryConditionSchedule.id,
                ).limit(limit)
            ).all()
            return [self._schedule_dict(row) for row in rows]

    def reconcile_telemetry_schedule(self, schedule_id: str) -> dict[str, Any]:
        schedule_id = _digest(schedule_id, "schedule_id")
        fire = False
        with self._lock, self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("telemetry schedule not found")
            if row.state in SCHEDULE_TERMINAL_STATES:
                return self._schedule_dict(row)
            if row.state == "CLAIMED":
                fire = True
            else:
                try:
                    clock = self._clock_reading(session)
                    row = self._synchronize_clock(
                        session,
                        TelemetryConditionSchedule,
                        row,
                        clock,
                        allowed_states={"PENDING"},
                    )
                except _ClockCorrelationError:
                    session.rollback()
                    row = session.get(
                        TelemetryConditionSchedule, schedule_id, with_for_update=True
                    )
                    if row is None or row.state in SCHEDULE_TERMINAL_STATES:
                        return self._schedule_dict(row) if row is not None else {}
                    return self._settle_schedule(
                        session,
                        row,
                        "ERROR",
                        self._clock_failure_time(row),
                        failure_code="CLOCK_CORRELATION_INVALID",
                    )
                now = clock.database_time
                if self._deadline_reached(row, clock):
                    return self._settle_schedule(
                        session, row, "MISSED", now, failure_code="ORIGINAL_DEADLINE_REACHED"
                    )
                if (
                    not self._target_reached(row, _utc(row.next_attempt_at), clock)
                    or row.attempt_count > row.retry_count
                ):
                    if row.attempt_count > row.retry_count:
                        row = self._cas_progress(
                            session,
                            TelemetryConditionSchedule,
                            row,
                            allowed_states={"PENDING"},
                            values={
                                **self._next_attempt_clock_values(
                                    row,
                                    clock,
                                    row.deadline_monotonic_ns - clock.monotonic_ns,
                                ),
                            },
                        )
                    return self._schedule_dict(row)
                plan_record = session.get(ConditionPlanRecord, row.plan_id)
                if plan_record is None or plan_record.plan_digest != row.plan_digest:
                    return self._settle_schedule(
                        session, row, "ERROR", now, failure_code="PINNED_PLAN_MISSING"
                    )
                try:
                    stored = self._evaluate_attempt(
                        session,
                        operation_kind="SCHEDULE",
                        operation_id=row.id,
                        attempt_number=row.attempt_count + 1,
                        plan_record=plan_record,
                        policy=self._policy_from_row(row),
                        after_snapshot_cursor=(
                            row.last_snapshot_cursor
                            if row.last_snapshot_cursor is not None
                            else row.start_snapshot_cursor
                        ),
                        not_before_clock=clock,
                    )
                except _ClockCorrelationError:
                    session.rollback()
                    row = session.get(
                        TelemetryConditionSchedule, schedule_id, with_for_update=True
                    )
                    if row is None or row.state in SCHEDULE_TERMINAL_STATES:
                        return self._schedule_dict(row) if row is not None else {}
                    return self._settle_schedule(
                        session,
                        row,
                        "ERROR",
                        self._clock_failure_time(row),
                        failure_code="CLOCK_CORRELATION_INVALID",
                    )
                except Exception:
                    session.rollback()
                    row = session.get(TelemetryConditionSchedule, schedule_id, with_for_update=True)
                    if row is None or row.state in SCHEDULE_TERMINAL_STATES:
                        return self._schedule_dict(row) if row is not None else {}
                    return self._settle_schedule(
                        session,
                        row,
                        "ERROR",
                        self._database_now(session),
                        failure_code="SNAPSHOT_OR_EVALUATION_FAILED",
                    )
                try:
                    row = self._synchronize_clock(
                        session,
                        TelemetryConditionSchedule,
                        row,
                        stored.clock,
                        allowed_states={"PENDING"},
                    )
                except _ClockCorrelationError:
                    session.rollback()
                    row = session.get(
                        TelemetryConditionSchedule, schedule_id, with_for_update=True
                    )
                    if row is None or row.state in SCHEDULE_TERMINAL_STATES:
                        return self._schedule_dict(row) if row is not None else {}
                    return self._settle_schedule(
                        session,
                        row,
                        "ERROR",
                        self._clock_failure_time(row),
                        failure_code="CLOCK_CORRELATION_INVALID",
                    )
                row.attempt_count += 1
                row.last_evaluation_id = stored.record.id
                row.last_snapshot_cursor = stored.record.snapshot_cursor
                settled_now = _utc(stored.record.settled_at)
                if self._deadline_reached(row, stored.clock):
                    return self._settle_schedule(
                        session,
                        row,
                        "MISSED",
                        settled_now,
                        failure_code="ORIGINAL_DEADLINE_REACHED",
                    )
                if stored.record.composite_result == "REJECTED":
                    return self._settle_schedule(
                        session,
                        row,
                        "ERROR",
                        settled_now,
                        failure_code="CONDITION_REJECTED",
                    )
                if stored.record.composite_result != "TRUE":
                    row = self._cas_progress(
                        session,
                        TelemetryConditionSchedule,
                        row,
                        allowed_states={"PENDING"},
                        values={
                            "attempt_count": row.attempt_count,
                            "last_evaluation_id": row.last_evaluation_id,
                            "last_snapshot_cursor": row.last_snapshot_cursor,
                            **self._next_attempt_clock_values(
                                row,
                                stored.clock,
                                (
                                    row.retry_interval_ns
                                    if row.attempt_count <= row.retry_count
                                    else row.deadline_monotonic_ns
                                    - stored.clock.monotonic_ns
                                ),
                            ),
                        },
                    )
                    return self._schedule_dict(row)
                expected_revision = row.revision
                occurrence_id = _canonical_digest(
                    {
                        "schedule_id": row.id,
                        "condition_result_digest": stored.record.result_digest,
                    }
                )
                with session.no_autoflush:
                    claimed = session.execute(
                        update(TelemetryConditionSchedule)
                        .where(
                            TelemetryConditionSchedule.id == row.id,
                            TelemetryConditionSchedule.revision == expected_revision,
                            TelemetryConditionSchedule.state == "PENDING",
                        )
                        .values(
                            state="CLAIMED",
                            revision=expected_revision + 1,
                            attempt_count=row.attempt_count,
                            last_evaluation_id=stored.record.id,
                            winning_evaluation_id=stored.record.id,
                            last_snapshot_cursor=stored.record.snapshot_cursor,
                            occurrence_id=occurrence_id,
                            claimed_at=settled_now,
                            updated_at=settled_now,
                        )
                    )
                if claimed.rowcount != 1:
                    session.rollback()
                    winner = session.get(TelemetryConditionSchedule, schedule_id)
                    if winner is None:
                        raise ConditionServiceNotFoundError("telemetry schedule disappeared")
                    return self._schedule_dict(winner)
                session.expire(row)
                session.add(
                    TelemetryScheduleOccurrence(
                        id=occurrence_id,
                        schedule_id=row.id,
                        evaluation_id=stored.record.id,
                        condition_result_digest=stored.record.result_digest,
                        state="CLAIMED",
                        dispatch_attempts=0,
                        claimed_at=settled_now,
                    )
                )
                session.commit()
                fire = True
        return self._fire_claimed_schedule(schedule_id) if fire else self.get_telemetry_schedule(schedule_id)

    def _fire_claimed_schedule(self, schedule_id: str) -> dict[str, Any]:
        with self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id)
            if row is None:
                raise ConditionServiceNotFoundError("telemetry schedule not found")
            if row.state != "CLAIMED":
                return self._schedule_dict(row)
            occurrence = session.get(TelemetryScheduleOccurrence, row.occurrence_id)
            evaluation = session.get(ConditionEvaluationRecord, row.winning_evaluation_id)
            if occurrence is None or evaluation is None:
                return self._mark_schedule_error(
                    schedule_id, "CLAIM_EVIDENCE_MISSING", "claimed schedule evidence is missing"
                )
            schedule_view = self._schedule_dict(row)
            evidence = self._evaluation_payload(evaluation)
            occurrence_id = occurrence.id
        if self.execution_starter is None:
            return self._record_dispatch_failure(
                schedule_id, "EXECUTION_STARTER_UNAVAILABLE"
            )
        try:
            started = self.execution_starter(
                occurrence_id=occurrence_id,
                schedule=schedule_view,
                condition_evidence=evidence,
            )
            execution_id = self._execution_id(started)
        except Exception:
            return self._record_dispatch_failure(schedule_id, "EXECUTION_START_FAILED")
        with self._lock, self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id, with_for_update=True)
            occurrence = (
                session.get(TelemetryScheduleOccurrence, row.occurrence_id, with_for_update=True)
                if row is not None and row.occurrence_id
                else None
            )
            if row is None or occurrence is None:
                raise ConditionServiceNotFoundError("claimed telemetry schedule disappeared")
            if row.state == "FIRED":
                if row.fired_execution_id != execution_id:
                    raise ConditionServiceConflictError(
                        "occurrence-bound starter returned a different execution identity"
                    )
                return self._schedule_dict(row)
            if row.state != "CLAIMED":
                return self._schedule_dict(row)
            now = self._database_now(session)
            expected_revision = row.revision
            claimed = session.execute(
                update(TelemetryConditionSchedule)
                .where(
                    TelemetryConditionSchedule.id == row.id,
                    TelemetryConditionSchedule.revision == expected_revision,
                    TelemetryConditionSchedule.state == "CLAIMED",
                    TelemetryConditionSchedule.occurrence_id == occurrence.id,
                )
                .values(
                    state="FIRED",
                    revision=expected_revision + 1,
                    fired_execution_id=execution_id,
                    dispatch_attempts=row.dispatch_attempts + 1,
                    updated_at=now,
                    settled_at=now,
                )
            )
            if claimed.rowcount != 1:
                session.rollback()
            else:
                occurrence.state = "FIRED"
                occurrence.execution_id = execution_id
                occurrence.dispatch_attempts += 1
                occurrence.settled_at = now
                session.commit()
            session.expire_all()
            winner = session.get(TelemetryConditionSchedule, schedule_id)
            if winner is None:
                raise ConditionServiceNotFoundError("telemetry schedule disappeared")
            return self._schedule_dict(winner)

    @staticmethod
    def _execution_id(value: Any) -> str:
        if isinstance(value, str):
            candidate = value
        elif isinstance(value, Mapping):
            candidate = value.get("execution_id")
        else:
            candidate = getattr(value, "id", None)
        return _identifier(candidate, "execution_id")

    def _record_dispatch_failure(self, schedule_id: str, code: str) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("telemetry schedule not found")
            if row.state != "CLAIMED":
                return self._schedule_dict(row)
            occurrence = session.get(TelemetryScheduleOccurrence, row.occurrence_id)
            now = self._database_now(session)
            attempts = row.dispatch_attempts + 1
            terminal = attempts >= MAX_DISPATCH_ATTEMPTS
            expected_revision = row.revision
            with session.no_autoflush:
                claimed = session.execute(
                    update(TelemetryConditionSchedule)
                    .where(
                        TelemetryConditionSchedule.id == row.id,
                        TelemetryConditionSchedule.revision == expected_revision,
                        TelemetryConditionSchedule.state == "CLAIMED",
                    )
                    .values(
                        state="ERROR" if terminal else "CLAIMED",
                        revision=expected_revision + 1,
                        dispatch_attempts=attempts,
                        failure_code=code if terminal else None,
                        error_message=(
                            "occurrence-bound execution dispatch remains unresolved"
                        ),
                        updated_at=now,
                        settled_at=now if terminal else None,
                    )
                )
            if claimed.rowcount != 1:
                session.rollback()
            else:
                session.expire(row)
                if occurrence is not None:
                    occurrence.dispatch_attempts += 1
                    if terminal:
                        occurrence.state = "ERROR"
                        occurrence.settled_at = now
                session.commit()
            session.expire_all()
            winner = session.get(TelemetryConditionSchedule, schedule_id)
            if winner is None:
                raise ConditionServiceNotFoundError("telemetry schedule disappeared")
            return self._schedule_dict(winner)

    def _mark_schedule_error(
        self, schedule_id: str, code: str, message: str
    ) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("telemetry schedule not found")
            if row.state in SCHEDULE_TERMINAL_STATES:
                return self._schedule_dict(row)
            now = self._database_now(session)
            row.state = "ERROR"
            row.failure_code = _identifier(code, "failure_code")
            row.error_message = message[:500]
            row.revision += 1
            row.updated_at = now
            row.settled_at = now
            session.commit()
            return self._schedule_dict(row)

    def _settle_schedule(
        self,
        session: Session,
        row: TelemetryConditionSchedule,
        state: str,
        now: datetime,
        *,
        failure_code: str,
    ) -> dict[str, Any]:
        expected_revision = row.revision
        with session.no_autoflush:
            claimed = session.execute(
                update(TelemetryConditionSchedule)
                .where(
                    TelemetryConditionSchedule.id == row.id,
                    TelemetryConditionSchedule.revision == expected_revision,
                    TelemetryConditionSchedule.state == "PENDING",
                )
                .values(
                    state=state,
                    revision=expected_revision + 1,
                    attempt_count=row.attempt_count,
                    last_evaluation_id=row.last_evaluation_id,
                    last_snapshot_cursor=row.last_snapshot_cursor,
                    failure_code=failure_code,
                    updated_at=now,
                    settled_at=now,
                )
            )
        if claimed.rowcount != 1:
            session.rollback()
        else:
            session.expire(row)
            session.commit()
        session.expire_all()
        winner = session.get(TelemetryConditionSchedule, row.id)
        if winner is None:
            raise ConditionServiceNotFoundError("telemetry schedule disappeared")
        return self._schedule_dict(winner)

    def cancel_telemetry_schedule(
        self, schedule_id: str, *, expected_revision: int
    ) -> dict[str, Any]:
        schedule_id = _digest(schedule_id, "schedule_id")
        with self._lock, self.session_factory() as session:
            row = session.get(TelemetryConditionSchedule, schedule_id, with_for_update=True)
            if row is None:
                raise ConditionServiceNotFoundError("telemetry schedule not found")
            if row.state in SCHEDULE_TERMINAL_STATES or row.state == "CLAIMED":
                return self._schedule_dict(row)
            if row.revision != expected_revision:
                raise ConditionServiceConflictError("telemetry schedule revision conflict")
            return self._settle_schedule(
                session,
                row,
                "CANCELLED",
                self._database_now(session),
                failure_code="CANCELLED",
            )

    @staticmethod
    def _schedule_dict(row: TelemetryConditionSchedule) -> dict[str, Any]:
        return {
            "schedule_id": row.id,
            "idempotency_key": row.idempotency_key,
            "revision": row.revision,
            "schedule_type": "TELEMETRY_CONDITION",
            "state": row.state,
            "condition_plan_id": row.plan_id,
            "condition_plan_digest": row.plan_digest,
            "quality_freshness_policy_id": row.policy_id,
            "quality_freshness_policy_revision": row.policy_revision,
            "start_snapshot_cursor": str(row.start_snapshot_cursor),
            "last_snapshot_cursor": (
                str(row.last_snapshot_cursor)
                if row.last_snapshot_cursor is not None
                else None
            ),
            "attempt_count": row.attempt_count,
            "retry_count": row.retry_count,
            "retry_interval_ns": row.retry_interval_ns,
            "next_attempt_at_database_time": _iso(row.next_attempt_at),
            "created_at_database_time": _iso(row.created_at),
            "deadline_at_database_time": _iso(row.deadline_at),
            "controller_execution_id": row.controller_execution_id,
            "procedure_catalog_id": row.procedure_catalog_id,
            "procedure_revision": row.procedure_revision,
            "bundle_digest": row.bundle_digest,
            "context_id": row.context_id,
            "created_by": row.created_by,
            "arguments": dict(row.arguments),
            "arguments_digest": row.arguments_digest,
            "automatic": row.automatic,
            "background_allowed": row.background_allowed,
            "visible": row.visible,
            "last_evaluation_id": row.last_evaluation_id,
            "winning_evaluation_id": row.winning_evaluation_id,
            "occurrence_id": row.occurrence_id,
            "fired_execution_id": row.fired_execution_id,
            "dispatch_attempts": row.dispatch_attempts,
            "failure_code": row.failure_code,
            "error_message": row.error_message,
            "claimed_at_database_time": _iso(row.claimed_at),
            "settled_at_database_time": _iso(row.settled_at),
        }

    def recover_verifies(self, *, limit: int = MAX_RECOVERY_BATCH) -> list[dict[str, Any]]:
        ids = self._recoverable_ids(VerifyOperation, VERIFY_TERMINAL_STATES, limit)
        return [self.reconcile_verify(item) for item in ids]

    def recover_waits(self, *, limit: int = MAX_RECOVERY_BATCH) -> list[dict[str, Any]]:
        ids = self._recoverable_ids(
            WaitForOperation, WAIT_TERMINAL_STATES | {"INTERRUPTED"}, limit
        )
        return [self.reconcile_wait(item) for item in ids]

    def recover_telemetry_schedules(
        self, *, limit: int = MAX_RECOVERY_BATCH
    ) -> list[dict[str, Any]]:
        ids = self._recoverable_ids(
            TelemetryConditionSchedule, SCHEDULE_TERMINAL_STATES, limit
        )
        return [self.reconcile_telemetry_schedule(item) for item in ids]

    def _recoverable_ids(
        self, model: Any, excluded_states: frozenset[str] | set[str], limit: int
    ) -> list[str]:
        if type(limit) is not int or not 1 <= limit <= MAX_RECOVERY_BATCH:
            raise ConditionServiceValidationError("recovery limit is outside its bound")
        with self.session_factory() as session:
            return list(
                session.scalars(
                    select(model.id)
                    .where(model.state.not_in(tuple(excluded_states)))
                    .order_by(model.created_at, model.id)
                    .limit(limit)
                ).all()
            )


__all__ = [
    "ConditionService",
    "ConditionServiceConflictError",
    "ConditionServiceError",
    "ConditionServiceNotFoundError",
    "ConditionServiceValidationError",
    "ExecutionStarter",
    "SnapshotProvider",
]
