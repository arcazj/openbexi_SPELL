from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .bundled_observation_catalog import (
    CATALOG_DIGEST as BUNDLED_CATALOG_DIGEST,
    CATALOG_ITEMS as BUNDLED_CATALOG_ITEMS,
)
from .driver_models import (
    DriverContextGeneration,
    DriverHostGeneration,
    DriverProfile,
)
from .models import new_id
from .observation_domain import (
    DriverTelemetrySample as DomainTelemetrySample,
    DriverTimeObservation as DomainTimeObservation,
    GapBounds,
    GenerationTuple,
    GetTMMode,
    ScalarKind,
)
from .observation_models import (
    DriverTimeHead,
    DriverTimeObservation,
    ObservationFreshnessPolicy,
    ObservationOutboxEvent,
    ObservationStream,
    TelemetryAlarmHead,
    TelemetryAlarmObservation,
    TelemetryGap,
    TelemetryItemHead,
    TelemetryLimitHead,
    TelemetryLimitSet,
    TelemetrySample,
    TelemetrySourceCursor,
)


OBSERVATION_EVENT_SCHEMA = "spell.driver.observation.event/1"
OBSERVATION_SNAPSHOT_SCHEMA = "spell.driver.observation.snapshot/1"
OBSERVATION_STREAM = "driver.observation"
DEFAULT_AUTHORIZATION_SCOPE = "bundled-simulator-observation"
DEFAULT_POLICY_DEFINITION_ID = "simulator-default:v07-r1"
MAX_OBSERVATION_REPLAY = 10_001
MAX_OBSERVATION_SEQUENCE = 9_223_372_036_854_775_807
MAX_SNAPSHOT_ITEMS = 128
BUNDLED_OBSERVATION_ITEM_IDS = frozenset(item.item_id for item in BUNDLED_CATALOG_ITEMS)
BUNDLED_OBSERVATION_SOURCE_ID = "bundled-deterministic-simulator"
BUNDLED_OBSERVATION_WIRE_SOURCE = "SIMULATOR"
BUNDLED_CLOCK_PROVENANCE = frozenset(
    {
        "bundled-deterministic-simulator-clock",
        "simulator-emulated-gcs-clock",
        "explicit-host-clock-fallback",
    }
)
_BUNDLED_ITEM_BY_ID = {item.item_id: item for item in BUNDLED_CATALOG_ITEMS}
_SOURCE_EPOCH = re.compile(r"^epoch-[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ObservationRepositoryError(RuntimeError):
    code = "INTERNAL"


class ObservationNotFoundError(ObservationRepositoryError):
    code = "NOT_FOUND"


class ObservationConflictError(ObservationRepositoryError):
    code = "CONTRACT_MISMATCH"


class ObservationStaleGenerationError(ObservationConflictError):
    code = "STALE_GENERATION"


class ObservationClockError(ObservationConflictError):
    code = "CLOCK_UNCERTAIN"


class ObservationValidationError(ObservationRepositoryError):
    code = "INVALID_ARGUMENT"


def _wire(value: str | Enum) -> str:
    return str(value.value) if isinstance(value, Enum) else str(value)


def _identifier(value: str, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ObservationValidationError(f"{label} is not a bounded identifier")
    return value


def _digest(value: str, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ObservationValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _database_time(unix_ns: int) -> datetime:
    try:
        return datetime.fromtimestamp(unix_ns / 1_000_000_000, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ObservationClockError("backend receive time is outside the supported range") from exc


def _stored_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class ObservationRepository:
    """Durable backend projection for v0.7 read-only simulator observations."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock_ns: Callable[[], int] = time.time_ns,
        authorization_scope: str = DEFAULT_AUTHORIZATION_SCOPE,
        visible_item_ids: frozenset[str] = BUNDLED_OBSERVATION_ITEM_IDS,
    ):
        self.session_factory = session_factory
        self._clock_ns = clock_ns
        self.authorization_scope = _identifier(
            authorization_scope, "authorization_scope"
        )
        if (
            not isinstance(visible_item_ids, frozenset)
            or not visible_item_ids
            or any(_IDENTIFIER.fullmatch(item_id) is None for item_id in visible_item_ids)
        ):
            raise ObservationValidationError("visible_item_ids must be a bounded frozen set")
        self.visible_item_ids = visible_item_ids
        self._lock = threading.RLock()

    def record_time(
        self,
        observation: DomainTimeObservation,
        *,
        context_generation_id: str | None = None,
    ) -> dict[str, Any]:
        if type(observation) is not DomainTimeObservation:
            raise ObservationValidationError("observation must be a DriverTimeObservation")
        expected_provenance = {
            "SIMULATOR": "bundled-deterministic-simulator-clock",
            "SIMULATOR_GCS_TIME": "simulator-emulated-gcs-clock",
            "HOST_FALLBACK": "explicit-host-clock-fallback",
        }.get(observation.clock_source.value)
        if observation.provenance != expected_provenance:
            raise ObservationConflictError(
                "driver time provenance differs from the bundled observation contract"
            )
        if context_generation_id is not None:
            context_generation_id = _identifier(
                context_generation_id, "context_generation_id"
            )
        received_ns = self._receive_time_ns()
        received_at = _database_time(received_ns)
        payload = self._time_payload(observation)
        payload_digest = _canonical_digest(payload)

        with self._lock, self.session_factory() as session:
            try:
                host = self._require_host(session, observation.generations, lock=True)
                context = None
                stream = None
                if context_generation_id is not None:
                    context = session.get(
                        DriverContextGeneration,
                        context_generation_id,
                        with_for_update=True,
                    )
                    if (
                        context is None
                        or context.host_generation_id != host.id
                        or context.state != "ACTIVE"
                        or not context.ready
                    ):
                        raise ObservationStaleGenerationError(
                            "time observation context generation is not active"
                        )
                    stream = self._stream(session, context.id, create=True, lock=True)

                existing = session.get(DriverTimeObservation, observation.observation_id)
                if existing is not None:
                    if existing.payload_digest != payload_digest:
                        raise ObservationConflictError(
                            "time observation identity was reused with different content"
                        )
                    return self._time_dict(existing, context)

                head = session.get(DriverTimeHead, host.id, with_for_update=True)
                if head is not None:
                    prior = session.get(DriverTimeObservation, head.observation_id)
                    assert prior is not None
                    if (
                        observation.time_unix_ns + observation.uncertainty_ns
                        < prior.time_unix_ns - prior.uncertainty_ns
                    ):
                        raise ObservationClockError(
                            "driver time regressed beyond its declared uncertainty"
                        )

                row = DriverTimeObservation(
                    id=observation.observation_id,
                    host_generation_id=host.id,
                    payload_digest=payload_digest,
                    time_unix_ns=observation.time_unix_ns,
                    acquired_at_unix_ns=observation.acquired_at_unix_ns,
                    received_at_unix_ns=received_ns,
                    received_at=received_at,
                    clock_source=observation.clock_source.value,
                    provenance=observation.provenance,
                    uncertainty_ns=observation.uncertainty_ns,
                    quality=observation.quality.value,
                    validity=observation.validity.value,
                )
                session.add(row)
                session.flush()
                if head is None:
                    head = DriverTimeHead(
                        host_generation_id=host.id,
                        observation_id=row.id,
                        revision=0,
                        updated_at=received_at,
                    )
                    session.add(head)
                else:
                    head.observation_id = row.id
                    head.revision += 1
                    head.updated_at = received_at
                session.flush()
                if stream is not None:
                    self._emit(
                        session,
                        stream,
                        event_type="driver.time_observed",
                        aggregate_type="driver_time",
                        aggregate_id=row.id,
                        data=self._time_dict(row, context),
                        created_at=received_at,
                    )
                session.commit()
                return self._time_dict(row, context)
            except IntegrityError as exc:
                session.rollback()
                raise ObservationConflictError(
                    "time observation conflicts with durable projection state"
                ) from exc
            except Exception:
                session.rollback()
                raise

    def ingest_sample(
        self,
        sample: DomainTelemetrySample,
        *,
        mode: GetTMMode,
        resynchronized: bool = False,
    ) -> dict[str, Any]:
        if type(sample) is not DomainTelemetrySample:
            raise ObservationValidationError("sample must be a DriverTelemetrySample")
        if type(mode) is not GetTMMode:
            raise ObservationValidationError("mode must be a GetTMMode")
        if type(resynchronized) is not bool:
            raise ObservationValidationError("resynchronized must be boolean")
        self._validate_bundled_sample(sample)
        received_ns = self._receive_time_ns()
        received_at = _database_time(received_ns)
        payload = self._sample_payload(sample)
        payload_digest = _canonical_digest(payload)
        identity = sample.sample_identity

        with self._lock, self.session_factory() as session:
            try:
                _host, context = self._require_context(
                    session, sample.generations, lock=True
                )
                stream = self._stream(session, context.id, create=True, lock=True)
                assert stream is not None
                policy = session.get(
                    ObservationFreshnessPolicy, DEFAULT_POLICY_DEFINITION_ID
                )
                if policy is None:
                    raise ObservationConflictError(
                        "the pinned freshness policy is unavailable"
                    )

                existing = session.get(TelemetrySample, identity.sample_id)
                if existing is not None:
                    if (
                        existing.payload_digest != payload_digest
                        or existing.context_generation_id != context.id
                    ):
                        raise ObservationConflictError(
                            "sample identity was reused with different content"
                        )
                    if mode is GetTMMode.CURRENT and resynchronized:
                        cursor = session.scalar(
                            select(TelemetrySourceCursor)
                            .where(
                                TelemetrySourceCursor.context_generation_id == context.id,
                                TelemetrySourceCursor.source_id == identity.source_id,
                                TelemetrySourceCursor.item_id == identity.item_id,
                            )
                            .with_for_update()
                        )
                        head = session.scalar(
                            select(TelemetryItemHead)
                            .where(
                                TelemetryItemHead.context_generation_id == context.id,
                                TelemetryItemHead.item_id == identity.item_id,
                            )
                            .with_for_update()
                        )
                        if (
                            cursor is None
                            or head is None
                            or cursor.source_epoch != identity.source_epoch
                            or cursor.source_sequence != identity.source_sequence
                            or head.sample_id != existing.id
                        ):
                            raise ObservationConflictError(
                                "resynchronized CURRENT sample is not the durable source head"
                            )
                        if cursor.synchronization_state == "GAPPED":
                            cursor.synchronization_state = "COMPLETE"
                            cursor.revision += 1
                            cursor.updated_at = received_at
                            head.synchronization_state = "COMPLETE"
                            head.revision += 1
                            head.updated_at = received_at
                            for prior_gap in session.scalars(
                                select(TelemetryGap)
                                .where(
                                    TelemetryGap.context_generation_id == context.id,
                                    TelemetryGap.source_id == identity.source_id,
                                    TelemetryGap.item_id == identity.item_id,
                                    TelemetryGap.state == "OPEN",
                                )
                                .with_for_update()
                            ):
                                prior_gap.state = "RESOLVED"
                                prior_gap.resolved_at = received_at
                                prior_gap.resolution_sample_id = existing.id
                            self._emit(
                                session,
                                stream,
                                event_type="telemetry.sample_observed",
                                aggregate_type="telemetry_sample",
                                aggregate_id=existing.id,
                                data={
                                    **self._sample_dict(existing, head),
                                    "current_head_revision": head.revision,
                                    "resynchronized": True,
                                },
                                created_at=received_at,
                            )
                            self._evaluate_alarm(
                                session,
                                stream,
                                existing,
                                head,
                                evaluated_at=self._database_now(session),
                            )
                            session.commit()
                    return self._sample_projection(session, existing)
                reused_observation = session.scalar(
                    select(TelemetrySample).where(
                        TelemetrySample.observation_id == sample.observation_id
                    )
                )
                if reused_observation is not None:
                    raise ObservationConflictError(
                        "observation identity was reused for another sample"
                    )

                cursor = session.scalar(
                    select(TelemetrySourceCursor)
                    .where(
                        TelemetrySourceCursor.context_generation_id == context.id,
                        TelemetrySourceCursor.source_id == identity.source_id,
                        TelemetrySourceCursor.item_id == identity.item_id,
                    )
                    .with_for_update()
                )
                head = session.scalar(
                    select(TelemetryItemHead)
                    .where(
                        TelemetryItemHead.context_generation_id == context.id,
                        TelemetryItemHead.item_id == identity.item_id,
                    )
                    .with_for_update()
                )
                gap: tuple[int, int] | None = None
                synchronization_state = "COMPLETE"
                if cursor is not None:
                    if cursor.source_epoch != identity.source_epoch:
                        if mode is not GetTMMode.CURRENT or not resynchronized:
                            raise ObservationConflictError(
                                "source epoch replacement requires a resynchronized CURRENT sample"
                            )
                    else:
                        if identity.source_sequence <= cursor.source_sequence:
                            raise ObservationConflictError(
                                "source sequence regressed or reused without identical content"
                            )
                        expected = cursor.source_sequence + 1
                        if identity.source_sequence > expected and not (
                            mode is GetTMMode.CURRENT and resynchronized
                        ):
                            gap = (expected, identity.source_sequence)
                            synchronization_state = "GAPPED"
                        elif cursor.synchronization_state == "GAPPED" and not resynchronized:
                            synchronization_state = "GAPPED"

                freshness, fresh_until = self._freshness(
                    sample.acquired_at_unix_ns,
                    received_ns,
                    sample.clock_uncertainty_ns,
                    sample.clock_provenance,
                    policy,
                )
                row = TelemetrySample(
                    id=identity.sample_id,
                    observation_id=sample.observation_id,
                    host_generation_id=sample.generations.driver_host_generation,
                    context_generation_id=context.id,
                    payload_digest=payload_digest,
                    item_id=identity.item_id,
                    qualified_name=sample.item_identity.qualified_name,
                    catalog_digest=sample.item_identity.catalog_digest,
                    source_id=identity.source_id,
                    source_epoch=identity.source_epoch,
                    source_sequence=identity.source_sequence,
                    raw_value=self._scalar_dict(sample.raw_value),
                    engineering_value=self._scalar_dict(sample.engineering_value),
                    description=sample.description,
                    unit=sample.unit,
                    acquired_at_unix_ns=sample.acquired_at_unix_ns,
                    received_at_unix_ns=received_ns,
                    received_at=received_at,
                    source=sample.source,
                    clock_provenance=sample.clock_provenance,
                    clock_uncertainty_ns=sample.clock_uncertainty_ns,
                    validity=sample.validity.value,
                    quality=sample.quality.value,
                    quality_reason=sample.quality_reason,
                    freshness=freshness,
                    freshness_policy_id=policy.id,
                    freshness_policy_revision=policy.revision,
                    fresh_until_unix_ns=fresh_until,
                )
                session.add(row)
                session.flush()

                if cursor is None:
                    cursor = TelemetrySourceCursor(
                        context_generation_id=context.id,
                        source_id=identity.source_id,
                        item_id=identity.item_id,
                        source_epoch=identity.source_epoch,
                        source_sequence=identity.source_sequence,
                        sample_id=row.id,
                        synchronization_state=synchronization_state,
                        revision=0,
                        updated_at=received_at,
                    )
                    session.add(cursor)
                else:
                    cursor.source_epoch = identity.source_epoch
                    cursor.source_sequence = identity.source_sequence
                    cursor.sample_id = row.id
                    cursor.synchronization_state = synchronization_state
                    cursor.revision += 1
                    cursor.updated_at = received_at

                if head is None:
                    head = TelemetryItemHead(
                        context_generation_id=context.id,
                        item_id=identity.item_id,
                        sample_id=row.id,
                        catalog_digest=row.catalog_digest,
                        source_id=row.source_id,
                        source_epoch=row.source_epoch,
                        source_sequence=row.source_sequence,
                        freshness=freshness,
                        synchronization_state=synchronization_state,
                        revision=0,
                        updated_at=received_at,
                    )
                    session.add(head)
                else:
                    head.sample_id = row.id
                    head.catalog_digest = row.catalog_digest
                    head.source_id = row.source_id
                    head.source_epoch = row.source_epoch
                    head.source_sequence = row.source_sequence
                    head.freshness = freshness
                    head.synchronization_state = synchronization_state
                    head.revision += 1
                    head.updated_at = received_at

                if resynchronized:
                    open_gaps = session.scalars(
                        select(TelemetryGap)
                        .where(
                            TelemetryGap.context_generation_id == context.id,
                            TelemetryGap.source_id == identity.source_id,
                            TelemetryGap.item_id == identity.item_id,
                            TelemetryGap.state == "OPEN",
                        )
                        .with_for_update()
                    ).all()
                    for prior_gap in open_gaps:
                        prior_gap.state = "RESOLVED"
                        prior_gap.resolved_at = received_at
                        prior_gap.resolution_sample_id = row.id

                session.flush()
                if gap is not None:
                    gap_row = TelemetryGap(
                        context_generation_id=context.id,
                        source_id=row.source_id,
                        item_id=row.item_id,
                        source_epoch=row.source_epoch,
                        expected_sequence=gap[0],
                        observed_sequence=gap[1],
                        state="OPEN",
                        detected_at=received_at,
                    )
                    session.add(gap_row)
                    session.flush()
                    self._emit(
                        session,
                        stream,
                        event_type="telemetry.gap_detected",
                        aggregate_type="telemetry_item",
                        aggregate_id=row.item_id,
                        data={
                            "gap_id": gap_row.id,
                            "context_generation_id": context.id,
                            "item_id": row.item_id,
                            "source_id": row.source_id,
                            "source_epoch": row.source_epoch,
                            "expected_source_sequence": str(gap[0]),
                            "observed_source_sequence": str(gap[1]),
                        },
                        created_at=received_at,
                    )

                self._emit(
                    session,
                    stream,
                    event_type="telemetry.sample_observed",
                    aggregate_type="telemetry_sample",
                    aggregate_id=row.id,
                    data={
                        **self._sample_dict(row, head),
                        "current_head_revision": head.revision,
                    },
                    created_at=received_at,
                )
                self._evaluate_alarm(
                    session, stream, row, head, evaluated_at=self._database_now(session)
                )
                session.commit()
                return self._sample_projection(session, row)
            except IntegrityError as exc:
                session.rollback()
                raise ObservationConflictError(
                    "sample conflicts with durable projection state"
                ) from exc
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _validate_bundled_sample(sample: DomainTelemetrySample) -> None:
        identity = sample.sample_identity
        definition = _BUNDLED_ITEM_BY_ID.get(identity.item_id)
        if (
            definition is None
            or sample.item_identity.item_id != definition.item_id
            or sample.item_identity.qualified_name != definition.qualified_name
            or sample.item_identity.catalog_digest != BUNDLED_CATALOG_DIGEST
            or sample.raw_value.kind.value != definition.raw_type
            or sample.engineering_value.kind.value != definition.engineering_type
            or sample.unit != definition.unit
            or sample.description != definition.description
            or identity.source_id != BUNDLED_OBSERVATION_SOURCE_ID
            or sample.source != BUNDLED_OBSERVATION_WIRE_SOURCE
            or _SOURCE_EPOCH.fullmatch(identity.source_epoch) is None
            or sample.clock_provenance not in BUNDLED_CLOCK_PROVENANCE
        ):
            raise ObservationConflictError(
                "telemetry sample differs from the immutable bundled catalog contract"
            )

    def record_gap(
        self,
        generations: GenerationTuple,
        *,
        source_id: str,
        item_id: str,
        bounds: GapBounds,
    ) -> dict[str, Any]:
        source_id = _identifier(source_id, "source_id")
        item_id = _identifier(item_id, "item_id")
        if type(bounds) is not GapBounds:
            raise ObservationValidationError("bounds must be GapBounds")
        received_ns = self._receive_time_ns()
        received_at = _database_time(received_ns)
        with self._lock, self.session_factory() as session:
            try:
                _host, context = self._require_context(session, generations, lock=True)
                stream = self._stream(session, context.id, create=True, lock=True)
                assert stream is not None
                cursor = session.scalar(
                    select(TelemetrySourceCursor)
                    .where(
                        TelemetrySourceCursor.context_generation_id == context.id,
                        TelemetrySourceCursor.source_id == source_id,
                        TelemetrySourceCursor.item_id == item_id,
                    )
                    .with_for_update()
                )
                head = session.scalar(
                    select(TelemetryItemHead)
                    .where(
                        TelemetryItemHead.context_generation_id == context.id,
                        TelemetryItemHead.item_id == item_id,
                    )
                    .with_for_update()
                )
                if cursor is None or head is None:
                    raise ObservationConflictError(
                        "a source cursor is required before recording a NEXT gap"
                    )
                if cursor.source_epoch != bounds.source_epoch:
                    raise ObservationConflictError("gap source epoch differs from cursor")
                expected = cursor.source_sequence + 1
                if bounds.first_available_sequence <= expected:
                    raise ObservationConflictError("gap bounds do not skip the expected sample")
                existing = session.scalar(
                    select(TelemetryGap).where(
                        TelemetryGap.context_generation_id == context.id,
                        TelemetryGap.source_id == source_id,
                        TelemetryGap.item_id == item_id,
                        TelemetryGap.source_epoch == bounds.source_epoch,
                        TelemetryGap.expected_sequence == expected,
                        TelemetryGap.observed_sequence == bounds.first_available_sequence,
                    )
                )
                if existing is not None:
                    return self._gap_dict(existing)
                cursor.synchronization_state = "GAPPED"
                cursor.revision += 1
                cursor.updated_at = received_at
                head.synchronization_state = "GAPPED"
                head.revision += 1
                head.updated_at = received_at
                gap = TelemetryGap(
                    context_generation_id=context.id,
                    source_id=source_id,
                    item_id=item_id,
                    source_epoch=bounds.source_epoch,
                    expected_sequence=expected,
                    observed_sequence=bounds.first_available_sequence,
                    state="OPEN",
                    detected_at=received_at,
                )
                session.add(gap)
                session.flush()
                self._emit(
                    session,
                    stream,
                    event_type="telemetry.gap_detected",
                    aggregate_type="telemetry_item",
                    aggregate_id=item_id,
                    data={
                        **self._gap_dict(gap),
                        "last_available_source_sequence": str(
                            bounds.last_available_sequence
                        ),
                    },
                    created_at=received_at,
                )
                sample = session.get(TelemetrySample, head.sample_id)
                assert sample is not None
                self._evaluate_alarm(
                    session, stream, sample, head, evaluated_at=self._database_now(session)
                )
                session.commit()
                return self._gap_dict(gap)
            except Exception:
                session.rollback()
                raise

    def mark_stale(self, *, now_unix_ns: int | None = None) -> int:
        now_ns = self._receive_time_ns() if now_unix_ns is None else now_unix_ns
        if type(now_ns) is not int:
            raise ObservationValidationError("now_unix_ns must be an integer")
        now = _database_time(now_ns)
        changed = 0
        with self._lock, self.session_factory() as session:
            try:
                evaluated_at = self._database_now(session)
                heads = session.scalars(
                    select(TelemetryItemHead)
                    .join(TelemetrySample, TelemetrySample.id == TelemetryItemHead.sample_id)
                    .where(
                        TelemetryItemHead.freshness == "FRESH",
                        TelemetrySample.fresh_until_unix_ns.is_not(None),
                        TelemetrySample.fresh_until_unix_ns < now_ns,
                    )
                    .order_by(
                        TelemetryItemHead.context_generation_id,
                        TelemetryItemHead.item_id,
                    )
                    .with_for_update()
                ).all()
                for head in heads:
                    stream = self._stream(
                        session, head.context_generation_id, create=True, lock=True
                    )
                    assert stream is not None
                    sample = session.get(TelemetrySample, head.sample_id)
                    assert sample is not None
                    head.freshness = "STALE"
                    head.revision += 1
                    head.updated_at = now
                    self._emit(
                        session,
                        stream,
                        event_type="telemetry.freshness_changed",
                        aggregate_type="telemetry_item",
                        aggregate_id=head.item_id,
                        data={
                            "context_generation_id": head.context_generation_id,
                            "item_id": head.item_id,
                            "sample_id": head.sample_id,
                            "freshness": "STALE",
                            "freshness_policy_revision": sample.freshness_policy_revision,
                            "evaluated_at_database_time": evaluated_at.isoformat(),
                        },
                        created_at=now,
                    )
                    self._evaluate_alarm(
                        session, stream, sample, head, evaluated_at=evaluated_at
                    )
                    changed += 1
                session.commit()
                return changed
            except Exception:
                session.rollback()
                raise

    def driver_time(self, context_id: str) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        with self.session_factory() as session:
            context = self._active_context(session, context_id)
            head = session.get(DriverTimeHead, context.host_generation_id)
            if head is None:
                raise ObservationNotFoundError("driver time is not available")
            row = session.get(DriverTimeObservation, head.observation_id)
            if row is None:
                raise ObservationConflictError("driver time head is incomplete")
            return self._time_dict(row, context)

    def snapshot(self, context_id: str) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        with self._lock, self.session_factory() as session:
            context = self._active_context(session, context_id, lock=True)
            stream = self._stream(session, context.id, create=True, lock=True)
            assert stream is not None
            snapshot_time = self._database_now(session)
            heads = session.scalars(
                select(TelemetryItemHead)
                .where(TelemetryItemHead.context_generation_id == context.id)
                .order_by(TelemetryItemHead.item_id)
                .limit(MAX_SNAPSHOT_ITEMS + 1)
            ).all()
            if len(heads) > MAX_SNAPSHOT_ITEMS:
                raise ObservationConflictError("snapshot item bound was exceeded")
            items: list[dict[str, Any]] = []
            for head in heads:
                sample = session.get(TelemetrySample, head.sample_id)
                if sample is None:
                    raise ObservationConflictError("telemetry item head is incomplete")
                items.append(self._sample_projection(session, sample))
            cursors = session.scalars(
                select(TelemetrySourceCursor)
                .where(TelemetrySourceCursor.context_generation_id == context.id)
                .order_by(TelemetrySourceCursor.source_id, TelemetrySourceCursor.item_id)
            ).all()
            time_head = session.get(DriverTimeHead, context.host_generation_id)
            time_row = (
                session.get(DriverTimeObservation, time_head.observation_id)
                if time_head is not None
                else None
            )
            if not items:
                sync = "NO_SAMPLE"
            elif any(item["synchronization_state"] == "GAPPED" for item in items):
                sync = "GAPPED"
            else:
                sync = "COMPLETE"
            session.commit()
            return {
                "schema_version": OBSERVATION_SNAPSHOT_SCHEMA,
                "stream": OBSERVATION_STREAM,
                "stream_epoch": stream.stream_epoch,
                "through_sequence": str(stream.last_sequence),
                "snapshot_at_database_time": snapshot_time.isoformat(),
                "context_id": context.context_id,
                "context_generation_id": context.id,
                "source_epochs": [
                    {
                        "source_id": cursor.source_id,
                        "item_id": cursor.item_id,
                        "source_epoch": cursor.source_epoch,
                        "last_source_sequence": str(cursor.source_sequence),
                        "synchronization_state": cursor.synchronization_state,
                    }
                    for cursor in cursors
                ],
                "items": items,
                "driver_time": (
                    self._time_dict(time_row, context) if time_row is not None else None
                ),
                "synchronization_state": sync,
            }

    def telemetry_anchor(self, context_id: str, item_id: str) -> dict[str, str]:
        """Read a durable NEXT anchor and its projection cursor atomically."""

        context_id = _identifier(context_id, "context_id")
        item_id = _identifier(item_id, "item_id")
        with self._lock, self.session_factory() as session:
            context = self._active_context(session, context_id, lock=True)
            stream = self._stream(session, context.id, create=False, lock=True)
            if stream is None:
                raise ObservationNotFoundError(
                    "observation stream is not initialized"
                )
            head = session.scalar(
                select(TelemetryItemHead).where(
                    TelemetryItemHead.context_generation_id == context.id,
                    TelemetryItemHead.item_id == item_id,
                )
            )
            if head is None:
                raise ObservationNotFoundError(
                    "telemetry item has no durable observation anchor"
                )
            return {
                "context_id": context.context_id,
                "context_generation_id": context.id,
                "stream_epoch": stream.stream_epoch,
                "projection_sequence": str(stream.last_sequence),
                "item_id": head.item_id,
                "source_id": head.source_id,
                "source_epoch": head.source_epoch,
                "source_sequence": str(head.source_sequence),
                "sample_id": head.sample_id,
            }

    def restart_cursors(self, context_generation_id: str) -> list[dict[str, Any]]:
        context_generation_id = _identifier(
            context_generation_id, "context_generation_id"
        )
        with self.session_factory() as session:
            return [
                {
                    "context_generation_id": item.context_generation_id,
                    "source_id": item.source_id,
                    "item_id": item.item_id,
                    "source_epoch": item.source_epoch,
                    "after_source_sequence": item.source_sequence,
                    "synchronization_state": item.synchronization_state,
                }
                for item in session.scalars(
                    select(TelemetrySourceCursor)
                    .where(
                        TelemetrySourceCursor.context_generation_id
                        == context_generation_id
                    )
                    .order_by(
                        TelemetrySourceCursor.source_id,
                        TelemetrySourceCursor.item_id,
                    )
                )
            ]

    def replay(
        self,
        context_id: str,
        *,
        stream_epoch: str,
        after_sequence: int,
        limit: int,
    ) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        stream_epoch = _identifier(stream_epoch, "stream_epoch")
        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or not 0 <= after_sequence <= MAX_OBSERVATION_SEQUENCE
        ):
            raise ObservationValidationError("after_sequence is outside the cursor range")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_OBSERVATION_REPLAY
        ):
            raise ObservationValidationError(
                f"replay limit must be between 1 and {MAX_OBSERVATION_REPLAY}"
            )
        with self.session_factory() as session:
            context = self._active_context(session, context_id)
            stream = self._stream(session, context.id, create=False, lock=False)
            if stream is None:
                raise ObservationNotFoundError("observation stream is not initialized")
            epoch_matches = stream_epoch == stream.stream_epoch
            first, last = session.execute(
                select(
                    func.min(ObservationOutboxEvent.projection_sequence),
                    func.max(ObservationOutboxEvent.projection_sequence),
                ).where(
                    ObservationOutboxEvent.stream_id == stream.id,
                    ObservationOutboxEvent.stream_epoch == stream.stream_epoch,
                )
            ).one()
            first_sequence = int(first) if first is not None else None
            authoritative = stream.last_sequence
            cursor_available = epoch_matches
            if epoch_matches:
                if after_sequence > authoritative:
                    cursor_available = False
                elif after_sequence == 0:
                    cursor_available = first_sequence in {None, 1}
                elif after_sequence < authoritative:
                    cursor_available = session.scalar(
                        select(func.count())
                        .select_from(ObservationOutboxEvent)
                        .where(
                            ObservationOutboxEvent.stream_id == stream.id,
                            ObservationOutboxEvent.stream_epoch == stream.stream_epoch,
                            ObservationOutboxEvent.projection_sequence == after_sequence,
                        )
                    ) == 1
            rows = session.scalars(
                select(ObservationOutboxEvent)
                .where(
                    ObservationOutboxEvent.stream_id == stream.id,
                    ObservationOutboxEvent.stream_epoch == stream.stream_epoch,
                    ObservationOutboxEvent.projection_sequence > after_sequence,
                )
                .order_by(ObservationOutboxEvent.projection_sequence)
                .limit(limit)
            ).all()
            return {
                "stream_epoch": stream.stream_epoch,
                "first_sequence": (
                    str(first_sequence) if first_sequence is not None else None
                ),
                "last_sequence": str(authoritative),
                "epoch_matches": epoch_matches,
                "cursor_available": cursor_available,
                "items": [self._event_dict(row) for row in rows] if epoch_matches else [],
            }

    def stream_cursor(self, context_id: str) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        with self.session_factory() as session:
            context = self._active_context(session, context_id)
            stream = self._stream(session, context.id, create=False, lock=False)
            if stream is None:
                raise ObservationNotFoundError("observation stream is not initialized")
            return {
                "stream_epoch": stream.stream_epoch,
                "last_sequence": str(stream.last_sequence),
            }

    def rotate_stream_epoch(self, context_id: str) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        with self._lock, self.session_factory() as session:
            context = self._active_context(session, context_id, lock=True)
            stream = self._stream(session, context.id, create=True, lock=True)
            assert stream is not None
            stream.stream_epoch = str(uuid.uuid4())
            stream.last_sequence = 0
            stream.revision += 1
            stream.updated_at = _database_time(self._receive_time_ns())
            session.commit()
            return {
                "stream_epoch": stream.stream_epoch,
                "last_sequence": str(stream.last_sequence),
            }

    def pending_outbox(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ObservationValidationError("outbox limit must be between 1 and 100")
        with self.session_factory() as session:
            rows = session.scalars(
                select(ObservationOutboxEvent)
                .where(ObservationOutboxEvent.published_at.is_(None))
                .order_by(ObservationOutboxEvent.created_at, ObservationOutboxEvent.id)
                .limit(limit)
            ).all()
            return [self._event_dict(row) for row in rows]

    def mark_outbox_published(
        self, event_id: str, *, published_at: datetime
    ) -> None:
        event_id = _identifier(event_id, "event_id")
        published_at = _stored_utc(published_at)
        with self._lock, self.session_factory() as session:
            row = session.get(ObservationOutboxEvent, event_id, with_for_update=True)
            if row is None:
                raise ObservationNotFoundError("observation outbox event not found")
            if row.published_at is None:
                row.delivery_attempts += 1
                row.published_at = published_at
                session.commit()

    def get_limits(self, item_id: str, catalog_digest: str) -> dict[str, Any]:
        item_id = _identifier(item_id, "item_id")
        catalog_digest = _digest(catalog_digest, "catalog_digest")
        with self.session_factory() as session:
            head = session.scalar(
                select(TelemetryLimitHead).where(
                    TelemetryLimitHead.item_id == item_id,
                    TelemetryLimitHead.catalog_digest == catalog_digest,
                )
            )
            if head is None:
                raise ObservationNotFoundError("telemetry limits are not available")
            definition = session.get(TelemetryLimitSet, head.limit_definition_id)
            if definition is None:
                raise ObservationConflictError("telemetry limit head is incomplete")
            return self._limit_dict(definition)

    def is_alarmed(self, context_id: str, item_id: str) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        item_id = _identifier(item_id, "item_id")
        if item_id not in self.visible_item_ids:
            raise ObservationNotFoundError("telemetry alarm state is not available")
        with self.session_factory() as session:
            context = self._active_context(session, context_id)
            head = session.scalar(
                select(TelemetryAlarmHead).where(
                    TelemetryAlarmHead.context_generation_id == context.id,
                    TelemetryAlarmHead.item_id == item_id,
                )
            )
            if head is None:
                stream = self._stream(session, context.id, create=False, lock=False)
                limit_head = session.scalar(
                    select(TelemetryLimitHead)
                    .where(TelemetryLimitHead.item_id == item_id)
                    .order_by(TelemetryLimitHead.updated_at.desc())
                    .limit(1)
                )
                limit = (
                    session.get(TelemetryLimitSet, limit_head.limit_definition_id)
                    if limit_head is not None
                    else None
                )
                evaluated_at = self._database_now(session)
                evaluated_at_iso = _stored_utc(evaluated_at).isoformat()
                stream_epoch = stream.stream_epoch if stream is not None else "UNINITIALIZED"
                projection_sequence = stream.last_sequence if stream is not None else 0
                view_id = _canonical_digest(
                    {
                        "schema_version": "spell.v07.no-sample-alarm/1",
                        "context_generation_id": context.id,
                        "item_id": item_id,
                        "limit_definition_id": limit.id if limit is not None else None,
                        "stream_epoch": stream_epoch,
                        "projection_sequence": projection_sequence,
                        "evaluated_at_database_time": evaluated_at_iso,
                        "reason": "NO_SAMPLE",
                    }
                )
                return {
                    "alarm_observation_id": view_id,
                    "item_id": item_id,
                    "sample_id": None,
                    "limit_set_id": limit.limit_set_id if limit is not None else None,
                    "limit_revision": limit.limit_revision if limit is not None else None,
                    "state": "INDETERMINATE",
                    "severity": "INDETERMINATE",
                    "evaluated_engineering_value": None,
                    "quality": "UNKNOWN",
                    "validity": "UNKNOWN",
                    "freshness": "UNKNOWN",
                    "boolean_value": None,
                    "snapshot_cursor": {
                        "stream_epoch": stream_epoch,
                        "projection_sequence": str(projection_sequence),
                    },
                    "evaluated_at_database_time": evaluated_at_iso,
                    "reason": "NO_SAMPLE",
                }
            observation = session.get(
                TelemetryAlarmObservation, head.alarm_observation_id
            )
            if observation is None:
                raise ObservationConflictError("telemetry alarm head is incomplete")
            return self._alarm_dict(session, observation)

    def _receive_time_ns(self) -> int:
        value = self._clock_ns()
        if type(value) is not int or not -(2**63) <= value <= 2**63 - 1:
            raise ObservationClockError("backend clock returned an invalid Unix nanosecond value")
        return value

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
        return _stored_utc(value)

    @staticmethod
    def _require_host(
        session: Session, generations: GenerationTuple, *, lock: bool
    ) -> DriverHostGeneration:
        host = session.get(
            DriverHostGeneration,
            generations.driver_host_generation,
            with_for_update=lock,
        )
        profile = (
            session.get(DriverProfile, host.profile_id) if host is not None else None
        )
        if (
            host is None
            or profile is None
            or host.logical_driver_id != profile.logical_driver_id
            or profile.server_profile_id != generations.server_profile_id
            or host.configuration_digest != generations.host_profile_digest
            or host.state not in {"READY", "DEGRADED"}
        ):
            raise ObservationStaleGenerationError(
                "driver host generation tuple is stale"
            )
        return host

    @classmethod
    def _require_context(
        cls, session: Session, generations: GenerationTuple, *, lock: bool
    ) -> tuple[DriverHostGeneration, DriverContextGeneration]:
        host = cls._require_host(session, generations, lock=lock)
        context = session.get(
            DriverContextGeneration,
            generations.context_generation,
            with_for_update=lock,
        )
        if (
            context is None
            or context.host_generation_id != host.id
            or context.context_id != generations.context_id
            or context.configuration_digest != generations.context_binding_digest
            or context.state != "ACTIVE"
            or not context.ready
        ):
            raise ObservationStaleGenerationError(
                "driver context generation tuple is stale"
            )
        return host, context

    @staticmethod
    def _active_context(
        session: Session, context_id: str, *, lock: bool = False
    ) -> DriverContextGeneration:
        query = (
            select(DriverContextGeneration)
            .where(
                DriverContextGeneration.context_id == context_id,
                DriverContextGeneration.state == "ACTIVE",
                DriverContextGeneration.ready.is_(True),
            )
            .order_by(DriverContextGeneration.generation_number.desc())
            .limit(1)
        )
        if lock:
            query = query.with_for_update()
        context = session.scalar(query)
        if context is None:
            raise ObservationNotFoundError("active driver context was not found")
        return context

    def _stream(
        self,
        session: Session,
        context_generation_id: str,
        *,
        create: bool,
        lock: bool,
    ) -> ObservationStream | None:
        query = select(ObservationStream).where(
            ObservationStream.authorization_scope == self.authorization_scope,
            ObservationStream.context_generation_id == context_generation_id,
        )
        if lock:
            query = query.with_for_update()
        stream = session.scalar(query)
        if stream is None and create:
            stream = ObservationStream(
                authorization_scope=self.authorization_scope,
                context_generation_id=context_generation_id,
                stream_epoch=str(uuid.uuid4()),
                last_sequence=0,
                revision=0,
            )
            session.add(stream)
            session.flush()
        return stream

    @staticmethod
    def _freshness(
        acquired_ns: int,
        received_ns: int,
        uncertainty_ns: int,
        clock_provenance: str,
        policy: ObservationFreshnessPolicy,
    ) -> tuple[str, int | None]:
        if uncertainty_ns > policy.max_clock_uncertainty_ns:
            return "UNKNOWN", None
        if clock_provenance in {
            "bundled-deterministic-simulator-clock",
            "simulator-emulated-gcs-clock",
        }:
            fresh_until = received_ns + policy.max_age_ns
            return (
                ("FRESH", fresh_until)
                if fresh_until <= 2**63 - 1
                else ("UNKNOWN", None)
            )
        if acquired_ns > received_ns + uncertainty_ns:
            return "UNKNOWN", None
        fresh_until = acquired_ns + uncertainty_ns + policy.max_age_ns
        if fresh_until > 2**63 - 1:
            return "UNKNOWN", None
        return ("FRESH" if received_ns <= fresh_until else "STALE"), fresh_until

    @staticmethod
    def _scalar_dict(value: Any) -> dict[str, Any]:
        return {"type": value.kind.value, "value": value.canonical_json_value()}

    @classmethod
    def _time_payload(cls, observation: DomainTimeObservation) -> dict[str, Any]:
        return {
            "observation_id": observation.observation_id,
            "generations": observation.generations.canonical(),
            "time_unix_ns": str(observation.time_unix_ns),
            "acquired_at_unix_ns": str(observation.acquired_at_unix_ns),
            "clock_source": observation.clock_source.value,
            "provenance": observation.provenance,
            "uncertainty_ns": str(observation.uncertainty_ns),
            "quality": observation.quality.value,
            "validity": observation.validity.value,
        }

    @classmethod
    def _sample_payload(cls, sample: DomainTelemetrySample) -> dict[str, Any]:
        return {
            "generations": sample.generations.canonical(),
            "sample_identity": {
                "sample_id": sample.sample_identity.sample_id,
                "item_id": sample.sample_identity.item_id,
                "source_id": sample.sample_identity.source_id,
                "source_epoch": sample.sample_identity.source_epoch,
                "source_sequence": str(sample.sample_identity.source_sequence),
            },
            "item_identity": {
                "item_id": sample.item_identity.item_id,
                "qualified_name": sample.item_identity.qualified_name,
                "catalog_digest": sample.item_identity.catalog_digest,
            },
            "raw_value": cls._scalar_dict(sample.raw_value),
            "engineering_value": cls._scalar_dict(sample.engineering_value),
            "description": sample.description,
            "unit": sample.unit,
            "acquired_at_unix_ns": str(sample.acquired_at_unix_ns),
            "source": sample.source,
            "clock_provenance": sample.clock_provenance,
            "clock_uncertainty_ns": str(sample.clock_uncertainty_ns),
            "validity": sample.validity.value,
            "quality": sample.quality.value,
            "quality_reason": sample.quality_reason,
        }

    @staticmethod
    def _time_dict(
        row: DriverTimeObservation, context: DriverContextGeneration | None
    ) -> dict[str, Any]:
        return {
            "observation_id": row.id,
            "context_id": context.context_id if context is not None else None,
            "context_generation_id": context.id if context is not None else None,
            "driver_host_generation": row.host_generation_id,
            "time_unix_ns": str(row.time_unix_ns),
            "acquired_at_unix_ns": str(row.acquired_at_unix_ns),
            "received_at_unix_ns": str(row.received_at_unix_ns),
            "received_at": _stored_utc(row.received_at).isoformat(),
            "clock_source": row.clock_source,
            "provenance": row.provenance,
            "uncertainty_ns": str(row.uncertainty_ns),
            "quality": row.quality,
            "validity": row.validity,
        }

    @staticmethod
    def _sample_dict(
        sample: TelemetrySample, head: TelemetryItemHead
    ) -> dict[str, Any]:
        return {
            "sample_id": sample.id,
            "observation_id": sample.observation_id,
            "context_generation_id": sample.context_generation_id,
            "item_id": sample.item_id,
            "qualified_name": sample.qualified_name,
            "catalog_digest": sample.catalog_digest,
            "source_id": sample.source_id,
            "source_epoch": sample.source_epoch,
            "source_sequence": str(sample.source_sequence),
            "raw_value": sample.raw_value,
            "engineering_value": sample.engineering_value,
            "description": sample.description,
            "unit": sample.unit,
            "acquired_at_unix_ns": str(sample.acquired_at_unix_ns),
            "received_at_unix_ns": str(sample.received_at_unix_ns),
            "received_at": _stored_utc(sample.received_at).isoformat(),
            "source": sample.source,
            "clock_provenance": sample.clock_provenance,
            "clock_uncertainty_ns": str(sample.clock_uncertainty_ns),
            "validity": sample.validity,
            "quality": sample.quality,
            "quality_reason": sample.quality_reason,
            "freshness": head.freshness,
            "freshness_policy_revision": sample.freshness_policy_revision,
            "synchronization_state": head.synchronization_state,
        }

    def _sample_projection(
        self, session: Session, sample: TelemetrySample
    ) -> dict[str, Any]:
        head = session.scalar(
            select(TelemetryItemHead).where(
                TelemetryItemHead.context_generation_id == sample.context_generation_id,
                TelemetryItemHead.item_id == sample.item_id,
            )
        )
        if head is None:
            raise ObservationConflictError("telemetry sample head is incomplete")
        result = self._sample_dict(sample, head)
        alarm_head = session.scalar(
            select(TelemetryAlarmHead).where(
                TelemetryAlarmHead.context_generation_id == sample.context_generation_id,
                TelemetryAlarmHead.item_id == sample.item_id,
            )
        )
        result["alarm"] = None
        if alarm_head is not None:
            alarm = session.get(
                TelemetryAlarmObservation, alarm_head.alarm_observation_id
            )
            if alarm is not None:
                result["alarm"] = self._alarm_dict(session, alarm)
        return result

    @staticmethod
    def _gap_dict(gap: TelemetryGap) -> dict[str, Any]:
        return {
            "gap_id": gap.id,
            "context_generation_id": gap.context_generation_id,
            "source_id": gap.source_id,
            "item_id": gap.item_id,
            "source_epoch": gap.source_epoch,
            "expected_source_sequence": str(gap.expected_sequence),
            "observed_source_sequence": str(gap.observed_sequence),
            "state": gap.state,
            "detected_at": _stored_utc(gap.detected_at).isoformat(),
        }

    @staticmethod
    def _limit_dict(limit: TelemetryLimitSet) -> dict[str, Any]:
        return {
            "limit_set_id": limit.limit_set_id,
            "item_id": limit.item_id,
            "catalog_digest": limit.catalog_digest,
            "limit_revision": limit.limit_revision,
            "value_domain": limit.value_domain,
            "unit": limit.unit,
            "bands": limit.bands,
            "definition_digest": limit.definition_digest,
        }

    def _evaluate_alarm(
        self,
        session: Session,
        stream: ObservationStream,
        sample: TelemetrySample,
        head: TelemetryItemHead,
        *,
        evaluated_at: datetime,
    ) -> TelemetryAlarmObservation:
        limit_head = session.scalar(
            select(TelemetryLimitHead).where(
                TelemetryLimitHead.item_id == sample.item_id,
                TelemetryLimitHead.catalog_digest == sample.catalog_digest,
            )
        )
        limit = (
            session.get(TelemetryLimitSet, limit_head.limit_definition_id)
            if limit_head is not None
            else None
        )
        state, severity, boolean_value, reason, evaluated_value = self._alarm_state(
            sample, head, limit
        )
        prior_head = session.scalar(
            select(TelemetryAlarmHead)
            .where(
                TelemetryAlarmHead.context_generation_id == sample.context_generation_id,
                TelemetryAlarmHead.item_id == sample.item_id,
            )
            .with_for_update()
        )
        transition = (
            prior_head is None
            or prior_head.state != state
            or prior_head.sample_id != sample.id
            or prior_head.reason != reason
            or prior_head.limit_definition_id != (limit.id if limit else None)
        )
        projected_sequence = stream.last_sequence
        event_type = (
            "telemetry.alarm_indeterminate"
            if state == "INDETERMINATE"
            else "telemetry.alarm_changed"
        )
        if transition:
            projected_sequence = stream.last_sequence + 1
        alarm_payload = {
            "context_generation_id": sample.context_generation_id,
            "item_id": sample.item_id,
            "sample_id": sample.id,
            "limit_definition_id": limit.id if limit is not None else None,
            "state": state,
            "severity": severity,
            "evaluated_value": evaluated_value,
            "quality": sample.quality,
            "validity": sample.validity,
            "freshness": head.freshness,
            "boolean_value": boolean_value,
            "stream_epoch": stream.stream_epoch,
            "projection_sequence": projected_sequence,
            "reason": reason,
        }
        alarm = TelemetryAlarmObservation(
            context_generation_id=sample.context_generation_id,
            item_id=sample.item_id,
            sample_id=sample.id,
            limit_definition_id=limit.id if limit is not None else None,
            state=state,
            severity=severity,
            evaluated_value=evaluated_value,
            quality=sample.quality,
            validity=sample.validity,
            freshness=head.freshness,
            boolean_value=boolean_value,
            stream_epoch=stream.stream_epoch,
            projection_sequence=projected_sequence,
            evaluated_at=evaluated_at,
            reason=reason,
            payload_digest=_canonical_digest(alarm_payload),
        )
        session.add(alarm)
        session.flush()
        if prior_head is None:
            prior_head = TelemetryAlarmHead(
                context_generation_id=sample.context_generation_id,
                item_id=sample.item_id,
                alarm_observation_id=alarm.id,
                state=state,
                sample_id=sample.id,
                limit_definition_id=limit.id if limit else None,
                reason=reason,
                revision=0,
                updated_at=evaluated_at,
            )
            session.add(prior_head)
        else:
            prior_head.alarm_observation_id = alarm.id
            prior_head.state = state
            prior_head.sample_id = sample.id
            prior_head.limit_definition_id = limit.id if limit else None
            prior_head.reason = reason
            prior_head.revision += 1
            prior_head.updated_at = evaluated_at
        if transition:
            self._emit(
                session,
                stream,
                event_type=event_type,
                aggregate_type="telemetry_alarm",
                aggregate_id=sample.item_id,
                data=self._alarm_dict(session, alarm),
                created_at=evaluated_at,
            )
        return alarm

    @staticmethod
    def _alarm_state(
        sample: TelemetrySample,
        head: TelemetryItemHead,
        limit: TelemetryLimitSet | None,
    ) -> tuple[str, str, bool | None, str, dict[str, Any] | None]:
        value = sample.engineering_value if limit is None or limit.value_domain == "ENGINEERING" else sample.raw_value
        if sample.validity != "VALID":
            return "INDETERMINATE", "INDETERMINATE", None, "VALIDITY_UNACCEPTABLE", value
        if sample.quality != "GOOD":
            return "INDETERMINATE", "INDETERMINATE", None, "QUALITY_UNACCEPTABLE", value
        if head.freshness != "FRESH":
            return "INDETERMINATE", "INDETERMINATE", None, "FRESHNESS_UNACCEPTABLE", value
        if head.synchronization_state != "COMPLETE":
            return "INDETERMINATE", "INDETERMINATE", None, "SOURCE_SEQUENCE_GAP", value
        if limit is None:
            return "INDETERMINATE", "INDETERMINATE", None, "LIMIT_SET_UNAVAILABLE", value
        if limit.value_domain == "ENGINEERING" and sample.unit != limit.unit:
            return "INDETERMINATE", "INDETERMINATE", None, "UNIT_MISMATCH", value
        if value.get("type") not in {
            ScalarKind.INT64.value,
            ScalarKind.UINT64.value,
            ScalarKind.FINITE_DOUBLE.value,
        }:
            return "INDETERMINATE", "INDETERMINATE", None, "TYPE_MISMATCH", value
        try:
            numeric = float(value["value"])
        except (KeyError, TypeError, ValueError, OverflowError):
            return "INDETERMINATE", "INDETERMINATE", None, "TYPE_MISMATCH", value

        tests = (
            ("HARD_LOW", "CRITICAL_LOW", "CRITICAL", lambda a, b: a < b),
            ("HARD_HIGH", "CRITICAL_HIGH", "CRITICAL", lambda a, b: a > b),
            ("SOFT_LOW", "WARNING_LOW", "WARNING", lambda a, b: a < b),
            ("SOFT_HIGH", "WARNING_HIGH", "WARNING", lambda a, b: a > b),
        )
        for band_name, state, severity, comparison in tests:
            band = limit.bands.get(band_name)
            if not isinstance(band, dict) or not band.get("enabled"):
                continue
            threshold = band.get("threshold")
            if not isinstance(threshold, dict):
                return "INDETERMINATE", "INDETERMINATE", None, "LIMIT_SET_INVALID", value
            try:
                threshold_value = float(threshold["value"])
            except (KeyError, TypeError, ValueError, OverflowError):
                return "INDETERMINATE", "INDETERMINATE", None, "LIMIT_SET_INVALID", value
            hit = comparison(numeric, threshold_value)
            if band.get("inclusive") and numeric == threshold_value:
                hit = True
            if hit:
                return state, severity, True, band_name, value
        return "NOT_ALARMED", "NONE", False, "WITHIN_LIMITS", value

    def _alarm_dict(
        self, session: Session, alarm: TelemetryAlarmObservation
    ) -> dict[str, Any]:
        limit = (
            session.get(TelemetryLimitSet, alarm.limit_definition_id)
            if alarm.limit_definition_id is not None
            else None
        )
        return {
            "alarm_observation_id": alarm.id,
            "item_id": alarm.item_id,
            "sample_id": alarm.sample_id,
            "limit_set_id": limit.limit_set_id if limit is not None else None,
            "limit_revision": limit.limit_revision if limit is not None else None,
            "state": alarm.state,
            "severity": alarm.severity,
            "evaluated_engineering_value": alarm.evaluated_value,
            "quality": alarm.quality,
            "validity": alarm.validity,
            "freshness": alarm.freshness,
            "boolean_value": alarm.boolean_value,
            "snapshot_cursor": {
                "stream_epoch": alarm.stream_epoch,
                "projection_sequence": str(alarm.projection_sequence),
            },
            "evaluated_at_database_time": _stored_utc(alarm.evaluated_at).isoformat(),
            "reason": alarm.reason,
        }

    @staticmethod
    def _emit(
        session: Session,
        stream: ObservationStream,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        data: dict[str, Any],
        created_at: datetime,
    ) -> ObservationOutboxEvent:
        if stream.last_sequence >= MAX_OBSERVATION_SEQUENCE:
            raise ObservationConflictError("observation projection sequence is exhausted")
        stream.last_sequence += 1
        stream.revision += 1
        stream.updated_at = created_at
        event_id = new_id()
        envelope = {
            "schema_version": OBSERVATION_EVENT_SCHEMA,
            "stream": OBSERVATION_STREAM,
            "stream_epoch": stream.stream_epoch,
            "projection_sequence": stream.last_sequence,
            "event_id": event_id,
            "event_type": event_type,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "data": data,
        }
        row = ObservationOutboxEvent(
            id=event_id,
            stream_id=stream.id,
            stream_epoch=stream.stream_epoch,
            projection_sequence=stream.last_sequence,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            payload=envelope,
            delivery_attempts=0,
            created_at=created_at,
        )
        session.add(row)
        session.flush()
        return row

    @staticmethod
    def _event_dict(row: ObservationOutboxEvent) -> dict[str, Any]:
        event = {
            **row.payload,
            "created_at": _stored_utc(row.created_at).isoformat(),
        }
        event["projection_sequence"] = str(row.projection_sequence)
        return event


__all__ = [
    "DEFAULT_AUTHORIZATION_SCOPE",
    "MAX_OBSERVATION_REPLAY",
    "MAX_OBSERVATION_SEQUENCE",
    "OBSERVATION_EVENT_SCHEMA",
    "OBSERVATION_SNAPSHOT_SCHEMA",
    "OBSERVATION_STREAM",
    "ObservationClockError",
    "ObservationConflictError",
    "ObservationNotFoundError",
    "ObservationRepository",
    "ObservationRepositoryError",
    "ObservationStaleGenerationError",
    "ObservationValidationError",
]
