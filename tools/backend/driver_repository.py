from __future__ import annotations

import base64
import binascii
import json
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from spell.driver.configuration import canonical_configuration_digest

from .driver_domain import CAPABILITY_MATRIX, ResultCode
from .driver_models import (
    BINDING_STATES,
    CONTEXT_STATES,
    EFFECT_CERTAINTIES,
    HOST_STATES,
    LIFECYCLE_EFFECT_CLASSES,
    LIFECYCLE_METHODS,
    OPERATION_STAGES,
    DriverAuditEvent,
    DriverBinding,
    DriverCapability,
    DriverContext,
    DriverContextGeneration,
    DriverHostGeneration,
    DriverOperation,
    DriverOperationAttempt,
    DriverOperationTransition,
    DriverOutboxEvent,
    DriverProfile,
)
from .driver_serialization import (
    binding_dict,
    context_generation_dict,
    driver_dict,
    operation_dict,
)
from .models import new_id


DEFAULT_PROFILE_ID = "local-synthetic-simulator"
DEFAULT_PROFILE_DIGEST = "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
DRIVER_EVENT_SCHEMA = "spell.driver.event/1"
DRIVER_EVENT_TOPIC = "driver.lifecycle"
MAX_DRIVER_EVENT_REPLAY = 10_001
MAX_DRIVER_EVENT_SEQUENCE = 9_223_372_036_854_775_807
READ_METHODS = ("Handshake", "Health", "GetOperation")
ALL_RPC_METHODS = READ_METHODS + LIFECYCLE_METHODS
_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_METHOD_EFFECT = dict(zip(LIFECYCLE_METHODS, LIFECYCLE_EFFECT_CLASSES))
_RESULT_CODES = frozenset(item.value for item in ResultCode)
_STAGE_RANK = {stage: index for index, stage in enumerate(OPERATION_STAGES)}
_HOST_TRANSITIONS = {
    "STARTING": {"STARTING", "READY", "DEGRADED", "DRAINING", "FAILED"},
    "READY": {"READY", "DEGRADED", "DRAINING", "FAILED"},
    "DEGRADED": {"DEGRADED", "READY", "DRAINING", "FAILED"},
    "DRAINING": {"DRAINING", "CLOSED", "DEGRADED", "FAILED"},
    "CLOSED": {"CLOSED"},
    "FAILED": {"FAILED"},
}
_CONTEXT_TRANSITIONS = {
    "OPENING": {"OPENING", "ACTIVE", "DEGRADED", "CLOSING", "FAILED"},
    "ACTIVE": {"ACTIVE", "DEGRADED", "CLOSING", "FAILED"},
    "DEGRADED": {"DEGRADED", "ACTIVE", "CLOSING", "FAILED"},
    "CLOSING": {"CLOSING", "CLOSED", "DEGRADED", "FAILED"},
    "CLOSED": {"CLOSED"},
    "FAILED": {"FAILED"},
}
_BINDING_TRANSITIONS = {
    "ATTACHING": {"ATTACHING", "ATTACHED", "DETACHING", "FAILED"},
    "ATTACHED": {"ATTACHED", "DETACHING", "FAILED"},
    "DETACHING": {"DETACHING", "DETACHED", "FAILED"},
    "DETACHED": {"DETACHED"},
    "FAILED": {"FAILED"},
}
_CERTAINTY_TRANSITIONS = {
    "NO_EFFECT": {"NO_EFFECT", "EFFECT_POSSIBLE"},
    "EFFECT_POSSIBLE": {
        "EFFECT_POSSIBLE",
        "NO_EFFECT",
        "EFFECT_CONFIRMED",
        "EFFECT_UNKNOWN",
    },
    "EFFECT_UNKNOWN": {"EFFECT_UNKNOWN", "NO_EFFECT", "EFFECT_CONFIRMED"},
    "EFFECT_CONFIRMED": {"EFFECT_CONFIRMED"},
}


class DriverRepositoryError(RuntimeError):
    pass


class DriverNotFoundError(DriverRepositoryError):
    pass


class DriverConflictError(DriverRepositoryError):
    pass


class DriverValidationError(DriverRepositoryError):
    pass


@dataclass(frozen=True)
class CapabilitySpec:
    service: str
    method: str
    mutability: str
    modifiers: tuple[str, ...]
    formats: tuple[str, ...]
    stream_support: str


@dataclass(frozen=True)
class ContextStateObservation:
    context_generation_id: str
    state: str
    expected_revision: int
    observed_at: datetime


@dataclass(frozen=True)
class BindingStateObservation:
    driver_binding_id: str
    state: str
    expected_revision: int
    observed_at: datetime


def _wire_value(value: str | Enum) -> str:
    return str(value.value) if isinstance(value, Enum) else str(value)


def _bounded(value: str | Enum, label: str, maximum: int) -> str:
    resolved = _wire_value(value)
    if not resolved or resolved != resolved.strip() or len(resolved) > maximum:
        raise DriverValidationError(f"{label} is invalid")
    return resolved


def _identifier(value: str | Enum, label: str) -> str:
    resolved = _wire_value(value)
    if not _IDENTIFIER.fullmatch(resolved):
        raise DriverValidationError(f"{label} is not a bounded identifier")
    return resolved


def _optional_identifier(value: str | Enum | None, label: str) -> str | None:
    return _identifier(value, label) if value is not None else None


def _digest(value: str, label: str) -> str:
    if not _LOWER_HEX_64.fullmatch(value):
        raise DriverValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DriverValidationError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _cursor(kind: str, last_id: str) -> str:
    raw = json.dumps(
        {"kind": kind, "last_id": last_id, "version": 1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_cursor(kind: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not value or len(value) > 512 or not value.isascii():
        raise DriverValidationError("cursor is invalid")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
        decoded = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DriverValidationError("cursor is invalid") from exc
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"kind", "last_id", "version"}
        or decoded.get("kind") != kind
        or decoded.get("version") != 1
        or not isinstance(decoded.get("last_id"), str)
        or not decoded["last_id"]
        or not _IDENTIFIER.fullmatch(decoded["last_id"])
        or _cursor(kind, decoded["last_id"]) != value
    ):
        raise DriverValidationError("cursor is invalid")
    return decoded["last_id"]


class DriverRepository:
    """Canonical project-database boundary for the v0.4 driver foundation."""

    def __init__(self, session_factory: sessionmaker[Session]):
        self.session_factory = session_factory
        self._lock = threading.RLock()

    def set_profile_enabled(
        self,
        profile_id: str,
        enabled: bool,
        *,
        expected_revision: int,
        actor: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        profile_id = _identifier(profile_id, "profile_id")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                profile = session.get(DriverProfile, profile_id, with_for_update=True)
                if profile is None:
                    raise DriverNotFoundError("driver profile not found")
                if profile.revision != expected_revision:
                    raise DriverConflictError("driver profile revision conflict")
                if profile.enabled == enabled:
                    return self._driver_view_in_session(session, profile)
                self._apply_profile_enabled(
                    session, profile, enabled, actor=actor, correlation_id=correlation_id
                )
                session.commit()
                return self._driver_view_in_session(session, profile)
            except Exception:
                session.rollback()
                raise

    def configure_profile_enabled(
        self,
        profile_id: str,
        enabled: bool,
        *,
        actor: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        """Idempotently reconcile startup configuration against the profile row."""

        profile_id = _identifier(profile_id, "profile_id")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                profile = session.get(DriverProfile, profile_id, with_for_update=True)
                if profile is None:
                    raise DriverNotFoundError("driver profile not found")
                if profile.enabled == enabled:
                    return {"driver": self._driver_view_in_session(session, profile)}
                self._apply_profile_enabled(
                    session, profile, enabled, actor=actor, correlation_id=correlation_id
                )
                session.commit()
                return {"driver": self._driver_view_in_session(session, profile)}
            except Exception:
                session.rollback()
                raise

    def get_profile_configuration(self, profile_id: str) -> dict[str, Any]:
        """Return the canonical non-secret profile tuple used for handshakes."""

        profile_id = _identifier(profile_id, "profile_id")
        with self._lock, self.session_factory() as session:
            profile = session.get(DriverProfile, profile_id)
            if profile is None:
                raise DriverNotFoundError("driver profile not found")
            return self._profile_configuration_dict(profile)

    def rotate_profile_credentials(
        self,
        profile_id: str,
        *,
        credential_reference: str,
        credential_epoch: int,
        configuration_digest: str,
        expected_revision: int,
        actor: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        """Fence a credential rotation without accepting secret material."""

        profile_id = _identifier(profile_id, "profile_id")
        credential_reference = _identifier(
            credential_reference, "credential_reference"
        )
        if isinstance(credential_epoch, bool) or not isinstance(credential_epoch, int):
            raise DriverValidationError("credential_epoch must be an integer")
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
            raise DriverValidationError("expected_revision must be an integer")
        configuration_digest = _digest(
            configuration_digest, "configuration_digest"
        )
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")

        with self._lock, self.session_factory() as session:
            try:
                profile = session.get(DriverProfile, profile_id, with_for_update=True)
                if profile is None:
                    raise DriverNotFoundError("driver profile not found")
                if profile.revision != expected_revision:
                    raise DriverConflictError("driver profile revision conflict")
                if credential_epoch != profile.credential_epoch + 1:
                    raise DriverConflictError(
                        "credential epoch must advance by exactly one"
                    )
                latest_host = session.scalar(
                    select(DriverHostGeneration)
                    .where(DriverHostGeneration.profile_id == profile.id)
                    .order_by(DriverHostGeneration.generation_number.desc())
                    .limit(1)
                )
                if latest_host is not None and latest_host.state not in {
                    "CLOSED",
                    "FAILED",
                }:
                    raise DriverConflictError(
                        "driver host generation must be terminal before rotation"
                    )

                current_digest = self._canonical_profile_digest(
                    profile, credential_reference=profile.credential_reference
                )
                if profile.configuration_digest != current_digest:
                    raise DriverConflictError(
                        "stored driver profile digest does not bind its configuration"
                    )
                expected_digest = self._canonical_profile_digest(
                    profile, credential_reference=credential_reference
                )
                if configuration_digest != expected_digest:
                    raise DriverValidationError(
                        "configuration_digest does not bind the rotated profile"
                    )

                prior_epoch = profile.credential_epoch
                prior_reference = profile.credential_reference
                prior_digest = profile.configuration_digest
                profile.credential_reference = credential_reference
                profile.credential_epoch = credential_epoch
                profile.configuration_digest = configuration_digest
                profile.revision += 1
                profile.updated_at = datetime.now(timezone.utc)
                self._record_event(
                    session,
                    event_type="driver.profile_credentials_rotated",
                    aggregate_type="driver_profile",
                    aggregate_id=profile.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "profile_id": profile.id,
                        "prior_credential_reference": prior_reference,
                        "credential_reference": profile.credential_reference,
                        "prior_credential_epoch": prior_epoch,
                        "credential_epoch": profile.credential_epoch,
                        "prior_configuration_digest": prior_digest,
                        "configuration_digest": profile.configuration_digest,
                        "revision": profile.revision,
                    },
                )
                session.commit()
                return self._profile_configuration_dict(profile)
            except Exception:
                session.rollback()
                raise

    def create_host_generation(
        self,
        *,
        profile_id: str,
        host_generation_id: str,
        contract_version: str,
        implementation_version: str,
        capabilities: Iterable[CapabilitySpec],
        actor: str,
        correlation_id: str,
    ) -> DriverHostGeneration:
        profile_id = _identifier(profile_id, "profile_id")
        host_generation_id = _identifier(host_generation_id, "host_generation_id")
        contract_version = _bounded(contract_version, "contract_version", 40)
        implementation_version = _bounded(
            implementation_version, "implementation_version", 80
        )
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        parsed_capabilities = self._validate_capabilities(tuple(capabilities))
        with self._lock, self.session_factory() as session:
            try:
                profile = session.get(DriverProfile, profile_id, with_for_update=True)
                if profile is None:
                    raise DriverNotFoundError("driver profile not found")
                if not profile.enabled:
                    raise DriverConflictError("driver profile is disabled")
                if session.get(DriverHostGeneration, host_generation_id) is not None:
                    raise DriverConflictError("driver host generation already exists")
                prior = session.scalar(
                    select(DriverHostGeneration)
                    .where(DriverHostGeneration.profile_id == profile.id)
                    .order_by(DriverHostGeneration.generation_number.desc())
                    .limit(1)
                )
                if prior is not None and prior.state not in {"CLOSED", "FAILED"}:
                    raise DriverConflictError("prior driver host generation is not fenced")
                generation_number = 1 if prior is None else prior.generation_number + 1
                host = DriverHostGeneration(
                    id=host_generation_id,
                    profile_id=profile.id,
                    generation_number=generation_number,
                    logical_driver_id=profile.logical_driver_id,
                    simulator=profile.simulator,
                    contract_version=contract_version,
                    implementation_version=implementation_version,
                    configuration_schema_version=profile.configuration_schema_version,
                    configuration_digest=profile.configuration_digest,
                    credential_epoch=profile.credential_epoch,
                    state="STARTING",
                    ready=False,
                    max_contexts=profile.max_contexts_per_host,
                    contexts_in_use=0,
                    max_lifecycle_operations=profile.max_lifecycle_operations_per_host,
                    lifecycle_operations_in_use=0,
                    revision=0,
                )
                session.add(host)
                session.flush()
                for capability in parsed_capabilities:
                    session.add(
                        DriverCapability(
                            host_generation_id=host.id,
                            service=capability.service,
                            method=capability.method,
                            modifiers=list(capability.modifiers),
                            formats=list(capability.formats),
                            mutability=capability.mutability,
                            stream_support=capability.stream_support,
                        )
                    )
                self._record_event(
                    session,
                    event_type="driver.host_generation_created",
                    aggregate_type="driver_host_generation",
                    aggregate_id=host.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "profile_id": profile.id,
                        "host_generation_id": host.id,
                        "generation_number": host.generation_number,
                        "configuration_digest": host.configuration_digest,
                        "state": host.state,
                    },
                )
                session.commit()
                session.refresh(host)
                session.expunge(host)
                return host
            except IntegrityError as exc:
                session.rollback()
                raise DriverConflictError("driver host generation conflicts with canonical state") from exc
            except Exception:
                session.rollback()
                raise

    def record_host_state(
        self,
        host_generation_id: str,
        state: str | Enum,
        *,
        expected_revision: int,
        actor: str,
        correlation_id: str,
        observed_at: datetime,
    ) -> DriverHostGeneration:
        host_generation_id = _identifier(host_generation_id, "host_generation_id")
        state = _wire_value(state)
        if state not in HOST_STATES:
            raise DriverValidationError("host state is invalid")
        observed_at = _aware(observed_at, "observed_at")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                host = session.get(DriverHostGeneration, host_generation_id, with_for_update=True)
                if host is None:
                    raise DriverNotFoundError("driver host generation not found")
                if host.revision != expected_revision:
                    raise DriverConflictError("driver host generation revision conflict")
                if state not in _HOST_TRANSITIONS[host.state]:
                    raise DriverConflictError("invalid driver host state transition")
                host.state = state
                host.ready = state == "READY"
                host.last_observed_at = observed_at
                host.revision += 1
                if state == "CLOSED" and host.closed_at is None:
                    host.closed_at = observed_at
                self._record_event(
                    session,
                    event_type="driver.host_state_changed",
                    aggregate_type="driver_host_generation",
                    aggregate_id=host.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "host_generation_id": host.id,
                        "state": host.state,
                        "ready": host.ready,
                        "revision": host.revision,
                    },
                )
                session.commit()
                session.refresh(host)
                session.expunge(host)
                return host
            except Exception:
                session.rollback()
                raise

    def create_context_generation(
        self,
        *,
        profile_id: str,
        host_generation_id: str,
        context_id: str,
        context_generation_id: str,
        configuration_schema_version: str,
        configuration_digest: str,
        actor: str,
        correlation_id: str,
    ) -> DriverContextGeneration:
        profile_id = _identifier(profile_id, "profile_id")
        host_generation_id = _identifier(host_generation_id, "host_generation_id")
        context_id = _identifier(context_id, "context_id")
        context_generation_id = _identifier(
            context_generation_id, "context_generation_id"
        )
        configuration_schema_version = _bounded(
            configuration_schema_version, "configuration_schema_version", 128
        )
        configuration_digest = _digest(configuration_digest, "configuration_digest")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                profile = session.get(DriverProfile, profile_id, with_for_update=True)
                host = session.get(DriverHostGeneration, host_generation_id, with_for_update=True)
                if profile is None or host is None or host.profile_id != profile.id:
                    raise DriverNotFoundError("driver profile or host generation not found")
                if not profile.enabled or host.state != "READY" or not host.ready:
                    raise DriverConflictError("driver host is not ready")
                if host.configuration_digest != profile.configuration_digest:
                    raise DriverConflictError("driver host configuration is stale")
                if host.contexts_in_use >= host.max_contexts:
                    raise DriverConflictError("driver host context capacity is exhausted")
                if session.get(DriverContextGeneration, context_generation_id) is not None:
                    raise DriverConflictError("context generation already exists")
                context = session.get(DriverContext, context_id, with_for_update=True)
                if context is None:
                    context = DriverContext(id=context_id, profile_id=profile.id)
                    session.add(context)
                    session.flush()
                elif context.profile_id != profile.id:
                    raise DriverConflictError("context belongs to another driver profile")
                prior = session.scalar(
                    select(DriverContextGeneration)
                    .where(DriverContextGeneration.context_id == context.id)
                    .order_by(DriverContextGeneration.generation_number.desc())
                    .limit(1)
                )
                if prior is not None and prior.state not in {"CLOSED", "FAILED"}:
                    raise DriverConflictError("prior context generation is not settled")
                generation_number = 1 if prior is None else prior.generation_number + 1
                generation = DriverContextGeneration(
                    id=context_generation_id,
                    context_id=context.id,
                    host_generation_id=host.id,
                    generation_number=generation_number,
                    configuration_schema_version=configuration_schema_version,
                    configuration_digest=configuration_digest,
                    parent_host_configuration_digest=host.configuration_digest,
                    state="OPENING",
                    ready=False,
                    max_attachments=profile.max_attachments_per_context,
                    attachments_in_use=0,
                    max_lifecycle_operations=profile.max_lifecycle_operations_per_context,
                    lifecycle_operations_in_use=0,
                    revision=0,
                )
                host.contexts_in_use += 1
                host.revision += 1
                session.add(generation)
                session.flush()
                self._record_event(
                    session,
                    event_type="driver.context_generation_created",
                    aggregate_type="driver_context_generation",
                    aggregate_id=generation.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "context_id": context.id,
                        "context_generation_id": generation.id,
                        "generation_number": generation.generation_number,
                        "host_generation_id": host.id,
                        "configuration_digest": generation.configuration_digest,
                        "state": generation.state,
                    },
                )
                session.commit()
                session.refresh(generation)
                session.expunge(generation)
                return generation
            except IntegrityError as exc:
                session.rollback()
                raise DriverConflictError("context generation conflicts with canonical state") from exc
            except Exception:
                session.rollback()
                raise

    def record_context_state(
        self,
        context_generation_id: str,
        state: str | Enum,
        *,
        expected_revision: int,
        actor: str,
        correlation_id: str,
        observed_at: datetime,
    ) -> DriverContextGeneration:
        context_generation_id = _identifier(
            context_generation_id, "context_generation_id"
        )
        state = _wire_value(state)
        if state not in CONTEXT_STATES:
            raise DriverValidationError("context state is invalid")
        observed_at = _aware(observed_at, "observed_at")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                context_probe = session.get(
                    DriverContextGeneration, context_generation_id
                )
                if context_probe is None:
                    raise DriverNotFoundError("context generation not found")
                host = session.get(
                    DriverHostGeneration,
                    context_probe.host_generation_id,
                    with_for_update=True,
                )
                context = session.scalar(
                    select(DriverContextGeneration)
                    .where(DriverContextGeneration.id == context_generation_id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if (
                    host is None
                    or context is None
                    or context.host_generation_id != host.id
                ):
                    raise DriverConflictError(
                        "context generation changed during state locking"
                    )
                if context.revision != expected_revision:
                    raise DriverConflictError("context generation revision conflict")
                if state not in _CONTEXT_TRANSITIONS[context.state]:
                    raise DriverConflictError("invalid context state transition")
                prior_state = context.state
                context.state = state
                context.ready = state == "ACTIVE"
                context.last_observed_at = observed_at
                context.revision += 1
                if state == "CLOSED" and prior_state != "CLOSED":
                    if context.attachments_in_use:
                        raise DriverConflictError("context still has reserved attachments")
                    if host.contexts_in_use <= 0:
                        raise DriverConflictError("host context capacity is inconsistent")
                    host.contexts_in_use -= 1
                    host.revision += 1
                    context.closed_at = observed_at
                self._record_event(
                    session,
                    event_type="driver.context_state_changed",
                    aggregate_type="driver_context_generation",
                    aggregate_id=context.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "context_id": context.context_id,
                        "context_generation_id": context.id,
                        "state": context.state,
                        "ready": context.ready,
                        "revision": context.revision,
                    },
                )
                session.commit()
                session.refresh(context)
                session.expunge(context)
                return context
            except Exception:
                session.rollback()
                raise

    def create_binding(
        self,
        *,
        context_generation_id: str,
        driver_binding_id: str,
        execution_id: str,
        attachment_generation_id: str,
        configuration_schema_version: str,
        configuration_digest: str,
        actor: str,
        correlation_id: str,
        replaces_driver_binding_id: str | None = None,
    ) -> DriverBinding:
        context_generation_id = _identifier(
            context_generation_id, "context_generation_id"
        )
        driver_binding_id = _identifier(driver_binding_id, "driver_binding_id")
        execution_id = _identifier(execution_id, "execution_id")
        attachment_generation_id = _identifier(
            attachment_generation_id, "attachment_generation_id"
        )
        configuration_schema_version = _bounded(
            configuration_schema_version, "configuration_schema_version", 128
        )
        configuration_digest = _digest(configuration_digest, "configuration_digest")
        replaces_driver_binding_id = _optional_identifier(
            replaces_driver_binding_id, "replaces_driver_binding_id"
        )
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                context_probe = session.get(
                    DriverContextGeneration, context_generation_id
                )
                if context_probe is None:
                    raise DriverNotFoundError("context generation not found")
                host = session.get(
                    DriverHostGeneration,
                    context_probe.host_generation_id,
                    with_for_update=True,
                )
                context = session.scalar(
                    select(DriverContextGeneration)
                    .where(DriverContextGeneration.id == context_generation_id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if (
                    host is None
                    or context is None
                    or context.host_generation_id != host.id
                ):
                    raise DriverConflictError(
                        "context generation changed during admission locking"
                    )
                if context.state != "ACTIVE" or not context.ready:
                    raise DriverConflictError("context generation is not active")
                if replaces_driver_binding_id is not None:
                    active_operation = session.scalar(
                        select(DriverOperation)
                        .where(
                            DriverOperation.host_generation_id == host.id,
                            DriverOperation.stage != "SETTLED",
                        )
                        .order_by(DriverOperation.id)
                        .limit(1)
                        .with_for_update()
                    )
                    if active_operation is not None:
                        raise DriverConflictError(
                            "reload replacement conflicts with active lifecycle work"
                        )
                host_bindings = list(
                    session.scalars(
                        select(DriverBinding)
                    .join(
                        DriverContextGeneration,
                        DriverBinding.context_generation_id
                        == DriverContextGeneration.id,
                    )
                    .where(
                        DriverContextGeneration.host_generation_id == host.id,
                    )
                    .order_by(DriverBinding.id)
                    .with_for_update()
                    ).all()
                )
                if any(item.id == driver_binding_id for item in host_bindings):
                    raise DriverConflictError("driver binding already exists")
                pending_replacement = next(
                    (item for item in host_bindings if item.replacement_pending),
                    None,
                )
                if pending_replacement is not None:
                    raise DriverConflictError(
                        "unresolved reload replacement blocks binding creation"
                    )
                replacement = None
                if replaces_driver_binding_id is not None:
                    replacement = next(
                        (
                            item
                            for item in host_bindings
                            if item.id == replaces_driver_binding_id
                        ),
                        None,
                    )
                    if (
                        replacement is None
                        or replacement.context_generation_id != context.id
                        or replacement.execution_id != execution_id
                        or replacement.state != "ATTACHED"
                    ):
                        raise DriverConflictError(
                            "reload replacement binding is not currently attached"
                        )
                elif context.attachments_in_use >= context.max_attachments:
                    raise DriverConflictError("context attachment capacity is exhausted")
                prior = session.scalar(
                    select(DriverBinding)
                    .where(DriverBinding.execution_id == execution_id)
                    .order_by(DriverBinding.attachment_generation_number.desc())
                    .limit(1)
                )
                if replacement is not None and (
                    prior is None or prior.id != replacement.id
                ):
                    raise DriverConflictError(
                        "reload replacement is not the latest execution attachment"
                    )
                if (
                    replacement is None
                    and prior is not None
                    and prior.state not in {"DETACHED", "FAILED"}
                ):
                    raise DriverConflictError("prior execution attachment is not settled")
                generation_number = (
                    1 if prior is None else prior.attachment_generation_number + 1
                )
                binding = DriverBinding(
                    id=driver_binding_id,
                    context_generation_id=context.id,
                    replacement_of_binding_id=(
                        replacement.id if replacement is not None else None
                    ),
                    capacity_reserved=replacement is None,
                    replacement_pending=replacement is not None,
                    execution_id=execution_id,
                    attachment_generation_id=attachment_generation_id,
                    attachment_generation_number=generation_number,
                    configuration_schema_version=configuration_schema_version,
                    configuration_digest=configuration_digest,
                    parent_context_configuration_digest=context.configuration_digest,
                    state="ATTACHING",
                    revision=0,
                )
                if replacement is None:
                    context.attachments_in_use += 1
                context.revision += 1
                session.add(binding)
                session.flush()
                self._record_event(
                    session,
                    event_type="driver.binding_created",
                    aggregate_type="driver_binding",
                    aggregate_id=binding.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "driver_binding_id": binding.id,
                        "execution_id": binding.execution_id,
                        "context_generation_id": context.id,
                        "replacement_of_driver_binding_id": (
                            replacement.id if replacement is not None else None
                        ),
                        "capacity_reserved": binding.capacity_reserved,
                        "replacement_pending": binding.replacement_pending,
                        "attachment_generation_id": binding.attachment_generation_id,
                        "attachment_generation_number": binding.attachment_generation_number,
                        "configuration_digest": binding.configuration_digest,
                        "state": binding.state,
                    },
                )
                session.commit()
                session.refresh(binding)
                session.expunge(binding)
                return binding
            except IntegrityError as exc:
                session.rollback()
                raise DriverConflictError("driver binding conflicts with canonical state") from exc
            except Exception:
                session.rollback()
                raise

    def record_binding_state(
        self,
        driver_binding_id: str,
        state: str | Enum,
        *,
        expected_revision: int,
        actor: str,
        correlation_id: str,
        observed_at: datetime,
    ) -> DriverBinding:
        driver_binding_id = _identifier(driver_binding_id, "driver_binding_id")
        state = _wire_value(state)
        if state not in BINDING_STATES:
            raise DriverValidationError("binding state is invalid")
        observed_at = _aware(observed_at, "observed_at")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                binding_probe = session.get(DriverBinding, driver_binding_id)
                if binding_probe is None:
                    raise DriverNotFoundError("driver binding not found")
                context_probe = session.get(
                    DriverContextGeneration, binding_probe.context_generation_id
                )
                if context_probe is None:
                    raise DriverConflictError("driver binding context is missing")
                host = session.get(
                    DriverHostGeneration,
                    context_probe.host_generation_id,
                    with_for_update=True,
                )
                context = session.scalar(
                    select(DriverContextGeneration)
                    .where(DriverContextGeneration.id == context_probe.id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                binding = session.scalar(
                    select(DriverBinding)
                    .where(DriverBinding.id == driver_binding_id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                if (
                    host is None
                    or context is None
                    or binding is None
                    or context.host_generation_id != host.id
                    or binding.context_generation_id != context.id
                ):
                    raise DriverConflictError(
                        "driver binding changed during state locking"
                    )
                if binding.revision != expected_revision:
                    raise DriverConflictError("driver binding revision conflict")
                if state not in _BINDING_TRANSITIONS[binding.state]:
                    raise DriverConflictError("invalid driver binding state transition")
                prior_state = binding.state
                if state in {"DETACHED", "FAILED"} and binding.capacity_reserved:
                    if context.attachments_in_use <= 0:
                        raise DriverConflictError(
                            "context attachment capacity is inconsistent"
                        )
                    context.attachments_in_use -= 1
                    context.revision += 1
                    binding.capacity_reserved = False
                binding.state = state
                binding.last_observed_at = observed_at
                binding.revision += 1
                if state == "DETACHED" and prior_state != "DETACHED":
                    binding.detached_at = observed_at
                self._record_event(
                    session,
                    event_type="driver.binding_state_changed",
                    aggregate_type="driver_binding",
                    aggregate_id=binding.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "driver_binding_id": binding.id,
                        "state": binding.state,
                        "capacity_reserved": binding.capacity_reserved,
                        "replacement_pending": binding.replacement_pending,
                        "revision": binding.revision,
                    },
                )
                session.commit()
                session.refresh(binding)
                session.expunge(binding)
                return binding
            except Exception:
                session.rollback()
                raise

    def apply_health_snapshot(
        self,
        host_generation_id: str,
        state: str | Enum,
        *,
        expected_revision: int,
        observed_at: datetime,
        contexts: Iterable[ContextStateObservation],
        bindings: Iterable[BindingStateObservation],
        actor: str,
        correlation_id: str,
    ) -> None:
        """Validate and commit one complete driver Health observation atomically."""

        host_generation_id = _identifier(host_generation_id, "host_generation_id")
        state = _wire_value(state)
        if state not in HOST_STATES:
            raise DriverValidationError("host state is invalid")
        if type(expected_revision) is not int or expected_revision < 0:
            raise DriverValidationError("host expected revision is invalid")
        observed_at = _aware(observed_at, "observed_at")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")

        parsed_contexts: list[ContextStateObservation] = []
        context_ids: set[str] = set()
        for item in contexts:
            if not isinstance(item, ContextStateObservation):
                raise DriverValidationError(
                    "context health item must be a ContextStateObservation"
                )
            context_id = _identifier(
                item.context_generation_id, "context_generation_id"
            )
            context_state = _wire_value(item.state)
            if context_state not in CONTEXT_STATES:
                raise DriverValidationError("context state is invalid")
            if type(item.expected_revision) is not int or item.expected_revision < 0:
                raise DriverValidationError("context expected revision is invalid")
            if context_id in context_ids:
                raise DriverValidationError("context health items are duplicated")
            context_ids.add(context_id)
            parsed_contexts.append(
                ContextStateObservation(
                    context_generation_id=context_id,
                    state=context_state,
                    expected_revision=item.expected_revision,
                    observed_at=_aware(item.observed_at, "context observed_at"),
                )
            )

        parsed_bindings: list[BindingStateObservation] = []
        binding_ids: set[str] = set()
        for item in bindings:
            if not isinstance(item, BindingStateObservation):
                raise DriverValidationError(
                    "binding health item must be a BindingStateObservation"
                )
            binding_id = _identifier(item.driver_binding_id, "driver_binding_id")
            binding_state = _wire_value(item.state)
            if binding_state not in BINDING_STATES:
                raise DriverValidationError("binding state is invalid")
            if type(item.expected_revision) is not int or item.expected_revision < 0:
                raise DriverValidationError("binding expected revision is invalid")
            if binding_id in binding_ids:
                raise DriverValidationError("binding health items are duplicated")
            binding_ids.add(binding_id)
            parsed_bindings.append(
                BindingStateObservation(
                    driver_binding_id=binding_id,
                    state=binding_state,
                    expected_revision=item.expected_revision,
                    observed_at=_aware(item.observed_at, "binding observed_at"),
                )
            )

        with self._lock, self.session_factory() as session:
            try:
                host = session.get(
                    DriverHostGeneration, host_generation_id, with_for_update=True
                )
                if host is None:
                    raise DriverNotFoundError("driver host generation not found")
                if host.revision != expected_revision:
                    raise DriverConflictError("driver host generation revision conflict")
                if state not in _HOST_TRANSITIONS[host.state]:
                    raise DriverConflictError("invalid driver host state transition")

                context_rows: dict[str, DriverContextGeneration] = {}
                for context_id in sorted(context_ids):
                    context = session.get(
                        DriverContextGeneration, context_id, with_for_update=True
                    )
                    if context is None:
                        raise DriverNotFoundError("context generation not found")
                    context_rows[context_id] = context

                binding_rows: dict[str, DriverBinding] = {}
                for binding_id in sorted(binding_ids):
                    binding = session.get(
                        DriverBinding, binding_id, with_for_update=True
                    )
                    if binding is None:
                        raise DriverNotFoundError("driver binding not found")
                    binding_rows[binding_id] = binding

                for item in parsed_contexts:
                    context = context_rows[item.context_generation_id]
                    if context.host_generation_id != host.id:
                        raise DriverConflictError(
                            "context generation belongs to another host"
                        )
                    if context.revision != item.expected_revision:
                        raise DriverConflictError("context generation revision conflict")
                    if item.state not in _CONTEXT_TRANSITIONS[context.state]:
                        raise DriverConflictError(
                            "invalid context generation state transition"
                        )

                release_counts = {context_id: 0 for context_id in context_ids}
                for item in parsed_bindings:
                    binding = binding_rows[item.driver_binding_id]
                    if binding.context_generation_id not in context_ids:
                        raise DriverConflictError(
                            "driver binding is outside the health context set"
                        )
                    if binding.revision != item.expected_revision:
                        raise DriverConflictError("driver binding revision conflict")
                    if item.state not in _BINDING_TRANSITIONS[binding.state]:
                        raise DriverConflictError("invalid driver binding state transition")
                    if (
                        item.state in {"DETACHED", "FAILED"}
                        and binding.capacity_reserved
                    ):
                        release_counts[binding.context_generation_id] += 1

                closing_context_count = 0
                for item in parsed_contexts:
                    context = context_rows[item.context_generation_id]
                    final_attachments = (
                        context.attachments_in_use
                        - release_counts[item.context_generation_id]
                    )
                    if final_attachments < 0:
                        raise DriverConflictError(
                            "context attachment capacity is inconsistent"
                        )
                    if (
                        item.state == "CLOSED"
                        and context.state != "CLOSED"
                        and final_attachments != 0
                    ):
                        raise DriverConflictError(
                            "context still has reserved attachments after health snapshot"
                        )
                    if item.state == "CLOSED" and context.state != "CLOSED":
                        closing_context_count += 1
                if host.contexts_in_use < closing_context_count:
                    raise DriverConflictError("host context capacity is inconsistent")

                prior_host_state = host.state
                host.state = state
                host.ready = state == "READY"
                host.last_observed_at = observed_at
                host.revision += 1
                if state == "CLOSED" and prior_host_state != "CLOSED":
                    host.closed_at = observed_at

                for item in parsed_contexts:
                    context = context_rows[item.context_generation_id]
                    prior_state = context.state
                    context.state = item.state
                    context.ready = item.state == "ACTIVE"
                    context.last_observed_at = item.observed_at
                    context.revision += 1
                    if item.state == "CLOSED" and prior_state != "CLOSED":
                        host.contexts_in_use -= 1
                        host.revision += 1
                        context.closed_at = item.observed_at

                for item in parsed_bindings:
                    binding = binding_rows[item.driver_binding_id]
                    prior_state = binding.state
                    binding.state = item.state
                    binding.last_observed_at = item.observed_at
                    binding.revision += 1
                    if item.state in {"DETACHED", "FAILED"} and binding.capacity_reserved:
                        context = context_rows[binding.context_generation_id]
                        context.attachments_in_use -= 1
                        context.revision += 1
                        binding.capacity_reserved = False
                    if item.state == "DETACHED" and prior_state != "DETACHED":
                        binding.detached_at = item.observed_at

                # Emit only after every child-induced parent revision is final.
                self._record_event(
                    session,
                    event_type="driver.host_state_changed",
                    aggregate_type="driver_host_generation",
                    aggregate_id=host.id,
                    actor=actor,
                    correlation_id=correlation_id,
                    payload={
                        "host_generation_id": host.id,
                        "state": host.state,
                        "ready": host.ready,
                        "revision": host.revision,
                    },
                )
                for item in parsed_contexts:
                    context = context_rows[item.context_generation_id]
                    self._record_event(
                        session,
                        event_type="driver.context_state_changed",
                        aggregate_type="driver_context_generation",
                        aggregate_id=context.id,
                        actor=actor,
                        correlation_id=correlation_id,
                        payload={
                            "context_id": context.context_id,
                            "context_generation_id": context.id,
                            "state": context.state,
                            "ready": context.ready,
                            "revision": context.revision,
                        },
                    )
                for item in parsed_bindings:
                    binding = binding_rows[item.driver_binding_id]
                    self._record_event(
                        session,
                        event_type="driver.binding_state_changed",
                        aggregate_type="driver_binding",
                        aggregate_id=binding.id,
                        actor=actor,
                        correlation_id=correlation_id,
                        payload={
                            "driver_binding_id": binding.id,
                            "state": binding.state,
                            "capacity_reserved": binding.capacity_reserved,
                            "replacement_pending": binding.replacement_pending,
                            "revision": binding.revision,
                        },
                    )
                session.commit()
            except Exception:
                session.rollback()
                raise

    def accept_operation(
        self,
        *,
        operation_id: str,
        attempt_id: str,
        method: str | Enum,
        request_digest: str,
        effect_class: str | Enum,
        host_generation_id: str,
        context_generation_id: str | None,
        driver_binding_id: str | None,
        target_operation_id: str | None,
        target_attempt_id: str | None,
        actor: str,
        correlation_id: str,
        deadline_at: datetime,
        lifecycle_reason: str | None = None,
        replaced_driver_binding_id: str | None = None,
    ) -> dict[str, Any]:
        operation_id = _identifier(operation_id, "operation_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        host_generation_id = _identifier(host_generation_id, "host_generation_id")
        context_generation_id = _optional_identifier(
            context_generation_id, "context_generation_id"
        )
        driver_binding_id = _optional_identifier(
            driver_binding_id, "driver_binding_id"
        )
        target_operation_id = _optional_identifier(
            target_operation_id, "target_operation_id"
        )
        target_attempt_id = _optional_identifier(target_attempt_id, "target_attempt_id")
        method = _wire_value(method)
        effect_class = _wire_value(effect_class)
        request_digest = _digest(request_digest, "request_digest")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        deadline_at = _aware(deadline_at, "deadline_at")
        replaced_driver_binding_id = _optional_identifier(
            replaced_driver_binding_id, "replaced_driver_binding_id"
        )
        if method not in LIFECYCLE_METHODS:
            raise DriverValidationError("operation method is not an effect-bearing v0.4 RPC")
        if effect_class != _METHOD_EFFECT[method]:
            raise DriverValidationError("effect class does not match operation method")
        if method == "AttachExecution":
            lifecycle_reason = lifecycle_reason or "INITIAL_LOAD"
            if lifecycle_reason not in {"INITIAL_LOAD", "RELOAD"}:
                raise DriverValidationError("attachment lifecycle reason is invalid")
            if lifecycle_reason == "RELOAD" and replaced_driver_binding_id is None:
                raise DriverValidationError(
                    "reload requires a replaced driver binding"
                )
            if (
                lifecycle_reason == "INITIAL_LOAD"
                and replaced_driver_binding_id is not None
            ):
                raise DriverValidationError(
                    "initial attachment cannot replace a driver binding"
                )
        elif lifecycle_reason is not None:
            raise DriverValidationError(
                "lifecycle reason is allowed only for execution attachment"
            )
        elif replaced_driver_binding_id is not None:
            raise DriverValidationError(
                "replaced driver binding is allowed only for execution attachment"
            )
        self._validate_method_identity(
            method,
            context_generation_id,
            driver_binding_id,
            target_operation_id,
            target_attempt_id,
        )
        with self._lock, self.session_factory() as session:
            try:
                # Capacity rows are the admission fence. Every path locks them
                # before inspecting replacement or active-operation state.
                capacity_rows = self._lock_operation_capacity_rows(
                    session, host_generation_id, context_generation_id
                )
                existing = session.get(DriverOperation, operation_id, with_for_update=True)
                if existing is not None:
                    if (
                        existing.method != method
                        or existing.request_digest != request_digest
                        or existing.effect_class != effect_class
                        or existing.current_attempt_id != attempt_id
                        or existing.host_generation_id != host_generation_id
                        or existing.context_generation_id != context_generation_id
                        or existing.binding_id != driver_binding_id
                        or existing.target_operation_id != target_operation_id
                        or existing.target_attempt_id != target_attempt_id
                        or existing.lifecycle_reason != lifecycle_reason
                        or existing.replaced_binding_id
                        != replaced_driver_binding_id
                    ):
                        raise DriverConflictError(
                            "operation ID was used with conflicting immutable intent"
                        )
                    return self._operation_view_in_session(session, existing)
                if session.get(DriverOperationAttempt, attempt_id) is not None:
                    raise DriverConflictError("attempt ID was already used")
                self._increment_locked_operation_capacity(*capacity_rows)
                if lifecycle_reason == "RELOAD":
                    active_other = session.scalar(
                        select(DriverOperation)
                        .where(
                            DriverOperation.host_generation_id
                            == host_generation_id,
                            DriverOperation.stage != "SETTLED",
                        )
                        .order_by(DriverOperation.id)
                        .limit(1)
                        .with_for_update()
                    )
                    if active_other is not None:
                        raise DriverConflictError(
                            "reload admission conflicts with active lifecycle work"
                        )
                pending_replacements = list(
                    session.scalars(
                        select(DriverBinding)
                        .join(
                            DriverContextGeneration,
                            DriverBinding.context_generation_id
                            == DriverContextGeneration.id,
                        )
                        .where(
                            DriverContextGeneration.host_generation_id
                            == host_generation_id,
                            DriverBinding.replacement_pending.is_(True),
                        )
                        .order_by(DriverBinding.id)
                        .with_for_update()
                    ).all()
                )
                admits_pending = method == "DrainHost" or (
                    method == "AttachExecution"
                    and lifecycle_reason == "RELOAD"
                    and driver_binding_id is not None
                    and len(pending_replacements) == 1
                    and pending_replacements[0].id == driver_binding_id
                )
                if pending_replacements and not admits_pending:
                    raise DriverConflictError(
                        "unresolved reload replacement blocks lifecycle admission"
                    )
                if replaced_driver_binding_id is not None:
                    replacement = session.get(
                        DriverBinding,
                        replaced_driver_binding_id,
                        with_for_update=True,
                    )
                    new_binding = session.get(
                        DriverBinding,
                        driver_binding_id,
                        with_for_update=True,
                    )
                    if (
                        replacement is None
                        or new_binding is None
                        or new_binding.replacement_of_binding_id != replacement.id
                        or not new_binding.replacement_pending
                        or not replacement.capacity_reserved
                    ):
                        raise DriverConflictError(
                            "reload binding reservation differs from immutable intent"
                        )
                tuple_values = self._resolve_generation_tuple(
                    session,
                    host_generation_id,
                    context_generation_id,
                    driver_binding_id,
                )
                operation = DriverOperation(
                    id=operation_id,
                    method=method,
                    request_digest=request_digest,
                    effect_class=effect_class,
                    actor=actor,
                    correlation_id=correlation_id,
                    host_generation_id=host_generation_id,
                    context_generation_id=context_generation_id,
                    binding_id=driver_binding_id,
                    target_operation_id=target_operation_id,
                    target_attempt_id=target_attempt_id,
                    lifecycle_reason=lifecycle_reason,
                    replaced_binding_id=replaced_driver_binding_id,
                    current_attempt_number=1,
                    current_attempt_id=attempt_id,
                    deadline_at=deadline_at,
                    stage="ACCEPTED",
                    certainty="NO_EFFECT",
                    requires_reconciliation=False,
                    capacity_reserved=True,
                    revision=0,
                )
                attempt = DriverOperationAttempt(
                    id=attempt_id,
                    operation_id=operation_id,
                    attempt_number=1,
                    request_digest=request_digest,
                    effect_class=effect_class,
                    server_profile_id=tuple_values["server_profile_id"],
                    host_generation_id=host_generation_id,
                    context_generation_id=context_generation_id,
                    binding_id=driver_binding_id,
                    execution_id=tuple_values["execution_id"],
                    attachment_generation_id=tuple_values["attachment_generation_id"],
                    host_configuration_digest=tuple_values["host_digest"],
                    context_configuration_digest=tuple_values["context_digest"],
                    attachment_configuration_digest=tuple_values["attachment_digest"],
                    target_operation_id=target_operation_id,
                    target_attempt_id=target_attempt_id,
                    lifecycle_reason=lifecycle_reason,
                    replaced_binding_id=replaced_driver_binding_id,
                    credential_epoch=tuple_values["credential_epoch"],
                    deadline_at=deadline_at,
                )
                session.add_all((operation, attempt))
                session.flush()
                transition = self._add_transition(
                    session,
                    operation,
                    attempt,
                    sequence=1,
                    stage="ACCEPTED",
                    certainty="NO_EFFECT",
                    disposition=None,
                    safe_error_code=None,
                    safe_error_message=None,
                    evidence_digest=None,
                    actor=actor,
                    correlation_id=correlation_id,
                )
                self._record_operation_event(session, operation, attempt, transition)
                session.commit()
                return self._operation_view_in_session(session, operation)
            except IntegrityError as exc:
                session.rollback()
                raise DriverConflictError("operation identity conflicts with canonical state") from exc
            except Exception:
                session.rollback()
                raise

    def append_operation_transition(
        self,
        operation_id: str,
        attempt_id: str,
        *,
        expected_revision: int,
        stage: str | Enum,
        certainty: str | Enum,
        disposition: str | Enum | None,
        safe_error_code: str | Enum | None,
        safe_error_message: str | None,
        evidence_digest: str | None,
        actor: str,
        correlation_id: str,
        terminal_observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        operation_id = _identifier(operation_id, "operation_id")
        attempt_id = _identifier(attempt_id, "attempt_id")
        stage = _wire_value(stage)
        certainty = _wire_value(certainty)
        if stage not in OPERATION_STAGES or certainty not in EFFECT_CERTAINTIES:
            raise DriverValidationError("operation stage or certainty is invalid")
        disposition_value = _wire_value(disposition) if disposition is not None else None
        error_code = _wire_value(safe_error_code) if safe_error_code is not None else None
        if disposition_value is not None:
            disposition_value = _bounded(disposition_value, "disposition", 60)
        if stage == "SETTLED" and disposition_value not in _RESULT_CODES:
            raise DriverValidationError(
                "settled operation disposition is not a ResultCode"
            )
        if error_code is not None:
            error_code = _bounded(error_code, "safe_error_code", 80)
        if safe_error_message is not None:
            safe_error_message = _bounded(safe_error_message, "safe_error_message", 1000)
        if evidence_digest is not None:
            evidence_digest = _digest(evidence_digest, "evidence_digest")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        if stage == "SETTLED" and terminal_observed_at is None:
            raise DriverValidationError(
                "settled operation requires a terminal observation"
            )
        if terminal_observed_at is not None:
            terminal_observed_at = _aware(
                terminal_observed_at, "terminal_observed_at"
            )
            if stage != "SETTLED" or certainty not in {
                "NO_EFFECT",
                "EFFECT_CONFIRMED",
            }:
                raise DriverValidationError(
                    "terminal observation requires a certain settled transition"
                )
        with self._lock, self.session_factory() as session:
            try:
                operation_probe = session.get(DriverOperation, operation_id)
                if operation_probe is None:
                    raise DriverNotFoundError("operation or attempt not found")
                capacity_rows = self._lock_operation_capacity_rows(
                    session,
                    operation_probe.host_generation_id,
                    operation_probe.context_generation_id,
                )
                operation = session.scalar(
                    select(DriverOperation)
                    .where(DriverOperation.id == operation_id)
                    .execution_options(populate_existing=True)
                    .with_for_update()
                )
                attempt = session.get(
                    DriverOperationAttempt, attempt_id, with_for_update=True
                )
                if operation is None or attempt is None or attempt.operation_id != operation_id:
                    raise DriverNotFoundError("operation or attempt not found")
                locked_host, locked_context = capacity_rows
                if (
                    operation.host_generation_id != locked_host.id
                    or operation.context_generation_id
                    != (locked_context.id if locked_context is not None else None)
                ):
                    raise DriverConflictError(
                        "operation generation tuple changed during capacity locking"
                    )
                if operation.current_attempt_id != attempt_id:
                    raise DriverConflictError("attempt is not current")
                if operation.revision != expected_revision:
                    raise DriverConflictError("operation revision conflict")
                last = session.scalar(
                    select(DriverOperationTransition)
                    .where(DriverOperationTransition.attempt_id == attempt_id)
                    .order_by(DriverOperationTransition.sequence.desc())
                    .limit(1)
                )
                if last is None:
                    raise DriverConflictError("operation attempt has no acceptance transition")
                if (
                    last.stage == stage
                    and last.certainty == certainty
                    and last.disposition == disposition_value
                    and last.safe_error_code == error_code
                    and last.safe_error_message == safe_error_message
                    and last.evidence_digest == evidence_digest
                ):
                    if stage == "SETTLED":
                        if (
                            _stored_utc(operation.effect_observed_at)
                            != terminal_observed_at
                            or _stored_utc(attempt.effect_observed_at)
                            != terminal_observed_at
                        ):
                            raise DriverConflictError(
                                "terminal observation conflicts with settled operation"
                            )
                        if attempt.projection_outcome is None:
                            raise DriverConflictError(
                                "settled attempt is missing its projection outcome"
                            )
                    return self._operation_view_in_session(session, operation)
                self._validate_operation_transition(
                    operation,
                    stage,
                    certainty,
                    disposition_value,
                )
                transition = self._add_transition(
                    session,
                    operation,
                    attempt,
                    sequence=last.sequence + 1,
                    stage=stage,
                    certainty=certainty,
                    disposition=disposition_value,
                    safe_error_code=error_code,
                    safe_error_message=safe_error_message,
                    evidence_digest=evidence_digest,
                    actor=actor,
                    correlation_id=correlation_id,
                )
                releases_capacity = stage in {"RECONCILING", "SETTLED"}
                if releases_capacity and operation.capacity_reserved:
                    self._release_locked_operation_capacity(*capacity_rows)
                    operation.capacity_reserved = False
                operation.stage = stage
                operation.certainty = certainty
                operation.disposition = disposition_value
                operation.safe_error_code = error_code
                operation.safe_error_message = safe_error_message
                operation.requires_reconciliation = stage == "RECONCILING"
                operation.revision += 1
                operation.updated_at = datetime.now(timezone.utc)
                if stage == "SETTLED":
                    operation.settled_at = operation.updated_at
                    operation.effect_observed_at = terminal_observed_at
                if terminal_observed_at is not None:
                    projection_outcome = self._apply_terminal_operation_projection(
                        session,
                        operation,
                        certainty=certainty,
                        observed_at=terminal_observed_at,
                        actor=actor,
                        correlation_id=correlation_id,
                    )
                    attempt.effect_observed_at = terminal_observed_at
                    attempt.projection_outcome = projection_outcome
                self._record_operation_event(session, operation, attempt, transition)
                session.commit()
                return self._operation_view_in_session(session, operation)
            except IntegrityError as exc:
                session.rollback()
                raise DriverConflictError("operation transition conflicts with canonical state") from exc
            except Exception:
                session.rollback()
                raise

    def authorize_retry(
        self,
        operation_id: str,
        *,
        expected_revision: int,
        new_attempt_id: str,
        host_generation_id: str,
        context_generation_id: str | None,
        driver_binding_id: str | None,
        deadline_at: datetime,
        actor: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        operation_id = _identifier(operation_id, "operation_id")
        new_attempt_id = _identifier(new_attempt_id, "new_attempt_id")
        host_generation_id = _identifier(host_generation_id, "host_generation_id")
        context_generation_id = _optional_identifier(
            context_generation_id, "context_generation_id"
        )
        driver_binding_id = _optional_identifier(
            driver_binding_id, "driver_binding_id"
        )
        deadline_at = _aware(deadline_at, "deadline_at")
        actor = _bounded(actor, "actor", 200)
        correlation_id = _identifier(correlation_id, "correlation_id")
        with self._lock, self.session_factory() as session:
            try:
                capacity_rows = self._lock_operation_capacity_rows(
                    session, host_generation_id, context_generation_id
                )
                operation = session.get(DriverOperation, operation_id, with_for_update=True)
                if operation is None:
                    raise DriverNotFoundError("operation not found")
                if operation.revision != expected_revision:
                    raise DriverConflictError("operation revision conflict")
                if operation.stage != "SETTLED" or operation.certainty != "NO_EFFECT":
                    raise DriverConflictError(
                        "a new attempt requires a settled authoritative NO_EFFECT result"
                    )
                previous_attempt = session.get(
                    DriverOperationAttempt,
                    operation.current_attempt_id,
                    with_for_update=True,
                )
                if (
                    previous_attempt is None
                    or previous_attempt.effect_observed_at is None
                    or previous_attempt.projection_outcome is None
                ):
                    raise DriverConflictError(
                        "settled attempt is missing terminal projection evidence"
                    )
                if (
                    host_generation_id != operation.host_generation_id
                    or context_generation_id != operation.context_generation_id
                    or driver_binding_id != operation.binding_id
                ):
                    raise DriverConflictError(
                        "retry must preserve the accepted generation tuple"
                    )
                if session.get(DriverOperationAttempt, new_attempt_id) is not None:
                    raise DriverConflictError("attempt ID was already used")
                if operation.capacity_reserved:
                    raise DriverConflictError(
                        "settled operation still owns lifecycle capacity"
                    )
                self._increment_locked_operation_capacity(*capacity_rows)
                if operation.lifecycle_reason == "RELOAD":
                    active_other = session.scalar(
                        select(DriverOperation)
                        .where(
                            DriverOperation.host_generation_id
                            == host_generation_id,
                            DriverOperation.id != operation.id,
                            DriverOperation.stage != "SETTLED",
                        )
                        .order_by(DriverOperation.id)
                        .limit(1)
                        .with_for_update()
                    )
                    if active_other is not None:
                        raise DriverConflictError(
                            "reload retry conflicts with active lifecycle work"
                        )
                self._validate_method_identity(
                    operation.method,
                    context_generation_id,
                    driver_binding_id,
                    operation.target_operation_id,
                    operation.target_attempt_id,
                )
                tuple_values = self._resolve_generation_tuple(
                    session,
                    host_generation_id,
                    context_generation_id,
                    driver_binding_id,
                )
                host_row, _ = capacity_rows
                latest_host = session.scalar(
                    select(DriverHostGeneration)
                    .where(DriverHostGeneration.profile_id == host_row.profile_id)
                    .order_by(DriverHostGeneration.generation_number.desc())
                    .limit(1)
                )
                if latest_host is None or latest_host.id != host_generation_id:
                    raise DriverConflictError(
                        "retry host generation is no longer current"
                    )
                if (
                    previous_attempt.request_digest != operation.request_digest
                    or previous_attempt.server_profile_id
                    != tuple_values["server_profile_id"]
                    or previous_attempt.host_configuration_digest
                    != tuple_values["host_digest"]
                    or previous_attempt.context_configuration_digest
                    != tuple_values["context_digest"]
                    or previous_attempt.attachment_configuration_digest
                    != tuple_values["attachment_digest"]
                    or previous_attempt.execution_id != tuple_values["execution_id"]
                    or previous_attempt.attachment_generation_id
                    != tuple_values["attachment_generation_id"]
                    or previous_attempt.credential_epoch
                    != tuple_values["credential_epoch"]
                ):
                    raise DriverConflictError(
                        "retry generation tuple differs from immutable intent"
                    )
                attempt_number = operation.current_attempt_number + 1
                attempt = DriverOperationAttempt(
                    id=new_attempt_id,
                    operation_id=operation.id,
                    attempt_number=attempt_number,
                    request_digest=operation.request_digest,
                    effect_class=operation.effect_class,
                    server_profile_id=tuple_values["server_profile_id"],
                    host_generation_id=host_generation_id,
                    context_generation_id=context_generation_id,
                    binding_id=driver_binding_id,
                    execution_id=tuple_values["execution_id"],
                    attachment_generation_id=tuple_values["attachment_generation_id"],
                    host_configuration_digest=tuple_values["host_digest"],
                    context_configuration_digest=tuple_values["context_digest"],
                    attachment_configuration_digest=tuple_values["attachment_digest"],
                    target_operation_id=operation.target_operation_id,
                    target_attempt_id=operation.target_attempt_id,
                    lifecycle_reason=operation.lifecycle_reason,
                    replaced_binding_id=operation.replaced_binding_id,
                    credential_epoch=tuple_values["credential_epoch"],
                    deadline_at=deadline_at,
                )
                session.add(attempt)
                operation.host_generation_id = host_generation_id
                operation.context_generation_id = context_generation_id
                operation.binding_id = driver_binding_id
                operation.current_attempt_number = attempt_number
                operation.current_attempt_id = new_attempt_id
                operation.deadline_at = deadline_at
                operation.stage = "ACCEPTED"
                operation.certainty = "NO_EFFECT"
                operation.disposition = None
                operation.safe_error_code = None
                operation.safe_error_message = None
                operation.requires_reconciliation = False
                operation.capacity_reserved = True
                operation.revision += 1
                operation.updated_at = datetime.now(timezone.utc)
                operation.settled_at = None
                operation.effect_observed_at = None
                session.flush()
                self._rearm_retry_projection(
                    session,
                    operation,
                    previous_attempt=previous_attempt,
                    attempt=attempt,
                    actor=actor,
                    correlation_id=correlation_id,
                )
                transition = self._add_transition(
                    session,
                    operation,
                    attempt,
                    sequence=1,
                    stage="ACCEPTED",
                    certainty="NO_EFFECT",
                    disposition=None,
                    safe_error_code=None,
                    safe_error_message=None,
                    evidence_digest=None,
                    actor=actor,
                    correlation_id=correlation_id,
                )
                self._record_operation_event(session, operation, attempt, transition)
                session.commit()
                return self._operation_view_in_session(session, operation)
            except IntegrityError as exc:
                session.rollback()
                raise DriverConflictError("retry attempt conflicts with canonical state") from exc
            except Exception:
                session.rollback()
                raise

    def list_drivers(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        last_id = _decode_cursor("drivers", cursor)
        with self.session_factory() as session:
            statement = select(DriverProfile).order_by(DriverProfile.id).limit(self._limit(limit) + 1)
            if last_id is not None:
                statement = statement.where(DriverProfile.id > last_id)
            profiles = list(session.scalars(statement).all())
            page, next_cursor = self._page("drivers", profiles, limit)
            return {
                "items": [self._driver_view_in_session(session, item) for item in page],
                "next_cursor": next_cursor,
            }

    def get_driver(self, profile_id: str) -> dict[str, Any]:
        profile_id = _identifier(profile_id, "profile_id")
        with self.session_factory() as session:
            profile = session.get(DriverProfile, profile_id)
            if profile is None:
                raise DriverNotFoundError("driver profile not found")
            return {"driver": self._driver_view_in_session(session, profile)}

    def list_context_generations(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        last_id = _decode_cursor("context_generations", cursor)
        with self.session_factory() as session:
            statement = (
                select(DriverContextGeneration)
                .order_by(DriverContextGeneration.id)
                .limit(self._limit(limit) + 1)
            )
            if last_id is not None:
                statement = statement.where(DriverContextGeneration.id > last_id)
            items = list(session.scalars(statement).all())
            page, next_cursor = self._page("context_generations", items, limit)
            return {
                "items": [context_generation_dict(item) for item in page],
                "next_cursor": next_cursor,
            }

    def get_context_generation(
        self, context_id: str, context_generation: str | int
    ) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        with self.session_factory() as session:
            statement = select(DriverContextGeneration).where(
                DriverContextGeneration.context_id == context_id
            )
            if isinstance(context_generation, int) or str(context_generation).isdigit():
                if int(context_generation) <= 0:
                    raise DriverValidationError("context_generation must be positive")
                statement = statement.where(
                    DriverContextGeneration.generation_number == int(context_generation)
                )
            else:
                generation_id = _identifier(
                    str(context_generation), "context_generation"
                )
                statement = statement.where(DriverContextGeneration.id == generation_id)
            item = session.scalar(statement)
            if item is None:
                raise DriverNotFoundError("context generation not found")
            return {"context_generation": context_generation_dict(item)}

    def list_bindings(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        last_id = _decode_cursor("bindings", cursor)
        with self.session_factory() as session:
            statement = select(DriverBinding).order_by(DriverBinding.id).limit(self._limit(limit) + 1)
            if last_id is not None:
                statement = statement.where(DriverBinding.id > last_id)
            items = list(session.scalars(statement).all())
            page, next_cursor = self._page("bindings", items, limit)
            return {
                "items": self._binding_projections(session, page),
                "next_cursor": next_cursor,
            }

    def get_binding(self, driver_binding_id: str) -> dict[str, Any]:
        driver_binding_id = _identifier(driver_binding_id, "driver_binding_id")
        with self.session_factory() as session:
            item = session.get(DriverBinding, driver_binding_id)
            if item is None:
                raise DriverNotFoundError("driver binding not found")
            return {"binding": self._binding_projections(session, [item])[0]}

    def list_reconciliation_operation_ids(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        """Page current attempts whose possible effect still needs read-only proof."""

        limit = self._limit(limit)
        last_id = _decode_cursor("driver-operation-reconciliation", cursor)
        with self.session_factory() as session:
            statement = (
                select(DriverOperation.id)
                .where(DriverOperation.stage.in_(("DISPATCHED", "RECONCILING")))
                .order_by(DriverOperation.id)
                .limit(limit + 1)
            )
            if last_id is not None:
                statement = statement.where(DriverOperation.id > last_id)
            operation_ids = list(session.scalars(statement).all())
            page = operation_ids[:limit]
            return {
                "items": page,
                "next_cursor": (
                    _cursor("driver-operation-reconciliation", page[-1])
                    if len(operation_ids) > limit and page
                    else None
                ),
            }

    def get_operation(self, operation_id: str) -> dict[str, Any]:
        operation_id = _identifier(operation_id, "operation_id")
        with self.session_factory() as session:
            operation = session.get(DriverOperation, operation_id)
            if operation is None:
                raise DriverNotFoundError("driver operation not found")
            return {"operation": self._operation_view_in_session(session, operation)}

    def pending_outbox(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            items = session.scalars(
                select(DriverOutboxEvent)
                .where(DriverOutboxEvent.published_at.is_(None))
                .order_by(DriverOutboxEvent.sequence)
                .limit(self._limit(limit))
            ).all()
            return [
                {
                    "sequence": item.sequence,
                    "event_id": item.event_id,
                    "topic": item.topic,
                    "aggregate_type": item.aggregate_type,
                    "aggregate_id": item.aggregate_id,
                    "payload": item.payload,
                    "created_at": item.created_at.isoformat(),
                }
                for item in items
            ]

    def driver_event_cursor(self) -> dict[str, int | None]:
        """Return the durable committed outbox bounds for downstream readers."""

        with self.session_factory() as session:
            first_sequence, last_sequence = session.execute(
                select(
                    func.min(DriverOutboxEvent.sequence),
                    func.max(DriverOutboxEvent.sequence),
                )
            ).one()
            return {
                "first_sequence": (
                    int(first_sequence) if first_sequence is not None else None
                ),
                "last_sequence": int(last_sequence) if last_sequence is not None else 0,
            }

    def replay_driver_events(
        self, *, after_sequence: int, limit: int
    ) -> dict[str, Any]:
        """Read one ordered, bounded replay window from committed outbox rows."""

        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or not 0 <= after_sequence <= MAX_DRIVER_EVENT_SEQUENCE
        ):
            raise DriverValidationError("after_sequence is outside the bounded cursor range")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_DRIVER_EVENT_REPLAY
        ):
            raise DriverValidationError(
                f"driver event replay limit must be between 1 and {MAX_DRIVER_EVENT_REPLAY}"
            )

        with self.session_factory() as session:
            first_sequence, last_sequence = session.execute(
                select(
                    func.min(DriverOutboxEvent.sequence),
                    func.max(DriverOutboxEvent.sequence),
                )
            ).one()
            resolved_first = (
                int(first_sequence) if first_sequence is not None else None
            )
            resolved_last = int(last_sequence) if last_sequence is not None else 0
            cursor_available = after_sequence == 0
            if 0 < after_sequence <= resolved_last:
                cursor_available = (
                    session.get(DriverOutboxEvent, after_sequence) is not None
                )

            items = session.scalars(
                select(DriverOutboxEvent)
                .where(DriverOutboxEvent.sequence > after_sequence)
                .order_by(DriverOutboxEvent.sequence)
                .limit(limit)
            ).all()
            return {
                "first_sequence": resolved_first,
                "last_sequence": resolved_last,
                "cursor_available": cursor_available,
                "items": [self._outbox_event_dict(item) for item in items],
            }

    def mark_outbox_published(
        self, sequence: int, event_id: str, *, published_at: datetime
    ) -> None:
        event_id = _identifier(event_id, "event_id")
        published_at = _aware(published_at, "published_at")
        with self._lock, self.session_factory() as session:
            try:
                item = session.get(DriverOutboxEvent, sequence, with_for_update=True)
                if item is None or item.event_id != event_id:
                    raise DriverNotFoundError("driver outbox event not found")
                if item.published_at is not None:
                    return
                item.delivery_attempts += 1
                item.published_at = published_at
                session.commit()
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _outbox_event_dict(item: DriverOutboxEvent) -> dict[str, Any]:
        return {
            **item.payload,
            "sequence": item.sequence,
            "created_at": item.created_at.isoformat(),
        }

    @staticmethod
    def _limit(limit: int) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise DriverValidationError("limit must be between 1 and 100")
        return limit

    @staticmethod
    def _page(kind: str, items: list[Any], limit: int) -> tuple[list[Any], str | None]:
        DriverRepository._limit(limit)
        page = items[:limit]
        next_cursor = _cursor(kind, page[-1].id) if len(items) > limit and page else None
        return page, next_cursor

    @staticmethod
    def _binding_projections(
        session: Session, bindings: Iterable[DriverBinding]
    ) -> list[dict[str, Any]]:
        page = list(bindings)
        if not page:
            return []
        latest_operation_id = (
            select(DriverOperation.id)
            .where(DriverOperation.binding_id == DriverBinding.id)
            .order_by(
                DriverOperation.updated_at.desc(),
                DriverOperation.created_at.desc(),
                DriverOperation.id.desc(),
            )
            .limit(1)
            .correlate(DriverBinding)
            .scalar_subquery()
        )
        latest_by_binding = dict(
            session.execute(
                select(DriverBinding.id, latest_operation_id).where(
                    DriverBinding.id.in_(item.id for item in page)
                )
            ).all()
        )
        return [
            {
                **binding_dict(item),
                "latest_operation_id": latest_by_binding.get(item.id),
            }
            for item in page
        ]

    @staticmethod
    def _validate_capabilities(
        capabilities: tuple[CapabilitySpec, ...],
    ) -> tuple[CapabilitySpec, ...]:
        expected = {
            definition.method.value: CapabilitySpec(
                service=definition.service,
                method=definition.method.value,
                mutability=definition.mutability,
                modifiers=definition.modifiers,
                formats=(definition.format,),
                stream_support=definition.stream_support,
            )
            for definition in CAPABILITY_MATRIX
        }
        if len(capabilities) != len(expected):
            raise DriverValidationError("handshake must contain exactly nine RPC capabilities")
        parsed: list[CapabilitySpec] = []
        seen: set[str] = set()
        for item in capabilities:
            if not isinstance(item, CapabilitySpec):
                raise DriverValidationError("capability must be a CapabilitySpec")
            service = _bounded(item.service, "capability service", 100)
            method = _wire_value(item.method)
            mutability = _wire_value(item.mutability)
            modifiers = tuple(
                _bounded(modifier, "capability modifier", 100)
                for modifier in item.modifiers
            )
            formats = tuple(
                _bounded(value_format, "capability format", 100)
                for value_format in item.formats
            )
            stream_support = _bounded(
                item.stream_support, "capability stream support", 20
            )
            if method not in expected or method in seen:
                raise DriverValidationError("capability methods must be the exact nine-RPC surface")
            parsed_item = CapabilitySpec(
                service=service,
                method=method,
                mutability=mutability,
                modifiers=modifiers,
                formats=formats,
                stream_support=stream_support,
            )
            if parsed_item != expected[method]:
                raise DriverValidationError("capability dimensions do not match the approved matrix")
            seen.add(method)
            parsed.append(parsed_item)
        if seen != set(expected):
            raise DriverValidationError("capabilities must expose the exact nine-RPC matrix")
        return tuple(sorted(parsed, key=lambda item: item.method))

    @staticmethod
    def _validate_method_identity(
        method: str,
        context_generation_id: str | None,
        driver_binding_id: str | None,
        target_operation_id: str | None,
        target_attempt_id: str | None,
    ) -> None:
        if method in {"OpenContext", "CloseContext"}:
            valid = context_generation_id is not None and driver_binding_id is None
        elif method in {"AttachExecution", "DetachExecution"}:
            valid = context_generation_id is not None and driver_binding_id is not None
        elif method == "CancelLifecycleOperation":
            valid = target_operation_id is not None and target_attempt_id is not None
        elif method == "DrainHost":
            valid = context_generation_id is None and driver_binding_id is None
        else:
            valid = False
        if method != "CancelLifecycleOperation" and (
            target_operation_id is not None or target_attempt_id is not None
        ):
            valid = False
        if not valid:
            raise DriverValidationError("operation identity tuple does not match its method")

    @staticmethod
    def _resolve_generation_tuple(
        session: Session,
        host_generation_id: str,
        context_generation_id: str | None,
        driver_binding_id: str | None,
    ) -> dict[str, Any]:
        host = session.get(DriverHostGeneration, host_generation_id)
        if host is None:
            raise DriverNotFoundError("driver host generation not found")
        profile = session.get(DriverProfile, host.profile_id)
        if profile is None or not profile.enabled:
            raise DriverConflictError("driver profile is disabled or missing")
        context = (
            session.get(DriverContextGeneration, context_generation_id)
            if context_generation_id is not None
            else None
        )
        if context_generation_id is not None and (
            context is None or context.host_generation_id != host.id
        ):
            raise DriverConflictError("context generation does not belong to host generation")
        binding = (
            session.get(DriverBinding, driver_binding_id)
            if driver_binding_id is not None
            else None
        )
        if driver_binding_id is not None and (
            binding is None
            or context is None
            or binding.context_generation_id != context.id
        ):
            raise DriverConflictError("driver binding does not belong to context generation")
        return {
            "server_profile_id": profile.server_profile_id,
            "host_digest": host.configuration_digest,
            "context_digest": context.configuration_digest if context else None,
            "attachment_digest": binding.configuration_digest if binding else None,
            "execution_id": binding.execution_id if binding else None,
            "attachment_generation_id": (
                binding.attachment_generation_id if binding else None
            ),
            "credential_epoch": host.credential_epoch,
        }

    def _apply_terminal_operation_projection(
        self,
        session: Session,
        operation: DriverOperation,
        *,
        certainty: str,
        observed_at: datetime,
        actor: str,
        correlation_id: str,
    ) -> str:
        """Project a certain lifecycle result in the settlement transaction."""

        host = session.get(
            DriverHostGeneration, operation.host_generation_id, with_for_update=True
        )
        if host is None:
            raise DriverNotFoundError("driver host generation not found")

        changed_host = False
        changed_contexts: dict[str, DriverContextGeneration] = {}
        changed_bindings: dict[str, DriverBinding] = {}
        projection_outcome = "APPLIED"

        def is_newer(row: Any) -> bool:
            last_observed = _stored_utc(row.last_observed_at)
            return last_observed is not None and last_observed > observed_at

        def load_context() -> DriverContextGeneration:
            if operation.context_generation_id is None:
                raise DriverConflictError("operation context generation is missing")
            context = session.get(
                DriverContextGeneration,
                operation.context_generation_id,
                with_for_update=True,
            )
            if context is None or context.host_generation_id != host.id:
                raise DriverConflictError(
                    "operation context generation does not belong to host"
                )
            return context

        def load_binding(context: DriverContextGeneration) -> DriverBinding:
            if operation.binding_id is None:
                raise DriverConflictError("operation driver binding is missing")
            binding = session.get(
                DriverBinding, operation.binding_id, with_for_update=True
            )
            if binding is None or binding.context_generation_id != context.id:
                raise DriverConflictError(
                    "operation driver binding does not belong to context"
                )
            return binding

        def context_bindings(
            context: DriverContextGeneration,
        ) -> list[DriverBinding]:
            return list(
                session.scalars(
                    select(DriverBinding)
                    .where(DriverBinding.context_generation_id == context.id)
                    .order_by(DriverBinding.id)
                    .with_for_update()
                ).all()
            )

        def update_binding(
            binding: DriverBinding,
            *,
            state: str,
            capacity_reserved: bool,
            replacement_pending: bool,
        ) -> None:
            state_changed = binding.state != state
            capacity_changed = binding.capacity_reserved != capacity_reserved
            if is_newer(binding) and (state_changed or capacity_changed):
                raise DriverConflictError(
                    "terminal projection conflicts with a newer binding observation"
                )
            changed = (
                state_changed
                or capacity_changed
                or binding.replacement_pending != replacement_pending
            )
            if not changed:
                return
            binding.state = state
            binding.capacity_reserved = capacity_reserved
            binding.replacement_pending = replacement_pending
            if state_changed and not is_newer(binding):
                binding.last_observed_at = observed_at
                if state == "DETACHED":
                    binding.detached_at = observed_at
            binding.revision += 1
            changed_bindings[binding.id] = binding

        def detach_binding(
            binding: DriverBinding, context: DriverContextGeneration
        ) -> None:
            if is_newer(binding):
                return
            if binding.capacity_reserved:
                if context.attachments_in_use <= 0:
                    raise DriverConflictError(
                        "context attachment capacity is inconsistent"
                    )
                context.attachments_in_use -= 1
                context.revision += 1
                changed_contexts[context.id] = context
            update_binding(
                binding,
                state="DETACHED",
                capacity_reserved=False,
                replacement_pending=False,
            )

        def close_context(
            context: DriverContextGeneration, bindings: list[DriverBinding]
        ) -> bool:
            nonlocal changed_host
            if is_newer(context) or any(is_newer(item) for item in bindings):
                return False
            owners = [item for item in bindings if item.capacity_reserved]
            if context.attachments_in_use != len(owners):
                raise DriverConflictError(
                    "context attachment capacity is inconsistent"
                )
            if context.state == "CLOSED":
                if owners or any(item.state != "DETACHED" for item in bindings):
                    raise DriverConflictError(
                        "closed context still has reserved attachments"
                    )
                return True
            if host.contexts_in_use <= 0:
                raise DriverConflictError("host context capacity is inconsistent")
            for binding in bindings:
                detach_binding(binding, context)
            context.state = "CLOSED"
            context.ready = False
            context.last_observed_at = observed_at
            context.closed_at = observed_at
            context.revision += 1
            host.contexts_in_use -= 1
            host.revision += 1
            changed_contexts[context.id] = context
            changed_host = True
            return True

        def project_reload(
            context: DriverContextGeneration, binding: DriverBinding
        ) -> str:
            if (
                operation.replaced_binding_id is None
                or binding.replacement_of_binding_id
                != operation.replaced_binding_id
            ):
                raise DriverConflictError("reload binding lineage differs")
            replaced = session.get(
                DriverBinding,
                operation.replaced_binding_id,
                with_for_update=True,
            )
            if (
                replaced is None
                or replaced.context_generation_id != context.id
                or replaced.execution_id != binding.execution_id
            ):
                raise DriverConflictError("reload replacement binding differs")
            bindings = context_bindings(context)
            owners_before = {item.id for item in bindings if item.capacity_reserved}
            if context.attachments_in_use != len(owners_before):
                raise DriverConflictError(
                    "context attachment capacity is inconsistent"
                )
            pair = (replaced, binding)
            pair_owners_before = {
                item.id for item in pair if item.capacity_reserved
            }

            newer_attached = [
                item
                for item in pair
                if is_newer(item) and item.state == "ATTACHED"
            ]
            desired_owner: DriverBinding | None
            if certainty == "NO_EFFECT":
                terminal_owner = replaced
            elif operation.disposition == ResultCode.OK.value:
                terminal_owner = binding
            else:
                terminal_owner = None
            if len(newer_attached) > 1:
                raise DriverConflictError(
                    "newer reload observations are contradictory"
                )
            if newer_attached:
                desired_owner = newer_attached[0]
            elif terminal_owner is not None and is_newer(terminal_owner):
                desired_owner = None
            else:
                desired_owner = terminal_owner

            for item in pair:
                desired_state = "ATTACHED" if item is desired_owner else "DETACHED"
                update_binding(
                    item,
                    state=desired_state,
                    capacity_reserved=item is desired_owner,
                    replacement_pending=False,
                )
            pair_owners_after = (
                {desired_owner.id} if desired_owner is not None else set()
            )
            context.attachments_in_use += (
                len(pair_owners_after) - len(pair_owners_before)
            )
            if not 0 <= context.attachments_in_use <= context.max_attachments:
                raise DriverConflictError(
                    "context attachment capacity is inconsistent"
                )
            owners_after = {item.id for item in bindings if item.capacity_reserved}
            if context.attachments_in_use != len(owners_after):
                raise DriverConflictError(
                    "reload projection did not preserve attachment ownership"
                )
            if pair_owners_after != pair_owners_before:
                context.revision += 1
                changed_contexts[context.id] = context
            return (
                "RECONCILED_FROM_NEWER_OBSERVATION"
                if is_newer(replaced) or is_newer(binding)
                else "APPLIED"
            )

        if certainty == "NO_EFFECT":
            if operation.method == "OpenContext":
                context = load_context()
                if is_newer(context):
                    projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
                elif context.state not in {"OPENING", "CLOSED"}:
                    raise DriverConflictError(
                        "no-effect context open conflicts with canonical state"
                    )
                elif not close_context(context, context_bindings(context)):
                    projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
            elif operation.method == "AttachExecution":
                context = load_context()
                binding = load_binding(context)
                if operation.lifecycle_reason == "RELOAD":
                    projection_outcome = project_reload(context, binding)
                else:
                    if is_newer(binding):
                        projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
                    elif binding.state not in {"ATTACHING", "DETACHED"}:
                        raise DriverConflictError(
                            "no-effect execution attach conflicts with canonical state"
                        )
                    else:
                        detach_binding(binding, context)
        elif operation.method == "OpenContext":
            context = load_context()
            if is_newer(context):
                projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
            elif context.state not in {"OPENING", "ACTIVE", "DEGRADED"}:
                raise DriverConflictError(
                    "confirmed context open conflicts with canonical state"
                )
            elif context.state != "ACTIVE":
                context.state = "ACTIVE"
                context.ready = True
                context.last_observed_at = observed_at
                context.revision += 1
                changed_contexts[context.id] = context
        elif operation.method == "AttachExecution":
            context = load_context()
            binding = load_binding(context)
            if operation.lifecycle_reason == "RELOAD":
                projection_outcome = project_reload(context, binding)
            else:
                if is_newer(binding):
                    projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
                elif binding.state not in {"ATTACHING", "ATTACHED"}:
                    raise DriverConflictError(
                        "confirmed execution attach conflicts with canonical state"
                    )
                elif binding.state != "ATTACHED":
                    binding.state = "ATTACHED"
                    binding.last_observed_at = observed_at
                    binding.revision += 1
                    changed_bindings[binding.id] = binding
        elif operation.method == "DetachExecution":
            context = load_context()
            binding = load_binding(context)
            if is_newer(binding):
                projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
            else:
                detach_binding(binding, context)
        elif operation.method == "CloseContext":
            context = load_context()
            if not close_context(context, context_bindings(context)):
                projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
        elif operation.method == "DrainHost":
            contexts = list(
                session.scalars(
                    select(DriverContextGeneration)
                    .where(DriverContextGeneration.host_generation_id == host.id)
                    .order_by(DriverContextGeneration.id)
                    .with_for_update()
                ).all()
            )
            nonterminal_contexts = [
                item for item in contexts if item.state != "CLOSED"
            ]
            if host.contexts_in_use != len(nonterminal_contexts):
                raise DriverConflictError("host context capacity is inconsistent")
            bindings_by_context = {
                context.id: context_bindings(context) for context in contexts
            }
            if is_newer(host) or any(
                is_newer(context)
                or any(is_newer(binding) for binding in bindings_by_context[context.id])
                for context in contexts
            ):
                projection_outcome = "SUPERSEDED_BY_NEWER_OBSERVATION"
            else:
                for context in contexts:
                    owners = [
                        item
                        for item in bindings_by_context[context.id]
                        if item.capacity_reserved
                    ]
                    if context.attachments_in_use != len(owners):
                        raise DriverConflictError(
                            "context attachment capacity is inconsistent"
                        )
                for context in contexts:
                    close_context(context, bindings_by_context[context.id])
                if host.state != "CLOSED":
                    host.state = "CLOSED"
                    host.ready = False
                    host.last_observed_at = observed_at
                    host.closed_at = observed_at
                    host.revision += 1
                    changed_host = True

        # Parent revisions include every child capacity delta before publication.
        if changed_host:
            self._record_event(
                session,
                event_type="driver.host_state_changed",
                aggregate_type="driver_host_generation",
                aggregate_id=host.id,
                operation_id=operation.id,
                attempt_id=operation.current_attempt_id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "host_generation_id": host.id,
                    "state": host.state,
                    "ready": host.ready,
                    "revision": host.revision,
                },
            )
        for context in sorted(changed_contexts.values(), key=lambda item: item.id):
            self._record_event(
                session,
                event_type="driver.context_state_changed",
                aggregate_type="driver_context_generation",
                aggregate_id=context.id,
                operation_id=operation.id,
                attempt_id=operation.current_attempt_id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "context_id": context.context_id,
                    "context_generation_id": context.id,
                    "state": context.state,
                    "ready": context.ready,
                    "revision": context.revision,
                },
            )
        for binding in sorted(changed_bindings.values(), key=lambda item: item.id):
            self._record_event(
                session,
                event_type="driver.binding_state_changed",
                aggregate_type="driver_binding",
                aggregate_id=binding.id,
                operation_id=operation.id,
                attempt_id=operation.current_attempt_id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "driver_binding_id": binding.id,
                    "state": binding.state,
                    "capacity_reserved": binding.capacity_reserved,
                    "replacement_pending": binding.replacement_pending,
                    "revision": binding.revision,
                },
            )
        return projection_outcome

    def _rearm_retry_projection(
        self,
        session: Session,
        operation: DriverOperation,
        *,
        previous_attempt: DriverOperationAttempt,
        attempt: DriverOperationAttempt,
        actor: str,
        correlation_id: str,
    ) -> None:
        """Restore a NO_EFFECT attempt's provisional resource in the retry transaction."""

        if previous_attempt.projection_outcome != "APPLIED":
            raise DriverConflictError(
                "retry cannot overwrite a terminal projection superseded by health"
            )
        if operation.method not in {"OpenContext", "AttachExecution"}:
            return

        host = session.get(
            DriverHostGeneration, operation.host_generation_id, with_for_update=True
        )
        if host is None:
            raise DriverNotFoundError("driver host generation not found")

        def record_host() -> None:
            self._record_event(
                session,
                event_type="driver.host_state_changed",
                aggregate_type="driver_host_generation",
                aggregate_id=host.id,
                operation_id=operation.id,
                attempt_id=attempt.id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "host_generation_id": host.id,
                    "state": host.state,
                    "ready": host.ready,
                    "revision": host.revision,
                },
            )

        def record_context(context: DriverContextGeneration) -> None:
            self._record_event(
                session,
                event_type="driver.context_state_changed",
                aggregate_type="driver_context_generation",
                aggregate_id=context.id,
                operation_id=operation.id,
                attempt_id=attempt.id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "context_id": context.context_id,
                    "context_generation_id": context.id,
                    "state": context.state,
                    "ready": context.ready,
                    "revision": context.revision,
                },
            )

        def record_binding(binding: DriverBinding) -> None:
            self._record_event(
                session,
                event_type="driver.binding_state_changed",
                aggregate_type="driver_binding",
                aggregate_id=binding.id,
                operation_id=operation.id,
                attempt_id=attempt.id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "driver_binding_id": binding.id,
                    "state": binding.state,
                    "capacity_reserved": binding.capacity_reserved,
                    "replacement_pending": binding.replacement_pending,
                    "revision": binding.revision,
                },
            )

        if operation.context_generation_id is None:
            raise DriverConflictError("retry operation context generation is missing")
        context = session.get(
            DriverContextGeneration,
            operation.context_generation_id,
            with_for_update=True,
        )
        if context is None or context.host_generation_id != host.id:
            raise DriverConflictError(
                "retry context generation does not belong to host"
            )

        if operation.method == "OpenContext":
            contexts = list(
                session.scalars(
                    select(DriverContextGeneration)
                    .where(DriverContextGeneration.host_generation_id == host.id)
                    .order_by(DriverContextGeneration.id)
                    .with_for_update()
                ).all()
            )
            latest = session.scalar(
                select(DriverContextGeneration)
                .where(DriverContextGeneration.context_id == context.context_id)
                .order_by(DriverContextGeneration.generation_number.desc())
                .limit(1)
                .with_for_update()
            )
            bindings = list(
                session.scalars(
                    select(DriverBinding)
                    .where(DriverBinding.context_generation_id == context.id)
                    .order_by(DriverBinding.id)
                    .with_for_update()
                ).all()
            )
            if latest is None or latest.id != context.id:
                raise DriverConflictError(
                    "open retry context generation is no longer current"
                )
            if host.state != "READY" or not host.ready:
                raise DriverConflictError("open retry driver host is not ready")
            if host.contexts_in_use != sum(
                item.state != "CLOSED" for item in contexts
            ):
                raise DriverConflictError("driver host context capacity is inconsistent")
            if host.contexts_in_use >= host.max_contexts:
                raise DriverConflictError("driver host context capacity is exhausted")
            if (
                context.state != "CLOSED"
                or context.ready
                or context.attachments_in_use != 0
                or any(
                    item.state != "DETACHED"
                    or item.capacity_reserved
                    or item.replacement_pending
                    for item in bindings
                )
            ):
                raise DriverConflictError(
                    "open retry context was not released by NO_EFFECT"
                )
            host.contexts_in_use += 1
            host.revision += 1
            context.state = "OPENING"
            context.ready = False
            context.closed_at = None
            context.revision += 1
            record_host()
            record_context(context)
            return

        if operation.binding_id is None:
            raise DriverConflictError("attach retry driver binding is missing")
        bindings = list(
            session.scalars(
                select(DriverBinding)
                .where(DriverBinding.context_generation_id == context.id)
                .order_by(DriverBinding.id)
                .with_for_update()
                ).all()
        )
        binding = next(
            (item for item in bindings if item.id == operation.binding_id), None
        )
        if binding is None:
            raise DriverConflictError("attach retry binding does not belong to context")
        owners = {item.id for item in bindings if item.capacity_reserved}
        if context.attachments_in_use != len(owners):
            raise DriverConflictError("context attachment capacity is inconsistent")
        latest = session.scalar(
            select(DriverBinding)
            .where(DriverBinding.execution_id == binding.execution_id)
            .order_by(DriverBinding.attachment_generation_number.desc())
            .limit(1)
            .with_for_update()
        )
        if latest is None or latest.id != binding.id:
            raise DriverConflictError("attach retry binding is no longer current")
        if context.state != "ACTIVE" or not context.ready:
            raise DriverConflictError("attach retry context is not active")

        if operation.lifecycle_reason == "RELOAD":
            if operation.replaced_binding_id is None:
                raise DriverConflictError("reload retry replacement binding is missing")
            replaced = session.get(
                DriverBinding,
                operation.replaced_binding_id,
                with_for_update=True,
            )
            if (
                replaced is None
                or replaced.context_generation_id != context.id
                or replaced.execution_id != binding.execution_id
                or binding.replacement_of_binding_id != replaced.id
                or replaced.state != "ATTACHED"
                or not replaced.capacity_reserved
                or replaced.replacement_pending
                or binding.state != "DETACHED"
                or binding.capacity_reserved
                or binding.replacement_pending
            ):
                raise DriverConflictError(
                    "reload retry binding was not released by NO_EFFECT"
                )
            pending = session.scalar(
                select(DriverBinding)
                .join(
                    DriverContextGeneration,
                    DriverBinding.context_generation_id
                    == DriverContextGeneration.id,
                )
                .where(
                    DriverContextGeneration.host_generation_id == host.id,
                    DriverBinding.replacement_pending.is_(True),
                )
                .limit(1)
            )
            if pending is not None:
                raise DriverConflictError(
                    "reload retry conflicts with a pending replacement"
                )
            binding.state = "ATTACHING"
            binding.replacement_pending = True
            binding.detached_at = None
            binding.revision += 1
            record_binding(binding)
            return

        if (
            operation.lifecycle_reason != "INITIAL_LOAD"
            or binding.replacement_of_binding_id is not None
            or binding.state != "DETACHED"
            or binding.capacity_reserved
            or binding.replacement_pending
        ):
            raise DriverConflictError(
                "initial attach retry binding was not released by NO_EFFECT"
            )
        if context.attachments_in_use >= context.max_attachments:
            raise DriverConflictError("context attachment capacity is exhausted")
        context.attachments_in_use += 1
        context.revision += 1
        binding.state = "ATTACHING"
        binding.capacity_reserved = True
        binding.detached_at = None
        binding.revision += 1
        record_context(context)
        record_binding(binding)

    @staticmethod
    def _lock_operation_capacity_rows(
        session: Session,
        host_generation_id: str,
        context_generation_id: str | None,
    ) -> tuple[DriverHostGeneration, DriverContextGeneration | None]:
        host = session.get(
            DriverHostGeneration, host_generation_id, with_for_update=True
        )
        if host is None:
            raise DriverNotFoundError("driver host generation not found")
        context = None
        if context_generation_id is not None:
            context = session.get(
                DriverContextGeneration, context_generation_id, with_for_update=True
            )
            if context is None or context.host_generation_id != host.id:
                raise DriverConflictError(
                    "context generation does not belong to host generation"
                )
        return host, context

    @staticmethod
    def _increment_locked_operation_capacity(
        host: DriverHostGeneration,
        context: DriverContextGeneration | None,
    ) -> None:
        if host.lifecycle_operations_in_use >= host.max_lifecycle_operations:
            raise DriverConflictError(
                "driver host lifecycle operation capacity is exhausted"
            )
        if (
            context is not None
            and context.lifecycle_operations_in_use
            >= context.max_lifecycle_operations
        ):
            raise DriverConflictError(
                "context lifecycle operation capacity is exhausted"
            )
        host.lifecycle_operations_in_use += 1
        host.revision += 1
        if context is not None:
            context.lifecycle_operations_in_use += 1
            context.revision += 1

    @staticmethod
    def _release_locked_operation_capacity(
        host: DriverHostGeneration,
        context: DriverContextGeneration | None,
    ) -> None:
        if host.lifecycle_operations_in_use <= 0:
            raise DriverConflictError("driver host lifecycle capacity is inconsistent")
        if context is not None and context.lifecycle_operations_in_use <= 0:
            raise DriverConflictError("context lifecycle capacity is inconsistent")
        host.lifecycle_operations_in_use -= 1
        host.revision += 1
        if context is not None:
            context.lifecycle_operations_in_use -= 1
            context.revision += 1

    @staticmethod
    def _validate_operation_transition(
        operation: DriverOperation,
        stage: str,
        certainty: str,
        disposition: str | None,
    ) -> None:
        if operation.stage == "SETTLED":
            raise DriverConflictError("settled operation is immutable")
        if _STAGE_RANK[stage] < _STAGE_RANK[operation.stage]:
            raise DriverConflictError("operation stage cannot regress within an attempt")
        if certainty not in _CERTAINTY_TRANSITIONS[operation.certainty]:
            raise DriverConflictError("operation certainty transition is invalid")
        if stage == "ACCEPTED" and certainty != "NO_EFFECT":
            raise DriverConflictError("accepted operation must retain NO_EFFECT certainty")
        if stage == "DISPATCHED" and certainty != "EFFECT_POSSIBLE":
            raise DriverConflictError("dispatch authorization must record EFFECT_POSSIBLE")
        if stage == "SETTLED":
            if certainty in {"EFFECT_POSSIBLE", "EFFECT_UNKNOWN"}:
                raise DriverConflictError("uncertain operation must remain in reconciliation")
            if disposition is None:
                raise DriverValidationError("settled operation requires a disposition")
        elif disposition is not None and stage != "RECONCILING":
            raise DriverValidationError("nonterminal disposition is allowed only in reconciliation")

    @staticmethod
    def _add_transition(
        session: Session,
        operation: DriverOperation,
        attempt: DriverOperationAttempt,
        *,
        sequence: int,
        stage: str,
        certainty: str,
        disposition: str | None,
        safe_error_code: str | None,
        safe_error_message: str | None,
        evidence_digest: str | None,
        actor: str,
        correlation_id: str,
    ) -> DriverOperationTransition:
        transition = DriverOperationTransition(
            operation_id=operation.id,
            attempt_id=attempt.id,
            sequence=sequence,
            stage=stage,
            certainty=certainty,
            disposition=disposition,
            safe_error_code=safe_error_code,
            safe_error_message=safe_error_message,
            evidence_digest=evidence_digest,
            actor=actor,
            correlation_id=correlation_id,
        )
        session.add(transition)
        session.flush()
        return transition

    @staticmethod
    def _record_operation_event(
        session: Session,
        operation: DriverOperation,
        attempt: DriverOperationAttempt,
        transition: DriverOperationTransition,
    ) -> None:
        DriverRepository._record_event(
            session,
            event_type="driver.operation_transitioned",
            aggregate_type="driver_operation",
            aggregate_id=operation.id,
            operation_id=operation.id,
            attempt_id=attempt.id,
            actor=transition.actor,
            correlation_id=transition.correlation_id,
            payload={
                "operation_id": operation.id,
                "attempt_id": attempt.id,
                "attempt_number": attempt.attempt_number,
                "method": operation.method,
                "stage": transition.stage,
                "certainty": transition.certainty,
                "disposition": transition.disposition,
                "transition_sequence": transition.sequence,
                "revision": operation.revision,
            },
        )

    @staticmethod
    def _record_event(
        session: Session,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        actor: str,
        correlation_id: str,
        payload: dict[str, Any],
        operation_id: str | None = None,
        attempt_id: str | None = None,
    ) -> None:
        event = DriverAuditEvent(
            id=new_id(),
            event_type=event_type,
            operation_id=operation_id,
            attempt_id=attempt_id,
            actor=actor,
            correlation_id=correlation_id,
            payload=payload,
        )
        session.add(event)
        session.flush()
        envelope = {
            "schema_version": DRIVER_EVENT_SCHEMA,
            "event_id": event.id,
            "event_type": event.event_type,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "actor": event.actor,
            "correlation_id": event.correlation_id,
            "operation_id": event.operation_id,
            "attempt_id": event.attempt_id,
            "data": payload,
        }
        session.add(
            DriverOutboxEvent(
                event_id=event.id,
                topic=DRIVER_EVENT_TOPIC,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                payload=envelope,
                delivery_attempts=0,
            )
        )
        session.flush()

    @staticmethod
    def _apply_profile_enabled(
        session: Session,
        profile: DriverProfile,
        enabled: bool,
        *,
        actor: str,
        correlation_id: str,
    ) -> None:
        profile.enabled = enabled
        profile.revision += 1
        profile.updated_at = datetime.now(timezone.utc)
        DriverRepository._record_event(
            session,
            event_type="driver.profile_enabled" if enabled else "driver.profile_disabled",
            aggregate_type="driver_profile",
            aggregate_id=profile.id,
            actor=actor,
            correlation_id=correlation_id,
            payload={
                "profile_id": profile.id,
                "enabled": profile.enabled,
                "revision": profile.revision,
            },
        )

    @staticmethod
    def _canonical_profile_digest(
        profile: DriverProfile, *, credential_reference: str
    ) -> str:
        return canonical_configuration_digest(
            {
                "configuration_schema_version": profile.configuration_schema_version,
                "contract_package": profile.contract_package,
                "credential_reference": credential_reference,
                "journal_max_bytes": profile.journal_max_bytes,
                "journal_max_entries": profile.journal_max_entries,
                "logical_driver_id": profile.logical_driver_id,
                "max_attachments_per_context": profile.max_attachments_per_context,
                "max_contexts_per_host": profile.max_contexts_per_host,
                "max_lifecycle_operations_per_context": (
                    profile.max_lifecycle_operations_per_context
                ),
                "max_lifecycle_operations_per_host": (
                    profile.max_lifecycle_operations_per_host
                ),
                "server_profile_id": profile.server_profile_id,
                "simulator": profile.simulator,
            }
        )

    @staticmethod
    def _profile_configuration_dict(profile: DriverProfile) -> dict[str, Any]:
        return {
            "id": profile.id,
            "server_profile_id": profile.server_profile_id,
            "logical_driver_id": profile.logical_driver_id,
            "simulator": profile.simulator,
            "enabled": profile.enabled,
            "contract_package": profile.contract_package,
            "configuration_schema_version": profile.configuration_schema_version,
            "configuration_digest": profile.configuration_digest,
            "credential_reference": profile.credential_reference,
            "credential_epoch": profile.credential_epoch,
            "max_contexts_per_host": profile.max_contexts_per_host,
            "max_attachments_per_context": profile.max_attachments_per_context,
            "max_lifecycle_operations_per_host": (
                profile.max_lifecycle_operations_per_host
            ),
            "max_lifecycle_operations_per_context": (
                profile.max_lifecycle_operations_per_context
            ),
            "journal_max_entries": profile.journal_max_entries,
            "journal_max_bytes": profile.journal_max_bytes,
            "revision": profile.revision,
        }

    @staticmethod
    def _driver_view_in_session(
        session: Session, profile: DriverProfile
    ) -> dict[str, Any]:
        host = session.scalar(
            select(DriverHostGeneration)
            .where(DriverHostGeneration.profile_id == profile.id)
            .order_by(DriverHostGeneration.generation_number.desc())
            .limit(1)
        )
        capabilities = (
            session.scalars(
                select(DriverCapability)
                .where(DriverCapability.host_generation_id == host.id)
                .order_by(DriverCapability.method)
            ).all()
            if host is not None
            else ()
        )
        return driver_dict(profile, host, capabilities)

    @staticmethod
    def _operation_view_in_session(
        session: Session, operation: DriverOperation
    ) -> dict[str, Any]:
        attempts = session.scalars(
            select(DriverOperationAttempt)
            .where(DriverOperationAttempt.operation_id == operation.id)
            .order_by(DriverOperationAttempt.attempt_number)
        ).all()
        transitions = session.scalars(
            select(DriverOperationTransition)
            .join(
                DriverOperationAttempt,
                DriverOperationTransition.attempt_id == DriverOperationAttempt.id,
            )
            .where(DriverOperationTransition.operation_id == operation.id)
            .order_by(
                DriverOperationAttempt.attempt_number,
                DriverOperationTransition.sequence,
            )
        ).all()
        return operation_dict(operation, attempts, transitions)


__all__ = [
    "ALL_RPC_METHODS",
    "CapabilitySpec",
    "DEFAULT_PROFILE_DIGEST",
    "DEFAULT_PROFILE_ID",
    "DriverConflictError",
    "DriverNotFoundError",
    "DriverRepository",
    "DriverRepositoryError",
    "DriverValidationError",
    "MAX_DRIVER_EVENT_REPLAY",
    "MAX_DRIVER_EVENT_SEQUENCE",
    "READ_METHODS",
]
