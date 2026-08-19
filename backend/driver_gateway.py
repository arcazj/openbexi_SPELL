"""Canonical supervisor boundary for the bundled v0.4 simulator driver."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy.exc import SQLAlchemyError

from .config import Settings
from .driver_client import DriverClient, DriverTransportError
from .driver_domain import (
    CAPABILITY_MATRIX,
    CONTRACT_MAJOR,
    CONTRACT_MINOR,
    CONTRACT_PACKAGE,
    DEFAULT_DRIVER_PROFILE_ID,
    DEFAULT_HOST_SCHEMA,
    DEFAULT_LOGICAL_DRIVER_ID,
    DEFAULT_SERVER_PROFILE_ID,
    AttachExecutionCommand,
    CancelLifecycleOperationCommand,
    CloseContextCommand,
    DetachExecutionCommand,
    DrainHostCommand,
    DriverRpcMethod,
    EffectCertainty,
    EffectClass,
    GenerationTuple,
    GetOperationQuery,
    HandshakeResult,
    HealthResult,
    OpenContextCommand,
    OperationAttemptResult,
    OperationResult,
    OperationStage,
    ResultCode,
)
from .driver_models import BINDING_STATES, CONTEXT_STATES
from .driver_repository import (
    BindingStateObservation,
    CapabilitySpec,
    ContextStateObservation,
    DriverConflictError,
    DriverNotFoundError,
    DriverRepository,
    DriverValidationError,
)
from .observation_domain import (
    GetTMQuery,
    GetTMResult,
    GetTimeQuery,
    GetTimeResult,
)


GATEWAY_ACTOR = "driver-gateway"
GATEWAY_CORRELATION = "driver-gateway-lifecycle"
EXPECTED_IMPLEMENTATION_VERSION = "0.4.0"
OUTBOX_BATCH_SIZE = 100
MAX_STORAGE_RETRY_SECONDS = 5.0
MAX_OBSERVATION_FUTURE_SKEW_SECONDS = 5.0
MAX_REJECTED_HEALTH_BEFORE_REHANDSHAKE = 3
_BOUNDED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_COMMAND_DETAILS = {
    OpenContextCommand: (DriverRpcMethod.OPEN_CONTEXT, EffectClass.CONTEXT_OPEN),
    CloseContextCommand: (DriverRpcMethod.CLOSE_CONTEXT, EffectClass.CONTEXT_CLOSE),
    AttachExecutionCommand: (
        DriverRpcMethod.ATTACH_EXECUTION,
        EffectClass.EXECUTION_ATTACH,
    ),
    DetachExecutionCommand: (
        DriverRpcMethod.DETACH_EXECUTION,
        EffectClass.EXECUTION_DETACH,
    ),
    CancelLifecycleOperationCommand: (
        DriverRpcMethod.CANCEL_LIFECYCLE_OPERATION,
        EffectClass.LIFECYCLE_CANCEL,
    ),
    DrainHostCommand: (DriverRpcMethod.DRAIN_HOST, EffectClass.HOST_DRAIN),
}
_CLIENT_METHODS = {
    DriverRpcMethod.OPEN_CONTEXT: "open_context",
    DriverRpcMethod.CLOSE_CONTEXT: "close_context",
    DriverRpcMethod.ATTACH_EXECUTION: "attach_execution",
    DriverRpcMethod.DETACH_EXECUTION: "detach_execution",
    DriverRpcMethod.CANCEL_LIFECYCLE_OPERATION: "cancel_lifecycle_operation",
    DriverRpcMethod.DRAIN_HOST: "drain_host",
}


class DriverGatewayError(RuntimeError):
    """A bounded gateway failure that contains no peer-supplied payload."""


def _utc_from_milliseconds(value: int) -> datetime:
    if type(value) is not int or value <= 0:
        raise DriverGatewayError("driver timestamp is invalid")
    try:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise DriverGatewayError("driver timestamp is invalid") from exc


def _observation_from_milliseconds(value: int) -> datetime:
    observed_at = _utc_from_milliseconds(value)
    latest_allowed = datetime.now(timezone.utc) + timedelta(
        seconds=MAX_OBSERVATION_FUTURE_SKEW_SECONDS
    )
    if observed_at > latest_allowed:
        raise DriverGatewayError("driver observation timestamp is in the future")
    return observed_at


def _capacity_values_are_exact_integers(capacity: Any) -> bool:
    return all(
        type(value) is int
        for value in (
            capacity.max_contexts_per_host,
            capacity.max_attachments_per_context,
            capacity.max_lifecycle_operations_per_host,
            capacity.max_lifecycle_operations_per_context,
            capacity.contexts,
            capacity.attachments,
            capacity.lifecycle_operations_host,
            capacity.lifecycle_operations_context,
        )
    )


def _result_evidence(result: OperationResult) -> str:
    encoded = json.dumps(
        asdict(result),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _terminal_observation(attempt: OperationAttemptResult) -> datetime:
    requested = attempt.requested_unix_ms
    accepted = attempt.accepted_unix_ms
    dispatched = attempt.dispatched_unix_ms
    settled = attempt.settled_unix_ms
    if any(
        type(value) is not int
        for value in (requested, accepted, dispatched, settled)
    ):
        raise DriverGatewayError("driver terminal timestamps are invalid")
    if requested <= 0 or accepted <= 0 or settled <= 0 or dispatched < 0:
        raise DriverGatewayError("driver terminal timestamps are invalid")
    if not requested <= accepted <= settled:
        raise DriverGatewayError("driver terminal timestamps are out of order")
    if dispatched == 0:
        if attempt.certainty is not EffectCertainty.NO_EFFECT:
            raise DriverGatewayError("confirmed effect has no dispatch timestamp")
    elif not accepted <= dispatched <= settled:
        raise DriverGatewayError("driver terminal timestamps are out of order")
    return _observation_from_milliseconds(settled)


class DriverGateway:
    """Own the mTLS channel and canonical no-resend reconciliation protocol."""

    def __init__(
        self,
        repository: DriverRepository,
        settings: Settings,
        *,
        client_factory: Callable[..., DriverClient] = DriverClient.from_files,
        outbox_publisher: Callable[[str, dict[str, Any]], Any] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self._client_factory = client_factory
        self._outbox_publisher = outbox_publisher
        self._client: DriverClient | None = None
        self._handshake: HandshakeResult | None = None
        self._revalidating_generation: str | None = None
        self._health_admitted_generation: str | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._outbox_task: asyncio.Task[None] | None = None
        self._operation_lock = asyncio.Lock()
        self._started = False
        self._closing = False

    @property
    def connected(self) -> bool:
        return (
            self._handshake is not None
            and self._revalidating_generation is None
            and self._health_admitted_generation == self.host_generation_id
        )

    @property
    def host_generation_id(self) -> str | None:
        return (
            self._handshake.driver.driver_host_generation
            if self._handshake is not None
            else None
        )

    def observation_generations(self) -> dict[str, Any]:
        """Return the currently admitted host and active context read tuples."""

        if (
            not self.connected
            or self._handshake is None
            or self._client is None
        ):
            raise DriverGatewayError("driver is not connected")
        driver = self._handshake.driver
        host = GenerationTuple(
            server_profile_id=driver.server_profile_id,
            driver_host_generation=driver.driver_host_generation,
            host_profile_digest=driver.host_profile_digest,
        )
        page = self.repository.list_context_generations(limit=100)
        contexts = tuple(
            GenerationTuple(
                server_profile_id=driver.server_profile_id,
                driver_host_generation=driver.driver_host_generation,
                host_profile_digest=driver.host_profile_digest,
                context_id=item["context_id"],
                context_generation=item["context_generation_id"],
                context_binding_digest=item["configuration_digest"],
            )
            for item in page["items"]
            if item["host_generation_id"] == driver.driver_host_generation
            and item["state"] == "ACTIVE"
            and item["ready"] is True
        )
        return {
            "host": host,
            "contexts": contexts,
            "credential_epoch": driver.credential_epoch,
        }

    async def get_time(self, query: GetTimeQuery) -> GetTimeResult:
        generations = self.observation_generations()
        if (
            query.generations != generations["host"]
            or query.credential_epoch != generations["credential_epoch"]
            or self._client is None
        ):
            raise DriverGatewayError("driver time query generation differs")
        return await self._client.get_time(query)

    async def get_tm(self, query: GetTMQuery) -> GetTMResult:
        generations = self.observation_generations()
        if (
            query.generations not in generations["contexts"]
            or query.credential_epoch != generations["credential_epoch"]
            or self._client is None
        ):
            raise DriverGatewayError("driver telemetry query generation differs")
        return await self._client.get_tm(query)

    async def start(self) -> None:
        if self._started:
            raise DriverGatewayError("driver gateway is already started")
        self._started = True
        self._closing = False
        try:
            self.repository.configure_profile_enabled(
                DEFAULT_DRIVER_PROFILE_ID,
                self.settings.driver_enabled,
                actor=GATEWAY_ACTOR,
                correlation_id=GATEWAY_CORRELATION,
            )
            if self.settings.driver_enabled:
                profile = self.repository.get_profile_configuration(
                    DEFAULT_DRIVER_PROFILE_ID
                )
                credential_epoch = int(profile["credential_epoch"])
                self._client = self._client_factory(
                    self.settings.driver_target,
                    self.settings.driver_ca_path,
                    self.settings.driver_client_cert_path,
                    self.settings.driver_client_key_path,
                    self.settings.driver_rpc_timeout_seconds,
                    credential_epoch=credential_epoch,
                    host_profile_digest=str(profile["configuration_digest"]),
                )
                try:
                    await self._handshake_once()
                    await self._health_once()
                    if self.connected:
                        await self.reconcile_pending_operations()
                except DriverTransportError:
                    # The channel retains its credentials and can reconnect. One
                    # failed call is not a mutation retry; the poll observes again.
                    pass
                self._poll_task = asyncio.create_task(
                    self._poll_loop(), name="spell-driver-health-poll"
                )
            if self._outbox_publisher is not None:
                self._outbox_task = asyncio.create_task(
                    self._outbox_loop(), name="spell-driver-outbox-relay"
                )
        except Exception:
            await self._stop_runtime()
            self._started = False
            raise

    async def close(self) -> None:
        self._closing = True
        await self._stop_runtime()
        self._started = False

    async def _stop_runtime(self) -> None:
        tasks = tuple(
            task for task in (self._poll_task, self._outbox_task) if task is not None
        )
        self._poll_task = None
        self._outbox_task = None
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self._client is not None:
            await self._client.close()
            self._client = None
        self._handshake = None
        self._revalidating_generation = None
        self._health_admitted_generation = None

    async def _poll_loop(self) -> None:
        storage_failure_count = 0
        rejected_health_count = 0
        while not self._closing:
            try:
                if storage_failure_count:
                    delay = self._storage_retry_delay(storage_failure_count)
                else:
                    delay = self.settings.driver_poll_seconds
                await asyncio.sleep(delay)
                if self._handshake is None:
                    if self._revalidating_generation is None:
                        await self._handshake_once()
                    else:
                        await self._handshake_once(
                            expected_generation=self._revalidating_generation,
                            persist_observation=False,
                        )
                else:
                    polled_generation = self.host_generation_id
                    try:
                        await self._health_once()
                    except (
                        DriverGatewayError,
                        DriverConflictError,
                        DriverNotFoundError,
                        DriverValidationError,
                    ):
                        storage_failure_count = 0
                        if self._handshake is None:
                            self._revalidating_generation = polled_generation
                        rejected_health_count += 1
                        if (
                            rejected_health_count
                            >= MAX_REJECTED_HEALTH_BEFORE_REHANDSHAKE
                        ):
                            self._revalidating_generation = polled_generation
                            self._handshake = None
                            self._health_admitted_generation = None
                            rejected_health_count = 0
                        continue
                    rejected_health_count = 0
                    if self.connected:
                        await self.reconcile_pending_operations()
                storage_failure_count = 0
            except asyncio.CancelledError:
                raise
            except SQLAlchemyError:
                # The last persisted observation becomes stale by time while the
                # system of record is unavailable. Keep the same poll task alive
                # and retry without attempting another storage mutation here.
                storage_failure_count += 1
            except DriverTransportError:
                self._record_host_failure("DEGRADED")
                # A recovered channel may terminate at a newly generated host.
                # Re-handshake before trusting any further health or operation
                # result instead of pinning the poller to a dead generation.
                self._handshake = None
                self._health_admitted_generation = None
            except Exception:
                self._record_host_failure("FAILED")
                return

    def _storage_retry_delay(self, failure_count: int) -> float:
        exponent = min(max(failure_count, 1), 16)
        ceiling = min(
            self.settings.driver_stale_after_seconds,
            MAX_STORAGE_RETRY_SECONDS,
        )
        return min(self.settings.driver_poll_seconds * (2**exponent), ceiling)

    async def _outbox_loop(self) -> None:
        while not self._closing:
            try:
                await self._publish_outbox_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Publication is downstream of the authoritative commit. Keep the
                # first failed row pending and retry it on the next relay pass.
                pass
            await asyncio.sleep(self.settings.driver_poll_seconds)

    async def _publish_outbox_once(self) -> int:
        if self._outbox_publisher is None:
            return 0
        published = 0
        while True:
            rows = self.repository.pending_outbox(limit=OUTBOX_BATCH_SIZE)
            if not rows:
                return published
            for row in rows:
                event = {
                    **row["payload"],
                    "sequence": row["sequence"],
                    "created_at": row["created_at"],
                }
                outcome = self._outbox_publisher(row["topic"], event)
                if inspect.isawaitable(outcome):
                    await outcome
                self.repository.mark_outbox_published(
                    row["sequence"],
                    row["event_id"],
                    published_at=datetime.now(timezone.utc),
                )
                published += 1
            if len(rows) < OUTBOX_BATCH_SIZE:
                return published

    async def _handshake_once(
        self,
        *,
        expected_generation: str | None = None,
        persist_observation: bool = True,
    ) -> None:
        if self._client is None:
            raise DriverGatewayError("driver channel is not configured")
        self._health_admitted_generation = None
        result = await self._client.handshake()
        profile = self.repository.get_profile_configuration(
            DEFAULT_DRIVER_PROFILE_ID
        )
        observed_at = self._validate_handshake(result, profile)
        if (
            expected_generation is not None
            and result.driver.driver_host_generation != expected_generation
        ):
            raise DriverGatewayError("driver handshake generation differs from health")
        if int(profile["credential_epoch"]) != result.driver.credential_epoch:
            raise DriverGatewayError("driver credential epoch differs")
        current = self.repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        current_generation = current.get("current_host_generation_id")
        if not persist_observation:
            if (
                expected_generation is None
                or self._revalidating_generation != expected_generation
                or current_generation != expected_generation
                or result.driver.driver_host_generation != expected_generation
                or current["state"] in {"CLOSED", "FAILED"}
            ):
                raise DriverGatewayError(
                    "driver revalidation handshake differs from canonical generation"
                )
            self._handshake = result
            return
        if current_generation and current_generation != result.driver.driver_host_generation:
            if current["state"] not in {"CLOSED", "FAILED"}:
                self.repository.record_host_state(
                    current_generation,
                    "FAILED",
                    expected_revision=int(current["revision"]),
                    actor=GATEWAY_ACTOR,
                    correlation_id=GATEWAY_CORRELATION,
                    observed_at=datetime.now(timezone.utc),
                )
            current_generation = None
        if current_generation is None:
            self.repository.create_host_generation(
                profile_id=DEFAULT_DRIVER_PROFILE_ID,
                host_generation_id=result.driver.driver_host_generation,
                contract_version=(
                    f"{result.contract_version.major}.{result.contract_version.minor}"
                ),
                implementation_version=result.driver.implementation_version,
                capabilities=tuple(
                    CapabilitySpec(
                        service=item.service,
                        method=item.method.value,
                        mutability=item.mutability,
                        modifiers=item.modifiers,
                        formats=item.formats,
                        stream_support=item.stream_support,
                    )
                    for item in result.capabilities
                ),
                actor=GATEWAY_ACTOR,
                correlation_id=GATEWAY_CORRELATION,
            )
        current = self.repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        if current["current_host_generation_id"] != result.driver.driver_host_generation:
            raise DriverGatewayError("driver generation did not become canonical")
        if current["state"] in {"CLOSED", "FAILED"}:
            raise DriverGatewayError("driver reused a terminal host generation")
        self.repository.record_host_state(
            result.driver.driver_host_generation,
            result.host_state,
            expected_revision=int(current["revision"]),
            actor=GATEWAY_ACTOR,
            correlation_id=GATEWAY_CORRELATION,
            observed_at=observed_at,
        )
        self._handshake = result

    async def _health_once(self) -> None:
        if self._client is None or self._handshake is None:
            raise DriverGatewayError("driver handshake is incomplete")
        self._health_admitted_generation = None
        result = await self._client.health()
        if (
            result.driver.driver_host_generation
            != self._handshake.driver.driver_host_generation
        ):
            if self._revalidating_generation is not None:
                raise DriverGatewayError(
                    "driver generation changed during health revalidation"
                )
            # A host restart is a generation transition, not a same-generation
            # health update. Validate the complete transition signal, then let a
            # fully validated handshake fence the old generation atomically.
            self._validate_generation_change_health(result)
            expected_generation = result.driver.driver_host_generation
            self._handshake = None
            await self._handshake_once(expected_generation=expected_generation)
            return
        current, host_observed_at, contexts, attachments = self._preflight_health(
            result
        )
        self.repository.apply_health_snapshot(
            result.driver.driver_host_generation,
            result.host_state,
            expected_revision=int(current["revision"]),
            observed_at=host_observed_at,
            contexts=tuple(
                ContextStateObservation(
                    context_generation_id=context.context_generation,
                    state=context.state,
                    expected_revision=int(stored["revision"]),
                    observed_at=observed_at,
                )
                for context, stored, observed_at in contexts
            ),
            bindings=tuple(
                BindingStateObservation(
                    driver_binding_id=attachment.driver_binding_id,
                    state=attachment.state,
                    expected_revision=int(stored["revision"]),
                    observed_at=observed_at,
                )
                for attachment, stored, observed_at in attachments
            ),
            actor=GATEWAY_ACTOR,
            correlation_id=GATEWAY_CORRELATION,
        )
        self._revalidating_generation = None
        self._health_admitted_generation = result.driver.driver_host_generation

    def _record_host_failure(self, state: str) -> None:
        try:
            current = self.repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
            generation = (
                self.host_generation_id
                or current.get("current_host_generation_id")
            )
            if generation is None:
                return
            if current["state"] in {"CLOSED", "FAILED"}:
                return
            self.repository.record_host_state(
                generation,
                state,
                expected_revision=int(current["revision"]),
                actor=GATEWAY_ACTOR,
                correlation_id=GATEWAY_CORRELATION,
                observed_at=datetime.now(timezone.utc),
            )
        except (DriverConflictError, DriverNotFoundError, SQLAlchemyError):
            return

    @staticmethod
    def _validate_handshake(
        result: HandshakeResult, profile: dict[str, Any]
    ) -> datetime:
        driver = result.driver
        capacity = result.capacity
        observed_at = _observation_from_milliseconds(result.last_observed_unix_ms)
        if result.error is not None:
            raise DriverGatewayError("driver handshake was rejected")
        if (
            profile.get("id") != DEFAULT_DRIVER_PROFILE_ID
            or profile.get("server_profile_id") != DEFAULT_SERVER_PROFILE_ID
            or profile.get("logical_driver_id") != DEFAULT_LOGICAL_DRIVER_ID
            or profile.get("simulator") is not True
            or profile.get("enabled") is not True
            or profile.get("contract_package") != CONTRACT_PACKAGE
            or profile.get("configuration_schema_version") != DEFAULT_HOST_SCHEMA
            or result.contract_version.major != CONTRACT_MAJOR
            or result.contract_version.minor != CONTRACT_MINOR
            or driver.logical_driver_id != profile["logical_driver_id"]
            or driver.server_profile_id != profile["server_profile_id"]
            or driver.driver_profile_id != DEFAULT_DRIVER_PROFILE_ID
            or not driver.simulator
            or driver.host_configuration_schema
            != profile["configuration_schema_version"]
            or driver.host_profile_digest != profile["configuration_digest"]
            or driver.implementation_version != EXPECTED_IMPLEMENTATION_VERSION
            or driver.credential_epoch != profile["credential_epoch"]
            or type(driver.driver_host_generation) is not str
            or _BOUNDED_ID.fullmatch(driver.driver_host_generation) is None
            or result.host_state not in {"STARTING", "READY", "DEGRADED"}
        ):
            raise DriverGatewayError("driver handshake identity differs")
        expected_capabilities = {
            (
                definition.method,
                definition.service,
                definition.mutability,
                definition.modifiers,
                (definition.format,),
                definition.stream_support,
            )
            for definition in CAPABILITY_MATRIX
        }
        actual_capabilities = {
            (
                item.method,
                item.service,
                item.mutability,
                item.modifiers,
                item.formats,
                item.stream_support,
            )
            for item in result.capabilities
        }
        if (
            not _capacity_values_are_exact_integers(capacity)
            or actual_capabilities != expected_capabilities
            or len(result.capabilities) != len(expected_capabilities)
            or capacity.max_contexts_per_host != profile["max_contexts_per_host"]
            or capacity.max_attachments_per_context
            != profile["max_attachments_per_context"]
            or capacity.max_lifecycle_operations_per_host
            != profile["max_lifecycle_operations_per_host"]
            or capacity.max_lifecycle_operations_per_context
            != profile["max_lifecycle_operations_per_context"]
            or not 0 <= capacity.contexts <= capacity.max_contexts_per_host
            or not 0
            <= capacity.lifecycle_operations_host
            <= capacity.max_lifecycle_operations_per_host
        ):
            raise DriverGatewayError("driver capability or capacity differs")
        return observed_at

    def _validate_generation_change_health(self, result: HealthResult) -> datetime:
        assert self._handshake is not None
        expected = self._handshake.driver
        expected_capacity = self._handshake.capacity
        observed_at = _observation_from_milliseconds(result.last_observed_unix_ms)
        for context in result.contexts:
            _observation_from_milliseconds(context.last_observed_unix_ms)
        for attachment in result.attachments:
            _observation_from_milliseconds(attachment.last_observed_unix_ms)
        actual_without_generation = (
            result.driver.logical_driver_id,
            result.driver.implementation_version,
            result.driver.simulator,
            result.driver.server_profile_id,
            result.driver.driver_profile_id,
            result.driver.host_configuration_schema,
            result.driver.host_profile_digest,
            result.driver.credential_epoch,
        )
        expected_without_generation = (
            expected.logical_driver_id,
            expected.implementation_version,
            expected.simulator,
            expected.server_profile_id,
            expected.driver_profile_id,
            expected.host_configuration_schema,
            expected.host_profile_digest,
            expected.credential_epoch,
        )
        capacity = result.capacity
        if (
            result.error is not None
            or result.contract_version != self._handshake.contract_version
            or actual_without_generation != expected_without_generation
            or type(result.driver.driver_host_generation) is not str
            or _BOUNDED_ID.fullmatch(result.driver.driver_host_generation) is None
            or result.host_state
            not in {"STARTING", "READY", "DEGRADED", "DRAINING", "CLOSED", "FAILED"}
            or type(result.ready) is not bool
            or result.ready != (result.host_state == "READY")
            or not _capacity_values_are_exact_integers(capacity)
            or capacity.max_contexts_per_host
            != expected_capacity.max_contexts_per_host
            or capacity.max_attachments_per_context
            != expected_capacity.max_attachments_per_context
            or capacity.max_lifecycle_operations_per_host
            != expected_capacity.max_lifecycle_operations_per_host
            or capacity.max_lifecycle_operations_per_context
            != expected_capacity.max_lifecycle_operations_per_context
            or result.contexts
            or result.attachments
            or capacity.contexts != 0
            or capacity.attachments != 0
            or not 0
            <= capacity.lifecycle_operations_host
            <= capacity.max_lifecycle_operations_per_host
            or not 0
            <= capacity.lifecycle_operations_context
            <= capacity.max_lifecycle_operations_per_context
        ):
            raise DriverGatewayError("driver generation transition health differs")
        return observed_at

    def _validate_health(
        self, result: HealthResult
    ) -> tuple[datetime, tuple[datetime, ...], tuple[datetime, ...]]:
        assert self._handshake is not None
        expected = self._handshake.driver
        expected_capacity = self._handshake.capacity
        capacity = result.capacity
        context_keys = {
            (item.context_id, item.context_generation) for item in result.contexts
        }
        attachment_keys = {
            item.driver_binding_id for item in result.attachments
        }
        host_observed_at = _observation_from_milliseconds(
            result.last_observed_unix_ms
        )
        context_observations = tuple(
            _observation_from_milliseconds(context.last_observed_unix_ms)
            for context in result.contexts
        )
        attachment_observations = tuple(
            _observation_from_milliseconds(attachment.last_observed_unix_ms)
            for attachment in result.attachments
        )
        if (
            result.error is not None
            or result.contract_version != self._handshake.contract_version
            or result.driver != expected
            or result.host_state not in {
                "STARTING",
                "READY",
                "DEGRADED",
                "DRAINING",
                "CLOSED",
                "FAILED",
            }
            or type(result.ready) is not bool
            or result.ready != (result.host_state == "READY")
            or not _capacity_values_are_exact_integers(capacity)
            or capacity.max_contexts_per_host
            != expected_capacity.max_contexts_per_host
            or capacity.max_attachments_per_context
            != expected_capacity.max_attachments_per_context
            or capacity.max_lifecycle_operations_per_host
            != expected_capacity.max_lifecycle_operations_per_host
            or capacity.max_lifecycle_operations_per_context
            != expected_capacity.max_lifecycle_operations_per_context
            or not 0 <= capacity.contexts <= capacity.max_contexts_per_host
            or not 0 <= capacity.attachments <= capacity.max_contexts_per_host
            * capacity.max_attachments_per_context
            or not 0
            <= capacity.lifecycle_operations_host
            <= capacity.max_lifecycle_operations_per_host
            or not 0
            <= capacity.lifecycle_operations_context
            <= capacity.max_lifecycle_operations_per_context
            or capacity.contexts != len(result.contexts)
            or capacity.attachments != len(result.attachments)
            or len(context_keys) != len(result.contexts)
            or len(attachment_keys) != len(result.attachments)
            or any(
                context.state not in CONTEXT_STATES
                or type(context.ready) is not bool
                or context.ready != (context.state == "ACTIVE")
                for context in result.contexts
            )
            or any(
                attachment.state not in BINDING_STATES
                for attachment in result.attachments
            )
        ):
            raise DriverGatewayError("driver health identity differs")
        return host_observed_at, context_observations, attachment_observations

    def _preflight_health(
        self, result: HealthResult
    ) -> tuple[
        dict[str, Any],
        datetime,
        tuple[tuple[Any, dict[str, Any], datetime], ...],
        tuple[tuple[Any, dict[str, Any], datetime], ...],
    ]:
        assert self._handshake is not None
        host_observed_at, context_observations, attachment_observations = (
            self._validate_health(result)
        )
        current = self.repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        if (
            current.get("current_host_generation_id")
            != self._handshake.driver.driver_host_generation
        ):
            raise DriverGatewayError("canonical driver generation differs")

        contexts = []
        context_generation_ids = set()
        for context, observed_at in zip(result.contexts, context_observations):
            stored = self.repository.get_context_generation(
                context.context_id, context.context_generation
            )["context_generation"]
            if (
                stored["host_generation_id"]
                != self._handshake.driver.driver_host_generation
                or stored["context_id"] != context.context_id
                or stored["context_generation_id"] != context.context_generation
                or stored["configuration_digest"]
                != context.context_binding_digest
            ):
                raise DriverGatewayError("driver context identity differs")
            context_generation_ids.add(context.context_generation)
            contexts.append((context, stored, observed_at))

        attachments = []
        for attachment, observed_at in zip(
            result.attachments, attachment_observations
        ):
            stored = self.repository.get_binding(attachment.driver_binding_id)[
                "binding"
            ]
            if (
                stored["context_generation_id"] not in context_generation_ids
                or stored["driver_binding_id"] != attachment.driver_binding_id
                or stored["execution_id"] != attachment.execution_id
                or stored["attachment_generation_id"]
                != attachment.execution_attachment_generation
                or stored["configuration_digest"]
                != attachment.execution_attachment_digest
            ):
                raise DriverGatewayError("driver attachment identity differs")
            attachments.append((attachment, stored, observed_at))
        return (
            current,
            host_observed_at,
            tuple(contexts),
            tuple(attachments),
        )

    async def execute_lifecycle(
        self,
        command: OpenContextCommand
        | CloseContextCommand
        | AttachExecutionCommand
        | DetachExecutionCommand
        | CancelLifecycleOperationCommand
        | DrainHostCommand,
        *,
        actor: str,
    ) -> dict[str, Any]:
        """Persist one command, dispatch once, and never resend uncertain work."""

        async with self._operation_lock:
            return await self._execute_lifecycle(command, actor=actor)

    async def _execute_lifecycle(
        self,
        command: OpenContextCommand
        | CloseContextCommand
        | AttachExecutionCommand
        | DetachExecutionCommand
        | CancelLifecycleOperationCommand
        | DrainHostCommand,
        *,
        actor: str,
    ) -> dict[str, Any]:

        if (
            self._client is None
            or self._handshake is None
            or self._revalidating_generation is not None
            or self._health_admitted_generation != self.host_generation_id
        ):
            raise DriverGatewayError("driver is not connected")
        details = _COMMAND_DETAILS.get(type(command))
        if details is None:
            raise DriverGatewayError("unsupported driver lifecycle command")
        method, effect_class = details
        identity = command.identity
        generations = identity.generations
        if (
            generations.driver_host_generation != self.host_generation_id
            or generations.host_profile_digest
            != self._handshake.driver.host_profile_digest
            or generations.server_profile_id
            != self._handshake.driver.server_profile_id
            or identity.credential_epoch != self._handshake.driver.credential_epoch
        ):
            raise DriverGatewayError("driver command generation differs")
        self._validate_command_tuple(command)
        target_operation_id = (
            command.target_operation_id
            if isinstance(command, CancelLifecycleOperationCommand)
            else None
        )
        target_attempt_id = (
            command.target_attempt_id
            if isinstance(command, CancelLifecycleOperationCommand)
            else None
        )
        try:
            existing = self.repository.get_operation(identity.operation_id)["operation"]
        except DriverNotFoundError:
            existing = None
        if existing is None and identity.attempt_number != 1:
            raise DriverGatewayError("new driver operation must begin with attempt one")
        accepted = self.repository.accept_operation(
            operation_id=identity.operation_id,
            attempt_id=identity.attempt_id,
            method=method,
            request_digest=command.request_digest,
            effect_class=effect_class,
            host_generation_id=generations.driver_host_generation,
            context_generation_id=generations.context_generation or None,
            driver_binding_id=generations.driver_binding_id or None,
            target_operation_id=target_operation_id,
            target_attempt_id=target_attempt_id,
            actor=actor,
            correlation_id=identity.correlation_id,
            deadline_at=_utc_from_milliseconds(identity.deadline_unix_ms),
            lifecycle_reason=(
                command.configuration.reason
                if isinstance(command, AttachExecutionCommand)
                else None
            ),
            replaced_driver_binding_id=(
                command.configuration.replaced_driver_binding_id
                if isinstance(command, AttachExecutionCommand)
                else None
            ),
        )
        self._validate_canonical_acceptance(command, accepted)
        if accepted["stage"] != "ACCEPTED":
            return accepted
        if datetime.now(timezone.utc) >= _utc_from_milliseconds(identity.deadline_unix_ms):
            return self.repository.append_operation_transition(
                identity.operation_id,
                identity.attempt_id,
                expected_revision=int(accepted["revision"]),
                stage="SETTLED",
                certainty="NO_EFFECT",
                disposition=ResultCode.DEADLINE_EXCEEDED,
                safe_error_code="DEADLINE",
                safe_error_message="driver request deadline elapsed before dispatch",
                evidence_digest=None,
                actor=actor,
                correlation_id=identity.correlation_id,
                terminal_observed_at=datetime.now(timezone.utc),
            )
        dispatched = self.repository.append_operation_transition(
            identity.operation_id,
            identity.attempt_id,
            expected_revision=int(accepted["revision"]),
            stage="DISPATCHED",
            certainty="EFFECT_POSSIBLE",
            disposition=None,
            safe_error_code=None,
            safe_error_message=None,
            evidence_digest=None,
            actor=actor,
            correlation_id=identity.correlation_id,
        )
        try:
            result = await getattr(self._client, _CLIENT_METHODS[method])(command)
        except DriverTransportError as exc:
            return self.repository.append_operation_transition(
                identity.operation_id,
                identity.attempt_id,
                expected_revision=int(dispatched["revision"]),
                stage="RECONCILING",
                certainty="EFFECT_POSSIBLE",
                disposition=ResultCode.RECONCILIATION_REQUIRED,
                safe_error_code="TRANSPORT",
                safe_error_message=f"driver response unavailable ({exc.code})",
                evidence_digest=None,
                actor=actor,
                correlation_id=identity.correlation_id,
            )
        try:
            return self._record_result(command, result, dispatched, actor=actor)
        except (DriverConflictError, DriverNotFoundError):
            raise
        except Exception:
            return self.repository.append_operation_transition(
                identity.operation_id,
                identity.attempt_id,
                expected_revision=int(dispatched["revision"]),
                stage="RECONCILING",
                certainty="EFFECT_UNKNOWN",
                disposition=ResultCode.RECONCILIATION_REQUIRED,
                safe_error_code="CONTRACT_MISMATCH",
                safe_error_message="driver result could not be validated",
                evidence_digest=None,
                actor=actor,
                correlation_id=identity.correlation_id,
            )

    @staticmethod
    def _validate_canonical_acceptance(
        command: OpenContextCommand
        | CloseContextCommand
        | AttachExecutionCommand
        | DetachExecutionCommand
        | CancelLifecycleOperationCommand
        | DrainHostCommand,
        accepted: dict[str, Any],
    ) -> None:
        identity = command.identity
        attempt = next(
            (
                item
                for item in accepted["attempts"]
                if item["attempt_id"] == identity.attempt_id
            ),
            None,
        )
        acceptance = next(
            (
                item
                for item in accepted["transitions"]
                if item["attempt_id"] == identity.attempt_id
                and item["sequence"] == 1
                and item["stage"] == "ACCEPTED"
            ),
            None,
        )
        expected_deadline = _utc_from_milliseconds(identity.deadline_unix_ms)
        try:
            persisted_deadline = datetime.fromisoformat(attempt["deadline_at"])
        except (AttributeError, TypeError, ValueError):
            persisted_deadline = None
        expected_reason = (
            command.configuration.reason
            if isinstance(command, AttachExecutionCommand)
            else None
        )
        expected_replaced_binding = (
            command.configuration.replaced_driver_binding_id
            if isinstance(command, AttachExecutionCommand)
            and command.configuration.replaced_driver_binding_id
            else None
        )
        if (
            accepted["operation_id"] != identity.operation_id
            or accepted["current_attempt_id"] != identity.attempt_id
            or accepted["current_attempt_number"] != identity.attempt_number
            or attempt is None
            or attempt["attempt_number"] != identity.attempt_number
            or attempt["request_digest"] != command.request_digest
            or attempt["credential_epoch"] != identity.credential_epoch
            or attempt["lifecycle_reason"] != expected_reason
            or attempt["replaced_driver_binding_id"]
            != expected_replaced_binding
            or persisted_deadline != expected_deadline
            or acceptance is None
            or acceptance["correlation_id"] != identity.correlation_id
        ):
            raise DriverGatewayError("driver operation acceptance identity differs")

    def _validate_command_tuple(
        self,
        command: OpenContextCommand
        | CloseContextCommand
        | AttachExecutionCommand
        | DetachExecutionCommand
        | CancelLifecycleOperationCommand
        | DrainHostCommand,
    ) -> None:
        """Fence the outbound tuple against the canonical persisted identities."""

        generations = command.identity.generations
        context: dict[str, Any] | None = None
        binding: dict[str, Any] | None = None
        try:
            if generations.context_generation:
                context = self.repository.get_context_generation(
                    generations.context_id, generations.context_generation
                )["context_generation"]
            if generations.driver_binding_id:
                binding = self.repository.get_binding(
                    generations.driver_binding_id
                )["binding"]
        except DriverNotFoundError as exc:
            raise DriverGatewayError("driver command canonical tuple differs") from exc

        if context is not None and (
            context["host_generation_id"] != generations.driver_host_generation
            or context["context_id"] != generations.context_id
            or context["context_generation_id"] != generations.context_generation
            or context["configuration_digest"]
            != generations.context_binding_digest
        ):
            raise DriverGatewayError("driver command canonical tuple differs")
        if binding is not None and (
            context is None
            or binding["context_generation_id"]
            != generations.context_generation
            or binding["execution_id"] != generations.execution_id
            or binding["attachment_generation_id"]
            != generations.execution_attachment_generation
            or binding["configuration_digest"]
            != generations.execution_attachment_digest
        ):
            raise DriverGatewayError("driver command canonical tuple differs")

        if isinstance(command, (OpenContextCommand, CloseContextCommand)):
            exact_shape = context is not None and binding is None
        elif isinstance(command, (AttachExecutionCommand, DetachExecutionCommand)):
            exact_shape = context is not None and binding is not None
        elif isinstance(command, DrainHostCommand):
            exact_shape = context is None and binding is None
        else:
            exact_shape = self._cancel_tuple_matches(command, context, binding)
        if not exact_shape:
            raise DriverGatewayError("driver command canonical tuple differs")

        if isinstance(command, OpenContextCommand) and (
            context["configuration_schema_version"]
            != command.configuration.schema_version
            or generations.context_binding_digest
            != command.configuration.expected_digest
        ):
            raise DriverGatewayError("driver context configuration differs")
        if isinstance(command, AttachExecutionCommand) and (
            binding["configuration_schema_version"]
            != command.configuration.schema_version
            or generations.execution_attachment_digest
            != command.configuration.expected_digest
        ):
            raise DriverGatewayError("driver attachment configuration differs")
        if isinstance(command, AttachExecutionCommand):
            if command.configuration.reason == "RELOAD":
                try:
                    replaced = self.repository.get_binding(
                        command.configuration.replaced_driver_binding_id
                    )["binding"]
                except DriverNotFoundError as exc:
                    raise DriverGatewayError(
                        "driver reload replacement differs"
                    ) from exc
                if (
                    binding["replacement_of_driver_binding_id"]
                    != replaced["driver_binding_id"]
                    or not binding["replacement_pending"]
                    or binding["capacity_reserved"]
                    or replaced["context_generation_id"]
                    != generations.context_generation
                    or replaced["execution_id"] != generations.execution_id
                    or not replaced["capacity_reserved"]
                ):
                    raise DriverGatewayError("driver reload replacement differs")
            elif (
                binding["replacement_of_driver_binding_id"] is not None
                or binding["replacement_pending"]
            ):
                raise DriverGatewayError("initial attachment has reload lineage")

    def _cancel_tuple_matches(
        self,
        command: CancelLifecycleOperationCommand,
        context: dict[str, Any] | None,
        binding: dict[str, Any] | None,
    ) -> bool:
        try:
            target = self.repository.get_operation(command.target_operation_id)[
                "operation"
            ]
        except DriverNotFoundError:
            return False
        if target["current_attempt_id"] != command.target_attempt_id:
            return False
        attempt = next(
            (
                item
                for item in target["attempts"]
                if item["attempt_id"] == command.target_attempt_id
            ),
            None,
        )
        if attempt is None:
            return False
        generations = command.identity.generations
        return (
            attempt["server_profile_id"] == generations.server_profile_id
            and attempt["host_generation_id"]
            == generations.driver_host_generation
            and attempt["host_configuration_digest"]
            == generations.host_profile_digest
            and (attempt["context_generation_id"] or "")
            == generations.context_generation
            and (attempt["context_configuration_digest"] or "")
            == generations.context_binding_digest
            and (attempt["execution_id"] or "") == generations.execution_id
            and (attempt["attachment_generation_id"] or "")
            == generations.execution_attachment_generation
            and (attempt["attachment_configuration_digest"] or "")
            == generations.execution_attachment_digest
            and (attempt["driver_binding_id"] or "")
            == generations.driver_binding_id
            and (context is not None) == bool(generations.context_generation)
            and (binding is not None) == bool(generations.driver_binding_id)
        )

    def _record_result(
        self,
        command: OpenContextCommand
        | CloseContextCommand
        | AttachExecutionCommand
        | DetachExecutionCommand
        | CancelLifecycleOperationCommand
        | DrainHostCommand,
        result: OperationResult,
        canonical: dict[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        identity = command.identity
        method, effect_class = _COMMAND_DETAILS[type(command)]
        matching = [
            item for item in result.attempts if item.attempt_id == identity.attempt_id
        ]
        expected_reason = (
            command.configuration.reason
            if isinstance(command, AttachExecutionCommand)
            else ""
        )
        expected_replaced_binding = (
            command.configuration.replaced_driver_binding_id
            if isinstance(command, AttachExecutionCommand)
            else ""
        )
        valid = (
            result.operation_id == identity.operation_id
            and result.method == method
            and result.current_attempt_id == identity.attempt_id
            and len(matching) == 1
            and matching[0].attempt_number == identity.attempt_number
            and matching[0].request_digest == command.request_digest
            and matching[0].effect_class == effect_class
            and matching[0].generations == identity.generations
            and matching[0].lifecycle_reason == expected_reason
            and matching[0].replaced_driver_binding_id
            == expected_replaced_binding
            and matching[0].certainty is not None
            and (
                matching[0].error is None
                or len(matching[0].error.message.encode("utf-8")) <= 256
            )
        )
        attempt = matching[0] if valid else None
        terminal = bool(
            attempt is not None
            and attempt.stage == OperationStage.SETTLED
            and attempt.certainty
            in {EffectCertainty.NO_EFFECT, EffectCertainty.EFFECT_CONFIRMED}
        )
        terminal_observed_at: datetime | None = None
        if terminal:
            try:
                terminal_observed_at = _terminal_observation(attempt)
            except DriverGatewayError:
                valid = False
        if not valid:
            return self.repository.append_operation_transition(
                identity.operation_id,
                identity.attempt_id,
                expected_revision=int(canonical["revision"]),
                stage="RECONCILING",
                certainty="EFFECT_UNKNOWN",
                disposition=ResultCode.RECONCILIATION_REQUIRED,
                safe_error_code="CONTRACT_MISMATCH",
                safe_error_message="driver result did not satisfy the lifecycle contract",
                evidence_digest=None,
                actor=actor,
                correlation_id=identity.correlation_id,
            )
        assert attempt is not None
        certainty = attempt.certainty.value
        if not terminal and certainty not in {"EFFECT_POSSIBLE", "EFFECT_UNKNOWN"}:
            certainty = "EFFECT_UNKNOWN"
        error = attempt.error
        return self.repository.append_operation_transition(
            identity.operation_id,
            identity.attempt_id,
            expected_revision=int(canonical["revision"]),
            stage="SETTLED" if terminal else "RECONCILING",
            certainty=certainty,
            disposition=attempt.result_code,
            safe_error_code=error.code if error else None,
            safe_error_message=error.message if error else None,
            evidence_digest=_result_evidence(result),
            actor=actor,
            correlation_id=identity.correlation_id,
            terminal_observed_at=terminal_observed_at,
        )

    async def reconcile_pending_operations(self) -> int:
        """Read every unresolved current attempt once without resending its command."""

        reconciled = 0
        cursor: str | None = None
        while True:
            page = self.repository.list_reconciliation_operation_ids(
                limit=OUTBOX_BATCH_SIZE, cursor=cursor
            )
            for operation_id in page["items"]:
                try:
                    result = await self.reconcile_operation(operation_id)
                except (DriverConflictError, DriverNotFoundError):
                    # A competing request may have committed a newer canonical
                    # revision after this page was read. Re-read it next cycle.
                    continue
                if result["stage"] == "SETTLED":
                    reconciled += 1
            cursor = page["next_cursor"]
            if cursor is None:
                return reconciled

    async def reconcile_operation(self, operation_id: str) -> dict[str, Any]:
        """Query by original identity only; this method never dispatches a mutation."""

        async with self._operation_lock:
            return await self._reconcile_operation(operation_id)

    async def _reconcile_operation(self, operation_id: str) -> dict[str, Any]:

        if (
            self._client is None
            or self._handshake is None
            or self._revalidating_generation is not None
            or self._health_admitted_generation != self.host_generation_id
        ):
            raise DriverGatewayError("driver is not connected")
        canonical = self.repository.get_operation(operation_id)["operation"]
        if canonical["stage"] not in {"DISPATCHED", "RECONCILING"}:
            return canonical
        attempt = next(
            item
            for item in canonical["attempts"]
            if item["attempt_id"] == canonical["current_attempt_id"]
        )
        context_id = ""
        context_generation = attempt["context_generation_id"] or ""
        context_digest = attempt["context_configuration_digest"] or ""
        binding_id = attempt["driver_binding_id"] or ""
        if context_generation:
            cursor = None
            while True:
                page = self.repository.list_context_generations(
                    limit=100, cursor=cursor
                )
                context = next(
                    (
                        item
                        for item in page["items"]
                        if item["context_generation_id"] == context_generation
                    ),
                    None,
                )
                if context is not None:
                    context_id = context["context_id"]
                    break
                cursor = page["next_cursor"]
                if cursor is None:
                    raise DriverGatewayError("canonical context generation is missing")
        from .driver_domain import GenerationTuple

        generations = GenerationTuple(
            server_profile_id=attempt["server_profile_id"],
            driver_host_generation=attempt["host_generation_id"],
            host_profile_digest=attempt["host_configuration_digest"],
            context_id=context_id,
            context_generation=context_generation,
            context_binding_digest=context_digest,
            execution_id=attempt["execution_id"] or "",
            execution_attachment_generation=(
                attempt["attachment_generation_id"] or ""
            ),
            execution_attachment_digest=(
                attempt["attachment_configuration_digest"] or ""
            ),
            driver_binding_id=binding_id,
        )
        query = GetOperationQuery(
            generations=generations,
            target_operation_id=canonical["operation_id"],
            target_attempt_id=canonical["current_attempt_id"],
            correlation_id=canonical["transitions"][-1]["correlation_id"],
            deadline_unix_ms=int(
                datetime.now(timezone.utc).timestamp() * 1000
                + self.settings.driver_rpc_timeout_seconds * 1000
            ),
            # The query tuple names the historical accepting generation, while
            # the current service credential epoch authenticates this read.
            credential_epoch=int(self._handshake.driver.credential_epoch),
        )
        try:
            result = await self._client.get_operation(query)
        except DriverTransportError:
            return canonical
        # Reuse the immutable command digest/identity validation without creating
        # a second mutation. The journal result is validated directly here.
        matching = [
            item for item in result.attempts if item.attempt_id == query.target_attempt_id
        ]
        valid = not (
            result.operation_id != canonical["operation_id"]
            or result.current_attempt_id != canonical["current_attempt_id"]
            or result.method.value != canonical["method"]
            or len(matching) != 1
            or matching[0].request_digest != canonical["request_digest"]
            or matching[0].effect_class.value != canonical["effect_class"]
            or matching[0].attempt_number != canonical["current_attempt_number"]
            or matching[0].generations != query.generations
            or matching[0].lifecycle_reason
            != (attempt["lifecycle_reason"] or "")
            or matching[0].replaced_driver_binding_id
            != (attempt["replaced_driver_binding_id"] or "")
            or matching[0].certainty is None
            or not (
                (
                    matching[0].stage == OperationStage.SETTLED
                    and matching[0].certainty
                    in {
                        EffectCertainty.NO_EFFECT,
                        EffectCertainty.EFFECT_CONFIRMED,
                    }
                )
                or (
                    matching[0].stage != OperationStage.SETTLED
                    and matching[0].certainty
                    in {
                        EffectCertainty.EFFECT_POSSIBLE,
                        EffectCertainty.EFFECT_UNKNOWN,
                    }
                )
            )
            or (
                matching[0].error is not None
                and len(matching[0].error.message.encode("utf-8")) > 256
            )
        )
        terminal_observed_at: datetime | None = None
        if valid:
            item = matching[0]
            terminal = item.stage == OperationStage.SETTLED and item.certainty in {
                EffectCertainty.NO_EFFECT,
                EffectCertainty.EFFECT_CONFIRMED,
            }
            if terminal:
                try:
                    terminal_observed_at = _terminal_observation(item)
                except DriverGatewayError:
                    valid = False
        if not valid:
            certainty = "EFFECT_UNKNOWN"
            stage = "RECONCILING"
            disposition = ResultCode.RECONCILIATION_REQUIRED
            error_code = "CONTRACT_MISMATCH"
            error_message = "driver reconciliation result did not satisfy the contract"
            evidence = None
        else:
            item = matching[0]
            terminal = item.stage == OperationStage.SETTLED and item.certainty in {
                EffectCertainty.NO_EFFECT,
                EffectCertainty.EFFECT_CONFIRMED,
            }
            stage = "SETTLED" if terminal else "RECONCILING"
            certainty = item.certainty.value
            disposition = item.result_code
            error_code = item.error.code if item.error else None
            error_message = item.error.message if item.error else None
            evidence = _result_evidence(result)
        return self.repository.append_operation_transition(
            canonical["operation_id"],
            canonical["current_attempt_id"],
            expected_revision=int(canonical["revision"]),
            stage=stage,
            certainty=certainty,
            disposition=disposition,
            safe_error_code=error_code,
            safe_error_message=error_message,
            evidence_digest=evidence,
            actor=GATEWAY_ACTOR,
            correlation_id=query.correlation_id,
            terminal_observed_at=terminal_observed_at,
        )


__all__ = ["DriverGateway", "DriverGatewayError"]
