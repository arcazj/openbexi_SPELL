from __future__ import annotations

import asyncio
import inspect
from collections import deque
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from backend.config import Settings
from backend.database import create_database
from backend.driver_client import DriverTransportError, _operation
from backend.driver_domain import (
    CAPABILITY_MATRIX,
    DEFAULT_DRIVER_PROFILE_ID,
    DEFAULT_HOST_PROFILE_DIGEST,
    DEFAULT_HOST_SCHEMA,
    DEFAULT_LOGICAL_DRIVER_ID,
    DEFAULT_SERVER_PROFILE_ID,
    AttachExecutionCommand,
    AttachmentConfiguration,
    Capacity,
    Capability,
    CloseContextCommand,
    ContractVersion,
    ContextConfiguration,
    ContextHealth,
    DetachExecutionCommand,
    DrainHostCommand,
    DriverIdentity,
    DriverRpcMethod,
    EffectCertainty,
    EffectClass,
    GenerationTuple,
    HandshakeResult,
    HealthResult,
    AttachmentHealth,
    OperationAttemptResult,
    OperationIdentity,
    OperationResult,
    OperationStage,
    ResultCode,
)
from backend.driver_gateway import DriverGateway, DriverGatewayError
from backend.driver_models import (
    DriverAuditEvent,
    DriverHostGeneration,
    DriverOutboxEvent,
)
from backend.driver_repository import (
    DriverConflictError,
    DriverNotFoundError,
    DriverRepository,
)
from backend.tests.migration_support import run_migrations


def uid(value: int) -> str:
    return str(UUID(int=value))


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def settings(tmp_path: Path, *, enabled: bool, poll_seconds: float = 60.0) -> Settings:
    return Settings(
        database_url=f"sqlite:///{(tmp_path / 'gateway.db').as_posix()}",
        procedures_dir=tmp_path,
        websocket_replay_limit=100,
        websocket_queue_size=10,
        websocket_keepalive_seconds=5.0,
        driver_enabled=enabled,
        driver_rpc_timeout_seconds=2.0,
        driver_poll_seconds=poll_seconds,
        driver_stale_after_seconds=max(1.0, poll_seconds * 2.0),
    )


def exact_capabilities() -> tuple[Capability, ...]:
    return tuple(
        Capability(
            service=item.service,
            method=item.method,
            modifiers=item.modifiers,
            formats=(item.format,),
            mutability=item.mutability,
            stream_support=item.stream_support,
        )
        for item in CAPABILITY_MATRIX
    )


def driver_identity(host_generation: str = uid(1)) -> DriverIdentity:
    return DriverIdentity(
        logical_driver_id=DEFAULT_LOGICAL_DRIVER_ID,
        implementation_version="0.4.0",
        simulator=True,
        server_profile_id=DEFAULT_SERVER_PROFILE_ID,
        driver_profile_id=DEFAULT_DRIVER_PROFILE_ID,
        driver_host_generation=host_generation,
        host_configuration_schema=DEFAULT_HOST_SCHEMA,
        host_profile_digest=DEFAULT_HOST_PROFILE_DIGEST,
        credential_epoch=1,
    )


def handshake(
    *,
    driver: DriverIdentity | None = None,
    state: str = "READY",
    observed_ms: int | None = None,
) -> HandshakeResult:
    return HandshakeResult(
        contract_version=ContractVersion(),
        driver=driver or driver_identity(),
        host_state=state,
        capabilities=exact_capabilities(),
        capacity=Capacity(1, 1, 8, 8),
        last_observed_unix_ms=observed_ms or now_ms(),
    )


def health(
    accepted: HandshakeResult,
    *,
    state: str = "READY",
    driver: DriverIdentity | None = None,
    observed_ms: int | None = None,
) -> HealthResult:
    return HealthResult(
        contract_version=accepted.contract_version,
        driver=driver or accepted.driver,
        host_state=state,
        ready=state == "READY",
        capacity=Capacity(1, 1, 8, 8),
        contexts=(),
        attachments=(),
        last_observed_unix_ms=observed_ms or now_ms(),
    )


def health_children(
    repository: DriverRepository, accepted: HandshakeResult
) -> tuple[ContextHealth, AttachmentHealth]:
    context_id = "health-context"
    context_generation = uid(900)
    context_digest = "a" * 64
    context = repository.create_context_generation(
        profile_id=DEFAULT_DRIVER_PROFILE_ID,
        host_generation_id=accepted.driver.driver_host_generation,
        context_id=context_id,
        context_generation_id=context_generation,
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest=context_digest,
        actor="pytest-supervisor",
        correlation_id=uid(901),
    )
    repository.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest-supervisor",
        correlation_id=uid(902),
        observed_at=datetime.now(timezone.utc),
    )
    binding_id = uid(903)
    attachment_generation = uid(904)
    attachment_digest = "b" * 64
    binding = repository.create_binding(
        context_generation_id=context_generation,
        driver_binding_id=binding_id,
        execution_id="health-execution",
        attachment_generation_id=attachment_generation,
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest=attachment_digest,
        actor="pytest-supervisor",
        correlation_id=uid(905),
    )
    repository.record_binding_state(
        binding.id,
        "ATTACHED",
        expected_revision=0,
        actor="pytest-supervisor",
        correlation_id=uid(906),
        observed_at=datetime.now(timezone.utc),
    )
    observed = now_ms()
    return (
        ContextHealth(
            context_id=context_id,
            context_generation=context_generation,
            context_binding_digest=context_digest,
            state="ACTIVE",
            ready=True,
            last_observed_unix_ms=observed,
        ),
        AttachmentHealth(
            execution_id="health-execution",
            execution_attachment_generation=attachment_generation,
            execution_attachment_digest=attachment_digest,
            driver_binding_id=binding_id,
            state="ATTACHED",
            last_observed_unix_ms=observed,
        ),
    )


def drain_command(
    accepted: HandshakeResult,
    *,
    operation_number: int,
    deadline: datetime | None = None,
) -> DrainHostCommand:
    return DrainHostCommand(
        identity=OperationIdentity(
            generations=GenerationTuple(
                server_profile_id=DEFAULT_SERVER_PROFILE_ID,
                driver_host_generation=accepted.driver.driver_host_generation,
                host_profile_digest=DEFAULT_HOST_PROFILE_DIGEST,
            ),
            operation_id=uid(operation_number),
            attempt_id=uid(operation_number + 1),
            attempt_number=1,
            correlation_id=uid(operation_number + 2),
            deadline_unix_ms=int(
                (deadline or datetime.now(timezone.utc) + timedelta(seconds=10)).timestamp()
                * 1000
            ),
            credential_epoch=accepted.driver.credential_epoch,
        ),
        grace_period_ms=0,
    )


def persist_dispatched(
    repository: DriverRepository, command: DrainHostCommand
) -> dict[str, Any]:
    identity = command.identity
    accepted = repository.accept_operation(
        operation_id=identity.operation_id,
        attempt_id=identity.attempt_id,
        method=DriverRpcMethod.DRAIN_HOST,
        request_digest=command.request_digest,
        effect_class=EffectClass.HOST_DRAIN,
        host_generation_id=identity.generations.driver_host_generation,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest-supervisor",
        correlation_id=identity.correlation_id,
        deadline_at=datetime.fromtimestamp(
            identity.deadline_unix_ms / 1000, tz=timezone.utc
        ),
    )
    return repository.append_operation_transition(
        identity.operation_id,
        identity.attempt_id,
        expected_revision=int(accepted["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest=None,
        actor="pytest-supervisor",
        correlation_id=identity.correlation_id,
    )


def operation_result(
    command: DrainHostCommand,
    *,
    operation_id: str | None = None,
    request_digest: str | None = None,
    effect_class: EffectClass = EffectClass.HOST_DRAIN,
    stage: OperationStage = OperationStage.SETTLED,
    certainty: EffectCertainty = EffectCertainty.EFFECT_CONFIRMED,
    result_code: ResultCode = ResultCode.OK,
) -> OperationResult:
    timestamp = now_ms()
    attempt = OperationAttemptResult(
        attempt_id=command.identity.attempt_id,
        attempt_number=command.identity.attempt_number,
        request_digest=request_digest or command.request_digest,
        stage=stage,
        effect_class=effect_class,
        certainty=certainty,
        result_code=result_code,
        error=None,
        requested_unix_ms=timestamp,
        accepted_unix_ms=timestamp,
        dispatched_unix_ms=timestamp,
        settled_unix_ms=timestamp if stage == OperationStage.SETTLED else 0,
        generations=command.identity.generations,
    )
    return OperationResult(
        operation_id=operation_id or command.identity.operation_id,
        method=DriverRpcMethod.DRAIN_HOST,
        current_attempt_id=command.identity.attempt_id,
        attempts=(attempt,),
    )


class FakeClient:
    def __init__(self, handshake_outcome: Any) -> None:
        self.handshake_outcome = handshake_outcome
        self.health_outcomes: deque[Any] = deque()
        self.drain_outcome: Any = None
        self.get_operation_outcome: Any = None
        self.calls: list[tuple[str, Any]] = []
        self.closed = 0
        self.last_handshake: HandshakeResult | None = None

    async def _resolve(self, outcome: Any, *args: Any) -> Any:
        if isinstance(outcome, BaseException):
            raise outcome
        if callable(outcome):
            outcome = outcome(*args)
        if inspect.isawaitable(outcome):
            outcome = await outcome
        return outcome

    async def handshake(self) -> HandshakeResult:
        self.calls.append(("handshake", None))
        result = await self._resolve(self.handshake_outcome)
        self.last_handshake = result
        return result

    async def health(self) -> HealthResult:
        self.calls.append(("health", None))
        if not self.health_outcomes:
            if self.last_handshake is None:
                raise AssertionError("Health called before an accepted handshake")
            return health(self.last_handshake)
        return await self._resolve(self.health_outcomes.popleft())

    async def drain_host(self, command: DrainHostCommand) -> OperationResult:
        self.calls.append(("drain_host", command))
        return await self._resolve(self.drain_outcome, command)

    async def get_operation(self, query: Any) -> OperationResult:
        self.calls.append(("get_operation", query))
        return await self._resolve(self.get_operation_outcome, query)

    async def close(self) -> None:
        self.closed += 1


class RecordingFactory:
    def __init__(self, client: FakeClient) -> None:
        self.client = client
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> FakeClient:
        self.calls.append((args, kwargs))
        return self.client


class StorageOutageRepository:
    def __init__(self, repository: DriverRepository) -> None:
        self.repository = repository
        self.unavailable = False
        self.failed_read_count = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.repository, name)

    def get_driver(self, profile_id: str) -> dict[str, Any]:
        if self.unavailable:
            self.failed_read_count += 1
            raise OperationalError(
                "SELECT driver projection",
                {},
                RuntimeError("controlled storage outage"),
            )
        return self.repository.get_driver(profile_id)


@pytest.fixture
def repository(tmp_path: Path):
    engine, session_factory = create_database(
        f"sqlite:///{(tmp_path / 'gateway-repository.db').as_posix()}"
    )
    run_migrations(engine)
    try:
        yield DriverRepository(session_factory)
    finally:
        engine.dispose()


async def cancel_poll(gateway: DriverGateway) -> None:
    if gateway._poll_task is None:
        return
    gateway._poll_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await gateway._poll_task
    gateway._poll_task = None


def test_disabled_start_never_accesses_the_client_credentials(
    repository: DriverRepository, tmp_path: Path
) -> None:
    def scenario() -> None:
        def fail_factory(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("disabled startup accessed driver credentials")

        async def run() -> None:
            gateway = DriverGateway(
                repository,
                settings(tmp_path, enabled=False),
                client_factory=fail_factory,
            )
            await gateway.start()
            assert gateway.connected is False
            assert gateway._poll_task is None
            assert repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"][
                "enabled"
            ] is False
            await gateway.close()

        asyncio.run(run())

    scenario()


def test_start_uses_exact_factory_arguments_and_persists_the_exact_handshake(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake(observed_ms=now_ms() - 100)
        client = FakeClient(accepted)
        factory = RecordingFactory(client)
        configured = settings(tmp_path, enabled=True)
        gateway = DriverGateway(repository, configured, client_factory=factory)
        await gateway.start()
        try:
            assert factory.calls == [
                (
                    (
                        configured.driver_target,
                        configured.driver_ca_path,
                        configured.driver_client_cert_path,
                        configured.driver_client_key_path,
                        configured.driver_rpc_timeout_seconds,
                    ),
                    {
                        "credential_epoch": 1,
                        "host_profile_digest": DEFAULT_HOST_PROFILE_DIGEST,
                    },
                )
            ]
            assert gateway.connected is True
            assert gateway.host_generation_id == accepted.driver.driver_host_generation
            persisted = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
            assert persisted["enabled"] is True
            assert persisted["current_host_generation_id"] == gateway.host_generation_id
            assert persisted["state"] == "READY"
            assert persisted["contract_version"] == "1.0"
            assert persisted["implementation_version"] == "0.4.0"
            assert {item["method"] for item in persisted["capabilities"]} == {
                item.method.value for item in CAPABILITY_MATRIX
            }
        finally:
            await gateway.close()
        assert client.closed == 1

    asyncio.run(run())


def test_rotated_epoch_and_persisted_profile_digest_drive_the_next_handshake(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        rotated = repository.rotate_profile_credentials(
            DEFAULT_DRIVER_PROFILE_ID,
            credential_reference="local-v04-driver-mtls",
            credential_epoch=2,
            configuration_digest=DEFAULT_HOST_PROFILE_DIGEST,
            expected_revision=0,
            actor="pytest-service-manager",
            correlation_id=uid(347),
        )
        accepted = handshake(
            driver=replace(driver_identity(), credential_epoch=2)
        )
        client = FakeClient(accepted)
        factory = RecordingFactory(client)
        configured = settings(tmp_path, enabled=True)
        gateway = DriverGateway(repository, configured, client_factory=factory)
        await gateway.start()
        try:
            assert rotated["credential_epoch"] == 2
            assert factory.calls == [
                (
                    (
                        configured.driver_target,
                        configured.driver_ca_path,
                        configured.driver_client_cert_path,
                        configured.driver_client_key_path,
                        configured.driver_rpc_timeout_seconds,
                    ),
                    {
                        "credential_epoch": 2,
                        "host_profile_digest": DEFAULT_HOST_PROFILE_DIGEST,
                    },
                )
            ]
            assert gateway.connected is True
            persisted = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
            assert persisted["credential_epoch"] == 2
        finally:
            await gateway.close()

    asyncio.run(run())


def test_handshake_mismatch_fails_closed_and_closes_the_client(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        mismatched = handshake(
            driver=replace(driver_identity(), logical_driver_id="unexpected-driver")
        )
        client = FakeClient(mismatched)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        with pytest.raises(DriverGatewayError, match="identity differs"):
            await gateway.start()
        assert client.closed == 1
        assert gateway._client is None
        assert gateway._poll_task is None
        persisted = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        assert persisted["enabled"] is True
        assert persisted["current_host_generation_id"] is None
        assert persisted["ready"] is False

    asyncio.run(run())


def test_transport_unavailable_degrades_startup_without_fabricating_a_generation(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        client = FakeClient(DriverTransportError("UNAVAILABLE"))
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        try:
            persisted = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
            assert persisted["enabled"] is True
            assert persisted["ready"] is False
            assert persisted["current_host_generation_id"] is None
            assert gateway.connected is False
            assert gateway._poll_task is not None
        finally:
            await gateway.close()
        assert client.closed == 1

    asyncio.run(run())


def test_health_updates_state_then_transport_and_contract_failures_fail_closed(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        configured = settings(tmp_path, enabled=True, poll_seconds=0.001)
        gateway = DriverGateway(
            repository, configured, client_factory=RecordingFactory(client)
        )
        await gateway.start()
        await cancel_poll(gateway)

        observed = now_ms() + 50
        client.health_outcomes.append(
            health(accepted, state="DEGRADED", observed_ms=observed)
        )
        await gateway._health_once()
        updated = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        assert updated["state"] == "DEGRADED"
        assert updated["ready"] is False

        mismatched = health(
            accepted,
            state="DEGRADED",
            driver=replace(accepted.driver, credential_epoch=2),
        )
        client.health_outcomes.append(DriverTransportError("UNAVAILABLE"))
        client.handshake_outcome = replace(
            accepted,
            driver=mismatched.driver,
        )
        gateway._closing = False
        gateway._poll_task = asyncio.create_task(gateway._poll_loop())
        await asyncio.wait_for(gateway._poll_task, timeout=1.0)
        gateway._poll_task = None
        failed = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        assert failed["state"] == "FAILED"
        assert failed["ready"] is False
        assert [name for name, _ in client.calls].count("health") == 3
        assert [name for name, _ in client.calls].count("handshake") == 2
        await gateway.close()

    asyncio.run(run())


def test_poll_task_survives_storage_outage_and_resumes_observation_without_restart(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        initial_observation = now_ms() - 1_000
        recovered_observation = now_ms()
        client = FakeClient(accepted)
        client.health_outcomes.append(
            health(accepted, observed_ms=initial_observation)
        )
        client.health_outcomes.extend(
            health(accepted, observed_ms=recovered_observation) for _ in range(256)
        )
        storage = StorageOutageRepository(repository)
        configured = replace(
            settings(tmp_path, enabled=True, poll_seconds=0.005),
            driver_stale_after_seconds=0.03,
        )
        gateway = DriverGateway(
            storage,
            configured,
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        original_task = gateway._poll_task
        assert original_task is not None
        initial = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]

        storage.unavailable = True
        deadline = asyncio.get_running_loop().time() + 1.0
        while (
            storage.failed_read_count == 0
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.001)
        assert storage.failed_read_count >= 1
        await asyncio.sleep(0.05)

        during = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        observed_at = datetime.fromisoformat(during["last_observed_at"])
        assert during["state"] == "READY"
        assert during["last_observed_at"] == initial["last_observed_at"]
        assert (
            datetime.now(timezone.utc) - observed_at
        ).total_seconds() > configured.driver_stale_after_seconds
        assert gateway._poll_task is original_task
        assert not original_task.done()
        assert storage.failed_read_count <= 6
        assert gateway._storage_retry_delay(100) == configured.driver_stale_after_seconds

        storage.unavailable = False
        deadline = asyncio.get_running_loop().time() + 1.0
        recovered = during
        while (
            recovered["last_observed_at"] == initial["last_observed_at"]
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.005)
            recovered = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]

        try:
            assert recovered["state"] == "READY"
            assert recovered["last_observed_at"] != initial["last_observed_at"]
            assert gateway._poll_task is original_task
            assert not original_task.done()
        finally:
            await gateway.close()

    asyncio.run(run())


def test_future_health_observation_is_rejected_without_refreshing_canonical_state(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        before = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        client.health_outcomes.append(
            health(accepted, observed_ms=now_ms() + 60_000)
        )

        try:
            with pytest.raises(DriverGatewayError, match="timestamp is in the future"):
                await gateway._health_once()
            after = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
            assert after == before
        finally:
            await gateway.close()

    asyncio.run(run())


@pytest.mark.parametrize("rejection", ["future", "malformed-context-id"])
def test_poll_rejected_health_preserves_canonical_state_and_rehandshakes_after_bound(
    repository: DriverRepository, tmp_path: Path, rejection: str
) -> None:
    async def run() -> None:
        accepted = handshake(observed_ms=now_ms() - 1_000)
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True, poll_seconds=0.02),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        before = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]

        if rejection == "future":
            rejected = health(accepted, observed_ms=now_ms() + 60_000)
        else:
            malformed_context = ContextHealth(
                context_id="health-context",
                context_generation="not a bounded id",
                context_binding_digest="a" * 64,
                state="ACTIVE",
                ready=True,
                last_observed_unix_ms=now_ms(),
            )
            rejected = HealthResult(
                contract_version=accepted.contract_version,
                driver=accepted.driver,
                host_state="READY",
                ready=True,
                capacity=Capacity(1, 1, 8, 8, contexts=1),
                contexts=(malformed_context,),
                attachments=(),
                last_observed_unix_ms=now_ms(),
            )
        client.health_outcomes.extend((rejected, rejected, rejected))
        gateway._closing = False
        gateway._poll_task = asyncio.create_task(gateway._poll_loop())

        deadline = asyncio.get_running_loop().time() + 1.0
        while (
            gateway._handshake is not None
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.002)
        assert gateway._handshake is None
        assert gateway._poll_task is not None and not gateway._poll_task.done()
        assert [name for name, _ in client.calls].count("health") == 4
        await cancel_poll(gateway)
        assert repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"] == before

        recovered_handshake = handshake(
            driver=accepted.driver, observed_ms=now_ms() + 100
        )
        client.handshake_outcome = recovered_handshake
        client.health_outcomes.append(
            health(recovered_handshake, observed_ms=now_ms() + 200)
        )
        gateway._poll_task = asyncio.create_task(gateway._poll_loop())
        deadline = asyncio.get_running_loop().time() + 1.0
        recovered = before
        while (
            recovered["revision"] == before["revision"]
                or [name for name, _ in client.calls].count("health") < 5
        ) and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.002)
            recovered = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        await cancel_poll(gateway)

        assert recovered["state"] == "READY"
        assert recovered["last_observed_at"] != before["last_observed_at"]
        assert [name for name, _ in client.calls].count("handshake") == 2
        await gateway.close()

    asyncio.run(run())


def test_valid_health_resets_the_consecutive_rejection_budget(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True, poll_seconds=0.02),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        rejected = health(accepted, observed_ms=now_ms() + 60_000)
        valid = health(accepted, observed_ms=now_ms() + 100)
        release_sixth = asyncio.Event()

        async def blocking_sixth_rejection() -> HealthResult:
            await release_sixth.wait()
            return rejected

        client.health_outcomes.extend(
            (
                rejected,
                rejected,
                valid,
                rejected,
                rejected,
                blocking_sixth_rejection,
            )
        )
        gateway._closing = False
        gateway._poll_task = asyncio.create_task(gateway._poll_loop())

        deadline = asyncio.get_running_loop().time() + 1.0
        while (
            [name for name, _ in client.calls].count("health") < 7
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.002)
        assert gateway._handshake is accepted
        assert gateway._poll_task is not None and not gateway._poll_task.done()

        release_sixth.set()
        deadline = asyncio.get_running_loop().time() + 1.0
        while (
            gateway._handshake is not None
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.002)
        assert gateway._handshake is None
        assert [name for name, _ in client.calls].count("health") == 7
        await cancel_poll(gateway)
        await gateway.close()

    asyncio.run(run())


def test_revalidation_handshake_does_not_admit_mutation_dispatch(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        gateway._revalidating_generation = accepted.driver.driver_host_generation
        gateway._handshake = None

        await gateway._handshake_once(
            expected_generation=accepted.driver.driver_host_generation,
            persist_observation=False,
        )
        command = drain_command(accepted, operation_number=825)
        try:
            assert gateway._handshake is accepted
            assert gateway.connected is False
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.execute_lifecycle(command, actor="pytest-supervisor")
            with pytest.raises(DriverNotFoundError):
                repository.get_operation(command.identity.operation_id)
            assert "drain_host" not in [name for name, _ in client.calls]
        finally:
            await gateway.close()

    asyncio.run(run())


def test_handshake_without_health_denies_mutation_and_pending_reconciliation(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        repository.configure_profile_enabled(
            DEFAULT_DRIVER_PROFILE_ID,
            True,
            actor="pytest-supervisor",
            correlation_id=uid(820),
        )
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        gateway._client = client
        await gateway._handshake_once()
        pending_command = drain_command(accepted, operation_number=821)
        persist_dispatched(repository, pending_command)
        blocked_command = drain_command(accepted, operation_number=824)

        try:
            assert gateway.connected is False
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.execute_lifecycle(
                    blocked_command, actor="pytest-supervisor"
                )
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.reconcile_operation(
                    pending_command.identity.operation_id
                )
            with pytest.raises(DriverNotFoundError):
                repository.get_operation(blocked_command.identity.operation_id)
            assert [name for name, _ in client.calls] == ["handshake"]
        finally:
            await gateway.close()

    asyncio.run(run())


def test_rejected_health_immediately_denies_mutation_and_reconciliation(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake(observed_ms=now_ms() - 100)
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        pending_command = drain_command(accepted, operation_number=830)
        persist_dispatched(repository, pending_command)
        blocked_command = drain_command(accepted, operation_number=833)
        client.health_outcomes.append(
            health(accepted, observed_ms=now_ms() + 60_000)
        )

        try:
            with pytest.raises(DriverGatewayError, match="timestamp is in the future"):
                await gateway._health_once()
            assert gateway._handshake is accepted
            assert gateway.connected is False
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.execute_lifecycle(
                    blocked_command, actor="pytest-supervisor"
                )
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.reconcile_operation(
                    pending_command.identity.operation_id
                )
            assert "drain_host" not in [name for name, _ in client.calls]
            assert "get_operation" not in [name for name, _ in client.calls]

            client.health_outcomes.append(
                health(accepted, observed_ms=now_ms() + 100)
            )
            await gateway._health_once()
            assert gateway.connected is True
            client.get_operation_outcome = operation_result(pending_command)
            settled = await gateway.reconcile_operation(
                pending_command.identity.operation_id
            )
            assert settled["stage"] == "SETTLED"
            assert [name for name, _ in client.calls][-2:] == [
                "health",
                "get_operation",
            ]
        finally:
            await gateway.close()

    asyncio.run(run())


def test_health_persistence_failure_revokes_admission_until_valid_refresh(
    repository: DriverRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run() -> None:
        accepted = handshake(observed_ms=now_ms() - 100)
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        pending_command = drain_command(accepted, operation_number=840)
        persist_dispatched(repository, pending_command)
        blocked_command = drain_command(accepted, operation_number=843)
        original_apply = repository.apply_health_snapshot

        def fail_health_persistence(*_args: Any, **_kwargs: Any) -> None:
            raise OperationalError(
                "UPDATE driver_host_generations",
                {},
                RuntimeError("controlled health persistence failure"),
            )

        monkeypatch.setattr(
            repository, "apply_health_snapshot", fail_health_persistence
        )
        try:
            with pytest.raises(OperationalError):
                await gateway._health_once()
            assert gateway.connected is False
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.execute_lifecycle(
                    blocked_command, actor="pytest-supervisor"
                )
            with pytest.raises(DriverGatewayError, match="not connected"):
                await gateway.reconcile_operation(
                    pending_command.identity.operation_id
                )
            assert "drain_host" not in [name for name, _ in client.calls]
            assert "get_operation" not in [name for name, _ in client.calls]

            monkeypatch.setattr(
                repository, "apply_health_snapshot", original_apply
            )
            client.health_outcomes.append(
                health(accepted, observed_ms=now_ms() + 100)
            )
            await gateway._health_once()
            assert gateway.connected is True
            client.get_operation_outcome = operation_result(pending_command)
            settled = await gateway.reconcile_operation(
                pending_command.identity.operation_id
            )
            assert settled["stage"] == "SETTLED"
        finally:
            await gateway.close()

    asyncio.run(run())


def test_generation_change_waits_for_same_generation_health_before_reconcile(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake(observed_ms=now_ms() - 100)
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True, poll_seconds=0.05),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        pending_command = drain_command(accepted, operation_number=850)
        persist_dispatched(repository, pending_command)
        restarted = replace(
            accepted,
            driver=replace(
                accepted.driver,
                driver_host_generation="health-gated-restarted-generation",
            ),
            last_observed_unix_ms=now_ms() + 100,
        )
        second_health_started = asyncio.Event()
        release_second_health = asyncio.Event()

        async def blocking_same_generation_health() -> HealthResult:
            second_health_started.set()
            await release_second_health.wait()
            return health(restarted, observed_ms=now_ms() + 100)

        client.handshake_outcome = restarted
        client.health_outcomes.extend(
            (
                health(restarted, observed_ms=now_ms() + 100),
                blocking_same_generation_health,
            )
        )
        client.get_operation_outcome = operation_result(pending_command)
        gateway._closing = False
        gateway._poll_task = asyncio.create_task(gateway._poll_loop())

        try:
            await asyncio.wait_for(second_health_started.wait(), timeout=1.0)
            assert gateway.host_generation_id == (
                "health-gated-restarted-generation"
            )
            assert gateway.connected is False
            assert repository.get_operation(pending_command.identity.operation_id)[
                "operation"
            ]["stage"] == "DISPATCHED"
            assert "get_operation" not in [name for name, _ in client.calls]
            assert gateway._poll_task is not None and not gateway._poll_task.done()

            release_second_health.set()
            deadline = asyncio.get_running_loop().time() + 1.0
            while asyncio.get_running_loop().time() < deadline:
                recovered = repository.get_operation(
                    pending_command.identity.operation_id
                )["operation"]
                if recovered["stage"] == "SETTLED":
                    break
                await asyncio.sleep(0.002)
            else:
                raise AssertionError(
                    "same-generation Health did not release reconciliation"
                )
            assert gateway.connected is True
            assert gateway._poll_task is not None and not gateway._poll_task.done()
            assert [name for name, _ in client.calls] == [
                "handshake",
                "health",
                "health",
                "handshake",
                "health",
                "get_operation",
            ]
        finally:
            release_second_health.set()
            await cancel_poll(gateway)
            await gateway.close()

    asyncio.run(run())


def test_later_invalid_health_child_rolls_back_host_and_context_refresh(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        context, attachment = health_children(repository, accepted)
        before = (
            repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"],
            repository.get_context_generation(
                context.context_id, context.context_generation
            )["context_generation"],
            repository.get_binding(attachment.driver_binding_id)["binding"],
        )
        with repository.session_factory() as session:
            audit_before = session.scalar(
                select(func.count()).select_from(DriverAuditEvent)
            )
            outbox_before = session.scalar(
                select(func.count()).select_from(DriverOutboxEvent)
            )
        client.health_outcomes.append(
            HealthResult(
                contract_version=accepted.contract_version,
                driver=accepted.driver,
                host_state="READY",
                ready=True,
                capacity=Capacity(1, 1, 8, 8, contexts=1, attachments=1),
                contexts=(context,),
                attachments=(replace(attachment, state="DETACHED"),),
                last_observed_unix_ms=now_ms() + 100,
            )
        )

        with pytest.raises(DriverConflictError, match="binding state transition"):
            await gateway._health_once()
        after = (
            repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"],
            repository.get_context_generation(
                context.context_id, context.context_generation
            )["context_generation"],
            repository.get_binding(attachment.driver_binding_id)["binding"],
        )
        assert after == before
        with repository.session_factory() as session:
            assert session.scalar(
                select(func.count()).select_from(DriverAuditEvent)
            ) == audit_before
            assert session.scalar(
                select(func.count()).select_from(DriverOutboxEvent)
            ) == outbox_before
        await gateway.close()

    asyncio.run(run())


def test_simultaneous_closed_and_detached_health_commits_atomically(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        context, attachment = health_children(repository, accepted)
        stored_context = repository.get_context_generation(
            context.context_id, context.context_generation
        )["context_generation"]
        repository.record_context_state(
            context.context_generation,
            "CLOSING",
            expected_revision=int(stored_context["revision"]),
            actor="pytest-supervisor",
            correlation_id=uid(907),
            observed_at=datetime.now(timezone.utc),
        )
        stored_binding = repository.get_binding(attachment.driver_binding_id)["binding"]
        repository.record_binding_state(
            attachment.driver_binding_id,
            "DETACHING",
            expected_revision=int(stored_binding["revision"]),
            actor="pytest-supervisor",
            correlation_id=uid(908),
            observed_at=datetime.now(timezone.utc),
        )
        client.health_outcomes.append(
            HealthResult(
                contract_version=accepted.contract_version,
                driver=accepted.driver,
                host_state="READY",
                ready=True,
                capacity=Capacity(1, 1, 8, 8, contexts=1, attachments=1),
                contexts=(replace(context, state="CLOSED", ready=False),),
                attachments=(replace(attachment, state="DETACHED"),),
                last_observed_unix_ms=now_ms() + 100,
            )
        )

        await gateway._health_once()

        driver = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        closed = repository.get_context_generation(
            context.context_id, context.context_generation
        )["context_generation"]
        detached = repository.get_binding(attachment.driver_binding_id)["binding"]
        assert driver["capacity"]["contexts_in_use"] == 0
        assert closed["state"] == "CLOSED"
        assert closed["capacity"]["attachments_in_use"] == 0
        assert detached["state"] == "DETACHED"
        with repository.session_factory() as session:
            events = session.scalars(
                select(DriverAuditEvent).where(
                    DriverAuditEvent.correlation_id == "driver-gateway-lifecycle",
                    DriverAuditEvent.event_type.in_(
                        (
                            "driver.host_state_changed",
                            "driver.context_state_changed",
                            "driver.binding_state_changed",
                        )
                    ),
                )
            ).all()
        revisions: dict[str, list[int]] = {}
        for item in events:
            revisions.setdefault(item.event_type, []).append(
                int(item.payload["revision"])
            )
        assert max(revisions["driver.host_state_changed"]) == driver["revision"]
        assert max(revisions["driver.context_state_changed"]) == closed["revision"]
        assert max(revisions["driver.binding_state_changed"]) == detached["revision"]
        await gateway.close()

    asyncio.run(run())


@pytest.mark.parametrize("future_child", ["context", "attachment"])
def test_future_nested_health_is_rejected_before_any_canonical_refresh(
    repository: DriverRepository, tmp_path: Path, future_child: str
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        context, attachment = health_children(repository, accepted)
        before = (
            repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"],
            repository.get_context_generation(
                context.context_id, context.context_generation
            )["context_generation"],
            repository.get_binding(attachment.driver_binding_id)["binding"],
        )
        future = now_ms() + 60_000
        if future_child == "context":
            context = replace(context, last_observed_unix_ms=future)
        else:
            attachment = replace(attachment, last_observed_unix_ms=future)
        client.health_outcomes.append(
            HealthResult(
                contract_version=accepted.contract_version,
                driver=accepted.driver,
                host_state="READY",
                ready=True,
                capacity=Capacity(1, 1, 8, 8, contexts=1, attachments=1),
                contexts=(context,),
                attachments=(attachment,),
                last_observed_unix_ms=now_ms() + 100,
            )
        )

        try:
            with pytest.raises(DriverGatewayError, match="timestamp is in the future"):
                await gateway._health_once()
            after = (
                repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"],
                repository.get_context_generation(
                    context.context_id, context.context_generation
                )["context_generation"],
                repository.get_binding(attachment.driver_binding_id)["binding"],
            )
            assert after == before
        finally:
            await gateway.close()

    asyncio.run(run())


def test_malformed_attachment_identity_is_rejected_before_host_or_context_refresh(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        context, attachment = health_children(repository, accepted)
        before = (
            repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"],
            repository.get_context_generation(
                context.context_id, context.context_generation
            )["context_generation"],
        )
        client.health_outcomes.append(
            HealthResult(
                contract_version=accepted.contract_version,
                driver=accepted.driver,
                host_state="READY",
                ready=True,
                capacity=Capacity(1, 1, 8, 8, contexts=1, attachments=1),
                contexts=(context,),
                attachments=(
                    replace(attachment, execution_attachment_digest="c" * 64),
                ),
                last_observed_unix_ms=now_ms() + 100,
            )
        )

        try:
            with pytest.raises(DriverGatewayError, match="attachment identity"):
                await gateway._health_once()
            after = (
                repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"],
                repository.get_context_generation(
                    context.context_id, context.context_generation
                )["context_generation"],
            )
            assert after == before
        finally:
            await gateway.close()

    asyncio.run(run())


def test_future_rehandshake_is_rejected_before_fencing_canonical_generation(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        before = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        future = replace(
            accepted,
            driver=replace(
                accepted.driver, driver_host_generation="future-host-generation"
            ),
            last_observed_unix_ms=now_ms() + 60_000,
        )
        client.handshake_outcome = future

        try:
            with pytest.raises(DriverGatewayError, match="timestamp is in the future"):
                await gateway._handshake_once(
                    expected_generation=future.driver.driver_host_generation
                )
            after = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
            assert after == before
        finally:
            await gateway.close()

    asyncio.run(run())


def test_health_generation_change_fences_old_host_and_rehandshakes(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)

        restarted = replace(
            accepted,
            driver=replace(
                accepted.driver,
                driver_host_generation="host-restarted-generation",
            ),
            last_observed_unix_ms=now_ms() + 100,
        )
        client.health_outcomes.append(health(restarted, state="READY"))
        client.handshake_outcome = restarted

        await gateway._health_once()

        current = repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"]
        assert current["current_host_generation_id"] == "host-restarted-generation"
        assert current["host_generation_number"] == 2
        assert current["state"] == "READY"
        assert gateway.host_generation_id == "host-restarted-generation"
        assert [name for name, _ in client.calls][-2:] == ["health", "handshake"]
        await gateway.close()

    asyncio.run(run())


def test_lifecycle_persists_dispatch_before_rpc_and_records_settled_result(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        command = drain_command(accepted, operation_number=100)

        def observe_dispatch(received: DrainHostCommand) -> OperationResult:
            assert received is command
            persisted = repository.get_operation(command.identity.operation_id)[
                "operation"
            ]
            assert persisted["stage"] == "DISPATCHED"
            assert persisted["certainty"] == "EFFECT_POSSIBLE"
            assert [item["stage"] for item in persisted["transitions"]] == [
                "ACCEPTED",
                "DISPATCHED",
            ]
            return operation_result(command)

        client.drain_outcome = observe_dispatch
        settled = await gateway.execute_lifecycle(command, actor="pytest-supervisor")
        assert settled["stage"] == "SETTLED"
        assert settled["certainty"] == "EFFECT_CONFIRMED"
        assert settled["disposition"] == "OK"
        assert settled["transitions"][-1]["evidence_digest"] is not None
        assert [name for name, _ in client.calls].count("drain_host") == 1
        await gateway.close()

    asyncio.run(run())


def test_expired_deadline_settles_no_effect_without_dispatch(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        command = drain_command(
            accepted,
            operation_number=110,
            deadline=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        client.drain_outcome = AssertionError("expired request reached the driver")
        settled = await gateway.execute_lifecycle(command, actor="pytest-supervisor")
        assert settled["stage"] == "SETTLED"
        assert settled["certainty"] == "NO_EFFECT"
        assert settled["disposition"] == "DEADLINE_EXCEEDED"
        assert [item["stage"] for item in settled["transitions"]] == [
            "ACCEPTED",
            "SETTLED",
        ]
        assert "drain_host" not in [name for name, _ in client.calls]
        await gateway.close()

    asyncio.run(run())


def test_context_tuple_mismatch_fails_before_acceptance_or_rpc(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        context_id = "synthetic-context"
        context_generation = uid(200)
        canonical_digest = "a" * 64
        context = repository.create_context_generation(
            profile_id=DEFAULT_DRIVER_PROFILE_ID,
            host_generation_id=accepted.driver.driver_host_generation,
            context_id=context_id,
            context_generation_id=context_generation,
            configuration_schema_version="spell.driver.context-profile/1",
            configuration_digest=canonical_digest,
            actor="pytest-supervisor",
            correlation_id=uid(201),
        )
        repository.record_context_state(
            context.id,
            "ACTIVE",
            expected_revision=0,
            actor="pytest-supervisor",
            correlation_id=uid(202),
            observed_at=datetime.now(timezone.utc),
        )
        command = CloseContextCommand(
            identity=OperationIdentity(
                generations=GenerationTuple(
                    server_profile_id=DEFAULT_SERVER_PROFILE_ID,
                    driver_host_generation=accepted.driver.driver_host_generation,
                    host_profile_digest=DEFAULT_HOST_PROFILE_DIGEST,
                    context_id=context_id,
                    context_generation=context_generation,
                    context_binding_digest="b" * 64,
                ),
                operation_id=uid(203),
                attempt_id=uid(204),
                attempt_number=1,
                correlation_id=uid(205),
                deadline_unix_ms=now_ms() + 10_000,
            )
        )
        with pytest.raises(DriverGatewayError, match="canonical tuple differs"):
            await gateway.execute_lifecycle(command, actor="pytest-supervisor")
        with pytest.raises(DriverNotFoundError):
            repository.get_operation(command.identity.operation_id)
        assert [name for name, _ in client.calls] == ["handshake", "health"]
        await gateway.close()

    asyncio.run(run())


def test_lost_response_latches_reconciliation_and_repeat_never_resends(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        client.drain_outcome = DriverTransportError("UNAVAILABLE")
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        command = drain_command(accepted, operation_number=120)
        first = await gateway.execute_lifecycle(command, actor="pytest-supervisor")
        assert first["stage"] == "RECONCILING"
        assert first["certainty"] == "EFFECT_POSSIBLE"
        assert first["requires_reconciliation"] is True

        repeated = await gateway.execute_lifecycle(command, actor="pytest-supervisor")
        assert repeated == first
        assert [name for name, _ in client.calls].count("drain_host") == 1
        await gateway.close()

    asyncio.run(run())


def test_accepted_operation_cannot_be_dispatched_with_an_extended_deadline(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        command = drain_command(accepted, operation_number=125)
        identity = command.identity
        repository.accept_operation(
            operation_id=identity.operation_id,
            attempt_id=identity.attempt_id,
            method=DriverRpcMethod.DRAIN_HOST,
            request_digest=command.request_digest,
            effect_class=EffectClass.HOST_DRAIN,
            host_generation_id=identity.generations.driver_host_generation,
            context_generation_id=None,
            driver_binding_id=None,
            target_operation_id=None,
            target_attempt_id=None,
            actor="pytest-supervisor",
            correlation_id=identity.correlation_id,
            deadline_at=datetime.fromtimestamp(
                identity.deadline_unix_ms / 1000, tz=timezone.utc
            ),
        )
        altered = DrainHostCommand(
            identity=replace(
                identity, deadline_unix_ms=identity.deadline_unix_ms + 60_000
            ),
            grace_period_ms=command.grace_period_ms,
        )
        with pytest.raises(
            DriverGatewayError, match="operation acceptance identity differs"
        ):
            await gateway.execute_lifecycle(altered, actor="pytest-supervisor")
        persisted = repository.get_operation(identity.operation_id)["operation"]
        assert persisted["stage"] == "ACCEPTED"
        assert [name for name, _ in client.calls] == ["handshake", "health"]
        await gateway.close()

    asyncio.run(run())


def test_mismatched_lifecycle_result_becomes_effect_unknown(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        command = drain_command(accepted, operation_number=130)
        client.drain_outcome = operation_result(
            command, effect_class=EffectClass.CONTEXT_OPEN
        )
        result = await gateway.execute_lifecycle(command, actor="pytest-supervisor")
        assert result["stage"] == "RECONCILING"
        assert result["certainty"] == "EFFECT_UNKNOWN"
        assert result["safe_error"] == {
            "code": "CONTRACT_MISMATCH",
            "message": "driver result did not satisfy the lifecycle contract",
        }
        await gateway.close()

    asyncio.run(run())


def test_reconciliation_uses_only_get_operation_and_settles_same_attempt(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        client.drain_outcome = DriverTransportError("UNAVAILABLE")
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        command = drain_command(accepted, operation_number=140)
        uncertain = await gateway.execute_lifecycle(
            command, actor="pytest-supervisor"
        )
        assert uncertain["stage"] == "RECONCILING"

        def reconcile(query: Any) -> OperationResult:
            assert query.target_operation_id == command.identity.operation_id
            assert query.target_attempt_id == command.identity.attempt_id
            assert query.generations.driver_host_generation == gateway.host_generation_id
            assert query.generations.host_profile_digest == DEFAULT_HOST_PROFILE_DIGEST
            return operation_result(command)

        client.get_operation_outcome = reconcile
        settled = await gateway.reconcile_operation(command.identity.operation_id)
        assert settled["stage"] == "SETTLED"
        assert settled["certainty"] == "EFFECT_CONFIRMED"
        assert [name for name, _ in client.calls] == [
            "handshake",
            "health",
            "drain_host",
            "get_operation",
        ]
        await gateway.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    ("reported_stage", "reported_certainty"),
    (
        (OperationStage.RECONCILING, EffectCertainty.NO_EFFECT),
        (OperationStage.RECONCILING, EffectCertainty.EFFECT_CONFIRMED),
        (OperationStage.SETTLED, EffectCertainty.EFFECT_POSSIBLE),
        (OperationStage.SETTLED, EffectCertainty.EFFECT_UNKNOWN),
    ),
    ids=(
        "nonterminal-no-effect",
        "nonterminal-confirmed",
        "settled-possible",
        "settled-unknown",
    ),
)
def test_reconciliation_normalizes_invalid_driver_stage_certainty_pairs(
    repository: DriverRepository,
    tmp_path: Path,
    reported_stage: OperationStage,
    reported_certainty: EffectCertainty,
) -> None:
    async def run() -> None:
        accepted = handshake()
        client = FakeClient(accepted)
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(client),
        )
        await gateway.start()
        await cancel_poll(gateway)
        with repository.session_factory() as session:
            host = session.get(
                DriverHostGeneration,
                accepted.driver.driver_host_generation,
            )
            assert host is not None
            host.max_lifecycle_operations = 1
            session.commit()
        command = drain_command(accepted, operation_number=145)
        persist_dispatched(repository, command)
        client.get_operation_outcome = operation_result(
            command,
            stage=reported_stage,
            certainty=reported_certainty,
        )

        try:
            normalized = await gateway.reconcile_operation(
                command.identity.operation_id
            )
            assert normalized["stage"] == "RECONCILING"
            assert normalized["certainty"] == "EFFECT_UNKNOWN"
            assert normalized["disposition"] == "RECONCILIATION_REQUIRED"
            assert normalized["requires_reconciliation"] is True
            assert normalized["capacity_reserved"] is False
            assert normalized["safe_error"] == {
                "code": "CONTRACT_MISMATCH",
                "message": (
                    "driver reconciliation result did not satisfy the contract"
                ),
            }
            assert repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"][
                "capacity"
            ]["lifecycle_operations_per_host_in_use"] == 0

            containment = drain_command(accepted, operation_number=148)
            client.drain_outcome = operation_result(containment)
            settled = await gateway.execute_lifecycle(
                containment, actor="pytest-supervisor"
            )
            assert settled["stage"] == "SETTLED"
            assert repository.get_driver(DEFAULT_DRIVER_PROFILE_ID)["driver"][
                "capacity"
            ]["lifecycle_operations_per_host_in_use"] == 0
        finally:
            await gateway.close()

    asyncio.run(run())


def test_startup_reconciles_all_unresolved_operations_without_resending_mutations(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        original_client = FakeClient(accepted)
        original_gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(original_client),
        )
        await original_gateway.start()
        await cancel_poll(original_gateway)
        dispatched_command = drain_command(accepted, operation_number=150)
        dispatched = persist_dispatched(repository, dispatched_command)
        assert dispatched["stage"] == "DISPATCHED"
        reconciling_command = drain_command(accepted, operation_number=153)
        reconciling = persist_dispatched(repository, reconciling_command)
        reconciling = repository.append_operation_transition(
            reconciling_command.identity.operation_id,
            reconciling_command.identity.attempt_id,
            expected_revision=int(reconciling["revision"]),
            stage="RECONCILING",
            certainty="EFFECT_POSSIBLE",
            disposition=ResultCode.RECONCILIATION_REQUIRED,
            safe_error_code="TRANSPORT",
            safe_error_message="driver response unavailable (UNAVAILABLE)",
            evidence_digest=None,
            actor="pytest-supervisor",
            correlation_id=reconciling_command.identity.correlation_id,
        )
        assert reconciling["stage"] == "RECONCILING"
        await original_gateway.close()

        recovery_client = FakeClient(accepted)
        commands = {
            command.identity.operation_id: command
            for command in (dispatched_command, reconciling_command)
        }
        recovery_client.get_operation_outcome = lambda query: operation_result(
            commands[query.target_operation_id]
        )
        recovery_gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(recovery_client),
        )
        await recovery_gateway.start()
        try:
            for command in commands.values():
                recovered = repository.get_operation(command.identity.operation_id)[
                    "operation"
                ]
                assert recovered["stage"] == "SETTLED"
                assert recovered["certainty"] == "EFFECT_CONFIRMED"
            assert [name for name, _ in recovery_client.calls] == [
                "handshake",
                "health",
                "get_operation",
                "get_operation",
            ]
            assert "drain_host" not in [name for name, _ in original_client.calls]
        finally:
            await recovery_gateway.close()

    asyncio.run(run())


def test_transport_recovery_handshake_automatically_reconciles_pending_operation(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        accepted = handshake()
        seed_client = FakeClient(accepted)
        seed_gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            client_factory=RecordingFactory(seed_client),
        )
        await seed_gateway.start()
        await cancel_poll(seed_gateway)
        command = drain_command(accepted, operation_number=160)
        persist_dispatched(repository, command)
        await seed_gateway.close()

        recovery_client = FakeClient(DriverTransportError("UNAVAILABLE"))
        recovery_gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True, poll_seconds=0.001),
            client_factory=RecordingFactory(recovery_client),
        )
        await recovery_gateway.start()
        assert recovery_gateway.connected is False
        recovery_client.handshake_outcome = accepted
        recovery_client.get_operation_outcome = operation_result(command)
        deadline = asyncio.get_running_loop().time() + 1.0
        while asyncio.get_running_loop().time() < deadline:
            recovered = repository.get_operation(command.identity.operation_id)[
                "operation"
            ]
            if recovered["stage"] == "SETTLED":
                break
            await asyncio.sleep(0.001)
        else:
            raise AssertionError("transport recovery did not reconcile pending work")
        try:
            assert [name for name, _ in recovery_client.calls][:4] == [
                "handshake",
                "handshake",
                "health",
                "get_operation",
            ]
            assert "drain_host" not in [name for name, _ in recovery_client.calls]
        finally:
            await recovery_gateway.close()

    asyncio.run(run())


def test_outbox_relay_retries_stable_committed_sequence_and_closes_task(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        repository.configure_profile_enabled(
            DEFAULT_DRIVER_PROFILE_ID,
            True,
            actor="pytest-seed",
            correlation_id=uid(170),
        )
        initial = repository.pending_outbox()
        assert len(initial) == 1
        deliveries: list[tuple[str, dict[str, Any]]] = []
        fail_first = True

        async def publish(topic: str, event: dict[str, Any]) -> None:
            nonlocal fail_first
            deliveries.append((topic, event))
            if fail_first:
                fail_first = False
                raise RuntimeError("simulated downstream outage")

        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=False, poll_seconds=0.001),
            outbox_publisher=publish,
        )
        await gateway.start()
        deadline = asyncio.get_running_loop().time() + 1.0
        while repository.pending_outbox() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.001)
        try:
            assert repository.pending_outbox() == []
            assert [item[0] for item in deliveries] == [
                "driver.lifecycle",
                "driver.lifecycle",
                "driver.lifecycle",
            ]
            sequences = [item[1]["sequence"] for item in deliveries]
            assert sequences[:2] == [initial[0]["sequence"], initial[0]["sequence"]]
            assert sequences[2] > sequences[1]
            assert deliveries[0][1]["event_id"] == initial[0]["event_id"]
            assert deliveries[0][1]["created_at"] == initial[0]["created_at"]
            assert gateway._outbox_task is not None
        finally:
            await gateway.close()
        assert gateway._outbox_task is None
        assert gateway._poll_task is None

    asyncio.run(run())


def test_outbox_relay_accepts_synchronous_publisher(
    repository: DriverRepository, tmp_path: Path
) -> None:
    async def run() -> None:
        repository.configure_profile_enabled(
            DEFAULT_DRIVER_PROFILE_ID,
            True,
            actor="pytest-seed",
            correlation_id=uid(180),
        )
        deliveries: list[tuple[str, dict[str, Any]]] = []
        gateway = DriverGateway(
            repository,
            settings(tmp_path, enabled=True),
            outbox_publisher=lambda topic, event: deliveries.append((topic, event)),
        )
        assert await gateway._publish_outbox_once() == 1
        assert len(deliveries) == 1
        assert deliveries[0][0] == "driver.lifecycle"
        assert repository.pending_outbox() == []

    asyncio.run(run())
