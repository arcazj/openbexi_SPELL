from __future__ import annotations

import asyncio
from pathlib import Path

import grpc

from spell.driver.v1 import driver_pb2

from driver_host.config import JournalConfig
from driver_host.domain import Certainty, Method, Result
from driver_host.hooks import DeterministicHooks
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost
from driver_host.service import DriverInfrastructureService
from driver_host.tests.support import (
    make_command,
    make_config,
    make_identity,
    protobuf_identity,
)


LIMITS = JournalConfig(max_entries=100, max_bytes=1_048_576)


class RpcAbort(Exception):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        super().__init__(details)
        self.code = code
        self.details = details


class AbortContext:
    async def abort(self, code: grpc.StatusCode, details: str) -> None:
        raise RpcAbort(code, details)


def test_protobuf_preserves_nine_method_infrastructure_and_adds_observation() -> None:
    services = driver_pb2.DESCRIPTOR.services_by_name
    assert tuple(services) == (
        "DriverInfrastructureService",
        "DriverObservationService",
    )
    service = services["DriverInfrastructureService"]
    assert [method.name for method in service.methods] == [
        "Handshake",
        "Health",
        "OpenContext",
        "CloseContext",
        "AttachExecution",
        "DetachExecution",
        "CancelLifecycleOperation",
        "DrainHost",
        "GetOperation",
    ]
    assert all(not method.client_streaming for method in service.methods)
    assert all(not method.server_streaming for method in service.methods)
    observation = services["DriverObservationService"]
    assert [method.name for method in observation.methods] == ["GetTime", "GetTM"]
    assert all(not method.client_streaming for method in observation.methods)
    assert all(not method.server_streaming for method in observation.methods)

    forbidden_untyped_messages = {
        "google.protobuf.Any",
        "google.protobuf.Struct",
        "google.protobuf.Value",
    }
    assert all(
        field.message_type is None
        or field.message_type.full_name not in forbidden_untyped_messages
        for message in driver_pb2.DESCRIPTOR.message_types_by_name.values()
        for field in message.fields
    )


def test_handshake_reports_exact_identity_capabilities_capacity_and_typed_mismatch(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "handshake.sqlite",
                config.driver_host_generation,
                LIMITS,
            ),
        )
        service = DriverInfrastructureService(config, host)
        identity = make_identity(config)
        try:
            request = driver_pb2.HandshakeRequest(
                identity=protobuf_identity(identity, "handshake"),
                requested_version=driver_pb2.ContractVersion(major=1, minor=0),
                expected_logical_driver_id=config.logical_driver_id,
                expected_host_profile_digest=config.host_profile_digest,
            )
            response = await service.Handshake(request, AbortContext())

            assert response.contract_version == driver_pb2.ContractVersion(
                major=1, minor=0
            )
            assert response.error.code == driver_pb2.SAFE_ERROR_CODE_NONE
            assert response.driver.logical_driver_id == config.logical_driver_id
            assert response.driver.driver_host_generation == (
                config.driver_host_generation
            )
            assert response.driver.host_profile_digest == config.host_profile_digest
            assert response.driver.simulator is True
            assert response.host_state == driver_pb2.HOST_STATE_READY
            assert len(response.capabilities) == 9
            assert {item.method for item in response.capabilities} == set(range(1, 10))
            assert all(
                item.formats == [driver_pb2.CAPABILITY_FORMAT_PROTOBUF_BINARY]
                and item.stream_support == driver_pb2.STREAM_SUPPORT_NONE
                for item in response.capabilities
            )
            assert response.capacity_limits.max_contexts_per_host == 1
            assert response.capacity_limits.max_attachments_per_context == 1

            mismatch = driver_pb2.HandshakeRequest()
            mismatch.CopyFrom(request)
            mismatch.requested_version.major = 2
            mismatch_response = await service.Handshake(mismatch, AbortContext())
            assert (
                mismatch_response.error.code
                == driver_pb2.SAFE_ERROR_CODE_VERSION_MISMATCH
            )

            unsupported = driver_pb2.HandshakeRequest()
            unsupported.CopyFrom(request)
            unsupported.required_capabilities.append(
                driver_pb2.CapabilityDescriptor(
                    service=driver_pb2.INFRASTRUCTURE_SERVICE_HOST,
                    method=driver_pb2.RPC_METHOD_OPEN_CONTEXT,
                    modifiers=[driver_pb2.CAPABILITY_MODIFIER_NONE],
                    formats=[driver_pb2.CAPABILITY_FORMAT_PROTOBUF_BINARY],
                    mutability=driver_pb2.MUTABILITY_READ_ONLY,
                    stream_support=driver_pb2.STREAM_SUPPORT_NONE,
                )
            )
            unsupported_response = await service.Handshake(
                unsupported, AbortContext()
            )
            assert (
                unsupported_response.error.code
                == driver_pb2.SAFE_ERROR_CODE_UNSUPPORTED
            )
            assert service.dispatch_counts[Method.HANDSHAKE.value] == 3
        finally:
            host.close()

    asyncio.run(scenario())


def test_wire_mutation_health_reconciliation_duplicate_and_digest_conflict(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = make_config()
        hooks = DeterministicHooks()
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "wire.sqlite", config.driver_host_generation, LIMITS
            ),
            hooks=hooks,
        )
        service = DriverInfrastructureService(config, host)
        context_identity = make_identity(config, context=True)
        wire_identity = protobuf_identity(context_identity, "wire-open")
        request = driver_pb2.OpenContextRequest(
            identity=wire_identity,
            configuration=driver_pb2.ContextBindingConfiguration(
                schema_version="context-schema-1",
                context_profile_id="context-profile-1",
                synthetic_context_label="synthetic-context-1",
                expected_context_binding_digest=context_identity.context_binding_digest,
            ),
        )
        try:
            response = await service.OpenContext(request, AbortContext())
            attempt = response.operation.attempts[-1]
            assert response.contract_version.major == 1
            assert response.operation.method == driver_pb2.RPC_METHOD_OPEN_CONTEXT
            assert attempt.stage == driver_pb2.OPERATION_STAGE_SETTLED
            assert attempt.certainty_present is True
            assert attempt.certainty == driver_pb2.EFFECT_CERTAINTY_CONFIRMED
            assert attempt.result_code == driver_pb2.RESULT_CODE_OK
            assert [trace.sequence for trace in attempt.hook_traces] == [1, 2, 3]
            assert all(
                trace.operation_id == wire_identity.operation_id
                and trace.attempt_id == wire_identity.attempt_id
                and trace.identity.context_binding_digest
                == context_identity.context_binding_digest
                for trace in attempt.hook_traces
            )
            assert sum(hooks.effect_count.values()) == 3

            duplicate = await service.OpenContext(request, AbortContext())
            assert duplicate.operation == response.operation
            assert sum(hooks.effect_count.values()) == 3

            conflict_request = driver_pb2.OpenContextRequest()
            conflict_request.CopyFrom(request)
            conflict_request.configuration.synthetic_context_label = "conflicting-label"
            conflict = await service.OpenContext(conflict_request, AbortContext())
            assert (
                conflict.operation.attempts[-1].result_code
                == driver_pb2.RESULT_CODE_CONFLICT
            )
            assert (
                conflict.operation.attempts[-1].certainty
                == driver_pb2.EFFECT_CERTAINTY_NO_EFFECT
            )
            assert sum(hooks.effect_count.values()) == 3

            health = await service.Health(
                driver_pb2.HealthRequest(
                    identity=protobuf_identity(make_identity(config), "health")
                ),
                AbortContext(),
            )
            assert health.ready is True
            assert health.host_state == driver_pb2.HOST_STATE_READY
            assert health.capacity_use.contexts == 1
            assert len(health.contexts) == 1
            assert health.contexts[0].state == driver_pb2.CONTEXT_STATE_ACTIVE

            reconciled = await service.GetOperation(
                driver_pb2.GetOperationRequest(
                    identity=protobuf_identity(context_identity, "get-wire"),
                    target_operation_id=wire_identity.operation_id,
                    target_attempt_id=wire_identity.attempt_id,
                ),
                AbortContext(),
            )
            assert not reconciled.HasField("error")
            assert reconciled.operation == response.operation

            missing = await service.GetOperation(
                driver_pb2.GetOperationRequest(
                    identity=protobuf_identity(make_identity(config), "get-missing"),
                    target_operation_id="operation-missing",
                ),
                AbortContext(),
            )
            assert missing.error.code == driver_pb2.SAFE_ERROR_CODE_VALIDATION
            assert not missing.HasField("operation")
            assert service.dispatch_counts[Method.OPEN_CONTEXT.value] == 3
            assert service.dispatch_counts[Method.HEALTH.value] == 1
            assert service.dispatch_counts[Method.GET_OPERATION.value] == 2
        finally:
            host.close()

    asyncio.run(scenario())


def test_stale_wire_identity_is_typed_and_never_dispatched(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = make_config()
        host = SimulatorLifecycleHost(
            config,
            OperationJournal(
                tmp_path / "invalid.sqlite", config.driver_host_generation, LIMITS
            ),
        )
        service = DriverInfrastructureService(config, host)
        identity = protobuf_identity(
            make_identity(config, context=True), "invalid-open"
        )
        identity.host_profile_digest = "0" * 64
        request = driver_pb2.OpenContextRequest(
            identity=identity,
            configuration=driver_pb2.ContextBindingConfiguration(
                schema_version="context-schema-1",
                context_profile_id="context-profile-1",
                synthetic_context_label="synthetic-context-1",
                expected_context_binding_digest=identity.context_binding_digest,
            ),
        )
        try:
            response = await service.OpenContext(request, AbortContext())
            attempt = response.operation.attempts[-1]
            assert attempt.result_code == driver_pb2.RESULT_CODE_STALE_GENERATION
            assert attempt.certainty == driver_pb2.EFFECT_CERTAINTY_NO_EFFECT
            assert attempt.error.code == driver_pb2.SAFE_ERROR_CODE_DIGEST_MISMATCH
            assert service.dispatch_counts[Method.OPEN_CONTEXT.value] == 0
            assert host.journal.list_operations() == ()
        finally:
            host.close()

    asyncio.run(scenario())


def test_new_host_generation_can_get_old_generation_operation_evidence(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        path = tmp_path / "generation-restart.sqlite"
        old_config = make_config(generation="host-generation-old")
        old_identity = make_identity(old_config, context=True)
        old_command = make_command(
            old_config,
            Method.OPEN_CONTEXT,
            "old-operation",
            identity=old_identity,
        )
        old_journal = OperationJournal(
            path, old_config.driver_host_generation, LIMITS
        )
        old_journal.accept(old_command)
        old_journal.settle(
            old_command.attempt_id, Certainty.NO_EFFECT, Result.CANCELLED
        )
        old_journal.close()

        new_config = make_config(generation="host-generation-new")
        host = SimulatorLifecycleHost(
            new_config,
            OperationJournal(path, new_config.driver_host_generation, LIMITS),
        )
        service = DriverInfrastructureService(new_config, host)
        try:
            assert host.snapshot().state.value == "READY"
            response = await service.GetOperation(
                driver_pb2.GetOperationRequest(
                    identity=protobuf_identity(
                        old_identity,
                        "old-reconciliation",
                        credential_epoch=new_config.credential_epoch,
                    ),
                    target_operation_id=old_command.operation_id,
                    target_attempt_id=old_command.attempt_id,
                ),
                AbortContext(),
            )
            assert not response.HasField("error")
            assert response.operation.operation_id == old_command.operation_id
            assert response.operation.attempts[0].identity.driver_host_generation == (
                old_config.driver_host_generation
            )
            assert (
                response.operation.attempts[0].result_code
                == driver_pb2.RESULT_CODE_CANCELLED
            )
        finally:
            host.close()

    asyncio.run(scenario())
