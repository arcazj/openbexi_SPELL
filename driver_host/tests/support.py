from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from spell.driver.v1 import driver_pb2
from spell.driver.configuration import (
    context_binding_digest,
    execution_attachment_digest,
)

from driver_host.config import HookConfig, HostConfig, host_profile_digest
from driver_host.domain import GenerationIdentity, Method, OperationCommand


FUTURE_DEADLINE_MS = 4_102_444_800_000
CONTEXT_SCHEMA_VERSION = "context-schema-1"
CONTEXT_PROFILE_ID = "context-profile-1"
SYNTHETIC_CONTEXT_LABEL = "synthetic-context-1"
ATTACHMENT_SCHEMA_VERSION = "attachment-schema-1"
ATTACHMENT_PROFILE_ID = "attachment-profile-1"
SYNTHETIC_EXECUTION_LABEL = "synthetic-execution-1"


def make_config(
    *,
    generation: str = "host-generation-1",
    hooks: HookConfig | None = None,
    **changes: Any,
) -> HostConfig:
    base = HostConfig()
    values: dict[str, Any] = {
        **vars(base),
        "driver_host_generation": generation,
        "hooks": hooks
        or HookConfig(
            context_hooks=("context-fixture-a", "context-fixture-b"),
            attachment_hooks=("attachment-fixture-a", "attachment-fixture-b"),
        ),
    }
    values.update(changes)
    values["host_profile_digest"] = host_profile_digest(SimpleNamespace(**values))
    return HostConfig(**values)


def make_identity(
    config: HostConfig,
    *,
    context: bool = False,
    attachment: bool = False,
    generation: str | None = None,
    **changes: str,
) -> GenerationIdentity:
    context = context or attachment
    explicit_context_digest = changes.pop("context_binding_digest", None)
    explicit_attachment_digest = changes.pop("execution_attachment_digest", None)
    values = {
        "server_profile_id": config.server_profile_id,
        "driver_host_generation": generation or config.driver_host_generation,
        "host_profile_digest": config.host_profile_digest,
        "context_id": "context-1" if context else "",
        "context_generation": "context-generation-1" if context else "",
        "context_binding_digest": "",
        "execution_id": "execution-1" if attachment else "",
        "execution_attachment_generation": (
            "attachment-generation-1" if attachment else ""
        ),
        "execution_attachment_digest": "",
        "driver_binding_id": "driver-binding-1" if attachment else "",
    }
    values.update(changes)
    if context:
        values["context_binding_digest"] = explicit_context_digest or context_binding_digest(
            server_profile_id=values["server_profile_id"],
            driver_host_generation=values["driver_host_generation"],
            host_profile_digest=values["host_profile_digest"],
            schema_version=CONTEXT_SCHEMA_VERSION,
            context_profile_id=CONTEXT_PROFILE_ID,
            synthetic_context_label=SYNTHETIC_CONTEXT_LABEL,
        )
    if attachment:
        values["execution_attachment_digest"] = (
            explicit_attachment_digest
            or execution_attachment_digest(
                server_profile_id=values["server_profile_id"],
                driver_host_generation=values["driver_host_generation"],
                host_profile_digest=values["host_profile_digest"],
                context_id=values["context_id"],
                context_generation=values["context_generation"],
                context_binding_digest=values["context_binding_digest"],
                execution_id=values["execution_id"],
                schema_version=ATTACHMENT_SCHEMA_VERSION,
                attachment_profile_id=ATTACHMENT_PROFILE_ID,
                synthetic_execution_label=SYNTHETIC_EXECUTION_LABEL,
            )
        )
    return GenerationIdentity(**values)


def make_command(
    config: HostConfig,
    method: Method,
    suffix: str,
    *,
    identity: GenerationIdentity | None = None,
    operation_id: str | None = None,
    attempt_id: str | None = None,
    attempt_number: int = 1,
    deadline_unix_ms: int = FUTURE_DEADLINE_MS,
    **changes: Any,
) -> OperationCommand:
    if identity is None:
        identity = make_identity(
            config,
            context=method
            in {
                Method.OPEN_CONTEXT,
                Method.CLOSE_CONTEXT,
                Method.ATTACH_EXECUTION,
                Method.DETACH_EXECUTION,
            },
            attachment=method in {Method.ATTACH_EXECUTION, Method.DETACH_EXECUTION},
        )
    values: dict[str, Any] = {
        "method": method,
        "identity": identity,
        "operation_id": operation_id or f"operation-{suffix}",
        "attempt_id": attempt_id or f"attempt-{suffix}",
        "attempt_number": attempt_number,
        "correlation_id": f"correlation-{suffix}",
        "deadline_unix_ms": deadline_unix_ms,
        "credential_epoch": config.credential_epoch,
    }
    if method is Method.OPEN_CONTEXT:
        values.update(
            context_schema_version=CONTEXT_SCHEMA_VERSION,
            context_profile_id=CONTEXT_PROFILE_ID,
            synthetic_context_label=SYNTHETIC_CONTEXT_LABEL,
            expected_context_digest=identity.context_binding_digest,
        )
    elif method is Method.ATTACH_EXECUTION:
        values.update(
            attachment_schema_version=ATTACHMENT_SCHEMA_VERSION,
            attachment_profile_id=ATTACHMENT_PROFILE_ID,
            synthetic_execution_label=SYNTHETIC_EXECUTION_LABEL,
            expected_attachment_digest=identity.execution_attachment_digest,
            lifecycle_reason="INITIAL_LOAD",
        )
    elif method is Method.DETACH_EXECUTION:
        values["lifecycle_reason"] = "FINISHED"
    changes = dict(changes)
    if "target_operation_id" in changes or "target_attempt_id" in changes:
        values.update(
            target_operation_id=changes.pop("target_operation_id", ""),
            target_attempt_id=changes.pop("target_attempt_id", ""),
        )
    values.update(changes)
    return OperationCommand(**values)


def protobuf_identity(
    identity: GenerationIdentity,
    suffix: str,
    *,
    credential_epoch: int = 1,
    operation_id: str | None = None,
    attempt_id: str | None = None,
    attempt_number: int = 1,
    deadline_unix_ms: int = FUTURE_DEADLINE_MS,
) -> Any:
    return driver_pb2.RequestIdentity(
        contract_version=driver_pb2.ContractVersion(major=1, minor=0),
        server_profile_id=identity.server_profile_id,
        driver_host_generation=identity.driver_host_generation,
        host_profile_digest=identity.host_profile_digest,
        context_id=identity.context_id,
        context_generation=identity.context_generation,
        context_binding_digest=identity.context_binding_digest,
        execution_id=identity.execution_id,
        execution_attachment_generation=identity.execution_attachment_generation,
        execution_attachment_digest=identity.execution_attachment_digest,
        driver_binding_id=identity.driver_binding_id,
        operation_id=operation_id or f"operation-{suffix}",
        attempt_id=attempt_id or f"attempt-{suffix}",
        attempt_number=attempt_number,
        correlation_id=f"correlation-{suffix}",
        deadline_unix_ms=deadline_unix_ms,
        credential_epoch=credential_epoch,
    )
