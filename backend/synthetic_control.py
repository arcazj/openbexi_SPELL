"""Closed compatibility facade over the existing durable simulator supervisor."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, StrictInt, field_validator
from sqlalchemy import select

from .models import Execution
from .operator_models import OperatorCommand
from .operator_serialization import command_dict
from .operator_service import (
    OperatorAuthorizationError, OperatorConflictError, OperatorNotFoundError, OperatorValidationError,
)
from .schemas import OperatorControlProof

PROFILE = "LOCAL_SYNTHETIC_PROCEDURE_CONTROL"
OPERATIONS = {"RUN": "RUN", "STEP": "STEP", "PAUSE": "PAUSE", "ABORT": "ABORT",
              "RETURN_TO_READ_ONLY": "STOP"}
PREFIX = "compat-v13:"


class CompatibilityCommand(OperatorControlProof):
    operation: Literal["RUN", "STEP", "PAUSE", "ABORT", "RETURN_TO_READ_ONLY"]
    operation_id: UUID
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_execution_revision: StrictInt = Field(ge=0)
    expected_lease_revision: StrictInt = Field(ge=1)
    control_fencing_token: StrictInt = Field(ge=1)
    reason: str = Field(min_length=1, max_length=900)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value: str) -> str:
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError("a printable reason is required")
        return value


def profile() -> dict:
    value = json.loads((Path(__file__).resolve().parents[1] / "contracts/v13/control_profile.json").read_bytes())
    if value["commands"] != OPERATIONS or value["profile"] != PROFILE:
        raise RuntimeError("synthetic control profile differs")
    extension = json.loads((Path(__file__).resolve().parents[1] / "contracts/v16/control_extension.json").read_bytes())
    if extension.get("additional_execution_ir_versions") != ["0.16"] or extension.get("new_commands") != [] or extension.get("operational_authorization") is not False:
        raise RuntimeError("synthetic control extension differs")
    value["execution_ir_versions"] = [*value["execution_ir_versions"], "0.16"]
    value["extension_schema"] = extension["schema_version"]
    extension = json.loads((Path(__file__).resolve().parents[1] / "contracts/v17/control_extension.json").read_bytes())
    if (extension.get("schema_version") != "spell.v17.control-extension/1"
            or extension.get("extends") != "contracts/v16/control_extension.json"
            or extension.get("profile") != PROFILE
            or extension.get("additional_execution_ir_versions") != ["0.17"]
            or extension.get("new_commands") != []
            or extension.get("operational_authorization") is not False):
        raise RuntimeError("synthetic control v0.17 extension differs")
    value["execution_ir_versions"].append("0.17")
    value["extension_schema"] = extension["schema_version"]
    extension = json.loads((Path(__file__).resolve().parents[1] / "contracts/v18/control_extension.json").read_bytes())
    if (extension.get("schema_version") != "spell.v18.control-extension/1"
            or extension.get("extends") != "contracts/v17/control_extension.json"
            or extension.get("profile") != PROFILE
            or extension.get("additional_execution_ir_versions") != ["0.18"]
            or extension.get("new_commands") != []
            or extension.get("operational_authorization") is not False):
        raise RuntimeError("synthetic control v0.18 extension differs")
    value["execution_ir_versions"].append("0.18")
    value["extension_schema"] = extension["schema_version"]
    return value


class SyntheticControl:
    def __init__(self, service, supervisor):
        self.service, self.supervisor = service, supervisor

    def execution(self, execution_id: str) -> Execution:
        with self.service.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            if execution.context_id != "simulator":
                raise OperatorAuthorizationError("synthetic simulator context required")
            if execution.ir_version not in {"0.6", "0.7", "0.8", "0.10", "0.11", "0.16", "0.17", "0.18"}:
                raise OperatorValidationError("a fenced operator execution profile is required")
            return execution

    def submit(self, execution_id: str, request: CompatibilityCommand, *, actor: str, role: str) -> dict:
        if role not in {"operator", "admin"}:
            raise OperatorAuthorizationError("operator role required")
        execution = self.execution(execution_id)
        if execution.procedure_hash != request.source_digest:
            raise OperatorConflictError("procedure source digest differs")
        command = self.service.accept_operator_command(
            execution_id=execution_id, command_type=OPERATIONS[request.operation],
            expected_execution_revision=request.expected_execution_revision,
            idempotency_key=PREFIX + str(request.operation_id), actor=actor, role=role,
            reason=f"[v13 {request.operation}] {request.reason}",
            controller_lease_id=request.lease_id, expected_lease_revision=request.expected_lease_revision,
            control_fencing_token=request.control_fencing_token, holder_session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id, correlation_id=str(request.operation_id),
        )
        if command["state"] == "ACCEPTED":
            self.supervisor.dispatch_operator_command(command)
        return self.receipt(execution_id, request.operation_id)

    def receipt(self, execution_id: str, operation_id: UUID) -> dict:
        execution = self.execution(execution_id)
        with self.service.session_factory() as session:
            row = session.scalar(select(OperatorCommand).where(
                OperatorCommand.execution_id == execution_id,
                OperatorCommand.idempotency_key == PREFIX + str(operation_id),
            ))
            if row is None:
                raise OperatorNotFoundError("compatibility operation not found")
            command = command_dict(row)
        rollback = command["type"] == "STOP"
        settled_read_only = rollback and command["state"] == "SETTLED" and execution.state in {
            "completed", "aborted", "failed"}
        return {"profile": PROFILE, "operation_id": str(operation_id), "command": command,
                "source_digest": execution.procedure_hash, "legacy_system_qualified": False,
                "read_only_confirmed": settled_read_only,
                "rollback_pending": rollback and command["state"] in {
                    "ACCEPTED", "WAITING_SAFE_POINT", "APPLYING", "RECONCILING"}}
