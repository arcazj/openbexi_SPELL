from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecutionCreate(BaseModel):
    procedure_id: str
    context_id: str = "simulator"
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)


class CommandCreate(BaseModel):
    type: Literal["pause", "resume", "abort", "recover", "simulate_crash"]
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    correlation_id: UUID | None = None


class PromptResponseCreate(BaseModel):
    value: str = Field(min_length=1, max_length=200)
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    correlation_id: UUID | None = None


class ProcedureValidationRequest(BaseModel):
    source: str = Field(min_length=1, max_length=100_000)
    source_name: str = Field(
        default="submitted.spell.py",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )


class ErrorResponse(BaseModel):
    detail: str
    current: dict[str, Any] | None = None


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ControlMutationCreate(StrictRequest):
    action: Literal["ACQUIRE", "RENEW", "RELEASE_TO_BACKGROUND"]
    session_id: str = Field(min_length=1, max_length=128)
    client_instance_key_id: str = Field(min_length=1, max_length=128)
    expected_execution_revision: int = Field(ge=0)
    lease_id: str | None = Field(default=None, min_length=1, max_length=64)
    expected_lease_revision: int | None = Field(default=None, ge=1)
    control_fencing_token: int | None = Field(default=None, ge=1)
    lease_seconds: int = Field(default=30, ge=5, le=300)
    acknowledgement: str | None = Field(default=None, min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class MonitorSubscriptionCreate(StrictRequest):
    session_id: str = Field(min_length=1, max_length=128)
    client_instance_key_id: str = Field(min_length=1, max_length=128)


class HandoverRequestCreate(StrictRequest):
    requester_monitor_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=128)
    client_instance_key_id: str = Field(min_length=1, max_length=128)
    expected_execution_revision: int = Field(ge=0)
    responsibility_acknowledgement: str = Field(min_length=1, max_length=1000)
    expires_seconds: int = Field(default=60, ge=5, le=300)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ContextSettingsUpdate(StrictRequest):
    settings: dict[str, Any] = Field(min_length=1, max_length=3)
    expected_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class OperatorControlProof(StrictRequest):
    lease_id: str = Field(min_length=1, max_length=64)
    expected_lease_revision: int = Field(ge=1)
    control_fencing_token: int = Field(ge=1)
    session_id: str = Field(min_length=1, max_length=128)
    client_instance_key_id: str = Field(min_length=1, max_length=128)


class HandoverApproveCreate(OperatorControlProof):
    expected_handover_revision: int = Field(ge=1)
    expected_execution_revision: int = Field(ge=0)
    lease_seconds: int = Field(default=60, ge=5, le=300)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ExecutionSettingsUpdate(OperatorControlProof):
    settings: dict[str, Any] = Field(min_length=1, max_length=3)
    expected_execution_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class OperatorCommandCreate(OperatorControlProof):
    type: Literal[
        "RUN",
        "STEP",
        "STEP_OVER",
        "PAUSE",
        "SKIP",
        "GOTO",
        "RELOAD",
        "ABORT",
        "RECOVER",
        "BACKGROUND",
        "STOP",
        "KILL",
    ]
    expected_execution_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=200)
    correlation_id: UUID | None = None
    target: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)


class OperatorPromptResponseCreate(OperatorControlProof):
    action: Literal["COMMIT", "ABORT"]
    value: Any = None
    expected_prompt_revision: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ScheduleCreate(OperatorControlProof):
    controller_execution_id: str = Field(min_length=1, max_length=64)
    schedule_type: Literal["RELATIVE", "ABSOLUTE"]
    target: str | int | float
    procedure_catalog_id: str = Field(min_length=1, max_length=200)
    procedure_revision: int | None = Field(default=None, ge=1)
    context_id: str = Field(default="simulator", min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    automatic: bool = True
    background_allowed: bool = True
    visible: bool = True
    misfire_policy: Literal["FIRE_ONCE", "SKIP"] = "FIRE_ONCE"
    maximum_lateness_seconds: int = Field(default=3600, ge=0, le=604800)
    expected_execution_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ScheduleCancelCreate(OperatorControlProof):
    expected_schedule_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class InspectionEditCreate(OperatorControlProof):
    path: str = Field(min_length=1, max_length=200)
    scope: Literal["LOCAL_VARIABLE", "GLOBAL_VARIABLE", "ARGS", "IVARS"]
    type: Literal["NULL", "BOOLEAN", "INTEGER", "FINITE_DECIMAL", "STRING", "LIST", "MAP"]
    value: Any
    expected_value_revision: int = Field(ge=0)
    expected_execution_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class ConsoleOperationCreate(StrictRequest):
    operation: Literal[
        "LIST_SCOPE",
        "READ_VALUE",
        "EXPAND_VALUE",
        "SEARCH_SOURCE_LITERAL",
        "WRITE_TYPED_LITERAL",
    ]
    path: str | None = Field(default=None, min_length=1, max_length=200)
    scope: Literal[
        "LOCAL_VARIABLE", "GLOBAL_VARIABLE", "ARGS", "IVARS", "SHARED_DATA"
    ] | None = None
    query: str | None = Field(default=None, min_length=1, max_length=200)
    limit: int = Field(default=100, ge=1, le=200)
    type: Literal[
        "NULL",
        "BOOLEAN",
        "INTEGER",
        "FINITE_DECIMAL",
        "STRING",
        "LIST",
        "MAP",
    ] | None = None
    value: Any = None
    expected_execution_revision: int = Field(ge=0)
    lease_id: str | None = Field(default=None, min_length=1, max_length=64)
    expected_lease_revision: int | None = Field(default=None, ge=1)
    control_fencing_token: int | None = Field(default=None, ge=1)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    client_instance_key_id: str | None = Field(default=None, min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_operation_shape(self):
        common = {
            "operation",
            "expected_execution_revision",
            "idempotency_key",
            "reason",
        }
        operation_fields = {
            "LIST_SCOPE": {"scope", "limit"},
            "READ_VALUE": {"path"},
            "EXPAND_VALUE": {"path", "limit"},
            "SEARCH_SOURCE_LITERAL": {"query", "limit"},
            "WRITE_TYPED_LITERAL": {
                "path",
                "type",
                "value",
                "lease_id",
                "expected_lease_revision",
                "control_fencing_token",
                "session_id",
                "client_instance_key_id",
            },
        }
        required = {
            "LIST_SCOPE": {"scope"},
            "READ_VALUE": {"path"},
            "EXPAND_VALUE": {"path"},
            "SEARCH_SOURCE_LITERAL": {"query"},
            "WRITE_TYPED_LITERAL": {
                "path",
                "type",
                "value",
                "lease_id",
                "expected_lease_revision",
                "control_fencing_token",
                "session_id",
                "client_instance_key_id",
            },
        }
        unsupported = self.model_fields_set - common - operation_fields[self.operation]
        if unsupported:
            raise ValueError(
                f"{self.operation} contains unsupported fields: "
                + ", ".join(sorted(unsupported))
            )
        missing = [
            field
            for field in required[self.operation]
            if (
                field not in self.model_fields_set
                or (field != "value" and getattr(self, field) is None)
            )
        ]
        if missing:
            raise ValueError(
                f"{self.operation} requires: " + ", ".join(sorted(missing))
            )
        return self


class UserActionInvokeCreate(OperatorControlProof):
    expected_action_revision: int = Field(ge=1)
    expected_execution_revision: int = Field(ge=0)
    arguments: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class UserActionMutationCreate(OperatorControlProof):
    operation: Literal["ENABLE", "DISABLE", "DISMISS"]
    expected_action_revision: int = Field(ge=1)
    expected_execution_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class BreakpointMutationCreate(OperatorControlProof):
    expected_execution_revision: int = Field(ge=0)
    one_shot: bool = False
    idempotency_key: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)
