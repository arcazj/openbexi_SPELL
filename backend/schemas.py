from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


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
