from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base, utc_now


def new_id() -> str:
    return str(uuid.uuid4())


class Execution(Base):
    __tablename__ = "executions"
    __table_args__ = (
        UniqueConstraint("created_by", "creation_idempotency_key", name="uq_execution_creation"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    procedure_id: Mapped[str] = mapped_column(String(200), index=True)
    procedure_name: Mapped[str] = mapped_column(String(200))
    procedure_hash: Mapped[str] = mapped_column(String(64))
    procedure_source: Mapped[str] = mapped_column(Text)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    ir_version: Mapped[str] = mapped_column(String(20), default="0.3", server_default="0.3")
    variables: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, server_default=text("'{}'"), nullable=False
    )
    context_id: Mapped[str] = mapped_column(String(100), default="simulator")
    created_by: Mapped[str] = mapped_column(String(200))
    creation_idempotency_key: Mapped[str] = mapped_column(String(200))
    state: Mapped[str] = mapped_column(String(40), default="created", index=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    total_steps: Mapped[int] = mapped_column(Integer)
    worker_generation: Mapped[int] = mapped_column(Integer, default=0)
    next_sequence: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    events: Mapped[list["Event"]] = relationship(back_populates="execution")
    commands: Mapped[list["Command"]] = relationship(back_populates="execution")
    prompts: Mapped[list["Prompt"]] = relationship(back_populates="execution")


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("execution_id", "sequence", name="uq_event_execution_sequence"),
        Index("ix_event_execution_sequence", "execution_id", "sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"))
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    source: Mapped[str] = mapped_column(String(60), default="supervisor")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    correlation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    causation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    execution: Mapped[Execution] = relationship(back_populates="events")


class Command(Base):
    __tablename__ = "commands"
    __table_args__ = (
        UniqueConstraint("execution_id", "idempotency_key", name="uq_command_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"))
    command_type: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="accepted")
    idempotency_key: Mapped[str] = mapped_column(String(200))
    expected_revision: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id)
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    execution: Mapped[Execution] = relationship(back_populates="commands")


class Prompt(Base):
    __tablename__ = "prompts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    execution_id: Mapped[str] = mapped_column(ForeignKey("executions.id"), index=True)
    step_index: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default="open")
    question: Mapped[str] = mapped_column(Text)
    choices: Mapped[list[str]] = mapped_column(JSON, default=list)
    default_choice: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    response: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    responded_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    execution: Mapped[Execution] = relationship(back_populates="prompts")
