from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import Command, Event, Execution, Prompt
from .procedure_parser import language_profile_for_ir


def iso(value):
    return value.isoformat() if value is not None else None


def event_dict(event: Event) -> dict[str, Any]:
    return {
        "schema_version": "0.3",
        "payload_version": "1",
        "event_id": event.id,
        "execution_id": event.execution_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "server_time": iso(event.created_at),
        "source": event.source,
        "severity": event.severity,
        "correlation_id": event.correlation_id,
        "causation_id": event.causation_id,
        "payload": event.payload,
    }


def command_dict(command: Command) -> dict[str, Any]:
    return {
        "id": command.id,
        "execution_id": command.execution_id,
        "type": command.command_type,
        "status": command.status,
        "idempotency_key": command.idempotency_key,
        "expected_revision": command.expected_revision,
        "actor": command.actor,
        "role": command.role,
        "reason": command.reason,
        "correlation_id": command.correlation_id,
        "result": command.result_payload,
        "created_at": iso(command.created_at),
        "completed_at": iso(command.completed_at),
    }


def prompt_dict(prompt: Prompt) -> dict[str, Any]:
    return {
        "id": prompt.id,
        "execution_id": prompt.execution_id,
        "step_index": prompt.step_index,
        "status": prompt.status,
        "question": prompt.question,
        "choices": prompt.choices,
        "default": prompt.default_choice,
        "response": prompt.response,
        "responded_by": prompt.responded_by,
        "created_at": iso(prompt.created_at),
        "responded_at": iso(prompt.responded_at),
    }


def execution_configuration_hash(
    *,
    context_id: str,
    procedure_hash: str,
    ir_version: str,
    steps: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> str:
    identity = {
        "context_id": context_id,
        "procedure_hash": procedure_hash,
        "procedure_subset_version": language_profile_for_ir(ir_version),
        "steps": list(steps),
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def execution_dict(execution: Execution) -> dict[str, Any]:
    subset_version = language_profile_for_ir(execution.ir_version)
    config_hash = execution_configuration_hash(
        context_id=execution.context_id,
        procedure_hash=execution.procedure_hash,
        ir_version=execution.ir_version,
        steps=execution.steps,
    )
    return {
        "id": execution.id,
        "procedure_id": execution.procedure_id,
        "procedure_name": execution.procedure_name,
        "procedure_hash": execution.procedure_hash,
        "context_id": execution.context_id,
        "state": execution.state,
        "revision": execution.revision,
        "current_step": execution.current_step,
        "total_steps": execution.total_steps,
        "worker_generation": execution.worker_generation,
        "variables": execution.variables,
        "procedure_subset_version": subset_version,
        "configuration_hash": config_hash,
        "last_sequence": execution.next_sequence - 1,
        "created_at": iso(execution.created_at),
        "updated_at": iso(execution.updated_at),
    }
