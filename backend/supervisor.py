from __future__ import annotations

import os
import multiprocessing
import hashlib
import json
import math
import queue
import threading
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, Mapping

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from .data_domain import DataDomainError, ProcedureCallerBinding
from .data_repository import runtime_container_definitions
from .events import EventHub
from .ir_v03 import IRValidationError, validate_ir_v03
from .ir_v06 import (
    IR_VERSION as V06_IR_VERSION,
    SafePoint,
    V06ValidationError,
    validate_ir_v06,
    validate_safe_point,
)
from .ir_v07 import (
    IR_VERSION as V07_IR_VERSION,
    ObservationAnchorProvider,
    ObservationRuntime,
    V07ValidationError,
    bind_observation_anchor,
    canonicalize_observation_result,
    unavailable_observation_anchor,
    unavailable_observation_result,
    validate_anchored_observation_request,
    validate_ir_v07,
    validate_observation_request,
    validate_observation_result,
)
from .ir_v08 import (
    IR_VERSION as V08_IR_VERSION,
    DataRuntime,
    V08ValidationError,
    argument_declarations_from_steps,
    canonicalize_data_result,
    closed_file_handle_reference,
    data_request_id,
    is_file_handle_reference,
    persistable_data_result,
    stale_file_handle_result,
    unavailable_data_result,
    validate_data_request,
    validate_data_result,
    validate_file_handle_reference,
    validate_ir_v08,
)
from .models import Command, Event, Execution, Prompt
from .operator_models import OperatorCommand, OperatorPrompt
from .operator_serialization import command_dict as operator_command_dict
from .procedure_parser import IR_VERSION, Procedure, ProcedureCatalog
from .serialization import command_dict, event_dict, execution_dict, prompt_dict
from .worker import sanitized_worker_environment, worker_main

if TYPE_CHECKING:
    from .operator_service import OperatorService


TERMINAL_STATES = {"completed", "aborted", "failed"}
ACTIVE_STATES = {
    "starting",
    "running",
    "pausing",
    "paused",
    "resuming",
    "prompting",
    "waiting",
    "aborting",
    "recovering",
}

_LEGACY_EVENT_REFERENCE_LIMIT = 36
_LEGACY_EVENT_REFERENCE_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "openbexi-spell:legacy-event-reference"
)
_WORKER_HANDLE_UNSET = object()
_DATA_RUNTIME_BINDING_KEY = "_runtime_binding"
_V06_PLUS_IR_VERSIONS = frozenset(
    {V06_IR_VERSION, V07_IR_VERSION, V08_IR_VERSION}
)


def _legacy_event_reference(value: str | None) -> str | None:
    """Fit opaque internal identities into the immutable v0.2 Event schema."""

    if value is None:
        return None
    if type(value) is not str or not value:
        raise ValueError("event reference must be a non-empty string")
    if len(value) <= _LEGACY_EVENT_REFERENCE_LIMIT:
        return value
    return str(uuid.uuid5(_LEGACY_EVENT_REFERENCE_NAMESPACE, value))


def _contains_file_handle_token(value: Any, token_digests: set[str]) -> bool:
    if type(value) is str:
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError:
            return False
        return hashlib.sha256(encoded).hexdigest() in token_digests
    if type(value) is list:
        return any(
            _contains_file_handle_token(item, token_digests) for item in value
        )
    if type(value) is dict:
        return any(
            _contains_file_handle_token(item, token_digests)
            for item in value.values()
        )
    return False


PROCEDURE_SUBSET_VERSION = f"spell-restricted-ast/{IR_VERSION}"
_WORKER_SPAWN_ENVIRONMENT_LOCK = threading.Lock()


def canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def configuration_hash(procedure: Procedure, context_id: str) -> str:
    return canonical_hash(
        {
            "context_id": context_id,
            "procedure_hash": procedure.sha256,
            "procedure_subset_version": f"spell-restricted-ast/{procedure.ir_version}",
            "steps": list(procedure.steps),
            "user_actions": list(procedure.user_actions),
        }
    )


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


class StaleWorkerMessage(ConflictError):
    pass


class AuthorizationError(PermissionError):
    pass


class _AfterSupervisorUnlock:
    __slots__ = ("callback",)

    def __init__(self, callback):
        self.callback = callback


def _resolve_after_supervisor_unlock(method):
    @wraps(method)
    def resolved(*args, **kwargs):
        result = method(*args, **kwargs)
        if isinstance(result, _AfterSupervisorUnlock):
            return result.callback()
        return result

    return resolved


@dataclass
class WorkerHandle:
    process: multiprocessing.Process
    control: Any
    output: Any
    generation: int
    normal_exit: bool = False
    intentional_stop: bool = False
    failure_signal: threading.Event = field(default_factory=threading.Event)
    failure_detail: str | None = None
    dispatch_lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
    )


class Supervisor:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        catalog: ProcedureCatalog,
        hub: EventHub,
        command_ack_timeout_seconds: float = 5.0,
        operator_service: "OperatorService | None" = None,
        observation_runtime: (
            ObservationRuntime
            | Callable[[Mapping[str, Any]], Mapping[str, Any]]
            | None
        ) = None,
        observation_anchor_provider: ObservationAnchorProvider | None = None,
        data_runtime: (
            DataRuntime
            | Callable[[Mapping[str, Any]], Mapping[str, Any]]
            | None
        ) = None,
        data_repository: Any | None = None,
        development_runtime_pin: Callable[..., dict[str, Any] | None] | None = None,
    ):
        self.session_factory = session_factory
        self.catalog = catalog
        self.hub = hub
        self._ctx = multiprocessing.get_context("spawn")
        self._lock = threading.RLock()
        self._workers: dict[str, WorkerHandle] = {}
        self._spawning: set[str] = set()
        self._startproc_watchers: set[tuple[str, str, int]] = set()
        self._observation_requests: set[tuple[str, str, int]] = set()
        self._data_requests: set[tuple[str, str, int]] = set()
        self._abort_cleanup_barriers: set[tuple[str, str]] = set()
        self._recovery_pause_pending: set[str] = set()
        self._prompt_settlement_attempts: dict[str, float] = {}
        self._durable_delivery_attempts: dict[tuple[str, str, int], float] = {}
        self._operator_bridge_started = False
        self._closed = False
        if (
            not math.isfinite(command_ack_timeout_seconds)
            or command_ack_timeout_seconds <= 0
        ):
            raise ValueError("command ACK timeout must be a positive finite number")
        self.command_ack_timeout_seconds = command_ack_timeout_seconds
        self.operator_service = operator_service
        self.observation_runtime = observation_runtime
        self.observation_anchor_provider = observation_anchor_provider
        self.data_runtime = data_runtime
        self.data_repository = data_repository
        self.development_runtime_pin = development_runtime_pin
        if operator_service is not None:
            if operator_service.prompt_settlement_sink is None:
                operator_service.prompt_settlement_sink = self.dispatch_prompt_settlement
            self._start_operator_bridge()

    def attach_operator_service(self, operator_service: "OperatorService") -> None:
        """Attach the durable v0.6 operator store during application assembly."""

        if self.operator_service is not None and self.operator_service is not operator_service:
            raise ConflictError("another operator service is already attached")
        self.operator_service = operator_service
        if operator_service.prompt_settlement_sink is None:
            operator_service.prompt_settlement_sink = self.dispatch_prompt_settlement
        self._start_operator_bridge()

    def _pin_development_execution(
        self,
        session: Session,
        *,
        execution_id: str,
        procedure: Procedure,
        inherited_runtime_kind: str | None,
        inherited_runtime_id: str | None,
    ) -> None:
        callback = self.development_runtime_pin
        if callback is None or procedure.bundle_digest is None:
            raise ConflictError("development runtime admission is unavailable")
        try:
            result = callback(
                session,
                runtime_kind="EXECUTION",
                runtime_id=execution_id,
                procedure_id=procedure.id,
                bundle_digest=procedure.bundle_digest,
                inherited_runtime_kind=inherited_runtime_kind,
                inherited_runtime_id=inherited_runtime_id,
            )
        except Exception as exc:
            raise ConflictError("development runtime admission failed") from exc
        if result is None:
            raise ConflictError("development procedure is not currently promoted")

    @staticmethod
    def _v08_admission_binding(
        execution: Execution, creation_request_hash: str
    ) -> ProcedureCallerBinding:
        request_id = "admission." + hashlib.sha256(
            f"{execution.id}\0{creation_request_hash}".encode("ascii")
        ).hexdigest()
        return ProcedureCallerBinding(
            service_principal_id="procedure-runtime",
            execution_id=execution.id,
            worker_generation=int(execution.worker_generation),
            deterministic_request_id=request_id,
        )

    def _start_operator_bridge(self) -> None:
        with self._lock:
            if self._operator_bridge_started:
                return
            self._operator_bridge_started = True
        threading.Thread(target=self._operator_bridge_loop, daemon=True).start()

    def _operator_bridge_loop(self) -> None:
        while not self._closed:
            try:
                service = self.operator_service
                if service is not None:
                    service.replay_prompt_deliveries()
                    reserved = self._replay_operator_command_deliveries()
                    reserved.update(
                        self._replay_user_action_deliveries(
                            skip_execution_ids=reserved
                        )
                    )
                    self._replay_startproc_deliveries()
                    self._replay_inspection_edit_deliveries(
                        skip_execution_ids=reserved
                    )
                    self._replay_control_loss_events()
                    self._replay_control_loss_deliveries()
            except Exception:
                # Durable rows remain replayable; a later iteration or process
                # restart retries without creating a second settlement.
                pass
            time.sleep(0.1)

    def _admit_operator_bundle(
        self,
        execution_id: str,
        procedure: Procedure,
        *,
        automatic: bool,
        background_allowed: bool = False,
        visible: bool = True,
        catalog_revision_id: str | None = None,
        predecessor_execution_id: str | None = None,
        depth: int = 0,
        ownership_mode: str = "CONTROL_LOST",
        operator_settings: dict[str, Any] | None = None,
    ) -> None:
        service = self.operator_service
        if service is None:
            return
        service.ensure_execution_projection(
            execution_id,
            actor="operator-bootstrap",
            automatic=automatic,
            background_allowed=background_allowed,
            visible=visible,
            catalog_revision_id=catalog_revision_id,
            predecessor_execution_id=predecessor_execution_id,
            depth=depth,
            ownership_mode=ownership_mode,
            settings=operator_settings or {},
            authoritative=True,
        )
        if procedure.ir_version not in _V06_PLUS_IR_VERSIONS:
            return
        reparsed = self.catalog.validate_source(
            procedure.source,
            f"{procedure.id}.spell.py",
            path=procedure.path,
        )
        if (
            reparsed.sha256 != procedure.sha256
            or reparsed.ir_version != procedure.ir_version
            or reparsed.steps != procedure.steps
        ):
            raise ConflictError(
                "procedure action metadata does not match the immutable source snapshot"
            )
        if not reparsed.user_actions:
            return
        for action in reparsed.user_actions:
            action_name = action["name"]
            action_id = "action-" + uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"openbexi-spell:{execution_id}:{procedure.sha256}:{action_name}",
            ).hex
            service.register_user_action(
                execution_id,
                {**action, "id": action_id},
                actor="operator-bootstrap",
                idempotency_key=(
                    f"bundle-action:{procedure.sha256[:24]}:{action_name}"
                ),
            )

    @_resolve_after_supervisor_unlock
    def create_execution(
        self,
        procedure: Procedure,
        actor: str,
        role: str,
        reason: str,
        idempotency_key: str,
        context_id: str = "simulator",
        automatic: bool = True,
        initial_variables: dict[str, Any] | None = None,
        background_allowed: bool = False,
        visible: bool = True,
        catalog_revision_id: str | None = None,
        predecessor_execution_id: str | None = None,
        depth: int = 0,
        ownership_mode: str = "CONTROL_LOST",
        operator_settings: dict[str, Any] | None = None,
        runtime_pin_parent_kind: str | None = None,
        runtime_pin_parent_id: str | None = None,
    ) -> Execution:
        if role not in {"operator", "admin"}:
            raise AuthorizationError("operator role required")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ConflictError(
                "idempotency key is required and must not exceed 200 characters"
            )
        if type(automatic) is not bool:
            raise ConflictError("automatic must be Boolean")
        if type(background_allowed) is not bool or type(visible) is not bool:
            raise ConflictError("projection visibility settings must be Boolean")
        if type(depth) is not int or depth < 0 or depth > 8:
            raise ConflictError("execution depth is outside the v0.6 bound")
        if ownership_mode not in {"C", "B", "CONTROL_LOST"}:
            raise ConflictError("execution ownership mode is invalid")
        if catalog_revision_id is not None and (
            type(catalog_revision_id) is not str or not catalog_revision_id
        ):
            raise ConflictError("catalog revision identity is invalid")
        if predecessor_execution_id is not None and (
            type(predecessor_execution_id) is not str
            or not predecessor_execution_id
        ):
            raise ConflictError("predecessor execution identity is invalid")
        if (runtime_pin_parent_kind is None) != (runtime_pin_parent_id is None):
            raise ConflictError("runtime pin predecessor is incomplete")
        if runtime_pin_parent_kind not in {None, "SCHEDULE", "STARTPROC"}:
            raise ConflictError("runtime pin predecessor kind is invalid")
        operator_settings = operator_settings or {}
        if not isinstance(operator_settings, dict):
            raise ConflictError("operator settings must be a finite JSON object")
        try:
            json.dumps(operator_settings, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ConflictError(
                "operator settings must be a finite JSON object"
            ) from exc
        if initial_variables is None:
            initial_variables = {}
        try:
            json.dumps(initial_variables, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ConflictError("initial variables must be finite JSON data") from exc
        if not isinstance(initial_variables, dict) or len(initial_variables) > 64:
            raise ConflictError("initial variables must be a bounded object")
        v08_argument_definitions = None
        if procedure.ir_version == V08_IR_VERSION:
            try:
                v08_argument_definitions = runtime_container_definitions(
                    initial_variables,
                    declared_types=argument_declarations_from_steps(procedure.steps),
                )
            except (DataDomainError, V08ValidationError) as exc:
                raise ConflictError(
                    "v0.8 arguments do not match the immutable procedure declaration"
                ) from exc
        creation_request_hash = canonical_hash(
            {
                "procedure_id": procedure.id,
                "context_id": context_id,
                "reason": reason,
                "actor": actor,
            }
        )
        if (
            procedure.ir_version in _V06_PLUS_IR_VERSIONS
            or not automatic
            or initial_variables
            or background_allowed
            or not visible
            or catalog_revision_id is not None
            or predecessor_execution_id is not None
            or depth != 0
            or ownership_mode != "CONTROL_LOST"
            or operator_settings
            or runtime_pin_parent_kind is not None
        ):
            creation_request_hash = canonical_hash(
                {
                    "procedure_id": procedure.id,
                    "context_id": context_id,
                    "reason": reason,
                    "actor": actor,
                    "automatic": automatic,
                    "initial_variables": initial_variables,
                    "background_allowed": background_allowed,
                    "visible": visible,
                    "catalog_revision_id": catalog_revision_id,
                    "predecessor_execution_id": predecessor_execution_id,
                    "depth": depth,
                    "ownership_mode": ownership_mode,
                    "operator_settings": operator_settings,
                    "runtime_pin_parent_kind": runtime_pin_parent_kind,
                    "runtime_pin_parent_id": runtime_pin_parent_id,
                }
            )
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            existing = session.scalar(
                select(Execution).where(
                    Execution.created_by == actor,
                    Execution.creation_idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                created_event = session.scalar(
                    select(Event).where(
                        Event.execution_id == existing.id,
                        Event.event_type == "execution.created",
                    )
                )
                stored_hash = created_event.payload.get("request_hash") if created_event else None
                if stored_hash != creation_request_hash:
                    raise ConflictError("creation idempotency key was used for another request")
                if procedure.bundle_digest is not None:
                    self._pin_development_execution(
                        session,
                        execution_id=existing.id,
                        procedure=procedure,
                        inherited_runtime_kind=runtime_pin_parent_kind,
                        inherited_runtime_id=runtime_pin_parent_id,
                    )
                if existing.ir_version == V08_IR_VERSION:
                    repository = self.data_repository
                    if repository is None:
                        raise ConflictError("v0.8 data repository is unavailable")
                    repository.assert_execution_projections(
                        session,
                        existing,
                        self._v08_admission_binding(existing, creation_request_hash),
                        args=v08_argument_definitions,
                    )
                session.commit()
                session.expunge(existing)

                def admit_existing() -> Execution:
                    self._admit_operator_bundle(
                        existing.id,
                        procedure,
                        automatic=automatic,
                        background_allowed=background_allowed,
                        visible=visible,
                        catalog_revision_id=catalog_revision_id,
                        predecessor_execution_id=predecessor_execution_id,
                        depth=depth,
                        ownership_mode=ownership_mode,
                        operator_settings=operator_settings,
                    )
                    return existing

                return _AfterSupervisorUnlock(admit_existing)
            execution = Execution(
                procedure_id=procedure.id,
                procedure_name=procedure.name,
                procedure_hash=procedure.sha256,
                procedure_source=procedure.source,
                steps=list(procedure.steps),
                ir_version=procedure.ir_version,
                variables={"ARGS": initial_variables} if initial_variables else {},
                total_steps=len(procedure.steps),
                context_id=context_id,
                created_by=actor,
                creation_idempotency_key=idempotency_key,
            )
            session.add(execution)
            session.flush()
            if procedure.bundle_digest is not None:
                self._pin_development_execution(
                    session,
                    execution_id=execution.id,
                    procedure=procedure,
                    inherited_runtime_kind=runtime_pin_parent_kind,
                    inherited_runtime_id=runtime_pin_parent_id,
                )
            config_hash = configuration_hash(procedure, context_id)
            created_event = self._add_event(
                session,
                execution,
                "execution.created",
                {
                    "procedure_id": procedure.id,
                    "procedure_hash": procedure.sha256,
                    "procedure_subset_version": f"spell-restricted-ast/{procedure.ir_version}",
                    "configuration_hash": config_hash,
                    "request_hash": creation_request_hash,
                    "user_action_count": len(procedure.user_actions),
                },
                source="api",
            )
            execution.state = "validated"
            execution.revision = 1
            self._add_event(
                session,
                execution,
                "execution.state_changed",
                {"previous": "created", "state": "validated", "revision": 1},
                source="supervisor",
            )
            execution.state = "ready"
            execution.revision = 2
            self._add_event(
                session,
                execution,
                "execution.state_changed",
                {"previous": "validated", "state": "ready", "revision": 2},
                source="supervisor",
            )
            if not automatic:
                if execution.ir_version == V08_IR_VERSION:
                    repository = self.data_repository
                    if repository is None:
                        raise ConflictError("v0.8 data repository is unavailable")
                    admission = repository.stage_execution_admission(
                        session,
                        execution,
                        self._v08_admission_binding(execution, creation_request_hash),
                        args=v08_argument_definitions,
                    )
                    created_event.payload = {
                        **created_event.payload,
                        "data_projections": admission["projections"],
                    }
                session.commit()
                session.refresh(execution)
                events = session.scalars(
                    select(Event)
                    .where(Event.execution_id == execution.id)
                    .order_by(Event.sequence)
                ).all()
                self._publish(execution.id, [event_dict(event) for event in events])
                execution_id = execution.id
                session.commit()
                session.expunge(execution)

                def admit_manual() -> Execution:
                    self._admit_operator_bundle(
                        execution_id,
                        procedure,
                        automatic=False,
                        background_allowed=background_allowed,
                        visible=visible,
                        catalog_revision_id=catalog_revision_id,
                        predecessor_execution_id=predecessor_execution_id,
                        depth=depth,
                        ownership_mode=ownership_mode,
                        operator_settings=operator_settings,
                    )
                    return execution

                return _AfterSupervisorUnlock(admit_manual)
            start_payload = {"creation_request_hash": creation_request_hash}
            start_correlation_id = str(uuid.uuid4())
            start_request_hash = canonical_hash(
                {
                    "command_type": "start",
                    "expected_revision": 2,
                    "actor": actor,
                    "reason": reason or "Start newly created simulator execution",
                    "correlation_id": start_correlation_id,
                    "payload": start_payload,
                }
            )
            start_command = Command(
                execution_id=execution.id,
                command_type="start",
                idempotency_key=f"auto-start:{execution.id}",
                expected_revision=2,
                actor=actor,
                role=role,
                reason=reason or "Start newly created simulator execution",
                correlation_id=start_correlation_id,
                request_payload={"request": start_payload, "_request_hash": start_request_hash},
            )
            session.add(start_command)
            execution.state = "starting"
            execution.revision = 3
            session.flush()
            if execution.ir_version == V08_IR_VERSION:
                repository = self.data_repository
                if repository is None:
                    raise ConflictError("v0.8 data repository is unavailable")
                admission = repository.stage_execution_admission(
                    session,
                    execution,
                    self._v08_admission_binding(execution, creation_request_hash),
                    args=v08_argument_definitions,
                )
                created_event.payload = {
                    **created_event.payload,
                    "data_projections": admission["projections"],
                }
            self._add_event(
                session,
                execution,
                "command.accepted",
                {"command": command_dict(start_command)},
                source="api",
                correlation_id=start_command.correlation_id,
                causation_id=start_command.id,
            )
            self._add_event(
                session,
                execution,
                "execution.state_changed",
                {"previous": "ready", "state": "starting", "revision": 3},
                source="api",
                correlation_id=start_command.correlation_id,
                causation_id=start_command.id,
            )
            session.commit()
            session.refresh(execution)
            events = session.scalars(
                select(Event).where(Event.execution_id == execution.id).order_by(Event.sequence)
            ).all()
            published = [event_dict(event) for event in events]
            execution_id = execution.id
            start_command_id = start_command.id
            self._publish(execution_id, published)
        self._admit_operator_bundle(
            execution_id,
            procedure,
            automatic=True,
            background_allowed=background_allowed,
            visible=visible,
            catalog_revision_id=catalog_revision_id,
            predecessor_execution_id=predecessor_execution_id,
            depth=depth,
            ownership_mode=ownership_mode,
            operator_settings=operator_settings,
        )
        try:
            handle = self._spawn_worker(execution_id, start_command_id)
            self._arm_command_watchdog(execution_id, start_command_id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"worker startup failed: {exc}",
                expected_handle=locals().get("handle"),
            )
        return self.get_execution(execution_id)

    def get_execution(self, execution_id: str) -> Execution:
        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            session.expunge(execution)
            return execution

    def list_executions(self, limit: int = 100) -> list[Execution]:
        with self.session_factory() as session:
            items = session.scalars(
                select(Execution).order_by(Execution.created_at.desc()).limit(limit)
            ).all()
            for item in items:
                session.expunge(item)
            return list(items)

    def reconcile_orphaned_executions(self) -> None:
        """Mark persisted active executions recoverable after a control-plane restart."""
        with self.session_factory() as session:
            active_rows = list(
                session.execute(
                    select(Execution.id, Execution.state).where(
                        Execution.state.in_(ACTIVE_STATES)
                    )
                ).all()
            )
            abort_commands: dict[str, tuple[str, str]] = {}
            for execution_id, state in active_rows:
                if state != "aborting":
                    continue
                command = session.scalar(
                    select(OperatorCommand)
                    .where(
                        OperatorCommand.execution_id == execution_id,
                        OperatorCommand.command_type.in_(["ABORT", "STOP"]),
                        OperatorCommand.state.in_(
                            [
                                "ACCEPTED",
                                "WAITING_SAFE_POINT",
                                "APPLYING",
                                "RECONCILING",
                            ]
                        ),
                    )
                    .order_by(OperatorCommand.updated_at.desc())
                    .limit(1)
                )
                if command is not None:
                    abort_commands[execution_id] = (
                        command.id,
                        command.effect_certainty_before,
                    )
            operator_commands: dict[str, dict[str, Any]] = {}
            for command in session.scalars(
                select(OperatorCommand)
                .where(
                    OperatorCommand.state.in_(
                        ["ACCEPTED", "WAITING_SAFE_POINT", "APPLYING"]
                    )
                )
                .order_by(OperatorCommand.created_at, OperatorCommand.id)
            ).all():
                operator_commands.setdefault(
                    command.execution_id, operator_command_dict(command)
                )
            successor_preparations: list[tuple[str, str, bool]] = []
            for successor in session.scalars(
                select(Execution).where(
                    Execution.creation_idempotency_key.like("v06-successor:%"),
                    Execution.state.in_(["created", "recovering"]),
                )
            ).all():
                parent_command_id = successor.creation_idempotency_key.removeprefix(
                    "v06-successor:"
                )
                parent_command = session.get(OperatorCommand, parent_command_id)
                if (
                    parent_command is not None
                    and parent_command.state == "SETTLED"
                    and parent_command.command_type in {"RELOAD", "RECOVER"}
                ):
                    successor_preparations.append(
                        (
                            successor.id,
                            parent_command.id,
                            parent_command.command_type == "RECOVER",
                        )
                    )
        active_states = dict(active_rows)
        resumed_operator_commands: set[str] = set()
        for execution_id, command in operator_commands.items():
            command_type = str(command.get("type", "")).upper()
            if command_type in {"RELOAD", "RECOVER"}:
                self._apply_successor_operator_command(
                    command, asynchronous_prepare=False
                )
                continue
            if command_type in {"ABORT", "STOP"}:
                continue
            state = active_states.get(execution_id)
            if state is None:
                continue
            if (
                command.get("state") == "APPLYING"
                and command_type in {"STEP", "STEP_OVER"}
            ):
                reconcile = getattr(
                    self.operator_service,
                    "reconcile_operator_command_application",
                    None,
                )
                if reconcile is None:
                    raise ConflictError(
                        "operator command application reconciliation is unavailable"
                    )
                command = reconcile(command["id"])
                if command.get("state") != "APPLYING":
                    continue
            self.append_event(
                execution_id,
                "supervisor.restart_detected",
                {
                    "action": "replay_operator_application",
                    "operator_command_id": command["id"],
                    "operator_command_revision": command.get("revision"),
                },
                source="supervisor",
                severity="warning",
            )
            self._resume_operator_worker_application(
                execution_id, command, state
            )
            resumed_operator_commands.add(execution_id)
        managed_successors: set[str] = set()
        for successor_id, parent_command_id, recover in successor_preparations:
            self._prepare_successor_execution(
                successor_id, parent_command_id, recover
            )
            managed_successors.add(successor_id)
        for execution_id, _state in active_rows:
            if (
                execution_id in resumed_operator_commands
                or execution_id in managed_successors
            ):
                continue
            cleanup = abort_commands.get(execution_id)
            if cleanup is not None:
                self.append_event(
                    execution_id,
                    "supervisor.restart_detected",
                    {"action": "resume_blocking_child_cleanup"},
                    source="supervisor",
                    severity="warning",
                )
                self._start_abort_cleanup_barrier(
                    execution_id,
                    cleanup[0],
                    effect_certainty=cleanup[1],
                )
                continue
            self.append_event(
                execution_id,
                "supervisor.restart_detected",
                {"action": "recovery_required"},
                source="supervisor",
                severity="warning",
            )
            self._set_state(
                execution_id,
                "recovery_required",
                source="supervisor",
                preserve_open_prompts=True,
                pending_command_error="supervisor restarted before command completion",
            )
        with self.session_factory() as session:
            settled_execution_ids = list(
                session.scalars(
                    select(Execution.id)
                    .join(Command, Command.execution_id == Execution.id)
                    .where(
                        Execution.state.in_(TERMINAL_STATES | {"recovery_required"}),
                        Command.status == "accepted",
                    )
                    .distinct()
                ).all()
            )
            settled_states = {
                execution_id: session.get(Execution, execution_id).state
                for execution_id in settled_execution_ids
            }
        for execution_id, state in settled_states.items():
            self._set_state(
                execution_id,
                state,
                source="supervisor",
                preserve_open_prompts=state == "recovery_required",
                pending_command_error="supervisor restarted before command completion",
            )

    def _resume_operator_worker_application(
        self,
        execution_id: str,
        operator_command: dict[str, Any],
        previous_state: str,
    ) -> None:
        with self._lock:
            live = self._workers.get(execution_id)
            if live is not None and live.process.is_alive():
                return
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id, with_for_update=True)
            if execution is None or execution.state in TERMINAL_STATES:
                return
            replay_generation = execution.worker_generation + 1
            idempotency_key = (
                f"v06-operator-replay:{operator_command['id']}:{replay_generation}"
            )
            command = session.scalar(
                select(Command).where(
                    Command.execution_id == execution_id,
                    Command.idempotency_key == idempotency_key,
                )
            )
            if command is None:
                correlation_id = str(uuid.uuid4())
                command = Command(
                    execution_id=execution_id,
                    command_type="recover",
                    idempotency_key=idempotency_key,
                    expected_revision=execution.revision,
                    actor="operator-runtime",
                    role="admin",
                    reason="Replay a reserved v0.6 operator application",
                    correlation_id=correlation_id,
                    request_payload={
                        "operator_command_id": operator_command["id"],
                        "operator_command_revision": operator_command.get("revision"),
                    },
                )
                session.add(command)
                prior = execution.state
                execution.state = "recovering"
                execution.revision += 1
                session.flush()
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            "command.accepted",
                            {"command": command_dict(command)},
                            source="operator-runtime",
                            correlation_id=correlation_id,
                            causation_id=command.id,
                        )
                    )
                )
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            "execution.state_changed",
                            {
                                "previous": prior,
                                "state": "recovering",
                                "revision": execution.revision,
                                "operator_command_id": operator_command["id"],
                            },
                            source="operator-runtime",
                            correlation_id=correlation_id,
                            causation_id=command.id,
                        )
                    )
                )
                session.commit()
            elif command.status != "accepted":
                return
            command_id = command.id
        if published:
            self._publish(execution_id, published)
        command_type = str(operator_command.get("type", "")).upper()
        resume_paused = command_type in {"STEP", "STEP_OVER", "SKIP", "GOTO"} or (
            command_type == "RUN"
            and previous_state in {"paused", "prompting", "waiting"}
        )
        initial_controls = None
        if resume_paused:
            with self._lock:
                self._recovery_pause_pending.add(execution_id)
            initial_controls = [
                {
                    "type": "pause",
                    "command_id": f"operator-recovery-pause:{operator_command['id']}",
                }
            ]
        try:
            handle = self._spawn_worker(
                execution_id,
                command_id,
                initial_controls=initial_controls,
            )
            self._arm_command_watchdog(execution_id, command_id, handle)
        except Exception as exc:
            with self._lock:
                self._recovery_pause_pending.discard(execution_id)
            self._recover_dispatch_failure(
                execution_id,
                f"operator application recovery failed: {exc}",
                expected_handle=locals().get("handle"),
            )

    def snapshot(self, execution_id: str) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            events = session.scalars(
                select(Event)
                .where(Event.execution_id == execution_id)
                .order_by(Event.sequence.desc())
                .limit(200)
            ).all()
            events.reverse()
            prompts = session.scalars(
                select(Prompt)
                .where(Prompt.execution_id == execution_id)
                .order_by(Prompt.created_at.desc())
            ).all()
            commands = session.scalars(
                select(Command)
                .where(Command.execution_id == execution_id)
                .order_by(Command.created_at.desc())
                .limit(50)
            ).all()
            serialized_events = [event_dict(item) for item in events]
            data = execution_dict(execution)
            data.update(
                {
                    "current_step_id": execution.current_step,
                    "current_line": (
                        execution.steps[execution.current_step]["line"]
                        if execution.current_step < execution.total_steps
                        else None
                    ),
                    "steps": execution.steps,
                    "source": execution.procedure_source,
                }
            )
            return {
                "execution": data,
                "telemetry": [
                    item for item in serialized_events if item["event_type"] == "telemetry.sample"
                ],
                "events": serialized_events,
                "logs": [
                    item for item in serialized_events if item["event_type"] == "procedure.log"
                ],
                "commands": [command_dict(item) for item in commands],
                "active_prompt": next(
                    (prompt_dict(item) for item in prompts if item.status == "open"), None
                ),
                "last_sequence": execution.next_sequence - 1,
            }

    def issue_command(
        self,
        execution_id: str,
        command_type: str,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
        role: str,
        reason: str,
        correlation_id: str | None,
        payload: dict[str, Any],
    ) -> Command:
        if role not in {"operator", "admin"}:
            raise AuthorizationError("operator role required")
        if command_type == "simulate_crash" and role != "admin":
            raise AuthorizationError("admin role required for simulated crash")
        if command_type not in {"start", "pause", "resume", "abort", "recover", "simulate_crash"}:
            raise ConflictError(f"unsupported command: {command_type}")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ConflictError("idempotency key is required and must not exceed 200 characters")
        if not reason.strip():
            raise ConflictError("a command reason is required")

        request_hash = canonical_hash(
            {
                "command_type": command_type,
                "expected_revision": expected_revision,
                "actor": actor,
                "reason": reason,
                "correlation_id": correlation_id,
                "payload": payload,
            }
        )
        published: list[dict[str, Any]] = []

        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            existing = session.scalar(
                select(Command).where(
                    Command.execution_id == execution_id,
                    Command.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_payload.get("_request_hash") != request_hash:
                    raise ConflictError("idempotency key was used for another command request")
                session.expunge(existing)
                return existing
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            if execution.revision != expected_revision:
                raise ConflictError(
                    f"revision mismatch: expected {expected_revision}, current {execution.revision}"
                )
            self._validate_transition(execution.state, command_type)
            state_before = execution.state
            command = Command(
                execution_id=execution_id,
                command_type=command_type,
                idempotency_key=idempotency_key,
                expected_revision=expected_revision,
                actor=actor,
                role=role,
                reason=reason,
                correlation_id=correlation_id or str(uuid.uuid4()),
                request_payload={"request": payload, "_request_hash": request_hash},
            )
            session.add(command)
            execution.revision += 1
            intermediate = {
                "start": "starting",
                "pause": "pausing",
                "resume": "resuming",
                "abort": "aborting",
                "recover": "recovering",
                "simulate_crash": execution.state,
            }[command_type]
            execution.state = intermediate
            session.flush()
            accepted = self._add_event(
                session,
                execution,
                "command.accepted",
                {"command": command_dict(command)},
                source="api",
                correlation_id=command.correlation_id,
                causation_id=command.id,
            )
            state_event = None
            if state_before != intermediate:
                state_event = self._add_event(
                    session,
                    execution,
                    "execution.state_changed",
                    {
                        "previous": state_before,
                        "state": intermediate,
                        "revision": execution.revision,
                    },
                    source="api",
                    correlation_id=command.correlation_id,
                    causation_id=command.id,
                )
            session.commit()
            session.refresh(command)
            published = [event_dict(accepted)]
            if state_event is not None:
                published.append(event_dict(state_event))
            session.expunge(command)
            self._publish(execution_id, published)
        try:
            if command_type in {"start", "recover"}:
                handle = self._spawn_worker(execution_id, command.id)
                self._arm_command_watchdog(execution_id, command.id, handle)
            elif command_type == "simulate_crash":
                with self._lock:
                    handle = self._workers.get(execution_id)
                self._simulate_crash(execution_id, command.id, expected_handle=handle)
            elif command_type == "abort" and state_before == "recovery_required":
                self._set_state(
                    execution_id, "aborted", source="supervisor", command_id=command.id
                )
            else:
                with self._lock:
                    if self._closed:
                        raise RuntimeError("supervisor is closed")
                    handle = self._workers.get(execution_id)
                if handle is None:
                    raise RuntimeError("worker is unavailable")
                with getattr(handle, "dispatch_lock", nullcontext()):
                    with self._lock:
                        current = (
                            not self._closed
                            and not handle.intentional_stop
                            and self._workers.get(execution_id) is handle
                        )
                    if not current or not handle.process.is_alive():
                        raise RuntimeError("worker is unavailable")
                    handle.control.put(
                        {"type": command_type, "command_id": command.id, **payload}
                    )
                    self._arm_command_watchdog(execution_id, command.id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"command dispatch failed: {exc}",
                expected_handle=locals().get("handle"),
            )
        return command

    def respond_to_prompt(
        self,
        prompt_id: str,
        response: str,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
        role: str,
        reason: str,
        correlation_id: str | None,
    ) -> Command:
        if role not in {"operator", "admin"}:
            raise AuthorizationError("operator role required")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ConflictError(
                "idempotency key is required and must not exceed 200 characters"
            )
        request_hash = canonical_hash(
            {
                "prompt_id": prompt_id,
                "response": response,
                "expected_revision": expected_revision,
                "actor": actor,
                "reason": reason,
                "correlation_id": correlation_id,
            }
        )
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            prompt = session.get(Prompt, prompt_id)
            if prompt is None:
                raise NotFoundError("prompt not found")
            existing = session.scalar(
                select(Command).where(
                    Command.execution_id == prompt.execution_id,
                    Command.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_payload.get("_request_hash") != request_hash:
                    raise ConflictError("idempotency key was used for another prompt response")
                session.expunge(existing)
                return existing
            execution = session.get(Execution, prompt.execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            if execution.revision != expected_revision:
                raise ConflictError(
                    f"revision mismatch: expected {expected_revision}, current {execution.revision}"
                )
            if execution.state != "prompting" or prompt.status != "open":
                raise ConflictError("prompt is not open")
            if response not in prompt.choices:
                raise ConflictError("response must be one of the prompt choices")
            if not reason.strip():
                raise ConflictError("a response reason is required")
            command = Command(
                execution_id=execution.id,
                command_type="prompt_response",
                idempotency_key=idempotency_key,
                expected_revision=expected_revision,
                actor=actor,
                role=role,
                reason=reason,
                correlation_id=correlation_id or str(uuid.uuid4()),
                request_payload={
                    "prompt_id": prompt_id,
                    "response": response,
                    "_request_hash": request_hash,
                },
            )
            session.add(command)
            execution.revision += 1
            prompt.status = "responding"
            prompt.response = response
            prompt.responded_by = actor
            prompt.responded_at = datetime.now(timezone.utc)
            session.flush()
            accepted = self._add_event(
                session,
                execution,
                "command.accepted",
                {"command": command_dict(command)},
                source="api",
                correlation_id=command.correlation_id,
                causation_id=command.id,
            )
            reserved = self._add_event(
                session,
                execution,
                "prompt.response_reserved",
                {"prompt_id": prompt.id, "response": response, "revision": execution.revision},
                source="api",
                correlation_id=command.correlation_id,
                causation_id=command.id,
            )
            session.commit()
            session.refresh(command)
            published = [event_dict(accepted), event_dict(reserved)]
            session.expunge(command)
            execution_id = command.execution_id
            self._publish(execution_id, published)
        try:
            with self._lock:
                if self._closed:
                    raise RuntimeError("supervisor is closed")
                handle = self._workers.get(execution_id)
            if handle is None:
                raise RuntimeError("worker is unavailable")
            with getattr(handle, "dispatch_lock", nullcontext()):
                with self._lock:
                    current = (
                        not self._closed
                        and not handle.intentional_stop
                        and self._workers.get(execution_id) is handle
                    )
                if not current or not handle.process.is_alive():
                    raise RuntimeError("worker is unavailable")
                handle.control.put(
                    {
                        "type": "prompt_response",
                        "command_id": command.id,
                        "prompt_id": prompt_id,
                        "response": response,
                    }
                )
                self._arm_command_watchdog(execution_id, command.id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"prompt dispatch failed: {exc}",
                expected_handle=locals().get("handle"),
            )
        return command

    def dispatch_operator_command(self, command: dict[str, Any]) -> dict[str, Any]:
        """Dispatch one already accepted durable v0.6 command to its safe point."""

        service = self.operator_service
        if service is None:
            raise ConflictError("v0.6 operator service is not attached")
        if command.get("state") != "ACCEPTED":
            return command
        command_id = command.get("id")
        execution_id = command.get("execution_id")
        command_type = command.get("type")
        if not all(type(value) is str and value for value in (command_id, execution_id, command_type)):
            raise ConflictError("operator command identity is invalid")
        command_type = command_type.upper()
        if command_type == "KILL":
            raise ConflictError("KILL_UNSUPPORTED")
        if command_type in {"RELOAD", "RECOVER"}:
            return self._apply_successor_operator_command(command)
        command = service.transition_operator_command(
            command_id, "WAITING_SAFE_POINT"
        )
        lifecycle_claimed = False

        def apply_without_worker() -> dict[str, Any]:
            if command_type in {"ABORT", "STOP"}:
                projection = service.get_execution_projection(execution_id)
                applying = self._begin_operator_command_application(
                    command, projection.get("current_safe_point_id")
                )
                if applying.get("state") != "APPLYING":
                    return applying
                self._set_state(
                    execution_id,
                    "aborting",
                    source="operator-runtime",
                    command_id=None,
                )
                return self._start_abort_cleanup_barrier(
                    execution_id,
                    command_id,
                    effect_certainty=applying.get(
                        "effect_certainty_before", "NO_EFFECT"
                    ),
                )
            return service.transition_operator_command(
                command_id,
                "FAILED",
                result={"error": "worker is unavailable"},
                rejection_code="WORKER_UNAVAILABLE",
            )

        with self._lock:
            if self._closed:
                raise ConflictError("supervisor is closed")
            handle = self._workers.get(execution_id)
            spawning = getattr(self, "_spawning", set())
            if handle is None:
                if execution_id in spawning:
                    return command
                spawning.add(execution_id)
                self._spawning = spawning
                lifecycle_claimed = True
        if handle is None:
            try:
                return apply_without_worker()
            finally:
                if lifecycle_claimed:
                    with self._lock:
                        self._spawning.discard(execution_id)

        with getattr(handle, "dispatch_lock", nullcontext()):
            with self._lock:
                if (
                    self._closed
                    or getattr(handle, "intentional_stop", False)
                    or self._workers.get(execution_id) is not handle
                ):
                    return command
            try:
                alive = handle.process.is_alive()
            except (AssertionError, AttributeError, OSError, ValueError):
                alive = False
            if not alive:
                with self._lock:
                    spawning = getattr(self, "_spawning", set())
                    if execution_id in spawning:
                        return command
                    spawning.add(execution_id)
                    self._spawning = spawning
                    lifecycle_claimed = True
                try:
                    if not self._invalidate_worker(execution_id):
                        return command
                    return apply_without_worker()
                finally:
                    with self._lock:
                        self._spawning.discard(execution_id)
            projection = service.get_execution_projection(execution_id)
            if projection.get("state") in {
                "PAUSED",
                "WAITING",
                "PROMPT",
                "INTERRUPTED",
            }:
                return self._queue_operator_command_at_safe_point(
                    command,
                    handle,
                    projection.get("current_safe_point_id"),
                )
            return command

    def _apply_successor_operator_command(
        self,
        command: dict[str, Any],
        *,
        asynchronous_prepare: bool = True,
    ) -> dict[str, Any]:
        service = self.operator_service
        if service is None:
            raise ConflictError("v0.6 operator service is not attached")
        command_id = command.get("id")
        execution_id = command.get("execution_id")
        command_type = str(command.get("type", "")).upper()
        if (
            type(command_id) is not str
            or type(execution_id) is not str
            or command_type not in {"RELOAD", "RECOVER"}
        ):
            raise ConflictError("successor command identity is invalid")
        if command.get("state") != "APPLYING":
            projection = service.get_execution_projection(execution_id)
            command = self._begin_operator_command_application(
                command, projection.get("current_safe_point_id")
            )
        if command.get("state") != "APPLYING":
            return command
        try:
            successor = self._create_successor_execution(
                execution_id,
                command_id=command_id,
                actor=command.get("actor", "operator-runtime"),
                reason=command.get("reason", command_type.title()),
                recover=command_type == "RECOVER",
            )
        except Exception:
            return service.transition_operator_command(
                command_id,
                "FAILED",
                result={
                    "code": "SUCCESSOR_CREATION_FAILED",
                    "target_mutation": "UNKNOWN",
                },
                rejection_code="SUCCESSOR_CREATION_FAILED",
                effect_certainty="EFFECT_UNKNOWN",
            )
        settle = getattr(service, "settle_operator_command_application", None)
        if settle is None:
            raise ConflictError("operator command application settlement is unavailable")
        settled_command = settle(
            command_id,
            result={
                "predecessor_execution_id": execution_id,
                "execution_id": successor.id,
                "state": "REQUESTED",
            },
            application_safe_point_id=command.get("application_safe_point_id"),
            effect_certainty=command.get("effect_certainty_before", "NO_EFFECT"),
        )
        prepare = lambda: self._prepare_successor_execution(
            successor.id, command_id, command_type == "RECOVER"
        )
        if asynchronous_prepare:
            threading.Thread(target=prepare, daemon=True).start()
        else:
            prepare()
        return settled_command

    def _begin_operator_command_application(
        self,
        command: dict[str, Any],
        safe_point_id: str | None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        service = self.operator_service
        begin = getattr(service, "begin_operator_command_application", None)
        if begin is None:
            raise ConflictError(
                "operator command application fence service is unavailable"
            )
        if worker_generation is None:
            return begin(command["id"], safe_point_id)
        return begin(
            command["id"], safe_point_id, worker_generation=worker_generation
        )

    @staticmethod
    def _operator_command_message(command: dict[str, Any]) -> dict[str, Any]:
        command_id = command.get("id")
        command_type = command.get("type")
        if type(command_id) is not str or not command_id:
            raise ConflictError("operator command identity is invalid")
        if type(command_type) is not str:
            raise ConflictError("operator command type is invalid")
        command_type = command_type.upper()
        if command_type not in {
            "RUN",
            "STEP",
            "STEP_OVER",
            "PAUSE",
            "SKIP",
            "GOTO",
            "BACKGROUND",
            "STOP",
            "ABORT",
        }:
            raise ConflictError("operator command type is not worker-dispatchable")
        message = {
            "type": command_type.lower(),
            "command_id": command_id,
            "operator_application_safe_point_id": command.get(
                "application_safe_point_id"
            ),
        }
        if command_type == "GOTO":
            target = command.get("target")
            target_step = target.get("target_step") if type(target) is dict else None
            if type(target_step) is not int or target_step < 0:
                raise ConflictError("operator command target is invalid")
            message["target_step"] = target_step
        return message

    def _queue_operator_command_at_safe_point(
        self,
        command: dict[str, Any],
        handle: WorkerHandle,
        safe_point_id: str | None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        if (
            command.get("state") == "APPLYING"
            and str(command.get("type", "")).upper() in {"STEP", "STEP_OVER"}
        ):
            reconcile = getattr(
                self.operator_service,
                "reconcile_operator_command_application",
                None,
            )
            if reconcile is None:
                raise ConflictError(
                    "operator command application reconciliation is unavailable"
                )
            command = reconcile(command["id"])
            if command.get("state") != "APPLYING":
                return command
        command = self._begin_operator_command_application(
            command,
            safe_point_id,
            worker_generation=worker_generation,
        )
        if command.get("state") != "APPLYING":
            return command
        revision = command.get("revision", 0)
        if type(revision) is not int:
            raise ConflictError("operator command delivery revision is invalid")
        if not self._delivery_attempt_is_due(
            "operator_command", command["id"], revision
        ):
            return command
        handle.control.put(self._operator_command_message(command))
        return command

    def _waiting_operator_command(
        self, execution_id: str
    ) -> dict[str, Any] | None:
        with self.session_factory() as session:
            command = session.scalar(
                select(OperatorCommand)
                .where(
                    OperatorCommand.execution_id == execution_id,
                    OperatorCommand.state.in_(
                        ["ACCEPTED", "WAITING_SAFE_POINT", "APPLYING"]
                    ),
                )
                .order_by(OperatorCommand.created_at, OperatorCommand.id)
                .limit(1)
            )
            return operator_command_dict(command) if command is not None else None

    def _replay_operator_command_deliveries(self) -> set[str]:
        service = self.operator_service
        if service is None:
            return set()
        with self.session_factory() as session:
            commands = session.scalars(
                select(OperatorCommand)
                .where(
                    OperatorCommand.state.in_(
                        ["ACCEPTED", "WAITING_SAFE_POINT", "APPLYING"]
                    )
                )
                .order_by(OperatorCommand.created_at, OperatorCommand.id)
            ).all()
            pending = [operator_command_dict(command) for command in commands]
        reserved: set[str] = set()
        for command in pending:
            execution_id = command.get("execution_id")
            if type(execution_id) is not str or execution_id in reserved:
                continue
            projection = service.get_execution_projection(execution_id)
            if projection.get("state") not in {
                "PAUSED",
                "WAITING",
                "PROMPT",
                "INTERRUPTED",
            }:
                continue
            safe_point_id = projection.get("current_safe_point_id")
            if type(safe_point_id) is not str or not safe_point_id:
                continue
            with self._lock:
                handle = self._workers.get(execution_id)
            if handle is None or not handle.process.is_alive():
                continue
            result = self._queue_operator_command_at_safe_point(
                command, handle, safe_point_id
            )
            if result.get("state") == "APPLYING":
                reserved.add(execution_id)
        return reserved

    def dispatch_prompt_settlement(self, result: dict[str, Any]) -> None:
        """Publish the immutable durable prompt winner to its worker once."""

        prompt = result.get("prompt") or {}
        settlement = prompt.get("settlement") or {}
        prompt_id = prompt.get("id")
        execution_id = prompt.get("execution_id")
        if not all(type(value) is str and value for value in (prompt_id, execution_id)):
            raise ConflictError("prompt settlement identity is invalid")
        if not settlement:
            return
        settlement_id = settlement.get("id")
        if type(settlement_id) is not str:
            raise ConflictError("prompt settlement identity is invalid")
        with self._lock:
            attempted_at = self._prompt_settlement_attempts.get(settlement_id)
            now = time.monotonic()
            if attempted_at is not None and now - attempted_at < 0.1:
                return
            handle = self._workers.get(execution_id)
        if handle is None or not handle.process.is_alive():
            raise ConflictError("prompt worker is unavailable; delivery remains pending")
        with self._lock:
            attempted_at = self._prompt_settlement_attempts.get(settlement_id)
            now = time.monotonic()
            if attempted_at is not None and now - attempted_at < 0.1:
                return
            self._prompt_settlement_attempts[settlement_id] = now
        handle.control.put(
            {
                "type": "prompt_settlement",
                "command_id": (result.get("attempt") or {}).get("id"),
                "prompt_id": prompt_id,
                "settlement_id": settlement_id,
                "outcome": settlement.get("outcome"),
                "value": settlement.get("value"),
            }
        )

    def dispatch_user_action(
        self,
        execution_id: str,
        invocation_id: str,
        handler: list[dict[str, Any]],
        delivery_revision: int = 0,
        *,
        safe_point_id: str | None = None,
        handle: WorkerHandle | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any] | None:
        service = self.operator_service
        begin = getattr(service, "begin_user_action_application", None)
        if begin is None:
            raise ConflictError("user action application fence service is unavailable")
        if safe_point_id is None:
            projection = service.get_execution_projection(execution_id)
            if projection.get("state") not in {
                "PAUSED",
                "WAITING",
                "PROMPT",
                "INTERRUPTED",
            }:
                return None
            safe_point_id = projection.get("current_safe_point_id")
        if type(safe_point_id) is not str or not safe_point_id:
            return None
        invocation = (
            begin(invocation_id, safe_point_id)
            if worker_generation is None
            else begin(
                invocation_id,
                safe_point_id,
                worker_generation=worker_generation,
            )
        )
        if invocation.get("state") != "APPLYING":
            return invocation
        pinned_handler = invocation.get("pinned_handler")
        if isinstance(pinned_handler, list):
            handler = pinned_handler
        delivery_revision = invocation.get("delivery_revision", delivery_revision)
        if type(delivery_revision) is not int:
            raise ConflictError("user action delivery revision is invalid")
        if not self._delivery_attempt_is_due(
            "user_action", invocation_id, delivery_revision
        ):
            return invocation
        supplied_handle = handle is not None
        if handle is None:
            with self._lock:
                handle = self._workers.get(execution_id)
        if handle is None or (
            not supplied_handle and not handle.process.is_alive()
        ):
            raise ConflictError("worker is unavailable")
        handle.control.put(
            {
                "type": "user_action",
                "invocation_id": invocation_id,
                "handler": handler,
                "delivery_revision": delivery_revision,
            }
        )
        mark_attempt = getattr(service, "mark_user_action_delivery_attempt", None)
        if mark_attempt is not None:
            if worker_generation is None:
                mark_attempt(invocation_id)
            else:
                mark_attempt(
                    invocation_id, worker_generation=worker_generation
                )
        return invocation

    def _delivery_attempt_is_due(
        self, kind: str, identity: str, revision: int
    ) -> bool:
        key = (kind, identity, revision)
        now = time.monotonic()
        with self._lock:
            previous = self._durable_delivery_attempts.get(key)
            if previous is not None and now - previous < 0.25:
                return False
            self._durable_delivery_attempts[key] = now
        return True

    def _replay_user_action_deliveries(
        self,
        execution_id: str | None = None,
        *,
        safe_point_id: str | None = None,
        handle: WorkerHandle | None = None,
        skip_execution_ids: set[str] | None = None,
        worker_generation: int | None = None,
    ) -> set[str]:
        service = self.operator_service
        list_pending = getattr(
            service, "list_replayable_user_action_invocations", None
        )
        if list_pending is None:
            return set()
        reserved = set(skip_execution_ids or ())
        pending = (
            list_pending(execution_id)
            if execution_id is not None
            else list_pending()
        )
        for invocation in pending:
            invocation_id = invocation.get("id")
            invocation_execution_id = invocation.get("execution_id")
            revision = invocation.get("delivery_revision", 0)
            if (
                type(invocation_id) is not str
                or type(invocation_execution_id) is not str
                or type(revision) is not int
                or invocation_execution_id in reserved
            ):
                continue
            handler = invocation.get("pinned_handler")
            if not isinstance(handler, list):
                handler = invocation.get("handler")
            if not isinstance(handler, list):
                definition = invocation.get("definition") or {}
                handler = definition.get("handler")
            if not isinstance(handler, list):
                action_id = invocation.get("action_id")
                action_revision = invocation.get("action_revision")
                action = next(
                    (
                        item
                        for item in service.list_user_actions(
                            invocation_execution_id
                        )
                        if item.get("id") == action_id
                        and item.get("revision") == action_revision
                    ),
                    None,
                )
                handler = (
                    (action.get("definition") or {}).get("handler")
                    if action is not None
                    else None
                )
            if not isinstance(handler, list):
                raise ConflictError(
                    "pending user action has no pinned handler definition"
                )
            try:
                result = self.dispatch_user_action(
                    invocation_execution_id,
                    invocation_id,
                    handler,
                    delivery_revision=revision,
                    safe_point_id=safe_point_id,
                    handle=handle,
                    worker_generation=worker_generation,
                )
            except ConflictError:
                continue
            if result is not None and result.get("state") == "APPLYING":
                reserved.add(invocation_execution_id)
        return reserved

    def _deliver_startproc_result(
        self,
        parent_execution_id: str,
        operation: dict[str, Any],
        *,
        handle: WorkerHandle | None = None,
    ) -> bool:
        startproc_id = operation.get("id")
        revision = operation.get("revision", 0)
        if type(startproc_id) is not str or type(revision) is not int:
            raise ConflictError("StartProc delivery identity is invalid")
        if not self._delivery_attempt_is_due("startproc", startproc_id, revision):
            return
        supplied_handle = handle is not None
        if handle is None:
            with self._lock:
                handle = self._workers.get(parent_execution_id)
        if handle is None or (
            not supplied_handle and not handle.process.is_alive()
        ):
            raise ConflictError("StartProc parent worker is unavailable")
        state = operation.get("state")
        handle.control.put(
            {
                "type": "startproc_result",
                "startproc_id": startproc_id,
                "delivery_revision": revision,
                "outcome": "SETTLED" if state == "SETTLED" else "REJECTED",
                "child_execution_id": operation.get("child_execution_id"),
                "rejection_code": operation.get("rejection_code"),
                "result": operation.get("result", {}),
            }
        )
        service = self.operator_service
        mark_attempt = getattr(
            service, "mark_startproc_result_delivery_attempt", None
        )
        if mark_attempt is not None:
            mark_attempt(startproc_id, revision)

    def _replay_startproc_deliveries(self) -> None:
        service = self.operator_service
        list_pending = getattr(service, "list_unacked_startproc_results", None)
        if list_pending is None:
            return False
        for operation in list_pending():
            parent_execution_id = operation.get("parent_execution_id")
            if type(parent_execution_id) is not str:
                continue
            try:
                self._deliver_startproc_result(parent_execution_id, operation)
            except ConflictError:
                continue

    def _replay_inspection_edit_deliveries(
        self,
        execution_id: str | None = None,
        *,
        safe_point_id: str | None = None,
        handle: WorkerHandle | None = None,
        skip_execution_ids: set[str] | None = None,
        worker_generation: int | None = None,
    ) -> set[str]:
        service = self.operator_service
        list_pending = getattr(service, "list_unacked_inspection_edits", None)
        if list_pending is None:
            return set()
        reserved = set(skip_execution_ids or ())
        pending = (
            list_pending(execution_id)
            if execution_id is not None
            else list_pending()
        )
        for edit in pending:
            edit_execution_id = edit.get("execution_id")
            if (
                type(edit_execution_id) is not str
                or edit_execution_id in reserved
            ):
                continue
            try:
                result = self.dispatch_inspection_edit(
                    edit,
                    safe_point_id=safe_point_id,
                    handle=handle,
                    worker_generation=worker_generation,
                )
            except ConflictError:
                continue
            if result is not None and result.get("state") == "APPLYING":
                reserved.add(edit_execution_id)
        return reserved

    def dispatch_inspection_edit(
        self,
        edit: dict[str, Any],
        *,
        safe_point_id: str | None = None,
        handle: WorkerHandle | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any] | None:
        service = self.operator_service
        edit_id = edit.get("id") or edit.get("edit_id")
        execution_id = edit.get("execution_id")
        revision = edit.get("delivery_revision", edit.get("revision", 0))
        variables = (
            edit.get("variables")
            if "variables" in edit
            else edit.get("authoritative_variables")
        )
        if (
            type(edit_id) is not str
            or type(execution_id) is not str
            or type(revision) is not int
            or type(variables) is not dict
        ):
            raise ConflictError("inspection edit delivery is invalid")
        begin = getattr(service, "begin_inspection_edit_application", None)
        if begin is None:
            raise ConflictError("inspection edit application fence service is unavailable")
        if safe_point_id is None:
            projection = service.get_execution_projection(execution_id)
            if projection.get("state") not in {
                "PAUSED",
                "WAITING",
                "PROMPT",
                "INTERRUPTED",
            }:
                return None
            safe_point_id = projection.get("current_safe_point_id")
        if type(safe_point_id) is not str or not safe_point_id:
            return None
        edit = (
            begin(edit_id, revision, safe_point_id)
            if worker_generation is None
            else begin(
                edit_id,
                revision,
                safe_point_id,
                worker_generation=worker_generation,
            )
        )
        if edit.get("state") != "APPLYING":
            return edit
        variables = (
            edit.get("variables")
            if "variables" in edit
            else edit.get("authoritative_variables")
        )
        if type(variables) is not dict:
            raise ConflictError("inspection edit authoritative variables are invalid")
        if not self._delivery_attempt_is_due("inspection_edit", edit_id, revision):
            return edit
        supplied_handle = handle is not None
        if handle is None:
            with self._lock:
                handle = self._workers.get(execution_id)
        if handle is None or (
            not supplied_handle and not handle.process.is_alive()
        ):
            raise ConflictError("inspection edit worker is unavailable")
        handle.control.put(
                {
                    "type": "inspection_edit",
                    "edit_id": edit_id,
                    "delivery_revision": revision,
                    "execution_revision": edit.get("execution_revision"),
                    "scope": edit.get("scope"),
                    "path": edit.get("path"),
                    "declared_type": edit.get("type"),
                    "variables": variables,
                }
        )
        mark_attempt = getattr(service, "mark_inspection_edit_delivery_attempt", None)
        if mark_attempt is not None:
            if worker_generation is None:
                mark_attempt(edit_id, revision)
            else:
                mark_attempt(
                    edit_id,
                    revision,
                    worker_generation=worker_generation,
                )
        return edit

    def _replay_control_loss_deliveries(self) -> None:
        service = self.operator_service
        list_pending = getattr(service, "list_pending_control_loss", None)
        if list_pending is None:
            return
        for loss in list_pending():
            self.dispatch_control_loss(loss)

    def _replay_control_loss_events(self) -> None:
        service = self.operator_service
        list_unpublished = getattr(
            service, "list_unpublished_control_loss_events", None
        )
        mark_published = getattr(
            service, "mark_control_loss_event_published", None
        )
        if list_unpublished is None or mark_published is None:
            return
        for event in list_unpublished():
            event_id = event.get("id")
            execution_id = event.get("execution_id")
            if type(event_id) is not str or type(execution_id) is not str:
                continue
            self.hub.publish(execution_id, event)
            mark_published(event_id)

    def dispatch_control_loss(self, loss: dict[str, Any]) -> None:
        service = self.operator_service
        execution_id = loss.get("execution_id")
        fencing_token = loss.get("fencing_token")
        delivery_id = loss.get("delivery_id") or (
            f"control-loss:{execution_id}:{fencing_token}"
            if type(execution_id) is str and type(fencing_token) is int
            else None
        )
        revision = loss.get("delivery_revision", fencing_token)
        if (
            type(execution_id) is not str
            or type(delivery_id) is not str
            or type(revision) is not int
        ):
            raise ConflictError("control-loss delivery is invalid")
        if not self._delivery_attempt_is_due("control_loss", delivery_id, revision):
            return
        no_worker_claim = False
        with self._lock:
            handle = self._workers.get(execution_id)
            spawning = getattr(self, "_spawning", set())
            if handle is None:
                if execution_id in spawning:
                    return
                spawning.add(execution_id)
                self._spawning = spawning
                no_worker_claim = True
        if no_worker_claim:
            try:
                self._set_state(
                    execution_id,
                    "recovery_required",
                    source="operator-runtime",
                    preserve_open_prompts=True,
                    pending_command_error="controller lease expired without a live worker",
                )
                acknowledge = getattr(service, "ack_control_loss_application", None)
                safe_point_id = service.get_execution_projection(execution_id).get(
                    "current_safe_point_id"
                )
                if acknowledge is not None and type(safe_point_id) is str:
                    acknowledge(execution_id, fencing_token, safe_point_id)
            finally:
                with self._lock:
                    self._spawning.discard(execution_id)
            return

        with getattr(handle, "dispatch_lock", nullcontext()):
            with self._lock:
                current = (
                    not self._closed
                    and not getattr(handle, "intentional_stop", False)
                    and self._workers.get(execution_id) is handle
                )
            if not current:
                return
            try:
                alive = handle.process.is_alive()
            except (AssertionError, AttributeError, OSError, ValueError):
                alive = False
            if not alive:
                self._recover_dispatch_failure(
                    execution_id,
                    "controller lease expired without a live worker",
                    expected_handle=handle,
                )
                return
            handle.control.put(
                {
                    "type": "control_loss",
                    "delivery_id": delivery_id,
                    "lease_id": loss.get("lease_id"),
                    "fencing_token": fencing_token,
                    "delivery_revision": revision,
                }
            )
        mark_attempt = getattr(service, "mark_control_loss_delivery_attempt", None)
        if mark_attempt is not None:
            mark_attempt(execution_id, delivery_id, revision)

    def _create_successor_execution(
        self,
        predecessor_id: str,
        *,
        command_id: str,
        actor: str,
        reason: str,
        recover: bool,
    ) -> Execution:
        predecessor_projection = (
            self.operator_service.get_execution_projection(predecessor_id)
            if self.operator_service is not None
            else {}
        )
        with self._lock, self.session_factory() as session:
            predecessor = session.get(Execution, predecessor_id)
            if predecessor is None:
                raise NotFoundError("predecessor execution not found")
            existing = session.scalar(
                select(Execution).where(
                    Execution.created_by == actor,
                    Execution.creation_idempotency_key == f"v06-successor:{command_id}",
                )
            )
            if existing is not None:
                successor = existing
            else:
                successor = Execution(
                    procedure_id=predecessor.procedure_id,
                    procedure_name=predecessor.procedure_name,
                    procedure_hash=predecessor.procedure_hash,
                    procedure_source=predecessor.procedure_source,
                    steps=predecessor.steps,
                    ir_version=predecessor.ir_version,
                    variables=dict(predecessor.variables) if recover else {},
                    total_steps=predecessor.total_steps,
                    current_step=predecessor.current_step if recover else 0,
                    context_id=predecessor.context_id,
                    created_by=actor,
                    creation_idempotency_key=f"v06-successor:{command_id}",
                    state="created",
                    revision=0,
                )
                session.add(successor)
                session.flush()
                self._add_event(
                    session,
                    successor,
                    "execution.created",
                    {
                        "procedure_id": successor.procedure_id,
                        "procedure_hash": successor.procedure_hash,
                        "predecessor_execution_id": predecessor_id,
                        "operator_command_id": command_id,
                        "recovery": recover,
                        "reason": reason,
                    },
                    source="operator-runtime",
                    causation_id=command_id,
                )
                session.commit()
            session.refresh(successor)
            successor_id = successor.id
            session.expunge(successor)
        if self.operator_service is not None:
            self.operator_service.ensure_execution_projection(
                successor_id,
                actor=actor,
                automatic=False,
                background_allowed=bool(
                    predecessor_projection.get("background_allowed", False)
                ),
                visible=bool(predecessor_projection.get("visible", True)),
                catalog_revision_id=predecessor_projection.get("catalog_revision_id"),
                predecessor_execution_id=predecessor_id,
                depth=int(predecessor_projection.get("depth", 0)),
                ownership_mode="CONTROL_LOST",
                settings=dict(predecessor_projection.get("settings") or {}),
                authoritative=True,
            )
        return successor

    def _prepare_successor_execution(
        self, execution_id: str, parent_command_id: str, recover: bool
    ) -> None:
        if not recover:
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                state = execution.state if execution is not None else None
            if state == "created":
                self._set_state(execution_id, "ready", source="operator-runtime")
            return
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id, with_for_update=True)
            if execution is None or execution.state in TERMINAL_STATES:
                return
            command = session.scalar(
                select(Command).where(
                    Command.execution_id == execution_id,
                    Command.idempotency_key == f"v06-recover:{parent_command_id}",
                )
            )
            if command is None:
                if execution.state != "created":
                    return
                correlation_id = str(uuid.uuid4())
                command = Command(
                    execution_id=execution_id,
                    command_type="recover",
                    idempotency_key=f"v06-recover:{parent_command_id}",
                    expected_revision=execution.revision,
                    actor="operator-runtime",
                    role="admin",
                    reason="Start compatible v0.6 recovery successor",
                    correlation_id=correlation_id,
                    request_payload={"predecessor_command_id": parent_command_id},
                )
                session.add(command)
                execution.state = "recovering"
                execution.revision += 1
                session.flush()
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            "command.accepted",
                            {"command": command_dict(command)},
                            source="operator-runtime",
                            correlation_id=correlation_id,
                            causation_id=command.id,
                        )
                    )
                )
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            "execution.state_changed",
                            {
                                "previous": "created",
                                "state": "recovering",
                                "revision": execution.revision,
                            },
                            source="operator-runtime",
                            correlation_id=correlation_id,
                            causation_id=command.id,
                        )
                    )
                )
            elif command.status != "accepted" or execution.state != "recovering":
                return
            session.commit()
            command_id = command.id
        if published:
            self._publish(execution_id, published)
        with self._lock:
            live = self._workers.get(execution_id)
            if live is not None and live.process.is_alive():
                return
        try:
            handle = self._spawn_worker(execution_id, command_id)
            self._arm_command_watchdog(execution_id, command_id, handle)
        except Exception as exc:
            self._recover_dispatch_failure(
                execution_id,
                f"recovery successor startup failed: {exc}",
                expected_handle=locals().get("handle"),
            )

    @staticmethod
    def _validate_transition(state: str, command_type: str) -> None:
        allowed = {
            "start": {"ready"},
            "pause": {"running"},
            "resume": {"paused"},
            "abort": ACTIVE_STATES
            | {
                "created",
                "validated",
                "ready",
                "recovery_required",
            },
            "recover": {"recovery_required"},
            "simulate_crash": {"running", "paused", "prompting"},
        }
        if state not in allowed[command_type]:
            raise ConflictError(f"cannot {command_type} while execution is {state}")

    def _spawn_worker(
        self,
        execution_id: str,
        command_id: str,
        *,
        initial_controls: list[dict[str, Any]] | None = None,
    ) -> WorkerHandle:
        with self._lock:
            spawning = getattr(self, "_spawning", None)
            if spawning is None:
                spawning = self._spawning = set()
            if execution_id in spawning:
                raise ConflictError("execution worker spawn is already in progress")
            previous_handle = self._workers.get(execution_id)
            spawning.add(execution_id)
        try:
            return self._spawn_worker_claimed(
                execution_id,
                command_id,
                initial_controls=initial_controls,
            )
        except Exception:
            with self._lock:
                partial_handle = self._workers.get(execution_id)
            if partial_handle is not None and partial_handle is not previous_handle:
                with partial_handle.dispatch_lock:
                    with self._lock:
                        current = self._workers.get(execution_id) is partial_handle
                    if current:
                        self._fence_worker_epoch(execution_id, partial_handle)
                        with self._lock:
                            if self._workers.get(execution_id) is partial_handle:
                                partial_handle.intentional_stop = True
                        if not self._terminate_worker(partial_handle):
                            raise RuntimeError(
                                "partially started worker could not be terminated"
                            )
                        self._cleanup_worker(execution_id, partial_handle)
            raise
        finally:
            with self._lock:
                self._spawning.discard(execution_id)

    def _spawn_worker_claimed(
        self,
        execution_id: str,
        command_id: str,
        *,
        initial_controls: list[dict[str, Any]] | None = None,
    ) -> WorkerHandle:
        while True:
            with self._lock:
                previous = self._workers.get(execution_id)
            if previous is None:
                break
            with previous.dispatch_lock:
                with self._lock:
                    if self._workers.get(execution_id) is not previous:
                        continue
                    if previous.process.is_alive():
                        raise ConflictError("execution already has a live worker")
                self._fence_worker_epoch(execution_id, previous)
                self._cleanup_worker(execution_id, previous)
                break
        with self._lock, self.session_factory() as session:
            if self._closed:
                raise ConflictError("supervisor is closed")
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise NotFoundError("execution not found")
            command = session.get(Command, command_id)
            expected_state = {
                "start": "starting",
                "recover": "recovering",
            }.get(command.command_type if command is not None else "")
            if (
                command is None
                or command.status != "accepted"
                or expected_state is None
                or execution.state != expected_state
            ):
                raise ConflictError("execution is no longer eligible to spawn a worker")
            previous = self._workers.get(execution_id)
            if previous is not None:
                raise ConflictError("execution already has a live worker")
            start_step = execution.current_step
            resume_prompts = session.scalars(
                select(Prompt).where(
                    Prompt.execution_id == execution_id,
                    Prompt.status == "open",
                ).limit(2)
            ).all()
            operator_resume_prompts = (
                session.scalars(
                    select(OperatorPrompt).where(
                        OperatorPrompt.execution_id == execution_id,
                        OperatorPrompt.state == "OPEN",
                    ).limit(2)
                ).all()
                if execution.ir_version in _V06_PLUS_IR_VERSIONS
                else []
            )
            settled_resume_prompt = (
                session.scalar(
                    select(OperatorPrompt)
                    .where(
                        OperatorPrompt.execution_id == execution_id,
                        OperatorPrompt.state == "SETTLED",
                        OperatorPrompt.step_index == execution.current_step,
                    )
                    .order_by(OperatorPrompt.settled_at.desc())
                    .limit(1)
                )
                if execution.ir_version in _V06_PLUS_IR_VERSIONS
                else None
            )
            all_resume_prompts = [*resume_prompts, *operator_resume_prompts]
            if not all_resume_prompts and settled_resume_prompt is not None:
                all_resume_prompts.append(settled_resume_prompt)
            resume_prompt = all_resume_prompts[0] if len(all_resume_prompts) == 1 else None
            resume_prompt_id = resume_prompt.id if resume_prompt is not None else None
            resume_prompt_settlement = (
                {
                    "prompt_id": settled_resume_prompt.id,
                    "settlement_id": settled_resume_prompt.settlement_id,
                    "outcome": settled_resume_prompt.settlement_outcome,
                    "response": settled_resume_prompt.settled_value,
                    "command_id": None,
                }
                if settled_resume_prompt is not None
                and resume_prompt is settled_resume_prompt
                else None
            )
            ir_version = execution.ir_version
            persisted_checkpoint = dict(execution.variables)
            durable_arguments = None
            runtime_checkpoint: dict[str, Any] = {}
            if ir_version in _V06_PLUS_IR_VERSIONS:
                durable_arguments = persisted_checkpoint.pop("ARGS", {})
                runtime_checkpoint = {
                    name: persisted_checkpoint.pop(name)
                    for name in ("GLOBALS", "IVARS", "SHARED_DATA")
                    if name in persisted_checkpoint
                }
                if not isinstance(durable_arguments, dict):
                    raise ConflictError("persisted ARGS container is invalid")
            try:
                if command.command_type == "start" and all_resume_prompts:
                    raise IRValidationError(
                        "$.resume_prompt_id",
                        "initial start cannot have an open prompt record",
                    )
                if len(all_resume_prompts) > 1:
                    raise IRValidationError(
                        "$.resume_prompt_id",
                        "execution has multiple open prompt records",
                    )
                validation_metadata: dict[str, Any] = {}
                if command.command_type == "recover":
                    validation_metadata["resume_prompt_step"] = (
                        resume_prompt.step_index if resume_prompt is not None else None
                    )
                validator = (
                    validate_ir_v08
                    if ir_version == V08_IR_VERSION
                    else validate_ir_v07
                    if ir_version == V07_IR_VERSION
                    else validate_ir_v06
                    if ir_version == V06_IR_VERSION
                    else validate_ir_v03
                )
                validated_ir = validator(
                    ir_version,
                    execution.steps,
                    start_step=start_step,
                    resume_prompt_id=resume_prompt_id,
                    checkpoint_variables=persisted_checkpoint,
                    expected_total_steps=execution.total_steps,
                    **validation_metadata,
                )
            except (
                IRValidationError,
                V06ValidationError,
                V07ValidationError,
                V08ValidationError,
            ) as exc:
                rejection = self._add_event(
                    session,
                    execution,
                    "execution.ir_rejected",
                    {"phase": "supervisor_preflight", **exc.audit_payload()},
                    source="supervisor",
                    severity="error",
                    correlation_id=command.correlation_id,
                    causation_id=command.id,
                )
                session.commit()
                self._publish(execution_id, [event_dict(rejection)])
                raise ConflictError(
                    f"persisted execution IR failed validation [{exc.code}]"
                ) from exc
            execution.worker_generation += 1
            generation = execution.worker_generation
            steps = validated_ir.steps
            checkpoint_variables = {
                **validated_ir.checkpoint_variables,
                **runtime_checkpoint,
            }
            session.commit()
            control = self._ctx.Queue()
            output = self._ctx.Queue()
            for initial_control in initial_controls or []:
                control.put(initial_control)
            process = self._ctx.Process(
                target=worker_main,
                name=f"spell-{execution_id[:8]}-g{generation}",
                args=(
                    execution_id,
                    generation,
                    ir_version,
                    steps,
                    start_step,
                    command_id,
                    resume_prompt_id,
                    checkpoint_variables,
                    control,
                    output,
                    resume_prompt_settlement,
                    durable_arguments,
                ),
                daemon=True,
            )
            handle = WorkerHandle(
                process=process,
                control=control,
                output=output,
                generation=generation,
            )
            self._workers[execution_id] = handle
            # ``spawn`` otherwise copies every backend service secret into the
            # child process environment. Serialize the short environment swap so
            # the child starts with only inert runtime keys, then restore the API.
            with _WORKER_SPAWN_ENVIRONMENT_LOCK:
                service_environment = dict(os.environ)
                try:
                    worker_environment = sanitized_worker_environment()
                    os.environ.clear()
                    os.environ.update(worker_environment)
                    process.start()
                finally:
                    os.environ.clear()
                    os.environ.update(service_environment)
        threading.Thread(
            target=self._consume_worker, args=(execution_id, handle), daemon=True
        ).start()
        threading.Thread(
            target=self._monitor_worker, args=(execution_id, handle), daemon=True
        ).start()
        self._rearm_startproc_watches(execution_id, handle)
        return handle

    def _arm_command_watchdog(
        self, execution_id: str, command_id: str, handle: WorkerHandle
    ) -> threading.Thread:
        timeout_seconds = self.command_ack_timeout_seconds
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("command ACK timeout must be a positive finite number")
        watchdog = threading.Thread(
            target=self._watch_command_ack,
            args=(execution_id, command_id, handle, timeout_seconds),
            daemon=True,
        )
        watchdog.start()
        return watchdog

    def _watch_command_ack(
        self,
        execution_id: str,
        command_id: str,
        handle: WorkerHandle,
        timeout_seconds: float,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        retry_delay = 0.05
        while not self._closed:
            try:
                with self.session_factory() as session:
                    command = session.get(Command, command_id)
                    if (
                        command is None
                        or command.execution_id != execution_id
                        or command.status != "accepted"
                    ):
                        return
                    command_type = command.command_type
            except Exception:
                if self._closed:
                    return
                remaining = deadline - time.monotonic()
                time.sleep(min(retry_delay, remaining) if remaining > 0 else retry_delay)
                retry_delay = min(retry_delay * 2, 1.0)
                continue

            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.05, remaining))
                continue
            self._recover_worker_loss(
                execution_id,
                handle,
                "worker.command_ack_timeout",
                {
                    "command_id": command_id,
                    "command_type": command_type,
                    "timeout_seconds": timeout_seconds,
                },
                f"worker did not acknowledge {command_type} command within "
                f"{timeout_seconds:g} seconds",
                pending_command_id=command_id,
            )
            return

    def _consume_worker(self, execution_id: str, handle: WorkerHandle) -> None:
        dead_since: float | None = None
        while not self._closed and not handle.intentional_stop:
            try:
                message = handle.output.get(timeout=0.2)
            except queue.Empty:
                try:
                    alive = handle.process.is_alive()
                except (AssertionError, OSError, ValueError) as exc:
                    if not handle.intentional_stop:
                        self._signal_worker_failure(
                            handle,
                            f"worker liveness check failed: {type(exc).__name__}: {exc}",
                        )
                    return
                if alive:
                    dead_since = None
                    continue
                dead_since = dead_since or time.monotonic()
                if time.monotonic() - dead_since >= 2.0:
                    return
                continue
            except (EOFError, OSError, ValueError) as exc:
                if not handle.intentional_stop:
                    self._signal_worker_failure(
                        handle,
                        f"worker output consumer failed: {type(exc).__name__}: {exc}",
                    )
                return
            try:
                kind = message["kind"]
                # A handle-local reservation establishes whether this delivery
                # happens before or after invalidation/replacement.  It is kept
                # across the durable handler transaction, but never holds the
                # global supervisor lock while calling OperatorService.
                with handle.dispatch_lock:
                    if not self._worker_message_is_current(execution_id, handle, message):
                        continue
                    self._reject_raw_file_handle_worker_message(
                        execution_id, handle.generation, message
                    )
                    if kind == "terminal":
                        handle.process.join(timeout=2)
                        if handle.process.is_alive():
                            self._signal_worker_failure(
                                handle, "worker remained alive after its terminal message"
                            )
                            return
                        handle.normal_exit = True
                        self._cleanup_worker(execution_id, handle)
                        return
                    # Handler methods own their short supervisor critical sections.
                    # In particular, no global supervisor lock may span a call into
                    # OperatorService: durable service callbacks deliver back into
                    # the supervisor only after their transaction commits.
                    if kind == "event":
                        self.append_event(
                            execution_id,
                            message["event_type"],
                            message.get("payload", {}),
                            source=message.get("source", "worker"),
                            severity=message.get("severity", "info"),
                            worker_generation=handle.generation,
                        )
                    elif kind == "state":
                        self._set_worker_state(
                            execution_id,
                            message["state"],
                            command_id=message.get("command_id"),
                            generation=handle.generation,
                        )
                    elif kind == "step_commit":
                        self._commit_step(execution_id, handle.generation, message)
                    elif kind == "prompt_opened":
                        self._open_prompt(
                            execution_id, handle.generation, message
                        )
                    elif kind == "safe_point":
                        self._record_worker_safe_point(
                            execution_id, handle.generation, message
                        )
                    elif kind == "command_applied":
                        self._settle_operator_command(
                            execution_id,
                            message,
                            settled=True,
                            generation=handle.generation,
                        )
                    elif kind == "command_rejected":
                        self._settle_operator_command(
                            execution_id,
                            message,
                            settled=False,
                            generation=handle.generation,
                        )
                    elif kind == "user_action_settled":
                        self._settle_user_action(
                            execution_id, handle.generation, message
                        )
                    elif kind == "inspection_edit_applied":
                        self._settle_inspection_edit(
                            execution_id,
                            message,
                            generation=handle.generation,
                        )
                    elif kind == "control_loss_applied":
                        self._settle_control_loss(
                            execution_id,
                            message,
                            generation=handle.generation,
                        )
                    elif kind == "startproc_requested":
                        self._handle_startproc_request(execution_id, handle, message)
                    elif kind == "observation_requested":
                        self._handle_observation_request(execution_id, handle, message)
                    elif kind == "data_requested":
                        self._handle_data_request(execution_id, handle, message)
                    else:
                        raise ValueError(f"unsupported worker message kind: {kind!r}")
            except Exception as exc:
                if isinstance(exc, StaleWorkerMessage) or getattr(
                    exc, "code", None
                ) == "STALE_WORKER_GENERATION":
                    continue
                self._signal_worker_failure(
                    handle,
                    f"worker consumer failed while handling a message: "
                    f"{type(exc).__name__}: {exc}",
                )
                return

    def _record_worker_safe_point(
        self,
        execution_id: str,
        generation: int,
        message: dict[str, Any],
    ) -> None:
        service = self.operator_service
        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None or execution.worker_generation != generation:
                return
            point = validate_safe_point(
                SafePoint(
                    kind=message.get("safe_point_kind"),
                    step_index=message.get("step_index"),
                    line=message.get("line"),
                    source_digest=execution.procedure_hash,
                    execution_revision=execution.revision,
                    effect_certainty=message.get("effect_certainty", "NO_EFFECT"),
                )
            )
        breakpoint = None
        if service is not None:
            service.record_safe_point(
                execution_id,
                safe_point_id=point.id,
                safe_point_type=point.kind,
                step_index=point.step_index,
                line=point.line,
                lexical_frame_id=message.get("lexical_frame_id"),
                reachability_id=message.get("reachability_id"),
                worker_generation=generation,
            )
            consume = getattr(service, "consume_breakpoint", None)
            with self._lock:
                recovery_pause = execution_id in self._recovery_pause_pending
            if (
                consume is not None
                and point.kind == "BEFORE_STATEMENT"
                and not recovery_pause
            ):
                breakpoint = consume(
                    execution_id,
                    point.line,
                    point.source_digest,
                    worker_generation=generation,
                )
        with self._lock:
            handle = self._workers.get(execution_id)
            recovery_pause = execution_id in self._recovery_pause_pending
        if handle is None or handle.generation != generation:
            return
        if recovery_pause:
            with self._lock:
                if self._workers.get(execution_id) is handle:
                    self._recovery_pause_pending.discard(execution_id)
        waiting_command = (
            self._waiting_operator_command(execution_id)
            if service is not None and not recovery_pause
            else None
        )
        mutation_reserved = recovery_pause
        if waiting_command is not None:
            command = self._queue_operator_command_at_safe_point(
                waiting_command,
                handle,
                point.id,
                worker_generation=generation,
            )
            mutation_reserved = command.get("state") == "APPLYING"
        if service is not None and not mutation_reserved:
            mutation_reserved = execution_id in self._replay_user_action_deliveries(
                execution_id,
                safe_point_id=point.id,
                handle=handle,
                worker_generation=generation,
            )
        if service is not None and not mutation_reserved:
            self._replay_inspection_edit_deliveries(
                execution_id,
                safe_point_id=point.id,
                handle=handle,
                worker_generation=generation,
            )
        with self.session_factory() as session:
            if self._require_worker_epoch(
                session, execution_id, generation
            ) is None:
                return
            handle.control.put(
                {
                    "type": "safe_point_ack",
                    "safe_point_token": message.get("safe_point_token"),
                }
            )
            if breakpoint is not None:
                handle.control.put(
                    {
                        "type": "pause",
                        "command_id": f"breakpoint:{breakpoint['id']}:{point.id}",
                    }
                )
            session.commit()

    def _settle_operator_command(
        self,
        execution_id: str,
        message: dict[str, Any],
        *,
        settled: bool,
        generation: int | None = None,
    ) -> None:
        service = self.operator_service
        command_id = message.get("command_id")
        if service is None or type(command_id) is not str or not command_id:
            return
        if settled and str(message.get("command_type", "")).upper() == "BACKGROUND":
            apply_background = getattr(service, "apply_background_command", None)
            if apply_background is None:
                raise ConflictError("background command settlement service is unavailable")
            if generation is None:
                safe_point_id = service.get_execution_projection(
                    execution_id
                ).get("current_safe_point_id")
                apply_background(command_id, safe_point_id)
            else:
                apply_background(
                    command_id,
                    None,
                    worker_generation=generation,
                )
            return
        try:
            command = (
                service.transition_operator_command(command_id, "APPLYING")
                if generation is None
                else service.transition_operator_command(
                    command_id,
                    "APPLYING",
                    worker_generation=generation,
                )
            )
        except Exception:
            # Legacy command identities never exist in the v0.6 command store.
            return
        safe_point_id = command.get("application_safe_point_id")
        if generation is None and safe_point_id is None:
            safe_point_id = service.get_execution_projection(
                execution_id
            ).get("current_safe_point_id")
        if settled:
            settle_application = getattr(
                service, "settle_operator_command_application", None
            )
            if settle_application is None:
                raise ConflictError(
                    "operator command application settlement service is unavailable"
                )
            settlement_fields: dict[str, Any] = {
                "result": message.get("result") or {},
                "application_safe_point_id": safe_point_id,
                "effect_certainty": message.get(
                    "effect_certainty", "NO_EFFECT"
                ),
            }
            checkpoint_step = message.get("checkpoint_step")
            if type(checkpoint_step) is int:
                settlement_fields["current_step"] = checkpoint_step
            if generation is None:
                settle_application(command_id, **settlement_fields)
            else:
                settle_application(
                    command_id,
                    worker_generation=generation,
                    **settlement_fields,
                )
            return
        failure_fields = {
            "result": {
                "code": message.get("code", "COMMAND_APPLICATION_FAILED"),
                "detail": message.get(
                    "detail", "command was rejected by the worker"
                ),
                "target_mutation": "NONE",
            },
            "rejection_code": message.get(
                "code", "COMMAND_APPLICATION_FAILED"
            ),
            "application_safe_point_id": safe_point_id,
        }
        if generation is None:
            service.transition_operator_command(
                command_id, "FAILED", **failure_fields
            )
        else:
            service.transition_operator_command(
                command_id,
                "FAILED",
                worker_generation=generation,
                **failure_fields,
            )

    def _settle_user_action(
        self,
        execution_id: str,
        generation: int,
        message: dict[str, Any],
    ) -> None:
        service = self.operator_service
        if service is None:
            return
        invocation_id = message.get("invocation_id")
        settle = getattr(service, "settle_user_action_invocation", None)
        if type(invocation_id) is not str or settle is None:
            raise ConflictError("user action settlement service is unavailable")
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None or execution.worker_generation != generation:
                return
        executed = message.get("outcome") == "EXECUTED"
        settle(
            invocation_id,
            message.get("outcome"),
            result={
                "variables_checkpointed": executed,
                "application_id": message.get("application_id"),
                "safe_point_step": message.get("safe_point_step"),
                "replayed": bool(message.get("replayed", False)),
            },
            rejection_code=message.get("code"),
            application_safe_point_id=None,
            variables=message.get("variables") if executed else None,
            effects=message.get("effects", []) if executed else [],
            worker_generation=generation,
        )

    def _settle_inspection_edit(
        self,
        execution_id: str,
        message: dict[str, Any],
        *,
        generation: int | None = None,
    ) -> None:
        service = self.operator_service
        acknowledge = getattr(
            service, "ack_inspection_edit_application", None
        )
        if acknowledge is None:
            raise ConflictError("inspection edit acknowledgement service is unavailable")
        edit_id = message.get("edit_id")
        if type(edit_id) is not str:
            raise ConflictError("inspection edit acknowledgement is invalid")
        acknowledgement_fields = {
            "outcome": message.get("outcome"),
            "rejection_code": message.get("code"),
            "application_safe_point_id": None,
            "variables": message.get("variables"),
        }
        if generation is None:
            acknowledge(
                edit_id,
                message.get("application_id"),
                **acknowledgement_fields,
            )
        else:
            acknowledge(
                edit_id,
                message.get("application_id"),
                worker_generation=generation,
                **acknowledgement_fields,
            )

    def _settle_control_loss(
        self,
        execution_id: str,
        message: dict[str, Any],
        *,
        generation: int | None = None,
    ) -> None:
        service = self.operator_service
        acknowledge = getattr(service, "ack_control_loss_application", None)
        if acknowledge is None:
            raise ConflictError("control-loss acknowledgement service is unavailable")
        if generation is None:
            safe_point_id = service.get_execution_projection(
                execution_id
            ).get("current_safe_point_id")
            acknowledge(
                execution_id,
                message.get("fencing_token"),
                safe_point_id,
            )
        else:
            acknowledge(
                execution_id,
                message.get("fencing_token"),
                None,
                worker_generation=generation,
            )

    def _handle_startproc_request(
        self,
        execution_id: str,
        handle: WorkerHandle,
        message: dict[str, Any],
    ) -> None:
        service = self.operator_service
        admit = getattr(service, "admit_startproc", None) if service is not None else None
        if admit is None:
            handle.control.put(
                {
                    "type": "startproc_result",
                    "startproc_id": message.get("startproc_id"),
                    "outcome": "REJECTED",
                    "rejection_code": "STARTPROC_SERVICE_UNAVAILABLE",
                }
            )
            return
        try:
            admission_args = (
                execution_id,
                message.get("startproc_id"),
                message.get("step_index"),
                {
                    "child_reference": message.get("child_reference"),
                    "arguments": message.get("arguments"),
                    "arguments_digest": message.get("arguments_digest"),
                    "blocking": message.get("blocking"),
                    "visible": message.get("visible"),
                    "automatic": message.get("automatic"),
                },
            )
            generation = getattr(handle, "generation", None)
            result = (
                admit(*admission_args, worker_generation=generation)
                if type(generation) is int
                else admit(*admission_args)
            )
        except Exception as exc:
            if getattr(exc, "code", None) == "STALE_WORKER_GENERATION":
                raise
            result = {
                "id": message.get("startproc_id"),
                "revision": 0,
                "parent_execution_id": execution_id,
                "state": "REJECTED",
                "rejection_code": getattr(exc, "code", "ADMISSION_REJECTED"),
            }
        state = result.get("state")
        child_execution_id = result.get("child_execution_id")
        blocking = bool(message.get("blocking"))
        admitted = type(child_execution_id) is str and state in {
            "CHILD_CREATED",
            "WAITING_CHILD",
            "SETTLED",
        }
        if admitted and not blocking:
            outcome = "SETTLED"
        elif admitted and blocking and state == "SETTLED":
            outcome = "SETTLED"
        else:
            outcome = "WAITING_CHILD" if admitted else "REJECTED"
        if outcome == "WAITING_CHILD":
            self._start_startproc_watch(execution_id, handle, result)
        if outcome != "WAITING_CHILD":
            self._deliver_startproc_result(execution_id, result, handle=handle)

    @staticmethod
    def _observation_event(
        session: Session,
        execution_id: str,
        event_type: str,
        request_id: str,
    ) -> Event | None:
        event = session.scalar(
            select(Event)
            .where(
                Event.execution_id == execution_id,
                Event.event_type == event_type,
                Event.correlation_id == request_id,
            )
            .order_by(Event.sequence.desc())
            .limit(1)
        )
        if event is not None and (
            type(event.payload) is not dict
            or event.payload.get("request_id") != request_id
        ):
            raise ConflictError("durable observation event identity is inconsistent")
        return event

    def _handle_observation_request(
        self,
        execution_id: str,
        handle: WorkerHandle,
        message: dict[str, Any],
    ) -> None:
        request_payload = {
            key: value
            for key, value in message.items()
            if key not in {"kind", "generation"}
        }
        published: list[dict[str, Any]] = []
        replay: dict[str, Any] | None = None
        with self._lock, self.session_factory() as session:
            execution = self._require_worker_epoch(
                session, execution_id, handle.generation
            )
            if execution is None:
                raise StaleWorkerMessage("worker generation is no longer current")
            step_index = request_payload.get("step_index")
            if (
                execution.ir_version not in {V07_IR_VERSION, V08_IR_VERSION}
                or type(step_index) is not int
                or step_index != execution.current_step
                or step_index < 0
                or step_index >= len(execution.steps)
            ):
                raise ConflictError("observation request does not target the current v0.7 step")
            base_request = validate_observation_request(
                execution.steps[step_index],
                request_payload,
                execution_id=execution_id,
            )
            request_id = base_request["request_id"]
            requested = self._observation_event(
                session,
                execution_id,
                "procedure.observation_requested",
                request_id,
            )
            is_next = (
                base_request["operation"] == "GET_TM"
                and base_request["parameters"]["mode"] == "NEXT"
            )
            if requested is not None:
                request = (
                    validate_anchored_observation_request(
                        execution.steps[step_index],
                        requested.payload,
                        execution_id=execution_id,
                        context_id=execution.context_id,
                    )
                    if is_next
                    else validate_observation_request(
                        execution.steps[step_index],
                        requested.payload,
                        execution_id=execution_id,
                    )
                )
            else:
                request = (
                    self._anchored_observation_request(
                        base_request,
                        execution.context_id,
                    )
                    if is_next
                    else base_request
                )
                event = self._add_event(
                    session,
                    execution,
                    "procedure.observation_requested",
                    request,
                    source="worker",
                    correlation_id=request_id,
                )
                session.commit()
                published.append(event_dict(event))

            settled = self._observation_event(
                session,
                execution_id,
                "procedure.observation_result",
                request_id,
            )
            if settled is not None:
                replay = validate_observation_result(request, settled.payload)
            else:
                inflight = getattr(self, "_observation_requests", None)
                if inflight is None:
                    inflight = self._observation_requests = set()
                key = (execution_id, request_id, handle.generation)
                if key in inflight:
                    return
                inflight.add(key)

            for event in published:
                self.hub.publish(execution_id, event)

        if replay is not None:
            handle.control.put({"type": "observation_result", **replay})
            return

        threading.Thread(
            target=self._resolve_observation_request,
            args=(execution_id, handle, request),
            name=f"spell-observation-{execution_id[:8]}-{step_index}",
            daemon=True,
        ).start()

    def _anchored_observation_request(
        self,
        request: dict[str, Any],
        context_id: str,
    ) -> dict[str, Any]:
        provider = getattr(self, "observation_anchor_provider", None)
        try:
            capture = getattr(provider, "telemetry_anchor", None)
            if not callable(capture):
                raise RuntimeError("observation anchor provider is unavailable")
            anchor = capture(context_id, request["parameters"]["item_id"])
        except Exception:
            anchor = unavailable_observation_anchor(
                "OBSERVATION_ANCHOR_UNAVAILABLE"
            )
        requested_at_unix_ns = time.time_ns()
        timeout_ns = int(
            (
                Decimal(str(request["parameters"]["timeout_seconds"]))
                * Decimal(1_000_000_000)
            ).to_integral_value(rounding=ROUND_CEILING)
        )
        return bind_observation_anchor(
            request,
            context_id,
            anchor,
            requested_at_unix_ns=str(requested_at_unix_ns),
            deadline_at_unix_ns=str(requested_at_unix_ns + timeout_ns),
        )

    def _resolve_observation_request(
        self,
        execution_id: str,
        handle: WorkerHandle,
        request: dict[str, Any],
    ) -> None:
        key = (execution_id, request["request_id"], handle.generation)
        try:
            anchor = request.get("anchor")
            if type(anchor) is dict and anchor.get("status") == "UNAVAILABLE":
                result = unavailable_observation_result(
                    request, anchor["error_code"]
                )
            elif (runtime := getattr(self, "observation_runtime", None)) is None:
                result = unavailable_observation_result(
                    request, "OBSERVATION_RUNTIME_UNAVAILABLE"
                )
            else:
                runtime_request = json.loads(
                    json.dumps(request, sort_keys=True, separators=(",", ":"))
                )
                runtime_request["resolver_generation"] = handle.generation
                resolver = getattr(runtime, "resolve", None)
                raw_result = (
                    resolver(runtime_request)
                    if callable(resolver)
                    else runtime(runtime_request)
                    if callable(runtime)
                    else None
                )
                if raw_result is None:
                    raise V07ValidationError(
                        "OBSERVATION_RESULT_INVALID",
                        "$.result",
                        "runtime returned no result",
                    )
                result = canonicalize_observation_result(request, raw_result)
        except Exception:
            result = unavailable_observation_result(
                request, "OBSERVATION_RUNTIME_RESULT_INVALID"
            )
        try:
            self._settle_observation_result(execution_id, handle, request, result)
        finally:
            with self._lock:
                getattr(self, "_observation_requests", set()).discard(key)

    def _settle_observation_result(
        self,
        execution_id: str,
        handle: WorkerHandle,
        request: dict[str, Any],
        result: dict[str, Any],
    ) -> bool:
        canonical = validate_observation_result(request, result)
        published: dict[str, Any] | None = None
        delivered: dict[str, Any] | None = None
        with handle.dispatch_lock:
            with self._lock, self.session_factory() as session:
                if self._workers.get(execution_id) is not handle:
                    return False
                execution = self._require_worker_epoch(
                    session, execution_id, handle.generation
                )
                if (
                    execution is None
                    or execution.current_step != request["step_index"]
                    or execution.ir_version not in {V07_IR_VERSION, V08_IR_VERSION}
                ):
                    return False
                existing = self._observation_event(
                    session,
                    execution_id,
                    "procedure.observation_result",
                    request["request_id"],
                )
                if existing is None:
                    event = self._add_event(
                        session,
                        execution,
                        "procedure.observation_result",
                        canonical,
                        source="observation-runtime",
                        severity=("info" if canonical["outcome"] in {"OK", "TRUE", "FALSE", "SATISFIED"} else "warning"),
                        correlation_id=request["request_id"],
                    )
                    session.commit()
                    published = event_dict(event)
                    delivered = canonical
                else:
                    delivered = validate_observation_result(request, existing.payload)
                if published is not None:
                    self.hub.publish(execution_id, published)
            handle.control.put({"type": "observation_result", **delivered})
        return True

    def _reject_raw_file_handle_worker_message(
        self,
        execution_id: str,
        generation: int,
        message: Mapping[str, Any],
    ) -> None:
        """Fence every worker persistence path against copied capability tokens."""

        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if (
                execution is None
                or execution.ir_version != V08_IR_VERSION
                or execution.worker_generation != generation
            ):
                return
            token_digests = {
                value["token_sha256"]
                for value in (
                    execution.variables.values()
                    if type(execution.variables) is dict
                    else ()
                )
                if is_file_handle_reference(value)
            }
            results = session.scalars(
                select(Event).where(
                    Event.execution_id == execution_id,
                    Event.event_type == "procedure.data_result",
                )
            ).all()
            token_digests.update(
                event.payload["value"]["token_sha256"]
                for event in results
                if type(event.payload) is dict
                and is_file_handle_reference(event.payload.get("value"))
            )
        if token_digests and _contains_file_handle_token(message, token_digests):
            raise ConflictError("worker message contains a raw FileHandle token")

    @staticmethod
    def _data_event(
        session: Session,
        execution_id: str,
        event_type: str,
        request_id: str,
    ) -> Event | None:
        event = session.scalar(
            select(Event)
            .where(
                Event.execution_id == execution_id,
                Event.event_type == event_type,
                Event.correlation_id == request_id,
            )
            .order_by(Event.sequence.desc())
            .limit(1)
        )
        if event is not None and (
            type(event.payload) is not dict
            or event.payload.get("request_id") != request_id
        ):
            raise ConflictError("durable data event identity is inconsistent")
        return event

    def _handle_data_request(
        self,
        execution_id: str,
        handle: WorkerHandle,
        message: dict[str, Any],
    ) -> None:
        request_payload = {
            key: value
            for key, value in message.items()
            if key not in {"kind", "generation"}
        }
        published: list[dict[str, Any]] = []
        replay: dict[str, Any] | None = None
        original_binding: ProcedureCallerBinding | None = None
        with self._lock, self.session_factory() as session:
            execution = self._require_worker_epoch(
                session, execution_id, handle.generation
            )
            if execution is None:
                raise StaleWorkerMessage("worker generation is no longer current")
            step_index = request_payload.get("step_index")
            if (
                execution.ir_version != V08_IR_VERSION
                or type(step_index) is not int
                or step_index != execution.current_step
                or step_index < 0
                or step_index >= len(execution.steps)
            ):
                raise ConflictError("data request does not target the current v0.8 step")
            request = validate_data_request(
                execution.steps[step_index],
                request_payload,
                execution_id=execution_id,
                authoritative_variables=execution.variables,
                worker_generation=handle.generation,
            )
            request_id = request["request_id"]
            current_binding = ProcedureCallerBinding(
                "procedure-runtime", execution_id, handle.generation, request_id
            )
            requested = self._data_event(
                session,
                execution_id,
                "procedure.data_requested",
                request_id,
            )
            if requested is None:
                durable_request = {
                    **request,
                    _DATA_RUNTIME_BINDING_KEY: {
                        "deterministic_request_id": request_id,
                        "execution_id": execution_id,
                        "service_principal_id": "procedure-runtime",
                        "worker_generation": handle.generation,
                    },
                }
                event = self._add_event(
                    session,
                    execution,
                    "procedure.data_requested",
                    durable_request,
                    source="worker",
                    correlation_id=request_id,
                )
                session.commit()
                published.append(event_dict(event))
                original_binding = current_binding
            else:
                stored_request = dict(requested.payload)
                stored_binding = stored_request.pop(
                    _DATA_RUNTIME_BINDING_KEY, None
                )
                request = validate_data_request(
                    execution.steps[step_index],
                    stored_request,
                    execution_id=execution_id,
                    authoritative_variables=execution.variables,
                    worker_generation=handle.generation,
                )
                if type(stored_binding) is not dict or set(stored_binding) != {
                    "deterministic_request_id",
                    "execution_id",
                    "service_principal_id",
                    "worker_generation",
                }:
                    raise ConflictError(
                        "durable data request binding is unavailable or corrupt"
                    )
                try:
                    original_binding = ProcedureCallerBinding(**stored_binding)
                except DataDomainError as exc:
                    raise ConflictError(
                        "durable data request binding is invalid"
                    ) from exc
                if (
                    original_binding.execution_id != execution_id
                    or original_binding.deterministic_request_id != request_id
                    or original_binding.service_principal_id != "procedure-runtime"
                    or original_binding.worker_generation > handle.generation
                ):
                    raise ConflictError("durable data request binding differs")

            settled = self._data_event(
                session,
                execution_id,
                "procedure.data_result",
                request_id,
            )
            if settled is not None:
                replay = validate_data_result(request, settled.payload)
                if (
                    replay["operation"] == "OPEN_FILE"
                    and replay["outcome"] == "OK"
                ):
                    replay = stale_file_handle_result(request)
            else:
                key = (execution_id, request_id, handle.generation)
                if key in self._data_requests:
                    return
                self._data_requests.add(key)

            for event in published:
                self.hub.publish(execution_id, event)

        if replay is not None:
            handle.control.put({"type": "data_result", **replay})
            return

        threading.Thread(
            target=self._resolve_data_request,
            args=(execution_id, handle, request, original_binding),
            name=f"spell-data-{execution_id[:8]}-{step_index}",
            daemon=True,
        ).start()

    def _resolve_data_request(
        self,
        execution_id: str,
        handle: WorkerHandle,
        request: dict[str, Any],
        original_binding: ProcedureCallerBinding,
    ) -> None:
        key = (execution_id, request["request_id"], handle.generation)
        try:
            runtime = self.data_runtime
            if runtime is None:
                result = unavailable_data_result(
                    request, "DATA_RUNTIME_UNAVAILABLE"
                )
            else:
                runtime_request = json.loads(
                    json.dumps(request, sort_keys=True, separators=(",", ":"))
                )
                runtime_request.update(
                    service_principal_id="procedure-runtime",
                    worker_generation=handle.generation,
                )
                if original_binding.worker_generation != handle.generation:
                    recoverer = getattr(runtime, "recover", None)
                    if not callable(recoverer):
                        raise V08ValidationError(
                            "DATA_RESULT_INVALID",
                            "$.result",
                            "runtime has no settlement recovery channel",
                        )
                    raw_result = recoverer(
                        runtime_request,
                        original_binding=original_binding,
                    )
                else:
                    resolver = getattr(runtime, "resolve", None)
                    raw_result = (
                        resolver(runtime_request)
                        if callable(resolver)
                        else runtime(runtime_request)
                        if callable(runtime)
                        else None
                    )
                if raw_result is None:
                    raise V08ValidationError(
                        "DATA_RESULT_INVALID",
                        "$.result",
                        "runtime returned no result",
                    )
                result = canonicalize_data_result(request, raw_result)
        except Exception:
            result = unavailable_data_result(
                request, "DATA_RUNTIME_RESULT_INVALID"
            )
        try:
            self._settle_data_result(execution_id, handle, request, result)
        finally:
            with self._lock:
                self._data_requests.discard(key)

    def _settle_data_result(
        self,
        execution_id: str,
        handle: WorkerHandle,
        request: dict[str, Any],
        result: dict[str, Any],
    ) -> bool:
        transient = validate_data_result(request, result)
        durable = persistable_data_result(
            request, transient, worker_generation=handle.generation
        )
        published: dict[str, Any] | None = None
        delivered: dict[str, Any] | None = None
        with handle.dispatch_lock:
            with self._lock, self.session_factory() as session:
                if self._workers.get(execution_id) is not handle:
                    return False
                execution = self._require_worker_epoch(
                    session, execution_id, handle.generation
                )
                if (
                    execution is None
                    or execution.current_step != request["step_index"]
                    or execution.ir_version != V08_IR_VERSION
                ):
                    return False
                existing = self._data_event(
                    session,
                    execution_id,
                    "procedure.data_result",
                    request["request_id"],
                )
                if existing is None:
                    event = self._add_event(
                        session,
                        execution,
                        "procedure.data_result",
                        durable,
                        source="data-runtime",
                        severity=(
                            "info" if durable["outcome"] == "OK" else "warning"
                        ),
                        correlation_id=request["request_id"],
                    )
                    session.commit()
                    published = event_dict(event)
                    delivered = transient
                else:
                    delivered = validate_data_result(request, existing.payload)
                    if (
                        delivered["operation"] == "OPEN_FILE"
                        and delivered["outcome"] == "OK"
                    ):
                        delivered = stale_file_handle_result(request)
                if published is not None:
                    self.hub.publish(execution_id, published)
            handle.control.put({"type": "data_result", **delivered})
        return True

    def _watch_startproc_child(
        self,
        parent_execution_id: str,
        parent_handle: WorkerHandle,
        operation: dict[str, Any],
    ) -> None:
        service = self.operator_service
        if service is None:
            return
        startproc_id = operation.get("id")
        child_execution_id = operation.get("child_execution_id")
        if type(startproc_id) is not str or type(child_execution_id) is not str:
            return
        while not self._closed and not parent_handle.intentional_stop:
            with self._lock:
                if self._workers.get(parent_execution_id) is not parent_handle:
                    return
            with self.session_factory() as session:
                child = session.get(Execution, child_execution_id)
                child_state = child.state if child is not None else None
            if child_state in TERMINAL_STATES:
                canonical = {
                    "completed": "FINISHED",
                    "aborted": "ABORTED",
                    "failed": "ERROR",
                }[child_state]
                settled = service.settle_startproc_child(
                    startproc_id, child_execution_id, canonical
                )
                self._deliver_startproc_result(
                    parent_execution_id,
                    settled,
                    handle=parent_handle,
                )
                return
            time.sleep(0.1)

    def _start_startproc_watch(
        self,
        execution_id: str,
        handle: WorkerHandle,
        operation: dict[str, Any],
    ) -> None:
        startproc_id = operation.get("id")
        if type(startproc_id) is not str:
            return
        key = (execution_id, startproc_id, handle.generation)
        with self._lock:
            if key in self._startproc_watchers:
                return
            self._startproc_watchers.add(key)

        def run() -> None:
            try:
                self._watch_startproc_child(execution_id, handle, operation)
            finally:
                with self._lock:
                    self._startproc_watchers.discard(key)

        threading.Thread(target=run, daemon=True).start()

    def _rearm_startproc_watches(
        self, execution_id: str, handle: WorkerHandle
    ) -> None:
        service = self.operator_service
        if service is None:
            return
        reconcile_admissions = getattr(
            service, "reconcile_startproc_admissions", None
        )
        if reconcile_admissions is not None:
            reconcile_admissions(execution_id)
        for operation in service.list_reconcilable_startprocs(execution_id):
            if operation.get("state") != "WAITING_CHILD":
                continue
            self._start_startproc_watch(execution_id, handle, operation)

    def _operator_command_state(self, command_id: str) -> str | None:
        with self.session_factory() as session:
            command = session.get(OperatorCommand, command_id)
            return command.state if command is not None else None

    def _transition_abort_command_to_applying(
        self, command_id: str
    ) -> dict[str, Any] | None:
        service = self.operator_service
        if service is None:
            return None
        try:
            return service.transition_operator_command(command_id, "APPLYING")
        except Exception:
            state = self._operator_command_state(command_id)
        if state is None:
            return None
        if state in {"APPLYING", "RECONCILING"}:
            return service.transition_operator_command(command_id, state)
        raise ConflictError(
            f"abort cleanup command is unexpectedly {state.lower()}"
        )

    def _blocking_startproc_operations(
        self, parent_execution_id: str
    ) -> list[dict[str, Any]]:
        service = self.operator_service
        if service is None:
            return []
        operations = service.list_reconcilable_startprocs(parent_execution_id)
        return [
            operation
            for operation in operations
            if operation.get("blocking")
            and operation.get("state")
            not in {"SETTLED", "REJECTED", "CANCELLED"}
        ]

    def _reconcile_blocking_startprocs(self, parent_execution_id: str) -> None:
        service = self.operator_service
        if service is None:
            return
        reconcile_admissions = getattr(
            service, "reconcile_startproc_admissions", None
        )
        if reconcile_admissions is not None:
            reconcile_admissions(parent_execution_id)
        reconcile_children = getattr(service, "reconcile_startproc_children", None)
        if reconcile_children is not None:
            reconcile_children()

    def _start_abort_cleanup_barrier(
        self,
        execution_id: str,
        command_id: str,
        *,
        effect_certainty: str,
    ) -> dict[str, Any]:
        command = self._transition_abort_command_to_applying(command_id)
        self._reconcile_blocking_startprocs(execution_id)
        self._abort_blocking_children(execution_id, command_id)
        self._reconcile_blocking_startprocs(execution_id)
        if not self._blocking_startproc_operations(execution_id):
            return self._finalize_abort_cleanup(
                execution_id,
                command_id,
                effect_certainty=effect_certainty,
                operator_command=command is not None,
            )

        key = (execution_id, command_id)
        with self._lock:
            barriers = getattr(self, "_abort_cleanup_barriers", None)
            if barriers is None:
                barriers = self._abort_cleanup_barriers = set()
            if key in barriers:
                return command or {
                    "id": command_id,
                    "state": "APPLYING",
                    "execution_id": execution_id,
                }
            barriers.add(key)

        def run() -> None:
            deadline = time.monotonic() + max(
                5.0, self.command_ack_timeout_seconds * 4
            )
            last_error: Exception | None = None
            try:
                while not self._closed:
                    try:
                        self._reconcile_blocking_startprocs(execution_id)
                        self._abort_blocking_children(execution_id, command_id)
                        self._reconcile_blocking_startprocs(execution_id)
                        if not self._blocking_startproc_operations(execution_id):
                            self._finalize_abort_cleanup(
                                execution_id,
                                command_id,
                                effect_certainty=effect_certainty,
                                operator_command=command is not None,
                            )
                            return
                        last_error = None
                    except Exception as exc:
                        last_error = exc
                    if time.monotonic() >= deadline:
                        self._fail_abort_cleanup(
                            execution_id,
                            command_id,
                            effect_certainty=effect_certainty,
                            operator_command=command is not None,
                            detail=(
                                str(last_error)
                                if last_error is not None
                                else "blocking child cleanup did not settle"
                            ),
                        )
                        return
                    time.sleep(0.1)
            finally:
                with self._lock:
                    self._abort_cleanup_barriers.discard(key)

        threading.Thread(
            target=run,
            name=f"spell-abort-cleanup-{execution_id[:8]}",
            daemon=True,
        ).start()
        return command or {
            "id": command_id,
            "state": "APPLYING",
            "execution_id": execution_id,
        }

    def _finalize_abort_cleanup(
        self,
        execution_id: str,
        command_id: str,
        *,
        effect_certainty: str,
        operator_command: bool,
    ) -> dict[str, Any]:
        self._set_state(
            execution_id,
            "aborted",
            source="operator-runtime",
            command_id=None if operator_command else command_id,
        )
        if not operator_command or self.operator_service is None:
            return {
                "id": command_id,
                "execution_id": execution_id,
                "state": "SETTLED",
                "result": {"state": "ABORTED"},
            }
        safe_point_id = self.operator_service.get_execution_projection(
            execution_id
        ).get("current_safe_point_id")
        return self.operator_service.transition_operator_command(
            command_id,
            "SETTLED",
            result={
                "state": "ABORTED",
                "blocking_child_cleanup": "SETTLED",
                "clean_external_state": False,
            },
            application_safe_point_id=safe_point_id,
            effect_certainty=effect_certainty,
        )

    def _fail_abort_cleanup(
        self,
        execution_id: str,
        command_id: str,
        *,
        effect_certainty: str,
        operator_command: bool,
        detail: str,
    ) -> None:
        detail = detail[:500]
        self._set_state(
            execution_id,
            "recovery_required",
            source="operator-runtime",
            command_id=None if operator_command else command_id,
            preserve_open_prompts=True,
            pending_command_error=f"blocking child cleanup failed: {detail}",
        )
        if operator_command and self.operator_service is not None:
            self.operator_service.transition_operator_command(
                command_id,
                "FAILED",
                result={
                    "state": "SUSPENDED",
                    "error": detail,
                    "blocking_child_cleanup": "INCOMPLETE",
                },
                rejection_code="BLOCKING_CHILD_CLEANUP_INCOMPLETE",
                effect_certainty=effect_certainty,
            )

    def _abort_blocking_children(
        self, parent_execution_id: str, parent_command_id: str
    ) -> None:
        service = self.operator_service
        if service is None:
            return
        for operation in self._blocking_startproc_operations(parent_execution_id):
            if operation.get("state") not in {"CHILD_CREATED", "WAITING_CHILD"}:
                continue
            child_id = operation.get("child_execution_id")
            if type(child_id) is not str:
                continue
            with self.session_factory() as session:
                child = session.get(Execution, child_id)
                if child is None or child.state in TERMINAL_STATES:
                    continue
                child_revision = child.revision
            try:
                lifecycle_claimed = False
                with self._lock:
                    child_handle = self._workers.get(child_id)
                    spawning = getattr(self, "_spawning", set())
                    if child_id in spawning:
                        continue
                    if child_handle is None:
                        spawning.add(child_id)
                        self._spawning = spawning
                        lifecycle_claimed = True
                if child_handle is None:
                    try:
                        self._set_state(child_id, "aborting", source="operator-runtime")
                        self._set_state(child_id, "aborted", source="operator-runtime")
                    finally:
                        with self._lock:
                            self._spawning.discard(child_id)
                    continue

                with getattr(child_handle, "dispatch_lock", nullcontext()):
                    with self._lock:
                        if (
                            self._workers.get(child_id) is not child_handle
                            or getattr(child_handle, "intentional_stop", False)
                            or child_id in getattr(self, "_spawning", set())
                        ):
                            continue
                    try:
                        child_is_live = child_handle.process.is_alive()
                    except (AssertionError, AttributeError, OSError, ValueError):
                        child_is_live = False
                    with self.session_factory() as session:
                        current_child = session.get(Execution, child_id)
                        if current_child is None or current_child.state in TERMINAL_STATES:
                            continue
                        child_revision = current_child.revision
                    if child_is_live:
                        self.issue_command(
                            child_id,
                            "abort",
                            child_revision,
                            f"parent-abort:{parent_command_id}:{operation['id']}",
                            "operator-runtime",
                            "admin",
                            "Propagate parent abort to blocking child",
                            parent_command_id,
                            {},
                        )
                        continue
                    with self._lock:
                        spawning = getattr(self, "_spawning", set())
                        if child_id in spawning:
                            continue
                        spawning.add(child_id)
                        self._spawning = spawning
                        lifecycle_claimed = True
                    self._invalidate_worker(child_id)
                    self._set_state(child_id, "aborting", source="operator-runtime")
                    self._set_state(child_id, "aborted", source="operator-runtime")
            except Exception:
                # The durable WAITING_CHILD operation remains reconcilable and
                # preserves the original parent/child failure evidence.
                continue
            finally:
                if lifecycle_claimed:
                    with self._lock:
                        self._spawning.discard(child_id)

    def _monitor_worker(self, execution_id: str, handle: WorkerHandle) -> None:
        while not self._closed and not handle.intentional_stop:
            if handle.failure_signal.wait(timeout=0.05):
                self._recover_worker_loss(
                    execution_id,
                    handle,
                    "worker.consumer_failed",
                    {"error": handle.failure_detail or "worker consumer failed"},
                    handle.failure_detail or "worker consumer failed",
                )
                return
            try:
                handle.process.join(timeout=0.05)
                if not handle.process.is_alive():
                    break
            except (AssertionError, OSError, ValueError) as exc:
                if not self._closed and not handle.intentional_stop:
                    self._recover_worker_loss(
                        execution_id,
                        handle,
                        "worker.monitor_failed",
                        {"error": f"{type(exc).__name__}: {exc}"},
                        f"worker monitor failed: {type(exc).__name__}: {exc}",
                    )
                return
        if self._closed or handle.intentional_stop:
            return
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if self._closed or handle.normal_exit or handle.intentional_stop:
                return
            if handle.failure_signal.wait(timeout=0.05):
                self._recover_worker_loss(
                    execution_id,
                    handle,
                    "worker.consumer_failed",
                    {"error": handle.failure_detail or "worker consumer failed"},
                    handle.failure_detail or "worker consumer failed",
                )
                return
        if self._closed or handle.normal_exit or handle.intentional_stop:
            return
        terminal_execution = False
        with self._lock:
            if self._workers.get(execution_id) is not handle:
                return
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                if execution is not None and execution.state in TERMINAL_STATES:
                    handle.normal_exit = True
                    terminal_execution = True
                else:
                    exit_code = handle.process.exitcode
        if terminal_execution:
            self._cleanup_worker(execution_id, handle)
            return
        self._recover_worker_loss(
            execution_id,
            handle,
            "worker.crashed",
            {"exit_code": exit_code},
            f"worker exited unexpectedly with code {exit_code}",
        )

    @staticmethod
    def _signal_worker_failure(handle: WorkerHandle, detail: str) -> None:
        if handle.failure_signal.is_set():
            return
        handle.failure_detail = detail
        handle.failure_signal.set()

    def _recover_worker_loss(
        self,
        execution_id: str,
        handle: WorkerHandle,
        event_type: str,
        payload: dict[str, Any],
        command_error: str,
        pending_command_id: str | None = None,
    ) -> None:
        with handle.dispatch_lock:
            with self._lock:
                if (
                    self._closed
                    or handle.intentional_stop
                    or self._workers.get(execution_id) is not handle
                ):
                    return
                if pending_command_id is not None:
                    with self.session_factory() as session:
                        command = session.get(Command, pending_command_id)
                        if (
                            command is None
                            or command.execution_id != execution_id
                            or command.status != "accepted"
                        ):
                            return
            fenced = self._fence_worker_epoch(execution_id, handle)
            with self._lock:
                if self._workers.get(execution_id) is not handle:
                    return
                handle.intentional_stop = True
            terminated = self._terminate_worker(handle)
            if terminated:
                self._cleanup_worker(execution_id, handle)
        if not fenced:
            return
        try:
            self.append_event(
                execution_id,
                event_type,
                payload,
                source="supervisor",
                severity="error",
            )
        except Exception:
            # The recovery transition below remains the durable source of truth if
            # recording the supplementary worker-loss event also fails.
            pass
        retry_delay = 0.05
        while not self._closed:
            try:
                self._set_state(
                    execution_id,
                    "recovery_required",
                    source="supervisor",
                    preserve_open_prompts=True,
                    pending_command_error=command_error,
                )
                return
            except Exception:
                if self._closed:
                    return
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 1.0)

    def _recover_dispatch_failure(
        self,
        execution_id: str,
        command_error: str,
        *,
        expected_handle: WorkerHandle | None = None,
    ) -> None:
        recovery_slot_claimed = False
        invalidated = expected_handle is None
        should_invalidate = False
        reservation = (
            getattr(expected_handle, "dispatch_lock", nullcontext())
            if expected_handle is not None
            else nullcontext()
        )
        with reservation:
            with self._lock:
                spawning = getattr(self, "_spawning", None)
                if spawning is None:
                    spawning = self._spawning = set()
                current = self._workers.get(execution_id)
                if expected_handle is None:
                    # A pre-install spawn failure has no handle to invalidate. A
                    # concurrently installed worker owns recovery from this point.
                    if current is not None or execution_id in spawning:
                        return
                elif execution_id in spawning:
                    return
                elif current is expected_handle:
                    should_invalidate = True
                elif current is not None:
                    return
                else:
                    # The failing dispatch may already have fenced and removed
                    # its captured handle before a later durable write failed.
                    invalidated = True
                spawning.add(execution_id)
                recovery_slot_claimed = True
            if should_invalidate:
                try:
                    invalidated = self._invalidate_worker(execution_id)
                except RuntimeError as exc:
                    invalidated = True
                    command_error = f"{command_error}; {exc}"
        try:
            if not invalidated:
                return
            retry_delay = 0.05
            while True:
                try:
                    self._set_state(
                        execution_id,
                        "recovery_required",
                        source="supervisor",
                        preserve_open_prompts=True,
                        pending_command_error=command_error,
                    )
                    return
                except Exception:
                    if self._closed:
                        return
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 1.0)
        finally:
            if recovery_slot_claimed:
                with self._lock:
                    self._spawning.discard(execution_id)

    def _simulate_crash(
        self,
        execution_id: str,
        command_id: str,
        *,
        expected_handle: WorkerHandle | None | object = _WORKER_HANDLE_UNSET,
    ) -> None:
        if expected_handle is _WORKER_HANDLE_UNSET:
            with self._lock:
                handle = self._workers.get(execution_id)
        else:
            handle = expected_handle
        if handle is None:
            lifecycle_claimed = False
            with self._lock:
                spawning = getattr(self, "_spawning", set())
                if self._workers.get(execution_id) is not None or execution_id in spawning:
                    competing_worker = True
                else:
                    spawning.add(execution_id)
                    self._spawning = spawning
                    lifecycle_claimed = True
                    competing_worker = False
            if competing_worker:
                self._fail_command(
                    command_id, "worker was replaced before simulated crash"
                )
                return
            try:
                self._fail_command(command_id, "worker is unavailable")
                self._set_state(
                    execution_id,
                    "recovery_required",
                    source="supervisor",
                    preserve_open_prompts=True,
                )
            finally:
                if lifecycle_claimed:
                    with self._lock:
                        self._spawning.discard(execution_id)
            return
        if not isinstance(handle, WorkerHandle):
            raise TypeError("expected worker handle is invalid")
        with handle.dispatch_lock:
            with self._lock:
                current = self._workers.get(execution_id) is handle
            with self.session_factory() as session:
                pending = session.get(Command, command_id)
                command_is_pending = (
                    pending is not None
                    and pending.execution_id == execution_id
                    and pending.status == "accepted"
                )
            if not current or not command_is_pending:
                if command_is_pending:
                    self._fail_command(
                        command_id, "worker was replaced before simulated crash"
                    )
                return
            fenced = self._fence_worker_epoch(execution_id, handle)
            with self._lock:
                if handle is not None and self._workers.get(execution_id) is handle:
                    handle.intentional_stop = True
                else:
                    handle = None
            if not fenced:
                if handle is not None:
                    self._terminate_worker(handle)
                    self._cleanup_worker(execution_id, handle)
                self._fail_command(
                    command_id, "worker generation is no longer current"
                )
                return
            if handle is None or not handle.process.is_alive():
                if handle is not None:
                    self._cleanup_worker(execution_id, handle)
                self._fail_command(command_id, "worker is unavailable")
                self._set_state(
                    execution_id,
                    "recovery_required",
                    source="supervisor",
                    preserve_open_prompts=True,
                )
                return
            if not self._terminate_worker(handle):
                raise RuntimeError("simulated crash could not terminate worker")
            exit_code = handle.process.exitcode
            self._cleanup_worker(execution_id, handle)
        self.append_event(
            execution_id,
            "worker.crash_simulated",
            {"exit_code": exit_code},
            source="supervisor",
            severity="warning",
            causation_id=command_id,
        )
        self._complete_command(command_id, {"state": "recovery_required"})
        self._set_state(
            execution_id,
            "recovery_required",
            source="supervisor",
            preserve_open_prompts=True,
        )

    def _worker_message_is_current(
        self, execution_id: str, handle: WorkerHandle, message: dict[str, Any]
    ) -> bool:
        if message.get("generation") != handle.generation:
            return False
        with self._lock:
            if (
                handle.intentional_stop
                or self._workers.get(execution_id) is not handle
            ):
                return False
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                return execution is not None and execution.worker_generation == handle.generation

    @staticmethod
    def _require_worker_epoch(
        session: Session,
        execution_id: str,
        generation: int,
    ) -> Execution | None:
        claimed = session.execute(
            update(Execution)
            .where(
                Execution.id == execution_id,
                Execution.worker_generation == generation,
            )
            .values(worker_generation=generation)
        )
        if claimed.rowcount != 1:
            return None
        return session.get(Execution, execution_id)

    def _fence_worker_epoch(
        self,
        execution_id: str,
        handle: WorkerHandle,
    ) -> bool:
        with self.session_factory() as session:
            fenced = session.execute(
                update(Execution)
                .where(
                    Execution.id == execution_id,
                    Execution.worker_generation == handle.generation,
                )
                .values(worker_generation=handle.generation + 1)
            )
            session.commit()
            return fenced.rowcount == 1

    def _commit_step(
        self, execution_id: str, generation: int, message: dict[str, Any]
    ) -> bool:
        published: list[dict[str, Any]] = []
        prompt_application: tuple[str, str] | None = None
        startproc_applications: list[tuple[str, int]] = []
        checkpoint_revision = 0
        checkpoint_step = 0
        with self._lock, self.session_factory() as session:
            execution = self._require_worker_epoch(
                session, execution_id, generation
            )
            if execution is None:
                return False
            if execution.state not in {
                "running",
                "pausing",
                "paused",
                "resuming",
                "prompting",
                "waiting",
                "aborting",
            }:
                return False
            step_index = message["step_index"]
            next_step = message["next_step"]
            if next_step <= execution.current_step:
                return False
            if step_index != execution.current_step or next_step != step_index + 1:
                raise ConflictError("worker checkpoint is not contiguous")

            prompt_resolution = message.get("prompt_resolution")
            checkpoint_variables = message.get("variables")
            if not isinstance(checkpoint_variables, dict):
                raise ConflictError("worker checkpoint variables are missing or invalid")
            if execution.ir_version == V08_IR_VERSION:
                known_handle_digests = {
                    value["token_sha256"]
                    for variables in (execution.variables, checkpoint_variables)
                    if type(variables) is dict
                    for value in variables.values()
                    if is_file_handle_reference(value)
                }
                current_step = execution.steps[step_index]
                if (
                    current_step.get("type") == "data_operation"
                    and current_step.get("operation") == "OPEN_FILE"
                ):
                    open_result = self._data_event(
                        session,
                        execution_id,
                        "procedure.data_result",
                        data_request_id(execution_id, step_index),
                    )
                    if open_result is not None and is_file_handle_reference(
                        open_result.payload.get("value")
                    ):
                        known_handle_digests.add(
                            open_result.payload["value"]["token_sha256"]
                        )
                if known_handle_digests and _contains_file_handle_token(
                    message, known_handle_digests
                ):
                    raise ConflictError(
                        "worker checkpoint attempts to persist a raw FileHandle token"
                    )
            if prompt_resolution is not None:
                prompt = session.get(Prompt, prompt_resolution["prompt_id"])
                operator_prompt = session.get(
                    OperatorPrompt, prompt_resolution["prompt_id"]
                )
                if operator_prompt is not None:
                    if (
                        operator_prompt.execution_id != execution_id
                        or operator_prompt.state != "SETTLED"
                        or type(operator_prompt.settlement_id) is not str
                        or len(operator_prompt.settlement_id)
                        != _LEGACY_EVENT_REFERENCE_LIMIT
                        or operator_prompt.settlement_id
                        != prompt_resolution.get("settlement_id")
                        or operator_prompt.settlement_outcome
                        != prompt_resolution.get("outcome")
                    ):
                        raise ConflictError(
                            "operator prompt checkpoint does not match its durable settlement"
                        )
                    if operator_prompt.settlement_outcome == "ANSWERED":
                        if canonical_hash(
                            {"value": operator_prompt.settled_value}
                        ) != canonical_hash({"value": prompt_resolution.get("response")}):
                            raise ConflictError(
                                "operator prompt checkpoint value does not match its settlement"
                            )
                    elif prompt_resolution.get("response") is not None:
                        raise ConflictError(
                            "non-answer prompt settlement cannot apply a response value"
                        )
                    if prompt is not None:
                        prompt.status = (
                            "answered"
                            if operator_prompt.settlement_outcome == "ANSWERED"
                            else "cancelled"
                        )
                        prompt.response = operator_prompt.settled_value
                        prompt.responded_by = operator_prompt.settled_by
                        prompt.responded_at = operator_prompt.settled_at
                    # Worker delivery IDs are namespaced (for example,
                    # ``settlement:<uuid>``) and exceed the immutable v0.2
                    # Event reference width.  The durable settlement UUID is
                    # the authoritative cause of this checkpoint.
                    causation_id = operator_prompt.settlement_id
                    prompt_application = (
                        operator_prompt.id,
                        operator_prompt.settlement_id,
                    )
                elif prompt is not None:
                    command = session.get(Command, prompt_resolution["command_id"])
                    if command is None or prompt.status != "responding":
                        raise ConflictError("prompt checkpoint references an unreserved prompt")
                    if (
                        prompt.response != prompt_resolution["response"]
                        or command.request_payload.get("prompt_id") != prompt.id
                    ):
                        raise ConflictError("prompt checkpoint does not match the reserved response")
                    prompt.status = "answered"
                    causation_id = command.id
                    completed = self._complete_command_in_session(
                        session,
                        execution,
                        command,
                        {"response": prompt_resolution["response"]},
                    )
                    if completed is not None:
                        published.append(event_dict(completed))
                else:
                    raise ConflictError("prompt checkpoint references an unknown prompt")
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            (
                                "prompt.answered"
                                if prompt_resolution.get("outcome", "ANSWERED") == "ANSWERED"
                                else "prompt.settled"
                            ),
                            {
                                "prompt_id": prompt_resolution["prompt_id"],
                                "settlement_id": prompt_resolution.get("settlement_id"),
                                "outcome": prompt_resolution.get("outcome", "ANSWERED"),
                                "response": prompt_resolution["response"],
                            },
                            source="worker",
                            causation_id=causation_id,
                        )
                    )
                )

            for effect in message["effects"]:
                if effect.get("event_type") == "procedure.startproc_settled":
                    payload = effect.get("payload") or {}
                    startproc_id = payload.get("startproc_id")
                    delivery_revision = payload.get("delivery_revision", 0)
                    if type(startproc_id) is str and type(delivery_revision) is int:
                        startproc_applications.append(
                            (startproc_id, delivery_revision)
                        )
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            effect["event_type"],
                            effect.get("payload", {}),
                            source=effect.get("source", "worker"),
                            severity=effect.get("severity", "info"),
                        )
                    )
                )
            prior_checkpoint_variables = (
                dict(execution.variables)
                if isinstance(execution.variables, dict)
                else {}
            )
            if execution.ir_version == V08_IR_VERSION:
                current_step = execution.steps[step_index]
                handle_names = {
                    candidate["target"]
                    for candidate in execution.steps
                    if candidate.get("type") == "data_operation"
                    and candidate.get("operation") == "OPEN_FILE"
                    and type(candidate.get("target")) is str
                }
                bound_handle_names = {
                    candidate["target"]
                    for candidate in execution.steps[:step_index]
                    if candidate.get("type") == "data_operation"
                    and candidate.get("operation") == "OPEN_FILE"
                    and type(candidate.get("target")) is str
                }
                if (
                    current_step.get("type") == "data_operation"
                    and current_step.get("operation") == "OPEN_FILE"
                    and type(current_step.get("target")) is str
                ):
                    bound_handle_names.add(current_step["target"])
                unknown_references = {
                    name
                    for name, value in checkpoint_variables.items()
                    if is_file_handle_reference(value)
                    and name not in bound_handle_names
                }
                if unknown_references:
                    raise ConflictError(
                        "worker checkpoint introduces an unbound FileHandle reference"
                    )
                expected_handles = {
                    name: prior_checkpoint_variables.get(name)
                    for name in bound_handle_names
                }
                if current_step.get("type") == "data_operation":
                    operation = current_step.get("operation")
                    request_id = data_request_id(execution_id, step_index)
                    result_event = self._data_event(
                        session,
                        execution_id,
                        "procedure.data_result",
                        request_id,
                    )
                    if result_event is not None and result_event.payload.get("outcome") != "OK":
                        raise ConflictError(
                            "worker checkpoint applies an unsuccessful data result"
                        )
                    if operation == "OPEN_FILE" and type(current_step.get("target")) is str:
                        target_name = current_step["target"]
                        if result_event is not None:
                            expected_handles[target_name] = validate_file_handle_reference(
                                result_event.payload.get("value"),
                                "$.procedure.data_result.value",
                                execution_id=execution_id,
                                worker_generation=generation,
                                creator_request_id=request_id,
                                require_open=True,
                            )
                    elif operation == "CLOSE_FILE":
                        reference = current_step.get("parameters", {}).get("handle", {})
                        target_name = reference.get("name")
                        if result_event is not None and target_name in handle_names:
                            expected_handles[target_name] = closed_file_handle_reference(
                                prior_checkpoint_variables.get(target_name)
                            )
                for name, expected in expected_handles.items():
                    if checkpoint_variables.get(name) != expected:
                        raise ConflictError(
                            "worker FileHandle checkpoint differs from durable data settlement"
                        )
            execution.current_step = next_step
            execution.variables = checkpoint_variables
            data_checkpoint: dict[str, Any] | None = None
            if execution.ir_version == V08_IR_VERSION:
                repository = self.data_repository
                if repository is None:
                    raise ConflictError("v0.8 data repository is unavailable")
                prior_args = prior_checkpoint_variables.get("ARGS", {})
                submitted_args = checkpoint_variables.get("ARGS", {})
                if submitted_args != prior_args:
                    raise ConflictError("v0.8 ARGS checkpoint differs from admission")
                ivars = checkpoint_variables.get("IVARS", {})
                if type(ivars) is not dict:
                    raise ConflictError("v0.8 IVARS checkpoint must be a map")
                local = {
                    name: value
                    for name, value in checkpoint_variables.items()
                    if name not in {"ARGS", "GLOBALS", "IVARS", "SHARED_DATA"}
                    and not is_file_handle_reference(value)
                }
                revisions = repository.execution_projection_revisions(
                    session, execution.id
                )
                checkpoint_request_id = "checkpoint." + hashlib.sha256(
                    f"{execution.id}\0{next_step}".encode("ascii")
                ).hexdigest()
                data_checkpoint = repository.stage_execution_checkpoint(
                    session,
                    execution,
                    ProcedureCallerBinding(
                        service_principal_id="procedure-runtime",
                        execution_id=execution.id,
                        worker_generation=generation,
                        deterministic_request_id=checkpoint_request_id,
                    ),
                    checkpoint_sequence=next_step,
                    expected_ivars_revision=revisions["IVARS"],
                    expected_local_revision=revisions["LOCAL"],
                    ivars=runtime_container_definitions(ivars),
                    local=runtime_container_definitions(local),
                )
            checkpoint_revision = execution.revision
            checkpoint_step = next_step
            checkpoint_payload: dict[str, Any] = {
                "next_step": next_step,
                "generation": generation,
                "variables": checkpoint_variables,
            }
            if data_checkpoint is not None:
                checkpoint_payload["data_projections"] = data_checkpoint[
                    "projections"
                ]
            published.append(
                event_dict(
                    self._add_event(
                        session,
                        execution,
                        "execution.checkpointed",
                        checkpoint_payload,
                        source="supervisor",
                    )
                )
            )
            session.commit()
            self._publish(execution_id, published)
        service = self.operator_service
        if service is not None and prompt_application is not None:
            acknowledge = getattr(
                service, "ack_prompt_settlement_application", None
            )
            if acknowledge is not None:
                try:
                    try:
                        acknowledge(
                            prompt_application[0],
                            prompt_application[1],
                            execution_revision=checkpoint_revision,
                            current_step=checkpoint_step,
                        )
                    except TypeError:
                        acknowledge(prompt_application[0], prompt_application[1])
                except Exception:
                    pass
                else:
                    with self._lock:
                        self._prompt_settlement_attempts.pop(
                            prompt_application[1], None
                        )
        if service is not None and startproc_applications:
            acknowledge = getattr(
                service, "ack_startproc_result_application", None
            )
            if acknowledge is not None:
                for startproc_id, delivery_revision in startproc_applications:
                    try:
                        try:
                            acknowledge(
                                startproc_id,
                                delivery_revision,
                                execution_revision=checkpoint_revision,
                                current_step=checkpoint_step,
                            )
                        except TypeError:
                            acknowledge(startproc_id, delivery_revision)
                    except Exception:
                        pass
        return True

    def _open_prompt(
        self,
        execution_id: str,
        generation: int,
        message: dict[str, Any],
    ) -> None:
        if "prompt_type" in message:
            self._open_typed_prompt(execution_id, generation, message)
            return

        # The legacy Prompt row is the compatibility anchor for IR 0.2/0.3, and
        # must exist before OperatorPrompt can reference it.  Do not publish the
        # prompt event yet: consumers must never observe a revision-bearing
        # prompt event before the fenced OperatorPrompt projection exists.
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = self._require_worker_epoch(
                session, execution_id, generation
            )
            if execution is None or execution.state not in {
                "running",
                "pausing",
                "prompting",
                "aborting",
            }:
                return
            prompt = session.get(Prompt, message["prompt_id"])
            if prompt is None:
                prompt = Prompt(
                    id=message["prompt_id"],
                    execution_id=execution_id,
                    step_index=message["step_index"],
                    question=message["question"],
                    choices=message["choices"],
                    default_choice=message["default"],
                )
                session.add(prompt)
                event_type = "prompt.opened"
            else:
                event_type = "prompt.reopened"
            session.commit()

        service = self.operator_service
        if service is None:
            raise ConflictError("legacy prompt requires the v0.6 operator service")
        from .operator_service import OperatorNotFoundError

        try:
            operator_prompt = service.ensure_legacy_prompt_projection(
                message["prompt_id"], worker_generation=generation
            )
        except OperatorNotFoundError:
            service.ensure_execution_projection(
                execution_id,
                actor="operator-runtime",
                worker_generation=generation,
            )
            operator_prompt = service.ensure_legacy_prompt_projection(
                message["prompt_id"], worker_generation=generation
            )

        terminal_outcome: str | None = None
        with self._lock, self.session_factory() as session:
            execution = self._require_worker_epoch(
                session, execution_id, generation
            )
            prompt = session.get(Prompt, message["prompt_id"])
            if execution is None or prompt is None:
                return
            if execution.state in TERMINAL_STATES:
                terminal_outcome = (
                    "ERROR" if execution.state == "failed" else "EXECUTION_TERMINATED"
                )
            elif execution.state not in {
                "running",
                "pausing",
                "prompting",
                "aborting",
            }:
                return
            if terminal_outcome is None:
                previous = execution.state
                transition_to_prompting = previous not in {"pausing", "aborting"}
                if transition_to_prompting and previous != "prompting":
                    execution.state = "prompting"
                    execution.revision += 1
                    published.append(
                        event_dict(
                            self._add_event(
                                session,
                                execution,
                                "execution.state_changed",
                                {
                                    "previous": previous,
                                    "state": "prompting",
                                    "revision": execution.revision,
                                },
                                source="worker",
                            )
                        )
                    )
                prompt_event = self._add_event(
                    session,
                    execution,
                    event_type,
                    {
                        "prompt_id": operator_prompt["id"],
                        "legacy_prompt_id": prompt.id,
                        "step_index": operator_prompt["step_index"],
                        "type": operator_prompt["type"],
                        "list_mode": operator_prompt["list_mode"],
                        "question": operator_prompt["question"],
                        "options": operator_prompt["options"],
                        "default": operator_prompt["default"],
                        "prompt_revision": operator_prompt["revision"],
                        "execution_revision": execution.revision,
                    },
                    source="worker",
                )
                published.append(event_dict(prompt_event))
                session.commit()
        if terminal_outcome is not None:
            service.settle_prompt_terminal(
                operator_prompt["id"], terminal_outcome
            )
            return
        self._publish(execution_id, published)

    def _open_typed_prompt(
        self,
        execution_id: str,
        generation: int,
        message: dict[str, Any],
    ) -> None:
        service = self.operator_service
        if service is None:
            raise ConflictError("typed prompt requires the v0.6 operator service")
        declaration = {
            "type": message["prompt_type"],
            "question": message["question"],
            "options": message.get("choices", []),
            "list_mode": message.get("list_mode"),
            "default": message.get("default"),
        }
        settings = {
            key: value
            for key, value in {
                "PROMPT_WARNING_DELAY": message.get("warning_delay_seconds"),
                "PROMPT_RESPONSE_TIMEOUT": message.get("response_timeout_seconds"),
                "NO_CONTROLLER_GRACE": message.get("no_controller_grace_seconds"),
            }.items()
            if value is not None
        }
        from .operator_service import OperatorNotFoundError

        try:
            prompt = service.open_typed_prompt(
                execution_id,
                message["prompt_id"],
                message["step_index"],
                declaration,
                settings,
                worker_generation=generation,
            )
        except OperatorNotFoundError:
            # Ensure a legacy-created v0.6 execution obtains its immutable
            # catalog/operator projection before the prompt is retried.
            service.ensure_execution_projection(
                execution_id,
                actor="operator-runtime",
                worker_generation=generation,
            )
            prompt = service.open_typed_prompt(
                execution_id,
                message["prompt_id"],
                message["step_index"],
                declaration,
                settings,
                worker_generation=generation,
            )
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            execution = self._require_worker_epoch(
                session, execution_id, generation
            )
            if execution is None or execution.state not in {
                "running",
                "pausing",
                "prompting",
                "aborting",
            }:
                return
            previous = execution.state
            transition = previous not in {"pausing", "aborting"}
            if transition and previous != "prompting":
                execution.state = "prompting"
                execution.revision += 1
            published.append(
                event_dict(
                    self._add_event(
                        session,
                        execution,
                        "prompt.opened" if prompt["state"] == "OPEN" else "prompt.settled",
                        {
                            "prompt_id": prompt["id"],
                            "step_index": prompt["step_index"],
                            "type": prompt["type"],
                            "question": prompt["question"],
                            "options": prompt["options"],
                            "default": prompt["default"],
                            "prompt_revision": prompt["revision"],
                            "execution_revision": execution.revision,
                        },
                        source="worker",
                    )
                )
            )
            if transition and previous != "prompting":
                published.append(
                    event_dict(
                        self._add_event(
                            session,
                            execution,
                            "execution.state_changed",
                            {
                                "previous": previous,
                                "state": "prompting",
                                "revision": execution.revision,
                            },
                            source="worker",
                        )
                    )
                )
            session.commit()
        self._publish(execution_id, published)

    def _set_worker_state(
        self,
        execution_id: str,
        state: str,
        command_id: str | None = None,
        generation: int | None = None,
    ) -> None:
        if state == "aborted" and command_id is not None:
            with self.session_factory() as session:
                operator_command = session.get(OperatorCommand, command_id)
                operator_abort = (
                    operator_command is not None
                    and operator_command.command_type in {"ABORT", "STOP"}
                )
                effect_certainty = (
                    operator_command.effect_certainty_before
                    if operator_abort
                    else "NO_EFFECT"
                )
            if operator_abort or self._blocking_startproc_operations(execution_id):
                self._set_state(
                    execution_id,
                    "aborting",
                    source="worker",
                    command_id=None,
                    expected_worker_generation=generation,
                )
                self._start_abort_cleanup_barrier(
                    execution_id,
                    command_id,
                    effect_certainty=effect_certainty,
                )
                return
        allowed_previous = {
            "running": {
                "starting",
                "recovering",
                "resuming",
                "prompting",
                "waiting",
                "paused",
                "running",
            },
            "waiting": {"running", "paused", "waiting"},
            "paused": {"pausing", "running", "waiting", "prompting", "paused"},
            "prompting": {"running", "paused", "prompting"},
            "aborted": ACTIVE_STATES | {"waiting", "aborted"},
            "completed": {"running", "waiting", "prompting", "paused", "completed"},
            "failed": ACTIVE_STATES | {"waiting", "failed"},
        }
        pending_command_error: str | None = None
        with self._lock:
            with self.session_factory() as session:
                execution = session.get(Execution, execution_id)
                if execution is None or execution.state in TERMINAL_STATES:
                    return
                previous = execution.state
                if previous not in allowed_previous.get(state, set()):
                    if state not in TERMINAL_STATES or previous not in {
                        "pausing",
                        "resuming",
                        "aborting",
                    }:
                        return
                    pending_command_error = (
                        f"worker reached {state} before command dispatch"
                    )
        self._set_state(
            execution_id,
            state,
            source="worker",
            command_id=command_id,
            pending_command_error=pending_command_error,
            expected_worker_generation=generation,
        )
        if command_id is not None:
            self._settle_operator_command(
                execution_id,
                {
                    "command_id": command_id,
                    "result": {"state": state.upper()},
                    "effect_certainty": "NO_EFFECT",
                },
                settled=True,
                generation=generation,
            )

    def _set_state(
        self,
        execution_id: str,
        state: str,
        source: str,
        command_id: str | None = None,
        preserve_open_prompts: bool = False,
        pending_command_error: str | None = None,
        expected_worker_generation: int | None = None,
    ) -> None:
        published: list[dict[str, Any]] = []
        terminal_typed_prompts: list[tuple[str, str]] = []
        with self._lock, self.session_factory() as session:
            execution = (
                self._require_worker_epoch(
                    session, execution_id, expected_worker_generation
                )
                if expected_worker_generation is not None
                else session.get(Execution, execution_id)
            )
            if execution is None:
                if expected_worker_generation is not None:
                    raise StaleWorkerMessage(
                        "worker generation is no longer current"
                    )
                return
            previous = execution.state
            if previous in TERMINAL_STATES and previous != state:
                return
            if previous != state:
                execution.state = state
                execution.revision += 1
                state_payload: dict[str, Any] = {
                    "previous": previous,
                    "state": state,
                    "revision": execution.revision,
                }
                if pending_command_error is not None:
                    state_payload["reason"] = pending_command_error
                state_event = self._add_event(
                    session,
                    execution,
                    "execution.state_changed",
                    state_payload,
                    source=source,
                    causation_id=command_id,
                )
                published.append(event_dict(state_event))
                if state in TERMINAL_STATES | {"recovery_required"}:
                    if state != "recovery_required":
                        typed_prompts = session.scalars(
                            select(OperatorPrompt).where(
                                OperatorPrompt.execution_id == execution_id,
                                OperatorPrompt.state == "OPEN",
                            )
                        ).all()
                        typed_outcome = (
                            "ERROR" if state == "failed" else "EXECUTION_TERMINATED"
                        )
                        terminal_typed_prompts.extend(
                            (prompt.id, typed_outcome) for prompt in typed_prompts
                        )
                    active_prompts = session.scalars(
                        select(Prompt).where(
                            Prompt.execution_id == execution_id,
                            Prompt.status.in_(["open", "responding"]),
                        )
                    ).all()
                    for prompt in active_prompts:
                        if (
                            state == "recovery_required"
                            and preserve_open_prompts
                            and prompt.status == "open"
                        ):
                            continue
                        was_responding = prompt.status == "responding"
                        if state == "aborted":
                            prompt.status = "cancelled"
                            event_type = "prompt.cancelled"
                            reason = "execution_aborted"
                        elif state == "completed":
                            prompt.status = "closed"
                            event_type = "prompt.closed"
                            reason = "execution_completed"
                        else:
                            prompt.status = "interrupted"
                            event_type = "prompt.interrupted"
                            reason = (
                                "worker_recovery_required"
                                if state == "recovery_required"
                                else "execution_failed"
                            )
                        prompt.responded_at = datetime.now(timezone.utc)
                        prompt_event = self._add_event(
                            session,
                            execution,
                            event_type,
                            {"prompt_id": prompt.id, "reason": reason},
                            source="supervisor",
                            severity="warning" if state != "completed" else "info",
                            causation_id=command_id,
                        )
                        published.append(event_dict(prompt_event))
                        if was_responding and state != "completed":
                            pending_responses = session.scalars(
                                select(Command).where(
                                    Command.execution_id == execution_id,
                                    Command.command_type == "prompt_response",
                                    Command.status == "accepted",
                                )
                            ).all()
                            for pending in pending_responses:
                                if pending.request_payload.get("prompt_id") != prompt.id:
                                    continue
                                pending.status = "failed"
                                pending.result_payload = {
                                    "error": f"prompt response interrupted by {state}"
                                }
                                pending.completed_at = datetime.now(timezone.utc)
                                failed_event = self._add_event(
                                    session,
                                    execution,
                                    "command.failed",
                                    {
                                        "command_id": pending.id,
                                        "error": pending.result_payload["error"],
                                    },
                                    source="supervisor",
                                    severity="error",
                                    correlation_id=pending.correlation_id,
                                    causation_id=pending.id,
                                )
                                published.append(event_dict(failed_event))
            if state in TERMINAL_STATES | {"recovery_required"}:
                pending_commands = session.scalars(
                    select(Command).where(
                        Command.execution_id == execution_id,
                        Command.status == "accepted",
                    )
                ).all()
                error = pending_command_error or (
                    f"execution entered {state} before command completion"
                )
                for pending in pending_commands:
                    if command_id is not None and pending.id == command_id:
                        continue
                    failed_event = self._fail_command_in_session(
                        session, execution, pending, error
                    )
                    if failed_event is not None:
                        published.append(event_dict(failed_event))
            revision = execution.revision
            if command_id is not None:
                command = session.get(Command, command_id)
                if command is not None and command.execution_id == execution_id:
                    completed = self._complete_command_in_session(
                        session, execution, command, {"state": state, "revision": revision}
                    )
                    if completed is not None:
                        published.append(event_dict(completed))
            session.commit()
            self._publish(execution_id, published)
        settle_terminal = getattr(
            self.operator_service, "settle_prompt_terminal", None
        )
        if settle_terminal is not None:
            for prompt_id, outcome in terminal_typed_prompts:
                settle_terminal(prompt_id, outcome)
        if previous != state:
            self._reconcile_observation_lifecycle(
                execution_id, previous_state=previous, state=state
            )

    def _reconcile_observation_lifecycle(
        self,
        execution_id: str,
        *,
        previous_state: str,
        state: str,
    ) -> None:
        runtime = getattr(self, "observation_runtime", None)
        if runtime is None:
            return
        callback = None
        if state in TERMINAL_STATES:
            callback = getattr(runtime, "cancel_execution", None)
        elif state in {"paused", "recovery_required"}:
            callback = getattr(runtime, "interrupt_execution", None)
        elif previous_state in {"paused", "pausing", "recovery_required"} and state in {
            "running",
            "resuming",
            "recovering",
            "waiting",
            "prompting",
        }:
            callback = getattr(runtime, "resume_execution", None)
        if callable(callback):
            try:
                callback(execution_id)
            except Exception:
                # The durable recovery loop re-derives execution lifecycle state.
                pass

    def _complete_command(self, command_id: str, result: dict[str, Any]) -> None:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            command = session.get(Command, command_id)
            if command is None or command.status != "accepted":
                return
            execution_id = command.execution_id
            execution = session.get(Execution, execution_id)
            if execution is None:
                return
            event = self._complete_command_in_session(session, execution, command, result)
            session.commit()
            if event is not None:
                published = [event_dict(event)]
            self._publish(execution_id, published)

    def _complete_command_in_session(
        self,
        session: Session,
        execution: Execution,
        command: Command,
        result: dict[str, Any],
    ) -> Event | None:
        if command.status != "accepted":
            return None
        command.status = "completed"
        command.result_payload = result
        command.completed_at = datetime.now(timezone.utc)
        return self._add_event(
            session,
            execution,
            "command.completed",
            {"command_id": command.id, "result": result},
            source="supervisor",
            correlation_id=command.correlation_id,
            causation_id=command.id,
        )

    def _fail_command(self, command_id: str, message: str) -> None:
        published: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            command = session.get(Command, command_id)
            if command is None or command.status != "accepted":
                return
            execution_id = command.execution_id
            execution = session.get(Execution, execution_id)
            if execution is None:
                return
            event = self._fail_command_in_session(session, execution, command, message)
            session.commit()
            if event is not None:
                published = [event_dict(event)]
            self._publish(execution_id, published)

    def _fail_command_in_session(
        self,
        session: Session,
        execution: Execution,
        command: Command,
        message: str,
    ) -> Event | None:
        if command.status != "accepted":
            return None
        command.status = "failed"
        command.result_payload = {"error": message}
        command.completed_at = datetime.now(timezone.utc)
        return self._add_event(
            session,
            execution,
            "command.failed",
            {"command_id": command.id, "error": message},
            source="supervisor",
            severity="error",
            correlation_id=command.correlation_id,
            causation_id=command.id,
        )

    def append_event(
        self,
        execution_id: str,
        event_type: str,
        payload: dict[str, Any],
        source: str,
        severity: str = "info",
        correlation_id: str | None = None,
        causation_id: str | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            execution = (
                self._require_worker_epoch(
                    session, execution_id, worker_generation
                )
                if worker_generation is not None
                else session.get(Execution, execution_id)
            )
            if execution is None:
                if worker_generation is not None:
                    raise StaleWorkerMessage(
                        "worker generation is no longer current"
                    )
                raise NotFoundError("execution not found")
            event = self._add_event(
                session,
                execution,
                event_type,
                payload,
                source,
                severity,
                correlation_id,
                causation_id,
            )
            session.commit()
            serialized = event_dict(event)
            # Commit and publication share the supervisor lock so live subscribers
            # observe the same per-execution order as the durable event log.
            self.hub.publish(execution_id, serialized)
        return serialized

    @staticmethod
    def _add_event(
        session: Session,
        execution: Execution,
        event_type: str,
        payload: dict[str, Any],
        source: str,
        severity: str = "info",
        correlation_id: str | None = None,
        causation_id: str | None = None,
    ) -> Event:
        event = Event(
            execution_id=execution.id,
            sequence=execution.next_sequence,
            event_type=event_type,
            source=source,
            severity=severity,
            correlation_id=_legacy_event_reference(correlation_id),
            causation_id=_legacy_event_reference(causation_id),
            payload=payload,
        )
        execution.next_sequence += 1
        session.add(event)
        session.flush()
        return event

    def _publish(self, execution_id: str, events: list[dict[str, Any]]) -> None:
        for event in events:
            self.hub.publish(execution_id, event)

    def _invalidate_worker(self, execution_id: str) -> bool:
        with self._lock:
            handle = self._workers.get(execution_id)
        if handle is None:
            return False
        with handle.dispatch_lock:
            with self._lock:
                if self._workers.get(execution_id) is not handle:
                    return False
            fenced = self._fence_worker_epoch(execution_id, handle)
            with self._lock:
                if self._workers.get(execution_id) is not handle:
                    return False
                handle.intentional_stop = True
            if not self._terminate_worker(handle):
                raise RuntimeError("worker termination failed; generation remains fenced")
            self._cleanup_worker(execution_id, handle)
            # A false CAS result means this exact mapped handle was already
            # durably fenced. Successful removal still owns the invalidation.
            return True

    @staticmethod
    def _terminate_worker(handle: WorkerHandle) -> bool:
        try:
            if not handle.process.is_alive():
                return True
        except (AssertionError, AttributeError, OSError, ValueError):
            return False
        try:
            handle.process.terminate()
            handle.process.join(timeout=2)
        except (AssertionError, AttributeError, OSError, ValueError):
            pass
        try:
            if handle.process.is_alive():
                handle.process.kill()
                handle.process.join(timeout=2)
        except (AssertionError, AttributeError, OSError, ValueError):
            pass
        try:
            return not handle.process.is_alive()
        except (AssertionError, AttributeError, OSError, ValueError):
            return False

    def _cleanup_worker(self, execution_id: str, handle: WorkerHandle) -> None:
        with handle.dispatch_lock:
            with self._lock:
                if self._workers.get(execution_id) is not handle:
                    return
                self._workers.pop(execution_id, None)
            for worker_queue in (handle.control, handle.output):
                try:
                    worker_queue.close()
                    worker_queue.cancel_join_thread()
                except (OSError, ValueError):
                    pass
            try:
                if not handle.process.is_alive():
                    handle.process.close()
            except (AssertionError, AttributeError, ValueError):
                pass

    def events_after(self, execution_id: str, after: int, limit: int) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            if session.get(Execution, execution_id) is None:
                raise NotFoundError("execution not found")
            events = session.scalars(
                select(Event)
                .where(Event.execution_id == execution_id, Event.sequence > after)
                .order_by(Event.sequence)
                .limit(limit)
            ).all()
            return [event_dict(event) for event in events]

    def close(self) -> None:
        with self._lock:
            self._closed = True
            handles = tuple(self._workers.items())
        for execution_id, handle in handles:
            with handle.dispatch_lock:
                with self._lock:
                    if self._workers.get(execution_id) is not handle:
                        continue
                self._fence_worker_epoch(execution_id, handle)
                with self._lock:
                    if self._workers.get(execution_id) is not handle:
                        continue
                    handle.intentional_stop = True
                self._terminate_worker(handle)
                self._cleanup_worker(execution_id, handle)

        with self.session_factory() as session:
            execution_ids = set(
                session.scalars(
                    select(Execution.id).where(Execution.state.in_(ACTIVE_STATES))
                ).all()
            )
            execution_ids.update(
                session.scalars(
                    select(Command.execution_id)
                    .where(Command.status == "accepted")
                    .distinct()
                ).all()
            )
            states = {
                execution_id: session.get(Execution, execution_id).state
                for execution_id in execution_ids
                if session.get(Execution, execution_id) is not None
            }
        for execution_id, state in states.items():
            target_state = (
                state
                if state in TERMINAL_STATES | {"recovery_required"}
                else "recovery_required"
            )
            self._set_state(
                execution_id,
                target_state,
                source="supervisor",
                preserve_open_prompts=target_state == "recovery_required",
                pending_command_error="supervisor stopped before command completion",
            )
