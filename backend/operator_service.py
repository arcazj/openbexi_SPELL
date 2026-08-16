from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Iterable

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .ir_v06 import (
    V06ValidationError,
    normalize_prompt_value,
    validate_operator_command,
    validate_prompt_declaration,
    validate_user_action,
    validate_user_action_block,
)
from .models import Event, Execution, Prompt
from .operator_models import (
    ControllerLease,
    ControllerHandover,
    ExecutionOperatorState,
    InspectionEditOperation,
    MonitorSubscription,
    OperatorAuditEvent,
    OperatorBreakpoint,
    OperatorCommand,
    OperatorContext,
    OperatorPrompt,
    OperatorRequest,
    OperatorUserAction,
    OperatorUserActionInvocation,
    ParentChildLink,
    ProcedureCatalogEntry,
    ProcedureCatalogRevision,
    ProcedureSchedule,
    PromptAttempt,
    ScheduleOccurrence,
    StartProcOperation,
    new_id,
)
from .operator_serialization import (
    catalog_entry_dict,
    catalog_revision_dict,
    command_dict,
    context_dict,
    lease_dict,
    monitor_dict,
    operator_state_dict,
    prompt_attempt_dict,
    prompt_dict,
    relationship_dict,
    schedule_dict,
)
from .procedure_parser import Procedure, ProcedureCatalog
from .serialization import execution_dict


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_ABSOLUTE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATH = re.compile(
    r"(?:^|[._-])(secret|password|passwd|token|credential|private[_-]?key|api[_-]?key)(?:$|[._-])",
    re.IGNORECASE,
)
_PROMPT_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,})\b"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
    re.compile(r"\b(?:password|passwd|secret|token|credential|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE),
)
_TERMINAL_COMMAND_STATES = {
    "SETTLED",
    "REJECTED",
    "CANCELLED",
    "SUPERSEDED",
    "FAILED",
}
_COMMAND_TRANSITIONS = {
    "RECEIVED": {"VALIDATING", "REJECTED", "FAILED"},
    "VALIDATING": {"ACCEPTED", "REJECTED", "FAILED"},
    "ACCEPTED": {"WAITING_SAFE_POINT", "APPLYING", "CANCELLED", "SUPERSEDED", "FAILED"},
    "WAITING_SAFE_POINT": {"APPLYING", "CANCELLED", "SUPERSEDED", "FAILED"},
    "APPLYING": {"RECONCILING", "SETTLED", "FAILED"},
    "RECONCILING": {"SETTLED", "FAILED"},
    "SETTLED": set(),
    "REJECTED": set(),
    "CANCELLED": set(),
    "SUPERSEDED": set(),
    "FAILED": set(),
}
_COMMAND_MATRIX = {
    "RUN": ({"PAUSED", "INTERRUPTED"}, "REQUIRED"),
    "STEP": ({"PAUSED", "INTERRUPTED"}, "REQUIRED"),
    "STEP_OVER": ({"PAUSED", "INTERRUPTED"}, "REQUIRED"),
    "PAUSE": ({"RUNNING", "WAITING", "PROMPT"}, "REQUIRED"),
    "SKIP": ({"PAUSED", "INTERRUPTED"}, "REQUIRED"),
    "GOTO": ({"PAUSED"}, "REQUIRED"),
    "RELOAD": ({"FINISHED", "ABORTED", "ERROR"}, "NOT_REQUIRED"),
    "ABORT": (
        {
            "REQUESTED",
            "VALIDATING",
            "ADMISSION_PENDING",
            "LOADING",
            "PAUSED",
            "RUNNING",
            "WAITING",
            "PROMPT",
            "INTERRUPTED",
            "SUSPENDED",
            "RECOVERING",
        },
        "REQUIRED_AFTER_ACCEPTANCE",
    ),
    "RECOVER": ({"ERROR"}, "NOT_REQUIRED"),
    "BACKGROUND": ({"PAUSED", "RUNNING", "WAITING", "INTERRUPTED"}, "REQUIRED"),
    "STOP": (
        {
            "REQUESTED",
            "VALIDATING",
            "ADMISSION_PENDING",
            "LOADING",
            "PAUSED",
            "RUNNING",
            "WAITING",
            "PROMPT",
            "INTERRUPTED",
            "SUSPENDED",
            "RECOVERING",
        },
        "REQUIRED_AFTER_ACCEPTANCE",
    ),
    "KILL": (set(), "NOT_APPLICABLE"),
}
_LEGACY_STATE_PROJECTION = {
    "created": "REQUESTED",
    "validated": "VALIDATING",
    "ready": "PAUSED",
    "starting": "LOADING",
    "running": "RUNNING",
    "pausing": "RUNNING",
    "paused": "PAUSED",
    "resuming": "RUNNING",
    "prompting": "PROMPT",
    "aborting": "STOPPING",
    "recovering": "RECOVERING",
    "recovery_required": "SUSPENDED",
    "completed": "FINISHED",
    "aborted": "ABORTED",
    "failed": "ERROR",
}
_PROMPT_TYPES = {
    "OK": ("FIXED_CHOICE", ["OK"]),
    "CANCEL": ("FIXED_CHOICE", ["CANCEL"]),
    "OK_CANCEL": ("FIXED_CHOICE", ["OK", "CANCEL"]),
    "YES": ("FIXED_CHOICE", ["YES"]),
    "NO": ("FIXED_CHOICE", ["NO"]),
    "YES_NO": ("FIXED_CHOICE", ["YES", "NO"]),
    "ALPHA": ("TEXT", []),
    "NUM": ("NUMBER", []),
    "DATE": ("DATE", []),
    "LIST": ("LIST", []),
}


class OperatorServiceError(RuntimeError):
    code = "OPERATOR_SERVICE_ERROR"

    def __init__(self, message: str, *, current: dict[str, Any] | None = None):
        super().__init__(message)
        self.current = current


class OperatorNotFoundError(OperatorServiceError):
    code = "NOT_FOUND"


class OperatorConflictError(OperatorServiceError):
    code = "CONFLICT"


class OperatorStaleWorkerError(OperatorConflictError):
    code = "STALE_WORKER_GENERATION"


class OperatorAuthorizationError(OperatorServiceError):
    code = "FORBIDDEN"


class OperatorValidationError(OperatorServiceError):
    code = "VALIDATION_FAILED"


class PromptSecretMaterialError(OperatorValidationError):
    code = "PROMPT_SECRET_MATERIAL_REJECTED"


class _AfterServiceUnlock:
    __slots__ = ("callback",)

    def __init__(self, callback: Callable[[], dict[str, Any]]) -> None:
        self.callback = callback


class UserActionArgumentsUnsupportedError(OperatorValidationError):
    code = "USER_ACTION_ARGUMENTS_UNSUPPORTED"


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise OperatorValidationError("value is not canonical bounded JSON data") from exc
    return hashlib.sha256(encoded).hexdigest()


def _stored_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _bounded(value: str, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise OperatorValidationError(f"{label} is invalid")
    return value


def _identifier(value: str, label: str) -> str:
    value = _bounded(value, label)
    if not _IDENTIFIER.fullmatch(value):
        raise OperatorValidationError(f"{label} is not a bounded identifier")
    return value


def _idempotency_key(value: str) -> str:
    return _bounded(value, "idempotency_key", 200)


def _validate_literal(value: Any) -> Any:
    count = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal count
        count += 1
        if count > 2048 or depth > 8:
            raise OperatorValidationError("typed literal exceeds its container bound")
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            if len(str(abs(item))) > 1024:
                raise OperatorValidationError("integer typed literal exceeds its digit bound")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise OperatorValidationError("numeric typed literal must be finite")
            return item
        if type(item) is str:
            if len(item) > 100_000:
                raise OperatorValidationError("string typed literal exceeds its bound")
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise OperatorValidationError(
                    "string typed literal is not valid UTF-8"
                ) from exc
            return item
        if type(item) is list:
            return [visit(child, depth + 1) for child in item]
        if type(item) is dict:
            result: dict[str, Any] = {}
            for key, child in item.items():
                if type(key) is not str or not key or len(key) > 200:
                    raise OperatorValidationError("typed map keys must be bounded strings")
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise OperatorValidationError(
                        "typed map key is not valid UTF-8"
                    ) from exc
                result[key] = visit(child, depth + 1)
            return result
        raise OperatorValidationError("typed literal contains an unsupported value")

    result = visit(value, 0)
    if len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("utf-8")) > 1_000_000:
        raise OperatorValidationError("typed literal exceeds its encoded byte bound")
    return result


def _reject_prompt_secret_material(value: Any, path: str = "value") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _SECRET_PATH.search(child_path) and child is not None and child != "":
                raise PromptSecretMaterialError(
                    "prompt value contains prohibited secret material"
                )
            _reject_prompt_secret_material(child, child_path)
        return
    if isinstance(value, list):
        for child in value:
            _reject_prompt_secret_material(child, path)
        return
    if isinstance(value, str) and any(
        pattern.search(value) for pattern in _PROMPT_SECRET_PATTERNS
    ):
        raise PromptSecretMaterialError(
            "prompt value contains prohibited secret material"
        )


class OperatorService:
    """Durable local-simulator boundary for v0.6 operator resources."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        catalog: ProcedureCatalog,
        *,
        execution_starter: Callable[..., Execution] | None = None,
        prompt_settlement_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.catalog = catalog
        self.execution_starter = execution_starter
        self.prompt_settlement_sink = prompt_settlement_sink
        self._lock = threading.RLock()
        self._legacy_compatibility_inflight: set[str] = set()
        self._stop = threading.Event()
        self._reconciler: threading.Thread | None = None

    @staticmethod
    def project_execution_state(legacy_state: str) -> str:
        return _LEGACY_STATE_PROJECTION.get(legacy_state, "ERROR")

    @staticmethod
    def _database_now(session: Session) -> datetime:
        value = session.scalar(select(func.current_timestamp()))
        if not isinstance(value, datetime):
            raise OperatorServiceError("database clock did not return a timestamp")
        return _stored_utc(value)  # type: ignore[return-value]

    @staticmethod
    def _require_worker_epoch(
        session: Session,
        execution_id: str,
        worker_generation: int | None,
    ) -> None:
        if worker_generation is None:
            return
        if type(worker_generation) is not int or worker_generation < 1:
            raise OperatorValidationError("worker generation is invalid")
        claimed = session.execute(
            update(Execution)
            .where(
                Execution.id == execution_id,
                Execution.worker_generation == worker_generation,
            )
            .values(worker_generation=worker_generation)
        )
        if claimed.rowcount != 1:
            raise OperatorStaleWorkerError("worker generation is no longer current")

    @staticmethod
    def _lease_view(
        lease: ControllerLease,
        *,
        actor: str | None = None,
        session_id: str | None = None,
        client_instance_key_id: str | None = None,
    ) -> dict[str, Any]:
        result = lease_dict(lease)
        if actor is None:
            return result
        held_by_current_session = (
            lease.holder_subject_id == actor
            and session_id is not None
            and client_instance_key_id is not None
            and lease.holder_session_id == session_id
            and lease.client_instance_key_id == client_instance_key_id
        )
        result["held_by_current_session"] = held_by_current_session
        if not held_by_current_session:
            result.pop("holder_session_id", None)
            result.pop("client_instance_key_id", None)
            result.pop("control_fencing_token", None)
        return result

    @staticmethod
    def _has_mutation_reservation(
        session: Session,
        execution_id: str,
        *,
        command_id: str | None = None,
        invocation_id: str | None = None,
        edit_id: str | None = None,
    ) -> bool:
        """Return whether another operator mutation owns this execution's apply slot.

        Callers hold the execution projection row with ``FOR UPDATE``. That row is
        the cross-table mutex on PostgreSQL; ``self._lock`` provides the equivalent
        serialization for SQLite.
        """

        command_query = select(OperatorCommand.id).where(
            OperatorCommand.execution_id == execution_id,
            OperatorCommand.state == "APPLYING",
        )
        if command_id is not None:
            command_query = command_query.where(OperatorCommand.id != command_id)
        if session.scalar(command_query.limit(1)) is not None:
            return True

        invocation_query = select(OperatorUserActionInvocation.id).where(
            OperatorUserActionInvocation.execution_id == execution_id,
            OperatorUserActionInvocation.state == "APPLYING",
        )
        if invocation_id is not None:
            invocation_query = invocation_query.where(
                OperatorUserActionInvocation.id != invocation_id
            )
        if session.scalar(invocation_query.limit(1)) is not None:
            return True

        edit_query = select(InspectionEditOperation.id).where(
            InspectionEditOperation.execution_id == execution_id,
            InspectionEditOperation.state == "APPLYING",
        )
        if edit_id is not None:
            edit_query = edit_query.where(InspectionEditOperation.id != edit_id)
        return session.scalar(edit_query.limit(1)) is not None

    def bootstrap(self) -> None:
        self.sync_catalog(actor="operator-bootstrap")
        self.reconcile_once()

    def start(self, interval_seconds: float = 0.25) -> None:
        if self._reconciler is not None and self._reconciler.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval_seconds):
                try:
                    self.reconcile_once()
                except Exception:
                    # Each resource transition is transactional. A later pass retries
                    # unresolved resources by their stable identity.
                    continue

        self._reconciler = threading.Thread(
            target=loop, name="spell-v06-operator-reconciler", daemon=True
        )
        self._reconciler.start()

    def close(self) -> None:
        self._stop.set()
        if self._reconciler is not None:
            self._reconciler.join(timeout=2)
            self._reconciler = None

    def sync_catalog(self, *, actor: str) -> list[dict[str, Any]]:
        actor = _bounded(actor, "actor")
        procedures = self.catalog.list()
        with self._lock, self.session_factory() as session:
            now = self._database_now(session)
            for procedure in procedures:
                catalog_id = "pc-" + hashlib.sha256(
                    procedure.id.encode("utf-8")
                ).hexdigest()[:32]
                bundle_digest = canonical_digest(
                    {
                        "procedure_ref": procedure.id,
                        "source_digest": procedure.sha256,
                        "ir_version": procedure.ir_version,
                        "steps": list(procedure.steps),
                    }
                )
                entry = session.get(ProcedureCatalogEntry, catalog_id, with_for_update=True)
                if entry is None:
                    entry = ProcedureCatalogEntry(
                        id=catalog_id,
                        procedure_ref=procedure.id,
                        name=procedure.name,
                        description=procedure.description,
                        entrypoint=procedure.path.name,
                        current_revision=1,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(entry)
                    next_revision = 1
                else:
                    current = session.scalar(
                        select(ProcedureCatalogRevision).where(
                            ProcedureCatalogRevision.catalog_id == entry.id,
                            ProcedureCatalogRevision.revision == entry.current_revision,
                        )
                    )
                    if current is not None and current.bundle_digest == bundle_digest:
                        continue
                    next_revision = entry.current_revision + 1
                    entry.current_revision = next_revision
                    entry.name = procedure.name
                    entry.description = procedure.description
                    entry.entrypoint = procedure.path.name
                    entry.updated_at = now
                revision = ProcedureCatalogRevision(
                    id=new_id(),
                    catalog_id=catalog_id,
                    revision=next_revision,
                    source_digest=procedure.sha256,
                    bundle_digest=bundle_digest,
                    ir_version=procedure.ir_version,
                    source=procedure.source,
                    steps=list(procedure.steps),
                    properties={
                        "name": procedure.name,
                        "description": procedure.description,
                        "entrypoint": procedure.path.name,
                        "step_count": len(procedure.steps),
                    },
                    created_by=actor,
                    created_at=now,
                )
                session.add(revision)
                self._audit(
                    session,
                    event_type="catalog.revision_registered",
                    aggregate_type="procedure_catalog",
                    aggregate_id=catalog_id,
                    actor=actor,
                    payload={
                        "catalog_id": catalog_id,
                        "revision": next_revision,
                        "source_digest": procedure.sha256,
                        "bundle_digest": bundle_digest,
                    },
                    created_at=now,
                )
            session.commit()
        return self.list_catalog(sync=False)

    def list_contexts(self) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            rows = session.scalars(select(OperatorContext).order_by(OperatorContext.id)).all()
            return [context_dict(item) for item in rows]

    def _normalize_prompt_settings(self, settings: dict[str, Any]) -> dict[str, Any]:
        settings = _validate_literal(settings)
        allowed = {
            "PROMPT_WARNING_DELAY": 86_400,
            "PROMPT_RESPONSE_TIMEOUT": 604_800,
            "NO_CONTROLLER_GRACE": 604_800,
        }
        if not settings or set(settings) - set(allowed):
            raise OperatorValidationError("prompt settings contain unsupported keys")
        result: dict[str, Any] = {}
        for key, value in settings.items():
            duration = self._optional_duration(value, key, maximum=allowed[key])
            result[key] = duration if duration else None
        return result

    def update_context_settings(
        self,
        context_id: str,
        *,
        settings: dict[str, Any],
        expected_revision: int,
        actor: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        context_id = _identifier(context_id, "context_id")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        patch = self._normalize_prompt_settings(settings)
        digest = canonical_digest(
            {
                "context_id": context_id,
                "settings": patch,
                "expected_revision": expected_revision,
                "reason": reason,
            }
        )
        scope = f"context-settings:{context_id}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=digest,
            )
            if replay is not None:
                return replay
            context = session.get(OperatorContext, context_id, with_for_update=True)
            if context is None:
                raise OperatorNotFoundError("operator context not found")
            if context.revision != expected_revision:
                raise OperatorConflictError(
                    "context revision conflict", current={"context": context_dict(context)}
                )
            context.settings = {**context.settings, **patch}
            context.revision += 1
            now = self._database_now(session)
            context.updated_at = now
            response = context_dict(context)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=digest,
                resource_type="operator_context",
                resource_id=context.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="context.prompt_settings_updated",
                aggregate_type="operator_context",
                aggregate_id=context.id,
                actor=actor,
                payload={"revision": context.revision, "settings": patch, "reason": reason},
                created_at=now,
            )
            session.commit()
            return response

    def update_execution_settings(
        self,
        execution_id: str,
        *,
        settings: dict[str, Any],
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        patch = self._normalize_prompt_settings(settings)
        digest = canonical_digest(
            {
                "execution_id": execution_id,
                "settings": patch,
                "expected_execution_revision": expected_execution_revision,
                "reason": reason,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
            }
        )
        scope = f"execution-settings:{execution_id}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=digest,
            )
            if replay is not None:
                return replay
            projection, _lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id)
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            projection.settings = {**projection.settings, **patch}
            projection.revision += 1
            now = self._database_now(session)
            projection.updated_at = now
            response = operator_state_dict(projection)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=digest,
                resource_type="execution_operator_state",
                resource_id=execution_id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="execution.prompt_settings_updated",
                aggregate_type="execution",
                aggregate_id=execution_id,
                execution_id=execution_id,
                actor=actor,
                payload={"operator_revision": projection.revision, "settings": patch, "reason": reason},
                created_at=now,
            )
            session.commit()
            return response

    def list_catalog(self, *, sync: bool = True) -> list[dict[str, Any]]:
        if sync:
            self.sync_catalog(actor="catalog-read-sync")
        with self.session_factory() as session:
            entries = session.scalars(
                select(ProcedureCatalogEntry).order_by(ProcedureCatalogEntry.procedure_ref)
            ).all()
            result: list[dict[str, Any]] = []
            for entry in entries:
                revision = session.scalar(
                    select(ProcedureCatalogRevision).where(
                        ProcedureCatalogRevision.catalog_id == entry.id,
                        ProcedureCatalogRevision.revision == entry.current_revision,
                    )
                )
                result.append(catalog_entry_dict(entry, revision))
            return result

    def catalog_history(self, procedure_ref_or_id: str) -> dict[str, Any]:
        value = _bounded(procedure_ref_or_id, "procedure_id")
        with self.session_factory() as session:
            entry = session.scalar(
                select(ProcedureCatalogEntry).where(
                    or_(
                        ProcedureCatalogEntry.id == value,
                        ProcedureCatalogEntry.procedure_ref == value,
                    )
                )
            )
            if entry is None:
                raise OperatorNotFoundError("procedure catalog entry not found")
            revisions = session.scalars(
                select(ProcedureCatalogRevision)
                .where(ProcedureCatalogRevision.catalog_id == entry.id)
                .order_by(ProcedureCatalogRevision.revision.desc())
            ).all()
            return {
                "procedure": catalog_entry_dict(entry),
                "items": [catalog_revision_dict(item, include_source=True) for item in revisions],
            }

    def ensure_execution_projection(
        self,
        execution: Execution | str,
        *,
        actor: str,
        automatic: bool = True,
        background_allowed: bool = False,
        visible: bool = True,
        catalog_revision_id: str | None = None,
        predecessor_execution_id: str | None = None,
        depth: int = 0,
        ownership_mode: str = "CONTROL_LOST",
        settings: dict[str, Any] | None = None,
        authoritative: bool = False,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        actor = _bounded(actor, "actor")
        if ownership_mode not in {"C", "B", "CONTROL_LOST"}:
            raise OperatorValidationError("ownership_mode is invalid")
        if depth < 0 or depth > 8:
            raise OperatorValidationError("execution depth is outside the v0.6 bound")
        if type(authoritative) is not bool:
            raise OperatorValidationError("authoritative projection flag is invalid")
        settings = _validate_literal(settings or {})
        if not isinstance(settings, dict):
            raise OperatorValidationError("execution settings must be a map")
        execution_id = execution if isinstance(execution, str) else execution.id
        if catalog_revision_id is None:
            # Legacy executions may be created after process bootstrap (including
            # tests that add a procedure dynamically). Register the immutable
            # source snapshot before binding the execution projection.
            self.sync_catalog(actor=actor)
        with self._lock, self.session_factory() as session:
            self._require_worker_epoch(
                session, execution_id, worker_generation
            )
            stored = session.get(Execution, execution_id, with_for_update=True)
            if stored is None:
                raise OperatorNotFoundError("execution not found")
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if projection is not None:
                self._sync_projection_from_execution(projection, stored)
                if authoritative:
                    if (
                        catalog_revision_id is not None
                        and projection.catalog_revision_id != catalog_revision_id
                    ):
                        pinned = session.get(
                            ProcedureCatalogRevision, catalog_revision_id
                        )
                        if pinned is None or pinned.source_digest != stored.procedure_hash:
                            raise OperatorConflictError(
                                "authoritative catalog revision does not match execution"
                            )
                        projection.catalog_revision_id = catalog_revision_id
                    if (
                        projection.predecessor_execution_id is not None
                        and predecessor_execution_id is not None
                        and projection.predecessor_execution_id
                        != predecessor_execution_id
                    ):
                        raise OperatorConflictError(
                            "execution predecessor identity is immutable"
                        )
                    projection.automatic = automatic
                    projection.background_allowed = background_allowed
                    projection.visible = visible
                    projection.predecessor_execution_id = predecessor_execution_id
                    projection.depth = depth
                    projection.ownership_mode = ownership_mode
                    projection.settings = settings
                    if ownership_mode != "CONTROL_LOST":
                        projection.hold_reason = None
                    projection.revision += 1
                    projection.updated_at = self._database_now(session)
                session.commit()
                return operator_state_dict(projection)
            context = session.get(OperatorContext, stored.context_id)
            if context is None or not context.enabled:
                raise OperatorConflictError("execution context is not available")
            if catalog_revision_id is None:
                revision = session.scalar(
                    select(ProcedureCatalogRevision)
                    .join(
                        ProcedureCatalogEntry,
                        ProcedureCatalogEntry.id == ProcedureCatalogRevision.catalog_id,
                    )
                    .where(
                        ProcedureCatalogEntry.procedure_ref == stored.procedure_id,
                        ProcedureCatalogRevision.source_digest == stored.procedure_hash,
                    )
                    .order_by(ProcedureCatalogRevision.revision.desc())
                    .limit(1)
                )
            else:
                revision = session.get(ProcedureCatalogRevision, catalog_revision_id)
            if revision is None and catalog_revision_id is None:
                entry = session.scalar(
                    select(ProcedureCatalogEntry).where(
                        ProcedureCatalogEntry.procedure_ref == stored.procedure_id
                    )
                )
                now = self._database_now(session)
                if entry is None:
                    entry = ProcedureCatalogEntry(
                        id=(
                            "legacy-"
                            + hashlib.sha256(
                                stored.procedure_id.encode("utf-8")
                            ).hexdigest()[:57]
                        ),
                        procedure_ref=stored.procedure_id,
                        name=stored.procedure_name,
                        description="Immutable execution snapshot",
                        entrypoint=stored.procedure_id,
                        current_revision=1,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(entry)
                    next_revision = 1
                else:
                    latest = session.scalar(
                        select(func.max(ProcedureCatalogRevision.revision)).where(
                            ProcedureCatalogRevision.catalog_id == entry.id
                        )
                    )
                    next_revision = int(latest or 0) + 1
                    entry.current_revision = next_revision
                    entry.updated_at = now
                revision = ProcedureCatalogRevision(
                    id=new_id(),
                    catalog_id=entry.id,
                    revision=next_revision,
                    source_digest=stored.procedure_hash,
                    bundle_digest=canonical_digest(
                        {
                            "source_digest": stored.procedure_hash,
                            "ir_version": stored.ir_version,
                            "steps": stored.steps,
                        }
                    ),
                    ir_version=stored.ir_version,
                    source=stored.procedure_source,
                    steps=stored.steps,
                    properties={"legacy_execution_snapshot": True},
                    created_by=actor,
                    created_at=now,
                )
                session.add(revision)
                session.flush()
            if revision is None or revision.source_digest != stored.procedure_hash:
                raise OperatorConflictError(
                    "execution source is not bound to an immutable catalog revision"
                )
            now = self._database_now(session)
            projection = ExecutionOperatorState(
                execution_id=execution_id,
                state=self.project_execution_state(stored.state),
                resume_state=None,
                current_step=stored.current_step,
                current_line=self._current_line(stored),
                current_lexical_frame_id=self._current_step_field(
                    stored, "lexical_frame_id"
                ),
                current_reachability_id=self._current_step_field(
                    stored, "reachability_id"
                ),
                source_digest=stored.procedure_hash,
                context_id=stored.context_id,
                catalog_revision_id=revision.id,
                ownership_mode=ownership_mode,
                revision=0,
                control_fencing_token=0,
                current_lease_id=None,
                hold_reason=(
                    "INITIAL_CONTROL_AVAILABLE"
                    if ownership_mode == "CONTROL_LOST"
                    else None
                ),
                settings=settings,
                control_loss_fencing_token=None,
                control_loss_requested_at=None,
                control_loss_applied_at=None,
                control_loss_safe_point_id=None,
                saved_resume_target={},
                effect_certainty="NO_EFFECT",
                automatic=automatic,
                background_allowed=background_allowed,
                visible=visible,
                predecessor_execution_id=predecessor_execution_id,
                depth=depth,
                attached_by=actor,
                attached_at=now,
                updated_at=now,
            )
            session.add(projection)
            self._audit(
                session,
                event_type="execution.operator_projection_attached",
                aggregate_type="execution",
                aggregate_id=execution_id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "context_id": projection.context_id,
                    "catalog_revision_id": projection.catalog_revision_id,
                    "ownership_mode": projection.ownership_mode,
                },
                created_at=now,
            )
            session.commit()
            return operator_state_dict(projection)

    def get_execution_projection(
        self,
        execution_id: str,
        *,
        actor: str | None = None,
        session_id: str | None = None,
        client_instance_key_id: str | None = None,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            execution_exists = session.get(Execution, execution_id) is not None
            projection_exists = (
                session.get(ExecutionOperatorState, execution_id) is not None
            )
        if not execution_exists:
            raise OperatorNotFoundError("execution not found")
        if not projection_exists:
            self.ensure_execution_projection(
                execution_id,
                actor="operator-compatibility",
                automatic=False,
            )
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id, with_for_update=True)
            projection = session.get(ExecutionOperatorState, execution_id, with_for_update=True)
            if execution is None or projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            self._sync_projection_from_execution(projection, execution)
            lease = self._active_lease(session, projection, expire=True)
            session.commit()
            result = operator_state_dict(projection)
            result["controller_lease"] = (
                self._lease_view(
                    lease,
                    actor=actor,
                    session_id=session_id,
                    client_instance_key_id=client_instance_key_id,
                )
                if lease is not None
                else None
            )
            return result

    def master(
        self,
        *,
        limit: int = 500,
        actor: str | None = None,
        session_id: str | None = None,
        client_instance_key_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise OperatorValidationError("limit must be 1 through 500")
        with self._lock, self.session_factory() as session:
            executions = session.scalars(
                select(Execution).order_by(Execution.created_at.desc()).limit(limit)
            ).all()
            result: list[dict[str, Any]] = []
            for execution in executions:
                projection = session.get(ExecutionOperatorState, execution.id)
                item = execution_dict(execution)
                if projection is not None:
                    self._sync_projection_from_execution(projection, execution)
                    lease = self._active_lease(session, projection, expire=True)
                    projection_data = operator_state_dict(projection)
                    item["operator_state"] = projection_data.pop("state")
                    item["operator_revision"] = projection_data.pop("revision")
                    projection_data.pop("current_step", None)
                    item.update(projection_data)
                    item["controller_lease"] = (
                        self._lease_view(
                            lease,
                            actor=actor,
                            session_id=session_id,
                            client_instance_key_id=client_instance_key_id,
                        )
                        if lease
                        else None
                    )
                else:
                    item.update(
                        ownership_mode="CONTROL_LOST",
                        controller_lease=None,
                        operator_projection_missing=True,
                    )
                parents = session.scalars(
                    select(ParentChildLink).where(
                        ParentChildLink.child_execution_id == execution.id
                    )
                ).all()
                children = session.scalars(
                    select(ParentChildLink).where(
                        ParentChildLink.parent_execution_id == execution.id
                    )
                ).all()
                item["parent_execution_id"] = (
                    parents[0].parent_execution_id if parents else None
                )
                item["child_execution_ids"] = [link.child_execution_id for link in children]
                item["monitor_count"] = int(
                    session.scalar(
                        select(func.count())
                        .select_from(MonitorSubscription)
                        .where(
                            MonitorSubscription.execution_id == execution.id,
                            MonitorSubscription.state == "ACTIVE",
                        )
                    )
                    or 0
                )
                result.append(item)
            session.commit()
            return result

    def active_monitor_count(self, execution_id: str) -> int:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(MonitorSubscription)
                    .where(
                        MonitorSubscription.execution_id == execution_id,
                        MonitorSubscription.state == "ACTIVE",
                    )
                )
                or 0
            )

    def execute_legacy_command_compatibility(
        self,
        execution_id: str,
        *,
        actor: str,
        role: str,
        operation: Callable[[], Any],
    ) -> Any:
        """Run the v0.5 command adapter only for its bounded unfenced owner case."""

        execution_id = _identifier(execution_id, "execution_id")
        actor = _bounded(actor, "actor")
        role = _identifier(role, "role")
        if role not in {"operator", "admin"}:
            raise OperatorAuthorizationError("operator role required")
        with self._lock, self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            if str(execution.ir_version).startswith("0.6"):
                raise OperatorAuthorizationError(
                    "v0.6 executions require a fenced operator command"
                )
            if execution.created_by != actor and role != "admin":
                raise OperatorAuthorizationError(
                    "legacy command compatibility is restricted to the creator"
                )
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if projection is not None:
                self._sync_projection_from_execution(projection, execution)
                active = self._active_lease(session, projection, expire=True)
                any_lease = session.scalar(
                    select(ControllerLease.id)
                    .where(ControllerLease.execution_id == execution_id)
                    .limit(1)
                )
                if (
                    active is not None
                    or any_lease is not None
                    or projection.ownership_mode == "C"
                    or projection.control_fencing_token > 0
                ):
                    raise OperatorAuthorizationError(
                        "execution with operator-control history requires a fenced command"
                    )
            if execution_id in self._legacy_compatibility_inflight:
                raise OperatorConflictError(
                    "another legacy compatibility mutation is in progress"
                )
            self._legacy_compatibility_inflight.add(execution_id)
            session.commit()
        try:
            return operation()
        finally:
            with self._lock:
                self._legacy_compatibility_inflight.discard(execution_id)

    def execute_legacy_prompt_compatibility(
        self,
        prompt_id: str,
        *,
        actor: str,
        role: str,
        operation: Callable[[], Any],
    ) -> Any:
        """Allow the pre-v0.6 response path only without an operator projection."""

        prompt_id = _identifier(prompt_id, "prompt_id")
        actor = _bounded(actor, "actor")
        role = _identifier(role, "role")
        if role not in {"operator", "admin"}:
            raise OperatorAuthorizationError("operator role required")
        with self._lock, self.session_factory() as session:
            prompt = session.get(Prompt, prompt_id)
            if prompt is None:
                raise OperatorNotFoundError("prompt not found")
            execution = session.get(Execution, prompt.execution_id)
            if execution is None:
                raise OperatorNotFoundError("prompt execution not found")
            projection = session.get(ExecutionOperatorState, execution.id)
            operator_prompt = session.scalar(
                select(OperatorPrompt.id).where(
                    or_(
                        OperatorPrompt.id == prompt_id,
                        OperatorPrompt.legacy_prompt_id == prompt_id,
                    )
                )
            )
            if projection is not None or operator_prompt is not None:
                raise OperatorAuthorizationError(
                    "operator-projected prompts require a fenced response"
                )
            if execution.ir_version == "0.6":
                raise OperatorAuthorizationError(
                    "v0.6 prompts require a fenced response"
                )
            if execution.created_by != actor and role != "admin":
                raise OperatorAuthorizationError(
                    "legacy prompt compatibility is restricted to the creator"
                )
        return operation()

    @staticmethod
    def _current_line(execution: Execution) -> int | None:
        if execution.current_step < execution.total_steps:
            value = execution.steps[execution.current_step].get("line")
            return value if type(value) is int else None
        return None

    @staticmethod
    def _current_step_field(execution: Execution, field: str) -> str | None:
        if execution.current_step >= execution.total_steps:
            return None
        value = execution.steps[execution.current_step].get(field)
        return value if type(value) is str and value else None

    def _sync_projection_from_execution(
        self, projection: ExecutionOperatorState, execution: Execution
    ) -> None:
        state = self.project_execution_state(execution.state)
        current_line = self._current_line(execution)
        current_frame = self._current_step_field(execution, "lexical_frame_id")
        current_reachability = self._current_step_field(execution, "reachability_id")
        preserve_semantic_state = (
            projection.state == "SUSPENDED" and projection.hold_reason is not None
        ) or projection.state in {"STOPPING", "RECOVERING"}
        if (
            (not preserve_semantic_state and projection.state != state)
            or projection.current_step != execution.current_step
            or projection.current_line != current_line
            or projection.current_lexical_frame_id != current_frame
            or projection.current_reachability_id != current_reachability
        ):
            if not preserve_semantic_state:
                projection.state = state
            projection.current_step = execution.current_step
            projection.current_line = current_line
            projection.current_lexical_frame_id = current_frame
            projection.current_reachability_id = current_reachability
            projection.updated_at = _stored_utc(execution.updated_at) or datetime.now(timezone.utc)

    def acquire_control(
        self,
        execution_id: str,
        *,
        expected_execution_revision: int,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        lease_seconds: int,
        idempotency_key: str,
        reason: str,
        acknowledgement: str | None = None,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        actor = _bounded(actor, "actor")
        holder_session_id = _identifier(holder_session_id, "holder_session_id")
        client_instance_key_id = _identifier(
            client_instance_key_id, "client_instance_key_id"
        )
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 300:
            raise OperatorValidationError("lease_seconds must be 5 through 300")
        request = {
            "execution_id": execution_id,
            "expected_execution_revision": expected_execution_revision,
            "actor": actor,
            "holder_session_id": holder_session_id,
            "client_instance_key_id": client_instance_key_id,
            "lease_seconds": lease_seconds,
            "reason": reason,
            "acknowledgement": acknowledgement,
        }
        request_digest = canonical_digest(request)
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=f"lease-acquire:{execution_id}",
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            execution = session.get(Execution, execution_id, with_for_update=True)
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if execution is None or projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            if execution_id in self._legacy_compatibility_inflight:
                raise OperatorConflictError(
                    "legacy compatibility mutation is in progress"
                )
            if execution.revision != expected_execution_revision:
                raise OperatorConflictError(
                    "execution revision conflict",
                    current={"execution_revision": execution.revision},
                )
            self._sync_projection_from_execution(projection, execution)
            active = self._active_lease(session, projection, expire=True)
            if active is not None:
                raise OperatorConflictError(
                    "control lease is already held",
                    current={
                        "ownership_mode": projection.ownership_mode,
                        "lease": {
                            "id": active.id,
                            "expires_at_database_time": lease_dict(active)[
                                "expires_at_database_time"
                            ],
                        },
                    },
                )
            if (
                projection.hold_reason not in {None, "INITIAL_CONTROL_AVAILABLE"}
                and not acknowledgement
            ):
                raise OperatorConflictError("control-loss acknowledgement is required")
            if acknowledgement is not None:
                _bounded(acknowledgement, "acknowledgement", 1000)
            now = self._database_now(session)
            projection.control_fencing_token += 1
            projection.revision += 1
            projection.ownership_mode = "C"
            projection.hold_reason = None
            projection.updated_at = now
            open_prompts = session.scalars(
                select(OperatorPrompt).where(
                    OperatorPrompt.execution_id == execution_id,
                    OperatorPrompt.state == "OPEN",
                )
            ).all()
            for prompt in open_prompts:
                prompt.no_controller_deadline = None
            lease = ControllerLease(
                id=new_id(),
                execution_id=execution_id,
                revision=1,
                fencing_token=projection.control_fencing_token,
                holder_subject_id=actor,
                holder_session_id=holder_session_id,
                client_instance_key_id=client_instance_key_id,
                issued_at=now,
                expires_at=now + timedelta(seconds=lease_seconds),
                state="ACTIVE",
                reason=reason,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                updated_at=now,
            )
            session.add(lease)
            session.flush()
            projection.current_lease_id = lease.id
            response = {
                "execution": operator_state_dict(projection),
                "control_lease": lease_dict(lease),
            }
            self._store_request(
                session,
                scope=f"lease-acquire:{execution_id}",
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="controller_lease",
                resource_id=lease.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="control.lease_acquired",
                aggregate_type="controller_lease",
                aggregate_id=lease.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "lease_id": lease.id,
                    "lease_revision": lease.revision,
                    "control_fencing_token": lease.fencing_token,
                    "expires_at_database_time": lease.expires_at.isoformat(),
                },
                created_at=now,
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise OperatorConflictError("a competing controller won acquisition") from exc
            return response

    def renew_control(
        self,
        execution_id: str,
        *,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        lease_seconds: int,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 300:
            raise OperatorValidationError("lease_seconds must be 5 through 300")
        values = self._validated_control_values(
            execution_id,
            lease_id,
            actor,
            holder_session_id,
            client_instance_key_id,
            idempotency_key,
            reason,
        )
        request_digest = canonical_digest(
            {
                **values,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "lease_seconds": lease_seconds,
            }
        )
        scope = f"lease-renew:{values['lease_id']}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=values["actor"],
                idempotency_key=values["idempotency_key"],
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            projection, lease = self._require_control_in_session(
                session,
                values["execution_id"],
                values["actor"],
                values["holder_session_id"],
                values["client_instance_key_id"],
                values["lease_id"],
                expected_lease_revision,
                control_fencing_token,
            )
            now = self._database_now(session)
            lease.revision += 1
            lease.expires_at = now + timedelta(seconds=lease_seconds)
            lease.reason = values["reason"]
            lease.updated_at = now
            response = {
                "execution": operator_state_dict(projection),
                "control_lease": lease_dict(lease),
            }
            self._store_request(
                session,
                scope=scope,
                actor=values["actor"],
                idempotency_key=values["idempotency_key"],
                request_digest=request_digest,
                resource_type="controller_lease",
                resource_id=lease.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="control.lease_renewed",
                aggregate_type="controller_lease",
                aggregate_id=lease.id,
                execution_id=lease.execution_id,
                actor=values["actor"],
                payload={
                    "lease_revision": lease.revision,
                    "control_fencing_token": lease.fencing_token,
                    "expires_at_database_time": lease.expires_at.isoformat(),
                },
                created_at=now,
            )
            session.commit()
            return response

    def release_control_to_background(
        self,
        execution_id: str,
        *,
        expected_execution_revision: int,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        values = self._validated_control_values(
            execution_id,
            lease_id,
            actor,
            holder_session_id,
            client_instance_key_id,
            idempotency_key,
            reason,
        )
        request_digest = canonical_digest(
            {
                **values,
                "expected_execution_revision": expected_execution_revision,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
            }
        )
        scope = f"lease-release:{values['lease_id']}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=values["actor"],
                idempotency_key=values["idempotency_key"],
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            projection, lease = self._require_control_in_session(
                session,
                values["execution_id"],
                values["actor"],
                values["holder_session_id"],
                values["client_instance_key_id"],
                values["lease_id"],
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, values["execution_id"], with_for_update=True)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            if self._has_mutation_reservation(session, execution.id):
                raise OperatorConflictError(
                    "an admitted operator mutation is still applying"
                )
            if execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            self._sync_projection_from_execution(projection, execution)
            if not projection.background_allowed:
                raise OperatorConflictError("procedure does not permit background execution")
            if projection.state == "PROMPT" or session.scalar(
                select(Prompt).where(
                    Prompt.execution_id == execution.id,
                    Prompt.status.in_(["open", "responding"]),
                )
            ) is not None:
                raise OperatorConflictError("an interactive prompt prevents background mode")
            if projection.state not in {"PAUSED", "INTERRUPTED"}:
                raise OperatorConflictError(
                    "direct release requires a stable paused boundary; use the "
                    "BACKGROUND command for running or waiting work"
                )
            now = self._database_now(session)
            lease.state = "RELEASED"
            lease.revision += 1
            lease.terminated_at = now
            lease.termination_reason = "RELEASE_TO_BACKGROUND"
            lease.updated_at = now
            projection.ownership_mode = "B"
            projection.current_lease_id = None
            projection.revision += 1
            projection.updated_at = now
            response = {
                "execution": operator_state_dict(projection),
                "control_lease": lease_dict(lease),
            }
            self._store_request(
                session,
                scope=scope,
                actor=values["actor"],
                idempotency_key=values["idempotency_key"],
                request_digest=request_digest,
                resource_type="controller_lease",
                resource_id=lease.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="control.released_to_background",
                aggregate_type="controller_lease",
                aggregate_id=lease.id,
                execution_id=execution.id,
                actor=values["actor"],
                payload={
                    "lease_revision": lease.revision,
                    "ownership_mode": "B",
                    "effect_certainty": projection.effect_certainty,
                },
                created_at=now,
            )
            session.commit()
            return response

    def require_control(
        self,
        execution_id: str,
        *,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
    ) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            projection, lease = self._require_control_in_session(
                session,
                _identifier(execution_id, "execution_id"),
                _bounded(actor, "actor"),
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            return {
                "execution": operator_state_dict(projection),
                "control_lease": lease_dict(lease),
            }

    def start_monitor(
        self,
        execution_id: str,
        *,
        actor: str,
        session_id: str,
        client_instance_key_id: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        actor = _bounded(actor, "actor")
        session_id = _identifier(session_id, "session_id")
        client_instance_key_id = _identifier(
            client_instance_key_id, "client_instance_key_id"
        )
        with self._lock, self.session_factory() as session:
            if session.get(ExecutionOperatorState, execution_id) is None:
                raise OperatorNotFoundError("operator execution projection not found")
            existing = session.scalar(
                select(MonitorSubscription).where(
                    MonitorSubscription.execution_id == execution_id,
                    MonitorSubscription.subject_id == actor,
                    MonitorSubscription.session_id == session_id,
                    MonitorSubscription.client_instance_key_id == client_instance_key_id,
                    MonitorSubscription.state == "ACTIVE",
                )
            )
            if existing is not None:
                return monitor_dict(existing)
            now = self._database_now(session)
            subscription = MonitorSubscription(
                id=new_id(),
                execution_id=execution_id,
                subject_id=actor,
                session_id=session_id,
                client_instance_key_id=client_instance_key_id,
                state="ACTIVE",
                created_at=now,
            )
            session.add(subscription)
            self._audit(
                session,
                event_type="monitor.started",
                aggregate_type="monitor_subscription",
                aggregate_id=subscription.id,
                execution_id=execution_id,
                actor=actor,
                payload={"mode": "M"},
                created_at=now,
            )
            session.commit()
            return monitor_dict(subscription)

    def stop_monitor(
        self,
        execution_id: str,
        subscription_id: str,
        *,
        actor: str,
        session_id: str,
        client_instance_key_id: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        subscription_id = _identifier(subscription_id, "subscription_id")
        actor = _bounded(actor, "actor")
        session_id = _identifier(session_id, "session_id")
        client_instance_key_id = _identifier(
            client_instance_key_id, "client_instance_key_id"
        )
        with self._lock, self.session_factory() as session:
            subscription = session.get(
                MonitorSubscription, subscription_id, with_for_update=True
            )
            if subscription is None:
                raise OperatorNotFoundError("monitor subscription not found")
            if subscription.execution_id != execution_id:
                raise OperatorNotFoundError("monitor subscription not found")
            if (
                subscription.subject_id != actor
                or subscription.session_id != session_id
                or subscription.client_instance_key_id != client_instance_key_id
            ):
                raise OperatorAuthorizationError("monitor subscription belongs to another subject")
            if subscription.state == "ACTIVE":
                now = self._database_now(session)
                subscription.state = "CLOSED"
                subscription.closed_at = now
                self._audit(
                    session,
                    event_type="monitor.stopped",
                    aggregate_type="monitor_subscription",
                    aggregate_id=subscription.id,
                    execution_id=execution_id,
                    actor=actor,
                    payload={"mode": "M"},
                    created_at=now,
                )
                session.commit()
            return monitor_dict(subscription)

    @staticmethod
    def _handover_dict(handover: ControllerHandover) -> dict[str, Any]:
        return {
            "id": handover.id,
            "execution_id": handover.execution_id,
            "revision": handover.revision,
            "state": handover.state,
            "requester_subject_id": handover.requester_subject_id,
            "requester_session_id": handover.requester_session_id,
            "requester_client_instance_key_id": handover.requester_client_instance_key_id,
            "requester_monitor_id": handover.requester_monitor_id,
            "expected_execution_revision": handover.expected_execution_revision,
            "requested_at": handover.requested_at.isoformat(),
            "expires_at": handover.expires_at.isoformat(),
            "approved_by": handover.approved_by,
            "predecessor_lease_id": handover.predecessor_lease_id,
            "successor_lease_id": handover.successor_lease_id,
            "updated_at": handover.updated_at.isoformat(),
            "settled_at": (
                handover.settled_at.isoformat()
                if handover.settled_at is not None
                else None
            ),
        }

    @classmethod
    def _handover_view(
        cls,
        handover: ControllerHandover,
        *,
        actor: str,
        session_id: str,
        client_instance_key_id: str,
    ) -> dict[str, Any]:
        result = cls._handover_dict(handover)
        requester_session = (
            handover.requester_subject_id == actor
            and handover.requester_session_id == session_id
            and handover.requester_client_instance_key_id
            == client_instance_key_id
        )
        result["requested_by_current_session"] = requester_session
        if not requester_session:
            result.pop("requester_session_id", None)
            result.pop("requester_client_instance_key_id", None)
        return result

    def list_control_handovers(
        self,
        execution_id: str,
        *,
        actor: str,
        session_id: str,
        client_instance_key_id: str,
        include_terminal: bool = False,
    ) -> list[dict[str, Any]]:
        execution_id = _identifier(execution_id, "execution_id")
        actor = _bounded(actor, "actor")
        session_id = _identifier(session_id, "session_id")
        client_instance_key_id = _identifier(
            client_instance_key_id, "client_instance_key_id"
        )
        self.expire_due_handovers(execution_id=execution_id)
        with self.session_factory() as session:
            if session.get(Execution, execution_id) is None:
                raise OperatorNotFoundError("execution not found")
            projection = session.get(ExecutionOperatorState, execution_id)
            active_lease = (
                session.get(ControllerLease, projection.current_lease_id)
                if projection is not None and projection.current_lease_id is not None
                else None
            )
            query = select(ControllerHandover).where(
                ControllerHandover.execution_id == execution_id
            )
            is_current_holder = (
                active_lease is not None
                and active_lease.state == "ACTIVE"
                and active_lease.holder_subject_id == actor
                and active_lease.holder_session_id == session_id
                and active_lease.client_instance_key_id
                == client_instance_key_id
            )
            if not is_current_holder:
                query = query.where(
                    ControllerHandover.requester_subject_id == actor,
                    ControllerHandover.requester_session_id == session_id,
                    ControllerHandover.requester_client_instance_key_id
                    == client_instance_key_id,
                )
            if not include_terminal:
                query = query.where(ControllerHandover.state == "REQUESTED")
            rows = session.scalars(
                query.order_by(
                    ControllerHandover.requested_at,
                    ControllerHandover.id,
                )
            ).all()
            result: list[dict[str, Any]] = []
            for handover in rows:
                item = self._handover_view(
                    handover,
                    actor=actor,
                    session_id=session_id,
                    client_instance_key_id=client_instance_key_id,
                )
                if (
                    handover.requester_subject_id == actor
                    and handover.requester_session_id == session_id
                    and handover.requester_client_instance_key_id
                    == client_instance_key_id
                    and handover.state == "COMPLETED"
                    and handover.successor_lease_id is not None
                ):
                    successor = session.get(
                        ControllerLease, handover.successor_lease_id
                    )
                    item["successor_control_lease"] = (
                        self._lease_view(
                            successor,
                            actor=actor,
                            session_id=session_id,
                            client_instance_key_id=client_instance_key_id,
                        )
                        if successor is not None
                        else None
                    )
                result.append(item)
            return result

    def request_control_handover(
        self,
        execution_id: str,
        *,
        requester_monitor_id: str,
        expected_execution_revision: int,
        actor: str,
        requester_session_id: str,
        requester_client_instance_key_id: str,
        responsibility_acknowledgement: str,
        expires_seconds: int,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        requester_monitor_id = _identifier(requester_monitor_id, "requester_monitor_id")
        actor = _bounded(actor, "actor")
        requester_session_id = _identifier(requester_session_id, "requester_session_id")
        requester_client_instance_key_id = _identifier(
            requester_client_instance_key_id,
            "requester_client_instance_key_id",
        )
        acknowledgement = _bounded(
            responsibility_acknowledgement,
            "responsibility_acknowledgement",
            1000,
        )
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        if type(expires_seconds) is not int or not 5 <= expires_seconds <= 300:
            raise OperatorValidationError("handover expiry must be 5 through 300 seconds")
        digest = canonical_digest(
            {
                "execution_id": execution_id,
                "requester_monitor_id": requester_monitor_id,
                "expected_execution_revision": expected_execution_revision,
                "actor": actor,
                "requester_session_id": requester_session_id,
                "requester_client_instance_key_id": requester_client_instance_key_id,
                "responsibility_acknowledgement": acknowledgement,
                "expires_seconds": expires_seconds,
                "reason": reason,
            }
        )
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(ControllerHandover).where(
                    ControllerHandover.execution_id == execution_id,
                    ControllerHandover.requester_subject_id == actor,
                    ControllerHandover.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != digest:
                    raise OperatorConflictError(
                        "idempotency key was used for another handover request"
                    )
                return self._handover_dict(existing)
            execution = session.get(Execution, execution_id)
            projection = session.get(ExecutionOperatorState, execution_id)
            monitor = session.get(MonitorSubscription, requester_monitor_id)
            if execution is None or projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            if execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            active_lease = self._active_lease(session, projection, expire=True)
            if active_lease is None or projection.ownership_mode != "C":
                raise OperatorConflictError("handover requires an active controller")
            if (
                monitor is None
                or monitor.execution_id != execution_id
                or monitor.state != "ACTIVE"
                or monitor.subject_id != actor
                or monitor.session_id != requester_session_id
                or monitor.client_instance_key_id != requester_client_instance_key_id
            ):
                raise OperatorAuthorizationError(
                    "named requester monitor proof does not match"
                )
            if (
                active_lease.holder_subject_id == actor
                and active_lease.holder_session_id == requester_session_id
            ):
                raise OperatorConflictError("handover requester is already controller")
            now = self._database_now(session)
            handover = ControllerHandover(
                id=new_id(),
                execution_id=execution_id,
                revision=1,
                state="REQUESTED",
                requester_subject_id=actor,
                requester_session_id=requester_session_id,
                requester_client_instance_key_id=requester_client_instance_key_id,
                requester_monitor_id=requester_monitor_id,
                responsibility_acknowledgement=acknowledgement,
                expected_execution_revision=expected_execution_revision,
                idempotency_key=idempotency_key,
                request_digest=digest,
                requested_at=now,
                expires_at=now + timedelta(seconds=expires_seconds),
                updated_at=now,
            )
            session.add(handover)
            self._audit(
                session,
                event_type="control.handover_requested",
                aggregate_type="controller_handover",
                aggregate_id=handover.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "requester_monitor_id": requester_monitor_id,
                    "expected_execution_revision": expected_execution_revision,
                    "reason": reason,
                },
                created_at=now,
            )
            session.commit()
            return self._handover_dict(handover)

    def approve_control_handover(
        self,
        execution_id: str,
        handover_id: str,
        *,
        expected_handover_revision: int,
        expected_execution_revision: int,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        lease_seconds: int,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        handover_id = _identifier(handover_id, "handover_id")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 300:
            raise OperatorValidationError("lease_seconds must be 5 through 300")
        digest = canonical_digest(
            {
                "handover_id": handover_id,
                "expected_handover_revision": expected_handover_revision,
                "expected_execution_revision": expected_execution_revision,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "actor": actor,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "lease_seconds": lease_seconds,
                "reason": reason,
            }
        )
        scope = f"handover-approve:{handover_id}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=digest,
            )
            if replay is not None:
                return replay
            handover = session.get(ControllerHandover, handover_id, with_for_update=True)
            if handover is None or handover.execution_id != execution_id:
                raise OperatorNotFoundError("handover request not found")
            now = self._database_now(session)
            if handover.state == "REQUESTED" and (
                _stored_utc(handover.expires_at) or now
            ) <= now:
                self._expire_handover_row(session, handover, now)
                session.commit()
                raise OperatorConflictError("handover request expired")
            if handover.state != "REQUESTED":
                raise OperatorConflictError("handover request is not pending")
            if handover.revision != expected_handover_revision:
                raise OperatorConflictError("handover revision conflict")
            projection, old_lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id)
            monitor = session.get(
                MonitorSubscription, handover.requester_monitor_id, with_for_update=True
            )
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            if (
                monitor is None
                or monitor.state != "ACTIVE"
                or monitor.subject_id != handover.requester_subject_id
                or monitor.session_id != handover.requester_session_id
                or monitor.client_instance_key_id
                != handover.requester_client_instance_key_id
            ):
                raise OperatorConflictError("handover requester monitor is no longer active")
            if self._has_mutation_reservation(session, execution_id):
                raise OperatorConflictError(
                    "an admitted operator mutation is still applying"
                )
            old_lease.state = "TRANSFERRED"
            old_lease.revision += 1
            old_lease.terminated_at = now
            old_lease.termination_reason = "EXPLICIT_HANDOVER"
            old_lease.updated_at = now
            projection.control_fencing_token += 1
            session.flush()
            successor = ControllerLease(
                id=new_id(),
                execution_id=execution_id,
                revision=1,
                fencing_token=projection.control_fencing_token,
                holder_subject_id=handover.requester_subject_id,
                holder_session_id=handover.requester_session_id,
                client_instance_key_id=handover.requester_client_instance_key_id,
                issued_at=now,
                expires_at=now + timedelta(seconds=lease_seconds),
                state="ACTIVE",
                reason=reason,
                idempotency_key=f"handover:{handover.id}",
                request_digest=digest,
                predecessor_lease_id=old_lease.id,
                updated_at=now,
            )
            session.add(successor)
            monitor.state = "CLOSED"
            monitor.closed_at = now
            former_monitor = session.scalar(
                select(MonitorSubscription).where(
                    MonitorSubscription.execution_id == execution_id,
                    MonitorSubscription.subject_id == old_lease.holder_subject_id,
                    MonitorSubscription.session_id == old_lease.holder_session_id,
                    MonitorSubscription.client_instance_key_id
                    == old_lease.client_instance_key_id,
                    MonitorSubscription.state == "ACTIVE",
                )
            )
            if former_monitor is None:
                former_monitor = MonitorSubscription(
                    id=new_id(),
                    execution_id=execution_id,
                    subject_id=old_lease.holder_subject_id,
                    session_id=old_lease.holder_session_id,
                    client_instance_key_id=old_lease.client_instance_key_id,
                    state="ACTIVE",
                    created_at=now,
                )
                session.add(former_monitor)
            projection.current_lease_id = successor.id
            projection.ownership_mode = "C"
            projection.hold_reason = None
            projection.revision += 1
            projection.updated_at = now
            handover.state = "COMPLETED"
            handover.revision += 1
            handover.approved_by = actor
            handover.predecessor_lease_id = old_lease.id
            handover.successor_lease_id = successor.id
            handover.updated_at = now
            handover.settled_at = now
            session.flush()
            response = {
                "handover": self._handover_view(
                    handover,
                    actor=actor,
                    session_id=holder_session_id,
                    client_instance_key_id=client_instance_key_id,
                ),
                "execution": operator_state_dict(projection),
                "control_lease": self._lease_view(
                    successor,
                    actor=actor,
                    session_id=holder_session_id,
                    client_instance_key_id=client_instance_key_id,
                ),
                "former_monitor": monitor_dict(former_monitor),
                "former_holder_monitor": monitor_dict(former_monitor),
            }
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=digest,
                resource_type="controller_handover",
                resource_id=handover.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="control.handover_completed",
                aggregate_type="controller_handover",
                aggregate_id=handover.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "predecessor_lease_id": old_lease.id,
                    "successor_lease_id": successor.id,
                    "control_fencing_token": successor.fencing_token,
                },
                created_at=now,
            )
            session.commit()
            return response

    @staticmethod
    def _validated_control_values(
        execution_id: str,
        lease_id: str,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, str]:
        return {
            "execution_id": _identifier(execution_id, "execution_id"),
            "lease_id": _identifier(lease_id, "lease_id"),
            "actor": _bounded(actor, "actor"),
            "holder_session_id": _identifier(holder_session_id, "holder_session_id"),
            "client_instance_key_id": _identifier(
                client_instance_key_id, "client_instance_key_id"
            ),
            "idempotency_key": _idempotency_key(idempotency_key),
            "reason": _bounded(reason, "reason", 1000),
        }

    def _require_control_in_session(
        self,
        session: Session,
        execution_id: str,
        actor: str,
        holder_session_id: str,
        client_instance_key_id: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
    ) -> tuple[ExecutionOperatorState, ControllerLease]:
        projection = session.get(
            ExecutionOperatorState, execution_id, with_for_update=True
        )
        lease = session.get(ControllerLease, lease_id, with_for_update=True)
        if projection is None:
            raise OperatorNotFoundError("operator execution projection not found")
        if lease is None or lease.execution_id != execution_id:
            raise OperatorAuthorizationError("control lease is invalid for the execution")
        now = self._database_now(session)
        if lease.state == "ACTIVE" and (_stored_utc(lease.expires_at) or now) <= now:
            if self._expire_lease(session, projection, lease, now):
                session.commit()
            else:
                raise OperatorAuthorizationError(
                    "controller lease expired while an admitted mutation is applying"
                )
        if (
            lease.state != "ACTIVE"
            or projection.ownership_mode != "C"
            or projection.current_lease_id != lease.id
        ):
            raise OperatorAuthorizationError("an active controller lease is required")
        if (
            lease.holder_subject_id != actor
            or lease.holder_session_id != holder_session_id
            or lease.client_instance_key_id != client_instance_key_id
        ):
            raise OperatorAuthorizationError("control lease holder proof does not match")
        if (
            lease.fencing_token != control_fencing_token
            or projection.control_fencing_token != control_fencing_token
        ):
            raise OperatorAuthorizationError("stale control fencing token")
        if lease.revision != expected_lease_revision:
            raise OperatorConflictError(
                "control lease revision conflict",
                current={"control_lease": lease_dict(lease)},
            )
        return projection, lease

    def _active_lease(
        self,
        session: Session,
        projection: ExecutionOperatorState,
        *,
        expire: bool,
    ) -> ControllerLease | None:
        if projection.current_lease_id is None:
            return None
        lease = session.get(ControllerLease, projection.current_lease_id, with_for_update=True)
        if lease is None or lease.state != "ACTIVE":
            projection.current_lease_id = None
            if projection.ownership_mode == "C":
                projection.ownership_mode = "CONTROL_LOST"
                projection.hold_reason = "CONTROL_LEASE_MISSING"
            return None
        if expire:
            now = self._database_now(session)
            if (_stored_utc(lease.expires_at) or now) <= now:
                if self._expire_lease(session, projection, lease, now):
                    return None
        return lease

    def _expire_lease(
        self,
        session: Session,
        projection: ExecutionOperatorState,
        lease: ControllerLease,
        now: datetime,
    ) -> bool:
        if self._has_mutation_reservation(session, lease.execution_id):
            return False
        lease.state = "EXPIRED"
        lease.revision += 1
        lease.terminated_at = now
        lease.termination_reason = "LEASE_EXPIRED"
        lease.updated_at = now
        projection.current_lease_id = None
        projection.ownership_mode = "CONTROL_LOST"
        projection.hold_reason = "CONTROL_LOST"
        projection.resume_state = projection.state
        projection.state = "SUSPENDED"
        projection.control_loss_fencing_token = lease.fencing_token
        projection.control_loss_requested_at = now
        projection.control_loss_applied_at = None
        projection.control_loss_safe_point_id = None
        open_prompts = session.scalars(
            select(OperatorPrompt).where(
                OperatorPrompt.execution_id == lease.execution_id,
                OperatorPrompt.state == "OPEN",
            )
        ).all()
        for prompt in open_prompts:
            grace = self._optional_duration(
                prompt.settings_snapshot.get("NO_CONTROLLER_GRACE"),
                "NO_CONTROLLER_GRACE",
                maximum=604_800,
            )
            prompt.no_controller_deadline = (
                now + timedelta(seconds=grace) if grace else None
            )
        execution = session.get(Execution, lease.execution_id, with_for_update=True)
        if execution is None:
            raise OperatorNotFoundError("lease execution not found")
        event_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"openbexi-control-loss:{lease.execution_id}:{lease.fencing_token}",
            )
        )
        event = session.get(Event, event_id)
        if event is None:
            event = Event(
                id=event_id,
                execution_id=execution.id,
                sequence=execution.next_sequence,
                event_type="operator.control_loss_requested",
                source="operator-reconciler",
                severity="warning",
                correlation_id=None,
                causation_id=None,
                payload={
                    "ownership_mode": "CONTROL_LOST",
                    "state": "SUSPENDED",
                    "hold_reason": "CONTROL_LOST",
                    "requested_at_database_time": now.isoformat(),
                },
                created_at=now,
            )
            session.add(event)
            execution.next_sequence += 1
            session.flush([event])
        projection.control_loss_event_id = event_id
        projection.control_loss_published_at = None
        projection.revision += 1
        projection.updated_at = now
        self._audit(
            session,
            event_type="control.lease_expired",
            aggregate_type="controller_lease",
            aggregate_id=lease.id,
            execution_id=lease.execution_id,
            actor="operator-reconciler",
            payload={
                "lease_revision": lease.revision,
                "control_fencing_token": lease.fencing_token,
                "hold_reason": "CONTROL_LOST",
            },
            created_at=now,
        )
        return True

    def list_unpublished_control_loss_events(
        self, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise OperatorValidationError("control-loss event limit is invalid")
        with self.session_factory() as session:
            projections = session.scalars(
                select(ExecutionOperatorState)
                .where(
                    ExecutionOperatorState.control_loss_event_id.is_not(None),
                    ExecutionOperatorState.control_loss_published_at.is_(None),
                )
                .order_by(ExecutionOperatorState.control_loss_requested_at)
                .limit(limit)
            ).all()
            result: list[dict[str, Any]] = []
            for projection in projections:
                event = session.get(Event, projection.control_loss_event_id)
                if event is None:
                    continue
                result.append(
                    {
                        "id": event.id,
                        "execution_id": event.execution_id,
                        "sequence": event.sequence,
                        "event_type": event.event_type,
                        "source": event.source,
                        "severity": event.severity,
                        "correlation_id": event.correlation_id,
                        "causation_id": event.causation_id,
                        "payload": event.payload,
                        "created_at": event.created_at.isoformat(),
                    }
                )
            return result

    def mark_control_loss_event_published(self, event_id: str) -> dict[str, Any]:
        event_id = _identifier(event_id, "event_id")
        with self._lock, self.session_factory() as session:
            projection = session.scalar(
                select(ExecutionOperatorState)
                .where(ExecutionOperatorState.control_loss_event_id == event_id)
                .with_for_update()
            )
            if projection is None:
                raise OperatorNotFoundError("control-loss event not found")
            if projection.control_loss_published_at is None:
                projection.control_loss_published_at = self._database_now(session)
                session.commit()
            return operator_state_dict(projection)

    def record_safe_point(
        self,
        execution_id: str,
        *,
        safe_point_id: str,
        safe_point_type: str,
        step_index: int | None,
        line: int | None,
        state: str | None = None,
        lexical_frame_id: str | None = None,
        reachability_id: str | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        safe_point_id = _identifier(safe_point_id, "safe_point_id")
        safe_point_type = _identifier(safe_point_type, "safe_point_type")
        if step_index is not None and (type(step_index) is not int or step_index < 0):
            raise OperatorValidationError("safe-point step index is invalid")
        if line is not None and (type(line) is not int or line < 1):
            raise OperatorValidationError("safe-point line is invalid")
        if lexical_frame_id is not None:
            lexical_frame_id = _bounded(
                lexical_frame_id, "lexical_frame_id", 256
            )
        if reachability_id is not None:
            reachability_id = _bounded(
                reachability_id, "reachability_id", 512
            )
        with self._lock, self.session_factory() as session:
            self._require_worker_epoch(
                session, execution_id, worker_generation
            )
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            if state is not None:
                state = _identifier(state, "state")
                if state not in set(_LEGACY_STATE_PROJECTION.values()):
                    raise OperatorValidationError("canonical execution state is invalid")
                projection.state = state
            projection.current_safe_point_id = safe_point_id
            projection.current_step = step_index
            projection.current_line = line
            projection.current_lexical_frame_id = lexical_frame_id
            projection.current_reachability_id = reachability_id
            projection.saved_resume_target = {
                "safe_point_type": safe_point_type,
                "step_index": step_index,
                "line": line,
                "lexical_frame_id": lexical_frame_id,
                "reachability_id": reachability_id,
            }
            projection.revision += 1
            projection.updated_at = self._database_now(session)
            session.commit()
            return operator_state_dict(projection)

    def accept_operator_command(
        self,
        execution_id: str,
        command_type: str,
        expected_execution_revision: int,
        idempotency_key: str,
        actor: str,
        role: str,
        reason: str,
        controller_lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        payload: dict[str, Any] | None = None,
        target: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        command_type = _identifier(command_type.upper(), "command_type")
        idempotency_key = _idempotency_key(idempotency_key)
        actor = _bounded(actor, "actor")
        role = _identifier(role, "role")
        reason = _bounded(reason, "reason", 1000)
        controller_lease_id = _identifier(controller_lease_id, "controller_lease_id")
        holder_session_id = _identifier(holder_session_id, "holder_session_id")
        client_instance_key_id = _identifier(
            client_instance_key_id, "client_instance_key_id"
        )
        correlation_id = _identifier(
            correlation_id or str(uuid.uuid4()), "correlation_id"
        )
        payload = _validate_literal(payload or {})
        target = _validate_literal(target or {})
        if payload:
            raise OperatorValidationError(
                f"{command_type} does not accept a command payload"
            )
        if command_type not in {"RUN", "GOTO"} and target:
            raise OperatorValidationError(
                f"{command_type} does not accept a command target"
            )
        if command_type in {"RUN", "GOTO"} and target:
            if set(target) - {"line", "label", "source_digest"}:
                raise OperatorValidationError(
                    f"{command_type} target contains unsupported fields"
                )
            selectors = [key for key in ("line", "label") if key in target]
            if len(selectors) != 1:
                raise OperatorValidationError(
                    f"{command_type} target requires exactly one line or label"
                )
            if command_type == "RUN" and selectors != ["line"]:
                raise OperatorValidationError("RUN target requires a line")
            if "line" in target and (
                type(target["line"]) is not int or target["line"] < 1
            ):
                raise OperatorValidationError(f"{command_type} target line is invalid")
            if "label" in target:
                _identifier(target["label"], "target label")
            target_source_digest = target.get("source_digest")
            if target_source_digest is not None and not (
                isinstance(target_source_digest, str)
                and _LOWER_HEX_64.fullmatch(target_source_digest)
            ):
                raise OperatorValidationError(
                    f"{command_type} target source_digest is invalid"
                )
            _reject_prompt_secret_material(target, "target")
        if command_type == "GOTO" and not target:
            raise OperatorValidationError("GOTO requires a static line target")
        if role not in {"operator", "admin"}:
            raise OperatorAuthorizationError("operator role required")
        if command_type not in _COMMAND_MATRIX:
            raise OperatorValidationError("operator command is unsupported")
        request_digest = canonical_digest(
            {
                "execution_id": execution_id,
                "command_type": command_type,
                "expected_execution_revision": expected_execution_revision,
                "actor": actor,
                "role": role,
                "reason": reason,
                "controller_lease_id": controller_lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "payload": payload,
                "target": target,
            }
        )
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(OperatorCommand).where(
                    OperatorCommand.execution_id == execution_id,
                    OperatorCommand.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise OperatorConflictError(
                        "idempotency key was used for another operator command"
                    )
                return command_dict(existing)
            execution = session.get(Execution, execution_id, with_for_update=True)
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if execution is None or projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            self._sync_projection_from_execution(projection, execution)
            _, safe_point = _COMMAND_MATRIX[command_type]
            now = self._database_now(session)
            rejection_code: str | None = None
            lease: ControllerLease | None = None
            if command_type == "KILL":
                rejection_code = "KILL_UNSUPPORTED"
            else:
                projection, lease = self._require_control_in_session(
                    session,
                    execution_id,
                    actor,
                    holder_session_id,
                    client_instance_key_id,
                    controller_lease_id,
                    expected_lease_revision,
                    control_fencing_token,
                )
                if execution.revision != expected_execution_revision:
                    raise OperatorConflictError(
                        "execution revision conflict",
                        current={"execution_revision": execution.revision},
                    )
                in_flight = session.scalar(
                    select(OperatorCommand.id).where(
                        OperatorCommand.execution_id == execution_id,
                        OperatorCommand.state.in_(
                            [
                                "ACCEPTED",
                                "WAITING_SAFE_POINT",
                                "APPLYING",
                                "RECONCILING",
                            ]
                        ),
                    ).limit(1)
                )
                target_step: int | None = None
                if command_type in {"RUN", "GOTO"} and target:
                    if (
                        target.get("source_digest") is not None
                        and target["source_digest"] != projection.source_digest
                    ):
                        raise OperatorConflictError(
                            f"{command_type} target source revision conflict",
                            current={"source_digest": projection.source_digest},
                        )
                    current_frame = (
                        projection.current_lexical_frame_id
                        or self._current_step_field(
                            execution, "lexical_frame_id"
                        )
                    )
                    if execution.ir_version == "0.6" and current_frame is None:
                        raise OperatorConflictError(
                            "command target requires a committed lexical frame"
                        )
                    candidates: list[tuple[int, dict[str, Any]]] = []
                    for index, item in enumerate(execution.steps):
                        if not isinstance(item, dict):
                            continue
                        if (
                            current_frame is not None
                            and item.get("lexical_frame_id") != current_frame
                        ):
                            continue
                        if "line" in target and item.get("line") == target["line"]:
                            candidates.append((index, item))
                            continue
                        if "label" in target and any(
                            isinstance(label, dict)
                            and label.get("name") == target["label"]
                            and label.get("frame_id") == current_frame
                            for label in item.get("labels", [])
                        ):
                            candidates.append((index, item))
                    if not candidates:
                        raise OperatorValidationError(
                            f"{command_type} target is not executable in the current frame"
                        )
                    if len(candidates) != 1:
                        raise OperatorValidationError(
                            f"{command_type} target is ambiguous in the current frame"
                        )
                    target_step, target_item = candidates[0]
                    target_reachability = target_item.get("reachability_id")
                    if execution.ir_version == "0.6" and (
                        type(target_reachability) is not str
                        or not target_reachability
                    ):
                        raise OperatorConflictError(
                            "command target has no static reachability identity"
                        )
                    if command_type == "RUN" and target_step <= execution.current_step:
                        raise OperatorValidationError(
                            "RUN target must be a future executable line"
                        )
                    target = {
                        **target,
                        "source_digest": projection.source_digest,
                        "target_step": target_step,
                        "lexical_frame_id": current_frame,
                        "reachability_id": target_reachability,
                    }
                if in_flight is not None:
                    rejection_code = "COMMAND_IN_FLIGHT"
                else:
                    try:
                        application = validate_operator_command(
                            command_type,
                            projection.state,
                            current_step=execution.current_step,
                            total_steps=execution.total_steps,
                            target_step=target_step,
                            effect_certainty=projection.effect_certainty,
                            background_allowed=projection.background_allowed,
                            prompt_open=projection.state == "PROMPT",
                            interactive_decision_pending=projection.state == "PROMPT",
                        )
                        safe_point = application.safe_point_policy
                    except V06ValidationError as exc:
                        rejection_code = exc.code
            command = OperatorCommand(
                id=new_id(),
                execution_id=execution_id,
                command_type=command_type,
                state="REJECTED" if rejection_code is not None else "ACCEPTED",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expected_execution_revision=expected_execution_revision,
                accepted_execution_revision=(
                    execution.revision if rejection_code is None else None
                ),
                accepted_lease_id=lease.id if lease is not None else None,
                accepted_lease_revision=lease.revision if lease is not None else None,
                accepted_fencing_token=lease.fencing_token if lease is not None else None,
                safe_point=safe_point,
                actor=actor,
                role=role,
                reason=reason,
                correlation_id=correlation_id,
                target=target,
                request_payload=payload,
                result_payload=(
                    {"code": rejection_code, "target_mutation": "NONE"}
                    if rejection_code is not None
                    else {}
                ),
                effect_certainty_before=projection.effect_certainty,
                effect_certainty_after=projection.effect_certainty,
                revision=0,
                rejection_code=rejection_code,
                created_at=now,
                updated_at=now,
                settled_at=now if rejection_code is not None else None,
            )
            session.add(command)
            session.flush()
            if rejection_code is None and command_type == "RUN" and target:
                line = target["line"]
                breakpoint = OperatorBreakpoint(
                    id=new_id(),
                    execution_id=execution_id,
                    source_digest=projection.source_digest,
                    line_id=f"line:{line}",
                    bound_command_id=command.id,
                    one_shot=True,
                    enabled=True,
                    revision=1,
                    created_by=actor,
                    created_at=now,
                )
                session.add(breakpoint)
                session.flush()
                command.result_payload = {
                    "run_to_line": {
                        "breakpoint_id": breakpoint.id,
                        "line": line,
                        "source_digest": projection.source_digest,
                        "one_shot": True,
                        "owned_by_command": True,
                    }
                }
            self._audit(
                session,
                event_type=(
                    "operator.command_rejected"
                    if rejection_code is not None
                    else "operator.command_accepted"
                ),
                aggregate_type="operator_command",
                aggregate_id=command.id,
                execution_id=execution_id,
                actor=actor,
                correlation_id=correlation_id,
                payload={
                    "command_id": command.id,
                    "command_type": command_type,
                    "state": command.state,
                    "rejection_code": rejection_code,
                    "safe_point": safe_point,
                    "effect_certainty": projection.effect_certainty,
                },
                created_at=now,
            )
            session.commit()
            return command_dict(command)

    def begin_operator_command_application(
        self,
        command_id: str,
        application_safe_point_id: str | None = None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        """Re-fence an accepted command immediately before target mutation."""

        command_id = _identifier(command_id, "command_id")
        with self._lock, self.session_factory() as session:
            command_execution_id = session.scalar(
                select(OperatorCommand.execution_id).where(
                    OperatorCommand.id == command_id
                )
            )
            if command_execution_id is None:
                raise OperatorNotFoundError("operator command not found")
            self._require_worker_epoch(
                session, command_execution_id, worker_generation
            )
            command = session.get(OperatorCommand, command_id, with_for_update=True)
            if command is None:
                raise OperatorNotFoundError("operator command not found")
            if command.state == "APPLYING":
                return command_dict(command)
            if command.state in _TERMINAL_COMMAND_STATES:
                return command_dict(command)
            if command.state not in {"ACCEPTED", "WAITING_SAFE_POINT"}:
                raise OperatorConflictError("operator command is not ready to apply")
            projection = session.get(
                ExecutionOperatorState, command.execution_id, with_for_update=True
            )
            execution = session.get(
                Execution, command.execution_id, with_for_update=True
            )
            lease = (
                session.get(
                    ControllerLease,
                    command.accepted_lease_id,
                    with_for_update=True,
                )
                if command.accepted_lease_id is not None
                else None
            )
            now = self._database_now(session)
            if (
                lease is not None
                and lease.state == "ACTIVE"
                and (_stored_utc(lease.expires_at) or now) <= now
            ):
                self._expire_lease(session, projection, lease, now)
            authority_valid = (
                projection is not None
                and execution is not None
                and lease is not None
                and projection.ownership_mode == "C"
                and projection.current_lease_id == command.accepted_lease_id
                and lease.state == "ACTIVE"
                and lease.revision == command.accepted_lease_revision
                and lease.fencing_token == command.accepted_fencing_token
                and projection.control_fencing_token
                == command.accepted_fencing_token
                and (_stored_utc(lease.expires_at) or now) > now
            )
            revision_valid = (
                execution is not None
                and execution.revision == command.expected_execution_revision
            )
            if not authority_valid or not revision_valid:
                rejection_code = (
                    "CONTROL_FENCE_STALE"
                    if not authority_valid
                    else "STALE_EXECUTION_REVISION"
                )
                command.state = "SUPERSEDED"
                command.revision += 1
                command.rejection_code = rejection_code
                command.result_payload = {"target_mutation": "NONE"}
                command.effect_certainty_after = "NO_EFFECT"
                command.updated_at = now
                command.settled_at = now
                bound = session.scalar(
                    select(OperatorBreakpoint).where(
                        OperatorBreakpoint.bound_command_id == command.id
                    )
                )
                if bound is not None:
                    session.delete(bound)
                self._audit(
                    session,
                    event_type="operator.command_superseded",
                    aggregate_type="operator_command",
                    aggregate_id=command.id,
                    execution_id=command.execution_id,
                    actor="operator-runtime",
                    correlation_id=command.correlation_id,
                    payload={
                        "rejection_code": rejection_code,
                        "target_mutation": "NONE",
                    },
                    created_at=now,
                )
                session.commit()
                return command_dict(command)
            if self._has_mutation_reservation(
                session,
                command.execution_id,
                command_id=command.id,
            ):
                return command_dict(command)
            safe_point_id = application_safe_point_id or projection.current_safe_point_id
            if safe_point_id is not None:
                command.application_safe_point_id = _identifier(
                    safe_point_id, "application_safe_point_id"
                )
            application_step = (
                projection.current_step
                if type(projection.current_step) is int
                else execution.current_step
            )
            command.result_payload = {
                **command.result_payload,
                "application_step": application_step,
            }
            command.state = "APPLYING"
            command.revision += 1
            command.updated_at = now
            self._audit(
                session,
                event_type="operator.command_applying",
                aggregate_type="operator_command",
                aggregate_id=command.id,
                execution_id=command.execution_id,
                actor="operator-runtime",
                correlation_id=command.correlation_id,
                payload={
                    "application_safe_point_id": command.application_safe_point_id,
                    "accepted_fencing_token": command.accepted_fencing_token,
                },
                created_at=now,
            )
            session.commit()
            return command_dict(command)

    def reconcile_operator_command_application(
        self, command_id: str
    ) -> dict[str, Any]:
        """Resolve an APPLYING step from its durable execution checkpoint."""

        command_id = _identifier(command_id, "command_id")
        with self._lock, self.session_factory() as session:
            command = session.get(OperatorCommand, command_id, with_for_update=True)
            if command is None:
                raise OperatorNotFoundError("operator command not found")
            if command.state != "APPLYING" or command.command_type not in {
                "STEP",
                "STEP_OVER",
            }:
                return command_dict(command)
            execution = session.get(
                Execution, command.execution_id, with_for_update=True
            )
            projection = session.get(
                ExecutionOperatorState,
                command.execution_id,
                with_for_update=True,
            )
            if execution is None or projection is None:
                raise OperatorNotFoundError("operator command execution not found")
            application_step = command.result_payload.get("application_step")
            if type(application_step) is not int or application_step < 0:
                raise OperatorConflictError(
                    "operator command application checkpoint is missing"
                )
            if execution.current_step == application_step:
                return command_dict(command)
            now = self._database_now(session)
            if execution.current_step > application_step:
                command.state = "SETTLED"
                command.result_payload = {
                    **command.result_payload,
                    "target_step": execution.current_step,
                    "checkpoint_reconciled": True,
                    "applied_execution_revision": execution.revision,
                }
                command.effect_certainty_after = projection.effect_certainty
                event_type = "operator.command_settled"
            else:
                command.state = "FAILED"
                command.rejection_code = "APPLICATION_CHECKPOINT_INCONSISTENT"
                command.result_payload = {
                    **command.result_payload,
                    "target_mutation": "UNKNOWN",
                    "observed_step": execution.current_step,
                }
                command.effect_certainty_after = "EFFECT_UNKNOWN"
                event_type = "operator.command_failed"
            command.revision += 1
            command.updated_at = now
            command.settled_at = now
            self._audit(
                session,
                event_type=event_type,
                aggregate_type="operator_command",
                aggregate_id=command.id,
                execution_id=command.execution_id,
                actor="operator-reconciler",
                correlation_id=command.correlation_id,
                payload={
                    "application_step": application_step,
                    "observed_step": execution.current_step,
                    "state": command.state,
                    "effect_certainty": command.effect_certainty_after,
                },
                created_at=now,
            )
            session.commit()
            return command_dict(command)

    def transition_operator_command(
        self,
        command_id: str,
        state: str,
        *,
        result: dict[str, Any] | None = None,
        rejection_code: str | None = None,
        application_safe_point_id: str | None = None,
        applied_event_id: str | None = None,
        effect_certainty: str | None = None,
        legacy_command_id: str | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        command_id = _identifier(command_id, "command_id")
        state = _identifier(state.upper(), "state")
        if state not in _COMMAND_TRANSITIONS:
            raise OperatorValidationError("operator command state is invalid")
        if effect_certainty is not None and effect_certainty not in {
            "NO_EFFECT",
            "EFFECT_CONFIRMED",
            "EFFECT_POSSIBLE",
            "EFFECT_UNKNOWN",
        }:
            raise OperatorValidationError("effect certainty is invalid")
        with self._lock, self.session_factory() as session:
            command_execution_id = session.scalar(
                select(OperatorCommand.execution_id).where(
                    OperatorCommand.id == command_id
                )
            )
            if command_execution_id is None:
                raise OperatorNotFoundError("operator command not found")
            self._require_worker_epoch(
                session, command_execution_id, worker_generation
            )
            command = session.get(OperatorCommand, command_id, with_for_update=True)
            if command is None:
                raise OperatorNotFoundError("operator command not found")
            if command.state == state:
                return command_dict(command)
            if state not in _COMMAND_TRANSITIONS[command.state]:
                raise OperatorConflictError("invalid operator command state transition")
            if command.state in _TERMINAL_COMMAND_STATES:
                raise OperatorConflictError("operator command is already terminal")
            now = self._database_now(session)
            command.state = state
            command.revision += 1
            command.updated_at = now
            if result is not None:
                command.result_payload = _validate_literal(result)
            if rejection_code is not None:
                command.rejection_code = _identifier(
                    rejection_code, "rejection_code"
                )
            if application_safe_point_id is not None:
                command.application_safe_point_id = _identifier(
                    application_safe_point_id, "application_safe_point_id"
                )
            if applied_event_id is not None:
                command.applied_event_id = _identifier(applied_event_id, "applied_event_id")
            if legacy_command_id is not None:
                command.legacy_command_id = _identifier(
                    legacy_command_id, "legacy_command_id"
                )
            if effect_certainty is not None:
                command.effect_certainty_after = effect_certainty
            if state in _TERMINAL_COMMAND_STATES:
                command.settled_at = now
                if (
                    state in {"REJECTED", "CANCELLED", "SUPERSEDED", "FAILED"}
                    and command.application_safe_point_id is None
                ):
                    bound_breakpoint = session.scalar(
                        select(OperatorBreakpoint).where(
                            OperatorBreakpoint.bound_command_id == command.id
                        )
                    )
                    if bound_breakpoint is not None:
                        session.delete(bound_breakpoint)
            self._audit(
                session,
                event_type=f"operator.command_{state.lower()}",
                aggregate_type="operator_command",
                aggregate_id=command.id,
                execution_id=command.execution_id,
                actor="operator-runtime",
                correlation_id=command.correlation_id,
                payload={
                    "command_id": command.id,
                    "state": state,
                    "revision": command.revision,
                    "rejection_code": command.rejection_code,
                    "effect_certainty": command.effect_certainty_after,
                },
                created_at=now,
            )
            session.commit()
            return command_dict(command)

    def settle_operator_command_application(
        self,
        command_id: str,
        *,
        result: dict[str, Any] | None = None,
        application_safe_point_id: str | None = None,
        applied_event_id: str | None = None,
        effect_certainty: str = "EFFECT_CONFIRMED",
        current_step: int | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        """Settle the operation reserved by ``begin_operator_command_application``."""

        command_id = _identifier(command_id, "command_id")
        if effect_certainty not in {
            "NO_EFFECT",
            "EFFECT_CONFIRMED",
            "EFFECT_POSSIBLE",
            "EFFECT_UNKNOWN",
        }:
            raise OperatorValidationError("effect certainty is invalid")
        if current_step is not None and (
            type(current_step) is not int or current_step < 0
        ):
            raise OperatorValidationError("command checkpoint step is invalid")
        with self._lock, self.session_factory() as session:
            command_execution_id = session.scalar(
                select(OperatorCommand.execution_id).where(
                    OperatorCommand.id == command_id
                )
            )
            if command_execution_id is None:
                raise OperatorNotFoundError("operator command not found")
            self._require_worker_epoch(
                session, command_execution_id, worker_generation
            )
            command = session.get(OperatorCommand, command_id, with_for_update=True)
            if command is None:
                raise OperatorNotFoundError("operator command not found")
            if command.state == "SETTLED":
                if (
                    application_safe_point_id is not None
                    and command.application_safe_point_id
                    not in {None, application_safe_point_id}
                ):
                    raise OperatorConflictError(
                        "operator command has competing safe-point evidence"
                    )
                if (
                    applied_event_id is not None
                    and command.applied_event_id not in {None, applied_event_id}
                ):
                    raise OperatorConflictError(
                        "operator command has competing application evidence"
                    )
                return command_dict(command)
            if command.state in _TERMINAL_COMMAND_STATES:
                return command_dict(command)
            if command.state != "APPLYING":
                raise OperatorConflictError("operator command application has not begun")
            now = self._database_now(session)
            if (
                application_safe_point_id is not None
                and command.application_safe_point_id
                not in {None, application_safe_point_id}
            ):
                raise OperatorConflictError(
                    "operator command application safe point does not match reservation"
                )
            command.state = "SETTLED"
            command.result_payload = _validate_literal(result or {})
            command.effect_certainty_after = effect_certainty
            if command.command_type in {"SKIP", "GOTO"}:
                if current_step is None:
                    raise OperatorConflictError(
                        "command checkpoint evidence is required"
                    )
                execution = session.get(
                    Execution, command.execution_id, with_for_update=True
                )
                projection = session.get(
                    ExecutionOperatorState,
                    command.execution_id,
                    with_for_update=True,
                )
                if execution is None or projection is None:
                    raise OperatorNotFoundError(
                        "command execution checkpoint is unavailable"
                    )
                if command.command_type == "SKIP":
                    expected_step = execution.current_step + 1
                else:
                    expected_step = command.target.get("target_step")
                if (
                    type(expected_step) is not int
                    or expected_step < 0
                    or expected_step >= execution.total_steps
                    or current_step != expected_step
                    or (
                        "target_step" in command.result_payload
                        and command.result_payload["target_step"] != expected_step
                    )
                ):
                    raise OperatorConflictError(
                        "command checkpoint does not match the pinned target"
                    )
                execution.current_step = expected_step
                execution.revision += 1
                projection.current_step = expected_step
                line = execution.steps[expected_step].get("line")
                projection.current_line = line if type(line) is int else None
                projection.revision += 1
                projection.updated_at = now
                command.result_payload = {
                    **command.result_payload,
                    "checkpoint_step": expected_step,
                    "applied_execution_revision": execution.revision,
                }
            command.revision += 1
            command.application_safe_point_id = (
                _identifier(application_safe_point_id, "application_safe_point_id")
                if application_safe_point_id is not None
                else command.application_safe_point_id
            )
            command.applied_event_id = (
                _identifier(applied_event_id, "applied_event_id")
                if applied_event_id is not None
                else None
            )
            command.updated_at = now
            command.settled_at = now
            self._audit(
                session,
                event_type=f"operator.command_{command.state.lower()}",
                aggregate_type="operator_command",
                aggregate_id=command.id,
                execution_id=command.execution_id,
                actor="operator-runtime",
                correlation_id=command.correlation_id,
                payload={
                    "state": command.state,
                    "rejection_code": command.rejection_code,
                    "effect_certainty": command.effect_certainty_after,
                    "application_safe_point_id": command.application_safe_point_id,
                },
                created_at=now,
            )
            session.commit()
            return command_dict(command)

    def apply_background_command(
        self,
        command_id: str,
        application_safe_point_id: str | None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        """Atomically settle BACKGROUND and release the accepted fenced lease."""

        command_id = _identifier(command_id, "command_id")
        begun = self.begin_operator_command_application(
            command_id,
            application_safe_point_id,
            worker_generation=worker_generation,
        )
        if begun["state"] != "APPLYING":
            return begun
        with self._lock, self.session_factory() as session:
            command_execution_id = session.scalar(
                select(OperatorCommand.execution_id).where(
                    OperatorCommand.id == command_id
                )
            )
            if command_execution_id is None:
                raise OperatorNotFoundError("operator command not found")
            self._require_worker_epoch(
                session, command_execution_id, worker_generation
            )
            command = session.get(OperatorCommand, command_id, with_for_update=True)
            if command is None:
                raise OperatorNotFoundError("operator command not found")
            if command.command_type != "BACKGROUND":
                raise OperatorValidationError("command is not BACKGROUND")
            if command.state == "SETTLED":
                return command_dict(command)
            if command.state in _TERMINAL_COMMAND_STATES:
                raise OperatorConflictError("operator command is already terminal")
            if command.state != "APPLYING":
                raise OperatorConflictError("BACKGROUND command is not applicable")
            projection = session.get(
                ExecutionOperatorState, command.execution_id, with_for_update=True
            )
            lease = (
                session.get(ControllerLease, command.accepted_lease_id, with_for_update=True)
                if command.accepted_lease_id is not None
                else None
            )
            if projection is None or lease is None:
                raise OperatorConflictError("accepted BACKGROUND control proof is unavailable")
            now = self._database_now(session)
            safe_point_id = application_safe_point_id or projection.current_safe_point_id
            if safe_point_id is None:
                raise OperatorConflictError("BACKGROUND requires a committed safe point")
            safe_point_id = _identifier(safe_point_id, "application_safe_point_id")

            lease.state = "RELEASED"
            lease.revision += 1
            lease.terminated_at = now
            lease.termination_reason = "BACKGROUND_COMMAND"
            lease.updated_at = now
            projection.ownership_mode = "B"
            projection.current_lease_id = None
            projection.revision += 1
            projection.updated_at = now
            command.state = "SETTLED"
            command.revision += 1
            command.application_safe_point_id = safe_point_id
            command.result_payload = {
                "ownership_mode": "B",
                "released_lease_id": lease.id,
                "target_mutation": "CONFIRMED",
            }
            command.effect_certainty_after = projection.effect_certainty
            command.updated_at = now
            command.settled_at = now
            self._audit(
                session,
                event_type="operator.background_applied",
                aggregate_type="operator_command",
                aggregate_id=command.id,
                execution_id=command.execution_id,
                actor="operator-runtime",
                correlation_id=command.correlation_id,
                payload={
                    "command_id": command.id,
                    "lease_id": lease.id,
                    "lease_revision": lease.revision,
                    "control_fencing_token": lease.fencing_token,
                    "ownership_mode": "B",
                    "safe_point_id": safe_point_id,
                },
                created_at=now,
            )
            session.commit()
            return command_dict(command)

    def ensure_legacy_prompt_projection(
        self,
        prompt_id: str,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        """Idempotently project an open legacy Prompt into the fenced prompt store."""

        prompt_id = _identifier(prompt_id, "prompt_id")
        with self._lock, self.session_factory() as session:
            existing = session.get(OperatorPrompt, prompt_id)
            if existing is not None:
                return prompt_dict(existing)
            linked = session.scalar(
                select(OperatorPrompt).where(
                    OperatorPrompt.legacy_prompt_id == prompt_id
                )
            )
            if linked is not None:
                if linked.id != prompt_id:
                    raise OperatorConflictError(
                        "legacy prompt is bound to another operator prompt identity"
                    )
                return prompt_dict(linked)
            legacy = session.get(Prompt, prompt_id)
            if legacy is None:
                raise OperatorNotFoundError("prompt not found")
            execution = session.get(Execution, legacy.execution_id)
            projection = session.get(ExecutionOperatorState, legacy.execution_id)
            if execution is None:
                raise OperatorNotFoundError("prompt execution not found")
            if projection is None:
                raise OperatorNotFoundError(
                    "prompt execution has no operator projection"
                )
            if legacy.status != "open" and execution.state not in {
                "completed",
                "aborted",
                "failed",
            }:
                raise OperatorConflictError("legacy prompt is not open")
            if not isinstance(legacy.choices, list) or not legacy.choices:
                raise OperatorValidationError("legacy prompt choices are invalid")
            choices = [
                {
                    "value": _bounded(choice, "legacy prompt choice", 200),
                    "label": _bounded(choice, "legacy prompt choice label", 500),
                }
                for choice in legacy.choices
            ]
            question = _bounded(legacy.question, "legacy prompt question", 10_000)
            default = legacy.default_choice
            execution_id = legacy.execution_id
            step_index = legacy.step_index
        return self.open_typed_prompt(
            execution_id,
            prompt_id,
            step_index,
            {
                "type": "LIST",
                "question": question,
                "options": choices,
                "list_mode": "VALUE",
                "default": default,
            },
            {},
            legacy_prompt_id=prompt_id,
            worker_generation=worker_generation,
        )

    def open_typed_prompt(
        self,
        execution_id: str,
        prompt_id: str,
        step_index: int,
        declaration: dict[str, Any],
        settings_snapshot: dict[str, Any],
        *,
        legacy_prompt_id: str | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        prompt_id = _identifier(prompt_id, "prompt_id")
        if type(step_index) is not int or step_index < 0:
            raise OperatorValidationError("prompt step index is invalid")
        declaration = _validate_literal(declaration)
        settings_snapshot = _validate_literal(settings_snapshot)
        if type(declaration) is not dict or set(declaration) - {
            "type",
            "question",
            "options",
            "default",
            "list_mode",
            "warning_delay_seconds",
            "response_timeout_seconds",
            "no_controller_grace_seconds",
        }:
            raise OperatorValidationError(
                "prompt declaration contains unsupported fields"
            )
        if type(settings_snapshot) is not dict or set(settings_snapshot) - {
            "PROMPT_WARNING_DELAY",
            "PROMPT_RESPONSE_TIMEOUT",
            "NO_CONTROLLER_GRACE",
        }:
            raise OperatorValidationError(
                "prompt settings snapshot contains unsupported fields"
            )
        raw_prompt_type = declaration.get("type", "OK")
        raw_question = declaration.get("question")
        raw_options = declaration.get("options")
        raw_default = declaration.get("default")
        raw_list_mode = declaration.get("list_mode")
        try:
            spec = validate_prompt_declaration(
                raw_question,
                prompt_type=raw_prompt_type,
                choices=raw_options,
                default=raw_default,
                list_mode=raw_list_mode,
                warning_delay_seconds=declaration.get("warning_delay_seconds"),
                response_timeout_seconds=declaration.get("response_timeout_seconds"),
                no_controller_grace_seconds=declaration.get(
                    "no_controller_grace_seconds"
                ),
            )
        except V06ValidationError as exc:
            if exc.code == "PROMPT_SECRET_MATERIAL_REJECTED":
                raise PromptSecretMaterialError(
                    "prompt declaration contains prohibited secret material"
                ) from exc
            raise OperatorValidationError(
                f"prompt declaration is invalid ({exc.code})"
            ) from exc
        prompt_type = spec.prompt_type
        input_kind = _PROMPT_TYPES[prompt_type][0]
        question = spec.question
        options = list(spec.choices)
        list_mode = spec.list_mode
        default = spec.default
        with self._lock, self.session_factory() as session:
            self._require_worker_epoch(
                session, execution_id, worker_generation
            )
            existing = session.get(OperatorPrompt, prompt_id, with_for_update=True)
            if existing is not None:
                requested = canonical_digest(
                    {
                        "execution_id": execution_id,
                        "step_index": step_index,
                        "type": prompt_type,
                        "list_mode": list_mode,
                        "question": question,
                        "options": options,
                        "default": default,
                    }
                )
                stored = canonical_digest(
                    {
                        "execution_id": existing.execution_id,
                        "step_index": existing.step_index,
                        "type": existing.prompt_type,
                        "list_mode": existing.list_mode,
                        "question": existing.question,
                        "options": existing.options,
                        "default": existing.default_value,
                    }
                )
                if requested != stored:
                    raise OperatorConflictError(
                        "PromptId is already bound to another declaration"
                    )
                return prompt_dict(existing)
            execution = session.get(Execution, execution_id, with_for_update=True)
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if execution is None or projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            if step_index >= execution.total_steps:
                raise OperatorConflictError("prompt step is outside the execution")
            context = session.get(OperatorContext, projection.context_id)
            context_settings = context.settings if context is not None else {}
            resolved_settings: dict[str, Any] = {}
            for key in (
                "PROMPT_WARNING_DELAY",
                "PROMPT_RESPONSE_TIMEOUT",
                "NO_CONTROLLER_GRACE",
            ):
                value = None
                for source in (context_settings, projection.settings, settings_snapshot):
                    candidate = source.get(key) if isinstance(source, dict) else None
                    if candidate is not None:
                        value = candidate
                normalized = self._optional_duration(
                    value,
                    key,
                    maximum=86_400 if key == "PROMPT_WARNING_DELAY" else 604_800,
                )
                resolved_settings[key] = normalized if normalized else None
            explicit_settings = {
                "PROMPT_WARNING_DELAY": (
                    "warning_delay_seconds",
                    spec.warning_delay_seconds,
                ),
                "PROMPT_RESPONSE_TIMEOUT": (
                    "response_timeout_seconds",
                    spec.response_timeout_seconds,
                ),
                "NO_CONTROLLER_GRACE": (
                    "no_controller_grace_seconds",
                    spec.no_controller_grace_seconds,
                ),
            }
            for key, (declaration_key, value) in explicit_settings.items():
                if declaration_key in declaration:
                    resolved_settings[key] = value
            settings_snapshot = resolved_settings
            now = self._database_now(session)
            warning_delay = self._optional_duration(
                settings_snapshot.get("PROMPT_WARNING_DELAY"),
                "PROMPT_WARNING_DELAY",
                maximum=86_400,
            )
            response_timeout = self._optional_duration(
                settings_snapshot.get("PROMPT_RESPONSE_TIMEOUT"),
                "PROMPT_RESPONSE_TIMEOUT",
                maximum=604_800,
            )
            no_controller_grace = self._optional_duration(
                settings_snapshot.get("NO_CONTROLLER_GRACE"),
                "NO_CONTROLLER_GRACE",
                maximum=604_800,
            )
            active_lease = self._active_lease(session, projection, expire=True)
            has_controller = (
                projection.ownership_mode == "C" and active_lease is not None
            )
            terminal_outcome = (
                "ERROR"
                if execution.state == "failed"
                else "EXECUTION_TERMINATED"
                if execution.state in {"completed", "aborted"}
                else None
            )
            prompt = OperatorPrompt(
                id=prompt_id,
                execution_id=execution_id,
                legacy_prompt_id=(
                    _identifier(legacy_prompt_id, "legacy_prompt_id")
                    if legacy_prompt_id is not None
                    else None
                ),
                step_index=step_index,
                revision=1,
                state="SETTLED" if terminal_outcome is not None else "OPEN",
                prompt_type=prompt_type,
                input_kind=input_kind,
                list_mode=list_mode,
                question=question,
                options=options,
                option_revision=1,
                settings_snapshot=settings_snapshot,
                warning_at=(
                    now + timedelta(seconds=warning_delay)
                    if warning_delay and terminal_outcome is None
                    else None
                ),
                response_deadline=(
                    now + timedelta(seconds=response_timeout)
                    if response_timeout and terminal_outcome is None
                    else None
                ),
                no_controller_deadline=(
                    now + timedelta(seconds=no_controller_grace)
                    if no_controller_grace
                    and not has_controller
                    and terminal_outcome is None
                    else None
                ),
                attempt_count=0,
                created_at=now,
                opened_at=now,
            )
            if default is not None:
                prompt.default_value = self._validate_prompt_value(prompt, default)
            if terminal_outcome is not None:
                prompt.settlement_id = new_id()
                prompt.settlement_outcome = terminal_outcome
                prompt.settled_by = "operator-runtime"
                prompt.settled_at = now
            session.add(prompt)
            if terminal_outcome is None:
                projection.resume_state = projection.state
                if projection.ownership_mode == "B":
                    projection.state = "SUSPENDED"
                    projection.ownership_mode = "CONTROL_LOST"
                    projection.hold_reason = "CONTROL_LOST"
                else:
                    projection.state = "PROMPT"
                projection.revision += 1
                projection.updated_at = now
            self._audit(
                session,
                event_type=(
                    "prompt.opened"
                    if terminal_outcome is None
                    else "prompt.settled"
                ),
                aggregate_type="operator_prompt",
                aggregate_id=prompt.id,
                execution_id=execution_id,
                actor="operator-runtime",
                payload={
                    "prompt_id": prompt.id,
                    "prompt_revision": prompt.revision,
                    "type": prompt.prompt_type,
                    "settlement_id": prompt.settlement_id,
                    "settlement_outcome": prompt.settlement_outcome,
                    "warning_at": prompt.warning_at.isoformat() if prompt.warning_at else None,
                    "response_deadline": (
                        prompt.response_deadline.isoformat()
                        if prompt.response_deadline
                        else None
                    ),
                },
                created_at=now,
            )
            session.commit()
            return prompt_dict(prompt)

    def settle_prompt(
        self,
        prompt_id: str,
        expected_prompt_revision: int,
        action: str,
        value: Any,
        actor: str,
        controller_lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        prompt_id = _identifier(prompt_id, "prompt_id")
        action = _identifier(action.upper(), "action")
        if action not in {"COMMIT", "ABORT", "RESET"}:
            raise OperatorValidationError("prompt action is invalid")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000) if reason is not None else None
        if action == "RESET":
            return {
                "action": "RESET",
                "draft_cleared": True,
                "durable_state_changed": False,
            }
        value = _validate_literal(value)
        if action == "COMMIT":
            _reject_prompt_secret_material(value)
        request_digest = canonical_digest(
            {
                "prompt_id": prompt_id,
                "expected_prompt_revision": expected_prompt_revision,
                "action": action,
                "value": value,
                "actor": actor,
                "controller_lease_id": controller_lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
        )
        delivery_prompt_id: str | None = None
        with self._lock, self.session_factory() as session:
            prompt = session.get(OperatorPrompt, prompt_id, with_for_update=True)
            if prompt is None:
                raise OperatorNotFoundError("operator prompt not found")
            prior_attempt = session.scalar(
                select(PromptAttempt).where(
                    PromptAttempt.prompt_id == prompt_id,
                    PromptAttempt.actor == actor,
                    PromptAttempt.idempotency_key == idempotency_key,
                )
            )
            if prior_attempt is not None:
                if prior_attempt.request_digest != request_digest:
                    raise OperatorConflictError(
                        "idempotency key was used for another prompt attempt"
                    )
                return {
                    "prompt": prompt_dict(prompt),
                    "attempt": prompt_attempt_dict(prior_attempt),
                }
            projection, lease = self._require_control_in_session(
                session,
                prompt.execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(controller_lease_id, "controller_lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            now = self._database_now(session)
            outcome = "ACCEPTED_SETTLEMENT"
            normalized_value: Any = None
            if prompt.state != "OPEN":
                outcome = "LOST_SETTLEMENT_RACE"
            elif prompt.revision != expected_prompt_revision:
                outcome = "STALE_PROMPT_REVISION"
            elif action == "COMMIT":
                try:
                    normalized_value = self._validate_prompt_value(prompt, value)
                except OperatorValidationError:
                    outcome = "INVALID_VALUE"
            attempt = PromptAttempt(
                id=new_id(),
                prompt_id=prompt.id,
                prompt_revision=expected_prompt_revision,
                actor=actor,
                action=action,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                outcome=outcome,
                value_digest=canonical_digest(value) if action == "COMMIT" else None,
                settlement_id=prompt.settlement_id,
                controller_lease_id=lease.id,
                accepted_lease_revision=lease.revision,
                control_fencing_token=lease.fencing_token,
                created_at=now,
            )
            prompt.attempt_count += 1
            if outcome == "ACCEPTED_SETTLEMENT":
                prompt.state = "SETTLED"
                prompt.revision += 1
                prompt.settlement_id = new_id()
                prompt.settlement_outcome = (
                    "ANSWERED" if action == "COMMIT" else "CANCELLED"
                )
                prompt.settled_value = normalized_value if action == "COMMIT" else None
                prompt.settled_by = actor
                prompt.settled_at = now
                attempt.settlement_id = prompt.settlement_id
                projection.state = projection.resume_state or "PAUSED"
                projection.resume_state = None
                projection.revision += 1
                projection.updated_at = now
            session.add(attempt)
            self._audit(
                session,
                event_type=(
                    "prompt.settled"
                    if outcome == "ACCEPTED_SETTLEMENT"
                    else "prompt.attempt_rejected"
                ),
                aggregate_type="operator_prompt",
                aggregate_id=prompt.id,
                execution_id=prompt.execution_id,
                actor=actor,
                payload={
                    "prompt_id": prompt.id,
                    "attempt_id": attempt.id,
                    "outcome": outcome,
                    "settlement_id": prompt.settlement_id,
                    "settlement_outcome": prompt.settlement_outcome,
                },
                created_at=now,
            )
            session.commit()
            response = {
                "prompt": prompt_dict(prompt),
                "attempt": prompt_attempt_dict(attempt),
            }
            if outcome == "ACCEPTED_SETTLEMENT":
                delivery_prompt_id = prompt.id
        if delivery_prompt_id is not None:
            self._deliver_prompt_settlement(delivery_prompt_id)
        return response

    @staticmethod
    def _optional_duration(value: Any, label: str, *, maximum: int) -> float | None:
        if value in {None, 0, 0.0, "0"}:
            return None
        if type(value) not in {float, int} or isinstance(value, bool):
            raise OperatorValidationError(f"{label} must be a finite duration")
        duration = float(value)
        if not math.isfinite(duration) or duration < 0 or duration > maximum:
            raise OperatorValidationError(f"{label} is outside its bound")
        return duration

    @staticmethod
    def _validate_prompt_value(prompt: OperatorPrompt, value: Any) -> Any:
        try:
            return normalize_prompt_value(
                prompt.prompt_type,
                value,
                choices=prompt.options,
                list_mode=prompt.list_mode,
            )
        except V06ValidationError as exc:
            if exc.code == "PROMPT_SECRET_MATERIAL_REJECTED":
                raise PromptSecretMaterialError(
                    "prompt response contains prohibited secret material"
                ) from exc
            raise OperatorValidationError(
                f"prompt response is invalid ({exc.code})"
            ) from exc

    def create_schedule(
        self,
        *,
        controller_execution_id: str,
        schedule_type: str,
        target: str | int | float,
        procedure_catalog_id: str,
        procedure_revision: int | None,
        context_id: str,
        arguments: dict[str, Any],
        automatic: bool,
        background_allowed: bool,
        visible: bool,
        misfire_policy: str,
        maximum_lateness_seconds: int,
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        controller_execution_id = _identifier(
            controller_execution_id, "controller_execution_id"
        )
        schedule_type = _identifier(str(schedule_type).upper(), "schedule_type")
        if schedule_type not in {"RELATIVE", "ABSOLUTE"}:
            if schedule_type == "TELEMETRY_CONDITION":
                raise OperatorValidationError("SCHEDULE_TYPE_DEFERRED_V07")
            raise OperatorValidationError("SCHEDULE_TYPE_NOT_IN_V06")
        procedure_catalog_id = _bounded(procedure_catalog_id, "procedure_catalog_id")
        context_id = _identifier(context_id, "context_id")
        arguments = _validate_literal(arguments)
        if not isinstance(arguments, dict) or len(arguments) > 64:
            raise OperatorValidationError("schedule arguments exceed their map bound")
        try:
            _reject_prompt_secret_material(arguments, "arguments")
        except PromptSecretMaterialError as exc:
            raise OperatorValidationError(
                "secret material is not accepted in schedule arguments"
            ) from exc
        misfire_policy = _identifier(misfire_policy.upper(), "misfire_policy")
        if misfire_policy not in {"FIRE_ONCE", "SKIP"}:
            raise OperatorValidationError("misfire_policy must be FIRE_ONCE or SKIP")
        if (
            type(maximum_lateness_seconds) is not int
            or maximum_lateness_seconds < 0
            or maximum_lateness_seconds > 604_800
        ):
            raise OperatorValidationError("maximum lateness is outside its bound")
        if automatic and not background_allowed:
            raise OperatorValidationError(
                "automatic scheduled execution requires BackgroundAllowed"
            )
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(ProcedureSchedule).where(
                    ProcedureSchedule.created_by == actor,
                    ProcedureSchedule.idempotency_key == idempotency_key,
                )
            )
            now = self._database_now(session)
            original_target, original_offset, duration, target_at = self._schedule_target(
                schedule_type, target, now
            )
            request = {
                "controller_execution_id": controller_execution_id,
                "schedule_type": schedule_type,
                "original_target": original_target,
                "procedure_catalog_id": procedure_catalog_id,
                "procedure_revision": procedure_revision,
                "context_id": context_id,
                "arguments": arguments,
                "automatic": automatic,
                "background_allowed": background_allowed,
                "visible": visible,
                "misfire_policy": misfire_policy,
                "maximum_lateness_seconds": maximum_lateness_seconds,
                "expected_execution_revision": expected_execution_revision,
                "actor": actor,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
            request_digest = canonical_digest(request)
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise OperatorConflictError(
                        "idempotency key was used for another schedule"
                    )
                return schedule_dict(existing)
            projection, _lease = self._require_control_in_session(
                session,
                controller_execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, controller_execution_id)
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            if projection.state in {"FINISHED", "ABORTED", "ERROR"}:
                raise OperatorConflictError("terminal execution cannot create schedules")
            context = session.get(OperatorContext, context_id)
            if context is None or not context.enabled:
                raise OperatorConflictError("schedule context is unavailable")
            entry = session.scalar(
                select(ProcedureCatalogEntry).where(
                    or_(
                        ProcedureCatalogEntry.id == procedure_catalog_id,
                        ProcedureCatalogEntry.procedure_ref == procedure_catalog_id,
                    )
                )
            )
            if entry is None:
                raise OperatorNotFoundError("procedure catalog entry not found")
            wanted_revision = procedure_revision or entry.current_revision
            revision = session.scalar(
                select(ProcedureCatalogRevision).where(
                    ProcedureCatalogRevision.catalog_id == entry.id,
                    ProcedureCatalogRevision.revision == wanted_revision,
                )
            )
            if revision is None:
                raise OperatorNotFoundError("procedure catalog revision not found")
            arguments_digest = canonical_digest(arguments)
            schedule = ProcedureSchedule(
                id=new_id(),
                revision=0,
                controller_execution_id=controller_execution_id,
                schedule_type=schedule_type,
                original_target=original_target,
                original_offset=original_offset,
                original_duration_seconds=duration,
                target_at=target_at,
                catalog_revision_id=revision.id,
                procedure_catalog_id=entry.id,
                procedure_revision=revision.revision,
                bundle_digest=revision.bundle_digest,
                context_id=context_id,
                arguments=arguments,
                arguments_digest=arguments_digest,
                automatic=automatic,
                background_allowed=background_allowed,
                visible=visible,
                misfire_policy=misfire_policy,
                maximum_lateness_seconds=maximum_lateness_seconds,
                state="PENDING",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                created_by=actor,
                created_at=now,
                updated_at=now,
            )
            session.add(schedule)
            self._audit(
                session,
                event_type="schedule.created",
                aggregate_type="procedure_schedule",
                aggregate_id=schedule.id,
                execution_id=controller_execution_id,
                actor=actor,
                payload={
                    "schedule_id": schedule.id,
                    "schedule_type": schedule.schedule_type,
                    "target_at_database_time": schedule.target_at.isoformat(),
                    "catalog_revision_id": revision.id,
                    "arguments_digest": arguments_digest,
                },
                created_at=now,
            )
            session.commit()
            return schedule_dict(schedule)

    def list_schedules(
        self, *, controller_execution_id: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise OperatorValidationError("limit must be 1 through 500")
        with self.session_factory() as session:
            query = select(ProcedureSchedule)
            if controller_execution_id is not None:
                query = query.where(
                    ProcedureSchedule.controller_execution_id
                    == _identifier(controller_execution_id, "controller_execution_id")
                )
            schedules = session.scalars(
                query.order_by(ProcedureSchedule.created_at.desc()).limit(limit)
            ).all()
            return [schedule_dict(item) for item in schedules]

    def cancel_schedule(
        self,
        schedule_id: str,
        *,
        expected_schedule_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        schedule_id = _identifier(schedule_id, "schedule_id")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        request_digest = canonical_digest(
            {
                "schedule_id": schedule_id,
                "expected_schedule_revision": expected_schedule_revision,
                "actor": actor,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
        )
        scope = f"schedule-cancel:{schedule_id}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            schedule = session.get(ProcedureSchedule, schedule_id, with_for_update=True)
            if schedule is None:
                raise OperatorNotFoundError("schedule not found")
            self._require_control_in_session(
                session,
                schedule.controller_execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            if schedule.revision != expected_schedule_revision:
                raise OperatorConflictError(
                    "schedule revision conflict", current={"schedule": schedule_dict(schedule)}
                )
            if schedule.state != "PENDING":
                return schedule_dict(schedule)
            now = self._database_now(session)
            schedule.state = "CANCELLED"
            schedule.revision += 1
            schedule.updated_at = now
            schedule.settled_at = now
            response = schedule_dict(schedule)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="procedure_schedule",
                resource_id=schedule.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="schedule.cancelled",
                aggregate_type="procedure_schedule",
                aggregate_id=schedule.id,
                execution_id=schedule.controller_execution_id,
                actor=actor,
                payload={"schedule_id": schedule.id, "revision": schedule.revision},
                created_at=now,
            )
            session.commit()
            return response

    @staticmethod
    def _schedule_target(
        schedule_type: str, target: str | int | float, now: datetime
    ) -> tuple[str, str | None, str | None, datetime]:
        horizon = now + timedelta(days=365)
        if schedule_type == "RELATIVE":
            if isinstance(target, bool) or type(target) not in {str, int, float}:
                raise OperatorValidationError("relative target must be a duration in seconds")
            try:
                duration = Decimal(str(target))
            except InvalidOperation as exc:
                raise OperatorValidationError("relative target is not a duration") from exc
            if not duration.is_finite() or duration <= 0 or duration > Decimal(31_536_000):
                raise OperatorValidationError("relative duration is outside its bound")
            seconds = float(duration)
            target_at = now + timedelta(seconds=seconds)
            return str(target), None, format(duration.normalize(), "f"), target_at
        if type(target) is not str or not _ABSOLUTE_TIME.fullmatch(target):
            raise OperatorValidationError(
                "absolute target must be RFC 3339 with an explicit UTC offset"
            )
        normalized = target[:-1] + "+00:00" if target.endswith("Z") else target
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise OperatorValidationError("absolute target is invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise OperatorValidationError("absolute target requires a UTC offset")
        target_at = parsed.astimezone(timezone.utc)
        if target_at <= now or target_at > horizon:
            raise OperatorValidationError("absolute target is outside the scheduling horizon")
        offset = "Z" if target.endswith("Z") else target[-6:]
        return target, offset, None, target_at

    def reconcile_once(self) -> dict[str, int]:
        expired = self.expire_due_leases()
        expired_handovers = self.expire_due_handovers()
        prompts = self.reconcile_prompt_timers()
        schedules = self.reconcile_schedules()
        startproc_admissions = len(self.reconcile_startproc_admissions())
        startproc_children = len(self.reconcile_startproc_children())
        deliveries = self.replay_prompt_deliveries()
        return {
            "leases": expired,
            "handovers": expired_handovers,
            "prompts": prompts,
            "prompt_deliveries": deliveries,
            "schedules": schedules,
            "startproc_admissions": startproc_admissions,
            "startproc_children": startproc_children,
        }

    def _expire_handover_row(
        self,
        session: Session,
        handover: ControllerHandover,
        now: datetime,
    ) -> None:
        if handover.state != "REQUESTED":
            return
        handover.state = "EXPIRED"
        handover.revision += 1
        handover.updated_at = now
        handover.settled_at = now
        self._audit(
            session,
            event_type="control.handover_expired",
            aggregate_type="controller_handover",
            aggregate_id=handover.id,
            execution_id=handover.execution_id,
            actor="operator-reconciler",
            payload={"revision": handover.revision},
            created_at=now,
        )

    def expire_due_handovers(self, *, execution_id: str | None = None) -> int:
        count = 0
        with self._lock, self.session_factory() as session:
            now = self._database_now(session)
            query = select(ControllerHandover).where(
                ControllerHandover.state == "REQUESTED",
                ControllerHandover.expires_at <= now,
            )
            if execution_id is not None:
                query = query.where(
                    ControllerHandover.execution_id
                    == _identifier(execution_id, "execution_id")
                )
            rows = session.scalars(query.with_for_update()).all()
            for handover in rows:
                self._expire_handover_row(session, handover, now)
                count += 1
            session.commit()
        return count

    def expire_due_leases(self) -> int:
        count = 0
        with self._lock, self.session_factory() as session:
            now = self._database_now(session)
            leases = session.scalars(
                select(ControllerLease)
                .where(
                    ControllerLease.state == "ACTIVE",
                    ControllerLease.expires_at <= now,
                )
                .with_for_update()
            ).all()
            for lease in leases:
                projection = session.get(
                    ExecutionOperatorState, lease.execution_id, with_for_update=True
                )
                if projection is None or projection.current_lease_id != lease.id:
                    continue
                if self._expire_lease(session, projection, lease, now):
                    count += 1
            session.commit()
        return count

    def list_pending_control_loss(
        self, execution_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            query = select(ExecutionOperatorState).where(
                ExecutionOperatorState.control_loss_fencing_token.is_not(None),
                ExecutionOperatorState.control_loss_applied_at.is_(None),
            )
            if execution_id is not None:
                query = query.where(
                    ExecutionOperatorState.execution_id
                    == _identifier(execution_id, "execution_id")
                )
            rows = session.scalars(query.order_by(ExecutionOperatorState.updated_at)).all()
            return [
                {
                    "execution_id": row.execution_id,
                    "fencing_token": row.control_loss_fencing_token,
                    "requested_at": (
                        row.control_loss_requested_at.isoformat()
                        if row.control_loss_requested_at is not None
                        else None
                    ),
                    "hold_reason": row.hold_reason,
                    "saved_resume_target": row.saved_resume_target,
                }
                for row in rows
            ]

    def ack_control_loss_application(
        self,
        execution_id: str,
        fencing_token: int,
        safe_point_id: str | None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        with self._lock, self.session_factory() as session:
            self._require_worker_epoch(
                session, execution_id, worker_generation
            )
            projection = session.get(
                ExecutionOperatorState, execution_id, with_for_update=True
            )
            if projection is None:
                raise OperatorNotFoundError("operator execution projection not found")
            if projection.control_loss_fencing_token != fencing_token:
                raise OperatorConflictError("control-loss fence does not match")
            if projection.control_loss_applied_at is not None:
                return operator_state_dict(projection)
            safe_point_id = _identifier(
                safe_point_id or projection.current_safe_point_id,
                "safe_point_id",
            )
            now = self._database_now(session)
            projection.control_loss_applied_at = now
            projection.control_loss_safe_point_id = safe_point_id
            projection.current_safe_point_id = safe_point_id
            projection.revision += 1
            projection.updated_at = now
            self._audit(
                session,
                event_type="control.loss_applied",
                aggregate_type="execution",
                aggregate_id=execution_id,
                execution_id=execution_id,
                actor="operator-runtime",
                payload={
                    "control_fencing_token": fencing_token,
                    "safe_point_id": safe_point_id,
                },
                created_at=now,
            )
            session.commit()
            return operator_state_dict(projection)

    def reconcile_prompt_timers(self) -> int:
        settled = 0
        delivery_ids: list[str] = []
        with self._lock, self.session_factory() as session:
            now = self._database_now(session)
            prompts = session.scalars(
                select(OperatorPrompt)
                .where(OperatorPrompt.state == "OPEN")
                .with_for_update()
            ).all()
            for prompt in prompts:
                if (
                    prompt.warning_at is not None
                    and prompt.warning_emitted_at is None
                    and (_stored_utc(prompt.warning_at) or now) <= now
                ):
                    prompt.warning_emitted_at = now
                    self._audit(
                        session,
                        event_type="prompt.warning_due",
                        aggregate_type="operator_prompt",
                        aggregate_id=prompt.id,
                        execution_id=prompt.execution_id,
                        actor="operator-reconciler",
                        payload={"prompt_id": prompt.id},
                        created_at=now,
                    )
                deadline_due = (
                    prompt.response_deadline is not None
                    and (_stored_utc(prompt.response_deadline) or now) <= now
                )
                no_controller_due = (
                    prompt.no_controller_deadline is not None
                    and (_stored_utc(prompt.no_controller_deadline) or now) <= now
                )
                if not deadline_due and not no_controller_due:
                    continue
                projection = session.get(ExecutionOperatorState, prompt.execution_id)
                if no_controller_due and projection is not None and projection.ownership_mode == "C":
                    no_controller_due = False
                if not deadline_due and not no_controller_due:
                    continue
                outcome = "NO_CONTROLLER" if no_controller_due else "TIMED_OUT"
                value = None
                if deadline_due and prompt.default_value is not None:
                    outcome = "ANSWERED"
                    value = prompt.default_value
                prompt.state = "SETTLED"
                prompt.revision += 1
                prompt.settlement_id = new_id()
                prompt.settlement_outcome = outcome
                prompt.settled_value = value
                prompt.settled_by = "operator-reconciler"
                prompt.settled_at = now
                if projection is not None:
                    projection.state = projection.resume_state or "SUSPENDED"
                    projection.resume_state = None
                    projection.revision += 1
                    projection.updated_at = now
                self._audit(
                    session,
                    event_type="prompt.settled",
                    aggregate_type="operator_prompt",
                    aggregate_id=prompt.id,
                    execution_id=prompt.execution_id,
                    actor="operator-reconciler",
                    payload={
                        "prompt_id": prompt.id,
                        "settlement_id": prompt.settlement_id,
                        "outcome": outcome,
                    },
                    created_at=now,
                )
                settled += 1
                delivery_ids.append(prompt.id)
            session.commit()
        for prompt_id in delivery_ids:
            self._deliver_prompt_settlement(prompt_id)
        return settled

    def reconcile_schedules(self) -> int:
        processed = 0
        claimed_ids: list[str] = []
        with self._lock, self.session_factory() as session:
            now = self._database_now(session)
            schedules = session.scalars(
                select(ProcedureSchedule)
                .where(
                    ProcedureSchedule.state == "PENDING",
                    ProcedureSchedule.target_at <= now,
                )
                .order_by(ProcedureSchedule.target_at, ProcedureSchedule.id)
                .with_for_update()
            ).all()
            for schedule in schedules:
                target_at = _stored_utc(schedule.target_at) or now
                lateness = max(0.0, (now - target_at).total_seconds())
                should_skip = (
                    schedule.misfire_policy == "SKIP"
                    and lateness > schedule.maximum_lateness_seconds
                )
                occurrence_id = canonical_digest(
                    {"schedule_id": schedule.id, "target_at": target_at.isoformat()}
                )
                if should_skip:
                    schedule.state = "MISSED"
                    schedule.revision += 1
                    schedule.occurrence_id = occurrence_id
                    schedule.updated_at = now
                    schedule.settled_at = now
                    session.add(
                        ScheduleOccurrence(
                            id=occurrence_id,
                            schedule_id=schedule.id,
                            target_at=target_at,
                            state="MISSED",
                            claimed_at=now,
                            settled_at=now,
                        )
                    )
                    self._audit(
                        session,
                        event_type="schedule.missed",
                        aggregate_type="procedure_schedule",
                        aggregate_id=schedule.id,
                        execution_id=schedule.controller_execution_id,
                        actor="operator-reconciler",
                        payload={
                            "schedule_id": schedule.id,
                            "occurrence_id": occurrence_id,
                            "lateness_seconds": lateness,
                            "maximum_lateness_seconds": (
                                schedule.maximum_lateness_seconds
                            ),
                        },
                        created_at=now,
                    )
                    processed += 1
                    continue
                schedule.state = "CLAIMED"
                schedule.revision += 1
                schedule.occurrence_id = occurrence_id
                schedule.updated_at = now
                session.add(
                    ScheduleOccurrence(
                        id=occurrence_id,
                        schedule_id=schedule.id,
                        target_at=target_at,
                        state="CLAIMED",
                        claimed_at=now,
                    )
                )
                claimed_ids.append(schedule.id)
            session.commit()
        for schedule_id in claimed_ids:
            if self._fire_claimed_schedule(schedule_id):
                processed += 1
        with self.session_factory() as session:
            recovering = list(
                session.scalars(
                    select(ProcedureSchedule.id).where(
                        ProcedureSchedule.state == "CLAIMED",
                        ProcedureSchedule.id.not_in(claimed_ids or [""]),
                    )
                ).all()
            )
        for schedule_id in recovering:
            if self._fire_claimed_schedule(schedule_id):
                processed += 1
        return processed

    def _fire_claimed_schedule(self, schedule_id: str) -> bool:
        if self.execution_starter is None:
            return False
        with self.session_factory() as session:
            schedule = session.get(ProcedureSchedule, schedule_id)
            if schedule is None or schedule.state != "CLAIMED":
                return False
            revision = session.get(
                ProcedureCatalogRevision, schedule.catalog_revision_id
            )
            entry = (
                session.get(ProcedureCatalogEntry, revision.catalog_id)
                if revision is not None
                else None
            )
            if revision is None or entry is None:
                self._fail_schedule(schedule_id, "PINNED_CATALOG_MISSING", "pinned catalog revision is missing")
                return True
            procedure = Procedure(
                id=entry.procedure_ref,
                name=entry.name,
                description=entry.description,
                path=Path(entry.entrypoint),
                source=revision.source,
                sha256=revision.source_digest,
                steps=tuple(revision.steps),
                ir_version=revision.ir_version,
            )
            schedule_view = schedule_dict(schedule)
        try:
            execution = self.execution_starter(
                procedure=procedure,
                schedule=schedule_view,
            )
            if not isinstance(execution, Execution):
                raise OperatorServiceError("schedule starter returned no execution")
            self.ensure_execution_projection(
                execution,
                actor="schedule-service",
                automatic=bool(schedule_view["automatic"]),
                background_allowed=bool(schedule_view["background_allowed"]),
                visible=bool(schedule_view["visible"]),
                catalog_revision_id=str(schedule_view["catalog_revision_id"]),
                ownership_mode=(
                    "B"
                    if schedule_view["automatic"]
                    and schedule_view["background_allowed"]
                    else "CONTROL_LOST"
                ),
                authoritative=True,
            )
        except Exception:
            self._fail_schedule(
                schedule_id,
                "ADMISSION_REJECTED",
                "scheduled execution admission failed",
            )
            return True
        with self._lock, self.session_factory() as session:
            schedule = session.get(ProcedureSchedule, schedule_id, with_for_update=True)
            occurrence = (
                session.get(ScheduleOccurrence, schedule.occurrence_id)
                if schedule is not None and schedule.occurrence_id
                else None
            )
            if schedule is None:
                return False
            if schedule.state == "FIRED":
                return True
            if schedule.state != "CLAIMED" or occurrence is None:
                return False
            now = self._database_now(session)
            schedule.state = "FIRED"
            schedule.revision += 1
            schedule.fired_execution_id = execution.id
            schedule.updated_at = now
            schedule.settled_at = now
            occurrence.state = "FIRED"
            occurrence.execution_id = execution.id
            occurrence.settled_at = now
            self._audit(
                session,
                event_type="schedule.fired",
                aggregate_type="procedure_schedule",
                aggregate_id=schedule.id,
                execution_id=schedule.controller_execution_id,
                actor="schedule-service",
                payload={
                    "schedule_id": schedule.id,
                    "occurrence_id": occurrence.id,
                    "execution_id": execution.id,
                },
                created_at=now,
            )
            session.commit()
            return True

    def _fail_schedule(self, schedule_id: str, code: str, message: str) -> None:
        with self._lock, self.session_factory() as session:
            schedule = session.get(ProcedureSchedule, schedule_id, with_for_update=True)
            if schedule is None or schedule.state != "CLAIMED":
                return
            now = self._database_now(session)
            schedule.state = "ERROR"
            schedule.revision += 1
            schedule.error_code = _identifier(code, "error_code")
            schedule.error_message = message[:500]
            schedule.updated_at = now
            schedule.settled_at = now
            occurrence = (
                session.get(ScheduleOccurrence, schedule.occurrence_id)
                if schedule.occurrence_id
                else None
            )
            if occurrence is not None:
                occurrence.state = "ERROR"
                occurrence.settled_at = now
            self._audit(
                session,
                event_type="schedule.error",
                aggregate_type="procedure_schedule",
                aggregate_id=schedule.id,
                execution_id=schedule.controller_execution_id,
                actor="schedule-service",
                payload={
                    "schedule_id": schedule.id,
                    "occurrence_id": schedule.occurrence_id,
                    "error_code": schedule.error_code,
                },
                created_at=now,
            )
            session.commit()

    @staticmethod
    def _request_replay(
        session: Session,
        *,
        scope: str,
        actor: str,
        idempotency_key: str,
        request_digest: str,
    ) -> dict[str, Any] | None:
        request = session.scalar(
            select(OperatorRequest).where(
                OperatorRequest.scope == scope,
                OperatorRequest.actor == actor,
                OperatorRequest.idempotency_key == idempotency_key,
            )
        )
        if request is None:
            return None
        if request.request_digest != request_digest:
            raise OperatorConflictError(
                "idempotency key was used for another operator request"
            )
        return dict(request.response)

    @staticmethod
    def _store_request(
        session: Session,
        *,
        scope: str,
        actor: str,
        idempotency_key: str,
        request_digest: str,
        resource_type: str,
        resource_id: str,
        response: dict[str, Any],
        created_at: datetime,
    ) -> None:
        session.add(
            OperatorRequest(
                id=new_id(),
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type=resource_type,
                resource_id=resource_id,
                response=response,
                created_at=created_at,
            )
        )

    @staticmethod
    def _audit(
        session: Session,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        actor: str,
        payload: dict[str, Any],
        created_at: datetime,
        execution_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        session.add(
            OperatorAuditEvent(
                id=new_id(),
                execution_id=execution_id,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                event_type=event_type,
                actor=actor,
                correlation_id=correlation_id or str(uuid.uuid4()),
                payload=_validate_literal(payload),
                created_at=created_at,
            )
        )

    def settle_prompt_terminal(
        self,
        prompt_id: str,
        outcome: str,
        *,
        actor: str = "operator-runtime",
        value: Any = None,
    ) -> dict[str, Any]:
        prompt_id = _identifier(prompt_id, "prompt_id")
        outcome = _identifier(outcome.upper(), "outcome")
        if outcome not in {
            "ANSWERED",
            "CANCELLED",
            "TIMED_OUT",
            "NO_CONTROLLER",
            "EXECUTION_TERMINATED",
            "ERROR",
        }:
            raise OperatorValidationError("prompt settlement outcome is invalid")
        actor = _bounded(actor, "actor")
        with self._lock, self.session_factory() as session:
            prompt = session.get(OperatorPrompt, prompt_id, with_for_update=True)
            if prompt is None:
                raise OperatorNotFoundError("operator prompt not found")
            if prompt.state == "SETTLED":
                return prompt_dict(prompt)
            now = self._database_now(session)
            prompt.state = "SETTLED"
            prompt.revision += 1
            prompt.settlement_id = new_id()
            prompt.settlement_outcome = outcome
            prompt.settled_value = (
                self._validate_prompt_value(prompt, value)
                if outcome == "ANSWERED"
                else None
            )
            prompt.settled_by = actor
            prompt.settled_at = now
            projection = session.get(ExecutionOperatorState, prompt.execution_id)
            if projection is not None:
                projection.state = projection.resume_state or (
                    "SUSPENDED"
                    if outcome in {"NO_CONTROLLER", "ERROR"}
                    else "PAUSED"
                )
                projection.resume_state = None
                projection.revision += 1
                projection.updated_at = now
            self._audit(
                session,
                event_type="prompt.settled",
                aggregate_type="operator_prompt",
                aggregate_id=prompt.id,
                execution_id=prompt.execution_id,
                actor=actor,
                payload={
                    "prompt_id": prompt.id,
                    "settlement_id": prompt.settlement_id,
                    "outcome": outcome,
                },
                created_at=now,
            )
            session.commit()
            result = prompt_dict(prompt)
            delivery_prompt_id = prompt.id
        self._deliver_prompt_settlement(delivery_prompt_id)
        return result

    def pending_prompt_deliveries(self) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            prompts = session.scalars(
                select(OperatorPrompt)
                .where(
                    OperatorPrompt.state == "SETTLED",
                    OperatorPrompt.settlement_delivered_at.is_(None),
                )
                .order_by(OperatorPrompt.settled_at, OperatorPrompt.id)
            ).all()
            return [prompt_dict(item) for item in prompts]

    def active_typed_prompt(self, execution_id: str) -> dict[str, Any] | None:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            if session.get(Execution, execution_id) is None:
                raise OperatorNotFoundError("execution not found")
            prompt = session.scalar(
                select(OperatorPrompt)
                .where(
                    OperatorPrompt.execution_id == execution_id,
                    OperatorPrompt.state == "OPEN",
                )
                .order_by(OperatorPrompt.created_at.desc(), OperatorPrompt.id.desc())
                .limit(1)
            )
            return prompt_dict(prompt) if prompt is not None else None

    def replay_prompt_deliveries(self) -> int:
        delivered = 0
        for prompt in self.pending_prompt_deliveries():
            if self._deliver_prompt_settlement(str(prompt["id"])):
                delivered += 1
        return delivered

    def _deliver_prompt_settlement(self, prompt_id: str) -> bool:
        if self.prompt_settlement_sink is None:
            return False
        with self._lock, self.session_factory() as session:
            prompt = session.get(OperatorPrompt, prompt_id, with_for_update=True)
            if (
                prompt is None
                or prompt.state != "SETTLED"
                or prompt.settlement_id is None
                or prompt.settlement_delivered_at is not None
            ):
                return False
            execution = session.get(Execution, prompt.execution_id)
            if execution is not None and execution.current_step > prompt.step_index:
                prompt.settlement_delivered_at = self._database_now(session)
                session.commit()
                return True
            delivery = {
                "prompt": prompt_dict(prompt),
                "attempt": {"id": f"settlement:{prompt.settlement_id}"},
            }
        try:
            self.prompt_settlement_sink(delivery)
        except Exception:
            return False
        with self._lock, self.session_factory() as session:
            prompt = session.get(OperatorPrompt, prompt_id, with_for_update=True)
            if (
                prompt is not None
                and prompt.state == "SETTLED"
                and prompt.settlement_delivered_at is None
            ):
                prompt.settlement_delivery_attempts += 1
                session.commit()
        return True

    def ack_prompt_settlement_application(
        self,
        prompt_id: str,
        settlement_id: str,
        execution_revision: int | None = None,
        current_step: int | None = None,
    ) -> dict[str, Any]:
        prompt_id = _identifier(prompt_id, "prompt_id")
        settlement_id = _identifier(settlement_id, "settlement_id")
        with self._lock, self.session_factory() as session:
            prompt = session.get(OperatorPrompt, prompt_id, with_for_update=True)
            if prompt is None or prompt.settlement_id != settlement_id:
                raise OperatorConflictError("prompt settlement identity does not match")
            if prompt.settlement_delivered_at is not None:
                return prompt_dict(prompt)
            execution = session.get(Execution, prompt.execution_id)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            if execution_revision is not None and execution.revision < execution_revision:
                raise OperatorConflictError("prompt application revision is not committed")
            if current_step is not None and execution.current_step < current_step:
                raise OperatorConflictError("prompt application step is not committed")
            now = self._database_now(session)
            prompt.settlement_delivered_at = now
            self._audit(
                session,
                event_type="prompt.settlement_applied",
                aggregate_type="operator_prompt",
                aggregate_id=prompt.id,
                execution_id=prompt.execution_id,
                actor="operator-runtime",
                payload={
                    "prompt_id": prompt.id,
                    "settlement_id": settlement_id,
                    "execution_revision": execution.revision,
                    "current_step": execution.current_step,
                },
                created_at=now,
            )
            session.commit()
            return prompt_dict(prompt)

    @staticmethod
    def _action_dict(action: OperatorUserAction) -> dict[str, Any]:
        return {
            "id": action.id,
            "execution_id": action.execution_id,
            "name": action.name,
            "label": action.label,
            "severity": action.severity,
            "handler_id": action.handler_id,
            "source_digest": action.source_digest,
            "definition": action.definition,
            "enabled": action.enabled,
            "dismissed": action.dismissed,
            "revision": action.revision,
            "created_at": action.created_at.isoformat(),
        }

    @staticmethod
    def _invocation_dict(invocation: OperatorUserActionInvocation) -> dict[str, Any]:
        return {
            "id": invocation.id,
            "action_id": invocation.action_id,
            "execution_id": invocation.execution_id,
            "action_revision": invocation.action_revision,
            "expected_execution_revision": invocation.expected_execution_revision,
            "accepted_lease_id": invocation.accepted_lease_id,
            "accepted_lease_revision": invocation.accepted_lease_revision,
            "accepted_fencing_token": invocation.accepted_fencing_token,
            "state": invocation.state,
            "actor": invocation.actor,
            "arguments": invocation.arguments,
            "handler_digest": invocation.handler_digest,
            "delivery_attempts": invocation.delivery_attempts,
            "last_delivery_attempt_at": (
                invocation.last_delivery_attempt_at.isoformat()
                if invocation.last_delivery_attempt_at is not None
                else None
            ),
            "delivered_at": (
                invocation.delivered_at.isoformat()
                if invocation.delivered_at is not None
                else None
            ),
            "result": invocation.result_payload,
            "rejection_code": invocation.rejection_code,
            "application_safe_point_id": invocation.application_safe_point_id,
            "applied_event_id": invocation.applied_event_id,
            "created_at": invocation.created_at.isoformat(),
            "settled_at": (
                invocation.settled_at.isoformat()
                if invocation.settled_at is not None
                else None
            ),
        }

    def register_user_action(
        self,
        execution_id: str,
        definition: dict[str, Any],
        *,
        actor: str = "operator-runtime",
        idempotency_key: str | None = None,
        reason: str = "Register pinned procedure action",
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        definition = _validate_literal(definition)
        action_id = _identifier(
            str(definition.get("id") or new_id()), "action_id"
        )
        name = _identifier(str(definition.get("name", "")), "action name")
        label = _bounded(str(definition.get("label", "")), "action label")
        severity = _identifier(
            str(definition.get("severity", "INFO")).upper(), "action severity"
        )
        if severity not in {"INFO", "WARNING", "ERROR"}:
            raise OperatorValidationError("action severity is invalid")
        handler_id = _identifier(str(definition.get("handler_id", "")), "handler_id")
        handler = definition.get("handler")
        if not isinstance(handler, list) or len(handler) > 64 or any(
            not isinstance(item, dict) for item in handler
        ):
            raise OperatorValidationError("action handler is not a bounded operation list")
        source_digest = str(definition.get("source_digest", ""))
        if not _LOWER_HEX_64.fullmatch(source_digest):
            raise OperatorValidationError("action source_digest is invalid")
        revision = definition.get("revision", 1)
        if type(revision) is not int or revision < 1:
            raise OperatorValidationError("action revision is invalid")
        enabled = definition.get("enabled", True)
        try:
            spec = validate_user_action(
                action_id=action_id,
                action_revision=revision,
                name=name,
                label=label,
                severity=severity,
                handler_id=handler_id,
                enabled=enabled,
                source_digest=source_digest,
                allowlisted_handlers={handler_id},
            )
            operations = validate_user_action_block(handler)
        except V06ValidationError as exc:
            raise OperatorValidationError(
                f"action definition is invalid ({exc.code})"
            ) from exc
        canonical_handler = [
            {"op": operation.operation, **operation.payload}
            for operation in operations
        ]
        definition = {
            **definition,
            "id": spec.action_id,
            "revision": spec.action_revision,
            "name": spec.name,
            "label": spec.label,
            "severity": spec.severity,
            "handler_id": spec.handler_id,
            "enabled": spec.enabled,
            "source_digest": spec.source_digest,
            "handler": canonical_handler,
        }
        actor = _bounded(actor, "actor")
        if actor not in {"operator-runtime", "operator-bootstrap"}:
            raise OperatorAuthorizationError(
                "user actions may only be registered from a pinned runtime bundle"
            )
        reason = _bounded(reason, "reason", 1000)
        if idempotency_key is not None:
            idempotency_key = _idempotency_key(idempotency_key)
        request_digest = canonical_digest(
            {"execution_id": execution_id, "definition": definition, "reason": reason}
        )
        with self._lock, self.session_factory() as session:
            if idempotency_key is not None:
                replay = self._request_replay(
                    session,
                    scope=f"action-register:{execution_id}",
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                )
                if replay is not None:
                    return replay
            projection = session.get(ExecutionOperatorState, execution_id)
            if projection is None or projection.source_digest != source_digest:
                raise OperatorConflictError("action source digest is stale")
            existing = session.get(OperatorUserAction, action_id)
            if existing is not None:
                if canonical_digest(existing.definition) != canonical_digest(definition):
                    raise OperatorConflictError("ActionId is bound to another definition")
                return self._action_dict(existing)
            now = self._database_now(session)
            action = OperatorUserAction(
                id=action_id,
                execution_id=execution_id,
                name=name,
                label=label,
                severity=severity,
                handler_id=handler_id,
                source_digest=source_digest,
                definition=definition,
                enabled=spec.enabled,
                dismissed=False,
                revision=revision,
                created_at=now,
            )
            session.add(action)
            session.flush()
            response = self._action_dict(action)
            if idempotency_key is not None:
                self._store_request(
                    session,
                    scope=f"action-register:{execution_id}",
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    resource_type="operator_user_action",
                    resource_id=action.id,
                    response=response,
                    created_at=now,
                )
            self._audit(
                session,
                event_type="user_action.registered",
                aggregate_type="operator_user_action",
                aggregate_id=action.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "action_id": action.id,
                    "revision": action.revision,
                    "handler_id": action.handler_id,
                    "source_digest": action.source_digest,
                    "reason": reason,
                },
                created_at=now,
            )
            session.commit()
            return response

    def mutate_user_action(
        self,
        execution_id: str,
        action_id: str,
        *,
        operation: str,
        expected_action_revision: int,
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        action_id = _identifier(action_id, "action_id")
        operation = _identifier(operation.upper(), "operation")
        if operation not in {"ENABLE", "DISABLE", "DISMISS"}:
            raise OperatorValidationError("user action mutation is unsupported")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        request_digest = canonical_digest(
            {
                "execution_id": execution_id,
                "action_id": action_id,
                "operation": operation,
                "expected_action_revision": expected_action_revision,
                "expected_execution_revision": expected_execution_revision,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
        )
        scope = f"action-mutation:{action_id}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id)
            action = session.get(OperatorUserAction, action_id, with_for_update=True)
            if action is None or action.execution_id != execution_id:
                raise OperatorNotFoundError("user action not found")
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            if action.revision != expected_action_revision:
                raise OperatorConflictError(
                    "user action revision conflict",
                    current={"action": self._action_dict(action)},
                )
            if operation == "ENABLE":
                if action.dismissed:
                    raise OperatorConflictError("dismissed action cannot be re-enabled")
                action.enabled = True
            elif operation == "DISABLE":
                action.enabled = False
            else:
                action.enabled = False
                action.dismissed = True
            action.revision += 1
            now = self._database_now(session)
            response = self._action_dict(action)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="operator_user_action",
                resource_id=action.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type=f"user_action.{operation.lower()}",
                aggregate_type="operator_user_action",
                aggregate_id=action.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "operation": operation,
                    "revision": action.revision,
                    "reason": reason,
                },
                created_at=now,
            )
            session.commit()
            return response

    def list_user_actions(self, execution_id: str) -> list[dict[str, Any]]:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            actions = session.scalars(
                select(OperatorUserAction)
                .where(OperatorUserAction.execution_id == execution_id)
                .order_by(OperatorUserAction.created_at, OperatorUserAction.id)
            ).all()
            return [self._action_dict(item) for item in actions]

    def invoke_user_action(
        self,
        execution_id: str,
        action_id: str,
        *,
        expected_action_revision: int,
        expected_execution_revision: int,
        arguments: dict[str, Any],
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        action_id = _identifier(action_id, "action_id")
        actor = _bounded(actor, "actor")
        arguments = _validate_literal(arguments)
        if arguments:
            raise UserActionArgumentsUnsupportedError(
                "v0.6 static user actions do not accept arguments"
            )
        try:
            _reject_prompt_secret_material(arguments, "arguments")
        except PromptSecretMaterialError as exc:
            raise OperatorValidationError(
                "secret material is not accepted in action arguments"
            ) from exc
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        request_digest = canonical_digest(
            {
                "execution_id": execution_id,
                "action_id": action_id,
                "expected_action_revision": expected_action_revision,
                "expected_execution_revision": expected_execution_revision,
                "arguments": arguments,
                "actor": actor,
                "reason": reason,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
            }
        )
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(OperatorUserActionInvocation).where(
                    OperatorUserActionInvocation.action_id == action_id,
                    OperatorUserActionInvocation.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise OperatorConflictError(
                        "idempotency key was used for another action invocation"
                    )
                return self._invocation_dict(existing)
            action = session.get(OperatorUserAction, action_id)
            execution = session.get(Execution, execution_id)
            if action is None or action.execution_id != execution_id:
                raise OperatorNotFoundError("user action not found")
            projection, lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            rejection: str | None = None
            if action.revision != expected_action_revision:
                rejection = "STALE_ACTION_REVISION"
            elif execution is None or execution.revision != expected_execution_revision:
                rejection = "STALE_EXECUTION_REVISION"
            elif not action.enabled or action.dismissed:
                rejection = "ACTION_NOT_ENABLED"
            elif projection.source_digest != action.source_digest:
                rejection = "STALE_SOURCE_DIGEST"
            elif projection.state not in {
                "PAUSED",
                "RUNNING",
                "WAITING",
                "PROMPT",
                "INTERRUPTED",
            }:
                rejection = "ACTION_NOT_ALLOWED_IN_STATE"
            now = self._database_now(session)
            pinned_handler = _validate_literal(
                list(action.definition.get("handler") or [])
            )
            handler_digest = canonical_digest(pinned_handler)
            invocation = OperatorUserActionInvocation(
                id=new_id(),
                action_id=action_id,
                execution_id=execution_id,
                action_revision=expected_action_revision,
                expected_execution_revision=expected_execution_revision,
                accepted_lease_id=lease.id,
                accepted_lease_revision=lease.revision,
                accepted_fencing_token=lease.fencing_token,
                state="REJECTED" if rejection else "PENDING_SAFE_POINT",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                actor=actor,
                arguments=arguments,
                pinned_handler=pinned_handler,
                handler_digest=handler_digest,
                delivery_attempts=0,
                result_payload={},
                rejection_code=rejection,
                created_at=now,
                settled_at=now if rejection else None,
            )
            session.add(invocation)
            self._audit(
                session,
                event_type=(
                    "user_action.invocation_rejected"
                    if rejection is not None
                    else "user_action.invocation_admitted"
                ),
                aggregate_type="operator_user_action_invocation",
                aggregate_id=invocation.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "action_id": action.id,
                    "action_revision": expected_action_revision,
                    "state": invocation.state,
                    "rejection_code": rejection,
                    "handler_digest": handler_digest,
                },
                created_at=now,
            )
            session.commit()
            return self._invocation_dict(invocation)

    def list_replayable_user_action_invocations(
        self, execution_id: str | None = None, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise OperatorValidationError("limit must be 1 through 500")
        with self.session_factory() as session:
            query = select(OperatorUserActionInvocation).where(
                OperatorUserActionInvocation.state.in_(
                    ["PENDING_SAFE_POINT", "APPLYING"]
                ),
                OperatorUserActionInvocation.delivered_at.is_(None),
            )
            if execution_id is not None:
                query = query.where(
                    OperatorUserActionInvocation.execution_id
                    == _identifier(execution_id, "execution_id")
                )
            rows = session.scalars(
                query.order_by(
                    OperatorUserActionInvocation.created_at,
                    OperatorUserActionInvocation.id,
                ).limit(limit)
            ).all()
            return [
                {
                    **self._invocation_dict(row),
                    "pinned_handler": row.pinned_handler,
                }
                for row in rows
            ]

    def mark_user_action_delivery_attempt(
        self,
        invocation_id: str,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        invocation_id = _identifier(invocation_id, "invocation_id")
        with self._lock, self.session_factory() as session:
            invocation_execution_id = session.scalar(
                select(OperatorUserActionInvocation.execution_id).where(
                    OperatorUserActionInvocation.id == invocation_id
                )
            )
            if invocation_execution_id is None:
                raise OperatorNotFoundError("action invocation not found")
            self._require_worker_epoch(
                session, invocation_execution_id, worker_generation
            )
            invocation = session.get(
                OperatorUserActionInvocation, invocation_id, with_for_update=True
            )
            if invocation is None:
                raise OperatorNotFoundError("action invocation not found")
            if invocation.state not in {"PENDING_SAFE_POINT", "APPLYING"}:
                return {
                    **self._invocation_dict(invocation),
                    "pinned_handler": invocation.pinned_handler,
                }
            invocation.delivery_attempts += 1
            invocation.last_delivery_attempt_at = self._database_now(session)
            session.commit()
            return {
                **self._invocation_dict(invocation),
                "pinned_handler": invocation.pinned_handler,
            }

    def begin_user_action_application(
        self,
        invocation_id: str,
        application_safe_point_id: str | None = None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        invocation_id = _identifier(invocation_id, "invocation_id")
        with self._lock, self.session_factory() as session:
            invocation_execution_id = session.scalar(
                select(OperatorUserActionInvocation.execution_id).where(
                    OperatorUserActionInvocation.id == invocation_id
                )
            )
            if invocation_execution_id is None:
                raise OperatorNotFoundError("action invocation not found")
            self._require_worker_epoch(
                session, invocation_execution_id, worker_generation
            )
            invocation = session.get(
                OperatorUserActionInvocation, invocation_id, with_for_update=True
            )
            if invocation is None:
                raise OperatorNotFoundError("action invocation not found")
            if invocation.state == "APPLYING":
                return {
                    **self._invocation_dict(invocation),
                    "pinned_handler": invocation.pinned_handler,
                }
            if invocation.state != "PENDING_SAFE_POINT":
                return self._invocation_dict(invocation)
            projection = session.get(
                ExecutionOperatorState,
                invocation.execution_id,
                with_for_update=True,
            )
            execution = session.get(
                Execution, invocation.execution_id, with_for_update=True
            )
            lease = session.get(
                ControllerLease,
                invocation.accepted_lease_id,
                with_for_update=True,
            )
            now = self._database_now(session)
            if (
                projection is not None
                and lease is not None
                and lease.state == "ACTIVE"
                and (_stored_utc(lease.expires_at) or now) <= now
            ):
                self._expire_lease(session, projection, lease, now)
            valid = (
                projection is not None
                and execution is not None
                and lease is not None
                and execution.revision == invocation.expected_execution_revision
                and projection.ownership_mode == "C"
                and projection.current_lease_id == invocation.accepted_lease_id
                and lease.state == "ACTIVE"
                and lease.revision == invocation.accepted_lease_revision
                and lease.fencing_token == invocation.accepted_fencing_token
                and projection.control_fencing_token
                == invocation.accepted_fencing_token
                and (_stored_utc(lease.expires_at) or now) > now
            )
            if not valid:
                invocation.state = "SUPERSEDED"
                invocation.rejection_code = "CONTROL_FENCE_STALE"
                invocation.result_payload = {"target_mutation": "NONE"}
                invocation.delivered_at = now
                invocation.settled_at = now
                self._audit(
                    session,
                    event_type="user_action.invocation_superseded",
                    aggregate_type="operator_user_action_invocation",
                    aggregate_id=invocation.id,
                    execution_id=invocation.execution_id,
                    actor="operator-runtime",
                    payload={
                        "state": invocation.state,
                        "rejection_code": invocation.rejection_code,
                        "target_mutation": "NONE",
                    },
                    created_at=now,
                )
                session.commit()
                return self._invocation_dict(invocation)
            if self._has_mutation_reservation(
                session,
                invocation.execution_id,
                invocation_id=invocation.id,
            ):
                return {
                    **self._invocation_dict(invocation),
                    "pinned_handler": invocation.pinned_handler,
                }
            invocation.state = "APPLYING"
            invocation.application_safe_point_id = (
                _identifier(application_safe_point_id, "application_safe_point_id")
                if application_safe_point_id is not None
                else projection.current_safe_point_id
            )
            self._audit(
                session,
                event_type="user_action.invocation_applying",
                aggregate_type="operator_user_action_invocation",
                aggregate_id=invocation.id,
                execution_id=invocation.execution_id,
                actor="operator-runtime",
                payload={
                    "state": invocation.state,
                    "application_safe_point_id": (
                        invocation.application_safe_point_id
                    ),
                    "handler_digest": invocation.handler_digest,
                },
                created_at=now,
            )
            session.commit()
            return {
                **self._invocation_dict(invocation),
                "pinned_handler": invocation.pinned_handler,
            }

    def settle_user_action_invocation(
        self,
        invocation_id: str,
        outcome: str,
        *,
        result: dict[str, Any] | None = None,
        rejection_code: str | None = None,
        application_safe_point_id: str | None = None,
        variables: dict[str, Any] | None = None,
        effects: list[dict[str, Any]] | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        invocation_id = _identifier(invocation_id, "invocation_id")
        outcome = _identifier(outcome.upper(), "outcome")
        if outcome not in {"EXECUTED", "REJECTED", "CANCELLED", "SUPERSEDED"}:
            raise OperatorValidationError("action settlement outcome is invalid")
        with self._lock, self.session_factory() as session:
            invocation_execution_id = session.scalar(
                select(OperatorUserActionInvocation.execution_id).where(
                    OperatorUserActionInvocation.id == invocation_id
                )
            )
            if invocation_execution_id is None:
                raise OperatorNotFoundError("action invocation not found")
            self._require_worker_epoch(
                session, invocation_execution_id, worker_generation
            )
            invocation = session.get(
                OperatorUserActionInvocation, invocation_id, with_for_update=True
            )
            if invocation is None:
                raise OperatorNotFoundError("action invocation not found")
            if invocation.state in {"EXECUTED", "REJECTED", "CANCELLED", "SUPERSEDED"}:
                return self._invocation_dict(invocation)
            if outcome == "EXECUTED" and invocation.state != "APPLYING":
                raise OperatorConflictError(
                    "action invocation application has not been reserved"
                )
            now = self._database_now(session)
            settlement_result = _validate_literal(result or {})
            if not isinstance(settlement_result, dict):
                raise OperatorValidationError("action result must be a map")
            invocation.rejection_code = (
                _identifier(rejection_code, "rejection_code")
                if rejection_code is not None
                else None
            )
            if application_safe_point_id is not None:
                application_safe_point_id = _identifier(
                    application_safe_point_id, "application_safe_point_id"
                )
                if invocation.application_safe_point_id not in {
                    None,
                    application_safe_point_id,
                }:
                    raise OperatorConflictError(
                        "action application safe point does not match reservation"
                    )
                invocation.application_safe_point_id = application_safe_point_id
            submitted_effects = _validate_literal(effects or [])
            if not isinstance(submitted_effects, list) or len(submitted_effects) > 256:
                raise OperatorValidationError("action effects exceed their bound")
            execution: Execution | None = None
            effects_to_persist = submitted_effects
            if outcome == "EXECUTED":
                if variables is None:
                    raise OperatorValidationError(
                        "executed action settlement requires variables"
                    )
                variables = _validate_literal(variables)
                if not isinstance(variables, dict):
                    raise OperatorValidationError("action variables must be a map")
                execution = session.get(
                    Execution, invocation.execution_id, with_for_update=True
                )
                projection = session.get(
                    ExecutionOperatorState,
                    invocation.execution_id,
                    with_for_update=True,
                )
                if execution is None or projection is None:
                    raise OperatorNotFoundError("action execution not found")
                safe_point_step = settlement_result.get("safe_point_step")
                if (
                    type(safe_point_step) is not int
                    or safe_point_step < 0
                    or safe_point_step != projection.current_step
                ):
                    raise OperatorConflictError(
                        "action safe-point evidence does not match the reservation"
                    )
                expected_application_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "openbexi-spell:user-action:"
                        f"{invocation.execution_id}:{invocation.id}",
                    )
                )
                if settlement_result.get("application_id") != expected_application_id:
                    raise OperatorConflictError(
                        "action application identity does not match"
                    )
                expected_variables = dict(execution.variables)
                expected_effects: list[dict[str, Any]] = []
                try:
                    operations = validate_user_action_block(
                        invocation.pinned_handler
                    )
                except V06ValidationError as exc:
                    raise OperatorConflictError(
                        "pinned action handler is invalid"
                    ) from exc
                variable_types = {
                    step.get("name"): step.get("declared_type")
                    for step in execution.steps
                    if isinstance(step, dict)
                    and step.get("type") == "variable_set"
                    and type(step.get("name")) is str
                    and type(step.get("declared_type")) is str
                }
                for operation in operations:
                    if operation.operation == "LOG":
                        expected_effects.append(
                            {
                                "event_type": "procedure.user_action_log",
                                "source": "procedure",
                                "severity": operation.payload["severity"],
                                "payload": {
                                    "message": operation.payload["message"],
                                    "step_index": safe_point_step,
                                    "invocation_id": invocation.id,
                                },
                            }
                        )
                        continue
                    name = operation.payload["name"]
                    current_value = expected_variables.get(name)
                    current_type = (
                        "bool"
                        if type(current_value) is bool
                        else "int"
                        if type(current_value) is int
                        else "float"
                        if type(current_value) is float
                        else "str"
                        if type(current_value) is str
                        else None
                    )
                    if (
                        name not in expected_variables
                        or (variable_types.get(name) or current_type)
                        != operation.payload["declared_type"]
                    ):
                        raise OperatorConflictError(
                            "pinned action target is no longer valid"
                        )
                    expected_variables[name] = operation.payload["value"]
                if canonical_digest(variables) != canonical_digest(expected_variables):
                    raise OperatorConflictError(
                        "action variables do not match the pinned handler result"
                    )
                replayed_without_effects = (
                    settlement_result.get("replayed") is True
                    and submitted_effects == []
                )
                if (
                    not replayed_without_effects
                    and canonical_digest(submitted_effects)
                    != canonical_digest(expected_effects)
                ):
                    raise OperatorConflictError(
                        "action effects do not match the pinned handler result"
                    )
                effects_to_persist = expected_effects
                variables = expected_variables
            elif variables is not None or submitted_effects:
                raise OperatorValidationError(
                    "non-executed action settlement cannot mutate targets"
                )
            invocation.state = outcome
            invocation.result_payload = settlement_result
            invocation.settled_at = now
            event_ids: list[str] = []
            if variables is not None:
                if execution is None:
                    execution = session.get(
                        Execution, invocation.execution_id, with_for_update=True
                    )
                assert execution is not None
                execution.variables = variables
                execution.revision += 1
                invocation.result_payload = {
                    **invocation.result_payload,
                    "variables_digest": canonical_digest(variables),
                    "applied_execution_revision": execution.revision,
                }
            if effects_to_persist:
                if execution is None:
                    execution = session.get(
                        Execution, invocation.execution_id, with_for_update=True
                    )
                if execution is None:
                    raise OperatorNotFoundError("action execution not found")
                for index, raw_effect in enumerate(effects_to_persist):
                    if not isinstance(raw_effect, dict):
                        raise OperatorValidationError("action effect must be a map")
                    event_type = _identifier(
                        str(raw_effect.get("event_type", "")), "event_type"
                    )
                    source = _bounded(
                        str(raw_effect.get("source", "worker")), "event source", 60
                    )
                    severity = _identifier(
                        str(raw_effect.get("severity", "info")), "event severity"
                    )
                    payload = _validate_literal(raw_effect.get("payload", {}))
                    if not isinstance(payload, dict):
                        raise OperatorValidationError("action event payload must be a map")
                    event_id = str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            f"openbexi-action:{invocation.id}:{index}",
                        )
                    )
                    session.add(
                        Event(
                            id=event_id,
                            execution_id=execution.id,
                            sequence=execution.next_sequence,
                            event_type=event_type,
                            source=source,
                            severity=severity,
                            correlation_id=invocation.id,
                            causation_id=invocation.id,
                            payload=payload,
                            created_at=now,
                        )
                    )
                    execution.next_sequence += 1
                    event_ids.append(event_id)
                invocation.result_payload = {
                    **invocation.result_payload,
                    "applied_event_ids": event_ids,
                }
                invocation.applied_event_id = event_ids[-1]
            invocation.delivered_at = now
            self._audit(
                session,
                event_type=f"user_action.invocation_{outcome.lower()}",
                aggregate_type="operator_user_action_invocation",
                aggregate_id=invocation.id,
                execution_id=invocation.execution_id,
                actor="operator-runtime",
                payload={
                    "state": outcome,
                    "handler_digest": invocation.handler_digest,
                    "application_safe_point_id": invocation.application_safe_point_id,
                    "rejection_code": invocation.rejection_code,
                },
                created_at=now,
            )
            session.commit()
            return self._invocation_dict(invocation)

    @staticmethod
    def _startproc_dict(operation: StartProcOperation) -> dict[str, Any]:
        return {
            "id": operation.id,
            "revision": operation.revision,
            "state": operation.state,
            "parent_execution_id": operation.parent_execution_id,
            "expected_parent_revision": operation.expected_parent_revision,
            "parent_catalog_revision_id": operation.parent_catalog_revision_id,
            "child_procedure_ref": operation.child_procedure_ref,
            "resolved_child_catalog_revision_id": (
                operation.resolved_child_catalog_revision_id
            ),
            "library_revision": operation.library_revision,
            "bundle_digest": operation.bundle_digest,
            "dependency_closure": operation.dependency_closure,
            "arguments": operation.arguments,
            "arguments_digest": operation.arguments_digest,
            "blocking": operation.blocking,
            "visible": operation.visible,
            "automatic": operation.automatic,
            "depth": operation.depth,
            "saved_successor": operation.saved_successor,
            "child_execution_id": operation.child_execution_id,
            "result": operation.result_payload,
            "rejection_code": operation.rejection_code,
            "effect_certainty": operation.effect_certainty,
            "result_delivery_attempts": operation.result_delivery_attempts,
            "result_last_attempt_at": (
                operation.result_last_attempt_at.isoformat()
                if operation.result_last_attempt_at is not None
                else None
            ),
            "result_applied_at": (
                operation.result_applied_at.isoformat()
                if operation.result_applied_at is not None
                else None
            ),
            "result_applied_parent_revision": (
                operation.result_applied_parent_revision
            ),
            "result_applied_parent_step": operation.result_applied_parent_step,
            "created_at": operation.created_at.isoformat(),
            "updated_at": operation.updated_at.isoformat(),
            "settled_at": (
                operation.settled_at.isoformat()
                if operation.settled_at is not None
                else None
            ),
        }

    def admit_startproc(
        self,
        parent_execution_id: str,
        startproc_id: str,
        step_index: int,
        declaration: dict[str, Any],
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        result = self._persist_startproc_admission(
            parent_execution_id,
            startproc_id,
            step_index,
            declaration,
            worker_generation=worker_generation,
        )
        if isinstance(result, _AfterServiceUnlock):
            return result.callback()
        return result

    def _persist_startproc_admission(
        self,
        parent_execution_id: str,
        startproc_id: str,
        step_index: int,
        declaration: dict[str, Any],
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any] | _AfterServiceUnlock:
        parent_execution_id = _identifier(
            parent_execution_id, "parent_execution_id"
        )
        startproc_id = _identifier(startproc_id, "startproc_id")
        if type(step_index) is not int or step_index < 0:
            raise OperatorValidationError("StartProc step index is invalid")
        declaration = _validate_literal(declaration)
        if type(declaration) is not dict or set(declaration) - {
            "child_reference",
            "arguments",
            "arguments_digest",
            "blocking",
            "visible",
            "automatic",
            "expected_parent_revision",
            "idempotency_key",
            "actor",
            "saved_successor",
        }:
            raise OperatorValidationError(
                "StartProc declaration contains unsupported fields"
            )
        raw_child_ref = declaration.get("child_reference")
        if type(raw_child_ref) is not str:
            raise OperatorValidationError("StartProc child_reference must be a string")
        child_ref = _bounded(raw_child_ref, "child_reference")
        arguments = _validate_literal(declaration.get("arguments", {}))
        if not isinstance(arguments, dict) or len(arguments) > 64:
            raise OperatorValidationError("StartProc arguments exceed their bound")
        try:
            _reject_prompt_secret_material(arguments, "arguments")
        except PromptSecretMaterialError as exc:
            raise OperatorValidationError(
                "secret material is not accepted in StartProc arguments"
            ) from exc
        arguments_digest = canonical_digest(arguments)
        declared_arguments_digest = declaration.get("arguments_digest")
        if declared_arguments_digest is not None and (
            type(declared_arguments_digest) is not str
            or _LOWER_HEX_64.fullmatch(declared_arguments_digest) is None
        ):
            raise OperatorValidationError("StartProc arguments digest is invalid")
        if (
            declared_arguments_digest is not None
            and declared_arguments_digest != arguments_digest
        ):
            raise OperatorConflictError("StartProc arguments digest does not match")
        blocking = declaration.get("blocking", True)
        visible = declaration.get("visible", True)
        automatic = declaration.get("automatic", True)
        if any(type(value) is not bool for value in (blocking, visible, automatic)):
            raise OperatorValidationError(
                "StartProc blocking, visible, and automatic must be Boolean"
            )
        expected_parent_revision = declaration.get("expected_parent_revision")
        raw_idempotency_key = declaration.get("idempotency_key", startproc_id)
        if type(raw_idempotency_key) is not str:
            raise OperatorValidationError("StartProc idempotency key must be a string")
        idempotency_key = _idempotency_key(raw_idempotency_key)
        raw_actor = declaration.get("actor", "operator-runtime")
        if type(raw_actor) is not str:
            raise OperatorValidationError("StartProc actor must be a string")
        actor = _bounded(raw_actor, "actor")
        saved_successor = _validate_literal(
            declaration.get("saved_successor", {"step_index": step_index + 1})
        )
        if (
            type(saved_successor) is not dict
            or set(saved_successor) != {"step_index"}
            or type(saved_successor.get("step_index")) is not int
            or saved_successor["step_index"] < 0
        ):
            raise OperatorValidationError("StartProc saved successor is invalid")
        request_digest = canonical_digest(
            {
                "parent_execution_id": parent_execution_id,
                "startproc_id": startproc_id,
                "step_index": step_index,
                "child_ref": child_ref,
                "arguments": arguments,
                "blocking": blocking,
                "visible": visible,
                "automatic": automatic,
                "expected_parent_revision": expected_parent_revision,
                "saved_successor": saved_successor,
            }
        )
        with self._lock, self.session_factory() as session:
            self._require_worker_epoch(
                session, parent_execution_id, worker_generation
            )
            existing = session.get(StartProcOperation, startproc_id, with_for_update=True)
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise OperatorConflictError(
                        "StartProcId is bound to another request"
                    )
                if existing.state in {"ADMITTING", "CHILD_CREATED", "RECONCILING"}:
                    session.commit()
                    return _AfterServiceUnlock(
                        lambda: self._resume_startproc_admission(startproc_id)
                    )
                return self._startproc_dict(existing)
            parent = session.get(Execution, parent_execution_id, with_for_update=True)
            parent_projection = session.get(
                ExecutionOperatorState, parent_execution_id, with_for_update=True
            )
            if parent is None or parent_projection is None:
                raise OperatorNotFoundError("parent execution projection not found")
            if expected_parent_revision is None:
                expected_parent_revision = parent.revision
            if type(expected_parent_revision) is not int:
                raise OperatorValidationError("expected parent revision is invalid")
            rejection: str | None = None
            if parent.revision != expected_parent_revision:
                rejection = "PARENT_REVISION_CONFLICT"
            inherited_closure = self._inherited_startproc_closure(
                session, parent_execution_id
            )
            entry, revision, resolution_rejection = self._resolve_startproc_catalog(
                session,
                child_ref,
                pinned_closure=inherited_closure,
            )
            rejection = rejection or resolution_rejection
            if revision is None:
                rejection = rejection or "PROCEDURE_NOT_FOUND"
            dependency_closure = inherited_closure
            if revision is not None and entry is not None and not dependency_closure:
                dependency_closure, closure_rejection = (
                    self._build_startproc_dependency_closure(
                        session, entry, revision
                    )
                )
                rejection = rejection or closure_rejection
            depth = parent_projection.depth + 1
            if depth > 8:
                rejection = rejection or "STARTPROC_DEPTH_EXCEEDED"
            active_children = session.scalar(
                select(func.count())
                .select_from(ParentChildLink)
                .join(Execution, Execution.id == ParentChildLink.child_execution_id)
                .where(
                    ParentChildLink.parent_execution_id == parent_execution_id,
                    Execution.state.not_in(["completed", "aborted", "failed"]),
                )
            )
            pending_admissions = session.scalar(
                select(func.count())
                .select_from(StartProcOperation)
                .outerjoin(
                    ParentChildLink,
                    ParentChildLink.startproc_id == StartProcOperation.id,
                )
                .where(
                    StartProcOperation.parent_execution_id == parent_execution_id,
                    StartProcOperation.state.in_(
                        [
                            "ADMITTING",
                            "CHILD_CREATED",
                            "WAITING_CHILD",
                            "RECONCILING",
                        ]
                    ),
                    ParentChildLink.id.is_(None),
                )
            )
            if (active_children or 0) + (pending_admissions or 0) >= 32:
                rejection = rejection or "STARTPROC_CHILD_CAPACITY_EXCEEDED"
            if revision is not None:
                ancestor_revisions = self._ancestor_catalog_revisions(
                    session, parent_execution_id
                )
                if revision.id in ancestor_revisions:
                    rejection = rejection or (
                        "STARTPROC_DIRECT_CYCLE"
                        if revision.id == parent_projection.catalog_revision_id
                        else "STARTPROC_INDIRECT_CYCLE"
                    )
            now = self._database_now(session)
            operation = StartProcOperation(
                id=startproc_id,
                revision=0,
                parent_execution_id=parent_execution_id,
                expected_parent_revision=expected_parent_revision,
                parent_catalog_revision_id=parent_projection.catalog_revision_id,
                child_procedure_ref=child_ref,
                resolved_child_catalog_revision_id=(
                    revision.id if revision is not None else None
                ),
                library_revision=entry.current_revision if entry is not None else None,
                bundle_digest=revision.bundle_digest if revision is not None else None,
                dependency_closure=dependency_closure,
                arguments=arguments,
                arguments_digest=arguments_digest,
                blocking=blocking,
                visible=visible,
                automatic=automatic,
                depth=depth,
                state="REJECTED" if rejection else "ADMITTING",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                actor=actor,
                saved_successor=saved_successor,
                result_payload={},
                rejection_code=rejection,
                effect_certainty=parent_projection.effect_certainty,
                created_at=now,
                updated_at=now,
                settled_at=now if rejection else None,
            )
            session.add(operation)
            self._audit(
                session,
                event_type=(
                    "startproc.admission_rejected"
                    if rejection is not None
                    else "startproc.admitting"
                ),
                aggregate_type="startproc_operation",
                aggregate_id=operation.id,
                execution_id=parent_execution_id,
                actor=actor,
                payload={
                    "state": operation.state,
                    "child_procedure_ref": child_ref,
                    "resolved_child_catalog_revision_id": (
                        operation.resolved_child_catalog_revision_id
                    ),
                    "bundle_digest": operation.bundle_digest,
                    "arguments_digest": operation.arguments_digest,
                    "rejection_code": rejection,
                },
                created_at=now,
            )
            session.commit()
            operation_view = self._startproc_dict(operation)
            if rejection is not None or revision is None or entry is None:
                return operation_view
            return _AfterServiceUnlock(
                lambda: self._resume_startproc_admission(startproc_id)
            )

    @staticmethod
    def _resolve_current_startproc_catalog(
        session: Session, child_reference: str
    ) -> tuple[
        ProcedureCatalogEntry | None,
        ProcedureCatalogRevision | None,
        str | None,
    ]:
        entry = session.scalar(
            select(ProcedureCatalogEntry).where(
                ProcedureCatalogEntry.procedure_ref == child_reference
            )
        )
        if entry is None:
            # v0.6 has one local catalog priority tier. Exact qualified refs win;
            # unqualified basename/stem resolution therefore must be unique.
            requested_name = Path(child_reference).name
            requested_stem = Path(child_reference).stem
            candidates = [
                item
                for item in session.scalars(select(ProcedureCatalogEntry)).all()
                if requested_name
                in {
                    Path(item.procedure_ref).name,
                    Path(item.entrypoint).name,
                }
                or requested_stem
                in {
                    Path(item.procedure_ref).stem,
                    Path(item.entrypoint).stem,
                }
            ]
            if len(candidates) > 1:
                return None, None, "AMBIGUOUS_PROCEDURE_REFERENCE"
            entry = candidates[0] if candidates else None
        revision = (
            session.scalar(
                select(ProcedureCatalogRevision).where(
                    ProcedureCatalogRevision.catalog_id == entry.id,
                    ProcedureCatalogRevision.revision == entry.current_revision,
                )
            )
            if entry is not None
            else None
        )
        return entry, revision, None if revision is not None else "PROCEDURE_NOT_FOUND"

    @staticmethod
    def _inherited_startproc_closure(
        session: Session, parent_execution_id: str
    ) -> list[dict[str, Any]]:
        link = session.scalar(
            select(ParentChildLink).where(
                ParentChildLink.child_execution_id == parent_execution_id
            )
        )
        if link is None:
            return []
        parent_operation = session.get(StartProcOperation, link.startproc_id)
        if parent_operation is None:
            return []
        return list(parent_operation.dependency_closure or [])

    @classmethod
    def _resolve_startproc_catalog(
        cls,
        session: Session,
        child_reference: str,
        *,
        pinned_closure: list[dict[str, Any]] | None = None,
    ) -> tuple[
        ProcedureCatalogEntry | None,
        ProcedureCatalogRevision | None,
        str | None,
    ]:
        closure = pinned_closure or []
        if not closure:
            return cls._resolve_current_startproc_catalog(session, child_reference)
        exact = [
            item
            for item in closure
            if child_reference
            in {item.get("procedure_ref"), item.get("entrypoint")}
        ]
        candidates = exact
        if not candidates:
            requested_name = Path(child_reference).name
            requested_stem = Path(child_reference).stem
            candidates = [
                item
                for item in closure
                if requested_name
                in {
                    Path(str(item.get("procedure_ref", ""))).name,
                    Path(str(item.get("entrypoint", ""))).name,
                }
                or requested_stem
                in {
                    Path(str(item.get("procedure_ref", ""))).stem,
                    Path(str(item.get("entrypoint", ""))).stem,
                }
            ]
        if len(candidates) > 1:
            return None, None, "AMBIGUOUS_PROCEDURE_REFERENCE"
        if not candidates:
            return None, None, "PROCEDURE_NOT_FOUND"
        pinned = candidates[0]
        entry = session.get(
            ProcedureCatalogEntry, pinned.get("procedure_catalog_id")
        )
        revision = session.get(
            ProcedureCatalogRevision, pinned.get("catalog_revision_id")
        )
        if entry is None or revision is None or revision.catalog_id != entry.id:
            return None, None, "PINNED_CATALOG_MISSING"
        if (
            revision.revision != pinned.get("procedure_revision")
            or revision.bundle_digest != pinned.get("bundle_digest")
        ):
            return None, None, "PINNED_CATALOG_MISMATCH"
        return entry, revision, None

    @classmethod
    def _build_startproc_dependency_closure(
        cls,
        session: Session,
        root_entry: ProcedureCatalogEntry,
        root_revision: ProcedureCatalogRevision,
    ) -> tuple[list[dict[str, Any]], str | None]:
        closure: list[dict[str, Any]] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(
            entry: ProcedureCatalogEntry,
            revision: ProcedureCatalogRevision,
            depth: int,
        ) -> str | None:
            if depth > 8:
                return "STARTPROC_DEPTH_EXCEEDED"
            if revision.id in visiting:
                return (
                    "STARTPROC_DIRECT_CYCLE"
                    if revision.id == root_revision.id
                    else "STARTPROC_INDIRECT_CYCLE"
                )
            if revision.id in visited:
                return None
            if len(visited) >= 128:
                return "STARTPROC_DEPENDENCY_CLOSURE_EXCEEDED"
            visiting.add(revision.id)
            closure.append(
                {
                    "procedure_catalog_id": entry.id,
                    "procedure_ref": entry.procedure_ref,
                    "entrypoint": entry.entrypoint,
                    "procedure_revision": revision.revision,
                    "catalog_revision_id": revision.id,
                    "library_revision": entry.current_revision,
                    "bundle_digest": revision.bundle_digest,
                    "source_digest": revision.source_digest,
                }
            )
            for step in revision.steps:
                if not isinstance(step, dict) or step.get("type") != "startproc":
                    continue
                reference = step.get("child_reference")
                if type(reference) is not str:
                    return "STARTPROC_DEPENDENCY_INVALID"
                child_entry, child_revision, rejection = (
                    cls._resolve_current_startproc_catalog(session, reference)
                )
                if rejection is not None or child_entry is None or child_revision is None:
                    return rejection or "PROCEDURE_NOT_FOUND"
                rejection = visit(child_entry, child_revision, depth + 1)
                if rejection is not None:
                    return rejection
            visiting.remove(revision.id)
            visited.add(revision.id)
            return None

        rejection = visit(root_entry, root_revision, 1)
        return closure, rejection

    def _resume_startproc_admission(self, startproc_id: str) -> dict[str, Any]:
        startproc_id = _identifier(startproc_id, "startproc_id")
        with self.session_factory() as session:
            operation = session.get(StartProcOperation, startproc_id)
            if operation is None:
                raise OperatorNotFoundError("StartProc operation not found")
            if operation.state not in {"ADMITTING", "CHILD_CREATED", "RECONCILING"}:
                return self._startproc_dict(operation)
            revision = (
                session.get(
                    ProcedureCatalogRevision,
                    operation.resolved_child_catalog_revision_id,
                )
                if operation.resolved_child_catalog_revision_id is not None
                else None
            )
            entry = (
                session.get(ProcedureCatalogEntry, revision.catalog_id)
                if revision is not None
                else None
            )
            if revision is None or entry is None:
                return self._reject_startproc(
                    startproc_id,
                    "PINNED_CATALOG_MISSING",
                    "pinned StartProc catalog revision is missing",
                )
            operation_view = self._startproc_dict(operation)
            child_id = operation.child_execution_id
            procedure = Procedure(
                id=entry.procedure_ref,
                name=entry.name,
                description=entry.description,
                path=Path(entry.entrypoint),
                source=revision.source,
                sha256=revision.source_digest,
                steps=tuple(revision.steps),
                ir_version=revision.ir_version,
            )
        if child_id is None:
            if self.execution_starter is None:
                return operation_view
            try:
                child = self.execution_starter(
                    procedure=procedure, startproc=operation_view
                )
                if not isinstance(child, Execution):
                    raise OperatorServiceError("StartProc starter returned no execution")
            except Exception:
                return self._reject_startproc(
                    startproc_id,
                    "ADMISSION_REJECTED",
                    "child execution admission failed",
                )
            child_id = child.id
            with self._lock, self.session_factory() as session:
                operation = session.get(
                    StartProcOperation, startproc_id, with_for_update=True
                )
                if operation is None:
                    raise OperatorNotFoundError("StartProc operation disappeared")
                if operation.child_execution_id is None:
                    operation.child_execution_id = child_id
                    operation.state = "CHILD_CREATED"
                    operation.revision += 1
                    now = self._database_now(session)
                    operation.updated_at = now
                    self._audit(
                        session,
                        event_type="startproc.child_created",
                        aggregate_type="startproc_operation",
                        aggregate_id=operation.id,
                        execution_id=operation.parent_execution_id,
                        actor="startproc-service",
                        payload={
                            "state": operation.state,
                            "child_execution_id": child_id,
                            "revision": operation.revision,
                        },
                        created_at=now,
                    )
                    session.commit()
                elif operation.child_execution_id != child_id:
                    raise OperatorConflictError(
                        "StartProc admission produced a competing child"
                    )
        with self.session_factory() as session:
            child = session.get(Execution, child_id)
            if child is None:
                return self._reject_startproc(
                    startproc_id,
                    "CHILD_EXECUTION_MISSING",
                    "StartProc child execution is missing",
                )
            session.expunge(child)
        try:
            with self.session_factory() as session:
                parent_projection = session.get(
                    ExecutionOperatorState,
                    operation_view["parent_execution_id"],
                )
                inherited_settings = (
                    dict(parent_projection.settings)
                    if parent_projection is not None
                    else {}
                )
            self.ensure_execution_projection(
                child,
                actor="startproc-service",
                automatic=bool(operation_view["automatic"]),
                background_allowed=bool(operation_view["automatic"]),
                visible=bool(operation_view["visible"]),
                catalog_revision_id=revision.id,
                predecessor_execution_id=operation_view["parent_execution_id"],
                depth=int(operation_view["depth"]),
                ownership_mode=(
                    "B" if operation_view["automatic"] else "CONTROL_LOST"
                ),
                settings=inherited_settings,
                authoritative=True,
            )
        except Exception:
            return self._reject_startproc(
                startproc_id,
                "ADMISSION_REJECTED",
                "child execution projection admission failed",
            )
        with self._lock, self.session_factory() as session:
            operation = session.get(StartProcOperation, startproc_id, with_for_update=True)
            if operation is None:
                raise OperatorNotFoundError("StartProc operation disappeared")
            if operation.state in {"WAITING_CHILD", "SETTLED"}:
                return self._startproc_dict(operation)
            if operation.child_execution_id != child_id:
                raise OperatorConflictError("StartProc child identity changed")
            link = session.scalar(
                select(ParentChildLink).where(
                    ParentChildLink.startproc_id == startproc_id
                )
            )
            now = self._database_now(session)
            if link is None:
                session.add(
                    ParentChildLink(
                        id=new_id(),
                        startproc_id=startproc_id,
                        parent_execution_id=operation.parent_execution_id,
                        child_execution_id=child_id,
                        child_catalog_revision_id=revision.id,
                        arguments_digest=operation.arguments_digest,
                        blocking=operation.blocking,
                        visible=operation.visible,
                        automatic=operation.automatic,
                        created_at=now,
                    )
                )
            elif link.child_execution_id != child_id:
                raise OperatorConflictError("StartProc link is bound to another child")
            operation.state = "WAITING_CHILD" if operation.blocking else "SETTLED"
            operation.revision += 1
            operation.result_payload = (
                {}
                if operation.blocking
                else {"outcome": "CHILD_ADMITTED", "child_execution_id": child_id}
            )
            operation.updated_at = now
            operation.settled_at = None if operation.blocking else now
            self._audit(
                session,
                event_type=(
                    "startproc.waiting_child"
                    if operation.blocking
                    else "startproc.child_admitted"
                ),
                aggregate_type="startproc_operation",
                aggregate_id=operation.id,
                execution_id=operation.parent_execution_id,
                actor="startproc-service",
                payload={
                    "state": operation.state,
                    "child_execution_id": child_id,
                    "revision": operation.revision,
                },
                created_at=now,
            )
            session.commit()
            return self._startproc_dict(operation)

    def reconcile_startproc_admissions(
        self, parent_execution_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            query = select(StartProcOperation.id).where(
                StartProcOperation.state.in_(
                    ["ADMITTING", "CHILD_CREATED", "RECONCILING"]
                )
            )
            if parent_execution_id is not None:
                query = query.where(
                    StartProcOperation.parent_execution_id
                    == _identifier(parent_execution_id, "parent_execution_id")
                )
            ids = list(session.scalars(query.order_by(StartProcOperation.created_at)).all())
        return [self._resume_startproc_admission(item) for item in ids]

    @staticmethod
    def _ancestor_catalog_revisions(
        session: Session, execution_id: str
    ) -> set[str]:
        result: set[str] = set()
        current = execution_id
        for _ in range(9):
            projection = session.get(ExecutionOperatorState, current)
            if projection is None:
                break
            result.add(projection.catalog_revision_id)
            link = session.scalar(
                select(ParentChildLink).where(
                    ParentChildLink.child_execution_id == current
                )
            )
            if link is None:
                break
            current = link.parent_execution_id
        return result

    def _reject_startproc(
        self, startproc_id: str, code: str, message: str
    ) -> dict[str, Any]:
        with self._lock, self.session_factory() as session:
            operation = session.get(StartProcOperation, startproc_id, with_for_update=True)
            if operation is None:
                raise OperatorNotFoundError("StartProc operation not found")
            if operation.state in {"SETTLED", "REJECTED", "CANCELLED"}:
                return self._startproc_dict(operation)
            now = self._database_now(session)
            operation.state = "REJECTED"
            operation.revision += 1
            operation.rejection_code = _identifier(code, "rejection_code")
            operation.result_payload = {"error": message}
            operation.updated_at = now
            operation.settled_at = now
            self._audit(
                session,
                event_type="startproc.admission_rejected",
                aggregate_type="startproc_operation",
                aggregate_id=operation.id,
                execution_id=operation.parent_execution_id,
                actor="startproc-service",
                payload={
                    "state": operation.state,
                    "rejection_code": operation.rejection_code,
                    "revision": operation.revision,
                },
                created_at=now,
            )
            session.commit()
            return self._startproc_dict(operation)

    def reconcile_startproc_children(self) -> list[dict[str, Any]]:
        settled: list[dict[str, Any]] = []
        with self._lock, self.session_factory() as session:
            operations = session.scalars(
                select(StartProcOperation)
                .where(StartProcOperation.state == "WAITING_CHILD")
                .with_for_update()
            ).all()
            now = self._database_now(session)
            for operation in operations:
                child = (
                    session.get(Execution, operation.child_execution_id)
                    if operation.child_execution_id is not None
                    else None
                )
                if child is None or child.state not in {"completed", "aborted", "failed"}:
                    continue
                operation.state = "SETTLED"
                operation.revision += 1
                operation.result_payload = {
                    "outcome": (
                        "CHILD_FINISHED"
                        if child.state == "completed"
                        else "CHILD_FAILED"
                    ),
                    "child_execution_id": child.id,
                    "child_state": self.project_execution_state(child.state),
                }
                operation.updated_at = now
                operation.settled_at = now
                self._audit(
                    session,
                    event_type="startproc.child_settled",
                    aggregate_type="startproc_operation",
                    aggregate_id=operation.id,
                    execution_id=operation.parent_execution_id,
                    actor="operator-reconciler",
                    payload={
                        "state": operation.state,
                        "child_execution_id": child.id,
                        "child_state": self.project_execution_state(child.state),
                        "revision": operation.revision,
                    },
                    created_at=now,
                )
                settled.append(self._startproc_dict(operation))
            session.commit()
        return settled

    def list_reconcilable_startprocs(
        self, parent_execution_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            query = select(StartProcOperation).where(
                StartProcOperation.state.in_(
                    ["ADMITTING", "CHILD_CREATED", "WAITING_CHILD", "RECONCILING"]
                )
            )
            if parent_execution_id is not None:
                query = query.where(
                    StartProcOperation.parent_execution_id
                    == _identifier(parent_execution_id, "parent_execution_id")
                )
            operations = session.scalars(
                query.order_by(StartProcOperation.created_at, StartProcOperation.id)
            ).all()
            return [self._startproc_dict(item) for item in operations]

    def list_startproc_operations(
        self, *, parent_execution_id: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise OperatorValidationError("limit must be 1 through 500")
        with self.session_factory() as session:
            query = select(StartProcOperation)
            if parent_execution_id is not None:
                query = query.where(
                    StartProcOperation.parent_execution_id
                    == _identifier(parent_execution_id, "parent_execution_id")
                )
            rows = session.scalars(
                query.order_by(StartProcOperation.created_at.desc()).limit(limit)
            ).all()
            return [self._startproc_dict(item) for item in rows]

    def list_unacked_startproc_results(
        self, parent_execution_id: str | None = None, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise OperatorValidationError("limit must be 1 through 500")
        with self.session_factory() as session:
            query = select(StartProcOperation).where(
                StartProcOperation.state.in_(["SETTLED", "REJECTED", "CANCELLED"]),
                StartProcOperation.result_applied_at.is_(None),
            )
            if parent_execution_id is not None:
                query = query.where(
                    StartProcOperation.parent_execution_id
                    == _identifier(parent_execution_id, "parent_execution_id")
                )
            rows = session.scalars(
                query.order_by(StartProcOperation.updated_at, StartProcOperation.id).limit(
                    limit
                )
            ).all()
            return [self._startproc_dict(item) for item in rows]

    def mark_startproc_result_delivery_attempt(
        self, startproc_id: str, revision: int
    ) -> dict[str, Any]:
        startproc_id = _identifier(startproc_id, "startproc_id")
        if type(revision) is not int or revision < 0:
            raise OperatorValidationError("StartProc revision is invalid")
        with self._lock, self.session_factory() as session:
            operation = session.get(
                StartProcOperation, startproc_id, with_for_update=True
            )
            if operation is None:
                raise OperatorNotFoundError("StartProc operation not found")
            if operation.revision != revision:
                raise OperatorConflictError(
                    "StartProc result revision conflict",
                    current={"revision": operation.revision},
                )
            if operation.state not in {"SETTLED", "REJECTED", "CANCELLED"}:
                raise OperatorConflictError("StartProc result is not terminal")
            if operation.result_applied_at is None:
                operation.result_delivery_attempts += 1
                operation.result_last_attempt_at = self._database_now(session)
                session.commit()
            return self._startproc_dict(operation)

    def ack_startproc_result_application(
        self,
        startproc_id: str,
        revision: int,
        parent_execution_revision: int | None = None,
        current_step: int | None = None,
    ) -> dict[str, Any]:
        startproc_id = _identifier(startproc_id, "startproc_id")
        if type(revision) is not int or revision < 0:
            raise OperatorValidationError("StartProc revision is invalid")
        if parent_execution_revision is not None and (
            type(parent_execution_revision) is not int
            or parent_execution_revision < 0
        ):
            raise OperatorValidationError("parent execution revision is invalid")
        if current_step is not None and (type(current_step) is not int or current_step < 0):
            raise OperatorValidationError("parent current step is invalid")
        with self._lock, self.session_factory() as session:
            operation = session.get(
                StartProcOperation, startproc_id, with_for_update=True
            )
            if operation is None:
                raise OperatorNotFoundError("StartProc operation not found")
            if operation.revision != revision:
                raise OperatorConflictError(
                    "StartProc result revision conflict",
                    current={"revision": operation.revision},
                )
            if operation.state not in {"SETTLED", "REJECTED", "CANCELLED"}:
                raise OperatorConflictError("StartProc result is not terminal")
            if operation.result_applied_at is not None:
                return self._startproc_dict(operation)
            parent = session.get(
                Execution, operation.parent_execution_id, with_for_update=True
            )
            if parent is None:
                raise OperatorNotFoundError("StartProc parent execution not found")
            observed_revision = (
                parent.revision
                if parent_execution_revision is None
                else parent_execution_revision
            )
            observed_step = parent.current_step if current_step is None else current_step
            if observed_revision > parent.revision:
                raise OperatorConflictError("parent execution evidence is ahead of storage")
            if observed_step is None:
                raise OperatorConflictError("StartProc application evidence is missing")
            now = self._database_now(session)
            operation.result_applied_at = now
            operation.result_applied_parent_revision = observed_revision
            operation.result_applied_parent_step = observed_step
            self._audit(
                session,
                event_type="startproc.result_applied",
                aggregate_type="startproc_operation",
                aggregate_id=operation.id,
                execution_id=operation.parent_execution_id,
                actor="operator-runtime",
                payload={
                    "revision": operation.revision,
                    "parent_execution_revision": observed_revision,
                    "parent_current_step": observed_step,
                },
                created_at=now,
            )
            session.commit()
            return self._startproc_dict(operation)

    def settle_startproc_child(
        self,
        startproc_id: str,
        child_execution_id: str,
        child_terminal_state: str,
    ) -> dict[str, Any]:
        startproc_id = _identifier(startproc_id, "startproc_id")
        child_execution_id = _identifier(child_execution_id, "child_execution_id")
        child_terminal_state = _identifier(
            child_terminal_state.upper(), "child_terminal_state"
        )
        if child_terminal_state not in {"FINISHED", "ABORTED", "ERROR"}:
            raise OperatorValidationError("child state is not terminal")
        with self._lock, self.session_factory() as session:
            operation = session.get(StartProcOperation, startproc_id, with_for_update=True)
            if operation is None:
                raise OperatorNotFoundError("StartProc operation not found")
            if operation.child_execution_id != child_execution_id:
                raise OperatorConflictError("StartProc child identity does not match")
            if operation.state == "SETTLED":
                return self._startproc_dict(operation)
            if operation.state != "WAITING_CHILD":
                raise OperatorConflictError("StartProc is not waiting for its child")
            now = self._database_now(session)
            operation.state = "SETTLED"
            operation.revision += 1
            operation.result_payload = {
                "outcome": (
                    "CHILD_FINISHED"
                    if child_terminal_state == "FINISHED"
                    else "CHILD_FAILED"
                ),
                "child_execution_id": child_execution_id,
                "child_state": child_terminal_state,
            }
            operation.updated_at = now
            operation.settled_at = now
            self._audit(
                session,
                event_type="startproc.child_settled",
                aggregate_type="startproc_operation",
                aggregate_id=operation.id,
                execution_id=operation.parent_execution_id,
                actor="operator-runtime",
                payload={
                    "state": operation.state,
                    "child_execution_id": child_execution_id,
                    "child_state": child_terminal_state,
                    "revision": operation.revision,
                },
                created_at=now,
            )
            session.commit()
            return self._startproc_dict(operation)

    def relationships(self, execution_id: str) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            parents = session.scalars(
                select(ParentChildLink).where(
                    ParentChildLink.child_execution_id == execution_id
                )
            ).all()
            children = session.scalars(
                select(ParentChildLink).where(
                    ParentChildLink.parent_execution_id == execution_id
                )
            ).all()
            return {
                "parents": [relationship_dict(item) for item in parents],
                "children": [relationship_dict(item) for item in children],
            }

    def inspection(self, execution_id: str) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            projection = session.get(ExecutionOperatorState, execution_id)
            safe_to_edit = projection is not None and projection.state in {
                "PAUSED",
                "PROMPT",
                "INTERRUPTED",
            }
            variables = execution.variables if isinstance(execution.variables, dict) else {}
            items: list[dict[str, Any]] = []

            def append_value(scope: str, prefix: str, name: str, value: Any) -> None:
                path = f"{prefix}.{name}"
                safe_value, redacted = self._redact_literal(
                    value, path=path, marker=None
                )
                editable = (
                    safe_to_edit
                    and scope != "SHARED_DATA"
                    and not redacted
                )
                items.append(
                    {
                        "path": path,
                        "scope": scope,
                        "name": name,
                        "type": self._literal_type(value),
                        "value": safe_value,
                        "value_revision": execution.revision,
                        "revision": execution.revision,
                        "execution_revision": execution.revision,
                        "freshness": "COMMITTED",
                        "editable": editable,
                        "redacted": redacted,
                    }
                )

            reserved = {"ARGS", "IVARS", "GLOBALS", "SHARED_DATA"}
            for name, value in sorted(variables.items()):
                if name.startswith("__spell_") or name in reserved:
                    continue
                append_value("LOCAL_VARIABLE", "variables", name, value)

            containers = (
                ("ARGS", "ARGS"),
                ("IVARS", "IVARS"),
                ("GLOBAL_VARIABLE", "GLOBALS"),
                ("SHARED_DATA", "SHARED_DATA"),
            )
            for scope, key in containers:
                container = variables.get(key)
                if isinstance(container, dict):
                    for name, value in sorted(container.items()):
                        append_value(scope, key, name, value)
                else:
                    items.append(
                        {
                            "path": key,
                            "scope": scope,
                            "name": key,
                            "type": "NULL",
                            "value": None,
                            "value_revision": execution.revision,
                            "revision": execution.revision,
                            "execution_revision": execution.revision,
                            "freshness": "NOT_AVAILABLE",
                            "editable": False,
                            "redacted": False,
                        }
                    )
            return {
                "items": items,
                "console_operations": [
                    "LIST_SCOPE",
                    "READ_VALUE",
                    "EXPAND_VALUE",
                    "SEARCH_SOURCE_LITERAL",
                    "WRITE_TYPED_LITERAL",
                ],
                "execution_revision": execution.revision,
            }

    def search_workspace(
        self,
        execution_id: str,
        *,
        query: str,
        view: str,
        source_digest: str | None = None,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        query = _bounded(query, "query", 200)
        view = _identifier(view.upper(), "view")
        if view not in {"SOURCE", "TEXT", "AS_RUN", "SUPPORT"}:
            raise OperatorValidationError("workspace search view is not allowlisted")
        if type(after_sequence) is not int or after_sequence < 0:
            raise OperatorValidationError("workspace search cursor is invalid")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise OperatorValidationError("workspace search limit is outside its bound")
        try:
            _reject_prompt_secret_material(query, "query")
        except PromptSecretMaterialError as exc:
            raise OperatorAuthorizationError(
                "secret material cannot be used as a workspace search literal"
            ) from exc
        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            if source_digest is not None and source_digest != execution.procedure_hash:
                raise OperatorConflictError(
                    "workspace search source revision conflict",
                    current={"source_digest": execution.procedure_hash},
                )
            items: list[dict[str, Any]] = []
            if view == "SOURCE":
                for line, source_line in enumerate(
                    execution.procedure_source.splitlines(), start=1
                ):
                    column = source_line.find(query)
                    if column < 0:
                        continue
                    items.append(
                        {
                            "id": f"source:{execution.procedure_hash}:{line}:{column + 1}",
                            "line": line,
                            "column": column + 1,
                            "text": source_line[:1000],
                            "source_digest": execution.procedure_hash,
                        }
                    )
                    if len(items) >= limit:
                        break
                next_cursor = after_sequence
            else:
                events = session.scalars(
                    select(Event)
                    .where(
                        Event.execution_id == execution_id,
                        Event.sequence > after_sequence,
                    )
                    .order_by(Event.sequence)
                    .limit(1000)
                ).all()
                for event in events:
                    if view == "TEXT" and event.event_type not in {
                        "procedure.log",
                        "procedure.user_action_log",
                    }:
                        continue
                    if view == "SUPPORT" and event.severity.lower() not in {
                        "warning",
                        "error",
                        "critical",
                    }:
                        continue
                    searchable = json.dumps(
                        {"event_type": event.event_type, "payload": event.payload},
                        sort_keys=True,
                        ensure_ascii=True,
                    )
                    if query not in searchable:
                        continue
                    safe_payload = self.redact_for_report(event.payload)
                    items.append(
                        {
                            "id": event.id,
                            "sequence": event.sequence,
                            "time": event.created_at.isoformat(),
                            "scope": event.source,
                            "kind": event.event_type,
                            "message": str(
                                (safe_payload or {}).get("message", event.event_type)
                            )[:2000],
                            "correlation_id": event.correlation_id,
                            "line": (safe_payload or {}).get("line"),
                            "payload": safe_payload,
                        }
                    )
                    if len(items) >= limit:
                        break
                next_cursor = items[-1]["sequence"] if items else after_sequence
            return {
                "view": view,
                "query": query,
                "source_digest": execution.procedure_hash,
                "items": items,
                "next_cursor": next_cursor,
            }

    def workspace_view(
        self,
        execution_id: str,
        *,
        view: str,
        source_digest: str | None = None,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        view = _identifier(view.upper(), "view")
        if view not in {"TEXT", "AS_RUN", "SUPPORT"}:
            raise OperatorValidationError("workspace history view is not allowlisted")
        if type(after_sequence) is not int or after_sequence < 0:
            raise OperatorValidationError("workspace history cursor is invalid")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise OperatorValidationError("workspace history limit is outside its bound")
        with self.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            if source_digest is not None and source_digest != execution.procedure_hash:
                raise OperatorConflictError(
                    "workspace history source revision conflict",
                    current={"source_digest": execution.procedure_hash},
                )
            statement = select(Event).where(
                Event.execution_id == execution_id,
                Event.sequence > after_sequence,
            )
            if view == "TEXT":
                statement = statement.where(
                    Event.event_type.in_(
                        {"procedure.log", "procedure.user_action_log"}
                    )
                )
            elif view == "SUPPORT":
                statement = statement.where(
                    func.lower(Event.severity).in_(
                        {"warning", "error", "critical"}
                    )
                )
            rows = session.scalars(
                statement.order_by(Event.sequence).limit(limit + 1)
            ).all()
            has_more = len(rows) > limit
            rows = rows[:limit]
            items = [self._workspace_event_entry(event, execution.steps) for event in rows]
            return {
                "view": view,
                "source_digest": execution.procedure_hash,
                "items": items,
                "after_sequence": after_sequence,
                "next_cursor": items[-1]["sequence"] if has_more and items else None,
                "has_more": has_more,
                "through_sequence": execution.next_sequence - 1,
            }

    def _workspace_event_entry(
        self, event: Event, steps: list[dict[str, Any]] | Any
    ) -> dict[str, Any]:
        safe_payload = self.redact_for_report(event.payload)
        payload = safe_payload if isinstance(safe_payload, dict) else {}
        line = payload.get("line")
        if type(line) is not int:
            step_index = payload.get("step_index")
            if type(step_index) is not int:
                next_step = payload.get("next_step")
                step_index = next_step - 1 if type(next_step) is int else None
            if (
                type(step_index) is int
                and isinstance(steps, list)
                and 0 <= step_index < len(steps)
                and isinstance(steps[step_index], dict)
                and type(steps[step_index].get("line")) is int
            ):
                line = steps[step_index]["line"]
            else:
                line = None
        created_at = event.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        return {
            "id": event.id,
            "sequence": event.sequence,
            "time": created_at.astimezone(timezone.utc).isoformat(),
            "scope": event.source,
            "kind": event.event_type,
            "message": str(payload.get("message", event.event_type))[:2000],
            "correlation_id": event.correlation_id,
            "line": line,
            "outcome": payload.get("outcome") or payload.get("state"),
        }

    @staticmethod
    def _is_secret_path(path: str) -> bool:
        return _SECRET_PATH.search(path) is not None

    @classmethod
    def _redact_literal(
        cls,
        value: Any,
        *,
        path: str = "",
        marker: Any = "[REDACTED]",
    ) -> tuple[Any, bool]:
        if path and cls._is_secret_path(path):
            return marker, True
        if isinstance(value, str) and any(
            pattern.search(value) for pattern in _PROMPT_SECRET_PATTERNS
        ):
            return marker, True
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            redacted = False
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                safe_child, child_redacted = cls._redact_literal(
                    child, path=child_path, marker=marker
                )
                result[str(key)] = safe_child
                redacted = redacted or child_redacted
            return result, redacted
        if isinstance(value, list):
            result_list: list[Any] = []
            redacted = False
            for index, child in enumerate(value):
                child_path = f"{path}.{index}" if path else str(index)
                safe_child, child_redacted = cls._redact_literal(
                    child, path=child_path, marker=marker
                )
                result_list.append(safe_child)
                redacted = redacted or child_redacted
            return result_list, redacted
        return value, False

    @staticmethod
    def _inspection_location(path: str, scope: str) -> tuple[str | None, str]:
        prefixes = {
            "LOCAL_VARIABLE": (None, ("variables.", "LOCAL_VARIABLE.")),
            "GLOBAL_VARIABLE": ("GLOBALS", ("GLOBALS.", "GLOBAL_VARIABLE.")),
            "ARGS": ("ARGS", ("ARGS.",)),
            "IVARS": ("IVARS", ("IVARS.",)),
        }
        container, accepted = prefixes[scope]
        for prefix in accepted:
            if path.startswith(prefix):
                return container, path[len(prefix) :]
        raise OperatorValidationError("inspection path does not match its declared scope")

    def edit_inspection(
        self,
        execution_id: str,
        *,
        path: str,
        scope: str,
        declared_type: str,
        value: Any,
        expected_value_revision: int,
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        path = _bounded(path, "path")
        scope = _identifier(scope, "scope")
        if scope not in {"LOCAL_VARIABLE", "GLOBAL_VARIABLE", "ARGS", "IVARS"}:
            raise OperatorValidationError("inspection scope is not editable in v0.6")
        declared_type = _identifier(declared_type, "type")
        value = _validate_literal(value)
        try:
            _reject_prompt_secret_material(value, path)
        except PromptSecretMaterialError as exc:
            raise OperatorAuthorizationError(
                "secret material is not accepted in inspection edits"
            ) from exc
        if self._literal_type(value) != declared_type:
            if not (declared_type == "FINITE_DECIMAL" and type(value) is int):
                raise OperatorValidationError("typed literal does not match the declared type")
        if self._is_secret_path(path):
            raise OperatorAuthorizationError("redacted inspection values are not editable")
        container_name, name = self._inspection_location(path, scope)
        if not name or "." in name or name.startswith("__spell_"):
            raise OperatorValidationError("only an existing top-level variable may be edited")
        request_digest = canonical_digest(
            {
                "execution_id": execution_id,
                "path": path,
                "scope": scope,
                "type": declared_type,
                "value": value,
                "expected_value_revision": expected_value_revision,
                "expected_execution_revision": expected_execution_revision,
                "reason": reason,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
            }
        )
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        with self._lock, self.session_factory() as session:
            existing = session.scalar(
                select(InspectionEditOperation).where(
                    InspectionEditOperation.execution_id == execution_id,
                    InspectionEditOperation.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise OperatorConflictError(
                        "idempotency key was used for another inspection edit"
                    )
                return self._inspection_edit_dict(existing, include_variables=True)
            projection, lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id, with_for_update=True)
            if execution is None:
                raise OperatorNotFoundError("execution not found")
            self._sync_projection_from_execution(projection, execution)
            if projection.state not in {"PAUSED", "PROMPT", "INTERRUPTED"}:
                raise OperatorConflictError("inspection edit is not allowed in this state")
            if (
                execution.revision != expected_execution_revision
                or expected_value_revision != execution.revision
            ):
                raise OperatorConflictError("inspection value revision conflict")
            variables = dict(execution.variables)
            target = variables if container_name is None else variables.get(container_name)
            if not isinstance(target, dict) or name not in target:
                raise OperatorNotFoundError("editable variable not found")
            old_value = target[name]
            if self._literal_type(old_value) != declared_type:
                raise OperatorConflictError(
                    "declared inspection type does not match the current target"
                )
            if container_name is None:
                variables[name] = value
            else:
                updated_container = dict(target)
                updated_container[name] = value
                variables[container_name] = updated_container
            now = self._database_now(session)
            operation = InspectionEditOperation(
                id=new_id(),
                execution_id=execution_id,
                revision=1,
                state="PENDING_SAFE_POINT",
                path=path,
                scope=scope,
                declared_type=declared_type,
                value=value,
                old_value_digest=canonical_digest(old_value),
                new_value_digest=canonical_digest(value),
                expected_value_revision=expected_value_revision,
                expected_execution_revision=expected_execution_revision,
                authoritative_variables=variables,
                controller_lease_id=lease.id,
                accepted_lease_revision=lease.revision,
                control_fencing_token=lease.fencing_token,
                actor=actor,
                reason=_bounded(reason, "reason", 1000),
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                delivery_attempts=0,
                result_payload={},
                created_at=now,
            )
            session.add(operation)
            session.flush()
            response = self._inspection_edit_dict(operation, include_variables=True)
            self._store_request(
                session,
                scope=f"inspection-edit:{execution_id}:{path}",
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="inspection_edit_operation",
                resource_id=operation.id,
                response={key: value for key, value in response.items() if key != "variables"},
                created_at=now,
            )
            self._audit(
                session,
                event_type="inspection.edit_admitted",
                aggregate_type="inspection_edit_operation",
                aggregate_id=operation.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "path": path,
                    "scope": scope,
                    "old_value_digest": operation.old_value_digest,
                    "new_value_digest": operation.new_value_digest,
                    "expected_execution_revision": expected_execution_revision,
                    "reason": operation.reason,
                },
                created_at=now,
            )
            session.commit()
            return response

    @staticmethod
    def _inspection_edit_dict(
        operation: InspectionEditOperation, *, include_variables: bool = False
    ) -> dict[str, Any]:
        result = {
            "id": operation.id,
            "edit_id": operation.id,
            "execution_id": operation.execution_id,
            "revision": operation.revision,
            "delivery_revision": operation.revision,
            "state": operation.state,
            "path": operation.path,
            "scope": operation.scope,
            "type": operation.declared_type,
            "value": operation.value,
            "value_revision": (
                operation.applied_execution_revision
                if operation.applied_execution_revision is not None
                else operation.expected_value_revision
            ),
            "execution_revision": (
                operation.applied_execution_revision
                if operation.applied_execution_revision is not None
                else operation.expected_execution_revision
            ),
            "freshness": (
                "COMMITTED" if operation.state == "APPLIED" else "PENDING_APPLICATION"
            ),
            "editable": operation.state == "APPLIED",
            "redacted": False,
            "delivery_attempts": operation.delivery_attempts,
            "accepted_lease_id": operation.controller_lease_id,
            "accepted_lease_revision": operation.accepted_lease_revision,
            "accepted_fencing_token": operation.control_fencing_token,
            "last_delivery_attempt_at": (
                operation.last_delivery_attempt_at.isoformat()
                if operation.last_delivery_attempt_at is not None
                else None
            ),
            "application_id": operation.application_id,
            "application_safe_point_id": operation.application_safe_point_id,
            "rejection_code": operation.rejection_code,
            "result": operation.result_payload,
            "created_at": operation.created_at.isoformat(),
            "settled_at": (
                operation.settled_at.isoformat()
                if operation.settled_at is not None
                else None
            ),
        }
        if include_variables:
            result["variables"] = operation.authoritative_variables
        return result

    def list_unacked_inspection_edits(
        self, execution_id: str | None = None, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise OperatorValidationError("limit must be 1 through 500")
        with self.session_factory() as session:
            query = select(InspectionEditOperation).where(
                InspectionEditOperation.state.in_(["PENDING_SAFE_POINT", "APPLYING"])
            )
            if execution_id is not None:
                query = query.where(
                    InspectionEditOperation.execution_id
                    == _identifier(execution_id, "execution_id")
                )
            rows = session.scalars(
                query.order_by(
                    InspectionEditOperation.created_at,
                    InspectionEditOperation.id,
                ).limit(limit)
            ).all()
            return [
                self._inspection_edit_dict(item, include_variables=True)
                for item in rows
            ]

    def mark_inspection_edit_delivery_attempt(
        self,
        edit_id: str,
        revision: int,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        edit_id = _identifier(edit_id, "edit_id")
        with self._lock, self.session_factory() as session:
            operation_execution_id = session.scalar(
                select(InspectionEditOperation.execution_id).where(
                    InspectionEditOperation.id == edit_id
                )
            )
            if operation_execution_id is None:
                raise OperatorNotFoundError("inspection edit not found")
            self._require_worker_epoch(
                session, operation_execution_id, worker_generation
            )
            operation = session.get(
                InspectionEditOperation, edit_id, with_for_update=True
            )
            if operation is None:
                raise OperatorNotFoundError("inspection edit not found")
            if operation.revision != revision:
                raise OperatorConflictError(
                    "inspection edit revision conflict",
                    current={"revision": operation.revision},
                )
            if operation.state in {"PENDING_SAFE_POINT", "APPLYING"}:
                operation.delivery_attempts += 1
                operation.last_delivery_attempt_at = self._database_now(session)
                session.commit()
            return self._inspection_edit_dict(operation, include_variables=True)

    def begin_inspection_edit_application(
        self,
        edit_id: str,
        revision: int,
        application_safe_point_id: str | None = None,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        edit_id = _identifier(edit_id, "edit_id")
        if type(revision) is not int or revision < 1:
            raise OperatorValidationError("inspection edit revision is invalid")
        with self._lock, self.session_factory() as session:
            operation_execution_id = session.scalar(
                select(InspectionEditOperation.execution_id).where(
                    InspectionEditOperation.id == edit_id
                )
            )
            if operation_execution_id is None:
                raise OperatorNotFoundError("inspection edit not found")
            self._require_worker_epoch(
                session, operation_execution_id, worker_generation
            )
            operation = session.get(
                InspectionEditOperation, edit_id, with_for_update=True
            )
            if operation is None:
                raise OperatorNotFoundError("inspection edit not found")
            if operation.revision != revision:
                raise OperatorConflictError(
                    "inspection edit revision conflict",
                    current={"revision": operation.revision},
                )
            if operation.state == "APPLYING":
                return self._inspection_edit_dict(operation, include_variables=True)
            if operation.state != "PENDING_SAFE_POINT":
                return self._inspection_edit_dict(operation)
            projection = session.get(
                ExecutionOperatorState,
                operation.execution_id,
                with_for_update=True,
            )
            execution = session.get(
                Execution, operation.execution_id, with_for_update=True
            )
            lease = session.get(
                ControllerLease,
                operation.controller_lease_id,
                with_for_update=True,
            )
            now = self._database_now(session)
            if (
                projection is not None
                and lease is not None
                and lease.state == "ACTIVE"
                and (_stored_utc(lease.expires_at) or now) <= now
            ):
                self._expire_lease(session, projection, lease, now)
            valid = (
                projection is not None
                and execution is not None
                and lease is not None
                and execution.revision == operation.expected_execution_revision
                and projection.ownership_mode == "C"
                and projection.current_lease_id == operation.controller_lease_id
                and lease.state == "ACTIVE"
                and lease.revision == operation.accepted_lease_revision
                and lease.fencing_token == operation.control_fencing_token
                and projection.control_fencing_token
                == operation.control_fencing_token
                and (_stored_utc(lease.expires_at) or now) > now
            )
            if not valid:
                operation.state = "REJECTED"
                operation.rejection_code = "CONTROL_FENCE_STALE"
                operation.result_payload = {"target_mutation": "NONE"}
                operation.settled_at = now
                session.commit()
                return self._inspection_edit_dict(operation)
            if self._has_mutation_reservation(
                session,
                operation.execution_id,
                edit_id=operation.id,
            ):
                return self._inspection_edit_dict(
                    operation, include_variables=True
                )
            operation.state = "APPLYING"
            operation.application_safe_point_id = (
                _identifier(application_safe_point_id, "application_safe_point_id")
                if application_safe_point_id is not None
                else projection.current_safe_point_id
            )
            session.commit()
            return self._inspection_edit_dict(operation, include_variables=True)

    def ack_inspection_edit_application(
        self,
        edit_id: str,
        application_id: str,
        *,
        outcome: str,
        rejection_code: str | None = None,
        application_safe_point_id: str | None = None,
        variables: dict[str, Any] | None = None,
        worker_generation: int | None = None,
    ) -> dict[str, Any]:
        edit_id = _identifier(edit_id, "edit_id")
        application_id = _identifier(application_id, "application_id")
        outcome = _identifier(str(outcome).upper(), "outcome")
        if outcome not in {"APPLIED", "REJECTED"}:
            raise OperatorValidationError("inspection edit outcome is invalid")
        with self._lock, self.session_factory() as session:
            operation_execution_id = session.scalar(
                select(InspectionEditOperation.execution_id).where(
                    InspectionEditOperation.id == edit_id
                )
            )
            if operation_execution_id is None:
                raise OperatorNotFoundError("inspection edit not found")
            self._require_worker_epoch(
                session, operation_execution_id, worker_generation
            )
            operation = session.get(
                InspectionEditOperation, edit_id, with_for_update=True
            )
            if operation is None:
                raise OperatorNotFoundError("inspection edit not found")
            if operation.state in {"APPLIED", "REJECTED", "CANCELLED"}:
                if operation.application_id not in {None, application_id}:
                    raise OperatorConflictError(
                        "inspection edit has competing application evidence"
                    )
                if (
                    application_safe_point_id is not None
                    and operation.application_safe_point_id
                    not in {None, application_safe_point_id}
                ):
                    raise OperatorConflictError(
                        "inspection edit has competing safe-point evidence"
                    )
                return self._inspection_edit_dict(operation)
            if outcome == "APPLIED" and operation.state != "APPLYING":
                raise OperatorConflictError(
                    "inspection edit application has not been reserved"
                )
            now = self._database_now(session)
            operation.application_id = application_id
            if application_safe_point_id is not None:
                application_safe_point_id = _identifier(
                    application_safe_point_id, "application_safe_point_id"
                )
                if operation.application_safe_point_id not in {
                    None,
                    application_safe_point_id,
                }:
                    raise OperatorConflictError(
                        "inspection edit application safe point does not match reservation"
                    )
                operation.application_safe_point_id = application_safe_point_id
            operation.state = outcome
            operation.rejection_code = (
                _identifier(rejection_code, "rejection_code")
                if rejection_code is not None
                else None
            )
            operation.settled_at = now
            if outcome == "APPLIED":
                variables = _validate_literal(variables)
                if not isinstance(variables, dict):
                    raise OperatorValidationError(
                        "inspection edit application variables are missing"
                    )
                if canonical_digest(variables) != canonical_digest(
                    operation.authoritative_variables
                ):
                    raise OperatorConflictError(
                        "inspection edit application snapshot does not match admission"
                    )
                execution = session.get(
                    Execution, operation.execution_id, with_for_update=True
                )
                projection = session.get(
                    ExecutionOperatorState,
                    operation.execution_id,
                    with_for_update=True,
                )
                if execution is None or projection is None:
                    raise OperatorNotFoundError("inspection edit execution not found")
                execution.variables = variables
                execution.revision += 1
                projection.revision += 1
                projection.updated_at = now
                operation.applied_execution_revision = execution.revision
                operation.result_payload = {
                    "variables_digest": canonical_digest(variables),
                    "applied_execution_revision": execution.revision,
                }
            else:
                operation.result_payload = {"target_mutation": "NONE"}
            self._audit(
                session,
                event_type=f"inspection.edit_{outcome.lower()}",
                aggregate_type="inspection_edit_operation",
                aggregate_id=operation.id,
                execution_id=operation.execution_id,
                actor="operator-runtime",
                payload={
                    "path": operation.path,
                    "scope": operation.scope,
                    "application_id": application_id,
                    "application_safe_point_id": operation.application_safe_point_id,
                    "rejection_code": operation.rejection_code,
                },
                created_at=now,
            )
            session.commit()
            return self._inspection_edit_dict(operation)

    def console_operation(
        self,
        execution_id: str,
        *,
        operation: str,
        path: str | None,
        scope: str | None = None,
        query: str | None = None,
        limit: int = 100,
        actor: str,
        expected_execution_revision: int,
        idempotency_key: str,
        reason: str,
        declared_type: str | None = None,
        value: Any = None,
        control_proof: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        operation = _identifier(operation, "operation")
        if operation == "WRITE_TYPED_LITERAL":
            if control_proof is None or declared_type is None or path is None:
                raise OperatorAuthorizationError("write operation requires control proof")
            if path.startswith("ARGS."):
                scope = "ARGS"
            elif path.startswith("IVARS."):
                scope = "IVARS"
            elif path.startswith(("GLOBALS.", "GLOBAL_VARIABLE.")):
                scope = "GLOBAL_VARIABLE"
            else:
                scope = "LOCAL_VARIABLE"
            result = self.edit_inspection(
                execution_id,
                path=path,
                scope=scope,
                declared_type=declared_type,
                value=value,
                expected_value_revision=expected_execution_revision,
                expected_execution_revision=expected_execution_revision,
                actor=actor,
                idempotency_key=idempotency_key,
                reason=reason,
                **control_proof,
            )
            return {"operation": operation, "result": result}
        inspection = self.inspection(execution_id)
        if inspection["execution_revision"] != expected_execution_revision:
            raise OperatorConflictError("execution revision conflict")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise OperatorValidationError("console result limit is outside its bound")
        if operation == "LIST_SCOPE":
            if scope not in {
                "LOCAL_VARIABLE",
                "GLOBAL_VARIABLE",
                "ARGS",
                "IVARS",
                "SHARED_DATA",
            }:
                raise OperatorValidationError("console inspection scope is invalid")
            result: Any = [
                item for item in inspection["items"] if item["scope"] == scope
            ][:limit]
        elif operation == "READ_VALUE":
            if path is None:
                raise OperatorValidationError("READ_VALUE requires path")
            matches = [item for item in inspection["items"] if item["path"] == path]
            if len(matches) != 1:
                raise OperatorNotFoundError("inspection path not found")
            result = matches[0]
        elif operation == "EXPAND_VALUE":
            if path is None:
                raise OperatorValidationError("EXPAND_VALUE requires path")
            matches = [item for item in inspection["items"] if item["path"] == path]
            if len(matches) != 1:
                raise OperatorNotFoundError("inspection path not found")
            item = matches[0]
            if item.get("redacted") and item.get("value") is None:
                raise OperatorAuthorizationError("redacted value cannot be expanded")
            container = item.get("value")
            if isinstance(container, dict):
                result = []
                for key, child in list(container.items())[:limit]:
                    child_path = f"{path}.{key}"
                    safe_child, redacted = self._redact_literal(
                        child, path=child_path, marker=None
                    )
                    result.append(
                        {
                            "path": child_path,
                            "name": key,
                            "type": self._literal_type(child),
                            "value": safe_child,
                            "redacted": redacted,
                        }
                    )
            elif isinstance(container, list):
                result = []
                for index, child in enumerate(container[:limit]):
                    child_path = f"{path}.{index}"
                    safe_child, redacted = self._redact_literal(
                        child, path=child_path, marker=None
                    )
                    result.append(
                        {
                            "path": child_path,
                            "name": str(index),
                            "type": self._literal_type(child),
                            "value": safe_child,
                            "redacted": redacted,
                        }
                    )
            else:
                raise OperatorValidationError("inspection value is not expandable")
        elif operation == "SEARCH_SOURCE_LITERAL":
            query = _bounded(query or "", "query", 200)
            try:
                _reject_prompt_secret_material(query)
            except PromptSecretMaterialError as exc:
                raise OperatorAuthorizationError(
                    "secret material cannot be used as a source search literal"
                ) from exc
            with self.session_factory() as session:
                execution = session.get(Execution, _identifier(execution_id, "execution_id"))
                if execution is None:
                    raise OperatorNotFoundError("execution not found")
                matches = []
                for line_number, text_value in enumerate(
                    execution.procedure_source.splitlines(), start=1
                ):
                    column = text_value.find(query)
                    if column >= 0:
                        matches.append(
                            {
                                "line": line_number,
                                "column": column + 1,
                                "text": text_value[:1000],
                                "source_digest": execution.procedure_hash,
                            }
                        )
                    if len(matches) >= limit:
                        break
                result = matches
        else:
            raise OperatorValidationError("console operation is not allowed")
        return {"operation": operation, "result": result}

    @staticmethod
    def _literal_type(value: Any) -> str:
        if value is None:
            return "NULL"
        if type(value) is bool:
            return "BOOLEAN"
        if type(value) is int:
            return "INTEGER"
        if type(value) is float:
            return "FINITE_DECIMAL"
        if type(value) is str:
            return "STRING"
        if type(value) is list:
            return "LIST"
        if type(value) is dict:
            return "MAP"
        raise OperatorValidationError("value does not have a bounded literal type")

    def put_breakpoint(
        self,
        execution_id: str,
        line: int,
        *,
        one_shot: bool,
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        if type(line) is not int or line < 1:
            raise OperatorValidationError("breakpoint line is invalid")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        request_digest = canonical_digest(
            {
                "operation": "ADD",
                "execution_id": execution_id,
                "line": line,
                "one_shot": one_shot,
                "expected_execution_revision": expected_execution_revision,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
        )
        scope = f"breakpoint-add:{execution_id}:{line}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            projection, _lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id)
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            if line not in {item.get("line") for item in execution.steps}:
                raise OperatorValidationError("breakpoint target is not executable")
            line_id = f"line:{line}"
            breakpoint = session.scalar(
                select(OperatorBreakpoint).where(
                    OperatorBreakpoint.execution_id == execution_id,
                    OperatorBreakpoint.source_digest == projection.source_digest,
                    OperatorBreakpoint.line_id == line_id,
                    OperatorBreakpoint.bound_command_id.is_(None),
                )
            )
            if breakpoint is None:
                breakpoint = OperatorBreakpoint(
                    id=new_id(),
                    execution_id=execution_id,
                    source_digest=projection.source_digest,
                    line_id=line_id,
                    one_shot=one_shot,
                    enabled=True,
                    revision=1,
                    created_by=actor,
                    created_at=self._database_now(session),
                )
                session.add(breakpoint)
            elif breakpoint.one_shot != one_shot or not breakpoint.enabled:
                breakpoint.one_shot = one_shot
                breakpoint.enabled = True
                breakpoint.revision += 1
            session.flush()
            response = {
                "id": breakpoint.id,
                "execution_id": execution_id,
                "line": line,
                "line_id": line_id,
                "one_shot": breakpoint.one_shot,
                "enabled": breakpoint.enabled,
                "revision": breakpoint.revision,
                "source_digest": breakpoint.source_digest,
            }
            now = self._database_now(session)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="operator_breakpoint",
                resource_id=breakpoint.id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="breakpoint.added",
                aggregate_type="operator_breakpoint",
                aggregate_id=breakpoint.id,
                execution_id=execution_id,
                actor=actor,
                payload={
                    "line": line,
                    "one_shot": one_shot,
                    "revision": breakpoint.revision,
                    "reason": reason,
                },
                created_at=now,
            )
            session.commit()
            return response

    def delete_breakpoint(
        self,
        execution_id: str,
        line: int,
        *,
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        if type(line) is not int or line < 1:
            raise OperatorValidationError("breakpoint line is invalid")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        request_digest = canonical_digest(
            {
                "operation": "REMOVE",
                "execution_id": execution_id,
                "line": line,
                "expected_execution_revision": expected_execution_revision,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
        )
        scope = f"breakpoint-remove:{execution_id}:{line}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            projection, _lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id)
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            breakpoint = session.scalar(
                select(OperatorBreakpoint).where(
                    OperatorBreakpoint.execution_id == execution_id,
                    OperatorBreakpoint.source_digest == projection.source_digest,
                    OperatorBreakpoint.line_id == f"line:{line}",
                    OperatorBreakpoint.bound_command_id.is_(None),
                )
            )
            response = {"removed": breakpoint is not None, "line": line}
            resource_id = breakpoint.id if breakpoint is not None else execution_id
            if breakpoint is not None:
                session.delete(breakpoint)
            now = self._database_now(session)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="operator_breakpoint",
                resource_id=resource_id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="breakpoint.removed",
                aggregate_type="operator_breakpoint",
                aggregate_id=resource_id,
                execution_id=execution_id,
                actor=actor,
                payload={"line": line, "removed": response["removed"], "reason": reason},
                created_at=now,
            )
            session.commit()
            return response

    def remove_all_breakpoints(
        self,
        execution_id: str,
        *,
        expected_execution_revision: int,
        actor: str,
        lease_id: str,
        expected_lease_revision: int,
        control_fencing_token: int,
        holder_session_id: str,
        client_instance_key_id: str,
        idempotency_key: str,
        reason: str,
    ) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        actor = _bounded(actor, "actor")
        idempotency_key = _idempotency_key(idempotency_key)
        reason = _bounded(reason, "reason", 1000)
        request_digest = canonical_digest(
            {
                "operation": "REMOVE_ALL",
                "execution_id": execution_id,
                "expected_execution_revision": expected_execution_revision,
                "lease_id": lease_id,
                "expected_lease_revision": expected_lease_revision,
                "control_fencing_token": control_fencing_token,
                "holder_session_id": holder_session_id,
                "client_instance_key_id": client_instance_key_id,
                "reason": reason,
            }
        )
        scope = f"breakpoint-remove-all:{execution_id}"
        with self._lock, self.session_factory() as session:
            replay = self._request_replay(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay
            projection, _lease = self._require_control_in_session(
                session,
                execution_id,
                actor,
                _identifier(holder_session_id, "holder_session_id"),
                _identifier(client_instance_key_id, "client_instance_key_id"),
                _identifier(lease_id, "lease_id"),
                expected_lease_revision,
                control_fencing_token,
            )
            execution = session.get(Execution, execution_id)
            if execution is None or execution.revision != expected_execution_revision:
                raise OperatorConflictError("execution revision conflict")
            rows = session.scalars(
                select(OperatorBreakpoint).where(
                    OperatorBreakpoint.execution_id == execution_id,
                    OperatorBreakpoint.source_digest == projection.source_digest,
                    OperatorBreakpoint.bound_command_id.is_(None),
                )
            ).all()
            removed = len(rows)
            for row in rows:
                session.delete(row)
            response = {"removed": removed}
            now = self._database_now(session)
            self._store_request(
                session,
                scope=scope,
                actor=actor,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_type="operator_breakpoint_set",
                resource_id=execution_id,
                response=response,
                created_at=now,
            )
            self._audit(
                session,
                event_type="breakpoint.removed_all",
                aggregate_type="execution",
                aggregate_id=execution_id,
                execution_id=execution_id,
                actor=actor,
                payload={"removed": removed, "reason": reason},
                created_at=now,
            )
            session.commit()
            return response

    def list_breakpoints(self, execution_id: str) -> list[dict[str, Any]]:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            rows = session.scalars(
                select(OperatorBreakpoint)
                .where(
                    OperatorBreakpoint.execution_id == execution_id,
                    OperatorBreakpoint.enabled.is_(True),
                )
                .order_by(
                    OperatorBreakpoint.line_id,
                    OperatorBreakpoint.bound_command_id.is_(None),
                )
            ).all()
            return [
                {
                    "id": row.id,
                    "execution_id": row.execution_id,
                    "line": int(row.line_id.removeprefix("line:")),
                    "line_id": row.line_id,
                    "bound_command_id": row.bound_command_id,
                    "one_shot": row.one_shot,
                    "enabled": row.enabled,
                    "revision": row.revision,
                    "source_digest": row.source_digest,
                }
                for row in rows
            ]

    def consume_breakpoint(
        self,
        execution_id: str,
        line: int,
        source_digest: str,
        *,
        worker_generation: int | None = None,
    ) -> dict[str, Any] | None:
        execution_id = _identifier(execution_id, "execution_id")
        if type(line) is not int or line < 1:
            raise OperatorValidationError("breakpoint line is invalid")
        if not _LOWER_HEX_64.fullmatch(source_digest):
            raise OperatorValidationError("breakpoint source_digest is invalid")
        with self._lock, self.session_factory() as session:
            self._require_worker_epoch(
                session, execution_id, worker_generation
            )
            breakpoint = session.scalar(
                select(OperatorBreakpoint)
                .where(
                    OperatorBreakpoint.execution_id == execution_id,
                    OperatorBreakpoint.source_digest == source_digest,
                    OperatorBreakpoint.line_id == f"line:{line}",
                    OperatorBreakpoint.enabled.is_(True),
                )
                .order_by(OperatorBreakpoint.bound_command_id.is_(None))
                .with_for_update()
            )
            if breakpoint is None:
                return None
            response = {
                "id": breakpoint.id,
                "execution_id": execution_id,
                "line": line,
                "line_id": breakpoint.line_id,
                "bound_command_id": breakpoint.bound_command_id,
                "one_shot": breakpoint.one_shot,
                "enabled": breakpoint.enabled,
                "revision": breakpoint.revision,
                "source_digest": breakpoint.source_digest,
            }
            now = self._database_now(session)
            self._audit(
                session,
                event_type="breakpoint.consumed",
                aggregate_type="operator_breakpoint",
                aggregate_id=breakpoint.id,
                execution_id=execution_id,
                actor="operator-runtime",
                payload={"line": line, "one_shot": breakpoint.one_shot},
                created_at=now,
            )
            if breakpoint.one_shot:
                session.delete(breakpoint)
            session.commit()
            return response

    @classmethod
    def redact_for_report(cls, value: Any, path: str = "") -> Any:
        proof_keys = {
            "accepted_fencing_token",
            "accepted_lease_id",
            "client_instance_key_id",
            "control_fencing_token",
            "controller_lease_id",
            "fencing_token",
            "holder_session_id",
            "idempotency_key",
            "lease_id",
            "requester_client_instance_key_id",
            "requester_session_id",
            "session_id",
        }

        def redact_proofs(item: Any) -> Any:
            if isinstance(item, dict):
                return {
                    str(key): redact_proofs(child)
                    for key, child in item.items()
                    if str(key).lower() not in proof_keys
                }
            if isinstance(item, list):
                return [redact_proofs(child) for child in item]
            return item

        return cls._redact_literal(
            redact_proofs(value), path=path, marker="[REDACTED]"
        )[0]

    def report_projection(self, execution_id: str) -> dict[str, Any]:
        execution_id = _identifier(execution_id, "execution_id")
        with self.session_factory() as session:
            projection = session.get(ExecutionOperatorState, execution_id)
            leases = session.scalars(
                select(ControllerLease)
                .where(ControllerLease.execution_id == execution_id)
                .order_by(ControllerLease.issued_at)
            ).all()
            commands = session.scalars(
                select(OperatorCommand)
                .where(OperatorCommand.execution_id == execution_id)
                .order_by(OperatorCommand.created_at)
            ).all()
            prompts = session.scalars(
                select(OperatorPrompt)
                .where(OperatorPrompt.execution_id == execution_id)
                .order_by(OperatorPrompt.created_at)
            ).all()
            schedules = session.scalars(
                select(ProcedureSchedule)
                .where(ProcedureSchedule.controller_execution_id == execution_id)
                .order_by(ProcedureSchedule.created_at)
            ).all()
            actions = session.scalars(
                select(OperatorUserAction)
                .where(OperatorUserAction.execution_id == execution_id)
                .order_by(OperatorUserAction.created_at)
            ).all()
            invocations = session.scalars(
                select(OperatorUserActionInvocation)
                .where(OperatorUserActionInvocation.execution_id == execution_id)
                .order_by(OperatorUserActionInvocation.created_at)
            ).all()
            startprocs = session.scalars(
                select(StartProcOperation)
                .where(StartProcOperation.parent_execution_id == execution_id)
                .order_by(StartProcOperation.created_at)
            ).all()
            audits = session.scalars(
                select(OperatorAuditEvent)
                .where(OperatorAuditEvent.execution_id == execution_id)
                .order_by(OperatorAuditEvent.sequence)
            ).all()
            result = {
                "operator_projection": (
                    operator_state_dict(projection) if projection is not None else None
                ),
                "controller_leases": [lease_dict(item) for item in leases],
                "operator_commands": [command_dict(item) for item in commands],
                "typed_prompts": [prompt_dict(item) for item in prompts],
                "schedules": [schedule_dict(item) for item in schedules],
                "user_actions": [self._action_dict(item) for item in actions],
                "user_action_invocations": [
                    self._invocation_dict(item) for item in invocations
                ],
                "startproc_operations": [
                    self._startproc_dict(item) for item in startprocs
                ],
                "relationships": self.relationships(execution_id),
                "operator_audit": [
                    {
                        "sequence": item.sequence,
                        "id": item.id,
                        "event_type": item.event_type,
                        "aggregate_type": item.aggregate_type,
                        "aggregate_id": item.aggregate_id,
                        "actor": item.actor,
                        "correlation_id": item.correlation_id,
                        "payload": item.payload,
                        "created_at": item.created_at.isoformat(),
                    }
                    for item in audits
                ],
            }
            return self.redact_for_report(result)
