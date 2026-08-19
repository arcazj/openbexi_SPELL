"""Authorization-first atomic idempotency, audit, and outbox settlement."""

from __future__ import annotations

import json
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .data_domain import (
    AuthorizationContext,
    DataAuthorizationError,
    DataCapacityError,
    DataConflictError,
    DataCorruptionError,
    DataNotFoundError,
    DataValidationError,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    actor_principal_id,
    caller_binding_digest,
    canonical_json_bytes,
    require_expected_revision,
    require_identifier,
    require_positive_revision,
    sha256_digest,
)
from .data_models import DataAuditOutbox, DataMutationIdempotency
from .database import begin_mutation_write


MAX_IDEMPOTENCY_KEY_BYTES = 128
MAX_SETTLEMENT_RECORDS = 100_000
MAX_AUDIT_RECORDS = 1_000_000
MAX_OUTBOX_RECORDS = 1_000_000
MAX_RESULT_BYTES = 1_048_576
_OPERATION = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")


class IdempotencyConflictError(DataConflictError):
    code = "IDEMPOTENCY_CONFLICT"


class EvidenceCorruptionError(DataCorruptionError):
    code = "EVIDENCE_CORRUPT"


class MutationBusyError(DataConflictError):
    """The bounded database writer/lock wait expired before admission."""


class MutationSerializationError(DataConflictError):
    """The backend rejected a serialization/deadlock race for bounded retry."""


class _ConcurrentSettlement(RuntimeError):
    pass


_POSTGRES_RETRYABLE_SQLSTATES = frozenset({"40001", "40P01", "55P03"})
_SQLITE_BUSY_CODES = frozenset({5, 6})


def _translated_transaction_error(error: BaseException) -> DataConflictError | None:
    if not isinstance(error, DBAPIError):
        return None
    original = error.orig
    sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
    if sqlstate in _POSTGRES_RETRYABLE_SQLSTATES:
        return MutationSerializationError(
            "database serialization conflict; retry with the same idempotency identity"
        )
    sqlite_code = getattr(original, "sqlite_errorcode", None)
    message = str(original).lower()
    if sqlite_code in _SQLITE_BUSY_CODES or (
        "database" in message and ("locked" in message or "busy" in message)
    ):
        return MutationBusyError(
            "database writer is busy; retry with the same idempotency identity"
        )
    return None


def _idempotency_key(value: Any) -> str:
    if type(value) is not str:
        raise DataValidationError("idempotency_key must be ASCII text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DataValidationError("idempotency_key must be ASCII") from exc
    if (
        not 1 <= len(encoded) <= MAX_IDEMPOTENCY_KEY_BYTES
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise DataValidationError("idempotency_key is outside its bounded domain")
    return value


def _operation(value: Any) -> str:
    if type(value) is not str or _OPERATION.fullmatch(value) is None:
        raise DataValidationError("mutation operation is invalid")
    return value


def _json_clone(value: Any, maximum_bytes: int, label: str) -> tuple[Any, bytes]:
    raw = canonical_json_bytes(value)
    if len(raw) > maximum_bytes:
        raise DataValidationError(f"{label} exceeds {maximum_bytes} bytes")
    return json.loads(raw.decode("utf-8")), raw


@dataclass(frozen=True, slots=True)
class MutationRequest:
    authorization: AuthorizationContext
    resource_family: ResourceFamily
    operation: str
    owner_id: str
    resource_id: str
    acl_revision: int | None
    expected_revision: int
    idempotency_key: str
    body: Any
    body_digest: str
    resource_identity_digest: str
    request_digest: str

    @classmethod
    def build(
        cls,
        authorization: AuthorizationContext,
        resource_family: ResourceFamily,
        operation: str,
        *,
        owner_id: str,
        resource_id: str,
        acl_revision: int | None,
        expected_revision: int,
        idempotency_key: str,
        body: Any,
    ) -> "MutationRequest":
        if type(authorization) is not AuthorizationContext:
            raise DataValidationError("authorization context is invalid")
        if type(resource_family) is not ResourceFamily:
            raise DataValidationError("resource family is invalid")
        operation = _operation(operation)
        owner_id = require_identifier(owner_id, "owner_id")
        resource_id = require_identifier(resource_id, "resource_id")
        if acl_revision is not None:
            acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_expected_revision(expected_revision)
        idempotency_key = _idempotency_key(idempotency_key)
        caller = authorization.caller
        if (
            type(caller) is ProcedureCallerBinding
            and idempotency_key != caller.deterministic_request_id
        ):
            raise DataValidationError(
                "procedure idempotency key must equal deterministic_request_id"
            )
        body, body_bytes = _json_clone(body, MAX_RESULT_BYTES, "mutation body")
        body_digest = sha256_digest(body_bytes)
        resource_payload = {
            "owner_id": owner_id,
            "resource_family": resource_family.value,
            "resource_id": resource_id,
        }
        resource_digest = sha256_digest(canonical_json_bytes(resource_payload))
        recovery_binding = (
            {
                "deterministic_request_id": caller.deterministic_request_id,
                "execution_id": caller.execution_id,
                "service_principal_id": caller.service_principal_id,
            }
            if type(caller) is ProcedureCallerBinding
            else None
        )
        request_digest = sha256_digest(
            canonical_json_bytes(
                {
                    "body_digest": body_digest,
                    "expected_revision": expected_revision,
                    "operation": operation,
                    "procedure_recovery_binding": recovery_binding,
                    "resource_identity_digest": resource_digest,
                }
            )
        )
        return cls(
            authorization=authorization,
            resource_family=resource_family,
            operation=operation,
            owner_id=owner_id,
            resource_id=resource_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body=body,
            body_digest=body_digest,
            resource_identity_digest=resource_digest,
            request_digest=request_digest,
        )

    @property
    def caller_binding_digest(self) -> str:
        return caller_binding_digest(self.authorization.caller)

    @property
    def actor_principal_id(self) -> str:
        return actor_principal_id(self.authorization.caller)

    @property
    def caller_binding_kind(self) -> str:
        if type(self.authorization.caller) is HTTPCallerBinding:
            return "HTTP_MUTATION"
        if type(self.authorization.caller) is ProcedureCallerBinding:
            return "PROCEDURE_RUNTIME"
        raise DataValidationError("caller binding is invalid")


@dataclass(frozen=True, slots=True)
class MutationEffect:
    result: Mapping[str, Any]
    prior_revision: int | None
    new_revision: int | None
    outcome: str
    response_status: int = 200

    def __post_init__(self) -> None:
        if not isinstance(self.result, Mapping):
            raise DataValidationError("mutation result must be an object")
        if self.prior_revision is not None:
            require_expected_revision(self.prior_revision, "prior_revision")
        if self.new_revision is not None:
            require_positive_revision(self.new_revision, "new_revision")
        _operation(self.outcome)
        if type(self.response_status) is not int or not 100 <= self.response_status <= 599:
            raise DataValidationError("response_status is invalid")


@dataclass(frozen=True, slots=True)
class MutationResult:
    operation_id: str
    result: dict[str, Any]
    outcome: str
    response_status: int
    prior_revision: int | None
    new_revision: int | None
    replayed: bool


AuthorizationCheck = Callable[[Session, MutationRequest], None]
MutationCallback = Callable[[Session, MutationRequest], MutationEffect]
ProcedureBindingCheck = Callable[[Session, ProcedureCallerBinding], None]
SchemaCheck = Callable[[Session], None]
DeadlineCheck = Callable[[], None]


class DataMutationCoordinator:
    """Settle one mutation and its evidence in the same database transaction."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        maximum_settlements: int = MAX_SETTLEMENT_RECORDS,
        maximum_audit_records: int = MAX_AUDIT_RECORDS,
        maximum_outbox_records: int = MAX_OUTBOX_RECORDS,
        procedure_binding_check: ProcedureBindingCheck | None = None,
        schema_check: SchemaCheck | None = None,
    ) -> None:
        self.session_factory = session_factory
        for value, label in (
            (maximum_settlements, "maximum_settlements"),
            (maximum_audit_records, "maximum_audit_records"),
            (maximum_outbox_records, "maximum_outbox_records"),
        ):
            if type(value) is not int or value < 1:
                raise DataValidationError(f"{label} must be a positive integer")
        self.maximum_settlements = maximum_settlements
        self.maximum_audit_records = maximum_audit_records
        self.maximum_outbox_records = maximum_outbox_records
        self.procedure_binding_check = procedure_binding_check
        self.schema_check = schema_check
        self._lock = threading.RLock()

    def execute(
        self,
        request: MutationRequest,
        mutate: MutationCallback,
        *,
        authorization_check: AuthorizationCheck | None = None,
        deadline_check: DeadlineCheck | None = None,
    ) -> MutationResult:
        if (
            type(request) is not MutationRequest
            or not callable(mutate)
            or (deadline_check is not None and not callable(deadline_check))
        ):
            raise DataValidationError("mutation request or callback is invalid")
        try:
            self._check_deadline(deadline_check)
            # The trusted context check precedes every durable settlement lookup,
            # including replay. The optional callback repeats ACL checks under lock.
            self._authorize(request)
            with self._lock, self.session_factory() as session:
                begin_mutation_write(session)
                try:
                    return self._execute_in_session(
                        session,
                        request,
                        mutate,
                        authorization_check=authorization_check,
                        deadline_check=deadline_check,
                    )
                except _ConcurrentSettlement:
                    session.rollback()
            # A concurrent unique-key winner may have committed. Reauthorize in a
            # fresh transaction before observing or replaying its settlement.
            self._authorize(request)
            with self._lock, self.session_factory() as session:
                self._check_deadline(deadline_check)
                begin_mutation_write(session)
                self._authorize_inside_transaction(
                    session, request, authorization_check
                )
                self._check_deadline(deadline_check)
                existing = self._find_settlement(session, request, lock=True)
                if existing is None:
                    raise DataConflictError("concurrent mutation did not settle")
                result = self._replay(existing, request)
                self._check_deadline(deadline_check)
                session.commit()
                return result
        except Exception as exc:
            translated = _translated_transaction_error(exc)
            if translated is not None:
                raise translated from exc
            raise

    def recover_procedure_settlement(
        self,
        original_request: MutationRequest,
        current_binding: ProcedureCallerBinding,
    ) -> MutationResult:
        """Recover one exact committed result without admitting another mutation."""

        if type(original_request) is not MutationRequest:
            raise DataValidationError("original mutation request is invalid")
        original_binding = original_request.authorization.caller
        if (
            type(original_binding) is not ProcedureCallerBinding
            or type(current_binding) is not ProcedureCallerBinding
        ):
            raise DataValidationError("procedure settlement recovery bindings are invalid")
        if (
            current_binding.service_principal_id
            != original_binding.service_principal_id
            or current_binding.execution_id != original_binding.execution_id
            or current_binding.deterministic_request_id
            != original_binding.deterministic_request_id
            or current_binding.worker_generation < original_binding.worker_generation
        ):
            raise DataAuthorizationError("procedure settlement recovery lineage differs")
        if self.procedure_binding_check is None:
            raise DataAuthorizationError(
                "procedure settlement recovery requires generation authorization"
            )
        self._authorize(original_request)
        try:
            with self._lock, self.session_factory() as session:
                begin_mutation_write(session)
                if self.schema_check is not None:
                    self.schema_check(session)
                self.procedure_binding_check(session, current_binding)
                settlement = self._find_settlement(
                    session, original_request, lock=True
                )
                if settlement is None:
                    raise DataNotFoundError(
                        "original committed procedure settlement is unavailable"
                    )
                result = self._replay(settlement, original_request)
                self._verify_recovery_audit(session, original_request, result)
                session.commit()
                return result
        except Exception as exc:
            translated = _translated_transaction_error(exc)
            if translated is not None:
                raise translated from exc
            raise

    def recover_procedure_settlement_identity(
        self,
        original_binding: ProcedureCallerBinding,
        current_binding: ProcedureCallerBinding,
        *,
        resource_family: ResourceFamily,
        operations: tuple[str, ...],
    ) -> MutationResult:
        """Recover the one settlement bound to an admitted procedure request.

        This lookup never invokes a mutation callback. The exact original binding
        and deterministic request identity select the row; the caller-provided
        family and operation allowlist are then checked against its paired audit.
        """

        if (
            type(original_binding) is not ProcedureCallerBinding
            or type(current_binding) is not ProcedureCallerBinding
            or type(resource_family) is not ResourceFamily
            or type(operations) is not tuple
            or not operations
        ):
            raise DataValidationError("procedure settlement recovery identity is invalid")
        allowed_operations = tuple(sorted({_operation(value) for value in operations}))
        self._validate_recovery_lineage(original_binding, current_binding)
        if self.procedure_binding_check is None:
            raise DataAuthorizationError(
                "procedure settlement recovery requires generation authorization"
            )
        original_digest = caller_binding_digest(original_binding)
        try:
            with self._lock, self.session_factory() as session:
                begin_mutation_write(session)
                if self.schema_check is not None:
                    self.schema_check(session)
                self.procedure_binding_check(session, current_binding)
                rows = session.scalars(
                    select(DataMutationIdempotency)
                    .where(
                        DataMutationIdempotency.actor_principal_id
                        == actor_principal_id(original_binding),
                        DataMutationIdempotency.caller_binding_kind
                        == "PROCEDURE_RUNTIME",
                        DataMutationIdempotency.caller_binding_digest
                        == original_digest,
                        DataMutationIdempotency.idempotency_key
                        == original_binding.deterministic_request_id,
                        DataMutationIdempotency.operation.in_(allowed_operations),
                    )
                    .with_for_update()
                ).all()
                if not rows:
                    raise DataNotFoundError(
                        "original committed procedure settlement is unavailable"
                    )
                if len(rows) != 1:
                    raise EvidenceCorruptionError(
                        "procedure settlement recovery identity is ambiguous"
                    )
                settlement = rows[0]
                result = self._decode_settlement(settlement)
                self._verify_identity_recovery_audit(
                    session,
                    original_binding,
                    resource_family,
                    settlement,
                    result,
                )
                session.commit()
                return result
        except Exception as exc:
            translated = _translated_transaction_error(exc)
            if translated is not None:
                raise translated from exc
            raise

    @staticmethod
    def _validate_recovery_lineage(
        original_binding: ProcedureCallerBinding,
        current_binding: ProcedureCallerBinding,
    ) -> None:
        if (
            current_binding.service_principal_id
            != original_binding.service_principal_id
            or current_binding.execution_id != original_binding.execution_id
            or current_binding.deterministic_request_id
            != original_binding.deterministic_request_id
            or current_binding.worker_generation < original_binding.worker_generation
        ):
            raise DataAuthorizationError("procedure settlement recovery lineage differs")

    @staticmethod
    def _check_deadline(deadline_check: DeadlineCheck | None) -> None:
        if deadline_check is not None:
            deadline_check()

    @staticmethod
    def _authorize(request: MutationRequest) -> None:
        request.authorization.require(
            request.resource_family,
            request.operation,
            owner_id=request.owner_id,
            resource_id=request.resource_id,
            acl_revision=request.acl_revision,
        )

    def _execute_in_session(
        self,
        session: Session,
        request: MutationRequest,
        mutate: MutationCallback,
        *,
        authorization_check: AuthorizationCheck | None,
        deadline_check: DeadlineCheck | None,
    ) -> MutationResult:
        try:
            self._check_deadline(deadline_check)
            self._authorize_inside_transaction(
                session, request, authorization_check
            )
            self._check_deadline(deadline_check)
            existing = self._find_settlement(session, request, lock=True)
            if existing is not None:
                result = self._replay(existing, request)
                self._check_deadline(deadline_check)
                session.commit()
                return result
            self._require_capacity(session)
            self._check_deadline(deadline_check)
            settlement_id = str(uuid.uuid4())
            settlement = DataMutationIdempotency(
                settlement_id=settlement_id,
                actor_principal_id=request.actor_principal_id,
                caller_binding_kind=request.caller_binding_kind,
                caller_binding_digest=request.caller_binding_digest,
                operation=request.operation,
                resource_identity_digest=request.resource_identity_digest,
                idempotency_key=request.idempotency_key,
                request_digest=request.request_digest,
                state="PENDING",
                response_status=None,
                result_payload=None,
                result_payload_sha256=None,
            )
            session.add(settlement)
            try:
                session.flush()
            except IntegrityError as exc:
                raise _ConcurrentSettlement from exc

            effect = mutate(session, request)
            if type(effect) is not MutationEffect:
                raise DataValidationError("mutation callback returned an invalid effect")
            self._check_deadline(deadline_check)
            result_payload, result_bytes = _json_clone(
                dict(effect.result), MAX_RESULT_BYTES, "mutation result"
            )
            now = self._database_now(session)
            operation_id = str(uuid.uuid4())
            event_id = str(uuid.uuid4())
            caller = request.authorization.caller
            request_session = caller.session_id if type(caller) is HTTPCallerBinding else None
            client_instance = (
                caller.client_instance_key_id
                if type(caller) is HTTPCallerBinding
                else None
            )
            audit_payload = canonical_json_bytes(
                {
                    "event_id": event_id,
                    "operation_id": operation_id,
                    "outcome": effect.outcome,
                    "response_status": effect.response_status,
                    "result_digest": sha256_digest(result_bytes),
                    "schema_version": "spell.data.audit-outbox/1",
                }
            )
            audit = DataAuditOutbox(
                event_id=event_id,
                operation_id=operation_id,
                actor_principal_id=request.actor_principal_id,
                request_session_binding=request_session,
                client_instance_key_binding=client_instance,
                caller_binding_digest=request.caller_binding_digest,
                resource_family=request.resource_family.value,
                resource_identity_digest=request.resource_identity_digest,
                operation=request.operation,
                request_digest=request.request_digest,
                prior_revision=effect.prior_revision,
                new_revision=effect.new_revision,
                outcome=effect.outcome,
                payload=audit_payload,
                payload_sha256=sha256_digest(audit_payload),
                delivery_attempts=0,
                created_at_database_time=now,
                published_at_database_time=None,
            )
            session.add(audit)
            settlement.state = "COMMITTED"
            settlement.response_status = effect.response_status
            settlement_payload = canonical_json_bytes(
                {
                    "new_revision": effect.new_revision,
                    "operation_id": operation_id,
                    "outcome": effect.outcome,
                    "prior_revision": effect.prior_revision,
                    "result": result_payload,
                }
            )
            if len(settlement_payload) > MAX_RESULT_BYTES:
                raise DataValidationError("mutation settlement exceeds its byte limit")
            settlement.result_payload = settlement_payload
            settlement.result_payload_sha256 = sha256_digest(settlement_payload)
            settlement.committed_at_database_time = now
            session.flush()
            self._check_deadline(deadline_check)
            session.commit()
            return MutationResult(
                operation_id=operation_id,
                result=result_payload,
                outcome=effect.outcome,
                response_status=effect.response_status,
                prior_revision=effect.prior_revision,
                new_revision=effect.new_revision,
                replayed=False,
            )
        except Exception:
            session.rollback()
            raise

    @staticmethod
    def _database_now(session: Session) -> datetime:
        value = session.execute(select(func.current_timestamp())).scalar_one()
        if type(value) is not datetime:
            raise EvidenceCorruptionError("database clock returned an invalid value")
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _authorize_inside_transaction(
        self,
        session: Session,
        request: MutationRequest,
        authorization_check: AuthorizationCheck | None,
    ) -> None:
        if self.schema_check is not None:
            self.schema_check(session)
        caller = request.authorization.caller
        if type(caller) is ProcedureCallerBinding:
            if self.procedure_binding_check is None:
                raise DataValidationError(
                    "procedure mutation requires an admitted-generation authorizer"
                )
            self.procedure_binding_check(session, caller)
        if authorization_check is not None:
            authorization_check(session, request)

    @staticmethod
    def _find_settlement(
        session: Session,
        request: MutationRequest,
        *,
        lock: bool,
    ) -> DataMutationIdempotency | None:
        conditions = [
            DataMutationIdempotency.actor_principal_id == request.actor_principal_id,
            DataMutationIdempotency.caller_binding_kind
            == request.caller_binding_kind,
            DataMutationIdempotency.operation == request.operation,
            DataMutationIdempotency.resource_identity_digest
            == request.resource_identity_digest,
            DataMutationIdempotency.idempotency_key == request.idempotency_key,
            DataMutationIdempotency.caller_binding_digest
            == request.caller_binding_digest,
        ]
        query = select(DataMutationIdempotency).where(*conditions)
        if lock:
            query = query.with_for_update()
        rows = session.scalars(query).all()
        if len(rows) > 1:
            raise EvidenceCorruptionError("idempotency recovery identity is ambiguous")
        return rows[0] if rows else None

    def _require_capacity(self, session: Session) -> None:
        settlement_count = session.scalar(
            select(func.count()).select_from(DataMutationIdempotency)
        )
        audit_count = session.scalar(select(func.count()).select_from(DataAuditOutbox))
        if (
            type(settlement_count) is not int
            or type(audit_count) is not int
            or settlement_count < 0
            or audit_count < 0
        ):
            raise EvidenceCorruptionError("mutation evidence cardinality is invalid")
        if settlement_count >= self.maximum_settlements:
            raise DataCapacityError("idempotency settlement capacity is exhausted")
        if (
            audit_count >= self.maximum_audit_records
            or audit_count >= self.maximum_outbox_records
        ):
            raise DataCapacityError("audit-outbox capacity is exhausted")

    @staticmethod
    def _verify_recovery_audit(
        session: Session,
        request: MutationRequest,
        result: MutationResult,
    ) -> None:
        rows = session.scalars(
            select(DataAuditOutbox)
            .where(DataAuditOutbox.operation_id == result.operation_id)
            .with_for_update()
        ).all()
        if len(rows) != 1:
            raise EvidenceCorruptionError(
                "procedure settlement audit identity is missing or ambiguous"
            )
        audit = rows[0]
        if (
            audit.actor_principal_id != request.actor_principal_id
            or audit.caller_binding_digest != request.caller_binding_digest
            or audit.resource_family != request.resource_family.value
            or audit.resource_identity_digest != request.resource_identity_digest
            or audit.operation != request.operation
            or audit.request_digest != request.request_digest
            or audit.prior_revision != result.prior_revision
            or audit.new_revision != result.new_revision
            or audit.outcome != result.outcome
            or type(audit.payload) is not bytes
            or type(audit.payload_sha256) is not str
            or sha256_digest(audit.payload) != audit.payload_sha256
        ):
            raise EvidenceCorruptionError("procedure settlement audit evidence differs")
        try:
            payload = json.loads(audit.payload.decode("utf-8"))
            if canonical_json_bytes(payload) != audit.payload:
                raise EvidenceCorruptionError(
                    "procedure settlement audit payload is not canonical"
                )
        except (UnicodeDecodeError, json.JSONDecodeError, DataValidationError) as exc:
            raise EvidenceCorruptionError(
                "procedure settlement audit payload is invalid JSON"
            ) from exc
        expected_payload = {
            "event_id": audit.event_id,
            "operation_id": result.operation_id,
            "outcome": result.outcome,
            "response_status": result.response_status,
            "result_digest": sha256_digest(canonical_json_bytes(result.result)),
            "schema_version": "spell.data.audit-outbox/1",
        }
        if payload != expected_payload:
            raise EvidenceCorruptionError("procedure settlement audit payload differs")

    @staticmethod
    def _verify_identity_recovery_audit(
        session: Session,
        original_binding: ProcedureCallerBinding,
        resource_family: ResourceFamily,
        settlement: DataMutationIdempotency,
        result: MutationResult,
    ) -> None:
        rows = session.scalars(
            select(DataAuditOutbox)
            .where(DataAuditOutbox.operation_id == result.operation_id)
            .with_for_update()
        ).all()
        if len(rows) != 1:
            raise EvidenceCorruptionError(
                "procedure settlement audit identity is missing or ambiguous"
            )
        audit = rows[0]
        if (
            settlement.actor_principal_id != actor_principal_id(original_binding)
            or settlement.caller_binding_kind != "PROCEDURE_RUNTIME"
            or settlement.caller_binding_digest != caller_binding_digest(original_binding)
            or settlement.idempotency_key
            != original_binding.deterministic_request_id
            or audit.actor_principal_id != settlement.actor_principal_id
            or audit.caller_binding_digest != settlement.caller_binding_digest
            or audit.resource_family != resource_family.value
            or audit.resource_identity_digest
            != settlement.resource_identity_digest
            or audit.operation != settlement.operation
            or audit.request_digest != settlement.request_digest
            or audit.prior_revision != result.prior_revision
            or audit.new_revision != result.new_revision
            or audit.outcome != result.outcome
            or type(audit.payload) is not bytes
            or type(audit.payload_sha256) is not str
            or sha256_digest(audit.payload) != audit.payload_sha256
        ):
            raise EvidenceCorruptionError("procedure settlement audit evidence differs")
        try:
            payload = json.loads(audit.payload.decode("utf-8"))
            if canonical_json_bytes(payload) != audit.payload:
                raise EvidenceCorruptionError(
                    "procedure settlement audit payload is not canonical"
                )
        except (UnicodeDecodeError, json.JSONDecodeError, DataValidationError) as exc:
            raise EvidenceCorruptionError(
                "procedure settlement audit payload is invalid JSON"
            ) from exc
        if payload != {
            "event_id": audit.event_id,
            "operation_id": result.operation_id,
            "outcome": result.outcome,
            "response_status": result.response_status,
            "result_digest": sha256_digest(canonical_json_bytes(result.result)),
            "schema_version": "spell.data.audit-outbox/1",
        }:
            raise EvidenceCorruptionError("procedure settlement audit payload differs")

    @staticmethod
    def _replay(
        settlement: DataMutationIdempotency,
        request: MutationRequest,
    ) -> MutationResult:
        if settlement.request_digest != request.request_digest:
            raise IdempotencyConflictError(
                "idempotency identity was used for different request bytes"
            )
        return DataMutationCoordinator._decode_settlement(settlement)

    @staticmethod
    def _decode_settlement(
        settlement: DataMutationIdempotency,
    ) -> MutationResult:
        if (
            settlement.state != "COMMITTED"
            or settlement.response_status is None
            or type(settlement.result_payload) is not bytes
            or type(settlement.result_payload_sha256) is not str
        ):
            raise EvidenceCorruptionError("idempotency settlement is not committed")
        raw = settlement.result_payload
        if sha256_digest(raw) != settlement.result_payload_sha256:
            raise EvidenceCorruptionError("idempotency settlement digest differs")
        try:
            payload = json.loads(raw.decode("utf-8"))
            if canonical_json_bytes(payload) != raw:
                raise EvidenceCorruptionError(
                    "idempotency settlement is not canonical"
                )
        except (UnicodeDecodeError, json.JSONDecodeError, DataValidationError) as exc:
            raise EvidenceCorruptionError("idempotency settlement is invalid JSON") from exc
        expected_fields = {
            "new_revision",
            "operation_id",
            "outcome",
            "prior_revision",
            "result",
        }
        if set(payload) != expected_fields or type(payload["result"]) is not dict:
            raise EvidenceCorruptionError("idempotency settlement payload is invalid")
        result_payload, _ = _json_clone(
            payload["result"], MAX_RESULT_BYTES, "settled mutation result"
        )
        return MutationResult(
            operation_id=payload["operation_id"],
            result=result_payload,
            outcome=payload["outcome"],
            response_status=settlement.response_status,
            prior_revision=payload["prior_revision"],
            new_revision=payload["new_revision"],
            replayed=True,
        )


__all__ = [
    "AuthorizationCheck",
    "DataMutationCoordinator",
    "DeadlineCheck",
    "EvidenceCorruptionError",
    "IdempotencyConflictError",
    "MutationCallback",
    "MutationBusyError",
    "MutationEffect",
    "MutationRequest",
    "MutationResult",
    "MutationSerializationError",
    "ProcedureBindingCheck",
    "SchemaCheck",
]
