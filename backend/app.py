import asyncio
import hashlib
import json
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path as PathParam,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import select

from .auth import AuthConfig, AuthenticationError, authenticate_bearer, decode_token
from .config import Settings
from .bundled_observation_catalog import CATALOG_ITEMS, POLICY_ID, POLICY_REVISION
from .condition_engine import (
    ConditionContractError,
    ConditionPlan,
    QualityFreshnessPolicy,
)
from .condition_runtime import (
    CommittedObservationSnapshotProvider,
    ConditionProcedureRuntime,
    ConditionRecoveryLoop,
    DurableExecutionCancellationProbe,
    DurableOperationContextResolver,
    OccurrenceBoundExecutionStarter,
    RepositoryGetTMResolver,
)
from .condition_service import (
    ConditionService,
    ConditionServiceConflictError,
    ConditionServiceError,
    ConditionServiceNotFoundError,
    ConditionServiceValidationError,
)
from .database import create_database
from .driver_repository import (
    DriverNotFoundError,
    DriverRepository,
    DriverValidationError,
    MAX_DRIVER_EVENT_REPLAY,
    MAX_DRIVER_EVENT_SEQUENCE,
)
from .driver_gateway import DriverGateway
from .events import EventHub
from .migrations import run_migrations
from .models import Command, Event, Execution, Prompt
from .observation_repository import (
    MAX_OBSERVATION_REPLAY,
    MAX_OBSERVATION_SEQUENCE,
    OBSERVATION_EVENT_SCHEMA,
    OBSERVATION_STREAM,
    ObservationConflictError,
    ObservationNotFoundError,
    ObservationRepository,
    ObservationRepositoryError,
    ObservationStaleGenerationError,
    ObservationValidationError,
)
from .observation_read_service import ObservationReadService
from .observation_service import ObservationRuntime
from .operator_service import (
    OperatorAuthorizationError,
    OperatorConflictError,
    OperatorNotFoundError,
    OperatorService,
    OperatorValidationError,
)
from .procedure_parser import (
    IR_VERSION,
    Procedure,
    ProcedureCatalog,
    ProcedureValidationError,
)
from .schemas import (
    CommandCreate,
    BreakpointMutationCreate,
    ConsoleOperationCreate,
    ContextSettingsUpdate,
    ControlMutationCreate,
    ExecutionCreate,
    ExecutionSettingsUpdate,
    HandoverApproveCreate,
    HandoverRequestCreate,
    InspectionEditCreate,
    MonitorSubscriptionCreate,
    OperatorCommandCreate,
    OperatorPromptResponseCreate,
    ProcedureValidationRequest,
    PromptResponseCreate,
    ScheduleCancelCreate,
    ScheduleCreate,
    TelemetryScheduleCancelCreate,
    TelemetryScheduleCreate,
    UserActionInvokeCreate,
    UserActionMutationCreate,
)
from .serialization import command_dict, event_dict, execution_dict, prompt_dict
from .supervisor import AuthorizationError, ConflictError, NotFoundError, Supervisor
from .version import PRODUCT_VERSION, REPORT_VERSION


@dataclass(frozen=True)
class Identity:
    actor: str
    role: str


@dataclass(frozen=True)
class SessionBinding:
    session_id: str | None
    client_instance_key_id: str | None


def create_app(
    settings: Optional[Settings] = None,
    auth_config: AuthConfig | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    engine, session_factory = create_database(settings.database_url)
    catalog = ProcedureCatalog(settings.procedures_dir)
    hub = EventHub(settings.websocket_queue_size)
    supervisor = Supervisor(
        session_factory,
        catalog,
        hub,
        command_ack_timeout_seconds=settings.command_ack_timeout_seconds,
    )

    def start_operator_execution(
        *,
        procedure,
        schedule: dict[str, Any] | None = None,
        startproc: dict[str, Any] | None = None,
    ) -> Execution:
        resource = schedule or startproc or {}
        if schedule is not None:
            idempotency_key = f"schedule:{schedule['occurrence_id']}"
            actor = "schedule-service"
            reason = f"Fire durable schedule {schedule['id']}"
        else:
            idempotency_key = f"startproc:{resource['id']}"
            actor = "startproc-service"
            reason = f"Admit durable StartProc {resource['id']}"
        automatic = bool(resource.get("automatic", True))
        background_allowed = bool(
            resource.get(
                "background_allowed",
                automatic if startproc is not None else False,
            )
        )
        context_id = str(resource.get("context_id", "simulator"))
        predecessor_execution_id = None
        depth = 0
        operator_settings: dict[str, Any] = {}
        catalog_revision_id = resource.get("catalog_revision_id")
        if startproc is not None:
            predecessor_execution_id = str(resource["parent_execution_id"])
            parent_projection = operator_service.get_execution_projection(
                predecessor_execution_id
            )
            context_id = str(parent_projection["context_id"])
            depth = int(resource["depth"])
            operator_settings = dict(parent_projection.get("settings") or {})
            catalog_revision_id = resource.get(
                "resolved_child_catalog_revision_id"
            )
        elif schedule is not None:
            context = next(
                (
                    item
                    for item in operator_service.list_contexts()
                    if item["id"] == context_id
                ),
                None,
            )
            operator_settings = dict((context or {}).get("settings") or {})
        kwargs = {
            "procedure": procedure,
            "actor": actor,
            "role": "operator",
            "reason": reason,
            "idempotency_key": idempotency_key,
            "context_id": context_id,
            "automatic": automatic,
            "initial_variables": dict(resource.get("arguments") or {}),
            "background_allowed": background_allowed,
            "visible": bool(resource.get("visible", True)),
            "catalog_revision_id": (
                str(catalog_revision_id)
                if catalog_revision_id is not None
                else None
            ),
            "predecessor_execution_id": predecessor_execution_id,
            "depth": depth,
            "ownership_mode": (
                "B" if automatic and background_allowed else "CONTROL_LOST"
            ),
            "operator_settings": operator_settings,
        }
        return supervisor.create_execution(**kwargs)

    operator_service = OperatorService(
        session_factory,
        catalog,
        execution_starter=start_operator_execution,
        prompt_settlement_sink=supervisor.dispatch_prompt_settlement,
    )
    supervisor.attach_operator_service(operator_service)
    driver_repository = DriverRepository(session_factory)
    driver_gateway = DriverGateway(
        driver_repository,
        settings,
        outbox_publisher=lambda _topic, event: hub.publish(
            "driver.lifecycle", event
        ),
    )
    observation_repository = ObservationRepository(session_factory)
    observation_read_service = ObservationReadService()
    observation_runtime = ObservationRuntime(
        observation_repository,
        publisher=lambda _topic, event: hub.publish(OBSERVATION_STREAM, event),
        generation_provider=driver_gateway.observation_generations,
        get_time=driver_gateway.get_time,
        get_tm=driver_gateway.get_tm,
        poll_seconds=settings.observation_poll_seconds,
        freshness_sweep_seconds=settings.observation_freshness_sweep_seconds,
    )

    def execution_context_id(execution_id: str) -> str:
        return str(supervisor.get_execution(execution_id).context_id)

    def create_or_find_condition_execution(
        *,
        occurrence_id: str,
        schedule: dict[str, Any],
        condition_evidence: dict[str, Any],
    ) -> str:
        history = operator_service.catalog_history(schedule["procedure_catalog_id"])
        entry = history["procedure"]
        revision = next(
            (
                item
                for item in history["items"]
                if item["revision"] == schedule["procedure_revision"]
            ),
            None,
        )
        if revision is None:
            raise OperatorNotFoundError("procedure catalog revision not found")
        if revision["bundle_digest"] != schedule["bundle_digest"]:
            raise OperatorConflictError("procedure bundle digest changed")
        procedure = Procedure(
            id=entry["procedure_ref"],
            name=entry["name"],
            description=entry["description"],
            path=Path(entry["entrypoint"]),
            source=revision["source"],
            sha256=revision["source_digest"],
            steps=tuple(revision["steps"]),
            ir_version=revision["ir_version"],
        )
        execution = start_operator_execution(
            procedure=procedure,
            schedule={
                **schedule,
                "id": schedule["schedule_id"],
                "occurrence_id": occurrence_id,
                "catalog_revision_id": revision["id"],
                "condition_evidence": condition_evidence,
            },
        )
        return execution.id

    operation_contexts = DurableOperationContextResolver(
        session_factory, execution_context_id
    )
    condition_snapshots = CommittedObservationSnapshotProvider(
        observation_repository,
        operation_contexts,
        expected_policy_revision=POLICY_REVISION,
    )
    condition_service = ConditionService(
        session_factory,
        snapshot_provider=condition_snapshots,
        execution_starter=OccurrenceBoundExecutionStarter(
            create_or_find_condition_execution
        ),
    )
    condition_runtime = ConditionProcedureRuntime(
        condition_service,
        policy=QualityFreshnessPolicy(POLICY_ID, POLICY_REVISION),
        get_tm_resolver=RepositoryGetTMResolver(
            observation_repository,
            execution_context_id,
            known_item_ids=frozenset(item.item_id for item in CATALOG_ITEMS),
            cancellation_probe=DurableExecutionCancellationProbe(session_factory),
        ),
    )
    condition_recovery = ConditionRecoveryLoop(condition_service)
    supervisor.observation_anchor_provider = observation_repository
    supervisor.observation_runtime = condition_runtime
    resolved_auth_config = auth_config

    def get_auth_config() -> AuthConfig:
        nonlocal resolved_auth_config
        if resolved_auth_config is None:
            resolved_auth_config = AuthConfig.from_env()
        return resolved_auth_config

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        gateway_started = False
        observation_started = False
        condition_recovery_started = False
        try:
            app.state.auth_config = get_auth_config()
            run_migrations(engine)
            operator_service.bootstrap()
            await driver_gateway.start()
            gateway_started = True
            await observation_runtime.start()
            observation_started = True
            supervisor.reconcile_orphaned_executions()
            operator_service.replay_prompt_deliveries()
            operator_service.start()
            condition_recovery.start()
            condition_recovery_started = True
            yield
        finally:
            try:
                if condition_recovery_started:
                    condition_recovery.stop()
            finally:
                try:
                    operator_service.close()
                finally:
                    try:
                        if observation_started:
                            await observation_runtime.close()
                    finally:
                        try:
                            if gateway_started:
                                await driver_gateway.close()
                        finally:
                            try:
                                supervisor.close()
                            finally:
                                engine.dispose()

    app = FastAPI(
        title="OpenBEXI SPELL Simulator API",
        version=PRODUCT_VERSION,
        description="Simulator-only restricted-language environment. Not approved for spacecraft operations.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Idempotency-Key",
            "X-Spell-Session-Id",
            "X-Spell-Client-Instance-Key-Id",
        ],
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "testserver"],
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.catalog = catalog
    app.state.supervisor = supervisor
    app.state.operator_service = operator_service
    app.state.driver_repository = driver_repository
    app.state.driver_gateway = driver_gateway
    app.state.observation_repository = observation_repository
    app.state.observation_read_service = observation_read_service
    app.state.observation_runtime = observation_runtime
    app.state.condition_service = condition_service
    app.state.condition_runtime = condition_runtime
    app.state.condition_recovery = condition_recovery
    app.state.hub = hub
    app.state.auth_config = auth_config

    @app.middleware("http")
    async def reject_ambiguous_json(request: Request, call_next):
        media_type = (
            request.headers.get("content-type", "")
            .split(";", 1)[0]
            .strip()
            .lower()
        )
        structured_json = media_type == "application/json" or (
            media_type.startswith("application/") and media_type.endswith("+json")
        )
        if (
            request.method in {"POST", "PUT", "DELETE"}
            and request.url.path.startswith("/api/v1/")
            and request.url.path != "/api/v1/procedures/validate"
            and structured_json
        ):
            maximum_body_bytes = 1_000_000
            declared_length = request.headers.get("content-length")
            if declared_length is not None:
                try:
                    if int(declared_length) > maximum_body_bytes:
                        return JSONResponse(
                            status_code=413,
                            content={"detail": "structured request body is too large"},
                        )
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "invalid Content-Length header"},
                    )
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > maximum_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "structured request body is too large"},
                    )
            raw = bytes(body)
            request._body = raw

            def object_pairs(pairs):
                result: dict[str, Any] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON object key")
                    result[key] = value
                return result

            def reject_constant(_: str):
                raise ValueError("non-finite JSON number")

            def validate_utf8(value: Any) -> None:
                if isinstance(value, str):
                    value.encode("utf-8")
                elif isinstance(value, list):
                    for child in value:
                        validate_utf8(child)
                elif isinstance(value, dict):
                    for key, child in value.items():
                        key.encode("utf-8")
                        validate_utf8(child)

            try:
                parsed = json.loads(
                    raw.decode("utf-8"),
                    object_pairs_hook=object_pairs,
                    parse_constant=reject_constant,
                )
                validate_utf8(parsed)
            except (UnicodeError, ValueError):
                return JSONResponse(
                    status_code=422,
                    content={
                        "detail": [
                            {
                                "type": "json_invalid",
                                "loc": ["body"],
                                "msg": "request body must be unambiguous finite UTF-8 JSON",
                            }
                        ]
                    },
                )
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def safe_request_validation_error(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Rejected input can contain non-UTF-8 Unicode scalars. Never echo it
        # into the response, and keep the validation contract data-only.
        errors = [
            {
                key: error[key]
                for key in ("type", "loc", "msg")
                if key in error
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    def identity(
        authorization: Annotated[Optional[str], Header()] = None,
    ) -> Identity:
        try:
            claims = authenticate_bearer(authorization, get_auth_config())
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=401,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        return Identity(actor=claims.subject, role=claims.role)

    IdentityDep = Annotated[Identity, Depends(identity)]

    def session_binding(
        x_spell_session_id: Annotated[
            Optional[str], Header(max_length=128)
        ] = None,
        x_spell_client_instance_key_id: Annotated[
            Optional[str], Header(max_length=128)
        ] = None,
    ) -> SessionBinding:
        return SessionBinding(
            session_id=x_spell_session_id,
            client_instance_key_id=x_spell_client_instance_key_id,
        )

    SessionBindingDep = Annotated[SessionBinding, Depends(session_binding)]

    def require_session_binding(
        binding: SessionBinding,
        *,
        session_id: str | None = None,
        client_instance_key_id: str | None = None,
    ) -> None:
        if not binding.session_id or not binding.client_instance_key_id:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "SESSION_BINDING_REQUIRED",
                    "message": "v0.6 requests require bound session headers",
                    "current": None,
                },
            )
        if (
            session_id is not None
            and binding.session_id != session_id
        ) or (
            client_instance_key_id is not None
            and binding.client_instance_key_id != client_instance_key_id
        ):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "SESSION_BINDING_MISMATCH",
                    "message": "request session proof does not match its headers",
                    "current": None,
                },
            )

    def mutation_identity(caller: IdentityDep) -> Identity:
        if caller.role not in {"operator", "admin"}:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN",
                    "message": "operator role required for durable mutations",
                    "current": None,
                },
            )
        return caller

    MutationIdentityDep = Annotated[Identity, Depends(mutation_identity)]

    def translate_error(exc: Exception) -> HTTPException:
        if isinstance(exc, OperatorNotFoundError):
            return HTTPException(
                status_code=404,
                detail={"code": exc.code, "message": str(exc), "current": exc.current},
            )
        if isinstance(exc, OperatorAuthorizationError):
            return HTTPException(
                status_code=403,
                detail={"code": exc.code, "message": str(exc), "current": exc.current},
            )
        if isinstance(exc, OperatorConflictError):
            return HTTPException(
                status_code=409,
                detail={"code": exc.code, "message": str(exc), "current": exc.current},
            )
        if isinstance(exc, OperatorValidationError):
            return HTTPException(
                status_code=422,
                detail={"code": exc.code, "message": str(exc), "current": exc.current},
            )
        if isinstance(exc, NotFoundError):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, AuthorizationError):
            return HTTPException(status_code=403, detail=str(exc))
        if isinstance(exc, ConflictError):
            return HTTPException(status_code=409, detail=str(exc))
        return HTTPException(status_code=500, detail="internal server error")

    def translate_condition_error(exc: Exception) -> HTTPException:
        if isinstance(exc, ConditionServiceNotFoundError):
            status = 404
            code = "NOT_FOUND"
        elif isinstance(exc, ConditionServiceConflictError):
            status = 409
            code = "CONFLICT"
        elif isinstance(
            exc, (ConditionServiceValidationError, ConditionContractError)
        ):
            status = 422
            code = (
                exc.code
                if isinstance(exc, ConditionContractError)
                else "VALIDATION_FAILED"
            )
        elif isinstance(exc, ConditionServiceError):
            status = 500
            code = "CONDITION_SERVICE_ERROR"
        else:
            return translate_error(exc)
        return HTTPException(
            status_code=status,
            detail={"code": code, "message": str(exc), "current": None},
        )

    def operator_control_kwargs(request: Any) -> dict[str, Any]:
        return {
            "lease_id": request.lease_id,
            "expected_lease_revision": request.expected_lease_revision,
            "control_fencing_token": request.control_fencing_token,
            "holder_session_id": request.session_id,
            "client_instance_key_id": request.client_instance_key_id,
        }

    @app.get("/api/v1/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": PRODUCT_VERSION,
            "mode": "simulator-only",
            "operational_use": False,
        }

    @app.get("/api/v1/procedures")
    def list_procedures(_: IdentityDep) -> dict[str, Any]:
        try:
            items = []
            for procedure in catalog.list():
                item = procedure.summary()
                item.update(
                    {
                        "version": IR_VERSION,
                        "entrypoint": procedure.path.name,
                        "source": procedure.source,
                        "steps": list(procedure.steps),
                    }
                )
                items.append(item)
            return {"items": items}
        except ProcedureValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/procedures/validate")
    def validate_procedure(
        request: ProcedureValidationRequest, _: IdentityDep
    ) -> dict[str, Any]:
        subset_version = f"spell-restricted-ast/{IR_VERSION}"
        try:
            procedure = catalog.validate_source(request.source, request.source_name)
        except ProcedureValidationError as exc:
            try:
                source_hash: str | None = hashlib.sha256(
                    request.source.encode("utf-8")
                ).hexdigest()
            except UnicodeEncodeError:
                source_hash = None
            return {
                "valid": False,
                "subset_version": subset_version,
                "sha256": source_hash,
                "steps": [],
                "variables": {},
                "diagnostics": [item.as_dict() for item in exc.diagnostics],
            }
        variables = {
            step["name"]: step["declared_type"]
            for step in procedure.steps
            if step["type"] == "variable_set"
            and not str(step["name"]).startswith("__spell_")
        }
        return {
            "valid": True,
            "subset_version": subset_version,
            "sha256": procedure.sha256,
            "steps": list(procedure.steps),
            "variables": variables,
            "diagnostics": [],
        }

    @app.get("/api/v1/procedures/{procedure_id}")
    def get_procedure(procedure_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            procedure = catalog.get(procedure_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="procedure not found") from exc
        result = procedure.summary()
        result.update(
            {"source": procedure.source, "steps": list(procedure.steps)}
        )
        return result

    @app.get("/api/v1/contexts")
    def list_operator_contexts(_: IdentityDep) -> dict[str, Any]:
        return {"items": operator_service.list_contexts()}

    @app.put("/api/v1/contexts/{context_id}/settings")
    def update_context_settings(
        context_id: str,
        request: ContextSettingsUpdate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(binding)
        if caller.role != "admin":
            raise HTTPException(status_code=403, detail="admin role required")
        try:
            return {
                "context": operator_service.update_context_settings(
                    context_id,
                    settings=request.settings,
                    expected_revision=request.expected_revision,
                    actor=caller.actor,
                    idempotency_key=request.idempotency_key,
                    reason=request.reason,
                )
            }
        except (
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/procedures/{procedure_id}/history")
    def procedure_history(procedure_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            return operator_service.catalog_history(procedure_id)
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/master")
    def operator_master(
        caller: IdentityDep,
        binding: SessionBindingDep,
        limit: int = Query(100, ge=1, le=500),
    ) -> dict[str, Any]:
        return {
            "items": operator_service.master(
                limit=limit,
                actor=caller.actor,
                session_id=binding.session_id,
                client_instance_key_id=binding.client_instance_key_id,
            )
        }

    @app.get("/api/v1/executions")
    def list_executions(
        caller: IdentityDep,
        binding: SessionBindingDep,
        limit: int = Query(100, ge=1, le=500),
    ) -> dict[str, Any]:
        return {
            "items": operator_service.master(
                limit=limit,
                actor=caller.actor,
                session_id=binding.session_id,
                client_instance_key_id=binding.client_instance_key_id,
            )
        }

    @app.post("/api/v1/executions", status_code=202)
    def create_execution(
        request: ExecutionCreate,
        caller: MutationIdentityDep,
        x_idempotency_key: Annotated[
            Optional[str], Header(min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        if request.context_id != "simulator":
            raise HTTPException(
                status_code=422,
                detail="only the bundled simulator execution context is supported",
            )
        key = request.idempotency_key or x_idempotency_key
        if not key:
            raise HTTPException(status_code=422, detail="idempotency_key is required")
        try:
            procedure = catalog.get(request.procedure_id)
            execution = supervisor.create_execution(
                procedure,
                caller.actor,
                caller.role,
                request.reason,
                key,
                request.context_id,
                automatic=procedure.ir_version not in {"0.6", "0.7"},
            )
            projection = operator_service.ensure_execution_projection(
                execution, actor=caller.actor
            )
            projection["operator_state"] = projection.pop("state")
            projection["operator_revision"] = projection.pop("revision")
            projection.pop("current_step", None)
            return {"execution": {**execution_dict(execution), **projection}}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="procedure not found") from exc
        except (AuthorizationError, ConflictError, NotFoundError) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/snapshot")
    def snapshot(
        execution_id: str,
        caller: IdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        try:
            result = supervisor.snapshot(execution_id)
            projection = operator_service.get_execution_projection(
                execution_id,
                actor=caller.actor,
                session_id=binding.session_id,
                client_instance_key_id=binding.client_instance_key_id,
            )
            relationships = operator_service.relationships(execution_id)
            projection["operator_state"] = projection.pop("state")
            projection["operator_revision"] = projection.pop("revision")
            projection.pop("current_step", None)
            result["execution"].update(projection)
            result["execution"]["variables"] = operator_service.redact_for_report(
                result["execution"].get("variables", {})
            )
            for collection in ("events", "logs", "telemetry"):
                if collection in result:
                    result[collection] = operator_service.redact_for_report(
                        result[collection]
                    )
            result["execution"]["breakpoints"] = [
                item["line"] for item in operator_service.list_breakpoints(execution_id)
            ]
            result["execution"]["parent_execution_id"] = (
                relationships["parents"][0]["parent_execution_id"]
                if relationships["parents"]
                else None
            )
            result["execution"]["child_execution_ids"] = [
                item["child_execution_id"] for item in relationships["children"]
            ]
            result["execution"]["monitor_count"] = (
                operator_service.active_monitor_count(execution_id)
            )
            pinned_source = result["execution"].get("source", "")
            result["execution"]["as_run_source"] = None
            result["execution"]["text"] = "\n".join(
                str((item.get("payload") or {}).get("message", ""))
                for item in result.get("logs", [])
                if (item.get("payload") or {}).get("message") is not None
            )
            result["execution"]["outline"] = [
                {
                    "id": f"step:{index}",
                    "label": (
                        str((step.get("labels") or [{}])[0].get("name"))
                        if step.get("labels")
                        else str(step.get("type", "step"))
                        .replace("_", " ")
                        .title()
                    ),
                    "line": step.get("line", index + 1),
                    "depth": max(
                        0, len(step.get("lexical_frame_path") or []) - 1
                    ),
                    "kind": step.get("type", "step"),
                    "lexical_frame_id": step.get("lexical_frame_id"),
                    "reachability_id": step.get("reachability_id"),
                    "labels": step.get("labels") or [],
                    "child_reference": step.get("child_reference"),
                }
                for index, step in enumerate(result["execution"].get("steps", []))
            ]
            result["execution"]["support_logs"] = [
                item
                for item in result.get("events", [])
                if str(item.get("severity", "info")).lower()
                in {"warning", "error", "critical"}
            ]
            steps = result["execution"].get("steps", [])

            def event_line(item: dict[str, Any]) -> int | None:
                payload = item.get("payload") or {}
                line = payload.get("line")
                if type(line) is int:
                    return line
                step_index = payload.get("step_index")
                if type(step_index) is not int:
                    next_step = payload.get("next_step")
                    step_index = next_step - 1 if type(next_step) is int else None
                if (
                    type(step_index) is int
                    and 0 <= step_index < len(steps)
                    and type(steps[step_index].get("line")) is int
                ):
                    return steps[step_index]["line"]
                return None

            def view_entry(item: dict[str, Any]) -> dict[str, Any]:
                payload = item.get("payload") or {}
                return {
                    "id": item.get("event_id"),
                    "sequence": item.get("sequence"),
                    "time": item.get("server_time"),
                    "scope": item.get("source"),
                    "kind": item.get("event_type"),
                    "message": str(
                        payload.get("message", item.get("event_type", "event"))
                    )[:2000],
                    "correlation_id": item.get("correlation_id"),
                    "line": event_line(item),
                    "outcome": payload.get("outcome") or payload.get("state"),
                }

            committed_events = result.get("events", [])
            result["execution"]["text_entries"] = [
                view_entry(item)
                for item in committed_events
                if item.get("event_type")
                in {"procedure.log", "procedure.user_action_log"}
            ]
            result["execution"]["as_run_entries"] = [
                view_entry(item) for item in committed_events
            ]
            executed_lines = sorted(
                {
                    line
                    for item in committed_events
                    for line in [event_line(item)]
                    if type(line) is int
                }
            )
            result["execution"]["executed_lines"] = executed_lines
            result["execution"]["executed_line_coverage"] = {
                "source_digest": result["execution"].get("source_digest")
                or result["execution"].get("procedure_hash"),
                "lines": executed_lines,
                "through_sequence": result.get("last_sequence", 0),
            }
            result["execution"]["workspace_cursor"] = result.get(
                "last_sequence", 0
            )
            typed_prompt = operator_service.active_typed_prompt(execution_id)
            # Legacy Prompt rows are staged before their fenced OperatorPrompt
            # projection, which is itself staged before the execution enters
            # prompting. Never expose either transient shape to a v0.6 client.
            if result["execution"]["state"] == "running":
                typed_prompt = None
            result["active_prompt"] = typed_prompt
            result["typed_prompt"] = typed_prompt
            result["inspection"] = operator_service.inspection(execution_id)["items"]
            result["schedules"] = operator_service.list_schedules(
                controller_execution_id=execution_id
            )
            result["actions"] = operator_service.list_user_actions(execution_id)
            result["relationships"] = [
                *relationships["parents"],
                *relationships["children"],
            ]
            return result
        except (NotFoundError, OperatorNotFoundError) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/control")
    def mutate_control(
        execution_id: str,
        request: ControlMutationCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            if request.action == "ACQUIRE":
                return operator_service.acquire_control(
                    execution_id,
                    expected_execution_revision=request.expected_execution_revision,
                    actor=caller.actor,
                    holder_session_id=request.session_id,
                    client_instance_key_id=request.client_instance_key_id,
                    lease_seconds=request.lease_seconds,
                    idempotency_key=request.idempotency_key,
                    reason=request.reason,
                    acknowledgement=request.acknowledgement,
                )
            if (
                request.lease_id is None
                or request.expected_lease_revision is None
                or request.control_fencing_token is None
            ):
                raise OperatorValidationError(
                    "renew and release require a complete controller lease proof"
                )
            proof = {
                "lease_id": request.lease_id,
                "expected_lease_revision": request.expected_lease_revision,
                "control_fencing_token": request.control_fencing_token,
                "actor": caller.actor,
                "holder_session_id": request.session_id,
                "client_instance_key_id": request.client_instance_key_id,
                "idempotency_key": request.idempotency_key,
                "reason": request.reason,
            }
            if request.action == "RENEW":
                return operator_service.renew_control(
                    execution_id, lease_seconds=request.lease_seconds, **proof
                )
            return operator_service.release_control_to_background(
                execution_id,
                expected_execution_revision=request.expected_execution_revision,
                **proof,
            )
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.put("/api/v1/executions/{execution_id}/settings")
    def update_execution_settings(
        execution_id: str,
        request: ExecutionSettingsUpdate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            return {
                "execution": operator_service.update_execution_settings(
                    execution_id,
                    settings=request.settings,
                    expected_execution_revision=request.expected_execution_revision,
                    actor=caller.actor,
                    idempotency_key=request.idempotency_key,
                    reason=request.reason,
                    **operator_control_kwargs(request),
                )
            }
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/monitors", status_code=201)
    def start_monitor(
        execution_id: str,
        request: MonitorSubscriptionCreate,
        caller: IdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            return {
                "monitor": operator_service.start_monitor(
                    execution_id,
                    actor=caller.actor,
                    session_id=request.session_id,
                    client_instance_key_id=request.client_instance_key_id,
                )
            }
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.delete("/api/v1/executions/{execution_id}/monitors/{monitor_id}")
    def stop_monitor(
        execution_id: str,
        monitor_id: str,
        caller: IdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(binding)
        try:
            monitor = operator_service.stop_monitor(
                execution_id,
                monitor_id,
                actor=caller.actor,
                session_id=str(binding.session_id),
                client_instance_key_id=str(binding.client_instance_key_id),
            )
            return {"monitor": monitor}
        except (
            OperatorAuthorizationError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/handovers", status_code=201)
    def request_handover(
        execution_id: str,
        request: HandoverRequestCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            return {
                "handover": operator_service.request_control_handover(
                    execution_id,
                    requester_monitor_id=request.requester_monitor_id,
                    expected_execution_revision=request.expected_execution_revision,
                    actor=caller.actor,
                    requester_session_id=request.session_id,
                    requester_client_instance_key_id=request.client_instance_key_id,
                    responsibility_acknowledgement=request.responsibility_acknowledgement,
                    expires_seconds=request.expires_seconds,
                    idempotency_key=request.idempotency_key,
                    reason=request.reason,
                )
            }
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/handovers")
    def list_handovers(
        execution_id: str,
        caller: IdentityDep,
        binding: SessionBindingDep,
        include_terminal: bool = False,
    ) -> dict[str, Any]:
        require_session_binding(binding)
        try:
            return {
                "items": operator_service.list_control_handovers(
                    execution_id,
                    actor=caller.actor,
                    session_id=str(binding.session_id),
                    client_instance_key_id=str(binding.client_instance_key_id),
                    include_terminal=include_terminal,
                )
            }
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.post(
        "/api/v1/executions/{execution_id}/handovers/{handover_id}/approve"
    )
    def approve_handover(
        execution_id: str,
        handover_id: str,
        request: HandoverApproveCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            return operator_service.approve_control_handover(
                execution_id,
                handover_id,
                expected_handover_revision=request.expected_handover_revision,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                lease_seconds=request.lease_seconds,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/events")
    def get_events(
        execution_id: str,
        _: IdentityDep,
        after_sequence: int = Query(0, ge=0),
        limit: int = Query(200, ge=1, le=1000),
    ) -> dict[str, Any]:
        try:
            items = supervisor.events_after(execution_id, after_sequence, limit)
            return {"items": items}
        except NotFoundError as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/commands", status_code=202)
    def command(
        execution_id: str,
        request: CommandCreate | OperatorCommandCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
        x_idempotency_key: Annotated[
            Optional[str], Header(min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        key = request.idempotency_key or x_idempotency_key
        if not key:
            raise HTTPException(status_code=422, detail="idempotency_key is required")
        try:
            if isinstance(request, OperatorCommandCreate):
                require_session_binding(
                    binding,
                    session_id=request.session_id,
                    client_instance_key_id=request.client_instance_key_id,
                )
                result = operator_service.accept_operator_command(
                    execution_id=execution_id,
                    command_type=request.type,
                    expected_execution_revision=request.expected_execution_revision,
                    idempotency_key=key,
                    actor=caller.actor,
                    role=caller.role,
                    reason=request.reason,
                    controller_lease_id=request.lease_id,
                    expected_lease_revision=request.expected_lease_revision,
                    control_fencing_token=request.control_fencing_token,
                    holder_session_id=request.session_id,
                    client_instance_key_id=request.client_instance_key_id,
                    payload=request.payload,
                    target=request.target,
                    correlation_id=(
                        str(request.correlation_id)
                        if request.correlation_id is not None
                        else None
                    ),
                )
                if result["state"] == "ACCEPTED":
                    result = supervisor.dispatch_operator_command(result)
                return {"command": result}
            result = operator_service.execute_legacy_command_compatibility(
                execution_id,
                actor=caller.actor,
                role=caller.role,
                operation=lambda: supervisor.issue_command(
                    execution_id=execution_id,
                    command_type=request.type,
                    expected_revision=request.expected_revision,
                    idempotency_key=key,
                    actor=caller.actor,
                    role=caller.role,
                    reason=request.reason,
                    correlation_id=(
                        str(request.correlation_id)
                        if request.correlation_id
                        else None
                    ),
                    payload={},
                ),
            )
            return {"command": command_dict(result)}
        except (
            AuthorizationError,
            ConflictError,
            NotFoundError,
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/prompts/{prompt_id}/responses", status_code=202)
    def prompt_response(
        prompt_id: str,
        request: PromptResponseCreate | OperatorPromptResponseCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
        x_idempotency_key: Annotated[
            Optional[str], Header(min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        key = request.idempotency_key or x_idempotency_key
        if not key:
            raise HTTPException(status_code=422, detail="idempotency_key is required")
        try:
            if isinstance(request, OperatorPromptResponseCreate):
                require_session_binding(
                    binding,
                    session_id=request.session_id,
                    client_instance_key_id=request.client_instance_key_id,
                )
                operator_service.ensure_legacy_prompt_projection(prompt_id)
                return operator_service.settle_prompt(
                    prompt_id=prompt_id,
                    expected_prompt_revision=request.expected_prompt_revision,
                    action=request.action,
                    value=request.value,
                    actor=caller.actor,
                    controller_lease_id=request.lease_id,
                    expected_lease_revision=request.expected_lease_revision,
                    control_fencing_token=request.control_fencing_token,
                    holder_session_id=request.session_id,
                    client_instance_key_id=request.client_instance_key_id,
                    idempotency_key=key,
                    reason=request.reason,
                )
            result = operator_service.execute_legacy_prompt_compatibility(
                prompt_id,
                actor=caller.actor,
                role=caller.role,
                operation=lambda: supervisor.respond_to_prompt(
                    prompt_id=prompt_id,
                    response=request.value,
                    expected_revision=request.expected_revision,
                    idempotency_key=key,
                    actor=caller.actor,
                    role=caller.role,
                    reason=request.reason,
                    correlation_id=(
                        str(request.correlation_id)
                        if request.correlation_id
                        else None
                    ),
                ),
            )
            return {"command": command_dict(result)}
        except (
            AuthorizationError,
            ConflictError,
            NotFoundError,
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/schedules")
    def list_schedules(
        _: IdentityDep,
        controller_execution_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        try:
            return {
                "items": operator_service.list_schedules(
                    controller_execution_id=controller_execution_id, limit=limit
                )
            }
        except OperatorValidationError as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/schedules", status_code=201)
    def create_schedule(
        request: ScheduleCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            schedule = operator_service.create_schedule(
                controller_execution_id=request.controller_execution_id,
                schedule_type=request.schedule_type,
                target=request.target,
                procedure_catalog_id=request.procedure_catalog_id,
                procedure_revision=request.procedure_revision,
                context_id=request.context_id,
                arguments=request.arguments,
                automatic=request.automatic,
                background_allowed=request.background_allowed,
                visible=request.visible,
                misfire_policy=request.misfire_policy,
                maximum_lateness_seconds=request.maximum_lateness_seconds,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
            return {"schedule": schedule}
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    def cancel_schedule_resource(
        schedule_id: str, request: ScheduleCancelCreate, caller: Identity
    ) -> dict[str, Any]:
        try:
            schedule = operator_service.cancel_schedule(
                schedule_id,
                expected_schedule_revision=request.expected_schedule_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
            return {"schedule": schedule}
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/schedules/{schedule_id}/cancel")
    def cancel_schedule_post(
        schedule_id: str,
        request: ScheduleCancelCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        return cancel_schedule_resource(schedule_id, request, caller)

    @app.delete("/api/v1/schedules/{schedule_id}")
    def cancel_schedule_delete(
        schedule_id: str,
        request: ScheduleCancelCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        return cancel_schedule_resource(schedule_id, request, caller)

    @app.get("/api/v1/telemetry-schedules")
    def list_telemetry_schedules(
        _: IdentityDep,
        controller_execution_id: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        try:
            return {
                "items": condition_service.list_telemetry_schedules(
                    controller_execution_id=controller_execution_id,
                    limit=limit,
                )
            }
        except ConditionServiceError as exc:
            raise translate_condition_error(exc) from exc

    @app.get("/api/v1/telemetry-schedules/{schedule_id}")
    def get_telemetry_schedule(
        schedule_id: str, _: IdentityDep
    ) -> dict[str, Any]:
        try:
            return {
                "schedule": condition_service.get_telemetry_schedule(schedule_id)
            }
        except ConditionServiceError as exc:
            raise translate_condition_error(exc) from exc

    @app.post("/api/v1/telemetry-schedules", status_code=201)
    def create_telemetry_schedule(
        request: TelemetryScheduleCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            control = operator_service.require_control(
                request.controller_execution_id,
                actor=caller.actor,
                **operator_control_kwargs(request),
            )
            execution = supervisor.get_execution(request.controller_execution_id)
            if execution.revision != request.expected_execution_revision:
                raise OperatorConflictError(
                    "execution revision conflict",
                    current={"execution_revision": execution.revision},
                )
            if control["execution"]["state"] in {"FINISHED", "ABORTED", "ERROR"}:
                raise OperatorConflictError(
                    "terminal execution cannot create telemetry schedules"
                )
            context = next(
                (
                    item
                    for item in operator_service.list_contexts()
                    if item["id"] == request.context_id
                ),
                None,
            )
            if context is None or not context["enabled"]:
                raise OperatorConflictError("schedule context is unavailable")
            history = operator_service.catalog_history(
                request.procedure_catalog_id
            )
            entry = history["procedure"]
            wanted_revision = (
                request.procedure_revision or entry["current_revision"]
            )
            revision = next(
                (
                    item
                    for item in history["items"]
                    if item["revision"] == wanted_revision
                ),
                None,
            )
            if revision is None:
                raise OperatorNotFoundError(
                    "procedure catalog revision not found"
                )
            snapshot = observation_repository.snapshot(request.context_id)
            plan = ConditionPlan.from_dict(request.condition_plan)
            schedule = condition_service.create_telemetry_schedule(
                plan=plan,
                policy=QualityFreshnessPolicy(POLICY_ID, POLICY_REVISION),
                start_snapshot_cursor=int(snapshot["through_sequence"]),
                timeout_seconds=request.timeout_seconds,
                retry_count=request.retry_count,
                retry_interval_seconds=request.retry_interval_seconds,
                controller_execution_id=request.controller_execution_id,
                procedure_catalog_id=entry["id"],
                procedure_revision=revision["revision"],
                bundle_digest=revision["bundle_digest"],
                context_id=request.context_id,
                arguments=request.arguments,
                automatic=request.automatic,
                background_allowed=request.background_allowed,
                visible=request.visible,
                created_by=caller.actor,
                idempotency_key=request.idempotency_key,
            )
            return {"schedule": schedule}
        except (
            ConditionContractError,
            ConditionServiceError,
            ObservationRepositoryError,
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
            AuthorizationError,
            ConflictError,
            NotFoundError,
        ) as exc:
            if isinstance(exc, ObservationRepositoryError):
                raise translate_observation_error(exc) from exc
            if isinstance(exc, (ConditionContractError, ConditionServiceError)):
                raise translate_condition_error(exc) from exc
            raise translate_error(exc) from exc

    @app.post("/api/v1/telemetry-schedules/{schedule_id}/cancel")
    def cancel_telemetry_schedule(
        schedule_id: str,
        request: TelemetryScheduleCancelCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            current = condition_service.get_telemetry_schedule(schedule_id)
            if (
                current["controller_execution_id"]
                != request.controller_execution_id
            ):
                raise OperatorConflictError(
                    "telemetry schedule controller mismatch"
                )
            operator_service.require_control(
                request.controller_execution_id,
                actor=caller.actor,
                **operator_control_kwargs(request),
            )
            return {
                "schedule": condition_service.cancel_telemetry_schedule(
                    schedule_id,
                    expected_revision=request.expected_schedule_revision,
                )
            }
        except (
            ConditionServiceError,
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            if isinstance(exc, ConditionServiceError):
                raise translate_condition_error(exc) from exc
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/inspection")
    def inspect_execution(execution_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            return operator_service.inspection(execution_id)
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/workspace-search")
    def search_execution_workspace(
        execution_id: str,
        _: IdentityDep,
        query: str = Query(min_length=1, max_length=200),
        view: str = Query(default="SOURCE", min_length=1, max_length=20),
        source_digest: str | None = Query(default=None, min_length=64, max_length=64),
        after_sequence: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=200),
    ) -> dict[str, Any]:
        try:
            return operator_service.search_workspace(
                execution_id,
                query=query,
                view=view,
                source_digest=source_digest,
                after_sequence=after_sequence,
                limit=limit,
            )
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/workspace-view")
    def get_execution_workspace_view(
        execution_id: str,
        _: IdentityDep,
        view: str = Query(default="AS_RUN", min_length=1, max_length=20),
        source_digest: str | None = Query(default=None, min_length=64, max_length=64),
        after_sequence: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=200),
    ) -> dict[str, Any]:
        try:
            return operator_service.workspace_view(
                execution_id,
                view=view,
                source_digest=source_digest,
                after_sequence=after_sequence,
                limit=limit,
            )
        except (
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/inspection/edits")
    def edit_inspection_value(
        execution_id: str,
        request: InspectionEditCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            value = operator_service.edit_inspection(
                execution_id,
                path=request.path,
                scope=request.scope,
                declared_type=request.type,
                value=request.value,
                expected_value_revision=request.expected_value_revision,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
            try:
                supervisor.dispatch_inspection_edit(value)
            except ConflictError:
                pass
            return {
                "value": {key: item for key, item in value.items() if key != "variables"}
            }
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/console-operations")
    def console_operation(
        execution_id: str,
        request: ConsoleOperationCreate,
        caller: IdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        proof = None
        if request.operation == "WRITE_TYPED_LITERAL":
            mutation_identity(caller)
            if any(
                item is None
                for item in (
                    request.lease_id,
                    request.expected_lease_revision,
                    request.control_fencing_token,
                    request.session_id,
                    request.client_instance_key_id,
                )
            ):
                raise translate_error(
                    OperatorAuthorizationError(
                        "write operation requires a complete controller lease proof"
                    )
                )
            proof = operator_control_kwargs(request)
        try:
            result = operator_service.console_operation(
                execution_id,
                operation=request.operation,
                path=request.path,
                scope=request.scope,
                query=request.query,
                limit=request.limit,
                actor=caller.actor,
                expected_execution_revision=request.expected_execution_revision,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                declared_type=request.type,
                value=request.value,
                control_proof=proof,
            )
            if request.operation == "WRITE_TYPED_LITERAL":
                edit = result.get("result")
                if isinstance(edit, dict):
                    try:
                        supervisor.dispatch_inspection_edit(edit)
                    except ConflictError:
                        pass
                    result["result"] = {
                        key: item for key, item in edit.items() if key != "variables"
                    }
            return result
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/actions")
    def list_user_actions(execution_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            return {"items": operator_service.list_user_actions(execution_id)}
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/actions/{action_id}/mutations")
    def mutate_user_action(
        execution_id: str,
        action_id: str,
        request: UserActionMutationCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            action = operator_service.mutate_user_action(
                execution_id,
                action_id,
                operation=request.operation,
                expected_action_revision=request.expected_action_revision,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
            return {"action": action}
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/executions/{execution_id}/actions/{action_id}/invoke")
    def invoke_user_action(
        execution_id: str,
        action_id: str,
        request: UserActionInvokeCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            invocation = operator_service.invoke_user_action(
                execution_id,
                action_id,
                expected_action_revision=request.expected_action_revision,
                expected_execution_revision=request.expected_execution_revision,
                arguments=request.arguments,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
            if invocation["state"] == "PENDING_SAFE_POINT":
                dispatched = supervisor.dispatch_user_action(
                    execution_id,
                    invocation["id"],
                    list(invocation.get("pinned_handler") or []),
                )
                if dispatched is not None:
                    invocation = {
                        key: value
                        for key, value in dispatched.items()
                        if key != "pinned_handler"
                    }
            return {"invocation": invocation}
        except (
            StopIteration,
            ConflictError,
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            if isinstance(exc, StopIteration):
                exc = OperatorNotFoundError("user action not found")
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/relationships")
    def execution_relationships(execution_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            result = operator_service.relationships(execution_id)
            return {
                **result,
                "items": [*result["parents"], *result["children"]],
            }
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/startproc-operations")
    def startproc_operations(execution_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            return {
                "items": operator_service.list_startproc_operations(
                    parent_execution_id=execution_id
                )
            }
        except (OperatorNotFoundError, OperatorValidationError) as exc:
            raise translate_error(exc) from exc

    @app.put("/api/v1/executions/{execution_id}/breakpoints/{line}")
    def put_breakpoint(
        execution_id: str,
        line: int,
        request: BreakpointMutationCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            breakpoint = operator_service.put_breakpoint(
                execution_id,
                line,
                one_shot=request.one_shot,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
            return {"breakpoint": breakpoint}
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.delete("/api/v1/executions/{execution_id}/breakpoints/{line}")
    def delete_breakpoint(
        execution_id: str,
        line: int,
        request: BreakpointMutationCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            return operator_service.delete_breakpoint(
                execution_id,
                line,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.delete("/api/v1/executions/{execution_id}/breakpoints")
    def remove_all_breakpoints(
        execution_id: str,
        request: BreakpointMutationCreate,
        caller: MutationIdentityDep,
        binding: SessionBindingDep,
    ) -> dict[str, Any]:
        require_session_binding(
            binding,
            session_id=request.session_id,
            client_instance_key_id=request.client_instance_key_id,
        )
        try:
            return operator_service.remove_all_breakpoints(
                execution_id,
                expected_execution_revision=request.expected_execution_revision,
                actor=caller.actor,
                idempotency_key=request.idempotency_key,
                reason=request.reason,
                **operator_control_kwargs(request),
            )
        except (
            OperatorAuthorizationError,
            OperatorConflictError,
            OperatorNotFoundError,
            OperatorValidationError,
        ) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/report")
    def as_run_report(execution_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            execution = supervisor.get_execution(execution_id)
        except NotFoundError as exc:
            raise translate_error(exc) from exc
        with session_factory() as session:
            events = session.scalars(
                select(Event)
                .where(Event.execution_id == execution_id)
                .order_by(Event.sequence)
            ).all()
            commands = session.scalars(
                select(Command)
                .where(Command.execution_id == execution_id)
                .order_by(Command.created_at)
            ).all()
            prompts = session.scalars(
                select(Prompt)
                .where(Prompt.execution_id == execution_id)
                .order_by(Prompt.created_at)
            ).all()
        serialized_events = operator_service.redact_for_report(
            [event_dict(item) for item in events]
        )
        commands_data = operator_service.redact_for_report(
            [command_dict(item) for item in commands]
        )
        prompts_data = operator_service.redact_for_report(
            [prompt_dict(item) for item in prompts]
        )
        report_variables = operator_service.redact_for_report(execution.variables)
        operator_data = operator_service.report_projection(execution_id)
        integrity_input = {
            "execution_id": execution.id,
            "procedure_hash": execution.procedure_hash,
            "procedure_subset_version": execution_dict(execution)["procedure_subset_version"],
            "configuration_hash": execution_dict(execution)["configuration_hash"],
            "context_id": execution.context_id,
            "state": execution.state,
            "variables": report_variables,
            "commands": commands_data,
            "prompts": prompts_data,
            "events": serialized_events,
            "operator": operator_data,
        }
        digest = hashlib.sha256(
            json.dumps(integrity_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "report_version": REPORT_VERSION,
            "execution_id": execution.id,
            "procedure_name": execution.procedure_name,
            "procedure_hash": execution.procedure_hash,
            "procedure_subset_version": execution_dict(execution)["procedure_subset_version"],
            "configuration_hash": execution_dict(execution)["configuration_hash"],
            "context_id": execution.context_id,
            "state": execution.state,
            "variables": report_variables,
            "started_at": execution.created_at.isoformat(),
            "finished_at": (
                execution.updated_at.isoformat() if execution.state in {"completed", "aborted", "failed"} else None
            ),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "completed_steps": execution.current_step,
                "total_steps": execution.total_steps,
                "event_count": len(serialized_events),
                "command_count": len(commands),
                "worker_generations": execution.worker_generation,
                "variable_count": len(execution.variables),
            },
            "commands": commands_data,
            "prompts": prompts_data,
            "events": serialized_events,
            **operator_data,
            "integrity": {
                "algorithm": "sha256",
                "canonicalization": "json-sort-keys-v1",
                "digest": digest,
            },
        }

    def driver_projection(value: dict[str, Any]) -> dict[str, Any]:
        """Add read-time freshness without exposing the transport boundary."""

        projected = dict(value)
        observed = projected.get("last_observed_at")
        if observed is None:
            projected["stale"] = False
            projected["staleness"] = "UNKNOWN"
            return projected
        try:
            observed_at = datetime.fromisoformat(str(observed))
            if observed_at.tzinfo is None or observed_at.utcoffset() is None:
                raise ValueError("naive timestamp")
            age_seconds = (datetime.now(timezone.utc) - observed_at).total_seconds()
        except (TypeError, ValueError):
            projected["stale"] = True
            projected["staleness"] = "STALE"
            return projected
        projected["stale"] = age_seconds > settings.driver_stale_after_seconds
        projected["staleness"] = "STALE" if projected["stale"] else "OBSERVED"
        return projected

    def translate_driver_read_error(exc: Exception) -> HTTPException:
        if isinstance(exc, DriverNotFoundError):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, DriverValidationError):
            return HTTPException(status_code=422, detail=str(exc))
        return HTTPException(status_code=500, detail="internal server error")

    def translate_observation_error(exc: ObservationRepositoryError) -> HTTPException:
        if isinstance(exc, ObservationNotFoundError):
            status = 404
        elif isinstance(exc, ObservationStaleGenerationError):
            status = 409
        elif isinstance(exc, ObservationConflictError):
            status = 409
        elif isinstance(exc, ObservationValidationError):
            status = 422
        else:
            status = 500
        return HTTPException(
            status_code=status,
            detail={"code": exc.code, "message": str(exc)},
        )

    @app.get("/api/v1/driver-time")
    def get_driver_time(
        _: IdentityDep,
        context_id: str = Query("simulator", min_length=1, max_length=128),
    ) -> dict[str, Any]:
        try:
            return {"driver_time": observation_repository.driver_time(context_id)}
        except ObservationRepositoryError as exc:
            raise translate_observation_error(exc) from exc

    @app.get("/api/v1/observation-catalog")
    def observation_catalog(_: IdentityDep) -> dict[str, Any]:
        return observation_read_service.identity()

    @app.get("/api/v1/resources/{resource_id}")
    def observation_resource(
        resource_id: str,
        _: IdentityDep,
        resource_type: str,
        catalog_id: str,
        catalog_digest: str,
    ) -> dict[str, Any]:
        return observation_read_service.get_resource(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    @app.get("/api/v1/memory-lookup")
    def observation_memory_lookup(
        _: IdentityDep,
        catalog_id: str,
        catalog_digest: str,
        maximum_entries: int = 128,
        memory_region_id: str | None = None,
        start_address: int | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        return observation_read_service.memory_lookup(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            maximum_entries=maximum_entries,
            memory_region_id=memory_region_id,
            start_address=start_address,
            length=length,
        )

    @app.get("/api/v1/tmtc-lookup")
    def observation_tmtc_lookup(
        _: IdentityDep,
        catalog_id: str,
        catalog_digest: str,
        direction: str,
        maximum_entries: int = 128,
        item_id: str | None = None,
        qualified_name: str | None = None,
    ) -> dict[str, Any]:
        return observation_read_service.tmtc_lookup(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            direction=direction,
            maximum_entries=maximum_entries,
            item_id=item_id,
            qualified_name=qualified_name,
        )

    @app.get("/api/v1/observation-limits/{item_id}")
    def observation_limits(
        item_id: str,
        _: IdentityDep,
        catalog_id: str,
        catalog_digest: str,
    ) -> dict[str, Any]:
        return observation_read_service.get_limits(
            catalog_id=catalog_id,
            catalog_digest=catalog_digest,
            item_id=item_id,
        )

    @app.get("/api/v1/telemetry/snapshot")
    def telemetry_snapshot(
        _: IdentityDep,
        context_id: str = Query("simulator", min_length=1, max_length=128),
    ) -> dict[str, Any]:
        try:
            return observation_repository.snapshot(context_id)
        except ObservationRepositoryError as exc:
            raise translate_observation_error(exc) from exc

    @app.get("/api/v1/telemetry/{item_id}/limits")
    def telemetry_limits(
        item_id: Annotated[str, PathParam(min_length=1, max_length=128)],
        _: IdentityDep,
        catalog_digest: str = Query(min_length=64, max_length=64),
    ) -> dict[str, Any]:
        try:
            return {
                "limits": observation_repository.get_limits(
                    item_id, catalog_digest
                )
            }
        except ObservationRepositoryError as exc:
            raise translate_observation_error(exc) from exc

    @app.get("/api/v1/telemetry/{item_id}/alarm")
    def telemetry_alarm(
        item_id: Annotated[str, PathParam(min_length=1, max_length=128)],
        _: IdentityDep,
        context_id: str = Query("simulator", min_length=1, max_length=128),
    ) -> dict[str, Any]:
        try:
            return {
                "alarm": observation_repository.is_alarmed(context_id, item_id)
            }
        except ObservationRepositoryError as exc:
            raise translate_observation_error(exc) from exc

    @app.get("/api/v1/drivers")
    def list_drivers(
        _: IdentityDep,
        limit: int = Query(100, ge=1, le=100),
        cursor: Annotated[Optional[str], Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        try:
            page = driver_repository.list_drivers(limit=limit, cursor=cursor)
            return {
                **page,
                "items": [driver_projection(item) for item in page["items"]],
            }
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.get("/api/v1/drivers/{driver_id}")
    def get_driver(
        driver_id: Annotated[str, PathParam(min_length=1, max_length=100)],
        _: IdentityDep,
    ) -> dict[str, Any]:
        try:
            result = driver_repository.get_driver(driver_id)
            return {"driver": driver_projection(result["driver"])}
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.get("/api/v1/driver-contexts")
    def list_driver_contexts(
        _: IdentityDep,
        limit: int = Query(100, ge=1, le=100),
        cursor: Annotated[Optional[str], Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        try:
            page = driver_repository.list_context_generations(limit=limit, cursor=cursor)
            return {
                **page,
                "items": [driver_projection(item) for item in page["items"]],
            }
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.get("/api/v1/driver-contexts/{context_id}/generations/{context_generation}")
    def get_driver_context_generation(
        context_id: Annotated[str, PathParam(min_length=1, max_length=100)],
        context_generation: Annotated[
            str, PathParam(min_length=1, max_length=100)
        ],
        _: IdentityDep,
    ) -> dict[str, Any]:
        try:
            result = driver_repository.get_context_generation(
                context_id, context_generation
            )
            return {
                "context_generation": driver_projection(result["context_generation"])
            }
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.get("/api/v1/driver-bindings")
    def list_driver_bindings(
        _: IdentityDep,
        limit: int = Query(100, ge=1, le=100),
        cursor: Annotated[Optional[str], Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        try:
            page = driver_repository.list_bindings(limit=limit, cursor=cursor)
            return {
                **page,
                "items": [driver_projection(item) for item in page["items"]],
            }
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.get("/api/v1/driver-bindings/{driver_binding_id}")
    def get_driver_binding(
        driver_binding_id: Annotated[
            str, PathParam(min_length=1, max_length=100)
        ],
        _: IdentityDep,
    ) -> dict[str, Any]:
        try:
            result = driver_repository.get_binding(driver_binding_id)
            return {"binding": driver_projection(result["binding"])}
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.get("/api/v1/driver-operations/{operation_id}")
    def get_driver_operation(
        operation_id: Annotated[str, PathParam(min_length=1, max_length=100)],
        _: IdentityDep,
    ) -> dict[str, Any]:
        try:
            return driver_repository.get_operation(operation_id)
        except (DriverNotFoundError, DriverValidationError) as exc:
            raise translate_driver_read_error(exc) from exc

    @app.websocket("/api/v1/telemetry-events/ws")
    async def websocket_telemetry_events(
        websocket: WebSocket,
        context_id: str = Query("simulator", min_length=1, max_length=128),
        stream_epoch: str = Query(..., min_length=1, max_length=128),
        after_sequence: int = Query(0, ge=0, le=MAX_OBSERVATION_SEQUENCE),
    ) -> None:
        protocols = websocket.scope.get("subprotocols", [])
        if len(protocols) != 2 or protocols[0] != "spell-auth":
            await websocket.close(code=4401, reason="invalid websocket credentials")
            return
        try:
            websocket_identity = decode_token(get_auth_config(), protocols[1])
        except AuthenticationError:
            await websocket.close(code=4401, reason="invalid websocket credentials")
            return
        seconds_until_expiry = websocket_identity.expires_at - time.time()
        if seconds_until_expiry <= 0:
            await websocket.close(code=4401, reason="websocket credentials expired")
            return
        try:
            authority = observation_repository.stream_cursor(context_id)
        except ObservationRepositoryError:
            await websocket.close(code=4404, reason="observation stream not found")
            return

        loop = asyncio.get_running_loop()
        expiry_deadline = loop.time() + seconds_until_expiry
        await websocket.accept(subprotocol="spell-auth")
        subscription = hub.subscribe(OBSERVATION_STREAM)
        last_sent = after_sequence
        replay_limit = min(
            settings.websocket_replay_limit, MAX_OBSERVATION_REPLAY - 1
        )

        async def resync(reason: str, cursor: dict[str, Any]) -> None:
            await websocket.send_json(
                {
                    "schema_version": OBSERVATION_EVENT_SCHEMA,
                    "stream": OBSERVATION_STREAM,
                    "event_type": "stream.resync_required",
                    "stream_epoch": cursor["stream_epoch"],
                    "data": {
                        "reason": reason,
                        "authoritative_stream_epoch": cursor["stream_epoch"],
                        "authoritative_sequence": cursor["last_sequence"],
                    },
                }
            )
            await websocket.close(
                code=4409, reason="snapshot resynchronization required"
            )

        async def replay_committed() -> bool:
            nonlocal last_sent, authority
            authority = observation_repository.stream_cursor(context_id)
            window = observation_repository.replay(
                context_id,
                stream_epoch=stream_epoch,
                after_sequence=last_sent,
                limit=replay_limit + 1,
            )
            if not window["epoch_matches"]:
                await resync("STREAM_EPOCH_CHANGED", authority)
                return False
            if last_sent > int(window["last_sequence"]):
                await resync("SEQUENCE_AHEAD_OF_AUTHORITY", authority)
                return False
            if not window["cursor_available"]:
                await resync("CURSOR_UNAVAILABLE", authority)
                return False
            replay = window["items"]
            if len(replay) > replay_limit:
                await resync("REPLAY_LIMIT_EXCEEDED", authority)
                return False
            for item in replay:
                if loop.time() >= expiry_deadline:
                    await websocket.close(
                        code=4401, reason="websocket credentials expired"
                    )
                    return False
                sequence = int(item["projection_sequence"])
                if sequence <= last_sent:
                    continue
                if sequence != last_sent + 1:
                    await resync("CURSOR_UNAVAILABLE", authority)
                    return False
                await websocket.send_json(item)
                last_sent = sequence
            return True

        try:
            # Subscribe before replay. Live delivery is only a wake-up; every
            # data frame is reread from the committed observation outbox.
            if not await replay_committed():
                return
            while True:
                seconds_remaining = expiry_deadline - loop.time()
                if seconds_remaining <= 0:
                    await websocket.close(
                        code=4401, reason="websocket credentials expired"
                    )
                    return
                if subscription.overflowed:
                    authority = observation_repository.stream_cursor(context_id)
                    await resync("CLIENT_QUEUE_OVERFLOW", authority)
                    return
                try:
                    await asyncio.wait_for(
                        subscription.queue.get(),
                        timeout=min(
                            settings.websocket_keepalive_seconds,
                            seconds_remaining,
                        ),
                    )
                except asyncio.TimeoutError:
                    if loop.time() >= expiry_deadline:
                        await websocket.close(
                            code=4401, reason="websocket credentials expired"
                        )
                        return
                    authority = observation_repository.stream_cursor(context_id)
                    if authority["stream_epoch"] != stream_epoch:
                        await resync("STREAM_EPOCH_CHANGED", authority)
                        return
                    await websocket.send_json(
                        {
                            "schema_version": OBSERVATION_EVENT_SCHEMA,
                            "stream": OBSERVATION_STREAM,
                            "stream_epoch": stream_epoch,
                            "event_type": "stream.keepalive",
                            "last_sequence": str(last_sent),
                            "server_time": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    continue
                if not await replay_committed():
                    return
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(OBSERVATION_STREAM, subscription)

    @app.websocket("/api/v1/driver-events/ws")
    async def websocket_driver_events(
        websocket: WebSocket,
        after_sequence: int = Query(0, ge=0, le=MAX_DRIVER_EVENT_SEQUENCE),
    ) -> None:
        protocols = websocket.scope.get("subprotocols", [])
        if len(protocols) != 2 or protocols[0] != "spell-auth":
            await websocket.close(code=4401, reason="invalid websocket credentials")
            return
        try:
            websocket_identity = decode_token(get_auth_config(), protocols[1])
        except AuthenticationError:
            await websocket.close(code=4401, reason="invalid websocket credentials")
            return
        seconds_until_expiry = websocket_identity.expires_at - time.time()
        if seconds_until_expiry <= 0:
            await websocket.close(code=4401, reason="websocket credentials expired")
            return

        loop = asyncio.get_running_loop()
        expiry_deadline = loop.time() + seconds_until_expiry
        await websocket.accept(subprotocol="spell-auth")
        subscription = hub.subscribe("driver.lifecycle")
        last_sent = after_sequence
        replay_limit = min(
            settings.websocket_replay_limit, MAX_DRIVER_EVENT_REPLAY - 1
        )

        async def resync(reason: str, authoritative_sequence: int) -> None:
            await websocket.send_json(
                {
                    "event_type": "stream.resync_required",
                    "stream": "driver.lifecycle",
                    "payload": {
                        "reason": reason,
                        "authoritative_sequence": authoritative_sequence,
                    },
                }
            )
            await websocket.close(
                code=4409, reason="snapshot resynchronization required"
            )

        async def replay_committed() -> bool:
            nonlocal last_sent
            window = driver_repository.replay_driver_events(
                after_sequence=last_sent, limit=replay_limit + 1
            )
            authoritative_sequence = int(window["last_sequence"])
            if last_sent > authoritative_sequence:
                await resync("sequence_ahead_of_authority", authoritative_sequence)
                return False
            if not window["cursor_available"]:
                await resync("cursor_unavailable", authoritative_sequence)
                return False
            replay = window["items"]
            if len(replay) > replay_limit:
                await resync("replay_limit_exceeded", authoritative_sequence)
                return False
            for item in replay:
                if loop.time() >= expiry_deadline:
                    await websocket.close(
                        code=4401, reason="websocket credentials expired"
                    )
                    return False
                sequence = int(item["sequence"])
                if sequence <= last_sent:
                    continue
                await websocket.send_json(item)
                last_sent = sequence
            return True

        try:
            # Subscribe before replay so a commit racing with the query is either
            # read durably, observed live, or both and then deduplicated.
            if not await replay_committed():
                return
            while True:
                seconds_remaining = expiry_deadline - loop.time()
                if seconds_remaining <= 0:
                    await websocket.close(
                        code=4401, reason="websocket credentials expired"
                    )
                    return
                if subscription.overflowed:
                    authoritative_sequence = int(
                        driver_repository.driver_event_cursor()["last_sequence"]
                    )
                    await resync("client_queue_overflow", authoritative_sequence)
                    return
                try:
                    await asyncio.wait_for(
                        subscription.queue.get(),
                        timeout=min(
                            settings.websocket_keepalive_seconds, seconds_remaining
                        ),
                    )
                except asyncio.TimeoutError:
                    if loop.time() >= expiry_deadline:
                        await websocket.close(
                            code=4401, reason="websocket credentials expired"
                        )
                        return
                    await websocket.send_json(
                        {
                            "event_type": "stream.keepalive",
                            "stream": "driver.lifecycle",
                            "last_sequence": last_sent,
                        }
                    )
                    continue
                # A live frame is only a wake-up signal. Re-read the committed
                # outbox so ordering and payload authority never depend on fan-out.
                if not await replay_committed():
                    return
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe("driver.lifecycle", subscription)

    @app.websocket("/api/v1/ws")
    async def websocket_events(
        websocket: WebSocket,
        execution_id: str,
        after_sequence: int = Query(0, ge=0),
    ) -> None:
        protocols = websocket.scope.get("subprotocols", [])
        if len(protocols) != 2 or protocols[0] != "spell-auth":
            await websocket.close(code=4401, reason="invalid websocket credentials")
            return
        try:
            websocket_identity = decode_token(get_auth_config(), protocols[1])
        except AuthenticationError:
            await websocket.close(code=4401, reason="invalid websocket credentials")
            return
        seconds_until_expiry = websocket_identity.expires_at - time.time()
        if seconds_until_expiry <= 0:
            await websocket.close(code=4401, reason="websocket credentials expired")
            return
        loop = asyncio.get_running_loop()
        expiry_deadline = loop.time() + seconds_until_expiry
        try:
            execution = supervisor.get_execution(execution_id)
        except NotFoundError:
            await websocket.close(code=4404, reason="execution not found")
            return
        if loop.time() >= expiry_deadline:
            await websocket.close(code=4401, reason="websocket credentials expired")
            return
        await websocket.accept(subprotocol="spell-auth")
        if after_sequence > execution.next_sequence - 1:
            await websocket.send_json(
                {
                    "event_type": "stream.resync_required",
                    "execution_id": execution_id,
                    "payload": {"reason": "sequence_ahead_of_authority"},
                }
            )
            await websocket.close(code=4409, reason="snapshot resynchronization required")
            return
        subscription = hub.subscribe(execution_id)
        last_sent = after_sequence
        try:
            replay = supervisor.events_after(
                execution_id, after_sequence, settings.websocket_replay_limit + 1
            )
            if len(replay) > settings.websocket_replay_limit:
                await websocket.send_json(
                    {
                        "event_type": "stream.resync_required",
                        "execution_id": execution_id,
                        "payload": {"reason": "replay_limit_exceeded"},
                    }
                )
                await websocket.close(code=4409, reason="snapshot resynchronization required")
                return
            for item in replay:
                if loop.time() >= expiry_deadline:
                    await websocket.close(code=4401, reason="websocket credentials expired")
                    return
                await websocket.send_json(item)
                last_sent = item["sequence"]
            while True:
                seconds_remaining = expiry_deadline - loop.time()
                if seconds_remaining <= 0:
                    await websocket.close(code=4401, reason="websocket credentials expired")
                    return
                if subscription.overflowed:
                    await websocket.send_json(
                        {
                            "event_type": "stream.resync_required",
                            "execution_id": execution_id,
                            "payload": {"reason": "client_queue_overflow"},
                        }
                    )
                    await websocket.close(code=4409, reason="snapshot resynchronization required")
                    return
                try:
                    item = await asyncio.wait_for(
                        subscription.queue.get(),
                        timeout=min(settings.websocket_keepalive_seconds, seconds_remaining),
                    )
                except asyncio.TimeoutError:
                    if loop.time() >= expiry_deadline:
                        await websocket.close(code=4401, reason="websocket credentials expired")
                        return
                    await websocket.send_json({"event_type": "stream.keepalive", "execution_id": execution_id})
                    continue
                if item["sequence"] <= last_sent:
                    continue
                await websocket.send_json(item)
                last_sent = item["sequence"]
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(execution_id, subscription)

    return app


app = create_app()
