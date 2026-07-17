import asyncio
import hashlib
import json
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import select

from .auth import AuthConfig, AuthenticationError, authenticate_bearer, decode_token
from .config import Settings
from .database import create_database
from .events import EventHub
from .migrations import run_migrations
from .models import Command, Event, Execution, Prompt
from .procedure_parser import IR_VERSION, ProcedureCatalog, ProcedureValidationError
from .schemas import (
    CommandCreate,
    ExecutionCreate,
    ProcedureValidationRequest,
    PromptResponseCreate,
)
from .serialization import command_dict, event_dict, execution_dict, prompt_dict
from .supervisor import AuthorizationError, ConflictError, NotFoundError, Supervisor
from .version import PRODUCT_VERSION, REPORT_VERSION


@dataclass(frozen=True)
class Identity:
    actor: str
    role: str


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
    resolved_auth_config = auth_config

    def get_auth_config() -> AuthConfig:
        nonlocal resolved_auth_config
        if resolved_auth_config is None:
            resolved_auth_config = AuthConfig.from_env()
        return resolved_auth_config

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        app.state.auth_config = get_auth_config()
        run_migrations(engine)
        supervisor.reconcile_orphaned_executions()
        try:
            yield
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
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Idempotency-Key"],
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
    app.state.hub = hub
    app.state.auth_config = auth_config

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

    def translate_error(exc: Exception) -> HTTPException:
        if isinstance(exc, NotFoundError):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, AuthorizationError):
            return HTTPException(status_code=403, detail=str(exc))
        if isinstance(exc, ConflictError):
            return HTTPException(status_code=409, detail=str(exc))
        return HTTPException(status_code=500, detail="internal server error")

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

    @app.get("/api/v1/executions")
    def list_executions(_: IdentityDep, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
        return {"items": [execution_dict(item) for item in supervisor.list_executions(limit)]}

    @app.post("/api/v1/executions", status_code=202)
    def create_execution(
        request: ExecutionCreate,
        caller: IdentityDep,
        x_idempotency_key: Annotated[
            Optional[str], Header(min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        if request.context_id != "simulator":
            raise HTTPException(status_code=422, detail="v0.3 supports only the simulator context")
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
            )
            return {"execution": execution_dict(execution)}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="procedure not found") from exc
        except (AuthorizationError, ConflictError, NotFoundError) as exc:
            raise translate_error(exc) from exc

    @app.get("/api/v1/executions/{execution_id}/snapshot")
    def snapshot(execution_id: str, _: IdentityDep) -> dict[str, Any]:
        try:
            return supervisor.snapshot(execution_id)
        except NotFoundError as exc:
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
        request: CommandCreate,
        caller: IdentityDep,
        x_idempotency_key: Annotated[
            Optional[str], Header(min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        key = request.idempotency_key or x_idempotency_key
        if not key:
            raise HTTPException(status_code=422, detail="idempotency_key is required")
        try:
            result = supervisor.issue_command(
                execution_id=execution_id,
                command_type=request.type,
                expected_revision=request.expected_revision,
                idempotency_key=key,
                actor=caller.actor,
                role=caller.role,
                reason=request.reason,
                correlation_id=str(request.correlation_id) if request.correlation_id else None,
                payload={},
            )
            return {"command": command_dict(result)}
        except (AuthorizationError, ConflictError, NotFoundError) as exc:
            raise translate_error(exc) from exc

    @app.post("/api/v1/prompts/{prompt_id}/responses", status_code=202)
    def prompt_response(
        prompt_id: str,
        request: PromptResponseCreate,
        caller: IdentityDep,
        x_idempotency_key: Annotated[
            Optional[str], Header(min_length=1, max_length=200)
        ] = None,
    ) -> dict[str, Any]:
        key = request.idempotency_key or x_idempotency_key
        if not key:
            raise HTTPException(status_code=422, detail="idempotency_key is required")
        try:
            result = supervisor.respond_to_prompt(
                prompt_id=prompt_id,
                response=request.value,
                expected_revision=request.expected_revision,
                idempotency_key=key,
                actor=caller.actor,
                role=caller.role,
                reason=request.reason,
                correlation_id=str(request.correlation_id) if request.correlation_id else None,
            )
            return {"command": command_dict(result)}
        except (AuthorizationError, ConflictError, NotFoundError) as exc:
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
        serialized_events = [event_dict(item) for item in events]
        commands_data = [command_dict(item) for item in commands]
        integrity_input = {
            "execution_id": execution.id,
            "procedure_hash": execution.procedure_hash,
            "procedure_subset_version": execution_dict(execution)["procedure_subset_version"],
            "configuration_hash": execution_dict(execution)["configuration_hash"],
            "context_id": execution.context_id,
            "state": execution.state,
            "variables": execution.variables,
            "commands": commands_data,
            "prompts": [prompt_dict(item) for item in prompts],
            "events": serialized_events,
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
            "variables": execution.variables,
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
            "prompts": [prompt_dict(item) for item in prompts],
            "events": serialized_events,
            "integrity": {
                "algorithm": "sha256",
                "canonicalization": "json-sort-keys-v1",
                "digest": digest,
            },
        }

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
