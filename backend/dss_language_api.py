"""Authenticated read-only access to durable nested DSS evidence, one bounded case at a time."""
from fastapi import Depends, HTTPException, Query
from sqlalchemy import select

from .auth import Identity, require_any_role
from .dss_language_broker import canonical, digest, validate_request, validate_subject_result
from .migrations.versions.v0011_dss_language_ledger import language_cases
from .models import Execution


def install_dss_language_evidence_api(app, *, identity_dependency, supervisor):
    @app.get("/api/v1/executions/{execution_id}/dss-driver-evidence")
    def driver_evidence(execution_id: str, epoch: str = Query(min_length=1, max_length=160),
                        packet_sha256: str = Query(default="", max_length=64, pattern="^([0-9a-f]{64})?$"),
                        identity: Identity = Depends(identity_dependency)):
        require_any_role(identity, {"operator", "viewer", "admin"})
        with supervisor.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise HTTPException(404, "execution was not found")
            context_id = execution.context_id
        runtime = getattr(supervisor, "dss_runtime", None)
        if runtime is None:
            raise HTTPException(409, "actual DSS runtime is unavailable")
        health = runtime.health(context_id, allow_stale=True)
        packets = runtime.await_packet(epoch,packet_sha256) if packet_sha256 else runtime.evidence(epoch)
        response = {"schema_version":"spell.dss.driver-evidence/1", "execution_id":execution_id,
            "health":health, "packets":[{**row, "packet":row["packet"].hex()} for row in packets]}
        if len(canonical(response)) > 16_000_000:
            raise HTTPException(409, "DSS driver evidence exceeds the scenario bound")
        return response

    @app.get("/api/v1/executions/{execution_id}/dss-language-evidence")
    def evidence(execution_id: str, subject: str | None = Query(default=None, max_length=200),
                 request_id: str | None = Query(default=None, max_length=36),
                 identity: Identity = Depends(identity_dependency)):
        require_any_role(identity, {"operator", "viewer", "admin"})
        with supervisor.session_factory() as session:
            execution = session.get(Execution, execution_id)
            if execution is None:
                raise HTTPException(404, "execution was not found")
            columns=list(language_cases.c) if subject is not None else [column for column in language_cases.c if column.name != "result"]
            query = select(*columns).where(language_cases.c.execution_id == execution_id)
            if request_id is not None:
                query = query.where(language_cases.c.request_id == request_id)
            if subject is not None:
                if request_id is None:
                    raise HTTPException(422, "subject reads require request_id")
                query = query.where(language_cases.c.subject == subject)
            rows = session.execute(query.order_by(language_cases.c.request_id, language_cases.c.subject)
                .limit(344)).mappings().all()
            if len(rows) > 343:
                raise HTTPException(409, "select one bounded request_id")
            items = []
            for row in rows:
                request = row["request"]
                validate_request(request, execution_id=execution_id, step_index=request.get("step_index"),
                    selection=request.get("selection"))
                if row["request_hash"] != digest(request):
                    raise HTTPException(409, "durable request digest differs")
                result = None
                if row["state"] == "SETTLED" and subject is not None:
                    result = validate_subject_result(row["subject"], row["result"])
                    if row["result_hash"] != digest(result):
                        raise HTTPException(409, "durable result digest differs")
                item = {"request":request, "subject":row["subject"], "state":row["state"],
                    "binding_sha256":row["binding_hash"], "result_sha256":row["result_hash"]}
                if subject is not None:
                    item["result"] = result
                items.append(item)
            response = {"schema_version":"spell.dss.language-evidence/1", "execution_id":execution_id,
                "procedure_sha256":execution.procedure_hash, "ir_version":execution.ir_version,
                "items":items}
            if len(canonical(response)) > 16_000_000:
                raise HTTPException(409, "DSS evidence exceeds the case bound")
            return response
