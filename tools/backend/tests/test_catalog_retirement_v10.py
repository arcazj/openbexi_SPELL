from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url

import backend.migrations as migration_runner
from backend.migrations.versions import (
    v0009_procedure_catalog_availability as migration,
)
from backend.models import Execution, Prompt
from backend.operator_models import (
    ExecutionOperatorState,
    ProcedureCatalogAvailability,
    ProcedureCatalogEntry,
    ProcedureCatalogRevision,
    ProcedureSchedule,
)
from backend.operator_service import (
    OperatorAuthorizationError,
    OperatorConflictError,
    OperatorNotFoundError,
)
from backend.procedure_parser import Procedure
from backend.tests.migration_support import reset_test_database, run_migrations


POSTGRES_URL = os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL")
postgres_required = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="dedicated PostgreSQL migration database not configured",
)


def _migrate_to_predecessor(engine, monkeypatch) -> None:
    predecessor_index = next(
        index
        for index, item in enumerate(migration_runner.MIGRATIONS)
        if item.VERSION == migration.REQUIRED_PREDECESSOR
    )
    with monkeypatch.context() as migration_scope:
        migration_scope.setattr(
            migration_runner,
            "MIGRATIONS",
            migration_runner.MIGRATIONS[: predecessor_index + 1],
        )
        assert run_migrations(engine)[-1] == migration.REQUIRED_PREDECESSOR


def _seed_catalog_predecessor(engine) -> None:
    now = datetime.now(timezone.utc)
    entries = []
    revisions = []
    cases = (
        ("built-in", {}, "BUILT_IN", "ACTIVE"),
        (
            "promoted",
            {"development_bundle_digest": "d" * 64},
            "PROMOTED",
            "ACTIVE",
        ),
        (
            "historical",
            {"legacy_execution_snapshot": True},
            "HISTORICAL",
            "INACTIVE",
        ),
    )
    for ordinal, (name, properties, _source_kind, _state) in enumerate(cases, 1):
        catalog_id = f"pc-predecessor-{name}"
        entries.append(
            {
                "id": catalog_id,
                "procedure_ref": f"legacy/{name}",
                "name": name,
                "description": "predecessor catalog row",
                "entrypoint": f"{name}.spell.py",
                "current_revision": 1,
                "created_at": now,
                "updated_at": now,
            }
        )
        revisions.append(
            {
                "id": f"revision-{ordinal}",
                "catalog_id": catalog_id,
                "revision": 1,
                "source_digest": f"{ordinal}" * 64,
                "bundle_digest": f"{ordinal + 3}" * 64,
                "ir_version": "0.6",
                "source": "Log('retained')\n",
                "steps": [],
                "properties": properties,
                "created_by": "predecessor-test",
                "created_at": now,
            }
        )
    with engine.begin() as connection:
        connection.execute(ProcedureCatalogEntry.__table__.insert(), entries)
        connection.execute(ProcedureCatalogRevision.__table__.insert(), revisions)


def _assert_migration_backfill(engine, monkeypatch) -> None:
    _migrate_to_predecessor(engine, monkeypatch)
    _seed_catalog_predecessor(engine)

    with engine.begin() as connection:
        before_entries = connection.scalar(
            select(func.count()).select_from(ProcedureCatalogEntry)
        )
        before_revisions = connection.scalar(
            select(func.count()).select_from(ProcedureCatalogRevision)
        )
        migration.upgrade(connection)
        migration.verify(connection)
        rows = connection.execute(
            select(
                ProcedureCatalogEntry.procedure_ref,
                ProcedureCatalogAvailability.source_kind,
                ProcedureCatalogAvailability.state,
                ProcedureCatalogAvailability.availability_revision,
            )
            .join(
                ProcedureCatalogAvailability,
                ProcedureCatalogAvailability.catalog_id
                == ProcedureCatalogEntry.id,
            )
            .order_by(ProcedureCatalogEntry.procedure_ref)
        ).all()
        assert connection.scalar(
            select(func.count()).select_from(ProcedureCatalogEntry)
        ) == before_entries
        assert connection.scalar(
            select(func.count()).select_from(ProcedureCatalogRevision)
        ) == before_revisions

    assert rows == [
        ("legacy/built-in", "BUILT_IN", "ACTIVE", 1),
        ("legacy/historical", "HISTORICAL", "INACTIVE", 1),
        ("legacy/promoted", "PROMOTED", "ACTIVE", 1),
    ]


def test_catalog_availability_migration_backfills_sqlite(
    tmp_path: Path, monkeypatch
) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'catalog-v10.db').as_posix()}")
    _assert_migration_backfill(engine, monkeypatch)


@postgres_required
def test_catalog_availability_migration_backfills_postgresql(monkeypatch) -> None:
    assert POSTGRES_URL is not None
    assert make_url(POSTGRES_URL).database == "spell_migration_test"
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    reset_test_database(engine)
    try:
        _assert_migration_backfill(engine, monkeypatch)
    finally:
        reset_test_database(engine)
        engine.dispose()


def _controller_and_lease(client):
    service = client.app.state.operator_service
    procedure = client.app.state.catalog.get("integration")
    execution = client.app.state.supervisor.create_execution(
        procedure,
        actor="catalog-retirement-test",
        role="operator",
        reason="catalog retirement controller",
        idempotency_key="catalog-retirement-controller",
        automatic=False,
    )
    service.ensure_execution_projection(
        execution, actor="catalog-retirement-test", automatic=False
    )
    lease = service.acquire_control(
        execution.id,
        expected_execution_revision=execution.revision,
        actor="catalog-retirement-test",
        holder_session_id="catalog-retirement-session",
        client_instance_key_id="catalog-retirement-client",
        lease_seconds=60,
        idempotency_key="catalog-retirement-lease",
        reason="catalog retirement test control",
    )["control_lease"]
    return service, execution, lease


def _schedule_proof(lease: dict) -> dict:
    return {
        "actor": "catalog-retirement-test",
        "lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "holder_session_id": "catalog-retirement-session",
        "client_instance_key_id": "catalog-retirement-client",
    }


def _create_schedule(service, execution: Execution, lease: dict, catalog_id: str, key: str):
    return service.create_schedule(
        controller_execution_id=execution.id,
        schedule_type="RELATIVE",
        target="60.0",
        procedure_catalog_id=catalog_id,
        procedure_revision=None,
        context_id="simulator",
        arguments={"case": key},
        automatic=False,
        background_allowed=False,
        visible=True,
        misfire_policy="FIRE_ONCE",
        maximum_lateness_seconds=300,
        expected_execution_revision=execution.revision,
        idempotency_key=key,
        reason="catalog retirement schedule",
        **_schedule_proof(lease),
    )


def test_deleted_file_is_retired_while_pinned_schedule_and_history_remain(
    client, procedures_dir: Path
) -> None:
    service, controller, lease = _controller_and_lease(client)
    catalog_item = next(
        item for item in service.list_catalog() if item["procedure_ref"] == "pause"
    )
    catalog_id = catalog_item["id"]
    revision = catalog_item["revision"]
    pinned_schedule = _create_schedule(
        service,
        controller,
        lease,
        catalog_id,
        "catalog-retirement-pinned",
    )
    source_path = procedures_dir / "pause.spell.py"
    retained_source = source_path.read_bytes()
    source_path.unlink()

    service.sync_catalog(actor="catalog-retirement-test")

    assert catalog_id not in {item["id"] for item in service.list_catalog(sync=False)}
    history = service.catalog_history(catalog_id)
    assert history["procedure"]["availability_state"] == "INACTIVE"
    assert history["procedure"]["source_kind"] == "BUILT_IN"
    assert history["items"][0]["id"] == revision["id"]
    assert history["items"][0]["source"] == retained_source.decode("utf-8")

    with client.app.state.session_factory() as session:
        availability = session.get(ProcedureCatalogAvailability, catalog_id)
        assert availability.state == "INACTIVE"
        assert availability.availability_revision == 2
        assert session.get(ProcedureCatalogEntry, catalog_id) is not None
        assert session.get(ProcedureCatalogRevision, revision["id"]) is not None
        assert session.get(ProcedureSchedule, pinned_schedule["id"]) is not None

        current_entry, current_revision, rejection = (
            service._resolve_current_startproc_catalog(session, "pause")
        )
        assert (current_entry, current_revision, rejection) == (
            None,
            None,
            "PROCEDURE_NOT_FOUND",
        )
        pinned_entry, pinned_revision, rejection = service._resolve_startproc_catalog(
            session,
            "pause",
            pinned_closure=[
                {
                    "procedure_catalog_id": catalog_id,
                    "procedure_ref": "pause",
                    "entrypoint": catalog_item["entrypoint"],
                    "procedure_revision": revision["revision"],
                    "catalog_revision_id": revision["id"],
                    "bundle_digest": revision["bundle_digest"],
                }
            ],
        )
        assert rejection is None
        assert pinned_entry.id == catalog_id
        assert pinned_revision.id == revision["id"]

    with pytest.raises(OperatorNotFoundError, match="catalog entry"):
        _create_schedule(
            service,
            controller,
            lease,
            catalog_id,
            "catalog-retirement-new-rejected",
        )

    with client.app.state.session_factory() as session:
        session.get(ProcedureSchedule, pinned_schedule["id"]).target_at = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        session.commit()
    service.reconcile_schedules()
    fired = next(
        item
        for item in service.list_schedules()
        if item["id"] == pinned_schedule["id"]
    )
    assert fired["state"] == "FIRED"
    with client.app.state.session_factory() as session:
        child_projection = session.get(ExecutionOperatorState, fired["execution_id"])
        assert child_projection.catalog_revision_id == revision["id"]

    source_path.write_bytes(retained_source)
    service.sync_catalog(actor="catalog-retirement-test")
    restored = next(
        item for item in service.list_catalog(sync=False) if item["id"] == catalog_id
    )
    assert restored["current_revision"] == catalog_item["current_revision"]
    assert restored["revision"]["id"] == revision["id"]
    assert restored["availability_state"] == "ACTIVE"
    assert restored["availability_revision"] == 3


def test_promoted_catalog_entry_is_retired_and_reactivated_without_revision_churn(
    client, monkeypatch
) -> None:
    service = client.app.state.operator_service
    built_ins = service.catalog.list()
    source = "# @procedure promoted/catalog-retirement\nLog('promoted')\n"
    promoted = Procedure(
        id="promoted/catalog-retirement",
        name="catalog-retirement",
        description="promoted catalog retirement test",
        path=Path("catalog-retirement.spell.py"),
        source=source,
        sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        steps=({"type": "log", "message": "promoted", "line": 2},),
        ir_version="0.6",
        bundle_digest="a" * 64,
    )
    monkeypatch.setattr(service.catalog, "list", lambda: [*built_ins, promoted])
    service.sync_catalog(actor="catalog-retirement-test")
    active = next(
        item
        for item in service.list_catalog(sync=False)
        if item["procedure_ref"] == promoted.id
    )
    assert active["source_kind"] == "PROMOTED"

    monkeypatch.setattr(service.catalog, "list", lambda: list(built_ins))
    service.sync_catalog(actor="catalog-retirement-test")
    history = service.catalog_history(active["id"])
    assert history["procedure"]["availability_state"] == "INACTIVE"
    assert history["procedure"]["source_kind"] == "PROMOTED"
    assert len(history["items"]) == 1

    monkeypatch.setattr(service.catalog, "list", lambda: [*built_ins, promoted])
    service.sync_catalog(actor="catalog-retirement-test")
    restored = next(
        item
        for item in service.list_catalog(sync=False)
        if item["procedure_ref"] == promoted.id
    )
    assert restored["availability_state"] == "ACTIVE"
    assert restored["availability_revision"] == 3
    assert restored["revision"]["id"] == active["revision"]["id"]


def test_ir_v10_requires_fenced_legacy_adapters_and_static_command_identity(
    client,
) -> None:
    service = client.app.state.operator_service
    legacy_execution = Execution(
        procedure_id="ir-v10-legacy-guard",
        procedure_name="IR v0.10 legacy guard",
        procedure_hash="f" * 64,
        procedure_source="Log('guard')\n",
        steps=[],
        ir_version="0.10",
        total_steps=0,
        context_id="simulator",
        created_by="catalog-retirement-test",
        creation_idempotency_key="ir-v10-legacy-guard",
        state="ready",
    )
    prompt = Prompt(
        id=str(uuid.uuid4()),
        execution_id=legacy_execution.id,
        step_index=0,
        question="Fenced?",
        choices=["yes"],
        default_choice="yes",
    )
    with client.app.state.session_factory() as session:
        session.add(legacy_execution)
        session.flush()
        prompt.execution_id = legacy_execution.id
        session.add(prompt)
        session.commit()

    with pytest.raises(OperatorAuthorizationError, match="v0.6-plus executions"):
        service.execute_legacy_command_compatibility(
            legacy_execution.id,
            actor="catalog-retirement-test",
            role="operator",
            operation=lambda: pytest.fail("legacy command operation ran"),
        )
    with pytest.raises(OperatorAuthorizationError, match="v0.6-plus prompts"):
        service.execute_legacy_prompt_compatibility(
            prompt.id,
            actor="catalog-retirement-test",
            role="operator",
            operation=lambda: pytest.fail("legacy prompt operation ran"),
        )

    service, controller, lease = _controller_and_lease(client)
    with client.app.state.session_factory() as session:
        stored = session.get(Execution, controller.id)
        stored.ir_version = "0.10"
        stored.steps = [
            {"type": "log", "line": 1},
            {"type": "log", "line": 2},
        ]
        stored.total_steps = 2
        stored.current_step = 0
        session.commit()
    command_arguments = {
        "execution_id": controller.id,
        "command_type": "RUN",
        "expected_execution_revision": controller.revision,
        "actor": "catalog-retirement-test",
        "role": "operator",
        "reason": "IR v0.10 static command identity guard",
        "controller_lease_id": lease["id"],
        "expected_lease_revision": lease["revision"],
        "control_fencing_token": lease["control_fencing_token"],
        "holder_session_id": "catalog-retirement-session",
        "client_instance_key_id": "catalog-retirement-client",
        "target": {"line": 2},
    }
    with pytest.raises(OperatorConflictError, match="committed lexical frame"):
        service.accept_operator_command(
            idempotency_key="ir-v10-missing-frame",
            **command_arguments,
        )

    with client.app.state.session_factory() as session:
        stored = session.get(Execution, controller.id)
        stored.steps = [
            {
                "type": "log",
                "line": 1,
                "lexical_frame_id": "root",
                "reachability_id": "root:1",
            },
            {"type": "log", "line": 2, "lexical_frame_id": "root"},
        ]
        session.commit()
    with pytest.raises(OperatorConflictError, match="static reachability identity"):
        service.accept_operator_command(
            idempotency_key="ir-v10-missing-reachability",
            **command_arguments,
        )
