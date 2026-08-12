from __future__ import annotations

import multiprocessing
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from backend.database import create_database
from backend.driver_domain import CAPABILITY_MATRIX
from backend.driver_models import (
    DriverAuditEvent,
    DriverOperation,
    DriverOutboxEvent,
)
from backend.driver_repository import (
    DEFAULT_PROFILE_ID,
    CapabilitySpec,
    DriverRepository,
)
from backend.migrations import run_migrations


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _uid(value: int) -> str:
    return str(UUID(int=value))


def _capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(
        CapabilitySpec(
            service=item.service,
            method=item.method.value,
            mutability=item.mutability,
            modifiers=item.modifiers,
            formats=(item.format,),
            stream_support=item.stream_support,
        )
        for item in CAPABILITY_MATRIX
    )


def _initialize_database(path: Path) -> tuple[DriverRepository, object]:
    engine, factory = create_database(f"sqlite:///{path.as_posix()}")
    run_migrations(engine)
    repository = DriverRepository(factory)
    repository.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="process-fault-service-manager",
        correlation_id=_uid(800),
    )
    repository.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=_uid(801),
        contract_version="1.0",
        implementation_version="0.4.0-test",
        capabilities=_capabilities(),
        actor="process-fault-service-manager",
        correlation_id=_uid(802),
    )
    repository.record_host_state(
        _uid(801),
        "READY",
        expected_revision=0,
        actor="process-fault-service-manager",
        correlation_id=_uid(803),
        observed_at=NOW,
    )
    return repository, engine


def _accept_operation(repository: DriverRepository) -> dict[str, object]:
    return repository.accept_operation(
        operation_id=_uid(810),
        attempt_id=_uid(811),
        method="DrainHost",
        request_digest="a" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=_uid(801),
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="process-fault-api",
        correlation_id=_uid(812),
        deadline_at=NOW + timedelta(minutes=1),
    )


def _project_commit_crash_process(path: str, boundary: str) -> None:
    engine = create_engine(f"sqlite:///{Path(path).as_posix()}")

    class CrashSession(Session):
        def commit(self) -> None:
            if boundary == "before_project_commit":
                os._exit(81)
            super().commit()
            if boundary == "after_project_commit_before_reply":
                os._exit(82)

    repository = DriverRepository(
        sessionmaker(bind=engine, class_=CrashSession, expire_on_commit=False)
    )
    _accept_operation(repository)
    os._exit(83)


@pytest.mark.parametrize(
    ("boundary", "operation_count"),
    (
        ("before_project_commit", 0),
        ("after_project_commit_before_reply", 1),
    ),
)
def test_api_process_crash_at_project_commit_is_atomic_and_reconstructable(
    tmp_path: Path,
    boundary: str,
    operation_count: int,
) -> None:
    database_path = tmp_path / f"{boundary}.sqlite"
    repository, engine = _initialize_database(database_path)
    engine.dispose()

    process = multiprocessing.get_context("spawn").Process(
        target=_project_commit_crash_process,
        args=(str(database_path), boundary),
    )
    process.start()
    process.join(timeout=20)
    assert not process.is_alive()
    assert process.exitcode not in {None, 0}

    engine, factory = create_database(f"sqlite:///{database_path.as_posix()}")
    repository = DriverRepository(factory)
    try:
        with factory() as session:
            assert session.scalar(select(func.count()).select_from(DriverOperation)) == operation_count
            operation_audits = session.scalar(
                select(func.count())
                .select_from(DriverAuditEvent)
                .where(DriverAuditEvent.operation_id == _uid(810))
            )
            operation_outbox = session.scalar(
                select(func.count())
                .select_from(DriverOutboxEvent)
                .where(DriverOutboxEvent.aggregate_id == _uid(810))
            )
            assert operation_audits == operation_outbox == operation_count
        if operation_count == 0:
            assert repository.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"][
                "lifecycle_operations_per_host_in_use"
            ] == 0
            return

        durable = repository.get_operation(_uid(810))["operation"]
        assert durable["stage"] == "ACCEPTED"
        assert durable["certainty"] == "NO_EFFECT"
        replayed = _accept_operation(repository)
        assert replayed == durable
        with factory() as session:
            assert session.scalar(
                select(func.count())
                .select_from(DriverAuditEvent)
                .where(DriverAuditEvent.operation_id == _uid(810))
            ) == 1
            pending = session.scalars(
                select(DriverOutboxEvent).where(
                    DriverOutboxEvent.aggregate_id == _uid(810),
                    DriverOutboxEvent.published_at.is_(None),
                )
            ).all()
            assert len(pending) == 1
    finally:
        engine.dispose()


def _api_dispatch_crash_process(path: str, boundary: str) -> None:
    engine, factory = create_database(f"sqlite:///{Path(path).as_posix()}")
    repository = DriverRepository(factory)
    accepted = _accept_operation(repository)
    if boundary == "after_accept_before_dispatch":
        os._exit(84)
    repository.append_operation_transition(
        _uid(810),
        _uid(811),
        expected_revision=int(accepted["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="b" * 64,
        actor="process-fault-gateway",
        correlation_id=_uid(813),
    )
    os._exit(85)


@pytest.mark.parametrize(
    ("boundary", "stage", "certainty"),
    (
        ("after_accept_before_dispatch", "ACCEPTED", "NO_EFFECT"),
        ("after_dispatch", "DISPATCHED", "EFFECT_POSSIBLE"),
    ),
)
def test_api_process_crash_preserves_durable_dispatch_boundary(
    tmp_path: Path,
    boundary: str,
    stage: str,
    certainty: str,
) -> None:
    database_path = tmp_path / f"{boundary}.sqlite"
    _, engine = _initialize_database(database_path)
    engine.dispose()
    process = multiprocessing.get_context("spawn").Process(
        target=_api_dispatch_crash_process,
        args=(str(database_path), boundary),
    )
    process.start()
    process.join(timeout=20)
    assert not process.is_alive()
    assert process.exitcode not in {None, 0}

    engine, factory = create_database(f"sqlite:///{database_path.as_posix()}")
    try:
        repository = DriverRepository(factory)
        operation = repository.get_operation(_uid(810))["operation"]
        assert operation["stage"] == stage
        assert operation["certainty"] == certainty
        if stage == "DISPATCHED":
            operation = repository.append_operation_transition(
                _uid(810),
                _uid(811),
                expected_revision=int(operation["revision"]),
                stage="RECONCILING",
                certainty="EFFECT_POSSIBLE",
                disposition="PROCESS_RESTART",
                safe_error_code="UNAVAILABLE",
                safe_error_message="API restarted after durable dispatch",
                evidence_digest="c" * 64,
                actor="process-fault-reconciler",
                correlation_id=_uid(814),
            )
            assert operation["requires_reconciliation"] is True
        else:
            assert operation["requires_reconciliation"] is False
    finally:
        engine.dispose()
