from __future__ import annotations

import threading
from pathlib import Path

import pytest

from backend.data_domain import (
    AuthorizationContext,
    DataAuthorizationError,
    DataConflictError,
    DataPermission,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    Role,
)
from backend.data_models import activate_data_schema
from backend.data_mutations import (
    DataMutationCoordinator,
    EvidenceCorruptionError,
    MutationBusyError,
    MutationEffect,
    MutationRequest,
)
from backend.database import create_database
from backend.tests.migration_support import run_migrations


def _http_request() -> MutationRequest:
    authorization = AuthorizationContext(
        HTTPCallerBinding(
            "operator-a",
            Role.OPERATOR,
            "session-binding-0001",
            "client-key-binding-0001",
        ),
        (
            DataPermission(
                ResourceFamily.SHARED, "PUT", "project-a", "namespace-a", 1
            ),
        ),
    )
    return MutationRequest.build(
        authorization,
        ResourceFamily.SHARED,
        "PUT",
        owner_id="project-a",
        resource_id="namespace-a",
        acl_revision=1,
        expected_revision=0,
        idempotency_key="http-mutation-1",
        body={"key": "alpha"},
    )


def _procedure_request(generation: int) -> MutationRequest:
    caller = ProcedureCallerBinding(
        "procedure-service", "execution-a", generation, "procedure-request-1"
    )
    authorization = AuthorizationContext(
        caller,
        (
            DataPermission(
                ResourceFamily.SHARED, "PUT", "project-a", "namespace-a", 1
            ),
        ),
    )
    return MutationRequest.build(
        authorization,
        ResourceFamily.SHARED,
        "PUT",
        owner_id="project-a",
        resource_id="namespace-a",
        acl_revision=1,
        expected_revision=0,
        idempotency_key=caller.deterministic_request_id,
        body={"key": "alpha"},
    )


def _effect(_session, _request) -> MutationEffect:
    return MutationEffect(
        result={"value": "settled"},
        prior_revision=0,
        new_revision=1,
        outcome="UPDATED",
    )


def _prepare_database(path: Path, *, busy_timeout_ms: int = 5_000):
    engine, sessions = create_database(
        f"sqlite:///{path.as_posix()}",
        sqlite_busy_timeout_ms=busy_timeout_ms,
    )
    return engine, sessions


def test_independent_sqlite_engines_settle_one_racing_mutation(tmp_path: Path) -> None:
    database = tmp_path / "independent-race.sqlite"
    first_engine, first_sessions = _prepare_database(database)
    run_migrations(first_engine)
    activate_data_schema(first_engine)
    second_engine, second_sessions = _prepare_database(database)
    first = DataMutationCoordinator(first_sessions)
    second = DataMutationCoordinator(second_sessions)
    request = _http_request()
    entered = threading.Event()
    release = threading.Event()
    calls = 0
    calls_lock = threading.Lock()
    results = []
    failures: list[BaseException] = []

    def mutate(session, current_request) -> MutationEffect:
        nonlocal calls
        with calls_lock:
            calls += 1
        entered.set()
        assert release.wait(timeout=3)
        return _effect(session, current_request)

    def run(coordinator: DataMutationCoordinator, callback) -> None:
        try:
            results.append(coordinator.execute(request, callback))
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    first_thread = threading.Thread(target=run, args=(first, mutate))
    second_thread = threading.Thread(target=run, args=(second, _effect))
    first_thread.start()
    assert entered.wait(timeout=3)
    second_thread.start()
    release.set()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)
    try:
        assert not first_thread.is_alive()
        assert not second_thread.is_alive()
        assert failures == []
        assert calls == 1
        assert len(results) == 2
        assert results[0].operation_id == results[1].operation_id
        assert {item.replayed for item in results} == {False, True}
    finally:
        first_engine.dispose()
        second_engine.dispose()


def test_sqlite_writer_timeout_is_a_typed_bounded_busy_outcome(tmp_path: Path) -> None:
    database = tmp_path / "bounded-busy.sqlite"
    owner_engine, _ = _prepare_database(database)
    run_migrations(owner_engine)
    activate_data_schema(owner_engine)
    contender_engine, contender_sessions = _prepare_database(
        database, busy_timeout_ms=50
    )
    coordinator = DataMutationCoordinator(contender_sessions)
    called = False

    def mutate(session, request) -> MutationEffect:
        nonlocal called
        called = True
        return _effect(session, request)

    try:
        with owner_engine.connect() as owner:
            owner.exec_driver_sql("BEGIN IMMEDIATE")
            with pytest.raises(MutationBusyError, match="writer is busy"):
                coordinator.execute(_http_request(), mutate)
            owner.rollback()
        assert called is False
    finally:
        owner_engine.dispose()
        contender_engine.dispose()


def test_procedure_settlement_identity_is_generation_bound(tmp_path: Path) -> None:
    engine, sessions = _prepare_database(tmp_path / "procedure-binding.sqlite")
    run_migrations(engine)
    activate_data_schema(engine)
    active_generation = 1

    def authorize(_session, binding: ProcedureCallerBinding) -> None:
        if binding.worker_generation != active_generation:
            raise DataAuthorizationError("procedure generation is not admitted")

    coordinator = DataMutationCoordinator(
        sessions, procedure_binding_check=authorize
    )
    original_request = _procedure_request(1)
    first = coordinator.execute(original_request, _effect)
    assert first.replayed is False

    with pytest.raises(DataAuthorizationError, match="not admitted"):
        coordinator.execute(_procedure_request(2), _effect)

    active_generation = 2

    def reject_cross_generation(_session, _request) -> MutationEffect:
        raise DataConflictError("cross-generation settlement replay denied")

    with pytest.raises(DataConflictError, match="cross-generation"):
        coordinator.execute(_procedure_request(2), reject_cross_generation)
    recovered = coordinator.recover_procedure_settlement(
        original_request,
        _procedure_request(2).authorization.caller,
    )
    assert recovered.operation_id == first.operation_id
    assert recovered.result == first.result
    assert recovered.replayed is True
    with pytest.raises(DataAuthorizationError, match="not admitted"):
        coordinator.execute(_procedure_request(1), _effect)

    with sessions() as session:
        from backend.data_models import DataAuditOutbox

        audit = session.query(DataAuditOutbox).one()
        audit.outcome = "CORRUPTED"
        session.commit()
    with pytest.raises(EvidenceCorruptionError, match="audit evidence differs"):
        coordinator.recover_procedure_settlement(
            original_request,
            _procedure_request(2).authorization.caller,
        )
    engine.dispose()
