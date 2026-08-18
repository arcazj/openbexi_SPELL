from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import func, select

from backend.data_domain import (
    AuthorizationContext,
    DataAuthorizationError,
    DataConflictError,
    DataPermission,
    DataValidationError,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    Role,
    caller_binding_digest,
)
from backend.data_models import (
    DataAuditOutbox,
    DataContainer,
    DataContainerRevision,
    DataMutationIdempotency,
    activate_data_schema,
)
from backend.data_repository import (
    ContainerVariableDefinition,
    DataRepository,
    runtime_container_definitions,
)
from backend.data_values import make_typed_value
from backend.database import create_database
from backend.tests.migration_support import run_migrations
from backend.models import Execution


OWNER_ID = "container-owner"
CONTAINER_ID = "durable-container"
ACL_REVISION = 3


def _execution(execution_id: str = "execution-0001") -> Execution:
    return Execution(
        id=execution_id,
        procedure_id="procedure-0001",
        procedure_name="Container procedure",
        procedure_hash="a" * 64,
        procedure_source="pass\n",
        steps=[],
        ir_version="0.8",
        variables={},
        context_id="simulator",
        created_by="pytest-operator",
        creation_idempotency_key="create-execution-0001",
        state="ready",
        revision=2,
        current_step=0,
        total_steps=0,
        worker_generation=0,
        next_sequence=1,
    )


def _binding(execution_id: str, generation: int, request_id: str) -> ProcedureCallerBinding:
    return ProcedureCallerBinding(
        "procedure-runtime", execution_id, generation, request_id
    )


def _binding_check(session, binding: ProcedureCallerBinding) -> None:
    execution = session.get(Execution, binding.execution_id)
    if (
        execution is None
        or execution.ir_version != "0.8"
        or execution.worker_generation != binding.worker_generation
    ):
        raise DataAuthorizationError("procedure generation is not admitted")


@pytest.fixture()
def repository(tmp_path: Path):
    engine, factory = create_database(
        f"sqlite:///{(tmp_path / 'containers.db').as_posix()}"
    )
    run_migrations(engine)
    activate_data_schema(engine)
    repo = DataRepository(
        factory,
        cursor_secret=b"container-test-cursor-secret-0001",
        procedure_binding_check=_binding_check,
    )
    try:
        yield repo, factory
    finally:
        engine.dispose()


def _http_authorization(
    *operations: str,
    owner_id: str = OWNER_ID,
    container_id: str = CONTAINER_ID,
) -> AuthorizationContext:
    caller = HTTPCallerBinding(
        "pytest-operator",
        Role.OPERATOR,
        "container-session-0001",
        "container-client-key-0001",
    )
    return AuthorizationContext(
        caller,
        tuple(
            DataPermission(
                ResourceFamily.CONTAINERS,
                operation,
                owner_id,
                container_id,
                ACL_REVISION,
            )
            for operation in operations
        ),
    )


def _procedure_authorization(
    binding: ProcedureCallerBinding, operation: str, container_id: str
) -> AuthorizationContext:
    return AuthorizationContext(
        binding,
        (
            DataPermission(
                ResourceFamily.CONTAINERS,
                operation,
                binding.execution_id,
                container_id,
                0,
            ),
        ),
    )


def test_runtime_mapping_preserves_declared_types_and_stable_identities() -> None:
    now = datetime(2026, 8, 17, 20, 30, tzinfo=timezone.utc)
    values = {
        "enabled": True,
        "epoch": now,
        "ratio": 1.25,
        "remaining": 500_000_000,
        "sequence": 7,
        "title": "qualified",
    }
    declared = {
        "enabled": "bool",
        "epoch": "DATETIME",
        "ratio": "float",
        "remaining": "RELTIME",
        "sequence": "int",
        "title": "str",
    }

    first = runtime_container_definitions(values, declared_types=declared)
    second = runtime_container_definitions(dict(reversed(tuple(values.items()))), declared_types=declared)

    assert first == second
    assert [item.name for item in first] == sorted(values)
    assert [item.declared_type for item in first] == [
        "BOOLEAN",
        "DATETIME",
        "FLOAT",
        "RELTIME",
        "LONG",
        "STRING",
    ]
    assert all(
        item.variable_id
        == "runtime." + hashlib.sha256(item.name.encode("utf-8")).hexdigest()
        for item in first
    )
    assert [item.value["type"] for item in first] == [
        "BOOLEAN",
        "UTC_DATETIME",
        "FINITE_DOUBLE",
        "REL_DURATION",
        "INT64",
        "STRING",
    ]

    with pytest.raises(DataValidationError):
        runtime_container_definitions({"unsupported": [1, 2]})
    with pytest.raises(DataValidationError):
        runtime_container_definitions({"sequence": 7}, declared_types={"sequence": "FLOAT"})


def test_runtime_mapping_accepts_exact_typed_envelopes_without_coercion() -> None:
    timestamp = make_typed_value(
        "UTC_DATETIME", datetime(2026, 8, 17, 21, 15, tzinfo=timezone.utc)
    )
    duration = make_typed_value("REL_DURATION", 750_000_000)
    definitions = runtime_container_definitions(
        {"at": timestamp, "delay": duration},
        declared_types={"at": "DATETIME", "delay": "RELTIME"},
    )
    assert [item.declared_type for item in definitions] == ["DATETIME", "RELTIME"]
    assert [item.value for item in definitions] == [timestamp, duration]

    with pytest.raises(DataValidationError):
        runtime_container_definitions(
            {"at": duration}, declared_types={"at": "DATETIME"}
        )
    with pytest.raises(DataValidationError):
        runtime_container_definitions(
            {"items": make_typed_value("LIST", ())},
            declared_types={"items": "LIST"},
        )


def test_procedure_resource_handle_binds_deterministic_request_id(repository) -> None:
    repo, _ = repository
    binding = _binding("execution-0001", 3, "creator-request")
    token = repo._procedure_handle(
        binding,
        ResourceFamily.CONTAINERS,
        owner_id=binding.execution_id,
        resource_id="container-handle",
        revision=1,
        content_digest="a" * 64,
    )
    decoded = repo.handles.decode(
        token, caller_digest=caller_binding_digest(binding)
    )
    assert decoded.resource_id == "container-handle"
    with pytest.raises(DataAuthorizationError):
        repo.handles.decode(
            token,
            caller_digest=caller_binding_digest(
                _binding("execution-0001", 3, "different-request")
            ),
        )


def test_container_mutation_replay_and_evidence_are_atomic(repository) -> None:
    repo, factory = repository
    created = repo.create_container(
        _http_authorization("CREATE"),
        owner_id=OWNER_ID,
        container_id=CONTAINER_ID,
        schema_revision=1,
        acl_revision=ACL_REVISION,
        idempotency_key="create-container-0001",
    )
    assert created["revision"] == 1

    variable = ContainerVariableDefinition(
        "variable-0001", "count", "LONG", make_typed_value("INT64", 7)
    )
    updated = repo.set_container_variable(
        _http_authorization("SET"),
        owner_id=OWNER_ID,
        container_id=CONTAINER_ID,
        acl_revision=ACL_REVISION,
        expected_revision=1,
        expected_variable_revision=0,
        idempotency_key="set-variable-0001",
        variable=variable,
    )
    replay = repo.set_container_variable(
        _http_authorization("SET"),
        owner_id=OWNER_ID,
        container_id=CONTAINER_ID,
        acl_revision=ACL_REVISION,
        expected_revision=1,
        expected_variable_revision=0,
        idempotency_key="set-variable-0001",
        variable=variable,
    )
    assert updated["revision"] == 2
    assert replay == {**updated, "replayed": True}

    current = repo.read_container(
        _http_authorization("READ"),
        owner_id=OWNER_ID,
        container_id=CONTAINER_ID,
        acl_revision=ACL_REVISION,
    )
    assert current["variables"] == [
        {
            "declared_type": "LONG",
            "name": "count",
            "revision": 1,
            "value": make_typed_value("INT64", 7),
            "value_digest": current["variables"][0]["value_digest"],
            "variable_id": "variable-0001",
        }
    ]

    with factory() as session:
        assert session.scalar(select(func.count()).select_from(DataMutationIdempotency)) == 2
        assert session.scalar(select(func.count()).select_from(DataAuditOutbox)) == 2
        rows = session.scalars(select(DataContainerRevision)).all()
        assert len(rows) == 2
        assert all(type(row.canonical_variables) is bytes for row in rows)


def test_committed_procedure_mutation_does_not_replay_under_new_generation(
    repository,
) -> None:
    repo, factory = repository
    execution = _execution()
    with factory() as session:
        session.add(execution)
        session.commit()

    container_id = "procedure-owned-container"
    request_id = "procedure-create-container-0001"
    binding0 = _binding(execution.id, 0, request_id)
    first = repo.create_container(
        _procedure_authorization(binding0, "CREATE", container_id),
        owner_id=execution.id,
        container_id=container_id,
        schema_revision=1,
        acl_revision=0,
        idempotency_key=request_id,
    )

    with factory() as session:
        current = session.get(Execution, execution.id)
        current.worker_generation = 1
        session.commit()

    with pytest.raises(DataAuthorizationError):
        repo.create_container(
            _procedure_authorization(binding0, "CREATE", container_id),
            owner_id=execution.id,
            container_id=container_id,
            schema_revision=1,
            acl_revision=0,
            idempotency_key=request_id,
        )

    binding1 = _binding(execution.id, 1, request_id)
    with pytest.raises(DataConflictError):
        repo.create_container(
            _procedure_authorization(binding1, "CREATE", container_id),
            owner_id=execution.id,
            container_id=container_id,
            schema_revision=1,
            acl_revision=0,
            idempotency_key=request_id,
        )
    assert first["replayed"] is False
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(DataContainer)) == 1
        assert session.scalar(select(func.count()).select_from(DataAuditOutbox)) == 1


def test_admission_assertion_survives_generation_advance_and_checkpoint_is_atomic(
    repository,
) -> None:
    repo, factory = repository
    execution = _execution()
    args = runtime_container_definitions({"mode": "safe"})
    ivars = runtime_container_definitions({"counter": 1})
    local = runtime_container_definitions({"status": "new"})
    binding0 = _binding(execution.id, 0, "admission-request-0001")

    with factory() as session:
        session.add(execution)
        session.flush()
        repo.stage_execution_admission(
            session, execution, binding0, args=args, ivars=ivars, local=local
        )
        session.commit()

    with factory() as session:
        current = session.get(Execution, execution.id)
        current.worker_generation = 1
        session.commit()

    binding1 = _binding(execution.id, 1, "admission-replay-0001")
    with factory() as session:
        current = session.get(Execution, execution.id)
        before = session.scalar(select(func.count()).select_from(DataContainerRevision))
        projection = repo.assert_execution_projections(
            session, current, binding1, args=args, ivars=ivars, local=local
        )
        session.commit()
    assert projection["projections"]["ARGS"]["revision"] == 1
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(DataContainerRevision)) == before

    next_ivars = runtime_container_definitions({"counter": 2})
    next_local = runtime_container_definitions({"status": "running"})
    with factory() as session:
        current = session.get(Execution, execution.id)
        revisions = repo.execution_projection_revisions(session, execution.id)
        repo.stage_execution_checkpoint(
            session,
            current,
            binding1,
            checkpoint_sequence=1,
            expected_ivars_revision=revisions["IVARS"],
            expected_local_revision=revisions["LOCAL"],
            ivars=next_ivars,
            local=next_local,
        )
        session.rollback()

    with factory() as session:
        assert repo.execution_projection_revisions(session, execution.id) == {
            "IVARS": 1,
            "LOCAL": 1,
        }

    with factory() as session:
        current = session.get(Execution, execution.id)
        committed = repo.stage_execution_checkpoint(
            session,
            current,
            binding1,
            checkpoint_sequence=1,
            expected_ivars_revision=1,
            expected_local_revision=1,
            ivars=next_ivars,
            local=next_local,
        )
        session.commit()
    assert committed["execution_revision"] == 2
    with factory() as session:
        assert repo.execution_projection_revisions(session, execution.id) == {
            "IVARS": 2,
            "LOCAL": 2,
        }
        args_head = session.get(
            DataContainer,
            {
                "kind": "ARGS",
                "owner_id": execution.id,
                "container_id": f"{execution.id}.ARGS",
            },
        )
        assert args_head.current_revision == 1


def _assert_two_owner_container_identity(repo: DataRepository, factory) -> None:
    owners = ("container-owner-a", "container-owner-b")
    shared_id = "same-container-id"
    for index, owner_id in enumerate(owners):
        result = repo.create_container(
            _http_authorization(
                "CREATE", owner_id=owner_id, container_id=shared_id
            ),
            owner_id=owner_id,
            container_id=shared_id,
            schema_revision=1,
            acl_revision=ACL_REVISION,
            idempotency_key=f"create-same-container-{index}",
        )
        assert result["revision"] == 1
    for owner_id in owners:
        projection = repo.read_container(
            _http_authorization(
                "READ", owner_id=owner_id, container_id=shared_id
            ),
            owner_id=owner_id,
            container_id=shared_id,
            acl_revision=ACL_REVISION,
        )
        assert projection["owner_id"] == owner_id
        assert projection["container_id"] == shared_id
    with factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(DataContainer)
            .where(DataContainer.container_id == shared_id)
        ) == 2
        assert session.scalar(
            select(func.count())
            .select_from(DataContainerRevision)
            .where(DataContainerRevision.container_id == shared_id)
        ) == 2


def test_two_owners_can_use_the_same_container_id_on_sqlite(repository) -> None:
    _assert_two_owner_container_identity(*repository)


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_two_owners_can_use_the_same_container_id_on_postgresql() -> None:
    from backend.tests.test_migrations import reset_migration_database

    engine, factory = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    reset_migration_database(engine)
    try:
        run_migrations(engine)
        activate_data_schema(engine)
        repo = DataRepository(
            factory, cursor_secret=b"postgres-container-owner-test-01"
        )
        _assert_two_owner_container_identity(repo, factory)
    finally:
        reset_migration_database(engine)
        engine.dispose()
