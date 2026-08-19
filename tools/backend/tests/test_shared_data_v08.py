from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from sqlalchemy import func, select

from backend.data_domain import (
    AuthorizationContext,
    DataAuthorizationError,
    DataCapacityError,
    DataConflictError,
    DataPermission,
    HTTPCallerBinding,
    ResourceFamily,
    Role,
)
from backend.data_models import (
    DataAuditOutbox,
    DataMutationIdempotency,
    DataSchemaError,
    SharedEntry,
    SharedNamespace,
    activate_data_schema,
    canonical_virtual_root_configuration_bytes,
    verify_data_integrity,
)
from backend.data_repository import (
    CorruptNamespaceError,
    DataRepository,
    SharedScope,
)
from backend.data_values import make_typed_value
from backend.database import create_database
from backend.tests.migration_support import run_migrations


OWNER_ID = "shared-owner"
NAMESPACE_ID = "shared-namespace"
ACL_REVISION = 4


@pytest.fixture()
def repository(tmp_path: Path):
    engine, factory = create_database(
        f"sqlite:///{(tmp_path / 'shared.db').as_posix()}"
    )
    run_migrations(engine)
    activate_data_schema(engine)
    repo = DataRepository(
        factory,
        cursor_secret=b"shared-data-test-cursor-secret-01",
    )
    try:
        yield repo, factory
    finally:
        engine.dispose()


def _authorization(
    *operations: str,
    role: Role = Role.OPERATOR,
    owner_id: str = OWNER_ID,
    namespace_id: str = NAMESPACE_ID,
) -> AuthorizationContext:
    caller = HTTPCallerBinding(
        "pytest-operator",
        role,
        "shared-session-0001",
        "shared-client-key-0001",
    )
    return AuthorizationContext(
        caller,
        tuple(
            DataPermission(
                ResourceFamily.SHARED,
                operation,
                owner_id,
                namespace_id,
                ACL_REVISION,
            )
            for operation in operations
        ),
    )


def _create(repo: DataRepository) -> dict:
    return repo.create_shared_namespace(
        _authorization("CREATE_NAMESPACE"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        scope=SharedScope.PROJECT,
        acl_revision=ACL_REVISION,
        idempotency_key="create-shared-namespace-0001",
    )


def _put(
    repo: DataRepository,
    *,
    key: str,
    value,
    expected_revision: int,
    expected_entry_revision: int = 0,
) -> dict:
    return repo.put_shared_entry(
        _authorization("PUT"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        acl_revision=ACL_REVISION,
        expected_revision=expected_revision,
        key=key,
        expected_entry_revision=expected_entry_revision,
        idempotency_key=f"put-{key}-{expected_revision}",
        value=value,
    )


def test_shared_cas_enumeration_replay_and_evidence(repository) -> None:
    repo, factory = repository
    created = _create(repo)
    replayed_create = _create(repo)
    assert created["revision"] == 1
    assert replayed_create == {**created, "replayed": True}

    alpha = _put(
        repo,
        key="alpha",
        value=make_typed_value("INT64", 7),
        expected_revision=1,
    )
    replayed_alpha = _put(
        repo,
        key="alpha",
        value=make_typed_value("INT64", 7),
        expected_revision=1,
    )
    assert alpha["revision"] == 2
    assert replayed_alpha == {**alpha, "replayed": True}

    beta = _put(
        repo,
        key="beta",
        value=make_typed_value("STRING", "two"),
        expected_revision=2,
    )
    assert beta["entry_revision"] == 1

    page = repo.enumerate_shared_namespace(
        _authorization("ENUMERATE"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        acl_revision=ACL_REVISION,
        page_size=1,
    )
    assert [item["key"] for item in page["entries"]] == ["alpha"]
    assert page["next_cursor"] is not None

    alpha_read = repo.get_shared_entry(
        _authorization("GET"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        acl_revision=ACL_REVISION,
        key="alpha",
    )
    assert alpha_read["value"] == make_typed_value("INT64", 7)
    with pytest.raises(DataConflictError):
        _put(
            repo,
            key="alpha",
            value=make_typed_value("INT64", 8),
            expected_revision=2,
            expected_entry_revision=1,
        )

    _put(
        repo,
        key="gamma",
        value=make_typed_value("BOOLEAN", True),
        expected_revision=3,
    )
    with pytest.raises(DataConflictError) as stale:
        repo.enumerate_shared_namespace(
            _authorization("ENUMERATE"),
            owner_id=OWNER_ID,
            namespace_id=NAMESPACE_ID,
            acl_revision=ACL_REVISION,
            page_size=1,
            cursor=page["next_cursor"],
        )
    assert stale.value.code == "RESYNC_REQUIRED"

    with factory() as session:
        assert session.scalar(select(func.count()).select_from(DataMutationIdempotency)) == 4
        assert session.scalar(select(func.count()).select_from(DataAuditOutbox)) == 4
        rows = session.scalars(select(SharedEntry)).all()
        assert all(
            row.canonical_value is None or type(row.canonical_value) is bytes
            for row in rows
        )
        assert all(
            row.canonical_value is None
            or hashlib.sha256(row.canonical_value).hexdigest() == row.value_digest
            for row in rows
        )


def test_shared_authorization_precedes_namespace_lookup(repository) -> None:
    repo, _ = repository
    unauthorized = AuthorizationContext(
        HTTPCallerBinding(
            "pytest-viewer",
            Role.VIEWER,
            "shared-view-session-01",
            "shared-view-client-01",
        ),
        (),
    )
    with pytest.raises(DataAuthorizationError):
        repo.enumerate_shared_namespace(
            unauthorized,
            owner_id=OWNER_ID,
            namespace_id="does-not-exist",
            acl_revision=ACL_REVISION,
        )


def test_shared_clear_bound_and_namespace_tombstone(repository) -> None:
    repo, _ = repository
    _create(repo)
    _put(
        repo,
        key="alpha",
        value=make_typed_value("STRING", "one"),
        expected_revision=1,
    )
    _put(
        repo,
        key="beta",
        value=make_typed_value("STRING", "two"),
        expected_revision=2,
    )

    with pytest.raises(DataCapacityError):
        repo.clear_shared_namespace(
            _authorization("CLEAR"),
            owner_id=OWNER_ID,
            namespace_id=NAMESPACE_ID,
            acl_revision=ACL_REVISION,
            expected_revision=3,
            maximum_affected_entries=1,
            idempotency_key="clear-too-small-0001",
        )
    assert repo.read_shared_namespace(
        _authorization("GET"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        acl_revision=ACL_REVISION,
    )["revision"] == 3

    cleared = repo.clear_shared_namespace(
        _authorization("CLEAR"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        acl_revision=ACL_REVISION,
        expected_revision=3,
        maximum_affected_entries=2,
        idempotency_key="clear-shared-0001",
    )
    assert cleared["affected_entries"] == 2
    deleted = repo.delete_shared_namespace(
        _authorization("DELETE_NAMESPACE"),
        owner_id=OWNER_ID,
        namespace_id=NAMESPACE_ID,
        acl_revision=ACL_REVISION,
        expected_revision=4,
        idempotency_key="delete-shared-0001",
    )
    assert deleted["revision"] == 5


def test_shared_digest_corruption_fails_closed(repository) -> None:
    repo, factory = repository
    _create(repo)
    _put(
        repo,
        key="alpha",
        value=make_typed_value("STRING", "one"),
        expected_revision=1,
    )
    with factory() as session:
        head = session.get(
            SharedNamespace,
            {
                "scope": "PROJECT",
                "owner_id": OWNER_ID,
                "namespace_id": NAMESPACE_ID,
            },
        )
        head.current_content_digest = "0" * 64
        session.commit()
    with pytest.raises(CorruptNamespaceError):
        repo.get_shared_entry(
            _authorization("GET"),
            owner_id=OWNER_ID,
            namespace_id=NAMESPACE_ID,
            acl_revision=ACL_REVISION,
            key="alpha",
        )


def _assert_two_owner_namespace_identity(repo: DataRepository, factory) -> None:
    owners = ("shared-owner-a", "shared-owner-b")
    shared_id = "same-namespace-id"
    for index, owner_id in enumerate(owners):
        created = repo.create_shared_namespace(
            _authorization(
                "CREATE_NAMESPACE",
                owner_id=owner_id,
                namespace_id=shared_id,
            ),
            owner_id=owner_id,
            namespace_id=shared_id,
            scope=SharedScope.PROJECT,
            acl_revision=ACL_REVISION,
            idempotency_key=f"create-same-namespace-{index}",
        )
        assert created["revision"] == 1
        repo.put_shared_entry(
            _authorization("PUT", owner_id=owner_id, namespace_id=shared_id),
            owner_id=owner_id,
            namespace_id=shared_id,
            scope=SharedScope.PROJECT,
            acl_revision=ACL_REVISION,
            expected_revision=1,
            key="owner",
            expected_entry_revision=0,
            idempotency_key=f"put-same-namespace-{index}",
            value=make_typed_value("STRING", owner_id),
        )
    for owner_id in owners:
        value = repo.get_shared_entry(
            _authorization("GET", owner_id=owner_id, namespace_id=shared_id),
            owner_id=owner_id,
            namespace_id=shared_id,
            scope=SharedScope.PROJECT,
            acl_revision=ACL_REVISION,
            key="owner",
        )
        assert value["value"] == make_typed_value("STRING", owner_id)
    with factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(SharedNamespace)
            .where(SharedNamespace.namespace_id == shared_id)
        ) == 2
        assert session.scalar(
            select(func.count())
            .select_from(SharedEntry)
            .where(SharedEntry.namespace_id == shared_id)
        ) == 2


def test_two_owners_can_use_the_same_namespace_id_on_sqlite(repository) -> None:
    _assert_two_owner_namespace_identity(*repository)


def test_same_owner_scope_is_part_of_namespace_identity_and_evidence(repository) -> None:
    repo, factory = repository
    shared_id = "same-id-across-scopes"
    authorization = _authorization(
        "CREATE_NAMESPACE", owner_id=OWNER_ID, namespace_id=shared_id
    )
    for scope in (SharedScope.PROJECT, SharedScope.CONTEXT):
        created = repo.create_shared_namespace(
            authorization,
            owner_id=OWNER_ID,
            namespace_id=shared_id,
            scope=scope,
            acl_revision=ACL_REVISION,
            idempotency_key="same-idempotency-key-across-scopes",
        )
        assert created["scope"] == scope.value
        assert created["replayed"] is False
    with factory() as session:
        settlements = session.scalars(select(DataMutationIdempotency)).all()
        assert len(settlements) == 2
        assert len({row.resource_identity_digest for row in settlements}) == 2


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_two_owners_can_use_the_same_namespace_id_on_postgresql() -> None:
    from backend.tests.test_migrations import reset_migration_database

    engine, factory = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    reset_migration_database(engine)
    try:
        run_migrations(engine)
        activate_data_schema(engine)
        repo = DataRepository(
            factory, cursor_secret=b"postgres-shared-owner-test-000001"
        )
        _assert_two_owner_namespace_identity(repo, factory)
    finally:
        reset_migration_database(engine)
        engine.dispose()


@pytest.mark.parametrize("tamper", ["delete", "orphan", "binding", "payload"])
def test_integrity_requires_exact_settlement_audit_evidence(repository, tamper: str) -> None:
    repo, factory = repository
    _create(repo)
    with factory() as session:
        verify_data_integrity(session.connection())
        audit = session.scalar(select(DataAuditOutbox))
        assert audit is not None
        if tamper == "delete":
            session.delete(audit)
        elif tamper == "orphan":
            audit.operation_id = "orphaned-operation"
        elif tamper == "binding":
            audit.caller_binding_digest = "f" * 64
        else:
            payload = json.loads(audit.payload)
            payload["outcome"] = "TAMPERED"
            audit.payload = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            audit.payload_sha256 = hashlib.sha256(audit.payload).hexdigest()
        session.commit()
    with factory() as session, pytest.raises(DataSchemaError):
        verify_data_integrity(session.connection())


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_postgresql_latest_revision_reconstruction_uses_parent_row_locks() -> None:
    from backend.tests.test_migrations import reset_migration_database

    engine, factory = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    reset_migration_database(engine)
    try:
        run_migrations(engine)
        activate_data_schema(engine)
        repo = DataRepository(
            factory, cursor_secret=b"postgres-revision-lock-test-0001"
        )
        _create(repo)
        assert _put(
            repo,
            key="alpha",
            value=make_typed_value("STRING", "one"),
            expected_revision=1,
        )["revision"] == 2

        file_owner = "postgres-file-owner"
        root_id = "PROJECT_DATA"
        configuration = {
            "acl_revision": 1,
            "owner_id": file_owner,
            "quota_bytes": 4096,
            "quota_nodes": 16,
            "root_id": root_id,
            "root_kind": root_id,
        }
        configuration_digest = hashlib.sha256(
            canonical_virtual_root_configuration_bytes(configuration)
        ).hexdigest()
        repo.provision_virtual_root(
            root_id=root_id,
            root_kind=root_id,
            owner_id=file_owner,
            acl_revision=1,
            configuration_digest=configuration_digest,
            quota_bytes=4096,
            quota_nodes=16,
        )
        file_authorization = AuthorizationContext(
            HTTPCallerBinding(
                "pytest-operator",
                Role.OPERATOR,
                "postgres-file-session-01",
                "postgres-file-client-01",
            ),
            (
                DataPermission(
                    ResourceFamily.FILES,
                    "CREATE_DIRECTORY",
                    file_owner,
                    root_id,
                    1,
                ),
            ),
        )
        created = repo.create_virtual_directory(
            file_authorization,
            owner_id=file_owner,
            root_id=root_id,
            acl_revision=1,
            virtual_path="reports",
            expected_parent_revision=0,
            idempotency_key="postgres-create-directory",
            request_digest=hashlib.sha256(b"postgres-directory").hexdigest(),
        )
        assert created["revision"] == 1
    finally:
        reset_migration_database(engine)
        engine.dispose()
