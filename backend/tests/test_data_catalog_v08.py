from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from backend.data_domain import (
    AuthorizationContext,
    CatalogDependency,
    CatalogKind,
    CatalogNode,
    CatalogURI,
    CursorCodec,
    DataAuthorizationError,
    DataCapacityError,
    DataConflictError,
    DataPermission,
    DataValidationError,
    DependencyCycleError,
    DependencyDigestError,
    DependencyNotFoundError,
    DependencyRelationship,
    HTTPCallerBinding,
    LegacyCatalogURI,
    ResourceFamily,
    RevisionCursor,
    Role,
    pin_legacy_catalog_uri,
    resolve_catalog_closure,
)
from backend.data_models import (
    DataDependency,
    DataSchemaError,
    activate_data_schema,
    verify_data_integrity,
)
from backend.data_repository import (
    CatalogDependencyDefinition,
    CatalogEntryDefinition,
    CorruptCatalogError,
    DataRepository,
)
from backend.database import create_database
from backend.tests.migration_support import run_migrations


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


@pytest.fixture()
def repository(tmp_path: Path):
    engine, factory = create_database(
        f"sqlite:///{(tmp_path / 'catalogs.db').as_posix()}"
    )
    run_migrations(engine)
    activate_data_schema(engine)
    repo = DataRepository(
        factory, cursor_secret=b"catalog-test-cursor-secret-0000001"
    )
    try:
        yield repo, factory
    finally:
        engine.dispose()


def http_caller(role: Role = Role.ADMIN) -> HTTPCallerBinding:
    return HTTPCallerBinding(
        subject="subject-1",
        role=role,
        session_id="session-binding-0001",
        client_instance_key_id="client-binding-0001",
    )


def test_local_catalog_uri_is_exact_canonical_and_never_a_network_or_path() -> None:
    text = "spell+local:/catalogs/MMD/catalog.1/revisions/7/entries/item_1"
    parsed = CatalogURI.parse(text)
    assert parsed == CatalogURI(CatalogKind.MMD, "catalog.1", 7, "item_1")
    assert parsed.canonical == text

    rejected = (
        "file:///etc/passwd",
        "https://example.invalid/catalog",
        "spell+local://host/catalogs/MMD/c/revisions/1/entries/e",
        "spell+local:/catalogs/MMD/c/revisions/1/entries/e?query=x",
        "spell+local:/catalogs/MMD/c/revisions/1/entries/e#fragment",
        "spell+local:/catalogs/MMD/c/revisions/01/entries/e",
        "spell+local:/catalogs/mmd/c/revisions/1/entries/e",
        "spell+local:/catalogs/MMD/../revisions/1/entries/e",
        "spell+local:/catalogs/MMD/c/revisions/1/entries/%2e%2e",
        "spell+local:/catalogs/MMD/c/revisions/1/entries/a\\b",
        "spell+local:/catalogs/MMD/c/revisions/1/entries/e/extra",
    )
    for value in rejected:
        with pytest.raises(DataValidationError):
            CatalogURI.parse(value)


def test_legacy_uri_is_only_syntax_and_requires_an_explicit_immutable_pin() -> None:
    parsed = LegacyCatalogURI.parse("mmd://folder/name")
    assert parsed.target_kind is CatalogKind.MMD
    assert parsed.canonical == "mmd://folder/name"
    pinned = pin_legacy_catalog_uri(
        parsed.canonical,
        catalog_id="mmd-catalog",
        revision=3,
        content_digest=DIGEST_A,
        entry_id="entry-1",
    )
    assert pinned.uri.canonical == (
        "spell+local:/catalogs/MMD/mmd-catalog/revisions/3/entries/entry-1"
    )
    assert pinned.content_digest == DIGEST_A

    for value in (
        "MMD://folder/name",
        "mmd://user@folder/name",
        "mmd://folder:80/name",
        "mmd://folder/name/more",
        "mmd://folder/%6eame",
        "usr://folder/..",
        "http://folder/name",
    ):
        with pytest.raises(DataValidationError):
            LegacyCatalogURI.parse(value)


def test_dependency_closure_is_immutable_bounded_and_deterministic() -> None:
    nodes = (
        CatalogNode("root", CatalogKind.PROC, 2, DIGEST_A),
        CatalogNode("map", CatalogKind.MMD, 4, DIGEST_B),
        CatalogNode("dictionary", CatalogKind.USER_DICTIONARY, 1, DIGEST_C),
    )
    edges = (
        CatalogDependency(
            "edge-b",
            "map",
            4,
            "dictionary",
            1,
            DIGEST_C,
            DependencyRelationship.REFERENCES,
        ),
        CatalogDependency(
            "edge-a",
            "root",
            2,
            "map",
            4,
            DIGEST_B,
            DependencyRelationship.IMPORTS,
        ),
    )
    first = resolve_catalog_closure(("root", 2), reversed(nodes), reversed(edges))
    second = resolve_catalog_closure(("root", 2), nodes, edges)
    assert first == second
    assert [node.identity for node in first.nodes] == [
        ("dictionary", 1),
        ("map", 4),
        ("root", 2),
    ]
    assert [edge.dependency_id for edge in first.dependencies] == ["edge-a", "edge-b"]
    assert len(first.closure_digest) == 64


def test_dependency_closure_rejects_missing_digest_cycle_and_direct_overflow() -> None:
    root = CatalogNode("root", CatalogKind.PROC, 1, DIGEST_A)
    target = CatalogNode("target", CatalogKind.MMD, 1, DIGEST_B)
    edge = CatalogDependency(
        "edge",
        "root",
        1,
        "target",
        1,
        DIGEST_B,
        DependencyRelationship.IMPORTS,
    )
    with pytest.raises(DependencyNotFoundError):
        resolve_catalog_closure(("root", 1), (root,), (edge,))
    with pytest.raises(DependencyDigestError):
        resolve_catalog_closure(
            ("root", 1), (root, replace(target, content_digest=DIGEST_C)), (edge,)
        )

    reverse = CatalogDependency(
        "reverse",
        "target",
        1,
        "root",
        1,
        DIGEST_A,
        DependencyRelationship.REFERENCES,
    )
    with pytest.raises(DependencyCycleError):
        resolve_catalog_closure(("root", 1), (root, target), (edge, reverse))

    many_targets = tuple(
        CatalogNode(f"target-{index}", CatalogKind.MMD, 1, DIGEST_B)
        for index in range(129)
    )
    many_edges = tuple(
        CatalogDependency(
            f"edge-{index}",
            "root",
            1,
            node.catalog_id,
            1,
            DIGEST_B,
            DependencyRelationship.IMPORTS,
        )
        for index, node in enumerate(many_targets)
    )
    with pytest.raises(DataCapacityError):
        resolve_catalog_closure(("root", 1), (root, *many_targets), many_edges)


def test_authorization_is_exact_deny_by_default_and_role_bounded() -> None:
    permission = DataPermission(
        ResourceFamily.CATALOGS,
        "PUBLISH",
        owner_id="project-1",
        resource_id="catalog-1",
        acl_revision=2,
    )
    admin = AuthorizationContext(http_caller(), (permission,))
    admin.require(
        ResourceFamily.CATALOGS,
        "PUBLISH",
        owner_id="project-1",
        resource_id="catalog-1",
        acl_revision=2,
    )
    for changed in (
        {"owner_id": "project-2"},
        {"resource_id": "catalog-2"},
        {"acl_revision": 3},
    ):
        values = {
            "owner_id": "project-1",
            "resource_id": "catalog-1",
            "acl_revision": 2,
            **changed,
        }
        with pytest.raises(DataAuthorizationError):
            admin.require(ResourceFamily.CATALOGS, "PUBLISH", **values)

    operator = AuthorizationContext(http_caller(Role.OPERATOR), (permission,))
    with pytest.raises(DataAuthorizationError):
        operator.require(
            ResourceFamily.CATALOGS,
            "PUBLISH",
            owner_id="project-1",
            resource_id="catalog-1",
            acl_revision=2,
        )
    with pytest.raises(DataValidationError):
        HTTPCallerBinding(
            subject="subject-1",
            role="Admin",  # type: ignore[arg-type]
            session_id="session-binding-0001",
            client_instance_key_id="client-binding-0001",
        )


def test_cursor_is_opaque_tamper_evident_revision_and_authorization_bound() -> None:
    context = AuthorizationContext(
        http_caller(Role.VIEWER),
        (
            DataPermission(
                ResourceFamily.CATALOGS,
                "LIST",
                owner_id="project-1",
                acl_revision=1,
            ),
        ),
    )
    cursor = RevisionCursor(
        resource_identity="project-1",
        revision=7,
        authorization_digest=context.authorization_digest,
        last_key="name",
        last_identity="catalog-1",
    )
    codec = CursorCodec(b"cursor-secret" * 4)
    encoded = codec.encode(cursor)
    assert "project-1" not in encoded
    assert codec.decode(
        encoded,
        resource_identity="project-1",
        revision=7,
        authorization_digest=context.authorization_digest,
    ) == cursor

    replacement = "A" if encoded[-1] != "A" else "B"
    with pytest.raises(DataValidationError):
        codec.decode(
            encoded[:-1] + replacement,
            resource_identity="project-1",
            revision=7,
            authorization_digest=context.authorization_digest,
        )
    with pytest.raises(DataConflictError) as stale:
        codec.decode(
            encoded,
            resource_identity="project-1",
            revision=8,
            authorization_digest=context.authorization_digest,
        )
    assert stale.value.code == "RESYNC_REQUIRED"
    with pytest.raises(DataAuthorizationError):
        codec.decode(
            encoded,
            resource_identity="project-1",
            revision=7,
            authorization_digest="d" * 64,
        )


def _catalog_authorization(
    owner_id: str,
    *permissions: tuple[str, str],
    acl_revision: int = 2,
) -> AuthorizationContext:
    return AuthorizationContext(
        http_caller(),
        tuple(
            DataPermission(
                ResourceFamily.CATALOGS,
                operation,
                owner_id,
                catalog_id,
                acl_revision,
            )
            for operation, catalog_id in permissions
        ),
    )


def _publish_leaf(
    repo: DataRepository,
    *,
    owner_id: str,
    catalog_id: str,
    idempotency_key: str,
) -> dict:
    return repo.publish_catalog(
        _catalog_authorization(owner_id, ("PUBLISH", catalog_id)),
        owner_id=owner_id,
        catalog_id=catalog_id,
        kind=CatalogKind.MMD,
        schema_version="1.0",
        acl_revision=2,
        expected_revision=0,
        idempotency_key=idempotency_key,
        entries=(
            CatalogEntryDefinition(
                "entry-1", "entry.one", {"name": catalog_id, "version": 1}
            ),
        ),
    )


def _dependency(target: dict, *, dependency_id: str = "dependency-1"):
    return CatalogDependencyDefinition(
        dependency_id,
        target["catalog_id"],
        target["revision"],
        target["content_digest"],
        DependencyRelationship.IMPORTS,
    )


def test_publish_requires_exact_target_read_and_rejects_cross_owner(repository) -> None:
    repo, _ = repository
    owner_id = "catalog-owner"
    target = _publish_leaf(
        repo,
        owner_id=owner_id,
        catalog_id="target-catalog",
        idempotency_key="publish-target-0001",
    )
    dependency = _dependency(target)
    assert repo.catalog_dependency_target_ids((dependency, dependency)) == (
        "target-catalog",
    )

    with pytest.raises(DataAuthorizationError):
        repo.publish_catalog(
            _catalog_authorization(owner_id, ("PUBLISH", "source-catalog")),
            owner_id=owner_id,
            catalog_id="source-catalog",
            kind=CatalogKind.PROC,
            schema_version="1.0",
            acl_revision=2,
            expected_revision=0,
            idempotency_key="publish-source-without-read-0001",
            entries=(),
            dependencies=(dependency,),
        )

    source = repo.publish_catalog(
        _catalog_authorization(
            owner_id,
            ("PUBLISH", "source-catalog"),
            ("READ", "target-catalog"),
        ),
        owner_id=owner_id,
        catalog_id="source-catalog",
        kind=CatalogKind.PROC,
        schema_version="1.0",
        acl_revision=2,
        expected_revision=0,
        idempotency_key="publish-source-0001",
        entries=(),
        dependencies=(dependency,),
    )
    assert source["revision"] == 1
    republished = repo.publish_catalog(
        _catalog_authorization(
            owner_id,
            ("PUBLISH", "source-catalog"),
            ("READ", "target-catalog"),
        ),
        owner_id=owner_id,
        catalog_id="source-catalog",
        kind=CatalogKind.PROC,
        schema_version="1.0",
        acl_revision=2,
        expected_revision=1,
        idempotency_key="publish-source-0002",
        entries=(),
        dependencies=(dependency,),
    )
    assert republished["revision"] == 2

    foreign = _publish_leaf(
        repo,
        owner_id="foreign-owner",
        catalog_id="foreign-target",
        idempotency_key="publish-foreign-target-0001",
    )
    with pytest.raises(DataAuthorizationError):
        repo.publish_catalog(
            AuthorizationContext(
                http_caller(),
                (
                    DataPermission(
                        ResourceFamily.CATALOGS,
                        "PUBLISH",
                        owner_id,
                        "cross-owner-source",
                        2,
                    ),
                    DataPermission(
                        ResourceFamily.CATALOGS,
                        "READ",
                        "foreign-owner",
                        "foreign-target",
                        2,
                    ),
                ),
            ),
            owner_id=owner_id,
            catalog_id="cross-owner-source",
            kind=CatalogKind.PROC,
            schema_version="1.0",
            acl_revision=2,
            expected_revision=0,
            idempotency_key="publish-cross-owner-source-0001",
            entries=(),
            dependencies=(_dependency(foreign),),
        )


@pytest.mark.parametrize("tamper", ["delete", "relationship"])
def test_catalog_read_and_startup_reject_missing_or_tampered_edge(
    repository, tamper: str
) -> None:
    repo, factory = repository
    owner_id = "catalog-owner"
    target = _publish_leaf(
        repo,
        owner_id=owner_id,
        catalog_id="target-catalog",
        idempotency_key="publish-target-for-tamper-0001",
    )
    source = repo.publish_catalog(
        _catalog_authorization(
            owner_id,
            ("PUBLISH", "source-catalog"),
            ("READ", "target-catalog"),
        ),
        owner_id=owner_id,
        catalog_id="source-catalog",
        kind=CatalogKind.PROC,
        schema_version="1.0",
        acl_revision=2,
        expected_revision=0,
        idempotency_key="publish-source-for-tamper-0001",
        entries=(),
        dependencies=(_dependency(target),),
    )
    with factory() as session:
        edge = session.scalar(
            select(DataDependency).where(
                DataDependency.source_catalog_id == "source-catalog"
            )
        )
        assert edge is not None
        if tamper == "delete":
            session.delete(edge)
        else:
            edge.relationship = DependencyRelationship.REFERENCES.value
        session.commit()

    read_authorization = _catalog_authorization(
        owner_id, ("READ", "source-catalog")
    )
    with pytest.raises(CorruptCatalogError):
        repo.read_catalog_revision(
            read_authorization,
            owner_id=owner_id,
            catalog_id="source-catalog",
            acl_revision=2,
            revision=source["revision"],
        )
    with factory() as session, pytest.raises(DataSchemaError):
        verify_data_integrity(session.connection())


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_catalog_dependency_graph_is_verified_on_postgresql() -> None:
    from backend.tests.test_migrations import reset_migration_database

    engine, factory = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    reset_migration_database(engine)
    try:
        run_migrations(engine)
        activate_data_schema(engine)
        repo = DataRepository(
            factory, cursor_secret=b"postgres-catalog-graph-test-00001"
        )
        owner_id = "catalog-owner"
        target = _publish_leaf(
            repo,
            owner_id=owner_id,
            catalog_id="target-catalog",
            idempotency_key="postgres-publish-target-0001",
        )
        source = repo.publish_catalog(
            _catalog_authorization(
                owner_id,
                ("PUBLISH", "source-catalog"),
                ("READ", "target-catalog"),
            ),
            owner_id=owner_id,
            catalog_id="source-catalog",
            kind=CatalogKind.PROC,
            schema_version="1.0",
            acl_revision=2,
            expected_revision=0,
            idempotency_key="postgres-publish-source-0001",
            entries=(),
            dependencies=(_dependency(target),),
        )
        projection = repo.read_catalog_revision(
            _catalog_authorization(owner_id, ("READ", "source-catalog")),
            owner_id=owner_id,
            catalog_id="source-catalog",
            acl_revision=2,
            revision=source["revision"],
        )
        assert projection["closure_digest"] == source["closure_digest"]
    finally:
        reset_migration_database(engine)
        engine.dispose()
