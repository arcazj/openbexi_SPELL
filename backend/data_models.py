"""Durable models and schema fingerprint for the bounded v0.8 data service."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Table

from .database import Base
from .data_domain import (
    CatalogDependency,
    CatalogKind,
    CatalogNode,
    CatalogURI,
    DataDomainError,
    DependencyRelationship,
    require_identifier,
    require_nfc_string,
    resolve_catalog_closure,
)
from .data_state import (
    decode_container_state,
    decode_dictionary_state,
    validate_container_history,
    validate_dictionary_history,
    validate_shared_history,
)
from .data_values import (
    TypedValueError,
    decode_stored_typed_value,
    strict_json_loads,
)
from .dictionary_exchange import (
    DictionaryEntry,
    build_db_document,
    parse_dictionary_document,
)
from .models import Execution


MIGRATION_ID = "0007_data_local_service"
SCHEMA_FINGERPRINT_VERSION = "spell.data.schema-fingerprint/1"
MAX_CONTRACT_INTEGER = (1 << 63) - 1


def _digest_check(column: str, name: str) -> CheckConstraint:
    return CheckConstraint(f"length({column}) = 64", name=name)


class DataSchemaFingerprint(Base):
    __tablename__ = "data_schema_fingerprints"
    __table_args__ = (
        CheckConstraint(
            "backend_kind IN ('sqlite','postgresql')", name="ck_data_schema_backend"
        ),
        _digest_check("canonical_schema_sha256", "ck_data_schema_digest"),
    )

    migration_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    backend_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    canonical_schema_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    activated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )


class DataCatalog(Base):
    __tablename__ = "data_catalogs"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('SCDB','GDB','PROC','MMD','USER_DICTIONARY')",
            name="ck_data_catalog_kind",
        ),
        CheckConstraint(
            f"current_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_catalog_revision",
        ),
        CheckConstraint(
            f"acl_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_catalog_acl_revision",
        ),
        _digest_check("current_content_digest", "ck_data_catalog_digest"),
        UniqueConstraint("kind", "owner_id", "catalog_id", name="uq_data_catalog_owner"),
    )

    catalog_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    authorization_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    current_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    acl_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DataCatalogRevision(Base):
    __tablename__ = "data_catalog_revisions"
    __table_args__ = (
        CheckConstraint(
            f"revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_catalog_revision_positive",
        ),
        _digest_check("content_digest", "ck_data_catalog_revision_digest"),
        _digest_check("closure_digest", "ck_data_catalog_closure_digest"),
        CheckConstraint(
            "length(canonical_content) BETWEEN 2 AND 16777216",
            name="ck_data_catalog_revision_content_length",
        ),
    )

    catalog_id: Mapped[str] = mapped_column(
        ForeignKey("data_catalogs.catalog_id", ondelete="RESTRICT"), primary_key=True
    )
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    closure_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_by_principal: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DataCatalogEntry(Base):
    __tablename__ = "data_catalog_entries"
    __table_args__ = (
        ForeignKeyConstraint(
            ("catalog_id", "catalog_revision"),
            ("data_catalog_revisions.catalog_id", "data_catalog_revisions.revision"),
            ondelete="RESTRICT",
            name="fk_data_catalog_entry_revision",
        ),
        _digest_check("content_digest", "ck_data_catalog_entry_digest"),
        CheckConstraint(
            "length(canonical_entry) BETWEEN 2 AND 1048576",
            name="ck_data_catalog_entry_content_length",
        ),
        UniqueConstraint(
            "catalog_id",
            "catalog_revision",
            "qualified_name",
            name="uq_data_catalog_entry_name",
        ),
    )

    catalog_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    catalog_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    entry_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    qualified_name: Mapped[str] = mapped_column(String(256), nullable=False)
    local_uri: Mapped[str] = mapped_column(String(1024), nullable=False)
    canonical_entry: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)


class DataDependency(Base):
    __tablename__ = "data_dependencies"
    __table_args__ = (
        ForeignKeyConstraint(
            ("source_catalog_id", "source_revision"),
            ("data_catalog_revisions.catalog_id", "data_catalog_revisions.revision"),
            ondelete="RESTRICT",
            name="fk_data_dependency_source",
        ),
        ForeignKeyConstraint(
            ("target_catalog_id", "target_revision"),
            ("data_catalog_revisions.catalog_id", "data_catalog_revisions.revision"),
            ondelete="RESTRICT",
            name="fk_data_dependency_target",
        ),
        CheckConstraint(
            "relationship IN ('IMPORTS','REFERENCES','MAPS_TO')",
            name="ck_data_dependency_relationship",
        ),
        CheckConstraint("ordinal >= 0", name="ck_data_dependency_ordinal"),
        _digest_check("target_content_digest", "ck_data_dependency_digest"),
        UniqueConstraint(
            "source_catalog_id",
            "source_revision",
            "target_catalog_id",
            "target_revision",
            "relationship",
            name="uq_data_dependency_edge",
        ),
    )

    dependency_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_catalog_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    target_catalog_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    target_content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    relationship: Mapped[str] = mapped_column(String(20), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)


class DataDictionary(Base):
    __tablename__ = "data_dictionaries"
    __table_args__ = (
        CheckConstraint(
            f"current_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_dictionary_revision",
        ),
        CheckConstraint(
            f"acl_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_dictionary_acl_revision",
        ),
        _digest_check("current_content_digest", "ck_data_dictionary_digest"),
    )

    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    dictionary_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    authorization_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    current_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    acl_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    tombstoned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DataDictionaryRevision(Base):
    __tablename__ = "data_dictionary_revisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("owner_id", "dictionary_id"),
            ("data_dictionaries.owner_id", "data_dictionaries.dictionary_id"),
            ondelete="RESTRICT",
            name="fk_data_dictionary_revision_head",
        ),
        CheckConstraint(
            f"revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_dictionary_revision_positive",
        ),
        CheckConstraint(
            f"base_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_dictionary_base_revision",
        ),
        CheckConstraint("source_format IN ('DB','IMP')", name="ck_data_dictionary_format"),
        CheckConstraint(
            "caller_binding_kind IN ('HTTP_MUTATION','PROCEDURE_RUNTIME')",
            name="ck_data_dictionary_caller_kind",
        ),
        CheckConstraint(
            "original_byte_length BETWEEN 0 AND 16777216",
            name="ck_data_dictionary_original_length",
        ),
        CheckConstraint(
            "length(original_bytes) = original_byte_length",
            name="ck_data_dictionary_original_bytes",
        ),
        CheckConstraint(
            "length(canonical_entry_state) BETWEEN 2 AND 16777216",
            name="ck_data_dictionary_entry_state_length",
        ),
        CheckConstraint(
            "length(canonical_source_document) BETWEEN 2 AND 16777216",
            name="ck_data_dictionary_source_document_length",
        ),
        _digest_check("content_digest", "ck_data_dictionary_revision_digest"),
        _digest_check("original_bytes_sha256", "ck_data_dictionary_original_digest"),
        _digest_check(
            "canonical_entry_state_sha256", "ck_data_dictionary_entry_state_digest"
        ),
        _digest_check(
            "canonical_source_document_sha256",
            "ck_data_dictionary_source_document_digest",
        ),
        _digest_check("caller_binding_digest", "ck_data_dictionary_caller_digest"),
    )

    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    dictionary_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    base_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_format: Mapped[str] = mapped_column(String(8), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_entry_state: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    canonical_entry_state_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_source_document: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    canonical_source_document_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    original_media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    original_byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    original_bytes_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    original_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    actor_principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    caller_binding_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    caller_binding_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DataContainer(Base):
    __tablename__ = "data_containers"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('LOCAL','ARGS','IVARS','DATA_CONTAINER')",
            name="ck_data_container_kind",
        ),
        CheckConstraint(
            f"current_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_revision",
        ),
        CheckConstraint(
            f"schema_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_schema_revision",
        ),
        CheckConstraint(
            f"acl_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_acl_revision",
        ),
        CheckConstraint(
            "(kind IN ('LOCAL','ARGS','IVARS') "
            "AND execution_id IS NOT NULL "
            "AND admission_worker_generation IS NOT NULL "
            "AND admission_execution_revision IS NOT NULL "
            "AND admission_binding_digest IS NOT NULL) OR "
            "(kind = 'DATA_CONTAINER' "
            "AND execution_id IS NULL "
            "AND admission_worker_generation IS NULL "
            "AND admission_execution_revision IS NULL "
            "AND admission_binding_digest IS NULL)",
            name="ck_data_container_execution_owner",
        ),
        CheckConstraint(
            "(kind = 'ARGS' AND mutable = FALSE AND current_revision = 1 "
            "AND tombstoned = FALSE) OR (kind <> 'ARGS' AND mutable = TRUE)",
            name="ck_data_container_args_immutable",
        ),
        CheckConstraint(
            f"admission_worker_generation IS NULL OR "
            f"admission_worker_generation BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_worker_generation",
        ),
        CheckConstraint(
            f"admission_execution_revision IS NULL OR "
            f"admission_execution_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_execution_revision",
        ),
        _digest_check("current_content_digest", "ck_data_container_digest"),
        CheckConstraint(
            "admission_binding_digest IS NULL OR length(admission_binding_digest) = 64",
            name="ck_data_container_admission_digest",
        ),
    )

    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    container_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("executions.id", ondelete="RESTRICT")
    )
    admission_worker_generation: Mapped[int | None] = mapped_column(BigInteger)
    admission_execution_revision: Mapped[int | None] = mapped_column(BigInteger)
    admission_binding_digest: Mapped[str | None] = mapped_column(String(64))
    current_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    schema_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    acl_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mutable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    tombstoned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DataContainerRevision(Base):
    __tablename__ = "data_container_revisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ("kind", "owner_id", "container_id"),
            (
                "data_containers.kind",
                "data_containers.owner_id",
                "data_containers.container_id",
            ),
            ondelete="RESTRICT",
            name="fk_data_container_revision_head",
        ),
        CheckConstraint(
            f"revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_revision_positive",
        ),
        CheckConstraint(
            f"schema_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_revision_schema",
        ),
        CheckConstraint(
            f"checkpoint_sequence IS NULL OR "
            f"checkpoint_sequence BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_checkpoint_sequence",
        ),
        CheckConstraint(
            f"execution_revision IS NULL OR "
            f"execution_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_commit_execution_revision",
        ),
        CheckConstraint(
            f"worker_generation IS NULL OR "
            f"worker_generation BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_container_commit_worker_generation",
        ),
        CheckConstraint(
            "(checkpoint_sequence IS NULL AND execution_revision IS NULL "
            "AND worker_generation IS NULL) OR "
            "(checkpoint_sequence IS NOT NULL AND execution_revision IS NOT NULL "
            "AND worker_generation IS NOT NULL)",
            name="ck_data_container_checkpoint_shape",
        ),
        _digest_check("content_digest", "ck_data_container_revision_digest"),
        _digest_check("commit_binding_digest", "ck_data_container_commit_digest"),
        CheckConstraint(
            "length(canonical_variables) BETWEEN 2 AND 16777216",
            name="ck_data_container_revision_content_length",
        ),
    )

    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    container_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    schema_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    checkpoint_sequence: Mapped[int | None] = mapped_column(BigInteger)
    execution_revision: Mapped[int | None] = mapped_column(BigInteger)
    worker_generation: Mapped[int | None] = mapped_column(BigInteger)
    commit_binding_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_variables: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tombstoned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    created_by_principal: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class SharedNamespace(Base):
    __tablename__ = "shared_namespaces"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('PROJECT','CONTEXT','EXECUTION')",
            name="ck_shared_namespace_scope",
        ),
        CheckConstraint(
            f"current_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_shared_namespace_revision",
        ),
        CheckConstraint(
            f"acl_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_shared_namespace_acl_revision",
        ),
        _digest_check("current_content_digest", "ck_shared_namespace_digest"),
    )

    scope: Mapped[str] = mapped_column(String(20), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    namespace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    current_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    acl_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    tombstoned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class SharedEntry(Base):
    __tablename__ = "shared_entries"
    __table_args__ = (
        ForeignKeyConstraint(
            ("scope", "owner_id", "namespace_id"),
            (
                "shared_namespaces.scope",
                "shared_namespaces.owner_id",
                "shared_namespaces.namespace_id",
            ),
            ondelete="RESTRICT",
            name="fk_shared_entry_namespace",
        ),
        CheckConstraint(
            f"revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_shared_entry_revision",
        ),
        _digest_check("value_digest", "ck_shared_entry_digest"),
        CheckConstraint(
            "canonical_value IS NULL OR length(canonical_value) BETWEEN 2 AND 1048576",
            name="ck_shared_entry_value_length",
        ),
        CheckConstraint(
            "(tombstoned = TRUE AND canonical_value IS NULL) OR "
            "(tombstoned = FALSE AND canonical_value IS NOT NULL)",
            name="ck_shared_entry_tombstone",
        ),
        UniqueConstraint(
            "scope",
            "owner_id",
            "namespace_id",
            "key",
            "revision",
            name="uq_shared_entry_key_revision",
        ),
    )

    scope: Mapped[str] = mapped_column(String(20), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    namespace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    entry_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    key: Mapped[str] = mapped_column(String(512), nullable=False)
    canonical_value: Mapped[bytes | None] = mapped_column(LargeBinary)
    value_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    tombstoned: Mapped[bool] = mapped_column(Boolean, nullable=False)
    updated_by_principal: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class VirtualFileRoot(Base):
    __tablename__ = "virtual_file_roots"
    __table_args__ = (
        CheckConstraint(
            "root_kind IN ('PROCEDURE_DATA','PROJECT_DATA','EXECUTION_SCRATCH')",
            name="ck_virtual_file_root_kind",
        ),
        CheckConstraint(
            f"acl_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_virtual_file_root_acl_revision",
        ),
        CheckConstraint(
            f"current_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_virtual_file_root_revision",
        ),
        CheckConstraint(
            "quota_bytes BETWEEN 0 AND 268435456", name="ck_virtual_file_root_quota_bytes"
        ),
        CheckConstraint(
            "quota_nodes BETWEEN 0 AND 10000", name="ck_virtual_file_root_quota_nodes"
        ),
        CheckConstraint(
            "used_bytes BETWEEN 0 AND quota_bytes", name="ck_virtual_file_root_used_bytes"
        ),
        CheckConstraint(
            "used_nodes BETWEEN 0 AND quota_nodes", name="ck_virtual_file_root_used_nodes"
        ),
        CheckConstraint(
            "reserved_bytes BETWEEN 0 AND quota_bytes",
            name="ck_virtual_file_root_reserved_bytes",
        ),
        CheckConstraint(
            "reserved_nodes BETWEEN 0 AND quota_nodes",
            name="ck_virtual_file_root_reserved_nodes",
        ),
        CheckConstraint(
            "(reservation_id IS NULL AND reservation_binding_digest IS NULL "
            "AND reserved_bytes = 0 AND reserved_nodes = 0) OR "
            "(reservation_id IS NOT NULL AND reservation_binding_digest IS NOT NULL)",
            name="ck_virtual_file_root_reservation_shape",
        ),
        _digest_check("content_digest", "ck_virtual_file_root_digest"),
        _digest_check("configuration_digest", "ck_virtual_file_root_config_digest"),
        _digest_check(
            "reservation_binding_digest", "ck_virtual_file_root_reservation_digest"
        ),
    )

    root_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    root_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    acl_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    quota_nodes: Mapped[int] = mapped_column(Integer, nullable=False)
    used_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    used_nodes: Mapped[int] = mapped_column(Integer, nullable=False)
    reservation_id: Mapped[str | None] = mapped_column(String(32))
    reservation_binding_digest: Mapped[str | None] = mapped_column(String(64))
    reserved_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    reserved_nodes: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class VirtualFile(Base):
    __tablename__ = "virtual_files"
    __table_args__ = (
        CheckConstraint(
            f"revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_virtual_file_revision",
        ),
        CheckConstraint(
            "node_type IN ('FILE','DIRECTORY')", name="ck_virtual_file_node_type"
        ),
        CheckConstraint(
            "encoding IS NULL OR encoding IN ('UTF8_TEXT','BINARY')",
            name="ck_virtual_file_encoding",
        ),
        CheckConstraint(
            "byte_length BETWEEN 0 AND 16777216", name="ck_virtual_file_byte_length"
        ),
        CheckConstraint(
            "(node_type = 'DIRECTORY' AND encoding IS NULL AND byte_length = 0) OR "
            "(node_type = 'FILE' AND encoding IS NOT NULL)",
            name="ck_virtual_file_shape",
        ),
        _digest_check("content_digest", "ck_virtual_file_digest"),
    )

    root_id: Mapped[str] = mapped_column(
        ForeignKey("virtual_file_roots.root_id", ondelete="RESTRICT"), primary_key=True
    )
    virtual_path: Mapped[str] = mapped_column(String(1024), primary_key=True)
    revision: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    parent_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    node_type: Mapped[str] = mapped_column(String(16), nullable=False)
    encoding: Mapped[str | None] = mapped_column(String(16))
    byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    tombstoned: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("FALSE")
    )
    created_by_principal: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DataMutationIdempotency(Base):
    __tablename__ = "data_mutation_idempotency"
    __table_args__ = (
        CheckConstraint(
            "caller_binding_kind IN ('HTTP_MUTATION','PROCEDURE_RUNTIME')",
            name="ck_data_idempotency_caller_kind",
        ),
        CheckConstraint("state IN ('PENDING','COMMITTED')", name="ck_data_idempotency_state"),
        CheckConstraint(
            "response_status IS NULL OR response_status BETWEEN 100 AND 599",
            name="ck_data_idempotency_status",
        ),
        CheckConstraint(
            "(state = 'PENDING' AND response_status IS NULL "
            "AND result_payload IS NULL AND result_payload_sha256 IS NULL "
            "AND committed_at_database_time IS NULL) OR "
            "(state = 'COMMITTED' AND response_status IS NOT NULL "
            "AND result_payload IS NOT NULL AND result_payload_sha256 IS NOT NULL "
            "AND committed_at_database_time IS NOT NULL)",
            name="ck_data_idempotency_settlement_shape",
        ),
        _digest_check("caller_binding_digest", "ck_data_idempotency_caller_digest"),
        _digest_check("resource_identity_digest", "ck_data_idempotency_resource_digest"),
        _digest_check("request_digest", "ck_data_idempotency_request_digest"),
        CheckConstraint(
            "result_payload_sha256 IS NULL OR length(result_payload_sha256) = 64",
            name="ck_data_idempotency_result_digest",
        ),
        CheckConstraint(
            "result_payload IS NULL OR length(result_payload) BETWEEN 2 AND 1048576",
            name="ck_data_idempotency_result_length",
        ),
        UniqueConstraint(
            "actor_principal_id",
            "caller_binding_digest",
            "operation",
            "resource_identity_digest",
            "idempotency_key",
            name="uq_data_idempotency_identity",
        ),
    )

    settlement_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    caller_binding_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    caller_binding_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_identity_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    result_payload: Mapped[bytes | None] = mapped_column(LargeBinary)
    result_payload_sha256: Mapped[str | None] = mapped_column(String(64))
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    committed_at_database_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class DataAuditOutbox(Base):
    __tablename__ = "data_audit_outbox"
    __table_args__ = (
        CheckConstraint("delivery_attempts >= 0", name="ck_data_outbox_attempts"),
        CheckConstraint(
            f"prior_revision IS NULL OR "
            f"prior_revision BETWEEN 0 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_audit_prior_revision",
        ),
        CheckConstraint(
            f"new_revision IS NULL OR "
            f"new_revision BETWEEN 1 AND {MAX_CONTRACT_INTEGER}",
            name="ck_data_audit_new_revision",
        ),
        _digest_check("caller_binding_digest", "ck_data_audit_caller_digest"),
        _digest_check("resource_identity_digest", "ck_data_audit_resource_digest"),
        _digest_check("request_digest", "ck_data_audit_request_digest"),
        _digest_check("payload_sha256", "ck_data_audit_payload_digest"),
        CheckConstraint(
            "length(payload) BETWEEN 2 AND 1048576",
            name="ck_data_audit_payload_length",
        ),
        UniqueConstraint("operation_id", name="uq_data_audit_operation"),
    )

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    request_session_binding: Mapped[str | None] = mapped_column(String(128))
    client_instance_key_binding: Mapped[str | None] = mapped_column(String(128))
    caller_binding_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_family: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_identity_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(80), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    prior_revision: Mapped[int | None] = mapped_column(BigInteger)
    new_revision: Mapped[int | None] = mapped_column(BigInteger)
    outcome: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at_database_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    published_at_database_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


Index(
    "ix_data_catalog_revision_digest",
    DataCatalogRevision.catalog_id,
    DataCatalogRevision.content_digest,
)
Index(
    "ix_data_catalog_entry_uri",
    DataCatalogEntry.catalog_id,
    DataCatalogEntry.catalog_revision,
    DataCatalogEntry.local_uri,
)
Index(
    "ix_data_dependency_source",
    DataDependency.source_catalog_id,
    DataDependency.source_revision,
    DataDependency.ordinal,
)
Index(
    "ix_data_dictionary_revision_digest",
    DataDictionaryRevision.owner_id,
    DataDictionaryRevision.dictionary_id,
    DataDictionaryRevision.content_digest,
)
Index(
    "ix_data_container_owner",
    DataContainer.owner_id,
    DataContainer.kind,
    DataContainer.container_id,
)
Index(
    "ix_shared_namespace_owner",
    SharedNamespace.owner_id,
    SharedNamespace.scope,
    SharedNamespace.namespace_id,
)
Index(
    "ix_shared_entry_enumeration",
    SharedEntry.scope,
    SharedEntry.owner_id,
    SharedEntry.namespace_id,
    SharedEntry.key,
    SharedEntry.entry_id,
    SharedEntry.revision,
)
Index(
    "ix_virtual_file_enumeration",
    VirtualFile.root_id,
    VirtualFile.parent_path,
    VirtualFile.virtual_path,
    VirtualFile.revision,
)
Index(
    "ix_data_idempotency_state",
    DataMutationIdempotency.state,
    DataMutationIdempotency.created_at_database_time,
)
Index(
    "ix_data_outbox_pending",
    DataAuditOutbox.published_at_database_time,
    DataAuditOutbox.created_at_database_time,
)


data_schema_fingerprints = DataSchemaFingerprint.__table__
data_catalogs = DataCatalog.__table__
data_catalog_revisions = DataCatalogRevision.__table__
data_catalog_entries = DataCatalogEntry.__table__
data_dependencies = DataDependency.__table__
data_dictionaries = DataDictionary.__table__
data_dictionary_revisions = DataDictionaryRevision.__table__
data_containers = DataContainer.__table__
data_container_revisions = DataContainerRevision.__table__
shared_namespaces = SharedNamespace.__table__
shared_entries = SharedEntry.__table__
virtual_file_roots = VirtualFileRoot.__table__
virtual_files = VirtualFile.__table__
data_mutation_idempotency = DataMutationIdempotency.__table__
data_audit_outbox = DataAuditOutbox.__table__

DATA_TABLES: tuple[Table, ...] = (
    data_catalogs,
    data_schema_fingerprints,
    data_catalog_revisions,
    data_catalog_entries,
    data_dependencies,
    data_dictionaries,
    data_dictionary_revisions,
    data_containers,
    data_container_revisions,
    shared_namespaces,
    shared_entries,
    virtual_file_roots,
    virtual_files,
    data_mutation_idempotency,
    data_audit_outbox,
)
DATA_TABLE_NAMES = tuple(table.name for table in DATA_TABLES)


class DataSchemaError(RuntimeError):
    pass


VirtualFileReader = Callable[[str, str, str], bytes]


def _canonical_data_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_shared_namespace_state_bytes(
    entries: Iterable[Mapping[str, Any]],
) -> bytes:
    live = sorted(
        (
            {
                "entry_id": item["entry_id"],
                "key": item["key"],
                "revision": item["revision"],
                "value_digest": item["value_digest"],
            }
            for item in entries
            if not item["tombstoned"]
        ),
        key=lambda item: (
            item["key"].encode("utf-8"),
            item["entry_id"].encode("ascii"),
        ),
    )
    return _canonical_data_json_bytes(
        {"entries": live, "schema_version": "spell.data.shared-state/1"}
    )


def canonical_virtual_root_configuration_bytes(root: Mapping[str, Any]) -> bytes:
    return _canonical_data_json_bytes(
        {
            "acl_revision": root["acl_revision"],
            "owner_id": root["owner_id"],
            "quota_bytes": root["quota_bytes"],
            "quota_nodes": root["quota_nodes"],
            "root_id": root["root_id"],
            "root_kind": root["root_kind"],
            "schema_version": "spell.data.virtual-root-configuration/1",
        }
    )


def canonical_virtual_root_state_bytes(
    root_id: str, nodes: Iterable[Mapping[str, Any]]
) -> bytes:
    live = sorted(
        (
            {
                "byte_length": item["byte_length"],
                "content_digest": item["content_digest"],
                "encoding": item["encoding"],
                "node_type": item["node_type"],
                "parent_path": item["parent_path"],
                "revision": item["revision"],
                "virtual_path": item["virtual_path"],
            }
            for item in nodes
            if not item["tombstoned"]
        ),
        key=lambda item: item["virtual_path"].encode("utf-8"),
    )
    return _canonical_data_json_bytes(
        {
            "nodes": live,
            "root_id": root_id,
            "schema_version": "spell.data.virtual-root-state/1",
        }
    )


def _type_token(type_: Any) -> str:
    if isinstance(type_, LargeBinary):
        return "BYTES"
    if isinstance(type_, String):
        return f"STRING:{type_.length or 0}"
    if isinstance(type_, BigInteger):
        return "BIGINT"
    if isinstance(type_, Integer):
        return "INTEGER"
    if isinstance(type_, Boolean):
        return "BOOLEAN"
    if isinstance(type_, DateTime):
        return "UTC_DATETIME"
    return type(type_).__name__.upper()


def _normalized_sql(value: Any) -> str:
    normalized = re.sub(r"\s+", " ", str(value).strip()).upper()
    while normalized.startswith("(") and normalized.endswith(")"):
        depth = 0
        encloses_all = True
        for index, character in enumerate(normalized):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(normalized) - 1:
                    encloses_all = False
                    break
        if not encloses_all or depth != 0:
            break
        normalized = normalized[1:-1].strip()
    normalized = re.sub(r"::(?:BOOLEAN|BOOL)\b", "", normalized)
    if normalized in {"0", "'FALSE'", "FALSE"}:
        return "FALSE"
    if normalized in {"1", "'TRUE'", "TRUE"}:
        return "TRUE"
    return normalized


def _canonical_check_sql(value: Any) -> str:
    """Normalize SQLite and PostgreSQL renderings of the same check AST."""

    normalized = _normalized_sql(value)
    normalized = re.sub(r"'(-?[0-9]+)'::BIGINT", r"\1", normalized)
    normalized = re.sub(
        r"::(?:TEXT\[\]|CHARACTER VARYING|TEXT|BIGINT)", "", normalized
    )
    normalized = re.sub(
        r"\b([A-Z_][A-Z0-9_]*) = ANY \(ARRAY\[(.*?)\]\)",
        lambda match: f"{match.group(1)} IN ({match.group(2)})",
        normalized,
    )
    normalized = re.sub(r"\s*,\s*", ",", normalized)

    protected: list[str] = []
    protected_indexes: dict[str, int] = {}

    def protect(match: re.Match[str]) -> str:
        expression = match.group(0)
        index = protected_indexes.get(expression)
        if index is None:
            index = len(protected)
            protected_indexes[expression] = index
            protected.append(expression)
        return f"__ATOM{index}__"

    # Parentheses inside functions and IN lists are scalar syntax. Protect them
    # before parsing the remaining parentheses as Boolean grouping.
    normalized = re.sub(r"\bLENGTH\([^()]*\)", protect, normalized)
    normalized = re.sub(r"\bIN \([^()]*\)", protect, normalized)
    expression = r"(?:__ATOM[0-9]+__|[A-Z_][A-Z0-9_]*)"
    bound = r"(?:[A-Z_][A-Z0-9_]*|-?[0-9]+)"
    normalized = re.sub(
        rf"(?P<expression>{expression}) BETWEEN (?P<lower>{bound}) "
        rf"AND (?P<upper>{bound})",
        lambda match: (
            f"{match.group('expression')} BETWEEN_RANGE "
            f"{match.group('lower')} THROUGH {match.group('upper')}"
        ),
        normalized,
    )
    normalized = re.sub(
        rf"(?P<expression>{expression}) >= (?P<lower>{bound}) AND "
        rf"(?P=expression) <= (?P<upper>{bound})",
        lambda match: (
            f"{match.group('expression')} BETWEEN_RANGE "
            f"{match.group('lower')} THROUGH {match.group('upper')}"
        ),
        normalized,
    )

    tokens = [
        token.strip()
        for token in re.split(r"(\(|\)|\bAND\b|\bOR\b)", normalized)
        if token.strip()
    ]
    position = 0

    def parse_primary() -> tuple[str, Any]:
        nonlocal position
        if position >= len(tokens):
            raise DataSchemaError("check constraint expression is incomplete")
        if tokens[position] == "(":
            position += 1
            result = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise DataSchemaError("check constraint grouping is invalid")
            position += 1
            return result
        if tokens[position] in {"AND", "OR", ")"}:
            raise DataSchemaError("check constraint atom is invalid")
        result = ("ATOM", tokens[position])
        position += 1
        return result

    def parse_and() -> tuple[str, Any]:
        nonlocal position
        children = [parse_primary()]
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            children.append(parse_primary())
        return children[0] if len(children) == 1 else ("AND", children)

    def parse_or() -> tuple[str, Any]:
        nonlocal position
        children = [parse_and()]
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            children.append(parse_and())
        return children[0] if len(children) == 1 else ("OR", children)

    tree = parse_or()
    if position != len(tokens):
        raise DataSchemaError("check constraint expression has trailing syntax")

    def render(node: tuple[str, Any]) -> str:
        if node[0] == "ATOM":
            return node[1]
        flattened: list[tuple[str, Any]] = []
        for child in node[1]:
            if child[0] == node[0]:
                flattened.extend(child[1])
            else:
                flattened.append(child)
        return f"{node[0]}[{'|'.join(render(child) for child in flattened)}]"

    canonical = render(tree)
    for index, scalar in enumerate(protected):
        canonical = canonical.replace(f"__ATOM{index}__", scalar)
    return canonical


def _default_token(value: Any) -> str | None:
    if value is None:
        return None
    argument = getattr(value, "arg", value)
    return _normalized_sql(argument)


def _model_schema_payload() -> dict[str, Any]:
    tables: list[dict[str, Any]] = []
    for table in sorted(DATA_TABLES, key=lambda item: item.name):
        columns = [
            {
                "name": column.name,
                "type": _type_token(column.type),
                "nullable": column.nullable,
                "primary_key": column.primary_key,
                "server_default": column.server_default is not None,
            }
            for column in table.columns
        ]
        foreign_keys = sorted(
            {
                (
                    tuple(column.name for column in constraint.columns),
                    constraint.referred_table.name,
                    tuple(element.column.name for element in constraint.elements),
                    (constraint.ondelete or "RESTRICT").upper(),
                )
                for constraint in table.foreign_key_constraints
            }
        )
        unique = sorted(
            (
                constraint.name,
                tuple(column.name for column in constraint.columns),
            )
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        )
        checks = sorted(
            (constraint.name, _canonical_check_sql(constraint.sqltext))
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint)
        )
        indexes = sorted(
            (
                index.name,
                bool(index.unique),
                tuple(column.name for column in index.columns),
            )
            for index in table.indexes
        )
        tables.append(
            {
                "name": table.name,
                "columns": columns,
                "primary_key": [column.name for column in table.primary_key.columns],
                "foreign_keys": foreign_keys,
                "unique": unique,
                "checks": checks,
                "indexes": indexes,
            }
        )
    return {"schema_version": SCHEMA_FINGERPRINT_VERSION, "tables": tables}


CANONICAL_SCHEMA_BYTES = json.dumps(
    _model_schema_payload(),
    ensure_ascii=True,
    allow_nan=False,
    separators=(",", ":"),
    sort_keys=True,
).encode("ascii")
CANONICAL_SCHEMA_SHA256 = hashlib.sha256(CANONICAL_SCHEMA_BYTES).hexdigest()


def schema_validation_errors(bind: Connection | Engine) -> list[str]:
    """Compare the physical v0.8 schema with the accepted model shape."""

    inspector = inspect(bind)
    errors: list[str] = []
    actual_names = set(inspector.get_table_names())
    expected_names = set(DATA_TABLE_NAMES)
    relevant_names = {
        name
        for name in actual_names
        if name.startswith(("data_", "shared_", "virtual_file"))
    }
    if relevant_names != expected_names:
        errors.append(
            "v0.8 table inventory differs: "
            f"missing={sorted(expected_names - relevant_names)!r}, "
            f"extra={sorted(relevant_names - expected_names)!r}"
        )
    for expected in DATA_TABLES:
        if expected.name not in actual_names:
            continue
        actual_columns = {
            item["name"]: item for item in inspector.get_columns(expected.name)
        }
        if set(actual_columns) != set(expected.columns.keys()):
            errors.append(f"{expected.name} column inventory differs")
            continue
        for column in expected.columns:
            actual = actual_columns[column.name]
            if bool(actual["nullable"]) != bool(column.nullable):
                errors.append(f"{expected.name}.{column.name} nullability differs")
            if _type_token(actual["type"]) != _type_token(column.type):
                errors.append(f"{expected.name}.{column.name} type differs")
            if _default_token(actual.get("default")) != _default_token(
                column.server_default
            ):
                errors.append(f"{expected.name}.{column.name} server default differs")
        actual_pk = tuple(
            inspector.get_pk_constraint(expected.name).get("constrained_columns") or ()
        )
        expected_pk = tuple(column.name for column in expected.primary_key.columns)
        if actual_pk != expected_pk:
            errors.append(f"{expected.name} primary key differs")
        expected_fk = {
            (
                tuple(column.name for column in constraint.columns),
                constraint.referred_table.name,
                tuple(element.column.name for element in constraint.elements),
                (constraint.ondelete or "RESTRICT").upper(),
            )
            for constraint in expected.foreign_key_constraints
        }
        actual_fk = {
            (
                tuple(item["constrained_columns"]),
                item["referred_table"],
                tuple(item["referred_columns"]),
                str((item.get("options") or {}).get("ondelete") or "RESTRICT").upper(),
            )
            for item in inspector.get_foreign_keys(expected.name)
        }
        if actual_fk != expected_fk:
            errors.append(f"{expected.name} foreign keys differ")
        expected_unique = {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in expected.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        actual_unique = {
            (item["name"], tuple(item["column_names"]))
            for item in inspector.get_unique_constraints(expected.name)
        }
        if expected_unique != actual_unique:
            errors.append(f"{expected.name} unique constraints differ")
        expected_checks = {
            (constraint.name, _canonical_check_sql(constraint.sqltext))
            for constraint in expected.constraints
            if isinstance(constraint, CheckConstraint)
        }
        actual_checks = {
            (item["name"], _canonical_check_sql(item["sqltext"]))
            for item in inspector.get_check_constraints(expected.name)
        }
        if expected_checks != actual_checks:
            errors.append(f"{expected.name} check constraints differ")
        expected_indexes = {
            (index.name, bool(index.unique), tuple(column.name for column in index.columns))
            for index in expected.indexes
        }
        actual_indexes = {
            (
                item["name"],
                bool(item["unique"]),
                tuple(item["column_names"]),
            )
            for item in inspector.get_indexes(expected.name)
            if not item.get("duplicates_constraint")
        }
        if expected_indexes != actual_indexes:
            errors.append(f"{expected.name} indexes differ")
    return errors


def live_schema_fingerprint(bind: Connection | Engine) -> str:
    errors = schema_validation_errors(bind)
    if errors:
        raise DataSchemaError("; ".join(errors))
    return CANONICAL_SCHEMA_SHA256


def verify_persisted_schema_fingerprint(
    connection: Connection, *, require_activated: bool = False
) -> None:
    live = live_schema_fingerprint(connection)
    rows = connection.execute(select(data_schema_fingerprints)).mappings().all()
    if len(rows) != 1:
        raise DataSchemaError("v0.8 schema fingerprint record cardinality differs")
    row = rows[0]
    if row["migration_id"] != MIGRATION_ID:
        raise DataSchemaError("v0.8 schema fingerprint migration identity differs")
    if row["backend_kind"] != connection.dialect.name:
        raise DataSchemaError("v0.8 schema fingerprint backend differs")
    if row["canonical_schema_sha256"] != live:
        raise DataSchemaError("v0.8 persisted schema fingerprint differs")
    if require_activated and not row["activated"]:
        raise DataSchemaError("v0.8 data schema is not activated")


def activate_data_schema(bind: Connection | Engine) -> None:
    """Verify and atomically activate the one exact v0.8 schema fingerprint."""

    if isinstance(bind, Engine):
        with bind.begin() as connection:
            activate_data_schema(connection)
        return
    verify_persisted_schema_fingerprint(bind)
    row = bind.execute(select(data_schema_fingerprints)).mappings().one()
    if not row["activated"]:
        result = bind.execute(
            data_schema_fingerprints.update()
            .where(
                data_schema_fingerprints.c.migration_id == MIGRATION_ID,
                data_schema_fingerprints.c.backend_kind == bind.dialect.name,
                data_schema_fingerprints.c.canonical_schema_sha256
                == CANONICAL_SCHEMA_SHA256,
                data_schema_fingerprints.c.activated.is_(False),
            )
            .values(activated=True)
        )
        if result.rowcount != 1:
            raise DataSchemaError("v0.8 schema activation compare-and-set failed")
    verify_persisted_schema_fingerprint(bind, require_activated=True)


def _catalog_graph_integrity_errors(connection: Connection) -> list[str]:
    errors: list[str] = []
    heads = {
        row["catalog_id"]: row
        for row in connection.execute(select(data_catalogs)).mappings()
    }
    revision_rows = {
        (row["catalog_id"], row["revision"]): row
        for row in connection.execute(select(data_catalog_revisions)).mappings()
    }
    entries_by_revision: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    for row in connection.execute(select(data_catalog_entries)).mappings():
        entries_by_revision.setdefault(
            (row["catalog_id"], row["catalog_revision"]), []
        ).append(row)
    dependencies_by_revision: dict[tuple[str, int], list[Mapping[str, Any]]] = {}
    for row in connection.execute(select(data_dependencies)).mappings():
        dependencies_by_revision.setdefault(
            (row["source_catalog_id"], row["source_revision"]), []
        ).append(row)

    nodes: dict[tuple[str, int], CatalogNode] = {}
    outgoing: dict[tuple[str, int], tuple[CatalogDependency, ...]] = {}
    for identity, revision in revision_rows.items():
        head = heads.get(identity[0])
        if head is None:
            errors.append(
                f"catalog revision {identity[0]}:{identity[1]} has no head"
            )
            continue
        try:
            kind = CatalogKind(head["kind"])
            require_identifier(head["catalog_id"], "catalog_id", maximum_bytes=128)
            require_identifier(head["owner_id"], "owner_id", maximum_bytes=128)
            require_nfc_string(
                head["authorization_scope"], "authorization_scope", 128
            )
            require_nfc_string(
                revision["schema_version"], "schema_version", 80
            )
            if revision["schema_version"] != head["schema_version"]:
                raise ValueError("schema version differs")
            entry_content: list[dict[str, Any]] = []
            entry_ids: set[str] = set()
            qualified_names: set[str] = set()
            entry_rows = sorted(
                entries_by_revision.get(identity, []),
                key=lambda row: row["entry_id"].encode("ascii"),
            )
            for entry in entry_rows:
                entry_id = require_identifier(
                    entry["entry_id"], "catalog entry_id", maximum_bytes=128
                )
                qualified_name = require_nfc_string(
                    entry["qualified_name"], "catalog qualified_name", 256
                )
                if (
                    entry_id in entry_ids
                    or qualified_name in qualified_names
                ):
                    raise ValueError("entry identity is ambiguous")
                raw = entry["canonical_entry"]
                if not isinstance(raw, (bytes, bytearray, memoryview)):
                    raise ValueError("entry bytes are unavailable")
                exact = bytes(raw)
                content = strict_json_loads(exact, maximum_bytes=1_048_576)
                expected_uri = CatalogURI(
                    kind,
                    identity[0],
                    identity[1],
                    entry_id,
                ).canonical
                if (
                    _canonical_data_json_bytes(content) != exact
                    or hashlib.sha256(exact).hexdigest() != entry["content_digest"]
                    or entry["local_uri"] != expected_uri
                ):
                    raise ValueError("entry projection differs")
                entry_ids.add(entry_id)
                qualified_names.add(qualified_name)
                entry_content.append(
                    {
                        "content": content,
                        "entry_id": entry_id,
                        "qualified_name": qualified_name,
                    }
                )

            edge_content: list[dict[str, Any]] = []
            edges: list[CatalogDependency] = []
            edge_rows = sorted(
                dependencies_by_revision.get(identity, []),
                key=lambda row: row["dependency_id"].encode("ascii"),
            )
            for ordinal, dependency in enumerate(edge_rows):
                if dependency["ordinal"] != ordinal:
                    raise ValueError("dependency order differs")
                edge = CatalogDependency(
                    dependency["dependency_id"],
                    dependency["source_catalog_id"],
                    dependency["source_revision"],
                    dependency["target_catalog_id"],
                    dependency["target_revision"],
                    dependency["target_content_digest"],
                    DependencyRelationship(dependency["relationship"]),
                )
                edges.append(edge)
                edge_content.append(
                    {
                        "dependency_id": edge.dependency_id,
                        "relationship": edge.relationship.value,
                        "target_catalog_id": edge.target_catalog_id,
                        "target_content_digest": edge.target_content_digest,
                        "target_revision": edge.target_revision,
                    }
                )
            expected_content = _canonical_data_json_bytes(
                {
                    "catalog_id": identity[0],
                    "dependencies": edge_content,
                    "entries": entry_content,
                    "kind": kind.value,
                    "revision": identity[1],
                    "schema_version": revision["schema_version"],
                }
            )
            if (
                not isinstance(
                    revision["canonical_content"],
                    (bytes, bytearray, memoryview),
                )
                or bytes(revision["canonical_content"]) != expected_content
                or hashlib.sha256(expected_content).hexdigest()
                != revision["content_digest"]
            ):
                raise ValueError("revision projection differs")
            node = CatalogNode(
                identity[0], kind, identity[1], revision["content_digest"]
            )
            nodes[identity] = node
            outgoing[identity] = tuple(edges)
        except (
            DataDomainError,
            TypedValueError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            errors.append(
                f"catalog revision {identity[0]}:{identity[1]} graph projection differs: {exc}"
            )

    for source in dependencies_by_revision:
        if source not in revision_rows:
            errors.append(
                f"catalog dependency source {source[0]}:{source[1]} is missing"
            )

    for root, root_node in nodes.items():
        root_head = heads[root[0]]
        selected_nodes: dict[tuple[str, int], CatalogNode] = {}
        selected_edges: dict[str, CatalogDependency] = {}
        queue = [root]
        graph_invalid = False
        while queue:
            identity = queue.pop(0)
            if identity in selected_nodes:
                continue
            node = nodes.get(identity)
            target_head = heads.get(identity[0])
            if node is None or target_head is None:
                errors.append(
                    f"catalog closure {root[0]}:{root[1]} has a missing target"
                )
                graph_invalid = True
                break
            if (
                target_head["owner_id"] != root_head["owner_id"]
                or target_head["acl_revision"] != root_head["acl_revision"]
                or target_head["authorization_scope"]
                != root_head["authorization_scope"]
            ):
                errors.append(
                    f"catalog closure {root[0]}:{root[1]} authority differs"
                )
                graph_invalid = True
                break
            selected_nodes[identity] = node
            for edge in outgoing.get(identity, ()):
                previous = selected_edges.get(edge.dependency_id)
                if previous is not None and previous != edge:
                    errors.append(
                        f"catalog closure {root[0]}:{root[1]} dependency identity is ambiguous"
                    )
                    graph_invalid = True
                    break
                target = nodes.get(edge.target_identity)
                if target is None or target.content_digest != edge.target_content_digest:
                    errors.append(
                        f"catalog closure {root[0]}:{root[1]} target digest differs"
                    )
                    graph_invalid = True
                    break
                selected_edges[edge.dependency_id] = edge
                queue.append(edge.target_identity)
            if graph_invalid:
                break
        if graph_invalid:
            continue
        try:
            closure = resolve_catalog_closure(
                root,
                tuple(selected_nodes.values()),
                tuple(selected_edges.values()),
            )
        except DataDomainError as exc:
            errors.append(
                f"catalog closure {root[0]}:{root[1]} is invalid: {exc}"
            )
            continue
        if closure.closure_digest != revision_rows[root]["closure_digest"]:
            errors.append(
                f"catalog closure {root[0]}:{root[1]} digest differs"
            )
    return errors


def data_integrity_errors(
    connection: Connection, *, virtual_file_reader: VirtualFileReader | None = None
) -> list[str]:
    """Recompute digests whose complete authoritative bytes are stored locally."""

    errors: list[str] = []

    def check_bytes(
        label: str, raw: Any, expected: str, *, canonical_json: bool = True
    ) -> None:
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            errors.append(f"{label} is not stored as authoritative bytes")
            return
        exact = bytes(raw)
        if hashlib.sha256(exact).hexdigest() != expected:
            errors.append(f"{label} digest differs")
            return
        if canonical_json:
            try:
                value = strict_json_loads(exact, maximum_bytes=16_777_216)
                if _canonical_data_json_bytes(value) != exact:
                    errors.append(f"{label} canonical bytes differ")
            except (TypedValueError, TypeError, ValueError):
                errors.append(f"{label} canonical bytes are invalid")

    for row in connection.execute(select(data_catalog_revisions)).mappings():
        check_bytes(
            f"catalog revision {row['catalog_id']}:{row['revision']}",
            row["canonical_content"],
            row["content_digest"],
        )
    for row in connection.execute(select(data_catalog_entries)).mappings():
        check_bytes(
            f"catalog entry {row['catalog_id']}:{row['catalog_revision']}:{row['entry_id']}",
            row["canonical_entry"],
            row["content_digest"],
        )
    errors.extend(_catalog_graph_integrity_errors(connection))
    dictionary_histories: dict[
        tuple[str, str],
        list[tuple[Mapping[str, Any], tuple[dict[str, Any], ...] | None]],
    ] = {}
    for row in connection.execute(select(data_dictionary_revisions)).mappings():
        identity = (
            f"dictionary revision {row['owner_id']}:"
            f"{row['dictionary_id']}:{row['revision']}"
        )
        check_bytes(
            f"{identity} entry state",
            row["canonical_entry_state"],
            row["canonical_entry_state_sha256"],
        )
        check_bytes(
            f"{identity} canonical source",
            row["canonical_source_document"],
            row["canonical_source_document_sha256"],
        )
        check_bytes(
            f"{identity} original source",
            row["original_bytes"],
            row["original_bytes_sha256"],
            canonical_json=False,
        )
        state: tuple[dict[str, Any], ...] | None = None
        try:
            state = decode_dictionary_state(
                row["canonical_entry_state"],
                row["canonical_entry_state_sha256"],
            )
            exported = build_db_document(
                row["dictionary_id"],
                row["revision"],
                (
                    DictionaryEntry(
                        item["entry_id"],
                        item["qualified_name"],
                        item["value"],
                        item["value_digest"],
                    )
                    for item in state
                    if not item["tombstoned"]
                ),
            )
            if exported.content_digest != row["content_digest"]:
                errors.append(f"{identity} content digest differs")
        except (DataDomainError, TypedValueError, TypeError, UnicodeError):
            errors.append(f"{identity} entry state is semantically invalid")
        dictionary_histories.setdefault(
            (row["owner_id"], row["dictionary_id"]), []
        ).append((row, state))
        try:
            canonical_source = bytes(row["canonical_source_document"])
            source = parse_dictionary_document(
                canonical_source,
                media_type=row["original_media_type"],
            )
            original = parse_dictionary_document(
                bytes(row["original_bytes"]),
                media_type=row["original_media_type"],
            )
            if (
                source.canonical_bytes != canonical_source
                or original.canonical_bytes != canonical_source
                or source.dictionary_id != row["dictionary_id"]
                or source.base_revision != row["base_revision"]
                or source.format.value != row["source_format"]
            ):
                errors.append(f"{identity} source provenance differs")
        except (DataDomainError, TypedValueError, TypeError, UnicodeError):
            errors.append(f"{identity} source provenance is semantically invalid")
    container_histories: dict[
        tuple[str, str, str],
        list[tuple[Mapping[str, Any], tuple[dict[str, Any], ...] | None]],
    ] = {}
    for row in connection.execute(select(data_container_revisions)).mappings():
        identity = (
            f"container revision {row['kind']}:{row['owner_id']}:"
            f"{row['container_id']}:{row['revision']}"
        )
        check_bytes(
            identity,
            row["canonical_variables"],
            row["content_digest"],
        )
        state = None
        try:
            state = decode_container_state(
                row["canonical_variables"], row["content_digest"]
            )
        except (DataDomainError, TypedValueError, TypeError, UnicodeError):
            errors.append(f"{identity} state is semantically invalid")
        container_histories.setdefault(
            (row["kind"], row["owner_id"], row["container_id"]), []
        ).append((row, state))
    for row in connection.execute(
        select(shared_entries).where(shared_entries.c.tombstoned.is_(False))
    ).mappings():
        identity = (
            f"shared entry {row['scope']}:{row['owner_id']}:"
            f"{row['namespace_id']}:{row['entry_id']}:{row['revision']}"
        )
        check_bytes(
            identity,
            row["canonical_value"],
            row["value_digest"],
        )
        try:
            decode_stored_typed_value(row["canonical_value"], row["value_digest"])
        except (TypedValueError, TypeError, UnicodeError):
            errors.append(f"{identity} typed value is semantically invalid")
    settlements = connection.execute(select(data_mutation_idempotency)).mappings().all()
    audits = connection.execute(select(data_audit_outbox)).mappings().all()
    for row in settlements:
        if row["state"] == "PENDING":
            errors.append(
                f"idempotency settlement {row['settlement_id']} is durably pending"
            )
            continue
        if row["state"] != "COMMITTED":
            continue
        check_bytes(
            f"idempotency settlement {row['settlement_id']}",
            row["result_payload"],
            row["result_payload_sha256"],
        )
    for row in audits:
        check_bytes(
            f"audit outbox event {row['event_id']}",
            row["payload"],
            row["payload_sha256"],
        )

    audits_by_operation: dict[str, list[Mapping[str, Any]]] = {}
    for row in audits:
        audits_by_operation.setdefault(row["operation_id"], []).append(row)
    linked_operations: set[str] = set()
    for settlement in settlements:
        identity = f"idempotency settlement {settlement['settlement_id']}"
        if settlement["state"] == "PENDING":
            continue
        try:
            settlement_payload = strict_json_loads(
                bytes(settlement["result_payload"]), maximum_bytes=1_048_576
            )
        except (TypeError, ValueError, TypedValueError):
            errors.append(f"{identity} payload is invalid")
            continue
        if type(settlement_payload) is not dict or set(settlement_payload) != {
            "new_revision",
            "operation_id",
            "outcome",
            "prior_revision",
            "result",
        }:
            errors.append(f"{identity} payload shape differs")
            continue
        operation_id = settlement_payload.get("operation_id")
        if type(operation_id) is not str or not operation_id:
            errors.append(f"{identity} operation identity differs")
            continue
        matching = audits_by_operation.get(operation_id, [])
        if len(matching) != 1:
            errors.append(f"{identity} audit evidence cardinality differs")
            continue
        audit = matching[0]
        linked_operations.add(operation_id)
        comparable = (
            ("actor_principal_id", "actor principal"),
            ("caller_binding_digest", "caller binding"),
            ("operation", "operation"),
            ("resource_identity_digest", "resource identity"),
            ("request_digest", "request"),
        )
        for column, label in comparable:
            if audit[column] != settlement[column]:
                errors.append(f"{identity} {label} audit binding differs")
        for column in ("prior_revision", "new_revision", "outcome"):
            if audit[column] != settlement_payload[column]:
                errors.append(f"{identity} {column} audit binding differs")
        if (
            settlement["caller_binding_kind"] == "HTTP_MUTATION"
            and (
                not audit["request_session_binding"]
                or not audit["client_instance_key_binding"]
            )
        ):
            errors.append(f"{identity} HTTP request binding is missing")
        if settlement["caller_binding_kind"] == "PROCEDURE_RUNTIME" and (
            audit["request_session_binding"] is not None
            or audit["client_instance_key_binding"] is not None
        ):
            errors.append(f"{identity} procedure request binding differs")
        try:
            audit_payload = strict_json_loads(
                bytes(audit["payload"]), maximum_bytes=1_048_576
            )
        except (TypeError, ValueError, TypedValueError):
            errors.append(f"{identity} audit payload is invalid")
            continue
        if type(audit_payload) is not dict or set(audit_payload) != {
            "event_id",
            "operation_id",
            "outcome",
            "response_status",
            "result_digest",
            "schema_version",
        }:
            errors.append(f"{identity} audit payload shape differs")
            continue
        try:
            result_digest = hashlib.sha256(
                _canonical_data_json_bytes(settlement_payload["result"])
            ).hexdigest()
        except (TypeError, ValueError):
            errors.append(f"{identity} result is not canonical data")
            continue
        expected_audit_payload = {
            "event_id": audit["event_id"],
            "operation_id": operation_id,
            "outcome": audit["outcome"],
            "response_status": settlement["response_status"],
            "result_digest": result_digest,
            "schema_version": "spell.data.audit-outbox/1",
        }
        if audit_payload != expected_audit_payload:
            errors.append(f"{identity} audit payload binding differs")
    for operation_id, rows in audits_by_operation.items():
        if len(rows) != 1 or operation_id not in linked_operations:
            errors.append(f"audit operation {operation_id} is orphaned or ambiguous")

    head_specs = (
        (
            data_catalogs,
            data_catalog_revisions,
            "catalog_id",
            "current_content_digest",
            "catalog",
        ),
    )
    for heads, revisions, identity_column, digest_column, label in head_specs:
        for head in connection.execute(select(heads)).mappings():
            revision = connection.execute(
                select(revisions).where(
                    revisions.c[identity_column] == head[identity_column],
                    revisions.c.revision == head["current_revision"],
                )
            ).mappings().one_or_none()
            if revision is None or revision["content_digest"] != head[digest_column]:
                errors.append(f"{label} head {head[identity_column]} differs")

    for dictionary in connection.execute(select(data_dictionaries)).mappings():
        revision = connection.execute(
            select(data_dictionary_revisions).where(
                data_dictionary_revisions.c.owner_id == dictionary["owner_id"],
                data_dictionary_revisions.c.dictionary_id
                == dictionary["dictionary_id"],
                data_dictionary_revisions.c.revision
                == dictionary["current_revision"],
            )
        ).mappings().one_or_none()
        if (
            revision is None
            or revision["content_digest"]
            != dictionary["current_content_digest"]
        ):
            errors.append(
                f"dictionary head {dictionary['owner_id']}:"
                f"{dictionary['dictionary_id']} differs"
            )
        try:
            validate_dictionary_history(
                dictionary_histories.get(
                    (dictionary["owner_id"], dictionary["dictionary_id"]), []
                ),
                current_revision=dictionary["current_revision"],
            )
        except DataDomainError:
            errors.append(
                f"dictionary history {dictionary['owner_id']}:"
                f"{dictionary['dictionary_id']} differs"
            )

    for container in connection.execute(select(data_containers)).mappings():
        revision = connection.execute(
            select(data_container_revisions).where(
                data_container_revisions.c.kind == container["kind"],
                data_container_revisions.c.owner_id == container["owner_id"],
                data_container_revisions.c.container_id
                == container["container_id"],
                data_container_revisions.c.revision
                == container["current_revision"],
            )
        ).mappings().one_or_none()
        identity = (
            f"{container['kind']}:{container['owner_id']}:"
            f"{container['container_id']}"
        )
        if (
            revision is None
            or revision["content_digest"]
            != container["current_content_digest"]
        ):
            errors.append(f"container head {identity} differs")
        try:
            validate_container_history(
                container,
                container_histories.get(
                    (
                        container["kind"],
                        container["owner_id"],
                        container["container_id"],
                    ),
                    [],
                ),
            )
        except DataDomainError:
            errors.append(f"container history {identity} differs")
        if container["kind"] == "ARGS":
            revisions = sorted(connection.execute(
                select(data_container_revisions.c.revision).where(
                    data_container_revisions.c.kind == container["kind"],
                    data_container_revisions.c.owner_id == container["owner_id"],
                    data_container_revisions.c.container_id == container["container_id"]
                )
            ).scalars().all())
            if revisions != [1]:
                errors.append(
                    f"ARGS container {identity} is not immutable"
                )

    shared_rows = connection.execute(select(shared_entries)).mappings().all()
    try:
        validate_shared_history(shared_rows)
    except DataDomainError:
        errors.append("shared entry history differs")
    shared_by_namespace: dict[
        tuple[str, str, str], list[Mapping[str, Any]]
    ] = {}
    for row in shared_rows:
        shared_by_namespace.setdefault(
            (row["scope"], row["owner_id"], row["namespace_id"]), []
        ).append(row)
    for namespace in connection.execute(select(shared_namespaces)).mappings():
        namespace_identity = (
            namespace["scope"],
            namespace["owner_id"],
            namespace["namespace_id"],
        )
        latest_by_entry: dict[str, Mapping[str, Any]] = {}
        for row in shared_by_namespace.get(namespace_identity, []):
            previous = latest_by_entry.get(row["entry_id"])
            if previous is None or row["revision"] > previous["revision"]:
                latest_by_entry[row["entry_id"]] = row
        latest = list(latest_by_entry.values())
        live_keys = [row["key"] for row in latest if not row["tombstoned"]]
        if len(live_keys) != len(set(live_keys)):
            errors.append(
                f"shared namespace {namespace['namespace_id']} has ambiguous live keys"
            )
        if namespace["tombstoned"] and live_keys:
            errors.append(
                f"shared namespace {namespace['namespace_id']} tombstone has live entries"
            )
        if latest and namespace["current_revision"] < max(
            row["revision"] for row in latest
        ):
            errors.append(
                f"shared namespace {namespace['namespace_id']} revision regressed"
            )
        state = canonical_shared_namespace_state_bytes(latest)
        if hashlib.sha256(state).hexdigest() != namespace["current_content_digest"]:
            errors.append(
                f"shared namespace head {namespace['namespace_id']} differs"
            )

    virtual_rows = connection.execute(select(virtual_files)).mappings().all()
    virtual_by_root: dict[str, list[Mapping[str, Any]]] = {}
    for row in virtual_rows:
        virtual_by_root.setdefault(row["root_id"], []).append(row)
    for root in connection.execute(select(virtual_file_roots)).mappings():
        latest_by_path: dict[str, Mapping[str, Any]] = {}
        for row in virtual_by_root.get(root["root_id"], []):
            previous = latest_by_path.get(row["virtual_path"])
            if previous is None or row["revision"] > previous["revision"]:
                latest_by_path[row["virtual_path"]] = row
        latest = list(latest_by_path.values())
        live = [row for row in latest if not row["tombstoned"]]
        if latest and root["current_revision"] < max(
            row["revision"] for row in latest
        ):
            errors.append(f"virtual root {root['root_id']} revision regressed")
        configuration = canonical_virtual_root_configuration_bytes(root)
        if hashlib.sha256(configuration).hexdigest() != root["configuration_digest"]:
            errors.append(f"virtual root {root['root_id']} configuration differs")
        state = canonical_virtual_root_state_bytes(root["root_id"], latest)
        if hashlib.sha256(state).hexdigest() != root["content_digest"]:
            errors.append(f"virtual root head {root['root_id']} differs")
        used_bytes = sum(
            row["byte_length"] for row in live if row["node_type"] == "FILE"
        )
        if root["used_nodes"] != len(live) or root["used_bytes"] != used_bytes:
            errors.append(f"virtual root {root['root_id']} usage differs")
        reservation_id = root["reservation_id"]
        reservation_digest = root["reservation_binding_digest"]
        reserved_bytes = root["reserved_bytes"]
        reserved_nodes = root["reserved_nodes"]
        reservation_absent = (
            reservation_id is None
            and reservation_digest is None
            and reserved_bytes == 0
            and reserved_nodes == 0
        )
        reservation_present = (
            type(reservation_id) is str
            and re.fullmatch(r"[0-9a-f]{32}", reservation_id) is not None
            and type(reservation_digest) is str
            and re.fullmatch(r"[0-9a-f]{64}", reservation_digest) is not None
            and type(reserved_bytes) is int
            and reserved_bytes >= 0
            and type(reserved_nodes) is int
            and reserved_nodes in {0, 1}
            and root["used_bytes"] + reserved_bytes <= root["quota_bytes"]
            and root["used_nodes"] + reserved_nodes <= root["quota_nodes"]
        )
        if not reservation_absent and not reservation_present:
            errors.append(f"virtual root {root['root_id']} reservation differs")
        if virtual_file_reader is not None:
            for row in live:
                if row["node_type"] != "FILE":
                    continue
                try:
                    raw = virtual_file_reader(
                        root["root_id"], row["virtual_path"], row["content_digest"]
                    )
                except Exception:
                    errors.append(
                        f"virtual file {root['root_id']}:{row['virtual_path']} is unavailable"
                    )
                    continue
                if type(raw) is not bytes or len(raw) != row["byte_length"]:
                    errors.append(
                        f"virtual file {root['root_id']}:{row['virtual_path']} length differs"
                    )
                elif hashlib.sha256(raw).hexdigest() != row["content_digest"]:
                    errors.append(
                        f"virtual file {root['root_id']}:{row['virtual_path']} digest differs"
                    )
    return errors


def verify_data_integrity(
    connection: Connection, *, virtual_file_reader: VirtualFileReader | None = None
) -> None:
    errors = data_integrity_errors(
        connection, virtual_file_reader=virtual_file_reader
    )
    if errors:
        raise DataSchemaError("; ".join(errors))


__all__ = [
    "CANONICAL_SCHEMA_BYTES",
    "CANONICAL_SCHEMA_SHA256",
    "DATA_TABLES",
    "DATA_TABLE_NAMES",
    "DataAuditOutbox",
    "DataCatalog",
    "DataCatalogEntry",
    "DataCatalogRevision",
    "DataContainer",
    "DataContainerRevision",
    "DataDependency",
    "DataDictionary",
    "DataDictionaryRevision",
    "DataMutationIdempotency",
    "DataSchemaError",
    "DataSchemaFingerprint",
    "MIGRATION_ID",
    "MAX_CONTRACT_INTEGER",
    "SCHEMA_FINGERPRINT_VERSION",
    "SharedEntry",
    "SharedNamespace",
    "VirtualFile",
    "VirtualFileReader",
    "VirtualFileRoot",
    "data_audit_outbox",
    "activate_data_schema",
    "canonical_shared_namespace_state_bytes",
    "canonical_virtual_root_configuration_bytes",
    "canonical_virtual_root_state_bytes",
    "data_catalog_entries",
    "data_catalog_revisions",
    "data_catalogs",
    "data_container_revisions",
    "data_containers",
    "data_dependencies",
    "data_dictionaries",
    "data_dictionary_revisions",
    "data_mutation_idempotency",
    "data_schema_fingerprints",
    "data_integrity_errors",
    "live_schema_fingerprint",
    "schema_validation_errors",
    "shared_entries",
    "shared_namespaces",
    "verify_persisted_schema_fingerprint",
    "verify_data_integrity",
    "virtual_file_roots",
    "virtual_files",
]
