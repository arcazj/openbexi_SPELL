"""Transactional repository for bounded v0.8 catalogs, dictionaries, and data."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from .data_domain import (
    AuthorizationContext,
    CatalogDependency,
    CatalogKind,
    CatalogNode,
    CatalogURI,
    CursorCodec,
    DataAuthorizationError,
    DataCapacityError,
    DataConflictError,
    DataCorruptionError,
    DataNotFoundError,
    DataPermission,
    DataValidationError,
    DependencyCycleError,
    DependencyDigestError,
    DependencyNotFoundError,
    DependencyRelationship,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    ResourceHandle,
    ResourceHandleCodec,
    ResolvedCatalogClosure,
    RevisionCursor,
    actor_principal_id,
    caller_binding_digest,
    caller_binding_payload,
    canonical_json_bytes,
    require_digest,
    require_expected_revision,
    require_identifier,
    require_nfc_string,
    require_positive_revision,
    resolve_catalog_closure,
    sha256_digest,
)
from .data_models import (
    DataCatalog,
    DataCatalogEntry,
    DataCatalogRevision,
    DataContainer,
    DataContainerRevision,
    DataDependency,
    DataDictionary,
    DataDictionaryRevision,
    DataMutationIdempotency,
    DataSchemaError,
    SharedEntry,
    SharedNamespace,
    VirtualFile,
    VirtualFileRoot,
    canonical_shared_namespace_state_bytes,
    canonical_virtual_root_configuration_bytes,
    canonical_virtual_root_state_bytes,
    verify_data_integrity,
    verify_persisted_schema_fingerprint,
)
from .data_state import (
    CorruptContainerError,
    CorruptDictionaryError,
    DECLARED_TYPE_MAPPING,
    decode_container_state,
    decode_dictionary_state,
)
from .data_mutations import (
    DataMutationCoordinator,
    DeadlineCheck,
    MutationEffect,
    MutationRequest,
    MutationResult,
    ProcedureBindingCheck,
    _translated_transaction_error,
)
from .data_values import (
    CorruptValueError,
    TypedValueError,
    canonical_typed_value_json,
    decode_stored_typed_value,
    make_typed_value,
    strict_json_loads,
    typed_value_digest,
    typed_value_to_python,
    validate_typed_value,
)
from .dictionary_exchange import (
    DB_MEDIA_TYPE,
    DictionaryDocument,
    DictionaryEntry,
    DictionaryExchangeError,
    DictionaryFormat,
    ImportOperation,
    build_db_document,
    export_dictionary_document,
    parse_dictionary_document,
)
from .database import begin_mutation_write


MAX_CATALOG_ENTRIES = 100_000
MAX_CONTAINER_VARIABLES = 4096
MAX_CONTAINER_BYTES = 16_777_216
MAX_ENUMERATION_PAGE = 256
MAX_SHARED_ENTRIES = 100_000
MAX_SHARED_CLEAR = 4096
MAX_SHARED_KEY_BYTES = 512
MAX_SHARED_VALUE_BYTES = 1_048_576
MAX_INTERNAL_STATE_BYTES = 16_777_216
MAX_VIRTUAL_FILE_BYTES = 16_777_216
MAX_VIRTUAL_ROOT_BYTES = 268_435_456
MAX_VIRTUAL_ROOT_NODES = 10_000
MAX_VIRTUAL_PATH_BYTES = 1024
MAX_VIRTUAL_SEGMENT_BYTES = 255
MAX_VIRTUAL_PATH_DEPTH = 32
VIRTUAL_ROOT_KINDS = frozenset(
    {"PROCEDURE_DATA", "PROJECT_DATA", "EXECUTION_SCRATCH"}
)
VIRTUAL_FILE_ENCODINGS = frozenset({"UTF8_TEXT", "BINARY"})
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class CorruptCatalogError(DataCorruptionError):
    code = "CATALOG_CORRUPT"


class CorruptNamespaceError(DataCorruptionError):
    code = "CORRUPT_NAMESPACE"


class CorruptVirtualFileError(DataCorruptionError):
    code = "CORRUPT_FILE"


class ContainerKind(str, Enum):
    LOCAL = "LOCAL"
    ARGS = "ARGS"
    IVARS = "IVARS"
    DATA_CONTAINER = "DATA_CONTAINER"


class SharedScope(str, Enum):
    PROJECT = "PROJECT"
    CONTEXT = "CONTEXT"
    EXECUTION = "EXECUTION"


_RUNTIME_DECLARED_TYPE_ALIASES = {
    "bool": "BOOLEAN",
    "float": "FLOAT",
    "int": "LONG",
    "str": "STRING",
}


@dataclass(frozen=True, slots=True)
class CatalogEntryDefinition:
    entry_id: str
    qualified_name: str
    content: Mapping[str, Any]

    def __post_init__(self) -> None:
        require_identifier(self.entry_id, "entry_id", maximum_bytes=128)
        require_nfc_string(self.qualified_name, "qualified_name", 256)
        if not isinstance(self.content, Mapping):
            raise DataValidationError("catalog entry content must be an object")
        canonical_json_bytes(dict(self.content))


@dataclass(frozen=True, slots=True)
class CatalogDependencyDefinition:
    dependency_id: str
    target_catalog_id: str
    target_revision: int
    target_content_digest: str
    relationship: DependencyRelationship

    def __post_init__(self) -> None:
        require_identifier(self.dependency_id, "dependency_id", maximum_bytes=128)
        require_identifier(self.target_catalog_id, "target_catalog_id", maximum_bytes=128)
        require_positive_revision(self.target_revision, "target_revision")
        require_digest(self.target_content_digest, "target_content_digest")
        if type(self.relationship) is not DependencyRelationship:
            raise DataValidationError("dependency relationship is invalid")


@dataclass(frozen=True, slots=True)
class ContainerVariableDefinition:
    variable_id: str
    name: str
    declared_type: str
    value: Mapping[str, Any]

    def __post_init__(self) -> None:
        require_identifier(self.variable_id, "variable_id", maximum_bytes=128)
        require_nfc_string(self.name, "variable name", 256)
        if self.declared_type not in DECLARED_TYPE_MAPPING:
            raise DataValidationError("declared container type is unsupported")
        try:
            canonical = validate_typed_value(self.value)
        except TypedValueError as exc:
            raise DataValidationError("container typed value is invalid") from exc
        if canonical["type"] != DECLARED_TYPE_MAPPING[self.declared_type]:
            raise DataValidationError("container value does not match its declared type")


def runtime_container_definitions(
    values: Mapping[str, Any],
    *,
    declared_types: Mapping[str, str] | None = None,
) -> tuple[ContainerVariableDefinition, ...]:
    """Convert one bounded runtime mapping to stable container definitions."""

    if type(values) is not dict:
        raise DataValidationError("runtime variables must be a plain mapping")
    if len(values) > MAX_CONTAINER_VARIABLES:
        raise DataCapacityError("runtime variable count is exceeded")
    if declared_types is not None:
        if type(declared_types) is not dict or set(declared_types) != set(values):
            raise DataValidationError("runtime declared types must exactly cover variables")

    definitions: list[ContainerVariableDefinition] = []
    for name in sorted(values, key=lambda item: item.encode("utf-8") if type(item) is str else b""):
        name = require_nfc_string(name, "runtime variable name", 256)
        value = values[name]
        raw_declared_type = declared_types[name] if declared_types is not None else None
        if raw_declared_type is None:
            if type(value) is bool:
                declared_type = "BOOLEAN"
            elif type(value) is int:
                declared_type = "LONG"
            elif type(value) is float:
                declared_type = "FLOAT"
            elif type(value) is str:
                declared_type = "STRING"
            elif type(value) is datetime:
                declared_type = "DATETIME"
            else:
                raise DataValidationError(
                    "runtime variable has no authorized declared type"
                )
        else:
            if type(raw_declared_type) is not str:
                raise DataValidationError("runtime declared type is invalid")
            declared_type = _RUNTIME_DECLARED_TYPE_ALIASES.get(
                raw_declared_type, raw_declared_type
            )
            if declared_type not in DECLARED_TYPE_MAPPING:
                raise DataValidationError("runtime declared type is unsupported")

        type_id = DECLARED_TYPE_MAPPING[declared_type]
        try:
            if type(value) is dict:
                typed_value = validate_typed_value(value)
                if typed_value["type"] != type_id:
                    raise DataValidationError(
                        "runtime typed envelope does not match its declared type"
                    )
            else:
                if type_id == "BOOLEAN" and type(value) is not bool:
                    raise DataValidationError("BOOLEAN runtime value must be bool")
                if type_id in {"INT64", "REL_DURATION"} and type(value) is not int:
                    raise DataValidationError(
                        f"{declared_type} runtime value must be int"
                    )
                if type_id == "FINITE_DOUBLE" and type(value) is not float:
                    raise DataValidationError("FLOAT runtime value must be float")
                if type_id == "STRING" and type(value) is not str:
                    raise DataValidationError("STRING runtime value must be str")
                if type_id == "UTC_DATETIME" and type(value) is not datetime:
                    raise DataValidationError(
                        "DATETIME runtime value must be datetime"
                    )
                typed_value = make_typed_value(type_id, value)
        except TypedValueError as exc:
            raise DataValidationError("runtime variable value is invalid") from exc
        variable_id = "runtime." + sha256_digest(name.encode("utf-8"))
        definitions.append(
            ContainerVariableDefinition(
                variable_id=variable_id,
                name=name,
                declared_type=declared_type,
                value=typed_value,
            )
        )
    return tuple(definitions)


def _schema_version(value: Any) -> str:
    return require_nfc_string(value, "schema_version", 80)


def _page_size(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_ENUMERATION_PAGE:
        raise DataValidationError("page_size must be between 1 and 256")
    return value


def _next_revision(value: Any, label: str = "revision") -> int:
    current = require_positive_revision(value, label)
    return require_positive_revision(current + 1, label)


def _mutation_projection(result: MutationResult) -> dict[str, Any]:
    return {
        **result.result,
        "new_revision": result.new_revision,
        "operation_id": result.operation_id,
        "outcome": result.outcome,
        "prior_revision": result.prior_revision,
        "replayed": result.replayed,
    }


def _identity_bound_authorization(
    authorization: AuthorizationContext,
    family: ResourceFamily,
    operation: str,
    *,
    owner_id: str,
    public_resource_id: str,
    evidence_resource_id: str,
    acl_revision: int,
) -> AuthorizationContext:
    authorization.require(
        family,
        operation,
        owner_id=owner_id,
        resource_id=public_resource_id,
        acl_revision=acl_revision,
    )
    permission = DataPermission(
        family,
        operation,
        owner_id,
        require_identifier(evidence_resource_id, "evidence resource identity"),
        acl_revision,
    )
    permissions = authorization.permissions
    if permission not in permissions:
        permissions = (*permissions, permission)
    return AuthorizationContext(
        authorization.caller,
        permissions,
        authorization.scope_profile,
    )


def _json_text(value: Any, maximum_bytes: int, label: str) -> tuple[bytes, str]:
    raw = canonical_json_bytes(value)
    if len(raw) > maximum_bytes:
        raise DataCapacityError(f"{label} exceeds its byte limit")
    return raw, sha256_digest(raw)


def _caller_source(binding: HTTPCallerBinding | ProcedureCallerBinding) -> tuple[str, str]:
    if type(binding) is HTTPCallerBinding:
        return "HTTP_MUTATION", binding.subject
    if type(binding) is ProcedureCallerBinding:
        return "PROCEDURE_RUNTIME", binding.service_principal_id
    raise DataValidationError("caller binding is invalid")


def _raise_revision_conflict(
    authorization: AuthorizationContext,
    family: ResourceFamily,
    read_operation: str,
    *,
    owner_id: str,
    resource_id: str,
    acl_revision: int | None,
    current_revision: int,
) -> None:
    visible: int | None = None
    try:
        authorization.require(
            family,
            read_operation,
            owner_id=owner_id,
            resource_id=resource_id,
            acl_revision=acl_revision,
        )
        visible = current_revision
    except DataAuthorizationError:
        pass
    raise DataConflictError("resource revision differs", current_revision=visible)


def _decode_dictionary_state(row: DataDictionaryRevision) -> tuple[dict[str, Any], ...]:
    return decode_dictionary_state(
        row.canonical_entry_state,
        row.canonical_entry_state_sha256,
    )


def _dictionary_state_bytes(entries: Iterable[Mapping[str, Any]]) -> tuple[bytes, str]:
    ordered = sorted(
        (dict(item) for item in entries), key=lambda item: item["entry_id"].encode("ascii")
    )
    raw = canonical_json_bytes(
        {"entries": ordered, "schema_version": "spell.data.dictionary-state/1"}
    )
    if len(raw) > MAX_INTERNAL_STATE_BYTES:
        raise DataCapacityError("dictionary state exceeds its byte limit")
    return raw, sha256_digest(raw)


def _live_dictionary_entries(
    state: Iterable[Mapping[str, Any]],
) -> tuple[DictionaryEntry, ...]:
    return tuple(
        DictionaryEntry(
            item["entry_id"],
            item["qualified_name"],
            item["value"],
            item["value_digest"],
        )
        for item in state
        if not item["tombstoned"]
    )


def _container_state_bytes(
    variables: Iterable[Mapping[str, Any]],
) -> tuple[bytes, str]:
    ordered = sorted(
        (dict(item) for item in variables),
        key=lambda item: item["variable_id"].encode("ascii"),
    )
    raw = canonical_json_bytes(
        {"schema_version": "spell.data.container-state/1", "variables": ordered}
    )
    if len(raw) > MAX_CONTAINER_BYTES:
        raise DataCapacityError("container state exceeds its byte limit")
    return raw, sha256_digest(raw)


def _decode_container_state(
    row: DataContainerRevision,
) -> tuple[dict[str, Any], ...]:
    return decode_container_state(
        row.canonical_variables,
        row.content_digest,
    )


def _variable_state(
    definition: ContainerVariableDefinition,
    revision: int,
) -> dict[str, Any]:
    canonical = validate_typed_value(definition.value)
    return {
        "declared_type": definition.declared_type,
        "name": definition.name,
        "revision": require_positive_revision(revision, "variable revision"),
        "tombstoned": False,
        "value": canonical,
        "value_digest": typed_value_digest(canonical),
        "variable_id": definition.variable_id,
    }


def _validate_variable_definitions(
    values: Iterable[ContainerVariableDefinition],
) -> tuple[ContainerVariableDefinition, ...]:
    definitions = tuple(values)
    if len(definitions) > MAX_CONTAINER_VARIABLES:
        raise DataCapacityError("container variable bound exceeded")
    if any(type(item) is not ContainerVariableDefinition for item in definitions):
        raise DataValidationError("container variables are invalid")
    if len({item.variable_id for item in definitions}) != len(definitions):
        raise DataValidationError("container variable identity is duplicated")
    if len({item.name for item in definitions}) != len(definitions):
        raise DataValidationError("container variable name is duplicated")
    return tuple(sorted(definitions, key=lambda item: item.variable_id.encode("ascii")))


def _runtime_container_id(execution_id: str, kind: ContainerKind) -> str:
    execution_id = require_identifier(
        execution_id, "execution_id", maximum_bytes=120
    )
    if kind not in {ContainerKind.LOCAL, ContainerKind.ARGS, ContainerKind.IVARS}:
        raise DataValidationError("runtime container kind is invalid")
    return require_identifier(
        f"{execution_id}.{kind.value}", "runtime container_id", maximum_bytes=128
    )


def _container_identity(
    kind: ContainerKind | str, owner_id: str, container_id: str
) -> dict[str, str]:
    value = kind.value if type(kind) is ContainerKind else kind
    if value not in {item.value for item in ContainerKind}:
        raise DataValidationError("container kind is invalid")
    return {
        "kind": value,
        "owner_id": require_identifier(owner_id, "owner_id", maximum_bytes=128),
        "container_id": require_identifier(
            container_id, "container_id", maximum_bytes=128
        ),
    }


def _dictionary_identity(owner_id: str, dictionary_id: str) -> dict[str, str]:
    return {
        "owner_id": require_identifier(owner_id, "owner_id", maximum_bytes=128),
        "dictionary_id": require_identifier(
            dictionary_id, "dictionary_id", maximum_bytes=128
        ),
    }


def _dictionary_revision_identity(
    owner_id: str, dictionary_id: str, revision: int
) -> dict[str, Any]:
    return {
        **_dictionary_identity(owner_id, dictionary_id),
        "revision": require_positive_revision(revision),
    }


def _container_revision_identity(
    kind: ContainerKind | str,
    owner_id: str,
    container_id: str,
    revision: int,
) -> dict[str, Any]:
    return {
        **_container_identity(kind, owner_id, container_id),
        "revision": require_positive_revision(revision),
    }


def _container_cursor_identity(row: DataContainer) -> str:
    return require_identifier(
        f"{row.kind}.{row.container_id}",
        "container cursor identity",
    )


def _shared_identity(
    scope: SharedScope | str, owner_id: str, namespace_id: str
) -> dict[str, str]:
    value = scope.value if type(scope) is SharedScope else scope
    if value not in {item.value for item in SharedScope}:
        raise DataValidationError("shared namespace scope is invalid")
    return {
        "scope": value,
        "owner_id": require_identifier(owner_id, "owner_id", maximum_bytes=128),
        "namespace_id": require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        ),
    }


def _shared_cursor_identity(row: SharedNamespace) -> str:
    return require_identifier(
        f"{row.scope}.{row.namespace_id}",
        "shared namespace cursor identity",
    )


def _runtime_commit_digest(
    binding: ProcedureCallerBinding,
    *,
    container_id: str,
    container_revision: int,
    content_digest: str,
    checkpoint_sequence: int,
    execution_revision: int,
) -> str:
    return _runtime_commit_digest_from_binding(
        caller_digest=caller_binding_digest(binding),
        worker_generation=binding.worker_generation,
        container_id=container_id,
        container_revision=container_revision,
        content_digest=content_digest,
        checkpoint_sequence=checkpoint_sequence,
        execution_revision=execution_revision,
    )


def _runtime_commit_digest_from_binding(
    *,
    caller_digest: str,
    worker_generation: int,
    container_id: str,
    container_revision: int,
    content_digest: str,
    checkpoint_sequence: int,
    execution_revision: int,
) -> str:
    require_digest(caller_digest, "runtime caller binding digest")
    worker_generation = require_expected_revision(
        worker_generation, "worker_generation"
    )
    return sha256_digest(
        canonical_json_bytes(
            {
                "caller_binding_digest": caller_digest,
                "checkpoint_sequence": checkpoint_sequence,
                "container_id": container_id,
                "container_revision": container_revision,
                "content_digest": content_digest,
                "execution_revision": execution_revision,
                "schema_version": "spell.data.runtime-container-commit/1",
                "worker_generation": worker_generation,
            }
        )
    )


def _replace_container_state(
    prior: Iterable[Mapping[str, Any]],
    definitions: Iterable[ContainerVariableDefinition],
) -> tuple[dict[str, Any], ...]:
    requested = _validate_variable_definitions(definitions)
    prior_by_id = {item["variable_id"]: dict(item) for item in prior}
    requested_ids = {item.variable_id for item in requested}
    live_names: set[str] = set()
    for definition in requested:
        current = prior_by_id.get(definition.variable_id)
        if current is not None and current["tombstoned"]:
            raise DataConflictError("runtime variable identity is tombstoned")
        if definition.name in live_names:
            raise DataConflictError("runtime variable name is duplicated")
        live_names.add(definition.name)
        canonical = validate_typed_value(definition.value)
        if current is None:
            prior_by_id[definition.variable_id] = _variable_state(definition, 1)
            continue
        if (
            current["name"] != definition.name
            or current["declared_type"] != definition.declared_type
        ):
            raise DataConflictError("runtime variable declaration is immutable")
        digest = typed_value_digest(canonical)
        revision = (
            current["revision"]
            if current["value_digest"] == digest
            else _next_revision(current["revision"], "variable revision")
        )
        prior_by_id[definition.variable_id] = {
            **current,
            "revision": revision,
            "tombstoned": False,
            "value": canonical,
            "value_digest": digest,
        }
    for variable_id, current in tuple(prior_by_id.items()):
        if not current["tombstoned"] and variable_id not in requested_ids:
            prior_by_id[variable_id] = {
                **current,
                "revision": _next_revision(
                    current["revision"], "variable revision"
                ),
                "tombstoned": True,
                "value": None,
            }
    return tuple(prior_by_id.values())


def _shared_key(value: Any) -> str:
    return require_nfc_string(value, "shared key", MAX_SHARED_KEY_BYTES)


def _shared_state_bytes(entries: Iterable[Mapping[str, Any]]) -> tuple[bytes, str]:
    values = tuple(dict(item) for item in entries)
    live_count = len([item for item in values if not item["tombstoned"]])
    if live_count > MAX_SHARED_ENTRIES:
        raise DataCapacityError("shared namespace live entry bound is exceeded")
    raw = canonical_shared_namespace_state_bytes(values)
    return raw, sha256_digest(raw)


def _shared_entry_projection(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "entry_id": item["entry_id"],
        "key": item["key"],
        "revision": item["revision"],
        "value": item["value"],
        "value_digest": item["value_digest"],
    }


def _procedure_handle_caller_digest(binding: ProcedureCallerBinding) -> str:
    return caller_binding_digest(binding)


def _inferred_typed_value(value: Any) -> dict[str, Any]:
    if value is None:
        return make_typed_value("NULL", None)
    if type(value) is bool:
        return make_typed_value("BOOLEAN", value)
    if type(value) is int:
        return make_typed_value("INT64", value)
    if type(value) is float:
        return make_typed_value("FINITE_DOUBLE", value)
    if type(value) is str:
        return make_typed_value("STRING", value)
    if type(value) is list:
        return make_typed_value("LIST", [_inferred_typed_value(item) for item in value])
    if type(value) is dict and all(type(key) is str for key in value):
        return make_typed_value(
            "MAP", {key: _inferred_typed_value(item) for key, item in value.items()}
        )
    raise DataValidationError("procedure value has no authorized typed representation")


def _declared_procedure_value(declared_type: str, value: Any) -> dict[str, Any]:
    type_id = DECLARED_TYPE_MAPPING.get(declared_type)
    if type_id is None:
        raise DataValidationError("procedure declared type is unsupported")
    wire = str(value) if type_id in {"INT64", "REL_DURATION"} and type(value) is int else value
    return validate_typed_value(
        {"schema_version": "spell.data.value/1", "type": type_id, "value": wire}
    )


def _procedure_result_value(value: Mapping[str, Any]) -> Any:
    canonical = validate_typed_value(value)
    if canonical["type"] in {"LIST", "MAP"}:
        return canonical_typed_value_json(canonical)
    if canonical["type"] in {"BYTES", "DECIMAL", "UTC_DATETIME"}:
        return canonical["value"]
    return typed_value_to_python(canonical)


def _virtual_root_storage_id(root_id: Any, owner_id: Any) -> str:
    root_id = require_identifier(root_id, "virtual root_id", maximum_bytes=128)
    owner_id = require_identifier(owner_id, "virtual root owner_id", maximum_bytes=128)
    if root_id not in VIRTUAL_ROOT_KINDS:
        raise DataValidationError("virtual root kind is invalid")
    storage_id = (
        f"EXECUTION_SCRATCH.{owner_id}"
        if root_id == "EXECUTION_SCRATCH"
        else root_id
    )
    return require_identifier(
        storage_id, "virtual root storage identity", maximum_bytes=128
    )


def _virtual_path(value: Any, *, allow_root: bool = False) -> str:
    if value == "" and allow_root:
        return ""
    path = require_nfc_string(value, "virtual path", MAX_VIRTUAL_PATH_BYTES)
    if (
        path.startswith(("/", "\\"))
        or path.endswith("/")
        or "\\" in path
        or "%" in path
        or ":" in path
    ):
        raise DataValidationError("virtual path is not a relative canonical path")
    segments = path.split("/")
    if len(segments) > MAX_VIRTUAL_PATH_DEPTH:
        raise DataCapacityError("virtual path depth is exceeded")
    for segment in segments:
        encoded = segment.encode("utf-8")
        stem = segment.split(".", 1)[0].upper()
        if (
            not encoded
            or len(encoded) > MAX_VIRTUAL_SEGMENT_BYTES
            or segment in {".", ".."}
            or segment.endswith((" ", "."))
            or stem in _WINDOWS_DEVICE_NAMES
        ):
            raise DataValidationError("virtual path segment is forbidden")
    return path


def _virtual_empty_digest() -> str:
    return sha256_digest(b"")


class DataRepository:
    """The only durable mutation boundary for v0.8 local data resources."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        cursor_secret: bytes,
        procedure_binding_check: ProcedureBindingCheck | None = None,
        virtual_file_reader: Callable[[str, str, str], bytes] | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.cursors = CursorCodec(cursor_secret)
        self.handles = ResourceHandleCodec(cursor_secret)
        self.procedure_binding_check = procedure_binding_check
        self.virtual_file_reader = virtual_file_reader
        self.mutations = DataMutationCoordinator(
            session_factory,
            procedure_binding_check=procedure_binding_check,
            schema_check=self._verify_mutation_integrity,
        )

    @staticmethod
    def _verify_schema(session: Session) -> None:
        verify_persisted_schema_fingerprint(
            session.connection(), require_activated=True
        )

    def _verify_mutation_integrity(self, session: Session) -> None:
        self._verify_schema(session)
        try:
            verify_data_integrity(
                session.connection(), virtual_file_reader=self.virtual_file_reader
            )
        except DataSchemaError as exc:
            raise DataCorruptionError(
                "data service integrity verification failed"
            ) from exc

    def _verify_execution_binding(
        self,
        session: Session,
        execution: Any,
        binding: ProcedureCallerBinding,
    ) -> tuple[str, int]:
        if not isinstance(session, Session) or type(binding) is not ProcedureCallerBinding:
            raise DataValidationError("runtime container transaction is invalid")
        self._verify_schema(session)
        session.flush()
        execution_id = require_identifier(
            getattr(execution, "id", None), "execution_id", maximum_bytes=120
        )
        if (
            execution_id != binding.execution_id
            or getattr(execution, "ir_version", None) != "0.8"
            or getattr(execution, "worker_generation", None)
            != binding.worker_generation
        ):
            raise DataAuthorizationError("runtime execution binding differs")
        execution_revision = require_expected_revision(
            getattr(execution, "revision", None), "execution revision"
        )
        if self.procedure_binding_check is None:
            raise DataAuthorizationError(
                "runtime containers require admitted-generation authorization"
            )
        self.procedure_binding_check(session, binding)
        return execution_id, execution_revision

    def stage_execution_admission(
        self,
        session: Session,
        execution: Any,
        binding: ProcedureCallerBinding,
        *,
        args: Iterable[ContainerVariableDefinition],
        ivars: Iterable[ContainerVariableDefinition] = (),
        local: Iterable[ContainerVariableDefinition] = (),
        schema_revision: int = 1,
        acl_revision: int = 0,
    ) -> dict[str, Any]:
        """Stage ARGS/IVARS/LOCAL revision 1 in the caller's transaction."""

        execution_id, execution_revision = self._verify_execution_binding(
            session, execution, binding
        )
        schema_revision = require_positive_revision(
            schema_revision, "schema_revision"
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        admission_digest = caller_binding_digest(binding)
        definitions = {
            ContainerKind.ARGS: _validate_variable_definitions(args),
            ContainerKind.IVARS: _validate_variable_definitions(ivars),
            ContainerKind.LOCAL: _validate_variable_definitions(local),
        }
        projections: dict[str, Any] = {}
        for kind in (ContainerKind.ARGS, ContainerKind.IVARS, ContainerKind.LOCAL):
            container_id = _runtime_container_id(execution_id, kind)
            identity = _container_identity(kind, execution_id, container_id)
            if session.get(DataContainer, identity, with_for_update=True) is not None:
                raise DataConflictError("runtime container identity already exists")
            states = tuple(_variable_state(item, 1) for item in definitions[kind])
            state_bytes, digest = _container_state_bytes(states)
            commit_digest = _runtime_commit_digest(
                binding,
                container_id=container_id,
                container_revision=1,
                content_digest=digest,
                checkpoint_sequence=0,
                execution_revision=execution_revision,
            )
            session.add(
                DataContainer(
                    container_id=container_id,
                    kind=kind.value,
                    owner_id=execution_id,
                    execution_id=execution_id,
                    admission_worker_generation=binding.worker_generation,
                    admission_execution_revision=execution_revision,
                    admission_binding_digest=admission_digest,
                    current_revision=1,
                    schema_revision=schema_revision,
                    current_content_digest=digest,
                    acl_revision=acl_revision,
                    mutable=kind is not ContainerKind.ARGS,
                    tombstoned=False,
                )
            )
            session.flush()
            session.add(
                DataContainerRevision(
                    kind=kind.value,
                    owner_id=execution_id,
                    container_id=container_id,
                    revision=1,
                    schema_revision=schema_revision,
                    checkpoint_sequence=0,
                    execution_revision=execution_revision,
                    worker_generation=binding.worker_generation,
                    commit_binding_digest=commit_digest,
                    content_digest=digest,
                    canonical_variables=state_bytes,
                    tombstoned=False,
                    created_by_principal=binding.service_principal_id,
                )
            )
            projections[kind.value] = {
                "container_id": container_id,
                "content_digest": digest,
                "revision": 1,
                "variable_count": len(states),
            }
        session.flush()
        return {
            "execution_id": execution_id,
            "execution_revision": execution_revision,
            "projections": projections,
            "worker_generation": binding.worker_generation,
        }

    def stage_execution_checkpoint(
        self,
        session: Session,
        execution: Any,
        binding: ProcedureCallerBinding,
        *,
        checkpoint_sequence: int,
        expected_ivars_revision: int,
        expected_local_revision: int,
        ivars: Iterable[ContainerVariableDefinition],
        local: Iterable[ContainerVariableDefinition],
    ) -> dict[str, Any]:
        """Stage IVARS and LOCAL heads beside an Execution checkpoint update."""

        execution_id, execution_revision = self._verify_execution_binding(
            session, execution, binding
        )
        checkpoint_sequence = require_expected_revision(
            checkpoint_sequence, "checkpoint_sequence"
        )
        expected = {
            ContainerKind.IVARS: require_positive_revision(
                expected_ivars_revision, "expected_ivars_revision"
            ),
            ContainerKind.LOCAL: require_positive_revision(
                expected_local_revision, "expected_local_revision"
            ),
        }
        requested = {
            ContainerKind.IVARS: _validate_variable_definitions(ivars),
            ContainerKind.LOCAL: _validate_variable_definitions(local),
        }
        staged: list[
            tuple[ContainerKind, DataContainer, tuple[dict[str, Any], ...]]
        ] = []
        for kind in (ContainerKind.IVARS, ContainerKind.LOCAL):
            container_id = _runtime_container_id(execution_id, kind)
            head, state = self._load_container(
                session,
                execution_id,
                container_id,
                0,
                kind=kind,
                lock=True,
            )
            if (
                head.kind != kind.value
                or head.execution_id != execution_id
                or head.current_revision != expected[kind]
            ):
                raise DataConflictError("runtime container revision differs")
            previous = session.get(
                DataContainerRevision,
                _container_revision_identity(
                    kind, execution_id, container_id, head.current_revision
                ),
                with_for_update=True,
            )
            if (
                previous is None
                or previous.checkpoint_sequence is None
                or previous.checkpoint_sequence >= checkpoint_sequence
            ):
                raise DataConflictError("runtime checkpoint sequence is not monotonic")
            staged.append(
                (kind, head, _replace_container_state(state, requested[kind]))
            )
        projections: dict[str, Any] = {}
        for kind, head, states in staged:
            new_revision = _next_revision(head.current_revision)
            state_bytes, digest = _container_state_bytes(states)
            commit_digest = _runtime_commit_digest(
                binding,
                container_id=head.container_id,
                container_revision=new_revision,
                content_digest=digest,
                checkpoint_sequence=checkpoint_sequence,
                execution_revision=execution_revision,
            )
            session.add(
                DataContainerRevision(
                    kind=kind.value,
                    owner_id=execution_id,
                    container_id=head.container_id,
                    revision=new_revision,
                    schema_revision=head.schema_revision,
                    checkpoint_sequence=checkpoint_sequence,
                    execution_revision=execution_revision,
                    worker_generation=binding.worker_generation,
                    commit_binding_digest=commit_digest,
                    content_digest=digest,
                    canonical_variables=state_bytes,
                    tombstoned=False,
                    created_by_principal=binding.service_principal_id,
                )
            )
            head.current_revision = new_revision
            head.current_content_digest = digest
            projections[kind.value] = {
                "container_id": head.container_id,
                "content_digest": digest,
                "revision": new_revision,
                "variable_count": len(
                    [item for item in states if not item["tombstoned"]]
                ),
            }
        session.flush()
        return {
            "checkpoint_sequence": checkpoint_sequence,
            "execution_id": execution_id,
            "execution_revision": execution_revision,
            "projections": projections,
            "worker_generation": binding.worker_generation,
        }

    def execution_projection_revisions(
        self,
        session: Session,
        execution_id: str,
    ) -> dict[str, int]:
        """Lock and return the authoritative IVARS/LOCAL head revisions."""

        if not isinstance(session, Session):
            raise DataValidationError("runtime container transaction is invalid")
        self._verify_schema(session)
        execution_id = require_identifier(
            execution_id, "execution_id", maximum_bytes=120
        )
        revisions: dict[str, int] = {}
        for kind in (ContainerKind.IVARS, ContainerKind.LOCAL):
            container_id = _runtime_container_id(execution_id, kind)
            head, _ = self._load_container(
                session,
                execution_id,
                container_id,
                0,
                kind=kind,
                lock=True,
            )
            if (
                head.kind != kind.value
                or head.execution_id != execution_id
                or head.admission_binding_digest is None
                or head.admission_worker_generation is None
                or head.admission_execution_revision is None
            ):
                raise CorruptContainerError("runtime container binding is corrupt")
            revisions[kind.value] = require_positive_revision(
                head.current_revision, f"{kind.value} revision"
            )
        return revisions

    def assert_execution_projections(
        self,
        session: Session,
        execution: Any,
        binding: ProcedureCallerBinding,
        *,
        args: Iterable[ContainerVariableDefinition],
        ivars: Iterable[ContainerVariableDefinition] = (),
        local: Iterable[ContainerVariableDefinition] = (),
        schema_revision: int = 1,
        acl_revision: int = 0,
    ) -> dict[str, Any]:
        """Verify immutable admission projections on an idempotent create replay."""

        execution_id, _ = self._verify_execution_binding(session, execution, binding)
        schema_revision = require_positive_revision(
            schema_revision, "schema_revision"
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected = {
            ContainerKind.ARGS: _validate_variable_definitions(args),
            ContainerKind.IVARS: _validate_variable_definitions(ivars),
            ContainerKind.LOCAL: _validate_variable_definitions(local),
        }
        projections: dict[str, Any] = {}
        for kind in (ContainerKind.ARGS, ContainerKind.IVARS, ContainerKind.LOCAL):
            container_id = _runtime_container_id(execution_id, kind)
            head = session.get(
                DataContainer,
                _container_identity(kind, execution_id, container_id),
                with_for_update=True,
            )
            initial = session.get(
                DataContainerRevision,
                _container_revision_identity(kind, execution_id, container_id, 1),
                with_for_update=True,
            )
            states = tuple(_variable_state(item, 1) for item in expected[kind])
            expected_bytes, expected_digest = _container_state_bytes(states)
            expected_commit_digest = (
                _runtime_commit_digest_from_binding(
                    caller_digest=head.admission_binding_digest,
                    worker_generation=head.admission_worker_generation,
                    container_id=container_id,
                    container_revision=1,
                    content_digest=expected_digest,
                    checkpoint_sequence=0,
                    execution_revision=initial.execution_revision,
                )
                if (
                    head is not None
                    and head.admission_binding_digest is not None
                    and head.admission_worker_generation is not None
                    and initial is not None
                    and initial.execution_revision is not None
                )
                else None
            )
            if (
                head is None
                or initial is None
                or head.kind != kind.value
                or head.owner_id != execution_id
                or head.execution_id != execution_id
                or head.schema_revision != schema_revision
                or head.acl_revision != acl_revision
                or initial.schema_revision != schema_revision
                or initial.canonical_variables != expected_bytes
                or initial.content_digest != expected_digest
                or initial.checkpoint_sequence != 0
                or initial.worker_generation != head.admission_worker_generation
                or initial.execution_revision != head.admission_execution_revision
                or initial.commit_binding_digest != expected_commit_digest
                or (kind is ContainerKind.ARGS and head.current_revision != 1)
            ):
                raise CorruptContainerError("runtime admission projection differs")
            current_head, current_state = self._load_container(
                session,
                execution_id,
                container_id,
                acl_revision,
                kind=kind,
                lock=True,
            )
            projections[kind.value] = {
                "container_id": container_id,
                "content_digest": current_head.current_content_digest,
                "revision": current_head.current_revision,
                "variable_count": len(
                    [item for item in current_state if not item["tombstoned"]]
                ),
            }
        return {"execution_id": execution_id, "projections": projections}

    @staticmethod
    def catalog_dependency_target_ids(
        dependencies: Iterable[CatalogDependencyDefinition],
    ) -> tuple[str, ...]:
        """Return the exact target IDs for server-issued READ grants."""

        values = tuple(dependencies)
        if any(type(item) is not CatalogDependencyDefinition for item in values):
            raise DataValidationError("catalog dependencies are invalid")
        return tuple(
            sorted(
                {item.target_catalog_id for item in values},
                key=lambda value: value.encode("ascii"),
            )
        )

    @staticmethod
    def _catalog_revision_components(
        session: Session,
        head: DataCatalog,
        revision: DataCatalogRevision,
    ) -> tuple[CatalogNode, tuple[CatalogDependency, ...]]:
        try:
            kind = CatalogKind(head.kind)
            if (
                revision.catalog_id != head.catalog_id
                or revision.schema_version != head.schema_version
                or type(revision.canonical_content) is not bytes
            ):
                raise CorruptCatalogError("catalog revision identity differs")
            entry_rows = session.scalars(
                select(DataCatalogEntry)
                .where(
                    DataCatalogEntry.catalog_id == head.catalog_id,
                    DataCatalogEntry.catalog_revision == revision.revision,
                )
                .order_by(DataCatalogEntry.entry_id)
            ).all()
            entries: list[dict[str, Any]] = []
            entry_ids: set[str] = set()
            names: set[str] = set()
            for row in entry_rows:
                entry_id = require_identifier(
                    row.entry_id, "catalog entry_id", maximum_bytes=128
                )
                qualified_name = require_nfc_string(
                    row.qualified_name, "catalog qualified_name", 256
                )
                expected_uri = CatalogURI(
                    kind, head.catalog_id, revision.revision, entry_id
                ).canonical
                if (
                    entry_id in entry_ids
                    or qualified_name in names
                    or row.local_uri != expected_uri
                    or type(row.canonical_entry) is not bytes
                    or sha256_digest(row.canonical_entry) != row.content_digest
                ):
                    raise CorruptCatalogError("catalog entry projection differs")
                content = strict_json_loads(
                    row.canonical_entry, maximum_bytes=MAX_INTERNAL_STATE_BYTES
                )
                if canonical_json_bytes(content) != row.canonical_entry:
                    raise CorruptCatalogError("catalog entry is not canonical")
                entry_ids.add(entry_id)
                names.add(qualified_name)
                entries.append(
                    {
                        "content": content,
                        "entry_id": entry_id,
                        "qualified_name": qualified_name,
                    }
                )

            dependency_rows = session.scalars(
                select(DataDependency)
                .where(
                    DataDependency.source_catalog_id == head.catalog_id,
                    DataDependency.source_revision == revision.revision,
                )
                .order_by(DataDependency.dependency_id)
            ).all()
            dependencies: list[CatalogDependency] = []
            dependency_content: list[dict[str, Any]] = []
            for ordinal, row in enumerate(dependency_rows):
                if row.ordinal != ordinal:
                    raise CorruptCatalogError("catalog dependency order differs")
                dependency = CatalogDependency(
                    row.dependency_id,
                    row.source_catalog_id,
                    row.source_revision,
                    row.target_catalog_id,
                    row.target_revision,
                    row.target_content_digest,
                    DependencyRelationship(row.relationship),
                )
                dependencies.append(dependency)
                dependency_content.append(
                    {
                        "dependency_id": dependency.dependency_id,
                        "relationship": dependency.relationship.value,
                        "target_catalog_id": dependency.target_catalog_id,
                        "target_content_digest": dependency.target_content_digest,
                        "target_revision": dependency.target_revision,
                    }
                )

            expected_content = canonical_json_bytes(
                {
                    "catalog_id": head.catalog_id,
                    "dependencies": dependency_content,
                    "entries": entries,
                    "kind": kind.value,
                    "revision": revision.revision,
                    "schema_version": revision.schema_version,
                }
            )
            if (
                expected_content != revision.canonical_content
                or sha256_digest(expected_content) != revision.content_digest
            ):
                raise CorruptCatalogError("catalog revision projection differs")
            return (
                CatalogNode(
                    head.catalog_id,
                    kind,
                    revision.revision,
                    revision.content_digest,
                ),
                tuple(dependencies),
            )
        except CorruptCatalogError:
            raise
        except (DataValidationError, TypedValueError, ValueError) as exc:
            raise CorruptCatalogError("catalog revision is corrupt") from exc

    @classmethod
    def _verify_catalog_graph(
        cls,
        session: Session,
        catalog_id: str,
        revision: int,
        *,
        owner_id: str,
        authorization_scope: str,
    ) -> ResolvedCatalogClosure:
        queue: list[tuple[str, int]] = [(catalog_id, revision)]
        nodes: dict[tuple[str, int], CatalogNode] = {}
        revisions: dict[tuple[str, int], DataCatalogRevision] = {}
        edges: dict[str, CatalogDependency] = {}
        while queue:
            identity = queue.pop(0)
            if identity in nodes:
                continue
            head = session.get(DataCatalog, identity[0])
            row = session.get(DataCatalogRevision, identity)
            if head is None or row is None:
                raise CorruptCatalogError("catalog dependency revision is missing")
            if (
                head.owner_id != owner_id
                or head.authorization_scope != authorization_scope
            ):
                raise CorruptCatalogError("catalog dependency authority differs")
            node, outgoing = cls._catalog_revision_components(session, head, row)
            nodes[node.identity] = node
            revisions[node.identity] = row
            for edge in outgoing:
                previous = edges.get(edge.dependency_id)
                if previous is not None and previous != edge:
                    raise CorruptCatalogError(
                        "catalog dependency identity is ambiguous"
                    )
                edges[edge.dependency_id] = edge
                queue.append(edge.target_identity)

        try:
            values = tuple(nodes.values())
            dependencies = tuple(edges.values())
            closure = resolve_catalog_closure(
                (catalog_id, revision), values, dependencies
            )
            for identity, row in revisions.items():
                expected = resolve_catalog_closure(identity, values, dependencies)
                if expected.closure_digest != row.closure_digest:
                    raise CorruptCatalogError("catalog closure digest differs")
            return closure
        except CorruptCatalogError:
            raise
        except (
            DataValidationError,
            DependencyCycleError,
            DependencyDigestError,
            DependencyNotFoundError,
        ) as exc:
            raise CorruptCatalogError("catalog dependency graph is corrupt") from exc

    def publish_catalog(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        catalog_id: str,
        kind: CatalogKind,
        schema_version: str,
        acl_revision: int,
        expected_revision: int,
        idempotency_key: str,
        entries: Iterable[CatalogEntryDefinition],
        dependencies: Iterable[CatalogDependencyDefinition] = (),
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        catalog_id = require_identifier(catalog_id, "catalog_id", maximum_bytes=128)
        if type(kind) is not CatalogKind:
            raise DataValidationError("catalog kind is invalid")
        schema_version = _schema_version(schema_version)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_expected_revision(expected_revision)
        entry_values = tuple(entries)
        dependency_values = tuple(dependencies)
        if len(entry_values) > MAX_CATALOG_ENTRIES:
            raise DataCapacityError("catalog entry bound exceeded")
        if any(type(item) is not CatalogEntryDefinition for item in entry_values):
            raise DataValidationError("catalog entries are invalid")
        if any(type(item) is not CatalogDependencyDefinition for item in dependency_values):
            raise DataValidationError("catalog dependencies are invalid")
        if len({item.entry_id for item in entry_values}) != len(entry_values):
            raise DataValidationError("catalog entry identity is duplicated")
        if len({item.qualified_name for item in entry_values}) != len(entry_values):
            raise DataValidationError("catalog qualified name is duplicated")
        if len({item.dependency_id for item in dependency_values}) != len(dependency_values):
            raise DataValidationError("catalog dependency identity is duplicated")
        ordered_entries = tuple(
            sorted(entry_values, key=lambda item: item.entry_id.encode("ascii"))
        )
        ordered_dependencies = tuple(
            sorted(dependency_values, key=lambda item: item.dependency_id.encode("ascii"))
        )
        for target_catalog_id in self.catalog_dependency_target_ids(
            ordered_dependencies
        ):
            authorization.require(
                ResourceFamily.CATALOGS,
                "READ",
                owner_id=owner_id,
                resource_id=target_catalog_id,
                acl_revision=acl_revision,
            )
        body = {
            "acl_revision": acl_revision,
            "dependencies": [
                {
                    "dependency_id": item.dependency_id,
                    "relationship": item.relationship.value,
                    "target_catalog_id": item.target_catalog_id,
                    "target_content_digest": item.target_content_digest,
                    "target_revision": item.target_revision,
                }
                for item in ordered_dependencies
            ],
            "entries": [
                {
                    "content": dict(item.content),
                    "entry_id": item.entry_id,
                    "qualified_name": item.qualified_name,
                }
                for item in ordered_entries
            ],
            "kind": kind.value,
            "schema_version": schema_version,
        }
        request = MutationRequest.build(
            authorization,
            ResourceFamily.CATALOGS,
            "PUBLISH",
            owner_id=owner_id,
            resource_id=catalog_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body=body,
        )
        target_closures: dict[tuple[str, int], ResolvedCatalogClosure] = {}

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            head = session.get(DataCatalog, catalog_id, with_for_update=True)
            if head is not None and (
                head.owner_id != owner_id
                or head.acl_revision != acl_revision
                or head.authorization_scope != authorization.scope_profile
            ):
                raise DataAuthorizationError("catalog publication is not authorized")
            if head is not None:
                self._verify_catalog_graph(
                    session,
                    head.catalog_id,
                    head.current_revision,
                    owner_id=owner_id,
                    authorization_scope=authorization.scope_profile,
                )
            target_closures.clear()
            for item in ordered_dependencies:
                target_head = session.get(
                    DataCatalog, item.target_catalog_id, with_for_update=True
                )
                target_revision = session.get(
                    DataCatalogRevision,
                    (item.target_catalog_id, item.target_revision),
                    with_for_update=True,
                )
                if target_head is None or target_revision is None:
                    raise DependencyNotFoundError(
                        "dependency target catalog is unavailable"
                    )
                if (
                    target_head.owner_id != owner_id
                    or target_head.acl_revision != acl_revision
                    or target_head.authorization_scope != authorization.scope_profile
                ):
                    raise DataAuthorizationError(
                        "catalog dependency target is not authorized"
                    )
                authorization.require(
                    ResourceFamily.CATALOGS,
                    "READ",
                    owner_id=owner_id,
                    resource_id=item.target_catalog_id,
                    acl_revision=target_head.acl_revision,
                )
                if target_revision.content_digest != item.target_content_digest:
                    raise DependencyDigestError(
                        "dependency target digest differs"
                    )
                identity = (item.target_catalog_id, item.target_revision)
                if identity not in target_closures:
                    target_closures[identity] = self._verify_catalog_graph(
                        session,
                        item.target_catalog_id,
                        item.target_revision,
                        owner_id=owner_id,
                        authorization_scope=authorization.scope_profile,
                    )

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            head = session.get(DataCatalog, catalog_id, with_for_update=True)
            if head is None:
                if expected_revision != 0:
                    raise DataConflictError("catalog creation revision differs")
                new_revision = 1
            else:
                if head.kind != kind.value or head.schema_version != schema_version:
                    raise DataConflictError("catalog immutable identity differs")
                if head.current_revision != expected_revision:
                    _raise_revision_conflict(
                        authorization,
                        ResourceFamily.CATALOGS,
                        "READ",
                        owner_id=owner_id,
                        resource_id=catalog_id,
                        acl_revision=acl_revision,
                        current_revision=head.current_revision,
                    )
                new_revision = _next_revision(head.current_revision)
            canonical_content = {
                "catalog_id": catalog_id,
                "dependencies": body["dependencies"],
                "entries": body["entries"],
                "kind": kind.value,
                "revision": new_revision,
                "schema_version": schema_version,
            }
            content_text, content_digest = _json_text(
                canonical_content, MAX_INTERNAL_STATE_BYTES, "catalog content"
            )
            root_node = CatalogNode(catalog_id, kind, new_revision, content_digest)
            nodes = {root_node.identity: root_node}
            edges: dict[str, CatalogDependency] = {}
            for target_closure in target_closures.values():
                for node in target_closure.nodes:
                    previous = nodes.get(node.identity)
                    if previous is not None and previous != node:
                        raise CorruptCatalogError(
                            "catalog dependency node identity differs"
                        )
                    nodes[node.identity] = node
                for edge in target_closure.dependencies:
                    previous = edges.get(edge.dependency_id)
                    if previous is not None and previous != edge:
                        raise CorruptCatalogError(
                            "catalog dependency identity is ambiguous"
                        )
                    edges[edge.dependency_id] = edge
            for edge in (
                CatalogDependency(
                    item.dependency_id,
                    catalog_id,
                    new_revision,
                    item.target_catalog_id,
                    item.target_revision,
                    item.target_content_digest,
                    item.relationship,
                )
                for item in ordered_dependencies
            ):
                previous = edges.get(edge.dependency_id)
                if previous is not None and previous != edge:
                    raise DataValidationError(
                        "catalog dependency identity is ambiguous in the closure"
                    )
                edges[edge.dependency_id] = edge
            closure = resolve_catalog_closure(
                root_node.identity, tuple(nodes.values()), tuple(edges.values())
            )
            principal = actor_principal_id(authorization.caller)
            if head is None:
                head = DataCatalog(
                    catalog_id=catalog_id,
                    kind=kind.value,
                    owner_id=owner_id,
                    authorization_scope=authorization.scope_profile,
                    current_revision=new_revision,
                    current_content_digest=content_digest,
                    schema_version=schema_version,
                    acl_revision=acl_revision,
                )
                session.add(head)
            else:
                head.current_revision = new_revision
                head.current_content_digest = content_digest
            session.add(
                DataCatalogRevision(
                    catalog_id=catalog_id,
                    revision=new_revision,
                    schema_version=schema_version,
                    content_digest=content_digest,
                    closure_digest=closure.closure_digest,
                    canonical_content=content_text,
                    created_by_principal=principal,
                )
            )
            session.flush()
            for item in ordered_entries:
                entry_text, entry_digest = _json_text(
                    dict(item.content), MAX_INTERNAL_STATE_BYTES, "catalog entry"
                )
                session.add(
                    DataCatalogEntry(
                        catalog_id=catalog_id,
                        catalog_revision=new_revision,
                        entry_id=item.entry_id,
                        qualified_name=item.qualified_name,
                        local_uri=CatalogURI(
                            kind, catalog_id, new_revision, item.entry_id
                        ).canonical,
                        canonical_entry=entry_text,
                        content_digest=entry_digest,
                    )
                )
            for ordinal, item in enumerate(ordered_dependencies):
                session.add(
                    DataDependency(
                        dependency_id=item.dependency_id,
                        source_catalog_id=catalog_id,
                        source_revision=new_revision,
                        target_catalog_id=item.target_catalog_id,
                        target_revision=item.target_revision,
                        target_content_digest=item.target_content_digest,
                        relationship=item.relationship.value,
                        ordinal=ordinal,
                    )
                )
            session.flush()
            verified = self._verify_catalog_graph(
                session,
                catalog_id,
                new_revision,
                owner_id=owner_id,
                authorization_scope=authorization.scope_profile,
            )
            if verified.closure_digest != closure.closure_digest:
                raise CorruptCatalogError("published catalog closure differs")
            return MutationEffect(
                result={
                    "catalog_id": catalog_id,
                    "closure_digest": closure.closure_digest,
                    "content_digest": content_digest,
                    "kind": kind.value,
                    "revision": new_revision,
                },
                prior_revision=expected_revision,
                new_revision=new_revision,
                outcome="PUBLISHED",
                response_status=201 if expected_revision == 0 else 200,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def read_catalog_entry(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        acl_revision: int,
        uri: str,
    ) -> dict[str, Any]:
        parsed = CatalogURI.parse(uri)
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        authorization.require(
            ResourceFamily.CATALOGS,
            "READ",
            owner_id=owner_id,
            resource_id=parsed.catalog_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head = session.get(DataCatalog, parsed.catalog_id)
            if (
                head is None
                or head.owner_id != owner_id
                or head.acl_revision != acl_revision
            ):
                raise DataNotFoundError("catalog entry not found")
            if head.kind != parsed.kind.value:
                raise DataNotFoundError("catalog entry not found")
            revision = session.get(
                DataCatalogRevision, (parsed.catalog_id, parsed.revision)
            )
            if revision is None:
                raise DataNotFoundError("catalog entry not found")
            self._verify_catalog_graph(
                session,
                parsed.catalog_id,
                parsed.revision,
                owner_id=owner_id,
                authorization_scope=head.authorization_scope,
            )
            row = session.get(
                DataCatalogEntry,
                (parsed.catalog_id, parsed.revision, parsed.entry_id),
            )
            if row is None or row.local_uri != parsed.canonical:
                raise DataNotFoundError("catalog entry not found")
            try:
                raw = row.canonical_entry
                if type(raw) is not bytes:
                    raise CorruptCatalogError("catalog entry bytes are invalid")
                if sha256_digest(raw) != row.content_digest:
                    raise CorruptCatalogError("catalog entry digest differs")
                content = strict_json_loads(raw, maximum_bytes=MAX_INTERNAL_STATE_BYTES)
                if canonical_json_bytes(content) != raw:
                    raise CorruptCatalogError("catalog entry is not canonical")
            except TypedValueError as exc:
                raise CorruptCatalogError("catalog entry is corrupt") from exc
            return {
                "catalog_id": row.catalog_id,
                "catalog_revision": row.catalog_revision,
                "content": content,
                "content_digest": row.content_digest,
                "entry_id": row.entry_id,
                "kind": head.kind,
                "local_uri": row.local_uri,
                "qualified_name": row.qualified_name,
            }

    def list_catalogs(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        page_size = _page_size(page_size)
        authorization.require(ResourceFamily.CATALOGS, "LIST", owner_id=owner_id)
        with self.session_factory() as session:
            self._verify_schema(session)
            rows = session.scalars(
                select(DataCatalog)
                .where(DataCatalog.owner_id == owner_id)
                .order_by(DataCatalog.catalog_id)
            ).all()
            for row in rows:
                self._verify_catalog_graph(
                    session,
                    row.catalog_id,
                    row.current_revision,
                    owner_id=owner_id,
                    authorization_scope=row.authorization_scope,
                )
            snapshot = canonical_json_bytes(
                [
                    {
                        "catalog_id": row.catalog_id,
                        "content_digest": row.current_content_digest,
                        "revision": row.current_revision,
                    }
                    for row in rows
                ]
            )
            owner_revision = int(sha256_digest(snapshot)[:16], 16) & ((1 << 63) - 1)
            owner_revision = owner_revision or 1
            last_identity = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=owner_id,
                    revision=owner_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_identity = decoded.last_identity
            selected = [
                row
                for row in rows
                if row.catalog_id.encode("ascii") > last_identity.encode("ascii")
            ][: page_size + 1]
            page = selected[:page_size]
            next_cursor = None
            if len(selected) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=owner_id,
                        revision=owner_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final.catalog_id,
                        last_identity=final.catalog_id,
                    )
                )
            return {
                "catalogs": [
                    {
                        "acl_revision": row.acl_revision,
                        "catalog_id": row.catalog_id,
                        "content_digest": row.current_content_digest,
                        "kind": row.kind,
                        "revision": row.current_revision,
                        "schema_version": row.schema_version,
                    }
                    for row in page
                ],
                "next_cursor": next_cursor,
                "owner_revision": owner_revision,
            }

    def read_catalog_revision(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        catalog_id: str,
        acl_revision: int,
        revision: int,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        catalog_id = require_identifier(catalog_id, "catalog_id", maximum_bytes=128)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        revision = require_positive_revision(revision)
        authorization.require(
            ResourceFamily.CATALOGS,
            "READ",
            owner_id=owner_id,
            resource_id=catalog_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head = session.get(DataCatalog, catalog_id)
            row = session.get(DataCatalogRevision, (catalog_id, revision))
            if (
                head is None
                or row is None
                or head.owner_id != owner_id
                or head.acl_revision != acl_revision
            ):
                raise DataNotFoundError("catalog revision not found")
            self._verify_catalog_graph(
                session,
                catalog_id,
                revision,
                owner_id=owner_id,
                authorization_scope=head.authorization_scope,
            )
            if type(row.canonical_content) is not bytes:
                raise CorruptCatalogError("catalog revision bytes are invalid")
            if sha256_digest(row.canonical_content) != row.content_digest:
                raise CorruptCatalogError("catalog revision digest differs")
            try:
                content = strict_json_loads(
                    row.canonical_content, maximum_bytes=MAX_INTERNAL_STATE_BYTES
                )
            except TypedValueError as exc:
                raise CorruptCatalogError("catalog revision content is invalid") from exc
            if canonical_json_bytes(content) != row.canonical_content:
                raise CorruptCatalogError("catalog revision content is not canonical")
            return {
                "catalog_id": catalog_id,
                "closure_digest": row.closure_digest,
                "content": content,
                "content_digest": row.content_digest,
                "kind": head.kind,
                "revision": row.revision,
                "schema_version": row.schema_version,
            }

    def create_dictionary(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        dictionary_id: str,
        acl_revision: int,
        idempotency_key: str,
        document: DictionaryDocument,
        deadline_check: DeadlineCheck | None = None,
    ) -> dict[str, Any]:
        if type(document) is not DictionaryDocument or document.format is not DictionaryFormat.DB:
            raise DictionaryExchangeError(
                "FORMAT_UNSUPPORTED", "CreateDictionary accepts only a DB document"
            )
        if document.base_revision != 0:
            raise DictionaryExchangeError(
                "REVISION_CONFLICT", "CreateDictionary requires base revision zero"
            )
        return self._mutate_dictionary(
            authorization,
            owner_id=owner_id,
            dictionary_id=dictionary_id,
            acl_revision=acl_revision,
            expected_revision=0,
            idempotency_key=idempotency_key,
            document=document,
            allow_create=True,
            deadline_check=deadline_check,
        )

    def load_dictionary(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        dictionary_id: str,
        acl_revision: int,
        expected_revision: int,
        idempotency_key: str,
        document: DictionaryDocument,
        deadline_check: DeadlineCheck | None = None,
    ) -> dict[str, Any]:
        return self._mutate_dictionary(
            authorization,
            owner_id=owner_id,
            dictionary_id=dictionary_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            document=document,
            allow_create=False,
            deadline_check=deadline_check,
        )

    def _mutate_dictionary(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        dictionary_id: str,
        acl_revision: int,
        expected_revision: int,
        idempotency_key: str,
        document: DictionaryDocument,
        allow_create: bool,
        deadline_check: DeadlineCheck | None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        dictionary_id = require_identifier(
            dictionary_id, "dictionary_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_expected_revision(expected_revision)
        if type(document) is not DictionaryDocument:
            raise DataValidationError("document must be a DictionaryDocument")
        if document.dictionary_id != dictionary_id:
            raise DictionaryExchangeError(
                "CORRUPT_DOCUMENT", "document dictionary identity differs from route identity"
            )
        if document.base_revision != expected_revision:
            raise DictionaryExchangeError(
                "REVISION_CONFLICT", "document base revision differs from the request"
            )
        body = {
            "canonical_document_sha256": document.canonical_document_sha256,
            "content_digest": document.content_digest,
            "format": document.format.value,
            "original_bytes_sha256": (
                document.original_bytes_sha256
                or sha256_digest(document.canonical_bytes)
            ),
        }
        request = MutationRequest.build(
            authorization,
            ResourceFamily.DICTIONARIES,
            "IMPORT",
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body=body,
        )
        identity = _dictionary_identity(owner_id, dictionary_id)

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            head = session.get(DataDictionary, identity, with_for_update=True)
            if head is not None and (
                head.owner_id != owner_id or head.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("dictionary import is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            head = session.get(DataDictionary, identity, with_for_update=True)
            if head is None:
                if not allow_create or expected_revision != 0:
                    raise DataNotFoundError("dictionary not found")
                prior_state: tuple[dict[str, Any], ...] = ()
                new_revision = 1
            else:
                if head.tombstoned:
                    raise DataNotFoundError("dictionary not found")
                if allow_create:
                    raise DataConflictError("dictionary identity already exists")
                if head.current_revision != expected_revision:
                    _raise_revision_conflict(
                        authorization,
                        ResourceFamily.DICTIONARIES,
                        "READ",
                        owner_id=owner_id,
                        resource_id=dictionary_id,
                        acl_revision=acl_revision,
                        current_revision=head.current_revision,
                    )
                prior_row = session.get(
                    DataDictionaryRevision,
                    _dictionary_revision_identity(
                        owner_id, dictionary_id, head.current_revision
                    ),
                )
                if prior_row is None:
                    raise CorruptDictionaryError("dictionary head revision is missing")
                prior_state = _decode_dictionary_state(prior_row)
                prior_export = build_db_document(
                    dictionary_id,
                    head.current_revision,
                    _live_dictionary_entries(prior_state),
                )
                if prior_export.content_digest != head.current_content_digest:
                    raise CorruptDictionaryError("dictionary head digest differs")
                new_revision = _next_revision(head.current_revision)

            state_by_id = {item["entry_id"]: dict(item) for item in prior_state}
            folded_historical = {
                item["entry_id"].casefold(): item["entry_id"] for item in prior_state
            }
            if document.format is DictionaryFormat.DB:
                supplied = {entry.entry_id: entry for entry in document.entries}
                for entry_id, state in tuple(state_by_id.items()):
                    if not state["tombstoned"] and entry_id not in supplied:
                        state_by_id[entry_id] = {
                            **state,
                            "revision": _next_revision(state["revision"], "entry revision"),
                            "tombstoned": True,
                            "value": None,
                        }
                for entry in document.entries:
                    state = state_by_id.get(entry.entry_id)
                    historical = folded_historical.get(entry.entry_id.casefold())
                    if historical is not None and historical != entry.entry_id:
                        raise DictionaryExchangeError(
                            "CASE_COLLISION", "dictionary identity has a historical case collision"
                        )
                    if state is not None and state["tombstoned"]:
                        raise DataConflictError("dictionary entry identity is tombstoned")
                    if state is None:
                        entry_revision = 1
                    elif (
                        state["qualified_name"] == entry.qualified_name
                        and state["value_digest"] == entry.value_digest
                    ):
                        entry_revision = state["revision"]
                    else:
                        entry_revision = _next_revision(state["revision"], "entry revision")
                    state_by_id[entry.entry_id] = {
                        "entry_id": entry.entry_id,
                        "qualified_name": entry.qualified_name,
                        "revision": entry_revision,
                        "tombstoned": False,
                        "value": entry.value,
                        "value_digest": entry.value_digest,
                    }
            else:
                for record in document.records:
                    state = state_by_id.get(record.entry_id)
                    if record.operation is ImportOperation.DELETE:
                        if (
                            state is None
                            or state["tombstoned"]
                            or state["revision"] != record.expected_entry_revision
                        ):
                            raise DataConflictError("dictionary entry revision differs")
                        state_by_id[record.entry_id] = {
                            **state,
                            "revision": _next_revision(state["revision"], "entry revision"),
                            "tombstoned": True,
                            "value": None,
                        }
                        continue
                    if record.expected_entry_revision == 0:
                        if state is not None or record.entry_id.casefold() in folded_historical:
                            raise DataConflictError("dictionary entry identity already exists")
                        entry_revision = 1
                    else:
                        if (
                            state is None
                            or state["tombstoned"]
                            or state["revision"] != record.expected_entry_revision
                        ):
                            raise DataConflictError("dictionary entry revision differs")
                        entry_revision = _next_revision(state["revision"], "entry revision")
                    state_by_id[record.entry_id] = {
                        "entry_id": record.entry_id,
                        "qualified_name": record.qualified_name,
                        "revision": entry_revision,
                        "tombstoned": False,
                        "value": record.value,
                        "value_digest": record.value_digest,
                    }

            state_values = tuple(state_by_id.values())
            live_entries = _live_dictionary_entries(state_values)
            exported = build_db_document(dictionary_id, new_revision, live_entries)
            state_bytes, state_sha256 = _dictionary_state_bytes(state_values)
            source_bytes = document.canonical_bytes
            original_bytes = document.original_bytes or source_bytes
            original_sha256 = sha256_digest(original_bytes)
            caller_kind, principal = _caller_source(authorization.caller)
            if head is None:
                head = DataDictionary(
                    dictionary_id=dictionary_id,
                    owner_id=owner_id,
                    authorization_scope=authorization.scope_profile,
                    current_revision=new_revision,
                    current_content_digest=exported.content_digest,
                    acl_revision=acl_revision,
                    tombstoned=False,
                )
                session.add(head)
            else:
                head.current_revision = new_revision
                head.current_content_digest = exported.content_digest
            session.flush()
            session.add(
                DataDictionaryRevision(
                    owner_id=owner_id,
                    dictionary_id=dictionary_id,
                    revision=new_revision,
                    base_revision=expected_revision,
                    source_format=document.format.value,
                    content_digest=exported.content_digest,
                    canonical_entry_state=state_bytes,
                    canonical_entry_state_sha256=state_sha256,
                    canonical_source_document=source_bytes,
                    canonical_source_document_sha256=sha256_digest(source_bytes),
                    original_media_type=document.format.media_type,
                    original_byte_length=len(original_bytes),
                    original_bytes_sha256=original_sha256,
                    original_bytes=original_bytes,
                    actor_principal_id=principal,
                    caller_binding_kind=caller_kind,
                    caller_binding_digest=caller_binding_digest(authorization.caller),
                )
            )
            return MutationEffect(
                result={
                    "content_digest": exported.content_digest,
                    "dictionary_id": dictionary_id,
                    "entry_count": len(live_entries),
                    "revision": new_revision,
                    "source_format": document.format.value,
                },
                prior_revision=expected_revision,
                new_revision=new_revision,
                outcome="IMPORTED",
                response_status=201 if expected_revision == 0 else 200,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
                deadline_check=deadline_check,
            )
        )

    def export_dictionary(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        dictionary_id: str,
        acl_revision: int,
        revision: int | None = None,
    ) -> bytes:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        dictionary_id = require_identifier(
            dictionary_id, "dictionary_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        if revision is not None:
            revision = require_positive_revision(revision)
        authorization.require(
            ResourceFamily.DICTIONARIES,
            "EXPORT",
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head = session.get(
                DataDictionary, _dictionary_identity(owner_id, dictionary_id)
            )
            if (
                head is None
                or head.tombstoned
                or head.owner_id != owner_id
                or head.acl_revision != acl_revision
            ):
                raise DataNotFoundError("dictionary not found")
            selected_revision = revision or head.current_revision
            row = session.get(
                DataDictionaryRevision,
                _dictionary_revision_identity(
                    owner_id, dictionary_id, selected_revision
                ),
            )
            if row is None:
                raise DataNotFoundError("dictionary revision not found")
            state = _decode_dictionary_state(row)
            document = build_db_document(
                dictionary_id,
                selected_revision,
                _live_dictionary_entries(state),
            )
            if document.content_digest != row.content_digest:
                raise CorruptDictionaryError("dictionary revision digest differs")
            if selected_revision == head.current_revision and (
                document.content_digest != head.current_content_digest
            ):
                raise CorruptDictionaryError("dictionary head digest differs")
            return export_dictionary_document(document)

    def list_dictionaries(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        page_size = _page_size(page_size)
        authorization.require(
            ResourceFamily.DICTIONARIES,
            "LIST",
            owner_id=owner_id,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            rows = session.scalars(
                select(DataDictionary)
                .where(
                    DataDictionary.owner_id == owner_id,
                    DataDictionary.tombstoned.is_(False),
                )
                .order_by(DataDictionary.dictionary_id)
            ).all()
            snapshot = canonical_json_bytes(
                [
                    {
                        "content_digest": row.current_content_digest,
                        "dictionary_id": row.dictionary_id,
                        "revision": row.current_revision,
                    }
                    for row in rows
                ]
            )
            owner_revision = int(sha256_digest(snapshot)[:16], 16) & ((1 << 63) - 1)
            owner_revision = owner_revision or 1
            last_identity = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=owner_id,
                    revision=owner_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_identity = decoded.last_identity
            selected = [
                row
                for row in rows
                if row.dictionary_id.encode("ascii") > last_identity.encode("ascii")
            ][: page_size + 1]
            page = selected[:page_size]
            next_cursor = None
            if len(selected) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=owner_id,
                        revision=owner_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final.dictionary_id,
                        last_identity=final.dictionary_id,
                    )
                )
            return {
                "dictionaries": [
                    {
                        "acl_revision": row.acl_revision,
                        "content_digest": row.current_content_digest,
                        "dictionary_id": row.dictionary_id,
                        "revision": row.current_revision,
                    }
                    for row in page
                ],
                "next_cursor": next_cursor,
                "owner_revision": owner_revision,
            }

    def create_container(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        container_id: str,
        schema_revision: int,
        acl_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._create_container(
            authorization,
            owner_id=owner_id,
            container_id=container_id,
            kind=ContainerKind.DATA_CONTAINER,
            schema_revision=schema_revision,
            acl_revision=acl_revision,
            idempotency_key=idempotency_key,
            variables=(),
        )

    def _create_container(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        container_id: str,
        kind: ContainerKind,
        schema_revision: int,
        acl_revision: int,
        idempotency_key: str,
        variables: Iterable[ContainerVariableDefinition],
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        container_id = require_identifier(
            container_id, "container_id", maximum_bytes=128
        )
        if type(kind) is not ContainerKind:
            raise DataValidationError("container kind is invalid")
        schema_revision = require_positive_revision(
            schema_revision, "schema_revision"
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        definitions = _validate_variable_definitions(variables)
        body = {
            "acl_revision": acl_revision,
            "kind": kind.value,
            "schema_revision": schema_revision,
            "variables": [
                {
                    "declared_type": item.declared_type,
                    "name": item.name,
                    "value": validate_typed_value(item.value),
                    "variable_id": item.variable_id,
                }
                for item in definitions
            ],
        }
        evidence_resource_id = f"{kind.value}.{container_id}"
        mutation_authorization = _identity_bound_authorization(
            authorization,
            ResourceFamily.CONTAINERS,
            "CREATE",
            owner_id=owner_id,
            public_resource_id=container_id,
            evidence_resource_id=evidence_resource_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            mutation_authorization,
            ResourceFamily.CONTAINERS,
            "CREATE",
            owner_id=owner_id,
            resource_id=evidence_resource_id,
            acl_revision=acl_revision,
            expected_revision=0,
            idempotency_key=idempotency_key,
            body=body,
        )
        identity = _container_identity(kind, owner_id, container_id)

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            current = session.get(DataContainer, identity, with_for_update=True)
            if current is not None and (
                current.owner_id != owner_id or current.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("container creation is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            if session.get(DataContainer, identity, with_for_update=True) is not None:
                raise DataConflictError("container identity already exists")
            states = tuple(_variable_state(item, 1) for item in definitions)
            state_text, digest = _container_state_bytes(states)
            mutable = kind is not ContainerKind.ARGS
            session.add(
                DataContainer(
                    container_id=container_id,
                    kind=kind.value,
                    owner_id=owner_id,
                    current_revision=1,
                    schema_revision=schema_revision,
                    current_content_digest=digest,
                    acl_revision=acl_revision,
                    mutable=mutable,
                    tombstoned=False,
                )
            )
            session.flush()
            session.add(
                DataContainerRevision(
                    kind=kind.value,
                    owner_id=owner_id,
                    container_id=container_id,
                    revision=1,
                    schema_revision=schema_revision,
                    content_digest=digest,
                    canonical_variables=state_text,
                    checkpoint_sequence=None,
                    execution_revision=None,
                    worker_generation=None,
                    commit_binding_digest=caller_binding_digest(
                        authorization.caller
                    ),
                    tombstoned=False,
                    created_by_principal=actor_principal_id(authorization.caller),
                )
            )
            return MutationEffect(
                result={
                    "container_id": container_id,
                    "content_digest": digest,
                    "kind": kind.value,
                    "revision": 1,
                    "schema_revision": schema_revision,
                    "variable_count": len(states),
                },
                prior_revision=0,
                new_revision=1,
                outcome="CREATED",
                response_status=201,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def read_container(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        container_id: str,
        acl_revision: int,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        container_id = require_identifier(
            container_id, "container_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        authorization.require(
            ResourceFamily.CONTAINERS,
            "READ",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head, state = self._load_container(
                session, owner_id, container_id, acl_revision
            )
            return self._container_projection(head, state)

    def list_containers(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        page_size = _page_size(page_size)
        authorization.require(ResourceFamily.CONTAINERS, "READ", owner_id=owner_id)
        with self.session_factory() as session:
            self._verify_schema(session)
            rows = session.scalars(
                select(DataContainer)
                .where(
                    DataContainer.owner_id == owner_id,
                    DataContainer.tombstoned.is_(False),
                )
                .order_by(DataContainer.kind, DataContainer.container_id)
            ).all()
            snapshot = canonical_json_bytes(
                [
                    {
                        "container_id": row.container_id,
                        "content_digest": row.current_content_digest,
                        "kind": row.kind,
                        "revision": row.current_revision,
                    }
                    for row in rows
                ]
            )
            owner_revision = int(sha256_digest(snapshot)[:16], 16) & ((1 << 63) - 1)
            owner_revision = owner_revision or 1
            last_identity = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=owner_id,
                    revision=owner_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_identity = decoded.last_identity
            selected = [
                row
                for row in rows
                if _container_cursor_identity(row).encode("ascii")
                > last_identity.encode("ascii")
            ][: page_size + 1]
            page = selected[:page_size]
            next_cursor = None
            if len(selected) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=owner_id,
                        revision=owner_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final.container_id,
                        last_identity=_container_cursor_identity(final),
                    )
                )
            return {
                "containers": [
                    {
                        "acl_revision": row.acl_revision,
                        "container_id": row.container_id,
                        "content_digest": row.current_content_digest,
                        "kind": row.kind,
                        "revision": row.current_revision,
                        "schema_revision": row.schema_revision,
                    }
                    for row in page
                ],
                "next_cursor": next_cursor,
                "owner_revision": owner_revision,
            }

    @staticmethod
    def _load_container(
        session: Session,
        owner_id: str,
        container_id: str,
        acl_revision: int,
        *,
        kind: ContainerKind = ContainerKind.DATA_CONTAINER,
        lock: bool = False,
    ) -> tuple[DataContainer, tuple[dict[str, Any], ...]]:
        head = session.get(
            DataContainer,
            _container_identity(kind, owner_id, container_id),
            with_for_update=lock,
        )
        if (
            head is None
            or head.tombstoned
            or head.owner_id != owner_id
            or head.acl_revision != acl_revision
        ):
            raise DataNotFoundError("container not found")
        revision = session.get(
            DataContainerRevision,
            _container_revision_identity(
                kind, owner_id, container_id, head.current_revision
            ),
            with_for_update=lock,
        )
        if revision is None or revision.tombstoned:
            raise CorruptContainerError("container head revision is missing")
        state = _decode_container_state(revision)
        if revision.content_digest != head.current_content_digest:
            raise CorruptContainerError("container head digest differs")
        return head, state

    @staticmethod
    def _container_projection(
        head: DataContainer,
        state: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        variables = [
            {
                "declared_type": item["declared_type"],
                "name": item["name"],
                "revision": item["revision"],
                "value": item["value"],
                "value_digest": item["value_digest"],
                "variable_id": item["variable_id"],
            }
            for item in state
            if not item["tombstoned"]
        ]
        return {
            "acl_revision": head.acl_revision,
            "container_id": head.container_id,
            "content_digest": head.current_content_digest,
            "kind": head.kind,
            "mutable": head.mutable,
            "owner_id": head.owner_id,
            "revision": head.current_revision,
            "schema_revision": head.schema_revision,
            "variables": variables,
        }

    def set_container_variable(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        container_id: str,
        acl_revision: int,
        expected_revision: int,
        expected_variable_revision: int,
        idempotency_key: str,
        variable: ContainerVariableDefinition,
    ) -> dict[str, Any]:
        if type(variable) is not ContainerVariableDefinition:
            raise DataValidationError("variable is invalid")
        canonical_value = validate_typed_value(variable.value)
        body = {
            "declared_type": variable.declared_type,
            "expected_variable_revision": require_expected_revision(
                expected_variable_revision, "expected_variable_revision"
            ),
            "name": variable.name,
            "value": canonical_value,
            "variable_id": variable.variable_id,
        }
        return self._mutate_container_variable(
            authorization,
            operation="SET",
            owner_id=owner_id,
            container_id=container_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body=body,
            variable=variable,
            expected_variable_revision=expected_variable_revision,
        )

    def delete_container_variable(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        container_id: str,
        acl_revision: int,
        expected_revision: int,
        variable_id: str,
        expected_variable_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        variable_id = require_identifier(
            variable_id, "variable_id", maximum_bytes=128
        )
        expected_variable_revision = require_positive_revision(
            expected_variable_revision, "expected_variable_revision"
        )
        return self._mutate_container_variable(
            authorization,
            operation="DELETE",
            owner_id=owner_id,
            container_id=container_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body={
                "expected_variable_revision": expected_variable_revision,
                "variable_id": variable_id,
            },
            variable=None,
            expected_variable_revision=expected_variable_revision,
        )

    def _mutate_container_variable(
        self,
        authorization: AuthorizationContext,
        *,
        operation: str,
        owner_id: str,
        container_id: str,
        acl_revision: int,
        expected_revision: int,
        idempotency_key: str,
        body: Mapping[str, Any],
        variable: ContainerVariableDefinition | None,
        expected_variable_revision: int,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        container_id = require_identifier(
            container_id, "container_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_positive_revision(expected_revision)
        evidence_resource_id = f"{ContainerKind.DATA_CONTAINER.value}.{container_id}"
        mutation_authorization = _identity_bound_authorization(
            authorization,
            ResourceFamily.CONTAINERS,
            operation,
            owner_id=owner_id,
            public_resource_id=container_id,
            evidence_resource_id=evidence_resource_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            mutation_authorization,
            ResourceFamily.CONTAINERS,
            operation,
            owner_id=owner_id,
            resource_id=evidence_resource_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body=dict(body),
        )
        identity = _container_identity(
            ContainerKind.DATA_CONTAINER, owner_id, container_id
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            head = session.get(DataContainer, identity, with_for_update=True)
            if head is not None and (
                head.owner_id != owner_id or head.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("container mutation is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            head, state = self._load_container(
                session, owner_id, container_id, acl_revision, lock=True
            )
            if not head.mutable or head.kind == ContainerKind.ARGS.value:
                raise DataConflictError("container is immutable")
            if head.current_revision != expected_revision:
                _raise_revision_conflict(
                    authorization,
                    ResourceFamily.CONTAINERS,
                    "READ",
                    owner_id=owner_id,
                    resource_id=container_id,
                    acl_revision=acl_revision,
                    current_revision=head.current_revision,
                )
            by_id = {item["variable_id"]: dict(item) for item in state}
            if operation == "SET":
                assert variable is not None
                current = by_id.get(variable.variable_id)
                if current is None:
                    if expected_variable_revision != 0:
                        raise DataConflictError("container variable revision differs")
                    if len([item for item in state if not item["tombstoned"]]) >= MAX_CONTAINER_VARIABLES:
                        raise DataCapacityError("container variable bound exceeded")
                    if any(
                        not item["tombstoned"] and item["name"] == variable.name
                        for item in state
                    ):
                        raise DataConflictError("container variable name already exists")
                    updated = _variable_state(variable, 1)
                else:
                    if current["tombstoned"]:
                        raise DataConflictError("container variable identity is tombstoned")
                    if current["revision"] != expected_variable_revision:
                        raise DataConflictError("container variable revision differs")
                    if (
                        current["declared_type"] != variable.declared_type
                        or current["name"] != variable.name
                    ):
                        raise DataConflictError("container variable declaration is immutable")
                    updated = _variable_state(
                        variable,
                        _next_revision(current["revision"], "variable revision"),
                    )
                by_id[variable.variable_id] = updated
                variable_id = variable.variable_id
                variable_revision = updated["revision"]
            else:
                variable_id = body["variable_id"]
                current = by_id.get(variable_id)
                if (
                    current is None
                    or current["tombstoned"]
                    or current["revision"] != expected_variable_revision
                ):
                    raise DataConflictError("container variable revision differs")
                variable_revision = _next_revision(
                    current["revision"], "variable revision"
                )
                by_id[variable_id] = {
                    **current,
                    "revision": variable_revision,
                    "tombstoned": True,
                    "value": None,
                }
            new_revision = _next_revision(head.current_revision)
            state_text, digest = _container_state_bytes(by_id.values())
            session.add(
                DataContainerRevision(
                    kind=head.kind,
                    owner_id=head.owner_id,
                    container_id=container_id,
                    revision=new_revision,
                    schema_revision=head.schema_revision,
                    content_digest=digest,
                    canonical_variables=state_text,
                    checkpoint_sequence=None,
                    execution_revision=None,
                    worker_generation=None,
                    commit_binding_digest=caller_binding_digest(
                        authorization.caller
                    ),
                    tombstoned=False,
                    created_by_principal=actor_principal_id(authorization.caller),
                )
            )
            head.current_revision = new_revision
            head.current_content_digest = digest
            return MutationEffect(
                result={
                    "container_id": container_id,
                    "content_digest": digest,
                    "revision": new_revision,
                    "variable_id": variable_id,
                    "variable_revision": variable_revision,
                },
                prior_revision=expected_revision,
                new_revision=new_revision,
                outcome="UPDATED" if operation == "SET" else "DELETED",
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def enumerate_container(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        container_id: str,
        acl_revision: int,
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page_size = _page_size(page_size)
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        container_id = require_identifier(
            container_id, "container_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        authorization.require(
            ResourceFamily.CONTAINERS,
            "ENUMERATE",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head, state = self._load_container(
                session, owner_id, container_id, acl_revision
            )
            last_identity = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=container_id,
                    revision=head.current_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_identity = decoded.last_identity
            live = [item for item in state if not item["tombstoned"]]
            live.sort(key=lambda item: item["variable_id"].encode("ascii"))
            selected = [
                item
                for item in live
                if item["variable_id"].encode("ascii")
                > last_identity.encode("ascii")
            ][: page_size + 1]
            page = selected[:page_size]
            next_cursor = None
            if len(selected) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=container_id,
                        revision=head.current_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final["variable_id"],
                        last_identity=final["variable_id"],
                    )
                )
            return {
                "container_id": container_id,
                "next_cursor": next_cursor,
                "revision": head.current_revision,
                "variables": [
                    {
                        key: item[key]
                        for key in (
                            "declared_type",
                            "name",
                            "revision",
                            "value",
                            "value_digest",
                            "variable_id",
                        )
                    }
                    for item in page
                ],
            }

    @staticmethod
    def _shared_heads(
        session: Session,
        scope: SharedScope | str,
        owner_id: str,
        namespace_id: str,
        *,
        lock: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        identity = _shared_identity(scope, owner_id, namespace_id)
        latest = (
            select(
                SharedEntry.scope.label("scope"),
                SharedEntry.owner_id.label("owner_id"),
                SharedEntry.namespace_id.label("namespace_id"),
                SharedEntry.entry_id.label("entry_id"),
                func.max(SharedEntry.revision).label("revision"),
            )
            .where(
                SharedEntry.scope == identity["scope"],
                SharedEntry.owner_id == identity["owner_id"],
                SharedEntry.namespace_id == identity["namespace_id"],
            )
            .group_by(
                SharedEntry.scope,
                SharedEntry.owner_id,
                SharedEntry.namespace_id,
                SharedEntry.entry_id,
            )
            .subquery()
        )
        query = (
            select(SharedEntry)
            .join(
                latest,
                (SharedEntry.scope == latest.c.scope)
                & (SharedEntry.owner_id == latest.c.owner_id)
                & (SharedEntry.namespace_id == latest.c.namespace_id)
                & (SharedEntry.entry_id == latest.c.entry_id)
                & (SharedEntry.revision == latest.c.revision),
            )
            .order_by(SharedEntry.key, SharedEntry.entry_id)
        )
        # Mutations lock the namespace head before reconstruction. PostgreSQL
        # forbids FOR UPDATE on this latest-revision grouped subquery.
        rows = session.scalars(query).all()
        entries: list[dict[str, Any]] = []
        live_keys: set[str] = set()
        identities: set[str] = set()
        for row in rows:
            try:
                entry_id = require_identifier(
                    row.entry_id, "shared entry_id", maximum_bytes=128
                )
                key = _shared_key(row.key)
                revision = require_positive_revision(
                    row.revision, "shared entry revision"
                )
                digest = require_digest(row.value_digest, "shared value_digest")
            except DataValidationError as exc:
                raise CorruptNamespaceError("shared entry identity is corrupt") from exc
            if entry_id in identities or type(row.tombstoned) is not bool:
                raise CorruptNamespaceError("shared entry head is ambiguous")
            identities.add(entry_id)
            if row.tombstoned:
                if row.canonical_value is not None:
                    raise CorruptNamespaceError("shared tombstone exposes a value")
                value = None
            else:
                if key in live_keys or type(row.canonical_value) is not bytes:
                    raise CorruptNamespaceError("shared live key is ambiguous")
                live_keys.add(key)
                try:
                    value = decode_stored_typed_value(row.canonical_value, digest)
                except (TypedValueError, CorruptValueError) as exc:
                    raise CorruptNamespaceError("shared typed value is corrupt") from exc
            entries.append(
                {
                    "entry_id": entry_id,
                    "key": key,
                    "revision": revision,
                    "tombstoned": row.tombstoned,
                    "value": value,
                    "value_digest": digest,
                }
            )
        if len(live_keys) > MAX_SHARED_ENTRIES:
            raise CorruptNamespaceError("shared live entry bound is exceeded")
        return tuple(entries)

    @staticmethod
    def _shared_namespace_head(
        session: Session,
        owner_id: str,
        namespace_id: str,
        *,
        scope: SharedScope | None = None,
        lock: bool = False,
    ) -> SharedNamespace | None:
        if scope is not None and type(scope) is not SharedScope:
            raise DataValidationError("shared namespace scope is invalid")
        if scope is None:
            query = select(SharedNamespace).where(
                SharedNamespace.owner_id == owner_id,
                SharedNamespace.namespace_id == namespace_id,
            )
            if lock:
                query = query.with_for_update()
            candidates = session.scalars(query).all()
            if len(candidates) > 1:
                raise DataConflictError("shared namespace scope is ambiguous")
            head = candidates[0] if candidates else None
        else:
            head = session.get(
                SharedNamespace,
                _shared_identity(scope, owner_id, namespace_id),
                with_for_update=lock,
            )
        return head

    @classmethod
    def _load_shared_namespace(
        cls,
        session: Session,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        *,
        scope: SharedScope | None = None,
        lock: bool = False,
    ) -> tuple[SharedNamespace, tuple[dict[str, Any], ...]]:
        head = cls._shared_namespace_head(
            session,
            owner_id,
            namespace_id,
            scope=scope,
            lock=lock,
        )
        if (
            head is None
            or head.tombstoned
            or head.owner_id != owner_id
            or head.acl_revision != acl_revision
            or (scope is not None and head.scope != scope.value)
        ):
            raise DataNotFoundError("shared namespace not found")
        entries = cls._shared_heads(
            session,
            head.scope,
            head.owner_id,
            head.namespace_id,
            lock=lock,
        )
        _, digest = _shared_state_bytes(entries)
        if digest != head.current_content_digest:
            raise CorruptNamespaceError("shared namespace head digest differs")
        return head, entries

    def create_shared_namespace(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        scope: SharedScope,
        acl_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        if type(scope) is not SharedScope:
            raise DataValidationError("shared namespace scope is invalid")
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        evidence_resource_id = f"{scope.value}.{namespace_id}"
        mutation_authorization = _identity_bound_authorization(
            authorization,
            ResourceFamily.SHARED,
            "CREATE_NAMESPACE",
            owner_id=owner_id,
            public_resource_id=namespace_id,
            evidence_resource_id=evidence_resource_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            mutation_authorization,
            ResourceFamily.SHARED,
            "CREATE_NAMESPACE",
            owner_id=owner_id,
            resource_id=evidence_resource_id,
            acl_revision=acl_revision,
            expected_revision=0,
            idempotency_key=idempotency_key,
            body={"acl_revision": acl_revision, "scope": scope.value},
        )
        identity = _shared_identity(scope, owner_id, namespace_id)

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            current = session.get(SharedNamespace, identity, with_for_update=True)
            if current is not None and (
                current.owner_id != owner_id or current.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("shared namespace creation is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            if session.get(SharedNamespace, identity, with_for_update=True) is not None:
                raise DataConflictError("shared namespace identity already exists")
            count = session.scalar(
                select(func.count())
                .select_from(SharedNamespace)
                .where(
                    SharedNamespace.owner_id == owner_id,
                    SharedNamespace.tombstoned.is_(False),
                )
            )
            if type(count) is not int or count < 0:
                raise CorruptNamespaceError("shared namespace count is invalid")
            if count >= 256:
                raise DataCapacityError("shared namespace owner capacity is exhausted")
            _, digest = _shared_state_bytes(())
            session.add(
                SharedNamespace(
                    namespace_id=namespace_id,
                    scope=scope.value,
                    owner_id=owner_id,
                    current_revision=1,
                    current_content_digest=digest,
                    acl_revision=acl_revision,
                    tombstoned=False,
                )
            )
            return MutationEffect(
                result={
                    "acl_revision": acl_revision,
                    "content_digest": digest,
                    "namespace_id": namespace_id,
                    "revision": 1,
                    "scope": scope.value,
                },
                prior_revision=0,
                new_revision=1,
                outcome="CREATED",
                response_status=201,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def list_shared_namespaces(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        page_size = _page_size(page_size)
        authorization.require(
            ResourceFamily.SHARED,
            "LIST_NAMESPACES",
            owner_id=owner_id,
        )
        if scope is not None and type(scope) is not SharedScope:
            raise DataValidationError("shared namespace scope is invalid")
        with self.session_factory() as session:
            self._verify_schema(session)
            query = select(SharedNamespace).where(
                SharedNamespace.owner_id == owner_id,
                SharedNamespace.tombstoned.is_(False),
            )
            if scope is not None:
                query = query.where(SharedNamespace.scope == scope.value)
            rows = session.scalars(
                query
                .order_by(SharedNamespace.scope, SharedNamespace.namespace_id)
            ).all()
            snapshot = canonical_json_bytes(
                [
                    {
                        "acl_revision": row.acl_revision,
                        "content_digest": row.current_content_digest,
                        "namespace_id": row.namespace_id,
                        "revision": row.current_revision,
                        "scope": row.scope,
                    }
                    for row in rows
                ]
            )
            owner_revision = int(sha256_digest(snapshot)[:16], 16) & ((1 << 63) - 1)
            owner_revision = owner_revision or 1
            cursor_resource = require_identifier(
                f"{owner_id}.{scope.value}" if scope is not None else owner_id,
                "shared namespace list cursor resource",
            )
            last_identity = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=cursor_resource,
                    revision=owner_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_identity = decoded.last_identity
            selected = [
                row
                for row in rows
                if _shared_cursor_identity(row).encode("ascii")
                > last_identity.encode("ascii")
            ][: page_size + 1]
            page = selected[:page_size]
            next_cursor = None
            if len(selected) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=cursor_resource,
                        revision=owner_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final.namespace_id,
                        last_identity=_shared_cursor_identity(final),
                    )
                )
            return {
                "namespaces": [
                    {
                        "acl_revision": row.acl_revision,
                        "content_digest": row.current_content_digest,
                        "namespace_id": row.namespace_id,
                        "revision": row.current_revision,
                        "scope": row.scope,
                    }
                    for row in page
                ],
                "next_cursor": next_cursor,
                "owner_revision": owner_revision,
            }

    def get_shared_entry(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        key: str,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        key = _shared_key(key)
        authorization.require(
            ResourceFamily.SHARED,
            "GET",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head, entries = self._load_shared_namespace(
                session,
                owner_id,
                namespace_id,
                acl_revision,
                scope=scope,
            )
            matches = [
                item for item in entries if not item["tombstoned"] and item["key"] == key
            ]
            if len(matches) != 1:
                raise DataNotFoundError("shared entry not found")
            return {
                **_shared_entry_projection(matches[0]),
                "namespace_id": namespace_id,
                "namespace_revision": head.current_revision,
                "scope": head.scope,
            }

    def read_shared_namespace(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        authorization.require(
            ResourceFamily.SHARED,
            "GET",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head, entries = self._load_shared_namespace(
                session,
                owner_id,
                namespace_id,
                acl_revision,
                scope=scope,
            )
            return {
                "acl_revision": head.acl_revision,
                "content_digest": head.current_content_digest,
                "entry_count": len(
                    [item for item in entries if not item["tombstoned"]]
                ),
                "namespace_id": head.namespace_id,
                "owner_id": head.owner_id,
                "revision": head.current_revision,
                "scope": head.scope,
            }

    def enumerate_shared_namespace(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        page_size = _page_size(page_size)
        authorization.require(
            ResourceFamily.SHARED,
            "ENUMERATE",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            head, entries = self._load_shared_namespace(
                session,
                owner_id,
                namespace_id,
                acl_revision,
                scope=scope,
            )
            cursor_identity = _shared_cursor_identity(head)
            last_key = ""
            last_identity = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=cursor_identity,
                    revision=head.current_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_key = decoded.last_key
                last_identity = decoded.last_identity
            live = sorted(
                (item for item in entries if not item["tombstoned"]),
                key=lambda item: (
                    item["key"].encode("utf-8"),
                    item["entry_id"].encode("ascii"),
                ),
            )
            boundary = (last_key.encode("utf-8"), last_identity.encode("ascii"))
            selected = [
                item
                for item in live
                if (item["key"].encode("utf-8"), item["entry_id"].encode("ascii"))
                > boundary
            ][: page_size + 1]
            page = selected[:page_size]
            next_cursor = None
            if len(selected) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=cursor_identity,
                        revision=head.current_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final["key"],
                        last_identity=final["entry_id"],
                    )
                )
            return {
                "entries": [_shared_entry_projection(item) for item in page],
                "namespace_id": namespace_id,
                "next_cursor": next_cursor,
                "revision": head.current_revision,
                "scope": head.scope,
            }

    def put_shared_entry(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        expected_revision: int,
        key: str,
        expected_entry_revision: int,
        idempotency_key: str,
        value: Mapping[str, Any],
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        canonical_value = validate_typed_value(value)
        value_bytes = canonical_typed_value_json(canonical_value).encode("utf-8")
        if len(value_bytes) > MAX_SHARED_VALUE_BYTES:
            raise DataCapacityError("shared value exceeds its byte limit")
        return self._mutate_shared_entry(
            authorization,
            operation="PUT",
            owner_id=owner_id,
            namespace_id=namespace_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            expected_entry_revision=require_expected_revision(
                expected_entry_revision, "expected_entry_revision"
            ),
            idempotency_key=idempotency_key,
            key=_shared_key(key),
            value=canonical_value,
            scope=scope,
        )

    def delete_shared_entry(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        expected_revision: int,
        key: str,
        expected_entry_revision: int,
        idempotency_key: str,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        return self._mutate_shared_entry(
            authorization,
            operation="DELETE",
            owner_id=owner_id,
            namespace_id=namespace_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            expected_entry_revision=require_positive_revision(
                expected_entry_revision, "expected_entry_revision"
            ),
            idempotency_key=idempotency_key,
            key=_shared_key(key),
            value=None,
            scope=scope,
        )

    def _mutate_shared_entry(
        self,
        authorization: AuthorizationContext,
        *,
        operation: str,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        expected_revision: int,
        expected_entry_revision: int,
        idempotency_key: str,
        key: str,
        value: Mapping[str, Any] | None,
        scope: SharedScope | None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_positive_revision(expected_revision)
        body: dict[str, Any] = {
            "expected_entry_revision": expected_entry_revision,
            "key": key,
        }
        if value is not None:
            body["value"] = dict(value)
        authorization.require(
            ResourceFamily.SHARED,
            operation,
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            existing = self._shared_namespace_head(
                session,
                owner_id,
                namespace_id,
                scope=scope,
            )
            if existing is None or existing.acl_revision != acl_revision:
                raise DataNotFoundError("shared namespace not found")
            resolved_scope = SharedScope(existing.scope)
        body["scope"] = resolved_scope.value
        evidence_resource_id = f"{resolved_scope.value}.{namespace_id}"
        mutation_authorization = _identity_bound_authorization(
            authorization,
            ResourceFamily.SHARED,
            operation,
            owner_id=owner_id,
            public_resource_id=namespace_id,
            evidence_resource_id=evidence_resource_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            mutation_authorization,
            ResourceFamily.SHARED,
            operation,
            owner_id=owner_id,
            resource_id=evidence_resource_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body=body,
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            head = self._shared_namespace_head(
                session,
                owner_id,
                namespace_id,
                scope=resolved_scope,
                lock=True,
            )
            if head is not None and (
                head.owner_id != owner_id or head.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("shared entry mutation is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            head, entries = self._load_shared_namespace(
                session,
                owner_id,
                namespace_id,
                acl_revision,
                scope=resolved_scope,
                lock=True,
            )
            if head.current_revision != expected_revision:
                _raise_revision_conflict(
                    authorization,
                    ResourceFamily.SHARED,
                    "GET",
                    owner_id=owner_id,
                    resource_id=namespace_id,
                    acl_revision=acl_revision,
                    current_revision=head.current_revision,
                )
            live = [
                item for item in entries if not item["tombstoned"] and item["key"] == key
            ]
            if len(live) > 1:
                raise CorruptNamespaceError("shared live key is ambiguous")
            current = live[0] if live else None
            if operation == "PUT":
                assert value is not None
                if current is None:
                    if expected_entry_revision != 0:
                        raise DataConflictError("shared entry revision differs")
                    if len([item for item in entries if not item["tombstoned"]]) >= MAX_SHARED_ENTRIES:
                        raise DataCapacityError("shared live entry capacity is exhausted")
                    entry_id = str(uuid.uuid4())
                    entry_revision = 1
                else:
                    if current["revision"] != expected_entry_revision:
                        raise DataConflictError("shared entry revision differs")
                    entry_id = current["entry_id"]
                    entry_revision = _next_revision(
                        current["revision"], "shared entry revision"
                    )
                canonical_value = validate_typed_value(value)
                value_bytes = canonical_typed_value_json(canonical_value).encode("utf-8")
                digest = typed_value_digest(canonical_value)
                updated = {
                    "entry_id": entry_id,
                    "key": key,
                    "revision": entry_revision,
                    "tombstoned": False,
                    "value": canonical_value,
                    "value_digest": digest,
                }
                outcome = "UPDATED" if current is not None else "CREATED"
            else:
                if current is None or current["revision"] != expected_entry_revision:
                    raise DataConflictError("shared entry revision differs")
                entry_id = current["entry_id"]
                entry_revision = _next_revision(
                    current["revision"], "shared entry revision"
                )
                value_bytes = None
                digest = current["value_digest"]
                updated = {
                    **current,
                    "revision": entry_revision,
                    "tombstoned": True,
                    "value": None,
                }
                outcome = "DELETED"
            by_id = {item["entry_id"]: dict(item) for item in entries}
            by_id[entry_id] = updated
            _, namespace_digest = _shared_state_bytes(by_id.values())
            new_revision = _next_revision(head.current_revision)
            session.add(
                SharedEntry(
                    scope=head.scope,
                    owner_id=head.owner_id,
                    namespace_id=namespace_id,
                    entry_id=entry_id,
                    revision=entry_revision,
                    key=key,
                    canonical_value=value_bytes,
                    value_digest=digest,
                    tombstoned=operation == "DELETE",
                    updated_by_principal=actor_principal_id(authorization.caller),
                )
            )
            head.current_revision = new_revision
            head.current_content_digest = namespace_digest
            return MutationEffect(
                result={
                    "entry_id": entry_id,
                    "entry_revision": entry_revision,
                    "key": key,
                    "namespace_id": namespace_id,
                    "revision": new_revision,
                    "value_digest": digest if operation == "PUT" else None,
                },
                prior_revision=expected_revision,
                new_revision=new_revision,
                outcome=outcome,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def clear_shared_namespace(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        expected_revision: int,
        maximum_affected_entries: int,
        idempotency_key: str,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_positive_revision(expected_revision)
        if (
            type(maximum_affected_entries) is not int
            or not 0 <= maximum_affected_entries <= MAX_SHARED_CLEAR
        ):
            raise DataValidationError("maximum_affected_entries is outside its bound")
        authorization.require(
            ResourceFamily.SHARED,
            "CLEAR",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            existing = self._shared_namespace_head(
                session, owner_id, namespace_id, scope=scope
            )
            if existing is None or existing.acl_revision != acl_revision:
                raise DataNotFoundError("shared namespace not found")
            resolved_scope = SharedScope(existing.scope)
        evidence_resource_id = f"{resolved_scope.value}.{namespace_id}"
        mutation_authorization = _identity_bound_authorization(
            authorization,
            ResourceFamily.SHARED,
            "CLEAR",
            owner_id=owner_id,
            public_resource_id=namespace_id,
            evidence_resource_id=evidence_resource_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            mutation_authorization,
            ResourceFamily.SHARED,
            "CLEAR",
            owner_id=owner_id,
            resource_id=evidence_resource_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body={
                "maximum_affected_entries": maximum_affected_entries,
                "scope": resolved_scope.value,
            },
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            head = self._shared_namespace_head(
                session,
                owner_id,
                namespace_id,
                scope=resolved_scope,
                lock=True,
            )
            if head is not None and (
                head.owner_id != owner_id or head.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("shared clear is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            head, entries = self._load_shared_namespace(
                session,
                owner_id,
                namespace_id,
                acl_revision,
                scope=resolved_scope,
                lock=True,
            )
            if head.current_revision != expected_revision:
                _raise_revision_conflict(
                    authorization,
                    ResourceFamily.SHARED,
                    "GET",
                    owner_id=owner_id,
                    resource_id=namespace_id,
                    acl_revision=acl_revision,
                    current_revision=head.current_revision,
                )
            live = [item for item in entries if not item["tombstoned"]]
            if len(live) > maximum_affected_entries:
                raise DataCapacityError("shared clear affected-entry bound is exceeded")
            principal = actor_principal_id(authorization.caller)
            by_id = {item["entry_id"]: dict(item) for item in entries}
            for item in live:
                tombstone = {
                    **item,
                    "revision": _next_revision(
                        item["revision"], "shared entry revision"
                    ),
                    "tombstoned": True,
                    "value": None,
                }
                by_id[item["entry_id"]] = tombstone
                session.add(
                    SharedEntry(
                        scope=head.scope,
                        owner_id=head.owner_id,
                        namespace_id=namespace_id,
                        entry_id=item["entry_id"],
                        revision=tombstone["revision"],
                        key=item["key"],
                        canonical_value=None,
                        value_digest=item["value_digest"],
                        tombstoned=True,
                        updated_by_principal=principal,
                    )
                )
            _, digest = _shared_state_bytes(by_id.values())
            new_revision = _next_revision(head.current_revision)
            head.current_revision = new_revision
            head.current_content_digest = digest
            return MutationEffect(
                result={
                    "affected_entries": len(live),
                    "content_digest": digest,
                    "namespace_id": namespace_id,
                    "revision": new_revision,
                },
                prior_revision=expected_revision,
                new_revision=new_revision,
                outcome="CLEARED",
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def delete_shared_namespace(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        namespace_id: str,
        acl_revision: int,
        expected_revision: int,
        idempotency_key: str,
        scope: SharedScope | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        namespace_id = require_identifier(
            namespace_id, "namespace_id", maximum_bytes=128
        )
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        expected_revision = require_positive_revision(expected_revision)
        authorization.require(
            ResourceFamily.SHARED,
            "DELETE_NAMESPACE",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            existing = self._shared_namespace_head(
                session, owner_id, namespace_id, scope=scope
            )
            if existing is None or existing.acl_revision != acl_revision:
                raise DataNotFoundError("shared namespace not found")
            resolved_scope = SharedScope(existing.scope)
        evidence_resource_id = f"{resolved_scope.value}.{namespace_id}"
        mutation_authorization = _identity_bound_authorization(
            authorization,
            ResourceFamily.SHARED,
            "DELETE_NAMESPACE",
            owner_id=owner_id,
            public_resource_id=namespace_id,
            evidence_resource_id=evidence_resource_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            mutation_authorization,
            ResourceFamily.SHARED,
            "DELETE_NAMESPACE",
            owner_id=owner_id,
            resource_id=evidence_resource_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body={"scope": resolved_scope.value},
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            head = self._shared_namespace_head(
                session,
                owner_id,
                namespace_id,
                scope=resolved_scope,
                lock=True,
            )
            if head is not None and (
                head.owner_id != owner_id or head.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("shared namespace deletion is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            head, entries = self._load_shared_namespace(
                session,
                owner_id,
                namespace_id,
                acl_revision,
                scope=resolved_scope,
                lock=True,
            )
            if head.current_revision != expected_revision:
                _raise_revision_conflict(
                    authorization,
                    ResourceFamily.SHARED,
                    "GET",
                    owner_id=owner_id,
                    resource_id=namespace_id,
                    acl_revision=acl_revision,
                    current_revision=head.current_revision,
                )
            if any(not item["tombstoned"] for item in entries):
                raise DataConflictError("shared namespace still contains live entries")
            new_revision = _next_revision(head.current_revision)
            head.current_revision = new_revision
            head.tombstoned = True
            return MutationEffect(
                result={"namespace_id": namespace_id, "revision": new_revision},
                prior_revision=expected_revision,
                new_revision=new_revision,
                outcome="DELETED",
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    @staticmethod
    def virtual_root_storage_id(root_id: str, owner_id: str) -> str:
        return _virtual_root_storage_id(root_id, owner_id)

    @staticmethod
    def _virtual_heads(
        session: Session,
        storage_root_id: str,
        *,
        lock: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        latest = (
            select(
                VirtualFile.root_id.label("root_id"),
                VirtualFile.virtual_path.label("virtual_path"),
                func.max(VirtualFile.revision).label("revision"),
            )
            .where(VirtualFile.root_id == storage_root_id)
            .group_by(VirtualFile.root_id, VirtualFile.virtual_path)
            .subquery()
        )
        query = (
            select(VirtualFile)
            .join(
                latest,
                (VirtualFile.root_id == latest.c.root_id)
                & (VirtualFile.virtual_path == latest.c.virtual_path)
                & (VirtualFile.revision == latest.c.revision),
            )
            .order_by(VirtualFile.virtual_path)
        )
        # Mutations lock the root head before reconstruction. PostgreSQL
        # forbids FOR UPDATE on this latest-revision grouped subquery.
        rows = session.scalars(query).all()
        values: list[dict[str, Any]] = []
        paths: set[str] = set()
        for row in rows:
            try:
                path = _virtual_path(row.virtual_path)
                parent_path = _virtual_path(row.parent_path, allow_root=True)
                revision = require_positive_revision(row.revision, "file revision")
                digest = require_digest(row.content_digest, "file content_digest")
            except DataValidationError as exc:
                raise CorruptVirtualFileError("virtual node identity is corrupt") from exc
            if (
                path in paths
                or parent_path != path.rpartition("/")[0]
                or row.node_type not in {"FILE", "DIRECTORY"}
                or type(row.tombstoned) is not bool
                or type(row.byte_length) is not int
                or not 0 <= row.byte_length <= MAX_VIRTUAL_FILE_BYTES
                or (
                    row.node_type == "DIRECTORY"
                    and (row.encoding is not None or row.byte_length != 0)
                )
                or (
                    row.node_type == "FILE"
                    and row.encoding not in VIRTUAL_FILE_ENCODINGS
                )
            ):
                raise CorruptVirtualFileError("virtual node metadata is corrupt")
            paths.add(path)
            values.append(
                {
                    "byte_length": row.byte_length,
                    "content_digest": digest,
                    "encoding": row.encoding,
                    "node_type": row.node_type,
                    "parent_path": parent_path,
                    "revision": revision,
                    "tombstoned": row.tombstoned,
                    "virtual_path": path,
                }
            )
        return tuple(values)

    @staticmethod
    def _validate_virtual_reservation(root: VirtualFileRoot) -> None:
        reservation_id = root.reservation_id
        binding_digest = root.reservation_binding_digest
        absent = (
            reservation_id is None
            and binding_digest is None
            and root.reserved_bytes == 0
            and root.reserved_nodes == 0
        )
        present = (
            type(reservation_id) is str
            and len(reservation_id) == 32
            and all(character in "0123456789abcdef" for character in reservation_id)
            and type(binding_digest) is str
            and len(binding_digest) == 64
            and all(character in "0123456789abcdef" for character in binding_digest)
            and type(root.reserved_bytes) is int
            and root.reserved_bytes >= 0
            and type(root.reserved_nodes) is int
            and root.reserved_nodes in {0, 1}
            and root.used_bytes + root.reserved_bytes <= root.quota_bytes
            and root.used_nodes + root.reserved_nodes <= root.quota_nodes
        )
        if not absent and not present:
            raise CorruptVirtualFileError("virtual root reservation is corrupt")

    @staticmethod
    def _clear_virtual_reservation(root: VirtualFileRoot) -> None:
        root.reservation_id = None
        root.reservation_binding_digest = None
        root.reserved_bytes = 0
        root.reserved_nodes = 0

    @staticmethod
    def _virtual_write_request(
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_revision: int,
        encoding: str,
        byte_length: int,
        content_digest: str,
        idempotency_key: str,
        request_digest: str,
    ) -> MutationRequest:
        return MutationRequest.build(
            authorization,
            ResourceFamily.FILES,
            "WRITE",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body={
                "byte_length": byte_length,
                "content_digest": content_digest,
                "encoding": encoding,
                "request_digest": request_digest,
                "virtual_path": virtual_path,
            },
        )

    @staticmethod
    def _virtual_reservation_binding_digest(
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_revision: int,
    ) -> str:
        caller_payload = caller_binding_payload(authorization.caller)
        if type(authorization.caller) is ProcedureCallerBinding:
            caller_payload = {
                key: value
                for key, value in caller_payload.items()
                if key != "deterministic_request_id"
            }
        return sha256_digest(
            canonical_json_bytes(
                {
                    "acl_revision": acl_revision,
                    "caller": caller_payload,
                    "expected_revision": expected_revision,
                    "owner_id": owner_id,
                    "root_id": root_id,
                    "schema_version": "spell.data.virtual-file-reservation/1",
                    "virtual_path": virtual_path,
                }
            )
        )

    @classmethod
    def _load_virtual_root(
        cls,
        session: Session,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        lock: bool = False,
    ) -> tuple[VirtualFileRoot, tuple[dict[str, Any], ...]]:
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        root = session.get(VirtualFileRoot, storage_id, with_for_update=lock)
        if (
            root is None
            or not root.active
            or root.owner_id != owner_id
            or root.root_kind != root_id
            or root.acl_revision != acl_revision
        ):
            raise DataNotFoundError("virtual root not found")
        cls._validate_virtual_reservation(root)
        heads = cls._virtual_heads(session, storage_id, lock=lock)
        canonical = canonical_virtual_root_state_bytes(storage_id, heads)
        live = [item for item in heads if not item["tombstoned"]]
        used_bytes = sum(
            item["byte_length"] for item in live if item["node_type"] == "FILE"
        )
        if (
            sha256_digest(canonical) != root.content_digest
            or root.used_nodes != len(live)
            or root.used_bytes != used_bytes
            or root.used_nodes > root.quota_nodes
            or root.used_bytes > root.quota_bytes
            or root.used_nodes + root.reserved_nodes > root.quota_nodes
            or root.used_bytes + root.reserved_bytes > root.quota_bytes
        ):
            raise CorruptVirtualFileError("virtual root head is corrupt")
        return root, heads

    @staticmethod
    def _virtual_head_by_path(
        heads: Iterable[Mapping[str, Any]], virtual_path: str
    ) -> dict[str, Any] | None:
        matches = [dict(item) for item in heads if item["virtual_path"] == virtual_path]
        if len(matches) > 1:
            raise CorruptVirtualFileError("virtual path head is ambiguous")
        return matches[0] if matches else None

    @staticmethod
    def _virtual_parent_revision(
        root: VirtualFileRoot,
        heads: Iterable[Mapping[str, Any]],
        parent_path: str,
    ) -> int:
        if parent_path == "":
            return require_expected_revision(root.current_revision, "root revision")
        parent = DataRepository._virtual_head_by_path(heads, parent_path)
        if (
            parent is None
            or parent["tombstoned"]
            or parent["node_type"] != "DIRECTORY"
        ):
            raise DataNotFoundError("virtual parent directory not found")
        return parent["revision"]

    @staticmethod
    def _stage_virtual_parent_bump(
        session: Session,
        root: VirtualFileRoot,
        heads_by_path: dict[str, dict[str, Any]],
        virtual_path: str,
        principal: str,
    ) -> None:
        parent_path = virtual_path.rpartition("/")[0]
        if not parent_path:
            return
        parent = heads_by_path.get(parent_path)
        if (
            parent is None
            or parent["tombstoned"]
            or parent["node_type"] != "DIRECTORY"
        ):
            raise CorruptVirtualFileError("virtual parent metadata is corrupt")
        parent_revision = _next_revision(parent["revision"], "directory revision")
        updated = {**parent, "revision": parent_revision}
        heads_by_path[parent_path] = updated
        session.add(
            VirtualFile(
                root_id=root.root_id,
                virtual_path=parent_path,
                revision=parent_revision,
                parent_path=parent["parent_path"],
                node_type="DIRECTORY",
                encoding=None,
                byte_length=0,
                content_digest=parent["content_digest"],
                tombstoned=False,
                created_by_principal=principal,
            )
        )

    @staticmethod
    def _settle_virtual_root(
        root: VirtualFileRoot,
        heads_by_path: Mapping[str, Mapping[str, Any]],
    ) -> int:
        DataRepository._validate_virtual_reservation(root)
        if root.reservation_id is not None:
            raise DataConflictError("virtual root has an active write reservation")
        heads = tuple(heads_by_path.values())
        live = [item for item in heads if not item["tombstoned"]]
        used_bytes = sum(
            item["byte_length"] for item in live if item["node_type"] == "FILE"
        )
        if len(live) > root.quota_nodes or used_bytes > root.quota_bytes:
            raise DataCapacityError("virtual root quota is exhausted")
        new_revision = require_positive_revision(
            root.current_revision + 1, "root revision"
        )
        root.current_revision = new_revision
        root.used_nodes = len(live)
        root.used_bytes = used_bytes
        root.content_digest = sha256_digest(
            canonical_virtual_root_state_bytes(root.root_id, heads)
        )
        return new_revision

    def provision_virtual_root(
        self,
        *,
        root_id: str,
        root_kind: str,
        owner_id: str,
        acl_revision: int,
        configuration_digest: str,
        quota_bytes: int,
        quota_nodes: int,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        if root_kind != root_id or root_kind not in VIRTUAL_ROOT_KINDS:
            raise DataValidationError("virtual root kind differs")
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        configuration_digest = require_digest(
            configuration_digest, "configuration_digest"
        )
        if type(quota_bytes) is not int or not 0 <= quota_bytes <= MAX_VIRTUAL_ROOT_BYTES:
            raise DataValidationError("virtual root byte quota is invalid")
        if type(quota_nodes) is not int or not 0 <= quota_nodes <= MAX_VIRTUAL_ROOT_NODES:
            raise DataValidationError("virtual root node quota is invalid")
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        expected_configuration = sha256_digest(
            canonical_virtual_root_configuration_bytes(
                {
                    "acl_revision": acl_revision,
                    "owner_id": owner_id,
                    "quota_bytes": quota_bytes,
                    "quota_nodes": quota_nodes,
                    "root_id": storage_id,
                    "root_kind": root_kind,
                }
            )
        )
        if configuration_digest != expected_configuration:
            raise DataValidationError("virtual root configuration digest differs")
        empty_digest = sha256_digest(
            canonical_virtual_root_state_bytes(storage_id, ())
        )
        with self.session_factory() as session:
            try:
                self._verify_schema(session)
                existing = session.get(
                    VirtualFileRoot, storage_id, with_for_update=True
                )
                if existing is None:
                    existing = VirtualFileRoot(
                        root_id=storage_id,
                        root_kind=root_kind,
                        owner_id=owner_id,
                        acl_revision=acl_revision,
                        current_revision=0,
                        content_digest=empty_digest,
                        configuration_digest=configuration_digest,
                        quota_bytes=quota_bytes,
                        quota_nodes=quota_nodes,
                        used_bytes=0,
                        used_nodes=0,
                        reservation_id=None,
                        reservation_binding_digest=None,
                        reserved_bytes=0,
                        reserved_nodes=0,
                        active=True,
                    )
                    session.add(existing)
                elif any(
                    (
                        existing.root_kind != root_kind,
                        existing.owner_id != owner_id,
                        existing.acl_revision != acl_revision,
                        existing.configuration_digest != configuration_digest,
                        existing.quota_bytes != quota_bytes,
                        existing.quota_nodes != quota_nodes,
                        not existing.active,
                    )
                ):
                    raise DataConflictError("virtual root provisioning differs")
                session.flush()
                session.commit()
                return {
                    "acl_revision": existing.acl_revision,
                    "configuration_digest": existing.configuration_digest,
                    "content_digest": existing.content_digest,
                    "owner_id": owner_id,
                    "revision": existing.current_revision,
                    "root_id": root_id,
                    "storage_root_id": storage_id,
                }
            except Exception as exc:
                session.rollback()
                translated = _translated_transaction_error(exc)
                if translated is not None:
                    raise translated from exc
                raise

    def read_virtual_node(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path)
        authorization.require(
            ResourceFamily.FILES,
            "READ",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            _, heads = self._load_virtual_root(
                session,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
            )
            row = self._virtual_head_by_path(heads, virtual_path)
            if row is None or row["tombstoned"]:
                raise DataNotFoundError("virtual node not found")
            return {
                "content_sha256": row["content_digest"]
                if row["node_type"] == "FILE"
                else None,
                "encoding": row["encoding"],
                "kind": row["node_type"],
                "revision": row["revision"],
                "size": row["byte_length"],
            }

    def read_virtual_file(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        revision: int | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path)
        if revision is not None:
            revision = require_positive_revision(revision)
        authorization.require(
            ResourceFamily.FILES,
            "READ",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            _, heads = self._load_virtual_root(
                session,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
            )
            if revision is None:
                current = self._virtual_head_by_path(heads, virtual_path)
                row = (
                    None
                    if current is None
                    else session.get(
                        VirtualFile,
                        (storage_id, virtual_path, current["revision"]),
                    )
                )
            else:
                row = session.get(VirtualFile, (storage_id, virtual_path, revision))
            if row is None or row.tombstoned or row.node_type != "FILE":
                raise DataNotFoundError("virtual file not found")
            return {
                "content_sha256": row.content_digest,
                "encoding": row.encoding,
                "revision": row.revision,
                "root_id": root_id,
                "size": row.byte_length,
                "storage_root_id": storage_id,
                "virtual_path": virtual_path,
            }

    def list_virtual_directory(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str = "",
        page_size: int = MAX_ENUMERATION_PAGE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path, allow_root=True)
        page_size = _page_size(page_size)
        authorization.require(
            ResourceFamily.FILES,
            "LIST",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
        )
        with self.session_factory() as session:
            self._verify_schema(session)
            root, heads = self._load_virtual_root(
                session,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
            )
            if virtual_path:
                directory = self._virtual_head_by_path(heads, virtual_path)
                if (
                    directory is None
                    or directory["tombstoned"]
                    or directory["node_type"] != "DIRECTORY"
                ):
                    raise DataNotFoundError("virtual directory not found")
            last_path = ""
            if cursor is not None:
                decoded = self.cursors.decode(
                    cursor,
                    resource_identity=storage_id,
                    revision=root.current_revision,
                    authorization_digest=authorization.authorization_digest,
                )
                last_path = decoded.last_key
            children = sorted(
                (
                    item
                    for item in heads
                    if not item["tombstoned"]
                    and item["parent_path"] == virtual_path
                    and item["virtual_path"].encode("utf-8")
                    > last_path.encode("utf-8")
                ),
                key=lambda item: item["virtual_path"].encode("utf-8"),
            )[: page_size + 1]
            page = children[:page_size]
            next_cursor = None
            if len(children) > page_size and page:
                final = page[-1]
                next_cursor = self.cursors.encode(
                    RevisionCursor(
                        resource_identity=storage_id,
                        revision=root.current_revision,
                        authorization_digest=authorization.authorization_digest,
                        last_key=final["virtual_path"],
                        last_identity=sha256_digest(
                            final["virtual_path"].encode("utf-8")
                        ),
                    )
                )
            return {
                "items": [
                    {
                        "content_sha256": item["content_digest"]
                        if item["node_type"] == "FILE"
                        else None,
                        "kind": item["node_type"],
                        "name": item["virtual_path"].rsplit("/", 1)[-1],
                        "revision": item["revision"],
                        "size": item["byte_length"],
                        "virtual_path": item["virtual_path"],
                    }
                    for item in page
                ],
                "next_cursor": next_cursor,
                "revision": root.current_revision,
                "root_id": root_id,
                "virtual_path": virtual_path,
            }

    def referenced_virtual_content_digests(self) -> frozenset[tuple[str, str]]:
        with self.session_factory() as session:
            self._verify_schema(session)
            rows = session.execute(
                select(VirtualFile.root_id, VirtualFile.content_digest).where(
                    VirtualFile.node_type == "FILE",
                    VirtualFile.tombstoned.is_(False),
                )
            ).all()
            return frozenset(
                (
                    require_identifier(
                        root_id, "virtual storage root identity", maximum_bytes=128
                    ),
                    require_digest(content_digest, "virtual content digest"),
                )
                for root_id, content_digest in rows
            )

    def reserve_virtual_file(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_revision: int,
        encoding: str,
        byte_length: int,
        content_digest: str,
        idempotency_key: str,
        request_digest: str,
    ) -> dict[str, Any]:
        """Durably reserve the complete logical quota delta before byte staging."""

        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path)
        expected_revision = require_expected_revision(expected_revision)
        if encoding not in VIRTUAL_FILE_ENCODINGS:
            raise DataValidationError("virtual file encoding is invalid")
        if type(byte_length) is not int or not 0 <= byte_length <= MAX_VIRTUAL_FILE_BYTES:
            raise DataCapacityError("virtual file byte length is outside its bound")
        content_digest = require_digest(content_digest, "content_digest")
        request_digest = require_digest(request_digest, "request_digest")
        request = self._virtual_write_request(
            authorization,
            owner_id=owner_id,
            root_id=root_id,
            acl_revision=acl_revision,
            virtual_path=virtual_path,
            expected_revision=expected_revision,
            encoding=encoding,
            byte_length=byte_length,
            content_digest=content_digest,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            root = session.get(VirtualFileRoot, storage_id, with_for_update=True)
            if root is not None and (
                root.owner_id != owner_id
                or root.root_kind != root_id
                or root.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("virtual root write is not authorized")

        self.mutations._authorize(request)
        with self.mutations._lock, self.session_factory() as session:
            try:
                begin_mutation_write(session)
                self.mutations._authorize_inside_transaction(
                    session, request, authorize_in_transaction
                )
                root, heads = self._load_virtual_root(
                    session,
                    owner_id=owner_id,
                    root_id=root_id,
                    acl_revision=acl_revision,
                    lock=True,
                )
                existing = self.mutations._find_settlement(
                    session, request, lock=True
                )
                if existing is not None:
                    replay = self.mutations._replay(existing, request)
                    session.commit()
                    return _mutation_projection(replay)
                if root.reservation_id is not None:
                    raise DataConflictError(
                        "virtual root already has an active write reservation"
                    )

                current = self._virtual_head_by_path(heads, virtual_path)
                if current is None:
                    if expected_revision != 0:
                        raise DataConflictError("virtual file revision differs")
                    current_revision = 0
                    old_length = 0
                    reserved_nodes = 1
                else:
                    if current["tombstoned"]:
                        raise DataConflictError("virtual file identity is tombstoned")
                    if current["node_type"] != "FILE":
                        raise DataConflictError("virtual target is not a file")
                    current_revision = current["revision"]
                    old_length = current["byte_length"]
                    reserved_nodes = 0
                    if current_revision != expected_revision:
                        raise DataConflictError(
                            "virtual file revision differs",
                            current_revision=current_revision,
                        )
                parent_path = virtual_path.rpartition("/")[0]
                self._virtual_parent_revision(root, heads, parent_path)
                live = [item for item in heads if not item["tombstoned"]]
                if current is None:
                    name = virtual_path.rsplit("/", 1)[-1].casefold()
                    if any(
                        item["parent_path"] == parent_path
                        and item["virtual_path"].rsplit("/", 1)[-1].casefold()
                        == name
                        for item in live
                    ):
                        raise DataConflictError("virtual sibling has a case collision")
                reserved_bytes = max(0, byte_length - old_length)
                if root.used_bytes + reserved_bytes > root.quota_bytes:
                    raise DataCapacityError("virtual root byte quota is exhausted")
                if root.used_nodes + reserved_nodes > root.quota_nodes:
                    raise DataCapacityError("virtual root node quota is exhausted")

                reservation_id = uuid.uuid4().hex
                root.reservation_id = reservation_id
                root.reservation_binding_digest = (
                    self._virtual_reservation_binding_digest(
                        authorization,
                        owner_id=owner_id,
                        root_id=root_id,
                        acl_revision=acl_revision,
                        virtual_path=virtual_path,
                        expected_revision=expected_revision,
                    )
                )
                root.reserved_bytes = reserved_bytes
                root.reserved_nodes = reserved_nodes
                session.flush()
                session.commit()
                return {
                    "reservation_id": reservation_id,
                    "reserved_bytes": reserved_bytes,
                    "reserved_nodes": reserved_nodes,
                }
            except Exception as exc:
                session.rollback()
                translated = _translated_transaction_error(exc)
                if translated is not None:
                    raise translated from exc
                raise

    def release_virtual_file_reservation(
        self,
        *,
        owner_id: str,
        root_id: str,
        reservation_id: str,
    ) -> bool:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        if (
            type(reservation_id) is not str
            or len(reservation_id) != 32
            or any(character not in "0123456789abcdef" for character in reservation_id)
        ):
            raise DataValidationError("virtual file reservation identity is invalid")
        with self.mutations._lock, self.session_factory() as session:
            try:
                begin_mutation_write(session)
                self._verify_schema(session)
                root = session.get(VirtualFileRoot, storage_id, with_for_update=True)
                if root is None:
                    raise CorruptVirtualFileError("virtual reservation root is missing")
                self._validate_virtual_reservation(root)
                if root.reservation_id != reservation_id:
                    session.commit()
                    return False
                self._clear_virtual_reservation(root)
                session.flush()
                session.commit()
                return True
            except Exception as exc:
                session.rollback()
                translated = _translated_transaction_error(exc)
                if translated is not None:
                    raise translated from exc
                raise

    def recover_virtual_file_reservations(self) -> int:
        """Release only structurally valid reservations left by a stopped server."""

        with self.mutations._lock, self.session_factory() as session:
            try:
                begin_mutation_write(session)
                self._verify_schema(session)
                roots = session.scalars(
                    select(VirtualFileRoot).order_by(VirtualFileRoot.root_id).with_for_update()
                ).all()
                recovered = 0
                for root in roots:
                    self._validate_virtual_reservation(root)
                    if root.reservation_id is None:
                        continue
                    self._clear_virtual_reservation(root)
                    recovered += 1
                session.flush()
                session.commit()
                return recovered
            except Exception as exc:
                session.rollback()
                translated = _translated_transaction_error(exc)
                if translated is not None:
                    raise translated from exc
                raise

    def create_virtual_directory(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_parent_revision: int,
        idempotency_key: str,
        request_digest: str,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path)
        expected_parent_revision = require_expected_revision(
            expected_parent_revision, "expected_parent_revision"
        )
        request_digest = require_digest(request_digest, "request_digest")
        request = MutationRequest.build(
            authorization,
            ResourceFamily.FILES,
            "CREATE_DIRECTORY",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
            expected_revision=expected_parent_revision,
            idempotency_key=idempotency_key,
            body={
                "request_digest": request_digest,
                "virtual_path": virtual_path,
            },
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            root = session.get(VirtualFileRoot, storage_id, with_for_update=True)
            if root is not None and (
                root.owner_id != owner_id
                or root.root_kind != root_id
                or root.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("virtual root mutation is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            root, heads = self._load_virtual_root(
                session,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
                lock=True,
            )
            current = self._virtual_head_by_path(heads, virtual_path)
            if current is not None:
                raise DataConflictError("virtual node identity already exists")
            parent_path = virtual_path.rpartition("/")[0]
            parent_revision = self._virtual_parent_revision(
                root, heads, parent_path
            )
            if parent_revision != expected_parent_revision:
                raise DataConflictError(
                    "virtual parent revision differs",
                    current_revision=parent_revision,
                )
            live = [item for item in heads if not item["tombstoned"]]
            if len(live) >= root.quota_nodes:
                raise DataCapacityError("virtual root node quota is exhausted")
            name = virtual_path.rsplit("/", 1)[-1].casefold()
            if any(
                item["parent_path"] == parent_path
                and item["virtual_path"].rsplit("/", 1)[-1].casefold() == name
                for item in live
            ):
                raise DataConflictError("virtual sibling has a case collision")
            principal = actor_principal_id(authorization.caller)
            directory = {
                "byte_length": 0,
                "content_digest": _virtual_empty_digest(),
                "encoding": None,
                "node_type": "DIRECTORY",
                "parent_path": parent_path,
                "revision": 1,
                "tombstoned": False,
                "virtual_path": virtual_path,
            }
            session.add(
                VirtualFile(
                    root_id=storage_id,
                    virtual_path=virtual_path,
                    revision=1,
                    parent_path=parent_path,
                    node_type="DIRECTORY",
                    encoding=None,
                    byte_length=0,
                    content_digest=directory["content_digest"],
                    tombstoned=False,
                    created_by_principal=principal,
                )
            )
            heads_by_path = {
                item["virtual_path"]: dict(item) for item in heads
            }
            heads_by_path[virtual_path] = directory
            self._stage_virtual_parent_bump(
                session, root, heads_by_path, virtual_path, principal
            )
            root_revision = self._settle_virtual_root(root, heads_by_path)
            return MutationEffect(
                result={
                    "kind": "DIRECTORY",
                    "revision": 1,
                    "root_id": root_id,
                    "root_revision": root_revision,
                    "virtual_path": virtual_path,
                },
                prior_revision=expected_parent_revision,
                new_revision=1,
                outcome="CREATED",
                response_status=201,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def commit_virtual_file(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_revision: int,
        encoding: str,
        byte_length: int,
        content_digest: str,
        idempotency_key: str,
        request_digest: str,
        reservation_id: str,
        finalize_bytes: Callable[[], None],
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path)
        expected_revision = require_expected_revision(expected_revision)
        if encoding not in VIRTUAL_FILE_ENCODINGS:
            raise DataValidationError("virtual file encoding is invalid")
        if type(byte_length) is not int or not 0 <= byte_length <= MAX_VIRTUAL_FILE_BYTES:
            raise DataCapacityError("virtual file byte length is outside its bound")
        content_digest = require_digest(content_digest, "content_digest")
        request_digest = require_digest(request_digest, "request_digest")
        if (
            type(reservation_id) is not str
            or len(reservation_id) != 32
            or any(character not in "0123456789abcdef" for character in reservation_id)
        ):
            raise DataValidationError("virtual file reservation identity is invalid")
        if not callable(finalize_bytes):
            raise DataValidationError("virtual file finalizer is invalid")
        request = self._virtual_write_request(
            authorization,
            owner_id=owner_id,
            root_id=root_id,
            acl_revision=acl_revision,
            virtual_path=virtual_path,
            expected_revision=expected_revision,
            encoding=encoding,
            byte_length=byte_length,
            content_digest=content_digest,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            root = session.get(VirtualFileRoot, storage_id, with_for_update=True)
            if root is not None and (
                root.owner_id != owner_id
                or root.root_kind != root_id
                or root.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("virtual root write is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            root, heads = self._load_virtual_root(
                session,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
                lock=True,
            )
            if root.reservation_id != reservation_id:
                raise DataConflictError("virtual file reservation differs")
            if root.reservation_binding_digest != self._virtual_reservation_binding_digest(
                authorization,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
                virtual_path=virtual_path,
                expected_revision=expected_revision,
            ):
                raise DataConflictError("virtual file reservation binding differs")
            current = self._virtual_head_by_path(heads, virtual_path)
            if current is None:
                if expected_revision != 0:
                    raise DataConflictError("virtual file revision differs")
                current_revision = 0
                old_length = 0
            else:
                if current["tombstoned"]:
                    raise DataConflictError("virtual file identity is tombstoned")
                if current["node_type"] != "FILE":
                    raise DataConflictError("virtual target is not a file")
                current_revision = current["revision"]
                old_length = current["byte_length"]
                if current_revision != expected_revision:
                    raise DataConflictError(
                        "virtual file revision differs",
                        current_revision=current_revision,
                    )
            parent_path = virtual_path.rpartition("/")[0]
            self._virtual_parent_revision(root, heads, parent_path)
            live = [item for item in heads if not item["tombstoned"]]
            expected_reserved_bytes = max(0, byte_length - old_length)
            expected_reserved_nodes = 1 if current is None else 0
            if (
                root.reserved_bytes < expected_reserved_bytes
                or root.reserved_nodes != expected_reserved_nodes
            ):
                raise CorruptVirtualFileError("virtual file reservation delta differs")
            if root.used_nodes + expected_reserved_nodes > root.quota_nodes:
                raise DataCapacityError("virtual root node quota is exhausted")
            if root.used_bytes + expected_reserved_bytes > root.quota_bytes:
                raise DataCapacityError("virtual root byte quota is exhausted")
            if current is None:
                name = virtual_path.rsplit("/", 1)[-1].casefold()
                if any(
                    item["parent_path"] == parent_path
                    and item["virtual_path"].rsplit("/", 1)[-1].casefold()
                    == name
                    for item in live
                ):
                    raise DataConflictError("virtual sibling has a case collision")
            finalize_result = finalize_bytes()
            if finalize_result is not None:
                raise DataValidationError("virtual file finalizer returned data")
            new_revision = (
                1
                if current_revision == 0
                else _next_revision(current_revision, "file revision")
            )
            principal = actor_principal_id(authorization.caller)
            updated = {
                "byte_length": byte_length,
                "content_digest": content_digest,
                "encoding": encoding,
                "node_type": "FILE",
                "parent_path": parent_path,
                "revision": new_revision,
                "tombstoned": False,
                "virtual_path": virtual_path,
            }
            session.add(
                VirtualFile(
                    root_id=storage_id,
                    virtual_path=virtual_path,
                    revision=new_revision,
                    parent_path=parent_path,
                    node_type="FILE",
                    encoding=encoding,
                    byte_length=byte_length,
                    content_digest=content_digest,
                    tombstoned=False,
                    created_by_principal=principal,
                )
            )
            heads_by_path = {
                item["virtual_path"]: dict(item) for item in heads
            }
            heads_by_path[virtual_path] = updated
            self._stage_virtual_parent_bump(
                session, root, heads_by_path, virtual_path, principal
            )
            self._clear_virtual_reservation(root)
            root_revision = self._settle_virtual_root(root, heads_by_path)
            return MutationEffect(
                result={
                    "content_sha256": content_digest,
                    "encoding": encoding,
                    "revision": new_revision,
                    "root_id": root_id,
                    "root_revision": root_revision,
                    "size": byte_length,
                    "virtual_path": virtual_path,
                },
                prior_revision=current_revision,
                new_revision=new_revision,
                outcome="WRITTEN",
                response_status=201 if current_revision == 0 else 200,
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    def delete_virtual_node(
        self,
        authorization: AuthorizationContext,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_revision: int,
        idempotency_key: str,
        request_digest: str,
    ) -> dict[str, Any]:
        owner_id = require_identifier(owner_id, "owner_id", maximum_bytes=128)
        storage_id = _virtual_root_storage_id(root_id, owner_id)
        acl_revision = require_expected_revision(acl_revision, "acl_revision")
        virtual_path = _virtual_path(virtual_path)
        expected_revision = require_positive_revision(expected_revision)
        request_digest = require_digest(request_digest, "request_digest")
        request = MutationRequest.build(
            authorization,
            ResourceFamily.FILES,
            "DELETE",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            body={
                "request_digest": request_digest,
                "virtual_path": virtual_path,
            },
        )

        def authorize_in_transaction(session: Session, _: MutationRequest) -> None:
            root = session.get(VirtualFileRoot, storage_id, with_for_update=True)
            if root is not None and (
                root.owner_id != owner_id
                or root.root_kind != root_id
                or root.acl_revision != acl_revision
            ):
                raise DataAuthorizationError("virtual root deletion is not authorized")

        def mutate(session: Session, _: MutationRequest) -> MutationEffect:
            root, heads = self._load_virtual_root(
                session,
                owner_id=owner_id,
                root_id=root_id,
                acl_revision=acl_revision,
                lock=True,
            )
            current = self._virtual_head_by_path(heads, virtual_path)
            if current is None or current["tombstoned"]:
                raise DataNotFoundError("virtual node not found")
            if current["revision"] != expected_revision:
                raise DataConflictError(
                    "virtual node revision differs",
                    current_revision=current["revision"],
                )
            if current["node_type"] == "DIRECTORY" and any(
                not item["tombstoned"]
                and item["virtual_path"].startswith(f"{virtual_path}/")
                for item in heads
            ):
                raise DataConflictError("virtual directory is not empty")
            principal = actor_principal_id(authorization.caller)
            tombstone_revision = _next_revision(
                current["revision"], "virtual node revision"
            )
            tombstone = {
                **current,
                "revision": tombstone_revision,
                "tombstoned": True,
            }
            session.add(
                VirtualFile(
                    root_id=storage_id,
                    virtual_path=virtual_path,
                    revision=tombstone_revision,
                    parent_path=current["parent_path"],
                    node_type=current["node_type"],
                    encoding=current["encoding"],
                    byte_length=current["byte_length"],
                    content_digest=current["content_digest"],
                    tombstoned=True,
                    created_by_principal=principal,
                )
            )
            heads_by_path = {
                item["virtual_path"]: dict(item) for item in heads
            }
            heads_by_path[virtual_path] = tombstone
            self._stage_virtual_parent_bump(
                session, root, heads_by_path, virtual_path, principal
            )
            root_revision = self._settle_virtual_root(root, heads_by_path)
            return MutationEffect(
                result={
                    "deleted_revision": current["revision"],
                    "revision": tombstone_revision,
                    "root_id": root_id,
                    "root_revision": root_revision,
                    "virtual_path": virtual_path,
                },
                prior_revision=current["revision"],
                new_revision=tombstone_revision,
                outcome="DELETED",
            )

        return _mutation_projection(
            self.mutations.execute(
                request,
                mutate,
                authorization_check=authorize_in_transaction,
            )
        )

    @staticmethod
    def _procedure_authorization(
        binding: ProcedureCallerBinding,
        family: ResourceFamily,
        operations: Iterable[str],
        *,
        owner_id: str,
        resource_id: str | None,
        acl_revision: int | None,
    ) -> AuthorizationContext:
        return AuthorizationContext(
            binding,
            tuple(
                DataPermission(
                    family,
                    operation,
                    owner_id,
                    resource_id,
                    acl_revision,
                )
                for operation in operations
            ),
        )

    def _procedure_handle(
        self,
        binding: ProcedureCallerBinding,
        family: ResourceFamily,
        *,
        owner_id: str,
        resource_id: str,
        revision: int,
        content_digest: str,
    ) -> str:
        return self.handles.encode(
            ResourceHandle(
                resource_family=family,
                owner_id=owner_id,
                resource_id=resource_id,
                revision=revision,
                content_digest=content_digest,
                caller_digest=_procedure_handle_caller_digest(binding),
            )
        )

    def _procedure_shared_acl(
        self,
        binding: ProcedureCallerBinding,
        namespace_id: str,
    ) -> int:
        with self.session_factory() as session:
            self._verify_schema(session)
            if self.procedure_binding_check is None:
                raise DataAuthorizationError(
                    "procedure shared data requires admitted-generation authorization"
                )
            self.procedure_binding_check(session, binding)
            head = session.get(
                SharedNamespace,
                _shared_identity(
                    SharedScope.EXECUTION,
                    binding.execution_id,
                    namespace_id,
                ),
            )
            if (
                head is None
                or head.tombstoned
                or head.owner_id != binding.execution_id
                or head.scope != SharedScope.EXECUTION.value
            ):
                raise DataNotFoundError("shared namespace not found")
            return require_expected_revision(head.acl_revision, "acl_revision")

    def recover_procedure_virtual_file_write(
        self,
        original_binding: ProcedureCallerBinding,
        current_binding: ProcedureCallerBinding,
        *,
        owner_id: str,
        root_id: str,
        acl_revision: int,
        virtual_path: str,
        expected_revision: int,
        encoding: str,
        byte_length: int,
        content_digest: str,
        request_digest: str,
    ) -> dict[str, Any]:
        """Recover an exact WRITE settlement; this path cannot create a write."""

        authorization = self._procedure_authorization(
            original_binding,
            ResourceFamily.FILES,
            ("WRITE",),
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            authorization,
            ResourceFamily.FILES,
            "WRITE",
            owner_id=owner_id,
            resource_id=root_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=original_binding.deterministic_request_id,
            body={
                "byte_length": byte_length,
                "content_digest": content_digest,
                "encoding": encoding,
                "request_digest": request_digest,
                "virtual_path": virtual_path,
            },
        )
        return _mutation_projection(
            self.mutations.recover_procedure_settlement(request, current_binding)
        )

    def recover_procedure_mutation(
        self,
        original_binding: ProcedureCallerBinding,
        current_binding: ProcedureCallerBinding,
        *,
        resource_family: ResourceFamily,
        operations: tuple[str, ...],
    ) -> dict[str, Any]:
        """Project one exact committed procedure settlement without mutating."""

        return _mutation_projection(
            self.mutations.recover_procedure_settlement_identity(
                original_binding,
                current_binding,
                resource_family=resource_family,
                operations=operations,
            )
        )

    def recover_procedure_dictionary_load(
        self,
        original_binding: ProcedureCallerBinding,
        current_binding: ProcedureCallerBinding,
        *,
        owner_id: str,
        dictionary_id: str,
        acl_revision: int,
        expected_revision: int,
        document: DictionaryDocument,
    ) -> dict[str, Any]:
        """Recover an exact IMPORT settlement; this path cannot import again."""

        body = {
            "canonical_document_sha256": document.canonical_document_sha256,
            "content_digest": document.content_digest,
            "format": document.format.value,
            "original_bytes_sha256": (
                document.original_bytes_sha256
                or sha256_digest(document.canonical_bytes)
            ),
        }
        authorization = self._procedure_authorization(
            original_binding,
            ResourceFamily.DICTIONARIES,
            ("IMPORT",),
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=acl_revision,
        )
        request = MutationRequest.build(
            authorization,
            ResourceFamily.DICTIONARIES,
            "IMPORT",
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=acl_revision,
            expected_revision=expected_revision,
            idempotency_key=original_binding.deterministic_request_id,
            body=body,
        )
        return _mutation_projection(
            self.mutations.recover_procedure_settlement(request, current_binding)
        )

    def resolve(
        self,
        request: Mapping[str, Any],
        *,
        binding: ProcedureCallerBinding,
    ) -> dict[str, Any]:
        """Resolve one already-admitted closed procedure data command."""

        if type(request) is not dict or type(binding) is not ProcedureCallerBinding:
            raise DataValidationError("procedure data request is invalid")
        expected_fields = {
            "execution_id",
            "operation",
            "parameters",
            "request_digest",
            "request_id",
            "schema_version",
            "service_principal_id",
            "step_index",
            "worker_generation",
        }
        if set(request) != expected_fields or request.get("schema_version") != "spell.v08.data-request/1":
            raise DataValidationError("procedure data request is not closed")
        if (
            request.get("execution_id") != binding.execution_id
            or request.get("service_principal_id") != binding.service_principal_id
            or request.get("worker_generation") != binding.worker_generation
            or request.get("request_id") != binding.deterministic_request_id
        ):
            raise DataAuthorizationError("procedure caller binding differs")
        parameters = request.get("parameters")
        operation = request.get("operation")
        if type(parameters) is not dict or type(operation) is not str:
            raise DataValidationError("procedure data operation is invalid")
        dictionary_owner = binding.execution_id
        execution_owner = binding.execution_id
        request_id = binding.deterministic_request_id

        if operation == "CREATE_DICTIONARY":
            if set(parameters) != {"dictionary_id", "format"} or parameters["format"] != "DB":
                raise DataValidationError("CreateDictionary parameters are invalid")
            dictionary_id = require_identifier(
                parameters["dictionary_id"], "dictionary_id", maximum_bytes=128
            )
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.DICTIONARIES,
                ("IMPORT",),
                owner_id=dictionary_owner,
                resource_id=dictionary_id,
                acl_revision=0,
            )
            result = self.create_dictionary(
                authorization,
                owner_id=dictionary_owner,
                dictionary_id=dictionary_id,
                acl_revision=0,
                idempotency_key=request_id,
                document=build_db_document(dictionary_id, 0, ()),
            )
            handle = self._procedure_handle(
                binding,
                ResourceFamily.DICTIONARIES,
                owner_id=dictionary_owner,
                resource_id=dictionary_id,
                revision=result["revision"],
                content_digest=result["content_digest"],
            )
            return {"outcome": "OK", "value": handle, "revision": result["revision"]}

        if operation in {"LOAD_DICTIONARY", "SAVE_DICTIONARY"}:
            required = {"dictionary_id", "format"}
            if frozenset(parameters) not in {
                frozenset(required),
                frozenset(required | {"revision"}),
            }:
                raise DataValidationError("dictionary operation parameters are invalid")
            if parameters["format"] not in {"DB", "IMP"}:
                raise DataValidationError("dictionary format is invalid")
            dictionary_id = require_identifier(
                parameters["dictionary_id"], "dictionary_id", maximum_bytes=128
            )
            revision = parameters.get("revision")
            if revision is not None:
                revision = require_positive_revision(revision)
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.DICTIONARIES,
                ("EXPORT",),
                owner_id=dictionary_owner,
                resource_id=dictionary_id,
                acl_revision=0,
            )
            exported = self.export_dictionary(
                authorization,
                owner_id=dictionary_owner,
                dictionary_id=dictionary_id,
                acl_revision=0,
                revision=revision,
            )
            document = parse_dictionary_document(exported, media_type=DB_MEDIA_TYPE)
            selected_revision = document.base_revision
            if operation == "SAVE_DICTIONARY":
                return {"outcome": "OK", "revision": selected_revision}
            handle = self._procedure_handle(
                binding,
                ResourceFamily.DICTIONARIES,
                owner_id=dictionary_owner,
                resource_id=dictionary_id,
                revision=selected_revision,
                content_digest=document.content_digest,
            )
            return {"outcome": "OK", "value": handle, "revision": selected_revision}

        if operation == "CREATE_CONTAINER":
            if set(parameters) != {"container_id", "schema_revision"}:
                raise DataValidationError("DataContainer parameters are invalid")
            container_id = require_identifier(
                parameters["container_id"], "container_id", maximum_bytes=128
            )
            schema_revision = require_positive_revision(
                parameters["schema_revision"], "schema_revision"
            )
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.CONTAINERS,
                ("CREATE",),
                owner_id=execution_owner,
                resource_id=container_id,
                acl_revision=0,
            )
            result = self.create_container(
                authorization,
                owner_id=execution_owner,
                container_id=container_id,
                schema_revision=schema_revision,
                acl_revision=0,
                idempotency_key=request_id,
            )
            handle = self._procedure_handle(
                binding,
                ResourceFamily.CONTAINERS,
                owner_id=execution_owner,
                resource_id=container_id,
                revision=result["revision"],
                content_digest=result["content_digest"],
            )
            return {"outcome": "OK", "value": handle, "revision": result["revision"]}

        if operation in {"SET_VARIABLE", "DELETE_VARIABLE"}:
            required = (
                {
                    "container_id",
                    "declared_type",
                    "expected_revision",
                    "name",
                    "value",
                    "variable_id",
                }
                if operation == "SET_VARIABLE"
                else {"container_id", "expected_revision", "variable_id"}
            )
            if set(parameters) != required:
                raise DataValidationError("container variable parameters are invalid")
            container_id = require_identifier(
                parameters["container_id"], "container_id", maximum_bytes=128
            )
            variable_id = require_identifier(
                parameters["variable_id"], "variable_id", maximum_bytes=128
            )
            expected_revision = require_positive_revision(parameters["expected_revision"])
            operations = ("READ", operation.removesuffix("_VARIABLE"))
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.CONTAINERS,
                operations,
                owner_id=execution_owner,
                resource_id=container_id,
                acl_revision=0,
            )
            current = self.read_container(
                authorization,
                owner_id=execution_owner,
                container_id=container_id,
                acl_revision=0,
            )
            matches = [
                item for item in current["variables"] if item["variable_id"] == variable_id
            ]
            expected_variable_revision = matches[0]["revision"] if matches else 0
            if operation == "SET_VARIABLE":
                result = self.set_container_variable(
                    authorization,
                    owner_id=execution_owner,
                    container_id=container_id,
                    acl_revision=0,
                    expected_revision=expected_revision,
                    expected_variable_revision=expected_variable_revision,
                    idempotency_key=request_id,
                    variable=ContainerVariableDefinition(
                        variable_id=variable_id,
                        name=_shared_key(parameters["name"]),
                        declared_type=parameters["declared_type"],
                        value=_declared_procedure_value(
                            parameters["declared_type"], parameters["value"]
                        ),
                    ),
                )
            else:
                if expected_variable_revision == 0:
                    raise DataNotFoundError("container variable not found")
                result = self.delete_container_variable(
                    authorization,
                    owner_id=execution_owner,
                    container_id=container_id,
                    acl_revision=0,
                    expected_revision=expected_revision,
                    variable_id=variable_id,
                    expected_variable_revision=expected_variable_revision,
                    idempotency_key=request_id,
                )
            return {"outcome": "OK", "revision": result["revision"]}

        if operation == "SHARED_CREATE_NAMESPACE":
            if set(parameters) != {"acl_revision", "namespace_id", "scope"}:
                raise DataValidationError("shared namespace parameters are invalid")
            if parameters["scope"] != "EXECUTION":
                raise DataAuthorizationError("procedure shared namespace scope is not authorized")
            namespace_id = require_identifier(
                parameters["namespace_id"], "namespace_id", maximum_bytes=128
            )
            acl_revision = require_expected_revision(
                parameters["acl_revision"], "acl_revision"
            )
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.SHARED,
                ("CREATE_NAMESPACE",),
                owner_id=execution_owner,
                resource_id=namespace_id,
                acl_revision=acl_revision,
            )
            result = self.create_shared_namespace(
                authorization,
                owner_id=execution_owner,
                namespace_id=namespace_id,
                scope=SharedScope.EXECUTION,
                acl_revision=acl_revision,
                idempotency_key=request_id,
            )
            return {"outcome": "OK", "revision": result["revision"]}

        if operation == "SHARED_LIST_NAMESPACES":
            if frozenset(parameters) not in {
                frozenset(),
                frozenset({"cursor"}),
            }:
                raise DataValidationError("shared namespace list parameters are invalid")
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.SHARED,
                ("LIST_NAMESPACES",),
                owner_id=execution_owner,
                resource_id=None,
                acl_revision=None,
            )
            result = self.list_shared_namespaces(
                authorization,
                owner_id=execution_owner,
                cursor=parameters.get("cursor"),
                scope=SharedScope.EXECUTION,
            )
            value = _inferred_typed_value(
                {
                    "namespaces": [item["namespace_id"] for item in result["namespaces"]],
                    "next_cursor": result["next_cursor"],
                }
            )
            return {
                "outcome": "OK",
                "value": canonical_typed_value_json(value),
                "revision": result["owner_revision"],
            }

        if operation in {
            "SHARED_GET",
            "SHARED_ENUMERATE",
            "SHARED_PUT",
            "SHARED_DELETE",
            "SHARED_CLEAR",
            "SHARED_DELETE_NAMESPACE",
        }:
            namespace_id = require_identifier(
                parameters.get("namespace_id"), "namespace_id", maximum_bytes=128
            )
            acl_revision = self._procedure_shared_acl(binding, namespace_id)
            permission = {
                "SHARED_GET": "GET",
                "SHARED_ENUMERATE": "ENUMERATE",
                "SHARED_PUT": "PUT",
                "SHARED_DELETE": "DELETE",
                "SHARED_CLEAR": "CLEAR",
                "SHARED_DELETE_NAMESPACE": "DELETE_NAMESPACE",
            }[operation]
            authorization = self._procedure_authorization(
                binding,
                ResourceFamily.SHARED,
                (permission,),
                owner_id=execution_owner,
                resource_id=namespace_id,
                acl_revision=acl_revision,
            )
            if operation == "SHARED_GET":
                if set(parameters) != {"key", "namespace_id"}:
                    raise DataValidationError("shared get parameters are invalid")
                result = self.get_shared_entry(
                    authorization,
                    owner_id=execution_owner,
                    namespace_id=namespace_id,
                    acl_revision=acl_revision,
                    key=parameters["key"],
                    scope=SharedScope.EXECUTION,
                )
                return {
                    "outcome": "OK",
                    "value": _procedure_result_value(result["value"]),
                    "revision": result["namespace_revision"],
                }
            if operation == "SHARED_ENUMERATE":
                if frozenset(parameters) not in {
                    frozenset({"namespace_id"}),
                    frozenset({"cursor", "namespace_id"}),
                }:
                    raise DataValidationError("shared enumerate parameters are invalid")
                result = self.enumerate_shared_namespace(
                    authorization,
                    owner_id=execution_owner,
                    namespace_id=namespace_id,
                    acl_revision=acl_revision,
                    cursor=parameters.get("cursor"),
                    scope=SharedScope.EXECUTION,
                )
                value = _inferred_typed_value(
                    {
                        "keys": [item["key"] for item in result["entries"]],
                        "next_cursor": result["next_cursor"],
                    }
                )
                return {
                    "outcome": "OK",
                    "value": canonical_typed_value_json(value),
                    "revision": result["revision"],
                }
            expected_revision = require_positive_revision(
                parameters.get("expected_namespace_revision"),
                "expected_namespace_revision",
            )
            if operation == "SHARED_PUT":
                expected_fields = {
                    "expected_entry_revision",
                    "expected_namespace_revision",
                    "key",
                    "namespace_id",
                    "value",
                }
                if set(parameters) != expected_fields:
                    raise DataValidationError("shared put parameters are invalid")
                result = self.put_shared_entry(
                    authorization,
                    owner_id=execution_owner,
                    namespace_id=namespace_id,
                    acl_revision=acl_revision,
                    expected_revision=expected_revision,
                    key=parameters["key"],
                    expected_entry_revision=require_expected_revision(
                        parameters["expected_entry_revision"],
                        "expected_entry_revision",
                    ),
                    idempotency_key=request_id,
                    value=_inferred_typed_value(parameters["value"]),
                    scope=SharedScope.EXECUTION,
                )
            elif operation == "SHARED_DELETE":
                if set(parameters) != {
                    "expected_entry_revision",
                    "expected_namespace_revision",
                    "key",
                    "namespace_id",
                }:
                    raise DataValidationError("shared delete parameters are invalid")
                result = self.delete_shared_entry(
                    authorization,
                    owner_id=execution_owner,
                    namespace_id=namespace_id,
                    acl_revision=acl_revision,
                    expected_revision=expected_revision,
                    key=parameters["key"],
                    expected_entry_revision=require_positive_revision(
                        parameters["expected_entry_revision"],
                        "expected_entry_revision",
                    ),
                    idempotency_key=request_id,
                    scope=SharedScope.EXECUTION,
                )
            elif operation == "SHARED_CLEAR":
                if set(parameters) != {"expected_namespace_revision", "namespace_id"}:
                    raise DataValidationError("shared clear parameters are invalid")
                result = self.clear_shared_namespace(
                    authorization,
                    owner_id=execution_owner,
                    namespace_id=namespace_id,
                    acl_revision=acl_revision,
                    expected_revision=expected_revision,
                    maximum_affected_entries=MAX_SHARED_CLEAR,
                    idempotency_key=request_id,
                    scope=SharedScope.EXECUTION,
                )
            else:
                if set(parameters) != {"expected_namespace_revision", "namespace_id"}:
                    raise DataValidationError("shared delete namespace parameters are invalid")
                result = self.delete_shared_namespace(
                    authorization,
                    owner_id=execution_owner,
                    namespace_id=namespace_id,
                    acl_revision=acl_revision,
                    expected_revision=expected_revision,
                    idempotency_key=request_id,
                    scope=SharedScope.EXECUTION,
                )
            return {"outcome": "OK", "revision": result["revision"]}

        raise DataAuthorizationError("procedure data operation is unavailable")
