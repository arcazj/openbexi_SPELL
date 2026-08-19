"""Closed-world domain rules for the bounded v0.8 local data service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping
from urllib.parse import SplitResult, urlsplit


SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_DATA_SERVICE"
MAX_IDENTIFIER_BYTES = 256
MAX_URI_BYTES = 2048
MAX_DIRECT_DEPENDENCIES = 128
MAX_CLOSURE_NODES = 1024
MAX_DEPENDENCY_DEPTH = 16
MAX_CURSOR_BYTES = 4096
MAX_CONTRACT_INTEGER = (1 << 63) - 1

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[A-Z][A-Z0-9_]*$")


class DataDomainError(ValueError):
    code = "REJECTED"

    def __init__(self, message: str, *, current_revision: int | None = None):
        super().__init__(message)
        self.current_revision = current_revision


class DataValidationError(DataDomainError):
    code = "REJECTED"


class DataAuthorizationError(DataDomainError):
    code = "NOT_AUTHORIZED"


class DataNotFoundError(DataDomainError):
    code = "NOT_FOUND"


class DataConflictError(DataDomainError):
    code = "REVISION_CONFLICT"


class DataCorruptionError(DataDomainError):
    code = "DATA_CORRUPT"


class DataCapacityError(DataDomainError):
    code = "SERVICE_CAPACITY_EXHAUSTED"


class DependencyCycleError(DataDomainError):
    code = "DEPENDENCY_CYCLE"


class DependencyNotFoundError(DataDomainError):
    code = "DEPENDENCY_NOT_FOUND"


class DependencyDigestError(DataDomainError):
    code = "DEPENDENCY_DIGEST_MISMATCH"


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON without accepting non-finite numbers."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DataValidationError("value is not canonical JSON data") from exc


def sha256_digest(payload: bytes) -> str:
    if type(payload) is not bytes:
        raise DataValidationError("digest payload must be bytes")
    return hashlib.sha256(payload).hexdigest()


def require_digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise DataValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_identifier(
    value: Any,
    label: str,
    *,
    maximum_bytes: int = MAX_IDENTIFIER_BYTES,
) -> str:
    if (
        type(value) is not str
        or _IDENTIFIER.fullmatch(value) is None
        or len(value.encode("ascii")) > maximum_bytes
    ):
        raise DataValidationError(f"{label} is not a bounded ASCII identifier")
    return value


def require_principal(value: Any, label: str) -> str:
    if type(value) is not str or _PRINCIPAL.fullmatch(value) is None:
        raise DataValidationError(f"{label} is not a bounded principal identifier")
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise DataValidationError(f"{label} is not ASCII") from exc
    if size > MAX_IDENTIFIER_BYTES:
        raise DataValidationError(f"{label} exceeds {MAX_IDENTIFIER_BYTES} bytes")
    return value


def require_nfc_string(value: Any, label: str, maximum_bytes: int) -> str:
    if type(value) is not str or unicodedata.normalize("NFC", value) != value:
        raise DataValidationError(f"{label} must be an NFC string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DataValidationError(f"{label} is not valid UTF-8") from exc
    if not encoded or len(encoded) > maximum_bytes or any(ord(char) < 32 for char in value):
        raise DataValidationError(f"{label} is outside its bounded string domain")
    return value


def require_positive_revision(value: Any, label: str = "revision") -> int:
    if type(value) is not int or not 1 <= value <= MAX_CONTRACT_INTEGER:
        raise DataValidationError(f"{label} must be a positive signed 64-bit integer")
    return value


def require_expected_revision(value: Any, label: str = "expected_revision") -> int:
    if type(value) is not int or not 0 <= value <= MAX_CONTRACT_INTEGER:
        raise DataValidationError(
            f"{label} must be a nonnegative signed 64-bit integer"
        )
    return value


class CatalogKind(str, Enum):
    SCDB = "SCDB"
    GDB = "GDB"
    PROC = "PROC"
    MMD = "MMD"
    USER_DICTIONARY = "USER_DICTIONARY"


class DependencyRelationship(str, Enum):
    IMPORTS = "IMPORTS"
    REFERENCES = "REFERENCES"
    MAPS_TO = "MAPS_TO"


class ResourceFamily(str, Enum):
    CATALOGS = "CATALOGS"
    DICTIONARIES = "DICTIONARIES"
    CONTAINERS = "CONTAINERS"
    SHARED = "SHARED"
    FILES = "FILES"


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


def _strict_uri_text(value: Any) -> str:
    if type(value) is not str:
        raise DataValidationError("catalog URI must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DataValidationError("catalog URI must be ASCII") from exc
    if (
        not encoded
        or len(encoded) > MAX_URI_BYTES
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
        or b"%" in encoded
        or b"\\" in encoded
    ):
        raise DataValidationError("catalog URI contains a forbidden representation")
    return value


def _split_uri(value: Any) -> SplitResult:
    text = _strict_uri_text(value)
    try:
        parsed = urlsplit(text, allow_fragments=True)
    except ValueError as exc:
        raise DataValidationError("catalog URI is malformed") from exc
    if parsed.query or parsed.fragment:
        raise DataValidationError("catalog URI query and fragment are forbidden")
    return parsed


@dataclass(frozen=True, slots=True)
class CatalogURI:
    kind: CatalogKind
    catalog_id: str
    revision: int
    entry_id: str

    def __post_init__(self) -> None:
        if type(self.kind) is not CatalogKind:
            raise DataValidationError("catalog URI kind is invalid")
        require_identifier(self.catalog_id, "catalog_id")
        require_positive_revision(self.revision)
        require_identifier(self.entry_id, "entry_id")

    @property
    def canonical(self) -> str:
        return (
            f"spell+local:/catalogs/{self.kind.value}/{self.catalog_id}/"
            f"revisions/{self.revision}/entries/{self.entry_id}"
        )

    @classmethod
    def parse(cls, value: Any) -> "CatalogURI":
        parsed = _split_uri(value)
        if parsed.scheme != "spell+local" or parsed.netloc:
            raise DataValidationError("catalog URI must use local repository syntax")
        if not parsed.path.startswith("/") or "//" in parsed.path:
            raise DataValidationError("catalog URI path is malformed")
        parts = parsed.path[1:].split("/")
        if len(parts) != 7 or parts[0] != "catalogs" or parts[3] != "revisions" or parts[5] != "entries":
            raise DataValidationError("catalog URI does not match the closed grammar")
        try:
            kind = CatalogKind(parts[1])
        except ValueError as exc:
            raise DataValidationError("catalog URI kind is not authorized") from exc
        revision_text = parts[4]
        if not revision_text.isascii() or not revision_text.isdecimal() or revision_text.startswith("0"):
            raise DataValidationError("catalog URI revision is not canonical")
        instance = cls(
            kind=kind,
            catalog_id=require_identifier(parts[2], "catalog_id"),
            revision=require_positive_revision(int(revision_text)),
            entry_id=require_identifier(parts[6], "entry_id"),
        )
        if instance.canonical != value:
            raise DataValidationError("catalog URI is not canonical")
        return instance


@dataclass(frozen=True, slots=True)
class LegacyCatalogURI:
    scheme: str
    logical_folder: str
    logical_name: str

    def __post_init__(self) -> None:
        if self.scheme not in {"mmd", "usr"}:
            raise DataValidationError("legacy catalog URI scheme is not authorized")
        require_identifier(self.logical_folder, "logical_folder")
        require_identifier(self.logical_name, "logical_name")

    @property
    def target_kind(self) -> CatalogKind:
        return CatalogKind.MMD if self.scheme == "mmd" else CatalogKind.USER_DICTIONARY

    @property
    def canonical(self) -> str:
        return f"{self.scheme}://{self.logical_folder}/{self.logical_name}"

    @classmethod
    def parse(cls, value: Any) -> "LegacyCatalogURI":
        parsed = _split_uri(value)
        if parsed.scheme not in {"mmd", "usr"} or not parsed.netloc:
            raise DataValidationError("legacy catalog URI scheme is not authorized")
        if parsed.username is not None or parsed.password is not None:
            raise DataValidationError("legacy catalog URI user information is forbidden")
        try:
            if parsed.port is not None:
                raise DataValidationError("legacy catalog URI port is forbidden")
        except ValueError as exc:
            raise DataValidationError("legacy catalog URI authority is malformed") from exc
        path = parsed.path
        if not path.startswith("/") or path.count("/") != 1:
            raise DataValidationError("legacy catalog URI path is malformed")
        instance = cls(
            scheme=parsed.scheme,
            logical_folder=require_identifier(parsed.netloc, "logical_folder"),
            logical_name=require_identifier(path[1:], "logical_name"),
        )
        if instance.canonical != value:
            raise DataValidationError("legacy catalog URI is not canonical")
        return instance


@dataclass(frozen=True, slots=True)
class PinnedCatalogReference:
    uri: CatalogURI
    content_digest: str
    legacy_source: LegacyCatalogURI | None = None

    def __post_init__(self) -> None:
        if type(self.uri) is not CatalogURI:
            raise DataValidationError("pinned catalog reference URI is invalid")
        require_digest(self.content_digest, "content_digest")
        if self.legacy_source is not None and self.legacy_source.target_kind is not self.uri.kind:
            raise DataValidationError("legacy URI kind differs from its pinned catalog")


def pin_legacy_catalog_uri(
    value: Any,
    *,
    catalog_id: Any,
    revision: Any,
    content_digest: Any,
    entry_id: Any,
) -> PinnedCatalogReference:
    legacy = LegacyCatalogURI.parse(value)
    return PinnedCatalogReference(
        uri=CatalogURI(
            kind=legacy.target_kind,
            catalog_id=require_identifier(catalog_id, "catalog_id"),
            revision=require_positive_revision(revision),
            entry_id=require_identifier(entry_id, "entry_id"),
        ),
        content_digest=require_digest(content_digest, "content_digest"),
        legacy_source=legacy,
    )


@dataclass(frozen=True, slots=True)
class CatalogNode:
    catalog_id: str
    kind: CatalogKind
    revision: int
    content_digest: str

    def __post_init__(self) -> None:
        require_identifier(self.catalog_id, "catalog_id")
        if type(self.kind) is not CatalogKind:
            raise DataValidationError("catalog kind is invalid")
        require_positive_revision(self.revision)
        require_digest(self.content_digest, "content_digest")

    @property
    def identity(self) -> tuple[str, int]:
        return self.catalog_id, self.revision


@dataclass(frozen=True, slots=True)
class CatalogDependency:
    dependency_id: str
    source_catalog_id: str
    source_revision: int
    target_catalog_id: str
    target_revision: int
    target_content_digest: str
    relationship: DependencyRelationship

    def __post_init__(self) -> None:
        require_identifier(self.dependency_id, "dependency_id")
        require_identifier(self.source_catalog_id, "source_catalog_id")
        require_positive_revision(self.source_revision, "source_revision")
        require_identifier(self.target_catalog_id, "target_catalog_id")
        require_positive_revision(self.target_revision, "target_revision")
        require_digest(self.target_content_digest, "target_content_digest")
        if type(self.relationship) is not DependencyRelationship:
            raise DataValidationError("dependency relationship is invalid")

    @property
    def source_identity(self) -> tuple[str, int]:
        return self.source_catalog_id, self.source_revision

    @property
    def target_identity(self) -> tuple[str, int]:
        return self.target_catalog_id, self.target_revision


@dataclass(frozen=True, slots=True)
class ResolvedCatalogClosure:
    root: tuple[str, int]
    nodes: tuple[CatalogNode, ...]
    dependencies: tuple[CatalogDependency, ...]
    closure_digest: str


def resolve_catalog_closure(
    root: tuple[str, int],
    nodes: Iterable[CatalogNode],
    dependencies: Iterable[CatalogDependency],
) -> ResolvedCatalogClosure:
    if (
        type(root) is not tuple
        or len(root) != 2
        or type(root[0]) is not str
        or type(root[1]) is not int
    ):
        raise DataValidationError("catalog closure root is invalid")
    node_map: dict[tuple[str, int], CatalogNode] = {}
    for node in nodes:
        if type(node) is not CatalogNode or node.identity in node_map:
            raise DataValidationError("catalog closure contains a duplicate node")
        node_map[node.identity] = node
    if root not in node_map:
        raise DependencyNotFoundError("root catalog revision is unavailable")

    edge_ids: set[str] = set()
    outgoing: dict[tuple[str, int], list[CatalogDependency]] = {}
    for dependency in dependencies:
        if type(dependency) is not CatalogDependency or dependency.dependency_id in edge_ids:
            raise DataValidationError("catalog closure contains a duplicate dependency")
        edge_ids.add(dependency.dependency_id)
        outgoing.setdefault(dependency.source_identity, []).append(dependency)
    for source, edges in outgoing.items():
        if source not in node_map:
            raise DependencyNotFoundError("dependency source catalog is unavailable")
        if len(edges) > MAX_DIRECT_DEPENDENCIES:
            raise DataCapacityError("direct dependency bound exceeded")
        edges.sort(key=lambda edge: edge.dependency_id.encode("ascii"))

    visited: set[tuple[str, int]] = set()
    active: set[tuple[str, int]] = set()
    selected_edges: dict[str, CatalogDependency] = {}

    def visit(identity: tuple[str, int], depth: int) -> None:
        if depth > MAX_DEPENDENCY_DEPTH:
            raise DataCapacityError("dependency depth bound exceeded")
        if identity in active:
            raise DependencyCycleError("catalog dependency cycle detected")
        if identity in visited:
            return
        if len(visited) + len(active) >= MAX_CLOSURE_NODES:
            raise DataCapacityError("dependency closure node bound exceeded")
        node = node_map.get(identity)
        if node is None:
            raise DependencyNotFoundError("dependency target catalog is unavailable")
        active.add(identity)
        for edge in outgoing.get(identity, ()):
            target = node_map.get(edge.target_identity)
            if target is None:
                raise DependencyNotFoundError("dependency target catalog is unavailable")
            if target.content_digest != edge.target_content_digest:
                raise DependencyDigestError("dependency target digest differs")
            selected_edges[edge.dependency_id] = edge
            visit(edge.target_identity, depth + 1)
        active.remove(identity)
        visited.add(identity)

    visit(root, 0)
    ordered_nodes = tuple(sorted((node_map[item] for item in visited), key=lambda node: (node.catalog_id.encode("ascii"), node.revision)))
    ordered_edges = tuple(sorted(selected_edges.values(), key=lambda edge: edge.dependency_id.encode("ascii")))
    payload = {
        "nodes": [
            {
                "catalog_id": node.catalog_id,
                "content_digest": node.content_digest,
                "kind": node.kind.value,
                "revision": node.revision,
            }
            for node in ordered_nodes
        ],
        "dependencies": [
            {
                "dependency_id": edge.dependency_id,
                "relationship": edge.relationship.value,
                "source_catalog_id": edge.source_catalog_id,
                "source_revision": edge.source_revision,
                "target_catalog_id": edge.target_catalog_id,
                "target_content_digest": edge.target_content_digest,
                "target_revision": edge.target_revision,
            }
            for edge in ordered_edges
        ],
    }
    return ResolvedCatalogClosure(
        root=root,
        nodes=ordered_nodes,
        dependencies=ordered_edges,
        closure_digest=sha256_digest(canonical_json_bytes(payload)),
    )


def _request_binding(value: Any, label: str) -> str:
    if type(value) is not str:
        raise DataValidationError(f"{label} must be an ASCII request binding")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DataValidationError(f"{label} must be ASCII") from exc
    if not 16 <= len(encoded) <= 128 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise DataValidationError(f"{label} must contain 16 through 128 printable ASCII bytes")
    return value


@dataclass(frozen=True, slots=True)
class HTTPCallerBinding:
    subject: str
    role: Role
    session_id: str
    client_instance_key_id: str

    def __post_init__(self) -> None:
        require_principal(self.subject, "subject")
        if type(self.role) is not Role:
            raise DataValidationError("role must be one accepted lowercase role")
        _request_binding(self.session_id, "session_id")
        _request_binding(self.client_instance_key_id, "client_instance_key_id")


@dataclass(frozen=True, slots=True)
class ProcedureCallerBinding:
    service_principal_id: str
    execution_id: str
    worker_generation: int
    deterministic_request_id: str

    def __post_init__(self) -> None:
        require_principal(self.service_principal_id, "service_principal_id")
        require_identifier(self.execution_id, "execution_id")
        if (
            type(self.worker_generation) is not int
            or not 0 <= self.worker_generation <= MAX_CONTRACT_INTEGER
        ):
            raise DataValidationError("worker_generation must be a nonnegative integer")
        require_identifier(self.deterministic_request_id, "deterministic_request_id")


CallerBinding = HTTPCallerBinding | ProcedureCallerBinding


def caller_binding_payload(binding: CallerBinding) -> dict[str, Any]:
    if type(binding) is HTTPCallerBinding:
        return {
            "client_instance_key_id": binding.client_instance_key_id,
            "kind": "HTTP",
            "role": binding.role.value,
            "session_id": binding.session_id,
            "subject": binding.subject,
        }
    if type(binding) is ProcedureCallerBinding:
        return {
            "deterministic_request_id": binding.deterministic_request_id,
            "execution_id": binding.execution_id,
            "kind": "PROCEDURE",
            "service_principal_id": binding.service_principal_id,
            "worker_generation": binding.worker_generation,
        }
    raise DataValidationError("caller binding is invalid")


def caller_binding_digest(binding: CallerBinding) -> str:
    return sha256_digest(canonical_json_bytes(caller_binding_payload(binding)))


def actor_principal_id(binding: CallerBinding) -> str:
    if type(binding) is HTTPCallerBinding:
        return binding.subject
    if type(binding) is ProcedureCallerBinding:
        return binding.service_principal_id
    raise DataValidationError("caller binding is invalid")


@dataclass(frozen=True, slots=True)
class DataPermission:
    resource_family: ResourceFamily
    operation: str
    owner_id: str
    resource_id: str | None = None
    acl_revision: int | None = None

    def __post_init__(self) -> None:
        if type(self.resource_family) is not ResourceFamily:
            raise DataValidationError("permission resource family is invalid")
        if type(self.operation) is not str or _OPERATION.fullmatch(self.operation) is None:
            raise DataValidationError("permission operation is invalid")
        require_identifier(self.owner_id, "permission owner_id")
        if self.resource_id is not None:
            require_identifier(self.resource_id, "permission resource_id")
        if self.acl_revision is not None:
            require_expected_revision(self.acl_revision, "permission acl_revision")


_READ_OPERATIONS = frozenset(
    {"LIST", "READ", "GET", "ENUMERATE", "LIST_NAMESPACES", "EXPORT"}
)


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    caller: CallerBinding
    permissions: tuple[DataPermission, ...]
    scope_profile: str = SCOPE_PROFILE

    def __post_init__(self) -> None:
        caller_binding_payload(self.caller)
        if type(self.permissions) is not tuple or any(
            type(permission) is not DataPermission for permission in self.permissions
        ):
            raise DataValidationError("permissions must be an immutable permission tuple")
        if len(set(self.permissions)) != len(self.permissions):
            raise DataValidationError("permissions contain duplicates")
        if self.scope_profile != SCOPE_PROFILE:
            raise DataAuthorizationError("data scope profile is not authorized")

    def require(
        self,
        resource_family: ResourceFamily,
        operation: str,
        *,
        owner_id: str,
        resource_id: str | None = None,
        acl_revision: int | None = None,
    ) -> None:
        if type(resource_family) is not ResourceFamily:
            raise DataValidationError("resource family is invalid")
        if type(operation) is not str or _OPERATION.fullmatch(operation) is None:
            raise DataValidationError("operation is invalid")
        require_identifier(owner_id, "owner_id")
        if resource_id is not None:
            require_identifier(resource_id, "resource_id")
        if acl_revision is not None:
            require_expected_revision(acl_revision, "acl_revision")
        if type(self.caller) is HTTPCallerBinding:
            if self.caller.role is Role.VIEWER and operation not in _READ_OPERATIONS:
                raise DataAuthorizationError("mutation is not authorized")
            if self.caller.role is Role.OPERATOR and operation in {"PUBLISH", "ACL_ADMIN"}:
                raise DataAuthorizationError("administrative operation is not authorized")
        wanted = (resource_family, operation, owner_id, resource_id, acl_revision)
        if not any(
            (
                permission.resource_family,
                permission.operation,
                permission.owner_id,
                permission.resource_id,
                permission.acl_revision,
            )
            == wanted
            for permission in self.permissions
        ):
            raise DataAuthorizationError("data operation is not authorized")

    @property
    def authorization_digest(self) -> str:
        payload = {
            "caller": caller_binding_payload(self.caller),
            "permissions": [
                {
                    "acl_revision": item.acl_revision,
                    "operation": item.operation,
                    "owner_id": item.owner_id,
                    "resource_family": item.resource_family.value,
                    "resource_id": item.resource_id,
                }
                for item in sorted(
                    self.permissions,
                    key=lambda permission: (
                        permission.resource_family.value,
                        permission.operation,
                        permission.owner_id,
                        permission.resource_id or "",
                        permission.acl_revision or 0,
                    ),
                )
            ],
            "scope_profile": self.scope_profile,
        }
        return sha256_digest(canonical_json_bytes(payload))


@dataclass(frozen=True, slots=True)
class RevisionCursor:
    resource_identity: str
    revision: int
    authorization_digest: str
    last_key: str
    last_identity: str

    def __post_init__(self) -> None:
        require_identifier(self.resource_identity, "cursor resource_identity")
        require_positive_revision(self.revision, "cursor revision")
        require_digest(self.authorization_digest, "cursor authorization_digest")
        require_nfc_string(self.last_key, "cursor last_key", 512)
        require_identifier(self.last_identity, "cursor last_identity")


class CursorCodec:
    """Opaque, integrity-protected cursor bound to revision and authorization."""

    def __init__(self, secret: bytes):
        if type(secret) is not bytes or len(secret) < 32:
            raise DataValidationError("cursor secret must contain at least 32 bytes")
        self._secret = secret

    def encode(self, cursor: RevisionCursor) -> str:
        if type(cursor) is not RevisionCursor:
            raise DataValidationError("cursor payload is invalid")
        payload = canonical_json_bytes(
            {
                "authorization_digest": cursor.authorization_digest,
                "last_identity": cursor.last_identity,
                "last_key": cursor.last_key,
                "resource_identity": cursor.resource_identity,
                "revision": cursor.revision,
                "schema_version": "spell.data.cursor/1",
            }
        )
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(payload + signature).rstrip(b"=").decode("ascii")
        if len(encoded) > MAX_CURSOR_BYTES:
            raise DataValidationError("cursor exceeds its encoded bound")
        return encoded

    def decode(
        self,
        value: Any,
        *,
        resource_identity: str,
        revision: int,
        authorization_digest: str,
    ) -> RevisionCursor:
        require_identifier(resource_identity, "cursor resource_identity")
        require_positive_revision(revision, "cursor revision")
        require_digest(authorization_digest, "cursor authorization_digest")
        if type(value) is not str or not value or len(value) > MAX_CURSOR_BYTES:
            raise DataValidationError("cursor is invalid")
        try:
            raw = value.encode("ascii")
            decoded = base64.b64decode(
                raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True
            )
        except (UnicodeEncodeError, ValueError) as exc:
            raise DataValidationError("cursor is invalid") from exc
        if len(decoded) <= 32:
            raise DataValidationError("cursor is invalid")
        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if canonical != value:
            raise DataValidationError("cursor is not canonically encoded")
        payload, supplied = decoded[:-32], decoded[-32:]
        expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, expected):
            raise DataValidationError("cursor is invalid")
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DataValidationError("cursor is invalid") from exc
        if type(parsed) is not dict or set(parsed) != {
            "authorization_digest",
            "last_identity",
            "last_key",
            "resource_identity",
            "revision",
            "schema_version",
        } or parsed["schema_version"] != "spell.data.cursor/1":
            raise DataValidationError("cursor is invalid")
        cursor = RevisionCursor(
            resource_identity=parsed["resource_identity"],
            revision=parsed["revision"],
            authorization_digest=parsed["authorization_digest"],
            last_key=parsed["last_key"],
            last_identity=parsed["last_identity"],
        )
        if (
            cursor.resource_identity != resource_identity
            or cursor.authorization_digest != authorization_digest
        ):
            raise DataAuthorizationError("cursor authorization binding differs")
        if cursor.revision != revision:
            error = DataConflictError("cursor revision changed", current_revision=revision)
            error.code = "RESYNC_REQUIRED"
            raise error
        return cursor


@dataclass(frozen=True, slots=True)
class ResourceHandle:
    resource_family: ResourceFamily
    owner_id: str
    resource_id: str
    revision: int
    content_digest: str
    caller_digest: str

    def __post_init__(self) -> None:
        if type(self.resource_family) is not ResourceFamily:
            raise DataValidationError("handle resource family is invalid")
        require_identifier(self.owner_id, "handle owner_id")
        require_identifier(self.resource_id, "handle resource_id")
        require_positive_revision(self.revision, "handle revision")
        require_digest(self.content_digest, "handle content_digest")
        require_digest(self.caller_digest, "handle caller_digest")


class ResourceHandleCodec:
    """Stateless opaque handle bound to one immutable resource revision."""

    def __init__(self, secret: bytes):
        if type(secret) is not bytes or len(secret) < 32:
            raise DataValidationError("handle secret must contain at least 32 bytes")
        self._secret = secret

    def encode(self, handle: ResourceHandle) -> str:
        if type(handle) is not ResourceHandle:
            raise DataValidationError("handle payload is invalid")
        payload = canonical_json_bytes(
            {
                "caller_digest": handle.caller_digest,
                "content_digest": handle.content_digest,
                "owner_id": handle.owner_id,
                "resource_family": handle.resource_family.value,
                "resource_id": handle.resource_id,
                "revision": handle.revision,
                "schema_version": "spell.data.resource-handle/1",
            }
        )
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).rstrip(b"=").decode("ascii")

    def decode(self, value: Any, *, caller_digest: str) -> ResourceHandle:
        require_digest(caller_digest, "handle caller_digest")
        if type(value) is not str or not value or len(value) > MAX_CURSOR_BYTES:
            raise DataValidationError("resource handle is invalid")
        try:
            encoded = value.encode("ascii")
            decoded = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
        except (UnicodeEncodeError, ValueError) as exc:
            raise DataValidationError("resource handle is invalid") from exc
        if len(decoded) <= 32:
            raise DataValidationError("resource handle is invalid")
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            raise DataValidationError("resource handle is not canonically encoded")
        payload, supplied = decoded[:-32], decoded[-32:]
        expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, expected):
            raise DataValidationError("resource handle is invalid")
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DataValidationError("resource handle is invalid") from exc
        if type(parsed) is not dict or set(parsed) != {
            "caller_digest",
            "content_digest",
            "owner_id",
            "resource_family",
            "resource_id",
            "revision",
            "schema_version",
        } or parsed["schema_version"] != "spell.data.resource-handle/1":
            raise DataValidationError("resource handle is invalid")
        try:
            handle = ResourceHandle(
                resource_family=ResourceFamily(parsed["resource_family"]),
                owner_id=parsed["owner_id"],
                resource_id=parsed["resource_id"],
                revision=parsed["revision"],
                content_digest=parsed["content_digest"],
                caller_digest=parsed["caller_digest"],
            )
        except (ValueError, DataDomainError) as exc:
            raise DataValidationError("resource handle is invalid") from exc
        if handle.caller_digest != caller_digest:
            raise DataAuthorizationError("resource handle caller binding differs")
        return handle


__all__ = [
    "AuthorizationContext",
    "CallerBinding",
    "CatalogDependency",
    "CatalogKind",
    "CatalogNode",
    "CatalogURI",
    "CursorCodec",
    "DataAuthorizationError",
    "DataCapacityError",
    "DataConflictError",
    "DataCorruptionError",
    "DataDomainError",
    "DataNotFoundError",
    "DataPermission",
    "DataValidationError",
    "DependencyCycleError",
    "DependencyDigestError",
    "DependencyNotFoundError",
    "DependencyRelationship",
    "HTTPCallerBinding",
    "LegacyCatalogURI",
    "MAX_CONTRACT_INTEGER",
    "PinnedCatalogReference",
    "ProcedureCallerBinding",
    "ResolvedCatalogClosure",
    "ResourceFamily",
    "RevisionCursor",
    "ResourceHandle",
    "ResourceHandleCodec",
    "Role",
    "SCOPE_PROFILE",
    "actor_principal_id",
    "caller_binding_digest",
    "caller_binding_payload",
    "canonical_json_bytes",
    "pin_legacy_catalog_uri",
    "require_digest",
    "require_expected_revision",
    "require_identifier",
    "require_nfc_string",
    "require_positive_revision",
    "resolve_catalog_closure",
    "sha256_digest",
]
