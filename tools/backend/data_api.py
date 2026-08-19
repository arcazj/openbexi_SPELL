"""Authenticated, bounded REST boundary for the v0.8 local data service."""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from typing import Any, AsyncIterator, Callable, TypeVar

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ValidationError

from .data_domain import (
    AuthorizationContext,
    CatalogKind,
    CatalogURI,
    DataAuthorizationError,
    DataCapacityError,
    DataConflictError,
    DataDomainError,
    DataNotFoundError,
    DataPermission,
    DependencyRelationship,
    HTTPCallerBinding,
    ResourceFamily,
    Role,
    canonical_json_bytes,
)
from .data_schemas import (
    CatalogPublishRequest,
    ContainerCreateRequest,
    ContainerDeleteRequest,
    ContainerSetRequest,
    DirectoryCreateRequest,
    DICTIONARY_IMPORT_MEDIA_TYPES,
    FileDeleteRequest,
    MAXIMUM_FILE_BYTES,
    MAXIMUM_IMPORT_BYTES,
    MAXIMUM_JSON_BYTES,
    MAXIMUM_PAGE_SIZE,
    NamespaceCreateRequest,
    NamespaceDeleteRequest,
    SharedClearRequest,
    SharedDeleteRequest,
    SharedPutRequest,
    WirePositiveRevision,
    WireRevision,
)
from .data_values import (
    TypedValueError,
    contract_integer_from_wire,
    contract_integer_to_wire,
    strict_json_loads,
)
from .data_repository import (
    CatalogDependencyDefinition,
    CatalogEntryDefinition,
    ContainerVariableDefinition,
    DataRepository,
    SharedScope,
)
from .dictionary_exchange import (
    DB_MEDIA_TYPE,
    DictionaryExchangeError,
    parse_dictionary_document,
)
from .virtual_file_service import VirtualFileError, VirtualFileService
from .virtual_file_service import validate_virtual_path


_Model = TypeVar("_Model", bound=BaseModel)
_READ_SESSION_BINDING = "server-read-bind-1"
_READ_CLIENT_BINDING = "server-read-client-1"
_HTTP_DATA_OWNER_ID = "local-project"
_HTTP_DATA_ACL_REVISION = 1
_DICTIONARY_IMPORT_DURATION_SECONDS = 60.0
_READ_OPERATIONS = frozenset(
    {"ENUMERATE", "EXPORT", "GET", "LIST", "LIST_NAMESPACES", "READ"}
)
_FAMILY_OPERATIONS = {
    ResourceFamily.CATALOGS: frozenset({"LIST", "PUBLISH", "READ"}),
    ResourceFamily.DICTIONARIES: frozenset({"EXPORT", "IMPORT", "LIST"}),
    ResourceFamily.CONTAINERS: frozenset(
        {"CREATE", "DELETE", "ENUMERATE", "READ", "SET"}
    ),
    ResourceFamily.SHARED: frozenset(
        {
            "CLEAR",
            "CREATE_NAMESPACE",
            "DELETE",
            "DELETE_NAMESPACE",
            "ENUMERATE",
            "GET",
            "LIST_NAMESPACES",
            "PUT",
        }
    ),
    ResourceFamily.FILES: frozenset(
        {"CREATE_DIRECTORY", "DELETE", "LIST", "READ", "WRITE"}
    ),
}


def _status_for(code: str) -> int:
    if code in {"NOT_AUTHORIZED"}:
        return 403
    if code in {"NOT_FOUND"}:
        return 404
    if code in {"REVISION_CONFLICT", "IDEMPOTENCY_CONFLICT", "RESYNC_REQUIRED", "STALE_HANDLE"}:
        return 409
    if code in {"LIMIT_EXCEEDED"}:
        return 413
    if code in {"SERVICE_CAPACITY_EXHAUSTED"}:
        return 507
    if code in {"CORRUPT_FILE", "DATA_CORRUPT", "INTERNAL"}:
        return 500
    return 422


def _error_response(error: Exception) -> JSONResponse:
    code = str(getattr(error, "code", "REJECTED"))
    content: dict[str, Any] = {"code": code, "detail": str(error)[:240]}
    current_revision = getattr(error, "current_revision", None)
    if current_revision is not None:
        content["current_revision"] = contract_integer_to_wire(
            current_revision, label="current_revision"
        )
    return JSONResponse(status_code=_status_for(code), content=content)


def _revision_parameter(
    value: str | None,
    *,
    allow_none: bool = False,
    allow_zero: bool = True,
    label: str = "revision",
) -> int | None:
    if value is None and allow_none:
        return None
    try:
        return contract_integer_from_wire(
            value, allow_zero=allow_zero, label=label  # type: ignore[arg-type]
        )
    except TypedValueError as exc:
        raise VirtualFileError("REJECTED", str(exc)) from exc


_WIRE_INTEGER_KEYS = frozenset(
    {
        "checkpoint_sequence",
        "revision",
        "sequence",
        "worker_generation",
    }
)
_OPAQUE_DATA_KEYS = frozenset({"content", "value"})


def _wire_contract_integers(payload: Any) -> Any:
    if type(payload) is list:
        return [_wire_contract_integers(item) for item in payload]
    if type(payload) is tuple:
        return [_wire_contract_integers(item) for item in payload]
    if type(payload) is not dict:
        return payload
    projected: dict[str, Any] = {}
    for key, value in payload.items():
        is_contract_integer = key in _WIRE_INTEGER_KEYS or key.endswith("_revision")
        if is_contract_integer and type(value) is int:
            projected[key] = contract_integer_to_wire(value, label=key)
        elif key in _OPAQUE_DATA_KEYS:
            projected[key] = value
        else:
            projected[key] = _wire_contract_integers(value)
    return projected


def _printable_ascii_binding(value: str | None, label: str) -> str:
    if value is None:
        raise VirtualFileError("REJECTED", f"{label} is required")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise VirtualFileError("REJECTED", f"{label} must be ASCII") from exc
    if not 16 <= len(encoded) <= 128 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise VirtualFileError(
            "REJECTED", f"{label} must contain 16 through 128 printable ASCII bytes"
        )
    return value


def _idempotency_key(value: str | None) -> str:
    if value is None:
        raise VirtualFileError("REJECTED", "Idempotency-Key is required")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise VirtualFileError("REJECTED", "Idempotency-Key must be ASCII") from exc
    if not encoded or len(encoded) > 128 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise VirtualFileError("REJECTED", "Idempotency-Key is invalid")
    return value


def _media_type(request: Request) -> str:
    return request.headers.get("content-type", "").strip().lower()


def _require_identity_encoding(request: Request) -> None:
    content_encoding = request.headers.get("content-encoding", "identity").strip().lower()
    if content_encoding != "identity":
        raise VirtualFileError("REJECTED", "compressed request bodies are forbidden")
    if request.headers.get("transfer-encoding") is not None:
        raise VirtualFileError("REJECTED", "chunked request bodies are forbidden")


def _declared_length(request: Request, maximum: int) -> int:
    _require_identity_encoding(request)
    raw = request.headers.get("content-length")
    if raw is None:
        raise VirtualFileError("REJECTED", "bounded Content-Length is required")
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise VirtualFileError("REJECTED", "Content-Length is invalid") from exc
    if value < 0:
        raise VirtualFileError("REJECTED", "Content-Length is invalid")
    if value > maximum:
        raise VirtualFileError("LIMIT_EXCEEDED", "request body exceeds its byte limit")
    return value


async def _strict_json_body(
    request: Request, model: type[_Model], *, maximum: int = MAXIMUM_JSON_BYTES
) -> tuple[_Model, bytes]:
    media_type = _media_type(request).split(";", 1)[0]
    if media_type != "application/json":
        raise VirtualFileError("REJECTED", "Content-Type must be application/json")
    declared = _declared_length(request, maximum)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise VirtualFileError("LIMIT_EXCEEDED", "request body exceeds its byte limit")
    if len(body) != declared:
        raise VirtualFileError("REJECTED", "request body length differs from Content-Length")
    try:
        parsed = strict_json_loads(bytes(body), maximum_bytes=maximum)
        validated = model.model_validate(parsed)
    except (TypedValueError, ValidationError) as exc:
        raise VirtualFileError("REJECTED", "request body does not match the closed schema") from exc
    return validated, bytes(body)


def _request_digest(
    method: str,
    resource_identity: str,
    expected_revision: int,
    body_sha256: str,
) -> str:
    payload = {
        "body_sha256": body_sha256,
        "expected_revision": expected_revision,
        "method": method,
        "resource_identity": resource_identity,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _semantic_body_digest(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _http_caller(identity: Any, session_id: str, client_key: str) -> HTTPCallerBinding:
    try:
        role = Role(str(identity.role))
        return HTTPCallerBinding(str(identity.actor), role, session_id, client_key)
    except (ValueError, DataDomainError) as exc:
        raise VirtualFileError("NOT_AUTHORIZED", "authenticated identity is not accepted") from exc


class LocalDataPermissionResolver:
    """Issue exact HTTP permissions from the server-owned local-project policy."""

    def __init__(
        self,
        *,
        owner_id: str = _HTTP_DATA_OWNER_ID,
        acl_revision: int = _HTTP_DATA_ACL_REVISION,
    ) -> None:
        if owner_id != _HTTP_DATA_OWNER_ID or acl_revision != _HTTP_DATA_ACL_REVISION:
            raise DataAuthorizationError("HTTP data policy differs from the fixed local scope")
        self.owner_id = owner_id
        self.acl_revision = acl_revision

    def resolve(
        self,
        caller: HTTPCallerBinding,
        family: ResourceFamily,
        operation: str,
        *,
        owner_id: str,
        resource_id: str | None,
        acl_revision: int | None,
    ) -> AuthorizationContext:
        if type(caller) is not HTTPCallerBinding:
            raise DataAuthorizationError("HTTP data caller binding is not trusted")
        if operation not in _FAMILY_OPERATIONS.get(family, frozenset()):
            raise DataAuthorizationError("data operation is outside the local policy")
        if caller.role is Role.VIEWER and operation not in _READ_OPERATIONS:
            raise DataAuthorizationError("viewer mutation is not authorized")
        if caller.role is Role.OPERATOR and operation == "PUBLISH":
            raise DataAuthorizationError("catalog publication requires administrator authority")

        if family is ResourceFamily.FILES:
            root_policy = {
                "PROCEDURE_DATA": (
                    "procedure-library",
                    frozenset({"LIST", "READ"}),
                ),
                "PROJECT_DATA": (
                    self.owner_id,
                    frozenset(
                        {"CREATE_DIRECTORY", "DELETE", "LIST", "READ", "WRITE"}
                    ),
                ),
            }.get(resource_id or "")
            if (
                root_policy is None
                or owner_id != root_policy[0]
                or operation not in root_policy[1]
                or acl_revision != self.acl_revision
            ):
                raise DataAuthorizationError("virtual root access is not granted")
        else:
            if owner_id != self.owner_id:
                raise DataAuthorizationError("data owner is not granted to this HTTP scope")
            if resource_id is None:
                expected_list = {
                    ResourceFamily.CATALOGS: "LIST",
                    ResourceFamily.DICTIONARIES: "LIST",
                    ResourceFamily.CONTAINERS: "READ",
                    ResourceFamily.SHARED: "LIST_NAMESPACES",
                }.get(family)
                if operation != expected_list or acl_revision is not None:
                    raise DataAuthorizationError("owner enumeration is not granted")
            elif acl_revision != self.acl_revision:
                raise DataAuthorizationError("data ACL revision is not granted")

        permission = DataPermission(
            family,
            operation,
            owner_id,
            resource_id,
            acl_revision,
        )
        authorization = AuthorizationContext(caller, (permission,))
        authorization.require(
            family,
            operation,
            owner_id=owner_id,
            resource_id=resource_id,
            acl_revision=acl_revision,
        )
        return authorization


def _root_owner(root_id: str) -> str:
    if root_id == "PROCEDURE_DATA":
        return "procedure-library"
    if root_id == "PROJECT_DATA":
        return "local-project"
    if root_id == "EXECUTION_SCRATCH":
        raise VirtualFileError("NOT_AUTHORIZED", "execution scratch is not exposed over HTTP")
    raise VirtualFileError("NOT_FOUND", "virtual root is unavailable")


def _require_public_shared_scope(scope: SharedScope) -> None:
    if scope is not SharedScope.PROJECT:
        raise VirtualFileError(
            "NOT_AUTHORIZED",
            "HTTP shared data is restricted to the server-owned project scope",
        )


def _catalog_id_from_uri(uri: str) -> str:
    return CatalogURI.parse(uri).catalog_id


def _file_authorization(
    resolver: LocalDataPermissionResolver,
    identity: Any,
    root_id: str,
    operation: str,
    *,
    session_id: str | None = None,
    client_key: str | None = None,
) -> AuthorizationContext:
    owner = _root_owner(root_id)
    mutation = operation not in _READ_OPERATIONS
    if mutation:
        if str(identity.role) == "viewer":
            raise VirtualFileError("NOT_AUTHORIZED", "viewer mutations are forbidden")
        session = _printable_ascii_binding(session_id, "X-Spell-Session-Id")
        client = _printable_ascii_binding(
            client_key, "X-Spell-Client-Instance-Key-Id"
        )
    else:
        session = session_id or _READ_SESSION_BINDING
        client = client_key or _READ_CLIENT_BINDING
    return resolver.resolve(
        _http_caller(identity, session, client),
        ResourceFamily.FILES,
        operation,
        owner_id=owner,
        resource_id=root_id,
        acl_revision=_HTTP_DATA_ACL_REVISION,
    )


def _data_authorization(
    resolver: LocalDataPermissionResolver,
    identity: Any,
    family: ResourceFamily,
    operation: str,
    *,
    owner_id: str,
    resource_id: str | None = None,
    acl_revision: int | None = None,
    session_id: str | None = None,
    client_key: str | None = None,
) -> AuthorizationContext:
    mutation = operation not in {
        "ENUMERATE",
        "EXPORT",
        "GET",
        "LIST",
        "LIST_NAMESPACES",
        "READ",
    }
    if mutation:
        session = _printable_ascii_binding(session_id, "X-Spell-Session-Id")
        client = _printable_ascii_binding(
            client_key, "X-Spell-Client-Instance-Key-Id"
        )
    else:
        session = session_id or _READ_SESSION_BINDING
        client = client_key or _READ_CLIENT_BINDING
    return resolver.resolve(
        _http_caller(identity, session, client),
        family,
        operation,
        owner_id=owner_id,
        resource_id=resource_id,
        acl_revision=acl_revision,
    )


def _repository_for(request: Request, configured: Any | None) -> Any:
    repository = configured or getattr(request.app.state, "data_repository", None)
    if repository is None:
        raise VirtualFileError("INTERNAL", "data repository is unavailable")
    return repository


def _required_content_digest(value: str | None) -> str:
    if value is None or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise VirtualFileError(
            "REJECTED", "Content-SHA256 must be a lowercase SHA-256 digest"
        )
    return value


class _DictionaryImportDeadline:
    def __init__(self, monotonic: Callable[[], float]) -> None:
        if not callable(monotonic):
            raise VirtualFileError("INTERNAL", "monotonic clock is unavailable")
        self._monotonic = monotonic
        started = self._now()
        self._deadline = started + _DICTIONARY_IMPORT_DURATION_SECONDS

    def _now(self) -> float:
        current = self._monotonic()
        if (
            isinstance(current, bool)
            or not isinstance(current, (int, float))
            or not math.isfinite(float(current))
        ):
            raise VirtualFileError("INTERNAL", "monotonic clock is invalid")
        return float(current)

    def check(self) -> None:
        if self._now() >= self._deadline:
            raise DictionaryExchangeError(
                "LIMIT_EXCEEDED",
                "dictionary import exceeded its 60 second duration limit",
            )

    def remaining_seconds(self) -> float:
        remaining = self._deadline - self._now()
        if remaining <= 0:
            raise DictionaryExchangeError(
                "LIMIT_EXCEEDED",
                "dictionary import exceeded its 60 second duration limit",
            )
        return remaining


async def _bounded_raw_body(
    request: Request,
    *,
    maximum: int,
    expected_sha256: str,
    files: VirtualFileService,
    deadline: _DictionaryImportDeadline | None = None,
) -> bytes:
    declared = _declared_length(request, maximum)
    staged = files.prepare_quarantined_upload(maximum)
    try:
        if deadline is not None:
            deadline.check()

        async def receive() -> None:
            async for chunk in request.stream():
                staged.write(bytes(chunk))
                if deadline is not None:
                    deadline.check()

        try:
            if deadline is None:
                await receive()
            else:
                async with asyncio.timeout(deadline.remaining_seconds()):
                    await receive()
        except TimeoutError as exc:
            raise DictionaryExchangeError(
                "LIMIT_EXCEEDED",
                "dictionary import exceeded its 60 second duration limit",
            ) from exc
        if deadline is not None:
            deadline.check()
        payload = staged.read_verified(
            declared_length=declared, content_sha256=expected_sha256
        )
        if deadline is not None:
            deadline.check()
        return payload
    finally:
        staged.abort()


def _json_size_guard(payload: Any) -> Response:
    encoded = canonical_json_bytes(_wire_contract_integers(payload))
    if len(encoded) > MAXIMUM_JSON_BYTES:
        raise VirtualFileError("LIMIT_EXCEEDED", "JSON response exceeds its byte limit")
    return Response(content=encoded, media_type="application/json")


def install_data_api(
    app: Any,
    *,
    files: VirtualFileService,
    repository: Any | None,
    identity_dependency: Callable[..., Any],
    permission_resolver: LocalDataPermissionResolver,
) -> APIRouter:
    """Install the closed data routes using the application's JWT dependency."""

    router = APIRouter(prefix="/api/v1/data", tags=["data-v08"])

    def data_authorization(*args: Any, **kwargs: Any) -> AuthorizationContext:
        return _data_authorization(permission_resolver, *args, **kwargs)

    def file_authorization(*args: Any, **kwargs: Any) -> AuthorizationContext:
        return _file_authorization(permission_resolver, *args, **kwargs)

    @router.get("/catalogs")
    async def list_catalogs(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        page_size: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
        cursor: str | None = Query(default=None, max_length=4096),
    ):
        authorization = data_authorization(
            identity, ResourceFamily.CATALOGS, "LIST", owner_id=owner_id
        )
        repository_value = _repository_for(request, repository)
        if not hasattr(repository_value, "list_catalogs"):
            raise VirtualFileError("INTERNAL", "catalog listing is unavailable")
        return _json_size_guard(
            repository_value.list_catalogs(
                authorization,
                owner_id=owner_id,
                page_size=page_size,
                cursor=cursor,
            )
        )

    @router.get("/catalogs/{catalog_id}/revisions/{revision}")
    async def read_catalog_revision(
        request: Request,
        catalog_id: str,
        revision: WirePositiveRevision,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CATALOGS,
            "READ",
            owner_id=owner_id,
            resource_id=catalog_id,
            acl_revision=acl_revision,
        )
        repository_value = _repository_for(request, repository)
        if not hasattr(repository_value, "read_catalog_revision"):
            raise VirtualFileError("INTERNAL", "catalog revision reads are unavailable")
        result = repository_value.read_catalog_revision(
            authorization,
            owner_id=owner_id,
            catalog_id=catalog_id,
            revision=revision,
            acl_revision=acl_revision,
        )
        result["content"] = _wire_contract_integers(result["content"])
        return _json_size_guard(result)

    @router.get("/catalogs/entries/by-uri")
    async def read_catalog_entry(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        catalog_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        uri: str = Query(..., max_length=2048),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CATALOGS,
            "READ",
            owner_id=owner_id,
            resource_id=catalog_id,
            acl_revision=acl_revision,
        )
        if _catalog_id_from_uri(uri) != catalog_id:
            raise VirtualFileError("REJECTED", "catalog URI identity differs")
        return _json_size_guard(
            _repository_for(request, repository).read_catalog_entry(
                authorization,
                owner_id=owner_id,
                acl_revision=acl_revision,
                uri=uri,
            )
        )

    @router.post("/catalogs/{catalog_id}/revisions")
    async def publish_catalog(
        request: Request,
        catalog_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CATALOGS,
            "PUBLISH",
            owner_id=owner_id,
            resource_id=catalog_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, CatalogPublishRequest)
        entries = tuple(
            CatalogEntryDefinition(item.entry_id, item.qualified_name, item.content)
            for item in body.entries
        )
        dependencies = tuple(
            CatalogDependencyDefinition(
                item.dependency_id,
                item.target_catalog_id,
                item.target_revision,
                item.target_content_digest,
                DependencyRelationship(item.relationship),
            )
            for item in body.dependencies
        )
        target_permissions = tuple(
            permission_resolver.resolve(
                authorization.caller,
                ResourceFamily.CATALOGS,
                "READ",
                owner_id=owner_id,
                resource_id=target_catalog_id,
                acl_revision=acl_revision,
            ).permissions[0]
            for target_catalog_id in DataRepository.catalog_dependency_target_ids(
                dependencies
            )
        )
        authorization = AuthorizationContext(
            authorization.caller,
            authorization.permissions + target_permissions,
            authorization.scope_profile,
        )
        result = _repository_for(request, repository).publish_catalog(
            authorization,
            owner_id=owner_id,
            catalog_id=catalog_id,
            kind=CatalogKind(body.kind),
            schema_version=body.schema_version,
            acl_revision=acl_revision,
            expected_revision=body.expected_revision,
            idempotency_key=key,
            entries=entries,
            dependencies=dependencies,
        )
        return _json_size_guard(result)

    @router.get("/dictionaries")
    async def list_dictionaries(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        page_size: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
        cursor: str | None = Query(default=None, max_length=4096),
    ):
        authorization = data_authorization(
            identity, ResourceFamily.DICTIONARIES, "LIST", owner_id=owner_id
        )
        return _json_size_guard(
            _repository_for(request, repository).list_dictionaries(
                authorization,
                owner_id=owner_id,
                page_size=page_size,
                cursor=cursor,
            )
        )

    @router.post("/dictionaries/{dictionary_id}/imports")
    async def import_dictionary(
        request: Request,
        dictionary_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        expected_revision: WireRevision = Query(...),
        content_sha256: str | None = Header(default=None, alias="Content-SHA256"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        deadline = _DictionaryImportDeadline(
            getattr(request.app.state, "data_import_monotonic", time.monotonic)
        )
        authorization = data_authorization(
            identity,
            ResourceFamily.DICTIONARIES,
            "IMPORT",
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        media_type = _media_type(request)
        if media_type not in DICTIONARY_IMPORT_MEDIA_TYPES:
            raise DictionaryExchangeError(
                "FORMAT_UNSUPPORTED", "dictionary media type is unsupported"
            )
        expected_digest = _required_content_digest(content_sha256)
        source = await _bounded_raw_body(
            request,
            maximum=MAXIMUM_IMPORT_BYTES,
            expected_sha256=expected_digest,
            files=files,
            deadline=deadline,
        )
        deadline.check()
        document = parse_dictionary_document(source, media_type=media_type)
        deadline.check()
        if document.dictionary_id != dictionary_id:
            raise DictionaryExchangeError(
                "CORRUPT_DOCUMENT", "document dictionary identity differs"
            )
        if document.base_revision != expected_revision:
            raise DictionaryExchangeError(
                "REVISION_CONFLICT", "document base revision differs"
            )
        repository_value = _repository_for(request, repository)
        if expected_revision == 0:
            result = repository_value.create_dictionary(
                authorization,
                owner_id=owner_id,
                dictionary_id=dictionary_id,
                acl_revision=acl_revision,
                idempotency_key=key,
                document=document,
                deadline_check=deadline.check,
            )
        else:
            result = repository_value.load_dictionary(
                authorization,
                owner_id=owner_id,
                dictionary_id=dictionary_id,
                acl_revision=acl_revision,
                expected_revision=expected_revision,
                idempotency_key=key,
                document=document,
                deadline_check=deadline.check,
            )
        return _json_size_guard(result)

    @router.get("/dictionaries/{dictionary_id}/revisions/{revision}/exports")
    async def export_dictionary(
        request: Request,
        dictionary_id: str,
        revision: WirePositiveRevision,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        format: str = Query(..., pattern="^DB$"),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.DICTIONARIES,
            "EXPORT",
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=acl_revision,
        )
        payload = _repository_for(request, repository).export_dictionary(
            authorization,
            owner_id=owner_id,
            dictionary_id=dictionary_id,
            acl_revision=acl_revision,
            revision=revision,
        )

        async def dictionary_content() -> AsyncIterator[bytes]:
            for offset in range(0, len(payload), 64 * 1024):
                yield payload[offset : offset + 64 * 1024]

        return StreamingResponse(
            dictionary_content(),
            media_type=DB_MEDIA_TYPE,
            headers={
                "Content-Length": str(len(payload)),
                "Content-SHA256": hashlib.sha256(payload).hexdigest(),
                "X-Spell-Revision": str(revision),
            },
        )

    @router.get("/containers")
    async def list_containers(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        page_size: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
        cursor: str | None = Query(default=None, max_length=4096),
    ):
        authorization = data_authorization(
            identity, ResourceFamily.CONTAINERS, "READ", owner_id=owner_id
        )
        repository_value = _repository_for(request, repository)
        if not hasattr(repository_value, "list_containers"):
            raise VirtualFileError("INTERNAL", "container listing is unavailable")
        return _json_size_guard(
            repository_value.list_containers(
                authorization,
                owner_id=owner_id,
                page_size=page_size,
                cursor=cursor,
            )
        )

    @router.post("/containers")
    async def create_container(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        container_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CONTAINERS,
            "CREATE",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, ContainerCreateRequest)
        if body.expected_revision != 0:
            raise VirtualFileError(
                "REVISION_CONFLICT", "container creation requires expected revision zero"
            )
        return _json_size_guard(
            _repository_for(request, repository).create_container(
                authorization,
                owner_id=owner_id,
                container_id=container_id,
                schema_revision=body.schema_revision,
                acl_revision=acl_revision,
                idempotency_key=key,
            )
        )

    @router.get("/containers/{container_id}")
    async def read_container(
        request: Request,
        container_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CONTAINERS,
            "READ",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
        )
        return _json_size_guard(
            _repository_for(request, repository).read_container(
                authorization,
                owner_id=owner_id,
                container_id=container_id,
                acl_revision=acl_revision,
            )
        )

    @router.get("/containers/{container_id}/variables")
    async def enumerate_container(
        request: Request,
        container_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        page_size: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
        cursor: str | None = Query(default=None, max_length=4096),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CONTAINERS,
            "ENUMERATE",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
        )
        return _json_size_guard(
            _repository_for(request, repository).enumerate_container(
                authorization,
                owner_id=owner_id,
                container_id=container_id,
                acl_revision=acl_revision,
                page_size=page_size,
                cursor=cursor,
            )
        )

    @router.put("/containers/{container_id}/variables/{variable_id}")
    async def set_container_variable(
        request: Request,
        container_id: str,
        variable_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CONTAINERS,
            "SET",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, ContainerSetRequest)
        variable = ContainerVariableDefinition(
            variable_id,
            body.name,
            body.declared_type,
            body.value,
        )
        return _json_size_guard(
            _repository_for(request, repository).set_container_variable(
                authorization,
                owner_id=owner_id,
                container_id=container_id,
                acl_revision=acl_revision,
                expected_revision=body.expected_revision,
                expected_variable_revision=body.expected_variable_revision,
                idempotency_key=key,
                variable=variable,
            )
        )

    @router.delete("/containers/{container_id}/variables/{variable_id}")
    async def delete_container_variable(
        request: Request,
        container_id: str,
        variable_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.CONTAINERS,
            "DELETE",
            owner_id=owner_id,
            resource_id=container_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, ContainerDeleteRequest)
        return _json_size_guard(
            _repository_for(request, repository).delete_container_variable(
                authorization,
                owner_id=owner_id,
                container_id=container_id,
                acl_revision=acl_revision,
                expected_revision=body.expected_revision,
                variable_id=variable_id,
                expected_variable_revision=body.expected_variable_revision,
                idempotency_key=key,
            )
        )

    @router.get("/shared/namespaces")
    async def list_shared_namespaces(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        page_size: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
        cursor: str | None = Query(default=None, max_length=4096),
    ):
        authorization = data_authorization(
            identity, ResourceFamily.SHARED, "LIST_NAMESPACES", owner_id=owner_id
        )
        return _json_size_guard(
            _repository_for(request, repository).list_shared_namespaces(
                authorization,
                owner_id=owner_id,
                page_size=page_size,
                cursor=cursor,
            )
        )

    @router.post("/shared/namespaces")
    async def create_shared_namespace(
        request: Request,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        namespace_id: str = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "CREATE_NAMESPACE",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, NamespaceCreateRequest)
        scope = SharedScope(body.scope)
        _require_public_shared_scope(scope)
        if body.expected_revision != 0:
            raise VirtualFileError(
                "REVISION_CONFLICT", "namespace creation requires expected revision zero"
            )
        return _json_size_guard(
            _repository_for(request, repository).create_shared_namespace(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                scope=scope,
                acl_revision=acl_revision,
                idempotency_key=key,
            )
        )

    @router.get("/shared/namespaces/{namespace_id}")
    async def read_shared_namespace(
        request: Request,
        namespace_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "GET",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        repository_value = _repository_for(request, repository)
        if not hasattr(repository_value, "read_shared_namespace"):
            raise VirtualFileError("INTERNAL", "shared namespace reads are unavailable")
        return _json_size_guard(
            repository_value.read_shared_namespace(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                scope=scope,
            )
        )

    @router.get("/shared/namespaces/{namespace_id}/entries")
    async def enumerate_shared_entries(
        request: Request,
        namespace_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        page_size: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
        cursor: str | None = Query(default=None, max_length=4096),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "ENUMERATE",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        return _json_size_guard(
            _repository_for(request, repository).enumerate_shared_namespace(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                page_size=page_size,
                cursor=cursor,
                scope=scope,
            )
        )

    @router.get("/shared/namespaces/{namespace_id}/entries/{key:path}")
    async def get_shared_entry(
        request: Request,
        namespace_id: str,
        key: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "GET",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
        )
        return _json_size_guard(
            _repository_for(request, repository).get_shared_entry(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                key=key,
                scope=scope,
            )
        )

    @router.put("/shared/namespaces/{namespace_id}/entries/{key:path}")
    async def put_shared_entry(
        request: Request,
        namespace_id: str,
        key: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "PUT",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        idempotency = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, SharedPutRequest)
        return _json_size_guard(
            _repository_for(request, repository).put_shared_entry(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                expected_revision=body.expected_namespace_revision,
                key=key,
                expected_entry_revision=body.expected_entry_revision,
                idempotency_key=idempotency,
                value=body.value,
                scope=scope,
            )
        )

    @router.delete("/shared/namespaces/{namespace_id}/entries/{key:path}")
    async def delete_shared_entry(
        request: Request,
        namespace_id: str,
        key: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "DELETE",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        idempotency = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, SharedDeleteRequest)
        return _json_size_guard(
            _repository_for(request, repository).delete_shared_entry(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                expected_revision=body.expected_namespace_revision,
                key=key,
                expected_entry_revision=body.expected_entry_revision,
                idempotency_key=idempotency,
                scope=scope,
            )
        )

    @router.post("/shared/namespaces/{namespace_id}/clear")
    async def clear_shared_namespace(
        request: Request,
        namespace_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "CLEAR",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        idempotency = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, SharedClearRequest)
        return _json_size_guard(
            _repository_for(request, repository).clear_shared_namespace(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                expected_revision=body.expected_namespace_revision,
                maximum_affected_entries=body.maximum_affected_entries,
                idempotency_key=idempotency,
                scope=scope,
            )
        )

    @router.delete("/shared/namespaces/{namespace_id}")
    async def delete_shared_namespace(
        request: Request,
        namespace_id: str,
        identity: Any = Depends(identity_dependency),
        owner_id: str = Query(...),
        scope: SharedScope = Query(...),
        acl_revision: WirePositiveRevision = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        _require_public_shared_scope(scope)
        authorization = data_authorization(
            identity,
            ResourceFamily.SHARED,
            "DELETE_NAMESPACE",
            owner_id=owner_id,
            resource_id=namespace_id,
            acl_revision=acl_revision,
            session_id=session_id,
            client_key=client_key,
        )
        idempotency = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, NamespaceDeleteRequest)
        return _json_size_guard(
            _repository_for(request, repository).delete_shared_namespace(
                authorization,
                owner_id=owner_id,
                namespace_id=namespace_id,
                acl_revision=acl_revision,
                expected_revision=body.expected_namespace_revision,
                idempotency_key=idempotency,
                scope=scope,
            )
        )

    @router.get("/files/{root_id}/content")
    async def read_file(
        root_id: str,
        identity: Any = Depends(identity_dependency),
        virtual_path: str = Query(..., min_length=1),
        revision: WirePositiveRevision | None = Query(default=None),
    ):
        authorization = file_authorization(identity, root_id, "READ")
        result = files.read_file(
            authorization, root_id, virtual_path, revision=revision
        )
        payload = result.pop("content")

        async def content() -> AsyncIterator[bytes]:
            for offset in range(0, len(payload), 64 * 1024):
                yield payload[offset : offset + 64 * 1024]

        return StreamingResponse(
            content(),
            media_type="application/octet-stream",
            headers={
                "Content-Length": str(len(payload)),
                "Content-SHA256": str(result["content_sha256"]),
                "X-Spell-Encoding": str(result["encoding"]),
                "X-Spell-Revision": str(result["revision"]),
            },
        )

    @router.get("/files/{root_id}/directory")
    async def list_directory(
        root_id: str,
        identity: Any = Depends(identity_dependency),
        virtual_path: str = Query(default=""),
        cursor: str | None = Query(default=None, max_length=4096),
        limit: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
    ):
        authorization = file_authorization(identity, root_id, "LIST")
        return _json_size_guard(
            files.list_directory(
                authorization,
                root_id,
                virtual_path,
                cursor=cursor,
                limit=limit,
            )
        )

    @router.post("/files/{root_id}/directories")
    async def create_directory(
        request: Request,
        root_id: str,
        identity: Any = Depends(identity_dependency),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = file_authorization(
            identity,
            root_id,
            "CREATE_DIRECTORY",
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, DirectoryCreateRequest)
        virtual_path = validate_virtual_path(body.virtual_path)
        digest = _request_digest(
            "POST",
            f"FILES:{root_id}:{hashlib.sha256(virtual_path.encode('utf-8')).hexdigest()}",
            body.expected_revision,
            _semantic_body_digest(
                {
                    "expected_revision": body.expected_revision,
                    "virtual_path": virtual_path,
                }
            ),
        )
        result = files.create_directory(
            authorization,
            root_id,
            virtual_path,
            expected_revision=body.expected_revision,
            idempotency_key=key,
            request_digest=digest,
        )
        return _json_size_guard(result)

    @router.put("/files/{root_id}/content")
    async def write_file(
        request: Request,
        root_id: str,
        identity: Any = Depends(identity_dependency),
        virtual_path: str = Query(..., min_length=1),
        expected_revision: WireRevision = Query(...),
        encoding: str = Query(..., pattern="^(UTF8_TEXT|BINARY)$"),
        content_sha256: str | None = Header(default=None, alias="Content-SHA256"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = file_authorization(
            identity,
            root_id,
            "WRITE",
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        if _media_type(request) != "application/octet-stream":
            raise VirtualFileError(
                "REJECTED", "Content-Type must be exactly application/octet-stream"
            )
        declared = _declared_length(request, MAXIMUM_FILE_BYTES)
        if content_sha256 is None or len(content_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in content_sha256
        ):
            raise VirtualFileError(
                "REJECTED", "Content-SHA256 must be a lowercase SHA-256 digest"
            )
        normalized_path = validate_virtual_path(virtual_path)
        digest = _request_digest(
            "PUT",
            f"FILES:{root_id}:{hashlib.sha256(normalized_path.encode('utf-8')).hexdigest()}",
            expected_revision,
            _semantic_body_digest(
                {
                    "content_sha256": content_sha256,
                    "declared_length": declared,
                    "encoding": encoding,
                    "expected_revision": expected_revision,
                    "virtual_path": normalized_path,
                }
            ),
        )
        prepared = files.prepare_write(
            authorization,
            root_id,
            normalized_path,
            expected_revision=expected_revision,
            encoding=encoding,
            idempotency_key=key,
            request_digest=digest,
            declared_length=declared,
            content_sha256=content_sha256,
        )
        if isinstance(prepared, dict):
            observed = hashlib.sha256()
            received = 0
            async for chunk in request.stream():
                received += len(chunk)
                if received > MAXIMUM_FILE_BYTES:
                    raise VirtualFileError("LIMIT_EXCEEDED", "file exceeds its byte limit")
                observed.update(chunk)
            if received != declared or observed.hexdigest() != content_sha256:
                raise VirtualFileError("REJECTED", "replayed file body differs")
            return _json_size_guard(prepared)
        try:
            observed = hashlib.sha256()
            async for chunk in request.stream():
                prepared.write(bytes(chunk))
                observed.update(chunk)
            if prepared.bytes_written != declared:
                raise VirtualFileError(
                    "REJECTED", "request body length differs from Content-Length"
                )
            if observed.hexdigest() != content_sha256:
                raise VirtualFileError("REJECTED", "file content digest differs")
            result = files.commit_write(
                authorization,
                prepared,
                declared_length=declared,
                content_sha256=content_sha256,
            )
        except Exception:
            prepared.abort()
            raise
        return _json_size_guard(result)

    @router.delete("/files/{root_id}/nodes")
    async def delete_file(
        request: Request,
        root_id: str,
        identity: Any = Depends(identity_dependency),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        authorization = file_authorization(
            identity,
            root_id,
            "DELETE",
            session_id=session_id,
            client_key=client_key,
        )
        key = _idempotency_key(idempotency_key)
        body, _ = await _strict_json_body(request, FileDeleteRequest)
        virtual_path = validate_virtual_path(body.virtual_path)
        digest = _request_digest(
            "DELETE",
            f"FILES:{root_id}:{hashlib.sha256(virtual_path.encode('utf-8')).hexdigest()}",
            body.expected_revision,
            _semantic_body_digest(
                {
                    "expected_revision": body.expected_revision,
                    "virtual_path": virtual_path,
                }
            ),
        )
        result = files.delete_node(
            authorization,
            root_id,
            virtual_path,
            expected_revision=body.expected_revision,
            idempotency_key=key,
            request_digest=digest,
        )
        return _json_size_guard(result)

    @router.get("/files")
    async def read_file_at_family_path(
        identity: Any = Depends(identity_dependency),
        root_id: str = Query(...),
        virtual_path: str = Query(..., min_length=1),
        revision: WirePositiveRevision | None = Query(default=None),
    ):
        return await read_file(
            identity=identity,
            root_id=root_id,
            virtual_path=virtual_path,
            revision=revision,
        )

    @router.get("/files/directory")
    async def list_directory_at_family_path(
        identity: Any = Depends(identity_dependency),
        root_id: str = Query(...),
        virtual_path: str = Query(default=""),
        cursor: str | None = Query(default=None, max_length=4096),
        limit: int = Query(default=MAXIMUM_PAGE_SIZE, ge=1, le=MAXIMUM_PAGE_SIZE),
    ):
        return await list_directory(
            identity=identity,
            root_id=root_id,
            virtual_path=virtual_path,
            cursor=cursor,
            limit=limit,
        )

    @router.post("/files/directory")
    async def create_directory_at_family_path(
        request: Request,
        identity: Any = Depends(identity_dependency),
        root_id: str = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        return await create_directory(
            request=request,
            identity=identity,
            root_id=root_id,
            idempotency_key=idempotency_key,
            session_id=session_id,
            client_key=client_key,
        )

    @router.put("/files")
    async def write_file_at_family_path(
        request: Request,
        identity: Any = Depends(identity_dependency),
        root_id: str = Query(...),
        virtual_path: str = Query(..., min_length=1),
        expected_revision: WireRevision = Query(...),
        encoding: str = Query(..., pattern="^(UTF8_TEXT|BINARY)$"),
        content_sha256: str | None = Header(default=None, alias="Content-SHA256"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        return await write_file(
            request=request,
            identity=identity,
            root_id=root_id,
            virtual_path=virtual_path,
            expected_revision=expected_revision,
            encoding=encoding,
            content_sha256=content_sha256,
            idempotency_key=idempotency_key,
            session_id=session_id,
            client_key=client_key,
        )

    @router.delete("/files")
    async def delete_file_at_family_path(
        request: Request,
        identity: Any = Depends(identity_dependency),
        root_id: str = Query(...),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        session_id: str | None = Header(default=None, alias="X-Spell-Session-Id"),
        client_key: str | None = Header(
            default=None, alias="X-Spell-Client-Instance-Key-Id"
        ),
    ):
        return await delete_file(
            request=request,
            identity=identity,
            root_id=root_id,
            idempotency_key=idempotency_key,
            session_id=session_id,
            client_key=client_key,
        )

    async def virtual_file_error_handler(_request: Request, error: VirtualFileError):
        return _error_response(error)

    async def data_domain_error_handler(_request: Request, error: DataDomainError):
        return _error_response(error)

    app.add_exception_handler(VirtualFileError, virtual_file_error_handler)
    app.add_exception_handler(DataDomainError, data_domain_error_handler)
    app.include_router(router)
    return router


__all__ = ["install_data_api"]
