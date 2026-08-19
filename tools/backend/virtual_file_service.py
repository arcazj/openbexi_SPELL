"""Bounded virtual files and execution-scoped file handles for SPELL v0.8."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .data_domain import (
    AuthorizationContext,
    DataAuthorizationError,
    DataCapacityError,
    DataConflictError,
    DataDomainError,
    DataNotFoundError,
    DataPermission,
    DataValidationError,
    HTTPCallerBinding,
    ProcedureCallerBinding,
    ResourceFamily,
    caller_binding_digest,
    caller_binding_payload,
    canonical_json_bytes,
    require_identifier,
)
from .data_models import canonical_virtual_root_configuration_bytes
from .dictionary_exchange import (
    DB_MEDIA_TYPE,
    IMP_MEDIA_TYPE,
    parse_dictionary_document,
)
from .ir_v08 import V08ValidationError, validate_file_handle_reference
from .secure_filesystem import (
    OwnedDirectory,
    SecureFilesystemError,
    entry_kind,
    file_identity,
    fsync_directory,
    list_names,
    move_entry,
    open_child_directory,
    open_owned_directory,
    open_regular_file,
    read_regular_file,
    read_stream,
    regular_file_exists,
    rename_open_file,
    unlink_entry,
    unlink_regular_file,
)


MAXIMUM_FILE_BYTES = 16_777_216
MAXIMUM_ROOT_BYTES = 268_435_456
MAXIMUM_ROOT_NODES = 10_000
MAXIMUM_PATH_BYTES = 1_024
MAXIMUM_SEGMENT_BYTES = 255
MAXIMUM_PATH_DEPTH = 32
MAXIMUM_LIST_PAGE = 256
MAXIMUM_OPEN_HANDLES = 32
MAXIMUM_HANDLE_IDLE_SECONDS = 900
ROOT_IDS = frozenset({"PROCEDURE_DATA", "PROJECT_DATA", "EXECUTION_SCRATCH"})
FILE_ENCODINGS = frozenset({"UTF8_TEXT", "BINARY"})
HANDLE_MODES = frozenset({"READ", "WRITE", "READ_WRITE", "APPEND"})

_RESERVED_DEVICE = re.compile(
    r"(?i)(?:CON|PRN|AUX|NUL|CLOCK\$|COM[1-9]|LPT[1-9])(?:\..*)?\Z"
)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_INTERNAL_PREFIXES = (
    ".spell-control",
    ".spell-handle-",
    ".spell-objects",
    ".spell-quarantine",
    ".spell-write-",
)


class VirtualFileError(ValueError):
    """A safe, stable virtual-file failure suitable for an API outcome."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        current_revision: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.current_revision = current_revision


@dataclass(frozen=True, slots=True)
class FileValue:
    root_id: str
    virtual_path: str

    def __post_init__(self) -> None:
        require_identifier(self.root_id, "root_id")
        validate_virtual_path(self.virtual_path)

    def as_dict(self) -> dict[str, str]:
        return {"root_id": self.root_id, "virtual_path": self.virtual_path}

    def to_opaque_string(self) -> str:
        payload = canonical_json_bytes(self.as_dict())
        return "spell-file-v1." + base64.urlsafe_b64encode(payload).rstrip(b"=").decode(
            "ascii"
        )

    @classmethod
    def from_opaque_string(cls, value: Any) -> "FileValue":
        if type(value) is not str or not value.startswith("spell-file-v1."):
            raise VirtualFileError("REJECTED", "File value is invalid")
        token = value.removeprefix("spell-file-v1.")
        if not token or len(token) > 2048:
            raise VirtualFileError("REJECTED", "File value is invalid")
        try:
            raw = base64.b64decode(
                token.encode("ascii") + b"=" * (-len(token) % 4),
                altchars=b"-_",
                validate=True,
            )
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise VirtualFileError("REJECTED", "File value is invalid") from exc
        if type(payload) is not dict or set(payload) != {"root_id", "virtual_path"}:
            raise VirtualFileError("REJECTED", "File value is invalid")
        result = cls(payload["root_id"], payload["virtual_path"])
        if result.to_opaque_string() != value:
            raise VirtualFileError("REJECTED", "File value is not canonical")
        return result


@dataclass(frozen=True, slots=True)
class RootSpec:
    root_id: str
    owner_id: str
    directory_name: str
    acl_revision: int = 1

    def __post_init__(self) -> None:
        if self.root_id not in ROOT_IDS:
            raise DataValidationError("virtual root identity is not allowlisted")
        require_identifier(self.owner_id, "owner_id")
        require_identifier(self.directory_name, "directory_name")
        if type(self.acl_revision) is not int or self.acl_revision < 1:
            raise DataValidationError("root ACL revision must be positive")


@dataclass(frozen=True, slots=True)
class _Root:
    root_id: str
    owner_id: str
    path: Path
    acl_revision: int


@dataclass(slots=True)
class PreparedWrite:
    root: _Root
    virtual_path: str
    expected_revision: int
    encoding: str
    caller_digest: str
    idempotency_key: str
    request_digest: str
    declared_length: int
    content_sha256: str
    reservation_id: str
    temporary_path: Path
    temporary_name: str
    _file: Any = field(repr=False)
    _discard_file: Callable[[], None] = field(repr=False)
    _release_reservation: Callable[[str], None] = field(repr=False)
    bytes_written: int = 0
    _closed: bool = False
    _finished: bool = False
    _reservation_open: bool = True

    def write(self, chunk: bytes) -> None:
        if self._closed or self._finished:
            raise VirtualFileError("REJECTED", "write stage is already closed")
        if type(chunk) is not bytes:
            raise VirtualFileError("REJECTED", "file content chunk must be bytes")
        if self.bytes_written + len(chunk) > self.declared_length:
            raise VirtualFileError("LIMIT_EXCEEDED", "file exceeds its reserved length")
        self._file.write(chunk)
        self.bytes_written += len(chunk)

    def finish(self) -> None:
        if self._closed or self._finished:
            return
        self._file.flush()
        os.fsync(self._file.fileno())
        self._finished = True

    def abort(self) -> None:
        try:
            if not self._closed:
                self._file.close()
                self._closed = True
            self._discard_file()
        finally:
            if self._reservation_open:
                self._release_reservation(self.reservation_id)
                self._reservation_open = False


@dataclass(slots=True)
class QuarantinedUpload:
    temporary_path: Path
    temporary_name: str
    maximum_bytes: int
    _file: Any = field(repr=False)
    _discard_file: Callable[[], None] = field(repr=False)
    bytes_written: int = 0
    _closed: bool = False

    def write(self, chunk: bytes) -> None:
        if self._closed or type(chunk) is not bytes:
            raise VirtualFileError("REJECTED", "quarantine upload chunk is invalid")
        if self.bytes_written + len(chunk) > self.maximum_bytes:
            raise VirtualFileError("LIMIT_EXCEEDED", "request body exceeds its byte limit")
        self._file.write(chunk)
        self.bytes_written += len(chunk)

    def read_verified(self, *, declared_length: int, content_sha256: str) -> bytes:
        if not self._closed:
            self._file.flush()
            os.fsync(self._file.fileno())
        if self.bytes_written != declared_length:
            raise VirtualFileError(
                "REJECTED", "request body length differs from Content-Length"
            )
        payload = read_stream(self._file)
        if hashlib.sha256(payload).hexdigest() != content_sha256:
            raise VirtualFileError("REJECTED", "request body digest differs")
        return payload

    def abort(self) -> None:
        if not self._closed:
            self._file.close()
            self._closed = True
        self._discard_file()


@dataclass(slots=True)
class _Handle:
    token_digest: str
    caller_digest: str
    origin_request_id: str | None
    execution_id: str
    root: _Root
    virtual_path: str
    opened_revision: int
    mode: str
    encoding: str
    content_digest: str | None
    cursor: int
    last_access: float
    stage_path: Path | None = None
    stage_name: str | None = None
    stage_stream: Any | None = field(default=None, repr=False)
    reservation_id: str | None = None
    dirty: bool = False


def validate_virtual_path(value: Any, *, allow_root: bool = False) -> str:
    """Validate an already-decoded, NFC, relative virtual path lexically."""

    if type(value) is not str:
        raise VirtualFileError("REJECTED", "virtual path must be a string")
    if value == "":
        if allow_root:
            return value
        raise VirtualFileError("REJECTED", "virtual path must not be empty")
    if value[0] in "/\\" or value.endswith("/"):
        raise VirtualFileError("REJECTED", "virtual path must be relative and canonical")
    if "\\" in value or ":" in value or "\x00" in value:
        raise VirtualFileError("REJECTED", "virtual path contains a forbidden character")
    if _PERCENT_ESCAPE.search(value) is not None:
        raise VirtualFileError("REJECTED", "percent-encoded path segments are forbidden")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise VirtualFileError("REJECTED", "virtual path is not valid UTF-8") from exc
    if len(encoded) > MAXIMUM_PATH_BYTES:
        raise VirtualFileError("LIMIT_EXCEEDED", "virtual path exceeds 1024 UTF-8 bytes")
    segments = value.split("/")
    if len(segments) > MAXIMUM_PATH_DEPTH:
        raise VirtualFileError("LIMIT_EXCEEDED", "virtual path exceeds depth 32")
    for segment in segments:
        if segment in {"", ".", ".."}:
            raise VirtualFileError("REJECTED", "virtual path contains a forbidden segment")
        if unicodedata.normalize("NFC", segment) != segment:
            raise VirtualFileError("REJECTED", "virtual path segments must already be NFC")
        try:
            segment_bytes = segment.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise VirtualFileError("REJECTED", "virtual path segment is not valid UTF-8") from exc
        if len(segment_bytes) > MAXIMUM_SEGMENT_BYTES:
            raise VirtualFileError("LIMIT_EXCEEDED", "virtual path segment exceeds 255 bytes")
        if any(ord(character) < 32 or ord(character) == 127 for character in segment):
            raise VirtualFileError("REJECTED", "control characters are forbidden in paths")
        if segment.endswith((" ", ".")) or _RESERVED_DEVICE.fullmatch(segment):
            raise VirtualFileError("REJECTED", "virtual path uses a reserved host name")
        if segment.startswith(_INTERNAL_PREFIXES):
            raise VirtualFileError("REJECTED", "virtual path uses a server-reserved name")
    return value


def _default_root_specs() -> tuple[RootSpec, ...]:
    return (
        RootSpec("PROCEDURE_DATA", "procedure-library", "procedure-data"),
        RootSpec("PROJECT_DATA", "local-project", "project-data"),
        RootSpec("EXECUTION_SCRATCH", "execution-scratch", "execution-scratch"),
    )


class VirtualFileService:
    """Owns fixed virtual roots without ever exposing their host paths."""

    def __init__(
        self,
        base_directory: Path,
        *,
        root_specs: Iterable[RootSpec] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._base = Path(base_directory).absolute()
        self._control_dir = self._base / ".spell-control"
        self._quarantine_dir = self._base / ".spell-quarantine"
        specs = tuple(root_specs or _default_root_specs())
        if len(specs) != len({item.root_id for item in specs}):
            raise DataValidationError("virtual root specifications contain duplicates")
        if {item.root_id for item in specs} != ROOT_IDS:
            raise DataValidationError("all and only the three fixed virtual roots are required")
        self._specs = {item.root_id: item for item in specs}
        self._clock = monotonic
        self._lock = threading.RLock()
        self._handles: dict[str, _Handle] = {}
        self._prepared_writes: dict[str, PreparedWrite] = {}
        self._cursor_secret = b""
        self._repository: Any | None = None
        self._base_handle: OwnedDirectory | None = None
        self._control_handle: OwnedDirectory | None = None
        self._quarantine_handle: OwnedDirectory | None = None
        self._scratch_handle: OwnedDirectory | None = None
        self._root_handles: dict[str, OwnedDirectory] = {}
        self._object_handles: dict[str, OwnedDirectory] = {}
        self._started = False

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            try:
                self._base_handle = open_owned_directory(self._base, create=True)
                self._control_handle = open_child_directory(
                    self._base_handle, ".spell-control", create=True
                )
                self._quarantine_handle = open_child_directory(
                    self._base_handle, ".spell-quarantine", create=True
                )
                self._scratch_handle = open_child_directory(
                    self._base_handle,
                    self._specs["EXECUTION_SCRATCH"].directory_name,
                    create=True,
                )
                try:
                    secret = read_regular_file(self._control_handle, "cursor.key")
                except FileNotFoundError:
                    secret = secrets.token_bytes(32)
                    with open_regular_file(
                        self._control_handle,
                        "cursor.key",
                        create=True,
                        writable=True,
                    ) as target:
                        target.write(secret)
                        target.flush()
                        os.fsync(target.fileno())
                if len(secret) != 32:
                    raise VirtualFileError("CORRUPT_FILE", "cursor key is corrupt")
                self._cursor_secret = secret
                for root_id in ("PROCEDURE_DATA", "PROJECT_DATA"):
                    root = self._root_from_spec(self._specs[root_id])
                    self._activate_storage_root(root)
                self._started = True
            except VirtualFileError:
                self._close_directory_handles()
                raise
            except (OSError, SecureFilesystemError) as exc:
                self._close_directory_handles()
                raise VirtualFileError(
                    "REJECTED", "virtual root activation failed closed"
                ) from exc

    def attach_repository(self, repository: Any) -> None:
        with self._lock:
            if repository is None or not all(
                hasattr(repository, name)
                for name in (
                    "commit_virtual_file",
                    "create_virtual_directory",
                    "delete_virtual_node",
                    "list_virtual_directory",
                    "provision_virtual_root",
                    "read_virtual_file",
                    "read_virtual_node",
                    "recover_virtual_file_reservations",
                    "referenced_virtual_content_digests",
                    "release_virtual_file_reservation",
                    "reserve_virtual_file",
                )
            ):
                raise DataValidationError("virtual file repository is incomplete")
            self._require_started()
            self._repository = repository
            for root_id in ("PROCEDURE_DATA", "PROJECT_DATA"):
                self._provision_root(self._root_from_spec(self._specs[root_id]))
            self.recover()

    def close(self) -> None:
        with self._lock:
            for prepared in tuple(self._prepared_writes.values()):
                prepared.abort()
            for handle in tuple(self._handles.values()):
                self._discard_handle_stage(handle)
                if handle.reservation_id is not None:
                    self._release_prepared_write(handle.root, handle.reservation_id)
            self._handles.clear()
            self._prepared_writes.clear()
            self._started = False
            self._close_directory_handles()

    @property
    def cursor_secret(self) -> bytes:
        with self._lock:
            self._require_started()
            return bytes(self._cursor_secret)

    def recover(self) -> dict[str, int]:
        with self._lock:
            self._require_started()
            repository = self._require_repository()
            self._repository_call(repository.recover_virtual_file_reservations)
            inventory = repository.referenced_virtual_content_digests()
            referenced: dict[str, set[str]] = {}
            for item in inventory:
                if (
                    type(item) is not tuple
                    or len(item) != 2
                    or type(item[0]) is not str
                    or type(item[1]) is not str
                ):
                    raise VirtualFileError(
                        "CORRUPT_FILE", "virtual content inventory is not root-scoped"
                    )
                storage_root_id, content_digest = item
                self._root_from_storage_id(storage_root_id)
                self._validate_digest(content_digest, "content digest")
                referenced.setdefault(storage_root_id, set()).add(content_digest)
            removed_temporary = 0
            quarantined = 0
            quarantine = self._require_quarantine_handle()
            for name in list_names(quarantine):
                if name.startswith(".spell-import-"):
                    if entry_kind(quarantine, name) != "REGULAR":
                        raise VirtualFileError(
                            "CORRUPT_FILE", "quarantine stage identity is ambiguous"
                        )
                    unlink_regular_file(quarantine, name)
                    removed_temporary += 1
            for root_id in ("PROCEDURE_DATA", "PROJECT_DATA"):
                root = self._root_from_spec(self._specs[root_id])
                result = self._recover_storage_root(
                    root, frozenset(referenced.get(root_id, set()))
                )
                removed_temporary += result[0]
                quarantined += result[1]
            scratch = self._require_scratch_handle()
            for owner in list_names(scratch):
                valid_owner = entry_kind(scratch, owner) == "DIRECTORY"
                if valid_owner:
                    try:
                        require_identifier(owner, "execution_id")
                    except DataValidationError:
                        valid_owner = False
                if not valid_owner:
                    move_entry(
                        scratch,
                        owner,
                        quarantine,
                        f"{uuid.uuid4().hex}-{owner}",
                    )
                    quarantined += 1
                    continue
                root = self._execution_root(owner)
                self._provision_root(root)
                storage_root_id = f"EXECUTION_SCRATCH.{owner}"
                result = self._recover_storage_root(
                    root,
                    frozenset(referenced.get(storage_root_id, set())),
                )
                removed_temporary += result[0]
                quarantined += result[1]
            for storage_root_id, digests in referenced.items():
                root = self._root_from_storage_id(storage_root_id)
                for content_digest in digests:
                    self._read_physical_object(root, content_digest)
            return {
                "removed_temporary": removed_temporary,
                "quarantined_orphans": quarantined,
            }

    def read_physical_content(
        self,
        storage_root_id: str,
        virtual_path: str,
        content_digest: str,
    ) -> bytes:
        """Read one committed object for the database integrity verifier."""

        with self._lock:
            self._require_started()
            root = self._root_from_storage_id(storage_root_id)
            validate_virtual_path(virtual_path)
            self._validate_digest(content_digest, "content digest")
            return self._read_physical_object(root, content_digest)

    def file_value(self, root_id: str, virtual_path: str) -> FileValue:
        if root_id not in ROOT_IDS:
            raise VirtualFileError("NOT_FOUND", "virtual root is unavailable")
        return FileValue(root_id, virtual_path)

    def prepare_quarantined_upload(self, maximum_bytes: int) -> QuarantinedUpload:
        with self._lock:
            self._require_started()
            if type(maximum_bytes) is not int or maximum_bytes < 1:
                raise VirtualFileError("REJECTED", "upload bound is invalid")
            name = f".spell-import-{uuid.uuid4().hex}"
            directory = self._require_quarantine_handle()
            handle = open_regular_file(
                directory,
                name,
                create=True,
                writable=True,
                delete_access=True,
                share_delete=True,
            )
            return QuarantinedUpload(
                directory.path / name,
                name,
                maximum_bytes,
                handle,
                lambda: unlink_entry(directory, name),
            )

    def read_file(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
        *,
        revision: int | None = None,
        length: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            root = self._authorized_root(authorization, root_id, "READ")
            path = validate_virtual_path(virtual_path)
            record = self._repository_call(
                self._require_repository().read_virtual_file,
                authorization,
                owner_id=root.owner_id,
                root_id=root.root_id,
                acl_revision=root.acl_revision,
                virtual_path=path,
                revision=revision,
            )
            try:
                payload = self._read_object(root, record["content_sha256"])
            except FileNotFoundError as exc:
                raise VirtualFileError("CORRUPT_FILE", "file content is missing") from exc
            digest = hashlib.sha256(payload).hexdigest()
            if len(payload) != record["size"] or digest != record["content_sha256"]:
                raise VirtualFileError("CORRUPT_FILE", "file content is corrupt")
            if length is not None:
                if type(length) is not int or length < 0 or length > MAXIMUM_FILE_BYTES:
                    raise VirtualFileError("REJECTED", "read length is invalid")
                payload = payload[:length]
            return {
                "root_id": root.root_id,
                "virtual_path": path,
                "encoding": record["encoding"],
                "content": payload,
                "content_sha256": digest,
                "size": int(record["size"]),
                "revision": int(record["revision"]),
            }

    def list_directory(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str = "",
        *,
        cursor: str | None = None,
        limit: int = MAXIMUM_LIST_PAGE,
    ) -> dict[str, Any]:
        with self._lock:
            root = self._authorized_root(authorization, root_id, "LIST")
            path = validate_virtual_path(virtual_path, allow_root=True)
            if type(limit) is not int or not 1 <= limit <= MAXIMUM_LIST_PAGE:
                raise VirtualFileError("REJECTED", "directory page limit is invalid")
            return self._repository_call(
                self._require_repository().list_virtual_directory,
                authorization,
                owner_id=root.owner_id,
                root_id=root.root_id,
                acl_revision=root.acl_revision,
                virtual_path=path,
                page_size=limit,
                cursor=cursor,
            )

    def file_properties(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
    ) -> dict[str, str | bool]:
        with self._lock:
            root = self._authorized_root(authorization, root_id, "READ")
            path = validate_virtual_path(virtual_path)
            try:
                record = self._repository_call(
                    self._require_repository().read_virtual_node,
                    authorization,
                    owner_id=root.owner_id,
                    root_id=root.root_id,
                    acl_revision=root.acl_revision,
                    virtual_path=path,
                )
            except VirtualFileError as exc:
                if exc.code != "NOT_FOUND":
                    raise
                record = None
            if record is not None and record["kind"] == "FILE":
                try:
                    stream = self._open_object(root, record["content_sha256"])
                except FileNotFoundError:
                    raise VirtualFileError("CORRUPT_FILE", "file content is missing")
                else:
                    stream.close()
            can_write = True
            try:
                authorization.require(
                    ResourceFamily.FILES,
                    "WRITE",
                    owner_id=root.owner_id,
                    resource_id=root.root_id,
                    acl_revision=root.acl_revision,
                )
            except DataAuthorizationError:
                can_write = False
            caller_digest = self._handle_caller_digest(authorization)
            execution_id = getattr(authorization.caller, "execution_id", None)
            cutoff = self._clock() - MAXIMUM_HANDLE_IDLE_SECONDS
            is_open = any(
                handle.caller_digest == caller_digest
                and handle.execution_id == execution_id
                and handle.root.root_id == root.root_id
                and handle.root.owner_id == root.owner_id
                and handle.virtual_path == path
                and handle.last_access > cutoff
                for handle in self._handles.values()
            )
            basename = path.rsplit("/", 1)[-1]
            return {
                "filename": path,
                "dirname": path.rpartition("/")[0],
                "basename": basename,
                "exists": record is not None,
                "isdir": record is not None and record.get("kind") == "DIRECTORY",
                "isfile": record is not None and record.get("kind") == "FILE",
                "isOpen": is_open,
                "canRead": True,
                "canWrite": can_write,
            }

    def handle_properties(
        self,
        authorization: AuthorizationContext,
        token: str,
        *,
        execution_id: str,
    ) -> dict[str, str | bool]:
        if type(token) is not str:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")
        try:
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale") from exc
        return self.handle_properties_digest(
            authorization, digest, execution_id=execution_id
        )

    def handle_properties_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        *,
        execution_id: str,
    ) -> dict[str, str | bool]:
        with self._lock:
            handle = self._bound_handle_digest(
                authorization, token_digest, execution_id
            )
            properties = self.file_properties(
                authorization, handle.root.root_id, handle.virtual_path
            )
            properties["isOpen"] = True
            return properties

    def create_directory(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        request_digest: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            root = self._authorized_root(authorization, root_id, "CREATE_DIRECTORY")
            path = validate_virtual_path(virtual_path)
            self._validate_expected_revision(expected_revision)
            self._validate_idempotency_key(idempotency_key)
            digest = request_digest or self._request_digest(
                "CREATE_DIRECTORY", root, path, expected_revision, b""
            )
            return self._repository_call(
                self._require_repository().create_virtual_directory,
                authorization,
                owner_id=root.owner_id,
                root_id=root.root_id,
                acl_revision=root.acl_revision,
                virtual_path=path,
                expected_parent_revision=expected_revision,
                idempotency_key=idempotency_key,
                request_digest=digest,
            )

    def prepare_write(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
        *,
        expected_revision: int,
        encoding: str,
        idempotency_key: str,
        request_digest: str,
        declared_length: int,
        content_sha256: str,
    ) -> PreparedWrite | dict[str, Any]:
        with self._lock:
            root = self._authorized_root(authorization, root_id, "WRITE")
            path = validate_virtual_path(virtual_path)
            self._validate_expected_revision(expected_revision)
            self._validate_encoding(encoding)
            self._validate_idempotency_key(idempotency_key)
            self._validate_digest(request_digest, "request digest")
            if (
                type(declared_length) is not int
                or not 0 <= declared_length <= MAXIMUM_FILE_BYTES
            ):
                raise VirtualFileError("LIMIT_EXCEEDED", "declared file length is invalid")
            self._validate_digest(content_sha256, "content digest")
            reservation = self._repository_call(
                self._require_repository().reserve_virtual_file,
                authorization,
                owner_id=root.owner_id,
                root_id=root.root_id,
                acl_revision=root.acl_revision,
                virtual_path=path,
                expected_revision=expected_revision,
                encoding=encoding,
                byte_length=declared_length,
                content_digest=content_sha256,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            reservation_id = reservation.get("reservation_id")
            if reservation_id is None:
                return reservation
            temporary_name = f".spell-write-{uuid.uuid4().hex}"
            root_directory = self._root_directory(root)
            temporary = root_directory.path / temporary_name
            handle = None
            try:
                handle = open_regular_file(
                    root_directory,
                    temporary_name,
                    create=True,
                    writable=True,
                    delete_access=True,
                    share_delete=True,
                )
                prepared = PreparedWrite(
                    root=root,
                    virtual_path=path,
                    expected_revision=expected_revision,
                    encoding=encoding,
                    caller_digest=caller_binding_digest(authorization.caller),
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    declared_length=declared_length,
                    content_sha256=content_sha256,
                    reservation_id=reservation_id,
                    temporary_path=temporary,
                    temporary_name=temporary_name,
                    _file=handle,
                    _discard_file=lambda: unlink_entry(
                        root_directory, temporary_name
                    ),
                    _release_reservation=lambda identity: self._release_prepared_write(
                        root, identity
                    ),
                )
                self._prepared_writes[reservation_id] = prepared
                return prepared
            except Exception:
                try:
                    if handle is not None:
                        handle.close()
                    unlink_entry(root_directory, temporary_name)
                finally:
                    self._repository_call(
                        self._require_repository().release_virtual_file_reservation,
                        owner_id=root.owner_id,
                        root_id=root.root_id,
                        reservation_id=reservation_id,
                    )
                raise

    def commit_write(
        self,
        authorization: AuthorizationContext,
        prepared: PreparedWrite,
        *,
        declared_length: int,
        content_sha256: str,
    ) -> dict[str, Any]:
        with self._lock:
            if prepared.caller_digest != caller_binding_digest(authorization.caller):
                prepared.abort()
                raise VirtualFileError("NOT_AUTHORIZED", "write stage binding differs")
            if (
                declared_length != prepared.declared_length
                or content_sha256 != prepared.content_sha256
            ):
                prepared.abort()
                raise VirtualFileError("REJECTED", "write reservation binding differs")
            prepared.finish()
            self._validate_digest(content_sha256, "content digest")
            if prepared.bytes_written != prepared.declared_length:
                prepared.abort()
                raise VirtualFileError("REJECTED", "declared file length differs")
            payload = read_stream(prepared._file)
            actual_digest = hashlib.sha256(payload).hexdigest()
            if actual_digest != content_sha256:
                prepared.abort()
                raise VirtualFileError("REJECTED", "file content digest differs")
            if prepared.encoding == "UTF8_TEXT":
                self._validate_utf8_content(payload)
            root = self._authorized_root(authorization, prepared.root.root_id, "WRITE")
            if root.owner_id != prepared.root.owner_id:
                prepared.abort()
                raise VirtualFileError("NOT_AUTHORIZED", "virtual root binding differs")
            root_directory = self._root_directory(root)
            objects = self._objects_directory(root)

            def finalize_bytes() -> None:
                try:
                    target_exists = regular_file_exists(objects, actual_digest)
                except (OSError, SecureFilesystemError) as exc:
                    raise VirtualFileError(
                        "CORRUPT_FILE", "content object identity is ambiguous"
                    ) from exc
                if target_exists:
                    existing = read_regular_file(objects, actual_digest)
                    if (
                        len(existing) != len(payload)
                        or hashlib.sha256(existing).hexdigest() != actual_digest
                    ):
                        raise VirtualFileError("CORRUPT_FILE", "content object is corrupt")
                    return
                before = file_identity(prepared._file)
                try:
                    rename_open_file(
                        root_directory,
                        prepared.temporary_name,
                        prepared._file,
                        objects,
                        actual_digest,
                    )
                except FileExistsError:
                    existing = read_regular_file(objects, actual_digest)
                    if (
                        len(existing) != len(payload)
                        or hashlib.sha256(existing).hexdigest() != actual_digest
                    ):
                        raise VirtualFileError(
                            "CORRUPT_FILE", "content object is corrupt"
                        )
                    return
                prepared._file.close()
                prepared._closed = True
                try:
                    finalized_stream = open_regular_file(objects, actual_digest)
                except (OSError, SecureFilesystemError) as exc:
                    raise VirtualFileError(
                        "CORRUPT_FILE", "content object identity changed during finalize"
                    ) from exc
                prepared._file = finalized_stream
                prepared._closed = False
                if file_identity(finalized_stream) != before:
                    raise VirtualFileError(
                        "CORRUPT_FILE", "content object identity changed during finalize"
                    )
                finalized = read_stream(finalized_stream)
                if finalized != payload or hashlib.sha256(finalized).hexdigest() != actual_digest:
                    raise VirtualFileError(
                        "CORRUPT_FILE", "content object changed during finalize"
                    )
                fsync_directory(objects)

            try:
                result = self._repository_call(
                    self._require_repository().commit_virtual_file,
                    authorization,
                    owner_id=root.owner_id,
                    root_id=root.root_id,
                    acl_revision=root.acl_revision,
                    virtual_path=prepared.virtual_path,
                    expected_revision=prepared.expected_revision,
                    encoding=prepared.encoding,
                    byte_length=len(payload),
                    content_digest=actual_digest,
                    idempotency_key=prepared.idempotency_key,
                    request_digest=prepared.request_digest,
                    reservation_id=prepared.reservation_id,
                    finalize_bytes=finalize_bytes,
                )
            finally:
                prepared.abort()
            return result

    def write_file(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
        payload: bytes,
        *,
        expected_revision: int,
        encoding: str,
        content_sha256: str,
        idempotency_key: str,
        request_digest: str | None = None,
    ) -> dict[str, Any]:
        if type(payload) is not bytes:
            raise VirtualFileError("REJECTED", "file content must be bytes")
        digest = request_digest or self._request_digest(
            "WRITE",
            self._root_for(authorization, root_id),
            validate_virtual_path(virtual_path),
            expected_revision,
            payload,
        )
        prepared = self.prepare_write(
            authorization,
            root_id,
            virtual_path,
            expected_revision=expected_revision,
            encoding=encoding,
            idempotency_key=idempotency_key,
            request_digest=digest,
            declared_length=len(payload),
            content_sha256=content_sha256,
        )
        if isinstance(prepared, dict):
            return prepared
        try:
            prepared.write(payload)
            return self.commit_write(
                authorization,
                prepared,
                declared_length=len(payload),
                content_sha256=content_sha256,
            )
        except Exception:
            prepared.abort()
            raise

    def delete_node(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        request_digest: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            root = self._authorized_root(authorization, root_id, "DELETE")
            path = validate_virtual_path(virtual_path)
            self._validate_expected_revision(expected_revision)
            digest = request_digest or self._request_digest(
                "DELETE", root, path, expected_revision, b""
            )
            self._validate_idempotency_key(idempotency_key)
            return self._repository_call(
                self._require_repository().delete_virtual_node,
                authorization,
                owner_id=root.owner_id,
                root_id=root.root_id,
                acl_revision=root.acl_revision,
                virtual_path=path,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
                request_digest=digest,
            )

    def open_file(
        self,
        authorization: AuthorizationContext,
        root_id: str,
        virtual_path: str,
        *,
        execution_id: str,
        mode: str,
        revision: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._expire_handles()
            if mode not in HANDLE_MODES:
                raise VirtualFileError("REJECTED", "file handle mode is invalid")
            self._validate_execution_binding(authorization, execution_id)
            operation = "READ" if mode == "READ" else "WRITE"
            root = self._authorized_root(authorization, root_id, operation)
            path = validate_virtual_path(virtual_path)
            if sum(1 for item in self._handles.values() if item.execution_id == execution_id) >= MAXIMUM_OPEN_HANDLES:
                raise VirtualFileError("LIMIT_EXCEEDED", "execution already has 32 open handles")
            try:
                record = self._repository_call(
                    self._require_repository().read_virtual_node,
                    authorization,
                    owner_id=root.owner_id,
                    root_id=root.root_id,
                    acl_revision=root.acl_revision,
                    virtual_path=path,
                )
            except VirtualFileError as exc:
                if exc.code != "NOT_FOUND":
                    raise
                record = None
            if record is not None and record.get("kind") != "FILE":
                raise VirtualFileError("REVISION_CONFLICT", "target is not a file")
            current_revision = int(record["revision"]) if record else 0
            if mode == "READ" and record is None:
                raise VirtualFileError("NOT_FOUND", "file is unavailable")
            if revision is not None and revision != current_revision:
                raise VirtualFileError(
                    "REVISION_CONFLICT",
                    "file revision differs",
                    current_revision=current_revision,
                )
            if mode != "READ" and revision is None:
                raise VirtualFileError("REJECTED", "write handle requires an exact revision")
            token = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
            token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
            stage_path = None
            stage_name = None
            stage_stream = None
            reservation_id = None
            cursor = 0
            encoding = str((record or {}).get("encoding", "BINARY"))
            if mode != "READ":
                binding = authorization.caller
                idempotency_key = (
                    binding.deterministic_request_id
                    if type(binding) is ProcedureCallerBinding
                    else token_digest
                )
                reservation = self._repository_call(
                    self._require_repository().reserve_virtual_file,
                    authorization,
                    owner_id=root.owner_id,
                    root_id=root.root_id,
                    acl_revision=root.acl_revision,
                    virtual_path=path,
                    expected_revision=current_revision,
                    encoding=encoding,
                    byte_length=MAXIMUM_FILE_BYTES,
                    content_digest=hashlib.sha256(b"").hexdigest(),
                    idempotency_key=idempotency_key,
                    request_digest=self._request_digest(
                        "OPEN_WRITE_HANDLE", root, path, current_revision, token.encode("ascii")
                    ),
                )
                reservation_id = reservation.get("reservation_id")
                if reservation_id is None:
                    raise VirtualFileError(
                        "CORRUPT_FILE", "write handle reservation did not settle"
                    )
            if mode != "READ" or record is not None:
                root_directory = self._root_directory(root)
                stage_name = f".spell-handle-{uuid.uuid4().hex}"
                stage_path = root_directory.path / stage_name
                try:
                    stage_stream = open_regular_file(
                        root_directory,
                        stage_name,
                        create=True,
                        writable=True,
                        delete_access=True,
                        share_delete=True,
                    )
                    if record is not None and mode in {"READ", "READ_WRITE", "APPEND"}:
                        try:
                            with self._open_object(
                                root, record["content_sha256"]
                            ) as existing:
                                while True:
                                    chunk = existing.read(1024 * 1024)
                                    if not chunk:
                                        break
                                    stage_stream.write(chunk)
                        except FileNotFoundError as exc:
                            raise VirtualFileError(
                                "CORRUPT_FILE", "file content is missing"
                            ) from exc
                    stage_stream.flush()
                    os.fsync(stage_stream.fileno())
                    if mode == "APPEND":
                        cursor = int((record or {}).get("size", 0))
                except Exception:
                    if stage_stream is not None:
                        stage_stream.close()
                    if stage_name is not None:
                        unlink_entry(root_directory, stage_name)
                    if reservation_id is not None:
                        self._release_prepared_write(root, reservation_id)
                    raise
            self._handles[token_digest] = _Handle(
                token_digest=token_digest,
                caller_digest=self._handle_caller_digest(authorization),
                origin_request_id=getattr(
                    authorization.caller, "deterministic_request_id", None
                ),
                execution_id=execution_id,
                root=root,
                virtual_path=path,
                opened_revision=current_revision,
                mode=mode,
                encoding=encoding,
                content_digest=(record or {}).get("content_sha256"),
                cursor=cursor,
                last_access=self._clock(),
                stage_path=stage_path,
                stage_name=stage_name,
                stage_stream=stage_stream,
                reservation_id=reservation_id,
            )
            return {
                "handle": token,
                "root_id": root.root_id,
                "virtual_path": path,
                "mode": mode,
                "opened_revision": current_revision,
                "cursor": cursor,
            }

    def read_handle(
        self,
        authorization: AuthorizationContext,
        token: str,
        *,
        execution_id: str,
        length: int | None = None,
    ) -> dict[str, Any]:
        if type(token) is not str:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")
        try:
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale") from exc
        return self.read_handle_digest(
            authorization, digest, execution_id=execution_id, length=length
        )

    def read_handle_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        *,
        execution_id: str,
        length: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            handle = self._bound_handle_digest(
                authorization, token_digest, execution_id
            )
            if handle.mode not in {"READ", "READ_WRITE"}:
                raise VirtualFileError("NOT_AUTHORIZED", "file handle is not readable")
            if length is None:
                length = MAXIMUM_FILE_BYTES
            if type(length) is not int or not 0 <= length <= MAXIMUM_FILE_BYTES:
                raise VirtualFileError("REJECTED", "read length is invalid")
            if handle.stage_stream is not None:
                source_stream = handle.stage_stream
                source_stream.seek(handle.cursor)
                payload = source_stream.read(length)
            elif handle.content_digest is not None:
                try:
                    with self._open_object(
                        handle.root, handle.content_digest
                    ) as source_stream:
                        source_stream.seek(handle.cursor)
                        payload = source_stream.read(length)
                except FileNotFoundError as exc:
                    raise VirtualFileError(
                        "CORRUPT_FILE", "file handle content is missing"
                    ) from exc
            else:
                raise VirtualFileError("CORRUPT_FILE", "file handle content is missing")
            handle.cursor += len(payload)
            handle.last_access = self._clock()
            return {
                "content": payload,
                "encoding": handle.encoding,
                "cursor": handle.cursor,
                "revision": handle.opened_revision,
            }

    def write_handle(
        self,
        authorization: AuthorizationContext,
        token: str,
        payload: bytes,
        *,
        execution_id: str,
        encoding: str,
        content_sha256: str | None = None,
    ) -> dict[str, Any]:
        if type(token) is not str:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")
        try:
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale") from exc
        return self.write_handle_digest(
            authorization,
            digest,
            payload,
            execution_id=execution_id,
            encoding=encoding,
            content_sha256=content_sha256,
        )

    def write_handle_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        payload: bytes,
        *,
        execution_id: str,
        encoding: str,
        content_sha256: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            handle = self._bound_handle_digest(
                authorization, token_digest, execution_id
            )
            if (
                handle.mode not in {"WRITE", "READ_WRITE", "APPEND"}
                or handle.stage_stream is None
            ):
                raise VirtualFileError("NOT_AUTHORIZED", "file handle is not writable")
            self._validate_encoding(encoding)
            if handle.dirty and handle.encoding != encoding:
                raise VirtualFileError("REJECTED", "file handle encoding cannot change")
            if content_sha256 is not None:
                self._validate_digest(content_sha256, "content digest")
                if hashlib.sha256(payload).hexdigest() != content_sha256:
                    raise VirtualFileError("REJECTED", "file content digest differs")
            size = os.fstat(handle.stage_stream.fileno()).st_size
            resulting_size = max(size, handle.cursor + len(payload))
            if resulting_size > MAXIMUM_FILE_BYTES:
                raise VirtualFileError("LIMIT_EXCEEDED", "file exceeds 16777216 bytes")
            handle.stage_stream.seek(handle.cursor)
            handle.stage_stream.write(payload)
            handle.stage_stream.flush()
            os.fsync(handle.stage_stream.fileno())
            handle.cursor += len(payload)
            handle.encoding = encoding
            handle.dirty = True
            handle.last_access = self._clock()
            return {"written": len(payload), "cursor": handle.cursor}

    def close_file(
        self,
        authorization: AuthorizationContext,
        token: str,
        *,
        execution_id: str,
    ) -> dict[str, Any]:
        if type(token) is not str:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")
        try:
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale") from exc
        return self.close_file_digest(
            authorization, digest, execution_id=execution_id
        )

    def close_file_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        *,
        execution_id: str,
    ) -> dict[str, Any]:
        with self._lock:
            handle = self._bound_handle_digest(
                authorization, token_digest, execution_id
            )
            del self._handles[handle.token_digest]
            if not handle.dirty or handle.stage_stream is None:
                self._discard_handle_stage(handle)
                if handle.reservation_id is not None:
                    self._release_prepared_write(handle.root, handle.reservation_id)
                return {"closed": True, "revision": handle.opened_revision}
            if handle.reservation_id is None:
                self._discard_handle_stage(handle)
                raise VirtualFileError("CORRUPT_FILE", "write handle reservation is missing")
            try:
                payload = read_stream(handle.stage_stream)
                content_digest = hashlib.sha256(payload).hexdigest()
                binding = authorization.caller
                idempotency_key = (
                    binding.deterministic_request_id
                    if type(binding) is ProcedureCallerBinding
                    else handle.token_digest
                )
                request_digest = self._request_digest(
                    "WRITE",
                    handle.root,
                    handle.virtual_path,
                    handle.opened_revision,
                    payload,
                )
                prepared = PreparedWrite(
                    root=handle.root,
                    virtual_path=handle.virtual_path,
                    expected_revision=handle.opened_revision,
                    encoding=handle.encoding,
                    caller_digest=caller_binding_digest(authorization.caller),
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    declared_length=len(payload),
                    content_sha256=content_digest,
                    reservation_id=handle.reservation_id,
                    temporary_path=handle.stage_path,
                    temporary_name=str(handle.stage_name),
                    _file=handle.stage_stream,
                    _discard_file=lambda: unlink_entry(
                        self._root_directory(handle.root), str(handle.stage_name)
                    ),
                    _release_reservation=lambda identity: self._release_prepared_write(
                        handle.root, identity
                    ),
                    bytes_written=len(payload),
                    _finished=True,
                )
                handle.stage_stream = None
                self._prepared_writes[handle.reservation_id] = prepared
            except Exception:
                self._discard_handle_stage(handle)
                self._release_prepared_write(handle.root, handle.reservation_id)
                raise
            result = self.commit_write(
                authorization,
                prepared,
                declared_length=len(payload),
                content_sha256=content_digest,
            )
            return {"closed": True, "revision": result["revision"]}

    def _authorized_root(
        self, authorization: AuthorizationContext, root_id: str, operation: str
    ) -> _Root:
        root = self._root_for(authorization, root_id)
        try:
            authorization.require(
                ResourceFamily.FILES,
                operation,
                owner_id=root.owner_id,
                resource_id=root.root_id,
                acl_revision=root.acl_revision,
            )
        except DataAuthorizationError as exc:
            raise VirtualFileError("NOT_AUTHORIZED", "virtual file operation is not authorized") from exc
        return root

    def _root_for(self, authorization: AuthorizationContext, root_id: str) -> _Root:
        self._require_started()
        if root_id not in ROOT_IDS:
            raise VirtualFileError("NOT_FOUND", "virtual root is unavailable")
        if root_id == "EXECUTION_SCRATCH":
            binding = authorization.caller
            if type(binding) is not ProcedureCallerBinding:
                raise VirtualFileError("NOT_AUTHORIZED", "execution scratch is procedure scoped")
            root = self._execution_root(binding.execution_id)
            self._activate_storage_root(root)
            self._provision_root(root)
            return root
        return self._root_from_spec(self._specs[root_id])

    def _root_from_spec(self, spec: RootSpec) -> _Root:
        return _Root(
            spec.root_id,
            spec.owner_id,
            self._base / spec.directory_name,
            spec.acl_revision,
        )

    def _execution_root(self, execution_id: str) -> _Root:
        require_identifier(execution_id, "execution_id")
        spec = self._specs["EXECUTION_SCRATCH"]
        return _Root(
            "EXECUTION_SCRATCH",
            execution_id,
            self._base / spec.directory_name / execution_id,
            spec.acl_revision,
        )

    def _root_from_storage_id(self, storage_root_id: str) -> _Root:
        if type(storage_root_id) is not str:
            raise VirtualFileError("CORRUPT_FILE", "virtual storage root is not fixed")
        if storage_root_id in {"PROCEDURE_DATA", "PROJECT_DATA"}:
            return self._root_from_spec(self._specs[storage_root_id])
        prefix = "EXECUTION_SCRATCH."
        if type(storage_root_id) is str and storage_root_id.startswith(prefix):
            execution_id = storage_root_id.removeprefix(prefix)
            if execution_id:
                return self._execution_root(execution_id)
        raise VirtualFileError("CORRUPT_FILE", "virtual storage root is not fixed")

    def _read_physical_object(self, root: _Root, content_digest: str) -> bytes:
        try:
            payload = self._read_object(root, content_digest)
        except FileNotFoundError as exc:
            raise VirtualFileError(
                "CORRUPT_FILE", "referenced virtual content is missing"
            ) from exc
        if hashlib.sha256(payload).hexdigest() != content_digest:
            raise VirtualFileError(
                "CORRUPT_FILE", "referenced virtual content digest differs"
            )
        return payload

    def _activate_storage_root(self, root: _Root) -> None:
        storage_id = self._storage_root_id(root)
        if storage_id in self._root_handles:
            return
        if root.root_id == "EXECUTION_SCRATCH":
            parent = self._require_scratch_handle()
            name = root.owner_id
        else:
            parent = self._require_base_handle()
            name = self._specs[root.root_id].directory_name
        try:
            directory = open_child_directory(parent, name, create=True)
            objects = open_child_directory(directory, ".spell-objects", create=True)
        except Exception:
            if "directory" in locals():
                directory.close()
            raise
        self._root_handles[storage_id] = directory
        self._object_handles[storage_id] = objects

    def _provision_root(self, root: _Root) -> None:
        repository = self._require_repository()
        storage_id = repository.virtual_root_storage_id(root.root_id, root.owner_id)
        configuration = {
            "acl_revision": root.acl_revision,
            "owner_id": root.owner_id,
            "quota_bytes": MAXIMUM_ROOT_BYTES,
            "quota_nodes": MAXIMUM_ROOT_NODES,
            "root_id": storage_id,
            "root_kind": root.root_id,
        }
        digest = hashlib.sha256(
            canonical_virtual_root_configuration_bytes(configuration)
        ).hexdigest()
        self._repository_call(
            repository.provision_virtual_root,
            root_id=root.root_id,
            root_kind=root.root_id,
            owner_id=root.owner_id,
            acl_revision=root.acl_revision,
            configuration_digest=digest,
            quota_bytes=MAXIMUM_ROOT_BYTES,
            quota_nodes=MAXIMUM_ROOT_NODES,
        )

    def _object_path(self, root: _Root, content_digest: str) -> Path:
        self._validate_digest(content_digest, "content digest")
        return self._objects_directory(root).path / content_digest

    @staticmethod
    def _storage_root_id(root: _Root) -> str:
        if root.root_id == "EXECUTION_SCRATCH":
            return f"EXECUTION_SCRATCH.{root.owner_id}"
        return root.root_id

    def _root_directory(self, root: _Root) -> OwnedDirectory:
        directory = self._root_handles.get(self._storage_root_id(root))
        if directory is None or directory.closed:
            raise VirtualFileError("CORRUPT_FILE", "virtual root handle is unavailable")
        return directory

    def _objects_directory(self, root: _Root) -> OwnedDirectory:
        directory = self._object_handles.get(self._storage_root_id(root))
        if directory is None or directory.closed:
            raise VirtualFileError(
                "CORRUPT_FILE", "virtual object root handle is unavailable"
            )
        return directory

    def _open_object(self, root: _Root, content_digest: str) -> Any:
        self._validate_digest(content_digest, "content digest")
        try:
            return open_regular_file(self._objects_directory(root), content_digest)
        except SecureFilesystemError as exc:
            raise VirtualFileError(
                "CORRUPT_FILE", "content object identity is ambiguous"
            ) from exc

    def _read_object(self, root: _Root, content_digest: str) -> bytes:
        with self._open_object(root, content_digest) as source:
            return read_stream(source)

    def _require_base_handle(self) -> OwnedDirectory:
        if self._base_handle is None or self._base_handle.closed:
            raise VirtualFileError("INTERNAL", "virtual base handle is unavailable")
        return self._base_handle

    def _require_quarantine_handle(self) -> OwnedDirectory:
        if self._quarantine_handle is None or self._quarantine_handle.closed:
            raise VirtualFileError("INTERNAL", "quarantine handle is unavailable")
        return self._quarantine_handle

    def _require_scratch_handle(self) -> OwnedDirectory:
        if self._scratch_handle is None or self._scratch_handle.closed:
            raise VirtualFileError("INTERNAL", "scratch root handle is unavailable")
        return self._scratch_handle

    def _discard_handle_stage(self, handle: _Handle) -> None:
        if handle.stage_stream is not None:
            try:
                handle.stage_stream.close()
            finally:
                handle.stage_stream = None
        if handle.stage_name is not None:
            try:
                unlink_entry(
                    self._root_directory(handle.root), handle.stage_name
                )
            except FileNotFoundError:
                pass

    def _close_directory_handles(self) -> None:
        ordered = [
            *self._object_handles.values(),
            *self._root_handles.values(),
            self._scratch_handle,
            self._quarantine_handle,
            self._control_handle,
            self._base_handle,
        ]
        seen: set[int] = set()
        for directory in ordered:
            if directory is None or id(directory) in seen:
                continue
            seen.add(id(directory))
            directory.close()
        self._object_handles.clear()
        self._root_handles.clear()
        self._scratch_handle = None
        self._quarantine_handle = None
        self._control_handle = None
        self._base_handle = None

    def _recover_storage_root(
        self, root: _Root, referenced: frozenset[str]
    ) -> tuple[int, int]:
        self._activate_storage_root(root)
        removed_temporary = 0
        quarantined = 0
        directory = self._root_directory(root)
        objects = self._objects_directory(root)
        quarantine = self._require_quarantine_handle()
        for name in list_names(directory):
            if name == ".spell-objects":
                continue
            if name.startswith((".spell-write-", ".spell-handle-")):
                if entry_kind(directory, name) != "REGULAR":
                    raise VirtualFileError(
                        "CORRUPT_FILE", "temporary file identity is ambiguous"
                    )
                unlink_regular_file(directory, name)
                removed_temporary += 1
                continue
            move_entry(
                directory,
                name,
                quarantine,
                f"{uuid.uuid4().hex}-{name}",
            )
            quarantined += 1
        for name in list_names(objects):
            valid_name = bool(re.fullmatch(r"[0-9a-f]{64}", name))
            regular = entry_kind(objects, name) == "REGULAR"
            actual = (
                hashlib.sha256(read_regular_file(objects, name)).hexdigest()
                if valid_name and regular
                else ""
            )
            if not valid_name or actual != name or name not in referenced:
                move_entry(
                    objects,
                    name,
                    quarantine,
                    f"{uuid.uuid4().hex}-{name}",
                )
                quarantined += 1
        return removed_temporary, quarantined

    def _require_repository(self) -> Any:
        if self._repository is None:
            raise VirtualFileError("INTERNAL", "virtual file repository is unavailable")
        return self._repository

    def _release_prepared_write(self, root: _Root, reservation_id: str) -> None:
        with self._lock:
            self._repository_call(
                self._require_repository().release_virtual_file_reservation,
                owner_id=root.owner_id,
                root_id=root.root_id,
                reservation_id=reservation_id,
            )
            self._prepared_writes.pop(reservation_id, None)

    @staticmethod
    def _repository_call(callback: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return callback(*args, **kwargs)
        except DataDomainError as exc:
            code = getattr(exc, "code", "REJECTED")
            if code == "DATA_CORRUPT":
                code = "CORRUPT_FILE"
            raise VirtualFileError(
                code,
                str(exc),
                current_revision=getattr(exc, "current_revision", None),
            ) from exc

    @staticmethod
    def _validate_expected_revision(value: Any) -> None:
        if type(value) is not int or value < 0:
            raise VirtualFileError("REJECTED", "expected revision must be nonnegative")

    @staticmethod
    def _validate_encoding(value: Any) -> None:
        if value not in FILE_ENCODINGS:
            raise VirtualFileError("REJECTED", "file encoding is invalid")

    @staticmethod
    def _validate_digest(value: Any, label: str) -> None:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise VirtualFileError("REJECTED", f"{label} must be a lowercase SHA-256 digest")

    @staticmethod
    def _validate_handle_digest(value: Any) -> None:
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")

    @staticmethod
    def _validate_utf8_content(payload: bytes) -> None:
        if payload.startswith(b"\xef\xbb\xbf"):
            raise VirtualFileError("REJECTED", "UTF8_TEXT must not contain a byte-order mark")
        try:
            text = payload.decode("utf-8", errors="strict")
            text.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise VirtualFileError("REJECTED", "UTF8_TEXT content is not strict UTF-8") from exc

    def _request_digest(
        self,
        operation: str,
        root: _Root,
        virtual_path: str,
        expected_revision: int,
        body: bytes,
    ) -> str:
        material = {
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "expected_revision": expected_revision,
            "operation": operation,
            "resource": f"{root.root_id}:{root.owner_id}:{virtual_path}",
        }
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()

    @staticmethod
    def _validate_idempotency_key(value: Any) -> str:
        if type(value) is not str:
            raise VirtualFileError("REJECTED", "Idempotency-Key is required")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise VirtualFileError("REJECTED", "Idempotency-Key must be ASCII") from exc
        if not encoded or len(encoded) > 128 or any(byte < 0x21 or byte > 0x7E for byte in encoded):
            raise VirtualFileError("REJECTED", "Idempotency-Key is invalid")
        return value

    def _validate_execution_binding(
        self, authorization: AuthorizationContext, execution_id: str
    ) -> None:
        require_identifier(execution_id, "execution_id")
        caller = authorization.caller
        if type(caller) is ProcedureCallerBinding and caller.execution_id != execution_id:
            raise VirtualFileError("NOT_AUTHORIZED", "execution binding differs")

    def _bound_handle(
        self,
        authorization: AuthorizationContext,
        token: str,
        execution_id: str,
    ) -> _Handle:
        if type(token) is not str:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")
        try:
            token_bytes = token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise VirtualFileError("STALE_HANDLE", "file handle is stale") from exc
        return self._bound_handle_digest(
            authorization, hashlib.sha256(token_bytes).hexdigest(), execution_id
        )

    def _bound_handle_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        execution_id: str,
    ) -> _Handle:
        self._expire_handles()
        self._validate_execution_binding(authorization, execution_id)
        self._validate_handle_digest(token_digest)
        handle = self._handles.get(token_digest)
        if (
            handle is None
            or handle.execution_id != execution_id
            or handle.caller_digest != self._handle_caller_digest(authorization)
        ):
            raise VirtualFileError("STALE_HANDLE", "file handle is stale")
        return handle

    def _procedure_handle_authorization(
        self,
        authorization: AuthorizationContext,
        token: str,
        execution_id: str,
    ) -> AuthorizationContext:
        """Rebuild the exact OpenFile creator binding from server-held state."""

        with self._lock:
            if type(token) is not str:
                raise VirtualFileError("STALE_HANDLE", "file handle is stale")
            try:
                token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
            except UnicodeEncodeError as exc:
                raise VirtualFileError("STALE_HANDLE", "file handle is stale") from exc
            return self._procedure_handle_authorization_digest(
                authorization, token_digest, execution_id
            )

    def _procedure_handle_authorization_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        execution_id: str,
        *,
        creator_request_id: str | None = None,
    ) -> AuthorizationContext:
        """Rebuild an exact creator binding from a digest-only handle marker."""

        with self._lock:
            self._expire_handles()
            caller = authorization.caller
            if type(caller) is not ProcedureCallerBinding:
                raise VirtualFileError("STALE_HANDLE", "file handle is stale")
            self._validate_execution_binding(authorization, execution_id)
            self._validate_handle_digest(token_digest)
            handle = self._handles.get(token_digest)
            if (
                handle is None
                or handle.execution_id != execution_id
                or type(handle.origin_request_id) is not str
                or not handle.origin_request_id
                or (
                    creator_request_id is not None
                    and handle.origin_request_id != creator_request_id
                )
            ):
                raise VirtualFileError("STALE_HANDLE", "file handle is stale")
            creator = ProcedureCallerBinding(
                caller.service_principal_id,
                caller.execution_id,
                caller.worker_generation,
                handle.origin_request_id,
            )
            rebound = AuthorizationContext(creator, authorization.permissions)
            if handle.caller_digest != self._handle_caller_digest(rebound):
                raise VirtualFileError("STALE_HANDLE", "file handle is stale")
            return rebound

    def _procedure_close_authorization(
        self,
        creator_authorization: AuthorizationContext,
        token: str,
        execution_id: str,
        current_binding: ProcedureCallerBinding,
    ) -> AuthorizationContext:
        """Transfer a verified handle to the exact durable CloseFile request."""

        with self._lock:
            handle = self._bound_handle(
                creator_authorization, token, execution_id
            )
            rebound = AuthorizationContext(
                current_binding, creator_authorization.permissions
            )
            handle.origin_request_id = current_binding.deterministic_request_id
            handle.caller_digest = self._handle_caller_digest(rebound)
            return rebound

    def _procedure_close_authorization_digest(
        self,
        creator_authorization: AuthorizationContext,
        token_digest: str,
        execution_id: str,
        current_binding: ProcedureCallerBinding,
    ) -> AuthorizationContext:
        with self._lock:
            handle = self._bound_handle_digest(
                creator_authorization, token_digest, execution_id
            )
            rebound = AuthorizationContext(
                current_binding, creator_authorization.permissions
            )
            handle.origin_request_id = current_binding.deterministic_request_id
            handle.caller_digest = self._handle_caller_digest(rebound)
            return rebound

    def close_procedure_file(
        self,
        authorization: AuthorizationContext,
        token: str,
        *,
        execution_id: str,
    ) -> dict[str, Any]:
        """Verify creator ownership, transfer, and commit CloseFile atomically."""

        with self._lock:
            caller = authorization.caller
            if type(caller) is not ProcedureCallerBinding:
                raise VirtualFileError("STALE_HANDLE", "file handle is stale")
            creator = self._procedure_handle_authorization(
                authorization, token, execution_id
            )
            close_authorization = self._procedure_close_authorization(
                creator, token, execution_id, caller
            )
            return self.close_file(
                close_authorization, token, execution_id=execution_id
            )

    def close_procedure_file_digest(
        self,
        authorization: AuthorizationContext,
        token_digest: str,
        *,
        execution_id: str,
        creator_request_id: str | None = None,
    ) -> dict[str, Any]:
        """Close a procedure handle represented only by its server-held digest."""

        with self._lock:
            caller = authorization.caller
            if type(caller) is not ProcedureCallerBinding:
                raise VirtualFileError("STALE_HANDLE", "file handle is stale")
            creator = self._procedure_handle_authorization_digest(
                authorization,
                token_digest,
                execution_id,
                creator_request_id=creator_request_id,
            )
            close_authorization = self._procedure_close_authorization_digest(
                creator, token_digest, execution_id, caller
            )
            return self.close_file_digest(
                close_authorization, token_digest, execution_id=execution_id
            )

    @staticmethod
    def _handle_caller_digest(authorization: AuthorizationContext) -> str:
        return hashlib.sha256(
            canonical_json_bytes(caller_binding_payload(authorization.caller))
        ).hexdigest()

    def _expire_handles(self) -> None:
        cutoff = self._clock() - MAXIMUM_HANDLE_IDLE_SECONDS
        for digest, handle in tuple(self._handles.items()):
            if handle.last_access <= cutoff:
                self._discard_handle_stage(handle)
                if handle.reservation_id is not None:
                    self._release_prepared_write(handle.root, handle.reservation_id)
                del self._handles[digest]

    def _require_started(self) -> None:
        if not self._started:
            raise VirtualFileError("INTERNAL", "virtual file service is not started")


class ProcedureDataRuntime:
    """Supervisor-facing adapter for closed v0.8 procedure data requests."""

    _FILE_OPERATIONS = frozenset(
        {
            "FILE_VALUE",
            "OPEN_FILE",
            "CLOSE_FILE",
            "READ_FILE",
            "READ_DIRECTORY",
            "WRITE_FILE",
            "DELETE_FILE",
            "FILE_PROPERTY",
        }
    )
    _DICTIONARY_FILE_OPERATIONS = frozenset(
        {"LOAD_DICTIONARY", "SAVE_DICTIONARY"}
    )
    _MUTATION_RECOVERY = {
        "CREATE_DICTIONARY": (ResourceFamily.DICTIONARIES, ("IMPORT",)),
        "LOAD_DICTIONARY": (ResourceFamily.DICTIONARIES, ("IMPORT",)),
        "CREATE_CONTAINER": (ResourceFamily.CONTAINERS, ("CREATE",)),
        "SET_VARIABLE": (ResourceFamily.CONTAINERS, ("SET",)),
        "DELETE_VARIABLE": (ResourceFamily.CONTAINERS, ("DELETE",)),
        "SHARED_CREATE_NAMESPACE": (ResourceFamily.SHARED, ("CREATE_NAMESPACE",)),
        "SHARED_PUT": (ResourceFamily.SHARED, ("PUT",)),
        "SHARED_DELETE": (ResourceFamily.SHARED, ("DELETE",)),
        "SHARED_CLEAR": (ResourceFamily.SHARED, ("CLEAR",)),
        "SHARED_DELETE_NAMESPACE": (
            ResourceFamily.SHARED,
            ("DELETE_NAMESPACE",),
        ),
        "WRITE_FILE": (ResourceFamily.FILES, ("WRITE",)),
        "DELETE_FILE": (ResourceFamily.FILES, ("DELETE",)),
        "CLOSE_FILE": (ResourceFamily.FILES, ("WRITE",)),
        "SAVE_DICTIONARY": (ResourceFamily.FILES, ("WRITE",)),
    }

    def __init__(
        self,
        files: VirtualFileService,
        repository: Any | None = None,
        *,
        service_principal_id: str = "procedure-runtime",
        worker_generation: Callable[[str], int] | None = None,
    ) -> None:
        require_identifier(service_principal_id, "service_principal_id")
        self._files = files
        self._repository = repository
        self._service_principal_id = service_principal_id
        self._worker_generation = worker_generation

    def attach_repository(self, repository: Any) -> None:
        if repository is None:
            raise DataValidationError("data repository is required")
        self._repository = repository

    def resolve(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            canonical = self._validate_request(request)
        except VirtualFileError as exc:
            return {
                "outcome": self._runtime_outcome(exc.code),
                "detail": str(exc)[:240],
            }
        operation = canonical["operation"]
        parameters = canonical["parameters"]
        binding = ProcedureCallerBinding(
            service_principal_id=canonical["service_principal_id"],
            execution_id=canonical["execution_id"],
            worker_generation=canonical["worker_generation"],
            deterministic_request_id=canonical["request_id"],
        )
        try:
            if operation in self._FILE_OPERATIONS:
                raw = self._resolve_file(binding, operation, parameters)
            elif operation in self._DICTIONARY_FILE_OPERATIONS:
                raw = self._resolve_dictionary_file(
                    binding,
                    operation,
                    parameters,
                    request_digest=canonical["request_digest"],
                )
            elif self._repository is not None and hasattr(self._repository, "resolve"):
                raw = self._repository.resolve(canonical, binding=binding)
            else:
                raw = {"outcome": "NOT_AUTHORIZED", "detail": "operation is unavailable"}
        except VirtualFileError as exc:
            raw = {"outcome": self._runtime_outcome(exc.code), "detail": str(exc)[:240]}
            if exc.current_revision is not None:
                raw["revision"] = exc.current_revision
        except (DataValidationError, DataAuthorizationError, DataNotFoundError, DataConflictError, DataCapacityError) as exc:
            raw = {"outcome": self._runtime_outcome(getattr(exc, "code", "REJECTED")), "detail": str(exc)[:240]}
            if getattr(exc, "current_revision", None) is not None:
                raw["revision"] = exc.current_revision
        return raw

    def recover(
        self,
        request: Mapping[str, Any],
        *,
        original_binding: ProcedureCallerBinding,
    ) -> Mapping[str, Any]:
        """Recover a committed old-generation result without re-running its effect."""

        try:
            canonical = self._validate_request(request)
            current_binding = ProcedureCallerBinding(
                service_principal_id=canonical["service_principal_id"],
                execution_id=canonical["execution_id"],
                worker_generation=canonical["worker_generation"],
                deterministic_request_id=canonical["request_id"],
            )
            if type(original_binding) is not ProcedureCallerBinding:
                raise DataValidationError("original procedure binding is invalid")
            operation = canonical["operation"]
            parameters = canonical["parameters"]
            repository = self._repository or getattr(self._files, "_repository", None)
            if repository is None:
                raise DataAuthorizationError("data repository is unavailable")
            recovery_contract = self._MUTATION_RECOVERY.get(operation)
            if operation == "WRITE_FILE" and "handle" in parameters:
                recovery_contract = None
            if recovery_contract is not None:
                family, settlement_operations = recovery_contract
                try:
                    result = repository.recover_procedure_mutation(
                        original_binding,
                        current_binding,
                        resource_family=family,
                        operations=settlement_operations,
                    )
                except DataNotFoundError as exc:
                    if operation == "CLOSE_FILE":
                        raise VirtualFileError(
                            "STALE_HANDLE",
                            "file handle close has no committed settlement",
                        ) from exc
                    raise
                if operation in {"CREATE_DICTIONARY", "LOAD_DICTIONARY"}:
                    dictionary_id = require_identifier(
                        parameters["dictionary_id"],
                        "dictionary_id",
                        maximum_bytes=128,
                    )
                    handle = repository._procedure_handle(
                        current_binding,
                        ResourceFamily.DICTIONARIES,
                        owner_id=current_binding.execution_id,
                        resource_id=dictionary_id,
                        revision=result["revision"],
                        content_digest=result["content_digest"],
                    )
                    return {
                        "outcome": "OK",
                        "value": handle,
                        "revision": result["revision"],
                    }
                if operation == "CREATE_CONTAINER":
                    container_id = require_identifier(
                        parameters["container_id"],
                        "container_id",
                        maximum_bytes=128,
                    )
                    handle = repository._procedure_handle(
                        current_binding,
                        ResourceFamily.CONTAINERS,
                        owner_id=current_binding.execution_id,
                        resource_id=container_id,
                        revision=result["revision"],
                        content_digest=result["content_digest"],
                    )
                    return {
                        "outcome": "OK",
                        "value": handle,
                        "revision": result["revision"],
                    }
                revision = (
                    result.get("deleted_revision")
                    if operation == "DELETE_FILE"
                    else result.get("revision")
                )
                if revision is None:
                    revision = result.get("new_revision")
                return {"outcome": "OK", "revision": revision}
            if operation == "OPEN_FILE" or "handle" in parameters:
                raise VirtualFileError(
                    "STALE_HANDLE",
                    "transient file handle state cannot cross a worker generation",
                )
            raise DataAuthorizationError(
                "data operation has no committed-settlement recovery path"
            )
        except VirtualFileError as exc:
            raw = {
                "outcome": self._runtime_outcome(exc.code),
                "detail": str(exc)[:240],
            }
            if exc.current_revision is not None:
                raw["revision"] = exc.current_revision
            return raw
        except DataDomainError as exc:
            raw = {
                "outcome": self._runtime_outcome(getattr(exc, "code", "REJECTED")),
                "detail": str(exc)[:240],
            }
            if getattr(exc, "current_revision", None) is not None:
                raw["revision"] = exc.current_revision
            return raw

    def _path_authorization(
        self,
        binding: ProcedureCallerBinding,
        root_id: str,
        *operations: str,
    ) -> AuthorizationContext:
        if root_id == "EXECUTION_SCRATCH":
            owner_id = binding.execution_id
        else:
            spec = self._files._specs.get(root_id)
            if spec is None:
                raise VirtualFileError("NOT_FOUND", "virtual root is unavailable")
            owner_id = spec.owner_id
        return AuthorizationContext(
            binding,
            tuple(
                DataPermission(
                    ResourceFamily.FILES,
                    operation,
                    owner_id,
                    root_id,
                    1,
                )
                for operation in operations
            ),
        )

    def _resolve_dictionary_file(
        self,
        binding: ProcedureCallerBinding,
        operation: str,
        parameters: Mapping[str, Any],
        *,
        request_digest: str,
    ) -> dict[str, Any]:
        repository = self._repository
        if repository is None:
            raise DataAuthorizationError("data repository is unavailable")
        dictionary_id = require_identifier(
            parameters["dictionary_id"],
            "dictionary_id",
            maximum_bytes=128,
        )
        owner_id = binding.execution_id
        root_id = str(parameters["root_id"])
        virtual_path = str(parameters["virtual_path"])
        if operation == "LOAD_DICTIONARY":
            file_authorization = self._path_authorization(binding, root_id, "READ")
            source = self._files.read_file(
                file_authorization,
                root_id,
                virtual_path,
                revision=parameters["source_revision"],
            )
            media_type = (
                DB_MEDIA_TYPE if parameters["format"] == "DB" else IMP_MEDIA_TYPE
            )
            document = parse_dictionary_document(
                source["content"],
                media_type=media_type,
            )
            authorization = repository._procedure_authorization(
                binding,
                ResourceFamily.DICTIONARIES,
                ("IMPORT",),
                owner_id=owner_id,
                resource_id=dictionary_id,
                acl_revision=0,
            )
            result = repository.load_dictionary(
                authorization,
                owner_id=owner_id,
                dictionary_id=dictionary_id,
                acl_revision=0,
                expected_revision=parameters["expected_revision"],
                idempotency_key=binding.deterministic_request_id,
                document=document,
            )
            handle = repository._procedure_handle(
                binding,
                ResourceFamily.DICTIONARIES,
                owner_id=owner_id,
                resource_id=dictionary_id,
                revision=result["revision"],
                content_digest=result["content_digest"],
            )
            return {
                "outcome": "OK",
                "value": handle,
                "revision": result["revision"],
            }

        if parameters["format"] != "DB":
            raise DataValidationError("SaveDictionary emits only DB documents")
        authorization = repository._procedure_authorization(
            binding,
            ResourceFamily.DICTIONARIES,
            ("EXPORT",),
            owner_id=owner_id,
            resource_id=dictionary_id,
            acl_revision=0,
        )
        exported = repository.export_dictionary(
            authorization,
            owner_id=owner_id,
            dictionary_id=dictionary_id,
            acl_revision=0,
            revision=parameters["dictionary_revision"],
        )
        file_authorization = self._path_authorization(binding, root_id, "WRITE")
        result = self._files.write_file(
            file_authorization,
            root_id,
            virtual_path,
            exported,
            expected_revision=parameters["expected_file_revision"],
            encoding="UTF8_TEXT",
            content_sha256=hashlib.sha256(exported).hexdigest(),
            idempotency_key=binding.deterministic_request_id,
            request_digest=request_digest,
        )
        return {"outcome": "OK", "revision": result["revision"]}

    def _resolve_file(
        self,
        binding: ProcedureCallerBinding,
        operation: str,
        parameters: Mapping[str, Any],
    ) -> dict[str, Any]:
        root_id = str(parameters.get("root_id", ""))
        permission_operation = {
            "FILE_VALUE": "READ",
            "OPEN_FILE": "READ" if parameters.get("mode") == "READ" else "WRITE",
            "CLOSE_FILE": "WRITE",
            "READ_FILE": "READ",
            "READ_DIRECTORY": "LIST",
            "WRITE_FILE": "WRITE",
            "DELETE_FILE": "DELETE",
            "FILE_PROPERTY": "READ",
        }[operation]
        handle_operation = operation in {"CLOSE_FILE"} or (
            operation in {"READ_FILE", "WRITE_FILE", "FILE_PROPERTY"}
            and "handle" in parameters
        )
        roots = (
            ("PROCEDURE_DATA", "procedure-library"),
            ("PROJECT_DATA", "local-project"),
            ("EXECUTION_SCRATCH", binding.execution_id),
        )
        if handle_operation:
            permission_operations = (
                ("READ", "WRITE") if operation == "FILE_PROPERTY" else (permission_operation,)
            )
            permissions = tuple(
                DataPermission(ResourceFamily.FILES, permitted, owner, fixed_root, 1)
                for fixed_root, owner in roots
                for permitted in permission_operations
            )
        else:
            if root_id == "EXECUTION_SCRATCH":
                owner = binding.execution_id
            else:
                spec = self._files._specs.get(root_id)
                if spec is None:
                    raise VirtualFileError("NOT_FOUND", "virtual root is unavailable")
                owner = spec.owner_id
            permission_operations = (
                ("READ", "WRITE")
                if operation == "FILE_PROPERTY"
                or (operation == "OPEN_FILE" and permission_operation == "WRITE")
                else (permission_operation,)
            )
            permissions = tuple(
                DataPermission(ResourceFamily.FILES, permitted, owner, root_id, 1)
                for permitted in permission_operations
            )
        authorization = AuthorizationContext(binding, permissions)
        handle_reference: dict[str, Any] | None = None
        if handle_operation and operation != "CLOSE_FILE":
            try:
                handle_reference = validate_file_handle_reference(
                    parameters["handle"],
                    "$.parameters.handle",
                    execution_id=binding.execution_id,
                    worker_generation=binding.worker_generation,
                    require_open=True,
                )
            except V08ValidationError as exc:
                code = "STALE_HANDLE" if exc.code == "STALE_HANDLE" else "REJECTED"
                raise VirtualFileError(code, "file handle reference is invalid") from exc
            authorization = self._files._procedure_handle_authorization_digest(
                authorization,
                handle_reference["token_sha256"],
                binding.execution_id,
                creator_request_id=handle_reference["creator_request_id"],
            )
        elif operation == "CLOSE_FILE":
            try:
                handle_reference = validate_file_handle_reference(
                    parameters["handle"],
                    "$.parameters.handle",
                    execution_id=binding.execution_id,
                    worker_generation=binding.worker_generation,
                    require_open=True,
                )
            except V08ValidationError as exc:
                code = "STALE_HANDLE" if exc.code == "STALE_HANDLE" else "REJECTED"
                raise VirtualFileError(code, "file handle reference is invalid") from exc
        if operation == "FILE_VALUE":
            value = self._files.file_value(root_id, parameters["virtual_path"])
            return {"outcome": "OK", "value": value.to_opaque_string()}
        if operation == "FILE_PROPERTY":
            if "handle" in parameters:
                assert handle_reference is not None
                properties = self._files.handle_properties_digest(
                    authorization,
                    handle_reference["token_sha256"],
                    execution_id=binding.execution_id,
                )
            else:
                properties = self._files.file_properties(
                    authorization, root_id, parameters["virtual_path"]
                )
            property_name = parameters.get("property")
            if property_name not in properties:
                raise VirtualFileError("REJECTED", "File property is invalid")
            return {"outcome": "OK", "value": properties[property_name]}
        if operation == "OPEN_FILE":
            result = self._files.open_file(
                authorization,
                root_id,
                parameters["virtual_path"],
                execution_id=binding.execution_id,
                mode=parameters["mode"],
                revision=parameters.get("revision"),
            )
            return {
                "outcome": "OK",
                "value": result["handle"],
                "revision": result["opened_revision"],
            }
        if operation == "CLOSE_FILE":
            assert handle_reference is not None
            result = self._files.close_procedure_file_digest(
                authorization,
                handle_reference["token_sha256"],
                execution_id=binding.execution_id,
                creator_request_id=handle_reference["creator_request_id"],
            )
            return {"outcome": "OK", "revision": result["revision"]}
        if operation == "READ_FILE":
            if "handle" in parameters:
                assert handle_reference is not None
                result = self._files.read_handle_digest(
                    authorization,
                    handle_reference["token_sha256"],
                    execution_id=binding.execution_id,
                    length=parameters.get("length"),
                )
            else:
                result = self._files.read_file(
                    authorization,
                    root_id,
                    parameters["virtual_path"],
                    revision=parameters.get("revision"),
                    length=parameters.get("length"),
                )
            content = result["content"]
            value = (
                content.decode("utf-8")
                if result["encoding"] == "UTF8_TEXT"
                else base64.b64encode(content).decode("ascii")
            )
            return {"outcome": "OK", "value": value, "revision": result["revision"]}
        if operation == "READ_DIRECTORY":
            result = self._files.list_directory(
                authorization,
                root_id,
                parameters["virtual_path"],
                cursor=parameters.get("cursor"),
            )
            value = json.dumps(
                result, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
            )
            return {"outcome": "OK", "value": value, "revision": result["revision"]}
        if operation == "WRITE_FILE":
            payload = self._decode_content(parameters["encoding"], parameters["content"])
            if "handle" in parameters:
                assert handle_reference is not None
                self._files.write_handle_digest(
                    authorization,
                    handle_reference["token_sha256"],
                    payload,
                    execution_id=binding.execution_id,
                    encoding=parameters["encoding"],
                    content_sha256=parameters.get("content_sha256"),
                )
                return {"outcome": "OK"}
            content_digest = parameters.get("content_sha256") or hashlib.sha256(payload).hexdigest()
            result = self._files.write_file(
                authorization,
                root_id,
                parameters["virtual_path"],
                payload,
                expected_revision=parameters["expected_revision"],
                encoding=parameters["encoding"],
                content_sha256=content_digest,
                idempotency_key=binding.deterministic_request_id,
            )
            return {"outcome": "OK", "revision": result["revision"]}
        if operation == "DELETE_FILE":
            result = self._files.delete_node(
                authorization,
                root_id,
                parameters["virtual_path"],
                expected_revision=parameters["expected_revision"],
                idempotency_key=binding.deterministic_request_id,
            )
            return {"outcome": "OK", "revision": result["deleted_revision"]}
        raise VirtualFileError("REJECTED", "file operation is unavailable")

    def _validate_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if type(request) is not dict or set(request) != {
            "schema_version",
            "request_id",
            "execution_id",
            "step_index",
            "operation",
            "parameters",
            "request_digest",
            "service_principal_id",
            "worker_generation",
        }:
            raise VirtualFileError("REJECTED", "data request is not closed")
        canonical = json.loads(
            json.dumps(request, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        )
        if canonical["schema_version"] != "spell.v08.data-request/1":
            raise VirtualFileError("REJECTED", "data request schema is unsupported")
        supplied = canonical.pop("request_digest")
        service_principal_id = canonical.pop("service_principal_id")
        worker_generation = canonical.pop("worker_generation")
        expected = hashlib.sha256(
            json.dumps(canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        canonical["request_digest"] = supplied
        canonical["service_principal_id"] = service_principal_id
        canonical["worker_generation"] = worker_generation
        if not hmac.compare_digest(str(supplied), expected):
            raise VirtualFileError("REJECTED", "data request digest differs")
        if service_principal_id != self._service_principal_id:
            raise VirtualFileError("NOT_AUTHORIZED", "procedure service principal differs")
        require_identifier(service_principal_id, "service_principal_id")
        if type(worker_generation) is not int or worker_generation < 0:
            raise VirtualFileError("REJECTED", "worker generation is invalid")
        if self._worker_generation is not None:
            try:
                admitted_generation = self._worker_generation(canonical["execution_id"])
            except Exception as exc:
                raise VirtualFileError(
                    "NOT_AUTHORIZED", "execution generation is unavailable"
                ) from exc
            if admitted_generation != worker_generation:
                raise VirtualFileError("NOT_AUTHORIZED", "worker generation is stale")
        require_identifier(canonical["execution_id"], "execution_id")
        require_identifier(canonical["request_id"], "request_id")
        if type(canonical["parameters"]) is not dict:
            raise VirtualFileError("REJECTED", "data request parameters are invalid")
        return canonical

    @staticmethod
    def _decode_content(encoding: str, content: Any) -> bytes:
        if encoding == "UTF8_TEXT" and type(content) is str:
            try:
                return content.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise VirtualFileError("REJECTED", "text content is invalid") from exc
        if encoding == "BINARY" and type(content) is str:
            try:
                return base64.b64decode(content, validate=True)
            except ValueError as exc:
                raise VirtualFileError("REJECTED", "binary content is not canonical base64") from exc
        raise VirtualFileError("REJECTED", "file content does not match its encoding")

    @staticmethod
    def _wire_file_result(result: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(result)
        content = payload.get("content")
        if type(content) is bytes:
            if payload.get("encoding") == "UTF8_TEXT":
                payload["content"] = content.decode("utf-8")
            else:
                payload["content"] = base64.b64encode(content).decode("ascii")
        return payload

    @staticmethod
    def _runtime_outcome(code: str) -> str:
        return {
            "IDEMPOTENCY_CONFLICT": "REVISION_CONFLICT",
            "CORRUPT_FILE": "CORRUPT_DATA",
            "SERVICE_CAPACITY_EXHAUSTED": "LIMIT_EXCEEDED",
        }.get(code, code if code in {
            "NOT_FOUND",
            "NOT_AUTHORIZED",
            "REVISION_CONFLICT",
            "RESYNC_REQUIRED",
            "TYPE_MISMATCH",
            "LIMIT_EXCEEDED",
            "STALE_HANDLE",
            "REJECTED",
            "CANCELLED",
            "INTERNAL",
        } else "REJECTED")


__all__ = [
    "FILE_ENCODINGS",
    "FileValue",
    "HANDLE_MODES",
    "MAXIMUM_FILE_BYTES",
    "MAXIMUM_HANDLE_IDLE_SECONDS",
    "MAXIMUM_LIST_PAGE",
    "MAXIMUM_OPEN_HANDLES",
    "MAXIMUM_PATH_BYTES",
    "MAXIMUM_PATH_DEPTH",
    "MAXIMUM_ROOT_BYTES",
    "MAXIMUM_ROOT_NODES",
    "MAXIMUM_SEGMENT_BYTES",
    "PreparedWrite",
    "ProcedureDataRuntime",
    "ROOT_IDS",
    "RootSpec",
    "VirtualFileError",
    "VirtualFileService",
    "validate_virtual_path",
]
