"""Pure bounded-domain helpers for the v0.9 development environment."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


MAX_PROJECT_BYTES = 67_108_864
MAX_RESOURCE_BYTES = 16_777_216
MAX_RESOURCES = 10_000
MAX_TREE_DEPTH = 32
MAX_PATH_BYTES = 512
MAX_IDEMPOTENCY_BYTES = 200
MAX_REASON_BYTES = 4096
MAX_NAME_BYTES = 256
RESOURCE_KINDS = frozenset(
    {
        "PROJECT",
        "SOURCE_FOLDER",
        "FOLDER",
        "PROCEDURE",
        "LIBRARY",
        "DICTIONARY",
        "PROJECT_METADATA",
    }
)
CASE_POLICIES = frozenset({"CASE_SENSITIVE", "CASE_INSENSITIVE"})
CHECK_SCOPES = frozenset({"FILE", "FOLDER", "PROJECT", "CHANGED_SET"})
PROMOTION_OPERATIONS = frozenset(
    {"PROMOTE", "SUPERSEDE", "WITHDRAW", "ROLLBACK_PROMOTE"}
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class DevelopmentError(ValueError):
    """Base error with a stable HTTP-safe code and optional current state."""

    code = "VALIDATION_FAILED"

    def __init__(self, message: str, *, current: Any = None):
        self.current = current
        super().__init__(message)


class DevelopmentNotFoundError(DevelopmentError):
    code = "NOT_FOUND"


class DevelopmentAuthorizationError(DevelopmentError):
    code = "FORBIDDEN"


class DevelopmentConflictError(DevelopmentError):
    code = "STATE_CONFLICT"

    def __init__(
        self,
        message: str,
        *,
        code: str = "STATE_CONFLICT",
        current: Any = None,
    ):
        self.code = code
        super().__init__(message, current=current)


class DevelopmentCorruptionError(DevelopmentError):
    code = "CORRUPT_STORED_STATE"


class DevelopmentLimitError(DevelopmentError):
    code = "LIMIT_EXCEEDED"


@dataclass(frozen=True)
class Actor:
    subject: str
    role: str


def require_actor(subject: Any, role: Any) -> Actor:
    normalized = require_text(subject, "subject", 200)
    if not normalized.strip():
        raise DevelopmentAuthorizationError("authenticated subject is required")
    if role not in {"viewer", "operator", "admin"}:
        raise DevelopmentAuthorizationError("authenticated role is not authorized")
    return Actor(normalized, str(role))


def require_mutation_actor(subject: Any, role: Any) -> Actor:
    actor = require_actor(subject, role)
    if actor.role not in {"operator", "admin"}:
        raise DevelopmentAuthorizationError("operator role is required")
    return actor


def require_admin(subject: Any, role: Any) -> Actor:
    actor = require_actor(subject, role)
    if actor.role != "admin":
        raise DevelopmentAuthorizationError("admin role is required")
    return actor


def require_identifier(value: Any, label: str) -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise DevelopmentError(f"{label} is invalid")
    return value


def require_text(value: Any, label: str, maximum_bytes: int) -> str:
    if type(value) is not str:
        raise DevelopmentError(f"{label} must be text")
    normalized = unicodedata.normalize("NFC", value)
    try:
        raw = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DevelopmentError(f"{label} is not valid UTF-8") from exc
    if not raw or len(raw) > maximum_bytes or "\x00" in normalized:
        raise DevelopmentError(f"{label} is outside its bound")
    return normalized


def require_digest(value: Any, label: str = "digest") -> str:
    if type(value) is not str or not DIGEST.fullmatch(value):
        raise DevelopmentError(f"{label} is not a canonical SHA-256 digest")
    return value


def require_revision(value: Any, label: str = "expected_workspace_revision") -> int:
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise DevelopmentError(f"{label} is invalid")
    return value


def require_idempotency_key(value: Any) -> str:
    return require_text(value, "idempotency_key", MAX_IDEMPOTENCY_BYTES)


def require_case_policy(value: Any) -> str:
    if value not in CASE_POLICIES:
        raise DevelopmentError("case_policy is invalid")
    return str(value)


def normalize_path(value: Any, *, allow_manifest: bool = True) -> str:
    path = unicodedata.normalize("NFC", require_text(value, "path", MAX_PATH_BYTES))
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise DevelopmentError("path is too long")
    if "\\" in path or path.startswith("/") or path.endswith("/"):
        raise DevelopmentError("path must be relative and use forward slashes")
    parts = path.split("/")
    if not parts or len(parts) > MAX_TREE_DEPTH:
        raise DevelopmentError("path depth is outside its bound")
    if any(part in {"", ".", ".."} for part in parts):
        raise DevelopmentError("path contains a forbidden segment")
    if any(
        part.endswith((".", " "))
        or ":" in part
        or any(ord(character) < 32 for character in part)
        for part in parts
    ):
        raise DevelopmentError("path contains a non-portable segment")
    reserved = {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    reserved.update(f"COM{index}" for index in range(1, 10))
    reserved.update(f"LPT{index}" for index in range(1, 10))
    if any(part.split(".", 1)[0].upper() in reserved for part in parts):
        raise DevelopmentError("path contains a reserved device segment")
    if not allow_manifest and path == "spell-project.yaml":
        raise DevelopmentError("project manifest is managed by the project service")
    return path


def path_identity(path: str, case_policy: str) -> str:
    normalized = normalize_path(path)
    return normalized if require_case_policy(case_policy) == "CASE_SENSITIVE" else normalized.casefold()


def canonical_json_bytes(value: Any) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise DevelopmentError("value is not canonical finite JSON data") from exc
    return raw


def strict_json_bytes(raw: bytes, label: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DevelopmentError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                DevelopmentError(f"{label} contains a non-finite number")
            ),
        )
    except DevelopmentError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise DevelopmentError(f"{label} is not strict UTF-8 JSON") from exc
    if canonical_json_bytes(value) != raw:
        raise DevelopmentError(f"{label} is not canonical JSON")
    return value


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_request_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(dict(value)))


def canonical_tree(
    resources: Iterable[Mapping[str, Any]],
    *,
    case_policy: str,
) -> tuple[bytes, str]:
    seen: set[str] = set()
    entries: list[dict[str, Any]] = []
    total = 0
    for resource in resources:
        path = normalize_path(resource.get("path"))
        identity = path_identity(path, case_policy)
        if identity in seen:
            raise DevelopmentConflictError(
                "resource paths collide under the project case policy",
                code="CASE_CONFLICT",
                current={"path": path},
            )
        seen.add(identity)
        kind = resource.get("kind")
        if kind not in RESOURCE_KINDS:
            raise DevelopmentError("resource kind is invalid")
        content = resource.get("content", b"")
        if type(content) is not bytes or len(content) > MAX_RESOURCE_BYTES:
            raise DevelopmentError("resource bytes are outside their bound")
        total += len(content)
        entries.append(
            {
                "content_sha256": sha256_bytes(content),
                "kind": kind,
                "media_type": require_text(
                    resource.get("media_type", "application/octet-stream"),
                    "media_type",
                    160,
                ),
                "path": path,
                "size": len(content),
            }
        )
    if len(entries) > MAX_RESOURCES or total > MAX_PROJECT_BYTES:
        raise DevelopmentLimitError("project resources exceed their bound")
    raw = canonical_json_bytes({"entries": sorted(entries, key=lambda item: item["path"].encode("utf-8"))})
    return raw, sha256_bytes(raw)


__all__ = [
    "Actor",
    "CASE_POLICIES",
    "CHECK_SCOPES",
    "DevelopmentAuthorizationError",
    "DevelopmentConflictError",
    "DevelopmentCorruptionError",
    "DevelopmentError",
    "DevelopmentLimitError",
    "DevelopmentNotFoundError",
    "MAX_PROJECT_BYTES",
    "MAX_RESOURCE_BYTES",
    "MAX_RESOURCES",
    "PROMOTION_OPERATIONS",
    "RESOURCE_KINDS",
    "canonical_json_bytes",
    "canonical_request_digest",
    "canonical_tree",
    "normalize_path",
    "path_identity",
    "require_actor",
    "require_admin",
    "require_case_policy",
    "require_digest",
    "require_idempotency_key",
    "require_identifier",
    "require_mutation_actor",
    "require_revision",
    "require_text",
    "sha256_bytes",
    "strict_json_bytes",
]
