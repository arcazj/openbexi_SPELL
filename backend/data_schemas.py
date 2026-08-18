"""Strict HTTP schemas for the bounded v0.8 local data API."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
)

from .data_values import contract_integer_from_wire


MAXIMUM_JSON_BYTES = 1_048_576
MAXIMUM_IMPORT_BYTES = 16_777_216
MAXIMUM_FILE_BYTES = 16_777_216
MAXIMUM_PAGE_SIZE = 256
MAXIMUM_IDEMPOTENCY_KEY_BYTES = 128
DICTIONARY_IMPORT_MEDIA_TYPES = frozenset(
    {
        "application/vnd.openbexi.spell.dictionary-db+json",
        "application/vnd.openbexi.spell.dictionary-imp+json",
    }
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _nonnegative_revision(value: Any) -> int:
    return contract_integer_from_wire(value, label="revision")


def _positive_revision(value: Any) -> int:
    return contract_integer_from_wire(value, allow_zero=False, label="revision")


WireRevision = Annotated[int, BeforeValidator(_nonnegative_revision)]
WirePositiveRevision = Annotated[int, BeforeValidator(_positive_revision)]


class StrictDataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _identifier(value: str, label: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} must be a bounded ASCII identifier")
    return value


class ExpectedRevision(StrictDataModel):
    expected_revision: WireRevision


class CatalogEntryRequest(StrictDataModel):
    entry_id: StrictStr
    qualified_name: StrictStr = Field(min_length=1, max_length=256)
    content: dict[str, Any]

    @field_validator("entry_id")
    @classmethod
    def validate_entry_id(cls, value: str) -> str:
        return _identifier(value, "entry_id")


class CatalogDependencyRequest(StrictDataModel):
    dependency_id: StrictStr
    target_catalog_id: StrictStr
    target_revision: WirePositiveRevision
    target_content_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    relationship: Literal["IMPORTS", "REFERENCES", "MAPS_TO"]

    @field_validator("dependency_id", "target_catalog_id")
    @classmethod
    def validate_dependency_id(cls, value: str) -> str:
        return _identifier(value, "identifier")


class CatalogPublishRequest(ExpectedRevision):
    kind: Literal["SCDB", "GDB", "PROC", "MMD", "USER_DICTIONARY"]
    schema_version: StrictStr = Field(min_length=1, max_length=80)
    entries: list[CatalogEntryRequest] = Field(max_length=100_000)
    dependencies: list[CatalogDependencyRequest] = Field(
        default_factory=list, max_length=128
    )


class ContainerCreateRequest(ExpectedRevision):
    schema_revision: WirePositiveRevision


class ContainerSetRequest(ExpectedRevision):
    expected_variable_revision: WireRevision
    name: StrictStr = Field(min_length=1, max_length=256)
    declared_type: Literal["BOOLEAN", "LONG", "FLOAT", "STRING", "DATETIME", "RELTIME"]
    value: dict[str, Any]


class ContainerDeleteRequest(ExpectedRevision):
    expected_variable_revision: WirePositiveRevision


class NamespaceCreateRequest(ExpectedRevision):
    scope: Literal["PROJECT", "CONTEXT", "EXECUTION"]


class SharedPutRequest(StrictDataModel):
    value: dict[str, Any]
    expected_namespace_revision: WirePositiveRevision
    expected_entry_revision: WireRevision


class SharedDeleteRequest(StrictDataModel):
    expected_namespace_revision: WirePositiveRevision
    expected_entry_revision: WirePositiveRevision


class SharedClearRequest(StrictDataModel):
    expected_namespace_revision: WirePositiveRevision
    maximum_affected_entries: StrictInt = Field(ge=0, le=4096)


class NamespaceDeleteRequest(StrictDataModel):
    expected_namespace_revision: WirePositiveRevision


class DirectoryCreateRequest(ExpectedRevision):
    virtual_path: StrictStr = Field(min_length=1)


class FileDeleteRequest(ExpectedRevision):
    virtual_path: StrictStr = Field(min_length=1)


class FileOpenRequest(StrictDataModel):
    root_id: StrictStr
    virtual_path: StrictStr
    mode: Literal["READ", "WRITE", "READ_WRITE", "APPEND"]
    revision: WireRevision | None = None

    @field_validator("root_id")
    @classmethod
    def validate_root_id(cls, value: str) -> str:
        return _identifier(value, "root_id")


class FileHandleRequest(StrictDataModel):
    handle: StrictStr = Field(min_length=43, max_length=64)


class DataErrorResponse(StrictDataModel):
    code: StrictStr
    detail: StrictStr
    current_revision: StrictStr | None = None


def require_sha256(value: str) -> str:
    if _DIGEST.fullmatch(value) is None:
        raise ValueError("Content-SHA256 must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "CatalogPublishRequest",
    "CatalogDependencyRequest",
    "CatalogEntryRequest",
    "ContainerCreateRequest",
    "ContainerDeleteRequest",
    "ContainerSetRequest",
    "DICTIONARY_IMPORT_MEDIA_TYPES",
    "DataErrorResponse",
    "DirectoryCreateRequest",
    "FileDeleteRequest",
    "FileHandleRequest",
    "FileOpenRequest",
    "MAXIMUM_FILE_BYTES",
    "MAXIMUM_IDEMPOTENCY_KEY_BYTES",
    "MAXIMUM_IMPORT_BYTES",
    "MAXIMUM_JSON_BYTES",
    "MAXIMUM_PAGE_SIZE",
    "NamespaceCreateRequest",
    "NamespaceDeleteRequest",
    "SharedClearRequest",
    "SharedDeleteRequest",
    "SharedPutRequest",
    "StrictDataModel",
    "WirePositiveRevision",
    "WireRevision",
    "require_sha256",
]
