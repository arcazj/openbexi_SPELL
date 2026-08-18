"""Strict, non-executing DB and IMP dictionary exchange for SPELL v0.8."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from .data_domain import (
    DataValidationError,
    canonical_json_bytes,
    require_digest,
    require_expected_revision,
    require_identifier,
    require_nfc_string,
)
from .data_values import TypedValueError, strict_json_loads, typed_value_digest, validate_typed_value


DB_MEDIA_TYPE = "application/vnd.openbexi.spell.dictionary-db+json"
IMP_MEDIA_TYPE = "application/vnd.openbexi.spell.dictionary-imp+json"
DB_SCHEMA_VERSION = "spell.dictionary.db/1"
IMP_SCHEMA_VERSION = "spell.dictionary.imp/1"
MAX_DOCUMENT_BYTES = 16_777_216
MAX_ENTRIES = 100_000
MAX_ENTRY_BYTES = 2_097_152
MAX_IDENTIFIER_BYTES = 256
MAX_PARSE_DEPTH = 12
MAX_DIAGNOSTICS = 256


class DictionaryExchangeError(DataValidationError):
    def __init__(self, code: str, message: str, *, diagnostics: Iterable[str] = ()):
        super().__init__(message)
        self.code = code
        self.diagnostics = tuple(diagnostics)[:MAX_DIAGNOSTICS]


class DictionaryFormat(str, Enum):
    DB = "DB"
    IMP = "IMP"

    @property
    def schema_version(self) -> str:
        return DB_SCHEMA_VERSION if self is DictionaryFormat.DB else IMP_SCHEMA_VERSION

    @property
    def media_type(self) -> str:
        return DB_MEDIA_TYPE if self is DictionaryFormat.DB else IMP_MEDIA_TYPE


class ImportOperation(str, Enum):
    UPSERT = "UPSERT"
    DELETE = "DELETE"


def _canonical_document_digest(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_digest", None)
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def _closed_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(key) is not str for key in value):
        raise DictionaryExchangeError(
            "CORRUPT_DOCUMENT", f"{label} does not have its exact closed-world fields"
        )
    return value


def _measure_depth(value: Any, depth: int = 1) -> None:
    if depth > MAX_PARSE_DEPTH:
        raise DictionaryExchangeError("LIMIT_EXCEEDED", "dictionary parse depth exceeds 12")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise DictionaryExchangeError("CORRUPT_DOCUMENT", "dictionary key is not text")
            _measure_depth(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _measure_depth(item, depth + 1)


def _dictionary_id(value: Any) -> str:
    try:
        return require_identifier(
            value, "dictionary_id", maximum_bytes=MAX_IDENTIFIER_BYTES
        )
    except DataValidationError as exc:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", str(exc)) from exc


def _entry_id(value: Any) -> str:
    try:
        return require_identifier(value, "entry_id", maximum_bytes=MAX_IDENTIFIER_BYTES)
    except DataValidationError as exc:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", str(exc)) from exc


def _qualified_name(value: Any) -> str:
    try:
        return require_nfc_string(value, "qualified_name", MAX_IDENTIFIER_BYTES)
    except DataValidationError as exc:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", str(exc)) from exc


def _typed_value(value: Any, supplied_digest: Any) -> tuple[dict[str, Any], str]:
    try:
        canonical = validate_typed_value(value)
        calculated = typed_value_digest(canonical)
        expected = require_digest(supplied_digest, "value_digest")
    except (TypedValueError, DataValidationError) as exc:
        code = exc.code if isinstance(exc, TypedValueError) and exc.code == "LIMIT_EXCEEDED" else "CORRUPT_DOCUMENT"
        raise DictionaryExchangeError(code, "dictionary typed value is invalid") from exc
    if calculated != expected:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", "dictionary value digest differs")
    return canonical, calculated


@dataclass(frozen=True, slots=True)
class DictionaryEntry:
    entry_id: str
    qualified_name: str
    value: dict[str, Any]
    value_digest: str

    @classmethod
    def from_payload(cls, payload: Any) -> "DictionaryEntry":
        item = _closed_object(
            payload,
            {"entry_id", "qualified_name", "value", "value_digest"},
            "DB entry",
        )
        entry_id = _entry_id(item["entry_id"])
        qualified_name = _qualified_name(item["qualified_name"])
        value, digest = _typed_value(item["value"], item["value_digest"])
        result = cls(entry_id, qualified_name, value, digest)
        if len(canonical_json_bytes(result.as_payload())) > MAX_ENTRY_BYTES:
            raise DictionaryExchangeError("LIMIT_EXCEEDED", "dictionary entry exceeds its byte limit")
        return result

    def as_payload(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "qualified_name": self.qualified_name,
            "value": self.value,
            "value_digest": self.value_digest,
        }


@dataclass(frozen=True, slots=True)
class DictionaryRecord:
    operation: ImportOperation
    entry_id: str
    expected_entry_revision: int
    qualified_name: str | None = None
    value: dict[str, Any] | None = None
    value_digest: str | None = None

    @classmethod
    def from_payload(cls, payload: Any) -> "DictionaryRecord":
        if type(payload) is not dict or type(payload.get("operation")) is not str:
            raise DictionaryExchangeError("CORRUPT_DOCUMENT", "IMP record is invalid")
        try:
            operation = ImportOperation(payload["operation"])
        except ValueError as exc:
            raise DictionaryExchangeError("CORRUPT_DOCUMENT", "IMP operation is unsupported") from exc
        common = {"operation", "entry_id", "expected_entry_revision"}
        fields = common | (
            {"qualified_name", "value", "value_digest"}
            if operation is ImportOperation.UPSERT
            else set()
        )
        item = _closed_object(payload, fields, "IMP record")
        entry_id = _entry_id(item["entry_id"])
        try:
            expected = require_expected_revision(
                item["expected_entry_revision"], "expected_entry_revision"
            )
        except DataValidationError as exc:
            raise DictionaryExchangeError("CORRUPT_DOCUMENT", str(exc)) from exc
        if operation is ImportOperation.DELETE:
            if expected == 0:
                raise DictionaryExchangeError(
                    "CORRUPT_DOCUMENT", "IMP DELETE requires a live positive revision"
                )
            return cls(operation, entry_id, expected)
        qualified_name = _qualified_name(item["qualified_name"])
        value, digest = _typed_value(item["value"], item["value_digest"])
        result = cls(operation, entry_id, expected, qualified_name, value, digest)
        if len(canonical_json_bytes(result.as_payload())) > MAX_ENTRY_BYTES:
            raise DictionaryExchangeError("LIMIT_EXCEEDED", "IMP record exceeds its byte limit")
        return result

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "entry_id": self.entry_id,
            "expected_entry_revision": self.expected_entry_revision,
            "operation": self.operation.value,
        }
        if self.operation is ImportOperation.UPSERT:
            payload.update(
                {
                    "qualified_name": self.qualified_name,
                    "value": self.value,
                    "value_digest": self.value_digest,
                }
            )
        return payload


@dataclass(frozen=True, slots=True)
class DictionaryDocument:
    format: DictionaryFormat
    dictionary_id: str
    base_revision: int
    content_digest: str
    entries: tuple[DictionaryEntry, ...] = ()
    records: tuple[DictionaryRecord, ...] = ()
    original_bytes: bytes = b""
    original_bytes_sha256: str = ""

    @property
    def schema_version(self) -> str:
        return self.format.schema_version

    def unsigned_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "base_revision": self.base_revision,
            "dictionary_id": self.dictionary_id,
            "format": self.format.value,
            "schema_version": self.schema_version,
        }
        if self.format is DictionaryFormat.DB:
            payload["entries"] = [entry.as_payload() for entry in self.entries]
        else:
            payload["records"] = [record.as_payload() for record in self.records]
        return payload

    def as_payload(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "content_digest": self.content_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.as_payload())

    @property
    def canonical_document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def _validate_unique_entries(entries: tuple[DictionaryEntry, ...]) -> None:
    ids: set[str] = set()
    folded_ids: set[str] = set()
    folded_names: set[str] = set()
    for entry in entries:
        folded_id = entry.entry_id.casefold()
        folded_name = entry.qualified_name.casefold()
        if entry.entry_id in ids:
            raise DictionaryExchangeError("DUPLICATE_ENTRY", "dictionary entry identity is duplicated")
        if folded_id in folded_ids or folded_name in folded_names:
            raise DictionaryExchangeError("CASE_COLLISION", "dictionary entry has a case collision")
        ids.add(entry.entry_id)
        folded_ids.add(folded_id)
        folded_names.add(folded_name)


def _validate_unique_records(records: tuple[DictionaryRecord, ...]) -> None:
    targets: set[str] = set()
    for record in records:
        if record.entry_id in targets:
            raise DictionaryExchangeError(
                "DUPLICATE_ENTRY_TARGET", "IMP targets one entry more than once"
            )
        targets.add(record.entry_id)


def _new_document(
    *,
    format: DictionaryFormat,
    dictionary_id: Any,
    base_revision: Any,
    entries: Iterable[DictionaryEntry] = (),
    records: Iterable[DictionaryRecord] = (),
    original_bytes: bytes = b"",
) -> DictionaryDocument:
    dictionary_id = _dictionary_id(dictionary_id)
    try:
        base_revision = require_expected_revision(base_revision, "base_revision")
    except DataValidationError as exc:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", str(exc)) from exc
    entry_tuple = tuple(sorted(entries, key=lambda entry: entry.entry_id.encode("ascii")))
    record_tuple = tuple(sorted(records, key=lambda record: record.entry_id.encode("ascii")))
    if len(entry_tuple if format is DictionaryFormat.DB else record_tuple) > MAX_ENTRIES:
        raise DictionaryExchangeError("LIMIT_EXCEEDED", "dictionary entry bound exceeded")
    if format is DictionaryFormat.DB:
        if record_tuple:
            raise DictionaryExchangeError("CORRUPT_DOCUMENT", "DB cannot contain IMP records")
        _validate_unique_entries(entry_tuple)
    else:
        if entry_tuple:
            raise DictionaryExchangeError("CORRUPT_DOCUMENT", "IMP cannot contain DB entries")
        _validate_unique_records(record_tuple)
    provisional = DictionaryDocument(
        format,
        dictionary_id,
        base_revision,
        "0" * 64,
        entry_tuple,
        record_tuple,
        original_bytes,
        hashlib.sha256(original_bytes).hexdigest() if original_bytes else "",
    )
    digest = hashlib.sha256(canonical_json_bytes(provisional.unsigned_payload())).hexdigest()
    document = DictionaryDocument(
        format,
        dictionary_id,
        base_revision,
        digest,
        entry_tuple,
        record_tuple,
        original_bytes,
        hashlib.sha256(original_bytes).hexdigest() if original_bytes else "",
    )
    if len(document.canonical_bytes) > MAX_DOCUMENT_BYTES:
        raise DictionaryExchangeError("LIMIT_EXCEEDED", "dictionary document exceeds its byte limit")
    return document


def parse_dictionary_document(
    payload: bytes,
    *,
    media_type: str | None = None,
) -> DictionaryDocument:
    if type(payload) is not bytes:
        raise TypeError("dictionary document must be exact source bytes")
    try:
        decoded = strict_json_loads(payload, maximum_bytes=MAX_DOCUMENT_BYTES)
    except TypedValueError as exc:
        code = "LIMIT_EXCEEDED" if exc.code == "LIMIT_EXCEEDED" else "CORRUPT_DOCUMENT"
        raise DictionaryExchangeError(code, "dictionary document is not strict JSON") from exc
    _measure_depth(decoded)
    if type(decoded) is not dict:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", "dictionary document must be an object")
    try:
        format = DictionaryFormat(decoded.get("format"))
    except (TypeError, ValueError) as exc:
        raise DictionaryExchangeError("FORMAT_UNSUPPORTED", "dictionary format is unsupported") from exc
    if media_type is not None and media_type != format.media_type:
        raise DictionaryExchangeError("FORMAT_UNSUPPORTED", "dictionary media type differs")
    if decoded.get("schema_version") != format.schema_version:
        raise DictionaryExchangeError("SCHEMA_UNSUPPORTED", "dictionary schema is unsupported")
    expected_fields = {
        "base_revision",
        "content_digest",
        "dictionary_id",
        "entries" if format is DictionaryFormat.DB else "records",
        "format",
        "schema_version",
    }
    document_payload = _closed_object(decoded, expected_fields, "dictionary document")
    sequence_name = "entries" if format is DictionaryFormat.DB else "records"
    sequence = document_payload[sequence_name]
    if type(sequence) is not list:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", f"{sequence_name} must be an array")
    if len(sequence) > MAX_ENTRIES:
        raise DictionaryExchangeError("LIMIT_EXCEEDED", "dictionary entry bound exceeded")
    entries = (
        tuple(DictionaryEntry.from_payload(item) for item in sequence)
        if format is DictionaryFormat.DB
        else ()
    )
    records = (
        tuple(DictionaryRecord.from_payload(item) for item in sequence)
        if format is DictionaryFormat.IMP
        else ()
    )
    document = _new_document(
        format=format,
        dictionary_id=document_payload["dictionary_id"],
        base_revision=document_payload["base_revision"],
        entries=entries,
        records=records,
        original_bytes=payload,
    )
    try:
        supplied = require_digest(document_payload["content_digest"], "content_digest")
    except DataValidationError as exc:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", str(exc)) from exc
    if supplied != document.content_digest:
        raise DictionaryExchangeError("CORRUPT_DOCUMENT", "dictionary content digest differs")
    return document


def build_db_document(
    dictionary_id: str,
    base_revision: int,
    entries: Iterable[DictionaryEntry],
) -> DictionaryDocument:
    return _new_document(
        format=DictionaryFormat.DB,
        dictionary_id=dictionary_id,
        base_revision=base_revision,
        entries=entries,
    )


def build_imp_document(
    dictionary_id: str,
    base_revision: int,
    records: Iterable[DictionaryRecord],
) -> DictionaryDocument:
    return _new_document(
        format=DictionaryFormat.IMP,
        dictionary_id=dictionary_id,
        base_revision=base_revision,
        records=records,
    )


def export_dictionary_document(document: DictionaryDocument) -> bytes:
    if type(document) is not DictionaryDocument:
        raise TypeError("document must be a DictionaryDocument")
    if _canonical_document_digest(document.as_payload()) != document.content_digest:
        raise DictionaryExchangeError("CORRUPT_DICTIONARY", "dictionary document digest differs")
    return document.canonical_bytes


__all__ = [
    "DB_MEDIA_TYPE",
    "DB_SCHEMA_VERSION",
    "IMP_MEDIA_TYPE",
    "IMP_SCHEMA_VERSION",
    "DictionaryDocument",
    "DictionaryEntry",
    "DictionaryExchangeError",
    "DictionaryFormat",
    "DictionaryRecord",
    "ImportOperation",
    "build_db_document",
    "build_imp_document",
    "export_dictionary_document",
    "parse_dictionary_document",
]
