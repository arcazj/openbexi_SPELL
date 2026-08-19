"""Strict decoders for durable v0.8 dictionary and container state."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .data_domain import (
    DataCorruptionError,
    DataValidationError,
    canonical_json_bytes,
    require_digest,
    require_identifier,
    require_nfc_string,
    require_positive_revision,
    sha256_digest,
)
from .data_values import (
    TypedValueError,
    strict_json_loads,
    typed_value_digest,
    validate_typed_value,
)


MAX_INTERNAL_STATE_BYTES = 16_777_216
MAX_DICTIONARY_ENTRIES = 100_000
MAX_CONTAINER_VARIABLES = 4096
DECLARED_TYPE_MAPPING = {
    "BOOLEAN": "BOOLEAN",
    "LONG": "INT64",
    "FLOAT": "FINITE_DOUBLE",
    "STRING": "STRING",
    "DATETIME": "UTC_DATETIME",
    "RELTIME": "REL_DURATION",
}


class CorruptDictionaryError(DataCorruptionError):
    code = "CORRUPT_DICTIONARY"


class CorruptContainerError(DataCorruptionError):
    code = "CORRUPT_CONTAINER"


def _strict_internal_state(
    raw: bytes | str,
    expected_digest: str,
    *,
    schema_version: str,
    corruption_type: type[DataCorruptionError],
) -> dict[str, Any]:
    try:
        source = raw.encode("utf-8") if isinstance(raw, str) else raw
        if type(source) is not bytes or sha256_digest(source) != expected_digest:
            raise corruption_type("stored state digest differs")
        payload = strict_json_loads(source, maximum_bytes=MAX_INTERNAL_STATE_BYTES)
        if canonical_json_bytes(payload) != source:
            raise corruption_type("stored state is not canonical")
        if type(payload) is not dict or payload.get("schema_version") != schema_version:
            raise corruption_type("stored state schema differs")
        return payload
    except (TypedValueError, DataValidationError) as exc:
        if isinstance(exc, corruption_type):
            raise
        raise corruption_type("stored state is corrupt") from exc


def decode_dictionary_state(
    raw: bytes | str, expected_digest: str
) -> tuple[dict[str, Any], ...]:
    payload = _strict_internal_state(
        raw,
        expected_digest,
        schema_version="spell.data.dictionary-state/1",
        corruption_type=CorruptDictionaryError,
    )
    if set(payload) != {"entries", "schema_version"} or type(payload["entries"]) is not list:
        raise CorruptDictionaryError("dictionary state fields differ")
    if len(payload["entries"]) > MAX_DICTIONARY_ENTRIES:
        raise CorruptDictionaryError("dictionary state entry count is exceeded")
    entries: list[dict[str, Any]] = []
    identities: set[str] = set()
    for item in payload["entries"]:
        fields = {
            "entry_id",
            "qualified_name",
            "revision",
            "tombstoned",
            "value",
            "value_digest",
        }
        if type(item) is not dict or set(item) != fields:
            raise CorruptDictionaryError("dictionary state entry fields differ")
        try:
            entry_id = require_identifier(item["entry_id"], "entry_id", maximum_bytes=256)
            name = require_nfc_string(item["qualified_name"], "qualified_name", 256)
            revision = require_positive_revision(item["revision"], "entry revision")
            digest = require_digest(item["value_digest"], "value_digest")
        except DataValidationError as exc:
            raise CorruptDictionaryError("dictionary state entry is invalid") from exc
        if type(item["tombstoned"]) is not bool or entry_id in identities:
            raise CorruptDictionaryError("dictionary state identity is invalid")
        identities.add(entry_id)
        value = item["value"]
        if item["tombstoned"]:
            if value is not None:
                raise CorruptDictionaryError("dictionary tombstone exposes a value")
        else:
            try:
                value = validate_typed_value(value)
                if typed_value_digest(value) != digest:
                    raise CorruptDictionaryError("dictionary entry digest differs")
            except TypedValueError as exc:
                raise CorruptDictionaryError("dictionary entry is corrupt") from exc
        entries.append(
            {
                "entry_id": entry_id,
                "qualified_name": name,
                "revision": revision,
                "tombstoned": item["tombstoned"],
                "value": value,
                "value_digest": digest,
            }
        )
    if entries != sorted(entries, key=lambda item: item["entry_id"].encode("ascii")):
        raise CorruptDictionaryError("dictionary state order differs")
    return tuple(entries)


def decode_container_state(
    raw: bytes | str, expected_digest: str
) -> tuple[dict[str, Any], ...]:
    payload = _strict_internal_state(
        raw,
        expected_digest,
        schema_version="spell.data.container-state/1",
        corruption_type=CorruptContainerError,
    )
    if set(payload) != {"schema_version", "variables"} or type(payload["variables"]) is not list:
        raise CorruptContainerError("container state fields differ")
    if len(payload["variables"]) > MAX_CONTAINER_VARIABLES:
        raise CorruptContainerError("container variable count is exceeded")
    variables: list[dict[str, Any]] = []
    identities: set[str] = set()
    names: set[str] = set()
    expected_fields = {
        "declared_type",
        "name",
        "revision",
        "tombstoned",
        "value",
        "value_digest",
        "variable_id",
    }
    for item in payload["variables"]:
        if type(item) is not dict or set(item) != expected_fields:
            raise CorruptContainerError("container variable fields differ")
        try:
            variable_id = require_identifier(
                item["variable_id"], "variable_id", maximum_bytes=128
            )
            name = require_nfc_string(item["name"], "variable name", 256)
            revision = require_positive_revision(item["revision"], "variable revision")
            digest = require_digest(item["value_digest"], "value_digest")
        except DataValidationError as exc:
            raise CorruptContainerError("container variable is invalid") from exc
        declared_type = item["declared_type"]
        if (
            declared_type not in DECLARED_TYPE_MAPPING
            or type(item["tombstoned"]) is not bool
            or variable_id in identities
            or (not item["tombstoned"] and name in names)
        ):
            raise CorruptContainerError("container variable identity differs")
        identities.add(variable_id)
        if not item["tombstoned"]:
            names.add(name)
        value = item["value"]
        if item["tombstoned"]:
            if value is not None:
                raise CorruptContainerError("container tombstone exposes a value")
        else:
            try:
                value = validate_typed_value(value)
                if (
                    value["type"] != DECLARED_TYPE_MAPPING[declared_type]
                    or typed_value_digest(value) != digest
                ):
                    raise CorruptContainerError("container value digest or type differs")
            except TypedValueError as exc:
                raise CorruptContainerError("container value is corrupt") from exc
        variables.append(
            {
                "declared_type": declared_type,
                "name": name,
                "revision": revision,
                "tombstoned": item["tombstoned"],
                "value": value,
                "value_digest": digest,
                "variable_id": variable_id,
            }
        )
    if variables != sorted(
        variables, key=lambda item: item["variable_id"].encode("ascii")
    ):
        raise CorruptContainerError("container variable order differs")
    return tuple(variables)


def _require_contiguous_revisions(
    rows: list[Mapping[str, Any]],
    *,
    maximum_revision: int,
    corruption_type: type[DataCorruptionError],
    label: str,
) -> None:
    if len(rows) != maximum_revision or any(
        row["revision"] != expected_revision
        for expected_revision, row in enumerate(rows, 1)
    ):
        raise corruption_type(f"{label} revision chain differs")


def validate_dictionary_history(
    revisions: Iterable[
        tuple[Mapping[str, Any], tuple[dict[str, Any], ...] | None]
    ],
    *,
    current_revision: int,
) -> None:
    ordered = sorted(revisions, key=lambda item: item[0]["revision"])
    rows = [item[0] for item in ordered]
    _require_contiguous_revisions(
        rows,
        maximum_revision=current_revision,
        corruption_type=CorruptDictionaryError,
        label="dictionary",
    )
    prior: dict[str, dict[str, Any]] = {}
    historical_identities: dict[str, str] = {}
    for row, state in ordered:
        revision = row["revision"]
        if row["base_revision"] != revision - 1 or state is None:
            raise CorruptDictionaryError("dictionary base revision differs")
        current = {item["entry_id"]: item for item in state}
        if not set(prior).issubset(current):
            raise CorruptDictionaryError("dictionary history discarded an entry")
        for entry_id, item in current.items():
            previous = prior.get(entry_id)
            if previous is None:
                folded = entry_id.casefold()
                if (
                    item["revision"] != 1
                    or item["tombstoned"]
                    or (
                        folded in historical_identities
                        and historical_identities[folded] != entry_id
                    )
                ):
                    raise CorruptDictionaryError(
                        "dictionary entry creation history differs"
                    )
                historical_identities[folded] = entry_id
                continue
            if previous["tombstoned"]:
                if item != previous:
                    raise CorruptDictionaryError(
                        "dictionary tombstone was changed or resurrected"
                    )
                continue
            if item["revision"] not in {
                previous["revision"],
                previous["revision"] + 1,
            }:
                raise CorruptDictionaryError("dictionary entry revision differs")
            previous_projection = {
                key: value for key, value in previous.items() if key != "revision"
            }
            current_projection = {
                key: value for key, value in item.items() if key != "revision"
            }
            if (
                current_projection != previous_projection
                and item["revision"] != previous["revision"] + 1
            ):
                raise CorruptDictionaryError(
                    "dictionary entry mutation revision differs"
                )
            if item["tombstoned"] and (
                item["value_digest"] != previous["value_digest"]
                or item["qualified_name"] != previous["qualified_name"]
            ):
                raise CorruptDictionaryError("dictionary tombstone binding differs")
        if any(item["revision"] > revision for item in current.values()):
            raise CorruptDictionaryError("dictionary entry revision is ahead")
        prior = {entry_id: dict(item) for entry_id, item in current.items()}


def runtime_container_commit_digest(
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
    if type(worker_generation) is not int or worker_generation < 0:
        raise CorruptContainerError("runtime worker generation differs")
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


def validate_container_history(
    head: Mapping[str, Any],
    revisions: Iterable[
        tuple[Mapping[str, Any], tuple[dict[str, Any], ...] | None]
    ],
) -> None:
    ordered = sorted(revisions, key=lambda item: item[0]["revision"])
    rows = [item[0] for item in ordered]
    _require_contiguous_revisions(
        rows,
        maximum_revision=head["current_revision"],
        corruption_type=CorruptContainerError,
        label="container",
    )
    runtime = head["kind"] in {"LOCAL", "ARGS", "IVARS"}
    if runtime:
        if (
            head["execution_id"] != head["owner_id"]
            or head["container_id"] != f"{head['owner_id']}.{head['kind']}"
        ):
            raise CorruptContainerError("runtime container ownership differs")
    prior_state: dict[str, dict[str, Any]] = {}
    prior_row: Mapping[str, Any] | None = None
    for row, state in ordered:
        revision = row["revision"]
        if state is None or row["schema_revision"] != head["schema_revision"]:
            raise CorruptContainerError("container schema binding differs")
        if runtime:
            if (
                row["checkpoint_sequence"] is None
                or row["execution_revision"] is None
                or row["worker_generation"] is None
                or row["created_by_principal"] != "procedure-runtime"
            ):
                raise CorruptContainerError("runtime checkpoint binding differs")
            if prior_row is None:
                expected_commit = runtime_container_commit_digest(
                    caller_digest=head["admission_binding_digest"],
                    worker_generation=head["admission_worker_generation"],
                    container_id=head["container_id"],
                    container_revision=1,
                    content_digest=row["content_digest"],
                    checkpoint_sequence=0,
                    execution_revision=head["admission_execution_revision"],
                )
                if (
                    row["checkpoint_sequence"] != 0
                    or row["execution_revision"]
                    != head["admission_execution_revision"]
                    or row["worker_generation"]
                    != head["admission_worker_generation"]
                    or row["commit_binding_digest"] != expected_commit
                ):
                    raise CorruptContainerError(
                        "runtime admission revision binding differs"
                    )
            elif (
                row["checkpoint_sequence"] <= prior_row["checkpoint_sequence"]
                or row["execution_revision"] <= prior_row["execution_revision"]
                or row["worker_generation"] < prior_row["worker_generation"]
            ):
                raise CorruptContainerError("runtime checkpoint order differs")
        elif any(
            row[field] is not None
            for field in (
                "checkpoint_sequence",
                "execution_revision",
                "worker_generation",
            )
        ):
            raise CorruptContainerError("persistent container binding differs")

        current = {item["variable_id"]: item for item in state}
        if not set(prior_state).issubset(current):
            raise CorruptContainerError("container history discarded a variable")
        for variable_id, item in current.items():
            previous = prior_state.get(variable_id)
            if previous is None:
                if item["revision"] != 1 or item["tombstoned"]:
                    raise CorruptContainerError(
                        "container variable creation history differs"
                    )
                continue
            if (
                item["name"] != previous["name"]
                or item["declared_type"] != previous["declared_type"]
            ):
                raise CorruptContainerError("container declaration changed")
            if previous["tombstoned"]:
                if item != previous:
                    raise CorruptContainerError(
                        "container tombstone was changed or resurrected"
                    )
                continue
            if item["revision"] not in {
                previous["revision"],
                previous["revision"] + 1,
            }:
                raise CorruptContainerError("container variable revision differs")
            previous_projection = {
                key: value for key, value in previous.items() if key != "revision"
            }
            current_projection = {
                key: value for key, value in item.items() if key != "revision"
            }
            if (
                current_projection != previous_projection
                and item["revision"] != previous["revision"] + 1
            ):
                raise CorruptContainerError(
                    "container variable mutation revision differs"
                )
            if item["tombstoned"] and item["value_digest"] != previous["value_digest"]:
                raise CorruptContainerError("container tombstone binding differs")
        if any(item["revision"] > revision for item in current.values()):
            raise CorruptContainerError("container variable revision is ahead")
        prior_state = {
            variable_id: dict(item) for variable_id, item in current.items()
        }
        prior_row = row


def validate_shared_history(rows: Iterable[Mapping[str, Any]]) -> None:
    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        try:
            require_identifier(row["owner_id"], "owner_id", maximum_bytes=128)
            require_identifier(row["namespace_id"], "namespace_id", maximum_bytes=128)
            require_identifier(row["entry_id"], "entry_id", maximum_bytes=128)
            require_nfc_string(row["key"], "shared key", 512)
        except DataValidationError as exc:
            raise DataCorruptionError("shared entry identity differs") from exc
        grouped.setdefault(
            (
                row["scope"],
                row["owner_id"],
                row["namespace_id"],
                row["entry_id"],
            ),
            [],
        ).append(row)
    for history in grouped.values():
        ordered = sorted(history, key=lambda row: row["revision"])
        revisions = [row["revision"] for row in ordered]
        if revisions != list(range(1, len(ordered) + 1)):
            raise DataCorruptionError("shared entry revision chain differs")
        initial = ordered[0]
        if initial["tombstoned"]:
            raise DataCorruptionError("shared entry begins with a tombstone")
        key = initial["key"]
        for index, row in enumerate(ordered):
            if row["key"] != key:
                raise DataCorruptionError("shared entry key changed")
            if index and ordered[index - 1]["tombstoned"]:
                raise DataCorruptionError("shared tombstone was resurrected")
            if row["tombstoned"] and (
                index == 0
                or row["value_digest"] != ordered[index - 1]["value_digest"]
            ):
                raise DataCorruptionError("shared tombstone binding differs")


__all__ = [
    "CorruptContainerError",
    "CorruptDictionaryError",
    "DECLARED_TYPE_MAPPING",
    "decode_container_state",
    "decode_dictionary_state",
    "runtime_container_commit_digest",
    "validate_container_history",
    "validate_dictionary_history",
    "validate_shared_history",
]
