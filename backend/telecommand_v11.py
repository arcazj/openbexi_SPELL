"""Bounded v0.11 simulator telecommand domain.

This module models BuildTC and Send without adding a live driver route.  It
keeps operation progress, per-element stages, disposition, and effect
certainty independent so that an accepted transport or a loaded command can
never be reported as onboard execution success.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


CATALOG_SCHEMA_VERSION = "spell.v11.telecommand-catalog/1"
EXECUTION_SCHEMA_VERSION = "spell.v11.telecommand-execution/1"
PLAN_SCHEMA_VERSION = "spell.v11.telecommand-plan/1"
CHECKPOINT_SCHEMA_VERSION = "spell.v11.telecommand-checkpoint/1"
DEFAULT_CATALOG_SHA256 = "f60b574d18d4c3aa23c8c986b6ea3242e4e83fd41bc611f4ff6a37a15eb6e64c"
DEFAULT_EXECUTION_SHA256 = "d757eb602b03476ee512e8a89a714fae3024d3be3a4b590ebabca0dcd06021a3"
MAX_CONTRACT_BYTES = 131_072
MAX_CHECKPOINT_BYTES = 262_144
MAX_INTEGER_BITS = 4_096

_COMMAND_NAME = re.compile(r"[A-Z][A-Z0-9_.]{0,127}\Z")
_ARGUMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CHANNEL = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SECRET_KEY = re.compile(r"password|passwd|secret|token|credential|private.?key", re.I)


class TelecommandError(ValueError):
    """Base class for typed v0.11 telecommand failures."""

    def __init__(self, code: str, path: str, message: str):
        self.code = str(code)[:80]
        self.path = str(path)[:180]
        self.message = str(message)[:300]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class TelecommandContractError(TelecommandError):
    pass


class TelecommandValidationError(TelecommandError):
    pass


class ConfirmationRequired(TelecommandError):
    def __init__(self, challenge: str):
        self.challenge = challenge
        super().__init__(
            "TC_CONFIRMATION_REQUIRED",
            "$.confirmation",
            "explicit preflight confirmation is required before dispatch",
        )


class ProviderScriptError(TelecommandError):
    pass


class SimulatedProviderCrash(RuntimeError):
    """Deterministic crash after a provider action but before checkpointing."""

    def __init__(self, stage: str, element_id: str):
        self.stage = stage
        self.element_id = element_id
        super().__init__(f"simulated crash after {stage} for {element_id}")


def _reject(path: str, message: str, code: str = "TC_VALIDATION_FAILED") -> None:
    raise TelecommandValidationError(code, path, message)


def _finite_float(
    value: Any,
    path: str,
    *,
    code: str = "TC_VALIDATION_FAILED",
    message: str = "value must be a finite number",
) -> float:
    if type(value) not in {int, float} or type(value) is bool:
        _reject(path, message, code)
    if type(value) is int and value.bit_length() > MAX_INTEGER_BITS:
        _reject(path, message, code)
    try:
        normalized = float(value)
    except (OverflowError, ValueError) as exc:
        raise TelecommandValidationError(code, path, message) from exc
    if not math.isfinite(normalized):
        _reject(path, message, code)
    return normalized


def _contract_reject(path: str, message: str) -> None:
    raise TelecommandContractError("TC_CONTRACT_INVALID", path, message)


def _exact_keys(
    value: Mapping[str, Any], required: set[str], optional: set[str], path: str,
    *, contract: bool = False,
) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    fail = _contract_reject if contract else _reject
    if missing:
        fail(path, f"missing field {sorted(missing)[0]}")
    if unknown:
        fail(path, f"unknown field {sorted(unknown)[0]}")


def _walk_json(value: Any, path: str, depth: int = 0) -> None:
    if depth > 8:
        _reject(path, "JSON nesting exceeds 8 levels", "TC_JSON_BOUNDS")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            _reject(path, "integer is outside signed 64-bit bounds", "TC_JSON_BOUNDS")
        return
    if type(value) is float:
        if not math.isfinite(value):
            _reject(path, "number must be finite", "TC_JSON_INVALID")
        return
    if type(value) is str:
        if len(value) > 1024:
            _reject(path, "string exceeds 1024 characters", "TC_JSON_BOUNDS")
        return
    if type(value) is list:
        if len(value) > 64:
            _reject(path, "array exceeds 64 items", "TC_JSON_BOUNDS")
        for index, item in enumerate(value):
            _walk_json(item, f"{path}[{index}]", depth + 1)
        return
    if type(value) is dict:
        if len(value) > 64:
            _reject(path, "object exceeds 64 fields", "TC_JSON_BOUNDS")
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 128:
                _reject(path, "object keys must be bounded nonempty strings", "TC_JSON_INVALID")
            _walk_json(item, f"{path}.{key}", depth + 1)
        return
    _reject(path, "value is not finite JSON", "TC_JSON_INVALID")


def _canonical_bytes(value: Any, path: str = "$") -> bytes:
    _walk_json(value, path)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise TelecommandValidationError(
            "TC_JSON_INVALID", path, "value is not canonical finite JSON"
        ) from exc


def _canonical(value: Any, path: str = "$") -> Any:
    return json.loads(_canonical_bytes(value, path).decode("ascii"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _strict_json_loads(raw: bytes, *, max_bytes: int, path: str) -> dict[str, Any]:
    if not raw or len(raw) > max_bytes:
        raise TelecommandContractError(
            "TC_JSON_BOUNDS", path, f"JSON input must be 1..{max_bytes} bytes"
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise TelecommandContractError("TC_JSON_INVALID", path, "UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TelecommandContractError("TC_JSON_INVALID", path, "invalid UTF-8") from exc

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise TelecommandContractError(
                    "TC_JSON_INVALID", path, f"duplicate object key {key}"
                )
            result[key] = value
        return result

    def no_constants(value: str) -> None:
        raise TelecommandContractError(
            "TC_JSON_INVALID", path, f"non-finite number {value} is forbidden"
        )

    try:
        value = json.loads(
            text, object_pairs_hook=no_duplicates, parse_constant=no_constants
        )
    except TelecommandContractError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise TelecommandContractError("TC_JSON_INVALID", path, "malformed JSON") from exc
    if type(value) is not dict:
        _contract_reject(path, "top-level JSON value must be an object")
    try:
        detached = _canonical(value, path)
    except TelecommandValidationError as exc:
        raise TelecommandContractError(exc.code, exc.path, exc.message) from exc
    return detached


def default_catalog_path() -> Path:
    return Path(__file__).resolve().parents[1] / "contracts" / "v11" / "telecommand_catalog.json"


def default_execution_contract_path() -> Path:
    return Path(__file__).resolve().parents[1] / "contracts" / "v11" / "telecommand_execution.json"


@dataclass(frozen=True)
class CatalogLimits:
    max_json_bytes: int
    max_commands: int
    max_sequences: int
    max_arguments_per_command: int
    max_expanded_elements: int
    max_string_length: int
    max_provider_detail_bytes: int
    max_additional_info_bytes: int
    max_verifications_per_element: int
    max_timeout_ms: int
    max_delay_ms: int


@dataclass(frozen=True)
class ArgumentDefinition:
    name: str
    value_type: str
    required: bool
    has_default: bool
    default: Any
    minimum: int | float | None
    maximum: int | float | None
    allowed_values: tuple[Any, ...]
    allowed_formats: tuple[str, ...]


@dataclass(frozen=True)
class CommandDefinition:
    name: str
    critical: bool
    arguments: tuple[ArgumentDefinition, ...]


@dataclass(frozen=True)
class SequenceMember:
    command: str
    args: Mapping[str, Any]
    modifiers: Mapping[str, Any]


@dataclass(frozen=True)
class SequenceDefinition:
    name: str
    members: tuple[SequenceMember, ...]


def _validate_scalar(
    value: Any,
    definition: ArgumentDefinition,
    path: str,
    *,
    max_string_length: int = 256,
) -> Any:
    kind = definition.value_type
    if kind == "LONG":
        if type(value) is not int:
            _reject(path, "value must be a LONG integer", "TC_ARGUMENT_TYPE")
        if value.bit_length() > MAX_INTEGER_BITS:
            _reject(path, "LONG exceeds the integer safety bound", "TC_ARGUMENT_RANGE")
        normalized: Any = value
    elif kind == "FLOAT":
        normalized = _finite_float(
            value,
            path,
            code="TC_ARGUMENT_TYPE",
            message="value must be a finite FLOAT",
        )
    elif kind == "STRING":
        if type(value) is not str:
            _reject(path, "value must be a STRING", "TC_ARGUMENT_TYPE")
        if len(value) > max_string_length:
            _reject(path, "string exceeds the catalog length bound", "TC_ARGUMENT_RANGE")
        normalized = value
    elif kind == "BOOLEAN":
        if type(value) is not bool:
            _reject(path, "value must be a BOOLEAN", "TC_ARGUMENT_TYPE")
        normalized = value
    elif kind == "TIME":
        normalized = _absolute_time(value, path)
    else:
        _reject(path, f"unsupported catalog value type {kind}", "TC_ARGUMENT_TYPE")
    if type(normalized) in {int, float}:
        if definition.minimum is not None and normalized < definition.minimum:
            _reject(path, "value is below the catalog minimum", "TC_ARGUMENT_RANGE")
        if definition.maximum is not None and normalized > definition.maximum:
            _reject(path, "value is above the catalog maximum", "TC_ARGUMENT_RANGE")
    if definition.allowed_values and normalized not in definition.allowed_values:
        _reject(path, "value is not in the catalog allowlist", "TC_ARGUMENT_VALUE")
    return normalized


@dataclass(frozen=True)
class TypedArgument:
    name: str
    value_type: str
    value_format: str
    radix: str
    value: Any
    encoded: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_type": self.value_type,
            "value_format": self.value_format,
            "radix": self.radix,
            "value": self.value,
            "encoded": self.encoded,
        }


def _argument_envelope(value: Any, path: str) -> tuple[Any, dict[str, Any]]:
    if type(value) is not dict:
        return value, {}
    aliases = {
        "value": "value",
        "ValueType": "value_type",
        "value_type": "value_type",
        "ValueFormat": "value_format",
        "value_format": "value_format",
        "Radix": "radix",
        "radix": "radix",
    }
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        target = aliases.get(key)
        if target is None:
            _reject(path, f"unknown argument modifier {key}", "TC_ARGUMENT_MODIFIER")
        if target in normalized:
            _reject(path, f"duplicate argument modifier {target}", "TC_ARGUMENT_MODIFIER")
        normalized[target] = item
    if "value" not in normalized:
        _reject(path, "argument envelope is missing value", "TC_ARGUMENT_MODIFIER")
    raw = normalized.pop("value")
    return raw, normalized


def _encode_argument(value: Any, value_type: str, radix: str) -> str:
    if value_type == "LONG":
        if radix == "HEX":
            return f"0x{value:X}"
        if radix == "OCT":
            return f"0o{value:o}"
        if radix == "BIN":
            return f"0b{value:b}"
        return str(value)
    if value_type == "FLOAT":
        return format(value, ".17g")
    if value_type == "BOOLEAN":
        return "true" if value else "false"
    return str(value)


def _typed_arguments(
    definition: CommandDefinition,
    args: Any,
    path: str,
    *,
    max_string_length: int = 256,
) -> tuple[TypedArgument, ...]:
    supplied: dict[str, Any] = {}
    if args is None:
        pass
    elif isinstance(args, Mapping):
        supplied = dict(args)
    elif type(args) in {list, tuple}:
        for index, row in enumerate(args):
            row_path = f"{path}[{index}]"
            if type(row) not in {list, tuple} or len(row) not in {2, 3}:
                _reject(row_path, "argument row must contain name, value, and optional modifiers")
            name = row[0]
            if type(name) is not str or _ARGUMENT_NAME.fullmatch(name) is None:
                _reject(f"{row_path}[0]", "argument name is invalid")
            if name in supplied:
                _reject(row_path, f"duplicate argument {name}", "TC_ARGUMENT_DUPLICATE")
            raw: Any = row[1]
            if len(row) == 3:
                if type(row[2]) is not dict:
                    _reject(f"{row_path}[2]", "argument modifiers must be an object")
                raw = {"value": raw, **row[2]}
            supplied[name] = raw
    else:
        _reject(path, "args must be an object or a bounded list")
    if len(supplied) > len(definition.arguments):
        _reject(path, "too many command arguments", "TC_ARGUMENT_COUNT")

    by_name = {item.name: item for item in definition.arguments}
    unknown = set(supplied) - set(by_name)
    if unknown:
        _reject(path, f"unknown argument {sorted(unknown)[0]}", "TC_ARGUMENT_UNKNOWN")
    result: list[TypedArgument] = []
    for item in definition.arguments:
        if item.name not in supplied:
            if item.has_default:
                raw, modifiers = item.default, {}
            elif item.required:
                _reject(path, f"missing required argument {item.name}", "TC_ARGUMENT_REQUIRED")
            else:
                continue
        else:
            raw, modifiers = _argument_envelope(supplied[item.name], f"{path}.{item.name}")
        value_type = modifiers.get("value_type", item.value_type)
        if value_type != item.value_type:
            _reject(
                f"{path}.{item.name}.ValueType",
                "ValueType cannot override the catalog type",
                "TC_ARGUMENT_TYPE",
            )
        value_format = modifiers.get("value_format", "ENG")
        if value_format not in item.allowed_formats:
            _reject(
                f"{path}.{item.name}.ValueFormat",
                "ValueFormat is not allowed by the catalog",
                "TC_ARGUMENT_FORMAT",
            )
        radix = modifiers.get("radix", "DEC")
        if radix not in {"DEC", "HEX", "OCT", "BIN"}:
            _reject(f"{path}.{item.name}.Radix", "Radix is invalid", "TC_ARGUMENT_RADIX")
        if item.value_type != "LONG" and radix != "DEC":
            _reject(
                f"{path}.{item.name}.Radix",
                "non-decimal radix is valid only for LONG arguments",
                "TC_ARGUMENT_RADIX",
            )
        normalized = _validate_scalar(
            raw,
            item,
            f"{path}.{item.name}.value",
            max_string_length=max_string_length,
        )
        result.append(
            TypedArgument(
                name=item.name,
                value_type=item.value_type,
                value_format=value_format,
                radix=radix,
                value=normalized,
                encoded=_encode_argument(normalized, item.value_type, radix),
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class TelecommandCatalog:
    catalog_id: str
    revision: str
    digest: str
    limits: CatalogLimits
    commands: Mapping[str, CommandDefinition]
    sequences: Mapping[str, SequenceDefinition]
    simulator_only: bool = True
    live_dispatch: bool = False

    @classmethod
    def load(cls, path: Path | str | None = None) -> "TelecommandCatalog":
        source = Path(path) if path is not None else default_catalog_path()
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise TelecommandContractError(
                "TC_CONTRACT_UNAVAILABLE", "$", "telecommand catalog is unavailable"
            ) from exc
        digest = hashlib.sha256(raw).hexdigest()
        if path is None and digest != DEFAULT_CATALOG_SHA256:
            _contract_reject("$", "default telecommand catalog digest does not match the release pin")
        payload = _strict_json_loads(raw, max_bytes=MAX_CONTRACT_BYTES, path="$catalog")
        _exact_keys(
            payload,
            {
                "schema_version", "catalog_id", "revision", "simulator_only",
                "live_dispatch", "limits", "commands", "sequences",
            },
            set(), "$catalog", contract=True,
        )
        if payload["schema_version"] != CATALOG_SCHEMA_VERSION:
            _contract_reject("$catalog.schema_version", "catalog schema version is unsupported")
        if payload["simulator_only"] is not True or payload["live_dispatch"] is not False:
            _contract_reject("$catalog", "v0.11 catalog must be simulator-only with no live route")
        if type(payload["catalog_id"]) is not str or _IDENTITY.fullmatch(payload["catalog_id"]) is None:
            _contract_reject("$catalog.catalog_id", "catalog identity is invalid")
        if type(payload["revision"]) is not str or not payload["revision"] or len(payload["revision"]) > 32:
            _contract_reject("$catalog.revision", "catalog revision is invalid")

        limit_names = set(CatalogLimits.__dataclass_fields__)
        raw_limits = payload["limits"]
        if type(raw_limits) is not dict:
            _contract_reject("$catalog.limits", "limits must be an object")
        _exact_keys(raw_limits, limit_names, set(), "$catalog.limits", contract=True)
        if any(type(raw_limits[name]) is not int or raw_limits[name] <= 0 for name in limit_names):
            _contract_reject("$catalog.limits", "all limits must be positive integers")
        limits = CatalogLimits(**raw_limits)
        if limits.max_json_bytes > MAX_CONTRACT_BYTES or limits.max_expanded_elements > 256:
            _contract_reject("$catalog.limits", "declared bounds exceed implementation limits")

        raw_commands = payload["commands"]
        if type(raw_commands) is not list or not 1 <= len(raw_commands) <= limits.max_commands:
            _contract_reject("$catalog.commands", "command corpus size is invalid")
        commands: dict[str, CommandDefinition] = {}
        for index, raw_command in enumerate(raw_commands):
            item_path = f"$catalog.commands[{index}]"
            if type(raw_command) is not dict:
                _contract_reject(item_path, "command must be an object")
            _exact_keys(raw_command, {"name", "critical", "arguments"}, set(), item_path, contract=True)
            name = raw_command["name"]
            if type(name) is not str or _COMMAND_NAME.fullmatch(name) is None:
                _contract_reject(f"{item_path}.name", "command name is invalid")
            if name in commands:
                _contract_reject(f"{item_path}.name", "command name is duplicated")
            if type(raw_command["critical"]) is not bool:
                _contract_reject(f"{item_path}.critical", "critical must be boolean")
            raw_arguments = raw_command["arguments"]
            if type(raw_arguments) is not list or len(raw_arguments) > limits.max_arguments_per_command:
                _contract_reject(f"{item_path}.arguments", "argument list is invalid")
            definitions: list[ArgumentDefinition] = []
            seen_arguments: set[str] = set()
            for arg_index, raw_arg in enumerate(raw_arguments):
                arg_path = f"{item_path}.arguments[{arg_index}]"
                if type(raw_arg) is not dict:
                    _contract_reject(arg_path, "argument definition must be an object")
                _exact_keys(
                    raw_arg,
                    {
                        "name", "value_type", "required", "has_default", "default",
                        "minimum", "maximum", "allowed_values", "allowed_formats",
                    },
                    set(), arg_path, contract=True,
                )
                arg_name = raw_arg["name"]
                if type(arg_name) is not str or _ARGUMENT_NAME.fullmatch(arg_name) is None:
                    _contract_reject(f"{arg_path}.name", "argument name is invalid")
                if arg_name in seen_arguments:
                    _contract_reject(f"{arg_path}.name", "argument name is duplicated")
                seen_arguments.add(arg_name)
                value_type = raw_arg["value_type"]
                if value_type not in {"LONG", "FLOAT", "STRING", "BOOLEAN", "TIME"}:
                    _contract_reject(f"{arg_path}.value_type", "argument type is unsupported")
                if type(raw_arg["required"]) is not bool or type(raw_arg["has_default"]) is not bool:
                    _contract_reject(arg_path, "required and has_default must be boolean")
                if raw_arg["required"] and raw_arg["has_default"]:
                    _contract_reject(arg_path, "required arguments cannot declare defaults")
                allowed_values = raw_arg["allowed_values"]
                allowed_formats = raw_arg["allowed_formats"]
                if type(allowed_values) is not list or len(allowed_values) > 32:
                    _contract_reject(f"{arg_path}.allowed_values", "allowed values are invalid")
                if (
                    type(allowed_formats) is not list
                    or not allowed_formats
                    or any(value not in {"ENG", "RAW"} for value in allowed_formats)
                    or len(set(allowed_formats)) != len(allowed_formats)
                ):
                    _contract_reject(f"{arg_path}.allowed_formats", "allowed formats are invalid")
                definition = ArgumentDefinition(
                    name=arg_name,
                    value_type=value_type,
                    required=raw_arg["required"],
                    has_default=raw_arg["has_default"],
                    default=raw_arg["default"],
                    minimum=raw_arg["minimum"],
                    maximum=raw_arg["maximum"],
                    allowed_values=tuple(allowed_values),
                    allowed_formats=tuple(allowed_formats),
                )
                try:
                    if definition.minimum is not None and type(definition.minimum) not in {int, float}:
                        _contract_reject(f"{arg_path}.minimum", "minimum must be numeric or null")
                    if definition.maximum is not None and type(definition.maximum) not in {int, float}:
                        _contract_reject(f"{arg_path}.maximum", "maximum must be numeric or null")
                    if definition.minimum is not None and definition.maximum is not None and definition.minimum > definition.maximum:
                        _contract_reject(arg_path, "minimum exceeds maximum")
                    for allowed in definition.allowed_values:
                        _validate_scalar(
                            allowed,
                            definition,
                            f"{arg_path}.allowed_values",
                            max_string_length=limits.max_string_length,
                        )
                    if definition.has_default:
                        _validate_scalar(
                            definition.default,
                            definition,
                            f"{arg_path}.default",
                            max_string_length=limits.max_string_length,
                        )
                    elif definition.default is not None:
                        _contract_reject(f"{arg_path}.default", "default must be null when has_default is false")
                except TelecommandValidationError as exc:
                    raise TelecommandContractError(exc.code, exc.path, exc.message) from exc
                definitions.append(definition)
            commands[name] = CommandDefinition(name, raw_command["critical"], tuple(definitions))

        raw_sequences = payload["sequences"]
        if type(raw_sequences) is not list or len(raw_sequences) > limits.max_sequences:
            _contract_reject("$catalog.sequences", "sequence corpus size is invalid")
        sequences: dict[str, SequenceDefinition] = {}
        for index, raw_sequence in enumerate(raw_sequences):
            item_path = f"$catalog.sequences[{index}]"
            if type(raw_sequence) is not dict:
                _contract_reject(item_path, "sequence must be an object")
            _exact_keys(raw_sequence, {"name", "members"}, set(), item_path, contract=True)
            name = raw_sequence["name"]
            if type(name) is not str or _COMMAND_NAME.fullmatch(name) is None or name in sequences:
                _contract_reject(f"{item_path}.name", "sequence name is invalid or duplicated")
            raw_members = raw_sequence["members"]
            if type(raw_members) is not list or not 1 <= len(raw_members) <= limits.max_expanded_elements:
                _contract_reject(f"{item_path}.members", "sequence members are invalid")
            members: list[SequenceMember] = []
            for member_index, raw_member in enumerate(raw_members):
                member_path = f"{item_path}.members[{member_index}]"
                if type(raw_member) is not dict:
                    _contract_reject(member_path, "sequence member must be an object")
                _exact_keys(raw_member, {"command", "args", "modifiers"}, set(), member_path, contract=True)
                if raw_member["command"] not in commands:
                    _contract_reject(f"{member_path}.command", "sequence command is not in the catalog")
                if type(raw_member["args"]) is not dict or type(raw_member["modifiers"]) is not dict:
                    _contract_reject(member_path, "sequence args and modifiers must be objects")
                try:
                    _typed_arguments(
                        commands[raw_member["command"]],
                        raw_member["args"],
                        f"{member_path}.args",
                        max_string_length=limits.max_string_length,
                    )
                    parse_modifiers(raw_member["modifiers"], limits, f"{member_path}.modifiers")
                except TelecommandValidationError as exc:
                    raise TelecommandContractError(exc.code, exc.path, exc.message) from exc
                members.append(
                    SequenceMember(
                        raw_member["command"],
                        MappingProxyType(dict(raw_member["args"])),
                        MappingProxyType(dict(raw_member["modifiers"])),
                    )
                )
            sequences[name] = SequenceDefinition(name, tuple(members))
        return cls(
            payload["catalog_id"], payload["revision"], digest, limits,
            MappingProxyType(commands), MappingProxyType(sequences), True, False,
        )

    def build_tc(
        self, name: str, args: Any = None, *, modifiers: Mapping[str, Any] | None = None
    ) -> "CommandItem":
        if type(name) is not str or name not in self.commands:
            _reject("$.name", "command is not present in the pinned catalog", "TC_COMMAND_UNKNOWN")
        definition = self.commands[name]
        typed = _typed_arguments(
            definition,
            args,
            "$.args",
            max_string_length=self.limits.max_string_length,
        )
        command_modifiers = parse_modifiers(modifiers or {}, self.limits, "$.modifiers")
        identity = {
            "catalog_digest": self.digest,
            "name": name,
            "arguments": [item.as_dict() for item in typed],
            "modifiers": command_modifiers.explicit_dict(),
        }
        return CommandItem(
            name=name,
            arguments=typed,
            modifiers=command_modifiers,
            critical=definition.critical,
            catalog_digest=self.digest,
            item_digest=_digest(identity),
        )


def load_execution_contract(path: Path | str | None = None) -> tuple[Mapping[str, Any], str]:
    source = Path(path) if path is not None else default_execution_contract_path()
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise TelecommandContractError(
            "TC_CONTRACT_UNAVAILABLE", "$", "telecommand execution contract is unavailable"
        ) from exc
    digest = hashlib.sha256(raw).hexdigest()
    if path is None and digest != DEFAULT_EXECUTION_SHA256:
        _contract_reject("$", "default execution contract digest does not match the release pin")
    payload = _strict_json_loads(raw, max_bytes=MAX_CONTRACT_BYTES, path="$execution")
    _exact_keys(
        payload,
        {
            "schema_version", "simulator_only", "live_dispatch", "operation_states",
            "expansion_modes", "element_stages", "effect_certainties",
            "modifier_precedence", "supported_modifiers", "rules",
        },
        set(), "$execution", contract=True,
    )
    expected = {
        "schema_version": EXECUTION_SCHEMA_VERSION,
        "simulator_only": True,
        "live_dispatch": False,
        "operation_states": ["REQUESTED", "ACCEPTED", "DISPATCHED", "RECONCILING", "SETTLED"],
        "expansion_modes": ["SIMPLE", "SEQUENCE", "GROUP", "BLOCK"],
        "element_stages": [
            "TRANSPORT", "LOADING", "RELEASE", "ACKNOWLEDGEMENT",
            "ONBOARD_EXECUTION", "VERIFICATION",
        ],
        "effect_certainties": [
            "NO_EFFECT", "EFFECT_CONFIRMED", "EFFECT_POSSIBLE", "EFFECT_UNKNOWN",
        ],
        "modifier_precedence": ["DEFAULT", "GLOBAL", "PER_COMMAND"],
    }
    for key, value in expected.items():
        if payload[key] != value:
            _contract_reject(f"$execution.{key}", "execution policy conflicts with v0.11 semantics")
    required_rules = {
        "duplicate_children_receive_unique_element_ids": True,
        "critical_commands_require_explicit_preflight_confirmation": True,
        "transport_success_implies_execution_success": False,
        "loading_success_implies_execution_success": False,
        "load_only_is_execution_success": False,
        "automatic_resend": False,
        "unsupported_modifiers_are_ignored": False,
        "recovered_nonterminal_operations_require_reconciliation": True,
        "reconciliation_dispatches_commands": False,
        "provider_detail_is_separate_per_element_and_stage": True,
    }
    if payload["rules"] != required_rules:
        _contract_reject("$execution.rules", "execution safety rules are incomplete or changed")
    supported = set(payload["supported_modifiers"])
    if supported != set(_MODIFIER_FIELDS) | {"per_command", "group", "block"}:
        _contract_reject("$execution.supported_modifiers", "modifier contract and runtime differ")
    return MappingProxyType(payload), digest


class OperationState(str, Enum):
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    DISPATCHED = "DISPATCHED"
    RECONCILING = "RECONCILING"
    SETTLED = "SETTLED"


class ExpansionMode(str, Enum):
    SIMPLE = "SIMPLE"
    SEQUENCE = "SEQUENCE"
    GROUP = "GROUP"
    BLOCK = "BLOCK"


class ElementStage(str, Enum):
    TRANSPORT = "TRANSPORT"
    LOADING = "LOADING"
    RELEASE = "RELEASE"
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT"
    ONBOARD_EXECUTION = "ONBOARD_EXECUTION"
    VERIFICATION = "VERIFICATION"


class EffectCertainty(str, Enum):
    NO_EFFECT = "NO_EFFECT"
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    EFFECT_POSSIBLE = "EFFECT_POSSIBLE"
    EFFECT_UNKNOWN = "EFFECT_UNKNOWN"


class Disposition(str, Enum):
    PENDING = "PENDING"
    TRANSPORT_REJECTED = "TRANSPORT_REJECTED"
    LOAD_FAILED = "LOAD_FAILED"
    RELEASE_FAILED = "RELEASE_FAILED"
    ACKNOWLEDGEMENT_FAILED = "ACKNOWLEDGEMENT_FAILED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    LOADED_ONLY = "LOADED_ONLY"
    EXECUTED_UNVERIFIED = "EXECUTED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    TIMED_OUT = "TIMED_OUT"
    UNCERTAIN = "UNCERTAIN"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True)
class VerificationIntent:
    channel: str
    operator: str
    expected: Any
    tolerance: float | None = None
    timeout_ms: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "operator": self.operator,
            "expected": self.expected,
            "tolerance": self.tolerance,
            "timeout_ms": self.timeout_ms,
        }


@dataclass(frozen=True)
class TelemetryFixture:
    value: Any
    available_after_ms: int = 0
    quality: str = "GOOD"


@dataclass(frozen=True)
class VerificationEvaluation:
    outcome: str
    duration_ms: int
    detail: Mapping[str, Any]


class DeterministicTelemetryEvaluator:
    """Evaluates closed-loop conditions from fixed telemetry fixtures."""

    def __init__(
        self,
        fixtures: Mapping[str, TelemetryFixture | Mapping[str, Any] | Any],
        *,
        allow_limit_adjustment: bool = True,
    ):
        if not isinstance(fixtures, Mapping) or len(fixtures) > 64:
            _reject("$.telemetry", "telemetry fixtures must be a bounded object")
        if type(allow_limit_adjustment) is not bool:
            _reject("$.telemetry.allow_limit_adjustment", "limit capability must be boolean")
        normalized: dict[str, TelemetryFixture] = {}
        for channel, raw in fixtures.items():
            path = f"$.telemetry.{channel}"
            if type(channel) is not str or _CHANNEL.fullmatch(channel) is None:
                _reject(path, "telemetry fixture channel is invalid")
            if isinstance(raw, TelemetryFixture):
                fixture = raw
            elif type(raw) is dict and set(raw) <= {
                "value",
                "available_after_ms",
                "quality",
            } and "value" in raw:
                fixture = TelemetryFixture(
                    value=raw["value"],
                    available_after_ms=raw.get("available_after_ms", 0),
                    quality=raw.get("quality", "GOOD"),
                )
            else:
                fixture = TelemetryFixture(raw)
            if (
                type(fixture.available_after_ms) is not int
                or not 0 <= fixture.available_after_ms <= 3_600_000
            ):
                _reject(f"{path}.available_after_ms", "telemetry availability is out of bounds")
            if fixture.quality not in {"GOOD", "STALE", "INVALID"}:
                _reject(f"{path}.quality", "telemetry fixture quality is invalid")
            normalized[channel] = replace(
                fixture, value=_canonical(fixture.value, f"{path}.value")
            )
        self.fixtures = MappingProxyType(normalized)
        self.allow_limit_adjustment = allow_limit_adjustment
        self.calls: list[dict[str, Any]] = []

    def evaluate(
        self,
        intents: tuple[VerificationIntent, ...],
        *,
        global_tolerance: float,
        adjust_limits: bool,
    ) -> VerificationEvaluation:
        if not intents:
            _reject("$.verification", "telemetry evaluator requires verification intent")
        if adjust_limits and not self.allow_limit_adjustment:
            detail = {
                "evaluator": "deterministic-telemetry",
                "limits_adjusted": False,
                "reason": "LIMIT_ADJUSTMENT_UNAVAILABLE",
                "conditions": [],
            }
            self.calls.append(detail)
            return VerificationEvaluation("FAILED", 0, MappingProxyType(detail))
        conditions: list[dict[str, Any]] = []
        duration_ms = 0
        saw_failure = False
        saw_indeterminate = False
        for intent in intents:
            fixture = self.fixtures.get(intent.channel)
            tolerance = (
                intent.tolerance
                if intent.tolerance is not None
                else global_tolerance
            )
            if fixture is None:
                state = "MISSING"
                actual = None
                saw_indeterminate = True
            elif (
                intent.timeout_ms is not None
                and fixture.available_after_ms > intent.timeout_ms
            ):
                state = "TIMED_OUT"
                actual = None
                duration_ms = max(duration_ms, intent.timeout_ms)
                saw_indeterminate = True
            elif fixture.quality != "GOOD":
                state = fixture.quality
                actual = fixture.value
                duration_ms = max(duration_ms, fixture.available_after_ms)
                saw_indeterminate = True
            else:
                actual = fixture.value
                duration_ms = max(duration_ms, fixture.available_after_ms)
                passed = self._compare(
                    actual, intent.operator, intent.expected, tolerance
                )
                state = "PASSED" if passed else "FAILED"
                saw_failure = saw_failure or not passed
            conditions.append(
                {
                    "channel": intent.channel,
                    "operator": intent.operator,
                    "expected": intent.expected,
                    "actual": actual,
                    "tolerance": tolerance,
                    "timeout_ms": intent.timeout_ms,
                    "state": state,
                }
            )
        outcome = (
            "INDETERMINATE"
            if saw_indeterminate
            else "FAILED" if saw_failure else "PASSED"
        )
        detail = {
            "evaluator": "deterministic-telemetry",
            "limits_adjusted": adjust_limits,
            "conditions": conditions,
        }
        self.calls.append(_canonical(detail))
        return VerificationEvaluation(
            outcome, duration_ms, MappingProxyType(_canonical(detail))
        )

    @staticmethod
    def _compare(actual: Any, operator: str, expected: Any, tolerance: float) -> bool:
        numeric = (
            type(actual) in {int, float}
            and type(actual) is not bool
            and type(expected) in {int, float}
            and type(expected) is not bool
        )
        if tolerance and not numeric:
            return False
        if operator == "eq":
            return abs(float(actual) - float(expected)) <= tolerance if numeric else actual == expected
        if operator == "neq":
            return abs(float(actual) - float(expected)) > tolerance if numeric else actual != expected
        try:
            if operator == "gt":
                return actual > (expected - tolerance if numeric else expected)
            if operator == "ge":
                return actual >= (expected - tolerance if numeric else expected)
            if operator == "lt":
                return actual < (expected + tolerance if numeric else expected)
            if operator == "le":
                return actual <= (expected + tolerance if numeric else expected)
        except TypeError:
            return False
        return False


_MODIFIER_FIELDS = (
    "time", "release_time", "load_only", "confirm", "confirm_critical",
    "timeout_ms", "additional_info", "send_delay_ms", "verification",
    "adjust_limits", "delay_ms", "tolerance", "on_failure", "prompt_user",
)

_MODIFIER_ALIASES = {
    **{name: name for name in _MODIFIER_FIELDS},
    "Time": "time",
    "ReleaseTime": "release_time",
    "LoadOnly": "load_only",
    "Confirm": "confirm",
    "ConfirmCritical": "confirm_critical",
    "Timeout": "timeout_ms",
    "addInfo": "additional_info",
    "SendDelay": "send_delay_ms",
    "verify": "verification",
    "AdjLimits": "adjust_limits",
    "Delay": "delay_ms",
    "Tolerance": "tolerance",
    "OnFailure": "on_failure",
    "PromptUser": "prompt_user",
    "timeout_seconds": "timeout_ms",
    "send_delay_seconds": "send_delay_ms",
    "verification_delay_seconds": "delay_ms",
}


def _absolute_time(value: Any, path: str) -> str:
    if type(value) in {int, float} and type(value) is not bool:
        numeric = _finite_float(
            value,
            path,
            code="TC_TIME_INVALID",
            message="numeric absolute time is invalid",
        )
        if numeric < 0 or numeric > 253_402_300_799:
            _reject(path, "numeric absolute time is outside the UTC epoch range", "TC_TIME_INVALID")
        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError) as exc:
            raise TelecommandValidationError(
                "TC_TIME_INVALID", path, "numeric absolute time is invalid"
            ) from exc
    if type(value) is not str or not value.strip() or len(value) > 80:
        _reject(path, "absolute time must be a bounded string", "TC_TIME_INVALID")
    text = value.strip()
    if re.fullmatch(r"(?:NOW|TODAY)(?:[+-](?:0|[1-9]\d{0,8})(?:\.\d+)?s)?", text):
        return text
    try:
        if re.fullmatch(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", text):
            parsed = datetime.strptime(text, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                _reject(path, "absolute time must include a timezone", "TC_TIME_INVALID")
            parsed = parsed.astimezone(timezone.utc)
    except TelecommandValidationError:
        raise
    except ValueError as exc:
        raise TelecommandValidationError(
            "TC_TIME_INVALID", path, "absolute time format is invalid"
        ) from exc
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _iso_to_epoch_ms(value: str, path: str) -> int:
    normalized = _absolute_time(value, path)
    if normalized.startswith(("NOW", "TODAY")):
        _reject(path, "relative clock expression requires an execution anchor")
    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1000)


def _epoch_ms_to_iso(value: int) -> str:
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


class DeterministicClock:
    """Logical UTC clock that advances instantly and never sleeps."""

    def __init__(self, start: str = "2026-01-01T00:00:00Z"):
        self._epoch_ms = _iso_to_epoch_ms(start, "$.clock.start")

    @property
    def epoch_ms(self) -> int:
        return self._epoch_ms

    @property
    def now(self) -> str:
        return _epoch_ms_to_iso(self._epoch_ms)

    def advance_ms(self, milliseconds: int) -> str:
        if type(milliseconds) is not int or milliseconds < 0 or milliseconds > 86_400_000:
            _reject("$.clock.advance_ms", "clock advance must be 0..86400000 milliseconds")
        self._epoch_ms += milliseconds
        return self.now

    def advance_to(self, target_epoch_ms: int) -> str:
        if type(target_epoch_ms) is not int or target_epoch_ms < 0:
            _reject("$.clock.target", "clock target is invalid")
        if target_epoch_ms > self._epoch_ms:
            self._epoch_ms = target_epoch_ms
        return self.now


def _resolve_clock_expression(value: str | None, anchor_epoch_ms: int) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(
        r"(NOW|TODAY)(?:([+-])((?:0|[1-9]\d{0,8})(?:\.\d+)?)s)?", value
    )
    if match is None:
        return _iso_to_epoch_ms(value, "$.time")
    base = anchor_epoch_ms
    if match.group(1) == "TODAY":
        anchor = datetime.fromtimestamp(anchor_epoch_ms / 1000, tz=timezone.utc)
        base = int(
            anchor.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
            * 1000
        )
    if match.group(2) is not None:
        offset_ms = int(float(match.group(3)) * 1000)
        base += offset_ms if match.group(2) == "+" else -offset_ms
    return base


def _duration_ms(value: Any, path: str, maximum: int, *, seconds_alias: bool) -> int:
    numeric = _finite_float(
        value, path, message="duration must be a finite nonnegative number"
    )
    milliseconds = numeric * (1000 if seconds_alias else 1)
    if milliseconds < 0 or milliseconds > maximum or not milliseconds.is_integer():
        _reject(path, f"duration must be whole milliseconds within 0..{maximum}")
    return int(milliseconds)


def _verification(value: Any, limits: CatalogLimits, path: str) -> tuple[VerificationIntent, ...]:
    if type(value) not in {list, tuple} or not 1 <= len(value) <= limits.max_verifications_per_element:
        _reject(path, "verification must be a bounded nonempty list")
    result: list[VerificationIntent] = []
    for index, raw in enumerate(value):
        item_path = f"{path}[{index}]"
        if type(raw) is dict:
            _exact_keys(raw, {"channel", "operator", "expected"}, {"tolerance", "timeout_ms"}, item_path)
            channel, operator, expected = raw["channel"], raw["operator"], raw["expected"]
            local = {key: raw[key] for key in ("tolerance", "timeout_ms") if key in raw}
        elif type(raw) in {list, tuple} and len(raw) in {3, 4}:
            channel, operator, expected = raw[:3]
            local = raw[3] if len(raw) == 4 else {}
            if type(local) is not dict:
                _reject(f"{item_path}[3]", "verification modifiers must be an object")
            aliases = {"Tolerance": "tolerance", "tolerance": "tolerance", "Timeout": "timeout_ms", "timeout_ms": "timeout_ms"}
            normalized_local: dict[str, Any] = {}
            timeout_is_seconds = False
            for key, item in local.items():
                target = aliases.get(key)
                if target is None or target in normalized_local:
                    _reject(f"{item_path}[3]", f"unknown or duplicate verification modifier {key}")
                normalized_local[target] = item
                timeout_is_seconds = timeout_is_seconds or key == "Timeout"
            local = normalized_local
            if timeout_is_seconds and "timeout_ms" in local:
                local["timeout_ms"] = _duration_ms(
                    local["timeout_ms"],
                    f"{item_path}.Timeout",
                    limits.max_timeout_ms,
                    seconds_alias=True,
                )
        else:
            _reject(item_path, "verification item must be an object or 3/4-item list")
        if type(channel) is not str or _CHANNEL.fullmatch(channel) is None:
            _reject(f"{item_path}.channel", "verification channel is invalid")
        if operator not in {"eq", "neq", "gt", "ge", "lt", "le"}:
            _reject(f"{item_path}.operator", "verification operator is unsupported")
        expected = _canonical(expected, f"{item_path}.expected")
        tolerance = local.get("tolerance")
        if tolerance is not None:
            tolerance = _finite_float(
                tolerance,
                f"{item_path}.tolerance",
                message="tolerance must be finite and nonnegative",
            )
            if tolerance < 0:
                _reject(f"{item_path}.tolerance", "tolerance must be finite and nonnegative")
        timeout = local.get("timeout_ms")
        if timeout is not None:
            timeout = _duration_ms(
                timeout,
                f"{item_path}.timeout_ms",
                limits.max_timeout_ms,
                seconds_alias=False,
            )
        result.append(VerificationIntent(channel, operator, expected, tolerance, timeout))
    return tuple(result)


@dataclass(frozen=True)
class SendModifiers:
    time: str | None = None
    release_time: str | None = None
    load_only: bool = False
    confirm: bool = False
    confirm_critical: bool = False
    timeout_ms: int = 60_000
    additional_info: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    send_delay_ms: int = 0
    verification: tuple[VerificationIntent, ...] = ()
    adjust_limits: bool = False
    delay_ms: int = 0
    tolerance: float = 0.0
    on_failure: str = "CANCEL"
    prompt_user: bool = True
    specified: frozenset[str] = frozenset()

    def as_dict(self) -> dict[str, Any]:
        return {
            "time": self.time,
            "release_time": self.release_time,
            "load_only": self.load_only,
            "confirm": self.confirm,
            "confirm_critical": self.confirm_critical,
            "timeout_ms": self.timeout_ms,
            "additional_info": dict(self.additional_info),
            "send_delay_ms": self.send_delay_ms,
            "verification": [item.as_dict() for item in self.verification],
            "adjust_limits": self.adjust_limits,
            "delay_ms": self.delay_ms,
            "tolerance": self.tolerance,
            "on_failure": self.on_failure,
            "prompt_user": self.prompt_user,
        }

    def explicit_dict(self) -> dict[str, Any]:
        all_values = self.as_dict()
        return {name: all_values[name] for name in _MODIFIER_FIELDS if name in self.specified}


def parse_modifiers(
    raw: Mapping[str, Any] | None, limits: CatalogLimits, path: str = "$.modifiers"
) -> SendModifiers:
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        _reject(path, "modifiers must be an object")
    raw = dict(raw)
    normalized: dict[str, Any] = {}
    source_keys: dict[str, str] = {}
    for key, value in raw.items():
        target = _MODIFIER_ALIASES.get(key)
        if target is None:
            _reject(path, f"unsupported modifier {key}", "TC_MODIFIER_UNSUPPORTED")
        if target in normalized:
            _reject(path, f"duplicate modifier {target}", "TC_MODIFIER_DUPLICATE")
        normalized[target] = value
        source_keys[target] = key
    values: dict[str, Any] = {}
    for name, value in normalized.items():
        item_path = f"{path}.{source_keys[name]}"
        if name in {"time", "release_time"}:
            values[name] = _absolute_time(value, item_path)
        elif name in {"load_only", "confirm", "confirm_critical", "adjust_limits", "prompt_user"}:
            if type(value) is not bool:
                _reject(item_path, "modifier must be boolean")
            values[name] = value
        elif name == "timeout_ms":
            values[name] = _duration_ms(
                value,
                item_path,
                limits.max_timeout_ms,
                seconds_alias=source_keys[name] in {"Timeout", "timeout_seconds"},
            )
        elif name in {"send_delay_ms", "delay_ms"}:
            values[name] = _duration_ms(
                value,
                item_path,
                limits.max_delay_ms,
                seconds_alias=source_keys[name]
                in {"SendDelay", "Delay", "send_delay_seconds", "verification_delay_seconds"},
            )
        elif name == "additional_info":
            if type(value) is not dict:
                _reject(item_path, "additional information must be an object")
            _reject_secret_keys(value, item_path)
            detached = _canonical(value, item_path)
            if len(_canonical_bytes(detached, item_path)) > limits.max_additional_info_bytes:
                _reject(item_path, "additional information exceeds its byte bound", "TC_JSON_BOUNDS")
            values[name] = MappingProxyType(detached)
        elif name == "verification":
            values[name] = _verification(value, limits, item_path)
        elif name == "tolerance":
            value = _finite_float(
                value,
                item_path,
                message="tolerance must be finite and nonnegative",
            )
            if value < 0:
                _reject(item_path, "tolerance must be finite and nonnegative")
            values[name] = value
        elif name == "on_failure":
            if value not in {"ABORT", "CANCEL", "CONTINUE"}:
                _reject(item_path, "OnFailure supports only ABORT, CANCEL, or CONTINUE; resend and skip are forbidden", "TC_NO_RESEND")
            values[name] = value
    return SendModifiers(**values, specified=frozenset(normalized))


def merge_modifiers(global_values: SendModifiers, local_values: SendModifiers) -> tuple[SendModifiers, Mapping[str, str]]:
    defaults = SendModifiers()
    merged: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name in _MODIFIER_FIELDS:
        if name in local_values.specified:
            merged[name] = getattr(local_values, name)
            sources[name] = "PER_COMMAND"
        elif name in global_values.specified:
            merged[name] = getattr(global_values, name)
            sources[name] = "GLOBAL"
        else:
            merged[name] = getattr(defaults, name)
            sources[name] = "DEFAULT"
    return SendModifiers(**merged, specified=frozenset(_MODIFIER_FIELDS)), MappingProxyType(sources)


def _reject_secret_keys(value: Any, path: str) -> None:
    if type(value) is dict:
        for key, item in value.items():
            if _SECRET_KEY.search(key):
                _reject(path, "secret-like additional information keys are forbidden", "TC_SECRET_REJECTED")
            _reject_secret_keys(item, f"{path}.{key}")
    elif type(value) is list:
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")


def _overlay_modifiers(base: SendModifiers, override: SendModifiers) -> SendModifiers:
    values = {
        name: getattr(override, name) if name in override.specified else getattr(base, name)
        for name in _MODIFIER_FIELDS
    }
    return SendModifiers(
        **values, specified=base.specified | override.specified
    )


def _replace_item_modifiers(item: "CommandItem", modifiers: SendModifiers) -> "CommandItem":
    identity = {
        "catalog_digest": item.catalog_digest,
        "name": item.name,
        "arguments": [argument.as_dict() for argument in item.arguments],
        "modifiers": modifiers.explicit_dict(),
    }
    return replace(item, modifiers=modifiers, item_digest=_digest(identity))


@dataclass(frozen=True)
class CommandItem:
    name: str
    arguments: tuple[TypedArgument, ...]
    modifiers: SendModifiers
    critical: bool
    catalog_digest: str
    item_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": [item.as_dict() for item in self.arguments],
            "modifiers": self.modifiers.explicit_dict(),
            "critical": self.critical,
            "catalog_digest": self.catalog_digest,
            "item_digest": self.item_digest,
        }


@dataclass(frozen=True)
class SendRequest:
    operation_id: str
    command: str | CommandItem | None = None
    sequence: str | None = None
    group: Sequence[str | CommandItem] | None = None
    args: Any = None
    modifiers: Mapping[str, Any] | None = None
    block: bool = False


@dataclass(frozen=True)
class ExpandedElement:
    ordinal: int
    element_id: str
    path: str
    transport_unit_id: str
    command: CommandItem
    global_modifiers: SendModifiers
    effective_modifiers: SendModifiers
    modifier_sources: Mapping[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "element_id": self.element_id,
            "path": self.path,
            "transport_unit_id": self.transport_unit_id,
            "command": self.command.as_dict(),
            "global_modifiers": self.global_modifiers.explicit_dict(),
            "effective_modifiers": self.effective_modifiers.as_dict(),
            "modifier_sources": dict(self.modifier_sources),
        }


@dataclass(frozen=True)
class SendPlan:
    operation_id: str
    request_digest: str
    plan_id: str
    plan_digest: str
    catalog_id: str
    catalog_digest: str
    policy_digest: str
    mode: ExpansionMode
    grouped_transport: bool
    elements: tuple[ExpandedElement, ...]
    confirmation_required: bool
    confirmation_challenge: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "request_digest": self.request_digest,
            "plan_id": self.plan_id,
            "catalog_id": self.catalog_id,
            "catalog_digest": self.catalog_digest,
            "policy_digest": self.policy_digest,
            "mode": self.mode.value,
            "grouped_transport": self.grouped_transport,
            "elements": [item.as_dict() for item in self.elements],
            "confirmation_required": self.confirmation_required,
            "confirmation_challenge": self.confirmation_challenge,
            "plan_digest": self.plan_digest,
        }


@dataclass(frozen=True)
class Preflight:
    plan: SendPlan

    @property
    def confirmation_required(self) -> bool:
        return self.plan.confirmation_required


@dataclass(frozen=True)
class Confirmation:
    plan_id: str
    challenge: str
    actor: str
    reason: str
    confirmation_digest: str

    def as_dict(self) -> dict[str, str]:
        return {
            "plan_id": self.plan_id,
            "challenge": self.challenge,
            "actor": self.actor,
            "reason": self.reason,
            "confirmation_digest": self.confirmation_digest,
        }


@dataclass(frozen=True)
class ElementResult:
    element_id: str
    command_name: str
    transport: str = "NOT_ATTEMPTED"
    loading: str = "NOT_ATTEMPTED"
    release: str = "NOT_ATTEMPTED"
    acknowledgement: str = "NOT_ATTEMPTED"
    onboard_execution: str = "NOT_ATTEMPTED"
    verification: str = "NOT_REQUESTED"
    disposition: Disposition = Disposition.PENDING
    effect_certainty: EffectCertainty = EffectCertainty.NO_EFFECT
    next_stage: ElementStage | None = ElementStage.TRANSPORT
    provider_detail: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    timing_detail: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def execution_succeeded(self) -> bool:
        return self.onboard_execution == "SUCCEEDED"

    @property
    def verification_succeeded(self) -> bool:
        return self.verification == "PASSED"

    @property
    def terminal(self) -> bool:
        return self.next_stage is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "element_id": self.element_id,
            "command_name": self.command_name,
            "transport": self.transport,
            "loading": self.loading,
            "release": self.release,
            "acknowledgement": self.acknowledgement,
            "onboard_execution": self.onboard_execution,
            "verification": self.verification,
            "disposition": self.disposition.value,
            "effect_certainty": self.effect_certainty.value,
            "next_stage": self.next_stage.value if self.next_stage is not None else None,
            "provider_detail": {key: _canonical(value) for key, value in self.provider_detail.items()},
            "timing_detail": _canonical(dict(self.timing_detail)),
        }


@dataclass(frozen=True)
class ExecutionSnapshot:
    plan: SendPlan
    state: OperationState
    revision: int
    current_index: int
    elements: tuple[ElementResult, ...]
    accepted_at: str = "2026-01-01T00:00:00.000Z"
    provider_call_count: int = 0
    confirmed_by: str | None = None
    cancellation_reason: str | None = None

    @property
    def settled(self) -> bool:
        return self.state is OperationState.SETTLED

    @property
    def execution_succeeded(self) -> bool:
        return bool(self.elements) and all(item.execution_succeeded for item in self.elements)

    @property
    def verification_succeeded(self) -> bool:
        requested = [item for item in self.elements if item.verification != "NOT_REQUESTED"]
        return bool(requested) and all(item.verification_succeeded for item in requested)

    @property
    def successful(self) -> bool:
        return self.settled and bool(self.elements) and all(
            item.disposition in {Disposition.EXECUTED_UNVERIFIED, Disposition.VERIFIED}
            for item in self.elements
        )

    def as_checkpoint(self) -> dict[str, Any]:
        body = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "operation_id": self.plan.operation_id,
            "plan_digest": self.plan.plan_digest,
            "catalog_digest": self.plan.catalog_digest,
            "policy_digest": self.plan.policy_digest,
            "state": self.state.value,
            "revision": self.revision,
            "current_index": self.current_index,
            "provider_call_count": self.provider_call_count,
            "accepted_at": self.accepted_at,
            "confirmed_by": self.confirmed_by,
            "cancellation_reason": self.cancellation_reason,
            "elements": [item.as_dict() for item in self.elements],
        }
        return {**body, "checkpoint_digest": _digest(body)}


@dataclass(frozen=True)
class ProviderOutcome:
    stage: ElementStage
    outcome: str
    detail: Mapping[str, Any]
    duration_ms: int = 0


@dataclass(frozen=True)
class ProviderStep:
    stage: ElementStage
    outcome: str
    element_id: str
    detail: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    crash_after: bool = False
    duration_ms: int = 0


@dataclass(frozen=True)
class ProviderCall:
    plan_id: str
    element_id: str
    stage: ElementStage
    outcome: str
    duration_ms: int = 0


@dataclass(frozen=True)
class ReconciliationReport:
    known: bool
    outcomes: Mapping[str, ProviderOutcome]
    detail: Mapping[str, Any]


_STAGE_OUTCOMES: Mapping[ElementStage, frozenset[str]] = MappingProxyType(
    {
        ElementStage.TRANSPORT: frozenset({"ACCEPTED", "REJECTED", "UNCERTAIN"}),
        ElementStage.LOADING: frozenset({"LOADED", "FAILED", "UNCERTAIN"}),
        ElementStage.RELEASE: frozenset({"RELEASED", "FAILED", "UNCERTAIN"}),
        ElementStage.ACKNOWLEDGEMENT: frozenset(
            {"ACKNOWLEDGED", "NACKED", "TIMED_OUT", "UNCERTAIN"}
        ),
        ElementStage.ONBOARD_EXECUTION: frozenset({"SUCCEEDED", "FAILED", "UNCERTAIN"}),
        ElementStage.VERIFICATION: frozenset({"PASSED", "FAILED", "INDETERMINATE"}),
    }
)


class DeterministicScriptedProvider:
    """An exact scripted provider with a reconciliation journal.

    A step is consumed once.  The provider journals its result before an
    optional simulated crash, which lets recovery prove that reconciliation
    can resume without dispatching the same stage again.
    """

    def __init__(
        self,
        steps: Sequence[ProviderStep | Mapping[str, Any]],
        *,
        reconciliation_mode: str = "JOURNAL",
        max_detail_bytes: int = 4096,
    ):
        if reconciliation_mode not in {"JOURNAL", "UNKNOWN"}:
            _reject("$.reconciliation_mode", "reconciliation mode is invalid")
        if type(steps) not in {list, tuple} or len(steps) > 384:
            _reject("$.steps", "provider script must be a bounded list")
        normalized: list[ProviderStep] = []
        for index, raw in enumerate(steps):
            path = f"$.steps[{index}]"
            if isinstance(raw, ProviderStep):
                step = raw
            else:
                if type(raw) is not dict:
                    _reject(path, "provider step must be an object")
                _exact_keys(
                    raw,
                    {"stage", "outcome", "element_id"},
                    {"detail", "crash_after", "duration_ms"},
                    path,
                )
                try:
                    stage = ElementStage(raw["stage"])
                except (TypeError, ValueError) as exc:
                    raise TelecommandValidationError(
                        "TC_PROVIDER_SCRIPT", f"{path}.stage", "provider stage is invalid"
                    ) from exc
                step = ProviderStep(
                    stage=stage,
                    outcome=raw["outcome"],
                    element_id=raw["element_id"],
                    detail=MappingProxyType(_canonical(raw.get("detail", {}), f"{path}.detail")),
                    crash_after=raw.get("crash_after", False),
                    duration_ms=raw.get("duration_ms", 0),
                )
            if type(step.element_id) is not str or not step.element_id:
                _reject(f"{path}.element_id", "provider element identity is invalid")
            if step.outcome not in _STAGE_OUTCOMES[step.stage]:
                _reject(f"{path}.outcome", "provider outcome is invalid for the stage")
            if type(step.crash_after) is not bool:
                _reject(f"{path}.crash_after", "crash_after must be boolean")
            if (
                type(step.duration_ms) is not int
                or not 0 <= step.duration_ms <= 86_400_000
            ):
                _reject(f"{path}.duration_ms", "provider duration is outside bounds")
            detail = _canonical(dict(step.detail), f"{path}.detail")
            _reject_secret_keys(detail, f"{path}.detail")
            if len(_canonical_bytes(detail)) > max_detail_bytes:
                _reject(f"{path}.detail", "provider detail exceeds its byte bound", "TC_JSON_BOUNDS")
            normalized.append(replace(step, detail=MappingProxyType(detail)))
        self._steps = tuple(normalized)
        self._cursor = 0
        self._reconciliation_mode = reconciliation_mode
        self._max_detail_bytes = max_detail_bytes
        self._journal: dict[tuple[str, str], dict[str, ProviderOutcome]] = {}
        self.calls: list[ProviderCall] = []
        self.reconciliation_calls: list[tuple[str, str]] = []

    @classmethod
    def nominal(
        cls, plan: SendPlan, *, include_verification: bool = True
    ) -> "DeterministicScriptedProvider":
        if type(include_verification) is not bool:
            _reject("$.include_verification", "verification selection must be boolean")
        steps: list[ProviderStep] = []
        seen_transport_units: set[str] = set()
        for element in plan.elements:
            expected: list[tuple[ElementStage, str, str]] = []
            if element.transport_unit_id not in seen_transport_units:
                shared_transport = sum(
                    candidate.transport_unit_id == element.transport_unit_id
                    for candidate in plan.elements
                ) > 1
                expected.append(
                    (
                        ElementStage.TRANSPORT,
                        "ACCEPTED",
                        element.transport_unit_id if shared_transport else element.element_id,
                    )
                )
                seen_transport_units.add(element.transport_unit_id)
            expected.append((ElementStage.LOADING, "LOADED", element.element_id))
            if not element.effective_modifiers.load_only:
                expected.extend(
                    [
                        (ElementStage.RELEASE, "RELEASED", element.element_id),
                        (ElementStage.ACKNOWLEDGEMENT, "ACKNOWLEDGED", element.element_id),
                        (ElementStage.ONBOARD_EXECUTION, "SUCCEEDED", element.element_id),
                    ]
                )
                if element.effective_modifiers.verification and include_verification:
                    expected.append((ElementStage.VERIFICATION, "PASSED", element.element_id))
            for stage, outcome, provider_element_id in expected:
                steps.append(
                    ProviderStep(
                        stage,
                        outcome,
                        provider_element_id,
                        MappingProxyType(
                            {
                                "provider": "deterministic-simulator",
                                "stage": stage.value,
                            }
                        ),
                    )
                )
        return cls(steps, max_detail_bytes=4096)

    @property
    def remaining_steps(self) -> int:
        return len(self._steps) - self._cursor

    def perform(
        self, plan_id: str, element_id: str, stage: ElementStage
    ) -> ProviderOutcome:
        if self._cursor >= len(self._steps):
            raise ProviderScriptError(
                "TC_PROVIDER_SCRIPT_EXHAUSTED",
                "$.provider",
                f"no scripted outcome for {stage.value}",
            )
        step = self._steps[self._cursor]
        if step.stage is not stage or step.element_id != element_id:
            raise ProviderScriptError(
                "TC_PROVIDER_SCRIPT_MISMATCH",
                "$.provider",
                f"expected {step.stage.value}/{step.element_id}, got {stage.value}/{element_id}",
            )
        key = (plan_id, element_id)
        element_journal = self._journal.setdefault(key, {})
        if stage.value in element_journal:
            raise ProviderScriptError(
                "TC_AUTOMATIC_RESEND_FORBIDDEN",
                "$.provider",
                f"stage {stage.value} was already dispatched for this element",
            )
        self._cursor += 1
        outcome = ProviderOutcome(stage, step.outcome, step.detail, step.duration_ms)
        element_journal[stage.value] = outcome
        self.calls.append(
            ProviderCall(plan_id, element_id, stage, step.outcome, step.duration_ms)
        )
        if step.crash_after:
            raise SimulatedProviderCrash(stage.value, element_id)
        return outcome

    def reconcile(self, plan_id: str, element_id: str) -> ReconciliationReport:
        self.reconciliation_calls.append((plan_id, element_id))
        if self._reconciliation_mode == "UNKNOWN":
            return ReconciliationReport(
                False,
                MappingProxyType({}),
                MappingProxyType({"provider": "deterministic-simulator", "certainty": "UNKNOWN"}),
            )
        journal = self._journal.get((plan_id, element_id), {})
        if not journal:
            return ReconciliationReport(
                False,
                MappingProxyType({}),
                MappingProxyType({"provider": "deterministic-simulator", "certainty": "UNKNOWN"}),
            )
        return ReconciliationReport(
            True,
            MappingProxyType(dict(journal)),
            MappingProxyType({"provider": "deterministic-simulator", "certainty": "JOURNALED"}),
        )

    def assert_consumed(self) -> None:
        if self.remaining_steps:
            raise AssertionError(f"provider script has {self.remaining_steps} unconsumed steps")


def _validate_item(item: CommandItem, catalog: TelecommandCatalog, path: str) -> None:
    if type(item) is not CommandItem:
        _reject(path, "command selector must be a catalog name or CommandItem")
    if item.catalog_digest != catalog.digest or item.name not in catalog.commands:
        _reject(path, "command item belongs to a different catalog", "TC_COMMAND_ITEM_INVALID")
    if item.critical != catalog.commands[item.name].critical:
        _reject(path, "command item criticality was modified", "TC_COMMAND_ITEM_INVALID")
    identity = {
        "catalog_digest": item.catalog_digest,
        "name": item.name,
        "arguments": [argument.as_dict() for argument in item.arguments],
        "modifiers": item.modifiers.explicit_dict(),
    }
    if item.item_digest != _digest(identity):
        _reject(path, "command item digest is invalid", "TC_COMMAND_ITEM_INVALID")


class TelecommandService:
    """In-memory deterministic simulator state machine with idempotency checks."""

    def __init__(
        self,
        catalog: TelecommandCatalog | None = None,
        *,
        execution_contract_path: Path | str | None = None,
        clock: DeterministicClock | None = None,
        telemetry_evaluator: DeterministicTelemetryEvaluator | None = None,
    ):
        self.catalog = catalog or default_catalog()
        self.execution_contract, self.policy_digest = load_execution_contract(
            execution_contract_path
        )
        if clock is not None and not isinstance(clock, DeterministicClock):
            _reject("$.clock", "clock must be DeterministicClock")
        if telemetry_evaluator is not None and not isinstance(
            telemetry_evaluator, DeterministicTelemetryEvaluator
        ):
            _reject(
                "$.telemetry_evaluator",
                "telemetry evaluator must be DeterministicTelemetryEvaluator",
            )
        self.clock = clock or DeterministicClock()
        self.telemetry_evaluator = telemetry_evaluator
        self._plans: dict[str, SendPlan] = {}
        self._operations: dict[str, ExecutionSnapshot] = {}

    def build_tc(
        self, name: str, args: Any = None, *, modifiers: Mapping[str, Any] | None = None
    ) -> CommandItem:
        return self.catalog.build_tc(name, args, modifiers=modifiers)

    def preflight(self, request: SendRequest) -> Preflight:
        if type(request) is not SendRequest:
            _reject("$.request", "request must be SendRequest")
        if type(request.operation_id) is not str or _IDENTITY.fullmatch(request.operation_id) is None:
            _reject("$.operation_id", "operation identity is invalid")
        selectors = [request.command is not None, request.sequence is not None, request.group is not None]
        if sum(selectors) != 1:
            _reject("$.selector", "exactly one of command, sequence, or group is required")
        if type(request.block) is not bool:
            _reject("$.block", "block must be boolean")
        raw_modifiers = dict(request.modifiers or {})
        control_aliases = {
            "PerCommand": "per_command",
            "per_command": "per_command",
            "Group": "group",
            "group": "group",
            "Block": "block",
            "block": "block",
        }
        controls: dict[str, Any] = {}
        for source_name, target_name in control_aliases.items():
            if source_name not in raw_modifiers:
                continue
            if target_name in controls:
                _reject("$.modifiers", f"duplicate control modifier {target_name}")
            controls[target_name] = raw_modifiers.pop(source_name)
        block_requested = request.block
        grouped_transport = False
        if "group" in controls:
            if controls["group"] is not True or request.group is None:
                _reject("$.modifiers.group", "Group=True requires a group selector")
            grouped_transport = True
        if "block" in controls:
            if type(controls["block"]) is not bool:
                _reject("$.modifiers.block", "Block must be boolean")
            if request.block and controls["block"] is False:
                _reject("$.modifiers.block", "conflicting block selectors")
            block_requested = controls["block"]
        if block_requested and request.group is None:
            _reject("$.block", "block mode is valid only for a group")
        per_command_raw = controls.get("per_command", {})
        if type(per_command_raw) is not dict:
            _reject("$.modifiers.per_command", "PerCommand must be an object")
        global_modifiers = parse_modifiers(raw_modifiers, self.catalog.limits)
        has_arguments = request.args is not None and request.args != {} and request.args != []

        items: list[tuple[str, CommandItem]] = []
        if request.command is not None:
            if isinstance(request.command, str):
                item = self.build_tc(request.command, request.args)
            else:
                if has_arguments:
                    _reject("$.args", "args cannot accompany a prebuilt command item")
                item = request.command
                _validate_item(item, self.catalog, "$.command")
            items.append(("simple/0000", item))
            mode = ExpansionMode.SIMPLE
        elif request.sequence is not None:
            if has_arguments:
                _reject("$.args", "args cannot accompany a sequence")
            if type(request.sequence) is not str or request.sequence not in self.catalog.sequences:
                _reject("$.sequence", "sequence is not present in the pinned catalog", "TC_SEQUENCE_UNKNOWN")
            sequence = self.catalog.sequences[request.sequence]
            for index, member in enumerate(sequence.members):
                item = self.build_tc(member.command, member.args, modifiers=member.modifiers)
                items.append((f"sequence/{sequence.name}/{index:04d}", item))
            mode = ExpansionMode.SEQUENCE
        else:
            if has_arguments:
                _reject("$.args", "group arguments must be carried by CommandItem values")
            raw_group = request.group
            if type(raw_group) not in {list, tuple} or not raw_group:
                _reject("$.group", "group must be a bounded nonempty list")
            if len(raw_group) > self.catalog.limits.max_expanded_elements:
                _reject("$.group", "group exceeds the expansion bound")
            for index, raw_item in enumerate(raw_group):
                if isinstance(raw_item, str):
                    item = self.build_tc(raw_item)
                else:
                    item = raw_item
                    _validate_item(item, self.catalog, f"$.group[{index}]")
                items.append((f"{'block' if block_requested else 'group'}/{index:04d}", item))
            mode = ExpansionMode.BLOCK if block_requested else ExpansionMode.GROUP
        if not 1 <= len(items) <= self.catalog.limits.max_expanded_elements:
            _reject("$.selector", "expanded element count is outside bounds")

        configured_items: list[tuple[str, CommandItem]] = []
        used_per_command: set[str] = set()
        for index, (path, item) in enumerate(items):
            ordinal_key = str(index)
            matching = [key for key in (ordinal_key, item.name) if key in per_command_raw]
            if len(matching) > 1:
                _reject(
                    "$.modifiers.per_command",
                    f"command {index} is configured by both ordinal and name",
                    "TC_MODIFIER_DUPLICATE",
                )
            if matching:
                key = matching[0]
                raw_local = per_command_raw[key]
                if type(raw_local) is not dict:
                    _reject(f"$.modifiers.per_command.{key}", "per-command modifiers must be an object")
                local_override = parse_modifiers(
                    raw_local, self.catalog.limits, f"$.modifiers.per_command.{key}"
                )
                item = _replace_item_modifiers(
                    item, _overlay_modifiers(item.modifiers, local_override)
                )
                used_per_command.add(key)
            configured_items.append((path, item))
        unknown_per_command = set(per_command_raw) - used_per_command
        if unknown_per_command:
            _reject(
                "$.modifiers.per_command",
                f"per-command selector {sorted(unknown_per_command, key=str)[0]} matched no element",
            )
        items = configured_items

        request_identity = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "operation_id": request.operation_id,
            "catalog_digest": self.catalog.digest,
            "policy_digest": self.policy_digest,
            "mode": mode.value,
            "grouped_transport": grouped_transport,
            "global_modifiers": global_modifiers.explicit_dict(),
            "items": [{"path": path, "command": item.as_dict()} for path, item in items],
        }
        request_digest = _digest(request_identity)
        plan_id = "tc-plan-" + hashlib.sha256(
            f"{request.operation_id}:{request_digest}".encode("ascii")
        ).hexdigest()[:32]
        shared_unit = "tc-unit-" + hashlib.sha256(
            f"{plan_id}:{'block' if mode is ExpansionMode.BLOCK else 'group'}".encode("ascii")
        ).hexdigest()[:24]
        expanded: list[ExpandedElement] = []
        confirmation_required = False
        for ordinal, (path, item) in enumerate(items):
            effective, sources = merge_modifiers(global_modifiers, item.modifiers)
            if effective.load_only and effective.verification:
                _reject(f"$.elements[{ordinal}]", "LoadOnly conflicts with verification", "TC_MODIFIER_CONFLICT")
            if effective.load_only and effective.release_time is not None:
                _reject(f"$.elements[{ordinal}]", "LoadOnly conflicts with ReleaseTime", "TC_MODIFIER_CONFLICT")
            if effective.adjust_limits and not effective.verification:
                _reject(f"$.elements[{ordinal}]", "AdjLimits requires verification", "TC_MODIFIER_CONFLICT")
            element_id = "tc-el-" + hashlib.sha256(
                f"{plan_id}:{path}:{item.name}".encode("ascii")
            ).hexdigest()[:32]
            unit_id = (
                shared_unit
                if mode is ExpansionMode.BLOCK or grouped_transport
                else "tc-unit-"
                + hashlib.sha256(f"{plan_id}:{path}".encode("ascii")).hexdigest()[:24]
            )
            expanded.append(
                ExpandedElement(
                    ordinal,
                    element_id,
                    path,
                    unit_id,
                    item,
                    global_modifiers,
                    effective,
                    sources,
                )
            )
            confirmation_required = confirmation_required or item.critical or effective.confirm or effective.confirm_critical

        plan_without_digest = {
            **request_identity,
            "plan_id": plan_id,
            "elements": [item.as_dict() for item in expanded],
            "confirmation_required": confirmation_required,
        }
        plan_digest = _digest(plan_without_digest)
        challenge = hashlib.sha256(f"confirm:{plan_digest}".encode("ascii")).hexdigest()
        plan = SendPlan(
            operation_id=request.operation_id,
            request_digest=request_digest,
            plan_id=plan_id,
            plan_digest=plan_digest,
            catalog_id=self.catalog.catalog_id,
            catalog_digest=self.catalog.digest,
            policy_digest=self.policy_digest,
            mode=mode,
            grouped_transport=grouped_transport,
            elements=tuple(expanded),
            confirmation_required=confirmation_required,
            confirmation_challenge=challenge,
        )
        previous = self._plans.get(request.operation_id)
        if previous is not None and previous.request_digest != request_digest:
            _reject("$.operation_id", "operation identity was reused with different content", "TC_IDEMPOTENCY_CONFLICT")
        if previous is not None:
            return Preflight(previous)
        self._plans[request.operation_id] = plan
        return Preflight(plan)

    def confirm(self, preflight: Preflight, *, actor: str, reason: str) -> Confirmation:
        plan = self._validate_preflight(preflight)
        if type(actor) is not str or _IDENTITY.fullmatch(actor) is None:
            _reject("$.confirmation.actor", "confirmation actor is invalid")
        if type(reason) is not str or not reason.strip() or len(reason) > 240:
            _reject("$.confirmation.reason", "confirmation reason is invalid")
        payload = {
            "plan_id": plan.plan_id,
            "challenge": plan.confirmation_challenge,
            "actor": actor,
            "reason": reason.strip(),
        }
        return Confirmation(**payload, confirmation_digest=_digest(payload))

    def start(
        self, preflight: Preflight, confirmation: Confirmation | None = None
    ) -> ExecutionSnapshot:
        plan = self._validate_preflight(preflight)
        previous = self._operations.get(plan.operation_id)
        if previous is not None:
            return previous
        confirmed_by: str | None = None
        if plan.confirmation_required:
            if confirmation is None:
                raise ConfirmationRequired(plan.confirmation_challenge)
            self._validate_confirmation(plan, confirmation)
            confirmed_by = confirmation.actor
        elif confirmation is not None:
            self._validate_confirmation(plan, confirmation)
            confirmed_by = confirmation.actor
        records = tuple(
            ElementResult(
                element_id=item.element_id,
                command_name=item.command.name,
                release="NOT_REQUESTED" if item.effective_modifiers.load_only else "NOT_ATTEMPTED",
                verification=(
                    "NOT_ATTEMPTED" if item.effective_modifiers.verification else "NOT_REQUESTED"
                ),
            )
            for item in plan.elements
        )
        snapshot = ExecutionSnapshot(
            plan=plan,
            state=OperationState.ACCEPTED,
            revision=0,
            current_index=0,
            elements=records,
            accepted_at=self.clock.now,
            confirmed_by=confirmed_by,
        )
        self._operations[plan.operation_id] = snapshot
        return snapshot

    def get_operation(self, operation_id: str) -> ExecutionSnapshot:
        try:
            return self._operations[operation_id]
        except KeyError as exc:
            raise TelecommandValidationError(
                "TC_OPERATION_UNKNOWN", "$.operation_id", "telecommand operation is unknown"
            ) from exc

    def advance(
        self, snapshot: ExecutionSnapshot, provider: DeterministicScriptedProvider
    ) -> ExecutionSnapshot:
        self._validate_current(snapshot)
        if snapshot.state is OperationState.SETTLED:
            return snapshot
        if snapshot.state is OperationState.RECONCILING:
            _reject("$.operation", "recovered operation must be reconciled before progress", "TC_RECONCILIATION_REQUIRED")
        if snapshot.current_index >= len(snapshot.elements):
            _reject("$.operation.current_index", "nonterminal operation has no current element")
        element = snapshot.elements[snapshot.current_index]
        if element.next_stage is None:
            _reject("$.operation", "current element is already terminal")
        snapshot = self._prepare_stage_timing(snapshot, snapshot.current_index)
        element = snapshot.elements[snapshot.current_index]
        if self._deadline_exceeded(element):
            return self._store(
                self._timeout_without_provider(snapshot, snapshot.current_index)
            )
        if (
            element.next_stage is ElementStage.VERIFICATION
            and self.telemetry_evaluator is not None
        ):
            intent = snapshot.plan.elements[
                snapshot.current_index
            ].effective_modifiers
            evaluation = self.telemetry_evaluator.evaluate(
                intent.verification,
                global_tolerance=intent.tolerance,
                adjust_limits=intent.adjust_limits,
            )
            self.clock.advance_ms(evaluation.duration_ms)
            outcome = ProviderOutcome(
                ElementStage.VERIFICATION,
                evaluation.outcome,
                evaluation.detail,
                evaluation.duration_ms,
            )
            updated = self._apply_outcome(
                snapshot,
                snapshot.current_index,
                outcome,
                timed_out=self._deadline_exceeded(element),
                count_provider_call=False,
            )
            return self._store(updated)
        provider_element_id = self._provider_element_id(
            snapshot.plan, snapshot.current_index, element.next_stage
        )
        outcome = provider.perform(snapshot.plan.plan_id, provider_element_id, element.next_stage)
        if type(outcome.duration_ms) is not int or not 0 <= outcome.duration_ms <= 86_400_000:
            _reject("$.provider.duration_ms", "provider duration is outside bounds")
        self.clock.advance_ms(outcome.duration_ms)
        timed_out = self._deadline_exceeded(element)
        if element.next_stage is ElementStage.TRANSPORT and provider_element_id != element.element_id:
            updated = self._apply_shared_transport(snapshot, outcome)
        else:
            updated = self._apply_outcome(
                snapshot,
                snapshot.current_index,
                outcome,
                timed_out=timed_out,
            )
        return self._store(updated)

    def run(
        self, snapshot: ExecutionSnapshot, provider: DeterministicScriptedProvider
    ) -> ExecutionSnapshot:
        budget = len(snapshot.elements) * len(ElementStage) + 1
        current = snapshot
        for _ in range(budget):
            if current.state is OperationState.SETTLED:
                return current
            current = self.advance(current, provider)
        _reject("$.operation", "execution exceeded its deterministic action bound")

    def cancel(self, snapshot: ExecutionSnapshot, *, reason: str) -> ExecutionSnapshot:
        self._validate_current(snapshot)
        if snapshot.state is OperationState.SETTLED:
            return snapshot
        if type(reason) is not str or not reason.strip() or len(reason) > 240:
            _reject("$.cancellation.reason", "cancellation reason is invalid")
        elements = list(snapshot.elements)
        for index, item in enumerate(elements):
            if not item.terminal:
                elements[index] = replace(
                    item,
                    disposition=Disposition.CANCELLED,
                    effect_certainty=(
                        EffectCertainty.NO_EFFECT
                        if item.transport == "NOT_ATTEMPTED"
                        else EffectCertainty.EFFECT_UNKNOWN
                    ),
                    next_stage=None,
                )
        return self._store(
            replace(
                snapshot,
                state=OperationState.SETTLED,
                revision=snapshot.revision + 1,
                current_index=len(elements),
                elements=tuple(elements),
                cancellation_reason=reason.strip(),
            )
        )

    def recover(
        self, plan: SendPlan, checkpoint: Mapping[str, Any] | str | bytes
    ) -> ExecutionSnapshot:
        self._validate_plan_integrity(plan)
        if isinstance(checkpoint, str):
            payload = _strict_json_loads(
                checkpoint.encode("utf-8"), max_bytes=MAX_CHECKPOINT_BYTES, path="$checkpoint"
            )
        elif isinstance(checkpoint, bytes):
            payload = _strict_json_loads(checkpoint, max_bytes=MAX_CHECKPOINT_BYTES, path="$checkpoint")
        elif type(checkpoint) is dict:
            raw = _canonical_bytes(checkpoint, "$checkpoint")
            if len(raw) > MAX_CHECKPOINT_BYTES:
                _reject("$checkpoint", "checkpoint exceeds its byte bound", "TC_JSON_BOUNDS")
            payload = json.loads(raw.decode("ascii"))
        else:
            _reject("$checkpoint", "checkpoint must be an object or JSON bytes")
        required = {
            "schema_version", "operation_id", "plan_digest", "catalog_digest",
            "policy_digest", "state", "revision", "current_index",
            "provider_call_count", "accepted_at", "confirmed_by", "cancellation_reason", "elements",
            "checkpoint_digest",
        }
        _exact_keys(payload, required, set(), "$checkpoint")
        claimed = payload.pop("checkpoint_digest")
        if type(claimed) is not str or _HEX_DIGEST.fullmatch(claimed) is None or claimed != _digest(payload):
            _reject("$checkpoint.checkpoint_digest", "checkpoint digest is invalid", "TC_CHECKPOINT_INVALID")
        if payload["schema_version"] != CHECKPOINT_SCHEMA_VERSION:
            _reject("$checkpoint.schema_version", "checkpoint schema is unsupported")
        identities = {
            "operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "catalog_digest": plan.catalog_digest,
            "policy_digest": plan.policy_digest,
        }
        for key, expected in identities.items():
            if payload[key] != expected:
                _reject(f"$checkpoint.{key}", "checkpoint identity does not match the plan", "TC_CHECKPOINT_INVALID")
        try:
            saved_state = OperationState(payload["state"])
        except (TypeError, ValueError) as exc:
            raise TelecommandValidationError(
                "TC_CHECKPOINT_INVALID", "$checkpoint.state", "checkpoint state is invalid"
            ) from exc
        for key in ("revision", "current_index", "provider_call_count"):
            if type(payload[key]) is not int or payload[key] < 0:
                _reject(f"$checkpoint.{key}", "checkpoint counter is invalid", "TC_CHECKPOINT_INVALID")
        if type(payload["accepted_at"]) is not str:
            _reject("$checkpoint.accepted_at", "checkpoint clock anchor is invalid")
        accepted_epoch_ms = _iso_to_epoch_ms(
            payload["accepted_at"], "$checkpoint.accepted_at"
        )
        if payload["current_index"] > len(plan.elements):
            _reject("$checkpoint.current_index", "checkpoint cursor is out of bounds", "TC_CHECKPOINT_INVALID")
        raw_elements = payload["elements"]
        if type(raw_elements) is not list or len(raw_elements) != len(plan.elements):
            _reject("$checkpoint.elements", "checkpoint element count differs from plan", "TC_CHECKPOINT_INVALID")
        elements = tuple(
            self._element_from_checkpoint(plan.elements[index], raw, f"$checkpoint.elements[{index}]")
            for index, raw in enumerate(raw_elements)
        )
        self._validate_checkpoint_coherence(
            plan, saved_state, payload["current_index"], elements
        )
        for field_name in ("confirmed_by", "cancellation_reason"):
            value = payload[field_name]
            if value is not None and (type(value) is not str or len(value) > 240):
                _reject(f"$checkpoint.{field_name}", "checkpoint text field is invalid")
        confirmed_by = payload["confirmed_by"]
        if confirmed_by is not None and _IDENTITY.fullmatch(confirmed_by) is None:
            _reject(
                "$checkpoint.confirmed_by",
                "checkpoint confirmation actor is invalid",
                "TC_CHECKPOINT_INVALID",
            )
        if plan.confirmation_required and confirmed_by is None:
            _reject(
                "$checkpoint.confirmed_by",
                "critical or confirmed plan is missing confirmation evidence",
                "TC_CHECKPOINT_INVALID",
            )
        state = saved_state if saved_state is OperationState.SETTLED else OperationState.RECONCILING
        recovered = ExecutionSnapshot(
            plan=plan,
            state=state,
            revision=payload["revision"] + (0 if state is saved_state else 1),
            current_index=payload["current_index"],
            elements=elements,
            accepted_at=_epoch_ms_to_iso(accepted_epoch_ms),
            provider_call_count=payload["provider_call_count"],
            confirmed_by=confirmed_by,
            cancellation_reason=payload["cancellation_reason"],
        )
        self._plans[plan.operation_id] = plan
        self._operations[plan.operation_id] = recovered
        latest_epoch_ms = accepted_epoch_ms
        for item in elements:
            for value in item.timing_detail.get("stage_times", {}).values():
                if type(value) is str:
                    latest_epoch_ms = max(
                        latest_epoch_ms,
                        _iso_to_epoch_ms(value, "$checkpoint.timing.stage_times"),
                    )
        self.clock.advance_to(latest_epoch_ms)
        return recovered

    def reconcile(
        self, snapshot: ExecutionSnapshot, provider: DeterministicScriptedProvider
    ) -> ExecutionSnapshot:
        self._validate_current(snapshot)
        if snapshot.state is not OperationState.RECONCILING:
            _reject("$.operation", "only a recovered nonterminal operation can be reconciled")
        if snapshot.current_index >= len(snapshot.elements):
            _reject("$.operation.current_index", "reconciliation cursor is invalid")
        snapshot = self._prepare_stage_timing(snapshot, snapshot.current_index)
        element = snapshot.elements[snapshot.current_index]
        if element.next_stage is None:
            _reject("$.operation", "reconciliation element is already terminal")
        provider_element_id = self._provider_element_id(
            snapshot.plan, snapshot.current_index, element.next_stage
        )
        report = provider.reconcile(snapshot.plan.plan_id, provider_element_id)
        if (
            type(report) is not ReconciliationReport
            or type(report.known) is not bool
            or not isinstance(report.outcomes, Mapping)
            or not isinstance(report.detail, Mapping)
        ):
            _reject("$.reconciliation", "provider reconciliation report is invalid")
        outcome = report.outcomes.get(element.next_stage.value) if report.known else None
        if outcome is None:
            uncertain = self._mark_reconciliation_unknown(element, report.detail)
            elements = list(snapshot.elements)
            elements[snapshot.current_index] = uncertain
            return self._store(
                replace(
                    snapshot,
                    revision=snapshot.revision + 1,
                    elements=tuple(elements),
                    state=OperationState.RECONCILING,
                )
            )
        if type(outcome.duration_ms) is not int or not 0 <= outcome.duration_ms <= 86_400_000:
            _reject("$.reconciliation.duration_ms", "reconciled duration is outside bounds")
        self.clock.advance_ms(outcome.duration_ms)
        timed_out = self._deadline_exceeded(element)
        if element.next_stage is ElementStage.TRANSPORT and provider_element_id != element.element_id:
            updated = self._apply_shared_transport(snapshot, outcome)
        else:
            updated = self._apply_outcome(
                snapshot,
                snapshot.current_index,
                outcome,
                timed_out=timed_out,
            )
        return self._store(updated)

    @staticmethod
    def _provider_element_id(
        plan: SendPlan, index: int, stage: ElementStage
    ) -> str:
        element = plan.elements[index]
        if stage is ElementStage.TRANSPORT and sum(
            candidate.transport_unit_id == element.transport_unit_id
            for candidate in plan.elements
        ) > 1:
            return element.transport_unit_id
        return element.element_id

    def _initialize_timing(
        self,
        snapshot: ExecutionSnapshot,
        index: int,
        ready_epoch_ms: int,
    ) -> ElementResult:
        item = snapshot.elements[index]
        if item.timing_detail:
            return item
        modifiers = snapshot.plan.elements[index].effective_modifiers
        anchor_epoch_ms = _iso_to_epoch_ms(snapshot.accepted_at, "$.accepted_at")
        scheduled = _resolve_clock_expression(modifiers.time, anchor_epoch_ms)
        base_epoch_ms = max(
            ready_epoch_ms,
            scheduled if scheduled is not None else ready_epoch_ms,
        )
        requested_due = base_epoch_ms + modifiers.send_delay_ms
        timing = {
            "ready_at": _epoch_ms_to_iso(ready_epoch_ms),
            "requested_transport_due_at": _epoch_ms_to_iso(requested_due),
            "transport_due_at": _epoch_ms_to_iso(requested_due),
            "deadline_at": _epoch_ms_to_iso(
                requested_due + modifiers.timeout_ms
            ),
            "stage_times": {},
            "waits": {},
        }
        return replace(item, timing_detail=MappingProxyType(timing))

    def _prepare_stage_timing(
        self, snapshot: ExecutionSnapshot, index: int
    ) -> ExecutionSnapshot:
        item = snapshot.elements[index]
        if item.next_stage is None:
            return snapshot
        elements = list(snapshot.elements)
        before_epoch_ms = self.clock.epoch_ms
        if item.next_stage is ElementStage.TRANSPORT:
            unit_id = snapshot.plan.elements[index].transport_unit_id
            indexes = [
                candidate
                for candidate, plan_element in enumerate(snapshot.plan.elements)
                if plan_element.transport_unit_id == unit_id
                and snapshot.elements[candidate].next_stage is ElementStage.TRANSPORT
            ]
            for candidate in indexes:
                elements[candidate] = self._initialize_timing(
                    snapshot, candidate, before_epoch_ms
                )
            requested = [
                _iso_to_epoch_ms(
                    elements[candidate].timing_detail["requested_transport_due_at"],
                    "$.timing.requested_transport_due_at",
                )
                for candidate in indexes
            ]
            due_epoch_ms = max(requested)
            shared = len(indexes) > 1
            for candidate in indexes:
                timing = dict(elements[candidate].timing_detail)
                if shared:
                    modifiers = snapshot.plan.elements[
                        candidate
                    ].effective_modifiers
                    timing["transport_due_at"] = _epoch_ms_to_iso(due_epoch_ms)
                    timing["deadline_at"] = _epoch_ms_to_iso(
                        due_epoch_ms + modifiers.timeout_ms
                    )
                waits = dict(timing["waits"])
                waits[ElementStage.TRANSPORT.value] = {
                    "from": _epoch_ms_to_iso(before_epoch_ms),
                    "until": _epoch_ms_to_iso(due_epoch_ms),
                    "duration_ms": max(0, due_epoch_ms - before_epoch_ms),
                }
                timing["waits"] = waits
                elements[candidate] = replace(
                    elements[candidate], timing_detail=MappingProxyType(timing)
                )
        else:
            elements[index] = self._initialize_timing(
                snapshot, index, before_epoch_ms
            )
            timing = dict(elements[index].timing_detail)
            due_epoch_ms = before_epoch_ms
            modifiers = snapshot.plan.elements[index].effective_modifiers
            if item.next_stage is ElementStage.RELEASE:
                if "release_due_at" in timing:
                    release_due_epoch_ms = _iso_to_epoch_ms(
                        timing["release_due_at"], "$.timing.release_due_at"
                    )
                else:
                    release_target = _resolve_clock_expression(
                        modifiers.release_time,
                        _iso_to_epoch_ms(snapshot.accepted_at, "$.accepted_at"),
                    )
                    stage_times = timing.get("stage_times", {})
                    ready_at = stage_times.get(ElementStage.LOADING.value)
                    release_ready_epoch_ms = (
                        _iso_to_epoch_ms(ready_at, "$.timing.loading")
                        if type(ready_at) is str
                        else before_epoch_ms
                    )
                    release_due_epoch_ms = max(
                        release_ready_epoch_ms,
                        release_target
                        if release_target is not None
                        else release_ready_epoch_ms,
                    )
                    hold_ms = release_due_epoch_ms - release_ready_epoch_ms
                    deadline_epoch_ms = _iso_to_epoch_ms(
                        timing["deadline_at"], "$.timing.deadline_at"
                    )
                    timing["deadline_at"] = _epoch_ms_to_iso(
                        deadline_epoch_ms + hold_ms
                    )
                    timing["release_due_at"] = _epoch_ms_to_iso(
                        release_due_epoch_ms
                    )
                due_epoch_ms = max(before_epoch_ms, release_due_epoch_ms)
            elif item.next_stage is ElementStage.VERIFICATION:
                stage_times = timing.get("stage_times", {})
                executed_at = stage_times.get(
                    ElementStage.ONBOARD_EXECUTION.value,
                    _epoch_ms_to_iso(before_epoch_ms),
                )
                if "verification_due_at" in timing:
                    verification_due_epoch_ms = _iso_to_epoch_ms(
                        timing["verification_due_at"],
                        "$.timing.verification_due_at",
                    )
                else:
                    verification_ready_epoch_ms = _iso_to_epoch_ms(
                        executed_at, "$.timing.onboard_execution"
                    )
                    verification_due_epoch_ms = (
                        verification_ready_epoch_ms + modifiers.delay_ms
                    )
                    deadline_epoch_ms = _iso_to_epoch_ms(
                        timing["deadline_at"], "$.timing.deadline_at"
                    )
                    timing["deadline_at"] = _epoch_ms_to_iso(
                        deadline_epoch_ms + modifiers.delay_ms
                    )
                    timing["verification_due_at"] = _epoch_ms_to_iso(
                        verification_due_epoch_ms
                    )
                due_epoch_ms = max(before_epoch_ms, verification_due_epoch_ms)
            waits = dict(timing["waits"])
            waits[item.next_stage.value] = {
                "from": _epoch_ms_to_iso(before_epoch_ms),
                "until": _epoch_ms_to_iso(due_epoch_ms),
                "duration_ms": max(0, due_epoch_ms - before_epoch_ms),
            }
            timing["waits"] = waits
            elements[index] = replace(
                elements[index], timing_detail=MappingProxyType(timing)
            )
        self.clock.advance_to(due_epoch_ms)
        return replace(snapshot, elements=tuple(elements))

    def _deadline_exceeded(self, item: ElementResult) -> bool:
        deadline = item.timing_detail.get("deadline_at")
        return (
            type(deadline) is str
            and self.clock.epoch_ms
            > _iso_to_epoch_ms(deadline, "$.timing.deadline_at")
        )

    def _record_stage_time(
        self, item: ElementResult, stage: ElementStage
    ) -> ElementResult:
        timing = dict(item.timing_detail)
        stage_times = dict(timing.get("stage_times", {}))
        stage_times[stage.value] = self.clock.now
        timing["stage_times"] = stage_times
        return replace(item, timing_detail=MappingProxyType(timing))

    def _timeout_without_provider(
        self, snapshot: ExecutionSnapshot, index: int
    ) -> ExecutionSnapshot:
        item = snapshot.elements[index]
        timing = dict(item.timing_detail)
        timing["timed_out_at"] = self.clock.now
        certainty = (
            EffectCertainty.NO_EFFECT
            if item.transport in {"NOT_ATTEMPTED", "REJECTED"}
            else EffectCertainty.EFFECT_CONFIRMED
            if item.onboard_execution == "SUCCEEDED"
            else EffectCertainty.EFFECT_UNKNOWN
        )
        item = replace(
            item,
            disposition=Disposition.TIMED_OUT,
            effect_certainty=certainty,
            next_stage=None,
            timing_detail=MappingProxyType(timing),
        )
        elements = list(snapshot.elements)
        elements[index] = item
        on_failure = snapshot.plan.elements[index].effective_modifiers.on_failure
        if on_failure in {"ABORT", "CANCEL"}:
            for later in range(index + 1, len(elements)):
                elements[later] = replace(
                    elements[later], disposition=Disposition.CANCELLED, next_stage=None
                )
            next_index = len(elements)
        else:
            next_index = index + 1
        return replace(
            snapshot,
            state=(
                OperationState.SETTLED
                if next_index >= len(elements)
                else snapshot.state
            ),
            revision=snapshot.revision + 1,
            current_index=next_index,
            elements=tuple(elements),
        )

    def _validate_preflight(self, preflight: Preflight) -> SendPlan:
        if type(preflight) is not Preflight:
            _reject("$.preflight", "preflight object is invalid")
        known = self._plans.get(preflight.plan.operation_id)
        if known is None or known != preflight.plan:
            _reject("$.preflight", "preflight is not registered by this service")
        return known

    def _validate_confirmation(self, plan: SendPlan, confirmation: Confirmation) -> None:
        if type(confirmation) is not Confirmation:
            _reject("$.confirmation", "confirmation object is invalid")
        payload = {
            "plan_id": confirmation.plan_id,
            "challenge": confirmation.challenge,
            "actor": confirmation.actor,
            "reason": confirmation.reason,
        }
        if (
            confirmation.plan_id != plan.plan_id
            or confirmation.challenge != plan.confirmation_challenge
            or confirmation.confirmation_digest != _digest(payload)
        ):
            _reject("$.confirmation", "confirmation does not bind this plan", "TC_CONFIRMATION_INVALID")

    def _validate_current(self, snapshot: ExecutionSnapshot) -> None:
        if type(snapshot) is not ExecutionSnapshot:
            _reject("$.operation", "operation snapshot is invalid")
        current = self._operations.get(snapshot.plan.operation_id)
        if current is None or current.plan.plan_digest != snapshot.plan.plan_digest:
            _reject("$.operation", "operation is not registered by this service")
        if current.revision != snapshot.revision:
            _reject("$.operation.revision", "stale operation snapshot", "TC_STALE_REVISION")
        if current != snapshot:
            _reject(
                "$.operation",
                "operation snapshot differs from the registered canonical state",
                "TC_SNAPSHOT_INVALID",
            )

    def _validate_plan_integrity(self, plan: SendPlan) -> None:
        if type(plan) is not SendPlan:
            _reject("$.plan", "recovery plan must be SendPlan", "TC_PLAN_INVALID")
        if (
            plan.catalog_id != self.catalog.catalog_id
            or plan.catalog_digest != self.catalog.digest
            or plan.policy_digest != self.policy_digest
        ):
            _reject("$.plan", "recovery plan does not match this service", "TC_PLAN_INVALID")
        if type(plan.operation_id) is not str or _IDENTITY.fullmatch(plan.operation_id) is None:
            _reject("$.plan.operation_id", "plan operation identity is invalid", "TC_PLAN_INVALID")
        if type(plan.grouped_transport) is not bool:
            _reject("$.plan.grouped_transport", "grouped transport flag is invalid", "TC_PLAN_INVALID")
        if plan.grouped_transport and plan.mode not in {ExpansionMode.GROUP, ExpansionMode.BLOCK}:
            _reject("$.plan.grouped_transport", "grouped transport conflicts with expansion mode", "TC_PLAN_INVALID")
        if not 1 <= len(plan.elements) <= self.catalog.limits.max_expanded_elements:
            _reject("$.plan.elements", "plan element count is outside bounds", "TC_PLAN_INVALID")
        if not _HEX_DIGEST.fullmatch(plan.request_digest) or not _HEX_DIGEST.fullmatch(plan.plan_digest):
            _reject("$.plan", "plan digest field is invalid", "TC_PLAN_INVALID")
        expected_plan_id = "tc-plan-" + hashlib.sha256(
            f"{plan.operation_id}:{plan.request_digest}".encode("ascii")
        ).hexdigest()[:32]
        if plan.plan_id != expected_plan_id:
            _reject("$.plan.plan_id", "plan identity is invalid", "TC_PLAN_INVALID")

        first_global = plan.elements[0].global_modifiers
        paths: list[str] = []
        confirmation_required = False
        seen_elements: set[str] = set()
        sequence_name: str | None = None
        shared_unit = "tc-unit-" + hashlib.sha256(
            f"{plan.plan_id}:{'block' if plan.mode is ExpansionMode.BLOCK else 'group'}".encode(
                "ascii"
            )
        ).hexdigest()[:24]
        for index, element in enumerate(plan.elements):
            path = f"$.plan.elements[{index}]"
            if type(element) is not ExpandedElement or element.ordinal != index:
                _reject(path, "plan element ordinal is invalid", "TC_PLAN_INVALID")
            _validate_item(element.command, self.catalog, f"{path}.command")
            if element.global_modifiers != first_global:
                _reject(path, "plan elements disagree on global modifiers", "TC_PLAN_INVALID")
            if plan.mode is ExpansionMode.SIMPLE:
                expected_path = "simple/0000"
            elif plan.mode is ExpansionMode.SEQUENCE:
                match = re.fullmatch(r"sequence/([A-Z][A-Z0-9_.]{0,127})/(\d{4})", element.path)
                if match is None or int(match.group(2)) != index:
                    _reject(f"{path}.path", "sequence expansion path is invalid", "TC_PLAN_INVALID")
                sequence_name = sequence_name or match.group(1)
                if match.group(1) != sequence_name:
                    _reject(f"{path}.path", "sequence paths name different sequences", "TC_PLAN_INVALID")
                expected_path = element.path
            else:
                prefix = "block" if plan.mode is ExpansionMode.BLOCK else "group"
                expected_path = f"{prefix}/{index:04d}"
            if element.path != expected_path:
                _reject(f"{path}.path", "plan expansion path is invalid", "TC_PLAN_INVALID")
            paths.append(element.path)
            expected_element_id = "tc-el-" + hashlib.sha256(
                f"{plan.plan_id}:{element.path}:{element.command.name}".encode("ascii")
            ).hexdigest()[:32]
            if element.element_id != expected_element_id or element.element_id in seen_elements:
                _reject(f"{path}.element_id", "plan element identity is invalid or duplicated", "TC_PLAN_INVALID")
            seen_elements.add(element.element_id)
            expected_unit = (
                shared_unit
                if plan.mode is ExpansionMode.BLOCK or plan.grouped_transport
                else "tc-unit-"
                + hashlib.sha256(f"{plan.plan_id}:{element.path}".encode("ascii")).hexdigest()[:24]
            )
            if element.transport_unit_id != expected_unit:
                _reject(f"{path}.transport_unit_id", "transport unit identity is invalid", "TC_PLAN_INVALID")
            effective, sources = merge_modifiers(first_global, element.command.modifiers)
            if element.effective_modifiers != effective or dict(element.modifier_sources) != dict(sources):
                _reject(path, "effective modifier projection is invalid", "TC_PLAN_INVALID")
            if effective.load_only and (effective.verification or effective.release_time is not None):
                _reject(path, "plan contains conflicting LoadOnly intent", "TC_PLAN_INVALID")
            if effective.adjust_limits and not effective.verification:
                _reject(path, "plan contains AdjLimits without verification", "TC_PLAN_INVALID")
            confirmation_required = (
                confirmation_required
                or element.command.critical
                or effective.confirm
                or effective.confirm_critical
            )

        if plan.mode is ExpansionMode.SEQUENCE:
            assert sequence_name is not None
            sequence = self.catalog.sequences.get(sequence_name)
            if sequence is None or len(sequence.members) != len(plan.elements):
                _reject("$.plan.elements", "sequence plan differs from the catalog", "TC_PLAN_INVALID")
            for index, member in enumerate(sequence.members):
                element = plan.elements[index]
                expected_base = self.build_tc(member.command, member.args)
                if (
                    element.command.name != expected_base.name
                    or element.command.arguments != expected_base.arguments
                ):
                    _reject(
                        f"$.plan.elements[{index}]",
                        "sequence command or arguments differ from the catalog",
                        "TC_PLAN_INVALID",
                    )
        if plan.confirmation_required != confirmation_required:
            _reject("$.plan.confirmation_required", "plan confirmation policy is invalid", "TC_PLAN_INVALID")

        request_identity = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "operation_id": plan.operation_id,
            "catalog_digest": self.catalog.digest,
            "policy_digest": self.policy_digest,
            "mode": plan.mode.value,
            "grouped_transport": plan.grouped_transport,
            "global_modifiers": first_global.explicit_dict(),
            "items": [
                {"path": path, "command": plan.elements[index].command.as_dict()}
                for index, path in enumerate(paths)
            ],
        }
        if plan.request_digest != _digest(request_identity):
            _reject("$.plan.request_digest", "plan request digest is invalid", "TC_PLAN_INVALID")
        plan_without_digest = {
            **request_identity,
            "plan_id": plan.plan_id,
            "elements": [item.as_dict() for item in plan.elements],
            "confirmation_required": confirmation_required,
        }
        if plan.plan_digest != _digest(plan_without_digest):
            _reject("$.plan.plan_digest", "plan content digest is invalid", "TC_PLAN_INVALID")
        challenge = hashlib.sha256(f"confirm:{plan.plan_digest}".encode("ascii")).hexdigest()
        if plan.confirmation_challenge != challenge:
            _reject("$.plan.confirmation_challenge", "plan confirmation challenge is invalid", "TC_PLAN_INVALID")

    def _store(self, snapshot: ExecutionSnapshot) -> ExecutionSnapshot:
        self._operations[snapshot.plan.operation_id] = snapshot
        return snapshot

    def _detail(
        self, item: ElementResult, outcome: ProviderOutcome
    ) -> Mapping[str, Any]:
        detail = dict(item.provider_detail)
        native = _canonical(dict(outcome.detail), "$.provider.detail")
        _reject_secret_keys(native, "$.provider.detail")
        if len(_canonical_bytes(native)) > self.catalog.limits.max_provider_detail_bytes:
            _reject("$.provider.detail", "provider detail exceeds its byte bound", "TC_JSON_BOUNDS")
        detail[outcome.stage.value] = {
            "outcome": outcome.outcome,
            "native": native,
        }
        return MappingProxyType(detail)

    def _apply_outcome(
        self,
        snapshot: ExecutionSnapshot,
        index: int,
        outcome: ProviderOutcome,
        *,
        timed_out: bool = False,
        count_provider_call: bool = True,
    ) -> ExecutionSnapshot:
        item = snapshot.elements[index]
        if item.next_stage is not outcome.stage:
            _reject("$.provider", "provider outcome does not match the pending stage", "TC_PROVIDER_STAGE")
        if outcome.outcome not in _STAGE_OUTCOMES[outcome.stage]:
            _reject("$.provider.outcome", "provider outcome is invalid for the pending stage")
        item = self._record_stage_time(item, outcome.stage)
        detail = self._detail(item, outcome)
        value = outcome.outcome
        if outcome.stage is ElementStage.TRANSPORT:
            if value == "ACCEPTED":
                item = replace(item, transport=value, effect_certainty=EffectCertainty.EFFECT_POSSIBLE, next_stage=ElementStage.LOADING, provider_detail=detail)
            elif value == "REJECTED":
                item = replace(item, transport=value, disposition=Disposition.TRANSPORT_REJECTED, effect_certainty=EffectCertainty.NO_EFFECT, next_stage=None, provider_detail=detail)
            else:
                item = replace(item, transport=value, disposition=Disposition.UNCERTAIN, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
        elif outcome.stage is ElementStage.LOADING:
            if value == "LOADED":
                if snapshot.plan.elements[index].effective_modifiers.load_only:
                    item = replace(item, loading=value, disposition=Disposition.LOADED_ONLY, effect_certainty=EffectCertainty.NO_EFFECT, next_stage=None, provider_detail=detail)
                else:
                    item = replace(item, loading=value, next_stage=ElementStage.RELEASE, provider_detail=detail)
            elif value == "FAILED":
                item = replace(item, loading=value, disposition=Disposition.LOAD_FAILED, effect_certainty=EffectCertainty.NO_EFFECT, next_stage=None, provider_detail=detail)
            else:
                item = replace(item, loading=value, disposition=Disposition.UNCERTAIN, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
        elif outcome.stage is ElementStage.RELEASE:
            if value == "RELEASED":
                item = replace(item, release=value, effect_certainty=EffectCertainty.EFFECT_POSSIBLE, next_stage=ElementStage.ACKNOWLEDGEMENT, provider_detail=detail)
            elif value == "FAILED":
                item = replace(item, release=value, disposition=Disposition.RELEASE_FAILED, effect_certainty=EffectCertainty.NO_EFFECT, next_stage=None, provider_detail=detail)
            else:
                item = replace(item, release=value, disposition=Disposition.UNCERTAIN, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
        elif outcome.stage is ElementStage.ACKNOWLEDGEMENT:
            if value == "ACKNOWLEDGED":
                item = replace(item, acknowledgement=value, next_stage=ElementStage.ONBOARD_EXECUTION, provider_detail=detail)
            elif value in {"NACKED", "TIMED_OUT"}:
                item = replace(item, acknowledgement=value, disposition=Disposition.ACKNOWLEDGEMENT_FAILED, effect_certainty=EffectCertainty.EFFECT_POSSIBLE, next_stage=None, provider_detail=detail)
            else:
                item = replace(item, acknowledgement=value, disposition=Disposition.UNCERTAIN, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
        elif outcome.stage is ElementStage.ONBOARD_EXECUTION:
            if value == "SUCCEEDED":
                if snapshot.plan.elements[index].effective_modifiers.verification:
                    item = replace(item, onboard_execution=value, effect_certainty=EffectCertainty.EFFECT_POSSIBLE, next_stage=ElementStage.VERIFICATION, provider_detail=detail)
                else:
                    item = replace(item, onboard_execution=value, disposition=Disposition.EXECUTED_UNVERIFIED, effect_certainty=EffectCertainty.EFFECT_CONFIRMED, next_stage=None, provider_detail=detail)
            elif value == "FAILED":
                item = replace(item, onboard_execution=value, disposition=Disposition.EXECUTION_FAILED, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
            else:
                item = replace(item, onboard_execution=value, disposition=Disposition.UNCERTAIN, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
        else:
            if value == "PASSED":
                item = replace(item, verification=value, disposition=Disposition.VERIFIED, effect_certainty=EffectCertainty.EFFECT_CONFIRMED, next_stage=None, provider_detail=detail)
            elif value == "FAILED":
                item = replace(item, verification=value, disposition=Disposition.VERIFICATION_FAILED, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)
            else:
                item = replace(item, verification=value, disposition=Disposition.UNCERTAIN, effect_certainty=EffectCertainty.EFFECT_UNKNOWN, next_stage=None, provider_detail=detail)

        if timed_out:
            timing = dict(item.timing_detail)
            timing["timed_out_at"] = self.clock.now
            certainty = (
                EffectCertainty.NO_EFFECT
                if item.transport in {"NOT_ATTEMPTED", "REJECTED"}
                else EffectCertainty.EFFECT_CONFIRMED
                if item.onboard_execution == "SUCCEEDED"
                else EffectCertainty.EFFECT_UNKNOWN
            )
            item = replace(
                item,
                disposition=Disposition.TIMED_OUT,
                effect_certainty=certainty,
                next_stage=None,
                timing_detail=MappingProxyType(timing),
            )

        elements = list(snapshot.elements)
        elements[index] = item
        next_index = index
        if item.terminal:
            is_failure = item.disposition not in {
                Disposition.LOADED_ONLY,
                Disposition.EXECUTED_UNVERIFIED,
                Disposition.VERIFIED,
            }
            on_failure = snapshot.plan.elements[index].effective_modifiers.on_failure
            if is_failure and on_failure in {"ABORT", "CANCEL"}:
                for later in range(index + 1, len(elements)):
                    elements[later] = replace(
                        elements[later], disposition=Disposition.CANCELLED, next_stage=None
                    )
                next_index = len(elements)
            else:
                next_index = index + 1
        state = OperationState.SETTLED if next_index >= len(elements) else OperationState.DISPATCHED
        return replace(
            snapshot,
            state=state,
            revision=snapshot.revision + 1,
            current_index=next_index,
            elements=tuple(elements),
            provider_call_count=snapshot.provider_call_count
            + (1 if count_provider_call else 0),
        )

    def _apply_shared_transport(
        self,
        snapshot: ExecutionSnapshot,
        outcome: ProviderOutcome,
    ) -> ExecutionSnapshot:
        current_plan_element = snapshot.plan.elements[snapshot.current_index]
        unit_id = current_plan_element.transport_unit_id
        indexes = [
            index
            for index, plan_element in enumerate(snapshot.plan.elements)
            if plan_element.transport_unit_id == unit_id
            and snapshot.elements[index].next_stage is ElementStage.TRANSPORT
        ]
        if not indexes or outcome.stage is not ElementStage.TRANSPORT:
            _reject("$.provider", "shared transport outcome has no pending transport unit")
        elements = list(snapshot.elements)
        timed_out_indexes = {
            index
            for index in indexes
            if self._deadline_exceeded(elements[index])
        }
        for index in indexes:
            item = self._record_stage_time(elements[index], outcome.stage)
            detail = self._detail(item, outcome)
            if outcome.outcome == "ACCEPTED":
                elements[index] = replace(
                    item,
                    transport="ACCEPTED",
                    effect_certainty=EffectCertainty.EFFECT_POSSIBLE,
                    next_stage=ElementStage.LOADING,
                    provider_detail=detail,
                )
            elif outcome.outcome == "REJECTED":
                elements[index] = replace(
                    item,
                    transport="REJECTED",
                    disposition=Disposition.TRANSPORT_REJECTED,
                    effect_certainty=EffectCertainty.NO_EFFECT,
                    next_stage=None,
                    provider_detail=detail,
                )
            else:
                elements[index] = replace(
                    item,
                    transport="UNCERTAIN",
                    disposition=Disposition.UNCERTAIN,
                    effect_certainty=EffectCertainty.EFFECT_UNKNOWN,
                    next_stage=None,
                    provider_detail=detail,
                )
            if index in timed_out_indexes:
                timed_item = elements[index]
                timing = dict(timed_item.timing_detail)
                timing["timed_out_at"] = self.clock.now
                elements[index] = replace(
                    timed_item,
                    disposition=Disposition.TIMED_OUT,
                    effect_certainty=(
                        EffectCertainty.NO_EFFECT
                        if timed_item.transport == "REJECTED"
                        else EffectCertainty.EFFECT_UNKNOWN
                    ),
                    next_stage=None,
                    timing_detail=MappingProxyType(timing),
                )
        if outcome.outcome == "ACCEPTED" and len(timed_out_indexes) < len(indexes):
            next_index = next(
                index for index, item in enumerate(elements) if not item.terminal
            )
            state = OperationState.DISPATCHED
        else:
            for index, item in enumerate(elements):
                if not item.terminal:
                    elements[index] = replace(
                        item, disposition=Disposition.CANCELLED, next_stage=None
                    )
            next_index = len(elements)
            state = OperationState.SETTLED
        return replace(
            snapshot,
            state=state,
            revision=snapshot.revision + 1,
            current_index=next_index,
            elements=tuple(elements),
            provider_call_count=snapshot.provider_call_count + 1,
        )

    def _mark_reconciliation_unknown(
        self, item: ElementResult, detail: Mapping[str, Any]
    ) -> ElementResult:
        provider_detail = dict(item.provider_detail)
        native = _canonical(dict(detail), "$.reconciliation.detail")
        _reject_secret_keys(native, "$.reconciliation.detail")
        if len(_canonical_bytes(native)) > self.catalog.limits.max_provider_detail_bytes:
            _reject(
                "$.reconciliation.detail",
                "provider reconciliation detail exceeds its byte bound",
                "TC_JSON_BOUNDS",
            )
        provider_detail["RECONCILIATION"] = {
            "outcome": "UNKNOWN",
            "native": native,
        }
        field_name = {
            ElementStage.TRANSPORT: "transport",
            ElementStage.LOADING: "loading",
            ElementStage.RELEASE: "release",
            ElementStage.ACKNOWLEDGEMENT: "acknowledgement",
            ElementStage.ONBOARD_EXECUTION: "onboard_execution",
            ElementStage.VERIFICATION: "verification",
        }[item.next_stage]
        return replace(
            item,
            **{field_name: "UNCERTAIN"},
            disposition=Disposition.UNCERTAIN,
            effect_certainty=EffectCertainty.EFFECT_UNKNOWN,
            provider_detail=MappingProxyType(provider_detail),
        )

    def _element_from_checkpoint(
        self, plan_element: ExpandedElement, raw: Any, path: str
    ) -> ElementResult:
        if type(raw) is not dict:
            _reject(path, "checkpoint element must be an object", "TC_CHECKPOINT_INVALID")
        fields = {
            "element_id", "command_name", "transport", "loading", "release",
            "acknowledgement", "onboard_execution", "verification", "disposition",
            "effect_certainty", "next_stage", "provider_detail", "timing_detail",
        }
        _exact_keys(raw, fields, set(), path)
        if raw["element_id"] != plan_element.element_id or raw["command_name"] != plan_element.command.name:
            _reject(path, "checkpoint element identity differs from plan", "TC_CHECKPOINT_INVALID")
        allowed_states = {
            "transport": {"NOT_ATTEMPTED", "ACCEPTED", "REJECTED", "UNCERTAIN"},
            "loading": {"NOT_ATTEMPTED", "LOADED", "FAILED", "UNCERTAIN"},
            "release": {"NOT_ATTEMPTED", "NOT_REQUESTED", "RELEASED", "FAILED", "UNCERTAIN"},
            "acknowledgement": {"NOT_ATTEMPTED", "ACKNOWLEDGED", "NACKED", "TIMED_OUT", "UNCERTAIN"},
            "onboard_execution": {"NOT_ATTEMPTED", "SUCCEEDED", "FAILED", "UNCERTAIN"},
            "verification": {"NOT_REQUESTED", "NOT_ATTEMPTED", "PASSED", "FAILED", "INDETERMINATE", "UNCERTAIN"},
        }
        for name, allowed in allowed_states.items():
            if raw[name] not in allowed:
                _reject(f"{path}.{name}", "checkpoint stage state is invalid", "TC_CHECKPOINT_INVALID")
        try:
            disposition = Disposition(raw["disposition"])
            certainty = EffectCertainty(raw["effect_certainty"])
            next_stage = None if raw["next_stage"] is None else ElementStage(raw["next_stage"])
        except (TypeError, ValueError) as exc:
            raise TelecommandValidationError(
                "TC_CHECKPOINT_INVALID", path, "checkpoint enum value is invalid"
            ) from exc
        if type(raw["provider_detail"]) is not dict:
            _reject(f"{path}.provider_detail", "provider detail must be an object")
        detail = _canonical(raw["provider_detail"], f"{path}.provider_detail")
        if len(_canonical_bytes(detail)) > self.catalog.limits.max_provider_detail_bytes * len(ElementStage):
            _reject(f"{path}.provider_detail", "checkpoint provider detail exceeds bounds")
        if type(raw["timing_detail"]) is not dict:
            _reject(f"{path}.timing_detail", "timing detail must be an object")
        timing = _canonical(raw["timing_detail"], f"{path}.timing_detail")
        if len(_canonical_bytes(timing)) > self.catalog.limits.max_provider_detail_bytes:
            _reject(f"{path}.timing_detail", "checkpoint timing detail exceeds bounds")
        if timing:
            _exact_keys(
                timing,
                {
                    "ready_at",
                    "requested_transport_due_at",
                    "transport_due_at",
                    "deadline_at",
                    "stage_times",
                    "waits",
                },
                {"release_due_at", "verification_due_at", "timed_out_at"},
                f"{path}.timing_detail",
            )
            for key in (
                "ready_at",
                "requested_transport_due_at",
                "transport_due_at",
                "deadline_at",
                "release_due_at",
                "verification_due_at",
                "timed_out_at",
            ):
                if key in timing:
                    if type(timing[key]) is not str:
                        _reject(f"{path}.timing_detail.{key}", "timing value is invalid")
                    _iso_to_epoch_ms(timing[key], f"{path}.timing_detail.{key}")
            if type(timing["stage_times"]) is not dict or type(timing["waits"]) is not dict:
                _reject(f"{path}.timing_detail", "timing stage maps are invalid")
            for stage, at in timing["stage_times"].items():
                if stage not in {value.value for value in ElementStage} or type(at) is not str:
                    _reject(f"{path}.timing_detail.stage_times", "stage timestamp is invalid")
                _iso_to_epoch_ms(at, f"{path}.timing_detail.stage_times.{stage}")
            for stage, wait in timing["waits"].items():
                if stage not in {value.value for value in ElementStage} or type(wait) is not dict:
                    _reject(f"{path}.timing_detail.waits", "stage wait is invalid")
                _exact_keys(
                    wait,
                    {"from", "until", "duration_ms"},
                    set(),
                    f"{path}.timing_detail.waits.{stage}",
                )
                if type(wait["duration_ms"]) is not int or wait["duration_ms"] < 0:
                    _reject(f"{path}.timing_detail.waits.{stage}", "wait duration is invalid")
                _iso_to_epoch_ms(wait["from"], f"{path}.timing_detail.waits.{stage}.from")
                _iso_to_epoch_ms(wait["until"], f"{path}.timing_detail.waits.{stage}.until")
        if disposition is Disposition.PENDING and next_stage is None:
            _reject(path, "pending element must name its next stage", "TC_CHECKPOINT_INVALID")
        if disposition is not Disposition.PENDING and disposition is not Disposition.UNCERTAIN and next_stage is not None:
            _reject(path, "terminal disposition cannot name a next stage", "TC_CHECKPOINT_INVALID")
        return ElementResult(
            element_id=raw["element_id"],
            command_name=raw["command_name"],
            transport=raw["transport"],
            loading=raw["loading"],
            release=raw["release"],
            acknowledgement=raw["acknowledgement"],
            onboard_execution=raw["onboard_execution"],
            verification=raw["verification"],
            disposition=disposition,
            effect_certainty=certainty,
            next_stage=next_stage,
            provider_detail=MappingProxyType(detail),
            timing_detail=MappingProxyType(timing),
        )

    def _validate_checkpoint_coherence(
        self,
        plan: SendPlan,
        state: OperationState,
        current_index: int,
        elements: tuple[ElementResult, ...],
    ) -> None:
        if state is OperationState.SETTLED:
            if current_index != len(elements) or any(not item.terminal for item in elements):
                _reject(
                    "$checkpoint",
                    "settled checkpoint contains pending elements or an incomplete cursor",
                    "TC_CHECKPOINT_INVALID",
                )
        else:
            if current_index >= len(elements) or elements[current_index].terminal:
                _reject(
                    "$checkpoint.current_index",
                    "nonterminal checkpoint cursor does not identify pending work",
                    "TC_CHECKPOINT_INVALID",
                )
            if any(not item.terminal for item in elements[:current_index]):
                _reject(
                    "$checkpoint.elements",
                    "checkpoint cursor skips unfinished elements",
                    "TC_CHECKPOINT_INVALID",
                )

        for index, item in enumerate(elements):
            path = f"$checkpoint.elements[{index}]"
            next_stage = item.next_stage
            if next_stage is ElementStage.TRANSPORT:
                coherent = (
                    item.transport in {"NOT_ATTEMPTED", "UNCERTAIN"}
                    and item.loading == "NOT_ATTEMPTED"
                    and item.acknowledgement == "NOT_ATTEMPTED"
                    and item.onboard_execution == "NOT_ATTEMPTED"
                )
            elif next_stage is ElementStage.LOADING:
                coherent = (
                    item.transport == "ACCEPTED"
                    and item.loading in {"NOT_ATTEMPTED", "UNCERTAIN"}
                    and item.acknowledgement == "NOT_ATTEMPTED"
                    and item.onboard_execution == "NOT_ATTEMPTED"
                )
            elif next_stage is ElementStage.RELEASE:
                coherent = (
                    item.transport == "ACCEPTED"
                    and item.loading == "LOADED"
                    and item.release in {"NOT_ATTEMPTED", "UNCERTAIN"}
                    and item.acknowledgement == "NOT_ATTEMPTED"
                )
            elif next_stage is ElementStage.ACKNOWLEDGEMENT:
                coherent = item.release == "RELEASED" and item.acknowledgement in {
                    "NOT_ATTEMPTED",
                    "UNCERTAIN",
                }
            elif next_stage is ElementStage.ONBOARD_EXECUTION:
                coherent = (
                    item.acknowledgement == "ACKNOWLEDGED"
                    and item.onboard_execution in {"NOT_ATTEMPTED", "UNCERTAIN"}
                )
            elif next_stage is ElementStage.VERIFICATION:
                coherent = (
                    item.onboard_execution == "SUCCEEDED"
                    and item.verification in {"NOT_ATTEMPTED", "UNCERTAIN"}
                )
            else:
                terminal_checks = {
                    Disposition.TRANSPORT_REJECTED: item.transport == "REJECTED",
                    Disposition.LOAD_FAILED: item.loading == "FAILED",
                    Disposition.RELEASE_FAILED: item.release == "FAILED",
                    Disposition.ACKNOWLEDGEMENT_FAILED: item.acknowledgement
                    in {"NACKED", "TIMED_OUT"},
                    Disposition.EXECUTION_FAILED: item.onboard_execution == "FAILED",
                    Disposition.VERIFICATION_FAILED: (
                        item.onboard_execution == "SUCCEEDED"
                        and item.verification == "FAILED"
                    ),
                    Disposition.LOADED_ONLY: (
                        item.loading == "LOADED"
                        and item.release == "NOT_REQUESTED"
                        and item.onboard_execution == "NOT_ATTEMPTED"
                    ),
                    Disposition.EXECUTED_UNVERIFIED: (
                        item.onboard_execution == "SUCCEEDED"
                        and item.verification == "NOT_REQUESTED"
                    ),
                    Disposition.VERIFIED: (
                        item.onboard_execution == "SUCCEEDED"
                        and item.verification == "PASSED"
                    ),
                    Disposition.TIMED_OUT: "timed_out_at" in item.timing_detail,
                    Disposition.UNCERTAIN: any(
                        value in {"UNCERTAIN", "INDETERMINATE"}
                        for value in (
                            item.transport,
                            item.loading,
                            item.release,
                            item.acknowledgement,
                            item.onboard_execution,
                            item.verification,
                        )
                    ),
                    Disposition.CANCELLED: True,
                    Disposition.PENDING: False,
                }
                coherent = terminal_checks[item.disposition]
            if not coherent:
                _reject(
                    path,
                    "checkpoint contains an impossible stage/disposition combination",
                    "TC_CHECKPOINT_INVALID",
                )
            if any(
                value != "NOT_ATTEMPTED"
                for value in (
                    item.transport,
                    item.loading,
                    item.acknowledgement,
                    item.onboard_execution,
                )
            ) and not item.timing_detail:
                _reject(
                    f"{path}.timing_detail",
                    "checkpoint with stage progress is missing timing evidence",
                    "TC_CHECKPOINT_INVALID",
                )
            if item.disposition in {
                Disposition.TRANSPORT_REJECTED,
                Disposition.LOAD_FAILED,
                Disposition.RELEASE_FAILED,
                Disposition.LOADED_ONLY,
            } and item.effect_certainty is not EffectCertainty.NO_EFFECT:
                _reject(
                    f"{path}.effect_certainty",
                    "checkpoint certainty conflicts with an authoritative no-effect disposition",
                    "TC_CHECKPOINT_INVALID",
                )
            if item.disposition in {
                Disposition.EXECUTED_UNVERIFIED,
                Disposition.VERIFIED,
            } and item.effect_certainty is not EffectCertainty.EFFECT_CONFIRMED:
                _reject(
                    f"{path}.effect_certainty",
                    "checkpoint certainty conflicts with confirmed execution",
                    "TC_CHECKPOINT_INVALID",
                )
            if plan.elements[index].effective_modifiers.load_only and item.release not in {
                "NOT_REQUESTED",
            }:
                _reject(
                    f"{path}.release",
                    "LoadOnly checkpoint contains a release stage",
                    "TC_CHECKPOINT_INVALID",
                )


@lru_cache(maxsize=1)
def default_catalog() -> TelecommandCatalog:
    return TelecommandCatalog.load()


def BuildTC(
    name: str,
    args: Any = None,
    *,
    modifiers: Mapping[str, Any] | None = None,
    catalog: TelecommandCatalog | None = None,
) -> CommandItem:
    """Build one immutable command item from the pinned typed catalog."""

    return (catalog or default_catalog()).build_tc(name, args, modifiers=modifiers)


build_tc = BuildTC


def Send(
    *,
    operation_id: str,
    command: str | CommandItem | None = None,
    sequence: str | None = None,
    group: Sequence[str | CommandItem] | None = None,
    args: Any = None,
    catalog: TelecommandCatalog | None = None,
    provider: DeterministicScriptedProvider | None = None,
    clock: DeterministicClock | None = None,
    telemetry_evaluator: DeterministicTelemetryEvaluator | None = None,
    confirmation_actor: str | None = None,
    confirmation_reason: str = "confirmed for deterministic simulation",
    block: bool = False,
    **modifiers: Any,
) -> ExecutionSnapshot:
    """Execute a bounded one-shot simulator Send request.

    The explicit service API should be used for cancellation and recovery.  A
    nominal provider is created only after the complete plan is accepted.
    """

    if "Block" in modifiers:
        legacy_block = modifiers.pop("Block")
        if type(legacy_block) is not bool or (block and not legacy_block):
            _reject("$.Block", "Block selector is invalid")
        block = legacy_block
    if "Group" in modifiers:
        legacy_group = modifiers["Group"]
        if legacy_group is not True or group is None:
            _reject("$.Group", "Group=True requires a group selector")
    service = TelecommandService(
        catalog,
        clock=clock,
        telemetry_evaluator=telemetry_evaluator,
    )
    preflight = service.preflight(
        SendRequest(
            operation_id=operation_id,
            command=command,
            sequence=sequence,
            group=group,
            args=args,
            modifiers=modifiers,
            block=block,
        )
    )
    confirmation = None
    if preflight.confirmation_required:
        if confirmation_actor is None:
            raise ConfirmationRequired(preflight.plan.confirmation_challenge)
        confirmation = service.confirm(
            preflight, actor=confirmation_actor, reason=confirmation_reason
        )
    snapshot = service.start(preflight, confirmation)
    selected_provider = provider or DeterministicScriptedProvider.nominal(
        preflight.plan,
        include_verification=telemetry_evaluator is None,
    )
    return service.run(snapshot, selected_provider)


send = Send


__all__ = [
    "BuildTC",
    "CHECKPOINT_SCHEMA_VERSION",
    "CATALOG_SCHEMA_VERSION",
    "CommandDefinition",
    "CommandItem",
    "Confirmation",
    "ConfirmationRequired",
    "DeterministicClock",
    "DeterministicScriptedProvider",
    "DeterministicTelemetryEvaluator",
    "Disposition",
    "EffectCertainty",
    "ElementResult",
    "ElementStage",
    "EXECUTION_SCHEMA_VERSION",
    "ExecutionSnapshot",
    "ExpandedElement",
    "ExpansionMode",
    "OperationState",
    "PLAN_SCHEMA_VERSION",
    "Preflight",
    "ProviderCall",
    "ProviderOutcome",
    "ProviderScriptError",
    "ProviderStep",
    "ReconciliationReport",
    "Send",
    "SendModifiers",
    "SendPlan",
    "SendRequest",
    "SequenceDefinition",
    "SimulatedProviderCrash",
    "TelecommandCatalog",
    "TelecommandContractError",
    "TelecommandError",
    "TelecommandService",
    "TelecommandValidationError",
    "TelemetryFixture",
    "TypedArgument",
    "VerificationEvaluation",
    "VerificationIntent",
    "build_tc",
    "default_catalog",
    "default_catalog_path",
    "default_execution_contract_path",
    "load_execution_contract",
    "merge_modifiers",
    "parse_modifiers",
    "send",
]
