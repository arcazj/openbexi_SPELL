"""Closed, data-only procedure IR additions for v0.8 local data services.

Workers can request only the bounded operations declared here. They never
receive repository, database, filesystem, credential, or network authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Mapping, Protocol

from .ir_v03 import ValidatedIR
from .ir_v06 import V06_STEP_TARGET_FIELDS, V06ValidationError, reject_secret_material, validate_ir_v06
from .ir_v07 import V07ValidationError, validate_ir_v07


IR_VERSION = "0.8"
REQUEST_SCHEMA_VERSION = "spell.v08.data-request/1"
RESULT_SCHEMA_VERSION = "spell.v08.data-result/1"
FILE_HANDLE_REFERENCE_SCHEMA_VERSION = "spell.v08.file-handle-reference/1"
MAX_PARAMETER_BYTES = 2_000_000
MAX_RESULT_BYTES = 2_000_000

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_BASE_STEP_FIELDS = frozenset(
    {"index", "type", "line", "column", "guard", *V06_STEP_TARGET_FIELDS}
)
_TARGET_TYPES = frozenset({"bool", "float", "int", "str"})
_ARGUMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_ARGUMENT_TYPES = frozenset(
    {
        "bool",
        "float",
        "int",
        "str",
        "BOOLEAN",
        "LONG",
        "FLOAT",
        "STRING",
        "DATETIME",
        "RELTIME",
    }
)
_OUTCOMES = frozenset(
    {
        "OK",
        "NOT_FOUND",
        "NOT_AUTHORIZED",
        "REVISION_CONFLICT",
        "RESYNC_REQUIRED",
        "TYPE_MISMATCH",
        "LIMIT_EXCEEDED",
        "CORRUPT_DATA",
        "STALE_HANDLE",
        "REJECTED",
        "CANCELLED",
        "INTERNAL",
    }
)
_HANDLE_RESULT_OPERATIONS = frozenset(
    {
        "CREATE_DICTIONARY",
        "LOAD_DICTIONARY",
        "CREATE_CONTAINER",
        "FILE_VALUE",
        "OPEN_FILE",
    }
)
_VALUE_RESULT_OPERATIONS = frozenset(
    {
        "SHARED_LIST_NAMESPACES",
        "SHARED_GET",
        "SHARED_ENUMERATE",
        "FILE_PROPERTY",
        "READ_FILE",
        "READ_DIRECTORY",
    }
)

# Required and optional parameters are deliberately operation-specific. The
# values remain canonical JSON. FileHandle inputs use one closed variable-ref
# node which the worker resolves by exact name and type before requesting work.
_OPERATION_FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "CREATE_DICTIONARY": (frozenset({"dictionary_id", "format"}), frozenset()),
    "LOAD_DICTIONARY": (
        frozenset(
            {
                "dictionary_id",
                "expected_revision",
                "format",
                "root_id",
                "source_revision",
                "virtual_path",
            }
        ),
        frozenset(),
    ),
    "SAVE_DICTIONARY": (
        frozenset(
            {
                "dictionary_id",
                "dictionary_revision",
                "expected_file_revision",
                "format",
                "root_id",
                "virtual_path",
            }
        ),
        frozenset(),
    ),
    "CREATE_CONTAINER": (
        frozenset({"container_id", "schema_revision"}),
        frozenset(),
    ),
    "SET_VARIABLE": (
        frozenset(
            {
                "container_id",
                "variable_id",
                "name",
                "declared_type",
                "value",
                "expected_revision",
            }
        ),
        frozenset(),
    ),
    "DELETE_VARIABLE": (
        frozenset({"container_id", "variable_id", "expected_revision"}),
        frozenset(),
    ),
    "SHARED_CREATE_NAMESPACE": (
        frozenset({"namespace_id", "scope", "acl_revision"}),
        frozenset(),
    ),
    "SHARED_LIST_NAMESPACES": (frozenset(), frozenset({"cursor"})),
    "SHARED_GET": (frozenset({"namespace_id", "key"}), frozenset()),
    "SHARED_ENUMERATE": (frozenset({"namespace_id"}), frozenset({"cursor"})),
    "SHARED_PUT": (
        frozenset(
            {
                "namespace_id",
                "key",
                "value",
                "expected_namespace_revision",
                "expected_entry_revision",
            }
        ),
        frozenset(),
    ),
    "SHARED_DELETE": (
        frozenset(
            {
                "namespace_id",
                "key",
                "expected_namespace_revision",
                "expected_entry_revision",
            }
        ),
        frozenset(),
    ),
    "SHARED_CLEAR": (
        frozenset({"namespace_id", "expected_namespace_revision"}),
        frozenset(),
    ),
    "SHARED_DELETE_NAMESPACE": (
        frozenset({"namespace_id", "expected_namespace_revision"}),
        frozenset(),
    ),
    "FILE_VALUE": (frozenset({"root_id", "virtual_path"}), frozenset()),
    "FILE_PROPERTY": (
        frozenset({"property"}),
        frozenset({"root_id", "virtual_path", "handle"}),
    ),
    "OPEN_FILE": (
        frozenset({"root_id", "virtual_path", "mode"}),
        frozenset({"revision"}),
    ),
    "CLOSE_FILE": (frozenset({"handle"}), frozenset()),
    "READ_FILE": (
        frozenset(),
        frozenset({"root_id", "virtual_path", "revision", "handle", "length"}),
    ),
    "READ_DIRECTORY": (
        frozenset({"root_id", "virtual_path"}),
        frozenset({"cursor"}),
    ),
    "WRITE_FILE": (
        frozenset({"encoding", "content"}),
        frozenset(
            {
                "root_id",
                "virtual_path",
                "handle",
                "expected_revision",
                "content_sha256",
            }
        ),
    ),
    "DELETE_FILE": (
        frozenset({"root_id", "virtual_path", "expected_revision"}),
        frozenset(),
    ),
}

_REQUEST_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "openbexi-spell:v0.8:data-request"
)


class V08ValidationError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class DataRuntime(Protocol):
    def resolve(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _reject(code: str, path: str, message: str) -> None:
    raise V08ValidationError(code, path, message)


def _canonical_json(value: Any, path: str, maximum: int) -> Any:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(encoded) > maximum:
            _reject("BOUND_EXCEEDED", path, "canonical JSON exceeds the byte limit")
        return json.loads(encoded.decode("ascii"))
    except V08ValidationError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise V08ValidationError(
            "DATA_CONTRACT_INVALID", path, "value must be finite JSON data"
        ) from exc


def _exact_keys(
    value: Mapping[str, Any], required: set[str] | frozenset[str], optional: set[str] | frozenset[str], path: str
) -> None:
    keys = set(value)
    missing = set(required) - keys
    extra = keys - set(required) - set(optional)
    if missing:
        _reject("DATA_CONTRACT_INVALID", path, f"missing fields: {', '.join(sorted(missing))}")
    if extra:
        _reject("DATA_CONTRACT_INVALID", path, f"unknown fields: {', '.join(sorted(extra))}")


def _identifier(value: Any, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject("DATA_CONTRACT_INVALID", path, "must be a bounded ASCII identifier")
    return value


def validate_file_handle_reference(
    value: Any,
    path: str = "$.file_handle",
    *,
    execution_id: str | None = None,
    worker_generation: int | None = None,
    creator_request_id: str | None = None,
    require_open: bool = False,
) -> dict[str, Any]:
    """Validate the closed, digest-only durable representation of a FileHandle."""

    if type(value) is not dict:
        _reject("DATA_CONTRACT_INVALID", path, "FileHandle reference must be an object")
    canonical = _canonical_json(value, path, 4_096)
    _exact_keys(
        canonical,
        {
            "schema_version",
            "value_type",
            "token_sha256",
            "execution_id",
            "worker_generation",
            "creator_request_id",
            "state",
        },
        frozenset(),
        path,
    )
    if canonical["schema_version"] != FILE_HANDLE_REFERENCE_SCHEMA_VERSION:
        _reject("DATA_CONTRACT_INVALID", f"{path}.schema_version", "FileHandle schema is invalid")
    if canonical["value_type"] != "FileHandle":
        _reject("DATA_CONTRACT_INVALID", f"{path}.value_type", "FileHandle type is invalid")
    if type(canonical["token_sha256"]) is not str or _DIGEST.fullmatch(
        canonical["token_sha256"]
    ) is None:
        _reject("DATA_CONTRACT_INVALID", f"{path}.token_sha256", "FileHandle digest is invalid")
    reference_execution_id = canonical["execution_id"]
    if (
        type(reference_execution_id) is not str
        or not reference_execution_id
        or len(reference_execution_id) > 200
        or not reference_execution_id.isascii()
    ):
        _reject("DATA_CONTRACT_INVALID", f"{path}.execution_id", "FileHandle execution is invalid")
    reference_generation = canonical["worker_generation"]
    if type(reference_generation) is not int or reference_generation < 0:
        _reject("DATA_CONTRACT_INVALID", f"{path}.worker_generation", "FileHandle generation is invalid")
    _identifier(canonical["creator_request_id"], f"{path}.creator_request_id")
    if canonical["state"] not in {"OPEN", "CLOSED"}:
        _reject("DATA_CONTRACT_INVALID", f"{path}.state", "FileHandle state is invalid")
    if execution_id is not None and reference_execution_id != execution_id:
        _reject("STALE_HANDLE", path, "FileHandle execution binding is stale")
    if worker_generation is not None and reference_generation != worker_generation:
        _reject("STALE_HANDLE", path, "FileHandle worker generation is stale")
    if creator_request_id is not None and canonical["creator_request_id"] != creator_request_id:
        _reject("STALE_HANDLE", path, "FileHandle creator request is stale")
    if require_open and canonical["state"] != "OPEN":
        _reject("STALE_HANDLE", path, "FileHandle is closed or stale")
    return canonical


def file_handle_reference(
    token: Any,
    *,
    execution_id: str,
    worker_generation: int,
    creator_request_id: str,
) -> dict[str, Any]:
    """Hash a transient capability token into its persistable typed reference."""

    if type(token) is not str or not token or len(token) > 2_048 or not token.isascii():
        _reject("DATA_RESULT_INVALID", "$.result.value", "transient FileHandle token is invalid")
    return validate_file_handle_reference(
        {
            "schema_version": FILE_HANDLE_REFERENCE_SCHEMA_VERSION,
            "value_type": "FileHandle",
            "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "execution_id": execution_id,
            "worker_generation": worker_generation,
            "creator_request_id": creator_request_id,
            "state": "OPEN",
        }
    )


def closed_file_handle_reference(value: Any) -> dict[str, Any]:
    reference = validate_file_handle_reference(value, require_open=True)
    return {**reference, "state": "CLOSED"}


def is_file_handle_reference(value: Any) -> bool:
    try:
        validate_file_handle_reference(value)
    except V08ValidationError:
        return False
    return True


def _validate_argument_declarations(value: Any, path: str) -> dict[str, str]:
    if type(value) is not dict or len(value) > 64:
        _reject(
            "IR_VALIDATION_FAILED",
            path,
            "argument declarations must be a bounded object",
        )
    canonical = _canonical_json(value, path, 32_768)
    declarations: dict[str, str] = {}
    for name in sorted(canonical):
        declared_type = canonical[name]
        if (
            _ARGUMENT_NAME.fullmatch(name) is None
            or name.startswith("__")
            or name in {"ARGS", "IVARS"}
        ):
            _reject(
                "IR_VALIDATION_FAILED",
                f"{path}.{name}",
                "argument name is invalid or reserved",
            )
        if declared_type not in _ARGUMENT_TYPES:
            _reject(
                "IR_VALIDATION_FAILED",
                f"{path}.{name}",
                "argument type is not authorized",
            )
        declarations[name] = declared_type
    return declarations


def _validate_variable_reference(value: Any, path: str) -> dict[str, str]:
    if type(value) is not dict:
        _reject("DATA_CONTRACT_INVALID", path, "FileHandle input must be a variable reference")
    _exact_keys(value, {"kind", "name", "value_type"}, frozenset(), path)
    if value.get("kind") != "variable_ref" or value.get("value_type") != "FileHandle":
        _reject("DATA_CONTRACT_INVALID", path, "FileHandle variable reference is invalid")
    return {
        "kind": "variable_ref",
        "name": _identifier(value.get("name"), f"{path}.name"),
        "value_type": "FileHandle",
    }


def _is_variable_reference(value: Any) -> bool:
    return type(value) is dict and value.get("kind") == "variable_ref"


def argument_declarations_from_steps(steps: Any) -> dict[str, str]:
    """Return the independently validated immutable v0.8 argument contract."""

    if type(steps) not in {list, tuple} or not steps or type(steps[0]) is not dict:
        _reject("IR_VALIDATION_FAILED", "$.steps", "steps must be a nonempty array")
    return _validate_argument_declarations(
        steps[0].get("argument_declarations"),
        "$.steps[0].argument_declarations",
    )


def _validate_parameters(
    operation: str,
    value: Any,
    path: str,
    *,
    resolved_references: bool = False,
) -> dict[str, Any]:
    if type(value) is not dict:
        _reject("DATA_CONTRACT_INVALID", path, "parameters must be an object")
    parameters = _canonical_json(value, path, MAX_PARAMETER_BYTES)
    required, optional = _OPERATION_FIELDS[operation]
    _exact_keys(parameters, required, optional, path)
    reject_secret_material(parameters, path)
    if "handle" in parameters:
        if resolved_references:
            parameters["handle"] = validate_file_handle_reference(
                parameters["handle"], f"{path}.handle", require_open=True
            )
        else:
            parameters["handle"] = _validate_variable_reference(
                parameters["handle"], f"{path}.handle"
            )
    for key in (
        "dictionary_id",
        "container_id",
        "variable_id",
        "namespace_id",
        "owner_id",
        "root_id",
    ):
        if key in parameters:
            _identifier(parameters[key], f"{path}.{key}")
    if "format" in parameters and parameters["format"] not in {"DB", "IMP"}:
        _reject("DATA_CONTRACT_INVALID", f"{path}.format", "format must be DB or IMP")
    if "scope" in parameters and parameters["scope"] not in {"PROJECT", "CONTEXT", "EXECUTION"}:
        _reject("DATA_CONTRACT_INVALID", f"{path}.scope", "scope is invalid")
    if operation == "SHARED_CREATE_NAMESPACE" and parameters.get("scope") != "EXECUTION":
        _reject(
            "DATA_CONTRACT_INVALID",
            f"{path}.scope",
            "procedure shared namespaces are execution scoped",
        )
    if "mode" in parameters and parameters["mode"] not in {"READ", "WRITE", "READ_WRITE", "APPEND"}:
        _reject("DATA_CONTRACT_INVALID", f"{path}.mode", "mode is invalid")
    if "encoding" in parameters and parameters["encoding"] not in {"UTF8_TEXT", "BINARY"}:
        _reject("DATA_CONTRACT_INVALID", f"{path}.encoding", "encoding is invalid")
    if "content_sha256" in parameters and (
        type(parameters["content_sha256"]) is not str
        or _DIGEST.fullmatch(parameters["content_sha256"]) is None
    ):
        _reject("DATA_CONTRACT_INVALID", f"{path}.content_sha256", "digest is invalid")
    for key in (
        "revision",
        "source_revision",
        "dictionary_revision",
        "expected_file_revision",
        "schema_revision",
        "expected_revision",
        "expected_namespace_revision",
        "expected_entry_revision",
        "acl_revision",
        "length",
    ):
        if key in parameters and (type(parameters[key]) is not int or parameters[key] < 0):
            _reject("DATA_CONTRACT_INVALID", f"{path}.{key}", "revision or length is invalid")
    for key in ("source_revision", "dictionary_revision"):
        if key in parameters and parameters[key] == 0:
            _reject(
                "DATA_CONTRACT_INVALID",
                f"{path}.{key}",
                "selected revision must be positive",
            )
    if operation == "SAVE_DICTIONARY" and parameters.get("format") != "DB":
        _reject(
            "DATA_CONTRACT_INVALID",
            f"{path}.format",
            "SaveDictionary emits only canonical DB bytes",
        )
    if operation == "READ_FILE" and not (
        ("handle" in parameters)
        ^ ({"root_id", "virtual_path"} <= set(parameters))
    ):
        _reject("DATA_CONTRACT_INVALID", path, "READ_FILE requires a handle or root/path")
    if operation == "WRITE_FILE" and not (
        ("handle" in parameters)
        ^ ({"root_id", "virtual_path"} <= set(parameters))
    ):
        _reject("DATA_CONTRACT_INVALID", path, "WRITE_FILE requires a handle or root/path")
    if operation == "FILE_PROPERTY":
        if parameters["property"] not in {
            "basename",
            "dirname",
            "filename",
            "exists",
            "isdir",
            "isfile",
            "isOpen",
            "canRead",
            "canWrite",
        }:
            _reject(
                "DATA_CONTRACT_INVALID",
                f"{path}.property",
                "file property is not authorized",
            )
        if not (
            ("handle" in parameters)
            ^ ({"root_id", "virtual_path"} <= set(parameters))
        ):
            _reject(
                "DATA_CONTRACT_INVALID",
                path,
                "FILE_PROPERTY requires a handle or root/path",
            )
    return parameters


def _project_data_step(step: Mapping[str, Any]) -> dict[str, Any]:
    projected = {
        key: value
        for key, value in step.items()
        if key in _BASE_STEP_FIELDS and key != "type"
    }
    if "target" in step:
        target = {"expr": "variable", "name": step["target"]}
        if step["target_type"] == "str":
            projected.update(type="log", message=target, level="info")
        else:
            projected.update(type="telemetry", channel="v08.data.target", value=target)
    else:
        projected.update(type="log", message=f"Data:{step['operation']}", level="info")
    return projected


def _expression_variable_names(value: Any) -> set[str]:
    names: set[str] = set()
    if type(value) is dict:
        if value.get("expr") == "variable" and type(value.get("name")) is str:
            names.add(value["name"])
        for nested in value.values():
            names.update(_expression_variable_names(nested))
    elif type(value) is list:
        for nested in value:
            names.update(_expression_variable_names(nested))
    return names


def validate_ir_v08(
    ir_version: Any,
    steps: Any,
    *,
    start_step: Any = 0,
    resume_prompt_id: Any = None,
    resume_prompt_step: Any = None,
    checkpoint_variables: Any = None,
    expected_total_steps: Any = None,
) -> ValidatedIR:
    if ir_version != IR_VERSION:
        _reject("IR_VALIDATION_FAILED", "$.ir_version", "IR version must be exactly 0.8")
    if type(steps) is not list or not steps:
        _reject("IR_VALIDATION_FAILED", "$.steps", "steps must be a nonempty array")

    canonical_candidates: list[dict[str, Any] | None] = []
    projected: list[dict[str, Any]] = []
    has_data = False
    has_v07 = False
    argument_declarations: dict[str, str] | None = None
    for index, raw in enumerate(steps):
        path = f"$.steps[{index}]"
        if type(raw) is not dict:
            _reject("IR_VALIDATION_FAILED", path, "step must be an object")
        step = _canonical_json(raw, path, MAX_PARAMETER_BYTES)
        if step.get("index") != index:
            _reject("IR_VALIDATION_FAILED", f"{path}.index", "indexes must be contiguous")
        if index == 0:
            if "argument_declarations" not in step:
                _reject(
                    "IR_VALIDATION_FAILED",
                    f"{path}.argument_declarations",
                    "v0.8 argument declarations are required on the first step",
                )
            argument_declarations = _validate_argument_declarations(
                step.pop("argument_declarations"),
                f"{path}.argument_declarations",
            )
        elif "argument_declarations" in step:
            _reject(
                "IR_VALIDATION_FAILED",
                f"{path}.argument_declarations",
                "argument declarations may appear only on the first step",
            )
        if step.get("type") != "data_operation":
            canonical_candidates.append(None)
            projected.append(step)
            has_v07 = has_v07 or step.get("type") in {"get_tm", "verify", "wait_for"}
            continue
        required = (_BASE_STEP_FIELDS - {"guard"}) | {"operation", "parameters"}
        optional = {"guard", "target", "target_type"}
        _exact_keys(step, required, optional, path)
        operation = step.get("operation")
        if operation not in _OPERATION_FIELDS:
            _reject("IR_VALIDATION_FAILED", f"{path}.operation", "operation is not authorized")
        if "guard" in step and operation in {"OPEN_FILE", "CLOSE_FILE"}:
            _reject(
                "IR_VALIDATION_FAILED",
                f"{path}.guard",
                "FileHandle lifetime transitions must be unconditional",
            )
        target_fields = {"target", "target_type"} & set(step)
        if target_fields and target_fields != {"target", "target_type"}:
            _reject("IR_VALIDATION_FAILED", path, "target and target_type must appear together")
        if "target" in step:
            _identifier(step["target"], f"{path}.target")
            if step["target_type"] not in _TARGET_TYPES:
                _reject("IR_VALIDATION_FAILED", f"{path}.target_type", "target type is invalid")
        step["parameters"] = _validate_parameters(
            operation, step["parameters"], f"{path}.parameters"
        )
        canonical_candidates.append(step)
        projected.append(_project_data_step(step))
        has_data = True
    if not has_data:
        _reject("IR_VALIDATION_FAILED", "$.steps", "IR 0.8 requires a data operation")

    open_targets = {
        step["target"]
        for step in canonical_candidates
        if step is not None
        and step.get("operation") == "OPEN_FILE"
        and "target" in step
    }
    projected_checkpoint = checkpoint_variables
    canonical_checkpoint: dict[str, Any] | None = None
    if checkpoint_variables is not None:
        if type(checkpoint_variables) is not dict:
            _reject(
                "IR_VALIDATION_FAILED",
                "$.checkpoint_variables",
                "checkpoint variables must be an object",
            )
        canonical_checkpoint = _canonical_json(
            checkpoint_variables, "$.checkpoint_variables", MAX_PARAMETER_BYTES
        )
        projected_checkpoint = dict(canonical_checkpoint)
        for name, value in canonical_checkpoint.items():
            if is_file_handle_reference(value):
                if name not in open_targets:
                    _reject(
                        "IR_VALIDATION_FAILED",
                        f"$.checkpoint_variables.{name}",
                        "FileHandle checkpoint does not name an OPEN_FILE target",
                    )
                validate_file_handle_reference(
                    value, f"$.checkpoint_variables.{name}"
                )
                projected_checkpoint[name] = ""

    metadata: dict[str, Any] = {}
    if resume_prompt_step is not None:
        metadata["resume_prompt_step"] = resume_prompt_step
    try:
        if has_v07:
            validated = validate_ir_v07(
                "0.7",
                projected,
                start_step=start_step,
                resume_prompt_id=resume_prompt_id,
                checkpoint_variables=projected_checkpoint,
                expected_total_steps=expected_total_steps,
                **metadata,
            )
        else:
            validated = validate_ir_v06(
                "0.6",
                projected,
                start_step=start_step,
                resume_prompt_id=resume_prompt_id,
                checkpoint_variables=projected_checkpoint,
                expected_total_steps=expected_total_steps,
                **metadata,
            )
    except (V06ValidationError, V07ValidationError) as exc:
        raise V08ValidationError(exc.code, exc.path, exc.message) from exc

    opaque_variables: dict[str, str] = {}
    opaque_declared: set[str] = set()
    for index, step in enumerate(canonical_candidates):
        if step is None:
            projected_step = validated.steps[index]
            referenced = _expression_variable_names(projected_step)
            leaked = sorted(referenced & opaque_declared)
            if leaked:
                _reject(
                    "IR_VALIDATION_FAILED",
                    f"$.steps[{index}]",
                    f"FileHandle variable {leaked[0]} cannot be used as a scalar expression",
                )
            if projected_step.get("type") == "variable_set":
                name = projected_step.get("name")
                if name in opaque_declared:
                    _reject(
                        "IR_VALIDATION_FAILED",
                        f"$.steps[{index}].name",
                        "FileHandle variable cannot be assigned as a scalar",
                    )
                opaque_variables.pop(name, None)
            continue
        leaked = sorted(_expression_variable_names(step.get("guard")) & opaque_declared)
        if leaked:
            _reject(
                "IR_VALIDATION_FAILED",
                f"$.steps[{index}].guard",
                f"FileHandle variable {leaked[0]} cannot be used as a scalar expression",
            )
        if "target" in step and validated.variable_types.get(step["target"]) != step["target_type"]:
            _reject(
                "IR_VALIDATION_FAILED",
                f"$.steps[{index}].target",
                f"target must have exact declared type {step['target_type']}",
            )
        handle = step["parameters"].get("handle")
        if handle is not None:
            reference = _validate_variable_reference(
                handle, f"$.steps[{index}].parameters.handle"
            )
            name = reference["name"]
            if (
                validated.variable_types.get(name) != "str"
                or opaque_variables.get(name) != "FileHandle"
            ):
                _reject(
                    "IR_VALIDATION_FAILED",
                    f"$.steps[{index}].parameters.handle",
                    "FileHandle reference must name a prior OPEN_FILE target",
                )
        if (
            "target" in step
            and step["target"] in opaque_declared
            and step["operation"] != "OPEN_FILE"
        ):
            _reject(
                "IR_VALIDATION_FAILED",
                f"$.steps[{index}].target",
                "FileHandle variable cannot receive a scalar data result",
            )
        if step["operation"] == "OPEN_FILE" and "target" in step:
            if step["target"] in opaque_variables:
                _reject(
                    "IR_VALIDATION_FAILED",
                    f"$.steps[{index}].target",
                    "open FileHandle must be closed before the target is reused",
                )
            opaque_variables[step["target"]] = "FileHandle"
            opaque_declared.add(step["target"])
        elif "target" in step:
            opaque_variables.pop(step["target"], None)
        if step["operation"] == "CLOSE_FILE" and handle is not None:
            opaque_variables.pop(handle["name"], None)
    canonical = [
        candidate if candidate is not None else validated.steps[index]
        for index, candidate in enumerate(canonical_candidates)
    ]
    assert argument_declarations is not None
    canonical[0] = {
        **canonical[0],
        "argument_declarations": argument_declarations,
    }
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    if len(encoded) > 8_000_000:
        _reject("IR_VALIDATION_FAILED", "$.steps", "serialized IR exceeds accepted bytes")
    restored_checkpoint = (
        canonical_checkpoint
        if canonical_checkpoint is not None
        else validated.checkpoint_variables
    )
    return ValidatedIR(canonical, encoded, validated.variable_types, restored_checkpoint)


def data_request_id(execution_id: str, step_index: int) -> str:
    if type(execution_id) is not str or not execution_id or len(execution_id) > 200:
        _reject("DATA_REQUEST_INVALID", "$.execution_id", "execution identity is invalid")
    if type(step_index) is not int or step_index < 0:
        _reject("DATA_REQUEST_INVALID", "$.step_index", "step index is invalid")
    return str(uuid.uuid5(_REQUEST_NAMESPACE, f"{execution_id}:{step_index}"))


def data_operation_required_fields(operation: str) -> frozenset[str]:
    fields = _OPERATION_FIELDS.get(operation)
    if fields is None:
        _reject("DATA_CONTRACT_INVALID", "$.operation", "operation is not authorized")
    return fields[0]


def _request_with_parameters(
    execution_id: str, step: Mapping[str, Any], parameters: Mapping[str, Any]
) -> dict[str, Any]:
    operation = step["operation"]
    request = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": data_request_id(execution_id, step["index"]),
        "execution_id": execution_id,
        "step_index": step["index"],
        "operation": operation,
        "parameters": dict(parameters),
    }
    request["request_digest"] = hashlib.sha256(
        json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return request


def resolve_data_parameters(
    step: Mapping[str, Any],
    variables: Mapping[str, Any],
    *,
    execution_id: str | None = None,
    worker_generation: int | None = None,
) -> dict[str, Any]:
    """Resolve closed opaque references by exact variable lookup only."""

    if type(variables) is not dict:
        _reject("DATA_REQUEST_INVALID", "$.variables", "worker variables must be an object")
    operation = step.get("operation")
    if operation not in _OPERATION_FIELDS:
        _reject("DATA_REQUEST_INVALID", "$.step.operation", "operation is invalid")
    parameters = _validate_parameters(operation, step.get("parameters"), "$.parameters")
    handle = parameters.get("handle")
    if handle is not None:
        reference = _validate_variable_reference(handle, "$.parameters.handle")
        value = variables.get(reference["name"])
        try:
            resolved_handle = validate_file_handle_reference(
                value,
                "$.parameters.handle",
                execution_id=execution_id,
                worker_generation=worker_generation,
                require_open=True,
            )
        except V08ValidationError as exc:
            if exc.code == "STALE_HANDLE":
                raise
            _reject(
                "DATA_REQUEST_INVALID",
                "$.parameters.handle",
                "FileHandle variable is unavailable or has changed type",
            )
        parameters["handle"] = resolved_handle
    return _validate_parameters(
        operation, parameters, "$.parameters", resolved_references=True
    )


def data_request_for_step(
    execution_id: str,
    step: Mapping[str, Any],
    *,
    variables: Mapping[str, Any] | None = None,
    worker_generation: int | None = None,
) -> dict[str, Any]:
    if step.get("type") != "data_operation" or type(step.get("index")) is not int:
        _reject("DATA_REQUEST_INVALID", "$.step", "step is not a data operation")
    operation = step.get("operation")
    if operation not in _OPERATION_FIELDS:
        _reject("DATA_REQUEST_INVALID", "$.step.operation", "operation is invalid")
    symbolic = _validate_parameters(operation, step.get("parameters"), "$.parameters")
    if _is_variable_reference(symbolic.get("handle")):
        if variables is None:
            _reject(
                "DATA_REQUEST_INVALID",
                "$.variables",
                "FileHandle request requires worker variables",
            )
        parameters = resolve_data_parameters(
            step,
            variables,
            execution_id=execution_id,
            worker_generation=worker_generation,
        )
    else:
        parameters = symbolic
    return _request_with_parameters(execution_id, step, parameters)


def validate_data_request(
    step: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    execution_id: str,
    authoritative_variables: Mapping[str, Any] | None = None,
    worker_generation: int | None = None,
) -> dict[str, Any]:
    if type(payload) is not dict:
        _reject("DATA_REQUEST_INVALID", "$.request", "request must be an object")
    canonical = _canonical_json(payload, "$.request", MAX_PARAMETER_BYTES)
    if step.get("type") != "data_operation" or type(step.get("index")) is not int:
        _reject("DATA_REQUEST_INVALID", "$.step", "step is not a data operation")
    operation = step.get("operation")
    if operation not in _OPERATION_FIELDS:
        _reject("DATA_REQUEST_INVALID", "$.step.operation", "operation is invalid")
    symbolic = _validate_parameters(operation, step.get("parameters"), "$.parameters")
    actual = canonical.get("parameters")
    if type(actual) is not dict:
        _reject("DATA_REQUEST_INVALID", "$.request.parameters", "parameters must be an object")
    has_reference = _is_variable_reference(symbolic.get("handle"))
    resolved = _validate_parameters(
        operation,
        actual,
        "$.request.parameters",
        resolved_references=has_reference,
    )
    if has_reference:
        if type(authoritative_variables) is not dict:
            _reject(
                "DATA_REQUEST_INVALID",
                "$.authoritative_variables",
                "authoritative FileHandle variables are required",
            )
        reference = _validate_variable_reference(
            symbolic["handle"], "$.parameters.handle"
        )
        try:
            expected_handle = validate_file_handle_reference(
                authoritative_variables.get(reference["name"]),
                f"$.authoritative_variables.{reference['name']}",
                execution_id=execution_id,
                worker_generation=worker_generation,
                require_open=True,
            )
        except V08ValidationError as exc:
            if exc.code == "STALE_HANDLE":
                raise
            _reject(
                "DATA_REQUEST_INVALID",
                f"$.authoritative_variables.{reference['name']}",
                "authoritative FileHandle variable is unavailable",
            )
        if resolved.get("handle") != expected_handle:
            _reject(
                "DATA_REQUEST_INVALID",
                "$.request.parameters.handle",
                "FileHandle request differs from the authoritative variable",
            )
    for key, value in symbolic.items():
        if key == "handle" and has_reference:
            continue
        if resolved.get(key) != value:
            _reject(
                "DATA_REQUEST_INVALID",
                f"$.request.parameters.{key}",
                "request differs from the pinned parameter",
            )
    expected = _request_with_parameters(execution_id, step, resolved)
    if canonical != expected:
        _reject("DATA_REQUEST_INVALID", "$.request", "request does not match the pinned step")
    return canonical


def canonicalize_data_result(
    request: Mapping[str, Any], raw: Mapping[str, Any]
) -> dict[str, Any]:
    if type(raw) is not dict:
        _reject("DATA_RESULT_INVALID", "$.result", "result must be an object")
    optional = {"value", "revision", "detail"}
    _exact_keys(raw, {"outcome"}, optional, "$.result")
    outcome = raw.get("outcome")
    if outcome not in _OUTCOMES:
        _reject("DATA_RESULT_INVALID", "$.result.outcome", "outcome is invalid")
    if outcome != "OK" and "value" in raw:
        _reject(
            "DATA_RESULT_INVALID",
            "$.result.value",
            "non-success results cannot carry a value",
        )
    if outcome == "OK" and request["operation"] in (
        _HANDLE_RESULT_OPERATIONS | _VALUE_RESULT_OPERATIONS
    ) and "value" not in raw:
        _reject(
            "DATA_RESULT_INVALID",
            "$.result.value",
            "successful value or handle result omitted its value",
        )
    if (
        outcome == "OK"
        and request["operation"]
        not in (_HANDLE_RESULT_OPERATIONS | _VALUE_RESULT_OPERATIONS)
        and "value" in raw
    ):
        _reject(
            "DATA_RESULT_INVALID",
            "$.result.value",
            "effect-only result cannot carry a value",
        )
    result: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_id": request["request_id"],
        "request_digest": request["request_digest"],
        "operation": request["operation"],
        "outcome": outcome,
        "result_kind": (
            "HANDLE"
            if outcome == "OK"
            and "value" in raw
            and request["operation"] in _HANDLE_RESULT_OPERATIONS
            else "VALUE"
            if outcome == "OK" and request["operation"] in _VALUE_RESULT_OPERATIONS
            else "EFFECT"
        ),
    }
    if "value" in raw:
        result["value"] = _canonical_json(raw["value"], "$.result.value", MAX_RESULT_BYTES)
    if "revision" in raw:
        revision = raw["revision"]
        if type(revision) is int and revision >= 0:
            revision = str(revision)
        if type(revision) is not str or not revision.isascii() or not revision.isdigit():
            _reject("DATA_RESULT_INVALID", "$.result.revision", "revision must be decimal")
        result["revision"] = revision
    if "detail" in raw:
        detail = raw["detail"]
        if type(detail) is not str or not detail or len(detail) > 240 or not detail.isascii():
            _reject("DATA_RESULT_INVALID", "$.result.detail", "detail is invalid")
        result["detail"] = detail
    digest_material = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    if len(digest_material) > MAX_RESULT_BYTES:
        _reject("BOUND_EXCEEDED", "$.result", "result exceeds the byte limit")
    result["result_digest"] = hashlib.sha256(digest_material).hexdigest()
    return result


def validate_data_result(
    request: Mapping[str, Any], payload: Mapping[str, Any]
) -> dict[str, Any]:
    if type(payload) is not dict:
        _reject("DATA_RESULT_INVALID", "$.result", "result must be an object")
    raw = dict(payload)
    result_digest = raw.pop("result_digest", None)
    for key in (
        "schema_version",
        "request_id",
        "request_digest",
        "operation",
        "result_kind",
    ):
        raw.pop(key, None)
    canonical = canonicalize_data_result(request, raw)
    expected_identity = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_id": request["request_id"],
        "request_digest": request["request_digest"],
        "operation": request["operation"],
    }
    if any(payload.get(key) != value for key, value in expected_identity.items()):
        _reject("DATA_RESULT_INVALID", "$.result", "result identity does not match request")
    if result_digest != canonical["result_digest"]:
        _reject("DATA_RESULT_INVALID", "$.result.result_digest", "result digest mismatch")
    if payload != canonical:
        _reject("DATA_RESULT_INVALID", "$.result", "result payload is not canonical")
    return canonical


def persistable_data_result(
    request: Mapping[str, Any],
    payload: Mapping[str, Any],
    *,
    worker_generation: int,
) -> dict[str, Any]:
    """Replace an OPEN_FILE token with the exact digest-only durable reference."""

    canonical = validate_data_result(request, payload)
    if canonical["operation"] != "OPEN_FILE" or canonical["outcome"] != "OK":
        return canonical
    reference = file_handle_reference(
        canonical["value"],
        execution_id=request["execution_id"],
        worker_generation=worker_generation,
        creator_request_id=request["request_id"],
    )
    raw = {
        key: canonical[key]
        for key in ("outcome", "revision", "detail")
        if key in canonical
    }
    raw["value"] = reference
    return canonicalize_data_result(request, raw)


def stale_file_handle_result(
    request: Mapping[str, Any], detail: str = "FILE_HANDLE_NOT_TRANSIENT"
) -> dict[str, Any]:
    return canonicalize_data_result(
        request, {"outcome": "STALE_HANDLE", "detail": detail}
    )


def unavailable_data_result(request: Mapping[str, Any], detail: str) -> dict[str, Any]:
    return canonicalize_data_result(request, {"outcome": "INTERNAL", "detail": detail})


__all__ = [
    "DataRuntime",
    "FILE_HANDLE_REFERENCE_SCHEMA_VERSION",
    "IR_VERSION",
    "REQUEST_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "V08ValidationError",
    "canonicalize_data_result",
    "closed_file_handle_reference",
    "data_operation_required_fields",
    "data_request_for_step",
    "data_request_id",
    "file_handle_reference",
    "is_file_handle_reference",
    "persistable_data_result",
    "resolve_data_parameters",
    "unavailable_data_result",
    "stale_file_handle_result",
    "validate_data_request",
    "validate_data_result",
    "validate_file_handle_reference",
    "validate_ir_v08",
]
