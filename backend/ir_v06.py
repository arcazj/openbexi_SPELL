from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .ir_v03 import ValidatedIR, validate_ir_v03


IR_VERSION = "0.6"
MAX_CONTAINER_DEPTH = 8
MAX_CONTAINER_ITEMS = 1_024
MAX_ARGUMENT_ENTRIES = 64
MAX_ENCODED_BYTES = 1_000_000
MAX_PROMPT_OPTIONS = 1_000
MAX_STRING_CODEPOINTS = 100_000
MAX_STARTPROC_DEPTH = 8
MAX_ACTIVE_CHILDREN = 32
MAX_PROMPT_WARNING_DELAY_SECONDS = 86_400
MAX_PROMPT_RESPONSE_TIMEOUT_SECONDS = 604_800
MAX_PROMPT_NO_CONTROLLER_GRACE_SECONDS = 604_800

EXECUTION_STATES = frozenset(
    {
        "REQUESTED",
        "VALIDATING",
        "ADMISSION_PENDING",
        "LOADING",
        "PAUSED",
        "RUNNING",
        "WAITING",
        "PROMPT",
        "INTERRUPTED",
        "SUSPENDED",
        "RECOVERING",
        "STOPPING",
        "FINISHED",
        "ABORTED",
        "ERROR",
    }
)
EFFECT_CERTAINTY_VALUES = frozenset(
    {"NO_EFFECT", "EFFECT_CONFIRMED", "EFFECT_POSSIBLE", "EFFECT_UNKNOWN"}
)
SAFE_POINT_KINDS = frozenset(
    {
        "BEFORE_STATEMENT",
        "AFTER_PURE_STATEMENT",
        "WAIT_BOUNDARY",
        "PROMPT_BOUNDARY",
        "DRIVER_OPERATION_SETTLED",
        "CHILD_JOIN_SETTLED",
        "CLEANUP_BOUNDARY",
    }
)
COMMAND_ALLOWED_STATES: dict[str, frozenset[str]] = {
    "RUN": frozenset({"PAUSED", "INTERRUPTED"}),
    "STEP": frozenset({"PAUSED", "INTERRUPTED"}),
    "STEP_OVER": frozenset({"PAUSED", "INTERRUPTED"}),
    "PAUSE": frozenset({"RUNNING", "WAITING", "PROMPT"}),
    "SKIP": frozenset({"PAUSED", "INTERRUPTED"}),
    "GOTO": frozenset({"PAUSED"}),
    "RELOAD": frozenset({"FINISHED", "ABORTED", "ERROR"}),
    "BACKGROUND": frozenset({"PAUSED", "RUNNING", "WAITING", "INTERRUPTED"}),
    "STOP": frozenset(EXECUTION_STATES - {"STOPPING", "FINISHED", "ABORTED", "ERROR"}),
    "ABORT": frozenset(EXECUTION_STATES - {"STOPPING", "FINISHED", "ABORTED", "ERROR"}),
    "RECOVER": frozenset({"ERROR"}),
    "KILL": frozenset(),
}
COMMAND_SAFE_POINT_POLICY = {
    "RUN": "REQUIRED",
    "STEP": "REQUIRED",
    "STEP_OVER": "REQUIRED",
    "PAUSE": "REQUIRED",
    "SKIP": "REQUIRED",
    "GOTO": "REQUIRED",
    "RELOAD": "NOT_REQUIRED",
    "BACKGROUND": "REQUIRED",
    "STOP": "REQUIRED_AFTER_ACCEPTANCE",
    "ABORT": "REQUIRED_AFTER_ACCEPTANCE",
    "RECOVER": "NOT_REQUIRED",
    "KILL": "NOT_APPLICABLE",
}
PROMPT_FIXED_CHOICES: dict[str, tuple[str, ...]] = {
    "OK": ("OK",),
    "CANCEL": ("CANCEL",),
    "OK_CANCEL": ("OK", "CANCEL"),
    "YES": ("YES",),
    "NO": ("NO",),
    "YES_NO": ("YES", "NO"),
}
PROMPT_TYPES = frozenset({*PROMPT_FIXED_CHOICES, "ALPHA", "NUM", "DATE", "LIST"})
LIST_MODES = frozenset({"KEY", "INDEX", "VALUE"})
V06_STEP_TARGET_FIELDS = frozenset(
    {
        "lexical_frame_id",
        "lexical_frame_path",
        "reachability_id",
        "step_over_target",
        "call_boundary_id",
        "labels",
    }
)
USER_ACTION_STATES = frozenset({"PAUSED", "RUNNING", "WAITING", "PROMPT", "INTERRUPTED"})
USER_ACTION_SEVERITIES = frozenset({"INFO", "WARNING", "ERROR"})
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SECRET_FIELD_NAMES = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "bearertoken",
        "clientsecret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "token",
    }
)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
    re.compile(
        r"\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.IGNORECASE),
    re.compile(
        r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|github_pat_[A-Za-z0-9_]{20,}|"
        r"gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,})\b"
    ),
)


class V06ValidationError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def audit_payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class SafePoint:
    kind: str
    step_index: int
    line: int
    source_digest: str
    execution_revision: int
    effect_certainty: str = "NO_EFFECT"

    @property
    def id(self) -> str:
        return _canonical_digest(
            {
                "kind": self.kind,
                "step_index": self.step_index,
                "line": self.line,
                "source_digest": self.source_digest,
                "execution_revision": self.execution_revision,
                "effect_certainty": self.effect_certainty,
            }
        )


@dataclass(frozen=True)
class CommandApplication:
    command: str
    safe_point_policy: str
    target_step: int | None = None
    run_budget: int | None = None
    resulting_mode: str | None = None


@dataclass(frozen=True)
class PromptSpec:
    prompt_type: str
    question: str
    choices: tuple[Any, ...]
    default: Any
    list_mode: str | None
    warning_delay_seconds: float | None
    response_timeout_seconds: float | None
    no_controller_grace_seconds: float | None

    def as_ir_fields(self) -> dict[str, Any]:
        return {
            "prompt_type": self.prompt_type,
            "question": self.question,
            "choices": list(self.choices),
            "default": self.default,
            "list_mode": self.list_mode,
            "warning_delay_seconds": self.warning_delay_seconds,
            "response_timeout_seconds": self.response_timeout_seconds,
            "no_controller_grace_seconds": self.no_controller_grace_seconds,
        }


@dataclass(frozen=True)
class StartProcSpec:
    child_reference: str
    arguments: dict[str, Any]
    arguments_digest: str
    blocking: bool
    visible: bool
    automatic: bool

    def as_ir_fields(self) -> dict[str, Any]:
        return {
            "child_reference": self.child_reference,
            "arguments": self.arguments,
            "arguments_digest": self.arguments_digest,
            "blocking": self.blocking,
            "visible": self.visible,
            "automatic": self.automatic,
        }


@dataclass(frozen=True)
class ResolvedProcedure:
    procedure_catalog_id: str
    qualified_name: str
    library_revision: str
    bundle_digest: str
    priority: int


@dataclass(frozen=True)
class UserActionSpec:
    action_id: str
    action_revision: int
    name: str
    label: str
    severity: str
    handler_id: str
    enabled: bool
    source_digest: str


@dataclass(frozen=True)
class UserActionOperation:
    operation: str
    payload: dict[str, Any]


def validate_safe_point(value: Mapping[str, Any] | SafePoint) -> SafePoint:
    if isinstance(value, SafePoint):
        point = value
    elif isinstance(value, Mapping):
        try:
            point = SafePoint(
                kind=value["kind"],
                step_index=value["step_index"],
                line=value["line"],
                source_digest=value["source_digest"],
                execution_revision=value["execution_revision"],
                effect_certainty=value.get("effect_certainty", "NO_EFFECT"),
            )
        except KeyError as exc:
            raise V06ValidationError("SAFE_POINT_INVALID", "$", f"missing {exc.args[0]}") from exc
    else:
        raise V06ValidationError("SAFE_POINT_INVALID", "$", "safe point must be an object")
    if point.kind not in SAFE_POINT_KINDS:
        _reject("SAFE_POINT_INVALID", "$.kind", "safe point kind is not allowlisted")
    if type(point.step_index) is not int or point.step_index < 0:
        _reject("SAFE_POINT_INVALID", "$.step_index", "step index must be nonnegative")
    if type(point.line) is not int or point.line < 1:
        _reject("SAFE_POINT_INVALID", "$.line", "line must be positive")
    _digest(point.source_digest, "$.source_digest")
    if type(point.execution_revision) is not int or point.execution_revision < 0:
        _reject("SAFE_POINT_INVALID", "$.execution_revision", "revision must be nonnegative")
    if point.effect_certainty not in EFFECT_CERTAINTY_VALUES:
        _reject("SAFE_POINT_INVALID", "$.effect_certainty", "effect certainty is invalid")
    return point


def validate_operator_command(
    command: str,
    execution_state: str,
    *,
    current_step: int | None = None,
    total_steps: int | None = None,
    target_step: int | None = None,
    effect_certainty: str = "NO_EFFECT",
    background_allowed: bool = False,
    prompt_open: bool = False,
    interactive_decision_pending: bool = False,
) -> CommandApplication:
    if type(command) is not str:
        _reject("COMMAND_UNSUPPORTED", "$.command", "command must be a string")
    command = command.upper()
    if command == "KILL":
        _reject("KILL_UNSUPPORTED", "$.command", "hard kill is not a product command")
    if command not in COMMAND_ALLOWED_STATES:
        _reject("COMMAND_UNSUPPORTED", "$.command", "command is not allowlisted")
    if execution_state not in EXECUTION_STATES:
        _reject("EXECUTION_STATE_INVALID", "$.execution_state", "state is not canonical")
    if execution_state not in COMMAND_ALLOWED_STATES[command]:
        _reject(
            "COMMAND_NOT_ALLOWED_IN_STATE",
            "$.execution_state",
            f"{command} is not allowed in {execution_state}",
        )
    if effect_certainty not in EFFECT_CERTAINTY_VALUES:
        _reject("EFFECT_CERTAINTY_INVALID", "$.effect_certainty", "certainty is invalid")
    if effect_certainty in {"EFFECT_POSSIBLE", "EFFECT_UNKNOWN"}:
        _reject(
            "UNRESOLVED_EXTERNAL_EFFECT",
            "$.effect_certainty",
            "command cannot cross unresolved external effect evidence",
        )
    if command == "BACKGROUND":
        if not background_allowed:
            _reject("BACKGROUND_NOT_ALLOWED", "$.background_allowed", "bundle forbids background")
        if prompt_open or interactive_decision_pending:
            _reject(
                "BACKGROUND_INTERACTIVE_DECISION_PENDING",
                "$.prompt_open",
                "background mode cannot retain an interactive decision",
            )
        return CommandApplication(command, COMMAND_SAFE_POINT_POLICY[command], resulting_mode="B")
    if command in {"SKIP", "GOTO"}:
        if type(current_step) is not int or type(total_steps) is not int:
            _reject("COMMAND_TARGET_INVALID", "$.current_step", "current and total steps are required")
        if current_step < 0 or total_steps < 1 or current_step >= total_steps:
            _reject("COMMAND_TARGET_INVALID", "$.current_step", "current step is outside the IR")
        if command == "SKIP":
            target_step = current_step + 1
        if type(target_step) is not int or target_step < 0 or target_step >= total_steps:
            _reject("COMMAND_TARGET_INVALID", "$.target_step", "target is not an executable step")
        return CommandApplication(command, COMMAND_SAFE_POINT_POLICY[command], target_step=target_step)
    if command in {"STEP", "STEP_OVER"}:
        return CommandApplication(command, COMMAND_SAFE_POINT_POLICY[command], run_budget=1)
    return CommandApplication(command, COMMAND_SAFE_POINT_POLICY[command])


def validate_prompt_declaration(
    question: Any,
    *,
    prompt_type: Any = "OK",
    choices: Any = None,
    default: Any = None,
    list_mode: Any = None,
    warning_delay_seconds: Any = None,
    response_timeout_seconds: Any = None,
    no_controller_grace_seconds: Any = None,
) -> PromptSpec:
    reject_secret_material(question, "$.question")
    reject_secret_material(choices, "$.choices")
    reject_secret_material(default, "$.default")
    question = _text(question, "$.question", nonempty=True)
    if type(prompt_type) is not str or prompt_type.upper() not in PROMPT_TYPES:
        _reject("PROMPT_TYPE_INVALID", "$.prompt_type", "prompt type is not allowlisted")
    prompt_type = prompt_type.upper()
    canonical_choices: tuple[Any, ...]
    canonical_mode: str | None = None
    if prompt_type in PROMPT_FIXED_CHOICES:
        canonical_choices = PROMPT_FIXED_CHOICES[prompt_type]
        if choices is not None and tuple(choices) != canonical_choices:
            _reject("PROMPT_OPTIONS_INVALID", "$.choices", "fixed choices cannot be changed")
        if list_mode is not None:
            _reject("PROMPT_OPTIONS_INVALID", "$.list_mode", "list mode requires LIST")
    elif prompt_type == "LIST":
        if type(list_mode) is not str or list_mode.upper() not in LIST_MODES:
            _reject("PROMPT_OPTIONS_INVALID", "$.list_mode", "LIST requires KEY, INDEX, or VALUE")
        canonical_mode = list_mode.upper()
        canonical_choices = _normalize_list_choices(choices, canonical_mode)
    else:
        if choices not in (None, (), []):
            _reject("PROMPT_OPTIONS_INVALID", "$.choices", f"{prompt_type} does not accept choices")
        if list_mode is not None:
            _reject("PROMPT_OPTIONS_INVALID", "$.list_mode", "list mode requires LIST")
        canonical_choices = ()
    canonical_default = None
    if default is not None:
        canonical_default = normalize_prompt_value(
            prompt_type, default, choices=canonical_choices, list_mode=canonical_mode
        )
    warning = _optional_duration(
        warning_delay_seconds,
        "$.warning_delay_seconds",
        maximum=MAX_PROMPT_WARNING_DELAY_SECONDS,
    )
    timeout = _optional_duration(
        response_timeout_seconds,
        "$.response_timeout_seconds",
        zero_is_none=True,
        maximum=MAX_PROMPT_RESPONSE_TIMEOUT_SECONDS,
    )
    grace = _optional_duration(
        no_controller_grace_seconds,
        "$.no_controller_grace_seconds",
        maximum=MAX_PROMPT_NO_CONTROLLER_GRACE_SECONDS,
    )
    return PromptSpec(
        prompt_type,
        question,
        canonical_choices,
        canonical_default,
        canonical_mode,
        warning,
        timeout,
        grace,
    )


def normalize_prompt_value(
    prompt_type: str,
    value: Any,
    *,
    choices: Sequence[Any] = (),
    list_mode: str | None = None,
) -> Any:
    reject_secret_material(value, "$.value")
    if prompt_type in PROMPT_FIXED_CHOICES:
        if type(value) is not str or value not in PROMPT_FIXED_CHOICES[prompt_type]:
            _reject("PROMPT_VALUE_INVALID", "$.value", "value is not an exact fixed token")
        return value
    if prompt_type == "ALPHA":
        value = _text(value, "$.value", nonempty=True)
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            _reject("PROMPT_VALUE_INVALID", "$.value", "text contains a control character")
        return value
    if prompt_type == "NUM":
        if type(value) not in {str, int, float} or type(value) is bool:
            _reject("PROMPT_VALUE_INVALID", "$.value", "number must be base-10 data")
        if type(value) is float and not math.isfinite(value):
            _reject("PROMPT_VALUE_INVALID", "$.value", "number must be finite")
        try:
            decimal = Decimal(str(value))
        except InvalidOperation as exc:
            raise V06ValidationError("PROMPT_VALUE_INVALID", "$.value", "number is invalid") from exc
        if not decimal.is_finite():
            _reject("PROMPT_VALUE_INVALID", "$.value", "number must be finite")
        return format(decimal, "f")
    if prompt_type == "DATE":
        if type(value) is not str:
            _reject("PROMPT_VALUE_INVALID", "$.value", "date must use YYYY-MM-DD")
        try:
            canonical = date.fromisoformat(value).isoformat()
        except ValueError as exc:
            raise V06ValidationError("PROMPT_VALUE_INVALID", "$.value", "date is invalid") from exc
        if canonical != value:
            _reject("PROMPT_VALUE_INVALID", "$.value", "date must use YYYY-MM-DD")
        return canonical
    if prompt_type != "LIST" or list_mode not in LIST_MODES:
        _reject("PROMPT_TYPE_INVALID", "$.prompt_type", "prompt type is not allowlisted")
    if list_mode == "INDEX":
        if type(value) is not int or value < 0 or value >= len(choices):
            _reject("PROMPT_VALUE_INVALID", "$.value", "list index is outside the options")
        return value
    field = "key" if list_mode == "KEY" else "value"
    matches = [option[field] for option in choices if _canonical_equal(option[field], value)]
    if len(matches) != 1:
        _reject("PROMPT_VALUE_INVALID", "$.value", "value does not select exactly one option")
    return matches[0]


def reject_secret_material(value: Any, path: str = "$") -> None:
    """Reject recognizable plaintext credentials without reflecting their value."""

    def visit(item: Any, item_path: str, depth: int) -> None:
        if depth > MAX_CONTAINER_DEPTH:
            return
        if type(item) is str:
            if any(pattern.search(item) is not None for pattern in _SECRET_PATTERNS):
                _reject(
                    "PROMPT_SECRET_MATERIAL_REJECTED",
                    item_path,
                    "plaintext secret material is not accepted",
                )
            return
        if type(item) is list or type(item) is tuple:
            for index, child in enumerate(item):
                visit(child, f"{item_path}[{index}]", depth + 1)
            return
        if type(item) is dict:
            for key, child in item.items():
                normalized_key = (
                    re.sub(r"[^a-z0-9]", "", key.lower())
                    if type(key) is str
                    else ""
                )
                if (
                    normalized_key in _SECRET_FIELD_NAMES
                    and child is not None
                    and child != ""
                ):
                    _reject(
                        "PROMPT_SECRET_MATERIAL_REJECTED",
                        item_path,
                        "plaintext secret material is not accepted",
                    )
                visit(child, f"{item_path}.*", depth + 1)

    visit(value, path, 0)


def validate_user_action(
    *,
    action_id: Any,
    action_revision: Any,
    name: Any,
    label: Any,
    severity: Any,
    handler_id: Any,
    enabled: Any,
    source_digest: Any,
    allowlisted_handlers: Iterable[str],
) -> UserActionSpec:
    action_id = _identifier(action_id, "$.action_id")
    if type(action_revision) is not int or action_revision < 1:
        _reject("USER_ACTION_INVALID", "$.action_revision", "revision must be positive")
    name = _identifier(name, "$.name")
    label = _text(label, "$.label", nonempty=True, maximum=200)
    if type(severity) is not str or severity.upper() not in USER_ACTION_SEVERITIES:
        _reject("USER_ACTION_INVALID", "$.severity", "severity is not allowlisted")
    handler_id = _identifier(handler_id, "$.handler_id")
    if handler_id not in frozenset(allowlisted_handlers):
        _reject("USER_ACTION_HANDLER_NOT_ALLOWLISTED", "$.handler_id", "handler is not pinned")
    if type(enabled) is not bool:
        _reject("USER_ACTION_INVALID", "$.enabled", "enabled must be Boolean")
    source_digest = _digest(source_digest, "$.source_digest")
    return UserActionSpec(
        action_id, action_revision, name, label, severity.upper(), handler_id, enabled, source_digest
    )


def validate_user_action_invocation(
    action: UserActionSpec,
    *,
    execution_state: str,
    source_digest: str,
) -> None:
    if execution_state not in USER_ACTION_STATES:
        _reject("USER_ACTION_NOT_ALLOWED_IN_STATE", "$.execution_state", "action is not allowed")
    if not action.enabled:
        _reject("USER_ACTION_DISABLED", "$.action_id", "action is disabled")
    if action.source_digest != source_digest:
        _reject("USER_ACTION_STALE", "$.source_digest", "source digest no longer matches")


def validate_user_action_block(value: Any) -> tuple[UserActionOperation, ...]:
    """Validate the only executable payload accepted for a v0.6 user action.

    The block is already compiled data. It cannot name modules, callables, source,
    files, processes, or networks. A literal assignment can only update an
    existing worker variable of the exact declared checkpoint type.
    """

    if type(value) is not list or not value or len(value) > 32:
        _reject("USER_ACTION_BLOCK_INVALID", "$.handler", "handler block must be bounded")
    result: list[UserActionOperation] = []
    for index, raw in enumerate(value):
        path = f"$.handler[{index}]"
        if type(raw) is not dict or type(raw.get("op")) is not str:
            _reject("USER_ACTION_BLOCK_INVALID", path, "operation must be an object")
        operation = raw["op"].upper()
        if operation == "LOG":
            if set(raw) - {"op", "message", "severity"}:
                _reject("USER_ACTION_BLOCK_INVALID", path, "LOG contains unknown fields")
            payload = {
                "message": _text(raw.get("message"), f"{path}.message", nonempty=True, maximum=2_000),
                "severity": raw.get("severity", "info"),
            }
            if payload["severity"] not in {"debug", "info", "warning", "error"}:
                _reject("USER_ACTION_BLOCK_INVALID", f"{path}.severity", "severity is invalid")
            reject_secret_material(payload["message"], f"{path}.message")
        elif operation == "SET_LITERAL":
            if set(raw) != {"op", "name", "declared_type", "value"}:
                _reject("USER_ACTION_BLOCK_INVALID", path, "SET_LITERAL fields are invalid")
            declared_type = raw["declared_type"]
            if declared_type not in {"bool", "float", "int", "str"}:
                _reject("USER_ACTION_BLOCK_INVALID", f"{path}.declared_type", "type is invalid")
            literal = _bounded_literal(raw["value"], f"{path}.value", 0)
            actual = type(literal).__name__
            if actual != declared_type and not (declared_type == "float" and actual == "int"):
                _reject("USER_ACTION_BLOCK_INVALID", f"{path}.value", "literal type does not match")
            payload = {
                "name": _identifier(raw["name"], f"{path}.name"),
                "declared_type": declared_type,
                "value": float(literal) if declared_type == "float" and actual == "int" else literal,
            }
            reject_secret_material(
                {payload["name"]: payload["value"]}, path
            )
        else:
            _reject("USER_ACTION_BLOCK_INVALID", f"{path}.op", "operation is not allowlisted")
        result.append(UserActionOperation(operation, payload))
    return tuple(result)


def validate_startproc_declaration(
    child_reference: Any,
    *,
    arguments: Any = None,
    blocking: Any = True,
    visible: Any = True,
    automatic: Any = True,
) -> StartProcSpec:
    reference = _procedure_reference(child_reference)
    if arguments is None:
        arguments = {}
    if type(arguments) is not dict or len(arguments) > MAX_ARGUMENT_ENTRIES:
        _reject("INVALID_ARGUMENTS", "$.arguments", "arguments must be a bounded map")
    canonical: dict[str, Any] = {}
    for key, value in arguments.items():
        key = _text(key, "$.arguments.<key>", nonempty=True, maximum=128)
        if key in canonical:
            _reject("INVALID_ARGUMENTS", "$.arguments", "argument keys must be unique")
        canonical[key] = _bounded_literal(value, f"$.arguments.{key}", 0)
    reject_secret_material(canonical, "$.arguments")
    for path, flag in {
        "$.blocking": blocking,
        "$.visible": visible,
        "$.automatic": automatic,
    }.items():
        if type(flag) is not bool:
            _reject("STARTPROC_MODE_INVALID", path, "mode flag must be Boolean")
    return StartProcSpec(
        reference,
        canonical,
        _canonical_digest(canonical),
        blocking,
        visible,
        automatic,
    )


def resolve_procedure_reference(
    reference: str,
    candidates: Iterable[Mapping[str, Any]],
    *,
    library_revision: str,
) -> ResolvedProcedure:
    reference = _procedure_reference(reference)
    qualified = "/" in reference
    matches: list[ResolvedProcedure] = []
    for index, item in enumerate(candidates):
        path = f"$.candidates[{index}]"
        qualified_name = _procedure_reference(item.get("qualified_name"))
        if qualified:
            selected = qualified_name == reference
        else:
            selected = PurePosixPath(qualified_name).name == reference
        if not selected:
            continue
        catalog_id = _identifier(item.get("procedure_catalog_id"), f"{path}.procedure_catalog_id")
        digest = _digest(item.get("bundle_digest"), f"{path}.bundle_digest")
        priority = item.get("priority", 0)
        if type(priority) is not int:
            _reject("IMMUTABLE_BUNDLE_REQUIRED", f"{path}.priority", "priority must be integer")
        matches.append(
            ResolvedProcedure(catalog_id, qualified_name, library_revision, digest, priority)
        )
    if not matches:
        _reject("PROCEDURE_NOT_FOUND", "$.child_reference", "procedure did not resolve")
    highest = max(item.priority for item in matches)
    winners = [item for item in matches if item.priority == highest]
    if len(winners) != 1:
        _reject(
            "AMBIGUOUS_PROCEDURE_REFERENCE",
            "$.child_reference",
            "highest-priority procedure reference is not unique",
        )
    return winners[0]


def validate_startproc_graph(
    child: ResolvedProcedure,
    *,
    parent_depth: int,
    ancestor_identities: Sequence[tuple[str, str]],
    active_children: int,
) -> int:
    if type(parent_depth) is not int or parent_depth < 0:
        _reject("STARTPROC_DEPTH_EXCEEDED", "$.parent_depth", "parent depth is invalid")
    depth = parent_depth + 1
    if depth > MAX_STARTPROC_DEPTH:
        _reject("STARTPROC_DEPTH_EXCEEDED", "$.parent_depth", "maximum depth exceeded")
    if type(active_children) is not int or active_children < 0 or active_children >= MAX_ACTIVE_CHILDREN:
        _reject(
            "STARTPROC_CHILD_CAPACITY_EXCEEDED",
            "$.active_children",
            "active child capacity exceeded",
        )
    identity = (child.procedure_catalog_id, child.bundle_digest)
    if identity in ancestor_identities:
        code = "STARTPROC_DIRECT_CYCLE" if ancestor_identities and ancestor_identities[-1] == identity else "STARTPROC_INDIRECT_CYCLE"
        _reject(code, "$.child_reference", "resolved child is already in the ancestor chain")
    return depth


def _validate_step_target_metadata(
    step: dict[str, Any],
    index: int,
    total_steps: int,
    *,
    seen_reachability: set[str],
    seen_labels: set[tuple[str, str]],
) -> None:
    present = set(step) & V06_STEP_TARGET_FIELDS
    if not present:
        return
    if present != V06_STEP_TARGET_FIELDS:
        _reject(
            "IR_VALIDATION_FAILED",
            f"$.steps[{index}]",
            "v0.6 target metadata must be complete",
        )
    frame_id = _text(
        step.get("lexical_frame_id"),
        f"$.steps[{index}].lexical_frame_id",
        nonempty=True,
        maximum=256,
    )
    frame_path = step.get("lexical_frame_path")
    if (
        type(frame_path) is not list
        or not frame_path
        or len(frame_path) > 17
    ):
        _reject(
            "IR_VALIDATION_FAILED",
            f"$.steps[{index}].lexical_frame_path",
            "lexical frame path is invalid",
        )
    canonical_path = [
        _text(
            item,
            f"$.steps[{index}].lexical_frame_path[{path_index}]",
            nonempty=True,
            maximum=256,
        )
        for path_index, item in enumerate(frame_path)
    ]
    if canonical_path[0] != "root" or canonical_path[-1] != frame_id:
        _reject(
            "IR_VALIDATION_FAILED",
            f"$.steps[{index}].lexical_frame_path",
            "lexical frame path does not bind the current frame",
        )
    reachability = _text(
        step.get("reachability_id"),
        f"$.steps[{index}].reachability_id",
        nonempty=True,
        maximum=512,
    )
    if reachability in seen_reachability:
        _reject(
            "IR_VALIDATION_FAILED",
            f"$.steps[{index}].reachability_id",
            "reachability identity is duplicated",
        )
    seen_reachability.add(reachability)
    step_over_target = step.get("step_over_target")
    if (
        type(step_over_target) is not int
        or step_over_target <= index
        or step_over_target > total_steps
    ):
        _reject(
            "IR_VALIDATION_FAILED",
            f"$.steps[{index}].step_over_target",
            "step-over target is invalid",
        )
    boundary = step.get("call_boundary_id")
    if boundary is not None:
        boundary = _text(
            boundary,
            f"$.steps[{index}].call_boundary_id",
            nonempty=True,
            maximum=256,
        )
        if boundary not in canonical_path:
            _reject(
                "IR_VALIDATION_FAILED",
                f"$.steps[{index}].call_boundary_id",
                "call boundary is outside the lexical path",
            )
    labels = step.get("labels")
    if type(labels) is not list or len(labels) > MAX_CONTAINER_ITEMS:
        _reject(
            "IR_VALIDATION_FAILED",
            f"$.steps[{index}].labels",
            "label metadata is invalid",
        )
    canonical_labels: list[dict[str, str]] = []
    for label_index, raw_label in enumerate(labels):
        path = f"$.steps[{index}].labels[{label_index}]"
        if type(raw_label) is not dict or set(raw_label) != {"name", "frame_id"}:
            _reject("IR_VALIDATION_FAILED", path, "label metadata is invalid")
        name = _identifier(raw_label.get("name"), f"{path}.name")
        owner = _text(
            raw_label.get("frame_id"),
            f"{path}.frame_id",
            nonempty=True,
            maximum=256,
        )
        if owner not in canonical_path:
            _reject("IR_VALIDATION_FAILED", path, "label owner is outside the lexical path")
        identity = (owner, name)
        if identity in seen_labels:
            _reject("IR_VALIDATION_FAILED", path, "label is duplicated in its frame")
        seen_labels.add(identity)
        canonical_labels.append({"name": name, "frame_id": owner})
    step.update(
        lexical_frame_id=frame_id,
        lexical_frame_path=canonical_path,
        reachability_id=reachability,
        step_over_target=step_over_target,
        call_boundary_id=boundary,
        labels=canonical_labels,
    )


def validate_ir_v06(
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
        _reject("IR_VALIDATION_FAILED", "$.ir_version", "IR version must be exactly 0.6")
    if type(steps) is not list or not steps:
        _reject("IR_VALIDATION_FAILED", "$.steps", "steps must be a nonempty array")
    projected: list[dict[str, Any]] = []
    canonical: list[dict[str, Any]] = []
    seen_reachability: set[str] = set()
    seen_labels: set[tuple[str, str]] = set()
    for index, raw in enumerate(steps):
        if type(raw) is not dict:
            _reject("IR_VALIDATION_FAILED", f"$.steps[{index}]", "step must be an object")
        step = _json_detach(raw, f"$.steps[{index}]")
        if step.get("index") != index:
            _reject("IR_VALIDATION_FAILED", f"$.steps[{index}].index", "indexes must be contiguous")
        _validate_step_target_metadata(
            step,
            index,
            len(steps),
            seen_reachability=seen_reachability,
            seen_labels=seen_labels,
        )
        step_type = step.get("type")
        if step_type == "prompt" and "prompt_type" in step:
            question = step.get("question")
            validation_question = "dynamic question" if type(question) is dict else question
            spec = validate_prompt_declaration(
                validation_question,
                prompt_type=step.get("prompt_type"),
                choices=step.get("choices"),
                default=step.get("default"),
                list_mode=step.get("list_mode"),
                warning_delay_seconds=step.get("warning_delay_seconds"),
                response_timeout_seconds=step.get("response_timeout_seconds"),
                no_controller_grace_seconds=step.get("no_controller_grace_seconds"),
            )
            allowed = {
                "index",
                "type",
                "line",
                "column",
                "guard",
                *spec.as_ir_fields(),
                *V06_STEP_TARGET_FIELDS,
            }
            _exact_keys(step, allowed, f"$.steps[{index}]")
            step.update(spec.as_ir_fields())
            step["question"] = question
            projection = _project_effect_step(step, "prompt")
            projection.update(question=question, choices=["continue"], default=None)
        elif step_type == "startproc":
            spec = validate_startproc_declaration(
                step.get("child_reference"),
                arguments=step.get("arguments"),
                blocking=step.get("blocking"),
                visible=step.get("visible"),
                automatic=step.get("automatic"),
            )
            allowed = {
                "index",
                "type",
                "line",
                "column",
                "guard",
                *spec.as_ir_fields(),
                *V06_STEP_TARGET_FIELDS,
            }
            _exact_keys(step, allowed, f"$.steps[{index}]")
            if step.get("arguments_digest") != spec.arguments_digest:
                _reject("INVALID_ARGUMENTS", f"$.steps[{index}].arguments_digest", "digest mismatch")
            step.update(spec.as_ir_fields())
            projection = _project_effect_step(step, "log")
            projection.update(message=f"StartProc:{spec.child_reference}", level="info")
        else:
            projection = {
                key: value
                for key, value in step.items()
                if key not in V06_STEP_TARGET_FIELDS
            }
        canonical.append(step)
        projected.append(projection)
    metadata: dict[str, Any] = {}
    if resume_prompt_step is not None:
        metadata["resume_prompt_step"] = resume_prompt_step
    validated = validate_ir_v03(
        "0.3",
        projected,
        start_step=start_step,
        resume_prompt_id=resume_prompt_id,
        checkpoint_variables=checkpoint_variables,
        expected_total_steps=expected_total_steps,
        **metadata,
    )
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > 8_000_000:
        _reject("IR_VALIDATION_FAILED", "$.steps", "serialized IR exceeds accepted bytes")
    return ValidatedIR(canonical, encoded, validated.variable_types, validated.checkpoint_variables)


def _project_effect_step(step: dict[str, Any], step_type: str) -> dict[str, Any]:
    projected = {
        "index": step["index"],
        "type": step_type,
        "line": step["line"],
        "column": step["column"],
    }
    if "guard" in step:
        projected["guard"] = step["guard"]
    return projected


def _normalize_list_choices(value: Any, mode: str) -> tuple[Any, ...]:
    if type(value) not in {list, tuple} or not value or len(value) > MAX_PROMPT_OPTIONS:
        _reject("PROMPT_OPTIONS_INVALID", "$.choices", "LIST choices must be nonempty and bounded")
    canonical: list[Any] = []
    seen: set[bytes] = set()
    for index, option in enumerate(value):
        path = f"$.choices[{index}]"
        if mode == "INDEX":
            item: Any = _text(option, path, nonempty=True, maximum=500)
            identity = _canonical_bytes(item)
        else:
            if type(option) is not dict or set(option) != {"key" if mode == "KEY" else "value", "label"}:
                _reject("PROMPT_OPTIONS_INVALID", path, "option shape does not match list mode")
            field = "key" if mode == "KEY" else "value"
            selected = (
                _text(option[field], f"{path}.{field}", nonempty=True, maximum=200)
                if mode == "KEY"
                else _bounded_literal(option[field], f"{path}.{field}", 0)
            )
            item = {field: selected, "label": _text(option["label"], f"{path}.label", nonempty=True, maximum=500)}
            identity = _canonical_bytes(selected)
        if identity in seen:
            _reject("PROMPT_OPTIONS_INVALID", path, "option identities must be unique")
        seen.add(identity)
        canonical.append(item)
    return tuple(canonical)


def _bounded_literal(value: Any, path: str, depth: int) -> Any:
    if depth > MAX_CONTAINER_DEPTH:
        _reject("INVALID_ARGUMENTS", path, "container depth exceeds the limit")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if len(str(abs(value))) > 1_000:
            _reject("INVALID_ARGUMENTS", path, "integer digit limit exceeded")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _reject("INVALID_ARGUMENTS", path, "decimal must be finite")
        return value
    if type(value) is str:
        return _text(value, path)
    if type(value) is list:
        if len(value) > MAX_CONTAINER_ITEMS:
            _reject("INVALID_ARGUMENTS", path, "container item limit exceeded")
        return [_bounded_literal(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)]
    if type(value) is dict:
        if len(value) > MAX_CONTAINER_ITEMS:
            _reject("INVALID_ARGUMENTS", path, "container item limit exceeded")
        result: dict[str, Any] = {}
        for key, item in value.items():
            key = _text(key, f"{path}.<key>", nonempty=True, maximum=200)
            if key in result:
                _reject("INVALID_ARGUMENTS", path, "duplicate map key")
            result[key] = _bounded_literal(item, f"{path}.{key}", depth + 1)
        return result
    _reject("INVALID_ARGUMENTS", path, "value is not a bounded typed literal")


def _procedure_reference(value: Any) -> str:
    value = _text(value, "$.child_reference", nonempty=True, maximum=300)
    if "\\" in value or ":" in value or value.startswith("/"):
        _reject("IMMUTABLE_BUNDLE_REQUIRED", "$.child_reference", "reference must use the virtual root")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        _reject("IMMUTABLE_BUNDLE_REQUIRED", "$.child_reference", "traversal is forbidden")
    return str(path)


def _identifier(value: Any, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject("IDENTIFIER_INVALID", path, "identifier is invalid")
    return value


def _digest(value: Any, path: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _reject("DIGEST_INVALID", path, "SHA-256 digest is invalid")
    return value


def _text(value: Any, path: str, *, nonempty: bool = False, maximum: int = MAX_STRING_CODEPOINTS) -> str:
    if type(value) is not str or (nonempty and not value) or len(value) > maximum:
        _reject("TEXT_INVALID", path, "text is invalid or outside bounds")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise V06ValidationError("TEXT_INVALID", path, "text is not valid UTF-8") from exc
    if len(encoded) > MAX_ENCODED_BYTES or "\x00" in value:
        _reject("TEXT_INVALID", path, "text is outside persistence bounds")
    return value


def _optional_duration(
    value: Any,
    path: str,
    *,
    zero_is_none: bool = False,
    maximum: float,
) -> float | None:
    if value is None:
        return None
    if type(value) not in {int, float} or type(value) is bool or not math.isfinite(value) or value < 0:
        _reject("PROMPT_SETTING_INVALID", path, "duration must be finite and nonnegative")
    if value > maximum:
        _reject("PROMPT_SETTING_INVALID", path, "duration exceeds the allowed maximum")
    if zero_is_none and value == 0:
        return None
    return float(value)


def _exact_keys(value: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unexpected = set(value) - allowed
    if unexpected:
        _reject("IR_VALIDATION_FAILED", path, f"unexpected fields: {sorted(unexpected)}")


def _json_detach(value: Any, path: str) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        return json.loads(encoded)
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise V06ValidationError("IR_VALIDATION_FAILED", path, "value is not canonical JSON data") from exc


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_equal(left: Any, right: Any) -> bool:
    try:
        return _canonical_bytes(left) == _canonical_bytes(right)
    except (TypeError, ValueError):
        return False


def _reject(code: str, path: str, message: str) -> None:
    raise V06ValidationError(code, path, message)
