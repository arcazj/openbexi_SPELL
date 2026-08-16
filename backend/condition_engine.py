"""Bounded, declarative v0.7 telemetry condition semantics.

The evaluator is intentionally independent of persistence and transport.  Callers
must construct one committed :class:`ConditionSnapshot` per attempt; every
telemetry operand is then resolved from that snapshot and cannot perform I/O.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping, Sequence, TypeAlias


MAX_PLAN_DEPTH = 16
MAX_PLAN_NODES = 128
MAX_PLAN_OPERANDS = 256
MAX_IDENTIFIER_LENGTH = 128
MAX_STRING_BYTES = 65_536
MAX_BYTES_VALUE = 65_536

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SIGNED_DECIMAL = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_UNSIGNED_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")


class ConditionContractError(ValueError):
    """A stable, non-secret-bearing condition contract failure."""

    def __init__(self, code: str, path: str, message: str):
        self.code = code
        self.path = path[:160]
        self.message = message[:240]
        super().__init__(f"{self.path}: {self.message} [{self.code}]")

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class ScalarType(str, Enum):
    BOOLEAN = "BOOLEAN"
    INT64 = "INT64"
    UINT64 = "UINT64"
    FINITE_DOUBLE = "FINITE_DOUBLE"
    STRING = "STRING"
    BYTES = "BYTES"


class ComparisonOperator(str, Enum):
    EQ = "EQ"
    NE = "NE"
    LT = "LT"
    LE = "LE"
    GT = "GT"
    GE = "GE"


class LogicalOperator(str, Enum):
    AND = "AND"
    OR = "OR"


class TruthValue(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    INDETERMINATE = "INDETERMINATE"
    REJECTED = "REJECTED"


class ValueField(str, Enum):
    RAW = "RAW"
    ENGINEERING = "ENGINEERING"


NUMERIC_TYPES = frozenset(
    {ScalarType.INT64, ScalarType.UINT64, ScalarType.FINITE_DOUBLE}
)
ORDERABLE_NON_NUMERIC_TYPES = frozenset({ScalarType.STRING, ScalarType.BYTES})


def _fail(code: str, path: str, message: str) -> None:
    raise ConditionContractError(code, path, message)


def _require_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] = frozenset(),
    path: str,
) -> None:
    if not isinstance(value, Mapping):
        _fail("INVALID_SHAPE", path, "must be an object")
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        _fail("MISSING_FIELD", path, f"missing fields: {', '.join(sorted(missing))}")
    if extra:
        _fail("UNKNOWN_FIELD", path, f"unknown fields: {', '.join(sorted(extra))}")


def _bounded_identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail("INVALID_IDENTIFIER", path, "must be a bounded ASCII identifier")
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail("INVALID_DIGEST", path, "must be a lowercase SHA-256 digest")
    return value


def _enum(enum_type: type[Enum], value: Any, path: str) -> Any:
    if not isinstance(value, str):
        _fail("INVALID_ENUM", path, "must be an enumerated string")
    try:
        return enum_type(value)
    except ValueError:
        _fail("INVALID_ENUM", path, f"unsupported value {value!r}")


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def sample_id_for(
    source_id: str, source_epoch: str, item_id: str, source_sequence: int
) -> str:
    """Return the v0.7 canonical durable sample identity digest."""

    _bounded_identifier(source_id, "sample_identity.source_id")
    _bounded_identifier(source_epoch, "sample_identity.source_epoch")
    _bounded_identifier(item_id, "sample_identity.item_id")
    if type(source_sequence) is not int or source_sequence < 1 or source_sequence >= 2**64:
        _fail("INVALID_SEQUENCE", "sample_identity.source_sequence", "must be a positive UINT64")
    return _canonical_digest(
        {
            "item_id": item_id,
            "source_epoch": source_epoch,
            "source_id": source_id,
            "source_sequence": str(source_sequence),
        }
    )


@dataclass(frozen=True)
class TypedScalar:
    scalar_type: ScalarType
    value: bool | int | float | str | bytes

    def __post_init__(self) -> None:
        path = "typed_scalar.value"
        if type(self.scalar_type) is not ScalarType:
            _fail("INVALID_ENUM", "typed_scalar.type", "scalar type must be typed")
        if self.scalar_type is ScalarType.BOOLEAN:
            if type(self.value) is not bool:
                _fail("TYPE_MISMATCH", path, "BOOLEAN requires a boolean")
        elif self.scalar_type is ScalarType.INT64:
            if type(self.value) is not int or not -(2**63) <= self.value < 2**63:
                _fail("TYPE_MISMATCH", path, "INT64 requires a signed 64-bit integer")
        elif self.scalar_type is ScalarType.UINT64:
            if type(self.value) is not int or not 0 <= self.value < 2**64:
                _fail("TYPE_MISMATCH", path, "UINT64 requires an unsigned 64-bit integer")
        elif self.scalar_type is ScalarType.FINITE_DOUBLE:
            if type(self.value) is not float or not math.isfinite(self.value):
                _fail("NON_FINITE", path, "FINITE_DOUBLE requires a finite float")
        elif self.scalar_type is ScalarType.STRING:
            if not isinstance(self.value, str):
                _fail("TYPE_MISMATCH", path, "STRING requires text")
            if len(self.value.encode("utf-8")) > MAX_STRING_BYTES:
                _fail("BOUND_EXCEEDED", path, "STRING exceeds the byte bound")
        elif self.scalar_type is ScalarType.BYTES:
            if not isinstance(self.value, bytes):
                _fail("TYPE_MISMATCH", path, "BYTES requires bytes")
            if len(self.value) > MAX_BYTES_VALUE:
                _fail("BOUND_EXCEEDED", path, "BYTES exceeds the byte bound")
        else:  # pragma: no cover - Enum construction normally makes this impossible.
            _fail("INVALID_ENUM", "typed_scalar.type", "unsupported scalar type")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], *, path: str = "value") -> "TypedScalar":
        _require_keys(value, required={"type", "value"}, path=path)
        scalar_type = _enum(ScalarType, value["type"], f"{path}.type")
        raw = value["value"]
        if scalar_type is ScalarType.INT64:
            if not isinstance(raw, str) or _SIGNED_DECIMAL.fullmatch(raw) is None:
                _fail("NON_CANONICAL_INTEGER", f"{path}.value", "INT64 must be canonical base-10 text")
            raw = int(raw)
        elif scalar_type is ScalarType.UINT64:
            if not isinstance(raw, str) or _UNSIGNED_DECIMAL.fullmatch(raw) is None:
                _fail("NON_CANONICAL_INTEGER", f"{path}.value", "UINT64 must be canonical base-10 text")
            raw = int(raw)
        elif scalar_type is ScalarType.FINITE_DOUBLE:
            if type(raw) not in (int, float) or isinstance(raw, bool):
                _fail("TYPE_MISMATCH", f"{path}.value", "FINITE_DOUBLE must be a JSON number")
            try:
                raw = float(raw)
            except OverflowError:
                _fail("NON_FINITE", f"{path}.value", "FINITE_DOUBLE is outside the finite range")
        elif scalar_type is ScalarType.BYTES:
            if not isinstance(raw, str):
                _fail("TYPE_MISMATCH", f"{path}.value", "BYTES must be canonical base64 text")
            try:
                decoded = base64.b64decode(raw, validate=True)
            except (ValueError, binascii.Error):
                _fail("INVALID_BASE64", f"{path}.value", "BYTES is not canonical base64")
            if base64.b64encode(decoded).decode("ascii") != raw:
                _fail("INVALID_BASE64", f"{path}.value", "BYTES is not canonical base64")
            raw = decoded
        return cls(scalar_type, raw)

    def as_dict(self) -> dict[str, Any]:
        value: Any = self.value
        if self.scalar_type in {ScalarType.INT64, ScalarType.UINT64}:
            value = str(value)
        elif self.scalar_type is ScalarType.BYTES:
            value = base64.b64encode(value).decode("ascii")
        return {"type": self.scalar_type.value, "value": value}

    def numeric(self) -> Decimal:
        if self.scalar_type not in NUMERIC_TYPES:
            _fail("TYPE_MISMATCH", "typed_scalar", "value is not numeric")
        if self.scalar_type is ScalarType.FINITE_DOUBLE:
            return Decimal(str(self.value))
        return Decimal(self.value)


@dataclass(frozen=True)
class LiteralOperand:
    value: TypedScalar

    def as_dict(self) -> dict[str, Any]:
        return {"kind": "LITERAL", "value": self.value.as_dict()}

    @property
    def scalar_type(self) -> ScalarType:
        return self.value.scalar_type


@dataclass(frozen=True)
class TelemetryOperand:
    item_id: str
    catalog_digest: str
    scalar_type: ScalarType
    value_field: ValueField = ValueField.ENGINEERING

    def __post_init__(self) -> None:
        _bounded_identifier(self.item_id, "telemetry.item_id")
        _digest(self.catalog_digest, "telemetry.catalog_digest")
        if type(self.scalar_type) is not ScalarType or type(self.value_field) is not ValueField:
            _fail("INVALID_ENUM", "telemetry", "scalar type and value field must be typed")

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "TELEMETRY",
            "item_id": self.item_id,
            "catalog_digest": self.catalog_digest,
            "scalar_type": self.scalar_type.value,
            "value_field": self.value_field.value,
        }


ConditionOperand: TypeAlias = LiteralOperand | TelemetryOperand


@dataclass(frozen=True)
class PredicateNode:
    node_id: str
    operator: ComparisonOperator
    left: ConditionOperand
    right: ConditionOperand
    tolerance: TypedScalar | None = None

    def __post_init__(self) -> None:
        _bounded_identifier(self.node_id, "predicate.node_id")
        if type(self.operator) is not ComparisonOperator:
            _fail("INVALID_ENUM", self.node_id, "comparison operator must be typed")
        if not isinstance(self.left, (LiteralOperand, TelemetryOperand)) or not isinstance(
            self.right, (LiteralOperand, TelemetryOperand)
        ):
            _fail("INVALID_SHAPE", self.node_id, "predicate operands must be typed")
        if self.tolerance is not None and not isinstance(self.tolerance, TypedScalar):
            _fail("TYPE_MISMATCH", self.node_id, "tolerance must be a typed scalar")
        left_type = self.left.scalar_type
        right_type = self.right.scalar_type
        compatible_numeric = left_type in NUMERIC_TYPES and right_type in NUMERIC_TYPES
        if left_type is not right_type and not compatible_numeric:
            _fail("TYPE_MISMATCH", self.node_id, "predicate operands are not compatible")
        if self.operator in {
            ComparisonOperator.LT,
            ComparisonOperator.LE,
            ComparisonOperator.GT,
            ComparisonOperator.GE,
        }:
            if not compatible_numeric and not (
                left_type is right_type and left_type in ORDERABLE_NON_NUMERIC_TYPES
            ):
                _fail("UNORDERABLE_TYPE", self.node_id, "operator requires orderable operands")
        if self.tolerance is not None:
            if self.operator not in {ComparisonOperator.EQ, ComparisonOperator.NE}:
                _fail("INVALID_TOLERANCE", self.node_id, "tolerance is valid only for EQ or NE")
            if not compatible_numeric or self.tolerance.scalar_type not in NUMERIC_TYPES:
                _fail("INVALID_TOLERANCE", self.node_id, "tolerance requires numeric operands")
            if self.tolerance.numeric() < 0:
                _fail("INVALID_TOLERANCE", self.node_id, "tolerance cannot be negative")

    def as_dict(self) -> dict[str, Any]:
        result = {
            "type": "PREDICATE",
            "node_id": self.node_id,
            "operator": self.operator.value,
            "left": self.left.as_dict(),
            "right": self.right.as_dict(),
        }
        if self.tolerance is not None:
            result["tolerance"] = self.tolerance.as_dict()
        return result


@dataclass(frozen=True)
class LogicalNode:
    node_id: str
    operator: LogicalOperator
    children: tuple["ConditionNode", ...]

    def __post_init__(self) -> None:
        _bounded_identifier(self.node_id, "logical.node_id")
        if type(self.operator) is not LogicalOperator:
            _fail("INVALID_ENUM", self.node_id, "logical operator must be typed")
        if not isinstance(self.children, tuple) or not all(
            isinstance(child, (PredicateNode, LogicalNode)) for child in self.children
        ):
            _fail("INVALID_SHAPE", self.node_id, "children must be a tuple of typed nodes")
        if len(self.children) < 2:
            _fail("INVALID_ARITY", self.node_id, "AND and OR require at least two children")

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.operator.value,
            "node_id": self.node_id,
            "children": [child.as_dict() for child in self.children],
        }


ConditionNode: TypeAlias = PredicateNode | LogicalNode


def _parse_operand(value: Mapping[str, Any], path: str) -> ConditionOperand:
    if not isinstance(value, Mapping):
        _fail("INVALID_SHAPE", path, "operand must be an object")
    kind = value.get("kind")
    if kind == "LITERAL":
        _require_keys(value, required={"kind", "value"}, path=path)
        return LiteralOperand(TypedScalar.from_dict(value["value"], path=f"{path}.value"))
    if kind == "TELEMETRY":
        _require_keys(
            value,
            required={"kind", "item_id", "catalog_digest", "scalar_type", "value_field"},
            path=path,
        )
        return TelemetryOperand(
            item_id=_bounded_identifier(value["item_id"], f"{path}.item_id"),
            catalog_digest=_digest(value["catalog_digest"], f"{path}.catalog_digest"),
            scalar_type=_enum(ScalarType, value["scalar_type"], f"{path}.scalar_type"),
            value_field=_enum(ValueField, value["value_field"], f"{path}.value_field"),
        )
    _fail("INVALID_NODE_TYPE", f"{path}.kind", "operand must be LITERAL or TELEMETRY")


def _parse_node(value: Mapping[str, Any], path: str, depth: int) -> ConditionNode:
    if depth > MAX_PLAN_DEPTH:
        _fail("DEPTH_EXCEEDED", path, f"plan depth exceeds {MAX_PLAN_DEPTH}")
    if not isinstance(value, Mapping):
        _fail("INVALID_SHAPE", path, "condition node must be an object")
    node_type = value.get("type")
    if node_type == "PREDICATE":
        _require_keys(
            value,
            required={"type", "node_id", "operator", "left", "right"},
            optional={"tolerance"},
            path=path,
        )
        tolerance = value.get("tolerance")
        return PredicateNode(
            node_id=_bounded_identifier(value["node_id"], f"{path}.node_id"),
            operator=_enum(ComparisonOperator, value["operator"], f"{path}.operator"),
            left=_parse_operand(value["left"], f"{path}.left"),
            right=_parse_operand(value["right"], f"{path}.right"),
            tolerance=(
                TypedScalar.from_dict(tolerance, path=f"{path}.tolerance")
                if tolerance is not None
                else None
            ),
        )
    if node_type in {"AND", "OR"}:
        _require_keys(value, required={"type", "node_id", "children"}, path=path)
        children = value["children"]
        if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
            _fail("INVALID_SHAPE", f"{path}.children", "children must be an array")
        if len(children) > MAX_PLAN_NODES:
            _fail("NODE_BOUND_EXCEEDED", f"{path}.children", "too many direct children")
        return LogicalNode(
            node_id=_bounded_identifier(value["node_id"], f"{path}.node_id"),
            operator=_enum(LogicalOperator, node_type, f"{path}.type"),
            children=tuple(
                _parse_node(child, f"{path}.children[{index}]", depth + 1)
                for index, child in enumerate(children)
            ),
        )
    _fail("INVALID_NODE_TYPE", f"{path}.type", "node must be PREDICATE, AND, or OR")


@dataclass(frozen=True)
class ConditionPlan:
    condition_plan_id: str
    root: ConditionNode
    condition_plan_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _bounded_identifier(self.condition_plan_id, "condition_plan_id")
        if not isinstance(self.root, (PredicateNode, LogicalNode)):
            _fail("INVALID_SHAPE", "condition_plan.root", "root must be a typed condition node")
        node_ids: set[str] = set()
        node_count = 0
        operand_count = 0

        def walk(node: ConditionNode, depth: int) -> None:
            nonlocal node_count, operand_count
            if depth > MAX_PLAN_DEPTH:
                _fail("DEPTH_EXCEEDED", node.node_id, f"plan depth exceeds {MAX_PLAN_DEPTH}")
            node_count += 1
            if node_count > MAX_PLAN_NODES:
                _fail("NODE_BOUND_EXCEEDED", node.node_id, f"plan exceeds {MAX_PLAN_NODES} nodes")
            if node.node_id in node_ids:
                _fail("DUPLICATE_NODE_ID", node.node_id, "node identifiers must be unique")
            node_ids.add(node.node_id)
            if isinstance(node, PredicateNode):
                operand_count += 2
                if operand_count > MAX_PLAN_OPERANDS:
                    _fail("OPERAND_BOUND_EXCEEDED", node.node_id, "plan has too many operands")
            else:
                for child in node.children:
                    walk(child, depth + 1)

        walk(self.root, 1)
        digest = _canonical_digest(
            {
                "schema_version": "spell.v07.condition-plan/1",
                "condition_plan_id": self.condition_plan_id,
                "root": self.root.as_dict(),
            }
        )
        object.__setattr__(self, "condition_plan_digest", digest)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConditionPlan":
        _require_keys(
            value,
            required={"condition_plan_id", "root"},
            optional={"schema_version", "condition_plan_digest"},
            path="condition_plan",
        )
        if value.get("schema_version", "spell.v07.condition-plan/1") != "spell.v07.condition-plan/1":
            _fail("CONTRACT_MISMATCH", "condition_plan.schema_version", "unsupported plan schema")
        plan = cls(
            condition_plan_id=_bounded_identifier(
                value["condition_plan_id"], "condition_plan.condition_plan_id"
            ),
            root=_parse_node(value["root"], "condition_plan.root", 1),
        )
        supplied_digest = value.get("condition_plan_digest")
        if supplied_digest is not None and _digest(
            supplied_digest, "condition_plan.condition_plan_digest"
        ) != plan.condition_plan_digest:
            _fail("CONTRACT_MISMATCH", "condition_plan.condition_plan_digest", "plan digest mismatch")
        return plan

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "spell.v07.condition-plan/1",
            "condition_plan_id": self.condition_plan_id,
            "condition_plan_digest": self.condition_plan_digest,
            "root": self.root.as_dict(),
        }


@dataclass(frozen=True)
class QualityFreshnessPolicy:
    policy_id: str
    policy_revision: str
    accepted_validity: frozenset[str] = frozenset({"VALID"})
    accepted_quality: frozenset[str] = frozenset({"GOOD"})
    accepted_freshness: frozenset[str] = frozenset({"FRESH"})

    def __post_init__(self) -> None:
        _bounded_identifier(self.policy_id, "policy.policy_id")
        _bounded_identifier(self.policy_revision, "policy.policy_revision")
        required = {
            "accepted_validity": frozenset({"VALID"}),
            "accepted_quality": frozenset({"GOOD"}),
            "accepted_freshness": frozenset({"FRESH"}),
        }
        for name, values in required.items():
            selected = getattr(self, name)
            if not isinstance(selected, frozenset) or selected != values:
                _fail("INVALID_POLICY", f"policy.{name}", "does not match the pinned v0.7 acceptance set")

    def as_dict(self) -> dict[str, Any]:
        return {
            "quality_freshness_policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "accepted_validity": sorted(self.accepted_validity),
            "accepted_quality": sorted(self.accepted_quality),
            "accepted_freshness": sorted(self.accepted_freshness),
        }


@dataclass(frozen=True)
class SampleEvidence:
    sample_id: str
    item_id: str
    catalog_digest: str
    source_id: str
    source_epoch: str
    source_sequence: int
    snapshot_cursor: int
    raw_value: TypedScalar
    engineering_value: TypedScalar
    unit: str
    validity: str
    quality: str
    freshness: str
    synchronized: bool = True
    has_gap: bool = False
    clock_acceptable: bool = True

    def __post_init__(self) -> None:
        _digest(self.sample_id, "sample.sample_id")
        _bounded_identifier(self.item_id, "sample.item_id")
        _digest(self.catalog_digest, "sample.catalog_digest")
        _bounded_identifier(self.source_id, "sample.source_id")
        _bounded_identifier(self.source_epoch, "sample.source_epoch")
        if type(self.source_sequence) is not int or self.source_sequence < 1:
            _fail("INVALID_SEQUENCE", "sample.source_sequence", "must be positive")
        if self.sample_id != sample_id_for(
            self.source_id, self.source_epoch, self.item_id, self.source_sequence
        ):
            _fail("CONTRACT_MISMATCH", "sample.sample_id", "does not bind the canonical sample identity")
        if type(self.snapshot_cursor) is not int or self.snapshot_cursor < 0:
            _fail("INVALID_CURSOR", "sample.snapshot_cursor", "must be nonnegative")
        if not isinstance(self.unit, str) or len(self.unit.encode("utf-8")) > 256:
            _fail("BOUND_EXCEEDED", "sample.unit", "unit must be bounded text")
        if not isinstance(self.raw_value, TypedScalar) or not isinstance(
            self.engineering_value, TypedScalar
        ):
            _fail("TYPE_MISMATCH", "sample", "raw and engineering values must be typed")
        if self.validity not in {"VALID", "INVALID", "UNKNOWN"}:
            _fail("INVALID_ENUM", "sample.validity", "unsupported validity")
        if self.quality not in {"GOOD", "SUSPECT", "BAD", "UNKNOWN"}:
            _fail("INVALID_ENUM", "sample.quality", "unsupported quality")
        if self.freshness not in {"FRESH", "STALE", "UNKNOWN"}:
            _fail("INVALID_ENUM", "sample.freshness", "unsupported freshness")
        if any(type(value) is not bool for value in (self.synchronized, self.has_gap, self.clock_acceptable)):
            _fail("TYPE_MISMATCH", "sample", "sample state flags must be boolean")

    def selected_value(self, field: ValueField) -> TypedScalar:
        return self.raw_value if field is ValueField.RAW else self.engineering_value


@dataclass(frozen=True)
class ConditionSnapshot:
    snapshot_cursor: int
    samples: tuple[SampleEvidence, ...]
    synchronized: bool = True
    has_gap: bool = False
    clock_acceptable: bool = True

    def __post_init__(self) -> None:
        if type(self.snapshot_cursor) is not int or self.snapshot_cursor < 0:
            _fail("INVALID_CURSOR", "snapshot.snapshot_cursor", "must be nonnegative")
        if not isinstance(self.samples, tuple) or not all(
            isinstance(sample, SampleEvidence) for sample in self.samples
        ):
            _fail("INVALID_SHAPE", "snapshot.samples", "must be a tuple of sample evidence")
        if len(self.samples) > MAX_PLAN_OPERANDS:
            _fail("BOUND_EXCEEDED", "snapshot.samples", "snapshot contains too many samples")
        identities: set[tuple[str, str]] = set()
        for sample in self.samples:
            if sample.snapshot_cursor != self.snapshot_cursor:
                _fail("CONTRACT_MISMATCH", "snapshot.samples", "sample cursor does not match snapshot")
            identity = (sample.item_id, sample.catalog_digest)
            if identity in identities:
                _fail("DUPLICATE_SAMPLE", sample.item_id, "snapshot contains duplicate item evidence")
            identities.add(identity)
        if any(type(value) is not bool for value in (self.synchronized, self.has_gap, self.clock_acceptable)):
            _fail("TYPE_MISMATCH", "snapshot", "snapshot state flags must be boolean")

    def find(self, item_id: str, catalog_digest: str) -> SampleEvidence | None:
        return next(
            (
                sample
                for sample in self.samples
                if sample.item_id == item_id and sample.catalog_digest == catalog_digest
            ),
            None,
        )

    def find_item(self, item_id: str) -> SampleEvidence | None:
        return next((sample for sample in self.samples if sample.item_id == item_id), None)


@dataclass(frozen=True)
class OperandEvidence:
    kind: str
    scalar_type: str
    typed_value: Mapping[str, Any] | None = None
    item_id: str | None = None
    sample_id: str | None = None
    value_field: str | None = None

    def as_dict(self) -> dict[str, Any]:
        if self.kind == "LITERAL":
            return {"kind": self.kind, "typed_value": dict(self.typed_value or {})}
        return {
            "kind": self.kind,
            "item_id": self.item_id,
            "sample_id": self.sample_id,
            "scalar_type": self.scalar_type,
            "value_field": self.value_field,
        }


@dataclass(frozen=True)
class LeafResult:
    node_id: str
    operator: str
    left_typed_value_or_sample_id: OperandEvidence
    right_typed_value_or_sample_id: OperandEvidence
    tolerance: Mapping[str, Any] | None
    result: TruthValue
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "operator": self.operator,
            "left_typed_value_or_sample_id": self.left_typed_value_or_sample_id.as_dict(),
            "right_typed_value_or_sample_id": self.right_typed_value_or_sample_id.as_dict(),
            "tolerance": dict(self.tolerance) if self.tolerance is not None else None,
            "result": self.result.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ConditionEvaluation:
    condition_plan_id: str
    condition_plan_digest: str
    quality_freshness_policy_id: str
    quality_freshness_policy_revision: str
    snapshot_cursor: int
    composite_result: TruthValue
    leaf_results: tuple[LeafResult, ...]
    consumed_sample_ids: tuple[str, ...]
    reason: str

    @property
    def result_digest(self) -> str:
        return _canonical_digest(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "spell.v07.condition-attempt-result/1",
            "condition_plan_id": self.condition_plan_id,
            "condition_plan_digest": self.condition_plan_digest,
            "quality_freshness_policy_id": self.quality_freshness_policy_id,
            "quality_freshness_policy_revision": self.quality_freshness_policy_revision,
            "snapshot_cursor": self.snapshot_cursor,
            "composite_result": self.composite_result.value,
            "leaf_results": [result.as_dict() for result in self.leaf_results],
            "consumed_sample_ids": list(self.consumed_sample_ids),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class _ResolvedOperand:
    value: TypedScalar | None
    evidence: OperandEvidence
    result: TruthValue
    reason: str
    sample_id: str | None = None


def _resolve_operand(
    operand: ConditionOperand,
    snapshot: ConditionSnapshot,
    policy: QualityFreshnessPolicy,
) -> _ResolvedOperand:
    if isinstance(operand, LiteralOperand):
        return _ResolvedOperand(
            operand.value,
            OperandEvidence(
                kind="LITERAL",
                scalar_type=operand.scalar_type.value,
                typed_value=operand.value.as_dict(),
            ),
            TruthValue.TRUE,
            "LITERAL",
        )
    sample = snapshot.find(operand.item_id, operand.catalog_digest)
    evidence = OperandEvidence(
        kind="TELEMETRY",
        scalar_type=operand.scalar_type.value,
        item_id=operand.item_id,
        sample_id=sample.sample_id if sample else None,
        value_field=operand.value_field.value,
    )
    if sample is None:
        mismatch = snapshot.find_item(operand.item_id)
        reason = "CATALOG_MISMATCH" if mismatch is not None else "SAMPLE_MISSING"
        state = TruthValue.REJECTED if mismatch is not None else TruthValue.INDETERMINATE
        return _ResolvedOperand(None, evidence, state, reason)
    selected = sample.selected_value(operand.value_field)
    if selected.scalar_type is not operand.scalar_type:
        return _ResolvedOperand(None, evidence, TruthValue.REJECTED, "SAMPLE_TYPE_MISMATCH", sample.sample_id)
    gates = (
        (snapshot.has_gap or sample.has_gap, "SOURCE_GAP"),
        (not snapshot.synchronized or not sample.synchronized, "UNSYNCHRONIZED"),
        (not snapshot.clock_acceptable or not sample.clock_acceptable, "CLOCK_UNACCEPTABLE"),
        (sample.validity not in policy.accepted_validity, "VALIDITY_UNACCEPTABLE"),
        (sample.quality not in policy.accepted_quality, "QUALITY_UNACCEPTABLE"),
        (sample.freshness not in policy.accepted_freshness, "FRESHNESS_UNACCEPTABLE"),
    )
    for failed, reason in gates:
        if failed:
            return _ResolvedOperand(None, evidence, TruthValue.INDETERMINATE, reason, sample.sample_id)
    return _ResolvedOperand(selected, evidence, TruthValue.TRUE, "SAMPLE_ACCEPTED", sample.sample_id)


def _compare(left: TypedScalar, right: TypedScalar, node: PredicateNode) -> bool:
    numeric = left.scalar_type in NUMERIC_TYPES and right.scalar_type in NUMERIC_TYPES
    if numeric:
        left_value: Any = left.numeric()
        right_value: Any = right.numeric()
    else:
        left_value = left.value
        right_value = right.value
    if node.operator in {ComparisonOperator.EQ, ComparisonOperator.NE}:
        if node.tolerance is not None:
            equal = abs(left_value - right_value) <= node.tolerance.numeric()
        else:
            equal = left_value == right_value
        return equal if node.operator is ComparisonOperator.EQ else not equal
    if node.operator is ComparisonOperator.LT:
        return left_value < right_value
    if node.operator is ComparisonOperator.LE:
        return left_value <= right_value
    if node.operator is ComparisonOperator.GT:
        return left_value > right_value
    if node.operator is ComparisonOperator.GE:
        return left_value >= right_value
    raise AssertionError("validated operator was not handled")


def evaluate_condition(
    plan: ConditionPlan,
    snapshot: ConditionSnapshot,
    policy: QualityFreshnessPolicy,
) -> ConditionEvaluation:
    """Evaluate a validated plan once against exactly one committed snapshot."""

    leaf_results: list[LeafResult] = []
    consumed: list[str] = []

    def evaluate_node(node: ConditionNode) -> TruthValue:
        if isinstance(node, PredicateNode):
            left = _resolve_operand(node.left, snapshot, policy)
            right = _resolve_operand(node.right, snapshot, policy)
            for resolved in (left, right):
                if resolved.sample_id is not None and resolved.sample_id not in consumed:
                    consumed.append(resolved.sample_id)
            rejected = left.result is TruthValue.REJECTED or right.result is TruthValue.REJECTED
            indeterminate = (
                left.result is TruthValue.INDETERMINATE
                or right.result is TruthValue.INDETERMINATE
            )
            if rejected:
                result = TruthValue.REJECTED
                reason = next(
                    item.reason for item in (left, right) if item.result is TruthValue.REJECTED
                )
            elif indeterminate:
                result = TruthValue.INDETERMINATE
                reason = next(
                    item.reason
                    for item in (left, right)
                    if item.result is TruthValue.INDETERMINATE
                )
            else:
                matched = _compare(left.value, right.value, node)  # type: ignore[arg-type]
                result = TruthValue.TRUE if matched else TruthValue.FALSE
                reason = "COMPARISON_TRUE" if matched else "COMPARISON_FALSE"
            leaf_results.append(
                LeafResult(
                    node_id=node.node_id,
                    operator=node.operator.value,
                    left_typed_value_or_sample_id=left.evidence,
                    right_typed_value_or_sample_id=right.evidence,
                    tolerance=node.tolerance.as_dict() if node.tolerance else None,
                    result=result,
                    reason=reason,
                )
            )
            return result

        child_results = tuple(evaluate_node(child) for child in node.children)
        if TruthValue.REJECTED in child_results:
            return TruthValue.REJECTED
        if node.operator is LogicalOperator.AND:
            if TruthValue.FALSE in child_results:
                return TruthValue.FALSE
            if all(result is TruthValue.TRUE for result in child_results):
                return TruthValue.TRUE
            return TruthValue.INDETERMINATE
        if TruthValue.TRUE in child_results:
            return TruthValue.TRUE
        if all(result is TruthValue.FALSE for result in child_results):
            return TruthValue.FALSE
        return TruthValue.INDETERMINATE

    composite = evaluate_node(plan.root)
    return ConditionEvaluation(
        condition_plan_id=plan.condition_plan_id,
        condition_plan_digest=plan.condition_plan_digest,
        quality_freshness_policy_id=policy.policy_id,
        quality_freshness_policy_revision=policy.policy_revision,
        snapshot_cursor=snapshot.snapshot_cursor,
        composite_result=composite,
        leaf_results=tuple(leaf_results),
        consumed_sample_ids=tuple(consumed),
        reason=(
            "PLAN_REJECTED"
            if composite is TruthValue.REJECTED
            else "ATOMIC_SNAPSHOT_EVALUATED"
        ),
    )


__all__ = [
    "ComparisonOperator",
    "ConditionContractError",
    "ConditionEvaluation",
    "ConditionPlan",
    "ConditionSnapshot",
    "LeafResult",
    "LiteralOperand",
    "LogicalNode",
    "LogicalOperator",
    "PredicateNode",
    "QualityFreshnessPolicy",
    "SampleEvidence",
    "ScalarType",
    "TelemetryOperand",
    "TruthValue",
    "TypedScalar",
    "ValueField",
    "evaluate_condition",
    "sample_id_for",
]
