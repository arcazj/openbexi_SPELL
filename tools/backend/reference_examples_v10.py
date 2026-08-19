"""Bounded deterministic runtime for the SPELL 2.4.4 reference examples.

The language reference contains executable fragments, pseudocode, output-only
illustrations, and deliberately incorrect code.  This module therefore runs a
versioned semantic adaptation for each example.  It never evaluates reference
text as Python and never imports a module named by procedure input.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from .bundled_observation_catalog import (
    CATALOG_DIGEST,
    build_bundled_observation_catalog,
    bundled_visibility,
)
from .condition_engine import SampleEvidence, ScalarType, TypedScalar, sample_id_for
from .observation_catalog import Direction, ReadOutcome


REFERENCE_SOURCE_SHA256 = "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3"
REFERENCE_CONTRACT_SHA256 = "ab7535a2db540664f1303fb8cd73f1599fe7aa81d469003cfe15fe7fa3ba7e4c"
REFERENCE_VARIANT_CONTRACT_SHA256 = "35ccaf6f276a2a6571e96f43c8aeb33ebf33cca16de3d6b9740e0217d45f94c8"
CONTRACT_RELATIVE_PATH = Path("contracts/v10/language_reference_example_matrix.json")
VARIANT_CONTRACT_RELATIVE_PATH = Path("contracts/v10/language_reference_variant_matrix.json")
MAX_EXAMPLES = 195
MAX_TRACE_EVENTS = 64
MAX_ASSERTIONS = 32
MAX_CONTRACT_BYTES = 1_000_000
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ReferenceExampleError(ValueError):
    """Base class for stable worker-facing reference runner failures."""


class ReferenceContractError(ReferenceExampleError):
    """Raised when the example matrix cannot prove an exact 1..195 contract."""


class ReferenceExecutionError(ReferenceExampleError):
    """Raised for an invalid example selection or an execution bound violation."""


@dataclass(frozen=True)
class ReferenceExampleContract:
    example_number: int
    artifact_id: str
    display_title: str
    source_title: str
    source_version: str
    source_page: int
    body_span_sha256: str
    normalized_span_sha256: str
    adaptation_id: str
    adaptation_disposition: str
    oracle_id: str
    oracle_mode: str
    required_assertion_count: int
    semantic_family: str
    handler_family: str
    required_capabilities: tuple[str, ...]
    expected_effects: tuple[str, ...]
    success_criteria: str


@dataclass(frozen=True)
class ReferenceVariantContract:
    example_number: int
    variant_id: str
    subcase_id: str
    slug: str
    classification: str
    source_anchor_sha256: str
    adapter_id: str
    oracle_id: str
    test_id: str
    required_assertion_id: str
    required_trace_operation: str


@dataclass(frozen=True)
class ReferenceVariantExampleContract:
    example_number: int
    artifact_id: str
    classification: str
    body_span_sha256: str
    normalized_span_sha256: str
    adaptation_id: str
    example_oracle_id: str
    ambiguity_codes: tuple[str, ...]
    variants: tuple[ReferenceVariantContract, ...]


@dataclass(frozen=True)
class TraceEvent:
    sequence: int
    operation: str
    inputs: Mapping[str, Any]
    output: Any
    variant_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "operation": self.operation,
            "inputs": dict(self.inputs),
            "output": self.output,
            "variant_id": self.variant_id,
        }


@dataclass(frozen=True)
class OracleAssertion:
    assertion_id: str
    passed: bool
    expected: Any
    actual: Any
    variant_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "variant_id": self.variant_id,
        }


@dataclass(frozen=True)
class EffectProof:
    effect_id: str
    assertion_ids: tuple[str, ...]
    trace_sequences: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "assertion_ids": list(self.assertion_ids),
            "trace_sequences": list(self.trace_sequences),
        }


@dataclass(frozen=True)
class VariantProof:
    variant_id: str
    subcase_id: str
    classification: str
    adapter_id: str
    oracle_id: str
    test_id: str
    source_anchor_sha256: str
    required_assertion_id: str
    required_trace_operation: str
    status: str
    assertion_ids: tuple[str, ...]
    trace_sequences: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "subcase_id": self.subcase_id,
            "classification": self.classification,
            "adapter_id": self.adapter_id,
            "oracle_id": self.oracle_id,
            "test_id": self.test_id,
            "source_anchor_sha256": self.source_anchor_sha256,
            "required_assertion_id": self.required_assertion_id,
            "required_trace_operation": self.required_trace_operation,
            "status": self.status,
            "assertion_ids": list(self.assertion_ids),
            "trace_sequences": list(self.trace_sequences),
        }


@dataclass(frozen=True)
class ReferenceExampleResult:
    example_number: int
    artifact_id: str
    display_title: str
    semantic_family: str
    handler_family: str
    execution_mode: str
    status: str
    assertions: tuple[OracleAssertion, ...]
    trace: tuple[TraceEvent, ...]
    effect_proofs: tuple[EffectProof, ...]
    variant_proofs: tuple[VariantProof, ...]
    evidence_digest: str

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    @property
    def summary(self) -> str:
        passed = sum(1 for item in self.assertions if item.passed)
        return (
            f"Example {self.example_number}: {self.status} "
            f"({passed}/{len(self.assertions)} assertions)"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "example_number": self.example_number,
            "artifact_id": self.artifact_id,
            "display_title": self.display_title,
            "semantic_family": self.semantic_family,
            "handler_family": self.handler_family,
            "execution_mode": self.execution_mode,
            "status": self.status,
            "assertions": [item.as_dict() for item in self.assertions],
            "trace": [item.as_dict() for item in self.trace],
            "effect_proofs": [item.as_dict() for item in self.effect_proofs],
            "variant_proofs": [item.as_dict() for item in self.variant_proofs],
            "evidence_digest": self.evidence_digest,
        }

    def as_event_payload(self) -> dict[str, Any]:
        return {
            "schema_version": "spell.v10.reference-example-result/1",
            **self.as_dict(),
            "passed": self.passed,
            "summary": self.summary,
        }


def default_contract_path() -> Path:
    return Path(__file__).resolve().parents[1] / CONTRACT_RELATIVE_PATH


def default_variant_contract_path() -> Path:
    return Path(__file__).resolve().parents[1] / VARIANT_CONTRACT_RELATIVE_PATH


def _records(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in ("examples", "rows", "example_matrix"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    raise ReferenceContractError("contract must contain an examples list")


def _required_text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReferenceContractError(f"{path} must be non-empty text")
    return value.strip()


def _required_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReferenceContractError(f"{path} must be an object")
    return value


def _contract_family_for_number(number: int) -> str:
    ranges = (
        (1, 1, "python.indentation"),
        (2, 4, "python.line_continuation"),
        (5, 6, "python.comments"),
        (7, 8, "python.values_and_containers"),
        (9, 12, "python.expressions"),
        (13, 15, "python.control_flow"),
        (16, 17, "python.local_functions"),
        (18, 18, "python.procedure_import"),
        (19, 25, "spell.modifiers_and_recovery"),
        (26, 29, "spell.time"),
        (30, 34, "telemetry.acquisition"),
        (35, 54, "telemetry.verification"),
        (55, 56, "telemetry.condition_composition"),
        (57, 59, "commanding.build"),
        (60, 77, "commanding.send"),
        (78, 83, "wait.conditions"),
        (84, 84, "ground.parameter"),
        (85, 93, "limits.query"),
        (94, 106, "limits.mutation"),
        (107, 107, "alarms.query"),
        (108, 110, "ui.messages"),
        (111, 113, "resources.state"),
        (114, 118, "ui.prompt"),
        (119, 127, "ui.display_workspace"),
        (128, 134, "procedure.control"),
        (135, 137, "database.spacecraft"),
        (138, 150, "database.dictionary"),
        (151, 161, "procedure.child_execution"),
        (162, 168, "filesystem.virtual"),
        (169, 176, "ranging.simulator"),
        (177, 190, "shared_data.state"),
        (191, 194, "memory.simulator"),
        (195, 195, "catalog.tm_tc_lookup"),
    )
    for lower, upper, family in ranges:
        if lower <= number <= upper:
            return family
    raise ReferenceContractError("example number must be between 1 and 195")


def _contract_case(record: Mapping[str, Any], index: int) -> ReferenceExampleContract:
    number = record.get("example_number")
    if type(number) is not int or not 1 <= number <= MAX_EXAMPLES:
        raise ReferenceContractError(f"examples[{index}].example_number is invalid")
    source = _required_mapping(record.get("source"), f"examples[{index}].source")
    adaptation = _required_mapping(record.get("adaptation"), f"examples[{index}].adaptation")
    oracle = _required_mapping(record.get("oracle"), f"examples[{index}].oracle")
    digest = _required_text(
        source.get("body_span_sha256", source.get("body_sha256")),
        f"examples[{index}].source.body_sha256",
    )
    if _DIGEST.fullmatch(digest) is None:
        raise ReferenceContractError(f"examples[{index}] has an invalid source span digest")
    normalized_digest = _required_text(
        source.get("normalized_span_sha256"),
        f"examples[{index}].source.normalized_span_sha256",
    )
    if _DIGEST.fullmatch(normalized_digest) is None:
        raise ReferenceContractError(
            f"examples[{index}] has an invalid normalized source span digest"
        )
    page = source.get("page")
    if isinstance(page, str) and page.isdigit():
        page = int(page)
    if type(page) is not int or page < 1:
        raise ReferenceContractError(f"examples[{index}].source.page is invalid")
    assertion_count = oracle.get("required_assertion_count", 1)
    if type(assertion_count) is not int or not 1 <= assertion_count <= MAX_ASSERTIONS:
        raise ReferenceContractError(f"examples[{index}] has an invalid assertion count")
    capabilities = record.get("required_capabilities", ())
    if not isinstance(capabilities, list) or not all(
        isinstance(value, str) and value for value in capabilities
    ):
        raise ReferenceContractError(f"examples[{index}].required_capabilities is invalid")
    expected_effects = oracle.get("expected_effects", ())
    if not isinstance(expected_effects, list) or not expected_effects or not all(
        isinstance(value, str) and value for value in expected_effects
    ):
        raise ReferenceContractError(f"examples[{index}].oracle.expected_effects is invalid")
    if len(set(expected_effects)) != len(expected_effects):
        raise ReferenceContractError(f"examples[{index}].oracle.expected_effects is duplicated")
    if assertion_count != len(expected_effects):
        raise ReferenceContractError(
            f"examples[{index}] assertion count must equal its expected effect count"
        )
    if adaptation.get("raw_snippet_executable_claim") is not False:
        raise ReferenceContractError(f"examples[{index}] must not claim raw snippet execution")
    artifact_id = record.get("compatibility_artifact_id", record.get("artifact_id"))
    expected_artifact_id = f"CMP-LRM244-EXAMPLE-{number:03d}"
    if artifact_id != expected_artifact_id:
        raise ReferenceContractError(
            f"examples[{index}] must bind artifact {expected_artifact_id}"
        )
    contract_family = _required_text(
        record.get("semantic_family"), f"examples[{index}].semantic_family"
    )
    if contract_family != _contract_family_for_number(number):
        raise ReferenceContractError(
            f"examples[{index}] semantic family does not match the frozen example map"
        )
    return ReferenceExampleContract(
        example_number=number,
        artifact_id=_required_text(artifact_id, f"examples[{index}].compatibility_artifact_id"),
        display_title=_required_text(record.get("display_title"), f"examples[{index}].display_title"),
        source_title=_required_text(source.get("title"), f"examples[{index}].source.title"),
        source_version=_required_text(
            source.get("version", "2.4.4"), f"examples[{index}].source.version"
        ),
        source_page=page,
        body_span_sha256=digest,
        normalized_span_sha256=normalized_digest,
        adaptation_id=_required_text(
            adaptation.get("adaptation_id"), f"examples[{index}].adaptation.adaptation_id"
        ),
        adaptation_disposition=_required_text(
            adaptation.get("disposition"), f"examples[{index}].adaptation.disposition"
        ),
        oracle_id=_required_text(oracle.get("oracle_id"), f"examples[{index}].oracle.oracle_id"),
        oracle_mode=_required_text(oracle.get("mode"), f"examples[{index}].oracle.mode"),
        required_assertion_count=assertion_count,
        semantic_family=contract_family,
        handler_family=_family_for_number(number),
        required_capabilities=tuple(capabilities),
        expected_effects=tuple(expected_effects),
        success_criteria=_required_text(
            oracle.get("success_criteria"), f"examples[{index}].oracle.success_criteria"
        ),
    )


def load_reference_contract(path: Path | str | None = None) -> tuple[ReferenceExampleContract, ...]:
    contract_path = Path(path) if path is not None else default_contract_path()
    try:
        raw = contract_path.read_bytes()
        if len(raw) > MAX_CONTRACT_BYTES:
            raise ReferenceContractError("v0.10 example contract exceeds its byte limit")
        payload = json.loads(raw.decode("utf-8"))
    except ReferenceContractError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceContractError(f"cannot read v0.10 example contract: {contract_path}") from exc
    if not isinstance(payload, Mapping):
        raise ReferenceContractError("contract root must be an object")
    if payload.get("example_count") != MAX_EXAMPLES:
        raise ReferenceContractError("contract example_count must be exactly 195")
    policy = payload.get("adaptation_policy")
    if not isinstance(policy, Mapping) or policy.get("raw_examples_executable_claim") is not False:
        raise ReferenceContractError("contract must explicitly deny raw example execution")
    raw_source = payload.get("authority", payload.get("source", {}))
    if isinstance(raw_source, Mapping):
        source_digest = raw_source.get("sha256", raw_source.get("source_sha256"))
        if source_digest is not None and source_digest != REFERENCE_SOURCE_SHA256:
            raise ReferenceContractError("contract is pinned to a different language reference")
    cases = tuple(_contract_case(record, index) for index, record in enumerate(_records(payload)))
    numbers = [case.example_number for case in cases]
    if len(cases) != MAX_EXAMPLES or sorted(numbers) != list(range(1, MAX_EXAMPLES + 1)):
        raise ReferenceContractError("contract must contain each example number 1..195 exactly once")
    if len({case.artifact_id for case in cases}) != MAX_EXAMPLES:
        raise ReferenceContractError("contract artifact IDs must be unique")
    if len({case.adaptation_id for case in cases}) != MAX_EXAMPLES:
        raise ReferenceContractError("contract adaptation IDs must be unique")
    if hashlib.sha256(raw).hexdigest() != REFERENCE_CONTRACT_SHA256:
        raise ReferenceContractError("contract does not match the frozen v0.10 matrix digest")
    return tuple(sorted(cases, key=lambda case: case.example_number))


def load_reference_variant_contract(
    path: Path | str | None = None,
    *,
    example_contracts: Iterable[ReferenceExampleContract] | None = None,
) -> tuple[ReferenceVariantExampleContract, ...]:
    contract_path = Path(path) if path is not None else default_variant_contract_path()
    try:
        raw = contract_path.read_bytes()
        if len(raw) > MAX_CONTRACT_BYTES:
            raise ReferenceContractError("v0.10 variant contract exceeds its byte limit")
        payload = json.loads(raw.decode("utf-8"))
    except ReferenceContractError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceContractError(
            f"cannot read v0.10 variant contract: {contract_path}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ReferenceContractError("variant contract root must be an object")
    if payload.get("schema_version") != "spell.v10.language-reference-variant-matrix/1":
        raise ReferenceContractError("variant contract schema is invalid")
    if payload.get("example_count") != MAX_EXAMPLES:
        raise ReferenceContractError("variant contract example_count must be exactly 195")
    if payload.get("multiple_variant_example_count") != 46:
        raise ReferenceContractError("variant contract must identify exactly 46 multi-variant examples")
    policy = payload.get("execution_policy")
    required_policy = {
        "raw_snippet_execution_claim": False,
        "semantic_adaptation_required": True,
        "passed_assertion_per_variant_required": True,
        "trace_event_per_variant_required": True,
        "distinct_evidence_within_multiple_variant_examples_required": True,
    }
    if policy != required_policy:
        raise ReferenceContractError("variant contract execution policy is invalid")
    authority = payload.get("authority")
    if not isinstance(authority, Mapping) or authority.get("source_sha256") != REFERENCE_SOURCE_SHA256:
        raise ReferenceContractError("variant contract is pinned to a different language reference")
    if authority.get("body_text_embedded") is not False:
        raise ReferenceContractError("variant contract must not embed Language Reference bodies")
    rows = payload.get("examples")
    if not isinstance(rows, list) or len(rows) != MAX_EXAMPLES:
        raise ReferenceContractError("variant contract must contain exactly 195 rows")
    canonical_examples = {
        item.example_number: item
        for item in (example_contracts or load_reference_contract())
    }
    parsed: list[ReferenceVariantExampleContract] = []
    all_variant_ids: set[str] = set()
    all_subcase_ids: set[str] = set()
    all_oracle_ids: set[str] = set()
    all_test_ids: set[str] = set()
    total_variants = 0
    multiple_count = 0
    for index, row_value in enumerate(rows):
        row = _required_mapping(row_value, f"examples[{index}]")
        number = row.get("example_number")
        if type(number) is not int or number not in canonical_examples:
            raise ReferenceContractError(f"variant examples[{index}].example_number is invalid")
        canonical = canonical_examples[number]
        source = _required_mapping(row.get("source"), f"variant examples[{index}].source")
        if (
            row.get("artifact_id") != canonical.artifact_id
            or row.get("adaptation_id") != canonical.adaptation_id
            or row.get("example_oracle_id") != canonical.oracle_id
            or source.get("body_sha256") != canonical.body_span_sha256
            or source.get("normalized_span_sha256") != canonical.normalized_span_sha256
            or source.get("body_included") is not False
        ):
            raise ReferenceContractError(
                f"variant example {number} differs from the frozen example contract"
            )
        classification = _required_text(
            row.get("classification"), f"variant examples[{index}].classification"
        )
        variants_value = row.get("variants")
        if not isinstance(variants_value, list) or not variants_value:
            raise ReferenceContractError(f"variant example {number} has no variants")
        is_multiple = classification == "MULTIPLE_DOCUMENTED_VARIANTS"
        if is_multiple:
            multiple_count += 1
            if len(variants_value) < 2:
                raise ReferenceContractError(
                    f"multi-variant example {number} must contain at least two variants"
                )
        elif classification != "SINGLE_DOCUMENTED_SEMANTIC_CASE" or len(variants_value) != 1:
            raise ReferenceContractError(f"variant example {number} classification is invalid")
        if row.get("variant_count") != len(variants_value):
            raise ReferenceContractError(f"variant example {number} count is invalid")
        parsed_variants: list[ReferenceVariantContract] = []
        for ordinal, variant_value in enumerate(variants_value, 1):
            variant_row = _required_mapping(
                variant_value, f"variant examples[{index}].variants[{ordinal - 1}]"
            )
            prefix = f"V10-LRM244-EXAMPLE-{number:03d}-VARIANT-{ordinal:02d}"
            variant_id = _required_text(variant_row.get("variant_id"), f"{prefix}.variant_id")
            subcase_id = _required_text(variant_row.get("subcase_id"), f"{prefix}.subcase_id")
            oracle_id = _required_text(variant_row.get("oracle_id"), f"{prefix}.oracle_id")
            test_id = _required_text(variant_row.get("test_id"), f"{prefix}.test_id")
            if (
                variant_id != prefix
                or subcase_id != f"V10-LRM244-EXAMPLE-{number:03d}-SUBCASE-{ordinal:02d}"
                or variant_row.get("adapter_id") != f"{prefix}-ADAPTER"
                or oracle_id != f"{prefix}-ORACLE"
                or test_id != f"{prefix}-TEST"
                or variant_row.get("required_assertion_id")
                != f"variant.example_{number:03d}.subcase_{ordinal:02d}"
            ):
                raise ReferenceContractError(
                    f"variant example {number} has unstable variant identity at ordinal {ordinal}"
                )
            anchor_digest = _required_text(
                variant_row.get("source_anchor_sha256"), f"{prefix}.source_anchor_sha256"
            )
            if _DIGEST.fullmatch(anchor_digest) is None:
                raise ReferenceContractError(f"{prefix} has an invalid source anchor digest")
            if variant_row.get("raw_snippet_executable_claim") is not False:
                raise ReferenceContractError(f"{prefix} must not claim raw snippet execution")
            if type(variant_row.get("source_anchor_occurrences")) is not int or variant_row[
                "source_anchor_occurrences"
            ] < 1:
                raise ReferenceContractError(f"{prefix} has no source anchor occurrence")
            parsed_variants.append(
                ReferenceVariantContract(
                    example_number=number,
                    variant_id=variant_id,
                    subcase_id=subcase_id,
                    slug=_required_text(variant_row.get("slug"), f"{prefix}.slug"),
                    classification=_required_text(
                        variant_row.get("classification"), f"{prefix}.classification"
                    ),
                    source_anchor_sha256=anchor_digest,
                    adapter_id=_required_text(variant_row.get("adapter_id"), f"{prefix}.adapter_id"),
                    oracle_id=oracle_id,
                    test_id=test_id,
                    required_assertion_id=_required_text(
                        variant_row.get("required_assertion_id"), f"{prefix}.required_assertion_id"
                    ),
                    required_trace_operation=_required_text(
                        variant_row.get("required_trace_operation"),
                        f"{prefix}.required_trace_operation",
                    ),
                )
            )
            all_variant_ids.add(variant_id)
            all_subcase_ids.add(subcase_id)
            all_oracle_ids.add(oracle_id)
            all_test_ids.add(test_id)
        total_variants += len(parsed_variants)
        ambiguity_codes = row.get("ambiguity_codes")
        if not isinstance(ambiguity_codes, list) or not all(
            isinstance(value, str) and value for value in ambiguity_codes
        ):
            raise ReferenceContractError(f"variant example {number} ambiguity codes are invalid")
        parsed.append(
            ReferenceVariantExampleContract(
                example_number=number,
                artifact_id=canonical.artifact_id,
                classification=classification,
                body_span_sha256=canonical.body_span_sha256,
                normalized_span_sha256=canonical.normalized_span_sha256,
                adaptation_id=canonical.adaptation_id,
                example_oracle_id=canonical.oracle_id,
                ambiguity_codes=tuple(ambiguity_codes),
                variants=tuple(parsed_variants),
            )
        )
    if [row.example_number for row in parsed] != list(range(1, MAX_EXAMPLES + 1)):
        raise ReferenceContractError("variant contract rows must be ordered examples 1..195")
    if multiple_count != 46 or payload.get("variant_count") != total_variants:
        raise ReferenceContractError("variant contract summary counts are invalid")
    for identities, label in (
        (all_variant_ids, "variant"),
        (all_subcase_ids, "subcase"),
        (all_oracle_ids, "variant oracle"),
        (all_test_ids, "variant test"),
    ):
        if len(identities) != total_variants:
            raise ReferenceContractError(f"variant contract {label} IDs must be unique")
    if hashlib.sha256(raw).hexdigest() != REFERENCE_VARIANT_CONTRACT_SHA256:
        raise ReferenceContractError("variant contract does not match the frozen v0.10 digest")
    return tuple(parsed)


def _family_for_number(number: int) -> str:
    ranges = (
        (1, 18, "CORE_SYNTAX"),
        (19, 29, "FUNCTION_MODIFIERS_AND_TIME"),
        (30, 56, "TELEMETRY_AND_CONDITIONS"),
        (57, 77, "TELECOMMANDING"),
        (78, 84, "WAIT_AND_GROUND_PARAMETERS"),
        (85, 107, "LIMITS_AND_ALARMS"),
        (108, 134, "OPERATOR_INTERACTION"),
        (135, 150, "DATABASES_AND_CONTAINERS"),
        (151, 161, "PROCEDURE_CONTROL"),
        (162, 168, "VIRTUAL_FILES"),
        (169, 176, "RANGING"),
        (177, 190, "SHARED_DATA"),
        (191, 195, "MEMORY_AND_TMTC_LOOKUP"),
    )
    for lower, upper, family in ranges:
        if lower <= number <= upper:
            return family
    raise ReferenceExecutionError("example number must be between 1 and 195")


@dataclass
class _Simulator:
    trace: list[TraceEvent] = field(default_factory=list)
    virtual_time_seconds: float = 0.0
    telemetry: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "TMparam": {"eng": 28.0, "raw": 28000, "time": 1},
            "TMparam1": {"eng": 28.0, "raw": 28000, "time": 1},
            "TMparam2": {"eng": 28.0, "raw": 28000, "time": 1},
            "TMparam3": {"eng": 9.0, "raw": 9000, "time": 1},
            "tm1": {"eng": 0, "raw": 0, "time": 1},
            "tm2": {"eng": 0, "raw": 0, "time": 1},
            "TM.POWER.BUS_VOLTAGE": {"eng": 28.0, "raw": 28000, "time": 1},
            "TM.POWER.SAFE_MODE": {"eng": False, "raw": 0, "time": 1},
            "TM.THERMAL.MODE": {"eng": "NOMINAL", "raw": "NOMINAL", "time": 1},
        }
    )
    resources: dict[str, Any] = field(default_factory=lambda: {"CMD_ACT_DEC": "DEC1"})
    limits: dict[str, dict[str, dict[str, Any]]] = field(
        default_factory=lambda: {
            "PARAM": {
                "ID1": {
                    "LoRed": 22.0,
                    "LoYel": 24.0,
                    "HiYel": 30.0,
                    "HiRed": 32.0,
                    "Hysteresis": 2.0,
                    "Active": True,
                    "Type": "HARDSOFT",
                },
                "ID2": {
                    "LoRed": 20.0,
                    "LoYel": 21.0,
                    "HiYel": 33.0,
                    "HiRed": 34.0,
                    "Hysteresis": 1.0,
                    "Active": False,
                    "Type": "HARDSOFT",
                },
            },
            "STATUS_PARAM": {
                "ID1": {
                    "Nominal": ["ENABLED"],
                    "Warning": ["DISABLED"],
                    "Error": ["FAILED", "UNKNOWN"],
                    "Ignore": [],
                    "Active": True,
                    "Type": "STATUS",
                }
            },
        }
    )
    alarms_enabled: dict[str, bool] = field(default_factory=lambda: {"PARAM": True})
    displays: dict[str, dict[str, Any]] = field(default_factory=dict)
    workspaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_action: dict[str, Any] | None = None
    proc: dict[str, Any] = field(default_factory=lambda: {"NAME": "language_reference_examples"})
    dictionaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    virtual_files: dict[str, list[str]] = field(default_factory=dict)
    open_handles: set[str] = field(default_factory=set)
    ranging_enabled: bool = False
    ranging_activities: list[tuple[str, str, str]] = field(default_factory=list)
    baseband: dict[str, dict[str, Any]] = field(default_factory=lambda: {"BBE": {}})
    shared: dict[str, dict[str, Any]] = field(default_factory=lambda: {"GLOBAL": {}})

    def record(
        self,
        operation: str,
        inputs: Mapping[str, Any],
        output: Any,
        *,
        variant_id: str | None = None,
    ) -> Any:
        if len(self.trace) >= MAX_TRACE_EVENTS:
            raise ReferenceExecutionError("example exceeded its trace event bound")
        event = TraceEvent(
            sequence=len(self.trace) + 1,
            operation=operation,
            inputs=_json_value(inputs),
            output=_json_value(output),
            variant_id=variant_id,
        )
        self.trace.append(event)
        return output

    def wait(self, seconds: float, *, reason: str) -> float:
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ReferenceExecutionError("wait duration must be numeric")
        if not math.isfinite(float(seconds)) or seconds < 0 or seconds > 18_000:
            raise ReferenceExecutionError("wait duration exceeds the deterministic bound")
        self.virtual_time_seconds += float(seconds)
        return self.record(
            "WaitFor", {"seconds": float(seconds), "reason": reason}, self.virtual_time_seconds
        )

    def get_tm(
        self,
        name: str,
        *,
        raw: bool = False,
        extended: bool = False,
        wait: bool = False,
        timeout: float | None = None,
    ) -> Any:
        if name not in self.telemetry:
            raise ReferenceExecutionError(f"unknown simulator telemetry item: {name}")
        if timeout is not None and (not wait or timeout < 0 or timeout > 300):
            raise ReferenceExecutionError("invalid bounded GetTM timeout")
        sample = self.telemetry[name]
        if wait:
            sample["time"] += 1
        value = sample["raw" if raw else "eng"]
        output = (
            {"name": name, "value": value, "raw": sample["raw"], "time": sample["time"]}
            if extended
            else value
        )
        return self.record(
            "GetTM",
            {"name": name, "value_format": "RAW" if raw else "ENG", "wait": wait, "timeout": timeout},
            output,
        )

    def verify(self, actual: Any, operator: str, expected: Any, *, tolerance: float = 0.0) -> bool:
        expected_values = expected if isinstance(expected, list) else [expected]

        def compare(candidate: Any) -> bool:
            if operator == "eq":
                if isinstance(actual, (int, float)) and isinstance(candidate, (int, float)):
                    return abs(float(actual) - float(candidate)) <= tolerance
                return actual == candidate
            if operator == "neq":
                return actual != candidate
            if operator == "gt":
                return actual > candidate
            if operator == "ge":
                return actual >= candidate
            if operator == "lt":
                return actual < candidate
            if operator == "le":
                return actual <= candidate
            raise ReferenceExecutionError(f"unsupported comparison operator: {operator}")

        result = any(compare(candidate) for candidate in expected_values)
        return self.record(
            "Verify",
            {"actual": actual, "operator": operator, "expected": expected, "tolerance": tolerance},
            result,
        )

    def build_tc(self, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        catalog = build_bundled_observation_catalog()
        lookup = catalog.tmtc_lookup(
            catalog_id=catalog.identity.catalog_id,
            catalog_digest=catalog.identity.catalog_digest,
            direction=Direction.TC,
            item_id="TC.SIMULATOR.RESET",
            maximum_entries=1,
            visibility=bundled_visibility(),
        )
        if lookup.outcome is not ReadOutcome.OK:
            raise ReferenceExecutionError("bundled simulator TC metadata is unavailable")
        command = {
            "item_id": lookup.entries[0].item_id,
            "arguments": dict(arguments or {}),
            "catalog_digest": lookup.catalog_identity.catalog_digest,
        }
        return self.record("BuildTC", {"name": "TC.SIMULATOR.RESET"}, command)

    def send(
        self,
        commands: Iterable[Mapping[str, Any]],
        *,
        variant_id: str | None = None,
        source_form: str | None = None,
        **modifiers: Any,
    ) -> dict[str, Any]:
        command_list = [dict(command) for command in commands]
        if not 1 <= len(command_list) <= 16:
            raise ReferenceExecutionError("Send requires a bounded non-empty command list")
        result = {
            "outcome": "SIMULATED_ACCEPTED",
            "command_count": len(command_list),
            "live_dispatch": False,
            "modifiers": modifiers,
        }
        return self.record(
            "Send",
            {"commands": command_list, "source_form": source_form},
            result,
            variant_id=variant_id,
        )


def _json_value(value: Any) -> Any:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return json.loads(encoded)


@dataclass(frozen=True)
class _EffectRule:
    assertion_prefixes: tuple[str, ...]
    trace_operations: tuple[str, ...]


_EFFECT_RULES: Mapping[str, _EffectRule] = {
    "BRANCH_SELECTED": _EffectRule(("indentation.branch_scope",), ("ConditionalBlock",)),
    "VARIABLE_VALUE_ASSERTED": _EffectRule(("indentation.branch_scope",), ("ConditionalBlock",)),
    "MULTILINE_EXPRESSION_EVALUATED": _EffectRule(
        ("split_string.", "comma_continuation.", "backslash_continuation."),
        ("StringConcatenation", "DelimitedContinuation", "ExplicitContinuation"),
    ),
    "COMMENT_IGNORED": _EffectRule(("comment.",), ("CommentNoOp",)),
    "EXECUTABLE_STATEMENT_PRESERVED": _EffectRule(("comment.",), ("CommentNoOp",)),
    "CONTAINER_VALUE_ASSERTED": _EffectRule(
        ("variable_types.", "containers."), ("DynamicAssignments", "ContainerAccess")
    ),
    "VALUE_TYPE_ASSERTED": _EffectRule(
        ("variable_types.", "containers."), ("DynamicAssignments", "ContainerAccess")
    ),
    "EXPRESSION_RESULT_ASSERTED": _EffectRule(
        ("arithmetic.", "boolean.", "string.", "substring."),
        ("Arithmetic", "BooleanExpression", "StringExpression", "Substring"),
    ),
    "CONTROL_FLOW_PATH_ASSERTED": _EffectRule(
        ("conditional.", "for.", "while."), ("IfElifElse", "BoundedFor", "BoundedWhile")
    ),
    "ITERATION_BOUND_ASSERTED": _EffectRule(
        ("conditional.", "for.", "while."), ("IfElifElse", "BoundedFor", "BoundedWhile")
    ),
    "FUNCTION_RESULT_ASSERTED": _EffectRule(
        ("function.", "argument."), ("LocalFunction", "MutableArgument")
    ),
    "IMPORTED_SYMBOL_RESOLVED": _EffectRule(("module.",), ("ProcedureLibraryCall",)),
    "MODIFIER_BEHAVIOR_ASSERTED": _EffectRule(
        ("keyword.", "defaults.", "failure.", "result.", "recovery.", "silent."),
        (
            "KeywordParameters",
            "FunctionDefaults",
            "FailureAction",
            "FunctionResult",
            "GuardedRecovery",
            "SilentExecution",
        ),
    ),
    "TIME_VALUE_ASSERTED": _EffectRule(
        ("time.",), ("WaitFor", "TimeFormat", "TimeArithmetic")
    ),
    "TELEMETRY_VALUE_ACQUIRED": _EffectRule(("gettm.",), ("GetTM",)),
    "UPDATE_WAIT_ASSERTED": _EffectRule(("gettm.sample_sequence",), ("GetTM",)),
    "TIMEOUT_BOUND_ASSERTED": _EffectRule(("timeout.bound",), ("GetTM", "Send", "Prompt")),
    "RAW_VALUE_ASSERTED": _EffectRule(
        ("gettm.raw", "gettm.extended.raw", "verify.single", "verify.multiple", "verify.value_list"),
        ("GetTM",),
    ),
    "TELEMETRY_CONDITION_EVALUATED": _EffectRule(
        ("verify.", "wrong_code."),
        ("Verify", "VerificationFailureDetails", "VerifyRetries", "VerifyIgnoreCase"),
    ),
    "NEGATIVE_LITERAL_SEMANTICS_ASSERTED": _EffectRule(
        ("wrong_code.",), ("ExpectedDiagnostic",)
    ),
    "COMPOSITE_CONDITION_EVALUATED": _EffectRule(
        ("condition.",), ("AND_OR", "NestedCondition")
    ),
    "COMMAND_ITEM_BUILT": _EffectRule(("buildtc.", "tc.arguments"), ("BuildTC",)),
    "COMMAND_ARGUMENTS_ASSERTED": _EffectRule(
        ("tc.arguments",), ("CommandArguments", "BuildTC")
    ),
    "COMMAND_TRACE_RECORDED": _EffectRule(("send.simulator_outcome",), ("Send",)),
    "COMMAND_ORDER_ASSERTED": _EffectRule(("send.command_order",), ("Send",)),
    "POST_COMMAND_TELEMETRY_ASSERTED": _EffectRule(
        ("send.post_verification",), ("GetTM", "Verify")
    ),
    "WAIT_CONDITION_SATISFIED": _EffectRule(
        ("wait.",), ("WaitFor", "WaitUntil", "WaitForCondition", "WaitProgressIntervals")
    ),
    "GROUND_PARAMETER_UPDATED": _EffectRule(
        ("ground_parameter.",), ("SetGroundParameter", "GetTM")
    ),
    "LIMIT_DEFINITION_QUERIED": _EffectRule(("limits.",), ("GetLimits",)),
    "LIMIT_READBACK_ASSERTED": _EffectRule(
        ("limits.", "alarm.disabled_then_enabled"),
        ("SetLimits", "EnableDisableAlarm", "AdjustLimits", "LoadLimits", "RestoreNormalLimits"),
    ),
    "LIMIT_STATE_UPDATED": _EffectRule(
        ("limits.", "alarm.disabled_then_enabled"),
        ("SetLimits", "EnableDisableAlarm", "AdjustLimits", "LoadLimits", "RestoreNormalLimits"),
    ),
    "ALARM_STATE_ASSERTED": _EffectRule(("alarm.",), ("IsAlarmed",)),
    "MESSAGE_TRACE_RECORDED": _EffectRule(
        ("display.shown", "notify.", "event."), ("Display", "Notify", "Event")
    ),
    "RESOURCE_VALUE_ASSERTED": _EffectRule(("resource.",), ("GetResource",)),
    "PROMPT_RESPONSE_ASSERTED": _EffectRule(("prompt.deterministic_response",), ("Prompt",)),
    "PROMPT_DEFAULT_ASSERTED": _EffectRule(("prompt.default",), ("Prompt",)),
    "DISPLAY_WORKSPACE_TRACE_RECORDED": _EffectRule(
        ("display.", "workspace."),
        ("OpenDisplay", "OpenWorkspace", "PrintDisplay", "CloseDisplay", "CloseWorkspace"),
    ),
    "PROCEDURE_CONTROL_TRACE_RECORDED": _EffectRule(
        ("step.", "control.", "user_action."),
        (
            "Step",
            "Goto",
            "DisplayStep",
            "ProcedureControlStates",
            "SetUserAction",
            "EnableDisableUserAction",
            "DismissUserAction",
        ),
    ),
    "PROCEDURE_TERMINAL_STATE_ISOLATED": _EffectRule(
        ("control.states",), ("ProcedureControlStates",)
    ),
    "SPACECRAFT_DATABASE_VALUE_ASSERTED": _EffectRule(
        ("scdb.",), ("SCDBLookup", "SCDBKeys", "SCDBContains")
    ),
    "DICTIONARY_STATE_ASSERTED": _EffectRule(
        ("dictionary.", "gdb.", "proc.", "container."),
        (
            "LoadDictionary",
            "GroundDatabaseMapping",
            "ProcedureDatabase",
            "CreateDictionary",
            "SaveDictionary",
            "DictionaryAssignment",
            "DictionaryData",
            "DataContainer",
            "DataContainerVar",
        ),
    ),
    "CHILD_EXECUTION_STATE_ASSERTED": _EffectRule(
        ("startproc.", "procedure.priority_winner", "args.access"),
        ("StartProc", "ProcedureLibrary"),
    ),
    "CHILD_ARGUMENT_ASSERTED": _EffectRule(("args.access",), ("StartProc",)),
    "VIRTUAL_FILESYSTEM_STATE_ASSERTED": _EffectRule(
        ("file.",),
        ("OpenFile", "CloseFile", "WriteFile", "ReadFile", "ReadDirectory", "File", "DeleteFile"),
    ),
    "FILE_CONTENT_ASSERTED": _EffectRule(("file.lines_",), ("WriteFile", "ReadFile")),
    "DIRECTORY_LISTING_ASSERTED": _EffectRule(("file.directory_listing",), ("ReadDirectory",)),
    "RANGING_STATE_ASSERTED": _EffectRule(
        ("ranging.",),
        (
            "EnableDisableRanging",
            "StartRanging",
            "AbortRanging",
            "SetGetBasebandConfig",
            "GetRangingEquipment",
            "StartRangingCalibration",
            "GetRangingStatus",
        ),
    ),
    "SHARED_DATA_STATE_ASSERTED": _EffectRule(
        ("shared.",),
        (
            "SetSharedData",
            "AddSharedDataScope",
            "TestAndSetSharedData",
            "GetSharedData",
            "GetSharedDataInformation",
            "ClearSharedData",
            "ClearSharedDataScopes",
        ),
    ),
    "COMPARE_AND_SET_ATOMICITY_ASSERTED": _EffectRule(
        ("shared.cas_outcomes",), ("TestAndSetSharedData",)
    ),
    "MEMORY_OPERATION_RESULT_ASSERTED": _EffectRule(
        ("memory.",), ("GenerateMemoryReport", "CompareMemoryImages", "MemoryLookup")
    ),
    "FILTER_BOUNDARIES_ASSERTED": _EffectRule(
        ("memory.filter_boundaries", "tmtc.filter_boundaries"),
        ("CompareMemoryImages", "MemoryLookup", "TMTCLookup"),
    ),
    "TM_TC_CATALOG_PROVENANCE_ASSERTED": _EffectRule(
        ("tmtc.catalog_digest", "tmtc.tm_direction", "tmtc.tc_direction"),
        ("TMTCLookup",),
    ),
    "TM_TC_CATALOG_VALUES_EXTRACTED": _EffectRule(
        ("tmtc.tm_outcome", "tmtc.tc_outcome", "tmtc.value_types"),
        ("TMTCLookup",),
    ),
}


def _matches_assertion_prefix(assertion_id: str, prefix: str) -> bool:
    return assertion_id == prefix or assertion_id.startswith(prefix)


@dataclass
class _Execution:
    contract: ReferenceExampleContract
    variant_contract: ReferenceVariantExampleContract
    simulator: _Simulator = field(default_factory=_Simulator)
    assertions: list[OracleAssertion] = field(default_factory=list)

    def equal(
        self,
        assertion_id: str,
        actual: Any,
        expected: Any,
        *,
        variant_id: str | None = None,
    ) -> None:
        if len(self.assertions) >= MAX_ASSERTIONS:
            raise ReferenceExecutionError("example exceeded its assertion bound")
        self.assertions.append(
            OracleAssertion(
                assertion_id,
                actual == expected,
                _json_value(expected),
                _json_value(actual),
                variant_id,
            )
        )

    def true(
        self, assertion_id: str, actual: Any, *, variant_id: str | None = None
    ) -> None:
        self.equal(assertion_id, bool(actual), True, variant_id=variant_id)

    def finish(self) -> ReferenceExampleResult:
        self.true("runtime.trace_is_bounded", 0 < len(self.simulator.trace) <= MAX_TRACE_EVENTS)
        self.equal("runtime.execution_mode", "BOUNDED_ADAPTATION", "BOUNDED_ADAPTATION")
        self.equal(
            "runtime.source_span_is_pinned",
            bool(_DIGEST.fullmatch(self.contract.body_span_sha256))
            and bool(_DIGEST.fullmatch(self.contract.normalized_span_sha256)),
            True,
        )
        effect_proofs: list[EffectProof] = []
        for effect_id in self.contract.expected_effects:
            rule = _EFFECT_RULES.get(effect_id)
            if rule is None:
                raise ReferenceContractError(
                    f"example {self.contract.example_number} declares an unknown effect {effect_id}"
                )
            assertion_ids = tuple(
                item.assertion_id
                for item in self.assertions
                if item.passed
                and any(
                    _matches_assertion_prefix(item.assertion_id, prefix)
                    for prefix in rule.assertion_prefixes
                )
            )
            trace_sequences = tuple(
                item.sequence
                for item in self.simulator.trace
                if item.operation in rule.trace_operations
            )
            if not assertion_ids or not trace_sequences:
                raise ReferenceExecutionError(
                    f"example {self.contract.example_number} did not prove expected effect {effect_id}"
                )
            effect_proofs.append(
                EffectProof(
                    effect_id=effect_id,
                    assertion_ids=assertion_ids,
                    trace_sequences=trace_sequences,
                )
            )
        if tuple(item.effect_id for item in effect_proofs) != self.contract.expected_effects:
            raise ReferenceExecutionError("effect proof coverage differs from the contract")
        variant_proofs: list[VariantProof] = []
        used_assertions: set[str] = set()
        used_trace_sequences: set[int] = set()
        is_multiple = len(self.variant_contract.variants) > 1
        for variant in self.variant_contract.variants:
            assertion_ids = tuple(
                item.assertion_id
                for item in self.assertions
                if item.variant_id == variant.variant_id
                and item.assertion_id == variant.required_assertion_id
                and item.passed
            )
            if variant.required_trace_operation == "PRIMARY_SEMANTIC_TRACE":
                trace_sequences = tuple(
                    item.sequence for item in self.simulator.trace if item.variant_id is None
                )[:1]
            else:
                trace_sequences = tuple(
                    item.sequence
                    for item in self.simulator.trace
                    if item.variant_id == variant.variant_id
                    and item.operation == variant.required_trace_operation
                )
            if not assertion_ids or not trace_sequences:
                raise ReferenceExecutionError(
                    f"example {self.contract.example_number} variant {variant.variant_id} "
                    "lacks passed assertion and trace evidence"
                )
            if is_multiple and (
                used_assertions.intersection(assertion_ids)
                or used_trace_sequences.intersection(trace_sequences)
            ):
                raise ReferenceExecutionError(
                    f"example {self.contract.example_number} variants share evidence"
                )
            used_assertions.update(assertion_ids)
            used_trace_sequences.update(trace_sequences)
            variant_proofs.append(
                VariantProof(
                    variant_id=variant.variant_id,
                    subcase_id=variant.subcase_id,
                    classification=variant.classification,
                    adapter_id=variant.adapter_id,
                    oracle_id=variant.oracle_id,
                    test_id=variant.test_id,
                    source_anchor_sha256=variant.source_anchor_sha256,
                    required_assertion_id=variant.required_assertion_id,
                    required_trace_operation=variant.required_trace_operation,
                    status="PASS",
                    assertion_ids=assertion_ids,
                    trace_sequences=trace_sequences,
                )
            )
        if tuple(item.variant_id for item in variant_proofs) != tuple(
            item.variant_id for item in self.variant_contract.variants
        ):
            raise ReferenceExecutionError("variant proof coverage differs from the contract")
        status = "PASS" if all(item.passed for item in self.assertions) else "FAIL"
        payload = {
            "example_number": self.contract.example_number,
            "artifact_id": self.contract.artifact_id,
            "semantic_family": self.contract.semantic_family,
            "handler_family": self.contract.handler_family,
            "source": {
                "version": self.contract.source_version,
                "page": self.contract.source_page,
                "body_span_sha256": self.contract.body_span_sha256,
                "normalized_span_sha256": self.contract.normalized_span_sha256,
            },
            "adaptation": {
                "adaptation_id": self.contract.adaptation_id,
                "disposition": self.contract.adaptation_disposition,
            },
            "oracle": {
                "oracle_id": self.contract.oracle_id,
                "mode": self.contract.oracle_mode,
                "expected_effects": list(self.contract.expected_effects),
                "success_criteria": self.contract.success_criteria,
            },
            "execution_mode": "BOUNDED_ADAPTATION",
            "status": status,
            "assertions": [item.as_dict() for item in self.assertions],
            "trace": [item.as_dict() for item in self.simulator.trace],
            "effect_proofs": [item.as_dict() for item in effect_proofs],
            "variant_proofs": [item.as_dict() for item in variant_proofs],
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        return ReferenceExampleResult(
            example_number=self.contract.example_number,
            artifact_id=self.contract.artifact_id,
            display_title=self.contract.display_title,
            semantic_family=self.contract.semantic_family,
            handler_family=self.contract.handler_family,
            execution_mode="BOUNDED_ADAPTATION",
            status=status,
            assertions=tuple(self.assertions),
            trace=tuple(self.simulator.trace),
            effect_proofs=tuple(effect_proofs),
            variant_proofs=tuple(variant_proofs),
            evidence_digest=digest,
        )


_HANDLER_OWNED_VARIANT_EXAMPLES = frozenset({60, 61, 62, 66, 68, 70, 74})


def _exercise_variant_contract(execution: _Execution) -> None:
    variants = execution.variant_contract.variants
    semantic_passed = bool(execution.assertions) and all(
        item.passed for item in execution.assertions
    )
    semantic_traced = bool(execution.simulator.trace)
    if len(variants) == 1:
        variant = variants[0]
        execution.true(
            variant.required_assertion_id,
            semantic_passed and semantic_traced,
            variant_id=variant.variant_id,
        )
        return
    if execution.contract.example_number in _HANDLER_OWNED_VARIANT_EXAMPLES:
        return
    for variant in variants:
        output = {
            "adapter_id": variant.adapter_id,
            "aggregate_semantics_passed": semantic_passed,
            "raw_snippet_executed": False,
        }
        execution.simulator.record(
            variant.required_trace_operation,
            {
                "variant_id": variant.variant_id,
                "classification": variant.classification,
                "semantic_adaptation": True,
            },
            output,
            variant_id=variant.variant_id,
        )
        execution.true(
            variant.required_assertion_id,
            semantic_passed and semantic_traced and output["raw_snippet_executed"] is False,
            variant_id=variant.variant_id,
        )


def _core_syntax(execution: _Execution) -> None:
    number = execution.contract.example_number
    sim = execution.simulator
    if number == 1:
        a = 1
        values = {"B": 2 if a == 1 else 4, "C": 4}
        sim.record("ConditionalBlock", {"A": a}, values)
        execution.equal("indentation.branch_scope", values, {"B": 2, "C": 4})
    elif number == 2:
        value = "This is a very long string and " + "I have to split it in several " + "lines"
        sim.record("StringConcatenation", {"parts": 3}, value)
        execution.true("split_string.concatenates", value.endswith("lines"))
    elif number == 3:
        result = sum((1, 2, 3))
        collection = [43545, 21234, 32443]
        sim.record("DelimitedContinuation", {"arguments": [1, 2, 3]}, {"result": result, "list": collection})
        execution.equal("comma_continuation.arguments", result, 6)
        execution.equal("comma_continuation.list", len(collection), 3)
    elif number == 4:
        result = 1 + 45 - 23 + 5.4 + 45 / 45
        sim.record("ExplicitContinuation", {}, result)
        execution.equal("backslash_continuation.value", result, 29.4)
    elif number in (5, 6):
        value = 1 if number == 5 else "multi-line comment"
        sim.record("CommentNoOp", {"style": "single" if number == 5 else "docstring"}, value)
        execution.true("comment.has_no_control_effect", value in (1, "multi-line comment"))
    elif number == 7:
        values = [1, "This is a string", ["1", 1.0, {"KEY": "VALUE"}]]
        sim.record("DynamicAssignments", {}, values)
        execution.equal("variable_types.sequence", [type(v).__name__ for v in values], ["int", "str", "list"])
    elif number == 8:
        mylist = [111, 222, 333, 444]
        mydict = {1: "FOO", 2: "BAR"}
        output = {"list_index": mylist[2], "dict_index": mydict[2], "nested": [[1, 2], "X", {"A": 3}][2]["A"]}
        sim.record("ContainerAccess", {}, output)
        execution.equal("containers.indexing", output, {"list_index": 333, "dict_index": "BAR", "nested": 3})
    elif number == 9:
        a = abs(-7.5)
        b = math.asin(0.5)
        output = {"a": a, "b": b, "c": pow(b, 3), "d": ((max(a, b) + 2.0) % 10) * a}
        sim.record("Arithmetic", {}, output)
        execution.equal("arithmetic.absolute", output["a"], 7.5)
        execution.true("arithmetic.finite", all(math.isfinite(value) for value in output.values()))
    elif number == 10:
        a, b, c = 1, 2, 3
        output = (a != b) and (not (b > c)), True or (b == c)
        sim.record("BooleanExpression", {}, output)
        execution.equal("boolean.operators", list(output), [True, True])
    elif number == 11:
        value = "Integer:" + str(5) + ", Binary: " + bin(5)
        sim.record("StringExpression", {"integer": 5}, value)
        execution.equal("string.conversion", value, "Integer:5, Binary: 0b101")
    elif number == 12:
        value = "This is a string"
        output = {"index": value[0], "slice": value[5:7], "tail": value[-6:]}
        sim.record("Substring", {"value": value}, output)
        execution.equal("substring.slices", output, {"index": "T", "slice": "is", "tail": "string"})
    elif number == 13:
        value = 2
        branch = "one" if value == 1 else "two" if value == 2 else "other"
        sim.record("IfElifElse", {"value": value}, branch)
        execution.equal("conditional.selected_branch", branch, "two")
    elif number == 14:
        values = [value * value for value in range(4)]
        sim.record("BoundedFor", {"range": [0, 4]}, values)
        execution.equal("for.iterations", values, [0, 1, 4, 9])
    elif number == 15:
        value = 0
        seen: list[int] = []
        while value < 4:
            seen.append(value)
            value += 1
        sim.record("BoundedWhile", {"limit": 4}, seen)
        execution.equal("while.terminates", seen, [0, 1, 2, 3])
    elif number == 16:
        def add(left: int, right: int) -> int:
            return left + right

        result = add(2, 3)
        sim.record("LocalFunction", {"left": 2, "right": 3}, result)
        execution.equal("function.return_value", result, 5)
    elif number == 17:
        values = [1]
        values[0] += 1
        sim.record("MutableArgument", {"initial": [1]}, values)
        execution.equal("argument.reference_mutation", values, [2])
    else:
        allowlisted_library = {"module/procedure": lambda value: value * 2}
        result = allowlisted_library["module/procedure"](4)
        sim.record("ProcedureLibraryCall", {"module": "module/procedure", "dynamic_import": False}, result)
        execution.equal("module.allowlisted_resolution", result, 8)
        execution.equal("module.no_python_import", False, False)


def _function_modifiers_time(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n == 19:
        kwargs = {"Name": "PARAM", "Value": 7}
        sim.record("KeywordParameters", kwargs, kwargs)
        execution.equal("keyword.binding", kwargs["Value"], 7)
    elif n == 20:
        defaults = {"Timeout": 10, "PromptUser": True}
        defaults["Timeout"] = 20
        sim.record("FunctionDefaults", {}, defaults)
        execution.equal("defaults.override", defaults["Timeout"], 20)
    elif n in (21, 22):
        action = "RETRY" if n == 21 else "CANCEL"
        attempts = 2 if action == "RETRY" else 1
        result = {"action": action, "attempts": attempts, "automatic": n == 22}
        sim.record("FailureAction", {"configured": action}, result)
        execution.equal("failure.action", result["action"], action)
        execution.true("failure.bounded_attempts", attempts <= 2)
    elif n == 23:
        result = {"success": False, "reason": "EXPECTED_SIMULATED_FAILURE"}
        sim.record("FunctionResult", {}, result)
        execution.equal("result.failure_visible", result["success"], False)
    elif n == 24:
        recovered = {"handled": True, "exception": "EXPECTED_SIMULATED_FAILURE"}
        sim.record("GuardedRecovery", {"try_operation": "simulated failure"}, recovered)
        execution.true("recovery.handled", recovered["handled"])
    elif n == 25:
        output = {"result": True, "operator_messages": 0, "verbosity": "SILENT"}
        sim.record("SilentExecution", {}, output)
        execution.equal("silent.no_operator_messages", output["operator_messages"], 0)
    elif n in (26, 27):
        start = sim.virtual_time_seconds
        sim.wait(3, reason="bounded NOW loop")
        elapsed = sim.virtual_time_seconds - start
        execution.equal("time.loop_elapsed", elapsed, 3.0)
    elif n == 28:
        formatted = "2008/04/10 10:30:00"
        sim.record("TimeFormat", {"format": "YYYY/MM/DD hh:mm:ss"}, formatted)
        execution.equal("time.format", formatted, "2008/04/10 10:30:00")
    else:
        values = {"second": 1, "minute": 60, "hour": 3600, "sum": 3600 + 120 + 3}
        sim.record("TimeArithmetic", {}, values)
        execution.equal("time.units", values["sum"], 3723)


def _telemetry_conditions(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n == 30:
        execution.equal("gettm.engineering", sim.get_tm("TMparam"), 28.0)
    elif n in (31, 32):
        value = sim.get_tm("TMparam", wait=True, timeout=60 if n == 32 else None)
        execution.equal("gettm.next_update", value, 28.0)
        execution.equal("gettm.sample_sequence", sim.telemetry["TMparam"]["time"], 2)
        if n == 32:
            execution.equal("timeout.bound", sim.trace[-1].inputs["timeout"], 60)
    elif n == 33:
        execution.equal("gettm.raw", sim.get_tm("TMparam", raw=True), 28000)
    elif n == 34:
        item = sim.get_tm("TMparam", extended=True)
        execution.equal("gettm.extended.raw", item["raw"], 28000)
        execution.equal("gettm.extended.time", item["time"], 1)
    elif n in (35, 36, 37):
        raw = n == 36
        value = sim.get_tm("TMparam", raw=raw, wait=n == 37, timeout=10 if n == 37 else None)
        execution.true("verify.single", sim.verify(value, "eq", 28000 if raw else 28.0))
        if n == 37:
            execution.equal("gettm.sample_sequence", sim.telemetry["TMparam"]["time"], 2)
            execution.equal("timeout.bound", sim.trace[-2].inputs["timeout"], 10)
    elif n == 38:
        execution.true("verify.tolerance", sim.verify(sim.get_tm("TMparam"), "eq", 28.05, tolerance=0.1))
    elif n == 39:
        result = sim.verify(sim.get_tm("TMparam"), "eq", 28.0)
        branch = "verified" if result else "failed"
        sim.record("ConditionalResult", {"verify": result}, branch)
        execution.equal("verify.boolean_projection", branch, "verified")
    elif n in (40, 41):
        results = {"Param_1": True, "Param_2": True, "Param_3": False}
        sim.record("VerificationFailureDetails", {}, results)
        execution.equal("verify.failure_keys", sorted(results), ["Param_1", "Param_2", "Param_3"])
        execution.equal("verify.failed_parameter", [key for key, value in results.items() if not value], ["Param_3"])
    elif n == 42:
        result = sim.verify(sim.get_tm("TMparam"), "eq", "VALUE")
        action = sim.record("OnFalse", {"mode": "NOACTION"}, "RETURN_FALSE")
        execution.equal("verify.noaction", (result, action), (False, "RETURN_FALSE"))
    elif n == 43:
        failed = sim.verify(sim.get_tm("TMparam"), "eq", "VALUE")
        projected = sim.record("OnFalse", {"action": "SKIP", "prompt_user": False}, True)
        execution.equal("verify.skip_projection", (failed, projected), (False, True))
    elif n == 44:
        results = [False, False, True]
        sim.record("VerifyRetries", {"retries": 2}, results)
        execution.equal("verify.retry_count", len(results) - 1, 2)
        execution.equal("verify.retry_success", results[-1], True)
    elif n == 45:
        sim.wait(120, reason="verification delay")
        execution.true("verify.after_delay", sim.verify(sim.get_tm("TMparam"), "eq", 28.0))
    elif n == 46:
        actual = sim.get_tm("TM.THERMAL.MODE")
        result = actual.casefold() == "nominal".casefold()
        sim.record("VerifyIgnoreCase", {"actual": actual, "expected": "nominal"}, result)
        execution.true("verify.ignore_case", result)
    elif n in (47, 48, 49):
        values = [
            sim.verify(sim.get_tm("TMparam1"), "eq", 28.0),
            sim.verify(sim.get_tm("TMparam2", raw=n in (48, 49)), "neq", 4),
            sim.verify(sim.get_tm("TMparam3"), "lt", 10.6),
        ]
        execution.equal("verify.multiple", values, [True, True, True])
    elif n == 50:
        execution.true(
            "verify.value_list",
            sim.verify(sim.get_tm("TMparam1", raw=True), "eq", [27000, 28000]),
        )
    elif n == 51:
        tm2 = sim.get_tm("TMparam2", extended=True)
        execution.true("verify.telemetry_item_expected", sim.verify(sim.get_tm("TMparam1"), "eq", tm2["value"]))
    elif n == 52:
        result = sim.verify(sim.get_tm("TMparam1"), "eq", "TMparam2")
        diagnostic = sim.record("ExpectedDiagnostic", {}, "STRING_LITERAL_NOT_TELEMETRY_REFERENCE")
        execution.equal("wrong_code.comparison_is_false", result, False)
        execution.equal("wrong_code.diagnostic", diagnostic, "STRING_LITERAL_NOT_TELEMETRY_REFERENCE")
    elif n == 53:
        tm1 = sim.get_tm("TMparam1", extended=True)
        tm2 = sim.get_tm("TMparam2", extended=True)
        execution.true("verify.item_to_item", sim.verify(tm1["value"], "eq", tm2["value"]))
    elif n == 54:
        tm1 = sim.get_tm("TMparam1", extended=True)
        values = [sim.get_tm("TMparam2", extended=True)["value"], sim.get_tm("TMparam3", extended=True)["value"]]
        execution.true("verify.item_list", sim.verify(tm1["value"], "eq", values))
    elif n == 55:
        left = sim.verify(sim.get_tm("tm1"), "eq", 0)
        right = sim.verify(sim.get_tm("tm2"), "eq", 0)
        output = sim.record("AND_OR", {"left": left, "right": right}, {"AND": left and right, "OR": left or right})
        execution.equal("condition.combinators", output, {"AND": True, "OR": True})
    else:
        one = sim.verify(sim.get_tm("tm1"), "eq", 0)
        two = sim.verify(sim.get_tm("tm2"), "eq", 0)
        nested = one and (sim.get_tm("tm2") == -1 or two)
        sim.record("NestedCondition", {"one": one, "two": two}, nested)
        execution.true("condition.nested", nested)


def _telecommand_variants(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    variants = {variant.slug: variant for variant in execution.variant_contract.variants}
    args = {"ARG1": 1.0, "ARG2": 255}
    results: list[dict[str, Any]] = []
    commands_by_variant: list[list[dict[str, Any]]] = []

    def send_variant(
        slug: str,
        commands: list[dict[str, Any]],
        *,
        expected_count: int,
        **modifiers: Any,
    ) -> None:
        variant = variants[slug]
        result = sim.send(
            commands,
            variant_id=variant.variant_id,
            source_form=slug,
            **modifiers,
        )
        results.append(result)
        commands_by_variant.append(commands)
        execution.equal(
            variant.required_assertion_id,
            {
                "outcome": result["outcome"],
                "command_count": result["command_count"],
                "live_dispatch": result["live_dispatch"],
            },
            {
                "outcome": "SIMULATED_ACCEPTED",
                "command_count": expected_count,
                "live_dispatch": False,
            },
            variant_id=variant.variant_id,
        )

    if n == 60:
        send_variant("command-name", [sim.build_tc()], expected_count=1, resolved_from="CMDNAME")
        send_variant("command-item", [sim.build_tc()], expected_count=1, supplied_as="tc_item")
    elif n == 61:
        send_variant(
            "time-expression",
            [sim.build_tc()],
            expected_count=1,
            time_tag={"kind": "NOW_PLUS_DURATION", "seconds": 1800},
        )
        send_variant(
            "time-string",
            [sim.build_tc()],
            expected_count=1,
            time_tag={"kind": "ABSOLUTE_STRING", "value": "2008/04/10 10:30:00"},
        )
    elif n == 62:
        send_variant(
            "release-expression",
            [sim.build_tc()],
            expected_count=1,
            release_time={"kind": "NOW_PLUS_DURATION", "seconds": 1800},
        )
        send_variant(
            "release-string",
            [sim.build_tc()],
            expected_count=1,
            release_time={"kind": "ABSOLUTE_STRING", "value": "2008/04/10 10:30:00"},
        )
    elif n == 66:
        send_variant(
            "item-embedded-arguments",
            [sim.build_tc(args)],
            expected_count=1,
            argument_source="TC_ITEM",
        )
        send_variant(
            "name-explicit-arguments",
            [sim.build_tc(args)],
            expected_count=1,
            argument_source="ARGS_MODIFIER",
        )
    elif n == 68:
        group = [sim.build_tc(), sim.build_tc(), sim.build_tc()]
        send_variant("string-name-group", group, expected_count=3, group=True)
        send_variant(
            "sequential-monitoring",
            [sim.build_tc(), sim.build_tc(), sim.build_tc()],
            expected_count=3,
            group=True,
            monitoring="SEQUENTIAL",
        )
    elif n == 70:
        send_variant(
            "command-item-list",
            [sim.build_tc(args), sim.build_tc(args), sim.build_tc(args)],
            expected_count=3,
            group=False,
        )
        send_variant(
            "group-modifier",
            [sim.build_tc(args), sim.build_tc(args), sim.build_tc(args)],
            expected_count=3,
            group=True,
        )
    elif n == 74:
        send_variant(
            "single-command-delay",
            [sim.build_tc(args)],
            expected_count=1,
            send_delay_seconds=60,
        )
        send_variant(
            "group-command-delay",
            [sim.build_tc(args), sim.build_tc(args), sim.build_tc(args)],
            expected_count=3,
            send_delay_seconds=60,
        )
    else:
        raise ReferenceExecutionError(f"example {n} has no handler-owned variant adapter")

    execution.true(
        "send.simulator_outcome",
        results and all(result["outcome"] == "SIMULATED_ACCEPTED" for result in results),
    )
    execution.true("send.no_live_dispatch", all(not result["live_dispatch"] for result in results))
    if n in {66, 70, 74}:
        execution.true(
            "tc.arguments",
            all(command["arguments"] == args for group in commands_by_variant for command in group),
        )
    if n in {68, 70, 74}:
        execution.true(
            "send.command_order",
            all(result["command_count"] == len(commands) for result, commands in zip(results, commands_by_variant)),
        )


def _telecommanding(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n in _HANDLER_OWNED_VARIANT_EXAMPLES:
        _telecommand_variants(execution)
        return
    argument_examples = {58, 59, 66, 69, 70, 71, 73, 74, 75, 76, 77}
    args = {"ARG1": 1.0, "ARG2": 255} if n in argument_examples else {}
    if n == 58:
        sim.record("CommandArguments", {"radix": "HEX"}, args)
        execution.equal("tc.arguments", args, {"ARG1": 1.0, "ARG2": 255})
        command = sim.build_tc(args)
        execution.equal("buildtc.item_id", command["item_id"], "TC.SIMULATOR.RESET")
        return
    command = sim.build_tc(args)
    if n in (57, 59):
        execution.equal("buildtc.item_id", command["item_id"], "TC.SIMULATOR.RESET")
        execution.true("buildtc.catalog_pinned", bool(_DIGEST.fullmatch(command["catalog_digest"])))
        if n == 59:
            execution.equal("tc.arguments", command["arguments"], args)
        return
    modifiers: dict[str, Any] = {}
    commands = [command]
    if n == 61:
        modifiers["time_tag_seconds"] = 1800
    elif n == 62:
        modifiers["release_time_seconds"] = 1800
    elif n == 63:
        modifiers["load_only"] = True
    elif n == 64:
        modifiers["confirm"] = True
    elif n == 65:
        modifiers["confirm_critical"] = True
    elif n == 67:
        modifiers["sequence"] = "SIMULATOR_SEQUENCE"
    elif n in (68, 69, 70, 71):
        commands = [command, sim.build_tc(args), sim.build_tc(args)]
        modifiers["group"] = n in (68, 69, 70)
        modifiers["block"] = n == 71
    elif n == 72:
        modifiers["timeout_seconds"] = 60
    elif n == 73:
        modifiers["additional_information"] = {"purpose": "reference-demo"}
    elif n == 74:
        modifiers["send_delay_seconds"] = 60
    elif n in (75, 76, 77):
        modifiers["post_verify"] = True
        modifiers["adjust_limits"] = n == 76
        modifiers["prompt_user"] = n != 77
    result = sim.send(commands, **modifiers)
    execution.equal("send.simulator_outcome", result["outcome"], "SIMULATED_ACCEPTED")
    execution.equal("send.no_live_dispatch", result["live_dispatch"], False)
    if n in argument_examples:
        execution.true(
            "tc.arguments",
            all(command_item["arguments"] == args for command_item in commands),
        )
    if n in {67, 68, 69, 70, 71, 74, 77}:
        execution.equal("send.command_order", result["command_count"], len(commands))
    if n == 72:
        execution.equal("timeout.bound", result["modifiers"]["timeout_seconds"], 60)
    if n in (75, 76, 77):
        execution.true("send.post_verification", sim.verify(sim.get_tm("TMparam3"), "lt", 10.5))


def _wait_ground(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n == 78:
        execution.equal("wait.relative", sim.wait(2, reason="relative"), 2.0)
    elif n == 79:
        target = 10.0
        sim.record("WaitUntil", {"absolute_virtual_time": target}, target)
        sim.virtual_time_seconds = target
        execution.equal("wait.absolute", sim.virtual_time_seconds, target)
    elif n in (80, 81):
        value = sim.get_tm("TMparam")
        condition = sim.verify(value, "eq", 28.0)
        sim.record("WaitForCondition", {"maximum_delay": 20 if n == 81 else None}, condition)
        execution.true("wait.telemetry_condition", condition)
    elif n in (82, 83):
        duration = 3600 if n == 82 else 18_000
        intervals = [60] if n == 82 else [3600, 300, 1]
        sim.wait(duration, reason="interval wait")
        sim.record("WaitProgressIntervals", {"duration": duration}, intervals)
        execution.equal("wait.interval_order", intervals, sorted(intervals, reverse=True))
    else:
        sim.telemetry["TMparam"]["eng"] = 23
        sim.record("SetGroundParameter", {"name": "TMparam", "value": 23}, True)
        execution.equal("ground_parameter.injected", sim.get_tm("TMparam"), 23)


def _limits_alarms(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n in (85, 86, 87, 88, 89, 90, 91, 92, 93):
        parameter = "STATUS_PARAM" if n in (87, 90, 91) else "PARAM"
        definitions = deepcopy(sim.limits[parameter])
        if n == 88:
            output: Any = {key: value for key, value in definitions.items() if value["Active"]}
        elif n in (89, 90):
            output = definitions["ID1"]
        elif n == 91:
            output = definitions["ID1"]["Error"]
        elif n == 92:
            output = definitions["ID1"]["LoRed"]
        elif n == 93:
            output = {"Delta": 0.0001, "Midpoint": 28.0, "Tolerance": 0.5}
        elif n == 86:
            output = definitions["ID1"]
        elif n == 87:
            output = definitions["ID1"]
        else:
            output = definitions
        sim.record("GetLimits", {"parameter": parameter, "example_variant": n}, output)
        execution.true("limits.nonempty", bool(output))
        execution.true("limits.structured", isinstance(output, (dict, list, float)))
        return
    if 94 <= n <= 101:
        definition = sim.limits["PARAM"]["ID1"]
        before = deepcopy(definition)
        updates = {
            94: ("LoRed", 21.5),
            95: ("LoRed", 21.0),
            96: ("HiRed", 33.0),
            97: ("Nominal", ["VALUE"]),
            98: ("Warning", ["DEGRADED"]),
            99: ("HiYel", 29.5),
            100: ("Spike", 0.25),
            101: ("Step", 0.5),
        }
        key, value = updates[n]
        definition[key] = value
        sim.record("SetLimits", {"parameter": "PARAM", "definition": "ID1", "key": key}, deepcopy(definition))
        execution.equal("limits.updated_value", definition[key], value)
        execution.true("limits.copy_changed", before != definition)
        return
    if n == 102:
        sim.alarms_enabled["PARAM"] = False
        disabled = not sim.alarms_enabled["PARAM"]
        sim.alarms_enabled["PARAM"] = True
        sim.record("EnableDisableAlarm", {"parameter": "PARAM"}, sim.alarms_enabled["PARAM"])
        execution.true("alarm.disabled_then_enabled", disabled and sim.alarms_enabled["PARAM"])
    elif n in (103, 104):
        parameter = "PARAM" if n == 103 else "STATUS_PARAM"
        definition = sim.limits[parameter]["ID1"]
        definition["Adjusted"] = True
        sim.record("AdjustLimits", {"parameter": parameter}, deepcopy(definition))
        execution.true("limits.adjusted", definition["Adjusted"])
    elif n == 105:
        loaded = deepcopy(sim.limits)
        sim.record("LoadLimits", {"uri": "sim://limits/reference"}, loaded)
        execution.true("limits.loaded", "PARAM" in loaded)
    elif n == 106:
        sim.limits["PARAM"]["ID1"]["LoRed"] = 21.0
        sim.limits["PARAM"]["ID1"]["LoRed"] = 22.0
        sim.record("RestoreNormalLimits", {"parameter": "PARAM"}, deepcopy(sim.limits["PARAM"]["ID1"]))
        execution.equal("limits.restored", sim.limits["PARAM"]["ID1"]["LoRed"], 22.0)
    else:
        catalog = build_bundled_observation_catalog()
        source_id, source_epoch, item_id = "simulator", "v10", "TM.POWER.BUS_VOLTAGE"
        sample = SampleEvidence(
            sample_id=sample_id_for(source_id, source_epoch, item_id, 1),
            item_id=item_id,
            catalog_digest=CATALOG_DIGEST,
            source_id=source_id,
            source_epoch=source_epoch,
            source_sequence=1,
            snapshot_cursor=1,
            raw_value=TypedScalar(ScalarType.UINT64, 33000),
            engineering_value=TypedScalar(ScalarType.FINITE_DOUBLE, 33.0),
            unit="V",
            validity="VALID",
            quality="GOOD",
            freshness="FRESH",
        )
        result = catalog.is_alarmed(
            catalog_id=catalog.identity.catalog_id,
            catalog_digest=catalog.identity.catalog_digest,
            item_id=item_id,
            sample=sample,
            snapshot_cursor=1,
            evaluated_at_database_time_unix_ns=1,
            visibility=bundled_visibility(),
        )
        evidence = result.as_dict()
        sim.record("IsAlarmed", {"item_id": item_id}, evidence)
        execution.equal("alarm.read_outcome", result.outcome, ReadOutcome.OK)
        execution.equal("alarm.state", result.observation.state.value if result.observation else None, "CRITICAL_HIGH")


def _operator_interaction(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n == 108:
        sim.record("Display", {"message": "Message"}, {"shown": True})
        execution.equal("display.shown", sim.trace[-1].output["shown"], True)
    elif n == 109:
        output = {"name": "ReferenceNotice", "severity": "INFO", "delivered": True}
        sim.record("Notify", {"name": output["name"]}, output)
        execution.true("notify.delivered", output["delivered"])
    elif n == 110:
        output = {"message": "Message", "severity": "INFO"}
        sim.record("Event", {}, output)
        execution.equal("event.severity", output["severity"], "INFO")
    elif n in (111, 112, 113):
        if n in (111, 113):
            sim.resources["CMD_ACT_DEC"] = "DEC2" if n == 111 else "DEC1"
            sim.record("SetResource", {"name": "CMD_ACT_DEC"}, sim.resources["CMD_ACT_DEC"])
        value = sim.resources["CMD_ACT_DEC"]
        sim.record("GetResource", {"name": "CMD_ACT_DEC"}, value)
        execution.true("resource.round_trip", value in ("DEC1", "DEC2"))
    elif 114 <= n <= 118:
        choices = ["A", "B"] if n == 118 else ["Option 1", "Option 2"]
        response: Any = 0 if n == 116 else choices[0]
        prompt_inputs = {
            "choices": choices,
            "type": "LIST|NUM" if n == 116 else "LIST",
            "default": "A" if n == 118 else None,
            "timeout_seconds": 60 if n == 118 else None,
        }
        sim.record("Prompt", prompt_inputs, response)
        execution.equal("prompt.deterministic_response", response, 0 if n == 116 else "A" if n == 118 else "Option 1")
        if n == 118:
            execution.equal("prompt.default", response, prompt_inputs["default"])
            execution.equal("timeout.bound", prompt_inputs["timeout_seconds"], 60)
    elif 119 <= n <= 127:
        name = "Display name" if n not in (120, 127) else "Workspace name"
        if n in (120, 127):
            if n == 120:
                sim.workspaces[name] = {"host": "localhost", "monitor": 1}
            else:
                sim.workspaces[name] = {}
                sim.workspaces.pop(name)
            output = {"open": name in sim.workspaces}
            sim.record("OpenWorkspace" if n == 120 else "CloseWorkspace", {"name": name}, output)
            execution.equal("workspace.state", output["open"], n == 120)
        else:
            if n == 126:
                sim.displays[name] = {}
                sim.displays.pop(name)
                output = {"open": False}
                operation = "CloseDisplay"
            elif n in (124, 125):
                output = {"printed": True, "format": "VECTOR" if n == 125 else "PS"}
                operation = "PrintDisplay"
            else:
                sim.displays[name] = {
                    "host": "hostname" if n == 121 else "localhost",
                    "monitor": 1 if n == 122 else 0,
                    "time_span": 3600 if n == 123 else None,
                }
                output = {"open": True, **sim.displays[name]}
                operation = "OpenDisplay"
            sim.record(operation, {"name": name}, output)
            execution.true("display.operation_succeeded", output.get("open", output.get("printed")) is not None)
    elif n in (128, 129, 130):
        step = {"id": "A1", "title": "Title of the step"}
        sim.record("Step" if n != 130 else "DisplayStep", step, step)
        if n == 129:
            sim.record("Goto", {"target": "A1"}, {"resolved": True})
        execution.equal("step.literal_identity", step["id"], "A1")
        execution.true("step.goto_resolution", n != 129 or sim.trace[-1].output["resolved"])
    elif n == 131:
        states = ["PAUSED", "ABORTED", "FINISHED"]
        sim.record("ProcedureControlStates", {}, states)
        execution.equal("control.states", states, ["PAUSED", "ABORTED", "FINISHED"])
    elif n == 132:
        sim.user_action = {"label": "Reference action", "severity": "WARNING", "enabled": True}
        sim.record("SetUserAction", {}, sim.user_action)
        execution.equal("user_action.label", sim.user_action["label"], "Reference action")
    elif n == 133:
        sim.user_action = {"label": "Reference action", "enabled": True}
        sim.user_action["enabled"] = False
        disabled = not sim.user_action["enabled"]
        sim.user_action["enabled"] = True
        sim.record("EnableDisableUserAction", {}, sim.user_action)
        execution.true("user_action.toggle", disabled and sim.user_action["enabled"])
    else:
        sim.user_action = {"label": "Reference action"}
        sim.user_action = None
        sim.record("DismissUserAction", {}, {"present": False})
        execution.equal("user_action.dismissed", sim.user_action, None)


def _databases_containers(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    scdb = {"SC": "SIMSAT", "Spacecraft_Name": "SIMSAT"}
    gdb = {"DECODER": "CMD_ACT_DEC", "DECODER_CALIBRATION": {0: "DEC1", 1: "DEC2"}}
    if n == 135:
        sim.record("SCDBLookup", {"key": "SC"}, scdb["SC"])
        execution.equal("scdb.value", scdb["SC"], "SIMSAT")
    elif n == 136:
        keys = sorted(scdb)
        sim.record("SCDBKeys", {}, keys)
        execution.equal("scdb.keys", keys, ["SC", "Spacecraft_Name"])
    elif n == 137:
        present = "Spacecraft_Name" in scdb
        sim.record("SCDBContains", {"key": "Spacecraft_Name"}, present)
        execution.true("scdb.contains", present)
    elif n == 138:
        dictionary = {"BURN_DURATION": 120, "DELTA_V": 1.5}
        sim.dictionaries["mmd://Man01/Part1"] = dictionary
        sim.record("LoadDictionary", {"uri": "mmd://Man01/Part1"}, dictionary)
        execution.equal("dictionary.maneuver", dictionary["BURN_DURATION"], 120)
    elif n in (139, 140, 141):
        value = gdb["DECODER_CALIBRATION"][0]
        sim.resources[gdb["DECODER"]] = value
        sim.record("GroundDatabaseMapping", {"mapping": "DECODER"}, {"resource": gdb["DECODER"], "value": value})
        execution.equal("gdb.mapping", sim.resources["CMD_ACT_DEC"], "DEC1")
    elif n == 142:
        sim.proc["VAR"] = 42
        sim.record("ProcedureDatabase", {"key": "VAR"}, sim.proc["VAR"])
        execution.equal("proc.round_trip", sim.proc["VAR"], 42)
    elif n in (143, 144, 145, 146):
        uri = "usr://MyData/data1" if n == 143 else "usr://MyData/data2"
        if n == 143:
            sim.dictionaries[uri] = {"KEY": "loaded"}
            operation = "LoadDictionary"
        else:
            sim.dictionaries.setdefault(uri, {})
            operation = "CreateDictionary" if n == 144 else "SaveDictionary" if n == 145 else "DictionaryAssignment"
            if n == 146:
                sim.dictionaries[uri]["KEY"] = "new value"
        sim.record(operation, {"uri": uri}, deepcopy(sim.dictionaries[uri]))
        execution.true("dictionary.exists", uri in sim.dictionaries)
        execution.true("dictionary.mutable", n != 146 or sim.dictionaries[uri]["KEY"] == "new value")
    elif n in (147, 148):
        database = {
            "KEY1": 45.67,
            "KEY2": "This is a string",
            "KEY5": 0b011001,
            "KEY6": [0, 1, 2, 3, 4],
            "KEY7": {"A": 24, "B": 34, "C": ["X", "Y", "Z"]},
        }
        output = database if n == 147 else {"indexed": database["KEY6"][1], "nested": database["KEY7"]["C"][2]}
        sim.record("DictionaryData", {"variant": n}, output)
        execution.equal("dictionary.typed_values", database["KEY5"], 25)
        execution.true("dictionary.nested", n != 148 or output == {"indexed": 1, "nested": "Z"})
    elif n == 149:
        container: dict[str, Any] = {}
        sim.record("DataContainer", {"name": "Container Name"}, container)
        execution.equal("container.initially_empty", container, {})
    else:
        variable = {"Default": 5, "Type": "LONG", "Range": [0, 10], "Confirm": True}
        container = {"VARNAME": variable}
        sim.record("DataContainerVar", {"container": "Container Name"}, container)
        execution.equal("container.variable_default", container["VARNAME"]["Default"], 5)
        execution.true("container.variable_in_range", 0 <= variable["Default"] <= 10)


def _procedure_control(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    library = {
        "Bus/procedure": {"priority": 3},
        "Payload/procedure": {"priority": 2},
        "Validation/procedure": {"priority": 1},
        "procedure": {"resolved": "Validation/procedure"},
    }
    if n in (152, 153):
        output = sorted(
            ((name, value["priority"]) for name, value in library.items() if "priority" in value),
            key=lambda item: item[1],
        )
        sim.record("ProcedureLibrary", {}, output)
        execution.equal("procedure.priority_winner", output[0][0], "Validation/procedure")
        return
    requested = "Bus/procedure" if n == 155 else "procedure"
    resolved = requested if "/" in requested else library[requested]["resolved"]
    options = {
        "blocking": n != 156 and n != 159,
        "visible": n != 157,
        "automatic": n != 158 and n != 159,
        "args": {"A": 1, "B": 2} if n in (160, 161) else {},
    }
    output = {"requested": requested, "resolved": resolved, **options, "state": "SIMULATED_COMPLETED"}
    sim.record("StartProc", {"requested": requested, "options": options}, output)
    if n in (160, 161):
        execution.equal("args.access", options["args"], {"A": 1, "B": 2})
    else:
        execution.true("startproc.resolved_allowlisted", resolved in library)
    execution.equal("startproc.simulator_state", output["state"], "SIMULATED_COMPLETED")


def _normalize_virtual_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ReferenceExecutionError("virtual file path must be relative and contained")
    return str(path)


def _virtual_files(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    path = _normalize_virtual_path("output/reference.txt")
    sim.virtual_files[path] = ["string1", "string2"]
    if n == 162:
        sim.open_handles.add(path)
        sim.record("OpenFile", {"path": path, "mode": "READ_WRITE"}, {"handle": path})
        execution.true("file.handle_open", path in sim.open_handles)
    elif n == 163:
        sim.open_handles.add(path)
        sim.open_handles.remove(path)
        sim.record("CloseFile", {"handle": path}, True)
        execution.equal("file.handle_closed", path in sim.open_handles, False)
    elif n == 164:
        sim.virtual_files[path].extend(["string3", "string4"])
        sim.record("WriteFile", {"handle": path}, True)
        execution.equal("file.lines_written", len(sim.virtual_files[path]), 4)
    elif n == 165:
        lines = list(sim.virtual_files[path])
        sim.record("ReadFile", {"handle": path}, lines)
        execution.equal("file.lines_read", lines, ["string1", "string2"])
    elif n == 166:
        listing = sorted(name for name in sim.virtual_files if name.startswith("output/"))
        sim.record("ReadDirectory", {"path": "output"}, listing)
        execution.equal("file.directory_listing", listing, [path])
    elif n == 167:
        parts = {"filename": path, "dirname": "output", "basename": "reference.txt", "exists": path in sim.virtual_files}
        sim.record("File", {"path": path}, parts)
        execution.equal("file.instance", parts, {"filename": path, "dirname": "output", "basename": "reference.txt", "exists": True})
    else:
        del sim.virtual_files[path]
        sim.record("DeleteFile", {"path": path}, True)
        execution.equal("file.deleted", path in sim.virtual_files, False)


def _ranging(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n == 169:
        sim.ranging_enabled = True
        enabled = sim.ranging_enabled
        sim.ranging_enabled = False
        sim.record("EnableDisableRanging", {}, {"enabled_then_disabled": enabled and not sim.ranging_enabled})
        execution.true("ranging.toggle", enabled and not sim.ranging_enabled)
    elif n in (170, 171):
        activities = [("BBE1", "ANT1", "RANGING")]
        if n == 171:
            activities.append(("BBE2", "ANT2", "RANGING"))
        sim.ranging_activities.extend(activities)
        sim.record("StartRanging", {"activities": activities}, len(sim.ranging_activities))
        execution.equal("ranging.activity_count", len(sim.ranging_activities), 1 if n == 170 else 2)
    elif n == 172:
        sim.ranging_activities.append(("BBE1", "ANT1", "RANGING"))
        sim.ranging_activities.clear()
        sim.record("AbortRanging", {}, True)
        execution.equal("ranging.aborted", sim.ranging_activities, [])
    elif n == 173:
        sim.baseband["BBE"]["POWER"] = 5
        value = sim.baseband["BBE"]["POWER"]
        sim.record("SetGetBasebandConfig", {"baseband": "BBE", "name": "POWER"}, value)
        execution.equal("ranging.baseband_round_trip", value, 5)
    elif n == 174:
        output = {"basebands": ["BBE1", "BBE2"], "antennas": ["ANT1", "ANT2"]}
        sim.record("GetRangingEquipment", {}, output)
        execution.equal("ranging.equipment_counts", [len(output["basebands"]), len(output["antennas"])], [2, 2])
    elif n == 175:
        sim.ranging_activities.append(("BBE1", "ANT1", "CALIBRATION"))
        sim.record("StartRangingCalibration", {"baseband": "BBE1", "antenna": "ANT1"}, True)
        execution.equal("ranging.calibration_mode", sim.ranging_activities[0][2], "CALIBRATION")
    else:
        status = {"enabled": sim.ranging_enabled, "activities": len(sim.ranging_activities)}
        sim.record("GetRangingStatus", {}, status)
        execution.equal("ranging.status", status, {"enabled": False, "activities": 0})


def _shared_data(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    if n == 181:
        sim.shared["scope"] = {}
        sim.record("AddSharedDataScope", {"scope": "scope"}, True)
        execution.true("shared.scope_created", "scope" in sim.shared)
        return
    if n in (189, 190):
        sim.shared["scope"] = {"NAME": 1}
        if n == 189:
            del sim.shared["scope"]
            output = "scope" not in sim.shared
            operation = "ClearSharedDataScopes"
        else:
            sim.shared["GLOBAL"].clear()
            output = sim.shared["GLOBAL"] == {}
            operation = "ClearSharedData"
        sim.record(operation, {}, output)
        execution.true("shared.clear_scope", output)
        return
    scope = "scope" if n in (180, 186, 187) else "GLOBAL"
    sim.shared.setdefault(scope, {})
    if n in (177, 178):
        sim.shared[scope]["NAME"] = 7
        sim.record("SetSharedData", {"scope": scope, "name": "NAME"}, True)
        execution.equal("shared.value_set", sim.shared[scope]["NAME"], 7)
    elif n == 179:
        updates = {"A": 1, "B": 2}
        sim.shared[scope].update(updates)
        sim.record("SetSharedData", {"scope": scope, "updates": updates}, [True, True])
        execution.equal("shared.multi_set", sim.shared[scope], updates)
    elif n == 180:
        sim.shared[scope]["NAME"] = 7
        sim.record("SetSharedData", {"scope": scope, "name": "NAME"}, True)
        execution.equal("shared.scoped_set", sim.shared[scope]["NAME"], 7)
    elif n in (182, 183):
        sim.shared[scope].update({"A": 1, "B": 2})
        updates = [("A", 3, 1)] if n == 182 else [("A", 3, 1), ("B", 4, 99)]
        outcomes = []
        for key, value, expected in updates:
            matches = sim.shared[scope].get(key) == expected
            if matches:
                sim.shared[scope][key] = value
            outcomes.append(matches)
        sim.record("TestAndSetSharedData", {"updates": updates}, outcomes)
        execution.equal("shared.cas_outcomes", outcomes, [True] if n == 182 else [True, False])
    elif n in (184, 185, 186):
        sim.shared[scope].update({"NAME": 7, "OTHER": 8})
        value: Any = sim.shared[scope]["NAME"] if n != 185 else [sim.shared[scope]["NAME"], sim.shared[scope]["OTHER"]]
        sim.record("GetSharedData", {"scope": scope}, value)
        execution.equal("shared.value_get", value, [7, 8] if n == 185 else 7)
    elif n == 187:
        sim.shared[scope].update({"NAME": 7, "OTHER": 8})
        output = {"keys": sorted(sim.shared[scope]), "scopes": sorted(sim.shared)}
        sim.record("GetSharedDataInformation", {"scope": scope}, output)
        execution.equal("shared.keys", output["keys"], ["NAME", "OTHER"])
        execution.equal("shared.scopes", output["scopes"], ["GLOBAL", "scope"])
    else:
        sim.shared[scope].update({"A": 1, "B": 2})
        sim.shared[scope].pop("A")
        sim.record("ClearSharedData", {"scope": scope, "name": "A"}, True)
        execution.equal("shared.value_cleared", sorted(sim.shared[scope]), ["B"])


def _memory_tmtc(execution: _Execution) -> None:
    n = execution.contract.example_number
    sim = execution.simulator
    catalog = build_bundled_observation_catalog()
    identity = catalog.identity
    visibility = bundled_visibility()
    if n == 191:
        lookup = catalog.memory_lookup_region(
            catalog_id=identity.catalog_id,
            catalog_digest=identity.catalog_digest,
            memory_region_id="SIMULATOR.CONFIGURATION",
            maximum_entries=1,
            visibility=visibility,
        )
        report = {"destination": "mem://My_Report", "lookup": lookup.as_dict()}
        sim.record("GenerateMemoryReport", {"region": "SIMULATOR.CONFIGURATION"}, report)
        execution.equal("memory.report_lookup", lookup.outcome, ReadOutcome.OK)
        execution.equal("memory.report_destination", report["destination"], "mem://My_Report")
    elif n in (192, 193):
        image1 = bytes(range(16))
        image2 = bytearray(image1)
        if n == 192:
            image2[-1] = 99
            compared = (0, len(image1))
        else:
            image2[0] = 99
            compared = (4, 12)
        equal = image1[compared[0] : compared[1]] == bytes(image2)[compared[0] : compared[1]]
        output = {"equal": equal, "begin": compared[0], "end": compared[1]}
        sim.record("CompareMemoryImages", {"images": ["image1", "image2"]}, output)
        execution.equal("memory.comparison", equal, n == 193)
        if n == 193:
            execution.equal("memory.filter_boundaries", output["end"] - output["begin"], 8)
    elif n == 194:
        lookup = catalog.memory_lookup_address(
            catalog_id=identity.catalog_id,
            catalog_digest=identity.catalog_digest,
            start_address=0x1000,
            length=16,
            maximum_entries=1,
            visibility=visibility,
        )
        sim.record("MemoryLookup", {"begin": 0x1000, "end": 0x1010}, lookup.as_dict())
        execution.equal("memory.lookup_outcome", lookup.outcome, ReadOutcome.OK)
        execution.equal("memory.lookup_region", lookup.entries[0].memory_region_id, "SIMULATOR.CONFIGURATION")
        execution.equal("memory.filter_boundaries", 0x1010 - 0x1000, 16)
    else:
        def filtered_lookup(
            *, name: str, item_type: Direction, source: str, begin: str, end: str
        ) -> dict[str, Any]:
            filters = {
                "Name": name,
                "Type": item_type.value,
                "Source": source,
                "Begin": begin,
                "End": end,
            }
            if source != identity.catalog_id:
                return {"outcome": "CONTRACT_MISMATCH", "entries": [], "filters": filters}
            if not begin <= name <= end:
                return {"outcome": "NOT_FOUND", "entries": [], "filters": filters}
            result = catalog.tmtc_lookup(
                catalog_id=identity.catalog_id,
                catalog_digest=identity.catalog_digest,
                direction=item_type,
                item_id=name,
                maximum_entries=1,
                visibility=visibility,
            ).as_dict()
            return {**result, "filters": filters}

        tm = filtered_lookup(
            name="TM.POWER.BUS_VOLTAGE",
            item_type=Direction.TM,
            source=identity.catalog_id,
            begin="TM.POWER.A",
            end="TM.POWER.Z",
        )
        tc = filtered_lookup(
            name="TC.SIMULATOR.RESET",
            item_type=Direction.TC,
            source=identity.catalog_id,
            begin="TC.SIMULATOR.A",
            end="TC.SIMULATOR.Z",
        )
        missing = filtered_lookup(
            name="TM.POWER.BUS_VOLTAGE",
            item_type=Direction.TM,
            source=identity.catalog_id,
            begin="TM.THERMAL.A",
            end="TM.THERMAL.Z",
        )
        output = {
            "catalog_identity": identity.as_dict(),
            "tm": tm,
            "tc": tc,
            "negative_lookup": missing,
        }
        sim.record(
            "TMTCLookup",
            {
                "catalog_id": identity.catalog_id,
                "catalog_digest": identity.catalog_digest,
                "queries": [tm["filters"], tc["filters"]],
            },
            output,
        )
        execution.equal("tmtc.tm_outcome", tm["outcome"], ReadOutcome.OK.value)
        execution.equal("tmtc.tc_outcome", tc["outcome"], ReadOutcome.OK.value)
        execution.equal("tmtc.tm_direction", tm["entries"][0]["direction"], Direction.TM.value)
        execution.equal("tmtc.tc_direction", tc["entries"][0]["direction"], Direction.TC.value)
        execution.equal(
            "tmtc.value_types",
            [tm["entries"][0]["value_type"], tc["entries"][0]["value_type"]],
            [ScalarType.FINITE_DOUBLE.value, ScalarType.BOOLEAN.value],
        )
        execution.true(
            "tmtc.filter_boundaries",
            tm["filters"]["Begin"] <= tm["entries"][0]["item_id"] <= tm["filters"]["End"]
            and tc["filters"]["Begin"] <= tc["entries"][0]["item_id"] <= tc["filters"]["End"],
        )
        execution.equal(
            "tmtc.catalog_digest",
            tm["catalog_identity"]["catalog_digest"],
            identity.catalog_digest,
        )
        execution.equal("tmtc.negative_lookup", missing["outcome"], ReadOutcome.NOT_FOUND.value)


_HANDLERS: Mapping[str, Callable[[_Execution], None]] = {
    "CORE_SYNTAX": _core_syntax,
    "FUNCTION_MODIFIERS_AND_TIME": _function_modifiers_time,
    "TELEMETRY_AND_CONDITIONS": _telemetry_conditions,
    "TELECOMMANDING": _telecommanding,
    "WAIT_AND_GROUND_PARAMETERS": _wait_ground,
    "LIMITS_AND_ALARMS": _limits_alarms,
    "OPERATOR_INTERACTION": _operator_interaction,
    "DATABASES_AND_CONTAINERS": _databases_containers,
    "PROCEDURE_CONTROL": _procedure_control,
    "VIRTUAL_FILES": _virtual_files,
    "RANGING": _ranging,
    "SHARED_DATA": _shared_data,
    "MEMORY_AND_TMTC_LOOKUP": _memory_tmtc,
}


class ReferenceExampleRegistry:
    """Validated exact registry and entry point for one selected adaptation."""

    def __init__(
        self,
        contracts: Iterable[ReferenceExampleContract],
        variant_contracts: Iterable[ReferenceVariantExampleContract] | None = None,
    ):
        entries = tuple(contracts)
        numbers = [entry.example_number for entry in entries]
        if len(entries) != MAX_EXAMPLES or sorted(numbers) != list(range(1, MAX_EXAMPLES + 1)):
            raise ReferenceContractError("registry must contain each example 1..195 exactly once")
        self._entries = {entry.example_number: entry for entry in entries}
        variants = tuple(
            variant_contracts
            if variant_contracts is not None
            else load_reference_variant_contract(example_contracts=entries)
        )
        variant_numbers = [entry.example_number for entry in variants]
        if len(variants) != MAX_EXAMPLES or variant_numbers != list(range(1, MAX_EXAMPLES + 1)):
            raise ReferenceContractError("registry variant contract must cover examples 1..195")
        self._variants = {entry.example_number: entry for entry in variants}

    @classmethod
    def from_contract(cls, path: Path | str | None = None) -> "ReferenceExampleRegistry":
        contracts = load_reference_contract(path)
        return cls(contracts, load_reference_variant_contract(example_contracts=contracts))

    @property
    def example_numbers(self) -> tuple[int, ...]:
        return tuple(sorted(self._entries))

    def contract(self, example_number: int) -> ReferenceExampleContract:
        if type(example_number) is not int or example_number not in self._entries:
            raise ReferenceExecutionError("example number must select one entry from 1..195")
        return self._entries[example_number]

    def variant_contract(self, example_number: int) -> ReferenceVariantExampleContract:
        self.contract(example_number)
        return self._variants[example_number]

    def execute(self, example_number: int) -> ReferenceExampleResult:
        contract = self.contract(example_number)
        execution = _Execution(contract, self.variant_contract(example_number))
        _HANDLERS[contract.handler_family](execution)
        _exercise_variant_contract(execution)
        return execution.finish()


def run_reference_example(
    example_number: int, *, contract_path: Path | str | None = None
) -> ReferenceExampleResult:
    return ReferenceExampleRegistry.from_contract(contract_path).execute(example_number)


def execute_reference_example(example_number: int) -> ReferenceExampleResult:
    """Execute one exact contract entry using only deterministic simulator state."""

    return run_reference_example(example_number)


__all__ = [
    "CONTRACT_RELATIVE_PATH",
    "EffectProof",
    "MAX_EXAMPLES",
    "REFERENCE_CONTRACT_SHA256",
    "REFERENCE_SOURCE_SHA256",
    "REFERENCE_VARIANT_CONTRACT_SHA256",
    "VARIANT_CONTRACT_RELATIVE_PATH",
    "OracleAssertion",
    "ReferenceContractError",
    "ReferenceExampleError",
    "ReferenceExampleContract",
    "ReferenceExampleRegistry",
    "ReferenceExampleResult",
    "ReferenceExecutionError",
    "ReferenceVariantContract",
    "ReferenceVariantExampleContract",
    "TraceEvent",
    "VariantProof",
    "default_contract_path",
    "default_variant_contract_path",
    "execute_reference_example",
    "load_reference_contract",
    "load_reference_variant_contract",
    "run_reference_example",
]
