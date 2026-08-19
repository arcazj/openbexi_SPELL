#!/usr/bin/env python3
"""Validate the exhaustive local v0.4 compatibility disposition ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote


DOC_ROOT = Path(__file__).resolve().parents[2]
DATA_ROOT = DOC_ROOT / "requirements" / "compatibility"
INVENTORY_PATH = DATA_ROOT / "COMPATIBILITY_SOURCE_INVENTORY.json"
LEDGER_PATH = DATA_ROOT / "COMPATIBILITY_LEDGER.json"
SCOPE_PATH = DATA_ROOT / "scopes" / "v0.4.json"
RECONCILIATION_PATH = DATA_ROOT / "COMPATIBILITY_RECONCILIATION.json"
TECHNICAL_REVIEW_PATH = (
    DOC_ROOT / "quality" / "V04_COMPATIBILITY_TECHNICAL_REVIEW.json"
)
SOURCE_AUTHORITY_PATH = DOC_ROOT / "SOURCE_AUTHORITY.md"

REQUIRED_COLUMNS = (
    "ArtifactId",
    "Kind",
    "PublicName",
    "SourceTitle",
    "SourceVersion",
    "SourceHash",
    "Pages",
    "SignatureOrGrammar",
    "LegacyInputs",
    "LegacyResult",
    "LegacyOrdering",
    "LegacyErrors",
    "EffectClass",
    "ModernBehavior",
    "Disposition",
    "Diagnostic",
    "DriverCapability",
    "Persistence",
    "Recovery",
    "SecurityConstraints",
    "TargetIncrement",
    "TestVectors",
    "Decision",
    "Approvers",
    "Status",
)

SOURCE_ORDER = (
    "LRM244",
    "DDM244",
    "GUI244",
    "DEV244",
    "SRV244",
    "BLD244",
    "GUI402",
)
EXPECTED_SCOPE_COUNTS = {
    "LRM244": 763,
    "DDM244": 207,
    "GUI244": 349,
    "DEV244": 164,
    "SRV244": 113,
    "BLD244": 65,
    "GUI402": 21,
}
EXPECTED_SCOPE_TOTAL = 1682
EXPECTED_NORMATIVE_EXAMPLES = 195
EXPECTED_V04_ROWS = 125
EXPECTED_DEFERRED_ROWS = 1557

EXPECTED_SOURCE_IDENTITIES = {
    "LRM244": {
        "source_title": "SPELL - Language Reference - 2.4.4",
        "source_version": "2.4.4",
        "source_hash": "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3",
        "page_count": 118,
    },
    "DDM244": {
        "source_title": "SPELL - Driver Development Manual - 2.4.4",
        "source_version": "2.4.4",
        "source_hash": "057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5",
        "page_count": 45,
    },
    "GUI244": {
        "source_title": "SPELL - GUI User Manual - 2.4.4",
        "source_version": "2.4.4",
        "source_hash": "1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6",
        "page_count": 54,
    },
    "DEV244": {
        "source_title": "SPELL - Development Environment Manual - 2.4.4",
        "source_version": "2.4.4",
        "source_hash": "cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81",
        "page_count": 57,
    },
    "SRV244": {
        "source_title": "SPELL - Server Manual - 2.4.4",
        "source_version": "2.4.4",
        "source_hash": "ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9",
        "page_count": 11,
    },
    "BLD244": {
        "source_title": "SPELL - Build Manual - 2.4.4",
        "source_version": "2.4.4",
        "source_hash": "6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6",
        "page_count": 16,
    },
    "GUI402": {
        "source_title": "SPELL-GUI-4.0.2-Build-Instructions",
        "source_version": "GUI 4.0.2",
        "source_hash": "5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6",
        "page_count": 3,
    },
}

EXPECTED_ARTIFACT_MANIFEST_SHA256 = (
    "cd33f5d43294ef42d37b43c8bbe23c541f3da9dcdbee1b356bd9fef9ff6f5b20"
)
EXPECTED_LEDGER_ROWS_SHA256 = (
    "53037f4e958d776d4b4e1237d986740b2c90f4a93b0ba8a9becf099befb28d2f"
)
EXPECTED_EXAMPLE_CATALOG_SHA256 = (
    "b9199640281b5ff299d737b719640f1fe5d843eaa0b921ad4ede2b49dca08850"
)

INVENTORY_STATUS = "COMPLETE_FOR_LOCAL_V0_4_DISPOSITION"
APPROVAL_STATE = "OWNER_APPROVED_CANDIDATE_A_SCOPE_DISPOSITIONS"
RECONCILIATION_STATUS = "RECONCILED_FOR_LOCAL_V0_4_DISPOSITION"
SCOPE_ID = "local-v0.4-seven-source-exhaustive-disposition"
APPROVER = "JC Arcaz (project owner; Candidate A scope disposition)"
DECISION_PREFIX = "V04-OWNER-20260718 scope disposition; "
REVIEW_LIMITATIONS = (
    "AI-assisted independent technical source review; not a human approval.",
    "Static source-disposition review only; not runtime semantic conformance or implementation verification.",
    "No row-by-row owner source-review claim, operational authorization, or compliance determination.",
)

ALLOWED_DISPOSITIONS = {
    "EXACT",
    "SAFE",
    "TRANS",
    "ADAPT",
    "UNSUP",
    "AMBIG",
    "EXCLUDE",
}
ALLOWED_EFFECT_CLASSES = {
    "NONE",
    "PRESENTATION",
    "OPERATOR_DECISION",
    "LIFECYCLE",
    "READ",
    "CONFIGURATION",
    "CONTROL_STATE",
    "EXTERNAL_EFFECT",
    "LOCAL_MUTATION",
    "UNCLASSIFIED",
}

SOURCE_ROW_PATTERN = re.compile(
    r"^\| \[([^\]]+\.pdf)\]\(([^)]+)\) \| ([0-9]+) \| "
    r"`([0-9a-f]{64})` \|"
)
ARTIFACT_ID_PATTERN = re.compile(r"^CMP-[A-Z0-9][A-Z0-9_.-]+$")
PLANNED_TEST_SUFFIX = "; planned-only; no fixture execution or result recorded."
TEST_VECTOR_PATTERN = re.compile(
    r"^NGV-CMP-[A-Z0-9][A-Z0-9_.-]+; planned-only; "
    r"no fixture execution or result recorded\.$"
)
DIAGNOSTIC_PATTERN = re.compile(r"^SPELL-[A-Z0-9][A-Z0-9-]+$")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def require_keys(
    value: dict[str, Any], expected: set[str], label: str
) -> list[str]:
    actual = set(value)
    if actual == expected:
        return []
    return [
        f"{label} keys differ: missing={sorted(expected - actual)}, "
        f"extra={sorted(actual - expected)}"
    ]


def parse_pages(
    value: str, maximum: int, label: str
) -> tuple[list[str], set[int]]:
    errors: list[str] = []
    pages: set[int] = set()
    if not value:
        return [f"{label}: empty page reference"], pages
    for token in (part.strip() for part in value.split(",")):
        match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", token)
        if not match:
            errors.append(f"{label}: invalid page reference {token!r}")
            continue
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start < 1 or end < start or end > maximum:
            errors.append(
                f"{label}: page reference {token!r} exceeds 1-{maximum}"
            )
            continue
        pages.update(range(start, end + 1))
    return errors, pages


def parse_source_authority() -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for line in SOURCE_AUTHORITY_PATH.read_text(encoding="utf-8").splitlines():
        match = SOURCE_ROW_PATTERN.match(line)
        if not match:
            continue
        title, target, pages, digest = match.groups()
        sources[title] = {
            "source_path": (SOURCE_AUTHORITY_PATH.parent / unquote(target)).resolve(),
            "page_count": int(pages),
            "source_hash": digest,
        }
    return sources


def validate_source_inventory(
    inventory: dict[str, Any],
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    errors = require_keys(
        inventory,
        {
            "schema_version",
            "inventory_id",
            "status",
            "approval_state",
            "scope_limit",
            "sources",
            "counts",
        },
        "compatibility source inventory",
    )
    if inventory.get("schema_version") != "ng-spell-compatibility-source-inventory/2":
        errors.append("unsupported compatibility source-inventory schema")
    if inventory.get("inventory_id") != SCOPE_ID:
        errors.append("compatibility source inventory has an unexpected ID")
    if inventory.get("status") != INVENTORY_STATUS:
        errors.append("compatibility source inventory status differs")
    if inventory.get("approval_state") != APPROVAL_STATE:
        errors.append("compatibility source inventory approval state differs")
    scope_limit = str(inventory.get("scope_limit", ""))
    for required in ("not implementation", "operational", "compliance"):
        if required not in scope_limit.lower():
            errors.append(
                f"compatibility source inventory scope limit omits {required!r}"
            )

    authority = parse_source_authority()
    sources = inventory.get("sources")
    if not isinstance(sources, list):
        return errors + ["compatibility sources must be a list"], {}, {}
    if len(sources) != len(SOURCE_ORDER):
        errors.append(
            f"compatibility source record cardinality differs: actual={len(sources)}, "
            f"expected={len(SOURCE_ORDER)}"
        )

    source_by_code: dict[str, dict[str, Any]] = {}
    artifact_by_id: dict[str, dict[str, Any]] = {}
    actual_by_source: Counter[str] = Counter()
    source_codes_in_order: list[str] = []

    for index, source in enumerate(sources):
        label = f"compatibility source {index}"
        if not isinstance(source, dict):
            errors.append(f"{label}: source must be an object")
            continue
        errors.extend(
            require_keys(
                source,
                {
                    "source_code",
                    "source_title",
                    "source_version",
                    "source_hash",
                    "page_count",
                    "reviewed_page_slices",
                    "inventory_complete_for_local_v0_4_disposition",
                    "extraction",
                    "artifacts",
                },
                label,
            )
        )
        code = source.get("source_code")
        source_codes_in_order.append(str(code))
        if code in source_by_code:
            errors.append(f"duplicate compatibility source code: {code}")
        if isinstance(code, str):
            source_by_code[code] = source
        expected_identity = EXPECTED_SOURCE_IDENTITIES.get(str(code))
        identity = {
            field: source.get(field)
            for field in (
                "source_title",
                "source_version",
                "source_hash",
                "page_count",
            )
        }
        if expected_identity is None or identity != expected_identity:
            errors.append(f"{label}: source identity differs from the pinned set")
        title = source.get("source_title")
        authority_source = authority.get(f"{title}.pdf")
        if authority_source is None:
            errors.append(f"{label}: source title is not authoritative: {title!r}")
        else:
            if source.get("source_hash") != authority_source["source_hash"]:
                errors.append(f"{label}: source hash differs from authority")
            if source.get("page_count") != authority_source["page_count"]:
                errors.append(f"{label}: source page count differs from authority")
            source_path = authority_source["source_path"]
            if not source_path.is_file():
                errors.append(f"{label}: authoritative PDF is missing")
            elif sha256_file(source_path) != authority_source["source_hash"]:
                errors.append(f"{label}: authoritative PDF digest mismatch")
        page_count = source.get("page_count")
        reviewed_pages: set[int] = set()
        slices = source.get("reviewed_page_slices")
        if not isinstance(slices, list) or not slices or not isinstance(page_count, int):
            errors.append(f"{label}: reviewed page slices are invalid")
        else:
            for page_slice in slices:
                page_errors, parsed = parse_pages(str(page_slice), page_count, label)
                errors.extend(page_errors)
                reviewed_pages.update(parsed)
            if reviewed_pages != set(range(1, page_count + 1)):
                errors.append(f"{label}: reviewed pages do not cover the full source")
        if source.get("inventory_complete_for_local_v0_4_disposition") is not True:
            errors.append(f"{label}: local v0.4 disposition inventory is incomplete")
        extraction = source.get("extraction")
        if not isinstance(extraction, dict) or set(extraction) != {
            "library",
            "method",
            "candidate_rows_sha256",
        }:
            errors.append(f"{label}: extraction record differs")
        elif extraction.get("library") != "pypdf 6.14.2":
            errors.append(f"{label}: extraction library differs")

        artifacts = source.get("artifacts")
        if not isinstance(artifacts, list):
            errors.append(f"{label}: artifacts must be a list")
            continue
        previous_id = ""
        for artifact_index, artifact in enumerate(artifacts):
            artifact_label = f"{label} artifact {artifact_index}"
            if not isinstance(artifact, dict):
                errors.append(f"{artifact_label}: artifact must be an object")
                continue
            errors.extend(
                require_keys(
                    artifact,
                    {
                        "ArtifactId",
                        "Kind",
                        "PublicName",
                        "Pages",
                        "Section",
                        "TargetIncrement",
                        "inventory_classification",
                        "review_state",
                    },
                    artifact_label,
                )
            )
            artifact_id = artifact.get("ArtifactId")
            if not isinstance(artifact_id, str) or not ARTIFACT_ID_PATTERN.fullmatch(
                artifact_id
            ):
                errors.append(f"{artifact_label}: invalid ArtifactId")
                continue
            if artifact_id <= previous_id:
                errors.append(f"{label}: artifacts are not sorted by ArtifactId")
            previous_id = artifact_id
            if artifact_id in artifact_by_id:
                errors.append(f"duplicate inventory ArtifactId: {artifact_id}")
            artifact_by_id[artifact_id] = {**artifact, "source_code": code}
            actual_by_source[str(code)] += 1
            if not artifact_id.startswith(f"CMP-{code}-"):
                errors.append(f"{artifact_label}: ArtifactId is not source-code bound")
            if artifact.get("inventory_classification") != "ARTIFACT":
                errors.append(f"{artifact_label}: classification differs")
            if artifact.get("review_state") != "DISPOSITION_APPROVED":
                errors.append(f"{artifact_label}: review state differs")
            if artifact.get("TargetIncrement") not in {"v0.4", "Deferred"}:
                errors.append(f"{artifact_label}: target increment differs")
            if isinstance(page_count, int):
                page_errors, artifact_pages = parse_pages(
                    str(artifact.get("Pages", "")), page_count, artifact_label
                )
                errors.extend(page_errors)
                if artifact_pages - reviewed_pages:
                    errors.append(f"{artifact_label}: cites an unreviewed page")
            for field in ("Kind", "PublicName", "Section"):
                if not isinstance(artifact.get(field), str) or not artifact[field].strip():
                    errors.append(f"{artifact_label}: empty {field}")

    if tuple(source_codes_in_order) != SOURCE_ORDER:
        errors.append("compatibility source records are not in the pinned order")
    if set(source_by_code) != set(SOURCE_ORDER):
        errors.append("compatibility source codes differ from the pinned set")
    if dict(actual_by_source) != EXPECTED_SCOPE_COUNTS:
        errors.append(
            f"compatibility per-source counts differ: actual={dict(actual_by_source)}, "
            f"expected={EXPECTED_SCOPE_COUNTS}"
        )
    return errors, source_by_code, artifact_by_id


def validate_ledger(
    ledger: dict[str, Any],
    source_by_code: dict[str, dict[str, Any]],
    artifact_by_id: dict[str, dict[str, Any]],
) -> tuple[list[str], dict[str, dict[str, str]]]:
    errors = require_keys(
        ledger,
        {
            "schema_version",
            "ledger_id",
            "status",
            "approval_state",
            "approval_limit",
            "required_columns",
            "rows",
        },
        "compatibility ledger",
    )
    if ledger.get("schema_version") != "ng-spell-compatibility-ledger/2":
        errors.append("unsupported compatibility-ledger schema")
    if ledger.get("ledger_id") != SCOPE_ID:
        errors.append("compatibility ledger ID differs")
    if ledger.get("status") != INVENTORY_STATUS:
        errors.append("compatibility ledger status differs")
    if ledger.get("approval_state") != APPROVAL_STATE:
        errors.append("compatibility ledger approval state differs")
    approval_limit = str(ledger.get("approval_limit", ""))
    for required in (
        "scope disposition",
        "does not claim",
        "operational",
        "personally reviewed",
    ):
        if required not in approval_limit.lower():
            errors.append(f"compatibility approval limit omits {required!r}")
    if tuple(ledger.get("required_columns", [])) != REQUIRED_COLUMNS:
        errors.append("compatibility required columns differ")
    rows = ledger.get("rows")
    if not isinstance(rows, list):
        return errors + ["compatibility rows must be a list"], {}
    if len(rows) != EXPECTED_SCOPE_TOTAL:
        errors.append(
            f"compatibility ledger has {len(rows)} rows, expected {EXPECTED_SCOPE_TOTAL}"
        )

    row_by_id: dict[str, dict[str, str]] = {}
    previous_id = ""
    example_rows: list[dict[str, str]] = []
    target_counts: Counter[str] = Counter()
    for index, row in enumerate(rows):
        label = f"compatibility row {index}"
        if not isinstance(row, dict):
            errors.append(f"{label}: row must be an object")
            continue
        errors.extend(require_keys(row, set(REQUIRED_COLUMNS), label))
        if any(
            not isinstance(row.get(column), str) or not row[column].strip()
            for column in REQUIRED_COLUMNS
        ):
            errors.append(f"{label}: empty or non-string fields")
            continue
        artifact_id = row["ArtifactId"]
        if not ARTIFACT_ID_PATTERN.fullmatch(artifact_id):
            errors.append(f"{label}: invalid ArtifactId")
            continue
        if artifact_id <= previous_id:
            errors.append("compatibility rows are not sorted by ArtifactId")
        previous_id = artifact_id
        if artifact_id in row_by_id:
            errors.append(f"duplicate compatibility ledger row: {artifact_id}")
        row_by_id[artifact_id] = row
        inventory_artifact = artifact_by_id.get(artifact_id)
        if inventory_artifact is None:
            continue
        source = source_by_code[inventory_artifact["source_code"]]
        for field in ("Kind", "PublicName", "Pages", "TargetIncrement"):
            if row[field] != inventory_artifact[field]:
                errors.append(f"{artifact_id}: {field} differs from inventory")
        for field in ("SourceTitle", "SourceVersion", "SourceHash"):
            inventory_field = {
                "SourceTitle": "source_title",
                "SourceVersion": "source_version",
                "SourceHash": "source_hash",
            }[field]
            if row[field] != source[inventory_field]:
                errors.append(f"{artifact_id}: {field} differs from source record")
        if row["Disposition"] not in ALLOWED_DISPOSITIONS:
            errors.append(f"{artifact_id}: invalid disposition")
        if row["EffectClass"] not in ALLOWED_EFFECT_CLASSES:
            errors.append(f"{artifact_id}: invalid effect class")
        if not DIAGNOSTIC_PATTERN.fullmatch(row["Diagnostic"]):
            errors.append(f"{artifact_id}: invalid diagnostic")
        if row["Status"] != "DispositionApproved":
            errors.append(f"{artifact_id}: status differs")
        if row["Approvers"] != APPROVER:
            errors.append(f"{artifact_id}: scope approver differs")
        decision = row["Decision"]
        technical_rationale = (
            decision.removeprefix(DECISION_PREFIX)
            if decision.startswith(DECISION_PREFIX)
            else ""
        )
        if (
            not technical_rationale.strip()
            or DECISION_PREFIX.strip() in technical_rationale
        ):
            errors.append(
                f"{artifact_id}: owner scope reference or technical rationale differs"
            )
        expected_test_vector = f"NGV-{artifact_id}{PLANNED_TEST_SUFFIX}"
        if (
            row["TestVectors"] != expected_test_vector
            or not TEST_VECTOR_PATTERN.fullmatch(row["TestVectors"])
        ):
            errors.append(f"{artifact_id}: test-vector identity differs")
        target_counts[row["TargetIncrement"]] += 1
        if row["TargetIncrement"] == "Deferred":
            if row["Disposition"] != "EXCLUDE":
                errors.append(f"{artifact_id}: deferred row must be EXCLUDE")
            if row["DriverCapability"] != "NOT_ADVERTISED_IN_V0_4":
                errors.append(f"{artifact_id}: deferred capability differs")
            if "excluded from v0.4" not in row["ModernBehavior"].lower():
                errors.append(f"{artifact_id}: deferred behavior is not explicit")
        elif row["TargetIncrement"] == "v0.4":
            if row["Disposition"] in {"EXCLUDE", "AMBIG"}:
                errors.append(f"{artifact_id}: in-scope row has unresolved disposition")
        else:
            errors.append(f"{artifact_id}: invalid target increment")
        if row["Kind"].upper() in {"EXAMPLE", "NORMATIVE_EXAMPLE"}:
            example_rows.append(row)

    missing = sorted(set(artifact_by_id) - set(row_by_id))
    extra = sorted(set(row_by_id) - set(artifact_by_id))
    if missing or extra:
        errors.append(
            f"compatibility inventory/ledger mismatch: missing={missing}, extra={extra}"
        )
    if target_counts != Counter(
        {"v0.4": EXPECTED_V04_ROWS, "Deferred": EXPECTED_DEFERRED_ROWS}
    ):
        errors.append(f"compatibility target counts differ: {dict(target_counts)}")
    test_vector_counts = Counter(
        row.get("TestVectors")
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("TestVectors"), str)
    )
    duplicate_test_vectors = sorted(
        value for value, count in test_vector_counts.items() if count > 1
    )
    if duplicate_test_vectors:
        errors.append(
            "duplicate compatibility test vectors: "
            f"{duplicate_test_vectors}"
        )
    if len(example_rows) != EXPECTED_NORMATIVE_EXAMPLES:
        errors.append(
            f"Language Reference example count differs: {len(example_rows)}"
        )
    example_catalog = [
        {
            "ArtifactId": row["ArtifactId"],
            "Pages": row["Pages"],
            "PublicName": row["PublicName"],
        }
        for row in sorted(example_rows, key=lambda item: item["ArtifactId"])
    ]
    if canonical_sha256(example_catalog) != EXPECTED_EXAMPLE_CATALOG_SHA256:
        errors.append("Language Reference example catalog differs from the pinned set")
    if canonical_sha256(rows) != EXPECTED_LEDGER_ROWS_SHA256:
        errors.append("compatibility ledger rows differ from the pinned exhaustive set")
    artifact_manifest = [
        {
            "ArtifactId": row["ArtifactId"],
            "Kind": row["Kind"],
            "Pages": row["Pages"],
            "PublicName": row["PublicName"],
            "SourceHash": row["SourceHash"],
        }
        for row in rows
    ]
    if canonical_sha256(artifact_manifest) != EXPECTED_ARTIFACT_MANIFEST_SHA256:
        errors.append("compatibility artifact manifest differs from the pinned set")
    return errors, row_by_id


def validate_scope(
    scope: dict[str, Any],
    source_by_code: dict[str, dict[str, Any]],
    artifact_by_id: dict[str, dict[str, Any]],
    row_by_id: dict[str, dict[str, str]],
) -> list[str]:
    errors = require_keys(
        scope,
        {
            "schema_version",
            "scope_id",
            "target_increment",
            "status",
            "approval_state",
            "scope_basis",
            "source_slices",
            "artifact_ids",
            "counts",
            "complete_for_candidate_v0_4_gate",
            "implementation_claim",
            "operational_authorization",
            "compliance_determination",
        },
        "v0.4 compatibility scope",
    )
    expected_scalars = {
        "schema_version": "ng-spell-compatibility-scope/2",
        "scope_id": SCOPE_ID,
        "target_increment": "v0.4",
        "status": INVENTORY_STATUS,
        "approval_state": APPROVAL_STATE,
        "complete_for_candidate_v0_4_gate": True,
        "implementation_claim": False,
        "operational_authorization": False,
        "compliance_determination": False,
    }
    for field, expected in expected_scalars.items():
        if scope.get(field) != expected:
            errors.append(f"compatibility scope {field} differs")
    basis = str(scope.get("scope_basis", ""))
    for required in (
        "approved candidate a",
        "exclusion disposition",
        "technical",
        "row-by-row",
    ):
        if required not in basis.lower():
            errors.append(f"compatibility scope basis omits {required!r}")
    artifact_ids = scope.get("artifact_ids")
    if not isinstance(artifact_ids, list):
        errors.append("compatibility scope artifact_ids must be a list")
    else:
        if artifact_ids != sorted(artifact_ids):
            errors.append("compatibility scope artifact_ids are not sorted")
        if len(artifact_ids) != len(set(artifact_ids)):
            errors.append("compatibility scope artifact_ids are not unique")
        if set(artifact_ids) != set(artifact_by_id) or set(artifact_ids) != set(row_by_id):
            errors.append("compatibility scope does not match inventory and ledger")
    expected_counts = {
        "source_slices": len(SOURCE_ORDER),
        "artifact_ids": EXPECTED_SCOPE_TOTAL,
        "normative_examples": EXPECTED_NORMATIVE_EXAMPLES,
        "v0_4": EXPECTED_V04_ROWS,
        "deferred": EXPECTED_DEFERRED_ROWS,
        "disposition_approved": EXPECTED_SCOPE_TOTAL,
    }
    if scope.get("counts") != expected_counts:
        errors.append("compatibility scope counts differ")
    source_slices = scope.get("source_slices")
    if not isinstance(source_slices, list):
        errors.append("compatibility source_slices must be a list")
    else:
        expected_slices = [
            {
                "source_code": code,
                "pages": source_by_code[code]["reviewed_page_slices"],
                "artifact_count": EXPECTED_SCOPE_COUNTS[code],
            }
            for code in SOURCE_ORDER
            if code in source_by_code
        ]
        if source_slices != expected_slices:
            errors.append("compatibility source_slices differ")
    return errors


def expected_inventory_counts() -> dict[str, int]:
    return {
        "source_records": len(SOURCE_ORDER),
        "required_source_records": len(SOURCE_ORDER),
        "artifacts": EXPECTED_SCOPE_TOTAL,
        **{
            f"{code}_artifacts": count
            for code, count in EXPECTED_SCOPE_COUNTS.items()
        },
        "normative_examples": EXPECTED_NORMATIVE_EXAMPLES,
        "v0_4_artifacts": EXPECTED_V04_ROWS,
        "deferred_artifacts": EXPECTED_DEFERRED_ROWS,
        "disposition_approved_artifacts": EXPECTED_SCOPE_TOTAL,
    }


def build_reconciliation(
    inventory: dict[str, Any],
    ledger: dict[str, Any],
    scope: dict[str, Any],
    input_sha256: dict[str, str],
) -> dict[str, Any]:
    rows = ledger.get("rows", [])
    example_rows = [
        row
        for row in rows
        if isinstance(row, dict)
        and str(row.get("Kind", "")).upper() in {"EXAMPLE", "NORMATIVE_EXAMPLE"}
    ]
    source_counts = {
        code: sum(
            1
            for row in rows
            if isinstance(row, dict)
            and str(row.get("ArtifactId", "")).startswith(f"CMP-{code}-")
        )
        for code in SOURCE_ORDER
    }


    artifact_manifest = [
        {
            "ArtifactId": row.get("ArtifactId"),
            "Kind": row.get("Kind"),
            "Pages": row.get("Pages"),
            "PublicName": row.get("PublicName"),
            "SourceHash": row.get("SourceHash"),
        }
        for row in rows
        if isinstance(row, dict)
    ]
    example_catalog = [
        {
            "ArtifactId": row.get("ArtifactId"),
            "Pages": row.get("Pages"),
            "PublicName": row.get("PublicName"),
        }
        for row in sorted(example_rows, key=lambda item: str(item.get("ArtifactId", "")))
    ]
    return {
        "schema_version": "ng-spell-compatibility-reconciliation/2",
        "reconciliation_id": SCOPE_ID,
        "status": RECONCILIATION_STATUS,
        "approval_state": APPROVAL_STATE,
        "source_inventory": {
            "path": "COMPATIBILITY_SOURCE_INVENTORY.json",
            "sha256": input_sha256["source_inventory"],
            "expected_artifacts": EXPECTED_SCOPE_TOTAL,
            "artifact_manifest_sha256": canonical_sha256(artifact_manifest),
            "example_catalog_sha256": canonical_sha256(example_catalog),
        },
        "ledger": {
            "path": "COMPATIBILITY_LEDGER.json",
            "sha256": input_sha256["ledger"],
            "expected_rows": EXPECTED_SCOPE_TOTAL,
            "required_columns": len(REQUIRED_COLUMNS),
            "canonical_rows_sha256": canonical_sha256(rows),
        },
        "scope": {
            "path": "scopes/v0.4.json",
            "sha256": input_sha256["scope"],
            "expected_artifact_ids": EXPECTED_SCOPE_TOTAL,
        },
        "counts": {
            "inventory_artifacts": EXPECTED_SCOPE_TOTAL,
            "ledger_rows": len(rows),
            "unique_artifact_ids": len(
                {
                    row.get("ArtifactId")
                    for row in rows
                    if isinstance(row, dict)
                }
            ),
            "scope_artifact_ids": len(scope.get("artifact_ids", [])),
            **{
                f"{code}_inventory_artifacts": EXPECTED_SCOPE_COUNTS[code]
                for code in SOURCE_ORDER
            },
            **{
                f"{code}_ledger_rows": source_counts[code]
                for code in SOURCE_ORDER
            },
            "normative_examples": len(example_rows),
            "v0_4_rows": sum(
                1
                for row in rows
                if isinstance(row, dict) and row.get("TargetIncrement") == "v0.4"
            ),
            "deferred_rows": sum(
                1
                for row in rows
                if isinstance(row, dict) and row.get("TargetIncrement") == "Deferred"
            ),
            "required_source_records": len(SOURCE_ORDER),
            "represented_source_records": len(inventory.get("sources", [])),
            "fully_inventoried_source_records": sum(
                1
                for source in inventory.get("sources", [])
                if isinstance(source, dict)
                and source.get("inventory_complete_for_local_v0_4_disposition") is True
            ),
            "disposition_approved_rows": sum(
                1
                for row in rows
                if isinstance(row, dict) and row.get("Status") == "DispositionApproved"
            ),
            "implemented_rows": sum(
                1
                for row in rows
                if isinstance(row, dict) and row.get("Status") == "Implemented"
            ),
            "verified_rows": sum(
                1
                for row in rows
                if isinstance(row, dict) and row.get("Status") == "Verified"
            ),
        },
        "scope_reconciled": True,
        "global_reconciled": True,
        "local_v0_4_disposition_complete": True,
        "blocking_gaps": [],
        "deferred_non_claims": [
            "Deferred language examples are not executable fixtures or semantic oracles.",
            "Deferred language, GUI, development, build, server, and driver behavior is not implemented by v0.4.",
            "This reconciliation is not operational authorization or a compliance determination.",
        ],
    }


def validate_technical_review(
    review: dict[str, Any], ledger: dict[str, Any]
) -> list[str]:
    errors = require_keys(
        review,
        {
            "schema_version",
            "review_id",
            "status",
            "reviewed_date",
            "method",
            "source_results",
            "catalog_binding",
            "limitations",
            "claims",
        },
        "v0.4 compatibility technical review",
    )
    expected_scalars = {
        "schema_version": "ng-spell-v04-compatibility-technical-review/1",
        "review_id": SCOPE_ID,
        "status": "PASS",
        "reviewed_date": "2026-07-18",
    }
    for field, expected in expected_scalars.items():
        if review.get(field) != expected:
            errors.append(f"compatibility technical review {field} differs")
    method = str(review.get("method", "")).lower()
    for required in (
        "independent",
        "source-grounding",
        "exact supplied pdf",
        "structural validation",
    ):
        if required not in method:
            errors.append(
                f"compatibility technical review method omits {required!r}"
            )

    rows = ledger.get("rows", [])
    source_results = review.get("source_results")
    if not isinstance(source_results, list):
        errors.append("compatibility technical source_results must be a list")
        source_results = []
    if len(source_results) != len(SOURCE_ORDER):
        errors.append("compatibility technical source_results cardinality differs")
    codes = [
        result.get("source_code")
        for result in source_results
        if isinstance(result, dict)
    ]
    if codes != list(SOURCE_ORDER):
        errors.append("compatibility technical source_results order differs")
    if len(codes) != len(set(codes)):
        errors.append("duplicate compatibility technical source result")
    review_passes: list[str] = []
    for result in source_results:
        if not isinstance(result, dict):
            errors.append("compatibility technical source result must be an object")
            continue
        code = result.get("source_code")
        if code not in EXPECTED_SOURCE_IDENTITIES:
            errors.append(f"unknown compatibility technical source code: {code}")
            continue
        expected_keys = {
            "source_code",
            "source_hash",
            "row_count",
            "canonical_rows_sha256",
            "review_pass",
            "decision",
            "blocking_findings",
            "high_findings",
        }
        errors.extend(
            require_keys(result, expected_keys, f"technical review {code}")
        )
        source_rows = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("ArtifactId", "")).startswith(f"CMP-{code}-")
        ]
        if result.get("source_hash") != EXPECTED_SOURCE_IDENTITIES[code][
            "source_hash"
        ]:
            errors.append(f"technical review {code}: source hash differs")
        if result.get("row_count") != EXPECTED_SCOPE_COUNTS[code]:
            errors.append(f"technical review {code}: row count differs")
        if result.get("canonical_rows_sha256") != canonical_sha256(source_rows):
            errors.append(f"technical review {code}: canonical rows digest differs")
        review_pass = result.get("review_pass")
        if not isinstance(review_pass, str) or not review_pass.strip():
            errors.append(f"technical review {code}: review pass is empty")
        else:
            review_passes.append(review_pass)
        if result.get("decision") != "PASS":
            errors.append(f"technical review {code}: decision differs")
        if result.get("blocking_findings") != 0:
            errors.append(f"technical review {code}: blocking findings remain")
        if result.get("high_findings") != 0:
            errors.append(f"technical review {code}: high findings remain")
    if len(review_passes) != len(set(review_passes)):
        errors.append("compatibility technical review pass identities are not unique")

    expected_binding = {
        "canonical_rows_sha256": EXPECTED_LEDGER_ROWS_SHA256,
        "artifact_manifest_sha256": EXPECTED_ARTIFACT_MANIFEST_SHA256,
        "example_catalog_sha256": EXPECTED_EXAMPLE_CATALOG_SHA256,
    }
    if review.get("catalog_binding") != expected_binding:
        errors.append("compatibility technical review catalog binding differs")
    if review.get("limitations") != list(REVIEW_LIMITATIONS):
        errors.append("compatibility technical review limitations differ")
    expected_claims = {
        "human_approval": False,
        "row_by_row_owner_source_review": False,
        "implementation_verified": False,
        "runtime_semantic_conformance": False,
        "operational_authorization": False,
        "compliance_determination": False,
    }
    if review.get("claims") != expected_claims:
        errors.append("compatibility technical review claims differ")
    return errors


def validate_payloads(
    inventory: dict[str, Any],
    ledger: dict[str, Any],
    scope: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors, source_by_code, artifact_by_id = validate_source_inventory(inventory)
    if inventory.get("counts") != expected_inventory_counts():
        errors.append("compatibility inventory counts differ")
    ledger_errors, row_by_id = validate_ledger(
        ledger, source_by_code, artifact_by_id
    )
    errors.extend(ledger_errors)
    errors.extend(validate_scope(scope, source_by_code, artifact_by_id, row_by_id))
    rows = ledger.get("rows", [])
    summary = {
        "schema_present": True,
        "schema_valid": not errors,
        "row_count": len(rows),
        "example_count": sum(
            1
            for row in rows
            if isinstance(row, dict)
            and str(row.get("Kind", "")).upper() in {"EXAMPLE", "NORMATIVE_EXAMPLE"}
        ),
        "indexed_rows": sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("Status") == "Indexed"
        ),
        "decomposed_rows": sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("Status") == "Decomposed"
        ),
        "approved_rows": sum(
            1
            for row in rows
            if isinstance(row, dict)
            and row.get("Status") == "DispositionApproved"
        ),
        "disposition_approved_rows": sum(
            1
            for row in rows
            if isinstance(row, dict)
            and row.get("Status") == "DispositionApproved"
        ),
        "implemented_rows": sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("Status") == "Implemented"
        ),
        "verified_rows": sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("Status") == "Verified"
        ),
        "v0_4_rows": sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("TargetIncrement") == "v0.4"
        ),
        "deferred_rows": sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("TargetIncrement") == "Deferred"
        ),
        "candidate_scope_reconciled": not errors,
        "scope_reconciled": not errors,
        "global_reconciled": not errors,
        "local_v0_4_disposition_complete": not errors,
        "source_count": len(inventory.get("sources", [])),
    }
    return errors, summary


def validate_repository(
    write_reconciliation: bool = False,
) -> tuple[list[str], dict[str, Any]]:
    try:
        inventory = read_json(INVENTORY_PATH)
        ledger = read_json(LEDGER_PATH)
        scope = read_json(SCOPE_PATH)
        technical_review = read_json(TECHNICAL_REVIEW_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot load compatibility evidence: {exc}"], {
            "schema_present": False,
            "schema_valid": False,
            "row_count": 0,
            "example_count": 0,
            "indexed_rows": 0,
            "decomposed_rows": 0,
            "approved_rows": 0,
            "disposition_approved_rows": 0,
            "implemented_rows": 0,
            "verified_rows": 0,
            "v0_4_rows": 0,
            "deferred_rows": 0,
            "candidate_scope_reconciled": False,
            "scope_reconciled": False,
            "global_reconciled": False,
            "local_v0_4_disposition_complete": False,
            "technical_review_verified": False,
            "source_count": 0,
        }
    errors, summary = validate_payloads(inventory, ledger, scope)
    review_errors = validate_technical_review(technical_review, ledger)
    errors.extend(review_errors)
    summary["technical_review_verified"] = not review_errors
    input_sha256 = {
        "ledger": sha256_file(LEDGER_PATH),
        "scope": sha256_file(SCOPE_PATH),
        "source_inventory": sha256_file(INVENTORY_PATH),
    }
    expected = build_reconciliation(inventory, ledger, scope, input_sha256)
    if write_reconciliation and not errors:
        write_json(RECONCILIATION_PATH, expected)
    try:
        actual = read_json(RECONCILIATION_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load compatibility reconciliation: {exc}")
    else:
        if actual != expected:
            errors.append(
                "compatibility reconciliation is stale; regenerate it with "
                "quality/tools/validate_compatibility.py --write-reconciliation"
            )
    summary["schema_valid"] = not errors
    summary["candidate_scope_reconciled"] = not errors
    summary["scope_reconciled"] = not errors
    summary["global_reconciled"] = not errors
    summary["local_v0_4_disposition_complete"] = not errors
    return errors, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-reconciliation", action="store_true")
    args = parser.parse_args()
    errors, summary = validate_repository(args.write_reconciliation)
    print(
        "local_scope="
        f"{'RECONCILED' if summary['scope_reconciled'] else 'INVALID'} "
        f"rows={summary['row_count']} examples={summary['example_count']} "
        f"v0.4={summary['v0_4_rows']} deferred={summary['deferred_rows']} "
        f"disposition_approved={summary['disposition_approved_rows']}"
    )
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
