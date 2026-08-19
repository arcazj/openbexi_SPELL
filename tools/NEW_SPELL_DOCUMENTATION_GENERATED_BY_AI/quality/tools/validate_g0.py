#!/usr/bin/env python3
"""Generate and validate deterministic NG-WP-00 Gate G0 evidence scaffolding."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

import validate_compatibility


DOC_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = DOC_ROOT.parent
REQUIREMENTS_PATH = DOC_ROOT / "requirements" / "SYSTEM_REQUIREMENTS.md"
RULES_PATH = DOC_ROOT / "requirements" / "IMPLEMENTATION_ALLOCATION_RULES.json"
ALLOCATION_PATH = DOC_ROOT / "requirements" / "IMPLEMENTATION_ALLOCATION.csv"
APPROVAL_EVIDENCE_PATH = DOC_ROOT / "quality" / "G0_HUMAN_APPROVAL_LEDGER.json"
REPORT_PATH = DOC_ROOT / "quality" / "G0_READINESS_REPORT.json"
DOCUMENT_ALLOCATION_PATH = (
    DOC_ROOT / "requirements" / "DOCUMENT_REQUIREMENT_ALLOCATION.md"
)
SOURCE_AUTHORITY_PATH = DOC_ROOT / "SOURCE_AUTHORITY.md"
STATE_MODELS_PATH = DOC_ROOT / "architecture" / "state-machines.json"
OPEN_DECISIONS_PATH = DOC_ROOT / "quality" / "OPEN_DECISIONS.md"
CHECKLIST_PATH = DOC_ROOT / "quality" / "DOCUMENT_ACCEPTANCE_CHECKLIST.md"
DOCUMENT_CONTROL_PATH = DOC_ROOT / "DOCUMENT_CONTROL.md"
COMPATIBILITY_PATH = DOC_ROOT / "requirements" / "COMPATIBILITY_LEDGER.md"
COMPATIBILITY_DATA_ROOT = DOC_ROOT / "requirements" / "compatibility"
COMPATIBILITY_INVENTORY_PATH = (
    COMPATIBILITY_DATA_ROOT / "COMPATIBILITY_SOURCE_INVENTORY.json"
)
DETAILED_COMPATIBILITY_PATH = (
    COMPATIBILITY_DATA_ROOT / "COMPATIBILITY_LEDGER.json"
)
COMPATIBILITY_SCOPE_PATH = COMPATIBILITY_DATA_ROOT / "scopes" / "v0.4.json"
COMPATIBILITY_RECONCILIATION_PATH = (
    COMPATIBILITY_DATA_ROOT / "COMPATIBILITY_RECONCILIATION.json"
)
ADR_DIRECTORY = DOC_ROOT / "architecture" / "decisions"
V04_SCOPE_PATH = WORKSPACE_ROOT / "SPELL_v0.4_Pre-Implementation.md"
V04_TEST_PLAN_PATH = WORKSPACE_ROOT / "Test_and_Integration.md"

OWNER_AUTHORIZATION_TEXT = (
    "Revise v0.4 to a local-only, synthetic non-CUI simulator engineering "
    "gate. I, JC Arcaz, am the project owner and approve Candidate A, its "
    "exclusions, budgets, and test plan. Remove organization-only approval "
    "requirements without making operational or compliance claims."
)
LOCAL_SCOPE_PROFILE = {
    "profile_id": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    "candidate": "Candidate A - Typed Simulator Driver and Context Foundation",
    "candidate_b_disposition": "DEFERRED",
    "local_only": True,
    "synthetic_data_only": True,
    "cui_allowed": False,
    "operational_use_allowed": False,
    "external_effects_allowed": False,
    "gcs_or_spacecraft_connectivity_allowed": False,
}
COMPATIBILITY_DISPOSITION = {
    "decision_reference": "V04-OWNER-20260718",
    "basis": (
        "The project owner's approval of Candidate A and its exclusions "
        "approves the scope-disposition policy used to assign authoritative "
        "manual artifacts either to the exact Candidate A v0.4 lifecycle "
        "slice or to Deferred/EXCLUDE."
    ),
    "in_scope_policy": (
        "Only artifacts required by the exact nine-RPC typed simulator host, "
        "context, execution-attachment, lifecycle, configuration, capacity, "
        "identity, journal, persistence, read-only projection, packaging, and "
        "engineering-evidence boundary may target v0.4."
    ),
    "deferred_policy": (
        "All language execution, procedure routing, telemetry, telecommand, "
        "operational, connected, mission, broader GUI/development, and other "
        "future behavior is Deferred/EXCLUDE and is not advertised by v0.4."
    ),
    "gate_0_evidence_policy": (
        "Every row requires exact source identity/span, effect class or "
        "explicit excluded ambiguity, safe behavior and disposition, target "
        "phase, unique planned test identity, errata disposition, and "
        "reconciled counts. Deferred/EXCLUDE rows require static source and "
        "negative-scope evidence, not executable fixtures, semantic oracles, "
        "or results."
    ),
    "technical_validation_required": True,
    "owner_row_by_row_source_review_claimed": False,
    "implementation_claim": False,
    "operational_authorization": False,
    "compliance_determination": False,
}
LOCAL_BASELINE_ARTIFACTS = (
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/"
    "IMPLEMENTATION_ALLOCATION_RULES.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "COMPATIBILITY_LEDGER.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "COMPATIBILITY_SOURCE_INVENTORY.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/requirements/compatibility/"
    "scopes/v0.4.json",
    "NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/quality/"
    "V04_COMPATIBILITY_TECHNICAL_REVIEW.json",
    "SPELL_DOCUMENTATION_REVIEW.md",
    "SPELL_v0.4_Pre-Implementation.md",
    "Test_and_Integration.md",
)
RETAINED_ENGINEERING_GATES = (
    "scope-and-exclusion-enforcement",
    "synthetic-simulator-only-resolution",
    "bounded-ir-and-mtls-credential-separation",
    "fail-closed-driver-authentication",
    "typed-contract-and-lifecycle-integrity",
    "operation-idempotency-and-no-resend-certainty",
    "migration-and-rollback",
    "secret-and-supply-chain-hygiene",
    "v0.3-regression",
    "evidence-bound-release-acceptance",
)

REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Z]+-[0-9]{3}$")
REQUIREMENT_ROW_PATTERN = re.compile(r"^\| ([A-Z]+-[0-9]{3}) \|")
RANGE_PATTERN = re.compile(
    r"\b([A-Z]+-[0-9]{3})(?:\.\.([A-Z]+-[0-9]{3}))?\b"
)
MARKDOWN_LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
DOCUMENT_ROW_PATTERN = re.compile(r"^\| `([^`]+\.md)` \|")
SOURCE_ROW_PATTERN = re.compile(
    r"^\| \[([^\]]+\.pdf)\]\(([^)]+)\) \| ([0-9]+) \| "
    r"`([0-9a-f]{64})` \|"
)
OPEN_DECISION_PATTERN = re.compile(r"^\| (OD-[0-9]{3}) \|")
EXPECTED_SOURCE_EVIDENCE = {
    "SPELL - Language Reference - 2.4.4.pdf": (
        118,
        "ed13fae748997a48d6930ac40a30fb31f8b54119be0005a0431a1920613801c3",
    ),
    "SPELL - Driver Development Manual - 2.4.4.pdf": (
        45,
        "057794f11846588724ccfffb69a1e7150042011e7a45e7fa6e7958500e56bae5",
    ),
    "SPELL - GUI User Manual - 2.4.4.pdf": (
        54,
        "1a6b13190b0bb25d6f19a0549f3917beaac72a40d851eac5165a95c9d3b779c6",
    ),
    "SPELL - Development Environment Manual - 2.4.4.pdf": (
        57,
        "cedf617a4d551701394f75a8ec1769a402059a4c7b659ed87079ce5148074a81",
    ),
    "SPELL - Server Manual - 2.4.4.pdf": (
        11,
        "ee123aaf6434ec781e9f2679729207d138f775ba99175ae7310558b98ca4dcb9",
    ),
    "SPELL - Build Manual - 2.4.4.pdf": (
        16,
        "6ab753a3c8b07465e92a48ab8c1ab28693062942a456ac540c80baac7e17e9e6",
    ),
    "SPELL-GUI-4.0.2-Build-Instructions.pdf": (
        3,
        "5d8c93bec655499b42f921336640c42eb9dcd68f8979eced3e74758aef71dba6",
    ),
}

CSV_FIELDS = (
    "requirement_id",
    "family",
    "requirement_record_sha256",
    "owner",
    "accountable_owner",
    "required_approvers",
    "verification_methods",
    "primary_design",
    "primary_work_package",
    "supporting_work_packages",
    "phase",
    "supporting_phases",
    "entry_gate",
    "acceptance_gate",
    "supporting_gates",
    "test_target",
    "result_target",
    "approval_status",
    "approval_reference",
)
VALID_WORK_PACKAGES = {f"NG-WP-{number:02d}" for number in range(9)}
VALID_GATES = {f"G{number}" for number in range(10)}
VALID_APPROVAL_STATES = {"OUTSIDE_LOCAL_V04_GATE"}
VALID_OWNER_ROLES = {
    "AS", "CM", "DA", "GA", "LA", "MO", "PO", "QL", "RO", "SA", "SO", "SY"
}
VALID_VERIFICATION_METHODS = {"A", "D", "E", "I", "T"}
COMPATIBILITY_COLUMNS = (
    "ArtifactId", "Kind", "PublicName", "SourceTitle", "SourceVersion",
    "SourceHash", "Pages", "SignatureOrGrammar", "LegacyInputs",
    "LegacyResult", "LegacyOrdering", "LegacyErrors", "EffectClass",
    "ModernBehavior", "Disposition", "Diagnostic", "DriverCapability",
    "Persistence", "Recovery", "SecurityConstraints", "TargetIncrement",
    "TestVectors", "Decision", "Approvers", "Status",
)
REQUIRED_MACHINE_NAMES = {
    "domain", "controller_lease", "execution", "internal_control_command",
    "durable_prompt", "external_driver_operation",
}


@dataclass(frozen=True)
class Requirement:
    requirement_id: str
    statement: str
    verification_methods: str
    owner: str

    @property
    def family(self) -> str:
        return self.requirement_id.split("-", 1)[0]

    @property
    def record_digest(self) -> str:
        canonical = json.dumps(
            {
                "owner": self.owner,
                "requirement_id": self.requirement_id,
                "statement": self.statement,
                "verification_methods": self.verification_methods,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sha256_documentation_tree() -> str:
    digest = hashlib.sha256()
    paths = [
        path
        for path in DOC_ROOT.rglob("*")
        if path.is_file()
        and path != REPORT_PATH
        and "__pycache__" not in path.parts
    ]
    paths.sort(key=lambda path: path.relative_to(DOC_ROOT).as_posix())
    for path in paths:
        relative = path.relative_to(DOC_ROOT).as_posix().encode("utf-8")
        content_digest = sha256_file(path).encode("ascii")
        digest.update(str(len(relative)).encode("ascii"))
        digest.update(b":")
        digest.update(relative)
        digest.update(b":")
        digest.update(content_digest)
        digest.update(b"\n")
    return digest.hexdigest()


def parse_requirements() -> list[Requirement]:
    requirements: list[Requirement] = []
    for line_number, line in enumerate(read_text(REQUIREMENTS_PATH).splitlines(), 1):
        if not REQUIREMENT_ROW_PATTERN.match(line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            raise ValueError(
                f"{REQUIREMENTS_PATH}:{line_number}: expected four requirement cells"
            )
        requirement_id, statement, methods, owner = cells
        requirements.append(
            Requirement(requirement_id, statement, methods, owner)
        )
    return requirements


def load_rules() -> dict[str, Any]:
    return json.loads(read_text(RULES_PATH))


def load_approval_evidence() -> dict[str, Any]:
    return json.loads(read_text(APPROVAL_EVIDENCE_PATH))


def validate_rules(rules: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if rules.get("schema_version") != "ng-spell-implementation-allocation-rules/3":
        errors.append("unsupported implementation-allocation rules schema")
    if rules.get("status") != "APPROVED_LOCAL_ENGINEERING_INPUT":
        errors.append("allocation rules are not the approved local engineering input")
    if not isinstance(rules.get("baseline"), str) or not rules["baseline"]:
        errors.append("allocation rules baseline must be non-empty")

    g0 = rules.get("g0", {})
    if g0.get("approval_evidence_path") != (
        "quality/G0_HUMAN_APPROVAL_LEDGER.json"
    ):
        errors.append("G0 approval evidence must use the separate controlled ledger")
    if len(set(g0.get("blocking_decisions", []))) != len(
        g0.get("blocking_decisions", [])
    ):
        errors.append("G0 blocking decisions contain duplicates")
    if g0.get("blocking_decisions") != []:
        errors.append("local G0 cannot retain organization-only decision blockers")
    if g0.get("gate_ids") != ["G0", "V04-GATE-0"]:
        errors.append("local G0 gate identifiers differ")
    if g0.get("scope_profile") != "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR":
        errors.append("local G0 scope profile differs")
    if g0.get("approval_mode") != "RECORDED_PROJECT_OWNER_ATTESTATION":
        errors.append("local G0 approval mode differs")
    if g0.get("base_product_commit") != (
        "7bccbb4eb096b22d0d1f2f765d5172f6dde244f1"
    ):
        errors.append("local G0 base product commit differs")
    if g0.get("required_signer_roles") != ["Project owner"]:
        errors.append("local G0 requires only the project-owner record")
    if g0.get("required_adrs") != []:
        errors.append("broader proposed ADR approvals are outside local G0")
    excluded_decisions = g0.get("organization_decisions_excluded_from_local_gate")
    if (
        not isinstance(excluded_decisions, list)
        or len(excluded_decisions) != len(set(excluded_decisions))
        or len(excluded_decisions) != 10
    ):
        errors.append("local G0 must identify ten excluded organization decisions")
    if g0.get("retained_engineering_gates") != list(RETAINED_ENGINEERING_GATES):
        errors.append("local G0 retained engineering gates differ")
    if g0.get("required_python") != "3.13":
        errors.append("G0 qualification must pin Python 3.13")

    for family, allocation in rules.get("families", {}).items():
        errors.extend(validate_rule_allocation(f"family {family}", allocation))
    for index, override in enumerate(rules.get("overrides", []), 1):
        errors.extend(validate_rule_allocation(f"override {index}", override, partial=True))
    return errors


def validate_rule_allocation(
    label: str, allocation: dict[str, Any], partial: bool = False
) -> list[str]:
    errors: list[str] = []
    if not partial:
        required = {
            "primary_design", "primary_work_package", "supporting_work_packages",
            "phase", "acceptance_gate",
        }
        missing = sorted(required - set(allocation))
        if missing:
            errors.append(f"{label}: missing allocation fields {missing}")
    packages = allocation.get("supporting_work_packages")
    if packages is not None:
        if not isinstance(packages, list) or len(packages) != len(set(packages)):
            errors.append(f"{label}: supporting work packages must be unique list")
        elif set(packages) - VALID_WORK_PACKAGES:
            errors.append(f"{label}: invalid supporting work package")
        if allocation.get("primary_work_package") in packages:
            errors.append(f"{label}: primary work package repeated as supporting")
    primary_package = allocation.get("primary_work_package")
    if primary_package is not None and primary_package not in VALID_WORK_PACKAGES:
        errors.append(f"{label}: invalid primary work package")
    phase = allocation.get("phase")
    if phase is not None and (not isinstance(phase, int) or phase not in range(9)):
        errors.append(f"{label}: phase must be an integer from 0 through 8")
    supporting_phases = allocation.get("supporting_phases", [])
    if not isinstance(supporting_phases, list) or len(supporting_phases) != len(
        set(supporting_phases)
    ) or any(not isinstance(value, int) or value not in range(9) for value in supporting_phases):
        errors.append(f"{label}: invalid or duplicate supporting phases")
    gate = allocation.get("acceptance_gate")
    if gate is not None and gate not in VALID_GATES:
        errors.append(f"{label}: invalid acceptance gate")
    supporting_gates = allocation.get("supporting_gates", [])
    if not isinstance(supporting_gates, list) or len(supporting_gates) != len(
        set(supporting_gates)
    ) or set(supporting_gates) - VALID_GATES:
        errors.append(f"{label}: invalid or duplicate supporting gates")
    if "required_approvers" in allocation:
        errors.extend(
            validate_approver_list(allocation["required_approvers"], label)
        )
    return errors


def validate_approver_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{label}: required approvers must be a non-empty role list"]
    roles = [role.strip() for role in value.split(",")]
    if (
        any(not role for role in roles)
        or len(roles) != len(set(roles))
        or set(roles) - VALID_OWNER_ROLES
    ):
        return [f"{label}: invalid or duplicate required approver roles {roles}"]
    return []


def validate_approval_evidence(
    evidence: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    expected_keys = {
        "schema_version", "status", "gate_ids", "scope_profile", "approval",
        "compatibility_disposition", "baseline_binding",
        "retained_engineering_gates", "claims",
        "approval_record_sha256",
    }
    if set(evidence) != expected_keys:
        errors.append(
            "G0 owner-approval record fields differ: "
            f"missing={sorted(expected_keys - set(evidence))}, "
            f"extra={sorted(set(evidence) - expected_keys)}"
        )
    if evidence.get("schema_version") != "ng-spell-g0-owner-approval-record/4":
        errors.append("unsupported G0 owner-approval record schema")
    if evidence.get("status") != (
        "OWNER_SCOPE_APPROVED_IMPLEMENTATION_AUTHORIZED"
    ):
        errors.append("G0 owner-approval record status differs")
    if evidence.get("gate_ids") != ["G0", "V04-GATE-0"]:
        errors.append("G0 owner-approval record gate IDs differ")
    if evidence.get("scope_profile") != LOCAL_SCOPE_PROFILE:
        errors.append("G0 owner-approved scope profile differs")

    expected_approval = {
        "owner_name": "JC Arcaz",
        "owner_role": "Project owner",
        "recorded_date": "2026-07-18",
        "source": "Direct project-owner instruction in this project conversation",
        "authorization_text": OWNER_AUTHORIZATION_TEXT,
        "decision": "APPROVE_CANDIDATE_A_LOCAL_ENGINEERING_SCOPE",
        "worker_isolation_decision": (
            "BOUNDED_NON_EXECUTING_IR_AND_STRICT_MTLS_CREDENTIAL_SEPARATION"
        ),
        "worker_isolation_residual_risk": (
            "For this local synthetic scope, a shared development network route "
            "may exist; no product call path or usable driver credential may be "
            "available to the worker, and driver authentication must fail closed."
        ),
        "cryptographic_signature": None,
        "identity_verification": (
            "DIRECT_USER_INSTRUCTION_NOT_CRYPTOGRAPHICALLY_VERIFIED"
        ),
    }
    if evidence.get("approval") != expected_approval:
        errors.append("G0 owner approval does not match the recorded instruction")
    if evidence.get("compatibility_disposition") != COMPATIBILITY_DISPOSITION:
        errors.append("G0 compatibility scope-disposition policy differs")

    binding = evidence.get("baseline_binding", {})
    expected_binding_keys = {
        "binding_kind", "base_product_commit", "tag", "artifacts",
        "manifest_sha256", "note",
    }
    if not isinstance(binding, dict) or set(binding) != expected_binding_keys:
        errors.append("G0 local baseline binding fields differ")
    if binding.get("binding_kind") != "SHA256_FILE_MANIFEST":
        errors.append("G0 local baseline must use the SHA-256 file manifest")
    if binding.get("base_product_commit") != (
        "7bccbb4eb096b22d0d1f2f765d5172f6dde244f1"
    ):
        errors.append("G0 local baseline base product commit differs")
    if binding.get("tag") is not None:
        errors.append("working-tree owner approval cannot claim a signed tag")
    if binding.get("note") != (
        "Content digests provide deterministic change detection only; this is "
        "not a cryptographic signature or a signed Git baseline."
    ):
        errors.append("G0 local baseline integrity limitation differs")

    artifacts = binding.get("artifacts")
    manifest_verified = isinstance(artifacts, dict)
    if not isinstance(artifacts, dict):
        errors.append("G0 local baseline artifacts must be an object")
        artifacts = {}
        manifest_verified = False
    if set(artifacts) != set(LOCAL_BASELINE_ARTIFACTS):
        errors.append("G0 local baseline artifact paths differ")
        manifest_verified = False
    for relative_path in LOCAL_BASELINE_ARTIFACTS:
        expected_digest = artifacts.get(relative_path)
        path = (WORKSPACE_ROOT / relative_path).resolve()
        if not path.is_file():
            errors.append(f"G0 local baseline artifact is missing: {relative_path}")
            manifest_verified = False
            continue
        actual_digest = sha256_file(path)
        if expected_digest != actual_digest:
            errors.append(f"G0 local baseline artifact changed: {relative_path}")
            manifest_verified = False
    expected_manifest_digest = canonical_sha256(artifacts)
    if binding.get("manifest_sha256") != expected_manifest_digest:
        errors.append("G0 local baseline manifest digest differs")
        manifest_verified = False

    if evidence.get("retained_engineering_gates") != list(
        RETAINED_ENGINEERING_GATES
    ):
        errors.append("G0 owner record retained engineering gates differ")
    expected_claims = {
        "scope_approved": True,
        "implementation_authorized": True,
        "release_accepted": False,
        "operational_authorization": False,
        "compliance_determination": False,
        "cryptographic_signature_verified": False,
    }
    if evidence.get("claims") != expected_claims:
        errors.append("G0 owner record claims differ")

    record_payload = {
        key: value
        for key, value in evidence.items()
        if key != "approval_record_sha256"
    }
    if evidence.get("approval_record_sha256") != canonical_sha256(record_payload):
        errors.append("G0 owner-approval record digest differs")

    record_valid = not errors
    return errors, {
        "status": evidence.get("status", "UNKNOWN"),
        "approval_mode": "RECORDED_PROJECT_OWNER_ATTESTATION",
        "owner_name": evidence.get("approval", {}).get("owner_name", "UNKNOWN"),
        "owner_scope_approval_valid": record_valid,
        "manifest_verified": manifest_verified,
        "cryptographic_signature_verified": False,
        "identity_cryptographically_verified": False,
        "compatibility_scope_approval_verified": record_valid and manifest_verified,
        "records_present": 1 if evidence.get("approval") else 0,
    }


def validate_runtime(
    rules: dict[str, Any], actual_version: str | None = None
) -> list[str]:
    required = rules["g0"]["required_python"]
    actual = actual_version or f"{sys.version_info.major}.{sys.version_info.minor}"
    if actual != required:
        return [
            f"qualification runtime is Python {actual}, required Python {required}"
        ]
    return []


def parse_document_allocation_metadata() -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(
        read_text(DOCUMENT_ALLOCATION_PATH).splitlines(), 1
    ):
        match = DOCUMENT_ROW_PATTERN.match(line)
        if not match:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 5:
            raise ValueError(
                f"{DOCUMENT_ALLOCATION_PATH}:{line_number}: "
                "expected five allocation cells"
            )
        path = match.group(1).replace("\\", "/")
        allocated_ids: set[str] = set()
        for start, end in RANGE_PATTERN.findall(cells[2]):
            selector = f"{start}..{end}" if end else start
            allocated_ids.update(expand_selector(selector))
        metadata[path] = {
            "allocated_ids": allocated_ids,
            "required_approvers": cells[4],
        }
    return metadata


def expand_selector(selector: str) -> tuple[str, ...]:
    if ".." not in selector:
        if not REQUIREMENT_ID_PATTERN.fullmatch(selector):
            raise ValueError(f"invalid requirement selector: {selector}")
        return (selector,)
    start, end = selector.split("..", 1)
    start_family, start_number = start.split("-", 1)
    end_family, end_number = end.split("-", 1)
    if start_family != end_family or int(start_number) > int(end_number):
        raise ValueError(f"invalid requirement range: {selector}")
    return tuple(
        f"{start_family}-{number:03d}"
        for number in range(int(start_number), int(end_number) + 1)
    )


def validate_central_register(
    requirements: list[Requirement], rules: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    ids = [requirement.requirement_id for requirement in requirements]
    duplicates = sorted(
        requirement_id
        for requirement_id, count in Counter(ids).items()
        if count > 1
    )
    if duplicates:
        errors.append(f"duplicate central requirement IDs: {', '.join(duplicates)}")

    expected_counts = rules["expected_family_counts"]
    actual_counts = Counter(requirement.family for requirement in requirements)
    if dict(sorted(actual_counts.items())) != dict(sorted(expected_counts.items())):
        errors.append(
            "central family counts differ from allocation rules: "
            f"actual={dict(sorted(actual_counts.items()))} "
            f"expected={dict(sorted(expected_counts.items()))}"
        )

    id_set = set(ids)
    for family, count in expected_counts.items():
        expected_ids = {f"{family}-{number:03d}" for number in range(1, count + 1)}
        missing = sorted(expected_ids - id_set)
        extra = sorted(
            requirement_id
            for requirement_id in id_set
            if requirement_id.startswith(f"{family}-")
            and requirement_id not in expected_ids
        )
        if missing or extra:
            errors.append(
                f"{family} continuity failure: missing={missing}, extra={extra}"
            )

    for requirement in requirements:
        if not requirement.statement:
            errors.append(f"{requirement.requirement_id}: empty statement")
        methods = requirement.verification_methods.split(",")
        if (
            not requirement.verification_methods
            or len(methods) != len(set(methods))
            or set(methods) - VALID_VERIFICATION_METHODS
        ):
            errors.append(
                f"{requirement.requirement_id}: invalid verification methods "
                f"{requirement.verification_methods!r}"
            )
        owners = requirement.owner.split("/")
        if (
            not requirement.owner
            or len(owners) != len(set(owners))
            or set(owners) - VALID_OWNER_ROLES
        ):
            errors.append(
                f"{requirement.requirement_id}: invalid owner roles "
                f"{requirement.owner!r}"
            )
    return errors


def build_expected_allocation(
    requirements: list[Requirement], rules: dict[str, Any]
) -> list[dict[str, str]]:
    requirement_ids = {requirement.requirement_id for requirement in requirements}
    overrides: dict[str, dict[str, Any]] = {}
    for override in rules["overrides"]:
        values = {key: value for key, value in override.items() if key != "selectors"}
        for selector in override["selectors"]:
            for requirement_id in expand_selector(selector):
                if requirement_id not in requirement_ids:
                    raise ValueError(f"override references unknown ID {requirement_id}")
                if requirement_id in overrides:
                    raise ValueError(f"overlapping override for {requirement_id}")
                overrides[requirement_id] = values

    g0 = rules["g0"]
    document_metadata = parse_document_allocation_metadata()
    rows: list[dict[str, str]] = []
    for requirement in requirements:
        allocation = dict(rules["families"][requirement.family])
        allocation.update(overrides.get(requirement.requirement_id, {}))
        primary_design = allocation["primary_design"]
        if primary_design not in document_metadata:
            raise ValueError(f"primary design is not registered: {primary_design}")
        rows.append(
            {
                "requirement_id": requirement.requirement_id,
                "family": requirement.family,
                "requirement_record_sha256": requirement.record_digest,
                "owner": requirement.owner,
                "accountable_owner": (
                    requirement.owner
                    if "/" not in requirement.owner
                    else "PENDING_OWNER_SELECTION"
                ),
                "required_approvers": allocation.get(
                    "required_approvers",
                    document_metadata[primary_design]["required_approvers"],
                ),
                "verification_methods": requirement.verification_methods,
                "primary_design": primary_design,
                "primary_work_package": allocation["primary_work_package"],
                "supporting_work_packages": ";".join(
                    allocation["supporting_work_packages"]
                ),
                "phase": str(allocation["phase"]),
                "supporting_phases": ";".join(
                    str(value) for value in allocation.get("supporting_phases", [])
                ),
                "entry_gate": "G0",
                "acceptance_gate": allocation["acceptance_gate"],
                "supporting_gates": ";".join(
                    allocation.get("supporting_gates", [])
                ),
                "test_target": f"NGV-{requirement.requirement_id}",
                "result_target": f"NGR-{requirement.requirement_id}",
                "approval_status": "OUTSIDE_LOCAL_V04_GATE",
                "approval_reference": g0["approval_evidence_path"],
            }
        )
    return rows


def write_allocation(rows: list[dict[str, str]]) -> None:
    with ALLOCATION_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_allocation() -> tuple[list[dict[str, str]], list[str]]:
    errors: list[str] = []
    if not ALLOCATION_PATH.exists():
        return [], [f"missing generated allocation: {ALLOCATION_PATH}"]
    with ALLOCATION_PATH.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != CSV_FIELDS:
            errors.append(
                f"allocation columns differ: actual={reader.fieldnames}, "
                f"expected={list(CSV_FIELDS)}"
            )
        return list(reader), errors


def validate_allocation(
    actual: list[dict[str, str]], expected: list[dict[str, str]]
) -> list[str]:
    errors: list[str] = []
    document_metadata = parse_document_allocation_metadata()
    actual_by_id: dict[str, dict[str, str]] = {}
    for row in actual:
        requirement_id = row.get("requirement_id", "")
        if requirement_id in actual_by_id:
            errors.append(f"duplicate allocation row: {requirement_id}")
        actual_by_id[requirement_id] = row
    expected_by_id = {row["requirement_id"]: row for row in expected}
    missing = sorted(set(expected_by_id) - set(actual_by_id))
    extra = sorted(set(actual_by_id) - set(expected_by_id))
    if missing or extra:
        errors.append(f"allocation coverage mismatch: missing={missing}, extra={extra}")

    for requirement_id in sorted(set(expected_by_id) & set(actual_by_id)):
        actual_row = actual_by_id[requirement_id]
        expected_row = expected_by_id[requirement_id]
        for field in CSV_FIELDS:
            if actual_row.get(field, "") != expected_row[field]:
                errors.append(
                    f"{requirement_id}: {field}={actual_row.get(field)!r}, "
                    f"expected {expected_row[field]!r}"
                )
        design_path = DOC_ROOT / actual_row["primary_design"]
        if not design_path.is_file():
            errors.append(
                f"{requirement_id}: primary design does not exist: "
                f"{actual_row['primary_design']}"
            )
        design_allocation = document_metadata.get(actual_row["primary_design"])
        if (
            design_allocation is None
            or requirement_id not in design_allocation["allocated_ids"]
        ):
            errors.append(
                f"{requirement_id}: primary design is not allocated this requirement: "
                f"{actual_row['primary_design']}"
            )
        packages = [actual_row["primary_work_package"]]
        packages.extend(
            value
            for value in actual_row["supporting_work_packages"].split(";")
            if value
        )
        if len(packages) != len(set(packages)):
            errors.append(f"{requirement_id}: duplicate work-package allocation")
        invalid_packages = sorted(set(packages) - VALID_WORK_PACKAGES)
        if invalid_packages:
            errors.append(
                f"{requirement_id}: invalid work packages: {invalid_packages}"
            )
        if actual_row["entry_gate"] not in VALID_GATES:
            errors.append(f"{requirement_id}: invalid entry gate")
        if actual_row["acceptance_gate"] not in VALID_GATES:
            errors.append(f"{requirement_id}: invalid acceptance gate")
        supporting_gates = [
            value for value in actual_row["supporting_gates"].split(";") if value
        ]
        if (
            len(supporting_gates) != len(set(supporting_gates))
            or set(supporting_gates) - VALID_GATES
        ):
            errors.append(f"{requirement_id}: invalid supporting gates")
        supporting_phases = [
            value for value in actual_row["supporting_phases"].split(";") if value
        ]
        if (
            len(supporting_phases) != len(set(supporting_phases))
            or any(not value.isdigit() or int(value) not in range(9) for value in supporting_phases)
        ):
            errors.append(f"{requirement_id}: invalid supporting phases")
        if not actual_row["phase"].isdigit() or int(actual_row["phase"]) not in range(9):
            errors.append(f"{requirement_id}: invalid primary phase")
        if actual_row["approval_status"] not in VALID_APPROVAL_STATES:
            errors.append(f"{requirement_id}: invalid approval status")
        if actual_row["approval_reference"] != (
            "quality/G0_HUMAN_APPROVAL_LEDGER.json"
        ):
            errors.append(f"{requirement_id}: approval must use the separate ledger")
        errors.extend(
            validate_approver_list(
                actual_row["required_approvers"], requirement_id
            )
        )

    for field in ("test_target", "result_target"):
        values = [row.get(field, "") for row in actual]
        if len(values) != len(set(values)):
            errors.append(f"allocation {field} values are not unique")
    return errors


def validate_document_inventory() -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    allocated: list[str] = []
    for line in read_text(DOCUMENT_ALLOCATION_PATH).splitlines():
        match = DOCUMENT_ROW_PATTERN.match(line)
        if match:
            allocated.append(match.group(1).replace("\\", "/"))
    duplicates = sorted(path for path, count in Counter(allocated).items() if count > 1)
    markdown_paths = sorted(
        path.relative_to(DOC_ROOT).as_posix() for path in DOC_ROOT.rglob("*.md")
    )
    missing = sorted(set(markdown_paths) - set(allocated))
    extra = sorted(set(allocated) - set(markdown_paths))
    if duplicates:
        errors.append(f"duplicate Markdown allocations: {duplicates}")
    if missing or extra:
        errors.append(f"Markdown allocation mismatch: missing={missing}, extra={extra}")

    known_ids = {
        requirement.requirement_id for requirement in parse_requirements()
    }
    for line_number, line in enumerate(
        read_text(DOCUMENT_ALLOCATION_PATH).splitlines(), 1
    ):
        if not DOCUMENT_ROW_PATTERN.match(line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 5:
            errors.append(
                f"{DOCUMENT_ALLOCATION_PATH}:{line_number}: "
                "expected five allocation cells"
            )
            continue
        for start, end in RANGE_PATTERN.findall(cells[2]):
            selector = f"{start}..{end}" if end else start
            try:
                expanded = expand_selector(selector)
            except ValueError as exc:
                errors.append(
                    f"{DOCUMENT_ALLOCATION_PATH}:{line_number}: {exc}"
                )
                continue
            unknown = sorted(set(expanded) - known_ids)
            if unknown:
                errors.append(
                    f"{DOCUMENT_ALLOCATION_PATH}:{line_number}: unknown IDs {unknown}"
                )
    return errors, {
        "markdown_paths": len(markdown_paths),
        "allocated_paths": len(allocated),
    }


def validate_relative_links() -> tuple[list[str], int]:
    errors: list[str] = []
    checked = 0
    for markdown_path in DOC_ROOT.rglob("*.md"):
        text = read_text(markdown_path)
        for target in MARKDOWN_LINK_PATTERN.findall(text):
            target = target.strip().strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            path_part = unquote(target.split("#", 1)[0])
            if not path_part:
                continue
            checked += 1
            resolved = (markdown_path.parent / path_part).resolve()
            if not resolved.exists():
                errors.append(
                    f"{markdown_path.relative_to(WORKSPACE_ROOT)}: "
                    f"missing link target {target}"
                )
    return errors, checked


def split_table_cells(line: str) -> list[str]:
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    cells.append("".join(current).strip())
    if cells and not cells[0]:
        cells.pop(0)
    if cells and not cells[-1]:
        cells.pop()
    return cells


def validate_markdown_structure() -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    table_count = 0
    markdown_files = sorted(DOC_ROOT.rglob("*.md"))
    separator_pattern = re.compile(r"^:?-{3,}:?$")
    fence_pattern = re.compile(r"^\s*(`{3,}|~{3,})")

    for path in markdown_files:
        lines = read_text(path).splitlines()
        relative = path.relative_to(DOC_ROOT)
        fence_marker: str | None = None
        heading_levels: list[tuple[int, int]] = []
        table_block: list[tuple[int, str]] = []

        def flush_table() -> None:
            nonlocal table_count
            if not table_block:
                return
            table_count += 1
            if len(table_block) < 2:
                errors.append(
                    f"{relative}:{table_block[0][0]}: incomplete Markdown table"
                )
                table_block.clear()
                return
            parsed = [split_table_cells(line) for _, line in table_block]
            expected_cells = len(parsed[0])
            for (line_number, _), cells in zip(table_block, parsed):
                if len(cells) != expected_cells:
                    errors.append(
                        f"{relative}:{line_number}: table has {len(cells)} cells, "
                        f"expected {expected_cells}"
                    )
            if not all(separator_pattern.fullmatch(cell) for cell in parsed[1]):
                errors.append(
                    f"{relative}:{table_block[1][0]}: invalid table separator row"
                )
            table_block.clear()

        for line_number, line in enumerate(lines, 1):
            fence_match = fence_pattern.match(line)
            if fence_match:
                marker = fence_match.group(1)
                if fence_marker is None:
                    flush_table()
                    fence_marker = marker
                elif marker[0] == fence_marker[0] and len(marker) >= len(fence_marker):
                    fence_marker = None
                continue
            if fence_marker is not None:
                continue
            heading_match = re.match(r"^(#{1,6})\s+\S", line)
            if heading_match:
                flush_table()
                heading_levels.append((line_number, len(heading_match.group(1))))
            if line.startswith("|"):
                table_block.append((line_number, line))
            else:
                flush_table()
        flush_table()

        if fence_marker is not None:
            errors.append(f"{relative}: unclosed fenced block")
        if not heading_levels or heading_levels[0][1] != 1:
            errors.append(f"{relative}: first heading must be level 1")
        for previous, current in zip(heading_levels, heading_levels[1:]):
            if current[1] > previous[1] + 1:
                errors.append(
                    f"{relative}:{current[0]}: heading level jumps from "
                    f"{previous[1]} to {current[1]}"
                )
    return errors, {"markdown_files": len(markdown_files), "tables": table_count}


def validate_source_hashes() -> tuple[list[str], int]:
    errors: list[str] = []
    checked = 0
    titles: list[str] = []
    targets: list[str] = []
    page_total = 0
    observed_evidence: dict[str, tuple[int, str]] = {}
    source_lines = read_text(SOURCE_AUTHORITY_PATH).splitlines()
    for line_number, line in enumerate(source_lines, 1):
        match = SOURCE_ROW_PATTERN.match(line)
        if not match:
            continue
        title, encoded_target, pages, expected_digest = match.groups()
        titles.append(title)
        targets.append(unquote(encoded_target))
        page_total += int(pages)
        observed_evidence[title] = (int(pages), expected_digest)
        source_path = (SOURCE_AUTHORITY_PATH.parent / unquote(encoded_target)).resolve()
        if not source_path.is_file():
            errors.append(
                f"{SOURCE_AUTHORITY_PATH}:{line_number}: missing source {source_path}"
            )
            continue
        checked += 1
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if digest != expected_digest:
            errors.append(
                f"{SOURCE_AUTHORITY_PATH}:{line_number}: "
                f"digest mismatch for {source_path.name}"
            )
    if checked != 7:
        errors.append(f"expected seven source hash checks, completed {checked}")
    if len(titles) != len(set(titles)) or len(targets) != len(set(targets)):
        errors.append("source authority rows must have unique titles and targets")
    if page_total != 304:
        errors.append(f"source authority page total is {page_total}, expected 304")
    if observed_evidence != EXPECTED_SOURCE_EVIDENCE:
        errors.append("source authority metadata differs from the pinned evidence set")
    return errors, checked


def validate_state_models(known_ids: set[str]) -> tuple[list[str], int]:
    errors: list[str] = []
    try:
        models = json.loads(read_text(STATE_MODELS_PATH))
    except json.JSONDecodeError as exc:
        return [f"invalid state-machine JSON: {exc}"], 0
    requirement_ids = models.get("requirements")
    if not isinstance(requirement_ids, list):
        return ["state-machine JSON requirements must be a list"], 0
    unknown = sorted(set(requirement_ids) - known_ids)
    if unknown:
        errors.append(f"state-machine JSON references unknown requirements: {unknown}")
    if models.get("status") != "draft":
        errors.append("state-machine JSON status must remain draft before G0 approval")

    required_top_level = {
        "schema_version", "document_id", "status", "requirements",
        "model_contract", "actors", "identity_fences", "safe_points",
        "effect_certainty", "machines", "global_invariants",
    }
    missing_top_level = sorted(required_top_level - set(models))
    if missing_top_level:
        errors.append(f"state-machine JSON missing keys: {missing_top_level}")

    actors = models.get("actors", [])
    actor_ids = [actor.get("id") for actor in actors if isinstance(actor, dict)]
    if not actors or len(actor_ids) != len(actors) or len(actor_ids) != len(set(actor_ids)):
        errors.append("state-machine actors must be non-empty with unique IDs")
    for collection_name, identifier in (
        ("identity_fences", "name"), ("safe_points", "id")
    ):
        collection = models.get(collection_name, [])
        identifiers = [
            item.get(identifier) for item in collection if isinstance(item, dict)
        ]
        if (
            not collection
            or len(identifiers) != len(collection)
            or len(identifiers) != len(set(identifiers))
        ):
            errors.append(
                f"state-machine {collection_name} must be non-empty with unique IDs"
            )

    machines = models.get("machines")
    if not isinstance(machines, dict):
        errors.append("state-machine machines must be an object")
        return errors, len(requirement_ids)
    missing_machines = sorted(REQUIRED_MACHINE_NAMES - set(machines))
    if missing_machines:
        errors.append(f"state-machine JSON missing machines: {missing_machines}")
    transition_ids: list[str] = []
    for machine_name, machine in machines.items():
        if not isinstance(machine, dict):
            errors.append(f"state machine {machine_name} must be an object")
            continue
        if machine.get("machine_id") != machine_name:
            errors.append(f"state machine {machine_name} has mismatched machine_id")
        states = machine.get("states", [])
        state_names = [
            state.get("name") for state in states if isinstance(state, dict)
        ]
        if (
            not states
            or len(state_names) != len(states)
            or len(state_names) != len(set(state_names))
        ):
            errors.append(f"state machine {machine_name} has invalid states")
            continue
        if machine.get("initial_state") not in set(state_names):
            errors.append(f"state machine {machine_name} has invalid initial state")
        transitions = machine.get("transitions", [])
        if not transitions:
            errors.append(f"state machine {machine_name} has no transitions")
            continue
        outgoing: set[str] = set()
        for transition in transitions:
            if not isinstance(transition, dict):
                errors.append(f"state machine {machine_name} has invalid transition")
                continue
            transition_id = transition.get("id")
            transition_ids.append(transition_id)
            sources = transition.get("from", [])
            actors_for_transition = transition.get("actor", [])
            if (
                not transition_id
                or not isinstance(sources, list)
                or not sources
                or set(sources) - set(state_names)
                or transition.get("to") not in set(state_names)
            ):
                errors.append(
                    f"state machine {machine_name} transition {transition_id!r} "
                    "has invalid state references"
                )
            if (
                not isinstance(actors_for_transition, list)
                or not actors_for_transition
                or set(actors_for_transition) - set(actor_ids)
            ):
                errors.append(
                    f"state machine {machine_name} transition {transition_id!r} "
                    "has invalid actors"
                )
            outgoing.update(sources)
        terminal_states = {
            state["name"] for state in states if state.get("terminal") is True
        }
        invalid_terminal = sorted(terminal_states & outgoing)
        if invalid_terminal:
            errors.append(
                f"state machine {machine_name} terminal states have outgoing "
                f"transitions: {invalid_terminal}"
            )
    if len(transition_ids) != len(set(transition_ids)):
        errors.append("state-machine transition IDs must be globally unique")
    return errors, len(requirement_ids)


def validate_ascii() -> tuple[list[str], int]:
    errors: list[str] = []
    checked = 0
    suffixes = {".md", ".json", ".csv", ".py", ".css", ".html", ".cjs", ".txt"}
    for path in DOC_ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        checked += 1
        text = read_text(path)
        if any(ord(character) > 127 for character in text):
            errors.append(f"non-ASCII content: {path.relative_to(DOC_ROOT)}")
    return errors, checked


def validate_gate_input_structure(
    rules: dict[str, Any]
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    open_decisions = {
        match.group(1)
        for line in read_text(OPEN_DECISIONS_PATH).splitlines()
        if (match := OPEN_DECISION_PATTERN.match(line))
    }
    required_decisions = set(rules["g0"]["blocking_decisions"])
    missing_decisions = sorted(required_decisions - open_decisions)
    if missing_decisions:
        errors.append(
            f"open-decision register is missing G0 decisions: {missing_decisions}"
        )

    checklist_roles: list[str] = []
    in_signoff_table = False
    for line in read_text(CHECKLIST_PATH).splitlines():
        cells = split_table_cells(line) if line.startswith("|") else []
        if cells == [
            "Role", "Name", "Decision", "Date", "Baseline/tag",
            "Findings reference",
        ]:
            in_signoff_table = True
            continue
        if in_signoff_table and cells:
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                continue
            checklist_roles.append(cells[0])
        elif in_signoff_table:
            break
    required_roles = rules["g0"]["required_signer_roles"]
    if checklist_roles != required_roles:
        errors.append(
            "required-signoff role rows differ from the controlled role list: "
            f"actual={checklist_roles}, expected={required_roles}"
        )

    required_adrs = set(rules["g0"]["required_adrs"])
    actual_adrs = {path.name for path in ADR_DIRECTORY.glob("ADR-*.md")}
    if not required_adrs.issubset(actual_adrs):
        errors.append(
            "ADR approval targets differ: "
            f"missing={sorted(required_adrs - actual_adrs)}, "
            f"available={sorted(actual_adrs)}"
        )
    return errors, {
        "open_decisions_total": len(open_decisions),
        "required_g0_decisions": len(required_decisions),
        "organization_decisions_excluded": len(
            rules["g0"]["organization_decisions_excluded_from_local_gate"]
        ),
        "required_signer_roles": len(required_roles),
        "required_adrs": len(required_adrs),
        "available_proposed_adrs": len(actual_adrs),
    }


def analyze_compatibility_evidence(
    text: str | None = None,
) -> tuple[list[str], dict[str, Any]]:
    if text is None:
        return validate_compatibility.validate_repository()

    errors: list[str] = []
    lines = text.splitlines()
    header_index: int | None = None
    header: list[str] = []
    for index, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = split_table_cells(line)
        if cells and cells[0] == "ArtifactId":
            header_index = index
            header = cells
            break
    if header_index is None:
        return errors, {
            "schema_present": False,
            "schema_valid": False,
            "row_count": 0,
            "approved_rows": 0,
            "scope_reconciled": False,
        }
    if tuple(header) != COMPATIBILITY_COLUMNS:
        errors.append(
            "detailed compatibility table columns differ from the required schema"
        )

    rows: list[list[str]] = []
    for line in lines[header_index + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(split_table_cells(line))
    artifact_ids = [row[0] for row in rows if row]
    if any(len(row) != len(COMPATIBILITY_COLUMNS) for row in rows):
        errors.append("detailed compatibility rows have inconsistent columns")
    if len(artifact_ids) != len(set(artifact_ids)):
        errors.append("detailed compatibility ArtifactId values are not unique")
    approved_rows = sum(
        1
        for row in rows
        if len(row) == len(COMPATIBILITY_COLUMNS) and row[-1] == "Approved"
    )
    return errors, {
        "schema_present": True,
        "schema_valid": tuple(header) == COMPATIBILITY_COLUMNS,
        "row_count": len(rows),
        "approved_rows": approved_rows,
        "scope_reconciled": False,
    }


def collect_gate_blockers(
    actual_allocation: list[dict[str, str]],
    rules: dict[str, Any],
    evidence_summary: dict[str, Any],
    compatibility_summary: dict[str, Any],
    gate_input_summary: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    unresolved_entry_decisions = sorted(rules["g0"]["blocking_decisions"])
    if unresolved_entry_decisions:
        blockers.append(
            {
                "code": "OPEN_LOCAL_GATE_DECISIONS",
                "count": len(unresolved_entry_decisions),
                "items": unresolved_entry_decisions,
            }
        )

    broader_spec_rows = sorted(
        row["requirement_id"]
        for row in actual_allocation
        if row.get("approval_status") == "OUTSIDE_LOCAL_V04_GATE"
    )
    composite_owners = sorted(
        row["requirement_id"]
        for row in actual_allocation
        if row.get("accountable_owner") == "PENDING_OWNER_SELECTION"
    )

    if not evidence_summary.get("owner_scope_approval_valid", False):
        blockers.append(
            {
                "code": "OWNER_SCOPE_APPROVAL_RECORD_INVALID",
                "count": 1,
            }
        )
    if not evidence_summary.get("manifest_verified", False):
        blockers.append(
            {
                "code": "LOCAL_BASELINE_MANIFEST_INVALID",
                "count": 1,
                "required": "exact SHA-256 bindings for the owner-approved scope",
            }
        )

    compatibility_ready = (
        compatibility_summary["schema_valid"]
        and compatibility_summary["row_count"] > 0
        and compatibility_summary["scope_reconciled"]
        and compatibility_summary.get("global_reconciled", False)
        and compatibility_summary.get("technical_review_verified", False)
        and compatibility_summary.get("source_count", 0) == 7
        and compatibility_summary["approved_rows"]
        == compatibility_summary["row_count"]
        and evidence_summary.get(
            "compatibility_scope_approval_verified", False
        )
    )
    if not compatibility_ready:
        blockers.append(
            {
                "code": "DETAILED_COMPATIBILITY_EVIDENCE_INCOMPLETE",
                "count": 1,
                "observed_rows": compatibility_summary["row_count"],
                "candidate_scope_reconciled": compatibility_summary.get(
                    "candidate_scope_reconciled", False
                ),
                "represented_sources": compatibility_summary.get(
                    "source_count", 0
                ),
                "required_sources": 7,
                "approved_rows": compatibility_summary["approved_rows"],
                "global_reconciled": compatibility_summary.get(
                    "global_reconciled", False
                ),
                "technical_review_verified": compatibility_summary.get(
                    "technical_review_verified", False
                ),
                "verified_scope_approval": evidence_summary.get(
                    "compatibility_scope_approval_verified", False
                ),
                "required_rows": "exhaustive seven-source disposition catalog",
                "required": (
                    "full seven-source schema, unique rows, source and example "
                    "count reconciliation, source-grounded classifications, "
                    "Candidate A or Deferred/EXCLUDE dispositions, errata "
                    "handling, unique planned test identities, independent "
                    "technical validation, and exact scope-manifest binding"
                ),
            }
        )

    summary = {
        "open_decisions_total": gate_input_summary["open_decisions_total"],
        "unresolved_g0_decisions": len(unresolved_entry_decisions),
        "unresolved_local_entry_decisions": unresolved_entry_decisions,
        "organization_decisions_excluded": gate_input_summary[
            "organization_decisions_excluded"
        ],
        "broader_spec_rows_outside_local_gate": len(broader_spec_rows),
        "broader_spec_composite_owners_outside_local_gate": len(composite_owners),
        "required_owner_records": gate_input_summary["required_signer_roles"],
        "required_local_adrs": gate_input_summary["required_adrs"],
        "detailed_compatibility": compatibility_summary,
        "approval_evidence": evidence_summary,
    }
    return blockers, summary


def extend(errors: list[str], result: tuple[list[str], Any]) -> Any:
    new_errors, detail = result
    errors.extend(new_errors)
    return detail


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


def report_input_digests() -> dict[str, str]:
    paths = {
        "allocation_csv": ALLOCATION_PATH,
        "allocation_rules": RULES_PATH,
        "approval_ledger": APPROVAL_EVIDENCE_PATH,
        "compatibility_ledger": COMPATIBILITY_PATH,
        "compatibility_source_inventory": COMPATIBILITY_INVENTORY_PATH,
        "detailed_compatibility_ledger": DETAILED_COMPATIBILITY_PATH,
        "compatibility_scope_v0_4": COMPATIBILITY_SCOPE_PATH,
        "compatibility_reconciliation": COMPATIBILITY_RECONCILIATION_PATH,
        "compatibility_validator": Path(
            validate_compatibility.__file__
        ).resolve(),
        "document_allocation": DOCUMENT_ALLOCATION_PATH,
        "document_control": DOCUMENT_CONTROL_PATH,
        "requirements_register": REQUIREMENTS_PATH,
        "source_authority": SOURCE_AUTHORITY_PATH,
        "state_models": STATE_MODELS_PATH,
        "validator": Path(__file__).resolve(),
    }
    digests = {name: sha256_file(path) for name, path in sorted(paths.items())}
    digests["candidate_documentation_tree"] = sha256_documentation_tree()
    return dict(sorted(digests.items()))


def validate_report_freshness(report: dict[str, Any]) -> list[str]:
    if not REPORT_PATH.is_file():
        return ["canonical G0 readiness report is missing"]
    try:
        existing = json.loads(read_text(REPORT_PATH))
    except json.JSONDecodeError as exc:
        return [f"canonical G0 readiness report is invalid JSON: {exc}"]
    if existing != report:
        return [
            "canonical G0 readiness report is stale; regenerate it with "
            "--write-report quality/G0_READINESS_REPORT.json"
        ]
    return []


def resolve_report_destination(value: Path) -> Path:
    destination = value if value.is_absolute() else DOC_ROOT / value
    destination = destination.resolve()
    if destination != REPORT_PATH.resolve():
        raise ValueError(
            "--write-report must target quality/G0_READINESS_REPORT.json"
        )
    return destination


def determine_exit_code(
    structural_errors: list[str],
    authorization_blockers: list[dict[str, Any]],
    structural_only: bool,
) -> int:
    if structural_errors:
        return 1
    if structural_only:
        return 0
    if authorization_blockers:
        return 2
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--generate-allocation",
        action="store_true",
        help="regenerate IMPLEMENTATION_ALLOCATION.csv from the controlled rules",
    )
    parser.add_argument(
        "--write-report",
        type=Path,
        help=(
            "write the deterministic readiness report relative to the "
            "documentation root"
        ),
    )
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="return success for structural PASS even when a technical gate blocks",
    )
    parser.add_argument("--strict-g0", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(list(argv) if argv is not None else None)
    report_path: Path | None = None
    if args.write_report:
        try:
            report_path = resolve_report_destination(args.write_report)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    requirements = parse_requirements()
    rules = load_rules()
    approval_evidence = load_approval_evidence()
    errors = validate_rules(rules)
    errors.extend(validate_runtime(rules))
    errors.extend(validate_central_register(requirements, rules))
    evidence_errors, evidence_summary = validate_approval_evidence(
        approval_evidence
    )
    errors.extend(evidence_errors)
    expected_allocation = build_expected_allocation(requirements, rules)
    if args.generate_allocation:
        write_allocation(expected_allocation)

    actual_allocation, read_errors = read_allocation()
    errors.extend(read_errors)
    if actual_allocation:
        errors.extend(validate_allocation(actual_allocation, expected_allocation))

    inventory_summary = extend(errors, validate_document_inventory())
    relative_links = extend(errors, validate_relative_links())
    markdown_structure = extend(errors, validate_markdown_structure())
    source_hashes = extend(errors, validate_source_hashes())
    state_requirements = extend(
        errors,
        validate_state_models(
            {requirement.requirement_id for requirement in requirements}
        ),
    )
    ascii_files = extend(errors, validate_ascii())
    gate_input_summary = extend(errors, validate_gate_input_structure(rules))
    compatibility_summary = extend(errors, analyze_compatibility_evidence())
    blockers, gate_summary = collect_gate_blockers(
        actual_allocation,
        rules,
        evidence_summary,
        compatibility_summary,
        gate_input_summary,
    )

    family_counts = dict(
        sorted(Counter(requirement.family for requirement in requirements).items())
    )
    report = {
        "schema_version": "ng-spell-g0-readiness-report/3",
        "baseline": rules["baseline"],
        "gate": "G0/V04-GATE-0",
        "gate_scope": "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
        "gate_status": (
            "INVALID"
            if errors else ("BLOCKED" if blockers else "PASS")
        ),
        "structural_status": "FAIL" if errors else "PASS",
        "qualification": {
            "required_image": rules["g0"]["qualification_image"],
            "runtime_implementation": platform.python_implementation(),
            "runtime_version": platform.python_version(),
        },
        "input_sha256": report_input_digests(),
        "requirements": {
            "total": len(requirements),
            "family_counts": family_counts,
            "allocation_rows": len(actual_allocation),
        },
        "checks": {
            "ascii_files": ascii_files,
            "document_inventory": inventory_summary,
            "markdown_structure": markdown_structure,
            "relative_links": relative_links,
            "source_hashes": source_hashes,
            "state_model_requirement_references": state_requirements,
            "gate_input_structure": gate_input_summary,
            "compatibility_evidence": compatibility_summary,
        },
        "gate_summary": gate_summary,
        "structural_errors": errors,
        "authorization_blockers": blockers,
        "claims": {
            "product_implementation_started": False,
            "scope_approved_by_project_owner": evidence_summary.get(
                "owner_scope_approval_valid", False
            ),
            "implementation_authorized": not errors and not blockers,
            "g0_approved": not errors and not blockers,
            "release_accepted": False,
            "operational_authorization": False,
            "compliance_determination": False,
            "cryptographic_signature_verified": False,
        },
    }
    if report_path is not None:
        write_report(report_path, report)
    else:
        freshness_errors = validate_report_freshness(report)
        if freshness_errors:
            errors.extend(freshness_errors)
            report["structural_status"] = "FAIL"
            report["gate_status"] = "INVALID"

    print(
        f"structural={report['structural_status']} "
        f"gate={report['gate_status']} requirements={len(requirements)} "
        f"allocation_rows={len(actual_allocation)}"
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    if blockers:
        print(
            "BLOCKED: " + ", ".join(blocker["code"] for blocker in blockers)
        )
    return determine_exit_code(errors, blockers, args.structural_only)


if __name__ == "__main__":
    raise SystemExit(main())
