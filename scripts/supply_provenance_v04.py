#!/usr/bin/env python3
"""Create, validate, and promote strict v0.4 supply-chain evidence corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "spell.v04.supply-provenance/1"
TOOLCHAIN_SCHEMA_VERSION = "spell.v04.release-toolchain/1"
STAGING_DIRECTORY = Path("artifacts/v0.4/.qualification/supply-provenance")
CANONICAL_DIRECTORY = Path("artifacts/v0.4/provenance/supply")
MANIFEST_NAME = "manifest.json"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_CORPUS_BYTES = 128 * 1024 * 1024

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
PROJECT_PATTERN = re.compile(r"spellv04q-[0-9a-f]{24,32}\Z")

PROVENANCE_METRIC_KEYS = frozenset(
    {
        "supply_provenance_schema_version",
        "supply_provenance_run_id",
        "supply_provenance_manifest_sha256",
        "supply_provenance_corpus_sha256",
        "supply_provenance_file_count",
    }
)
SUPPORTED_TEST_IDS = frozenset(
    {"V04-SC-001", "V04-SC-003", "V04-SC-004", "V04-SC-006"}
)
DIRECTORY_NAMES = {
    "V04-SC-001": "sc-001",
    "V04-SC-003": "sc-003",
    "V04-SC-004": "sc-004",
    "V04-SC-006": "sc-006",
}

SC001_FILES = {
    "node-tools.json": "tool-identity",
    "npm-audit.json": "advisory-report",
    "pip-audit-backend.json": "advisory-report",
    "pip-audit-driver.json": "advisory-report",
    "pip-audit-generator.json": "advisory-report",
    "pip-audit-pki.json": "advisory-report",
    "pip-audit-supply.json": "advisory-report",
    "python-tools.json": "tool-identity",
    "scout-backend.sarif.json": "advisory-report",
    "scout-driver.sarif.json": "advisory-report",
    "scout-frontend.sarif.json": "advisory-report",
    "scout-pki_init.sarif.json": "advisory-report",
    "scout-postgres.sarif.json": "advisory-report",
    "scout-proxy.sarif.json": "advisory-report",
    "starlette-policy.json": "policy-report",
}
EXPECTED_ARTIFACTS = {
    "V04-SC-001": SC001_FILES,
    "V04-SC-003": {"image-inspection.json": "inspection-report"},
    "V04-SC-004": {
        "independent-build-1.json": "independent-build-result",
        "independent-build-2.json": "independent-build-result",
    },
    "V04-SC-006": {"lifecycle-cases.json": "lifecycle-case-ledger"},
}
REQUIRED_TOOLS = {
    "V04-SC-001": frozenset(
        {"docker-cli", "docker-compose", "docker-scout", "python"}
    ),
    "V04-SC-003": frozenset({"docker-cli", "docker-compose", "python"}),
    "V04-SC-004": frozenset({"docker-cli", "python"}),
    "V04-SC-006": frozenset({"docker-cli", "docker-compose", "python"}),
}
REQUIRED_IMAGES = {
    "V04-SC-001": frozenset(
        {"audit", "backend", "driver", "frontend", "pki_init", "postgres", "proxy"}
    ),
    "V04-SC-003": frozenset(
        {"backend", "driver", "frontend", "pki_init", "postgres", "probe", "proxy"}
    ),
    "V04-SC-004": frozenset({"generator"}),
    "V04-SC-006": frozenset({"driver_a", "driver_b", "pki_init"}),
}
TOOL_ENVIRONMENT = {
    "docker-cli": "SPELL_RELEASE_DOCKER_EXE",
    "docker-compose": "SPELL_RELEASE_COMPOSE_EXE",
    "docker-scout": "SPELL_RELEASE_SCOUT_EXE",
    "python": "SPELL_RELEASE_PYTHON_EXE",
}
TOOL_VERSION_KEYS = {
    "docker-cli": "docker_cli",
    "docker-compose": "docker_compose",
    "docker-scout": "docker_scout",
    "python": "host_python",
}

SECRET_PATTERNS = (
    re.compile(br"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(br"(?i)authorization\s*:\s*bearer\s+"),
    re.compile(br"(?i)://[^/@\s:]+:[^/@\s]+@"),
    re.compile(br"AKIA[0-9A-Z]{16}"),
    re.compile(br"gh[pousr]_[A-Za-z0-9]{32,}"),
    re.compile(br"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(br"synthetic-qualification-(?:password|jwt-secret)"),
    re.compile(br"spell-v04-service-secret-"),
)


class SupplyProvenanceError(ValueError):
    """A supply provenance corpus violates its closed schema or bindings."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SupplyProvenanceError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupplyProvenanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SupplyProvenanceError(f"non-finite JSON number: {value}")


def _load_json_bytes(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupplyProvenanceError(f"{label} is not UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise SupplyProvenanceError(f"{label} is not strict JSON") from exc


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    _require(
        observed == expected,
        f"{label} fields differ; missing={sorted(expected - observed)!r} "
        f"unexpected={sorted(observed - expected)!r}",
    )


def _safe_file(path: Path, label: str) -> None:
    _require(path.is_file() and not path.is_symlink(), f"{label} is missing or unsafe")
    mode = path.stat().st_mode
    _require(stat.S_ISREG(mode), f"{label} is not a regular file")
    _require(0 < path.stat().st_size <= MAX_FILE_BYTES, f"{label} size is invalid")


def _scan_secret_bytes(data: bytes, label: str) -> None:
    _require(
        not any(pattern.search(data) for pattern in SECRET_PATTERNS),
        f"{label} contains credential-like material",
    )


def _utc_timestamp(value: Any, label: str) -> str:
    _require(isinstance(value, str) and value, f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SupplyProvenanceError(f"{label} is not ISO-8601") from exc
    _require(
        parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0,
        f"{label} must be UTC",
    )
    return value


def _load_toolchain(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / "scripts/release-toolchain-v04.json"
    _safe_file(path, "release toolchain lock")
    data = path.read_bytes()
    value = _load_json_bytes(data, "release toolchain lock")
    _require(isinstance(value, dict), "release toolchain lock must be an object")
    _exact_keys(
        value,
        {"schema_version", "host_platform", "tools", "versions"},
        "release toolchain lock",
    )
    _require(
        value["schema_version"] == TOOLCHAIN_SCHEMA_VERSION,
        "release toolchain schema differs",
    )
    tools = value["tools"]
    _require(isinstance(tools, list), "release toolchain tools must be an array")
    by_name: dict[str, dict[str, Any]] = {}
    for item in tools:
        _require(isinstance(item, dict), "release toolchain entry must be an object")
        name = item.get("name")
        _require(isinstance(name, str) and name not in by_name, "release tool name is invalid")
        sha = item.get("sha256")
        relative = item.get("relative_path")
        _require(
            isinstance(sha, str)
            and SHA256_PATTERN.fullmatch(sha) is not None
            and isinstance(relative, str)
            and relative
            and not PurePosixPath(relative).is_absolute()
            and ".." not in PurePosixPath(relative).parts,
            f"release tool entry is invalid: {name}",
        )
        by_name[name] = item
    versions = value["versions"]
    _require(isinstance(versions, dict), "release toolchain versions must be an object")
    value["tools_by_name"] = by_name
    return value, data


def _path_ends_with(value: str, relative: str) -> bool:
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    relative_parts = tuple(part.casefold() for part in PurePosixPath(relative).parts)
    if windows.is_absolute():
        parts = tuple(part.casefold() for part in windows.parts)
    elif posix.is_absolute():
        parts = tuple(part.casefold() for part in posix.parts)
    else:
        return False
    return len(parts) >= len(relative_parts) and parts[-len(relative_parts) :] == relative_parts


def _validate_host_tools(
    root: Path,
    test_id: str,
    tools: Mapping[str, Any],
    *,
    verify_current_files: bool,
) -> tuple[dict[str, dict[str, str]], str]:
    toolchain, lock_bytes = _load_toolchain(root)
    required = REQUIRED_TOOLS[test_id]
    _require(set(tools) == required, f"{test_id} host tool set differs")
    normalized: dict[str, dict[str, str]] = {}
    for name in sorted(required):
        record = tools[name]
        _require(isinstance(record, dict), f"{test_id} host tool record is invalid: {name}")
        _exact_keys(record, {"path", "sha256", "version"}, f"{test_id} host tool {name}")
        locked = toolchain["tools_by_name"].get(name)
        _require(isinstance(locked, dict), f"{test_id} tool is absent from the lock: {name}")
        path = record["path"]
        sha = record["sha256"]
        version = record["version"]
        version_key = TOOL_VERSION_KEYS[name]
        _require(
            isinstance(path, str)
            and _path_ends_with(path, str(locked["relative_path"]))
            and sha == locked["sha256"]
            and isinstance(version, str)
            and version == toolchain["versions"].get(version_key),
            f"{test_id} host tool differs from the release lock: {name}",
        )
        if verify_current_files:
            current = Path(path)
            _safe_file(current, f"current locked host tool {name}")
            _require(_file_sha256(current) == sha, f"current host tool hash differs: {name}")
        normalized[name] = {"path": path, "sha256": sha, "version": version}
    return normalized, _sha256(lock_bytes)


def locked_host_tools(root: Path, test_id: str) -> dict[str, dict[str, str]]:
    """Resolve and verify the exact release-toolchain executables for a live run."""

    _require(test_id in SUPPORTED_TEST_IDS, f"unsupported supply provenance ID: {test_id}")
    toolchain, _ = _load_toolchain(root.resolve())
    records: dict[str, dict[str, str]] = {}
    for name in sorted(REQUIRED_TOOLS[test_id]):
        environment_name = TOOL_ENVIRONMENT[name]
        path = os.environ.get(environment_name)
        _require(path is not None and path, f"locked host tool environment is missing: {name}")
        locked = toolchain["tools_by_name"][name]
        records[name] = {
            "path": str(Path(path).resolve()),
            "sha256": str(locked["sha256"]),
            "version": str(toolchain["versions"][TOOL_VERSION_KEYS[name]]),
        }
    normalized, _ = _validate_host_tools(
        root.resolve(), test_id, records, verify_current_files=True
    )
    return normalized


def _aggregate_files(root: Path, names: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for name in sorted(names):
        data = (root / name).read_bytes()
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _pip_audit_is_clean(value: Any, label: str) -> None:
    dependencies: Any
    if isinstance(value, list):
        dependencies = value
    elif isinstance(value, dict):
        dependencies = value.get("dependencies")
    else:
        dependencies = None
    _require(isinstance(dependencies, list) and dependencies, f"{label} has no dependencies")
    for dependency in dependencies:
        _require(isinstance(dependency, dict), f"{label} dependency is invalid")
        vulns = dependency.get("vulns")
        _require(isinstance(vulns, list) and not vulns, f"{label} contains a vulnerability")


def _npm_audit_is_clean(value: Any) -> None:
    _require(isinstance(value, dict), "npm audit report must be an object")
    _require(
        isinstance(value.get("auditReportVersion"), int),
        "npm audit report version is missing",
    )
    metadata = value.get("metadata")
    _require(isinstance(metadata, dict), "npm audit metadata is missing")
    counts = metadata.get("vulnerabilities")
    _require(isinstance(counts, dict), "npm audit vulnerability counts are missing")
    for severity in ("high", "critical"):
        _require(counts.get(severity) == 0, f"npm audit reports {severity} findings")
    vulnerabilities = value.get("vulnerabilities", {})
    _require(isinstance(vulnerabilities, dict), "npm audit vulnerabilities are invalid")
    for finding in vulnerabilities.values():
        _require(isinstance(finding, dict), "npm audit finding is invalid")
        _require(
            finding.get("severity") not in {"high", "critical"},
            "npm audit contains a blocking finding",
        )


def _sarif_is_clean(value: Any, label: str) -> None:
    _require(isinstance(value, dict), f"{label} SARIF report must be an object")
    _require(value.get("version") == "2.1.0", f"{label} SARIF version differs")
    runs = value.get("runs")
    _require(isinstance(runs, list) and runs, f"{label} SARIF runs are missing")
    for run in runs:
        _require(isinstance(run, dict), f"{label} SARIF run is invalid")
        results = run.get("results", [])
        _require(isinstance(results, list) and not results, f"{label} has findings")


def _result_binding(result: Mapping[str, Any]) -> str:
    _require(
        isinstance(result.get("test_id"), str)
        and isinstance(result.get("source_fingerprint_sha256"), str)
        and isinstance(result.get("assertions"), list)
        and isinstance(result.get("metrics"), dict),
        "supply collector result shape is invalid",
    )
    metrics = {
        key: value
        for key, value in result["metrics"].items()
        if key not in PROVENANCE_METRIC_KEYS
    }
    return _sha256(
        _canonical_json(
            {
                "test_id": result["test_id"],
                "source_fingerprint_sha256": result["source_fingerprint_sha256"],
                "assertions": result["assertions"],
                "metrics": metrics,
            }
        )
    )


def _validate_images(test_id: str, images: Mapping[str, Any]) -> dict[str, str]:
    _require(set(images) == REQUIRED_IMAGES[test_id], f"{test_id} execution image set differs")
    normalized: dict[str, str] = {}
    for role, value in sorted(images.items()):
        _require(
            isinstance(value, str) and IMAGE_ID_PATTERN.fullmatch(value) is not None,
            f"{test_id} execution image ID is invalid: {role}",
        )
        normalized[role] = value
    _require(
        len(set(normalized.values())) == len(normalized),
        f"{test_id} execution image roles are not distinct",
    )
    return normalized


def _validate_sc001(
    artifact_root: Path,
    bindings: Mapping[str, Any],
    result: Mapping[str, Any] | None,
    images: Mapping[str, str],
) -> None:
    pip_names = sorted(name for name in SC001_FILES if name.startswith("pip-audit-"))
    scout_names = sorted(name for name in SC001_FILES if name.startswith("scout-"))
    for name in pip_names:
        _pip_audit_is_clean(_load_json_bytes((artifact_root / name).read_bytes(), name), name)
    _npm_audit_is_clean(
        _load_json_bytes((artifact_root / "npm-audit.json").read_bytes(), "npm audit")
    )
    for name in scout_names:
        _sarif_is_clean(_load_json_bytes((artifact_root / name).read_bytes(), name), name)
    policy = _load_json_bytes(
        (artifact_root / "starlette-policy.json").read_bytes(), "Starlette policy report"
    )
    _require(
        policy
        == {
            "policy": "security/starlette_exposure_policy.json",
            "passed": True,
            "violation_count": 0,
        },
        "Starlette policy report differs",
    )
    for name, expected_tool in (
        ("python-tools.json", {"pip_audit": "2.10.0", "python_prefix": "3.13."}),
        ("node-tools.json", {"npm": None, "node": None}),
    ):
        value = _load_json_bytes((artifact_root / name).read_bytes(), name)
        _require(isinstance(value, dict), f"{name} must be an object")
        if name == "python-tools.json":
            _exact_keys(value, {"pip_audit", "python"}, name)
            _require(value["pip_audit"] == expected_tool["pip_audit"], "pip-audit version differs")
            _require(
                isinstance(value["python"], str)
                and value["python"].startswith(str(expected_tool["python_prefix"])),
                "audit Python version differs",
            )
        else:
            _exact_keys(value, {"node", "npm"}, name)
            _require(
                all(isinstance(value[key], str) and value[key] for key in ("node", "npm")),
                "Node/npm tool identity is invalid",
            )
    databases = bindings.get("advisory_database_results")
    _require(isinstance(databases, dict), "SC001 advisory database binding is missing")
    expected = {
        "pypi": _aggregate_files(artifact_root, pip_names),
        "npm": _aggregate_files(artifact_root, ["npm-audit.json"]),
        "docker_scout": _aggregate_files(artifact_root, scout_names),
    }
    _require(databases == expected, "SC001 advisory database result binding differs")
    if result is not None:
        metrics = result["metrics"]
        _require(metrics.get("critical_finding_count") == 0, "SC001 critical findings differ")
        _require(metrics.get("high_finding_count") == 0, "SC001 high findings differ")
        audited = metrics.get("audited_image_ids")
        dependencies = metrics.get("compose_dependency_audited_image_ids")
        _require(isinstance(audited, dict) and isinstance(dependencies, dict), "SC001 image metrics are missing")
        _require(
            {
                "backend": images["backend"],
                "driver": images["driver"],
                "frontend": images["frontend"],
                "proxy": images["proxy"],
            }
            == audited
            and {"pki_init": images["pki_init"], "postgres": images["postgres"]}
            == dependencies,
            "SC001 result image identities differ from the corpus",
        )


def _validate_sc003(
    artifact_root: Path,
    bindings: Mapping[str, Any],
    result: Mapping[str, Any] | None,
    images: Mapping[str, str],
) -> None:
    path = artifact_root / "image-inspection.json"
    data = path.read_bytes()
    report = _load_json_bytes(data, "SC003 image inspection")
    _require(isinstance(report, dict), "SC003 image inspection must be an object")
    _require(
        report.get("schema_version") == "spell.v04.image-inspection/1",
        "SC003 image inspection schema differs",
    )
    subjects = report.get("image_ids")
    dependencies = report.get("compose_dependency_image_ids")
    _require(isinstance(subjects, dict) and isinstance(dependencies, dict), "SC003 image maps are missing")
    expected = {
        **{role: images[role] for role in ("backend", "driver", "frontend", "proxy")},
        **{role: images[role] for role in ("pki_init", "postgres")},
    }
    _require({**subjects, **dependencies} == expected, "SC003 inspected image IDs differ")
    for key in (
        "secret_file_count",
        "pdf_file_count",
        "manual_text_file_count",
        "legacy_archive_count",
        "runtime_journal_count",
        "runtime_generator_count",
        "hardening_failure_count",
        "layer_scan_failure_count",
    ):
        _require(report.get(key) == 0, f"SC003 inspection reports {key}")
    _require(
        bindings.get("inspection_report_sha256") == _sha256(data),
        "SC003 inspection report binding differs",
    )
    if result is not None:
        metrics = result["metrics"]
        _require(
            metrics.get("inspection_report_sha256") == _sha256(data),
            "SC003 final result inspection hash differs",
        )


def _validate_sc004(
    artifact_root: Path,
    bindings: Mapping[str, Any],
    result: Mapping[str, Any] | None,
    source: str,
) -> None:
    children: list[dict[str, Any]] = []
    for name in ("independent-build-1.json", "independent-build-2.json"):
        data = (artifact_root / name).read_bytes()
        value = _load_json_bytes(data, name)
        _require(isinstance(value, dict), f"{name} must be an object")
        _exact_keys(
            value,
            {
                "schema_version",
                "process_id",
                "source_fingerprint_sha256",
                "descriptor_sha256",
                "generation_manifest_sha256",
                "package_sha256",
                "product_path_count",
            },
            name,
        )
        _require(
            value["schema_version"] == "spell.v04.independent-build/1"
            and value["source_fingerprint_sha256"] == source
            and type(value["process_id"]) is int
            and value["process_id"] > 0
            and type(value["product_path_count"]) is int
            and value["product_path_count"] > 0,
            f"{name} identity is invalid",
        )
        for key in ("descriptor_sha256", "generation_manifest_sha256", "package_sha256"):
            _require(
                isinstance(value[key], str) and SHA256_PATTERN.fullmatch(value[key]) is not None,
                f"{name} {key} is invalid",
            )
        children.append(value)
    _require(children[0]["process_id"] != children[1]["process_id"], "SC004 child processes are not distinct")
    compared = (
        "source_fingerprint_sha256",
        "descriptor_sha256",
        "generation_manifest_sha256",
        "package_sha256",
        "product_path_count",
    )
    _require(
        all(children[0][key] == children[1][key] for key in compared),
        "SC004 independent build results differ",
    )
    _require(
        bindings.get("child_process_ids") == sorted(child["process_id"] for child in children),
        "SC004 child process binding differs",
    )
    if result is not None:
        metrics = result["metrics"]
        for key in ("descriptor_sha256", "generation_manifest_sha256", "package_sha256"):
            _require(metrics.get(key) == children[0][key], f"SC004 final {key} differs")


def _validate_sc006(
    artifact_root: Path,
    bindings: Mapping[str, Any],
    result: Mapping[str, Any] | None,
    source: str,
    run_id: str,
    images: Mapping[str, str],
    tools: Mapping[str, Any],
) -> None:
    data = (artifact_root / "lifecycle-cases.json").read_bytes()
    ledger = _load_json_bytes(data, "SC006 lifecycle ledger")
    _require(isinstance(ledger, dict), "SC006 lifecycle ledger must be an object")
    _exact_keys(
        ledger,
        {
            "schema_version",
            "run_id",
            "source_fingerprint_sha256",
            "images",
            "tools",
            "cases",
            "summary",
        },
        "SC006 lifecycle ledger",
    )
    _require(
        ledger["schema_version"] == "spell.v04.sc006-lifecycle-ledger/1"
        and ledger["run_id"] == run_id
        and ledger["source_fingerprint_sha256"] == source
        and ledger["images"] == images
        and ledger["tools"] == tools,
        "SC006 lifecycle ledger identity differs",
    )
    cases = ledger["cases"]
    _require(isinstance(cases, list) and len(cases) == 60, "SC006 must retain exactly 60 cases")
    observed_ids: set[str] = set()
    projects: set[str] = set()
    expected_pairs = {
        (action, stage, certainty, expected)
        for action in ("enable", "disable", "upgrade", "rollback", "uninstall")
        for stage, certainty, expected in (
            ("SETTLED", "EFFECT_CONFIRMED", True),
            ("SETTLED", "NO_EFFECT", True),
            ("REQUESTED", "NO_EFFECT", False),
            ("ACCEPTED", "NO_EFFECT", False),
            ("DISPATCHED", "EFFECT_POSSIBLE", False),
            ("RECONCILING", "EFFECT_CONFIRMED", False),
            ("RECONCILING", "EFFECT_POSSIBLE", False),
            ("RECONCILING", "EFFECT_UNKNOWN", False),
            ("SETTLED", "EFFECT_POSSIBLE", False),
            ("SETTLED", "EFFECT_UNKNOWN", False),
            ("UNRECOGNIZED_STAGE", "NO_EFFECT", False),
            ("SETTLED", "UNRECOGNIZED_CERTAINTY", False),
        )
    }
    observed_pairs: set[tuple[str, str, str, bool]] = set()
    for case in cases:
        _require(isinstance(case, dict), "SC006 lifecycle case must be an object")
        _exact_keys(
            case,
            {
                "case_id",
                "action",
                "stage",
                "certainty",
                "expected_applied",
                "observed_applied",
                "reason",
                "project_name",
                "before_state_sha256",
                "after_state_sha256",
                "before_evidence_sha256",
                "after_evidence_sha256",
                "driver_image_before",
                "driver_image_after",
                "pki_image_id",
                "cleanup_verified",
            },
            "SC006 lifecycle case",
        )
        case_id = case["case_id"]
        expected = case["expected_applied"]
        _require(
            isinstance(case_id, str)
            and case_id not in observed_ids
            and type(expected) is bool
            and case["observed_applied"] is expected
            and isinstance(case["reason"], str)
            and 0 < len(case["reason"]) <= 128
            and case["cleanup_verified"] is True,
            "SC006 lifecycle case identity/result is invalid",
        )
        observed_ids.add(case_id)
        pair = (case["action"], case["stage"], case["certainty"], expected)
        _require(pair not in observed_pairs, "SC006 lifecycle case is duplicated")
        observed_pairs.add(pair)
        project = case["project_name"]
        _require(isinstance(project, str) and PROJECT_PATTERN.fullmatch(project) is not None, "SC006 project is invalid")
        projects.add(project)
        for key in (
            "before_state_sha256",
            "after_state_sha256",
            "before_evidence_sha256",
            "after_evidence_sha256",
        ):
            _require(
                isinstance(case[key], str) and SHA256_PATTERN.fullmatch(case[key]) is not None,
                f"SC006 {key} is invalid",
            )
        for key in ("driver_image_before", "driver_image_after", "pki_image_id"):
            _require(
                isinstance(case[key], str) and IMAGE_ID_PATTERN.fullmatch(case[key]) is not None,
                f"SC006 {key} is invalid",
            )
        _require(case["pki_image_id"] == images["pki_init"], "SC006 PKI image differs")
        expected_driver_before = (
            images["driver_b"]
            if expected and case["action"] == "rollback"
            else images["driver_a"]
        )
        expected_driver_after = (
            images["driver_b"]
            if expected and case["action"] == "upgrade"
            else images["driver_a"]
        )
        _require(
            case["driver_image_before"] == expected_driver_before
            and case["driver_image_after"] == expected_driver_after,
            "SC006 case driver image binding differs",
        )
        if expected:
            _require(
                case["before_state_sha256"] != case["after_state_sha256"]
                and case["before_evidence_sha256"] == case["after_evidence_sha256"],
                "SC006 applied transition state/evidence binding differs",
            )
        else:
            _require(
                case["before_state_sha256"] == case["after_state_sha256"]
                and case["before_evidence_sha256"] == case["after_evidence_sha256"],
                "SC006 refused transition changed state or evidence",
            )
    _require(observed_pairs == expected_pairs, "SC006 lifecycle matrix differs")
    _require(len(projects) == 15, "SC006 lifecycle project count differs")
    project_counts = sorted(
        sum(1 for case in cases if case["project_name"] == project)
        for project in projects
    )
    _require(
        project_counts == [1] * 10 + [10] * 5,
        "SC006 lifecycle case-to-project isolation differs",
    )
    summary = ledger["summary"]
    _require(
        summary
        == {
            "case_count": 60,
            "failed_case_count": 0,
            "terminal_case_count": 10,
            "unsafe_refusal_case_count": 50,
            "unique_project_count": 15,
        },
        "SC006 lifecycle summary differs",
    )
    _require(bindings.get("case_ledger_sha256") == _sha256(data), "SC006 ledger binding differs")
    if result is not None:
        metrics = result["metrics"]
        _require(
            metrics.get("runtime_transition_case_count") == 60
            and metrics.get("terminal_case_count") == 10
            and metrics.get("unsafe_refusal_case_count") == 50
            and metrics.get("unique_project_count") == 15,
            "SC006 final metrics differ from the ledger",
        )


def _derive_bindings(test_id: str, artifact_root: Path) -> dict[str, Any]:
    if test_id == "V04-SC-001":
        pip_names = sorted(name for name in SC001_FILES if name.startswith("pip-audit-"))
        scout_names = sorted(name for name in SC001_FILES if name.startswith("scout-"))
        return {
            "advisory_database_results": {
                "pypi": _aggregate_files(artifact_root, pip_names),
                "npm": _aggregate_files(artifact_root, ["npm-audit.json"]),
                "docker_scout": _aggregate_files(artifact_root, scout_names),
            }
        }
    if test_id == "V04-SC-003":
        return {
            "inspection_report_sha256": _file_sha256(
                artifact_root / "image-inspection.json"
            )
        }
    if test_id == "V04-SC-004":
        children = [
            _load_json_bytes((artifact_root / name).read_bytes(), name)
            for name in ("independent-build-1.json", "independent-build-2.json")
        ]
        return {"child_process_ids": sorted(child["process_id"] for child in children)}
    return {
        "case_ledger_sha256": _file_sha256(artifact_root / "lifecycle-cases.json")
    }


def _validate_specific(
    test_id: str,
    artifact_root: Path,
    bindings: Mapping[str, Any],
    result: Mapping[str, Any] | None,
    source: str,
    run_id: str,
    images: Mapping[str, str],
    tools: Mapping[str, Any],
) -> None:
    if test_id == "V04-SC-001":
        _validate_sc001(artifact_root, bindings, result, images)
    elif test_id == "V04-SC-003":
        _validate_sc003(artifact_root, bindings, result, images)
    elif test_id == "V04-SC-004":
        _validate_sc004(artifact_root, bindings, result, source)
    else:
        _validate_sc006(
            artifact_root, bindings, result, source, run_id, images, tools
        )


def corpus_digest(directory: Path) -> tuple[str, int]:
    """Hash exact relative names and bytes for one closed corpus directory."""

    _require(directory.is_dir() and not directory.is_symlink(), "supply corpus is missing")
    digest = hashlib.sha256()
    count = 0
    total = 0
    for entry in sorted(directory.rglob("*"), key=lambda item: item.relative_to(directory).as_posix()):
        relative = entry.relative_to(directory)
        _require(not entry.is_symlink(), f"supply corpus contains a symlink: {relative}")
        if entry.is_dir():
            continue
        _safe_file(entry, f"supply corpus file {relative}")
        data = entry.read_bytes()
        _scan_secret_bytes(data, f"supply corpus file {relative}")
        total += len(data)
        _require(total <= MAX_CORPUS_BYTES, "supply corpus exceeds its size bound")
        digest.update(relative.as_posix().encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
        count += 1
    _require(count > 1, "supply corpus is empty")
    return digest.hexdigest(), count


def staged_directory(root: Path, source: str, test_id: str, run_id: str) -> Path:
    return (
        root.resolve()
        / STAGING_DIRECTORY
        / source
        / DIRECTORY_NAMES[test_id]
        / run_id
    )


def canonical_directory(root: Path, test_id: str) -> Path:
    return root.resolve() / CANONICAL_DIRECTORY / DIRECTORY_NAMES[test_id]


def stage_supply_corpus(
    root: Path,
    *,
    test_id: str,
    run_id: str,
    source: str,
    input_directory: Path,
    result: Mapping[str, Any],
    execution_images: Mapping[str, Any],
    host_tools: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy one fresh raw set into a strict immutable source/run staging path."""

    root = root.resolve()
    _require(test_id in SUPPORTED_TEST_IDS, f"unsupported supply provenance ID: {test_id}")
    _require(RUN_ID_PATTERN.fullmatch(run_id) is not None, "supply provenance run ID is invalid")
    _require(SHA256_PATTERN.fullmatch(source) is not None, "supply provenance source is invalid")
    _require(result.get("test_id") == test_id, "supply result test ID differs")
    _require(result.get("source_fingerprint_sha256") == source, "supply result source differs")
    images = _validate_images(test_id, execution_images)
    supplied_tools = host_tools if host_tools is not None else locked_host_tools(root, test_id)
    tools, lock_sha256 = _validate_host_tools(
        root, test_id, supplied_tools, verify_current_files=host_tools is None
    )
    _require(not input_directory.is_symlink(), "supply raw input directory is unsafe")
    input_directory = input_directory.resolve()
    _require(
        input_directory.is_dir() and not input_directory.is_symlink(),
        "supply raw input directory is missing or unsafe",
    )
    entries = tuple(input_directory.iterdir())
    expected = EXPECTED_ARTIFACTS[test_id]
    _require(
        {entry.name for entry in entries} == set(expected)
        and all(entry.is_file() and not entry.is_symlink() for entry in entries),
        f"{test_id} raw artifact set differs",
    )
    destination = staged_directory(root, source, test_id, run_id)
    _require(not destination.exists() and not destination.is_symlink(), "supply staging run already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".tmp-{uuid.uuid4().hex}"
    artifact_root = temporary / "artifacts"
    try:
        artifact_root.mkdir(parents=True)
        artifact_records: list[dict[str, Any]] = []
        for name, kind in sorted(expected.items()):
            source_path = input_directory / name
            _safe_file(source_path, f"raw supply artifact {name}")
            data = source_path.read_bytes()
            _scan_secret_bytes(data, f"raw supply artifact {name}")
            target = artifact_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            artifact_records.append(
                {
                    "path": f"artifacts/{name}",
                    "kind": kind,
                    "sha256": _sha256(data),
                    "bytes": len(data),
                }
            )
        bindings = _derive_bindings(test_id, artifact_root)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "test_id": test_id,
            "run_id": run_id,
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_fingerprint_sha256": source,
            "complete": True,
            "toolchain_lock_sha256": lock_sha256,
            "host_tools": tools,
            "execution_images": images,
            "result_sha256": _result_binding(result),
            "bindings": bindings,
            "artifacts": artifact_records,
        }
        (temporary / MANIFEST_NAME).write_bytes(_canonical_json(manifest))
        _validate_specific(
            test_id,
            artifact_root,
            bindings,
            result,
            source,
            run_id,
            images,
            tools,
        )
        os.replace(temporary, destination)
        validated = validate_supply_corpus(
            root,
            destination,
            expected_test_id=test_id,
            expected_source=source,
            expected_result=result,
            expected_run_id=run_id,
        )
        return validated["provenance_metrics"]
    finally:
        if temporary.is_dir() and not temporary.is_symlink():
            shutil.rmtree(temporary)


def validate_supply_corpus(
    root: Path,
    directory: Path,
    *,
    expected_test_id: str,
    expected_source: str,
    expected_result: Mapping[str, Any] | None = None,
    expected_run_id: str | None = None,
) -> dict[str, Any]:
    """Validate one exact staged or canonical supply provenance corpus."""

    root = root.resolve()
    _require(not directory.is_symlink(), "supply provenance corpus is unsafe")
    directory = directory.resolve()
    _require(expected_test_id in SUPPORTED_TEST_IDS, "unsupported supply provenance ID")
    _require(directory.is_dir() and not directory.is_symlink(), "supply provenance corpus is missing")
    top_entries = tuple(directory.iterdir())
    _require(
        {entry.name for entry in top_entries} == {MANIFEST_NAME, "artifacts"}
        and all(not entry.is_symlink() for entry in top_entries),
        "supply provenance corpus top-level tree differs",
    )
    manifest_path = directory / MANIFEST_NAME
    artifact_root = directory / "artifacts"
    _safe_file(manifest_path, "supply provenance manifest")
    _require(artifact_root.is_dir() and not artifact_root.is_symlink(), "supply artifact root is unsafe")
    manifest_bytes = manifest_path.read_bytes()
    manifest = _load_json_bytes(manifest_bytes, "supply provenance manifest")
    _require(isinstance(manifest, dict), "supply provenance manifest must be an object")
    _exact_keys(
        manifest,
        {
            "schema_version",
            "test_id",
            "run_id",
            "captured_at",
            "source_fingerprint_sha256",
            "complete",
            "toolchain_lock_sha256",
            "host_tools",
            "execution_images",
            "result_sha256",
            "bindings",
            "artifacts",
        },
        "supply provenance manifest",
    )
    _require(manifest_bytes == _canonical_json(manifest), "supply provenance manifest is not canonical")
    test_id = manifest["test_id"]
    run_id = manifest["run_id"]
    source = manifest["source_fingerprint_sha256"]
    _require(
        manifest["schema_version"] == SCHEMA_VERSION
        and test_id == expected_test_id
        and manifest["complete"] is True
        and isinstance(run_id, str)
        and RUN_ID_PATTERN.fullmatch(run_id) is not None
        and source == expected_source,
        "supply provenance identity differs",
    )
    if expected_run_id is not None:
        _require(run_id == expected_run_id, "supply provenance run ID differs")
    _utc_timestamp(manifest["captured_at"], "supply provenance captured_at")
    tools, lock_sha256 = _validate_host_tools(
        root, test_id, manifest["host_tools"], verify_current_files=False
    )
    _require(
        manifest["toolchain_lock_sha256"] == lock_sha256,
        "supply provenance toolchain lock hash differs",
    )
    images = _validate_images(test_id, manifest["execution_images"])
    records = manifest["artifacts"]
    expected_artifacts = EXPECTED_ARTIFACTS[test_id]
    _require(isinstance(records, list), "supply artifact manifest must be an array")
    by_name: dict[str, dict[str, Any]] = {}
    total = 0
    for record in records:
        _require(isinstance(record, dict), "supply artifact record must be an object")
        _exact_keys(record, {"path", "kind", "sha256", "bytes"}, "supply artifact record")
        relative = record["path"]
        _require(
            isinstance(relative, str)
            and relative.startswith("artifacts/")
            and len(PurePosixPath(relative).parts) == 2
            and ".." not in PurePosixPath(relative).parts,
            "supply artifact path is unsafe",
        )
        name = PurePosixPath(relative).name
        _require(name not in by_name and name in expected_artifacts, "supply artifact is duplicated or unexpected")
        path = artifact_root / name
        _safe_file(path, f"supply artifact {name}")
        data = path.read_bytes()
        _scan_secret_bytes(data, f"supply artifact {name}")
        _require(
            record["kind"] == expected_artifacts[name]
            and record["sha256"] == _sha256(data)
            and type(record["bytes"]) is int
            and record["bytes"] == len(data),
            f"supply artifact metadata differs: {name}",
        )
        total += len(data)
        by_name[name] = record
    _require(set(by_name) == set(expected_artifacts), "supply artifact manifest is incomplete")
    observed_entries = tuple(artifact_root.iterdir())
    _require(
        {entry.name for entry in observed_entries} == set(expected_artifacts)
        and all(entry.is_file() and not entry.is_symlink() for entry in observed_entries),
        "supply artifact tree differs from the exact manifest",
    )
    _require(total <= MAX_CORPUS_BYTES, "supply artifact corpus exceeds its size bound")
    bindings = manifest["bindings"]
    _require(isinstance(bindings, dict), "supply provenance bindings must be an object")
    _require(bindings == _derive_bindings(test_id, artifact_root), "supply provenance bindings differ")
    if expected_result is not None:
        _require(expected_result.get("test_id") == test_id, "supply final result ID differs")
        _require(
            manifest["result_sha256"] == _result_binding(expected_result),
            "supply final result differs from the retained corpus binding",
        )
    else:
        _require(
            isinstance(manifest["result_sha256"], str)
            and SHA256_PATTERN.fullmatch(manifest["result_sha256"]) is not None,
            "supply result binding is invalid",
        )
    _validate_specific(
        test_id,
        artifact_root,
        bindings,
        expected_result,
        source,
        run_id,
        images,
        tools,
    )
    corpus_sha, file_count = corpus_digest(directory)
    provenance_metrics = {
        "supply_provenance_schema_version": SCHEMA_VERSION,
        "supply_provenance_run_id": run_id,
        "supply_provenance_manifest_sha256": _sha256(manifest_bytes),
        "supply_provenance_corpus_sha256": corpus_sha,
        "supply_provenance_file_count": file_count,
    }
    if expected_result is not None:
        metrics = expected_result["metrics"]
        for key, expected in provenance_metrics.items():
            if key in metrics:
                _require(metrics[key] == expected, f"supply final provenance metric differs: {key}")
    return {
        "manifest": manifest,
        "provenance_metrics": provenance_metrics,
        "directory": directory,
    }


def copy_validated_corpus(source: Path, destination: Path) -> None:
    """Copy exact corpus bytes to a fresh publication directory."""

    _require(not destination.exists() and not destination.is_symlink(), "supply publication target exists")
    destination.mkdir(parents=True)
    try:
        for entry in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            relative = entry.relative_to(source)
            _require(not entry.is_symlink(), f"supply staging corpus contains a symlink: {relative}")
            target = destination / relative
            if entry.is_dir():
                target.mkdir()
            else:
                _safe_file(entry, f"supply staging file {relative}")
                with target.open("xb") as stream:
                    stream.write(entry.read_bytes())
                    stream.flush()
                    os.fsync(stream.fileno())
    except Exception:
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise


def _load_json_file(path: Path, label: str) -> dict[str, Any]:
    _safe_file(path, label)
    value = _load_json_bytes(path.read_bytes(), label)
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage")
    stage.add_argument("--root", type=Path, default=ROOT)
    stage.add_argument("--test-id", choices=sorted(SUPPORTED_TEST_IDS), required=True)
    stage.add_argument("--run-id", required=True)
    stage.add_argument("--source", required=True)
    stage.add_argument("--input-directory", type=Path, required=True)
    stage.add_argument("--result-json", type=Path, required=True)
    stage.add_argument("--execution-images-json", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--root", type=Path, default=ROOT)
    validate.add_argument("--test-id", choices=sorted(SUPPORTED_TEST_IDS), required=True)
    validate.add_argument("--source", required=True)
    validate.add_argument("--directory", type=Path, required=True)
    validate.add_argument("--result-json", type=Path)

    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.command == "stage":
            metrics = stage_supply_corpus(
                root,
                test_id=args.test_id,
                run_id=args.run_id,
                source=args.source,
                input_directory=args.input_directory,
                result=_load_json_file(args.result_json, "supply collector result"),
                execution_images=_load_json_file(
                    args.execution_images_json, "supply execution image map"
                ),
            )
            print(_canonical_json(metrics).decode("ascii"), end="")
        else:
            result = (
                _load_json_file(args.result_json, "supply collector result")
                if args.result_json is not None
                else None
            )
            validated = validate_supply_corpus(
                root,
                args.directory,
                expected_test_id=args.test_id,
                expected_source=args.source,
                expected_result=result,
            )
            print(_canonical_json(validated["provenance_metrics"]).decode("ascii"), end="")
    except (OSError, SupplyProvenanceError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
