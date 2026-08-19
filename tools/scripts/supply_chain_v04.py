#!/usr/bin/env python3
"""Strict v0.4 supply-chain probes and qualification collectors."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import build_reproducible_v04
from scripts.source_fingerprint_v04 import source_fingerprint_v04
from scripts.validate_release_evidence_v04 import (
    SBOM_FILES,
    parse_json_document_v04,
    validate_sboms_v04,
)


SHA256 = re.compile(r"[0-9a-f]{64}")
LOCK_PACKAGE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)\s+\\$")
LOCK_HASH = re.compile(r"^--hash=sha256:([0-9a-f]{64})(?:\s+(\\))?$")
DIRECT_REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?(.+)$")
FROM_DEFINITION = re.compile(
    r"(?im)^\s*FROM\s+([^\s]+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*$"
)
COMPOSE_IMAGE = re.compile(r"(?m)^\s*image:\s*([^\s#]+)")
LOCAL_COMPOSE_BUILD_IMAGE = "openbexi-spell-backend:${SPELL_IMAGE_TAG:-local}"
LOCAL_COMPOSE_BUILD_SERVICES = ("backend", "bundle-builder-a", "bundle-builder-b")
PINNED_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}$")
PYTHON_LOCKS = (
    ("backend/requirements.txt", "backend/requirements.hashes.lock"),
    ("driver_host/requirements.txt", "driver_host/requirements.hashes.lock"),
    ("driver_host/pki-requirements.txt", "driver_host/pki-requirements.hashes.lock"),
    ("contracts/generator-requirements.txt", "contracts/generator-requirements.hashes.lock"),
    ("scripts/supply-chain-requirements.txt", "scripts/supply-chain-requirements.hashes.lock"),
)
REQUIRED_IMAGE_DOCKERFILES = (
    "backend/Dockerfile",
    "driver_host/Dockerfile",
    "driver_host/pki.Dockerfile",
    "driver_host/postgres.Dockerfile",
    "proxy/Dockerfile",
    "scripts/package-v04.Dockerfile",
    "scripts/qualification.Dockerfile",
    "scripts/supply-chain-v04.Dockerfile",
    "scripts/generator-v04.Dockerfile",
)
RELEASE_TOOL_PATHS = {
    "docker-cli": "Docker/Docker/resources/bin/docker.exe",
    "docker-buildx": "Docker/Docker/resources/cli-plugins/docker-buildx.exe",
    "docker-compose": "Docker/Docker/resources/cli-plugins/docker-compose.exe",
    "docker-sbom": "OpenBEXI/release-toolchain/docker-sbom-0.6.0-windows-amd64/docker-sbom.exe",
    "docker-scout": "Docker/Docker/resources/cli-plugins/docker-scout.exe",
    "python": "OpenBEXI/release-toolchain/python-3.13.14-embed-amd64/python.exe",
}
RELEASE_TOOL_BASE_DIRECTORIES = {
    "docker-cli": "ProgramFiles",
    "docker-buildx": "ProgramFiles",
    "docker-compose": "ProgramFiles",
    "docker-sbom": "LocalAppData",
    "docker-scout": "ProgramFiles",
    "python": "LocalAppData",
}
RELEASE_TOOL_ARCHIVES = {
    "python": (
        "OpenBEXI/release-toolchain/python-3.13.14-embed-amd64.zip",
        "90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907",
        "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embeddable-amd64.zip",
    ),
}
RELEASE_TOOL_VERSIONS = {
    "docker_cli": "29.7.2",
    "docker_buildx": "v0.36.0-desktop.1",
    "docker_compose": "v5.3.1",
    "docker_sbom": "0.6.0",
    "syft_provider": "v0.43.0",
    "docker_scout": "v1.24.0",
    "host_python": "3.13.14",
}


@dataclass(frozen=True)
class LockValidation:
    lock_input_count: int
    python_package_count: int
    node_package_count: int
    image_input_count: int
    release_tool_count: int
    protobuf_version: str
    grpc_version: str
    tls_version: str


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _direct_requirements(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        content = line.partition("#")[0].strip()
        if not content:
            continue
        match = DIRECT_REQUIREMENT.fullmatch(content)
        if match is None:
            raise ValueError(f"invalid direct requirement in {path}: {content}")
        name = _normalized_name(match.group(1))
        if name in values:
            raise ValueError(f"duplicate direct requirement in {path}: {name}")
        values[name] = match.group(2).strip()
    return values


def _locked_requirements(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    locked: dict[str, tuple[str, tuple[str, ...]]] = {}
    current_name: str | None = None
    current_version: str | None = None
    hashes: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        content = line.strip()
        if not content or content.startswith("#"):
            continue
        if current_name is None:
            match = LOCK_PACKAGE.fullmatch(content)
            if match is None:
                raise ValueError(
                    f"unrecognized or unpinned lock line in {path}:{line_number}: {content}"
                )
            current_name = _normalized_name(match.group(1))
            current_version = match.group(2)
            if current_name in locked:
                raise ValueError(f"duplicate locked requirement in {path}: {current_name}")
            hashes = []
            continue

        hash_match = LOCK_HASH.fullmatch(content)
        if hash_match is None:
            raise ValueError(
                f"unrecognized lock continuation in {path}:{line_number}: {content}"
            )
        digest = hash_match.group(1)
        if digest in hashes:
            raise ValueError(f"duplicate locked SHA-256 in {path}:{line_number}")
        hashes.append(digest)
        if hash_match.group(2) is None:
            if current_version is None:
                raise AssertionError("lock parser lost the current version")
            locked[current_name] = (current_version, tuple(hashes))
            current_name = None
            current_version = None
            hashes = []
    if current_name is not None:
        raise ValueError(f"unterminated locked requirement in {path}: {current_name}")
    if not locked:
        raise ValueError(f"empty Python hash lock: {path}")
    return locked


def _exact_direct_version(specifier: str) -> str | None:
    match = re.fullmatch(r"==([^,;\s]+)", specifier)
    return match.group(1) if match else None


def _validate_release_toolchain(toolchain: Any) -> int:
    if not isinstance(toolchain, dict):
        raise ValueError("v0.4 release toolchain lock must be an object")
    tools = toolchain.get("tools")
    if (
        set(toolchain) != {"schema_version", "host_platform", "tools", "versions"}
        or toolchain.get("schema_version") != "spell.v04.release-toolchain/1"
        or not isinstance(tools, list)
        or len(tools) != len(RELEASE_TOOL_PATHS)
        or toolchain.get("host_platform") != "windows-amd64-docker-desktop"
        or toolchain.get("versions") != RELEASE_TOOL_VERSIONS
    ):
        raise ValueError("v0.4 release toolchain lock is incomplete")
    tool_names: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError("v0.4 release toolchain entry is invalid")
        name = tool.get("name")
        expected_keys = {"name", "base_directory", "relative_path", "sha256"}
        if name in RELEASE_TOOL_ARCHIVES:
            expected_keys.update(
                {"archive_relative_path", "archive_sha256", "archive_url"}
            )
        digest = tool.get("sha256")
        relative_path = tool.get("relative_path")
        if (
            set(tool) != expected_keys
            or not isinstance(name, str)
            or not name
            or name in tool_names
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or RELEASE_TOOL_PATHS.get(name) != relative_path
            or RELEASE_TOOL_BASE_DIRECTORIES.get(name) != tool.get("base_directory")
        ):
            raise ValueError("v0.4 release toolchain name/hash is invalid")
        if name in RELEASE_TOOL_ARCHIVES:
            archive_path, archive_digest, archive_url = RELEASE_TOOL_ARCHIVES[name]
            if (
                tool.get("archive_relative_path") != archive_path
                or tool.get("archive_sha256") != archive_digest
                or tool.get("archive_url") != archive_url
            ):
                raise ValueError("v0.4 release toolchain archive lock is invalid")
        tool_names.add(name)
    if tool_names != set(RELEASE_TOOL_PATHS):
        raise ValueError("v0.4 release toolchain set differs")
    return len(tools)


def validate_locks(root: Path) -> LockValidation:
    source_root = root.resolve()
    python_package_count = 0
    direct_by_path: dict[str, dict[str, str]] = {}
    locked_by_path: dict[str, dict[str, tuple[str, tuple[str, ...]]]] = {}
    for requirement_name, lock_name in PYTHON_LOCKS:
        requirement_path = source_root / requirement_name
        lock_path = source_root / lock_name
        if not requirement_path.is_file() or not lock_path.is_file():
            raise FileNotFoundError(f"missing Python requirement/lock pair: {requirement_name}")
        direct = _direct_requirements(requirement_path)
        locked = _locked_requirements(lock_path)
        for package in direct:
            if package not in locked:
                raise ValueError(f"{lock_name} does not resolve direct input {package}")
        python_package_count += len(locked)
        direct_by_path[requirement_name] = direct
        locked_by_path[lock_name] = locked

    versions: dict[str, set[str]] = {"grpcio": set(), "protobuf": set()}
    for direct in direct_by_path.values():
        for package in versions:
            if package in direct:
                version = _exact_direct_version(direct[package])
                if version is None:
                    raise ValueError(f"{package} must use an exact direct-input version")
                versions[package].add(version)
    if any(len(items) != 1 for items in versions.values()):
        raise ValueError(f"protobuf/gRPC direct-input versions differ: {versions!r}")
    tls_specifier = direct_by_path["driver_host/pki-requirements.txt"].get("cryptography")
    tls_version = _exact_direct_version(tls_specifier or "")
    if tls_version is None:
        raise ValueError("TLS library input must use an exact direct-input version")
    generator = direct_by_path["contracts/generator-requirements.txt"]
    if "grpcio-tools" not in generator or _exact_direct_version(generator["grpcio-tools"]) is None:
        raise ValueError("protobuf generator input must be version locked")

    node_lock_path = source_root / "frontend/package-lock.json"
    lock = json.loads(node_lock_path.read_text(encoding="utf-8"))
    if lock.get("lockfileVersion") != 3 or not isinstance(lock.get("packages"), dict):
        raise ValueError("Node lock must use package-lock schema version 3")
    node_manifest = json.loads(
        (source_root / "frontend/package.json").read_text(encoding="utf-8")
    )
    root_lock = lock["packages"].get("")
    if not isinstance(node_manifest, dict) or not isinstance(root_lock, dict):
        raise ValueError("Node manifest/root lock entry is invalid")
    for dependency_group in ("dependencies", "devDependencies", "optionalDependencies"):
        manifest_values = node_manifest.get(dependency_group, {})
        locked_values = root_lock.get(dependency_group, {})
        if manifest_values != locked_values:
            raise ValueError(f"Node {dependency_group} differs from the root lock entry")
    node_package_count = 0
    for package_path, package in lock["packages"].items():
        if not package_path.startswith("node_modules/"):
            continue
        if not isinstance(package, dict):
            raise ValueError(f"invalid Node lock entry: {package_path}")
        version = package.get("version")
        if not isinstance(version, str) or not version or re.search(r"[~^*<>=| ]", version):
            raise ValueError(f"Node package version is not exact: {package_path}")
        if package.get("link") is True:
            raise ValueError(f"Node package uses an unhashed link input: {package_path}")
        integrity = package.get("integrity")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            raise ValueError(f"Node package has no SHA-512 integrity: {package_path}")
        try:
            integrity_bytes = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"Node package SHA-512 integrity is invalid: {package_path}") from exc
        if len(integrity_bytes) != 64:
            raise ValueError(f"Node package SHA-512 integrity is invalid: {package_path}")
        node_package_count += 1
    if node_package_count < 1:
        raise ValueError("Node lock contains no resolved packages")

    image_inputs: list[str] = []
    discovered_dockerfiles = sorted(
        path.relative_to(source_root).as_posix()
        for tree_name in build_reproducible_v04.INCLUDE_TREES
        for path in (source_root / tree_name).rglob("*Dockerfile")
        if path.is_file() and not path.is_symlink()
    )
    missing_dockerfiles = set(REQUIRED_IMAGE_DOCKERFILES) - set(discovered_dockerfiles)
    if missing_dockerfiles:
        raise FileNotFoundError(
            "missing required image definitions: " + ", ".join(sorted(missing_dockerfiles))
        )
    for relative in discovered_dockerfiles:
        path = source_root / relative
        dockerfile_text = path.read_text(encoding="utf-8")
        from_lines = [
            line for line in dockerfile_text.splitlines() if line.lstrip().upper().startswith("FROM ")
        ]
        definitions = FROM_DEFINITION.findall(dockerfile_text)
        if len(definitions) != len(from_lines):
            raise ValueError(f"unsupported or ambiguous FROM instruction: {relative}")
        aliases: set[str] = set()
        for image, alias in definitions:
            if image not in aliases:
                image_inputs.append(image)
            if alias:
                aliases.add(alias)
    compose_text = (source_root / "compose.yaml").read_text(encoding="utf-8")
    compose_images = COMPOSE_IMAGE.findall(compose_text)
    local_build_count = compose_images.count(LOCAL_COMPOSE_BUILD_IMAGE)
    if local_build_count not in (0, len(LOCAL_COMPOSE_BUILD_SERVICES)):
        raise ValueError("local Compose build-output image references differ")
    if local_build_count:
        for service in LOCAL_COMPOSE_BUILD_SERVICES:
            service_image = re.compile(
                rf"(?m)^  {re.escape(service)}:\s*$\n(?:(?:    .*|\s*)\n)*?"
                rf"    image: {re.escape(LOCAL_COMPOSE_BUILD_IMAGE)}\s*$"
            )
            if service_image.search(compose_text) is None:
                raise ValueError(f"local Compose build-output service differs: {service}")
        backend_build = re.compile(
            r"(?m)^  backend:\s*$\n"
            r"    image: openbexi-spell-backend:\$\{SPELL_IMAGE_TAG:-local\}\s*$\n"
            r"    build:\s*$\n"
            r"      context: \.\s*$\n"
            r"      dockerfile: backend/Dockerfile\s*$"
        )
        if backend_build.search(compose_text) is None:
            raise ValueError("local Compose backend build definition differs")
    image_inputs.extend(
        image for image in compose_images if image != LOCAL_COMPOSE_BUILD_IMAGE
    )
    unlocked_images = [item for item in image_inputs if PINNED_IMAGE.fullmatch(item) is None]
    if unlocked_images:
        raise ValueError(f"image inputs are not digest pinned: {unlocked_images!r}")

    toolchain_path = source_root / "scripts/release-toolchain-v04.json"
    toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
    release_tool_count = _validate_release_toolchain(toolchain)

    return LockValidation(
        lock_input_count=len(PYTHON_LOCKS) + 2 + len(image_inputs),
        python_package_count=python_package_count,
        node_package_count=node_package_count,
        image_input_count=len(image_inputs),
        release_tool_count=release_tool_count,
        protobuf_version=next(iter(versions["protobuf"])),
        grpc_version=next(iter(versions["grpcio"])),
        tls_version=tls_version,
    )


def _result(test_id: str, root: Path, assertions: Iterable[str], metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        "test_id": test_id,
        "source_fingerprint_sha256": source_fingerprint_v04(root),
        "assertions": [{"id": item, "passed": True} for item in assertions],
        "metrics": metrics,
    }


def probe_sc_001(root: Path, marker_root: Path) -> dict[str, Any]:
    validation = validate_locks(root)
    markers = (
        "python-audit-passed",
        "node-audit-passed",
        "lock-validation-passed",
    )
    missing = [name for name in markers if not (marker_root / name).is_file()]
    if missing:
        raise ValueError(f"authoritative audit marker is missing: {missing!r}")
    return _result(
        "V04-SC-001",
        root,
        (
            "python-inputs-version-and-hash-locked",
            "node-inputs-version-and-integrity-locked",
            "protobuf-grpc-tls-generator-inputs-locked",
            "all-container-inputs-digest-pinned",
            "python-and-node-authoritative-audits-have-no-high-or-critical-findings",
        ),
        {
            "lock_input_count": validation.lock_input_count,
            "audit_tool_count": 3,
            "unlocked_input_count": 0,
            "critical_finding_count": 0,
            "high_finding_count": 0,
            "python_package_count": validation.python_package_count,
            "node_package_count": validation.node_package_count,
            "image_input_count": validation.image_input_count,
            "release_tool_count": validation.release_tool_count,
            "protobuf_version": validation.protobuf_version,
            "grpc_version": validation.grpc_version,
            "tls_version": validation.tls_version,
        },
    )


def probe_sc_002(root: Path) -> dict[str, Any]:
    source = source_fingerprint_v04(root)
    image_ids = validate_sboms_v04(root, source)
    return _result(
        "V04-SC-002",
        root,
        (
            "exact-four-cyclonedx-inventories-validated",
            "subjects-and-image-identities-are-distinct",
            "source-and-image-digests-are-bound",
            "required-component-licenses-are-recorded",
            "checksum-manifest-matches-inventory-bytes",
        ),
        {
            "sbom_count": 4,
            "distinct_image_count": len(set(image_ids)),
            "image_names": ["backend", "driver", "frontend", "proxy"],
            "licensed_inventory_count": 4,
        },
    )


def inspect_product_package_inputs_v04(
    root: Path, *, forbidden_marker: bytes | None = None
) -> dict[str, Any]:
    """Inspect the deterministic product-only inputs and decompressed archive."""

    source_root = root.resolve()
    if forbidden_marker is not None and (
        not isinstance(forbidden_marker, bytes)
        or not forbidden_marker
        or len(forbidden_marker) > 4096
    ):
        raise ValueError("product-package forbidden marker must be bounded non-empty bytes")

    source_before = source_fingerprint_v04(source_root)
    first_paths = build_reproducible_v04.product_files_v04(source_root)
    first_inputs: dict[str, bytes] = {}
    for path in first_paths:
        relative = path.relative_to(source_root).as_posix()
        data = path.read_bytes()
        build_reproducible_v04._validate_release_path_v04(Path(relative))
        build_reproducible_v04._validate_release_bytes_v04(Path(relative), data)
        if relative in first_inputs:
            raise ValueError("deterministic product-package input manifest has a duplicate path")
        first_inputs[relative] = data

    first_archive = build_reproducible_v04._archive_bytes_v04(source_root, first_paths)
    second_paths = build_reproducible_v04.product_files_v04(source_root)
    second_inputs = {
        path.relative_to(source_root).as_posix(): path.read_bytes() for path in second_paths
    }
    second_archive = build_reproducible_v04._archive_bytes_v04(source_root, second_paths)
    if first_inputs != second_inputs or first_archive != second_archive:
        raise ValueError("deterministic product-package inputs changed during inspection")

    archive_inputs: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(first_archive), mode="r:gz") as package:
        for member in package.getmembers():
            if not member.isfile():
                raise ValueError("deterministic product package contains a non-file member")
            relative = Path(member.name)
            build_reproducible_v04._validate_release_path_v04(relative)
            extracted = package.extractfile(member)
            if extracted is None:
                raise ValueError(
                    f"deterministic product package member cannot be read: {member.name}"
                )
            data = extracted.read()
            build_reproducible_v04._validate_release_bytes_v04(relative, data)
            if member.name in archive_inputs:
                raise ValueError("deterministic product package contains a duplicate member")
            archive_inputs[member.name] = data

    if archive_inputs != first_inputs:
        raise ValueError("deterministic product package bytes differ from inspected inputs")
    if forbidden_marker is not None and any(
        forbidden_marker in data
        for data in (*first_inputs.values(), *archive_inputs.values())
    ):
        raise ValueError("forbidden marker entered deterministic product-package bytes")
    if source_fingerprint_v04(source_root) != source_before:
        raise ValueError("source changed during deterministic product-package inspection")

    input_bytes = sum(len(data) for data in first_inputs.values())
    archive_member_bytes = sum(len(data) for data in archive_inputs.values())
    return {
        "source_fingerprint_sha256": source_before,
        "product_input_file_count": len(first_inputs),
        "product_package_file_count": len(archive_inputs),
        "product_scanned_file_count": len(first_inputs) + len(archive_inputs),
        "product_input_byte_count": input_bytes,
        "product_package_member_byte_count": archive_member_bytes,
        "product_scanned_byte_count": input_bytes + archive_member_bytes,
        "product_package_byte_count": len(first_archive),
        "product_package_sha256": hashlib.sha256(first_archive).hexdigest(),
        "product_secret_file_count": 0,
        "product_pdf_file_count": 0,
        "product_manual_text_file_count": 0,
        "product_legacy_archive_count": 0,
        "product_runtime_journal_count": 0,
        "product_forbidden_marker_count": 0,
    }


def _load_inspection(path: Path, expected_sha256: str) -> dict[str, Any]:
    data = path.read_bytes()
    if SHA256.fullmatch(expected_sha256) is None:
        raise ValueError("image inspection report expected hash is invalid")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("image inspection report hash differs from the fresh host report")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("v0.4 image inspection report is not UTF-8") from exc
    value = parse_json_document_v04(text, "v0.4 image inspection report")
    if not isinstance(value, dict) or value.get("schema_version") != "spell.v04.image-inspection/1":
        raise ValueError("image inspection report schema differs")
    if value.get("image_names") != ["backend", "driver", "frontend", "proxy"]:
        raise ValueError("image inspection does not cover the exact image set")
    image_ids = value.get("image_ids")
    if not isinstance(image_ids, dict) or set(image_ids) != {
        "backend",
        "driver",
        "frontend",
        "proxy",
    }:
        raise ValueError("image inspection image identities are incomplete")
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
        if value.get(key) != 0:
            raise ValueError(f"image inspection failed {key}: {value.get(key)!r}")
    if not isinstance(value.get("scanned_file_count"), int) or value["scanned_file_count"] < 1:
        raise ValueError("image inspection scanned no files")
    if value.get("scanned_image_count") != 6:
        raise ValueError("image inspection does not cover four subjects and two dependencies")
    if not isinstance(value.get("scanned_layer_count"), int) or value["scanned_layer_count"] < 6:
        raise ValueError("image inspection did not scan every image layer")
    dependency_ids = value.get("compose_dependency_image_ids")
    if not isinstance(dependency_ids, dict) or set(dependency_ids) != {
        "pki_init",
        "postgres",
    }:
        raise ValueError("Compose dependency image identities are incomplete")
    if any(
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        for image_id in dependency_ids.values()
    ):
        raise ValueError("Compose dependency image identity is invalid")
    references = value.get("compose_dependency_configured_references")
    if (
        not isinstance(references, dict)
        or set(references) != {"pki_init", "postgres"}
        or not isinstance(references.get("pki_init"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", references["pki_init"]) is None
        or not isinstance(references.get("postgres"), str)
        or (
            re.fullmatch(r"sha256:[0-9a-f]{64}", references["postgres"]) is None
            and re.search(r"@sha256:[0-9a-f]{64}$", references["postgres"]) is None
        )
    ):
        raise ValueError("Compose dependency configured references differ")
    return value


def probe_sc_003(
    root: Path, inspection_path: Path, inspection_report_sha256: str
) -> dict[str, Any]:
    inspection = _load_inspection(inspection_path, inspection_report_sha256)
    source = source_fingerprint_v04(root)
    sbom_image_ids = validate_sboms_v04(root, source)
    expected_image_ids = {
        name.partition(".")[0]: image_id
        for name, image_id in zip(SBOM_FILES, sbom_image_ids)
    }
    if inspection["image_ids"] != expected_image_ids:
        raise ValueError("image inspection identities differ from current SBOM inputs")
    product = inspect_product_package_inputs_v04(root)
    scanned = inspection["scanned_file_count"] + product["product_scanned_file_count"]
    return _result(
        "V04-SC-003",
        root,
        (
            "runtime-images-match-hardening-policy",
            "runtime-images-contain-no-forbidden-release-material",
            "source-inputs-contain-no-package-forbidden-material",
            "candidate-package-bytes-contain-no-forbidden-material-or-secret",
            "runtime-generator-and-embedded-journal-are-absent",
        ),
        {
            "scanned_file_count": scanned,
            "secret_file_count": 0,
            "pdf_file_count": 0,
            "manual_text_file_count": 0,
            "legacy_archive_count": 0,
            "runtime_journal_count": 0,
            "runtime_generator_count": 0,
            "hardening_failure_count": 0,
            "layer_scan_failure_count": 0,
            "image_scanned_file_count": inspection["scanned_file_count"],
            "scanned_image_count": inspection["scanned_image_count"],
            "scanned_layer_count": inspection["scanned_layer_count"],
            "source_scanned_file_count": product["product_input_file_count"],
            "candidate_package_file_count": product["product_package_file_count"],
            "product_package_sha256": product["product_package_sha256"],
            "inspected_image_ids": inspection["image_ids"],
            "compose_dependency_inspected_image_count": inspection[
                "compose_dependency_image_count"
            ],
            "compose_dependency_inspected_image_ids": inspection[
                "compose_dependency_image_ids"
            ],
            "inspection_report_sha256": inspection_report_sha256,
        },
    )


def _manifest_digest(root: Path, paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def probe_sc_004_once(root: Path) -> dict[str, Any]:
    from scripts import generate_driver_contract

    source_before = source_fingerprint_v04(root)
    with tempfile.TemporaryDirectory(prefix="spell-v04-generation-process-") as directory:
        generated_root = Path(directory)
        outputs = generate_driver_contract._generate(generated_root)
        generate_driver_contract._check_or_write(outputs, generated_root, False)
        descriptor = generated_root / generate_driver_contract.DESCRIPTOR_RELATIVE
        descriptor_sha = hashlib.sha256(descriptor.read_bytes()).hexdigest()
        generation_manifest = _manifest_digest(generated_root, outputs)
    paths = build_reproducible_v04.product_files_v04(root)
    package = build_reproducible_v04._archive_bytes_v04(root, paths)
    if source_fingerprint_v04(root) != source_before:
        raise RuntimeError("source changed during independent generation/package process")
    return {
        "schema_version": "spell.v04.independent-build/1",
        "process_id": os.getpid(),
        "source_fingerprint_sha256": source_before,
        "descriptor_sha256": descriptor_sha,
        "generation_manifest_sha256": generation_manifest,
        "package_sha256": hashlib.sha256(package).hexdigest(),
        "product_path_count": len(paths),
    }


def probe_sc_004(root: Path, provenance_output: Path | None = None) -> dict[str, Any]:
    source_before = source_fingerprint_v04(root)
    command = (
        sys.executable,
        str(Path(__file__).resolve()),
        "--root",
        str(root),
        "probe-sc-004-once",
    )
    processes = [
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(2)
    ]
    results: list[dict[str, Any]] = []
    for process in processes:
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            detail = stderr.strip().splitlines()
            suffix = f": {detail[-1]}" if detail else ""
            raise RuntimeError(f"independent SC004 process failed{suffix}")
        lines = [line for line in stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("independent SC004 process emitted no JSON")
        value = json.loads(lines[-1])
        if not isinstance(value, dict) or value.get("schema_version") != "spell.v04.independent-build/1":
            raise RuntimeError("independent SC004 process result schema differs")
        results.append(value)
    process_ids = {item.get("process_id") for item in results}
    if len(process_ids) != 2 or not all(isinstance(item, int) for item in process_ids):
        raise RuntimeError("SC004 generation/package builds did not use distinct processes")
    compared_fields = (
        "source_fingerprint_sha256",
        "descriptor_sha256",
        "generation_manifest_sha256",
        "package_sha256",
        "product_path_count",
    )
    if any(results[0].get(key) != results[1].get(key) for key in compared_fields):
        raise RuntimeError("independent SC004 generation/package results differ")
    if results[0]["source_fingerprint_sha256"] != source_before:
        raise RuntimeError("independent SC004 process used a stale source fingerprint")
    if source_fingerprint_v04(root) != source_before:
        raise RuntimeError("source changed during independent SC004 processes")
    if provenance_output is not None:
        output = provenance_output.resolve()
        parent = output.parent
        if (
            not parent.is_dir()
            or parent.is_symlink()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeError("SC004 provenance output path is not fresh and safe")
        output.mkdir()
        try:
            for index, child in enumerate(results, start=1):
                path = output / f"independent-build-{index}.json"
                data = (
                    json.dumps(child, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("ascii")
                with path.open("xb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
        except Exception:
            for path in output.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            output.rmdir()
            raise
    descriptor_sha = results[0]["descriptor_sha256"]
    generation_manifest = results[0]["generation_manifest_sha256"]
    package_sha = results[0]["package_sha256"]
    binding = hashlib.sha256(
        (
            source_before
            + "\0"
            + descriptor_sha
            + "\0"
            + generation_manifest
            + "\0"
            + package_sha
        ).encode("ascii")
    ).hexdigest()
    return _result(
        "V04-SC-004",
        root,
        (
            "two-offline-generations-are-byte-identical",
            "generation-and-package-builds-use-distinct-operating-system-processes",
            "generated-artifacts-match-committed-bytes",
            "two-immutable-product-package-builds-are-byte-identical",
            "generation-and-package-share-one-source-descriptor-evidence-binding",
        ),
        {
            "generation_build_count": 2,
            "generation_process_count": 2,
            "generation_byte_identical": True,
            "package_build_count": 2,
            "package_process_count": 2,
            "package_byte_identical": True,
            "distinct_build_process_count": 2,
            "generation_source_fingerprint_sha256": source_before,
            "package_source_fingerprint_sha256": source_before,
            "descriptor_sha256": descriptor_sha,
            "generation_manifest_sha256": generation_manifest,
            "generation_evidence_sha256": binding,
            "package_evidence_sha256": binding,
            "package_sha256": package_sha,
        },
    )


def _tree_snapshot(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return {
        item.relative_to(path).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(path.rglob("*"))
        if item.is_file() and not item.is_symlink()
    }


def probe_sc_005(root: Path) -> dict[str, Any]:
    before = _tree_snapshot(root / "artifacts/v0.3")
    paths = build_reproducible_v04.product_files_v04(root)
    archive = build_reproducible_v04._archive_bytes_v04(root, paths)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        names = set(package.getnames())
    after = _tree_snapshot(root / "artifacts/v0.3")
    v03_names = [name for name in names if name.startswith("artifacts/v0.3/")]
    generated_browser = [
        name
        for name in names
        if any(part in build_reproducible_v04.EXCLUDED_DIRECTORY_NAMES for part in Path(name).parts)
    ]
    if before != after or v03_names or generated_browser:
        raise RuntimeError("v0.4 package probe violated version/evidence isolation")
    relative = {path.relative_to(root).as_posix() for path in paths}
    generated = relative & set(build_reproducible_v04.REQUIRED_GENERATED_CONTRACT_ASSETS)
    product_assets = {
        name
        for name in relative
        if name.startswith(("frontend/src/", "backend/", "driver_host/", "spell/"))
        and name not in generated
    }
    return _result(
        "V04-SC-005",
        root,
        (
            "v04-artifact-path-is-isolated",
            "retained-v03-evidence-was-not-consumed-or-mutated",
            "candidate-package-has-no-v03-evidence",
            "generated-browser-output-is-excluded",
            "product-and-generated-contract-assets-are-retained",
        ),
        {
            "artifact_root": "artifacts/v0.4",
            "v03_evidence_file_count": len(v03_names),
            "v03_overwrite_count": 0 if before == after else 1,
            "generated_browser_image_count": len(generated_browser),
            "product_asset_count": len(product_assets),
            "generated_contract_asset_count": len(generated),
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "command",
        choices=(
            "validate-locks",
            "probe-sc-001",
            "probe-sc-002",
            "probe-sc-003",
            "probe-sc-004",
            "probe-sc-004-once",
            "probe-sc-005",
        ),
    )
    parser.add_argument("--marker-root", type=Path, default=Path("/"))
    parser.add_argument("--inspection-report", type=Path)
    parser.add_argument("--inspection-report-sha256")
    parser.add_argument("--provenance-output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == "validate-locks":
        print(json.dumps(validate_locks(root).__dict__, sort_keys=True, separators=(",", ":")))
    elif args.command == "probe-sc-001":
        print(json.dumps(probe_sc_001(root, args.marker_root), sort_keys=True, separators=(",", ":")))
    elif args.command == "probe-sc-002":
        print(json.dumps(probe_sc_002(root), sort_keys=True, separators=(",", ":")))
    elif args.command == "probe-sc-003":
        if args.inspection_report is None or args.inspection_report_sha256 is None:
            parser.error(
                "probe-sc-003 requires --inspection-report and --inspection-report-sha256"
            )
        print(
            json.dumps(
                probe_sc_003(root, args.inspection_report, args.inspection_report_sha256),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    elif args.command == "probe-sc-004":
        print(
            json.dumps(
                probe_sc_004(root, args.provenance_output),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    elif args.command == "probe-sc-004-once":
        print(json.dumps(probe_sc_004_once(root), sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(probe_sc_005(root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
