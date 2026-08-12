#!/usr/bin/env python3
"""Offline, strict CycloneDX schema validation for the v0.4 release SBOMs."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any


EXPECTED_FILES = (
    "backend.cdx.json",
    "driver.cdx.json",
    "frontend.cdx.json",
    "proxy.cdx.json",
)
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
VALIDATOR_VERSION = "11.11.0"


class CycloneDxValidationError(ValueError):
    """Raised when an inventory cannot be accepted as a strict CycloneDX BOM."""


def _reject_constant(value: str) -> None:
    raise CycloneDxValidationError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CycloneDxValidationError(f"duplicate JSON property is forbidden: {key}")
        result[key] = value
    return result


def parse_document(raw: str, label: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise CycloneDxValidationError(f"{label} exceeds the validation size limit")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise CycloneDxValidationError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CycloneDxValidationError(f"{label} must be a JSON object")
    return value


def _validator_for(spec_version: str):
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    versions = {
        "1.4": SchemaVersion.V1_4,
        "1.5": SchemaVersion.V1_5,
        "1.6": SchemaVersion.V1_6,
    }
    selected = versions.get(spec_version)
    if selected is None:
        raise CycloneDxValidationError(
            f"unsupported CycloneDX schema version: {spec_version!r}"
        )
    return JsonStrictValidator(selected)


def validate_document(raw: str, label: str) -> str:
    from cyclonedx.exception import MissingOptionalDependencyException

    document = parse_document(raw, label)
    if document.get("bomFormat") != "CycloneDX":
        raise CycloneDxValidationError(f"{label} is not a CycloneDX inventory")
    spec_version = document.get("specVersion")
    if not isinstance(spec_version, str):
        raise CycloneDxValidationError(f"{label} has no recognized specVersion")
    try:
        error = _validator_for(spec_version).validate_str(raw, all_errors=True)
    except MissingOptionalDependencyException as exc:
        raise CycloneDxValidationError(
            "CycloneDX JSON schema validation dependency is unavailable"
        ) from exc
    if error:
        details = "; ".join(str(item) for item in list(error)[:3])
        raise CycloneDxValidationError(
            f"{label} fails strict CycloneDX {spec_version} schema validation: {details}"
        )
    return spec_version


def run_negative_self_test() -> None:
    installed = distribution_version("cyclonedx-python-lib")
    if installed != VALIDATOR_VERSION:
        raise CycloneDxValidationError(
            f"CycloneDX validator version differs: {installed!r}"
        )
    valid = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "v0.4-schema-validator-self-test",
                "version": "1.0.0",
            }
        },
        "components": [],
    }
    validate_document(json.dumps(valid, separators=(",", ":")), "valid self-test")
    valid["metadata"]["component"]["type"] = "invalid-tampered-type"
    try:
        validate_document(json.dumps(valid, separators=(",", ":")), "tampered self-test")
    except CycloneDxValidationError as exc:
        if "schema validation" not in str(exc):
            raise
    else:
        raise CycloneDxValidationError(
            "CycloneDX validator accepted the deliberately tampered self-test"
        )


def validate_directory(directory: Path) -> dict[str, Any]:
    if not directory.is_dir() or directory.is_symlink():
        raise CycloneDxValidationError("SBOM validation directory is missing or unsafe")
    discovered = {path.name for path in directory.iterdir()}
    if discovered != set(EXPECTED_FILES):
        raise CycloneDxValidationError(
            "SBOM validation directory must contain exactly the four release inventories"
        )

    observed_versions: dict[str, str] = {}
    for name in EXPECTED_FILES:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise CycloneDxValidationError(f"SBOM inventory is missing or unsafe: {name}")
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise CycloneDxValidationError(f"SBOM inventory exceeds the size limit: {name}")
        try:
            raw = path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            raise CycloneDxValidationError(f"SBOM inventory is not UTF-8: {name}") from exc
        observed_versions[name] = validate_document(raw, name)

    run_negative_self_test()
    installed = distribution_version("cyclonedx-python-lib")
    if installed != VALIDATOR_VERSION:
        raise CycloneDxValidationError(
            f"CycloneDX validator version differs: {installed!r}"
        )
    return {
        "schema_version": "spell.v04.cyclonedx-validation/1",
        "validator": {
            "distribution": "cyclonedx-python-lib",
            "version": installed,
            "class": "cyclonedx.validation.json.JsonStrictValidator",
        },
        "validated_files": list(EXPECTED_FILES),
        "validated_schema_versions": observed_versions,
        "schema_validation_count": len(observed_versions),
        "network_mode": "none",
        "negative_tamper_rejected": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--directory", type=Path, required=True)
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        run_negative_self_test()
        print(
            json.dumps(
                {
                    "schema_version": "spell.v04.cyclonedx-validator-self-test/1",
                    "validator_version": distribution_version("cyclonedx-python-lib"),
                    "valid_document_accepted": True,
                    "negative_tamper_rejected": True,
                },
                separators=(",", ":"),
            )
        )
        return 0

    print(json.dumps(validate_directory(arguments.directory), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
