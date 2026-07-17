#!/usr/bin/env python3
"""Create a deterministic source-and-frontend release archive and checksum."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.compose_qualification import compose_reports, parse_json_document
from scripts.source_fingerprint import source_fingerprint


INCLUDE = (
    "backend",
    "procedures",
    "proxy",
    "frontend",
    "scripts",
    "security",
    "artifacts/sbom",
    "artifacts/v0.3",
    "compose.yaml",
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "pyproject.toml",
    "README.md",
    "PROMPT_Instructions.md",
    "PROMPT_History.md",
    "Test_and_Integration.md",
    "SPELL_v0.1_Pre-Implementation.md",
    "SPELL_v0.2_Release.md",
    "SPELL_v0.3_Pre-Implementation.md",
    "SPELL_v0.3_Release.md",
    "LICENSE",
    "NOTICE",
    "PROVENANCE.md",
)
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".vite",
    "node_modules",
    "dist",
    "playwright-report",
    "test-results",
}
EXCLUDED_SUFFIXES = {".pyc", ".tsbuildinfo"}
GENERATED_EVIDENCE_SUFFIXES = {".png"}
QUALIFICATION_DIRECTORY = Path("artifacts/v0.3")
QUALIFICATION_REPORTS = {
    "quick": QUALIFICATION_DIRECTORY / "qualification-quick.json",
    "soak": QUALIFICATION_DIRECTORY / "qualification-soak.json",
    "browser": QUALIFICATION_DIRECTORY / "qualification-browser-stream.json",
    "composed": QUALIFICATION_DIRECTORY / "qualification.json",
}
SBOM_DIRECTORY = Path("artifacts/sbom")
SBOM_FILES = ("backend.cdx.json", "proxy.cdx.json", "frontend.cdx.json")
SBOM_SUBJECTS = {
    "backend.cdx.json": "openbexi_spell-backend:latest",
    "proxy.cdx.json": "openbexi_spell-proxy:latest",
    "frontend.cdx.json": "openbexi_spell-frontend-sbom:0.3",
}
SBOM_REQUIRED_COMPONENTS = {
    "backend.cdx.json": {
        "fastapi",
        "psycopg",
        "pydantic",
        "python-dotenv",
        "sqlalchemy",
        "uvicorn",
    },
    "proxy.cdx.json": {"nginx"},
    "frontend.cdx.json": {
        "@reduxjs/toolkit",
        "echarts",
        "lucide-react",
        "react",
        "react-dom",
        "react-redux",
    },
}
SBOM_SOURCE_FINGERPRINT_PROPERTY = "openbexi:source-fingerprint-sha256"
SBOM_IMAGE_ID_PROPERTY = "openbexi:scanned-image-id"
ALLOWED_SBOM_INPUTS = {
    (SBOM_DIRECTORY / name).as_posix() for name in (*SBOM_FILES, "SHA256SUMS")
}
ALLOWED_QUALIFICATION_INPUTS = {
    path.as_posix() for path in QUALIFICATION_REPORTS.values()
}


def _load_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(
            f"required qualification report is missing: {path.as_posix()}"
        )
    try:
        text = path.read_text(encoding="utf-8")
        report = parse_json_document(text, path.as_posix())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(
            f"qualification report is not valid unambiguous JSON: {path.as_posix()}"
        ) from exc
    if not isinstance(report, dict):
        raise ValueError(f"qualification report is not an object: {path.as_posix()}")
    return report


def _require_passed_gate(
    report: dict[str, Any], gate_name: str, report_name: str
) -> None:
    gate = report.get("gates", {}).get(gate_name)
    if not isinstance(gate, dict) or gate.get("passed") is not True:
        raise ValueError(f"{report_name} qualification gate did not pass: {gate_name}")


def validate_qualification(root: Path) -> str:
    """Reject incomplete, stale, failed, or inconsistently composed evidence."""
    reports = {
        name: _load_report(root / relative)
        for name, relative in QUALIFICATION_REPORTS.items()
    }
    expected_fingerprint = source_fingerprint(root)
    for name, report in reports.items():
        if report.get("product_version") != "0.3.0":
            raise ValueError(f"{name} qualification report has the wrong product version")
        fingerprint = report.get("source", {}).get("fingerprint_sha256")
        if fingerprint != expected_fingerprint:
            raise ValueError(
                f"{name} qualification fingerprint does not match the current source"
            )

    quick = reports["quick"]
    soak = reports["soak"]
    browser = reports["browser"]
    composed = reports["composed"]
    if quick.get("profile") != "quick" or quick.get("overall_pass") is not True:
        raise ValueError("quick qualification report is not a passing quick profile")
    for gate_name in ("rest_mutations", "event_replay", "eventhub_fanout"):
        _require_passed_gate(quick, gate_name, "quick")
    if soak.get("profile") != "soak" or soak.get("overall_pass") is not True:
        raise ValueError("soak qualification report is not a passing soak profile")
    _require_passed_gate(soak, "soak", "soak")
    if browser.get("test_id") != "V03-PERF-003" or browser.get("passed") is not True:
        raise ValueError("browser-stream qualification report did not pass")
    if (
        composed.get("profile") != "release"
        or composed.get("overall_pass") is not True
        or composed.get("acceptance_complete") is not True
    ):
        raise ValueError(
            "composed qualification report is not a complete passing release profile"
        )

    expected_sources = {
        "quick": QUALIFICATION_REPORTS["quick"].name,
        "soak": QUALIFICATION_REPORTS["soak"].name,
        "browser": QUALIFICATION_REPORTS["browser"].name,
    }
    if composed.get("source_reports") != expected_sources:
        raise ValueError(
            "composed qualification report does not name the required source reports"
        )
    reconstructed = compose_reports(quick, soak, browser, expected_sources)
    reconstructed_without_time = {
        key: value for key, value in reconstructed.items() if key != "generated_at"
    }
    composed_without_time = {
        key: value for key, value in composed.items() if key != "generated_at"
    }
    if composed_without_time != reconstructed_without_time:
        raise ValueError(
            "composed qualification gates do not match independent semantic validation"
        )
    expected_gates = {
        "rest_mutations": quick["gates"]["rest_mutations"],
        "event_replay": quick["gates"]["event_replay"],
        "browser_stream": browser,
        "soak": soak["gates"]["soak"],
    }
    if composed.get("gates") != expected_gates:
        raise ValueError("composed qualification gates do not match their source reports")
    expected_supporting = {"eventhub_fanout": quick["gates"]["eventhub_fanout"]}
    if composed.get("supporting_gates") != expected_supporting:
        raise ValueError(
            "composed supporting qualification gates do not match the quick report"
        )
    return expected_fingerprint


def validate_sboms(root: Path, expected_fingerprint: str | None = None) -> None:
    directory = root / SBOM_DIRECTORY
    expected_fingerprint = expected_fingerprint or source_fingerprint(root)
    manifest_path = directory / "SHA256SUMS"
    if not manifest_path.is_file():
        raise FileNotFoundError("required SBOM checksum manifest is missing")
    try:
        lines = manifest_path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("SBOM checksum manifest is not ASCII") from exc
    manifest: dict[str, str] = {}
    for line in lines:
        checksum, separator, name = line.partition("  ")
        if (
            separator != "  "
            or len(checksum) != 64
            or any(character not in "0123456789abcdef" for character in checksum)
            or name in manifest
        ):
            raise ValueError("SBOM checksum manifest has an invalid entry")
        manifest[name] = checksum
    if set(manifest) != set(SBOM_FILES):
        raise ValueError("SBOM checksum manifest does not name all required inventories")
    for name in SBOM_FILES:
        path = directory / name
        if not path.is_file():
            raise FileNotFoundError(f"required SBOM inventory is missing: {name}")
        try:
            text = path.read_text(encoding="utf-8")
            inventory = parse_json_document(text, name)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"SBOM inventory is not valid JSON: {name}") from exc
        if (
            not isinstance(inventory, dict)
            or inventory.get("bomFormat") != "CycloneDX"
            or inventory.get("specVersion") not in {"1.4", "1.5", "1.6"}
            or inventory.get("version") != 1
            or not isinstance(inventory.get("components"), list)
            or not inventory["components"]
        ):
            raise ValueError(f"SBOM inventory is not a populated CycloneDX document: {name}")
        components = inventory["components"]
        if not all(
            isinstance(component, dict)
            and isinstance(component.get("name"), str)
            and bool(component["name"])
            for component in components
        ):
            raise ValueError(f"SBOM inventory has an invalid component: {name}")
        component_names = {component["name"].casefold() for component in components}
        missing_components = SBOM_REQUIRED_COMPONENTS[name] - component_names
        if missing_components:
            raise ValueError(
                f"SBOM inventory is missing required components for {name}: "
                + ", ".join(sorted(missing_components))
            )
        metadata = inventory.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError(f"SBOM inventory has no metadata: {name}")
        subject = metadata.get("component")
        if (
            not isinstance(subject, dict)
            or subject.get("type") != "container"
            or subject.get("name") != SBOM_SUBJECTS[name]
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(subject.get("version")))
            is None
        ):
            raise ValueError(f"SBOM inventory subject is invalid: {name}")
        properties = metadata.get("properties")
        if not isinstance(properties, list):
            raise ValueError(f"SBOM inventory has no source binding: {name}")
        fingerprint_values = [
            item.get("value")
            for item in properties
            if isinstance(item, dict)
            and item.get("name") == SBOM_SOURCE_FINGERPRINT_PROPERTY
        ]
        if fingerprint_values != [expected_fingerprint]:
            raise ValueError(f"SBOM inventory source fingerprint is stale: {name}")
        image_id_values = [
            item.get("value")
            for item in properties
            if isinstance(item, dict) and item.get("name") == SBOM_IMAGE_ID_PROPERTY
        ]
        if image_id_values != [subject["version"]]:
            raise ValueError(f"SBOM inventory image identity is invalid: {name}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != manifest[name]:
            raise ValueError(f"SBOM checksum does not match inventory: {name}")


def validate_release_inputs(root: Path) -> str:
    fingerprint = validate_qualification(root)
    validate_sboms(root, fingerprint)
    return fingerprint


def files(root: Path):
    required_reports = {path.as_posix() for path in QUALIFICATION_REPORTS.values()}
    included_reports: set[str] = set()
    for item_name in INCLUDE:
        item = root / item_name
        if not item.exists():
            raise FileNotFoundError(f"required release input is missing: {item_name}")
        if item.is_dir():
            candidates: list[Path] = []
            for current, directories, filenames in os.walk(item):
                for directory in directories:
                    path = Path(current) / directory
                    if path.is_symlink():
                        raise ValueError(
                            "release input must not be a symlink: "
                            + path.relative_to(root).as_posix()
                        )
                directories[:] = sorted(
                    name for name in directories if name not in EXCLUDED_PARTS
                )
                candidates.extend(
                    Path(current) / name for name in sorted(filenames)
                )
        else:
            candidates = [item]
        for candidate in candidates:
            relative = candidate.relative_to(root)
            if candidate.is_symlink():
                raise ValueError(
                    f"release input must not be a symlink: {relative.as_posix()}"
                )
            relative_name = relative.as_posix()
            if (
                candidate.is_file()
                and not EXCLUDED_PARTS.intersection(candidate.parts)
                and candidate.suffix not in EXCLUDED_SUFFIXES
                and (
                    relative.parts[:2] != ("artifacts", "sbom")
                    or relative_name in ALLOWED_SBOM_INPUTS
                )
                and (
                    relative.parts[:2] != ("artifacts", "v0.3")
                    or relative_name in ALLOWED_QUALIFICATION_INPUTS
                )
                and not (
                    relative.parts[:2] == ("artifacts", "v0.3")
                    and candidate.suffix.lower() in GENERATED_EVIDENCE_SUFFIXES
                )
            ):
                if relative_name in required_reports:
                    included_reports.add(relative_name)
                yield candidate
    missing_reports = required_reports - included_reports
    if missing_reports:
        raise FileNotFoundError(
            "required qualification reports are absent from release inputs: "
            + ", ".join(sorted(missing_reports))
        )


def build(root: Path, output: Path) -> str:
    validate_release_inputs(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(files(root), key=lambda value: value.relative_to(root).as_posix()):
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o755 if relative.startswith("scripts/") else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    with output.open("wb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=0) as compressed:
            compressed.write(buffer.getvalue())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{digest}  {output.name}\n", encoding="ascii"
    )
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/openbexi-spell-v0.3.tar.gz")
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate qualification and SBOM evidence without packaging",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.validate_only:
            print(validate_release_inputs(root))
        else:
            print(build(root, args.output.resolve()))
    except (FileNotFoundError, ValueError) as exc:
        parser.exit(1, f"release validation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
