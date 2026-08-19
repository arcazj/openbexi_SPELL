#!/usr/bin/env python3
"""Build and byte-verify the isolated v0.4 source release package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile
import uuid
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v04 import (
    FINGERPRINT_FILES,
    FINGERPRINT_TREES,
    source_fingerprint_v04,
)
from scripts.validate_release_evidence_v04 import (
    EVIDENCE_DIRECTORY,
    EXPECTED_TEST_IDS,
    GATE_REPORTS,
    SBOM_DIRECTORY,
    SBOM_FILES,
    TEST_EVIDENCE_DIRECTORY,
    ReleaseEvidenceValidationV04,
    validate_release_evidence_v04,
)


INCLUDE_TREES = FINGERPRINT_TREES
INCLUDE_FILES = (
    *FINGERPRINT_FILES,
    "README.md",
    "PROMPT_History.md",
    "PROJECT_ROADMAP.md",
    "SPELL_v0.4_Release.md",
    "VERSION_TIMELINE.md",
    "LICENSE",
    "NOTICE",
)
DEFAULT_OUTPUT = EVIDENCE_DIRECTORY / "openbexi-spell-v0.4.tar.gz"
ALLOWED_EVIDENCE_INPUTS = {
    *(path.as_posix() for path in GATE_REPORTS.values()),
    *((TEST_EVIDENCE_DIRECTORY / f"{test_id}.json").as_posix() for test_id in EXPECTED_TEST_IDS),
    *((SBOM_DIRECTORY / name).as_posix() for name in (*SBOM_FILES, "SHA256SUMS")),
}
if any(name.startswith("artifacts/v0.4/provenance/") for name in ALLOWED_EVIDENCE_INPUTS):
    raise RuntimeError("retained provenance must not enter the product release package")
REQUIRED_GENERATED_CONTRACT_ASSETS = (
    "contracts/spell/driver/v1/driver.proto",
    "contracts/spell_driver_v1.pb",
    "spell/driver/v1/driver_pb2.py",
    "spell/driver/v1/driver_pb2.pyi",
    "spell/driver/v1/driver_pb2_grpc.py",
)

EXCLUDED_DIRECTORY_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".vite",
    "coverage",
    "dist",
    "htmlcov",
    "node_modules",
    "playwright-report",
    "screenshots",
    "test-results",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tsbuildinfo"}
ARCHIVE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
}
RUNTIME_JOURNAL_SUFFIXES = {".db", ".journal", ".shm", ".sqlite", ".sqlite3", ".wal"}
RUNTIME_JOURNAL_PARTS = {"journal-data", "runtime-journal", "runtime_journal", "var"}
RUNTIME_JOURNAL_FILE_NAMES = {
    "canonical-audit.jsonl",
    "driver-journal.bin",
    "operation-evidence.json",
}
SECRET_FILE_NAMES = {
    ".env",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
}
SECRET_SUFFIXES = {".jks", ".key", ".p12", ".pem", ".pfx"}
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".proto",
    ".ps1",
    ".py",
    ".pyi",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
HIGH_CONFIDENCE_SECRET_PATTERNS = (
    re.compile(
        br"(?m)^[\t ]*-----BEGIN (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----[\t ]*$"
    ),
    re.compile(
        br"-----BEGIN (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----\r?\n"
        br"[A-Za-z0-9+/=\r\n]+"
        br"-----END (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----"
    ),
    re.compile(br"AKIA[0-9A-Z]{16}"),
    re.compile(br"gh[pousr]_[A-Za-z0-9]{32,}"),
    re.compile(br"xox[baprs]-[A-Za-z0-9-]{20,}"),
)


def _output_path_v04(root: Path, output: Path | None) -> Path:
    source_root = root.resolve()
    artifact_root = (source_root / EVIDENCE_DIRECTORY).resolve()
    candidate = output or DEFAULT_OUTPUT
    if not candidate.is_absolute():
        candidate = source_root / candidate
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(artifact_root)
    except ValueError as exc:
        raise ValueError("v0.4 package output must stay under artifacts/v0.4") from exc
    if not relative.parts:
        raise ValueError("v0.4 package output must be a file")
    if not resolved.name.endswith(".tar.gz"):
        raise ValueError("v0.4 package output must use a .tar.gz name")
    return resolved


def _is_generated_browser_path(relative: Path) -> bool:
    lowered_parts = {part.casefold() for part in relative.parts}
    return bool(lowered_parts & {name.casefold() for name in EXCLUDED_DIRECTORY_NAMES})


def _validate_release_path_v04(relative: Path) -> None:
    lowered_name = relative.name.casefold()
    lowered_parts = {part.casefold() for part in relative.parts}
    suffixes = {suffix.casefold() for suffix in relative.suffixes}
    if relative.suffix.casefold() == ".pdf":
        raise ValueError(f"supplied/generated PDF cannot enter v0.4 package: {relative.as_posix()}")
    if suffixes & ARCHIVE_SUFFIXES:
        raise ValueError(f"legacy/archive input cannot enter v0.4 package: {relative.as_posix()}")
    if "manual" in lowered_name and relative.suffix.casefold() in TEXT_SUFFIXES:
        raise ValueError(f"manual text cannot enter v0.4 package: {relative.as_posix()}")
    if (
        lowered_name in RUNTIME_JOURNAL_FILE_NAMES
        or relative.suffix.casefold() in RUNTIME_JOURNAL_SUFFIXES
        or lowered_parts & RUNTIME_JOURNAL_PARTS
    ):
        raise ValueError(f"generated journal cannot enter v0.4 package: {relative.as_posix()}")
    if (
        lowered_name in SECRET_FILE_NAMES
        or relative.suffix.casefold() in SECRET_SUFFIXES
        or "secrets" in lowered_parts
    ):
        raise ValueError(f"secret-bearing path cannot enter v0.4 package: {relative.as_posix()}")


def _validate_release_bytes_v04(relative: Path, data: bytes) -> None:
    for pattern in HIGH_CONFIDENCE_SECRET_PATTERNS:
        if pattern.search(data):
            raise ValueError(
                f"high-confidence secret material cannot enter v0.4 package: {relative.as_posix()}"
            )


def _walk_tree_v04(root: Path, tree: Path) -> Iterable[Path]:
    for current, directories, filenames in os.walk(tree):
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                raise ValueError(
                    "v0.4 release input must not be a symlink: "
                    + path.relative_to(root).as_posix()
                )
        directories[:] = sorted(
            name for name in directories if name not in EXCLUDED_DIRECTORY_NAMES
        )
        for name in sorted(filenames):
            path = current_path / name
            relative = path.relative_to(root)
            if path.is_symlink():
                raise ValueError(
                    f"v0.4 release input must not be a symlink: {relative.as_posix()}"
                )
            if path.suffix.casefold() in EXCLUDED_SUFFIXES:
                continue
            if _is_generated_browser_path(relative):
                continue
            _validate_release_path_v04(relative)
            yield path


def product_files_v04(root: Path) -> list[Path]:
    """Return the exact inspected product inputs before generated release evidence."""

    source_root = root.resolve()
    candidates: list[Path] = []
    for tree_name in INCLUDE_TREES:
        tree = source_root / tree_name
        if not tree.is_dir() or tree.is_symlink():
            raise FileNotFoundError(f"required v0.4 release tree is missing: {tree_name}")
        candidates.extend(_walk_tree_v04(source_root, tree))
    for file_name in INCLUDE_FILES:
        path = source_root / file_name
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"required v0.4 release file is missing: {file_name}")
        _validate_release_path_v04(path.relative_to(source_root))
        candidates.append(path)

    relative_names = {path.relative_to(source_root).as_posix() for path in candidates}
    missing_contract_assets = set(REQUIRED_GENERATED_CONTRACT_ASSETS) - relative_names
    if missing_contract_assets:
        raise FileNotFoundError(
            "required v0.4 product/generated contract assets are missing: "
            + ", ".join(sorted(missing_contract_assets))
        )
    return sorted(
        set(candidates), key=lambda path: path.relative_to(source_root).as_posix()
    )


def release_files_v04(root: Path) -> list[Path]:
    """Return the exact inspected final package inputs, including v0.4 evidence."""

    source_root = root.resolve()
    candidates = product_files_v04(source_root)
    for relative_name in sorted(ALLOWED_EVIDENCE_INPUTS):
        path = source_root / relative_name
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(
                f"required v0.4 evidence package input is missing: {relative_name}"
            )
        _validate_release_path_v04(path.relative_to(source_root))
        candidates.append(path)

    relative_names = {path.relative_to(source_root).as_posix() for path in candidates}
    if any(name.startswith("artifacts/v0.4/provenance/") for name in relative_names):
        raise ValueError("retained provenance cannot enter the v0.4 product package")
    if relative_names & {
        "artifacts/v0.3/qualification.json",
        "artifacts/v0.3/qualification-quick.json",
        "artifacts/v0.3/qualification-soak.json",
        "artifacts/v0.3/qualification-browser-stream.json",
    }:
        raise ValueError("v0.3 evidence cannot enter the v0.4 package")
    return sorted(
        set(candidates), key=lambda path: path.relative_to(source_root).as_posix()
    )


def _archive_bytes_v04(root: Path, paths: Iterable[Path]) -> bytes:
    source_root = root.resolve()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in paths:
            relative = path.relative_to(source_root).as_posix()
            data = path.read_bytes()
            _validate_release_bytes_v04(Path(relative), data)
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o755 if relative.startswith("scripts/") else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0) as destination:
        destination.write(buffer.getvalue())
    return compressed.getvalue()


def product_package_sha256_v04(root: Path) -> str:
    """Hash the canonical product-only archive used by the SC004 binding."""

    source_root = root.resolve()
    archive = _archive_bytes_v04(source_root, product_files_v04(source_root))
    return hashlib.sha256(archive).hexdigest()


def _invalidate_output_v04(output: Path) -> None:
    sidecar = output.with_name(output.name + ".sha256")
    for path in (output, sidecar):
        if path.exists():
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"refusing to replace unsafe v0.4 output path: {path}")
            path.unlink()


def build_reproducible_v04(root: Path, output: Path | None = None) -> str:
    """Validate inputs, build twice, compare bytes, and atomically publish."""

    source_root = root.resolve()
    output_path = _output_path_v04(source_root, output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _invalidate_output_v04(output_path)

    initial: ReleaseEvidenceValidationV04 = validate_release_evidence_v04(
        source_root, preliminary=True
    )
    first_paths = release_files_v04(source_root)
    first = _archive_bytes_v04(source_root, first_paths)

    if source_fingerprint_v04(source_root) != initial.source_fingerprint_sha256:
        raise ValueError("v0.4 source changed during the first package build")
    second_paths = release_files_v04(source_root)
    second = _archive_bytes_v04(source_root, second_paths)
    final = validate_release_evidence_v04(source_root, preliminary=True)
    if initial != final:
        raise ValueError("v0.4 source or release evidence changed during package builds")
    if [path.relative_to(source_root) for path in first_paths] != [
        path.relative_to(source_root) for path in second_paths
    ]:
        raise ValueError("v0.4 package input manifest changed between builds")
    if first != second:
        raise ValueError("v0.4 package builds are not byte-identical")

    digest = hashlib.sha256(first).hexdigest()
    sidecar = output_path.with_name(output_path.name + ".sha256")
    temporary_output = output_path.with_name(f".{output_path.name}.tmp-{uuid.uuid4().hex}")
    temporary_sidecar = sidecar.with_name(f".{sidecar.name}.tmp-{uuid.uuid4().hex}")
    try:
        temporary_output.write_bytes(first)
        temporary_sidecar.write_text(
            f"{digest}  {output_path.name}\n", encoding="ascii"
        )
        temporary_output.replace(output_path)
        temporary_sidecar.replace(sidecar)
    except Exception:
        for path in (temporary_output, temporary_sidecar, output_path, sidecar):
            if path.is_file() and not path.is_symlink():
                path.unlink()
        raise
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate v0.4 Gate 1-5 and SBOM inputs without writing a package",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if args.validate_only:
        result = validate_release_evidence_v04(root)
        print(result.source_fingerprint_sha256)
        return 0
    digest = build_reproducible_v04(root, args.output)
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
