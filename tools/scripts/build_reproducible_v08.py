#!/usr/bin/env python3
"""Build and byte-verify the bounded SPELL v0.8 source release package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIRECTORY = Path("artifacts/v0.8")
DEFAULT_OUTPUT = EVIDENCE_DIRECTORY / "openbexi-spell-v0.8.0.tar.gz"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v08 import (  # noqa: E402
    FINGERPRINT_FILES,
    FINGERPRINT_TREES,
    path_has_link_or_reparse_v08,
    source_fingerprint_v08,
)
from scripts.accepted_v07_release_v08 import (  # noqa: E402
    V07_ARCHIVE_SHA256,
    V07_SIDECAR_SHA256,
    V07_TAG_ARCHIVE_CLAIM,
    V07_TAG_OBJECT,
)


EXCLUDED_DIRECTORY_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".qualification",
    ".ruff_cache",
    ".vite",
    "coverage",
    "dist",
    "htmlcov",
    "node_modules",
    "playwright-report",
    "test-results",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tsbuildinfo"}
ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
RUNTIME_SUFFIXES = {".db", ".journal", ".shm", ".sqlite", ".sqlite3", ".wal"}
RUNTIME_PARTS = {"journal-data", "runtime-journal", "runtime_journal", "var"}
SECRET_NAMES = {".env", "credentials.json", "secrets.json", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
SECRET_SUFFIXES = {".jks", ".key", ".p12", ".pem", ".pfx"}
SECRET_PATTERNS = (
    re.compile(br"-----BEGIN (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----"),
    re.compile(br"AKIA[0-9A-Z]{16}"),
    re.compile(br"gh[pousr]_[A-Za-z0-9]{32,}"),
    re.compile(br"xox[baprs]-[A-Za-z0-9-]{20,}"),
)
PEM_PRIVATE_KEY_BEGIN = b"-----BEGIN " + b"PRIVATE KEY-----"
AWS_ACCESS_KEY_CANARY = b"AKIA" + b"ABCDEFGHIJKLMNOP"

# Product source includes fail-closed scanner tests and scanner literals.  Remove
# only these exact structured occurrences for scanning; archive their original
# bytes unchanged.
SECRET_SCANNER_LITERAL_CONTRACT = {
    "backend/tests/test_ir_v06.py": (
        b'    [\n'
        b'        "'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\nredacted",\n'
        b'        "Bearer abcdefghijklmnopqrstuvwxyz",\n'
        b'        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.signaturevalue",\n'
        b'        "password=plaintext-value",\n'
        b'        "https://operator:plaintext@example.invalid/path",\n'
        b'        "github_pat_abcdefghijklmnopqrstuvwxyz123456",\n'
        b'    ],\n',
        b'    [\n'
        b'        "'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\nredacted",\n'
        + b'        "'
        + AWS_ACCESS_KEY_CANARY
        + b'",\n'
        b'        "postgresql://operator:plaintext@example.invalid/app",\n'
        b'        "github_pat_abcdefghijklmnopqrstuvwxyz123456",\n'
        b'    ],\n',
    ),
    "scripts/collect_fault_runtime_v04.ps1": (
        b'      "' + PEM_PRIVATE_KEY_BEGIN + b'"\n',
    ),
    "scripts/tests/test_release_v08.py": (
        b'    source.write_bytes(b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\nnot-a-real-key\\n")\n',
    ),
    "scripts/tests/test_release_v07.py": (
        b'    source.write_bytes(b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\nnot-a-real-key\\n")\n',
    ),
    "scripts/tests/test_release_v06.py": (
        b'    source.write_bytes(b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\nnot-a-real-key\\n")\n',
    ),
    "scripts/tests/test_release_v05.py": (
        b'    source.write_bytes(b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\nnot-a-real-key\\n")\n',
    ),
    "scripts/tests/test_validate_candidate_evidence_v05.py": (
        b'        b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'        b"-----END PRIVATE KEY-----"\n',
        b'        b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\n"\n'
        b'        b"MAMCAQA=\\n"\n'
        b'        b"-----END PRIVATE KEY-----"\n',
    ),
    "scripts/validate_candidate_evidence_v05.py": (
        b'    "backend/app.py-'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'    "-----END PRIVATE KEY-----\\\\n-high-confidence secret material]",\n',
    ),
    "scripts/validate_release_evidence_v07.py": (
        b'    "backend/app.py-'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'    "-----END PRIVATE KEY-----\\\\n-high-confidence secret material]",\n',
        b'        b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'        b"-----END PRIVATE KEY-----\\\\n"\n',
    ),
    "scripts/validate_release_evidence_v06.py": (
        b'    "backend/app.py-'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'    "-----END PRIVATE KEY-----\\\\n-high-confidence secret material]",\n',
        b'        b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'        b"-----END PRIVATE KEY-----\\\\n"\n',
    ),
    "scripts/validate_release_evidence_v05.py": (
        b'    "backend/app.py-'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'    "-----END PRIVATE KEY-----\\\\n-high-confidence secret material]",\n',
        b'        b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'        b"-----END PRIVATE KEY-----\\\\n"\n',
    ),
    "scripts/validate_release_evidence_v08.py": (
        b'    "backend/app.py-'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'    "-----END PRIVATE KEY-----\\\\n-high-confidence secret material]",\n',
        b'        b"'
        + PEM_PRIVATE_KEY_BEGIN
        + b'\\\\n"\n'
        b'        b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\\\n"\n'
        b'        b"-----END PRIVATE KEY-----\\\\n"\n',
    ),
}
WORK_PACKAGE_MANIFEST = "artifacts/v0.8/work-package/qualification.json"
TOOLING_EVIDENCE_PATHS = {
    "artifacts/v0.8/work-package/tests/tooling.xml",
    "artifacts/v0.8/final/tests/tooling.xml",
}
BACKEND_SECRET_EVIDENCE_PATHS = {
    "artifacts/v0.8/work-package/tests/backend-postgresql.xml",
    "artifacts/v0.8/work-package/tests/backend-sqlite.xml",
    "artifacts/v0.8/final/tests/backend-postgresql.xml",
    "artifacts/v0.8/final/tests/backend-sqlite.xml",
}
STRUCTURED_SECRET_EVIDENCE_PATHS = (
    TOOLING_EVIDENCE_PATHS | BACKEND_SECRET_EVIDENCE_PATHS
)


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError("Git release-byte validation failed")
    return result.stdout


def _validate_path(relative: Path) -> None:
    lowered_parts = {part.casefold() for part in relative.parts}
    lowered_name = relative.name.casefold()
    suffixes = {suffix.casefold() for suffix in relative.suffixes}
    if (
        len(relative.parts) >= 2
        and relative.parts[0] == "artifacts"
        and relative.parts[1] != "v0.8"
    ):
        raise ValueError(
            f"accepted prior-release evidence cannot enter v0.8 package: {relative.as_posix()}"
        )
    if relative.suffix.casefold() == ".pdf" or suffixes & ARCHIVE_SUFFIXES:
        raise ValueError(f"PDF/archive input cannot enter v0.8 package: {relative.as_posix()}")
    if relative.suffix.casefold() in RUNTIME_SUFFIXES or lowered_parts & RUNTIME_PARTS:
        raise ValueError(f"runtime journal cannot enter v0.8 package: {relative.as_posix()}")
    if lowered_name in SECRET_NAMES or relative.suffix.casefold() in SECRET_SUFFIXES or "secrets" in lowered_parts:
        raise ValueError(f"secret-bearing path cannot enter v0.8 package: {relative.as_posix()}")


def _release_evidence_scanner_input(relative: str, data: bytes) -> bytes:
    if relative == WORK_PACKAGE_MANIFEST:
        # The candidate validator parses and scans this strict manifest and all
        # referenced captures before final packaging is admitted.
        return b""
    if relative in STRUCTURED_SECRET_EVIDENCE_PATHS:
        from scripts.validate_release_evidence_v08 import _secret_scannable_evidence

        return _secret_scannable_evidence(relative, data)
    return data


def _validate_bytes(relative: Path, data: bytes) -> None:
    normalized = relative.as_posix()
    scanner_input = _release_evidence_scanner_input(normalized, data)
    if PEM_PRIVATE_KEY_BEGIN in scanner_input:
        literals = SECRET_SCANNER_LITERAL_CONTRACT.get(normalized)
        if literals is None:
            raise ValueError(
                f"high-confidence secret material cannot enter v0.8 package: {normalized}"
            )
        for literal in literals:
            if literal.count(PEM_PRIVATE_KEY_BEGIN) != 1 or scanner_input.count(literal) != 1:
                raise ValueError(
                    f"secret-scanner literal contract differs: {normalized}"
                )
            scanner_input = scanner_input.replace(literal, b"")
        if PEM_PRIVATE_KEY_BEGIN in scanner_input:
            raise ValueError(
                f"high-confidence secret material cannot enter v0.8 package: {normalized}"
            )
    for pattern in SECRET_PATTERNS:
        if pattern.search(scanner_input):
            raise ValueError(
                f"high-confidence secret material cannot enter v0.8 package: {relative.as_posix()}"
            )


def _walk(root: Path, tree: Path) -> Iterable[Path]:
    for current, directories, filenames in os.walk(tree):
        current_path = Path(current)
        for name in directories:
            candidate = current_path / name
            if path_has_link_or_reparse_v08(root, candidate):
                raise ValueError(
                    "v0.8 release input must not be a link or reparse point: "
                    f"{candidate.relative_to(root).as_posix()}"
                )
        directories[:] = sorted(
            name for name in directories if name not in EXCLUDED_DIRECTORY_NAMES
        )
        for name in sorted(filenames):
            path = current_path / name
            relative = path.relative_to(root)
            if path_has_link_or_reparse_v08(root, path):
                raise ValueError(
                    "v0.8 release input must not be a link or reparse point: "
                    f"{relative.as_posix()}"
                )
            if path.suffix.casefold() in EXCLUDED_SUFFIXES:
                continue
            _validate_path(relative)
            yield path


def product_files_v08(root: Path) -> list[Path]:
    source_root = root.resolve()
    candidates: list[Path] = []
    for tree_name in FINGERPRINT_TREES:
        tree = source_root / tree_name
        if not tree.is_dir() or path_has_link_or_reparse_v08(source_root, tree):
            raise FileNotFoundError(f"required v0.8 release tree is missing: {tree_name}")
        candidates.extend(_walk(source_root, tree))
    for file_name in FINGERPRINT_FILES:
        path = source_root / file_name
        if not path.is_file() or path_has_link_or_reparse_v08(source_root, path):
            raise FileNotFoundError(f"required v0.8 release file is missing: {file_name}")
        _validate_path(path.relative_to(source_root))
        candidates.append(path)
    return sorted(set(candidates), key=lambda path: path.relative_to(source_root).as_posix())


def release_files_v08(root: Path) -> list[Path]:
    source_root = root.resolve()
    candidates = product_files_v08(source_root)
    evidence_root = source_root / EVIDENCE_DIRECTORY
    if not evidence_root.is_dir() or path_has_link_or_reparse_v08(
        source_root, evidence_root
    ):
        raise FileNotFoundError("required v0.8 evidence directory is missing")
    for path in evidence_root.rglob("*"):
        relative = path.relative_to(source_root)
        if ".qualification" in relative.parts:
            continue
        if path_has_link_or_reparse_v08(source_root, path):
            raise ValueError(
                "v0.8 evidence input must not be a link or reparse point: "
                f"{relative.as_posix()}"
            )
        if not path.is_file():
            continue
        if path.name.endswith(".tar.gz") or path.name.endswith(".tar.gz.sha256"):
            continue
        _validate_path(relative)
        candidates.append(path)
    paths = sorted(set(candidates), key=lambda path: path.relative_to(source_root).as_posix())
    if not any(path.relative_to(source_root).as_posix() == "artifacts/v0.8/release-qualification.json" for path in paths):
        raise FileNotFoundError("required v0.8 release qualification is missing")
    return paths


def _assert_head_bytes(root: Path, paths: Iterable[Path]) -> str:
    source_root = root.resolve()
    if _git(source_root, "status", "--porcelain").strip():
        raise ValueError("v0.8 release package requires a clean worktree")
    commit = _git(source_root, "rev-parse", "HEAD").decode("ascii").strip()
    for path in paths:
        relative = path.relative_to(source_root).as_posix()
        committed = _git(source_root, "show", f"HEAD:{relative}")
        if committed != path.read_bytes():
            raise ValueError(f"packaged bytes differ from release commit: {relative}")
    return commit


def _archive_bytes(root: Path, paths: Iterable[Path]) -> bytes:
    source_root = root.resolve()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in paths:
            relative = path.relative_to(source_root).as_posix()
            data = path.read_bytes()
            _validate_bytes(Path(relative), data)
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o755 if relative.startswith("scripts/") else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0) as output:
        output.write(buffer.getvalue())
    return compressed.getvalue()


def product_package_sha256_v08(root: Path) -> str:
    return hashlib.sha256(_archive_bytes(root.resolve(), product_files_v08(root))).hexdigest()


def build_reproducible_v08(root: Path, output: Path | None = None) -> dict[str, object]:
    source_root = root.resolve()
    lexical_artifact_root = source_root / EVIDENCE_DIRECTORY
    lexical_output = output or DEFAULT_OUTPUT
    if not lexical_output.is_absolute():
        lexical_output = source_root / lexical_output
    if path_has_link_or_reparse_v08(source_root, lexical_artifact_root):
        raise ValueError("v0.8 package artifact root must not contain a link or reparse point")
    if path_has_link_or_reparse_v08(source_root, lexical_output.parent):
        raise ValueError("v0.8 package output path must not contain a link or reparse point")
    artifact_root = lexical_artifact_root.resolve()
    output_path = lexical_output.resolve()
    try:
        output_path.relative_to(artifact_root)
    except ValueError as exc:
        raise ValueError("v0.8 package output must stay under artifacts/v0.8") from exc
    if not output_path.name.endswith(".tar.gz"):
        raise ValueError("v0.8 package output must use .tar.gz")

    from scripts.validate_release_evidence_v08 import validate_release_evidence_v08

    validation_before = validate_release_evidence_v08(
        source_root, require_package=False
    )
    paths_before = release_files_v08(source_root)
    release_commit = _assert_head_bytes(source_root, paths_before)
    first = _archive_bytes(source_root, paths_before)
    paths_after = release_files_v08(source_root)
    second = _archive_bytes(source_root, paths_after)
    validation_after = validate_release_evidence_v08(
        source_root, require_package=False
    )
    if validation_before != validation_after:
        raise ValueError("v0.8 evidence changed during package construction")
    if [path.relative_to(source_root) for path in paths_before] != [
        path.relative_to(source_root) for path in paths_after
    ]:
        raise ValueError("v0.8 package input manifest changed between builds")
    if first != second:
        raise ValueError("v0.8 package builds are not byte-identical")
    if source_fingerprint_v08(source_root) != validation_before.source_fingerprint_sha256:
        raise ValueError("v0.8 source fingerprint changed during package construction")

    digest = hashlib.sha256(first).hexdigest()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sidecar = output_path.with_name(output_path.name + ".sha256")
    for path in (output_path, sidecar):
        if path.exists() and (
            not path.is_file()
            or path_has_link_or_reparse_v08(source_root, path)
        ):
            raise ValueError(f"refusing unsafe v0.8 package output: {path}")
    temporary_output = output_path.with_name(f".{output_path.name}.tmp-{uuid.uuid4().hex}")
    temporary_sidecar = sidecar.with_name(f".{sidecar.name}.tmp-{uuid.uuid4().hex}")
    try:
        temporary_output.write_bytes(first)
        temporary_sidecar.write_text(f"{digest}  {output_path.name}\n", encoding="ascii")
        os.replace(temporary_output, output_path)
        os.replace(temporary_sidecar, sidecar)
    finally:
        temporary_output.unlink(missing_ok=True)
        temporary_sidecar.unlink(missing_ok=True)
    return {
        "schema_version": "spell.v08.package-result/1",
        "product_version": "0.8.0",
        "release_commit": release_commit,
        "source_fingerprint_sha256": validation_before.source_fingerprint_sha256,
        "evidence_fingerprint_sha256": validation_before.evidence_fingerprint_sha256,
        "product_package_sha256": product_package_sha256_v08(source_root),
        "final_archive_sha256": digest,
        "package_build_count": 2,
        "package_byte_identical": True,
        "accepted_v07_release": {
            "archive_sha256": V07_ARCHIVE_SHA256,
            "sidecar_sha256": V07_SIDECAR_SHA256,
            "tag_object": V07_TAG_OBJECT,
            "tag_archive_claim": V07_TAG_ARCHIVE_CLAIM,
        },
        "output": output_path.relative_to(source_root).as_posix(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    import json

    print(json.dumps(build_reproducible_v08(args.root, args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
