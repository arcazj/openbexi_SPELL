#!/usr/bin/env python3
"""Build or validate the exact source-bound SEC003 prepublish corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.qualify_browser_v04 import (  # noqa: E402
    BrowserQualificationError,
    validate_browser_provenance_v04,
)
from scripts.collect_regression_v04 import (  # noqa: E402
    RegressionCollectorError,
    validate_capture as validate_regression_capture_v04,
)
from scripts.qualify_faults_v04 import ProbeError, load_runtime_input  # noqa: E402
from scripts.source_fingerprint_v04 import source_fingerprint_v04  # noqa: E402
from scripts.validate_release_evidence_v04 import (  # noqa: E402
    SBOM_FILES,
    validate_sboms_v04,
)


SCHEMA_VERSION = "spell.v04.sec003-prepublish/1"
CATEGORIES = (
    "browser_storage",
    "frontend_bundle",
    "runtime_captures",
    "sboms",
    "screenshots",
)
SBOM_NAMES = frozenset(SBOM_FILES)
SBOM_SOURCE_NAMES = frozenset((*SBOM_FILES, "SHA256SUMS"))
BROWSER_PROVENANCE_NAMES = frozenset(
    {
        "desktop.json",
        "faults-desktop.json",
        "faults-mobile.json",
        "manifest.json",
        "mobile.json",
    }
)
SCREENSHOT_NAMES = {
    "driver-projection-desktop.png",
    "driver-projection-mobile.png",
}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

FRONTEND_FILE_LIMIT = 4_096
FRONTEND_FILE_BYTES = 64 * 1024 * 1024
FRONTEND_TOTAL_BYTES = 512 * 1024 * 1024
BROWSER_STORAGE_BYTES = 128 * 1024
SCREENSHOT_BYTES = 16 * 1024 * 1024
SBOM_FILE_BYTES = 64 * 1024 * 1024
SBOM_TOTAL_BYTES = 256 * 1024 * 1024
RUNTIME_FILE_LIMIT = 256
RUNTIME_FILE_BYTES = 1024 * 1024 * 1024
RUNTIME_TOTAL_BYTES = 4 * 1024 * 1024 * 1024

SECRET_PATTERNS = (
    re.compile(rb"(?i)-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----"),
    re.compile(rb"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(rb"(?i)://[^/@\s:]+:[^/@\s]+@"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{32,}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(rb"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(rb"spell-v04-service-secret-"),
)
SENSITIVE_ENVIRONMENT_NAME = re.compile(
    r"(?i)(?:password|secret|token|private_key|client_key|api_key|access_key)"
)
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class PrepublishError(RuntimeError):
    """An SEC003 input or output violates the closed staging contract."""


@dataclass(frozen=True)
class Bounds:
    file_count: int
    file_bytes: int
    total_bytes: int
    allow_empty: bool = False


@dataclass(frozen=True)
class FileRecord:
    bytes: int
    sha256: str


@dataclass(frozen=True)
class TreeSnapshot:
    files: Mapping[str, FileRecord]
    directories: frozenset[str]


@dataclass(frozen=True)
class CategoryPlan:
    sources: Mapping[str, Path]
    snapshot: TreeSnapshot
    bounds: Bounds


@dataclass(frozen=True)
class Inputs:
    root: Path
    destination: Path
    source_fingerprint: str
    frontend_bundle: Path
    browser_provenance: Path
    browser_storage: Path
    desktop_screenshot: Path
    mobile_screenshot: Path
    sbom_directory: Path
    runtime_captures: Path


@dataclass(frozen=True)
class PreparedInputs:
    source_fingerprint: str
    plans: Mapping[str, CategoryPlan]
    guards: Mapping[str, TreeSnapshot | FileRecord]


FRONTEND_BOUNDS = Bounds(
    FRONTEND_FILE_LIMIT, FRONTEND_FILE_BYTES, FRONTEND_TOTAL_BYTES
)
BROWSER_STORAGE_BOUNDS = Bounds(1, BROWSER_STORAGE_BYTES, BROWSER_STORAGE_BYTES)
SCREENSHOT_BOUNDS = Bounds(2, SCREENSHOT_BYTES, 2 * SCREENSHOT_BYTES)
SBOM_BOUNDS = Bounds(len(SBOM_NAMES), SBOM_FILE_BYTES, SBOM_TOTAL_BYTES)
SBOM_SOURCE_BOUNDS = Bounds(len(SBOM_SOURCE_NAMES), SBOM_FILE_BYTES, SBOM_TOTAL_BYTES)
RUNTIME_BOUNDS = Bounds(
    RUNTIME_FILE_LIMIT,
    RUNTIME_FILE_BYTES,
    RUNTIME_TOTAL_BYTES,
    allow_empty=True,
)
PROVENANCE_BOUNDS = Bounds(5, 1024 * 1024, 5 * 1024 * 1024)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PrepublishError(message)


def _absolute(base: Path, value: Path) -> Path:
    candidate = value if value.is_absolute() else base / value
    return Path(os.path.abspath(candidate))


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _strict_descendant(path: Path, parent: Path) -> bool:
    try:
        relative = Path(os.path.normcase(str(path))).relative_to(
            Path(os.path.normcase(str(parent)))
        )
    except ValueError:
        return False
    return bool(relative.parts)


def _paths_overlap(left: Path, right: Path) -> bool:
    return _same_path(left, right) or _strict_descendant(
        left, right
    ) or _strict_descendant(right, left)


def _is_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT
    )


def _assert_path_chain_safe(path: Path, label: str) -> None:
    cursor = path
    while True:
        try:
            metadata = os.lstat(cursor)
        except FileNotFoundError as exc:
            raise PrepublishError(f"{label} is missing: {cursor}") from exc
        if _is_reparse(metadata):
            raise PrepublishError(f"{label} traverses a symlink or reparse point: {cursor}")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent


def _secret_tokens(source: str) -> tuple[bytes, ...]:
    values = {f"spell-v04-service-secret-{source}".encode("ascii")}
    for name, value in os.environ.items():
        if (
            SENSITIVE_ENVIRONMENT_NAME.search(name)
            and 8 <= len(value) <= 4_096
        ):
            values.add(value.encode("utf-8"))
    return tuple(sorted(values))


def _record_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    allow_empty: bool,
    secret_tokens: tuple[bytes, ...],
) -> FileRecord:
    _assert_path_chain_safe(path, label)
    before = os.lstat(path)
    _require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    _require(
        (allow_empty or before.st_size > 0) and before.st_size <= maximum_bytes,
        f"{label} size is outside the bounded range",
    )
    digest = hashlib.sha256()
    tail_size = max((len(value) for value in secret_tokens), default=0)
    tail_size = max(4_096, tail_size) - 1
    tail = b""
    observed = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            observed += len(chunk)
            _require(observed <= maximum_bytes, f"{label} changed beyond its size bound")
            digest.update(chunk)
            window = tail + chunk
            if any(pattern.search(window) for pattern in SECRET_PATTERNS) or any(
                token and token in window for token in secret_tokens
            ):
                raise PrepublishError(f"{label} contains credential-like material")
            tail = window[-tail_size:]
    after = os.lstat(path)
    _require(
        not _is_reparse(after)
        and stat.S_ISREG(after.st_mode)
        and observed == before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns,
        f"{label} changed while it was read",
    )
    return FileRecord(observed, digest.hexdigest())


def _snapshot_tree(
    root: Path,
    *,
    label: str,
    bounds: Bounds,
    secret_tokens: tuple[bytes, ...],
) -> TreeSnapshot:
    _assert_path_chain_safe(root, label)
    metadata = os.lstat(root)
    _require(stat.S_ISDIR(metadata.st_mode), f"{label} is not a directory")
    files: dict[str, FileRecord] = {}
    directories: set[str] = set()
    pending: list[tuple[Path, Path]] = [(root, Path())]
    total = 0
    while pending:
        current, relative_root = pending.pop()
        with os.scandir(current) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name, reverse=True)
        for entry in entries:
            entry_path = Path(entry.path)
            relative_path = relative_root / entry.name
            relative = relative_path.as_posix()
            entry_metadata = entry.stat(follow_symlinks=False)
            if _is_reparse(entry_metadata):
                raise PrepublishError(
                    f"{label} contains a symlink or reparse point: {relative}"
                )
            if stat.S_ISDIR(entry_metadata.st_mode):
                directories.add(relative)
                pending.append((entry_path, relative_path))
                continue
            if not stat.S_ISREG(entry_metadata.st_mode):
                raise PrepublishError(f"{label} contains an unsafe entry: {relative}")
            _require(relative not in files, f"{label} contains a duplicate path: {relative}")
            _require(len(files) < bounds.file_count, f"{label} has too many files")
            record = _record_file(
                entry_path,
                label=f"{label} file {relative}",
                maximum_bytes=bounds.file_bytes,
                allow_empty=bounds.allow_empty,
                secret_tokens=secret_tokens,
            )
            total += record.bytes
            _require(total <= bounds.total_bytes, f"{label} exceeds its corpus size bound")
            files[relative] = record
    _require(files, f"{label} is empty")
    return TreeSnapshot(dict(sorted(files.items())), frozenset(directories))


def _strict_json(path: Path, label: str, maximum_bytes: int) -> dict[str, Any]:
    _assert_path_chain_safe(path, label)
    metadata = os.lstat(path)
    _require(
        stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= maximum_bytes,
        f"{label} size is outside the bounded range",
    )

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            _require(key not in value, f"{label} has a duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise PrepublishError(f"{label} has a non-finite JSON number: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PrepublishError(f"{label} is not strict UTF-8 JSON") from exc
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _frontend_digest(snapshot: TreeSnapshot) -> str:
    digest = hashlib.sha256()
    for relative, record in sorted(snapshot.files.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(record.sha256))
    return digest.hexdigest()


def _assert_canonical_inputs(inputs: Inputs) -> None:
    root = inputs.root
    source = inputs.source_fingerprint
    capture_root = root / "artifacts" / "v0.4" / ".qualification" / "runtime-captures"
    source_capture_root = capture_root / source
    expected = {
        "frontend bundle": source_capture_root / "regression" / "frontend-dist",
        "browser provenance": root / "artifacts" / "v0.4" / "provenance" / "browser",
        "browser storage": root / "artifacts" / "v0.4" / "browser-storage.json",
        "desktop screenshot": root / "artifacts" / "v0.4" / "driver-projection-desktop.png",
        "mobile screenshot": root / "artifacts" / "v0.4" / "driver-projection-mobile.png",
        "SBOM directory": root / "artifacts" / "v0.4" / "sbom",
    }
    actual = {
        "frontend bundle": inputs.frontend_bundle,
        "browser provenance": inputs.browser_provenance,
        "browser storage": inputs.browser_storage,
        "desktop screenshot": inputs.desktop_screenshot,
        "mobile screenshot": inputs.mobile_screenshot,
        "SBOM directory": inputs.sbom_directory,
    }
    for label, expected_path in expected.items():
        _require(
            _same_path(actual[label], expected_path),
            f"{label} is not the canonical source-bound v0.4 path",
        )
    _require(
        _strict_descendant(inputs.runtime_captures, source_capture_root)
        and not _paths_overlap(
            inputs.runtime_captures, source_capture_root / "regression"
        ),
        "runtime captures are not a dedicated corpus beneath the source-bound capture root",
    )


def _validate_source_bindings(
    inputs: Inputs,
    frontend: TreeSnapshot,
) -> None:
    source = inputs.source_fingerprint
    try:
        validate_regression_capture_v04(inputs.root, inputs.frontend_bundle.parent)
    except (OSError, RegressionCollectorError, ValueError) as exc:
        raise PrepublishError(
            f"frontend regression provenance is invalid: {exc}"
        ) from exc

    run_path = inputs.frontend_bundle.parent / "run.json"
    run = _strict_json(run_path, "regression run manifest", 16 * 1024 * 1024)
    build = run.get("frontend_build")
    _require(
        run.get("schema_version") == "spell.v04.regression-run/1"
        and run.get("source_fingerprint_before_sha256") == source
        and run.get("source_fingerprint_after_sha256") == source,
        "frontend bundle regression source binding is stale",
    )
    _require(
        isinstance(build, dict)
        and set(build) == {"file_count", "sha256"}
        and build.get("file_count") == len(frontend.files)
        and build.get("sha256") == _frontend_digest(frontend),
        "frontend bundle differs from its regression manifest",
    )

    storage = _strict_json(
        inputs.browser_storage, "browser storage inventory", BROWSER_STORAGE_BYTES
    )
    _require(
        storage.get("schema_version") == "spell.v04.browser-storage/1"
        and storage.get("source_fingerprint_sha256") == source,
        "browser storage source binding is stale",
    )
    try:
        validate_browser_provenance_v04(inputs.root, source)
    except BrowserQualificationError as exc:
        raise PrepublishError(f"browser provenance is invalid: {exc}") from exc

    try:
        validate_sboms_v04(inputs.root, source)
    except (FileNotFoundError, ValueError) as exc:
        raise PrepublishError(f"SBOM source binding is invalid: {exc}") from exc

    try:
        load_runtime_input(
            inputs.runtime_captures / "runtime-fault-evidence.json",
            expected_source=source,
            require_readonly=False,
            release_toolchain_root=inputs.root,
        )
    except (OSError, ProbeError, ValueError) as exc:
        raise PrepublishError(f"runtime capture source binding is invalid: {exc}") from exc


def _direct_plan(
    sources: Mapping[str, Path],
    records: Mapping[str, FileRecord],
    bounds: Bounds,
) -> CategoryPlan:
    return CategoryPlan(
        dict(sorted(sources.items())),
        TreeSnapshot(dict(sorted(records.items())), frozenset()),
        bounds,
    )


def _prepare_inputs(inputs: Inputs) -> PreparedInputs:
    _require(
        SHA256_PATTERN.fullmatch(inputs.source_fingerprint) is not None,
        "expected source fingerprint is invalid",
    )
    _assert_path_chain_safe(inputs.root, "source root")
    _require(stat.S_ISDIR(os.lstat(inputs.root).st_mode), "source root is not a directory")
    observed_source = source_fingerprint_v04(inputs.root)
    _require(
        observed_source == inputs.source_fingerprint,
        "current source differs from the explicitly frozen source fingerprint",
    )
    _assert_canonical_inputs(inputs)
    secret_tokens = _secret_tokens(observed_source)

    frontend = _snapshot_tree(
        inputs.frontend_bundle,
        label="frontend bundle",
        bounds=FRONTEND_BOUNDS,
        secret_tokens=secret_tokens,
    )
    _require("index.html" in frontend.files, "frontend bundle lacks index.html")
    frontend_directories = {
        parent.as_posix()
        for relative in frontend.files
        for parent in Path(relative).parents
        if parent != Path(".")
    }
    _require(
        frontend.directories == frontend_directories,
        "frontend bundle contains an unmanifested empty directory",
    )
    frontend_sources = {
        relative: inputs.frontend_bundle.joinpath(*Path(relative).parts)
        for relative in frontend.files
    }

    provenance = _snapshot_tree(
        inputs.browser_provenance,
        label="browser provenance",
        bounds=PROVENANCE_BOUNDS,
        secret_tokens=secret_tokens,
    )
    _require(
        set(provenance.files) == BROWSER_PROVENANCE_NAMES
        and not provenance.directories,
        "browser provenance differs from its exact five-file inventory",
    )

    storage_record = _record_file(
        inputs.browser_storage,
        label="browser storage inventory",
        maximum_bytes=BROWSER_STORAGE_BYTES,
        allow_empty=False,
        secret_tokens=secret_tokens,
    )
    screenshot_sources = {
        "driver-projection-desktop.png": inputs.desktop_screenshot,
        "driver-projection-mobile.png": inputs.mobile_screenshot,
    }
    screenshot_records: dict[str, FileRecord] = {}
    for name, path in screenshot_sources.items():
        record = _record_file(
            path,
            label=f"browser screenshot {name}",
            maximum_bytes=SCREENSHOT_BYTES,
            allow_empty=False,
            secret_tokens=secret_tokens,
        )
        _require(record.bytes > len(PNG_SIGNATURE), f"browser screenshot is empty: {name}")
        with path.open("rb") as stream:
            _require(stream.read(len(PNG_SIGNATURE)) == PNG_SIGNATURE, f"browser screenshot is not PNG: {name}")
        screenshot_records[name] = record

    sbom_source = _snapshot_tree(
        inputs.sbom_directory,
        label="SBOM source directory",
        bounds=SBOM_SOURCE_BOUNDS,
        secret_tokens=secret_tokens,
    )
    _require(
        set(sbom_source.files) == SBOM_SOURCE_NAMES and not sbom_source.directories,
        "SBOM source directory differs from the exact four inventories and checksum manifest",
    )
    sbom_sources = {
        name: inputs.sbom_directory / name for name in sorted(SBOM_NAMES)
    }
    sbom_records = {name: sbom_source.files[name] for name in sorted(SBOM_NAMES)}

    runtime = _snapshot_tree(
        inputs.runtime_captures,
        label="runtime capture corpus",
        bounds=RUNTIME_BOUNDS,
        secret_tokens=secret_tokens,
    )
    runtime_sources = {
        relative: inputs.runtime_captures.joinpath(*Path(relative).parts)
        for relative in runtime.files
    }

    _validate_source_bindings(inputs, frontend)
    run_record = _record_file(
        inputs.frontend_bundle.parent / "run.json",
        label="regression run manifest",
        maximum_bytes=16 * 1024 * 1024,
        allow_empty=False,
        secret_tokens=secret_tokens,
    )
    plans = {
        "browser_storage": _direct_plan(
            {"browser-storage.json": inputs.browser_storage},
            {"browser-storage.json": storage_record},
            BROWSER_STORAGE_BOUNDS,
        ),
        "frontend_bundle": CategoryPlan(frontend_sources, frontend, FRONTEND_BOUNDS),
        "runtime_captures": CategoryPlan(runtime_sources, runtime, RUNTIME_BOUNDS),
        "sboms": _direct_plan(sbom_sources, sbom_records, SBOM_BOUNDS),
        "screenshots": _direct_plan(
            screenshot_sources, screenshot_records, SCREENSHOT_BOUNDS
        ),
    }
    return PreparedInputs(
        observed_source,
        plans,
        {
            "browser_provenance": provenance,
            "regression_run": run_record,
            "sbom_source": sbom_source,
        },
    )


def _copy_file(
    source: Path,
    destination: Path,
    expected: FileRecord,
    secret_tokens: tuple[bytes, ...],
) -> None:
    current = _record_file(
        source,
        label=f"copy source {source}",
        maximum_bytes=expected.bytes,
        allow_empty=expected.bytes == 0,
        secret_tokens=secret_tokens,
    )
    _require(current == expected, f"copy source changed before staging: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied = 0
    with source.open("rb") as reader, destination.open("xb") as writer:
        while chunk := reader.read(1024 * 1024):
            copied += len(chunk)
            digest.update(chunk)
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    _require(
        FileRecord(copied, digest.hexdigest()) == expected,
        f"staged file differs from its source: {destination}",
    )


def _copy_plan(
    destination: Path,
    plan: CategoryPlan,
    secret_tokens: tuple[bytes, ...],
) -> None:
    destination.mkdir()
    for relative in sorted(plan.snapshot.directories, key=lambda value: (value.count("/"), value)):
        destination.joinpath(*Path(relative).parts).mkdir()
    for relative, source in sorted(plan.sources.items()):
        _copy_file(
            source,
            destination.joinpath(*Path(relative).parts),
            plan.snapshot.files[relative],
            secret_tokens,
        )


def _snapshot_prepublish(
    destination: Path,
    prepared: PreparedInputs,
) -> Mapping[str, TreeSnapshot]:
    _assert_path_chain_safe(destination, "SEC003 prepublish root")
    _require(stat.S_ISDIR(os.lstat(destination).st_mode), "SEC003 prepublish root is not a directory")
    with os.scandir(destination) as iterator:
        entries = list(iterator)
    _require(
        {entry.name for entry in entries} == set(CATEGORIES)
        and all(
            stat.S_ISDIR(entry.stat(follow_symlinks=False).st_mode)
            and not _is_reparse(entry.stat(follow_symlinks=False))
            for entry in entries
        ),
        "SEC003 prepublish root differs from the exact five category directories",
    )
    tokens = _secret_tokens(prepared.source_fingerprint)
    observed: dict[str, TreeSnapshot] = {}
    for category in CATEGORIES:
        plan = prepared.plans[category]
        snapshot = _snapshot_tree(
            destination / category,
            label=f"SEC003 {category} category",
            bounds=plan.bounds,
            secret_tokens=tokens,
        )
        _require(
            snapshot == plan.snapshot,
            f"SEC003 {category} category differs from its exact source inventory",
        )
        observed[category] = snapshot
    return observed


def _corpus_report(
    source: str,
    snapshots: Mapping[str, TreeSnapshot],
) -> dict[str, Any]:
    corpus = hashlib.sha256()
    categories: dict[str, dict[str, Any]] = {}
    total_files = 0
    total_bytes = 0
    for category in CATEGORIES:
        snapshot = snapshots[category]
        category_digest = hashlib.sha256()
        category_bytes = 0
        for relative in sorted(snapshot.directories):
            for digest in (category_digest, corpus):
                digest.update(category.encode("ascii"))
                digest.update(b"\0")
                digest.update(relative.encode("utf-8"))
                digest.update(b"\0directory\0")
        for relative, record in sorted(snapshot.files.items()):
            for digest in (category_digest, corpus):
                digest.update(category.encode("ascii"))
                digest.update(b"\0")
                digest.update(relative.encode("utf-8"))
                digest.update(b"\0")
                digest.update(str(record.bytes).encode("ascii"))
                digest.update(b"\0")
                digest.update(record.sha256.encode("ascii"))
                digest.update(b"\0")
            category_bytes += record.bytes
        categories[category] = {
            "file_count": len(snapshot.files),
            "byte_count": category_bytes,
            "sha256": category_digest.hexdigest(),
        }
        total_files += len(snapshot.files)
        total_bytes += category_bytes
    return {
        "schema_version": SCHEMA_VERSION,
        "source_fingerprint_sha256": source,
        "category_count": len(categories),
        "file_count": total_files,
        "byte_count": total_bytes,
        "corpus_sha256": corpus.hexdigest(),
        "categories": categories,
    }


def _remove_owned_tree(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if _is_reparse(metadata):
        if stat.S_ISDIR(metadata.st_mode):
            os.rmdir(path)
        else:
            os.unlink(path)
        return
    if not stat.S_ISDIR(metadata.st_mode):
        os.unlink(path)
        return
    with os.scandir(path) as iterator:
        children = [Path(entry.path) for entry in iterator]
    for child in children:
        _remove_owned_tree(child)
    os.rmdir(path)


def _assert_destination_disjoint(inputs: Inputs) -> None:
    sources = (
        inputs.frontend_bundle,
        inputs.browser_provenance,
        inputs.browser_storage,
        inputs.desktop_screenshot,
        inputs.mobile_screenshot,
        inputs.sbom_directory,
        inputs.runtime_captures,
    )
    _require(
        not any(_paths_overlap(inputs.destination, source) for source in sources),
        "SEC003 destination overlaps an input or binding source",
    )


def build_prepublish(inputs: Inputs) -> dict[str, Any]:
    """Validate explicit producers and atomically install one fresh corpus."""

    _assert_destination_disjoint(inputs)
    _require(
        not os.path.lexists(inputs.destination),
        "SEC003 destination must be fresh",
    )
    parent = inputs.destination.parent
    _assert_path_chain_safe(parent, "SEC003 destination parent")
    _require(stat.S_ISDIR(os.lstat(parent).st_mode), "SEC003 destination parent is not a directory")
    prepared = _prepare_inputs(inputs)
    token = uuid.uuid4().hex
    staging = parent / f".sec003-stage-{token}"
    _require(not os.path.lexists(staging), "SEC003 staging path already exists")
    installed = False
    try:
        staging.mkdir()
        secret_tokens = _secret_tokens(prepared.source_fingerprint)
        for category in CATEGORIES:
            _copy_plan(staging / category, prepared.plans[category], secret_tokens)
        snapshots = _snapshot_prepublish(staging, prepared)
        refreshed = _prepare_inputs(inputs)
        _require(refreshed == prepared, "SEC003 producer inputs changed during staging")
        _require(
            not os.path.lexists(inputs.destination),
            "SEC003 destination appeared during staging",
        )
        os.replace(staging, inputs.destination)
        installed = True
        return _corpus_report(prepared.source_fingerprint, snapshots)
    finally:
        if not installed:
            _remove_owned_tree(staging)


def validate_prepublish(inputs: Inputs) -> dict[str, Any]:
    """Revalidate a corpus against every explicit canonical producer input."""

    _assert_destination_disjoint(inputs)
    prepared = _prepare_inputs(inputs)
    snapshots = _snapshot_prepublish(inputs.destination, prepared)
    return _corpus_report(prepared.source_fingerprint, snapshots)


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--source-fingerprint", required=True)
    parser.add_argument("--frontend-bundle", type=Path, required=True)
    parser.add_argument("--browser-provenance", type=Path, required=True)
    parser.add_argument("--browser-storage", type=Path, required=True)
    parser.add_argument("--desktop-screenshot", type=Path, required=True)
    parser.add_argument("--mobile-screenshot", type=Path, required=True)
    parser.add_argument("--sbom-directory", type=Path, required=True)
    parser.add_argument("--runtime-captures", type=Path, required=True)


def _inputs_from_arguments(arguments: argparse.Namespace) -> Inputs:
    root = _absolute(Path.cwd(), arguments.root)
    return Inputs(
        root=root,
        destination=_absolute(root, arguments.destination),
        source_fingerprint=arguments.source_fingerprint,
        frontend_bundle=_absolute(root, arguments.frontend_bundle),
        browser_provenance=_absolute(root, arguments.browser_provenance),
        browser_storage=_absolute(root, arguments.browser_storage),
        desktop_screenshot=_absolute(root, arguments.desktop_screenshot),
        mobile_screenshot=_absolute(root, arguments.mobile_screenshot),
        sbom_directory=_absolute(root, arguments.sbom_directory),
        runtime_captures=_absolute(root, arguments.runtime_captures),
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    _add_common_arguments(commands.add_parser("build"))
    _add_common_arguments(commands.add_parser("validate"))
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    try:
        inputs = _inputs_from_arguments(arguments)
        result = (
            build_prepublish(inputs)
            if arguments.command == "build"
            else validate_prepublish(inputs)
        )
    except (OSError, ValueError, PrepublishError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
