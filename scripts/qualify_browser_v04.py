#!/usr/bin/env python3
"""Validate source-bound real-browser observations for SPELL v0.4 Gate 3."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v04 import source_fingerprint_v04
from scripts.validate_release_evidence_v04 import SCOPE_PROFILE


OBSERVATION_SCHEMA = "spell.v04.browser-observation/1"
FAULT_OBSERVATION_SCHEMA = "spell.v04.browser-fault-observation/1"
STORAGE_SCHEMA = "spell.v04.browser-storage/1"
PROVENANCE_SCHEMA = "spell.v04.browser-provenance/1"
TEST_IDS = {
    "V04-UI-001",
    "V04-UI-002",
    "V04-UI-003",
    "V04-UI-004",
}
EXPECTED_FIXTURE = {
    "binding": "00000000-0000-4000-8000-000000000402",
    "context": "v04-ui-synthetic-context",
    "operation": "00000000-0000-4000-8000-000000000404",
}
EXPECTED_PROJECTS = {"desktop", "mobile"}
EXPECTED_HTTP_PATHS = {
    "/api/v1/drivers",
    "/api/v1/driver-contexts",
    "/api/v1/driver-bindings",
}
EXPECTED_WEBSOCKET_PATHS = {"/api/v1/driver-events/ws"}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){2,3}")
UTC_TIMESTAMP_PATTERN = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z"
)
MAX_OBSERVATION_BYTES = 128 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PROVENANCE_DIRECTORY = Path("artifacts/v0.4/provenance/browser")
STORAGE_PATH = Path("artifacts/v0.4/browser-storage.json")
OBSERVATION_NAMES = {
    "desktop.json",
    "faults-desktop.json",
    "faults-mobile.json",
    "mobile.json",
}
CAPTURE_NAMES = {
    *OBSERVATION_NAMES,
    "driver-projection-desktop.png",
    "driver-projection-mobile.png",
}
PROVENANCE_NAMES = {*OBSERVATION_NAMES, "manifest.json"}
SCREENSHOT_PATHS = {
    "desktop": Path("artifacts/v0.4/driver-projection-desktop.png"),
    "mobile": Path("artifacts/v0.4/driver-projection-mobile.png"),
}
STACK_IMAGE_NAMES = {
    "backend",
    "driver",
    "pki_init",
    "postgres",
    "proxy",
    "qualification",
}
CONFIGURATION_PATHS = (
    Path("compose.yaml"),
    Path("frontend/package-lock.json"),
    Path("frontend/playwright.config.ts"),
)
RELEASE_TOOL_SPECS = {
    "docker_cli": ("docker-cli", "docker_cli"),
    "docker_compose": ("docker-compose", "docker_compose"),
    "python": ("python", "host_python"),
}
CAPTURE_COMMANDS = [
    {"id": "frontend-build", "argv": ["npm", "run", "build"]},
    {
        "id": "real-browser",
        "argv": [
            "npx",
            "playwright",
            "test",
            "e2e/driver-projection-real.spec.ts",
            "--project=chromium",
            "--project=mobile",
        ],
    },
    {
        "id": "fault-browser",
        "argv": [
            "npx",
            "playwright",
            "test",
            "e2e/driver-projection.spec.ts",
            "--project=chromium",
            "--project=mobile",
        ],
    },
]


class BrowserQualificationError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrowserQualificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BrowserQualificationError(f"browser observation is not a regular file: {path}")
    data = path.read_bytes()
    if not data or len(data) > MAX_OBSERVATION_BYTES:
        raise BrowserQualificationError(f"browser observation has an invalid size: {path}")
    try:
        value = json.loads(data, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserQualificationError(f"browser observation is invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise BrowserQualificationError(f"browser observation must be an object: {path}")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path, label: str) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise BrowserQualificationError(f"{label} is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _exact_directory(path: Path, expected: set[str], label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise BrowserQualificationError(f"{label} is missing or unsafe")
    entries = tuple(path.iterdir())
    if {entry.name for entry in entries} != expected:
        raise BrowserQualificationError(f"{label} differs from the exact file set")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise BrowserQualificationError(f"{label} contains an unsafe entry")


def _run_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or RUN_ID_PATTERN.fullmatch(value) is None:
        raise BrowserQualificationError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise BrowserQualificationError(f"{label} is not a millisecond UTC timestamp")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" != value:
        raise BrowserQualificationError(f"{label} is not canonical")
    return parsed


def _absolute_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1_024 or "\x00" in value:
        raise BrowserQualificationError(f"{label} is invalid")
    windows_path = PureWindowsPath(value)
    if windows_path.is_absolute():
        return windows_path.as_posix()
    posix_path = PurePosixPath(value)
    if posix_path.is_absolute():
        return posix_path.as_posix()
    raise BrowserQualificationError(f"{label} must be absolute")


def _runtime_identity(
    value: Any,
    project: str,
    command_kind: str,
) -> dict[str, Any]:
    runtime = _mapping(value, f"{project}.{command_kind}.runtime")
    if set(runtime) != {
        "node_version",
        "npm_version",
        "node_executable_path",
        "node_executable_sha256",
        "playwright_version",
        "browser_name",
        "browser_version",
        "browser_executable_path",
        "browser_executable_sha256",
        "project",
        "command_profile",
        "stack_image_ids",
    }:
        raise BrowserQualificationError(f"{project} {command_kind} runtime identity shape differs")
    if runtime.get("node_version") != "v24.13.0":
        raise BrowserQualificationError(f"{project} {command_kind} Node runtime differs")
    if runtime.get("npm_version") != "11.6.2":
        raise BrowserQualificationError(f"{project} {command_kind} npm runtime differs")
    if runtime.get("playwright_version") != "1.61.1":
        raise BrowserQualificationError(f"{project} {command_kind} Playwright runtime differs")
    if runtime.get("browser_name") != "chromium":
        raise BrowserQualificationError(f"{project} {command_kind} browser runtime differs")
    if VERSION_PATTERN.fullmatch(str(runtime.get("browser_version", ""))) is None:
        raise BrowserQualificationError(f"{project} {command_kind} browser version is invalid")
    expected_project = "mobile" if project == "mobile" else "chromium"
    if (
        runtime.get("project") != expected_project
        or runtime.get("command_profile")
        != f"driver-projection-{command_kind}:{expected_project}"
    ):
        raise BrowserQualificationError(f"{project} {command_kind} project identity differs")
    for key in ("node_executable_path", "browser_executable_path"):
        _absolute_path(runtime.get(key), f"{project}.{command_kind}.runtime.{key}")
    for key in ("node_executable_sha256", "browser_executable_sha256"):
        if SHA256_PATTERN.fullmatch(str(runtime.get(key, ""))) is None:
            raise BrowserQualificationError(f"{project} {command_kind} {key} is invalid")
    stack_images = _mapping(
        runtime.get("stack_image_ids"),
        f"{project}.{command_kind}.runtime.stack_image_ids",
    )
    if set(stack_images) != STACK_IMAGE_NAMES or any(
        re.fullmatch(r"sha256:[0-9a-f]{64}", str(image_id)) is None
        for image_id in stack_images.values()
    ):
        raise BrowserQualificationError(f"{project} {command_kind} stack image identity differs")
    return runtime


def _shared_runtime_identity(runtime: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in runtime.items()
        if key not in {"project", "command_profile", "stack_image_ids"}
    }


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrowserQualificationError(f"{label} must be an object")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BrowserQualificationError(f"{label} must be an integer >= {minimum}")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item or len(item) > 2_048 for item in value)
    ):
        raise BrowserQualificationError(f"{label} must be a bounded non-empty string list")
    return value


def _png_dimensions(path: Path) -> tuple[int, int, str]:
    if path.is_symlink() or not path.is_file():
        raise BrowserQualificationError(f"browser screenshot is not a regular file: {path}")
    data = path.read_bytes()
    if len(data) < 24 or data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        raise BrowserQualificationError(f"browser screenshot is not a PNG: {path}")
    width, height = struct.unpack(">II", data[16:24])
    if width < 1 or height < 1:
        raise BrowserQualificationError(f"browser screenshot has invalid dimensions: {path}")
    return width, height, hashlib.sha256(data).hexdigest()


def _artifact_path(root: Path, relative_value: Any) -> Path:
    if not isinstance(relative_value, str) or len(relative_value) > 512:
        raise BrowserQualificationError("screenshot path is invalid")
    relative = PurePosixPath(relative_value)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:2] != ("artifacts", "v0.4"):
        raise BrowserQualificationError("screenshot path escapes artifacts/v0.4")
    candidate = root.joinpath(*relative.parts)
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise BrowserQualificationError("screenshot path escapes the source root") from exc
    return candidate


def _validate_url(value: str) -> tuple[str, int | None, str]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        raise BrowserQualificationError("browser used an unapproved URL scheme")
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise BrowserQualificationError("browser used a non-loopback host")
    if parsed.username or parsed.password or parsed.fragment:
        raise BrowserQualificationError("browser URL contains credential-like material")
    query_names = {item.partition("=")[0].casefold() for item in parsed.query.split("&") if item}
    if query_names.intersection({"access_token", "authorization", "password", "secret", "token"}):
        raise BrowserQualificationError("browser URL contains a credential query")
    folded = value.casefold()
    if "spell-driver" in folded or ":50051" in folded:
        raise BrowserQualificationError("browser attempted a direct driver connection")
    return parsed.scheme, parsed.port, parsed.path


def load_observations(
    root: Path,
    directory: Path,
    source: str,
    *,
    screenshot_directory: Path | None = None,
) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    for project in sorted(EXPECTED_PROJECTS):
        value = _read_json(directory / f"{project}.json")
        if set(value) != {
            "schema_version",
            "scope_profile",
            "run_id",
            "source_fingerprint_sha256",
            "project",
            "source_test",
            "runtime",
            "fixture",
            "viewport",
            "accessibility",
            "interaction",
            "storage",
            "network",
            "screenshot",
        }:
            raise BrowserQualificationError(f"{project} observation shape differs")
        if value.get("schema_version") != OBSERVATION_SCHEMA:
            raise BrowserQualificationError(f"{project} observation schema differs")
        if value.get("scope_profile") != SCOPE_PROFILE:
            raise BrowserQualificationError(f"{project} observation scope differs")
        _run_id(value.get("run_id"), f"{project} observation run_id")
        if value.get("source_fingerprint_sha256") != source:
            raise BrowserQualificationError(f"{project} observation fingerprint is stale")
        if value.get("project") != project:
            raise BrowserQualificationError(f"{project} observation project differs")
        if value.get("source_test") != "frontend/e2e/driver-projection-real.spec.ts":
            raise BrowserQualificationError(f"{project} observation source test differs")

        _runtime_identity(value.get("runtime"), project, "real")
        if value.get("fixture") != EXPECTED_FIXTURE:
            raise BrowserQualificationError(f"{project} observation fixture differs")

        viewport = _mapping(value.get("viewport"), f"{project}.viewport")
        viewport_width = _integer(viewport.get("width"), f"{project}.viewport.width", minimum=320)
        viewport_height = _integer(viewport.get("height"), f"{project}.viewport.height", minimum=480)
        accessibility = _mapping(value.get("accessibility"), f"{project}.accessibility")
        for key in (
            "axe_critical_finding_count",
            "axe_serious_finding_count",
            "overflow_failure_count",
        ):
            if _integer(accessibility.get(key), f"{project}.accessibility.{key}") != 0:
                raise BrowserQualificationError(f"{project} has a blocking accessibility result")
        observed_viewport_width = _integer(
            accessibility.get("viewport_width"), f"{project}.accessibility.viewport_width", minimum=320
        )
        document_width = _integer(
            accessibility.get("document_width"), f"{project}.accessibility.document_width", minimum=1
        )
        if observed_viewport_width != viewport_width or document_width > observed_viewport_width:
            raise BrowserQualificationError(f"{project} viewport containment differs")

        interaction = _mapping(value.get("interaction"), f"{project}.interaction")
        for key in ("keyboard_failure_count", "mutation_control_count"):
            if _integer(interaction.get(key), f"{project}.interaction.{key}") != 0:
                raise BrowserQualificationError(f"{project} interaction boundary failed")

        storage = _mapping(value.get("storage"), f"{project}.storage")
        if set(storage) != {
            "inspected_key_count",
            "inspected_value_count",
            "service_secret_canary_match_count",
            "removed_ephemeral_auth_token_count",
            "local_storage",
            "session_storage",
        }:
            raise BrowserQualificationError(f"{project} storage inventory shape differs")
        if _integer(storage.get("inspected_key_count"), f"{project}.storage.inspected_key_count", minimum=1) < 1:
            raise BrowserQualificationError(f"{project} did not inspect browser storage")
        if _integer(storage.get("inspected_value_count"), f"{project}.storage.inspected_value_count", minimum=1) < 1:
            raise BrowserQualificationError(f"{project} did not inspect browser storage values")
        if _integer(
            storage.get("service_secret_canary_match_count"),
            f"{project}.storage.service_secret_canary_match_count",
        ) != 0:
            raise BrowserQualificationError(f"{project} browser storage contains the service canary")
        if _integer(
            storage.get("removed_ephemeral_auth_token_count"),
            f"{project}.storage.removed_ephemeral_auth_token_count",
        ) != 1:
            raise BrowserQualificationError(f"{project} ephemeral viewer credential accounting differs")
        if storage.get("local_storage") != [] or storage.get("session_storage") != []:
            raise BrowserQualificationError(f"{project} post-workflow browser storage is not empty")

        network = _mapping(value.get("network"), f"{project}.network")
        requests = _string_list(network.get("requests"), f"{project}.network.requests")
        websockets = _string_list(network.get("websockets"), f"{project}.network.websockets")
        request_paths = {_validate_url(item)[2] for item in requests}
        websocket_paths = {_validate_url(item)[2] for item in websockets}
        if not EXPECTED_HTTP_PATHS.issubset(request_paths):
            raise BrowserQualificationError(f"{project} did not observe the required REST projection")
        if not any(path.startswith("/api/v1/driver-operations/") for path in request_paths):
            raise BrowserQualificationError(f"{project} did not observe the operation projection")
        if not EXPECTED_WEBSOCKET_PATHS.issubset(websocket_paths):
            raise BrowserQualificationError(
                f"{project} did not observe the driver downstream WebSocket"
            )

        screenshot = _mapping(value.get("screenshot"), f"{project}.screenshot")
        expected_screenshot = SCREENSHOT_PATHS[project].as_posix()
        if set(screenshot) != {"path", "sha256"} or screenshot.get("path") != expected_screenshot:
            raise BrowserQualificationError(f"{project} screenshot binding differs")
        screenshot_path = (
            screenshot_directory / SCREENSHOT_PATHS[project].name
            if screenshot_directory is not None
            else _artifact_path(root, screenshot.get("path"))
        )
        width, height, digest = _png_dimensions(screenshot_path)
        if screenshot.get("sha256") != digest:
            raise BrowserQualificationError(f"{project} screenshot digest differs")
        if width < viewport_width or height < viewport_height:
            raise BrowserQualificationError(f"{project} screenshot does not contain the viewport")
        observations[project] = value
    return observations


def load_fault_observations(directory: Path, source: str) -> dict[str, dict[str, Any]]:
    expected_states = {
        "degraded": True,
        "disconnected": True,
        "failed": True,
        "stale": True,
        "uncertain": True,
        "unsupported": True,
    }
    observations: dict[str, dict[str, Any]] = {}
    for project in sorted(EXPECTED_PROJECTS):
        value = _read_json(directory / f"faults-{project}.json")
        if set(value) != {
            "schema_version",
            "scope_profile",
            "run_id",
            "source_fingerprint_sha256",
            "project",
            "source_test",
            "runtime",
            "states",
            "non_color_cue_count",
            "mutation_control_count",
        }:
            raise BrowserQualificationError(f"{project} fault observation shape differs")
        if value.get("schema_version") != FAULT_OBSERVATION_SCHEMA:
            raise BrowserQualificationError(f"{project} fault observation schema differs")
        if value.get("scope_profile") != SCOPE_PROFILE:
            raise BrowserQualificationError(f"{project} fault observation scope differs")
        _run_id(value.get("run_id"), f"{project} fault observation run_id")
        if value.get("source_fingerprint_sha256") != source:
            raise BrowserQualificationError(f"{project} fault observation fingerprint is stale")
        if value.get("project") != project:
            raise BrowserQualificationError(f"{project} fault observation project differs")
        if value.get("source_test") != "frontend/e2e/driver-projection.spec.ts":
            raise BrowserQualificationError(f"{project} fault observation source test differs")
        _runtime_identity(value.get("runtime"), project, "fault")
        if value.get("states") != expected_states:
            raise BrowserQualificationError(f"{project} fault-state accounting differs")
        if _integer(value.get("non_color_cue_count"), f"{project}.non_color_cue_count") < 6:
            raise BrowserQualificationError(f"{project} non-color fault cues are incomplete")
        if _integer(value.get("mutation_control_count"), f"{project}.mutation_control_count") != 0:
            raise BrowserQualificationError(f"{project} exposes a driver mutation control")
        observations[project] = value
    return observations


def validate_observation_binding(
    observations: dict[str, dict[str, Any]],
    fault_observations: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any], dict[str, str]]:
    values = [
        *(observations[project] for project in sorted(EXPECTED_PROJECTS)),
        *(fault_observations[project] for project in sorted(EXPECTED_PROJECTS)),
    ]
    run_ids = {_run_id(value.get("run_id"), "browser observation run_id") for value in values}
    if len(run_ids) != 1:
        raise BrowserQualificationError("browser observations were not captured in one run")
    runtimes = [_mapping(value.get("runtime"), "browser observation runtime") for value in values]
    shared_identities = {_canonical_bytes(_shared_runtime_identity(runtime)) for runtime in runtimes}
    if len(shared_identities) != 1:
        raise BrowserQualificationError("browser observations do not share one tool identity")
    stack_bindings = {
        _canonical_bytes(_mapping(runtime.get("stack_image_ids"), "browser stack image IDs"))
        for runtime in runtimes
    }
    if len(stack_bindings) != 1:
        raise BrowserQualificationError("browser observations do not share one image binding")
    runtime = runtimes[0]
    return (
        next(iter(run_ids)),
        _shared_runtime_identity(runtime),
        dict(_mapping(runtime["stack_image_ids"], "browser stack image IDs")),
    )


def storage_inventory_document(
    source: str,
    observations: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    run_ids = {
        _run_id(observations[project].get("run_id"), f"{project} observation run_id")
        for project in sorted(EXPECTED_PROJECTS)
    }
    if len(run_ids) != 1:
        raise BrowserQualificationError("browser storage observations were not captured in one run")
    return {
        "schema_version": STORAGE_SCHEMA,
        "scope_profile": SCOPE_PROFILE,
        "run_id": next(iter(run_ids)),
        "source_fingerprint_sha256": source,
        "projects": [
            {"project": project, **observations[project]["storage"]}
            for project in sorted(observations)
        ],
    }


def _atomic_write(destination: Path, data: bytes) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise BrowserQualificationError(f"atomic destination is unsafe: {destination}")
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    if temporary.exists():
        raise BrowserQualificationError(f"atomic temporary path already exists: {temporary}")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()
    return destination


def write_storage_inventory(root: Path, source: str, observations: dict[str, dict[str, Any]]) -> Path:
    destination = root / STORAGE_PATH
    _atomic_write(destination, _canonical_bytes(storage_inventory_document(source, observations)))
    return destination


def _load_release_toolchain(root: Path) -> dict[str, Any]:
    lock = _read_json(root / "scripts" / "release-toolchain-v04.json")
    if set(lock) != {"schema_version", "host_platform", "tools", "versions"}:
        raise BrowserQualificationError("release toolchain lock shape differs")
    if (
        lock.get("schema_version") != "spell.v04.release-toolchain/1"
        or lock.get("host_platform") != "windows-amd64-docker-desktop"
        or not isinstance(lock.get("tools"), list)
        or not isinstance(lock.get("versions"), dict)
    ):
        raise BrowserQualificationError("release toolchain lock identity differs")
    return lock


def _locked_tool_entry(lock: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [entry for entry in lock["tools"] if isinstance(entry, dict) and entry.get("name") == name]
    if len(matches) != 1:
        raise BrowserQualificationError(f"release toolchain lock lacks one {name} entry")
    entry = matches[0]
    required = {"name", "base_directory", "relative_path", "sha256"}
    if name == "python":
        required.update({"archive_relative_path", "archive_sha256", "archive_url"})
    if set(entry) != required:
        raise BrowserQualificationError(f"release toolchain {name} entry shape differs")
    if entry.get("base_directory") not in {"ProgramFiles", "LocalAppData"}:
        raise BrowserQualificationError(f"release toolchain {name} base directory differs")
    relative = PurePosixPath(str(entry.get("relative_path", "")))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise BrowserQualificationError(f"release toolchain {name} path is unsafe")
    if SHA256_PATTERN.fullmatch(str(entry.get("sha256", ""))) is None:
        raise BrowserQualificationError(f"release toolchain {name} hash is invalid")
    return entry


def _record_release_tools(
    root: Path,
    executable_paths: dict[str, Path],
) -> dict[str, dict[str, Any]]:
    lock = _load_release_toolchain(root)
    records: dict[str, dict[str, Any]] = {}
    for key, (lock_name, version_key) in RELEASE_TOOL_SPECS.items():
        entry = _locked_tool_entry(lock, lock_name)
        provided = executable_paths.get(key)
        if provided is None:
            raise BrowserQualificationError(f"browser capture did not declare {key}")
        base = os.environ.get(str(entry["base_directory"]))
        if not base:
            raise BrowserQualificationError(
                f"release tool base environment is unavailable: {entry['base_directory']}"
            )
        expected = Path(base).joinpath(*PurePosixPath(entry["relative_path"]).parts)
        if expected.is_symlink() or not expected.is_file():
            raise BrowserQualificationError(f"locked browser capture tool is missing: {lock_name}")
        expected = expected.resolve()
        if provided.is_symlink() or not provided.is_file():
            raise BrowserQualificationError(f"browser capture tool is missing or unsafe: {lock_name}")
        observed = provided.resolve()
        if os.path.normcase(str(observed)) != os.path.normcase(str(expected)):
            raise BrowserQualificationError(f"browser capture used a substituted {lock_name} path")
        _, digest = _sha256_path(observed, f"locked {lock_name}")
        if digest != entry["sha256"]:
            raise BrowserQualificationError(f"browser capture used a substituted {lock_name} binary")
        version = lock["versions"].get(version_key)
        if not isinstance(version, str) or not version:
            raise BrowserQualificationError(f"release toolchain {lock_name} version is missing")
        records[key] = {
            "path": observed.as_posix(),
            "base_directory": entry["base_directory"],
            "relative_path": entry["relative_path"],
            "sha256": entry["sha256"],
            "version": version,
        }
    return records


def _validate_recorded_release_tools(
    root: Path,
    records: Any,
) -> dict[str, dict[str, Any]]:
    tools = _mapping(records, "browser provenance release_tools")
    if set(tools) != set(RELEASE_TOOL_SPECS):
        raise BrowserQualificationError("browser provenance release tool set differs")
    lock = _load_release_toolchain(root)
    for key, (lock_name, version_key) in RELEASE_TOOL_SPECS.items():
        record = _mapping(tools[key], f"browser provenance release_tools.{key}")
        if set(record) != {"path", "base_directory", "relative_path", "sha256", "version"}:
            raise BrowserQualificationError(f"browser provenance {key} tool shape differs")
        entry = _locked_tool_entry(lock, lock_name)
        if (
            record.get("base_directory") != entry["base_directory"]
            or record.get("relative_path") != entry["relative_path"]
            or record.get("sha256") != entry["sha256"]
            or record.get("version") != lock["versions"].get(version_key)
        ):
            raise BrowserQualificationError(f"browser provenance {key} differs from the release lock")
        recorded_path = _absolute_path(record.get("path"), f"browser provenance {key}.path")
        normalized = recorded_path.replace("\\", "/").casefold()
        suffix = "/" + str(entry["relative_path"]).replace("\\", "/").casefold()
        if not normalized.endswith(suffix):
            raise BrowserQualificationError(f"browser provenance {key} path differs from its lock")
    return tools


def _configuration_records(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for relative in CONFIGURATION_PATHS:
        size, digest = _sha256_path(root / relative, f"browser configuration {relative.as_posix()}")
        records.append({"path": relative.as_posix(), "bytes": size, "sha256": digest})
    return records


def _artifact_record(relative: Path, role: str, data: bytes) -> dict[str, Any]:
    return {
        "path": relative.as_posix(),
        "role": role,
        "bytes": len(data),
        "sha256": _sha256_bytes(data),
    }


def _browser_file_roles() -> dict[Path, str]:
    return {
        PROVENANCE_DIRECTORY / "desktop.json": "real-observation-desktop",
        PROVENANCE_DIRECTORY / "faults-desktop.json": "fault-observation-desktop",
        PROVENANCE_DIRECTORY / "faults-mobile.json": "fault-observation-mobile",
        PROVENANCE_DIRECTORY / "mobile.json": "real-observation-mobile",
        STORAGE_PATH: "browser-storage-inventory",
        SCREENSHOT_PATHS["desktop"]: "desktop-screenshot",
        SCREENSHOT_PATHS["mobile"]: "mobile-screenshot",
    }


def _corpus_binding(records: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(str(record["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(record["role"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(record["bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(record["sha256"]).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _scan_browser_payloads(payloads: list[bytes]) -> None:
    secrets = {
        value.encode("utf-8")
        for name in (
            "SPELL_BROWSER_SECRET_CANARY",
            "SPELL_DB_PASSWORD",
            "SPELL_E2E_TOKEN",
            "SPELL_JWT_HS256_SECRET",
        )
        if (value := os.environ.get(name)) and len(value) >= 8
    }
    jwt_pattern = re.compile(rb"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    for data in payloads:
        if any(secret in data for secret in secrets) or jwt_pattern.search(data):
            raise BrowserQualificationError("browser provenance contains credential-like material")


def _remove_safe_tree(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)


def publish_browser_provenance_v04(
    root: Path,
    observation_directory: Path,
    *,
    run_id: str,
    started_at_utc: str,
    finished_at_utc: str,
    executable_paths: dict[str, Path],
    replace: bool,
) -> dict[str, Any]:
    source_root = root.resolve()
    source = source_fingerprint_v04(source_root)
    expected_observation_directory = source_root / "artifacts" / "v0.4" / "browser"
    if observation_directory.is_symlink() or observation_directory.resolve() != expected_observation_directory:
        raise BrowserQualificationError("browser observation source must be artifacts/v0.4/browser")
    _exact_directory(observation_directory, CAPTURE_NAMES, "browser observation source")
    capture_snapshot = {
        name: _sha256_path(observation_directory / name, f"browser capture {name}")
        for name in sorted(CAPTURE_NAMES)
    }
    _run_id(run_id, "browser publication run_id")
    started = _timestamp(started_at_utc, "browser publication started_at_utc")
    finished = _timestamp(finished_at_utc, "browser publication finished_at_utc")
    if finished < started:
        raise BrowserQualificationError("browser publication finished before it started")

    observations = load_observations(
        source_root,
        observation_directory,
        source,
        screenshot_directory=observation_directory,
    )
    fault_observations = load_fault_observations(observation_directory, source)
    observed_run_id, browser_runtime, stack_image_ids = validate_observation_binding(
        observations,
        fault_observations,
    )
    if observed_run_id != run_id:
        raise BrowserQualificationError("browser publication run_id differs from its observations")
    release_tools = _record_release_tools(source_root, executable_paths)
    configuration = _configuration_records(source_root)
    storage_data = _canonical_bytes(storage_inventory_document(source, observations))

    destination = source_root / PROVENANCE_DIRECTORY
    storage_destination = source_root / STORAGE_PATH
    screenshot_destinations = {
        project: source_root / relative for project, relative in SCREENSHOT_PATHS.items()
    }
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or storage_destination.parent.is_symlink():
        raise BrowserQualificationError("browser provenance destination parent is unsafe")
    for path, label in ((destination, "provenance"), (storage_destination, "storage")):
        if path.is_symlink() or (path.exists() and not (path.is_dir() if path == destination else path.is_file())):
            raise BrowserQualificationError(f"browser {label} destination is unsafe")
        if path.exists() and not replace:
            raise BrowserQualificationError(f"canonical browser {label} already exists")
    for project, path in screenshot_destinations.items():
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise BrowserQualificationError(f"browser {project} screenshot destination is unsafe")
        if path.exists() and not replace:
            raise BrowserQualificationError(f"canonical browser {project} screenshot already exists")

    token = uuid.uuid4().hex
    staging = parent / f".browser-stage-{token}"
    backup = parent / f".browser-backup-{token}"
    storage_stage = storage_destination.parent / f".browser-storage-stage-{token}.json"
    storage_backup = storage_destination.parent / f".browser-storage-backup-{token}.json"
    screenshot_stages = {
        project: path.parent / f".browser-{project}-screenshot-stage-{token}.png"
        for project, path in screenshot_destinations.items()
    }
    screenshot_backups = {
        project: path.parent / f".browser-{project}-screenshot-backup-{token}.png"
        for project, path in screenshot_destinations.items()
    }
    destination_installed = False
    destination_backed_up = False
    storage_installed = False
    storage_backed_up = False
    screenshots_installed: set[str] = set()
    screenshots_backed_up: set[str] = set()
    try:
        staging.mkdir()
        payloads: list[bytes] = []
        for name in sorted(OBSERVATION_NAMES):
            data = (observation_directory / name).read_bytes()
            (staging / name).write_bytes(data)
            payloads.append(data)
        with storage_stage.open("xb") as handle:
            handle.write(storage_data)
            handle.flush()
            os.fsync(handle.fileno())
        for project, stage_path in screenshot_stages.items():
            data = (observation_directory / SCREENSHOT_PATHS[project].name).read_bytes()
            with stage_path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())

        roles = _browser_file_roles()
        records: list[dict[str, Any]] = []
        for relative, role in sorted(roles.items(), key=lambda item: item[0].as_posix()):
            if relative == STORAGE_PATH:
                data = storage_data
            elif relative.parent == PROVENANCE_DIRECTORY:
                data = (staging / relative.name).read_bytes()
            elif relative in SCREENSHOT_PATHS.values():
                data = (observation_directory / relative.name).read_bytes()
            else:
                raise BrowserQualificationError(f"unexpected browser artifact role path: {relative}")
            records.append(_artifact_record(relative, role, data))
            payloads.append(data)
        manifest = {
            "schema_version": PROVENANCE_SCHEMA,
            "scope_profile": SCOPE_PROFILE,
            "run_id": run_id,
            "source_fingerprint_sha256": source,
            "started_at_utc": started_at_utc,
            "finished_at_utc": finished_at_utc,
            "passed": True,
            "commands": CAPTURE_COMMANDS,
            "configuration": configuration,
            "release_tools": release_tools,
            "browser_runtime": browser_runtime,
            "stack_image_ids": stack_image_ids,
            "files": records,
            "corpus_binding_sha256": _corpus_binding(records),
        }
        manifest_data = _canonical_bytes(manifest)
        _scan_browser_payloads([*payloads, manifest_data])
        (staging / "manifest.json").write_bytes(manifest_data)
        _exact_directory(staging, PROVENANCE_NAMES, "staged browser provenance")
        observed_snapshot = {
            name: _sha256_path(observation_directory / name, f"browser capture {name}")
            for name in sorted(CAPTURE_NAMES)
        }
        if observed_snapshot != capture_snapshot:
            raise BrowserQualificationError("browser capture changed during provenance publication")
        if source_fingerprint_v04(source_root) != source:
            raise BrowserQualificationError("source changed during browser provenance publication")

        if destination.exists():
            os.replace(destination, backup)
            destination_backed_up = True
        if storage_destination.exists():
            os.replace(storage_destination, storage_backup)
            storage_backed_up = True
        for project, screenshot_destination in screenshot_destinations.items():
            if screenshot_destination.exists():
                os.replace(screenshot_destination, screenshot_backups[project])
                screenshots_backed_up.add(project)
        os.replace(staging, destination)
        destination_installed = True
        os.replace(storage_stage, storage_destination)
        storage_installed = True
        for project, screenshot_destination in screenshot_destinations.items():
            os.replace(screenshot_stages[project], screenshot_destination)
            screenshots_installed.add(project)
        binding = validate_browser_provenance_v04(source_root, source)
        destination_backed_up = False
        storage_backed_up = False
        screenshots_backed_up.clear()
        return binding
    except Exception:
        if destination_installed:
            _remove_safe_tree(destination)
            destination_installed = False
        if destination_backed_up and backup.is_dir() and not backup.is_symlink():
            os.replace(backup, destination)
            destination_backed_up = False
        if storage_installed and storage_destination.is_file() and not storage_destination.is_symlink():
            storage_destination.unlink()
            storage_installed = False
        if storage_backed_up and storage_backup.is_file() and not storage_backup.is_symlink():
            os.replace(storage_backup, storage_destination)
            storage_backed_up = False
        for project in tuple(screenshots_installed):
            screenshot_destination = screenshot_destinations[project]
            if screenshot_destination.is_file() and not screenshot_destination.is_symlink():
                screenshot_destination.unlink()
            screenshots_installed.remove(project)
        for project in tuple(screenshots_backed_up):
            backup_path = screenshot_backups[project]
            if backup_path.is_file() and not backup_path.is_symlink():
                os.replace(backup_path, screenshot_destinations[project])
                screenshots_backed_up.remove(project)
        raise
    finally:
        _remove_safe_tree(staging)
        _remove_safe_tree(backup)
        for path in (storage_stage, storage_backup):
            if path.is_file() and not path.is_symlink():
                path.unlink()
        for path in (*screenshot_stages.values(), *screenshot_backups.values()):
            if path.is_file() and not path.is_symlink():
                path.unlink()


def validate_browser_provenance_v04(
    root: Path,
    expected_source: str | None = None,
) -> dict[str, Any]:
    source_root = root.resolve()
    source = expected_source or source_fingerprint_v04(source_root)
    directory = source_root / PROVENANCE_DIRECTORY
    _exact_directory(directory, PROVENANCE_NAMES, "retained browser provenance")
    observations = load_observations(source_root, directory, source)
    fault_observations = load_fault_observations(directory, source)
    run_id, browser_runtime, stack_image_ids = validate_observation_binding(
        observations,
        fault_observations,
    )

    storage = storage_inventory_document(source, observations)
    storage_path = source_root / STORAGE_PATH
    if storage_path.is_symlink() or not storage_path.is_file():
        raise BrowserQualificationError("retained browser storage inventory is missing or unsafe")
    if storage_path.read_bytes() != _canonical_bytes(storage):
        raise BrowserQualificationError("retained browser storage inventory differs")

    manifest_path = directory / "manifest.json"
    manifest = _read_json(manifest_path)
    if manifest_path.read_bytes() != _canonical_bytes(manifest):
        raise BrowserQualificationError("retained browser provenance manifest is not canonical")
    if set(manifest) != {
        "schema_version",
        "scope_profile",
        "run_id",
        "source_fingerprint_sha256",
        "started_at_utc",
        "finished_at_utc",
        "passed",
        "commands",
        "configuration",
        "release_tools",
        "browser_runtime",
        "stack_image_ids",
        "files",
        "corpus_binding_sha256",
    }:
        raise BrowserQualificationError("retained browser provenance manifest shape differs")
    if (
        manifest.get("schema_version") != PROVENANCE_SCHEMA
        or manifest.get("scope_profile") != SCOPE_PROFILE
        or manifest.get("run_id") != run_id
        or manifest.get("source_fingerprint_sha256") != source
        or manifest.get("passed") is not True
    ):
        raise BrowserQualificationError("retained browser provenance manifest identity differs")
    started = _timestamp(manifest.get("started_at_utc"), "browser provenance started_at_utc")
    finished = _timestamp(manifest.get("finished_at_utc"), "browser provenance finished_at_utc")
    if finished < started:
        raise BrowserQualificationError("retained browser provenance finished before it started")
    if manifest.get("commands") != CAPTURE_COMMANDS:
        raise BrowserQualificationError("retained browser provenance commands differ")
    configuration = _configuration_records(source_root)
    if manifest.get("configuration") != configuration:
        raise BrowserQualificationError("retained browser provenance configuration differs")
    release_tools = _validate_recorded_release_tools(source_root, manifest.get("release_tools"))
    if manifest.get("browser_runtime") != browser_runtime:
        raise BrowserQualificationError("retained browser provenance tool identity differs")
    if manifest.get("stack_image_ids") != stack_image_ids:
        raise BrowserQualificationError("retained browser provenance image binding differs")

    records: list[dict[str, Any]] = []
    for relative, role in sorted(_browser_file_roles().items(), key=lambda item: item[0].as_posix()):
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            raise BrowserQualificationError(f"retained browser artifact is missing or unsafe: {relative}")
        data = path.read_bytes()
        records.append(_artifact_record(relative, role, data))
    if manifest.get("files") != records:
        raise BrowserQualificationError("retained browser provenance artifact manifest differs")
    corpus_binding = _corpus_binding(records)
    if manifest.get("corpus_binding_sha256") != corpus_binding:
        raise BrowserQualificationError("retained browser provenance corpus binding differs")
    _scan_browser_payloads(
        [path.read_bytes() for path in directory.iterdir()]
        + [(source_root / STORAGE_PATH).read_bytes()]
        + [(source_root / relative).read_bytes() for relative in SCREENSHOT_PATHS.values()]
    )
    if expected_source is None and source_fingerprint_v04(source_root) != source:
        raise BrowserQualificationError("source changed during browser provenance validation")
    return {
        "browser_provenance_schema_version": PROVENANCE_SCHEMA,
        "browser_run_id": run_id,
        "browser_manifest_sha256": _sha256_path(manifest_path, "browser manifest")[1],
        "browser_corpus_binding_sha256": corpus_binding,
        "browser_qualification_image_id": stack_image_ids["qualification"],
        "browser_docker_sha256": release_tools["docker_cli"]["sha256"],
        "browser_compose_sha256": release_tools["docker_compose"]["sha256"],
        "browser_node_sha256": browser_runtime["node_executable_sha256"],
        "browser_executable_sha256": browser_runtime["browser_executable_sha256"],
    }


def _attach_provenance(result: dict[str, Any], provenance: dict[str, Any] | None) -> dict[str, Any]:
    if provenance is None:
        return result
    expected = {
        "browser_provenance_schema_version",
        "browser_run_id",
        "browser_manifest_sha256",
        "browser_corpus_binding_sha256",
        "browser_qualification_image_id",
        "browser_docker_sha256",
        "browser_compose_sha256",
        "browser_node_sha256",
        "browser_executable_sha256",
    }
    if set(provenance) != expected:
        raise BrowserQualificationError("browser provenance extraction binding shape differs")
    if provenance["browser_provenance_schema_version"] != PROVENANCE_SCHEMA:
        raise BrowserQualificationError("browser provenance extraction schema differs")
    _run_id(provenance["browser_run_id"], "browser provenance extraction run_id")
    for key in expected - {
        "browser_provenance_schema_version",
        "browser_run_id",
        "browser_qualification_image_id",
    }:
        if SHA256_PATTERN.fullmatch(str(provenance[key])) is None:
            raise BrowserQualificationError(f"browser provenance extraction {key} is invalid")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(provenance["browser_qualification_image_id"])) is None:
        raise BrowserQualificationError("browser provenance qualification image ID is invalid")
    metrics = _mapping(result.get("metrics"), "browser qualification metrics")
    if set(metrics).intersection(provenance):
        raise BrowserQualificationError("browser provenance extraction overlaps qualification metrics")
    metrics.update(provenance)
    return result


def result_for(
    test_id: str,
    source: str,
    observations: dict[str, dict[str, Any]],
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if test_id not in TEST_IDS:
        raise BrowserQualificationError(f"unsupported browser qualification ID: {test_id}")
    if test_id == "V04-UI-002":
        return _attach_provenance({
            "test_id": test_id,
            "source_fingerprint_sha256": source,
            "assertions": [
                {"id": "six-fault-states-distinguishable-with-text-and-icons", "passed": True},
                {"id": "failed-and-unsupported-capability-states-explicit", "passed": True},
                {"id": "fault-projection-remains-read-only", "passed": True},
            ],
            "metrics": {
                "desktop_viewport_count": 1,
                "mobile_viewport_count": 1,
                "distinguishable_state_count": 6,
                "non_color_cue_count": sum(
                    int(item["non_color_cue_count"]) for item in observations.values()
                ),
                "mutation_control_count": 0,
            },
        }, provenance)
    request_count = sum(len(item["network"]["requests"]) for item in observations.values())
    websocket_count = sum(len(item["network"]["websockets"]) for item in observations.values())
    common_metrics = {
        "desktop_viewport_count": 1,
        "mobile_viewport_count": 1,
        "screenshot_count": 2,
        "runtime_identity_count": 2,
        "stack_image_identity_count": 6,
    }
    if test_id == "V04-UI-001":
        assertions = [
            "real-backend-projection-identities-visible",
            "simulator-only-read-only-labels-visible",
            "desktop-mobile-screenshots-source-bound",
        ]
        metrics = {**common_metrics, "canonical_fixture_count": 1, "mutation_control_count": 0}
    elif test_id == "V04-UI-003":
        assertions = [
            "keyboard-tab-selection-passed",
            "accessible-live-status-present",
            "axe-and-responsive-containment-passed",
        ]
        metrics = {
            **common_metrics,
            "axe_serious_finding_count": 0,
            "axe_critical_finding_count": 0,
            "keyboard_failure_count": 0,
            "overflow_failure_count": 0,
        }
    elif test_id == "V04-UI-004":
        assertions = [
            "all-browser-requests-loopback",
            "driver-downstream-websocket-observed",
            "no-direct-driver-connection",
        ]
        metrics = {
            **common_metrics,
            "request_count": request_count,
            "websocket_count": websocket_count,
            "non_loopback_request_count": 0,
            "direct_driver_connection_count": 0,
        }
    else:
        raise BrowserQualificationError(f"unsupported browser qualification ID: {test_id}")
    if any(not math.isfinite(float(value)) for value in metrics.values() if isinstance(value, (int, float))):
        raise BrowserQualificationError("browser metrics are not finite")
    return _attach_provenance({
        "test_id": test_id,
        "source_fingerprint_sha256": source,
        "assertions": [{"id": item, "passed": True} for item in assertions],
        "metrics": metrics,
    }, provenance)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--observation-dir", type=Path, default=Path("artifacts/v0.4/browser"))
    parser.add_argument("--test-id", choices=sorted(TEST_IDS))
    parser.add_argument("--publish-provenance", action="store_true")
    parser.add_argument("--validate-provenance", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--started-at-utc")
    parser.add_argument("--finished-at-utc")
    parser.add_argument("--docker-executable", type=Path)
    parser.add_argument("--compose-executable", type=Path)
    parser.add_argument("--python-executable", type=Path)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    directory = args.observation_dir
    if not directory.is_absolute():
        directory = root / directory
    modes = int(args.publish_provenance) + int(args.validate_provenance) + int(args.test_id is not None)
    if modes != 1:
        parser.error("select exactly one of --publish-provenance, --validate-provenance, or --test-id")
    try:
        if args.publish_provenance:
            required = {
                "--run-id": args.run_id,
                "--started-at-utc": args.started_at_utc,
                "--finished-at-utc": args.finished_at_utc,
                "--docker-executable": args.docker_executable,
                "--compose-executable": args.compose_executable,
                "--python-executable": args.python_executable,
            }
            missing = [name for name, value in required.items() if value is None]
            if missing:
                parser.error(f"browser provenance publication requires: {', '.join(missing)}")
            binding = publish_browser_provenance_v04(
                root,
                directory,
                run_id=args.run_id,
                started_at_utc=args.started_at_utc,
                finished_at_utc=args.finished_at_utc,
                executable_paths={
                    "docker_cli": args.docker_executable,
                    "docker_compose": args.compose_executable,
                    "python": args.python_executable,
                },
                replace=args.replace,
            )
            print(json.dumps(binding, sort_keys=True, separators=(",", ":")))
            return 0
        provenance = validate_browser_provenance_v04(root)
        if args.validate_provenance:
            print(json.dumps(provenance, sort_keys=True, separators=(",", ":")))
            return 0
        source = source_fingerprint_v04(root)
        canonical_directory = root / PROVENANCE_DIRECTORY
        if args.test_id == "V04-UI-002":
            observations = load_fault_observations(canonical_directory, source)
        else:
            observations = load_observations(root, canonical_directory, source)
        print(
            json.dumps(
                result_for(args.test_id, source, observations, provenance),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (OSError, BrowserQualificationError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
