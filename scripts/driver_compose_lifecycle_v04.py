#!/usr/bin/env python3
"""Fail-closed Docker Compose lifecycle for the packaged v0.4 simulator host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.driver_package_lifecycle import load_profile
from scripts.source_fingerprint_v04 import source_fingerprint_v04
from scripts.supply_provenance_v04 import locked_host_tools


STATE_NAME = "compose-install-state.json"
OPERATIONS_NAME = "operation-evidence.json"
AUDIT_NAME = "canonical-audit.jsonl"
OVERRIDE_NAME = "compose-package.override.json"
STATE_SCHEMA = "spell.driver-compose-package-state/1"
EVIDENCE_SCHEMA = "spell.driver-operation-evidence/1"
SCOPE_PROFILE = "candidate-a-local-synthetic-simulator"
PLATFORM_ID = "oci-compose-linux-amd64"
MAX_JSON_BYTES = 1024 * 1024
PACKAGE_SERVICES = ("pki-init", "spell-driver")
VOLUME_KEYS = (
    "spell-driver-client-credentials",
    "spell-driver-server-credentials",
    "spell-driver-journal",
)
STATE_KEYS = {
    "schema_version",
    "profile_sha256",
    "scope_profile",
    "platform_profile",
    "project_name",
    "package_version",
    "installed",
    "enabled",
    "driver_image_id",
    "pki_image_id",
    "prior_profile",
}
PRIOR_PROFILE_KEYS = {
    "package_version",
    "installed",
    "enabled",
    "driver_image_id",
    "pki_image_id",
    "previous_prior_profile",
}
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROJECT_PATTERN = re.compile(r"spellv04(?:q)?-[0-9a-f]{24,32}\Z")
VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}\Z")
TERMINAL_STAGE = "SETTLED"
TERMINAL_CERTAINTIES = frozenset({"NO_EFFECT", "EFFECT_CONFIRMED"})
VOLUME_DIGEST_SCRIPT = (
    "import hashlib,json,pathlib;"
    "r=pathlib.Path('/input');h=hashlib.sha256();"
    "items=sorted(r.rglob('*'),key=lambda p:p.relative_to(r).as_posix());"
    "[( (_ for _ in ()).throw(ValueError('symlink')) if p.is_symlink() else "
    "(h.update(p.relative_to(r).as_posix().encode()),h.update(b'\\0'),"
    "h.update(p.read_bytes()),h.update(b'\\0')) if p.is_file() else None) for p in items];"
    "n=sum(1 for p in items if p.is_file());"
    "print(json.dumps({'sha256':h.hexdigest(),'file_count':n},sort_keys=True))"
)


class LifecycleRefusal(RuntimeError):
    """The requested Compose lifecycle transition cannot safely proceed."""


class DockerCommandError(RuntimeError):
    """A Docker CLI command failed without exposing command environment values."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class TransitionResult:
    action: str
    applied: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "applied": self.applied, "reason": self.reason}


Runner = Callable[[Sequence[str], Path], CommandResult]


def _subprocess_runner(command: Sequence[str], cwd: Path) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("xb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        if temporary.exists() and temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file: {path}")
    data = path.read_bytes()
    if not data or len(data) > MAX_JSON_BYTES:
        raise ValueError(f"{label} has an invalid size")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    value = _loads_json(text, label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _loads_json(data: str, label: str) -> Any:
    try:
        return json.loads(
            data,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid strict JSON") from exc


def _exact_nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _validate_prior_profile(value: Any, *, depth: int = 0) -> None:
    if value is None:
        return
    if depth >= 16 or not isinstance(value, dict) or set(value) != PRIOR_PROFILE_KEYS:
        raise ValueError("Compose lifecycle prior profile is malformed")
    version = value.get("package_version")
    installed = value.get("installed")
    enabled = value.get("enabled")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ValueError("Compose lifecycle prior profile version is invalid")
    if type(installed) is not bool or enabled is not False:
        raise ValueError("Compose lifecycle prior profile flags are invalid")
    driver_image = value.get("driver_image_id")
    pki_image = value.get("pki_image_id")
    if installed:
        if (
            _normalize_image_id(driver_image, "prior driver image") != driver_image
            or _normalize_image_id(pki_image, "prior PKI image") != pki_image
        ):
            raise ValueError("Compose lifecycle prior profile images differ")
    elif driver_image is not None or pki_image is not None:
        raise ValueError("uninstalled prior profile must not select images")
    _validate_prior_profile(value.get("previous_prior_profile"), depth=depth + 1)


def _safe_state_directory(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("lifecycle state directory cannot be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ValueError("lifecycle state path must be a directory")
    return resolved


def _normalize_image_id(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an exact sha256 image ID")
    normalized = value.strip().casefold()
    if not IMAGE_ID_PATTERN.fullmatch(normalized):
        raise ValueError(f"{label} must be an exact sha256 image ID")
    return normalized


def _normalize_version(value: str, label: str) -> str:
    if not isinstance(value, str) or not VERSION_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not a bounded package version")
    return value


def _operation_blocker(path: Path, project_name: str) -> str | None:
    if not path.exists():
        return None
    evidence = _load_object(path, "Compose lifecycle operation evidence")
    if set(evidence) != {
        "schema_version",
        "scope_profile",
        "project_name",
        "operations",
    }:
        return "operation evidence fields are absent or unrecognized"
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        return "operation evidence schema is absent or unrecognized"
    if evidence.get("scope_profile") != SCOPE_PROFILE:
        return "operation evidence does not identify the local synthetic scope"
    if evidence.get("project_name") != project_name:
        return "operation evidence belongs to another Compose project"
    operations = evidence.get("operations")
    if not isinstance(operations, list):
        return "operation evidence operations are absent or malformed"
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) != {
            "operation_id",
            "stage",
            "certainty",
            "tombstone",
        }:
            return "operation evidence contains a malformed entry"
        operation_id = operation.get("operation_id")
        stage = operation.get("stage")
        certainty = operation.get("certainty")
        if (
            not isinstance(operation_id, str)
            or not operation_id
            or operation.get("tombstone") is not True
            or stage != TERMINAL_STAGE
            or certainty not in TERMINAL_CERTAINTIES
        ):
            identity = operation_id if isinstance(operation_id, str) and operation_id else "unknown"
            return (
                f"nonterminal or uncertain operation {identity}: "
                f"stage={stage} certainty={certainty}"
            )
    return None


class DockerCli:
    def __init__(
        self,
        root: Path,
        runner: Runner = _subprocess_runner,
        *,
        docker_executable: str | None = None,
        compose_executable: str | None = None,
        require_locked_paths: bool = False,
    ) -> None:
        self.root = root.resolve()
        self.runner = runner
        self.docker_executable = docker_executable or os.environ.get(
            "SPELL_RELEASE_DOCKER_EXE", "docker"
        )
        self.compose_executable = compose_executable or os.environ.get(
            "SPELL_RELEASE_COMPOSE_EXE"
        )
        if require_locked_paths:
            for value, label in (
                (self.docker_executable, "Docker CLI"),
                (self.compose_executable, "Docker Compose"),
            ):
                if (
                    not isinstance(value, str)
                    or not Path(value).is_absolute()
                    or not Path(value).is_file()
                ):
                    raise ValueError(f"locked {label} executable path is unavailable")
        self.command_count = 0
        self.mutating_command_count = 0

    def run(
        self,
        *arguments: str,
        check: bool = True,
        mutating: bool = False,
    ) -> CommandResult:
        self.command_count += 1
        if mutating:
            self.mutating_command_count += 1
        if arguments and arguments[0] == "compose" and self.compose_executable:
            command = (self.compose_executable, *arguments[1:])
        else:
            command = (self.docker_executable, *arguments)
        result = self.runner(command, self.root)
        if check and result.returncode != 0:
            detail = result.stderr.strip().splitlines()
            suffix = f": {detail[-1]}" if detail else ""
            raise DockerCommandError(f"Docker command failed ({arguments[0]}){suffix}")
        return result


class ComposeDriverPackage:
    def __init__(
        self,
        root: Path,
        state_directory: Path,
        *,
        docker: DockerCli | None = None,
    ) -> None:
        self.root = root.resolve()
        self.state_directory = _safe_state_directory(state_directory)
        self.profile_path = self.root / "scripts/driver-package-v04.json"
        self.profile = load_profile(self.profile_path)
        self.compose_file = self.root / self.profile["compose_file"]
        if (
            self.compose_file.is_symlink()
            or not self.compose_file.is_file()
            or self.compose_file.resolve() != (self.root / "compose.yaml").resolve()
        ):
            raise ValueError("driver package Compose file is absent or differs")
        if tuple(self.profile["compose_services"]) != PACKAGE_SERVICES:
            raise ValueError("driver package Compose service set differs")
        if tuple(self.profile["compose_volumes"]) != VOLUME_KEYS:
            raise ValueError("driver package Compose volume set differs")
        self.profile_sha256 = hashlib.sha256(self.profile_path.read_bytes()).hexdigest()
        self.docker = docker or DockerCli(self.root)
        self.image_confirmation_count = 0

    @property
    def state_path(self) -> Path:
        return self.state_directory / STATE_NAME

    @property
    def operation_path(self) -> Path:
        return self.state_directory / OPERATIONS_NAME

    @property
    def audit_path(self) -> Path:
        return self.state_directory / AUDIT_NAME

    @property
    def override_path(self) -> Path:
        return self.state_directory / OVERRIDE_NAME

    def _append_audit(self, event: dict[str, Any]) -> None:
        if self.audit_path.exists() and (
            self.audit_path.is_symlink() or not self.audit_path.is_file()
        ):
            raise ValueError("canonical lifecycle audit path is unsafe")
        previous = self.audit_path.read_bytes() if self.audit_path.exists() else b""
        _atomic_write(self.audit_path, previous + _canonical_bytes(event))

    def _load_state(self) -> dict[str, Any]:
        state = _load_object(self.state_path, "Compose lifecycle state")
        if set(state) != STATE_KEYS or state.get("schema_version") != STATE_SCHEMA:
            raise ValueError("Compose lifecycle state schema/fields differ")
        if state.get("profile_sha256") != self.profile_sha256:
            raise LifecycleRefusal("driver package profile changed after installation")
        project_name = state.get("project_name")
        if not isinstance(project_name, str) or not PROJECT_PATTERN.fullmatch(project_name):
            raise ValueError("Compose lifecycle project identity is invalid")
        if state.get("scope_profile") != SCOPE_PROFILE:
            raise ValueError("Compose lifecycle scope profile differs")
        if state.get("platform_profile") != PLATFORM_ID:
            raise ValueError("Compose lifecycle platform profile differs")
        version = state.get("package_version")
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError("Compose lifecycle package version is invalid")
        installed = state.get("installed")
        enabled = state.get("enabled")
        if type(installed) is not bool or type(enabled) is not bool:
            raise ValueError("Compose lifecycle state flags must be booleans")
        if enabled and not installed:
            raise ValueError("an uninstalled Compose package cannot be enabled")
        for key, label in (
            ("driver_image_id", "state driver image"),
            ("pki_image_id", "state PKI image"),
        ):
            value = state.get(key)
            if _normalize_image_id(value, label) != value:
                raise ValueError(f"Compose lifecycle {label} differs")
        _validate_prior_profile(state.get("prior_profile"))
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        _atomic_write(self.state_path, _canonical_bytes(state))

    def _write_override(self, state: dict[str, Any]) -> None:
        driver_image = _normalize_image_id(state["driver_image_id"], "driver image")
        pki_image = _normalize_image_id(state["pki_image_id"], "PKI image")
        value = {
            "services": {
                "pki-init": {"image": pki_image, "pull_policy": "never"},
                "spell-driver": {"image": driver_image, "pull_policy": "never"},
            }
        }
        _atomic_write(self.override_path, _canonical_bytes(value), 0o600)

    def _compose_arguments(
        self,
        state: dict[str, Any],
        *arguments: str,
        profile: bool = True,
    ) -> tuple[str, ...]:
        values = (
            "compose",
            "--project-name",
            state["project_name"],
            "--file",
            str(self.compose_file),
            "--file",
            str(self.override_path),
        )
        if profile:
            values += ("--profile", self.profile["compose_profile"])
        return (*values, *arguments)

    def _compose(
        self,
        state: dict[str, Any],
        *arguments: str,
        profile: bool = True,
        mutating: bool = False,
        check: bool = True,
    ) -> CommandResult:
        return self.docker.run(
            *self._compose_arguments(state, *arguments, profile=profile),
            check=check,
            mutating=mutating,
        )

    def _inspect_image(
        self,
        image_id: str,
        *,
        component: str,
        version: str,
    ) -> dict[str, Any]:
        normalized = _normalize_image_id(image_id, f"{component} image")
        result = self.docker.run("image", "inspect", normalized)
        values = _loads_json(result.stdout, "Docker image inspection")
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise ValueError("Docker image inspection cardinality differs")
        image = values[0]
        if str(image.get("Id", "")).casefold() != normalized:
            raise ValueError(f"{component} image identity differs")
        if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
            raise ValueError(f"{component} image platform differs")
        labels = image.get("Config", {}).get("Labels")
        if not isinstance(labels, dict):
            raise ValueError(f"{component} image labels are absent")
        expected = {
            "org.openbexi.spell.scope": SCOPE_PROFILE,
            "org.openbexi.spell.component": component,
            "org.openbexi.spell.package.version": version,
        }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError(f"{component} image does not identify the exact local package")
        self.image_confirmation_count += 1
        return image

    def _project_resource_names(self, project_name: str) -> tuple[list[str], list[str], list[str]]:
        containers = self.docker.run(
            "ps",
            "--all",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.ID}}",
        ).stdout.split()
        volumes = self.docker.run(
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.Name}}",
        ).stdout.split()
        networks = self.docker.run(
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.Name}}",
        ).stdout.split()
        return sorted(containers), sorted(volumes), sorted(networks)

    def _assert_project_unused(self, project_name: str) -> None:
        if not PROJECT_PATTERN.fullmatch(project_name):
            raise ValueError("Compose project must be a generated v0.4 project identity")
        resources = self._project_resource_names(project_name)
        if any(resources):
            raise LifecycleRefusal("Compose project identity is not unique")
        for key in VOLUME_KEYS:
            name = f"{project_name}_{key}"
            if self.docker.run("volume", "inspect", name, check=False).returncode == 0:
                raise LifecycleRefusal("Compose project volume name is not unique")

    def _container_inventory(self, state: dict[str, Any]) -> dict[str, dict[str, Any]]:
        identifiers, _, _ = self._project_resource_names(state["project_name"])
        if not identifiers:
            return {}
        result = self.docker.run("container", "inspect", *identifiers)
        values = _loads_json(result.stdout, "Docker container inspection")
        if not isinstance(values, list) or len(values) != len(identifiers):
            raise ValueError("Docker container inspection cardinality differs")
        inventory: dict[str, dict[str, Any]] = {}
        for container in values:
            if not isinstance(container, dict):
                raise ValueError("Docker container inspection entry is malformed")
            labels = container.get("Config", {}).get("Labels")
            service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
            project = labels.get("com.docker.compose.project") if isinstance(labels, dict) else None
            if project != state["project_name"] or service not in PACKAGE_SERVICES:
                raise LifecycleRefusal("Compose project contains an unexpected container")
            if service in inventory:
                raise LifecycleRefusal("Compose project contains duplicate package containers")
            inventory[service] = container
        return inventory

    @staticmethod
    def _container_running(container: dict[str, Any]) -> bool:
        running = container.get("State", {}).get("Running")
        if type(running) is not bool:
            raise ValueError("Docker container running state is not boolean")
        return running

    def _assert_disabled(self, state: dict[str, Any]) -> None:
        inventory = self._container_inventory(state)
        running = sorted(
            service for service, item in inventory.items() if self._container_running(item)
        )
        if running:
            raise LifecycleRefusal(f"driver package is not disabled: {','.join(running)}")

    def _assert_exact_containers(
        self,
        state: dict[str, Any],
        *,
        driver_running: bool,
    ) -> dict[str, dict[str, Any]]:
        inventory = self._container_inventory(state)
        if set(inventory) != set(PACKAGE_SERVICES):
            raise LifecycleRefusal("Compose package container set differs")
        pki = inventory["pki-init"]
        driver = inventory["spell-driver"]
        if str(pki.get("Image", "")).casefold() != state["pki_image_id"]:
            raise LifecycleRefusal("running PKI image differs from installed image ID")
        if str(driver.get("Image", "")).casefold() != state["driver_image_id"]:
            raise LifecycleRefusal("running driver image differs from installed image ID")
        pki_state = pki.get("State", {})
        if (
            pki_state.get("Running") is not False
            or not _exact_nonnegative_int(pki_state.get("ExitCode"))
            or pki_state.get("ExitCode") != 0
        ):
            raise LifecycleRefusal("PKI initializer did not complete exactly once")
        if self._container_running(driver) is not driver_running:
            raise LifecycleRefusal("driver container enabled state differs")
        if driver_running and driver.get("State", {}).get("Health", {}).get("Status") != "healthy":
            raise LifecycleRefusal("driver container is not healthy")
        self.image_confirmation_count += 2
        return inventory

    def _volume_name(self, state: dict[str, Any], key: str) -> str:
        if key not in VOLUME_KEYS:
            raise ValueError("unknown package volume key")
        return f"{state['project_name']}_{key}"

    def _volume_digest(self, state: dict[str, Any], key: str) -> dict[str, Any] | None:
        name = self._volume_name(state, key)
        inspected = self.docker.run("volume", "inspect", name, check=False)
        if inspected.returncode != 0:
            return None
        values = _loads_json(inspected.stdout, "Docker volume inspection")
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError("Docker volume inspection cardinality differs")
        labels = values[0].get("Labels")
        if not isinstance(labels, dict) or (
            labels.get("com.docker.compose.project") != state["project_name"]
            or labels.get("com.docker.compose.volume") != key
        ):
            raise LifecycleRefusal("package volume ownership labels differ")
        result = self.docker.run(
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--entrypoint",
            "python",
            "--mount",
            f"type=volume,src={name},dst=/input,readonly",
            state["pki_image_id"],
            "-c",
            VOLUME_DIGEST_SCRIPT,
        )
        digest = _loads_json(result.stdout.strip(), "package volume digest")
        if (
            not isinstance(digest, dict)
            or set(digest) != {"file_count", "sha256"}
            or not isinstance(digest.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest["sha256"])
            or not _exact_nonnegative_int(digest.get("file_count"))
        ):
            raise ValueError("package volume digest result differs")
        return digest

    def _volume_snapshot(self, state: dict[str, Any]) -> dict[str, Any]:
        return {key: self._volume_digest(state, key) for key in VOLUME_KEYS}

    def _mutation_fingerprint(self, state: dict[str, Any]) -> dict[str, Any]:
        inventory = self._container_inventory(state)
        containers = {
            service: {
                "id": item.get("Id"),
                "image": item.get("Image"),
                "running": item.get("State", {}).get("Running"),
                "exit_code": item.get("State", {}).get("ExitCode"),
            }
            for service, item in sorted(inventory.items())
        }
        return {
            "state_sha256": hashlib.sha256(self.state_path.read_bytes()).hexdigest(),
            "containers": containers,
            "volumes": self._volume_snapshot(state),
        }

    def _preflight(self, state: dict[str, Any], action: str) -> TransitionResult | None:
        blocker = _operation_blocker(self.operation_path, state["project_name"])
        if blocker is None:
            return None
        event = {"action": action, "applied": False, "reason": blocker}
        self._append_audit(event)
        return TransitionResult(action, False, blocker)

    def install(
        self,
        *,
        driver_image_id: str,
        pki_image_id: str,
        package_version: str = "0.4.0",
        project_name: str | None = None,
    ) -> TransitionResult:
        if self.state_path.exists():
            raise LifecycleRefusal("driver Compose package is already installed")
        version = _normalize_version(package_version, "package version")
        driver_image = _normalize_image_id(driver_image_id, "driver image")
        pki_image = _normalize_image_id(pki_image_id, "PKI image")
        if project_name is None:
            project_name = f"spellv04-{uuid.uuid4().hex}"
        if not PROJECT_PATTERN.fullmatch(project_name):
            raise ValueError("Compose project identity is not a generated v0.4 identity")
        platform = self.docker.run(
            "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"
        ).stdout.strip()
        if platform != "linux/amd64":
            raise ValueError(f"declared Compose platform is unavailable: {platform}")
        self._inspect_image(driver_image, component="spell-driver", version=version)
        self._inspect_image(pki_image, component="pki-init", version="0.4.0")
        self._assert_project_unused(project_name)
        state = {
            "schema_version": STATE_SCHEMA,
            "profile_sha256": self.profile_sha256,
            "scope_profile": SCOPE_PROFILE,
            "platform_profile": PLATFORM_ID,
            "project_name": project_name,
            "package_version": version,
            "installed": True,
            "enabled": False,
            "driver_image_id": driver_image,
            "pki_image_id": pki_image,
            "prior_profile": {
                "package_version": "0.3.0",
                "installed": False,
                "enabled": False,
                "driver_image_id": None,
                "pki_image_id": None,
                "previous_prior_profile": None,
            },
        }
        self._write_override(state)
        disabled = self._compose(state, "config", "--services", profile=False).stdout.split()
        enabled = self._compose(state, "config", "--services", profile=True).stdout.split()
        if set(enabled).difference(disabled) != set(PACKAGE_SERVICES):
            raise LifecycleRefusal("Compose driver profile service set differs")
        self._write_state(state)
        self._assert_disabled(state)
        self._append_audit(
            {
                "action": "install",
                "applied": True,
                "package_version": version,
                "platform_profile": PLATFORM_ID,
                "project_name": project_name,
                "reason": "installed-disabled",
            }
        )
        return TransitionResult("install", True, "installed-disabled")

    def _wait_for_driver(self, state: dict[str, Any], timeout_seconds: float = 60.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        last = "absent"
        while time.monotonic() < deadline:
            inventory = self._container_inventory(state)
            driver = inventory.get("spell-driver")
            if driver is not None:
                driver_state = driver.get("State", {})
                last = str(driver_state.get("Health", {}).get("Status", "missing-health"))
                if driver_state.get("Running") is True and last == "healthy":
                    return
                if driver_state.get("Running") is not True and last != "starting":
                    break
            time.sleep(0.5)
        raise LifecycleRefusal(f"driver did not become healthy: {last}")

    def enable(self) -> TransitionResult:
        state = self._load_state()
        blocked = self._preflight(state, "enable")
        if blocked is not None:
            return blocked
        if state.get("installed") is not True:
            raise LifecycleRefusal("cannot enable an uninstalled Compose package")
        self._write_override(state)
        inventory = self._container_inventory(state)
        if set(inventory).difference(PACKAGE_SERVICES):
            raise LifecycleRefusal("Compose project contains unexpected services")
        try:
            if not inventory:
                self._compose(
                    state,
                    "up",
                    "--detach",
                    "--no-build",
                    "pki-init",
                    "spell-driver",
                    mutating=True,
                )
            elif set(inventory) == set(PACKAGE_SERVICES):
                self._assert_exact_containers(state, driver_running=False)
                driver_id = inventory["spell-driver"]["Id"]
                self.docker.run("start", driver_id, mutating=True)
            elif set(inventory) == {"pki-init"}:
                pki = inventory["pki-init"]
                if (
                    str(pki.get("Image", "")).casefold() != state["pki_image_id"]
                    or pki.get("State", {}).get("Running") is not False
                    or not _exact_nonnegative_int(pki.get("State", {}).get("ExitCode"))
                    or pki.get("State", {}).get("ExitCode") != 0
                ):
                    raise LifecycleRefusal("retained PKI initializer is not exact and settled")
                self._compose(
                    state,
                    "create",
                    "--no-build",
                    "--no-deps",
                    "spell-driver",
                    mutating=True,
                )
                inventory = self._container_inventory(state)
                self.docker.run("start", inventory["spell-driver"]["Id"], mutating=True)
            else:
                raise LifecycleRefusal("Compose package is partially installed")
            self._wait_for_driver(state)
            self._assert_exact_containers(state, driver_running=True)
        except Exception:
            current = self._container_inventory(state)
            driver = current.get("spell-driver")
            if driver is not None and self._container_running(driver):
                self.docker.run("stop", driver["Id"], check=False, mutating=True)
            raise
        state["enabled"] = True
        self._write_state(state)
        self._append_audit({"action": "enable", "applied": True, "reason": "exact-driver-enabled"})
        return TransitionResult("enable", True, "exact-driver-enabled")

    def _stop_driver(self, state: dict[str, Any]) -> None:
        inventory = self._container_inventory(state)
        driver = inventory.get("spell-driver")
        if driver is not None and self._container_running(driver):
            self.docker.run("stop", driver["Id"], mutating=True)
        state["enabled"] = False
        self._write_state(state)
        self._assert_disabled(state)

    def disable(self) -> TransitionResult:
        state = self._load_state()
        blocked = self._preflight(state, "disable")
        if blocked is not None:
            return blocked
        if state.get("installed") is not True:
            raise LifecycleRefusal("cannot disable an uninstalled Compose package")
        before = self._volume_snapshot(state)
        self._stop_driver(state)
        after = self._volume_snapshot(state)
        if after != before:
            raise RuntimeError("disable changed retained package volumes")
        self._append_audit({"action": "disable", "applied": True, "reason": "driver-disabled"})
        return TransitionResult("disable", True, "driver-disabled")

    def _replace_disabled_driver(
        self,
        state: dict[str, Any],
        target: dict[str, Any],
    ) -> None:
        before = self._volume_snapshot(state)
        self._stop_driver(state)
        inventory = self._container_inventory(state)
        driver = inventory.get("spell-driver")
        if driver is not None:
            self.docker.run("rm", "--force", driver["Id"], mutating=True)
        self._write_override(target)
        if target.get("installed") is True and any(value is not None for value in before.values()):
            self._compose(
                target,
                "up",
                "--no-build",
                "--no-deps",
                "--no-start",
                "spell-driver",
                mutating=True,
            )
            inventory = self._container_inventory(target)
            driver = inventory.get("spell-driver")
            if driver is None or str(driver.get("Image", "")).casefold() != target["driver_image_id"]:
                raise LifecycleRefusal("replacement driver container image differs")
            if self._container_running(driver):
                raise LifecycleRefusal("replacement driver container was enabled")
            self.image_confirmation_count += 1
        after = self._volume_snapshot(target)
        if after != before:
            raise RuntimeError("image transition changed retained package volumes")

    def upgrade(self, *, driver_image_id: str, target_version: str) -> TransitionResult:
        state = self._load_state()
        blocked = self._preflight(state, "upgrade")
        if blocked is not None:
            return blocked
        if state.get("installed") is not True:
            raise LifecycleRefusal("cannot upgrade an uninstalled Compose package")
        version = _normalize_version(target_version, "upgrade target version")
        image_id = _normalize_image_id(driver_image_id, "upgrade driver image")
        if version == state["package_version"] or image_id == state["driver_image_id"]:
            raise ValueError("upgrade requires a distinct version and exact image ID")
        self._inspect_image(image_id, component="spell-driver", version=version)
        target = dict(state)
        target.update(
            {
                "package_version": version,
                "installed": True,
                "enabled": False,
                "driver_image_id": image_id,
                "prior_profile": {
                    "package_version": state["package_version"],
                    "installed": state["installed"],
                    "enabled": False,
                    "driver_image_id": state["driver_image_id"],
                    "pki_image_id": state["pki_image_id"],
                    "previous_prior_profile": state.get("prior_profile"),
                },
            }
        )
        self._replace_disabled_driver(state, target)
        self._write_state(target)
        self._append_audit(
            {
                "action": "upgrade",
                "applied": True,
                "reason": "exact-image-selected-disabled",
                "target_version": version,
                "driver_image_id": image_id,
            }
        )
        return TransitionResult("upgrade", True, "exact-image-selected-disabled")

    def rollback(self) -> TransitionResult:
        state = self._load_state()
        blocked = self._preflight(state, "rollback")
        if blocked is not None:
            return blocked
        prior = state.get("prior_profile")
        if not isinstance(prior, dict):
            raise LifecycleRefusal("no prior disabled profile is recorded")
        target = dict(state)
        target.update(
            {
                "package_version": prior.get("package_version"),
                "installed": prior.get("installed") is True,
                "enabled": False,
                "driver_image_id": prior.get("driver_image_id"),
                "pki_image_id": prior.get("pki_image_id") or state["pki_image_id"],
                "prior_profile": prior.get("previous_prior_profile"),
            }
        )
        if target["installed"]:
            _normalize_version(str(target["package_version"]), "rollback package version")
            self._inspect_image(
                target["driver_image_id"],
                component="spell-driver",
                version=target["package_version"],
            )
        else:
            target["driver_image_id"] = state["driver_image_id"]
        self._replace_disabled_driver(state, target)
        self._write_state(target)
        self._append_audit(
            {
                "action": "rollback",
                "applied": True,
                "reason": "prior-disabled-profile-restored",
                "target_version": target["package_version"],
                "installed": target["installed"],
            }
        )
        return TransitionResult("rollback", True, "prior-disabled-profile-restored")

    def uninstall(self) -> TransitionResult:
        state = self._load_state()
        blocked = self._preflight(state, "uninstall")
        if blocked is not None:
            return blocked
        journal_before = self._volume_digest(state, "spell-driver-journal")
        inventory = self._container_inventory(state)
        for service in PACKAGE_SERVICES:
            container = inventory.get(service)
            if container is not None:
                self.docker.run("rm", "--force", container["Id"], mutating=True)
        if self._container_inventory(state):
            raise LifecycleRefusal("package containers remain after uninstall")
        for key in VOLUME_KEYS[:2]:
            name = self._volume_name(state, key)
            inspected = self.docker.run("volume", "inspect", name, check=False)
            if inspected.returncode == 0:
                self.docker.run("volume", "rm", name, mutating=True)
            if self.docker.run("volume", "inspect", name, check=False).returncode == 0:
                raise LifecycleRefusal("credential volume remains after safe uninstall")
        if self._volume_digest(state, "spell-driver-journal") != journal_before:
            raise RuntimeError("uninstall changed retained driver journal evidence")
        state["installed"] = False
        state["enabled"] = False
        self._write_state(state)
        self._append_audit(
            {
                "action": "uninstall",
                "applied": True,
                "reason": "credentials-removed-records-retained",
                "journal_retained": journal_before is not None,
            }
        )
        return TransitionResult("uninstall", True, "credentials-removed-records-retained")

    def force_destroy_qualification_project(self) -> None:
        state = self._load_state()
        project = state["project_name"]
        if not project.startswith("spellv04q-"):
            raise LifecycleRefusal("destructive cleanup is limited to qualification projects")
        containers, volumes, networks = self._project_resource_names(project)
        if containers:
            self.docker.run("rm", "--force", *containers, check=False, mutating=True)
        for volume in volumes:
            if volume.startswith(f"{project}_"):
                self.docker.run("volume", "rm", "--force", volume, check=False, mutating=True)
        for network in networks:
            if network.startswith(f"{project}_"):
                self.docker.run("network", "rm", network, check=False, mutating=True)
        remaining = self._project_resource_names(project)
        named_volumes = [
            key
            for key in VOLUME_KEYS
            if self.docker.run(
                "volume",
                "inspect",
                f"{project}_{key}",
                check=False,
            ).returncode
            == 0
        ]
        if any(remaining) or named_volumes:
            raise LifecycleRefusal("qualification Compose project cleanup is incomplete")


CASES = (
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
ACTIONS = ("enable", "disable", "upgrade", "rollback", "uninstall")


def _write_evidence(package: ComposeDriverPackage, stage: str, certainty: str) -> None:
    value = {
        "schema_version": EVIDENCE_SCHEMA,
        "scope_profile": SCOPE_PROFILE,
        "project_name": package._load_state()["project_name"],
        "operations": [
            {
                "operation_id": f"operation-{stage.casefold()}-{certainty.casefold()}",
                "stage": stage,
                "certainty": certainty,
                "tombstone": True,
            }
        ],
    }
    _atomic_write(package.operation_path, _canonical_bytes(value))


def _invoke_action(
    package: ComposeDriverPackage,
    action: str,
    *,
    driver_image_b: str,
) -> TransitionResult:
    if action == "enable":
        return package.enable()
    if action == "disable":
        return package.disable()
    if action == "upgrade":
        return package.upgrade(driver_image_id=driver_image_b, target_version="0.4.1-test")
    if action == "rollback":
        return package.rollback()
    return package.uninstall()


def _transition_state_sha256(
    package: ComposeDriverPackage, state: dict[str, Any]
) -> str:
    snapshot = package._mutation_fingerprint(state)
    return hashlib.sha256(_canonical_bytes(snapshot)).hexdigest()


def _lifecycle_case(
    *,
    action: str,
    index: int,
    stage: str,
    certainty: str,
    expected: bool,
    result: TransitionResult,
    project: str,
    before_state_sha256: str,
    after_state_sha256: str,
    before_evidence_sha256: str,
    after_evidence_sha256: str,
    driver_image_before: str,
    driver_image_after: str,
    pki_image_id: str,
) -> dict[str, Any]:
    return {
        "case_id": f"{action}-{index:02d}-{stage.casefold()}-{certainty.casefold()}",
        "action": action,
        "stage": stage,
        "certainty": certainty,
        "expected_applied": expected,
        "observed_applied": result.applied,
        "reason": result.reason,
        "project_name": project,
        "before_state_sha256": before_state_sha256,
        "after_state_sha256": after_state_sha256,
        "before_evidence_sha256": before_evidence_sha256,
        "after_evidence_sha256": after_evidence_sha256,
        "driver_image_before": driver_image_before,
        "driver_image_after": driver_image_after,
        "pki_image_id": pki_image_id,
        "cleanup_verified": False,
    }


def qualify(
    root: Path,
    *,
    driver_image_a: str,
    driver_image_b: str,
    pki_image: str,
    run_id: str | None = None,
    provenance_output: Path | None = None,
) -> dict[str, Any]:
    source_root = root.resolve()
    source_before = source_fingerprint_v04(source_root)
    driver_image_a = _normalize_image_id(driver_image_a, "qualification driver A image")
    driver_image_b = _normalize_image_id(driver_image_b, "qualification driver B image")
    pki_image = _normalize_image_id(pki_image, "qualification PKI image")
    if len({driver_image_a, driver_image_b, pki_image}) != 3:
        raise ValueError("qualification execution images must be distinct")
    if (run_id is None) != (provenance_output is None):
        raise ValueError("SC006 run ID and provenance output must be supplied together")
    if run_id is not None and re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise ValueError("SC006 provenance run ID is invalid")
    output: Path | None = None
    if provenance_output is not None:
        output = provenance_output.resolve()
        if (
            output.name != "lifecycle-cases.json"
            or not output.parent.is_dir()
            or output.parent.is_symlink()
            or output.exists()
            or output.is_symlink()
        ):
            raise ValueError("SC006 provenance output path is not fresh and safe")
    host_tools = locked_host_tools(source_root, "V04-SC-006")
    docker = DockerCli(source_root, require_locked_paths=True)
    action_counts = {action: 0 for action in ACTIONS}
    installed_projects = 0
    failures: list[str] = []
    exact_confirmations = 0
    case_records: list[dict[str, Any]] = []

    def new_package(directory: str) -> ComposeDriverPackage:
        nonlocal installed_projects
        package = ComposeDriverPackage(source_root, Path(directory), docker=docker)
        project = f"spellv04q-{uuid.uuid4().hex[:24]}"
        package.install(
            driver_image_id=driver_image_a,
            pki_image_id=pki_image,
            package_version="0.4.0",
            project_name=project,
        )
        installed_projects += 1
        return package

    unsafe_cases = [case for case in CASES if not case[2]]
    terminal_cases = [case for case in CASES if case[2]]
    for action in ACTIONS:
        with tempfile.TemporaryDirectory(prefix=f"spell-v04-compose-unsafe-{action}-") as directory:
            package = new_package(directory)
            batch_start = len(case_records)
            try:
                if action != "enable":
                    _write_evidence(package, "SETTLED", "NO_EFFECT")
                    package.enable()
                for index, (stage, certainty, expected) in enumerate(unsafe_cases, start=1):
                    _write_evidence(package, stage, certainty)
                    before_state = package._load_state()
                    before = _transition_state_sha256(package, before_state)
                    evidence_before = package.operation_path.read_bytes()
                    result = _invoke_action(package, action, driver_image_b=driver_image_b)
                    action_counts[action] += 1
                    after_state = package._load_state()
                    after = _transition_state_sha256(package, after_state)
                    evidence_after = package.operation_path.read_bytes()
                    case_records.append(
                        _lifecycle_case(
                            action=action,
                            index=index,
                            stage=stage,
                            certainty=certainty,
                            expected=expected,
                            result=result,
                            project=before_state["project_name"],
                            before_state_sha256=before,
                            after_state_sha256=after,
                            before_evidence_sha256=hashlib.sha256(evidence_before).hexdigest(),
                            after_evidence_sha256=hashlib.sha256(evidence_after).hexdigest(),
                            driver_image_before=before_state["driver_image_id"],
                            driver_image_after=after_state["driver_image_id"],
                            pki_image_id=before_state["pki_image_id"],
                        )
                    )
                    if result.applied is not expected or after != before:
                        failures.append(f"{action}:unsafe:{index}: mutation was not refused")
                    if evidence_after != evidence_before:
                        failures.append(f"{action}:unsafe:{index}: operation evidence changed")
            finally:
                exact_confirmations += package.image_confirmation_count
                package.force_destroy_qualification_project()
                for record in case_records[batch_start:]:
                    record["cleanup_verified"] = True

    for action in ACTIONS:
        for index, (stage, certainty, expected) in enumerate(terminal_cases, start=1):
            with tempfile.TemporaryDirectory(prefix=f"spell-v04-compose-terminal-{action}-") as directory:
                package = new_package(directory)
                case_start = len(case_records)
                try:
                    if action != "enable":
                        _write_evidence(package, "SETTLED", "NO_EFFECT")
                        package.enable()
                    if action == "rollback":
                        _write_evidence(package, "SETTLED", "NO_EFFECT")
                        upgraded = package.upgrade(
                            driver_image_id=driver_image_b,
                            target_version="0.4.1-test",
                        )
                        if not upgraded.applied:
                            failures.append(f"{action}:terminal:{index}: pre-upgrade refused")
                    _write_evidence(package, stage, certainty)
                    before_state = package._load_state()
                    before = _transition_state_sha256(package, before_state)
                    evidence_before = package.operation_path.read_bytes()
                    result = _invoke_action(package, action, driver_image_b=driver_image_b)
                    action_counts[action] += 1
                    after_state = package._load_state()
                    after = _transition_state_sha256(package, after_state)
                    evidence_after = package.operation_path.read_bytes()
                    case_records.append(
                        _lifecycle_case(
                            action=action,
                            index=index,
                            stage=stage,
                            certainty=certainty,
                            expected=expected,
                            result=result,
                            project=before_state["project_name"],
                            before_state_sha256=before,
                            after_state_sha256=after,
                            before_evidence_sha256=hashlib.sha256(evidence_before).hexdigest(),
                            after_evidence_sha256=hashlib.sha256(evidence_after).hexdigest(),
                            driver_image_before=before_state["driver_image_id"],
                            driver_image_after=after_state["driver_image_id"],
                            pki_image_id=before_state["pki_image_id"],
                        )
                    )
                    if result.applied is not expected or after == before:
                        failures.append(f"{action}:terminal:{index}: transition refused")
                    if evidence_after != evidence_before:
                        failures.append(f"{action}:terminal:{index}: operation evidence changed")
                    state = after_state
                    if action == "enable":
                        package._assert_exact_containers(state, driver_running=True)
                        if state.get("enabled") is not True:
                            failures.append(f"{action}:terminal:{index}: not enabled")
                    elif action == "upgrade":
                        package._assert_exact_containers(state, driver_running=False)
                        if state.get("package_version") != "0.4.1-test":
                            failures.append(f"{action}:terminal:{index}: target differs")
                    elif action == "rollback":
                        package._assert_exact_containers(state, driver_running=False)
                        if state.get("package_version") != "0.4.0":
                            failures.append(f"{action}:terminal:{index}: prior differs")
                    elif action == "uninstall":
                        if state.get("installed") is not False:
                            failures.append(f"{action}:terminal:{index}: remains installed")
                        for key in VOLUME_KEYS[:2]:
                            if package._volume_digest(state, key) is not None:
                                failures.append(f"{action}:terminal:{index}: credential retained")
                    else:
                        package._assert_exact_containers(state, driver_running=False)
                        if state.get("enabled") is not False:
                            failures.append(f"{action}:terminal:{index}: remains enabled")
                finally:
                    exact_confirmations += package.image_confirmation_count
                    package.force_destroy_qualification_project()
                    for record in case_records[case_start:]:
                        record["cleanup_verified"] = True

    if failures:
        raise RuntimeError("; ".join(failures))
    terminal_count = len(terminal_cases) * len(ACTIONS)
    unsafe_count = len(unsafe_cases) * len(ACTIONS)
    if len(case_records) != terminal_count + unsafe_count:
        raise RuntimeError("SC006 detailed case ledger is incomplete")
    if source_fingerprint_v04(source_root) != source_before:
        raise RuntimeError("source changed during SC006 lifecycle qualification")
    if locked_host_tools(source_root, "V04-SC-006") != host_tools:
        raise RuntimeError("locked host tools changed during SC006 qualification")
    result = {
        "test_id": "V04-SC-006",
        "source_fingerprint_sha256": source_before,
        "assertions": [
            {"id": "declared-platform-runtime-verified", "passed": True},
            {"id": "hash-locked-docker-and-compose-paths-used", "passed": True},
            {"id": "unique-compose-project-per-install", "passed": True},
            {"id": "compose-driver-disabled-by-default", "passed": True},
            {"id": "compose-profile-enables-only-package-services", "passed": True},
            {"id": "exact-local-synthetic-images-confirmed", "passed": True},
            {"id": "unsafe-compose-transitions-refused-before-mutation", "passed": True},
            {"id": "terminal-compose-transition-postconditions-verified", "passed": True},
            {"id": "journal-and-credentials-preserved-across-image-transitions", "passed": True},
            {"id": "credentials-removed-only-after-safe-uninstall", "passed": True},
        ],
        "metrics": {
            "lifecycle_engine": "docker-compose-v2",
            "runtime_platform": "linux/amd64",
            "runtime_transition_matrix_executed": True,
            "locked_tool_paths_confirmed": True,
            "platform_profile_count": 1,
            "install_case_count": installed_projects,
            **{f"{action}_case_count": count for action, count in action_counts.items()},
            "terminal_case_count": terminal_count,
            "unsafe_refusal_case_count": unsafe_count,
            "runtime_transition_case_count": terminal_count + unsafe_count,
            "unique_project_count": installed_projects,
            "exact_image_confirmation_count": exact_confirmations,
            "docker_command_count": docker.command_count,
            "mutating_docker_command_count": docker.mutating_command_count,
            "failed_case_count": 0,
        },
    }
    if output is not None:
        ledger = {
            "schema_version": "spell.v04.sc006-lifecycle-ledger/1",
            "run_id": run_id,
            "source_fingerprint_sha256": source_before,
            "images": {
                "driver_a": driver_image_a,
                "driver_b": driver_image_b,
                "pki_init": pki_image,
            },
            "tools": host_tools,
            "cases": case_records,
            "summary": {
                "case_count": terminal_count + unsafe_count,
                "failed_case_count": 0,
                "terminal_case_count": terminal_count,
                "unsafe_refusal_case_count": unsafe_count,
                "unique_project_count": installed_projects,
            },
        }
        _atomic_write(output, _canonical_bytes(ledger))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--state-dir", type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--driver-image", required=True)
    install_parser.add_argument("--pki-image", required=True)
    install_parser.add_argument("--package-version", default="0.4.0")
    install_parser.add_argument("--project")

    subparsers.add_parser("enable")
    subparsers.add_parser("disable")
    upgrade_parser = subparsers.add_parser("upgrade")
    upgrade_parser.add_argument("--driver-image", required=True)
    upgrade_parser.add_argument("--target-version", required=True)
    subparsers.add_parser("rollback")
    subparsers.add_parser("uninstall")

    qualify_parser = subparsers.add_parser("qualify")
    qualify_parser.add_argument("--driver-image-a", required=True)
    qualify_parser.add_argument("--driver-image-b", required=True)
    qualify_parser.add_argument("--pki-image", required=True)
    qualify_parser.add_argument("--run-id")
    qualify_parser.add_argument("--provenance-output", type=Path)

    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == "qualify":
        result = qualify(
            root,
            driver_image_a=args.driver_image_a,
            driver_image_b=args.driver_image_b,
            pki_image=args.pki_image,
            run_id=args.run_id,
            provenance_output=args.provenance_output,
        )
    else:
        if args.state_dir is None:
            parser.error("--state-dir is required for lifecycle commands")
        package = ComposeDriverPackage(root, args.state_dir.resolve())
        if args.command == "install":
            result = package.install(
                driver_image_id=args.driver_image,
                pki_image_id=args.pki_image,
                package_version=args.package_version,
                project_name=args.project,
            )
        elif args.command == "enable":
            result = package.enable()
        elif args.command == "disable":
            result = package.disable()
        elif args.command == "upgrade":
            result = package.upgrade(
                driver_image_id=args.driver_image,
                target_version=args.target_version,
            )
        elif args.command == "rollback":
            result = package.rollback()
        else:
            result = package.uninstall()
        result = result.as_dict()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
