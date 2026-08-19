"""Strict local configuration for the isolated simulator host."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple


DEFAULT_SERVER_PROFILE_ID = "local-synthetic"
DEFAULT_DRIVER_PROFILE_ID = "local-synthetic-simulator"
DEFAULT_LOGICAL_DRIVER_ID = "bundled-deterministic-simulator"
DEFAULT_HOST_SCHEMA = "spell.driver.host-profile/1"
DEFAULT_CREDENTIAL_REFERENCE = "local-v04-driver-mtls"
DEFAULT_HOST_PROFILE_DIGEST = (
    "5eb17949cc4a33a460937e96d6ecc3c76ba190497d6adeb0cd673d4adfeef198"
)
DEFAULT_CLIENT_SAN = "spiffe://openbexi-spell.local/service/driver-gateway"
DEFAULT_CLIENT_COMMON_NAME = "openbexi-spell-driver-gateway"
DEFAULT_SERVER_NAME = "spell-driver"

_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
MAX_CONFIG_BYTES = 65_536


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key is forbidden: {key}")
        value[key] = item
    return value


def _reject_non_finite_json(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _require_exact_int(value: object, label: str, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the bounded integer range")


def canonical_host_profile_material(config: "HostConfig") -> dict[str, object]:
    """Return the non-secret typed material bound by the host profile digest."""

    return {
        "configuration_schema_version": config.host_configuration_schema,
        "contract_package": "spell.driver.v1",
        "credential_reference": config.credential_reference,
        "journal_max_bytes": config.journal.max_bytes,
        "journal_max_entries": config.journal.max_entries,
        "logical_driver_id": config.logical_driver_id,
        "max_attachments_per_context": config.capacity.max_attachments_per_context,
        "max_contexts_per_host": config.capacity.max_contexts_per_host,
        "max_lifecycle_operations_per_context": (
            config.capacity.max_lifecycle_operations_per_context
        ),
        "max_lifecycle_operations_per_host": (
            config.capacity.max_lifecycle_operations_per_host
        ),
        "server_profile_id": config.server_profile_id,
        "simulator": True,
    }


def host_profile_digest(config: "HostConfig") -> str:
    encoded = json.dumps(
        canonical_host_profile_material(config),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CapacityConfig:
    max_contexts_per_host: int = 1
    max_attachments_per_context: int = 1
    max_lifecycle_operations_per_host: int = 8
    max_lifecycle_operations_per_context: int = 8

    def __post_init__(self) -> None:
        values = (
            self.max_contexts_per_host,
            self.max_attachments_per_context,
            self.max_lifecycle_operations_per_host,
            self.max_lifecycle_operations_per_context,
        )
        for value in values:
            _require_exact_int(value, "capacity value", 1, 1024)


@dataclass(frozen=True)
class JournalConfig:
    max_entries: int = 10_000
    max_bytes: int = 16_777_216

    def __post_init__(self) -> None:
        _require_exact_int(
            self.max_entries, "journal max_entries", 1, 1_000_000
        )
        _require_exact_int(
            self.max_bytes, "journal max bytes", 1_048_576, 1_073_741_824
        )


@dataclass(frozen=True)
class HookConfig:
    context_hooks: Tuple[str, ...] = ("context-fixture-a", "context-fixture-b")
    attachment_hooks: Tuple[str, ...] = (
        "attachment-fixture-a",
        "attachment-fixture-b",
    )
    delay_ms: int = 0

    def __post_init__(self) -> None:
        if type(self.context_hooks) is not tuple or type(self.attachment_hooks) is not tuple:
            raise ValueError("hook collections must be tuples")
        if len(self.context_hooks) > 16 or len(self.attachment_hooks) > 16:
            raise ValueError("hook count exceeds the bounded limit")
        all_hooks = (*self.context_hooks, *self.attachment_hooks)
        if any(type(hook) is not str for hook in all_hooks):
            raise ValueError("hook identifiers must be strings")
        if len(all_hooks) != len(set(all_hooks)):
            raise ValueError("hook identifiers must be unique")
        if any(
            not hook or not hook.isascii() or len(hook.encode("ascii")) > 64
            for hook in all_hooks
        ):
            raise ValueError("hook identifiers must be nonempty bounded ASCII")
        _require_exact_int(self.delay_ms, "hook delay", 0, 10_000)


@dataclass(frozen=True)
class HostConfig:
    server_profile_id: str = DEFAULT_SERVER_PROFILE_ID
    driver_profile_id: str = DEFAULT_DRIVER_PROFILE_ID
    logical_driver_id: str = DEFAULT_LOGICAL_DRIVER_ID
    implementation_version: str = "0.4.0"
    host_configuration_schema: str = DEFAULT_HOST_SCHEMA
    host_profile_digest: str = ""
    driver_host_generation: str = field(
        default_factory=lambda: f"host-{uuid.uuid4()}"
    )
    credential_reference: str = DEFAULT_CREDENTIAL_REFERENCE
    credential_epoch: int = 1
    expected_client_san: str = DEFAULT_CLIENT_SAN
    expected_client_common_name: str = DEFAULT_CLIENT_COMMON_NAME
    revoked_client_fingerprints: Tuple[str, ...] = ()
    capacity: CapacityConfig = field(default_factory=CapacityConfig)
    journal: JournalConfig = field(default_factory=JournalConfig)
    hooks: HookConfig = field(default_factory=HookConfig)

    def __post_init__(self) -> None:
        bounded = (
            self.server_profile_id,
            self.driver_profile_id,
            self.logical_driver_id,
            self.implementation_version,
            self.host_configuration_schema,
            self.driver_host_generation,
            self.credential_reference,
            self.expected_client_san,
            self.expected_client_common_name,
        )
        if any(
            type(value) is not str
            or not value
            or len(value.encode("utf-8")) > 128
            for value in bounded
        ):
            raise ValueError("host identity fields must be nonempty and bounded")
        if type(self.capacity) is not CapacityConfig:
            raise ValueError("capacity must be a CapacityConfig")
        if type(self.journal) is not JournalConfig:
            raise ValueError("journal must be a JournalConfig")
        if type(self.hooks) is not HookConfig:
            raise ValueError("hooks must be a HookConfig")
        _require_exact_int(
            self.credential_epoch, "credential epoch", 1, 2_147_483_647
        )
        if type(self.revoked_client_fingerprints) is not tuple:
            raise ValueError("revoked client fingerprints must be a tuple")
        if any(
            type(value) is not str or _FINGERPRINT.fullmatch(value) is None
            for value in self.revoked_client_fingerprints
        ):
            raise ValueError("revoked client fingerprints must be lowercase SHA-256 values")
        if len(set(self.revoked_client_fingerprints)) != len(self.revoked_client_fingerprints):
            raise ValueError("revoked client fingerprints must be unique")
        if type(self.host_profile_digest) is not str:
            raise ValueError("host_profile_digest must be a string")
        resolved_digest = host_profile_digest(self)
        if self.host_profile_digest == "":
            object.__setattr__(self, "host_profile_digest", resolved_digest)
        elif _FINGERPRINT.fullmatch(self.host_profile_digest) is None:
            raise ValueError("host_profile_digest must be a lowercase SHA-256 digest")
        elif self.host_profile_digest != resolved_digest:
            raise ValueError("host_profile_digest does not bind the typed host profile")

    @classmethod
    def from_file(cls, path: str | Path) -> "HostConfig":
        config_path = Path(path)
        if config_path.is_symlink() or not config_path.is_file():
            raise ValueError("host configuration must be a regular file")
        encoded = config_path.read_bytes()
        if len(encoded) > MAX_CONFIG_BYTES:
            raise ValueError("host configuration exceeds the bounded size")
        raw = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_non_finite_json,
        )
        if not isinstance(raw, dict):
            raise ValueError("host configuration must be a JSON object")
        allowed = {
            "server_profile_id",
            "driver_profile_id",
            "logical_driver_id",
            "implementation_version",
            "host_configuration_schema",
            "host_profile_digest",
            "driver_host_generation",
            "credential_reference",
            "credential_epoch",
            "expected_client_san",
            "expected_client_common_name",
            "revoked_client_fingerprints",
            "capacity",
            "journal",
            "hooks",
        }
        unknown = set(raw).difference(allowed)
        if unknown:
            raise ValueError("unknown host configuration fields are forbidden")
        values = dict(raw)
        if "capacity" in values:
            if not isinstance(values["capacity"], dict):
                raise ValueError("capacity configuration must be an object")
            values["capacity"] = CapacityConfig(**values["capacity"])
        if "journal" in values:
            if not isinstance(values["journal"], dict):
                raise ValueError("journal configuration must be an object")
            values["journal"] = JournalConfig(**values["journal"])
        if "hooks" in values:
            if not isinstance(values["hooks"], dict):
                raise ValueError("hook configuration must be an object")
            hooks = dict(values["hooks"])
            if "context_hooks" in hooks:
                if type(hooks["context_hooks"]) is not list:
                    raise ValueError("context_hooks must be a JSON array")
                hooks["context_hooks"] = tuple(hooks["context_hooks"])
            if "attachment_hooks" in hooks:
                if type(hooks["attachment_hooks"]) is not list:
                    raise ValueError("attachment_hooks must be a JSON array")
                hooks["attachment_hooks"] = tuple(hooks["attachment_hooks"])
            values["hooks"] = HookConfig(**hooks)
        if "revoked_client_fingerprints" in values:
            if type(values["revoked_client_fingerprints"]) is not list:
                raise ValueError("revoked_client_fingerprints must be a JSON array")
            values["revoked_client_fingerprints"] = tuple(
                values["revoked_client_fingerprints"]
            )
        return cls(**values)
