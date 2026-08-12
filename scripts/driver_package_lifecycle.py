#!/usr/bin/env python3
"""Fail-closed local package lifecycle for the bundled v0.4 simulator host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "scripts/driver-package-v04.json"
STATE_NAME = "install-state.json"
OPERATIONS_NAME = "operation-evidence.json"
JOURNAL_NAME = "driver-journal.bin"
AUDIT_NAME = "canonical-audit.jsonl"
CREDENTIAL_NAME = "driver-credential.secret"
SCHEMA_VERSION = "spell.driver-package-state/1"
MAX_JSON_BYTES = 1024 * 1024
VERSION_PATTERN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}\Z")
PROFILE_KEYS = {
    "schema_version",
    "product_version",
    "scope_profile",
    "compose_file",
    "compose_services",
    "compose_volumes",
    "default_enabled",
    "bundled_simulator_service",
    "compose_profile",
    "declared_platforms",
    "retained_paths",
    "nonterminal_operation_stages",
    "terminal_operation_stage",
    "terminal_certainties",
    "uncertain_certainties",
    "unsafe_transition_policy",
}
STATE_KEYS = {
    "schema_version",
    "package_version",
    "platform_profile",
    "installed",
    "enabled",
    "active_service",
    "prior_profile",
}


class LifecycleRefusal(RuntimeError):
    """The requested package transition cannot safely proceed."""


@dataclass(frozen=True)
class TransitionResult:
    action: str
    applied: bool
    reason: str


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


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


def load_profile(path: Path = PROFILE_PATH) -> dict[str, Any]:
    profile = _load_object(path, "driver package profile")
    if set(profile) != PROFILE_KEYS:
        raise ValueError("driver package profile fields differ")
    if profile.get("schema_version") != "spell.driver-package-profile/1":
        raise ValueError("driver package profile schema differs")
    if profile.get("product_version") != "0.4.0":
        raise ValueError("driver package profile version differs")
    if profile.get("scope_profile") != "candidate-a-local-synthetic-simulator":
        raise ValueError("driver package scope profile differs")
    if profile.get("compose_file") != "compose.yaml":
        raise ValueError("driver package Compose file differs")
    if profile.get("compose_services") != ["pki-init", "spell-driver"]:
        raise ValueError("driver package Compose service set differs")
    if profile.get("compose_volumes") != [
        "spell-driver-client-credentials",
        "spell-driver-server-credentials",
        "spell-driver-journal",
    ]:
        raise ValueError("driver package Compose volume set differs")
    platforms = profile.get("declared_platforms")
    if platforms != [
        {
            "architecture": "amd64",
            "id": "oci-compose-linux-amd64",
            "operating_system": "linux",
            "packaging": "docker-compose-v2",
        }
    ]:
        raise ValueError("driver package declared platform profile differs")
    if profile.get("default_enabled") is not False:
        raise ValueError("driver package must be disabled by default")
    if profile.get("bundled_simulator_service") != "spell-driver":
        raise ValueError("driver package may enable only the bundled simulator")
    if profile.get("compose_profile") != "driver":
        raise ValueError("driver package Compose profile differs")
    if profile.get("retained_paths") != [
        JOURNAL_NAME,
        OPERATIONS_NAME,
        AUDIT_NAME,
    ]:
        raise ValueError("driver package retained evidence paths differ")
    if profile.get("unsafe_transition_policy") != "refuse-and-audit":
        raise ValueError("driver package unsafe transition policy differs")
    if profile.get("terminal_operation_stage") != "SETTLED":
        raise ValueError("driver package terminal operation stage differs")
    terminal_certainties = profile.get("terminal_certainties")
    if terminal_certainties != ["NO_EFFECT", "EFFECT_CONFIRMED"]:
        raise ValueError("driver package terminal certainties differ")
    nonterminal_stages = profile.get("nonterminal_operation_stages")
    if nonterminal_stages != ["REQUESTED", "ACCEPTED", "DISPATCHED", "RECONCILING"]:
        raise ValueError("driver package nonterminal operation stages differ")
    uncertain_certainties = profile.get("uncertain_certainties")
    if uncertain_certainties != ["EFFECT_POSSIBLE", "EFFECT_UNKNOWN"]:
        raise ValueError("driver package uncertain certainties differ")
    return profile


def _validate_state(state: dict[str, Any], profile: dict[str, Any]) -> None:
    if set(state) != STATE_KEYS or state.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("driver package state schema/fields differ")
    version = state.get("package_version")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ValueError("driver package state version is invalid")
    platform_ids = {item["id"] for item in profile["declared_platforms"]}
    if state.get("platform_profile") not in platform_ids:
        raise ValueError("driver package state platform differs")
    installed = state.get("installed")
    enabled = state.get("enabled")
    if type(installed) is not bool or type(enabled) is not bool:
        raise ValueError("driver package state flags must be booleans")
    if enabled and not installed:
        raise ValueError("an uninstalled driver package cannot be enabled")
    expected_service = profile["bundled_simulator_service"] if enabled else None
    if state.get("active_service") != expected_service:
        raise ValueError("driver package active service differs from enabled state")
    prior = state.get("prior_profile")
    if (
        not isinstance(prior, dict)
        or set(prior) != {"product_version", "driver_enabled"}
        or prior.get("product_version") != "0.3.0"
        or prior.get("driver_enabled") is not False
    ):
        raise ValueError("driver package prior profile differs")


def _safe_root(root: Path) -> Path:
    resolved = root.resolve()
    if root.is_symlink():
        raise ValueError("install root cannot be a symlink")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


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


def _sha256_if_present(path: Path) -> str | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"retained lifecycle input must be a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _append_audit(root: Path, event: dict[str, Any]) -> None:
    path = root / AUDIT_NAME
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("canonical audit path is unsafe")
    previous = path.read_bytes() if path.exists() else b""
    _atomic_write(path, previous + _canonical_bytes(event), 0o600)


def _operation_blocker(root: Path, profile: dict[str, Any]) -> str | None:
    path = root / OPERATIONS_NAME
    if not path.exists():
        return None
    evidence = _load_object(path, "operation evidence")
    if set(evidence) != {"operations"}:
        return "operation evidence fields are absent or unrecognized"
    operations = evidence.get("operations")
    if not isinstance(operations, list):
        raise ValueError("operation evidence operations must be a list")
    terminal_stage = profile["terminal_operation_stage"]
    terminal_certainties = set(profile["terminal_certainties"])
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
            or stage != terminal_stage
            or certainty not in terminal_certainties
        ):
            operation_id = operation_id or "unknown"
            return f"nonterminal or uncertain operation {operation_id}: stage={stage} certainty={certainty}"
    return None


def install(root: Path, *, platform_id: str) -> TransitionResult:
    target = _safe_root(root)
    profile = load_profile()
    platform_ids = {item.get("id") for item in profile["declared_platforms"]}
    if platform_id not in platform_ids:
        raise ValueError(f"undeclared platform profile: {platform_id}")
    state_path = target / STATE_NAME
    if state_path.exists():
        raise LifecycleRefusal("driver package is already installed")
    state = {
        "schema_version": SCHEMA_VERSION,
        "package_version": profile["product_version"],
        "platform_profile": platform_id,
        "installed": True,
        "enabled": False,
        "active_service": None,
        "prior_profile": {"product_version": "0.3.0", "driver_enabled": False},
    }
    _atomic_write(state_path, _canonical_bytes(state))
    _append_audit(
        target,
        {"action": "install", "applied": True, "platform_profile": platform_id},
    )
    return TransitionResult("install", True, "installed-disabled")


def transition(root: Path, action: str, *, target_version: str | None = None) -> TransitionResult:
    if action not in {"enable", "disable", "upgrade", "rollback", "uninstall"}:
        raise ValueError(f"unsupported lifecycle action: {action}")
    target = _safe_root(root)
    profile = load_profile()
    state_path = target / STATE_NAME
    state = _load_object(state_path, "driver package state")
    _validate_state(state, profile)
    before = {
        JOURNAL_NAME: _sha256_if_present(target / JOURNAL_NAME),
        OPERATIONS_NAME: _sha256_if_present(target / OPERATIONS_NAME),
    }

    blocker = _operation_blocker(target, profile)
    if blocker is not None:
        _append_audit(
            target,
            {
                "action": action,
                "applied": False,
                "reason": blocker,
                "retained_sha256": before,
            },
        )
        return TransitionResult(action, False, blocker)

    reason = "applied"
    if action == "enable":
        if state.get("installed") is not True:
            raise LifecycleRefusal("cannot enable an uninstalled driver package")
        state["enabled"] = True
        state["active_service"] = profile["bundled_simulator_service"]
        reason = "bundled-simulator-enabled"
    elif action == "disable":
        state["enabled"] = False
        state["active_service"] = None
        reason = "disabled"
    elif action == "upgrade":
        if (
            not isinstance(target_version, str)
            or not VERSION_PATTERN.fullmatch(target_version)
            or target_version == state.get("package_version")
        ):
            raise ValueError("upgrade requires a distinct target version")
        state["package_version"] = target_version
        state["enabled"] = False
        state["active_service"] = None
        reason = "upgraded-disabled"
    elif action == "rollback":
        state["installed"] = False
        state["enabled"] = False
        state["active_service"] = None
        state["package_version"] = state["prior_profile"]["product_version"]
        reason = "prior-disabled-profile-restored"
    else:
        state["installed"] = False
        state["enabled"] = False
        state["active_service"] = None
        credential = target / CREDENTIAL_NAME
        if credential.exists():
            if credential.is_symlink() or not credential.is_file():
                raise ValueError("credential path is unsafe")
            credential.unlink()
        reason = "uninstalled-records-retained"

    _atomic_write(state_path, _canonical_bytes(state))
    after = {
        JOURNAL_NAME: _sha256_if_present(target / JOURNAL_NAME),
        OPERATIONS_NAME: _sha256_if_present(target / OPERATIONS_NAME),
    }
    if before != after:
        raise RuntimeError("package lifecycle transition changed retained certainty evidence")
    _append_audit(
        target,
        {
            "action": action,
            "applied": True,
            "reason": reason,
            "retained_sha256": after,
        },
    )
    return TransitionResult(action, True, reason)


def _write_fixture(root: Path, stage: str, certainty: str) -> None:
    _atomic_write(root / JOURNAL_NAME, b"private-journal-and-no-reexecution-tombstones\n")
    _atomic_write(
        root / OPERATIONS_NAME,
        _canonical_bytes(
            {
                "operations": [
                    {
                        "operation_id": f"operation-{stage.casefold()}",
                        "stage": stage,
                        "certainty": certainty,
                        "tombstone": True,
                    }
                ]
            }
        ),
    )
    _atomic_write(root / CREDENTIAL_NAME, b"synthetic-test-secret\n")


def qualify(root: Path = ROOT) -> dict[str, Any]:
    if str(root) not in os.sys.path:
        os.sys.path.insert(0, str(root))
    from scripts.source_fingerprint_v04 import source_fingerprint_v04

    profile = load_profile(root / "scripts/driver-package-v04.json")
    platform_ids = [item["id"] for item in profile["declared_platforms"]]
    cases = (
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
    actions = ("enable", "disable", "upgrade", "rollback", "uninstall")
    counts = {action: 0 for action in actions}
    enable_count = 0
    failures: list[str] = []
    for platform_id in platform_ids:
        with tempfile.TemporaryDirectory(prefix="spell-driver-install-") as directory:
            location = Path(directory)
            install(location, platform_id=platform_id)
            state = _load_object(location / STATE_NAME, "installed state")
            if state["enabled"] is not False or state["active_service"] is not None:
                failures.append(f"{platform_id}: install was not disabled")
            enabled = transition(location, "enable")
            state = _load_object(location / STATE_NAME, "enabled state")
            if (
                not enabled.applied
                or state["enabled"] is not True
                or state["active_service"] != profile["bundled_simulator_service"]
            ):
                failures.append(f"{platform_id}: enabled a non-bundled service")
            else:
                enable_count += 1

        for action in actions:
            for index, (stage, certainty, should_apply) in enumerate(cases):
                with tempfile.TemporaryDirectory(prefix=f"spell-driver-{action}-") as directory:
                    location = Path(directory)
                    install(location, platform_id=platform_id)
                    if action != "enable":
                        transition(location, "enable")
                    _write_fixture(location, stage, certainty)
                    state_before = (location / STATE_NAME).read_bytes()
                    journal = (location / JOURNAL_NAME).read_bytes()
                    operations = (location / OPERATIONS_NAME).read_bytes()
                    credential_existed = (location / CREDENTIAL_NAME).exists()
                    result = transition(
                        location,
                        action,
                        target_version="0.4.1-test" if action == "upgrade" else None,
                    )
                    counts[action] += 1
                    if result.applied is not should_apply:
                        failures.append(
                            f"{platform_id}:{action}:{index}: applied={result.applied}"
                        )
                    if not should_apply and (location / STATE_NAME).read_bytes() != state_before:
                        failures.append(f"{platform_id}:{action}:{index}: state changed")
                    if (location / JOURNAL_NAME).read_bytes() != journal:
                        failures.append(f"{platform_id}:{action}:{index}: journal changed")
                    if (location / OPERATIONS_NAME).read_bytes() != operations:
                        failures.append(f"{platform_id}:{action}:{index}: evidence changed")
                    credential_exists = (location / CREDENTIAL_NAME).exists()
                    expected_credential = not (action == "uninstall" and should_apply)
                    if credential_existed and credential_exists is not expected_credential:
                        failures.append(f"{platform_id}:{action}:{index}: secret handling")
                    audit_lines = (location / AUDIT_NAME).read_text(encoding="utf-8").splitlines()
                    minimum_audit_lines = 2 if action == "enable" else 3
                    if len(audit_lines) < minimum_audit_lines:
                        failures.append(f"{platform_id}:{action}:{index}: audit missing")
                    else:
                        audit_event = _loads_json(audit_lines[-1], "canonical audit event")
                        if (
                            audit_event.get("action") != action
                            or audit_event.get("applied") is not should_apply
                        ):
                            failures.append(f"{platform_id}:{action}:{index}: audit differs")
                    if should_apply:
                        state = _load_object(location / STATE_NAME, "transitioned state")
                        expected_enabled = action == "enable"
                        expected_service = (
                            profile["bundled_simulator_service"] if expected_enabled else None
                        )
                        if (
                            state.get("enabled") is not expected_enabled
                            or state.get("active_service") != expected_service
                        ):
                            failures.append(f"{platform_id}:{action}:{index}: enabled state")
                        if action == "enable" and (
                            state.get("installed") is not True
                            or state.get("package_version") != "0.4.0"
                        ):
                            failures.append(f"{platform_id}:{action}:{index}: enable state")
                        if action == "disable" and (
                            state.get("installed") is not True
                            or state.get("package_version") != "0.4.0"
                        ):
                            failures.append(f"{platform_id}:{action}:{index}: disable state")
                        if action == "upgrade" and (
                            state.get("installed") is not True
                            or state.get("package_version") != "0.4.1-test"
                        ):
                            failures.append(f"{platform_id}:{action}:{index}: upgrade state")
                        if action == "rollback" and (
                            state.get("installed") is not False
                            or state.get("package_version") != "0.3.0"
                            or state.get("prior_profile", {}).get("driver_enabled") is not False
                        ):
                            failures.append(f"{platform_id}:{action}:{index}: rollback state")
                        if action == "uninstall" and state.get("installed") is not False:
                            failures.append(f"{platform_id}:{action}:{index}: uninstall state")

    if failures:
        raise RuntimeError("; ".join(failures))
    return {
        "test_id": "V04-SC-006",
        "source_fingerprint_sha256": source_fingerprint_v04(root),
        "assertions": [
            {"id": "declared-platform-profile-verified", "passed": True},
            {"id": "install-disabled-by-default", "passed": True},
            {"id": "enable-selects-only-bundled-simulator", "passed": True},
            {"id": "unsafe-transitions-refused-and-audited", "passed": True},
            {
                "id": "terminal-transition-postconditions-verified",
                "passed": True,
            },
            {"id": "journal-tombstones-and-certainty-preserved", "passed": True},
            {"id": "credentials-removed-only-after-safe-uninstall", "passed": True},
        ],
        "metrics": {
            "platform_profile_count": len(platform_ids),
            "install_case_count": len(platform_ids),
            "enable_case_count": enable_count + counts["enable"],
            "disable_case_count": counts["disable"],
            "upgrade_case_count": counts["upgrade"],
            "rollback_case_count": counts["rollback"],
            "uninstall_case_count": counts["uninstall"],
            "failed_case_count": 0,
            "terminal_case_count": (
                len(platform_ids)
                * sum(1 for _, _, should_apply in cases if should_apply)
                * len(actions)
            ),
            "unsafe_refusal_case_count": (
                len(platform_ids)
                * sum(1 for _, _, should_apply in cases if not should_apply)
                * len(actions)
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("command", choices=("qualify",))
    args = parser.parse_args()
    if args.command == "qualify":
        print(json.dumps(qualify(args.root.resolve()), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
