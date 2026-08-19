from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import pytest

from scripts import driver_compose_lifecycle_v04 as lifecycle


ROOT = Path(__file__).resolve().parents[2]
DRIVER_A = "sha256:" + "a" * 64
DRIVER_B = "sha256:" + "b" * 64
PKI = "sha256:" + "c" * 64
PROJECT = "spellv04-" + "d" * 24


class InstallRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str], _: Path) -> lifecycle.CommandResult:
        values = tuple(command)
        self.calls.append(values)
        if values[1:3] == ("version", "--format"):
            return lifecycle.CommandResult(0, "linux/amd64\n", "")
        if values[1:3] == ("image", "inspect"):
            image_id = values[3]
            if image_id == DRIVER_A:
                component, version = "spell-driver", "0.4.0"
            elif image_id == PKI:
                component, version = "pki-init", "0.4.0"
            else:
                return lifecycle.CommandResult(1, "", "not found")
            output = [
                {
                    "Id": image_id,
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Config": {
                        "Labels": {
                            "org.openbexi.spell.scope": lifecycle.SCOPE_PROFILE,
                            "org.openbexi.spell.component": component,
                            "org.openbexi.spell.package.version": version,
                        }
                    },
                }
            ]
            return lifecycle.CommandResult(0, json.dumps(output), "")
        if values[1:3] in {
            ("ps", "--all"),
            ("volume", "ls"),
            ("network", "ls"),
        }:
            return lifecycle.CommandResult(0, "", "")
        if values[1:3] == ("volume", "inspect"):
            return lifecycle.CommandResult(1, "", "not found")
        if len(values) > 2 and values[1] == "compose" and "config" in values:
            services = ["proxy", "backend", "postgres"]
            if "--profile" in values:
                services.extend(lifecycle.PACKAGE_SERVICES)
            return lifecycle.CommandResult(0, "\n".join(services) + "\n", "")
        raise AssertionError(f"unexpected Docker command: {values}")


def _installed_package(tmp_path: Path) -> tuple[lifecycle.ComposeDriverPackage, InstallRunner]:
    runner = InstallRunner()
    docker = lifecycle.DockerCli(ROOT, runner=runner)
    package = lifecycle.ComposeDriverPackage(ROOT, tmp_path, docker=docker)
    result = package.install(
        driver_image_id=DRIVER_A,
        pki_image_id=PKI,
        project_name=PROJECT,
    )
    assert result.applied
    return package, runner


def test_compose_install_is_unique_exact_and_disabled(tmp_path: Path) -> None:
    package, runner = _installed_package(tmp_path)
    state = json.loads(package.state_path.read_text(encoding="utf-8"))
    override = json.loads(package.override_path.read_text(encoding="utf-8"))

    assert state["project_name"] == PROJECT
    assert state["enabled"] is False
    assert state["installed"] is True
    assert set(override["services"]) == set(lifecycle.PACKAGE_SERVICES)
    assert override["services"]["spell-driver"]["image"] == DRIVER_A
    assert override["services"]["pki-init"]["image"] == PKI
    assert all("up" not in call and "create" not in call for call in runner.calls)


@pytest.mark.parametrize("action", lifecycle.ACTIONS)
def test_unsafe_evidence_refuses_before_any_docker_command(
    tmp_path: Path, action: str
) -> None:
    package, runner = _installed_package(tmp_path)
    lifecycle._write_evidence(package, "RECONCILING", "EFFECT_UNKNOWN")
    runner.calls.clear()

    result = lifecycle._invoke_action(package, action, driver_image_b=DRIVER_B)

    assert result.applied is False
    assert "nonterminal or uncertain" in result.reason
    assert runner.calls == []
    event = json.loads(package.audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert event["action"] == action
    assert event["applied"] is False


@pytest.mark.parametrize(
    "evidence_update",
    [
        {"schema_version": "unknown"},
        {"scope_profile": "not-local-synthetic"},
        {"project_name": "spellv04-" + "e" * 24},
        {"operations": "not-a-list"},
    ],
)
def test_untrusted_operation_evidence_fails_closed(
    tmp_path: Path, evidence_update: dict[str, object]
) -> None:
    package, runner = _installed_package(tmp_path)
    lifecycle._write_evidence(package, "SETTLED", "NO_EFFECT")
    evidence = json.loads(package.operation_path.read_text(encoding="utf-8"))
    evidence.update(evidence_update)
    package.operation_path.write_text(json.dumps(evidence), encoding="utf-8")
    runner.calls.clear()

    result = package.uninstall()

    assert result.applied is False
    assert runner.calls == []


@pytest.mark.parametrize("corruption", ["duplicate", "non-finite", "extra-field"])
def test_corrupt_compose_state_is_rejected_before_any_docker_command(
    tmp_path: Path, corruption: str
) -> None:
    package, runner = _installed_package(tmp_path)
    text = package.state_path.read_text(encoding="utf-8")
    if corruption == "duplicate":
        text = text.replace(
            '"schema_version":',
            '"schema_version":"duplicate","schema_version":',
            1,
        )
    elif corruption == "non-finite":
        text = text.replace('"enabled":false', '"enabled":NaN', 1)
    else:
        value = json.loads(text)
        value["unexpected"] = True
        text = json.dumps(value)
    package.state_path.write_text(text, encoding="utf-8")
    runner.calls.clear()

    with pytest.raises(ValueError, match="JSON|state"):
        package.enable()
    assert runner.calls == []


def test_docker_exit_code_rejects_bool_as_an_integer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, runner = _installed_package(tmp_path)
    state = package._load_state()
    inventory = {
        "pki-init": {"Image": PKI, "State": {"Running": False, "ExitCode": False}},
        "spell-driver": {
            "Image": DRIVER_A,
            "State": {"Running": False, "Health": {"Status": "healthy"}},
        },
    }
    monkeypatch.setattr(package, "_container_inventory", lambda _: inventory)
    runner.calls.clear()

    with pytest.raises(lifecycle.LifecycleRefusal, match="did not complete"):
        package._assert_exact_containers(state, driver_running=False)
    assert runner.calls == []


def test_exact_image_identity_and_local_scope_are_mandatory(tmp_path: Path) -> None:
    package, _ = _installed_package(tmp_path)
    with pytest.raises(ValueError, match="exact sha256 image ID"):
        package._inspect_image("openbexi-spell-driver:latest", component="spell-driver", version="0.4.0")


def test_volume_digest_helper_is_valid_python() -> None:
    compile(lifecycle.VOLUME_DIGEST_SCRIPT, "<volume-digest>", "exec")


def test_disabled_driver_replacement_uses_supported_no_start_up_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, _ = _installed_package(tmp_path)
    state = package._load_state()
    target = dict(state)
    target["driver_image_id"] = DRIVER_B
    confirmation_count_before = package.image_confirmation_count
    snapshots = iter(({"journal": "same"}, {"journal": "same"}))
    inventories = iter(
        (
            {"spell-driver": {"Id": "old-driver"}},
            {
                "spell-driver": {
                    "Image": DRIVER_B,
                    "State": {"Running": False},
                }
            },
        )
    )
    compose_calls: list[tuple[tuple[str, ...], bool]] = []

    monkeypatch.setattr(package, "_volume_snapshot", lambda _: next(snapshots))
    monkeypatch.setattr(package, "_stop_driver", lambda _: None)
    monkeypatch.setattr(package, "_container_inventory", lambda _: next(inventories))
    monkeypatch.setattr(package.docker, "run", lambda *args, **_: lifecycle.CommandResult(0, "", ""))
    monkeypatch.setattr(
        package,
        "_compose",
        lambda _, *args, mutating=False, **__: compose_calls.append((args, mutating))
        or lifecycle.CommandResult(0, "", ""),
    )

    package._replace_disabled_driver(state, target)

    assert compose_calls == [
        (("up", "--no-build", "--no-deps", "--no-start", "spell-driver"), True)
    ]
    assert package.image_confirmation_count == confirmation_count_before + 1


def test_destructive_cleanup_is_limited_to_qualification_projects(tmp_path: Path) -> None:
    package, runner = _installed_package(tmp_path)
    runner.calls.clear()
    with pytest.raises(lifecycle.LifecycleRefusal, match="qualification projects"):
        package.force_destroy_qualification_project()
    assert runner.calls == []
