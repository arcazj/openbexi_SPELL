from __future__ import annotations

import json
from pathlib import Path

import pytest

from driver_host.config import (
    MAX_CONFIG_BYTES,
    CapacityConfig,
    HookConfig,
    HostConfig,
    JournalConfig,
)
from driver_host.tests.support import make_config


def test_host_config_loads_only_typed_allowlisted_values(tmp_path: Path) -> None:
    capacity = CapacityConfig(2, 3, 4, 5)
    journal = JournalConfig(11, 1_048_576)
    hooks = HookConfig(("context-a",), ("attachment-a",), 9)
    expected = make_config(
        generation="host-generation-file",
        server_profile_id="test-server",
        credential_epoch=7,
        revoked_client_fingerprints=("f" * 64,),
        capacity=capacity,
        journal=journal,
        hooks=hooks,
    )
    path = tmp_path / "host.json"
    path.write_text(
        json.dumps(
            {
                "server_profile_id": "test-server",
                "driver_host_generation": "host-generation-file",
                "host_profile_digest": expected.host_profile_digest,
                "credential_epoch": 7,
                "revoked_client_fingerprints": ["f" * 64],
                "capacity": {
                    "max_contexts_per_host": 2,
                    "max_attachments_per_context": 3,
                    "max_lifecycle_operations_per_host": 4,
                    "max_lifecycle_operations_per_context": 5,
                },
                "journal": {"max_entries": 11, "max_bytes": 1_048_576},
                "hooks": {
                    "context_hooks": ["context-a"],
                    "attachment_hooks": ["attachment-a"],
                    "delay_ms": 9,
                },
            }
        ),
        encoding="utf-8",
    )

    config = HostConfig.from_file(path)

    assert config.server_profile_id == "test-server"
    assert config.driver_host_generation == "host-generation-file"
    assert config.credential_epoch == 7
    assert config.revoked_client_fingerprints == ("f" * 64,)
    assert config.capacity == capacity
    assert config.journal == journal
    assert config.hooks == hooks


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"unknown_override": True},
        {"host_profile_digest": "A" * 64},
        {"host_profile_digest": "0" * 64},
        {"credential_epoch": 0},
        {"capacity": {"max_contexts_per_host": 0}},
        {"journal": {"max_bytes": 1_048_575}},
        {"hooks": {"context_hooks": ["duplicate"], "attachment_hooks": ["duplicate"]}},
    ],
)
def test_host_config_rejects_malformed_or_out_of_bounds_input(
    tmp_path: Path, payload: object
) -> None:
    path = tmp_path / "host.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((TypeError, ValueError)):
        HostConfig.from_file(path)


@pytest.mark.parametrize(
    "text",
    [
        '{"credential_epoch":1,"credential_epoch":2}',
        '{"capacity":{"max_contexts_per_host":1,"max_contexts_per_host":2}}',
        '{"credential_epoch":NaN}',
        '{"credential_epoch":Infinity}',
        '{"credential_epoch":-Infinity}',
    ],
)
def test_host_config_rejects_duplicate_keys_and_non_finite_numbers(
    tmp_path: Path, text: str
) -> None:
    path = tmp_path / "host.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError):
        HostConfig.from_file(path)


@pytest.mark.parametrize(
    "payload",
    [
        {"credential_epoch": True},
        {"credential_epoch": 1.0},
        {"capacity": {"max_contexts_per_host": True}},
        {"capacity": {"max_contexts_per_host": 1.0}},
        {"journal": {"max_entries": True}},
        {"journal": {"max_bytes": 1_048_576.0}},
        {"hooks": {"delay_ms": False}},
        {"hooks": {"delay_ms": 1.0}},
        {"host_profile_digest": None},
        {"hooks": {"context_hooks": "context-a"}},
        {"hooks": {"attachment_hooks": {"attachment-a": True}}},
        {"revoked_client_fingerprints": "f" * 64},
        {"revoked_client_fingerprints": {"fingerprint": "f" * 64}},
    ],
)
def test_host_config_rejects_type_coercion_inputs(
    tmp_path: Path, payload: object
) -> None:
    path = tmp_path / "host.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((TypeError, ValueError)):
        HostConfig.from_file(path)


def test_host_config_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "host.json"
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))

    with pytest.raises(ValueError, match="bounded size"):
        HostConfig.from_file(path)


def test_host_config_requires_a_regular_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(ValueError, match="regular file"):
        HostConfig.from_file(missing)

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "host-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("the test filesystem does not permit symbolic links")
    with pytest.raises(ValueError, match="regular file"):
        HostConfig.from_file(link)


@pytest.mark.parametrize(
    ("factory", "kwargs"),
    [
        (CapacityConfig, {"max_lifecycle_operations_per_host": 1025}),
        (CapacityConfig, {"max_lifecycle_operations_per_host": True}),
        (CapacityConfig, {"max_lifecycle_operations_per_host": 8.0}),
        (JournalConfig, {"max_entries": 0}),
        (JournalConfig, {"max_entries": True}),
        (HookConfig, {"delay_ms": 10_001}),
        (HookConfig, {"delay_ms": False}),
        (HookConfig, {"context_hooks": ["not-a-tuple"]}),
        (HookConfig, {"context_hooks": ("non-ascii-\N{SNOWMAN}",)}),
    ],
)
def test_nested_config_bounds_are_enforced(factory, kwargs) -> None:
    with pytest.raises(ValueError):
        factory(**kwargs)


def test_default_host_generations_are_unique() -> None:
    first = HostConfig()
    second = HostConfig()

    assert first.driver_host_generation.startswith("host-")
    assert second.driver_host_generation.startswith("host-")
    assert first.driver_host_generation != second.driver_host_generation
