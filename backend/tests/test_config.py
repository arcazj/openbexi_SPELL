from __future__ import annotations

from pathlib import Path

import pytest

from backend.config import DRIVER_CLIENT_KEY_PATH, DRIVER_TARGET, Settings


def settings(**overrides) -> Settings:
    values = {
        "database_url": "sqlite://",
        "procedures_dir": Path("procedures"),
        "websocket_replay_limit": 1000,
        "websocket_queue_size": 256,
        "websocket_keepalive_seconds": 5.0,
        "command_ack_timeout_seconds": 5.0,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"websocket_replay_limit": 0}, "SPELL_WS_REPLAY_LIMIT"),
        ({"websocket_queue_size": -1}, "SPELL_WS_QUEUE_SIZE"),
        ({"websocket_keepalive_seconds": 0.0}, "SPELL_WS_KEEPALIVE_SECONDS"),
        ({"websocket_keepalive_seconds": float("nan")}, "SPELL_WS_KEEPALIVE_SECONDS"),
        ({"websocket_keepalive_seconds": float("inf")}, "SPELL_WS_KEEPALIVE_SECONDS"),
        ({"driver_target": "example.invalid:50051"}, "bundled simulator"),
        ({"driver_rpc_timeout_seconds": 0.0}, "SPELL_DRIVER_RPC_TIMEOUT_SECONDS"),
        ({"driver_poll_seconds": float("nan")}, "SPELL_DRIVER_POLL_SECONDS"),
        (
            {"driver_poll_seconds": 5.0, "driver_stale_after_seconds": 5.0},
            "SPELL_DRIVER_STALE_AFTER_SECONDS",
        ),
        (
            {"driver_enabled": True, "driver_client_key_path": Path("client.key")},
            "fixed service mount",
        ),
    ],
)
def test_settings_reject_unbounded_or_nonfinite_websocket_limits(
    overrides: dict, expected_error: str
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        settings(**overrides)


def test_settings_accept_positive_stream_and_command_limits() -> None:
    configured = settings()
    assert configured.websocket_replay_limit == 1000
    assert configured.websocket_queue_size == 256
    assert configured.websocket_keepalive_seconds == 5.0
    assert configured.command_ack_timeout_seconds == 5.0
    assert configured.driver_enabled is False
    assert configured.driver_target == DRIVER_TARGET
    assert configured.driver_client_key_path == DRIVER_CLIENT_KEY_PATH


def test_settings_from_env_rejects_ambiguous_driver_enablement(monkeypatch) -> None:
    monkeypatch.setenv("SPELL_DRIVER_ENABLED", "yes")

    with pytest.raises(ValueError, match="SPELL_DRIVER_ENABLED"):
        Settings.from_env()
