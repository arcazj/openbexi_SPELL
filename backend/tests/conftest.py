from __future__ import annotations

import time
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.auth import AuthConfig, issue_local_dev_token
from backend.config import Settings
from backend.database import Base, create_database
from backend.migrations import schema_migrations


@pytest.fixture
def procedures_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "procedures"
    directory.mkdir()
    (directory / "integration.spell.py").write_text(
        '"""Integration test procedure."""\n\n'
        'Log("begin")\n'
        'Telemetry("sim.test.value", value=42, unit="count")\n'
        'Wait(0.2)\n'
        'Prompt("Acknowledge?", choices=["yes"], default="yes")\n'
        'Log("done")\n',
        encoding="utf-8",
    )
    (directory / "recovery.spell.py").write_text(
        '"""Recovery test procedure."""\n\n'
        'Log("checkpoint before prompt")\n'
        'Prompt("Recover this prompt?", choices=["recover"], default="recover")\n'
        'Log("recovered")\n',
        encoding="utf-8",
    )
    (directory / "pause.spell.py").write_text(
        '"""Pause and resume test procedure."""\n\n'
        'Log("before wait")\n'
        'Wait(3.0)\n'
        'Log("after wait")\n',
        encoding="utf-8",
    )
    return directory


@pytest.fixture
def auth_config() -> AuthConfig:
    return AuthConfig(
        issuer="openbexi-spell-tests",
        audience="openbexi-spell-api",
        signing_secret=b"test-only-secret-with-at-least-32-bytes",
        clock_skew_seconds=1,
        max_token_lifetime_seconds=900,
        allow_local_dev_issuance=True,
    )


def _headers(auth_config: AuthConfig, subject: str, role: str) -> dict[str, str]:
    token = issue_local_dev_token(
        auth_config,
        subject=subject,
        role=role,
        peer_host="127.0.0.1",
        lifetime_seconds=600,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(tmp_path: Path, procedures_dir: Path, auth_config: AuthConfig):
    database_url = os.getenv(
        "SPELL_TEST_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    )
    if os.getenv("SPELL_TEST_DATABASE_URL"):
        engine, _ = create_database(database_url)
        with engine.begin() as connection:
            schema_migrations.drop(connection, checkfirst=True)
            Base.metadata.drop_all(connection)
        engine.dispose()
    settings = Settings(
        database_url=database_url,
        procedures_dir=procedures_dir,
        websocket_replay_limit=1000,
        websocket_queue_size=64,
        websocket_keepalive_seconds=0.1,
    )
    with TestClient(create_app(settings, auth_config=auth_config)) as test_client:
        yield test_client


@pytest.fixture
def viewer_headers(auth_config: AuthConfig) -> dict[str, str]:
    return _headers(auth_config, "pytest-viewer", "viewer")


@pytest.fixture
def operator_headers(auth_config: AuthConfig) -> dict[str, str]:
    return _headers(auth_config, "pytest-operator", "operator")


@pytest.fixture
def admin_headers(auth_config: AuthConfig) -> dict[str, str]:
    return _headers(auth_config, "pytest-admin", "admin")


def wait_for_state(
    client: TestClient,
    execution_id: str,
    headers: dict[str, str],
    states: set[str],
    timeout: float = 8,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/executions/{execution_id}/snapshot", headers=headers)
        assert response.status_code == 200, response.text
        last = response.json()
        if last["execution"]["state"] in states:
            return last
        time.sleep(0.05)
    raise AssertionError(f"execution did not enter {states}; last snapshot: {last}")
