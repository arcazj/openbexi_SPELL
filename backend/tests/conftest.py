from __future__ import annotations

import time
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.database import Base, create_database


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
def client(tmp_path: Path, procedures_dir: Path):
    database_url = os.getenv(
        "SPELL_TEST_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    )
    if os.getenv("SPELL_TEST_DATABASE_URL"):
        engine, _ = create_database(database_url)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        engine.dispose()
    settings = Settings(
        database_url=database_url,
        procedures_dir=procedures_dir,
        dev_auth_token="test-token",
        websocket_replay_limit=1000,
        websocket_queue_size=64,
        websocket_keepalive_seconds=0.1,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def viewer_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-token", "X-Dev-Role": "viewer"}


@pytest.fixture
def operator_headers() -> dict[str, str]:
    return {
        "Authorization": "Bearer test-token",
        "X-Dev-Role": "operator",
        "X-Dev-Actor": "pytest-operator",
    }


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {
        "Authorization": "Bearer test-token",
        "X-Dev-Role": "admin",
        "X-Dev-Actor": "pytest-admin",
    }


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
