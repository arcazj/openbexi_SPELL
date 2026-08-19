from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.auth import AuthConfig
from backend.config import Settings
from backend.development_bundle_builder import InProcessDualBundleBuilder

from .conftest import wait_for_state


def test_example_60_forms_execute_through_public_api_and_durable_supervisor(
    tmp_path: Path,
    procedures_dir: Path,
    auth_config: AuthConfig,
    operator_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    source = (
        "tc_item = BuildTC('CMDNAME')\n"
        "Send(command='CMDNAME')\n"
        "Send(command=tc_item)\n"
    )
    (procedures_dir / "v11_example_60.spell.py").write_text(
        source, encoding="utf-8"
    )
    backup_directory = tmp_path / "v11-api-migration-backups"
    backup_directory.mkdir()
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'v11-api.db').as_posix()}",
        procedures_dir=procedures_dir,
        data_dir=tmp_path / "v11-api-data",
        websocket_replay_limit=1000,
        websocket_queue_size=64,
        v0007_backup_directory=backup_directory,
        websocket_keepalive_seconds=0.1,
    )

    with TestClient(
        create_app(
            settings,
            auth_config=auth_config,
            development_bundle_builder=InProcessDualBundleBuilder(),
        )
    ) as client:
        validation = client.post(
            "/api/v1/procedures/validate",
            headers=viewer_headers,
            json={"source": source, "source_name": "v11_example_60.spell.py"},
        )
        assert validation.status_code == 200, validation.text
        assert validation.json()["valid"] is True
        assert validation.json()["subset_version"] == "spell-telecommand-simulator/0.11"

        created = client.post(
            "/api/v1/executions",
            headers=operator_headers,
            json={
                "procedure_id": "v11_example_60",
                "context_id": "simulator",
                "reason": "execute both documented Example 60 forms",
                "idempotency_key": "v11-api-example-60",
            },
        )
        assert created.status_code == 202, created.text
        execution_id = created.json()["execution"]["id"]
        completed = wait_for_state(
            client, execution_id, viewer_headers, {"completed", "failed"}, timeout=15
        )

        assert completed["execution"]["state"] == "completed", completed
        assert completed["execution"]["variables"]["tc_item"].startswith(
            "spell-tc-item-v11:"
        )
        events = client.get(
            f"/api/v1/executions/{execution_id}/events", headers=viewer_headers
        )
        assert events.status_code == 200, events.text
        items = events.json()["items"]
        requests = [
            item
            for item in items
            if item["event_type"] == "procedure.telecommand_requested"
        ]
        results = [
            item
            for item in items
            if item["event_type"] == "procedure.telecommand_result"
        ]
        settlements = [
            item
            for item in items
            if item["event_type"] == "procedure.telecommand_settled"
        ]
        assert [item["payload"]["selector"]["kind"] for item in requests] == [
            "name",
            "item",
        ]
        assert len(results) == len(settlements) == 2
        assert all(item["payload"]["outcome"] == "SETTLED" for item in results)
        assert all(item["payload"]["successful"] is True for item in settlements)

