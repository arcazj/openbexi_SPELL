from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.auth import AuthConfig
from backend.config import Settings
from backend.development_bundle_builder import InProcessDualBundleBuilder

from .conftest import wait_for_state
from .test_api_execution import fenced_prompt_request


ROOT = Path(__file__).resolve().parents[2]


def test_reference_runner_selects_example_195_through_the_public_api(
    tmp_path: Path,
    procedures_dir: Path,
    auth_config: AuthConfig,
    operator_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    source = (ROOT / "procedures" / "language_reference_244.spell.py").read_text(
        encoding="utf-8"
    )
    (procedures_dir / "language_reference_244.spell.py").write_text(
        source, encoding="utf-8"
    )
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'reference-api.db').as_posix()}",
        procedures_dir=procedures_dir,
        data_dir=tmp_path / "reference-api-data",
        websocket_replay_limit=1000,
        websocket_queue_size=64,
        v0007_backup_directory=tmp_path / "reference-api-migration-backups",
        websocket_keepalive_seconds=0.1,
    )
    settings.v0007_backup_directory.mkdir()

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
            json={
                "source": source,
                "source_name": "language_reference_244.spell.py",
            },
        )
        assert validation.status_code == 200, validation.text
        assert validation.json()["valid"] is True
        assert validation.json()["subset_version"] == "spell-lrm244-adapter/0.10"

        created = client.post(
            "/api/v1/executions",
            headers=operator_headers,
            json={
                "procedure_id": "language_reference_244",
                "context_id": "simulator",
                "reason": "prove SPELL reference Example 195",
                "idempotency_key": "v10-reference-api-example-195",
            },
        )
        assert created.status_code == 202, created.text
        execution_id = created.json()["execution"]["id"]

        prompting = wait_for_state(
            client, execution_id, viewer_headers, {"prompting"}, timeout=15
        )
        prompt = prompting["active_prompt"]
        assert prompt["type"] == "LIST"
        assert prompt["list_mode"] == "INDEX"
        assert len(prompt["options"]) == 195

        prompt_events = client.get(
            f"/api/v1/executions/{execution_id}/events", headers=viewer_headers
        )
        assert prompt_events.status_code == 200, prompt_events.text
        prompt_opened = next(
            item
            for item in prompt_events.json()["items"]
            if item["event_type"] == "prompt.opened"
        )
        assert prompt_opened["payload"]["type"] == "LIST"
        assert prompt_opened["payload"]["input_kind"] == "LIST"
        assert prompt_opened["payload"]["list_mode"] == "INDEX"

        prompt_headers, prompt_body = fenced_prompt_request(
            client,
            operator_headers,
            execution_id,
            prompting,
            value=194,
            idempotency_key="v10-reference-api-select-195",
            reason="select the final reference example",
        )
        answered = client.post(
            f"/api/v1/prompts/{prompt['id']}/responses",
            headers=prompt_headers,
            json=prompt_body,
        )
        assert answered.status_code == 202, answered.text

        completed = wait_for_state(
            client, execution_id, viewer_headers, {"completed", "failed"}, timeout=15
        )
        assert completed["execution"]["state"] == "completed", completed
        variables = completed["execution"]["variables"]
        assert variables["selected_index"] == 194
        assert variables["example_number"] == 195
        assert variables["result"].startswith("Example 195: PASS")

        events = client.get(
            f"/api/v1/executions/{execution_id}/events", headers=viewer_headers
        )
        assert events.status_code == 200, events.text
        reference_event = next(
            item
            for item in events.json()["items"]
            if item["event_type"] == "procedure.reference_example_completed"
        )
        payload = reference_event["payload"]
        assert payload["example_number"] == 195
        assert payload["status"] == "PASS"
        assert payload["passed"] is True
        assert any(
            assertion["assertion_id"] == "tmtc.catalog_digest"
            and assertion["passed"] is True
            for assertion in payload["assertions"]
        )
