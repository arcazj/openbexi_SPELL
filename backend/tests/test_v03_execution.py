from pathlib import Path

from fastapi.testclient import TestClient

from .conftest import wait_for_state
from .test_api_execution import create_execution


def test_typed_variables_survive_prompt_crash_and_recovery(
    client: TestClient,
    procedures_dir: Path,
    viewer_headers: dict[str, str],
    operator_headers: dict[str, str],
    admin_headers: dict[str, str],
) -> None:
    (procedures_dir / "typed_recovery.spell.py").write_text(
        "count: int = 0\n"
        "count = count + 1\n"
        "Prompt('Recover typed state?', choices=['recover'], default='recover')\n"
        "count = count + 1\n"
        "Telemetry('sim.recovered_count', value=count, unit='count')\n",
        encoding="utf-8",
    )
    execution_id = create_execution(client, operator_headers, "typed_recovery")
    prompting = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    assert prompting["execution"]["variables"] == {"count": 1}
    assert prompting["execution"]["current_step"] == 2
    prompt_id = prompting["active_prompt"]["id"]

    crash = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=admin_headers,
        json={
            "type": "simulate_crash",
            "expected_revision": prompting["execution"]["revision"],
            "reason": "verify typed checkpoint recovery",
            "idempotency_key": "typed-state-crash",
        },
    )
    assert crash.status_code == 202, crash.text
    recoverable = wait_for_state(
        client, execution_id, viewer_headers, {"recovery_required"}
    )
    assert recoverable["execution"]["variables"] == {"count": 1}

    recover = client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=operator_headers,
        json={
            "type": "recover",
            "expected_revision": recoverable["execution"]["revision"],
            "reason": "restore typed checkpoint",
            "idempotency_key": "typed-state-recover",
        },
    )
    assert recover.status_code == 202, recover.text
    reopened = wait_for_state(client, execution_id, viewer_headers, {"prompting"})
    assert reopened["active_prompt"]["id"] == prompt_id
    assert reopened["execution"]["variables"] == {"count": 1}

    response = client.post(
        f"/api/v1/prompts/{prompt_id}/responses",
        headers=operator_headers,
        json={
            "value": "recover",
            "expected_revision": reopened["execution"]["revision"],
            "reason": "finish typed recovery",
            "idempotency_key": "typed-state-response",
        },
    )
    assert response.status_code == 202, response.text
    completed = wait_for_state(client, execution_id, viewer_headers, {"completed"})
    assert completed["execution"]["variables"] == {"count": 2}
    samples = [
        item
        for item in completed["telemetry"]
        if item["payload"]["channel"] == "sim.recovered_count"
    ]
    assert len(samples) == 1
    assert samples[0]["payload"]["value"] == 2
