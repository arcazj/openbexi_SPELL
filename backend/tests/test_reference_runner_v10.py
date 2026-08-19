from __future__ import annotations

from pathlib import Path

import pytest

from backend.procedure_parser import ProcedureCatalog

from .test_worker_v06 import _next, _start_worker


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("example_number", range(1, 196), ids=lambda value: f"example-{value:03d}")
def test_every_reference_example_executes_through_the_v010_worker(
    monkeypatch: pytest.MonkeyPatch,
    example_number: int,
) -> None:
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        f"result: str = ''\nReferenceExample({example_number}, target=result)\n",
        f"reference-{example_number:03d}.spell.py",
    )
    assert procedure.ir_version == "0.10"

    thread, _control, output = _start_worker(
        monkeypatch,
        procedure,
        execution_id=f"reference-example-{example_number:03d}",
    )
    terminal, seen = _next(
        output,
        lambda item: item.get("kind") == "terminal",
        timeout=5,
    )
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert terminal["state"] == "completed"
    event = next(
        effect
        for message in seen
        if message.get("kind") == "step_commit"
        for effect in message.get("effects", [])
        if effect.get("event_type") == "procedure.reference_example_completed"
    )
    assert event["payload"]["example_number"] == example_number
    assert event["payload"]["passed"] is True
    assert event["payload"]["status"] == "PASS"
    assert event["payload"]["assertions"]
    assert event["payload"]["trace"]


def test_single_catalog_runner_routes_prompt_index_to_example_195(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    procedures = ProcedureCatalog(ROOT / "procedures").list()
    assert [procedure.id for procedure in procedures] == ["language_reference_244"]
    procedure = procedures[0]
    assert procedure.ir_version == "0.10"

    thread, control, output = _start_worker(
        monkeypatch,
        procedure,
        execution_id="reference-menu-example-195",
    )
    opened, before_prompt = _next(
        output,
        lambda item: item.get("kind") == "prompt_opened",
        timeout=5,
    )
    assert opened["prompt_type"] == "LIST"
    assert opened["list_mode"] == "INDEX"
    assert len(opened["choices"]) == 195
    assert opened["choices"][-1].endswith("extract TM/TC database values")

    control.put(
        {
            "type": "prompt_response",
            "prompt_id": opened["prompt_id"],
            "response": 194,
        }
    )
    terminal, after_prompt = _next(
        output,
        lambda item: item.get("kind") == "terminal",
        timeout=5,
    )
    thread.join(timeout=1)
    seen = [*before_prompt, *after_prompt]

    assert not thread.is_alive()
    assert terminal["state"] == "completed"
    reference_event = next(
        effect
        for message in seen
        if message.get("kind") == "step_commit"
        for effect in message.get("effects", [])
        if effect.get("event_type") == "procedure.reference_example_completed"
    )
    assert reference_event["payload"]["example_number"] == 195
    assert reference_event["payload"]["passed"] is True
    assert any(
        assertion["assertion_id"] == "tmtc.catalog_digest" and assertion["passed"]
        for assertion in reference_event["payload"]["assertions"]
    )
    final_commit = [
        message for message in seen if message.get("kind") == "step_commit"
    ][-1]
    assert final_commit["variables"]["selected_index"] == 194
    assert final_commit["variables"]["example_number"] == 195
    assert final_commit["variables"]["result"].startswith("Example 195: PASS")
