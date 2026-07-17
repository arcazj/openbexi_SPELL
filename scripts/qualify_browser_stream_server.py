#!/usr/bin/env python3
"""Serve an isolated browser/WebSocket fan-out qualification target."""

from __future__ import annotations

import asyncio
import hashlib
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn
from fastapi import HTTPException

from backend.app import create_app
from backend.auth import AuthConfig, issue_local_dev_token
from backend.config import Settings
from backend.models import Event, Execution
from scripts.qualify_v03 import (
    ELAPSED_OVERRUN_LIMIT_SECONDS,
    SCHEDULE_MAX_LIMIT_MS,
    SCHEDULE_P95_LIMIT_MS,
    _source_fingerprint,
    percentile,
    scheduled_event_count,
    sequence_integrity,
)


RATE = 100.0
DURATION_SECONDS = 60.0
EVENT_COUNT = scheduled_event_count(RATE, DURATION_SECONDS)
temporary_directory = tempfile.TemporaryDirectory(prefix="spell-browser-stream-")
temporary = Path(temporary_directory.name)
procedures = temporary / "procedures"
procedures.mkdir()

settings = Settings(
    database_url=f"sqlite:///{(temporary / 'browser-stream.db').as_posix()}",
    procedures_dir=procedures,
    websocket_replay_limit=10_000,
    websocket_queue_size=8_192,
    websocket_keepalive_seconds=1.0,
)
auth_config = AuthConfig(
    issuer="openbexi-spell-browser-qualification",
    audience="openbexi-spell-api",
    signing_secret=b"browser-qualification-secret-material-not-persisted",
    clock_skew_seconds=0,
    max_token_lifetime_seconds=300,
    allow_local_dev_issuance=True,
)
app = create_app(settings, auth_config=auth_config)
token = issue_local_dev_token(
    auth_config,
    subject="qualification.browser",
    role="viewer",
    peer_host="127.0.0.1",
    lifetime_seconds=300,
)
execution_id: str | None = None
producer_task: asyncio.Task[None] | None = None
producer_result: dict[str, Any] = {"state": "not_started"}


def ensure_execution() -> str:
    """Create the qualification record after application startup reconciliation."""

    global execution_id
    if execution_id is not None:
        return execution_id
    with app.state.session_factory() as session:
        execution = Execution(
            procedure_id="qualification-browser-stream",
            procedure_name="Qualification Browser Stream",
            procedure_hash=hashlib.sha256(b"browser-stream").hexdigest(),
            procedure_source='Log("qualification")\n',
            steps=[],
            ir_version="0.3",
            variables={},
            context_id="simulator",
            created_by="qualification",
            creation_idempotency_key=str(uuid.uuid4()),
            state="running",
            revision=1,
            current_step=0,
            total_steps=0,
            worker_generation=0,
            next_sequence=1,
        )
        session.add(execution)
        session.commit()
        execution_id = execution.id
    return execution_id


async def produce() -> None:
    global producer_result
    target_execution_id = ensure_execution()
    scheduling_lag_ms: list[float] = []
    errors: list[str] = []
    produced_event_count = 0
    started = time.perf_counter()
    for index in range(EVENT_COUNT):
        target = started + index / RATE
        remaining = target - time.perf_counter()
        if remaining > 0:
            await asyncio.sleep(remaining)
        scheduling_lag_ms.append(max(0.0, (time.perf_counter() - target) * 1000))
        try:
            await asyncio.to_thread(
                app.state.supervisor.append_event,
                target_execution_id,
                "qualification.browser_stream",
                {"index": index},
                source="qualification",
            )
            produced_event_count += 1
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            break
    production_elapsed_seconds = time.perf_counter() - started
    remaining = started + DURATION_SECONDS - time.perf_counter()
    if remaining > 0:
        await asyncio.sleep(remaining)
    if not errors:
        try:
            await asyncio.to_thread(
                app.state.supervisor.append_event,
                target_execution_id,
                "qualification.browser_stream_end",
                {"event_count": EVENT_COUNT},
                source="qualification",
            )
        except Exception as exc:
            errors.append(f"sentinel {type(exc).__name__}: {exc}")

    expected_last = EVENT_COUNT + (0 if errors else 1)
    persisted = await asyncio.to_thread(
        app.state.supervisor.events_after,
        target_execution_id,
        0,
        EVENT_COUNT + 1,
    )
    elapsed_seconds = time.perf_counter() - started
    achieved_rate = (
        produced_event_count / production_elapsed_seconds
        if production_elapsed_seconds > 0
        else 0.0
    )
    producer_result = {
        "state": "finished",
        "errors": errors,
        "produced_event_count": produced_event_count,
        "production_elapsed_seconds": round(production_elapsed_seconds, 6),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "achieved_events_per_second": round(achieved_rate, 3),
        "schedule_p95_ms": round(percentile(scheduling_lag_ms, 0.95), 3),
        "schedule_max_ms": round(max(scheduling_lag_ms), 3),
        "persisted_sequence_integrity": sequence_integrity(
            [event["sequence"] for event in persisted], 1, expected_last
        ),
    }


@app.get("/qualification/config")
async def qualification_config() -> dict[str, Any]:
    target_execution_id = ensure_execution()
    return {
        "execution_id": target_execution_id,
        "token": token,
        "rate": RATE,
        "duration_seconds": DURATION_SECONDS,
        "event_count": EVENT_COUNT,
        "expected_last_sequence": EVENT_COUNT + 1,
        "schedule_p95_ms_at_most": SCHEDULE_P95_LIMIT_MS,
        "schedule_max_ms_at_most": SCHEDULE_MAX_LIMIT_MS,
        "elapsed_overrun_seconds_at_most": ELAPSED_OVERRUN_LIMIT_SECONDS,
        "source_fingerprint_sha256": _source_fingerprint(),
    }


@app.post("/qualification/start", status_code=202)
async def qualification_start() -> dict[str, str]:
    global producer_task, producer_result
    ensure_execution()
    if producer_task is not None:
        raise HTTPException(status_code=409, detail="qualification already started")
    producer_result = {"state": "running"}
    producer_task = asyncio.create_task(produce())
    return {"state": "running"}


@app.get("/qualification/result")
async def qualification_result() -> dict[str, Any]:
    return producer_result


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8765, log_level="warning")
