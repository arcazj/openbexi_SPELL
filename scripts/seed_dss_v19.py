#!/usr/bin/env python3
"""Admit the actual DSS context, preserving fenced historical generations."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select
from backend.config import Settings
from backend.database import create_database
from backend.driver_gateway import DriverGateway
from backend.driver_models import DriverContextGeneration, DriverHostGeneration
from backend.driver_repository import DEFAULT_PROFILE_ID, DriverConflictError, DriverRepository
from backend.observation_repository import ObservationRepository
from dss.catalog import TELEMETRY_ITEMS
from scripts import seed_observation_v07 as legacy
from spell.driver.configuration import context_binding_digest

ACTOR = "v19-dss-bootstrap"


def _binding(driver, host_id, host_digest):
    return context_binding_digest(server_profile_id=str(driver["server_profile_id"]),
        driver_host_generation=host_id, host_profile_digest=host_digest,
        schema_version=legacy.CONTEXT_SCHEMA_VERSION,
        context_profile_id=legacy.CONTEXT_PROFILE_ID, synthetic_context_label=legacy.CONTEXT_LABEL)


def ensure_context(repository, driver, context_id="simulator"):
    """Retire only our own context on an already terminal host; never rewrite it."""
    host_id = str(driver["current_host_generation_id"])
    digest = _binding(driver, host_id, str(driver["configuration_digest"]))
    with repository.session_factory() as session:
        prior = session.scalar(select(DriverContextGeneration)
            .where(DriverContextGeneration.context_id == context_id)
            .order_by(DriverContextGeneration.generation_number.desc()).limit(1))
        old = None
        ordinal = 1
        if prior is not None:
            host = session.get(DriverHostGeneration, prior.host_generation_id)
            if (host is None or host.profile_id != DEFAULT_PROFILE_ID
                    or prior.configuration_schema_version != legacy.CONTEXT_SCHEMA_VERSION
                    or prior.configuration_digest != _binding(driver, host.id, host.configuration_digest)):
                raise RuntimeError("DSS bootstrap refuses a context outside its own fixed configuration")
            if prior.host_generation_id == host_id and prior.state in {"OPENING", "ACTIVE"}:
                return repository.get_context_generation(context_id, prior.id)["context_generation"], digest
            if host.state not in {"FAILED", "CLOSED"}:
                raise RuntimeError("DSS bootstrap refuses to replace a context on a live host")
            old = (prior.id, prior.revision, prior.state)
            ordinal = prior.generation_number + 1
    generation = str(uuid5(NAMESPACE_URL, f"openbexi:dss-context:{context_id}:{host_id}:{ordinal}"))
    correlation = str(uuid5(NAMESPACE_URL, f"openbexi:dss-bootstrap:{generation}"))
    if old is not None and old[2] not in {"CLOSED", "FAILED"}:
        repository.record_context_state(old[0], "FAILED", expected_revision=old[1],
            actor=ACTOR, correlation_id=correlation, observed_at=datetime.now(timezone.utc))
    repository.create_context_generation(profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id, context_id=context_id, context_generation_id=generation,
        configuration_schema_version=legacy.CONTEXT_SCHEMA_VERSION,
        configuration_digest=digest, actor=ACTOR, correlation_id=correlation)
    return repository.get_context_generation(context_id, generation)["context_generation"], digest


def open_command(driver, context, digest, context_id="simulator"):
    command = legacy._open_command(driver, digest, context_id=context_id)
    generation = str(context["context_generation_id"])
    return replace(command, identity=replace(command.identity,
        generations=replace(command.identity.generations, context_generation=generation),
        operation_id=str(uuid5(NAMESPACE_URL, generation + ":open")),
        attempt_id=str(uuid5(NAMESPACE_URL, generation + ":open:attempt:1")),
        correlation_id=str(uuid5(NAMESPACE_URL, generation + ":bootstrap"))))


async def start_gateway(repository, settings):
    # The running API also observes host health. Retry only its optimistic
    # projection revision race; no lifecycle operation has been sent yet.
    for attempt in range(3):
        # DriverClient consumes/unlinks its private-key file after constructing
        # the TLS channel, including starts that later lose a projection race.
        legacy._ensure_runtime_credentials()
        gateway = DriverGateway(repository, settings)
        try:
            await gateway.start()
            return gateway
        except DriverConflictError as exc:
            await gateway.close()
            if str(exc) != "driver host generation revision conflict" or attempt == 2:
                raise
            await asyncio.sleep(0.05)
    raise RuntimeError("DSS gateway startup exhausted its attempts")


async def seed(settings, repository, observations, *, timeout_seconds=60.0, context_id="simulator"):
    gateway = await start_gateway(repository, settings)
    try:
        driver = await legacy._wait_connected(gateway, repository, timeout_seconds=timeout_seconds)
        context, digest = ensure_context(repository, driver, context_id)
        if context["state"] == "OPENING":
            result = await gateway.execute_lifecycle(open_command(driver, context, digest, context_id), actor=ACTOR)
            if result["stage"] != "SETTLED" or result["disposition"] != "OK":
                raise RuntimeError("the real DSS context did not open")
    finally:
        await gateway.close()
    expected = tuple(sorted(item["item_id"] for item in TELEMETRY_ITEMS))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        snapshot = observations.snapshot(context_id)
        if (snapshot["driver_time"] is not None and snapshot["synchronization_state"] == "COMPLETE"
                and tuple(item["item_id"] for item in snapshot["items"]) == expected
                and all(item["source_id"] == "dss-GENERIC" and item["quality"] == "GOOD"
                    and item["validity"] == "VALID" and item["freshness"] == "FRESH"
                    for item in snapshot["items"])):
            return {"context_id": context_id, "context_generation_id": context["context_generation_id"],
                "item_ids": list(expected), "stream_epoch": snapshot["stream_epoch"],
                "through_sequence": snapshot["through_sequence"]}
        await asyncio.sleep(0.1)
    raise RuntimeError("the real DSS telemetry projection did not become complete")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--context-id", choices=["simulator"], default="simulator")
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args(argv)
    if args.confirm != legacy.CONFIRMATION or not 0 < args.timeout_seconds <= 60:
        raise ValueError("exact local confirmation and bounded timeout are required")
    settings = Settings.from_env()
    if not settings.dss_enabled or not settings.driver_enabled:
        raise ValueError("actual DSS and its driver must both be enabled")
    engine, sessions = create_database(settings.database_url)
    try:
        result = asyncio.run(seed(settings, DriverRepository(sessions),
            ObservationRepository(sessions, dss_enabled=True),
            timeout_seconds=args.timeout_seconds, context_id=args.context_id))
    finally:
        engine.dispose()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
