#!/usr/bin/env python3
"""Open one real simulator context and wait for its v0.7 observations."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.config import Settings
from backend.credential_bootstrap import (
    RUNTIME_DIRECTORY,
    SOURCE_DIRECTORY,
    clear_credentials,
    install_runtime_credentials,
    read_source_credentials,
)
from backend.database import create_database
from backend.driver_domain import (
    ContextConfiguration,
    GenerationTuple,
    OpenContextCommand,
    OperationIdentity,
)
from backend.driver_gateway import DriverGateway
from backend.driver_repository import (
    DEFAULT_PROFILE_ID,
    DriverNotFoundError,
    DriverRepository,
)
from backend.observation_repository import ObservationRepository
from spell.driver.configuration import context_binding_digest


CONFIRMATION = "LOCAL_SYNTHETIC_NON_CUI_ONLY"
CONTEXT_ID = "v07-telemetry-synthetic-context"
CONTEXT_GENERATION_ID = "00000000-0000-4000-8000-000000000701"
OPERATION_ID = "00000000-0000-4000-8000-000000000702"
ATTEMPT_ID = "00000000-0000-4000-8000-000000000703"
CORRELATION_ID = "00000000-0000-4000-8000-000000000704"
CONTEXT_SCHEMA_VERSION = "context-schema-1"
CONTEXT_PROFILE_ID = "context-profile-1"
CONTEXT_LABEL = "v07-telemetry-qualification-context"
ITEM_IDS = (
    "TM.POWER.BUS_VOLTAGE",
    "TM.POWER.SAFE_MODE",
    "TM.THERMAL.MODE",
)


def _ensure_runtime_credentials() -> None:
    key = RUNTIME_DIRECTORY / "client.key"
    if key.is_file() and not key.is_symlink():
        return
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("the telemetry seed cannot provision gateway credentials")
    credentials = read_source_credentials(SOURCE_DIRECTORY)
    try:
        install_runtime_credentials(credentials, RUNTIME_DIRECTORY)
    finally:
        clear_credentials(credentials)


async def _wait_connected(
    gateway: DriverGateway,
    repository: DriverRepository,
    *,
    timeout_seconds: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        driver = repository.get_driver(DEFAULT_PROFILE_ID)["driver"]
        if gateway.connected and driver["ready"]:
            return driver
        await asyncio.sleep(0.1)
    raise RuntimeError("the bundled simulator gateway did not become ready")


def _ensure_context_projection(
    repository: DriverRepository,
    driver: dict[str, object],
) -> tuple[dict[str, object], str]:
    host_generation = str(driver["current_host_generation_id"])
    digest = context_binding_digest(
        server_profile_id=str(driver["server_profile_id"]),
        driver_host_generation=host_generation,
        host_profile_digest=str(driver["configuration_digest"]),
        schema_version=CONTEXT_SCHEMA_VERSION,
        context_profile_id=CONTEXT_PROFILE_ID,
        synthetic_context_label=CONTEXT_LABEL,
    )
    try:
        context = repository.get_context_generation(
            CONTEXT_ID, CONTEXT_GENERATION_ID
        )["context_generation"]
    except DriverNotFoundError:
        repository.create_context_generation(
            profile_id=DEFAULT_PROFILE_ID,
            host_generation_id=host_generation,
            context_id=CONTEXT_ID,
            context_generation_id=CONTEXT_GENERATION_ID,
            configuration_schema_version=CONTEXT_SCHEMA_VERSION,
            configuration_digest=digest,
            actor="v07-browser-qualification",
            correlation_id=CORRELATION_ID,
        )
        context = repository.get_context_generation(
            CONTEXT_ID, CONTEXT_GENERATION_ID
        )["context_generation"]
    if (
        context["host_generation_id"] != host_generation
        or context["configuration_digest"] != digest
        or context["state"] not in {"OPENING", "ACTIVE"}
    ):
        raise RuntimeError("the telemetry qualification context differs")
    return context, digest


def _open_command(driver: dict[str, object], digest: str) -> OpenContextCommand:
    return OpenContextCommand(
        identity=OperationIdentity(
            generations=GenerationTuple(
                server_profile_id=str(driver["server_profile_id"]),
                driver_host_generation=str(driver["current_host_generation_id"]),
                host_profile_digest=str(driver["configuration_digest"]),
                context_id=CONTEXT_ID,
                context_generation=CONTEXT_GENERATION_ID,
                context_binding_digest=digest,
            ),
            operation_id=OPERATION_ID,
            attempt_id=ATTEMPT_ID,
            attempt_number=1,
            correlation_id=CORRELATION_ID,
            deadline_unix_ms=int(
                (datetime.now(timezone.utc) + timedelta(seconds=30)).timestamp()
                * 1000
            ),
            credential_epoch=int(driver["credential_epoch"]),
        ),
        configuration=ContextConfiguration(
            schema_version=CONTEXT_SCHEMA_VERSION,
            context_profile_id=CONTEXT_PROFILE_ID,
            synthetic_context_label=CONTEXT_LABEL,
            expected_digest=digest,
        ),
    )


async def seed(
    settings: Settings,
    driver_repository: DriverRepository,
    observation_repository: ObservationRepository,
    *,
    timeout_seconds: float,
) -> dict[str, object]:
    gateway = DriverGateway(driver_repository, settings)
    await gateway.start()
    try:
        driver = await _wait_connected(
            gateway, driver_repository, timeout_seconds=timeout_seconds
        )
        context, digest = _ensure_context_projection(driver_repository, driver)
        if context["state"] == "OPENING":
            result = await gateway.execute_lifecycle(
                _open_command(driver, digest), actor="v07-browser-qualification"
            )
            if result["stage"] != "SETTLED" or result["disposition"] != "OK":
                raise RuntimeError("the real telemetry context did not open")
    finally:
        await gateway.close()

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        snapshot = observation_repository.snapshot(CONTEXT_ID)
        if (
            snapshot["driver_time"] is not None
            and snapshot["synchronization_state"] == "COMPLETE"
            and tuple(item["item_id"] for item in snapshot["items"]) == ITEM_IDS
            and all(
                item["quality"] == "GOOD"
                and item["validity"] == "VALID"
                and item["freshness"] == "FRESH"
                and item["alarm"] is not None
                for item in snapshot["items"]
            )
        ):
            return {
                "context_id": CONTEXT_ID,
                "context_generation_id": CONTEXT_GENERATION_ID,
                "item_ids": list(ITEM_IDS),
                "stream_epoch": snapshot["stream_epoch"],
                "through_sequence": snapshot["through_sequence"],
            }
        await asyncio.sleep(0.1)
    raise RuntimeError("the real telemetry projection did not become complete")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.confirm != CONFIRMATION:
        raise ValueError("exact local synthetic confirmation is required")
    if not 0 < args.timeout_seconds <= 60:
        raise ValueError("timeout must be positive and at most 60 seconds")
    settings = Settings.from_env()
    if not settings.driver_enabled:
        raise ValueError("the real telemetry seed requires the bundled driver")
    _ensure_runtime_credentials()
    engine, session_factory = create_database(settings.database_url)
    try:
        result = asyncio.run(
            seed(
                settings,
                DriverRepository(session_factory),
                ObservationRepository(session_factory),
                timeout_seconds=args.timeout_seconds,
            )
        )
    finally:
        engine.dispose()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
