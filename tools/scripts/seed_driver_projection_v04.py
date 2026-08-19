#!/usr/bin/env python3
"""Seed one canonical synthetic projection for real-browser v0.4 qualification."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.database import create_database
from backend.driver_repository import DEFAULT_PROFILE_ID, DriverNotFoundError, DriverRepository
from spell.driver.configuration import context_binding_digest, execution_attachment_digest


CONFIRMATION = "LOCAL_SYNTHETIC_NON_CUI_ONLY"
CONTEXT_ID = "v04-ui-synthetic-context"
CONTEXT_GENERATION_ID = "00000000-0000-4000-8000-000000000401"
BINDING_ID = "00000000-0000-4000-8000-000000000402"
ATTACHMENT_GENERATION_ID = "00000000-0000-4000-8000-000000000403"
OPERATION_ID = "00000000-0000-4000-8000-000000000404"
ATTEMPT_ID = "00000000-0000-4000-8000-000000000405"
CORRELATION_ID = "00000000-0000-4000-8000-000000000406"


def _local_database_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme.startswith("sqlite"):
        return value
    if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
        raise ValueError("browser fixture requires SQLite or PostgreSQL")
    if parsed.hostname not in {"postgres", "localhost", "127.0.0.1"}:
        raise ValueError("browser fixture database must be local or the bundled service")
    if parsed.path.removeprefix("/") not in {"spell", "spell_ui_test"}:
        raise ValueError("browser fixture database name is not allowlisted")
    return value


def seed(repository: DriverRepository) -> dict[str, str]:
    driver = repository.get_driver(DEFAULT_PROFILE_ID)["driver"]
    if (
        not driver["simulator"]
        or not driver["enabled"]
        or not driver["ready"]
        or not driver["current_host_generation_id"]
    ):
        raise RuntimeError("the bundled synthetic driver must be enabled and ready")

    observed_at = datetime.now(timezone.utc)
    host_generation = str(driver["current_host_generation_id"])
    host_digest = str(driver["configuration_digest"])
    context_digest = context_binding_digest(
        server_profile_id=str(driver["server_profile_id"]),
        driver_host_generation=host_generation,
        host_profile_digest=host_digest,
        schema_version="spell.driver.context-profile/1",
        context_profile_id="local-synthetic-context",
        synthetic_context_label="UI qualification context",
    )
    changed = False
    try:
        context = repository.get_context_generation(CONTEXT_ID, CONTEXT_GENERATION_ID)[
            "context_generation"
        ]
    except DriverNotFoundError:
        repository.create_context_generation(
            profile_id=DEFAULT_PROFILE_ID,
            host_generation_id=host_generation,
            context_id=CONTEXT_ID,
            context_generation_id=CONTEXT_GENERATION_ID,
            configuration_schema_version="spell.driver.context-profile/1",
            configuration_digest=context_digest,
            actor="v04-browser-qualification",
            correlation_id=CORRELATION_ID,
        )
        context = repository.get_context_generation(CONTEXT_ID, CONTEXT_GENERATION_ID)[
            "context_generation"
        ]
        changed = True
    if (
        context["host_generation_id"] != host_generation
        or context["configuration_digest"] != context_digest
        or context["state"] not in {"OPENING", "ACTIVE"}
    ):
        raise RuntimeError("existing browser context differs from the canonical state")
    if context["state"] == "OPENING":
        repository.record_context_state(
            CONTEXT_GENERATION_ID,
            "ACTIVE",
            expected_revision=int(context["revision"]),
            actor="v04-browser-qualification",
            correlation_id=CORRELATION_ID,
            observed_at=observed_at,
        )
        changed = True

    attachment_digest = execution_attachment_digest(
        server_profile_id=str(driver["server_profile_id"]),
        driver_host_generation=host_generation,
        host_profile_digest=host_digest,
        context_id=CONTEXT_ID,
        context_generation=CONTEXT_GENERATION_ID,
        context_binding_digest=context_digest,
        execution_id="v04-ui-synthetic-execution",
        schema_version="spell.driver.attachment-profile/1",
        attachment_profile_id="local-synthetic-attachment",
        synthetic_execution_label="UI qualification execution",
    )
    try:
        binding = repository.get_binding(BINDING_ID)["binding"]
    except DriverNotFoundError:
        repository.create_binding(
            context_generation_id=CONTEXT_GENERATION_ID,
            driver_binding_id=BINDING_ID,
            execution_id="v04-ui-synthetic-execution",
            attachment_generation_id=ATTACHMENT_GENERATION_ID,
            configuration_schema_version="spell.driver.attachment-profile/1",
            configuration_digest=attachment_digest,
            actor="v04-browser-qualification",
            correlation_id=CORRELATION_ID,
        )
        binding = repository.get_binding(BINDING_ID)["binding"]
        changed = True
    if (
        binding["context_generation_id"] != CONTEXT_GENERATION_ID
        or binding["execution_id"] != "v04-ui-synthetic-execution"
        or binding["configuration_digest"] != attachment_digest
        or binding["state"] not in {"ATTACHING", "ATTACHED"}
    ):
        raise RuntimeError("existing browser binding differs from the canonical state")

    request_digest = hashlib.sha256(b"v04-ui-synthetic-attach").hexdigest()
    try:
        operation = repository.get_operation(OPERATION_ID)["operation"]
    except DriverNotFoundError:
        operation = repository.accept_operation(
            operation_id=OPERATION_ID,
            attempt_id=ATTEMPT_ID,
            method="AttachExecution",
            request_digest=request_digest,
            effect_class="EXECUTION_ATTACH",
            host_generation_id=host_generation,
            context_generation_id=CONTEXT_GENERATION_ID,
            driver_binding_id=BINDING_ID,
            target_operation_id=None,
            target_attempt_id=None,
            actor="v04-browser-qualification",
            correlation_id=CORRELATION_ID,
            deadline_at=observed_at + timedelta(seconds=30),
        )
        changed = True
    if (
        operation["current_attempt_id"] != ATTEMPT_ID
        or operation["method"] != "AttachExecution"
        or operation["request_digest"] != request_digest
        or operation["context_generation_id"] != CONTEXT_GENERATION_ID
        or operation["driver_binding_id"] != BINDING_ID
        or operation["stage"] not in {"ACCEPTED", "DISPATCHED", "SETTLED"}
    ):
        raise RuntimeError("existing browser operation differs from the canonical state")
    if operation["stage"] == "ACCEPTED":
        operation = repository.append_operation_transition(
            OPERATION_ID,
            ATTEMPT_ID,
            expected_revision=int(operation["revision"]),
            stage="DISPATCHED",
            certainty="EFFECT_POSSIBLE",
            disposition=None,
            safe_error_code=None,
            safe_error_message=None,
            evidence_digest=hashlib.sha256(b"v04-ui-dispatched").hexdigest(),
            actor="v04-browser-qualification",
            correlation_id=CORRELATION_ID,
        )
        changed = True
    if operation["stage"] == "DISPATCHED":
        operation = repository.append_operation_transition(
            OPERATION_ID,
            ATTEMPT_ID,
            expected_revision=int(operation["revision"]),
            stage="SETTLED",
            certainty="EFFECT_CONFIRMED",
            disposition="OK",
            safe_error_code=None,
            safe_error_message=None,
            evidence_digest=hashlib.sha256(b"v04-ui-settled").hexdigest(),
            actor="v04-browser-qualification",
            correlation_id=CORRELATION_ID,
            terminal_observed_at=datetime.now(timezone.utc),
        )
        changed = True
    if (
        operation["stage"] != "SETTLED"
        or operation["certainty"] != "EFFECT_CONFIRMED"
        or operation["disposition"] != "OK"
    ):
        raise RuntimeError("browser operation did not settle canonically")

    binding = repository.get_binding(BINDING_ID)["binding"]
    if binding["state"] != "ATTACHED" or binding["capacity_reserved"] is not True:
        raise RuntimeError("browser binding did not project canonically")
    return {
        "binding_id": BINDING_ID,
        "context_generation_id": CONTEXT_GENERATION_ID,
        "operation_id": OPERATION_ID,
        "status": "created" if changed else "existing",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL", ""))
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise ValueError("exact local synthetic confirmation is required")
    database_url = _local_database_url(args.database_url)
    engine, session_factory = create_database(database_url)
    try:
        result = seed(DriverRepository(session_factory))
    finally:
        engine.dispose()
    print(
        "fixture=" + result["status"]
        + " context_generation=" + result["context_generation_id"]
        + " binding=" + result["binding_id"]
        + " operation=" + result["operation_id"]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
