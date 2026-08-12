from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from backend.database import create_database
from backend.driver_domain import CAPABILITY_MATRIX
from backend.driver_repository import (
    DEFAULT_PROFILE_ID,
    CapabilitySpec,
    DriverRepository,
)
from backend.migrations import run_migrations
from scripts.seed_driver_projection_v04 import (
    BINDING_ID,
    CONTEXT_GENERATION_ID,
    CONTEXT_ID,
    OPERATION_ID,
    _local_database_url,
    seed,
)


def _uid(value: int) -> str:
    return str(UUID(int=value))


def _capabilities() -> tuple[CapabilitySpec, ...]:
    return tuple(
        CapabilitySpec(
            service=definition.service,
            method=definition.method.value,
            mutability=definition.mutability,
            modifiers=definition.modifiers,
            formats=(definition.format,),
            stream_support=definition.stream_support,
        )
        for definition in CAPABILITY_MATRIX
    )


def _ready_repository(database_path: Path) -> tuple[DriverRepository, object]:
    engine, session_factory = create_database(f"sqlite:///{database_path.as_posix()}")
    run_migrations(engine)
    repository = DriverRepository(session_factory)
    repository.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="pytest-browser-seed",
        correlation_id=_uid(1),
    )
    repository.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=_uid(2),
        contract_version="1.0",
        implementation_version="0.4.0-test",
        capabilities=_capabilities(),
        actor="pytest-browser-seed",
        correlation_id=_uid(3),
    )
    repository.record_host_state(
        _uid(2),
        "READY",
        expected_revision=0,
        actor="pytest-browser-seed",
        correlation_id=_uid(4),
        observed_at=datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc),
    )
    return repository, engine


def test_seed_creates_the_canonical_projection_and_is_idempotent(tmp_path: Path) -> None:
    repository, engine = _ready_repository(tmp_path / "browser-seed.db")
    try:
        assert seed(repository) == {
            "binding_id": BINDING_ID,
            "context_generation_id": CONTEXT_GENERATION_ID,
            "operation_id": OPERATION_ID,
            "status": "created",
        }
        assert seed(repository)["status"] == "existing"

        context = repository.get_context_generation(CONTEXT_ID, CONTEXT_GENERATION_ID)[
            "context_generation"
        ]
        binding = repository.get_binding(BINDING_ID)["binding"]
        operation = repository.get_operation(OPERATION_ID)["operation"]
        assert context["state"] == "ACTIVE"
        assert binding["state"] == "ATTACHED"
        assert operation["stage"] == "SETTLED"
        assert operation["certainty"] == "EFFECT_CONFIRMED"
        assert operation["disposition"] == "OK"
    finally:
        engine.dispose()


def test_seed_resumes_after_an_interrupted_operation_transition(tmp_path: Path) -> None:
    repository, engine = _ready_repository(tmp_path / "browser-seed-resume.db")

    class InterruptSettledTransition:
        def __init__(self, delegate: DriverRepository) -> None:
            self.delegate = delegate
            self.interrupted = False

        def __getattr__(self, name: str):
            return getattr(self.delegate, name)

        def append_operation_transition(self, *args, **kwargs):
            if kwargs.get("stage") == "SETTLED" and not self.interrupted:
                self.interrupted = True
                raise RuntimeError("synthetic qualification interruption")
            return self.delegate.append_operation_transition(*args, **kwargs)

    try:
        interrupted = InterruptSettledTransition(repository)
        with pytest.raises(RuntimeError, match="synthetic qualification interruption"):
            seed(interrupted)  # type: ignore[arg-type]
        assert seed(repository)["status"] == "created"
        assert seed(repository)["status"] == "existing"
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://spell:secret@example.com:5432/spell",
        "postgresql+psycopg://spell:secret@localhost:5432/production",
        "mysql://spell:secret@localhost:3306/spell",
    ],
)
def test_local_database_guard_rejects_nonqualification_targets(database_url: str) -> None:
    with pytest.raises(ValueError):
        _local_database_url(database_url)
