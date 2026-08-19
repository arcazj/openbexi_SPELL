from __future__ import annotations

import pytest

from backend.driver_repository import DriverNotFoundError
from scripts import seed_observation_v07 as seed


DRIVER = {
    "id": "local-synthetic-simulator",
    "server_profile_id": "bundled-deterministic-simulator",
    "current_host_generation_id": "host-generation-fixture",
    "configuration_digest": "a" * 64,
    "credential_epoch": 1,
    "ready": True,
}


class FixtureRepository:
    def __init__(self, context_id: str = seed.CONTEXT_ID) -> None:
        self.context_id = context_id
        self.context = None
        self.created: dict[str, object] | None = None

    def get_context_generation(self, context_id: str, generation_id: str):
        if self.context is None:
            raise DriverNotFoundError("fixture context is absent")
        assert context_id == self.context_id
        assert generation_id == seed.CONTEXT_GENERATION_ID
        return {"context_generation": self.context}

    def create_context_generation(self, **values):
        self.created = values
        self.context = {
            "host_generation_id": values["host_generation_id"],
            "configuration_digest": values["configuration_digest"],
            "state": "OPENING",
        }


def test_seed_builds_one_exact_real_driver_context_tuple() -> None:
    repository = FixtureRepository()
    context, digest = seed._ensure_context_projection(repository, DRIVER)
    command = seed._open_command(DRIVER, digest)

    assert context["state"] == "OPENING"
    assert repository.created == {
        "profile_id": "local-synthetic-simulator",
        "host_generation_id": "host-generation-fixture",
        "context_id": seed.CONTEXT_ID,
        "context_generation_id": seed.CONTEXT_GENERATION_ID,
        "configuration_schema_version": seed.CONTEXT_SCHEMA_VERSION,
        "configuration_digest": digest,
        "actor": "v07-browser-qualification",
        "correlation_id": seed.CORRELATION_ID,
    }
    assert command.identity.generations.context_id == seed.CONTEXT_ID
    assert command.identity.generations.context_generation == seed.CONTEXT_GENERATION_ID
    assert command.identity.generations.context_binding_digest == digest
    assert command.configuration.expected_digest == digest

    for release_context_id in (
        "v08-telemetry-synthetic-context",
        "v09-telemetry-synthetic-context",
    ):
        assert release_context_id in seed.SUPPORTED_CONTEXT_IDS
        release_repository = FixtureRepository(release_context_id)
        release_context, release_digest = seed._ensure_context_projection(
            release_repository,
            DRIVER,
            context_id=release_context_id,
        )
        release_command = seed._open_command(
            DRIVER,
            release_digest,
            context_id=release_context_id,
        )
        assert release_context["state"] == "OPENING"
        assert release_repository.created is not None
        assert release_repository.created["context_id"] == release_context_id
        assert release_command.identity.generations.context_id == release_context_id


def test_seed_rejects_a_conflicting_persisted_context() -> None:
    repository = FixtureRepository()
    repository.context = {
        "host_generation_id": "different-host-generation",
        "configuration_digest": "b" * 64,
        "state": "ACTIVE",
    }
    with pytest.raises(RuntimeError, match="context differs"):
        seed._ensure_context_projection(repository, DRIVER)


def test_seed_cli_requires_exact_local_confirmation() -> None:
    with pytest.raises(ValueError, match="exact local synthetic confirmation"):
        seed.main(["--confirm", "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"])
    with pytest.raises(ValueError, match="supported telemetry context identity"):
        seed.main(
            [
                "--confirm",
                seed.CONFIRMATION,
                "--context-id",
                "telemetry-synthetic-context",
            ]
        )
