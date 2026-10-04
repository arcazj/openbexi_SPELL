from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from backend.database import create_database
from backend.driver_models import DriverAuditEvent, DriverContextGeneration, DriverHostGeneration
from backend.driver_repository import DEFAULT_PROFILE_ID, DriverRepository
from backend.tests.migration_support import run_migrations
from backend.tests.test_observation_repository import capabilities
from scripts import seed_dss_v19 as seed


@pytest.fixture
def repository(tmp_path):
    engine, sessions = create_database(f"sqlite:///{(tmp_path / 'dss-bootstrap.sqlite').as_posix()}")
    run_migrations(engine)
    repository = DriverRepository(sessions)
    repository.set_profile_enabled(DEFAULT_PROFILE_ID, True, expected_revision=0, actor="test", correlation_id="enable")
    ready_host(repository, "old-host")
    yield repository
    engine.dispose()


def ready_host(repository, identity):
    repository.create_host_generation(profile_id=DEFAULT_PROFILE_ID, host_generation_id=identity,
        contract_version="1.0", implementation_version="0.19.0-test", capabilities=capabilities(),
        actor="test", correlation_id=identity)
    repository.record_host_state(identity, "READY", expected_revision=0,
        actor="test", correlation_id=identity, observed_at=datetime.now(timezone.utc))
    return repository.get_driver(DEFAULT_PROFILE_ID)["driver"]


def test_bootstrap_actual_tuple_is_idempotent_and_operation_identity_is_host_bound(repository):
    driver = repository.get_driver(DEFAULT_PROFILE_ID)["driver"]
    context, digest = seed.ensure_context(repository, driver)
    again, repeated = seed.ensure_context(repository, driver)
    assert again == context and repeated == digest
    command = seed.open_command(driver, context, digest)
    assert command.identity.generations.context_generation == context["context_generation_id"]
    assert command.identity.generations.driver_host_generation == "old-host"
    assert command.configuration.expected_digest == digest
    assert seed.open_command(driver, again, digest).identity.operation_id == command.identity.operation_id


def test_failed_host_context_is_audited_and_replaced_without_rewriting_old_binding(repository):
    driver = repository.get_driver(DEFAULT_PROFILE_ID)["driver"]
    old, old_digest = seed.ensure_context(repository, driver)
    repository.record_context_state(old["context_generation_id"], "ACTIVE", expected_revision=0,
        actor="test", correlation_id="active", observed_at=datetime.now(timezone.utc))
    with repository.session_factory() as session:
        revision = session.get(DriverHostGeneration, "old-host").revision
    repository.record_host_state("old-host", "FAILED", expected_revision=revision,
        actor="test", correlation_id="lost-host", observed_at=datetime.now(timezone.utc))
    driver = ready_host(repository, "replacement-host")
    new, digest = seed.ensure_context(repository, driver)
    assert new["context_generation_id"] != old["context_generation_id"] and digest != old_digest
    assert new["generation_number"] == 2 and new["state"] == "OPENING"
    preserved = repository.get_context_generation("simulator", old["context_generation_id"])["context_generation"]
    assert preserved["host_generation_id"] == "old-host"
    assert preserved["configuration_digest"] == old_digest and preserved["state"] == "FAILED"
    with repository.session_factory() as session:
        events = session.scalars(select(DriverAuditEvent).where(DriverAuditEvent.actor == seed.ACTOR)).all()
        assert any(event.event_type == "driver.context_state_changed" and event.payload["state"] == "FAILED" for event in events)
    assert seed.ensure_context(repository, driver)[0] == new


@pytest.mark.parametrize("mutation", ["tuple", "live_host"])
def test_bootstrap_refuses_wrong_tuple_or_live_host_replacement(repository, mutation):
    driver = repository.get_driver(DEFAULT_PROFILE_ID)["driver"]
    context, digest = seed.ensure_context(repository, driver)
    if mutation == "tuple":
        with repository.session_factory() as session:
            session.get(DriverContextGeneration, context["context_generation_id"]).configuration_digest = "b" * 64
            session.commit()
    else:
        driver = {**driver, "current_host_generation_id": "unadmitted-other-host"}
    with pytest.raises(RuntimeError, match="fixed configuration|live host"):
        seed.ensure_context(repository, driver)
    with repository.session_factory() as session:
        assert len(session.scalars(select(DriverContextGeneration)).all()) == 1


@pytest.mark.parametrize("error", ["driver host generation revision conflict", "different authority conflict"])
def test_bootstrap_only_retries_bounded_host_revision_race(monkeypatch, tmp_path, error):
    import asyncio
    from backend.driver_repository import DriverConflictError
    calls = []
    runtime_key = tmp_path / "consumed-client.key"
    provisions = []
    def provision():
        assert not runtime_key.exists()
        runtime_key.write_bytes(b"test-only-placeholder")
        provisions.append(True)
    class Gateway:
        def __init__(self, *args): pass
        async def start(self):
            assert runtime_key.read_bytes() == b"test-only-placeholder"
            runtime_key.unlink()
            calls.append("start")
            if calls.count("start") < 3:
                raise DriverConflictError(error)
        async def close(self): calls.append("close")
    monkeypatch.setattr(seed, "DriverGateway", Gateway)
    monkeypatch.setattr(seed.legacy, "_ensure_runtime_credentials", provision)
    if error == "different authority conflict":
        with pytest.raises(DriverConflictError, match=error):
            asyncio.run(seed.start_gateway(None, None))
        assert calls == ["start", "close"]
    else:
        assert isinstance(asyncio.run(seed.start_gateway(None, None)), Gateway)
        assert calls == ["start", "close", "start", "close", "start"]
    assert len(provisions) == calls.count("start") and not runtime_key.exists()
