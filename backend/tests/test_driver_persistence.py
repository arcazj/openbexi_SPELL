from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import func, inspect, select

from spell.driver.configuration import canonical_configuration_digest

from backend.database import create_database
from backend.driver_domain import CAPABILITY_MATRIX
from backend.driver_models import (
    DriverAuditEvent,
    DriverBinding,
    DriverContextGeneration,
    DriverHostGeneration,
    DriverOperation,
    DriverOperationAttempt,
    DriverOperationTransition,
    DriverOutboxEvent,
    DriverProfile,
)
from backend.driver_repository import (
    ALL_RPC_METHODS,
    BindingStateObservation,
    CapabilitySpec,
    ContextStateObservation,
    DEFAULT_PROFILE_DIGEST,
    DEFAULT_PROFILE_ID,
    DriverConflictError,
    DriverNotFoundError,
    DriverRepository,
    DriverValidationError,
)
from backend.tests.migration_support import run_migrations


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def uid(value: int) -> str:
    return str(UUID(int=value))


def exact_capabilities() -> tuple[CapabilitySpec, ...]:
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


@pytest.fixture
def repository(tmp_path: Path):
    engine, session_factory = create_database(
        f"sqlite:///{(tmp_path / 'driver-persistence.db').as_posix()}"
    )
    run_migrations(engine)
    try:
        yield DriverRepository(session_factory), session_factory
    finally:
        engine.dispose()


def enable_and_start_host(repository: DriverRepository, host_id: str = uid(1)) -> str:
    repository.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="pytest-service-manager",
        correlation_id=uid(900),
    )
    repository.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        contract_version="1.0",
        implementation_version="0.4.0-test",
        capabilities=exact_capabilities(),
        actor="pytest-service-manager",
        correlation_id=uid(901),
    )
    repository.record_host_state(
        host_id,
        "READY",
        expected_revision=0,
        actor="pytest-service-manager",
        correlation_id=uid(902),
        observed_at=NOW,
    )
    return host_id


def test_default_profile_is_disabled_and_bound_to_canonical_typed_configuration(
    repository,
) -> None:
    repo, session_factory = repository
    expected_material = {
        "configuration_schema_version": "spell.driver.host-profile/1",
        "contract_package": "spell.driver.v1",
        "credential_reference": "local-v04-driver-mtls",
        "journal_max_bytes": 16_777_216,
        "journal_max_entries": 10_000,
        "logical_driver_id": "bundled-deterministic-simulator",
        "max_attachments_per_context": 1,
        "max_contexts_per_host": 1,
        "max_lifecycle_operations_per_context": 8,
        "max_lifecycle_operations_per_host": 8,
        "server_profile_id": "local-synthetic",
        "simulator": True,
    }
    digest = hashlib.sha256(
        json.dumps(expected_material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert digest == DEFAULT_PROFILE_DIGEST

    body = repo.get_driver(DEFAULT_PROFILE_ID)["driver"]
    assert body == {
        "id": DEFAULT_PROFILE_ID,
        "server_profile_id": "local-synthetic",
        "logical_driver_id": "bundled-deterministic-simulator",
        "simulator": True,
        "enabled": False,
        "current_host_generation_id": None,
        "host_generation_number": None,
        "state": "DISABLED",
        "ready": False,
        "contract_package": "spell.driver.v1",
        "contract_version": None,
        "implementation_version": None,
        "configuration_schema_version": "spell.driver.host-profile/1",
        "configuration_digest": DEFAULT_PROFILE_DIGEST,
        "credential_epoch": 1,
        "capabilities": [],
        "capacity": {
            "max_contexts_per_host": 1,
            "contexts_in_use": 0,
            "max_attachments_per_context": 1,
            "max_lifecycle_operations_per_host": 8,
            "lifecycle_operations_per_host_in_use": 0,
            "max_lifecycle_operations_per_context": 8,
        },
        "last_observed_at": None,
        "revision": 0,
    }
    with session_factory() as session:
        profile = session.get(DriverProfile, DEFAULT_PROFILE_ID)
        assert profile is not None and profile.enabled is False
        assert profile.configuration_digest == digest
        profile_columns = {
            item["name"]: item for item in inspect(session.get_bind()).get_columns("driver_profiles")
        }
        assert profile_columns["id"]["type"].length == 128
        assert profile_columns["server_profile_id"]["type"].length == 128
        assert session.scalar(select(func.count()).select_from(DriverAuditEvent)) == 0
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == 0

    with pytest.raises(DriverNotFoundError):
        repo.get_driver("a" * 128)
    with pytest.raises(DriverValidationError, match="bounded identifier"):
        repo.get_driver("a" * 129)

    enabled = repo.configure_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        actor="pytest-startup",
        correlation_id=uid(90),
    )["driver"]
    assert enabled["enabled"] is True and enabled["revision"] == 1
    unchanged = repo.configure_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        actor="pytest-startup",
        correlation_id=uid(91),
    )["driver"]
    assert unchanged["revision"] == 1
    disabled = repo.configure_profile_enabled(
        DEFAULT_PROFILE_ID,
        False,
        actor="pytest-startup",
        correlation_id=uid(92),
    )["driver"]
    assert disabled["enabled"] is False and disabled["revision"] == 2
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverAuditEvent)) == 2
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == 2


def test_credential_rotation_is_fenced_source_bound_and_atomically_audited(
    repository,
) -> None:
    repo, session_factory = repository

    rotated = repo.rotate_profile_credentials(
        DEFAULT_PROFILE_ID,
        credential_reference="local-v04-driver-mtls",
        credential_epoch=2,
        configuration_digest=DEFAULT_PROFILE_DIGEST,
        expected_revision=0,
        actor="pytest-service-manager",
        correlation_id=uid(93),
    )
    assert rotated["credential_epoch"] == 2
    assert rotated["configuration_digest"] == DEFAULT_PROFILE_DIGEST
    assert rotated["revision"] == 1

    with session_factory() as session:
        audits = session.scalars(select(DriverAuditEvent)).all()
        outbox = session.scalars(select(DriverOutboxEvent)).all()
        assert len(audits) == len(outbox) == 1
        assert audits[0].event_type == "driver.profile_credentials_rotated"
        assert audits[0].payload["prior_credential_epoch"] == 1
        assert audits[0].payload["credential_epoch"] == 2
        assert outbox[0].payload["correlation_id"] == uid(93)

    with pytest.raises(DriverConflictError, match="exactly one"):
        repo.rotate_profile_credentials(
            DEFAULT_PROFILE_ID,
            credential_reference="local-v04-driver-mtls",
            credential_epoch=4,
            configuration_digest=DEFAULT_PROFILE_DIGEST,
            expected_revision=1,
            actor="pytest-service-manager",
            correlation_id=uid(94),
        )
    with pytest.raises(DriverValidationError, match="does not bind"):
        repo.rotate_profile_credentials(
            DEFAULT_PROFILE_ID,
            credential_reference="local-v04-driver-mtls-next",
            credential_epoch=3,
            configuration_digest=DEFAULT_PROFILE_DIGEST,
            expected_revision=1,
            actor="pytest-service-manager",
            correlation_id=uid(95),
        )

    material = {
        "configuration_schema_version": "spell.driver.host-profile/1",
        "contract_package": "spell.driver.v1",
        "credential_reference": "local-v04-driver-mtls-next",
        "journal_max_bytes": 16_777_216,
        "journal_max_entries": 10_000,
        "logical_driver_id": "bundled-deterministic-simulator",
        "max_attachments_per_context": 1,
        "max_contexts_per_host": 1,
        "max_lifecycle_operations_per_context": 8,
        "max_lifecycle_operations_per_host": 8,
        "server_profile_id": "local-synthetic",
        "simulator": True,
    }
    changed_digest = canonical_configuration_digest(material)
    changed = repo.rotate_profile_credentials(
        DEFAULT_PROFILE_ID,
        credential_reference="local-v04-driver-mtls-next",
        credential_epoch=3,
        configuration_digest=changed_digest,
        expected_revision=1,
        actor="pytest-service-manager",
        correlation_id=uid(96),
    )
    assert changed["credential_epoch"] == 3
    assert changed["credential_reference"] == "local-v04-driver-mtls-next"
    assert changed["configuration_digest"] == changed_digest


def test_credential_rotation_refuses_an_unfenced_host_generation(repository) -> None:
    repo, _ = repository
    host_id = enable_and_start_host(repo)
    profile = repo.get_profile_configuration(DEFAULT_PROFILE_ID)

    with pytest.raises(DriverConflictError, match="terminal before rotation"):
        repo.rotate_profile_credentials(
            DEFAULT_PROFILE_ID,
            credential_reference="local-v04-driver-mtls",
            credential_epoch=2,
            configuration_digest=DEFAULT_PROFILE_DIGEST,
            expected_revision=profile["revision"],
            actor="pytest-service-manager",
            correlation_id=uid(97),
        )

    host = repo.get_driver(DEFAULT_PROFILE_ID)["driver"]
    repo.record_host_state(
        host_id,
        "FAILED",
        expected_revision=host["revision"],
        actor="pytest-service-manager",
        correlation_id=uid(98),
        observed_at=NOW,
    )
    rotated = repo.rotate_profile_credentials(
        DEFAULT_PROFILE_ID,
        credential_reference="local-v04-driver-mtls",
        credential_epoch=2,
        configuration_digest=DEFAULT_PROFILE_DIGEST,
        expected_revision=profile["revision"],
        actor="pytest-service-manager",
        correlation_id=uid(99),
    )
    assert rotated["credential_epoch"] == 2


def test_host_requires_enabled_profile_and_exact_nine_rpc_capabilities(repository) -> None:
    repo, session_factory = repository
    with pytest.raises(DriverConflictError, match="disabled"):
        repo.create_host_generation(
            profile_id=DEFAULT_PROFILE_ID,
            host_generation_id=uid(1),
            contract_version="1.0",
            implementation_version="0.4.0-test",
            capabilities=exact_capabilities(),
            actor="pytest",
            correlation_id=uid(100),
        )

    repo.set_profile_enabled(
        DEFAULT_PROFILE_ID,
        True,
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(101),
    )
    with pytest.raises(DriverValidationError, match="exactly nine"):
        repo.create_host_generation(
            profile_id=DEFAULT_PROFILE_ID,
            host_generation_id=uid(1),
            contract_version="1.0",
            implementation_version="0.4.0-test",
            capabilities=exact_capabilities()[:-1],
            actor="pytest",
            correlation_id=uid(102),
        )

    wrong_matrix = list(exact_capabilities())
    first = wrong_matrix[0]
    wrong_matrix[0] = CapabilitySpec(
        service="CONTEXT_LIFECYCLE",
        method=first.method,
        mutability=first.mutability,
        modifiers=first.modifiers,
        formats=first.formats,
        stream_support=first.stream_support,
    )
    with pytest.raises(DriverValidationError, match="approved matrix"):
        repo.create_host_generation(
            profile_id=DEFAULT_PROFILE_ID,
            host_generation_id=uid(1),
            contract_version="1.0",
            implementation_version="0.4.0-test",
            capabilities=wrong_matrix,
            actor="pytest",
            correlation_id=uid(105),
        )

    host = repo.create_host_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=uid(1),
        contract_version="1.0",
        implementation_version="0.4.0-test",
        capabilities=reversed(exact_capabilities()),
        actor="pytest",
        correlation_id=uid(103),
    )
    assert host.state == "STARTING" and not host.ready
    host = repo.record_host_state(
        host.id,
        "READY",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(104),
        observed_at=NOW,
    )
    assert host.state == "READY" and host.ready and host.revision == 1
    projection = repo.get_driver(DEFAULT_PROFILE_ID)["driver"]
    assert projection["current_host_generation_id"] == uid(1)
    assert [item["method"] for item in projection["capabilities"]] == sorted(
        ALL_RPC_METHODS
    )
    assert projection["capabilities"] == sorted(
        (
            {
                "service": definition.service,
                "method": definition.method.value,
                "modifiers": list(definition.modifiers),
                "formats": [definition.format],
                "mutability": definition.mutability,
                "stream_support": definition.stream_support,
            }
            for definition in CAPABILITY_MATRIX
        ),
        key=lambda item: item["method"],
    )
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverAuditEvent)) == 3
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == 3


def test_context_binding_generations_release_capacity_only_after_cleanup(repository) -> None:
    repo, _ = repository
    host_id = enable_and_start_host(repo)
    context_generation_id = uid(10)
    context = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id="synthetic-context",
        context_generation_id=context_generation_id,
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="a" * 64,
        actor="pytest",
        correlation_id=uid(110),
    )
    assert context.state == "OPENING"
    with pytest.raises(DriverConflictError, match="capacity"):
        repo.create_context_generation(
            profile_id=DEFAULT_PROFILE_ID,
            host_generation_id=host_id,
            context_id="second-context",
            context_generation_id=uid(11),
            configuration_schema_version="spell.driver.context-profile/1",
            configuration_digest="b" * 64,
            actor="pytest",
            correlation_id=uid(111),
        )
    context = repo.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(112),
        observed_at=NOW,
    )
    binding = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(20),
        execution_id="synthetic-execution",
        attachment_generation_id=uid(21),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="b" * 64,
        actor="pytest",
        correlation_id=uid(113),
    )
    assert repo.get_binding(binding.id)["binding"]["latest_operation_id"] is None
    attachment_operation_id = uid(24)
    attachment_attempt_id = uid(25)
    repo.accept_operation(
        operation_id=attachment_operation_id,
        attempt_id=attachment_attempt_id,
        method="AttachExecution",
        request_digest="d" * 64,
        effect_class="EXECUTION_ATTACH",
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=binding.id,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(118),
        deadline_at=NOW + timedelta(seconds=5),
    )
    context_projection = repo.get_context_generation(
        "synthetic-context", context_generation_id
    )["context_generation"]
    assert context_projection["capacity"]["lifecycle_operations_in_use"] == 1
    dispatched = repo.append_operation_transition(
        attachment_operation_id,
        attachment_attempt_id,
        expected_revision=0,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="4" * 64,
        actor="pytest",
        correlation_id=uid(119),
    )
    repo.append_operation_transition(
        attachment_operation_id,
        attachment_attempt_id,
        expected_revision=dispatched["revision"],
        stage="SETTLED",
        certainty="EFFECT_CONFIRMED",
        disposition="OK",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="5" * 64,
        actor="pytest",
        correlation_id=uid(120),
        terminal_observed_at=NOW,
    )
    context_projection = repo.get_context_generation(
        "synthetic-context", context_generation_id
    )["context_generation"]
    assert context_projection["capacity"]["lifecycle_operations_in_use"] == 0
    binding_projection = repo.get_binding(binding.id)["binding"]
    assert binding_projection["state"] == "ATTACHED"
    assert binding_projection["revision"] == 1
    assert binding_projection["latest_operation_id"] == attachment_operation_id
    listed_binding = next(
        item
        for item in repo.list_bindings()["items"]
        if item["driver_binding_id"] == binding.id
    )
    assert listed_binding["latest_operation_id"] == attachment_operation_id
    with pytest.raises(DriverConflictError, match="capacity"):
        repo.create_binding(
            context_generation_id=context.id,
            driver_binding_id=uid(22),
            execution_id="another-execution",
            attachment_generation_id=uid(23),
            configuration_schema_version="spell.driver.attachment-profile/1",
            configuration_digest="c" * 64,
            actor="pytest",
            correlation_id=uid(115),
        )
    binding = repo.record_binding_state(
        binding.id,
        "DETACHING",
        expected_revision=1,
        actor="pytest",
        correlation_id=uid(116),
        observed_at=NOW,
    )
    binding = repo.record_binding_state(
        binding.id,
        "DETACHED",
        expected_revision=2,
        actor="pytest",
        correlation_id=uid(117),
        observed_at=NOW,
    )
    assert binding.detached_at is not None
    context_projection = repo.get_context_generation(
        "synthetic-context", context_generation_id
    )["context_generation"]
    assert context_projection["capacity"]["attachments_in_use"] == 0
    binding_projection = repo.get_binding(binding.id)["binding"]
    assert binding_projection["state"] == "DETACHED"
    assert "credential_reference" not in binding_projection


@pytest.mark.parametrize("observation_path", ("direct", "health"))
def test_failed_binding_releases_capacity_once_and_retains_reload_fence(
    repository, observation_path: str
) -> None:
    repo, _ = repository
    host_id = enable_and_start_host(repo)
    context = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id=f"failed-{observation_path}-context",
        context_generation_id=uid(600),
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="a" * 64,
        actor="pytest",
        correlation_id=uid(601),
    )
    context = repo.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(602),
        observed_at=NOW,
    )
    owner = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(603),
        execution_id=f"failed-{observation_path}-execution",
        attachment_generation_id=uid(604),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="b" * 64,
        actor="pytest",
        correlation_id=uid(605),
    )
    owner = repo.record_binding_state(
        owner.id,
        "ATTACHED",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(606),
        observed_at=NOW,
    )
    pending = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(607),
        execution_id=owner.execution_id,
        attachment_generation_id=uid(608),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="c" * 64,
        actor="pytest",
        correlation_id=uid(609),
        replaces_driver_binding_id=owner.id,
    )
    before = repo.get_context_generation(context.context_id, context.id)[
        "context_generation"
    ]
    assert before["capacity"]["attachments_in_use"] == 1

    if observation_path == "direct":
        failed = repo.record_binding_state(
            owner.id,
            "FAILED",
            expected_revision=1,
            actor="pytest",
            correlation_id=uid(610),
            observed_at=NOW + timedelta(seconds=1),
        )
        repo.record_binding_state(
            owner.id,
            "FAILED",
            expected_revision=failed.revision,
            actor="pytest",
            correlation_id=uid(611),
            observed_at=NOW + timedelta(seconds=2),
        )
    else:
        def apply_failed_snapshot(observed_at: datetime) -> None:
            driver = repo.get_driver(DEFAULT_PROFILE_ID)["driver"]
            stored_context = repo.get_context_generation(
                context.context_id, context.id
            )["context_generation"]
            stored_owner = repo.get_binding(owner.id)["binding"]
            stored_pending = repo.get_binding(pending.id)["binding"]
            repo.apply_health_snapshot(
                host_id,
                "READY",
                expected_revision=int(driver["revision"]),
                observed_at=observed_at,
                contexts=(
                    ContextStateObservation(
                        context_generation_id=context.id,
                        state="ACTIVE",
                        expected_revision=int(stored_context["revision"]),
                        observed_at=observed_at,
                    ),
                ),
                bindings=(
                    BindingStateObservation(
                        driver_binding_id=owner.id,
                        state="FAILED",
                        expected_revision=int(stored_owner["revision"]),
                        observed_at=observed_at,
                    ),
                    BindingStateObservation(
                        driver_binding_id=pending.id,
                        state="FAILED",
                        expected_revision=int(stored_pending["revision"]),
                        observed_at=observed_at,
                    ),
                ),
                actor="pytest",
                correlation_id=uid(612),
            )

        apply_failed_snapshot(NOW + timedelta(seconds=1))
        apply_failed_snapshot(NOW + timedelta(seconds=2))

    stored_context = repo.get_context_generation(context.context_id, context.id)[
        "context_generation"
    ]
    stored_owner = repo.get_binding(owner.id)["binding"]
    stored_pending = repo.get_binding(pending.id)["binding"]
    assert stored_context["capacity"]["attachments_in_use"] == 0
    assert stored_owner["state"] == "FAILED"
    assert stored_owner["capacity_reserved"] is False
    assert stored_pending["capacity_reserved"] is False
    assert stored_pending["replacement_pending"] is True

    with pytest.raises(DriverConflictError, match="unresolved reload"):
        repo.accept_operation(
            operation_id=uid(613),
            attempt_id=uid(614),
            method="CloseContext",
            request_digest="d" * 64,
            effect_class="CONTEXT_CLOSE",
            host_generation_id=host_id,
            context_generation_id=context.id,
            driver_binding_id=None,
            target_operation_id=None,
            target_attempt_id=None,
            actor="pytest",
            correlation_id=uid(615),
            deadline_at=NOW + timedelta(seconds=10),
        )
    after_rejection = repo.get_context_generation(context.context_id, context.id)[
        "context_generation"
    ]
    assert after_rejection["capacity"]["attachments_in_use"] == 0
    assert after_rejection["capacity"]["lifecycle_operations_in_use"] == 0
    assert repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"][
        "lifecycle_operations_per_host_in_use"
    ] == 0


def test_operation_history_is_idempotent_fenced_and_retries_only_after_no_effect(
    repository,
) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    operation_id = uid(30)
    attempt_id = uid(31)
    accepted = repo.accept_operation(
        operation_id=operation_id,
        attempt_id=attempt_id,
        method="DrainHost",
        request_digest="c" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest-supervisor",
        correlation_id=uid(130),
        deadline_at=NOW + timedelta(seconds=5),
    )
    assert accepted["stage"] == "ACCEPTED"
    assert accepted["certainty"] == "NO_EFFECT"
    assert (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"]
        ["lifecycle_operations_per_host_in_use"]
        == 1
    )
    duplicate = repo.accept_operation(
        operation_id=operation_id,
        attempt_id=attempt_id,
        method="DrainHost",
        request_digest="c" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest-supervisor",
        correlation_id=uid(130),
        deadline_at=NOW + timedelta(seconds=5),
    )
    assert duplicate == accepted
    with pytest.raises(DriverConflictError, match="conflicting immutable intent"):
        repo.accept_operation(
            operation_id=operation_id,
            attempt_id=uid(32),
            method="DrainHost",
            request_digest="d" * 64,
            effect_class="HOST_DRAIN",
            host_generation_id=host_id,
            context_generation_id=None,
            driver_binding_id=None,
            target_operation_id=None,
            target_attempt_id=None,
            actor="pytest-supervisor",
            correlation_id=uid(131),
            deadline_at=NOW + timedelta(seconds=5),
        )

    dispatched = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=0,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="1" * 64,
        actor="pytest-supervisor",
        correlation_id=uid(132),
    )
    reconciling = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=dispatched["revision"],
        stage="RECONCILING",
        certainty="EFFECT_POSSIBLE",
        disposition="RESPONSE_LOST",
        safe_error_code="UNAVAILABLE",
        safe_error_message="driver response unavailable",
        evidence_digest="2" * 64,
        actor="pytest-supervisor",
        correlation_id=uid(133),
    )
    assert reconciling["requires_reconciliation"] is True
    assert reconciling["capacity_reserved"] is False
    assert operation_id in repo.list_reconciliation_operation_ids()["items"]
    assert (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"]
        ["lifecycle_operations_per_host_in_use"]
        == 0
    )
    with pytest.raises(DriverConflictError, match="authoritative NO_EFFECT"):
        repo.authorize_retry(
            operation_id,
            expected_revision=reconciling["revision"],
            new_attempt_id=uid(32),
            host_generation_id=host_id,
            context_generation_id=None,
            driver_binding_id=None,
            deadline_at=NOW + timedelta(seconds=10),
            actor="pytest-supervisor",
            correlation_id=uid(134),
        )

    no_effect = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=reconciling["revision"],
        stage="RECONCILING",
        certainty="NO_EFFECT",
        disposition="CONFLICT",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="3" * 64,
        actor="pytest-reconciler",
        correlation_id=uid(135),
    )
    assert no_effect["requires_reconciliation"] is True
    assert no_effect["capacity_reserved"] is False
    assert operation_id in repo.list_reconciliation_operation_ids()["items"]
    assert (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"]
        ["lifecycle_operations_per_host_in_use"]
        == 0
    )
    settled_no_effect = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=no_effect["revision"],
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="CONFLICT",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="3" * 64,
        actor="pytest-reconciler",
        correlation_id=uid(136),
        terminal_observed_at=NOW,
    )
    assert settled_no_effect["requires_reconciliation"] is False
    assert operation_id not in repo.list_reconciliation_operation_ids()["items"]
    assert (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"]
        ["lifecycle_operations_per_host_in_use"]
        == 0
    )
    retried = repo.authorize_retry(
        operation_id,
        expected_revision=settled_no_effect["revision"],
        new_attempt_id=uid(32),
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        deadline_at=NOW + timedelta(seconds=10),
        actor="pytest-supervisor",
        correlation_id=uid(137),
    )
    assert retried["current_attempt_number"] == 2
    assert retried["current_attempt_id"] == uid(32)
    assert [item["attempt_number"] for item in retried["attempts"]] == [1, 2]
    assert [item["sequence"] for item in retried["transitions"]] == [1, 2, 3, 4, 5, 1]
    assert retried["stage"] == "ACCEPTED" and retried["certainty"] == "NO_EFFECT"
    assert (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"]
        ["lifecycle_operations_per_host_in_use"]
        == 1
    )
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverOperation)) == 1
        assert session.scalar(select(func.count()).select_from(DriverOperationAttempt)) == 2
        assert (
            session.scalar(select(func.count()).select_from(DriverOperationTransition))
            == 6
        )
        operation_events = session.scalar(
            select(func.count())
            .select_from(DriverAuditEvent)
            .where(DriverAuditEvent.operation_id == operation_id)
        )
        outbox_events = session.scalar(
            select(func.count())
            .select_from(DriverOutboxEvent)
            .where(DriverOutboxEvent.aggregate_id == operation_id)
        )
        assert operation_events == outbox_events == 6


def test_competing_reconciliation_commits_one_authoritative_public_result(
    repository,
) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    operation_id = uid(40)
    attempt_id = uid(41)
    accepted = repo.accept_operation(
        operation_id=operation_id,
        attempt_id=attempt_id,
        method="DrainHost",
        request_digest="e" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest-api",
        correlation_id=uid(140),
        deadline_at=NOW + timedelta(seconds=5),
    )
    dispatched = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=int(accepted["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="4" * 64,
        actor="pytest-gateway",
        correlation_id=uid(141),
    )
    reconciling = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=int(dispatched["revision"]),
        stage="RECONCILING",
        certainty="EFFECT_POSSIBLE",
        disposition="RESPONSE_LOST",
        safe_error_code="UNAVAILABLE",
        safe_error_message="driver response unavailable",
        evidence_digest="5" * 64,
        actor="pytest-gateway",
        correlation_id=uid(142),
    )
    barrier = Barrier(2)

    def settle(certainty: str, disposition: str, correlation: str) -> object:
        barrier.wait(timeout=5)
        try:
            return repo.append_operation_transition(
                operation_id,
                attempt_id,
                expected_revision=int(reconciling["revision"]),
                stage="SETTLED",
                certainty=certainty,
                disposition=disposition,
                safe_error_code=None,
                safe_error_message=None,
                evidence_digest="6" * 64,
                actor="pytest-reconciler",
                correlation_id=correlation,
                terminal_observed_at=NOW,
            )
        except DriverConflictError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(
            pool.map(
                lambda values: settle(*values),
                (
                    ("NO_EFFECT", "CONFLICT", uid(143)),
                    ("EFFECT_CONFIRMED", "OK", uid(144)),
                ),
            )
        )

    assert sum(isinstance(item, DriverConflictError) for item in results) == 1
    authoritative = repo.get_operation(operation_id)["operation"]
    assert authoritative["stage"] == "SETTLED"
    assert authoritative["certainty"] in {"NO_EFFECT", "EFFECT_CONFIRMED"}
    assert authoritative["disposition"] in {"CONFLICT", "OK"}
    assert authoritative["requires_reconciliation"] is False
    assert len(authoritative["attempts"]) == 1
    assert [item["sequence"] for item in authoritative["transitions"]] == [1, 2, 3, 4]
    with session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(DriverOperationTransition)
            .where(DriverOperationTransition.operation_id == operation_id)
        ) == 4


def test_host_lifecycle_capacity_fails_closed_before_acceptance(repository) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    for offset in range(8):
        repo.accept_operation(
            operation_id=uid(200 + offset),
            attempt_id=uid(300 + offset),
            method="DrainHost",
            request_digest=f"{offset:x}" * 64,
            effect_class="HOST_DRAIN",
            host_generation_id=host_id,
            context_generation_id=None,
            driver_binding_id=None,
            target_operation_id=None,
            target_attempt_id=None,
            actor="pytest",
            correlation_id=uid(400 + offset),
            deadline_at=NOW + timedelta(seconds=5),
        )

    with pytest.raises(DriverConflictError, match="capacity is exhausted"):
        repo.accept_operation(
            operation_id=uid(208),
            attempt_id=uid(308),
            method="DrainHost",
            request_digest="f" * 64,
            effect_class="HOST_DRAIN",
            host_generation_id=host_id,
            context_generation_id=None,
            driver_binding_id=None,
            target_operation_id=None,
            target_attempt_id=None,
            actor="pytest",
            correlation_id=uid(408),
            deadline_at=NOW + timedelta(seconds=5),
        )
    assert (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"]
        ["lifecycle_operations_per_host_in_use"]
        == 8
    )
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverOperation)) == 8


def test_transition_and_outbox_are_atomic_on_persistence_failure(
    repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    operation_id = uid(40)
    attempt_id = uid(41)
    repo.accept_operation(
        operation_id=operation_id,
        attempt_id=attempt_id,
        method="DrainHost",
        request_digest="e" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(140),
        deadline_at=NOW + timedelta(seconds=5),
    )
    with session_factory() as session:
        audit_before = session.scalar(select(func.count()).select_from(DriverAuditEvent))
        outbox_before = session.scalar(select(func.count()).select_from(DriverOutboxEvent))

    def fail_event(*_args, **_kwargs) -> None:
        raise RuntimeError("forced outbox failure")

    monkeypatch.setattr(repo, "_record_operation_event", fail_event)
    with pytest.raises(RuntimeError, match="forced outbox failure"):
        repo.append_operation_transition(
            operation_id,
            attempt_id,
            expected_revision=0,
            stage="DISPATCHED",
            certainty="EFFECT_POSSIBLE",
            disposition=None,
            safe_error_code=None,
            safe_error_message=None,
            evidence_digest="4" * 64,
            actor="pytest",
            correlation_id=uid(141),
        )

    snapshot = repo.get_operation(operation_id)["operation"]
    assert snapshot["stage"] == "ACCEPTED"
    assert snapshot["revision"] == 0
    assert len(snapshot["transitions"]) == 1
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverAuditEvent)) == audit_before
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == outbox_before


def test_terminal_projection_rolls_back_resources_counters_and_events(
    repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    context = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id="rollback-context",
        context_generation_id=uid(410),
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="a" * 64,
        actor="pytest",
        correlation_id=uid(411),
    )
    context = repo.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(412),
        observed_at=NOW,
    )
    binding = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(413),
        execution_id="rollback-execution",
        attachment_generation_id=uid(414),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="b" * 64,
        actor="pytest",
        correlation_id=uid(415),
    )
    binding = repo.record_binding_state(
        binding.id,
        "ATTACHED",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(416),
        observed_at=NOW,
    )
    operation_id = uid(417)
    attempt_id = uid(418)
    accepted = repo.accept_operation(
        operation_id=operation_id,
        attempt_id=attempt_id,
        method="CloseContext",
        request_digest="c" * 64,
        effect_class="CONTEXT_CLOSE",
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(419),
        deadline_at=NOW + timedelta(seconds=5),
    )
    dispatched = repo.append_operation_transition(
        operation_id,
        attempt_id,
        expected_revision=int(accepted["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="d" * 64,
        actor="pytest",
        correlation_id=uid(420),
    )
    before = (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"],
        repo.get_context_generation("rollback-context", context.id)[
            "context_generation"
        ],
        repo.get_binding(binding.id)["binding"],
        repo.get_operation(operation_id)["operation"],
    )
    with session_factory() as session:
        audit_before = session.scalar(select(func.count()).select_from(DriverAuditEvent))
        outbox_before = session.scalar(select(func.count()).select_from(DriverOutboxEvent))

    original_record_event = repo._record_event
    event_calls = 0

    def fail_after_partial_event_write(*args, **kwargs) -> None:
        nonlocal event_calls
        event_calls += 1
        original_record_event(*args, **kwargs)
        if event_calls == 2:
            raise RuntimeError("forced later projection event failure")

    monkeypatch.setattr(repo, "_record_event", fail_after_partial_event_write)
    with pytest.raises(RuntimeError, match="later projection event failure"):
        repo.append_operation_transition(
            operation_id,
            attempt_id,
            expected_revision=int(dispatched["revision"]),
            stage="SETTLED",
            certainty="EFFECT_CONFIRMED",
            disposition="INTERNAL",
            safe_error_code="HOOK",
            safe_error_message="cleanup completed with a bounded failure",
            evidence_digest="e" * 64,
            actor="pytest",
            correlation_id=uid(421),
            terminal_observed_at=NOW,
        )

    after = (
        repo.get_driver(DEFAULT_PROFILE_ID)["driver"],
        repo.get_context_generation("rollback-context", context.id)[
            "context_generation"
        ],
        repo.get_binding(binding.id)["binding"],
        repo.get_operation(operation_id)["operation"],
    )
    assert after == before
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverAuditEvent)) == audit_before
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == outbox_before


def test_no_effect_terminal_projection_releases_provisional_resources(repository) -> None:
    repo, _ = repository
    host_id = enable_and_start_host(repo)
    context = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id="no-effect-open",
        context_generation_id=uid(430),
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="a" * 64,
        actor="pytest",
        correlation_id=uid(431),
    )
    accepted = repo.accept_operation(
        operation_id=uid(432),
        attempt_id=uid(433),
        method="OpenContext",
        request_digest="b" * 64,
        effect_class="CONTEXT_OPEN",
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(434),
        deadline_at=NOW + timedelta(seconds=5),
    )
    settled = repo.append_operation_transition(
        uid(432),
        uid(433),
        expected_revision=int(accepted["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="DEADLINE_EXCEEDED",
        safe_error_code="DEADLINE",
        safe_error_message="request expired before dispatch",
        evidence_digest=None,
        actor="pytest",
        correlation_id=uid(434),
        terminal_observed_at=NOW,
    )
    closed = repo.get_context_generation("no-effect-open", context.id)[
        "context_generation"
    ]
    driver = repo.get_driver(DEFAULT_PROFILE_ID)["driver"]
    assert settled["stage"] == "SETTLED"
    assert closed["state"] == "CLOSED"
    assert closed["capacity"]["lifecycle_operations_in_use"] == 0
    assert driver["capacity"]["contexts_in_use"] == 0

    active = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id="no-effect-attach",
        context_generation_id=uid(435),
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="c" * 64,
        actor="pytest",
        correlation_id=uid(436),
    )
    active = repo.record_context_state(
        active.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(437),
        observed_at=NOW,
    )
    binding = repo.create_binding(
        context_generation_id=active.id,
        driver_binding_id=uid(438),
        execution_id="no-effect-execution",
        attachment_generation_id=uid(439),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="d" * 64,
        actor="pytest",
        correlation_id=uid(440),
    )
    accepted = repo.accept_operation(
        operation_id=uid(441),
        attempt_id=uid(442),
        method="AttachExecution",
        request_digest="e" * 64,
        effect_class="EXECUTION_ATTACH",
        host_generation_id=host_id,
        context_generation_id=active.id,
        driver_binding_id=binding.id,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(443),
        deadline_at=NOW + timedelta(seconds=5),
    )
    repo.append_operation_transition(
        uid(441),
        uid(442),
        expected_revision=int(accepted["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="CONFLICT",
        safe_error_code="CONFLICT",
        safe_error_message="attachment was not installed",
        evidence_digest="f" * 64,
        actor="pytest",
        correlation_id=uid(443),
        terminal_observed_at=NOW,
    )
    detached = repo.get_binding(binding.id)["binding"]
    active_projection = repo.get_context_generation(
        "no-effect-attach", active.id
    )["context_generation"]
    assert detached["state"] == "DETACHED"
    assert active_projection["state"] == "ACTIVE"
    assert active_projection["capacity"]["attachments_in_use"] == 0
    assert active_projection["capacity"]["lifecycle_operations_in_use"] == 0


def test_settled_transition_rejects_non_contract_disposition(repository) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    accepted = repo.accept_operation(
        operation_id=uid(450),
        attempt_id=uid(451),
        method="DrainHost",
        request_digest="a" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(452),
        deadline_at=NOW + timedelta(seconds=5),
    )
    with session_factory() as session:
        audit_before = session.scalar(select(func.count()).select_from(DriverAuditEvent))
        outbox_before = session.scalar(select(func.count()).select_from(DriverOutboxEvent))
    with pytest.raises(DriverValidationError, match="not a ResultCode"):
        repo.append_operation_transition(
            uid(450),
            uid(451),
            expected_revision=int(accepted["revision"]),
            stage="SETTLED",
            certainty="NO_EFFECT",
            disposition="SUCCEEDED",
            safe_error_code=None,
            safe_error_message=None,
            evidence_digest=None,
            actor="pytest",
            correlation_id=uid(452),
        )
    assert repo.get_operation(uid(450))["operation"] == accepted
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(DriverAuditEvent)) == audit_before
        assert session.scalar(select(func.count()).select_from(DriverOutboxEvent)) == outbox_before


def test_read_projection_cursor_is_typed_bounded_and_non_secret(repository) -> None:
    repo, _ = repository
    enable_and_start_host(repo)
    first_id = uid(50)
    first = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=uid(1),
        context_id="cursor-context",
        context_generation_id=first_id,
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="5" * 64,
        actor="pytest",
        correlation_id=uid(150),
    )
    first = repo.record_context_state(
        first.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(151),
        observed_at=NOW,
    )
    first = repo.record_context_state(
        first.id,
        "CLOSING",
        expected_revision=1,
        actor="pytest",
        correlation_id=uid(152),
        observed_at=NOW,
    )
    repo.record_context_state(
        first.id,
        "CLOSED",
        expected_revision=2,
        actor="pytest",
        correlation_id=uid(153),
        observed_at=NOW,
    )
    repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=uid(1),
        context_id="cursor-context",
        context_generation_id=uid(51),
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="5" * 64,
        actor="pytest",
        correlation_id=uid(154),
    )

    page_one = repo.list_context_generations(limit=1)
    assert len(page_one["items"]) == 1 and page_one["next_cursor"]
    page_two = repo.list_context_generations(
        limit=1, cursor=page_one["next_cursor"]
    )
    assert len(page_two["items"]) == 1 and page_two["next_cursor"] is None
    assert page_one["items"][0]["context_generation_id"] != page_two["items"][0][
        "context_generation_id"
    ]
    assert "parent_host_configuration_digest" not in page_one["items"][0]
    with pytest.raises(DriverValidationError, match="cursor"):
        repo.list_context_generations(limit=1, cursor="not-a-canonical-cursor")
    with pytest.raises(DriverValidationError, match="limit"):
        repo.list_drivers(limit=101)


def test_no_effect_retry_rearms_open_and_initial_attach_resources(repository) -> None:
    repo, _ = repository
    host_id = enable_and_start_host(repo)
    context_id = "retry-context"
    context_generation_id = uid(500)
    context = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id=context_id,
        context_generation_id=context_generation_id,
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="a" * 64,
        actor="pytest",
        correlation_id=uid(501),
    )
    open_operation_id = uid(502)
    open_attempt_id = uid(503)
    accepted = repo.accept_operation(
        operation_id=open_operation_id,
        attempt_id=open_attempt_id,
        method="OpenContext",
        request_digest="b" * 64,
        effect_class="CONTEXT_OPEN",
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(504),
        deadline_at=NOW + timedelta(seconds=10),
    )
    settled = repo.append_operation_transition(
        open_operation_id,
        open_attempt_id,
        expected_revision=int(accepted["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="INTERNAL",
        safe_error_code="JOURNAL",
        safe_error_message="pre-dispatch restart",
        evidence_digest="c" * 64,
        actor="pytest",
        correlation_id=uid(505),
        terminal_observed_at=NOW,
    )
    released = repo.get_context_generation(context_id, context.id)[
        "context_generation"
    ]
    assert released["state"] == "CLOSED"
    assert repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"][
        "contexts_in_use"
    ] == 0

    retried = repo.authorize_retry(
        open_operation_id,
        expected_revision=int(settled["revision"]),
        new_attempt_id=uid(506),
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=None,
        deadline_at=NOW + timedelta(seconds=20),
        actor="pytest",
        correlation_id=uid(507),
    )
    rearmed = repo.get_context_generation(context_id, context.id)[
        "context_generation"
    ]
    assert rearmed["state"] == "OPENING"
    assert repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"][
        "contexts_in_use"
    ] == 1
    assert retried["attempts"][0]["effect_observed_at"] == NOW.isoformat()
    assert retried["attempts"][0]["projection_outcome"] == "APPLIED"
    assert retried["attempts"][1]["effect_observed_at"] is None
    assert {item["request_digest"] for item in retried["attempts"]} == {
        "b" * 64
    }
    dispatched = repo.append_operation_transition(
        open_operation_id,
        uid(506),
        expected_revision=int(retried["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="d" * 64,
        actor="pytest",
        correlation_id=uid(508),
    )
    repo.append_operation_transition(
        open_operation_id,
        uid(506),
        expected_revision=int(dispatched["revision"]),
        stage="SETTLED",
        certainty="EFFECT_CONFIRMED",
        disposition="OK",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="e" * 64,
        actor="pytest",
        correlation_id=uid(509),
        terminal_observed_at=NOW + timedelta(seconds=1),
    )
    active = repo.get_context_generation(context_id, context.id)[
        "context_generation"
    ]
    assert active["state"] == "ACTIVE" and active["ready"] is True

    binding = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(510),
        execution_id="retry-execution",
        attachment_generation_id=uid(511),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="f" * 64,
        actor="pytest",
        correlation_id=uid(512),
    )
    attach_operation_id = uid(513)
    attach_attempt_id = uid(514)
    accepted = repo.accept_operation(
        operation_id=attach_operation_id,
        attempt_id=attach_attempt_id,
        method="AttachExecution",
        request_digest="1" * 64,
        effect_class="EXECUTION_ATTACH",
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=binding.id,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(515),
        deadline_at=NOW + timedelta(seconds=10),
        lifecycle_reason="INITIAL_LOAD",
    )
    settled = repo.append_operation_transition(
        attach_operation_id,
        attach_attempt_id,
        expected_revision=int(accepted["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="INTERNAL",
        safe_error_code="HOOK",
        safe_error_message="setup did not begin",
        evidence_digest="2" * 64,
        actor="pytest",
        correlation_id=uid(516),
        terminal_observed_at=NOW + timedelta(seconds=2),
    )
    released_binding = repo.get_binding(binding.id)["binding"]
    assert released_binding["state"] == "DETACHED"
    assert released_binding["capacity_reserved"] is False
    retried = repo.authorize_retry(
        attach_operation_id,
        expected_revision=int(settled["revision"]),
        new_attempt_id=uid(517),
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=binding.id,
        deadline_at=NOW + timedelta(seconds=20),
        actor="pytest",
        correlation_id=uid(518),
    )
    rearmed_binding = repo.get_binding(binding.id)["binding"]
    assert rearmed_binding["state"] == "ATTACHING"
    assert rearmed_binding["capacity_reserved"] is True
    assert repo.get_context_generation(context_id, context.id)[
        "context_generation"
    ]["capacity"]["attachments_in_use"] == 1
    dispatched = repo.append_operation_transition(
        attach_operation_id,
        uid(517),
        expected_revision=int(retried["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="3" * 64,
        actor="pytest",
        correlation_id=uid(519),
    )
    attached = repo.append_operation_transition(
        attach_operation_id,
        uid(517),
        expected_revision=int(dispatched["revision"]),
        stage="SETTLED",
        certainty="EFFECT_CONFIRMED",
        disposition="OK",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="4" * 64,
        actor="pytest",
        correlation_id=uid(520),
        terminal_observed_at=NOW + timedelta(seconds=3),
    )
    assert repo.get_binding(binding.id)["binding"]["state"] == "ATTACHED"
    assert [item["projection_outcome"] for item in attached["attempts"]] == [
        "APPLIED",
        "APPLIED",
    ]


def test_no_effect_reload_retry_rearms_shared_slot_and_fence(repository) -> None:
    repo, _ = repository
    host_id = enable_and_start_host(repo)
    context = repo.create_context_generation(
        profile_id=DEFAULT_PROFILE_ID,
        host_generation_id=host_id,
        context_id="reload-retry-context",
        context_generation_id=uid(530),
        configuration_schema_version="spell.driver.context-profile/1",
        configuration_digest="5" * 64,
        actor="pytest",
        correlation_id=uid(531),
    )
    context = repo.record_context_state(
        context.id,
        "ACTIVE",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(532),
        observed_at=NOW,
    )
    old = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(533),
        execution_id="reload-retry-execution",
        attachment_generation_id=uid(534),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="6" * 64,
        actor="pytest",
        correlation_id=uid(535),
    )
    old = repo.record_binding_state(
        old.id,
        "ATTACHED",
        expected_revision=0,
        actor="pytest",
        correlation_id=uid(536),
        observed_at=NOW,
    )
    replacement = repo.create_binding(
        context_generation_id=context.id,
        driver_binding_id=uid(537),
        execution_id=old.execution_id,
        attachment_generation_id=uid(538),
        configuration_schema_version="spell.driver.attachment-profile/1",
        configuration_digest="7" * 64,
        actor="pytest",
        correlation_id=uid(539),
        replaces_driver_binding_id=old.id,
    )
    accepted = repo.accept_operation(
        operation_id=uid(540),
        attempt_id=uid(541),
        method="AttachExecution",
        request_digest="8" * 64,
        effect_class="EXECUTION_ATTACH",
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=replacement.id,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(542),
        deadline_at=NOW + timedelta(seconds=10),
        lifecycle_reason="RELOAD",
        replaced_driver_binding_id=old.id,
    )
    settled = repo.append_operation_transition(
        uid(540),
        uid(541),
        expected_revision=int(accepted["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="INTERNAL",
        safe_error_code="JOURNAL",
        safe_error_message="restart before dispatch",
        evidence_digest="9" * 64,
        actor="pytest",
        correlation_id=uid(543),
        terminal_observed_at=NOW + timedelta(seconds=1),
    )
    assert repo.get_binding(old.id)["binding"]["capacity_reserved"] is True
    assert repo.get_binding(replacement.id)["binding"] == {
        **repo.get_binding(replacement.id)["binding"],
        "state": "DETACHED",
        "capacity_reserved": False,
        "replacement_pending": False,
    }
    retried = repo.authorize_retry(
        uid(540),
        expected_revision=int(settled["revision"]),
        new_attempt_id=uid(544),
        host_generation_id=host_id,
        context_generation_id=context.id,
        driver_binding_id=replacement.id,
        deadline_at=NOW + timedelta(seconds=20),
        actor="pytest",
        correlation_id=uid(545),
    )
    replacement_projection = repo.get_binding(replacement.id)["binding"]
    assert replacement_projection["state"] == "ATTACHING"
    assert replacement_projection["capacity_reserved"] is False
    assert replacement_projection["replacement_pending"] is True
    assert repo.get_context_generation("reload-retry-context", context.id)[
        "context_generation"
    ]["capacity"]["attachments_in_use"] == 1
    with pytest.raises(DriverConflictError, match="unresolved reload"):
        repo.accept_operation(
            operation_id=uid(546),
            attempt_id=uid(547),
            method="CloseContext",
            request_digest="a" * 64,
            effect_class="CONTEXT_CLOSE",
            host_generation_id=host_id,
            context_generation_id=context.id,
            driver_binding_id=None,
            target_operation_id=None,
            target_attempt_id=None,
            actor="pytest",
            correlation_id=uid(548),
            deadline_at=NOW + timedelta(seconds=10),
        )
    dispatched = repo.append_operation_transition(
        uid(540),
        uid(544),
        expected_revision=int(retried["revision"]),
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="b" * 64,
        actor="pytest",
        correlation_id=uid(549),
    )
    repo.append_operation_transition(
        uid(540),
        uid(544),
        expected_revision=int(dispatched["revision"]),
        stage="SETTLED",
        certainty="EFFECT_CONFIRMED",
        disposition="OK",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="c" * 64,
        actor="pytest",
        correlation_id=uid(550),
        terminal_observed_at=NOW + timedelta(seconds=2),
    )
    assert repo.get_binding(old.id)["binding"]["state"] == "DETACHED"
    final = repo.get_binding(replacement.id)["binding"]
    assert final["state"] == "ATTACHED"
    assert final["capacity_reserved"] is True
    assert final["replacement_pending"] is False


def test_reconciliation_releases_operation_capacity_exactly_once(repository) -> None:
    repo, session_factory = repository
    host_id = enable_and_start_host(repo)
    with session_factory() as session:
        host = session.get(DriverHostGeneration, host_id)
        assert host is not None
        host.max_lifecycle_operations = 1
        session.commit()
    accepted = repo.accept_operation(
        operation_id=uid(560),
        attempt_id=uid(561),
        method="DrainHost",
        request_digest="d" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(562),
        deadline_at=NOW + timedelta(seconds=10),
    )
    duplicate = repo.accept_operation(
        operation_id=uid(560),
        attempt_id=uid(561),
        method="DrainHost",
        request_digest="d" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(562),
        deadline_at=NOW + timedelta(seconds=10),
    )
    assert duplicate == accepted
    dispatched = repo.append_operation_transition(
        uid(560),
        uid(561),
        expected_revision=0,
        stage="DISPATCHED",
        certainty="EFFECT_POSSIBLE",
        disposition=None,
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="e" * 64,
        actor="pytest",
        correlation_id=uid(563),
    )
    reconciling = repo.append_operation_transition(
        uid(560),
        uid(561),
        expected_revision=int(dispatched["revision"]),
        stage="RECONCILING",
        certainty="EFFECT_POSSIBLE",
        disposition="RECONCILIATION_REQUIRED",
        safe_error_code="TRANSPORT",
        safe_error_message="response unavailable",
        evidence_digest="f" * 64,
        actor="pytest",
        correlation_id=uid(564),
    )
    assert reconciling["capacity_reserved"] is False
    assert repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"][
        "lifecycle_operations_per_host_in_use"
    ] == 0
    assert repo.append_operation_transition(
        uid(560),
        uid(561),
        expected_revision=int(reconciling["revision"]),
        stage="RECONCILING",
        certainty="EFFECT_POSSIBLE",
        disposition="RECONCILIATION_REQUIRED",
        safe_error_code="TRANSPORT",
        safe_error_message="response unavailable",
        evidence_digest="f" * 64,
        actor="pytest",
        correlation_id=uid(564),
    ) == reconciling
    containment = repo.accept_operation(
        operation_id=uid(565),
        attempt_id=uid(566),
        method="DrainHost",
        request_digest="1" * 64,
        effect_class="HOST_DRAIN",
        host_generation_id=host_id,
        context_generation_id=None,
        driver_binding_id=None,
        target_operation_id=None,
        target_attempt_id=None,
        actor="pytest",
        correlation_id=uid(567),
        deadline_at=NOW + timedelta(seconds=10),
    )
    repo.append_operation_transition(
        uid(565),
        uid(566),
        expected_revision=int(containment["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="CONFLICT",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest=None,
        actor="pytest",
        correlation_id=uid(568),
        terminal_observed_at=NOW,
    )
    settled = repo.append_operation_transition(
        uid(560),
        uid(561),
        expected_revision=int(reconciling["revision"]),
        stage="SETTLED",
        certainty="NO_EFFECT",
        disposition="CONFLICT",
        safe_error_code=None,
        safe_error_message=None,
        evidence_digest="2" * 64,
        actor="pytest",
        correlation_id=uid(569),
        terminal_observed_at=NOW + timedelta(seconds=1),
    )
    assert settled["capacity_reserved"] is False
    assert repo.get_driver(DEFAULT_PROFILE_ID)["driver"]["capacity"][
        "lifecycle_operations_per_host_in_use"
    ] == 0
