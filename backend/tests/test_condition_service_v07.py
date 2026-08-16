from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, inspect, select

from backend.condition_engine import (
    ComparisonOperator,
    ConditionPlan,
    ConditionSnapshot,
    LiteralOperand,
    PredicateNode,
    QualityFreshnessPolicy,
    SampleEvidence,
    ScalarType,
    TelemetryOperand,
    TypedScalar,
    evaluate_condition,
    sample_id_for,
)
from backend.condition_models import (
    ConditionEvaluationRecord,
    ConditionEvaluationSample,
    TelemetryConditionSchedule,
    TelemetryScheduleOccurrence,
    VerifyOperation,
    WaitForOperation,
)
from backend.condition_service import (
    ConditionService,
    ConditionServiceConflictError,
    ConditionServiceValidationError,
)
from backend.database import create_database
from backend.migrations import run_migrations
from backend.migrations.versions import v0006_observation_conditions
from backend.models import Execution
from driver_host.observation import CATALOG_DIGEST


def plan(*, plan_id: str = "plan.verify", expected: int = 10) -> ConditionPlan:
    return ConditionPlan(
        plan_id,
        PredicateNode(
            "value-equals",
            ComparisonOperator.EQ,
            TelemetryOperand("TM.POWER.VALUE", CATALOG_DIGEST, ScalarType.INT64),
            LiteralOperand(TypedScalar(ScalarType.INT64, expected)),
        ),
    )


def snapshot(
    cursor: int,
    value: int,
    *,
    freshness: str = "FRESH",
    quality: str = "GOOD",
    validity: str = "VALID",
    has_gap: bool = False,
) -> ConditionSnapshot:
    sequence = cursor + 1
    evidence = SampleEvidence(
        sample_id=sample_id_for(
            "bundled-deterministic-simulator",
            "epoch-service-tests",
            "TM.POWER.VALUE",
            sequence,
        ),
        item_id="TM.POWER.VALUE",
        catalog_digest=CATALOG_DIGEST,
        source_id="bundled-deterministic-simulator",
        source_epoch="epoch-service-tests",
        source_sequence=sequence,
        snapshot_cursor=cursor,
        raw_value=TypedScalar(ScalarType.INT64, value),
        engineering_value=TypedScalar(ScalarType.INT64, value),
        unit="count",
        validity=validity,
        quality=quality,
        freshness=freshness,
        has_gap=has_gap,
    )
    return ConditionSnapshot(cursor, (evidence,), has_gap=has_gap)


class SnapshotQueue:
    def __init__(self, *snapshots: ConditionSnapshot):
        self.snapshots = list(snapshots)
        self.calls: list[dict] = []

    def __call__(self, **request):
        self.calls.append(request)
        if not self.snapshots:
            raise AssertionError("unexpected snapshot request")
        return self.snapshots.pop(0)


class OccurrenceStarter:
    def __init__(self, *, fail_first: bool = False):
        self.fail_first = fail_first
        self.calls: list[str] = []
        self.executions: dict[str, str] = {}

    def __call__(self, *, occurrence_id, schedule, condition_evidence):
        self.calls.append(occurrence_id)
        assert schedule["occurrence_id"] == occurrence_id
        assert condition_evidence["composite_result"] == "TRUE"
        if self.fail_first and len(self.calls) == 1:
            raise RuntimeError("simulated process loss before local settlement")
        return self.executions.setdefault(occurrence_id, f"execution-{occurrence_id[:24]}")


class DeterministicClock:
    def __init__(
        self,
        *,
        database_time: datetime | None = None,
        monotonic_ns: int = 1_000_000_000,
        epoch: str = "boot-a",
    ):
        self.database_time = database_time or datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.monotonic_ns = monotonic_ns
        self.epoch = epoch

    def advance(self, seconds: int) -> None:
        self.database_time += timedelta(seconds=seconds)
        self.monotonic_ns += seconds * 1_000_000_000


class AdvancingSnapshot:
    def __init__(
        self,
        clock: DeterministicClock,
        value: ConditionSnapshot,
        *,
        seconds: int,
    ):
        self.clock = clock
        self.value = value
        self.seconds = seconds
        self.calls = 0

    def __call__(self, **_request):
        self.calls += 1
        self.clock.advance(self.seconds)
        return self.value


def clocked_service(
    factory,
    clock: DeterministicClock,
    provider,
    *,
    starter: OccurrenceStarter | None = None,
) -> ConditionService:
    service = ConditionService(
        factory,
        snapshot_provider=provider,
        execution_starter=starter,
        monotonic_ns=lambda: clock.monotonic_ns,
        monotonic_epoch_provider=lambda: clock.epoch,
    )
    service._database_now = lambda _session: clock.database_time
    return service


def as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


@pytest.fixture
def condition_db(tmp_path):
    engine, factory = create_database(f"sqlite:///{(tmp_path / 'conditions.db').as_posix()}")
    run_migrations(engine)
    with engine.begin() as connection:
        v0006_observation_conditions.upgrade(connection)
    with factory() as session:
        session.add(
            Execution(
                id="controller-execution",
                procedure_id="controller",
                procedure_name="Controller",
                procedure_hash="a" * 64,
                procedure_source="",
                steps=[],
                ir_version="0.7",
                variables={},
                context_id="simulator-context",
                created_by="scheduler",
                creation_idempotency_key="controller-fixture",
                state="running",
                revision=1,
                current_step=0,
                total_steps=0,
                worker_generation=1,
                next_sequence=1,
            )
        )
        session.commit()
    try:
        yield engine, factory
    finally:
        engine.dispose()


def policy() -> QualityFreshnessPolicy:
    return QualityFreshnessPolicy("simulator-default", "v07-r1")


def create_schedule(
    service: ConditionService,
    *,
    key: str = "schedule-1",
    start_snapshot_cursor: int = 0,
) -> dict:
    return service.create_telemetry_schedule(
        plan=plan(plan_id=f"plan.{key}"),
        policy=policy(),
        start_snapshot_cursor=start_snapshot_cursor,
        timeout_seconds=60,
        retry_count=1,
        retry_interval_seconds=0,
        controller_execution_id="controller-execution",
        procedure_catalog_id="procedure.catalog",
        procedure_revision=3,
        bundle_digest="b" * 64,
        context_id="simulator-context",
        arguments={"mode": "safe", "count": 2},
        automatic=True,
        background_allowed=True,
        visible=True,
        created_by="scheduler",
        idempotency_key=key,
    )


def test_migration_requires_v0005_and_adds_only_the_seven_condition_tables(condition_db) -> None:
    isolated = create_engine("sqlite:///:memory:")
    try:
        with isolated.begin() as connection:
            with pytest.raises(RuntimeError, match="requires observation projection"):
                v0006_observation_conditions.upgrade(connection)
    finally:
        isolated.dispose()

    engine, _factory = condition_db
    tables = set(inspect(engine).get_table_names())
    assert {table.name for table in v0006_observation_conditions.NEW_TABLES} == {
        "condition_plans",
        "condition_evaluations",
        "condition_evaluation_samples",
        "verify_operations",
        "waitfor_operations",
        "telemetry_condition_schedules",
        "telemetry_schedule_occurrences",
    }
    assert {table.name for table in v0006_observation_conditions.NEW_TABLES} <= tables
    expected_clock_columns = {
        "deadline_monotonic_ns",
        "clock_anchor_monotonic_ns",
        "clock_anchor_database_time",
        "monotonic_epoch",
    }
    inspector = inspect(engine)
    for table_name in (
        "verify_operations",
        "waitfor_operations",
        "telemetry_condition_schedules",
    ):
        assert expected_clock_columns <= {
            column["name"] for column in inspector.get_columns(table_name)
        }


@pytest.mark.skipif(
    not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
    reason="dedicated PostgreSQL migration database not configured",
)
def test_postgresql_database_clock_advances_inside_one_transaction() -> None:
    engine, factory = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    service = ConditionService(factory, snapshot_provider=SnapshotQueue())
    try:
        with factory() as session:
            first = service._database_now(session)
            session.execute(select(func.pg_sleep(0.02)))
            second = service._database_now(session)
        assert second > first
    finally:
        engine.dispose()


def test_plan_registration_is_immutable_and_digest_bound(condition_db) -> None:
    _engine, factory = condition_db
    service = ConditionService(factory, snapshot_provider=SnapshotQueue())
    first = service.register_plan(plan())
    replay = service.register_plan(plan())
    assert replay == first
    with pytest.raises(ConditionServiceConflictError, match="different immutable plan"):
        service.register_plan(plan(expected=11))


def test_verify_is_idempotent_retries_and_commits_leaf_sample_evidence(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue(snapshot(1, 9), snapshot(2, 10))
    service = ConditionService(factory, snapshot_provider=provider)
    request = dict(
        plan=plan(),
        policy=policy(),
        delay_seconds=0,
        timeout_seconds=60,
        retry_count=1,
        retry_interval_seconds=0,
        start_snapshot_cursor=0,
        request_scope="execution.verify",
        idempotency_key="verify-1",
    )
    first = service.verify(**request)
    assert first["state"] == "RETRY_WAIT"
    assert first["attempt_count"] == 1
    settled = service.verify(**request)
    assert settled["verify_id"] == first["verify_id"]
    assert settled["state"] == "TRUE"
    assert settled["attempt_count"] == 2
    assert settled["final_result"]["evaluation"]["composite_result"] == "TRUE"
    assert [call["after_snapshot_cursor"] for call in provider.calls] == [0, 1]

    with factory() as session:
        evaluations = session.scalars(
            select(ConditionEvaluationRecord)
            .where(ConditionEvaluationRecord.operation_id == settled["verify_id"])
            .order_by(ConditionEvaluationRecord.attempt_number)
        ).all()
        samples = session.scalars(select(ConditionEvaluationSample)).all()
        assert [item.composite_result for item in evaluations] == ["FALSE", "TRUE"]
        assert len(samples) == 2
        assert all(len(item.sample_id) == 64 for item in samples)

    assert service.verify(**request) == settled
    assert len(provider.calls) == 2
    with pytest.raises(ConditionServiceConflictError, match="another Verify"):
        service.verify(**{**request, "timeout_seconds": 59})


def test_verify_zero_retry_delay_timeout_and_cancel_are_durable(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue(snapshot(1, 9))
    service = ConditionService(factory, snapshot_provider=provider)
    false_result = service.verify(
        plan=plan(plan_id="plan.false"),
        policy=policy(),
        timeout_seconds=60,
        retry_count=0,
        request_scope="verify.false",
        idempotency_key="zero-retry",
    )
    assert false_result["state"] == "FALSE"
    assert false_result["attempt_count"] == 1

    timed_out = service.verify(
        plan=plan(plan_id="plan.timeout"),
        policy=policy(),
        delay_seconds=1,
        timeout_seconds=0,
        request_scope="verify.timeout",
        idempotency_key="deadline",
    )
    assert timed_out["state"] == "TIMED_OUT"
    assert timed_out["attempt_count"] == 0
    assert len(provider.calls) == 1

    delayed = service.verify(
        plan=plan(plan_id="plan.cancel"),
        policy=policy(),
        delay_seconds=60,
        timeout_seconds=120,
        request_scope="verify.cancel",
        idempotency_key="cancel",
    )
    assert delayed["state"] == "DELAYED"
    cancelled = service.cancel_verify(
        delayed["verify_id"], expected_revision=delayed["revision"]
    )
    assert cancelled["state"] == "CANCELLED"
    assert service.cancel_verify(delayed["verify_id"], expected_revision=0) == cancelled


def test_relative_and_absolute_waits_settle_from_database_targets(condition_db) -> None:
    _engine, factory = condition_db
    service = ConditionService(factory, snapshot_provider=SnapshotQueue())
    relative = service.create_wait(
        execution_id="execution-1",
        statement_id="wait-relative",
        wait_type="RELATIVE",
        target=0,
        idempotency_key="relative",
    )
    assert relative["state"] == "CREATED"
    relative = service.reconcile_wait(relative["wait_id"])
    assert relative["state"] == "SATISFIED"

    absolute = service.create_wait(
        execution_id="execution-1",
        statement_id="wait-absolute",
        wait_type="ABSOLUTE",
        target="2026-01-01T00:00:00-05:00",
        idempotency_key="absolute",
    )
    assert absolute["original_target"] == {"rfc3339": "2026-01-01T00:00:00-05:00"}
    assert absolute["canonical_target"] == "2026-01-01T05:00:00Z"
    assert service.reconcile_wait(absolute["wait_id"])["state"] == "SATISFIED"


def test_absolute_wait_uses_database_utc_when_monotonic_time_has_not_advanced(
    condition_db,
) -> None:
    _engine, factory = condition_db
    clock = DeterministicClock()
    service = clocked_service(factory, clock, SnapshotQueue())
    waiting = service.create_wait(
        execution_id="execution-absolute-clock-step",
        statement_id="wait-absolute-clock-step",
        wait_type="ABSOLUTE",
        target="2030-01-01T00:01:00Z",
        idempotency_key="absolute-clock-step",
    )
    deadline = waiting["deadline_at_database_time"]
    monotonic_before = clock.monotonic_ns

    clock.database_time += timedelta(seconds=60)
    settled = service.reconcile_wait(waiting["wait_id"])

    assert settled["state"] == "SATISFIED"
    assert settled["canonical_target"] == "2030-01-01T00:01:00Z"
    assert settled["deadline_at_database_time"] == deadline
    assert clock.monotonic_ns == monotonic_before


def test_wait_interrupt_resume_preserves_original_deadline_and_cancel_is_idempotent(condition_db) -> None:
    _engine, factory = condition_db
    service = ConditionService(factory, snapshot_provider=SnapshotQueue())
    waiting = service.create_wait(
        execution_id="execution-2",
        statement_id="wait-future",
        wait_type="RELATIVE",
        target=60,
        idempotency_key="future",
    )
    waiting = service.reconcile_wait(waiting["wait_id"])
    deadline = waiting["deadline_at_database_time"]
    interrupted = service.interrupt_wait(
        waiting["wait_id"], expected_revision=waiting["revision"]
    )
    assert interrupted["state"] == "INTERRUPTED"
    assert interrupted["deadline_at_database_time"] == deadline
    resumed = service.resume_wait(
        waiting["wait_id"], expected_revision=interrupted["revision"]
    )
    assert resumed["state"] == "WAITING"
    assert resumed["deadline_at_database_time"] == deadline
    cancelled = service.cancel_wait(
        waiting["wait_id"], expected_revision=resumed["revision"]
    )
    assert cancelled["state"] == "CANCELLED"
    assert service.reconcile_wait(waiting["wait_id"]) == cancelled
    assert service.cancel_wait(waiting["wait_id"], expected_revision=0) == cancelled


def test_telemetry_wait_restart_reuses_cursor_policy_deadline_and_evidence(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue(
        snapshot(5, 10, freshness="STALE"),
        snapshot(6, 10),
    )
    first_service = ConditionService(factory, snapshot_provider=provider)
    created = first_service.create_wait(
        execution_id="execution-3",
        statement_id="wait-condition",
        wait_type="TELEMETRY_CONDITION",
        target=None,
        plan=plan(plan_id="plan.wait"),
        policy=policy(),
        start_snapshot_cursor=4,
        timeout_seconds=60,
        retry_count=1,
        retry_interval_seconds=0,
        idempotency_key="condition",
    )
    first = first_service.reconcile_wait(created["wait_id"])
    assert first["state"] == "WAITING"
    assert first["attempt_count"] == 1
    interrupted = first_service.interrupt_wait(
        first["wait_id"], expected_revision=first["revision"]
    )
    original_deadline = interrupted["deadline_at_database_time"]

    recovered_service = ConditionService(factory, snapshot_provider=provider)
    assert recovered_service.recover_waits() == []
    settled = recovered_service.resume_wait(
        interrupted["wait_id"], expected_revision=interrupted["revision"]
    )
    assert settled["state"] == "SATISFIED"
    assert settled["attempt_count"] == 2
    assert settled["deadline_at_database_time"] == original_deadline
    assert settled["terminal_result"]["evaluation"]["snapshot_cursor"] == "6"
    assert settled["terminal_result"]["evaluation"]["consumed_sample_ids"]
    assert [call["after_snapshot_cursor"] for call in provider.calls] == [4, 5]


def test_wait_restart_times_out_against_original_deadline_without_snapshot(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue()
    service = ConditionService(factory, snapshot_provider=provider)
    created = service.create_wait(
        execution_id="execution-4",
        statement_id="wait-timeout",
        wait_type="TELEMETRY_CONDITION",
        target=None,
        plan=plan(plan_id="plan.wait.timeout"),
        policy=policy(),
        start_snapshot_cursor=10,
        timeout_seconds=0,
        retry_count=10,
        retry_interval_seconds=0,
        idempotency_key="timeout",
    )
    recovered = ConditionService(factory, snapshot_provider=provider).recover_waits()
    assert len(recovered) == 1
    assert recovered[0]["wait_id"] == created["wait_id"]
    assert recovered[0]["state"] == "TIMED_OUT"
    assert recovered[0]["attempt_count"] == 0
    assert provider.calls == []


def test_telemetry_schedule_pins_true_evidence_and_fires_one_occurrence(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue(snapshot(1, 9), snapshot(2, 10))
    starter = OccurrenceStarter()
    service = ConditionService(
        factory, snapshot_provider=provider, execution_starter=starter
    )
    created = create_schedule(service)
    pending = service.reconcile_telemetry_schedule(created["schedule_id"])
    assert pending["state"] == "PENDING"
    assert pending["attempt_count"] == 1
    fired = service.reconcile_telemetry_schedule(created["schedule_id"])
    assert fired["state"] == "FIRED"
    assert fired["winning_evaluation_id"]
    assert fired["occurrence_id"]
    assert fired["fired_execution_id"].startswith("execution-")
    assert starter.calls == [fired["occurrence_id"]]

    replay = create_schedule(service)
    assert replay == fired
    assert service.reconcile_telemetry_schedule(fired["schedule_id"]) == fired
    assert starter.calls == [fired["occurrence_id"]]
    with factory() as session:
        occurrences = session.scalars(select(TelemetryScheduleOccurrence)).all()
        assert len(occurrences) == 1
        assert occurrences[0].state == "FIRED"
        assert occurrences[0].execution_id == fired["fired_execution_id"]


def test_telemetry_schedule_cursors_are_lossless_json_decimal_strings(condition_db) -> None:
    _engine, factory = condition_db
    service = ConditionService(factory, snapshot_provider=SnapshotQueue())
    cursor = 9_007_199_254_740_993

    created = create_schedule(
        service,
        key="schedule-cursor-boundary",
        start_snapshot_cursor=cursor,
    )

    assert created["start_snapshot_cursor"] == str(cursor)
    assert created["last_snapshot_cursor"] is None
    assert service.get_telemetry_schedule(created["schedule_id"])[
        "start_snapshot_cursor"
    ] == str(cursor)
    assert service.list_telemetry_schedules()[0]["start_snapshot_cursor"] == str(cursor)


def test_condition_evidence_cursors_are_lossless_json_decimal_strings(condition_db) -> None:
    _engine, factory = condition_db
    cursor = 9_007_199_254_740_993
    service = ConditionService(
        factory, snapshot_provider=SnapshotQueue(snapshot(cursor, 10))
    )

    verified = service.verify(
        plan=plan(plan_id="plan.cursor.boundary"),
        policy=policy(),
        timeout_seconds=60,
        retry_count=0,
        start_snapshot_cursor=cursor - 1,
        request_scope="cursor.boundary",
        idempotency_key="cursor-boundary",
    )

    assert verified["final_result"]["snapshot_cursor"] == str(cursor)
    assert verified["final_result"]["evaluation"]["snapshot_cursor"] == str(cursor)


def test_claimed_schedule_recovers_with_the_same_occurrence_bound_callback(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue(snapshot(1, 10))
    starter = OccurrenceStarter(fail_first=True)
    service = ConditionService(
        factory, snapshot_provider=provider, execution_starter=starter
    )
    created = create_schedule(service, key="schedule-recovery")
    claimed = service.reconcile_telemetry_schedule(created["schedule_id"])
    assert claimed["state"] == "CLAIMED"
    assert claimed["dispatch_attempts"] == 1
    occurrence_id = claimed["occurrence_id"]

    restarted = ConditionService(
        factory, snapshot_provider=provider, execution_starter=starter
    )
    recovered = restarted.recover_telemetry_schedules()
    assert len(recovered) == 1
    assert recovered[0]["state"] == "FIRED"
    assert recovered[0]["occurrence_id"] == occurrence_id
    assert starter.calls == [occurrence_id, occurrence_id]
    assert len(starter.executions) == 1


def test_schedule_cancel_deadline_and_argument_security_are_fail_closed(condition_db) -> None:
    _engine, factory = condition_db
    service = ConditionService(factory, snapshot_provider=SnapshotQueue())
    created = create_schedule(service, key="schedule-cancel")
    cancelled = service.cancel_telemetry_schedule(
        created["schedule_id"], expected_revision=created["revision"]
    )
    assert cancelled["state"] == "CANCELLED"
    assert service.cancel_telemetry_schedule(
        created["schedule_id"], expected_revision=0
    ) == cancelled

    missed = service.create_telemetry_schedule(
        plan=plan(plan_id="plan.schedule.missed"),
        policy=policy(),
        start_snapshot_cursor=0,
        timeout_seconds=0,
        retry_count=1,
        retry_interval_seconds=0,
        controller_execution_id="controller-execution",
        procedure_catalog_id="procedure.catalog",
        procedure_revision=1,
        bundle_digest="c" * 64,
        context_id="simulator-context",
        arguments={},
        automatic=False,
        background_allowed=False,
        visible=True,
        created_by="scheduler",
        idempotency_key="schedule-missed",
    )
    assert service.reconcile_telemetry_schedule(missed["schedule_id"])["state"] == "MISSED"

    with pytest.raises(ConditionServiceValidationError, match="secret material"):
        service.create_telemetry_schedule(
            plan=plan(plan_id="plan.schedule.secret"),
            policy=policy(),
            start_snapshot_cursor=0,
            timeout_seconds=10,
            retry_count=0,
            retry_interval_seconds=0,
            controller_execution_id="controller-execution",
            procedure_catalog_id="procedure.catalog",
            procedure_revision=1,
            bundle_digest="d" * 64,
            context_id="simulator-context",
            arguments={"api_key": "not-accepted"},
            automatic=False,
            background_allowed=False,
            visible=True,
            created_by="scheduler",
            idempotency_key="schedule-secret",
        )


def test_persisted_terminal_states_are_not_rewritten_by_recovery(condition_db) -> None:
    _engine, factory = condition_db
    provider = SnapshotQueue(snapshot(1, 10))
    starter = OccurrenceStarter()
    service = ConditionService(
        factory, snapshot_provider=provider, execution_starter=starter
    )
    schedule = create_schedule(service, key="terminal")
    fired = service.reconcile_telemetry_schedule(schedule["schedule_id"])
    assert fired["state"] == "FIRED"
    assert service.recover_telemetry_schedules() == []
    assert service.cancel_telemetry_schedule(
        fired["schedule_id"], expected_revision=0
    ) == fired

    with factory() as session:
        stored = session.get(TelemetryConditionSchedule, fired["schedule_id"])
        assert stored.state == "FIRED"
        assert stored.fired_execution_id == fired["fired_execution_id"]


def test_database_clock_regression_fails_closed_without_moving_deadline(condition_db) -> None:
    _engine, factory = condition_db
    clock = DeterministicClock()
    service = clocked_service(factory, clock, SnapshotQueue())
    created = service.create_wait(
        execution_id="clock-regression",
        statement_id="relative-wait",
        wait_type="RELATIVE",
        target=60,
        idempotency_key="backward-database-clock",
    )
    waiting = service.reconcile_wait(created["wait_id"])
    original_deadline = waiting["deadline_at_database_time"]

    clock.monotonic_ns += 1_000_000_000
    clock.database_time -= timedelta(seconds=1)
    failed = service.reconcile_wait(created["wait_id"])

    assert failed["state"] == "FAILED"
    assert failed["failure_code"] == "CLOCK_CORRELATION_INVALID"
    assert failed["deadline_at_database_time"] == original_deadline


def test_same_epoch_restart_uses_persisted_monotonic_deadline(condition_db) -> None:
    _engine, factory = condition_db
    clock = DeterministicClock()
    first = clocked_service(factory, clock, SnapshotQueue())
    created = first.create_wait(
        execution_id="same-epoch-restart",
        statement_id="relative-wait",
        wait_type="RELATIVE",
        target=5,
        idempotency_key="restart-deadline",
    )
    waiting = first.reconcile_wait(created["wait_id"])
    original_deadline = waiting["deadline_at_database_time"]

    clock.monotonic_ns += 5_000_000_000
    restarted = clocked_service(factory, clock, SnapshotQueue())
    recovered = restarted.recover_waits()

    assert len(recovered) == 1
    assert recovered[0]["state"] == "SATISFIED"
    assert recovered[0]["deadline_at_database_time"] == original_deadline
    assert recovered[0]["settled_at_database_time"] == "2030-01-01T00:00:00Z"


def test_epoch_change_rebases_from_immutable_utc_deadline(condition_db) -> None:
    _engine, factory = condition_db
    clock = DeterministicClock(monotonic_ns=10_000_000_000)
    first = clocked_service(factory, clock, SnapshotQueue())
    created = first.create_wait(
        execution_id="epoch-restart",
        statement_id="relative-wait",
        wait_type="RELATIVE",
        target=60,
        idempotency_key="epoch-deadline",
    )
    waiting = first.reconcile_wait(created["wait_id"])
    original_deadline = waiting["deadline_at_database_time"]

    clock.database_time += timedelta(seconds=20)
    clock.monotonic_ns = 2_000_000_000
    clock.epoch = "boot-b"
    restarted = clocked_service(factory, clock, SnapshotQueue())
    rebased = restarted.reconcile_wait(created["wait_id"])
    assert rebased["state"] == "WAITING"
    assert rebased["deadline_at_database_time"] == original_deadline
    with factory() as session:
        row = session.get(WaitForOperation, created["wait_id"])
        assert row.monotonic_epoch == "boot-b"
        assert row.clock_anchor_monotonic_ns == 2_000_000_000
        assert row.deadline_monotonic_ns == 42_000_000_000
        assert as_utc(row.clock_anchor_database_time) == clock.database_time

    clock.monotonic_ns = 42_000_000_000
    satisfied = restarted.reconcile_wait(created["wait_id"])
    assert satisfied["state"] == "SATISFIED"
    assert satisfied["deadline_at_database_time"] == original_deadline


def test_late_true_snapshot_cannot_satisfy_verify_wait_or_schedule(condition_db) -> None:
    _engine, factory = condition_db

    verify_clock = DeterministicClock()
    verify_provider = AdvancingSnapshot(verify_clock, snapshot(1, 10), seconds=6)
    verify_service = clocked_service(factory, verify_clock, verify_provider)
    verified = verify_service.verify(
        plan=plan(plan_id="plan.late.verify"),
        policy=policy(),
        timeout_seconds=5,
        request_scope="late.verify",
        idempotency_key="late-true",
    )
    assert verified["state"] == "TIMED_OUT"
    assert verified["attempt_count"] == 1
    assert verified["final_result"]["evaluation"]["composite_result"] == "TRUE"
    assert verified["settled_at_database_time"] == "2030-01-01T00:00:06Z"

    wait_clock = DeterministicClock()
    wait_provider = AdvancingSnapshot(wait_clock, snapshot(1, 10), seconds=6)
    wait_service = clocked_service(factory, wait_clock, wait_provider)
    wait = wait_service.create_wait(
        execution_id="late-wait",
        statement_id="condition",
        wait_type="TELEMETRY_CONDITION",
        target=None,
        plan=plan(plan_id="plan.late.wait"),
        policy=policy(),
        timeout_seconds=5,
        idempotency_key="late-true",
    )
    waited = wait_service.reconcile_wait(wait["wait_id"])
    assert waited["state"] == "TIMED_OUT"
    assert waited["attempt_count"] == 1
    assert waited["terminal_result"]["evaluation"]["composite_result"] == "TRUE"
    assert waited["settled_at_database_time"] == "2030-01-01T00:00:06Z"

    schedule_clock = DeterministicClock()
    schedule_provider = AdvancingSnapshot(schedule_clock, snapshot(1, 10), seconds=6)
    starter = OccurrenceStarter()
    schedule_service = clocked_service(
        factory, schedule_clock, schedule_provider, starter=starter
    )
    schedule = schedule_service.create_telemetry_schedule(
        plan=plan(plan_id="plan.late.schedule"),
        policy=policy(),
        start_snapshot_cursor=0,
        timeout_seconds=5,
        retry_count=0,
        retry_interval_seconds=0,
        controller_execution_id="controller-execution",
        procedure_catalog_id="procedure.catalog",
        procedure_revision=1,
        bundle_digest="e" * 64,
        context_id="simulator-context",
        arguments={},
        automatic=False,
        background_allowed=False,
        visible=True,
        created_by="scheduler",
        idempotency_key="late-schedule",
    )
    missed = schedule_service.reconcile_telemetry_schedule(schedule["schedule_id"])
    assert missed["state"] == "MISSED"
    assert missed["attempt_count"] == 1
    assert missed["winning_evaluation_id"] is None
    assert missed["settled_at_database_time"] == "2030-01-01T00:00:06Z"
    assert starter.calls == []


def test_verify_may_settle_a_complete_predeadline_snapshot_after_evaluation_delay(
    condition_db, monkeypatch
) -> None:
    _engine, factory = condition_db
    clock = DeterministicClock()
    provider = SnapshotQueue(snapshot(1, 10))
    service = clocked_service(factory, clock, provider)
    original_evaluate = evaluate_condition

    def delayed_evaluate(*args, **kwargs):
        result = original_evaluate(*args, **kwargs)
        clock.advance(6)
        return result

    monkeypatch.setattr("backend.condition_service.evaluate_condition", delayed_evaluate)
    verified = service.verify(
        plan=plan(plan_id="plan.predeadline.snapshot"),
        policy=policy(),
        timeout_seconds=5,
        request_scope="predeadline.snapshot",
        idempotency_key="predeadline-snapshot",
    )

    assert verified["state"] == "TRUE"
    assert verified["attempt_count"] == 1
    assert verified["final_result"]["evaluation"]["snapshot_cursor"] == "1"
    assert verified["settled_at_database_time"] == "2030-01-01T00:00:06Z"


def test_evaluation_settlement_drives_retry_settlement_and_claim_times(condition_db) -> None:
    _engine, factory = condition_db

    retry_clock = DeterministicClock()
    retry_provider = AdvancingSnapshot(retry_clock, snapshot(1, 9), seconds=2)
    retry_service = clocked_service(factory, retry_clock, retry_provider)
    retrying = retry_service.verify(
        plan=plan(plan_id="plan.settled.retry"),
        policy=policy(),
        timeout_seconds=60,
        retry_count=1,
        retry_interval_seconds=10,
        request_scope="settled.retry",
        idempotency_key="settled-retry",
    )
    assert retrying["state"] == "RETRY_WAIT"
    assert retrying["updated_at_database_time"] == "2030-01-01T00:00:02Z"
    assert retrying["next_attempt_at_database_time"] == "2030-01-01T00:00:12Z"

    wait_clock = DeterministicClock()
    wait_provider = AdvancingSnapshot(wait_clock, snapshot(1, 10), seconds=2)
    wait_service = clocked_service(factory, wait_clock, wait_provider)
    wait = wait_service.create_wait(
        execution_id="settled-wait",
        statement_id="condition",
        wait_type="TELEMETRY_CONDITION",
        target=None,
        plan=plan(plan_id="plan.settled.wait"),
        policy=policy(),
        timeout_seconds=60,
        idempotency_key="settled-wait",
    )
    satisfied = wait_service.reconcile_wait(wait["wait_id"])
    assert satisfied["state"] == "SATISFIED"
    assert satisfied["settled_at_database_time"] == "2030-01-01T00:00:02Z"

    schedule_clock = DeterministicClock()
    schedule_provider = AdvancingSnapshot(schedule_clock, snapshot(1, 10), seconds=2)
    starter = OccurrenceStarter()
    schedule_service = clocked_service(
        factory, schedule_clock, schedule_provider, starter=starter
    )
    schedule = schedule_service.create_telemetry_schedule(
        plan=plan(plan_id="plan.settled.schedule"),
        policy=policy(),
        start_snapshot_cursor=0,
        timeout_seconds=60,
        retry_count=0,
        retry_interval_seconds=0,
        controller_execution_id="controller-execution",
        procedure_catalog_id="procedure.catalog",
        procedure_revision=1,
        bundle_digest="f" * 64,
        context_id="simulator-context",
        arguments={},
        automatic=False,
        background_allowed=False,
        visible=True,
        created_by="scheduler",
        idempotency_key="settled-schedule",
    )
    fired = schedule_service.reconcile_telemetry_schedule(schedule["schedule_id"])
    assert fired["state"] == "FIRED"
    assert fired["claimed_at_database_time"] == "2030-01-01T00:00:02Z"

    with factory() as session:
        verify_row = session.get(VerifyOperation, retrying["verify_id"])
        verify_evaluation = session.get(
            ConditionEvaluationRecord, verify_row.last_evaluation_id
        )
        assert as_utc(verify_row.updated_at) == as_utc(verify_evaluation.settled_at)
        assert as_utc(verify_row.clock_anchor_database_time) == as_utc(
            verify_evaluation.settled_at
        )
        wait_row = session.get(WaitForOperation, wait["wait_id"])
        wait_evaluation = session.get(
            ConditionEvaluationRecord, wait_row.terminal_evaluation_id
        )
        assert as_utc(wait_row.settled_at) == as_utc(wait_evaluation.settled_at)
        schedule_row = session.get(TelemetryConditionSchedule, schedule["schedule_id"])
        occurrence = session.get(TelemetryScheduleOccurrence, schedule_row.occurrence_id)
        schedule_evaluation = session.get(
            ConditionEvaluationRecord, schedule_row.winning_evaluation_id
        )
        assert as_utc(schedule_row.claimed_at) == as_utc(schedule_evaluation.settled_at)
        assert as_utc(occurrence.claimed_at) == as_utc(schedule_evaluation.settled_at)
