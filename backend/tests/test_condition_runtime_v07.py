from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import inspect

from backend.condition_engine import (
    ComparisonOperator,
    ConditionPlan,
    LiteralOperand,
    PredicateNode,
    QualityFreshnessPolicy,
    ScalarType,
    TelemetryOperand,
    TypedScalar,
    sample_id_for,
)
from backend.condition_runtime import (
    CommittedObservationSnapshotProvider,
    ConditionExecutionLifecycle,
    ConditionProcedureRuntime,
    ConditionRecoveryLoop,
    DurableExecutionCancellationProbe,
    OccurrenceBoundExecutionStarter,
    RepositoryGetTMResolver,
)
from backend.condition_service import ConditionService
from backend.database import create_database
from backend.ir_v07 import REQUEST_SCHEMA_VERSION, bind_observation_anchor
from backend.migrations import run_migrations
from backend.migrations.versions import v0006_observation_conditions
from backend.models import Execution
from driver_host.observation import CATALOG_DIGEST


SOURCE_ID = "bundled-deterministic-simulator"
SOURCE_EPOCH = "epoch-runtime"
CONTEXT_ID = "simulator"
CONTEXT_GENERATION = "context-generation-runtime"
STREAM_EPOCH = "stream-runtime"
ITEM_ID = "TM.POWER.VALUE"
REQUESTED_AT_UNIX_NS = 1_800_000_000_000_000_000


def _sample(
    sequence: int,
    *,
    raw_type: str = "INT64",
    raw_value: object = "10",
    engineering_type: str = "INT64",
    engineering_value: object = "10",
    synchronization_state: str = "COMPLETE",
) -> dict:
    return {
        "sample_id": sample_id_for(SOURCE_ID, SOURCE_EPOCH, ITEM_ID, sequence),
        "observation_id": f"observation-{sequence}",
        "context_generation_id": CONTEXT_GENERATION,
        "item_id": ITEM_ID,
        "qualified_name": "SIM.POWER.VALUE",
        "catalog_digest": CATALOG_DIGEST,
        "source_id": SOURCE_ID,
        "source_epoch": SOURCE_EPOCH,
        "source_sequence": str(sequence),
        "raw_value": {"type": raw_type, "value": raw_value},
        "engineering_value": {
            "type": engineering_type,
            "value": engineering_value,
        },
        "description": "Runtime test value",
        "unit": "count",
        "acquired_at_unix_ns": "1000000000",
        "received_at_unix_ns": "1000000100",
        "received_at": "2026-08-16T12:00:00+00:00",
        "source": SOURCE_ID,
        "clock_provenance": "bundled-deterministic-simulator-clock",
        "clock_uncertainty_ns": "1000",
        "validity": "VALID",
        "quality": "GOOD",
        "quality_reason": "deterministic-simulator",
        "freshness": "FRESH",
        "freshness_policy_revision": "v07-r1",
        "synchronization_state": synchronization_state,
        "alarm": None,
    }


def _snapshot(sequence: int, *, item: dict | None = None) -> dict:
    selected = _sample(sequence) if item is None else item
    return {
        "schema_version": "spell.driver.observation.snapshot/1",
        "stream": "driver.observation",
        "stream_epoch": STREAM_EPOCH,
        "through_sequence": str(sequence + 4),
        "snapshot_at_database_time": "2026-08-16T12:00:00+00:00",
        "context_id": CONTEXT_ID,
        "context_generation_id": CONTEXT_GENERATION,
        "source_epochs": [
            {
                "source_id": SOURCE_ID,
                "item_id": ITEM_ID,
                "source_epoch": SOURCE_EPOCH,
                "last_source_sequence": str(sequence),
                "synchronization_state": "COMPLETE",
            }
        ],
        "items": [selected],
        "driver_time": {
            "uncertainty_ns": "1000",
            "validity": "VALID",
            "quality": "GOOD",
        },
        "synchronization_state": "COMPLETE",
    }


class FakeRepository:
    def __init__(self, *, snapshots=(), replays=()):
        self.snapshots = list(snapshots)
        self.replays = list(replays)
        self.snapshot_calls: list[str] = []
        self.replay_calls: list[dict] = []

    def snapshot(self, context_id):
        self.snapshot_calls.append(context_id)
        if not self.snapshots:
            raise AssertionError("unexpected snapshot call")
        return self.snapshots.pop(0)

    def replay(self, context_id, *, stream_epoch, after_sequence, limit):
        self.replay_calls.append(
            {
                "context_id": context_id,
                "stream_epoch": stream_epoch,
                "after_sequence": after_sequence,
                "limit": limit,
            }
        )
        if not self.replays:
            raise AssertionError("unexpected replay call")
        return self.replays.pop(0)


def _request(*, mode="CURRENT", scalar_type="int", field="ENGINEERING") -> dict:
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "request_id": "00000000-0000-0000-0000-000000000701",
        "execution_id": "00000000-0000-0000-0000-000000000702",
        "step_index": 1,
        "operation": "GET_TM",
        "parameters": {
            "item_id": ITEM_ID,
            "scalar_type": scalar_type,
            "field": field,
            "mode": mode,
            "timeout_seconds": 1,
        },
    }


def _anchor_request(*, scalar_type="int") -> dict:
    request = _request(mode="NEXT", scalar_type=scalar_type)
    anchor = {
        "context_id": CONTEXT_ID,
        "context_generation_id": CONTEXT_GENERATION,
        "stream_epoch": STREAM_EPOCH,
        "projection_sequence": "5",
        "item_id": ITEM_ID,
        "source_id": SOURCE_ID,
        "source_epoch": SOURCE_EPOCH,
        "source_sequence": "1",
        "sample_id": sample_id_for(SOURCE_ID, SOURCE_EPOCH, ITEM_ID, 1),
    }
    return bind_observation_anchor(
        request,
        CONTEXT_ID,
        anchor,
        requested_at_unix_ns=str(REQUESTED_AT_UNIX_NS),
        deadline_at_unix_ns=str(REQUESTED_AT_UNIX_NS + 1_000_000_000),
    )


def _replay(*events: dict, cursor_available=True, epoch_matches=True) -> dict:
    return {
        "stream_epoch": STREAM_EPOCH,
        "first_sequence": "1",
        "last_sequence": str(
            max([5, *[int(event["projection_sequence"]) for event in events]])
        ),
        "epoch_matches": epoch_matches,
        "cursor_available": cursor_available,
        "items": list(events),
    }


def _sample_event(sequence: int, projection_sequence: int) -> dict:
    return {
        "schema_version": "spell.driver.observation.event/1",
        "stream": "driver.observation",
        "stream_epoch": STREAM_EPOCH,
        "projection_sequence": str(projection_sequence),
        "event_id": f"event-{projection_sequence}",
        "event_type": "telemetry.sample_observed",
        "aggregate_type": "telemetry_sample",
        "aggregate_id": sample_id_for(SOURCE_ID, SOURCE_EPOCH, ITEM_ID, sequence),
        "data": _sample(sequence),
        "created_at": "2026-08-16T12:00:00+00:00",
    }


def _runtime(repository: FakeRepository, **resolver_options):
    resolver_options.setdefault("wall_time_ns", lambda: REQUESTED_AT_UNIX_NS)
    resolver = RepositoryGetTMResolver(
        repository,
        lambda _execution_id: CONTEXT_ID,
        known_item_ids=frozenset({ITEM_ID}),
        **resolver_options,
    )
    return ConditionProcedureRuntime(
        object(),
        policy=QualityFreshnessPolicy("simulator-default", "v07-r1"),
        get_tm_resolver=resolver,
        sleeper=lambda _seconds: None,
    )


def test_repository_get_tm_current_preserves_uint64_and_atomic_evidence() -> None:
    maximum = 2**64 - 1
    item = _sample(
        1,
        raw_type="INT64",
        raw_value=str(-(2**63)),
        engineering_type="UINT64",
        engineering_value=str(maximum),
    )
    runtime = _runtime(FakeRepository(snapshots=[_snapshot(1, item=item)]))
    result = runtime.resolve(_request())

    assert result["outcome"] == "OK"
    assert result["value"] == maximum
    assert type(result["value"]) is int
    assert result["evidence"]["raw_value"]["value"] == str(-(2**63))
    assert result["evidence"]["engineering_value"]["value"] == str(maximum)
    assert result["evidence"]["sample_id"] == item["sample_id"]


def test_repository_get_tm_type_mismatch_is_typed_and_has_no_value() -> None:
    runtime = _runtime(FakeRepository(snapshots=[_snapshot(1)]))
    result = runtime.resolve(_request(scalar_type="float"))
    assert result["outcome"] == "CONTRACT_MISMATCH"
    assert result["error_code"] == "SCALAR_TYPE_MISMATCH"
    assert "value" not in result


def test_repository_get_tm_next_uses_bound_anchor_and_strictly_newer_event() -> None:
    repository = FakeRepository(
        snapshots=[_snapshot(1)], replays=[_replay(_sample_event(2, 6))]
    )
    request = _anchor_request()
    result = _runtime(repository).resolve(request)

    assert result["outcome"] == "OK"
    assert result["request_digest"] == request["request_digest"]
    assert result["evidence"]["source_sequence"] == "2"
    assert result["evidence"]["anchor"] == request["anchor"]
    assert repository.replay_calls[0]["after_sequence"] == 5


def test_repository_get_tm_next_preserves_gap_and_stale_generation() -> None:
    gap = {
        **_sample_event(3, 6),
        "event_type": "telemetry.gap_detected",
        "data": {
            "context_generation_id": CONTEXT_GENERATION,
            "item_id": ITEM_ID,
            "source_id": SOURCE_ID,
            "source_epoch": SOURCE_EPOCH,
            "expected_source_sequence": "2",
            "observed_source_sequence": "3",
        },
    }
    gap_result = _runtime(
        FakeRepository(snapshots=[_snapshot(1)], replays=[_replay(gap)])
    ).resolve(_anchor_request())
    assert gap_result["outcome"] == "GAP"
    assert gap_result["evidence"]["reason"] == "SOURCE_SEQUENCE_GAP"

    stale_snapshot = {
        **_snapshot(2),
        "context_generation_id": "replacement-generation",
    }
    stale_result = _runtime(FakeRepository(snapshots=[stale_snapshot])).resolve(
        _anchor_request()
    )
    assert stale_result["outcome"] == "STALE_GENERATION"


def test_repository_get_tm_next_deadline_is_bounded() -> None:
    clock = [0.0]
    wall_clock = [REQUESTED_AT_UNIX_NS]

    def sleep(seconds):
        clock[0] += seconds
        wall_clock[0] += int(seconds * 1_000_000_000)

    repository = FakeRepository(
        snapshots=[_snapshot(1), _snapshot(1), _snapshot(1)],
        replays=[_replay(), _replay(), _replay()],
    )
    resolver = RepositoryGetTMResolver(
        repository,
        lambda _execution_id: CONTEXT_ID,
        poll_seconds=0.5,
        monotonic=lambda: clock[0],
        wall_time_ns=lambda: wall_clock[0],
        sleeper=sleep,
    )
    result = resolver(_anchor_request())
    assert result["outcome"] == "DEADLINE_EXCEEDED"
    assert result["evidence"]["last_scanned_projection_sequence"] == "5"
    assert len(repository.replay_calls) == 2


def test_repository_get_tm_next_deadline_wins_when_replay_returns_at_deadline() -> None:
    clock = [0.0]
    wall_clock = [REQUESTED_AT_UNIX_NS]

    class DeadlineDuringReplay(FakeRepository):
        def replay(self, context_id, *, stream_epoch, after_sequence, limit):
            result = super().replay(
                context_id,
                stream_epoch=stream_epoch,
                after_sequence=after_sequence,
                limit=limit,
            )
            clock[0] = 1.0
            wall_clock[0] = REQUESTED_AT_UNIX_NS + 1_000_000_000
            return result

    repository = DeadlineDuringReplay(
        snapshots=[_snapshot(1)],
        replays=[_replay(_sample_event(2, 6))],
    )
    resolver = RepositoryGetTMResolver(
        repository,
        lambda _execution_id: CONTEXT_ID,
        monotonic=lambda: clock[0],
        wall_time_ns=lambda: wall_clock[0],
        sleeper=lambda _seconds: pytest.fail("deadline replay must not sleep"),
    )

    result = resolver(_anchor_request())

    assert result["outcome"] == "DEADLINE_EXCEEDED"
    assert result["error_code"] == "GET_TM_DEADLINE_EXCEEDED"
    assert result["evidence"]["last_scanned_projection_sequence"] == "5"
    assert len(repository.replay_calls) == 1


def test_repository_get_tm_next_replay_uses_the_persisted_deadline() -> None:
    request = _anchor_request()
    repository = FakeRepository()
    resolver = RepositoryGetTMResolver(
        repository,
        lambda _execution_id: CONTEXT_ID,
        monotonic=lambda: 0.0,
        wall_time_ns=lambda: REQUESTED_AT_UNIX_NS + 1_000_000_000,
        sleeper=lambda _seconds: pytest.fail("expired NEXT must not sleep"),
    )

    result = resolver(request)

    assert result["outcome"] == "DEADLINE_EXCEEDED"
    assert repository.snapshot_calls == []
    assert repository.replay_calls == []


def test_repository_get_tm_next_stops_when_execution_is_cancelled() -> None:
    clock = [0.0]
    wall_clock = [REQUESTED_AT_UNIX_NS]
    cancelled: set[str] = set()
    request = {**_anchor_request(), "resolver_generation": 7}
    repository = FakeRepository(
        snapshots=[_snapshot(1), _snapshot(1)],
        replays=[_replay(), _replay()],
    )

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        wall_clock[0] += int(seconds * 1_000_000_000)
        cancelled.add(request["execution_id"])

    resolver = RepositoryGetTMResolver(
        repository,
        lambda _execution_id: CONTEXT_ID,
        monotonic=lambda: clock[0],
        wall_time_ns=lambda: wall_clock[0],
        sleeper=sleep,
        cancellation_probe=lambda execution_id, generation: (
            generation == 7 and execution_id in cancelled
        ),
    )

    result = resolver(request)

    assert result["outcome"] == "CANCELLED"
    assert result["error_code"] == "GET_TM_CANCELLED"
    assert len(repository.replay_calls) == 1


def test_repository_get_tm_next_cancellation_wins_when_replay_returns_a_sample() -> None:
    cancelled = [False]
    request = {**_anchor_request(), "resolver_generation": 7}

    class CancellationDuringReplay(FakeRepository):
        def replay(self, context_id, *, stream_epoch, after_sequence, limit):
            result = super().replay(
                context_id,
                stream_epoch=stream_epoch,
                after_sequence=after_sequence,
                limit=limit,
            )
            cancelled[0] = True
            return result

    repository = CancellationDuringReplay(
        snapshots=[_snapshot(1)],
        replays=[_replay(_sample_event(2, 6))],
    )
    resolver = RepositoryGetTMResolver(
        repository,
        lambda _execution_id: CONTEXT_ID,
        monotonic=lambda: 0.0,
        wall_time_ns=lambda: REQUESTED_AT_UNIX_NS,
        sleeper=lambda _seconds: pytest.fail("cancelled replay must not sleep"),
        cancellation_probe=lambda _execution_id, generation: (
            generation != 7 or cancelled[0]
        ),
    )

    result = resolver(request)

    assert result["outcome"] == "CANCELLED"
    assert result["error_code"] == "GET_TM_CANCELLED"
    assert len(repository.replay_calls) == 1


def test_committed_snapshot_adapter_builds_one_atomic_condition_snapshot() -> None:
    repository = FakeRepository(snapshots=[_snapshot(1)])
    calls = []
    provider = CommittedObservationSnapshotProvider(
        repository,
        lambda operation_kind, operation_id: calls.append(
            (operation_kind, operation_id)
        )
        or CONTEXT_ID,
        expected_policy_revision="v07-r1",
    )
    result = provider(
        operation_kind="VERIFY",
        operation_id="a" * 64,
        condition_plan=_condition_plan(),
        after_snapshot_cursor=0,
    )
    assert result.snapshot_cursor == 5
    assert result.samples[0].sample_id == _sample(1)["sample_id"]
    assert result.samples[0].engineering_value.value == 10
    assert calls == [("VERIFY", "a" * 64)]


def _condition_plan() -> ConditionPlan:
    return ConditionPlan(
        "runtime-plan",
        PredicateNode(
            "runtime-predicate",
            ComparisonOperator.EQ,
            TelemetryOperand(ITEM_ID, CATALOG_DIGEST, ScalarType.INT64),
            LiteralOperand(TypedScalar(ScalarType.INT64, 10)),
        ),
    )


class StubConditionService:
    def __init__(self):
        self.calls = []

    def verify(self, **request):
        self.calls.append(("verify", request))
        return {"verify_id": "a" * 64, "state": "RETRY_WAIT", "revision": 1}

    def reconcile_verify(self, verify_id):
        self.calls.append(("reconcile_verify", verify_id))
        return {
            "verify_id": verify_id,
            "state": "TRUE",
            "revision": 2,
            "attempt_count": 2,
            "final_result": {"evaluation": {"composite_result": "TRUE"}},
        }

    def create_wait(self, **request):
        self.calls.append(("create_wait", request))
        return {"wait_id": "b" * 64, "state": "CREATED", "revision": 0}

    def reconcile_wait(self, wait_id):
        self.calls.append(("reconcile_wait", wait_id))
        return {
            "wait_id": wait_id,
            "state": "SATISFIED",
            "revision": 1,
            "wait_type": "RELATIVE",
            "original_target": {"duration_ns": 0},
        }


def test_procedure_runtime_drives_verify_and_wait_to_canonical_terminal_results() -> None:
    service = StubConditionService()
    runtime = ConditionProcedureRuntime(
        service,
        policy=QualityFreshnessPolicy("simulator-default", "v07-r1"),
        resolver_poll_seconds=0,
        sleeper=lambda _seconds: None,
    )
    verify = runtime.resolve(
        {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "request_id": "verify-runtime-1",
            "execution_id": "execution-runtime-1",
            "step_index": 2,
            "operation": "VERIFY",
            "parameters": {
                "condition": _condition_plan().as_dict(),
                "delay_seconds": 0,
                "timeout_seconds": 60,
                "retry_count": 1,
                "retry_interval_seconds": 0,
            },
        }
    )
    assert verify["outcome"] == "TRUE"
    assert verify["evidence"]["attempt_count"] == 2

    wait = runtime.resolve(
        {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "request_id": "wait-runtime-1",
            "execution_id": "execution-runtime-1",
            "step_index": 3,
            "operation": "WAIT_FOR",
            "parameters": {"seconds": 0},
        }
    )
    assert wait["outcome"] == "SATISFIED"
    assert [call[0] for call in service.calls] == [
        "verify",
        "reconcile_verify",
        "create_wait",
        "reconcile_wait",
    ]


class RecoveryService:
    def __init__(self):
        self.calls = []

    def recover_verifies(self, *, limit):
        self.calls.append(("verify", limit))
        return [{"state": "TRUE"}]

    def recover_waits(self, *, limit):
        self.calls.append(("wait", limit))
        return []

    def recover_telemetry_schedules(self, *, limit):
        self.calls.append(("schedule", limit))
        return [{"state": "FIRED"}]


def test_recovery_loop_and_occurrence_bound_starter_are_narrow_and_idempotent() -> None:
    service = RecoveryService()
    loop = ConditionRecoveryLoop(service, interval_seconds=0.01, batch_limit=7)
    assert loop.reconcile_once() == {"verifies": 1, "waits": 0, "schedules": 1}
    assert loop.status()["reconciled_operations"] == 2
    assert service.calls == [("verify", 7), ("wait", 7), ("schedule", 7)]

    calls = []
    starter = OccurrenceBoundExecutionStarter(
        lambda **request: calls.append(request) or "execution-created"
    )
    occurrence_id = "c" * 64
    assert starter(
        occurrence_id=occurrence_id,
        schedule={"occurrence_id": occurrence_id, "schedule_id": "d" * 64},
        condition_evidence={"composite_result": "TRUE", "result_digest": "e" * 64},
    ) == "execution-created"
    assert calls[0]["occurrence_id"] == occurrence_id
    with pytest.raises(Exception, match="TRUE evidence"):
        starter(
            occurrence_id=occurrence_id,
            schedule={"occurrence_id": occurrence_id},
            condition_evidence={"composite_result": "FALSE"},
        )


@pytest.fixture
def durable_condition_service(tmp_path):
    engine, factory = create_database(
        f"sqlite:///{(tmp_path / 'runtime-conditions.db').as_posix()}"
    )
    run_migrations(engine)
    if not inspect(engine).has_table("condition_plans"):
        with engine.begin() as connection:
            v0006_observation_conditions.upgrade(connection)
    service = ConditionService(
        factory,
        snapshot_provider=lambda **_request: pytest.fail(
            "delayed lifecycle operations must not capture a snapshot"
        ),
    )
    try:
        yield service
    finally:
        engine.dispose()


def _delayed_operations(service: ConditionService, suffix: str):
    verify = service.verify(
        plan=_condition_plan(),
        policy=QualityFreshnessPolicy("simulator-default", "v07-r1"),
        delay_seconds=60,
        timeout_seconds=120,
        request_scope=f"execution-{suffix}",
        idempotency_key=f"verify-{suffix}",
    )
    wait = service.create_wait(
        execution_id=f"execution-{suffix}",
        statement_id=f"statement-{suffix}",
        wait_type="RELATIVE",
        target=60,
        idempotency_key=f"wait-{suffix}",
    )
    return verify, wait


def test_execution_lifecycle_hooks_pause_resume_and_idempotently_cancel(
    durable_condition_service,
) -> None:
    service = durable_condition_service
    verify, wait = _delayed_operations(service, "lifecycle")
    lifecycle = ConditionExecutionLifecycle(service)

    interrupted = lifecycle.interrupt_execution("execution-lifecycle")
    assert interrupted["affected_count"] == 1
    assert interrupted["waits"][0]["state"] == "INTERRUPTED"
    assert service.get_verify(verify["verify_id"])["state"] == "DELAYED"
    assert lifecycle.interrupt_execution("execution-lifecycle")["affected_count"] == 0

    resumed = lifecycle.resume_execution("execution-lifecycle")
    assert resumed["waits"][0]["state"] == "WAITING"
    assert lifecycle.resume_execution("execution-lifecycle")["affected_count"] == 0
    lifecycle.interrupt_execution("execution-lifecycle")

    cancelled = lifecycle.cancel_execution("execution-lifecycle")
    assert {item["state"] for item in cancelled["waits"]} == {"CANCELLED"}
    assert {item["state"] for item in cancelled["verifies"]} == {"CANCELLED"}
    assert service.get_wait(wait["wait_id"])["state"] == "CANCELLED"
    assert lifecycle.cancel_execution("execution-lifecycle")["affected_count"] == 0


def test_durable_execution_cancellation_probe_tracks_terminal_state(
    durable_condition_service,
) -> None:
    factory = durable_condition_service.session_factory
    with factory() as session:
        session.add(
            Execution(
                id="execution-cancellation-probe",
                procedure_id="probe",
                procedure_name="Probe",
                procedure_hash="a" * 64,
                procedure_source="",
                steps=[],
                ir_version="0.7",
                variables={},
                context_id="simulator",
                created_by="operator",
                creation_idempotency_key="cancellation-probe",
                state="running",
                revision=1,
                current_step=0,
                total_steps=0,
                worker_generation=1,
                next_sequence=1,
            )
        )
        session.commit()
    probe = DurableExecutionCancellationProbe(factory)
    assert probe("execution-cancellation-probe", 1) is False

    with factory() as session:
        execution = session.get(Execution, "execution-cancellation-probe")
        execution.worker_generation = 2
        session.commit()

    assert probe("execution-cancellation-probe", 1) is True
    assert probe("execution-cancellation-probe", 2) is False

    with factory() as session:
        execution = session.get(Execution, "execution-cancellation-probe")
        execution.state = "aborted"
        session.commit()

    assert probe("execution-cancellation-probe", 2) is True


def test_execution_interrupt_accepts_a_concurrent_cas_winner(
    durable_condition_service, monkeypatch
) -> None:
    service = durable_condition_service
    _verify, wait = _delayed_operations(service, "race")
    original = service.interrupt_wait
    raced = False

    def concurrent_winner(wait_id, *, expected_revision):
        nonlocal raced
        if not raced:
            raced = True
            original(wait_id, expected_revision=expected_revision)
        return original(wait_id, expected_revision=expected_revision)

    monkeypatch.setattr(service, "interrupt_wait", concurrent_winner)
    result = ConditionExecutionLifecycle(service).interrupt_execution("execution-race")
    assert result["waits"][0]["wait_id"] == wait["wait_id"]
    assert result["waits"][0]["state"] == "INTERRUPTED"
