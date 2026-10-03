"""Closed snapshot inputs for independent worker/service language qualification.

The fixture supplies data to the production repository resolver, condition
service and v19 result filter. Expected outcomes live in the separate case
registry. It never accesses an outer execution, driver or command dispatcher.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .bundled_observation_catalog import CATALOG_DIGEST

ITEM_ID = "TM.POWER.BUS_VOLTAGE"
POLICY_REVISION = "v07-r1"
SOURCE_ID = "bundled-deterministic-simulator"
SOURCE_EPOCH = "language-v19-source"


def condition(expected: float = 27.5) -> dict:
    return {"condition_plan_id": f"language-v19-voltage-ge-{expected}", "root": {
        "type": "PREDICATE", "node_id": "voltage-acceptable", "operator": "GE",
        "left": {"kind": "TELEMETRY", "item_id": ITEM_ID,
                 "catalog_digest": CATALOG_DIGEST, "scalar_type": "FINITE_DOUBLE",
                 "value_field": "ENGINEERING"},
        "right": {"kind": "LITERAL", "value": {"type": "FINITE_DOUBLE", "value": expected}},
    }}


class _SnapshotInput:
    def __init__(self, kind: str) -> None:
        from .condition_engine import sample_id_for
        kinds = {"nominal", "low", "missing", "stale", "invalid", "bad-quality",
                 "gap", "policy", "clock"}
        if kind not in kinds:
            raise ValueError("unknown fixed observation input")
        value = 14.0 if kind == "low" else 28.0
        sample = {
            "sample_id": sample_id_for(SOURCE_ID, SOURCE_EPOCH, ITEM_ID, 1),
            "observation_id": "language-v19-observation-1",
            "context_generation_id": "language-v19-context",
            "item_id": ITEM_ID, "qualified_name": "SIM.POWER.BUS_VOLTAGE",
            "catalog_digest": CATALOG_DIGEST,
            "source_id": SOURCE_ID, "source_epoch": SOURCE_EPOCH, "source_sequence": "1",
            "raw_value": {"type": "FINITE_DOUBLE", "value": value},
            "engineering_value": {"type": "FINITE_DOUBLE", "value": value},
            "description": "Closed language qualification input", "unit": "V",
            "acquired_at_unix_ns": "1000000000", "received_at_unix_ns": "1000000100",
            "received_at": "2026-10-03T12:00:00+00:00", "source": SOURCE_ID,
            "clock_provenance": "closed-language-input", "clock_uncertainty_ns": "1000",
            "validity": "INVALID" if kind == "invalid" else "VALID",
            "quality": "BAD" if kind == "bad-quality" else "GOOD",
            "quality_reason": "closed-language-input",
            "freshness": "STALE" if kind == "stale" else "FRESH",
            "freshness_policy_revision": "different-policy" if kind == "policy" else POLICY_REVISION,
            "synchronization_state": "GAPPED" if kind == "gap" else "COMPLETE",
            "alarm": None,
        }
        self.snapshot_input = {
            "schema_version": "spell.driver.observation.snapshot/1",
            "stream": "driver.observation", "stream_epoch": "language-v19-stream",
            "through_sequence": "5", "snapshot_at_database_time": "2026-10-03T12:00:00+00:00",
            "context_id": "simulator", "context_generation_id": "language-v19-context",
            "source_epochs": [] if kind == "missing" else [{
                "source_id": SOURCE_ID, "item_id": ITEM_ID, "source_epoch": SOURCE_EPOCH,
                "last_source_sequence": "1", "synchronization_state": sample["synchronization_state"],
            }],
            "items": [] if kind == "missing" else [sample],
            "driver_time": {"uncertainty_ns": "2000000000" if kind == "clock" else "1000",
                            "validity": "VALID", "quality": "GOOD"},
            "synchronization_state": "GAPPED" if kind == "gap" else "COMPLETE",
        }

    def snapshot(self, context_id: str) -> dict:
        if context_id != "simulator":
            raise ValueError("closed fixture context differs")
        return deepcopy(self.snapshot_input)


class ObservationFixture:
    def __init__(self, kind: str = "nominal") -> None:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from .condition_engine import QualityFreshnessPolicy
        from .condition_runtime import (CommittedObservationSnapshotProvider,
            ConditionProcedureRuntime, RepositoryGetTMResolver)
        from .condition_service import ConditionService
        from .database import Base
        from . import models as _models
        self.engine = create_engine("sqlite+pysqlite://",
            connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        sessions = sessionmaker(self.engine, expire_on_commit=False)
        repository = _SnapshotInput(kind)
        snapshots = CommittedObservationSnapshotProvider(repository,
            lambda _kind, _identity: "simulator", expected_policy_revision=POLICY_REVISION)
        self.service = ConditionService(sessions, snapshot_provider=snapshots)
        resolver = RepositoryGetTMResolver(repository, lambda _execution: "simulator",
            known_item_ids=frozenset({ITEM_ID}))
        self.runtime = ConditionProcedureRuntime(self.service,
            policy=QualityFreshnessPolicy("simulator-default", POLICY_REVISION),
            get_tm_resolver=resolver, resolver_poll_seconds=0.001,
            wait_retry_interval_seconds=0.001)

    def resolve(self, request: dict) -> dict:
        from .runtime_composition_v19 import filter_observation_result
        result = dict(self.runtime.resolve(request))
        return filter_observation_result(request, result,
                                         expected_policy_revision=POLICY_REVISION)

    def close(self) -> None:
        self.engine.dispose()


def observation_summary(request: dict, result: dict) -> dict[str, Any]:
    from .ir_v07 import validate_observation_result
    value = validate_observation_result(request, result)
    return {"operation": request["operation"], "outcome": value["outcome"],
            "value": value.get("value")}
