from __future__ import annotations

import math
import inspect
from pathlib import Path

import pytest

from scripts.qualify_performance_v04 import (
    CANCELLATION_COUNT,
    HEALTH_COUNT,
    LIFECYCLE_COUNT,
    RESTART_COUNT,
    SOAK_DURATION_SECONDS,
    SOAK_MINIMUM_COUNT,
    _assertion,
    _gate,
    build_parser,
    child_process_ids,
    linear_slope,
    percentile,
    resident_memory_bytes,
)
from scripts.validate_release_evidence_v04 import (
    _validate_perf_001,
    _validate_perf_002,
    _validate_perf_003,
    _validate_perf_004,
)


def test_release_workload_cardinalities_and_duration_are_not_reducible() -> None:
    assert HEALTH_COUNT == 1_000
    assert LIFECYCLE_COUNT == 1_000
    assert CANCELLATION_COUNT == 100
    assert RESTART_COUNT == 25
    assert SOAK_DURATION_SECONDS == 600.0
    assert SOAK_MINIMUM_COUNT == 12_000
    parser = build_parser()
    assert not any(
        action.dest.endswith(("count", "rate", "duration_seconds"))
        for action in parser._actions
    )


def test_percentile_uses_nearest_rank_and_rejects_empty_or_bad_quantiles() -> None:
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.50) == 2.0
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.95) == 4.0
    assert math.isinf(percentile([], 0.95))
    with pytest.raises(ValueError):
        percentile([1.0], 0.0)


def test_linear_slope_reports_y_units_per_x_unit() -> None:
    assert linear_slope([]) == 0.0
    assert linear_slope([(1.0, 2.0)]) == 0.0
    assert linear_slope([(0.0, 10.0), (1.0, 12.0), (2.0, 14.0)]) == 2.0


def test_proc_sampler_has_no_cli_child_and_child_scan_is_deduplicated(
    tmp_path: Path,
) -> None:
    for task_id, children in (("1", "12 14\n"), ("2", "14 19\n")):
        task = tmp_path / "42" / "task" / task_id
        task.mkdir(parents=True)
        (task / "children").write_text(children, encoding="ascii")
    assert child_process_ids(tmp_path, pid=42) == (12, 14, 19)
    sampler_source = inspect.getsource(resident_memory_bytes)
    assert "subprocess" not in sampler_source
    assert "docker" not in sampler_source.casefold()


def test_gate_fails_closed_when_any_assertion_fails() -> None:
    gate = _gate(
        "V04-PERF-001",
        "test",
        {},
        [
            _assertion("one", True, observed=1, threshold=1),
            _assertion("two", False, observed=2, threshold=1),
        ],
    )
    assert gate["executed"] is True
    assert gate["passed"] is False


def test_emitted_metric_contracts_are_accepted_by_release_validator() -> None:
    _validate_perf_001(
        {
            "sample_count": 1_000,
            "duration_seconds": 9.5,
            "achieved_rate_per_second": 105.263,
            "p95_ms": 10.0,
            "max_ms": 20.0,
            "error_count": 0,
        },
        "perf001",
        "unused",
    )
    _validate_perf_002(
        {
            "operation_count": 1_000,
            "duration_seconds": 48.75,
            "achieved_rate_per_second": 20.513,
            "acceptance_p95_ms": 10.0,
            "terminal_p95_ms": 20.0,
            "duplicate_effect_count": 0,
            "stuck_operation_count": 0,
            "error_count": 0,
        },
        "perf002",
        "unused",
    )
    _validate_perf_003(
        {
            "cancellation_count": 100,
            "cancel_p95_ms": 10.0,
            "cancel_max_ms": 20.0,
            "restart_count": 25,
            "readiness_max_ms": 100.0,
            "reconciliation_max_ms": 150.0,
            "target_certainty_change_count": 0,
            "duplicate_effect_count": 0,
            "stuck_operation_count": 0,
            "error_count": 0,
        },
        "perf003",
        "unused",
    )
    _validate_perf_004(
        {
            "operation_count": 12_120,
            "duration_seconds": 600.0,
            "achieved_rate_per_second": 20.2,
            "loss_count": 0,
            "duplicate_effect_count": 0,
            "stuck_operation_count": 0,
            "crash_count": 0,
            "post_warmup_growth_mib": 1.0,
            "post_warmup_slope_mib_per_minute": 0.1,
        },
        "perf004",
        "unused",
    )
