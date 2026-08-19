from scripts.qualify_v03 import (
    linear_slope,
    percentile,
    scheduled_event_count,
    sequence_integrity,
    timing_metrics,
)


def test_percentile_uses_nearest_rank() -> None:
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.50) == 2.0
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.95) == 4.0


def test_sequence_integrity_reports_order_gaps_duplicates_and_unexpected_values() -> None:
    exact = sequence_integrity([3, 4, 5], 3, 5)
    assert exact["exact"] is True

    broken = sequence_integrity([3, 5, 5, 7], 3, 6)
    assert broken["exact"] is False
    assert broken["duplicate_examples"] == [5]
    assert broken["missing_examples"] == [4, 6]
    assert broken["unexpected_examples"] == [7]


def test_linear_slope_reports_units_per_x_unit() -> None:
    assert linear_slope([(0.0, 10.0), (1.0, 12.0), (2.0, 14.0)]) == 2.0
    assert linear_slope([(1.0, 4.0)]) == 0.0


def test_inclusive_schedule_and_actual_timing_gate() -> None:
    assert scheduled_event_count(100.0, 60.0) == 6001
    assert scheduled_event_count(20.0, 600.0) == 12_001

    passing = timing_metrics(6001, 60.0, 60.1, 100.0, 60.0, [1.0, 2.0, 3.0])
    assert passing["passed"] is True
    assert passing["achieved_events_per_second"] >= 100.0

    slow = timing_metrics(6001, 61.0, 61.0, 100.0, 60.0, [1.0, 2.0, 3.0])
    assert slow["passed"] is False

    lagged = timing_metrics(6001, 60.0, 60.1, 100.0, 60.0, [1.0, 1001.0])
    assert lagged["passed"] is False

    burst = timing_metrics(6001, 1.0, 60.0, 100.0, 60.0, [1.0, 2.0, 3.0])
    assert burst["passed"] is False
