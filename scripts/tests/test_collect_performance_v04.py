from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.collect_performance_v04 import (
    PerformanceCollectorError,
    QUICK_IDS,
    extract_result,
)
from scripts.validate_release_evidence_v04 import PRODUCT_VERSION, SCOPE_PROFILE


SOURCE = "a" * 64


def _metrics(test_id: str) -> dict[str, object]:
    if test_id == "V04-PERF-001":
        return {
            "sample_count": 1_000,
            "duration_seconds": 10.0,
            "achieved_rate_per_second": 100.0,
            "p95_ms": 2.0,
            "max_ms": 4.0,
            "error_count": 0,
        }
    if test_id == "V04-PERF-002":
        return {
            "operation_count": 1_000,
            "duration_seconds": 50.0,
            "achieved_rate_per_second": 20.0,
            "acceptance_p95_ms": 2.0,
            "terminal_p95_ms": 4.0,
            "duplicate_effect_count": 0,
            "stuck_operation_count": 0,
            "error_count": 0,
        }
    if test_id == "V04-PERF-003":
        return {
            "cancellation_count": 100,
            "cancel_p95_ms": 2.0,
            "cancel_max_ms": 4.0,
            "restart_count": 25,
            "readiness_max_ms": 10.0,
            "reconciliation_max_ms": 12.0,
            "target_certainty_change_count": 0,
            "duplicate_effect_count": 0,
            "stuck_operation_count": 0,
            "error_count": 0,
        }
    return {
        "operation_count": 12_000,
        "duration_seconds": 600.0,
        "achieved_rate_per_second": 20.0,
        "loss_count": 0,
        "duplicate_effect_count": 0,
        "stuck_operation_count": 0,
        "crash_count": 0,
        "post_warmup_growth_mib": 1.0,
        "post_warmup_slope_mib_per_minute": 0.1,
    }


def _write_report(path: Path, profile: str, source: str = SOURCE) -> None:
    ids = QUICK_IDS if profile == "quick" else {"V04-PERF-004"}
    report = {
        "schema_version": "spell.v04.performance-qualification/1",
        "product_version": PRODUCT_VERSION,
        "scope_profile": SCOPE_PROFILE,
        "profile": profile,
        "overall_pass": True,
        "acceptance_complete": False,
        "source": {
            "fingerprint_sha256": source,
            "fingerprint_after_sha256": source,
            "stable_during_run": True,
        },
        "runtime": {
            "initial_child_process_ids": [],
            "final_child_process_ids": [],
            "residual_child_process_ids": [],
            "process_sampling": "in-process /proc/self/statm; no CLI observer",
            "qualification_image_id": "sha256:" + "b" * 64,
        },
        "gates": {
            test_id: {
                "test_id": test_id,
                "executed": True,
                "passed": True,
                "assertions": [{"id": f"{test_id.lower()}-passed", "passed": True}],
                "metrics": _metrics(test_id),
            }
            for test_id in ids
        },
    }
    path.write_text(json.dumps(report), encoding="utf-8")


@pytest.mark.parametrize("test_id", sorted(QUICK_IDS))
def test_extracts_each_gate_only_from_a_complete_quick_report(tmp_path: Path, test_id: str) -> None:
    report = tmp_path / "quick.json"
    _write_report(report, "quick")
    result = extract_result(report, test_id, SOURCE)
    assert result["test_id"] == test_id
    assert result["source_fingerprint_sha256"] == SOURCE
    assert result["assertions"][0]["passed"] is True


def test_extracts_the_full_soak_and_rejects_stale_or_partial_reports(tmp_path: Path) -> None:
    report = tmp_path / "soak.json"
    _write_report(report, "soak")
    assert extract_result(report, "V04-PERF-004", SOURCE)["metrics"]["operation_count"] == 12_000

    value = json.loads(report.read_text(encoding="utf-8"))
    value["source"]["fingerprint_after_sha256"] = "c" * 64
    report.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PerformanceCollectorError, match="source binding is stale"):
        extract_result(report, "V04-PERF-004", SOURCE)

    _write_report(report, "quick")
    value = json.loads(report.read_text(encoding="utf-8"))
    value["gates"].pop("V04-PERF-003")
    report.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PerformanceCollectorError, match="gate set is incomplete"):
        extract_result(report, "V04-PERF-001", SOURCE)
