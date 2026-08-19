from __future__ import annotations

import copy
import unittest
from pathlib import Path

from scripts.compose_qualification import compose_reports
from scripts.source_fingerprint import source_fingerprint_inputs


FINGERPRINT = "a" * 64


def integrity(count: int) -> dict:
    return {
        "exact": True,
        "received_count": count,
        "expected_count": count,
        "duplicate_count": 0,
        "missing_count": 0,
        "unexpected_count": 0,
    }


def reader(count: int) -> dict:
    return {"error": None, "sequence_integrity": integrity(count)}


def browser_reader(count: int) -> dict:
    return {
        **reader(count),
        "sentinel_received": True,
        "subscription_ready_at_ms": 500.0,
        "first_sequence_at_ms": 1000.0,
        "first_data_at_ms": 1000.0,
        "last_data_at_ms": 61_000.0,
        "data_event_count": 6001,
        "sentinel_at_ms": 61_000.0,
        "delivery_elapsed_seconds": 60.0,
        "achieved_events_per_second": 100.0167,
    }


def passing_reports() -> tuple[dict, dict, dict]:
    source = {"fingerprint_sha256": FINGERPRINT}
    quick = {
        "schema_version": "1.0",
        "product_version": "0.3.0",
        "profile": "quick",
        "source": source,
        "environment": {},
        "overall_pass": True,
        "acceptance_complete": False,
        "gates": {
            "rest_mutations": {
                "test_id": "V03-PERF-001",
                "passed": True,
                "primary_mutations": 100,
                "primary_p95_ms": 20.0,
                "idempotent_retries": 100,
                "status_codes": [202],
                "retry_status_codes": [202],
                "retry_identity_mismatches": 0,
                "unique_command_ids": 100,
                "stored_command_count": 100,
                "durable_command_states": {"completed": 100},
                "workers_drained": True,
            },
            "event_replay": {
                "test_id": "V03-PERF-002",
                "passed": True,
                "event_count": 10_000,
                "replay_seconds": 0.2,
                "payloads_exact": True,
                "sequence_integrity": integrity(10_000),
            },
            "eventhub_fanout": {
                "test_id": "V03-PERF-003A",
                "passed": True,
                "target_events_per_second": 100.0,
                "target_duration_seconds": 60.0,
                "event_count_excluding_sentinel": 6001,
                "production_elapsed_seconds": 60.0,
                "measured_duration_seconds": 60.1,
                "achieved_events_per_second": 100.017,
                "schedule_p95_ms": 2.0,
                "schedule_max_ms": 10.0,
                "clients": 2,
                "producer_errors": [],
                "client_queue_overflowed": [False, False],
                "persisted_sequence_integrity": integrity(6002),
                "reader_results": [reader(6002), reader(6002)],
            },
        },
    }
    soak = {
        "schema_version": "1.0",
        "product_version": "0.3.0",
        "profile": "soak",
        "source": source,
        "environment": {},
        "overall_pass": True,
        "acceptance_complete": False,
        "gates": {
            "soak": {
                "test_id": "V03-PERF-004",
                "passed": True,
                "target_events_per_second": 20.0,
                "target_duration_seconds": 600.0,
                "event_count": 12_001,
                "production_elapsed_seconds": 600.0,
                "measured_duration_seconds": 600.1,
                "achieved_events_per_second": 20.002,
                "schedule_p95_ms": 2.0,
                "schedule_max_ms": 10.0,
                "producer_errors": [],
                "control_failures": [],
                "sequence_integrity": integrity(12_001),
                "memory_measurement": {
                    "post_warmup_growth_mib": 2.0,
                    "post_warmup_slope_mib_per_minute": 0.2,
                },
            }
        },
    }
    browser = {
        "schema_version": "1.0",
        "product_version": "0.3.0",
        "profile": "browser-stream",
        "test_id": "V03-PERF-003",
        "source": source,
        "environment": {},
        "passed": True,
        "overall_pass": True,
        "acceptance_complete": False,
        "target_events_per_second": 100.0,
        "target_duration_seconds": 60.0,
        "event_count_excluding_sentinel": 6001,
        "producer": {
            "state": "finished",
            "errors": [],
            "produced_event_count": 6001,
            "production_elapsed_seconds": 60.0,
            "elapsed_seconds": 60.1,
            "achieved_events_per_second": 100.017,
            "schedule_p95_ms": 2.0,
            "schedule_max_ms": 10.0,
            "persisted_sequence_integrity": integrity(6002),
        },
        "reader_results": [browser_reader(6002), browser_reader(6002)],
    }
    return quick, soak, browser


class QualificationCompositionTests(unittest.TestCase):
    def test_accepts_complete_measured_contract(self) -> None:
        quick, soak, browser = passing_reports()
        report = compose_reports(
            quick,
            soak,
            browser,
            {"quick": "quick.json", "soak": "soak.json", "browser": "browser.json"},
        )
        self.assertTrue(report["overall_pass"])
        self.assertTrue(report["acceptance_complete"])
        self.assertEqual(
            set(report["validated_test_ids"]),
            {
                "V03-PERF-001",
                "V03-PERF-002",
                "V03-PERF-003",
                "V03-PERF-003A",
                "V03-PERF-004",
            },
        )

    def test_rejects_slow_browser_delivery_even_when_passed_is_true(self) -> None:
        quick, soak, browser = passing_reports()
        altered = copy.deepcopy(browser)
        altered["reader_results"][0].update(
            {
                "last_data_at_ms": 62_100.0,
                "sentinel_at_ms": 62_100.0,
                "delivery_elapsed_seconds": 61.1,
                "achieved_events_per_second": 98.216,
            }
        )
        with self.assertRaisesRegex(ValueError, "delivery duration|delivery throughput"):
            compose_reports(quick, soak, altered, {})

    def test_rejects_browser_data_before_subscription_readiness(self) -> None:
        quick, soak, browser = passing_reports()
        browser["reader_results"][0]["subscription_ready_at_ms"] = 1001.0
        with self.assertRaisesRegex(ValueError, "before subscription readiness"):
            compose_reports(quick, soak, browser, {})

    def test_rejects_slow_soak_even_when_passed_is_true(self) -> None:
        quick, soak, browser = passing_reports()
        altered = copy.deepcopy(soak)
        altered["gates"]["soak"].update(
            {
                "production_elapsed_seconds": 601.0,
                "measured_duration_seconds": 601.0,
                "achieved_events_per_second": 19.968,
            }
        )
        with self.assertRaisesRegex(ValueError, "throughput"):
            compose_reports(quick, altered, browser, {})

    def test_rejects_burst_production_even_when_elapsed_window_is_reported(self) -> None:
        quick, soak, browser = passing_reports()
        altered = copy.deepcopy(quick)
        gate = altered["gates"]["eventhub_fanout"]
        gate.update(
            {
                "production_elapsed_seconds": 1.0,
                "achieved_events_per_second": 6001.0,
            }
        )
        with self.assertRaisesRegex(ValueError, "production duration"):
            compose_reports(altered, soak, browser, {})

    def test_rejects_integrity_counts_detached_from_measured_workload(self) -> None:
        quick, soak, browser = passing_reports()
        altered = copy.deepcopy(quick)
        altered["gates"]["event_replay"]["sequence_integrity"] = integrity(1)
        with self.assertRaisesRegex(ValueError, "measured workload"):
            compose_reports(altered, soak, browser, {})

    def test_rejects_missing_idempotent_retries(self) -> None:
        quick, soak, browser = passing_reports()
        altered = copy.deepcopy(quick)
        altered["gates"]["rest_mutations"]["idempotent_retries"] = 0
        with self.assertRaisesRegex(ValueError, "idempotent retry count"):
            compose_reports(altered, soak, browser, {})

    def test_rejects_wrong_component_identity(self) -> None:
        quick, soak, browser = passing_reports()
        quick["gates"]["eventhub_fanout"]["test_id"] = "V03-PERF-003"
        with self.assertRaisesRegex(ValueError, "test id"):
            compose_reports(quick, soak, browser, {})

    def test_fingerprint_manifest_covers_browser_and_release_implementations(self) -> None:
        root = Path(__file__).resolve().parents[2]
        relative = {
            path.relative_to(root).as_posix() for path in source_fingerprint_inputs(root)
        }
        for required in {
            "frontend/scripts/qualify-browser-stream.mjs",
            "frontend/package-lock.json",
            "scripts/compose_qualification.py",
            "scripts/qualification.Dockerfile",
            "scripts/qualify_release.ps1",
            "compose.yaml",
        }:
            self.assertIn(required, relative)


if __name__ == "__main__":
    unittest.main()
