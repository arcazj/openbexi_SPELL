#!/usr/bin/env python3
"""Validate and compose final v0.3 qualification evidence."""

from __future__ import annotations

import argparse
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


COMPONENT_SCHEMA_VERSION = "1.0"
RELEASE_SCHEMA_VERSION = "1.1"
PRODUCT_VERSION = "0.3.0"
REST_P95_LIMIT_MS = 250.0
REPLAY_LIMIT_SECONDS = 3.0
SCHEDULE_P95_LIMIT_MS = 250.0
SCHEDULE_MAX_LIMIT_MS = 1000.0
ELAPSED_OVERRUN_LIMIT_SECONDS = 1.0
EXPECTED_TEST_IDS = {
    "V03-PERF-001",
    "V03-PERF-002",
    "V03-PERF-003",
    "V03-PERF-003A",
    "V03-PERF-004",
}


def load(path: Path) -> dict[str, Any]:
    value = parse_json_document(path.read_text(encoding="utf-8"), str(path))
    if not isinstance(value, dict):
        raise ValueError(f"qualification report is not an object: {path}")
    return value


def parse_json_document(text: str, label: str) -> Any:
    """Parse standards-compliant JSON without ambiguous duplicate object keys."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} contains duplicate object key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains non-finite JSON number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _number(mapping: dict[str, Any], key: str, label: str) -> float:
    value = mapping.get(key)
    _require(
        isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value),
        f"{label}.{key} must be a finite number",
    )
    return float(value)


def _integer(mapping: dict[str, Any], key: str, label: str) -> int:
    value = mapping.get(key)
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label}.{key} must be an integer",
    )
    return value


def _validate_integrity(
    value: Any, label: str, expected_count: int | None = None
) -> None:
    integrity = _mapping(value, label)
    _require(integrity.get("exact") is True, f"{label} is not exact")
    for key in ("duplicate_count", "missing_count", "unexpected_count"):
        _require(_integer(integrity, key, label) == 0, f"{label}.{key} must be zero")
    received_count = _integer(integrity, "received_count", label)
    reported_expected_count = _integer(integrity, "expected_count", label)
    _require(
        received_count == reported_expected_count,
        f"{label} received/expected counts differ",
    )
    if expected_count is not None:
        _require(
            reported_expected_count == expected_count,
            f"{label} count does not match the measured workload",
        )


def _validate_source(report: dict[str, Any], label: str) -> str:
    source = _mapping(report.get("source"), f"{label}.source")
    fingerprint = source.get("fingerprint_sha256")
    _require(
        isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint) is not None,
        f"{label} source fingerprint is invalid",
    )
    return fingerprint


def _validate_component(
    report: dict[str, Any], label: str, profile: str, expected_gate_names: set[str]
) -> tuple[dict[str, Any], str]:
    _require(
        report.get("schema_version") == COMPONENT_SCHEMA_VERSION,
        f"{label} schema version is not {COMPONENT_SCHEMA_VERSION}",
    )
    _require(report.get("product_version") == PRODUCT_VERSION, f"{label} product version differs")
    _require(report.get("profile") == profile, f"{label} profile must be {profile}")
    _require(report.get("overall_pass") is True, f"{label} did not pass")
    _require(
        report.get("acceptance_complete") is False,
        f"{label} must not claim complete release acceptance",
    )
    gates = _mapping(report.get("gates"), f"{label}.gates")
    _require(set(gates) == expected_gate_names, f"{label} gate set is invalid")
    return gates, _validate_source(report, label)


def _validate_gate(gate: Any, label: str, test_id: str) -> dict[str, Any]:
    value = _mapping(gate, label)
    _require(value.get("test_id") == test_id, f"{label} test id must be {test_id}")
    _require(value.get("passed") is True, f"{label} did not pass")
    return value


def _validate_timing(
    gate: dict[str, Any],
    label: str,
    event_count_key: str,
    minimum_event_count: int,
    target_rate: float,
    target_duration: float,
) -> None:
    event_count = _integer(gate, event_count_key, label)
    production_elapsed = _number(gate, "production_elapsed_seconds", label)
    measured_duration = _number(gate, "measured_duration_seconds", label)
    achieved_rate = _number(gate, "achieved_events_per_second", label)
    _require(event_count >= minimum_event_count, f"{label} event count is below threshold")
    _require(production_elapsed > 0, f"{label} production elapsed time must be positive")
    recomputed_rate = event_count / production_elapsed
    _require(
        achieved_rate >= target_rate and abs(achieved_rate - recomputed_rate) <= 0.01,
        f"{label} actual throughput is below threshold or inconsistent",
    )
    _require(
        target_duration * 0.999
        <= production_elapsed
        <= target_duration + ELAPSED_OVERRUN_LIMIT_SECONDS,
        f"{label} production duration is outside the accepted window",
    )
    _require(
        target_duration * 0.999
        <= measured_duration
        <= target_duration + ELAPSED_OVERRUN_LIMIT_SECONDS,
        f"{label} measured duration is outside the accepted window",
    )
    _require(
        0 <= _number(gate, "schedule_p95_ms", label) <= SCHEDULE_P95_LIMIT_MS,
        f"{label} schedule p95 exceeds threshold",
    )
    _require(
        0 <= _number(gate, "schedule_max_ms", label) <= SCHEDULE_MAX_LIMIT_MS,
        f"{label} schedule maximum exceeds threshold",
    )


def _validate_rest(gate: Any) -> str:
    value = _validate_gate(gate, "quick.rest_mutations", "V03-PERF-001")
    primary = _integer(value, "primary_mutations", "quick.rest_mutations")
    _require(primary >= 100, "REST mutation count is below threshold")
    _require(
        0
        <= _number(value, "primary_p95_ms", "quick.rest_mutations")
        <= REST_P95_LIMIT_MS,
        "REST p95 exceeds threshold",
    )
    _require(value.get("status_codes") == [202], "REST status codes are not exactly [202]")
    _require(value.get("retry_status_codes") == [202], "REST retry status codes are invalid")
    _require(
        _integer(value, "idempotent_retries", "quick.rest_mutations") == primary,
        "REST idempotent retry count differs",
    )
    _require(
        _integer(value, "retry_identity_mismatches", "quick.rest_mutations") == 0,
        "REST retry identity mismatch detected",
    )
    for key in ("unique_command_ids", "stored_command_count"):
        _require(_integer(value, key, "quick.rest_mutations") == primary, f"REST {key} differs")
    states = _mapping(value.get("durable_command_states"), "quick.rest_mutations states")
    _require(states == {"completed": primary}, "REST durable command states differ")
    _require(value.get("workers_drained") is True, "REST workers were not drained")
    return str(value["test_id"])


def _validate_replay(gate: Any) -> str:
    value = _validate_gate(gate, "quick.event_replay", "V03-PERF-002")
    event_count = _integer(value, "event_count", "quick.event_replay")
    _require(event_count >= 10_000, "replay is too small")
    _require(
        0 <= _number(value, "replay_seconds", "quick.event_replay") <= REPLAY_LIMIT_SECONDS,
        "replay exceeded duration threshold",
    )
    _require(value.get("payloads_exact") is True, "replay payloads differ")
    _validate_integrity(
        value.get("sequence_integrity"),
        "quick.event_replay integrity",
        event_count,
    )
    return str(value["test_id"])


def _validate_stream_readers(
    value: dict[str, Any],
    label: str,
    minimum_clients: int = 2,
    delivery_event_count: float | None = None,
    target_rate: float | None = None,
    target_duration: float | None = None,
    expected_integrity_count: int | None = None,
    expected_clients: int | None = None,
) -> None:
    readers = value.get("reader_results")
    _require(
        isinstance(readers, list) and len(readers) >= minimum_clients,
        f"{label} readers missing",
    )
    if expected_clients is not None:
        _require(len(readers) == expected_clients, f"{label} reader count differs")
    for index, reader_value in enumerate(readers):
        reader = _mapping(reader_value, f"{label}.reader[{index}]")
        _require(reader.get("error") is None, f"{label}.reader[{index}] reported an error")
        if "sentinel_received" in reader:
            _require(
                reader.get("sentinel_received") is True,
                f"{label}.reader[{index}] missed sentinel",
            )
        if delivery_event_count is not None:
            _require(
                target_rate is not None and target_duration is not None,
                f"{label} delivery timing contract is incomplete",
            )
            _require(
                reader.get("sentinel_received") is True,
                f"{label}.reader[{index}] missed sentinel",
            )
            ready_ms = _number(
                reader, "subscription_ready_at_ms", f"{label}.reader[{index}]"
            )
            first_ms = _number(reader, "first_data_at_ms", f"{label}.reader[{index}]")
            last_ms = _number(reader, "last_data_at_ms", f"{label}.reader[{index}]")
            sentinel_ms = _number(reader, "sentinel_at_ms", f"{label}.reader[{index}]")
            elapsed = _number(reader, "delivery_elapsed_seconds", f"{label}.reader[{index}]")
            achieved = _number(reader, "achieved_events_per_second", f"{label}.reader[{index}]")
            data_event_count = _integer(
                reader, "data_event_count", f"{label}.reader[{index}]"
            )
            recomputed_elapsed = (last_ms - first_ms) / 1000
            _require(
                ready_ms <= first_ms,
                f"{label}.reader[{index}] received data before subscription readiness",
            )
            _require(
                elapsed > 0 and abs(elapsed - recomputed_elapsed) <= 0.001,
                f"{label}.reader[{index}] delivery elapsed time is inconsistent",
            )
            _require(
                data_event_count == delivery_event_count and sentinel_ms >= last_ms,
                f"{label}.reader[{index}] data or sentinel boundary is inconsistent",
            )
            _require(
                target_duration * 0.999
                <= elapsed
                <= target_duration + ELAPSED_OVERRUN_LIMIT_SECONDS,
                f"{label}.reader[{index}] delivery duration is outside the accepted window",
            )
            recomputed_rate = delivery_event_count / elapsed
            _require(
                achieved >= target_rate and abs(achieved - recomputed_rate) <= 0.01,
                f"{label}.reader[{index}] delivery throughput is below threshold or inconsistent",
            )
        _validate_integrity(
            reader.get("sequence_integrity"),
            f"{label}.reader[{index}] integrity",
            expected_integrity_count,
        )


def _validate_eventhub(gate: Any) -> str:
    value = _validate_gate(gate, "quick.eventhub_fanout", "V03-PERF-003A")
    target_rate = _number(value, "target_events_per_second", "quick.eventhub_fanout")
    target_duration = _number(value, "target_duration_seconds", "quick.eventhub_fanout")
    _require(target_rate >= 100 and target_duration >= 60, "EventHub target is below threshold")
    _validate_timing(
        value,
        "quick.eventhub_fanout",
        "event_count_excluding_sentinel",
        6001,
        target_rate,
        target_duration,
    )
    event_count = _integer(
        value, "event_count_excluding_sentinel", "quick.eventhub_fanout"
    )
    clients = _integer(value, "clients", "quick.eventhub_fanout")
    _require(clients >= 2, "EventHub clients missing")
    _require(value.get("producer_errors") == [], "EventHub producer errors are present")
    overflow = value.get("client_queue_overflowed")
    _require(
        isinstance(overflow, list)
        and len(overflow) == clients
        and all(item is False for item in overflow),
        "EventHub queue overflowed",
    )
    expected_integrity_count = event_count + 1
    _validate_integrity(
        value.get("persisted_sequence_integrity"),
        "EventHub persisted integrity",
        expected_integrity_count,
    )
    _validate_stream_readers(
        value,
        "EventHub",
        expected_integrity_count=expected_integrity_count,
        expected_clients=clients,
    )
    return str(value["test_id"])


def _validate_browser(report: dict[str, Any]) -> tuple[str, str]:
    label = "browser"
    _require(report.get("schema_version") == COMPONENT_SCHEMA_VERSION, "browser schema differs")
    _require(report.get("product_version") == PRODUCT_VERSION, "browser product version differs")
    _require(report.get("profile") == "browser-stream", "browser profile is invalid")
    _require(report.get("test_id") == "V03-PERF-003", "browser test id is invalid")
    _require(report.get("passed") is True and report.get("overall_pass") is True, "browser failed")
    _require(report.get("acceptance_complete") is False, "browser claims complete acceptance")
    target_rate = _number(report, "target_events_per_second", label)
    target_duration = _number(report, "target_duration_seconds", label)
    _require(target_rate >= 100, "browser rate target differs")
    _require(target_duration >= 60, "browser duration differs")
    producer = _mapping(report.get("producer"), "browser.producer")
    _require(producer.get("state") == "finished", "browser producer is not finished")
    _require(producer.get("errors") == [], "browser producer errors are present")
    timing = {
        **producer,
        "event_count_excluding_sentinel": report.get("event_count_excluding_sentinel"),
        "measured_duration_seconds": producer.get("elapsed_seconds"),
    }
    _validate_timing(
        timing,
        "browser.producer",
        "event_count_excluding_sentinel",
        6001,
        target_rate,
        target_duration,
    )
    event_count = _integer(report, "event_count_excluding_sentinel", label)
    _require(
        _integer(producer, "produced_event_count", "browser.producer") == event_count,
        "browser producer count differs",
    )
    _validate_integrity(
        producer.get("persisted_sequence_integrity"),
        "browser persisted integrity",
        event_count + 1,
    )
    _validate_stream_readers(
        report,
        "browser",
        delivery_event_count=event_count,
        target_rate=target_rate,
        target_duration=target_duration,
        expected_integrity_count=event_count + 1,
    )
    return "V03-PERF-003", _validate_source(report, label)


def _validate_soak(gate: Any) -> str:
    value = _validate_gate(gate, "soak.soak", "V03-PERF-004")
    target_rate = _number(value, "target_events_per_second", "soak.soak")
    target_duration = _number(value, "target_duration_seconds", "soak.soak")
    _require(target_rate >= 20 and target_duration >= 600, "soak target is below threshold")
    _validate_timing(
        value, "soak.soak", "event_count", 12_001, target_rate, target_duration
    )
    _require(value.get("producer_errors") == [], "soak producer errors are present")
    _require(value.get("control_failures") == [], "soak control failures are present")
    event_count = _integer(value, "event_count", "soak.soak")
    _validate_integrity(
        value.get("sequence_integrity"), "soak sequence integrity", event_count
    )
    memory = _mapping(value.get("memory_measurement"), "soak memory measurement")
    _require(
        _number(memory, "post_warmup_growth_mib", "soak memory measurement") <= 32,
        "soak memory growth exceeds threshold",
    )
    _require(
        _number(memory, "post_warmup_slope_mib_per_minute", "soak memory measurement") <= 2,
        "soak memory slope exceeds threshold",
    )
    return str(value["test_id"])


def compose_reports(
    quick: dict[str, Any],
    soak: dict[str, Any],
    browser: dict[str, Any],
    source_reports: dict[str, str],
) -> dict[str, Any]:
    quick_gates, quick_fingerprint = _validate_component(
        quick, "quick", "quick", {"rest_mutations", "event_replay", "eventhub_fanout"}
    )
    soak_gates, soak_fingerprint = _validate_component(soak, "soak", "soak", {"soak"})
    browser_test_id, browser_fingerprint = _validate_browser(browser)
    _require(
        len({quick_fingerprint, soak_fingerprint, browser_fingerprint}) == 1,
        "qualification source fingerprints do not match",
    )

    test_ids = {
        _validate_rest(quick_gates["rest_mutations"]),
        _validate_replay(quick_gates["event_replay"]),
        _validate_eventhub(quick_gates["eventhub_fanout"]),
        browser_test_id,
        _validate_soak(soak_gates["soak"]),
    }
    acceptance_complete = test_ids == EXPECTED_TEST_IDS
    _require(acceptance_complete, "validated qualification test set is incomplete")
    required = {
        "rest_mutations": quick_gates["rest_mutations"],
        "event_replay": quick_gates["event_replay"],
        "browser_stream": browser,
        "soak": soak_gates["soak"],
    }
    supporting = {"eventhub_fanout": quick_gates["eventhub_fanout"]}
    return {
        "schema_version": RELEASE_SCHEMA_VERSION,
        "product_version": PRODUCT_VERSION,
        "profile": "release",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            **_mapping(quick.get("source"), "quick.source"),
            "fingerprint_sha256": quick_fingerprint,
        },
        "environment": {
            "quick": quick.get("environment"),
            "soak": soak.get("environment"),
            "browser": browser.get("environment"),
        },
        "gates": required,
        "supporting_gates": supporting,
        "validated_test_ids": sorted(test_ids),
        "overall_pass": True,
        "acceptance_complete": acceptance_complete,
        "source_reports": source_reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", type=Path, required=True)
    parser.add_argument("--soak", type=Path, required=True)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = compose_reports(
        load(args.quick),
        load(args.soak),
        load(args.browser),
        {"quick": args.quick.name, "soak": args.soak.name, "browser": args.browser.name},
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
