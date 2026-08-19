#!/usr/bin/env python3
"""Extract one fail-closed PERF collector result from a complete v0.4 report."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint_v04 import source_fingerprint_v04
from scripts.validate_release_evidence_v04 import (
    PRODUCT_VERSION,
    SCOPE_PROFILE,
    SEMANTIC_VALIDATORS,
)


REPORT_SCHEMA = "spell.v04.performance-qualification/1"
QUICK_IDS = {"V04-PERF-001", "V04-PERF-002", "V04-PERF-003"}
SOAK_IDS = {"V04-PERF-004"}
TEST_IDS = QUICK_IDS | SOAK_IDS
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_REPORT_BYTES = 8 * 1024 * 1024


class PerformanceCollectorError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PerformanceCollectorError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_report(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PerformanceCollectorError("performance report is not a regular file")
    data = path.read_bytes()
    if not data or len(data) > MAX_REPORT_BYTES:
        raise PerformanceCollectorError("performance report has an invalid size")
    try:
        value = json.loads(data, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PerformanceCollectorError("performance report is invalid JSON") from exc
    if not isinstance(value, dict):
        raise PerformanceCollectorError("performance report must be an object")
    return value


def extract_result(path: Path, test_id: str, source: str) -> dict[str, Any]:
    if test_id not in TEST_IDS:
        raise PerformanceCollectorError(f"unsupported performance test ID: {test_id}")
    report = _load_report(path)
    expected_ids = QUICK_IDS if test_id in QUICK_IDS else SOAK_IDS
    expected_profile = "quick" if test_id in QUICK_IDS else "soak"
    if report.get("schema_version") != REPORT_SCHEMA:
        raise PerformanceCollectorError("performance report schema differs")
    if report.get("product_version") != PRODUCT_VERSION:
        raise PerformanceCollectorError("performance report product version differs")
    if report.get("scope_profile") != SCOPE_PROFILE:
        raise PerformanceCollectorError("performance report scope differs")
    if report.get("profile") != expected_profile:
        raise PerformanceCollectorError("performance report profile differs")
    if report.get("overall_pass") is not True or report.get("acceptance_complete") is not False:
        raise PerformanceCollectorError("performance report completion state differs")

    source_value = report.get("source")
    if not isinstance(source_value, dict):
        raise PerformanceCollectorError("performance source binding is missing")
    if (
        source_value.get("fingerprint_sha256") != source
        or source_value.get("fingerprint_after_sha256") != source
        or source_value.get("stable_during_run") is not True
    ):
        raise PerformanceCollectorError("performance report source binding is stale")
    runtime = report.get("runtime")
    if not isinstance(runtime, dict):
        raise PerformanceCollectorError("performance runtime record is missing")
    if runtime.get("residual_child_process_ids") != []:
        raise PerformanceCollectorError("performance run leaked a child process")
    if runtime.get("initial_child_process_ids") != [] or runtime.get("final_child_process_ids") != []:
        raise PerformanceCollectorError("performance observer process accounting differs")
    if runtime.get("process_sampling") != "in-process /proc/self/statm; no CLI observer":
        raise PerformanceCollectorError("performance memory observer differs")
    if not SHA256_PATTERN.fullmatch(str(runtime.get("qualification_image_id", ""))):
        raise PerformanceCollectorError("performance qualification image identity is invalid")

    gates = report.get("gates")
    if not isinstance(gates, dict) or set(gates) != expected_ids:
        raise PerformanceCollectorError("performance report gate set is incomplete")
    for gate_id, gate_value in gates.items():
        if not isinstance(gate_value, dict):
            raise PerformanceCollectorError(f"{gate_id} gate result must be an object")
        if (
            gate_value.get("test_id") != gate_id
            or gate_value.get("executed") is not True
            or gate_value.get("passed") is not True
        ):
            raise PerformanceCollectorError(f"{gate_id} gate did not execute and pass")
        assertions = gate_value.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            raise PerformanceCollectorError(f"{gate_id} assertions are empty")
        assertion_ids: set[str] = set()
        for assertion in assertions:
            if not isinstance(assertion, dict) or assertion.get("passed") is not True:
                raise PerformanceCollectorError(f"{gate_id} assertion did not pass")
            assertion_id = assertion.get("id")
            if not isinstance(assertion_id, str) or not assertion_id or assertion_id in assertion_ids:
                raise PerformanceCollectorError(f"{gate_id} assertion identity is invalid")
            assertion_ids.add(assertion_id)

    gate = gates[test_id]
    metrics = gate.get("metrics")
    if not isinstance(metrics, dict):
        raise PerformanceCollectorError(f"{test_id} metrics are missing")
    validator = SEMANTIC_VALIDATORS[test_id]
    try:
        validator(metrics, f"{test_id}.metrics", source)
    except ValueError as exc:
        raise PerformanceCollectorError(str(exc)) from exc
    return {
        "test_id": test_id,
        "source_fingerprint_sha256": source,
        "assertions": [
            {"id": assertion["id"], "passed": True}
            for assertion in gate["assertions"]
        ],
        "metrics": metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--test-id", choices=sorted(TEST_IDS), required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    report = args.report if args.report.is_absolute() else root / args.report
    source = source_fingerprint_v04(root)
    print(
        json.dumps(
            extract_result(report, args.test_id, source),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
