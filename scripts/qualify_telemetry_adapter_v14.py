"""Measure the bounded synthetic GetTM tranche without external I/O."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from backend.legacy_observation_v12 import load_sources
from backend.telemetry_adapter import TMQuery, compare_tm, get_tm


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sources = load_sources()
    latency_ms = []
    start = time.monotonic()
    while time.monotonic() - start < 60:
        before = time.perf_counter_ns()
        for source in sources.values():
            assert get_tm(source, "TEMP", TMQuery())["value"]["value"] == 20.1
            assert get_tm(source, "TEMP", TMQuery(wait=True, after=source.cursor(0), timeout_ms=60000))["outcome"] == "OK"
            assert get_tm(source, "UNKNOWN", TMQuery())["value"] is None
        assert compare_tm(sources["reference"], sources["simulator"], "COUNTER")["classification"] == "EQUIVALENT"
        latency_ms.append((time.perf_counter_ns() - before) / 1_000_000)
        time.sleep(0.005)
    elapsed = time.monotonic() - start
    assert len(latency_ms) >= 128 and max(latency_ms) < 500
    result = {"schema_version": "spell.telemetry-adapter-soak/1", "decision": "PASS",
              "scope": "LOCAL_SYNTHETIC_TELEMETRY_ADAPTER", "elapsed_seconds": elapsed,
              "batch_latency_ms": latency_ms, "batches": len(latency_ms), "reads_per_batch": 8,
              "failures": 0, "sources": {key: value.identity() for key, value in sources.items()}}
    args.output.write_bytes((json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    print(f"GetTM adapter soak: PASS {len(latency_ms)} batches, {elapsed:.3f}s")


if __name__ == "__main__":
    main()
