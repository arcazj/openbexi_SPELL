"""Exercise the synthetic replay contract in a network-disabled process."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from backend.legacy_observation_v12 import compare, load_sources


def qualify(soak_seconds: float = 1.0) -> dict:
    sources = load_sources()
    reference, simulator = sources["reference"], sources["simulator"]
    expected = {"EQUIVALENT": 5, "DIFFERENT": 0, "INDETERMINATE": 3, "UNSUPPORTED": 1}
    first = compare(reference, simulator)
    if first["counts"] != expected:
        raise ValueError("golden comparison changed")
    baseline = json.dumps(reference.snapshot(), sort_keys=True).encode()
    deadline = time.monotonic() + soak_seconds
    repetitions = 0
    maximum = 0.0
    while time.monotonic() < deadline or repetitions < 100:
        started = time.perf_counter()
        if json.dumps(reference.snapshot(), sort_keys=True).encode() != baseline:
            raise ValueError("snapshot changed during replay soak")
        page = reference.replay(reference.cursor(0))
        if [item["sequence"] for item in page["items"]] != [str(n) for n in range(1, 8)]:
            raise ValueError("replay order changed")
        if compare(reference, simulator) != first:
            raise ValueError("comparison changed during replay soak")
        maximum = max(maximum, time.perf_counter() - started)
        repetitions += 1
    if maximum >= 1.0:
        raise ValueError("one-second local replay latency budget exceeded")
    return {"schema_version": "spell.v12.replay-qualification/1", "comparison": first,
            "snapshot_sha256": hashlib.sha256(baseline).hexdigest(), "repetitions": repetitions,
            "soak_seconds": soak_seconds, "maximum_iteration_seconds": maximum,
            "network_required": False, "decision": "PASS"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--soak-seconds", type=float, default=1.0)
    args = parser.parse_args()
    if not 0 < args.soak_seconds <= 3600:
        parser.error("soak must be between zero and 3600 seconds")
    result = qualify(args.soak_seconds)
    if args.output:
        args.output.write_bytes((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(f"v0.12 replay: PASS repetitions={result['repetitions']} scope=SYNTHETIC_REPLAY_ONLY")


if __name__ == "__main__":
    main()
