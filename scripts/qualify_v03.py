#!/usr/bin/env python3
"""Execute the SPELL v0.3 local performance and reliability qualification.

The quick profile is intentionally not a smoke test. It executes V03-PERF-001,
V03-PERF-002, and a supporting in-process EventHub fan-out gate. The separate
browser-stream harness executes V03-PERF-003. The soak profile executes
V03-PERF-004 and may be run separately or with ``--all``.
No credential, token, or signing secret is written to the evidence report.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient
from sqlalchemy import func, insert, select

from backend.app import create_app
from backend.auth import AuthConfig, issue_local_dev_token
from backend.config import Settings
from backend.database import utc_now
from backend.models import Command, Event, Execution
from backend.version import PRODUCT_VERSION
from scripts.source_fingerprint import source_fingerprint, source_fingerprint_inputs


REPORT_SCHEMA_VERSION = "1.0"
REST_P95_LIMIT_MS = 250.0
REPLAY_LIMIT_SECONDS = 3.0
STREAM_RATE = 100.0
STREAM_DURATION_SECONDS = 60.0
SOAK_RATE = 20.0
SOAK_DURATION_SECONDS = 600.0
SOAK_MAX_MEMORY_GROWTH_MIB = 32.0
SOAK_MAX_MEMORY_SLOPE_MIB_PER_MINUTE = 2.0
SCHEDULE_P95_LIMIT_MS = 250.0
SCHEDULE_MAX_LIMIT_MS = 1000.0
ELAPSED_OVERRUN_LIMIT_SECONDS = 1.0


@dataclass(frozen=True)
class QualificationContext:
    client: TestClient
    token: str

    @property
    def authorization_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def supervisor(self):
        return self.client.app.state.supervisor

    @property
    def session_factory(self):
        return self.client.app.state.session_factory


def percentile(values: Sequence[float], fraction: float) -> float:
    """Return the nearest-rank percentile without interpolating measurements."""

    if not values:
        raise ValueError("at least one measurement is required")
    if not 0 < fraction <= 1:
        raise ValueError("percentile fraction must be in (0, 1]")
    ordered = sorted(values)
    return float(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)])


def sequence_integrity(
    sequences: Sequence[int], expected_first: int, expected_last: int
) -> dict[str, Any]:
    expected = list(range(expected_first, expected_last + 1))
    counts: dict[int, int] = {}
    for sequence in sequences:
        counts[sequence] = counts.get(sequence, 0) + 1
    duplicates = sorted(sequence for sequence, count in counts.items() if count > 1)
    missing = sorted(set(expected) - set(sequences))
    unexpected = sorted(set(sequences) - set(expected))
    return {
        "exact": list(sequences) == expected,
        "received_count": len(sequences),
        "expected_count": len(expected),
        "duplicate_count": len(duplicates),
        "missing_count": len(missing),
        "unexpected_count": len(unexpected),
        "duplicate_examples": duplicates[:10],
        "missing_examples": missing[:10],
        "unexpected_examples": unexpected[:10],
    }


def linear_slope(points: Sequence[tuple[float, float]]) -> float:
    """Return least-squares y units per x unit, or zero for a flat sample."""

    if len(points) < 2:
        return 0.0
    mean_x = sum(point[0] for point in points) / len(points)
    mean_y = sum(point[1] for point in points) / len(points)
    denominator = sum((point[0] - mean_x) ** 2 for point in points)
    if denominator == 0:
        return 0.0
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in points)
    return numerator / denominator


def scheduled_event_count(rate: float, duration_seconds: float) -> int:
    """Return the inclusive count for events scheduled from t=0 through duration."""

    if rate <= 0 or duration_seconds <= 0:
        raise ValueError("rate and duration must be positive")
    return math.floor(rate * duration_seconds) + 1


def timing_metrics(
    event_count: int,
    production_elapsed_seconds: float,
    measured_duration_seconds: float,
    target_rate: float,
    target_duration_seconds: float,
    scheduling_lag_ms: Sequence[float],
) -> dict[str, float | bool]:
    """Calculate and enforce actual throughput, elapsed time, and scheduler lag."""

    if event_count <= 0 or production_elapsed_seconds <= 0 or not scheduling_lag_ms:
        return {
            "achieved_events_per_second": 0.0,
            "schedule_p95_ms": math.inf,
            "schedule_max_ms": math.inf,
            "passed": False,
        }
    achieved_rate = event_count / production_elapsed_seconds
    schedule_p95_ms = percentile(scheduling_lag_ms, 0.95)
    schedule_max_ms = max(scheduling_lag_ms)
    passed = (
        achieved_rate >= target_rate
        and production_elapsed_seconds >= target_duration_seconds * 0.999
        and production_elapsed_seconds
        <= target_duration_seconds + ELAPSED_OVERRUN_LIMIT_SECONDS
        and measured_duration_seconds >= target_duration_seconds * 0.999
        and measured_duration_seconds
        <= target_duration_seconds + ELAPSED_OVERRUN_LIMIT_SECONDS
        and schedule_p95_ms <= SCHEDULE_P95_LIMIT_MS
        and schedule_max_ms <= SCHEDULE_MAX_LIMIT_MS
    )
    return {
        "achieved_events_per_second": achieved_rate,
        "schedule_p95_ms": schedule_p95_ms,
        "schedule_max_ms": schedule_max_ms,
        "passed": passed,
    }


def resident_memory_bytes() -> int:
    """Read current process RSS on Windows/Linux, with peak RSS as fallback."""

    if os.name == "nt":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
            process, ctypes.byref(counters), counters.cb
        ):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.WorkingSetSize)

    proc_statm = Path("/proc/self/statm")
    if proc_statm.exists():
        resident_pages = int(proc_statm.read_text(encoding="ascii").split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")

    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if platform.system() == "Darwin" else peak * 1024)


def _fingerprint_root() -> Path:
    configured = os.getenv("SPELL_QUALIFICATION_SOURCE_ROOT")
    return Path(configured).resolve() if configured else ROOT


def _source_fingerprint_inputs(root: Path | None = None) -> list[Path]:
    return source_fingerprint_inputs((root or _fingerprint_root()).resolve())


def _source_fingerprint(root: Path | None = None) -> str:
    return source_fingerprint((root or _fingerprint_root()).resolve())


def _git_metadata() -> dict[str, Any]:
    def run(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    try:
        commit = run("rev-parse", "HEAD")
        dirty = bool(run("status", "--porcelain"))
    except (FileNotFoundError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}
    return {"commit": commit, "dirty": dirty}


def _create_execution_record(context: QualificationContext, label: str) -> str:
    with context.session_factory() as session:
        execution = Execution(
            procedure_id=f"qualification-{label}",
            procedure_name=f"Qualification {label}",
            procedure_hash=hashlib.sha256(label.encode("utf-8")).hexdigest(),
            procedure_source='Log("qualification")\n',
            steps=[],
            ir_version="0.3",
            variables={},
            context_id="simulator",
            created_by="qualification",
            creation_idempotency_key=f"{label}-{uuid.uuid4()}",
            state="running",
            revision=1,
            current_step=0,
            total_steps=0,
            worker_generation=0,
            next_sequence=1,
        )
        session.add(execution)
        session.commit()
        return execution.id


def _wait_for_workers(context: QualificationContext, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not context.supervisor._workers:
            return True
        time.sleep(0.05)
    return not context.supervisor._workers


def _wait_for_execution_state(
    context: QualificationContext,
    execution_id: str,
    expected_state: str,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        response = context.client.get(
            f"/api/v1/executions/{execution_id}/snapshot",
            headers=context.authorization_headers,
        )
        if response.status_code != 200:
            raise RuntimeError(f"snapshot returned HTTP {response.status_code}")
        latest = response.json()
        if latest["execution"]["state"] == expected_state:
            return latest
        time.sleep(0.01)
    state = latest["execution"]["state"] if latest else "unavailable"
    raise TimeoutError(
        f"execution did not reach {expected_state!r}; latest state was {state!r}"
    )


def qualify_rest_mutations(
    context: QualificationContext, request_count: int
) -> dict[str, Any]:
    if request_count % 2:
        raise ValueError("REST mutation count must be even for pause/resume pairs")
    latencies_ms: list[float] = []
    retry_latencies_ms: list[float] = []
    command_ids: list[str] = []
    status_codes: list[int] = []
    retry_status_codes: list[int] = []
    retry_identity_mismatches = 0
    create_response = context.client.post(
        "/api/v1/executions",
        headers=context.authorization_headers,
        json={
            "procedure_id": "qualification_rest",
            "context_id": "simulator",
            "reason": "prepare v0.3 REST command qualification",
            "idempotency_key": "qualification-rest-execution",
        },
    )
    if create_response.status_code != 202:
        raise RuntimeError(
            f"qualification execution creation returned HTTP {create_response.status_code}"
        )
    execution_id = create_response.json()["execution"]["id"]
    snapshot = _wait_for_execution_state(context, execution_id, "running")

    for pair_index in range(request_count // 2):
        for command_type, expected_state in (("pause", "paused"), ("resume", "running")):
            key = f"qualification-rest-{command_type}-{pair_index}"
            body = {
                "type": command_type,
                "expected_revision": snapshot["execution"]["revision"],
                "reason": "v0.3 authenticated REST command qualification",
                "idempotency_key": key,
            }
            started = time.perf_counter()
            response = context.client.post(
                f"/api/v1/executions/{execution_id}/commands",
                headers=context.authorization_headers,
                json=body,
            )
            latencies_ms.append((time.perf_counter() - started) * 1000)
            status_codes.append(response.status_code)
            if response.status_code != 202:
                continue
            command_id = response.json()["command"]["id"]
            command_ids.append(command_id)

            retry_started = time.perf_counter()
            retry = context.client.post(
                f"/api/v1/executions/{execution_id}/commands",
                headers=context.authorization_headers,
                json=body,
            )
            retry_latencies_ms.append((time.perf_counter() - retry_started) * 1000)
            retry_status_codes.append(retry.status_code)
            if (
                retry.status_code != 202
                or retry.json()["command"]["id"] != command_id
            ):
                retry_identity_mismatches += 1
            snapshot = _wait_for_execution_state(
                context, execution_id, expected_state
            )

    abort = context.client.post(
        f"/api/v1/executions/{execution_id}/commands",
        headers=context.authorization_headers,
        json={
            "type": "abort",
            "expected_revision": snapshot["execution"]["revision"],
            "reason": "complete REST command qualification",
            "idempotency_key": "qualification-rest-abort",
        },
    )
    if abort.status_code != 202:
        raise RuntimeError(f"qualification abort returned HTTP {abort.status_code}")
    terminal = _wait_for_execution_state(context, execution_id, "aborted")
    workers_drained = _wait_for_workers(context, timeout_seconds=30.0)
    with context.session_factory() as session:
        stored_count = session.scalar(
            select(func.count())
            .select_from(Command)
            .where(
                Command.execution_id == execution_id,
                Command.command_type.in_({"pause", "resume"}),
            )
        )
        command_states = dict(
            session.execute(
                select(Command.status, func.count())
                .where(
                    Command.execution_id == execution_id,
                    Command.command_type.in_({"pause", "resume"}),
                )
                .group_by(Command.status)
            ).all()
        )

    p95_ms = percentile(latencies_ms, 0.95)
    retry_p95_ms = percentile(retry_latencies_ms, 0.95)
    unique_ids = len(set(command_ids))
    passed = (
        request_count >= 100
        and all(code == 202 for code in status_codes)
        and all(code == 202 for code in retry_status_codes)
        and len(command_ids) == request_count
        and unique_ids == request_count
        and stored_count == request_count
        and retry_identity_mismatches == 0
        and p95_ms <= REST_P95_LIMIT_MS
        and workers_drained
        and command_states == {"completed": request_count}
        and terminal["execution"]["worker_generation"] == 1
    )
    return {
        "test_id": "V03-PERF-001",
        "passed": passed,
        "threshold": {
            "minimum_primary_mutations": 100,
            "primary_p95_ms_at_most": REST_P95_LIMIT_MS,
            "duplicate_outcomes": 0,
        },
        "primary_mutations": request_count,
        "idempotent_retries": len(retry_latencies_ms),
        "primary_p50_ms": round(percentile(latencies_ms, 0.50), 3),
        "primary_p95_ms": round(p95_ms, 3),
        "primary_max_ms": round(max(latencies_ms), 3),
        "retry_p95_ms": round(retry_p95_ms, 3),
        "status_codes": sorted(set(status_codes)),
        "retry_status_codes": sorted(set(retry_status_codes)),
        "execution_id": execution_id,
        "mutation_types": {
            "pause": request_count // 2,
            "resume": request_count // 2,
        },
        "unique_command_ids": unique_ids,
        "stored_command_count": stored_count,
        "retry_identity_mismatches": retry_identity_mismatches,
        "durable_command_states": command_states,
        "terminal_execution_state": terminal["execution"]["state"],
        "worker_generations": terminal["execution"]["worker_generation"],
        "workers_drained": workers_drained,
    }


def _seed_events(
    context: QualificationContext, execution_id: str, count: int
) -> None:
    created_at = utc_now()
    rows = [
        {
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{execution_id}:{sequence}")),
            "execution_id": execution_id,
            "sequence": sequence,
            "event_type": "qualification.replay",
            "source": "qualification",
            "severity": "info",
            "correlation_id": None,
            "causation_id": None,
            "payload": {"index": sequence - 1, "canonical": True},
            "created_at": created_at,
        }
        for sequence in range(1, count + 1)
    ]
    with context.session_factory() as session:
        session.execute(insert(Event), rows)
        execution = session.get(Execution, execution_id)
        assert execution is not None
        execution.next_sequence = count + 1
        session.commit()


def qualify_replay(
    context: QualificationContext, event_count: int
) -> dict[str, Any]:
    execution_id = _create_execution_record(context, "replay")
    seed_started = time.perf_counter()
    _seed_events(context, execution_id, event_count)
    seed_seconds = time.perf_counter() - seed_started

    started = time.perf_counter()
    replay = context.supervisor.events_after(execution_id, 0, event_count)
    replay_seconds = time.perf_counter() - started
    sequences = [event["sequence"] for event in replay]
    integrity = sequence_integrity(sequences, 1, event_count)
    payloads_exact = all(
        event["payload"] == {"index": sequence - 1, "canonical": True}
        for sequence, event in enumerate(replay, start=1)
    )
    passed = (
        event_count >= 10_000
        and replay_seconds <= REPLAY_LIMIT_SECONDS
        and integrity["exact"]
        and payloads_exact
    )
    return {
        "test_id": "V03-PERF-002",
        "passed": passed,
        "threshold": {
            "minimum_events": 10_000,
            "replay_seconds_at_most": REPLAY_LIMIT_SECONDS,
            "missing_or_duplicate_events": 0,
        },
        "execution_id": execution_id,
        "event_count": event_count,
        "seed_seconds_excluded_from_measurement": round(seed_seconds, 6),
        "replay_seconds": round(replay_seconds, 6),
        "events_per_second": round(event_count / replay_seconds, 2),
        "sequence_integrity": integrity,
        "payloads_exact": payloads_exact,
    }


async def _deliver_concurrent_stream(
    context: QualificationContext,
    execution_id: str,
    rate: float,
    duration_seconds: float,
    event_count: int,
) -> dict[str, Any]:
    subscriptions = [
        context.client.app.state.hub.subscribe(execution_id),
        context.client.app.state.hub.subscribe(execution_id),
    ]
    readers = [
        {"name": "client-1", "error": None, "sequences": [], "delivery_latency_ms": []},
        {"name": "client-2", "error": None, "sequences": [], "delivery_latency_ms": []},
    ]
    scheduling_lag_ms: list[float] = []
    producer_errors: list[str] = []
    started = time.perf_counter()
    production_elapsed_seconds = 0.0

    def drain() -> None:
        for subscription, reader in zip(subscriptions, readers):
            while not subscription.queue.empty():
                message = subscription.queue.get_nowait()
                reader["sequences"].append(message["sequence"])
                published_ns = message.get("payload", {}).get(
                    "published_monotonic_ns"
                )
                if isinstance(published_ns, int):
                    reader["delivery_latency_ms"].append(
                        (time.monotonic_ns() - published_ns) / 1_000_000
                    )

    try:
        for index in range(event_count):
            target = started + index / rate
            remaining = target - time.perf_counter()
            if remaining > 0:
                await asyncio.sleep(remaining)
            scheduling_lag_ms.append(max(0.0, (time.perf_counter() - target) * 1000))
            try:
                context.supervisor.append_event(
                    execution_id,
                    "qualification.stream",
                    {
                        "index": index,
                        "published_monotonic_ns": time.monotonic_ns(),
                    },
                    source="qualification",
                )
            except Exception as exc:
                producer_errors.append(f"{type(exc).__name__}: {exc}")
                break
            await asyncio.sleep(0)
            drain()

        production_elapsed_seconds = time.perf_counter() - started
        remaining = started + duration_seconds - time.perf_counter()
        if remaining > 0:
            await asyncio.sleep(remaining)
        try:
            context.supervisor.append_event(
                execution_id,
                "qualification.stream_end",
                {"published_monotonic_ns": time.monotonic_ns()},
                source="qualification",
            )
        except Exception as exc:
            producer_errors.append(f"sentinel {type(exc).__name__}: {exc}")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        drain()
    finally:
        overflowed = [subscription.overflowed for subscription in subscriptions]
        for subscription in subscriptions:
            context.client.app.state.hub.unsubscribe(execution_id, subscription)
    return {
        "readers": readers,
        "producer_errors": producer_errors,
        "scheduling_lag_ms": scheduling_lag_ms,
        "overflowed": overflowed,
        "production_elapsed_seconds": production_elapsed_seconds,
        "elapsed_seconds": time.perf_counter() - started,
    }


def qualify_concurrent_stream(
    context: QualificationContext,
    rate: float,
    duration_seconds: float,
) -> dict[str, Any]:
    execution_id = _create_execution_record(context, "concurrent-stream")
    event_count = scheduled_event_count(rate, duration_seconds)
    expected_last = event_count + 1
    delivery = asyncio.run(
        _deliver_concurrent_stream(
            context, execution_id, rate, duration_seconds, event_count
        )
    )
    readers = delivery["readers"]
    scheduling_lag_ms = delivery["scheduling_lag_ms"]
    producer_errors = delivery["producer_errors"]
    elapsed_seconds = delivery["elapsed_seconds"]
    production_elapsed_seconds = delivery["production_elapsed_seconds"]

    reader_results = []
    for reader in readers:
        sequences = reader.get("sequences", [])
        latency = reader.get("delivery_latency_ms", [])
        integrity = sequence_integrity(sequences, 1, expected_last)
        reader_results.append(
            {
                "name": reader["name"],
                "error": reader.get("error"),
                "sequence_integrity": integrity,
                "delivery_p95_ms": (
                    round(percentile(latency, 0.95), 3) if latency else None
                ),
                "delivery_max_ms": round(max(latency), 3) if latency else None,
            }
        )

    persisted = context.supervisor.events_after(execution_id, 0, expected_last)
    persisted_integrity = sequence_integrity(
        [event["sequence"] for event in persisted], 1, expected_last
    )
    timing = timing_metrics(
        event_count,
        production_elapsed_seconds,
        elapsed_seconds,
        rate,
        duration_seconds,
        scheduling_lag_ms,
    )
    minimum_count = scheduled_event_count(STREAM_RATE, STREAM_DURATION_SECONDS)
    passed = (
        rate >= STREAM_RATE
        and duration_seconds >= STREAM_DURATION_SECONDS
        and event_count >= minimum_count
        and not producer_errors
        and not any(delivery["overflowed"])
        and timing["passed"] is True
        and persisted_integrity["exact"]
        and all(
            reader["error"] is None
            and reader["sequence_integrity"]["exact"]
            for reader in reader_results
        )
    )
    return {
        "test_id": "V03-PERF-003A",
        "passed": passed,
        "threshold": {
            "minimum_clients": 2,
            "minimum_rate_events_per_second": STREAM_RATE,
            "minimum_duration_seconds": STREAM_DURATION_SECONDS,
            "missing_or_duplicate_events": 0,
            "schedule_p95_ms_at_most": SCHEDULE_P95_LIMIT_MS,
            "schedule_max_ms_at_most": SCHEDULE_MAX_LIMIT_MS,
            "elapsed_overrun_seconds_at_most": ELAPSED_OVERRUN_LIMIT_SECONDS,
        },
        "execution_id": execution_id,
        "clients": len(readers),
        "delivery_boundary": "supporting in-process EventHub fan-out boundary",
        "target_events_per_second": rate,
        "target_duration_seconds": duration_seconds,
        "production_elapsed_seconds": round(production_elapsed_seconds, 6),
        "measured_duration_seconds": round(elapsed_seconds, 6),
        "event_count_excluding_sentinel": event_count,
        "achieved_events_per_second": round(
            float(timing["achieved_events_per_second"]), 3
        ),
        "window_events_per_second": round(
            float(timing["achieved_events_per_second"]), 3
        ),
        "schedule_p95_ms": round(float(timing["schedule_p95_ms"]), 3),
        "schedule_max_ms": round(float(timing["schedule_max_ms"]), 3),
        "producer_errors": producer_errors,
        "client_queue_overflowed": delivery["overflowed"],
        "persisted_sequence_integrity": persisted_integrity,
        "reader_results": reader_results,
    }


def _paged_sequences(
    context: QualificationContext, execution_id: str, event_count: int
) -> list[int]:
    sequences: list[int] = []
    after = 0
    while len(sequences) < event_count:
        page = context.supervisor.events_after(
            execution_id, after, min(1000, event_count - len(sequences))
        )
        if not page:
            break
        page_sequences = [event["sequence"] for event in page]
        sequences.extend(page_sequences)
        after = page_sequences[-1]
    return sequences


def qualify_soak(
    context: QualificationContext,
    rate: float,
    duration_seconds: float,
    sample_interval_seconds: float,
    max_memory_growth_mib: float,
    max_memory_slope_mib_per_minute: float,
) -> dict[str, Any]:
    execution_id = _create_execution_record(context, "soak")
    event_count = scheduled_event_count(rate, duration_seconds)
    memory_samples: list[dict[str, float]] = []
    append_latencies_ms: list[float] = []
    scheduling_lag_ms: list[float] = []
    control_failures: list[str] = []
    producer_errors: list[str] = []
    started = time.perf_counter()
    next_sample = started

    for index in range(event_count):
        target = started + index / rate
        remaining = target - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)
        scheduling_lag_ms.append(max(0.0, (time.perf_counter() - target) * 1000))
        append_started = time.perf_counter()
        try:
            context.supervisor.append_event(
                execution_id,
                "qualification.soak",
                {"index": index},
                source="qualification",
            )
        except Exception as exc:
            producer_errors.append(f"{type(exc).__name__}: {exc}")
            break
        append_latencies_ms.append((time.perf_counter() - append_started) * 1000)

        now = time.perf_counter()
        if now >= next_sample:
            memory_samples.append(
                {
                    "elapsed_seconds": round(now - started, 6),
                    "rss_mib": round(resident_memory_bytes() / (1024 * 1024), 3),
                }
            )
            response = context.client.get(
                f"/api/v1/executions/{execution_id}/snapshot",
                headers=context.authorization_headers,
            )
            if response.status_code != 200:
                control_failures.append(
                    f"snapshot status {response.status_code} at event {index}"
                )
            next_sample = now + sample_interval_seconds

    production_elapsed_seconds = time.perf_counter() - started
    remaining = started + duration_seconds - time.perf_counter()
    if remaining > 0:
        time.sleep(remaining)
    elapsed_seconds = time.perf_counter() - started
    memory_samples.append(
        {
            "elapsed_seconds": round(elapsed_seconds, 6),
            "rss_mib": round(resident_memory_bytes() / (1024 * 1024), 3),
        }
    )

    sequences = _paged_sequences(context, execution_id, event_count)
    integrity = sequence_integrity(sequences, 1, event_count)
    warmup_boundary = duration_seconds * 0.20
    post_warmup = [
        (sample["elapsed_seconds"] / 60.0, sample["rss_mib"])
        for sample in memory_samples
        if sample["elapsed_seconds"] >= warmup_boundary
    ]
    if len(post_warmup) < 2:
        post_warmup = [
            (sample["elapsed_seconds"] / 60.0, sample["rss_mib"])
            for sample in memory_samples
        ]
    memory_slope = linear_slope(post_warmup)
    memory_growth = (
        post_warmup[-1][1] - post_warmup[0][1] if len(post_warmup) >= 2 else 0.0
    )
    timing = timing_metrics(
        event_count,
        production_elapsed_seconds,
        elapsed_seconds,
        rate,
        duration_seconds,
        scheduling_lag_ms,
    )
    minimum_count = scheduled_event_count(SOAK_RATE, SOAK_DURATION_SECONDS)
    passed = (
        rate >= SOAK_RATE
        and duration_seconds >= SOAK_DURATION_SECONDS
        and event_count >= minimum_count
        and not producer_errors
        and not control_failures
        and timing["passed"] is True
        and integrity["exact"]
        and memory_growth <= max_memory_growth_mib
        and memory_slope <= max_memory_slope_mib_per_minute
    )
    return {
        "test_id": "V03-PERF-004",
        "passed": passed,
        "threshold": {
            "minimum_rate_events_per_second": SOAK_RATE,
            "minimum_duration_seconds": SOAK_DURATION_SECONDS,
            "missing_or_duplicate_events": 0,
            "schedule_p95_ms_at_most": SCHEDULE_P95_LIMIT_MS,
            "schedule_max_ms_at_most": SCHEDULE_MAX_LIMIT_MS,
            "elapsed_overrun_seconds_at_most": ELAPSED_OVERRUN_LIMIT_SECONDS,
            "post_warmup_memory_growth_mib_at_most": max_memory_growth_mib,
            "post_warmup_memory_slope_mib_per_minute_at_most": (
                max_memory_slope_mib_per_minute
            ),
        },
        "execution_id": execution_id,
        "target_events_per_second": rate,
        "target_duration_seconds": duration_seconds,
        "production_elapsed_seconds": round(production_elapsed_seconds, 6),
        "measured_duration_seconds": round(elapsed_seconds, 6),
        "event_count": event_count,
        "achieved_events_per_second": round(
            float(timing["achieved_events_per_second"]), 3
        ),
        "window_events_per_second": round(
            float(timing["achieved_events_per_second"]), 3
        ),
        "schedule_p95_ms": round(float(timing["schedule_p95_ms"]), 3),
        "schedule_max_ms": round(float(timing["schedule_max_ms"]), 3),
        "append_p95_ms": round(percentile(append_latencies_ms, 0.95), 3),
        "append_p99_ms": round(percentile(append_latencies_ms, 0.99), 3),
        "append_max_ms": round(max(append_latencies_ms), 3),
        "producer_errors": producer_errors,
        "control_failures": control_failures,
        "sequence_integrity": integrity,
        "memory_measurement": {
            "source": "process RSS",
            "warmup_excluded_fraction": 0.20,
            "post_warmup_growth_mib": round(memory_growth, 3),
            "post_warmup_slope_mib_per_minute": round(memory_slope, 3),
            "samples": memory_samples,
        },
    }


def _run_gate(name: str, function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    try:
        result = function()
    except Exception as exc:
        result = {
            "test_id": name,
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    result["started_at"] = started.isoformat()
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--quick",
        action="store_true",
        help="run V03-PERF-001, V03-PERF-002, and supporting EventHub fan-out (default)",
    )
    selection.add_argument(
        "--soak",
        action="store_true",
        help="run only the 10-minute V03-PERF-004 soak",
    )
    selection.add_argument(
        "--all",
        action="store_true",
        help="run quick gates followed by the soak",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="output report path; qualification.json is reserved for the release composer",
    )
    parser.add_argument("--rest-count", type=int, default=100)
    parser.add_argument("--replay-events", type=int, default=10_000)
    parser.add_argument("--stream-rate", type=float, default=STREAM_RATE)
    parser.add_argument(
        "--stream-duration-seconds", type=float, default=STREAM_DURATION_SECONDS
    )
    parser.add_argument("--soak-rate", type=float, default=SOAK_RATE)
    parser.add_argument(
        "--soak-duration-seconds", type=float, default=SOAK_DURATION_SECONDS
    )
    parser.add_argument("--soak-sample-interval-seconds", type=float, default=10.0)
    parser.add_argument(
        "--max-soak-memory-growth-mib",
        type=float,
        default=SOAK_MAX_MEMORY_GROWTH_MIB,
    )
    parser.add_argument(
        "--max-soak-memory-slope-mib-per-minute",
        type=float,
        default=SOAK_MAX_MEMORY_SLOPE_MIB_PER_MINUTE,
    )
    return parser


def _validate_arguments(args: argparse.Namespace) -> None:
    positive = {
        "rest-count": args.rest_count,
        "replay-events": args.replay_events,
        "stream-rate": args.stream_rate,
        "stream-duration-seconds": args.stream_duration_seconds,
        "soak-rate": args.soak_rate,
        "soak-duration-seconds": args.soak_duration_seconds,
        "soak-sample-interval-seconds": args.soak_sample_interval_seconds,
    }
    invalid = [name for name, value in positive.items() if value <= 0]
    if invalid:
        raise ValueError(f"arguments must be positive: {', '.join(invalid)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _validate_arguments(args)
    except ValueError as exc:
        parser.error(str(exc))

    run_quick = not args.soak
    run_soak = args.soak or args.all
    generated_at = datetime.now(timezone.utc)
    profile = "backend-all" if args.all else "soak" if args.soak else "quick"
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "product_version": PRODUCT_VERSION,
        "profile": profile,
        "generated_at": generated_at.isoformat(),
        "source": {**_git_metadata(), "fingerprint_sha256": _source_fingerprint()},
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "database": "temporary SQLite",
            "transport": (
                "FastAPI TestClient with signed JWT REST authentication; "
                "two bounded production EventHub delivery subscriptions; supporting gate only"
            ),
        },
        "gates": {},
    }

    default_output = ROOT / "artifacts" / "v0.3" / f"qualification-{profile}.json"
    output_path = (args.output or default_output).resolve()
    if output_path.name.lower() == "qualification.json":
        parser.error("qualification.json is reserved for compose_qualification.py")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Keep the SQLite workload on the runtime-native filesystem. In Docker
    # Desktop, SQLite on a Windows bind mount measures file-sharing latency
    # instead of the application and cannot sustain the planned event rate.
    with tempfile.TemporaryDirectory(
        prefix="openbexi-spell-v03-qualification-"
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        procedures = temporary / "procedures"
        procedures.mkdir()
        (procedures / "qualification_rest.spell.py").write_text(
            '"""REST mutation qualification procedure."""\n'
            "Wait(600)\n",
            encoding="utf-8",
        )
        settings = Settings(
            database_url=f"sqlite:///{(temporary / 'qualification.db').as_posix()}",
            procedures_dir=procedures,
            websocket_replay_limit=max(args.replay_events + 10, 20_000),
            websocket_queue_size=2048,
            websocket_keepalive_seconds=1.0,
        )
        auth_config = AuthConfig(
            issuer="openbexi-spell-qualification",
            audience="openbexi-spell-api",
            signing_secret=b"v03-qualification-secret-material-never-persisted",
            clock_skew_seconds=0,
            max_token_lifetime_seconds=900,
            allow_local_dev_issuance=True,
        )
        token = issue_local_dev_token(
            auth_config,
            subject="qualification.operator",
            role="operator",
            peer_host="127.0.0.1",
            lifetime_seconds=900,
        )
        with TestClient(create_app(settings, auth_config=auth_config)) as client:
            context = QualificationContext(client=client, token=token)
            if run_quick:
                report["gates"]["rest_mutations"] = _run_gate(
                    "V03-PERF-001",
                    lambda: qualify_rest_mutations(context, args.rest_count),
                )
                report["gates"]["event_replay"] = _run_gate(
                    "V03-PERF-002",
                    lambda: qualify_replay(context, args.replay_events),
                )
                report["gates"]["eventhub_fanout"] = _run_gate(
                    "V03-PERF-003A",
                    lambda: qualify_concurrent_stream(
                        context, args.stream_rate, args.stream_duration_seconds
                    ),
                )
            if run_soak:
                report["gates"]["soak"] = _run_gate(
                    "V03-PERF-004",
                    lambda: qualify_soak(
                        context,
                        args.soak_rate,
                        args.soak_duration_seconds,
                        args.soak_sample_interval_seconds,
                        args.max_soak_memory_growth_mib,
                        args.max_soak_memory_slope_mib_per_minute,
                    ),
                )

    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["overall_pass"] = bool(report["gates"]) and all(
        gate.get("passed") is True for gate in report["gates"].values()
    )
    # The primary browser/WebSocket gate is produced by a separate harness.
    # Backend-only profiles can never represent complete release acceptance.
    report["acceptance_complete"] = False
    _write_report(output_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Qualification evidence: {output_path}")
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
