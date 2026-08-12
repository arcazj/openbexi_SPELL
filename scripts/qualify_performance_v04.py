"""Execute the approved v0.4 driver-host performance gates.

The release profile is intentionally fixed.  The quick profile executes
V04-PERF-001 through V04-PERF-003, while the soak profile executes the full
600-second V04-PERF-004 workload.  Every measured RPC crosses an ephemeral
loopback mTLS gRPC boundary backed by the production lifecycle host and its
durable SQLite journal.
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
import sqlite3
import sys
import tempfile
import time
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import grpc

from driver_host.config import HostConfig, JournalConfig
from driver_host.domain import (
    Certainty,
    ErrorCode,
    GenerationIdentity,
    HookAction,
    HookOutcome,
    HookTraceRecord,
    Method,
    OperationCommand,
    Result,
    SafeFailure,
    Stage,
)
from driver_host.hooks import DeterministicHooks, HookSpec
from driver_host.journal import OperationJournal
from driver_host.lifecycle import SimulatorLifecycleHost
from driver_host.pki import PkiBundle, generate_bundle
from driver_host.server import build_server
from driver_host.config import DEFAULT_SERVER_NAME
from driver_host.security import (
    CONTRACT_MAJOR_METADATA,
    CREDENTIAL_EPOCH_METADATA,
)
from scripts.source_fingerprint_v04 import source_fingerprint_v04
from spell.driver.configuration import context_binding_digest
from spell.driver.v1 import driver_pb2, driver_pb2_grpc


REPORT_SCHEMA_VERSION = "spell.v04.performance-qualification/1"
PRODUCT_VERSION = "0.4.0"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
HEALTH_COUNT = 1_000
HEALTH_RATE = 105.0
LIFECYCLE_COUNT = 1_000
LIFECYCLE_RATE = 20.5
CANCELLATION_COUNT = 100
RESTART_COUNT = 25
SOAK_DURATION_SECONDS = 600.0
SOAK_RATE = 20.2
SOAK_MINIMUM_COUNT = 12_000
MEMORY_SAMPLE_INTERVAL_SECONDS = 10.0
CONTEXT_SCHEMA_VERSION = "context-schema-1"
CONTEXT_PROFILE_ID = "context-profile-1"
SYNTHETIC_CONTEXT_LABEL = "synthetic-context-1"
RPC_DEADLINE_SECONDS = 30.0
WIRE_DEADLINE_MILLISECONDS = 5 * 60 * 1_000
JOURNAL_LIMITS = JournalConfig(
    max_entries=100_000,
    max_bytes=1_073_741_824,
)
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


def percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        return math.inf
    if not 0 < quantile <= 1:
        raise ValueError("quantile must be in (0, 1]")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * quantile) - 1)]


def linear_slope(samples: Sequence[tuple[float, float]]) -> float:
    """Return the least-squares y-units per x-unit slope."""

    if len(samples) < 2:
        return 0.0
    mean_x = sum(item[0] for item in samples) / len(samples)
    mean_y = sum(item[1] for item in samples) / len(samples)
    denominator = sum((item[0] - mean_x) ** 2 for item in samples)
    if denominator == 0:
        return 0.0
    return sum(
        (item[0] - mean_x) * (item[1] - mean_y) for item in samples
    ) / denominator


def resident_memory_bytes() -> int:
    """Read current RSS on Linux/Windows without an optional dependency."""

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


def child_process_ids(
    proc_root: Path = Path("/proc"), *, pid: int | None = None
) -> tuple[int, ...]:
    """Read direct child IDs from procfs without starting an observer process."""

    task_root = proc_root / str(pid or os.getpid()) / "task"
    if not task_root.is_dir():
        return ()
    children: set[int] = set()
    for task in task_root.iterdir():
        child_file = task / "children"
        if not child_file.is_file():
            continue
        for value in child_file.read_text(encoding="ascii").split():
            children.add(int(value))
    return tuple(sorted(children))


def _now_utc() -> str:
    value = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return value[:-3] + "Z"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def performance_configuration(profile: str) -> dict[str, Any]:
    common: dict[str, Any] = {
        "transport": "loopback mutual TLS gRPC unary RPC",
        "hook_delay_ms": 0,
        "rpc_deadline_seconds": RPC_DEADLINE_SECONDS,
        "wire_deadline_milliseconds": WIRE_DEADLINE_MILLISECONDS,
        "journal": {
            "max_entries": JOURNAL_LIMITS.max_entries,
            "max_bytes": JOURNAL_LIMITS.max_bytes,
        },
    }
    if profile == "quick":
        common["workload"] = {
            "health_count": HEALTH_COUNT,
            "health_rate_per_second": HEALTH_RATE,
            "lifecycle_count": LIFECYCLE_COUNT,
            "lifecycle_rate_per_second": LIFECYCLE_RATE,
            "cancellation_count": CANCELLATION_COUNT,
            "restart_count": RESTART_COUNT,
        }
    elif profile == "soak":
        common["workload"] = {
            "duration_seconds": SOAK_DURATION_SECONDS,
            "rate_per_second": SOAK_RATE,
            "minimum_count": SOAK_MINIMUM_COUNT,
            "memory_sample_interval_seconds": MEMORY_SAMPLE_INTERVAL_SECONDS,
            "post_warmup_fraction": 0.20,
        }
    elif profile == "all":
        common["workload"] = {
            "quick": performance_configuration("quick")["workload"],
            "soak": performance_configuration("soak")["workload"],
        }
    else:
        raise ValueError(f"unsupported performance profile: {profile}")
    return common


def _source_root() -> Path:
    configured = os.getenv("SPELL_QUALIFICATION_SOURCE_ROOT")
    return Path(configured).resolve() if configured else ROOT


def _safe_exception(exc: BaseException) -> str:
    if isinstance(exc, grpc.aio.AioRpcError):
        return f"AioRpcError:{exc.code().name}"
    return type(exc).__name__


def _assertion(
    assertion_id: str,
    passed: bool,
    *,
    observed: Any,
    threshold: Any,
) -> dict[str, Any]:
    return {
        "id": assertion_id,
        "passed": bool(passed),
        "observed": observed,
        "threshold": threshold,
    }


def _gate(
    test_id: str,
    methodology: str,
    metrics: dict[str, Any],
    assertions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "test_id": test_id,
        "executed": True,
        "passed": bool(assertions) and all(item["passed"] for item in assertions),
        "methodology": methodology,
        "metrics": metrics,
        "assertions": assertions,
    }


def _config(generation: str) -> HostConfig:
    return HostConfig(
        driver_host_generation=generation,
        journal=JOURNAL_LIMITS,
    )


def _metadata(config: HostConfig) -> tuple[tuple[str, str], ...]:
    return (
        (CONTRACT_MAJOR_METADATA, "1"),
        (CREDENTIAL_EPOCH_METADATA, str(config.credential_epoch)),
    )


@dataclass(frozen=True)
class ContextToken:
    context_id: str
    context_generation: str
    context_binding_digest: str


def _context_token(config: HostConfig, index: int, prefix: str) -> ContextToken:
    return ContextToken(
        context_id=f"context-{prefix}",
        context_generation=f"context-generation-{index:06d}",
        context_binding_digest=context_binding_digest(
            server_profile_id=config.server_profile_id,
            driver_host_generation=config.driver_host_generation,
            host_profile_digest=config.host_profile_digest,
            schema_version=CONTEXT_SCHEMA_VERSION,
            context_profile_id=CONTEXT_PROFILE_ID,
            synthetic_context_label=SYNTHETIC_CONTEXT_LABEL,
        ),
    )


def _wire_identity(
    config: HostConfig,
    suffix: str,
    *,
    context: ContextToken | None = None,
) -> Any:
    return driver_pb2.RequestIdentity(
        contract_version=driver_pb2.ContractVersion(major=1, minor=0),
        server_profile_id=config.server_profile_id,
        driver_host_generation=config.driver_host_generation,
        host_profile_digest=config.host_profile_digest,
        context_id=context.context_id if context else "",
        context_generation=context.context_generation if context else "",
        context_binding_digest=context.context_binding_digest if context else "",
        operation_id=f"operation-{suffix}",
        attempt_id=f"attempt-{suffix}",
        attempt_number=1,
        correlation_id=f"correlation-{suffix}",
        deadline_unix_ms=(
            time.time_ns() // 1_000_000 + WIRE_DEADLINE_MILLISECONDS
        ),
        credential_epoch=config.credential_epoch,
    )


def _open_request(
    config: HostConfig, suffix: str, context: ContextToken
) -> Any:
    return driver_pb2.OpenContextRequest(
        identity=_wire_identity(config, suffix, context=context),
        configuration=driver_pb2.ContextBindingConfiguration(
            schema_version=CONTEXT_SCHEMA_VERSION,
            context_profile_id=CONTEXT_PROFILE_ID,
            synthetic_context_label=SYNTHETIC_CONTEXT_LABEL,
            expected_context_binding_digest=context.context_binding_digest,
        ),
    )


def _close_request(
    config: HostConfig, suffix: str, context: ContextToken
) -> Any:
    return driver_pb2.CloseContextRequest(
        identity=_wire_identity(config, suffix, context=context),
        detach_settled_attachments=False,
    )


def _health_request(config: HostConfig, suffix: str) -> Any:
    return driver_pb2.HealthRequest(identity=_wire_identity(config, suffix))


def _domain_open_command(
    config: HostConfig, suffix: str, context: ContextToken
) -> OperationCommand:
    return OperationCommand(
        method=Method.OPEN_CONTEXT,
        identity=GenerationIdentity(
            server_profile_id=config.server_profile_id,
            driver_host_generation=config.driver_host_generation,
            host_profile_digest=config.host_profile_digest,
            context_id=context.context_id,
            context_generation=context.context_generation,
            context_binding_digest=context.context_binding_digest,
        ),
        operation_id=f"operation-{suffix}",
        attempt_id=f"attempt-{suffix}",
        attempt_number=1,
        correlation_id=f"correlation-{suffix}",
        deadline_unix_ms=(
            time.time_ns() // 1_000_000 + WIRE_DEADLINE_MILLISECONDS
        ),
        credential_epoch=config.credential_epoch,
        context_schema_version=CONTEXT_SCHEMA_VERSION,
        context_profile_id=CONTEXT_PROFILE_ID,
        synthetic_context_label=SYNTHETIC_CONTEXT_LABEL,
        expected_context_digest=context.context_binding_digest,
    )


@dataclass
class RunningDriver:
    config: HostConfig
    journal: OperationJournal
    host: SimulatorLifecycleHost
    server: grpc.aio.Server
    channel: grpc.aio.Channel
    stub: Any
    service: Any

    async def close(self) -> None:
        await self.channel.close()
        await self.server.stop(grace=1)
        self.host.close()


async def _start_driver(
    config: HostConfig,
    journal_path: Path,
    bundle: PkiBundle,
    *,
    hooks: Any | None = None,
) -> RunningDriver:
    journal = OperationJournal(
        journal_path,
        config.driver_host_generation,
        config.journal,
    )
    host = SimulatorLifecycleHost(config, journal, hooks=hooks)
    server, service = build_server(config, host)
    server_credentials = grpc.ssl_server_credentials(
        ((bundle.server_private_key, bundle.server_certificate),),
        root_certificates=bundle.ca_certificate,
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", server_credentials)
    if port <= 0:
        host.close()
        raise RuntimeError("qualification driver failed to bind loopback mTLS")
    try:
        await server.start()
        channel_credentials = grpc.ssl_channel_credentials(
            root_certificates=bundle.ca_certificate,
            private_key=bundle.client_private_key,
            certificate_chain=bundle.client_certificate,
        )
        channel = grpc.aio.secure_channel(
            f"127.0.0.1:{port}",
            channel_credentials,
            options=(
                ("grpc.ssl_target_name_override", DEFAULT_SERVER_NAME),
                ("grpc.max_receive_message_length", 64 * 1024),
                ("grpc.max_send_message_length", 64 * 1024),
            ),
        )
        await asyncio.wait_for(channel.channel_ready(), timeout=5)
    except BaseException:
        await server.stop(grace=0)
        host.close()
        raise
    return RunningDriver(
        config=config,
        journal=journal,
        host=host,
        server=server,
        channel=channel,
        stub=driver_pb2_grpc.DriverInfrastructureServiceStub(channel),
        service=service,
    )


async def _pace(
    count: int,
    rate: float,
    action: Callable[[int], Awaitable[None]],
) -> tuple[float, list[float]]:
    started = time.perf_counter()
    scheduling_lag_ms: list[float] = []
    for index in range(count):
        target = started + index / rate
        remaining = target - time.perf_counter()
        if remaining > 0:
            await asyncio.sleep(remaining)
        scheduling_lag_ms.append(max(0.0, (time.perf_counter() - target) * 1000))
        await action(index)
    return time.perf_counter() - started, scheduling_lag_ms


def _operation_is(
    response: Any,
    *,
    result: int = driver_pb2.RESULT_CODE_OK,
    certainty: int = driver_pb2.EFFECT_CERTAINTY_CONFIRMED,
) -> bool:
    if not response.HasField("operation") or not response.operation.attempts:
        return False
    attempt = response.operation.attempts[-1]
    return (
        attempt.stage == driver_pb2.OPERATION_STAGE_SETTLED
        and attempt.certainty_present
        and attempt.certainty == certainty
        and attempt.result_code == result
    )


async def qualify_health_rpc(
    directory: Path,
    bundle: PkiBundle,
) -> dict[str, Any]:
    config = _config("perf-health-generation")
    driver = await _start_driver(config, directory / "health.sqlite", bundle)
    latencies_ms: list[float] = []
    errors: list[str] = []
    try:
        warmup = await driver.stub.Health(
            _health_request(config, "perf001-warmup"),
            metadata=_metadata(config),
            timeout=RPC_DEADLINE_SECONDS,
        )
        if not warmup.ready:
            raise RuntimeError("driver was not ready after warmup")

        async def sample(index: int) -> None:
            started = time.perf_counter()
            try:
                response = await driver.stub.Health(
                    _health_request(config, f"perf001-{index:06d}"),
                    metadata=_metadata(config),
                    timeout=RPC_DEADLINE_SECONDS,
                )
                if (
                    not response.ready
                    or response.host_state != driver_pb2.HOST_STATE_READY
                    or response.error.code
                    not in {
                        driver_pb2.SAFE_ERROR_CODE_UNSPECIFIED,
                        driver_pb2.SAFE_ERROR_CODE_NONE,
                    }
                ):
                    errors.append("invalid-health-response")
            except BaseException as exc:
                errors.append(_safe_exception(exc))
            finally:
                latencies_ms.append((time.perf_counter() - started) * 1000)

        duration, scheduling_lag = await _pace(HEALTH_COUNT, HEALTH_RATE, sample)
        achieved = HEALTH_COUNT / duration
        p95 = percentile(latencies_ms, 0.95)
        maximum = max(latencies_ms, default=math.inf)
        metrics = {
            "sample_count": HEALTH_COUNT,
            "duration_seconds": round(duration, 6),
            "achieved_rate_per_second": round(achieved, 3),
            "p95_ms": round(p95, 3),
            "max_ms": round(maximum, 3),
            "error_count": len(errors),
            "schedule_p95_ms": round(percentile(scheduling_lag, 0.95), 3),
            "schedule_max_ms": round(max(scheduling_lag), 3),
            "authorized_rpc_count": int(
                driver.service.authorization_audit.get("authorized", 0)
            ),
            "error_types": sorted(set(errors)),
        }
        assertions = [
            _assertion(
                "perf001-samples",
                HEALTH_COUNT >= 1_000,
                observed=HEALTH_COUNT,
                threshold=">=1000",
            ),
            _assertion(
                "perf001-rate",
                achieved >= 100.0,
                observed=round(achieved, 3),
                threshold=">=100/s",
            ),
            _assertion(
                "perf001-p95",
                p95 <= 50.0,
                observed=round(p95, 3),
                threshold="<=50ms",
            ),
            _assertion(
                "perf001-max",
                maximum <= 250.0,
                observed=round(maximum, 3),
                threshold="<=250ms",
            ),
            _assertion(
                "perf001-errors",
                not errors,
                observed=len(errors),
                threshold="0",
            ),
        ]
        return _gate(
            "V04-PERF-001",
            "1,000 paced Health unary RPCs over authenticated loopback mTLS; "
            "latency is client monotonic call-to-response time.",
            metrics,
            assertions,
        )
    finally:
        await driver.close()


async def qualify_lifecycle_rpc(
    directory: Path,
    bundle: PkiBundle,
) -> dict[str, Any]:
    config = _config("perf-lifecycle-generation")
    hooks = DeterministicHooks(delay_ms=0)
    driver = await _start_driver(
        config,
        directory / "lifecycle.sqlite",
        bundle,
        hooks=hooks,
    )
    acceptance_latencies_ms: list[float] = []
    terminal_latencies_ms: list[float] = []
    errors: list[str] = []
    seen_operation_ids: set[str] = set()
    current_context: ContextToken | None = None
    try:
        async def operation(index: int) -> None:
            nonlocal current_context
            suffix = f"perf002-{index:06d}"
            if index % 2 == 0:
                current_context = _context_token(config, index // 2, "perf002")
                request = _open_request(config, suffix, current_context)
                rpc = driver.stub.OpenContext
            else:
                assert current_context is not None
                request = _close_request(config, suffix, current_context)
                rpc = driver.stub.CloseContext
            started_wall_ms = time.time_ns() // 1_000_000
            started = time.perf_counter()
            try:
                response = await rpc(
                    request,
                    metadata=_metadata(config),
                    timeout=RPC_DEADLINE_SECONDS,
                )
                terminal_latencies_ms.append(
                    (time.perf_counter() - started) * 1000
                )
                if not _operation_is(response):
                    errors.append("invalid-lifecycle-response")
                    return
                attempt = response.operation.attempts[-1]
                acceptance_latencies_ms.append(
                    max(0.0, float(attempt.accepted_unix_ms - started_wall_ms))
                )
                if response.operation.operation_id in seen_operation_ids:
                    errors.append("duplicate-operation-id")
                seen_operation_ids.add(response.operation.operation_id)
                if len(attempt.hook_traces) != 3:
                    errors.append("unexpected-hook-trace-count")
            except BaseException as exc:
                terminal_latencies_ms.append(
                    (time.perf_counter() - started) * 1000
                )
                errors.append(_safe_exception(exc))

        duration, scheduling_lag = await _pace(
            LIFECYCLE_COUNT, LIFECYCLE_RATE, operation
        )
        driver.journal.verify()
        expected_effects = LIFECYCLE_COUNT * 3
        actual_effects = sum(hooks.effect_count.values())
        duplicate_effect_count = max(0, actual_effects - expected_effects)
        stuck_operation_count = sum(
            1
            for item in driver.journal.list_operations()
            if item.attempts[-1].stage is not Stage.SETTLED
        )
        if actual_effects != expected_effects:
            errors.append("effect-cardinality-mismatch")
        acceptance_p95 = percentile(acceptance_latencies_ms, 0.95)
        terminal_p95 = percentile(terminal_latencies_ms, 0.95)
        achieved = LIFECYCLE_COUNT / duration
        metrics = {
            "operation_count": LIFECYCLE_COUNT,
            "duration_seconds": round(duration, 6),
            "achieved_rate_per_second": round(achieved, 3),
            "acceptance_p95_ms": round(acceptance_p95, 3),
            "terminal_p95_ms": round(terminal_p95, 3),
            "terminal_max_ms": round(max(terminal_latencies_ms), 3),
            "duplicate_effect_count": duplicate_effect_count,
            "stuck_operation_count": stuck_operation_count,
            "error_count": len(errors),
            "expected_hook_effect_count": expected_effects,
            "observed_hook_effect_count": actual_effects,
            "unique_operation_count": len(seen_operation_ids),
            "schedule_p95_ms": round(percentile(scheduling_lag, 0.95), 3),
            "schedule_max_ms": round(max(scheduling_lag), 3),
            "error_types": sorted(set(errors)),
        }
        assertions = [
            _assertion(
                "perf002-operations",
                LIFECYCLE_COUNT >= 1_000,
                observed=LIFECYCLE_COUNT,
                threshold=">=1000",
            ),
            _assertion(
                "perf002-rate",
                achieved >= 20.0,
                observed=round(achieved, 3),
                threshold=">=20/s",
            ),
            _assertion(
                "perf002-acceptance-p95",
                acceptance_p95 <= 250.0,
                observed=round(acceptance_p95, 3),
                threshold="<=250ms",
            ),
            _assertion(
                "perf002-terminal-p95",
                terminal_p95 <= 500.0,
                observed=round(terminal_p95, 3),
                threshold="<=500ms",
            ),
            _assertion(
                "perf002-unique-effects",
                duplicate_effect_count == 0
                and actual_effects == expected_effects
                and len(seen_operation_ids) == LIFECYCLE_COUNT,
                observed={
                    "duplicates": duplicate_effect_count,
                    "effects": actual_effects,
                    "operations": len(seen_operation_ids),
                },
                threshold={
                    "duplicates": 0,
                    "effects": expected_effects,
                    "operations": LIFECYCLE_COUNT,
                },
            ),
            _assertion(
                "perf002-terminal-integrity",
                stuck_operation_count == 0 and not errors,
                observed={
                    "stuck": stuck_operation_count,
                    "errors": len(errors),
                },
                threshold={"stuck": 0, "errors": 0},
            ),
        ]
        return _gate(
            "V04-PERF-002",
            "1,000 paced alternating OpenContext/CloseContext unary RPCs over "
            "mTLS with zero-delay deterministic hooks and durable journal verification.",
            metrics,
            assertions,
        )
    finally:
        await driver.close()


@dataclass
class _CancellationControl:
    observed: asyncio.Event
    release: asyncio.Event


class _CoordinatedPreEffectHooks:
    """Hold the first setup hook after cancellation for an exact observation."""

    def __init__(self) -> None:
        self.started: asyncio.Queue[_CancellationControl] = asyncio.Queue()
        self.effect_count: dict[str, int] = {}

    async def run(
        self,
        spec: HookSpec,
        action: HookAction,
        sequence: int,
        cancelled: asyncio.Event,
    ) -> HookTraceRecord:
        started_ms = time.time_ns() // 1_000_000
        if action is not HookAction.SETUP:
            key = f"{spec.hook_id}:{action.value}"
            self.effect_count[key] = self.effect_count.get(key, 0) + 1
            return HookTraceRecord(
                sequence=sequence,
                hook_id=spec.hook_id,
                layer=spec.layer,
                action=action,
                outcome=HookOutcome.COMPLETED,
                started_unix_ms=started_ms,
                completed_unix_ms=time.time_ns() // 1_000_000,
            )
        control = _CancellationControl(asyncio.Event(), asyncio.Event())
        await self.started.put(control)
        await cancelled.wait()
        control.observed.set()
        await control.release.wait()
        return HookTraceRecord(
            sequence=sequence,
            hook_id=spec.hook_id,
            layer=spec.layer,
            action=action,
            outcome=HookOutcome.CANCELLED,
            started_unix_ms=started_ms,
            completed_unix_ms=time.time_ns() // 1_000_000,
            error=SafeFailure(
                ErrorCode.CANCELLED,
                "qualification pre-effect cancellation observed",
            ),
        )


async def _qualify_cancellations(
    directory: Path,
    bundle: PkiBundle,
) -> tuple[dict[str, Any], list[str]]:
    config = _config("perf-cancellation-generation")
    hooks = _CoordinatedPreEffectHooks()
    driver = await _start_driver(
        config,
        directory / "cancellation.sqlite",
        bundle,
        hooks=hooks,
    )
    latencies_ms: list[float] = []
    certainty_changes = 0
    duplicate_effect_count = 0
    errors: list[str] = []
    try:
        for index in range(CANCELLATION_COUNT):
            target_suffix = f"perf003-target-{index:06d}"
            context = _context_token(config, index, "perf003")
            target_request = _open_request(config, target_suffix, context)
            target_call = asyncio.ensure_future(
                driver.stub.OpenContext(
                    target_request,
                    metadata=_metadata(config),
                    timeout=RPC_DEADLINE_SECONDS,
                )
            )
            control = await asyncio.wait_for(hooks.started.get(), timeout=5)
            target_before = driver.journal.get_operation(
                target_request.identity.operation_id
            ).attempts[-1]
            cancel_suffix = f"perf003-cancel-{index:06d}"
            cancel_request = driver_pb2.CancelLifecycleOperationRequest(
                identity=_wire_identity(config, cancel_suffix),
                target_operation_id=target_request.identity.operation_id,
                target_attempt_id=target_request.identity.attempt_id,
            )
            started = time.perf_counter()
            try:
                cancel_response = await driver.stub.CancelLifecycleOperation(
                    cancel_request,
                    metadata=_metadata(config),
                    timeout=RPC_DEADLINE_SECONDS,
                )
                latencies_ms.append((time.perf_counter() - started) * 1000)
                await asyncio.wait_for(control.observed.wait(), timeout=5)
                target_after_cancel = driver.journal.get_operation(
                    target_request.identity.operation_id
                ).attempts[-1]
                if target_before.certainty != target_after_cancel.certainty:
                    certainty_changes += 1
                if not _operation_is(cancel_response):
                    errors.append("invalid-cancel-response")
            except BaseException as exc:
                latencies_ms.append((time.perf_counter() - started) * 1000)
                errors.append(_safe_exception(exc))
            finally:
                control.release.set()
            try:
                target_response = await asyncio.wait_for(target_call, timeout=5)
                if not _operation_is(
                    target_response,
                    result=driver_pb2.RESULT_CODE_CANCELLED,
                    certainty=driver_pb2.EFFECT_CERTAINTY_NO_EFFECT,
                ):
                    errors.append("invalid-cancelled-target-response")
            except BaseException as exc:
                errors.append(_safe_exception(exc))

        driver.journal.verify()
        if hooks.effect_count:
            duplicate_effect_count = sum(hooks.effect_count.values())
            errors.append("pre-effect-hook-ran")
        stuck = sum(
            1
            for item in driver.journal.list_operations()
            if item.attempts[-1].stage is not Stage.SETTLED
        )
        if stuck:
            errors.append("stuck-cancellation-operation")
        return (
            {
                "cancellation_count": CANCELLATION_COUNT,
                "cancel_p95_ms": round(percentile(latencies_ms, 0.95), 3),
                "cancel_max_ms": round(max(latencies_ms, default=math.inf), 3),
                "target_certainty_change_count": certainty_changes,
                "duplicate_effect_count": duplicate_effect_count,
                "stuck_operation_count": stuck,
                "cancellation_error_count": len(errors),
                "cancellation_error_types": sorted(set(errors)),
            },
            errors,
        )
    finally:
        await driver.close()


async def _qualify_restarts(
    directory: Path,
    bundle: PkiBundle,
) -> tuple[dict[str, Any], list[str]]:
    config = _config("perf-restart-generation")
    journal_path = directory / "restart.sqlite"
    readiness_ms: list[float] = []
    reconciliation_ms: list[float] = []
    errors: list[str] = []
    for index in range(RESTART_COUNT):
        suffix = f"perf003-restart-{index:06d}"
        context = _context_token(config, index, "restart")
        command = _domain_open_command(config, suffix, context)
        pre_crash = OperationJournal(
            journal_path,
            config.driver_host_generation,
            config.journal,
        )
        try:
            accepted, duplicate = pre_crash.accept(command)
            if duplicate or accepted.stage is not Stage.ACCEPTED:
                errors.append("accepted-fault-point-not-established")
        finally:
            pre_crash.close()

        restart_started = time.perf_counter()
        driver: RunningDriver | None = None
        try:
            driver = await _start_driver(config, journal_path, bundle)
            health = await driver.stub.Health(
                _health_request(config, f"{suffix}-health"),
                metadata=_metadata(config),
                timeout=RPC_DEADLINE_SECONDS,
            )
            ready_elapsed = (time.perf_counter() - restart_started) * 1000
            readiness_ms.append(ready_elapsed)
            if not health.ready:
                errors.append("restart-not-ready")
            response = await driver.stub.OpenContext(
                _open_request(config, suffix, context),
                metadata=_metadata(config),
                timeout=RPC_DEADLINE_SECONDS,
            )
            reconciliation_ms.append(
                (time.perf_counter() - restart_started) * 1000
            )
            if not _operation_is(
                response,
                result=driver_pb2.RESULT_CODE_INTERNAL,
                certainty=driver_pb2.EFFECT_CERTAINTY_NO_EFFECT,
            ):
                errors.append("restart-did-not-reconcile-accepted-attempt")
            if response.operation.operation_id != command.operation_id:
                errors.append("restart-operation-identity-changed")
        except BaseException as exc:
            errors.append(_safe_exception(exc))
        finally:
            if driver is not None:
                await driver.close()

    verification = OperationJournal(
        journal_path,
        config.driver_host_generation,
        config.journal,
    )
    try:
        verification.verify()
        operations = verification.list_operations()
        stuck = sum(
            1 for item in operations if item.attempts[-1].stage is not Stage.SETTLED
        )
        duplicate_effect_count = sum(
            1
            for item in operations
            if len(item.attempts) != 1
            or item.attempts[-1].certainty is not Certainty.NO_EFFECT
        )
    finally:
        verification.close()
    if stuck:
        errors.append("restart-left-stuck-operation")
    if duplicate_effect_count:
        errors.append("restart-effect-or-attempt-duplicated")
    return (
        {
            "restart_count": RESTART_COUNT,
            "readiness_max_ms": round(max(readiness_ms, default=math.inf), 3),
            "reconciliation_max_ms": round(
                max(reconciliation_ms, default=math.inf), 3
            ),
            "readiness_p95_ms": round(percentile(readiness_ms, 0.95), 3),
            "reconciliation_p95_ms": round(
                percentile(reconciliation_ms, 0.95), 3
            ),
            "restart_stuck_operation_count": stuck,
            "restart_duplicate_effect_count": duplicate_effect_count,
            "restart_error_count": len(errors),
            "restart_error_types": sorted(set(errors)),
        },
        errors,
    )


async def qualify_cancel_and_restart(
    directory: Path,
    bundle: PkiBundle,
) -> dict[str, Any]:
    cancellation, cancellation_errors = await _qualify_cancellations(
        directory, bundle
    )
    restarts, restart_errors = await _qualify_restarts(directory, bundle)
    error_count = len(cancellation_errors) + len(restart_errors)
    duplicate_effect_count = (
        cancellation["duplicate_effect_count"]
        + restarts["restart_duplicate_effect_count"]
    )
    stuck_operation_count = (
        cancellation["stuck_operation_count"]
        + restarts["restart_stuck_operation_count"]
    )
    metrics = {
        **cancellation,
        **restarts,
        "duplicate_effect_count": duplicate_effect_count,
        "stuck_operation_count": stuck_operation_count,
        "error_count": error_count,
    }
    assertions = [
        _assertion(
            "perf003-cancellation-count",
            cancellation["cancellation_count"] >= 100,
            observed=cancellation["cancellation_count"],
            threshold=">=100",
        ),
        _assertion(
            "perf003-cancel-p95",
            cancellation["cancel_p95_ms"] <= 500.0,
            observed=cancellation["cancel_p95_ms"],
            threshold="<=500ms",
        ),
        _assertion(
            "perf003-cancel-max",
            cancellation["cancel_max_ms"] <= 1_000.0,
            observed=cancellation["cancel_max_ms"],
            threshold="<=1000ms",
        ),
        _assertion(
            "perf003-certainty-unchanged",
            cancellation["target_certainty_change_count"] == 0,
            observed=cancellation["target_certainty_change_count"],
            threshold="0 during cancel RPC disposition",
        ),
        _assertion(
            "perf003-restart-count",
            restarts["restart_count"] >= 25,
            observed=restarts["restart_count"],
            threshold=">=25",
        ),
        _assertion(
            "perf003-restart-ready",
            restarts["readiness_max_ms"] <= 5_000.0,
            observed=restarts["readiness_max_ms"],
            threshold="<=5000ms",
        ),
        _assertion(
            "perf003-restart-reconcile",
            restarts["reconciliation_max_ms"] <= 5_000.0,
            observed=restarts["reconciliation_max_ms"],
            threshold="<=5000ms",
        ),
        _assertion(
            "perf003-integrity",
            error_count == duplicate_effect_count == stuck_operation_count == 0,
            observed={
                "errors": error_count,
                "duplicates": duplicate_effect_count,
                "stuck": stuck_operation_count,
            },
            threshold={"errors": 0, "duplicates": 0, "stuck": 0},
        ),
    ]
    return _gate(
        "V04-PERF-003",
        "100 coordinated pre-effect CancelLifecycleOperation RPCs, followed by "
        "25 full gRPC host stop/start cycles over the same journal. Each restart "
        "replays and settles one durably ACCEPTED pre-dispatch attempt by ID.",
        metrics,
        assertions,
    )


def _journal_counts(path: Path) -> tuple[int, int]:
    with sqlite3.connect(path) as connection:
        total = int(
            connection.execute("SELECT COUNT(*) FROM operation_attempts").fetchone()[0]
        )
        stuck = int(
            connection.execute(
                "SELECT COUNT(*) FROM operation_attempts WHERE stage != ?",
                (Stage.SETTLED.value,),
            ).fetchone()[0]
        )
    return total, stuck


async def qualify_soak(
    directory: Path,
    bundle: PkiBundle,
) -> dict[str, Any]:
    config = _config("perf-soak-generation")
    journal_path = directory / "soak.sqlite"
    hooks = DeterministicHooks(delay_ms=0)
    driver = await _start_driver(config, journal_path, bundle, hooks=hooks)
    event_count = max(SOAK_MINIMUM_COUNT, math.ceil(SOAK_RATE * SOAK_DURATION_SECONDS))
    lifecycle_count = 0
    health_count = 0
    successful_count = 0
    errors: list[str] = []
    seen_operation_ids: set[str] = set()
    memory_samples: list[dict[str, float]] = []
    scheduling_lag_ms: list[float] = []
    current_context: ContextToken | None = None
    initial_child_ids = child_process_ids()
    started = time.perf_counter()
    next_memory_sample = started
    next_progress = started + 60.0
    try:
        for index in range(event_count):
            target = started + index / SOAK_RATE
            remaining = target - time.perf_counter()
            if remaining > 0:
                await asyncio.sleep(remaining)
            now = time.perf_counter()
            scheduling_lag_ms.append(max(0.0, (now - target) * 1000))
            if now >= next_memory_sample:
                memory_samples.append(
                    {
                        "elapsed_seconds": round(now - started, 6),
                        "rss_mib": round(
                            resident_memory_bytes() / (1024 * 1024), 3
                        ),
                    }
                )
                next_memory_sample = now + MEMORY_SAMPLE_INTERVAL_SECONDS
            if now >= next_progress:
                print(
                    json.dumps(
                        {
                            "event": "V04-PERF-004-progress",
                            "elapsed_seconds": round(now - started, 3),
                            "issued_count": index,
                            "rss_mib": round(
                                resident_memory_bytes() / (1024 * 1024), 3
                            ),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                next_progress += 60.0

            suffix = f"perf004-{index:06d}"
            try:
                phase = index % 4
                if phase == 0:
                    current_context = _context_token(config, index // 4, "perf004")
                    response = await driver.stub.OpenContext(
                        _open_request(config, suffix, current_context),
                        metadata=_metadata(config),
                        timeout=RPC_DEADLINE_SECONDS,
                    )
                    lifecycle_count += 1
                    valid = _operation_is(response)
                    operation_id = response.operation.operation_id if valid else ""
                elif phase == 2:
                    assert current_context is not None
                    response = await driver.stub.CloseContext(
                        _close_request(config, suffix, current_context),
                        metadata=_metadata(config),
                        timeout=RPC_DEADLINE_SECONDS,
                    )
                    lifecycle_count += 1
                    valid = _operation_is(response)
                    operation_id = response.operation.operation_id if valid else ""
                else:
                    response = await driver.stub.Health(
                        _health_request(config, suffix),
                        metadata=_metadata(config),
                        timeout=RPC_DEADLINE_SECONDS,
                    )
                    health_count += 1
                    valid = (
                        response.ready
                        and response.host_state == driver_pb2.HOST_STATE_READY
                    )
                    operation_id = ""
                if not valid:
                    errors.append("invalid-mixed-response")
                    continue
                if operation_id:
                    if operation_id in seen_operation_ids:
                        errors.append("duplicate-operation-id")
                    seen_operation_ids.add(operation_id)
                successful_count += 1
            except BaseException as exc:
                errors.append(_safe_exception(exc))

        remaining = started + SOAK_DURATION_SECONDS - time.perf_counter()
        if remaining > 0:
            await asyncio.sleep(remaining)
        duration = time.perf_counter() - started
        memory_samples.append(
            {
                "elapsed_seconds": round(duration, 6),
                "rss_mib": round(resident_memory_bytes() / (1024 * 1024), 3),
            }
        )

        final_health_ok = False
        try:
            final_health = await driver.stub.Health(
                _health_request(config, "perf004-final-health"),
                metadata=_metadata(config),
                timeout=RPC_DEADLINE_SECONDS,
            )
            final_health_ok = (
                final_health.ready
                and final_health.host_state == driver_pb2.HOST_STATE_READY
            )
        except BaseException as exc:
            errors.append(_safe_exception(exc))

        journal_total, stuck_operation_count = _journal_counts(journal_path)
        verification_started = time.perf_counter()
        driver.journal.verify()
        verification_seconds = time.perf_counter() - verification_started
        expected_effects = lifecycle_count * 3
        actual_effects = sum(hooks.effect_count.values())
        duplicate_effect_count = max(0, actual_effects - expected_effects)
        if actual_effects != expected_effects:
            errors.append("effect-cardinality-mismatch")
        if journal_total != lifecycle_count:
            errors.append("journal-operation-count-mismatch")

        warmup_boundary = SOAK_DURATION_SECONDS * 0.20
        post_warmup = [
            (item["elapsed_seconds"] / 60.0, item["rss_mib"])
            for item in memory_samples
            if item["elapsed_seconds"] >= warmup_boundary
        ]
        if len(post_warmup) < 2:
            post_warmup = [
                (item["elapsed_seconds"] / 60.0, item["rss_mib"])
                for item in memory_samples
            ]
        baseline_mib = post_warmup[0][1]
        signed_end_delta = post_warmup[-1][1] - baseline_mib
        peak_growth = max(0.0, max(item[1] for item in post_warmup) - baseline_mib)
        signed_slope = linear_slope(post_warmup)
        measured_slope = max(0.0, signed_slope)
        loss_count = event_count - successful_count
        crash_count = 0 if final_health_ok else 1
        final_child_ids = child_process_ids()
        residual_child_ids = sorted(set(final_child_ids).difference(initial_child_ids))
        achieved = event_count / duration
        metrics = {
            "operation_count": event_count,
            "duration_seconds": round(duration, 6),
            "achieved_rate_per_second": round(achieved, 3),
            "loss_count": loss_count,
            "duplicate_effect_count": duplicate_effect_count,
            "stuck_operation_count": stuck_operation_count,
            "crash_count": crash_count,
            "post_warmup_growth_mib": round(peak_growth, 3),
            "post_warmup_slope_mib_per_minute": round(measured_slope, 3),
            "signed_post_warmup_end_delta_mib": round(signed_end_delta, 3),
            "signed_post_warmup_slope_mib_per_minute": round(signed_slope, 3),
            "lifecycle_rpc_count": lifecycle_count,
            "health_rpc_count": health_count,
            "successful_rpc_count": successful_count,
            "journal_operation_count": journal_total,
            "unique_lifecycle_operation_count": len(seen_operation_ids),
            "expected_hook_effect_count": expected_effects,
            "observed_hook_effect_count": actual_effects,
            "error_count": len(errors),
            "error_types": sorted(set(errors)),
            "schedule_p95_ms": round(percentile(scheduling_lag_ms, 0.95), 3),
            "schedule_max_ms": round(max(scheduling_lag_ms), 3),
            "journal_verification_seconds": round(verification_seconds, 6),
            "initial_child_process_ids": list(initial_child_ids),
            "final_child_process_ids": list(final_child_ids),
            "residual_child_process_count": len(residual_child_ids),
            "memory_samples": memory_samples,
        }
        assertions = [
            _assertion(
                "perf004-duration",
                duration >= 600.0,
                observed=round(duration, 6),
                threshold=">=600s",
            ),
            _assertion(
                "perf004-count-rate",
                event_count >= 12_000 and achieved >= 20.0,
                observed={"count": event_count, "rate": round(achieved, 3)},
                threshold={"count": ">=12000", "rate": ">=20/s"},
            ),
            _assertion(
                "perf004-delivery-integrity",
                loss_count
                == duplicate_effect_count
                == stuck_operation_count
                == crash_count
                == 0
                and not errors,
                observed={
                    "loss": loss_count,
                    "duplicates": duplicate_effect_count,
                    "stuck": stuck_operation_count,
                    "crashes": crash_count,
                    "errors": len(errors),
                },
                threshold={
                    "loss": 0,
                    "duplicates": 0,
                    "stuck": 0,
                    "crashes": 0,
                    "errors": 0,
                },
            ),
            _assertion(
                "perf004-memory-growth",
                peak_growth <= 32.0,
                observed=round(peak_growth, 3),
                threshold="<=32MiB",
            ),
            _assertion(
                "perf004-memory-slope",
                measured_slope <= 2.0,
                observed=round(measured_slope, 3),
                threshold="<=2MiB/min",
            ),
            _assertion(
                "perf004-no-observer-leak",
                not residual_child_ids,
                observed=residual_child_ids,
                threshold="no residual child processes",
            ),
        ]
        return _gate(
            "V04-PERF-004",
            "A full 600-second paced mix of alternating OpenContext, Health, "
            "CloseContext, and Health mTLS RPCs. RSS is sampled every 10 seconds; "
            "the first 20% is excluded and growth uses the conservative peak "
            "above the post-warmup baseline.",
            metrics,
            assertions,
        )
    finally:
        await driver.close()


async def _run_selected(profile: str, directory: Path) -> dict[str, Any]:
    bundle = generate_bundle()
    gates: dict[str, Any] = {}
    if profile in {"quick", "all"}:
        gates["V04-PERF-001"] = await qualify_health_rpc(directory, bundle)
        gates["V04-PERF-002"] = await qualify_lifecycle_rpc(directory, bundle)
        gates["V04-PERF-003"] = await qualify_cancel_and_restart(directory, bundle)
    if profile in {"soak", "all"}:
        gates["V04-PERF-004"] = await qualify_soak(directory, bundle)
    return gates


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
    selection.add_argument("--quick", action="store_true")
    selection.add_argument("--soak", action="store_true")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


async def _main_async(args: argparse.Namespace, argv: Sequence[str]) -> int:
    profile = "soak" if args.soak else "all" if args.all else "quick"
    if RUN_ID_PATTERN.fullmatch(args.run_id) is None:
        raise ValueError("performance run ID must be exactly 32 lowercase hex characters")
    source_root = _source_root()
    source_before = source_fingerprint_v04(source_root)
    initial_child_ids = child_process_ids()
    started_at = _now_utc()
    started = time.perf_counter()
    command_argv = [sys.executable, str(Path(__file__).resolve()), *argv]
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "product_version": PRODUCT_VERSION,
        "scope_profile": SCOPE_PROFILE,
        "run_id": args.run_id,
        "profile": profile,
        "started_at": started_at,
        "source": {
            "root": source_root.as_posix(),
            "fingerprint_sha256": source_before,
        },
        "command": {
            "argv": command_argv,
            "argv_sha256": hashlib.sha256(
                "\0".join(command_argv).encode("utf-8")
            ).hexdigest(),
        },
        "configuration": performance_configuration(profile),
        "runtime": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "python_executable": sys.executable,
            "python_executable_sha256": _sha256_file(Path(sys.executable)),
            "grpcio": grpc.__version__,
            "platform": platform.platform(),
            "transport": "loopback mutual TLS gRPC unary RPC",
            "lifecycle": "driver_host.lifecycle.SimulatorLifecycleHost",
            "journal": "driver_host.journal.OperationJournal on runtime-local SQLite",
            "hook_delay_ms": 0,
            "process_sampling": "in-process /proc/self/statm; no CLI observer",
            "initial_child_process_ids": list(initial_child_ids),
            "qualification_image_id": os.getenv(
                "SPELL_QUALIFICATION_IMAGE_ID", "not-injected"
            ),
        },
        "gates": {},
        "acceptance_complete": False,
    }
    fatal_error: str | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="openbexi-spell-v04-performance-"
        ) as temporary_directory:
            report["gates"] = await _run_selected(
                profile, Path(temporary_directory)
            )
    except BaseException as exc:
        fatal_error = _safe_exception(exc)
        report["fatal_error"] = fatal_error

    source_after = source_fingerprint_v04(source_root)
    report["source"]["fingerprint_after_sha256"] = source_after
    report["source"]["stable_during_run"] = source_before == source_after
    final_child_ids = child_process_ids()
    residual_child_ids = sorted(set(final_child_ids).difference(initial_child_ids))
    report["runtime"]["final_child_process_ids"] = list(final_child_ids)
    report["runtime"]["residual_child_process_ids"] = residual_child_ids
    report["finished_at"] = _now_utc()
    report["duration_seconds"] = round(time.perf_counter() - started, 6)
    report["overall_pass"] = (
        fatal_error is None
        and bool(report["gates"])
        and all(gate.get("passed") is True for gate in report["gates"].values())
        and source_before == source_after
        and platform.python_version_tuple()[:2] == ("3", "13")
        and not residual_child_ids
    )
    _write_report(args.output.resolve(), report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_pass"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parsed_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(parsed_argv)
    return asyncio.run(_main_async(args, parsed_argv))


if __name__ == "__main__":
    raise SystemExit(main())
