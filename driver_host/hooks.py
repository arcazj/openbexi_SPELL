"""Deterministic lifecycle-only simulator hooks and fault points."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, FrozenSet

from .domain import (
    ErrorCode,
    HookAction,
    HookLayer,
    HookOutcome,
    HookTraceRecord,
    SafeFailure,
)


@dataclass(frozen=True)
class HookSpec:
    hook_id: str
    layer: HookLayer


class DeterministicHooks:
    """Runs bounded local fixture hooks with injectable delay and failures."""

    def __init__(
        self,
        *,
        delay_ms: int = 0,
        fail_points: FrozenSet[str] = frozenset(),
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        if not 0 <= delay_ms <= 10_000:
            raise ValueError("hook delay is outside the bounded range")
        self.delay_ms = delay_ms
        self.fail_points = fail_points
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self.effect_count: dict[str, int] = {}

    async def run(
        self,
        spec: HookSpec,
        action: HookAction,
        sequence: int,
        cancelled: asyncio.Event,
    ) -> HookTraceRecord:
        started = self._clock_ms()
        if cancelled.is_set():
            return HookTraceRecord(
                sequence=sequence,
                hook_id=spec.hook_id,
                layer=spec.layer,
                action=action,
                outcome=HookOutcome.CANCELLED,
                started_unix_ms=started,
                completed_unix_ms=self._clock_ms(),
                error=SafeFailure(ErrorCode.CANCELLED, "lifecycle cancellation observed"),
            )
        if self.delay_ms:
            try:
                await asyncio.wait_for(cancelled.wait(), timeout=self.delay_ms / 1000)
            except asyncio.TimeoutError:
                pass
            if cancelled.is_set():
                return HookTraceRecord(
                    sequence=sequence,
                    hook_id=spec.hook_id,
                    layer=spec.layer,
                    action=action,
                    outcome=HookOutcome.CANCELLED,
                    started_unix_ms=started,
                    completed_unix_ms=self._clock_ms(),
                    error=SafeFailure(ErrorCode.CANCELLED, "lifecycle cancellation observed"),
                )
        fault_key = f"{spec.hook_id}:{action.value}"
        if fault_key in self.fail_points:
            return HookTraceRecord(
                sequence=sequence,
                hook_id=spec.hook_id,
                layer=spec.layer,
                action=action,
                outcome=HookOutcome.FAILED,
                started_unix_ms=started,
                completed_unix_ms=self._clock_ms(),
                error=SafeFailure(ErrorCode.HOOK, "deterministic lifecycle hook failed"),
            )
        effect_key = f"{spec.hook_id}:{action.value}"
        self.effect_count[effect_key] = self.effect_count.get(effect_key, 0) + 1
        return HookTraceRecord(
            sequence=sequence,
            hook_id=spec.hook_id,
            layer=spec.layer,
            action=action,
            outcome=HookOutcome.COMPLETED,
            started_unix_ms=started,
            completed_unix_ms=self._clock_ms(),
        )
