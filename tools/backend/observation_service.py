from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .observation_domain import (
    GetTMMode,
    GetTMQuery,
    GetTMResult,
    GetTimeQuery,
    GetTimeResult,
    ObservationResultCode,
)
from .observation_repository import OBSERVATION_STREAM, ObservationRepository


OBSERVATION_ITEM_IDS = (
    "TM.POWER.BUS_VOLTAGE",
    "TM.POWER.SAFE_MODE",
    "TM.THERMAL.MODE",
)


class ObservationRuntime:
    """Runs freshness projection and best-effort observation outbox wake-ups."""

    def __init__(
        self,
        repository: ObservationRepository,
        *,
        publisher: Callable[[str, dict[str, Any]], Any] | None = None,
        generation_provider: Callable[[], dict[str, Any]] | None = None,
        get_time: Callable[[GetTimeQuery], Any] | None = None,
        get_tm: Callable[[GetTMQuery], Any] | None = None,
        item_ids: tuple[str, ...] = OBSERVATION_ITEM_IDS,
        poll_seconds: float = 0.2,
        freshness_sweep_seconds: float = 0.5,
        collector_deadline_seconds: float = 1.0,
    ):
        if (
            poll_seconds <= 0
            or freshness_sweep_seconds <= 0
            or collector_deadline_seconds <= 0
        ):
            raise ValueError("observation runtime intervals must be positive")
        self.repository = repository
        self.publisher = publisher
        self.generation_provider = generation_provider
        self.get_time = get_time
        self.get_tm = get_tm
        self.item_ids = item_ids
        self.poll_seconds = poll_seconds
        self.freshness_sweep_seconds = freshness_sweep_seconds
        self.collector_deadline_seconds = collector_deadline_seconds
        self._projection_task: asyncio.Task[None] | None = None
        self._collector_task: asyncio.Task[None] | None = None
        self._force_current: set[tuple[str, str]] = set()
        self._closing = False

    async def start(self) -> None:
        if self._projection_task is not None or self._collector_task is not None:
            raise RuntimeError("observation runtime is already started")
        self._closing = False
        self._projection_task = asyncio.create_task(
            self._run_projection(), name="spell-observation-projection-runtime"
        )
        if all(
            callback is not None
            for callback in (self.generation_provider, self.get_time, self.get_tm)
        ):
            self._collector_task = asyncio.create_task(
                self._run_collector(), name="spell-observation-driver-collector"
            )

    async def close(self) -> None:
        self._closing = True
        tasks = tuple(
            task
            for task in (self._collector_task, self._projection_task)
            if task is not None
        )
        self._collector_task = None
        self._projection_task = None
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def publish_once(self) -> int:
        if self.publisher is None:
            return 0
        rows = await asyncio.to_thread(self.repository.pending_outbox, 100)
        published = 0
        for event in rows:
            outcome = self.publisher(OBSERVATION_STREAM, event)
            if inspect.isawaitable(outcome):
                await outcome
            await asyncio.to_thread(
                self.repository.mark_outbox_published,
                event["event_id"],
                published_at=datetime.now(timezone.utc),
            )
            published += 1
        return published

    async def sweep_once(self) -> int:
        return await asyncio.to_thread(self.repository.mark_stale)

    async def collect_once(self) -> int:
        if self.generation_provider is None or self.get_time is None or self.get_tm is None:
            return 0
        generation_set = self.generation_provider()
        if inspect.isawaitable(generation_set):
            generation_set = await generation_set
        host = generation_set["host"]
        contexts = tuple(generation_set["contexts"])
        credential_epoch = int(generation_set["credential_epoch"])
        deadline_ns = time.time_ns() + int(
            self.collector_deadline_seconds * 1_000_000_000
        )
        time_query = GetTimeQuery(
            observation_id=str(uuid.uuid4()),
            generations=host,
            correlation_id="observation-collector-time",
            deadline_unix_ns=deadline_ns,
            credential_epoch=credential_epoch,
        )
        time_result = self.get_time(time_query)
        if inspect.isawaitable(time_result):
            time_result = await time_result
        collected = 0
        if (
            type(time_result) is GetTimeResult
            and time_result.code is ObservationResultCode.OK
            and time_result.observation is not None
        ):
            context_generation_id = (
                contexts[0].context_generation if contexts else None
            )
            await asyncio.to_thread(
                self.repository.record_time,
                time_result.observation,
                context_generation_id=context_generation_id,
            )
            collected += 1
        results = await asyncio.gather(
            *(
                self._collect_item(context, item_id, credential_epoch)
                for context in contexts
                for item_id in self.item_ids
            )
        )
        return collected + sum(results)

    async def _collect_item(
        self, generations: Any, item_id: str, credential_epoch: int
    ) -> int:
        assert self.get_tm is not None
        cursors = await asyncio.to_thread(
            self.repository.restart_cursors, generations.context_generation
        )
        cursor = next((item for item in cursors if item["item_id"] == item_id), None)
        key = (generations.context_generation, item_id)
        use_current = (
            cursor is None
            or cursor["synchronization_state"] == "GAPPED"
            or key in self._force_current
        )
        mode = GetTMMode.CURRENT if use_current else GetTMMode.NEXT
        deadline_ns = time.time_ns() + int(
            self.collector_deadline_seconds * 1_000_000_000
        )
        query = GetTMQuery(
            observation_id=str(uuid.uuid4()),
            generations=generations,
            correlation_id="observation-collector-tm",
            deadline_unix_ns=deadline_ns,
            item_id=item_id,
            mode=mode,
            source_epoch="" if use_current else str(cursor["source_epoch"]),
            after_source_sequence=(
                0 if use_current else int(cursor["after_source_sequence"])
            ),
            credential_epoch=credential_epoch,
        )
        result = self.get_tm(query)
        if inspect.isawaitable(result):
            result = await result
        if type(result) is not GetTMResult:
            return 0
        if result.code is ObservationResultCode.OK and result.sample is not None:
            await asyncio.to_thread(
                self.repository.ingest_sample,
                result.sample,
                mode=mode,
                resynchronized=use_current,
            )
            self._force_current.discard(key)
            return 1
        if result.code is ObservationResultCode.GAP and result.gap is not None:
            if cursor is not None and result.gap.source_epoch == cursor["source_epoch"]:
                await asyncio.to_thread(
                    self.repository.record_gap,
                    generations,
                    source_id=cursor["source_id"],
                    item_id=item_id,
                    bounds=result.gap,
                )
            self._force_current.add(key)
        elif result.code is ObservationResultCode.STALE_GENERATION:
            self._force_current.add(key)
        return 0

    async def _run_projection(self) -> None:
        loop = asyncio.get_running_loop()
        next_sweep = loop.time()
        while not self._closing:
            try:
                await self.publish_once()
                if loop.time() >= next_sweep:
                    await self.sweep_once()
                    next_sweep = loop.time() + self.freshness_sweep_seconds
            except asyncio.CancelledError:
                raise
            except Exception:
                # Projection commits remain authoritative. A failed wake-up or
                # sweep is retried without manufacturing cursor progress.
                pass
            await asyncio.sleep(self.poll_seconds)

    async def _run_collector(self) -> None:
        while not self._closing:
            try:
                await self.collect_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Connection and generation changes are observed again. Durable
                # cursors ensure recovery never advances from an uncommitted read.
                pass
            await asyncio.sleep(self.poll_seconds)


__all__ = ["OBSERVATION_ITEM_IDS", "ObservationRuntime"]
