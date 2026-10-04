from __future__ import annotations

import asyncio
import inspect
import json
import logging
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
from .observation_repository import MAX_NOTIFICATION_ACKNOWLEDGEMENTS, OBSERVATION_STREAM, ObservationRepository, ObservationStaleGenerationError


OBSERVATION_ITEM_IDS = (
    "TM.POWER.BUS_VOLTAGE",
    "TM.POWER.SAFE_MODE",
    "TM.THERMAL.MODE",
)
LOGGER = logging.getLogger(__name__)


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
        self._collection_metrics: dict[str, Any] = {}
        self._next_diagnostic_at = 0.0
        self._collected_samples = 0

    async def _measure(self, phase: str, callback, *args, **kwargs):
        started = time.monotonic()
        try:
            result = callback(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result
        finally:
            elapsed = time.monotonic() - started
            metric = self._collection_metrics.setdefault(phase, {"calls": 0, "max_ms": 0})
            metric["calls"] += 1
            metric["max_ms"] = max(metric["max_ms"], round(elapsed * 1000, 2))

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
        if self.repository.dss_enabled:
            return await self._publish_dss_notifications(rows)
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

    async def _flush_notifications(self, acknowledgements) -> None:
        # Cancellation must join this write, not leave an unobserved thread
        # mutating acknowledgements after the projection task has stopped.
        task = asyncio.create_task(asyncio.to_thread(
            self.repository.mark_outbox_published_batch, acknowledgements))
        cancellation = None
        while True:
            try:
                await asyncio.shield(task)
                break
            except asyncio.CancelledError as exc:
                cancellation = cancellation or exc
                if task.done():
                    # Retrieve an exception if completion raced cancellation.
                    try:
                        task.result()
                    except BaseException:
                        pass
                    break
            except BaseException:
                if cancellation is not None:
                    raise cancellation
                raise
        if cancellation is not None:
            raise cancellation

    async def _publish_dss_notifications(self, rows) -> int:
        published = 0
        prefix = []
        try:
            for event in rows:
                outcome = self.publisher(OBSERVATION_STREAM, event)
                if inspect.isawaitable(outcome):
                    await outcome
                prefix.append((event["event_id"], datetime.now(timezone.utc)))
                published += 1
                if len(prefix) == MAX_NOTIFICATION_ACKNOWLEDGEMENTS:
                    batch, prefix = prefix, []
                    await self._flush_notifications(batch)
        except BaseException:
            if prefix:
                try:
                    await self._flush_notifications(prefix)
                except BaseException:
                    # The original callback/cancellation remains primary;
                    # unacknowledged stable event IDs remain replayable.
                    pass
            raise
        if prefix:
            await self._flush_notifications(prefix)
        return published

    async def sweep_once(self) -> int:
        return await asyncio.to_thread(self.repository.mark_stale)

    async def collect_once(self) -> int:
        self._collection_metrics = {}
        self._collected_samples = 0
        if self.generation_provider is None or self.get_time is None or self.get_tm is None:
            return 0
        generation_set = await self._measure("generation", self.generation_provider)
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
        time_result = await self._measure("clock_rpc", self.get_time, time_query)
        collected = 0
        async def collect_items():
            cursors = {}
            for context in contexts:
                rows = await self._measure("cursor_read", asyncio.to_thread,
                    self.repository.restart_cursors, context.context_generation)
                by_item = {}
                for row in rows:
                    by_item.setdefault(row["item_id"], row)
                cursors[context.context_generation] = by_item
            outcomes = await asyncio.gather(*(
                self._collect_item(context, item_id, credential_epoch,
                    cursor=cursors[context.context_generation].get(item_id))
                for context in contexts for item_id in self.item_ids), return_exceptions=True)
            # A rejected epoch must not leave peer ingestion tasks running while
            # the next poll starts another cohort against the same projection.
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    raise outcome
            return outcomes

        # DSS clocks belong to a physical satellite epoch. Admit telemetry first;
        # a clock captured across a reset must never retain the previous head.
        results = await collect_items() if self.repository.dss_enabled else []
        if (
            type(time_result) is GetTimeResult
            and time_result.code is ObservationResultCode.OK
            and time_result.observation is not None
        ):
            context_generation_id = (
                contexts[0].context_generation if contexts else None
            )
            try:
                await self._measure("clock_commit", asyncio.to_thread,
                    self.repository.record_time,
                    time_result.observation,
                    context_generation_id=context_generation_id,
                )
                collected += 1
            except ObservationStaleGenerationError:
                if not self.repository.dss_enabled:
                    raise
        if not self.repository.dss_enabled:
            results = await collect_items()
        self._collected_samples = sum(results)
        return collected + self._collected_samples

    async def _collect_item(
        self, generations: Any, item_id: str, credential_epoch: int,
        *, cursor: dict[str, Any] | None,
    ) -> int:
        assert self.get_tm is not None
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
        result = await self._measure("sample_rpc", self.get_tm, query)
        if type(result) is not GetTMResult:
            return 0
        codes = self._collection_metrics.setdefault("result_codes", {})
        codes[result.code.value] = codes.get(result.code.value, 0) + 1
        if result.code is ObservationResultCode.OK and result.sample is not None:
            await self._measure("sample_commit", asyncio.to_thread,
                self.repository.ingest_sample,
                result.sample,
                mode=mode,
                resynchronized=use_current,
                **({"include_projection": False} if self.repository.dss_enabled else {}),
            )
            self._force_current.discard(key)
            return 1
        if result.code is ObservationResultCode.GAP and result.gap is not None:
            if cursor is not None and result.gap.source_epoch == cursor["source_epoch"]:
                await self._measure("gap_commit", asyncio.to_thread,
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
            started = time.monotonic()
            error_type = None
            try:
                await self.collect_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Connection and generation changes are observed again. Durable
                # cursors ensure recovery never advances from an uncommitted read.
                error_type = type(exc).__name__
            elapsed = time.monotonic() - started
            if (error_type is not None or elapsed > self.collector_deadline_seconds) and time.monotonic() >= self._next_diagnostic_at:
                # Bounded phase metadata only: never samples, values, request
                # bodies or credentials. Healthy polls produce no log volume.
                LOGGER.warning("observation collector delayed: %s", json.dumps({
                    "elapsed_ms": round(elapsed * 1000, 2), "error_type": error_type,
                    "phases": self._collection_metrics}, sort_keys=True))
                self._next_diagnostic_at = time.monotonic() + 30
            delay = self.poll_seconds
            if self.repository.dss_enabled and error_type is None and self._collected_samples:
                # Successful DSS NEXT cohorts must catch up without adding a
                # fixed idle interval to the time already spent collecting.
                # Clock-only/failed polls retain backoff; even zero must yield.
                delay = max(0.0, self.poll_seconds - elapsed)
            await asyncio.sleep(delay)


__all__ = ["OBSERVATION_ITEM_IDS", "ObservationRuntime"]
