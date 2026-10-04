"""A failed observation batch cannot leave ingestion peers behind the next poll."""
import asyncio
from types import SimpleNamespace

import pytest

from backend.observation_domain import GetTimeResult, ObservationError, ObservationResultCode
from backend.observation_repository import ObservationConflictError
from backend.observation_service import ObservationRuntime
from backend.tests.test_driver_client_observation import generations


def unavailable_time(query):
    return GetTimeResult(ObservationResultCode.NOT_AVAILABLE,
        error=ObservationError(ObservationResultCode.NOT_AVAILABLE, "clock unavailable during epoch reset"))


@pytest.mark.parametrize("dss", [False, True])
def test_failed_epoch_batch_settles_peers_before_next_collector_poll(dss):
    async def scenario():
        repository = SimpleNamespace(dss_enabled=dss, restart_cursors=lambda _: [])
        runtime = ObservationRuntime(repository,
            generation_provider=lambda: {"host": generations(), "contexts": (generations(context=True),), "credential_epoch": 1},
            get_time=unavailable_time,
            get_tm=lambda query: None, item_ids=("retired-epoch", "in-flight-peer"), poll_seconds=0.005)
        failed, peer_entered, finish_peer, next_cohort = (asyncio.Event() for _ in range(4))
        calls, settled = [], []
        async def collect_item(context, item_id, credential_epoch, *, cursor):
            calls.append(item_id)
            if len(calls) > 2:
                assert settled == ["peer-committed-or-rejected"]
                next_cohort.set()
                return 0
            if item_id == "retired-epoch":
                await peer_entered.wait()
                failed.set()
                raise ObservationConflictError("retired DSS satellite epoch")
            peer_entered.set()
            await finish_peer.wait()
            settled.append("peer-committed-or-rejected")
            return 1
        runtime._collect_item = collect_item
        task = asyncio.create_task(runtime._run_collector())
        try:
            await asyncio.wait_for(failed.wait(), 1)
            # Several complete poll intervals pass while the already-dispatched
            # peer remains blocked. An early-return gather starts another batch.
            await asyncio.sleep(0.03)
            assert calls == ["retired-epoch", "in-flight-peer"]
            assert not next_cohort.is_set()
            finish_peer.set()
            await asyncio.wait_for(next_cohort.wait(), 1)
        finally:
            finish_peer.set()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    asyncio.run(scenario())


def test_collect_once_reports_failure_only_after_all_dispatched_items_settle():
    async def scenario():
        repository = SimpleNamespace(dss_enabled=True, restart_cursors=lambda _: [])
        runtime = ObservationRuntime(repository,
            generation_provider=lambda: {"host": generations(), "contexts": (generations(context=True),), "credential_epoch": 1},
            get_time=unavailable_time,
            get_tm=lambda query: None, item_ids=("bad", "peer"))
        peer_started, release = asyncio.Event(), asyncio.Event()
        settled = []
        async def collect_item(context, item_id, credential_epoch, *, cursor):
            if item_id == "bad":
                await peer_started.wait()
                raise ObservationConflictError("retired epoch is rejected")
            peer_started.set()
            await release.wait()
            settled.append(True)
            return 1
        runtime._collect_item = collect_item
        batch = asyncio.create_task(runtime.collect_once())
        await asyncio.wait_for(peer_started.wait(), 1)
        await asyncio.sleep(0)
        assert not batch.done()
        release.set()
        with pytest.raises(ObservationConflictError, match="retired epoch"):
            await batch
        assert settled == [True]
    asyncio.run(scenario())
