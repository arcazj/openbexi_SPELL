"""DSS admission waits for actual in-flight health, without resending commands."""
from __future__ import annotations

import asyncio
import threading
from dataclasses import replace

import pytest

from backend.driver_gateway import DriverGateway, DriverGatewayError
from backend.dss_runtime import DssRuntime
from backend.tests.test_driver_gateway import (
    FakeClient, RecordingFactory, cancel_poll, handshake, health, health_children,
    now_ms, repository, settings,
)
from spell.driver.dss.v1 import dss_pb2


@pytest.mark.parametrize("outcome", [
    "evidence", "command", "invalid_health", "new_generation", "closed_context",
    "revoked", "deadline", "client_failure", "second_refresh",
])
def test_dss_waits_for_health_and_rechecks_admission_before_one_rpc(repository, tmp_path, monkeypatch, outcome):
    async def scenario():
        accepted = handshake(observed_ms=now_ms() - 100)
        client = FakeClient(accepted)
        gateway = DriverGateway(repository, replace(settings(tmp_path, enabled=True), dss_enabled=True),
                                client_factory=RecordingFactory(client))
        await gateway.start()
        await cancel_poll(gateway)
        context, attachment = health_children(repository, accepted)
        valid_health = replace(health(accepted, observed_ms=now_ms() + 100),
                               contexts=(context,), attachments=(attachment,),
                               capacity=replace(accepted.capacity, contexts=1, attachments=1))
        client.health_outcomes.append(valid_health)
        await gateway._health_once()
        runtime = DssRuntime(gateway)
        identity = await asyncio.to_thread(runtime._identity, context.context_id)
        request = dss_pb2.CommandStageRequest(identity=identity)
        health_started, release_health = asyncio.Event(), asyncio.Event()
        second_started, release_second = asyncio.Event(), asyncio.Event()
        dispatch_waiting = asyncio.Event()
        second_tasks = []
        wait_started = threading.Event()
        calls, authorizations = [], []
        authorized = [True]

        async def paused_health():
            health_started.set()
            await release_health.wait()
            if outcome == "invalid_health":
                return replace(valid_health, driver=replace(accepted.driver, host_profile_digest="f" * 64))
            if outcome == "new_generation":
                changed = replace(accepted, driver=replace(accepted.driver, driver_host_generation="replacement-host"))
                client.handshake_outcome = changed
                return health(changed)
            if outcome == "closed_context":
                # An admitted host does not admit its now-closed context.
                return replace(valid_health, contexts=(replace(context, state="FAILED", ready=False),), attachments=(),
                               capacity=replace(valid_health.capacity, attachments=0))
            return valid_health

        async def call(method, value, **kwargs):
            assert gateway.connected
            calls.append((method, value))
            if outcome == "client_failure":
                raise RuntimeError("indeterminate transport")
            return dss_pb2.PacketEvidenceResponse() if method == "PacketEvidence" else "one receipt"

        original_wait = gateway._wait_for_dss_health_refresh
        original_admitted = gateway._dss_admitted_generations
        def observed_admission():
            if second_started.is_set() and not gateway._health_refresh_complete.is_set():
                dispatch_waiting.set()
            return original_admitted()
        def entered_wait(timeout):
            wait_started.set()
            return original_wait(timeout)
        def authorize():
            authorizations.append(threading.get_ident())
            if outcome == "second_refresh" and len(authorizations) == 1:
                async def begin_second():
                    async def another_paused_health():
                        second_started.set()
                        await release_second.wait()
                        return valid_health
                    client.health_outcomes.append(another_paused_health)
                    second_tasks.append(asyncio.create_task(gateway._health_once()))
                    await second_started.wait()
                asyncio.run_coroutine_threadsafe(begin_second(), loop).result(2)
            return authorized[0]
        loop = asyncio.get_running_loop()
        client.dss_call = call
        monkeypatch.setattr(gateway, "_wait_for_dss_health_refresh", entered_wait)
        monkeypatch.setattr(gateway, "_dss_admitted_generations", observed_admission)
        client.health_outcomes.append(paused_health)
        refresh = asyncio.create_task(gateway._health_once())
        await asyncio.wait_for(health_started.wait(), 2)
        assert not gateway.connected
        worker_thread = []
        def invoke():
            worker_thread.append(threading.get_ident())
            if outcome == "evidence":
                return runtime.evidence("epoch")
            return gateway.dss_call("CommandStage", request, authorize=authorize,
                                    timeout_seconds=0.1 if outcome == "deadline" else 2)
        pending = asyncio.create_task(asyncio.to_thread(invoke))
        try:
            assert await asyncio.to_thread(wait_started.wait, 2)
            assert not pending.done()
            assert calls == [] and authorizations == []
            if outcome == "deadline":
                with pytest.raises(DriverGatewayError, match="deadline"):
                    await asyncio.wait_for(pending, 2)
                assert not refresh.done() and calls == []
                release_health.set()
                await refresh
            else:
                if outcome == "revoked":
                    authorized[0] = False
                release_health.set()
                if outcome == "invalid_health":
                    with pytest.raises(DriverGatewayError):
                        await refresh
                else:
                    await refresh
                if outcome == "second_refresh":
                    await asyncio.wait_for(second_started.wait(), 2)
                    await asyncio.wait_for(dispatch_waiting.wait(), 2)
                    assert not gateway.connected and calls == [] and not pending.done()
                    release_second.set()
                    await second_tasks[0]
                if outcome in {"invalid_health", "new_generation", "closed_context", "revoked"}:
                    with pytest.raises(DriverGatewayError):
                        await asyncio.wait_for(pending, 2)
                    assert calls == []
                elif outcome == "client_failure":
                    with pytest.raises(RuntimeError, match="indeterminate transport"):
                        await pending
                    assert len(calls) == 1
                else:
                    assert await pending == ([] if outcome == "evidence" else "one receipt")
                    assert len(calls) == 1
            assert all(thread == worker_thread[0] for thread in authorizations)
            if outcome == "second_refresh":
                assert len(authorizations) == 2
        finally:
            release_health.set()
            release_second.set()
            await asyncio.gather(refresh, pending, return_exceptions=True)
            await asyncio.gather(*second_tasks, return_exceptions=True)
            await gateway.close()
    asyncio.run(scenario())
