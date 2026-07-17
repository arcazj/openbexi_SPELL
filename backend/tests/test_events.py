from __future__ import annotations

import asyncio

from backend.events import EventHub, Subscription


def test_closed_subscriber_loop_cannot_interrupt_authoritative_progress() -> None:
    class ClosedLoop:
        def call_soon_threadsafe(self, *_args) -> None:
            raise RuntimeError("event loop is closed")

    hub = EventHub(queue_size=4)
    subscription = Subscription(
        queue=asyncio.Queue(maxsize=4),
        loop=ClosedLoop(),  # type: ignore[arg-type]
    )
    with hub._lock:
        hub._subscribers["execution"] = {subscription}

    hub.publish("execution", {"sequence": 1})

    assert "execution" not in hub._subscribers
