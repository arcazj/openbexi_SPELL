from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Any


@dataclass(eq=False)
class Subscription:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop
    overflowed: bool = False


class EventHub:
    """Best-effort live fan-out; persisted events remain authoritative."""

    def __init__(self, queue_size: int):
        self.queue_size = queue_size
        self._lock = threading.Lock()
        self._subscribers: dict[str, set[Subscription]] = {}

    def subscribe(self, execution_id: str) -> Subscription:
        subscription = Subscription(
            queue=asyncio.Queue(maxsize=self.queue_size),
            loop=asyncio.get_running_loop(),
        )
        with self._lock:
            self._subscribers.setdefault(execution_id, set()).add(subscription)
        return subscription

    def unsubscribe(self, execution_id: str, subscription: Subscription) -> None:
        with self._lock:
            subscribers = self._subscribers.get(execution_id)
            if subscribers is not None:
                subscribers.discard(subscription)
                if not subscribers:
                    self._subscribers.pop(execution_id, None)

    def publish(self, execution_id: str, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers.get(execution_id, ()))
        for subscription in subscribers:
            subscription.loop.call_soon_threadsafe(self._put, subscription, event)

    @staticmethod
    def _put(subscription: Subscription, event: dict[str, Any]) -> None:
        if subscription.overflowed:
            return
        try:
            subscription.queue.put_nowait(event)
        except asyncio.QueueFull:
            subscription.overflowed = True
