"""Parent-side ownership of a worker's multiprocessing lifecycle.

CPython's Process liveness and exit-code reads can reap the child.  The same
raw child is also polled by the implicit cleanup in another Process.start().
Guard the actual Popen poll, as well as explicit lifecycle calls, so its real
exit status is published before another observer can interpret it.
"""
from __future__ import annotations

import threading
import weakref


# Only production children created through this facade participate.  Registry
# operations always precede a per-child lock; start must not hold its own child
# lock while CPython cleanup visits locks belonging to other children.
_REGISTRY_LOCK = threading.RLock()


class WorkerProcess:
    """Wrap an existing context Process without changing its spawn payload."""

    def __init__(self, process):
        self._process = process
        self._lock = threading.RLock()

    def start(self):
        with _REGISTRY_LOCK:
            result = self._process.start()
            # The raw Process has already been serialized.  Neither this lock
            # nor this parent-only closure is attached to the spawn payload.
            with self._lock:
                popen = getattr(self._process, "_popen", None)
                if popen is not None:
                    poll_ref = weakref.WeakMethod(popen.poll)
                    lock = self._lock

                    def guarded_poll(*args, **kwargs):
                        with lock:
                            poll = poll_ref()
                            if poll is None:
                                raise ValueError("worker process poll owner is unavailable")
                            return poll(*args, **kwargs)

                    popen.poll = guarded_poll
            return result

    def join(self, timeout=None):
        with self._lock:
            return self._process.join(timeout)

    def is_alive(self):
        with self._lock:
            return self._process.is_alive()

    @property
    def exitcode(self):
        with self._lock:
            return self._process.exitcode

    def terminate(self):
        with self._lock:
            return self._process.terminate()

    def kill(self):
        with self._lock:
            return self._process.kill()

    def close(self):
        with _REGISTRY_LOCK, self._lock:
            return self._process.close()

    def __getattr__(self, name):
        # Existing PID/name/sentinel/private diagnostic reads retain their raw
        # Process semantics, including errors before start or after close.
        with self._lock:
            return getattr(self._process, name)

    def __repr__(self):
        with self._lock:
            return repr(self._process)
