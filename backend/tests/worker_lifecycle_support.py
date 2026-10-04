"""Import-light targets for real spawn lifecycle tests.

Spawn imports the target's module before calling it.  These generic children
need no pytest, API fixture, database, or application imports to signal ready.
"""


def _exit_child(code=0):
    raise SystemExit(code)


def _gated_child(started, finish):
    started.set()
    if not finish.wait(10):
        raise RuntimeError("test parent did not release its child")


def _sleeping_child(started):
    import time
    started.set()
    time.sleep(10)
