"""SPELL v0.2 simulator-only backend."""

import sys

if sys.version_info < (3, 10):
    raise RuntimeError("SPELL v0.2 requires Python 3.10 or newer; Python 3.12+ is preferred")

__version__ = "0.2.0"
