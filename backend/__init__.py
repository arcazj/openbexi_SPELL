"""SPELL v0.3 simulator-only backend."""

import sys

if sys.version_info < (3, 10):
    raise RuntimeError("SPELL v0.3 requires Python 3.10 or newer; Python 3.13 is verified")

__version__ = "0.3.0"
