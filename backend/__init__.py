"""SPELL v0.5 local synthetic simulator backend."""

import sys

if sys.version_info < (3, 10):
    raise RuntimeError("SPELL v0.5 requires Python 3.10 or newer; Python 3.13 is verified")

__version__ = "0.5.0"
