"""Run the backend health probe with the service identity and no capabilities."""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.credential_bootstrap import drop_privileges


def main() -> int:
    drop_privileges()
    request = urllib.request.Request(
        "http://spell-api:8000/api/v1/health", headers={"Host": "127.0.0.1"}
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        if response.status != 200:
            raise RuntimeError("backend health endpoint is not ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
