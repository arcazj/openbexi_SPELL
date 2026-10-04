"""Check the actual HTTP service and its bounded runtime loops."""
import json
import sys
from urllib.request import urlopen


def main() -> int:
    try:
        with urlopen("http://127.0.0.1:8081/healthz", timeout=2) as response:
            value = json.load(response)
        return 0 if value.get("status") == "ready" else 1
    except (OSError, ValueError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
