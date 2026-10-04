"""Control the local DSS using its observed epoch and revision."""
from __future__ import annotations

import argparse
import json
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("PAUSE", "RESUME", "STEP"))
    parser.add_argument("--ticks", type=int, default=1)
    args = parser.parse_args()
    base = "http://127.0.0.1:8081/api/v1"
    with urlopen(base + "/state", timeout=5) as response:
        state = json.load(response)
    body = {"action": args.action, "expected_epoch": state["epoch"], "expected_revision": state["revision"]}
    if args.action == "STEP":
        body["ticks"] = args.ticks
    request = Request(base + "/control", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        print(response.read().decode())


if __name__ == "__main__":
    main()
