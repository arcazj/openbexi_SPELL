#!/usr/bin/env python3
"""Issue one short-lived local development JWT; never exposes an HTTP endpoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.auth import AuthConfig, issue_local_dev_token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--role", choices=("viewer", "operator", "admin"), default="operator")
    parser.add_argument("--lifetime", type=int, default=300)
    args = parser.parse_args()
    token = issue_local_dev_token(
        AuthConfig.from_env(),
        subject=args.subject,
        role=args.role,
        peer_host="127.0.0.1",
        lifetime_seconds=args.lifetime,
    )
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
