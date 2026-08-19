#!/usr/bin/env python3
"""Fail if the API begins using Starlette surfaces excluded by policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical JSON evidence")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    policy = json.loads((root / "security/starlette_exposure_policy.json").read_text("utf-8"))
    source = (root / "backend/app.py").read_text("utf-8")
    violations = [symbol for symbol in policy["forbidden_symbols"] if symbol in source]
    if violations:
        raise SystemExit(f"forbidden Starlette surface exposed: {', '.join(violations)}")
    if "TrustedHostMiddleware" not in source:
        raise SystemExit("TrustedHostMiddleware is required")
    if args.json:
        print(
            json.dumps(
                {
                    "passed": True,
                    "policy": "security/starlette_exposure_policy.json",
                    "violation_count": 0,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        print("Starlette exposure policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
