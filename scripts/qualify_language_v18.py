"""Produce bounded source and actual simulator service conformance evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.language_conformance_v18 import CASES, COVERAGE_PATH, coverage_contract, qualify, validate_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case["id"] for case in CASES])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-full", action="store_true")
    parser.add_argument("--write-contract", action="store_true")
    args = parser.parse_args()
    if args.write_contract:
        if args.case or args.output or args.require_full:
            parser.error("--write-contract cannot be combined with execution options")
        COVERAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
        COVERAGE_PATH.write_bytes((json.dumps(coverage_contract(), indent=2, ensure_ascii=True) + "\n").encode("ascii"))
        return 0
    report = qualify(args.case)
    if args.case is None: validate_report(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii"))
    print(json.dumps({key: report[key] for key in ("profile_result", "full_compatibility", "artifact_count", "coverage_counts", "gap_reason_counts", "case_count", "direct_count", "rejection_count")}))
    return 2 if args.require_full and not report["full_compatibility"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
