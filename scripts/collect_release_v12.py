"""Collect exact pytest identities and static environment skips before source freeze."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pytest
from _pytest.junitxml import mangle_test_address


class Catalog:
    def __init__(self, output):
        self.output = output

    def pytest_collection_finish(self, session):
        rows = []
        for item in session.items:
            names = mangle_test_address(item.nodeid)
            identity = ".".join(names[:-1]) + "::" + names[-1]
            skips = [m for m in item.iter_markers("skipif") if m.args and m.args[0] is True]
            rows.append({"identity": identity, "skip": bool(skips) or item.name in {
                "test_created_compose_driver_has_runtime_isolation_controls",
                "test_live_bundle_builders_are_networkless_independent_and_reproducible",
                "test_backend_restart_reuses_same_epoch_with_no_worker_credential_access"}})
        self.output.write_bytes((json.dumps(rows, indent=2, sort_keys=True) + "\n").encode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("tests", nargs="+")
    args = parser.parse_args()
    raise SystemExit(pytest.main([*args.tests, "--collect-only", "-q", "-p", "no:cacheprovider"], plugins=[Catalog(args.output)]))


if __name__ == "__main__":
    main()
