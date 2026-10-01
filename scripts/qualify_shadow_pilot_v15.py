"""Run a sustained local report/review/incident/restore drill on isolated SQLite."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time
from uuid import uuid4

from sqlalchemy import func, select
from backend.database import create_database
from backend.migrations import run_migrations
from backend.shadow_pilot import ActionRequest, CreateRequest, Plan, RestoreRequest, ShadowPilot, events, runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    latencies = []
    with tempfile.TemporaryDirectory(prefix="spell-shadow-soak-") as temporary:
        root = Path(temporary)
        backups = root / "migration-backups"
        backups.mkdir()
        engine, factory = create_database("sqlite:///" + (root / "pilot.sqlite").as_posix())
        try:
            run_migrations(engine, v0007_backup_directory=backups)
            service = ShadowPilot(factory)
            started = time.monotonic()
            while time.monotonic() - started < 60 or len(latencies) < 16:
                before = time.monotonic()
                current = service.create(CreateRequest(operation_id=uuid4(), reason="sustained shadow drill",
                    plan=Plan(items=["TEMP", "MODE", "COUNTER"])), "soak-owner", "operator")
                current = service.action(current["id"], ActionRequest(operation_id=uuid4(), reason="independent local review",
                    action="REVIEW", expected_revision=current["revision"]), "soak-reviewer", "admin")
                assert current["local_review_recorded"] is True
                backup = service.backup(current["id"])
                for action in ("INCIDENT", "ROLLBACK"):
                    current = service.action(current["id"], ActionRequest(operation_id=uuid4(), reason="read-only recovery drill",
                        action=action, expected_revision=current["revision"]), "soak-owner", "operator")
                    assert current["read_only"] and current["route"] == "SIMULATOR" and not current["local_review_recorded"]
                restored = service.restore(RestoreRequest(operation_id=uuid4(), reason="restore drill", backup=backup), "soak-reviewer", "admin")
                assert restored["state"] == "RESTORED_READ_ONLY" and not restored["local_review_recorded"]
                assert not restored["operational_authorization"] and restored["report_sha256"] == current["report_sha256"]
                latencies.append(time.monotonic() - before)
                time.sleep(1)
            elapsed = time.monotonic() - started
            with factory() as session:
                run_count = session.scalar(select(func.count()).select_from(runs))
                event_count = session.scalar(select(func.count()).select_from(events))
            assert max(latencies) < 10 and run_count == 2 * len(latencies) and event_count == 5 * len(latencies)
            result = {"schema_version": "spell.shadow-pilot-soak/1", "decision": "PASS", "elapsed_seconds": elapsed,
                      "iterations": len(latencies), "batch_seconds": latencies, "runs": run_count, "events": event_count,
                      "failures": 0, "operational_authorization": False, "source_identities": {name: source.identity() for name, source in service.sources.items()}}
            args.output.write_bytes((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
            print(f"Shadow-pilot soak: PASS {len(latencies)} complete drills in {elapsed:.3f}s")
        finally:
            engine.dispose()


if __name__ == "__main__":
    main()
