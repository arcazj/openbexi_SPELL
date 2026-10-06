from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import os
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, insert, inspect, select, update
from sqlalchemy.exc import OperationalError

from backend import migrations
from backend.database import create_database, utc_now
from backend.migrations.versions import v0010_shadow_pilot as migration
from backend.shadow_pilot import (ActionRequest, CreateRequest, PilotError, Plan, ShadowPilot,
                                  build_report, digest, events, runs)
from backend.tests.migration_support import reset_test_database, run_migrations

PREFIX = "/api/v1/shadow-pilot"


def new_request(**changes):
    return {"operation_id": str(uuid.uuid4()), "reason": "local shadow readiness drill",
            "plan": {"items": ["TEMP", "MODE", "COUNTER"], "repetitions": 2}, **changes}


def create(client, headers, **changes):
    request = new_request(**changes)
    response = client.post(PREFIX + "/runs", headers=headers, json=request)
    assert response.status_code == 201, response.text
    return response.json(), request


def act(client, headers, run, action, **changes):
    request = {"operation_id": str(uuid.uuid4()), "reason": "qualification action",
               "expected_revision": run["revision"], "action": action, **changes}
    return client.post(f"{PREFIX}/runs/{run['id']}/actions", headers=headers, json=request)


def test_role_identity_spoofing_and_read_only_profile(client, viewer_headers, operator_headers):
    assert client.get(PREFIX + "/profile").status_code == 401
    profile = client.get(PREFIX + "/profile", headers=viewer_headers).json()
    assert profile["operational_authorization"] is False and profile["real_pilot_qualified"] is False
    request = new_request()
    assert client.post(PREFIX + "/runs", headers={**viewer_headers, "X-Role": "admin"}, json=request).status_code == 403
    value, _ = create(client, operator_headers)
    assert value["creator"] == "pytest-operator" and value["read_only"] is True
    assert client.get(PREFIX + "/runs", headers=viewer_headers).json()["items"][0]["id"] == value["id"]


@pytest.mark.parametrize("changes", [{"plan": {"items": []}}, {"plan": {"items": ["TEMP"] * 9}},
    {"plan": {"items": ["TEMP", "TEMP"]}}, {"plan": {"items": ["TEMP"], "repetitions": True}},
    {"plan": {"items": ["TEMP"], "repetitions": 5}}, {"plan": {"items": ["TEMP"], "endpoint": "http://invalid"}},
    {"reason": " "}, {"actor": "other"}, {"plan": {"items": ["missing"]}}, {"operation_id": "invalid"}])
def test_closed_schema_and_workload_bounds(client, operator_headers, changes):
    response = client.post(PREFIX + "/runs", headers=operator_headers, json=new_request(**changes))
    assert response.status_code == 422


def test_differential_report_is_complete_hash_bound_and_review_requires_another_admin(client, operator_headers, admin_headers, viewer_headers):
    run, request = create(client, operator_headers)
    response = client.get(f"{PREFIX}/runs/{run['id']}", headers=viewer_headers).json()
    assert len(response["report"]["rows"]) == 6
    assert response["report"]["equivalent"] and response["report"]["budget_passed"]
    assert digest(response["report"]) == response["report_sha256"]
    for row in response["report"]["rows"]:
        assert row["comparison"]["reference"]["source"]["digest"] != row["comparison"]["simulator"]["source"]["digest"]
    assert act(client, operator_headers, run, "REVIEW").status_code == 403
    reviewed = act(client, admin_headers, run, "REVIEW")
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["local_review_recorded"] and not reviewed.json()["operational_authorization"]
    own, _ = create(client, admin_headers)
    assert act(client, admin_headers, own, "REVIEW").status_code == 403
    # Creation replay returns its original durable receipt after later review.
    assert client.post(PREFIX + "/runs", headers=operator_headers, json=request).json() == run


@pytest.mark.parametrize("item", ["STALE", "UNKNOWN", "MISSING", "OPAQUE"])
def test_non_good_reports_cannot_be_reviewed(client, operator_headers, admin_headers, item):
    run, _ = create(client, operator_headers, plan={"items": [item]})
    assert act(client, admin_headers, run, "REVIEW").status_code == 409


def test_incident_and_rollback_revoke_readiness_and_cannot_reopen(client, operator_headers, admin_headers):
    run, _ = create(client, operator_headers)
    reviewed = act(client, admin_headers, run, "REVIEW").json()
    started = time.monotonic()
    incident = act(client, operator_headers, reviewed, "INCIDENT").json()
    assert time.monotonic() - started < 5
    assert incident["route"] == "SIMULATOR" and incident["local_review_recorded"] is False
    rolled = act(client, operator_headers, incident, "ROLLBACK").json()
    assert rolled["state"] == "ROLLED_BACK_READ_ONLY"
    assert act(client, admin_headers, rolled, "REVIEW").status_code == 409
    detail = client.app.state.shadow_pilot.get(run["id"])
    assert [e["action"] for e in detail["events"]] == ["CREATE", "REVIEW", "INCIDENT", "ROLLBACK"]


def test_operation_retry_conflict_stale_revision_and_service_restart(client, operator_headers):
    run, request = create(client, operator_headers)
    assert client.post(PREFIX + "/runs", headers=operator_headers, json={**request, "reason": "different"}).status_code == 409
    body = {"operation_id": str(uuid.uuid4()), "expected_revision": 1, "action": "INCIDENT", "reason": "retain outcome"}
    url = f"{PREFIX}/runs/{run['id']}/actions"
    first = client.post(url, headers=operator_headers, json=body)
    assert first.status_code == 200
    assert client.post(url, headers=operator_headers, json=body).json() == first.json()
    assert client.post(url, headers=operator_headers, json={**body, "reason": "changed"}).status_code == 409
    assert act(client, operator_headers, run, "ROLLBACK").status_code == 409
    restarted = ShadowPilot(client.app.state.session_factory)
    assert restarted.get(run["id"])["state"] == "INCIDENT_READ_ONLY"
    assert len(restarted.get(run["id"])["events"]) == 2


def test_audit_order_uses_durable_revision_when_wall_clock_moves_backwards(client, operator_headers, monkeypatch):
    from backend import shadow_pilot
    run, _ = create(client, operator_headers)
    monkeypatch.setattr(shadow_pilot, "utc_now", lambda: datetime(2000, 1, 1, tzinfo=timezone.utc))
    assert act(client, operator_headers, run, "INCIDENT").status_code == 200
    history = client.app.state.shadow_pilot.get(run["id"])["events"]
    assert [event["action"] for event in history] == ["CREATE", "INCIDENT"]
    assert [event["result"]["revision"] for event in history] == [1, 2]


def test_backup_restore_preserves_trace_but_never_restores_review(client, operator_headers, admin_headers, viewer_headers):
    run, _ = create(client, operator_headers)
    assert act(client, admin_headers, run, "REVIEW").status_code == 200
    backup = client.get(f"{PREFIX}/runs/{run['id']}/backup", headers=viewer_headers).json()
    body = {"operation_id": str(uuid.uuid4()), "reason": "restore drill", "backup": backup}
    assert client.post(PREFIX + "/restore", headers=operator_headers, json=body).status_code == 403
    response = client.post(PREFIX + "/restore", headers=admin_headers, json=body)
    assert response.status_code == 201, response.text
    restored = response.json()
    assert restored["state"] == "RESTORED_READ_ONLY" and restored["route"] == "SIMULATOR"
    assert not restored["local_review_recorded"] and restored["report_sha256"] == run["report_sha256"]
    assert client.post(PREFIX + "/restore", headers=admin_headers, json=body).json() == restored
    detail = client.app.state.shadow_pilot.get(restored["id"])
    assert detail["origin"]["backup_sha256"] == backup["sha256"]
    assert detail["origin"]["audit_authority"] == "IMPORTED_UNTRUSTED_PROVENANCE"
    assert act(client, admin_headers, restored, "REVIEW").status_code == 403  # Restorer is creator.
    with pytest.raises(PilotError, match="PILOT_NOT_REVIEWABLE"):
        client.app.state.shadow_pilot.action(restored["id"], ActionRequest(operation_id=uuid.uuid4(), reason="independent review",
            action="REVIEW", expected_revision=1), "different-reviewer", "admin")


@pytest.mark.parametrize("tamper", ["digest", "trace", "source", "authority", "nan", "extra", "empty_history", "oversized", "audit_revision", "audit_result", "boolean"])
def test_restore_rejects_tampered_or_unbounded_evidence(client, operator_headers, admin_headers, tamper):
    run, _ = create(client, operator_headers)
    backup = client.app.state.shadow_pilot.backup(run["id"])
    original = backup["payload"]["run"]
    if tamper == "digest": backup["sha256"] = "0" * 64
    elif tamper == "trace": original["report"]["rows"][0]["comparison"]["reference"]["value"]["value"] = 123
    elif tamper == "source": original["report"]["rows"][0]["comparison"]["reference"]["source"]["digest"] = "0" * 64
    elif tamper == "authority": original["operational_authorization"] = True
    elif tamper == "nan": original["report"]["comparison_latency_ms"][0] = "NaN"
    elif tamper == "extra": backup["payload"]["endpoint"] = "http://invalid"
    elif tamper == "empty_history": original["events"] = []
    elif tamper == "audit_revision": original["events"][0]["result"]["revision"] = 2
    elif tamper == "audit_result": original["events"][0]["result"]["operational_authorization"] = True
    elif tamper == "boolean": original["report"]["equivalent"] = 1
    else: original["origin"] = {"oversized": "x" * 262144}
    if tamper != "digest":
        original["report_sha256"] = digest(original["report"])
        backup["sha256"] = digest(backup["payload"])
    result = client.post(PREFIX + "/restore", headers=admin_headers,
                         json={"operation_id": str(uuid.uuid4()), "reason": "tamper drill", "backup": backup})
    assert result.status_code == 422, result.text


def test_restore_validation_remains_enabled_under_python_optimization(client, operator_headers):
    run, _ = create(client, operator_headers)
    backup = client.app.state.shadow_pilot.backup(run["id"])
    backup["payload"]["run"]["operational_authorization"] = True
    backup["sha256"] = digest(backup["payload"])
    request = {"operation_id": str(uuid.uuid4()), "reason": "optimized runtime validation", "backup": backup}
    code = """
import json,sys
from backend.shadow_pilot import ShadowPilot, RestoreRequest, PilotError
try:
    ShadowPilot(None).restore(RestoreRequest.model_validate(json.load(sys.stdin)), 'reviewer', 'admin')
except PilotError as exc:
    if exc.code != 'INVALID_PILOT_BACKUP': raise
else:
    raise RuntimeError('invalid backup was accepted')
"""
    result = subprocess.run([sys.executable, "-O", "-c", code], input=json.dumps(request), text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("phase", ["before", "after_report"])
def test_database_failure_does_not_fabricate_acceptance(client, operator_headers, monkeypatch, phase):
    service = client.app.state.shadow_pilot
    def fail(*_args):
        raise OperationalError("synthetic", {}, RuntimeError("storage unavailable"))
    monkeypatch.setattr(service, "_lock" if phase == "before" else "_event", fail)
    request = new_request()
    response = client.post(PREFIX + "/runs", headers=operator_headers, json=request)
    assert response.status_code == 503
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(runs)) == 0
        assert session.scalar(select(func.count()).select_from(events)) == 0


def test_non_owner_cannot_change_a_run_and_corrupt_report_cannot_be_reviewed(client, operator_headers, admin_headers):
    run, _ = create(client, operator_headers)
    service = client.app.state.shadow_pilot
    with pytest.raises(PilotError, match="PILOT_OWNER_REQUIRED"):
        service.action(run["id"], ActionRequest(operation_id=uuid.uuid4(), reason="other owner",
            action="INCIDENT", expected_revision=1), "another-operator", "operator")
    report = copy.deepcopy(service.get(run["id"])["report"])
    report["rows"][0]["comparison"]["reference"]["value"]["value"] = 123
    with client.app.state.session_factory.begin() as session:
        session.execute(update(runs).where(runs.c.id == run["id"]).values(report=report, report_sha256=digest(report)))
    response = act(client, admin_headers, run, "REVIEW")
    assert response.status_code == 409 and response.json()["detail"]["code"] == "PILOT_REPORT_INTEGRITY"


def test_record_capacity_keeps_existing_idempotent_receipts_readable(client, operator_headers):
    run, request = create(client, operator_headers, plan={"items": ["TEMP"]})
    with client.app.state.session_factory.begin() as session:
        original = dict(session.execute(select(runs).where(runs.c.id == run["id"])).mappings().one())
        session.execute(insert(runs), [{**original, "id": str(uuid.uuid4())} for _ in range(511)])
    assert client.post(PREFIX + "/runs", headers=operator_headers, json=new_request()).status_code == 429
    assert client.post(PREFIX + "/runs", headers=operator_headers, json=request).json() == run
    assert len(client.app.state.shadow_pilot.list()["items"]) == 32


def test_largest_current_catalog_plan_retains_every_bounded_comparison(client, operator_headers):
    run, _ = create(client, operator_headers, plan={"items": ["TEMP", "MODE", "COUNTER", "STALE", "UNKNOWN", "OPAQUE", "MISSING"], "repetitions": 4})
    report = client.app.state.shadow_pilot.get(run["id"])["report"]
    assert len(report["rows"]) == 28 and len(report["comparison_latency_ms"]) == 28
    assert report["budget_passed"] and not report["equivalent"]


def test_competing_operations_preserve_one_revision_and_retryable_identity(client, operator_headers):
    run, _ = create(client, operator_headers)
    service = client.app.state.shadow_pilot
    requests = [ActionRequest(operation_id=uuid.uuid4(), reason="competing controller", action="INCIDENT", expected_revision=1) for _ in range(2)]
    def call(request):
        try:
            return service.action(run["id"], request, "pytest-operator", "operator")
        except (PilotError, OperationalError):
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(call, requests))
    assert sum(reply is not None for reply in replies) == 1
    assert service.get(run["id"])["revision"] == 2
    assert len(service.get(run["id"])["events"]) == 2


def test_bounded_readback_load_preserves_report(client, operator_headers):
    run, _ = create(client, operator_headers)
    service = client.app.state.shadow_pilot
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: service.get(run["id"]), range(128)))
    assert time.monotonic() - started < 30
    assert all(r["report_sha256"] == run["report_sha256"] and r["revision"] == 1 for r in results)


def test_concurrent_readback_never_mixes_row_and_audit_revisions(client, operator_headers):
    run, _ = create(client, operator_headers)
    service = client.app.state.shadow_pilot
    def writer():
        current = run
        for _ in range(10):
            current = service.action(run["id"], ActionRequest(operation_id=uuid.uuid4(), reason="snapshot contention",
                action="INCIDENT", expected_revision=current["revision"]), "pytest-operator", "operator")
    def reader():
        for _ in range(128):
            current = service.get(run["id"])
            assert current["revision"] == len(current["events"]) == current["events"][-1]["result"]["revision"]
            assert current["state"] == current["events"][-1]["result"]["state"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        writes, reads = pool.submit(writer), pool.submit(reader)
        writes.result(timeout=30)
        reads.result(timeout=30)


def test_migration_is_static_and_repeated_start_preserves_reports(client, operator_headers):
    run, _ = create(client, operator_headers)
    engine = client.app.state.session_factory.kw["bind"]
    assert run_migrations(engine) == ()
    with engine.connect() as connection:
        migration.verify(connection)
    assert client.app.state.shadow_pilot.get(run["id"])["report_sha256"] == run["report_sha256"]


@pytest.mark.parametrize("failure", [False, True])
def test_prior_migration_upgrade_is_atomic_and_repeatable(tmp_path, monkeypatch, failure):
    engine, _ = create_database(f"sqlite:///{(tmp_path / 'pilot-upgrade.db').as_posix()}")
    all_migrations = migrations.MIGRATIONS
    target_index = next(index for index, item in enumerate(all_migrations) if item.VERSION == migration.VERSION)
    target_migrations = all_migrations[:target_index + 1]
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:target_index])
    run_migrations(engine)
    monkeypatch.setattr(migrations, "MIGRATIONS", target_migrations)
    original = migration.verify
    if failure:
        monkeypatch.setattr(migration, "verify", lambda _: (_ for _ in ()).throw(RuntimeError("injected migration failure")))
        with pytest.raises(RuntimeError, match="injected"):
            run_migrations(engine)
        assert "shadow_pilot_runs" not in inspect(engine).get_table_names()
        monkeypatch.setattr(migration, "verify", original)
    assert run_migrations(engine) == (migration.VERSION,)
    assert run_migrations(engine) == ()
    engine.dispose()


@pytest.mark.skipif(not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"), reason="dedicated PostgreSQL migration database not configured")
@pytest.mark.parametrize("failure", [False, True])
def test_postgresql_prior_upgrade_failure_and_repeat(monkeypatch, failure):
    engine, _ = create_database(os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"])
    reset_test_database(engine)
    all_migrations = migrations.MIGRATIONS
    target_index = next(index for index, item in enumerate(all_migrations) if item.VERSION == migration.VERSION)
    target_migrations = all_migrations[:target_index + 1]
    monkeypatch.setattr(migrations, "MIGRATIONS", all_migrations[:target_index])
    run_migrations(engine)
    monkeypatch.setattr(migrations, "MIGRATIONS", target_migrations)
    original = migration.verify
    if failure:
        monkeypatch.setattr(migration, "verify", lambda _: (_ for _ in ()).throw(RuntimeError("injected migration failure")))
        with pytest.raises(RuntimeError, match="injected"):
            run_migrations(engine)
        assert "shadow_pilot_runs" not in inspect(engine).get_table_names()
        monkeypatch.setattr(migration, "verify", original)
    assert run_migrations(engine) == (migration.VERSION,)
    assert run_migrations(engine) == ()
    engine.dispose()


def test_budget_failure_is_explicit_not_readiness(monkeypatch):
    from backend import shadow_pilot
    from backend.legacy_observation_v12 import load_sources
    ticks = iter((100.0, 100.0, 100.6, 100.7))
    monkeypatch.setattr(shadow_pilot.time, "perf_counter", lambda: next(ticks))
    report = build_report(Plan(items=["TEMP"]), load_sources())
    assert report["equivalent"] and not report["budget_passed"]
