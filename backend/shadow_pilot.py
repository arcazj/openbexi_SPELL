"""Durable local engineering readiness; never grants execution authority."""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
import time
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StringConstraints, field_validator
from sqlalchemy import func, insert, select, text, update

from .database import Base, begin_mutation_write, utc_now
from .legacy_observation_v12 import load_sources
from .migrations.versions.v0010_shadow_pilot import events as frozen_events, runs as frozen_runs
from .telemetry_adapter import compare_tm

# Application metadata is derived from this immutable schema, never vice versa.
runs = frozen_runs.to_metadata(Base.metadata)
events = frozen_events.to_metadata(Base.metadata)
PROFILE = "LOCAL_SYNTHETIC_SHADOW_PILOT"
MAX_BACKUP_BYTES = 262144


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class PilotError(ValueError):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


def _require_backup(condition):
    if not condition:
        raise ValueError("invalid pilot backup")


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]] = Field(min_length=1, max_length=8)
    value_format: Literal["RAW", "ENG"] = "ENG"
    repetitions: StrictInt = Field(1, ge=1, le=4)

    @field_validator("items")
    @classmethod
    def unique(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("duplicate pilot item")
        return value


class RequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: UUID
    reason: str = Field(min_length=1, max_length=900)

    @field_validator("reason")
    @classmethod
    def reason_text(cls, value):
        if not value.strip() or any(not c.isprintable() for c in value):
            raise ValueError("printable reason required")
        return value


class CreateRequest(RequestBase):
    plan: Plan


class ActionRequest(RequestBase):
    action: Literal["REVIEW", "INCIDENT", "ROLLBACK"]
    expected_revision: StrictInt = Field(ge=1)


class RestoreRequest(RequestBase):
    backup: dict

    @field_validator("backup")
    @classmethod
    def bound(cls, value):
        try:
            if len(canonical(value)) > MAX_BACKUP_BYTES:
                raise ValueError("backup exceeds bound")
        except (RecursionError, OverflowError) as exc:
            raise ValueError("invalid backup") from exc
        return value


def profile():
    result = json.loads((Path(__file__).resolve().parents[1] / "contracts/v15/pilot_profile.json").read_bytes())
    if result["profile"] != PROFILE or result["operational_authorization"] is not False:
        raise RuntimeError("shadow-pilot profile differs")
    return result


def trace(plan: Plan, sources) -> list[dict]:
    known = {item["item_id"] for item in sources["reference"].catalog()["items"]}
    if not set(plan.items) <= known:
        raise PilotError("UNKNOWN_PILOT_ITEM", 422)
    return [{"repetition": repetition, "comparison": compare_tm(sources["reference"], sources["simulator"], item, plan.value_format)}
            for repetition in range(1, plan.repetitions + 1) for item in plan.items]


def build_report(plan: Plan, sources) -> dict:
    rows, durations = [], []
    started = time.perf_counter()
    # Validate before collecting any report.
    known = {item["item_id"] for item in sources["reference"].catalog()["items"]}
    if not set(plan.items) <= known:
        raise PilotError("UNKNOWN_PILOT_ITEM", 422)
    for repetition in range(1, plan.repetitions + 1):
        for item in plan.items:
            before = time.perf_counter()
            comparison = compare_tm(sources["reference"], sources["simulator"], item, plan.value_format)
            durations.append((time.perf_counter() - before) * 1000)
            rows.append({"repetition": repetition, "comparison": comparison})
    elapsed = time.perf_counter() - started
    return {"schema_version": "spell.shadow-pilot-report/1", "profile": PROFILE,
            "plan": plan.model_dump(), "rows": rows, "comparison_latency_ms": durations,
            "elapsed_seconds": elapsed, "budget_passed": elapsed <= 10 and max(durations) < 500,
            "equivalent": all(row["comparison"]["classification"] == "EQUIVALENT" for row in rows),
            "operational_authorization": False}


def summary(row):
    return {"id": row["id"], "creator": row["creator"], "state": row["state"], "revision": row["revision"],
            "report_sha256": row["report_sha256"], "read_only": True,
            "route": "SIMULATOR" if row["state"] in {"INCIDENT_READ_ONLY", "ROLLED_BACK_READ_ONLY", "RESTORED_READ_ONLY"} else "SHADOW_ONLY",
            "local_review_recorded": row["state"] == "REVIEWED_READ_ONLY", "operational_authorization": False}


class ShadowPilot:
    def __init__(self, session_factory, sources=None):
        self.factory = session_factory
        self.sources = load_sources() if sources is None else sources

    @staticmethod
    def _lock(session):
        begin_mutation_write(session)
        if session.bind.dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(731035015)"))

    @staticmethod
    def _allowed(actor, role):
        if role not in {"operator", "admin"} or not actor or len(actor) > 200:
            raise PilotError("PILOT_FORBIDDEN", 403)

    @staticmethod
    def _previous(session, operation_id, request_hash):
        previous = session.execute(select(events).where(events.c.operation_id == str(operation_id))).mappings().first()
        if previous is not None:
            if previous["request_hash"] != request_hash:
                raise PilotError("OPERATION_ID_CONFLICT")
            return previous["result"]
        return None

    @staticmethod
    def _event(session, request, actor, run_id, action, request_hash, result):
        if session.scalar(select(func.count()).select_from(events).where(events.c.run_id == run_id)) >= 128:
            raise PilotError("PILOT_AUDIT_CAPACITY", 429)
        session.execute(insert(events).values(operation_id=str(request.operation_id), run_id=run_id,
            action=action, actor=actor, reason=request.reason, request_hash=request_hash, revision=result["revision"], result=result, created_at=utc_now()))

    def create(self, request: CreateRequest, actor: str, role: str):
        self._allowed(actor, role)
        request_hash = digest({"action": "CREATE", "actor": actor, "request": request.model_dump(mode="json")})
        with self.factory.begin() as session:
            self._lock(session)
            previous = self._previous(session, request.operation_id, request_hash)
            if previous is not None:
                return previous
            if session.scalar(select(func.count()).select_from(runs)) >= 512:
                raise PilotError("PILOT_CAPACITY", 429)
            report = build_report(request.plan, self.sources)
            row = dict(id=str(request.operation_id), creator=actor, request_hash=request_hash, plan=request.plan.model_dump(),
                       report=report, report_sha256=digest(report), state="PENDING_REVIEW", revision=1, created_at=utc_now(), origin=None)
            session.execute(insert(runs).values(**row))
            result = summary(row)
            self._event(session, request, actor, row["id"], "CREATE", request_hash, result)
            return result

    def action(self, run_id: str, request: ActionRequest, actor: str, role: str):
        self._allowed(actor, role)
        request_hash = digest({"run_id": run_id, "actor": actor, "request": request.model_dump(mode="json")})
        with self.factory.begin() as session:
            self._lock(session)
            previous = self._previous(session, request.operation_id, request_hash)
            if previous is not None:
                return previous
            row = session.execute(select(runs).where(runs.c.id == run_id)).mappings().first()
            if row is None:
                raise PilotError("PILOT_NOT_FOUND", 404)
            if row["revision"] != request.expected_revision:
                raise PilotError("PILOT_REVISION_CONFLICT")
            if request.action == "REVIEW":
                if role != "admin" or actor == row["creator"]:
                    raise PilotError("INDEPENDENT_ADMIN_REQUIRED", 403)
                if row["state"] != "PENDING_REVIEW" or not row["report"]["equivalent"] or not row["report"]["budget_passed"]:
                    raise PilotError("PILOT_NOT_REVIEWABLE")
                if digest(row["report"]) != row["report_sha256"] or row["report"]["rows"] != trace(Plan.model_validate(row["plan"]), self.sources):
                    raise PilotError("PILOT_REPORT_INTEGRITY")
                state = "REVIEWED_READ_ONLY"
            else:
                if role != "admin" and actor != row["creator"]:
                    raise PilotError("PILOT_OWNER_REQUIRED", 403)
                state = "INCIDENT_READ_ONLY" if request.action == "INCIDENT" else "ROLLED_BACK_READ_ONLY"
            changed = {**row, "state": state, "revision": row["revision"] + 1}
            result = summary(changed)
            session.execute(update(runs).where(runs.c.id == run_id, runs.c.revision == request.expected_revision)
                            .values(state=state, revision=changed["revision"]))
            self._event(session, request, actor, run_id, request.action, request_hash, result)
            return result

    def get(self, run_id: str):
        with self.factory() as session:
            # Row and ledger must describe one committed revision, including
            # when another operator commits between the two SELECT statements.
            connection = session.connection()
            if connection.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN")
            elif connection.dialect.name == "postgresql":
                connection.exec_driver_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            else:
                raise PilotError("UNSUPPORTED_PILOT_DATABASE", 503)
            row = session.execute(select(runs).where(runs.c.id == run_id)).mappings().first()
            if row is None:
                raise PilotError("PILOT_NOT_FOUND", 404)
            history = session.execute(select(events).where(events.c.run_id == run_id).order_by(events.c.revision)).mappings().all()
            return {**summary(row), "plan": row["plan"], "report": row["report"], "origin": row["origin"],
                    "events": [{"operation_id": event["operation_id"], "action": event["action"], "actor": event["actor"],
                                "reason": event["reason"], "result": event["result"], "created_at": event["created_at"].isoformat()} for event in history]}

    def list(self):
        with self.factory() as session:
            return {"items": [summary(row) for row in session.execute(select(runs).order_by(runs.c.created_at.desc(), runs.c.id).limit(32)).mappings()]}

    def backup(self, run_id: str):
        payload = {"schema_version": "spell.shadow-pilot-backup/1", "profile": PROFILE, "run": self.get(run_id)}
        value = {"payload": payload, "sha256": digest(payload)}
        if len(canonical(value)) > MAX_BACKUP_BYTES:
            raise PilotError("BACKUP_CAPACITY", 413)
        return value

    def restore(self, request: RestoreRequest, actor: str, role: str):
        self._allowed(actor, role)
        if role != "admin":
            raise PilotError("RESTORE_ADMIN_REQUIRED", 403)
        backup = request.backup
        try:
            _require_backup(set(backup) == {"payload", "sha256"} and digest(backup["payload"]) == backup["sha256"])
            payload = backup["payload"]
            _require_backup(set(payload) == {"schema_version", "profile", "run"})
            _require_backup(payload["schema_version"] == "spell.shadow-pilot-backup/1" and payload["profile"] == PROFILE)
            original = payload["run"]
            _require_backup(set(original) == {"id", "creator", "state", "revision", "report_sha256", "read_only", "route", "local_review_recorded", "operational_authorization", "plan", "report", "origin", "events"})
            _require_backup(original["read_only"] is True and original["operational_authorization"] is False)
            _require_backup(str(UUID(original["id"])) == original["id"] and original["id"] != str(request.operation_id))
            _require_backup(type(original["revision"]) is int and 1 <= original["revision"] <= 128)
            _require_backup(isinstance(original["creator"], str) and 0 < len(original["creator"]) <= 200)
            _require_backup(original["state"] in {"PENDING_REVIEW", "REVIEWED_READ_ONLY", "INCIDENT_READ_ONLY", "ROLLED_BACK_READ_ONLY", "RESTORED_READ_ONLY"})
            _require_backup(original["local_review_recorded"] is (original["state"] == "REVIEWED_READ_ONLY"))
            _require_backup(original["route"] == summary(original)["route"])
            plan = Plan.model_validate(original["plan"])
            report = original["report"]
            _require_backup(set(report) == {"schema_version", "profile", "plan", "rows", "comparison_latency_ms", "elapsed_seconds", "budget_passed", "equivalent", "operational_authorization"})
            _require_backup(report["schema_version"] == "spell.shadow-pilot-report/1" and report["profile"] == PROFILE)
            _require_backup(type(report["equivalent"]) is bool and type(report["budget_passed"]) is bool)
            _require_backup(report["plan"] == plan.model_dump() and report["operational_authorization"] is False)
            _require_backup(digest(report) == original["report_sha256"] and report["rows"] == trace(plan, self.sources))
            durations = report["comparison_latency_ms"]
            _require_backup(len(durations) == len(report["rows"]) and all(type(v) in {int, float} and math.isfinite(v) and v >= 0 for v in durations))
            elapsed = report["elapsed_seconds"]
            _require_backup(type(elapsed) in {int, float} and math.isfinite(elapsed) and elapsed >= 0)
            _require_backup(report["budget_passed"] == (elapsed <= 10 and max(durations) < 500))
            _require_backup(report["equivalent"] == all(row["comparison"]["classification"] == "EQUIVALENT" for row in report["rows"]))
            history = original["events"]
            _require_backup(type(history) is list and len(history) == original["revision"] and len({str(UUID(e["operation_id"])) for e in history}) == len(history))
            _require_backup(history[0]["action"] in {"CREATE", "RESTORE"} and history[0]["operation_id"] == original["id"])
            _require_backup(history[0]["actor"] == original["creator"])
            for revision, event in enumerate(history, 1):
                _require_backup(set(event) == {"operation_id", "action", "actor", "reason", "result", "created_at"})
                _require_backup(event["action"] in {"CREATE", "REVIEW", "INCIDENT", "ROLLBACK", "RESTORE"})
                _require_backup(isinstance(event["actor"], str) and 0 < len(event["actor"]) <= 200)
                _require_backup(isinstance(event["reason"], str) and 0 < len(event["reason"]) <= 900)
                _require_backup(event["reason"].strip() and all(character.isprintable() for character in event["reason"]))
                _require_backup(str(UUID(event["operation_id"])) == event["operation_id"])
                _require_backup(isinstance(event["created_at"], str) and datetime.fromisoformat(event["created_at"]))
                receipt = event["result"]
                _require_backup(set(receipt) == set(summary(original)))
                _require_backup(type(receipt["revision"]) is int and receipt["revision"] == revision)
                _require_backup(receipt["id"] == original["id"] and receipt["creator"] == original["creator"])
                _require_backup(receipt["read_only"] is True and receipt["operational_authorization"] is False)
                _require_backup(receipt["report_sha256"] == original["report_sha256"])
                expected_state = {"CREATE": "PENDING_REVIEW", "REVIEW": "REVIEWED_READ_ONLY", "INCIDENT": "INCIDENT_READ_ONLY",
                                  "ROLLBACK": "ROLLED_BACK_READ_ONLY", "RESTORE": "RESTORED_READ_ONLY"}[event["action"]]
                _require_backup(receipt["state"] == expected_state and receipt["route"] == summary(receipt)["route"])
                _require_backup(receipt["local_review_recorded"] is (expected_state == "REVIEWED_READ_ONLY"))
            _require_backup(history[-1]["result"] == summary(original))
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise PilotError("INVALID_PILOT_BACKUP", 422) from exc
        request_hash = digest({"action": "RESTORE", "actor": actor, "request": request.model_dump(mode="json")})
        with self.factory.begin() as session:
            self._lock(session)
            previous = self._previous(session, request.operation_id, request_hash)
            if previous is not None:
                return previous
            if session.scalar(select(func.count()).select_from(runs)) >= 512:
                raise PilotError("PILOT_CAPACITY", 429)
            row = dict(id=str(request.operation_id), creator=actor, request_hash=request_hash, plan=plan.model_dump(), report=report,
                       report_sha256=digest(report), state="RESTORED_READ_ONLY", revision=1, created_at=utc_now(),
                       origin={"run_id": original["id"], "backup_sha256": backup["sha256"], "imported_events": history,
                               "audit_authority": "IMPORTED_UNTRUSTED_PROVENANCE"})
            session.execute(insert(runs).values(**row))
            result = summary(row)
            self._event(session, request, actor, row["id"], "RESTORE", request_hash, result)
            return result
