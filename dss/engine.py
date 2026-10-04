"""Transactional GENERIC bus/payload dynamics, command journal and packet outbox."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid

from . import SIMULATOR_VERSION, DYNAMICS_ENGINE_VERSION
from .catalog import SatelliteDatabase, TELEMETRY_ITEMS, canonical, validate_command
from .packets import decode_tc, encode_tm

TM_TOPIC, ACK_TOPIC = "openbexi.GENERIC.tm", "openbexi.GENERIC.ack"
MAX_PENDING_PACKETS = 256
STAGES = {"TRANSPORT", "LOADING", "RELEASE", "ACKNOWLEDGEMENT", "ONBOARD_EXECUTION", "VERIFICATION"}
OUTCOMES = {"TRANSPORT":"ACCEPTED", "LOADING":"LOADED", "RELEASE":"RELEASED",
            "ACKNOWLEDGEMENT":"ACKNOWLEDGED", "ONBOARD_EXECUTION":"SUCCEEDED", "VERIFICATION":"PASSED"}


def scenario_retirement_token(state: dict) -> str:
    """Explicit test-control acknowledgement bound to the displayed paused state."""
    return hashlib.sha256(canonical({key:state[key] for key in
        ("scenario_id","epoch","revision","database_digest")} |
        {"reason":"QUALIFICATION_CASE_TERMINATED"})).hexdigest()


class DssConflict(ValueError):
    code = "DSS_CONFLICT"


class DssEngine:
    def __init__(self, path: Path | str, catalog: SatelliteDatabase | None = None):
        self.catalog = catalog or SatelliteDatabase.load()
        self._lock = threading.RLock()
        target = Path(path)
        if str(path) != ":memory:": target.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scenarios (id TEXT PRIMARY KEY, epoch TEXT UNIQUE NOT NULL,
                initial_state TEXT NOT NULL, state TEXT NOT NULL, faults TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS commands (scenario_id TEXT NOT NULL, plan_id TEXT NOT NULL,
                element_id TEXT NOT NULL, definition TEXT NOT NULL, results TEXT NOT NULL,
                executed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(scenario_id,plan_id,element_id));
            CREATE TABLE IF NOT EXISTS operations (operation_id TEXT NOT NULL, scenario_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, element_id TEXT NOT NULL, stage TEXT NOT NULL,
                request_hash TEXT NOT NULL, raw_tc BLOB NOT NULL, acknowledgement TEXT NOT NULL,
                PRIMARY KEY(scenario_id,operation_id,plan_id,element_id,stage));
            CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY AUTOINCREMENT, scenario_id TEXT NOT NULL,
                epoch TEXT NOT NULL, sequence INTEGER NOT NULL, topic TEXT NOT NULL, packet BLOB NOT NULL,
                published INTEGER NOT NULL DEFAULT 0, UNIQUE(scenario_id,sequence,topic));
            -- Publication polls must touch pending packets, not retained BLOB history.
            CREATE INDEX IF NOT EXISTS dss_packets_pending ON packets(id) WHERE published=0;
            CREATE TABLE IF NOT EXISTS ingress_deliveries (scenario_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                plan_id TEXT NOT NULL, element_id TEXT NOT NULL, stage TEXT NOT NULL,
                request_hash TEXT NOT NULL, delivery_count INTEGER NOT NULL,
                PRIMARY KEY(scenario_id,operation_id,plan_id,element_id,stage));
        """)
        stored = self.db.execute("SELECT value FROM metadata WHERE name='database_digest'").fetchone()
        if stored and stored[0] != self.catalog.digest:
            raise DssConflict("persisted DSS database identity differs; explicit migration is required")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('database_digest',?)", (self.catalog.digest,))
        current = self.db.execute("SELECT value FROM metadata WHERE name='current_scenario'").fetchone()
        if current is None: self.reset("boot-" + uuid.uuid4().hex)

    @contextmanager
    def _transaction(self):
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _current(self):
        row = self.db.execute("SELECT value FROM metadata WHERE name='current_scenario'").fetchone()
        if row is None: return None
        return self.db.execute("SELECT * FROM scenarios WHERE id=?", (row[0],)).fetchone()

    def state(self) -> dict:
        with self._lock:
            return json.loads(self._current()["state"])

    def outbox_status(self) -> dict:
        with self._lock:
            pending = self.db.execute("SELECT count(*) FROM packets WHERE published=0").fetchone()[0]
            return {"pending_packets": pending, "pending_limit": MAX_PENDING_PACKETS,
                    "backpressure": pending >= MAX_PENDING_PACKETS}

    def _save(self, state):
        self.db.execute("UPDATE scenarios SET state=? WHERE id=?", (canonical(state).decode(), state["scenario_id"]))

    def _sequence(self, state, ack=False):
        key = "ack_sequence" if ack else "sequence"
        state[key] += 1
        return state[key]

    def _outbox(self, state, topic, body, ack=False):
        sequence = body["ack_sequence" if ack else "tm_sequence"]
        packet = encode_tm(body, sequence=sequence & 0x3fff, ack=ack)
        self.db.execute("INSERT INTO packets(scenario_id,epoch,sequence,topic,packet) VALUES (?,?,?,?,?)",
                        (state["scenario_id"], state["epoch"], sequence, topic, packet))
        return packet

    def _tm(self, state, faults, operation_id="", command=""):
        sequence = self._sequence(state)
        items = []
        for definition in TELEMETRY_ITEMS:
            if definition["item_id"] in faults.get("missing_items", []): continue
            group, key = definition["state_path"].split(".")
            raw = state[group][key]
            kind = definition["engineering_type"]
            engineering = float(raw * definition["engineering_scale"]) if kind == "FINITE_DOUBLE" else raw
            items.append({"item_id": definition["item_id"], "item_code": definition["item_code"],
                "qualified_name": definition["qualified_name"], "catalog_digest": definition["catalog_digest"],
                "raw": {"type": definition["raw_type"], "value": raw},
                "engineering": {"type": kind, "value": engineering}, "unit": definition["unit"],
                "description": definition["description"], "validity": faults.get("telemetry_validity", "VALID"),
                "quality": faults.get("telemetry_quality", "GOOD"), "quality_reason": "DSS_SCENARIO"})
        body = {"schema_version":"openbexi.dss.tm/1", "satellite_id":"GENERIC",
            "database_revision":self.catalog.revision, "database_digest":self.catalog.digest,
            "satellite_epoch":state["epoch"], "scenario_id":state["scenario_id"],
            "state_revision":state["revision"], "tm_sequence":sequence,
            "running":state["running"],
            "acquired_at_unix_ns":time.time_ns() - (10_000_000_000 if faults.get("stale") else 0),
            "simulation_time_ns":state["core"]["sim_time_ns"], "dynamics_tick":state["core"]["tick"],
            "clock_epoch_unix_ns":state["clock_epoch_unix_ns"],
            "clock_provenance":"dss-dynamics-clock", "clock_uncertainty_ns":faults.get("clock_uncertainty_ns", 1000),
            "driver_time_uncertainty_ns":faults.get("driver_time_uncertainty_ns", faults.get("clock_uncertainty_ns",1000)),
            "source_id":"dss-GENERIC", "freshness_policy_revision":faults.get("policy_revision", "v07-r1"),
            "synchronization_state":"GAPPED" if faults.get("source_gap") else "COMPLETE",
            "operation_id":operation_id, "cause_command":command, "items":items}
        self._outbox(state, TM_TOPIC, body)
        return body

    def reset(self, scenario_id: str, initial_state: dict | None = None, faults: dict | None = None,
              expected_epoch: str | None = None, retirement_token: str | None = None) -> dict:
        if type(scenario_id) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", scenario_id):
            raise ValueError("scenario identity is invalid")
        initial_state, faults = initial_state or {}, faults or {}
        if type(initial_state) is not dict or type(faults) is not dict: raise ValueError("scenario inputs must be objects")
        allowed_faults = {"transport_reject","execution_fail","verification_fail","lost_ack","telemetry_paused",
            "telemetry_quality","telemetry_validity","missing_items","source_gap","clock_uncertainty_ns","driver_time_uncertainty_ns",
            "policy_revision","stale","command_delay_ms","auto_advance_scheduled_time"}
        if set(faults) - allowed_faults: raise ValueError("unknown DSS scenario fault")
        for key in {"transport_reject","execution_fail","verification_fail","lost_ack","telemetry_paused","source_gap","stale","auto_advance_scheduled_time"}:
            if key in faults and type(faults[key]) is not bool: raise ValueError("scenario flag must be boolean")
        if faults.get("telemetry_quality","GOOD") not in {"GOOD","BAD","SUSPECT","UNKNOWN"}: raise ValueError("unknown quality")
        if faults.get("telemetry_validity","VALID") not in {"VALID","INVALID","UNKNOWN"}: raise ValueError("unknown validity")
        if type(faults.get("missing_items",[])) is not list or any(x not in {r["item_id"] for r in self.catalog.telemetry} for x in faults.get("missing_items",[])):
            raise ValueError("missing item set differs from database")
        for key, limit in (("command_delay_ms",5000),("clock_uncertainty_ns",10_000_000_000),
                           ("driver_time_uncertainty_ns",10_000_000_000)):
            value = faults.get(key,0)
            if type(value) is not int or not 0 <= value <= limit: raise ValueError("scenario duration/clock bound differs")
        if faults.get("policy_revision","v07-r1") not in {"v07-r1","different-policy"}: raise ValueError("unknown policy revision")
        with self._transaction():
            previous = self._current()
            if previous:
                old = json.loads(previous["state"])
                if expected_epoch is not None and old["epoch"] != expected_epoch: raise DssConflict("stale reset epoch")
                if old["running"]: raise DssConflict("pause the DSS before resetting a scenario")
                pending = [dict(plan_id=row["plan_id"],element_id=row["element_id"])
                    for row in self.db.execute("SELECT * FROM commands WHERE scenario_id=? AND executed=0 ORDER BY plan_id,element_id",(old["scenario_id"],))
                    if json.loads(row["results"]).get("TRANSPORT")=="ACCEPTED"
                    and not json.loads(row["results"]).get("RELEASE")]
                if retirement_token is not None and (type(retirement_token) is not str
                        or retirement_token != scenario_retirement_token(old)):
                    raise DssConflict("scenario retirement acknowledgement is stale or invalid")
                if pending and retirement_token is None:
                    raise DssConflict("unreleased commands require explicit test-case retirement")
                if retirement_token is not None:
                    retirement = {"reason":"QUALIFICATION_CASE_TERMINATED","state_revision":old["revision"],
                        "state_sha256":hashlib.sha256(canonical(old)).hexdigest(),
                        "acknowledgement_sha256":retirement_token,"unreleased_commands":pending,
                        "next_scenario_id":scenario_id}
                    self.db.execute("INSERT INTO metadata VALUES (?,?)",("retirement:"+old["epoch"],canonical(retirement).decode()))
            elif retirement_token is not None:
                raise DssConflict("no previous scenario can be retired")
            elif expected_epoch is not None: raise DssConflict("reset expected an unavailable epoch")
            if self.db.execute("SELECT 1 FROM scenarios WHERE id=?", (scenario_id,)).fetchone():
                raise DssConflict("scenario identity cannot be reused")
            values = deepcopy(self.catalog.material["initial_state"])
            for group, patch in initial_state.items():
                if group not in values or type(patch) is not dict:
                    raise ValueError("unknown initial satellite subsystem")
                for key, value in patch.items():
                    if key not in values[group] or type(value) is not type(values[group][key]):
                        raise ValueError("initial satellite value differs from database type")
                    if type(value) is int and not -(1<<40) <= value <= (1<<40): raise ValueError("initial value exceeds bounds")
                    values[group][key] = value
            if not 0 <= values["bus"]["battery_mwh"] <= self.catalog.material["dynamics"]["battery_capacity_mwh"]:
                raise ValueError("battery state exceeds physical capacity")
            if not 0 <= values["bus"]["bus_voltage_mv"] <= 100000: raise ValueError("bus voltage exceeds bounds")
            for definition in self.catalog.telemetry:
                group, key = definition["state_path"].split(".")
                value = values[group][key]
                if definition["raw_type"] == "UINT64" and not 0 <= value < (1 << 64):
                    raise ValueError("initial unsigned telemetry value exceeds bounds")
            if not -273150 <= values["payload"]["temperature_mc"] <= 1000000:
                raise ValueError("initial payload temperature exceeds physical bounds")
            if not 0 <= values["bus"]["energy_remainder_mw_ticks"] < 36000:
                raise ValueError("initial energy remainder exceeds dynamics bounds")
            if "bus_voltage_mv" in initial_state.get("bus",{}): values["bus"]["nominal_bus_voltage_mv"] = values["bus"]["bus_voltage_mv"]
            epoch = "epoch-" + hashlib.sha256((scenario_id+":"+uuid.uuid4().hex).encode()).hexdigest()
            state = dict(values, schema_version="openbexi.dss.state/1", satellite_id="GENERIC",
                database_revision=self.catalog.revision,database_digest=self.catalog.digest,
                simulator_version=SIMULATOR_VERSION,dynamics_engine_version=DYNAMICS_ENGINE_VERSION,
                scenario_id=scenario_id,epoch=epoch,revision=0,sequence=0,ack_sequence=0,
                clock_epoch_unix_ns=time.time_ns(),running=False)
            self.db.execute("INSERT INTO scenarios VALUES (?,?,?,?,?)", (scenario_id,epoch,canonical(state).decode(),canonical(state).decode(),canonical(faults).decode()))
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('current_scenario',?)", (scenario_id,))
            self._tm(state, faults)
            self._save(state)
            return deepcopy(state)

    def _ticks(self, state, count):
        model, bus, payload, core = self.catalog.material["dynamics"], state["bus"], state["payload"], state["core"]
        for _ in range(count):
            load = model["base_load_mw"] + (model["payload_load_mw"] if payload["enabled"] else 0) + (model["heater_load_mw"] if bus["heater"] else 0)
            bus["load_mw"], bus["generated_mw"] = load, model["solar_generation_mw"]
            energy = bus["energy_remainder_mw_ticks"] + bus["generated_mw"] - load
            increment, remainder = divmod(energy, 36000)
            bus["battery_mwh"] = min(model["battery_capacity_mwh"], max(0,bus["battery_mwh"]+increment))
            bus["energy_remainder_mw_ticks"] = remainder
            bus["bus_voltage_mv"] = bus["nominal_bus_voltage_mv"] if bus["battery_mwh"] else 0
            if not bus["battery_mwh"]: payload["enabled"], bus["safe_mode"] = False, True
            payload["temperature_mc"] += ((model["environment_temperature_mc"]-payload["temperature_mc"]) // model["thermal_relaxation_divisor"]
                + (model["powered_heating_mc_per_tick"] if payload["enabled"] else 0)
                + (model["heater_heating_mc_per_tick"] if bus["heater"] else 0))
            if payload["enabled"]: payload["generated_data_bytes"] += model["payload_bytes_per_tick"]
            core["tick"] += 1
            core["sim_time_ns"] += model["tick_ns"]
        state["revision"] += 1

    def advance(self, ticks: int = 1) -> dict:
        if type(ticks) is not int or not 1 <= ticks <= 1000: raise ValueError("tick count outside bounds")
        with self._transaction():
            row = self._current(); state, faults = json.loads(row["state"]), json.loads(row["faults"])
            if state["running"] and not self.outbox_status()["backpressure"]:
                self._ticks(state,ticks)
                if not faults.get("telemetry_paused"): self._tm(state,faults)
                self._save(state)
            return deepcopy(state)

    def control(self, action: str, expected_epoch: str, expected_revision: int, ticks: int = 1) -> dict:
        action = action.upper()
        if action not in {"PAUSE","RESUME","STEP"} or type(ticks) is not int or not 1 <= ticks <= 1000:
            raise ValueError("unsupported DSS control")
        with self._transaction():
            row = self._current(); state, faults = json.loads(row["state"]), json.loads(row["faults"])
            if (type(expected_revision) is not int or state["epoch"] != expected_epoch or state["revision"] != expected_revision):
                raise DssConflict("DSS control epoch/revision is stale")
            if action == "STEP":
                if state["running"]: raise DssConflict("pause before single stepping")
                self._ticks(state,ticks)
            else:
                state["running"] = action == "RESUME"
                state["revision"] += 1
            self._tm(state,faults)
            self._save(state)
            return deepcopy(state)

    def _effect(self, state, definition, arguments):
        bus, payload, core = state["bus"],state["payload"],state["core"]
        values = {arg["name"]:arg["value"] for arg in arguments}
        effect = definition["effect"]
        if effect == "PAYLOAD_ON":
            if bus["safe_mode"]: raise DssConflict("payload enable is rejected in safe mode")
            payload["enabled"] = True
        elif effect == "PAYLOAD_OFF": payload["enabled"] = False
        elif effect == "HEATER_TOGGLE":
            bus["heater"] = not bus["heater"]
            bus["thermal_mode"] = "ON" if bus["heater"] else "OFF"
        elif effect == "SETPOINT": payload["setpoint_milli"] = round(values.get("ARG1",0.0)*1000)
        elif effect == "SET_GROUND": state["reference"]["ground_parameter_milli"] = round(values["VALUE"]*1000)
        elif effect == "RESET_SUBSYSTEMS":
            if payload["enabled"] and not values.get("FORCE",False): raise DssConflict("active payload reset needs FORCE")
            original = self.catalog.material["initial_state"]
            state["bus"],state["payload"] = deepcopy(original["bus"]),deepcopy(original["payload"])
        elif effect == "SET_MODE":
            core["mode"] = values["MODE"]
            bus["safe_mode"] = values["MODE"] == "SAFE"
            if bus["safe_mode"]: payload["enabled"] = False
        else: raise ValueError("database command has an unsupported dynamics effect")
        core["commands_executed"] += 1
        core["last_command_name"] = definition["name"]
        core["last_command_arguments"] = deepcopy(arguments)
        state["revision"] += 1

    def process_tc(self, body: dict, raw: bytes) -> dict:
        if decode_tc(raw) != body: raise ValueError("TC bytes differ from supplied decoded command")
        required = {"database_revision","database_digest","satellite_id","scenario_id","satellite_epoch",
            "operation_id","procedure_id","execution_id","plan_id","element_id","stage","command_name","arguments","command_digest"}
        if not required <= set(body) or body.get("schema_version") != "openbexi.dss.tc/1":
            raise ValueError("TC schema or required correlation fields differ")
        for key in {"operation_id","procedure_id","execution_id","plan_id","element_id","command_name"}:
            if type(body[key]) is not str or not 1 <= len(body[key]) <= 256: raise ValueError("TC identity outside bounds")
        if body["stage"] not in STAGES: raise ValueError("unsupported command stage")
        if not re.fullmatch(r"[0-9a-f]{64}",body["command_digest"]): raise ValueError("command digest is invalid")
        request_hash = hashlib.sha256(canonical(body)).hexdigest()
        with self._transaction():
            row=self._current(); state,faults=json.loads(row["state"]),json.loads(row["faults"])
            if (body["satellite_id"] != "GENERIC" or body["database_revision"] != self.catalog.revision
                    or body["database_digest"] != self.catalog.digest or body["satellite_epoch"] != state["epoch"]
                    or body["scenario_id"] != state["scenario_id"]):
                raise DssConflict("TC satellite/database/scenario/epoch binding is stale")
            operation_key=tuple(body[k] for k in ("scenario_id","operation_id","plan_id","element_id","stage"))
            previous=self.db.execute("SELECT * FROM operations WHERE scenario_id=? AND operation_id=? AND plan_id=? AND element_id=? AND stage=?",operation_key).fetchone()
            self.db.execute("INSERT INTO ingress_deliveries VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(scenario_id,operation_id,plan_id,element_id,stage) "
                "DO UPDATE SET delivery_count=CASE WHEN delivery_count>0 THEN delivery_count+1 ELSE 0 END "
                "WHERE request_hash=excluded.request_hash", (*operation_key,request_hash,0 if previous else 1))
            if previous:
                if previous["request_hash"] != request_hash: raise DssConflict("operation identity has conflicting TC bytes")
                return json.loads(previous["acknowledgement"])
            if body["stage"] == "TRANSPORT" and "expected_revision" in body:
                if type(body["expected_revision"]) is not int or body["expected_revision"] != state["revision"]:
                    raise DssConflict("TC displayed state revision is stale")
            scheduling=body.get("scheduling")
            not_due=False
            if scheduling is not None:
                allowed={"target_sim_time_ns","anchor_sim_time_ns","clock_epoch_unix_ns","time","release_time","send_delay_ms","delay_ms"}
                if type(scheduling) is not dict or set(scheduling)-allowed or "target_sim_time_ns" not in scheduling:
                    raise ValueError("simulator scheduling schema differs")
                target=scheduling["target_sim_time_ns"]
                if type(target) is not int or not 0 <= target <= state["core"]["sim_time_ns"]+86_400_000_000_000:
                    raise ValueError("scheduled simulator time exceeds one-day bound")
                if scheduling.get("clock_epoch_unix_ns",state["clock_epoch_unix_ns"]) != state["clock_epoch_unix_ns"]:
                    raise DssConflict("scheduled simulation clock epoch differs")
                if target>state["core"]["sim_time_ns"]:
                    if faults.get("auto_advance_scheduled_time"):
                        step=self.catalog.material["dynamics"]["tick_ns"]
                        self._ticks(state,(target-state["core"]["sim_time_ns"]+step-1)//step)
                        self._tm(state,faults)
                    else: not_due=True
            definition=self.catalog.command(body["command_name"]); validate_command(body["command_name"],body["arguments"])
            identity=(state["scenario_id"],body["plan_id"],body["element_id"])
            command=self.db.execute("SELECT * FROM commands WHERE scenario_id=? AND plan_id=? AND element_id=?",identity).fetchone()
            command_definition={"command_name":body["command_name"],"arguments":body["arguments"],
                "command_digest":body["command_digest"],"procedure_id":body["procedure_id"],"execution_id":body["execution_id"]}
            if command and json.loads(command["definition"]) != command_definition: raise DssConflict("command element definition changed")
            results=json.loads(command["results"]) if command else {}
            stage=body["stage"]; outcome=OUTCOMES[stage]; detail={"provider":"generic-dss","database_digest":self.catalog.digest}
            if not_due:
                outcome="UNCERTAIN"
                detail.update(reason="SIMULATION_TIME_NOT_DUE",target_sim_time_ns=scheduling["target_sim_time_ns"])
            elif stage == "TRANSPORT":
                if faults.get("transport_reject"): outcome="REJECTED"
                elif body.get("elements") is not None:
                    elements=body["elements"]
                    if type(elements) is not list or not 1 <= len(elements) <= 64:
                        raise ValueError("shared transport elements exceed bounds")
                    if len({e.get("element_id") for e in elements if type(e) is dict}) != len(elements):
                        raise ValueError("shared transport element identities are ambiguous")
                    for element in elements:
                        if type(element) is not dict or set(element) != {"element_id","command_name","arguments","command_digest"}:
                            raise ValueError("shared transport element schema differs")
                        validate_command(element["command_name"],element["arguments"])
                        if type(element["element_id"]) is not str or not 1 <= len(element["element_id"]) <= 256:
                            raise ValueError("shared transport element identifier is invalid")
                        if type(element["command_digest"]) is not str or not re.fullmatch(r"[0-9a-f]{64}",element["command_digest"]):
                            raise ValueError("shared transport command digest is invalid")
                        child_identity=(state["scenario_id"],body["plan_id"],element["element_id"])
                        child_definition={**{k:element[k] for k in ("command_name","arguments","command_digest")},
                            "procedure_id":body["procedure_id"],"execution_id":body["execution_id"]}
                        existing=self.db.execute("SELECT definition FROM commands WHERE scenario_id=? AND plan_id=? AND element_id=?",child_identity).fetchone()
                        if existing:
                            if json.loads(existing["definition"]) != child_definition: raise DssConflict("group command definition changed")
                        else:
                            self.db.execute("INSERT INTO commands VALUES (?,?,?,?,?,0)",(*child_identity,canonical(child_definition).decode(),canonical({"TRANSPORT":"ACCEPTED","LOADING":"LOADED"}).decode()))
                            state["core"]["loaded_commands_count"]+=1
                            state["revision"]+=1
                elif command is None:
                    results.update(TRANSPORT="ACCEPTED",LOADING="LOADED")
                    self.db.execute("INSERT INTO commands VALUES (?,?,?,?,?,0)",(*identity,canonical(command_definition).decode(),canonical(results).decode()))
                    state["core"]["loaded_commands_count"]+=1
                    state["revision"]+=1
            elif command is None: outcome={"LOADING":"FAILED","RELEASE":"FAILED","ACKNOWLEDGEMENT":"NACKED","ONBOARD_EXECUTION":"UNCERTAIN","VERIFICATION":"INDETERMINATE"}[stage]
            elif stage == "RELEASE":
                if command["executed"]: outcome=results.get("RELEASE","RELEASED")
                elif results.get("RELEASE"): outcome=results["RELEASE"]
                else:
                    if faults.get("execution_fail"):
                        results.update(RELEASE="RELEASED",ACKNOWLEDGEMENT="ACKNOWLEDGED",ONBOARD_EXECUTION="FAILED",VERIFICATION="FAILED")
                    else:
                        try:
                            self._effect(state,definition,body["arguments"])
                            state["core"]["last_operation_id"]=body["operation_id"]
                            results.update(RELEASE="RELEASED",ACKNOWLEDGEMENT="ACKNOWLEDGED",ONBOARD_EXECUTION="SUCCEEDED",
                                           VERIFICATION="FAILED" if faults.get("verification_fail") else "PASSED")
                            self.db.execute("UPDATE commands SET executed=1 WHERE scenario_id=? AND plan_id=? AND element_id=?",identity)
                        except DssConflict as exc:
                            outcome="FAILED"; results.update(RELEASE="FAILED",ONBOARD_EXECUTION="FAILED")
                            detail["reason"]=str(exc)
                    self.db.execute("UPDATE commands SET results=? WHERE scenario_id=? AND plan_id=? AND element_id=?",(canonical(results).decode(),*identity))
                    self._tm(state,faults,body["operation_id"],body["command_name"])
            else: outcome=results.get(stage,{"ACKNOWLEDGEMENT":"UNCERTAIN","ONBOARD_EXECUTION":"UNCERTAIN","VERIFICATION":"INDETERMINATE"}.get(stage,"FAILED"))
            if not not_due and stage == "VERIFICATION" and command and command["executed"]:
                outcome, verification_detail=self._verify(state,faults,body.get("verification",[]),body.get("tolerance",0.0))
                detail.update(verification_detail)
            if stage == "TRANSPORT": self._tm(state,faults,body["operation_id"],body["command_name"])
            ack_sequence=self._sequence(state,ack=True)
            ack={"schema_version":"openbexi.dss.ack/1","satellite_id":"GENERIC","database_revision":self.catalog.revision,
                "database_digest":self.catalog.digest,"scenario_id":state["scenario_id"],"satellite_epoch":state["epoch"],
                "state_revision":state["revision"],"tm_sequence":state["sequence"],"ack_sequence":ack_sequence,
                "clock_epoch_unix_ns":state["clock_epoch_unix_ns"],"simulation_time_ns":state["core"]["sim_time_ns"],
                "dynamics_tick":state["core"]["tick"],
                **{k:body[k] for k in ("operation_id","procedure_id","execution_id","plan_id","element_id","command_name","command_digest","stage")},
                "outcome":outcome,"detail":detail}
            self.db.execute("INSERT INTO operations VALUES (?,?,?,?,?,?,?,?)",(body["operation_id"],state["scenario_id"],body["plan_id"],body["element_id"],stage,request_hash,raw,canonical(ack).decode()))
            self._outbox(state,ACK_TOPIC,ack,True); self._save(state)
            return ack

    def _verify(self, state, faults, intents, global_tolerance):
        if type(intents) is not list or not 1 <= len(intents) <= 8:
            raise ValueError("verification requires bounded actual telemetry predicates")
        if type(global_tolerance) not in {int,float} or not math.isfinite(global_tolerance) or not 0 <= global_tolerance <= 1_000_000:
            raise ValueError("verification tolerance is invalid")
        actuals={}
        for definition in TELEMETRY_ITEMS:
            group,key=definition["state_path"].split(".")
            value=state[group][key]
            if definition["engineering_type"] == "FINITE_DOUBLE": value=float(value*definition["engineering_scale"])
            actuals[definition["item_id"]]=value
        conditions=[]
        for intent in intents:
            if type(intent) is not dict or not {"channel","operator","expected"} <= set(intent) or set(intent)-{"channel","operator","expected","tolerance","timeout_ms"}:
                raise ValueError("verification predicate schema differs")
            channel,operator,expected=intent["channel"],intent["operator"],intent["expected"]
            if type(channel) is not str or operator not in {"eq","neq","gt","ge","lt","le"}:
                raise ValueError("verification channel/operator differs")
            tolerance=intent.get("tolerance")
            tolerance=global_tolerance if tolerance is None else tolerance
            if type(tolerance) not in {int,float} or not math.isfinite(tolerance) or not 0 <= tolerance <= 1_000_000:
                raise ValueError("verification predicate tolerance is invalid")
            actual=actuals.get(channel)
            unavailable=(channel not in actuals or channel in faults.get("missing_items",[]) or faults.get("stale")
                or faults.get("telemetry_quality","GOOD") != "GOOD" or faults.get("telemetry_validity","VALID") != "VALID"
                or faults.get("source_gap") or faults.get("policy_revision","v07-r1") != "v07-r1")
            if unavailable: status="INDETERMINATE"
            else:
                numeric=type(actual) in {int,float} and type(expected) in {int,float}
                if type(expected) is float and not math.isfinite(expected): raise ValueError("nonfinite verification expected value")
                if tolerance and not numeric: passed=False
                elif operator == "eq": passed=abs(actual-expected)<=tolerance if numeric else type(actual) is type(expected) and actual==expected
                elif operator == "neq": passed=abs(actual-expected)>tolerance if numeric else type(actual) is not type(expected) or actual!=expected
                elif not numeric: passed=False
                else: passed={"gt":actual>expected-tolerance,"ge":actual>=expected-tolerance,"lt":actual<expected+tolerance,"le":actual<=expected+tolerance}[operator]
                status="PASSED" if passed else "FAILED"
            conditions.append({"channel":channel,"operator":operator,"expected":expected,"actual":actual,
                               "tolerance":tolerance,"state":status})
        statuses={r["state"] for r in conditions}
        outcome="INDETERMINATE" if "INDETERMINATE" in statuses else "FAILED" if "FAILED" in statuses else "PASSED"
        return outcome,{"evaluator":"generic-dss-current-telemetry","conditions":conditions}

    def consume_transport_fault(self, body: dict, ack: dict) -> dict:
        """Test-declared one-shot ACK loss; committed command/TM remain truthful."""
        with self._transaction():
            row=self.db.execute("SELECT faults FROM scenarios WHERE id=?",(ack["scenario_id"],)).fetchone()
            if not row: raise DssConflict("transport fault scenario is unavailable")
            faults=json.loads(row[0]);drop=False
            if faults.get("lost_ack") and body["stage"] == "RELEASE":
                key="lost_ack:"+hashlib.sha256(canonical([body[k] for k in ("satellite_epoch","operation_id","plan_id","element_id","stage")])).hexdigest()
                if not self.db.execute("SELECT 1 FROM metadata WHERE name=?",(key,)).fetchone():
                    self.db.execute("INSERT INTO metadata VALUES (?,?)",(key,"CONSUMED"));drop=True
            return {"drop_ack":drop,"delay_ms":faults.get("command_delay_ms",0) if body["stage"] == "RELEASE" else 0}

    def pending_packets(self, limit: int = 128) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 256: raise ValueError("outbox batch outside bounds")
        with self._lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM packets WHERE published=0 ORDER BY id LIMIT ?",(limit,))]

    def mark_published(self, identity: int) -> None:
        if type(identity) is not int: raise ValueError("packet identity must be an integer")
        with self._transaction():
            if self.db.execute("UPDATE packets SET published=1 WHERE id=?",(identity,)).rowcount != 1:
                raise DssConflict("published packet was not in the transactional outbox")

    def telemetry(self) -> dict:
        from .packets import decode_tm
        with self._lock:
            state=self.state()
            row=self.db.execute("SELECT * FROM packets WHERE scenario_id=? AND topic=? ORDER BY id DESC LIMIT 1",(state["scenario_id"],TM_TOPIC)).fetchone()
            body=decode_tm(bytes(row["packet"]))
            samples=[dict(item,raw_value=item["raw"],engineering_value=item["engineering"],acquired_at_unix_ns=body["acquired_at_unix_ns"]) for item in body["items"]]
            return {"epoch":state["epoch"],"revision":body["state_revision"],"sequence":body["tm_sequence"],
                    "database_revision":self.catalog.revision,"database_digest":self.catalog.digest,
                    "samples":samples,"packet_hex":bytes(row["packet"]).hex(),"packet_sha256":hashlib.sha256(row["packet"]).hexdigest(),"published":bool(row["published"])}

    def _ingress_delivery_count(self, operation) -> int:
        identity=tuple(operation[key] for key in ("scenario_id","operation_id","plan_id","element_id","stage"))
        row=self.db.execute("SELECT delivery_count FROM ingress_deliveries WHERE scenario_id=? AND "
            "operation_id=? AND plan_id=? AND element_id=? AND stage=?",identity).fetchone()
        return row[0] if row else 0  # Older history has no instrumented receipt count.

    def _retirement(self, epoch):
        row=self.db.execute("SELECT value FROM metadata WHERE name=?",("retirement:"+epoch,)).fetchone()
        return json.loads(row[0]) if row else None

    def evidence(self, scenario_id: str) -> dict:
        with self._lock:
            row=self.db.execute("SELECT * FROM scenarios WHERE id=?",(scenario_id,)).fetchone()
            if not row: raise ValueError("scenario evidence is unavailable")
            commands=[dict(r,definition=json.loads(r["definition"]),results=json.loads(r["results"])) for r in self.db.execute("SELECT * FROM commands WHERE scenario_id=? ORDER BY plan_id,element_id",(scenario_id,))]
            operations=[{"operation_id":r["operation_id"],"request_hash":r["request_hash"],"packet_hex":bytes(r["raw_tc"]).hex(),"packet_sha256":hashlib.sha256(r["raw_tc"]).hexdigest(),"acknowledgement":json.loads(r["acknowledgement"]),"ingress_delivery_count":self._ingress_delivery_count(r)} for r in self.db.execute("SELECT * FROM operations WHERE scenario_id=? ORDER BY rowid",(scenario_id,))]
            packets=[dict(id=r["id"],topic=r["topic"],epoch=r["epoch"],sequence=r["sequence"],published=bool(r["published"]),packet_hex=bytes(r["packet"]).hex(),packet_sha256=hashlib.sha256(r["packet"]).hexdigest()) for r in self.db.execute("SELECT * FROM packets WHERE scenario_id=? ORDER BY id",(scenario_id,))]
            return {"schema_version":"openbexi.dss.evidence/1","scenario_id":scenario_id,"epoch":row["epoch"],
                "retirement":self._retirement(row["epoch"]),
                "database_revision":self.catalog.revision,"database_digest":self.catalog.digest,
                "simulator_version":SIMULATOR_VERSION,"dynamics_engine_version":DYNAMICS_ENGINE_VERSION,
                "initial_state":json.loads(row["initial_state"]),"final_state":json.loads(row["state"]),
                "faults":json.loads(row["faults"]),"commands":commands,"operations":operations,"packets":packets}

    def close(self):
        with self._lock: self.db.close()

    def evidence_page(self, scenario_id: str, *, offset: int = 0, limit: int = 32,
                      expected_revision: int | None = None) -> dict:
        """Bounded SQL page, read atomically with an evidence revision fence.

        Exporters freeze/retire a case first and require unchanged metadata,
        counts and revision across all pages. One offset applies independently
        to each ordered collection; exhausted collections return empty arrays.
        """
        if (type(offset) is not int or not 0 <= offset <= 10_000_000
                or type(limit) is not int or not 1 <= limit <= 32
                or (expected_revision is not None and type(expected_revision) is not int)):
            raise ValueError("evidence page is outside bounds")
        with self._lock:
            row = self.db.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
            if row is None:
                raise ValueError("scenario evidence is unavailable")
            final = json.loads(row["state"])
            counts = {name: self.db.execute(f"SELECT COUNT(*) FROM {name} WHERE scenario_id=?", (scenario_id,)).fetchone()[0]
                      for name in ("commands", "operations", "packets")}
            repeats = self.db.execute("SELECT COALESCE(SUM(MAX(delivery_count-1,0)),0) "
                "FROM ingress_deliveries WHERE scenario_id=?",(scenario_id,)).fetchone()[0]
            published = self.db.execute("SELECT COUNT(*) FROM packets WHERE scenario_id=? AND published=1",(scenario_id,)).fetchone()[0]
            revision = final["revision"] + sum(counts.values()) + repeats + published + int(self._retirement(row["epoch"]) is not None)
            if expected_revision is not None and revision != expected_revision:
                raise DssConflict("scenario changed during evidence export")
            commands = [dict(record, definition=json.loads(record["definition"]), results=json.loads(record["results"]))
                        for record in self.db.execute("SELECT * FROM commands WHERE scenario_id=? ORDER BY plan_id,element_id LIMIT ? OFFSET ?", (scenario_id, limit, offset))]
            operations = [{"operation_id": record["operation_id"], "request_hash": record["request_hash"],
                           "ingress_delivery_count": self._ingress_delivery_count(record),
                           "packet_hex": bytes(record["raw_tc"]).hex(), "packet_sha256": hashlib.sha256(record["raw_tc"]).hexdigest(),
                           "acknowledgement": json.loads(record["acknowledgement"])}
                          for record in self.db.execute("SELECT * FROM operations WHERE scenario_id=? ORDER BY rowid LIMIT ? OFFSET ?", (scenario_id, limit, offset))]
            packets = [dict(id=record["id"], topic=record["topic"], epoch=record["epoch"], sequence=record["sequence"],
                            published=bool(record["published"]), packet_hex=bytes(record["packet"]).hex(),
                            packet_sha256=hashlib.sha256(record["packet"]).hexdigest())
                       for record in self.db.execute("SELECT * FROM packets WHERE scenario_id=? ORDER BY id LIMIT ? OFFSET ?", (scenario_id, limit, offset))]
            return {"schema_version": "openbexi.dss.evidence/1", "scenario_id": scenario_id, "epoch": row["epoch"],
                    "retirement": self._retirement(row["epoch"]),
                    "database_revision": self.catalog.revision, "database_digest": self.catalog.digest,
                    "simulator_version": SIMULATOR_VERSION, "dynamics_engine_version": DYNAMICS_ENGINE_VERSION,
                    "initial_state": json.loads(row["initial_state"]), "final_state": final, "faults": json.loads(row["faults"]),
                    "commands": commands, "operations": operations, "packets": packets,
                    "pagination": {"offset": offset, "limit": limit, "next_offset": offset + limit if any(offset + limit < count for count in counts.values()) else None,
                                   "counts": counts, "revision": revision}}
