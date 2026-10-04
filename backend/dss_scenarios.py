"""Closed qualification inputs and wall-clock bounds for every nested source case."""
from copy import deepcopy
from datetime import datetime, timezone
import json

STALE_ACQUISITION_NS = 10_000_000_000
STALE_CLOCK_EXPECTATION = "UNAVAILABLE_FOR_DECLARED_STALE_ACQUISITION"
FRESH_ACQUISITION_NS = 5_000_000_000
OBSERVATION_FAULTS = {
    "missing":{"missing_items":["TM.POWER.BUS_VOLTAGE"]},"stale":{"stale":True},
    "invalid":{"telemetry_validity":"INVALID"},"bad-quality":{"telemetry_quality":"BAD"},
    "gap":{"source_gap":True},"policy":{"policy_revision":"different-policy"},
    "clock":{"driver_time_uncertainty_ns":2_000_000_000},"nominal":{},"low":{},
}


def _timestamp(value):
    if type(value) is not str or not 1<=len(value)<=19 or not value.isascii() or not value.isdecimal():return None
    parsed=int(value)
    return parsed if str(parsed)==value and 0<parsed<2**63 else None


def _snapshot_time(snapshot):
    raw=snapshot.get("snapshot_at_database_time")
    if type(raw) is not str or len(raw)>40:return None
    try:
        value=datetime.fromisoformat(raw)
        if value.tzinfo is None:return None
        delta=value-datetime(1970,1,1,tzinfo=timezone.utc)
        return (delta.days*86400+delta.seconds)*1_000_000_000+delta.microseconds*1000
    except ValueError:return None


def _fresh_received_sample(row, kind, snapshot_time):
    quality,reason=("UNKNOWN","DSS_SOURCE_GAP") if kind=="gap" else (
        ("UNKNOWN","DSS_POLICY_REVISION_MISMATCH") if kind=="policy" else
        ("BAD" if kind=="bad-quality" else "GOOD","DSS_SCENARIO"))
    if any(row.get(key)!=value for key,value in {
        "freshness":"FRESH","quality":quality,"quality_reason":reason,
        "validity":"INVALID" if kind=="invalid" else "VALID","synchronization_state":"COMPLETE",
        "source_id":"dss-GENERIC","source":"SIMULATOR","clock_provenance":"dss-dynamics-clock",
        "clock_uncertainty_ns":"1000","freshness_policy_revision":"v07-r1"}.items()):return False
    return _fresh_acquisition(row,snapshot_time)


def _fresh_acquisition(row,snapshot_time):
    acquired,received=(_timestamp(row.get(key)) for key in ("acquired_at_unix_ns","received_at_unix_ns"))
    return (snapshot_time is not None and acquired is not None and received is not None
        and acquired<=received+1000 and received<=snapshot_time+1000
        and snapshot_time<=acquired+1000+FRESH_ACQUISITION_NS)


def _stale_received_sample(row):
    if any(row.get(key)!=value for key,value in {
        "freshness":"STALE","quality":"GOOD","validity":"VALID","synchronization_state":"COMPLETE",
        "source_id":"dss-GENERIC","source":"SIMULATOR","clock_provenance":"dss-dynamics-clock",
        "clock_uncertainty_ns":"1000","freshness_policy_revision":"v07-r1"}.items()):
        return False
    values=[]
    for key in ("acquired_at_unix_ns","received_at_unix_ns"):
        value=row.get(key)
        if type(value) is not str or not 1<=len(value)<=19 or not value.isascii() or not value.isdecimal():return False
        parsed=int(value)
        if str(parsed)!=value or not 0<parsed<2**63:return False
        values.append(parsed)
    return values[1]-values[0]>=STALE_ACQUISITION_NS


def snapshot_matches_scenario(snapshot, state, spec):
    """All declared inputs must have reached the new physical epoch before source execution."""
    from dss.catalog import TELEMETRY_ITEMS
    faults=spec.get("faults")
    kind=spec.get("observation_input")
    if type(faults) is not dict or type(kind) is not str or kind not in OBSERVATION_FAULTS:return False
    observation_keys={key for values in OBSERVATION_FAULTS.values() for key in values}|{"clock_uncertainty_ns"}
    declared={key:value for key,value in faults.items() if key in observation_keys}
    expected_faults=OBSERVATION_FAULTS[kind]
    if (declared.keys()!=expected_faults.keys() or any(type(declared[key]) is not type(value)
            or declared[key]!=value for key,value in expected_faults.items())):return False
    expected={row["item_id"] for row in TELEMETRY_ITEMS}-set(spec["faults"].get("missing_items",[]))
    items={row["item_id"]:row for row in snapshot.get("items",[])}
    if not expected or not all(name in items and items[name].get("source_epoch")==state["epoch"] for name in expected):
        return False
    if spec.get("clock_expectation")==STALE_CLOCK_EXPECTATION:
        faults=spec["faults"]
        return (spec.get("observation_input")=="stale" and type(faults) is dict and set(faults)=={"stale"}
            and faults["stale"] is True and "driver_time" in snapshot and snapshot["driver_time"] is None
            and all(_stale_received_sample(items[name]) for name in expected))
    if spec.get("clock_expectation")!="CURRENT_EPOCH" or spec.get("observation_input")=="stale":return False
    if any(name in items and items[name].get("source_epoch")==state["epoch"] for name in faults.get("missing_items",[])):return False
    now=_snapshot_time(snapshot)
    if not all(_fresh_received_sample(items[name],kind,now) for name in expected):return False
    clock=snapshot.get("driver_time") or {}
    uncertainty=spec["faults"].get("driver_time_uncertainty_ns",spec["faults"].get("clock_uncertainty_ns",1000))
    return (clock.get("provenance")=="dss-dynamics-clock" and clock.get("source_epoch")==state["epoch"]
        and clock.get("uncertainty_ns")==str(uncertainty) and clock.get("quality")=="GOOD"
        and clock.get("validity")=="VALID" and _fresh_acquisition(clock,now))


def readiness_diagnostic(snapshot, state, spec):
    """Bounded readiness metadata only; never include telemetry values or credentials."""
    from dss.catalog import TELEMETRY_ITEMS
    expected={row["item_id"] for row in TELEMETRY_ITEMS}-set(spec["faults"].get("missing_items",[]))
    items={row["item_id"]:row for row in snapshot.get("items",[])}
    missing=sorted(expected-items.keys())
    old=[items[name] for name in sorted(expected & items.keys()) if items[name].get("source_epoch")!=state["epoch"]]
    unacceptable=[items[name] for name in sorted(expected & items.keys())
        if not (_stale_received_sample(items[name]) if spec.get("clock_expectation")==STALE_CLOCK_EXPECTATION
            else _fresh_received_sample(items[name],spec.get("observation_input"),_snapshot_time(snapshot)))]
    def bounded(value):return None if value is None else str(value)[:76]
    clock=snapshot.get("driver_time") or {}
    details={"expected_epoch":state["epoch"],"missing_count":len(missing),"missing":missing[:2],
        "unacceptable_count":len(unacceptable),
        "old_epoch_count":len(old),"clock":{key:bounded(clock.get(key)) for key in ("source_epoch","source_sequence","uncertainty_ns")},
        "expected_uncertainty_ns":str(spec["faults"].get("driver_time_uncertainty_ns",spec["faults"].get("clock_uncertainty_ns",1000))),
        "items":[{key:bounded(row.get(key)) for key in ("item_id","source_epoch","source_sequence","freshness","quality","validity","synchronization_state")} for row in (old or unacceptable)[:2]]}
    return json.dumps(details,sort_keys=True,separators=(",",":"),ensure_ascii=True)[:800]


def subject_execution_spec(subject, case):
    kind=case.get("observation_input","nominal")
    faults=deepcopy(OBSERVATION_FAULTS.get(kind,{}))
    if case.get("provider")=="reject_transport":faults["transport_reject"]=True
    if case.get("provider")=="fail_verification":faults["verification_fail"]=True
    command_faults={"transport_rejection":{"transport_reject":True},
        "execution_failure":{"execution_fail":True},"lost_release_ack":{"lost_ack":True},
        "release_ack_timeout":{"command_delay_ms":5000}}
    if case.get("command_fault") is not None:
        if case["command_fault"] not in command_faults:
            raise ValueError("unknown declared DSS command fault")
        faults.update(command_faults[case["command_fault"]])
    advances={"case:v18-relative-release-intent":1800_000_000_000,
        "case:v18-bounded-delay-and-timeout":3_000_000_000,
        "adaptation:061":1800_000_000_000,"adaptation:062":1800_000_000_000,"adaptation:074":120_000_000_000}
    if subject in advances:
        faults["auto_advance_scheduled_time"]=True
    return {"wall_timeout_seconds":120,"worker_timeout_seconds":90,
        "execution_control":"SCENARIO_RUNNING_THEN_PAUSED",
        "minimum_simulation_advance_ns":advances.get(subject,0),
        "initial_state":{"bus":{"bus_voltage_mv":14000 if kind=="low" else 28000,"thermal_mode":"NOMINAL"}},
        "faults":faults,"observation_input":kind,
        "clock_expectation":STALE_CLOCK_EXPECTATION if kind=="stale" else "CURRENT_EPOCH",
        "prompt_settlements":[deepcopy(row["settlements"]) for row in case.get("prompts",[])],
        "confirmations":list(case.get("confirmations",[])),"failure_answers":list(case.get("failure_answers",[]))}


def procedure_execution_spec(actions, inputs, *, run_all=False, brokered=False):
    base=subject_execution_spec("procedure",inputs)
    return {"wall_timeout_seconds":1800 if run_all else 150,
        "execution_control":"BROKERED_SUBJECTS" if brokered else base["execution_control"],
        "initial_state":base["initial_state"],"faults":base["faults"],"operator_actions":deepcopy(actions),
        "observation_input":base["observation_input"],"clock_expectation":base["clock_expectation"]}
