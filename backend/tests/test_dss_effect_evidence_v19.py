"""Delivery evidence must prove received physical effects, including valid tampering."""
from copy import deepcopy
import hashlib

import pytest

from dss.catalog import SatelliteDatabase
from dss.engine import DssEngine
from dss.evidence_validation import validate_command_effects
from dss.packets import decode_tm, encode_tc, encode_tm


def argument(name, value, kind):
    encoded=format(value, ".17g") if kind=="FLOAT" else "true" if value is True else "false" if value is False else str(value)
    return {"name":name,"value":value,"value_type":kind,"value_format":"ENG","radix":"DEC","encoded":encoded}


ARGUMENTS = {"CMDNAME":[argument("ARG1",1.25,"FLOAT")],
    "TCNAME":[argument("ARG1",-2.5,"FLOAT"),argument("ARG2",8,"LONG")],
    "TC.SIMULATOR.RESET":[argument("FORCE",True,"BOOLEAN")],
    "TC.SIMULATOR.SET_MODE":[argument("MODE","SAFE","STRING")],
    "DSS.REFERENCE.SEND":[argument("ARG1",2.25,"FLOAT")],
    "DSS.REFERENCE.SET_GROUND":[argument("PARAMETER","TMparam","STRING"),argument("VALUE",23.0,"FLOAT")]}


def capture_for(command="CMD1",faults=None):
    engine=DssEngine(":memory:")
    state=engine.reset("effect-clock-case",faults=faults) if faults is not None else engine.state()
    base={"schema_version":"openbexi.dss.tc/1","satellite_id":"GENERIC","database_revision":engine.catalog.revision,
        "database_digest":engine.catalog.digest,"satellite_epoch":state["epoch"],"scenario_id":state["scenario_id"],
        "operation_id":"effect-op","procedure_id":"effect-source","execution_id":"effect-execution",
        "plan_id":"effect-plan","element_id":"effect-element","command_name":command,
        "arguments":ARGUMENTS.get(command,[]),"command_digest":"a"*64}
    for stage in ("TRANSPORT","RELEASE"):
        body={**base,"stage":stage}
        assert engine.process_tc(body,encode_tc(body))["outcome"] in {"ACCEPTED","RELEASED"}
    for record in engine.pending_packets(): engine.mark_published(record["id"])
    satellite=engine.evidence(state["scenario_id"])
    driver=[{"packet":row["packet_hex"],"packet_sha256":row["packet_sha256"],"topic":row["topic"],
             "partition":0,"offset":index,"body":decode_tm(bytes.fromhex(row["packet_hex"]))}
            for index,row in enumerate(satellite["packets"])]
    engine.close()
    return {"dss":satellite,"driver":driver}


@pytest.mark.parametrize("command", [row["name"] for row in SatelliteDatabase.load().commands])
def test_every_database_command_has_received_causal_effect_evidence(command):
    validate_command_effects(capture_for(command))


@pytest.mark.parametrize("mutation", ["first_running","last_running","invalid_type"])
def test_crc_valid_dynamics_control_forgery_is_rejected(mutation):
    capture=capture_for()
    def mutate(body):
        body["running"]=0 if mutation=="invalid_type" else True
    mutate_state_packet(capture,mutate,first=mutation=="first_running")
    with pytest.raises(ValueError,match="dynamics state"):
        validate_command_effects(capture)


@pytest.mark.parametrize("mutation", [None,"driver_uncertainty","sample_uncertainty_type"])
def test_received_driver_and_sample_clock_uncertainty_match_declared_scenario(mutation):
    capture=capture_for(faults={"driver_time_uncertainty_ns":2_000_000_000})
    validate_command_effects(capture)
    if mutation:
        def mutate(body):
            if mutation=="driver_uncertainty":
                body["driver_time_uncertainty_ns"]=1000
            else:
                body["clock_uncertainty_ns"]="1000"
        mutate_state_packet(capture,mutate)
        with pytest.raises(ValueError,match="clock, policy"):
            validate_command_effects(capture)


def mutate_state_packet(capture, mutate, *, first=False):
    record=[row for row in capture["dss"]["packets"] if row["topic"]=="openbexi.GENERIC.tm"][0 if first else -1]
    old_hash=record["packet_sha256"]
    body=decode_tm(bytes.fromhex(record["packet_hex"]))
    mutate(body)
    raw=encode_tm(body,sequence=body["tm_sequence"] & 0x3fff)
    record.update(packet_hex=raw.hex(),packet_sha256=hashlib.sha256(raw).hexdigest())
    for received in capture["driver"]:
        if received["packet_sha256"]==old_hash:
            received.update(packet=raw.hex(),packet_sha256=record["packet_sha256"],body=body)


@pytest.mark.parametrize("mutation", ["unreceived", "wrong_effect", "wrong_conversion", "wrong_unit", "wrong_code",
    "wrong_catalog", "duplicate_item", "missing_item", "wrong_quality", "wrong_cause", "wrong_operation",
    "wrong_revision", "missing_before", "wrong_count", "false_journal"])
def test_crc_correct_self_consistent_evidence_cannot_hide_missing_or_wrong_effect(mutation):
    capture=capture_for()
    validate_command_effects(capture)
    if mutation=="unreceived": capture["driver"]=[row for row in capture["driver"] if row["body"].get("tm_sequence")!=3]
    elif mutation=="missing_before": capture["dss"]["packets"]=[row for row in capture["dss"]["packets"] if row["topic"]!="openbexi.GENERIC.tm" or row["sequence"]==3]
    elif mutation=="wrong_count": capture["dss"]["final_state"]["core"]["commands_executed"]=0
    elif mutation=="false_journal": capture["dss"]["commands"][0]["definition"]["arguments"]=[argument("ARG1",8.0,"FLOAT")]
    else:
        def mutate(body):
            item=next(row for row in body["items"] if row["item_id"]=="TM.PAYLOAD.ENABLED")
            if mutation=="wrong_effect": item["raw"]["value"]=False;item["engineering"]["value"]=False
            elif mutation=="wrong_conversion": item["engineering"]["value"]=False
            elif mutation=="wrong_unit": item["unit"]="W"
            elif mutation=="wrong_code": item["item_code"]=99
            elif mutation=="wrong_catalog": item["catalog_digest"]="b"*64
            elif mutation=="duplicate_item": body["items"].append(deepcopy(item))
            elif mutation=="missing_item": body["items"].remove(item)
            elif mutation=="wrong_quality": item["quality"]="BAD"
            elif mutation=="wrong_cause": body["cause_command"]="CMD2"
            elif mutation=="wrong_operation": body["operation_id"]="unrelated-op"
            elif mutation=="wrong_revision": body["state_revision"]+=1
        mutate_state_packet(capture,mutate)
    with pytest.raises(ValueError): validate_command_effects(capture)
