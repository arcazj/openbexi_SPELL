"""Independent database and causal telemetry checks for DSS delivery evidence."""
from __future__ import annotations

import hashlib
import math

from .catalog import SatelliteDatabase, TELEMETRY_ITEMS, canonical, validate_command
from .packets import decode_packet, decode_tc, decode_tm


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _equal(actual, expected, message):
    _require(type(actual) is type(expected) and actual == expected, message)


def _scalar(kind, value):
    if kind == "UINT64": return type(value) is int and 0 <= value < (1 << 64)
    if kind == "INT64": return type(value) is int and -(1 << 63) <= value < (1 << 63)
    if kind == "FINITE_DOUBLE": return type(value) is float and math.isfinite(value)
    if kind == "BOOLEAN": return type(value) is bool
    if kind == "STRING": return type(value) is str and len(value) <= 256
    return False


def validate_command_effects(capture: dict) -> None:
    """A release passes only when every executed effect is in received TM bytes.

    Uses decoded before/after packets and database definitions, without calling
    the dynamics engine or trusting its reported command-success flags alone.
    """
    database = SatelliteDatabase.load()
    satellite = capture["dss"]
    definitions = {item["item_id"]: item for item in TELEMETRY_ITEMS}
    missing = set(satellite["faults"].get("missing_items", []))
    state_packets = {}
    for record in satellite["packets"]:
        raw = bytes.fromhex(record["packet_hex"])
        _require(hashlib.sha256(raw).hexdigest() == record["packet_sha256"], "DSS effect packet digest differs")
        body = decode_tm(raw)
        primary = decode_packet(raw)
        ack = record["topic"] == "openbexi.GENERIC.ack"
        sequence_field = "ack_sequence" if ack else "tm_sequence"
        _require(primary.packet_type == 0 and primary.apid == (102 if ack else 101)
                 and primary.sequence == body[sequence_field] & 0x3fff
                 and record["sequence"] == body[sequence_field], "DSS packet primary sequence/APID differs")
        if record["topic"] != "openbexi.GENERIC.tm": continue
        sequence = body["tm_sequence"]
        _require(type(sequence) is int and sequence > 0 and sequence not in state_packets, "DSS effect TM sequence is ambiguous")
        _require(body["satellite_epoch"] == satellite["epoch"] and body["scenario_id"] == satellite["scenario_id"]
                 and body["database_digest"] == database.digest and body["database_revision"] == database.revision,
                 "DSS effect TM source binding differs")
        if "running" in body:
            _require(type(body["running"]) is bool,"DSS telemetry dynamics state has invalid type")
            if body["tm_sequence"] == 1:
                _require(body["running"] == satellite["initial_state"]["running"],
                         "DSS initial dynamics state differs from binary telemetry")
        _require(body["source_id"] == "dss-GENERIC" and body["clock_provenance"] == "dss-dynamics-clock"
                 and type(body["acquired_at_unix_ns"]) is int and body["acquired_at_unix_ns"] > 0
                 and body["clock_epoch_unix_ns"] == satellite["initial_state"]["clock_epoch_unix_ns"]
                 and type(body["clock_uncertainty_ns"]) is int
                 and body["clock_uncertainty_ns"] == satellite["faults"].get("clock_uncertainty_ns",1000)
                 and type(body.get("driver_time_uncertainty_ns",body["clock_uncertainty_ns"])) is int
                 and body.get("driver_time_uncertainty_ns",body["clock_uncertainty_ns"]) == satellite["faults"].get(
                     "driver_time_uncertainty_ns",satellite["faults"].get("clock_uncertainty_ns",1000))
                 and body["freshness_policy_revision"] == satellite["faults"].get("policy_revision","v07-r1")
                 and body["synchronization_state"] == ("GAPPED" if satellite["faults"].get("source_gap") else "COMPLETE"),
                 "DSS telemetry clock, policy or synchronization provenance differs")
        items = body["items"]
        _require(type(items) is list and len({item["item_id"] for item in items}) == len(items)
                 and {item["item_id"] for item in items} == set(definitions) - missing, "DSS telemetry item inventory differs")
        values = {}
        for item in items:
            definition = definitions[item["item_id"]]
            for key in ("item_code", "qualified_name", "catalog_digest", "unit", "description"):
                _equal(item[key], definition[key], "DSS telemetry metadata differs: " + key)
            _require(set(item["raw"]) == {"type", "value"} and set(item["engineering"]) == {"type", "value"},
                     "DSS telemetry scalar fields differ")
            _equal(item["raw"]["type"], definition["raw_type"], "DSS raw scalar type differs")
            _equal(item["engineering"]["type"], definition["engineering_type"], "DSS engineering scalar type differs")
            value = item["raw"]["value"]
            _require(_scalar(definition["raw_type"], value), "DSS raw scalar value differs")
            engineering = float(value * definition["engineering_scale"]) if definition["engineering_type"] == "FINITE_DOUBLE" else value
            _require(_scalar(definition["engineering_type"], item["engineering"]["value"]), "DSS engineering value type differs")
            _equal(item["engineering"]["value"], engineering, "DSS raw/engineering conversion differs")
            _equal(item["quality"], satellite["faults"].get("telemetry_quality", "GOOD"), "DSS declared telemetry quality differs")
            _equal(item["validity"], satellite["faults"].get("telemetry_validity", "VALID"), "DSS declared telemetry validity differs")
            values[definition["state_path"]] = value
        _require(body["dynamics_tick"] == values["core.tick"]
                 and body["simulation_time_ns"] == satellite["initial_state"]["core"]["sim_time_ns"]
                     + (body["dynamics_tick"] - satellite["initial_state"]["core"]["tick"]) * database.material["dynamics"]["tick_ns"],
                 "DSS telemetry model time differs from actual tick count")
        state_packets[sequence] = (body, values, record["packet_sha256"])
    _require(bool(state_packets), "DSS effect evidence contains no state telemetry")
    sequences = sorted(state_packets)
    if sequences and "running" in state_packets[sequences[-1]][0]:
        _require(state_packets[sequences[-1]][0]["running"] == satellite["final_state"]["running"],
                 "DSS final dynamics state differs from binary telemetry")
    _require(sequences == list(range(1, sequences[-1] + 1)), "DSS telemetry source sequence has a missing packet")
    received = {row["packet_sha256"] for row in capture["driver"] if row["topic"] == "openbexi.GENERIC.tm"}
    releases = []
    for operation in satellite["operations"]:
        body = decode_tc(bytes.fromhex(operation["packet_hex"]))
        if body["stage"] == "RELEASE": releases.append((body, operation["acknowledgement"]))
    executed = [command for command in satellite["commands"] if command["executed"] == 1]
    _require(len({(row["plan_id"],row["element_id"]) for row in executed}) == len(executed), "DSS effect execution identity duplicated")
    for command in executed:
        definition = command["definition"]
        matches = [(tc, ack) for tc, ack in releases if tc["plan_id"] == command["plan_id"]
                   and tc["element_id"] == command["element_id"] and ack["outcome"] == "RELEASED"]
        # A later query can retrieve a receipt, but must not manufacture another effect.
        causal = [(tc, ack) for tc, ack in matches if ack["tm_sequence"] in state_packets
                  and state_packets[ack["tm_sequence"]][0]["operation_id"] == tc["operation_id"]]
        _require(len(causal) == 1, "Executed DSS command has no unique causal state packet")
        tc, ack = causal[0]
        body, after, packet_hash = state_packets[ack["tm_sequence"]]
        _require(packet_hash in received, "Executed DSS command effect was not received by actual TLM")
        _require(body["cause_command"] == definition["command_name"] == tc["command_name"]
                 and body["state_revision"] == ack["state_revision"]
                 and body["simulation_time_ns"] == ack["simulation_time_ns"], "DSS causal command/telemetry correlation differs")
        _require(all(tc[key] == definition[key] for key in ("procedure_id","execution_id","command_name","command_digest","arguments")),
                 "DSS executed effect differs from its command definition")
        validate_command(tc["command_name"], tc["arguments"])
        earlier = [sequence for sequence in sequences if sequence < ack["tm_sequence"]]
        _require(bool(earlier), "DSS command effect lacks its prior state packet")
        before = state_packets[earlier[-1]][1]
        expected = {"core.commands_executed":before["core.commands_executed"] + 1,
                    "core.last_command_name":tc["command_name"]}
        args = {arg["name"]:arg["value"] for arg in tc["arguments"]}
        effect = database.command(tc["command_name"])["effect"]
        if effect == "SETPOINT": expected["payload.setpoint_milli"] = round(args.get("ARG1",0.0) * 1000)
        elif effect == "PAYLOAD_ON": expected["payload.enabled"] = True
        elif effect == "PAYLOAD_OFF": expected["payload.enabled"] = False
        elif effect == "HEATER_TOGGLE":
            expected["bus.heater"] = not before["bus.heater"]
            expected["bus.thermal_mode"] = "ON" if expected["bus.heater"] else "OFF"
        elif effect == "SET_GROUND": expected["reference.ground_parameter_milli"] = round(args["VALUE"] * 1000)
        elif effect == "SET_MODE":
            expected.update({"core.mode":args["MODE"], "bus.safe_mode":args["MODE"] == "SAFE"})
            if args["MODE"] == "SAFE": expected["payload.enabled"] = False
        elif effect == "RESET_SUBSYSTEMS":
            for path in after:
                group, key = path.split(".")
                if group in {"bus","payload"}: expected[path] = database.material["initial_state"][group][key]
        else: raise ValueError("DSS effect oracle has no database command mapping")
        for path, expected_value in expected.items():
            _require(path in after, "Executed DSS command effect channel is missing: " + path)
            _equal(after[path], expected_value, "DSS received command effect differs: " + path)
    initial_count = satellite["initial_state"]["core"]["commands_executed"]
    _equal(satellite["final_state"]["core"]["commands_executed"], initial_count + len(executed),
           "DSS final state command count disagrees with executed effects")
