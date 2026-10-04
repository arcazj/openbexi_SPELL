from __future__ import annotations

from copy import deepcopy
import hashlib
import socket
import threading
import time

import pytest

from dss.catalog import SatelliteDatabase, validate_command
from dss.engine import DssConflict, DssEngine, TM_TOPIC
from dss.packets import PacketError, decode_packet, decode_tc, decode_tm, encode_packet, encode_tc, recv_packet


def request(engine, *, stage="TRANSPORT", command="CMD1", args=None, element="element-1", operation="op-1"):
    state=engine.state()
    return dict(schema_version="openbexi.dss.tc/1",satellite_id="GENERIC",database_revision=engine.catalog.revision,
        database_digest=engine.catalog.digest,satellite_epoch=state["epoch"],scenario_id=state["scenario_id"],
        operation_id=operation,procedure_id="engine-test",execution_id="execution-1",plan_id="plan-1",
        element_id=element,stage=stage,command_name=command,arguments=args or [],command_digest="a"*64)


def send(engine, **kwargs):
    body=request(engine,**kwargs)
    return engine.process_tc(body,encode_tc(body))


def test_independent_ccsds_binary_vector_and_primary_fields():
    # Independently specified: TC/APID100, unsegmented/seq0, data length22;
    # DSS1 + one canonical map key 'a' with UINT64(1), application CRC2fcb.
    vector=bytes.fromhex("1864c000001544535301080001050001610300000000000000012fcb")
    packet=decode_packet(vector)
    assert (packet.packet_type,packet.apid,packet.sequence,packet.body)==(1,100,0,{"a":1})
    assert encode_packet(1,100,0,{"a":1})==vector
    for index in (0,2,4,8,len(vector)-1):
        bad=bytearray(vector);bad[index]^=1
        with pytest.raises(PacketError): decode_packet(bytes(bad))


@pytest.mark.parametrize("mutation",["type","apid","version","segmentation","secondary","length","trailing"])
def test_wire_rejects_unsupported_or_corrupt_packets(mutation):
    import binascii,struct
    data=bytearray(bytes.fromhex("1864c000001544535301080001050001610300000000000000012fcb"))
    if mutation=="type": data[0]^=0x10
    elif mutation=="apid": data[1]=105
    elif mutation=="version": data[0]|=0x20
    elif mutation=="segmentation": data[2]&=0x3f
    elif mutation=="secondary": data[0]&=0xf7
    elif mutation=="length": data[5]+=1
    else: data.extend(b"\x00")
    if mutation!="trailing": data[-2:]=struct.pack(">H",binascii.crc_hqx(data[:-2],0xffff))
    with pytest.raises(PacketError): decode_tc(bytes(data))


def test_socket_framing_handles_fragmented_and_coalesced_packets():
    raw=encode_tc({"one":1});other=encode_tc({"two":2},sequence=1)
    left,right=socket.socketpair()
    left.settimeout(1);right.settimeout(1)
    def write():
        for piece in (raw[:2],raw[2:7],raw[7:]+other): left.sendall(piece)
        left.close()
    writer=threading.Thread(target=write);writer.start()
    try:
        assert recv_packet(right)==raw
        assert recv_packet(right)==other
        with pytest.raises(PacketError): recv_packet(right)
    finally: right.close();writer.join(timeout=1)
    assert not writer.is_alive()


def test_socket_dribble_cannot_extend_aggregate_packet_deadline():
    left,right=socket.socketpair();right.settimeout(0.1)
    def dribble():
        try:
            for value in encode_tc({"a":1}):
                left.sendall(bytes([value]));time.sleep(0.03)
        except OSError: pass
        finally: left.close()
    writer=threading.Thread(target=dribble);writer.start();started=time.monotonic()
    try:
        with pytest.raises(TimeoutError): recv_packet(right)
        assert time.monotonic()-started<0.5
        assert right.gettimeout()==0.1
    finally: right.close();writer.join(timeout=1)
    assert not writer.is_alive()


def test_load_has_no_effect_release_once_and_real_tm_sequences(tmp_path):
    engine=DssEngine(tmp_path/"dss.sqlite")
    transport=send(engine)
    assert engine.state()["core"]["commands_executed"]==0
    assert not engine.state()["payload"]["enabled"]
    assert send(engine,stage="LOADING")["outcome"]=="LOADED"
    release=send(engine,stage="RELEASE")
    assert release["outcome"]=="RELEASED"
    assert send(engine,stage="RELEASE")==release
    assert engine.state()["core"]["commands_executed"]==1
    assert engine.state()["payload"]["enabled"] is True
    assert send(engine,stage="ONBOARD_EXECUTION")["outcome"]=="SUCCEEDED"
    evidence=engine.evidence(engine.state()["scenario_id"])
    release_evidence=next(row for row in evidence["operations"] if decode_tc(bytes.fromhex(row["packet_hex"]))["stage"]=="RELEASE")
    assert release_evidence["ingress_delivery_count"]==2
    tm=[decode_tm(bytes.fromhex(p["packet_hex"])) for p in evidence["packets"] if p["topic"]==TM_TOPIC]
    assert [p["tm_sequence"] for p in tm]==list(range(1,len(tm)+1))
    caused=next(p for p in tm if p["tm_sequence"]==release["tm_sequence"])
    assert caused["operation_id"]=="op-1" and caused["cause_command"]=="CMD1"
    assert next(p for p in caused["items"] if p["item_id"]=="TM.PAYLOAD.ENABLED")["engineering"]["value"] is True
    assert transport["ack_sequence"]<release["ack_sequence"]
    engine.close()


def test_state_effect_and_unsent_outbox_survive_restart(tmp_path):
    path=tmp_path/"durable.sqlite";engine=DssEngine(path)
    send(engine);ack=send(engine,stage="RELEASE");state=engine.state();packets=engine.pending_packets()
    engine.close();engine=DssEngine(path)
    assert engine.state()==state and engine.pending_packets()==packets
    assert send(engine,stage="RELEASE")==ack
    assert engine.state()["core"]["commands_executed"]==1
    evidence=engine.evidence(state["scenario_id"])
    counts={decode_tc(bytes.fromhex(row["packet_hex"]))["stage"]:row["ingress_delivery_count"] for row in evidence["operations"]}
    assert counts=={"TRANSPORT":1,"RELEASE":2}
    engine.close()


def test_old_journal_cannot_invent_a_complete_ingress_count(tmp_path):
    path=tmp_path/"prior.sqlite"
    engine=DssEngine(path)
    body=request(engine)
    raw=encode_tc(body)
    acknowledgement=engine.process_tc(body,raw)
    scenario=engine.state()["scenario_id"]
    engine.db.execute("DROP TABLE ingress_deliveries")
    engine.close()
    engine=DssEngine(path)
    assert engine.evidence(scenario)["operations"][0]["ingress_delivery_count"]==0
    assert engine.process_tc(body,raw)==acknowledgement
    assert engine.evidence(scenario)["operations"][0]["ingress_delivery_count"]==0
    engine.close()


def test_loaded_command_reset_requires_explicit_state_bound_retirement():
    from dss.engine import scenario_retirement_token
    engine=DssEngine(":memory:")
    send(engine)
    old=engine.state()
    with pytest.raises(DssConflict,match="unreleased"):
        engine.reset("next-case",expected_epoch=old["epoch"])
    with pytest.raises(DssConflict,match="retirement"):
        engine.reset("next-case",expected_epoch=old["epoch"],retirement_token="0"*64)
    assert engine.state()==old
    fresh=engine.reset("next-case",expected_epoch=old["epoch"],retirement_token=scenario_retirement_token(old))
    assert fresh["epoch"]!=old["epoch"] and fresh["core"]["commands_executed"]==0
    prior=engine.evidence(old["scenario_id"])
    assert prior["commands"][0]["executed"]==0
    assert prior["retirement"]["unreleased_commands"]==[{"plan_id":"plan-1","element_id":"element-1"}]
    assert prior["retirement"]["next_scenario_id"]=="next-case"
    engine.close()


def test_evidence_fence_detects_deduplicated_replay_and_publication():
    engine=DssEngine(":memory:")
    send(engine)
    state=engine.state()
    scenario=state["scenario_id"]
    before=engine.evidence_page(scenario)["pagination"]["revision"]
    send(engine)
    assert engine.state()==state
    with pytest.raises(DssConflict):
        engine.evidence_page(scenario,expected_revision=before)
    page=engine.evidence_page(scenario)
    assert page["operations"][0]["ingress_delivery_count"]==2
    before=page["pagination"]["revision"]
    engine.mark_published(engine.pending_packets(limit=1)[0]["id"])
    with pytest.raises(DssConflict):
        engine.evidence_page(scenario,expected_revision=before)
    engine.close()


def test_evidence_fence_detects_ack_only_stage_without_a_physical_change():
    engine=DssEngine(":memory:")
    send(engine)
    before=engine.state()
    revision=engine.evidence_page(before["scenario_id"])["pagination"]["revision"]
    send(engine,stage="LOADING")
    assert engine.state()["revision"]==before["revision"]
    with pytest.raises(DssConflict):
        engine.evidence_page(before["scenario_id"],expected_revision=revision)
    engine.close()


def test_coupled_power_thermal_payload_dynamics_are_repeatable():
    outputs=[]
    for _ in range(2):
        engine=DssEngine(":memory:");send(engine);send(engine,stage="RELEASE")
        before=engine.state();engine.control("STEP",before["epoch"],before["revision"],ticks=100)
        after=engine.state()
        assert after["bus"]["battery_mwh"]<before["bus"]["battery_mwh"]
        assert after["payload"]["temperature_mc"]>before["payload"]["temperature_mc"]
        assert after["payload"]["generated_data_bytes"]==12800
        outputs.append([after[k] for k in ("bus","payload","core")]);engine.close()
    assert outputs[0]==outputs[1]


def test_epoch_revision_and_argument_failures_cannot_mutate_state():
    engine=DssEngine(":memory:");before=engine.state()
    body=request(engine);body["expected_revision"]=before["revision"]+1
    with pytest.raises(DssConflict): engine.process_tc(body,encode_tc(body))
    with pytest.raises(ValueError): validate_command("CMDNAME",[{"name":"ARG1","value_type":"FLOAT","value":True}])
    with pytest.raises(ValueError): validate_command("TC.SIMULATOR.SET_MODE",[])
    engine.reset("new-scenario",expected_epoch=before["epoch"])
    with pytest.raises(DssConflict): engine.process_tc(request_from_old_epoch:=dict(body,expected_revision=0),encode_tc(request_from_old_epoch))
    assert engine.state()["core"]["commands_executed"]==0
    assert len(engine.evidence(before["scenario_id"])["operations"])==0
    engine.close()


def test_group_transport_preserves_each_element_and_executes_each_once():
    engine=DssEngine(":memory:");body=request(engine,element="group")
    body["elements"]=[{"element_id":"one","command_name":"CMD1","arguments":[],"command_digest":"a"*64},
                      {"element_id":"two","command_name":"CMD2","arguments":[],"command_digest":"b"*64}]
    assert engine.process_tc(body,encode_tc(body))["outcome"]=="ACCEPTED"
    for element,name,digest in (("one","CMD1","a"),("two","CMD2","b")):
        child=request(engine,stage="RELEASE",command=name,element=element);child["command_digest"]=digest*64
        assert engine.process_tc(child,encode_tc(child))["outcome"]=="RELEASED"
        assert engine.process_tc(child,encode_tc(child))["outcome"]=="RELEASED"
    assert engine.state()["core"]["commands_executed"]==2
    assert engine.state()["payload"]["enabled"] is False
    engine.close()


def test_verification_reads_actual_state_and_quality_not_expected_outcome():
    engine=DssEngine(":memory:");send(engine);send(engine,stage="RELEASE")
    body=request(engine,stage="VERIFICATION")
    body["verification"]=[{"channel":"TM.PAYLOAD.ENABLED","operator":"eq","expected":True}]
    assert engine.process_tc(body,encode_tc(body))["outcome"]=="PASSED"
    body["operation_id"]="different-verification";body["verification"][0]["expected"]=False
    ack=engine.process_tc(body,encode_tc(body))
    assert ack["outcome"]=="FAILED" and ack["detail"]["conditions"][0]["actual"] is True
    engine.close()


def test_lost_ack_never_erases_effect_or_caused_telemetry():
    engine=DssEngine(":memory:");engine.reset("lost-ack",faults={"lost_ack":True})
    send(engine);body=request(engine,stage="RELEASE");ack=engine.process_tc(body,encode_tc(body))
    assert engine.consume_transport_fault(body,ack)["drop_ack"] is True
    assert engine.consume_transport_fault(body,ack)["drop_ack"] is False
    assert engine.state()["core"]["commands_executed"]==1
    assert engine.telemetry()["sequence"]==ack["tm_sequence"]
    assert engine.process_tc(body,encode_tc(body))==ack
    engine.close()


def test_scheduled_intent_advances_physics_only_under_explicit_scenario_policy():
    engine=DssEngine(":memory:");body=request(engine)
    body["scheduling"]={"target_sim_time_ns":1_800_000_000_000,"clock_epoch_unix_ns":engine.state()["clock_epoch_unix_ns"]}
    assert engine.process_tc(body,encode_tc(body))["outcome"]=="UNCERTAIN"
    assert engine.state()["core"]["tick"]==0 and engine.state()["core"]["loaded_commands_count"]==0
    engine.reset("accelerated",faults={"auto_advance_scheduled_time":True});body=request(engine)
    body["scheduling"]={"target_sim_time_ns":1_800_000_000_000,"clock_epoch_unix_ns":engine.state()["clock_epoch_unix_ns"]}
    ack=engine.process_tc(body,encode_tc(body))
    assert ack["outcome"]=="ACCEPTED" and ack["dynamics_tick"]==18000
    assert ack["simulation_time_ns"]==1_800_000_000_000
    assert engine.state()["bus"]["battery_mwh"]>80000
    packet=decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
    assert packet["simulation_time_ns"]==ack["simulation_time_ns"]
    engine.close()


@pytest.mark.parametrize("mutation", ["extra", "missing", "encoded", "radix", "type", "boolean", "format"])
def test_normalized_argument_wire_cannot_disagree_with_its_typed_value(mutation):
    item={"name":"ARG1", "value":1.0, "value_type":"FLOAT", "value_format":"ENG", "radix":"DEC", "encoded":"1"}
    validate_command("CMDNAME", [item])
    if mutation=="extra": item["ignored_authority"]=True
    elif mutation=="missing": item.pop("encoded")
    elif mutation=="encoded": item["encoded"]="2"
    elif mutation=="radix": item["radix"]="HEX"
    elif mutation=="type": item["value_type"]="LONG"
    elif mutation=="boolean": item["value"]=True
    else: item["value_format"]="RAW"
    with pytest.raises(ValueError): validate_command("CMDNAME", [item])


@pytest.mark.parametrize("patch", [{"core":{"tick":-1}}, {"payload":{"generated_data_bytes":-1}},
    {"payload":{"temperature_mc":-273151}}, {"bus":{"energy_remainder_mw_ticks":36000}}])
def test_invalid_physical_initial_state_is_rejected_atomically(patch):
    engine=DssEngine(":memory:"); before=engine.state()
    with pytest.raises(ValueError): engine.reset("invalid-physical-state", initial_state=patch)
    assert engine.state()==before
    engine.close()


def test_broker_backpressure_stops_automatic_physics_without_dropping_evidence():
    from dss.engine import MAX_PENDING_PACKETS
    engine=DssEngine(":memory:"); state=engine.state()
    engine.control("RESUME", state["epoch"], state["revision"])
    for _ in range(MAX_PENDING_PACKETS): engine.advance()
    blocked=engine.state(); status=engine.outbox_status()
    assert status=={"pending_packets":MAX_PENDING_PACKETS,"pending_limit":MAX_PENDING_PACKETS,"backpressure":True}
    assert blocked["running"] is True
    assert engine.advance()==blocked
    record=engine.pending_packets(limit=1)[0]; engine.mark_published(record["id"])
    resumed=engine.advance()
    assert resumed["core"]["tick"]==blocked["core"]["tick"]+1
    assert engine.outbox_status()["pending_packets"]==MAX_PENDING_PACKETS
    engine.close()


@pytest.mark.parametrize("faults,sample_uncertainty,driver_uncertainty", [
    ({},1000,1000),
    ({"clock_uncertainty_ns":2_000_000_000},2_000_000_000,2_000_000_000),
    ({"driver_time_uncertainty_ns":2_000_000_000},1000,2_000_000_000),
])
def test_sample_acquisition_and_driver_time_uncertainty_have_separate_declared_faults(
    faults,sample_uncertainty,driver_uncertainty
):
    engine=DssEngine(":memory:")
    try:
        state=engine.reset("separate-clocks",faults=faults)
        packet=engine.evidence(state["scenario_id"])["packets"][0]
        body=decode_tm(bytes.fromhex(packet["packet_hex"]))
        assert body["clock_uncertainty_ns"]==sample_uncertainty
        assert body["driver_time_uncertainty_ns"]==driver_uncertainty
    finally:
        engine.close()


@pytest.mark.parametrize("value", [True,1.0,-1,10_000_000_001])
def test_invalid_driver_time_uncertainty_does_not_replace_scenario(value):
    engine=DssEngine(":memory:")
    try:
        before=engine.state()
        with pytest.raises(ValueError):
            engine.reset("invalid-driver-clock",faults={"driver_time_uncertainty_ns":value})
        assert engine.state()==before
    finally:
        engine.close()


def test_binary_telemetry_records_actual_resume_running_ticks_and_pause():
    engine=DssEngine(":memory:")
    try:
        state=engine.state()
        state=engine.control("RESUME",state["epoch"],state["revision"])
        state=engine.advance(10)
        state=engine.control("PAUSE",state["epoch"],state["revision"])
        bodies=[decode_tm(bytes.fromhex(row["packet_hex"]))
                for row in engine.evidence(state["scenario_id"])["packets"] if row["topic"]==TM_TOPIC]
        assert [body["running"] for body in bodies]==[False,True,True,False]
        assert [body["dynamics_tick"] for body in bodies]==[0,0,10,10]
        assert state["running"] is False
    finally:
        engine.close()


@pytest.mark.parametrize("pending_count", [0, 5, 256])
def test_pending_outbox_queries_are_bounded_by_backlog_not_retained_history(tmp_path, pending_count):
    from dss.engine import MAX_PENDING_PACKETS

    engine = DssEngine(tmp_path / "retained-outbox.sqlite")
    try:
        for row in engine.pending_packets():
            engine.mark_published(row["id"])
        # Opaque storage fixtures exercise query work and byte retention; they
        # are not claimed as executed satellite or binary protocol evidence.
        records = []
        pending_positions = set(range(0, pending_count * 47, 47))
        for position in range(12_032):
            records.append(("retained-history", "retained-epoch", position, TM_TOPIC,
                            position.to_bytes(4, "big") + b"audit-history" * 16,
                            0 if position in pending_positions else 1))
        with engine._transaction():
            engine.db.executemany(
                "INSERT INTO packets(scenario_id,epoch,sequence,topic,packet,published) VALUES(?,?,?,?,?,?)",
                records,
            )
        expected = [dict(row) for row in engine.db.execute(
            "SELECT * FROM packets WHERE published=0 ORDER BY id"
        )]
        assert len(expected) == pending_count
        assert engine.outbox_status() == {
            "pending_packets": pending_count,
            "pending_limit": MAX_PENDING_PACKETS,
            "backpressure": pending_count >= MAX_PENDING_PACKETS,
        }
        for query, arguments in (
            ("SELECT count(*) FROM packets WHERE published=0", ()),
            ("SELECT * FROM packets WHERE published=0 ORDER BY id LIMIT ?", (128,)),
        ):
            details = [row[3] for row in engine.db.execute("EXPLAIN QUERY PLAN " + query, arguments)]
            assert any(
                "USING INDEX dss_packets_pending" in detail
                or "USING COVERING INDEX dss_packets_pending" in detail
                for detail in details
            )
            assert not any("TEMP B-TREE" in detail for detail in details)
            # Count actual SQLite VM work rather than asserting wall-clock
            # speed on a shared host. A full history scan exceeds this budget.
            steps = []
            engine.db.set_progress_handler(lambda: steps.append(100) or 0, 100)
            try:
                engine.db.execute(query, arguments).fetchall()
            finally:
                engine.db.set_progress_handler(None, 0)
            assert sum(steps) < 10_000
        assert engine.pending_packets() == expected[:128]
        if expected:
            engine.mark_published(expected[0]["id"])
            assert engine.pending_packets() == expected[1:129]
            assert bytes(engine.db.execute(
                "SELECT packet FROM packets WHERE id=?", (expected[0]["id"],)
            ).fetchone()[0]) == expected[0]["packet"]
        state = engine.state()
        engine.control("STEP", state["epoch"], state["revision"])
        assert engine.outbox_status()["pending_packets"] == pending_count + (0 if expected else 1)
        assert engine.pending_packets(limit=256)[-1]["scenario_id"] == state["scenario_id"]
        assert engine.db.execute("SELECT count(*) FROM packets").fetchone()[0] == 12_034
    finally:
        engine.close()


def test_existing_outbox_index_upgrade_preserves_state_packets_and_command_evidence(tmp_path):
    path = tmp_path / "existing-outbox.sqlite"
    engine = DssEngine(path)
    try:
        send(engine)
        send(engine, stage="RELEASE")
        state = engine.state()
        before = engine.evidence(state["scenario_id"])
        pending = engine.pending_packets()
        engine.db.execute("DROP INDEX dss_packets_pending")
    finally:
        engine.close()
    engine = DssEngine(path)
    try:
        assert engine.state() == state
        assert engine.pending_packets() == pending
        assert engine.evidence(state["scenario_id"]) == before
        assert "dss_packets_pending" in {row[1] for row in engine.db.execute("PRAGMA index_list(packets)")}
        details = [row[3] for row in engine.db.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM packets WHERE published=0 ORDER BY id LIMIT 128"
        )]
        assert any("USING INDEX dss_packets_pending" in detail for detail in details)
    finally:
        engine.close()
