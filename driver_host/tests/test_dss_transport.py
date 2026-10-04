"""Real binary socket exchange and durable decoded telemetry boundary proofs."""
from __future__ import annotations

import hashlib
import asyncio
import json
import socket
import socketserver
import threading
import time
from dataclasses import replace

import pytest

from dss.catalog import DATABASE_DIGEST, DATABASE_REVISION
from dss.engine import DssEngine
from dss.packets import decode_tc, encode_tm, recv_packet
from driver_host.dss_command import DssCommandDriver, DssUnavailable
from driver_host.dss_config import DssConfig
from driver_host.dss_telemetry import DssTelemetryDriver, TM_TOPIC
from driver_host.observation import ObservationCode, ObservationFailure


@pytest.fixture
def engine(tmp_path):
    value = DssEngine(tmp_path / "satellite.sqlite")
    yield value
    value.close()


def command(engine, stage="TRANSPORT", **changes):
    state = engine.state()
    return dict(schema_version="openbexi.dss.tc/1", database_digest=DATABASE_DIGEST,
        database_revision=DATABASE_REVISION, satellite_id="GENERIC", satellite_epoch=state["epoch"],
        scenario_id=state["scenario_id"], operation_id="operation-test", procedure_id="procedure-test",
        execution_id="execution-test", plan_id="plan-test", element_id="element-test", stage=stage,
        command_name="CMD1", arguments=[], command_digest="a" * 64, **changes)


@pytest.fixture
def cortex(engine):
    counts = []
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            raw = recv_packet(self.request)
            body = decode_tc(raw)
            counts.append(body["stage"])
            ack = engine.process_tc(body, raw)
            self.request.sendall(encode_tm(ack, sequence=ack["ack_sequence"] & 0x3fff, ack=True))
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def connect(_endpoint, *, timeout):
        return socket.create_connection(server.server_address, timeout=timeout)
    yield connect, counts
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_actual_ccsds_transport_load_release_and_restart_replay(tmp_path, engine, cortex):
    connect, calls = cortex
    config = DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite")
    driver = DssCommandDriver(config, connect=connect)
    driver.perform(command(engine))
    assert engine.state()["core"]["commands_executed"] == 0
    driver.perform(command(engine, "LOADING"))
    assert engine.state()["core"]["commands_executed"] == 0
    driver.perform(command(engine, "RELEASE"))
    assert engine.state()["core"]["commands_executed"] == 1
    assert engine.state()["payload"]["enabled"] is True
    first = driver.perform(command(engine, "ONBOARD_EXECUTION"))
    driver.close()
    reopened = DssCommandDriver(config, connect=connect)
    assert reopened.perform(command(engine, "ONBOARD_EXECUTION")) == first
    assert calls == ["TRANSPORT", "LOADING", "RELEASE", "ONBOARD_EXECUTION"]
    assert engine.state()["core"]["commands_executed"] == 1
    reopened.close()


def test_unknown_dispatch_is_never_repeated_after_restart(tmp_path, engine):
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(True)
        raise TimeoutError()
    config = DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite")
    first = DssCommandDriver(config, connect=unavailable)
    with pytest.raises(DssUnavailable):
        first.perform(command(engine))
    first.close()
    reopened = DssCommandDriver(config, connect=unavailable)
    with pytest.raises(DssUnavailable, match="resend"):
        reopened.perform(command(engine))
    assert len(calls) == 1
    reopened.close()


@pytest.mark.parametrize("mutation", ["apid", "sequence"])
def test_crc_valid_wrong_ack_header_cannot_settle_or_allow_resend(tmp_path, engine, mutation):
    import io
    calls = []
    class Peer:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): self.timeout = value
        def gettimeout(self): return self.timeout
        def sendall(self, raw):
            calls.append(raw)
            ack = engine.process_tc(decode_tc(raw), raw)
            self.buffer = io.BytesIO(encode_tm(ack,
                sequence=(ack["ack_sequence"] + (1 if mutation == "sequence" else 0)) & 0x3fff,
                ack=mutation != "apid"))
        def recv(self, length): return self.buffer.read(length)
    driver = DssCommandDriver(DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite"),
        connect=lambda *args, **kwargs: Peer())
    with pytest.raises(DssUnavailable, match="invalid"):
        driver.perform(command(engine))
    with pytest.raises(DssUnavailable, match="resend"):
        driver.perform(command(engine))
    assert len(calls) == 1
    driver.close()


def ingest_pending(telemetry, engine):
    for item in engine.pending_packets():
        telemetry.ingest(item["topic"], 0, item["id"], bytes(item["packet"]))


def test_actual_packet_to_typed_sample_and_durable_provenance(tmp_path, engine):
    config = DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite")
    telemetry = DssTelemetryDriver(config)
    ingest_pending(telemetry, engine)
    sample = asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE"))
    assert sample.raw_value.value == 28000
    assert sample.engineering_value.value == 28.0
    body = telemetry.health()
    evidence = telemetry.evidence(body["satellite_epoch"], body["tm_sequence"])
    assert len(evidence) == 1
    assert hashlib.sha256(evidence[0]["packet"]).hexdigest() == evidence[0]["packet_sha256"]
    telemetry.close()
    reopened = DssTelemetryDriver(config)
    assert reopened.evidence(body["satellite_epoch"], body["tm_sequence"]) == evidence
    assert (asyncio.run(reopened.current("TM.POWER.BUS_VOLTAGE"))).sample_id == sample.sample_id
    reopened.close()


@pytest.mark.parametrize("historical_packet", [False, True])
def test_driver_time_uncertainty_is_separate_from_acquisition_and_survives_reopen(tmp_path, engine, historical_packet):
    from dss.packets import decode_tm
    faults = {"clock_uncertainty_ns": 2_000_000_000} if historical_packet else {
        "clock_uncertainty_ns": 1000, "driver_time_uncertainty_ns": 2_000_000_000}
    engine.reset("independent-clock-provenance", faults=faults)
    body = decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
    if historical_packet:
        # Retained pre-extension packets have only the original combined field.
        body.pop("driver_time_uncertainty_ns", None)
        body.pop("running", None)
    else:
        assert body["driver_time_uncertainty_ns"] == 2_000_000_000
    raw = encode_tm(body, sequence=body["tm_sequence"] & 0x3fff)
    config = DssConfig(enabled=True, journal_path=tmp_path / "independent-clock.sqlite")
    telemetry = DssTelemetryDriver(config)
    telemetry.ingest(TM_TOPIC, 0, 1, raw)
    telemetry.close()
    reopened = DssTelemetryDriver(config)
    try:
        sample = asyncio.run(reopened.current("TM.POWER.BUS_VOLTAGE"))
        clock = reopened.get_time()
        assert clock.uncertainty_ns == 2_000_000_000
        assert sample.clock_uncertainty_ns == (2_000_000_000 if historical_packet else 1000)
        assert sample.quality.value == "GOOD" and sample.validity.value == "VALID"
        assert reopened.evidence(body["satellite_epoch"], body["tm_sequence"])[0]["packet"] == raw
        if historical_packet:
            assert "running" not in decode_tm(raw)
    finally:
        reopened.close()


@pytest.mark.parametrize("value", [True, -1, 60_000_000_001, 2000.0, "2000", None, {}, []])
def test_crc_valid_invalid_driver_clock_uncertainty_cannot_enter_ledger(tmp_path, engine, value):
    from dss.packets import decode_tm
    body = decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
    body["driver_time_uncertainty_ns"] = value
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "bad-clock.sqlite"))
    try:
        with pytest.raises(ValueError, match="driver time uncertainty"):
            telemetry.ingest(TM_TOPIC, 0, 1, encode_tm(body, sequence=body["tm_sequence"] & 0x3fff))
        assert telemetry.evidence(body["satellite_epoch"]) == []
    finally:
        telemetry.close()


@pytest.mark.parametrize("value", [0, 1, None, "true", [], {}])
def test_crc_valid_nonboolean_running_flag_cannot_enter_ledger(tmp_path, engine, value):
    from dss.packets import decode_tm
    body = decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
    body["running"] = value
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "bad-running.sqlite"))
    try:
        with pytest.raises(ValueError, match="dynamics running flag"):
            telemetry.ingest(TM_TOPIC, 0, 1, encode_tm(body, sequence=body["tm_sequence"] & 0x3fff))
        assert telemetry.evidence(body["satellite_epoch"]) == []
    finally:
        telemetry.close()


@pytest.mark.parametrize("mutation", ["database", "type", "catalog", "duplicate", "topic", "unit", "engineering", "item_code", "code_type", "sequence", "apid"])
def test_invalid_packet_provenance_cannot_enter_the_ledger(tmp_path, engine, mutation):
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite"))
    body = json.loads(json.dumps(engine.telemetry()["samples"]))
    from dss.packets import decode_tm
    packet = engine.telemetry()["packet_hex"]
    body = decode_tm(bytes.fromhex(packet))
    topic = TM_TOPIC
    if mutation == "database": body["database_digest"] = "b" * 64
    if mutation == "type": body["items"][0]["raw"]["value"] = True
    if mutation == "catalog": body["items"][0]["catalog_digest"] = "b" * 64
    if mutation == "duplicate": body["items"].append(body["items"][0])
    if mutation == "topic": topic = "arbitrary"
    if mutation == "unit": body["items"][0]["unit"] = "forged"
    if mutation == "engineering": body["items"][0]["engineering"]["value"] += 1.0
    if mutation == "item_code": body["items"][0]["item_code"] += 1
    if mutation == "code_type": body["items"][0]["item_code"] = True
    sequence = (body["tm_sequence"] + (1 if mutation == "sequence" else 0)) & 0x3fff
    with pytest.raises(ValueError): telemetry.ingest(topic, 0, 0, encode_tm(body, sequence=sequence, ack=mutation == "apid"))
    assert telemetry.evidence(body["satellite_epoch"]) == []
    telemetry.close()


def test_exact_packet_digest_retrieves_older_consumed_proof_beyond_response_window(tmp_path, engine):
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite"))
    ingest_pending(telemetry, engine)
    health = telemetry.health()
    original = telemetry.evidence(health["satellite_epoch"])[0]
    from dss.packets import decode_tm
    body = decode_tm(original["packet"])
    for index in range(2, 23):
        body["tm_sequence"] = index
        telemetry.ingest(TM_TOPIC, 0, 100 + index, encode_tm(body, sequence=index))
    assert original["packet_sha256"] not in {item["packet_sha256"] for item in telemetry.evidence(health["satellite_epoch"])}
    assert telemetry.evidence(health["satellite_epoch"], packet_sha256=original["packet_sha256"]) == [original]
    with pytest.raises(ObservationFailure) as failure:
        asyncio.run(telemetry.next("TM.POWER.BUS_VOLTAGE", health["satellite_epoch"], 1,
            time.time_ns() + 1_000_000_000))
    assert failure.value.code is ObservationCode.GAP
    assert failure.value.gap.first_available_sequence == 15
    assert failure.value.gap.last_available_sequence == 22
    current = asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE"))
    assert current.source_sequence == 22
    # Within the declared window NEXT still returns the exact next sample.
    next_sample = asyncio.run(telemetry.next("TM.POWER.BUS_VOLTAGE", health["satellite_epoch"], 15,
        time.time_ns() + 1_000_000_000))
    assert next_sample.source_sequence == 16
    telemetry.close()


def test_retained_packet_history_does_not_turn_current_or_hash_reads_into_full_scans(tmp_path, engine):
    from dss.packets import decode_tm
    config = DssConfig(enabled=True, journal_path=tmp_path / "retained.sqlite")
    telemetry = DssTelemetryDriver(config)
    body = decode_tm(bytes.fromhex(engine.telemetry()["packet_hex"]))
    first_packet = None
    for sequence in range(1, 129):
        body["tm_sequence"] = sequence
        raw = encode_tm(body, sequence=sequence)
        telemetry.ingest(TM_TOPIC, 0, sequence, raw)
        if sequence == 1:
            first_packet = raw
    # Reopen a historical ledger without the additive indexes. Every original
    # packet remains; opening must install bounded lookup paths in place.
    for name in ("dss_packet_topic_latest", "dss_packet_topic_cursor", "dss_packet_hash"):
        telemetry._db.execute("DROP INDEX " + name)
    telemetry._db.commit()
    telemetry.close()
    telemetry = DssTelemetryDriver(config)
    plan = telemetry._db.execute("EXPLAIN QUERY PLAN SELECT body,received_ns FROM dss_packet "
        "WHERE topic=? ORDER BY id DESC LIMIT 1", (TM_TOPIC,)).fetchall()
    assert all("TEMP B-TREE" not in row[3] and "SCAN dss_packet" not in row[3] for row in plan)
    digest = hashlib.sha256(first_packet).hexdigest()
    # A VM instruction budget detects a scan independently of wall-clock load.
    # The old topic/offset index plus full-body sort exceeds this bound.
    telemetry._db.set_progress_handler(lambda: 1, 100)
    try:
        assert asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE")).source_sequence == 128
        proof = telemetry.evidence(body["satellite_epoch"], packet_sha256=digest)
        assert len(proof) == 1 and proof[0]["packet"] == first_packet
    finally:
        telemetry._db.set_progress_handler(None, 0)
    assert telemetry._db.execute("SELECT COUNT(*) FROM dss_packet").fetchone()[0] == 128
    telemetry.close()


@pytest.mark.parametrize("fault,reason", [("policy_revision", "DSS_POLICY_REVISION_MISMATCH"), ("source_gap", "DSS_SOURCE_GAP")])
def test_source_policy_and_gap_are_not_upgraded_to_good(tmp_path, engine, fault, reason):
    engine.reset("quality-case", faults={fault: "different-policy" if fault == "policy_revision" else True})
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite"))
    ingest_pending(telemetry, engine)
    sample = asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE"))
    assert sample.quality.value == "UNKNOWN"
    assert sample.quality_reason == reason
    telemetry.close()


def test_stale_acquisition_remains_stale_and_cannot_admit_commands(tmp_path, engine):
    engine.reset("stale-case", faults={"stale": True})
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite"))
    ingest_pending(telemetry, engine)
    sample = asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE"))
    assert time.time_ns() - sample.acquired_at_unix_ns >= 10_000_000_000
    with pytest.raises(DssUnavailable):
        telemetry.health()
    assert telemetry.health(require_fresh=False)["satellite_epoch"] == engine.state()["epoch"]
    telemetry.close()


def test_reset_requires_current_instead_of_silently_reusing_next_cursor(tmp_path, engine):
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "driver.sqlite"))
    ingest_pending(telemetry, engine)
    previous = asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE"))
    engine.reset("epoch-change")
    ingest_pending(telemetry, engine)
    with pytest.raises(ObservationFailure) as failure:
        asyncio.run(telemetry.next("TM.POWER.BUS_VOLTAGE", previous.source_epoch, previous.source_sequence, time.time_ns() + 1_000_000_000))
    assert failure.value.code is ObservationCode.STALE_GENERATION
    assert asyncio.run(telemetry.current("TM.POWER.BUS_VOLTAGE")).source_epoch != previous.source_epoch
    telemetry.close()
