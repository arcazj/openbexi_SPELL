from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import http.client
import json
import socket
import threading
import uuid

import pytest

from dss.engine import DssEngine
from dss.packets import decode_tc, decode_tm, encode_tc, recv_packet
from dss.server import ApiServer, DssRuntime, TcServer


@pytest.fixture
def runtime(tmp_path):
    engine = DssEngine(tmp_path / "satellite.sqlite")
    runtime = DssRuntime(engine, bootstrap_servers="unused.invalid:9092")
    yield runtime
    runtime.stop_event.set()
    engine.close()


@contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def post(address, path, body, origin="http://127.0.0.1:8080", content_type="application/json"):
    with closing(http.client.HTTPConnection(*address, timeout=3)) as connection:
        connection.request("POST", path, body=json.dumps(body),
                           headers={"Content-Type": content_type, "Origin": origin})
        response = connection.getresponse()
        return response.status, json.loads(response.read())


def command(runtime, stage, operation):
    state = runtime.engine.state()
    return {"schema_version": "openbexi.dss.tc/1", "satellite_id": "GENERIC",
            "database_revision": state["database_revision"], "database_digest": state["database_digest"],
            "satellite_epoch": state["epoch"], "scenario_id": state["scenario_id"],
            "operation_id": operation, "procedure_id": "tcp-test", "execution_id": "execution-1",
            "plan_id": "plan-1", "element_id": "element-1", "command_name": "CMDNAME",
            "command_digest": "a" * 64, "arguments": [], "stage": stage}


def test_http_controls_fence_state_and_reject_cross_origin_or_untyped_mutation(runtime):
    state = runtime.engine.state()
    body = {"action": "STEP", "expected_epoch": state["epoch"], "expected_revision": state["revision"]}
    with serving(ApiServer(("127.0.0.1", 0), runtime)) as address:
        assert post(address, "/api/v1/control", body, origin="https://example.invalid")[0] == 403
        assert post(address, "/api/v1/control", body, content_type="text/plain")[0] == 415
        assert runtime.engine.state() == state
        status, changed = post(address, "/api/v1/control", body)
        assert status == 200 and changed["core"]["tick"] == state["core"]["tick"] + 1
        assert changed["revision"] == state["revision"] + 1
        assert post(address, "/api/v1/control", body) == (409, {"error_code": "DSS_STATE_CONFLICT"})
        assert runtime.engine.state() == changed


def test_reset_is_test_only_epoch_fenced_and_retains_prior_evidence(runtime):
    old = runtime.engine.state()
    body = {"scenario_id": "new-scenario", "expected_epoch": old["epoch"]}
    with serving(ApiServer(("127.0.0.1", 0), runtime)) as address:
        assert post(address, "/api/v1/scenarios/reset", body)[0] == 403
        runtime.test_control = True
        assert post(address, "/api/v1/scenarios/reset", {**body, "expected_epoch": "old"})[0] == 409
        status, new = post(address, "/api/v1/scenarios/reset", body)
        assert status == 200 and new["epoch"] != old["epoch"]
        assert runtime.engine.evidence(old["scenario_id"])["final_state"] == old
        assert post(address, "/api/v1/scenarios/reset", body)[0] == 409


def test_tcp_fragmented_coalesced_commands_share_durable_ack_and_execute_once(runtime):
    transport = encode_tc(command(runtime, "TRANSPORT", "transport-1"), sequence=1)
    release = encode_tc(command(runtime, "RELEASE", "release-1"), sequence=2)
    with serving(TcServer(("127.0.0.1", 0), runtime)) as address:
        with socket.create_connection(address, timeout=3) as connection:
            connection.sendall(transport[:3])
            connection.sendall(transport[3:] + release)
            ack_transport, ack_release = recv_packet(connection), recv_packet(connection)
            assert decode_tm(ack_transport)["outcome"] == "ACCEPTED"
            assert decode_tm(ack_release)["outcome"] == "RELEASED"
            connection.sendall(release)
            assert recv_packet(connection) == ack_release
    state = runtime.engine.state()
    assert state["core"]["commands_executed"] == 1
    assert state["core"]["last_command_name"] == "CMDNAME"
    records = runtime.engine.pending_packets()
    assert ack_release in [row["packet"] for row in records if row["topic"].endswith(".ack")]
    evidence = runtime.engine.evidence(state["scenario_id"])
    assert len(evidence["operations"]) == 2
    assert len(evidence["commands"]) == 1


def test_invalid_tcp_packet_never_reaches_command_effect(runtime):
    before = runtime.engine.state()
    packet = bytearray(encode_tc(command(runtime, "TRANSPORT", "bad")))
    packet[-1] ^= 1
    with serving(TcServer(("127.0.0.1", 0), runtime)) as address:
        with socket.create_connection(address, timeout=3) as connection:
            connection.sendall(packet)
            assert connection.recv(1) == b""
    assert runtime.engine.state() == before
    assert runtime.engine.evidence(before["scenario_id"])["operations"] == []


def test_outbox_is_marked_only_after_confirmation_and_retries_identical_packet(runtime):
    original = runtime.engine.pending_packets()[0]
    calls = []

    class Receipt:
        def __init__(self, fail): self.fail = fail
        def get(self, timeout):
            assert timeout == 5
            if self.fail: raise TimeoutError("broker not confirmed")

    class Publisher:
        def __init__(self, fail): self.fail = fail
        def send(self, topic, *, key, value):
            calls.append((topic, key, value))
            return Receipt(self.fail)

    with pytest.raises(TimeoutError): runtime.publish_pending(Publisher(True))
    assert runtime.engine.pending_packets() == [original]
    assert runtime.publish_pending(Publisher(False)) == 1
    assert calls[0] == calls[1] == (original["topic"], original["epoch"].encode("ascii"), original["packet"])
    assert runtime.engine.pending_packets() == []
    proof = runtime.engine.evidence(runtime.engine.state()["scenario_id"])["packets"][0]
    assert proof["published"] is True
    assert proof["packet_sha256"] == hashlib.sha256(original["packet"]).hexdigest()


def test_http_duplicate_and_oversized_inputs_cannot_change_state(runtime):
    before = runtime.engine.state()
    with serving(ApiServer(("127.0.0.1", 0), runtime)) as address:
        with closing(http.client.HTTPConnection(*address, timeout=3)) as connection:
            connection.request("POST", "/api/v1/control", body='{"action":"PAUSE","action":"STEP"}',
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            assert response.status == 400
            response.read()
        assert post(address, "/api/v1/control", {"action": "x" * 65536})[0] == 413
    assert runtime.engine.state() == before


def test_ui_command_uses_real_tcp_and_distinct_bound_stage_receipts(runtime):
    state = runtime.engine.state()
    body = {"operation_id": str(uuid.uuid4()), "command_name": "CMD1", "arguments": [], "confirmed": True,
            "expected_epoch": state["epoch"], "expected_revision": state["revision"]}
    with serving(TcServer(("127.0.0.1", 0), runtime)) as tcp_address:
        runtime.tc_address = tcp_address
        with serving(ApiServer(("127.0.0.1", 0), runtime)) as address:
            assert post(address, "/api/v1/commands", {**body, "confirmed": False})[0] == 400
            assert runtime.engine.state() == state
            status, result = post(address, "/api/v1/commands", body)
            assert status == 200 and result["outcome"] == "SUCCEEDED"
            assert [(r["stage"], r["outcome"]) for r in result["receipts"]] == [
                ("TRANSPORT", "ACCEPTED"), ("LOADING", "LOADED"), ("RELEASE", "RELEASED"),
                ("ACKNOWLEDGEMENT", "ACKNOWLEDGED"), ("ONBOARD_EXECUTION", "SUCCEEDED")]
            assert post(address, "/api/v1/commands", body)[0] == 409
    current = runtime.engine.state()
    assert current["payload"]["enabled"] is True and current["core"]["commands_executed"] == 1
    proof = runtime.engine.evidence(current["scenario_id"])
    assert len(proof["operations"]) == 5
    assert all(r["acknowledgement"]["operation_id"] == body["operation_id"] for r in proof["operations"])
    assert all(r["acknowledgement"]["procedure_id"] == "DSS_UI" for r in proof["operations"])
    assert all(bytes.fromhex(r["packet_hex"])[:2] == b"\x18\x64" for r in proof["operations"])


def test_ui_lost_ack_preserves_effect_and_reports_uncertain_without_resending(runtime):
    original = runtime.engine.state()
    state = runtime.engine.reset("lost-ui-ack", faults={"lost_ack": True}, expected_epoch=original["epoch"])
    body = {"operation_id": str(uuid.uuid4()), "command_name": "CMD1", "arguments": [], "confirmed": True,
            "expected_epoch": state["epoch"], "expected_revision": state["revision"]}
    with serving(TcServer(("127.0.0.1", 0), runtime)) as tcp_address:
        runtime.tc_address = tcp_address
        result = runtime.execute_ui_command(body)
    assert result["outcome"] == "UNCERTAIN"
    assert [r["stage"] for r in result["receipts"]] == ["TRANSPORT", "LOADING"]
    proof = runtime.engine.evidence(state["scenario_id"])
    assert proof["final_state"]["payload"]["enabled"] is True
    assert proof["final_state"]["core"]["commands_executed"] == 1
    assert [r["acknowledgement"]["stage"] for r in proof["operations"]] == ["TRANSPORT", "LOADING", "RELEASE"]
    assert sum(r["executed"] for r in proof["commands"]) == 1


def test_evidence_pages_have_exact_membership_and_reject_changed_revision(runtime):
    state = runtime.engine.state()
    for _ in range(70):
        state = runtime.engine.control("STEP", expected_epoch=state["epoch"], expected_revision=state["revision"])
    full = runtime.engine.evidence(state["scenario_id"])
    collected = {"commands": [], "operations": [], "packets": []}
    offset = 0
    evidence_revision = None
    with serving(ApiServer(("127.0.0.1", 0), runtime)) as address:
        while offset is not None:
            with closing(http.client.HTTPConnection(*address, timeout=3)) as connection:
                path = f'/api/v1/evidence?scenario_id={state["scenario_id"]}&offset={offset}&limit=32'
                if evidence_revision is not None:
                    path += f"&expected_revision={evidence_revision}"
                connection.request("GET", path)
                response = connection.getresponse()
                assert response.status == 200
                page = json.loads(response.read())
            if evidence_revision is None:
                evidence_revision = page["pagination"]["revision"]
            assert page["pagination"]["revision"] == evidence_revision
            assert page["final_state"] == full["final_state"]
            assert page["pagination"]["counts"] == {key: len(full[key]) for key in collected}
            for key in collected:
                assert len(page[key]) <= 32
                collected[key].extend(page[key])
            offset = page["pagination"]["next_offset"]
        assert collected == {key: full[key] for key in collected}
        runtime.engine.control("STEP", expected_epoch=state["epoch"], expected_revision=state["revision"])
        with closing(http.client.HTTPConnection(*address, timeout=3)) as connection:
            connection.request("GET", f'/api/v1/evidence?scenario_id={state["scenario_id"]}&expected_revision={evidence_revision}')
            response = connection.getresponse()
            assert response.status == 409
            response.read()
    with pytest.raises(ValueError): runtime.engine.evidence_page(state["scenario_id"], limit=33)


@pytest.mark.parametrize("value,encoded", [(1.1, "1.1000000000000001"), (1000000.0, "1000000"),
                                          (1e-7, "9.9999999999999995e-08"), (-0.0, "-0"), (1, "1")])
def test_ui_float_value_is_canonicalized_before_strict_binary_database_validation(runtime, value, encoded):
    state = runtime.engine.state()
    arguments = [{"name": "ARG1", "value_type": "FLOAT", "value_format": "ENG", "value": value}]
    request = {"operation_id": str(uuid.uuid4()), "command_name": "CMDNAME", "arguments": arguments, "confirmed": True,
               "expected_epoch": state["epoch"], "expected_revision": state["revision"]}
    with serving(TcServer(("127.0.0.1", 0), runtime)) as address:
        runtime.tc_address = address
        result = runtime.execute_ui_command(request)
    assert result["outcome"] == "SUCCEEDED"
    proof = runtime.engine.evidence(state["scenario_id"])
    raw = bytes.fromhex(proof["operations"][0]["packet_hex"])
    actual = decode_tc(raw)["arguments"][0]
    assert type(actual["value"]) is float
    assert actual["encoded"] == encoded and actual["radix"] == "DEC"
    assert actual["value"] == float(value)
    # The UI API does not accept an asserted pre-encoded representation at all.
    with pytest.raises(ValueError):
        runtime.execute_ui_command({**request, "arguments": [{**arguments[0], "encoded": "forged", "radix": "DEC"}]})
    with pytest.raises(ValueError, match="finite numeric"):
        runtime.execute_ui_command({**request, "arguments": [{**arguments[0], "value": 1 << 4095}]})


def test_automatic_frame_integrates_ten_real_ticks_while_manual_step_stays_immediate(runtime):
    initial = runtime.engine.state()
    before = runtime.engine.control("RESUME", expected_epoch=initial["epoch"], expected_revision=initial["revision"])
    packets = len(runtime.engine.evidence(before["scenario_id"])["packets"])
    stop = runtime.stop_event
    class SingleCycle:
        calls = 0
        def wait(self, seconds):
            assert seconds == 1.0
            self.calls += 1
            return self.calls > 1
    runtime.stop_event = SingleCycle()
    try:
        runtime._tick_loop()
    finally:
        runtime.stop_event = stop
    after = runtime.engine.state()
    assert runtime.runtime_error is None
    assert after["core"]["tick"] == before["core"]["tick"] + 10
    assert after["core"]["sim_time_ns"] == before["core"]["sim_time_ns"] + 1_000_000_000
    assert len(runtime.engine.evidence(before["scenario_id"])["packets"]) == packets + 1
    assert runtime.health()["physics_ticks_per_frame"] == 10
    paused = runtime.engine.control("PAUSE", expected_epoch=after["epoch"], expected_revision=after["revision"])
    packets = len(runtime.engine.evidence(before["scenario_id"])["packets"])
    stepped = runtime.engine.control("STEP", expected_epoch=paused["epoch"], expected_revision=paused["revision"])
    assert stepped["core"]["tick"] == paused["core"]["tick"] + 1
    assert stepped["core"]["sim_time_ns"] == paused["core"]["sim_time_ns"] + runtime.database.material["dynamics"]["tick_ns"]
    assert len(runtime.engine.evidence(before["scenario_id"])["packets"]) == packets + 1
