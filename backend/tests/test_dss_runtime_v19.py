"""DSS provider stages use actual binary driver transport and decoded packets."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from backend.dss_runtime import DssRuntime, DssRuntimeError
from backend.procedure_parser import ProcedureCatalog
from backend.telecommand_runtime_v11 import prepare_send_request, execute_preflight
from driver_host.dss_command import DssCommandDriver
from driver_host.dss_config import DssConfig
from driver_host.dss_service import DssService
from driver_host.dss_telemetry import DssTelemetryDriver
from driver_host.tests.test_dss_transport import engine, cortex, ingest_pending
from spell.driver.dss.v1 import dss_pb2


@pytest.fixture
def runtime(tmp_path, engine, cortex):
    command = DssCommandDriver(DssConfig(enabled=True, journal_path=tmp_path / "command.sqlite"), connect=cortex[0])
    telemetry = DssTelemetryDriver(DssConfig(enabled=True, journal_path=tmp_path / "telemetry.sqlite"))
    class Observation:
        def _identity(self, *args, **kwargs): return True
        def _bound(self, *args): return True
        def _context_active(self, *args): return True
    class Context:
        async def abort(self, code, message): raise ValueError(message)
    service = DssService(Observation(), command, telemetry)
    class Gateway:
        def observation_generations(self):
            fields = dict(server_profile_id="local-synthetic", driver_host_generation="host-test", host_profile_digest="b" * 64,
                context_id="", context_generation="", context_binding_digest="")
            return {"host": SimpleNamespace(**fields), "contexts": [SimpleNamespace(**{**fields, "context_id": "simulator", "context_generation": "context-test", "context_binding_digest": "c" * 64})], "credential_epoch": 1}
        def dss_call(self, method, request, **kwargs):
            ingest_pending(telemetry, engine)
            return asyncio.run(getattr(service, method)(request, Context()))
    value = DssRuntime(Gateway())
    yield value
    command.close()
    telemetry.close()


def run_source(runtime, source):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source, "dss-proof.spell.py")
    request, service, preflight = prepare_send_request("execution-test", 0, procedure.steps[0], {})
    provider = runtime.provider(request, preflight, procedure_id="dss-proof", context_id="simulator")
    return execute_preflight(request, service, preflight, provider=provider), provider


@pytest.mark.parametrize("source,count,disposition", [
    ("Send(command='CMD1')", 1, "EXECUTED_UNVERIFIED"),
    ("Send(command='CMD1', LoadOnly=True)", 0, "LOADED_ONLY"),
    ("Send(group=['CMD1','CMD2'])", 2, "EXECUTED_UNVERIFIED"),
    ("Send(sequence='SEQNAME')", 3, "EXECUTED_UNVERIFIED"),
])
def test_actual_provider_command_modes(runtime, engine, source, count, disposition):
    result, provider = run_source(runtime, source)
    assert result["outcome"] == "SETTLED"
    assert all(item["disposition"] == disposition for item in result["checkpoint"]["elements"])
    assert engine.state()["core"]["commands_executed"] == count
    for call in provider.calls:
        assert call["detail"]["provider"] == "dss-cortex-kafka"
        assert len(call["detail"]["command_packet_sha256"]) == 64
        if call["stage"] == "ONBOARD_EXECUTION":
            assert call["detail"]["telemetry"]


def test_reference_mapping_reaches_real_ccsds_and_updates_ground_state(runtime, engine):
    definition = engine.catalog.command("DSS.REFERENCE.SET_GROUND")
    names = [item["name"] for item in definition["arguments"]]
    result = runtime.reference_command("DSS.REFERENCE.SET_GROUND", {names[0]: "TMparam", names[1]: 23.0},
        execution_id="reference-execution", procedure_id="language_reference_244", operation_id="reference-operation", context_id="simulator")
    assert result["stages"][-1]["outcome"] == "SUCCEEDED"
    assert engine.state()["core"]["commands_executed"] == 1
    with pytest.raises(DssRuntimeError, match="not admitted"):
        runtime.reference_command("CMD1", {}, execution_id="e", procedure_id="p", operation_id="o", context_id="simulator")


def test_authority_revocation_prevents_every_command_packet(runtime, engine):
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source("Send(command='CMD1')", "proof.spell.py")
    request, service, preflight = prepare_send_request("execution-test", 0, procedure.steps[0], {})
    provider = runtime.provider(request, preflight, procedure_id="proof", context_id="simulator", authorize=lambda: False)
    with pytest.raises(DssRuntimeError, match="authority"):
        execute_preflight(request, service, preflight, provider=provider)
    assert engine.evidence(engine.state()["scenario_id"])["operations"] == []


def test_configured_runtime_has_no_nominal_fallback(runtime, engine):
    runtime.gateway.dss_call = lambda *args, **kwargs: (_ for _ in ()).throw(DssRuntimeError("offline"))
    with pytest.raises(DssRuntimeError, match="offline"):
        run_source(runtime, "Send(command='CMD1')")
    assert engine.state()["core"]["commands_executed"] == 0


@pytest.mark.parametrize("modifiers,count,transport_count", [
    ({"load_only": True}, 0, 3),
    ({"group": True}, 3, 1),
    ({"block": True}, 3, 1),
    ({"post_verify": True}, 3, 3),
])
def test_reference_mapping_preserves_load_group_block_and_real_verification(runtime, engine, modifiers, count, transport_count):
    result = runtime.reference_command("DSS.REFERENCE.SEND", [{}, {}, {}], modifiers=modifiers,
        execution_id="reference-execution", procedure_id="language_reference_244", operation_id="reference-operation", context_id="simulator")
    assert result["executed_count"] == count
    assert engine.state()["core"]["commands_executed"] == count
    assert sum(item["stage"] == "TRANSPORT" for item in result["stages"]) == transport_count
    if modifiers.get("post_verify"):
        assert sum(item["stage"] == "VERIFICATION" and item["outcome"] == "PASSED" for item in result["stages"]) == 3


def test_long_relative_release_advances_real_physics_only_with_declared_policy(runtime, engine):
    engine.reset("accelerated-clock", faults={"auto_advance_scheduled_time": True})
    result, provider = run_source(runtime, "Send(command='CMD1', ReleaseTime=NOW+30*MINUTE)")
    assert result["checkpoint"]["elements"][0]["disposition"] == "EXECUTED_UNVERIFIED"
    state = engine.state()
    assert state["core"]["sim_time_ns"] >= 1_800_000_000_000
    assert state["core"]["tick"] > 0
    assert provider.calls[-1]["detail"]["dynamics_tick"] == state["core"]["tick"]


def test_future_release_without_acceleration_does_not_execute(runtime, engine):
    result, _ = run_source(runtime, "Send(command='CMD1', ReleaseTime=NOW+30*MINUTE)")
    assert result["checkpoint"]["elements"][0]["disposition"] == "UNCERTAIN"
    assert engine.state()["core"]["commands_executed"] == 0


def test_parent_rpc_bridge_refuses_to_block_its_own_event_loop():
    from backend.driver_gateway import DriverGateway, DriverGatewayError
    async def scenario():
        gateway = DriverGateway.__new__(DriverGateway)
        gateway.settings = SimpleNamespace(dss_enabled=True)
        gateway._handshake = SimpleNamespace(driver=SimpleNamespace(driver_host_generation="epoch"))
        gateway._revalidating_generation = None
        gateway._health_admitted_generation = "epoch"
        gateway._client = object()
        gateway._event_loop = asyncio.get_running_loop()
        with pytest.raises(DriverGatewayError, match="outside the event loop"):
            gateway.dss_call("Health", None)
    asyncio.run(scenario())


@pytest.mark.parametrize("reset", [False, True])
def test_durable_guard_read_epoch_fences_real_command_after_satellite_reset(runtime, engine, cortex, reset):
    from backend.models import Execution
    from backend.tests.test_supervisor_observation_command_v19 import EVIDENCE, Runtime, fixture, request_result, commit
    from backend.tests.test_supervisor_v11_runtime import _ordinary_step_commit
    epoch = runtime.health("simulator")["satellite_epoch"]
    observation = Runtime({"outcome": "OK", "value": 12, "evidence": {
        **EVIDENCE, "source_id": "dss-GENERIC", "source_epoch": epoch}})
    supervisor, sessions, procedure, execution_id = fixture(runtime=observation)
    request, result = request_result(supervisor, procedure, execution_id)
    variables = {"ARGS": {}, "reading": 12}
    assert supervisor._commit_step(execution_id, 7, commit(procedure, request, result, variables))
    variables["__spell_branch_0"] = True
    assert supervisor._commit_step(execution_id, 7, _ordinary_step_commit(procedure, 2, variables))
    # The epoch is recovered from durable events after the observer object is gone.
    supervisor.observation_runtime = None
    captured = supervisor._dss_command_observation_epochs(execution_id, 3)
    assert captured == frozenset({epoch})
    if reset:
        engine.reset("after-authoritative-read")
    request, service, preflight = prepare_send_request(execution_id, 3, procedure.steps[3], variables)
    if reset:
        with pytest.raises(DssRuntimeError, match="retired satellite epoch"):
            runtime.provider(request, preflight, procedure_id="guarded-proof", context_id="simulator", observation_epochs=captured)
        assert cortex[1] == []
        assert engine.state()["core"]["commands_executed"] == 0
    else:
        provider = runtime.provider(request, preflight, procedure_id="guarded-proof", context_id="simulator", observation_epochs=captured)
        assert execute_preflight(request, service, preflight, provider=provider)["outcome"] == "SETTLED"
        assert engine.state()["core"]["commands_executed"] == 1


def test_exact_consumed_packet_wait_returns_requested_identity(runtime, engine):
    packet = runtime.latest_telemetry("simulator")
    epoch, sequence = packet["satellite_epoch"], packet["tm_sequence"]
    proof = runtime.await_evidence(epoch, sequence)
    digest = next(item["packet_sha256"] for item in proof if item["topic"] == "openbexi.GENERIC.tm")
    assert all(item["packet_sha256"] == digest for item in runtime.await_packet(epoch, digest))
    with pytest.raises(DssRuntimeError, match="deadline"):
        runtime.await_packet(epoch, "0" * 64, timeout_seconds=0.03)


def test_duration_wait_is_not_falsely_treated_as_a_captured_satellite_sample():
    from backend.runtime_composition_v19 import command_observation_dependencies
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        "WaitFor(seconds=0.001)\nSend(command='CMD1')", "wait-command.spell.py")
    assert command_observation_dependencies(list(procedure.steps), 1) == ()
