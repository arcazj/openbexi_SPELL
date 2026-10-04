"""Real spawned workers plus binary TCP driver; release Kafka proof is a separate gate."""
import time
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import language_conformance_v19 as registry
from backend.dss_language_broker import digest,subject_binding
from backend.dss_language_executor import DssLanguageExecutor
from backend.dss_scenarios import subject_execution_spec
from backend.tests.test_dss_runtime_v19 import runtime
from driver_host.tests.test_dss_transport import engine
from scripts.validate_dss_delivery import validate_subject_capture,validate_outer_source_execution


@pytest.fixture
def cortex(engine):
    """Use the production TCP handler, including declared drop/delay fault behavior."""
    import socket, threading
    from dss.server import DssRuntime, TcServer
    service = DssRuntime(engine, bootstrap_servers="unused-unit-broker:9092")
    server = TcServer(("127.0.0.1",0), service)
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    def connect(_endpoint, *, timeout):
        return socket.create_connection(server.server_address,timeout=timeout)
    try:
        yield connect, []
    finally:
        service.stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("broken_diagnostic",[False,True])
def test_failing_actual_worker_oracle_keeps_durable_safe_diagnostic(tmp_path,monkeypatch,broken_diagnostic):
    import json,queue,threading
    from sqlalchemy import Column,JSON,MetaData,Table,select
    from backend.dss_language_broker import request_for_selection
    from backend.dss_language_diagnostics import readiness
    from backend.dss_language_supervisor import _resolve
    from backend.ir_v07 import canonicalize_observation_result
    from backend.migrations.versions.v0011_dss_language_ledger import metadata,language_cases
    import backend.dss_language_executor as executor_module
    import backend.dss_language_supervisor as dispatcher
    import backend.dss_language_diagnostics as diagnostics
    case=next(row for row in registry.CASES if row["id"]=="v19-observation-confirmation-no")
    request=request_for_selection("outer",4,195+registry.CASES.index(case))
    database=create_engine("sqlite:///"+str(tmp_path/"failed.sqlite"))
    metadata.create_all(database)
    event_metadata=MetaData()
    events=Table("diagnostic_events",event_metadata,Column("payload",JSON,nullable=False))
    event_metadata.create_all(database)
    factory=sessionmaker(database)
    evidence={"item_id":"TM.POWER.BUS_VOLTAGE","source_epoch":"epoch-current","source_sequence":"5",
        "quality":"GOOD","validity":"VALID","freshness":"STALE","synchronization_state":"COMPLETE",
        "acquired_at_unix_ns":"1000000000","received_at_unix_ns":"7000000000",
        "raw_value":{"value":"DO_NOT_RETAIN_RAW"},"engineering_value":{"value":"DO_NOT_RETAIN_ENGINEERING"}}
    class Runtime:
        policy=SimpleNamespace(policy_revision="v07-r1")
        def resolve(self,raw):
            return canonicalize_observation_result(raw,{"outcome":"NOT_AVAILABLE",
                "error_code":"V19_SAMPLE_NOT_ACCEPTABLE","error_message":"DO_NOT_RETAIN_MESSAGE","evidence":evidence})
    executor=DssLanguageExecutor.__new__(DssLanguageExecutor)
    executor.authorize=lambda:True
    executor.readiness_capture=readiness({"items":[evidence],"driver_time":{
        "source_epoch":"epoch-current","source_sequence":"4","provenance":"dss-dynamics-clock",
        "value":"DO_NOT_RETAIN_CLOCK"}}, {"epoch":"epoch-current"},8_000_000_000)
    monkeypatch.setattr(executor,"_observation_runtime",lambda:Runtime())
    monkeypatch.setattr(executor,"execute",lambda _subject:executor._source_case(case,{"scenario_id":"inner"}))
    monkeypatch.setattr(executor_module,"DssLanguageExecutor",lambda *_args,**_kwargs:executor)
    monkeypatch.setattr(dispatcher,"_active",lambda *_args:"simulator")
    def append_event(_execution,event_type,payload,**_kwargs):
        assert event_type=="procedure.dss_language_failed"
        with factory.begin() as session:session.execute(events.insert().values(payload=payload))
    handle=SimpleNamespace(generation=1,control=queue.Queue())
    key=("outer",request["request_id"],1)
    supervisor=SimpleNamespace(session_factory=factory,_lock=threading.RLock(),
        _dss_language_requests={key},append_event=append_event)
    if broken_diagnostic:
        monkeypatch.setattr(diagnostics,"failure",lambda _executor:(_ for _ in ()).throw(TypeError("DO_NOT_RETAIN_SERIALIZER")))
    try:
        _resolve(supervisor,"outer",handle,request)
        response=handle.control.get(timeout=1)
        assert response["outcome"]=="FAILED" and "source oracle mismatch" in response["error"]
        with factory() as session:
            payload=session.execute(select(events.c.payload)).scalar_one()
            intent=session.execute(select(language_cases)).mappings().one()
        assert intent["state"]=="DISPATCHING" and intent["result"] is None
        assert payload["subject"]=="case:"+case["id"] and payload["error"]==response["error"]
        encoded=json.dumps(payload)
        assert "DO_NOT_RETAIN" not in encoded
        diagnostic=payload["diagnostic"]
        if broken_diagnostic:
            assert diagnostic["unavailable_reason"]=="TypeError"
        else:
            assert diagnostic["readiness"]["clock"]["source_sequence"]=="4"
            assert diagnostic["readiness"]["items"][0]["freshness"]=="STALE"
            assert diagnostic["worker"]["source_sha256"]==case["source_sha256"]
            assert diagnostic["observations"][0]["result"]=={
                "outcome":"NOT_AVAILABLE","error_code":"V19_SAMPLE_NOT_ACCEPTABLE"}
            assert diagnostic["observations"][0]["evidence"]["source_sequence"]=="5"
            assert diagnostic["observation_count"]==1 and len(encoded)<diagnostics.MAX_BYTES
        assert not supervisor._dss_language_requests
    finally:database.dispose()


def test_failure_diagnostic_has_closed_item_result_string_and_byte_bounds():
    from backend import dss_language_diagnostics as diagnostics
    snapshot={"items":[{"item_id":"x"*1000,"value":"secret"} for _ in range(100)],"driver_time":None}
    prepared=diagnostics.readiness(snapshot,{"epoch":"epoch"},1)
    assert prepared["item_count"]==100 and len(prepared["items"])==diagnostics.MAX_ITEMS
    assert all(row=={"item_id":"x"*diagnostics.MAX_STRING} for row in prepared["items"])
    executor=SimpleNamespace(readiness_capture=prepared,worker_capture=None,
        observation_diagnostics=[{"result":{"outcome":"NOT_AVAILABLE"}}]*100,
        observation_diagnostic_count=100)
    actual=diagnostics.failure(executor)
    assert actual["observation_count"]==100 and len(actual["observations"])==diagnostics.MAX_RESULTS
    executor.readiness_capture={"malformed_oversized":"x"*diagnostics.MAX_BYTES}
    with pytest.raises(ValueError,match="byte bound"):diagnostics.failure(executor)


@pytest.mark.parametrize("case_id",["v17-core-arithmetic-precedence","v18-native-yes-built-command",
    "v18-native-no-no-dispatch","v18-native-cancel-no-dispatch","v18-native-plus-command-confirmation",
    "v18-load-only-is-not-execution","v18-block-group-transport","v18-literal-radix-format",
    "v18-relative-release-intent","v18-bounded-delay-and-timeout"])
def test_nested_source_worker_and_independent_raw_validator(case_id,runtime,engine,monkeypatch):
    case=next(row for row in registry.CASES if row["id"]==case_id)
    subject="case:"+case_id
    spec=subject_execution_spec(subject,case)
    state=engine.reset(str(uuid.uuid4()),initial_state=spec["initial_state"],faults=spec["faults"],expected_epoch=engine.state()["epoch"])
    engine.control("RESUME",expected_epoch=state["epoch"],expected_revision=state["revision"])
    database=create_engine("sqlite://")
    executor=DssLanguageExecutor.__new__(DssLanguageExecutor)
    executor.supervisor=SimpleNamespace(session_factory=sessionmaker(database))
    executor.runtime=runtime
    executor.context_id="simulator"
    executor.authorize=lambda:True
    monkeypatch.setattr(executor,"_observation_runtime",lambda:None)
    started=time.monotonic()
    try:
        actual=executor._source_case(case,state)
        current=engine.state()
        engine.control("PAUSE",expected_epoch=current["epoch"],expected_revision=current["revision"])
        evidence=engine.evidence(state["scenario_id"])
        packets=[packet for row in evidence["packets"] for packet in runtime.await_packet(state["epoch"],row["packet_sha256"])]
        # This unit fixture feeds the consumer directly. A simulated broker
        # acknowledgement permits testing downstream proof validation; only
        # the mandatory live delivery gate establishes actual Kafka delivery.
        for packet in engine.pending_packets():engine.mark_published(packet["id"])
        capture={"dss":engine.evidence(state["scenario_id"]),"driver":[{**row,"packet":row["packet"].hex()} for row in packets],
            "worker":executor.worker_capture,"reference_mappings":[],"reference_reads":[],"execution_spec":spec,"elapsed_seconds":time.monotonic()-started}
        result={"subject":subject,"binding":subject_binding(subject),"semantic":actual,"dss_evidence":{
            "mode":"ACTUAL_DSS_DRIVER","scenario_id":state["scenario_id"],"epoch":state["epoch"],"capture":capture,"capture_sha256":digest(capture)}}
        validate_subject_capture(result)
        assert actual==registry._expected_result(case)
        from copy import deepcopy
        for mutation in ("full-map", "cursor", "completion"):
            forged=deepcopy(result)
            raw=forged["dss_evidence"]["capture"]
            commit=next(row for row in raw["worker"]["events"] if row["kind"]=="step_commit")
            if mutation=="full-map":commit["variables"]["forged_dependency"]=True
            elif mutation=="cursor":commit["step_index"]+=1
            else:commit["effects"][-1]["payload"]["skipped"]=not commit["effects"][-1]["payload"]["skipped"]
            forged["dss_evidence"]["capture_sha256"]=digest(raw)
            with pytest.raises(ValueError):validate_subject_capture(forged)
        events=[]
        committed={}
        for event in executor.worker_capture["events"]:
            if event["kind"]=="telecommand_requested":
                service=next(row for row in executor.worker_capture["service_results"]
                    if row["kind"]=="telecommand" and row["step"]["index"]==event["step_index"])
                events.extend([{"event_type":"procedure.telecommand_requested","payload":service["request"]},
                    {"event_type":"procedure.telecommand_result","payload":service["result"]}])
            elif event["kind"]=="step_commit":
                events.extend(event["effects"])
                committed=event["variables"]
        outer={**capture,"procedure":{"source":case["source"]},"events":events,
            "execution":{"id":state["scenario_id"],"procedure_id":case_id,"state":actual["terminal"],"variables":committed},
            "typed_prompts":[{"step_index":row["step_index"],"settlement":{"outcome":row["settlement"]["outcome"],
                "value":row["settlement"].get("response")}} for row in executor.worker_capture["prompt_settlements"]]}
        validate_outer_source_execution(outer)
        ambient=deepcopy(outer)
        ambient["execution"]["variables"]["ARGS"]={}
        validate_outer_source_execution(ambient)
        for invalid_args in ({"command":"forged"},[],None,False):
            ambient["execution"]["variables"]["ARGS"]=invalid_args
            with pytest.raises(ValueError,match="framework ARGS"):
                validate_outer_source_execution(ambient)
        from copy import deepcopy
        forged=deepcopy(outer)
        forged["execution"]["variables"]["uncommitted"]=True
        with pytest.raises(ValueError,match="variable map"):
            validate_outer_source_execution(forged)
        if any(row["event_type"]=="procedure.telecommand_requested" for row in events):
            forged=deepcopy(outer)
            request=next(row["payload"] for row in forged["events"] if row["event_type"]=="procedure.telecommand_requested")
            request["operation_id"]="swapped-operation"
            with pytest.raises(ValueError):validate_outer_source_execution(forged)
    finally:database.dispose()


@pytest.mark.parametrize("mutation",["guard-value","source-cursor","next-cursor","generation"])
def test_parent_rejects_forged_checkpoint_before_any_driver_request(mutation,monkeypatch):
    """Inject the untrusted worker reply at the real parent dispatch boundary."""
    from backend.procedure_parser import ProcedureCatalog
    case=dict(next(row for row in registry.CASES if row["id"]=="v18-native-no-no-dispatch"))
    case["source"]="gate: bool = False\nPrompt('Continue')\nif gate:\n    Send(command='CMDNAME', PromptUser=False)\n"
    procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"])
    step=procedure.steps[0]
    message={"kind":"step_commit","generation":1,"step_index":0,"next_step":1,
        "variables":{"gate":False},"prompt_resolution":None,"effects":[{
            "event_type":"step.completed","source":"worker","severity":"info","payload":{
                "step_index":0,"line":step["line"],"step_type":"variable_set","skipped":False}}]}
    if mutation=="guard-value":message["variables"]["gate"]=True
    elif mutation=="source-cursor":message["step_index"]=1
    elif mutation=="next-cursor":message["next_step"]=2
    else:message["generation"]=True
    replies=SimpleNamespace(get=lambda **_:message,close=lambda:None)
    control=SimpleNamespace(put=lambda _:None,close=lambda:None)
    queues=iter((control,replies))
    process=SimpleNamespace(start=lambda:None,is_alive=lambda:False,join=lambda **_:None,exitcode=0)
    context=SimpleNamespace(Queue=lambda:next(queues),Process=lambda **_:process)
    monkeypatch.setattr("backend.dss_language_executor.multiprocessing.get_context",lambda _:context)
    calls=[]
    executor=DssLanguageExecutor.__new__(DssLanguageExecutor)
    executor.runtime=SimpleNamespace(provider=lambda *args,**kwargs:calls.append((args,kwargs)))
    executor.context_id="simulator"
    executor.authorize=lambda:True
    monkeypatch.setattr(executor,"_observation_runtime",lambda:None)
    with pytest.raises(ValueError,match="authoritative source|contiguous"):
        executor._source_case(case,{"scenario_id":str(uuid.uuid4())})
    assert calls==[]


@pytest.mark.parametrize("fault",["transport_rejection","execution_failure","lost_release_ack","release_ack_timeout"])
def test_command_fault_oracle_binds_real_tcp_outcomes_and_effects(fault,runtime,engine):
    from copy import deepcopy
    from backend.procedure_parser import ProcedureCatalog
    from backend.telecommand_runtime_v11 import prepare_send_request,execute_preflight,uncertain_replay_result
    from backend.dss_runtime import DssRuntimeError
    from scripts.qualify_dss_v19 import scenario_definitions
    from scripts.validate_dss_delivery import _observed_command_fault,_validate_stage_receipts,validate_transport_capture
    definition=next(row for row in scenario_definitions() if row["id"]=="command-"+fault)
    spec=definition["inputs"]["execution_spec"]
    state=engine.reset(str(uuid.uuid4()),initial_state=spec["initial_state"],faults=spec["faults"],expected_epoch=engine.state()["epoch"])
    source="Send(command='CMDNAME', PromptUser=False)"
    procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source(source)
    request,service,preflight=prepare_send_request("fault-execution",0,procedure.steps[0],{})
    provider=runtime.provider(request,preflight,procedure_id="fault-procedure",context_id="simulator")
    started=time.monotonic()
    try:
        result=execute_preflight(request,service,preflight,provider=provider)
    except (DssRuntimeError,ValueError):
        assert fault in {"lost_release_ack","release_ack_timeout"}
        result=uncertain_replay_result(request,service,preflight)
    evidence=engine.evidence(state["scenario_id"])
    packets=[packet for row in evidence["packets"] for packet in runtime.await_packet(state["epoch"],row["packet_sha256"])]
    # Controlled-ingest fixture; the release gate independently requires actual Kafka.
    for packet in engine.pending_packets():engine.mark_published(packet["id"])
    capture={"dss":engine.evidence(state["scenario_id"]),"driver":[{**row,"packet":row["packet"].hex()} for row in packets],
        "procedure":{"source":source},"execution":{"id":"fault-execution","procedure_id":"fault-procedure","variables":{},"state":"failed"},
        "typed_prompts":[],
        "events":[{"event_type":"procedure.telecommand_requested","payload":request},
            {"event_type":"procedure.telecommand_result","payload":result}],"elapsed_seconds":time.monotonic()-started}
    counts=validate_transport_capture(capture,scenario_id=state["scenario_id"],epoch=state["epoch"])
    assert counts["executed_commands"]==definition["expected"]["outer_executed_commands"]
    actual,results,unreceived=_observed_command_fault(capture,definition)
    assert actual==definition["expected"]["command_fault"]
    _validate_stage_receipts(capture,results,[],unreceived_operations=unreceived)
    validate_outer_source_execution(capture)
    for tamper in ("resend","missing-stage","disposition"):
        changed=deepcopy(capture)
        if tamper=="resend":changed["dss"]["operations"][0]["ingress_delivery_count"]=2
        elif tamper=="missing-stage":changed["dss"]["operations"].pop()
        else:changed["events"][1]["payload"]["checkpoint"]["elements"][0]["disposition"]="VERIFIED"
        with pytest.raises(ValueError):_observed_command_fault(changed,definition)
