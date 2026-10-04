from copy import deepcopy

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker

from backend import language_conformance_v19 as registry
from backend.dss_language_broker import (request_for_selection, validate_request, selected_subjects,
    subject_binding, result_for_request, validate_result, digest, worker_effects)
from backend.dss_language_ledger import LanguageLedger, DssLanguageUncertain
from backend.migrations.versions.v0011_dss_language_ledger import metadata, language_cases
from backend.procedure_parser import ProcedureCatalog
from backend.tests.test_worker_v06 import _start_worker, _next


def _result():
    case = registry.CASES[0]
    subject = "case:" + case["id"]
    return {"subject":subject, "binding":subject_binding(subject), "semantic":deepcopy(registry._expected_result(case)),
        "dss_evidence":{"mode":"ACTUAL_DSS_DRIVER", "scenario_id":"unit-scenario", "epoch":"unit-epoch",
                        "capture_sha256":"a" * 64}}


def test_closed_request_has_exact_all_selection_identities():
    request = request_for_selection("outer", 4, registry.ALL_SELECTION)
    subjects = selected_subjects(request)
    assert len(subjects) == 343 and len(set(subjects)) == 343
    assert subjects[:148] == tuple("case:" + row["id"] for row in registry.CASES)
    assert subjects[-195:] == tuple(f"adaptation:{number:03}" for number in range(1,196))


@pytest.mark.parametrize("field,value", [("selection",True), ("step_index",False), ("profile","0.18"),
    ("cases_sha256","0"*64), ("execution_id","other"), ("request_id","other"), ("source","Send('CMDNAME')")])
def test_request_rejects_changed_selection_profile_source_or_identity(field, value):
    request = request_for_selection("outer", 4, 195)
    request[field] = value
    with pytest.raises(ValueError):
        validate_request(request, execution_id="outer", step_index=4, selection=195)


@pytest.mark.parametrize("selection", [True, -1, registry.ALL_SELECTION + 1, "195"])
def test_selection_bounds_are_strict(selection):
    with pytest.raises(ValueError): request_for_selection("outer", 4, selection)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "changed-value", "changed-source", "helper-only", "digest"])
def test_result_rejects_omission_substitution_and_isolated_helper_claims(mutation):
    request = request_for_selection("outer", 4, 195)
    report = result_for_request(request, [_result()])
    if mutation == "missing": report["results"] = []
    elif mutation == "duplicate": report["results"] *= 2
    elif mutation == "changed-value": report["results"][0]["semantic"]["variables"]["count"] = 13
    elif mutation == "changed-source": report["results"][0]["binding"]["source_sha256"] = "0"*64
    elif mutation == "helper-only": report["results"][0]["dss_evidence"]["mode"] = "ISOLATED_PRODUCTION_HELPERS_NO_OUTER_DISPATCH"
    else: report["result_sha256"] = "0"*64
    with pytest.raises(ValueError): validate_result(request, report)


def test_ledger_preserves_unresolved_intent_across_new_owner_without_redispatch(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "ledger.sqlite"))
    metadata.create_all(engine)
    factory = sessionmaker(engine)
    request = request_for_selection("outer", 4, 195)
    subject = _result()["subject"]
    try:
        first = LanguageLedger(factory)
        assert first.reserve(request, subject) is None
        with pytest.raises(DssLanguageUncertain, match="automatic replay is forbidden"):
            LanguageLedger(factory).reserve(request, subject)
        first.settle(request, subject, _result())
        assert LanguageLedger(factory).reserve(request, subject) == _result()
        with factory.begin() as session:
            session.execute(update(language_cases).values(result_hash="0"*64))
        with pytest.raises(ValueError, match="digest differs"):
            LanguageLedger(factory).reserve(request, subject)
    finally:
        engine.dispose()


def test_run_all_error_preserves_inner_case_identity(monkeypatch):
    def failure(_selection):
        raise ValueError("v19-condition-wait-command: observed outcome differs")
    monkeypatch.setattr(registry, "execute_selection", failure)
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(
        'result: str = ""\nLanguageCheck(343, profile="0.19", target=result)\n')
    thread, _, output = _start_worker(monkeypatch, procedure)
    terminal, messages = _next(output, lambda row:row.get("kind") == "terminal")
    thread.join(timeout=1)
    assert not thread.is_alive() and terminal["state"] == "failed"
    errors = [row["payload"]["error"] for row in messages if row.get("event_type") == "procedure.error"]
    assert len(errors) == 1 and "v19-condition-wait-command" in errors[0]


def test_raw_capture_stays_in_durable_ledger_and_compact_worker_result_binds_it():
    result=_result()
    result["dss_evidence"]["capture"]={"large_raw_packet_archive":"x"*10000}
    result["dss_evidence"]["capture_sha256"]=digest(result["dss_evidence"]["capture"])
    request=request_for_selection("outer",4,195)
    report=result_for_request(request,[result])
    assert "capture" not in report["results"][0]["dss_evidence"]
    assert report["results"][0]["dss_evidence"]["capture_sha256"]==result["dss_evidence"]["capture_sha256"]
    assert "capture" in result["dss_evidence"]
    result["dss_evidence"]["capture"]["large_raw_packet_archive"]="changed"
    with pytest.raises(ValueError,match="capture digest"):
        result_for_request(request,[result])


@pytest.mark.parametrize("tamper",[None,"missing-settlement","variables","effect","other-request"])
def test_supervisor_language_checkpoint_requires_exact_durable_cases_and_full_map(tmp_path,tamper):
    from types import SimpleNamespace
    from backend.dss_language_supervisor import validate_checkpoint
    engine=create_engine("sqlite:///"+str(tmp_path/"check.sqlite"))
    metadata.create_all(engine)
    factory=sessionmaker(engine)
    procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source('result: str = ""\nLanguageCheck(195, profile="0.19", target=result)\n')
    step=procedure.steps[-1]
    request=request_for_selection("outer",step["index"],195)
    prior={"result":"", "unrelated":7}
    execution=SimpleNamespace(id="outer",ir_version="0.19",current_step=step["index"],steps=list(procedure.steps),variables=prior)
    supervisor=SimpleNamespace(dss_runtime=object())
    ledger=LanguageLedger(factory)
    ledger.reserve(request,_result()["subject"])
    if tamper!="missing-settlement":ledger.settle(request,_result()["subject"],_result())
    report=result_for_request(request,[_result()])
    summary,effects=worker_effects(request,report)
    message={"step_index":step["index"],"variables":{**prior,"result":summary},"effects":[*effects,
        {"event_type":"step.completed","source":"worker","severity":"info","payload":{
            "step_index":step["index"],"line":step["line"],"step_type":"language_check","skipped":False}}]}
    if tamper=="variables":message["variables"]["unrelated"]=8
    if tamper=="effect":message["effects"][0]["payload"]["dss_result_sha256"]="0"*64
    if tamper=="other-request":execution.id="other"
    try:
        with factory() as session:
            if tamper is None:validate_checkpoint(supervisor,session,execution,message,prior)
            else:
                with pytest.raises(ValueError):validate_checkpoint(supervisor,session,execution,message,prior)
    finally:engine.dispose()


@pytest.mark.parametrize("mode",["result","pause-result-resume","abort","failed-inner-case"])
def test_dss_worker_closed_response_control_and_inner_failure_identity(monkeypatch,mode):
    import queue,threading
    import backend.worker as worker
    procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source('result: str = ""\nLanguageCheck(195, profile="0.19", target=result)\n')
    control,output=queue.Queue(),queue.Queue()
    monkeypatch.setattr(worker,"_replace_worker_environment",lambda:None)
    thread=threading.Thread(target=worker.worker_main,args=("outer",1,procedure.ir_version,list(procedure.steps),0,
        "start",None,{},control,output,None,None,False,True),daemon=True)
    thread.start()
    try:
        message,_=_next(output,lambda row:row.get("kind")=="language_case_requested")
        request={key:value for key,value in message.items() if key not in {"kind","generation"}}
        assert request==request_for_selection("outer",procedure.steps[-1]["index"],195)
        if mode=="abort":control.put({"type":"abort","command_id":"abort-once"})
        elif mode=="failed-inner-case":control.put({"type":"language_case_result","request_id":request["request_id"],
            "outcome":"FAILED","error":"case:v19-condition-wait-command: actual mismatch"})
        else:
            if mode=="pause-result-resume":
                control.put({"type":"pause","command_id":"pause-once"})
                _next(output,lambda row:row.get("kind")=="state" and row.get("state")=="paused")
            else:
                control.put({"type":"language_case_result","request_id":"forged","outcome":"SETTLED","result":{}})
                _next(output,lambda row:row.get("kind")=="command_rejected")
            control.put({"type":"language_case_result","request_id":request["request_id"],"outcome":"SETTLED",
                "result":result_for_request(request,[_result()])})
            if mode=="pause-result-resume":control.put({"type":"resume","command_id":"resume-once"})
        terminal,messages=_next(output,lambda row:row.get("kind")=="terminal")
        assert terminal["state"]==("aborted" if mode=="abort" else "failed" if mode=="failed-inner-case" else "completed")
        if mode=="failed-inner-case":
            assert any("v19-condition-wait-command" in row.get("payload",{}).get("error","") for row in messages)
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        if thread.is_alive():control.put({"type":"stop"});thread.join(timeout=1)
