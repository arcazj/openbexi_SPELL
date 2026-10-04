"""Full-selection validation stays bounded without trusting compact worker proof."""
from copy import deepcopy
from datetime import datetime,timezone
import json
from types import SimpleNamespace
import weakref

import pytest
from sqlalchemy import create_engine,delete,event,select,update
from sqlalchemy.orm import sessionmaker

from backend import language_conformance_v19 as registry
from backend import dss_language_broker as broker
from backend.dss_language_supervisor import validate_checkpoint
from backend.migrations.versions.v0011_dss_language_ledger import metadata,language_cases
from backend.procedure_parser import ProcedureCatalog
from backend.reference_examples_v10 import ReferenceExampleRegistry,ReferenceContractError,default_contract_path


@pytest.fixture(scope="module")
def closed_results():
    """Synthetic ledger payloads test validation, not actual DSS transport evidence."""
    request=broker.request_for_selection("outer",1,registry.ALL_SELECTION)
    references=ReferenceExampleRegistry.from_contract()
    rows=[]
    with broker.validation_operation():
        for subject in broker.selected_subjects(request):
            semantic=(registry._expected_result(next(case for case in registry.CASES if subject=="case:"+case["id"]))
                if subject.startswith("case:") else references.execute(int(subject[11:])).as_dict())
            raw={"subject":subject,"padding":"x"*8192}
            rows.append({"subject":subject,"binding":broker.subject_binding(subject),"semantic":semantic,
                "dss_evidence":{"mode":"ACTUAL_DSS_DRIVER","scenario_id":"unit-"+subject,"epoch":"unit-epoch",
                    "capture":raw,"capture_sha256":broker.digest(raw)}})
    return rows


@pytest.fixture
def ledger(closed_results):
    live={"count":0,"peak":0}
    class TrackedCapture(dict):
        pass
    def decode(value):
        result=json.loads(value)
        if type(result) is dict and set(result)=={"subject","binding","semantic","dss_evidence"}:
            capture=TrackedCapture(result["dss_evidence"]["capture"])
            result["dss_evidence"]["capture"]=capture
            live["count"]+=1
            live["peak"]=max(live["peak"],live["count"])
            weakref.finalize(capture,lambda:live.__setitem__("count",live["count"]-1))
        return result
    database=create_engine("sqlite://",json_deserializer=decode)
    metadata.create_all(database)
    factory=sessionmaker(database)
    procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source('result: str = ""\nLanguageCheck(343, profile="0.19", target=result)\n')
    step=procedure.steps[-1]
    request=broker.request_for_selection("outer",step["index"],registry.ALL_SELECTION)
    values={"result":"","unrelated":7}
    execution=SimpleNamespace(id="outer",ir_version="0.19",current_step=step["index"],steps=list(procedure.steps),variables=values)
    with factory.begin() as session:
        session.execute(language_cases.insert(),[{"request_id":request["request_id"],"subject":row["subject"],
            "execution_id":"outer","request_hash":broker.digest(request),"request":request,
            "binding_hash":broker.digest(row["binding"]),"state":"SETTLED","result":row,
            "result_hash":broker.digest(row),"created_at":datetime.now(timezone.utc)} for row in closed_results])
    summary,effects=broker.worker_effects(request,broker.result_for_request(request,closed_results))
    message={"step_index":step["index"],"variables":{**values,"result":summary},"effects":[*effects,
        {"event_type":"step.completed","source":"worker","severity":"info","payload":{
            "step_index":step["index"],"line":step["line"],"step_type":"language_check","skipped":False}}]}
    try:yield database,factory,execution,request,message,live
    finally:database.dispose()


def test_all343_checkpoint_loads_one_registry_and_at_most_four_raw_results(ledger,monkeypatch):
    database,factory,execution,request,message,live=ledger
    loads=[]
    original=ReferenceExampleRegistry.from_contract.__func__
    def load(cls,*args,**kwargs):
        loads.append(1)
        return original(cls,*args,**kwargs)
    monkeypatch.setattr(ReferenceExampleRegistry,"from_contract",classmethod(load))
    queries=[]
    def query(_connection,_cursor,statement,parameters,_context,_many):
        if "FROM dss_language_cases" in statement:queries.append((statement,parameters))
    event.listen(database,"before_cursor_execute",query)
    with factory() as session:
        validate_checkpoint(SimpleNamespace(dss_runtime=object()),session,execution,message,execution.variables)
    assert len(loads)==1
    assert len(queries)==1+(343+3)//4
    assert "LIMIT" in queries[0][0] and 344 in queries[0][1]
    assert all(len(parameters)<=5 for _,parameters in queries)
    assert live["peak"]<=4 and live["count"]==0
    assert broker._VALIDATION_SCOPE.get() is None


@pytest.mark.parametrize("mutation",["missing","extra","state","rehashed-source","rehashed-oracle",
    "rehashed-capture","rehashed-request","full-variables","effects"])
def test_full_selection_rejects_late_durable_or_rehashed_worker_tampering(ledger,mutation):
    _,factory,execution,request,message,_=ledger
    subject="adaptation:195"
    with factory.begin() as session:
        row=session.execute(select(language_cases).where(language_cases.c.subject==subject)).mappings().one()
        if mutation=="missing":session.execute(delete(language_cases).where(language_cases.c.subject==subject))
        elif mutation=="extra":
            extra=dict(row)
            extra["subject"]="adaptation:196"
            session.execute(language_cases.insert().values(**extra))
        elif mutation=="state":session.execute(update(language_cases).where(language_cases.c.subject==subject).values(state="DISPATCHING"))
        elif mutation=="rehashed-request":
            changed=deepcopy(row["request"])
            changed["selection"]=194
            session.execute(update(language_cases).where(language_cases.c.subject==subject).values(request=changed,request_hash=broker.digest(changed)))
        elif mutation.startswith("rehashed-"):
            changed=deepcopy(dict(row["result"]))
            update_values={}
            if mutation=="rehashed-source":
                changed["binding"]["source_sha256"]="0"*64
                update_values["binding_hash"]=broker.digest(changed["binding"])
            elif mutation=="rehashed-oracle":changed["semantic"]["variant_proofs"][0]["status"]="FAIL"
            else:changed["dss_evidence"]["capture"]["padding"]="changed"
            session.execute(update(language_cases).where(language_cases.c.subject==subject).values(
                result=changed,result_hash=broker.digest(changed),**update_values))
        elif mutation=="full-variables":message["variables"]["unrelated"]=8
        else:message["effects"][-1]["payload"]["skipped"]=True
    with factory() as session,pytest.raises(ValueError):
        validate_checkpoint(SimpleNamespace(dss_runtime=object()),session,execution,message,execution.variables)
    assert broker._VALIDATION_SCOPE.get() is None


def test_registry_scope_reloads_after_success_exception_and_contract_tamper(tmp_path,monkeypatch):
    original=ReferenceExampleRegistry.from_contract.__func__
    paths=[]
    path=[None]
    def load(cls):
        paths.append(path[0])
        return original(cls,path[0])
    monkeypatch.setattr(ReferenceExampleRegistry,"from_contract",classmethod(load))
    with pytest.raises(RuntimeError,match="primary"):
        with broker.validation_operation():
            broker.subject_binding("adaptation:001")
            with broker.validation_operation():broker.subject_binding("adaptation:195")
            raise RuntimeError("primary")
    assert len(paths)==1 and broker._VALIDATION_SCOPE.get() is None
    broker.subject_binding("adaptation:195")
    assert len(paths)==2 and broker._VALIDATION_SCOPE.get() is None
    changed=tmp_path/"changed.json"
    changed.write_bytes(default_contract_path().read_bytes()+b" ")
    path[0]=changed
    with pytest.raises(ReferenceContractError):broker.subject_binding("adaptation:195")
    assert len(paths)==3 and broker._VALIDATION_SCOPE.get() is None
