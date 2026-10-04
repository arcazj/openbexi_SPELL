from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from backend.dss_capture import collect_evidence
from backend.tests.test_dss_engine_v19 import send
from dss.engine import DssEngine
from dss.packets import decode_tm
from scripts.qualify_dss_v19 import build_manifest, scenario_definitions
from scripts.validate_dss_delivery import canonical, load_manifest, sha256, source_inventory, validate_report, validate_transport_capture, reproduction_metadata, delivery_counts


def _write_sidecar(directory, value):
    data = canonical(value)
    identity = sha256(data)
    (directory / (identity + ".json")).write_bytes(data)
    return identity, {"path": identity + ".json", "size": len(data)}


def test_capture_store_streams_343_archives_with_at_most_two_decoded_payloads(tmp_path, monkeypatch):
    import weakref
    from scripts import validate_dss_delivery as module
    references = dict(_write_sidecar(tmp_path, {"index": index, "payload": ["x" * 16384]})
                      for index in range(343))
    decoded = []
    original = module.json.loads

    class Payload(list):
        pass

    def tracked(data):
        value = original(data)
        value["payload"] = Payload(value["payload"])
        decoded.append(weakref.ref(value["payload"]))
        assert sum(reference() is not None for reference in decoded) <= 2
        return value

    monkeypatch.setattr(module.json, "loads", tracked)
    captures = module.CaptureStore(tmp_path, references)
    for index, identity in enumerate(captures):
        assert captures[identity]["index"] == index
        assert len(captures._cache) <= 2
    assert len(decoded) == 343
    last = next(reversed(references))
    assert captures[last]["index"] == 342
    assert len(decoded) == 343  # A hash-checked cache hit avoids reparsing.
    del captures
    assert not any(reference() is not None for reference in decoded)


@pytest.mark.parametrize("cached", [False, True])
def test_capture_store_rejects_same_size_late_mutation_after_initial_audit(tmp_path, cached):
    import os
    from scripts.validate_dss_delivery import CaptureStore
    references = dict(_write_sidecar(tmp_path, {"index": index, "payload": "original"}) for index in range(4))
    captures = CaptureStore(tmp_path, references)
    for identity in captures:
        assert captures[identity]["payload"] == "original"
    identity = list(references)[-1 if cached else 0]
    path = tmp_path / references[identity]["path"]
    before = path.stat()
    data = path.read_bytes().replace(b"original", b"mutated!")
    assert len(data) == before.st_size
    path.write_bytes(data)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError, match="file digest differs"):
        captures[identity]


def test_capture_store_rejects_hash_bound_noncanonical_sidecar(tmp_path):
    from scripts.validate_dss_delivery import CaptureStore
    data = b'{ "value": 1 }'
    identity = sha256(data)
    (tmp_path / (identity + ".json")).write_bytes(data)
    captures = CaptureStore(tmp_path, {identity: {"path": identity + ".json", "size": len(data)}})
    with pytest.raises(ValueError, match="raw capture digest differs"):
        captures[identity]


@pytest.mark.parametrize("bound", ["individual", "total"])
def test_capture_store_preserves_existing_byte_bounds(tmp_path, bound):
    from scripts.validate_dss_delivery import CaptureStore
    count, size = (1, 16_000_001) if bound == "individual" else (33, 16_000_000)
    references = {f"{index:064x}": {"path": f"{index:064x}.json", "size": size} for index in range(count)}
    with pytest.raises(ValueError, match="reference is malformed|total capture size exceeds"):
        CaptureStore(tmp_path, references)


def test_producer_reloads_exact_persisted_runall_without_retaining_raw_children(tmp_path, monkeypatch):
    """Exercise producer closeout only; this fixture does not claim a live DSS run."""
    import json
    import weakref
    from backend import language_conformance_v19 as registry
    from scripts import qualify_dss_v19 as producer
    from scripts import validate_dss_delivery as validator
    definition = next(row for row in scenario_definitions() if row["id"] == "catalog-reference-all")
    source = (producer.ROOT / definition["subject"].removeprefix("procedure:")).read_bytes()
    spec = definition["inputs"]["execution_spec"]
    outer = {"execution": {"id": "retained-runall", "state": "completed",
        "variables": deepcopy(definition["expected"]["variables"]), "procedure_hash": sha256(source)},
        "procedure": {"source": source.decode()}, "actions": definition["operator_actions"],
        "execution_spec": spec, "initial_dss_state": deepcopy(spec["initial_state"]), "elapsed_seconds": 1.0,
        "typed_prompts": [{"type": "LIST", "settlement": {"outcome": "ANSWERED", "value": 343}}],
        "operator_audit": [], "broker_result": {},
        "events": [{"execution_id": "retained-runall", "sequence": 1, "event_type": "procedure.log",
                    "payload": {"message": definition["expected"]["logs"][0]}}]}
    observed = validator.observed_procedure(outer, definition)
    assert observed == definition["expected"]
    raw_children = []
    serialized = []

    class RawChild(dict):
        pass

    class CloseoutQualifier(producer.DeliveryQualifier):
        def assert_normal_finish(self, capture):
            pass  # This isolated test exercises Run-all payload lifetime only.

        def run_procedure(self, *args, **kwargs):
            child = RawChild(subject="test-only-child", raw_payload="x" * 100000)
            raw_children.append(weakref.ref(child))
            return {**outer, "subject_results": [child]}

        def evidence(self, capture, **kwargs):
            # A second serialization would feed compact children through the
            # full-result serializer. Closeout must reuse the saved descriptor.
            assert not serialized and "raw_payload" in capture["subject_results"][0]
            stored = {**capture, "subject_results": [{"subject": "test-only-child"}],
                      "subject_capture_refs": {"test-only-child": "a" * 64}}
            identity = self.store_capture(stored)
            descriptor = {"raw_capture_sha256": identity}
            serialized.append(descriptor)
            return descriptor

    qualifier = CloseoutQualifier.__new__(CloseoutQualifier)
    qualifier.output = tmp_path / "report.json"
    qualifier.capture_root = tmp_path / "captures"
    qualifier.capture_root.mkdir()
    qualifier.captures, qualifier.results, qualifier.scenarios = {}, {}, []
    qualifier.bindings = {"source_commit": "b" * 40, "image_ids": {}}
    qualifier.definitions = {"menu:000": {"definition_sha256": "c" * 64, "targets": ["test-only-child"]},
        definition["subject"]: {"definition_sha256": "d" * 64}}
    qualifier.manifest = {"scenarios": [definition], "inventory": [], "inventory_sha256": "e" * 64}
    from types import SimpleNamespace
    qualifier.dss = SimpleNamespace(call=lambda _: {"transport": {
        "automatic_interval_ns": 1_000_000_000, "physics_ticks_per_frame": 10}})
    monkeypatch.setattr(registry, "ALL_SELECTION", 0)
    original_store = validator.CaptureStore

    def released_store(*args, **kwargs):
        assert not any(reference() is not None for reference in raw_children)
        return original_store(*args, **kwargs)

    def final_validation(report, **kwargs):
        assert not any(reference() is not None for reference in raw_children)
        assert report["scenarios"][0]["evidence"] is serialized[0]
        stored = original_store(qualifier.capture_root, qualifier.captures)[serialized[0]["raw_capture_sha256"]]
        assert validator.observed_procedure(stored, definition) == observed

    monkeypatch.setattr(validator, "CaptureStore", released_store)
    monkeypatch.setattr(validator, "validate_report", final_validation)
    qualifier.run()
    assert json.loads(qualifier.output.read_bytes())["scenarios"][0]["observed"] == observed
    assert len(serialized) == 1


def test_exhaustive_inventory_and_scenarios_bind_every_source_and_menu():
    inventory=source_inventory()
    kinds={kind:sum(row["kind"]==kind for row in inventory) for kind in {row["kind"] for row in inventory}}
    assert kinds=={"PROCEDURE":10,"LANGUAGE_CASE":148,"REFERENCE_ADAPTATION":195,"REFERENCE_VARIANT":257,"MENU_SELECTION":344}
    assert len({row["id"] for row in inventory})==954
    assert load_manifest()==build_manifest()
    assert sum(row.get("execution_kind")=="EXPECTED_REJECTION" for row in inventory)==36
    assert {row["id"] for row in inventory if row["kind"]=="PROCEDURE"}<={row["subject"] for row in scenario_definitions()}


def test_final_normal_scenario_preserves_all_30_definitions_and_required_faults():
    scenarios = scenario_definitions()
    assert len(scenarios) == len({row["id"] for row in scenarios}) == 30
    assert scenarios[-1]["id"] == "core-tutorial"
    assert scenarios[-1]["inputs"]["execution_spec"]["faults"] == {}
    assert scenarios[-1]["expected"]["terminal"] == "completed"
    assert {row["id"] for row in scenarios if row["inputs"]["execution_spec"]["faults"]} == {
        "observation-rejects-" + fault for fault in ("missing", "stale", "invalid", "bad-quality", "gap", "policy")
    } | {"command-" + fault for fault in (
        "transport_rejection", "execution_failure", "lost_release_ack", "release_ack_timeout")}
    for row in scenarios:
        assert row["definition_sha256"] == sha256(canonical({
            key:value for key,value in row.items() if key != "definition_sha256"}))


@pytest.mark.parametrize("mutation", ["swap-first-pair", "move-normal-first"])
def test_report_rejects_reordered_scenarios_before_accepting_any_execution_claim(tmp_path, mutation):
    """A metadata-only report must never pass; isolate the ordering rejection."""
    from dss import SIMULATOR_VERSION, DYNAMICS_ENGINE_VERSION
    from dss.catalog import SatelliteDatabase
    database = SatelliteDatabase.load()
    manifest = load_manifest()
    images = {name:"sha256:" + "a" * 64 for name in ("backend", "driver", "dss", "kafka", "frontend", "proxy")}
    report = {"schema_version":"spell.dss.delivery/1", "release":"v0.19.0", "source_commit":"b" * 40,
        "image_ids":images, "database_identity":{"satellite_id":"GENERIC", "revision":database.revision,
            "sha256":database.digest, "simulator_version":SIMULATOR_VERSION, "dynamics_engine_version":DYNAMICS_ENGINE_VERSION},
        "decision":"PASS", "full_language_compatibility":False, "inventory_sha256":manifest["inventory_sha256"],
        "results":[], "scenarios":[{"id":row["id"]} for row in manifest["scenarios"]], "raw_captures":{},
        "reproduction":reproduction_metadata("v0.19.0"), "counts":{}}
    with pytest.raises(ValueError, match="raw DSS captures are missing"):
        validate_report(report, source_commit="b" * 40, image_ids=images, capture_root=tmp_path)
    if mutation == "swap-first-pair":
        report["scenarios"][0], report["scenarios"][1] = report["scenarios"][1], report["scenarios"][0]
    else:
        report["scenarios"].insert(0, report["scenarios"].pop())
    assert {row["id"] for row in report["scenarios"]} == {row["id"] for row in manifest["scenarios"]}
    with pytest.raises(ValueError, match="scenario order differs"):
        validate_report(report, source_commit="b" * 40, image_ids=images, capture_root=tmp_path)


@pytest.mark.parametrize("mutation", [None, "running", "epoch", "revision", "faults", "retirement",
    "evidence-state", "missing-faults", "counts", "late-state", "wrong-scenario-order"])
def test_final_finish_reads_actual_paused_fault_free_state_without_controls(tmp_path, mutation):
    from types import SimpleNamespace
    from scripts.qualify_dss_v19 import DeliveryQualifier
    engine = DssEngine(tmp_path / "finish.sqlite")
    try:
        engine.reset("normal-finish")
        capture = {"dss":engine.evidence("normal-finish")}
        qualifier = DeliveryQualifier.__new__(DeliveryQualifier)
        qualifier.manifest = {"scenarios":[{"id":"core-tutorial"}]}
        qualifier.scenarios = [{"id":"core-tutorial"}]
        calls = []

        def read(path):
            calls.append(path)
            if path == "/state":
                value = {**engine.state(), "transport":{"diagnostic":"not physical state"}}
                if mutation == "running": value["running"] = True
                elif mutation == "epoch": value["epoch"] = "another-epoch"
                elif mutation == "revision": value["revision"] += 1
                elif mutation == "late-state" and len(calls) == 3: value["running"] = True
                return value
            parsed = urlsplit(path)
            assert parsed.path == "/evidence"
            assert parse_qs(parsed.query) == {"scenario_id":["normal-finish"], "offset":["0"], "limit":["1"]}
            value = engine.evidence_page("normal-finish", limit=1)
            if mutation == "faults": value["faults"] = {"command_delay_ms":5000}
            elif mutation == "retirement": value["retirement"] = {"reason":"retired"}
            elif mutation == "evidence-state": value["final_state"]["revision"] += 1
            elif mutation == "missing-faults": del value["faults"]
            elif mutation == "counts": value["pagination"]["counts"]["packets"] += 1
            return value

        qualifier.dss = SimpleNamespace(call=read)
        if mutation == "wrong-scenario-order": qualifier.scenarios[-1]["id"] = "command-release_ack_timeout"
        if mutation is None:
            qualifier.assert_normal_finish(capture)
            assert len(calls) == 3
        else:
            with pytest.raises(ValueError, match="DSS (delivery|actual final)"):
                qualifier.assert_normal_finish(capture)
        assert len(calls) <= 3
        assert engine.evidence("normal-finish") == capture["dss"]
    finally:
        engine.close()


@pytest.mark.parametrize("failure", [None, "execution", "capture", "oracle", "validation", "finish"])
def test_scenario_failure_stops_before_normal_finish_and_preserves_prior_capture(tmp_path, monkeypatch, failure):
    """Test orchestration only; mocked source outcomes never count as live proof."""
    import json
    from types import SimpleNamespace
    from backend import language_conformance_v19 as registry
    from scripts import qualify_dss_v19 as producer
    from scripts import validate_dss_delivery as validator
    definitions = {row["id"]:row for row in scenario_definitions()}
    fault, normal = definitions["command-release_ack_timeout"], definitions["core-tutorial"]
    calls = []
    engine = DssEngine(tmp_path / "orchestration.sqlite")

    class Qualifier(producer.DeliveryQualifier):
        def run_procedure(self, identity, procedure, actions, inputs):
            calls.append(("execute", identity))
            if failure == "execution": raise ValueError("execution failed")
            # A local engine gives this orchestration test actual retained fault
            # records and state, without claiming network or procedure execution.
            engine.reset(identity, faults=inputs["execution_spec"]["faults"])
            return {"dss":engine.evidence(identity),
                    "execution":{"procedure_hash":"a" * 64, "id":identity}}

        def evidence(self, capture):
            identity = capture["dss"]["scenario_id"]
            calls.append(("capture", identity))
            if failure == "capture": raise ValueError("capture failed")
            return {"raw_capture_sha256":self.store_capture(capture)}

        def assert_normal_finish(self, capture):
            calls.append(("finish", capture["dss"]["scenario_id"]))
            if failure == "finish": raise ValueError("finish failed")
            super().assert_normal_finish(capture)

    qualifier = Qualifier.__new__(Qualifier)
    qualifier.output = tmp_path / "report.json"
    qualifier.capture_root = tmp_path / "captures"
    qualifier.capture_root.mkdir()
    qualifier.captures, qualifier.results, qualifier.scenarios = {}, {}, []
    qualifier.bindings = {"source_commit":"b" * 40, "image_ids":{}}
    qualifier.manifest = {"scenarios":[fault,normal], "inventory":[], "inventory_sha256":"c" * 64}
    qualifier.definitions = {row["subject"]:{"definition_sha256":row["definition_sha256"]} for row in (fault,normal)}

    def read(path):
        assert path == "/state" or path.startswith("/evidence?")
        if path == "/state":
            return {**engine.state(), "transport":{"automatic_interval_ns":1_000_000_000,"physics_ticks_per_frame":10}}
        query = parse_qs(urlsplit(path).query)
        return engine.evidence_page(query["scenario_id"][0], limit=int(query["limit"][0]))

    def observe(capture, definition):
        calls.append(("oracle", definition["id"]))
        if failure == "oracle": return {"terminal":"unexpected"}
        return deepcopy(definition["expected"])

    def validate(report, **kwargs):
        calls.append(("validate", "report"))
        if failure == "validation": raise ValueError("validation failed")

    qualifier.dss = SimpleNamespace(call=read)
    monkeypatch.setattr(registry, "ALL_SELECTION", -1)  # Only the scenario orchestration is under test.
    monkeypatch.setattr(validator, "observed_procedure", observe)
    monkeypatch.setattr(validator, "validate_report", validate)
    try:
        if failure is None:
            qualifier.run()
            assert json.loads(qualifier.output.read_bytes())["decision"] == "PASS"
            assert engine.state()["scenario_id"] == "core-tutorial"
            assert engine.state()["running"] is False
            assert engine.evidence("core-tutorial")["faults"] == {}
            assert calls == [("execute",fault["id"]),("capture",fault["id"]),("oracle",fault["id"]),
                ("execute",normal["id"]),("capture",normal["id"]),("oracle",normal["id"]),
                ("validate","report"),("finish",normal["id"])]
        else:
            with pytest.raises(ValueError): qualifier.run()
            assert not qualifier.output.exists()
            if failure in {"execution", "capture", "oracle"}:
                assert ("execute", normal["id"]) not in calls
            if failure != "finish": assert not any(kind == "finish" for kind, _ in calls)
        if failure not in {"execution", "capture"}:
            saved = [json.loads(path.read_bytes()) for path in qualifier.capture_root.iterdir()]
            fault_capture = next(row for row in saved if row["dss"]["scenario_id"] == fault["id"])
            assert fault_capture["dss"]["faults"] == {"command_delay_ms":5000}
            retained = engine.evidence(fault["id"])
            assert retained["faults"] == fault_capture["dss"]["faults"]
            assert retained["packets"] == fault_capture["dss"]["packets"]
    finally:
        engine.close()


def _fresh_snapshot(frame):
    from datetime import datetime,timezone
    from driver_host.dss_telemetry import DssTelemetryDriver
    acquired=frame["acquired_at_unix_ns"]
    now=(acquired//1000+10)*1000
    items=[]
    for definition in frame["items"]:
        sample=DssTelemetryDriver._sample(definition["item_id"],frame)
        items.append({"item_id":sample.item.item_id,"source_epoch":sample.source_epoch,
            "source_id":frame["source_id"],"source":"SIMULATOR","clock_provenance":sample.clock_provenance,
            "clock_uncertainty_ns":str(sample.clock_uncertainty_ns),"freshness_policy_revision":"v07-r1",
            "acquired_at_unix_ns":str(acquired),"received_at_unix_ns":str(acquired+1000),
            "freshness":"FRESH","quality":sample.quality.value,"quality_reason":sample.quality_reason,
            "validity":sample.validity.value,"synchronization_state":"COMPLETE"})
    return {"snapshot_at_database_time":datetime.fromtimestamp(now/1e9,timezone.utc).isoformat(),"items":items,
        "driver_time":{"provenance":"dss-dynamics-clock","uncertainty_ns":str(frame["driver_time_uncertainty_ns"]),
            "acquired_at_unix_ns":str(acquired),"received_at_unix_ns":str(acquired+1000),"quality":"GOOD","validity":"VALID",
            "source_epoch":frame["satellite_epoch"]}}


@pytest.mark.parametrize("mutation",[None,"missing-item","old-epoch","clock","clock-type","provenance","clock-epoch","clock-unbound",
    "clock-acquisition-expired","clock-acquisition-type","clock-quality","clock-validity"])
def test_scenario_readiness_requires_complete_epoch_and_declared_clock(tmp_path,mutation):
    from backend.dss_scenarios import snapshot_matches_scenario,subject_execution_spec
    spec=subject_execution_spec("case:clock",{"observation_input":"clock"})
    engine=DssEngine(tmp_path/"clock-readiness.sqlite")
    try:
        state=engine.reset("clock",faults=spec["faults"],expected_epoch=engine.state()["epoch"])
        snapshot=_fresh_snapshot(decode_tm(bytes.fromhex(engine.evidence("clock")["packets"][0]["packet_hex"])))
    finally:engine.close()
    assert snapshot_matches_scenario(snapshot,state,spec)
    if mutation=="missing-item":snapshot["items"].pop()
    elif mutation=="old-epoch":snapshot["items"][-1]["source_epoch"]="old"
    elif mutation=="clock":snapshot["driver_time"]["uncertainty_ns"]="1000"
    elif mutation=="clock-type":snapshot["driver_time"]["uncertainty_ns"]=2000000000
    elif mutation=="provenance":snapshot["driver_time"]["provenance"]="unrelated-clock"
    elif mutation=="clock-epoch":snapshot["driver_time"]["source_epoch"]="old"
    elif mutation=="clock-unbound":snapshot["driver_time"].pop("source_epoch")
    elif mutation=="clock-acquisition-expired":snapshot["driver_time"]["acquired_at_unix_ns"]=str(int(snapshot["driver_time"]["acquired_at_unix_ns"])-5_000_002_000)
    elif mutation=="clock-acquisition-type":snapshot["driver_time"]["acquired_at_unix_ns"]=int(snapshot["driver_time"]["acquired_at_unix_ns"])
    elif mutation=="clock-quality":snapshot["driver_time"]["quality"]="BAD"
    elif mutation=="clock-validity":snapshot["driver_time"]["validity"]="INVALID"
    assert snapshot_matches_scenario(snapshot,state,spec) is (mutation is None)


@pytest.mark.parametrize("kind",["nominal","low","missing","invalid","bad-quality","gap","policy","clock"])
def test_readiness_preserves_exact_declared_driver_fault_projection(tmp_path,kind):
    from backend.dss_scenarios import snapshot_matches_scenario,subject_execution_spec
    spec=subject_execution_spec("case:declared-input",{"observation_input":kind})
    engine=DssEngine(tmp_path/"declared-input.sqlite")
    try:
        state=engine.reset(kind,initial_state=spec["initial_state"],faults=spec["faults"],expected_epoch=engine.state()["epoch"])
        frame=decode_tm(bytes.fromhex(engine.evidence(kind)["packets"][0]["packet_hex"]))
        snapshot=_fresh_snapshot(frame)
        assert snapshot_matches_scenario(snapshot,state,spec)
        nominal=subject_execution_spec("case:nominal",{})
        assert snapshot_matches_scenario(snapshot,state,nominal) is (kind in {"nominal","low"})
        if kind not in {"nominal","low"}:
            forged=deepcopy(spec)
            key=next(iter(forged["faults"]))
            forged["faults"][key]=1 if type(forged["faults"][key]) is bool else None
            assert not snapshot_matches_scenario(snapshot,state,forged)
    finally:engine.close()


@pytest.mark.parametrize("mutation",["stale","bad-quality","invalid","gapped","policy","reason","acquisition-expired",
    "acquisition-future","timestamp-type","timestamp-leading-zero","missing-db-time","naive-db-time","malformed-kind"])
def test_nominal_readiness_rejects_unacceptable_or_forged_fresh_heads(tmp_path,mutation):
    from backend.dss_scenarios import snapshot_matches_scenario,subject_execution_spec
    spec=subject_execution_spec("case:nominal",{})
    engine=DssEngine(tmp_path/"nominal-readiness.sqlite")
    try:
        state=engine.state()
        snapshot=_fresh_snapshot(decode_tm(bytes.fromhex(engine.evidence(state["scenario_id"])["packets"][0]["packet_hex"])))
        assert snapshot_matches_scenario(snapshot,state,spec)
        item=snapshot["items"][-1]
        if mutation=="stale":item["freshness"]="STALE"
        elif mutation=="bad-quality":item["quality"]="BAD"
        elif mutation=="invalid":item["validity"]="INVALID"
        elif mutation=="gapped":item["synchronization_state"]="GAPPED"
        elif mutation=="policy":item["freshness_policy_revision"]="different-policy"
        elif mutation=="reason":item["quality_reason"]="DSS_POLICY_REVISION_MISMATCH"
        elif mutation=="acquisition-expired":item["acquired_at_unix_ns"]=str(int(item["acquired_at_unix_ns"])-5_000_002_000)
        elif mutation=="acquisition-future":item["acquired_at_unix_ns"]=str(int(item["received_at_unix_ns"])+1001)
        elif mutation=="timestamp-type":item["acquired_at_unix_ns"]=int(item["acquired_at_unix_ns"])
        elif mutation=="timestamp-leading-zero":item["received_at_unix_ns"]="0"+item["received_at_unix_ns"]
        elif mutation=="missing-db-time":snapshot.pop("snapshot_at_database_time")
        elif mutation=="naive-db-time":snapshot["snapshot_at_database_time"]="2026-10-03T00:00:00"
        elif mutation=="malformed-kind":spec["observation_input"]=[]
        assert not snapshot_matches_scenario(snapshot,state,spec)
    finally:engine.close()


def test_readiness_failure_preserves_bounded_metadata_and_pauses_without_a_command(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from backend import dss_language_executor as module
    from backend.dss_language_broker import request_for_selection,selected_subjects
    from backend.dss_language_executor import DssLanguageExecutor
    engine=DssEngine(tmp_path/"readiness-failure.sqlite")
    executor=DssLanguageExecutor.__new__(DssLanguageExecutor)
    executor.request=request_for_selection("readiness-proof",4,195)
    executor.context_id="simulator"
    executor.authorize=lambda:True
    def call(path,body=None):
        if path=="/state":return engine.state()
        if path=="/control":return engine.control(**{key:value for key,value in body.items()})
        assert path=="/scenarios/reset"
        return engine.reset(**body)
    executor._http=call
    executor.runtime=SimpleNamespace(health=lambda *_args,**_kwargs:{"scenario_id":engine.state()["scenario_id"],"satellite_epoch":engine.state()["epoch"]})
    executor.supervisor=SimpleNamespace(observation_anchor_provider=SimpleNamespace(snapshot=lambda _: {
        "items":[{"item_id":"TM.POWER.BUS_VOLTAGE","source_epoch":"old-epoch","source_sequence":"17",
            "freshness":"STALE","quality":"GOOD","validity":"VALID","synchronization_state":"GAPPED",
            "engineering_value":{"value":"NEVER_PRINT_TELEMETRY"}}],
        "driver_time":{"source_epoch":"old-clock","source_sequence":"9","uncertainty_ns":"2000000000",
            "unrelated_secret":"NEVER_PRINT_CREDENTIAL"}}))
    ticks=iter((0,0,11))
    monkeypatch.setattr(module,"time",SimpleNamespace(monotonic=lambda:next(ticks),sleep=lambda _:None,time_ns=lambda:123456789))
    try:
        with pytest.raises(ValueError) as error:executor._prepare(selected_subjects(executor.request)[0],{})
        detail=str(error.value)
        assert "committed observation repository" in detail and "old-clock" in detail and '"source_sequence":"9"' in detail
        assert '"expected_uncertainty_ns":"1000"' in detail and "TM.POWER.BUS_VOLTAGE" in detail
        assert all(word in detail for word in ("STALE","GOOD","VALID","GAPPED","missing"))
        assert "NEVER_PRINT" not in detail and len(detail)<1000
        from backend.dss_language_diagnostics import failure
        retained=failure(executor)
        assert retained["readiness"]["observed_at_unix_ns"]=="123456789"
        assert retained["readiness"]["clock"]["source_epoch"]=="old-clock"
        assert retained["readiness"]["items"][0]["source_sequence"]=="17"
        assert retained["readiness"]["items"][0]["synchronization_state"]=="GAPPED"
        assert b"NEVER_PRINT" not in canonical(retained)
        assert engine.state()["running"] is False
        evidence=engine.evidence(engine.state()["scenario_id"])
        assert evidence["commands"]==[] and evidence["operations"]==[]
    finally:engine.close()


@pytest.mark.parametrize("mutation",[None,"normal","uncertainty","mixed-fault","fault-bool","wrong-epoch",
    "missing-item","fresh-label","fresh-acquisition","wrong-quality","gapped","missing-clock","empty-clock","foreign-clock","timestamp-type"])
def test_declared_stale_readiness_requires_actual_stale_samples_and_explicit_no_clock(tmp_path,mutation):
    import time
    from backend.dss_scenarios import subject_execution_spec,snapshot_matches_scenario
    engine=DssEngine(tmp_path/"stale-readiness.sqlite")
    try:
        spec=subject_execution_spec("case:v19-read-rejects-stale",{"observation_input":"stale"})
        state=engine.reset("stale-readiness",initial_state=spec["initial_state"],faults=spec["faults"],expected_epoch=engine.state()["epoch"])
        frame=decode_tm(bytes.fromhex(engine.evidence(state["scenario_id"])["packets"][0]["packet_hex"]))
        snapshot={"driver_time":None,"items":[{"item_id":row["item_id"],"source_epoch":frame["satellite_epoch"],
            "source_id":frame["source_id"],"source":"SIMULATOR","clock_provenance":frame["clock_provenance"],
            "clock_uncertainty_ns":str(frame["clock_uncertainty_ns"]),"freshness_policy_revision":frame["freshness_policy_revision"],
            "acquired_at_unix_ns":str(frame["acquired_at_unix_ns"]),"received_at_unix_ns":str(time.time_ns()),
            "freshness":"STALE","quality":row["quality"],"validity":row["validity"],"synchronization_state":"COMPLETE"} for row in frame["items"]]}
        assert snapshot_matches_scenario(snapshot,state,spec)
        if mutation=="normal":spec=subject_execution_spec("case:normal",{})
        elif mutation=="uncertainty":spec=subject_execution_spec("case:clock",{"observation_input":"clock"})
        elif mutation=="mixed-fault":spec["faults"]["clock_uncertainty_ns"]=1000
        elif mutation=="fault-bool":spec["faults"]["stale"]=1
        elif mutation=="wrong-epoch":snapshot["items"][-1]["source_epoch"]="old"
        elif mutation=="missing-item":snapshot["items"].pop()
        elif mutation=="fresh-label":snapshot["items"][-1]["freshness"]="FRESH"
        elif mutation=="fresh-acquisition":snapshot["items"][-1]["acquired_at_unix_ns"]=snapshot["items"][-1]["received_at_unix_ns"]
        elif mutation=="wrong-quality":snapshot["items"][-1]["quality"]="BAD"
        elif mutation=="gapped":snapshot["items"][-1]["synchronization_state"]="GAPPED"
        elif mutation=="missing-clock":snapshot.pop("driver_time")
        elif mutation=="empty-clock":snapshot["driver_time"]={}
        elif mutation=="foreign-clock":snapshot["driver_time"]={"source_epoch":"old"}
        elif mutation=="timestamp-type":snapshot["items"][-1]["received_at_unix_ns"]=int(snapshot["items"][-1]["received_at_unix_ns"])
        assert snapshot_matches_scenario(snapshot,state,spec) is (mutation is None)
    finally:engine.close()


def test_stale_source_specs_bind_exact_rejection_oracles_and_raw_acquisition_age(tmp_path):
    import time
    from backend import language_conformance_v19 as registry
    from backend.dss_scenarios import subject_execution_spec,STALE_CLOCK_EXPECTATION
    from dss.packets import encode_tm
    from scripts.validate_dss_delivery import validate_execution_spec
    cases=[row for row in registry.CASES if row.get("observation_input")=="stale"]
    assert {row["id"]:[(entry["operation"],entry["outcome"]) for entry in row["expected_observations"]] for row in cases}=={
        "v19-read-rejects-stale":[("GET_TM","NOT_AVAILABLE")],
        "v19-verify-overwrites-prior-true":[("VERIFY","INDETERMINATE")]}
    assert all(not row["expected_telecommands"] and subject_execution_spec("case:"+row["id"],row)["clock_expectation"]==STALE_CLOCK_EXPECTATION for row in cases)
    outer=next(row for row in scenario_definitions() if row["id"]=="observation-rejects-stale")
    assert outer["inputs"]["execution_spec"]["clock_expectation"]==STALE_CLOCK_EXPECTATION
    engine=DssEngine(tmp_path/"stale-capture.sqlite")
    try:
        spec=subject_execution_spec("case:"+cases[0]["id"],cases[0])
        initial=engine.reset("stale-capture",initial_state=spec["initial_state"],faults=spec["faults"],expected_epoch=engine.state()["epoch"])
        resumed=engine.control("RESUME",expected_epoch=initial["epoch"],expected_revision=initial["revision"])
        engine.control("PAUSE",expected_epoch=initial["epoch"],expected_revision=resumed["revision"])
        for packet in engine.pending_packets():engine.mark_published(packet["id"])
        evidence=engine.evidence(initial["scenario_id"])
        capture={"execution_spec":spec,"elapsed_seconds":1.0,"dss":evidence,"driver":[{
            "topic":row["topic"],"body":decode_tm(bytes.fromhex(row["packet_hex"])),"received_unix_ns":time.time_ns()} for row in evidence["packets"]]}
        validate_execution_spec(capture,spec,initial,spec["faults"])
        changed=deepcopy(capture)
        body=changed["driver"][0]["body"]
        body["acquired_at_unix_ns"]=changed["driver"][0]["received_unix_ns"]
        changed["driver"][0]["body"]=decode_tm(encode_tm(body,sequence=body["tm_sequence"] & 0x3fff))
        with pytest.raises(ValueError,match="received stale acquisition"):
            validate_execution_spec(changed,spec,initial,spec["faults"])
    finally:engine.close()


@pytest.fixture
def capture(tmp_path):
    engine=DssEngine(tmp_path/"dss.sqlite")
    try:
        for stage in ("TRANSPORT","LOADING","RELEASE","ACKNOWLEDGEMENT","ONBOARD_EXECUTION"):
            send(engine,stage=stage)
        for packet in engine.pending_packets():
            engine.mark_published(packet["id"])
        state=engine.state()
        evidence=engine.evidence(state["scenario_id"])
        rows=[{"packet":row["packet_hex"],"packet_sha256":row["packet_sha256"],"topic":row["topic"],
            "partition":0,"offset":index,"received_unix_ns":1,"body":decode_tm(bytes.fromhex(row["packet_hex"]))}
            for index,row in enumerate(evidence["packets"])]
        yield {"dss":evidence,"driver":rows}
    finally:
        engine.close()


def test_packet_validator_decodes_real_engine_bytes_and_cross_binds_journal(capture):
    result=validate_transport_capture(capture,scenario_id=capture["dss"]["scenario_id"],epoch=capture["dss"]["epoch"])
    assert result["tc_stages"]==5 and result["executed_commands"]==1
    assert result["decoded_packets"]==len(capture["driver"])


@pytest.mark.parametrize("mutation",[None,"raw-number","raw-leading-zero","raw-plus","raw-space","raw-value","engineering","selection","result","wire-value"])
def test_gettm_binding_preserves_binary_integer_and_protocol_decimal_identity(capture,mutation):
    from scripts.validate_dss_delivery import _validate_observation_value_binding
    body=next(row["body"] for row in capture["driver"] if row["topic"]=="openbexi.GENERIC.tm")
    item=next(row for row in body["items"] if row["item_id"]=="TM.POWER.BUS_VOLTAGE")
    sample={"raw_value":{"type":"UINT64","value":"28000"},
        "engineering_value":{"type":"FINITE_DOUBLE","value":28.0},
        "selected_value":{"type":"FINITE_DOUBLE","value":28.0},"field":"ENGINEERING"}
    value=28.0
    if mutation=="raw-number":sample["raw_value"]["value"]=28000
    elif mutation=="raw-leading-zero":sample["raw_value"]["value"]="028000"
    elif mutation=="raw-plus":sample["raw_value"]["value"]="+28000"
    elif mutation=="raw-space":sample["raw_value"]["value"]="28000 "
    elif mutation=="raw-value":sample["raw_value"]["value"]="28001"
    elif mutation=="engineering":sample["engineering_value"]["value"]=27.0
    elif mutation=="selection":sample["selected_value"]={"type":"UINT64","value":"28000"}
    elif mutation=="result":value=27.0
    elif mutation=="wire-value":
        from dss.packets import encode_tm
        changed=deepcopy(body)
        next(row for row in changed["items"] if row["item_id"]==item["item_id"])["raw"]["value"]+=1
        decoded=decode_tm(encode_tm(changed))
        item=next(row for row in decoded["items"] if row["item_id"]==item["item_id"])
    if mutation is None:_validate_observation_value_binding(item,sample,value)
    else:
        with pytest.raises(ValueError):_validate_observation_value_binding(item,sample,value)


@pytest.mark.parametrize("kind,value,expected",[("INT64",-(2**63),str(-(2**63))),
    ("UINT64",2**64-1,str(2**64-1)),("UINT64",True,None),("UINT64",-1,None),
    ("UINT64",2**64,None),("INT64",2**63,None),("INT64",-(2**63)-1,None),
    ("UINT64","28000",None),("FINITE_DOUBLE",28,None),("BOOLEAN",1,None)])
def test_packet_observation_projection_is_exact_and_bounded(kind,value,expected):
    from scripts.validate_dss_delivery import _observation_scalar_from_packet
    if expected is None:
        with pytest.raises(ValueError):_observation_scalar_from_packet({"type":kind,"value":value})
    else:assert _observation_scalar_from_packet({"type":kind,"value":value})=={"type":kind,"value":expected}


@pytest.mark.parametrize("mutation",["missing-consumer","foreign-bytes","decoded-value","unpublished","offset-bool",
    "tc-hash","ack-substitution","extra-effect","executed-bool","database","epoch","duplicate-stage",
    "missing-initial-sample","duplicate-consumer","stage-resent"])
def test_packet_validator_rejects_missing_or_forged_transport_proof(capture,mutation):
    value=deepcopy(capture)
    if mutation=="missing-consumer":value["driver"]=[]
    elif mutation=="foreign-bytes":value["driver"][0]["packet"]="00"
    elif mutation=="decoded-value":value["driver"][0]["body"]["state_revision"]+=1
    elif mutation=="unpublished":value["dss"]["packets"][0]["published"]=False
    elif mutation=="offset-bool":value["driver"][0]["offset"]=True
    elif mutation=="tc-hash":value["dss"]["operations"][0]["packet_sha256"]="0"*64
    elif mutation=="ack-substitution":value["dss"]["operations"][0]["acknowledgement"]["operation_id"]="other"
    elif mutation=="extra-effect":value["dss"]["commands"][0]["element_id"]="other"
    elif mutation=="executed-bool":value["dss"]["commands"][0]["executed"]=True
    elif mutation=="database":value["dss"]["database_digest"]="0"*64
    elif mutation=="epoch":value["dss"]["epoch"]="different"
    elif mutation=="duplicate-stage":value["dss"]["operations"].append(deepcopy(value["dss"]["operations"][0]))
    elif mutation=="missing-initial-sample":value["driver"].pop(0)
    elif mutation=="duplicate-consumer":value["driver"].append(deepcopy(value["driver"][0]))
    else:value["dss"]["operations"][0]["ingress_delivery_count"]=2
    with pytest.raises((ValueError,KeyError)):
        validate_transport_capture(value,scenario_id=capture["dss"]["scenario_id"],epoch=capture["dss"]["epoch"])


def test_evidence_pagination_drains_all_records_and_rejects_revision_changes(tmp_path):
    engine=DssEngine(tmp_path/"pages.sqlite")
    try:
        scenario=engine.state()["scenario_id"]
        for _ in range(40):
            state=engine.state()
            engine.control("STEP",expected_epoch=state["epoch"],expected_revision=state["revision"],ticks=1)
        def call(path):
            values=parse_qs(urlsplit(path).query)
            return engine.evidence_page(values["scenario_id"][0],offset=int(values["offset"][0]),
                limit=int(values["limit"][0]),expected_revision=int(values["expected_revision"][0]) if "expected_revision" in values else None)
        assert collect_evidence(call,scenario)==engine.evidence(scenario)
        def changed(path):
            page=call(path)
            if page["pagination"]["offset"]:page["pagination"]["counts"]["packets"]+=1
            return page
        with pytest.raises(ValueError,match="changed during"):
            collect_evidence(changed,scenario)
    finally:engine.close()


def test_evidence_export_retries_only_bounded_read_conflicts(tmp_path):
    from urllib.error import HTTPError
    engine=DssEngine(tmp_path/"retry.sqlite")
    try:
        scenario=engine.state()["scenario_id"]
        calls=[]
        def conflicted(path):
            calls.append(path)
            assert path.startswith("/evidence?")
            if len(calls)<=2:raise HTTPError(path,409,"revision changed",{},None)
            return engine.evidence_page(scenario)
        assert collect_evidence(conflicted,scenario,conflict_retries=3)==engine.evidence(scenario)
        assert len(calls)==3
        def unavailable(path):raise HTTPError(path,503,"offline",{},None)
        with pytest.raises(HTTPError) as error:collect_evidence(unavailable,scenario,conflict_retries=3)
        assert error.value.code==503
    finally:engine.close()


def test_fenced_execution_controls_require_real_received_running_then_paused_frames(tmp_path):
    from backend.dss_capture import set_running
    from backend.dss_scenarios import subject_execution_spec
    from scripts.validate_dss_delivery import validate_execution_spec
    engine=DssEngine(tmp_path/"controls.sqlite")
    try:
        spec=subject_execution_spec("case:control",{})
        state=engine.reset("control-proof",initial_state=spec["initial_state"],expected_epoch=engine.state()["epoch"])
        calls=[]
        def call(path,body=None):
            calls.append((path,body))
            if path=="/state":return engine.state()
            assert path=="/control"
            return engine.control(body["action"],expected_epoch=body["expected_epoch"],expected_revision=body["expected_revision"])
        set_running(call,True,epoch=state["epoch"])
        engine.advance(10)
        set_running(call,False,epoch=state["epoch"])
        for packet in engine.pending_packets():engine.mark_published(packet["id"])
        evidence=engine.evidence(state["scenario_id"])
        raw={"execution_spec":spec,"elapsed_seconds":1.0,"dss":evidence,
            "driver":[{"topic":p["topic"],"body":decode_tm(bytes.fromhex(p["packet_hex"]))} for p in evidence["packets"]]}
        validate_execution_spec(raw,spec,state,{})
        assert [body["action"] for path,body in calls if path=="/control"]==["RESUME","PAUSE"]
        assert evidence["final_state"]["core"]["tick"]==10
        for tamper in ("no-running","final-running","wrong-type","missing-final"):
            changed=deepcopy(raw)
            if tamper=="no-running":
                for row in changed["driver"]:row["body"]["running"]=False
            elif tamper=="final-running":changed["dss"]["final_state"]["running"]=True
            elif tamper=="wrong-type":changed["driver"][1]["body"]["running"]=1
            else:changed["driver"].pop()
            with pytest.raises(ValueError,match="control evidence"):validate_execution_spec(changed,spec,state,{})
        with pytest.raises(ValueError,match="epoch"):set_running(call,True,epoch="other-epoch")
    finally:engine.close()


@pytest.mark.parametrize("failure",["one-revision-race","repeated-revision-race","unavailable"])
def test_pause_retries_only_unapplied_revision_conflicts(tmp_path,failure):
    from urllib.error import HTTPError
    from backend.dss_capture import set_running
    from dss.engine import DssConflict
    engine=DssEngine(tmp_path/"pause-race.sqlite")
    try:
        initial=engine.state()
        engine.control("RESUME",expected_epoch=initial["epoch"],expected_revision=initial["revision"])
        calls=[]
        def call(path,body=None):
            if path=="/state":return engine.state()
            assert path=="/control" and body["action"]=="PAUSE"
            calls.append(body)
            if failure=="unavailable":raise HTTPError(path,503,"offline",{},None)
            if failure=="repeated-revision-race" or len(calls)==1:
                engine.advance(1)
            try:
                return engine.control(body["action"],expected_epoch=body["expected_epoch"],expected_revision=body["expected_revision"])
            except DssConflict as exc:
                assert engine.state()["running"] is True
                raise HTTPError(path,409,str(exc),{},None) from exc
        if failure=="one-revision-race":
            final=set_running(call,False,epoch=initial["epoch"])
            assert len(calls)==2 and final["running"] is False
            assert final["core"]["tick"]==1
        else:
            with pytest.raises(HTTPError) as error:set_running(call,False,epoch=initial["epoch"])
            assert error.value.code==(409 if failure=="repeated-revision-race" else 503)
            assert len(calls)==(4 if failure=="repeated-revision-race" else 1)
            assert engine.state()["running"] is True
        evidence=engine.evidence(initial["scenario_id"])
        assert evidence["commands"]==[] and evidence["operations"]==[]
        paused=[decode_tm(bytes.fromhex(row["packet_hex"]))["running"] for row in evidence["packets"]]
        assert paused.count(False)==(2 if failure=="one-revision-race" else 1)
    finally:engine.close()


@pytest.mark.parametrize("mutation",["missing-report","skip-decision","full-language","missing-sidecar","path-traversal",
    "wrong-size","wrong-hash","unreferenced-file","missing-inventory-result"])
def test_delivery_gate_fails_closed_for_incomplete_and_unsafe_artifacts(tmp_path,mutation):
    from dss import SIMULATOR_VERSION,DYNAMICS_ENGINE_VERSION
    from dss.catalog import SatelliteDatabase
    database=SatelliteDatabase.load()
    image_ids={name:"sha256:"+"a"*64 for name in ("backend","driver","dss","kafka","frontend","proxy")}
    data=canonical({"unit":"cannot satisfy actual DSS execution"})
    identity=sha256(data)
    (tmp_path/(identity+".json")).write_bytes(data)
    report={"schema_version":"spell.dss.delivery/1","release":"v0.19.0","source_commit":"b"*40,
        "image_ids":image_ids,"database_identity":{"satellite_id":"GENERIC","revision":database.revision,
            "sha256":database.digest,"simulator_version":SIMULATOR_VERSION,"dynamics_engine_version":DYNAMICS_ENGINE_VERSION},
        "decision":"PASS","full_language_compatibility":False,"inventory_sha256":load_manifest()["inventory_sha256"],
        "results":[],"scenarios":[],"raw_captures":{identity:{"path":identity+".json","size":len(data)}},
        "reproduction":reproduction_metadata("v0.19.0"),"counts":{}}
    if mutation=="missing-report":report={}
    elif mutation=="skip-decision":report["decision"]="SKIP"
    elif mutation=="full-language":report["full_language_compatibility"]=True
    elif mutation=="missing-sidecar":(tmp_path/(identity+".json")).unlink()
    elif mutation=="path-traversal":report["raw_captures"][identity]["path"]="../other.json"
    elif mutation=="wrong-size":report["raw_captures"][identity]["size"]+=1
    elif mutation=="wrong-hash":(tmp_path/(identity+".json")).write_bytes(b"x"*len(data))
    elif mutation=="unreferenced-file":(tmp_path/"extra.json").write_text("{}")
    with pytest.raises(ValueError):validate_report(report,source_commit="b"*40,image_ids=image_ids,capture_root=tmp_path)


def test_reproduction_commands_and_counts_are_derived_from_reviewed_inputs():
    reproduction = reproduction_metadata("v0.19.0")
    root = Path(__file__).resolve().parents[2]
    for key in ("scenario_manifest", "reference_mappings"):
        assert reproduction[key]["sha256"] == sha256((root / reproduction[key]["path"]).read_bytes())
    assert reproduction["runtime_configuration"] == {
        "automatic_interval_ns":1_000_000_000,"physics_tick_ns":100_000_000,"physics_ticks_per_frame":10}
    assert reproduction["delivery_command"][-1] == "dss-validation"
    inventory = source_inventory()
    counts = delivery_counts(inventory, [{"status":"PASS"},{"status":"SKIP"}], [{"status":"PASS"}], {"a":{}})
    assert counts["required_inventory"] == 954 and counts["expected_compiler_rejections"] == 36
    assert counts["results_passed"] == 1 and counts["scenarios_passed"] == 1 and counts["capture_files"] == 1


@pytest.mark.parametrize("failure",["case","credentials","capture-directory","manifest"])
def test_first_live_failure_is_recorded_with_identity_and_cannot_publish_pass(tmp_path,monkeypatch,failure):
    import json,sys
    from scripts import qualify_dss_v19 as producer
    output=tmp_path/"dss-validation.json"
    bindings=tmp_path/"bindings.json"
    bindings.write_bytes(canonical({"source_commit":"b"*40,"image_ids":{}}))
    output.write_text('{"decision":"PASS"}')
    class FailedQualifier:
        current_identity="menu:000"
        results={}
        def __init__(self,*args):
            if failure=="capture-directory":raise ValueError("DSS capture directory is not empty")
        def run(self): raise ValueError("adaptation:001: actual decoded packet missing")
    monkeypatch.setattr(producer,"DeliveryQualifier",FailedQualifier)
    monkeypatch.setenv("SPELL_DSS_GATE_TOKEN","test-only-not-a-credential")
    monkeypatch.delenv("SPELL_DSS_GATE_TOKEN_FILE",raising=False)
    if failure=="credentials":monkeypatch.delenv("SPELL_DSS_GATE_TOKEN")
    if failure=="manifest":
        def stale_manifest(*args):raise ValueError("DSS inventory is stale or incomplete")
        monkeypatch.setattr(producer,"load_manifest",stale_manifest)
    monkeypatch.setattr(sys,"argv",["qualify_dss_v19","--bindings",str(bindings),"--output",str(output)])
    with pytest.raises(ValueError):
        producer.main()
    report=json.loads(output.read_bytes())
    assert report["decision"]=="FAIL" and report["failed_identity"]==("menu:000" if failure=="case" else "initialization")
    assert report["completed_identities"]==[]
    if failure=="case":assert "adaptation:001" in report["error"]
    with pytest.raises(ValueError):validate_report(report,source_commit="b"*40,image_ids={})


@pytest.mark.parametrize("mutation", ["command", "manifest", "mapping", "cadence"])
def test_reproduction_metadata_rejects_forged_commands_and_configuration(tmp_path, mutation):
    from dss import SIMULATOR_VERSION,DYNAMICS_ENGINE_VERSION
    from dss.catalog import SatelliteDatabase
    database = SatelliteDatabase.load()
    images = {name:"sha256:"+"a"*64 for name in ("backend","driver","dss","kafka","frontend","proxy")}
    reproduction = reproduction_metadata("v0.19.0")
    if mutation == "command": reproduction["delivery_command"][-1] = "documentation"
    elif mutation == "manifest": reproduction["scenario_manifest"]["sha256"] = "0"*64
    elif mutation == "mapping": reproduction["reference_mappings"]["sha256"] = "0"*64
    else: reproduction["runtime_configuration"]["physics_ticks_per_frame"] = 1
    report = {"schema_version":"spell.dss.delivery/1","release":"v0.19.0","source_commit":"b"*40,
        "image_ids":images,"database_identity":{"satellite_id":"GENERIC","revision":database.revision,
            "sha256":database.digest,"simulator_version":SIMULATOR_VERSION,"dynamics_engine_version":DYNAMICS_ENGINE_VERSION},
        "decision":"PASS","full_language_compatibility":False,"inventory_sha256":load_manifest()["inventory_sha256"],
        "results":[],"scenarios":[],"raw_captures":{},"reproduction":reproduction,"counts":{}}
    with pytest.raises(ValueError, match="reproduction"):
        validate_report(report, source_commit="b"*40, image_ids=images, capture_root=tmp_path)


def test_language_failure_distinguishes_outer_selection_from_actual_inner_dispatch():
    from scripts.qualify_dss_v19 import language_failure_detail
    events = [{"event_type":"worker.consumer_failed", "payload":{"error":"dependency checkpoint rejected"}},
        {"event_type":"execution.state_changed", "payload":{"state":"recovery_required"}}]
    outer = language_failure_detail(291, events)
    assert outer == {"subject":"case:v18-native-yes-built-command", "phase":"outer_execution",
        "error":"dependency checkpoint rejected"}
    assert language_failure_detail(343, events)["subject"] == "selection:ALL"
    events.append({"event_type":"procedure.dss_language_failed", "payload":{
        "subject":"case:v18-native-yes-built-command", "error":"actual transport failed", "request_id":"bound"}})
    assert language_failure_detail(291, events) == {"subject":"case:v18-native-yes-built-command",
        "phase":"inner_dispatch", "error":"actual transport failed", "request_id":"bound"}


def _receipt_result(capture):
    details={}
    for operation in capture["dss"]["operations"]:
        ack=operation["acknowledgement"]
        packet=next(row for row in capture["dss"]["packets"] if canonical(decode_tm(bytes.fromhex(row["packet_hex"])))==canonical(ack))
        details[ack["stage"]]={"outcome":ack["outcome"],"native":{
            "provider":"dss-cortex-kafka","command_packet_sha256":operation["packet_sha256"],
            "acknowledgement_packet_sha256":packet["packet_sha256"],"telemetry":[],
            **{key:ack[key] for key in ("satellite_epoch","scenario_id","database_digest","tm_sequence","state_revision")}}}
    return {"checkpoint":{"elements":[{"provider_detail":details}]}}


def test_provider_receipt_binds_every_actual_stage_and_consumed_ack(capture):
    from scripts.validate_dss_delivery import _validate_stage_receipts
    _validate_stage_receipts(capture,[_receipt_result(capture)],[])


@pytest.mark.parametrize("tamper",["outcome","tc-hash","ack-hash","unconsumed-ack","fixture","epoch","unused-stage"])
def test_provider_receipt_rejects_labels_and_count_only_success(capture,tamper):
    from scripts.validate_dss_delivery import _validate_stage_receipts
    result=_receipt_result(capture)
    stage=result["checkpoint"]["elements"][0]["provider_detail"]["RELEASE"]
    if tamper=="outcome":stage["outcome"]="FAILED"
    elif tamper=="tc-hash":stage["native"]["command_packet_sha256"]="0"*64
    elif tamper=="ack-hash":stage["native"]["acknowledgement_packet_sha256"]="0"*64
    elif tamper=="unconsumed-ack":capture["driver"]=[row for row in capture["driver"] if row["packet_sha256"]!=stage["native"]["acknowledgement_packet_sha256"]]
    elif tamper=="fixture":stage["native"]["provider"]="fake-success"
    elif tamper=="epoch":stage["native"]["satellite_epoch"]="other"
    else:del result["checkpoint"]["elements"][0]["provider_detail"]["RELEASE"]
    with pytest.raises(ValueError):_validate_stage_receipts(capture,[result],[])


@pytest.mark.parametrize("tamper",["elapsed","negative","boolean","nan","state","faults","bound","input"])
def test_execution_spec_rejects_unbounded_time_or_undeclared_physical_inputs(tamper):
    from backend.dss_scenarios import subject_execution_spec
    from scripts.validate_dss_delivery import validate_execution_spec
    spec=subject_execution_spec("case:unit",{})
    raw={"execution_spec":deepcopy(spec),"elapsed_seconds":1.0}
    state=deepcopy(spec["initial_state"])
    faults={}
    if tamper=="elapsed":raw["elapsed_seconds"]=121
    elif tamper=="negative":raw["elapsed_seconds"]=-1
    elif tamper=="boolean":raw["elapsed_seconds"]=True
    elif tamper=="nan":raw["elapsed_seconds"]=float("nan")
    elif tamper=="state":state["bus"]["bus_voltage_mv"]=14000
    elif tamper=="faults":faults["transport_reject"]=True
    elif tamper=="bound":raw["execution_spec"]["wall_timeout_seconds"]=9000
    else:raw["execution_spec"]["confirmations"]=["YES"]
    with pytest.raises(ValueError):validate_execution_spec(raw,spec,state,faults)
