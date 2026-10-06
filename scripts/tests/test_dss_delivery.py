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


@pytest.mark.parametrize('mutation', [None, 'wrong-pin', 'same-size-bytes', 'missing-file',
                                      'extra-file', 'linked-file', 'changed-mode', 'unsafe-path'])
def test_qualification_linux_source_audit_rejects_tampering(tmp_path, mutation):
    import hashlib
    import json
    import subprocess
    import sys
    from scripts.qualify_next import SOURCE_AUDIT

    source = tmp_path / 'source.py'
    data = b'qualified_source = True\n'
    source.write_bytes(data)
    source.chmod(0o644)
    manifest = {'schema_version': 'spell.qualification-linux-source/1', 'source_commit': 'a' * 40,
                'files': {'source.py': {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': '644'}}}
    if mutation == 'unsafe-path':
        manifest['files']['../escape'] = manifest['files'].pop('source.py')
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    (tmp_path / '.spell-source-snapshot.json').write_bytes(raw)
    pin = hashlib.sha256(raw).hexdigest()
    if mutation == 'wrong-pin':
        pin = '0' * 64
    elif mutation == 'same-size-bytes':
        source.write_bytes(data.replace(b'True', b'None'))
    elif mutation == 'missing-file':
        source.unlink()
    elif mutation == 'extra-file':
        (tmp_path / 'injected.py').write_text('injected = True\n')
    elif mutation == 'linked-file':
        other = tmp_path / 'other.py'
        other.write_bytes(data)
        source.unlink()
        source.symlink_to(other)
    elif mutation == 'changed-mode':
        source.chmod(0o755)
    result = subprocess.run([sys.executable, '-c', SOURCE_AUDIT, str(tmp_path), pin],
                            capture_output=True, timeout=15)
    if mutation is None:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {'decision': 'PASS', 'source_commit': 'a' * 40,
                                            'manifest_sha256': pin, 'files': 1}
    else:
        assert result.returncode != 0
        assert not result.stdout


@pytest.mark.parametrize('raw_crlf', [False, True])
def test_qualification_linux_source_requires_exact_committed_disk_bytes(tmp_path, raw_crlf):
    import subprocess
    from scripts.qualify_next import source_snapshot_input
    from scripts.release_next import ReleaseError

    def git(*args):
        return subprocess.check_output(['git', '-C', str(tmp_path), *args])
    git('init', '-q')
    git('config', 'user.name', 'Qualification source test')
    git('config', 'user.email', 'source-test@example.invalid')
    git('config', 'core.autocrlf', 'true')
    source = tmp_path / 'source.py'
    source.write_bytes(b'qualified_source = True\n')
    git('add', '--', 'source.py')
    git('commit', '-qm', 'Exact source input')
    if raw_crlf:
        source.write_bytes(b'qualified_source = True\r\n')
        git('add', '--', 'source.py')
        assert not git('status', '--porcelain')
        with pytest.raises(ReleaseError, match='Raw source bytes differ'):
            source_snapshot_input(tmp_path)
    else:
        manifest, raw, payloads = source_snapshot_input(tmp_path)
        assert manifest['source_commit'] == git('rev-parse', 'HEAD').decode().strip()
        assert manifest['files']['source.py']['mode'] == '644'
        assert payloads['source.py'] == source.read_bytes()
        assert raw.endswith(b'\n')


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
    outer["bootstrap"]=_bootstrap_capture(tmp_path)
    outer["initial_dss_state"]=outer["bootstrap"]["initial_state"]
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


def _bootstrap_snapshot(packet):
    """Controlled admission metadata from actual engine bytes; no Kafka claim."""
    frame=decode_tm(bytes.fromhex(packet["packet_hex"]))
    snapshot=_fresh_snapshot(frame)
    for item in snapshot["items"]:item["source_sequence"]=str(frame["tm_sequence"])
    snapshot["driver_time"].update(source_sequence=str(frame["tm_sequence"]),
        source_packet_sha256=packet["packet_sha256"],database_digest=frame["database_digest"])
    return snapshot


def _bootstrap_driver(evidence):
    return [{"packet":row["packet_hex"],"packet_sha256":row["packet_sha256"],"topic":row["topic"],
        "partition":0,"offset":index,"received_unix_ns":decode_tm(bytes.fromhex(row["packet_hex"]))["acquired_at_unix_ns"]+500,
        "body":decode_tm(bytes.fromhex(row["packet_hex"]))} for index,row in enumerate(evidence["packets"])]


def _bootstrap_capture(tmp_path):
    from backend.dss_scenarios import procedure_execution_spec
    engine=DssEngine(tmp_path/"bootstrap-capture.sqlite")
    try:
        spec=procedure_execution_spec([],{},brokered=True)
        initial=engine.reset("bootstrap",initial_state=spec["initial_state"],expected_epoch=engine.state()["epoch"])
        engine.control("RESUME",initial["epoch"],initial["revision"])
        running=engine.advance(10)
        readiness=_bootstrap_snapshot(engine.evidence("bootstrap")["packets"][-1])
        paused=engine.control("PAUSE",running["epoch"],running["revision"])
        for packet in engine.pending_packets():engine.mark_published(packet["id"])
        physical=engine.evidence("bootstrap")
        return {"schema_version":"spell.dss.broker-bootstrap/1","initial_state":initial,"paused_state":paused,
            "readiness":readiness,"readiness_elapsed_seconds":1.0,"dss":physical,"driver":_bootstrap_driver(physical)}
    finally:engine.close()


@pytest.mark.parametrize("mutation",[None,"missing","bound","bound-bool","declaration","foreign-epoch",
    "stale","missing-item","duplicate-item","missing-clock","clock-packet","unreceived","receipt-time",
    "unpublished","reset-frame","acquisition","value-leak","running-final","state","command","raw-bytes"])
def test_broker_bootstrap_independently_binds_controls_readiness_and_received_bytes(tmp_path,mutation):
    from backend.dss_scenarios import procedure_execution_spec
    from scripts.validate_dss_delivery import validate_broker_bootstrap,validate_execution_spec
    bootstrap=_bootstrap_capture(tmp_path)
    spec=procedure_execution_spec([],{},brokered=True)
    initial=deepcopy(bootstrap["initial_state"])
    validate_broker_bootstrap(bootstrap,spec,initial)
    row=bootstrap["readiness"]["items"][0]
    if mutation=="missing":bootstrap=None
    elif mutation=="bound":bootstrap["readiness_elapsed_seconds"]=15.00001
    elif mutation=="bound-bool":bootstrap["readiness_elapsed_seconds"]=True
    elif mutation=="declaration":spec["bootstrap"]["readiness_timeout_seconds"]=16
    elif mutation=="foreign-epoch":row["source_epoch"]="epoch-"+"0"*64
    elif mutation=="stale":row["freshness"]="STALE"
    elif mutation=="missing-item":bootstrap["readiness"]["items"].pop()
    elif mutation=="duplicate-item":bootstrap["readiness"]["items"][-1]=deepcopy(row)
    elif mutation=="missing-clock":bootstrap["readiness"]["driver_time"]=None
    elif mutation=="clock-packet":bootstrap["readiness"]["driver_time"]["source_packet_sha256"]="0"*64
    elif mutation=="unreceived":bootstrap["driver"].pop(1)
    elif mutation=="receipt-time":bootstrap["driver"][2]["received_unix_ns"]+=5_000_000_000
    elif mutation=="unpublished":bootstrap["dss"]["packets"][1]["published"]=False
    elif mutation=="reset-frame":row["source_sequence"]="1"
    elif mutation=="acquisition":row["acquired_at_unix_ns"]=str(int(row["acquired_at_unix_ns"])-2000)
    elif mutation=="value-leak":row["engineering_value"]="private"
    elif mutation=="running-final":bootstrap["paused_state"]["running"]=True
    elif mutation=="state":bootstrap["paused_state"]["core"]["tick"]+=1
    elif mutation=="command":bootstrap["dss"]["commands"]=[{}]
    elif mutation=="raw-bytes":bootstrap["driver"][1]["packet"]="00"
    capture={"bootstrap":bootstrap,"execution_spec":spec,"elapsed_seconds":2.0}
    if mutation is None:validate_execution_spec(capture,spec,initial)
    else:
        with pytest.raises((ValueError,KeyError)):validate_execution_spec(capture,spec,initial)


def _bootstrap_harness(tmp_path,monkeypatch,*,kind="fresh"):
    """Real engine controls/bytes and a deterministic API boundary, no live gate."""
    from types import SimpleNamespace
    from scripts import qualify_dss_v19 as producer
    engine=DssEngine(tmp_path/"bootstrap-harness.sqlite")
    calls=[]
    clock=[0.0]
    state={"polls":0,"last":None}
    def dss(path,body=None):
        calls.append((path,deepcopy(body)))
        if path=="/state":return engine.state()
        if path=="/scenarios/reset":return engine.reset(**body)
        if path=="/control":
            if kind=="resume-failure" and body["action"]=="RESUME":raise OSError("original resume failure")
            if kind=="pause-failure" and body["action"]=="PAUSE":raise OSError("original pause failure")
            return engine.control(body["action"],body["expected_epoch"],body["expected_revision"])
        values=parse_qs(urlsplit(path).query)
        assert path.startswith("/evidence?")
        for packet in engine.pending_packets():engine.mark_published(packet["id"])
        return engine.evidence_page(values["scenario_id"][0],offset=int(values.get("offset",[0])[0]),
            limit=int(values["limit"][0]),expected_revision=int(values["expected_revision"][0]) if "expected_revision" in values else None)
    def backend(path,body=None,**kwargs):
        calls.append((path,deepcopy(body)))
        if path=="/api/v1/executions":
            assert engine.state()["running"] is False
            raise LookupError("source creation reached after pause")
        if "dss-driver-evidence" in path:
            values=parse_qs(urlsplit(path).query)
            current=engine.state()
            assert values["epoch"]==[current["epoch"]]
            rows=_bootstrap_driver(engine.evidence(current["scenario_id"]))
            return {"execution_id":"bootstrap-execution","packets":[row for row in rows if row["packet_sha256"]==values["packet_sha256"][0]]}
        assert path=="/api/v1/telemetry/snapshot?context_id=simulator"
        state["polls"]+=1
        if state["polls"]==1 and kind=="expired-then-fresh":
            packet=engine.evidence(engine.state()["scenario_id"])["packets"][0]
        else:
            engine.advance(10)
            packet=engine.evidence(engine.state()["scenario_id"])["packets"][-1]
        snapshot=_bootstrap_snapshot(packet)
        if kind in {"stale","expired-then-fresh"} and (kind=="stale" or state["polls"]==1):
            from datetime import datetime,timedelta
            snapshot["snapshot_at_database_time"]=(datetime.fromisoformat(snapshot["snapshot_at_database_time"])+timedelta(seconds=6)).isoformat()
        elif kind=="missing":snapshot["items"].pop()
        elif kind=="clock":snapshot["driver_time"]=None
        elif kind=="wrong-epoch":snapshot["items"][0]["source_epoch"]="other"
        elif kind=="late-response":clock[0]=16.0
        elif kind=="foreign-reset":
            current=engine.state()
            engine.control("PAUSE",current["epoch"],current["revision"])
            engine.reset("foreign-owner",expected_epoch=current["epoch"])
        state["last"]=deepcopy(snapshot)
        return snapshot
    monkeypatch.setattr(producer,"time",SimpleNamespace(monotonic=lambda:clock[0],sleep=lambda _:clock.__setitem__(0,clock[0]+5.0)))
    qualifier=producer.DeliveryQualifier.__new__(producer.DeliveryQualifier)
    qualifier.backend,qualifier.dss=SimpleNamespace(call=backend),SimpleNamespace(call=dss)
    qualifier.logs=tmp_path
    return qualifier,engine,calls,state


@pytest.mark.parametrize("kind",["fresh","expired-then-fresh"])
def test_broker_bootstrap_requires_new_fresh_acquisition_and_pauses_before_source_create(tmp_path,monkeypatch,kind):
    from backend.dss_scenarios import procedure_execution_spec
    qualifier,engine,calls,observed=_bootstrap_harness(tmp_path,monkeypatch,kind=kind)
    try:
        spec=procedure_execution_spec([],{},brokered=True)
        state=qualifier.reset("menu:129",{})
        bootstrap=qualifier.prepare_bootstrap("menu:129",state,spec)
        assert observed["polls"]==(2 if kind=="expired-then-fresh" else 1)
        assert bootstrap["readiness_elapsed_seconds"]==(5.0 if kind=="expired-then-fresh" else 0.0)
        assert bootstrap["initial_state"]["core"]["tick"]==0
        assert bootstrap["paused_state"]["core"]["tick"]>0
        assert engine.state()["running"] is False
        qualifier.complete_bootstrap_evidence("menu:129",bootstrap,"bootstrap-execution",spec)
        assert not any(path=="/api/v1/executions" for path,_ in calls)
        with pytest.raises(LookupError,match="source creation reached after pause"):
            qualifier.run_procedure("menu:129","language_reference_244",[],selection=129)
        assert len([path for path,_ in calls if path=="/api/v1/executions"])==1
    finally:engine.close()


@pytest.mark.parametrize("kind",["stale","missing","clock","wrong-epoch","late-response","resume-failure","pause-failure","foreign-reset"])
def test_broker_bootstrap_failure_never_creates_source_or_pauses_foreign_epoch(tmp_path,monkeypatch,kind):
    import json
    qualifier,engine,calls,observed=_bootstrap_harness(tmp_path,monkeypatch,kind=kind)
    try:
        with pytest.raises((ValueError,OSError)):
            qualifier.run_procedure("menu:129","language_reference_244",[],selection=129)
        assert not any(path=="/api/v1/executions" for path,_ in calls)
        failed=json.loads((tmp_path/"menu-129-bootstrap-failed.json").read_bytes())
        assert failed["decision"]=="FAIL" and failed["phase"]=="outer_bootstrap"
        assert failed["dss"]["commands"]==failed["dss"]["operations"]==[]
        assert "packets" in failed["dss"]
        if kind=="foreign-reset":
            assert engine.state()["scenario_id"]=="foreign-owner"
            assert failed["pause_error_type"]=="ValueError"
            assert not any(body and body.get("expected_epoch")==engine.state()["epoch"] for path,body in calls if path=="/control")
        elif kind=="pause-failure":assert failed["pause_error_type"]=="OSError"
        else:assert engine.state()["running"] is False
        if observed["last"] is not None:assert failed["readiness"]==observed["last"]
    finally:engine.close()


def test_bootstrap_retention_failure_preserves_primary_error(tmp_path,monkeypatch):
    qualifier,engine,_calls,_state=_bootstrap_harness(tmp_path,monkeypatch,kind="resume-failure")
    def broken(*args):raise RuntimeError("secondary serialization failure")
    monkeypatch.setattr(qualifier,"retain_bootstrap_failure",broken)
    try:
        with pytest.raises(OSError,match="original resume failure") as caught:
            qualifier.run_procedure("menu:129","language_reference_244",[],selection=129)
        assert caught.value.__notes__==["Bootstrap evidence retention failed: RuntimeError"]
    finally:engine.close()


@pytest.mark.parametrize("kind",["nominal","low","stale","bad-quality","missing","clock"])
def test_each_inner_subject_resets_bootstrap_physics_and_preserves_declared_faults(tmp_path,monkeypatch,kind):
    from types import SimpleNamespace
    from backend.dss_language_executor import DssLanguageExecutor
    from backend.dss_language_broker import request_for_selection
    from backend.dss_scenarios import subject_execution_spec
    from backend.language_conformance_v19 import CASES
    from dss.catalog import SatelliteDatabase
    qualifier,engine,calls,_state=_bootstrap_harness(tmp_path,monkeypatch)
    try:
        outer=qualifier.reset("menu:129",{})
        current=engine.control("RESUME",outer["epoch"],outer["revision"])
        advanced=engine.advance(100)
        assert advanced["core"]["tick"]==100
        executor=DssLanguageExecutor.__new__(DssLanguageExecutor)
        case=next(row for row in CASES if row.get("observation_input","nominal")==kind)
        subject="case:"+case["id"]
        executor.request=request_for_selection("inner-reset-proof",4,195+CASES.index(case))
        executor.context_id="simulator"
        executor.authorize=lambda:None
        executor._http=qualifier.dss.call
        executor.runtime=SimpleNamespace(health=lambda *_,**__: {"scenario_id":engine.state()["scenario_id"],"satellite_epoch":engine.state()["epoch"]})
        def snapshot(_):
            packet=engine.evidence(engine.state()["scenario_id"])["packets"][-1]
            value=_bootstrap_snapshot(packet)
            if kind=="stale":
                value["driver_time"]=None
                for item in value["items"]:
                    item["freshness"]="STALE"
                    item["received_at_unix_ns"]=str(int(item["acquired_at_unix_ns"])+10_000_000_000)
            return value
        executor.supervisor=SimpleNamespace(observation_anchor_provider=SimpleNamespace(snapshot=snapshot))
        spec=subject_execution_spec(subject,case)
        state=executor._prepare(subject,case)
        physical=engine.evidence(state["scenario_id"])
        assert state["epoch"]!=outer["epoch"] and physical["initial_state"]["core"]["tick"]==0
        expected=deepcopy(SatelliteDatabase.load().material["initial_state"])
        for group,values in spec["initial_state"].items():expected[group].update(values)
        expected["bus"]["nominal_bus_voltage_mv"]=spec["initial_state"]["bus"]["bus_voltage_mv"]
        assert all(physical["initial_state"][group]==values for group,values in expected.items())
        assert physical["faults"]==spec["faults"] and physical["commands"]==[]
        retired=engine.evidence(outer["scenario_id"])
        assert retired["final_state"]["core"]["tick"]==100
        assert retired["retirement"]["next_scenario_id"]==state["scenario_id"]
        assert engine.state()["running"] is True
    finally:engine.close()


def test_readiness_diagnostic_keeps_complete_bounded_json_and_counts(tmp_path):
    import json
    from backend.dss_scenarios import readiness_diagnostic,subject_execution_spec
    from dss.catalog import TELEMETRY_ITEMS
    epoch="epoch-"+"e"*64
    snapshot={"driver_time":{"source_epoch":"x"*76,"source_sequence":"18446744073709551615",
        "uncertainty_ns":"1000","private":"NEVER_PRINT_SECRET"},"items":[
        {"item_id":row["item_id"],"source_epoch":"y"*76,"source_sequence":"18446744073709551615",
            "freshness":"STALE","quality":"GOOD","validity":"VALID","synchronization_state":"COMPLETE",
            "engineering_value":"NEVER_PRINT_VALUE"} for row in TELEMETRY_ITEMS]}
    result=readiness_diagnostic(snapshot,{"epoch":epoch},subject_execution_spec("case:diagnostic",{}))
    data=json.loads(result)
    assert data["old_epoch_count"]==data["unacceptable_count"]==22 and data["missing_count"]==0
    assert len(data["items"])==2 and len(result)<=4096 and "NEVER_PRINT" not in result
    assert data["clock"]["source_epoch"]=="x"*76 and data["items"][1]["source_epoch"]=="y"*76


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


def _native_action_receipt(kind="NUM", *, automatic=True, wire="2.5", ordinal=1, abort=False):
    """Public prompt/audit DTOs; literal wire values are independent test oracles."""
    import uuid
    identity = lambda offset: str(uuid.UUID(int=ordinal * 10 + offset))
    actor = "operator-reconciler" if automatic else "qualification-operator"
    outcome = "CANCELLED" if abort else "ANSWERED"
    prompt = {"id": identity(1), "execution_id": "prompt-test-execution", "step_index": (ordinal-1)*2,
        "revision": 2, "state": "SETTLED", "type": kind, "prompt_profile": "spell-lrm244/0.17",
        "question": "Prompt " + str(ordinal), "list_mode": "KEY" if kind == "LIST" else None,
        "options": [{"key":"A","label":"Primary"},{"key":"B","label":"Backup"}] if kind == "LIST" else [],
        "default": wire if automatic else None, "opened_at": "2026-10-04T12:00:00+00:00",
        "response_deadline": "2026-10-04T12:00:01+00:00" if automatic else None,
        "warning_at": None, "warning_emitted_at": None,
        "settings": {"PROMPT_PROFILE":"spell-lrm244/0.17", "PROMPT_RESPONSE_TIMEOUT":1.0 if automatic else None,
            "PROMPT_WARNING_DELAY":None, "NO_CONTROLLER_GRACE":None},
        "settlement": {"id":identity(2),"actor":actor,"outcome":outcome,"value":None if abort else wire,
            "settled_at":"2026-10-04T12:00:01.250000+00:00"}}
    payload = {"prompt_id":prompt["id"], "settlement_id":prompt["settlement"]["id"],
        "outcome":outcome if automatic else "ACCEPTED_SETTLEMENT"}
    if not automatic:payload.update(attempt_id=identity(3),settlement_outcome=outcome)
    audit = [{"id":identity(4), "sequence":ordinal, "event_type":"prompt.settled",
        "aggregate_type":"operator_prompt", "aggregate_id":prompt["id"], "actor":actor,
        "created_at":prompt["settlement"]["settled_at"], "payload":payload}]
    return prompt, audit


@pytest.mark.parametrize("kind,automatic,wire,requested,expected", [
    ("NUM",True,"2.5",2.5,2.5), ("NUM",False,"3.5","3.5",3.5),
    ("YES_NO",True,"NO","NO","NO"), ("LIST",False,"A","A","A"),
    ("ALPHA",False,"qualification","qualification","qualification"),
    ("OK_CANCEL",False,"CANCEL","CANCEL","CANCEL"),
], ids=["numeric-default","numeric-explicit","default-no","list-key","text","cancel-is-value"])
def test_native_prompt_receipt_preserves_canonical_wire_and_typed_result(kind,automatic,wire,requested,expected):
    from scripts.dss_prompt_validation import validate_native_prompt_action
    prompt,audit=_native_action_receipt(kind,automatic=automatic,wire=wire)
    original=deepcopy((prompt,audit))
    actual=validate_native_prompt_action(prompt,{"action":"await_default" if automatic else "answer","value":requested},
        audit,execution_id=prompt["execution_id"],expected_prompt_id=prompt["id"])
    assert type(actual) is type(expected) and actual == expected
    assert (prompt,audit) == original


@pytest.mark.parametrize("mutation", [
    "float-wire","boolean-wire","noncanonical-wire","nonfinite-wire","wrong-value","wrong-actor",
    "wrong-outcome","foreign-prompt","foreign-execution","settlement-id","missing-audit","duplicate-audit",
    "audit-prompt","audit-settlement","audit-actor","audit-outcome","no-deadline","early-settlement",
    "wrong-deadline","boolean-timeout","wrong-default","wrong-audit-time",
])
def test_native_numeric_default_rejects_forged_wire_authority_and_deadline(mutation):
    from scripts.dss_prompt_validation import validate_native_prompt_action
    prompt,audit=_native_action_receipt()
    prompt_id=prompt["id"]
    if mutation == "float-wire":prompt["settlement"]["value"]=2.5
    elif mutation == "boolean-wire":prompt["settlement"]["value"]=True
    elif mutation == "noncanonical-wire":prompt["settlement"]["value"]="2.50"
    elif mutation == "nonfinite-wire":prompt["settlement"]["value"]="NaN"
    elif mutation == "wrong-value":prompt["settlement"]["value"]="3.5"
    elif mutation == "wrong-actor":prompt["settlement"]["actor"]=audit[0]["actor"]="qualification-operator"
    elif mutation == "wrong-outcome":prompt["settlement"]["outcome"]=audit[0]["payload"]["outcome"]="TIMED_OUT"
    elif mutation == "foreign-prompt":prompt["id"]="00000000-0000-0000-0000-000000000099"
    elif mutation == "foreign-execution":prompt["execution_id"]="another-execution"
    elif mutation == "settlement-id":prompt["settlement"]["id"]="00000000-0000-0000-0000-000000000099"
    elif mutation == "missing-audit":audit=[]
    elif mutation == "duplicate-audit":audit.append(deepcopy(audit[0]))
    elif mutation == "audit-prompt":audit[0]["payload"]["prompt_id"]="another-prompt"
    elif mutation == "audit-settlement":audit[0]["payload"]["settlement_id"]="another-settlement"
    elif mutation == "audit-actor":audit[0]["actor"]="another-operator"
    elif mutation == "audit-outcome":audit[0]["payload"]["outcome"]="ACCEPTED_SETTLEMENT"
    elif mutation == "no-deadline":prompt["response_deadline"]=None
    elif mutation == "early-settlement":prompt["settlement"]["settled_at"]="2026-10-04T12:00:00.999999+00:00"
    elif mutation == "wrong-deadline":prompt["response_deadline"]="2026-10-04T12:00:02+00:00"
    elif mutation == "boolean-timeout":prompt["settings"]["PROMPT_RESPONSE_TIMEOUT"]=True
    elif mutation == "wrong-default":prompt["default"]="3.5"
    else:audit[0]["created_at"]="2026-10-04T12:00:01.249999+00:00"
    with pytest.raises(ValueError):
        validate_native_prompt_action(prompt,{"action":"await_default","value":2.5},audit,
            execution_id="prompt-test-execution",expected_prompt_id=prompt_id)


def test_native_prompt_abort_remains_distinct_from_cancel_answer():
    from scripts.dss_prompt_validation import validate_native_prompt_action
    prompt,audit=_native_action_receipt("OK_CANCEL",automatic=False,wire="CANCEL",abort=True)
    assert validate_native_prompt_action(prompt,{"action":"abort"},audit,
        execution_id=prompt["execution_id"]) is None
    with pytest.raises(ValueError):
        validate_native_prompt_action(prompt,{"action":"answer","value":"CANCEL"},audit,
            execution_id=prompt["execution_id"])


@pytest.mark.parametrize("mode", ["default","explicit","missing-default-audit","wrong-default-value"])
def test_four_prompt_producer_never_advances_actions_on_repeated_stale_prompt_ids(tmp_path,monkeypatch,mode):
    """Exercise the real producer loop with scripted API DTOs, not live DSS evidence."""
    from types import SimpleNamespace
    from scripts import qualify_dss_v19 as producer
    from backend import dss_capture,dss_scenarios
    default=mode != "explicit"
    definition=next(row for row in scenario_definitions() if row["id"] == (
        "prompt-warning-default" if default else "prompt-cancel-is-value"))
    wires=["A" if default else "B","2.5" if default else "3.5",
        "qualification" if default else "backup","OK" if default else "CANCEL"]
    receipts=[_native_action_receipt(kind,automatic=default and index==1,wire=wire,ordinal=index+1)
        for index,(kind,wire) in enumerate(zip(["LIST","NUM","ALPHA","OK_CANCEL"],wires))]
    prompts=[row[0] for row in receipts]
    audits=[audit for _,rows in receipts for audit in rows]
    prompts[0]["warning_emitted_at"]="2026-10-04T12:00:01+00:00" if default else None
    if default:audits.insert(0,{"event_type":"prompt.warning_due","aggregate_id":prompts[0]["id"],
        "aggregate_type":"operator_prompt","actor":"operator-reconciler","payload":{"prompt_id":prompts[0]["id"]}})
    execution={"id":"prompt-test-execution","state":"prompting","revision":1,"variables":{}}
    snapshots=[]
    for index,prompt in enumerate(prompts):
        active={**deepcopy(prompt),"state":"OPEN","settlement":None,"revision":1}
        if index==0 and default:
            snapshots.append({"execution":deepcopy(execution),"active_prompt":{**active,"warning_emitted_at":None}})
        # Previous already-handled IDs reappear even after the next prompt opens.
        snapshots.extend({"execution":deepcopy(execution),"active_prompt":deepcopy(active)} for _ in range(3))
        if index:
            snapshots.append({"execution":deepcopy(execution),"active_prompt":deepcopy(prompts[index-1])})
    snapshots.append({"execution":{**execution,"state":"completed","variables":definition["expected"]["variables"]},"active_prompt":None})
    if mode=="missing-default-audit":audits=[row for row in audits if row.get("aggregate_id")!=prompts[1]["id"]]
    if mode=="wrong-default-value":prompts[1]["settlement"]["value"]="3.5"
    posted=[]
    def backend(path,body=None,**kwargs):
        if path=="/api/v1/telemetry/snapshot?context_id=simulator":return {}
        if path=="/api/v1/executions":return {"execution":execution}
        if path.endswith("/snapshot"):
            assert snapshots, "producer exhausted its bounded scripted prompt sequence"
            return snapshots.pop(0)
        if path.endswith("/control"):
            assert body["action"]=="ACQUIRE"
            return {"control_lease":{"id":"lease","revision":1,"control_fencing_token":1}}
        if path.endswith("/responses"):
            posted.append((path.split("/")[-2],body["action"],body["value"]))
            return {}
        if path.endswith("/report"):return {"typed_prompts":prompts,"operator_audit":audits}
        if path.startswith("/api/v1/procedures/"):
            return {"source":(producer.ROOT/"procedures/prompt_workflow_v17.spell.py").read_text(encoding="utf-8")}
        raise AssertionError(path)
    clock=[0.0]
    monkeypatch.setattr(producer,"time",SimpleNamespace(monotonic=lambda:clock[0],sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds)))
    monkeypatch.setattr(dss_scenarios,"snapshot_matches_scenario",lambda *args:True)
    controls=[]
    monkeypatch.setattr(dss_capture,"set_running",lambda _call,running,**kwargs:controls.append(running))
    monkeypatch.setattr(dss_capture,"collect_evidence",lambda *args,**kwargs:{"scenario_id":"prompt-scenario","epoch":"epoch-unit","packets":[]})
    qualifier=producer.DeliveryQualifier.__new__(producer.DeliveryQualifier)
    qualifier.logs=tmp_path
    qualifier.backend=SimpleNamespace(call=backend)
    qualifier.dss=SimpleNamespace(call=lambda *args:None)
    qualifier.reset=lambda *args:{"scenario_id":"prompt-scenario","epoch":"epoch-unit"}
    qualifier.events=lambda _id:[]
    if mode.startswith(("missing-","wrong-")):
        with pytest.raises(ValueError):qualifier.run_procedure(definition["id"],"prompt_workflow_v17",definition["operator_actions"])
        assert not (tmp_path/(definition["id"]+".json")).exists()
        import json
        retained=json.loads((tmp_path/(definition["id"]+"-failed.json")).read_bytes())
        assert retained["decision"]=="FAIL" and retained["report"]["typed_prompts"]==prompts
        assert retained["capture"]["driver"]==[] and retained["capture"]["dss"]["packets"]==[]
    else:
        capture=qualifier.run_procedure(definition["id"],"prompt_workflow_v17",definition["operator_actions"])
        assert capture["execution"]["state"]=="completed"
        assert type(capture["execution"]["variables"]["rate"]) is float
        assert capture["execution"]["variables"]["rate"]==(2.5 if default else 3.5)
    assert not snapshots
    assert posted==[(prompt["id"],"COMMIT",wire) for index,(prompt,wire) in enumerate(zip(prompts,wires)) if not(default and index==1)]
    assert controls==[True,False]


@pytest.mark.parametrize("mode",["default","explicit","stripped-profile","wrong-wire"])
def test_independent_procedure_oracle_checks_native_wire_without_legacy_fallback(monkeypatch,mode):
    """Isolate report prompt semantics; transport execution has separate real proofs."""
    from scripts import validate_dss_delivery as validator
    default=mode != "explicit"
    definition=next(row for row in scenario_definitions() if row["id"] == (
        "prompt-warning-default" if default else "prompt-cancel-is-value"))
    wires=["A" if default else "B","2.5" if default else "3.5",
        "qualification" if default else "backup","OK" if default else "CANCEL"]
    receipts=[_native_action_receipt(kind,automatic=default and index==1,wire=wire,ordinal=index+1)
        for index,(kind,wire) in enumerate(zip(["LIST","NUM","ALPHA","OK_CANCEL"],wires))]
    prompts=[row[0] for row in receipts]
    audits=[audit for _,rows in receipts for audit in rows]
    if default:audits.append({"event_type":"prompt.warning_due"})
    if mode=="stripped-profile":prompts[1].pop("prompt_profile")
    if mode=="wrong-wire":prompts[1]["settlement"]["value"]=2.5
    source=(validator.ROOT/definition["subject"].removeprefix("procedure:")).read_bytes()
    execution={"id":"prompt-test-execution","state":"completed","procedure_hash":sha256(source),
        "variables":deepcopy(definition["expected"]["variables"])}
    capture={"execution":execution,"procedure":{"source":source.decode()},
        "actions":definition["operator_actions"],"typed_prompts":prompts,"operator_audit":audits,
        "initial_dss_state":{},"dss":{"scenario_id":"unit","epoch":"unit","faults":{},"commands":[]},
        "events":[{"execution_id":execution["id"],"sequence":index+1,"event_type":"procedure.log",
            "payload":{"message":message}} for index,message in enumerate(definition["expected"]["logs"])]}
    monkeypatch.setattr(validator,"validate_execution_spec",lambda *args:None)
    monkeypatch.setattr(validator,"validate_transport_capture",lambda *args,**kwargs:{"executed_commands":0,"loaded_unexecuted_commands":0})
    monkeypatch.setattr(validator,"validate_outer_source_execution",lambda *args:[])
    monkeypatch.setattr(validator,"_validate_stage_receipts",lambda *args:None)
    if mode in {"stripped-profile","wrong-wire"}:
        with pytest.raises(ValueError):validator.observed_procedure(capture,definition)
    else:
        assert validator.observed_procedure(capture,definition)==definition["expected"]


def _linux_pytest_report_receipt(data):
    import hashlib
    return {'name':'postgresql.xml','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':'644'}


def test_linux_pytest_report_copy_keeps_the_exact_report_bytes():
    from scripts.qualify_next import validate_pytest_report_copy
    data=b'<testsuites><testsuite><testcase classname="actual" name="result"/></testsuite></testsuites>'
    assert validate_pytest_report_copy('postgresql.xml',_linux_pytest_report_receipt(data),data) is None


@pytest.mark.parametrize('tamper',['same-size-case','truncated','wrong-name','executable','boolean-size','invalid-xml','empty-cases'])
def test_linux_pytest_report_copy_rejects_changed_or_invalid_evidence(tamper):
    from scripts.qualify_next import validate_pytest_report_copy
    data=b'<testsuites><testsuite><testcase classname="actual" name="result"/></testsuite></testsuites>'
    receipt=_linux_pytest_report_receipt(data)
    if tamper=='same-size-case':data=data.replace(b'result',b'forged')
    elif tamper=='truncated':data=data[:-1]
    elif tamper=='wrong-name':receipt['name']='candidate.xml'
    elif tamper=='executable':receipt['mode']='755'
    elif tamper=='boolean-size':receipt['bytes']=True
    elif tamper=='invalid-xml':
        data=b'<testsuites>'
        receipt=_linux_pytest_report_receipt(data)
    elif tamper=='empty-cases':
        data=b'<testsuites><testsuite tests="0"/></testsuites>'
        receipt=_linux_pytest_report_receipt(data)
    with pytest.raises(ValueError):validate_pytest_report_copy('postgresql.xml',receipt,data)


@pytest.mark.parametrize('tamper',['volume','source','marker','missing-labels'])
def test_linux_pytest_report_volume_rejects_foreign_ownership(tamper):
    from copy import deepcopy
    from scripts.qualify_next import require_pytest_evidence_owner
    expected={'volume':'spell-v19-pytest-evidence-owned','source_commit':'a'*40,'marker':'b'*32}
    original={'Name':expected['volume'],'Labels':{'openbexi.qualification.source':expected['source_commit'],
              'openbexi.qualification.evidence':expected['marker']}}
    require_pytest_evidence_owner(original,expected)
    changed=deepcopy(original)
    if tamper=='volume':changed['Name']='foreign-evidence'
    elif tamper=='source':changed['Labels']['openbexi.qualification.source']='c'*40
    elif tamper=='marker':changed['Labels']['openbexi.qualification.evidence']='d'*32
    elif tamper=='missing-labels':changed['Labels']={}
    with pytest.raises(ValueError):require_pytest_evidence_owner(changed,expected)


@pytest.mark.parametrize('tamper',['extra-file','symlink','directory'])
def test_linux_pytest_report_inventory_rejects_noncanonical_entries(tmp_path,tamper):
    import subprocess,sys
    from scripts.qualify_next import PYTEST_REPORT_AUDIT
    snapshot=tmp_path/'snapshot';snapshot.mkdir()
    report=snapshot/'postgresql.xml'
    report.write_bytes(b'<testsuites><testsuite><testcase name="actual"/></testsuite></testsuites>')
    if tamper=='extra-file':(snapshot/'unbound.xml').write_bytes(report.read_bytes())
    elif tamper=='symlink':
        target=tmp_path/'outside.xml';target.write_bytes(report.read_bytes());report.unlink();report.symlink_to(target)
    else:report.unlink();report.mkdir()
    code=PYTEST_REPORT_AUDIT.replace("root=Path('/snapshot')","root=Path(sys.argv[2])")
    actual=subprocess.run([sys.executable,'-c',code,'postgresql.xml',str(snapshot)],capture_output=True)
    assert actual.returncode!=0 and not actual.stdout


def test_pytest_report_mount_uses_linux_storage_and_preserves_read_only_source(monkeypatch):
    from scripts import qualify_next as producer
    monkeypatch.setattr(producer,'LINUX_SOURCE',{'volume':'owned-linux-source'})
    monkeypatch.setattr(producer,'LINUX_PYTEST_EVIDENCE',{'volume':'fresh-linux-report'})
    command=producer.docker_python('-m','pytest','backend/tests','--junitxml=/evidence/postgresql.xml')
    mounts=[command[index+1] for index,value in enumerate(command) if value=='-v']
    assert 'owned-linux-source:/workspace:ro' in mounts
    assert f"{(producer.ROOT/'.git').as_posix()}:/workspace/.git:ro" in mounts
    assert 'fresh-linux-report:/evidence' in mounts
    assert f'{producer.OUT.as_posix()}:/evidence' not in mounts


def test_failed_pytest_command_retains_its_actual_report_before_rejection(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from scripts import qualify_next as producer
    monkeypatch.setattr(producer,'OUT',tmp_path)
    monkeypatch.setattr(producer.subprocess,'run',lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout=b'actual failure',stderr=b''))
    controller=producer.Producer.__new__(producer.Producer)
    controller.gate='postgresql';controller.source='a'*40;controller.commands=[]
    controller.pytest_evidence={'volume':'owned-linux-report'}
    collected=[]
    def collect(evidence):
        assert controller.commands[0]['returncode']==1
        assert (tmp_path/'postgresql-00.log').read_bytes()==b'actual failure'
        (tmp_path/'postgresql.xml').write_bytes(b'actual failed report')
        collected.append(evidence)
    monkeypatch.setattr(producer,'collect_linux_pytest_evidence',collect)
    with pytest.raises(ValueError):controller.run(['docker','run','--rm','image','-m','pytest'])
    assert collected==[controller.pytest_evidence]
    assert (tmp_path/'postgresql.xml').read_bytes()==b'actual failed report'
