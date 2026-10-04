"""Independently validate exhaustive, source-bound DSS delivery evidence.

This validator deliberately distinguishes an executed negative test from an
unexecuted requirement. A missing case, skipped environment or synthetic service
substitution cannot satisfy a required DSS execution.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "spell.dss.delivery/1"
MANIFEST_SCHEMA = "spell.dss.procedure-scenarios/1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
V10_GOLDEN_SHA256 = "14192c9d991b33b502b080539db62a0f0ebfd476d7ee1830c1eb53bfdbd72c74"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class CaptureStore(Mapping):
    """Operation-local, hash-checked sidecars with at most two decoded objects.

    Every lookup rereads the file, including cache hits. A later same-size
    mutation cannot reuse an earlier successful integrity check.
    """

    def __init__(self, directory: Path, references: dict):
        require(type(references) is dict and references, "raw DSS captures are missing")
        self.directory = Path(directory)
        self.references = {}
        self._cache = OrderedDict()
        total_size = 0
        for capture_hash, reference in references.items():
            require(type(capture_hash) is str and HEX64.fullmatch(capture_hash) is not None
                    and type(reference) is dict and set(reference) == {"path", "size"}
                    and reference["path"] == capture_hash + ".json" and type(reference["size"]) is int
                    and 0 < reference["size"] <= 16_000_000, "DSS capture reference is malformed")
            total_size += reference["size"]
            require(total_size <= 512_000_000, "DSS total capture size exceeds bound")
            self.references[capture_hash] = dict(reference)
        require({path.name for path in self.directory.iterdir()} ==
                {reference["path"] for reference in self.references.values()},
                "DSS capture directory has unreferenced files")

    def __iter__(self):
        return iter(self.references)

    def __len__(self):
        return len(self.references)

    def __getitem__(self, capture_hash):
        reference = self.references[capture_hash]
        path = self.directory / reference["path"]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == reference["size"],
                "DSS capture file missing or size differs")
        data = path.read_bytes()
        require(len(data) == reference["size"] and sha256(data) == capture_hash,
                "DSS capture file digest differs")
        if capture_hash in self._cache:
            self._cache.move_to_end(capture_hash)
            return self._cache[capture_hash]
        # Evict before decoding, so the store never retains a third archive.
        if len(self._cache) == 2:
            self._cache.popitem(last=False)
        capture = json.loads(data)
        require(type(capture) is dict and sha256(canonical(capture)) == capture_hash,
                "DSS raw capture digest differs")
        self._cache[capture_hash] = capture
        return capture


def _release_minor(release: str) -> int:
    match = re.fullmatch(r"v0\.([1-9][0-9]*)\.0", release) if type(release) is str else None
    require(match is not None, "unsupported DSS release identity")
    return int(match[1])


def _definition(identity: str, kind: str, **fields: Any) -> dict:
    value = {"id": identity, "kind": kind, **fields}
    return {**value, "definition_sha256": sha256(canonical(value))}


def source_inventory(release: str = "v0.19.0", *, root: Path = ROOT) -> list[dict]:
    """Recompute identities from source, never from reported totals or results."""
    minor = _release_minor(release)
    registry = importlib.import_module(f"backend.language_conformance_v{minor}")
    from backend.dss_scenarios import subject_execution_spec,procedure_execution_spec
    rows = []
    for path in sorted((root / "procedures").rglob("*.spell.py")):
        relative = path.relative_to(root).as_posix()
        rows.append(_definition("procedure:" + relative, "PROCEDURE",
            source_path=relative, source_sha256=sha256(path.read_bytes()),execution_spec={"scenarios":"EXACT_DECLARED_PROCEDURE_SCENARIOS"}))
    require(bool(rows), "procedure inventory is empty")
    for case in registry.CASES:
        require(case["source_sha256"] == sha256(case["source"].encode("utf-8")),
                "language source hash differs: " + case["id"])
        rows.append(_definition("case:" + case["id"], "LANGUAGE_CASE",
            source_sha256=case["source_sha256"], oracle=registry._expected_result(case),
            execution_kind="EXPECTED_REJECTION" if case["expected_diagnostic"] else "DIRECT_SOURCE",
            execution_spec=subject_execution_spec("case:"+case["id"],case)))
    golden_path = root / "artifacts/v0.10/reference-examples.json"
    require(sha256(golden_path.read_bytes()) == V10_GOLDEN_SHA256,
            "immutable reference qualification identity differs")
    golden = json.loads(golden_path.read_bytes())
    variants = json.loads((root / "contracts/v10/language_reference_variant_matrix.json").read_bytes())
    examples = json.loads((root / "contracts/v10/language_reference_example_matrix.json").read_bytes())
    require([item["example_number"] for item in golden["results"]] == list(range(1, 196)),
            "reference example identities differ")
    matrix_rows = examples.get("examples", examples.get("rows"))
    require(type(matrix_rows) is list and len(matrix_rows) == 195, "example matrix is incomplete")
    variant_rows = {item["example_number"]: item for item in variants["examples"]}
    for example in golden["results"]:
        number = example["example_number"]
        matrix = next(item for item in matrix_rows if item["example_number"] == number)
        identity = f"adaptation:{number:03}"
        rows.append(_definition(identity, "REFERENCE_ADAPTATION", example_number=number,
            source_binding_sha256=sha256(canonical(matrix)), oracle=example,
            execution_kind="BOUNDED_ADAPTATION", raw_snippet_execution_claim=False,
            execution_spec=subject_execution_spec(identity,{})))
        proofs = {item["variant_id"]: item for item in example["variant_proofs"]}
        for variant in variant_rows[number]["variants"]:
            rows.append(_definition("variant:" + variant["variant_id"], "REFERENCE_VARIANT",
                parent=identity, source_binding_sha256=sha256(canonical(variant)),
                oracle=proofs[variant["variant_id"]],execution_spec={"same_execution_as":identity}))
    all_targets = [f"adaptation:{number:03}" for number in range(1, 196)] + [
        "case:" + case["id"] for case in registry.CASES]
    require(registry.ALL_SELECTION == len(all_targets), "runner selection boundary differs")
    for selection, target in enumerate(all_targets):
        rows.append(_definition(f"menu:{selection:03}", "MENU_SELECTION",
            selection=selection, targets=[target], cases_sha256=registry.CASESET_SHA256,
            execution_spec=procedure_execution_spec([{"action":"answer","value":selection}],{},brokered=True)))
    rows.append(_definition(f"menu:{registry.ALL_SELECTION:03}", "MENU_SELECTION",
        selection=registry.ALL_SELECTION, targets=all_targets, cases_sha256=registry.CASESET_SHA256,
        execution_spec=procedure_execution_spec([{"action":"answer","value":registry.ALL_SELECTION}],{},run_all=True,brokered=True)))
    identities = [row["id"] for row in rows]
    require(len(identities) == len(set(identities)), "duplicate required DSS identity")
    return sorted(rows, key=lambda row: row["id"])


def load_manifest(release: str = "v0.19.0", *, root: Path = ROOT) -> dict:
    path = root / f"contracts/dss/procedure_scenarios_v{_release_minor(release)}.json"
    require(path.is_file() and path.stat().st_size <= 8_000_000, "DSS scenario manifest is missing or oversized")
    manifest = json.loads(path.read_bytes())
    require(set(manifest) == {"schema_version", "release", "inventory", "inventory_sha256", "scenarios"},
            "DSS manifest fields differ")
    require(manifest["schema_version"] == MANIFEST_SCHEMA and manifest["release"] == release,
            "DSS manifest version differs")
    inventory = source_inventory(release, root=root)
    require(canonical(manifest["inventory"]) == canonical(inventory), "DSS inventory is stale or incomplete")
    require(manifest["inventory_sha256"] == sha256(canonical(inventory)), "DSS inventory digest differs")
    scenarios = manifest["scenarios"]
    require(type(scenarios) is list and scenarios, "DSS scenarios are missing")
    require(len({row["id"] for row in scenarios}) == len(scenarios), "duplicate DSS scenario")
    producer=importlib.import_module(f"scripts.qualify_dss_v{_release_minor(release)}")
    require(canonical(scenarios)==canonical(producer.scenario_definitions()),"DSS scenario inputs or independent oracles differ from reviewed source")
    for row in scenarios:
        require(set(row) == {"id", "subject", "inputs", "operator_actions", "expected", "definition_sha256"},
                "DSS scenario fields differ")
        require(row["definition_sha256"] == sha256(canonical({key: value for key, value in row.items()
            if key != "definition_sha256"})), "DSS scenario digest differs")
    subjects = {row["subject"] for row in scenarios}
    require({row["id"] for row in inventory if row["kind"] == "PROCEDURE"} <= subjects,
            "a procedure has no explicit DSS scenario")
    return manifest


def reproduction_metadata(release: str, *, root: Path = ROOT) -> dict:
    """Describe the reviewed commands and exact input files, without credentials."""
    import inspect
    from dss.catalog import SatelliteDatabase
    from dss.server import DssRuntime
    minor = _release_minor(release)
    producer = importlib.import_module(f"scripts.qualify_dss_v{minor}")
    manifest_path = f"contracts/dss/procedure_scenarios_v{minor}.json"
    mapping_path = f"contracts/dss/reference_adapters_v{minor}.json"
    mappings = (root / mapping_path).read_bytes()
    require(canonical(json.loads(mappings)) == canonical(producer.reference_mapping()),
            "DSS reference adapter contract is stale")
    tick_ns = SatelliteDatabase.load(root / "contracts/dss/satellite_database.json").material["dynamics"]["tick_ns"]
    interval_ns = round(inspect.signature(DssRuntime).parameters["tick_seconds"].default * 1_000_000_000)
    require(type(tick_ns) is int and tick_ns > 0 and interval_ns % tick_ns == 0,
            "DSS publication cadence differs from the reviewed physics clock")
    wrapper = f"scripts/run_release_v{minor}.ps1"
    return {
        "working_directory": "REPOSITORY_ROOT",
        "prepare_command": ["powershell", "-File", wrapper, "-Module", "scripts.qualify_next", "-Arguments", "prepare"],
        "delivery_command": ["powershell", "-File", wrapper, "-Module", "scripts.qualify_next", "-Arguments", "dss-validation"],
        "container_producer_command": ["python", "-m", f"scripts.qualify_dss_v{minor}",
            "--backend-url", "http://proxy:8080", "--dss-url", "http://dss:8081/api/v1",
            "--bindings", "/evidence/dss-bindings.json", "--output", "/evidence/dss-validation.json"],
        "scenario_manifest": {"path": manifest_path, "sha256": sha256((root / manifest_path).read_bytes())},
        "reference_mappings": {"path": mapping_path, "sha256": sha256(mappings)},
        "runtime_configuration": {"automatic_interval_ns": interval_ns,
            "physics_tick_ns": tick_ns, "physics_ticks_per_frame": interval_ns // tick_ns},
        "credentials": "PARENT_ONLY_RENEWABLE_OPERATOR_TOKEN_FILE",
        "scenario_inputs": "EXACT_MANIFEST_EXECUTION_SPEC_AND_OPERATOR_ACTIONS",
    }


def delivery_counts(inventory: list[dict], results: list[dict], scenarios: list[dict], captures: dict) -> dict:
    """Convenient totals only; all identities and raw proofs are validated separately."""
    return {"required_inventory": len(inventory),
        "inventory_by_kind": {kind: sum(row["kind"] == kind for row in inventory)
            for kind in sorted({row["kind"] for row in inventory})},
        "expected_compiler_rejections": sum(row.get("execution_kind") == "EXPECTED_REJECTION" for row in inventory),
        "results_passed": sum(row.get("status") == "PASS" for row in results),
        "scenarios_required": len(scenarios),
        "scenarios_passed": sum(row.get("status") == "PASS" for row in scenarios),
        "capture_files": len(captures)}


def validate_report(report: dict, *, source_commit: str, image_ids: dict[str, str],
                    database_identity: dict | None = None, root: Path = ROOT,
                    capture_root: Path | None = None) -> None:
    """Reject incomplete delivery evidence; caller supplies independently pinned bindings."""
    require(type(report) is dict and len(canonical(report)) <= 32_000_000,
            "DSS report is invalid or oversized")
    required = {"schema_version", "release", "source_commit", "image_ids", "database_identity",
                "inventory_sha256", "decision", "full_language_compatibility", "results", "scenarios", "raw_captures",
                "reproduction", "counts"}
    require(set(report) == required, "DSS report fields differ")
    require(report["schema_version"] == SCHEMA and report["decision"] == "PASS",
            "DSS delivery did not pass")
    require(report["full_language_compatibility"] is False, "DSS evidence cannot assert full language compatibility")
    require(type(source_commit) is str and HEX40.fullmatch(source_commit) is not None
            and report["source_commit"] == source_commit, "DSS source commit differs")
    require(type(image_ids) is dict and set(image_ids) == {"backend", "driver", "dss", "kafka", "frontend", "proxy"}
            and all(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in image_ids.values())
            and canonical(report["image_ids"]) == canonical(image_ids), "DSS image identities differ")
    from dss import SIMULATOR_VERSION, DYNAMICS_ENGINE_VERSION
    from dss.catalog import SatelliteDatabase
    database = SatelliteDatabase.load(root / "contracts/dss/satellite_database.json")
    expected_database = {"satellite_id":"GENERIC", "revision":database.revision, "sha256":database.digest,
        "simulator_version":SIMULATOR_VERSION, "dynamics_engine_version":DYNAMICS_ENGINE_VERSION}
    require(database_identity is None or canonical(database_identity) == canonical(expected_database),
            "caller DSS database identity differs from source")
    require(canonical(report["database_identity"]) == canonical(expected_database), "DSS database identity differs")
    require(canonical(report["reproduction"]) == canonical(reproduction_metadata(report["release"], root=root)),
            "DSS reproduction commands or configuration differ from source")
    manifest = load_manifest(report["release"], root=root)
    require(report["inventory_sha256"] == manifest["inventory_sha256"], "DSS report inventory differs")
    expected_scenarios = {row["id"]: row for row in manifest["scenarios"]}
    actual_scenarios = report["scenarios"]
    require(type(actual_scenarios) is list and len(actual_scenarios) == len(expected_scenarios)
            and len({row.get("id") for row in actual_scenarios}) == len(actual_scenarios)
            and {row.get("id") for row in actual_scenarios} == set(expected_scenarios),
            "missing, duplicate or unexpected DSS scenario")
    require([row["id"] for row in actual_scenarios] == list(expected_scenarios),
            "DSS scenario order differs from the reviewed manifest")
    references = report["raw_captures"]
    require(type(references) is dict and references, "raw DSS captures are missing")
    require(capture_root is not None,"DSS capture directory is required")
    captures = CaptureStore(capture_root, references)
    referenced={row.get("evidence",{}).get("raw_capture_sha256") for row in report["results"]+report["scenarios"]}
    executed_names, telemetry_names = set(), set()
    # Stream the complete integrity/coverage audit. Retain only identities, not
    # hundreds of decoded packet archives alongside the later semantic checks.
    for capture_hash in captures:
        capture = captures[capture_hash]
        referenced.update(capture.get("subject_capture_refs", {}).values())
        physical = (capture["subject_result"]["dss_evidence"]["capture"] if "subject_result" in capture
                    else capture if "dss" in capture else None)
        if physical is not None:
            executed_names.update(row["definition"]["command_name"] for row in physical["dss"]["commands"] if row["executed"] == 1)
            telemetry_names.update(item["item_id"] for packet in physical["driver"]
                                   if packet["topic"] == "openbexi.GENERIC.tm" for item in packet["body"]["items"])
        del capture, physical
    require(referenced==set(captures),"DSS report omits or includes unreferenced raw captures")
    require(executed_names=={row["name"] for row in database.commands},"DSS delivery did not execute every shared command definition")
    require(telemetry_names=={row["item_id"] for row in database.telemetry},"DSS delivery did not decode every shared telemetry definition")
    definitions = {row["id"]: row for row in manifest["inventory"]}
    results = report["results"]
    require(type(results) is list and len(results) == len(definitions), "missing or extra DSS results")
    require(len({row.get("id") for row in results}) == len(results)
            and {row.get("id") for row in results} == set(definitions), "DSS result identities differ")
    by_id = {row["id"]: row for row in results}
    for identity, definition in definitions.items():
        result = by_id[identity]
        require(set(result) == {"id", "definition_sha256", "status", "observed", "evidence"},
                "DSS result fields differ: " + identity)
        require(result["status"] == "PASS" and result["definition_sha256"] == definition["definition_sha256"],
                "unexecuted, stale or failing DSS result: " + identity)
        if "oracle" in definition:
            require(canonical(result["observed"]) == canonical(definition["oracle"]),
                    "DSS semantic oracle differs: " + identity)
        _validate_evidence(result["evidence"], identity, captures, source_commit)
        capture=captures[result["evidence"]["raw_capture_sha256"]]
        if definition["kind"] == "MENU_SELECTION":
            require(result["observed"] == {"selection": definition["selection"], "targets": definition["targets"]},
                    "DSS menu selected different cases")
            require(result["evidence"]["mode"] == "SUPERVISOR_DSS_BROKER",
                    "isolated helpers do not prove a DSS runner selection")
            require(capture.get("broker_request",{}).get("selection")==definition["selection"]
                    and set(capture.get("subject_capture_refs",{}))==set(definition["targets"]),
                    "menu capture selection/subjects differ")
            validate_execution_spec(capture,definition["execution_spec"],capture["initial_dss_state"])
        elif definition["kind"] == "REFERENCE_VARIANT":
            require(result["evidence"]["execution_id"] == by_id[definition["parent"]]["evidence"]["execution_id"],
                    "variant evidence is detached from its executed adaptation")
            require(capture.get("subject_result",{}).get("subject")==definition["parent"],"variant capture identifies another adaptation")
        elif definition["kind"] in {"LANGUAGE_CASE","REFERENCE_ADAPTATION"}:
            require(capture.get("subject_result",{}).get("subject")==identity
                    and canonical(capture["subject_result"]["semantic"])==canonical(definition["oracle"]),
                    "case capture is detached from its outcome")
            menu=next(row for row in definitions.values() if row["kind"]=="MENU_SELECTION" and row["targets"]==[identity])
            require(result["evidence"]["execution_id"]==by_id[menu["id"]]["evidence"]["execution_id"],
                    "individual case did not execute through its public runner selection")
        elif definition["kind"]=="PROCEDURE":
            require(capture.get("execution",{}).get("procedure_hash")==definition["source_sha256"],
                    "procedure capture source differs")
    for row in actual_scenarios:
        definition = expected_scenarios[row["id"]]
        require(set(row) == {"id", "definition_sha256", "status", "observed", "evidence"}
                and row["status"] == "PASS" and row["definition_sha256"] == definition["definition_sha256"]
                and canonical(row["observed"]) == canonical(definition["expected"]),
                "DSS scenario did not satisfy its independent oracle: " + row["id"])
        _validate_evidence(row["evidence"], row["id"], captures, source_commit)
        require(canonical(observed_procedure(captures[row["evidence"]["raw_capture_sha256"]],definition))
                ==canonical(definition["expected"]),"scenario raw evidence differs from reported outcome")
    require(canonical(report["counts"]) == canonical(delivery_counts(manifest["inventory"], results, actual_scenarios, references)),
            "DSS reported counts differ from the independently validated inventory and results")


def _validate_evidence(evidence: dict, identity: str, captures: dict, source_commit: str) -> None:
    require(type(evidence) is dict and set(evidence) == {"mode", "execution_id", "scenario_id", "epoch",
        "source_commit", "raw_capture_sha256", "transport_obligations", "transport_results"},
        "DSS execution evidence fields differ: " + identity)
    require(evidence["mode"] in {"SUPERVISOR_DSS_BROKER", "PUBLIC_API_DSS", "EXPECTED_COMPILER_REJECTION"},
            "synthetic evidence cannot replace a DSS execution: " + identity)
    require(all(type(evidence[key]) is str and 0 < len(evidence[key]) <= 200
                for key in ("execution_id", "scenario_id", "epoch")), "DSS execution binding is missing")
    require(type(evidence["source_commit"]) is str and HEX40.fullmatch(evidence["source_commit"]) is not None
            and evidence["source_commit"] == source_commit
            and type(evidence["raw_capture_sha256"]) is str and HEX64.fullmatch(evidence["raw_capture_sha256"]) is not None,
            "DSS raw evidence binding is missing")
    require(type(evidence["transport_obligations"]) is list and type(evidence["transport_results"]) is list,
            "DSS transport obligations are missing")
    require(evidence["transport_obligations"]==[] and evidence["transport_results"]==[],
            "transport claims must be derived from source and raw packets, not supplied counts")
    capture = captures.get(evidence["raw_capture_sha256"])
    require(type(capture) is dict, "DSS capture is not retained")
    # An outer Run-all has one independently validated child capture per subject.
    if "broker_result" in capture:
        from backend.dss_language_broker import validate_result
        report = validate_result(capture["broker_request"], capture["broker_result"])
        require(report["request"]["execution_id"] == evidence["execution_id"], "DSS broker execution differs")
        require(capture["execution"]["id"]==evidence["execution_id"] and capture["execution"]["state"]=="completed",
                "DSS runner did not complete")
        require(any(row["event_type"]=="procedure.dss_language_completed" and row["payload"].get("request_id")==report["request"]["request_id"]
            and row["payload"].get("result_sha256")==report["result_sha256"] for row in capture["events"]),
            "DSS runner has no durable broker completion binding")
        from backend.dss_language_broker import compact_subject_result,case_execution_id
        require(set(capture.get("subject_capture_refs",{}))=={row["subject"] for row in report["results"]},"nested capture identities differ")
        for result in report["results"]:
            stored=captures.get(capture["subject_capture_refs"][result["subject"]])
            require(type(stored) is dict and canonical(compact_subject_result(stored["subject_result"]))==canonical(result),
                    "nested compact response differs from durable raw result")
            require(canonical(stored["broker_request"])==canonical(report["request"])
                    and result["dss_evidence"]["scenario_id"]==case_execution_id(report["request"],result["subject"]),
                    "Run-all reused an independent selection instead of executing its own child")
            bootstrap=capture.get("bootstrap",{}).get("initial_state",{})
            require(result["dss_evidence"]["epoch"]!=bootstrap.get("epoch")
                and result["dss_evidence"]["scenario_id"]!=bootstrap.get("scenario_id"),
                "inner subject reused the outer bootstrap state")
            validate_subject_capture(stored["subject_result"])
    elif "subject_result" in capture:
        from backend.dss_language_broker import validate_subject_result,selected_subjects,case_execution_id
        result = validate_subject_result(capture["subject_result"]["subject"], capture["subject_result"])
        request=capture["broker_request"]
        require(request["execution_id"]==evidence["execution_id"]==capture["execution"]["id"]
                and result["subject"] in selected_subjects(request)
                and result["dss_evidence"]["scenario_id"]==case_execution_id(request,result["subject"]),
                "DSS subject request or derived physical scenario differs")
        require(result["dss_evidence"]["scenario_id"]==evidence["scenario_id"] and result["dss_evidence"]["epoch"]==evidence["epoch"],
            "DSS subject capture identity differs")
        validate_subject_capture(result)
    else:
        validate_transport_capture(capture, scenario_id=evidence["scenario_id"], epoch=evidence["epoch"])


def validate_broker_bootstrap(bootstrap, spec, initial_state):
    """Validate the setup independently against received packets and committed metadata."""
    from backend.dss_scenarios import (BROKER_BOOTSTRAP, bootstrap_readiness_snapshot,
        bootstrap_snapshot_ready, _timestamp, _snapshot_time)
    from dss.catalog import TELEMETRY_ITEMS, SatelliteDatabase
    require(canonical(spec.get("bootstrap"))==canonical(BROKER_BOOTSTRAP)
        and spec["faults"]=={} and spec["observation_input"]=="nominal", "broker bootstrap declaration differs")
    require(type(bootstrap) is dict and set(bootstrap)=={"schema_version","initial_state","paused_state",
        "readiness","readiness_elapsed_seconds","dss","driver"}
        and bootstrap["schema_version"]=="spell.dss.broker-bootstrap/1", "broker bootstrap evidence is missing")
    require(canonical(bootstrap["initial_state"])==canonical(initial_state),"bootstrap reset state differs")
    elapsed=bootstrap["readiness_elapsed_seconds"]
    require(type(elapsed) in {int,float} and math.isfinite(elapsed) and 0<=elapsed<=15,
        "bootstrap readiness exceeded its original bound")
    satellite=bootstrap["dss"]
    validate_transport_capture(bootstrap,scenario_id=initial_state["scenario_id"],epoch=initial_state["epoch"])
    require(satellite["commands"]==[] and satellite["operations"]==[] and satellite["faults"]=={}
        and satellite["retirement"] is None, "bootstrap contains command effects, faults or premature retirement")
    initial={key:value for key,value in initial_state.items() if key!="sequence"}
    require(canonical(initial)==canonical({key:value for key,value in satellite["initial_state"].items() if key!="sequence"})
        and type(initial_state["sequence"]) is int and initial_state["sequence"]==1
        and satellite["initial_state"]["sequence"]==0, "bootstrap original reset provenance differs")
    paused={key:value for key,value in bootstrap["paused_state"].items() if key!="transport"}
    require(canonical(paused)==canonical(satellite["final_state"])
        and initial_state["running"] is False and paused["running"] is False,
        "bootstrap lacks its exact fenced paused state")
    packets={row["body"]["tm_sequence"]:row for row in bootstrap["driver"] if row["topic"]=="openbexi.GENERIC.tm"}
    frames=[packets[key]["body"] for key in sorted(packets)]
    require(frames and frames[0].get("running") is False and frames[-1].get("running") is False
        and any(row.get("running") is True for row in frames)
        and all(type(row.get("running")) is bool for row in frames)
        and frames[-1]["state_revision"]==paused["revision"], "bootstrap running-to-paused packets differ")
    readiness=bootstrap["readiness"]
    require(canonical(bootstrap_readiness_snapshot(readiness))==canonical(readiness)
        and len(readiness["items"])==len(TELEMETRY_ITEMS)
        and {row["item_id"] for row in readiness["items"]}=={row["item_id"] for row in TELEMETRY_ITEMS}
        and bootstrap_snapshot_ready(readiness,initial_state,spec),"bootstrap committed readiness differs")
    now=_snapshot_time(readiness)
    require(now is not None and now<=frames[-1]["acquired_at_unix_ns"]+1000,
        "bootstrap readiness was not observed before pause")
    for row in [*readiness["items"],readiness["driver_time"]]:
        packet=packets.get(int(row["source_sequence"]))
        require(packet is not None,"bootstrap readiness refers to an unreceived packet")
        body=packet["body"]
        require(body["running"] is True and body["acquired_at_unix_ns"]==_timestamp(row["acquired_at_unix_ns"])
            and type(packet.get("received_unix_ns")) is int
            and body["acquired_at_unix_ns"]<=packet["received_unix_ns"]+1000
            and packet["received_unix_ns"]<=_timestamp(row["received_at_unix_ns"])+1000,
            "bootstrap readiness acquisition or consumer receipt differs")
        if "item_id" in row:
            require(any(item["item_id"]==row["item_id"] for item in body["items"]),
                "bootstrap readiness item is absent from its packet")
        else:
            require(row["source_packet_sha256"]==packet["packet_sha256"]
                and row["database_digest"]==SatelliteDatabase.load().digest,
                "bootstrap clock packet binding differs")


def validate_execution_spec(capture, spec, initial_state, faults=None):
    import math
    require(canonical(capture.get("execution_spec"))==canonical(spec),"declared execution inputs or bounds differ")
    elapsed=capture.get("elapsed_seconds")
    require(type(elapsed) in {int,float} and math.isfinite(elapsed) and 0<=elapsed<=spec["wall_timeout_seconds"],
        "execution exceeded or omitted its declared wall bound")
    for group,fields in spec["initial_state"].items():
        require(type(initial_state.get(group)) is dict and all(canonical(initial_state[group].get(key))==canonical(value)
            for key,value in fields.items()),"DSS initial physical state differs from declared scenario")
    if faults is not None:
        require(canonical(faults)==canonical(spec["faults"]),"DSS physical fault scenario differs")
    from backend.dss_scenarios import STALE_CLOCK_EXPECTATION,STALE_ACQUISITION_NS
    if spec["clock_expectation"]==STALE_CLOCK_EXPECTATION:
        require(spec["observation_input"]=="stale" and canonical(spec["faults"])==canonical({"stale":True})
            and canonical(capture["dss"]["faults"])==canonical(spec["faults"]),"stale clock exception lacks its exact declared fault")
        frames=[row for row in capture["driver"] if row["topic"]=="openbexi.GENERIC.tm"]
        require(frames and all(type(row.get("received_unix_ns")) is int
            and type(row["body"].get("acquired_at_unix_ns")) is int
            and row["received_unix_ns"]-row["body"]["acquired_at_unix_ns"]>=STALE_ACQUISITION_NS
            for row in frames),"declared stale scenario lacks actually received stale acquisition evidence")
    else:require(spec["clock_expectation"]=="CURRENT_EPOCH","unknown clock readiness expectation")
    if spec["execution_control"]=="SCENARIO_RUNNING_THEN_PAUSED":
        frames=[row["body"] for row in capture["driver"] if row["topic"]=="openbexi.GENERIC.tm"]
        frames.sort(key=lambda row:row["tm_sequence"])
        require(frames and frames[0].get("running") is False and frames[-1].get("running") is False
            and any(row.get("running") is True for row in frames)
            and all(type(row.get("running")) is bool for row in frames)
            and capture["dss"]["initial_state"]["running"] is False
            and capture["dss"]["final_state"]["running"] is False
            and frames[-1]["state_revision"]==capture["dss"]["final_state"]["revision"],
            "DSS execution lacks received running-to-paused control evidence")
    else:
        require(spec["execution_control"]=="BROKERED_SUBJECTS","DSS execution control profile is unknown")
        validate_broker_bootstrap(capture.get("bootstrap"),spec,initial_state)
    minimum=spec.get("minimum_simulation_advance_ns",0)
    if minimum:
        require(capture["dss"]["final_state"]["core"]["sim_time_ns"]-initial_state["core"]["sim_time_ns"]>=minimum,
            "scheduled source duration did not advance actual simulator time")


def _validate_stage_receipts(capture, native_results, reference_results, *, unreceived_operations=frozenset()):
    """Join every logical provider outcome to both raw TC and received binary ACK."""
    from dss.packets import decode_tc,decode_tm
    operations={row["packet_sha256"]:row for row in capture["dss"]["operations"]}
    acknowledgements={row["packet_sha256"]:decode_tm(bytes.fromhex(row["packet_hex"]))
        for row in capture["dss"]["packets"] if row["topic"]=="openbexi.GENERIC.ack"}
    consumed={row["packet_sha256"] for row in capture["driver"]}
    stages=[]
    for result in native_results:
        for element in result["checkpoint"]["elements"]:
            stages.extend({"stage":name,"outcome":detail["outcome"],"detail":detail["native"]}
                for name,detail in element["provider_detail"].items()
                if not (name == "RECONCILIATION" and unreceived_operations))
    expected={"TRANSPORT":"ACCEPTED","LOADING":"LOADED","RELEASE":"RELEASED",
        "ACKNOWLEDGEMENT":"ACKNOWLEDGED","ONBOARD_EXECUTION":"SUCCEEDED","VERIFICATION":"PASSED"}
    for result in reference_results:
        for stage in result["stages"]:
            require(stage["outcome"]==expected.get(stage["stage"]),"reference adaptation concealed a failed physical stage")
            stages.append(stage)
    used=set()
    for stage in stages:
        detail=stage["detail"]
        require(detail.get("provider")=="dss-cortex-kafka","stage used a fixture provider")
        command_hash=detail.get("command_packet_sha256")
        ack_hash=detail.get("acknowledgement_packet_sha256")
        require(command_hash in operations and ack_hash in acknowledgements and ack_hash in consumed,
            "provider stage lacks retained TC and actually consumed ACK bytes")
        operation=operations[command_hash]
        body=decode_tc(bytes.fromhex(operation["packet_hex"]))
        ack=acknowledgements[ack_hash]
        require(canonical(ack)==canonical(operation["acknowledgement"])
                and body["stage"]==stage["stage"] and ack["outcome"]==stage["outcome"],
                "provider outcome differs from actual binary acknowledgement")
        require(detail["satellite_epoch"]==ack["satellite_epoch"] and detail["scenario_id"]==ack["scenario_id"]
                and detail["database_digest"]==ack["database_digest"] and detail["tm_sequence"]==ack["tm_sequence"]
                and detail["state_revision"]==ack["state_revision"],"provider receipt identity differs")
        for item in detail.get("telemetry",[]):
            require(any(row["packet_sha256"]==item["packet_sha256"] and row["topic"]==item["topic"]
                and row["partition"]==item["partition"] and row["offset"]==item["offset"] for row in capture["driver"]),
                "provider telemetry receipt is not in actual consumed evidence")
        used.add(command_hash)
    require(used | set(unreceived_operations)==set(operations) and not used & set(unreceived_operations),
            "unaccounted binary command stage or missing provider result")


def _observed_command_fault(capture, definition):
    """Bind an expected failed API execution to its actual request, result and wire effects."""
    from backend.procedure_parser import ProcedureCatalog
    from backend.telecommand_runtime_v11 import validate_send_request, validate_result_payload
    from backend.worker import evaluate_expression
    from dss.packets import decode_tc
    expected = definition["expected"]["command_fault"]
    require(definition["inputs"].get("command_fault") == expected["kind"], "command fault input differs")
    events, execution = capture["events"], capture["execution"]
    requests = [row["payload"] for row in events if row["event_type"] == "procedure.telecommand_requested"]
    results = [row["payload"] for row in events if row["event_type"] == "procedure.telecommand_result"]
    require(len(requests) == len(results) == 1, "command fault must have exactly one durable request and result")
    request = {key:value for key,value in requests[0].items() if key != "_telecommand_runtime_binding"}
    procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(capture["procedure"]["source"])
    require(type(request.get("step_index")) is int and 0 <= request["step_index"] < len(procedure.steps),
            "command fault step differs")
    step = procedure.steps[request["step_index"]]
    require(step["type"] == "send_tc" and ("guard" not in step or evaluate_expression(step["guard"], execution["variables"]) is True),
            "command fault request bypassed its source guard")
    request, _, _ = validate_send_request(execution["id"], step["index"], step, execution["variables"], request)
    result = validate_result_payload(request, results[0])
    operations = capture["dss"]["operations"]
    packets = [decode_tc(bytes.fromhex(row["packet_hex"])) for row in operations]
    require(len(request["plan"]["elements"]) == 1, "fault oracle expects one closed command element")
    element = request["plan"]["elements"][0]
    for packet in packets:
        require(packet["operation_id"] == request["operation_id"] and packet["execution_id"] == execution["id"]
            and packet["procedure_id"] == execution["procedure_id"] and packet["plan_id"] == request["plan"]["plan_id"]
            and packet["element_id"] in {element["element_id"], element["transport_unit_id"]}
            and packet["command_name"] == element["command"]["name"]
            and canonical(packet["arguments"]) == canonical(element["command"]["arguments"]),
            "fault packet differs from the durable authoritative command plan")
    require(bool(operations), "fault scenario did not reach the actual binary transport")
    maximum = max(row["ingress_delivery_count"] for row in operations)
    actual = {"kind":expected["kind"],"request_count":len(requests),"result_count":len(results),
        "outcome":result["outcome"],"dispositions":[row["disposition"] for row in result["checkpoint"]["elements"]],
        "effect_certainties":[row["effect_certainty"] for row in result["checkpoint"]["elements"]],
        "physical_stages":[[packet["stage"], operation["acknowledgement"]["outcome"]]
            for packet, operation in zip(packets, operations)],"maximum_ingress_attempts_per_stage":maximum}
    # Engine evidence is ordered by stage identity, not necessarily chronological insertion.
    order = {name:index for index,name in enumerate(("TRANSPORT","LOADING","RELEASE","ACKNOWLEDGEMENT","ONBOARD_EXECUTION","VERIFICATION"))}
    actual["physical_stages"].sort(key=lambda row:order[row[0]])
    require(canonical(actual) == canonical(expected), "command fault stage, disposition or no-resend oracle differs: " + canonical(actual).decode())
    if expected["kind"] == "release_ack_timeout":
        require(capture["elapsed_seconds"] >= 3.0, "delayed acknowledgement did not exercise the real driver timeout")
    unreceived = frozenset()
    if result["outcome"] == "UNCERTAIN":
        require(expected["kind"] in {"lost_release_ack", "release_ack_timeout"}
            and all(set(row["provider_detail"]) == {"TRANSPORT", "LOADING", "RECONCILIATION"}
                and row["provider_detail"]["RECONCILIATION"] == {"outcome":"UNKNOWN",
                    "native":{"provider":"deterministic-simulator","certainty":"UNKNOWN"}}
                for row in result["checkpoint"]["elements"]),
            "uncertain replay cannot manufacture a received provider acknowledgement")
        unreceived = frozenset(row["packet_sha256"] for packet,row in zip(packets,operations) if packet["stage"]=="RELEASE")
    return actual, results, unreceived


def validate_outer_source_execution(capture):
    """Replay the bounded source's committed variables and bind all real service requests."""
    from backend.procedure_parser import ProcedureCatalog
    from backend.worker import evaluate_expression
    from backend.prompt_v17 import PROMPT_PROFILE,native_prompt_result
    from backend.ir_v07 import observation_request_for_step,validate_observation_result
    from backend.runtime_composition_v19 import observation_checkpoint_variables
    from backend.telecommand_runtime_v11 import (build_item_checkpoint_for_step,validate_send_request,
        validate_result_payload,result_failure_policy)
    from dss.packets import decode_tc
    execution=capture["execution"]
    procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source(capture["procedure"]["source"])
    values,requests,results,observations={}, {}, {}, {}
    if "ARGS" in execution["variables"]:
        require(type(execution["variables"]["ARGS"]) is dict and execution["variables"]["ARGS"]=={},
            "outer framework ARGS must be the declared empty invocation")
        values["ARGS"]={}
    cursor=0
    for event in capture["events"]:
        kind,payload=event["event_type"],event["payload"]
        if kind not in {"procedure.telecommand_requested","procedure.telecommand_result","procedure.observation_result","step.completed"}:
            continue
        index=payload.get("step_index")
        if kind=="procedure.telecommand_result":
            matches=[position for position,request in requests.items() if request["request_id"]==payload.get("request_id")]
            require(len(matches)==1,"outer command result has no unique source request")
            index=matches[0]
        require(type(index) is int and index==cursor and cursor<len(procedure.steps),"outer service/commit is outside its current source step")
        step=procedure.steps[cursor]
        enabled=step.get("guard") is None or evaluate_expression(step["guard"],values) is True
        if kind=="procedure.telecommand_requested":
            require(enabled and index not in requests,"outer command bypassed its guard or repeated")
            raw={key:value for key,value in payload.items() if key!="_telecommand_runtime_binding"}
            requests[index],_,_=validate_send_request(execution["id"],index,step,values,raw)
        elif kind=="procedure.telecommand_result":
            require(enabled and index not in results,"outer command result repeated or bypassed its guard")
            results[index]=validate_result_payload(requests[index],payload)
        elif kind=="procedure.observation_result":
            require(enabled and index not in observations,"outer observation result repeated or bypassed its guard")
            request=observation_request_for_step(execution["id"],step)
            observations[index]=validate_observation_result(request,payload)
        else:
            require(payload=={"step_index":index,"line":step["line"],"step_type":step["type"],"skipped":not enabled},
                "outer committed step or guard disposition differs")
            if enabled:
                if step["type"]=="variable_set":
                    value=evaluate_expression(step["expression"],values)
                    values[step["name"]]=float(value) if step["declared_type"]=="float" and type(value) is int else value
                elif step["type"]=="build_tc":values[step["target"]]=build_item_checkpoint_for_step(step,values)
                elif step["type"]=="prompt":
                    prompts=[row for row in capture["typed_prompts"] if row["step_index"]==index]
                    require(len(prompts)==1 and prompts[0].get("settlement",{}).get("outcome")=="ANSWERED",
                        "outer prompt commit lacks its answered source settlement")
                    settlement=prompts[0]["settlement"]
                    if "response_target" in step:
                        response={"outcome":settlement["outcome"],"response":settlement["value"]}
                        values[step["response_target"]]=native_prompt_result(step,response) if step.get("prompt_profile")==PROMPT_PROFILE else settlement["value"]
                elif step["type"] in {"get_tm","verify","wait_for"}:
                    require(index in observations,"outer observation checkpoint has no actual result")
                    values=observation_checkpoint_variables(step,values,observations[index])
                elif step["type"]=="send_tc":
                    require(index in results and result_failure_policy(requests[index],results[index]) is None,
                        "outer command advanced without a successful authoritative result")
                else:require(step["type"] in {"log","display","wait"},"outer source step has no reviewed replay oracle")
            cursor+=1
    require(set(requests)==set(results),"outer command lacks a durable result")
    require(canonical(values)==canonical(execution["variables"]),"outer final variable map differs from source and durable settlements")
    if execution["state"]=="completed":require(cursor==len(procedure.steps),"outer source did not complete every instruction")
    for operation in capture["dss"]["operations"]:
        body=decode_tc(bytes.fromhex(operation["packet_hex"]))
        matches=[request for request in requests.values() if request["operation_id"]==body["operation_id"]]
        require(len(matches)==1,"outer physical command has no source-bound operation")
        request=matches[0]
        elements=[element for element in request["plan"]["elements"] if body["element_id"] in {element["element_id"],element["transport_unit_id"]}]
        require(bool(elements),"outer binary element is outside its source plan")
        if len(elements)>1:
            require(body["stage"]=="TRANSPORT" and canonical(body.get("elements"))==canonical([
                {"element_id":element["element_id"],"command_name":element["command"]["name"],
                 "command_digest":element["command"]["item_digest"],"arguments":element["command"]["arguments"]}
                for element in elements]),"outer grouped transport differs from its source elements")
        else:require("elements" not in body,"outer single-command stage manufactured a group")
        command=elements[0]["command"]
        require(body["execution_id"]==execution["id"] and body["procedure_id"]==execution["procedure_id"]
            and body["plan_id"]==request["plan"]["plan_id"] and body["command_name"]==command["name"]
            and body["command_digest"]==command["item_digest"] and canonical(body["arguments"])==canonical(command["arguments"]),
            "outer binary command identity or arguments differ from source")
    return list(results.values())


def observed_procedure(capture: dict, definition: dict) -> dict:
    execution=capture["execution"]
    source=(ROOT/definition["subject"].removeprefix("procedure:")).read_bytes()
    require(execution["procedure_hash"]==sha256(source),"scenario procedure source hash differs")
    require(capture["procedure"]["source"].encode("utf-8")==source,"API procedure source differs")
    events=capture["events"]
    require(all(row["execution_id"]==execution["id"] and type(row["sequence"]) is int for row in events)
            and [row["sequence"] for row in events]==list(range(1,len(events)+1)),"procedure event sequence is incomplete")
    require(canonical(capture["actions"])==canonical(definition["operator_actions"]),"procedure operator actions differ")
    variables=execution["variables"]
    expected=definition["expected"]
    validate_execution_spec(capture,definition["inputs"]["execution_spec"],capture["initial_dss_state"],
        capture["dss"]["faults"] if "dss" in capture else None)
    actions=[row for row in definition["operator_actions"] if row["action"]!="await_warning"]
    prompts=capture["typed_prompts"]
    require(len(prompts)==len(actions),"procedure prompt settlement coverage differs")
    for action,prompt in zip(actions,prompts):
        settlement=prompt.get("settlement") or {}
        if action["action"]=="abort":require(settlement.get("outcome")=="CANCELLED","operator abort did not cancel prompt")
        else:
            value=action["value"]
            if prompt["type"]=="NUM":value=float(value)
            require(settlement.get("outcome")=="ANSWERED" and canonical(settlement.get("value"))==canonical(value),
                "operator prompt returned another value")
            if action["action"]=="await_default":require(settlement.get("actor")=="operator-reconciler","default was replaced by operator answer")
    if any(row["action"]=="await_warning" for row in definition["operator_actions"]):
        require(any(row["event_type"]=="prompt.warning_due" for row in capture["operator_audit"]),"warning scenario has no actual warning")
    require(set(expected["variables"])<=set(variables),"procedure expected variable is absent")
    if "broker_result" in capture:
        counts={"executed_commands":0,"loaded_unexecuted_commands":0}
        require(not any(row["event_type"]=="procedure.telecommand_settled" for row in events),"reference runner emitted an unexpected outer command")
    else:
        counts=validate_transport_capture(capture,scenario_id=capture["dss"]["scenario_id"],epoch=capture["dss"]["epoch"])
        validated_results=validate_outer_source_execution(capture)
        if "command_fault" in expected:
            command_fault, results, unreceived = _observed_command_fault(capture, definition)
            _validate_stage_receipts(capture, results, [], unreceived_operations=unreceived)
        else:
            _validate_stage_receipts(capture,validated_results,[])
        require(all(row["definition"]["execution_id"]==execution["id"] for row in capture["dss"]["commands"]),
            "scenario includes another execution's command")
    observed = {"terminal":execution["state"],"variables":{key:variables[key] for key in expected["variables"]},
        "logs":[row["payload"]["message"] for row in events if row["event_type"]=="procedure.log"],
        "outer_executed_commands":counts["executed_commands"],"outer_loaded_unexecuted_commands":counts["loaded_unexecuted_commands"],
        "observations":[[row["payload"]["operation"],row["payload"]["outcome"]] for row in events
            if row["event_type"]=="procedure.observation_result"]}
    if "command_fault" in expected:
        observed["command_fault"] = command_fault
    return observed


def _observation_scalar_from_packet(scalar):
    """The observation JSON contract renders exact 64-bit integers as decimals."""
    require(type(scalar) is dict and set(scalar)=={"type","value"},"binary observation scalar fields differ")
    kind,value=scalar["type"],scalar["value"]
    require(type(kind) is str,"binary observation scalar type differs")
    if kind in {"INT64","UINT64"}:
        lower,upper=(-(2**63),2**63-1) if kind=="INT64" else (0,2**64-1)
        require(type(value) is int and lower<=value<=upper,"binary observation integer type or range differs")
        return {"type":kind,"value":str(value)}
    require((kind=="FINITE_DOUBLE" and type(value) is float and math.isfinite(value))
        or (kind=="BOOLEAN" and type(value) is bool) or (kind=="STRING" and type(value) is str),
        "binary observation scalar type or value differs")
    return dict(scalar)


def _validate_observation_value_binding(item,sample,result_value):
    require(item is not None,"GetTM item is absent from decoded telemetry")
    raw=_observation_scalar_from_packet(item["raw"])
    engineering=_observation_scalar_from_packet(item["engineering"])
    selected=raw if sample.get("field")=="RAW" else engineering if sample.get("field")=="ENGINEERING" else None
    require(selected is not None and canonical(raw)==canonical(sample["raw_value"])
        and canonical(engineering)==canonical(sample["engineering_value"])
        and canonical(selected)==canonical(sample["selected_value"]),"GetTM value differs from decoded telemetry")
    value=int(selected["value"]) if selected["type"] in {"INT64","UINT64"} else selected["value"]
    require(canonical(result_value)==canonical(value),"GetTM result differs from selected typed telemetry")


def validate_subject_capture(result: dict) -> None:
    from backend import language_conformance_v19 as registry
    from backend.dss_language_broker import validate_subject_result
    from backend.procedure_parser import ProcedureCatalog,ProcedureValidationError
    from backend.worker import evaluate_expression
    from backend.ir_v07 import observation_request_for_step,validate_observation_result
    from backend.runtime_composition_v19 import observation_checkpoint_variables
    from backend.telecommand_runtime_v11 import validate_send_request,validate_result_payload,build_item_checkpoint_for_step
    from backend.prompt_v17 import PROMPT_PROFILE,native_prompt_result
    from dss.packets import decode_tc
    validate_subject_result(result["subject"],result)
    evidence=result["dss_evidence"]
    raw=evidence.get("capture")
    require(type(raw) is dict and sha256(canonical(raw))==evidence["capture_sha256"],"DSS raw subject evidence differs")
    validate_transport_capture(raw,scenario_id=evidence["scenario_id"],epoch=evidence["epoch"])
    packets=[decode_tc(bytes.fromhex(row["packet_hex"])) for row in raw["dss"]["operations"]]
    commands=raw["dss"]["commands"]
    if result["subject"].startswith("adaptation:"):
        from backend.dss_scenarios import subject_execution_spec
        validate_execution_spec(raw,subject_execution_spec(result["subject"],{}),raw["dss"]["initial_state"],raw["dss"]["faults"])
        semantic=result["semantic"]
        golden=json.loads((ROOT/"artifacts/v0.10/reference-examples.json").read_bytes())["results"][semantic["example_number"]-1]
        require(canonical(semantic)==canonical(golden),"DSS adaptation changed its historical oracle")
        mappings=raw["reference_mappings"]
        traces=[row for row in semantic["trace"] if row["operation"] in {"Send","SetGroundParameter"}]
        require(len(mappings)==len(traces),"a reference command was not physically mapped")
        for mapping,trace in zip(mappings,traces):
            name="DSS.REFERENCE.SEND" if trace["operation"]=="Send" else "DSS.REFERENCE.SET_GROUND"
            require(mapping["physical_command"]==name and mapping["logical_trace_sequence"]==trace["sequence"],
                "reference command mapping source differs")
            actual=mapping["actual"]
            expected_arguments=[row["arguments"] for row in trace["inputs"]["commands"]] if trace["operation"]=="Send" else {"PARAMETER":"TMparam","VALUE":23.0}
            require(canonical(mapping["arguments"])==canonical(expected_arguments),"reference mapping arguments differ from source trace")
            require(canonical(actual["reference_mapping"])==canonical(mapping["modifiers"]),"reference physical modifier mapping differs")
            require(actual.get("stages") and all(row.get("detail",{}).get("provider")=="dss-cortex-kafka" for row in actual["stages"]),
                "reference command did not use actual driver stages")
            operation_ids={row["operation_id"] for row in packets if row["operation_id"]==actual["operation_id"]}
            require(operation_ids=={actual["operation_id"]},"reference result has no actual command operation")
            requested=expected_arguments if type(expected_arguments) is list else [expected_arguments]
            loaded=[row for row in commands if row["definition"]["execution_id"]==evidence["scenario_id"]
                and any(packet["operation_id"]==actual["operation_id"] and packet["plan_id"]==row["plan_id"] for packet in packets)]
            require(len(loaded)==len(requested),"reference mapping command expansion differs")
            actual_arguments=[{arg["name"]:arg["value"] for arg in row["definition"]["arguments"]} for row in loaded]
            require(sorted(canonical(row) for row in actual_arguments)==sorted(canonical({key:float(value) if key in {"ARG1","VALUE"} else value
                for key,value in row.items()}) for row in requested),"reference binary arguments differ")
            require(sum(row["executed"] for row in loaded)==actual["executed_count"]
                and actual["executed_count"]==(0 if actual["load_only"] else len(requested)),"reference physical disposition differs")
        reads=[row for row in semantic["trace"] if row["operation"]=="GetTM"]
        require(len(raw["reference_reads"])==len(reads),"reference telemetry read coverage differs")
        for read,trace in zip(raw["reference_reads"],reads):
            require(read["logical_trace_sequence"]==trace["sequence"] and read["item_id"]==trace["inputs"]["name"]
                and read["source_epoch"]==evidence["epoch"],"reference telemetry source binding differs")
            matches=[packet["body"] for packet in raw["driver"] if packet["topic"]=="openbexi.GENERIC.tm"
                and packet["body"]["tm_sequence"]==read["tm_sequence"]]
            require(len(matches)==1,"reference telemetry read has no unique consumed packet")
            item=next((row for row in matches[0]["items"] if row["item_id"]==read["item_id"]),None)
            require(item is not None and canonical(item[read["field"]])==canonical(read["selected_value"]),
                "reference telemetry selected value differs from binary sample")
        require(bool(packets)==bool(mappings),"reference adaptation physical command count differs")
        _validate_stage_receipts(raw,[],[row["actual"] for row in mappings])
        if not mappings:
            require(not commands,"pure adaptation manufactured a physical command")
        return
    case=next(row for row in registry.CASES if result["subject"]=="case:"+row["id"])
    from backend.dss_scenarios import subject_execution_spec
    validate_execution_spec(raw,subject_execution_spec(result["subject"],case),raw["dss"]["initial_state"],raw["dss"]["faults"])
    worker=raw["worker"]
    require(worker["source_sha256"]==case["source_sha256"] and worker["execution_id"]==evidence["scenario_id"],
            "inner worker source/execution differs")
    try:
        procedure=ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"],case["id"]+".spell.py")
    except ProcedureValidationError as exc:
        require(case["expected_diagnostic"]==exc.diagnostics[0].code
                and worker["compiler_diagnostics"]==[{"code":row.code} for row in exc.diagnostics]
                and worker["events"]==[] and worker["service_results"]==[] and not packets and not commands,
                "expected rejection executed a forbidden service or changed diagnostic")
        return
    require(not case["expected_diagnostic"] and worker["ir_version"]==procedure.ir_version
            and canonical(worker["steps"])==canonical(list(procedure.steps)),"inner worker IR differs from source")
    values,logs,prompts,terminal={},[],[],None
    service_results={}
    for service in worker["service_results"]:
        key=(service["kind"],service["step"]["index"])
        require(key not in service_results,"inner service result is duplicated")
        service_results[key]=service
    used=set()
    expected_commands=[]
    cursor=0
    for event in worker["events"]:
        require(event.get("execution_id")==worker["execution_id"],"inner event execution differs")
        kind=event["kind"]
        require(terminal is None,"inner source trace continues after termination")
        if kind=="terminal":
            terminal=event["state"]
            require(terminal!="completed" or cursor==len(procedure.steps),"inner completion omitted source instructions")
            continue
        index=event["step_index"]
        require(type(index) is int and index==cursor and 0<=index<len(procedure.steps),"inner event source cursor differs")
        step=procedure.steps[index]
        enabled=True if step.get("guard") is None else evaluate_expression(step["guard"],values)
        require(type(enabled) is bool,"inner source guard is not Boolean")
        if kind=="prompt_opened" and step["type"]=="prompt":
            prompts.append({key:event.get(key) for key in registry.inherited.PROMPT_OBSERVATIONS})
        elif kind in {"observation_requested","telecommand_requested"}:
            require(step.get("guard") is None or evaluate_expression(step["guard"],values) is True,"inner service bypasses guard")
            service_kind="observation" if kind=="observation_requested" else "telecommand"
            key=(service_kind,index)
            require(key in service_results and key not in used,"inner request lacks unique actual result")
            service=service_results[key]
            require(canonical(service["step"])==canonical(step),"inner service original step differs")
            incoming={key:value for key,value in event.items() if key not in {"kind","generation"}}
            if service_kind=="observation":
                expected_request=observation_request_for_step(worker["execution_id"],step)
                require(canonical(incoming)==canonical(expected_request)==canonical(service["request"]),"inner observation request differs")
                validate_observation_result(expected_request,service["result"])
                if expected_request["operation"]=="GET_TM" and service["result"]["outcome"]=="OK":
                    sample=service["result"]["evidence"]
                    matches=[row["body"] for row in raw["driver"] if row["topic"]=="openbexi.GENERIC.tm"
                        and str(row["body"]["tm_sequence"])==sample["source_sequence"]
                        and row["body"]["satellite_epoch"]==sample["source_epoch"]]
                    require(len(matches)==1,"GetTM value has no exact consumed source packet")
                    item=next((row for row in matches[0]["items"] if row["item_id"]==sample["item_id"]),None)
                    _validate_observation_value_binding(item,sample,service["result"]["value"])
            else:
                request,_,_=validate_send_request(worker["execution_id"],index,step,values,incoming)
                require(canonical(request)==canonical(service["request"]),"inner TC request differs")
                validate_result_payload(request,service["result"])
                for element in request["plan"]["elements"]:
                    expected_commands.append((request["plan"]["plan_id"],element["element_id"],element["command"]))
            used.add(key)
        elif kind=="step_commit":
            effects=event["effects"]
            completed={"event_type":"step.completed","source":"worker","severity":"info",
                "payload":{"step_index":index,"line":step["line"],"step_type":step["type"],"skipped":not enabled}}
            require(type(event.get("next_step")) is int and event["next_step"]==cursor+1
                and effects and canonical(effects[-1])==canonical(completed)
                and sum(row.get("event_type")=="step.completed" for row in effects)==1,
                "inner source completion evidence differs")
            expected_values=dict(values)
            if not enabled:
                require(canonical(effects)==canonical([completed]) and event.get("prompt_resolution") is None,
                    "inner skipped instruction manufactured effects")
            elif step["type"]=="variable_set":
                value=evaluate_expression(step["expression"],values)
                expected_values[step["name"]]=float(value) if step["declared_type"]=="float" and type(value) is int else value
            elif step["type"]=="build_tc":
                expected_values[step["target"]]=build_item_checkpoint_for_step(step,values)
            elif step["type"]=="prompt":
                answers=[row["settlement"] for row in worker["prompt_settlements"]
                    if row["step_index"]==index and row["kind"]=="native"]
                require(len(answers)==1 and answers[0]["outcome"]=="ANSWERED","inner prompt lacks a unique answered settlement")
                fields=("prompt_id","settlement_id","outcome","response")
                require(type(event.get("prompt_resolution")) is dict and canonical({key:event["prompt_resolution"].get(key) for key in fields})
                    ==canonical({key:answers[0].get(key) for key in fields}),"inner prompt checkpoint settlement differs")
                if "response_target" in step:
                    expected_values[step["response_target"]]=native_prompt_result(step,answers[0]) if step.get("prompt_profile")==PROMPT_PROFILE else answers[0]["response"]
            elif step["type"] in {"get_tm","verify","wait_for"}:
                require(("observation",index) in used,"inner observation committed without a result")
                expected_values=observation_checkpoint_variables(step,values,service_results[("observation",index)]["result"])
            else:require(step["type"] in {"log","display","send_tc"},"inner source has no reviewed checkpoint oracle")
            require(canonical(event["variables"])==canonical(expected_values),"inner full variable map differs from authoritative source replay")
            if ("observation",index) in used:
                service=service_results[("observation",index)]
                require(canonical(event["variables"])==canonical(observation_checkpoint_variables(step,values,service["result"])),
                    "inner observation full variable checkpoint differs")
                registry._validate_observation_effect(effects[0],service["request"],service["result"],index)
            for effect in effects:
                if effect["event_type"]=="procedure.telecommand_settled":
                    require(("telecommand",index) in used,"inner TC settlement lacks actual request")
                    registry._validate_settlement_effect(effect,service_results[("telecommand",index)]["result"],index)
                if effect["event_type"]=="procedure.log":logs.append([effect["payload"]["message"],effect["severity"]])
            values=event["variables"]
            cursor+=1
    require(used==set(service_results),"inner service result has no worker request")
    _validate_stage_receipts(raw,[row["result"] for row in worker["service_results"] if row["kind"]=="telecommand"],[])
    registry.inherited._observed_result(case,terminal,values,logs,prompts)
    settlements=worker["prompt_settlements"]
    opened=[row for row in worker["events"] if row["kind"]=="prompt_opened"]
    require(len(opened)==len(settlements) and all(row["prompt_id"]==answer["settlement"]["prompt_id"]
        and row["step_index"]==answer["step_index"] for row,answer in zip(opened,settlements)),"inner operator settlement identity differs")
    native=[{key:row["settlement"].get(key) for key in ("outcome","response")} for row in settlements if row["kind"]=="native"]
    require(canonical(native)==canonical([row["settlements"][0] for row in case.get("prompts",[])]),"inner native operator input differs")
    if "expected_telecommands" in case:
        actual_commands=[registry._command_observation(row["request"],row["result"]) for row in worker["service_results"] if row["kind"]=="telecommand"]
        require(canonical(actual_commands)==canonical(case["expected_telecommands"]),"inner actual command result differs from independent source oracle")
        for kind,key in (("confirmation","confirmations"),("failure","failure_answers")):
            require(canonical([row["settlement"]["response"] for row in settlements if row["kind"]==kind])==canonical(case[key]),
                "inner TC operator response differs")
    if "expected_observations" in case:
        observed=[{"operation":row["request"]["operation"],"outcome":row["result"]["outcome"],"value":row["result"].get("value")}
            for row in worker["service_results"] if row["kind"]=="observation"]
        require(canonical(observed)==canonical(case["expected_observations"]),"inner actual observation outcome differs")
    allowed={(plan,element) for plan,element,command in expected_commands}
    require(all((row["plan_id"],row["element_id"]) in allowed for row in commands),"physical command is outside source plan")
    for plan,element,command in expected_commands:
        matching=[row for row in packets if row["plan_id"]==plan and (row["element_id"]==element or
            any(child["element_id"]==element for child in row.get("elements",[])))]
        require(matching,"source command has no actual binary TC")
        for row in matching:
            actual=next((child for child in row.get("elements",[]) if child["element_id"]==element),row)
            require(actual["command_name"]==command["name"] and canonical(actual["arguments"])==canonical(command["arguments"]),
                "actual binary command name/arguments differ from source plan")
    if case["id"]=="v18-relative-release-intent":
        first,last=raw["dss"]["initial_state"],raw["dss"]["final_state"]
        require(raw["dss"]["faults"].get("auto_advance_scheduled_time") is True
                and last["core"]["sim_time_ns"]-first["core"]["sim_time_ns"]>=1800_000_000_000,
                "relative release did not advance the actual simulator thirty minutes")


def validate_transport_capture(capture: dict, *, scenario_id: str, epoch: str) -> dict:
    """Decode retained bytes and cross-bind the DSS journal and independent TLM consumer."""
    from dss import SIMULATOR_VERSION, DYNAMICS_ENGINE_VERSION
    from dss.catalog import SatelliteDatabase
    from dss.packets import decode_tc, decode_tm
    database = SatelliteDatabase.load()
    require(type(capture) is dict and {"dss","driver"} <= set(capture), "DSS capture is incomplete")
    satellite = capture["dss"]
    require(satellite.get("schema_version") == "openbexi.dss.evidence/1"
            and satellite.get("scenario_id") == scenario_id and satellite.get("epoch") == epoch
            and satellite.get("database_digest") == database.digest
            and satellite.get("database_revision") == database.revision
            and satellite.get("simulator_version") == SIMULATOR_VERSION
            and satellite.get("dynamics_engine_version") == DYNAMICS_ENGINE_VERSION,
            "DSS capture version, database, scenario or epoch differs")
    for state in (satellite["initial_state"], satellite["final_state"]):
        require(state["scenario_id"] == scenario_id and state["epoch"] == epoch
                and state["database_digest"] == database.digest, "DSS state binding differs")
    packet_bodies = {}
    for packet in satellite["packets"]:
        raw = bytes.fromhex(packet["packet_hex"])
        require(packet["packet_sha256"] == sha256(raw), "DSS TM raw packet digest differs")
        body = decode_tm(raw)
        require(body["scenario_id"] == scenario_id and body["satellite_epoch"] == epoch
                and body["database_digest"] == database.digest, "DSS TM packet identity differs")
        require(packet["topic"] in {"openbexi.GENERIC.tm", "openbexi.GENERIC.ack"}, "DSS packet topic differs")
        packet_bodies[packet["packet_sha256"]] = (body, packet)
    require(bool(packet_bodies), "DSS emitted no binary telemetry")
    operations = satellite["operations"]
    identities = set()
    for operation in operations:
        require(type(operation.get("ingress_delivery_count")) is int and operation["ingress_delivery_count"] == 1,
                "DSS command stage was resent or lacks measured ingress evidence")
        raw = bytes.fromhex(operation["packet_hex"])
        require(sha256(raw) == operation["packet_sha256"], "DSS TC raw packet digest differs")
        body = decode_tc(raw)
        require(body["scenario_id"] == scenario_id and body["satellite_epoch"] == epoch
                and body["database_digest"] == database.digest, "DSS TC packet identity differs")
        identity = tuple(body[key] for key in ("operation_id","plan_id","element_id","stage"))
        require(identity not in identities, "DSS journal duplicated a command stage")
        identities.add(identity)
        acknowledgement = operation["acknowledgement"]
        require(all(acknowledgement.get(key) == body[key] for key in
                    ("operation_id","plan_id","element_id","stage","scenario_id","satellite_epoch")),
                "DSS acknowledgement does not identify its actual TC")
        require(any(canonical(value) == canonical(acknowledgement) for value, packet in packet_bodies.values()
                    if packet["topic"] == "openbexi.GENERIC.ack"), "DSS TC has no retained binary acknowledgement")
    driver_packets = capture["driver"]
    require(type(driver_packets) is list and driver_packets, "actual TLM consumer received no packet")
    consumed = set()
    for packet in driver_packets:
        raw = bytes.fromhex(packet["packet"])
        packet_hash = sha256(raw)
        require(packet_hash == packet["packet_sha256"] and packet_hash in packet_bodies and packet_hash not in consumed,
                "TLM consumer packet is absent from actual DSS outbox")
        body, source = packet_bodies[packet_hash]
        require(canonical(decode_tm(raw)) == canonical(packet["body"]) == canonical(body)
                and packet["topic"] == source["topic"] and source["published"] is True,
                "TLM decoded value/topic differs from the published binary packet")
        require(type(packet["partition"]) is int and packet["partition"] >= 0
                and type(packet["offset"]) is int and packet["offset"] >= 0,
                "actual Kafka partition/offset evidence is missing")
        consumed.add(packet_hash)
    require(consumed == set(packet_bodies), "DSS outbox has a packet absent from actual consumer evidence")
    require(any(packet["topic"] == "openbexi.GENERIC.tm" for _, packet in
                (packet_bodies[value] for value in consumed)), "TLM consumed no satellite state packet")
    for command in satellite["commands"]:
        require(command["scenario_id"] == scenario_id and type(command["executed"]) is int
                and command["executed"] in {0,1}, "DSS command journal is malformed")
        require(any(body["plan_id"] == command["plan_id"] and body["element_id"] == command["element_id"]
                    for operation in operations for body in [decode_tc(bytes.fromhex(operation["packet_hex"]))]),
                "DSS command journal has no actual TC")
    from dss.evidence_validation import validate_command_effects
    validate_command_effects(capture)
    return {"tc_stages":len(operations), "executed_commands":sum(row["executed"] for row in satellite["commands"]),
        "loaded_unexecuted_commands":sum(not row["executed"] and row["results"].get("LOADING") == "LOADED"
            for row in satellite["commands"]), "decoded_packets":len(consumed)}
