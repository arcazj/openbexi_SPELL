"""Execute the mandatory v0.19 DSS procedure and transport delivery gate."""
from __future__ import annotations

import argparse
import json
import os
import time
import uuid
import urllib.parse
from pathlib import Path
import urllib.request

from scripts.validate_dss_delivery import (
    ROOT, MANIFEST_SCHEMA, canonical, load_manifest, sha256, source_inventory,
)

RELEASE = "v0.19.0"
MANIFEST = ROOT / "contracts/dss/procedure_scenarios_v19.json"
REFERENCE_MAPPING = ROOT / "contracts/dss/reference_adapters_v19.json"


def language_failure_detail(selection, events):
    """Retain the actual failing phase; never invent an inner execution."""
    failures = [row["payload"] for row in events if row["event_type"] == "procedure.dss_language_failed"]
    if failures:
        return {**failures[-1], "phase":"inner_dispatch"}
    from backend.language_conformance_v19 import CASES, ALL_SELECTION
    subject = (f"adaptation:{selection + 1:03}" if selection < 195 else
        "case:" + CASES[selection - 195]["id"] if selection < ALL_SELECTION else "selection:ALL")
    errors = [row["payload"].get("error") or row["payload"].get("reason") for row in events
        if row["event_type"] in {"worker.consumer_failed", "execution.state_changed", "procedure.failed"}]
    return {"subject":subject, "phase":"outer_execution", "error":next(
        (value for value in reversed(errors) if value), "terminal execution lacks a durable failure reason")}


def _scenario(identity, procedure, actions, expected, **inputs):
    from backend.dss_scenarios import procedure_execution_spec
    value = {"id": identity, "subject": "procedure:procedures/" + procedure + ".spell.py",
        "inputs": {"observation_input": "nominal", **inputs,
            "execution_spec":procedure_execution_spec(actions,inputs,run_all=procedure=="language_reference_244",
                brokered=procedure=="language_reference_244")}, "operator_actions": actions,
        "expected": expected}
    return {**value, "definition_sha256": sha256(canonical(value))}


def _expect(terminal="completed", *, commands=0, loaded=0, variables=None, logs=None, observations=None, command_fault=None):
    result = {"terminal": terminal, "variables": variables or {}, "logs": logs or [],
        "outer_executed_commands": commands, "outer_loaded_unexecuted_commands": loaded, "observations": observations or []}
    if command_fault is not None:
        result["command_fault"] = command_fault
    return result


def scenario_definitions() -> list[dict]:
    """Reviewed inputs and independent procedure outcomes; never observed-result templates."""
    yes = {"action": "answer", "value": "YES"}
    no = {"action": "answer", "value": "NO"}
    abort = {"action": "abort"}
    observed = [["GET_TM", "OK"], ["VERIFY", "TRUE"], ["WAIT_FOR", "SATISFIED"]]
    rows = [
        _scenario("catalog-reference-all", "language_reference_244", [{"action": "answer", "value": 343}],
            _expect(variables={"selected_index":343, "example_number":344,
                "result":"Language checks: 148 PASS; 195 adaptations; full support: false"},
                logs=["Language checks: 148 PASS; 195 adaptations; full support: false"])),
        _scenario("native-branch-yes-confirm", "native_command_branch_v18", [yes, yes],
            _expect(commands=1, variables={"answer":"YES", "mask":9}, logs=["Simulated command completed"])),
        _scenario("native-branch-no", "native_command_branch_v18", [no],
            _expect(variables={"answer":"NO", "mask":9}, logs=["No command requested"])),
        _scenario("native-branch-confirm-no", "native_command_branch_v18", [yes, no],
            _expect("failed", variables={"answer":"YES", "mask":9})),
        _scenario("native-branch-abort", "native_command_branch_v18", [abort],
            _expect("aborted", variables={"mask":9})),
        _scenario("native-default-no", "native_command_default_v18", [{"action":"await_default", "value":"NO"}],
            _expect(variables={"answer":"NO"}, logs=["No command requested"])),
        _scenario("native-default-explicit-no", "native_command_default_v18", [no],
            _expect(variables={"answer":"NO"}, logs=["No command requested"])),
        _scenario("native-default-explicit-yes", "native_command_default_v18", [yes],
            _expect(commands=1, variables={"answer":"YES"}, logs=["Simulated command completed"])),
        _scenario("prompt-warning-default", "prompt_workflow_v17", [
            {"action":"await_warning"}, {"action":"answer", "value":"A"},
            {"action":"await_default", "value":2.5}, {"action":"answer", "value":"qualification"},
            {"action":"answer", "value":"OK"}],
            _expect(variables={"route":"A", "rate":2.5, "note":"qualification", "answer":"OK"},
                logs=["A", "Numeric default committed", "qualification", "OK"])),
        _scenario("prompt-cancel-is-value", "prompt_workflow_v17", [
            {"action":"answer", "value":"B"}, {"action":"answer", "value":"3.5"},
            {"action":"answer", "value":"backup"}, {"action":"answer", "value":"CANCEL"}],
            _expect(variables={"route":"B", "rate":3.5, "note":"backup", "answer":"CANCEL"},
                logs=["B", "Numeric default committed", "backup", "CANCEL"])),
        _scenario("prompt-abort-unbound", "prompt_workflow_v17", [abort], _expect("aborted")),
        _scenario("direct-built-load-only", "telecommand_modes_v18", [],
            _expect(commands=2, loaded=1, logs=["Direct command completed", "Built command completed",
                "Final command loaded only; not executed"])),
        _scenario("dss-command-catalog", "dss_command_catalog_v19", [],
            _expect(commands=3,logs=["Satellite catalog commands completed"])),
        _scenario("observation-yes-confirm", "observation_command_v19", [yes, yes],
            _expect(commands=1, variables={"reading":28.0, "status":"TRUE", "answer":"YES"},
                observations=observed, logs=["Observed simulator command completed"])),
        _scenario("observation-native-no", "observation_command_v19", [no],
            _expect(variables={"reading":28.0, "status":"TRUE", "answer":"NO"},
                observations=observed, logs=["No command requested"])),
        _scenario("observation-confirm-no", "observation_command_v19", [yes, no],
            _expect("failed", variables={"reading":28.0, "status":"TRUE", "answer":"YES"}, observations=observed)),
        _scenario("observation-native-abort", "observation_command_v19", [abort],
            _expect("aborted", variables={"reading":28.0, "status":"TRUE", "answer":""}, observations=observed)),
        _scenario("observation-false-overwrites-true", "observation_decision_v19", [],
            _expect(variables={"status":"FALSE"}, observations=[["VERIFY","FALSE"]],
                logs=["Condition not met; no command requested"])),
        _scenario("observation-wait-timeout", "observation_wait_v19", [],
            _expect("failed", observations=[["WAIT_FOR","TIMED_OUT"]])),
    ]
    for fault in ("missing", "stale", "invalid", "bad-quality", "gap", "policy"):
        rows.append(_scenario("observation-rejects-" + fault, "observation_command_v19", [],
            _expect("failed", variables={"reading":0.0, "status":"", "answer":""},
                    observations=[["GET_TM","NOT_AVAILABLE"]]), observation_input=fault))
    for fault, actions, commands, loaded, outcome, disposition, certainty, stages in (
        ("transport_rejection", [yes,no], 0, 0, "SETTLED", "TRANSPORT_REJECTED", "NO_EFFECT", [["TRANSPORT","REJECTED"]]),
        ("execution_failure", [yes], 0, 1, "SETTLED", "EXECUTION_FAILED", "EFFECT_UNKNOWN",
            [["TRANSPORT","ACCEPTED"],["LOADING","LOADED"],["RELEASE","RELEASED"],
             ["ACKNOWLEDGEMENT","ACKNOWLEDGED"],["ONBOARD_EXECUTION","FAILED"]]),
        ("lost_release_ack", [yes], 1, 0, "UNCERTAIN", "UNCERTAIN", "EFFECT_UNKNOWN",
            [["TRANSPORT","ACCEPTED"],["LOADING","LOADED"],["RELEASE","RELEASED"]]),
        ("release_ack_timeout", [yes], 1, 0, "UNCERTAIN", "UNCERTAIN", "EFFECT_UNKNOWN",
            [["TRANSPORT","ACCEPTED"],["LOADING","LOADED"],["RELEASE","RELEASED"]]),
    ):
        rows.append(_scenario("command-"+fault, "native_command_default_v18", actions,
            _expect("failed",commands=commands,loaded=loaded,variables={"answer":"YES"},
                command_fault={"kind":fault,"request_count":1,"result_count":1,"outcome":outcome,
                    "dispositions":[disposition],"effect_certainties":[certainty],"physical_stages":stages,
                    "maximum_ingress_attempts_per_stage":1}), command_fault=fault))
    # The final ordinary scenario resets declared faults only after every prior
    # scenario has terminated and its evidence and oracle have been checked.
    rows.append(_scenario("core-tutorial", "tutorial_core_v18", [],
        _expect(variables={"total":12, "power":32, "mask":3, "label":"core checks passed", "item":6},
            logs=["core checks passed", "", "Whitespace is preserved:  "])))
    return rows


def build_manifest() -> dict:
    inventory = source_inventory(RELEASE)
    return {"schema_version":MANIFEST_SCHEMA, "release":RELEASE, "inventory":inventory,
        "inventory_sha256":sha256(canonical(inventory)), "scenarios":scenario_definitions()}


def reference_mapping() -> dict:
    golden = json.loads((ROOT / "artifacts/v0.10/reference-examples.json").read_bytes())
    operations = sorted({trace["operation"] for result in golden["results"] for trace in result["trace"]})
    return {"schema_version":"spell.dss.reference-adapters/1", "release":RELEASE,
        "raw_snippet_execution_claim":False, "legacy_catalog_digest":"262a617704ae19c95fa6c7cbe7a74577fd4096bda941474052e657bfb54b9fc7",
        "operations":{operation:{"execution":"ACTUAL_TLM" if operation == "GetTM" else
            "ACTUAL_CMD" if operation in {"Send","SetGroundParameter"} else "EXECUTED_LOCAL_ADAPTATION",
            "physical_spacecraft_capability_claim":False} for operation in operations},
        "telemetry_aliases":{name:{"item_id":name, "logical_time":"REFERENCE_READ_ORDINAL",
            "actual_time":"DSS_PACKET_ACQUISITION_AND_SIMULATION_TIME",
            "integer_conversion":"EXACT_ONLY_WHEN_LEGACY_VALUE_IS_INTEGER"}
            for name in ("TMparam","TMparam1","TMparam2","TMparam3","tm1","tm2",
                "TM.POWER.BUS_VOLTAGE","TM.POWER.SAFE_MODE","TM.THERMAL.MODE")},
        "command_mappings":[{"operation":"Send", "legacy_item":"TC.SIMULATOR.RESET",
            "physical_command":"DSS.REFERENCE.SEND", "arguments":["ARG1","ARG2"],
            "logical_labels_only":["resolved_from","supplied_as","argument_source","confirm","confirm_critical","monitoring"]},
            {"operation":"SetGroundParameter", "legacy_item":"TMparam", "physical_command":"DSS.REFERENCE.SET_GROUND",
             "arguments":{"PARAMETER":"TMparam", "VALUE":23.0}}],
        "declared_accelerated_simulation_scenarios":["adaptation:061","adaptation:062","adaptation:074","case:v18-relative-release-intent","case:v18-bounded-delay-and-timeout"],
        "scope":"Existing bounded local adaptations execute; CMD/TLM operations additionally use actual binary DSS drivers. Native language completeness is not implied."}


class Api:
    """Parent-only HTTP client; authorization is never serialized into reports."""
    def __init__(self, base: str, token: str | None = None):
        self.base, self.token = base.rstrip("/"), token

    def call(self, path: str, value: dict | None = None, *, headers_extra=None) -> dict:
        headers = {"Content-Type":"application/json"}
        token_path = os.environ.get("SPELL_DSS_GATE_TOKEN_FILE") if self.token else None
        token = Path(token_path).read_text(encoding="utf-8").strip() if token_path else self.token
        if token:
            headers["Authorization"] = "Bearer " + token
        headers.update(headers_extra or {})
        request = urllib.request.Request(self.base + path,
            data=None if value is None else canonical(value), headers=headers,
            method="GET" if value is None else "POST")
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(32_000_001)
        if len(data) > 32_000_000:
            raise ValueError("DSS API response exceeds its bound")
        result = json.loads(data)
        if type(result) is not dict:
            raise ValueError("DSS API response is not an object")
        return result


class DeliveryQualifier:
    def __init__(self, backend, dss, bindings, output):
        self.backend, self.dss, self.bindings, self.output = backend, dss, bindings, output
        self.manifest = load_manifest(RELEASE)
        self.definitions = {row["id"]:row for row in self.manifest["inventory"]}
        self.results, self.scenarios, self.captures = {}, [], {}
        self.current_identity="initialization"
        self.logs = output.with_name(output.stem + "-cases")
        self.logs.mkdir(parents=True, exist_ok=True)
        self.capture_root = output.parent / "dss-validation-captures"
        self.capture_root.mkdir(parents=True, exist_ok=True)
        if any(self.capture_root.iterdir()):
            raise ValueError("DSS capture directory is not empty; preserve the prior attempt before a new run")

    def events(self, execution_id):
        rows, after = [], 0
        for _ in range(200):
            page = self.backend.call(f"/api/v1/executions/{execution_id}/events?after_sequence={after}&limit=1000")["items"]
            if any(row["execution_id"] != execution_id for row in page):
                raise ValueError("DSS API returned another execution's events")
            rows.extend(page)
            if len(page) < 1000:
                return rows
            after = page[-1]["sequence"]
        raise ValueError("DSS execution event bound exceeded")

    def reset(self, identity, inputs):
        from backend.dss_scenarios import procedure_execution_spec
        from backend.dss_capture import set_running
        from dss.engine import scenario_retirement_token
        state = set_running(self.dss.call,False)
        spec=procedure_execution_spec([],inputs)
        return self.dss.call("/scenarios/reset", {"scenario_id":"gate-" + uuid.uuid4().hex,
            "expected_epoch":state["epoch"], "initial_state":spec["initial_state"], "faults":spec["faults"],
            "retirement_token":scenario_retirement_token(state)})

    def run_procedure(self, identity, procedure_id, actions, inputs=None, *, selection=None):
        from backend.dss_scenarios import procedure_execution_spec, snapshot_matches_scenario, readiness_diagnostic
        from backend.dss_capture import set_running
        spec=procedure_execution_spec(actions,inputs or {},run_all=selection==343,brokered=selection is not None)
        started=time.monotonic()
        state = self.reset(identity, inputs or {})
        if selection is None:
            set_running(self.dss.call,True,epoch=state["epoch"])
        # Wait for actual host/consumer readiness before starting a source that may read immediately.
        deadline = time.monotonic() + 15
        last_reason = "no readiness observation"
        while time.monotonic() < deadline:
            telemetry = self.backend.call("/api/v1/telemetry/snapshot?context_id=simulator")
            if snapshot_matches_scenario(telemetry,state,spec):
                break
            last_reason = readiness_diagnostic(telemetry,state,spec)
            time.sleep(.05)
        else:
            raise ValueError(identity+": actual DSS epoch did not reach the committed observation repository; "+last_reason)
        created = self.backend.call("/api/v1/executions", {"procedure_id":procedure_id, "context_id":"simulator",
            "reason":"DSS exhaustive delivery " + identity, "idempotency_key":"dss-" + uuid.uuid4().hex})
        execution_id = created["execution"]["id"]
        session_id = "dss-" + uuid.uuid4().hex
        headers = {"X-Spell-Session-Id":session_id, "X-Spell-Client-Instance-Key-Id":session_id}
        lease, answered, action_index, default_prompt = None, set(), 0, None
        renewed_at=0.0
        deadline = started + spec["wall_timeout_seconds"]
        snapshot = None
        while time.monotonic() < deadline:
            snapshot = self.backend.call(f"/api/v1/executions/{execution_id}/snapshot", headers_extra=headers)
            execution = snapshot["execution"]
            if execution["state"] in {"completed", "failed", "aborted", "recovery_required"}:
                break
            if lease is not None and time.monotonic()-renewed_at>60:
                lease=self.backend.call(f"/api/v1/executions/{execution_id}/control",{
                    "action":"RENEW","session_id":session_id,"client_instance_key_id":session_id,
                    "expected_execution_revision":execution["revision"],"lease_id":lease["id"],
                    "expected_lease_revision":lease["revision"],"control_fencing_token":lease["control_fencing_token"],
                    "lease_seconds":300,"idempotency_key":"renew-"+uuid.uuid4().hex,"reason":"DSS qualification lease"},
                    headers_extra=headers)["control_lease"]
                renewed_at=time.monotonic()
            prompt = snapshot.get("active_prompt")
            if prompt is None or prompt["id"] in answered:
                time.sleep(.05)
                continue
            if action_index >= len(actions):
                raise ValueError(identity + ": unexpected operator prompt " + prompt["question"])
            action = actions[action_index]
            if action["action"] == "await_warning":
                if not prompt.get("warning_emitted_at"):
                    time.sleep(.05)
                    continue
                action_index += 1
                continue
            if action["action"] == "await_default":
                default_prompt = {"id":prompt["id"], "value":action["value"]}
                answered.add(prompt["id"])
                action_index += 1
                continue
            if lease is None:
                lease = self.backend.call(f"/api/v1/executions/{execution_id}/control", {
                    "action":"ACQUIRE", "session_id":session_id, "client_instance_key_id":session_id,
                    "expected_execution_revision":execution["revision"], "lease_seconds":300,
                    "acknowledgement":"I accept responsibility for the DSS qualification prompt",
                    "idempotency_key":"lease-" + uuid.uuid4().hex, "reason":"DSS qualification"},
                    headers_extra=headers)["control_lease"]
                renewed_at=time.monotonic()
            body = {"action":"ABORT" if action["action"] == "abort" else "COMMIT", "value":action.get("value"),
                "expected_prompt_revision":prompt["revision"], "lease_id":lease["id"],
                "expected_lease_revision":lease["revision"], "control_fencing_token":lease["control_fencing_token"],
                "session_id":session_id, "client_instance_key_id":session_id,
                "idempotency_key":"answer-" + uuid.uuid4().hex, "reason":"DSS qualification"}
            self.backend.call(f"/api/v1/prompts/{prompt['id']}/responses", body, headers_extra=headers)
            answered.add(prompt["id"])
            action_index += 1
        else:
            raise ValueError(identity + ": real procedure did not reach its bounded terminal outcome")
        events = self.events(execution_id)
        if selection is None:
            set_running(self.dss.call,False,epoch=state["epoch"])
        if selection is not None and snapshot["execution"]["state"] != "completed":
            detail = language_failure_detail(selection, events)
            self.logs.joinpath(identity.replace(":","-")+"-failed.json").write_bytes(canonical({
                "identity":identity,"execution_id":execution_id,"terminal":snapshot["execution"]["state"],
                "selection":selection,"failure":detail,"snapshot":snapshot,"events":events})+b"\n")
            raise ValueError(identity+": "+str(detail.get("subject"))+": "+str(detail.get("error"))[:1000])
        if action_index != len(actions):
            raise ValueError(identity + ": required operator actions were not executed")
        capture = {"execution":snapshot["execution"], "events":events, "actions":actions,
            "procedure":self.backend.call("/api/v1/procedures/" + procedure_id),
            "execution_spec":spec,"elapsed_seconds":time.monotonic()-started,"initial_dss_state":state}
        report=self.backend.call(f"/api/v1/executions/{execution_id}/report")
        capture["typed_prompts"]=report["typed_prompts"]
        capture["operator_audit"]=report["operator_audit"]
        if default_prompt is not None:
            if not any(row["id"]==default_prompt["id"] and row.get("settlement",{}).get("actor")=="operator-reconciler"
                       and row["settlement"].get("value")==default_prompt["value"] for row in report["typed_prompts"]):
                raise ValueError(identity + ": automatic default lacks an actual settlement event")
        if selection is not None:
            from backend.dss_language_broker import result_for_request, selected_subjects
            evidence = self.backend.call(f"/api/v1/executions/{execution_id}/dss-language-evidence")
            if not evidence["items"]:
                raise ValueError(identity + ": no actual parent-broker execution was recorded")
            request = evidence["items"][0]["request"]
            if request["selection"] != selection or len(evidence["items"]) != len(selected_subjects(request)):
                raise ValueError(identity + ": parent broker selected another or incomplete case set")
            subjects = []
            for subject in selected_subjects(request):
                path = f"/api/v1/executions/{execution_id}/dss-language-evidence?request_id={request['request_id']}&subject=" + urllib.parse.quote(subject,safe="")
                item = self.backend.call(path)["items"]
                if len(item) != 1 or item[0]["state"] != "SETTLED":
                    raise ValueError(identity + ": inner case is not durably settled: " + subject)
                subjects.append(item[0]["result"])
            capture.update(broker_request=request, broker_result=result_for_request(request, subjects), subject_results=subjects)
        else:
            from backend.dss_capture import collect_evidence
            satellite=collect_evidence(self.dss.call,state["scenario_id"],conflict_retries=3)
            packets=[]
            for packet in satellite["packets"]:
                driver = self.backend.call(f"/api/v1/executions/{execution_id}/dss-driver-evidence?epoch=" + urllib.parse.quote(state["epoch"],safe="")
                    +"&packet_sha256="+packet["packet_sha256"])
                packets.extend(driver["packets"])
            capture.update(dss=collect_evidence(self.dss.call,state["scenario_id"],conflict_retries=3), driver=packets)
        capture["elapsed_seconds"]=time.monotonic()-started
        if capture["elapsed_seconds"]>spec["wall_timeout_seconds"]:
            raise ValueError(identity+": execution and evidence collection exceeded declared wall bound")
        self.logs.joinpath(identity.replace(":","-") + ".json").write_bytes(canonical({
            "identity":identity,"execution_id":execution_id,"terminal":capture["execution"]["state"],
            "subjects":[row["subject"] for row in capture.get("subject_results",[])]}) + b"\n")
        return capture

    def store_capture(self, raw):
        data=canonical(raw)
        if len(data)>16_000_000:
            raise ValueError("individual DSS capture exceeds16MiB")
        identity=sha256(data)
        path=self.capture_root / (identity + ".json")
        path.write_bytes(data)
        self.captures[identity]={"path":identity+".json","size":len(data)}
        return identity

    def evidence(self, capture, *, subject=None):
        if subject is not None:
            raw = {"subject_result":subject,"broker_request":capture["broker_request"],
                "execution":capture["execution"]}
            physical = subject["dss_evidence"]
            execution_id = capture["execution"]["id"]
        else:
            raw = dict(capture)
            execution_id = capture["execution"]["id"]
            if "subject_results" in capture:
                from backend.dss_language_broker import compact_subject_result
                raw["subject_results"]=[compact_subject_result(row) for row in capture["subject_results"]]
                raw["subject_capture_refs"]={row["subject"]:self.store_capture({"subject_result":row,
                    "broker_request":capture["broker_request"],"execution":capture["execution"]}) for row in capture["subject_results"]}
                physical = capture["subject_results"][0]["dss_evidence"]
            else:
                physical = {"scenario_id":capture["dss"]["scenario_id"],"epoch":capture["dss"]["epoch"]}
        identity = self.store_capture(raw)
        return {"mode":"SUPERVISOR_DSS_BROKER" if "broker_result" in capture else "PUBLIC_API_DSS",
            "execution_id":execution_id, "scenario_id":physical["scenario_id"], "epoch":physical["epoch"],
            "source_commit":self.bindings["source_commit"], "raw_capture_sha256":identity,
            "transport_obligations":[], "transport_results":[]}

    def result(self, identity, observed, evidence):
        definition = self.definitions[identity]
        return {"id":identity,"definition_sha256":definition["definition_sha256"],
            "status":"PASS","observed":observed,"evidence":evidence}

    def assert_normal_finish(self, capture):
        """Read-only closeout; never clear faults or replay a failed scenario."""
        if (self.manifest["scenarios"][-1]["id"] != "core-tutorial"
                or self.scenarios[-1]["id"] != "core-tutorial"):
            raise ValueError("DSS delivery must finish with the reviewed core tutorial")
        expected = capture["dss"]
        if (expected["faults"] != {} or expected["final_state"]["running"] is not False
                or expected["retirement"] is not None):
            raise ValueError("DSS final capture is not paused and fault-free")
        state = self.dss.call("/state")
        physical = {key:value for key,value in state.items() if key != "transport"}
        if canonical(physical) != canonical(expected["final_state"]):
            raise ValueError("DSS actual final state differs from its retained capture")
        page = self.dss.call("/evidence?" + urllib.parse.urlencode({
            "scenario_id":expected["scenario_id"], "offset":0, "limit":1}))
        metadata = set(expected) - {"commands", "operations", "packets"}
        if (any(key not in page or canonical(page[key]) != canonical(expected[key]) for key in metadata)
                or canonical(page["pagination"]["counts"]) != canonical({key:len(expected[key])
                    for key in ("commands", "operations", "packets")})):
            raise ValueError("DSS actual final evidence differs from its retained capture")
        final = self.dss.call("/state")
        if canonical({key:value for key,value in final.items() if key != "transport"}) != canonical(physical):
            raise ValueError("DSS actual final state changed during closeout")

    def run(self):
        from backend import language_conformance_v19 as registry
        from scripts.validate_dss_delivery import CaptureStore, validate_report, observed_procedure, reproduction_metadata, delivery_counts
        reproduction = reproduction_metadata(RELEASE)
        health = self.dss.call("/state")["transport"]
        if any(health.get(key) != reproduction["runtime_configuration"][key]
               for key in ("automatic_interval_ns", "physics_ticks_per_frame")):
            raise ValueError("Actual DSS publication cadence differs from the declared reproduction configuration")
        # Every menu choice executes independently; Run-all additionally repeats every nested case.
        for selection in range(registry.ALL_SELECTION + 1):
            identity = f"menu:{selection:03}"
            self.current_identity=identity
            print(identity, flush=True)
            capture = self.run_procedure(identity, "language_reference_244", [{"action":"answer", "value":selection}], selection=selection)
            definition = self.definitions[identity]
            evidence = self.evidence(capture)
            self.results[identity] = self.result(identity, {"selection":selection,"targets":definition["targets"]}, evidence)
            for subject in capture["subject_results"]:
                name = subject["subject"]
                if selection != registry.ALL_SELECTION:
                    self.results[name] = self.result(name, subject["semantic"], self.evidence(capture,subject=subject))
                    for variant in self.definitions.values():
                        if variant.get("parent") == name:
                            proof = next(row for row in subject["semantic"]["variant_proofs"] if "variant:" + row["variant_id"] == variant["id"])
                            self.results[variant["id"]] = self.result(variant["id"],proof,self.evidence(capture,subject=subject))
            if selection == registry.ALL_SELECTION:
                all_evidence = evidence
            # Raw child captures are now persisted and hash-addressed. Do not
            # keep the full Run-all archive alive during report validation.
            del capture, subject
        for definition in self.manifest["scenarios"]:
            self.current_identity="scenario:"+definition["id"]
            print("scenario:" + definition["id"], flush=True)
            if definition["id"] == "catalog-reference-all":
                retained = CaptureStore(self.capture_root, self.captures)
                capture = retained[all_evidence["raw_capture_sha256"]]
                evidence = all_evidence
                del retained
            else:
                procedure = Path(definition["subject"].removeprefix("procedure:")).name.removesuffix(".spell.py")
                capture = self.run_procedure(definition["id"],procedure,definition["operator_actions"],definition["inputs"])
                evidence = self.evidence(capture)
            observed = observed_procedure(capture,definition)
            if canonical(observed) != canonical(definition["expected"]):
                raise ValueError(definition["id"] + ": actual procedure outcome differs: " + canonical(observed).decode())
            self.scenarios.append({"id":definition["id"],"definition_sha256":definition["definition_sha256"],
                "status":"PASS","observed":observed,"evidence":evidence})
            if definition["subject"] not in self.results:
                self.results[definition["subject"]] = self.result(definition["subject"],
                    {"scenario_id":definition["id"],"procedure_sha256":capture["execution"]["procedure_hash"]},evidence)
        from dss import SIMULATOR_VERSION,DYNAMICS_ENGINE_VERSION
        from dss.catalog import SatelliteDatabase
        database=SatelliteDatabase.load()
        report={"schema_version":"spell.dss.delivery/1","release":RELEASE,**self.bindings,
            "database_identity":{"satellite_id":"GENERIC","revision":database.revision,"sha256":database.digest,
                "simulator_version":SIMULATOR_VERSION,"dynamics_engine_version":DYNAMICS_ENGINE_VERSION},
            "inventory_sha256":self.manifest["inventory_sha256"],"decision":"PASS","full_language_compatibility":False,
            "results":[self.results[key] for key in sorted(self.results)],"scenarios":self.scenarios,"raw_captures":self.captures,
            "reproduction":reproduction}
        report["counts"] = delivery_counts(self.manifest["inventory"], report["results"], self.scenarios, self.captures)
        validate_report(report,source_commit=self.bindings["source_commit"],image_ids=self.bindings["image_ids"],capture_root=self.capture_root)
        self.current_identity = "final-state"
        self.assert_normal_finish(capture)
        self.output.write_bytes(canonical(report)+b"\n")
        print("v0.19.0 DSS delivery: PASS",flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-contract", action="store_true")
    parser.add_argument("--check-contract", action="store_true")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8080")
    parser.add_argument("--dss-url", default="http://127.0.0.1:8080/dss/api/v1")
    parser.add_argument("--bindings", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.write_contract:
        if args.check_contract or args.output or args.bindings:
            parser.error("contract generation cannot be combined with qualification")
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_bytes((json.dumps(build_manifest(), indent=2, sort_keys=True) + "\n").encode("ascii"))
        REFERENCE_MAPPING.write_bytes((json.dumps(reference_mapping(), indent=2, sort_keys=True) + "\n").encode("ascii"))
        return 0
    if args.check_contract:
        if args.output or args.bindings:
            parser.error("contract checking is not qualification")
        if canonical(load_manifest(RELEASE)) != canonical(build_manifest()):
            raise ValueError("reviewed DSS scenario definitions are stale")
        print("DSS inventory and scenario contract: PASS")
        return 0
    if not args.output or not args.bindings:
        parser.error("--bindings and --output are required for delivery qualification")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    qualifier=None
    try:
        load_manifest(RELEASE)
        if not (os.environ.get("SPELL_DSS_GATE_TOKEN") or os.environ.get("SPELL_DSS_GATE_TOKEN_FILE")):
            raise ValueError("DSS qualification operator credential is unavailable; gate cannot be skipped")
        bindings=json.loads(args.bindings.read_bytes())
        if set(bindings) != {"source_commit","image_ids"}:
            raise ValueError("DSS qualification bindings differ")
        qualifier=DeliveryQualifier(Api(args.backend_url,os.environ.get("SPELL_DSS_GATE_TOKEN") or "token-file"),
            Api(args.dss_url),bindings,args.output)
        qualifier.run()
    except Exception as exc:
        args.output.write_bytes(canonical({"schema_version":"spell.dss.delivery/1","release":RELEASE,
            "decision":"FAIL","failed_identity":qualifier.current_identity if qualifier else "initialization",
            "error":str(exc)[:1000],"completed_identities":sorted(qualifier.results) if qualifier else []})+b"\n")
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
