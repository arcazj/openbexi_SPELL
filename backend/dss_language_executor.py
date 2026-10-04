"""Execute closed source cases with real workers and parent-owned DSS services."""
from __future__ import annotations

import json
import multiprocessing
import os
import queue
import threading
import time
import urllib.parse
import urllib.request

from . import language_conformance_v19 as registry
from .dss_language_broker import canonical, digest, subject_binding, case_execution_id
from .dss_scenarios import subject_execution_spec, snapshot_matches_scenario, readiness_diagnostic

_SCENARIO_LOCK = threading.Lock()


class DssLanguageExecutor:
    def __init__(self, supervisor, request, context_id, *, authorize):
        self.supervisor, self.request, self.context_id = supervisor, request, context_id
        self.runtime, self.authorize = supervisor.dss_runtime, authorize
        self.reference_mappings = []
        self.reference_reads = []
        self.url = os.environ.get("SPELL_DSS_CONTROL_URL", "http://dss:8081/api/v1").rstrip("/")

    def _http(self, path, body=None):
        self.authorize()
        request = urllib.request.Request(self.url + path, data=None if body is None else canonical(body),
            headers={"Content-Type":"application/json"}, method="GET" if body is None else "POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            data = response.read(16_000_001)
        if len(data) > 16_000_000:
            raise ValueError("DSS scenario response exceeds its bound")
        return json.loads(data)

    def _prepare(self, subject, case):
        from dss.engine import scenario_retirement_token
        from .dss_capture import set_running
        scenario = case_execution_id(self.request, subject)
        state = set_running(self._http,False)
        spec=subject_execution_spec(subject,case)
        kind = spec["observation_input"]
        state = self._http("/scenarios/reset", {"scenario_id":scenario, "expected_epoch":state["epoch"],
            "initial_state":spec["initial_state"], "faults":spec["faults"],
            "retirement_token":scenario_retirement_token(state)})
        set_running(self._http,True,epoch=state["epoch"])
        deadline = time.monotonic() + 10
        last_reason = "no readiness observation"
        while time.monotonic() < deadline:
            self.authorize()
            try:
                health = self.runtime.health(self.context_id, allow_stale=kind == "stale")
                if health["scenario_id"] == scenario and health["satellite_epoch"] == state["epoch"]:
                    snapshot = self.supervisor.observation_anchor_provider.snapshot(self.context_id)
                    from .dss_language_diagnostics import readiness
                    self.readiness_capture = readiness(snapshot,state,time.time_ns())
                    if snapshot_matches_scenario(snapshot,state,spec):
                        return state
                    last_reason = readiness_diagnostic(snapshot,state,spec)
                else:
                    last_reason = "driver health scenario/epoch differs: " + json.dumps({
                        key:str(health.get(key))[:76] for key in ("scenario_id","satellite_epoch")},sort_keys=True)
            except (ValueError, RuntimeError) as exc:
                last_reason = "readiness error type=" + type(exc).__name__
            time.sleep(0.05)
        set_running(self._http,False,epoch=state["epoch"])
        raise ValueError(subject + ": actual DSS Kafka epoch did not reach the committed observation repository; " + last_reason)

    def execute(self, subject):
        with _SCENARIO_LOCK:
            started=time.monotonic()
            self.authorize()
            self.reference_mappings = []
            self.reference_reads = []
            self.worker_capture = None
            self.readiness_capture = None
            self.observation_diagnostics = []
            self.observation_diagnostic_count = 0
            case = next((row for row in registry.CASES if subject == "case:" + row["id"]), {})
            state = self._prepare(subject, case)
            from .dss_capture import collect_evidence, set_running
            try:
                if subject.startswith("case:"):
                    semantic = self._source_case(case, state)
                else:
                    from .dss_reference_adapter import execute_adaptation
                    semantic = execute_adaptation(int(subject[11:]), self, state)
            finally:
                set_running(self._http,False,epoch=state["epoch"])
            evidence = collect_evidence(self._http, state["scenario_id"], conflict_retries=3)
            packets=[]
            for packet in evidence["packets"]:
                self.authorize()
                packets.extend(self.runtime.await_packet(state["epoch"],packet["packet_sha256"]))
            # Publication marks can trail durable consumer receipt by one commit.
            evidence = collect_evidence(self._http, state["scenario_id"], conflict_retries=3)
            spec=subject_execution_spec(subject,case)
            elapsed=time.monotonic()-started
            if elapsed>spec["wall_timeout_seconds"]:
                raise ValueError(subject+": declared execution wall bound exceeded")
            capture = {"dss":evidence, "driver":[{**row, "packet":row["packet"].hex()} for row in packets],
                "execution_spec":spec,"elapsed_seconds":elapsed,
                "reference_mappings":list(self.reference_mappings), "reference_reads":list(self.reference_reads),"worker":self.worker_capture}
            if not packets or any(row["body"]["satellite_epoch"] != state["epoch"] for row in packets):
                raise ValueError(subject + ": actual decoded DSS packet provenance is missing")
            return {"subject":subject, "binding":subject_binding(subject), "semantic":semantic,
                "dss_evidence":{"mode":"ACTUAL_DSS_DRIVER", "scenario_id":state["scenario_id"],
                    "epoch":state["epoch"], "capture_sha256":digest(capture), "capture":capture}}

    def _observation_runtime(self):
        from .condition_runtime import (CommittedObservationSnapshotProvider,
            ConditionProcedureRuntime, RepositoryGetTMResolver)
        from .condition_service import ConditionService
        repository = self.supervisor.observation_anchor_provider
        source = self.supervisor.observation_runtime
        snapshots = CommittedObservationSnapshotProvider(repository, lambda *_: self.context_id,
            expected_policy_revision=source.policy.policy_revision)
        service = ConditionService(self.supervisor.session_factory, snapshot_provider=snapshots)
        resolver = RepositoryGetTMResolver(repository, lambda _:self.context_id,
            known_item_ids=source.get_tm_resolver.known_item_ids,
            cancellation_probe=lambda *_:not self._is_authorized())
        return ConditionProcedureRuntime(service, policy=source.policy, get_tm_resolver=resolver,
            wait_retry_interval_seconds=0.001, resolver_poll_seconds=0.001)

    def _is_authorized(self):
        try:
            self.authorize()
            return True
        except Exception:
            return False

    def _source_case(self, case, state):
        from .procedure_parser import ProcedureCatalog, ProcedureValidationError
        from .worker import worker_main, evaluate_expression, sanitized_worker_environment
        from .supervisor import _WORKER_SPAWN_ENVIRONMENT_LOCK
        from .ir_v07 import observation_request_for_step
        from .runtime_composition_v19 import filter_observation_result, observation_checkpoint_variables
        from .runtime_composition_v19 import command_observation_dependencies
        from .dss_runtime import captured_observation_epochs
        from .dss_language_checkpoint import ClosedCaseCheckpoints
        from .telecommand_runtime_v11 import (validate_send_request, execute_preflight,
            confirmation_prompt_id, failure_prompt_id, prepare_send_request)
        try:
            procedure = ProcedureCatalog.__new__(ProcedureCatalog).validate_source(case["source"], case["id"] + ".spell.py")
        except ProcedureValidationError as exc:
            if exc.diagnostics[0].code != case["expected_diagnostic"]:
                raise ValueError(case["id"] + ": actual compiler diagnostic differs") from exc
            self.worker_capture = {"execution_id":state["scenario_id"], "source_sha256":case["source_sha256"],
                "compiler_diagnostics":[{"code":row.code} for row in exc.diagnostics],
                "events":[], "service_results":[]}
            return registry._expected_result(case)
        if case["expected_diagnostic"]:
            raise ValueError(case["id"] + ": expected rejection was accepted")
        execution_id = state["scenario_id"]
        context = multiprocessing.get_context("spawn")
        control, output = context.Queue(), context.Queue()
        process = context.Process(target=worker_main, args=(execution_id, 1, procedure.ir_version,
            list(procedure.steps), 0, "dss-conformance", None, {}, control, output, None, None, False))
        values, logs, prompts, commands, built, confirmations, failure_answers = {}, [], [], [], [], [], []
        observations, observation_results, results, result_steps = [], {}, [], []
        self.worker_capture = {"execution_id":execution_id, "source_sha256":case["source_sha256"],
            "ir_version":procedure.ir_version, "steps":list(procedure.steps), "events":[], "service_results":[],"prompt_settlements":[]}
        runtime = self._observation_runtime()
        committed_commands = committed_observations = 0
        terminal = None
        checkpoints = ClosedCaseCheckpoints(procedure.steps)
        with _WORKER_SPAWN_ENVIRONMENT_LOCK:
            environment = dict(os.environ)
            try:
                retained = sanitized_worker_environment()
                os.environ.clear()
                os.environ.update(retained)
                process.start()
            finally:
                os.environ.clear()
                os.environ.update(environment)
        deadline = time.monotonic() + subject_execution_spec("case:"+case["id"],case)["worker_timeout_seconds"]
        try:
            while time.monotonic() < deadline:
                self.authorize()
                try:
                    message = output.get(timeout=0.1)
                except queue.Empty:
                    if not process.is_alive(): break
                    continue
                kind = message.get("kind")
                if kind in {"prompt_opened", "observation_requested", "telecommand_requested", "step_commit"}:
                    checkpoints.admit(message)
                if kind in {"prompt_opened", "observation_requested", "telecommand_requested", "step_commit", "terminal"}:
                    self.worker_capture["events"].append({"execution_id":execution_id, **message})
                    if len(self.worker_capture["events"]) > 12000:
                        raise ValueError("DSS inner worker trace exceeds its closed bound")
                if kind == "prompt_opened":
                    step = procedure.steps[message["step_index"]]
                    if step["type"] == "prompt":
                        prompt_kind="native"
                        ordinal = len(prompts)
                        observed = {key:message.get(key) for key in registry.inherited.PROMPT_OBSERVATIONS}
                        if canonical(observed) != canonical(case.get("prompts", [])[ordinal]["observed"]):
                            raise ValueError("DSS inner prompt differs from its closed source oracle")
                        prompts.append(observed)
                        settlement = case.get("prompts", [])[ordinal]["settlements"][0]
                    elif step["type"] == "send_tc":
                        if results and message["prompt_id"] == failure_prompt_id(execution_id, step["index"], results[-1]["result_digest"]):
                            prompt_kind="failure"
                            answer = case.get("failure_answers", [])[len(failure_answers)]
                            failure_answers.append(answer)
                        else:
                            prompt_kind="confirmation"
                            _, _, preflight = prepare_send_request(execution_id, step["index"], step, values)
                            if message["prompt_id"] != confirmation_prompt_id(execution_id, step["index"], preflight.plan.plan_digest):
                                raise ValueError("DSS command confirmation identity differs")
                            answer = case.get("confirmations", [])[len(confirmations)]
                            confirmations.append(answer)
                        settlement = {"outcome":"ANSWERED", "response":answer}
                    else:
                        raise ValueError("DSS case opened an unsupported prompt")
                    settled={"type":"prompt_settlement", "prompt_id":message["prompt_id"],
                        "settlement_id":f"dss-{len(prompts)}-{len(confirmations)}-{len(failure_answers)}", **settlement}
                    self.worker_capture["prompt_settlements"].append({"kind":prompt_kind,"step_index":step["index"],"settlement":settled})
                    control.put(settled)
                elif kind in {"observation_requested", "telecommand_requested"}:
                    step = procedure.steps[message["step_index"]]
                    if step.get("guard") is not None and evaluate_expression(step["guard"], values) is not True:
                        raise ValueError("DSS service request bypassed its source guard")
                    incoming = {key:value for key,value in message.items() if key not in {"kind","generation"}}
                    if kind == "observation_requested":
                        request = observation_request_for_step(execution_id, step)
                        if canonical(incoming) != canonical(request) or step["index"] in observation_results:
                            raise ValueError("DSS observation request differs or repeats")
                        resolved_start = time.time_ns()
                        result = filter_observation_result(request, dict(runtime.resolve(request)),
                            expected_policy_revision=runtime.policy.policy_revision)
                        from .dss_language_diagnostics import MAX_RESULTS, observation
                        self.observation_diagnostic_count = getattr(self,"observation_diagnostic_count",0)+1
                        if not hasattr(self,"observation_diagnostics"):
                            self.observation_diagnostics = []
                        if len(self.observation_diagnostics)<MAX_RESULTS:
                            self.observation_diagnostics.append(observation(request,result,resolved_start,time.time_ns()))
                        observations.append(registry.observation_summary(request, result) if hasattr(registry,"observation_summary") else
                            {"operation":request["operation"], "outcome":result["outcome"], "value":result.get("value")})
                        observation_results[step["index"]] = (request, result)
                        self.worker_capture["service_results"].append({"kind":"observation", "step":step,
                            "request":request, "result":result})
                        control.put({"type":"observation_result", **result})
                    else:
                        if step["index"] in result_steps:
                            raise ValueError("DSS inner command request repeats an already dispatched instruction")
                        request, service, preflight = validate_send_request(execution_id, step["index"], step, values, incoming)
                        epochs=set()
                        with self.supervisor.session_factory() as session:
                            for position in command_observation_dependencies(list(procedure.steps),step["index"]):
                                if position not in observation_results:
                                    raise ValueError("DSS command has no captured observation dependency")
                                epochs.update(captured_observation_epochs(session,observation_results[position][1]))
                        provider = self.runtime.provider(request, preflight, procedure_id=case["id"],
                            context_id=self.context_id, authorize=self.authorize,observation_epochs=frozenset(epochs))
                        result = execute_preflight(request, service, preflight,
                            confirmation_actor="closed-dss-scenario" if preflight.confirmation_required else None,
                            provider=provider)
                        results.append(result)
                        result_steps.append(step["index"])
                        commands.append(registry._command_observation(request, result))
                        self.worker_capture["service_results"].append({"kind":"telecommand", "step":step,
                            "request":request, "result":result})
                        control.put({"type":"telecommand_result", **result})
                elif kind == "step_commit":
                    step = procedure.steps[message["step_index"]]
                    effects = message.get("effects", [])
                    if step["type"] in {"get_tm", "verify", "wait_for"}:
                        completed = {"event_type":"step.completed", "source":"worker", "severity":"info",
                            "payload":{"step_index":step["index"], "line":step["line"],
                                "step_type":step["type"], "skipped":step["index"] not in observation_results}}
                        if step["index"] in observation_results:
                            request, result = observation_results[step["index"]]
                            if (canonical(message["variables"]) != canonical(observation_checkpoint_variables(step, values, result))
                                    or len(effects) != 2 or canonical(effects[1]) != canonical(completed)):
                                raise ValueError("DSS observation checkpoint differs from actual result")
                            registry._validate_observation_effect(effects[0], request, result, step["index"])
                            committed_observations += 1
                        elif canonical(effects) != canonical([completed]) or canonical(message["variables"]) != canonical(values):
                            raise ValueError("guarded-off DSS observation fabricated a checkpoint")
                    settlements = [row["settlement"] for row in self.worker_capture["prompt_settlements"]
                        if row["step_index"] == step["index"] and row["kind"] == "native"]
                    observation = observation_results.get(step["index"])
                    values = checkpoints.commit(message, settlement=settlements[-1] if settlements else None,
                        observation_result=observation[1] if observation is not None else None)
                    logs.extend([effect["payload"]["message"], effect["severity"]] for effect in effects if effect.get("event_type") == "procedure.log")
                    if any(effect.get("event_type") == "procedure.telecommand_built" for effect in effects):
                        built.append(registry._built_name(step, values))
                    for effect in effects:
                        if effect.get("event_type") == "procedure.telecommand_settled":
                            if committed_commands >= len(results) or step["index"] != result_steps[committed_commands]:
                                raise ValueError("DSS settlement lacks its actual original command")
                            registry._validate_settlement_effect(effect, results[committed_commands], step["index"])
                            committed_commands += 1
                elif kind == "terminal":
                    terminal = message["state"]
                    if terminal == "completed" and checkpoints.cursor != len(procedure.steps):
                        raise ValueError("DSS inner completion omitted source instructions")
                    break
            process.join(timeout=1)
            if process.is_alive() or process.exitcode != 0:
                raise ValueError(case["id"] + ": actual DSS case worker did not finish cleanly")
        finally:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            control.close()
            output.close()
        try:
            semantic = registry.inherited._observed_result(case, terminal, values, logs, prompts)
        except ValueError as exc:
            summary = {"terminal":terminal, "observations":[[row["operation"],row["outcome"]] for row in observations],
                "prompts":len(prompts), "commands":len(commands), "logs":logs[:2]}
            raise ValueError(case["id"] + ": source oracle mismatch: " + canonical(summary).decode()[:250]) from exc
        if "expected_telecommands" in case:
            semantic.update(ir_version=procedure.ir_version, telecommands=commands, built_commands=built,
                confirmations=confirmations, failure_answers=failure_answers)
        if "expected_observations" in case:
            semantic["observations"] = observations
        if (committed_commands != len(commands) - int(case.get("provider") == "fail_verification")
                or committed_observations != sum(row["operation"] == "VERIFY" or row["outcome"] in {"OK","SATISFIED"} for row in observations)
                or canonical(semantic) != canonical(registry._expected_result(case))):
            raise ValueError(case["id"] + ": actual DSS semantic/service outcome differs from independent oracle")
        return semantic
