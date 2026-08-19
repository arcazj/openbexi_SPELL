import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, hasActiveControlLease, normalizeActivePrompt, type ControlProof } from "./api";
import type { ControllerHandover, InspectionValue, NamedUserAction } from "./types";

const proof: ControlProof = {
  session_id: "session-1",
  client_instance_key_id: "client-1",
  lease_id: "lease-1",
  expected_lease_revision: 4,
  control_fencing_token: 8,
};

const inspection: InspectionValue = { path: "IVARS.counter", scope: "IVARS", name: "counter", type: "INTEGER", value: 2, value_revision: 3, execution_revision: 5, freshness: "CURRENT", editable: true };
const action: NamedUserAction = { id: "action-1", revision: 2, execution_id: "execution-1", name: "ack", label: "Acknowledge", severity: "WARNING", handler_id: "handler-1", enabled: true, source_digest: "a".repeat(64) };

describe("v0.6 operator API", () => {
  beforeEach(() => window.sessionStorage.setItem("openbexi.spell.access-token", "signed.test.token"));
  afterEach(() => { window.sessionStorage.clear(); vi.unstubAllGlobals(); });

  it("normalizes canonical LIST identities without flattening typed VALUE objects", () => {
    expect(normalizeActivePrompt({
      id: "prompt-key",
      type: "LIST",
      list_mode: "KEY",
      options: [{ key: "primary", label: "Primary" }, { key: "backup", label: "Backup" }],
      revision: 1,
    })?.option_values).toEqual(["primary", "backup"]);
    expect(normalizeActivePrompt({
      id: "prompt-index",
      type: "LIST",
      list_mode: "INDEX",
      options: ["Primary", "Backup"],
      revision: 1,
    })?.option_values).toEqual([0, 1]);
    expect(normalizeActivePrompt({
      id: "prompt-value",
      type: "LIST",
      list_mode: "VALUE",
      options: [
        { value: "primary", label: "Primary" },
        { value: { route: "backup", retries: 2 }, label: "Backup" },
      ],
      revision: 1,
    })?.option_values).toEqual(["primary", { route: "backup", retries: 2 }]);
  });

  it("binds every operator workbench control to its durable resource", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      calls.push({ path, init });
      let body: unknown = {};
      if (path.endsWith("/contexts")) body = { items: [{ id: "simulator", name: "Simulator", attached: true }] };
      else if (path.endsWith("/procedures/demo/history")) body = { procedure: { current_revision: 1 }, items: [{ id: "catalog-revision-1", catalog_id: "demo", revision: 1, source_digest: "b".repeat(64), bundle_digest: "a".repeat(64), created_at: "2026-08-15T10:00:00Z" }] };
      else if (path.endsWith("/master")) body = { items: [{ id: "execution-1", procedure_id: "demo", context_id: "simulator", state: "PAUSED", revision: 5, ownership_mode: "C", controller_lease: { id: "lease-1", revision: 4, control_fencing_token: 8, execution_id: "execution-1", holder_subject_id: "operator", issued_at: "2026-08-15T10:00:00Z", expires_at: "2026-08-15T10:01:00Z", state: "ACTIVE" } }] };
      else if (path.endsWith("/executions/execution-1/control")) body = { execution: { id: "execution-1", procedure_id: "demo", context_id: "simulator", state: "PAUSED", revision: 6, ownership_mode: "C" }, control_lease: { id: "lease-1", revision: 5, control_fencing_token: 8, execution_id: "execution-1", holder_subject_id: "operator", issued_at: "2026-08-15T10:00:00Z", expires_at: "2026-08-15T10:02:00Z", state: "ACTIVE" } };
      else if (path.endsWith("/executions/execution-1/monitors") && init?.method === "POST") body = { monitor: { id: "monitor-1", execution_id: "execution-1", subject_id: "operator", session_id: "session-1", client_instance_key_id: "client-1", mode: "M", state: "ACTIVE" } };
      else if (path.endsWith("/executions/execution-1/monitors/monitor-1")) body = { monitor: { id: "monitor-1", execution_id: "execution-1", subject_id: "operator", session_id: "session-1", client_instance_key_id: "client-1", mode: "M", state: "CLOSED" } };
      else if (path.endsWith("/executions/execution-1/commands")) body = { command: { id: "command-1", state: "ACCEPTED" } };
      else if (path.endsWith("/prompts/prompt-1/responses")) body = { prompt: { id: "prompt-1", state: "SETTLED" }, attempt: { id: "attempt-1", outcome: "ACCEPTED_SETTLEMENT" } };
      else if (path.endsWith("/schedules") && (init?.method ?? "GET") === "GET") body = { items: [] };
      else if (path.endsWith("/schedules") && init?.method === "POST") body = { schedule: { id: "schedule-1", revision: 1, controller_execution_id: "execution-1", schedule_type: "RELATIVE", original_target: "60", target_at_database_time: "2026-08-15T10:01:00Z", state: "PENDING", catalog_revision_id: "catalog-revision-1", context_id: "simulator", automatic: true, background_allowed: true } };
      else if (path.endsWith("/schedules/schedule-1/cancel")) body = { schedule: { id: "schedule-1", revision: 2, controller_execution_id: "execution-1", schedule_type: "RELATIVE", original_target: "60", target_at_database_time: "2026-08-15T10:01:00Z", state: "CANCELLED", catalog_revision_id: "catalog-revision-1", context_id: "simulator", automatic: true, background_allowed: true } };
      else if (path.endsWith("/inspection") && (init?.method ?? "GET") === "GET") body = { items: [inspection] };
      else if (path.endsWith("/inspection/edits")) body = { value: { ...inspection, value: 3, value_revision: 4 } };
      else if (path.endsWith("/console-operations")) body = { operation: { state: "SETTLED" }, result: 3 };
      else if (path.endsWith("/actions") && (init?.method ?? "GET") === "GET") body = { items: [action] };
      else if (path.endsWith("/actions/action-1/mutations")) {
        const operation = JSON.parse(String(init?.body)).operation as "ENABLE" | "DISABLE" | "DISMISS";
        body = { action: { ...action, revision: 3, enabled: operation === "ENABLE", dismissed: operation === "DISMISS" } };
      }
      else if (path.endsWith("/actions/action-1/invoke")) body = { invocation: { settlement: "EXECUTED" } };
      else if (path.endsWith("/relationships")) body = { items: [] };
      else if (path.endsWith("/breakpoints") && init?.method === "DELETE") body = { removed: 1 };
      return new Response(JSON.stringify(body), { status: init?.method === "POST" ? 202 : 200, headers: { "Content-Type": "application/json" } });
    }));

    expect(await api.contexts()).toHaveLength(1);
    expect(await api.procedureHistory("demo")).toHaveLength(1);
    expect((await api.executions())[0]?.ownership_mode).toBe("C");
    expect((await api.control("execution-1", "RENEW", 5, proof)).control_lease?.revision).toBe(5);
    const monitor = await api.startMonitor("execution-1", proof);
    expect((await api.stopMonitor("execution-1", monitor.id)).state).toBe("CLOSED");
    await api.command("execution-1", "RUN", 5, "test run-to-line", proof, { line: 17, source_digest: "a".repeat(64) });
    await api.respondToPrompt("prompt-1", "COMMIT", "YES", 3, proof);
    expect(await api.schedules()).toEqual([]);
    const schedule = await api.createSchedule({ controller_execution_id: "execution-1", schedule_type: "RELATIVE", target: 60, procedure_catalog_id: "demo", context_id: "simulator", automatic: true, background_allowed: true, expected_execution_revision: 5, proof });
    expect((await api.cancelSchedule(schedule.id, schedule.revision, proof)).state).toBe("CANCELLED");
    expect(await api.inspection("execution-1")).toHaveLength(1);
    expect((await api.editInspection("execution-1", { path: inspection.path, scope: inspection.scope, type: inspection.type, value: 3, expected_value_revision: 3, expected_execution_revision: 5 }, proof)).value).toBe(3);
    await api.consoleOperation("execution-1", { operation: "LIST_SCOPE", scope: "IVARS", expected_execution_revision: 5 });
    await api.consoleOperation("execution-1", { operation: "READ_VALUE", path: inspection.path, expected_execution_revision: 5 });
    await api.consoleOperation("execution-1", { operation: "EXPAND_VALUE", path: inspection.path, expected_execution_revision: 5 });
    await api.consoleOperation("execution-1", { operation: "SEARCH_SOURCE_LITERAL", query: "counter", limit: 25, expected_execution_revision: 5 });
    await api.consoleOperation("execution-1", { operation: "WRITE_TYPED_LITERAL", path: inspection.path, type: "INTEGER", value: 3, expected_execution_revision: 5 }, proof);
    expect(await api.actions("execution-1")).toHaveLength(1);
    await api.mutateAction("execution-1", action, "DISABLE", 5, proof);
    await api.mutateAction("execution-1", action, "ENABLE", 5, proof);
    expect((await api.mutateAction("execution-1", action, "DISMISS", 5, proof)).dismissed).toBe(true);
    await api.invokeAction("execution-1", action, 5, proof);
    expect(await api.relationships("execution-1")).toEqual([]);
    await api.setBreakpoint("execution-1", 17, true, 5, proof, true);
    await api.clearBreakpoints("execution-1", 5, proof);

    expect(calls.map((call) => call.path)).toEqual([
      "/api/v1/contexts", "/api/v1/procedures/demo/history", "/api/v1/master", "/api/v1/executions/execution-1/control",
      "/api/v1/executions/execution-1/monitors", "/api/v1/executions/execution-1/monitors/monitor-1",
      "/api/v1/executions/execution-1/commands", "/api/v1/prompts/prompt-1/responses",
      "/api/v1/schedules", "/api/v1/schedules", "/api/v1/schedules/schedule-1/cancel", "/api/v1/executions/execution-1/inspection",
      "/api/v1/executions/execution-1/inspection/edits", "/api/v1/executions/execution-1/console-operations", "/api/v1/executions/execution-1/console-operations", "/api/v1/executions/execution-1/console-operations", "/api/v1/executions/execution-1/console-operations", "/api/v1/executions/execution-1/console-operations", "/api/v1/executions/execution-1/actions",
      "/api/v1/executions/execution-1/actions/action-1/mutations", "/api/v1/executions/execution-1/actions/action-1/mutations", "/api/v1/executions/execution-1/actions/action-1/mutations",
      "/api/v1/executions/execution-1/actions/action-1/invoke", "/api/v1/executions/execution-1/relationships", "/api/v1/executions/execution-1/breakpoints/17", "/api/v1/executions/execution-1/breakpoints",
    ]);
    for (const call of calls) {
      const headers = new Headers(call.init?.headers);
      expect(headers.get("Authorization")).toBe("Bearer signed.test.token");
      expect(headers.get("X-Spell-Session-Id")).toBeTruthy();
      expect(headers.get("X-Spell-Client-Instance-Key-Id")).toBeTruthy();
    }
    const mutationBodies = calls.filter((call) => ["POST", "PUT", "DELETE"].includes(call.init?.method ?? "") && call.init?.body).map((call) => JSON.parse(String(call.init?.body)) as Record<string, unknown>);
    expect(mutationBodies.filter((body) => Object.keys(body).some((key) => !["session_id", "client_instance_key_id"].includes(key))).every((body) => typeof body.idempotency_key === "string")).toBe(true);
    expect(mutationBodies.find((body) => body.action === "RENEW")).toMatchObject({ expected_execution_revision: 5, lease_id: "lease-1", control_fencing_token: 8 });
    expect(mutationBodies.find((body) => body.type === "RUN")).toMatchObject({ expected_execution_revision: 5, target: { line: 17, source_digest: "a".repeat(64) } });
    expect(mutationBodies.find((body) => body.schedule_type === "RELATIVE")).toMatchObject({ controller_execution_id: "execution-1", target: 60, procedure_catalog_id: "demo", automatic: true, background_allowed: true, expected_execution_revision: 5 });
    expect(mutationBodies.find((body) => body.schedule_type === "RELATIVE")).not.toHaveProperty("original_target");
    const consoleBodies = mutationBodies.filter((body) => ["LIST_SCOPE", "READ_VALUE", "EXPAND_VALUE", "SEARCH_SOURCE_LITERAL", "WRITE_TYPED_LITERAL"].includes(String(body.operation)));
    expect(consoleBodies.map((body) => body.operation)).toEqual(["LIST_SCOPE", "READ_VALUE", "EXPAND_VALUE", "SEARCH_SOURCE_LITERAL", "WRITE_TYPED_LITERAL"]);
    expect(consoleBodies[0]).toMatchObject({ scope: "IVARS", expected_execution_revision: 5 });
    expect(consoleBodies[1]).toMatchObject({ path: inspection.path, expected_execution_revision: 5 });
    expect(consoleBodies[2]).toMatchObject({ path: inspection.path, expected_execution_revision: 5 });
    expect(consoleBodies[3]).toMatchObject({ query: "counter", limit: 25, expected_execution_revision: 5 });
    expect(consoleBodies[4]).toMatchObject({ path: inspection.path, type: "INTEGER", value: 3, lease_id: "lease-1", control_fencing_token: 8 });
    expect(consoleBodies.slice(0, 4).every((body) => !("lease_id" in body) && !("control_fencing_token" in body))).toBe(true);
    expect(mutationBodies.filter((body) => ["DISABLE", "ENABLE", "DISMISS"].includes(String(body.operation))).map((body) => body.operation)).toEqual(["DISABLE", "ENABLE", "DISMISS"]);
    expect(mutationBodies.find((body) => body.operation === "DISABLE")).toMatchObject({ expected_action_revision: 2, expected_execution_revision: 5, lease_id: "lease-1" });
    expect(mutationBodies.find((body) => body.one_shot === true)).toMatchObject({ one_shot: true, expected_execution_revision: 5 });
    expect(mutationBodies.at(-1)).toMatchObject({ one_shot: false, expected_execution_revision: 5 });
  });

  it("derives local lease ownership and preserves typed LIST values from a snapshot", async () => {
    window.sessionStorage.setItem("openbexi.spell.session-id", "session-1");
    window.sessionStorage.setItem("openbexi.spell.client-instance-key", "client-1");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      execution: {
        id: "execution-1",
        procedure_id: "demo",
        procedure_name: "Demo",
        context_id: "simulator",
        state: "PROMPT",
        operator_state: "SUSPENDED",
        revision: 5,
        current_step: 1,
        last_sequence: 3,
        ownership_mode: "C",
        controller_lease: {
          id: "lease-1",
          revision: 2,
          control_fencing_token: 7,
          execution_id: "execution-1",
          holder_subject_id: "operator",
          holder_session_id: "session-1",
          client_instance_key_id: "client-1",
          issued_at_database_time: "2026-08-15T10:00:00Z",
          expires_at_database_time: "2026-08-15T10:01:00Z",
          state: "ACTIVE",
        },
        breakpoints: [9, 17],
        steps: [{ index: 0, line: 9, type: "startproc", child_reference: "ops/child", lexical_frame_path: ["root", "frame:1:handoff:9:1"], call_boundary_id: "frame:1:handoff:9:1", reachability_id: "frame:1:handoff:9:1:step:0", labels: [{ name: "handoff", frame_id: "root" }] }],
        text_entries: [{ id: "text-1", sequence: 2, time: "2026-08-15T10:00:01Z", scope: "prompt", kind: "prompt.opened", message: "Select route", line: 9 }],
        as_run_entries: [{ id: "run-1", sequence: 3, time: "2026-08-15T10:00:02Z", scope: "operator", kind: "control.lease_acquired", message: "Control acquired", correlation_id: "correlation-1", outcome: "PAUSED" }],
        executed_line_coverage: { source_digest: "a".repeat(64), lines: [9], through_sequence: 3 },
        workspace_cursor: 3,
        support_logs: [{ event_id: "support-1", sequence: 3, server_time: "2026-08-15T10:00:02Z", source: "supervisor", severity: "warning", event_type: "execution.warning", payload: { message: "Control recovered" } }],
        outline: [{ id: "root", label: "Demo", line: 1, depth: 0, kind: "procedure" }, { id: "child", label: "Canonical child call", line: 9, depth: 2, kind: "call" }],
      },
      active_prompt: {
        id: "prompt-1",
        revision: 4,
        state: "OPEN",
        type: "LIST",
        input_kind: "LIST",
        list_mode: "VALUE",
        question: "Select route",
        options: [{ label: "Primary", route: "primary" }, { label: "Backup", route: "backup" }],
        default: { label: "Backup", route: "backup" },
      },
      events: [], telemetry: [], logs: [],
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const snapshot = await api.snapshot("execution-1");
    expect(snapshot.state).toBe("SUSPENDED");
    expect(snapshot.revision).toBe(5);
    expect(snapshot.controller_lease?.held_by_current_session).toBe(true);
    expect(snapshot.breakpoints).toEqual([9, 17]);
    expect(snapshot.active_prompt).toMatchObject({ type: "list", options: ["Primary", "Backup"], option_values: [{ label: "Primary", route: "primary" }, { label: "Backup", route: "backup" }], default_value: { label: "Backup", route: "backup" } });
    expect(snapshot.text_entries?.[0]).toMatchObject({ scope: "prompt", kind: "prompt.opened", message: "Select route", line: 9 });
    expect(snapshot.as_run_entries?.[0]).toMatchObject({ kind: "control.lease_acquired", correlation_id: "correlation-1", outcome: "PAUSED" });
    expect(snapshot.executed_lines).toEqual([9]);
    expect(snapshot.view_cursor).toBe(3);
    expect(snapshot.support_logs?.[0]).toMatchObject({ id: "support-1", level: "WARNING", message: "Control recovered" });
    expect(snapshot.outline).toEqual(expect.arrayContaining([expect.objectContaining({ label: "Canonical child call", depth: 2, kind: "call", line: 9 })]));
  });

  it("binds workspace search to the selected view, source digest, and cursor", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({
      view: "AS_RUN",
      query: "Pause now",
      source_digest: "a".repeat(64),
      items: [{ id: "event-15", sequence: 15, time: "2026-08-15T10:00:02Z", scope: "operator", kind: "command.settled", message: "Pause now", outcome: "PAUSED" }],
      next_cursor: 15,
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await api.workspaceSearch("execution-1", "Pause now", "AS_RUN", "a".repeat(64), 14, 25);

    expect(result).toMatchObject({ view: "AS_RUN", query: "Pause now", next_cursor: 15, items: [{ id: "event-15", sequence: 15, outcome: "PAUSED" }] });
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`/api/v1/executions/execution-1/workspace-search?query=Pause+now&view=AS_RUN&after_sequence=14&limit=25&source_digest=${"a".repeat(64)}`);
  });

  it("pages authoritative workspace history with its digest and cursor", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({
      view: "AS_RUN",
      source_digest: "a".repeat(64),
      items: [{ id: "event-15", sequence: 15, time: "2026-08-15T10:00:02Z", scope: "operator", kind: "command.settled", message: "Pause now", outcome: "PAUSED" }],
      after_sequence: 14,
      next_cursor: 15,
      has_more: true,
      through_sequence: 400,
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await api.workspaceHistory("execution-1", "AS_RUN", "a".repeat(64), 14, 25);

    expect(result).toMatchObject({ view: "AS_RUN", next_cursor: 15, has_more: true, through_sequence: 400, items: [{ id: "event-15", outcome: "PAUSED" }] });
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`/api/v1/executions/execution-1/workspace-view?view=AS_RUN&after_sequence=14&limit=25&source_digest=${"a".repeat(64)}`);
  });

  it("fails closed for expired leases and redacted other-holder projections", async () => {
    const now = Date.parse("2026-08-15T10:00:00Z");
    const lease = { id: "lease-1", revision: 1, fencing_token: 2, execution_id: "execution-1", holder_subject_id: "operator", issued_at: "2026-08-15T09:59:00Z", expires_at: "2026-08-15T10:00:01Z", state: "ACTIVE" as const, held_by_current_session: true };
    expect(hasActiveControlLease({ ownership_mode: "C", controller_lease: lease }, now)).toBe(true);
    expect(hasActiveControlLease({ ownership_mode: "C", controller_lease: lease }, now + 1_000)).toBe(false);

    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ items: [{
      id: "execution-2", procedure_id: "demo", state: "PAUSED", revision: 2, ownership_mode: "C",
      controller_lease: { id: "lease-redacted", revision: 1, control_fencing_token: 3, execution_id: "execution-2", holder_subject_id: "other", issued_at_database_time: "2026-08-15T10:00:00Z", expires_at_database_time: "2099-08-15T10:01:00Z", state: "ACTIVE", held_by_current_session: false },
    }] }), { status: 200, headers: { "Content-Type": "application/json" } })));
    const redacted = (await api.executions())[0]!;
    expect(redacted.controller_lease?.holder_session_id).toBeUndefined();
    expect(redacted.controller_lease?.client_instance_key_id).toBeUndefined();
    expect(hasActiveControlLease(redacted, now)).toBe(false);
  });

  it("uses the exact two-party handover and execution-settings request shapes", async () => {
    const handover: ControllerHandover = {
      id: "handover-1", execution_id: "execution-1", revision: 1, state: "REQUESTED",
      requester_subject_id: "relief", requester_session_id: "session-2",
      requester_client_instance_key_id: "client-2", requester_monitor_id: "monitor-2",
      expected_execution_revision: 5, requested_at: "2026-08-15T10:00:00Z",
      expires_at: "2026-08-15T10:01:00Z", updated_at: "2026-08-15T10:00:00Z",
    };
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      calls.push({ path, init });
      if (path.endsWith("/handovers?include_terminal=true") && (init?.method ?? "GET") === "GET") return new Response(JSON.stringify({ items: [{ ...handover, revision: 2, state: "COMPLETED", successor_lease_id: "lease-2", successor_control_lease: { id: "lease-2", revision: 1, control_fencing_token: 9, execution_id: "execution-1", holder_subject_id: "relief", holder_session_id: "session-2", client_instance_key_id: "client-2", issued_at_database_time: "2026-08-15T10:00:00Z", expires_at_database_time: "2099-08-15T10:01:00Z", state: "ACTIVE" } }] }), { status: 200, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/handovers") && (init?.method ?? "GET") === "GET") return new Response(JSON.stringify({ items: [handover] }), { status: 200, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/handovers") && init?.method === "POST") return new Response(JSON.stringify({ handover }), { status: 201, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/handovers/handover-1/approve")) return new Response(JSON.stringify({ handover: { ...handover, revision: 2, state: "COMPLETED" }, execution: { id: "execution-1", procedure_id: "demo", state: "PAUSED", revision: 5, ownership_mode: "C" }, control_lease: { id: "lease-2", revision: 1, fencing_token: 9, execution_id: "execution-1", holder_subject_id: "relief", issued_at: "2026-08-15T10:00:00Z", expires_at: "2099-08-15T10:01:00Z", state: "ACTIVE" }, former_monitor: { id: "monitor-former", execution_id: "execution-1", subject_id: "operator", session_id: "session-1", client_instance_key_id: "client-1", mode: "M", state: "ACTIVE" } }), { status: 200, headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ execution: {} }), { status: 200, headers: { "Content-Type": "application/json" } });
    }));

    expect(await api.handovers("execution-1")).toEqual([expect.objectContaining(handover)]);
    expect((await api.handovers("execution-1", true))[0]?.successor_control_lease?.id).toBe("lease-2");
    await api.requestHandover("execution-1", "monitor-2", 5, "I accept responsibility", "Shift change", proof);
    expect((await api.approveHandover("execution-1", handover, 6, "Approved shift change", proof)).former_monitor?.id).toBe("monitor-former");
    await api.updateExecutionSettings("execution-1", { PROMPT_WARNING_DELAY: 15, PROMPT_RESPONSE_TIMEOUT: 60, NO_CONTROLLER_GRACE: null }, 6, proof, "Tune prompt policy");

    expect(calls.map((call) => [call.path, call.init?.method ?? "GET"])).toEqual([
      ["/api/v1/executions/execution-1/handovers", "GET"],
      ["/api/v1/executions/execution-1/handovers?include_terminal=true", "GET"],
      ["/api/v1/executions/execution-1/handovers", "POST"],
      ["/api/v1/executions/execution-1/handovers/handover-1/approve", "POST"],
      ["/api/v1/executions/execution-1/settings", "PUT"],
    ]);
    const requestBody = JSON.parse(String(calls[2]?.init?.body));
    expect(requestBody).toMatchObject({ requester_monitor_id: "monitor-2", expected_execution_revision: 5, responsibility_acknowledgement: "I accept responsibility", expires_seconds: 60, reason: "Shift change" });
    expect(requestBody).not.toHaveProperty("lease_id");
    const approveBody = JSON.parse(String(calls[3]?.init?.body));
    expect(approveBody).toMatchObject({ expected_handover_revision: 1, expected_execution_revision: 6, lease_id: "lease-1", expected_lease_revision: 4, control_fencing_token: 8, lease_seconds: 60, reason: "Approved shift change" });
    const settingsBody = JSON.parse(String(calls[4]?.init?.body));
    expect(settingsBody).toMatchObject({ settings: { PROMPT_WARNING_DELAY: 15, PROMPT_RESPONSE_TIMEOUT: 60, NO_CONTROLLER_GRACE: null }, expected_execution_revision: 6, lease_id: "lease-1", reason: "Tune prompt policy" });
  });
});
