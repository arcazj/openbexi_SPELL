import { configureStore } from "@reduxjs/toolkit";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Provider } from "react-redux";
import { afterEach, describe, expect, it, vi } from "vitest";
import { consoleSlice, setConnectionPhase, startExecution } from "../store";
import type { ExecutionSnapshot } from "../types";
import { ExecutionWorkspace, OwnershipControls } from "./ExecutionWorkspace";

function execution(id: string): ExecutionSnapshot {
  return {
    id,
    procedure_id: "demo",
    procedure_name: "Demo",
    context_id: "simulator",
    state: "PAUSED",
    revision: 5,
    last_sequence: 3,
    steps: [], telemetry: [], events: [], logs: [],
    ownership_mode: "C",
    controller_lease: {
      id: `lease-${id}`,
      revision: 2,
      fencing_token: 7,
      execution_id: id,
      holder_subject_id: "operator",
      issued_at: "2026-08-15T10:00:00Z",
      expires_at: "2099-08-15T10:01:00Z",
      state: "ACTIVE",
      held_by_current_session: true,
    },
  };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); window.sessionStorage.clear(); });

describe("monitor subscription lifecycle", () => {
  it("releases to background through the fenced safe-point command", async () => {
    let command: Record<string, unknown> | null = null;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path.endsWith("/commands") && init?.method === "POST") {
        command = JSON.parse(String(init.body)) as Record<string, unknown>;
        return new Response(JSON.stringify({ command: { id: "command-background", state: "ACCEPTED" } }), { status: 202, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    const current = { ...execution("one"), background_allowed: true };
    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    render(<Provider store={store}><OwnershipControls execution={current} /></Provider>);

    await userEvent.click(screen.getByRole("button", { name: /B Background/ }));
    await waitFor(() => expect(command).not.toBeNull());
    expect(command).toMatchObject({ type: "BACKGROUND", expected_execution_revision: 5, lease_id: "lease-one", expected_lease_revision: 2, control_fencing_token: 7 });
  });

  it("closes the exact active subscription on execution switch and unmount", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = new URL(String(input), "http://localhost").pathname;
      const method = init?.method ?? "GET";
      calls.push({ path, method });
      const monitorMatch = path.match(/\/executions\/([^/]+)\/monitors$/);
      const closeMatch = path.match(/\/executions\/([^/]+)\/monitors\/([^/]+)$/);
      if (method === "POST" && monitorMatch) {
        const executionId = monitorMatch[1]!;
        return new Response(JSON.stringify({ monitor: { id: `monitor-${executionId}`, execution_id: executionId, subject_id: "operator", session_id: "session", client_instance_key_id: "client", mode: "M", state: "ACTIVE" } }), { status: 201, headers: { "Content-Type": "application/json" } });
      }
      if (method === "DELETE" && closeMatch) {
        return new Response(JSON.stringify({ monitor: { id: closeMatch[2], execution_id: closeMatch[1], subject_id: "operator", session_id: "session", client_instance_key_id: "client", mode: "M", state: "CLOSED" } }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    const view = render(<Provider store={store}><OwnershipControls execution={execution("one")} /></Provider>);
    await userEvent.click(screen.getByRole("button", { name: /M Monitor/ }));
    expect(await screen.findByRole("button", { name: /M Stop/ })).toBeEnabled();

    view.rerender(<Provider store={store}><OwnershipControls execution={execution("two")} /></Provider>);
    await waitFor(() => expect(calls).toContainEqual({ path: "/api/v1/executions/one/monitors/monitor-one", method: "DELETE" }));
    await userEvent.click(await screen.findByRole("button", { name: /M Monitor/ }));
    expect(await screen.findByRole("button", { name: /M Stop/ })).toBeEnabled();

    view.unmount();
    await waitFor(() => expect(calls).toContainEqual({ path: "/api/v1/executions/two/monitors/monitor-two", method: "DELETE" }));
    await waitFor(() => expect(calls.filter((call) => call.path === "/api/v1/master").length).toBeGreaterThanOrEqual(4));
  });

  it("expires local control at the deadline and enables authoritative reacquisition", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-08-15T10:00:00Z");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const expiring = execution("one");
    expiring.controller_lease = { ...expiring.controller_lease!, expires_at: "2026-08-15T10:00:05Z" };
    const store = configureStore({ reducer: { console: consoleSlice.reducer } });

    render(<Provider store={store}><OwnershipControls execution={expiring} /></Provider>);
    expect(screen.getByRole("button", { name: /C Renew/ })).toBeEnabled();

    await act(async () => { vi.advanceTimersByTime(5_010); });

    expect(screen.getByRole("button", { name: /C Acquire/ })).toBeEnabled();
    expect(screen.getByText("EXPIRED")).toBeInTheDocument();
  });

  it("bounds authoritative snapshot and Master refresh retries after lease expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-08-15T10:00:00Z");
    const expiring = execution("one");
    expiring.controller_lease = { ...expiring.controller_lease!, expires_at: "2026-08-15T10:00:01Z" };
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = new URL(String(input), "http://localhost").pathname;
      calls.push(path);
      if (path.endsWith("/snapshot")) return new Response(JSON.stringify({ execution: expiring, active_prompt: null, events: [], telemetry: [], logs: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(startExecution.fulfilled(expiring, "start", { procedureId: "demo", contextId: "simulator" }));
    store.dispatch(setConnectionPhase("CONNECTED"));
    render(<Provider store={store}><ExecutionWorkspace /></Provider>);

    await act(async () => { await vi.advanceTimersByTimeAsync(5_100); });

    expect(calls.filter((path) => path.endsWith("/snapshot"))).toHaveLength(3);
    expect(calls.filter((path) => path.endsWith("/master")).length).toBeGreaterThanOrEqual(3);
  });

  it("submits bounded execution prompt settings through the lease-only control", async () => {
    const bodies: Record<string, unknown>[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path.endsWith("/handovers")) return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/settings") && init?.method === "PUT") {
        bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
        return new Response(JSON.stringify({ execution: {} }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (path.endsWith("/snapshot")) return new Response(JSON.stringify({ execution: execution("one"), active_prompt: null, events: [], telemetry: [], logs: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    render(<Provider store={store}><OwnershipControls execution={{ ...execution("one"), settings: { PROMPT_WARNING_DELAY: 10 } }} /></Provider>);
    await userEvent.click(screen.getByRole("button", { name: "Execution prompt settings" }));
    const warning = screen.getByLabelText(/Warning delay/);
    expect(warning).toHaveValue(10);
    await userEvent.clear(warning);
    await userEvent.type(warning, "15");
    await userEvent.type(screen.getByLabelText("Operational reason"), "Align response policy");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({
      settings: { PROMPT_WARNING_DELAY: 15, PROMPT_RESPONSE_TIMEOUT: null, NO_CONTROLLER_GRACE: null },
      expected_execution_revision: 5,
      lease_id: "lease-one",
      expected_lease_revision: 2,
      control_fencing_token: 7,
      reason: "Align response policy",
    });
  });

  it("requires a named active monitor and responsibility acknowledgement for handover", async () => {
    const bodies: Record<string, unknown>[] = [];
    const monitored = { ...execution("one"), controller_lease: { ...execution("one").controller_lease!, held_by_current_session: false } };
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path.endsWith("/monitors") && init?.method === "POST") return new Response(JSON.stringify({ monitor: { id: "monitor-one", execution_id: "one", subject_id: "relief", session_id: "session", client_instance_key_id: "client", mode: "M", state: "ACTIVE" } }), { status: 201, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/handovers") && init?.method === "POST") {
        bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
        return new Response(JSON.stringify({ handover: { id: "handover-one", execution_id: "one", revision: 1, state: "REQUESTED", requester_subject_id: "relief", requester_session_id: "session", requester_client_instance_key_id: "client", requester_monitor_id: "monitor-one", expected_execution_revision: 5, requested_at: "2026-08-15T10:00:00Z", expires_at: "2026-08-15T10:01:00Z", updated_at: "2026-08-15T10:00:00Z" } }), { status: 201, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    render(<Provider store={store}><OwnershipControls execution={monitored} /></Provider>);
    expect(screen.getByRole("button", { name: "Request control handover" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /M Monitor/ }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Request control handover" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Request control handover" }));
    await userEvent.type(screen.getByLabelText("Operational reason"), "Shift relief");
    expect(screen.getByRole("button", { name: /^Request$/ })).toBeDisabled();
    await userEvent.click(screen.getByLabelText(/I accept responsibility/));
    await userEvent.click(screen.getByRole("button", { name: /^Request$/ }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ requester_monitor_id: "monitor-one", expected_execution_revision: 5, expires_seconds: 60, reason: "Shift relief" });
    expect(bodies[0]).toHaveProperty("responsibility_acknowledgement");
    expect(bodies[0]).not.toHaveProperty("lease_id");
  });

  it("lets the current holder approve a discovered handover with current lease proof", async () => {
    const bodies: Record<string, unknown>[] = [];
    const handover = { id: "handover-one", execution_id: "one", revision: 1, state: "REQUESTED", requester_subject_id: "relief", requester_session_id: "session-2", requester_client_instance_key_id: "client-2", requester_monitor_id: "monitor-two", expected_execution_revision: 5, requested_at: "2026-08-15T10:00:00Z", expires_at: "2026-08-15T10:01:00Z", updated_at: "2026-08-15T10:00:00Z" };
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path.endsWith("/handovers") && (init?.method ?? "GET") === "GET") return new Response(JSON.stringify({ items: [handover] }), { status: 200, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/handovers/handover-one/approve") && init?.method === "POST") {
        bodies.push(JSON.parse(String(init.body)) as Record<string, unknown>);
        return new Response(JSON.stringify({ handover: { ...handover, revision: 2, state: "COMPLETED" }, execution: execution("one"), control_lease: execution("one").controller_lease, former_monitor: { id: "former-monitor-one", execution_id: "one", subject_id: "operator", session_id: "session-1", client_instance_key_id: "client-1", mode: "M", state: "ACTIVE" } }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (path.endsWith("/snapshot")) return new Response(JSON.stringify({ execution: execution("one"), active_prompt: null, events: [], telemetry: [], logs: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    render(<Provider store={store}><OwnershipControls execution={execution("one")} /></Provider>);
    await userEvent.click(await screen.findByTitle("Approve control handover from relief"));
    await userEvent.type(screen.getByLabelText("Operational reason"), "Approve shift relief");
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ expected_handover_revision: 1, expected_execution_revision: 5, lease_id: "lease-one", expected_lease_revision: 2, control_fencing_token: 7, reason: "Approve shift relief" });
    expect(await screen.findByRole("button", { name: /M Stop/ })).toBeEnabled();
  });

  it("discovers a completed requester handover and refreshes the successor lease", async () => {
    window.sessionStorage.setItem("openbexi.spell.session-id", "requester-session");
    window.sessionStorage.setItem("openbexi.spell.client-instance-key", "requester-client");
    const calls: string[] = [];
    const oldView = { ...execution("one"), controller_lease: { ...execution("one").controller_lease!, holder_session_id: "holder-session", client_instance_key_id: "holder-client", held_by_current_session: false } };
    const successor = {
      id: "successor-lease", revision: 1, control_fencing_token: 8, execution_id: "one",
      holder_subject_id: "relief", holder_session_id: "requester-session", client_instance_key_id: "requester-client",
      issued_at_database_time: "2026-08-15T10:00:00Z", expires_at_database_time: "2099-08-15T10:01:00Z", state: "ACTIVE",
    };
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      calls.push(`${url.pathname}${url.search}`);
      if (url.pathname.endsWith("/handovers")) return new Response(JSON.stringify({ items: [{
        id: "handover-complete", execution_id: "one", revision: 2, state: "COMPLETED", requester_subject_id: "relief",
        requester_session_id: "requester-session", requester_client_instance_key_id: "requester-client", requester_monitor_id: "monitor-requester",
        expected_execution_revision: 5, requested_at: "2026-08-15T10:00:00Z", expires_at: "2026-08-15T10:01:00Z",
        successor_lease_id: "successor-lease", successor_control_lease: successor, updated_at: "2026-08-15T10:00:01Z", settled_at: "2026-08-15T10:00:01Z",
      }] }), { status: 200, headers: { "Content-Type": "application/json" } });
      if (url.pathname.endsWith("/snapshot")) return new Response(JSON.stringify({ execution: { ...oldView, controller_lease: successor }, active_prompt: null, events: [], telemetry: [], logs: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    const store = configureStore({ reducer: { console: consoleSlice.reducer } });

    render(<Provider store={store}><OwnershipControls execution={oldView} /></Provider>);

    await waitFor(() => expect(store.getState().console.execution?.controller_lease?.id).toBe("successor-lease"));
    expect(store.getState().console.execution?.controller_lease?.held_by_current_session).toBe(true);
    expect(calls).toContain("/api/v1/executions/one/handovers?include_terminal=true");
    expect(calls).toContain("/api/v1/executions/one/snapshot");
  });
});
