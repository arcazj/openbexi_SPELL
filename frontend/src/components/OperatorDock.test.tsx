import { configureStore } from "@reduxjs/toolkit";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Provider } from "react-redux";
import { afterEach, describe, expect, it, vi } from "vitest";
import { consoleSlice, resyncExecution, startExecution } from "../store";
import type { ExecutionSchedule, ExecutionSnapshot, ParentChildLink } from "../types";
import { ActionsPanel, InspectionPanel, RelationshipsPanel, SchedulesPanel } from "./OperatorDock";

const execution: ExecutionSnapshot = {
  id: "execution-1",
  procedure_id: "demo",
  procedure_name: "Demo",
  context_id: "simulator",
  state: "PAUSED",
  revision: 5,
  last_sequence: 4,
  steps: [],
  telemetry: [],
  events: [],
  logs: [],
  ownership_mode: "C",
  controller_lease: {
    id: "lease-1",
    revision: 2,
    fencing_token: 7,
    execution_id: "execution-1",
    holder_subject_id: "operator",
    issued_at: "2026-08-15T10:00:00Z",
    expires_at: "2099-08-15T10:01:00Z",
    state: "ACTIVE",
    held_by_current_session: true,
  },
};

afterEach(() => { cleanup(); vi.restoreAllMocks(); window.sessionStorage.clear(); });

describe("named action controls", () => {
  it("uses durable disable and dismiss mutations and renders their authoritative state", async () => {
    let action = { id: "action-1", revision: 2, execution_id: "execution-1", name: "ack", label: "Acknowledge", severity: "warning", handler_id: "handler-1", enabled: true, dismissed: false, source_digest: "a".repeat(64) };
    const operations: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      if (init?.method === "POST") {
        const operation = String(JSON.parse(String(init.body)).operation);
        operations.push(operation);
        action = { ...action, revision: action.revision + 1, enabled: operation === "ENABLE" ? true : operation === "DISABLE" ? false : action.enabled, dismissed: operation === "DISMISS" };
        return new Response(JSON.stringify({ action }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ items: [action] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(startExecution.fulfilled(execution, "start", { procedureId: "demo", contextId: "simulator" }));
    render(<Provider store={store}><ActionsPanel /></Provider>);

    await userEvent.click(await screen.findByRole("button", { name: "Disable Acknowledge" }));
    expect(await screen.findByRole("button", { name: "Enable Acknowledge" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Dismiss Acknowledge" }));

    await waitFor(() => expect(screen.getByText(/DISMISSED/)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Dismiss Acknowledge" })).toBeDisabled();
    expect(operations).toEqual(["DISABLE", "DISMISS"]);
  });
});

describe("bounded console controls", () => {
  it("exposes and sends all five canonical typed operations", async () => {
    const operations: Array<Record<string, unknown>> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        operations.push(body);
        return new Response(JSON.stringify({ operation: body.operation, result: {} }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ items: [{ path: "IVARS.counter", scope: "IVARS", name: "counter", type: "INTEGER", value: 2, value_revision: 3, execution_revision: 5, freshness: "CURRENT", editable: true, redacted: false }], console_operations: ["LIST_SCOPE", "READ_VALUE", "EXPAND_VALUE", "SEARCH_SOURCE_LITERAL", "WRITE_TYPED_LITERAL"], execution_revision: 5 }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(startExecution.fulfilled(execution, "start", { procedureId: "demo", contextId: "simulator" }));
    render(<Provider store={store}><InspectionPanel /></Provider>);
    await screen.findByRole("option", { name: /IVARS.counter/ });
    const select = screen.getByRole("combobox", { name: "Bounded console operation" });
    for (const label of ["List scope", "Read value", "Expand value", "Search source literal", "Write typed literal"]) {
      expect(within(select).getByRole("option", { name: label })).toBeInTheDocument();
    }
    const run = screen.getByRole("button", { name: "Run bounded console operation" });
    const user = userEvent.setup();

    await user.click(run);
    await waitFor(() => expect(operations).toHaveLength(1));
    await user.selectOptions(select, "LIST_SCOPE"); await user.click(run);
    await waitFor(() => expect(operations).toHaveLength(2));
    await user.selectOptions(select, "EXPAND_VALUE"); await user.click(run);
    await waitFor(() => expect(operations).toHaveLength(3));
    await user.selectOptions(select, "SEARCH_SOURCE_LITERAL");
    await user.type(screen.getByRole("textbox", { name: "Source literal query" }), "counter"); await user.click(run);
    await waitFor(() => expect(operations).toHaveLength(4));
    await user.selectOptions(select, "WRITE_TYPED_LITERAL"); await user.click(run);
    await waitFor(() => expect(operations).toHaveLength(5));

    expect(operations.map((body) => body.operation)).toEqual(["READ_VALUE", "LIST_SCOPE", "EXPAND_VALUE", "SEARCH_SOURCE_LITERAL", "WRITE_TYPED_LITERAL"]);
    expect(operations[1]).toMatchObject({ scope: "IVARS" });
    expect(operations[3]).toMatchObject({ query: "counter", limit: 50 });
    expect(operations.slice(0, 4).every((body) => !("lease_id" in body))).toBe(true);
    expect(operations[4]).toMatchObject({ path: "IVARS.counter", type: "INTEGER", value: 2, lease_id: "lease-1", control_fencing_token: 7 });
  });

  it("sends canonical typed ARGS writes when the safe-state projection is editable", async () => {
    const mutations: Array<Record<string, unknown>> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        mutations.push(body);
        return new Response(JSON.stringify({ operation: body.operation, result: {} }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({
        items: [{ path: "ARGS.mode", scope: "ARGS", name: "mode", type: "STRING", value: "nominal", value_revision: 1, execution_revision: 5, freshness: "CURRENT", editable: true, redacted: false }],
        console_operations: ["LIST_SCOPE", "READ_VALUE", "EXPAND_VALUE", "SEARCH_SOURCE_LITERAL", "WRITE_TYPED_LITERAL"],
        execution_revision: 5,
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(startExecution.fulfilled(execution, "start", { procedureId: "demo", contextId: "simulator" }));
    render(<Provider store={store}><InspectionPanel /></Provider>);
    await screen.findByRole("option", { name: /ARGS.mode/ });

    expect(screen.getByLabelText("Typed literal")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Commit audited edit" })).toBeEnabled();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Bounded console operation" }), "WRITE_TYPED_LITERAL");
    await userEvent.click(screen.getByRole("button", { name: "Run bounded console operation" }));
    await waitFor(() => expect(mutations).toHaveLength(1));
    expect(mutations[0]).toMatchObject({ operation: "WRITE_TYPED_LITERAL", path: "ARGS.mode", type: "STRING", value: "nominal", lease_id: "lease-1", control_fencing_token: 7 });
  });
});

describe("durable projection panels", () => {
  it("adopts schedule and relationship changes from an authoritative resync", async () => {
    let schedules: ExecutionSchedule[] = [{ id: "schedule-1", revision: 1, controller_execution_id: "execution-1", schedule_type: "RELATIVE", original_target: "60", target_at_database_time: "2026-08-15T10:01:00Z", state: "PENDING", catalog_revision_id: "catalog-1", context_id: "simulator", automatic: true, background_allowed: true }];
    let relationships: ParentChildLink[] = [{ id: "link-1", startproc_id: "startproc-1", parent_execution_id: "execution-1", child_execution_id: "child-1", child_catalog_revision_id: "catalog-child", arguments_digest: "a".repeat(64), blocking: true, visible: true, automatic: true }];
    const requestedUrls: URL[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = new URL(String(input), "http://localhost");
      requestedUrls.push(url);
      const path = url.pathname;
      const items = path.endsWith("/telemetry-schedules") ? [] : path.endsWith("/schedules") ? schedules : relationships;
      return new Response(JSON.stringify({ items }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(startExecution.fulfilled({ ...execution, schedules, relationships }, "start", { procedureId: "demo", contextId: "simulator" }));
    render(<Provider store={store}><SchedulesPanel /><RelationshipsPanel /></Provider>);

    expect(await screen.findByText("PENDING")).toBeInTheDocument();
    expect(await screen.findByTitle("child-1")).toBeInTheDocument();
    expect(requestedUrls.find((url) => url.pathname.endsWith("/schedules"))?.searchParams.get("controller_execution_id")).toBe("execution-1");

    schedules = [{ ...schedules[0]!, revision: 2, state: "FIRED" }];
    relationships = [{ ...relationships[0]!, id: "link-2", startproc_id: "startproc-2", child_execution_id: "child-2" }];
    store.dispatch(resyncExecution.fulfilled({ ...execution, revision: 6, last_sequence: 5, schedules, relationships }, "resync", "execution-1"));

    expect(await screen.findByText("FIRED")).toBeInTheDocument();
    expect(await screen.findByTitle("child-2")).toBeInTheDocument();
  });

  it("creates and cancels a bounded typed telemetry-conditioned schedule", async () => {
    const requests: Array<{ path: string; body?: Record<string, unknown> }> = [];
    let telemetrySchedule: Record<string, unknown> | null = null;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = new URL(String(input), "http://localhost");
      const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined;
      requests.push({ path: url.pathname, body });
      if (url.pathname === "/api/v1/schedules") {
        return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (url.pathname.endsWith("/cancel")) {
        telemetrySchedule = { ...telemetrySchedule, revision: 2, state: "CANCELLED" };
        return new Response(JSON.stringify({ schedule: telemetrySchedule }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (url.pathname === "/api/v1/telemetry-schedules" && init?.method === "POST") {
        const conditionPlan = body?.condition_plan as Record<string, unknown>;
        telemetrySchedule = {
          schedule_id: "e".repeat(64),
          revision: 1,
          controller_execution_id: "execution-1",
          schedule_type: "TELEMETRY_CONDITION",
          state: "PENDING",
          condition_plan_id: conditionPlan.condition_plan_id,
          condition_plan_digest: "b".repeat(64),
          quality_freshness_policy_id: "simulator-default",
          quality_freshness_policy_revision: "v07-r1",
          start_snapshot_cursor: "4",
          retry_count: 1000,
          retry_interval_ns: 250_000_000,
          deadline_at_database_time: "2026-08-15T10:02:00Z",
          procedure_catalog_id: "demo",
          procedure_revision: 1,
          bundle_digest: "c".repeat(64),
          context_id: "simulator",
          arguments: {},
          arguments_digest: "d".repeat(64),
          automatic: true,
          background_allowed: true,
          visible: true,
        };
        return new Response(JSON.stringify({ schedule: telemetrySchedule }), { status: 201, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ items: telemetrySchedule ? [telemetrySchedule] : [] }), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(consoleSlice.actions.setSelectedProcedure("demo"));
    store.dispatch(startExecution.fulfilled(execution, "start", { procedureId: "demo", contextId: "simulator" }));
    render(<Provider store={store}><SchedulesPanel /></Provider>);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Telemetry" }));
    expect(screen.getByRole("combobox", { name: "Telemetry item" })).toHaveValue("TM.POWER.BUS_VOLTAGE");
    expect(screen.getByRole("combobox", { name: "Comparison operator" })).toHaveValue("GE");
    await user.clear(screen.getByRole("spinbutton", { name: "Condition value" }));
    await user.type(screen.getByRole("spinbutton", { name: "Condition value" }), "31.5");
    await user.clear(screen.getByRole("spinbutton", { name: "Telemetry timeout in seconds" }));
    await user.type(screen.getByRole("spinbutton", { name: "Telemetry timeout in seconds" }), "120");
    await user.click(screen.getByRole("button", { name: "Create telemetry schedule" }));

    expect(await screen.findByText("TELEMETRY_CONDITION")).toBeInTheDocument();
    const createRequest = requests.find((request) => request.path === "/api/v1/telemetry-schedules" && request.body);
    expect(createRequest?.body).toMatchObject({
      controller_execution_id: "execution-1",
      timeout_seconds: 120,
      retry_count: 1000,
      retry_interval_seconds: 0.25,
      procedure_catalog_id: "demo",
      context_id: "simulator",
      expected_execution_revision: 5,
      lease_id: "lease-1",
      control_fencing_token: 7,
    });
    expect(createRequest?.body?.condition_plan).toMatchObject({
      schema_version: "spell.v07.condition-plan/1",
      root: {
        operator: "GE",
        left: {
          item_id: "TM.POWER.BUS_VOLTAGE",
          catalog_digest: "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94",
          scalar_type: "FINITE_DOUBLE",
          value_field: "ENGINEERING",
        },
        right: { value: { type: "FINITE_DOUBLE", value: 31.5 } },
      },
    });

    await user.click(screen.getByRole("button", { name: `Cancel schedule ${"e".repeat(64)}` }));
    expect(await screen.findByText("CANCELLED")).toBeInTheDocument();
    expect(requests.find((request) => request.path.endsWith("/cancel"))?.body).toMatchObject({
      controller_execution_id: "execution-1",
      expected_schedule_revision: 1,
    });

    await user.click(screen.getByRole("button", { name: "Relative" }));
    expect(screen.getByLabelText("Delay (seconds)")).toBeInTheDocument();
  });
});
