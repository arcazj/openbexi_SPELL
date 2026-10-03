import { configureStore } from "@reduxjs/toolkit";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Provider } from "react-redux";
import { useRef } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { consoleSlice, setConnectionPhase, startExecution } from "../store";
import type { ExecutionSnapshot } from "../types";
import { NavigationUtilities } from "./NavigationUtilities";
import { ProcedureViews } from "./ProcedureViews";
import { SourceWorkspace } from "./SourceWorkspace";
import { HighlightedSource, lineObservations } from "./tabularSource";
import { CommandEntry } from "./CommandEntry";

vi.mock("./DataDock", () => ({ DataDock: () => <section aria-label="Execution data" /> }));

function snapshot(): ExecutionSnapshot {
  return {
    id: "execution-1", procedure_id: "example", procedure_name: "Example", context_id: "simulator",
    state: "PAUSED", revision: 2, last_sequence: 7, current_line: 1,
    source: "# local procedure\nvalue = GetTM('A')\nDisplay(value)", source_digest: "a".repeat(64),
    steps: [{ id: "read", line: 2, label: "Read telemetry" }],
    telemetry: [], events: [], logs: [], executed_lines: [1], inspection: [],
  };
}
function storeWith(execution?: ExecutionSnapshot) {
  const store = configureStore({ reducer: { console: consoleSlice.reducer } });
  store.dispatch(setConnectionPhase("CONNECTED"));
  if (execution) store.dispatch(startExecution.fulfilled(execution, "load", { procedureId: "example", contextId: "simulator" }));
  return store;
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("manual-aligned procedure workspace", () => {
  it("routes typed control through the enabled button and preserves the abort confirmation action", async () => {
    const run = vi.fn(); const confirmAbort = vi.fn();
    function Controls() {
      const toolbar = useRef<HTMLDivElement>(null);
      return <><div ref={toolbar}><button title="Run" onClick={run}>Run</button><button title="Abort execution" onClick={confirmAbort}>Abort</button></div><CommandEntry toolbar={toolbar} disabled={false} /></>;
    }
    render(<Controls />);
    await userEvent.type(screen.getByLabelText("Enter command"), "run");
    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(run).toHaveBeenCalledOnce();
    await userEvent.type(screen.getByLabelText("Enter command"), "abort");
    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(confirmAbort).toHaveBeenCalledOnce();
  });

  it("rejects shell input and disabled typed control without invoking a button", async () => {
    const run = vi.fn();
    function Controls() {
      const toolbar = useRef<HTMLDivElement>(null);
      return <><div ref={toolbar}><button title="Run" onClick={run} disabled>Run</button></div><CommandEntry toolbar={toolbar} disabled={false} /></>;
    }
    render(<Controls />);
    await userEvent.type(screen.getByLabelText("Enter command"), "run; import os");
    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Use run, step");
    await userEvent.clear(screen.getByLabelText("Enter command"));
    await userEvent.type(screen.getByLabelText("Enter command"), "run");
    await userEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(screen.getByRole("alert")).toHaveTextContent("unavailable");
    expect(run).not.toHaveBeenCalled();
  });

  it("leaves Data and Result blank for traversal, uncorrelated data, and another execution", () => {
    const execution = snapshot();
    execution.events = [
      { event_id: "a", event_type: "step.completed", sequence: 1, server_time: "", execution_id: execution.id, payload: { line: 1 } },
      { event_id: "b", event_type: "telemetry.sample", sequence: 2, server_time: "", execution_id: execution.id, payload: { parameter: "A", value: 99, quality: "GOOD" } },
      { event_id: "c", event_type: "telemetry.sample", sequence: 3, server_time: "", execution_id: "another-execution", payload: { line: 2, parameter: "B", value: 12, quality: "GOOD" } },
    ];
    expect(lineObservations(execution).size).toBe(0);
    render(<Provider store={storeWith(execution)}><SourceWorkspace execution={execution} canMutate={false} /></Provider>);
    const line = screen.getByRole("row", { name: "Line 1, executed" });
    expect(within(line).getAllByRole("cell").slice(-2).map((cell) => cell.textContent)).toEqual(["", ""]);
  });

  it("shows the latest explicitly correlated observation by sequence without changing input order", () => {
    const execution = snapshot();
    execution.events = [
      { event_id: "new", event_type: "telemetry.sample", sequence: 9, server_time: "", execution_id: execution.id, payload: { line: 2, parameter: "A", value: 0, quality: "BAD" } },
      { event_id: "old", event_type: "telemetry.sample", sequence: 3, server_time: "", execution_id: execution.id, payload: { line: 2, parameter: "A", value: 42, quality: "GOOD" } },
    ];
    expect(lineObservations(execution).get(2)).toEqual({ item: "A", value: "0", result: "BAD" });
    expect(execution.events.map((event) => event.event_id)).toEqual(["new", "old"]);
  });

  it("renders source markup literally without creating executable elements", () => {
    const text = "Display('<img src=x onerror=alert(1)>') # <script>danger</script>";
    const { container } = render(<HighlightedSource text={text} />);
    expect(container.textContent).toBe(text);
    expect(container.querySelector("img,script")).toBeNull();
  });

  it("correlates durable observation results with the exact request and immutable source step", () => {
    const execution = snapshot();
    const event = (id: string, sequence: number, event_type: string, payload: Record<string, unknown>) => ({ event_id: id, sequence, event_type, execution_id: execution.id, server_time: "", payload });
    execution.events = [
      event("request", 1, "procedure.observation_requested", { request_id: "read-1", step_index: 0, operation: "GET_TM", parameters: { item_id: "TM.BUS" } }),
      event("wrong", 2, "procedure.observation_result", { request_id: "read-1", step_index: 1, operation: "GET_TM", outcome: "OK", value: 99 }),
      event("result", 3, "procedure.observation_result", { request_id: "read-1", step_index: 0, operation: "GET_TM", outcome: "OK", value: { type: "FINITE_DOUBLE", value: 0 } }),
      event("uncorrelated", 4, "procedure.observation_result", { request_id: "other", step_index: 0, operation: "GET_TM", outcome: "OK", value: 99 }),
      event("settled", 5, "procedure.observation_settled", { request_id: "read-1", step_index: 0, operation: "GET_TM", outcome: "OK" }),
    ];
    expect([...lineObservations(execution)]).toEqual([[2, { item: "TM.BUS", value: "0", result: "OK" }]]);
  });

  it("navigates paused source from the left Outline and interlocks running navigation", async () => {
    const execution = snapshot();
    const store = storeWith(execution);
    const view = render(<Provider store={store}><NavigationUtilities /><SourceWorkspace execution={execution} canMutate={false} /></Provider>);
    await userEvent.click(screen.getByRole("button", { name: /Read telemetry/ }));
    expect(screen.getByRole("row", { name: "Line 2" })).toHaveClass("selected-line");
    const running = { ...execution, state: "RUNNING" as const };
    store.dispatch(startExecution.fulfilled(running, "refresh", { procedureId: "example", contextId: "simulator" }));
    view.rerender(<Provider store={store}><NavigationUtilities /><SourceWorkspace execution={running} canMutate={false} /></Provider>);
    expect(screen.getByRole("button", { name: /Read telemetry/ })).toBeDisabled();
    fireEvent.keyDown(screen.getByRole("tab", { name: "Outline" }), { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Variables" })).toHaveAttribute("aria-selected", "true");
  });

  it("keeps Master permanent and switches to the selected instance using keyboard tabs", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "Content-Type": "application/json" } }));
    const store = storeWith(snapshot());
    render(<Provider store={store}><NavigationUtilities /><ProcedureViews /></Provider>);
    const tab = await screen.findByRole("tab", { name: /Example \(executio/ });
    await waitFor(() => expect(tab).toHaveAttribute("aria-selected", "true"));
    expect(screen.getByRole("table", { name: "Tabular procedure source" })).toBeVisible();
    fireEvent.keyDown(tab, { key: "Home" });
    expect(screen.getByRole("tab", { name: "Master" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("heading", { name: "Master" })).toBeVisible();
    expect(screen.queryByRole("table", { name: "Tabular procedure source" })).toBeNull();
    fireEvent.keyDown(screen.getByRole("tab", { name: "Master" }), { key: "End" });
    expect(screen.getByRole("table", { name: "Tabular procedure source" })).toBeVisible();
    await userEvent.click(screen.getByRole("tab", { name: "Master" }));
    await userEvent.click(screen.getByRole("button", { name: /Read telemetry/ }));
    expect(screen.getByRole("table", { name: "Tabular procedure source" })).toBeVisible();
    expect(screen.getByRole("row", { name: "Line 2" })).toHaveClass("selected-line");
    for (const id of ["second-instance", "third-instance"]) {
      await act(async () => { store.dispatch(startExecution.fulfilled({ ...snapshot(), id }, "switch", { procedureId: "example", contextId: "simulator" })); });
    }
    expect(screen.getAllByText("Compatibility control")).toHaveLength(1);
  });
});
