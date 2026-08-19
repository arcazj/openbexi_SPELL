import { configureStore } from "@reduxjs/toolkit";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Provider } from "react-redux";
import { afterEach, describe, expect, it, vi } from "vitest";
import { consoleSlice, ingestEvent, setConnectionPhase, startExecution } from "../store";
import type { ActivePrompt, ExecutionSnapshot } from "../types";
import { PromptPanel } from "./PromptPanel";

function snapshot(mode: "C" | "B" = "C"): ExecutionSnapshot {
  return {
    id: "execution-with-a-long-stable-identity",
    procedure_id: "checkout",
    procedure_name: "Checkout",
    context_id: "simulator",
    state: "PROMPT",
    revision: 7,
    last_sequence: 12,
    steps: [],
    telemetry: [],
    events: [],
    logs: [],
    ownership_mode: mode,
    controller_lease: mode === "C" ? {
      id: "lease-1",
      revision: 3,
      fencing_token: 9,
      execution_id: "execution-with-a-long-stable-identity",
      holder_subject_id: "operator",
      issued_at: "2026-08-15T11:00:00Z",
      expires_at: "2099-08-15T11:01:00Z",
      state: "ACTIVE",
      held_by_current_session: true,
    } : null,
  };
}

function renderPrompt(prompt: ActivePrompt, mode: "C" | "B" = "C", leaseState: "ACTIVE" | "EXPIRED" = "ACTIVE") {
  const store = configureStore({ reducer: { console: consoleSlice.reducer } });
  store.dispatch(setConnectionPhase("CONNECTED"));
  const current = snapshot(mode);
  if (current.controller_lease) current.controller_lease.state = leaseState;
  store.dispatch(startExecution.fulfilled(current, "start", { procedureId: "checkout", contextId: "simulator" }));
  render(<Provider store={store}><PromptPanel prompt={prompt} /></Provider>);
  return store;
}

afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe("durable prompt panel", () => {
  it("rejects a calendar rollover before sending a DATE settlement", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    renderPrompt({ id: "prompt-date", message: "Select date", type: "date", prompt_type: "DATE", revision: 4 });
    fireEvent.change(screen.getByLabelText("Response"), { target: { value: "2026-02-31" } });
    await userEvent.click(screen.getByRole("button", { name: "Commit response" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("YYYY-MM-DD");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("commits the typed LIST value rather than its display label", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ prompt: { id: "prompt-list", state: "SETTLED" }, attempt: { id: "attempt-1" } }), { status: 202, headers: { "Content-Type": "application/json" } }));
    renderPrompt({ id: "prompt-list", message: "Select channel", type: "list", prompt_type: "LIST", list_mode: "VALUE", options: ["Primary", "Backup"], option_values: [10, 20], revision: 5 });
    await userEvent.click(screen.getByRole("radio", { name: "Backup" }));
    await userEvent.click(screen.getByRole("button", { name: "Commit response" }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    const init = fetch.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ action: "COMMIT", value: 20, expected_prompt_revision: 5, lease_id: "lease-1", control_fencing_token: 9 });
  });

  it("filters a large reference-example menu without changing its typed index", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ prompt: { id: "prompt-reference", state: "SETTLED" }, attempt: { id: "attempt-1" } }), { status: 202, headers: { "Content-Type": "application/json" } }));
    const options = Array.from({ length: 195 }, (_, index) => `Example ${String(index + 1).padStart(3, "0")} - Demonstration`);
    renderPrompt({ id: "prompt-reference", message: "Select reference example", type: "list", prompt_type: "LIST", list_mode: "INDEX", options, option_values: options.map((_, index) => index), revision: 1 });

    await userEvent.type(screen.getByRole("searchbox", { name: "Filter 195 examples" }), "195");
    expect(screen.getByRole("status", { name: "" })).toHaveTextContent("Showing 1 of 195 examples");
    expect(screen.getByRole("radio", { name: /Example 195/ })).toBeVisible();
    expect(screen.queryByRole("radio", { name: /Example 001/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Commit response" })).toBeDisabled();
    await userEvent.click(screen.getByRole("radio", { name: /Example 195/ }));
    expect(screen.getByRole("button", { name: "Commit response" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Commit response" }));

    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    const init = fetch.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ action: "COMMIT", value: 194 });
  });

  it("does not submit an option hidden by a large-menu filter", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const options = Array.from({ length: 195 }, (_, index) => `Example ${String(index + 1).padStart(3, "0")} - Demonstration`);
    renderPrompt({ id: "prompt-hidden-selection", message: "Select reference example", type: "list", prompt_type: "LIST", list_mode: "INDEX", options, option_values: options.map((_, index) => index), default_value: 0, revision: 1 });

    expect(screen.getByRole("radio", { name: /Example 001/ })).toBeChecked();
    await userEvent.type(screen.getByRole("searchbox", { name: "Filter 195 examples" }), "195");

    expect(screen.getByRole("button", { name: "Commit response" })).toBeDisabled();
    fireEvent.submit(screen.getByRole("button", { name: "Commit response" }).closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("Select a response");
    expect(fetch).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Reset draft" }));
    expect(screen.getByRole("searchbox", { name: "Filter 195 examples" })).toHaveValue("");
    expect(screen.getByRole("radio", { name: /Example 001/ })).toBeChecked();
    expect(screen.getByRole("button", { name: "Commit response" })).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("commits the scalar identity projected by a canonical VALUE prompt event", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ prompt: { id: "prompt-event", state: "SETTLED" }, attempt: { id: "attempt-1", outcome: "ACCEPTED_SETTLEMENT" } }), { status: 202, headers: { "Content-Type": "application/json" } }));
    const store = configureStore({ reducer: { console: consoleSlice.reducer } });
    store.dispatch(setConnectionPhase("CONNECTED"));
    store.dispatch(startExecution.fulfilled(snapshot(), "start", { procedureId: "checkout", contextId: "simulator" }));
    store.dispatch(ingestEvent({
      event_id: "event-prompt-opened",
      event_type: "prompt.opened",
      execution_id: "execution-with-a-long-stable-identity",
      sequence: 13,
      server_time: "2026-08-15T11:00:01Z",
      payload: {
        prompt_id: "prompt-event",
        type: "LIST",
        input_kind: "LIST",
        list_mode: "VALUE",
        question: "Continue?",
        options: [
          { value: "yes", label: "Yes" },
          { value: { action: "hold" }, label: "Hold" },
        ],
        default: "yes",
        prompt_revision: 4,
        execution_revision: 8,
      },
    }));
    const prompt = store.getState().console.execution?.active_prompt;
    expect(prompt?.option_values).toEqual(["yes", { action: "hold" }]);
    render(<Provider store={store}><PromptPanel prompt={prompt!} /></Provider>);

    await userEvent.click(screen.getByRole("button", { name: "Commit response" }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    const init = fetch.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({
      action: "COMMIT",
      value: "yes",
      expected_prompt_revision: 4,
      lease_id: "lease-1",
      control_fencing_token: 9,
    });
  });

  it("preserves an object LIST value and selects its typed default", async () => {
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ prompt: { id: "prompt-object", state: "SETTLED" }, attempt: { id: "attempt-1" } }), { status: 202, headers: { "Content-Type": "application/json" } }));
    renderPrompt({ id: "prompt-object", message: "Select route", type: "list", prompt_type: "LIST", list_mode: "VALUE", options: ["Primary", "Backup"], option_values: [{ route: "primary" }, { route: "backup" }], default_value: { route: "backup" }, revision: 6 });
    expect(screen.getByRole("radio", { name: "Backup" })).toBeChecked();
    await userEvent.click(screen.getByRole("button", { name: "Commit response" }));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    const init = fetch.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ action: "COMMIT", value: { route: "backup" }, expected_prompt_revision: 6 });
  });

  it("keeps monitor sessions read-only while allowing local draft reset", async () => {
    renderPrompt({ id: "prompt-alpha", message: "Enter note", type: "text", prompt_type: "ALPHA", default_value: "nominal", revision: 2 }, "B");
    expect(screen.getByRole("button", { name: "Commit response" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Abort prompt" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Response"), { target: { value: "changed" } });
    await userEvent.click(screen.getByRole("button", { name: "Reset draft" }));
    expect(screen.getByLabelText("Response")).toHaveValue("nominal");
  });

  it("interlocks settlement after the controller lease expires", () => {
    renderPrompt({ id: "prompt-expired", message: "Confirm", type: "choice", prompt_type: "YES_NO", options: ["YES", "NO"], revision: 2 }, "C", "EXPIRED");
    expect(screen.getByRole("button", { name: "Commit response" })).toBeDisabled();
    expect(screen.getByText(/Acquire control/)).toBeInTheDocument();
  });

  it("advances warning and deadline state from server timestamps and resynchronizes each boundary", async () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-08-15T10:00:00.000Z");
    const prompt: ActivePrompt = {
      id: "prompt-timed",
      message: "Confirm timed operation",
      type: "choice",
      prompt_type: "YES_NO",
      options: ["YES", "NO"],
      revision: 8,
      warning_at: "2026-08-15T10:00:01.000Z",
      deadline: "2026-08-15T10:00:02.000Z",
    };
    const current = snapshot();
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({
      execution: current,
      active_prompt: prompt,
      last_sequence: current.last_sequence,
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    renderPrompt(prompt);
    expect(screen.queryByText("Response warning threshold reached.")).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(1_050); });
    expect(screen.getByText("Response warning threshold reached.")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
    expect(screen.getByText("Response deadline reached.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Commit response" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Abort prompt" })).toBeDisabled();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
