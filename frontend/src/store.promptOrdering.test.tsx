import { configureStore } from "@reduxjs/toolkit";
import { act, cleanup, render, screen } from "@testing-library/react";
import { Provider } from "react-redux";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useAppSelector } from "./hooks";
import { answerPrompt, consoleSlice, ingestEvent, openExecution, resyncExecution, sendExecutionCommand, setConnectionPhase, startExecution } from "./store";
import { PromptPanel } from "./components/PromptPanel";
import type { ActivePrompt, ExecutionSnapshot } from "./types";

const original: ActivePrompt = { id: "native-prompt", revision: 1, message: "Run the simulated command?", type: "choice", prompt_type: "YES_NO", prompt_profile: "spell-lrm244/0.17", options: ["YES", "NO"], option_values: ["YES", "NO"] };
const confirmation: ActivePrompt = { ...original, id: "command-confirmation", prompt_profile: undefined, message: "Confirm deterministic simulator telecommand plan retained-plan" };
const initial: ExecutionSnapshot = { id: "execution-one", procedure_id: "native_command_branch_v18", procedure_name: "Native Command Branch V18", context_id: "simulator", state: "PROMPTING", revision: 5, last_sequence: 19, active_prompt: original, steps: [], telemetry: [], logs: [], events: [] };

function CurrentPrompt() {
  const prompt = useAppSelector((state) => state.console.execution?.active_prompt);
  return prompt ? <PromptPanel prompt={prompt} /> : null;
}

function setup() {
  const store = configureStore({ reducer: { console: consoleSlice.reducer } });
  store.dispatch(startExecution.fulfilled(initial, "start", { procedureId: initial.procedure_id, contextId: "simulator" }));
  store.dispatch(setConnectionPhase("CONNECTED"));
  render(<Provider store={store}><CurrentPrompt /></Provider>);
  let deliver!: (response: Response) => void;
  const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(() => new Promise<Response>((resolve) => { deliver = resolve; }));
  let pending!: Promise<unknown>;
  act(() => { pending = store.dispatch(answerPrompt({ promptId: original.id, revision: original.revision, action: "COMMIT", value: "YES" })); });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(String(fetch.mock.calls[0]?.[0])).toContain(`/prompts/${original.id}/responses`);
  expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({ expected_prompt_revision: original.revision, value: "YES" });
  const finish = async (kind: "accepted" | "rejected" | "http-error" = "accepted") => {
    const body = kind === "http-error" ? { detail: "Old prompt HTTP failure" } : {
      prompt: { id: original.id, state: kind === "accepted" ? "SETTLED" : "OPEN" },
      attempt: { id: "old-response", outcome: kind === "accepted" ? "ACCEPTED_SETTLEMENT" : "INVALID_VALUE" },
    };
    await act(async () => {
      deliver(new Response(JSON.stringify(body), { status: kind === "http-error" ? 409 : 202, headers: { "Content-Type": "application/json" } }));
      await pending;
    });
  };
  return { store, finish };
}

function opened(store: ReturnType<typeof setup>["store"], prompt = confirmation) {
  act(() => { store.dispatch(ingestEvent({ event_id: "new-prompt-event", execution_id: initial.id, sequence: 31, server_time: "2026-10-04T13:15:50Z", event_type: prompt.id === original.id ? "prompt.reopened" : "prompt.opened", payload: { prompt_id: prompt.id, prompt_revision: prompt.revision, execution_revision: 7, question: prompt.message, input_kind: "YES_NO", type: "YES_NO", options: [{ value: "YES", label: "YES" }, { value: "NO", label: "NO" }] } })); });
  expect(screen.getByRole("heading", { name: prompt.message })).toBeVisible();
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("prompt response ordering", () => {
  it("keeps the next confirmation visible when its opened event precedes the old HTTP settlement", async () => {
    const { store, finish } = setup();
    opened(store);
    await finish();
    expect(store.getState().console.execution).toMatchObject({ state: "PROMPTING", revision: 7, last_sequence: 31, active_prompt: { id: confirmation.id, revision: 1 } });
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
  });

  it("retains an authoritative next-prompt resnapshot before the old HTTP settlement", async () => {
    const { store, finish } = setup();
    act(() => { store.dispatch(resyncExecution.fulfilled({ ...initial, revision: 7, last_sequence: 31, active_prompt: confirmation }, "snapshot", initial.id)); });
    await finish();
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
  });

  it("keeps a reopened higher revision of the same prompt after an old settlement", async () => {
    const { store, finish } = setup();
    opened(store, { ...original, revision: 2 });
    await finish();
    expect(store.getState().console.execution?.active_prompt).toMatchObject({ id: original.id, revision: 2 });
    expect(screen.getByRole("heading", { name: original.message })).toBeVisible();
  });

  it("does not clear the prompt of an execution selected while the old HTTP request is pending", async () => {
    const { store, finish } = setup();
    act(() => { store.dispatch(openExecution.fulfilled({ ...initial, id: "execution-two", active_prompt: confirmation }, "open", "execution-two")); });
    await finish();
    expect(store.getState().console.execution).toMatchObject({ id: "execution-two", active_prompt: { id: confirmation.id } });
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
  });

  it("does not apply an old durable value rejection to the next prompt", async () => {
    const { store, finish } = setup();
    opened(store);
    await finish("rejected");
    expect(store.getState().console.error).toBeNull();
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
  });

  it("does not apply an old HTTP failure to the next prompt", async () => {
    const { store, finish } = setup();
    opened(store);
    await finish("http-error");
    expect(store.getState().console.error).toBeNull();
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
  });

  it("still clears the currently answered prompt after its accepted settlement", async () => {
    const { store, finish } = setup();
    await finish();
    expect(store.getState().console.execution?.active_prompt).toBeNull();
    expect(store.getState().console.pendingAction).toBeNull();
    expect(store.getState().console.error).toBeNull();
    expect(screen.queryByRole("heading", { name: original.message })).not.toBeInTheDocument();
  });

  it("still reports a value rejection for the current prompt without dismissing it", async () => {
    const { store, finish } = setup();
    await finish("rejected");
    expect(store.getState().console.error).toBe("Prompt response does not match a declared option.");
    expect(store.getState().console.pendingAction).toBeNull();
    expect(screen.getByRole("heading", { name: original.message })).toBeVisible();
  });

  it.each(["accepted", "http-error"] as const)("keeps another pending action after the old request returns %s", async (outcome) => {
    const { store, finish } = setup();
    opened(store);
    act(() => { store.dispatch(sendExecutionCommand.pending("later-command", { executionId: initial.id, command: "PAUSE", revision: 7, reason: "Later action" })); });
    await finish(outcome);
    expect(store.getState().console.pendingAction).toBe("PAUSE");
    expect(store.getState().console.error).toBeNull();
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
  });

  it.each(["accepted", "http-error"] as const)("keeps a newer prompt response pending after the old request returns %s", async (outcome) => {
    const { store, finish } = setup();
    opened(store);
    let deliverNext!: (response: Response) => void;
    vi.mocked(globalThis.fetch).mockImplementationOnce(() => new Promise<Response>((resolve) => { deliverNext = resolve; }));
    let next!: Promise<unknown>;
    act(() => { next = store.dispatch(answerPrompt({ promptId: confirmation.id, revision: confirmation.revision, action: "COMMIT", value: "NO" })); });
    await finish(outcome);
    expect(store.getState().console.pendingAction).toBe("PROMPT_RESPONSE");
    expect(store.getState().console.error).toBeNull();
    expect(screen.getByRole("heading", { name: confirmation.message })).toBeVisible();
    await act(async () => {
      deliverNext(new Response(JSON.stringify({ prompt: { id: confirmation.id, state: "SETTLED" }, attempt: { outcome: "ACCEPTED_SETTLEMENT" } }), { status: 202, headers: { "Content-Type": "application/json" } }));
      await next;
    });
    expect(store.getState().console.pendingAction).toBeNull();
    expect(store.getState().console.execution?.active_prompt).toBeNull();
  });
});
