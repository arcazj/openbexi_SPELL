import { configureStore } from "@reduxjs/toolkit";
import { describe, expect, it } from "vitest";
import {
  consoleSlice,
  forceResyncExecution,
  ingestEvent,
  resyncExecution,
  setConnectionPhase,
  startExecution,
} from "./store";
import type { ExecutionSnapshot } from "./types";

const snapshot: ExecutionSnapshot = {
  id: "exec-1",
  procedure_id: "checkout",
  procedure_name: "Checkout",
  context_id: "simulator",
  state: "RUNNING",
  revision: 1,
  current_step_id: "0",
  current_line: 1,
  last_sequence: 1,
  steps: [
    { id: "0", line: 1, label: "Initialize", state: "active" },
    { id: "1", line: 2, label: "Read voltage", state: "pending" },
  ],
  telemetry: [],
  events: [],
  logs: [],
};

function testStore() {
  return configureStore({ reducer: { console: consoleSlice.reducer } });
}

describe("console state", () => {
  it("tracks explicit connection phases", () => {
    const store = testStore();
    store.dispatch(setConnectionPhase("RESYNCING"));
    expect(store.getState().console.connection.phase).toBe("RESYNCING");
    store.dispatch(setConnectionPhase("STALE"));
    expect(store.getState().console.connection.phase).toBe("STALE");
  });

  it("applies ordered backend event aliases and ignores duplicates", () => {
    const store = testStore();
    store.dispatch(
      startExecution.fulfilled(snapshot, "request", {
        procedureId: "checkout",
        contextId: "simulator",
      }),
    );
    store.dispatch(
      ingestEvent({
        event_id: "event-2",
        event_type: "telemetry.sample",
        execution_id: "exec-1",
        sequence: 2,
        server_time: "2026-07-12T20:00:00Z",
        payload: { channel: "BUS.VOLTAGE", value: 28.4, unit: "V", quality: "good" },
      }),
    );
    store.dispatch(
      ingestEvent({
        event_id: "event-2-duplicate",
        event_type: "telemetry.sample",
        execution_id: "exec-1",
        sequence: 2,
        server_time: "2026-07-12T20:00:00Z",
        payload: { channel: "BUS.VOLTAGE", value: 99 },
      }),
    );

    const execution = store.getState().console.execution;
    expect(execution?.last_sequence).toBe(2);
    expect(execution?.events).toHaveLength(1);
    expect(execution?.telemetry[0]).toMatchObject({ parameter: "BUS.VOLTAGE", value: 28.4 });
  });

  it("latches and resolves a durable prompt", () => {
    const store = testStore();
    store.dispatch(
      startExecution.fulfilled(snapshot, "request", {
        procedureId: "checkout",
        contextId: "simulator",
      }),
    );
    store.dispatch(
      ingestEvent({
        event_id: "event-2",
        event_type: "prompt.opened",
        execution_id: "exec-1",
        sequence: 2,
        server_time: "2026-07-12T20:00:00Z",
        payload: {
          prompt_id: "prompt-1",
          question: "Continue checkout?",
          choices: ["proceed", "hold"],
          default: "proceed",
          revision: 2,
        },
      }),
    );
    expect(store.getState().console.execution?.active_prompt).toMatchObject({
      id: "prompt-1",
      message: "Continue checkout?",
      options: ["proceed", "hold"],
    });
    expect(store.getState().console.execution?.revision).toBe(2);

    store.dispatch(
      ingestEvent({
        event_id: "event-3",
        event_type: "prompt.answered",
        execution_id: "exec-1",
        sequence: 3,
        server_time: "2026-07-12T20:00:02Z",
        payload: { prompt_id: "prompt-1", response: "proceed" },
      }),
    );
    expect(store.getState().console.execution?.active_prompt).toBeNull();
  });

  it("clears an interrupted prompt before recovery reopens it", () => {
    const store = testStore();
    store.dispatch(
      startExecution.fulfilled(snapshot, "request", {
        procedureId: "checkout",
        contextId: "simulator",
      }),
    );
    store.dispatch(
      ingestEvent({
        event_id: "event-2",
        event_type: "prompt.opened",
        execution_id: "exec-1",
        sequence: 2,
        server_time: "2026-07-12T20:00:00Z",
        payload: { prompt_id: "prompt-1", question: "Continue?", choices: ["continue"] },
      }),
    );
    store.dispatch(
      ingestEvent({
        event_id: "event-3",
        event_type: "prompt.interrupted",
        execution_id: "exec-1",
        sequence: 3,
        server_time: "2026-07-12T20:00:01Z",
        payload: { prompt_id: "prompt-1", reason: "worker_recovery_required" },
      }),
    );

    expect(store.getState().console.execution?.active_prompt).toBeNull();
  });

  it("does not let an older snapshot overwrite newer event state", () => {
    const store = testStore();
    store.dispatch(
      startExecution.fulfilled(snapshot, "request", {
        procedureId: "checkout",
        contextId: "simulator",
      }),
    );
    store.dispatch(
      ingestEvent({
        event_id: "event-2",
        event_type: "execution.state_changed",
        execution_id: "exec-1",
        sequence: 2,
        server_time: "2026-07-12T20:00:00Z",
        payload: { state: "paused", revision: 2 },
      }),
    );
    store.dispatch(resyncExecution.fulfilled(snapshot, "resync", "exec-1"));
    expect(store.getState().console.execution).toMatchObject({
      state: "PAUSED",
      revision: 2,
      last_sequence: 2,
    });
  });

  it("accepts an older authoritative snapshot after a stream reset", () => {
    const store = testStore();
    const newer = { ...snapshot, revision: 4, last_sequence: 8 };
    store.dispatch(
      startExecution.fulfilled(newer, "request", {
        procedureId: "checkout",
        contextId: "simulator",
      }),
    );
    store.dispatch(forceResyncExecution.fulfilled(snapshot, "force-resync", "exec-1"));
    expect(store.getState().console.execution).toMatchObject({
      revision: 1,
      last_sequence: 1,
    });
  });
});
