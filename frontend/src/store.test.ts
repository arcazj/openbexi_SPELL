import { configureStore } from "@reduxjs/toolkit";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api } from "./api";
import {
  answerPrompt,
  consoleSlice,
  forceResyncExecution,
  ingestEvent,
  resyncExecution,
  setSelectedProcedure,
  setConnectionPhase,
  startExecution,
  validateProcedure,
} from "./store";
import type { ExecutionSnapshot, ProcedureValidationResult } from "./types";

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

afterEach(() => {
  vi.restoreAllMocks();
});

describe("console state", () => {
  it("resnapshots and retries a fresh execution ACQUIRE after a revision conflict", async () => {
    const created = { ...snapshot, revision: 1 };
    const advanced = { ...snapshot, state: "PROMPTING" as const, revision: 3 };
    const controlled = { ...advanced, revision: 4 };
    vi.spyOn(api, "startExecution").mockResolvedValue(created);
    const control = vi.spyOn(api, "control")
      .mockRejectedValueOnce(new ApiError("Execution revision changed", 409))
      .mockResolvedValueOnce({
        execution: {
          id: advanced.id,
          procedure_id: advanced.procedure_id,
          procedure_name: advanced.procedure_name,
          context_id: advanced.context_id,
          state: advanced.state,
          revision: advanced.revision,
          last_sequence: advanced.last_sequence,
          ownership_mode: "C",
        },
        control_lease: null,
      });
    const getSnapshot = vi.spyOn(api, "snapshot")
      .mockResolvedValueOnce(advanced)
      .mockResolvedValueOnce(controlled);

    const result = await testStore().dispatch(startExecution({
      procedureId: "checkout",
      contextId: "simulator",
    })).unwrap();

    expect(control).toHaveBeenNthCalledWith(1, "exec-1", "ACQUIRE", 1, expect.any(Object));
    expect(control).toHaveBeenNthCalledWith(2, "exec-1", "ACQUIRE", 3, expect.any(Object));
    expect(getSnapshot).toHaveBeenCalledTimes(2);
    expect(result).toEqual(controlled);
  });

  it("does not retry a fresh execution ACQUIRE for non-conflict failures", async () => {
    vi.spyOn(api, "startExecution").mockResolvedValue(snapshot);
    const control = vi.spyOn(api, "control").mockRejectedValue(new ApiError("Forbidden", 403));
    const getSnapshot = vi.spyOn(api, "snapshot");

    await expect(testStore().dispatch(startExecution({
      procedureId: "checkout",
      contextId: "simulator",
    })).unwrap()).rejects.toMatchObject({ name: "ApiError", message: "Forbidden" });

    expect(control).toHaveBeenCalledTimes(1);
    expect(getSnapshot).not.toHaveBeenCalled();
  });

  it("bounds fresh execution ACQUIRE revision-conflict retries", async () => {
    vi.spyOn(api, "startExecution").mockResolvedValue(snapshot);
    const control = vi.spyOn(api, "control").mockRejectedValue(new ApiError("Conflict", 409));
    const getSnapshot = vi.spyOn(api, "snapshot")
      .mockResolvedValueOnce({ ...snapshot, revision: 2 })
      .mockResolvedValueOnce({ ...snapshot, revision: 3 });

    await expect(testStore().dispatch(startExecution({
      procedureId: "checkout",
      contextId: "simulator",
    })).unwrap()).rejects.toMatchObject({ name: "ApiError", message: "Conflict" });

    expect(control).toHaveBeenCalledTimes(3);
    expect(getSnapshot).toHaveBeenCalledTimes(2);
  });

  it("tracks validation independently and ignores a superseded response", () => {
    const store = testStore();
    const args = { procedureId: "checkout", source: "Log('ready')" };
    const result: ProcedureValidationResult = {
      valid: true,
      subset_version: "spell-restricted-ast/0.3",
      sha256: "a".repeat(64),
      steps: [{ index: 0, line: 1, type: "log", message: "ready" }],
      variables: { mode: "simulator" },
      diagnostics: [],
    };

    store.dispatch(validateProcedure.pending("validation-1", args));
    expect(store.getState().console.validation).toMatchObject({
      procedureId: "checkout",
      status: "pending",
    });

    store.dispatch(validateProcedure.fulfilled(result, "stale-validation", args));
    expect(store.getState().console.validation.status).toBe("pending");

    store.dispatch(validateProcedure.fulfilled(result, "validation-1", args));
    expect(store.getState().console.validation).toMatchObject({
      status: "complete",
      result: { valid: true, subset_version: "spell-restricted-ast/0.3" },
    });

    store.dispatch(setSelectedProcedure("another-procedure"));
    expect(store.getState().console.validation).toMatchObject({ status: "idle", result: null });
  });

  it("keeps validation request failures in the validation workflow", () => {
    const store = testStore();
    const args = { procedureId: "checkout", source: "import os" };
    store.dispatch(validateProcedure.pending("validation-error", args));
    store.dispatch(
      validateProcedure.rejected(
        new Error("Source is outside the restricted subset"),
        "validation-error",
        args,
      ),
    );
    expect(store.getState().console.validation).toMatchObject({
      status: "failed",
      error: "Source is outside the restricted subset",
    });
    expect(store.getState().console.pendingAction).toBeNull();
  });

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

  it("normalizes canonical typed prompt events without conflating prompt and execution revisions", () => {
    const store = testStore();
    store.dispatch(startExecution.fulfilled(snapshot, "request", { procedureId: "checkout", contextId: "simulator" }));
    store.dispatch(ingestEvent({
      event_id: "event-typed-prompt",
      event_type: "prompt.opened",
      execution_id: "exec-1",
      sequence: 2,
      server_time: "2026-07-12T20:00:00Z",
      payload: {
        prompt_id: "prompt-list",
        type: "LIST",
        input_kind: "LIST",
        list_mode: "KEY",
        question: "Select route",
        options: [{ key: "primary", label: "Primary" }, { key: "backup", label: "Backup" }],
        default: "backup",
        prompt_revision: 7,
        execution_revision: 3,
        warning_at: "2026-07-12T20:00:10Z",
        response_deadline: "2026-07-12T20:01:00Z",
        warning_emitted_at: "2026-07-12T20:00:11Z",
      },
    }));

    expect(store.getState().console.execution).toMatchObject({
      revision: 3,
      active_prompt: {
        id: "prompt-list",
        type: "list",
        prompt_type: "LIST",
        list_mode: "KEY",
        options: ["Primary", "Backup"],
        option_values: ["primary", "backup"],
        default_value: "backup",
        revision: 7,
        deadline: "2026-07-12T20:01:00Z",
        warning_at: "2026-07-12T20:00:10Z",
        warning_active: true,
      },
    });
  });

  it("retains an open prompt when a durable 202 attempt rejects its value", () => {
    const store = testStore();
    store.dispatch(startExecution.fulfilled(snapshot, "request", { procedureId: "checkout", contextId: "simulator" }));
    store.dispatch(ingestEvent({
      event_id: "event-invalid-prompt",
      event_type: "prompt.opened",
      execution_id: "exec-1",
      sequence: 2,
      server_time: "2026-07-12T20:00:00Z",
      payload: {
        prompt_id: "prompt-invalid",
        type: "LIST",
        input_kind: "LIST",
        list_mode: "VALUE",
        question: "Continue?",
        options: [{ value: "yes", label: "Yes" }],
        prompt_revision: 3,
        execution_revision: 2,
      },
    }));
    const args = { promptId: "prompt-invalid", action: "COMMIT" as const, value: { value: "yes", label: "Yes" }, revision: 3 };

    store.dispatch(answerPrompt.fulfilled({
      prompt: { id: "prompt-invalid", state: "OPEN" },
      attempt: { id: "attempt-invalid", outcome: "INVALID_VALUE" },
    }, "attempt-invalid", args));

    expect(store.getState().console.execution?.active_prompt?.id).toBe("prompt-invalid");
    expect(store.getState().console.error).toBe("Prompt response does not match a declared option.");

    store.dispatch(answerPrompt.fulfilled({
      prompt: { id: "prompt-invalid", state: "SETTLED" },
      attempt: { id: "attempt-accepted", outcome: "ACCEPTED_SETTLEMENT" },
    }, "attempt-accepted", { ...args, value: "yes" }));
    expect(store.getState().console.execution?.active_prompt).toBeNull();
    expect(store.getState().console.error).toBeNull();
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
