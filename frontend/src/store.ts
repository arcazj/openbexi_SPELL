import { configureStore, createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { api } from "./api";
import type {
  AsRunReport,
  ConnectionPhase,
  ExecutionEvent,
  ExecutionSnapshot,
  HealthStatus,
  LogEntry,
  ProcedureSummary,
  TelemetryPoint,
} from "./types";

export type DockTab = "telemetry" | "events" | "logs" | "report";

interface ConsoleState {
  connection: {
    phase: ConnectionPhase;
    server: HealthStatus | null;
    lastMessageAt: string | null;
    reconnectAttempt: number;
  };
  contextId: string;
  userName: string;
  procedures: ProcedureSummary[];
  selectedProcedureId: string | null;
  execution: ExecutionSnapshot | null;
  report: AsRunReport | null;
  dockTab: DockTab;
  loading: boolean;
  pendingAction: string | null;
  error: string | null;
}

const initialState: ConsoleState = {
  connection: {
    phase: "STALE",
    server: null,
    lastMessageAt: null,
    reconnectAttempt: 0,
  },
  contextId: "simulator",
  userName: import.meta.env.VITE_SPELL_ACTOR ?? "console.admin",
  procedures: [],
  selectedProcedureId: null,
  execution: null,
  report: null,
  dockTab: "telemetry",
  loading: false,
  pendingAction: null,
  error: null,
};

function normalizeSnapshot(snapshot: ExecutionSnapshot): ExecutionSnapshot {
  return {
    ...snapshot,
    steps: snapshot.steps ?? [],
    telemetry: snapshot.telemetry ?? [],
    events: snapshot.events ?? [],
    logs: snapshot.logs ?? [],
    last_sequence: snapshot.last_sequence ?? 0,
  };
}

export const bootstrap = createAsyncThunk("console/bootstrap", async () => {
  const [server, procedures] = await Promise.all([api.health(), api.procedures()]);
  return { server, procedures };
});

export const startExecution = createAsyncThunk(
  "console/startExecution",
  async ({ procedureId, contextId }: { procedureId: string; contextId: string }) =>
    api.startExecution(procedureId, contextId),
);

export const resyncExecution = createAsyncThunk(
  "console/resyncExecution",
  async (executionId: string) => api.snapshot(executionId),
);

export const forceResyncExecution = createAsyncThunk(
  "console/forceResyncExecution",
  async (executionId: string) => api.snapshot(executionId),
);

export const sendExecutionCommand = createAsyncThunk(
  "console/sendCommand",
  async (
    {
      executionId,
      command,
      revision,
      reason,
    }: {
      executionId: string;
      command: string;
      revision: number;
      reason: string;
    },
  ) => api.command(executionId, command, revision, reason),
);

export const answerPrompt = createAsyncThunk(
  "console/answerPrompt",
  async ({ promptId, value, revision }: { promptId: string; value: string; revision: number }) =>
    api.respondToPrompt(promptId, value, revision),
);

export const loadReport = createAsyncThunk(
  "console/loadReport",
  async (executionId: string) => api.report(executionId),
);

function eventTelemetry(event: ExecutionEvent): TelemetryPoint {
  return {
    parameter: String(event.payload.channel ?? event.payload.parameter ?? event.payload.name ?? "UNKNOWN"),
    value: (event.payload.value ?? "-") as string | number | boolean,
    unit: event.payload.unit ? String(event.payload.unit) : undefined,
    quality: String(event.payload.quality ?? "UNKNOWN").toUpperCase() as TelemetryPoint["quality"],
    source_time: String(event.source_time ?? event.server_time),
    sequence: event.sequence,
  };
}

function eventLog(event: ExecutionEvent): LogEntry {
  return {
    id: event.event_id,
    time: event.server_time,
    level: String(event.payload.level ?? event.severity ?? "INFO").toUpperCase() as LogEntry["level"],
    source: String(event.source ?? event.payload.source ?? "executor"),
    message: String(event.payload.message ?? event.event_type),
    sequence: event.sequence,
  };
}

const consoleSlice = createSlice({
  name: "console",
  initialState,
  reducers: {
    setSelectedProcedure(state, action: { payload: string }) {
      state.selectedProcedureId = action.payload;
    },
    setContext(state, action: { payload: string }) {
      state.contextId = action.payload;
    },
    setDockTab(state, action: { payload: DockTab }) {
      state.dockTab = action.payload;
    },
    setConnectionPhase(state, action: { payload: ConnectionPhase }) {
      state.connection.phase = action.payload;
      if (action.payload === "CONNECTED") state.connection.reconnectAttempt = 0;
    },
    markReconnect(state) {
      state.connection.phase = "RECONNECTING";
      state.connection.reconnectAttempt += 1;
    },
    dismissError(state) {
      state.error = null;
    },
    ingestEvent(state, action: { payload: ExecutionEvent }) {
      const event = action.payload;
      const execution = state.execution;
      if (!execution || execution.id !== event.execution_id) return;
      if (event.sequence <= execution.last_sequence) return;

      execution.last_sequence = event.sequence;
      execution.events.push(event);
      execution.events = execution.events.slice(-500);
      state.connection.lastMessageAt = event.server_time;

      if (event.event_type === "execution.state_changed") {
        execution.state = String(event.payload.state).toUpperCase() as ExecutionSnapshot["state"];
        execution.revision = Number(event.payload.revision ?? execution.revision + 1);
      } else if (
        event.event_type === "execution.step_changed" ||
        event.event_type === "procedure.step_started" ||
        event.event_type === "step.started" ||
        event.event_type === "step.completed"
      ) {
        const index = Number(event.payload.step_index ?? event.payload.step_id ?? 0);
        execution.current_step_id = String(
          event.event_type === "step.completed" ? index + 1 : index,
        );
        execution.current_line = Number(event.payload.line ?? 0);
        execution.revision = Number(event.payload.revision ?? execution.revision);
        execution.steps = execution.steps.map((step) => ({
          ...step,
          state:
            step.id === execution.current_step_id
              ? "active"
              : step.line < (execution.current_line ?? 0)
                ? "complete"
                : step.state === "failed"
                  ? "failed"
                  : "pending",
        }));
      } else if (event.event_type === "telemetry.observed" || event.event_type === "telemetry.sample") {
        const point = eventTelemetry(event);
        execution.telemetry = [
          ...execution.telemetry.filter((item) => item.parameter !== point.parameter),
          point,
        ].slice(-200);
      } else if (event.event_type === "log.emitted" || event.event_type === "procedure.log") {
        execution.logs.push(eventLog(event));
        execution.logs = execution.logs.slice(-500);
      } else if (event.event_type === "prompt.opened" || event.event_type === "prompt.reopened") {
        const prompt = (event.payload.prompt ?? event.payload) as Record<string, unknown>;
        execution.revision = Number(prompt.revision ?? execution.revision);
        execution.active_prompt = {
          id: String(prompt.id ?? prompt.prompt_id ?? event.event_id),
          message: String(prompt.message ?? prompt.question ?? "Operator response required"),
          type: String(prompt.type ?? (Array.isArray(prompt.choices) ? "choice" : "text")) as NonNullable<
            ExecutionSnapshot["active_prompt"]
          >["type"],
          options: Array.isArray(prompt.options)
            ? prompt.options.map(String)
            : Array.isArray(prompt.choices)
              ? prompt.choices.map(String)
              : undefined,
          default_value: prompt.default_value
            ? String(prompt.default_value)
            : prompt.default
              ? String(prompt.default)
              : undefined,
          deadline: prompt.deadline ? String(prompt.deadline) : undefined,
          revision: Number(prompt.revision ?? execution.revision),
        };
        execution.state = "PROMPTING";
      } else if (
        event.event_type === "prompt.resolved" ||
        event.event_type === "prompt.response_reserved" ||
        event.event_type === "prompt.answered" ||
        event.event_type === "prompt.interrupted" ||
        event.event_type === "prompt.cancelled"
      ) {
        execution.active_prompt = null;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(bootstrap.pending, (state) => {
        state.loading = true;
      })
      .addCase(bootstrap.fulfilled, (state, action) => {
        state.loading = false;
        state.connection.server = action.payload.server;
        state.connection.phase = "CONNECTED";
        state.procedures = action.payload.procedures;
        state.selectedProcedureId ??= action.payload.procedures[0]?.id ?? null;
      })
      .addCase(bootstrap.rejected, (state, action) => {
        state.loading = false;
        state.connection.phase = "STALE";
        state.error = action.error.message ?? "Unable to connect to the SPELL server";
      })
      .addCase(startExecution.pending, (state) => {
        state.pendingAction = "START";
        state.error = null;
      })
      .addCase(startExecution.fulfilled, (state, action) => {
        state.pendingAction = null;
        state.execution = normalizeSnapshot(action.payload);
        state.report = null;
      })
      .addCase(startExecution.rejected, (state, action) => {
        state.pendingAction = null;
        state.error = action.error.message ?? "Unable to start the procedure";
      })
      .addCase(resyncExecution.fulfilled, (state, action) => {
        const incoming = normalizeSnapshot(action.payload);
        const current = state.execution;
        const olderThanCurrent =
          current?.id === incoming.id &&
          (incoming.last_sequence < current.last_sequence || incoming.revision < current.revision);
        if (!olderThanCurrent) state.execution = incoming;
        state.connection.lastMessageAt = new Date().toISOString();
      })
      .addCase(resyncExecution.rejected, (state, action) => {
        state.connection.phase = "STALE";
        state.error = action.error.message ?? "Execution resynchronization failed";
      })
      .addCase(forceResyncExecution.fulfilled, (state, action) => {
        state.execution = normalizeSnapshot(action.payload);
        state.connection.lastMessageAt = new Date().toISOString();
      })
      .addCase(forceResyncExecution.rejected, (state, action) => {
        state.connection.phase = "STALE";
        state.error = action.error.message ?? "Authoritative execution reset failed";
      })
      .addCase(sendExecutionCommand.pending, (state, action) => {
        state.pendingAction = action.meta.arg.command;
        state.error = null;
      })
      .addCase(sendExecutionCommand.fulfilled, (state) => {
        state.pendingAction = null;
      })
      .addCase(sendExecutionCommand.rejected, (state, action) => {
        state.pendingAction = null;
        state.error = action.error.message ?? "Execution command was rejected";
      })
      .addCase(answerPrompt.pending, (state) => {
        state.pendingAction = "PROMPT_RESPONSE";
        state.error = null;
      })
      .addCase(answerPrompt.fulfilled, (state) => {
        state.pendingAction = null;
        if (state.execution) state.execution.active_prompt = null;
      })
      .addCase(answerPrompt.rejected, (state, action) => {
        state.pendingAction = null;
        state.error = action.error.message ?? "Prompt response was rejected";
      })
      .addCase(loadReport.pending, (state) => {
        state.pendingAction = "LOAD_REPORT";
      })
      .addCase(loadReport.fulfilled, (state, action) => {
        state.pendingAction = null;
        state.report = action.payload;
        state.dockTab = "report";
      })
      .addCase(loadReport.rejected, (state, action) => {
        state.pendingAction = null;
        state.error = action.error.message ?? "Unable to load the as-run report";
      });
  },
});

export const {
  dismissError,
  ingestEvent,
  markReconnect,
  setConnectionPhase,
  setContext,
  setDockTab,
  setSelectedProcedure,
} = consoleSlice.actions;

export const store = configureStore({ reducer: { console: consoleSlice.reducer } });
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
export { consoleSlice };
