import type {
  AsRunReport,
  CommandReceipt,
  ExecutionSnapshot,
  HealthStatus,
  ProcedureSummary,
} from "./types";

const API_ROOT = "/api/v1";
const DEVELOPMENT_TOKEN = import.meta.env.VITE_SPELL_TOKEN ?? "spell-dev-token";
const DEVELOPMENT_ACTOR = import.meta.env.VITE_SPELL_ACTOR ?? "console.admin";
const DEVELOPMENT_ROLE = import.meta.env.VITE_SPELL_ROLE ?? "admin";

type JsonObject = Record<string, unknown>;

function requestHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set("Authorization", `Bearer ${DEVELOPMENT_TOKEN}`);
  headers.set("X-Dev-Actor", DEVELOPMENT_ACTOR);
  headers.set("X-Dev-Role", DEVELOPMENT_ROLE);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return headers;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: requestHeaders(init?.headers),
  });

  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const message =
      typeof body === "object" && body !== null && "detail" in body
        ? String(body.detail)
        : `${response.status} ${response.statusText}`;
    throw new ApiError(message, response.status, body);
  }
  return body as T;
}

function unwrapList<T>(body: T[] | { items: T[] }): T[] {
  return Array.isArray(body) ? body : body.items;
}

function unwrapExecution(
  body: JsonObject,
): JsonObject {
  return typeof body.execution === "object" && body.execution !== null
    ? (body.execution as JsonObject)
    : body;
}

function stepLabel(step: JsonObject): string {
  const type = String(step.type ?? "step");
  if (type === "log") return `Log: ${String(step.message ?? "message")}`;
  if (type === "telemetry") return `TM: ${String(step.channel ?? "channel")}`;
  if (type === "wait") return `Wait ${String(step.seconds ?? 0)}s`;
  if (type === "prompt") return `Prompt: ${String(step.question ?? "operator")}`;
  return type;
}

function normalizeSteps(value: unknown, currentStep?: number): ProcedureSummary["steps"] {
  if (!Array.isArray(value)) return [];
  return value.map((raw, arrayIndex) => {
    const step = raw as JsonObject;
    const index = Number(step.index ?? arrayIndex);
    return {
      id: String(index),
      line: Number(step.line ?? index + 1),
      label: stepLabel(step),
      source: typeof step.source === "string" ? step.source : undefined,
      state:
        currentStep === undefined
          ? "pending"
          : index < currentStep
            ? "complete"
            : index === currentStep
              ? "active"
              : "pending",
    };
  });
}

function normalizeProcedure(raw: JsonObject): ProcedureSummary {
  return {
    id: String(raw.id),
    name: String(raw.name ?? raw.id),
    version: String(raw.version ?? "0.2"),
    description: String(raw.description ?? ""),
    entrypoint: String(raw.entrypoint ?? ""),
    step_count: Number(raw.step_count ?? 0),
    steps: normalizeSteps(raw.steps),
    source: typeof raw.source === "string" ? raw.source : undefined,
  };
}

function eventTelemetry(event: JsonObject): ExecutionSnapshot["telemetry"][number] {
  const payload = (event.payload ?? {}) as JsonObject;
  return {
    parameter: String(payload.channel ?? payload.parameter ?? "UNKNOWN"),
    value: (payload.value ?? "-") as string | number | boolean,
    unit: payload.unit ? String(payload.unit) : undefined,
    quality: String(payload.quality ?? "UNKNOWN").toUpperCase() as ExecutionSnapshot["telemetry"][number]["quality"],
    source_time: String(event.source_time ?? event.server_time ?? ""),
    sequence: Number(event.sequence ?? 0),
  };
}

function eventLog(event: JsonObject): ExecutionSnapshot["logs"][number] {
  const payload = (event.payload ?? {}) as JsonObject;
  return {
    id: String(event.event_id ?? crypto.randomUUID()),
    time: String(event.server_time ?? ""),
    level: String(payload.level ?? event.severity ?? "INFO").toUpperCase() as ExecutionSnapshot["logs"][number]["level"],
    source: String(event.source ?? "worker"),
    message: String(payload.message ?? ""),
    sequence: Number(event.sequence ?? 0),
  };
}

function normalizeSnapshot(body: JsonObject): ExecutionSnapshot {
  const execution = unwrapExecution(body);
  const currentStep = Number(execution.current_step_id ?? execution.current_step ?? 0);
  const events = (Array.isArray(body.events) ? body.events : []) as ExecutionSnapshot["events"];
  const telemetryEvents = (Array.isArray(body.telemetry) ? body.telemetry : []) as JsonObject[];
  const logEvents = (Array.isArray(body.logs) ? body.logs : []) as JsonObject[];
  const activePrompt = body.active_prompt as JsonObject | null | undefined;
  return {
    id: String(execution.id),
    procedure_id: String(execution.procedure_id),
    procedure_name: String(execution.procedure_name ?? execution.procedure_id),
    context_id: String(execution.context_id ?? "simulator"),
    state: String(execution.state ?? "created").toUpperCase() as ExecutionSnapshot["state"],
    revision: Number(execution.revision ?? 0),
    current_step_id: String(currentStep),
    current_line: execution.current_line == null ? undefined : Number(execution.current_line),
    started_at: String(execution.started_at ?? execution.created_at ?? "") || undefined,
    finished_at: execution.finished_at ? String(execution.finished_at) : undefined,
    last_sequence: Number(body.last_sequence ?? execution.last_sequence ?? 0),
    source: typeof execution.source === "string" ? execution.source : undefined,
    steps: normalizeSteps(execution.steps, currentStep) ?? [],
    telemetry: telemetryEvents.map(eventTelemetry),
    events,
    logs: logEvents.map(eventLog),
    active_prompt: activePrompt
      ? {
          id: String(activePrompt.id),
          message: String(activePrompt.question ?? "Operator response required"),
          type: Array.isArray(activePrompt.choices) ? "choice" : "text",
          options: Array.isArray(activePrompt.choices) ? activePrompt.choices.map(String) : undefined,
          default_value: activePrompt.default ? String(activePrompt.default) : undefined,
          revision: Number(execution.revision ?? 0),
        }
      : null,
  };
}

export const api = {
  async health(): Promise<HealthStatus> {
    const raw = await request<JsonObject>("/health");
    return {
      service: "SPELL Simulator",
      version: String(raw.version ?? "0.2.0"),
      status: String(raw.status ?? "unknown"),
      server_time: raw.server_time ? String(raw.server_time) : undefined,
      mode: raw.mode ? String(raw.mode) : undefined,
    };
  },

  async procedures(): Promise<ProcedureSummary[]> {
    const items = unwrapList(await request<JsonObject[] | { items: JsonObject[] }>("/procedures"));
    return items.map(normalizeProcedure);
  },

  async startExecution(
    procedureId: string,
    contextId: string,
  ): Promise<ExecutionSnapshot> {
    const body = await request<JsonObject>(
      "/executions",
      {
        method: "POST",
        body: JSON.stringify({
          procedure_id: procedureId,
          context_id: contextId,
          reason: "Started from SPELL operations console",
          idempotency_key: crypto.randomUUID(),
        }),
      },
    );
    const execution = unwrapExecution(body);
    return normalizeSnapshot(
      await request<JsonObject>(`/executions/${encodeURIComponent(String(execution.id))}/snapshot`),
    );
  },

  async snapshot(executionId: string): Promise<ExecutionSnapshot> {
    return normalizeSnapshot(
      await request<JsonObject>(`/executions/${encodeURIComponent(executionId)}/snapshot`),
    );
  },

  command: (
    executionId: string,
    type: string,
    expectedRevision: number,
    reason: string,
  ) =>
    request<{ command: CommandReceipt }>(
      `/executions/${encodeURIComponent(executionId)}/commands`,
      {
        method: "POST",
        body: JSON.stringify({
          type: type.toLowerCase(),
          expected_revision: expectedRevision,
          reason,
          idempotency_key: crypto.randomUUID(),
          correlation_id: crypto.randomUUID(),
        }),
      },
    ).then((body) => body.command),

  respondToPrompt: (
    promptId: string,
    value: string,
    expectedRevision: number,
  ) =>
    request<{ command: CommandReceipt }>(`/prompts/${encodeURIComponent(promptId)}/responses`, {
      method: "POST",
      body: JSON.stringify({
        value,
        expected_revision: expectedRevision,
        reason: "Operator response from SPELL console",
        idempotency_key: crypto.randomUUID(),
      }),
    }).then((body) => body.command),

  async report(executionId: string): Promise<AsRunReport> {
    const report = await request<AsRunReport>(`/executions/${encodeURIComponent(executionId)}/report`);
    return { ...report, state: report.state.toUpperCase() as AsRunReport["state"] };
  },
};

export function websocketUrl(executionId: string, afterSequence: number): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const query = new URLSearchParams({
    execution_id: executionId,
    after_sequence: String(afterSequence),
  });
  return `${scheme}//${window.location.host}${API_ROOT}/ws?${query.toString()}`;
}

export function websocketProtocols(): string[] {
  return ["spell-auth", DEVELOPMENT_TOKEN];
}
