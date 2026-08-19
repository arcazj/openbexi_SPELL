import type {
  ActivePrompt,
  AsRunReport,
  CommandReceipt,
  DriverBinding,
  DriverContextGeneration,
  DriverOperation,
  DriverRecord,
  DriverTimeObservation,
  ContextSummary,
  ControllerHandover,
  ControllerLease,
  ExecutionSchedule,
  ExecutionSummary,
  ExecutionSnapshot,
  ExecutionViewEntry,
  HealthStatus,
  InspectionValue,
  NamedUserAction,
  MonitorSubscription,
  PageResult,
  ParentChildLink,
  PromptSettings,
  ProcedureRevision,
  ProcedureSummary,
  ProcedureValidationResult,
  TelemetryConditionPlan,
  TelemetryConditionSchedule,
  TelemetryObservationSnapshot,
  WorkspaceHistoryResult,
  WorkspaceHistoryView,
  WorkspaceSearchResult,
  WorkspaceSearchView,
} from "./types";

const API_ROOT = "/api/v1";
const ACCESS_TOKEN_KEY = "openbexi.spell.access-token";
const SESSION_ID_KEY = "openbexi.spell.session-id";
const CLIENT_INSTANCE_KEY = "openbexi.spell.client-instance-key";

export const AUTH_CHANGED_EVENT = "spell-auth-changed";

export function getAccessToken(): string | null {
  try {
    return window.sessionStorage.getItem(ACCESS_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function normalizeAccessToken(token: string): string {
  const trimmed = token.trim();
  const normalized = /^Bearer\s+/i.test(trimmed)
    ? trimmed.replace(/^Bearer\s+/i, "").trim()
    : trimmed;
  if (normalized.split(".").length !== 3) {
    throw new Error("Enter a signed JWT with three segments.");
  }
  return normalized;
}

export function setAccessToken(token: string): void {
  const normalized = normalizeAccessToken(token);
  window.sessionStorage.setItem(ACCESS_TOKEN_KEY, normalized);
  window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
}

export function clearAccessToken(): void {
  window.sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
}

export function accessTokenExpiresAtMs(token = getAccessToken()): number | null {
  if (!token) return null;
  try {
    const payloadSegment = token.split(".")[1];
    if (!payloadSegment) return null;
    const normalized = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded)) as { exp?: unknown };
    return typeof payload.exp === "number" && Number.isFinite(payload.exp)
      ? payload.exp * 1000
      : null;
  } catch {
    return null;
  }
}

const MAX_BROWSER_TIMER_MS = 2_147_000_000;

export function scheduleAt(deadlineMs: number, callback: () => void): () => void {
  let timer: number | null = null;
  let cancelled = false;
  const arm = () => {
    if (cancelled) return;
    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) {
      callback();
      return;
    }
    timer = window.setTimeout(arm, Math.min(remainingMs, MAX_BROWSER_TIMER_MS));
  };
  arm();
  return () => {
    cancelled = true;
    if (timer !== null) window.clearTimeout(timer);
  };
}

export function accessTokenSubject(): string {
  const token = getAccessToken();
  if (!token) return "Unauthenticated";
  try {
    const payloadSegment = token.split(".")[1];
    if (!payloadSegment) return "Authenticated user";
    const payload = JSON.parse(atob(payloadSegment.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof payload.sub === "string" && payload.sub ? payload.sub : "Authenticated user";
  } catch {
    return "Authenticated user";
  }
}

function sessionValue(key: string): string {
  const existing = window.sessionStorage.getItem(key);
  if (existing) return existing;
  const value = crypto.randomUUID();
  window.sessionStorage.setItem(key, value);
  return value;
}

export function currentControlProof(lease?: ControllerLease | null): ControlProof {
  return {
    session_id: sessionValue(SESSION_ID_KEY),
    client_instance_key_id: sessionValue(CLIENT_INSTANCE_KEY),
    lease_id: lease?.id,
    expected_lease_revision: lease?.revision,
    control_fencing_token: lease?.fencing_token,
  };
}

export function hasActiveControlLease(execution?: {
  ownership_mode?: string;
  controller_lease?: ControllerLease | null;
} | null, nowMs = Date.now()): boolean {
  const lease = execution?.controller_lease;
  return execution?.ownership_mode === "C" && hasUnexpiredControlLease(lease, nowMs) && Boolean(lease?.held_by_current_session);
}

export function hasUnexpiredControlLease(lease?: ControllerLease | null, nowMs = Date.now()): boolean {
  if (lease?.state !== "ACTIVE") return false;
  const expiresAt = Date.parse(lease.expires_at);
  return Number.isFinite(expiresAt) && expiresAt > nowMs;
}

type JsonObject = Record<string, unknown>;

function requestHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  const token = getAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  headers.set("X-Spell-Session-Id", sessionValue(SESSION_ID_KEY));
  headers.set("X-Spell-Client-Instance-Key-Id", sessionValue(CLIENT_INSTANCE_KEY));
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

export async function authenticateAccessToken(token: string): Promise<string> {
  const normalized = normalizeAccessToken(token);
  const response = await fetch(`${API_ROOT}/procedures`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${normalized}`,
    },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as unknown;
    const detail = typeof body === "object" && body !== null && "detail" in body
      ? body.detail
      : null;
    const message = response.status === 401
      ? "The backend rejected this signed JWT."
      : typeof detail === "string"
        ? detail
        : `Authentication check failed (${response.status}).`;
    throw new ApiError(message, response.status, body);
  }
  setAccessToken(normalized);
  return normalized;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: requestHeaders(init?.headers),
  });

  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    if (response.status === 401) clearAccessToken();
    const detail = typeof body === "object" && body !== null && "detail" in body ? body.detail : null;
    const message = typeof detail === "object" && detail !== null
      ? `${"code" in detail ? `${String(detail.code)}: ` : ""}${"message" in detail ? String(detail.message) : "Request rejected"}`
      : detail != null ? String(detail) : `${response.status} ${response.statusText}`;
    throw new ApiError(message, response.status, body);
  }
  return body as T;
}

function unwrapList<T>(body: T[] | { items: T[] }): T[] {
  return Array.isArray(body) ? body : body.items;
}

function pageQuery(limit: number, cursor?: string): string {
  const query = new URLSearchParams({ limit: String(limit) });
  if (cursor) query.set("cursor", cursor);
  return query.toString();
}

function unwrapResource<T>(body: T | Record<string, T>, key: string): T {
  if (typeof body === "object" && body !== null && key in body) {
    return (body as Record<string, T>)[key] as T;
  }
  return body as T;
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
    version: String(raw.version ?? "0.3"),
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
    id: String(event.id ?? event.event_id ?? crypto.randomUUID()),
    time: String(event.time ?? event.server_time ?? event.created_at ?? ""),
    level: String(event.level ?? payload.level ?? event.severity ?? "INFO").toUpperCase() as ExecutionSnapshot["logs"][number]["level"],
    source: String(event.source ?? "worker"),
    message: String(event.message ?? payload.message ?? event.event_type ?? ""),
    sequence: Number(event.sequence ?? 0),
  };
}

function viewMessage(raw: JsonObject): string {
  const payload = typeof raw.payload === "object" && raw.payload !== null
    ? raw.payload as JsonObject
    : {};
  const candidate = raw.message ?? payload.message ?? payload.question ?? payload.detail
    ?? payload.outcome ?? payload.state;
  if (candidate !== undefined && (typeof candidate !== "object" || candidate === null)) return String(candidate);
  const kind = String(raw.event_type ?? raw.kind ?? "event");
  try {
    return Object.keys(payload).length ? `${kind}: ${JSON.stringify(payload)}` : kind;
  } catch {
    return kind;
  }
}

function normalizeViewEntry(raw: JsonObject, index: number): ExecutionViewEntry {
  const payload = typeof raw.payload === "object" && raw.payload !== null
    ? raw.payload as JsonObject
    : {};
  const sequence = Number(raw.sequence ?? index + 1);
  const line = raw.line ?? payload.line;
  return {
    id: String(raw.id ?? raw.event_id ?? `entry:${sequence}:${index}`),
    sequence,
    time: String(raw.time ?? raw.server_time ?? raw.created_at ?? ""),
    scope: String(raw.scope ?? raw.source ?? "procedure"),
    kind: String(raw.kind ?? raw.event_type ?? "event"),
    message: viewMessage(raw),
    correlation_id: optionalString(raw.correlation_id),
    line: typeof line === "number" ? line : undefined,
    outcome: optionalString(raw.outcome ?? payload.outcome ?? payload.state),
  };
}

function normalizeViewEntries(value: unknown): ExecutionViewEntry[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is JsonObject => typeof item === "object" && item !== null)
    .map(normalizeViewEntry)
    .sort((left, right) => left.sequence - right.sequence);
}

function optionalString(value: unknown): string | undefined {
  return value == null || value === "" ? undefined : String(value);
}

function normalizeLease(value: unknown): ControllerLease | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as JsonObject;
  return {
    id: String(raw.id ?? raw.controller_lease_id ?? ""),
    revision: Number(raw.revision ?? raw.lease_revision ?? 0),
    fencing_token: Number(raw.fencing_token ?? raw.control_fencing_token ?? 0),
    execution_id: String(raw.execution_id ?? ""),
    holder_subject_id: String(raw.holder_subject_id ?? raw.holder ?? ""),
    holder_session_id: optionalString(raw.holder_session_id),
    client_instance_key_id: optionalString(raw.client_instance_key_id),
    issued_at: String(raw.issued_at ?? raw.issued_at_database_time ?? ""),
    expires_at: String(raw.expires_at ?? raw.expires_at_database_time ?? ""),
    state: String(raw.state ?? "ACTIVE").toUpperCase() as ControllerLease["state"],
    reason: optionalString(raw.reason),
    held_by_current_session: raw.held_by_current_session == null
      ? optionalString(raw.holder_session_id) === sessionValue(SESSION_ID_KEY)
        && (raw.client_instance_key_id == null || optionalString(raw.client_instance_key_id) === sessionValue(CLIENT_INSTANCE_KEY))
      : Boolean(raw.held_by_current_session),
  };
}

function normalizeHandover(raw: JsonObject): ControllerHandover {
  return {
    id: String(raw.id),
    execution_id: String(raw.execution_id),
    revision: Number(raw.revision ?? 0),
    state: String(raw.state ?? "REQUESTED").toUpperCase() as ControllerHandover["state"],
    requester_subject_id: String(raw.requester_subject_id ?? ""),
    requester_session_id: String(raw.requester_session_id ?? ""),
    requester_client_instance_key_id: String(raw.requester_client_instance_key_id ?? ""),
    requester_monitor_id: String(raw.requester_monitor_id ?? ""),
    expected_execution_revision: Number(raw.expected_execution_revision ?? 0),
    requested_at: String(raw.requested_at ?? ""),
    expires_at: String(raw.expires_at ?? ""),
    approved_by: raw.approved_by == null ? null : String(raw.approved_by),
    predecessor_lease_id: raw.predecessor_lease_id == null ? null : String(raw.predecessor_lease_id),
    successor_lease_id: raw.successor_lease_id == null ? null : String(raw.successor_lease_id),
    successor_control_lease: normalizeLease(raw.successor_control_lease),
    updated_at: String(raw.updated_at ?? ""),
    settled_at: raw.settled_at == null ? null : String(raw.settled_at),
  };
}

function normalizeExecutionSummary(raw: JsonObject): ExecutionSummary {
  return {
    id: String(raw.id),
    procedure_id: String(raw.procedure_id),
    procedure_name: String(raw.procedure_name ?? raw.procedure_id),
    context_id: String(raw.context_id ?? "simulator"),
    state: String(raw.operator_state ?? raw.state ?? "REQUESTED").toUpperCase() as ExecutionSummary["state"],
    revision: Number(raw.revision ?? 0),
    last_sequence: Number(raw.last_sequence ?? 0),
    ownership_mode: String(raw.ownership_mode ?? raw.mode ?? "B").toUpperCase() as ExecutionSummary["ownership_mode"],
    hold_reason: raw.hold_reason == null ? null : String(raw.hold_reason),
    controller_lease: normalizeLease(raw.controller_lease),
    effect_certainty: optionalString(raw.effect_certainty) as ExecutionSummary["effect_certainty"],
    parent_execution_id: raw.parent_execution_id == null ? null : String(raw.parent_execution_id),
    child_count: Number(raw.child_count ?? (Array.isArray(raw.child_execution_ids) ? raw.child_execution_ids.length : 0)),
    monitor_count: Number(raw.monitor_count ?? 0),
    depth: Number(raw.depth ?? 0),
    created_at: optionalString(raw.created_at),
    updated_at: optionalString(raw.updated_at),
  };
}

function promptInputType(raw: JsonObject): NonNullable<ExecutionSnapshot["active_prompt"]>["type"] {
  const kind = String(raw.input_kind ?? raw.type ?? "").toUpperCase();
  if (kind === "LIST") return "list";
  if (Array.isArray(raw.choices) || Array.isArray(raw.options) || kind === "FIXED_CHOICE" || kind === "CHOICE") return "choice";
  if (kind === "NUMBER" || kind === "NUM") return "number";
  if (kind === "DATE") return "date";
  if (kind === "LIST") return "list";
  if (kind === "CONFIRM") return "confirm";
  return "text";
}

function promptOptionLabel(choice: unknown, index: number): string {
  if (typeof choice !== "object" || choice === null) return String(choice);
  const item = choice as JsonObject;
  const candidate = item.label ?? item.key ?? item.value;
  if (candidate !== undefined && (typeof candidate !== "object" || candidate === null)) return String(candidate);
  try {
    return JSON.stringify(choice);
  } catch {
    return `Option ${index + 1}`;
  }
}

function promptOptionValue(raw: JsonObject, choice: unknown, index: number): unknown {
  const mode = String(raw.list_mode ?? "VALUE").toUpperCase();
  if (mode === "INDEX") return index;
  if (typeof choice !== "object" || choice === null) return choice;
  const item = choice as JsonObject;
  const field = mode === "KEY" ? "key" : mode === "VALUE" ? "value" : null;
  if (
    field !== null &&
    Object.prototype.hasOwnProperty.call(item, field) &&
    Object.prototype.hasOwnProperty.call(item, "label") &&
    Object.keys(item).length === 2
  ) {
    return item[field];
  }
  return choice;
}

function promptOptions(raw: JsonObject): unknown[] | undefined {
  if (Array.isArray(raw.options)) return raw.options;
  return Array.isArray(raw.choices) ? raw.choices : undefined;
}

export function normalizeActivePrompt(value: unknown, fallbackRevision = 0): ActivePrompt | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as JsonObject;
  const options = promptOptions(raw);
  return {
    id: String(raw.id ?? raw.prompt_id ?? ""),
    message: String(raw.message ?? raw.question ?? "Operator response required"),
    type: promptInputType(raw),
    prompt_type: optionalString(raw.prompt_type ?? raw.type) as ActivePrompt["prompt_type"],
    options: options?.map(promptOptionLabel),
    option_values: Array.isArray(raw.option_values)
      ? raw.option_values
      : options?.map((choice, index) => promptOptionValue(raw, choice, index)),
    list_mode: optionalString(raw.list_mode) as ActivePrompt["list_mode"],
    default_value: raw.default_value == null
      ? raw.default == null ? undefined : raw.default
      : raw.default_value,
    deadline: optionalString(raw.deadline ?? raw.response_deadline),
    warning_at: optionalString(raw.warning_at),
    warning_active: Boolean(raw.warning_active ?? raw.warning_emitted_at),
    state: String(raw.state ?? raw.status ?? "OPEN").toUpperCase() as ActivePrompt["state"],
    revision: Number(raw.prompt_revision ?? raw.revision ?? fallbackRevision),
  };
}

function normalizeSchedule(raw: JsonObject): ExecutionSchedule {
  return {
    id: String(raw.id),
    revision: Number(raw.revision ?? 0),
    controller_execution_id: String(raw.controller_execution_id ?? ""),
    schedule_type: String(raw.schedule_type).toUpperCase() as ExecutionSchedule["schedule_type"],
    original_target: String(raw.original_target ?? ""),
    target_at_database_time: String(raw.target_at_database_time ?? ""),
    state: String(raw.state ?? "PENDING").toUpperCase() as ExecutionSchedule["state"],
    catalog_revision_id: String(raw.catalog_revision_id ?? ""),
    context_id: String(raw.context_id ?? "simulator"),
    automatic: Boolean(raw.automatic),
    background_allowed: Boolean(raw.background_allowed),
    created_by: optionalString(raw.created_by),
    created_at: optionalString(raw.created_at_database_time),
    execution_id: raw.execution_id == null ? null : String(raw.execution_id),
  };
}

function normalizeTelemetryConditionSchedule(raw: JsonObject): TelemetryConditionSchedule {
  const argumentsValue = raw.arguments;
  return {
    schedule_id: String(raw.schedule_id ?? raw.id ?? ""),
    idempotency_key: String(raw.idempotency_key ?? ""),
    revision: Number(raw.revision ?? 0),
    controller_execution_id: String(raw.controller_execution_id ?? ""),
    schedule_type: "TELEMETRY_CONDITION",
    state: String(raw.state ?? "PENDING").toUpperCase() as TelemetryConditionSchedule["state"],
    condition_plan_id: String(raw.condition_plan_id ?? ""),
    condition_plan_digest: String(raw.condition_plan_digest ?? ""),
    quality_freshness_policy_id: String(raw.quality_freshness_policy_id ?? ""),
    quality_freshness_policy_revision: String(raw.quality_freshness_policy_revision ?? ""),
    start_snapshot_cursor: String(raw.start_snapshot_cursor ?? "0"),
    last_snapshot_cursor: raw.last_snapshot_cursor == null ? null : String(raw.last_snapshot_cursor),
    attempt_count: Number(raw.attempt_count ?? 0),
    retry_count: Number(raw.retry_count ?? 0),
    retry_interval_ns: Number(raw.retry_interval_ns ?? 0),
    next_attempt_at_database_time: raw.next_attempt_at_database_time == null ? null : String(raw.next_attempt_at_database_time),
    created_at_database_time: raw.created_at_database_time == null ? null : String(raw.created_at_database_time),
    deadline_at_database_time: String(raw.deadline_at_database_time ?? ""),
    procedure_catalog_id: String(raw.procedure_catalog_id ?? ""),
    procedure_revision: Number(raw.procedure_revision ?? 0),
    bundle_digest: String(raw.bundle_digest ?? ""),
    context_id: String(raw.context_id ?? "simulator"),
    arguments: typeof argumentsValue === "object" && argumentsValue !== null && !Array.isArray(argumentsValue)
      ? argumentsValue as Record<string, unknown>
      : {},
    arguments_digest: String(raw.arguments_digest ?? ""),
    automatic: Boolean(raw.automatic),
    background_allowed: Boolean(raw.background_allowed),
    visible: Boolean(raw.visible),
    created_by: optionalString(raw.created_by),
    last_evaluation_id: raw.last_evaluation_id == null ? null : String(raw.last_evaluation_id),
    winning_evaluation_id: raw.winning_evaluation_id == null ? null : String(raw.winning_evaluation_id),
    occurrence_id: raw.occurrence_id == null ? null : String(raw.occurrence_id),
    fired_execution_id: raw.fired_execution_id == null ? null : String(raw.fired_execution_id),
    dispatch_attempts: Number(raw.dispatch_attempts ?? 0),
    failure_code: raw.failure_code == null ? null : String(raw.failure_code),
    error_message: raw.error_message == null ? null : String(raw.error_message),
    claimed_at_database_time: raw.claimed_at_database_time == null ? null : String(raw.claimed_at_database_time),
    settled_at_database_time: raw.settled_at_database_time == null ? null : String(raw.settled_at_database_time),
  };
}

function normalizeInspection(raw: JsonObject): InspectionValue {
  return {
    path: String(raw.path),
    scope: String(raw.scope).toUpperCase() as InspectionValue["scope"],
    name: optionalString(raw.name),
    type: String(raw.type).toUpperCase() as InspectionValue["type"],
    value: raw.value,
    value_revision: Number(raw.value_revision ?? 0),
    execution_revision: Number(raw.execution_revision ?? 0),
    freshness: String(raw.freshness ?? "CURRENT"),
    editable: Boolean(raw.editable),
    redacted: Boolean(raw.redacted),
  };
}

function normalizeAction(raw: JsonObject): NamedUserAction {
  return {
    id: String(raw.id),
    revision: Number(raw.revision ?? 0),
    execution_id: String(raw.execution_id ?? ""),
    name: String(raw.name ?? raw.id),
    label: String(raw.label ?? raw.name ?? raw.id),
    severity: String(raw.severity ?? "INFO").toUpperCase() as NamedUserAction["severity"],
    handler_id: String(raw.handler_id ?? ""),
    enabled: Boolean(raw.enabled),
    dismissed: Boolean(raw.dismissed),
    source_digest: String(raw.source_digest ?? ""),
    last_settlement: optionalString(raw.last_settlement) as NamedUserAction["last_settlement"],
  };
}

function normalizeOutline(execution: JsonObject, explicitValue: unknown): ExecutionSnapshot["outline"] {
  const explicit = Array.isArray(explicitValue)
    ? explicitValue.filter((item): item is JsonObject => typeof item === "object" && item !== null)
    : [];
  if (explicit.some((item) => Number(item.depth ?? 0) > 0 || ["procedure", "call", "branch"].includes(String(item.kind ?? "")))) {
    return explicit.map((item, index) => ({
      id: String(item.id ?? `outline:${index}`),
      label: String(item.label ?? item.kind ?? "Step"),
      line: Number(item.line ?? index + 1),
      depth: Math.max(0, Number(item.depth ?? 0)),
      kind: (["procedure", "branch", "call"].includes(String(item.kind)) ? String(item.kind) : "step") as "procedure" | "step" | "branch" | "call",
    }));
  }
  const rawSteps = Array.isArray(execution.steps) ? execution.steps as JsonObject[] : [];
  const firstLine = Number(rawSteps[0]?.line ?? 1);
  return [
    {
      id: `procedure:${String(execution.id ?? "execution")}`,
      label: String(execution.procedure_name ?? execution.procedure_id ?? "Procedure"),
      line: Number.isInteger(firstLine) && firstLine > 0 ? firstLine : 1,
      depth: 0,
      kind: "procedure" as const,
    },
    ...rawSteps.map((step, index) => {
      const framePath = Array.isArray(step.lexical_frame_path) ? step.lexical_frame_path : [];
      const labels = Array.isArray(step.labels)
        ? step.labels.flatMap((item) => typeof item === "object" && item !== null && "name" in item ? [String((item as JsonObject).name)] : [])
        : [];
      const type = String(step.type ?? "step");
      const boundary = optionalString(step.call_boundary_id);
      const functionName = boundary?.split(":")[2];
      const baseLabel = type === "startproc"
        ? `StartProc: ${String(step.child_reference ?? "child")}`
        : stepLabel(step);
      const scopedLabel = functionName ? `${functionName}: ${baseLabel}` : baseLabel;
      return {
        id: String(step.reachability_id ?? `step:${index}`),
        label: labels.length ? `${labels.join(", ")}: ${scopedLabel}` : scopedLabel,
        line: Number(step.line ?? index + 1),
        depth: 1 + Math.max(0, framePath.length - 1),
        kind: (type === "startproc" || boundary ? "call" : step.guard ? "branch" : "step") as "call" | "branch" | "step",
      };
    }),
  ];
}

function normalizeSnapshot(body: JsonObject): ExecutionSnapshot {
  const execution = unwrapExecution(body);
  const currentStep = Number(execution.current_step_id ?? execution.current_step ?? 0);
  const eventObjects = (Array.isArray(body.events) ? body.events : []) as JsonObject[];
  const events = eventObjects as unknown as ExecutionSnapshot["events"];
  const telemetryEvents = (Array.isArray(body.telemetry) ? body.telemetry : []) as JsonObject[];
  const logEvents = (Array.isArray(body.logs) ? body.logs : []) as JsonObject[];
  const activePrompt = body.active_prompt as JsonObject | null | undefined;
  const summary = normalizeExecutionSummary(execution);
  const steps = normalizeSteps(execution.steps, currentStep) ?? [];
  const textEntries = normalizeViewEntries(body.text_entries ?? execution.text_entries);
  const asRunEntries = normalizeViewEntries(body.as_run_entries ?? execution.as_run_entries);
  const fallbackTextEntries = normalizeViewEntries(eventObjects.filter((event) => {
    const eventType = String(event.event_type ?? "");
    const severity = String(event.severity ?? "").toLowerCase();
    return ["procedure.", "step.", "prompt."].some((prefix) => eventType.startsWith(prefix))
      || ["warning", "error", "critical"].includes(severity);
  }));
  const fallbackAsRunEntries = normalizeViewEntries(eventObjects.filter((event) => String(event.event_type ?? "") !== "telemetry.sample"));
  const coverage = typeof execution.executed_line_coverage === "object" && execution.executed_line_coverage !== null
    ? execution.executed_line_coverage as JsonObject
    : {};
  const explicitExecutedLines = Array.isArray(body.executed_lines)
    ? body.executed_lines
    : Array.isArray(execution.executed_lines)
      ? execution.executed_lines
      : Array.isArray(coverage.lines) ? coverage.lines : [];
  const executedLines = new Set(explicitExecutedLines.map(Number).filter((line) => Number.isInteger(line) && line > 0));
  if (!executedLines.size) {
    for (const event of eventObjects) {
      const eventType = String(event.event_type ?? "");
      const payload = typeof event.payload === "object" && event.payload !== null ? event.payload as JsonObject : {};
      const directLine = Number(payload.line);
      if ((eventType === "step.completed" || eventType === "execution.checkpointed") && Number.isInteger(directLine) && directLine > 0) executedLines.add(directLine);
      const index = eventType === "execution.checkpointed" ? Number(payload.next_step) - 1 : Number(payload.step_index);
      const stepLine = steps[index]?.line;
      if ((eventType === "step.completed" || eventType === "execution.checkpointed") && stepLine) executedLines.add(stepLine);
    }
  }
  if (!executedLines.size) steps.filter((step) => step.state === "complete").forEach((step) => executedLines.add(step.line));
  const supportValue = body.support_logs ?? execution.support_logs;
  const supportEvents = Array.isArray(supportValue)
    ? supportValue as JsonObject[]
    : eventObjects.filter((event) => ["warning", "error", "critical"].includes(String(event.severity ?? "").toLowerCase()));
  return {
    id: String(execution.id),
    procedure_id: String(execution.procedure_id),
    procedure_name: String(execution.procedure_name ?? execution.procedure_id),
    context_id: String(execution.context_id ?? "simulator"),
    state: String(execution.operator_state ?? execution.state ?? "created").toUpperCase() as ExecutionSnapshot["state"],
    revision: Number(execution.revision ?? 0),
    current_step_id: String(currentStep),
    current_line: execution.current_line == null ? undefined : Number(execution.current_line),
    started_at: String(execution.started_at ?? execution.created_at ?? "") || undefined,
    finished_at: execution.finished_at ? String(execution.finished_at) : undefined,
    last_sequence: Number(body.last_sequence ?? execution.last_sequence ?? 0),
    source: typeof execution.source === "string" ? execution.source : undefined,
    source_digest: optionalString(execution.source_digest),
    steps,
    telemetry: telemetryEvents.map(eventTelemetry),
    events,
    logs: logEvents.map(eventLog),
    active_prompt: normalizeActivePrompt(activePrompt, Number(execution.revision ?? 0)),
    ownership_mode: summary.ownership_mode,
    hold_reason: summary.hold_reason,
    controller_lease: summary.controller_lease,
    effect_certainty: summary.effect_certainty,
    automatic: Boolean(execution.automatic),
    background_allowed: Boolean(execution.background_allowed),
    visible: execution.visible == null ? undefined : Boolean(execution.visible),
    text: optionalString(execution.text ?? body.text),
    as_run_source: optionalString(execution.as_run_source ?? body.as_run_source),
    text_entries: textEntries.length ? textEntries : fallbackTextEntries,
    as_run_entries: asRunEntries.length ? asRunEntries : fallbackAsRunEntries,
    executed_lines: [...executedLines].sort((left, right) => left - right),
    view_cursor: Number(body.workspace_cursor ?? execution.workspace_cursor ?? body.view_cursor ?? body.last_sequence ?? execution.last_sequence ?? 0),
    support_logs: supportEvents.map(eventLog),
    outline: normalizeOutline(execution, body.outline ?? execution.outline),
    breakpoints: Array.isArray(body.breakpoints)
      ? body.breakpoints.map(Number)
      : Array.isArray(execution.breakpoints) ? execution.breakpoints.map(Number) : [],
    schedules: Array.isArray(body.schedules) ? (body.schedules as JsonObject[]).map(normalizeSchedule) : [],
    inspection: Array.isArray(body.inspection) ? body.inspection as InspectionValue[] : [],
    actions: Array.isArray(body.actions) ? (body.actions as JsonObject[]).map(normalizeAction) : [],
    relationships: Array.isArray(body.relationships) ? body.relationships as ParentChildLink[] : [],
    parent_execution_id: summary.parent_execution_id,
    child_execution_ids: Array.isArray(execution.child_execution_ids) ? execution.child_execution_ids.map(String) : [],
    depth: summary.depth,
    settings: typeof execution.settings === "object" && execution.settings !== null
      ? execution.settings as PromptSettings
      : {},
  };
}

export interface ControlProof {
  session_id: string;
  client_instance_key_id: string;
  lease_id?: string;
  expected_lease_revision?: number;
  control_fencing_token?: number;
}

export interface TelemetryScheduleCreateInput {
  controller_execution_id: string;
  condition_plan: TelemetryConditionPlan;
  timeout_seconds: number;
  retry_count?: number;
  retry_interval_seconds?: number;
  procedure_catalog_id: string;
  procedure_revision?: number;
  context_id: string;
  arguments?: Record<string, unknown>;
  automatic: boolean;
  background_allowed: boolean;
  visible?: boolean;
  expected_execution_revision: number;
  proof: ControlProof;
}

export interface PromptResponseResult {
  prompt: {
    id?: string;
    state?: string;
  };
  attempt: {
    id?: string;
    outcome?: string;
  };
}

type ConsoleOperationBase = { expected_execution_revision: number };
export type ConsoleOperationInput =
  | (ConsoleOperationBase & { operation: "LIST_SCOPE"; scope: InspectionValue["scope"] })
  | (ConsoleOperationBase & { operation: "READ_VALUE" | "EXPAND_VALUE"; path: string })
  | (ConsoleOperationBase & { operation: "SEARCH_SOURCE_LITERAL"; query: string; limit?: number })
  | (ConsoleOperationBase & { operation: "WRITE_TYPED_LITERAL"; path: string; type: InspectionValue["type"]; value: unknown });

function mutationProof(proof?: ControlProof): JsonObject {
  if (!proof) return {};
  return {
    session_id: proof.session_id,
    client_instance_key_id: proof.client_instance_key_id,
    lease_id: proof.lease_id,
    expected_lease_revision: proof.expected_lease_revision,
    control_fencing_token: proof.control_fencing_token,
  };
}

export const api = {
  async health(): Promise<HealthStatus> {
    const raw = await request<JsonObject>("/health");
    return {
      service: "SPELL Simulator",
      version: String(raw.version ?? "0.11.0"),
      status: String(raw.status ?? "unknown"),
      server_time: raw.server_time ? String(raw.server_time) : undefined,
      mode: raw.mode ? String(raw.mode) : undefined,
    };
  },

  async procedures(): Promise<ProcedureSummary[]> {
    const items = unwrapList(await request<JsonObject[] | { items: JsonObject[] }>("/procedures"));
    return items.map(normalizeProcedure);
  },

  async contexts(): Promise<ContextSummary[]> {
    const items = unwrapList(await request<JsonObject[] | { items: JsonObject[] }>("/contexts"));
    return items.map((raw) => ({
      id: String(raw.id),
      name: String(raw.name ?? raw.id),
      description: optionalString(raw.description),
      attached: Boolean(raw.attached ?? raw.enabled ?? true),
      catalog_revision: String(raw.catalog_revision ?? raw.revision ?? "current"),
      procedure_count: raw.procedure_count == null ? undefined : Number(raw.procedure_count),
      active_execution_count: raw.active_execution_count == null ? undefined : Number(raw.active_execution_count),
    }));
  },

  async procedureHistory(procedureId: string): Promise<ProcedureRevision[]> {
    const body = await request<{ procedure?: JsonObject; items: JsonObject[] }>(`/procedures/${encodeURIComponent(procedureId)}/history`);
    const currentRevision = Number(body.procedure?.current_revision ?? body.items[0]?.revision ?? 0);
    return body.items.map((raw) => ({
      id: String(raw.id),
      catalog_id: String(raw.catalog_id ?? procedureId),
      revision: Number(raw.revision),
      source_digest: String(raw.source_digest ?? ""),
      bundle_digest: String(raw.bundle_digest ?? ""),
      created_at: optionalString(raw.created_at),
      current: Number(raw.revision) === currentRevision,
    }));
  },

  async executions(): Promise<ExecutionSummary[]> {
    const items = unwrapList(await request<JsonObject[] | { items: JsonObject[] }>("/master"));
    return items.map(normalizeExecutionSummary);
  },

  async validateProcedure(source: string): Promise<ProcedureValidationResult> {
    return request<ProcedureValidationResult>("/procedures/validate", {
      method: "POST",
      body: JSON.stringify({ source }),
    });
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

  async workspaceSearch(
    executionId: string,
    query: string,
    view: WorkspaceSearchView,
    sourceDigest?: string,
    afterSequence = 0,
    limit = 100,
  ): Promise<WorkspaceSearchResult> {
    const parameters = new URLSearchParams({
      query,
      view,
      after_sequence: String(afterSequence),
      limit: String(limit),
    });
    if (sourceDigest) parameters.set("source_digest", sourceDigest);
    const body = await request<JsonObject>(
      `/executions/${encodeURIComponent(executionId)}/workspace-search?${parameters.toString()}`,
    );
    const rawItems = Array.isArray(body.items)
      ? body.items.filter((item): item is JsonObject => typeof item === "object" && item !== null)
      : [];
    return {
      view: String(body.view ?? view).toUpperCase() as WorkspaceSearchView,
      query: String(body.query ?? query),
      source_digest: optionalString(body.source_digest),
      items: rawItems.map((item, index) => {
        const normalized = normalizeViewEntry(item, index);
        return {
          ...normalized,
          sequence: item.sequence == null ? undefined : Number(item.sequence),
          time: item.time == null ? undefined : normalized.time,
          scope: item.scope == null ? undefined : normalized.scope,
          kind: item.kind == null ? undefined : normalized.kind,
          message: item.message == null ? undefined : normalized.message,
          line: item.line == null ? undefined : Number(item.line),
          column: item.column == null ? undefined : Number(item.column),
          text: optionalString(item.text),
          source_digest: optionalString(item.source_digest),
        };
      }),
      next_cursor: Number(body.next_cursor ?? afterSequence),
    };
  },

  async workspaceHistory(
    executionId: string,
    view: WorkspaceHistoryView,
    sourceDigest?: string,
    afterSequence = 0,
    limit = 100,
  ): Promise<WorkspaceHistoryResult> {
    const parameters = new URLSearchParams({
      view,
      after_sequence: String(afterSequence),
      limit: String(limit),
    });
    if (sourceDigest) parameters.set("source_digest", sourceDigest);
    const body = await request<JsonObject>(
      `/executions/${encodeURIComponent(executionId)}/workspace-view?${parameters.toString()}`,
    );
    const rawItems = Array.isArray(body.items)
      ? body.items.filter((item): item is JsonObject => typeof item === "object" && item !== null)
      : [];
    return {
      view: String(body.view ?? view).toUpperCase() as WorkspaceHistoryView,
      source_digest: String(body.source_digest ?? sourceDigest ?? ""),
      items: rawItems.map(normalizeViewEntry),
      after_sequence: Number(body.after_sequence ?? afterSequence),
      next_cursor: body.next_cursor == null ? undefined : Number(body.next_cursor),
      has_more: body.has_more === true,
      through_sequence: Number(body.through_sequence ?? 0),
    };
  },

  command: (
    executionId: string,
    type: string,
    expectedRevision: number,
    reason: string,
    proof?: ControlProof,
    target?: Record<string, unknown>,
  ) =>
    request<{ command: CommandReceipt }>(
      `/executions/${encodeURIComponent(executionId)}/commands`,
      {
        method: "POST",
        body: JSON.stringify({
          type: type.toUpperCase(),
          expected_execution_revision: expectedRevision,
          reason,
          idempotency_key: crypto.randomUUID(),
          correlation_id: crypto.randomUUID(),
          ...mutationProof(proof),
          target,
        }),
      },
    ).then((body) => body.command),

  respondToPrompt: (
    promptId: string,
    action: "COMMIT" | "ABORT",
    value: unknown,
    expectedPromptRevision: number,
    proof?: ControlProof,
  ) =>
    request<PromptResponseResult>(`/prompts/${encodeURIComponent(promptId)}/responses`, {
      method: "POST",
      body: JSON.stringify({
        action,
        value,
        expected_prompt_revision: expectedPromptRevision,
        ...mutationProof(proof),
        reason: "Operator response from SPELL console",
        idempotency_key: crypto.randomUUID(),
      }),
    }),

  async control(
    executionId: string,
    action: "ACQUIRE" | "RENEW" | "RELEASE_TO_BACKGROUND",
    expectedExecutionRevision: number,
    proof: ControlProof,
    acknowledgement?: string,
  ): Promise<{ execution: ExecutionSummary; control_lease: ControllerLease | null }> {
    const body = await request<{ execution: JsonObject; control_lease?: JsonObject | null }>(
      `/executions/${encodeURIComponent(executionId)}/control`,
      {
        method: "POST",
        body: JSON.stringify({
          action,
          expected_execution_revision: expectedExecutionRevision,
          ...mutationProof(proof),
          lease_seconds: 60,
          acknowledgement,
          idempotency_key: crypto.randomUUID(),
          reason: `${action} requested by SPELL console operator`,
        }),
      },
    );
    return {
      execution: normalizeExecutionSummary(body.execution),
      control_lease: normalizeLease(body.control_lease),
    };
  },

  async startMonitor(executionId: string, proof: ControlProof): Promise<MonitorSubscription> {
    const body = await request<{ monitor: MonitorSubscription }>(`/executions/${encodeURIComponent(executionId)}/monitors`, {
      method: "POST",
      body: JSON.stringify({ session_id: proof.session_id, client_instance_key_id: proof.client_instance_key_id }),
    });
    return body.monitor;
  },

  async stopMonitor(executionId: string, monitorId: string): Promise<MonitorSubscription> {
    const body = await request<{ monitor: MonitorSubscription }>(`/executions/${encodeURIComponent(executionId)}/monitors/${encodeURIComponent(monitorId)}`, { method: "DELETE" });
    return body.monitor;
  },

  async handovers(executionId: string, includeTerminal = false): Promise<ControllerHandover[]> {
    const query = includeTerminal ? "?include_terminal=true" : "";
    const body = await request<{ items: JsonObject[] }>(`/executions/${encodeURIComponent(executionId)}/handovers${query}`);
    return body.items.map(normalizeHandover);
  },

  async requestHandover(
    executionId: string,
    requesterMonitorId: string,
    expectedExecutionRevision: number,
    responsibilityAcknowledgement: string,
    reason: string,
    proof: ControlProof,
  ): Promise<ControllerHandover> {
    const body = await request<{ handover: JsonObject }>(`/executions/${encodeURIComponent(executionId)}/handovers`, {
      method: "POST",
      body: JSON.stringify({
        requester_monitor_id: requesterMonitorId,
        session_id: proof.session_id,
        client_instance_key_id: proof.client_instance_key_id,
        expected_execution_revision: expectedExecutionRevision,
        responsibility_acknowledgement: responsibilityAcknowledgement,
        expires_seconds: 60,
        idempotency_key: crypto.randomUUID(),
        reason,
      }),
    });
    return normalizeHandover(body.handover);
  },

  async approveHandover(
    executionId: string,
    handover: ControllerHandover,
    expectedExecutionRevision: number,
    reason: string,
    proof: ControlProof,
  ): Promise<{ handover: ControllerHandover; execution: ExecutionSummary; control_lease: ControllerLease; former_monitor?: MonitorSubscription }> {
    const body = await request<{ handover: JsonObject; execution: JsonObject; control_lease: JsonObject; former_monitor?: MonitorSubscription; former_holder_monitor?: MonitorSubscription }>(
      `/executions/${encodeURIComponent(executionId)}/handovers/${encodeURIComponent(handover.id)}/approve`,
      {
        method: "POST",
        body: JSON.stringify({
          expected_handover_revision: handover.revision,
          expected_execution_revision: expectedExecutionRevision,
          ...mutationProof(proof),
          lease_seconds: 60,
          idempotency_key: crypto.randomUUID(),
          reason,
        }),
      },
    );
    return {
      handover: normalizeHandover(body.handover),
      execution: normalizeExecutionSummary(body.execution),
      control_lease: normalizeLease(body.control_lease)!,
      former_monitor: body.former_monitor ?? body.former_holder_monitor,
    };
  },

  async updateExecutionSettings(
    executionId: string,
    settings: PromptSettings,
    expectedExecutionRevision: number,
    proof: ControlProof,
    reason: string,
  ): Promise<void> {
    await request(`/executions/${encodeURIComponent(executionId)}/settings`, {
      method: "PUT",
      body: JSON.stringify({
        settings,
        expected_execution_revision: expectedExecutionRevision,
        ...mutationProof(proof),
        idempotency_key: crypto.randomUUID(),
        reason,
      }),
    });
  },

  async schedules(controllerExecutionId?: string): Promise<ExecutionSchedule[]> {
    const query = controllerExecutionId
      ? `?${new URLSearchParams({ controller_execution_id: controllerExecutionId })}`
      : "";
    const body = await request<{ items: JsonObject[] }>(`/schedules${query}`);
    return body.items.map(normalizeSchedule);
  },

  async createSchedule(input: {
    controller_execution_id: string;
    schedule_type: "RELATIVE" | "ABSOLUTE";
    target: string | number;
    procedure_catalog_id: string;
    context_id: string;
    automatic: boolean;
    background_allowed: boolean;
    expected_execution_revision: number;
    proof: ControlProof;
  }): Promise<ExecutionSchedule> {
    const body = await request<JsonObject | { schedule: JsonObject }>("/schedules", {
      method: "POST",
      body: JSON.stringify({
        ...input,
        ...mutationProof(input.proof),
        proof: undefined,
        idempotency_key: crypto.randomUUID(),
        reason: "Schedule created by SPELL console operator",
      }),
    });
    return normalizeSchedule(unwrapResource<JsonObject>(body, "schedule"));
  },

  async cancelSchedule(scheduleId: string, revision: number, proof: ControlProof): Promise<ExecutionSchedule> {
    const body = await request<JsonObject | { schedule: JsonObject }>(
      `/schedules/${encodeURIComponent(scheduleId)}/cancel`,
      {
        method: "POST",
        body: JSON.stringify({
          expected_schedule_revision: revision,
          ...mutationProof(proof),
          idempotency_key: crypto.randomUUID(),
          reason: "Schedule cancelled by SPELL console operator",
        }),
      },
    );
    return normalizeSchedule(unwrapResource<JsonObject>(body, "schedule"));
  },

  async telemetrySchedules(controllerExecutionId?: string): Promise<TelemetryConditionSchedule[]> {
    const query = controllerExecutionId
      ? `?${new URLSearchParams({ controller_execution_id: controllerExecutionId })}`
      : "";
    const body = await request<{ items: JsonObject[] }>(`/telemetry-schedules${query}`);
    return body.items.map(normalizeTelemetryConditionSchedule);
  },

  async telemetrySchedule(scheduleId: string): Promise<TelemetryConditionSchedule> {
    const body = await request<JsonObject | { schedule: JsonObject }>(
      `/telemetry-schedules/${encodeURIComponent(scheduleId)}`,
    );
    return normalizeTelemetryConditionSchedule(unwrapResource<JsonObject>(body, "schedule"));
  },

  async createTelemetrySchedule(input: TelemetryScheduleCreateInput): Promise<TelemetryConditionSchedule> {
    const { proof, ...schedule } = input;
    const body = await request<JsonObject | { schedule: JsonObject }>("/telemetry-schedules", {
      method: "POST",
      body: JSON.stringify({
        ...schedule,
        ...mutationProof(proof),
        idempotency_key: crypto.randomUUID(),
        reason: "Telemetry-conditioned schedule created by SPELL console operator",
      }),
    });
    return normalizeTelemetryConditionSchedule(unwrapResource<JsonObject>(body, "schedule"));
  },

  async cancelTelemetrySchedule(
    scheduleId: string,
    controllerExecutionId: string,
    revision: number,
    proof: ControlProof,
  ): Promise<TelemetryConditionSchedule> {
    const body = await request<JsonObject | { schedule: JsonObject }>(
      `/telemetry-schedules/${encodeURIComponent(scheduleId)}/cancel`,
      {
        method: "POST",
        body: JSON.stringify({
          controller_execution_id: controllerExecutionId,
          expected_schedule_revision: revision,
          ...mutationProof(proof),
          idempotency_key: crypto.randomUUID(),
          reason: "Telemetry-conditioned schedule cancelled by SPELL console operator",
        }),
      },
    );
    return normalizeTelemetryConditionSchedule(unwrapResource<JsonObject>(body, "schedule"));
  },

  async inspection(executionId: string): Promise<InspectionValue[]> {
    const body = await request<{ items: JsonObject[] }>(`/executions/${encodeURIComponent(executionId)}/inspection`);
    return body.items.map(normalizeInspection);
  },

  async editInspection(
    executionId: string,
    input: Pick<InspectionValue, "path" | "scope" | "type" | "value"> & { expected_value_revision: number; expected_execution_revision: number },
    proof: ControlProof,
  ): Promise<InspectionValue> {
    const body = await request<JsonObject | { value: JsonObject }>(
      `/executions/${encodeURIComponent(executionId)}/inspection/edits`,
      {
        method: "POST",
        body: JSON.stringify({ ...input, ...mutationProof(proof), idempotency_key: crypto.randomUUID(), reason: "Typed safe-state edit from SPELL console" }),
      },
    );
    return normalizeInspection(unwrapResource<JsonObject>(body, "value"));
  },

  async consoleOperation(
    executionId: string,
    input: ConsoleOperationInput,
    proof?: ControlProof,
  ): Promise<unknown> {
    return request(`/executions/${encodeURIComponent(executionId)}/console-operations`, {
      method: "POST",
      body: JSON.stringify({ ...input, ...(input.operation === "WRITE_TYPED_LITERAL" ? mutationProof(proof) : {}), idempotency_key: crypto.randomUUID(), reason: "Bounded console operation" }),
    });
  },

  async actions(executionId: string): Promise<NamedUserAction[]> {
    const body = await request<{ items: JsonObject[] }>(`/executions/${encodeURIComponent(executionId)}/actions`);
    return body.items.map(normalizeAction);
  },

  async mutateAction(
    executionId: string,
    action: NamedUserAction,
    operation: "ENABLE" | "DISABLE" | "DISMISS",
    executionRevision: number,
    proof: ControlProof,
  ): Promise<NamedUserAction> {
    const body = await request<JsonObject | { action: JsonObject }>(
      `/executions/${encodeURIComponent(executionId)}/actions/${encodeURIComponent(action.id)}/mutations`,
      {
        method: "POST",
        body: JSON.stringify({
          operation,
          expected_action_revision: action.revision,
          expected_execution_revision: executionRevision,
          ...mutationProof(proof),
          idempotency_key: crypto.randomUUID(),
          reason: `${operation} named action ${action.name} from SPELL console`,
        }),
      },
    );
    return normalizeAction(unwrapResource<JsonObject>(body, "action"));
  },

  async invokeAction(executionId: string, action: NamedUserAction, executionRevision: number, proof: ControlProof): Promise<unknown> {
    return request(`/executions/${encodeURIComponent(executionId)}/actions/${encodeURIComponent(action.id)}/invoke`, {
      method: "POST",
      body: JSON.stringify({
        expected_action_revision: action.revision,
        expected_execution_revision: executionRevision,
        ...mutationProof(proof),
        idempotency_key: crypto.randomUUID(),
        reason: `Named action ${action.name} invoked by SPELL console operator`,
      }),
    });
  },

  async relationships(executionId: string): Promise<ParentChildLink[]> {
    const body = await request<{ items: ParentChildLink[] }>(`/executions/${encodeURIComponent(executionId)}/relationships`);
    return body.items;
  },

  async setBreakpoint(executionId: string, line: number, enabled: boolean, executionRevision: number, proof: ControlProof, oneShot = false): Promise<void> {
    await request(`/executions/${encodeURIComponent(executionId)}/breakpoints/${line}`, {
      method: enabled ? "PUT" : "DELETE",
      body: JSON.stringify({ expected_execution_revision: executionRevision, one_shot: oneShot, ...mutationProof(proof), idempotency_key: crypto.randomUUID(), reason: oneShot ? "One-shot run-to-line breakpoint from SPELL console" : "Breakpoint mutation from SPELL console" }),
    });
  },

  async clearBreakpoints(executionId: string, executionRevision: number, proof: ControlProof): Promise<void> {
    await request(`/executions/${encodeURIComponent(executionId)}/breakpoints`, {
      method: "DELETE",
      body: JSON.stringify({ expected_execution_revision: executionRevision, one_shot: false, ...mutationProof(proof), idempotency_key: crypto.randomUUID(), reason: "Remove all breakpoints from SPELL console" }),
    });
  },

  async report(executionId: string): Promise<AsRunReport> {
    const report = await request<AsRunReport>(`/executions/${encodeURIComponent(executionId)}/report`);
    return { ...report, state: report.state.toUpperCase() as AsRunReport["state"] };
  },

  async drivers(limit = 100, cursor?: string): Promise<PageResult<DriverRecord>> {
    return request<PageResult<DriverRecord>>(`/drivers?${pageQuery(limit, cursor)}`);
  },

  async driver(driverId: string): Promise<DriverRecord> {
    const body = await request<DriverRecord | { driver: DriverRecord }>(
      `/drivers/${encodeURIComponent(driverId)}`,
    );
    return unwrapResource(body, "driver");
  },

  async driverContexts(
    limit = 100,
    cursor?: string,
  ): Promise<PageResult<DriverContextGeneration>> {
    return request<PageResult<DriverContextGeneration>>(
      `/driver-contexts?${pageQuery(limit, cursor)}`,
    );
  },

  async driverContext(
    contextId: string,
    contextGeneration: string | number,
  ): Promise<DriverContextGeneration> {
    const body = await request<
      DriverContextGeneration | { context_generation: DriverContextGeneration }
    >(
      `/driver-contexts/${encodeURIComponent(contextId)}/generations/${encodeURIComponent(String(contextGeneration))}`,
    );
    return unwrapResource(body, "context_generation");
  },

  async driverBindings(limit = 100, cursor?: string): Promise<PageResult<DriverBinding>> {
    return request<PageResult<DriverBinding>>(
      `/driver-bindings?${pageQuery(limit, cursor)}`,
    );
  },

  async driverBinding(driverBindingId: string): Promise<DriverBinding> {
    const body = await request<DriverBinding | { binding: DriverBinding }>(
      `/driver-bindings/${encodeURIComponent(driverBindingId)}`,
    );
    return unwrapResource(body, "binding");
  },

  async driverOperation(operationId: string): Promise<DriverOperation> {
    const body = await request<DriverOperation | { operation: DriverOperation }>(
      `/driver-operations/${encodeURIComponent(operationId)}`,
    );
    return unwrapResource(body, "operation");
  },

  async driverTime(contextId: string): Promise<DriverTimeObservation> {
    const query = new URLSearchParams({ context_id: contextId });
    const body = await request<
      DriverTimeObservation | { driver_time: DriverTimeObservation }
    >(
      `/driver-time?${query.toString()}`,
    );
    return unwrapResource(body, "driver_time");
  },

  async telemetrySnapshot(contextId: string): Promise<TelemetryObservationSnapshot> {
    const query = new URLSearchParams({ context_id: contextId });
    const body = await request<
      TelemetryObservationSnapshot | { snapshot: TelemetryObservationSnapshot }
    >(`/telemetry/snapshot?${query.toString()}`);
    return unwrapResource(body, "snapshot");
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

export function driverWebsocketUrl(afterSequence: number): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const query = new URLSearchParams({ after_sequence: String(afterSequence) });
  return `${scheme}//${window.location.host}${API_ROOT}/driver-events/ws?${query.toString()}`;
}

export function telemetryWebsocketUrl(
  contextId: string,
  afterSequence: string,
  streamEpoch?: string,
): string {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const query = new URLSearchParams({
    context_id: contextId,
    after_sequence: afterSequence,
  });
  if (streamEpoch) query.set("stream_epoch", streamEpoch);
  return `${scheme}//${window.location.host}${API_ROOT}/telemetry-events/ws?${query.toString()}`;
}

export function websocketProtocols(token = getAccessToken()): string[] {
  return token ? ["spell-auth", token] : ["spell-auth"];
}
