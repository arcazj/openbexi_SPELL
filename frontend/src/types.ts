export type ConnectionPhase =
  | "CONNECTED"
  | "RECONNECTING"
  | "RESYNCING"
  | "STALE";

export type ExecutionState =
  | "CREATED"
  | "READY"
  | "RUNNING"
  | "PAUSED"
  | "WAITING"
  | "PROMPTING"
  | "RECOVERING"
  | "RECOVERY_REQUIRED"
  | "ABORTING"
  | "ABORTED"
  | "FAILED"
  | "COMPLETED";

export interface ProcedureStep {
  id: string;
  line: number;
  label: string;
  source?: string;
  state?: "pending" | "active" | "complete" | "failed";
}

export interface ProcedureSummary {
  id: string;
  name: string;
  version: string;
  description: string;
  entrypoint: string;
  step_count: number;
  steps?: ProcedureStep[];
  source?: string;
}

export interface TelemetryPoint {
  parameter: string;
  value: string | number | boolean;
  unit?: string;
  quality: "GOOD" | "WARNING" | "BAD" | "UNKNOWN";
  source_time: string;
  sequence?: number;
}

export interface LogEntry {
  id: string;
  time: string;
  level: "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";
  source: string;
  message: string;
  sequence?: number;
}

export interface ExecutionEvent {
  event_id: string;
  event_type: string;
  sequence: number;
  server_time: string;
  source_time?: string;
  execution_id: string;
  source?: string;
  severity?: string;
  payload: Record<string, unknown>;
}

export interface ActivePrompt {
  id: string;
  message: string;
  type: "text" | "number" | "choice" | "confirm";
  options?: string[];
  default_value?: string;
  deadline?: string;
  revision: number;
}

export interface ExecutionSnapshot {
  id: string;
  procedure_id: string;
  procedure_name: string;
  context_id: string;
  state: ExecutionState;
  revision: number;
  current_step_id?: string;
  current_line?: number;
  started_at?: string;
  finished_at?: string;
  last_sequence: number;
  source?: string;
  steps: ProcedureStep[];
  telemetry: TelemetryPoint[];
  events: ExecutionEvent[];
  logs: LogEntry[];
  active_prompt?: ActivePrompt | null;
}

export interface CommandReceipt {
  id: string;
  status: "ACCEPTED" | "REJECTED" | "COMPLETED" | "FAILED" | "UNCERTAIN";
}

export interface AsRunReport {
  execution_id: string;
  procedure_name: string;
  state: ExecutionState;
  started_at?: string;
  finished_at?: string;
  generated_at: string;
  summary: Record<string, string | number | boolean | null>;
  events: ExecutionEvent[];
}

export interface HealthStatus {
  service: string;
  version: string;
  status: string;
  server_time?: string;
  mode?: string;
}
