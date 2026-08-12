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

export interface ValidationDiagnostic {
  severity?: string;
  code?: string;
  message: string;
  line?: number | null;
  column?: number | null;
}

export type ValidationStep = Record<string, unknown> & {
  index?: number;
  line?: number;
  type?: string;
};

export interface ProcedureValidationResult {
  valid: boolean;
  subset_version: string;
  sha256: string | null;
  steps: ValidationStep[];
  variables: unknown[] | Record<string, unknown>;
  diagnostics: ValidationDiagnostic[];
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

export interface DriverCapability {
  service: string;
  method: string;
  modifiers: string[];
  formats: string[];
  mutability: string;
  stream_support: string;
}

export type DriverCapacityValue =
  | number
  | {
      limit?: number;
      used?: number;
      available?: number;
    };

export interface DriverRecord {
  id: string;
  logical_driver_id?: string;
  server_profile_id?: string;
  simulator: boolean;
  enabled: boolean;
  current_host_generation_id?: string | null;
  host_generation_number?: number | null;
  state: string;
  ready: boolean;
  contract_package?: string;
  configuration_schema_version?: string;
  configuration_digest?: string;
  credential_epoch?: number;
  contract_version?: string;
  implementation_version?: string;
  capabilities: DriverCapability[];
  capacity: Record<string, DriverCapacityValue>;
  staleness?: string;
  stale?: boolean;
  last_observed_at?: string | null;
  revision?: number;
}

export interface DriverContextGeneration {
  context_id: string;
  context_generation_id: string;
  generation_number?: number;
  host_generation_id: string;
  state: string;
  ready: boolean;
  configuration_schema_version?: string;
  configuration_digest?: string;
  capacity: Record<string, DriverCapacityValue>;
  staleness?: string;
  stale?: boolean;
  last_observed_at?: string | null;
  created_at?: string | null;
  closed_at?: string | null;
  revision?: number;
}

export interface DriverBinding {
  driver_binding_id: string;
  execution_id: string;
  context_id?: string;
  context_generation_id: string;
  attachment_generation_id?: string;
  attachment_generation_number: number;
  state: string;
  configuration_schema_version?: string;
  configuration_digest?: string;
  operation_id?: string | null;
  current_operation_id?: string | null;
  latest_operation_id?: string | null;
  operation_ids?: string[];
  stage?: string | null;
  certainty?: string | null;
  staleness?: string;
  stale?: boolean;
  last_observed_at?: string | null;
  created_at?: string | null;
  detached_at?: string | null;
  revision?: number;
}

export interface DriverOperationAttempt {
  attempt_id: string;
  attempt_number: number;
  request_digest: string;
  effect_class: string;
  server_profile_id?: string | null;
  host_generation_id: string;
  context_generation_id?: string | null;
  execution_id?: string | null;
  attachment_generation_id?: string | null;
  driver_binding_id?: string | null;
  host_configuration_digest: string;
  context_configuration_digest?: string | null;
  attachment_configuration_digest?: string | null;
  target_operation_id?: string | null;
  target_attempt_id?: string | null;
  credential_epoch: number;
  deadline_at?: string | null;
  created_at?: string | null;
}

export interface DriverOperationTransition {
  transition_id?: string;
  sequence?: number;
  attempt_id?: string;
  stage: string;
  certainty?: string | null;
  disposition?: string | null;
  safe_error?: { code?: string | null; message?: string | null } | null;
  evidence_digest?: string | null;
  actor?: string;
  correlation_id?: string;
  created_at?: string | null;
}

export interface DriverOperation {
  operation_id: string;
  method: string;
  request_digest?: string;
  current_attempt_number: number;
  current_attempt_id?: string | null;
  stage: string;
  certainty?: string | null;
  effect_class: string;
  host_generation_id?: string;
  context_generation_id?: string | null;
  driver_binding_id?: string | null;
  target_operation_id?: string | null;
  target_attempt_id?: string | null;
  requires_reconciliation: boolean;
  disposition?: string | null;
  safe_error?: { code?: string | null; message?: string | null } | null;
  deadline_at?: string | null;
  attempts: DriverOperationAttempt[];
  transitions: DriverOperationTransition[];
  created_at?: string | null;
  updated_at?: string | null;
  settled_at?: string | null;
  revision?: number;
}

export interface DriverLifecycleEvent {
  schema_version?: string;
  event_id?: string;
  event_type: string;
  aggregate_type?: string;
  aggregate_id?: string;
  sequence?: number;
  created_at?: string;
  data?: Record<string, unknown>;
  payload?: {
    reason?: string;
    authoritative_sequence?: number;
  };
}

export interface PageResult<T> {
  items: T[];
  next_cursor?: string | null;
}
