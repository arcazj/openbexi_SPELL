export type ConnectionPhase =
  | "CONNECTED"
  | "RECONNECTING"
  | "RESYNCING"
  | "STALE";

export type ExecutionState =
  | "REQUESTED"
  | "VALIDATING"
  | "ADMISSION_PENDING"
  | "LOADING"
  | "CREATED"
  | "READY"
  | "RUNNING"
  | "PAUSED"
  | "WAITING"
  | "PROMPT"
  | "PROMPTING"
  | "INTERRUPTED"
  | "SUSPENDED"
  | "RECOVERING"
  | "RECOVERY_REQUIRED"
  | "STOPPING"
  | "ABORTING"
  | "ABORTED"
  | "ERROR"
  | "FINISHED"
  | "FAILED"
  | "COMPLETED";

export type OwnershipMode = "C" | "M" | "B" | "CONTROL_LOST";

export interface ControllerLease {
  id: string;
  revision: number;
  fencing_token: number;
  execution_id: string;
  holder_subject_id: string;
  holder_session_id?: string;
  client_instance_key_id?: string;
  issued_at: string;
  expires_at: string;
  state: "ACTIVE" | "RELEASED" | "EXPIRED" | "REVOKED" | "TRANSFERRED";
  reason?: string;
  held_by_current_session?: boolean;
}

export interface MonitorSubscription {
  id: string;
  execution_id: string;
  subject_id: string;
  session_id: string;
  client_instance_key_id: string;
  mode: "M";
  state: "ACTIVE" | "CLOSED";
  created_at?: string;
  closed_at?: string | null;
}

export interface ControllerHandover {
  id: string;
  execution_id: string;
  revision: number;
  state: "REQUESTED" | "COMPLETED" | "CANCELLED" | "EXPIRED";
  requester_subject_id: string;
  requester_session_id: string;
  requester_client_instance_key_id: string;
  requester_monitor_id: string;
  expected_execution_revision: number;
  requested_at: string;
  expires_at: string;
  approved_by?: string | null;
  predecessor_lease_id?: string | null;
  successor_lease_id?: string | null;
  successor_control_lease?: ControllerLease | null;
  updated_at: string;
  settled_at?: string | null;
}

export interface PromptSettings {
  PROMPT_WARNING_DELAY?: number | null;
  PROMPT_RESPONSE_TIMEOUT?: number | null;
  NO_CONTROLLER_GRACE?: number | null;
}

export interface ExecutionSummary {
  id: string;
  procedure_id: string;
  procedure_name: string;
  context_id: string;
  state: ExecutionState;
  revision: number;
  last_sequence: number;
  ownership_mode: OwnershipMode;
  hold_reason?: string | null;
  controller_lease?: ControllerLease | null;
  effect_certainty?: "NO_EFFECT" | "EFFECT_CONFIRMED" | "EFFECT_POSSIBLE" | "EFFECT_UNKNOWN";
  parent_execution_id?: string | null;
  child_count?: number;
  monitor_count?: number;
  depth?: number;
  created_at?: string;
  updated_at?: string;
}

export interface ContextSummary {
  id: string;
  name: string;
  description?: string;
  attached: boolean;
  catalog_revision: string;
  procedure_count?: number;
  active_execution_count?: number;
}

export interface ProcedureRevision {
  id: string;
  catalog_id: string;
  revision: number;
  source_digest: string;
  bundle_digest: string;
  created_at?: string;
  current: boolean;
}

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

export interface ExecutionViewEntry {
  id: string;
  sequence: number;
  time: string;
  scope: string;
  kind: string;
  message: string;
  correlation_id?: string;
  line?: number;
  outcome?: string;
}

export type WorkspaceSearchView = "SOURCE" | "TEXT" | "AS_RUN" | "SUPPORT";

export interface WorkspaceSearchMatch {
  id: string;
  sequence?: number;
  time?: string;
  scope?: string;
  kind?: string;
  message?: string;
  correlation_id?: string;
  line?: number;
  column?: number;
  text?: string;
  source_digest?: string;
  outcome?: string;
}

export interface WorkspaceSearchResult {
  view: WorkspaceSearchView;
  query: string;
  source_digest?: string;
  items: WorkspaceSearchMatch[];
  next_cursor: number;
}

export type WorkspaceHistoryView = Exclude<WorkspaceSearchView, "SOURCE">;

export interface WorkspaceHistoryResult {
  view: WorkspaceHistoryView;
  source_digest: string;
  items: ExecutionViewEntry[];
  after_sequence: number;
  next_cursor?: number;
  has_more: boolean;
  through_sequence: number;
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
  type: "text" | "number" | "choice" | "confirm" | "date" | "list";
  prompt_type?: "OK" | "CANCEL" | "OK_CANCEL" | "YES" | "NO" | "YES_NO" | "ALPHA" | "NUM" | "DATE" | "LIST";
  options?: string[];
  option_values?: unknown[];
  list_mode?: "KEY" | "INDEX" | "VALUE";
  default_value?: unknown;
  deadline?: string;
  warning_at?: string;
  warning_active?: boolean;
  state?: "CREATED" | "OPEN" | "SETTLED";
  revision: number;
}

export interface ExecutionOutlineItem {
  id: string;
  label: string;
  line: number;
  depth: number;
  kind: "procedure" | "step" | "branch" | "call";
}

export interface ExecutionSchedule {
  id: string;
  revision: number;
  controller_execution_id: string;
  schedule_type: "RELATIVE" | "ABSOLUTE";
  original_target: string;
  target_at_database_time: string;
  state: "PENDING" | "CLAIMED" | "FIRED" | "CANCELLED" | "MISSED" | "ERROR";
  catalog_revision_id: string;
  context_id: string;
  automatic: boolean;
  background_allowed: boolean;
  created_by?: string;
  created_at?: string;
  execution_id?: string | null;
}

export interface InspectionValue {
  path: string;
  scope: "LOCAL_VARIABLE" | "GLOBAL_VARIABLE" | "ARGS" | "IVARS" | "SHARED_DATA";
  name?: string;
  type: "STRING" | "INTEGER" | "FINITE_DECIMAL" | "BOOLEAN" | "NULL" | "LIST" | "MAP";
  value: unknown;
  value_revision: number;
  execution_revision: number;
  freshness: string;
  editable: boolean;
  redacted?: boolean;
}

export interface NamedUserAction {
  id: string;
  revision: number;
  execution_id: string;
  name: string;
  label: string;
  severity: "INFO" | "WARNING" | "ERROR";
  handler_id: string;
  enabled: boolean;
  dismissed?: boolean;
  source_digest: string;
  last_settlement?: "EXECUTED" | "REJECTED" | "CANCELLED" | "SUPERSEDED";
}

export interface ParentChildLink {
  id: string;
  startproc_id: string;
  parent_execution_id: string;
  child_execution_id: string;
  child_catalog_revision_id: string;
  arguments_digest: string;
  blocking: boolean;
  visible: boolean;
  automatic: boolean;
  created_at?: string;
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
  source_digest?: string;
  steps: ProcedureStep[];
  telemetry: TelemetryPoint[];
  events: ExecutionEvent[];
  logs: LogEntry[];
  active_prompt?: ActivePrompt | null;
  ownership_mode?: OwnershipMode;
  hold_reason?: string | null;
  controller_lease?: ControllerLease | null;
  effect_certainty?: ExecutionSummary["effect_certainty"];
  automatic?: boolean;
  background_allowed?: boolean;
  visible?: boolean;
  text?: string;
  as_run_source?: string;
  text_entries?: ExecutionViewEntry[];
  as_run_entries?: ExecutionViewEntry[];
  executed_lines?: number[];
  view_cursor?: number;
  support_logs?: LogEntry[];
  outline?: ExecutionOutlineItem[];
  breakpoints?: number[];
  schedules?: ExecutionSchedule[];
  inspection?: InspectionValue[];
  actions?: NamedUserAction[];
  relationships?: ParentChildLink[];
  parent_execution_id?: string | null;
  child_execution_ids?: string[];
  depth?: number;
  settings?: PromptSettings;
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
