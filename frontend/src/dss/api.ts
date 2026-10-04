export type DssState = {
  satellite_id: string; epoch: string; scenario_id: string; revision: number; running: boolean;
  database_revision: string; database_digest: string; simulator_version: string; dynamics_engine_version: string;
  bus: Record<string, unknown>;
  core: Record<string, unknown>;
  payload: Record<string, unknown>;
  transport?: { status: string; publisher: string; error_code?: string | null; last_publish_ns?: number | null;
    outbox?: { pending_packets: number; pending_limit: number; backpressure: boolean } };
};
export type DssSample = {
  item_id: string; raw_value: unknown; engineering_value: unknown; unit?: string | null;
  validity: string; quality: string; acquired_at_unix_ns?: number | string;
};
export type DssTelemetry = {
  epoch: string; revision: number; sequence: number; samples: DssSample[];
  packet_hex?: string; packet_sha256?: string;
  published?: boolean;
};
export type DssArgumentDefinition = {
  name: string; value_type: "FLOAT" | "LONG" | "BOOLEAN" | "STRING"; required: boolean;
  has_default: boolean; default: unknown; minimum?: number; maximum?: number;
  allowed_values: Array<string | number | boolean>; allowed_formats: string[];
};
export type DssCommandDefinition = { name: string; effect: string; critical: boolean; role?: string; arguments: DssArgumentDefinition[] };
export type DssCatalog = { database_revision: string; database_digest: string; commands: DssCommandDefinition[] };
export type DssCommandResult = { operation_id: string; command_name: string; outcome: "SUCCEEDED" | "REJECTED" | "UNCERTAIN"; receipts: Array<{ stage: string; outcome: string }> };

async function request<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/dss/api/v1/${path}`, {
    method: body === undefined ? "GET" : "POST", cache: "no-store",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    const code = (await response.json().catch(() => ({}))) as { error_code?: unknown };
    if (typeof code.error_code === "string" && /^DSS_[A-Z_]+$/.test(code.error_code)) throw new Error(code.error_code);
    throw new Error("DSS_UNAVAILABLE");
  }
  return await response.json() as T;
}

export const dssApi = {
  state: () => request<DssState>("state"),
  telemetry: () => request<DssTelemetry>("telemetry"),
  catalog: () => request<DssCatalog>("catalog"),
  control: (action: "PAUSE" | "RESUME" | "STEP", state: DssState) => request<DssState>("control", {
    action, expected_epoch: state.epoch, expected_revision: state.revision, ticks: 1,
  }),
  command: (state: DssState, commandName: string, args: Array<{ name: string; value_type: string; value: unknown; value_format: string }>, operationId: string) => request<DssCommandResult>("commands", {
    command_name: commandName, arguments: args, operation_id: operationId, confirmed: true,
    expected_epoch: state.epoch, expected_revision: state.revision,
  }),
};
