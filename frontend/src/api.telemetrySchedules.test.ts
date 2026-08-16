import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, type ControlProof } from "./api";
import { createTelemetryConditionPlan } from "./telemetryConditions";

const proof: ControlProof = {
  session_id: "session-1",
  client_instance_key_id: "client-1",
  lease_id: "lease-1",
  expected_lease_revision: 4,
  control_fencing_token: 8,
};

function schedule(state = "PENDING", revision = 3) {
  return {
    schedule_id: "a".repeat(64),
    idempotency_key: "telemetry-schedule-1",
    revision,
    controller_execution_id: "execution-1",
    schedule_type: "TELEMETRY_CONDITION",
    state,
    condition_plan_id: "schedule-condition-1",
    condition_plan_digest: "b".repeat(64),
    quality_freshness_policy_id: "simulator-default",
    quality_freshness_policy_revision: "v07-r1",
    start_snapshot_cursor: "9007199254740993",
    last_snapshot_cursor: null,
    attempt_count: 0,
    retry_count: 1000,
    retry_interval_ns: 300_000_000,
    next_attempt_at_database_time: "2026-08-16T18:00:00Z",
    created_at_database_time: "2026-08-16T18:00:00Z",
    deadline_at_database_time: "2026-08-16T18:05:00Z",
    procedure_catalog_id: "demo",
    procedure_revision: 2,
    bundle_digest: "c".repeat(64),
    context_id: "simulator",
    arguments: {},
    arguments_digest: "d".repeat(64),
    automatic: true,
    background_allowed: true,
    visible: true,
    created_by: "operator",
    last_evaluation_id: null,
    winning_evaluation_id: null,
    occurrence_id: null,
    fired_execution_id: null,
    dispatch_attempts: 0,
    failure_code: null,
    error_message: null,
    claimed_at_database_time: null,
    settled_at_database_time: null,
  };
}

describe("v0.7 telemetry schedule API", () => {
  beforeEach(() => window.sessionStorage.setItem("openbexi.spell.access-token", "signed.test.token"));
  afterEach(() => {
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("binds list, read, create, and cancel to their authenticated durable resources", async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      calls.push({ path, init });
      const response = path.endsWith("/cancel")
        ? { schedule: schedule("CANCELLED", 4) }
        : path.includes(`/telemetry-schedules/${"a".repeat(64)}`)
          ? { schedule: schedule() }
          : init?.method === "POST"
            ? { schedule: schedule() }
            : { items: [schedule()] };
      return new Response(JSON.stringify(response), {
        status: init?.method === "POST" ? 202 : 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    const plan = createTelemetryConditionPlan({
      planId: "schedule-condition-1",
      itemId: "TM.POWER.BUS_VOLTAGE",
      operator: "GE",
      rawValue: "30",
    });
    const listed = await api.telemetrySchedules("execution-1");
    expect(listed[0]).toMatchObject({
      schedule_id: "a".repeat(64),
      idempotency_key: "telemetry-schedule-1",
      state: "PENDING",
      start_snapshot_cursor: "9007199254740993",
      procedure_catalog_id: "demo",
    });
    expect((await api.telemetrySchedule("a".repeat(64))).condition_plan_id).toBe("schedule-condition-1");
    const created = await api.createTelemetrySchedule({
      controller_execution_id: "execution-1",
      condition_plan: plan,
      timeout_seconds: 300,
      retry_count: 1000,
      retry_interval_seconds: 0.3,
      procedure_catalog_id: "demo",
      context_id: "simulator",
      arguments: {},
      automatic: true,
      background_allowed: true,
      visible: true,
      expected_execution_revision: 5,
      proof,
    });
    expect((await api.cancelTelemetrySchedule(created.schedule_id, "execution-1", created.revision, proof)).state).toBe("CANCELLED");

    expect(calls.map((call) => call.path)).toEqual([
      "/api/v1/telemetry-schedules?controller_execution_id=execution-1",
      `/api/v1/telemetry-schedules/${"a".repeat(64)}`,
      "/api/v1/telemetry-schedules",
      `/api/v1/telemetry-schedules/${"a".repeat(64)}/cancel`,
    ]);
    for (const call of calls) {
      expect(new Headers(call.init?.headers).get("Authorization")).toBe("Bearer signed.test.token");
    }
    const createBody = JSON.parse(String(calls[2]?.init?.body)) as Record<string, unknown>;
    expect(createBody).toMatchObject({
      controller_execution_id: "execution-1",
      condition_plan: plan,
      timeout_seconds: 300,
      retry_count: 1000,
      retry_interval_seconds: 0.3,
      procedure_catalog_id: "demo",
      context_id: "simulator",
      automatic: true,
      background_allowed: true,
      visible: true,
      expected_execution_revision: 5,
      lease_id: "lease-1",
      expected_lease_revision: 4,
      control_fencing_token: 8,
    });
    expect(createBody).not.toHaveProperty("proof");
    expect(typeof createBody.idempotency_key).toBe("string");
    const cancelBody = JSON.parse(String(calls[3]?.init?.body)) as Record<string, unknown>;
    expect(cancelBody).toMatchObject({
      controller_execution_id: "execution-1",
      expected_schedule_revision: 3,
      lease_id: "lease-1",
      control_fencing_token: 8,
    });
  });
});
