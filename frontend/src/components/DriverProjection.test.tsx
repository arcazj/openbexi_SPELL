import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import type {
  DriverBinding,
  DriverContextGeneration,
  DriverOperation,
  DriverRecord,
} from "../types";
import { DriverProjection } from "./DriverProjection";

vi.mock("../useDriverProjectionStream", () => ({
  useDriverProjectionStream: vi.fn(),
}));

const driver: DriverRecord = {
  id: "driver-record-1",
  logical_driver_id: "bundled-simulator",
  server_profile_id: "local-synthetic",
  simulator: true,
  enabled: true,
  current_host_generation_id: "host-generation-4",
  state: "DEGRADED",
  ready: false,
  configuration_schema_version: "1",
  configuration_digest: "a".repeat(64),
  credential_epoch: 3,
  contract_version: "spell.driver.v1",
  implementation_version: "0.4.0",
  capabilities: [
    {
      service: "Lifecycle",
      method: "Health",
      modifiers: ["SAFE", "IDEMPOTENT"],
      formats: ["PROTOBUF_BINARY"],
      mutability: "LIFECYCLE",
      stream_support: "NONE",
    },
  ],
  capacity: {
    max_contexts_per_host: { limit: 1, used: 1, available: 0 },
  },
  staleness: "STALE",
  stale: true,
  last_observed_at: "2026-07-19T12:00:00Z",
};

const context: DriverContextGeneration = {
  context_id: "synthetic-context",
  context_generation_id: "context-generation-2",
  generation_number: 2,
  host_generation_id: "host-generation-4",
  state: "ACTIVE",
  ready: true,
  configuration_schema_version: "1",
  configuration_digest: "b".repeat(64),
  capacity: { max_attachments_per_context: { limit: 1, used: 1, available: 0 } },
  stale: false,
  last_observed_at: "2026-07-19T12:00:00Z",
};

const binding: DriverBinding = {
  driver_binding_id: "binding-8",
  execution_id: "synthetic-execution-5",
  context_id: context.context_id,
  context_generation_id: context.context_generation_id,
  attachment_generation_number: 3,
  state: "ATTACHED",
  configuration_schema_version: "1",
  configuration_digest: "c".repeat(64),
  latest_operation_id: "operation-13",
  stage: "RECONCILING",
  certainty: "EFFECT_UNKNOWN",
  stale: false,
  last_observed_at: "2026-07-19T12:00:01Z",
};

const operation: DriverOperation = {
  operation_id: "operation-13",
  method: "AttachExecution",
  current_attempt_number: 1,
  stage: "RECONCILING",
  certainty: "EFFECT_UNKNOWN",
  effect_class: "SIMULATOR_LIFECYCLE",
  requires_reconciliation: true,
  disposition: "TIMED_OUT",
  updated_at: "2026-07-19T12:00:02Z",
  attempts: [
    {
      attempt_id: "attempt-1",
      attempt_number: 1,
      request_digest: "d".repeat(64),
      effect_class: "SIMULATOR_LIFECYCLE",
      host_generation_id: "host-generation-4",
      context_generation_id: context.context_generation_id,
      execution_id: binding.execution_id,
      driver_binding_id: binding.driver_binding_id,
      host_configuration_digest: driver.configuration_digest ?? "",
      context_configuration_digest: context.configuration_digest,
      attachment_configuration_digest: binding.configuration_digest,
      credential_epoch: 3,
    },
  ],
  transitions: [
    {
      transition_id: "transition-1",
      sequence: 1,
      attempt_id: "attempt-1",
      stage: "ACCEPTED",
      certainty: "NO_EFFECT",
      created_at: "2026-07-19T12:00:00Z",
    },
    {
      transition_id: "transition-2",
      sequence: 2,
      attempt_id: "attempt-1",
      stage: "RECONCILING",
      certainty: "EFFECT_UNKNOWN",
      created_at: "2026-07-19T12:00:02Z",
    },
  ],
};

function mockProjection(driverValue: DriverRecord = driver) {
  vi.spyOn(api, "drivers").mockResolvedValue({ items: [driverValue], next_cursor: null });
  vi.spyOn(api, "driver").mockResolvedValue(driverValue);
  vi.spyOn(api, "driverContexts").mockResolvedValue({ items: [context], next_cursor: null });
  vi.spyOn(api, "driverContext").mockResolvedValue(context);
  vi.spyOn(api, "driverBindings").mockResolvedValue({ items: [binding], next_cursor: null });
  vi.spyOn(api, "driverBinding").mockResolvedValue(binding);
  vi.spyOn(api, "driverOperation").mockResolvedValue(operation);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("DriverProjection", () => {
  it("shows explicit simulator, health, generation, capacity, stage, and certainty state", async () => {
    mockProjection();
    render(<DriverProjection />);

    const projection = await screen.findByRole("main", { name: "Simulator driver foundation" });
    expect(within(projection).getByText("Simulator only")).toBeInTheDocument();
    expect(within(projection).getByText("Read only")).toBeInTheDocument();
    expect(within(projection).getByRole("heading", { name: "bundled-simulator" })).toBeInTheDocument();
    expect(within(projection).getAllByText("DEGRADED").length).toBeGreaterThan(0);
    expect(within(projection).getAllByText("STALE").length).toBeGreaterThan(0);
    expect(within(projection).getAllByText("host-generation-4").length).toBeGreaterThan(0);
    expect(within(projection).getByText("limit 1 / used 1 / available 0")).toBeInTheDocument();
    expect(within(projection).getByText("SAFE / IDEMPOTENT / PROTOBUF BINARY")).toBeInTheDocument();
    expect(within(projection).getByText("NONE")).toBeInTheDocument();
    expect(within(projection).getAllByText("EFFECT UNKNOWN").length).toBeGreaterThan(0);
    expect(within(projection).getByText("REQUIRED")).toBeInTheDocument();
    expect(within(projection).getByText("synthetic-context")).toBeInTheDocument();
    expect(within(projection).getAllByText("binding-8").length).toBeGreaterThan(0);

    for (const mutation of [
      "Open context",
      "Close context",
      "Attach execution",
      "Detach execution",
      "Cancel lifecycle operation",
      "Drain host",
    ]) {
      expect(within(projection).queryByRole("button", { name: mutation })).not.toBeInTheDocument();
    }
    expect(api.drivers).toHaveBeenCalledTimes(1);
    expect(api.driverContexts).toHaveBeenCalledTimes(1);
    expect(api.driverBindings).toHaveBeenCalledTimes(1);
    expect(api.driverOperation).toHaveBeenCalledWith("operation-13");
  });

  it("keeps an unavailable projection read-only and retryable", async () => {
    vi.spyOn(api, "drivers").mockRejectedValue(new Error("projection offline"));
    vi.spyOn(api, "driverContexts").mockResolvedValue({ items: [] });
    vi.spyOn(api, "driverBindings").mockResolvedValue({ items: [] });
    render(<DriverProjection />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Driver projection unavailable");
    expect(alert).toHaveTextContent("projection offline");
    expect(within(alert).getByRole("button", { name: "Retry" })).toBeEnabled();
  });

  it("distinguishes a failed host with no supported capabilities", async () => {
    mockProjection({
      ...driver,
      capabilities: [],
      state: "FAILED",
      stale: false,
      staleness: "CURRENT",
    });
    render(<DriverProjection />);

    const projection = await screen.findByRole("main", { name: "Simulator driver foundation" });
    expect(within(projection).getAllByText("FAILED").length).toBeGreaterThan(0);
    expect(within(projection).getByText("No capabilities advertised")).toBeInTheDocument();
    expect(within(projection).getByText("CURRENT")).toBeInTheDocument();
  });
});
