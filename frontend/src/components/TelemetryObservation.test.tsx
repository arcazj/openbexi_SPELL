import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import type {
  DriverTimeObservation,
  TelemetryObservationSnapshot,
} from "../types";
import { TelemetryObservation } from "./TelemetryObservation";

vi.mock("../useTelemetryObservationStream", () => ({
  useTelemetryObservationStream: vi.fn(),
}));

const time: DriverTimeObservation = {
  observation_id: "time-1",
  context_id: "simulator",
  context_generation_id: "context-generation-2",
  driver_host_generation: "host-7",
  time_unix_ns: "1786903200123456789",
  acquired_at_unix_ns: "1786903200123456789",
  received_at_unix_ns: "1786903200124000000",
  received_at: "2026-08-16T18:00:00.124000Z",
  clock_source: "SIMULATOR",
  provenance: "deterministic-v07-clock",
  uncertainty_ns: "500000",
  validity: "VALID",
  quality: "GOOD",
};

const snapshot: TelemetryObservationSnapshot = {
  schema_version: "spell.driver.observation.snapshot/1",
  stream: "driver.observation",
  context_id: "simulator",
  context_generation_id: "context-generation-2",
  stream_epoch: "observation-epoch-4",
  through_sequence: "23",
  snapshot_at_database_time: "2026-08-16T18:00:00.124000Z",
  source_epochs: [{
    source_id: "bundled-deterministic-simulator",
    item_id: "TM.SIM.BUS_VOLTAGE",
    source_epoch: "source-epoch-4",
    last_source_sequence: "18446744073709551614",
    synchronization_state: "COMPLETE",
  }],
  driver_time: time,
  synchronization_state: "COMPLETE",
  items: [
    {
      sample_id: "sample-voltage-9",
      item_id: "TM.SIM.BUS_VOLTAGE",
      qualified_name: "SIM.BUS_VOLTAGE",
      catalog_digest: "a".repeat(64),
      source_id: "bundled-deterministic-simulator",
      source_epoch: "source-epoch-4",
      source_sequence: "18446744073709551614",
      raw_value: { type: "UINT64", value: "18446744073709551614" },
      engineering_value: { type: "FINITE_DOUBLE", value: 27.5 },
      description: "Synthetic main bus voltage",
      unit: "V",
      acquired_at_unix_ns: "1786903200123456789",
      received_at_unix_ns: "1786903200124000000",
      source: "SIMULATOR",
      clock_provenance: "deterministic-v07-clock",
      clock_uncertainty_ns: "500000",
      validity: "VALID",
      quality: "GOOD",
      quality_reason: "nominal",
      freshness: "FRESH",
      freshness_policy_revision: "freshness-v1",
      synchronization_state: "COMPLETE",
      alarm: {
        alarm_observation_id: "alarm-1",
        item_id: "TM.SIM.BUS_VOLTAGE",
        sample_id: "sample-voltage-9",
        limit_set_id: "bus-voltage-v1",
        limit_revision: "1",
        state: "NOT_ALARMED",
        severity: "NONE",
        evaluated_engineering_value: { type: "FINITE_DOUBLE", value: 27.5 },
        quality: "GOOD",
        validity: "VALID",
        freshness: "FRESH",
        boolean_value: false,
        snapshot_cursor: { stream_epoch: "observation-epoch-4", projection_sequence: "23" },
        evaluated_at_database_time: "2026-08-16T18:00:00.124000Z",
        reason: "WITHIN_LIMITS",
      },
    },
  ],
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("TelemetryObservation", () => {
  it("renders exact typed values and keeps quality facts distinct", async () => {
    vi.spyOn(api, "telemetrySnapshot").mockResolvedValue(snapshot);
    render(<TelemetryObservation contextId="simulator" />);

    const section = await screen.findByRole("region", { name: "Telemetry observation" });
    expect(within(section).getByText("1786903200123456789")).toBeInTheDocument();
    expect(within(section).getAllByText("18446744073709551614")).toHaveLength(2);
    expect(within(section).getByText("27.5")).toBeInTheDocument();
    expect(within(section).getByText("V")).toBeInTheDocument();
    expect(within(section).getAllByText("GOOD").length).toBeGreaterThan(0);
    expect(within(section).getAllByText("VALID").length).toBeGreaterThan(0);
    expect(within(section).getAllByText("FRESH").length).toBeGreaterThan(0);
    expect(within(section).getByText("observation-epoch-4")).toBeInTheDocument();
    expect(api.telemetrySnapshot).toHaveBeenCalledWith("simulator");
  });

  it("shows stream gaps independently from stale sample state", async () => {
    vi.spyOn(api, "telemetrySnapshot").mockResolvedValue({
      ...snapshot,
      synchronization_state: "GAPPED",
      items: [{ ...snapshot.items[0]!, freshness: "STALE", synchronization_state: "GAPPED" }],
      source_epochs: [{
        source_id: "bundled-deterministic-simulator",
        item_id: "TM.SIM.BUS_VOLTAGE",
        source_epoch: "source-epoch-4",
        last_source_sequence: "12",
        synchronization_state: "GAPPED",
      }],
    });
    render(<TelemetryObservation contextId="simulator" />);

    expect(await screen.findByText("Cursor gap")).toBeInTheDocument();
    expect(screen.getByText(/bundled-deterministic-simulator/)).toBeInTheDocument();
    expect(screen.getAllByText("STALE").length).toBeGreaterThan(0);
    expect(screen.getAllByText("GAP").length).toBeGreaterThan(0);
  });

  it("keeps an unavailable projection retryable", async () => {
    const telemetrySnapshot = vi
      .spyOn(api, "telemetrySnapshot")
      .mockRejectedValueOnce(new Error("observation offline"));
    render(<TelemetryObservation contextId="simulator" />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Observation unavailable");
    expect(alert).toHaveTextContent("observation offline");

    telemetrySnapshot.mockResolvedValue(snapshot);
    await userEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("SIM.BUS_VOLTAGE")).toBeInTheDocument();
  });

  it("renders an empty committed snapshot without requiring driver time", async () => {
    const driverTime = vi
      .spyOn(api, "driverTime")
      .mockRejectedValue(new Error("driver time must not be fetched"));
    vi.spyOn(api, "telemetrySnapshot").mockResolvedValue({
      ...snapshot,
      through_sequence: "0",
      source_epochs: [],
      items: [],
      driver_time: null,
      synchronization_state: "NO_SAMPLE",
    });

    render(<TelemetryObservation contextId="simulator" />);

    expect(await screen.findByText("No committed samples")).toBeInTheDocument();
    expect(screen.getByText("observation-epoch-4")).toBeInTheDocument();
    expect(driverTime).not.toHaveBeenCalled();
  });
});
