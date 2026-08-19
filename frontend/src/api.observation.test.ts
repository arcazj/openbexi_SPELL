import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, telemetryWebsocketUrl } from "./api";

describe("v0.7 observation API", () => {
  beforeEach(() => {
    window.sessionStorage.setItem("openbexi.spell.access-token", "signed.test.token");
  });

  afterEach(() => {
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("uses the exact authenticated read-only resources and cursor URL", async () => {
    const driverTime = {
      observation_id: "time-1",
      context_id: "synthetic context",
      context_generation_id: "generation-1",
      driver_host_generation: "host-1",
      time_unix_ns: "1786903200123456789",
      acquired_at_unix_ns: "1786903200123456789",
      received_at_unix_ns: "1786903200124000000",
      received_at: "2026-08-16T18:00:00.124Z",
      clock_source: "SIMULATOR",
      provenance: "deterministic-v07-clock",
      uncertainty_ns: "500000",
      quality: "GOOD",
      validity: "VALID",
    };
    const snapshot = {
      schema_version: "spell.driver.observation.snapshot/1",
      stream: "driver.observation",
      stream_epoch: "epoch-1",
      through_sequence: "9",
      snapshot_at_database_time: "2026-08-16T18:00:00.124Z",
      context_id: "synthetic context",
      context_generation_id: "generation-1",
      source_epochs: [],
      items: [],
      driver_time: driverTime,
      synchronization_state: "NO_SAMPLE",
    };
    const bodies = new Map<string, unknown>([
      ["/api/v1/driver-time?context_id=synthetic+context", { driver_time: driverTime }],
      ["/api/v1/telemetry/snapshot?context_id=synthetic+context", snapshot],
    ]);
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => ({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => bodies.get(String(input)),
    }) as Response);
    vi.stubGlobal("fetch", fetchMock);

    expect((await api.driverTime("synthetic context")).time_unix_ns).toBe(
      "1786903200123456789",
    );
    expect((await api.telemetrySnapshot("synthetic context")).stream_epoch).toBe("epoch-1");
    expect(fetchMock.mock.calls.map(([path]) => String(path))).toEqual([...bodies.keys()]);
    expect(telemetryWebsocketUrl("synthetic context", "9", "epoch-1")).toBe(
      "ws://localhost:3000/api/v1/telemetry-events/ws?context_id=synthetic+context&after_sequence=9&stream_epoch=epoch-1",
    );
  });
});
