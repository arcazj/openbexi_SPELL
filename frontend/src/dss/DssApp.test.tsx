import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DssApp } from "./DssApp";
import { dssApi, type DssState, type DssTelemetry } from "./api";

vi.mock("./api", () => ({ dssApi: { state: vi.fn(), telemetry: vi.fn(), control: vi.fn() } }));
vi.mock("./DssCommandForm", () => ({ DssCommandForm: () => null }));
const state: DssState = {
  satellite_id: "GENERIC", epoch: "epoch-1", scenario_id: "unit-test", revision: 4, running: false,
  database_revision: "GENERIC-r1", database_digest: "a".repeat(64), simulator_version: "0.1.0", dynamics_engine_version: "0.1.0",
  bus: { bus_voltage_mv: 28000, safe_mode: false }, core: { tick: 7, commands_executed: 2 }, payload: { temperature_mc: 23000, enabled: true },
  transport: { status: "ready", publisher: "connected" },
};
const telemetry: DssTelemetry = { epoch: "epoch-1", revision: 4, sequence: 8, packet_sha256: "b".repeat(64), packet_hex: "0102",
  samples: [{ item_id: "TM.POWER.BUS_VOLTAGE", raw_value: { type: "UINT64", value: 28000 }, engineering_value: { type: "FINITE_DOUBLE", value: 28 }, unit: "V", validity: "VALID", quality: "GOOD" }] };
beforeEach(() => { vi.mocked(dssApi.state).mockResolvedValue(state); vi.mocked(dssApi.telemetry).mockResolvedValue(telemetry); });
afterEach(() => { cleanup(); vi.resetAllMocks(); });

describe("DSS persisted state workspace", () => {
  it("uses the observed epoch and revision for controls and displays only returned state", async () => {
    vi.mocked(dssApi.control).mockResolvedValue({ ...state, revision: 5, core: { ...state.core, tick: 8 } });
    vi.mocked(dssApi.state).mockResolvedValueOnce(state).mockResolvedValue({ ...state, revision: 5, core: { ...state.core, tick: 8 } });
    render(<DssApp />);
    await screen.findByRole("table", { name: "Bus state" });
    expect(screen.getByRole("button", { name: "Pause" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Advance one tick" }));
    expect(dssApi.control).toHaveBeenCalledWith("STEP", state);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Revision 5"));
    expect(within(screen.getByRole("table", { name: "Core state" })).getByRole("row", { name: "Tick 8" })).toBeVisible();
    expect(screen.queryByRole("button", { name: /reset/i })).not.toBeInTheDocument();
  });

  it("shows packet-derived telemetry and provenance with keyboard tabs and filtering", async () => {
    render(<DssApp />);
    await screen.findByRole("table", { name: "Bus state" });
    screen.getByRole("tab", { name: "Satellite" }).focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Telemetry" })).toHaveFocus();
    const row = screen.getByRole("row", { name: "TM.POWER.BUS_VOLTAGE 28000 28 V VALID GOOD Unavailable" });
    expect(row).toBeVisible();
    await userEvent.click(screen.getByText("Packet provenance"));
    expect(screen.getByText("b".repeat(64))).toBeVisible();
    const packet = screen.getByRole("region", { name: "Raw telemetry packet" });
    expect(packet).toHaveAttribute("tabindex", "0");
    packet.focus();
    expect(packet).toHaveFocus();
    await userEvent.type(screen.getByRole("searchbox", { name: "Filter telemetry" }), "not-present");
    expect(screen.queryByRole("row", { name: /TM.POWER/ })).not.toBeInTheDocument();
    expect(screen.getByText(/No telemetry matches/)).toBeVisible();
  });

  it("retains stale state visibly and disables mutation after a failed refresh", async () => {
    render(<DssApp />);
    await screen.findByRole("table", { name: "Bus state" });
    vi.mocked(dssApi.state).mockRejectedValue(new Error("offline"));
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("button", { name: "Resume" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Advance one tick" })).toBeDisabled();
    expect(screen.getByRole("table", { name: "Bus state" })).toBeVisible();
    expect(dssApi.control).not.toHaveBeenCalled();
  });

  it("does not display previous-epoch telemetry or retry a conflicted control", async () => {
    vi.mocked(dssApi.telemetry).mockResolvedValue({ ...telemetry, epoch: "old-epoch" });
    vi.mocked(dssApi.control).mockRejectedValue(new Error("DSS_REVISION_CONFLICT"));
    render(<DssApp />);
    await screen.findByRole("table", { name: "Bus state" });
    await userEvent.click(screen.getByRole("button", { name: "Advance one tick" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("review it before trying again"));
    expect(dssApi.control).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("tab", { name: "Telemetry" }));
    expect(screen.queryByRole("row", { name: /TM.POWER/ })).not.toBeInTheDocument();
    expect(screen.getByText(/awaiting current epoch/)).toBeVisible();
  });
});
