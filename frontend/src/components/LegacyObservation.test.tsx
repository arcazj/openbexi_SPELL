import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api";
import { LegacyObservation, type ReplaySnapshot } from "./LegacyObservation";

const snapshot: ReplaySnapshot = {
  source: { source_id: "reference-244", digest: "a".repeat(64), clock_ns: "10000000000", live: false },
  connected: true, cursor: "recorded-cursor",
  items: [{ item_id: "COUNTER", outcome: "OK", unit: "count", validity: "VALID", quality: "GOOD",
    raw: { type: "UINT64", value: "18446744073709551615" }, eng: { type: "UINT64", value: "18446744073709551615" } }],
};

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("loads only after expansion and preserves uint64 values", async () => {
  const user = userEvent.setup();
  const read = vi.spyOn(api, "legacyReplaySnapshot").mockResolvedValue(snapshot);
  vi.spyOn(api, "legacyReplayComparison").mockResolvedValue({
    counts: { EQUIVALENT: 5, DIFFERENT: 0, INDETERMINATE: 3, UNSUPPORTED: 1 }, legacy_system_qualified: false,
  });
  render(<LegacyObservation />);
  expect(read).not.toHaveBeenCalled();
  await user.click(screen.getByText("Legacy observation replay"));
  expect(await screen.findByText(/reference-244/)).toBeVisible();
  expect(screen.getAllByText("18446744073709551615")).toHaveLength(2);
  expect(screen.getByLabelText("Compatibility comparison")).toHaveTextContent("5 equivalent, 0 different, 3 indeterminate, 1 unsupported");
  await user.selectOptions(screen.getByLabelText("Observation source"), "simulator");
  expect(read).toHaveBeenLastCalledWith("simulator");
});

it("clears stale evidence when the source fails and allows refresh", async () => {
  const user = userEvent.setup();
  const read = vi.spyOn(api, "legacyReplaySnapshot").mockRejectedValue(new Error("unavailable"));
  vi.spyOn(api, "legacyReplayComparison").mockResolvedValue({
    counts: { EQUIVALENT: 0, DIFFERENT: 0, INDETERMINATE: 0, UNSUPPORTED: 0 }, legacy_system_qualified: false,
  });
  render(<LegacyObservation />);
  await user.click(screen.getByText("Legacy observation replay"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Replay unavailable");
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  read.mockResolvedValue(snapshot);
  await user.click(screen.getByRole("button", { name: "Refresh replay" }));
  expect(await screen.findByText(/reference-244/)).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
