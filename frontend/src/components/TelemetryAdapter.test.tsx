import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api";
import { TelemetryAdapter, type AdapterRead } from "./TelemetryAdapter";

const value: AdapterRead = { source: { source_id: "reference-244", digest: "a".repeat(64), live: false },
  item_id: "COUNTER", outcome: "OK", cursor: "next-cursor", value: { type: "UINT64", value: "18446744073709551615" }, sample: null };
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
function catalog() { return vi.spyOn(api, "telemetryAdapterCatalog").mockResolvedValue({ items: [{ item_id: "TEMP" }, { item_id: "COUNTER" }], initial_cursor: "initial-cursor" }); }
async function open() {
  const user = userEvent.setup();
  render(<TelemetryAdapter />);
  await user.click(screen.getByText("Telemetry adapter", { exact: true }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Read current" })).toBeEnabled());
  return user;
}

it("loads on expansion and preserves values and source-bound next modifiers", async () => {
  const listing = catalog();
  const read = vi.spyOn(api, "telemetryAdapterRead").mockResolvedValue(value);
  const user = await open();
  expect(listing).toHaveBeenCalledTimes(1);
  await user.selectOptions(screen.getByLabelText("Telemetry item"), "COUNTER");
  await user.click(screen.getByRole("button", { name: "Read current" }));
  expect(await screen.findByText("Value: 18446744073709551615 (UINT64)")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Read next recorded sample" }));
  expect(read).toHaveBeenLastCalledWith("reference", "COUNTER", { value_format: "ENG", extended: true, wait: true, after: "next-cursor", timeout_ms: 60000 });
});

it("clears stale values and cursor when explicitly switching fallback source", async () => {
  catalog();
  const read = vi.spyOn(api, "telemetryAdapterRead").mockResolvedValue(value);
  const user = await open();
  await user.click(screen.getByRole("button", { name: "Read current" }));
  await screen.findByText(/Value: 184467/);
  await user.selectOptions(screen.getByLabelText("Adapter source"), "simulator");
  expect(screen.queryByText(/Value: 184467/)).not.toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole("button", { name: "Read next recorded sample" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Read next recorded sample" }));
  expect(read).toHaveBeenLastCalledWith("simulator", "TEMP", expect.objectContaining({ after: "initial-cursor" }));
});

it("shows failure without old data and supports explicit retry", async () => {
  catalog();
  const read = vi.spyOn(api, "telemetryAdapterRead").mockRejectedValue(new Error("offline"));
  const user = await open();
  await user.click(screen.getByRole("button", { name: "Read current" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Adapter unavailable");
  expect(screen.queryByLabelText("Adapter result")).not.toBeInTheDocument();
  read.mockResolvedValue({ ...value, outcome: "TIMEOUT", value: null });
  await user.click(screen.getByRole("button", { name: "Read current" }));
  expect(await screen.findByText("Value: Unavailable")).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("never presents indeterminate comparison as equivalent", async () => {
  catalog();
  vi.spyOn(api, "telemetryAdapterCompare").mockResolvedValue({ classification: "INDETERMINATE", differences: [], reference: value, simulator: value });
  const user = await open();
  await user.click(screen.getByRole("button", { name: "Compare both sources" }));
  expect(await screen.findByText("Comparison: INDETERMINATE")).toBeVisible();
});

it("discards late responses from a previous source", async () => {
  catalog();
  let complete!: (value: AdapterRead) => void;
  vi.spyOn(api, "telemetryAdapterRead").mockReturnValue(new Promise((resolve) => { complete = resolve; }));
  const user = await open();
  await user.click(screen.getByRole("button", { name: "Read current" }));
  await user.selectOptions(screen.getByLabelText("Adapter source"), "simulator");
  complete(value);
  await waitFor(() => expect(screen.getByRole("button", { name: "Read current" })).toBeEnabled());
  expect(screen.queryByLabelText("Adapter result")).not.toBeInTheDocument();
});
