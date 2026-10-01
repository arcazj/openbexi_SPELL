import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { api, setAccessToken } from "../api";
import { ShadowPilot, type PilotDetail } from "./ShadowPilot";

const run: PilotDetail = { id: "run-id", creator: "creator", state: "PENDING_REVIEW", revision: 1,
  report_sha256: "a".repeat(64), route: "SHADOW_ONLY", read_only: true, local_review_recorded: false,
  operational_authorization: false, plan: { items: ["TEMP"], repetitions: 1, value_format: "ENG" },
  report: { equivalent: true, budget_passed: true, elapsed_seconds: 0.01,
    rows: [{ repetition: 1, comparison: { item_id: "TEMP", classification: "EQUIVALENT", differences: [] } }] }, events: [] };
afterEach(() => { cleanup(); vi.restoreAllMocks(); sessionStorage.clear(); });
function identity(role: string, sub = "creator") { setAccessToken(`header.${btoa(JSON.stringify({ role, sub }))}.signature`); }
async function open(role = "operator", sub = "creator") {
  identity(role, sub);
  vi.spyOn(api, "pilotList").mockResolvedValue({ items: [run] });
  vi.spyOn(api, "pilotGet").mockResolvedValue(run);
  const user = userEvent.setup();
  render(<ShadowPilot />);
  await user.click(screen.getByText("Shadow pilot readiness", { exact: true }));
  await screen.findByRole("option", { name: /run-id/ });
  return user;
}

it("prevents viewer mutation and creator self-review", async () => {
  const user = await open("viewer");
  await user.type(screen.getByLabelText("Pilot action reason"), "read evidence");
  expect(screen.getByRole("button", { name: "Run read-only shadow" })).toBeDisabled();
  await user.selectOptions(screen.getByLabelText("Recent shadow runs"), "run-id");
  expect(await screen.findByRole("button", { name: "Record independent review" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Record incident" })).toBeDisabled();
});

it("retains the exact request across an uncertain response and remount", async () => {
  const create = vi.spyOn(api, "pilotCreate").mockRejectedValue(new Error("connection lost"));
  const user = await open();
  await user.type(screen.getByLabelText("Pilot action reason"), "local drill");
  await user.click(screen.getByRole("button", { name: "Run read-only shadow" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Outcome not confirmed");
  expect(create).toHaveBeenCalledTimes(1);
  const first = create.mock.calls[0]?.[0];
  cleanup();
  render(<ShadowPilot />);
  await user.click(screen.getByText("Shadow pilot readiness", { exact: true }));
  await user.click(await screen.findByRole("button", { name: "Retry same pilot request" }));
  await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
  expect(create.mock.calls[1]?.[0]).toEqual(first);
});

it("allows a different administrator to review and shows incident rollback", async () => {
  const user = await open("admin", "reviewer");
  const action = vi.spyOn(api, "pilotAction").mockResolvedValue({ ...run, state: "INCIDENT_READ_ONLY", revision: 2 });
  await user.type(screen.getByLabelText("Pilot action reason"), "review and drill");
  await user.selectOptions(screen.getByLabelText("Recent shadow runs"), "run-id");
  await waitFor(() => expect(screen.getByRole("button", { name: "Record independent review" })).toBeEnabled());
  vi.mocked(api.pilotGet).mockResolvedValue({ ...run, state: "INCIDENT_READ_ONLY", revision: 2, route: "SIMULATOR" });
  await user.click(screen.getByRole("button", { name: "Record incident" }));
  expect(await screen.findByText(/State: INCIDENT_READ_ONLY/)).toBeVisible();
  expect(action).toHaveBeenCalledWith("run-id", expect.objectContaining({ action: "INCIDENT", expected_revision: 1 }));
  expect(screen.getByRole("button", { name: "Record independent review" })).toBeDisabled();
});

it("rejects invalid backup JSON before any restore request", async () => {
  const user = await open("admin", "reviewer");
  const restore = vi.spyOn(api, "pilotRestore");
  await user.type(screen.getByLabelText("Pilot action reason"), "restore drill");
  await user.click(screen.getByText("Backup and restore drill", { exact: true }));
  await user.type(screen.getByLabelText("Pilot backup JSON"), "invalid");
  await user.click(screen.getByRole("button", { name: "Restore as read-only" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("valid backup JSON");
  expect(restore).not.toHaveBeenCalled();
});
