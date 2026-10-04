import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DssCommandForm } from "./DssCommandForm";
import { dssApi, type DssState } from "./api";

vi.mock("./api", () => ({ dssApi: { catalog: vi.fn(), command: vi.fn() } }));
const state: DssState = { satellite_id: "GENERIC", epoch: "epoch-1", scenario_id: "ui", revision: 4, running: false,
  database_revision: "GENERIC-r1", database_digest: "a".repeat(64), simulator_version: "0.1.0", dynamics_engine_version: "0.1.0", bus: {}, core: {}, payload: {} };
const changed = vi.fn().mockResolvedValue(undefined);
beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(dssApi.catalog).mockResolvedValue({ database_revision: state.database_revision, database_digest: state.database_digest,
    commands: [{ name: "CMDNAME", effect: "SETPOINT", critical: false, arguments: [{ name: "ARG1", value_type: "FLOAT", required: false,
      has_default: false, default: null, minimum: -10, maximum: 10, allowed_values: [], allowed_formats: ["ENG"] }] }] });
});
afterEach(() => { cleanup(); sessionStorage.clear(); vi.clearAllMocks(); });

it("requires separate command confirmation and sends exact typed database operands", async () => {
  vi.mocked(dssApi.command).mockImplementation(async (_state, name, _args, operation) => ({ operation_id: operation, command_name: name, outcome: "SUCCEEDED", receipts: [{ stage: "ONBOARD_EXECUTION", outcome: "SUCCEEDED" }] }));
  render(<DssCommandForm state={state} unavailable={false} onChanged={changed} />);
  await screen.findByRole("option", { name: "CMDNAME" });
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Command" }), "CMDNAME");
  await userEvent.type(screen.getByRole("textbox", { name: "ARG1 (FLOAT, optional)" }), "2.5");
  expect(screen.getByRole("button", { name: "Send simulator command" })).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox", { name: "Confirm this simulator command" }));
  await userEvent.click(screen.getByRole("button", { name: "Send simulator command" }));
  await screen.findByRole("status");
  expect(dssApi.command).toHaveBeenCalledExactlyOnceWith(state, "CMDNAME", [{ name: "ARG1", value_type: "FLOAT", value: 2.5, value_format: "ENG" }], expect.stringMatching(/^[0-9a-f-]{36}$/));
  expect(sessionStorage.getItem("openbexi.dss.uncertain-command")).toBeNull();
  expect(changed).toHaveBeenCalledOnce();
});

it("retains an uncertain operation across remount without sending again", async () => {
  vi.mocked(dssApi.command).mockRejectedValue(new Error("connection interrupted"));
  const mounted = render(<DssCommandForm state={state} unavailable={false} onChanged={changed} />);
  await screen.findByRole("option", { name: "CMDNAME" });
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Command" }), "CMDNAME");
  await userEvent.click(screen.getByRole("checkbox", { name: "Confirm this simulator command" }));
  await userEvent.click(screen.getByRole("button", { name: "Send simulator command" }));
  await waitFor(() => expect(screen.getByText(/Further UI commands are locked/)).toBeVisible());
  mounted.unmount();
  render(<DssCommandForm state={state} unavailable={false} onChanged={changed} />);
  await screen.findByRole("option", { name: "CMDNAME" });
  expect(screen.getByRole("combobox", { name: "Command" })).toBeDisabled();
  expect(dssApi.command).toHaveBeenCalledOnce();
});

it("clears confirmation when observed revision changes and fences a mismatched database", async () => {
  const mounted = render(<DssCommandForm state={state} unavailable={false} onChanged={changed} />);
  await screen.findByRole("option", { name: "CMDNAME" });
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Command" }), "CMDNAME");
  await userEvent.click(screen.getByRole("checkbox", { name: "Confirm this simulator command" }));
  mounted.rerender(<DssCommandForm state={{ ...state, revision: 5 }} unavailable={false} onChanged={changed} />);
  expect(screen.getByRole("checkbox")).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Send simulator command" })).toBeDisabled();
  mounted.rerender(<DssCommandForm state={{ ...state, database_digest: "b".repeat(64) }} unavailable={false} onChanged={changed} />);
  expect(screen.getByRole("combobox", { name: "Command" })).toBeDisabled();
  expect(dssApi.command).not.toHaveBeenCalled();
});
