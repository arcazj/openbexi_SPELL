import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api";
import type { ExecutionSnapshot } from "../types";
import { CompatibilityControl } from "./CompatibilityControl";

const execution: ExecutionSnapshot = {
  id: "execution-one", procedure_id: "demo", procedure_name: "Demo", context_id: "simulator",
  state: "PAUSED", revision: 5, last_sequence: 3, source_digest: "a".repeat(64),
  steps: [], telemetry: [], events: [], logs: [], ownership_mode: "C",
  controller_lease: { id: "lease-one", revision: 2, fencing_token: 7, execution_id: "execution-one",
    holder_subject_id: "operator", issued_at: "2026-10-01T10:00:00Z", expires_at: "2099-10-01T10:00:00Z",
    state: "ACTIVE", held_by_current_session: true },
};
afterEach(() => { cleanup(); vi.restoreAllMocks(); sessionStorage.clear(); });

describe("compatibility operation identity", () => {
  it("obeys authoritative Python actions and disables all mutations while actions are stale", async () => {
    const current = { ...execution, allowed_actions: ["RUN", "STOP", "ABORT"] };
    const send = vi.spyOn(api, "compatibilityCommand");
    const view = render(<CompatibilityControl execution={current} connected onRefresh={vi.fn()} />);
    await userEvent.click(screen.getByText("Compatibility control"));
    await userEvent.type(screen.getByLabelText("Control reason"), "Run full Python script");
    expect(screen.getByRole("button", { name: "Run through adapter" })).toBeEnabled();
    const step = screen.getByRole("button", { name: "Step through adapter" });
    expect(step).toBeDisabled();
    await userEvent.click(step);
    expect(send).not.toHaveBeenCalled();
    view.rerender(<CompatibilityControl execution={{ ...current, allowed_actions: [] }} connected onRefresh={vi.fn()} />);
    for (const name of ["Run through adapter", "Step through adapter", "Return to read-only", "Abort through adapter"])
      expect(screen.getByRole("button", { name })).toBeDisabled();
  });

  it("retains the exact source and proof across an uncertain outcome and explicit retry", async () => {
    const send = vi.spyOn(api, "compatibilityCommand").mockRejectedValueOnce(new Error("response lost"))
      .mockResolvedValue({ operation_id: "recorded", read_only_confirmed: false, rollback_pending: false,
        command: { id: "one", state: "SETTLED" } });
    render(<CompatibilityControl execution={execution} connected onRefresh={vi.fn()} />);
    await userEvent.click(screen.getByText("Compatibility control"));
    await userEvent.type(screen.getByLabelText("Control reason"), "Check next statement");
    await userEvent.click(screen.getByRole("button", { name: "Step through adapter" }));
    await screen.findByRole("alert");
    expect(send).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Retry same operation" }));
    await screen.findByText("Operation SETTLED");
    expect(send.mock.calls[1]).toEqual(send.mock.calls[0]);
    expect(send.mock.calls[0]![1]).toMatchObject({ source_digest: "a".repeat(64), expected_execution_revision: 5,
      expected_lease_revision: 2, control_fencing_token: 7, operation: "STEP" });
  });

  it("restores operation identity after remount and waits for authoritative rollback confirmation", async () => {
    const saved = { operation_id: "existing", operation: "RETURN_TO_READ_ONLY", source_digest: "a".repeat(64) };
    sessionStorage.setItem("openbexi.spell.compatibility-operation.execution-one", JSON.stringify(saved));
    vi.spyOn(api, "compatibilityReceipt").mockResolvedValue({ operation_id: "existing", read_only_confirmed: true,
      rollback_pending: false, command: { id: "one", state: "SETTLED" } });
    const send = vi.spyOn(api, "compatibilityCommand");
    render(<CompatibilityControl execution={execution} connected onRefresh={vi.fn()} />);
    await userEvent.click(screen.getByText("Compatibility control"));
    expect(screen.getByText("Awaiting authoritative outcome.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Refresh operation" }));
    await screen.findByText("Read-only confirmed: procedure stopped.");
    expect(send).not.toHaveBeenCalled();
  });

  it.each(["viewer", "disconnected", "expired"])("prevents control for %s", async (mode) => {
    const current: ExecutionSnapshot = { ...execution, ownership_mode: mode === "viewer" ? "M" : "C",
      controller_lease: mode === "expired" ? { ...execution.controller_lease!, expires_at: "2000-01-01T00:00:00Z" } : execution.controller_lease };
    render(<CompatibilityControl execution={current} connected={mode !== "disconnected"} onRefresh={vi.fn()} />);
    fireEvent.click(screen.getByText("Compatibility control"));
    fireEvent.change(screen.getByLabelText("Control reason"), { target: { value: "Test" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Step through adapter" })).toBeDisabled());
  });
});
