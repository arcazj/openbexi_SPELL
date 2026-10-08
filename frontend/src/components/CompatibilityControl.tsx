import { useState } from "react";
import { api, currentControlProof, type ControlProof } from "../api";
import type { ExecutionSnapshot } from "../types";
import { useControlLeaseStatus } from "../useControlLease";

export type CompatibilityOperation = "RUN" | "STEP" | "PAUSE" | "ABORT" | "RETURN_TO_READ_ONLY";
export interface CompatibilityRequest extends ControlProof {
  operation: CompatibilityOperation;
  operation_id: string;
  source_digest: string;
  expected_execution_revision: number;
  reason: string;
}
export interface CompatibilityReceipt {
  operation_id: string;
  read_only_confirmed: boolean;
  rollback_pending: boolean;
  command: { id: string; state: string; rejection_code?: string | null };
}

const terminal = new Set(["SETTLED", "REJECTED", "CANCELLED", "SUPERSEDED", "FAILED"]);
const stopped = new Set(["FINISHED", "COMPLETED", "ABORTED", "ERROR", "FAILED", "STOPPING"]);
const labels: Record<CompatibilityOperation, string> = {
  RUN: "Run through adapter", STEP: "Step through adapter", PAUSE: "Pause through adapter",
  ABORT: "Abort through adapter", RETURN_TO_READ_ONLY: "Return to read-only",
};

export function CompatibilityControl({ execution, connected, onRefresh }: {
  execution: ExecutionSnapshot; connected: boolean; onRefresh: () => void;
}) {
  const storageKey = `openbexi.spell.compatibility-operation.${execution.id}`;
  const [request, setRequest] = useState<CompatibilityRequest | null>(() => {
    try { return JSON.parse(sessionStorage.getItem(storageKey) ?? "null") as CompatibilityRequest | null; }
    catch { return null; }
  });
  const [receipt, setReceipt] = useState<CompatibilityReceipt | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { ownsControl } = useControlLeaseStatus(execution);
  const unresolved = request !== null && (!receipt || !terminal.has(receipt.command.state));
  const permitted = connected && ownsControl && !busy && Boolean(execution.source_digest);

  async function submit(body: CompatibilityRequest) {
    setBusy(true); setError(null);
    try {
      setReceipt(await api.compatibilityCommand(execution.id, body));
      onRefresh();
    } catch {
      setError("Outcome not confirmed. Refresh the recorded operation or retry the same operation ID.");
    } finally { setBusy(false); }
  }

  function start(operation: CompatibilityOperation) {
    const body: CompatibilityRequest = {
      ...currentControlProof(execution.controller_lease), operation, operation_id: crypto.randomUUID(),
      source_digest: execution.source_digest!, expected_execution_revision: execution.revision, reason: reason.trim(),
    };
    // Retain the exact request across reconnect; never generate a new ID on retry.
    try { sessionStorage.setItem(storageKey, JSON.stringify(body)); }
    catch { setError("Cannot retain operation identity in this browser session."); return; }
    setRequest(body); setReceipt(null); void submit(body);
  }

  async function refresh() {
    if (!request) return;
    setBusy(true); setError(null);
    try { setReceipt(await api.compatibilityReceipt(execution.id, request.operation_id)); onRefresh(); }
    catch { setError("No authoritative outcome available. Retain this operation ID; no replacement was sent."); }
    finally { setBusy(false); }
  }

  return <details className="compatibility-control foundation-card">
    <summary>Compatibility control</summary>
    <p>Local simulator procedure control. The current controller lease is required.</p>
    <label htmlFor="compatibility-reason">Control reason</label>{" "}
    <input id="compatibility-reason" value={reason} maxLength={900}
      onChange={(event) => setReason(event.target.value)} disabled={busy || unresolved} />
    <div className="command-toolbar" aria-label="Compatibility operations">
      {(Object.keys(labels) as CompatibilityOperation[]).map((operation) => {
        const validState = operation === "RUN" || operation === "STEP" ? ["PAUSED", "INTERRUPTED"].includes(execution.state)
          : operation === "PAUSE" ? ["RUNNING", "WAITING", "PROMPT", "PROMPTING"].includes(execution.state)
          : !stopped.has(execution.state);
        const action = operation === "RETURN_TO_READ_ONLY" ? "ABORT" : operation;
        const allowed = execution.allowed_actions === undefined || execution.allowed_actions.includes(action);
        return <button key={operation} type="button" onClick={() => start(operation)}
          disabled={!permitted || !allowed || unresolved || !reason.trim() || !validState}>{labels[operation]}</button>;
      })}
    </div>
    {!ownsControl && <p>Monitor access: acquire control before issuing an operation.</p>}
    {request && <div>
      <p className="replay-digest">Operation ID: {request.operation_id}</p>
      <p role="status">{receipt ? receipt.read_only_confirmed ? "Read-only confirmed: procedure stopped."
        : receipt.rollback_pending ? "Return to read-only pending settlement."
        : `Operation ${receipt.command.state}${receipt.command.rejection_code ? `: ${receipt.command.rejection_code}` : ""}`
        : "Awaiting authoritative outcome."}</p>
      <button type="button" disabled={busy} onClick={() => void refresh()}>Refresh operation</button>{" "}
      {unresolved && <button type="button" disabled={!permitted} onClick={() => void submit(request)}>Retry same operation</button>}
    </div>}
    {error && <p role="alert">{error}</p>}
  </details>;
}
