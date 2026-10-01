import { useEffect, useRef, useState } from "react";
import { accessTokenSubject, api, ApiError } from "../api";
import { canMutateData, currentDataRole } from "../dataApi";

export interface PilotPlan { items: string[]; value_format: "RAW" | "ENG"; repetitions: number }
export interface PilotSummary {
  id: string; creator: string; state: string; revision: number; report_sha256: string;
  route: string; read_only: boolean; local_review_recorded: boolean; operational_authorization: boolean;
}
export interface PilotDetail extends PilotSummary {
  plan: PilotPlan;
  report: { equivalent: boolean; budget_passed: boolean; elapsed_seconds: number;
    rows: Array<{ repetition: number; comparison: { item_id: string; classification: string; differences: string[] } }> };
  events: Array<{ operation_id: string; action: string; actor: string; reason: string; created_at: string }>;
}
export interface PilotCreate { operation_id: string; reason: string; plan: PilotPlan }
export interface PilotAction { operation_id: string; reason: string; action: "REVIEW" | "INCIDENT" | "ROLLBACK"; expected_revision: number }
export interface PilotRestore { operation_id: string; reason: string; backup: Record<string, unknown> }
type Pending = { kind: "CREATE"; body: PilotCreate } | { kind: "ACTION"; id: string; body: PilotAction } | { kind: "RESTORE"; body: PilotRestore };

function Workspace() {
  const storage = `openbexi.spell.pilot.pending.${accessTokenSubject()}`;
  const [pending, setPending] = useState<Pending | null>(() => {
    try { return JSON.parse(sessionStorage.getItem(storage) ?? "null") as Pending | null; } catch { return null; }
  });
  const [runs, setRuns] = useState<PilotSummary[]>([]);
  const [run, setRun] = useState<PilotDetail | null>(null);
  const [reason, setReason] = useState("");
  const [items, setItems] = useState("TEMP,MODE,COUNTER");
  const [repetitions, setRepetitions] = useState(1);
  const [format, setFormat] = useState<"RAW" | "ENG">("ENG");
  const [backup, setBackup] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  const role = currentDataRole();
  const mutate = canMutateData(role) && !busy && !pending && Boolean(reason.trim());
  useEffect(() => {
    let active = true;
    void api.pilotList().then((value) => { if (active) setRuns(value.items); })
      .catch(() => { if (active) setError("Unable to load shadow reports."); });
    return () => { active = false; generation.current++; };
  }, []);
  function retain(value: Pending | null) {
    setPending(value);
    if (value) sessionStorage.setItem(storage, JSON.stringify(value));
    else sessionStorage.removeItem(storage);
  }
  async function load(id: string) {
    const revision = ++generation.current;
    setError(""); setBusy(true); setRun(null);
    try {
      const detail = await api.pilotGet(id);
      if (revision === generation.current) {
        setRun(detail);
        if (pending && detail.events.some((event) => event.operation_id === pending.body.operation_id)) retain(null);
      }
    } catch { if (revision === generation.current) setError("Report unavailable. The pending request is retained."); }
    finally { if (revision === generation.current) setBusy(false); }
  }
  async function submit(value: Pending) {
    retain(value); setBusy(true); setError("");
    try {
      const receipt = value.kind === "CREATE" ? await api.pilotCreate(value.body) : value.kind === "ACTION" ?
        await api.pilotAction(value.id, value.body) : await api.pilotRestore(value.body);
      const [detail, listing] = await Promise.all([api.pilotGet(receipt.id), api.pilotList()]);
      retain(null);
      setRun(detail); setRuns(listing.items);
    } catch (failure) {
      if (failure instanceof ApiError && [400, 403, 404, 409, 422, 429].includes(failure.status)) {
        retain(null); setError(failure.message);
      } else setError("Outcome not confirmed. Read the recorded run or retry the same request.");
    } finally { setBusy(false); }
  }
  function action(kind: PilotAction["action"]) {
    if (run) void submit({ kind: "ACTION", id: run.id, body: { operation_id: crypto.randomUUID(), expected_revision: run.revision, action: kind, reason } });
  }
  async function exportBackup() {
    if (!run) return;
    setError(""); setBusy(true);
    try { setBackup(JSON.stringify(await api.pilotBackup(run.id), null, 2)); }
    catch { setError("Backup unavailable."); }
    finally { setBusy(false); }
  }
  function restore() {
    try {
      if (new TextEncoder().encode(backup).length > 262144) throw new Error();
      const value: unknown = JSON.parse(backup);
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
      void submit({ kind: "RESTORE", body: { operation_id: crypto.randomUUID(), reason, backup: value as Record<string, unknown> } });
    } catch { setError("Enter a valid backup JSON object of at most 256 KiB."); }
  }
  return <div>
    <p>Local synthetic shadow readiness. Every run is read-only; review records no operational approval.</p>
    <p><label>Pilot telemetry items <input value={items} maxLength={512} disabled={busy || Boolean(pending)} onChange={(e) => setItems(e.target.value)} /></label></p>
    <p><label>Pilot repetitions <input type="number" min={1} max={4} value={repetitions} disabled={busy || Boolean(pending)} onChange={(e) => setRepetitions(Number(e.target.value))} /></label>{" "}
      <label>Pilot value format <select value={format} disabled={busy || Boolean(pending)} onChange={(e) => setFormat(e.target.value as typeof format)}><option>ENG</option><option>RAW</option></select></label></p>
    <p><label>Pilot action reason <input value={reason} maxLength={900} disabled={busy} onChange={(e) => setReason(e.target.value)} /></label></p>
    <button disabled={!mutate || !items.trim() || !Number.isInteger(repetitions) || repetitions < 1 || repetitions > 4}
      onClick={() => void submit({ kind: "CREATE", body: { operation_id: crypto.randomUUID(), reason, plan: {
        items: items.split(",").map((item) => item.trim()), repetitions, value_format: format } } })}>Run read-only shadow</button>
    {pending && <div aria-label="Pending pilot request"><p>Unconfirmed {pending.kind.toLowerCase()} request retained.</p>
      <button disabled={busy || !canMutateData(role)} onClick={() => void submit(pending)}>Retry same pilot request</button>{" "}
      <button disabled={busy} onClick={() => void load(pending.kind === "ACTION" ? pending.id : pending.body.operation_id)}>Read recorded pilot run</button></div>}
    <p><label>Recent shadow runs <select value={run?.id ?? ""} disabled={busy} onChange={(e) => { if (e.target.value) void load(e.target.value); }}>
      <option value="">Select a report</option>{runs.map((item) => <option key={item.id} value={item.id}>{item.id.slice(0, 8)} · {item.state}</option>)}
    </select></label>{" "}<button disabled={busy} onClick={() => {
      setError(""); void api.pilotList().then((value) => setRuns(value.items)).catch(() => setError("Unable to load shadow reports."));
    }}>Refresh shadow reports</button></p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Loading shadow evidence…</p>}
    {run && <div aria-label="Pilot report">
      <p role="status">State: {run.state} · revision {run.revision} · {run.route}</p>
      <p>Owner: {run.creator}. Local review recorded: {run.local_review_recorded ? "Yes" : "No"}. Operational authorization: None.</p>
      <p>Comparisons: {run.report.rows.length}. Equivalent: {run.report.equivalent ? "Yes" : "No"}. Workload budget: {run.report.budget_passed ? "PASS" : "FAIL"}.</p>
      <p className="replay-digest">Report SHA-256: {run.report_sha256}</p>
      <p><button disabled={!mutate || role !== "admin" || run.creator === accessTokenSubject() || run.state !== "PENDING_REVIEW" || !run.report.equivalent || !run.report.budget_passed} onClick={() => action("REVIEW")}>Record independent review</button>{" "}
        <button disabled={!mutate || (role !== "admin" && run.creator !== accessTokenSubject())} onClick={() => action("INCIDENT")}>Record incident</button>{" "}
        <button disabled={!mutate || (role !== "admin" && run.creator !== accessTokenSubject())} onClick={() => action("ROLLBACK")}>Roll back to simulator</button>{" "}
        <button disabled={busy} onClick={() => void exportBackup()}>Prepare backup</button></p>
      <details><summary>Differential trace and audit</summary>
        <div className="foundation-table-scroll" tabIndex={0} role="region" aria-label="Pilot differential trace"><table><thead><tr><th>Repeat</th><th>Item</th><th>Classification</th><th>Differences</th></tr></thead>
          <tbody>{run.report.rows.map((row, index) => <tr key={index}><td>{row.repetition}</td><th scope="row">{row.comparison.item_id}</th><td>{row.comparison.classification}</td><td>{row.comparison.differences.join(", ") || "None"}</td></tr>)}</tbody></table></div>
        <ul>{run.events.map((event) => <li key={event.operation_id}>{event.action} · {event.actor} · {event.reason}</li>)}</ul>
      </details>
    </div>}
    <details><summary>Backup and restore drill</summary><p>Copy this data-only backup for later recovery. Restore always creates a new read-only report and cannot reinstate review.</p>
      <label>Pilot backup JSON<textarea style={{ width: "100%", boxSizing: "border-box" }} rows={6} maxLength={262144} value={backup} onChange={(e) => setBackup(e.target.value)} /></label>
      <button disabled={!mutate || role !== "admin" || !backup.trim()} onClick={restore}>Restore as read-only</button>
    </details>
  </div>;
}

export function ShadowPilot() {
  const [open, setOpen] = useState(false);
  return <details className="foundation-card shadow-pilot" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>Shadow pilot readiness</summary>{open && <Workspace />}
  </details>;
}
