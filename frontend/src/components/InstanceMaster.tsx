import { Eye, RefreshCcw, Search, Workflow } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { openExecution, refreshMaster } from "../store";
import type { ExecutionSummary } from "../types";

function formatAge(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function executionTone(state: ExecutionSummary["state"]): string {
  if (state === "RUNNING") return "running";
  if (["PAUSED", "WAITING", "PROMPT", "PROMPTING", "INTERRUPTED"].includes(state)) return "attention";
  if (["ERROR", "FAILED", "ABORTED", "SUSPENDED", "RECOVERY_REQUIRED"].includes(state)) return "danger";
  if (["FINISHED", "COMPLETED"].includes(state)) return "complete";
  return "neutral";
}

export function InstanceMaster() {
  const dispatch = useAppDispatch();
  const { executions, selectedExecutionId, connection, pendingAction } = useAppSelector((state) => state.console);
  const [query, setQuery] = useState("");
  const [showTerminal, setShowTerminal] = useState(false);

  useEffect(() => {
    if (connection.phase !== "CONNECTED") return;
    const timer = window.setInterval(() => void dispatch(refreshMaster()), 5_000);
    return () => window.clearInterval(timer);
  }, [connection.phase, dispatch]);

  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return executions.filter((item) => {
      const terminal = ["FINISHED", "COMPLETED", "ABORTED", "ERROR", "FAILED"].includes(item.state);
      if (!showTerminal && terminal) return false;
      return !normalized || `${item.id} ${item.procedure_name} ${item.context_id} ${item.state}`.toLowerCase().includes(normalized);
    });
  }, [executions, query, showTerminal]);

  return (
    <section className="instance-master" aria-labelledby="master-title">
      <div className="master-header">
        <div className="master-title">
          <Workflow aria-hidden="true" size={16} />
          <div><span className="eyebrow">Simulator context</span><h2 id="master-title">Master</h2></div>
          <span className="count-label">{filtered.length}</span>
        </div>
        <div className="master-tools">
          <label className="master-search">
            <Search aria-hidden="true" size={14} />
            <span className="sr-only">Filter execution instances</span>
            <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter instances" />
          </label>
          <label className="compact-check"><input type="checkbox" checked={showTerminal} onChange={(event) => setShowTerminal(event.target.checked)} /> Terminal</label>
          <button type="button" className="icon-command" aria-label="Refresh Master" title="Refresh Master" onClick={() => void dispatch(refreshMaster())} disabled={connection.phase !== "CONNECTED"}>
            <RefreshCcw aria-hidden="true" size={14} />
          </button>
        </div>
      </div>
      <div className="master-table-scroll" tabIndex={0} aria-label="Scrollable Master execution table">
        <table>
          <thead><tr><th>Instance</th><th>Procedure</th><th>Context</th><th>State</th><th>Mode</th><th>Control</th><th>Updated</th><th><span className="sr-only">Open</span></th></tr></thead>
          <tbody>
            {filtered.map((item) => (
              <tr key={item.id} className={item.id === selectedExecutionId ? "selected" : undefined}>
                <td><code title={item.id}>{item.id}</code>{item.parent_execution_id && <small className="parent-marker">child</small>}</td>
                <td><strong>{item.procedure_name}</strong></td>
                <td>{item.context_id}</td>
                <td><span className={`state-pill compact ${executionTone(item.state)}`}>{item.state}</span></td>
                <td><span className={`mode-badge mode-${item.ownership_mode.toLowerCase()}`}>{item.ownership_mode}</span></td>
                <td>{item.controller_lease?.holder_subject_id ?? (item.ownership_mode === "B" ? "Service" : "None")}{item.monitor_count ? ` +${item.monitor_count} M` : ""}</td>
                <td>{formatAge(item.updated_at)}</td>
                <td><button type="button" className="icon-command" aria-label={`Open ${item.procedure_name} ${item.id}`} title="Open execution" disabled={pendingAction !== null} onClick={() => void dispatch(openExecution(item.id))}><Eye aria-hidden="true" size={14} /></button></td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={8} className="master-empty">No execution instances match this view.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}
