import { CalendarClock, ChevronRight, CircleX, Command, LoaderCircle, Play, RefreshCcw, Save, Search, ToggleLeft, ToggleRight, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, currentControlProof, type ConsoleOperationInput } from "../api";
import { useAppDispatch, useAppSelector } from "../hooks";
import { openExecution } from "../store";
import type { ExecutionSchedule, InspectionValue, NamedUserAction, ParentChildLink } from "../types";
import { useActiveControlLease } from "../useControlLease";

function message(reason: unknown): string {
  return reason instanceof Error ? reason.message : "The server rejected the request.";
}

function parseLiteral(type: InspectionValue["type"], raw: string): unknown {
  if (type === "STRING") return raw;
  if (type === "NULL") {
    if (raw.trim().toLowerCase() !== "null") throw new Error("NULL requires the literal null.");
    return null;
  }
  if (type === "BOOLEAN") {
    if (!/^(true|false)$/i.test(raw.trim())) throw new Error("BOOLEAN requires true or false.");
    return raw.trim().toLowerCase() === "true";
  }
  if (type === "INTEGER") {
    if (!/^[+-]?\d+$/.test(raw.trim())) throw new Error("INTEGER requires a base-10 integer.");
    return Number(raw);
  }
  if (type === "FINITE_DECIMAL") {
    if (!/^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(raw.trim()) || !Number.isFinite(Number(raw))) throw new Error("FINITE_DECIMAL requires a finite base-10 value.");
    return Number(raw);
  }
  throw new Error(`${type} container replacement is not available in v0.6.`);
}

function valueText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function canEditInspectionValue(value?: InspectionValue): boolean {
  return Boolean(
    value?.editable &&
    value.scope !== "SHARED_DATA" &&
    !value.redacted &&
    !["LIST", "MAP"].includes(value.type),
  );
}

export function InspectionPanel() {
  const execution = useAppSelector((state) => state.console.execution);
  const [items, setItems] = useState<InspectionValue[]>([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const [consoleOperation, setConsoleOperation] = useState<ConsoleOperationInput["operation"]>("READ_VALUE");
  const [consoleQuery, setConsoleQuery] = useState("");
  const [consoleResult, setConsoleResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    if (!execution) return;
    setError(null);
    try {
      const loaded = await api.inspection(execution.id);
      setItems(loaded);
      const selected = loaded.find((item) => item.path === selectedPath) ?? loaded[0];
      if (selected) {
        setSelectedPath(selected.path);
        setDraft(valueText(selected.value));
      }
    } catch (reason) {
      setError(message(reason));
    }
  };

  useEffect(() => { void load(); }, [execution?.id]);
  const selected = items.find((item) => item.path === selectedPath);
  const filtered = useMemo(() => items.filter((item) => item.path.toLowerCase().includes(query.trim().toLowerCase())), [items, query]);
  const canControl = useActiveControlLease(execution);
  const safeEditState = execution ? ["PAUSED", "PROMPT", "PROMPTING", "INTERRUPTED"].includes(execution.state) : false;

  const save = async () => {
    if (!execution || !selected) return;
    if (!canEditInspectionValue(selected)) {
      setError("The selected value is read-only.");
      return;
    }
    setBusy(true); setError(null);
    try {
      const value = parseLiteral(selected.type, draft);
      const updated = await api.editInspection(execution.id, {
        path: selected.path,
        scope: selected.scope,
        type: selected.type,
        value,
        expected_value_revision: selected.value_revision,
        expected_execution_revision: execution.revision,
      }, currentControlProof(execution.controller_lease));
      setItems((current) => current.map((item) => item.path === updated.path ? updated : item));
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  };

  const runConsole = async () => {
    if (!execution) return;
    setBusy(true); setError(null);
    try {
      let input: ConsoleOperationInput;
      if (consoleOperation === "LIST_SCOPE") {
        if (!selected) throw new Error("Select a scope entry first.");
        input = { operation: consoleOperation, scope: selected.scope, expected_execution_revision: execution.revision };
      } else if (consoleOperation === "SEARCH_SOURCE_LITERAL") {
        if (!consoleQuery.trim()) throw new Error("Enter a bounded source literal query.");
        input = { operation: consoleOperation, query: consoleQuery.trim(), limit: 50, expected_execution_revision: execution.revision };
      } else if (consoleOperation === "WRITE_TYPED_LITERAL") {
        if (!selected || !canEditInspectionValue(selected)) throw new Error("Select an editable typed value first.");
        input = { operation: consoleOperation, path: selected.path, type: selected.type, value: parseLiteral(selected.type, draft), expected_execution_revision: execution.revision };
      } else {
        if (!selectedPath) throw new Error("Select a typed value first.");
        input = { operation: consoleOperation, path: selectedPath, expected_execution_revision: execution.revision };
      }
      const result = await api.consoleOperation(execution.id, input, consoleOperation === "WRITE_TYPED_LITERAL" ? currentControlProof(execution.controller_lease) : undefined);
      setConsoleResult(result);
      if (consoleOperation === "WRITE_TYPED_LITERAL") await load();
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  };

  if (!execution) return <div className="dock-empty">Open an execution to inspect its typed state.</div>;
  return (
    <div className="inspection-layout">
      <section className="inspection-browser" aria-labelledby="inspection-title">
        <div className="dock-panel-header"><h3 id="inspection-title">Typed inspection</h3><button type="button" className="icon-command" aria-label="Refresh inspection" title="Refresh inspection" onClick={() => void load()}><RefreshCcw aria-hidden="true" size={14} /></button></div>
        <label className="dock-search"><Search aria-hidden="true" size={13} /><span className="sr-only">Filter inspected values</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter paths" /></label>
        <div className="inspection-values" role="listbox" aria-label="Typed values">
          {filtered.map((item) => <button type="button" role="option" aria-selected={item.path === selectedPath} key={item.path} onClick={() => { setSelectedPath(item.path); setDraft(valueText(item.value)); }}><span><code>{item.path}</code><small>{item.scope} / {item.type} / rev {item.value_revision}</small></span><strong>{item.redacted ? "REDACTED" : valueText(item.value)}</strong></button>)}
          {!filtered.length && <p>No matching typed values.</p>}
        </div>
      </section>
      <section className="inspection-editor" aria-labelledby="typed-edit-title">
        <div className="dock-panel-header"><div><h3 id="typed-edit-title">Safe-state edit</h3><span>{execution.state} / {canControl ? "Controller" : "Monitor"}</span></div></div>
        {selected ? <>
          <dl className="inspection-meta"><div><dt>Path</dt><dd><code>{selected.path}</code></dd></div><div><dt>Scope</dt><dd>{selected.scope}</dd></div><div><dt>Type</dt><dd>{selected.type}</dd></div><div><dt>Revision</dt><dd>{selected.value_revision}</dd></div></dl>
          <label className="typed-value-input">Typed literal<input value={draft} onChange={(event) => setDraft(event.target.value)} disabled={!canEditInspectionValue(selected)} /></label>
          <button type="button" className="primary-command compact-primary" onClick={() => void save()} disabled={busy || !canControl || !safeEditState || !canEditInspectionValue(selected)}>{busy ? <LoaderCircle className="spin" aria-hidden="true" size={14} /> : <Save aria-hidden="true" size={14} />} Commit audited edit</button>
        </> : <p className="dock-note">Select a typed value.</p>}
        <div className="bounded-console">
          <div className="dock-panel-header"><h3>Bounded console</h3></div>
          <div className={`console-command-row ${consoleOperation === "SEARCH_SOURCE_LITERAL" ? "has-query" : ""}`}><select aria-label="Bounded console operation" value={consoleOperation} onChange={(event) => setConsoleOperation(event.target.value as typeof consoleOperation)}><option value="LIST_SCOPE">List scope</option><option value="READ_VALUE">Read value</option><option value="EXPAND_VALUE">Expand value</option><option value="SEARCH_SOURCE_LITERAL">Search source literal</option><option value="WRITE_TYPED_LITERAL">Write typed literal</option></select>{consoleOperation === "SEARCH_SOURCE_LITERAL" && <input aria-label="Source literal query" value={consoleQuery} onChange={(event) => setConsoleQuery(event.target.value)} maxLength={200} placeholder="Literal text" />}<button type="button" className="icon-command" aria-label="Run bounded console operation" title="Run operation" onClick={() => void runConsole()} disabled={busy || (consoleOperation === "SEARCH_SOURCE_LITERAL" ? !consoleQuery.trim() : !selected) || (consoleOperation === "WRITE_TYPED_LITERAL" && (!canControl || !safeEditState || !canEditInspectionValue(selected)))}><Command aria-hidden="true" size={14} /></button></div>
          <pre aria-live="polite">{consoleResult == null ? "No operation result." : JSON.stringify(consoleResult, null, 2)}</pre>
        </div>
        {error && <p className="dock-error" role="alert">{error}</p>}
      </section>
    </div>
  );
}

export function SchedulesPanel() {
  const { execution, selectedProcedureId, contextId, connection } = useAppSelector((state) => state.console);
  const [items, setItems] = useState<ExecutionSchedule[]>([]);
  const [type, setType] = useState<"RELATIVE" | "ABSOLUTE">("RELATIVE");
  const [target, setTarget] = useState("60");
  const [automatic, setAutomatic] = useState(true);
  const [background, setBackground] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const proof = currentControlProof(execution?.controller_lease);
  const canControl = useActiveControlLease(execution);
  const load = async () => {
    if (!execution) return;
    try { setItems(await api.schedules(execution.id)); setError(null); } catch (reason) { setError(message(reason)); }
  };
  useEffect(() => { setItems(execution?.schedules ?? []); }, [execution?.id, execution?.schedules]);
  useEffect(() => {
    void load();
    if (connection.phase !== "CONNECTED") return;
    const timer = window.setInterval(() => void load(), 5_000);
    return () => window.clearInterval(timer);
  }, [connection.phase, execution?.id]);

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!execution || !selectedProcedureId) return;
    setBusy(true); setError(null);
    try {
      const originalTarget = type === "RELATIVE" ? Number(target) : target.trim();
      if (type === "RELATIVE" && (!Number.isFinite(Number(target)) || Number(target) <= 0)) throw new Error("Relative delay must be a positive number of seconds.");
      if (type === "ABSOLUTE" && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/.test(String(originalTarget))) throw new Error("Absolute target must be RFC 3339 with an explicit UTC offset.");
      const created = await api.createSchedule({ controller_execution_id: execution.id, schedule_type: type, target: originalTarget, procedure_catalog_id: selectedProcedureId, context_id: contextId, automatic, background_allowed: background, expected_execution_revision: execution.revision, proof });
      setItems((current) => [created, ...current.filter((item) => item.id !== created.id)]);
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  };
  const cancel = async (item: ExecutionSchedule) => {
    setBusy(true); setError(null);
    try { const updated = await api.cancelSchedule(item.id, item.revision, proof); setItems((current) => current.map((candidate) => candidate.id === updated.id ? updated : candidate)); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  };
  return (
    <div className="schedule-layout">
      <form className="schedule-form" onSubmit={create}>
        <div className="dock-panel-header"><h3>One-shot schedule</h3><CalendarClock aria-hidden="true" size={16} /></div>
        <div className="segmented-control"><button type="button" aria-pressed={type === "RELATIVE"} onClick={() => { setType("RELATIVE"); setTarget("60"); }}>Relative</button><button type="button" aria-pressed={type === "ABSOLUTE"} onClick={() => { setType("ABSOLUTE"); setTarget(""); }}>Absolute</button></div>
        <label>{type === "RELATIVE" ? "Delay (seconds)" : "RFC 3339 target"}<input value={target} onChange={(event) => setTarget(event.target.value)} inputMode={type === "RELATIVE" ? "numeric" : undefined} placeholder={type === "ABSOLUTE" ? "2026-08-16T01:30:00-04:00" : undefined} /></label>
        <label className="compact-check"><input type="checkbox" checked={automatic} onChange={(event) => { setAutomatic(event.target.checked); if (event.target.checked) setBackground(true); }} /> Automatic</label>
        <label className="compact-check"><input type="checkbox" checked={background} onChange={(event) => setBackground(event.target.checked)} disabled={automatic} /> Background allowed</label>
        <button type="submit" className="primary-command compact-primary" disabled={!canControl || busy || !selectedProcedureId}>{busy ? <LoaderCircle className="spin" aria-hidden="true" size={14} /> : <CalendarClock aria-hidden="true" size={14} />} Create schedule</button>
        {error && <p className="dock-error" role="alert">{error}</p>}
      </form>
      <div className="table-scroll schedule-table" tabIndex={0}><table><thead><tr><th>Schedule</th><th>Type</th><th>Target UTC</th><th>Procedure</th><th>State</th><th><span className="sr-only">Cancel</span></th></tr></thead><tbody>
        {items.map((item) => <tr key={item.id}><td><code title={item.id}>{item.id.slice(0, 12)}</code></td><td>{item.schedule_type}</td><td>{item.target_at_database_time}</td><td><code>{item.catalog_revision_id}</code></td><td><span className={`schedule-state ${item.state.toLowerCase()}`}>{item.state}</span></td><td><button type="button" className="icon-command" aria-label={`Cancel schedule ${item.id}`} title="Cancel schedule" onClick={() => void cancel(item)} disabled={!canControl || busy || item.state !== "PENDING"}><Trash2 aria-hidden="true" size={14} /></button></td></tr>)}
        {!items.length && <tr><td colSpan={6}>No schedules.</td></tr>}
      </tbody></table></div>
    </div>
  );
}

export function ActionsPanel() {
  const execution = useAppSelector((state) => state.console.execution);
  const [items, setItems] = useState<NamedUserAction[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canControl = useActiveControlLease(execution);
  const allowedState = execution ? ["PAUSED", "RUNNING", "WAITING", "PROMPT", "PROMPTING", "INTERRUPTED"].includes(execution.state) : false;
  const load = async () => { if (!execution) return; try { setItems(await api.actions(execution.id)); setError(null); } catch (reason) { setError(message(reason)); } };
  useEffect(() => { void load(); }, [execution?.id]);
  const invoke = async (action: NamedUserAction) => {
    if (!execution) return;
    setBusy(`${action.id}:INVOKE`); setError(null);
    try { await api.invokeAction(execution.id, action, execution.revision, currentControlProof(execution.controller_lease)); await load(); }
    catch (reason) { setError(message(reason)); } finally { setBusy(null); }
  };
  const mutate = async (action: NamedUserAction, operation: "ENABLE" | "DISABLE" | "DISMISS") => {
    if (!execution) return;
    setBusy(`${action.id}:${operation}`); setError(null);
    try {
      const updated = await api.mutateAction(execution.id, action, operation, execution.revision, currentControlProof(execution.controller_lease));
      setItems((current) => current.map((candidate) => candidate.id === updated.id ? updated : candidate));
    } catch (reason) { setError(message(reason)); } finally { setBusy(null); }
  };
  return <div className="actions-panel"><div className="dock-panel-header"><div><h3>Named user actions</h3><span>{items.length} allowlisted</span></div><button type="button" className="icon-command" aria-label="Refresh named actions" title="Refresh actions" onClick={() => void load()}><RefreshCcw aria-hidden="true" size={14} /></button></div><div className="action-list">
    {items.map((action) => <div key={action.id}><span className={`action-severity ${action.severity.toLowerCase()}`}>{action.severity}</span><span><strong>{action.label}</strong><small><code>{action.name}</code> / rev {action.revision}{action.dismissed ? " / DISMISSED" : action.last_settlement ? ` / ${action.last_settlement}` : ""}</small></span><div className="action-controls">
      <button type="button" className="icon-command" aria-label={`${action.enabled ? "Disable" : "Enable"} ${action.label}`} title={`${action.enabled ? "Disable" : "Enable"} action`} aria-pressed={action.enabled} onClick={() => void mutate(action, action.enabled ? "DISABLE" : "ENABLE")} disabled={!canControl || action.dismissed || busy !== null}>{busy === `${action.id}:${action.enabled ? "DISABLE" : "ENABLE"}` ? <LoaderCircle className="spin" aria-hidden="true" size={14} /> : action.enabled ? <ToggleRight aria-hidden="true" size={15} /> : <ToggleLeft aria-hidden="true" size={15} />}</button>
      <button type="button" className="icon-command" aria-label={`Dismiss ${action.label}`} title="Dismiss action" onClick={() => void mutate(action, "DISMISS")} disabled={!canControl || action.dismissed || busy !== null}>{busy === `${action.id}:DISMISS` ? <LoaderCircle className="spin" aria-hidden="true" size={14} /> : <CircleX aria-hidden="true" size={14} />}</button>
      <button type="button" className="toolbar-command" onClick={() => void invoke(action)} disabled={!canControl || !allowedState || !action.enabled || action.dismissed || busy !== null}>{busy === `${action.id}:INVOKE` ? <LoaderCircle className="spin" aria-hidden="true" size={14} /> : <Play aria-hidden="true" size={14} />}<span>Invoke</span></button>
    </div></div>)}
    {!items.length && <p className="dock-note">No named actions are registered.</p>}
  </div>{error && <p className="dock-error" role="alert">{error}</p>}</div>;
}

export function RelationshipsPanel() {
  const dispatch = useAppDispatch();
  const execution = useAppSelector((state) => state.console.execution);
  const connection = useAppSelector((state) => state.console.connection.phase);
  const [items, setItems] = useState<ParentChildLink[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setItems(execution?.relationships ?? []); }, [execution?.id, execution?.relationships]);
  useEffect(() => {
    if (!execution) return;
    const load = () => void api.relationships(execution.id).then(setItems).catch((reason: unknown) => setError(message(reason)));
    load();
    if (connection !== "CONNECTED") return;
    const timer = window.setInterval(load, 5_000);
    return () => window.clearInterval(timer);
  }, [connection, execution?.id]);
  if (!execution) return <div className="dock-empty">Open an execution to inspect procedure relationships.</div>;
  return <div className="relationship-panel"><div className="dock-panel-header"><div><h3>Parent and child procedures</h3><span>Depth {execution.depth ?? 0} / limit 8</span></div></div><div className="relationship-tree">
    {items.map((link) => <div key={link.id} className={link.child_execution_id === execution.id ? "current" : undefined}><button type="button" onClick={() => void dispatch(openExecution(link.parent_execution_id))}><span>Parent</span><code title={link.parent_execution_id}>{link.parent_execution_id}</code></button><ChevronRight aria-hidden="true" size={15} /><span className="relationship-mode">{link.blocking ? "Blocking" : "Nonblocking"} / {link.visible ? "Visible" : "Hidden"}</span><ChevronRight aria-hidden="true" size={15} /><button type="button" onClick={() => void dispatch(openExecution(link.child_execution_id))}><span>Child</span><code title={link.child_execution_id}>{link.child_execution_id}</code></button><small>Catalog revision <code>{link.child_catalog_revision_id}</code></small></div>)}
    {!items.length && <p className="dock-note">This execution has no parent or child relationships.</p>}
  </div>{error && <p className="dock-error" role="alert">{error}</p>}</div>;
}
