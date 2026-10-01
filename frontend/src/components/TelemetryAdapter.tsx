import { useEffect, useRef, useState } from "react";
import { api } from "../api";

export interface AdapterRead {
  source: { source_id: string; digest: string; live: boolean };
  item_id: string;
  outcome: string;
  cursor: string | null;
  value: { type: string; value: unknown } | null;
  sample: { raw: { value: unknown } | null; eng: { value: unknown } | null; time_ns: string;
    unit: string; quality: string; validity: string } | null;
}
export interface AdapterComparison {
  classification: string;
  differences: string[];
  reference: AdapterRead;
  simulator: AdapterRead;
}
export interface AdapterOptions {
  value_format: "RAW" | "ENG";
  extended: boolean;
  wait?: boolean;
  after?: string;
  timeout_ms?: number;
}

function Inspector() {
  const [source, setSource] = useState<"reference" | "simulator">("reference");
  const [items, setItems] = useState<string[]>([]);
  const [item, setItem] = useState("TEMP");
  const [format, setFormat] = useState<"RAW" | "ENG">("ENG");
  const [extended, setExtended] = useState(true);
  const [result, setResult] = useState<AdapterRead | null>(null);
  const [comparison, setComparison] = useState<AdapterComparison | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [catalogRevision, setCatalogRevision] = useState(0);
  const generation = useRef(0);
  useEffect(() => {
    const revision = ++generation.current;
    setItems([]); setResult(null); setComparison(null); setCursor(null); setError(false); setBusy(true);
    void api.telemetryAdapterCatalog(source).then((catalog) => {
      if (revision === generation.current) {
        setItems(catalog.items.map((row) => row.item_id));
        setCursor(catalog.initial_cursor);
      }
    }).catch(() => { if (revision === generation.current) setError(true); })
      .finally(() => { if (revision === generation.current) setBusy(false); });
    return () => { generation.current++; };
  }, [source, catalogRevision]);
  function clear() { generation.current++; setResult(null); setComparison(null); setError(false); setBusy(false); }
  async function read(next: boolean) {
    const revision = ++generation.current;
    setBusy(true); setError(false); setResult(null); setComparison(null);
    try {
      const value = await api.telemetryAdapterRead(source, item, {
        value_format: format, extended, ...(next && cursor ? { wait: true, after: cursor, timeout_ms: 60000 } : {}),
      });
      if (revision === generation.current) { setResult(value); if (value.cursor) setCursor(value.cursor); }
    } catch { if (revision === generation.current) setError(true); }
    finally { if (revision === generation.current) setBusy(false); }
  }
  async function compare() {
    const revision = ++generation.current;
    setBusy(true); setError(false); setComparison(null); setResult(null);
    try {
      const value = await api.telemetryAdapterCompare(item, format);
      if (revision === generation.current) setComparison(value);
    } catch { if (revision === generation.current) setError(true); }
    finally { if (revision === generation.current) setBusy(false); }
  }
  return <div>
    <p>Read-only GetTM adapter. Synthetic archived data uses recorded logical time. No live connection.</p>
    <p><label>Adapter source <select value={source} onChange={(e) => setSource(e.target.value as typeof source)}>
      <option value="reference">Reference capture</option><option value="simulator">Simulator fallback</option>
    </select></label>{" "}<button disabled={busy} onClick={() => setCatalogRevision((value) => value + 1)}>Refresh adapter catalog</button></p>
    <p><label>Telemetry item <select value={item} disabled={busy || !items.length} onChange={(e) => { clear(); setItem(e.target.value); }}>
      {items.map((name) => <option key={name}>{name}</option>)}
    </select></label>{" "}
    <label>Value format <select value={format} disabled={busy} onChange={(e) => { clear(); setFormat(e.target.value as typeof format); }}>
      <option>ENG</option><option>RAW</option>
    </select></label></p>
    <p><label><input type="checkbox" disabled={busy} checked={extended} onChange={(e) => { clear(); setExtended(e.target.checked); }} /> Extended metadata</label></p>
    <p><button disabled={busy || !items.length} onClick={() => void read(false)}>Read current</button>{" "}
      <button disabled={busy || !cursor || !items.length} onClick={() => void read(true)}>Read next recorded sample</button>{" "}
      <button disabled={busy || !items.length} onClick={() => void compare()}>Compare both sources</button></p>
    {busy && <p role="status">Reading archived telemetry…</p>}
    {error && <p role="alert">Adapter unavailable. Retry the read or select the simulator fallback.</p>}
    {result && <div aria-label="Adapter result">
      <p role="status">{result.item_id}: {result.outcome} · {result.source.source_id}</p>
      <p>Value: {result.value ? `${String(result.value.value)} (${result.value.type})` : "Unavailable"}</p>
      {result.sample && <dl><dt>Raw / engineering</dt><dd>{String(result.sample.raw?.value ?? "Unavailable")} / {String(result.sample.eng?.value ?? "Unavailable")}</dd>
        <dt>Validity / quality</dt><dd>{result.sample.validity} / {result.sample.quality}</dd>
        <dt>Recorded time (ns)</dt><dd>{result.sample.time_ns}</dd><dt>Unit</dt><dd>{result.sample.unit || "None"}</dd></dl>}
    </div>}
    {comparison && <div aria-label="Adapter comparison"><p role="status">Comparison: {comparison.classification}</p>
      <p>{comparison.reference.source.source_id} ↔ {comparison.simulator.source.source_id}</p>
      <p>Differences: {comparison.differences.join(", ") || "None"}. Non-good observations cannot establish equivalence.</p></div>}
  </div>;
}

export function TelemetryAdapter() {
  const [open, setOpen] = useState(false);
  return <details className="foundation-card telemetry-adapter" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>Telemetry adapter</summary>{open && <Inspector />}
  </details>;
}
