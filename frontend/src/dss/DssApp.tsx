import { useCallback, useEffect, useRef, useState } from "react";
import { dssApi, type DssState, type DssTelemetry } from "./api";
import { DssCommandForm } from "./DssCommandForm";

function scalar(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.map((item: unknown) => {
    if (item && typeof item === "object" && "name" in item && "value" in item) return `${String(item.name)}=${scalar(item.value)}`;
    return scalar(item);
  }).join(", ") : "None";
  if (typeof value === "object" && "value" in value) return scalar(value.value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  return typeof value === "string" || typeof value === "number" ? String(value) : "Unavailable";
}
function label(key: string): string {
  return key.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
function acquired(value: string | number | undefined): string {
  const millis = Number(value) / 1_000_000;
  if (!Number.isFinite(millis) || millis < 0 || millis > 8.64e15) return "Unavailable";
  return new Date(millis).toISOString();
}
function StateTable({ name, values }: { name: string; values: DssState["core"] }) {
  const hidden = new Set(["energy_remainder_mw_ticks", "clock_epoch_unix_ns", "nominal_bus_voltage_mv"]);
  const units: Record<string, string> = { battery_mwh: "Battery (mWh)", bus_voltage_mv: "Bus voltage (mV)",
    load_mw: "Load (mW)", generated_mw: "Generation (mW)", temperature_mc: "Temperature (m°C)",
    setpoint_milli: "Setpoint (milliunits)", sim_time_ns: "Simulation time (ns)" };
  return <section className="dss-subsystem"><h2>{name}</h2><table aria-label={`${name} state`}>
    <thead><tr><th scope="col">Parameter</th><th scope="col">Value</th></tr></thead>
    <tbody>{Object.entries(values).filter(([key]) => !hidden.has(key)).map(([key, value]) => <tr key={key}><th scope="row">{units[key] ?? label(key)}</th><td title={scalar(value)}>{scalar(value)}</td></tr>)}</tbody>
  </table></section>;
}

export function DssApp() {
  const [state, setState] = useState<DssState | null>(null);
  const [telemetry, setTelemetry] = useState<DssTelemetry | null>(null);
  const [tab, setTab] = useState<"satellite" | "telemetry">("satellite");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const mounted = useRef(false);
  const generation = useRef(0);
  const fetching = useRef(false);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const refresh = useCallback(async () => {
    if (fetching.current) return;
    fetching.current = true;
    const request = ++generation.current;
    try {
      const [nextState, nextTelemetry] = await Promise.all([dssApi.state(), dssApi.telemetry()]);
      if (!mounted.current || request !== generation.current) return;
      setState(nextState); setTelemetry(nextTelemetry); setError(null);
    } catch {
      if (mounted.current && request === generation.current) setError("DSS is unavailable. Displayed values are stale; controls are disabled.");
    } finally { fetching.current = false; }
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1000);
    return () => { mounted.current = false; generation.current += 1; window.clearInterval(timer); };
  }, [refresh]);
  async function control(action: "PAUSE" | "RESUME" | "STEP") {
    if (!state || busy || error) return;
    setBusy(true); setNotice(""); generation.current += 1;
    try {
      const next = await dssApi.control(action, state);
      if (mounted.current) {
        setState(next);
        setNotice(`${action === "STEP" ? "Advanced one tick" : action === "PAUSE" ? "Simulation paused" : "Simulation running"}. Revision ${next.revision}.`);
      }
      await refresh();
    } catch (failure) {
      if (mounted.current) setNotice(failure instanceof Error && /FENCE|CONFLICT|EPOCH|REVISION/.test(failure.message)
        ? "State changed before the action. Refreshed current state; review it before trying again."
        : "Action was not confirmed. Refresh the state before trying again.");
      await refresh();
    } finally { if (mounted.current) setBusy(false); }
  }
  const synchronized = telemetry?.epoch === state?.epoch;
  const samples = synchronized ? (telemetry?.samples ?? []).filter((sample) => sample.item_id.toLowerCase().includes(filter.toLowerCase())) : [];
  return <div className="dss-shell">
    <header className="dss-header"><h1>DSS <span>GENERIC satellite</span></h1><a href="/">SPELL console</a></header>
    <div className="dss-status" aria-label="Simulator status"><strong>{error ? "STALE" : state ? state.running ? "RUNNING" : "PAUSED" : "CONNECTING"}</strong>
      <span>Local simulation</span><span>Kafka: {state?.transport?.publisher ?? "connecting"}</span><span>Revision: {state?.revision ?? "—"}</span>
      <button type="button" onClick={() => void refresh()}>Refresh</button>
    </div>
    {error && <p className="dss-error" role="alert">{error}</p>}
    {state?.transport?.outbox?.backpressure && <p className="dss-error" role="alert">Telemetry outbox is full. Automatic dynamics are held until Kafka acknowledges the pending packets; no recorded packet is dropped.</p>}
    <nav className="dss-tabs" aria-label="DSS views"><div role="tablist" aria-label="Simulator pages">
      {(["satellite", "telemetry"] as const).map((value, index) => <button type="button" key={value} ref={(element) => { tabRefs.current[index] = element; }}
        role="tab" id={`tab-${value}`} aria-selected={tab === value} aria-controls={`panel-${value}`} tabIndex={tab === value ? 0 : -1}
        onClick={() => setTab(value)} onKeyDown={(event) => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
          event.preventDefault(); const target = event.key === "Home" ? 0 : event.key === "End" ? 1 : 1 - index;
          setTab(target === 0 ? "satellite" : "telemetry"); tabRefs.current[target]?.focus();
        }}>{label(value)}</button>)}
    </div></nav>
    <main>
      {tab === "satellite" ? <section id="panel-satellite" role="tabpanel" aria-labelledby="tab-satellite">
        <div className="dss-controls" aria-label="Simulation controls">
          <button disabled={!state || !!error || busy || !state.running} onClick={() => void control("PAUSE")}>Pause</button>
          <button disabled={!state || !!error || busy || state.running} onClick={() => void control("RESUME")}>Resume</button>
          <button disabled={!state || !!error || busy || state.running} onClick={() => void control("STEP")}>Advance one tick</button>
          <span>Controls change the persisted simulator. Command effects arrive through TCP 3080.</span>
        </div>
        <p role="status" className="dss-notice">{notice}</p>
        {state && <div className="dss-subsystems"><StateTable name="Bus" values={state.bus} /><StateTable name="Core" values={state.core} /><StateTable name="Payload" values={state.payload} /></div>}
        {state && <DssCommandForm state={state} unavailable={!!error || busy} onChanged={refresh} />}
      </section> : <section id="panel-telemetry" role="tabpanel" aria-labelledby="tab-telemetry">
        <div className="dss-telemetry-tools"><label>Filter telemetry <input type="search" value={filter} onChange={(event) => setFilter(event.target.value)} /></label>
          <span>Packet sequence: {synchronized ? telemetry?.sequence : "awaiting current epoch"}</span></div>
        <p className="dss-caption">Values decoded from the latest DSS telemetry packet. Kafka receipt: {telemetry?.published ? "acknowledged" : "pending"}.</p>
        <div className="dss-table-scroll" tabIndex={0} role="region" aria-label="Telemetry values, scroll for packet details"><table aria-label="Satellite telemetry">
          <thead><tr>{["Item", "Raw", "Engineering", "Unit", "Validity", "Quality", "Acquired (UTC)"].map((name) => <th key={name} scope="col">{name}</th>)}</tr></thead>
          <tbody>{samples.map((sample) => <tr key={sample.item_id}><th scope="row">{sample.item_id}</th><td>{scalar(sample.raw_value)}</td><td>{scalar(sample.engineering_value)}</td><td>{sample.unit || "—"}</td><td>{sample.validity}</td><td>{sample.quality}</td><td>{acquired(sample.acquired_at_unix_ns)}</td></tr>)}</tbody>
        </table></div>
        {samples.length === 0 && <p>No telemetry matches the current epoch and filter.</p>}
        <details className="dss-packet"><summary>Packet provenance</summary><dl><dt>Epoch</dt><dd>{telemetry?.epoch ?? "—"}</dd><dt>SHA-256</dt><dd>{telemetry?.packet_sha256 ?? "—"}</dd></dl>
          <code tabIndex={0} role="region" aria-label="Raw telemetry packet">{telemetry?.packet_hex ?? "No packet"}</code></details>
      </section>}
    </main>
    <footer className="dss-footer"><span>Scenario: {state?.scenario_id ?? "—"}</span><span>Database: {state?.database_revision ?? "—"}</span>
      <span>Engine: {state?.dynamics_engine_version ?? "—"}</span><span title={state?.epoch}>Epoch: {state?.epoch ?? "—"}</span>
    </footer>
  </div>;
}
