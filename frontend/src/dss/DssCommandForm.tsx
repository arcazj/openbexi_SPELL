import { useEffect, useState } from "react";
import { dssApi, type DssCatalog, type DssCommandDefinition, type DssCommandResult, type DssState } from "./api";

const uncertaintyKey = "openbexi.dss.uncertain-command";
function remembered(): { epoch: string; operation: string } | null {
  try { return JSON.parse(sessionStorage.getItem(uncertaintyKey) ?? "null") as { epoch: string; operation: string } | null; }
  catch { return null; }
}
export function DssCommandForm({ state, unavailable, onChanged }: { state: DssState; unavailable: boolean; onChanged: () => Promise<void> }) {
  const [catalog, setCatalog] = useState<DssCatalog | null>(null);
  const [name, setName] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<DssCommandResult | null>(null);
  const [uncertain, setUncertain] = useState(remembered);
  useEffect(() => { setConfirmed(false); }, [state.epoch, state.revision]);
  useEffect(() => {
    let active = true;
    void dssApi.catalog().then((value) => { if (active) setCatalog(value); }).catch(() => { if (active) setError("Command database unavailable."); });
    return () => { active = false; };
  }, []);
  const commands = catalog?.commands.filter((command) => command.role !== "REFERENCE_ADAPTATION") ?? [];
  const definition = commands.find((command) => command.name === name);
  const bound = catalog?.database_digest === state.database_digest && catalog.database_revision === state.database_revision;
  const blocked = unavailable || busy || state.running || !bound || uncertain?.epoch === state.epoch;
  function select(command: DssCommandDefinition | undefined) {
    setName(command?.name ?? ""); setConfirmed(false); setResult(null); setError("");
    setValues(Object.fromEntries((command?.arguments ?? []).map((arg) => [arg.name, arg.has_default ? String(arg.default) : ""])));
  }
  function markUncertain(operation: string) {
    const value = { epoch: state.epoch, operation };
    setUncertain(value);
    try { sessionStorage.setItem(uncertaintyKey, JSON.stringify(value)); } catch { /* In-memory lock remains active. */ }
  }
  async function send(event: React.FormEvent) {
    event.preventDefault();
    if (!definition || !confirmed || blocked) return;
    setError(""); setResult(null);
    const args = [];
    for (const argument of definition.arguments) {
      const text = values[argument.name] ?? "";
      if (text === "" && !argument.required) continue;
      let value: string | number | boolean = text;
      if (argument.value_type === "FLOAT" || argument.value_type === "LONG") {
        value = Number(text);
        if (text.trim() === "" || !Number.isFinite(value) || (argument.value_type === "LONG" && !Number.isSafeInteger(value))
          || (argument.minimum !== undefined && value < argument.minimum) || (argument.maximum !== undefined && value > argument.maximum)) {
          setError(`${argument.name} is outside its database type or range.`); return;
        }
      } else if (argument.value_type === "BOOLEAN") {
        if (!["true", "false"].includes(text)) { setError(`Choose a value for ${argument.name}.`); return; }
        value = text === "true";
      }
      args.push({ name: argument.name, value_type: argument.value_type, value, value_format: argument.allowed_formats.includes("ENG") ? "ENG" : argument.allowed_formats[0]! });
    }
    const operation = crypto.randomUUID();
    setBusy(true); setConfirmed(false);
    // Persist before issuing bytes. A browser reload or interrupted response must
    // not turn an unknown result into a new command with a fresh identity.
    markUncertain(operation);
    try {
      const outcome = await dssApi.command(state, definition.name, args, operation);
      setResult(outcome);
      if (outcome.outcome !== "UNCERTAIN") {
        setUncertain(null);
        try { sessionStorage.removeItem(uncertaintyKey); } catch { /* A stale lock is conservative. */ }
      }
      await onChanged();
    } catch (failure) {
      if (failure instanceof Error && /STATE_CONFLICT|REQUEST_INVALID/.test(failure.message)) {
        setUncertain(null);
        try { sessionStorage.removeItem(uncertaintyKey); } catch { /* Conservative lock on reload. */ }
        setError("Command was not admitted. Refresh and review the current state and arguments.");
      } else setError("Command outcome is uncertain. It has not been retried. Inspect the satellite and scenario evidence.");
      await onChanged();
    } finally { setBusy(false); }
  }
  return <section className="dss-command" aria-labelledby="dss-command-heading">
    <h2 id="dss-command-heading">Satellite command</h2>
    <form onSubmit={(event) => void send(event)}>
      <label>Command <select value={name} disabled={blocked} onChange={(event) => select(commands.find((command) => command.name === event.target.value))}>
        <option value="">Select a database command</option>{commands.map((command) => <option key={command.name} value={command.name}>{command.name}</option>)}
      </select></label>
      {definition && <span className="dss-command-effect">{definition.effect.replaceAll("_", " ").toLowerCase()}{definition.critical ? " · critical command" : ""}</span>}
      <div className="dss-arguments">{definition?.arguments.map((argument) => <label key={argument.name}>{argument.name} ({argument.value_type}{argument.required ? ", required" : ", optional"})
        {argument.allowed_values.length || argument.value_type === "BOOLEAN" ? <select value={values[argument.name] ?? ""} disabled={blocked} required={argument.required}
          onChange={(event) => { setValues({ ...values, [argument.name]: event.target.value }); setConfirmed(false); }}>
          <option value="">Select value</option>{(argument.allowed_values.length ? argument.allowed_values.map(String) : ["false", "true"]).map((value) => <option key={value} value={value}>{value}</option>)}
        </select> : <input value={values[argument.name] ?? ""} maxLength={256} disabled={blocked} required={argument.required}
          inputMode={argument.value_type === "FLOAT" || argument.value_type === "LONG" ? "decimal" : "text"}
          onChange={(event) => { setValues({ ...values, [argument.name]: event.target.value }); setConfirmed(false); }} />}
      </label>)}</div>
      <label className="dss-confirm"><input type="checkbox" checked={confirmed} disabled={blocked || !definition} onChange={(event) => setConfirmed(event.target.checked)} />Confirm this simulator command</label>
      <button type="submit" disabled={blocked || !definition || !confirmed}>{busy ? "Sending…" : "Send simulator command"}</button>
    </form>
    <p className="dss-caption">Pause before reviewing a command. This local control sends binary TC through port 3080; it does not approve a SPELL procedure prompt.</p>
    {catalog && !bound && <p role="alert" className="dss-command-error">The satellite database changed. Reload this page before reviewing a command.</p>}
    {error && <p role="alert" className="dss-command-error">{error}</p>}
    {uncertain?.epoch === state.epoch && !busy && <p role="alert" className="dss-command-error">Uncertain command {uncertain.operation}. Further UI commands are locked for this scenario; no automatic resend.</p>}
    {result && <div role="status" className="dss-command-result"><strong>{result.outcome}</strong> · {result.command_name}<br />
      Operation {result.operation_id}<ul>{result.receipts.map((receipt) => <li key={receipt.stage}>{receipt.stage}: {receipt.outcome}</li>)}</ul></div>}
  </section>;
}
