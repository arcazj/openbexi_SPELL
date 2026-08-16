import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleOff,
  Clock3,
  Database,
  RefreshCw,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { useDriverProjectionStream } from "../useDriverProjectionStream";
import { TelemetryObservation } from "./TelemetryObservation";
import type {
  DriverBinding,
  DriverCapacityValue,
  DriverContextGeneration,
  DriverOperation,
  DriverRecord,
} from "../types";

const REFRESH_INTERVAL_MS = 5_000;

function displayId(value: string | null | undefined): string {
  return value?.trim() || "-";
}

function displayState(value: string | null | undefined): string {
  return value?.trim().replaceAll("_", " ").toUpperCase() || "UNKNOWN";
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "Not observed";
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.valueOf()) ? value : timestamp.toISOString().replace("T", " ");
}

function observationAge(value: string | null | undefined): string {
  if (!value) return "age unknown";
  const timestamp = new Date(value).valueOf();
  if (!Number.isFinite(timestamp)) return "age unknown";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1_000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3_600)}h ago`;
}

function stalenessLabel(record: {
  staleness?: string;
  stale?: boolean;
  last_observed_at?: string | null;
}): string {
  if (record.staleness) return displayState(record.staleness);
  if (record.stale === true) return "STALE";
  if (record.stale === false) return "OBSERVED";
  return record.last_observed_at ? "OBSERVED" : "UNKNOWN";
}

function stateTone(state: string, ready?: boolean, stale?: boolean): string {
  const normalized = state.toUpperCase();
  if (stale || normalized.includes("STALE") || normalized.includes("DISCONNECT")) return "stale";
  if (normalized.includes("FAIL")) return "failed";
  if (normalized.includes("DEGRADED") || normalized.includes("RECONCIL")) return "warning";
  if (ready || ["READY", "ACTIVE", "ATTACHED", "SETTLED"].includes(normalized)) return "ready";
  return "neutral";
}

function StateMark({ state, ready, stale }: { state: string; ready?: boolean; stale?: boolean }) {
  const tone = stateTone(state, ready, stale);
  const Icon =
    tone === "ready"
      ? CheckCircle2
      : tone === "failed"
        ? CircleOff
        : tone === "warning" || tone === "stale"
          ? AlertTriangle
          : Activity;
  return (
    <span className={`foundation-state ${tone}`}>
      <Icon aria-hidden="true" size={14} />
      <span>{displayState(state)}</span>
    </span>
  );
}

function contextGenerationValue(context: DriverContextGeneration): string | number {
  return context.generation_number ?? context.context_generation_id;
}

function contextKey(context: DriverContextGeneration): string {
  return `${context.context_id}:${String(contextGenerationValue(context))}`;
}

function operationIdFor(binding: DriverBinding | null): string | null {
  if (!binding) return null;
  return (
    binding.current_operation_id ??
    binding.latest_operation_id ??
    binding.operation_id ??
    binding.operation_ids?.[0] ??
    null
  );
}

function capacityValue(value: DriverCapacityValue): string {
  if (typeof value === "number") return String(value);
  const fields = [
    value.limit === undefined ? null : `limit ${value.limit}`,
    value.used === undefined ? null : `used ${value.used}`,
    value.available === undefined ? null : `available ${value.available}`,
  ].filter((item): item is string => item !== null);
  return fields.join(" / ") || "-";
}

function fieldLabel(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function DefinitionField({ label, value, code = false }: { label: string; value: string; code?: boolean }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{code ? <code>{value}</code> : value}</dd>
    </div>
  );
}

function EmptyRow({ columns, children }: { columns: number; children: React.ReactNode }) {
  return (
    <tr>
      <td className="foundation-empty-cell" colSpan={columns}>{children}</td>
    </tr>
  );
}

export function DriverProjection() {
  const mounted = useRef(true);
  const refreshInFlight = useRef(false);
  const refreshPending = useRef(false);
  const selectedDriverRef = useRef<string | null>(null);
  const selectedContextRef = useRef<string | null>(null);
  const selectedBindingRef = useRef<string | null>(null);
  const [drivers, setDrivers] = useState<DriverRecord[]>([]);
  const [contexts, setContexts] = useState<DriverContextGeneration[]>([]);
  const [bindings, setBindings] = useState<DriverBinding[]>([]);
  const [driver, setDriver] = useState<DriverRecord | null>(null);
  const [context, setContext] = useState<DriverContextGeneration | null>(null);
  const [binding, setBinding] = useState<DriverBinding | null>(null);
  const [operation, setOperation] = useState<DriverOperation | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "empty" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<string | null>(null);

  const refresh = useCallback(async (showLoading: boolean) => {
    if (refreshInFlight.current) {
      refreshPending.current = true;
      return;
    }
    refreshInFlight.current = true;
    if (showLoading) setPhase("loading");
    try {
      do {
        refreshPending.current = false;
        try {
          const [driverPage, contextPage, bindingPage] = await Promise.all([
            api.drivers(),
            api.driverContexts(),
            api.driverBindings(),
          ]);
          const nextDrivers = Array.isArray(driverPage.items) ? driverPage.items : [];
          const nextContexts = Array.isArray(contextPage.items) ? contextPage.items : [];
          const nextBindings = Array.isArray(bindingPage.items) ? bindingPage.items : [];
          const driverId =
            nextDrivers.find((item) => item.id === selectedDriverRef.current)?.id ??
            nextDrivers[0]?.id ??
            null;
          const contextSummary =
            nextContexts.find((item) => contextKey(item) === selectedContextRef.current) ??
            nextContexts[0] ??
            null;
          const bindingId =
            nextBindings.find((item) => item.driver_binding_id === selectedBindingRef.current)
              ?.driver_binding_id ??
            nextBindings[0]?.driver_binding_id ??
            null;

          const [driverDetail, contextDetail, bindingDetail] = await Promise.all([
            driverId ? api.driver(driverId) : Promise.resolve(null),
            contextSummary
              ? api.driverContext(contextSummary.context_id, contextGenerationValue(contextSummary))
              : Promise.resolve(null),
            bindingId ? api.driverBinding(bindingId) : Promise.resolve(null),
          ]);
          const operationId = operationIdFor(bindingDetail);
          const operationDetail = operationId ? await api.driverOperation(operationId) : null;

          if (!mounted.current) return;
          selectedDriverRef.current = driverId;
          selectedContextRef.current = contextSummary ? contextKey(contextSummary) : null;
          selectedBindingRef.current = bindingId;
          setDrivers(nextDrivers);
          setContexts(nextContexts);
          setBindings(nextBindings);
          setDriver(driverDetail);
          setContext(contextDetail);
          setBinding(bindingDetail);
          setOperation(operationDetail);
          setLastRefreshedAt(new Date().toISOString());
          setError(null);
          setPhase(nextDrivers.length === 0 ? "empty" : "ready");
        } catch (caught) {
          if (!mounted.current) return;
          setError(caught instanceof Error ? caught.message : "Driver projection is unavailable");
          setPhase("error");
        }
      } while (mounted.current && refreshPending.current);
    } finally {
      refreshInFlight.current = false;
    }
  }, []);

  const refreshFromStream = useCallback(() => refresh(false), [refresh]);
  useDriverProjectionStream(refreshFromStream);

  useEffect(() => {
    mounted.current = true;
    void refresh(true);
    const timer = window.setInterval(() => void refresh(false), REFRESH_INTERVAL_MS);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
    };
  }, [refresh]);

  const selectDriver = async (driverId: string) => {
    selectedDriverRef.current = driverId;
    const summary = drivers.find((item) => item.id === driverId) ?? null;
    setDriver(summary);
    try {
      const detail = await api.driver(driverId);
      if (mounted.current && selectedDriverRef.current === driverId) setDriver(detail);
    } catch (caught) {
      if (mounted.current) setError(caught instanceof Error ? caught.message : "Driver detail is unavailable");
    }
  };

  const selectContext = async (summary: DriverContextGeneration) => {
    const key = contextKey(summary);
    selectedContextRef.current = key;
    setContext(summary);
    try {
      const detail = await api.driverContext(summary.context_id, contextGenerationValue(summary));
      if (mounted.current && selectedContextRef.current === key) setContext(detail);
    } catch (caught) {
      if (mounted.current) setError(caught instanceof Error ? caught.message : "Context detail is unavailable");
    }
  };

  const selectBinding = async (bindingId: string) => {
    selectedBindingRef.current = bindingId;
    const summary = bindings.find((item) => item.driver_binding_id === bindingId) ?? null;
    setBinding(summary);
    setOperation(null);
    try {
      const detail = await api.driverBinding(bindingId);
      if (!mounted.current || selectedBindingRef.current !== bindingId) return;
      setBinding(detail);
      const operationId = operationIdFor(detail);
      if (operationId) setOperation(await api.driverOperation(operationId));
    } catch (caught) {
      if (mounted.current) setError(caught instanceof Error ? caught.message : "Binding detail is unavailable");
    }
  };

  const capacityEntries = useMemo(
    () => Object.entries(driver?.capacity ?? {}).sort(([left], [right]) => left.localeCompare(right)),
    [driver],
  );
  const capabilities = driver?.capabilities ?? [];

  return (
    <main className="driver-projection" aria-labelledby="driver-foundation-title">
      <div className="foundation-titlebar">
        <div>
          <span className="eyebrow">v0.4 infrastructure</span>
          <h1 id="driver-foundation-title">Simulator driver foundation</h1>
        </div>
        <div className="foundation-title-actions">
          <span className="scope-flag simulator"><ShieldCheck aria-hidden="true" size={14} /> Simulator only</span>
          <span className="scope-flag readonly"><Database aria-hidden="true" size={14} /> Read only</span>
          <button
            type="button"
            className="icon-command"
            aria-label="Refresh driver projection"
            title="Refresh driver projection"
            onClick={() => void refresh(true)}
            disabled={phase === "loading"}
          >
            <RefreshCw aria-hidden="true" size={16} className={phase === "loading" ? "spin" : undefined} />
          </button>
        </div>
      </div>

      <div className="foundation-observation" role="status" aria-live="polite">
        <Clock3 aria-hidden="true" size={14} />
        <span>{lastRefreshedAt ? `Projection read ${formatTimestamp(lastRefreshedAt)}` : "Reading committed driver state"}</span>
      </div>

      {phase === "loading" && drivers.length === 0 && (
        <div className="foundation-message" role="status">
          <RefreshCw aria-hidden="true" className="spin" size={20} />
          <strong>Loading driver state</strong>
        </div>
      )}

      {phase === "error" && drivers.length === 0 && (
        <div className="foundation-message error" role="alert">
          <AlertTriangle aria-hidden="true" size={20} />
          <div><strong>Driver projection unavailable</strong><span>{error}</span></div>
          <button type="button" onClick={() => void refresh(true)}><RefreshCw aria-hidden="true" size={15} /> Retry</button>
        </div>
      )}

      {phase === "empty" && (
        <div className="foundation-message empty" role="status">
          <ServerCog aria-hidden="true" size={22} />
          <div><strong>No driver records</strong><span>The bundled simulator profile is disabled.</span></div>
        </div>
      )}

      {driver && (
        <>
          {error && <div className="foundation-inline-error" role="alert"><AlertTriangle aria-hidden="true" size={15} />{error}</div>}
          <section className="foundation-section driver-overview" aria-labelledby="driver-overview-title">
            <div className="foundation-section-heading">
              <div>
                <span className="eyebrow">Logical driver</span>
                <h2 id="driver-overview-title">{displayId(driver.logical_driver_id ?? driver.id)}</h2>
              </div>
              <StateMark state={driver.state} ready={driver.ready} stale={driver.stale} />
            </div>

            {drivers.length > 1 && (
              <div className="foundation-selector" role="group" aria-label="Driver records">
                {drivers.map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    aria-pressed={driver.id === item.id}
                    onClick={() => void selectDriver(item.id)}
                  >
                    {item.logical_driver_id ?? item.id}
                  </button>
                ))}
              </div>
            )}

            <dl className="foundation-definition-grid">
              <DefinitionField label="Driver ID" value={displayId(driver.id)} code />
              <DefinitionField label="Host generation" value={displayId(driver.current_host_generation_id)} code />
              <DefinitionField label="Readiness" value={driver.ready ? "READY" : "NOT READY"} />
              <DefinitionField label="Staleness" value={stalenessLabel(driver)} />
              <DefinitionField label="Last observed" value={`${formatTimestamp(driver.last_observed_at)} (${observationAge(driver.last_observed_at)})`} />
              <DefinitionField label="Profile" value={displayId(driver.server_profile_id)} code />
              <DefinitionField label="Contract" value={displayId(driver.contract_version)} />
              <DefinitionField label="Implementation" value={displayId(driver.implementation_version)} />
              <DefinitionField label="Credential epoch" value={driver.credential_epoch === undefined ? "-" : String(driver.credential_epoch)} />
              <DefinitionField label="Configuration schema" value={displayId(driver.configuration_schema_version)} />
              <DefinitionField label="Configuration digest" value={displayId(driver.configuration_digest)} code />
              <DefinitionField label="Profile state" value={driver.enabled ? "ENABLED" : "DISABLED"} />
            </dl>
          </section>

          <div className="foundation-two-column">
            <section className="foundation-section" aria-labelledby="driver-capability-title">
              <div className="foundation-section-heading compact">
                <div><span className="eyebrow">Negotiated contract</span><h2 id="driver-capability-title">Capabilities</h2></div>
                <span className="foundation-count">{capabilities.length}</span>
              </div>
              <div className="foundation-table-scroll" tabIndex={0}>
                <table>
                  <thead><tr><th>Service</th><th>Method</th><th>Modifiers / formats</th><th>Mutation</th><th>Stream</th></tr></thead>
                  <tbody>
                    {capabilities.map((capability, index) => (
                      <tr key={`${capability.service}-${capability.method}-${capability.modifiers.join(",")}-${capability.formats.join(",") || index}`}>
                        <td><code>{capability.service}</code></td>
                        <td><code>{capability.method}</code></td>
                        <td>{[...capability.modifiers, ...capability.formats].map(displayState).join(" / ") || "-"}</td>
                        <td>{displayState(capability.mutability)}</td>
                        <td>{displayState(capability.stream_support)}</td>
                      </tr>
                    ))}
                    {capabilities.length === 0 && <EmptyRow columns={5}>No capabilities advertised</EmptyRow>}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="foundation-section" aria-labelledby="driver-capacity-title">
              <div className="foundation-section-heading compact">
                <div><span className="eyebrow">Current generation</span><h2 id="driver-capacity-title">Capacity</h2></div>
                <span className="foundation-count">{capacityEntries.length}</span>
              </div>
              <div className="foundation-table-scroll" tabIndex={0}>
                <table>
                  <thead><tr><th>Quota</th><th>Value</th></tr></thead>
                  <tbody>
                    {capacityEntries.map(([name, value]) => (
                      <tr key={name}><td>{fieldLabel(name)}</td><td><strong>{capacityValue(value)}</strong></td></tr>
                    ))}
                    {capacityEntries.length === 0 && <EmptyRow columns={2}>No capacity data</EmptyRow>}
                  </tbody>
                </table>
              </div>
            </section>
          </div>

          <section className="foundation-section" aria-labelledby="driver-context-title">
            <div className="foundation-section-heading compact">
              <div><span className="eyebrow">Current and retained generations</span><h2 id="driver-context-title">Context generations</h2></div>
              <span className="foundation-count">{contexts.length}</span>
            </div>
            <div className="foundation-table-scroll" tabIndex={0}>
              <table>
                <thead><tr><th>Context</th><th>Generation</th><th>Host generation</th><th>State</th><th>Staleness</th><th>Observed</th></tr></thead>
                <tbody>
                  {contexts.map((item) => (
                    <tr key={contextKey(item)} className={context && contextKey(context) === contextKey(item) ? "selected" : undefined}>
                      <td><button type="button" className="table-select" onClick={() => void selectContext(item)}>{item.context_id}</button></td>
                      <td><code>{String(contextGenerationValue(item))}</code></td>
                      <td><code>{item.host_generation_id}</code></td>
                      <td><StateMark state={item.state} ready={item.ready} stale={item.stale} /></td>
                      <td>{stalenessLabel(item)}</td>
                      <td>{observationAge(item.last_observed_at)}</td>
                    </tr>
                  ))}
                  {contexts.length === 0 && <EmptyRow columns={6}>No context generations</EmptyRow>}
                </tbody>
              </table>
            </div>
            {context && (
              <dl className="foundation-detail-strip" aria-label="Selected context generation detail">
                <DefinitionField label="Generation ID" value={context.context_generation_id} code />
                <DefinitionField label="Configuration schema" value={displayId(context.configuration_schema_version)} />
                <DefinitionField label="Configuration digest" value={displayId(context.configuration_digest)} code />
                <DefinitionField label="Readiness" value={context.ready ? "READY" : "NOT READY"} />
              </dl>
            )}
          </section>

          {context && <TelemetryObservation contextId={context.context_id} />}

          <section className="foundation-section" aria-labelledby="driver-binding-title">
            <div className="foundation-section-heading compact">
              <div><span className="eyebrow">Immutable attachment history</span><h2 id="driver-binding-title">Driver bindings</h2></div>
              <span className="foundation-count">{bindings.length}</span>
            </div>
            <div className="foundation-table-scroll" tabIndex={0}>
              <table>
                <thead><tr><th>Binding</th><th>Execution</th><th>Context generation</th><th>Attachment</th><th>State</th><th>Certainty</th></tr></thead>
                <tbody>
                  {bindings.map((item) => (
                    <tr key={item.driver_binding_id} className={binding?.driver_binding_id === item.driver_binding_id ? "selected" : undefined}>
                      <td><button type="button" className="table-select" onClick={() => void selectBinding(item.driver_binding_id)}>{item.driver_binding_id}</button></td>
                      <td><code>{item.execution_id}</code></td>
                      <td><code>{item.context_generation_id}</code></td>
                      <td>{item.attachment_generation_number}</td>
                      <td><StateMark state={item.state} stale={item.stale} /></td>
                      <td>{displayState(item.certainty ?? "not applicable")}</td>
                    </tr>
                  ))}
                  {bindings.length === 0 && <EmptyRow columns={6}>No driver bindings</EmptyRow>}
                </tbody>
              </table>
            </div>
            {binding && (
              <dl className="foundation-detail-strip" aria-label="Selected driver binding detail">
                <DefinitionField label="Binding ID" value={binding.driver_binding_id} code />
                <DefinitionField label="Configuration schema" value={displayId(binding.configuration_schema_version)} />
                <DefinitionField label="Configuration digest" value={displayId(binding.configuration_digest)} code />
                <DefinitionField label="Last observed" value={formatTimestamp(binding.last_observed_at)} />
              </dl>
            )}
          </section>

          <section className="foundation-section operation-section" aria-labelledby="driver-operation-title">
            <div className="foundation-section-heading compact">
              <div><span className="eyebrow">Canonical operation ledger</span><h2 id="driver-operation-title">Lifecycle operation</h2></div>
              {operation && <StateMark state={operation.stage} stale={operation.requires_reconciliation} />}
            </div>
            {!operation ? (
              <div className="foundation-operation-empty">No lifecycle operation is referenced by the selected binding.</div>
            ) : (
              <>
                <dl className="foundation-definition-grid operation-summary">
                  <DefinitionField label="Operation ID" value={operation.operation_id} code />
                  <DefinitionField label="Method" value={operation.method} code />
                  <DefinitionField label="Attempt" value={String(operation.current_attempt_number)} />
                  <DefinitionField label="Stage" value={displayState(operation.stage)} />
                  <DefinitionField label="Effect class" value={displayState(operation.effect_class)} />
                  <DefinitionField label="Certainty" value={displayState(operation.certainty ?? "not applicable")} />
                  <DefinitionField label="Disposition" value={displayState(operation.disposition)} />
                  <DefinitionField label="Reconciliation" value={operation.requires_reconciliation ? "REQUIRED" : "NOT REQUIRED"} />
                  <DefinitionField label="Updated" value={formatTimestamp(operation.updated_at)} />
                </dl>
                <div className="foundation-two-column operation-history">
                  <div>
                    <h3>Attempts</h3>
                    <div className="foundation-table-scroll" tabIndex={0}>
                      <table>
                        <thead><tr><th>No.</th><th>Attempt ID</th><th>Effect class</th><th>Deadline</th></tr></thead>
                        <tbody>
                          {(operation.attempts ?? []).map((attempt) => (
                            <tr key={attempt.attempt_id}>
                              <td>{attempt.attempt_number}</td><td><code>{attempt.attempt_id}</code></td>
                              <td>{displayState(attempt.effect_class)}</td><td>{formatTimestamp(attempt.deadline_at)}</td>
                            </tr>
                          ))}
                          {(operation.attempts ?? []).length === 0 && <EmptyRow columns={4}>No attempt history</EmptyRow>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                  <div>
                    <h3>Transitions</h3>
                    <div className="foundation-table-scroll" tabIndex={0}>
                      <table>
                        <thead><tr><th>Seq</th><th>Stage</th><th>Certainty</th><th>Time</th></tr></thead>
                        <tbody>
                          {(operation.transitions ?? []).map((transition, index) => (
                            <tr key={transition.transition_id ?? `${transition.attempt_id ?? "transition"}-${transition.sequence ?? index}`}>
                              <td>{transition.sequence ?? index + 1}</td><td>{displayState(transition.stage)}</td>
                              <td>{displayState(transition.certainty ?? "not applicable")}</td><td>{formatTimestamp(transition.created_at)}</td>
                            </tr>
                          ))}
                          {(operation.transitions ?? []).length === 0 && <EmptyRow columns={4}>No transition history</EmptyRow>}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </>
            )}
          </section>
        </>
      )}
    </main>
  );
}
