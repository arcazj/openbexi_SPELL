import {
  Activity,
  AlertTriangle,
  Clock3,
  Database,
  RefreshCw,
  WifiOff,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type {
  DriverTelemetrySample,
  DriverTimeObservation,
  ObservationScalarValue,
  TelemetryObservationSnapshot,
} from "../types";
import { useTelemetryObservationStream } from "../useTelemetryObservationStream";

function displayState(value: string): string {
  return value.replaceAll("_", " ").toUpperCase();
}

function displayInstant(value: string): string {
  const instant = new Date(value);
  return Number.isNaN(instant.valueOf())
    ? value || "-"
    : instant.toISOString().replace("T", " ");
}

export function displayObservationScalar(value: ObservationScalarValue): string {
  if (value.type === "BOOLEAN") return value.value === true ? "TRUE" : "FALSE";
  return String(value.value);
}

function observationTone(value: string): "ready" | "warning" | "failed" | "stale" | "neutral" {
  const state = value.toUpperCase();
  if (
    state === "GOOD" ||
    state === "VALID" ||
    state === "FRESH" ||
    state === "OBSERVED" ||
    state === "NOT_ALARMED" ||
    state === "NONE"
  ) {
    return "ready";
  }
  if (
    state === "BAD" ||
    state === "INVALID" ||
    state === "OFFLINE" ||
    state.startsWith("CRITICAL")
  ) return "failed";
  if (state === "STALE" || state === "GAP" || state === "GAPPED") return "stale";
  if (
    state === "SUSPECT" ||
    state === "INDETERMINATE" ||
    state === "WARNING" ||
    state.startsWith("WARNING_")
  ) return "warning";
  return "neutral";
}

function ObservationMark({ value }: { value: string }) {
  const tone = observationTone(value);
  const Icon =
    tone === "failed"
      ? WifiOff
      : tone === "warning" || tone === "stale"
        ? AlertTriangle
        : Activity;
  return (
    <span className={`foundation-state ${tone}`}>
      <Icon aria-hidden="true" size={13} />
      {displayState(value)}
    </span>
  );
}

function snapshotState(snapshot: TelemetryObservationSnapshot): string {
  if (snapshot.synchronization_state === "NO_SAMPLE") return "OFFLINE";
  if (snapshot.synchronization_state === "GAPPED") return "GAP";
  if (
    snapshot.items.some(
      (item) =>
        item.validity !== "VALID" ||
        item.quality !== "GOOD" ||
        item.freshness !== "FRESH",
    )
  ) {
    return "SUSPECT";
  }
  return "OBSERVED";
}

function timeUncertainty(value: DriverTimeObservation): string {
  return `${value.uncertainty_ns} ns`;
}

function ItemName({ item }: { item: DriverTelemetrySample }) {
  return (
    <div className="telemetry-item-name">
      <strong>{item.qualified_name}</strong>
      <code>{item.item_id}</code>
      <span>{item.description}</span>
    </div>
  );
}

export function TelemetryObservation({ contextId }: { contextId: string }) {
  const mounted = useRef(true);
  const [snapshot, setSnapshot] = useState<TelemetryObservationSnapshot | null>(null);
  const [time, setTime] = useState<DriverTimeObservation | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "empty" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const nextSnapshot = await api.telemetrySnapshot(contextId);
      if (!mounted.current) return null;
      setTime(nextSnapshot.driver_time);
      setSnapshot(nextSnapshot);
      setError(null);
      setPhase(nextSnapshot.items.length === 0 ? "empty" : "ready");
      return {
        stream_epoch: nextSnapshot.stream_epoch,
        through_sequence: nextSnapshot.through_sequence,
      };
    } catch (caught) {
      if (!mounted.current) return null;
      setError(caught instanceof Error ? caught.message : "Observation projection is unavailable");
      setPhase((current) => current === "ready" || current === "empty" ? current : "error");
      return null;
    }
  }, [contextId]);

  useTelemetryObservationStream(contextId, refresh);

  useEffect(() => {
    mounted.current = true;
    setSnapshot(null);
    setTime(null);
    setError(null);
    setPhase("loading");
    void refresh();
    return () => {
      mounted.current = false;
    };
  }, [contextId, refresh]);

  const state = snapshot ? snapshotState(snapshot) : "UNKNOWN";
  const sortedItems = useMemo(
    () => [...(snapshot?.items ?? [])].sort((left, right) => left.item_id.localeCompare(right.item_id)),
    [snapshot],
  );

  return (
    <section className="foundation-section telemetry-observation" aria-labelledby="telemetry-observation-title">
      <div className="foundation-section-heading compact">
        <div>
          <span className="eyebrow">v0.7 committed projection</span>
          <h2 id="telemetry-observation-title">Telemetry observation</h2>
        </div>
        <div className="telemetry-observation-actions">
          <ObservationMark value={state} />
          <button
            type="button"
            className="icon-command"
            aria-label="Refresh telemetry observation"
            title="Refresh telemetry observation"
            disabled={phase === "loading"}
            onClick={() => void refresh()}
          >
            <RefreshCw aria-hidden="true" size={15} className={phase === "loading" ? "spin" : undefined} />
          </button>
        </div>
      </div>

      {time && (
        <dl className="telemetry-time-strip" aria-label="Driver time observation">
          <div><dt><Clock3 aria-hidden="true" size={12} />Driver time</dt><dd><code>{time.time_unix_ns}</code></dd></div>
          <div><dt>Source</dt><dd>{displayState(time.clock_source)}</dd></div>
          <div><dt>Provenance</dt><dd>{time.provenance}</dd></div>
          <div><dt>Uncertainty</dt><dd>{timeUncertainty(time)}</dd></div>
          <div><dt>State</dt><dd className="telemetry-time-state"><ObservationMark value={time.quality} /><ObservationMark value={time.validity} /></dd></div>
          <div><dt>Received</dt><dd>{displayInstant(time.received_at)}</dd></div>
        </dl>
      )}

      {snapshot?.synchronization_state === "GAPPED" && (
        <div className="telemetry-gap" role="status">
          <AlertTriangle aria-hidden="true" size={15} />
          <strong>Cursor gap</strong>
          <span>{snapshot.source_epochs
            .filter((source) => source.synchronization_state === "GAPPED")
            .map((source) => `${source.source_id}: ${source.source_epoch}`)
            .join("; ") || "Observation stream"}</span>
        </div>
      )}

      {error && snapshot && (
        <div className="foundation-inline-error" role="alert">
          <AlertTriangle aria-hidden="true" size={15} />{error}
        </div>
      )}

      {phase === "loading" && !snapshot && (
        <div className="telemetry-observation-message" role="status">
          <RefreshCw aria-hidden="true" size={18} className="spin" />
          <strong>Loading observation</strong>
        </div>
      )}

      {phase === "error" && !snapshot && (
        <div className="telemetry-observation-message error" role="alert">
          <WifiOff aria-hidden="true" size={18} />
          <div><strong>Observation unavailable</strong><span>{error}</span></div>
          <button type="button" onClick={() => void refresh()}><RefreshCw aria-hidden="true" size={14} />Retry</button>
        </div>
      )}

      {phase === "empty" && snapshot && (
        <div className="telemetry-observation-message" role="status">
          <Database aria-hidden="true" size={18} />
          <strong>No committed samples</strong>
        </div>
      )}

      {sortedItems.length > 0 && (
        <div className="foundation-table-scroll telemetry-observation-table" tabIndex={0}>
          <table>
            <thead>
              <tr>
                <th>Item</th><th>Engineering</th><th>Raw</th><th>Quality</th>
                <th>Validity</th><th>Freshness</th><th>Alarm</th><th>Sequence</th><th>Times</th>
              </tr>
            </thead>
            <tbody>
              {sortedItems.map((item) => (
                <tr key={item.sample_id}>
                  <td><ItemName item={item} /></td>
                  <td><strong>{displayObservationScalar(item.engineering_value)}</strong>{item.unit && <span className="telemetry-unit"> {item.unit}</span>}</td>
                  <td><code>{displayObservationScalar(item.raw_value)}</code></td>
                  <td><ObservationMark value={item.quality} /><span className="telemetry-reason">{item.quality_reason}</span></td>
                  <td><ObservationMark value={item.validity} /></td>
                  <td><ObservationMark value={item.freshness} /><ObservationMark value={item.synchronization_state} /></td>
                  <td>{item.alarm ? <><ObservationMark value={item.alarm.state} /><span className="telemetry-reason">{item.alarm.reason}</span></> : <ObservationMark value="INDETERMINATE" />}</td>
                  <td><code>{item.source_sequence}</code><span className="telemetry-source">{item.source_epoch}</span></td>
                  <td><span>Acq ns {item.acquired_at_unix_ns}</span><span>Rx ns {item.received_at_unix_ns}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {snapshot && (
        <div className="telemetry-cursor" aria-label="Observation cursor">
          <span>Context <code>{snapshot.context_generation_id}</code></span>
          <span>Epoch <code>{snapshot.stream_epoch}</code></span>
          <span>Through <code>{snapshot.through_sequence}</code></span>
        </div>
      )}
    </section>
  );
}
