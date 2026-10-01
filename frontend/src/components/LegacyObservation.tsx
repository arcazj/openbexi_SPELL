import { useEffect, useState } from "react";
import { api } from "../api";

export interface ReplaySnapshot {
  source: { source_id: string; digest: string; clock_ns: string; live: boolean };
  connected: boolean;
  cursor: string;
  items: Array<{
    item_id: string; outcome: string; unit: string; validity: string; quality: string;
    raw: { type: string; value: unknown } | null;
    eng: { type: string; value: unknown } | null;
  }>;
}

export interface ReplayComparison {
  counts: Record<"EQUIVALENT" | "DIFFERENT" | "INDETERMINATE" | "UNSUPPORTED", number>;
  legacy_system_qualified: boolean;
}

function ReplayInspector() {
  const [source, setSource] = useState<"reference" | "simulator">("reference");
  const [revision, setRevision] = useState(0);
  const [snapshot, setSnapshot] = useState<ReplaySnapshot | null>(null);
  const [comparison, setComparison] = useState<ReplayComparison | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    let active = true;
    setSnapshot(null);
    setComparison(null);
    setError(false);
    void Promise.all([api.legacyReplaySnapshot(source), api.legacyReplayComparison()])
      .then(([nextSnapshot, nextComparison]) => {
        if (active) { setSnapshot(nextSnapshot); setComparison(nextComparison); }
      })
      .catch(() => { if (active) setError(true); });
    return () => { active = false; };
  }, [source, revision]);

  return <div className="legacy-replay-inspector">
    <p>Synthetic reference fixtures. Read-only archived observations; no live legacy system is connected.</p>
    <label htmlFor="legacy-replay-source">Observation source</label>{" "}
    <select id="legacy-replay-source" value={source} onChange={(event) => setSource(event.target.value as "reference" | "simulator")}>
      <option value="reference">SPELL 2.4.4 reference replay</option>
      <option value="simulator">Simulator fallback</option>
    </select>{" "}
    <button type="button" onClick={() => setRevision((value) => value + 1)}>Refresh replay</button>
    {error ? <p role="alert">Replay unavailable. Refresh or select the simulator fallback.</p> : !snapshot ?
      <p role="status">Loading observations…</p> : <>
        <p role="status">{snapshot.source.source_id} · {snapshot.connected ? "Recorded source available" : "Disconnected"}</p>
        <div className="foundation-table-scroll" tabIndex={0} role="region" aria-label="Replay telemetry table">
          <table>
            <thead><tr><th>Parameter</th><th>Raw</th><th>Engineering</th><th>Unit</th><th>Outcome</th><th>Validity / quality</th></tr></thead>
            <tbody>{snapshot.items.map((item) => <tr key={item.item_id}>
              <th scope="row">{item.item_id}</th><td>{item.raw ? String(item.raw.value) : "Unavailable"}</td>
              <td>{item.eng ? String(item.eng.value) : "Unavailable"}</td><td>{item.unit || "—"}</td>
              <td>{item.outcome}</td><td>{item.validity} / {item.quality}</td>
            </tr>)}</tbody>
          </table>
        </div>
        {comparison && <p aria-label="Compatibility comparison">
          Comparison: {comparison.counts.EQUIVALENT} equivalent, {comparison.counts.DIFFERENT} different,
          {" "}{comparison.counts.INDETERMINATE} indeterminate, {comparison.counts.UNSUPPORTED} unsupported.
          Real legacy-system compatibility remains unqualified.
        </p>}
        <details><summary>Source identity</summary>
          <p>Recorded logical time (nanoseconds): {snapshot.source.clock_ns}</p>
          <p className="replay-digest">Capture digest: {snapshot.source.digest}</p>
        </details>
      </>}
  </div>;
}

export function LegacyObservation() {
  const [open, setOpen] = useState(false);
  return <details className="foundation-card legacy-observation" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>Legacy observation replay</summary>
    {open && <ReplayInspector />}
  </details>;
}
