import { Circle, CircleDot, FileCode2, FileText, Play, Search, ShieldAlert, Text, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, currentControlProof } from "../api";
import { useAppDispatch } from "../hooks";
import { sendExecutionCommand } from "../store";
import type { ExecutionSnapshot, ExecutionViewEntry, WorkspaceHistoryView, WorkspaceSearchResult, WorkspaceSearchView } from "../types";

import { SOURCE_LINE_EVENT } from "./NavigationUtilities";
import { HighlightedSource, lineObservations } from "./tabularSource";

type SourceTab = "source" | "text" | "as-run" | "support";

function utc(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value || "-" : parsed.toISOString();
}

function legacyEntries(value: string | undefined, scope: string, kind: string): ExecutionViewEntry[] {
  if (!value) return [];
  return value.split("\n").map((message, index) => ({ id: `${kind}:${index}`, sequence: index + 1, time: "", scope, kind, message }));
}

export function SourceWorkspace({ execution, canMutate }: { execution: ExecutionSnapshot; canMutate: boolean }) {
  const dispatch = useAppDispatch();
  const codeRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [fontSize, setFontSize] = useState(12);
  const observations = useMemo(() => lineObservations(execution), [execution.events, execution.id]);
  const [tab, setTab] = useState<SourceTab>("source");
  const [query, setQuery] = useState("");
  const [selectedLine, setSelectedLine] = useState(execution.current_line ?? 1);
  const [breakpoints, setBreakpoints] = useState(() => new Set(execution.breakpoints ?? []));
  const [error, setError] = useState<string | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchResult, setSearchResult] = useState<WorkspaceSearchResult | null>(null);
  const [history, setHistory] = useState<Partial<Record<WorkspaceHistoryView, ExecutionViewEntry[]>>>({});
  const [historyCursor, setHistoryCursor] = useState<Partial<Record<WorkspaceHistoryView, number>>>({});
  const [historyHasMore, setHistoryHasMore] = useState<Partial<Record<WorkspaceHistoryView, boolean>>>({});
  const [historyLoading, setHistoryLoading] = useState(false);
  const source = execution.source ?? "";
  const sourceLines = source ? source.split("\n") : [];
  const textEntries = history.TEXT ?? (execution.text_entries?.length ? execution.text_entries : legacyEntries(execution.text, "procedure", "text"));
  const asRunEntries = history.AS_RUN ?? (execution.as_run_entries?.length ? execution.as_run_entries : legacyEntries(execution.as_run_source, "execution", "as-run"));
  const supportEntries = history.SUPPORT;
  const executedLines = useMemo(() => new Set(execution.executed_lines ?? []), [execution.executed_lines]);
  useEffect(() => setBreakpoints(new Set(execution.breakpoints ?? [])), [execution.breakpoints]);
  useEffect(() => {
    if (!autoScroll || !execution.current_line) return;
    setSelectedLine(execution.current_line);
    codeRef.current?.querySelector(`[data-source-line="${execution.current_line}"]`)?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [autoScroll, execution.current_line, tab]);
  useEffect(() => {
    const select = (event: Event) => {
      const detail = (event as CustomEvent<{ executionId: string; line: number }>).detail;
      if (detail.executionId !== execution.id || !["PAUSED", "INTERRUPTED"].includes(execution.state)) return;
      setTab("source"); setSelectedLine(detail.line);
      window.requestAnimationFrame(() => codeRef.current?.querySelector(`[data-source-line="${detail.line}"]`)?.scrollIntoView?.({ block: "nearest", inline: "nearest" }));
    };
    window.addEventListener(SOURCE_LINE_EVENT, select);
    return () => window.removeEventListener(SOURCE_LINE_EVENT, select);
  }, [execution.id, execution.state]);

  useEffect(() => {
    setHistory({});
    setHistoryCursor({});
    setHistoryHasMore({});
  }, [execution.id, execution.source_digest]);

  const historyView: WorkspaceHistoryView | null = tab === "source" ? null : tab === "as-run" ? "AS_RUN" : tab.toUpperCase() as WorkspaceHistoryView;
  const loadHistory = async (view: WorkspaceHistoryView, append: boolean) => {
    setHistoryLoading(true);
    setError(null);
    try {
      const afterSequence = append ? historyCursor[view] ?? 0 : 0;
      const result = await api.workspaceHistory(execution.id, view, execution.source_digest, afterSequence, 100);
      setHistory((current) => ({
        ...current,
        [view]: append ? [...(current[view] ?? []), ...result.items] : result.items,
      }));
      setHistoryCursor((current) => ({ ...current, [view]: result.next_cursor ?? result.through_sequence }));
      setHistoryHasMore((current) => ({ ...current, [view]: result.has_more }));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Workspace history failed");
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    if (historyView && history[historyView] == null) void loadHistory(historyView, false);
    // The execution/source reset deliberately triggers a fresh first page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [execution.id, execution.source_digest, historyView, history]);

  const searchView: WorkspaceSearchView = tab === "as-run" ? "AS_RUN" : tab.toUpperCase() as WorkspaceSearchView;
  const hasQuery = query.trim().length > 0;
  useEffect(() => {
    if (!hasQuery) {
      setSearchError(null);
      setSearchResult(null);
      setSearching(false);
      return;
    }
    let cancelled = false;
    setSearchError(null);
    setSearchResult(null);
    setSearching(true);
    const timer = window.setTimeout(() => {
      void api.workspaceSearch(execution.id, query, searchView, execution.source_digest, 0, 100)
        .then((result) => {
          if (!cancelled) setSearchResult(result);
        })
        .catch((reason: unknown) => {
          if (!cancelled) setSearchError(reason instanceof Error ? reason.message : "Workspace search failed");
        })
        .finally(() => {
          if (!cancelled) setSearching(false);
        });
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [execution.id, execution.source_digest, hasQuery, query, searchView]);

  const searchEntries = useMemo<ExecutionViewEntry[]>(() => (searchResult?.items ?? []).flatMap((item) => (
    item.sequence == null || item.time == null || item.scope == null || item.kind == null || item.message == null
      ? []
      : [{
          id: item.id,
          sequence: item.sequence,
          time: item.time,
          scope: item.scope,
          kind: item.kind,
          message: item.message,
          correlation_id: item.correlation_id,
          line: item.line,
          outcome: item.outcome,
        }]
  )), [searchResult]);
  const sourceMatches = useMemo(() => new Set((searchResult?.items ?? []).flatMap((item) => item.line == null ? [] : [item.line])), [searchResult]);
  const matchedEntryIds = useMemo(() => new Set(searchEntries.map((entry) => entry.id)), [searchEntries]);
  const matchCount = searchResult?.items.length ?? 0;
  const searchBinding = tab === "source" ? `Digest ${execution.source_digest?.slice(0, 12) ?? "unavailable"}` : `Cursor ${execution.view_cursor ?? execution.last_sequence}`;

  const toggleBreakpoint = async (line: number) => {
    const enabled = !breakpoints.has(line);
    setError(null);
    try {
      await api.setBreakpoint(execution.id, line, enabled, execution.revision, currentControlProof(execution.controller_lease));
      setBreakpoints((current) => {
        const next = new Set(current);
        enabled ? next.add(line) : next.delete(line);
        return next;
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Breakpoint request failed");
    }
  };

  const runToLine = async () => {
    setError(null);
    try {
      const proof = currentControlProof(execution.controller_lease);
      await dispatch(sendExecutionCommand({
        executionId: execution.id,
        command: "RUN",
        revision: execution.revision,
        reason: `Atomically run to line ${selectedLine}`,
        proof,
        target: { line: selectedLine, source_digest: execution.source_digest },
      })).unwrap();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Run-to-line request failed");
    }
  };

  const clearBreakpoints = async () => {
    setError(null);
    try {
      await api.clearBreakpoints(execution.id, execution.revision, currentControlProof(execution.controller_lease));
      setBreakpoints(new Set());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Breakpoint removal failed");
    }
  };

  const tabs: SourceTab[] = ["source", "text", "as-run", "support"];
  const moveTab = (event: React.KeyboardEvent, index: number) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : event.key === "ArrowRight" ? (index + 1) % tabs.length : (index - 1 + tabs.length) % tabs.length;
    const next = tabs[nextIndex];
    if (!next) return;
    setTab(next);
    document.getElementById(`source-tab-${next}`)?.focus();
  };

  const renderLines = (lines: string[], interactive: boolean, unavailable: string) => lines.length ? (
    <div className="tabular-scroll" ref={codeRef} tabIndex={0} aria-label="Scrollable source view" style={{ fontSize }}>
      <table className="operator-source-table" aria-label="Tabular procedure source">
        <colgroup><col className="breakpoint-column" /><col className="line-column" /><col className="code-column" /><col className="data-column" /><col className="result-column" /></colgroup>
        <thead><tr><th><span className="sr-only">Breakpoint</span></th><th>#</th><th>Code</th><th>Data</th><th>Result</th></tr></thead>
        <tbody>{lines.map((line, index) => {
          const lineNumber = index + 1;
          const observation = observations.get(lineNumber);
          return <tr key={lineNumber} data-source-line={lineNumber}
            aria-label={`Line ${lineNumber}${executedLines.has(lineNumber) ? ", executed" : ""}`}
            className={`${lineNumber === execution.current_line ? "current-line" : ""} ${lineNumber === selectedLine ? "selected-line" : ""} ${sourceMatches.has(lineNumber) ? "search-match" : ""} ${executedLines.has(lineNumber) ? "executed-line" : ""}`.trim()}
            onClick={() => setSelectedLine(lineNumber)}>
            <td>{interactive && <button type="button" className="breakpoint-toggle"
              aria-label={`${breakpoints.has(lineNumber) ? "Remove" : "Set"} breakpoint on line ${lineNumber}`}
              title={`${breakpoints.has(lineNumber) ? "Remove" : "Set"} breakpoint`} disabled={!canMutate}
              onClick={(event) => { event.stopPropagation(); void toggleBreakpoint(lineNumber); }}>
              {breakpoints.has(lineNumber) ? <CircleDot aria-hidden="true" size={11} /> : <Circle aria-hidden="true" size={11} />}
            </button>}</td>
            <td className="line-number">{lineNumber}</td>
            <td className="source-text"><code><HighlightedSource text={line || " "} /></code></td>
            <td className="line-data" title={observation ? `${observation.item} ${observation.value}` : undefined}>{observation && <>{observation.item}{observation.item && observation.value && " = "}{observation.value}</>}</td>
            <td className="line-result" title={observation?.result}>{observation?.result}</td>
          </tr>;
        })}</tbody>
      </table>
    </div>
  ) : <div className="source-unavailable" role="status">{unavailable}</div>;

  const renderEntries = (entries: ExecutionViewEntry[], matches: Set<string>, label: string, includeCorrelation = false, includeOutcome = false) => entries.length ? (
    <div className="table-scroll support-log-table committed-view-table" tabIndex={0}>
      <table aria-label={label}><thead><tr><th>UTC</th><th>Scope</th><th>Kind</th><th>Message</th>{includeOutcome && <th>Outcome</th>}{includeCorrelation && <th>Correlation</th>}</tr></thead><tbody>
        {entries.map((entry) => <tr key={entry.id} className={matches.has(entry.id) ? "search-match" : undefined}><td><time dateTime={entry.time}>{utc(entry.time)}</time></td><td>{entry.scope}</td><td><code>{entry.kind}</code></td><td>{entry.message}</td>{includeOutcome && <td>{entry.outcome ?? "-"}</td>}{includeCorrelation && <td><code title={entry.correlation_id}>{entry.correlation_id?.slice(0, 12) ?? "-"}</code></td>}</tr>)}
      </tbody></table>
    </div>
  ) : <div className="source-unavailable" role="status">{hasQuery && !searching ? `No matching ${label.toLowerCase()} entries.` : `No committed ${label.toLowerCase()} entries.`}</div>;

  return (
    <section className="source-workspace" aria-labelledby="source-title">
      <div className="presentation-indicators">
        <span>Step: {execution.steps.find((step) => step.id === execution.current_step_id)?.label ?? "(None)"}</span>
        <label><input type="checkbox" checked={autoScroll} onChange={(event) => setAutoScroll(event.target.checked)} /> Auto-scroll</label>
        <button type="button" aria-label="Decrease code font" disabled={fontSize <= 10} onClick={() => setFontSize((size) => size - 1)}>-</button>
        <button type="button" aria-label="Increase code font" disabled={fontSize >= 18} onClick={() => setFontSize((size) => size + 1)}>+</button>
        <strong>{execution.context_id}</strong>
      </div>
      <div className="source-toolbar">
        <h2 id="source-title" className="sr-only">Procedure source and execution views</h2>
        <div className="source-tabs" role="tablist" aria-label="Procedure views">
          <button id="source-tab-source" type="button" role="tab" aria-selected={tab === "source"} aria-controls="source-panel" tabIndex={tab === "source" ? 0 : -1} onKeyDown={(event) => moveTab(event, 0)} onClick={() => setTab("source")}><FileCode2 aria-hidden="true" size={14} /> Tabular</button>
          <button id="source-tab-text" type="button" role="tab" aria-selected={tab === "text"} aria-controls="source-panel" tabIndex={tab === "text" ? 0 : -1} onKeyDown={(event) => moveTab(event, 1)} onClick={() => setTab("text")}><Text aria-hidden="true" size={14} /> Text</button>
          <button id="source-tab-as-run" type="button" role="tab" aria-selected={tab === "as-run"} aria-controls="source-panel" tabIndex={tab === "as-run" ? 0 : -1} onKeyDown={(event) => moveTab(event, 2)} onClick={() => setTab("as-run")}><FileText aria-hidden="true" size={14} /> As-run</button>
          <button id="source-tab-support" type="button" role="tab" aria-selected={tab === "support"} aria-controls="source-panel" tabIndex={tab === "support" ? 0 : -1} onKeyDown={(event) => moveTab(event, 3)} onClick={() => setTab("support")}><ShieldAlert aria-hidden="true" size={14} /> Support log</button>
        </div>
        <label className="source-search"><Search aria-hidden="true" size={14} /><span className="sr-only">Search selected procedure view</span><input type="search" maxLength={200} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Literal search" /></label>
        <span className="source-search-binding" title={searchBinding}>{searching ? "Searching" : hasQuery ? `${matchCount} matches` : searchBinding}</span>
        <button type="button" className="icon-command" aria-label="Remove all breakpoints" title="Remove all breakpoints" onClick={() => void clearBreakpoints()} disabled={!canMutate || breakpoints.size === 0}><Trash2 aria-hidden="true" size={14} /></button>
        <button type="button" className="toolbar-command" aria-label={`Run to line ${selectedLine}`} onClick={() => void runToLine()} disabled={!canMutate || !execution.source_digest || !["PAUSED", "INTERRUPTED"].includes(execution.state)} title={execution.source_digest ? "Run atomically to selected line" : "Pinned source digest unavailable"}><Play aria-hidden="true" size={14} /><span>Line {selectedLine}</span></button>
      </div>
      {(error || searchError) && <div className="source-error" role="alert">{error ?? searchError}</div>}
      <div className="source-body">
        <div className="source-code" role="tabpanel" id="source-panel" aria-labelledby={`source-tab-${tab}`}>
          {tab === "source" && renderLines(sourceLines, true, "Pinned source is unavailable for this snapshot.")}
          {tab === "text" && renderEntries(hasQuery && searchResult ? searchEntries : textEntries, hasQuery ? matchedEntryIds : new Set(), "Text")}
          {tab === "as-run" && renderEntries(hasQuery && searchResult ? searchEntries : asRunEntries, hasQuery ? matchedEntryIds : new Set(), "As-run", true, true)}
          {tab === "support" && (
            hasQuery ? renderEntries(searchResult ? searchEntries : [], matchedEntryIds, "Support") : supportEntries ? renderEntries(supportEntries, new Set(), "Support", true) : <div className="table-scroll support-log-table" tabIndex={0}>
              <table><thead><tr><th>UTC</th><th>Level</th><th>Source</th><th>Message</th></tr></thead><tbody>
                {(execution.support_logs ?? []).map((entry) => <tr key={entry.id}><td><time dateTime={entry.time}>{utc(entry.time)}</time></td><td><span className={`log-level ${entry.level.toLowerCase()}`}>{entry.level}</span></td><td>{entry.source}</td><td>{entry.message}</td></tr>)}
                {!execution.support_logs?.length && <tr><td colSpan={4}>No support log entries.</td></tr>}
              </tbody></table>
            </div>
          )}
          {!hasQuery && historyView && historyHasMore[historyView] && (
            <button type="button" className="toolbar-command history-more" disabled={historyLoading} onClick={() => void loadHistory(historyView, true)}>
              {historyLoading ? "Loading" : "Load more history"}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
