import { BookOpen, FileCheck2, FileCode2, History, Layers3, LoaderCircle, Play, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { useAppDispatch, useAppSelector } from "../hooks";
import { setContext, setSelectedProcedure, startExecution, validateProcedure } from "../store";
import type { ProcedureRevision } from "../types";

export function ProcedureCatalog() {
  const dispatch = useAppDispatch();
  const {
    contexts,
    procedures,
    selectedProcedureId,
    contextId,
    connection,
    pendingAction,
    validation,
  } = useAppSelector((state) => state.console);
  const [query, setQuery] = useState("");
  const [view, setView] = useState<"catalog" | "contexts" | "history">("catalog");
  const [history, setHistory] = useState<ProcedureRevision[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return procedures;
    return procedures.filter((item) =>
      `${item.name} ${item.description} ${item.version}`.toLowerCase().includes(normalized),
    );
  }, [procedures, query]);

  const selected = procedures.find((item) => item.id === selectedProcedureId);
  const unavailable = connection.phase !== "CONNECTED" || pendingAction !== null;

  useEffect(() => {
    if (view !== "history" || !selectedProcedureId) return;
    setHistoryError(null);
    void api.procedureHistory(selectedProcedureId)
      .then(setHistory)
      .catch((error: unknown) => setHistoryError(error instanceof Error ? error.message : "Unable to load immutable history"));
  }, [selectedProcedureId, view]);

  const onStart = () => {
    if (!selectedProcedureId) return;
    void dispatch(startExecution({ procedureId: selectedProcedureId, contextId }));
  };

  const onValidate = () => {
    if (!selected?.source) return;
    void dispatch(
      validateProcedure({ procedureId: selected.id, source: selected.source }),
    ).then(() => {
      window.requestAnimationFrame(() => document.getElementById("validation-panel")?.focus());
    });
  };

  const moveSelection = (event: React.KeyboardEvent, index: number) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const nextIndex =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? filtered.length - 1
          : event.key === "ArrowDown"
            ? Math.min(filtered.length - 1, index + 1)
            : Math.max(0, index - 1);
    const next = filtered[nextIndex];
    if (!next) return;
    dispatch(setSelectedProcedure(next.id));
    document.getElementById(`procedure-option-${nextIndex}`)?.focus();
  };

  const moveView = (event: React.KeyboardEvent, index: number) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const views: Array<typeof view> = selected ? ["catalog", "contexts", "history"] : ["catalog", "contexts"];
    const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? views.length - 1 : event.key === "ArrowRight" ? (index + 1) % views.length : (index - 1 + views.length) % views.length;
    const next = views[nextIndex];
    if (!next) return;
    setView(next);
    document.getElementById(`catalog-tab-${next}`)?.focus();
  };

  return (
    <aside className="catalog-pane" aria-labelledby="catalog-title">
      <div className="pane-heading">
        <div>
          <span className="eyebrow">Simulator workspace</span>
          <h2 id="catalog-title">Procedures</h2>
        </div>
        <span className="count-label">{procedures.length}</span>
      </div>

      <div className="catalog-tabs" role="tablist" aria-label="Context and procedure navigation">
        <button id="catalog-tab-catalog" type="button" role="tab" aria-selected={view === "catalog"} aria-controls="catalog-navigation-panel" tabIndex={view === "catalog" ? 0 : -1} onKeyDown={(event) => moveView(event, 0)} onClick={() => setView("catalog")}><BookOpen aria-hidden="true" size={14} /><span>Catalog</span></button>
        <button id="catalog-tab-contexts" type="button" role="tab" aria-selected={view === "contexts"} aria-controls="catalog-navigation-panel" tabIndex={view === "contexts" ? 0 : -1} onKeyDown={(event) => moveView(event, 1)} onClick={() => setView("contexts")}><Layers3 aria-hidden="true" size={14} /><span>Contexts</span></button>
        <button id="catalog-tab-history" type="button" role="tab" aria-selected={view === "history"} aria-controls="catalog-navigation-panel" tabIndex={view === "history" ? 0 : -1} onKeyDown={(event) => moveView(event, 2)} onClick={() => setView("history")} disabled={!selected}><History aria-hidden="true" size={14} /><span>History</span></button>
      </div>

      <label className="field-label" htmlFor="context-select">Execution context</label>
      <select
        id="context-select"
        value={contextId}
        onChange={(event) => dispatch(setContext(event.target.value))}
        disabled={pendingAction !== null}
      >
        {(contexts.length ? contexts : [{ id: "simulator", name: "Simulator" }]).map((context) => (
          <option value={context.id} key={context.id}>{context.name}</option>
        ))}
      </select>

      {view === "catalog" && <div id="catalog-navigation-panel" className="catalog-view-panel" role="tabpanel" aria-labelledby="catalog-tab-catalog">
        <label className="search-field" htmlFor="procedure-search">
          <Search aria-hidden="true" size={16} />
          <span className="sr-only">Filter procedures</span>
          <input id="procedure-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter procedures" />
        </label>

        <div className="procedure-list" role="listbox" aria-label="Procedure catalog">
          {filtered.map((procedure, index) => (
            <button id={`procedure-option-${index}`} type="button" role="option" aria-selected={procedure.id === selectedProcedureId} className="procedure-row" key={procedure.id} onClick={() => dispatch(setSelectedProcedure(procedure.id))} onKeyDown={(event) => moveSelection(event, index)}>
              <FileCode2 aria-hidden="true" size={18} />
              <span><strong>{procedure.name}</strong><small>v{procedure.version} - {procedure.step_count} steps</small></span>
            </button>
          ))}
          {filtered.length === 0 && <p className="empty-list">No matching procedures</p>}
        </div>
      </div>}

      {view === "contexts" && (
        <div id="catalog-navigation-panel" className="context-list" role="tabpanel" aria-labelledby="catalog-tab-contexts">
          <div className="context-items" aria-label="Attached execution contexts">
          {contexts.map((context) => (
            <button type="button" key={context.id} aria-pressed={context.id === contextId} onClick={() => dispatch(setContext(context.id))}>
              <span><strong>{context.name}</strong><small>{context.description ?? context.id}</small></span>
              <span className="context-metrics"><b>{context.active_execution_count ?? "-"}</b> active<br /><b>{context.procedure_count ?? "-"}</b> procedures</span>
            </button>
          ))}
          </div>
        </div>
      )}

      {view === "history" && (
        <div id="catalog-navigation-panel" className="history-list" role="tabpanel" aria-labelledby="catalog-tab-history">
          <div className="history-items" aria-label="Immutable procedure history">
          {history.map((revision) => (
            <div key={`${revision.catalog_id}-${revision.revision}`} className={revision.current ? "current" : undefined}>
              <span><strong>Revision {revision.revision}</strong><small>Catalog {revision.catalog_id}</small></span>
              <code title={revision.bundle_digest}>{revision.bundle_digest.slice(0, 12)}</code>
            </div>
          ))}
          {historyError && <p className="inline-error" role="alert">{historyError}</p>}
          {!historyError && history.length === 0 && <p className="empty-list">No immutable history is available.</p>}
          </div>
        </div>
      )}

      <div className="catalog-start" hidden={view !== "catalog"}>
        <p>{selected?.description ?? "Select a procedure to review its execution profile."}</p>
        <div className="catalog-actions">
          <button
            type="button"
            className="validation-command"
            onClick={onValidate}
            disabled={!selected?.source || unavailable || validation.status === "pending"}
            aria-controls={validation.status !== "idle" ? "validation-panel" : undefined}
            aria-busy={validation.status === "pending"}
          >
            {validation.status === "pending" ? (
              <LoaderCircle className="spin" aria-hidden="true" size={17} />
            ) : (
              <FileCheck2 aria-hidden="true" size={17} />
            )}
            Validate source
          </button>
          <button
            type="button"
            className="primary-command"
            onClick={onStart}
            disabled={!selected || unavailable}
          >
            {pendingAction === "START" ? (
              <LoaderCircle className="spin" aria-hidden="true" size={17} />
            ) : (
              <Play aria-hidden="true" size={17} fill="currentColor" />
            )}
            Start procedure
          </button>
        </div>
      </div>
    </aside>
  );
}
