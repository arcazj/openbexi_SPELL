import { FileCode2, LoaderCircle, Play, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { setContext, setSelectedProcedure, startExecution } from "../store";

export function ProcedureCatalog() {
  const dispatch = useAppDispatch();
  const {
    procedures,
    selectedProcedureId,
    contextId,
    connection,
    pendingAction,
  } = useAppSelector((state) => state.console);
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return procedures;
    return procedures.filter((item) =>
      `${item.name} ${item.description} ${item.version}`.toLowerCase().includes(normalized),
    );
  }, [procedures, query]);

  const selected = procedures.find((item) => item.id === selectedProcedureId);
  const unavailable = connection.phase !== "CONNECTED" || pendingAction !== null;

  const onStart = () => {
    if (!selectedProcedureId) return;
    void dispatch(startExecution({ procedureId: selectedProcedureId, contextId }));
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

  return (
    <aside className="catalog-pane" aria-labelledby="catalog-title">
      <div className="pane-heading">
        <div>
          <span className="eyebrow">Simulator workspace</span>
          <h2 id="catalog-title">Procedures</h2>
        </div>
        <span className="count-label">{procedures.length}</span>
      </div>

      <label className="field-label" htmlFor="context-select">Execution context</label>
      <select
        id="context-select"
        value={contextId}
        onChange={(event) => dispatch(setContext(event.target.value))}
        disabled={pendingAction !== null}
      >
        <option value="simulator">Simulator</option>
      </select>

      <label className="search-field" htmlFor="procedure-search">
        <Search aria-hidden="true" size={16} />
        <span className="sr-only">Filter procedures</span>
        <input
          id="procedure-search"
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter procedures"
        />
      </label>

      <div className="procedure-list" role="listbox" aria-label="Procedure catalog">
        {filtered.map((procedure, index) => (
          <button
            id={`procedure-option-${index}`}
            type="button"
            role="option"
            aria-selected={procedure.id === selectedProcedureId}
            className="procedure-row"
            key={procedure.id}
            onClick={() => dispatch(setSelectedProcedure(procedure.id))}
            onKeyDown={(event) => moveSelection(event, index)}
          >
            <FileCode2 aria-hidden="true" size={18} />
            <span>
              <strong>{procedure.name}</strong>
              <small>v{procedure.version} - {procedure.step_count} steps</small>
            </span>
          </button>
        ))}
        {filtered.length === 0 && (
          <p className="empty-list">No matching procedures</p>
        )}
      </div>

      <div className="catalog-start">
        <p>{selected?.description ?? "Select a procedure to review its execution profile."}</p>
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
    </aside>
  );
}
