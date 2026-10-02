import { useState } from "react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { openExecution, setDockTab } from "../store";

export const SOURCE_LINE_EVENT = "spell:select-source-line";

export function NavigationUtilities() {
  const dispatch = useAppDispatch();
  const execution = useAppSelector((state) => state.console.execution);
  const [tab, setTab] = useState("outline");
  const tabs = ["outline", "variables", "calls"];
  const names: Record<string, string> = { outline: "Outline", variables: "Variables", calls: "Call stack" };
  const outline = execution?.outline?.length ? execution.outline : execution?.steps.map((step) => ({
    id: step.id, label: step.label, line: step.line, depth: 0,
  })) ?? [];
  const selectLine = (line: number) => {
    if (!execution || !["PAUSED", "INTERRUPTED"].includes(execution.state)) return;
    window.dispatchEvent(new Event("spell:show-procedure"));
    window.dispatchEvent(new CustomEvent(SOURCE_LINE_EVENT, { detail: { executionId: execution.id, line } }));
  };
  return <section className="navigation-utilities" aria-label="Utility views">
    <div className="utility-tabs" role="tablist" aria-label="Utility views">
      {tabs.map((id, index) => <button id={`utility-tab-${id}`} type="button" role="tab" key={id}
        aria-selected={tab === id} aria-controls="utility-panel" tabIndex={tab === id ? 0 : -1}
        onClick={() => setTab(id)} onKeyDown={(event) => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
          event.preventDefault();
          const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? 2 : (index + (event.key === "ArrowRight" ? 1 : -1) + 3) % 3;
          const next = tabs[nextIndex]!;
          setTab(next); document.getElementById(`utility-tab-${next}`)?.focus();
        }}>{names[id]}</button>)}
    </div>
    <div id="utility-panel" className="utility-content" role="tabpanel" tabIndex={0} aria-labelledby={`utility-tab-${tab}`}>
      {!execution ? <p>Open a procedure to inspect its state.</p> : tab === "outline" ? <nav aria-label="Procedure outline">
        {outline.map((item) => <button type="button" key={item.id} title={`${item.label}, line ${item.line}`}
          disabled={!["PAUSED", "INTERRUPTED"].includes(execution.state)}
          style={{ paddingLeft: 6 + item.depth * 10 }} onClick={() => selectLine(item.line)}>
          <span>{item.label}</span><small>{item.line}</small>
        </button>)}
        {!outline.length && <p>No outline entries.</p>}
      </nav> : tab === "variables" ? <>
        <table aria-label="Variables"><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>
          {(execution.inspection ?? []).map((value) => <tr key={value.path}><td title={value.scope}>{value.path}</td><td>{value.redacted ? "REDACTED" : JSON.stringify(value.value)}</td></tr>)}
          {!execution.inspection?.length && <tr><td colSpan={2}>No values in this snapshot.</td></tr>}
        </tbody></table>
        <button type="button" className="utility-action" onClick={() => {
          window.dispatchEvent(new Event("spell:show-procedure"));
          dispatch(setDockTab("inspection"));
          window.requestAnimationFrame(() => document.getElementById("dock-tab-inspection")?.focus());
        }}>Inspect and edit variables</button>
      </> : <nav aria-label="Procedure calls">
        {execution.parent_execution_id && <button type="button" onClick={() => void dispatch(openExecution(execution.parent_execution_id!))}>Parent: {execution.parent_execution_id}</button>}
        <p>Current: {execution.procedure_name}</p>
        {(execution.child_execution_ids ?? []).map((id) => <button key={id} type="button" onClick={() => void dispatch(openExecution(id))}>Child: {id}</button>)}
        <p className="utility-note">Procedure relationships from the committed snapshot.</p>
      </nav>}
    </div>
  </section>;
}
