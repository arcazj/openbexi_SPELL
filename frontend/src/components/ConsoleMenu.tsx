import { useAppDispatch, useAppSelector } from "../hooks";
import { bootstrap, startExecution, validateProcedure } from "../store";

export function ConsoleMenu({ onReconnect, onView }: {
  onReconnect: () => void; onView: (view: "execution" | "driver" | "data") => void;
}) {
  const dispatch = useAppDispatch();
  const { selectedProcedureId, procedures, contextId, execution, connection, pendingAction } = useAppSelector((state) => state.console);
  const selected = procedures.find((procedure) => procedure.id === selectedProcedureId);
  const unavailable = connection.phase !== "CONNECTED" || pendingAction !== null;
  const close = (event: React.MouseEvent<HTMLElement>) => {
    if ((event.target as HTMLElement).closest("button,a")) event.currentTarget.closest("details")?.removeAttribute("open");
  };
  return <nav className="console-menubar" aria-label="Application menu" onClick={(event) => {
    const summary = (event.target as HTMLElement).closest("summary");
    if (summary) event.currentTarget.querySelectorAll("details[open]").forEach((details) => {
      if (details !== summary.parentElement) details.removeAttribute("open");
    });
  }} onKeyDown={(event) => {
    if (event.key !== "Escape") return;
    const details = (event.target as HTMLElement).closest("details");
    details?.removeAttribute("open"); details?.querySelector("summary")?.focus();
  }}>
    <details><summary>System</summary><div className="menu-popup" onClick={close}>
      <button type="button" onClick={onReconnect}>Reconnect simulator</button>
      <button type="button" onClick={() => onView("driver")}>Driver foundation</button>
      <button type="button" onClick={() => onView("data")}>Data services</button>
      <a href="/development.html">Development workspace</a>
      <a href="/dss/">DSS satellite simulator</a>
    </div></details>
    <details><summary>Procedures</summary><div className="menu-popup" onClick={close}>
      <button type="button" disabled={!selected || unavailable} onClick={() => {
        onView("execution"); void dispatch(startExecution({ procedureId: selected!.id, contextId }));
      }}>Open selected procedure</button>
      <button type="button" disabled={!selected?.source || unavailable} onClick={() => {
        onView("execution"); void dispatch(validateProcedure({ procedureId: selected!.id, source: selected!.source! }));
      }}>Validate selected source</button>
      <button type="button" disabled={unavailable} onClick={() => void dispatch(bootstrap())}>Refresh procedure list</button>
    </div></details>
    <details><summary>Execution</summary><div className="menu-popup" onClick={close}>
      <button type="button" disabled={!execution} onClick={() => {
        onView("execution"); window.dispatchEvent(new Event("spell:show-procedure"));
        window.requestAnimationFrame(() => document.querySelector<HTMLButtonElement>('[aria-label="Execution controls"] button:not(:disabled)')?.focus());
      }}>Procedure control panel</button>
      <button type="button" disabled={!execution} onClick={() => {
        onView("execution"); window.dispatchEvent(new Event("spell:show-procedure"));
        window.requestAnimationFrame(() => document.querySelector<HTMLButtonElement>('[aria-label="Execution prompt settings"]')?.click());
      }}>Configure execution</button>
    </div></details>
    <details><summary>Help</summary><div className="menu-popup menu-help">
      <strong>OpenBEXI SPELL simulator</strong>
      <p>Open a procedure from Navigation. Master lists all instances. Tabular shows source, Data and Result; Text shows committed messages.</p>
      <p>Use arrow keys to switch view tabs. Enter opens the selected procedure. Escape closes menus.</p>
      <p>Local simulator only. The unrestricted legacy Shell and live GCS connections are unavailable.</p>
    </div></details>
  </nav>;
}
