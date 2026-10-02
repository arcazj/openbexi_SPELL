import { useEffect, useState } from "react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { openExecution } from "../store";
import { DataDock } from "./DataDock";
import { ExecutionWorkspace } from "./ExecutionWorkspace";
import { InstanceMaster } from "./InstanceMaster";
import { ValidationPanel } from "./ValidationPanel";

/** The manual's permanent Master view and one tab per opened procedure instance. */
export function ProcedureViews() {
  const dispatch = useAppDispatch();
  const { execution, selectedExecutionId, executions, validation, dockTab } = useAppSelector((state) => state.console);
  const [opened, setOpened] = useState<string[]>([]);
  const [active, setActive] = useState("master");
  const [dockExpanded, setDockExpanded] = useState(false);
  useEffect(() => { if (dockTab !== "telemetry") setDockExpanded(true); }, [dockTab]);
  useEffect(() => {
    if (!selectedExecutionId) return;
    setOpened((current) => current.includes(selectedExecutionId) ? current : [...current, selectedExecutionId]);
    setActive(selectedExecutionId);
  }, [selectedExecutionId]);
  useEffect(() => {
    const show = () => { if (selectedExecutionId) setActive(selectedExecutionId); };
    window.addEventListener("spell:show-procedure", show);
    return () => window.removeEventListener("spell:show-procedure", show);
  }, [selectedExecutionId]);

  const select = (id: string) => {
    setActive(id);
    if (id !== "master" && id !== selectedExecutionId) void dispatch(openExecution(id));
  };
  const tabs = ["master", ...opened];
  const keyboard = (event: React.KeyboardEvent, index: number) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1
      : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    select(tabs[next]!);
    document.getElementById(`instance-tab-${tabs[next]}`)?.focus();
  };
  return <div className="procedure-views">
    <div className="instance-tabs" role="tablist" aria-label="Open procedure views">
      {tabs.map((id, index) => {
        const item = execution?.id === id ? execution : executions.find((value) => value.id === id);
        const name = id === "master" ? "Master" : `${item?.procedure_name ?? "Procedure"} (${id.slice(0, 8)})`;
        return <button key={id} id={`instance-tab-${id}`} type="button" role="tab"
          aria-selected={active === id} aria-controls={id === "master" ? "master-view" : "procedure-view"}
          tabIndex={active === id ? 0 : -1} title={id === "master" ? "All procedure instances" : id}
          onClick={() => select(id)} onKeyDown={(event) => keyboard(event, index)}>
          {name}{item && <small>{item.state}</small>}
        </button>;
      })}
    </div>
    <div id="master-view" className="master-view" role="tabpanel" aria-labelledby="instance-tab-master" hidden={active !== "master"}>
      <InstanceMaster />
      {active === "master" && validation.status !== "idle" && <ValidationPanel />}
    </div>
    <div id="procedure-view" className="procedure-view" role="tabpanel"
      aria-labelledby={active === "master" ? undefined : `instance-tab-${active}`} hidden={active === "master"}>
      {active !== "master" && execution?.id !== active && <p role="status">Loading the selected procedure instance...</p>}
      <div className={`instance-content ${dockExpanded ? "" : "dock-collapsed"}`} hidden={execution?.id !== active}>
        {execution && <ExecutionWorkspace showValidation={active !== "master"} />}
        <DataDock expanded={dockExpanded} onToggle={() => setDockExpanded((current) => !current)} />
      </div>
    </div>
  </div>;
}
