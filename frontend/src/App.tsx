import { AlertCircle, ServerCog, Workflow, X } from "lucide-react";
import { useEffect, useState } from "react";
import { AUTH_CHANGED_EVENT, getAccessToken } from "./api";
import { AccessTokenGate } from "./components/AccessTokenGate";
import { ConsoleHeader } from "./components/ConsoleHeader";
import { DataDock } from "./components/DataDock";
import { DriverProjection } from "./components/DriverProjection";
import { ExecutionWorkspace } from "./components/ExecutionWorkspace";
import { InstanceMaster } from "./components/InstanceMaster";
import { ProcedureCatalog } from "./components/ProcedureCatalog";
import { useAppDispatch, useAppSelector } from "./hooks";
import { bootstrap, dismissError } from "./store";
import { useExecutionStream } from "./useExecutionStream";

export default function App() {
  const dispatch = useAppDispatch();
  const error = useAppSelector((state) => state.console.error);
  const [authenticated, setAuthenticated] = useState(() => Boolean(getAccessToken()));
  const [activeView, setActiveView] = useState<"execution" | "driver">("execution");
  useExecutionStream(authenticated);

  useEffect(() => {
    const updateAuthentication = () => setAuthenticated(Boolean(getAccessToken()));
    window.addEventListener(AUTH_CHANGED_EVENT, updateAuthentication);
    return () => window.removeEventListener(AUTH_CHANGED_EVENT, updateAuthentication);
  }, []);

  useEffect(() => {
    if (authenticated) void dispatch(bootstrap());
  }, [authenticated, dispatch]);

  if (!authenticated) return <AccessTokenGate />;

  return (
    <div className="app-frame">
      <ConsoleHeader />
      <div className="status-area">
        {error && (
          <div className="error-banner" role="alert">
            <AlertCircle aria-hidden="true" size={17} />
            <span>{error}</span>
            <button
              type="button"
              aria-label="Dismiss error"
              title="Dismiss error"
              onClick={() => dispatch(dismissError())}
            >
              <X aria-hidden="true" size={16} />
            </button>
          </div>
        )}
        <div className="workspace-tabs" role="tablist" aria-label="Console views">
          <button
            id="workspace-tab-execution"
            type="button"
            role="tab"
            aria-selected={activeView === "execution"}
            aria-controls="workspace-panel-execution"
            tabIndex={activeView === "execution" ? 0 : -1}
            onClick={() => setActiveView("execution")}
            onKeyDown={(event) => {
              if (event.key === "ArrowRight" || event.key === "End") {
                event.preventDefault();
                setActiveView("driver");
                document.getElementById("workspace-tab-driver")?.focus();
              }
            }}
          >
            <Workflow aria-hidden="true" size={15} />
            <span>Execution</span>
          </button>
          <button
            id="workspace-tab-driver"
            type="button"
            role="tab"
            aria-selected={activeView === "driver"}
            aria-controls="workspace-panel-driver"
            tabIndex={activeView === "driver" ? 0 : -1}
            onClick={() => setActiveView("driver")}
            onKeyDown={(event) => {
              if (event.key === "ArrowLeft" || event.key === "Home") {
                event.preventDefault();
                setActiveView("execution");
                document.getElementById("workspace-tab-execution")?.focus();
              }
            }}
          >
            <ServerCog aria-hidden="true" size={15} />
            <span>Driver foundation</span>
          </button>
        </div>
      </div>
      {activeView === "execution" ? (
        <div
          id="workspace-panel-execution"
          className="console-layout"
          role="tabpanel"
          aria-labelledby="workspace-tab-execution"
        >
          <ProcedureCatalog />
          <div className="work-region">
            <InstanceMaster />
            <ExecutionWorkspace />
            <DataDock />
          </div>
        </div>
      ) : (
        <div
          id="workspace-panel-driver"
          className="driver-shell"
          role="tabpanel"
          aria-labelledby="workspace-tab-driver"
        >
          <DriverProjection />
        </div>
      )}
    </div>
  );
}
