import { AlertCircle, Database, ServerCog, Workflow, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useSimulatorSession } from "./useSimulatorSession";
import { ConsoleMenu } from "./components/ConsoleMenu";
import { ConsoleHeader } from "./components/ConsoleHeader";
import { DataServiceWorkspace } from "./components/DataServiceWorkspace";
import { DriverProjection } from "./components/DriverProjection";
import { ProcedureViews } from "./components/ProcedureViews";
import { NavigationUtilities } from "./components/NavigationUtilities";
import { ProcedureCatalog } from "./components/ProcedureCatalog";
import { useAppDispatch, useAppSelector } from "./hooks";
import { bootstrap, dismissError } from "./store";
import { useExecutionStream } from "./useExecutionStream";

export default function App() {
  const dispatch = useAppDispatch();
  const error = useAppSelector((state) => state.console.error);
  const { accessToken, status, error: sessionError, retry } = useSimulatorSession();
  const [activeView, setActiveView] = useState<"execution" | "driver" | "data">("execution");
  useExecutionStream(accessToken);

  useEffect(() => {
    if (accessToken) void dispatch(bootstrap());
  }, [accessToken, dispatch]);

  return (
    <div className="app-frame manual-console">
      <div className="console-chrome"><ConsoleMenu onReconnect={retry} onView={setActiveView} /><ConsoleHeader onReconnect={retry} /></div>
      <div className="status-area">
        {status !== "connected" && <div className="session-notice" role="status">
          <span>{status === "connecting" ? "Connecting to OpenBEXI SPELL simulator..." : sessionError ?? "Simulator connection unavailable."}</span>
          {status !== "connecting" && <button type="button" onClick={retry}>Retry connection</button>}
        </div>}
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
              if (event.key === "ArrowRight") {
                event.preventDefault();
                setActiveView("driver");
                document.getElementById("workspace-tab-driver")?.focus();
              } else if (event.key === "End") {
                event.preventDefault();
                setActiveView("data");
                document.getElementById("workspace-tab-data")?.focus();
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
              } else if (event.key === "ArrowRight" || event.key === "End") {
                event.preventDefault();
                setActiveView("data");
                document.getElementById("workspace-tab-data")?.focus();
              }
            }}
          >
            <ServerCog aria-hidden="true" size={15} />
            <span>Driver foundation</span>
          </button>
          <button
            id="workspace-tab-data"
            type="button"
            role="tab"
            aria-selected={activeView === "data"}
            aria-controls="workspace-panel-data"
            tabIndex={activeView === "data" ? 0 : -1}
            onClick={() => setActiveView("data")}
            onKeyDown={(event) => {
              if (event.key === "ArrowLeft") {
                event.preventDefault();
                setActiveView("driver");
                document.getElementById("workspace-tab-driver")?.focus();
              } else if (event.key === "ArrowRight" || event.key === "Home") {
                event.preventDefault();
                setActiveView("execution");
                document.getElementById("workspace-tab-execution")?.focus();
              }
            }}
          >
            <Database aria-hidden="true" size={15} />
            <span>Data services</span>
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
          <div className="navigation-region">
            <ProcedureCatalog />
            <NavigationUtilities />
          </div>
          <ProcedureViews />
        </div>
      ) : activeView === "driver" ? (
        <div
          id="workspace-panel-driver"
          className="driver-shell"
          role="tabpanel"
          aria-labelledby="workspace-tab-driver"
        >
          <DriverProjection />
        </div>
      ) : (
        <div
          id="workspace-panel-data"
          className="data-shell"
          role="tabpanel"
          aria-labelledby="workspace-tab-data"
        >
          <DataServiceWorkspace />
        </div>
      )}
    </div>
  );
}
