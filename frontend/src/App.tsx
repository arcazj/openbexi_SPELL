import { AlertCircle, X } from "lucide-react";
import { useEffect } from "react";
import { ConsoleHeader } from "./components/ConsoleHeader";
import { DataDock } from "./components/DataDock";
import { ExecutionWorkspace } from "./components/ExecutionWorkspace";
import { ProcedureCatalog } from "./components/ProcedureCatalog";
import { useAppDispatch, useAppSelector } from "./hooks";
import { bootstrap, dismissError } from "./store";
import { useExecutionStream } from "./useExecutionStream";

export default function App() {
  const dispatch = useAppDispatch();
  const error = useAppSelector((state) => state.console.error);
  useExecutionStream();

  useEffect(() => {
    void dispatch(bootstrap());
  }, [dispatch]);

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
      </div>
      <div className="console-layout">
        <ProcedureCatalog />
        <div className="work-region">
          <ExecutionWorkspace />
          <DataDock />
        </div>
      </div>
    </div>
  );
}
