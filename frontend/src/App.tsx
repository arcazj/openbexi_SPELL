import { AlertCircle, X } from "lucide-react";
import { useEffect, useState } from "react";
import { AUTH_CHANGED_EVENT, getAccessToken } from "./api";
import { AccessTokenGate } from "./components/AccessTokenGate";
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
  const [authenticated, setAuthenticated] = useState(() => Boolean(getAccessToken()));
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
