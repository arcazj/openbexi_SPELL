import { Clock3, LogOut, Radio, Satellite, Server, UserRound } from "lucide-react";
import { useEffect, useState } from "react";
import { clearAccessToken } from "../api";
import { useAppSelector } from "../hooks";

function useUtcClock(): string {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  return now.toISOString().replace("T", " ").replace(".000Z", " UTC");
}

export function ConsoleHeader() {
  const utc = useUtcClock();
  const { connection, contextId, userName } = useAppSelector((state) => state.console);
  const statusClass = connection.phase.toLowerCase();

  return (
    <header className="console-header">
      <div className="brand-lockup" aria-label="SPELL operations console">
        <Satellite aria-hidden="true" size={24} strokeWidth={1.8} />
        <div>
          <strong>SPELL</strong>
          <span>Operations Console</span>
        </div>
      </div>
      <dl className="environment-strip">
        <div>
          <dt><Server aria-hidden="true" size={14} /> Server</dt>
          <dd>{connection.server?.service ?? "Unavailable"}</dd>
        </div>
        <div>
          <dt><Satellite aria-hidden="true" size={14} /> Context</dt>
          <dd>{contextId}</dd>
        </div>
        <div>
          <dt><UserRound aria-hidden="true" size={14} /> User</dt>
          <dd>{userName}</dd>
        </div>
        <div className="utc-clock">
          <dt><Clock3 aria-hidden="true" size={14} /> UTC</dt>
          <dd>{utc}</dd>
        </div>
      </dl>
      <div className={`connection-badge ${statusClass}`} role="status" aria-live="polite">
        <Radio aria-hidden="true" size={15} />
        <span>{connection.phase}</span>
      </div>
      <button
        type="button"
        className="session-button"
        aria-label="End session"
        title="End session"
        onClick={clearAccessToken}
      >
        <LogOut aria-hidden="true" size={16} />
      </button>
    </header>
  );
}
