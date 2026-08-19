import { KeyRound, LogIn } from "lucide-react";
import { FormEvent, useState } from "react";
import { authenticateAccessToken } from "../api";

interface AccessTokenGateProps {
  title?: string;
  subtitle?: string;
  authenticate?: (token: string) => Promise<unknown>;
}

export function AccessTokenGate({
  title = "Session access",
  subtitle = "OpenBEXI SPELL simulator",
  authenticate = authenticateAccessToken,
}: AccessTokenGateProps = {}) {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setConnecting(true);
    try {
      await authenticate(token);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The access token is invalid.");
    } finally {
      setConnecting(false);
    }
  }

  return (
    <main className="access-gate">
      <form className="access-dialog" onSubmit={connect} aria-labelledby="access-title">
        <div className="access-title">
          <KeyRound aria-hidden="true" size={22} />
          <div>
            <h1 id="access-title">{title}</h1>
            <span>{subtitle}</span>
          </div>
        </div>
        <label htmlFor="access-token">Signed JWT</label>
        <textarea
          id="access-token"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          value={token}
          onChange={(event) => {
            setToken(event.target.value);
            if (error) setError(null);
          }}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? "access-token-error" : undefined}
          autoFocus
        />
        {error && <p id="access-token-error" className="access-error" role="alert">{error}</p>}
        <button type="submit" className="primary-command" disabled={!token.trim() || connecting}>
          <LogIn aria-hidden="true" size={16} />
          {connecting ? "Checking..." : "Connect"}
        </button>
      </form>
    </main>
  );
}
