import { KeyRound, LogIn } from "lucide-react";
import { FormEvent, useState } from "react";
import { setAccessToken } from "../api";

export function AccessTokenGate() {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      setAccessToken(token);
      window.location.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The access token is invalid.");
    }
  }

  return (
    <main className="access-gate">
      <form className="access-dialog" onSubmit={connect} aria-labelledby="access-title">
        <div className="access-title">
          <KeyRound aria-hidden="true" size={22} />
          <div>
            <h1 id="access-title">Session access</h1>
            <span>OpenBEXI SPELL simulator</span>
          </div>
        </div>
        <label htmlFor="access-token">Signed JWT</label>
        <textarea
          id="access-token"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          value={token}
          onChange={(event) => setToken(event.target.value)}
          aria-invalid={Boolean(error)}
          autoFocus
        />
        {error && <p className="access-error" role="alert">{error}</p>}
        <button type="submit" className="primary-command" disabled={!token.trim()}>
          <LogIn aria-hidden="true" size={16} />
          Connect
        </button>
      </form>
    </main>
  );
}
