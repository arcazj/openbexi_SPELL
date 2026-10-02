import { useCallback, useEffect, useRef, useState } from "react";
import {
  accessTokenExpiresAtMs, AUTH_CHANGED_EVENT, clearAccessToken, getAccessToken,
  isSimulatorSession, scheduleAt, setSimulatorAccessToken,
} from "./api";

type Status = "connecting" | "connected" | "unavailable" | "disabled";
type Session = { accessToken: string | null; status: Status; error: string | null };

class ConnectionError extends Error {
  constructor(readonly disabled: boolean) {
    super(disabled
      ? "Automatic simulator connection is disabled on this server."
      : "Simulator unavailable. Check the local services, then reconnect.");
  }
}

// One request across React StrictMode's mount/cleanup/remount and concurrent
// consumers prevents two first-use cookies from assigning competing subjects.
let pendingConnection: Promise<void> | null = null;

function connect(): Promise<void> {
  if (pendingConnection) return pendingConnection;
  const previous = getAccessToken();
  pendingConnection = (async () => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 8_000);
    try {
      const response = await fetch("/api/v1/local-session", {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Spell-Local-Session": "bootstrap-v16" },
        body: "{}", signal: controller.signal,
      });
      if (!response.ok) throw new ConnectionError(response.status === 404);
      const body = await response.json() as Record<string, unknown>;
      if (typeof body.access_token !== "string" || body.role !== "operator"
        || body.mode !== "simulator-only" || body.operational_use !== false
        || body.token_type !== "Bearer" || typeof body.expires_at !== "number"
        || body.expires_at * 1000 <= Date.now()
        || accessTokenExpiresAtMs(body.access_token) !== body.expires_at * 1000) {
        throw new ConnectionError(false);
      }
      // An explicit identity selected while bootstrap was in flight wins.
      const current = getAccessToken();
      if (current === null || current === previous) setSimulatorAccessToken(body.access_token);
    } catch (error) {
      throw error instanceof ConnectionError ? error : new ConnectionError(false);
    } finally {
      window.clearTimeout(timeout);
    }
  })().finally(() => { pendingConnection = null; });
  return pendingConnection;
}

export function useSimulatorSession(): Session & { retry: () => void } {
  const [session, setSession] = useState<Session>(() => ({
    accessToken: getAccessToken(), status: getAccessToken() ? "connected" : "connecting", error: null,
  }));
  const retryRef = useRef<() => void>(() => undefined);
  const retry = useCallback(() => retryRef.current(), []);

  useEffect(() => {
    let active = true;
    let cancelTimer: (() => void) | undefined;
    let cancelExpiry: (() => void) | undefined;
    let reconnectTimer: number | undefined;
    const hasExplicitIdentity = () => {
      const token = getAccessToken();
      const expires = accessTokenExpiresAtMs(token);
      return token && !isSimulatorSession(token) && (expires === null || expires > Date.now());
    };
    const attempt = async () => {
      if (!active) return;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      if (hasExplicitIdentity()) { reconcile(); return; }
      setSession({ accessToken: getAccessToken(), status: "connecting", error: null });
      try {
        await connect();
        if (active) reconcile();
      } catch (error) {
        if (!active) return;
        if (hasExplicitIdentity()) { reconcile(); return; }
        const failure = error as ConnectionError;
        setSession({ accessToken: getAccessToken(), status: failure.disabled ? "disabled" : "unavailable", error: failure.message });
        // This retries session establishment only, never a procedure mutation.
        if (!failure.disabled) reconnectTimer = window.setTimeout(() => void attempt(), 5_000);
      }
    };
    function reconcile() {
      cancelTimer?.();
      cancelExpiry?.();
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      const token = getAccessToken();
      const expiresAt = accessTokenExpiresAtMs(token);
      if (token && expiresAt !== null && expiresAt <= Date.now()) {
        clearAccessToken();
        return;
      }
      if (!token) {
        void attempt();
        return;
      }
      setSession({ accessToken: token, status: "connected", error: null });
      if (expiresAt !== null) {
        cancelExpiry = scheduleAt(expiresAt, () => {
          if (getAccessToken() === token) clearAccessToken();
        });
        if (isSimulatorSession(token)) {
          const renewalAt = Math.max(Date.now() + 1_000, expiresAt - 30_000);
          cancelTimer = scheduleAt(renewalAt, () => void attempt());
        }
      }
    }
    retryRef.current = () => {
      if (getAccessToken() && !isSimulatorSession()) {
        window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
      } else {
        cancelTimer?.();
        void attempt();
      }
    };
    window.addEventListener(AUTH_CHANGED_EVENT, reconcile);
    window.addEventListener("online", retry);
    reconcile();
    return () => {
      active = false;
      cancelTimer?.();
      cancelExpiry?.();
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      window.removeEventListener(AUTH_CHANGED_EVENT, reconcile);
      window.removeEventListener("online", retry);
      retryRef.current = () => undefined;
    };
  }, [retry]);
  return { ...session, retry };
}
