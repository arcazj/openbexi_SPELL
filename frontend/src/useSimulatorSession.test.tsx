import { StrictMode } from "react";
import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearAccessToken, currentControlProof, getAccessToken, isSimulatorSession, setAccessToken, setSimulatorAccessToken } from "./api";
import { useSimulatorSession } from "./useSimulatorSession";

function token(id = "local-one", seconds = 300, role = "operator"): string {
  return `header.${btoa(JSON.stringify({ sub: "local.simulator.browser", role,
    jti: id, exp: Math.floor(Date.now() / 1000) + seconds }))}.signature`;
}

function response(credential = token()): Response {
  const claims = JSON.parse(atob(credential.split(".")[1]!));
  return new Response(JSON.stringify({ access_token: credential, role: "operator", token_type: "Bearer",
    mode: "simulator-only", operational_use: false, expires_at: claims.exp }),
  { status: 200, headers: { "Content-Type": "application/json" } });
}

async function flush(): Promise<void> {
  await act(async () => { for (let index = 0; index < 12; index += 1) await Promise.resolve(); });
}

describe("automatic local simulator session", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-01T12:00:00Z")); sessionStorage.clear(); });
  afterEach(async () => { cleanup(); await flush(); vi.useRealTimers(); vi.unstubAllGlobals(); sessionStorage.clear(); });

  it("bootstraps once under StrictMode without embedding a credential", async () => {
    const fetcher = vi.fn(async () => response()); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession, { wrapper: StrictMode });
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith("/api/v1/local-session", expect.objectContaining({
      method: "POST", credentials: "same-origin", cache: "no-store", body: "{}",
      headers: { "Content-Type": "application/json", "X-Spell-Local-Session": "bootstrap-v16" },
    }));
    expect(result.current.status).toBe("connected");
    expect(isSimulatorSession()).toBe(true);
    expect(getAccessToken()).toBe(token());
  });

  it("reuses a live session on reload and renews before expiry", async () => {
    setSimulatorAccessToken(token("existing"));
    const controllerBinding = currentControlProof();
    const fetcher = vi.fn(async () => response(token("renewed"))); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession);
    await flush(); expect(fetcher).not.toHaveBeenCalled();
    await act(async () => vi.advanceTimersByTime(270_000)); await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe("connected");
    expect(JSON.parse(atob(result.current.accessToken!.split(".")[1]!)).jti).toBe("renewed");
    expect(currentControlProof()).toEqual(controllerBinding);
  });

  it("keeps separately supplied admin identity and never renews it as admin", async () => {
    const admin = token("admin", 300, "admin"); setAccessToken(admin);
    const fetcher = vi.fn(async () => response()); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession);
    act(() => result.current.retry()); await flush();
    expect(fetcher).not.toHaveBeenCalled(); expect(getAccessToken()).toBe(admin);
    expect(isSimulatorSession()).toBe(false);
    await act(async () => vi.advanceTimersByTime(300_000)); await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(JSON.parse(atob(getAccessToken()!.split(".")[1]!)).role).toBe("operator");
  });

  it("recovers after expiry or a 4401 consumer erases the token", async () => {
    setSimulatorAccessToken(token("expired", -1));
    const fetcher = vi.fn(async () => response(token(`new-${fetcher.mock.calls.length}`))); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession); await flush();
    expect(result.current.status).toBe("connected");
    act(clearAccessToken); await flush();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result.current.status).toBe("connected");
  });

  it("shows unavailable and reconnects without replaying procedure requests", async () => {
    const fetcher = vi.fn().mockRejectedValueOnce(new Error("private server detail"))
      .mockImplementation(async () => response()); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession); await flush();
    expect(result.current.status).toBe("unavailable");
    expect(result.current.error).toBe("Simulator unavailable. Check the local services, then reconnect.");
    expect(getAccessToken()).toBeNull();
    act(() => result.current.retry()); await flush();
    expect(result.current.status).toBe("connected");
    expect(fetcher.mock.calls.every(([path]) => path === "/api/v1/local-session")).toBe(true);
  });

  it("retries when the browser returns online", async () => {
    const fetcher = vi.fn().mockRejectedValueOnce(new Error("offline"))
      .mockImplementation(async () => response()); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession); await flush();
    act(() => window.dispatchEvent(new Event("online"))); await flush();
    expect(result.current.status).toBe("connected");
  });

  it("stops automatic retries when backend bootstrap is explicitly disabled", async () => {
    const fetcher = vi.fn(async () => new Response("{}", { status: 404 })); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession); await flush();
    expect(result.current.status).toBe("disabled");
    await act(async () => vi.advanceTimersByTime(60_000)); await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("rejects malformed or expired bootstrap credentials", async () => {
    const fetcher = vi.fn(async () => response(token("expired", -1))); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession); await flush();
    expect(result.current.status).toBe("unavailable"); expect(getAccessToken()).toBeNull();
  });

  it("does not overwrite an explicit identity selected during bootstrap", async () => {
    let finish: (response: Response) => void = () => undefined;
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((resolve) => { finish = resolve; })));
    const { result } = renderHook(useSimulatorSession);
    const admin = token("admin", 300, "admin");
    act(() => setAccessToken(admin));
    await act(async () => finish(response())); await flush();
    expect(getAccessToken()).toBe(admin); expect(result.current.status).toBe("connected");
  });

  it("erases an expired local token even while renewal service is unavailable", async () => {
    setSimulatorAccessToken(token("existing", 40));
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    const { result } = renderHook(useSimulatorSession);
    await act(async () => vi.advanceTimersByTime(10_000)); await flush();
    expect(result.current.status).toBe("unavailable");
    await act(async () => vi.advanceTimersByTime(30_000)); await flush();
    expect(getAccessToken()).toBeNull();
  });

  it("cancels unavailable retries when an explicit identity is selected", async () => {
    const fetcher = vi.fn().mockRejectedValueOnce(new Error("offline"))
      .mockImplementation(async () => response()); vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(useSimulatorSession); await flush();
    const admin = token("admin", 300, "admin");
    act(() => setAccessToken(admin));
    await act(async () => vi.advanceTimersByTime(5_000)); await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(getAccessToken()).toBe(admin); expect(result.current.status).toBe("connected");
  });
});
