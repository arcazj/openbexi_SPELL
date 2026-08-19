import { configureStore } from "@reduxjs/toolkit";
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Provider } from "react-redux";
import { consoleSlice, startExecution } from "./store";
import type { ExecutionSnapshot } from "./types";
import { eventRequiresProjectionResync, useExecutionStream } from "./useExecutionStream";

const snapshot: ExecutionSnapshot = {
  id: "execution-1",
  procedure_id: "checkout",
  procedure_name: "Checkout",
  context_id: "simulator",
  state: "RUNNING",
  revision: 1,
  last_sequence: 0,
  steps: [],
  telemetry: [],
  events: [],
  logs: [],
};

class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  readonly protocols: string | string[] | undefined;
  readyState = FakeWebSocket.CONNECTING;
  private readonly listeners = new Map<string, Set<EventListener>>();

  constructor(url: string | URL, protocols?: string | string[]) {
    this.url = String(url);
    this.protocols = protocols;
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
    const callbacks = this.listeners.get(type) ?? new Set<EventListener>();
    callbacks.add(listener as EventListener);
    this.listeners.set(type, callbacks);
  }

  close = vi.fn(() => {
    this.readyState = FakeWebSocket.CLOSED;
  });

  emitClose(code: number): void {
    this.readyState = FakeWebSocket.CLOSED;
    const event = { code } as CloseEvent;
    for (const listener of this.listeners.get("close") ?? []) listener(event);
  }
}

function testStore() {
  const store = configureStore({ reducer: { console: consoleSlice.reducer } });
  store.dispatch(
    startExecution.fulfilled(snapshot, "request", {
      procedureId: "checkout",
      contextId: "simulator",
    }),
  );
  return store;
}

function emptyStore() {
  return configureStore({ reducer: { console: consoleSlice.reducer } });
}

function Harness({ accessToken }: { accessToken: string | null }) {
  useExecutionStream(accessToken);
  return null;
}

function currentToken(): string | null {
  return window.sessionStorage.getItem("openbexi.spell.access-token");
}

function expiringToken(expiresAt: Date): string {
  const payload = btoa(JSON.stringify({ exp: expiresAt.getTime() / 1000 }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `header.${payload}.signature`;
}

function activeSocket(): FakeWebSocket {
  const socket = FakeWebSocket.instances[0];
  if (!socket) throw new Error("Expected the execution stream to create a WebSocket");
  return socket;
}

describe("execution stream authentication lifecycle", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
    window.sessionStorage.setItem("openbexi.spell.access-token", "mock.jwt.token");
  });

  afterEach(() => {
    cleanup();
    window.sessionStorage.clear();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("closes an active socket when authentication ends", () => {
    const store = testStore();
    const view = render(
      <Provider store={store}>
        <Harness accessToken={currentToken()} />
      </Provider>,
    );
    const socket = activeSocket();

    view.rerender(
      <Provider store={store}>
        <Harness accessToken={null} />
      </Provider>,
    );

    expect(socket.close).toHaveBeenCalledOnce();
  });

  it("clears the session and does not reconnect after a 4401 close", () => {
    const store = testStore();
    render(
      <Provider store={store}>
        <Harness accessToken={currentToken()} />
      </Provider>,
    );
    const socket = activeSocket();

    act(() => socket.emitClose(4401));

    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
    act(() => vi.advanceTimersByTime(60_000));
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("clears the session at JWT expiry even when no close code is available", () => {
    const now = new Date("2026-07-14T00:00:00Z");
    vi.setSystemTime(now);
    const payload = btoa(JSON.stringify({ exp: now.getTime() / 1000 + 5 }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    window.sessionStorage.setItem(
      "openbexi.spell.access-token",
      `header.${payload}.signature`,
    );
    const store = testStore();
    render(
      <Provider store={store}>
        <Harness accessToken={currentToken()} />
      </Provider>,
    );
    const socket = activeSocket();

    act(() => vi.advanceTimersByTime(4_999));
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).not.toBeNull();
    act(() => vi.advanceTimersByTime(1));

    expect(socket.close).toHaveBeenCalledOnce();
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
    act(() => vi.advanceTimersByTime(60_000));
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("clears an expired session when no execution is selected", () => {
    const now = new Date("2026-07-14T00:00:00Z");
    vi.setSystemTime(now);
    const payload = btoa(JSON.stringify({ exp: now.getTime() / 1000 + 5 }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    window.sessionStorage.setItem(
      "openbexi.spell.access-token",
      `header.${payload}.signature`,
    );
    render(
      <Provider store={emptyStore()}>
        <Harness accessToken={currentToken()} />
      </Provider>,
    );

    act(() => vi.advanceTimersByTime(5_000));

    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
    expect(FakeWebSocket.instances).toHaveLength(0);
  });

  it("does not let a replaced token's old deadline clear a later token", () => {
    const now = new Date("2026-07-14T00:00:00Z");
    vi.setSystemTime(now);
    const oldToken = expiringToken(new Date(now.getTime() + 5_000));
    const laterToken = expiringToken(new Date(now.getTime() + 10_000));
    window.sessionStorage.setItem("openbexi.spell.access-token", oldToken);
    const store = testStore();
    const view = render(<Provider store={store}><Harness accessToken={oldToken} /></Provider>);
    const oldSocket = activeSocket();

    window.sessionStorage.setItem("openbexi.spell.access-token", laterToken);
    view.rerender(<Provider store={store}><Harness accessToken={laterToken} /></Provider>);

    expect(oldSocket.close).toHaveBeenCalledOnce();
    expect(FakeWebSocket.instances[1]?.protocols).toEqual(["spell-auth", laterToken]);
    act(() => vi.advanceTimersByTime(5_000));
    expect(currentToken()).toBe(laterToken);
    act(() => vi.advanceTimersByTime(5_000));
    expect(currentToken()).toBeNull();
  });

  it("replaces a later deadline with an earlier token deadline", () => {
    const now = new Date("2026-07-14T00:00:00Z");
    vi.setSystemTime(now);
    const oldToken = expiringToken(new Date(now.getTime() + 10_000));
    const earlierToken = expiringToken(new Date(now.getTime() + 3_000));
    window.sessionStorage.setItem("openbexi.spell.access-token", oldToken);
    const store = emptyStore();
    const view = render(<Provider store={store}><Harness accessToken={oldToken} /></Provider>);

    window.sessionStorage.setItem("openbexi.spell.access-token", earlierToken);
    view.rerender(<Provider store={store}><Harness accessToken={earlierToken} /></Provider>);

    act(() => vi.advanceTimersByTime(2_999));
    expect(currentToken()).toBe(earlierToken);
    act(() => vi.advanceTimersByTime(1));
    expect(currentToken()).toBeNull();
  });
});

describe("execution stream projection invalidation", () => {
  it("resyncs durable control, schedule, and StartProc projections but not ordinary telemetry", () => {
    expect(eventRequiresProjectionResync("control.lease_expired")).toBe(true);
    expect(eventRequiresProjectionResync("schedule.fired")).toBe(true);
    expect(eventRequiresProjectionResync("startproc.result_applied")).toBe(true);
    expect(eventRequiresProjectionResync("relationship.created")).toBe(true);
    expect(eventRequiresProjectionResync("operator.control_loss_requested")).toBe(true);
    expect(eventRequiresProjectionResync("telemetry.sample")).toBe(false);
  });
});
