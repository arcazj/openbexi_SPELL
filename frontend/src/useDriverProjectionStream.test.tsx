import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useDriverProjectionStream } from "./useDriverProjectionStream";

class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  readonly protocols: string | string[] | undefined;
  readonly send = vi.fn();
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

  emitOpen(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.emit("open", {} as Event);
  }

  emitMessage(value: unknown): void {
    this.emit("message", { data: JSON.stringify(value) } as MessageEvent);
  }

  emitClose(code: number): void {
    this.readyState = FakeWebSocket.CLOSED;
    this.emit("close", { code } as CloseEvent);
  }

  private emit(type: string, event: Event): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

function Harness({ refresh }: { refresh: () => Promise<void> }) {
  useDriverProjectionStream(refresh);
  return null;
}

function socketAt(index: number): FakeWebSocket {
  const socket = FakeWebSocket.instances[index];
  if (!socket) throw new Error(`Expected driver WebSocket ${index}`);
  return socket;
}

async function flush(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe("driver projection stream", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
    window.sessionStorage.setItem("openbexi.spell.access-token", "signed.test.token");
  });

  afterEach(() => {
    cleanup();
    window.sessionStorage.clear();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("refreshes from ordered committed notifications and deduplicates reconnects", async () => {
    const refresh = vi.fn(async () => undefined);
    render(<Harness refresh={refresh} />);
    const socket = socketAt(0);
    expect(socket.url).toBe(
      "ws://localhost:3000/api/v1/driver-events/ws?after_sequence=0",
    );
    expect(socket.protocols).toEqual(["spell-auth", "signed.test.token"]);

    act(() => {
      socket.emitOpen();
      socket.emitMessage({ event_type: "driver.profile_enabled", sequence: 1 });
      socket.emitMessage({ event_type: "driver.profile_enabled", sequence: 1 });
      socket.emitMessage({ event_type: "stream.keepalive", last_sequence: 1 });
      socket.emitMessage({ event_type: "driver.host_state_changed", sequence: 3 });
    });
    await flush();

    expect(refresh).toHaveBeenCalledTimes(2);
    expect(socket.send).not.toHaveBeenCalled();

    act(() => {
      socket.emitClose(1006);
      vi.advanceTimersByTime(1_000);
    });
    expect(socketAt(1).url).toContain("after_sequence=3");
  });

  it("refreshes authority and reconnects from a 4409 resync cursor", async () => {
    const refresh = vi.fn(async () => undefined);
    render(<Harness refresh={refresh} />);
    const socket = socketAt(0);

    act(() => {
      socket.emitOpen();
      socket.emitMessage({
        event_type: "stream.resync_required",
        payload: { reason: "cursor_unavailable", authoritative_sequence: 7 },
      });
      socket.emitClose(4409);
    });
    await flush();
    act(() => vi.advanceTimersByTime(0));

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(socketAt(1).url).toContain("after_sequence=7");
  });

  it("invalidates authentication on 4401 and never reconnects", () => {
    const refresh = vi.fn(async () => undefined);
    render(<Harness refresh={refresh} />);
    const socket = socketAt(0);

    act(() => socket.emitClose(4401));

    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
    act(() => vi.advanceTimersByTime(60_000));
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(refresh).not.toHaveBeenCalled();
  });
});
