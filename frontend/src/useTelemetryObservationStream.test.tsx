import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useTelemetryObservationStream } from "./useTelemetryObservationStream";

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

type Cursor = { stream_epoch: string; through_sequence: string };

function Harness({ refresh }: { refresh: () => Promise<Cursor | null> }) {
  useTelemetryObservationStream("synthetic context", refresh);
  return null;
}

function socketAt(index: number): FakeWebSocket {
  const socket = FakeWebSocket.instances[index];
  if (!socket) throw new Error(`Expected observation WebSocket ${index}`);
  return socket;
}

async function flush(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe("telemetry observation stream", () => {
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

  it("refreshes ordered projection events and ignores keepalives", async () => {
    const refresh = vi
      .fn<() => Promise<Cursor | null>>()
      .mockResolvedValueOnce({ stream_epoch: "epoch-1", through_sequence: "9007199254740993" })
      .mockResolvedValue({ stream_epoch: "epoch-1", through_sequence: "9007199254740994" });
    render(<Harness refresh={refresh} />);
    await flush();
    const socket = socketAt(0);
    expect(socket.url).toBe(
      "ws://localhost:3000/api/v1/telemetry-events/ws?context_id=synthetic+context&after_sequence=9007199254740993&stream_epoch=epoch-1",
    );
    expect(socket.protocols).toEqual(["spell-auth", "signed.test.token"]);

    act(() => {
      socket.emitMessage({
        schema_version: "spell.driver.observation.event/1",
        stream: "driver.observation",
        stream_epoch: "epoch-1",
        projection_sequence: "9007199254740994",
        event_type: "telemetry.sample_observed",
      });
      socket.emitMessage({
        schema_version: "spell.driver.observation.event/1",
        stream: "driver.observation",
        stream_epoch: "epoch-1",
        event_type: "stream.keepalive",
      });
    });
    await flush();
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("resynchronizes a sequence gap from the committed snapshot cursor", async () => {
    const refresh = vi.fn(async () => ({ stream_epoch: "epoch-2", through_sequence: "7" }));
    render(<Harness refresh={refresh} />);
    await flush();
    const socket = socketAt(0);

    act(() => {
      socket.emitMessage({
        schema_version: "spell.driver.observation.event/1",
        stream: "driver.observation",
        stream_epoch: "epoch-2",
        projection_sequence: "9",
        event_type: "telemetry.sample_observed",
      });
    });
    expect(socket.close).toHaveBeenCalledWith(4409, "observation resynchronization required");

    act(() => socket.emitClose(4409));
    await flush();
    expect(socketAt(1).url).toContain("after_sequence=7");
    expect(socketAt(1).url).toContain("stream_epoch=epoch-2");
  });

  it("backs off after a 4409 when the replacement snapshot is unavailable", async () => {
    const refresh = vi
      .fn<() => Promise<Cursor | null>>()
      .mockResolvedValueOnce({ stream_epoch: "stale-epoch", through_sequence: "7" })
      .mockRejectedValueOnce(new Error("snapshot unavailable"))
      .mockResolvedValue({ stream_epoch: "fresh-epoch", through_sequence: "11" });
    render(<Harness refresh={refresh} />);
    await flush();

    act(() => socketAt(0).emitClose(4409));
    await flush();
    expect(FakeWebSocket.instances).toHaveLength(1);

    act(() => vi.advanceTimersByTime(999));
    expect(FakeWebSocket.instances).toHaveLength(1);
    act(() => vi.advanceTimersByTime(1));
    await flush();

    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(socketAt(1).url).toContain("after_sequence=11");
    expect(socketAt(1).url).toContain("stream_epoch=fresh-epoch");
    expect(socketAt(1).url).not.toContain("stale-epoch");
  });

  it("invalidates authentication on 4401 without reconnecting", async () => {
    const refresh = vi.fn(async () => ({ stream_epoch: "epoch-3", through_sequence: "0" }));
    render(<Harness refresh={refresh} />);
    await flush();
    act(() => socketAt(0).emitClose(4401));
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
    act(() => vi.advanceTimersByTime(60_000));
    expect(FakeWebSocket.instances).toHaveLength(1);
  });
});
