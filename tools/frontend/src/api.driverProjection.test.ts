import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, driverWebsocketUrl } from "./api";

const driver = {
  id: "driver-1",
  simulator: true,
  enabled: true,
  state: "READY",
  ready: true,
  capabilities: [],
  capacity: {},
};
const context = {
  context_id: "synthetic-context",
  context_generation_id: "context-generation-1",
  generation_number: 1,
  host_generation_id: "host-generation-1",
  state: "ACTIVE",
  ready: true,
  capacity: {},
};
const binding = {
  driver_binding_id: "binding-1",
  execution_id: "synthetic-execution",
  context_generation_id: "context-generation-1",
  attachment_generation_number: 1,
  state: "ATTACHED",
};
const operation = {
  operation_id: "operation-1",
  method: "AttachExecution",
  current_attempt_number: 1,
  stage: "SETTLED",
  certainty: "EFFECT_CONFIRMED",
  effect_class: "SIMULATOR_LIFECYCLE",
  requires_reconciliation: false,
  attempts: [],
  transitions: [],
};

describe("v0.4 driver projection API", () => {
  beforeEach(() => {
    window.sessionStorage.setItem("openbexi.spell.access-token", "signed.test.token");
  });

  afterEach(() => {
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("uses only the seven approved authenticated GET resources", async () => {
    const bodies = new Map<string, unknown>([
      ["/api/v1/drivers?limit=100", { items: [driver], next_cursor: null }],
      ["/api/v1/drivers/driver-1", { driver }],
      ["/api/v1/driver-contexts?limit=100", { items: [context], next_cursor: null }],
      ["/api/v1/driver-contexts/synthetic-context/generations/1", { context_generation: context }],
      ["/api/v1/driver-bindings?limit=100", { items: [binding], next_cursor: null }],
      ["/api/v1/driver-bindings/binding-1", { binding }],
      ["/api/v1/driver-operations/operation-1", { operation }],
    ]);
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input);
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        json: async () => bodies.get(path),
      } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    expect((await api.drivers()).items).toHaveLength(1);
    expect((await api.driver("driver-1")).id).toBe("driver-1");
    expect((await api.driverContexts()).items).toHaveLength(1);
    expect((await api.driverContext("synthetic-context", 1)).context_generation_id).toBe(
      "context-generation-1",
    );
    expect((await api.driverBindings()).items).toHaveLength(1);
    expect((await api.driverBinding("binding-1")).driver_binding_id).toBe("binding-1");
    expect((await api.driverOperation("operation-1")).operation_id).toBe("operation-1");

    expect(fetchMock.mock.calls.map(([path]) => String(path))).toEqual([...bodies.keys()]);
    for (const [, init] of fetchMock.mock.calls) {
      expect(init?.method ?? "GET").toBe("GET");
      expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer signed.test.token");
    }
    expect(driverWebsocketUrl(17)).toBe(
      "ws://localhost:3000/api/v1/driver-events/ws?after_sequence=17",
    );
    expect(driverWebsocketUrl(17)).not.toContain("spell-driver");
  });
});
