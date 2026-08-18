import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./api";
import { canMutateData, currentDataRole, dataApi } from "./dataApi";

function token(role: string): string {
  return `e30.${btoa(JSON.stringify({ role, sub: "subject-1" }))}.signature`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status < 400 ? "OK" : "Rejected",
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  window.sessionStorage.setItem("openbexi.spell.access-token", token("operator"));
});

afterEach(() => {
  window.sessionStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("v0.8 data API", () => {
  it("decodes the authenticated role without granting unknown roles mutation access", () => {
    expect(currentDataRole()).toBe("operator");
    expect(canMutateData()).toBe(true);
    window.sessionStorage.setItem("openbexi.spell.access-token", token("auditor"));
    expect(currentDataRole()).toBe("unknown");
    expect(canMutateData()).toBe(false);
  });

  it("uses bounded cursor pagination and authenticated owner scope", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({
      catalogs: [],
      next_cursor: null,
      owner_revision: "9007199254740995",
    }));
    vi.stubGlobal("fetch", fetchMock);

    const page = await dataApi.catalogs("local-project", 100, "cursor-value");
    expect(page.owner_revision).toBe("9007199254740995");
    const [path, init] = fetchMock.mock.calls[0] ?? [];
    expect(path).toBe("/api/v1/data/catalogs?owner_id=local-project&page_size=100&cursor=cursor-value");
    expect(new Headers(init?.headers).get("Authorization")).toBe(
      `Bearer ${token("operator")}`,
    );
  });

  it("sends CAS revisions as decimal strings with explicit caller and idempotency bindings", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({
      new_revision: "9007199254740997",
      operation_id: "operation-1",
      outcome: "UPDATED",
      prior_revision: "9007199254740995",
      replayed: false,
    }));
    vi.stubGlobal("fetch", fetchMock);

    await dataApi.setContainerVariable({
      owner_id: "local-project",
      container_id: "container-1",
      variable_id: "variable-1",
      acl_revision: "2",
      expected_revision: "9007199254740995",
      expected_variable_revision: "9007199254740993",
      idempotency_key: "explicit-idempotency-key",
      name: "counter",
      declared_type: "LONG",
      value: {
        schema_version: "spell.data.value/1",
        type: "INT64",
        value: "9007199254740999",
      },
    });

    const [path, init] = fetchMock.mock.calls[0] ?? [];
    expect(path).toBe(
      "/api/v1/data/containers/container-1/variables/variable-1?owner_id=local-project&acl_revision=2",
    );
    expect(JSON.parse(String(init?.body))).toEqual({
      declared_type: "LONG",
      expected_revision: "9007199254740995",
      expected_variable_revision: "9007199254740993",
      name: "counter",
      value: {
        schema_version: "spell.data.value/1",
        type: "INT64",
        value: "9007199254740999",
      },
    });
    const requestHeaders = new Headers(init?.headers);
    expect(requestHeaders.get("Idempotency-Key")).toBe("explicit-idempotency-key");
    expect(requestHeaders.get("X-Spell-Session-Id")).toMatch(/^[0-9a-f-]{36}$/);
    expect(requestHeaders.get("X-Spell-Client-Instance-Key-Id")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("binds every namespace-specific request to the composite scope identity", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({
      acl_revision: "1",
      content_digest: "a".repeat(64),
      entry_count: 0,
      namespace_id: "shared-1",
      owner_id: "local-project",
      revision: "1",
      scope: "PROJECT",
    }));
    vi.stubGlobal("fetch", fetchMock);

    await dataApi.sharedNamespace("local-project", "shared-1", "1", "PROJECT");

    const [path] = fetchMock.mock.calls[0] ?? [];
    expect(path).toBe(
      "/api/v1/data/shared/namespaces/shared-1?owner_id=local-project&acl_revision=1&scope=PROJECT",
    );
  });

  it("normalizes the closed top-level error envelope", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({
      code: "REVISION_CONFLICT",
      detail: "container revision differs",
      current_revision: "9007199254740997",
    }, 409)));

    await expect(dataApi.containers("local-project")).rejects.toMatchObject({
      message: "REVISION_CONFLICT: container revision differs",
      status: 409,
    } satisfies Partial<ApiError>);
  });
});
