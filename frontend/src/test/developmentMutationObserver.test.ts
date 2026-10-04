import { describe, expect, it } from "vitest";
import { DevelopmentMutationObserver } from "../../e2e/development-mutation";

const url = "http://127.0.0.1:8080/api/v1/development/projects/project/resources/resource";
const fields = { content: "Display('exact source')\n", content_sha256: "a".repeat(64), media_type: "text/x-python", expected_workspace_revision: 1 };
const requestBody = JSON.stringify({ ...fields, idempotency_key: "one-logical-save" });
const retry = { detail: { code: "RETRYABLE_TRANSACTION_CONFLICT" } };
const response = (status = 200, body: unknown = {}) => ({ url, method: "PUT", requestBody, status, body });
const observer = () => new DevelopmentMutationObserver(url, "PUT", fields);

describe("development mutation response observer", () => {
  it("accepts a single successful response bound to the exact save", () => {
    const value = observer();
    expect(value.accept(response())).toBe(true);
    expect(value.observations).toEqual([{ status: 200, code: null, request_sha256: expect.stringMatching(/^[0-9a-f]{64}$/), disposition: "success" }]);
  });

  it("observes at most two explicit transaction conflicts before the same immutable save succeeds", () => {
    const value = observer();
    expect(value.accept(response(409, retry))).toBe(false);
    expect(value.accept(response(409, retry))).toBe(false);
    expect(value.accept(response())).toBe(true);
    expect(value.observations.map((item) => item.disposition)).toEqual(["intermediate", "intermediate", "success"]);
    expect(new Set(value.observations.map((item) => item.request_sha256)).size).toBe(1);
  });

  it("rejects ordinary conflicts, malformed error bodies and all other failed statuses", () => {
    for (const item of [response(409, { detail: { code: "WORKSPACE_REVISION_CONFLICT" } }), response(409, null), response(409, { code: "RETRYABLE_TRANSACTION_CONFLICT" }), response(503, retry)]) {
      expect(() => observer().accept(item)).toThrow("Development mutation failed");
    }
  });

  it("rejects an exhausted conflict instead of waiting for a later success", () => {
    const value = observer();
    value.accept(response(409, retry));
    value.accept(response(409, retry));
    expect(() => value.accept(response(409, retry))).toThrow("Development mutation failed");
    expect(() => value.accept(response())).toThrow("terminal response");
  });

  it("rejects changes to source, digest, media, revision, key or serialized byte order between responses", () => {
    const original = JSON.parse(requestBody) as Record<string, unknown>;
    const changes = Object.keys(original).map((key) => JSON.stringify({ ...original, [key]: key === "expected_workspace_revision" ? 2 : "changed" }));
    changes.push(JSON.stringify(Object.fromEntries(Object.entries(original).reverse())));
    for (const changed of changes) {
      const value = observer();
      value.accept(response(409, retry));
      expect(() => value.accept({ ...response(), requestBody: changed })).toThrow();
    }
  });

  it("rejects a changed origin, resource path or method", () => {
    for (const change of [{ url: url.replace("127.0.0.1", "localhost") }, { url: `${url}-different` }, { method: "POST" }]) {
      const value = observer();
      value.accept(response(409, retry));
      expect(() => value.accept({ ...response(), ...change })).toThrow("request scope changed");
    }
  });

  it("rejects an unbound first request even if its response is successful", () => {
    for (const body of [null, "{", "null", "[]", JSON.stringify(fields), JSON.stringify({ ...fields, expected_workspace_revision: "1", idempotency_key: "key" }), JSON.stringify({ ...fields, content: "different", idempotency_key: "key" })]) {
      expect(() => observer().accept({ ...response(), requestBody: body })).toThrow();
    }
  });

  it("keeps ordinary failure terminal and records sanitized response metadata", () => {
    const value = observer();
    expect(() => value.accept(response(409, { detail: { code: "WORKSPACE_REVISION_CONFLICT" } }))).toThrow();
    expect(() => value.accept(response())).toThrow("terminal response");
    expect(value.observations.every((item) => item.disposition === "rejected")).toBe(true);
    expect(JSON.stringify(value.observations)).not.toContain(fields.content);
    expect(JSON.stringify(value.observations)).not.toContain("one-logical-save");
  });

  it("binds resource creation to its POST template, path, kind and single workspace revision", () => {
    const creation = { ...fields, path: "src/new.spell.py", kind: "PROCEDURE" };
    const body = JSON.stringify({ ...creation, idempotency_key: "one-logical-create" });
    const value = new DevelopmentMutationObserver(`${url}s`, "POST", creation);
    const item = { ...response(), url: `${url}s`, method: "POST", requestBody: body };
    expect(value.accept({ ...item, status: 409, body: retry })).toBe(false);
    expect(value.accept(item)).toBe(true);
    expect(value.observations.map((entry) => entry.disposition)).toEqual(["intermediate", "success"]);
    expect(new Set(value.observations.map((entry) => entry.request_sha256)).size).toBe(1);
  });

  it("rejects changed creation fields and a POST retry that changes to PUT", () => {
    const creation = { ...fields, path: "src/new.spell.py", kind: "PROCEDURE" };
    const body = JSON.stringify({ ...creation, idempotency_key: "one-logical-create" });
    for (const change of [{ path: "src/other.spell.py" }, { kind: "LIBRARY" }, { content: "other template" }]) {
      const value = new DevelopmentMutationObserver(url, "POST", creation);
      expect(() => value.accept({ ...response(), method: "POST", requestBody: JSON.stringify({ ...creation, ...change, idempotency_key: "one-logical-create" }) })).toThrow();
    }
    const value = new DevelopmentMutationObserver(url, "POST", creation);
    value.accept({ ...response(409, retry), method: "POST", requestBody: body });
    expect(() => value.accept({ ...response(), requestBody: body })).toThrow("request scope changed");
  });
});
