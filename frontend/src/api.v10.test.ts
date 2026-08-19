import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, normalizeActivePrompt, type ControlProof } from "./api";

describe("v0.10 language-reference prompt API", () => {
  beforeEach(() => {
    window.sessionStorage.setItem("openbexi.spell.access-token", "signed.test.token");
    window.sessionStorage.setItem("openbexi.spell.session-id", "session-v10");
    window.sessionStorage.setItem("openbexi.spell.client-instance-key", "client-v10");
  });

  afterEach(() => {
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("preserves all 195 labels and maps the final INDEX choice to 194", () => {
    const choices = Array.from({ length: 195 }, (_, index) =>
      `Example ${String(index + 1).padStart(3, "0")} - Demonstration`,
    );
    const prompt = normalizeActivePrompt({
      prompt_id: "reference-menu",
      question: "Select a SPELL 2.4.4 reference example",
      type: "LIST",
      list_mode: "INDEX",
      options: choices,
      default: 0,
      prompt_revision: 3,
    });

    expect(prompt?.options).toHaveLength(195);
    expect(prompt?.options?.at(-1)).toMatch(/^Example 195/);
    expect(prompt?.option_values).toHaveLength(195);
    expect(prompt?.option_values?.at(-1)).toBe(194);
  });

  it("settles Example 195 with the typed index and complete lease proof", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({
      prompt: { id: "reference-menu", state: "SETTLED" },
      attempt: { id: "attempt-v10", outcome: "ACCEPTED_SETTLEMENT" },
    }), { status: 202, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const proof: ControlProof = {
      session_id: "session-v10",
      client_instance_key_id: "client-v10",
      lease_id: "lease-v10",
      expected_lease_revision: 2,
      control_fencing_token: 7,
    };

    await api.respondToPrompt("reference-menu", "COMMIT", 194, 3, proof);

    expect(String(fetchMock.mock.calls[0]?.[0])).toBe("/api/v1/prompts/reference-menu/responses");
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
    expect(body).toMatchObject({
      action: "COMMIT",
      value: 194,
      expected_prompt_revision: 3,
      lease_id: "lease-v10",
      expected_lease_revision: 2,
      control_fencing_token: 7,
      session_id: "session-v10",
      client_instance_key_id: "client-v10",
    });
  });
});
