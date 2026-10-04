/// <reference types="node" />
import { createHash } from "node:crypto";
import type { Locator, Page, Response } from "@playwright/test";

type ObservedResponse = { url: string; method: string; requestBody: string | null; status: number; body: unknown };
export type MutationObservation = { status: number; code: string | null; request_sha256: string; disposition?: "intermediate" | "success" | "rejected" };

function conflictCode(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("detail" in body)) return null;
  const detail = body.detail;
  return typeof detail === "object" && detail !== null && "code" in detail && typeof detail.code === "string"
    ? detail.code : null;
}

/** Observe the existing API's logical mutation; this class never sends or retries a request. */
export class DevelopmentMutationObserver {
  readonly observations: MutationObservation[] = [];
  requestBody: string | null = null;
  private intermediateCount = 0;
  private terminal = false;

  constructor(readonly url: string, readonly method: string, private readonly expectedFields: Record<string, unknown>) {}

  accept(response: ObservedResponse): boolean {
    const observation: MutationObservation = {
      status: response.status,
      code: conflictCode(response.body),
      request_sha256: createHash("sha256").update(response.requestBody ?? "").digest("hex"),
    };
    this.observations.push(observation);
    try {
      if (this.terminal) throw new Error("Development mutation already reached a terminal response");
      if (response.url !== this.url || response.method !== this.method) throw new Error("Development mutation request scope changed");
      if (response.requestBody === null) throw new Error("Development mutation lacks its immutable request body");
      const body = JSON.parse(response.requestBody) as Record<string, unknown>;
      if (typeof body !== "object" || body === null || Array.isArray(body)
        || typeof body.idempotency_key !== "string" || !body.idempotency_key
        || !Number.isSafeInteger(body.expected_workspace_revision) || Number(body.expected_workspace_revision) < 0) {
        throw new Error("Development mutation lacks its idempotency or revision binding");
      }
      for (const [key, value] of Object.entries(this.expectedFields)) {
        if (body[key] !== value) throw new Error(`Development mutation differs from expected ${key}`);
      }
      if (this.requestBody !== null && response.requestBody !== this.requestBody) throw new Error("Development mutation retry changed exact request bytes");
      this.requestBody = response.requestBody;
      if (response.status >= 200 && response.status < 300) {
        this.terminal = true;
        observation.disposition = "success";
        return true;
      }
      if (response.status !== 409 || observation.code !== "RETRYABLE_TRANSACTION_CONFLICT" || this.intermediateCount >= 2) {
        throw new Error(`Development mutation failed (${response.status}, ${observation.code ?? "no error code"})`);
      }
      this.intermediateCount += 1;
      observation.disposition = "intermediate";
      return false;
    } catch (error) {
      this.terminal = true;
      observation.disposition = "rejected";
      throw error;
    }
  }
}

export async function clickDevelopmentMutation(
  page: Page, path: string, button: Locator, expectedFields: Record<string, unknown>,
  record: (observations: MutationObservation[]) => Promise<void>,
  method: "PUT" | "POST" = "PUT",
): Promise<Response> {
  const observer = new DevelopmentMutationObserver(new URL(path, page.url()).href, method, expectedFields);
  let listener: (response: Response) => void = () => undefined;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const terminal = new Promise<Response>((resolve, reject) => {
    // Response events are ordered before reading their bodies, so a later 200 cannot bypass an earlier rejection.
    let sequence = Promise.resolve();
    listener = (response) => {
      const request = response.request();
      if (response.url() !== observer.url && (observer.requestBody === null || request.postData() !== observer.requestBody)) return;
      if (request.method() === "GET") return;
      sequence = sequence.then(async () => {
        const body: unknown = await response.json().catch(() => null);
        if (observer.accept({ url: response.url(), method: request.method(), requestBody: request.postData(), status: response.status(), body })) resolve(response);
      }).catch(reject);
    };
    page.on("response", listener);
    timeout = setTimeout(() => reject(new Error("Development mutation did not reach a valid terminal response within 30 seconds")), 30_000);
  });
  try {
    const [response] = await Promise.all([terminal, button.click()]);
    return response;
  } finally {
    clearTimeout(timeout);
    page.off("response", listener);
    await record(observer.observations);
  }
}
