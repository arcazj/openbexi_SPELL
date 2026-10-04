import { expect, type Page } from "@playwright/test";
import type { DssState } from "../src/dss/api";
import type { TelemetryObservationSnapshot } from "../src/types";

async function request<T>(page: Page, path: string, body?: unknown): Promise<T> {
  return page.evaluate(async ({ path, body }) => {
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST", cache: "no-store",
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem("openbexi.spell.access-token") ?? ""}`,
        "Content-Type": "application/json",
        "X-Spell-Session-Id": sessionStorage.getItem("openbexi.spell.session-id") ?? "",
        "X-Spell-Client-Instance-Key-Id": sessionStorage.getItem("openbexi.spell.client-instance-key") ?? "",
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) throw new Error(`DSS readiness request failed (${response.status})`);
    return response.json();
  }, { path, body }) as Promise<T>;
}

export async function ensureDssObservationReady(page: Page): Promise<void> {
  // Independent journeys pause DSS to capture immutable packet evidence.
  // Resume actual physics explicitly; never reset a scenario, replace samples,
  // or extend freshness to make a later command/observation workflow eligible.
  let simulator = await request<DssState>(page, "/dss/api/v1/state");
  if (!simulator.running) {
    simulator = await request<DssState>(page, "/dss/api/v1/control", {
      action: "RESUME", expected_epoch: simulator.epoch, expected_revision: simulator.revision,
    });
  }
  expect(simulator.running).toBe(true);
  const catalog = await request<{ telemetry: Array<{ item_id: string }> }>(page, "/dss/api/v1/catalog");
  const expectedItems = catalog.telemetry.map((item) => item.item_id).sort();
  expect(expectedItems.length).toBeGreaterThan(0);
  await expect.poll(async () => {
    const snapshot = await request<TelemetryObservationSnapshot>(page, "/api/v1/telemetry/snapshot?context_id=simulator");
    return snapshot.driver_time !== null && snapshot.synchronization_state === "COMPLETE"
      && JSON.stringify(snapshot.items.map((item) => item.item_id).sort()) === JSON.stringify(expectedItems)
      && snapshot.items.every((item) => item.source_id === "dss-GENERIC" && item.source_epoch === simulator.epoch
        && item.quality === "GOOD" && item.validity === "VALID" && item.freshness === "FRESH"
        && item.synchronization_state === "COMPLETE");
  }, { timeout: 20_000, message: "actual current-epoch DSS telemetry must be complete and fresh" }).toBe(true);
}
