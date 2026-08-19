import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute, resolve } from "node:path";

const require = createRequire(import.meta.url);
const playwrightVersion = String(require("@playwright/test/package.json").version);
const expectedItemIds = [
  "TM.POWER.BUS_VOLTAGE",
  "TM.POWER.SAFE_MODE",
  "TM.THERMAL.MODE",
] as const;
const stackImageEnvironment = {
  backend: "SPELL_BACKEND_IMAGE_ID",
  driver: "SPELL_DRIVER_IMAGE_ID",
  pki_init: "SPELL_PKI_IMAGE_ID",
  postgres: "SPELL_POSTGRES_IMAGE_ID",
  proxy: "SPELL_PROXY_IMAGE_ID",
  qualification: "SPELL_QUALIFICATION_IMAGE_ID",
} as const;

const captureDirectory = process.env.SPELL_BROWSER_CAPTURE_DIRECTORY ?? "";
const artifactDirectory = process.env.SPELL_E2E_ARTIFACT_DIRECTORY ?? "";

test.skip(
  !process.env.SPELL_REAL_BACKEND ||
    !process.env.SPELL_E2E_TOKEN ||
    !process.env.SPELL_E2E_BASE_URL ||
    !process.env.SPELL_TELEMETRY_CONTEXT_ID ||
    !isAbsolute(captureDirectory) ||
    !isAbsolute(artifactDirectory) ||
    resolve(captureDirectory) !== resolve(artifactDirectory) ||
    process.env.SPELL_NPM_VERSION !== "11.6.2" ||
    !/^[0-9a-f]{32}$/.test(process.env.SPELL_BROWSER_RUN_ID ?? "") ||
    !/^[0-9a-f]{64}$/.test(process.env.SPELL_SOURCE_FINGERPRINT ?? "") ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(process.env.SPELL_BROWSER_SECRET_CANARY ?? "") ||
    Object.values(stackImageEnvironment).some(
      (name) => !/^sha256:[0-9a-f]{64}$/.test(process.env[name] ?? ""),
    ),
  "requires the loopback v0.7 stack, signed viewer token, seeded telemetry context, and capture provenance",
);

const requestsByPage = new WeakMap<Page, string[]>();
const socketsByPage = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  await page.addInitScript((token) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
  }, process.env.SPELL_E2E_TOKEN!);
  const requests: string[] = [];
  const sockets: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("websocket", (socket) => sockets.push(socket.url()));
  requestsByPage.set(page, requests);
  socketsByPage.set(page, sockets);
});

function record(value: unknown, label: string): Record<string, unknown> {
  expect(value, label).toBeTruthy();
  expect(typeof value, label).toBe("object");
  expect(Array.isArray(value), label).toBe(false);
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown, label: string): string {
  expect(typeof value, label).toBe("string");
  expect(String(value).length, label).toBeGreaterThan(0);
  return String(value);
}

function decimal(value: unknown, label: string): string {
  const text = nonEmpty(value, label);
  expect(text, label).toMatch(/^(?:0|[1-9][0-9]*)$/);
  return text;
}

function telemetryResponse(url: string, path: string, contextId: string): boolean {
  const parsed = new URL(url);
  return parsed.pathname === path && parsed.searchParams.get("context_id") === contextId;
}

function assertLoopbackBoundary(page: Page): void {
  const urls = [...(requestsByPage.get(page) ?? []), ...(socketsByPage.get(page) ?? [])];
  expect(urls.length).toBeGreaterThan(0);
  for (const value of urls) {
    const parsed = new URL(value);
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    expect(["127.0.0.1", "localhost", "::1"]).toContain(hostname);
    expect(value).not.toContain("spell-driver");
    expect(value).not.toContain(":50051");
  }
}

test("renders real telemetry observations and cursor stream without mutation controls", async ({ browser, page }, testInfo) => {
  test.setTimeout(60_000);
  const contextId = process.env.SPELL_TELEMETRY_CONTEXT_ID!;
  await page.goto("/");
  await expect(page.getByRole("status").first()).toContainText("CONNECTED");
  await page.getByRole("tab", { name: "Driver foundation" }).click();

  const projection = page.getByRole("main", { name: "Simulator driver foundation" });
  const contextButton = projection.getByRole("button", { name: contextId, exact: true });
  await expect(contextButton).toBeVisible();
  await contextButton.click();

  const telemetry = projection.getByRole("region", { name: "Telemetry observation" });
  await expect(telemetry).toBeVisible();
  await expect(telemetry.locator("tbody tr")).toHaveCount(3);
  const refresh = telemetry.getByRole("button", { name: "Refresh telemetry observation" });
  await expect(refresh).toBeEnabled();

  const snapshotResponsePromise = page.waitForResponse((response) =>
    telemetryResponse(response.url(), "/api/v1/telemetry/snapshot", contextId),
  );
  await refresh.click();
  const snapshotResponse = await snapshotResponsePromise;
  expect(snapshotResponse.ok()).toBe(true);

  const snapshotEnvelope = record(await snapshotResponse.json(), "telemetry snapshot response");
  const snapshot = record(snapshotEnvelope.snapshot ?? snapshotEnvelope, "telemetry snapshot");
  const driverTime = record(snapshot.driver_time, "snapshot driver time");
  expect(driverTime.context_id).toBe(contextId);
  expect(snapshot.context_id).toBe(contextId);
  const contextGenerationId = nonEmpty(snapshot.context_generation_id, "snapshot context generation");
  expect(driverTime.context_generation_id).toBe(contextGenerationId);
  nonEmpty(driverTime.observation_id, "driver time observation identity");
  nonEmpty(driverTime.driver_host_generation, "driver host generation identity");
  decimal(driverTime.time_unix_ns, "driver time value");
  decimal(driverTime.acquired_at_unix_ns, "driver time acquisition");
  decimal(driverTime.received_at_unix_ns, "driver time receipt");
  nonEmpty(driverTime.provenance, "driver time provenance");
  expect(driverTime.quality).toBe("GOOD");
  expect(driverTime.validity).toBe("VALID");

  expect(snapshot.schema_version).toBe("spell.driver.observation.snapshot/1");
  expect(snapshot.stream).toBe("driver.observation");
  expect(snapshot.synchronization_state).toBe("COMPLETE");
  const streamEpoch = nonEmpty(snapshot.stream_epoch, "observation stream epoch");
  decimal(snapshot.through_sequence, "observation through sequence");
  const items = Array.isArray(snapshot.items)
    ? snapshot.items.map((item, index) => record(item, `telemetry item ${index}`))
    : [];
  expect(items.map((item) => item.item_id)).toEqual(expectedItemIds);
  const sourceEpochs = Array.isArray(snapshot.source_epochs)
    ? snapshot.source_epochs.map((item, index) => record(item, `source epoch ${index}`))
    : [];
  expect(sourceEpochs.map((item) => String(item.item_id)).sort()).toEqual([...expectedItemIds]);

  for (const item of items) {
    const itemId = nonEmpty(item.item_id, "telemetry item identity");
    expect(item.context_generation_id).toBe(contextGenerationId);
    expect(nonEmpty(item.catalog_digest, `${itemId} catalog digest`)).toMatch(/^[0-9a-f]{64}$/);
    nonEmpty(item.sample_id, `${itemId} sample identity`);
    nonEmpty(item.observation_id, `${itemId} observation identity`);
    const sourceId = nonEmpty(item.source_id, `${itemId} source identity`);
    const sourceEpoch = nonEmpty(item.source_epoch, `${itemId} source epoch`);
    const sourceSequence = decimal(item.source_sequence, `${itemId} source sequence`);
    decimal(item.acquired_at_unix_ns, `${itemId} acquisition`);
    decimal(item.received_at_unix_ns, `${itemId} receipt`);
    nonEmpty(item.clock_provenance, `${itemId} clock provenance`);
    expect(item.quality).toBe("GOOD");
    expect(item.validity).toBe("VALID");
    expect(item.freshness).toBe("FRESH");
    expect(item.synchronization_state).toBe("COMPLETE");

    const source = sourceEpochs.find((candidate) => candidate.item_id === itemId);
    expect(source).toBeTruthy();
    expect(source?.source_id).toBe(sourceId);
    expect(source?.source_epoch).toBe(sourceEpoch);
    expect(source?.last_source_sequence).toBe(sourceSequence);
    expect(source?.synchronization_state).toBe("COMPLETE");

    const alarm = record(item.alarm, `${itemId} alarm observation`);
    nonEmpty(alarm.alarm_observation_id, `${itemId} alarm identity`);
    expect(alarm.item_id).toBe(itemId);
    expect(alarm.sample_id).toBe(item.sample_id);
    const alarmCursor = record(alarm.snapshot_cursor, `${itemId} alarm cursor`);
    expect(alarmCursor.stream_epoch).toBe(streamEpoch);
    decimal(alarmCursor.projection_sequence, `${itemId} alarm projection sequence`);
  }

  const rows = telemetry.locator("tbody tr");
  expect(await rows.locator("td:first-child code").allTextContents()).toEqual(expectedItemIds);
  for (let index = 0; index < expectedItemIds.length; index += 1) {
    const row = rows.nth(index);
    await expect(row.locator("td").nth(3).getByText("GOOD", { exact: true })).toBeVisible();
    await expect(row.locator("td").nth(4).getByText("VALID", { exact: true })).toBeVisible();
    await expect(row.locator("td").nth(5).getByText("FRESH", { exact: true })).toBeVisible();
    await expect(row.locator("td").nth(6).locator(".foundation-state")).toBeVisible();
  }
  const timeStrip = telemetry.locator('[aria-label="Driver time observation"]');
  await expect(timeStrip.locator("dd code").first()).toHaveText(/^(?:0|[1-9][0-9]*)$/);
  await expect(timeStrip).toContainText(String(driverTime.provenance));
  const cursor = telemetry.locator('[aria-label="Observation cursor"]');
  await expect(cursor).toContainText(contextGenerationId);
  await expect(cursor).toContainText(streamEpoch);
  await expect(cursor.locator("code").last()).toHaveText(/^(?:0|[1-9][0-9]*)$/);

  await expect.poll(() => (socketsByPage.get(page) ?? []).some((value) => {
    const parsed = new URL(value);
    return parsed.pathname === "/api/v1/telemetry-events/ws" &&
      parsed.searchParams.get("context_id") === contextId &&
      parsed.searchParams.get("stream_epoch") === streamEpoch &&
      /^(?:0|[1-9][0-9]*)$/.test(parsed.searchParams.get("after_sequence") ?? "");
  })).toBe(true);

  const mutationNames = [
    "Open context",
    "Close context",
    "Attach execution",
    "Detach execution",
    "Cancel lifecycle operation",
    "Drain host",
  ];
  for (const name of mutationNames) {
    await expect(projection.getByRole("button", { name })).toHaveCount(0);
  }
  const mutationControlCount = await projection.locator(
    'button[aria-label="Open context"], button[aria-label="Close context"], button[aria-label="Attach execution"], button[aria-label="Detach execution"], button[aria-label="Cancel lifecycle operation"], button[aria-label="Drain host"]',
  ).count();
  expect(mutationControlCount).toBe(0);
  const requestPaths = (requestsByPage.get(page) ?? []).map(
    (value) => new URL(value).pathname,
  );
  expect(
    requestPaths.filter((path) => path === "/api/v1/telemetry/snapshot").length,
  ).toBeGreaterThanOrEqual(2);
  expect(requestPaths.filter((path) => path === "/api/v1/driver-time")).toEqual([]);
  assertLoopbackBoundary(page);

  const geometry = await page.evaluate(() => {
    const clippedControls = Array.from(
      document.querySelectorAll<HTMLElement>("button, input, select, textarea"),
    )
      .filter((element) => element.offsetParent !== null)
      .filter((element) => element.scrollWidth > element.clientWidth || element.scrollHeight > element.clientHeight)
      .map((element) => element.getAttribute("aria-label") ?? element.textContent?.trim() ?? element.tagName);
    const documentWidth = Math.max(document.body.scrollWidth, document.documentElement.scrollWidth);
    return {
      clippedControls,
      documentWidth,
      viewportWidth: document.documentElement.clientWidth,
    };
  });
  expect(geometry.documentWidth).toBeLessThanOrEqual(geometry.viewportWidth);
  expect(geometry.clippedControls).toEqual([]);
  const overflowFailures = geometry.clippedControls.length +
    (geometry.documentWidth > geometry.viewportWidth ? 1 : 0);

  const accessibility = await new AxeBuilder({ page }).analyze();
  const accessibilityBlockingFindings = accessibility.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  ).length;
  expect(accessibilityBlockingFindings).toBe(0);

  const storageValues = await page.evaluate((tokenKey) => {
    const values = (storage: Storage) =>
      Array.from({ length: storage.length }, (_, index) => storage.key(index))
        .filter((key): key is string => key !== null)
        .map((key) => storage.getItem(key) ?? "");
    const before = [...values(window.localStorage), ...values(window.sessionStorage)];
    window.sessionStorage.removeItem(tokenKey);
    return {
      before,
      after: [...values(window.localStorage), ...values(window.sessionStorage)],
    };
  }, "openbexi.spell.access-token");
  const secretCanary = process.env.SPELL_BROWSER_SECRET_CANARY!;
  expect(storageValues.before.some((value) => value.includes(secretCanary))).toBe(false);
  expect(storageValues.after.some((value) => value.includes(secretCanary))).toBe(false);

  const project = testInfo.project.name === "mobile" ? "mobile" : "desktop";
  mkdirSync(captureDirectory, { recursive: true });
  const artifactName = `telemetry-observation-${project}`;
  const screenshot = await page.screenshot({
    fullPage: true,
    path: resolve(captureDirectory, `${artifactName}.png`),
  });
  expect(screenshot.includes(Buffer.from(secretCanary, "utf8"))).toBe(false);
  const observation = {
    schema_version: "spell.v07.telemetry-browser-observation/1",
    scope_profile: "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    run_id: process.env.SPELL_BROWSER_RUN_ID,
    source_fingerprint_sha256: process.env.SPELL_SOURCE_FINGERPRINT,
    project,
    source_test: "frontend/e2e/telemetry-observation-real.spec.ts",
    context_id: contextId,
    runtime: {
      node_version: process.version,
      npm_version: process.env.SPELL_NPM_VERSION,
      playwright_version: playwrightVersion,
      browser_name: browser.browserType().name(),
      browser_version: browser.version(),
      project: testInfo.project.name,
      stack_image_ids: Object.fromEntries(
        Object.entries(stackImageEnvironment).map(([component, name]) => [
          component,
          process.env[name],
        ]),
      ),
    },
    assertions: {
      driver_time: true,
      item_ids: [...expectedItemIds],
      quality: "GOOD",
      validity: "VALID",
      freshness: "FRESH",
      alarm: true,
      cursor_websocket: true,
      accessibility_blocking_findings: accessibilityBlockingFindings,
      overflow_failures: overflowFailures,
      mutation_control_count: mutationControlCount,
    },
    screenshot: {
      path: `browser/${artifactName}.png`,
      sha256: createHash("sha256").update(screenshot).digest("hex"),
    },
  };
  const serialized = `${JSON.stringify(observation)}\n`;
  expect(serialized).not.toContain(secretCanary);
  const observationPath = resolve(captureDirectory, `${artifactName}.json`);
  const temporaryPath = `${observationPath}.tmp`;
  writeFileSync(temporaryPath, serialized, { encoding: "utf8", mode: 0o600 });
  renameSync(temporaryPath, observationPath);
});
