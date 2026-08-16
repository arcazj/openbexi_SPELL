import AxeBuilder from "@axe-core/playwright";
import { chromium, expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute, resolve } from "node:path";

const require = createRequire(import.meta.url);
const playwrightVersion = String(require("@playwright/test/package.json").version);
const sha256File = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const nodeExecutableSha256 = sha256File(process.execPath);
const browserExecutableSha256 = sha256File(chromium.executablePath());
const stackImageEnvironment = {
  backend: "SPELL_BACKEND_IMAGE_ID",
  driver: "SPELL_DRIVER_IMAGE_ID",
  pki_init: "SPELL_PKI_IMAGE_ID",
  postgres: "SPELL_POSTGRES_IMAGE_ID",
  proxy: "SPELL_PROXY_IMAGE_ID",
  qualification: "SPELL_QUALIFICATION_IMAGE_ID",
} as const;

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.sessionStorage.setItem("openbexi.spell.access-token", "mock.jwt.token");
  });
});

test("distinguishes every bounded driver fault state without a mutation route", async ({ browser, page }, testInfo) => {
  const driverRequests: Array<{ method: string; path: string }> = [];
  let scenario: "degraded" | "failed" | "disconnected" = "degraded";
  const driver = {
    id: "driver-record-1",
    logical_driver_id: "bundled-simulator",
    server_profile_id: "local-synthetic",
    simulator: true,
    enabled: true,
    current_host_generation_id: "host-generation-4",
    state: "DEGRADED",
    ready: false,
    configuration_schema_version: "1",
    configuration_digest: "a".repeat(64),
    credential_epoch: 3,
    contract_version: "spell.driver.v1",
    implementation_version: "0.4.0",
    capabilities: [
      {
        service: "Lifecycle",
        method: "Health",
        modifiers: ["SAFE", "IDEMPOTENT"],
        formats: ["PROTOBUF_BINARY"],
        mutability: "LIFECYCLE",
        stream_support: "NONE",
      },
    ],
    capacity: {
      max_contexts_per_host: { limit: 1, used: 1, available: 0 },
      max_lifecycle_operations_per_host: { limit: 4, used: 1, available: 3 },
    },
    staleness: "STALE",
    stale: true,
    last_observed_at: "2026-07-19T12:00:00Z",
  };
  const context = {
    context_id: "synthetic-context",
    context_generation_id: "context-generation-2",
    generation_number: 2,
    host_generation_id: "host-generation-4",
    state: "ACTIVE",
    ready: true,
    configuration_schema_version: "1",
    configuration_digest: "b".repeat(64),
    capacity: { max_attachments_per_context: { limit: 1, used: 1, available: 0 } },
    stale: false,
    last_observed_at: "2026-07-19T12:00:00Z",
  };
  const binding = {
    driver_binding_id: "binding-8",
    execution_id: "synthetic-execution-5",
    context_id: context.context_id,
    context_generation_id: context.context_generation_id,
    attachment_generation_number: 3,
    state: "ATTACHED",
    configuration_schema_version: "1",
    configuration_digest: "c".repeat(64),
    latest_operation_id: "operation-13",
    stage: "RECONCILING",
    certainty: "EFFECT_UNKNOWN",
    stale: false,
    last_observed_at: "2026-07-19T12:00:01Z",
  };
  const operation = {
    operation_id: "operation-13",
    method: "AttachExecution",
    current_attempt_number: 1,
    stage: "RECONCILING",
    certainty: "EFFECT_UNKNOWN",
    effect_class: "SIMULATOR_LIFECYCLE",
    requires_reconciliation: true,
    disposition: "TIMED_OUT",
    updated_at: "2026-07-19T12:00:02Z",
    attempts: [
      {
        attempt_id: "attempt-1",
        attempt_number: 1,
        request_digest: "d".repeat(64),
        effect_class: "SIMULATOR_LIFECYCLE",
        host_generation_id: "host-generation-4",
        context_generation_id: context.context_generation_id,
        execution_id: binding.execution_id,
        driver_binding_id: binding.driver_binding_id,
        host_configuration_digest: driver.configuration_digest,
        context_configuration_digest: context.configuration_digest,
        attachment_configuration_digest: binding.configuration_digest,
        credential_epoch: 3,
      },
    ],
    transitions: [
      {
        transition_id: "transition-1",
        sequence: 1,
        attempt_id: "attempt-1",
        stage: "ACCEPTED",
        certainty: "NO_EFFECT",
        created_at: "2026-07-19T12:00:00Z",
      },
      {
        transition_id: "transition-2",
        sequence: 2,
        attempt_id: "attempt-1",
        stage: "RECONCILING",
        certainty: "EFFECT_UNKNOWN",
        created_at: "2026-07-19T12:00:02Z",
      },
    ],
  };
  const failedDriver = {
    ...driver,
    capabilities: [],
    state: "FAILED",
    stale: false,
    staleness: "CURRENT",
  };

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    let body: unknown;

    if (path.startsWith("/api/v1/driver") || path.startsWith("/api/v1/drivers")) {
      driverRequests.push({ method: request.method(), path });
    }

    if (path === "/api/v1/health") {
      body = { status: "ok", version: "0.4.0", mode: "simulator-only" };
    } else if (path === "/api/v1/procedures") {
      body = { items: [] };
    } else if (path === "/api/v1/contexts") {
      body = { items: [{ id: "simulator", name: "Simulator", attached: true, catalog_revision: "library-1", procedure_count: 0, active_execution_count: 0 }] };
    } else if (path === "/api/v1/master") {
      body = { items: [] };
    } else if (path === "/api/v1/drivers") {
      if (scenario === "disconnected") {
        await route.fulfill({
          status: 503,
          contentType: "application/json",
          body: JSON.stringify({ detail: "synthetic projection disconnect" }),
        });
        return;
      }
      body = { items: [scenario === "failed" ? failedDriver : driver], next_cursor: null };
    } else if (path === "/api/v1/drivers/driver-record-1") {
      body = { driver: scenario === "failed" ? failedDriver : driver };
    } else if (path === "/api/v1/driver-contexts") {
      body = { items: [context], next_cursor: null };
    } else if (path === "/api/v1/driver-contexts/synthetic-context/generations/2") {
      body = { context_generation: context };
    } else if (path === "/api/v1/driver-bindings") {
      body = { items: [binding], next_cursor: null };
    } else if (path === "/api/v1/driver-bindings/binding-8") {
      body = { binding };
    } else if (path === "/api/v1/driver-operations/operation-13") {
      body = { operation };
    } else {
      await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ detail: "not found" }) });
      return;
    }

    await route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });

  await page.goto("/");
  const executionTab = page.getByRole("tab", { name: "Execution" });
  const driverTab = page.getByRole("tab", { name: "Driver foundation" });
  await expect(executionTab).toHaveAttribute("aria-selected", "true");
  await executionTab.focus();
  await page.keyboard.press("ArrowRight");
  await expect(driverTab).toBeFocused();
  await expect(driverTab).toHaveAttribute("aria-selected", "true");

  const projection = page.getByRole("main", { name: "Simulator driver foundation" });
  await expect(projection.getByRole("heading", { name: "bundled-simulator" })).toBeVisible();
  await expect(projection.getByText("Simulator only")).toBeVisible();
  await expect(projection.getByText("Read only")).toBeVisible();
  await expect(projection.getByText("synthetic-context")).toBeVisible();
  await expect(projection.getByText("binding-8").first()).toBeVisible();
  await expect(projection.getByText("EFFECT UNKNOWN").first()).toBeVisible();
  await expect(projection.getByText("REQUIRED")).toBeVisible();
  await expect(projection.getByText("SAFE / IDEMPOTENT / PROTOBUF BINARY")).toBeVisible();
  await expect(projection.getByText("NONE")).toBeVisible();

  const mutationControls = [
    "Open context",
    "Close context",
    "Attach execution",
    "Detach execution",
    "Cancel lifecycle operation",
    "Drain host",
  ];
  for (const mutation of mutationControls) {
    await expect(projection.getByRole("button", { name: mutation })).toHaveCount(0);
  }

  await expect.poll(() => driverRequests.length).toBe(7);
  expect(driverRequests.every((request) => request.method === "GET")).toBe(true);
  expect(new Set(driverRequests.map((request) => request.path))).toEqual(
    new Set([
      "/api/v1/drivers",
      "/api/v1/drivers/driver-record-1",
      "/api/v1/driver-contexts",
      "/api/v1/driver-contexts/synthetic-context/generations/2",
      "/api/v1/driver-bindings",
      "/api/v1/driver-bindings/binding-8",
      "/api/v1/driver-operations/operation-13",
    ]),
  );

  const widths = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(Math.max(widths.document, widths.body)).toBeLessThanOrEqual(widths.viewport);

  const clippedButtons = await projection.locator("button").evaluateAll((buttons) =>
    buttons
      .filter((button) => button.scrollWidth > button.clientWidth || button.scrollHeight > button.clientHeight)
      .map((button) => button.getAttribute("aria-label") ?? button.textContent?.trim() ?? "button"),
  );
  expect(clippedButtons).toEqual([]);

  const accessibility = await new AxeBuilder({ page }).analyze();
  const blocking = accessibility.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(blocking).toEqual([]);

  scenario = "failed";
  await page.reload();
  await page.getByRole("tab", { name: "Driver foundation" }).click();
  const failedProjection = page.getByRole("main", { name: "Simulator driver foundation" });
  await expect(failedProjection.getByText("FAILED").first()).toBeVisible();
  await expect(failedProjection.getByText("No capabilities advertised")).toBeVisible();
  await expect(failedProjection.getByText("CURRENT", { exact: true })).toBeVisible();
  for (const mutation of mutationControls) {
    await expect(failedProjection.getByRole("button", { name: mutation })).toHaveCount(0);
  }

  scenario = "disconnected";
  await page.reload();
  await page.getByRole("tab", { name: "Driver foundation" }).click();
  const unavailable = page
    .getByRole("main", { name: "Simulator driver foundation" })
    .getByRole("alert");
  await expect(unavailable).toContainText("Driver projection unavailable");
  await expect(unavailable.getByRole("button", { name: "Retry" })).toBeEnabled();

  const source = process.env.SPELL_SOURCE_FINGERPRINT;
  const runId = process.env.SPELL_BROWSER_RUN_ID;
  const captureDirectory = process.env.SPELL_BROWSER_CAPTURE_DIRECTORY;
  if (
    /^[0-9a-f]{64}$/.test(source ?? "") &&
    /^[0-9a-f]{32}$/.test(runId ?? "") &&
    isAbsolute(captureDirectory ?? "") &&
    process.env.SPELL_NPM_VERSION === "11.6.2" &&
    Object.values(stackImageEnvironment).every((name) =>
      /^sha256:[0-9a-f]{64}$/.test(process.env[name] ?? ""),
    )
  ) {
    const project = testInfo.project.name === "mobile" ? "mobile" : "desktop";
    const directory = captureDirectory!;
    mkdirSync(directory, { recursive: true });
    const destination = resolve(directory, `faults-${project}.json`);
    const temporary = `${destination}.tmp`;
    const observation = {
      schema_version: "spell.v04.browser-fault-observation/1",
      scope_profile: "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
      run_id: runId,
      source_fingerprint_sha256: source,
      project,
      source_test: "frontend/e2e/driver-projection.spec.ts",
      runtime: {
        node_version: process.version,
        npm_version: process.env.SPELL_NPM_VERSION,
        node_executable_path: process.execPath,
        node_executable_sha256: nodeExecutableSha256,
        playwright_version: playwrightVersion,
        browser_name: browser.browserType().name(),
        browser_version: browser.version(),
        browser_executable_path: chromium.executablePath(),
        browser_executable_sha256: browserExecutableSha256,
        project: testInfo.project.name,
        command_profile: `driver-projection-fault:${testInfo.project.name}`,
        stack_image_ids: Object.fromEntries(
          Object.entries(stackImageEnvironment).map(([component, name]) => [
            component,
            process.env[name],
          ]),
        ),
      },
      states: {
        degraded: true,
        disconnected: true,
        failed: true,
        stale: true,
        uncertain: true,
        unsupported: true,
      },
      non_color_cue_count: 6,
      mutation_control_count: 0,
    };
    writeFileSync(temporary, `${JSON.stringify(observation)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(temporary, destination);
  }
});
