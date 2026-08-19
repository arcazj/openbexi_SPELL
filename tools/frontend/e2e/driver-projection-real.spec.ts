import AxeBuilder from "@axe-core/playwright";
import { chromium, expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
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

test.skip(
  !process.env.SPELL_REAL_BACKEND ||
    !process.env.SPELL_E2E_TOKEN ||
    !isAbsolute(process.env.SPELL_BROWSER_CAPTURE_DIRECTORY ?? "") ||
    process.env.SPELL_NPM_VERSION !== "11.6.2" ||
    !/^[0-9a-f]{32}$/.test(process.env.SPELL_BROWSER_RUN_ID ?? "") ||
    !/^[0-9a-f]{64}$/.test(process.env.SPELL_SOURCE_FINGERPRINT ?? "") ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(process.env.SPELL_BROWSER_SECRET_CANARY ?? "") ||
    Object.values(stackImageEnvironment).some(
      (name) => !/^sha256:[0-9a-f]{64}$/.test(process.env[name] ?? ""),
    ),
  "requires the loopback v0.4 Compose stack, a signed viewer token, the source fingerprint, and a synthetic canary",
);

const expectedFixture = {
  binding: "00000000-0000-4000-8000-000000000402",
  context: "v04-ui-synthetic-context",
  operation: "00000000-0000-4000-8000-000000000404",
};

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

async function assertLoopbackNetworkBoundary(page: Page) {
  const allUrls = [...(requestsByPage.get(page) ?? []), ...(socketsByPage.get(page) ?? [])];
  expect(allUrls.length).toBeGreaterThan(0);
  for (const value of allUrls) {
    const url = new URL(value);
    expect(["127.0.0.1", "localhost"]).toContain(url.hostname);
    expect(value).not.toContain("spell-driver");
    expect(value).not.toContain(":50051");
  }
  const socketPaths = (socketsByPage.get(page) ?? []).map((value) => new URL(value).pathname);
  expect(socketPaths).toContain("/api/v1/driver-events/ws");
  return {
    requests: [...new Set(requestsByPage.get(page) ?? [])].sort(),
    websockets: [...new Set(socketsByPage.get(page) ?? [])].sort(),
  };
}

async function assertResponsiveAndAccessible(page: Page) {
  const geometry = await page.evaluate(() => ({
    body: document.body.scrollWidth,
    clippedButtons: Array.from(document.querySelectorAll<HTMLButtonElement>("button"))
      .filter((button) => button.scrollWidth > button.clientWidth || button.scrollHeight > button.clientHeight)
      .map((button) => button.getAttribute("aria-label") ?? button.textContent?.trim() ?? "button"),
    document: document.documentElement.scrollWidth,
    viewport: document.documentElement.clientWidth,
  }));
  expect(Math.max(geometry.body, geometry.document)).toBeLessThanOrEqual(geometry.viewport);
  expect(geometry.clippedButtons).toEqual([]);

  const analysis = await new AxeBuilder({ page }).analyze();
  const blocking = analysis.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(blocking).toEqual([]);
  return {
    axe_critical_finding_count: analysis.violations.filter((item) => item.impact === "critical").length,
    axe_serious_finding_count: analysis.violations.filter((item) => item.impact === "serious").length,
    document_width: Math.max(geometry.body, geometry.document),
    overflow_failure_count: geometry.clippedButtons.length,
    viewport_width: geometry.viewport,
  };
}

test("renders the committed simulator lifecycle projection without a control path", async ({ browser, page }, testInfo) => {
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("CONNECTED");

  const executionTab = page.getByRole("tab", { name: "Execution" });
  const driverTab = page.getByRole("tab", { name: "Driver foundation" });
  await executionTab.focus();
  await page.keyboard.press("ArrowRight");
  await expect(driverTab).toBeFocused();
  await expect(driverTab).toHaveAttribute("aria-selected", "true");

  const projection = page.getByRole("main", { name: "Simulator driver foundation" });
  await expect(projection.getByRole("heading", { name: "bundled-deterministic-simulator" })).toBeVisible();
  await expect(projection.getByText("Simulator only")).toBeVisible();
  await expect(projection.locator(".scope-flag.readonly")).toHaveText("Read only");
  await expect(projection.getByText(expectedFixture.context)).toBeVisible();
  await expect(projection.getByText(expectedFixture.binding).first()).toBeVisible();
  await expect(projection.getByText(expectedFixture.operation)).toBeVisible();
  await expect(projection.getByText("EFFECT CONFIRMED").first()).toBeVisible();
  await expect(projection.getByText("NOT REQUIRED")).toBeVisible();
  await expect(projection.getByRole("heading", { name: "Capabilities" })).toBeVisible();
  await expect(projection.getByRole("heading", { name: "Capacity" })).toBeVisible();

  for (const mutation of [
    "Open context",
    "Close context",
    "Attach execution",
    "Detach execution",
    "Cancel lifecycle operation",
    "Drain host",
  ]) {
    await expect(projection.getByRole("button", { name: mutation })).toHaveCount(0);
  }

  await expect.poll(() => socketsByPage.get(page)?.length ?? 0).toBeGreaterThanOrEqual(1);
  const network = await assertLoopbackNetworkBoundary(page);
  const accessibility = await assertResponsiveAndAccessible(page);
  const storage = await page.evaluate(
    ({ canary, tokenKey }) => {
      const entries = (area: Storage) =>
        Array.from({ length: area.length }, (_, index) => area.key(index))
          .filter((key): key is string => key !== null)
          .sort()
          .map((key) => ({ key, value: area.getItem(key) ?? "" }));
      const localBefore = entries(window.localStorage);
      const sessionBefore = entries(window.sessionStorage);
      const allBefore = [...localBefore, ...sessionBefore];
      const serviceSecretCanaryMatchCount = allBefore.filter(({ value }) => value.includes(canary)).length;
      const ephemeralAuthTokenCount = sessionBefore.filter(({ key }) => key === tokenKey).length;
      window.sessionStorage.removeItem(tokenKey);
      return {
        inspected_key_count: allBefore.length,
        inspected_value_count: allBefore.length,
        service_secret_canary_match_count: serviceSecretCanaryMatchCount,
        removed_ephemeral_auth_token_count: ephemeralAuthTokenCount,
        local_storage: entries(window.localStorage),
        session_storage: entries(window.sessionStorage),
      };
    },
    {
      canary: process.env.SPELL_BROWSER_SECRET_CANARY!,
      tokenKey: "openbexi.spell.access-token",
    },
  );
  expect(storage.service_secret_canary_match_count).toBe(0);
  expect(storage.removed_ephemeral_auth_token_count).toBe(1);
  expect(storage.local_storage).toEqual([]);
  expect(storage.session_storage).toEqual([]);
  const profile = testInfo.project.name === "mobile" ? "mobile" : "desktop";
  const artifactDirectory = process.env.SPELL_BROWSER_CAPTURE_DIRECTORY!;
  mkdirSync(artifactDirectory, { recursive: true });
  const screenshotRelativePath = `artifacts/v0.4/driver-projection-${profile}.png`;
  const screenshotPath = resolve(artifactDirectory, `driver-projection-${profile}.png`);
  const screenshot = await page.screenshot({
    fullPage: true,
    path: screenshotPath,
  });
  const observation = {
    schema_version: "spell.v04.browser-observation/1",
    scope_profile: "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR",
    run_id: process.env.SPELL_BROWSER_RUN_ID,
    source_fingerprint_sha256: process.env.SPELL_SOURCE_FINGERPRINT,
    project: profile,
    source_test: "frontend/e2e/driver-projection-real.spec.ts",
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
      command_profile: `driver-projection-real:${testInfo.project.name}`,
      stack_image_ids: Object.fromEntries(
        Object.entries(stackImageEnvironment).map(([component, name]) => [
          component,
          process.env[name],
        ]),
      ),
    },
    fixture: expectedFixture,
    viewport: page.viewportSize(),
    accessibility,
    interaction: {
      keyboard_failure_count: 0,
      mutation_control_count: 0,
    },
    network,
    storage,
    screenshot: {
      path: screenshotRelativePath,
      sha256: createHash("sha256").update(screenshot).digest("hex"),
    },
  };
  const observationPath = resolve(artifactDirectory, `${profile}.json`);
  const temporaryPath = `${observationPath}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(observation)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(temporaryPath, observationPath);
});
