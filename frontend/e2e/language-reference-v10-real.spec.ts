import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { stat, writeFile } from "node:fs/promises";

const token = process.env.SPELL_E2E_TOKEN ?? "";

test.skip(
  !process.env.SPELL_REAL_BACKEND || !token,
  "requires the loopback v0.10 stack and a signed operator JWT",
);
test.setTimeout(90_000);

test.beforeEach(async ({ page }) => {
  await page.addInitScript((credential) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", credential);
  }, token);
});

async function authorizedSnapshot(page: Page, executionId: string): Promise<{
  execution: { state: string };
  events: Array<{ event_type: string; payload?: Record<string, unknown> }>;
}> {
  return page.evaluate(async ({ credential, id }) => {
    const response = await fetch(`/api/v1/executions/${encodeURIComponent(id)}/snapshot`, {
      headers: {
        Authorization: `Bearer ${credential}`,
        Accept: "application/json",
        "X-Spell-Session-Id": window.sessionStorage.getItem("openbexi.spell.session-id") ?? "",
        "X-Spell-Client-Instance-Key-Id": window.sessionStorage.getItem("openbexi.spell.client-instance-key") ?? "",
      },
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`snapshot failed with ${response.status}`);
    return response.json();
  }, { credential: token, id: executionId });
}

async function expectHorizontallyContained(page: Page, locator: Locator): Promise<void> {
  await expect(locator).toBeVisible();
  const geometry = await locator.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return {
      left: bounds.left,
      right: bounds.right,
      viewport: document.documentElement.clientWidth,
    };
  });
  expect(geometry.left).toBeGreaterThanOrEqual(-0.5);
  expect(geometry.right).toBeLessThanOrEqual(geometry.viewport + 0.5);
}

test("selects Example 195 through the single v0.10 runner and records PASS evidence", async ({ page }, testInfo) => {
  const externalRequests: string[] = [];
  const controlAttempts: Array<{ status: number; request: Record<string, unknown> }> = [];
  page.on("request", (request) => {
    const host = new URL(request.url()).hostname;
    if (host !== "127.0.0.1" && host !== "localhost") externalRequests.push(request.url());
  });
  page.on("response", (response) => {
    const request = response.request();
    if (
      /\/api\/v1\/executions\/[^/]+\/control$/.test(new URL(response.url()).pathname)
      && request.method() === "POST"
    ) {
      controlAttempts.push({ status: response.status(), request: request.postDataJSON() as Record<string, unknown> });
    }
  });

  const catalogPromise = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/v1/procedures" && response.request().method() === "GET",
  );
  await page.goto("/");
  const catalogResponse = await catalogPromise;
  expect(catalogResponse.status()).toBe(200);
  const catalog = await catalogResponse.json() as { items: Array<{ id: string; name: string; version: string }> };
  expect(catalog.items.map((item) => item.id)).toEqual(["language_reference_244"]);
  expect(catalog.items[0]).toEqual(expect.objectContaining({ version: "0.10" }));
  await expect(
    page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option").filter({ hasText: catalog.items[0]!.name }),
  ).toBeVisible();

  const createPromise = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/v1/executions" && response.request().method() === "POST",
  );
  const controlPromise = page.waitForResponse((response) =>
    /\/api\/v1\/executions\/[^/]+\/control$/.test(new URL(response.url()).pathname)
      && response.request().method() === "POST"
      && response.status() >= 200
      && response.status() < 300,
  );
  await page.getByRole("button", { name: "Start procedure" }).click();

  const createResponse = await createPromise;
  expect(createResponse.status()).toBe(202);
  const createRequest = createResponse.request().postDataJSON() as { procedure_id: string; context_id: string };
  expect(createRequest).toEqual(expect.objectContaining({ procedure_id: "language_reference_244", context_id: "simulator" }));
  const created = await createResponse.json() as { execution: { id: string } };

  const controlResponse = await controlPromise;
  expect(controlResponse.status()).toBe(200);
  expect(controlResponse.request().postDataJSON()).toEqual(expect.objectContaining({ action: "ACQUIRE" }));
  expect(controlAttempts).toEqual(expect.arrayContaining([
    expect.objectContaining({ status: 200, request: expect.objectContaining({ action: "ACQUIRE" }) }),
  ]));
  const successfulAcquireIndex = controlAttempts.findIndex(
    (attempt) => attempt.status >= 200 && attempt.status < 300 && attempt.request.action === "ACQUIRE",
  );
  expect(successfulAcquireIndex).toBeGreaterThanOrEqual(0);
  expect(controlAttempts.slice(0, successfulAcquireIndex).every((attempt) => attempt.status === 409)).toBe(true);
  expect(controlAttempts.slice(successfulAcquireIndex).every((attempt) => attempt.status >= 200 && attempt.status < 300)).toBe(true);

  await expect(page.getByRole("heading", { name: "Select a SPELL 2.4.4 reference example" })).toBeVisible({ timeout: 15_000 });
  const optionList = page.getByRole("radiogroup", { name: "Prompt response" });
  const initialGeometry = await optionList.evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }));
  expect(initialGeometry.scrollHeight).toBeGreaterThan(initialGeometry.clientHeight);
  expect(initialGeometry.clientHeight).toBeLessThanOrEqual(380);
  expect(initialGeometry.scrollWidth).toBeLessThanOrEqual(initialGeometry.clientWidth);

  const search = page.getByRole("searchbox", { name: "Filter 195 examples" });
  await search.fill("195");
  await expect(page.getByText("Showing 1 of 195 examples")).toBeVisible();
  await expect(page.getByRole("button", { name: "Commit response" })).toBeDisabled();
  const example195 = page.getByRole("radio", { name: /Example 195.*extract TM\/TC database values/ });
  await expect(example195).toBeVisible();
  await example195.check();

  const documentGeometry = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(Math.max(documentGeometry.document, documentGeometry.body)).toBeLessThanOrEqual(documentGeometry.viewport);
  const accessibility = await new AxeBuilder({ page }).include(".prompt-panel").analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);

  const answerPromise = page.waitForResponse((response) =>
    /\/api\/v1\/prompts\/[^/]+\/responses$/.test(new URL(response.url()).pathname) && response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Commit response" }).click();
  const answerResponse = await answerPromise;
  expect(answerResponse.status()).toBe(202);
  expect(answerResponse.request().postDataJSON()).toEqual(expect.objectContaining({ action: "COMMIT", value: 194 }));

  await expect(page.getByText("COMPLETED", { exact: true }).first()).toBeVisible({ timeout: 20_000 });
  await expect.poll(async () => (await authorizedSnapshot(page, created.execution.id)).execution.state.toUpperCase(), { timeout: 20_000 }).toBe("COMPLETED");
  const snapshot = await authorizedSnapshot(page, created.execution.id);
  const evidence = snapshot.events.find((event) => event.event_type === "procedure.reference_example_completed");
  expect(evidence?.payload).toEqual(expect.objectContaining({ example_number: 195, status: "PASS", passed: true }));
  expect(evidence?.payload?.assertions).toEqual(expect.arrayContaining([
    expect.objectContaining({ assertion_id: "tmtc.catalog_digest", passed: true }),
  ]));
  expect(evidence?.payload?.trace).toEqual(expect.arrayContaining([
    expect.objectContaining({ operation: "TMTCLookup" }),
  ]));
  expect(externalRequests).toEqual([]);

  const completedGeometry = await page.evaluate(() => {
    const selectors = [
      "#root",
      ".app-frame",
      ".console-header",
      ".status-area",
      ".workspace-tabs",
      ".console-layout",
      ".catalog-pane",
      ".work-region",
      ".instance-master",
      ".execution-workspace",
      ".execution-titlebar",
      ".ownership-row",
      ".command-toolbar",
      ".flow-section",
      ".source-workspace",
      ".data-dock",
      ".dock-tabs",
    ];
    return {
      viewport: document.documentElement.clientWidth,
      scrollX: window.scrollX,
      documentWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
      rootWidth: document.getElementById("root")?.scrollWidth ?? 0,
      bounds: selectors.map((selector) => {
        const element = document.querySelector(selector);
        const rect = element?.getBoundingClientRect();
        return { selector, left: rect?.left ?? -1, right: rect?.right ?? -1 };
      }),
    };
  });
  expect(completedGeometry.scrollX).toBe(0);
  expect(Math.max(
    completedGeometry.documentWidth,
    completedGeometry.bodyWidth,
    completedGeometry.rootWidth,
  )).toBeLessThanOrEqual(completedGeometry.viewport);
  for (const bounds of completedGeometry.bounds) {
    expect(bounds.left, `${bounds.selector} crosses the left viewport edge`).toBeGreaterThanOrEqual(-0.5);
    expect(bounds.right, `${bounds.selector} crosses the right viewport edge`).toBeLessThanOrEqual(completedGeometry.viewport + 0.5);
  }

  const executionWorkspace = page.locator(".execution-workspace");
  for (const target of [
    page.getByRole("tab", { name: "Execution", exact: true }),
    page.getByRole("tab", { name: "Driver foundation", exact: true }),
    page.getByRole("tab", { name: "Data services", exact: true }),
    page.getByRole("heading", { name: "Procedures", exact: true }),
    page.getByRole("button", { name: "Validate source", exact: true }),
    page.getByRole("button", { name: "Start procedure", exact: true }),
    executionWorkspace.getByRole("heading", { name: "Language Reference 244", exact: true }),
    executionWorkspace.getByText("COMPLETED", { exact: true }),
    page.getByRole("button", { name: "As-run report", exact: true }),
  ]) {
    await expectHorizontallyContained(page, target);
  }

  const evidencePath = testInfo.outputPath(`language-reference-example-195-${testInfo.project.name}-evidence.json`);
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  expect((await stat(evidencePath)).size).toBeGreaterThan(0);
  await testInfo.attach(`language-reference-example-195-${testInfo.project.name}-evidence.json`, {
    path: evidencePath,
    contentType: "application/json",
  });
  const screenshotPath = testInfo.outputPath(`language-reference-example-195-${testInfo.project.name}-success.png`);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  expect((await stat(screenshotPath)).size).toBeGreaterThan(0);
  await testInfo.attach(`language-reference-example-195-${testInfo.project.name}-success.png`, {
    path: screenshotPath,
    contentType: "image/png",
  });
});
