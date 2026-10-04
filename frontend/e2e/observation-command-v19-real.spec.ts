import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Locator, type Page, type Response, type TestInfo } from "@playwright/test";
import { createHash } from "node:crypto";
import { ensureDssObservationReady } from "./dss-readiness";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the real local v0.19 simulator");
test.setTimeout(180_000);
const profile = "spell-lrm244-conformance/0.19";
const adminToken = process.env.SPELL_E2E_REVIEW_TOKEN ?? "";
const question = "Run the observed simulator command?";

type Snapshot = {
  execution: { state: string; operator_state: string; variables: Record<string, unknown>; procedure_hash: string; allowed_actions: string[]; controller_lease: { holder_subject_id: string } | null };
  active_prompt: { id: string; prompt_profile: string | null } | null;
};
type Event = { event_type: string; payload: { request_id?: string; operation?: string; outcome?: string; value?: unknown; step_index?: number; checkpoint?: { confirmed_by: string | null; provider_call_count: number } } };

async function request<T>(page: Page, path: string, body?: unknown, token?: string): Promise<T> {
  return page.evaluate(async ({ path, body, token }) => {
    const response = await fetch(path, { method: body === undefined ? "GET" : "POST", headers: {
      Authorization: `Bearer ${token ?? sessionStorage.getItem("openbexi.spell.access-token") ?? ""}`,
      "Content-Type": "application/json",
      "X-Spell-Session-Id": sessionStorage.getItem("openbexi.spell.session-id") ?? "",
      "X-Spell-Client-Instance-Key-Id": sessionStorage.getItem("openbexi.spell.client-instance-key") ?? "",
    }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: "no-store" });
    if (!response.ok) throw new Error(`workflow proof request failed (${response.status})`);
    return response.json();
  }, { path, body, token }) as Promise<T>;
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await ensureDssObservationReady(page);
});

async function clickMutation(page: Page, suffix: string, button: Locator, method = "POST") {
  await expect(button).toBeEnabled();
  const [response] = await Promise.all([
    page.waitForResponse((item) => new URL(item.url()).pathname.endsWith(suffix) && item.request().method() === method),
    button.click(),
  ]);
  expect(response.ok(), `${method} ${suffix} must succeed`).toBe(true);
  return response;
}

async function area(page: Page, name: "Explorer" | "Editor" | "Problems" | "Activity") {
  if ((page.viewportSize()?.width ?? 1440) <= 820) {
    await page.getByRole("navigation", { name: "Development areas" }).getByRole("button", { name }).click();
  }
}

async function workspaceRefreshed(page: Page, response: Response) {
  const body = await response.json() as { workspace_revision?: number; project?: { workspace_revision: number } };
  const revision = body.project?.workspace_revision ?? body.workspace_revision;
  expect(revision).toEqual(expect.any(Number));
  await expect(page.locator(".dev-workspace")).toHaveAttribute("data-workspace-revision", String(revision));
  await expect(page.locator(".dev-workspace")).toHaveAttribute("aria-busy", "false");
}

async function identity(page: Page, token: string, role: "operator" | "admin") {
  await page.evaluate((value) => { sessionStorage.setItem("openbexi.spell.access-token", value); window.dispatchEvent(new Event("spell-auth-changed")); }, token);
  await expect(page.locator(".dev-session small")).toHaveText(role);
}

async function openConsole(page: Page, testInfo: TestInfo) {
  if (testInfo.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await expect(page.getByText("Session access", { exact: true })).toHaveCount(0);
}

async function start(page: Page, name: string): Promise<string> {
  const option = page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option").filter({ hasText: name });
  await expect(option).toBeVisible();
  await option.click();
  const response = await clickMutation(page, "/api/v1/executions", page.getByRole("button", { name: "Start procedure" }));
  return ((await response.json()) as { execution: { id: string } }).execution.id;
}

async function snapshot(page: Page, id: string) { return request<Snapshot>(page, `/api/v1/executions/${id}/snapshot`); }
async function events(page: Page, id: string) { return (await request<{ items: Event[] }>(page, `/api/v1/executions/${id}/events?limit=1000`)).items; }
async function state(page: Page, id: string, expected: string) {
  await expect.poll(async () => (await snapshot(page, id)).execution.state, { timeout: 25_000 }).toBe(expected);
  const authoritative = await snapshot(page, id);
  await expect(page.locator(".execution-metadata .state-pill")).toHaveText(authoritative.execution.operator_state.toUpperCase(), { timeout: 15_000 });
}
async function answer(page: Page, value: "YES" | "NO") {
  await page.getByRole("radio", { name: value, exact: true }).check();
  await clickMutation(page, "/responses", page.getByRole("button", { name: "Commit response" }));
}
async function noDispatch(page: Page, id: string) {
  const rows = await events(page, id);
  expect(rows.filter((row) => ["procedure.telecommand_requested", "procedure.telecommand_result", "procedure.telecommand_settled"].includes(row.event_type))).toEqual([]);
}
async function capture(page: Page, testInfo: TestInfo, name: string) {
  const accessibility = await new AxeBuilder({ page }).include(".execution-workspace").analyze();
  expect(accessibility.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
  const geometry = await page.evaluate(() => ({ width: document.documentElement.clientWidth, content: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) }));
  expect(geometry.content).toBeLessThanOrEqual(geometry.width);
  const table = page.getByRole("table", { name: "Tabular procedure source" });
  const sourceBounds = await page.locator(".tabular-scroll").boundingBox();
  for (const heading of ["Code", "Data", "Result"]) {
    const bounds = await table.getByRole("columnheader", { name: heading, exact: true }).boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(sourceBounds!.x);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(sourceBounds!.x + sourceBounds!.width + 1);
  }
  const code = table.locator(".source-text code").filter({ hasText: "condition=" }).first();
  await code.focus();
  await code.press("ArrowRight");
  await expect.poll(() => code.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
  await code.press("ArrowLeft");
  await expect.poll(() => code.evaluate((element) => element.scrollLeft)).toBe(0);
  await page.screenshot({ path: testInfo.outputPath(`${name}-${testInfo.project.name}.png`), fullPage: true });
}

test("authors and promotes the exact observation workflow before independently confirmed dispatch", async ({ page }, testInfo) => {
  expect(Boolean(adminToken), "real authoring qualification requires a distinct reviewer credential").toBe(true);
  if (testInfo.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/development.html");
  await expect(page.locator(".dev-session small")).toHaveText("operator", { timeout: 20_000 });
  const authorToken = await page.evaluate(() => sessionStorage.getItem("openbexi.spell.access-token")!);
  const demo = await request<{ source: string }>(page, "/api/v1/procedures/observation_command_v19");
  const runId = (process.env.SPELL_BROWSER_RUN_ID ?? String(Date.now())).replace(/[^A-Za-z0-9]/g, "").slice(-12);
  const procedureId = `qualification-v19-${testInfo.project.name}-${runId}`;
  const source = [`# @procedure ${procedureId}`, `# @language-profile ${profile}`, ...demo.source.split("\n").filter((line) => !/^#\s*@(?:procedure|display-name|language-profile)\b/.test(line))].join("\n");
  const sourceDigest = createHash("sha256").update(source).digest("hex");
  let bundleDigest: string | null = null;
  let promoted = false;
  try {
    await area(page, "Explorer");
    await page.getByRole("button", { name: "Create project" }).first().click();
    const dialog = page.getByRole("dialog", { name: "Create project" });
    await dialog.getByLabel("Project name").fill(`Observation ${runId} ${testInfo.project.name}`);
    await expect(dialog.getByLabel("Language profile")).toHaveValue(profile);
    const projectResponse = await clickMutation(page, "/api/v1/development/projects", dialog.getByRole("button", { name: "Apply", exact: true }));
    const project = ((await projectResponse.json()) as { project: { project_id: string; owner_subject: string } }).project;
    const projectId = project.project_id;
    await expect(page.getByRole("combobox", { name: "Project" })).toHaveValue(projectId);
    await area(page, "Explorer");
    await page.getByRole("button", { name: "New procedure" }).click();
    const creation = page.getByRole("dialog", { name: "Create procedure" });
    await creation.getByLabel("Project-relative path").fill(`src/${procedureId}.spell.py`);
    const resourceResponse = await clickMutation(page, "/resources", creation.getByRole("button", { name: "Apply", exact: true }));
    const resource = ((await resourceResponse.json()) as { resource: { resource_id: string } }).resource;
    await workspaceRefreshed(page, resourceResponse);
    await area(page, "Problems");
    await page.getByRole("checkbox", { name: "Check on save" }).uncheck();
    await area(page, "Editor");
    const editor = page.getByLabel("Procedure source editor");
    await expect(editor).toHaveValue(new RegExp(`# @language-profile ${profile.replaceAll(".", "\\.")}`));
    await editor.fill(source);
    const saveResponse = await clickMutation(page, `/resources/${resource.resource_id}`, page.getByRole("button", { name: "Save resource" }), "PUT");
    await workspaceRefreshed(page, saveResponse);
    await area(page, "Problems");
    const checkResponse = await clickMutation(page, "/checks", page.getByRole("button", { name: "Run semantic check" }));
    const jobId = ((await checkResponse.json()) as { job: { job_id: string } }).job.job_id;
    await expect.poll(async () => (await request<{ job: { state: string } }>(page, `/api/v1/development/checks/${jobId}`)).job.state, { timeout: 30_000 }).toBe("COMPLETED");
    const check = await request<{ outcome: string; language_profile: string }>(page, `/api/v1/development/checks/${jobId}/report`);
    expect(check).toMatchObject({ outcome: "PASS", language_profile: profile });
    await area(page, "Activity");
    await page.getByRole("tab", { name: "History", exact: true }).click();
    await page.getByLabel("Commit message").fill("Reviewed observation-to-command workflow");
    await clickMutation(page, "/history", page.getByRole("button", { name: "Commit all changes" }));
    await identity(page, adminToken, "admin");
    await clickMutation(page, "/review", page.getByRole("button", { name: /Approve revision/ }));
    await identity(page, authorToken, "operator");
    const buildResponse = await clickMutation(page, "/bundles", page.getByRole("button", { name: /Build bundle/ }));
    const bundle = ((await buildResponse.json()) as { bundle: { bundle_digest: string; manifest: { language_profile: string; ir_schema_version: string[]; review_subject: string } } }).bundle;
    bundleDigest = bundle.bundle_digest;
    expect(bundle.manifest.language_profile).toBe(profile);
    expect(bundle.manifest.ir_schema_version).toEqual(["0.19"]);
    expect(bundle.manifest.review_subject).not.toBe(project.owner_subject);
    await identity(page, adminToken, "admin");
    await page.getByRole("tab", { name: "Bundles and promotion" }).click();
    await clickMutation(page, "/approve", page.getByRole("button", { name: `Approve bundle ${bundleDigest}`, exact: true }));
    await clickMutation(page, "/decisions", page.getByRole("button", { name: `Promote bundle ${bundleDigest}`, exact: true }));
    promoted = true;
    const admitted = await request<{ name: string; source: string; sha256: string; bundle_digest: string }>(page, `/api/v1/procedures/${procedureId}`);
    expect(admitted.source).toBe(source);
    expect(admitted.sha256).toBe(sourceDigest);
    expect(admitted.bundle_digest).toBe(bundleDigest);
    await identity(page, authorToken, "operator");
    await openConsole(page, testInfo);
    const id = await start(page, admitted.name);
    await expect(page.getByRole("heading", { name: question, exact: true })).toBeVisible({ timeout: 25_000 });
    const waiting = await snapshot(page, id);
    expect(waiting.execution.procedure_hash).toBe(sourceDigest);
    expect(waiting.execution.variables.status).toBe("TRUE");
    expect(waiting.execution.variables.reading).toEqual(expect.any(Number));
    expect(Number(waiting.execution.variables.reading)).toBeGreaterThanOrEqual(0);
    expect(waiting.execution.allowed_actions).not.toContain("skip");
    expect(waiting.execution.allowed_actions).not.toContain("goto");
    await expect(page.getByRole("button", { name: "Skip", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Goto", exact: true })).toBeDisabled();
    await noDispatch(page, id);
    await answer(page, "YES");
    await expect(page.getByRole("heading", { name: /^Confirm deterministic simulator telecommand plan / })).toBeVisible();
    const confirmation = await snapshot(page, id);
    expect(confirmation.active_prompt!.id).not.toBe(waiting.active_prompt!.id);
    expect(confirmation.active_prompt!.prompt_profile).toBeNull();
    const actor = confirmation.execution.controller_lease!.holder_subject_id;
    // The simulator checkpoint records the same bounded alias as the durable TC service.
    const confirmedBy = `operator-${createHash("sha256").update(actor, "utf8").digest("hex").slice(0, 32)}`;
    await noDispatch(page, id);
    await answer(page, "YES");
    await state(page, id, "completed");
    const rows = await events(page, id);
    const observations = rows.filter((item) => item.event_type === "procedure.observation_result");
    expect(observations.map((item) => item.payload.outcome)).toEqual(["OK", "TRUE", "SATISFIED"]);
    const observationRequests = rows.filter((item) => item.event_type === "procedure.observation_requested");
    expect(observationRequests.map((item) => item.payload.request_id)).toEqual(observations.map((item) => item.payload.request_id));
    const commands = rows.filter((item) => item.event_type === "procedure.telecommand_requested");
    const results = rows.filter((item) => item.event_type === "procedure.telecommand_result");
    expect(commands).toHaveLength(1);
    expect(results).toHaveLength(1);
    expect(results[0]!.payload).toMatchObject({ request_id: commands[0]!.payload.request_id, outcome: "SETTLED", checkpoint: { provider_call_count: 5, confirmed_by: confirmedBy } });
    expect(rows.filter((item) => item.event_type === "procedure.telecommand_settled")).toHaveLength(1);
    const readingLine = source.split("\n").findIndex((line) => line.startsWith("GetTM(")) + 1;
    const readingRow = page.getByRole("row", { name: new RegExp(`^Line ${readingLine}(?:,|$)`) });
    await expect(readingRow.locator(".line-data")).toContainText("TM.POWER.BUS_VOLTAGE");
    await expect(readingRow.locator(".line-result")).toHaveText("OK");
    await capture(page, testInfo, "observation-authoring-dispatch");
  } finally {
    if (promoted && bundleDigest) await request(page, `/api/v1/development/catalog/${procedureId}/decisions`, {
      operation: "WITHDRAW", bundle_digest: bundleDigest, expected_registry_revision: 1,
      reason: "Completed isolated v19 browser qualification", idempotency_key: `withdraw-${procedureId}`,
    }, adminToken);
  }
});

test("false observations, native NO and Abort, and wait timeout preserve zero command dispatch", async ({ page }, testInfo) => {
  await openConsole(page, testInfo);
  const declined = await start(page, "Observation Decision V19");
  await state(page, declined, "completed");
  expect((await snapshot(page, declined)).execution.variables.status).toBe("FALSE");
  expect((await events(page, declined)).filter((item) => item.event_type === "procedure.observation_result").map((item) => item.payload.outcome)).toContain("FALSE");
  await noDispatch(page, declined);
  const no = await start(page, "Observation Command V19");
  await expect(page.getByRole("heading", { name: question, exact: true })).toBeVisible({ timeout: 25_000 });
  await answer(page, "NO");
  await state(page, no, "completed");
  expect((await snapshot(page, no)).execution.variables.answer).toBe("NO");
  await noDispatch(page, no);
  const aborted = await start(page, "Observation Command V19");
  await expect(page.getByRole("heading", { name: question, exact: true })).toBeVisible({ timeout: 25_000 });
  await page.getByRole("button", { name: "Abort prompt" }).click();
  await state(page, aborted, "aborted");
  expect((await snapshot(page, aborted)).execution.variables.answer).toBe("");
  await noDispatch(page, aborted);
  const timedOut = await start(page, "Observation Wait V19");
  await state(page, timedOut, "failed");
  const before = await events(page, timedOut);
  expect(before.filter((item) => item.event_type === "procedure.observation_result").map((item) => item.payload.outcome)).toContain("TIMED_OUT");
  await noDispatch(page, timedOut);
  await page.getByRole("button", { name: "Reconnect simulator", exact: true }).click();
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await page.getByRole("button", { name: "Refresh authoritative snapshot" }).click();
  await state(page, timedOut, "failed");
  expect((await events(page, timedOut)).filter((item) => item.event_type === "procedure.observation_result")).toEqual(before.filter((item) => item.event_type === "procedure.observation_result"));
  await noDispatch(page, timedOut);
  await expect(page.getByRole("row").filter({ hasText: "WaitFor(condition=" }).locator(".line-result")).toHaveText("TIMED_OUT");
  await expect(page.locator(".compatibility-control")).toHaveCount(1);
  await capture(page, testInfo, "observation-no-dispatch");
});
