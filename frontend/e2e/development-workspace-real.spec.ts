import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Response, type TestInfo } from "@playwright/test";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

const operatorToken = process.env.SPELL_E2E_OPERATOR_TOKEN ?? "";
const adminToken = process.env.SPELL_E2E_ADMIN_TOKEN ?? "";

test.skip(
  !process.env.SPELL_REAL_BACKEND || !operatorToken || !adminToken,
  "requires the loopback v0.9 stack plus distinct signed operator and admin JWTs",
);
test.setTimeout(120_000);

function tokenSubject(token: string): string {
  const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")) as { sub?: unknown };
  return typeof payload.sub === "string" ? payload.sub : "";
}

function capturePath(testInfo: TestInfo, name: string): string {
  const directory = process.env.SPELL_E2E_ARTIFACT_DIRECTORY;
  return directory ? resolve(process.cwd(), directory, name) : testInfo.outputPath(name);
}

async function setIdentity(page: Page, token: string, role: "operator" | "admin") {
  await page.evaluate((credential) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", credential);
    window.dispatchEvent(new Event("spell-auth-changed"));
  }, token);
  await expect(page.locator(".dev-session small")).toHaveText(role);
}

async function openMobileArea(page: Page, label: "Explorer" | "Editor" | "Problems" | "Activity") {
  if ((page.viewportSize()?.width ?? 1000) > 820) return;
  const button = page.getByRole("navigation", { name: "Development areas" }).getByRole("button", { name: label });
  await expect(button).toBeVisible();
  await button.click();
}

type ResponseMatcher = (response: Response) => boolean;

async function waitForSuccessfulResponse(
  page: Page,
  description: string,
  matches: ResponseMatcher,
  action: () => Promise<unknown>,
  timeout = 15_000,
): Promise<Response> {
  const failures: Response[] = [];
  const observe = (response: Response) => {
    if (matches(response) && !response.ok()) failures.push(response);
  };
  page.on("response", observe);
  try {
    const responsePromise = page.waitForResponse(
      (response) => matches(response) && response.ok(),
      { timeout },
    );
    const [response] = await Promise.all([responsePromise, action()]);
    return response;
  } catch (caught) {
    const diagnostics = await Promise.all(failures.slice(-3).map(async (response) => {
      const body = await response.text().catch(() => "<body unavailable>");
      return `${response.request().method()} ${response.status()} ${response.url()} ${body.slice(0, 1024)}`;
    }));
    const cause = caught instanceof Error ? caught.message : String(caught);
    throw new Error(`${description} did not return a terminal 2xx response within ${timeout}ms.${diagnostics.length > 0 ? `\nObserved non-2xx responses:\n${diagnostics.join("\n")}` : ""}\nCause: ${cause}`);
  } finally {
    page.off("response", observe);
  }
}

function workspaceRevisionFrom(body: unknown): number | null {
  if (!body || typeof body !== "object") return null;
  const record = body as {
    workspace_revision?: unknown;
    project?: { workspace_revision?: unknown };
  };
  const revision = record.project?.workspace_revision ?? record.workspace_revision;
  return typeof revision === "number" && Number.isInteger(revision) && revision >= 0 ? revision : null;
}

async function waitForWorkspaceRefresh(page: Page, response: Response): Promise<number> {
  const revision = workspaceRevisionFrom(await response.json());
  expect(revision, "mutation response must identify its workspace revision").not.toBeNull();
  const workspace = page.locator(".dev-workspace");
  await expect(workspace).toHaveAttribute("data-workspace-revision", String(revision));
  await expect(workspace).toHaveAttribute("aria-busy", "false");
  return revision!;
}

interface BoundSession {
  session_id: string;
  client_instance_key_id: string;
}

interface AuthorizedResponse<T> {
  status: number;
  statusText: string;
  body: T;
}

async function boundSession(page: Page): Promise<BoundSession> {
  return page.evaluate(() => {
    const sessionKey = "openbexi.spell.session-id";
    const clientKey = "openbexi.spell.client-instance-key";
    const sessionId = window.sessionStorage.getItem(sessionKey) ?? crypto.randomUUID();
    const clientId = window.sessionStorage.getItem(clientKey) ?? crypto.randomUUID();
    window.sessionStorage.setItem(sessionKey, sessionId);
    window.sessionStorage.setItem(clientKey, clientId);
    return { session_id: sessionId, client_instance_key_id: clientId };
  });
}

async function authorizedRequest<T>(
  page: Page,
  path: string,
  token: string,
  init: { method?: string; body?: unknown } = {},
): Promise<AuthorizedResponse<T>> {
  const binding = await boundSession(page);
  return page.evaluate(async ({ requestPath, credential, requestInit, requestBinding }) => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${credential}`,
      Accept: "application/json",
      "X-Spell-Session-Id": requestBinding.session_id,
      "X-Spell-Client-Instance-Key-Id": requestBinding.client_instance_key_id,
    };
    if (requestInit.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(requestPath, {
      method: requestInit.method ?? "GET",
      headers,
      body: requestInit.body === undefined ? undefined : JSON.stringify(requestInit.body),
      cache: "no-store",
    });
    const text = await response.text();
    let body: unknown = null;
    if (text) {
      try {
        body = JSON.parse(text) as unknown;
      } catch {
        body = text;
      }
    }
    return { status: response.status, statusText: response.statusText, body };
  }, { requestPath: path, credential: token, requestInit: init, requestBinding: binding }) as Promise<AuthorizedResponse<T>>;
}

async function authorizedJson<T>(page: Page, path: string, token: string): Promise<T> {
  const response = await authorizedRequest<T>(page, path, token);
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`GET ${path} failed (${response.status} ${response.statusText})`);
  }
  return response.body;
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript((credential) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", credential);
  }, operatorToken);
});

test("authors, reviews, promotes, and admits a real v0.9 procedure", async ({ page }, testInfo) => {
  expect(tokenSubject(operatorToken)).not.toBe(tokenSubject(adminToken));
  const externalRequests: string[] = [];
  page.on("request", (request) => {
    const host = new URL(request.url()).hostname;
    if (host !== "127.0.0.1" && host !== "localhost") externalRequests.push(request.url());
  });

  const runId = (process.env.SPELL_BROWSER_RUN_ID ?? `${Date.now()}`).replace(/[^A-Za-z0-9_.-]/g, "-").slice(0, 48);
  const projectName = `V09 ${runId} ${testInfo.project.name}`;
  const procedureId = `qualification-${testInfo.project.name}`;
  const procedurePath = `src/${procedureId}.spell.py`;
  const commitMessage = `Validated ${procedureId}`;

  await page.goto("/development.html");
  await expect(page.getByText("Development environment")).toBeVisible();
  await openMobileArea(page, "Explorer");

  await page.getByRole("button", { name: "Create project" }).first().click();
  const createProjectDialog = page.getByRole("dialog", { name: "Create project" });
  await createProjectDialog.getByLabel("Project name").fill(projectName);
  await createProjectDialog.getByLabel("Filename case policy").selectOption("CASE_SENSITIVE");
  const projectResponse = await waitForSuccessfulResponse(
    page,
    "project creation",
    (response) => response.url().endsWith("/api/v1/development/projects") && response.request().method() === "POST",
    () => createProjectDialog.getByRole("button", { name: "Apply", exact: true }).click(),
  );
  expect(projectResponse.status()).toBe(200);
  const projectBody = await projectResponse.json() as { project?: { project_id: string }; project_id?: string };
  const projectId = projectBody.project?.project_id ?? projectBody.project_id;
  expect(projectId).toBeTruthy();
  await expect(page.getByRole("combobox", { name: "Project" })).toHaveValue(projectId!);
  await expect(page.getByRole("combobox", { name: "Project" }).locator("option:checked")).toHaveText(projectName);
  await openMobileArea(page, "Explorer");
  await expect(page.getByRole("complementary", { name: "Project explorer" })).toBeVisible();

  await page.getByRole("button", { name: "New procedure" }).click();
  const createProcedureDialog = page.getByRole("dialog", { name: "Create procedure" });
  await createProcedureDialog.getByLabel("Project-relative path").fill(procedurePath);
  const resourceResponse = await waitForSuccessfulResponse(
    page,
    "procedure creation",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().endsWith("/resources") && response.request().method() === "POST",
    () => createProcedureDialog.getByRole("button", { name: "Apply", exact: true }).click(),
  );
  expect(resourceResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, resourceResponse);

  await openMobileArea(page, "Problems");
  const checkOnSave = page.getByRole("checkbox", { name: "Check on save" });
  await expect(checkOnSave).toBeVisible();
  await checkOnSave.uncheck();
  await openMobileArea(page, "Editor");
  const editor = page.getByLabel("Procedure source editor");
  await expect(editor).toHaveValue(new RegExp(`# @procedure ${procedureId}`));
  await editor.fill(`${await editor.inputValue()}Log('real qualification edit')\n`);
  const saveResponse = await waitForSuccessfulResponse(
    page,
    "resource save",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().includes("/resources/") && response.request().method() === "PUT",
    () => page.getByRole("button", { name: "Save resource" }).click(),
  );
  expect(saveResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, saveResponse);

  const beforePromotion = await authorizedJson<{ items: Array<{ id: string }> }>(page, "/api/v1/procedures", operatorToken);
  expect(beforePromotion.items.some((item) => item.id === procedureId)).toBe(false);

  await openMobileArea(page, "Problems");
  const runCheck = page.getByRole("button", { name: "Run semantic check" });
  await expect(runCheck).toBeEnabled();
  const checkResponse = await waitForSuccessfulResponse(
    page,
    "semantic check start",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().endsWith("/checks") && response.request().method() === "POST",
    () => runCheck.click(),
  );
  expect(checkResponse.status()).toBe(200);
  const checkBody = await checkResponse.json() as { job?: { job_id: string }; job_id?: string };
  const jobId = checkBody.job?.job_id ?? checkBody.job_id;
  expect(jobId).toBeTruthy();
  await expect.poll(async () => {
    const body = await authorizedJson<{ job?: { state: string }; state?: string }>(page, `/api/v1/development/checks/${jobId}`, operatorToken);
    return body.job?.state ?? body.state;
  }, { timeout: 30_000 }).toBe("COMPLETED");
  const completedCheck = await authorizedJson<{ job: { report_sha256: string } }>(page, `/api/v1/development/checks/${jobId}`, operatorToken);
  expect(completedCheck.job.report_sha256).toMatch(/^[0-9a-f]{64}$/);
  const reportDownloadPromise = page.waitForEvent("download");
  const reportButton = page.getByRole("button", { name: "Download semantic report" });
  await expect(reportButton).toBeEnabled();
  await reportButton.click();
  const reportDownload = await reportDownloadPromise;
  expect(reportDownload.suggestedFilename()).toBe(`${jobId}.semantic-report.json`);
  const reportStream = await reportDownload.createReadStream();
  const reportChunks: Buffer[] = [];
  for await (const chunk of reportStream) reportChunks.push(Buffer.from(chunk));
  expect(createHash("sha256").update(Buffer.concat(reportChunks)).digest("hex")).toBe(completedCheck.job.report_sha256);

  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "History", exact: true }).click();
  await page.getByLabel("Commit message").fill(commitMessage);
  const commitResponse = await waitForSuccessfulResponse(
    page,
    "history commit",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().endsWith("/history") && response.request().method() === "POST",
    () => page.getByRole("button", { name: "Commit all changes" }).click(),
  );
  expect(commitResponse.status()).toBe(200);
  await expect(page.getByText(commitMessage, { exact: true })).toBeVisible();

  await setIdentity(page, adminToken, "admin");
  const approveRevision = page.getByRole("button", { name: /Approve revision/ });
  await expect(approveRevision).toBeEnabled();
  const reviewResponse = await waitForSuccessfulResponse(
    page,
    "history review",
    (response) => response.url().includes("/api/v1/development/history/") && response.url().endsWith("/review") && response.request().method() === "POST",
    () => approveRevision.click(),
  );
  expect(reviewResponse.status()).toBe(200);

  await setIdentity(page, operatorToken, "operator");
  const buildBundle = page.getByRole("button", { name: /Build bundle/ });
  await expect(buildBundle).toBeEnabled();
  const buildResponse = await waitForSuccessfulResponse(
    page,
    "bundle build",
    (response) => response.url().includes("/api/v1/development/history/") && response.url().endsWith("/bundles") && response.request().method() === "POST",
    () => buildBundle.click(),
  );
  expect(buildResponse.status()).toBe(200);
  const buildBody = await buildResponse.json() as { bundle: { bundle_digest: string } };
  const bundleDigest = buildBody.bundle.bundle_digest;
  expect(bundleDigest).toMatch(/^[0-9a-f]{64}$/);

  await setIdentity(page, adminToken, "admin");
  await page.getByRole("tab", { name: "Bundles and promotion" }).click();
  const approveBundle = page.getByRole("button", { name: `Approve bundle ${bundleDigest}`, exact: true });
  await expect(approveBundle).toBeEnabled();
  const approvalResponse = await waitForSuccessfulResponse(
    page,
    "bundle approval",
    (response) => response.url().endsWith(`/api/v1/development/bundles/${bundleDigest}/approve`) && response.request().method() === "POST",
    () => approveBundle.click(),
  );
  expect(approvalResponse.status()).toBe(200);

  const promoteBundle = page.getByRole("button", { name: `Promote bundle ${bundleDigest}`, exact: true });
  await expect(promoteBundle).toBeEnabled();
  const promotionResponse = await waitForSuccessfulResponse(
    page,
    "bundle promotion",
    (response) => response.url().endsWith(`/api/v1/development/catalog/${procedureId}/decisions`) && response.request().method() === "POST",
    () => promoteBundle.click(),
  );
  expect(promotionResponse.status()).toBe(200);
  await expect(page.locator(".dev-runtime-admission span")).toContainText(bundleDigest.slice(0, 10));

  const afterPromotion = await authorizedJson<{ items: Array<{ id: string; bundle_digest?: string }> }>(page, "/api/v1/procedures", adminToken);
  expect(afterPromotion.items).toContainEqual(expect.objectContaining({ id: procedureId, bundle_digest: bundleDigest }));

  const geometry = await page.evaluate(() => ({
    viewportWidth: document.documentElement.clientWidth,
    viewportHeight: document.documentElement.clientHeight,
    documentWidth: document.documentElement.scrollWidth,
    documentHeight: document.documentElement.scrollHeight,
    bodyWidth: document.body.scrollWidth,
    bodyHeight: document.body.scrollHeight,
    scrollX: window.scrollX,
    scrollY: window.scrollY,
  }));
  expect(Math.max(geometry.documentWidth, geometry.bodyWidth)).toBeLessThanOrEqual(geometry.viewportWidth);
  expect(Math.max(geometry.documentHeight, geometry.bodyHeight)).toBeLessThanOrEqual(geometry.viewportHeight);
  expect({ scrollX: geometry.scrollX, scrollY: geometry.scrollY }).toEqual({ scrollX: 0, scrollY: 0 });
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
  const screenshot = await page.screenshot({ path: capturePath(testInfo, `v09-development-real-${testInfo.project.name}.png`) });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
  expect(externalRequests).toEqual([]);
});

test("recovers real exchange conflicts and preserves pinned runtime admission after withdrawal", async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  expect(tokenSubject(operatorToken)).not.toBe(tokenSubject(adminToken));
  const externalRequests: string[] = [];
  page.on("request", (request) => {
    const host = new URL(request.url()).hostname;
    if (host !== "127.0.0.1" && host !== "localhost") externalRequests.push(request.url());
  });

  const runId = (process.env.SPELL_BROWSER_RUN_ID ?? `${Date.now()}`).replace(/[^A-Za-z0-9_.-]/g, "-").slice(0, 40);
  const projectName = `V09 continuity ${runId} ${testInfo.project.name}`;
  const procedureId = `continuity-${testInfo.project.name}`;
  const procedurePath = `src/${procedureId}.spell.py`;

  await page.goto("/development.html");
  await expect(page.getByText("Development environment")).toBeVisible();
  await openMobileArea(page, "Explorer");
  await page.getByRole("button", { name: "Create project" }).first().click();
  const createProjectDialog = page.getByRole("dialog", { name: "Create project" });
  await createProjectDialog.getByLabel("Project name").fill(projectName);
  await createProjectDialog.getByLabel("Filename case policy").selectOption("CASE_SENSITIVE");
  const projectResponse = await waitForSuccessfulResponse(
    page,
    "continuity project creation",
    (response) => response.url().endsWith("/api/v1/development/projects") && response.request().method() === "POST",
    () => createProjectDialog.getByRole("button", { name: "Apply", exact: true }).click(),
  );
  expect(projectResponse.status()).toBe(200);
  const projectBody = await projectResponse.json() as { project?: { project_id: string }; project_id?: string };
  const projectId = projectBody.project?.project_id ?? projectBody.project_id;
  expect(projectId).toBeTruthy();

  await openMobileArea(page, "Explorer");
  await page.getByRole("button", { name: "New procedure" }).click();
  const createProcedureDialog = page.getByRole("dialog", { name: "Create procedure" });
  await createProcedureDialog.getByLabel("Project-relative path").fill(procedurePath);
  const resourceResponse = await waitForSuccessfulResponse(
    page,
    "continuity procedure creation",
    (response) => response.url().includes(`/api/v1/development/projects/${projectId}/resources`) && response.request().method() === "POST",
    () => createProcedureDialog.getByRole("button", { name: "Apply", exact: true }).click(),
  );
  expect(resourceResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, resourceResponse);

  await openMobileArea(page, "Problems");
  const checkOnSave = page.getByRole("checkbox", { name: "Check on save" });
  await expect(checkOnSave).toBeVisible();
  await checkOnSave.uncheck();
  await openMobileArea(page, "Editor");
  const editor = page.getByLabel("Procedure source editor");
  await expect(editor).toHaveValue(new RegExp(`# @procedure ${procedureId}`));
  const generatedSource = await editor.inputValue();
  const validSource = generatedSource.replace(
    "Log('Procedure ready')",
    "ARGS()\nDataContainer('LOCAL.CONTINUITY')\nLog('Procedure ready')",
  );
  const invalidSource = validSource.replace("Log('Procedure ready')", "Log(");
  await editor.fill(invalidSource);
  const invalidSaveResponse = await waitForSuccessfulResponse(
    page,
    "invalid source save",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().includes("/resources/") && response.request().method() === "PUT",
    () => editor.press("Control+S"),
  );
  expect(invalidSaveResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, invalidSaveResponse);

  await openMobileArea(page, "Problems");
  const runFailedCheck = page.getByRole("button", { name: "Run semantic check" });
  await expect(runFailedCheck).toBeEnabled();
  const failedCheckResponse = await waitForSuccessfulResponse(
    page,
    "invalid-source semantic check start",
    (response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/checks`) && response.request().method() === "POST",
    () => runFailedCheck.click(),
  );
  expect(failedCheckResponse.status()).toBe(200);
  const failedCheckBody = await failedCheckResponse.json() as { job?: { job_id: string }; job_id?: string };
  const failedJobId = failedCheckBody.job?.job_id ?? failedCheckBody.job_id;
  expect(failedJobId).toBeTruthy();
  await expect.poll(async () => {
    const body = await authorizedJson<{ job?: { state: string }; state?: string }>(page, `/api/v1/development/checks/${failedJobId}`, operatorToken);
    return body.job?.state ?? body.state;
  }, { timeout: 30_000 }).toBe("COMPLETED");
  const failedCheck = await authorizedJson<{ job: { report_sha256: string } }>(page, `/api/v1/development/checks/${failedJobId}`, operatorToken);
  const reportButton = page.getByRole("button", { name: "Download semantic report" });
  await expect(reportButton).toBeEnabled({ timeout: 30_000 });
  const failedReportPromise = page.waitForEvent("download");
  await reportButton.click();
  const failedReportDownload = await failedReportPromise;
  expect(failedReportDownload.suggestedFilename()).toBe(`${failedJobId}.semantic-report.json`);
  const failedReportStream = await failedReportDownload.createReadStream();
  const failedReportChunks: Buffer[] = [];
  for await (const chunk of failedReportStream) failedReportChunks.push(Buffer.from(chunk));
  const failedReportBytes = Buffer.concat(failedReportChunks);
  expect(createHash("sha256").update(failedReportBytes).digest("hex")).toBe(failedCheck.job.report_sha256);
  const failedReport = JSON.parse(failedReportBytes.toString("utf8")) as {
    outcome: string;
    diagnostics: Array<{ code: string; source_path: string; start_line: number; start_column: number }>;
  };
  expect(failedReport.outcome).toBe("FAILED");
  const diagnostic = failedReport.diagnostics.find((item) => item.source_path === procedurePath);
  expect(diagnostic).toBeTruthy();
  const diagnosticButton = page.getByRole("button", { name: `Open ${diagnostic!.code} at exact source span` });
  await expect(diagnosticButton).toBeVisible();
  await diagnosticButton.click();
  await expect(editor).toBeFocused();
  const diagnosticOffset = invalidSource.split("\n").slice(0, diagnostic!.start_line - 1)
    .reduce((total, line) => total + line.length + 1, 0) + diagnostic!.start_column - 1;
  await expect.poll(() => editor.evaluate((element) => (element as HTMLTextAreaElement).selectionStart)).toBe(diagnosticOffset);

  await editor.fill(validSource);
  const validSaveResponse = await waitForSuccessfulResponse(
    page,
    "valid source save",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().includes("/resources/") && response.request().method() === "PUT",
    () => editor.press("Control+S"),
  );
  expect(validSaveResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, validSaveResponse);
  await openMobileArea(page, "Problems");
  const runValidCheck = page.getByRole("button", { name: "Run semantic check" });
  await expect(runValidCheck).toBeEnabled();
  const validCheckResponse = await waitForSuccessfulResponse(
    page,
    "valid-source semantic check start",
    (response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/checks`) && response.request().method() === "POST",
    () => runValidCheck.click(),
  );
  expect(validCheckResponse.status()).toBe(200);
  const validCheckBody = await validCheckResponse.json() as { job?: { job_id: string }; job_id?: string };
  const validJobId = validCheckBody.job?.job_id ?? validCheckBody.job_id;
  expect(validJobId).toBeTruthy();
  await expect.poll(async () => {
    const body = await authorizedJson<{ job?: { state: string }; state?: string }>(page, `/api/v1/development/checks/${validJobId}`, operatorToken);
    return body.job?.state ?? body.state;
  }, { timeout: 30_000 }).toBe("COMPLETED");

  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "History", exact: true }).click();
  const baseCommitMessage = `Base ${procedureId}`;
  await page.getByLabel("Commit message").fill(baseCommitMessage);
  const commitAll = page.getByRole("button", { name: "Commit all changes" });
  await expect(commitAll).toBeEnabled();
  const baseCommitResponse = await waitForSuccessfulResponse(
    page,
    "base history commit",
    (response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/history`) && response.request().method() === "POST",
    () => commitAll.click(),
  );
  expect(baseCommitResponse.status()).toBe(200);
  await expect(page.getByText(baseCommitMessage, { exact: true })).toBeVisible();

  await openMobileArea(page, "Explorer");
  const exportDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export project archive" }).click();
  const exportDownload = await exportDownloadPromise;
  expect(exportDownload.suggestedFilename()).toBe(`${projectId}.spell-project.zip`);
  const exportStream = await exportDownload.createReadStream();
  const exportChunks: Buffer[] = [];
  for await (const chunk of exportStream) exportChunks.push(Buffer.from(chunk));
  const exportedArchive = Buffer.concat(exportChunks);
  expect(exportedArchive.byteLength).toBeGreaterThan(0);

  await openMobileArea(page, "Editor");
  const oursSource = validSource.replace("Procedure ready", "Local workspace source");
  await editor.fill(oursSource);
  const oursSaveResponse = await waitForSuccessfulResponse(
    page,
    "local source save",
    (response) => response.url().includes("/api/v1/development/projects/") && response.url().includes("/resources/") && response.request().method() === "PUT",
    () => page.getByRole("button", { name: "Save resource" }).click(),
  );
  expect(oursSaveResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, oursSaveResponse);

  await openMobileArea(page, "Explorer");
  const importFilename = `${projectId}-røundtrip.zip`;
  const importResponsePromise = page.waitForResponse((response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/imports`) && response.request().method() === "POST");
  await page.getByLabel("Project archive file").setInputFiles({
    name: importFilename,
    mimeType: "application/vnd.openbexi.spell.project+zip",
    buffer: exportedArchive,
  });
  const importResponse = await importResponsePromise;
  expect(importResponse.status()).toBe(409);
  const importConflict = await importResponse.json() as { detail?: { current?: { operation_id?: string } } };
  const operationId = importConflict.detail?.current?.operation_id;
  expect(operationId).toBeTruthy();
  await expect(page.getByRole("alert")).toContainText("EXTERNAL_CHANGE_CONFLICT");
  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "Changes", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Retained project import" })).toBeVisible();
  await expect(page.getByText(importFilename, { exact: true })).toBeVisible();
  const retained = await authorizedJson<{ import_operation: { original_filename: string; original_bytes_sha256: string; status: string; conflict_paths: string[] } }>(page, `/api/v1/development/projects/${projectId}/imports/${operationId}`, operatorToken);
  expect(retained.import_operation).toMatchObject({
    original_filename: importFilename,
    original_bytes_sha256: createHash("sha256").update(exportedArchive).digest("hex"),
    status: "CONFLICT",
    conflict_paths: [procedurePath],
  });
  await page.getByRole("button", { name: "Dismiss error" }).click();

  await openMobileArea(page, "Explorer");
  await page.locator(`[role="treeitem"][title="${procedurePath}"]`).click();
  await openMobileArea(page, "Explorer");
  await page.getByRole("button", { name: "Delete resource" }).click();
  const deleteResponse = await waitForSuccessfulResponse(
    page,
    "conflicting resource deletion",
    (response) => response.url().includes(`/api/v1/development/projects/${projectId}/resources/`) && response.request().method() === "DELETE",
    () => page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click(),
  );
  expect(deleteResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, deleteResponse);

  await openMobileArea(page, "Activity");
  const applyResponse = await waitForSuccessfulResponse(
    page,
    "retained import apply",
    (response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/imports/${operationId}/apply`) && response.request().method() === "POST",
    () => page.getByRole("button", { name: "Apply retained import" }).click(),
  );
  expect(applyResponse.status()).toBe(200);
  await waitForWorkspaceRefresh(page, applyResponse);
  await expect(page.getByRole("heading", { name: "Retained project import" })).toHaveCount(0);
  await openMobileArea(page, "Editor");
  await expect(editor).toHaveValue(validSource);

  await openMobileArea(page, "Problems");
  const runFinalCheck = page.getByRole("button", { name: "Run semantic check" });
  await expect(runFinalCheck).toBeEnabled();
  const finalCheckResponse = await waitForSuccessfulResponse(
    page,
    "restored-source semantic check start",
    (response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/checks`) && response.request().method() === "POST",
    () => runFinalCheck.click(),
  );
  expect(finalCheckResponse.status()).toBe(200);
  const finalCheckBody = await finalCheckResponse.json() as { job?: { job_id: string }; job_id?: string };
  const finalJobId = finalCheckBody.job?.job_id ?? finalCheckBody.job_id;
  expect(finalJobId).toBeTruthy();
  await expect.poll(async () => {
    const body = await authorizedJson<{ job?: { state: string }; state?: string }>(page, `/api/v1/development/checks/${finalJobId}`, operatorToken);
    return body.job?.state ?? body.state;
  }, { timeout: 30_000 }).toBe("COMPLETED");

  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "History", exact: true }).click();
  const finalCommitMessage = `Resolved ${procedureId}`;
  await page.getByLabel("Commit message").fill(finalCommitMessage);
  await expect(commitAll).toBeEnabled();
  const finalCommitResponse = await waitForSuccessfulResponse(
    page,
    "resolved history commit",
    (response) => response.url().endsWith(`/api/v1/development/projects/${projectId}/history`) && response.request().method() === "POST",
    () => commitAll.click(),
  );
  expect(finalCommitResponse.status()).toBe(200);
  const finalCommitBody = await finalCommitResponse.json() as { history_revision?: { history_revision_id: string }; history_revision_id?: string };
  const finalHistoryRevisionId = finalCommitBody.history_revision?.history_revision_id ?? finalCommitBody.history_revision_id;
  expect(finalHistoryRevisionId).toBeTruthy();
  await expect(page.getByText(finalCommitMessage, { exact: true })).toBeVisible();

  await setIdentity(page, adminToken, "admin");
  const approveRevision = page.getByRole("button", { name: `Approve revision ${finalHistoryRevisionId}` });
  await expect(approveRevision).toBeEnabled();
  const reviewResponse = await waitForSuccessfulResponse(
    page,
    "resolved revision review",
    (response) => response.url().endsWith(`/api/v1/development/history/${finalHistoryRevisionId}/review`) && response.request().method() === "POST",
    () => approveRevision.click(),
  );
  expect(reviewResponse.status()).toBe(200);

  await setIdentity(page, operatorToken, "operator");
  const buildBundle = page.getByRole("button", { name: `Build bundle from revision ${finalHistoryRevisionId}` });
  await expect(buildBundle).toBeEnabled();
  const buildResponse = await waitForSuccessfulResponse(
    page,
    "resolved bundle build",
    (response) => response.url().endsWith(`/api/v1/development/history/${finalHistoryRevisionId}/bundles`) && response.request().method() === "POST",
    () => buildBundle.click(),
  );
  expect(buildResponse.status()).toBe(200);
  const buildBody = await buildResponse.json() as { bundle: { bundle_digest: string } };
  const bundleDigest = buildBody.bundle.bundle_digest;
  expect(bundleDigest).toMatch(/^[0-9a-f]{64}$/);

  await setIdentity(page, adminToken, "admin");
  await page.getByRole("tab", { name: "Bundles and promotion" }).click();
  const approveBundle = page.getByRole("button", { name: `Approve bundle ${bundleDigest}`, exact: true });
  await expect(approveBundle).toBeEnabled();
  const approvalResponse = await waitForSuccessfulResponse(
    page,
    "resolved bundle approval",
    (response) => response.url().endsWith(`/api/v1/development/bundles/${bundleDigest}/approve`) && response.request().method() === "POST",
    () => approveBundle.click(),
  );
  expect(approvalResponse.status()).toBe(200);
  const promoteBundle = page.getByRole("button", { name: `Promote bundle ${bundleDigest}`, exact: true });
  await expect(promoteBundle).toBeEnabled();
  const promotionResponse = await waitForSuccessfulResponse(
    page,
    "resolved bundle promotion",
    (response) => response.url().endsWith(`/api/v1/development/catalog/${procedureId}/decisions`) && response.request().method() === "POST",
    () => promoteBundle.click(),
  );
  expect(promotionResponse.status()).toBe(200);
  await expect(page.locator(".dev-runtime-admission span")).toContainText(bundleDigest.slice(0, 10));

  await setIdentity(page, operatorToken, "operator");
  const createExecution = await authorizedRequest<{ execution: {
    id: string;
    revision: number;
    catalog_revision_id: string;
    procedure_hash: string;
    state: string;
  } }>(page, "/api/v1/executions", operatorToken, {
    method: "POST",
    body: {
      procedure_id: procedureId,
      context_id: "simulator",
      reason: "Real browser withdrawal continuity controller",
      idempotency_key: `real-continuity-execution-${runId}-${testInfo.project.name}`,
    },
  });
  expect(createExecution.status).toBe(202);
  const execution = createExecution.body.execution;
  const catalogHistory = await authorizedJson<{
    procedure: { id: string };
    items: Array<{ id: string; revision: number; source_digest: string; bundle_digest: string }>;
  }>(page, `/api/v1/procedures/${encodeURIComponent(procedureId)}/history`, operatorToken);
  const catalogRevision = catalogHistory.items.find((item) => item.id === execution.catalog_revision_id);
  expect(catalogRevision).toEqual(expect.objectContaining({ bundle_digest: bundleDigest, source_digest: execution.procedure_hash }));
  const executionBeforeWithdrawal = await authorizedJson<{ execution: { id: string; state: string; catalog_revision_id: string; procedure_hash: string } }>(
    page,
    `/api/v1/executions/${execution.id}/snapshot`,
    operatorToken,
  );
  const binding = await boundSession(page);
  const control = await authorizedRequest<{ control_lease: { id: string; revision: number; control_fencing_token: number } }>(
    page,
    `/api/v1/executions/${execution.id}/control`,
    operatorToken,
    {
      method: "POST",
      body: {
        action: "ACQUIRE",
        ...binding,
        expected_execution_revision: execution.revision,
        lease_seconds: 60,
        acknowledgement: "Accept responsibility for withdrawal continuity proof",
        idempotency_key: `real-continuity-control-${runId}-${testInfo.project.name}`,
        reason: "Create a pinned schedule before withdrawal",
      },
    },
  );
  expect(control.status).toBe(200);
  const lease = control.body.control_lease;
  const schedulePayload = {
    controller_execution_id: execution.id,
    schedule_type: "RELATIVE",
    target: "3600.0",
    procedure_catalog_id: catalogHistory.procedure.id,
    procedure_revision: catalogRevision!.revision,
    context_id: "simulator",
    arguments: {},
    automatic: false,
    background_allowed: false,
    visible: true,
    misfire_policy: "FIRE_ONCE",
    maximum_lateness_seconds: 3600,
    expected_execution_revision: execution.revision,
    lease_id: lease.id,
    expected_lease_revision: lease.revision,
    control_fencing_token: lease.control_fencing_token,
    ...binding,
    reason: "Pin schedule before withdrawal",
  };
  const createSchedule = await authorizedRequest<{ schedule: {
    id: string;
    state: string;
    catalog_revision_id: string;
    bundle_digest: string;
  } }>(page, "/api/v1/schedules", operatorToken, {
    method: "POST",
    body: { ...schedulePayload, idempotency_key: `real-continuity-schedule-${runId}-${testInfo.project.name}` },
  });
  expect(createSchedule.status).toBe(201);
  expect(createSchedule.body.schedule).toEqual(expect.objectContaining({
    state: "PENDING",
    catalog_revision_id: catalogRevision!.id,
    bundle_digest: bundleDigest,
  }));

  await setIdentity(page, adminToken, "admin");
  const withdrawBundle = page.getByRole("button", { name: `Withdraw bundle ${bundleDigest}`, exact: true });
  await expect(withdrawBundle).toBeEnabled();
  const withdrawalResponse = await waitForSuccessfulResponse(
    page,
    "bundle withdrawal",
    (response) => response.url().endsWith(`/api/v1/development/catalog/${procedureId}/decisions`) && response.request().method() === "POST",
    () => withdrawBundle.click(),
  );
  expect(withdrawalResponse.status()).toBe(200);
  await expect(page.locator(".dev-runtime-admission span")).toHaveText("No v0.9 bundle promoted");

  const executionAfterWithdrawal = await authorizedJson<{ execution: { id: string; state: string; catalog_revision_id: string; procedure_hash: string } }>(
    page,
    `/api/v1/executions/${execution.id}/snapshot`,
    operatorToken,
  );
  expect(executionAfterWithdrawal.execution).toEqual(expect.objectContaining({
    id: executionBeforeWithdrawal.execution.id,
    state: executionBeforeWithdrawal.execution.state,
    catalog_revision_id: catalogRevision!.id,
    procedure_hash: catalogRevision!.source_digest,
  }));
  const schedulesAfterWithdrawal = await authorizedJson<{ items: Array<{
    id: string;
    state: string;
    catalog_revision_id: string;
    bundle_digest: string;
  }> }>(page, `/api/v1/schedules?controller_execution_id=${encodeURIComponent(execution.id)}`, operatorToken);
  expect(schedulesAfterWithdrawal.items).toContainEqual(expect.objectContaining({
    id: createSchedule.body.schedule.id,
    state: "PENDING",
    catalog_revision_id: catalogRevision!.id,
    bundle_digest: bundleDigest,
  }));

  const rejectedExecution = await authorizedRequest<{ detail?: { code?: string; message?: string } }>(page, "/api/v1/executions", operatorToken, {
    method: "POST",
    body: {
      procedure_id: procedureId,
      context_id: "simulator",
      reason: "New execution must be rejected after withdrawal",
      idempotency_key: `real-rejected-execution-${runId}-${testInfo.project.name}`,
    },
  });
  expect(rejectedExecution.status).toBe(404);
  expect(rejectedExecution.body.detail).toBe("procedure not found");
  const rejectedSchedule = await authorizedRequest<{ detail?: { code?: string; message?: string } }>(page, "/api/v1/schedules", operatorToken, {
    method: "POST",
    body: { ...schedulePayload, idempotency_key: `real-rejected-schedule-${runId}-${testInfo.project.name}` },
  });
  expect(rejectedSchedule.status).toBe(409);
  expect(rejectedSchedule.body.detail?.message).toContain("not currently promoted");

  const geometry = await page.evaluate(() => ({
    viewportWidth: document.documentElement.clientWidth,
    viewportHeight: document.documentElement.clientHeight,
    documentWidth: document.documentElement.scrollWidth,
    documentHeight: document.documentElement.scrollHeight,
    bodyWidth: document.body.scrollWidth,
    bodyHeight: document.body.scrollHeight,
    scrollX: window.scrollX,
    scrollY: window.scrollY,
  }));
  expect(Math.max(geometry.documentWidth, geometry.bodyWidth)).toBeLessThanOrEqual(geometry.viewportWidth);
  expect(Math.max(geometry.documentHeight, geometry.bodyHeight)).toBeLessThanOrEqual(geometry.viewportHeight);
  expect({ scrollX: geometry.scrollX, scrollY: geometry.scrollY }).toEqual({ scrollX: 0, scrollY: 0 });
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
  const screenshot = await page.screenshot({ path: capturePath(testInfo, `v09-development-real-continuity-${testInfo.project.name}.png`) });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
  expect(externalRequests).toEqual([]);
});
