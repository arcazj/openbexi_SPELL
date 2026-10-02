import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the local v0.17 simulator stack");
test.setTimeout(90_000);

async function snapshot(page: Page, executionId: string): Promise<{
  execution: { state: string; variables: Record<string, unknown>; current_step: number };
  active_prompt: { id: string; warning_at: string | null; warning_emitted_at: string | null; response_deadline: string | null } | null;
}> {
  return page.evaluate(async (id) => {
    const response = await fetch(`/api/v1/executions/${id}/snapshot`, {
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem("openbexi.spell.access-token") ?? ""}`,
        "X-Spell-Session-Id": sessionStorage.getItem("openbexi.spell.session-id") ?? "",
        "X-Spell-Client-Instance-Key-Id": sessionStorage.getItem("openbexi.spell.client-instance-key") ?? "",
      }, cache: "no-store",
    });
    if (!response.ok) throw new Error(`snapshot status ${response.status}`);
    return response.json();
  }, executionId);
}

async function startWalkthrough(page: Page): Promise<string> {
  const created = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/executions" && response.request().method() === "POST");
  const option = page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option").filter({ hasText: "Native prompt walkthrough" });
  await option.click();
  await page.getByRole("button", { name: "Start procedure" }).click();
  const response = await created;
  expect(response.status()).toBe(202);
  return ((await response.json()) as { execution: { id: string } }).execution.id;
}

test("resets native drafts, retains warning after reload and distinguishes CANCEL from Abort", async ({ page }, testInfo) => {
  if (testInfo.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  const executionId = await startWalkthrough(page);
  await expect(page.getByRole("heading", { name: "Choose a route" })).toBeVisible({ timeout: 20_000 });
  const response = page.getByRole("textbox", { name: "Response", exact: true });
  await expect(page.getByRole("button", { name: "Commit response" })).toBeDisabled();
  await page.getByRole("radio", { name: "Backup", exact: true }).check();
  await expect(response).toHaveValue("B");
  await page.getByRole("button", { name: "Reset draft" }).focus();
  await page.keyboard.press("Enter");
  await expect(response).toHaveValue("");
  await expect(page.getByRole("radio", { name: "Backup", exact: true })).not.toBeChecked();
  await expect(page.getByText("Response warning threshold reached.", { exact: true })).toBeVisible({ timeout: 10_000 });
  await expect.poll(async () => (await snapshot(page, executionId)).active_prompt?.warning_emitted_at).not.toBeNull();
  const warned = (await snapshot(page, executionId)).active_prompt!;
  expect(warned.response_deadline).toBeNull();

  await page.reload();
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await page.getByRole("button", { name: new RegExp(`Open .* ${executionId}$`) }).click();
  await expect(page.getByRole("heading", { name: "Choose a route" })).toBeVisible({ timeout: 20_000 });
  const reopened = (await snapshot(page, executionId)).active_prompt;
  expect(reopened).toEqual(expect.objectContaining({ id: warned.id, warning_at: warned.warning_at, warning_emitted_at: warned.warning_emitted_at, response_deadline: null }));
  await expect(page.getByText("Response warning threshold reached.", { exact: true })).toBeVisible();
  await response.fill("B");
  await expect(page.getByRole("radio", { name: "Backup", exact: true })).toBeChecked();
  await expect(page.getByRole("button", { name: "Commit response" })).toBeEnabled();
  const accessibility = await new AxeBuilder({ page }).include(".prompt-panel").analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
  const width = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
  expect(width.content).toBeLessThanOrEqual(width.viewport);
  await page.screenshot({ path: testInfo.outputPath(`prompt-v17-${testInfo.project.name}.png`), fullPage: true });
  await page.getByRole("button", { name: "Commit response" }).click();

  // The NUM timeout settles on the server; no browser action races its deadline.
  await expect(page.getByRole("heading", { name: "Record a note" })).toBeVisible({ timeout: 20_000 });
  expect((await snapshot(page, executionId)).execution.variables).toMatchObject({ route: "B", rate: 2.5 });
  await response.fill("native browser proof");
  await page.getByRole("button", { name: "Commit response" }).click();
  await expect(page.getByRole("heading", { name: "Finish walkthrough" })).toBeVisible();
  await page.getByRole("radio", { name: "CANCEL", exact: true }).check();
  await page.getByRole("button", { name: "Commit response" }).click();
  await expect(page.locator(".execution-metadata .state-pill")).toHaveText("COMPLETED", { timeout: 20_000 });
  expect((await snapshot(page, executionId)).execution.variables).toEqual({ ARGS: {}, route: "B", rate: 2.5, note: "native browser proof", answer: "CANCEL" });

  const abortedId = await startWalkthrough(page);
  await expect(page.getByRole("heading", { name: "Choose a route" })).toBeVisible({ timeout: 20_000 });
  await page.getByRole("button", { name: "Abort prompt" }).click();
  await expect(page.locator(".execution-metadata .state-pill")).toHaveText("ABORTED", { timeout: 20_000 });
  const aborted = (await snapshot(page, abortedId)).execution;
  expect(aborted.variables).not.toHaveProperty("route");
  expect(aborted.current_step).toBe(0);
});
