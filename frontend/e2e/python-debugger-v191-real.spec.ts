import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the actual isolated Python runner");
test.setTimeout(180_000);

type Snapshot = {
  execution: { state: string; current_line: number | null; procedure_hash: string; variables: Record<string, unknown> };
  logs: Array<{ payload: { message: string } }>;
};

test("Python source controls stop before lines, survive reload and finish every topic", async ({ page }, info) => {
  if (info.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 1000 });
  const source = readFileSync("../procedures/test_Python.py", "utf8");
  const lines = source.split("\n");
  const breakpoint = lines.findIndex(line => line.includes("integer, floating, boolean, nothing =")) + 1;
  const target = lines.findIndex(line => line.includes('check("truthiness"')) + 1;
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  const command = (name: string) => page.getByRole("button", { name, exact: true });
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 30_000 });
  await page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option")
    .filter({ has: page.getByText("Test Python", { exact: true }) }).click();
  const admitted = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/executions" && response.request().method() === "POST");
  await command("Start procedure").click();
  const response = await admitted;
  expect(response.status()).toBe(202);
  const id: string = (await response.json()).execution.id;
  const snapshot = async (): Promise<Snapshot> => page.evaluate(async id => {
    const result = await fetch(`/api/v1/executions/${id}/snapshot`, { headers: {
      Authorization: `Bearer ${sessionStorage.getItem("openbexi.spell.access-token") ?? ""}`,
    }, cache: "no-store" });
    if (!result.ok) throw new Error(`Python snapshot failed (${result.status})`);
    return result.json();
  }, id);
  await expect.poll(async () => (await snapshot()).execution.state, { timeout: 20_000 }).toBe("paused");
  expect((await snapshot()).logs).toEqual([]);
  await expect(command("Run")).toBeEnabled({ timeout: 15_000 });
  await expect(command("Set breakpoint on line 1")).toBeDisabled();
  await command(`Set breakpoint on line ${breakpoint}`).click();
  await command("Run").click();
  await expect.poll(async () => (await snapshot()).execution.current_line, { timeout: 25_000 }).toBe(breakpoint);
  await expect(page.locator(`tr.current-line[data-source-line="${breakpoint}"]`)).toHaveCount(1);
  expect((await snapshot()).logs.some(log => log.payload.message.includes("int, float, bool, None:"))).toBe(false);
  await command("Step").click();
  await expect.poll(async () => (await snapshot()).execution.current_line, { timeout: 15_000 }).toBe(breakpoint + 1);
  await expect(page.locator(`tr.current-line[data-source-line="${breakpoint + 1}"]`)).toHaveCount(1);
  await command("Step over").click();
  await expect.poll(async () => (await snapshot()).execution.current_line, { timeout: 15_000 }).toBe(breakpoint + 2);
  await page.locator(`tr[data-source-line="${target}"]`).click();
  await command(`Run to line ${target}`).click();
  await expect.poll(async () => (await snapshot()).execution.current_line, { timeout: 15_000 }).toBe(target);
  await page.reload();
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 30_000 });
  await command(`Open Test Python ${id}`).click();
  await expect(page.locator(`tr.current-line[data-source-line="${target}"]`)).toHaveCount(1, { timeout: 15_000 });
  await command("Remove all breakpoints").click();
  await command("Run").click();
  await expect.poll(async () => (await snapshot()).execution.state, { timeout: 40_000 }).toBe("completed");
  const final = await snapshot();
  expect(final.execution.procedure_hash).toBe(createHash("sha256").update(source).digest("hex"));
  expect(final.execution.variables).toMatchObject({ python_completed: true, python_exit_code: 0, python_stdout_lines: 345, python_stderr_lines: 0 });
  expect(final.logs.map(log => log.payload.message)).toContain("All runtime checks passed: 261 check(s), 39 topic(s), 0 optional capability check(s) skipped.");
  await page.getByRole("tab", { name: /^Logs/ }).click();
  await expect(page.getByLabel("Scrollable log table").locator("tbody tr")).toHaveCount(345);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter(issue => issue.impact === "serious" || issue.impact === "critical")).toEqual([]);
  expect(await page.evaluate(() => Math.max(document.body.scrollWidth, document.documentElement.scrollWidth))).toBeLessThanOrEqual(page.viewportSize()!.width);
  expect(errors).toEqual([]);
  await page.screenshot({ path: info.outputPath(`python-debugger-${info.project.name}.png`), fullPage: true });
});
