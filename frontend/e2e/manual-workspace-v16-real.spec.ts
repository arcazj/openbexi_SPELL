import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the local v0.16 simulator stack");
test.setTimeout(90_000);

test("opens the manual workspace directly and operates its compact procedure views", async ({ page }, testInfo) => {
  if (testInfo.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await expect(page.getByText("Session access", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("textbox", { name: /token/i })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Navigation" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Master" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Application menu" })).toBeVisible();
  await expect(page.locator(".environment-strip")).toContainText("Local operator");
  for (const name of ["System", "Procedures", "Execution", "Help"]) {
    const menu = page.locator(".console-menubar details").filter({ has: page.locator("summary", { hasText: new RegExp(`^${name}$`) }) });
    await menu.locator("summary").click();
    await expect(menu).toHaveAttribute("open", "");
    const bounds = await menu.locator(".menu-popup").boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    await page.keyboard.press("Escape");
    await expect(menu).not.toHaveAttribute("open", "");
  }

  const option = page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option").first();
  await option.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Select a SPELL 2.4.4 reference example" })).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole("tab", { name: "Tabular", exact: true })).toHaveAttribute("aria-selected", "true");
  const source = page.getByRole("table", { name: "Tabular procedure source" });
  await expect(source.getByRole("columnheader", { name: "Code", exact: true })).toBeVisible();
  await expect(source.getByRole("columnheader", { name: "Data", exact: true })).toBeVisible();
  await expect(source.getByRole("columnheader", { name: "Result", exact: true })).toBeVisible();
  await page.getByRole("searchbox", { name: /^Filter \d+ examples$/ }).fill("195");
  await page.getByRole("radio", { name: /Example 195.*extract TM\/TC database values/ }).check();
  await page.getByRole("button", { name: "Commit response" }).click();
  await expect(page.locator(".execution-metadata .state-pill")).toHaveText("FINISHED", { timeout: 25_000 });

  // Permanent Master and procedure instances share the central area, as in pp. 6/10/21.
  const instances = page.getByRole("tablist", { name: "Open procedure views" });
  const procedureTab = instances.getByRole("tab").nth(1);
  await procedureTab.focus();
  await page.keyboard.press("Home");
  await expect(instances.getByRole("tab", { name: "Master", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Master" })).toBeVisible();
  await page.keyboard.press("End");
  await expect(procedureTab).toHaveAttribute("aria-selected", "true");
  await expect(source).toBeVisible();
  await page.getByRole("tab", { name: "Tabular", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Text", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Home");
  await expect(page.getByRole("tab", { name: "Tabular", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "Logs", exact: true }).click();
  await expect(page.getByRole("button", { name: "Collapse execution data" })).toBeVisible();
  await page.getByRole("button", { name: "Collapse execution data" }).click();
  await expect(page.getByRole("button", { name: "Expand execution data" })).toBeVisible();

  const geometry = await page.evaluate(() => {
    const bounds = (selector: string) => {
      const rect = document.querySelector(selector)!.getBoundingClientRect();
      return { x: rect.x, y: rect.y, width: rect.width, height: rect.height, bottom: rect.bottom };
    };
    return {
      viewport: innerWidth, document: document.documentElement.scrollWidth,
      chrome: bounds(".console-chrome"), navigation: bounds(".navigation-region"), source: bounds(".source-workspace"),
      controls: bounds('.command-toolbar[aria-label="Execution controls"]'), filter: bounds(".search-field"),
    };
  });
  expect(geometry.document).toBeLessThanOrEqual(geometry.viewport + 1);
  expect(geometry.filter.height).toBeLessThanOrEqual(30);
  expect(geometry.controls.y).toBeGreaterThanOrEqual(geometry.source.bottom - 1);
  if (testInfo.project.name === "chromium") {
    expect(geometry.chrome.height).toBeLessThanOrEqual(60);
    expect(geometry.navigation.width).toBeLessThanOrEqual(240);
    expect(geometry.source.x).toBeGreaterThan(geometry.navigation.x + geometry.navigation.width);
    expect(geometry.source.height).toBeGreaterThan(450);
  }
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((issue) => issue.impact === "serious" || issue.impact === "critical")).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath(`manual-workspace-v16-${testInfo.project.name}.png`), fullPage: true });
});
