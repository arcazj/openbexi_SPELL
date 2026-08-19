import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

test.skip(
  !process.env.SPELL_REAL_BACKEND || !process.env.SPELL_E2E_TOKEN,
  "requires the loopback v0.8 stack and a signed data-service token",
);

test.beforeEach(async ({ page }) => {
  await page.addInitScript((token) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
  }, process.env.SPELL_E2E_TOKEN!);
});

async function openDomain(page: Page, name: string, pathFragment: string) {
  const responsePromise = page.waitForResponse((response) =>
    response.url().includes(pathFragment) && response.request().method() === "GET",
  );
  await page.getByRole("main", { name: "Data services workspace" }).getByRole("tab", { name }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(200);
  const url = new URL(response.url());
  expect(["127.0.0.1", "localhost"]).toContain(url.hostname);
}

test("reads every v0.8 data family through the loopback boundary", async ({ page }) => {
  await page.goto("/");
  const catalogResponse = page.waitForResponse((response) =>
    response.url().includes("/api/v1/data/catalogs") && response.request().method() === "GET",
  );
  await page.getByRole("tab", { name: "Data services" }).click();
  expect((await catalogResponse).status()).toBe(200);

  const workspace = page.getByRole("main", { name: "Data services workspace" });
  await expect(workspace.getByRole("heading", { name: "Data services" })).toBeVisible();
  await openDomain(page, "Dictionaries", "/api/v1/data/dictionaries");
  await openDomain(page, "Containers", "/api/v1/data/containers");
  await openDomain(page, "Shared", "/api/v1/data/shared/namespaces");
  await openDomain(page, "Files", "/api/v1/data/files/PROJECT_DATA/directory");

  const geometry = await page.evaluate(() => ({
    body: document.body.scrollWidth,
    document: document.documentElement.scrollWidth,
    viewport: document.documentElement.clientWidth,
    clippedButtons: Array.from(document.querySelectorAll<HTMLButtonElement>("button"))
      .filter((button) => button.scrollWidth > button.clientWidth || button.scrollHeight > button.clientHeight)
      .map((button) => button.getAttribute("aria-label") ?? button.textContent?.trim() ?? "button"),
  }));
  expect(Math.max(geometry.body, geometry.document)).toBeLessThanOrEqual(geometry.viewport);
  expect(geometry.clippedButtons).toEqual([]);

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
});
