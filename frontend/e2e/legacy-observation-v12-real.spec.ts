import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const token = process.env.SPELL_E2E_TOKEN ?? "";
test.skip(!process.env.SPELL_REAL_BACKEND || !token, "requires the isolated local v0.12 stack");

test("inspects read-only replay and switches to the simulator", async ({ page }, testInfo) => {
  await page.addInitScript((credential) => sessionStorage.setItem("openbexi.spell.access-token", credential), token);
  const requests: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.startsWith("/api/v1/legacy-observation")) requests.push(request.method());
  });
  await page.goto("/");
  await page.getByRole("tab", { name: "Driver foundation" }).click();
  await page.getByText("Legacy observation replay", { exact: true }).focus();
  await page.keyboard.press("Enter");
  const region = page.locator(".legacy-observation");
  await expect(region.getByText(/reference-244/)).toBeVisible();
  await expect(region.getByLabel("Compatibility comparison")).toContainText("5 equivalent");
  await expect(region.getByText("18446744073709551615")).toHaveCount(2);
  await region.getByLabel("Observation source").selectOption("simulator");
  await expect(region.getByText(/simulator-oracle/)).toBeVisible();
  await region.getByRole("button", { name: "Refresh replay" }).click();
  await expect(region.getByText(/simulator-oracle/)).toBeVisible();
  expect(requests.length).toBeGreaterThanOrEqual(6);
  expect(requests.every((method) => method === "GET")).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const accessibility = await new AxeBuilder({ page }).include(".legacy-observation").analyze();
  expect(accessibility.violations).toEqual([]);
  await region.screenshot({ path: testInfo.outputPath("legacy-replay.png") });
});
