import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const token = process.env.SPELL_E2E_TOKEN ?? "";
test.skip(!process.env.SPELL_REAL_BACKEND || !token, "requires the isolated local stack");

test("reads typed telemetry and verifies shadow comparison and fallback", async ({ page }, testInfo) => {
  await page.addInitScript((credential) => sessionStorage.setItem("openbexi.spell.access-token", credential), token);
  const methods: string[] = [];
  page.on("request", (request) => { if (new URL(request.url()).pathname.startsWith("/api/v1/telemetry-adapter")) methods.push(request.method()); });
  await page.goto("/");
  await page.getByRole("tab", { name: "Driver foundation" }).click();
  await page.getByText("Telemetry adapter", { exact: true }).focus();
  await page.keyboard.press("Enter");
  const region = page.locator(".telemetry-adapter");
  await region.getByRole("button", { name: "Read next recorded sample" }).click();
  await expect(region.getByText("Value: 20 (FINITE_DOUBLE)")).toBeVisible();
  await region.getByRole("button", { name: "Read next recorded sample" }).click();
  await expect(region.getByText("Value: 20.1 (FINITE_DOUBLE)")).toBeVisible();
  await region.getByRole("button", { name: "Read next recorded sample" }).click();
  await expect(region.getByLabel("Adapter result")).toContainText("TIMEOUT");
  await region.getByLabel("Telemetry item").selectOption("COUNTER");
  await region.getByRole("button", { name: "Read current" }).click();
  await expect(region.getByText("Value: 18446744073709551615 (UINT64)")).toBeVisible();
  await region.getByRole("button", { name: "Compare both sources" }).click();
  await expect(region.getByLabel("Adapter comparison")).toContainText("EQUIVALENT");
  await region.getByLabel("Adapter source").selectOption("simulator");
  await region.getByRole("button", { name: "Read current" }).click();
  await expect(region.getByLabel("Adapter result")).toContainText("simulator-oracle");
  expect(methods.length).toBeGreaterThan(6);
  expect(methods.every((method) => method === "GET")).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect((await new AxeBuilder({ page }).include(".telemetry-adapter").analyze()).violations).toEqual([]);
  await region.screenshot({ path: testInfo.outputPath("telemetry-adapter.png") });
});
