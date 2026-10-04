import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const token = process.env.SPELL_E2E_TOKEN ?? "";
test.skip(!process.env.SPELL_REAL_BACKEND || !token, "requires the isolated synthetic stack");
test.setTimeout(60_000);

test("returns a controlled procedure to confirmed read-only state", async ({ page }, testInfo) => {
  await page.addInitScript((credential) => sessionStorage.setItem("openbexi.spell.access-token", credential), token);
  await page.goto("/");
  await page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option", { name: /^Language Reference 244 / }).click();
  await page.getByRole("button", { name: "Start procedure" }).click();
  await expect(page.getByRole("heading", { name: "Select a SPELL 2.4.4 reference example" })).toBeVisible({ timeout: 20_000 });
  const panel = page.locator(".compatibility-control");
  await panel.locator("summary").focus();
  await page.keyboard.press("Enter");
  await panel.getByLabel("Control reason").fill("Complete local non-commanding rollback drill");
  const responsePromise = page.waitForResponse(response => response.url().includes("/legacy-control/") && response.request().method() === "POST");
  await panel.getByRole("button", { name: "Return to read-only", exact: true }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(202);
  const operation = await response.json() as { operation_id: string; command: { id: string } };
  expect(operation.operation_id).toBeTruthy();
  await expect(async () => {
    await panel.getByRole("button", { name: "Refresh operation" }).click();
    await expect(panel.getByRole("status")).toHaveText("Read-only confirmed: procedure stopped.");
  }).toPass({ timeout: 15_000 });
  await expect(panel.getByRole("button", { name: "Run through adapter" })).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  expect((await new AxeBuilder({ page }).include(".compatibility-control").analyze()).violations).toEqual([]);
  await panel.screenshot({ path: testInfo.outputPath("synthetic-control.png") });
});
