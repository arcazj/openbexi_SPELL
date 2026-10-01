import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const token = process.env.SPELL_E2E_TOKEN ?? "";
const reviewer = process.env.SPELL_E2E_REVIEW_TOKEN ?? "";
test.skip(!process.env.SPELL_REAL_BACKEND || !token || !reviewer, "requires two isolated local test identities");

test("records independent review, incident rollback and a read-only restore", async ({ page }, testInfo) => {
  await page.addInitScript((credential) => {
    if (!sessionStorage.getItem("openbexi.spell.access-token")) sessionStorage.setItem("openbexi.spell.access-token", credential);
  }, token);
  await page.goto("/");
  await page.getByRole("tab", { name: "Driver foundation" }).click();
  await page.getByText("Shadow pilot readiness", { exact: true }).focus();
  await page.keyboard.press("Enter");
  let region = page.locator(".shadow-pilot");
  await region.getByLabel("Pilot action reason").fill("Local shadow qualification");
  const created = page.waitForResponse((response) => response.url().endsWith("/api/v1/shadow-pilot/runs") && response.request().method() === "POST");
  await region.getByRole("button", { name: "Run read-only shadow" }).click();
  const response = await created;
  expect(response.status()).toBe(201);
  const receipt = await response.json();
  await expect(region.getByLabel("Pilot report")).toContainText("PENDING_REVIEW");
  await expect(region.getByRole("button", { name: "Record independent review" })).toBeDisabled();

  await page.evaluate((credential) => sessionStorage.setItem("openbexi.spell.access-token", credential), reviewer);
  await page.reload();
  await page.getByRole("tab", { name: "Driver foundation" }).click();
  await page.getByText("Shadow pilot readiness", { exact: true }).click();
  region = page.locator(".shadow-pilot");
  await region.getByLabel("Recent shadow runs").selectOption(receipt.id);
  await region.getByLabel("Pilot action reason").fill("Independent local review and recovery drill");
  await region.getByRole("button", { name: "Record independent review" }).click();
  await expect(region.getByLabel("Pilot report")).toContainText("REVIEWED_READ_ONLY");
  await region.getByRole("button", { name: "Prepare backup" }).click();
  await region.getByText("Backup and restore drill", { exact: true }).click();
  await expect(region.getByLabel("Pilot backup JSON")).not.toHaveValue("");
  await region.getByRole("button", { name: "Record incident" }).click();
  await expect(region.getByLabel("Pilot report")).toContainText("INCIDENT_READ_ONLY");
  await region.getByRole("button", { name: "Roll back to simulator" }).click();
  await expect(region.getByLabel("Pilot report")).toContainText("ROLLED_BACK_READ_ONLY");
  await region.getByRole("button", { name: "Restore as read-only" }).click();
  await expect(region.getByLabel("Pilot report")).toContainText("RESTORED_READ_ONLY");
  await expect(region.getByLabel("Pilot report")).toContainText("Local review recorded: No");
  await expect(region.getByRole("button", { name: "Record independent review" })).toBeDisabled();
  await region.getByText("Backup and restore drill", { exact: true }).click();
  await region.getByText("Differential trace and audit", { exact: true }).click();
  expect(await region.locator(".replay-digest").evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  expect((await new AxeBuilder({ page }).include(".shadow-pilot").analyze()).violations).toEqual([]);
  await region.screenshot({ path: testInfo.outputPath("shadow-pilot.png") });
});
