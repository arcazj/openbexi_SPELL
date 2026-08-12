import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { resolve } from "node:path";

function artifactPath(name: string): string {
  return resolve(
    process.cwd(),
    process.env.SPELL_E2E_ARTIFACT_DIRECTORY ?? "../artifacts/v0.3",
    name,
  );
}

test("requires a session JWT without embedding a default credential", async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Session access" })).toBeVisible();
  await expect(page.getByLabel("Signed JWT")).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect" })).toBeDisabled();

  await page.getByLabel("Signed JWT").fill("not-a-token");
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByRole("alert")).toContainText("three segments");
  await expect(page.getByRole("status")).toHaveCount(0);

  const accessibility = await new AxeBuilder({ page }).analyze();
  const blocking = accessibility.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(blocking).toEqual([]);

  const containment = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(Math.max(containment.document, containment.body)).toBeLessThanOrEqual(containment.viewport);
  if (testInfo.project.name === "chromium") {
    await page.screenshot({ path: artifactPath("session-access.png") });
  }
});
