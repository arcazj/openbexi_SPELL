import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("connects to the local simulator without a session access form", async ({ page }) => {
  const expires = Math.floor(Date.now() / 1000) + 300;
  const token = `header.${Buffer.from(JSON.stringify({ sub: "local.simulator.test", role: "operator", jti: "test", exp: expires })).toString("base64url")}.signature`;
  await page.route("**/api/v1/local-session", (route) => route.fulfill({
    contentType: "application/json", body: JSON.stringify({ access_token: token, expires_at: expires,
      token_type: "Bearer", role: "operator", mode: "simulator-only", operational_use: false }),
  }));
  await page.route("**/api/v1/health", (route) => route.fulfill({ contentType: "application/json",
    body: JSON.stringify({ status: "ok", version: "0.16.0", mode: "simulator-only" }) }));
  for (const endpoint of ["procedures", "contexts", "master"]) {
    await page.route(`**/api/v1/${endpoint}`, (route) => route.fulfill({ contentType: "application/json", body: '{"items":[]}' }));
  }
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Session access" })).toHaveCount(0);
  await expect(page.getByLabel("Signed JWT")).toHaveCount(0);
  await expect(page.locator(".connection-badge")).toContainText("CONNECTED");
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
