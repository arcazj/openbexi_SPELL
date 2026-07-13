import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/health", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ status: "ok", version: "0.2.0", mode: "simulator-only" }),
    }),
  );
  await page.route("**/api/v1/procedures", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        items: [
          {
            id: "power_checkout",
            name: "Power Checkout",
            description: "Simulator bus and battery checkout.",
            version: "0.2",
            entrypoint: "power_checkout.spell.py",
            step_count: 4,
            source: "Log('Starting')",
            steps: [{ index: 0, type: "log", line: 1, message: "Starting" }],
          },
        ],
      }),
    }),
  );
});

test("shows the connected simulator procedure catalog", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("SPELL", { exact: true })).toBeVisible();
  await expect(page.getByRole("status")).toContainText("CONNECTED");
  await expect(page.getByRole("option", { name: /Power Checkout/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Start procedure" })).toBeEnabled();
  await expect(page.getByText("No active execution")).toBeVisible();
  const widths = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(Math.max(widths.document, widths.body)).toBeLessThanOrEqual(widths.viewport);

  const accessibility = await new AxeBuilder({ page }).analyze();
  const blocking = accessibility.violations.filter((violation) =>
    violation.impact === "serious" || violation.impact === "critical",
  );
  expect(blocking).toEqual([]);
});
