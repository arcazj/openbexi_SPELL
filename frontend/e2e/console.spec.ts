import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.sessionStorage.setItem("openbexi.spell.access-token", "mock.jwt.token");
  });
  await page.route("**/api/v1/health", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ status: "ok", version: "0.3.0", mode: "simulator-only" }),
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
            version: "0.3",
            entrypoint: "power_checkout.spell.py",
            step_count: 4,
            source: "Log('Starting')",
            steps: [{ index: 0, type: "log", line: 1, message: "Starting" }],
          },
        ],
      }),
    }),
  );
  await page.route("**/api/v1/procedures/validate", async (route) => {
    expect(route.request().method()).toBe("POST");
    expect(route.request().postDataJSON()).toEqual({ source: "Log('Starting')" });
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        valid: true,
        subset_version: "spell-restricted-ast/0.3",
        sha256: "9a6f".repeat(16),
        steps: [{ index: 0, line: 1, type: "log", message: "Starting" }],
        variables: { mode: "simulator" },
        diagnostics: [],
      }),
    });
  });
});

test("validates selected source without creating an execution", async ({ page }) => {
  await page.goto("/");
  const validate = page.getByRole("button", { name: "Validate source" });
  await expect(validate).toBeEnabled();
  await validate.focus();
  await page.keyboard.press("Enter");

  const panel = page.getByRole("region", { name: "Power Checkout validation" });
  await expect(panel).toBeFocused();
  await expect(panel.getByRole("status")).toContainText("VALID");
  await expect(panel.getByText("spell-restricted-ast/0.3")).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Validated IR" })).toBeVisible();
  await expect(panel.getByText("simulator")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start procedure" })).toBeEnabled();

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

test("ends the authenticated session from the console header", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "End session" }).click();

  await expect(page.getByRole("heading", { name: "Session access" })).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(() => window.sessionStorage.getItem("openbexi.spell.access-token")),
    )
    .toBeNull();
});
