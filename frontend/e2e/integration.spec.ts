import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the local SPELL simulator backend");
test.setTimeout(60_000);

const externalRequestsByPage = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const externalRequests: string[] = [];
  page.on("request", (request) => {
    const host = new URL(request.url()).hostname;
    if (host !== "127.0.0.1" && host !== "localhost") externalRequests.push(request.url());
  });
  externalRequestsByPage.set(page, externalRequests);
});

async function expectLoopbackOnly(page: Page) {
  const tracked = externalRequestsByPage.get(page) ?? [];
  expect(tracked).toEqual([]);
}

async function expectControlTextFits(page: Page) {
  const clipped = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLButtonElement>("button"))
      .filter((button) => button.scrollWidth > button.clientWidth || button.scrollHeight > button.clientHeight)
      .map((button) => button.getAttribute("aria-label") ?? button.textContent?.trim() ?? "button"),
  );
  expect(clipped).toEqual([]);
}

test("recovers a crashed prompt workflow and loads its report", async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("CONNECTED");
  await expect(page.getByRole("option", { name: /Demo/ })).toBeVisible();
  await page.getByRole("button", { name: "Start procedure" }).click();

  await expect(page.getByRole("heading", { name: "Demo" })).toBeVisible();
  const pause = page.getByRole("button", { name: "Pause" });
  await expect(pause).toBeEnabled();
  await pause.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("PAUSED", { exact: true })).toBeVisible({ timeout: 10_000 });
  const resume = page.getByRole("button", { name: "Resume" });
  await resume.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Operator action required")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("heading", { name: "Procedure source" })).toBeVisible();
  await expect(page.getByText(/Line \d+ - Prompt:/)).toBeVisible();
  const widths = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(Math.max(widths.document, widths.body)).toBeLessThanOrEqual(widths.viewport);
  await expectControlTextFits(page);
  await page.getByRole("button", { name: "Simulate crash" }).click();
  await expect(page.getByText("RECOVERY_REQUIRED", { exact: true })).toBeVisible({ timeout: 10_000 });
  await page.getByRole("button", { name: "Recover" }).click();
  await expect(page.getByText("Operator action required")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("radio", { name: "acknowledge" })).toBeChecked();
  await expectControlTextFits(page);
  if (testInfo.project.name === "mobile") {
    await page.screenshot({ path: "../artifacts/v0.2/mobile-recovered-prompt.png" });
  }
  await page.getByRole("button", { name: "Commit response" }).click();

  await expect(page.getByText("COMPLETED", { exact: true })).toBeVisible({ timeout: 10_000 });
  await page.getByRole("button", { name: "As-run report" }).click();
  await expect(page.getByRole("button", { name: "Export JSON" })).toBeVisible();
  if (testInfo.project.name === "chromium") {
    await page.screenshot({ path: "../artifacts/v0.2/desktop-as-run-report.png" });
  }
  await expectLoopbackOnly(page);
});

test("aborts a prompting simulator execution", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("CONNECTED");
  await expect(page.getByRole("option", { name: /Demo/ })).toBeVisible();
  await page.getByRole("button", { name: "Start procedure" }).click();
  await expect(page.getByText("Operator action required")).toBeVisible({ timeout: 10_000 });
  await page.getByRole("button", { name: "Abort" }).click();
  await expect(page.getByRole("heading", { name: "Abort execution?" })).toBeVisible();
  await page.getByLabel("Operational reason").fill("Integration test controlled abort");
  await page.getByRole("button", { name: "Confirm abort" }).click();
  await expect(page.getByText("ABORTED", { exact: true })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("Operator action required")).not.toBeVisible();
  await expectLoopbackOnly(page);
});

test("interlocks controls until a disconnected client resynchronizes", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("CONNECTED");
  await page.getByRole("button", { name: "Start procedure" }).click();
  await expect(page.getByText("Operator action required")).toBeVisible({ timeout: 10_000 });

  await context.setOffline(true);
  await expect(page.getByRole("status")).toContainText(/RECONNECTING|STALE/, { timeout: 10_000 });
  await expect(page.getByRole("button", { name: "Abort" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Commit response" })).toBeDisabled();

  await context.setOffline(false);
  await expect(page.getByRole("status")).toContainText("CONNECTED", { timeout: 15_000 });
  await expect(page.getByRole("button", { name: "Commit response" })).toBeEnabled();
  await expectLoopbackOnly(page);
});
