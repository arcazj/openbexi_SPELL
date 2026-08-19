import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const operatorToken = "e30.eyJyb2xlIjoib3BlcmF0b3IiLCJzdWIiOiJvcGVyYXRvciJ9.signature";
const catalog = {
  acl_revision: "1",
  catalog_id: "catalog-1",
  content_digest: "a".repeat(64),
  kind: "USER_DICTIONARY",
  revision: "9007199254740995",
  schema_version: "1",
};

test.beforeEach(async ({ page }) => {
  await page.addInitScript((token) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
  }, operatorToken);
  await page.route("**/api/v1/health", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ status: "ok", version: "0.8.0", mode: "simulator-only" }),
  }));
  await page.route("**/api/v1/procedures", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [] }) }));
  await page.route("**/api/v1/contexts", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [] }) }));
  await page.route("**/api/v1/master", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ items: [] }) }));

  await page.route("**/api/v1/data/catalogs**", async (route) => {
    const request = route.request();
    if (request.method() === "POST") {
      const body = request.postDataJSON() as Record<string, unknown>;
      expect(body.expected_revision).toBe("0");
      expect(request.headers()["idempotency-key"]).toMatch(/^console-/);
      expect(request.headers()["x-spell-session-id"]).toMatch(/^[0-9a-f-]{36}$/);
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({
        ...catalog,
        revision: "1",
        new_revision: "1",
        prior_revision: "0",
        operation_id: "operation-1",
        outcome: "PUBLISHED",
        replayed: false,
      }) });
      return;
    }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({
      catalogs: [catalog], next_cursor: null, owner_revision: "9007199254740997",
    }) });
  });
  await page.route("**/api/v1/data/dictionaries**", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ dictionaries: [], next_cursor: null, owner_revision: "1" }) }));
  await page.route("**/api/v1/data/containers**", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ containers: [], next_cursor: null, owner_revision: "1" }) }));
  await page.route("**/api/v1/data/shared/namespaces**", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({ namespaces: [], next_cursor: null, owner_revision: "1" }) }));
  await page.route("**/api/v1/data/files/PROJECT_DATA/directory**", (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify({
    root_id: "PROJECT_DATA", virtual_path: "", revision: "2", next_cursor: null,
    items: [{ name: "result.txt", virtual_path: "result.txt", kind: "FILE", revision: "1", size: 12, content_sha256: "b".repeat(64) }],
  }) }));
});

async function assertContainedTables(page: import("@playwright/test").Page) {
  const failures = await page.locator(".data-table-scroll").evaluateAll((containers) =>
    containers.flatMap((container, index) => {
      const table = container.querySelector("table");
      if (!table) return [];
      const bounds = container.getBoundingClientRect();
      const viewport = document.documentElement.clientWidth;
      return bounds.left < -1 || bounds.right > viewport + 1 || table.scrollWidth > container.scrollWidth + 1
        ? [{ index, bounds: { left: bounds.left, right: bounds.right }, table: table.scrollWidth, container: container.scrollWidth, viewport }]
        : [];
    }),
  );
  expect(failures).toEqual([]);
}

test("operates the bounded data workspace with keyboard navigation", async ({ page }) => {
  await page.goto("/");
  const executionTab = page.getByRole("tab", { name: "Execution" });
  await executionTab.focus();
  await page.keyboard.press("End");

  const dataTab = page.getByRole("tab", { name: "Data services" });
  await expect(dataTab).toBeFocused();
  await expect(dataTab).toHaveAttribute("aria-selected", "true");
  const workspace = page.getByRole("main", { name: "Data services workspace" });
  await expect(workspace.getByText("OPERATOR")).toBeVisible();
  await expect(workspace.getByRole("button", { name: "catalog-1" })).toBeVisible();
  await expect(workspace.getByText("9007199254740995")).toBeVisible();
  await assertContainedTables(page);

  await workspace.getByLabel("Catalog ID").fill("new-catalog");
  await workspace.getByRole("button", { name: "Publish" }).click();
  await expect(workspace.getByRole("status")).toContainText("PUBLISHED at revision 1");

  const catalogsTab = workspace.getByRole("tab", { name: "Catalogs" });
  await catalogsTab.focus();
  await page.keyboard.press("End");
  await expect(workspace.getByRole("tab", { name: "Files" })).toBeFocused();
  await expect(workspace.getByRole("button", { name: /result\.txt/ })).toBeVisible();
  await assertContainedTables(page);

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
