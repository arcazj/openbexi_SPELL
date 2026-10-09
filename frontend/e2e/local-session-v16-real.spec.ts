import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the loopback simulator Compose profile");
test.use({ trace: "off", video: "off" });

test("automatically connects, reloads and renews the same local operator", async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toContainText("CONNECTED", { timeout: 20_000 });
  await expect(page.getByLabel("Signed JWT")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Session access" })).toHaveCount(0);
  const identity = () => page.evaluate(() => {
    const credential = sessionStorage.getItem("openbexi.spell.access-token");
    if (!credential) return { subject: "", role: "", lifetime: 0, id: "" };
    const body = JSON.parse(atob(credential.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { subject: body.sub, role: body.role, lifetime: body.exp - body.iat, id: body.jti };
  });
  const first = await identity();
  expect(first.role).toBe("operator"); expect(first.lifetime).toBeLessThanOrEqual(300);
  await page.reload();
  await expect(page.locator(".connection-badge")).toContainText("CONNECTED", { timeout: 20_000 });
  expect((await identity()).subject).toBe(first.subject);
  await page.evaluate(() => {
    sessionStorage.removeItem("openbexi.spell.access-token");
    window.dispatchEvent(new Event("spell-auth-changed"));
  });
  await expect.poll(async () => (await identity()).id, { timeout: 20_000 }).not.toBe("");
  await expect.poll(async () => (await identity()).id, { timeout: 20_000 }).not.toBe(first.id);
  expect((await identity()).subject).toBe(first.subject);
  await expect(page.locator(".connection-badge")).toContainText("CONNECTED", { timeout: 20_000 });
  expect((await new AxeBuilder({ page }).analyze()).violations.filter((item) =>
    item.impact === "serious" || item.impact === "critical")).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("automatic-simulator-session.png") });
  const development = await page.context().newPage();
  await development.goto("/development.html");
  await expect(development.getByText("Development environment", { exact: true })).toBeVisible();
  await expect(development.getByLabel("Signed JWT")).toHaveCount(0);
  await development.close();
});

test("recovers a fresh browser after the simulator is unavailable", async ({ page }, testInfo) => {
  await page.route("**/api/v1/local-session", (route) => route.abort("connectionfailed"));
  await page.goto("/");
  await expect(page.getByText("Simulator unavailable. Check the local services, then reconnect.")).toBeVisible();
  await expect(page.getByLabel("Signed JWT")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("simulator-unavailable.png") });
  await page.unroute("**/api/v1/local-session");
  await page.getByRole("button", { name: "Retry connection" }).click();
  await expect(page.locator(".connection-badge")).toContainText("CONNECTED", { timeout: 20_000 });
});

test("rejects non-browser bootstrap and leaves API authentication enforced", async ({ request, page }, testInfo) => {
  const bootstrap = await request.post("/api/v1/local-session", { data: {} });
  expect(bootstrap.status()).toBe(403);
  const anonymous = await request.get("/api/v1/procedures");
  expect(anonymous.status()).toBe(401);
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toContainText("CONNECTED", { timeout: 20_000 });
  await page.screenshot({ path: testInfo.outputPath("protected-simulator-session.png") });
});
