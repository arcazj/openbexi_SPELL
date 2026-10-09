import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type TestInfo } from "@playwright/test";
import { createHash } from "node:crypto";
import { ensureDssObservationReady } from "./dss-readiness";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the local DSS-backed simulator stack");
test.setTimeout(90_000);

type Snapshot = {
  execution: {
    state: string;
    variables: Record<string, unknown>;
    controller_lease: { holder_subject_id: string; state: string; held_by_current_session: boolean } | null;
  };
  active_prompt: { id: string; prompt_profile: string | null; default: unknown; response_deadline: string | null } | null;
};
type CommandEvent = {
  event_type: string;
  payload: {
    request_id?: string;
    selector?: { kind: string };
    confirmation?: { prompt_id: string } | null;
    outcome?: string;
    execution_succeeded?: boolean;
    checkpoint?: { provider_call_count: number; confirmed_by: string | null; elements: Array<{ disposition: string }> };
  };
};

const catalogIds = ["dss_command_catalog_v19", "language_reference_244", "native_command_branch_v18", "native_command_default_v18", "observation_command_v19", "observation_decision_v19", "observation_wait_v19", "prompt_workflow_v17", "telecommand_modes_v18", "test_Python", "test_python_core", "tutorial_core_v18"];

async function read<T>(page: Page, path: string): Promise<T> {
  return page.evaluate(async (url) => {
    const response = await fetch(url, { headers: {
      Authorization: `Bearer ${sessionStorage.getItem("openbexi.spell.access-token") ?? ""}`,
      "X-Spell-Session-Id": sessionStorage.getItem("openbexi.spell.session-id") ?? "",
      "X-Spell-Client-Instance-Key-Id": sessionStorage.getItem("openbexi.spell.client-instance-key") ?? "",
    }, cache: "no-store" });
    if (!response.ok) throw new Error(`proof read status ${response.status}`);
    return response.json();
  }, path) as Promise<T>;
}

async function start(page: Page, name: string): Promise<string> {
  const option = page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option").filter({ hasText: name });
  await expect(option).toBeVisible();
  await option.click();
  const [response] = await Promise.all([
    page.waitForResponse((item) => new URL(item.url()).pathname === "/api/v1/executions" && item.request().method() === "POST"),
    page.getByRole("button", { name: "Start procedure" }).click(),
  ]);
  expect(response.status()).toBe(202);
  return ((await response.json()) as { execution: { id: string } }).execution.id;
}

async function answer(page: Page, value: "YES" | "NO") {
  await page.getByRole("radio", { name: value, exact: true }).check();
  const [response] = await Promise.all([
    page.waitForResponse((item) => /\/api\/v1\/prompts\/[^/]+\/responses$/.test(new URL(item.url()).pathname) && item.request().method() === "POST"),
    page.getByRole("button", { name: "Commit response" }).click(),
  ]);
  expect(response.status()).toBe(202);
  expect(response.request().postDataJSON()).toEqual(expect.objectContaining({ action: "COMMIT", value }));
}

async function completed(page: Page, id: string) {
  await expect.poll(async () => (await read<Snapshot>(page, `/api/v1/executions/${id}/snapshot`)).execution.state, { timeout: 20_000 }).toBe("completed");
  await expect(page.locator(".execution-metadata .state-pill")).toHaveText("COMPLETED", { timeout: 20_000 });
}

async function commands(page: Page, id: string): Promise<CommandEvent[]> {
  return (await read<{ items: CommandEvent[] }>(page, `/api/v1/executions/${id}/events?limit=1000`)).items.filter((row) => row.event_type.startsWith("procedure.telecommand_"));
}

async function expectBuiltWithoutDispatch(page: Page, id: string) {
  const events = await commands(page, id);
  expect(events.map((row) => row.event_type)).toEqual(["procedure.telecommand_built"]);
  expect(events[0]!.payload).toEqual({ catalog_bound: true, step_index: 1, target: "command" });
  for (const kind of ["requested", "result", "settled"]) {
    expect(events.filter((row) => row.event_type === `procedure.telecommand_${kind}`)).toHaveLength(0);
  }
}

async function openWorkspace(page: Page, testInfo: TestInfo) {
  if (testInfo.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await ensureDssObservationReady(page);
  const catalog = await read<{ items: Array<{ id: string }> }>(page, "/api/v1/procedures");
  expect(catalog.items.map((item) => item.id)).toEqual(catalogIds);
  await expect(page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option")).toHaveCount(catalogIds.length);
}

async function capture(page: Page, testInfo: TestInfo, name: string, selector: string) {
  const accessibility = await new AxeBuilder({ page }).include(selector).analyze();
  expect(accessibility.violations.filter((row) => row.impact === "serious" || row.impact === "critical")).toEqual([]);
  const geometry = await page.evaluate((target) => {
    const bounds = document.querySelector(target)!.getBoundingClientRect();
    return {
      viewport: document.documentElement.clientWidth,
      content: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
      left: bounds.left,
      right: bounds.right,
    };
  }, selector);
  expect(geometry.content).toBeLessThanOrEqual(geometry.viewport);
  expect(geometry.left).toBeGreaterThanOrEqual(-0.5);
  expect(geometry.right).toBeLessThanOrEqual(geometry.viewport + 0.5);
  await page.screenshot({ path: testInfo.outputPath(`${name}-${testInfo.project.name}.png`), fullPage: true });
}

test("native NO and Abort prevent dispatch while YES requires separate command confirmation", async ({ page }, testInfo) => {
  await openWorkspace(page, testInfo);
  const declined = await start(page, "Native Command Branch V18");
  await expect(page.getByRole("heading", { name: "Run the simulated command?" })).toBeVisible({ timeout: 20_000 });
  await expectBuiltWithoutDispatch(page, declined);
  await answer(page, "NO");
  await completed(page, declined);
  expect((await read<Snapshot>(page, `/api/v1/executions/${declined}/snapshot`)).execution.variables).toMatchObject({ answer: "NO", mask: 9 });
  await expectBuiltWithoutDispatch(page, declined);

  const id = await start(page, "Native Command Branch V18");
  await expect(page.getByRole("heading", { name: "Run the simulated command?" })).toBeVisible({ timeout: 20_000 });
  const native = (await read<Snapshot>(page, `/api/v1/executions/${id}/snapshot`)).active_prompt!;
  expect(native.prompt_profile).toBe("spell-lrm244/0.17");
  await answer(page, "YES");
  await expect(page.getByRole("heading", { name: /^Confirm deterministic simulator telecommand plan / })).toBeVisible({ timeout: 20_000 });
  const confirmationSnapshot = await read<Snapshot>(page, `/api/v1/executions/${id}/snapshot`);
  const confirmation = confirmationSnapshot.active_prompt!;
  const lease = confirmationSnapshot.execution.controller_lease;
  expect(lease).toMatchObject({ state: "ACTIVE", held_by_current_session: true });
  expect(lease!.holder_subject_id).toEqual(expect.any(String));
  expect(lease!.holder_subject_id.length).toBeGreaterThan(0);
  // The TC checkpoint records the bounded SHA-256 alias of the durable actor.
  const confirmedBy = `operator-${createHash("sha256").update(lease!.holder_subject_id, "utf8").digest("hex").slice(0, 32)}`;
  expect(confirmation.id).not.toBe(native.id);
  expect(confirmation.prompt_profile).toBeNull();
  expect(confirmation.default).toBe("NO");
  await expectBuiltWithoutDispatch(page, id);
  await capture(page, testInfo, "native-command-confirmation", ".prompt-panel");
  await answer(page, "YES");
  await completed(page, id);
  const events = await commands(page, id);
  const requests = events.filter((row) => row.event_type === "procedure.telecommand_requested");
  const results = events.filter((row) => row.event_type === "procedure.telecommand_result");
  expect(events.filter((row) => row.event_type === "procedure.telecommand_built").map((row) => row.payload)).toEqual([{ catalog_bound: true, step_index: 1, target: "command" }]);
  expect(requests).toHaveLength(1);
  expect(requests[0]!.payload.selector?.kind).toBe("item");
  expect(requests[0]!.payload.confirmation?.prompt_id).toBe(confirmation.id);
  expect(results).toHaveLength(1);
  expect(results[0]!.payload.request_id).toBe(requests[0]!.payload.request_id);
  expect(results[0]!.payload.outcome).toBe("SETTLED");
  expect(results[0]!.payload.execution_succeeded).toBe(true);
  expect(results[0]!.payload.checkpoint?.provider_call_count).toBe(5);
  expect(results[0]!.payload.checkpoint?.confirmed_by).toBe(confirmedBy);
  expect(events.filter((row) => row.event_type === "procedure.telecommand_settled")).toHaveLength(1);
  expect((await read<Snapshot>(page, `/api/v1/executions/${id}/snapshot`)).execution.variables).toMatchObject({ answer: "YES", mask: 9 });

  const aborted = await start(page, "Native Command Branch V18");
  await expect(page.getByRole("heading", { name: "Run the simulated command?" })).toBeVisible({ timeout: 20_000 });
  await page.getByRole("button", { name: "Abort prompt" }).click();
  await expect.poll(async () => (await read<Snapshot>(page, `/api/v1/executions/${aborted}/snapshot`)).execution.state, { timeout: 20_000 }).toBe("aborted");
  expect((await read<Snapshot>(page, `/api/v1/executions/${aborted}/snapshot`)).execution.variables).not.toHaveProperty("answer");
  await expectBuiltWithoutDispatch(page, aborted);
});

test("server default skips dispatch and catalog tutorials prove direct built load-only and core results", async ({ page }, testInfo) => {
  await openWorkspace(page, testInfo);
  const defaulted = await start(page, "Native Command Default V18");
  await expect(page.getByRole("heading", { name: "Send only with YES" })).toBeVisible({ timeout: 20_000 });
  const prompt = (await read<Snapshot>(page, `/api/v1/executions/${defaulted}/snapshot`)).active_prompt!;
  expect(prompt.prompt_profile).toBe("spell-lrm244/0.17");
  expect(prompt.default).toBe("NO");
  expect(prompt.response_deadline).not.toBeNull();
  // Observe the server settlement without racing or submitting the default.
  await completed(page, defaulted);
  expect((await read<Snapshot>(page, `/api/v1/executions/${defaulted}/snapshot`)).execution.variables.answer).toBe("NO");
  expect(await commands(page, defaulted)).toHaveLength(0);

  const modes = await start(page, "Telecommand Modes V18");
  await completed(page, modes);
  const events = await commands(page, modes);
  const requests = events.filter((row) => row.event_type === "procedure.telecommand_requested");
  const results = events.filter((row) => row.event_type === "procedure.telecommand_result");
  expect(requests.map((row) => row.payload.selector?.kind)).toEqual(["name", "item", "name"]);
  expect(new Set(requests.map((row) => row.payload.request_id)).size).toBe(3);
  expect(results.map((row) => row.payload.request_id)).toEqual(requests.map((row) => row.payload.request_id));
  expect(results.map((row) => row.payload.outcome)).toEqual(["SETTLED", "SETTLED", "SETTLED"]);
  expect(results.map((row) => row.payload.execution_succeeded)).toEqual([true, true, false]);
  expect(results.map((row) => row.payload.checkpoint?.provider_call_count)).toEqual([5, 5, 2]);
  expect(results[2]!.payload.checkpoint?.elements.map((item) => item.disposition)).toEqual(["LOADED_ONLY"]);
  expect(events.filter((row) => row.event_type === "procedure.telecommand_settled")).toHaveLength(3);

  const core = await start(page, "Tutorial Core V18");
  await completed(page, core);
  expect((await read<Snapshot>(page, `/api/v1/executions/${core}/snapshot`)).execution.variables).toMatchObject({ total: 12, power: 32, mask: 3, label: "core checks passed" });
  expect(await commands(page, core)).toHaveLength(0);
  await capture(page, testInfo, "native-command-catalog-results", ".execution-workspace");
});
