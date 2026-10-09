import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type TestInfo } from "@playwright/test";
import { createHash, randomUUID } from "node:crypto";
import type { DssCommandResult, DssState, DssTelemetry } from "../src/dss/api";

test.skip(!process.env.SPELL_REAL_BACKEND, "requires the actual local DSS, Kafka and SPELL drivers");
test.describe.configure({ mode: "serial" });
test.setTimeout(120_000);

type Packet = { topic: string; packet_hex: string; packet_sha256: string; published: boolean };
type Operation = { operation_id: string; ingress_delivery_count: number; packet_hex: string; packet_sha256: string; acknowledgement: { execution_id: string; procedure_id: string; stage: string; outcome: string } };
type Evidence = { database_digest: string; epoch: string; operations: Operation[]; packets: Packet[]; commands: Array<{ executed: number }> };
type EvidencePage = Evidence & { final_state: DssState; pagination: { offset: number; limit: number; next_offset: number | null; counts: Record<"commands" | "operations" | "packets", number>; revision: number } };
type ProviderDetail = { provider: string; database_digest: string; command_packet_sha256: string; acknowledgement_packet_sha256: string;
  telemetry: Array<{ packet_sha256: string; topic: string; partition: number; offset: number }> };

async function read<T>(page: Page, path: string): Promise<T> {
  return page.evaluate(async (url) => {
    const headers: Record<string, string> = url.startsWith("/api/") ? {
      Authorization: `Bearer ${sessionStorage.getItem("openbexi.spell.access-token") ?? ""}`,
      "X-Spell-Session-Id": sessionStorage.getItem("openbexi.spell.session-id") ?? "",
      "X-Spell-Client-Instance-Key-Id": sessionStorage.getItem("openbexi.spell.client-instance-key") ?? "",
    } : {};
    const response = await fetch(url, { headers, cache: "no-store" });
    if (!response.ok) throw new Error(`evidence read failed (${response.status})`);
    return response.json();
  }, path) as Promise<T>;
}
async function capture(page: Page, info: TestInfo, name: string) {
  const audit = await new AxeBuilder({ page }).analyze();
  expect(audit.violations.filter((issue) => issue.impact === "critical" || issue.impact === "serious")).toEqual([]);
  expect(await page.evaluate(() => Math.max(document.body.scrollWidth, document.documentElement.scrollWidth))).toBeLessThanOrEqual(page.viewportSize()!.width);
  await page.screenshot({ path: info.outputPath(`${name}-${info.project.name}.png`), fullPage: true });
}
async function dss(page: Page, info: TestInfo) {
  if (info.project.name === "chromium") await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/dss/");
  await expect(page.getByRole("table", { name: "Bus state" })).toBeVisible();
  await expect(page.getByLabel("Simulator status")).toContainText("Kafka: connected", { timeout: 20_000 });
  // Test-only scenario setup preserves the previous packet journal. Each case
  // proves its own epoch and bounded evidence, independent of uptime/history.
  let state = await read<DssState>(page, "/dss/api/v1/state");
  if (state.running) state = await control(page, "Pause");
  // The closed qualification acknowledgement uses the canonical fields from
  // dss.engine.scenario_retirement_token; it is not a normal UI control.
  const retirement = createHash("sha256").update(JSON.stringify({
    database_digest: state.database_digest, epoch: state.epoch,
    reason: "QUALIFICATION_CASE_TERMINATED", revision: state.revision, scenario_id: state.scenario_id,
  })).digest("hex");
  const setup = await page.evaluate(async (body) => {
    const response = await fetch("/dss/api/v1/scenarios/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return { status: response.status, state: await response.json() as { epoch: string; running: boolean } };
  }, { scenario_id: `browser-${info.project.name}-${randomUUID()}`, expected_epoch: state.epoch, retirement_token: retirement });
  expect(setup.status).toBe(200);
  expect(setup.state.epoch).not.toBe(state.epoch);
  expect(setup.state.running).toBe(false);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText(`Epoch: ${setup.state.epoch}`, { exact: true })).toBeVisible();
  await expect.poll(async () => {
    const packet = await read<DssTelemetry>(page, "/dss/api/v1/telemetry");
    return packet.epoch === setup.state.epoch && packet.published;
  }).toBe(true);
}
async function control(page: Page, action: "Pause" | "Resume" | "Advance one tick"): Promise<DssState> {
  // If another automatic dynamics tick wins a PAUSE fence, explicitly observe
  // and review the new state before trying again. No command is retried here.
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const [response] = await Promise.all([
      page.waitForResponse((item) => new URL(item.url()).pathname === "/dss/api/v1/control" && item.request().method() === "POST"),
      page.getByRole("button", { name: action, exact: true }).click(),
    ]);
    if (response.status() === 200) return await response.json() as DssState;
    expect(response.status()).toBe(409);
    await expect(page.getByRole("status").first()).toContainText("State changed");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
  }
  throw new Error("control fence repeatedly changed");
}
function packetHash(packet: Packet | Operation) {
  expect(createHash("sha256").update(Buffer.from(packet.packet_hex, "hex")).digest("hex")).toBe(packet.packet_sha256);
}
async function evidence(page: Page, state: DssState): Promise<Evidence> {
  await expect.poll(async () => (await read<DssState>(page, "/dss/api/v1/state")).transport?.outbox?.pending_packets).toBe(0);
  const path = `/dss/api/v1/evidence?scenario_id=${encodeURIComponent(state.scenario_id)}&limit=32`;
  const first = await read<EvidencePage>(page, path);
  expect(first.final_state.epoch).toBe(state.epoch);
  expect(first.final_state.revision).toBe(state.revision);
  const all: Evidence = { ...first, operations: [...first.operations], packets: [...first.packets], commands: [...first.commands] };
  let offset = first.pagination.next_offset;
  for (let pages = 1; offset !== null; pages += 1) {
    expect(pages).toBeLessThan(2000);
    const next = await read<EvidencePage>(page, `${path}&offset=${offset}&expected_revision=${first.pagination.revision}`);
    expect(next.pagination.offset).toBe(offset);
    expect(next.pagination.counts).toEqual(first.pagination.counts);
    expect(next.pagination.revision).toBe(first.pagination.revision);
    expect(next.final_state).toEqual(first.final_state);
    expect(next.epoch).toBe(first.epoch);
    all.commands.push(...next.commands); all.operations.push(...next.operations); all.packets.push(...next.packets);
    offset = next.pagination.next_offset;
  }
  for (const key of ["commands", "operations", "packets"] as const) expect(all[key]).toHaveLength(first.pagination.counts[key]);
  return all;
}

test("DSS controls a persisted satellite and sends confirmed binary commands through its compact pages", async ({ page }, info) => {
  await dss(page, info);
  let before = await read<DssState>(page, "/dss/api/v1/state");
  if (before.running) before = await control(page, "Pause");
  const advanced = await control(page, "Advance one tick");
  expect(advanced.core.tick).toBe(Number(before.core.tick) + 1);
  expect(advanced.revision).toBe(before.revision + 1);
  await expect(page.getByLabel("Simulator status")).toContainText(`Revision: ${advanced.revision}`);
  await page.getByRole("combobox", { name: "Command", exact: true }).selectOption("CMDNAME");
  await page.getByRole("textbox", { name: "ARG1 (FLOAT, optional)" }).fill("1.1");
  await expect(page.getByRole("button", { name: "Send simulator command" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "Confirm this simulator command" }).check();
  const [response] = await Promise.all([
    page.waitForResponse((item) => new URL(item.url()).pathname === "/dss/api/v1/commands" && item.request().method() === "POST"),
    page.getByRole("button", { name: "Send simulator command" }).click(),
  ]);
  expect(response.status()).toBe(200);
  const result = await response.json() as DssCommandResult;
  expect(result.outcome).toBe("SUCCEEDED");
  expect(result.receipts.map((receipt) => receipt.outcome)).toEqual(["ACCEPTED", "LOADED", "RELEASED", "ACKNOWLEDGED", "SUCCEEDED"]);
  const after = await read<DssState>(page, "/dss/api/v1/state");
  expect(after.epoch).toBe(before.epoch);
  expect(after.payload.setpoint_milli).toBe(1100);
  expect(after.core.commands_executed).toBe(Number(before.core.commands_executed) + 1);
  const proof = await evidence(page, after);
  const commands = proof.operations.filter((operation) => operation.operation_id === result.operation_id);
  expect(commands).toHaveLength(5);
  expect(commands.every((operation) => operation.acknowledgement.procedure_id === "DSS_UI")).toBe(true);
  expect(commands.every((operation) => operation.ingress_delivery_count === 1)).toBe(true);
  commands.forEach(packetHash);
  expect(commands.every((operation) => operation.packet_hex.startsWith("1864"))).toBe(true);
  await expect.poll(async () => (await read<DssTelemetry>(page, "/dss/api/v1/telemetry")).published).toBe(true);
  const telemetry = await read<DssTelemetry>(page, "/dss/api/v1/telemetry");
  expect(telemetry.epoch).toBe(after.epoch);
  expect(telemetry.revision).toBe(after.revision);
  expect(proof.packets.find((packet) => packet.packet_sha256 === telemetry.packet_sha256)?.topic).toBe("openbexi.GENERIC.tm");
  await page.getByRole("tab", { name: "Satellite", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Telemetry", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("table", { name: "Satellite telemetry" })).toBeVisible();
  await page.getByRole("searchbox", { name: "Filter telemetry" }).fill("SETPOINT");
  const setpoint = telemetry.samples.find((sample) => sample.item_id.includes("SETPOINT"));
  expect(setpoint).toBeDefined();
  await expect(page.getByRole("row").filter({ hasText: setpoint!.item_id })).toContainText("1100");
  await page.getByText("Packet provenance", { exact: true }).click();
  await expect(page.getByText(telemetry.packet_sha256!, { exact: true })).toBeVisible();
  if (info.project.name === "mobile") {
    const scroll = page.getByRole("region", { name: "Telemetry values, scroll for packet details" });
    await scroll.focus(); await page.keyboard.press("ArrowRight");
    await expect.poll(() => scroll.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
    await page.keyboard.press("ArrowLeft");
    await expect.poll(() => scroll.evaluate((element) => element.scrollLeft)).toBe(0);
  }
  await capture(page, info, "dss-packet-telemetry");
});

test("SPELL command confirmation changes the same DSS state and binds actual Kafka telemetry", async ({ page }, info) => {
  await dss(page, info);
  let before = await read<DssState>(page, "/dss/api/v1/state");
  if (!before.running) before = await control(page, "Resume");
  await page.getByRole("link", { name: "SPELL console" }).click();
  await expect(page.locator(".connection-badge")).toHaveText("CONNECTED", { timeout: 20_000 });
  await expect(page.getByText("Session access", { exact: true })).toHaveCount(0);
  const option = page.getByRole("listbox", { name: "Procedure catalog" }).getByRole("option").filter({ hasText: "Native Command Branch V18" });
  await expect(option).toBeVisible(); await option.click();
  const [started] = await Promise.all([
    page.waitForResponse((item) => new URL(item.url()).pathname === "/api/v1/executions" && item.request().method() === "POST"),
    page.getByRole("button", { name: "Start procedure" }).click(),
  ]);
  expect(started.status()).toBe(202);
  const id = ((await started.json()) as { execution: { id: string } }).execution.id;
  await expect(page.getByRole("heading", { name: "Run the simulated command?" })).toBeVisible({ timeout: 20_000 });
  await page.getByRole("radio", { name: "YES", exact: true }).check();
  await page.getByRole("button", { name: "Commit response" }).click();
  await expect(page.getByRole("heading", { name: /^Confirm deterministic simulator telecommand plan / })).toBeVisible({ timeout: 20_000 });
  expect((await read<DssState>(page, "/dss/api/v1/state")).core.commands_executed).toBe(before.core.commands_executed);
  await page.getByRole("radio", { name: "YES", exact: true }).check();
  await page.getByRole("button", { name: "Commit response" }).click();
  await expect.poll(async () => (await read<{ execution: { state: string } }>(page, `/api/v1/executions/${id}/snapshot`)).execution.state, { timeout: 30_000 }).toBe("completed");
  const events = await read<{ items: Array<{ event_type: string; payload: { execution_succeeded?: boolean; checkpoint?: { elements: Array<{ provider_detail: Record<string, { native: ProviderDetail }> }> } } }> }>(page, `/api/v1/executions/${id}/events?limit=1000`);
  const results = events.items.filter((event) => event.event_type === "procedure.telecommand_result");
  expect(results).toHaveLength(1); expect(results[0]!.payload.execution_succeeded).toBe(true);
  const provider = results[0]!.payload.checkpoint!.elements[0]!.provider_detail.ONBOARD_EXECUTION!.native;
  expect(provider.provider).toBe("dss-cortex-kafka");
  expect(provider.database_digest).toBe(before.database_digest);
  expect(provider.telemetry).toHaveLength(1);
  expect(provider.telemetry[0]).toMatchObject({ topic: "openbexi.GENERIC.tm", partition: 0 });
  expect(provider.telemetry[0]!.offset).toBeGreaterThanOrEqual(0);
  let after = await read<DssState>(page, "/dss/api/v1/state");
  expect(after.core.commands_executed).toBe(Number(before.core.commands_executed) + 1);
  await page.locator(".console-menubar summary").filter({ hasText: /^System$/ }).click();
  await page.getByRole("link", { name: "DSS satellite simulator" }).click();
  await expect(page.getByRole("table", { name: "Core state" })).toBeVisible();
  after = await control(page, "Pause");
  const proof = await evidence(page, after);
  const operations = proof.operations.filter((operation) => operation.acknowledgement.execution_id === id);
  expect(operations).toHaveLength(5); operations.forEach(packetHash);
  expect(operations.every((operation) => operation.ingress_delivery_count === 1)).toBe(true);
  const decodedPacket = proof.packets.find((packet) => packet.packet_sha256 === provider.telemetry[0]!.packet_sha256);
  expect(decodedPacket).toBeDefined(); expect(decodedPacket!.published).toBe(true); packetHash(decodedPacket!);
  await expect(page.getByRole("table", { name: "Core state" }).getByRole("row", { name: /Last Command Name CMDNAME/ })).toBeVisible();
  await capture(page, info, "dss-shared-satellite-state");
});
