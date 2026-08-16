import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const executionId = "execution-20260815-very-long-stable-identity-000000000001";
const lease = {
  id: "controller-lease-20260815-0001",
  revision: 4,
  control_fencing_token: 12,
  execution_id: executionId,
  holder_subject_id: "operator-a",
  holder_session_id: "session-a",
  issued_at: "2026-08-15T18:00:00Z",
  expires_at: "2026-08-15T18:30:00Z",
  state: "ACTIVE",
  held_by_current_session: true,
};

test.beforeEach(async ({ page }) => {
  await page.clock.setFixedTime(new Date("2026-08-15T18:05:00Z"));
  await page.addInitScript(() => {
    window.sessionStorage.setItem("openbexi.spell.access-token", "mock.jwt.token");
    class StableWebSocket extends EventTarget {
      static OPEN = 1;
      readyState = 1;
      onopen: ((event: Event) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onclose: ((event: CloseEvent) => void) | null = null;
      onerror: ((event: Event) => void) | null = null;
      constructor(_url: string, _protocols?: string | string[]) { super(); window.setTimeout(() => this.onopen?.(new Event("open")), 0); }
      send(): void {}
      close(): void {}
    }
    Object.defineProperty(window, "WebSocket", { value: StableWebSocket });
  });

  let namedAction = { id: "action-1", revision: 2, execution_id: executionId, name: "acknowledge", label: "Acknowledge hold", severity: "WARNING", handler_id: "bounded-handler-1", enabled: true, dismissed: false, source_digest: "a".repeat(64) };
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let body: unknown;
    if (path === "/api/v1/health") body = { status: "ok", version: "0.6.0", mode: "simulator-only" };
    else if (path === "/api/v1/procedures") body = { items: [{ id: "checkout", name: "Checkout", description: "Synthetic checkout", version: "0.6", entrypoint: "checkout.spell.py", step_count: 3, source: "Log('start')\nPrompt('continue')\nLog('done')", steps: [{ index: 0, line: 1, type: "log", message: "start" }, { index: 1, line: 2, type: "prompt", question: "continue" }, { index: 2, line: 3, type: "log", message: "done" }] }] };
    else if (path === "/api/v1/contexts") body = { items: [{ id: "simulator", name: "Simulator", description: "Local synthetic context", attached: true, catalog_revision: "library-7", procedure_count: 1, active_execution_count: 1 }] };
    else if (path === "/api/v1/master") body = { items: [{ id: executionId, procedure_id: "checkout", procedure_name: "Checkout", context_id: "simulator", state: "PAUSED", revision: 9, last_sequence: 18, ownership_mode: "C", controller_lease: lease, effect_certainty: "NO_EFFECT", child_execution_ids: ["child-execution-1"], updated_at: "2026-08-15T12:00:08Z" }] };
    else if (path === `/api/v1/executions/${executionId}/snapshot`) body = {
      execution: { id: executionId, procedure_id: "checkout", procedure_name: "Checkout", context_id: "simulator", state: "PAUSED", revision: 9, current_step: 1, current_line: 2, last_sequence: 18, ownership_mode: "C", controller_lease: lease, effect_certainty: "NO_EFFECT", automatic: true, background_allowed: true, source_digest: "a".repeat(64), source: "Log('start')\nPrompt('continue')\nLog('done')", breakpoints: [3], outline: [{ id: "root", label: "Checkout", line: 1, depth: 0, kind: "procedure" }, { id: "prompt", label: "Continue prompt", line: 2, depth: 1, kind: "step" }], parent_execution_id: "parent-execution-1", child_execution_ids: ["child-execution-1"], steps: [{ index: 0, line: 1, type: "log", message: "start" }, { index: 1, line: 2, type: "prompt", question: "continue" }, { index: 2, line: 3, type: "log", message: "done" }], workspace_cursor: 18, executed_lines: [1], text_entries: [{ id: "text-1", sequence: 16, time: "2026-08-15T12:00:06Z", scope: "procedure", kind: "prompt.opened", message: "Continue decision opened", line: 2 }], as_run_entries: [{ id: "as-run-1", sequence: 17, time: "2026-08-15T12:00:07Z", scope: "operator", kind: "command.settled", message: "Pause applied", outcome: "PAUSED", correlation_id: "correlation-pause-1" }], support_logs: [{ event_id: "support-1", server_time: "2026-08-15T12:00:08Z", severity: "warning", source: "supervisor", event_type: "execution.warning", payload: { message: "Checkpoint committed" }, sequence: 18 }] },
      last_sequence: 18,
      events: [], telemetry: [], logs: [], inspection: [], schedules: [], actions: [], relationships: [],
    };
    else if (path === `/api/v1/executions/${executionId}/workspace-search`) {
      const url = new URL(request.url());
      const view = url.searchParams.get("view") ?? "SOURCE";
      const query = url.searchParams.get("query") ?? "";
      const items = view === "TEXT" && query === "decision"
        ? [{ id: "text-1", sequence: 16, time: "2026-08-15T12:00:06Z", scope: "procedure", kind: "prompt.opened", message: "Continue decision opened", line: 2 }]
        : [];
      body = { view, query, source_digest: "a".repeat(64), items, next_cursor: items.length ? 16 : 0 };
    }
    else if (path === `/api/v1/executions/${executionId}/workspace-view`) {
      const url = new URL(request.url());
      const view = url.searchParams.get("view") ?? "AS_RUN";
      const items = view === "TEXT"
        ? [{ id: "text-1", sequence: 16, time: "2026-08-15T12:00:06Z", scope: "procedure", kind: "prompt.opened", message: "Continue decision opened", line: 2 }]
        : view === "AS_RUN"
          ? [{ id: "as-run-1", sequence: 17, time: "2026-08-15T12:00:07Z", scope: "operator", kind: "command.settled", message: "Pause applied", outcome: "PAUSED", correlation_id: "correlation-pause-1" }]
          : [{ id: "support-1", sequence: 18, time: "2026-08-15T12:00:08Z", scope: "supervisor", kind: "execution.warning", message: "Checkpoint committed" }];
      body = { view, source_digest: "a".repeat(64), items, after_sequence: 0, next_cursor: null, has_more: false, through_sequence: 18 };
    }
    else if (path === `/api/v1/executions/${executionId}/inspection`) body = { items: [{ path: "IVARS.counter", scope: "IVARS", name: "counter", type: "INTEGER", value: 2, value_revision: 3, execution_revision: 9, freshness: "CURRENT", editable: true }, { path: "ARGS.mode", scope: "ARGS", name: "mode", type: "STRING", value: "nominal", value_revision: 1, execution_revision: 9, freshness: "CURRENT", editable: true }], console_operations: ["LIST_SCOPE", "READ_VALUE", "EXPAND_VALUE", "SEARCH_SOURCE_LITERAL", "WRITE_TYPED_LITERAL"], execution_revision: 9 };
    else if (path === `/api/v1/executions/${executionId}/monitors` && request.method() === "POST") body = { monitor: { id: "monitor-1", execution_id: executionId, subject_id: "operator-a", session_id: "session-a", client_instance_key_id: "client-a", mode: "M", state: "ACTIVE" } };
    else if (path === `/api/v1/executions/${executionId}/monitors/monitor-1` && request.method() === "DELETE") body = { monitor: { id: "monitor-1", execution_id: executionId, subject_id: "operator-a", session_id: "session-a", client_instance_key_id: "client-a", mode: "M", state: "CLOSED" } };
    else if (path === `/api/v1/executions/${executionId}/commands` && request.method() === "POST") body = { command: { id: "command-run-to-line", state: "ACCEPTED" } };
    else if (path === "/api/v1/schedules") body = { items: [{ id: "schedule-1", revision: 1, controller_execution_id: executionId, schedule_type: "ABSOLUTE", original_target: "2026-08-15T13:00:00Z", target_at_database_time: "2026-08-15T13:00:00Z", state: "PENDING", catalog_revision_id: "catalog-revision-1", context_id: "simulator", automatic: true, background_allowed: true }] };
    else if (path === `/api/v1/executions/${executionId}/actions`) body = { items: [namedAction] };
    else if (path === `/api/v1/executions/${executionId}/actions/action-1/mutations` && request.method() === "POST") {
      const operation = String(request.postDataJSON().operation);
      namedAction = { ...namedAction, revision: namedAction.revision + 1, enabled: operation === "ENABLE" ? true : operation === "DISABLE" ? false : namedAction.enabled, dismissed: operation === "DISMISS" };
      body = { action: namedAction };
    }
    else if (path === `/api/v1/executions/${executionId}/relationships`) body = { items: [{ id: "link-1", startproc_id: "startproc-1", parent_execution_id: "parent-execution-1", child_execution_id: executionId, child_catalog_revision_id: "catalog-revision-1", arguments_digest: "b".repeat(64), blocking: true, visible: true, automatic: false, created_at: "2026-08-15T12:00:00Z" }] };
    else if (path === `/api/v1/executions/${executionId}/breakpoints` && request.method() === "DELETE") body = { removed: 1 };
    else { await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ detail: `unmocked ${path}` }) }); return; }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
});

test("operates the dense v0.6 workspace on desktop and mobile", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText("CONNECTED");
  await expect(page.getByRole("heading", { name: "Master" })).toBeVisible();
  await page.getByRole("button", { name: new RegExp(`Open Checkout ${executionId}`) }).click();
  await expect(page.getByRole("heading", { name: "Checkout" })).toBeVisible();
  await expect(page.getByTitle(executionId).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /C Renew/ })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: /M Monitor/ })).toBeEnabled();
  await expect(page.getByRole("button", { name: /M Monitor/ })).toHaveAttribute("aria-pressed", "false");
  await page.getByRole("button", { name: /M Monitor/ }).click();
  await expect(page.getByRole("button", { name: /M Stop/ })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: /Simulate crash/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Kill$/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Remove all breakpoints" })).toBeEnabled();
  await page.getByRole("button", { name: "Remove all breakpoints" }).click();
  await expect(page.getByRole("button", { name: "Remove all breakpoints" })).toBeDisabled();
  const runRequest = page.waitForRequest((request) => new URL(request.url()).pathname === `/api/v1/executions/${executionId}/commands`);
  await page.getByTitle("Run atomically to selected line").click();
  const runPayload = (await runRequest).postDataJSON();
  expect(runPayload).toMatchObject({ type: "RUN", expected_execution_revision: 9, target: { line: 2, source_digest: "a".repeat(64) } });

  const sourceTab = page.getByRole("tab", { name: "Source" });
  await expect(page.locator(".operator-source-list li.executed-line")).toHaveCount(1);
  await sourceTab.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Text", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("table", { name: "Text" })).toContainText("Continue decision opened");
  await expect(page.getByRole("table", { name: "Text" })).toContainText("procedure");
  const searchRequest = page.waitForRequest((request) => new URL(request.url()).pathname === `/api/v1/executions/${executionId}/workspace-search`);
  await page.getByPlaceholder("Literal search").fill("decision");
  const searchUrl = new URL((await searchRequest).url());
  expect(Object.fromEntries(searchUrl.searchParams)).toMatchObject({ query: "decision", view: "TEXT", source_digest: "a".repeat(64), after_sequence: "0", limit: "100" });
  await expect(page.getByText("1 matches")).toBeVisible();
  await page.getByPlaceholder("Literal search").fill("");
  await page.getByRole("tablist", { name: "Procedure views" }).getByRole("tab", { name: "As-run", exact: true }).click();
  await expect(page.getByRole("table", { name: "As-run" })).toContainText("Pause applied");
  await expect(page.getByRole("table", { name: "As-run" })).toContainText("PAUSED");
  await expect(page.getByTitle("correlation-pause-1")).toBeVisible();
  await page.getByRole("tab", { name: "Support log", exact: true }).click();
  await expect(page.getByText("Checkpoint committed")).toBeVisible();

  await page.getByRole("tab", { name: "Inspect" }).click();
  await expect(page.getByRole("heading", { name: "Typed inspection" })).toBeVisible();
  await expect(page.getByRole("option", { name: /IVARS.counter/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Commit audited edit" })).toBeEnabled();
  await page.getByRole("tab", { name: "Schedules" }).click();
  await expect(page.getByRole("heading", { name: "One-shot schedule" })).toBeVisible();
  await expect(page.getByText("schedule-1")).toBeVisible();
  await page.getByRole("tab", { name: "Actions" }).click();
  await expect(page.getByText("Acknowledge hold")).toBeVisible();
  await page.getByRole("button", { name: "Disable Acknowledge hold" }).click();
  await expect(page.getByRole("button", { name: "Enable Acknowledge hold" })).toBeVisible();
  await page.getByRole("button", { name: "Enable Acknowledge hold" }).click();
  await page.getByRole("button", { name: "Dismiss Acknowledge hold" }).click();
  await expect(page.getByText(/DISMISSED/)).toBeVisible();
  await page.getByRole("tab", { name: "Relations" }).click();
  await expect(page.getByRole("heading", { name: "Parent and child procedures" })).toBeVisible();

  const widths = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }));
  expect(Math.max(widths.document, widths.body)).toBeLessThanOrEqual(widths.viewport);
  const clipped = await page.evaluate(() => Array.from(document.querySelectorAll<HTMLButtonElement>("button")).filter((button) => button.offsetParent !== null && (button.scrollWidth > button.clientWidth || button.scrollHeight > button.clientHeight)).map((button) => button.getAttribute("aria-label") ?? button.textContent?.trim()));
  expect(clipped).toEqual([]);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((violation) => violation.impact === "serious" || violation.impact === "critical")).toEqual([]);
});
