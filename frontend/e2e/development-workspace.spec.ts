import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { createHash } from "node:crypto";

const operatorToken = "e30.eyJzdWIiOiJvcGVyYXRvciIsInJvbGUiOiJvcGVyYXRvciJ9.signature";
const adminToken = "e30.eyJzdWIiOiJhZG1pbi1yZXZpZXdlciIsInJvbGUiOiJhZG1pbiJ9.signature";
const digestA = "a".repeat(64);
const digestB = "b".repeat(64);
const digestC = "c".repeat(64);
const exportArchive = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0xff, 0x10, 0x20]);
const exportDigest = createHash("sha256").update(exportArchive).digest("hex");
const bundleArchive = Buffer.from('{"format":"spell.bundle/1","entries":[]}');
const bundleDigest = createHash("sha256").update(bundleArchive).digest("hex");
const semanticReport = Buffer.from('{"diagnostics":[],"outcome":"PASS","project_id":"project-1","scope":"FILE","workspace_revision":4}');
const semanticReportDigest = createHash("sha256").update(semanticReport).digest("hex");

function project(closed = false, revision = 3) {
  return {
    project_id: "project-1",
    workspace_id: "workspace-1",
    display_name: "Flight Checkout",
    owner_subject: "operator",
    author_subject: "operator",
    workspace_revision: revision,
    base_history_revision_id: "history-1",
    base_bundle_digest: null,
    case_policy: "CASE_INSENSITIVE",
    manifest: {
      schema_version: "spell.project/0.9",
      project_id: "project-1",
      display_name: "Flight Checkout",
      case_policy: "CASE_INSENSITIVE",
      language_profile: "spell-restricted-ast/0.9",
      source_roots: ["src"],
      catalog_dependencies: [{ catalog_id: "sim-telemetry", catalog_revision: 4, content_digest: digestC }],
      owners: ["operator"],
      policy_labels: ["LOCAL_SYNTHETIC_NON_CUI_ONLY"],
    },
    closed,
    created_at: "2026-08-18T10:00:00Z",
    updated_at: "2026-08-18T10:00:00Z",
  };
}

const source = [
  "# @procedure checkout",
  "# @display-name Flight Checkout",
  "# @description Local simulator checkout",
  "# @language-profile spell-restricted-ast/0.9",
  "\"\"\"Flight checkout.\"\"\"",
  "Log('one')",
  "Log('two')",
  "",
].join("\n");

function resource(content = source) {
  return {
    resource_id: "resource-procedure",
    project_id: "project-1",
    path: "src/checkout.spell.py",
    kind: "PROCEDURE",
    media_type: "text/x-python",
    content,
    content_sha256: digestA,
    byte_length: new TextEncoder().encode(content).byteLength,
    revision: 2,
    created_by_subject: "operator",
    updated_by_subject: "operator",
    created_at: "2026-08-18T10:00:00Z",
    updated_at: "2026-08-18T10:00:00Z",
  };
}

function sourceFolder() {
  return {
    resource_id: "resource-src",
    project_id: "project-1",
    path: "src",
    kind: "SOURCE_FOLDER",
    media_type: "application/x-directory",
    content_sha256: createHash("sha256").update("").digest("hex"),
    byte_length: 0,
    revision: 1,
    created_by_subject: "operator",
    updated_by_subject: "operator",
    created_at: "2026-08-18T10:00:00Z",
    updated_at: "2026-08-18T10:00:00Z",
  };
}

interface ApiState {
  revision: number;
  closed: boolean;
  source: string;
  reviewed: boolean;
  bundleState: "CANDIDATE" | "APPROVED" | "PROMOTED" | "SUPERSEDED" | "WITHDRAWN";
  bundlePresent: boolean;
  promoted: boolean;
  registryRevision: number;
  registryState: "UNPUBLISHED" | "PROMOTED" | "SUPERSEDED" | "WITHDRAWN";
  currentBundleDigest: string | null;
  previousBundleDigest: string | null;
  promotionOperations: string[];
  externalAttempts: number;
  importMediaType: string | null;
  importAuthorization: string | null;
  importDigest: string | null;
  importFilename: string | null;
  importWorkspaceRevision: string | null;
  importIdempotencyKey: string | null;
  importBytes: Buffer | null;
  importShouldConflict: boolean;
  retainedImportApplied: boolean;
  exportAuthorization: string | null;
  reportAuthorization: string | null;
  createdDictionary: Record<string, unknown> | null;
  updatedManifest: Record<string, unknown> | null;
  checkRequests: Record<string, unknown>[];
  statusClean: boolean;
  historyOperations: Array<{ path: string; body: Record<string, unknown> }>;
}

async function installApi(page: Page): Promise<ApiState> {
  const state: ApiState = {
    revision: 3,
    closed: false,
    source,
    reviewed: false,
    bundleState: "CANDIDATE",
    bundlePresent: false,
    promoted: false,
    registryRevision: 0,
    registryState: "UNPUBLISHED",
    currentBundleDigest: null,
    previousBundleDigest: null,
    promotionOperations: [],
    externalAttempts: 0,
    importMediaType: null,
    importAuthorization: null,
    importDigest: null,
    importFilename: null,
    importWorkspaceRevision: null,
    importIdempotencyKey: null,
    importBytes: null,
    importShouldConflict: false,
    retainedImportApplied: false,
    exportAuthorization: null,
    reportAuthorization: null,
    createdDictionary: null,
    updatedManifest: null,
    checkRequests: [],
    statusClean: false,
    historyOperations: [],
  };
  const history = () => ({
    history_revision_id: "history-1",
    project_id: "project-1",
    parent_revision_ids: [],
    tree_digest: digestB,
    author_subject: "operator",
    message: "Validated checkout",
    validation_summary_digest: digestC,
    workspace_revision: 3,
    ordinal: 1,
    created_at: "2026-08-18T10:05:00Z",
    review_revision: state.reviewed ? 1 : 0,
    review: state.reviewed ? { review_id: "review-1", history_revision_id: "history-1", review_revision: 1, reviewer_subject: "admin-reviewer", decision: "APPROVED", reason: "Reviewed", created_at: "2026-08-18T10:06:00Z" } : null,
  });
  const bundle = () => ({
    bundle_digest: bundleDigest,
    project_id: "project-1",
    history_revision_id: "history-1",
    byte_length: 1024,
    manifest: { procedure_ids: ["checkout"] },
    source_tree_digest: digestA,
    validation_report_digest: digestC,
    author_subject: "operator",
    review_subject: "admin-reviewer",
    builder_identity: "local-builder",
    state: state.bundleState,
    state_revision: ["CANDIDATE", "APPROVED", "PROMOTED", "SUPERSEDED", "WITHDRAWN"].indexOf(state.bundleState) + 1,
    approved_by_subject: state.bundleState === "CANDIDATE" ? null : "admin-reviewer",
    approval_reason: state.bundleState === "CANDIDATE" ? null : "Approved",
    created_at: "2026-08-18T10:07:00Z",
    updated_at: "2026-08-18T10:07:00Z",
  });
  const workspace = () => ({
    project: project(state.closed, state.revision),
    workspace_revision: state.revision,
    resources: [sourceFolder(), resource(state.source)],
    problems: [{ diagnostic_id: "diagnostic-1", code: "SPELL900", severity: "WARNING", source_path: "src/checkout.spell.py", start_line: 6, start_column: 1, end_line: 6, end_column: 3, language_profile: "spell-restricted-ast/0.9", message: "Example exact-span warning", remediation_ref: "spell://diagnostics/SPELL900", tool_version: "spell-development-analysis/0.9" }],
    jobs: [],
    history: [history()],
    conflicts: [],
    bundles: state.bundlePresent ? [bundle()] : [],
    promotion_catalog_entries: [],
    pinned_catalog_entries: [
      { catalog_id: "sim-telemetry", catalog_revision: 4, content_digest: digestC, entry_id: "tm-mode", qualified_name: "TM.MODE", catalog_kind: "TM", data: { value_type: "STRING", description: "Simulator mode" } },
      { catalog_id: "mission-model", catalog_revision: 2, content_digest: digestA, entry_id: "mmd-mode", qualified_name: "MMD.MODE", catalog_kind: "MMD", data: { value_type: "UINT64", description: "Mission model mode" } },
    ],
    presence: [],
  });
  const catalogEntry = () => ({
    procedure_id: "checkout",
    registry_revision: state.registryRevision,
    current_bundle_digest: state.currentBundleDigest,
    previous_bundle_digest: state.previousBundleDigest,
    state: state.registryState,
    updated_by_subject: "admin-reviewer",
    created_at: "2026-08-18T10:08:00Z",
    updated_at: "2026-08-18T10:08:00Z",
  });

  await page.route("**/api/v1/development/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace("/api/v1/development", "");
    const method = request.method();
    const json = () => request.postDataJSON() as Record<string, unknown>;
    const fulfill = (body: unknown, status = 200, contentType = "application/json") => route.fulfill({ status, contentType, body: contentType === "application/json" ? JSON.stringify(body) : body as string });

    if (path === "/projects" && method === "GET") return fulfill({ items: [
      project(state.closed, state.revision),
      {
        ...project(false, 1),
        project_id: "project-2",
        workspace_id: "workspace-2",
        display_name: "Backup Checkout",
        manifest: { ...project(false, 1).manifest, project_id: "project-2", display_name: "Backup Checkout" },
      },
    ] });
    if (path === "/projects/project-1/workspace" && method === "GET") return fulfill({ workspace: workspace() });
    if (path === "/projects/project-1/status" && method === "GET") return fulfill({ status: {
      project_id: "project-1",
      workspace_revision: state.revision,
      base_history_revision_id: "history-other",
      clean: state.statusClean,
      change_count: state.statusClean ? 0 : 1,
      changes: state.statusClean ? [] : [{ resource_id: "resource-procedure", path: "src/checkout.spell.py", old_path: null, status: "MODIFIED", before_sha256: digestB, after_sha256: digestA }],
    } });
    if (path === "/projects/project-1/diff" && method === "GET") return fulfill({ diff: {
      history_revision_id: null,
      against_revision_id: "history-other",
      project_id: "project-1",
      workspace_revision: state.revision,
      changes: state.statusClean ? [] : [{ resource_id: "resource-procedure", path: "src/checkout.spell.py", old_path: null, before_path: "src/checkout.spell.py", after_path: "src/checkout.spell.py", status: "MODIFIED", content_changed: true, before_sha256: digestB, after_sha256: digestA, metadata_delta: { before: { kind: "PROCEDURE", media_type: "text/x-python" }, after: { kind: "PROCEDURE", media_type: "text/x-python" } }, dependency_impact: true, patch: "@@ -1 +1 @@\n-old\n+new\n" }],
      dependency_delta: { before: [], after: [] },
      validation_delta: { before_digest: digestB, after_digest: digestC, changed: true },
    } });
    if (path === "/projects/project-1/history/commit-selected" && method === "POST") {
      state.historyOperations.push({ path, body: json() });
      state.statusClean = true;
      state.revision += 1;
      return fulfill({ history_revision: history() });
    }
    if (path === "/projects/project-1/history/refresh-base" && method === "POST") {
      state.historyOperations.push({ path, body: json() });
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), base_history_revision: history() });
    }
    if (path === "/projects/project-1/properties" && method === "GET") return fulfill({ project: project(state.closed, state.revision), resource_counts: { PROCEDURE: 1 }, byte_length: resource(state.source).byte_length });
    if (path === "/projects/project-1/manifest" && method === "PUT") {
      state.updatedManifest = json().manifest as Record<string, unknown>;
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), resource: { ...resource(JSON.stringify(state.updatedManifest)), resource_id: "resource-manifest", path: "spell-project.yaml", kind: "PROJECT_METADATA", media_type: "application/json" }, replayed: false });
    }
    if (path === "/projects/project-1/resources/resource-procedure" && method === "GET") return fulfill({ resource: { ...resource(state.source), metadata: { procedure_id: "checkout", display_name: "Flight Checkout", description: "Local simulator checkout", language_profile: "spell-restricted-ast/0.9", arguments: {}, catalog_dependencies: [{ catalog_id: "sim-telemetry", catalog_revision: 4, content_digest: digestC }] }, language: { diagnostics: [], outline: [{ kind: "SPELL_CALL", name: "Log", line: 6, column: 1 }], completions: [{ label: "Log", kind: "SPELL_CALL", insert_text: "Log", sort_text: "log" }] } } });
    if (path === "/projects/project-1/resources/resource-procedure" && method === "PUT") {
      state.source = String(json().content ?? state.source);
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), resource: resource(state.source) });
    }
    if (path === "/projects/project-1/resources/resource-procedure/copy" && method === "POST") {
      expect(json().destination_path).toBe("src/checkout-copy.spell.py");
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), resource: { ...resource(state.source), resource_id: "resource-copy", path: "src/checkout-copy.spell.py" } });
    }
    if (path === "/projects/project-1/resources" && method === "POST") {
      const body = json();
      if (body.kind === "DICTIONARY") state.createdDictionary = body;
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), resource: { ...resource(String(body.content ?? "")), resource_id: "resource-new", path: body.path, kind: body.kind, media_type: body.media_type } });
    }
    if (path === "/projects/project-1/checks" && method === "POST") {
      const body = json();
      state.checkRequests.push(body);
      return fulfill({ job: {
        job_id: `check-${state.checkRequests.length}`,
        project_id: "project-1",
        workspace_revision: state.revision,
        scope: body.scope,
        scope_path: body.scope_path ?? null,
        state: "COMPLETED",
        progress: 100,
        report_sha256: semanticReportDigest,
        started_at: "2026-08-18T10:00:00Z",
        completed_at: "2026-08-18T10:00:01Z",
      } });
    }
    if (/^\/checks\/check-\d+\/report$/.test(path) && method === "GET") {
      state.reportAuthorization = request.headers().authorization ?? null;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Content-SHA256": semanticReportDigest },
        body: semanticReport,
      });
    }
    if ((path === "/projects/project-1/close" || path === "/projects/project-1/open") && method === "POST") {
      state.closed = path.endsWith("/close");
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), replayed: false });
    }
    if (path === "/projects/project-1/presence" && method === "PUT") return fulfill({ presence: {} });
    if (path === "/projects/project-1/imports" && method === "POST") {
      const headers = request.headers();
      state.importMediaType = headers["content-type"] ?? null;
      state.importAuthorization = headers.authorization ?? null;
      state.importDigest = headers["content-sha256"] ?? null;
      state.importFilename = headers["x-spell-filename-base64url"] ?? null;
      state.importWorkspaceRevision = headers["x-spell-workspace-revision"] ?? null;
      state.importIdempotencyKey = headers["idempotency-key"] ?? null;
      state.importBytes = request.postDataBuffer();
      if (state.importShouldConflict) return fulfill({
        detail: {
          code: "EXTERNAL_CHANGE_CONFLICT",
          message: "import conflicts with existing workspace resources",
          current: { operation_id: "import-operation-1", paths: ["src/checkout.spell.py"], workspace_revision: state.revision },
        },
      }, 409);
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision) });
    }
    if (path === "/projects/project-1/imports/import-operation-1" && method === "GET") return fulfill({ import_operation: {
      operation_id: "import-operation-1",
      project_id: "project-1",
      actor_subject: "operator",
      original_filename: "røund-trip.zip",
      original_media_type: "application/vnd.openbexi.spell.project+zip",
      original_byte_length: state.importBytes?.byteLength ?? 0,
      original_bytes_sha256: state.importDigest,
      original_bytes_available: true,
      imported_tree_sha256: digestB,
      canonical_tree_sha256: digestC,
      base_workspace_revision: state.revision,
      status: "CONFLICT",
      conflict_paths: ["src/checkout.spell.py"],
      audit_id: "audit-import-1",
      created_at: "2026-08-18T10:00:00Z",
    } });
    if (path === "/projects/project-1/imports/import-operation-1/apply" && method === "POST") {
      expect(json()).toMatchObject({ expected_workspace_revision: state.revision, idempotency_key: expect.any(String) });
      state.retainedImportApplied = true;
      state.revision += 1;
      return fulfill({ project: project(state.closed, state.revision), source_operation_id: "import-operation-1" });
    }
    if (path === "/projects/project-1/exports" && method === "POST") {
      expect(json()).toEqual({ expected_workspace_revision: state.revision });
      state.exportAuthorization = request.headers().authorization ?? null;
      return route.fulfill({
        status: 200,
        contentType: "application/vnd.openbexi.spell.project+zip",
        headers: { "Content-SHA256": exportDigest },
        body: exportArchive,
      });
    }
    if (path === "/projects/project-1/external-changes" && method === "POST") {
      const body = json();
      state.externalAttempts += 1;
      if (state.externalAttempts === 1) {
        expect(body).toMatchObject({ resolution: "KEEP_AS_NEW_CHANGE", changes: [{ base_content_sha256: digestA }] });
        return fulfill({ detail: { code: "CASE_CONFLICT", message: "incoming path collides under case policy", current: { path: "src/checkout.spell.py" } } }, 409);
      }
      expect(body).toMatchObject({ base_workspace_revision: 3, base_history_revision_id: "history-1", resolution: "THREE_WAY_MERGE", changes: [{ base_content_sha256: digestA, content_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) }] });
      return fulfill({ project: project(state.closed, state.revision), applied: 0, conflict_ids: ["conflict-1"] });
    }
    if (path === "/history/history-1/review" && method === "POST") {
      state.reviewed = true;
      return fulfill({ history_revision: history(), review: history().review });
    }
    if (path === "/history/history-1/bundles" && method === "POST") {
      state.bundlePresent = true;
      return fulfill({ bundle: bundle(), replayed: false });
    }
    if (path === `/bundles/${bundleDigest}/download` && method === "GET") {
      return route.fulfill({
        status: 200,
        contentType: "application/vnd.openbexi.spell.bundle+json",
        headers: { "Content-SHA256": bundleDigest },
        body: bundleArchive,
      });
    }
    if (path === `/bundles/${bundleDigest}/approve` && method === "POST") {
      state.bundleState = "APPROVED";
      return fulfill({ bundle: bundle(), replayed: false });
    }
    if (path === "/catalog/checkout" && method === "GET") {
      if (state.registryRevision === 0) return fulfill({ detail: { code: "NOT_FOUND", message: "registry absent", current: null } }, 404);
      return fulfill({ catalog_entry: catalogEntry(), decisions: [] });
    }
    if (path === "/catalog/checkout/decisions" && method === "POST") {
      const body = json();
      const operation = String(body.operation);
      expect(body).toMatchObject({ bundle_digest: bundleDigest, expected_registry_revision: state.registryRevision });
      state.promotionOperations.push(operation);
      const prior = state.currentBundleDigest;
      if (operation === "PROMOTE" || operation === "ROLLBACK_PROMOTE") {
        state.currentBundleDigest = bundleDigest;
        state.registryState = "PROMOTED";
        state.bundleState = "PROMOTED";
      } else if (operation === "SUPERSEDE") {
        state.previousBundleDigest = bundleDigest;
        state.currentBundleDigest = null;
        state.registryState = "SUPERSEDED";
        state.bundleState = "SUPERSEDED";
      } else if (operation === "WITHDRAW") {
        state.previousBundleDigest = bundleDigest;
        state.currentBundleDigest = null;
        state.registryState = "WITHDRAWN";
        state.bundleState = "WITHDRAWN";
      }
      state.registryRevision += 1;
      state.promoted = state.registryState === "PROMOTED";
      return fulfill({ catalog_entry: catalogEntry(), decision: { decision_id: `decision-${state.registryRevision}`, procedure_id: "checkout", registry_revision: state.registryRevision, operation, previous_bundle_digest: prior, new_bundle_digest: state.currentBundleDigest, actor_subject: "admin-reviewer", reason: String(body.reason), correlation_id: "correlation-1" }, replayed: false });
    }
    return fulfill({ detail: { code: "NOT_FOUND", message: `${method} ${path}`, current: null } }, 404);
  });
  return state;
}

async function storeToken(page: Page, token: string) {
  await page.addInitScript((credential) => window.sessionStorage.setItem("openbexi.spell.access-token", credential), token);
}

async function switchToken(page: Page, token: string, role: "operator" | "admin") {
  await page.evaluate((credential) => {
    window.sessionStorage.setItem("openbexi.spell.access-token", credential);
    window.dispatchEvent(new Event("spell-auth-changed"));
  }, token);
  await expect(page.locator(".dev-session small")).toHaveText(role);
}

async function openMobileArea(page: Page, label: "Explorer" | "Editor" | "Problems" | "Activity") {
  if ((page.viewportSize()?.width ?? 1000) > 820) return;
  const button = page.getByRole("navigation", { name: "Development areas" }).getByRole("button", { name: label });
  await expect(button).toBeVisible();
  await button.click();
}

async function assertNoPageOverflow(page: Page) {
  const geometry = await page.evaluate(() => ({
    viewportWidth: document.documentElement.clientWidth,
    viewportHeight: document.documentElement.clientHeight,
    documentWidth: document.documentElement.scrollWidth,
    documentHeight: document.documentElement.scrollHeight,
    bodyWidth: document.body.scrollWidth,
    bodyHeight: document.body.scrollHeight,
    scrollX: window.scrollX,
    scrollY: window.scrollY,
  }));
  expect(Math.max(geometry.documentWidth, geometry.bodyWidth)).toBeLessThanOrEqual(geometry.viewportWidth);
  expect(Math.max(geometry.documentHeight, geometry.bodyHeight)).toBeLessThanOrEqual(geometry.viewportHeight);
  expect({ scrollX: geometry.scrollX, scrollY: geometry.scrollY }).toEqual({ scrollX: 0, scrollY: 0 });
}

test("authenticates the signed JWT before opening the development shell", async ({ page }) => {
  await installApi(page);
  await page.goto("/development.html");
  await page.getByLabel("Signed JWT").fill(`  Bearer ${operatorToken}  `);
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByText("Development environment")).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Project" })).toHaveValue("project-1");
  await expect.poll(() => page.evaluate(() => window.sessionStorage.getItem("openbexi.spell.access-token"))).toBe(operatorToken);
});

test("supports rectangular editing and remains accessible and contained", async ({ page }, testInfo) => {
  if (testInfo.project.name === "chromium") await page.setViewportSize({ width: 1536, height: 768 });
  await storeToken(page, operatorToken);
  await installApi(page);
  await page.goto("/development.html");
  const editor = page.getByLabel("Procedure source editor");
  await expect(editor).toBeVisible();
  await editor.evaluate((element: HTMLTextAreaElement) => {
    const first = element.value.indexOf("Log('one')") + 3;
    const second = element.value.indexOf("Log('two')") + 3;
    element.focus();
    element.setSelectionRange(first, second);
  });
  await page.getByLabel("Rectangular edit text").fill("X");
  await page.keyboard.press("Alt+Shift+i");
  await expect(editor).toHaveValue(/LogX\('one'\)[\s\S]*LogX\('two'\)/);

  await page.getByLabel("Find in resource").fill("LogX");
  await page.getByLabel("Replace in resource").fill("Log");
  await page.getByLabel("Replace all matches").click();
  await page.getByLabel("Format source").click();
  await expect(editor).toHaveValue(/Log\('one'\)[\s\S]*Log\('two'\)\n$/);

  if (testInfo.project.name === "mobile") {
    const toolbar = page.getByRole("toolbar", { name: "Editor commands" });
    await expect.poll(() => toolbar.evaluate((element) => element.scrollWidth > element.clientWidth)).toBe(true);
    await toolbar.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
    await expect(page.getByRole("button", { name: "Save resource" })).toBeInViewport();
    await assertNoPageOverflow(page);
    const editorScreenshot = await page.screenshot({ path: testInfo.outputPath("development-mobile-editor.png") });
    expect(editorScreenshot.byteLength).toBeGreaterThan(10_000);
    const editorAccessibility = await new AxeBuilder({ page }).analyze();
    expect(editorAccessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
  }

  const exactMarker = page.locator(".syntax-diagnostic");
  await expect(exactMarker).toHaveCount(1);
  await expect(exactMarker).toHaveText("Log");
  await expect(exactMarker).toHaveAttribute("title", /SPELL900 6:1-6:3/);
  await openMobileArea(page, "Problems");
  await expect(page.getByRole("button", { name: /Open SPELL900 at exact source span/ })).toBeVisible();
  await assertNoPageOverflow(page);
  const screenshot = await page.screenshot({ path: testInfo.outputPath(`development-${testInfo.project.name}.png`) });
  expect(screenshot.byteLength).toBeGreaterThan(10_000);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
});

test("filters every pinned catalog family and inserts a text reference only", async ({ page }) => {
  await storeToken(page, operatorToken);
  await installApi(page);
  await page.goto("/development.html");

  await page.getByRole("tab", { name: "Catalog" }).click();
  await page.getByLabel("Catalog kind").selectOption("MMD");
  await page.getByLabel("Catalog filter field").selectOption("VALUE_TYPE");
  await page.getByLabel("Filter catalog").fill("uint64");
  await expect(page.getByText("MMD.MODE")).toBeVisible();
  await expect(page.getByText("TM.MODE")).toBeHidden();
  await page.getByRole("button", { name: "Insert MMD.MODE" }).click();
  await expect(page.getByLabel("Procedure source editor")).toHaveValue(/"MMD\.MODE"/);
});

test("preserves unsaved drafts and sends exact file and folder check paths", async ({ page }) => {
  await storeToken(page, operatorToken);
  const state = await installApi(page);
  await page.goto("/development.html");

  const editor = page.getByLabel("Procedure source editor");
  const draft = `${source}# unsaved draft\n`;
  await editor.fill(draft);

  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("Discard unsaved changes and switch projects");
    await dialog.dismiss();
  });
  await page.getByRole("combobox", { name: "Project" }).selectOption("project-2");
  await expect(page.getByRole("combobox", { name: "Project" })).toHaveValue("project-1");
  await expect(editor).toHaveValue(draft);

  await openMobileArea(page, "Explorer");
  await page.getByLabel("New folder").click();
  await page.getByLabel("Project-relative path").fill("src/generated");
  await page.getByRole("dialog").getByRole("button", { name: "Apply", exact: true }).click();
  await expect.poll(() => state.revision).toBe(4);
  await openMobileArea(page, "Editor");
  await expect(editor).toHaveValue(draft);

  await openMobileArea(page, "Explorer");
  const sourceRoot = page.getByRole("treeitem").filter({ has: page.locator('span:text-is("src")') });
  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("Discard unsaved changes");
    await dialog.dismiss();
  });
  await sourceRoot.click();
  await openMobileArea(page, "Editor");
  await expect(editor).toHaveValue(draft);

  await openMobileArea(page, "Explorer");
  page.once("dialog", (dialog) => dialog.accept());
  await sourceRoot.click();
  await openMobileArea(page, "Problems");
  const checkOnSave = page.getByRole("checkbox", { name: "Check on save" });
  await expect(checkOnSave).toBeVisible();
  await checkOnSave.uncheck();
  await expect(checkOnSave).not.toBeChecked();
  await assertNoPageOverflow(page);
  const problemsAccessibility = await new AxeBuilder({ page }).include(".dev-problems").analyze();
  expect(problemsAccessibility.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
  await page.getByLabel("Check scope").selectOption("FOLDER");
  const run = page.getByRole("button", { name: "Run semantic check" });
  await expect(run).toBeEnabled();
  await run.click();
  await expect.poll(() => state.checkRequests[0]).toMatchObject({ scope: "FOLDER", scope_path: "src" });
  await page.getByLabel("Check scope").selectOption("FILE");
  await expect(run).toBeDisabled();

  await openMobileArea(page, "Explorer");
  await page.getByRole("treeitem").filter({ hasText: "checkout.spell.py" }).click();
  await openMobileArea(page, "Problems");
  await page.getByLabel("Check scope").selectOption("FILE");
  await expect(run).toBeEnabled();
  await run.click();
  await expect.poll(() => state.checkRequests[1]).toMatchObject({ scope: "FILE", scope_path: "src/checkout.spell.py" });
  const reportDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download semantic report" }).click();
  const reportDownload = await reportDownloadPromise;
  expect(reportDownload.suggestedFilename()).toBe("check-2.semantic-report.json");
  const reportStream = await reportDownload.createReadStream();
  const reportChunks: Buffer[] = [];
  for await (const chunk of reportStream) reportChunks.push(Buffer.from(chunk));
  expect(Buffer.concat(reportChunks)).toEqual(semanticReport);
  expect(createHash("sha256").update(Buffer.concat(reportChunks)).digest("hex")).toBe(semanticReportDigest);
  expect(state.reportAuthorization).toBe(`Bearer ${operatorToken}`);
});

test("uses authoritative workspace status for selected commits, diffs, and base refresh", async ({ page }) => {
  await storeToken(page, operatorToken);
  const state = await installApi(page);
  await page.goto("/development.html");
  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "History", exact: true }).click();

  const changedResource = page.getByLabel("Workspace change status").getByText("src/checkout.spell.py");
  await expect(changedResource).toBeVisible();
  await page.getByRole("button", { name: "Compare workspace with base" }).click();
  await expect(page.getByLabel("Revision diff").getByText("Workspace to base")).toBeVisible();
  await page.getByRole("button", { name: "Close diff" }).click();

  await page.getByLabel("Workspace change status").getByRole("checkbox").check();
  await page.getByLabel("Commit message").fill("Commit checkout only");
  await page.getByRole("button", { name: "Commit selected changes" }).click();
  await expect.poll(() => state.historyOperations[0]).toMatchObject({
    path: "/projects/project-1/history/commit-selected",
    body: { message: "Commit checkout only", selected_resource_ids: ["resource-procedure"] },
  });
  await expect(page.getByText("Workspace matches its immutable base")).toBeVisible();

  const refresh = page.getByRole("button", { name: "Refresh base to revision history-1" });
  await expect(refresh).toBeEnabled();
  await refresh.click();
  await expect.poll(() => state.historyOperations[1]).toMatchObject({
    path: "/projects/project-1/history/refresh-base",
    body: { history_revision_id: "history-1" },
  });
});

test("recovers and applies a retained raw import operation", async ({ page }) => {
  await storeToken(page, operatorToken);
  const state = await installApi(page);
  state.importShouldConflict = true;
  await page.goto("/development.html");
  await openMobileArea(page, "Explorer");

  const importResponsePromise = page.waitForResponse((response) => response.url().endsWith("/api/v1/development/projects/project-1/imports"));
  await page.getByLabel("Project archive file").setInputFiles({
    name: "røund-trip.zip",
    mimeType: "application/vnd.openbexi.spell.project+zip",
    buffer: Buffer.from("retained-archive"),
  });
  expect((await importResponsePromise).status()).toBe(409);

  await expect(page.getByRole("heading", { name: "Retained project import" })).toBeVisible();
  await expect(page.getByText("røund-trip.zip", { exact: true })).toBeVisible();
  await expect(page.getByRole("list", { name: "Import conflict paths" })).toContainText("src/checkout.spell.py");
  expect(state.importBytes).toEqual(Buffer.from("retained-archive"));
  expect(Buffer.from(state.importFilename ?? "", "base64url").toString("utf8")).toBe("røund-trip.zip");
  expect(await page.evaluate(() => window.sessionStorage.getItem("openbexi.spell.import-operation:project-1"))).toBe("import-operation-1");

  await page.getByRole("button", { name: "Apply retained import" }).click();
  await expect.poll(() => state.retainedImportApplied).toBe(true);
  await expect(page.getByRole("heading", { name: "Retained project import" })).toHaveCount(0);
  expect(await page.evaluate(() => window.sessionStorage.getItem("openbexi.spell.import-operation:project-1"))).toBeNull();
});

test("operates lifecycle, strict exchange, external changes, and distinct-subject release duties", async ({ page }) => {
  test.setTimeout(75_000);
  await storeToken(page, operatorToken);
  const state = await installApi(page);
  await page.goto("/development.html");
  await openMobileArea(page, "Explorer");

  await page.getByLabel("Project properties").click();
  await expect(page.getByRole("dialog", { name: "Properties" })).toContainText("CASE_INSENSITIVE");
  await page.getByLabel("Close properties").click();

  await page.getByLabel("Project manifest").click();
  const manifestDialog = page.getByRole("dialog", { name: "Project manifest" });
  await expect(manifestDialog.getByRole("combobox", { name: "source root 1", exact: true })).toHaveValue("src");
  await manifestDialog.getByRole("button", { name: "Add policy label" }).click();
  await manifestDialog.getByRole("textbox", { name: "policy label 2", exact: true }).fill("FLIGHT_SIMULATOR");
  await manifestDialog.getByRole("button", { name: "Save manifest" }).click();
  await expect.poll(() => state.updatedManifest?.policy_labels).toEqual(["LOCAL_SYNTHETIC_NON_CUI_ONLY", "FLIGHT_SIMULATOR"]);

  await page.getByLabel("Copy resource").click();
  await page.getByLabel("Project-relative path").fill("src/checkout-copy.spell.py");
  await page.getByRole("dialog").getByRole("button", { name: "Apply", exact: true }).click();
  await expect.poll(() => state.revision).toBe(5);

  await page.getByLabel("New dictionary").click();
  await page.getByLabel("Dictionary exchange format").selectOption("IMP");
  await expect(page.getByLabel("Project-relative path")).toHaveValue("src/dictionary.imp");
  await page.getByRole("dialog").getByRole("button", { name: "Apply", exact: true }).click();
  await expect.poll(() => state.createdDictionary?.media_type).toBe("application/vnd.openbexi.spell.dictionary-imp+json");
  expect(JSON.parse(String(state.createdDictionary?.content))).toMatchObject({ schema_version: "spell.dictionary.imp/1", format: "IMP", dictionary_id: "dictionary" });

  await expect(page.getByRole("button", { name: "Import project archive" })).toBeEnabled();
  await page.getByLabel("Project archive file").setInputFiles({ name: "røund-trip.zip", mimeType: "application/zip", buffer: Buffer.from("archive") });
  await expect.poll(() => state.importMediaType).toBe("application/vnd.openbexi.spell.project+zip");
  expect(state.importAuthorization).toBe(`Bearer ${operatorToken}`);
  expect(state.importDigest).toBe(createHash("sha256").update("archive").digest("hex"));
  expect(Buffer.from(state.importFilename ?? "", "base64url").toString("utf8")).toBe("røund-trip.zip");
  expect(state.importWorkspaceRevision).toBe("6");
  expect(state.importIdempotencyKey).toMatch(/^[0-9a-f-]+$/);
  expect(state.importBytes).toEqual(Buffer.from("archive"));
  const downloadPromise = page.waitForEvent("download");
  await page.getByLabel("Export project archive").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("project-1.spell-project.zip");
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  expect(Buffer.concat(chunks)).toEqual(exportArchive);
  expect(state.exportAuthorization).toBe(`Bearer ${operatorToken}`);
  await page.getByLabel("Close project").click();
  await expect(page.getByLabel("Open project")).toBeVisible();
  await page.getByLabel("Open project").click();
  await expect(page.getByLabel("Close project")).toBeVisible();

  await openMobileArea(page, "Activity");
  await page.getByLabel("Changes").click();
  await page.getByLabel("Path").fill("SRC/CHECKOUT.SPELL.PY");
  await page.getByLabel("Incoming content").fill("Log('external')\n");
  await page.getByRole("button", { name: "Keep as new change" }).click();
  await expect(page.getByText(/CASE_CONFLICT/).first()).toBeVisible();
  await page.getByLabel("Path").fill("src/checkout.spell.py");
  await page.getByLabel("Base SHA-256").fill(digestA);
  await page.getByRole("button", { name: /Three-way merge/ }).click();
  await expect(page.getByText("Three-way merge conflicts recorded.")).toBeVisible();

  await switchToken(page, adminToken, "admin");
  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "History", exact: true }).click();
  await expect(page.getByRole("button", { name: /Build bundle/ })).toBeDisabled();
  await page.getByRole("button", { name: /Approve revision/ }).click();
  await expect.poll(() => state.reviewed).toBe(true);

  await switchToken(page, operatorToken, "operator");
  await openMobileArea(page, "Activity");
  await page.getByRole("tab", { name: "History", exact: true }).click();
  await expect(page.getByRole("button", { name: /Approve revision/ })).toBeDisabled();
  await page.getByRole("button", { name: /Build bundle/ }).click();
  await expect.poll(() => state.bundlePresent).toBe(true);
  await page.getByLabel("Bundles and promotion").click();
  const bundleDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /Download bundle/ }).click();
  const bundleDownload = await bundleDownloadPromise;
  expect(bundleDownload.suggestedFilename()).toBe(`${bundleDigest}.spell-bundle`);
  const bundleStream = await bundleDownload.createReadStream();
  const bundleChunks: Buffer[] = [];
  for await (const chunk of bundleStream) bundleChunks.push(Buffer.from(chunk));
  expect(Buffer.concat(bundleChunks)).toEqual(bundleArchive);

  await switchToken(page, adminToken, "admin");
  await openMobileArea(page, "Activity");
  await page.getByLabel("Bundles and promotion").click();
  await page.getByRole("button", { name: /Approve bundle/ }).click();
  await expect.poll(() => state.bundleState).toBe("APPROVED");
  await page.getByRole("button", { name: /Promote bundle/ }).click();
  await expect.poll(() => state.promoted).toBe(true);
  expect(state.promotionOperations).toEqual(["PROMOTE"]);
  await expect(page.locator(".dev-runtime-admission span")).toHaveText(`${bundleDigest.slice(0, 10)}...${bundleDigest.slice(-6)}`);
  await expect(page.getByRole("button", { name: /Promote bundle/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Rollback promote bundle/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: /Supersede bundle/ })).toBeEnabled();
  await page.getByRole("button", { name: /Supersede bundle/ }).click();
  await expect.poll(() => state.bundleState).toBe("SUPERSEDED");
  expect(state.promotionOperations).toEqual(["PROMOTE", "SUPERSEDE"]);
  await expect(page.locator(".dev-runtime-admission span")).toHaveText("No v0.9 bundle promoted");
  await expect(page.getByRole("button", { name: /Rollback promote bundle/ })).toBeEnabled();
  await page.getByRole("button", { name: /Rollback promote bundle/ }).click();
  await expect.poll(() => state.bundleState).toBe("PROMOTED");
  expect(state.promotionOperations).toEqual(["PROMOTE", "SUPERSEDE", "ROLLBACK_PROMOTE"]);
  await expect(page.getByRole("button", { name: /Supersede bundle/ })).toBeEnabled();
  await assertNoPageOverflow(page);
});
