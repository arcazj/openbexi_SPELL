import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, normalizeAccessToken, scheduleAt, setAccessToken } from "../api";
import { AccessTokenGate } from "../components/AccessTokenGate";
import { DevelopmentApp } from "./DevelopmentApp";
import {
  authenticateDevelopmentAccessToken,
  applyImportOperation,
  bundleCatalogAllowsDecision,
  bundleProcedureId,
  commitSelectedHistory,
  diffWorkspaceToBase,
  downloadBundle,
  downloadSemanticReport,
  discardImportOperation,
  exportProject,
  getPromotionRegistry,
  getImportOperation,
  getWorkspaceStatus,
  importProject,
  importOperationIdFromError,
  readResource,
  recordExternalChanges,
  refreshHistoryBase,
  updateResource,
  updateProjectManifest,
} from "./api";
import { applyRectangularEdit, CodeEditor, formatProcedureSource } from "./CodeEditor";
import { displayedSemanticJob } from "./DevelopmentWorkspace";
import { externalResourceAtPath } from "./ActivityPanel";
import { ProblemsPanel } from "./ProblemsPanel";
import { CatalogBrowser, catalogReferenceSnippet, createEmptyDictionary } from "./StructuredEditors";
import type { PinnedCatalogItem, ProcedureBundle, PromotionRegistry, ResourceDocument, SemanticJob } from "./types";

const token = "e30.eyJzdWIiOiJvcGVyYXRvciIsInJvbGUiOiJvcGVyYXRvciJ9.signature";

const document: ResourceDocument = {
  resource_id: "resource-1",
  project_id: "project-1",
  path: "src/demo.spell.py",
  kind: "PROCEDURE",
  media_type: "text/x-python",
  content: "Log('one')\nLog('two')\n",
  content_sha256: "a".repeat(64),
  byte_length: 24,
  revision: 2,
  metadata: {
    procedure_id: "demo",
    display_name: "Demo",
    description: "Test",
    language_profile: "spell-restricted-ast/0.9",
    arguments: {},
    catalog_dependencies: [],
  },
  language: { diagnostics: [], outline: [], completions: [{ label: "Log", kind: "SPELL_CALL", insert_text: "Log", sort_text: "log" }] },
};

beforeEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("v0.9 development authentication and timing", () => {
  it("accepts a trimmed optional Bearer prefix and rejects malformed credentials", () => {
    expect(normalizeAccessToken(`  Bearer   ${token}  `)).toBe(token);
    expect(() => normalizeAccessToken("not-signed")).toThrow("three segments");
  });

  it("does not persist a backend-rejected credential", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: { code: "AUTH", message: "rejected" } }), { status: 401, headers: { "Content-Type": "application/json" } })));
    await expect(authenticateDevelopmentAccessToken(token)).rejects.toThrow("AUTH: rejected");
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
  });

  it("chunks deadlines beyond the browser timer maximum", () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const callback = vi.fn();
    const clear = scheduleAt(3_000_000_000, callback);
    expect(vi.getTimerCount()).toBe(1);
    act(() => { vi.advanceTimersByTime(2_147_000_000); });
    expect(callback).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(1);
    clear();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps the gate visible for a 401 and clears stale feedback while editing", async () => {
    const authenticate = vi.fn(async () => { throw new Error("AUTH: rejected"); });
    render(<AccessTokenGate authenticate={authenticate} />);
    fireEvent.change(screen.getByLabelText("Signed JWT"), { target: { value: token } });
    fireEvent.submit(screen.getByLabelText("Signed JWT").closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("AUTH: rejected");
    expect(screen.getByRole("heading", { name: "Session access" })).toBeVisible();
    fireEvent.change(screen.getByLabelText("Signed JWT"), { target: { value: `${token}x` } });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("re-arms development expiry when a token is replaced", () => {
    vi.useFakeTimers();
    const now = new Date("2026-08-18T12:00:00Z");
    vi.setSystemTime(now);
    const expiringToken = (offsetMs: number) => {
      const payload = btoa(JSON.stringify({ sub: "operator", role: "operator", exp: (now.getTime() + offsetMs) / 1000 }))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      return `header.${payload}.signature`;
    };
    const oldToken = expiringToken(5_000);
    const laterToken = expiringToken(10_000);
    const earlierToken = expiringToken(7_000);
    window.sessionStorage.setItem("openbexi.spell.access-token", oldToken);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ items: [] }), {
      headers: { "Content-Type": "application/json" },
    })));
    render(<DevelopmentApp />);

    act(() => setAccessToken(laterToken));
    act(() => vi.advanceTimersByTime(5_000));
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBe(laterToken);

    act(() => setAccessToken(earlierToken));
    act(() => vi.advanceTimersByTime(1_999));
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBe(earlierToken);
    act(() => vi.advanceTimersByTime(1));
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
  });
});

describe("v0.9 semantic job presentation", () => {
  const job = (
    jobId: string,
    workspaceRevision: number,
    state: SemanticJob["state"],
    completedAt = state === "COMPLETED" ? "2026-08-18T00:00:01Z" : null,
  ): SemanticJob => ({
    job_id: jobId,
    project_id: "project-1",
    workspace_revision: workspaceRevision,
    scope: "PROJECT",
    state,
    progress: state === "COMPLETED" ? 100 : 25,
    started_at: "2026-08-18T00:00:00Z",
    completed_at: completedAt,
    report_sha256: state === "COMPLETED" ? "a".repeat(64) : null,
  });

  it("keeps the latest current-revision report available after the job completes", () => {
    expect(displayedSemanticJob([
      job("older-current-completed", 7, "COMPLETED", "2026-08-18T00:00:01Z"),
      job("stale-completed", 6, "COMPLETED"),
      job("newer-current-completed", 7, "COMPLETED", "2026-08-18T00:00:02Z"),
    ], 7)?.job_id).toBe("newer-current-completed");
    expect(displayedSemanticJob([job("stale-completed", 6, "COMPLETED")], 7)).toBeNull();
  });

  it("prioritizes an active job over a completed current-revision report", () => {
    expect(displayedSemanticJob([
      job("current-completed", 7, "COMPLETED"),
      job("active", 6, "RUNNING"),
    ], 7)?.job_id).toBe("active");
  });
});

describe("v0.9 editor operations", () => {
  it("applies a bounded rectangular edit across selected lines", () => {
    const source = "alpha\nbravo\ncharlie";
    expect(applyRectangularEdit(source, 2, 5 + 1 + 2, "X")).toBe("alXpha\nbrXavo\ncharlie");
  });

  it("formats deterministically without changing language semantics", () => {
    expect(formatProcedureSource("\tLog('one')  \r\n\r\n")).toBe("\tLog('one')  \n\n");
    expect(formatProcedureSource(formatProcedureSource("Log('one')"))).toBe("Log('one')\n");
    const multiline = "message: str = \"\"\"line with spaces  \r\n\tsecond line\"\"\"\r\nLog(message)";
    expect(formatProcedureSource(multiline)).toBe("message: str = \"\"\"line with spaces  \n\tsecond line\"\"\"\nLog(message)\n");
  });

  it("supports keyboard rectangular edit, find/replace, formatting, and custom snippets", () => {
    let content = document.content;
    const view = render(<CodeEditor
      document={document}
      content={content}
      dirty
      canEdit
      saving={false}
      catalogEntries={[]}
      diagnostics={[]}
      onChange={(value) => { content = value; view.rerender(<CodeEditor document={document} content={content} dirty canEdit saving={false} catalogEntries={[]} diagnostics={[]} onChange={(next) => { content = next; }} onSave={vi.fn()} />); }}
      onSave={vi.fn()}
    />);
    const editor = screen.getByLabelText("Procedure source editor") as HTMLTextAreaElement;
    editor.setSelectionRange(4, 15);
    fireEvent.change(screen.getByLabelText("Rectangular edit text"), { target: { value: "X" } });
    fireEvent.keyDown(editor, { key: "i", altKey: true, shiftKey: true });
    expect(content).toContain("Log(X'one')");

    fireEvent.change(screen.getByLabelText("Find in resource"), { target: { value: "Log" } });
    fireEvent.change(screen.getByLabelText("Replace in resource"), { target: { value: "Prompt" } });
    fireEvent.click(screen.getByLabelText("Replace all matches"));
    expect(content).toContain("Prompt");
    fireEvent.click(screen.getByLabelText("Format source"));
    expect(content.endsWith("\n")).toBe(true);
  });

  it("only enables file and folder checks for matching resource selections", () => {
    const onRun = vi.fn();
    const props = {
      problems: [],
      activeJob: null,
      selectedResource: document,
      canMutate: true,
      busy: false,
      checkOnSave: false,
      onCheckOnSaveChange: vi.fn(),
      onRun,
      onCancel: vi.fn(),
      onClean: vi.fn(),
      onDownloadReport: vi.fn(),
      onSelect: vi.fn(),
    };
    const view = render(<ProblemsPanel {...props} />);
    const scope = screen.getByLabelText("Check scope");
    const run = screen.getByRole("button", { name: "Run semantic check" });
    expect(screen.getByRole("button", { name: "Download semantic report" })).toBeDisabled();

    fireEvent.change(scope, { target: { value: "FOLDER" } });
    expect(run).toBeDisabled();

    const folder = { kind: "FOLDER" as const };
    view.rerender(<ProblemsPanel {...props} selectedResource={folder} />);
    expect(run).toBeEnabled();
    fireEvent.click(run);
    expect(onRun).toHaveBeenCalledWith("FOLDER", false);

    fireEvent.change(scope, { target: { value: "FILE" } });
    expect(run).toBeDisabled();

    view.rerender(<ProblemsPanel {...props} activeJob={{
      job_id: "check-1",
      project_id: "project-1",
      workspace_revision: 7,
      scope: "PROJECT",
      state: "COMPLETED",
      progress: 100,
      report_sha256: "a".repeat(64),
      started_at: "2026-08-18T10:00:00Z",
      completed_at: "2026-08-18T10:00:01Z",
    }} />);
    fireEvent.click(screen.getByRole("button", { name: "Download semantic report" }));
    expect(props.onDownloadReport).toHaveBeenCalledOnce();
  });

  it("does not expose an empty diagnostics container as an invalid ARIA list", () => {
    const view = render(<ProblemsPanel
      problems={[]}
      activeJob={null}
      selectedResource={document}
      canMutate
      busy={false}
      checkOnSave={false}
      onCheckOnSaveChange={vi.fn()}
      onRun={vi.fn()}
      onCancel={vi.fn()}
      onClean={vi.fn()}
      onDownloadReport={vi.fn()}
      onSelect={vi.fn()}
    />);

    expect(view.container.querySelector(".dev-problem-table")).not.toHaveAttribute("role");
    expect(screen.getByRole("status")).toHaveTextContent("No durable problems for this workspace revision");
  });

  it("disables revision-bound problem actions while a workspace mutation reloads", () => {
    const completedJob: SemanticJob = {
      job_id: "check-1",
      project_id: "project-1",
      workspace_revision: 7,
      scope: "PROJECT",
      state: "COMPLETED",
      progress: 100,
      report_sha256: "a".repeat(64),
      started_at: "2026-08-18T10:00:00Z",
      completed_at: "2026-08-18T10:00:01Z",
    };
    const view = render(<ProblemsPanel
      problems={[{
        diagnostic_id: "diagnostic-1",
        code: "SPELL_TEST",
        severity: "WARNING",
        source_path: document.path,
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 4,
        language_profile: "spell-restricted-ast/0.9",
        message: "Test diagnostic",
        remediation_ref: "spell:test",
        tool_version: "0.9.0",
      }]}
      activeJob={completedJob}
      selectedResource={document}
      canMutate
      busy
      checkOnSave={false}
      onCheckOnSaveChange={vi.fn()}
      onRun={vi.fn()}
      onCancel={vi.fn()}
      onClean={vi.fn()}
      onDownloadReport={vi.fn()}
      onSelect={vi.fn()}
    />);

    expect(screen.getByLabelText("Check scope")).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Reparse libraries" })).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Check on save" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run semantic check" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Clean problem results" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download semantic report" })).toBeDisabled();

    view.rerender(<ProblemsPanel
      problems={[]}
      activeJob={{ ...completedJob, state: "RUNNING", progress: 50, report_sha256: null, completed_at: null }}
      selectedResource={document}
      canMutate
      busy
      checkOnSave={false}
      onCheckOnSaveChange={vi.fn()}
      onRun={vi.fn()}
      onCancel={vi.fn()}
      onClean={vi.fn()}
      onDownloadReport={vi.fn()}
      onSelect={vi.fn()}
    />);
    expect(screen.getByRole("button", { name: "Cancel semantic check" })).toBeDisabled();
  });

  it("filters all pinned catalog kinds by typed fields and inserts text only", () => {
    const kinds: PinnedCatalogItem["catalog_kind"][] = ["TM", "TC", "RESOURCE", "SCDB", "GDB", "PROC", "MMD"];
    const entries = kinds.map((catalogKind, index): PinnedCatalogItem => ({
      catalog_id: `catalog-${catalogKind.toLowerCase()}`,
      catalog_revision: index + 1,
      content_digest: String(index).padStart(64, "a").slice(-64),
      entry_id: `entry-${catalogKind.toLowerCase()}`,
      qualified_name: `${catalogKind}.MODE`,
      catalog_kind: catalogKind,
      data: { value_type: catalogKind === "MMD" ? "UINT64" : "STRING", description: `${catalogKind} description` },
    }));
    const onInsert = vi.fn();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<CatalogBrowser entries={entries} canInsert onInsert={onInsert} />);

    const kind = screen.getByLabelText("Catalog kind");
    expect([...kind.querySelectorAll("option")].map((option) => option.value)).toEqual(["ALL", ...kinds]);
    fireEvent.change(kind, { target: { value: "MMD" } });
    fireEvent.change(screen.getByLabelText("Catalog filter field"), { target: { value: "VALUE_TYPE" } });
    fireEvent.change(screen.getByLabelText("Filter catalog"), { target: { value: "uint64" } });
    expect(screen.getByText("MMD.MODE")).toBeVisible();
    expect(screen.queryByText("TM.MODE")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Insert MMD.MODE" }));
    expect(onInsert).toHaveBeenCalledWith('"MMD.MODE"');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(catalogReferenceSnippet({ qualified_name: 'PROC."quoted"' })).toBe('"PROC.\\"quoted\\""');
  });

  it("bounds pinned catalog results to 500 entries", () => {
    const entries = Array.from({ length: 505 }, (_, index): PinnedCatalogItem => ({
      catalog_id: "large-catalog",
      catalog_revision: 1,
      content_digest: "d".repeat(64),
      entry_id: `entry-${index}`,
      qualified_name: `TM.ITEM_${String(index).padStart(3, "0")}`,
      catalog_kind: "TM",
      data: { value_type: "STRING", description: "bounded" },
    }));
    render(<CatalogBrowser entries={entries} canInsert={false} onInsert={vi.fn()} />);
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(501);
    expect(screen.getByText("500 / 505")).toBeVisible();
  });
});

describe("v0.9 strict exchange and API contracts", () => {
  it("replays the exact idempotent mutation after a retryable transaction conflict", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const calls: RequestInit[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(init ?? {});
      if (calls.length === 1) {
        return new Response(JSON.stringify({
          detail: {
            code: "RETRYABLE_TRANSACTION_CONFLICT",
            message: "transaction could not be completed; retry with the same idempotency key",
          },
        }), { status: 409, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ project: { workspace_revision: 8 } }), {
        headers: { "Content-Type": "application/json" },
      });
    }));

    await expect(updateResource({
      project_id: "project-1",
      resource_id: "resource-1",
      expected_workspace_revision: 7,
      content: "Log('retry')\n",
      media_type: "text/x-python",
    })).resolves.toMatchObject({ workspace_revision: 8 });

    expect(calls).toHaveLength(2);
    expect(calls[0]?.body).toBe(calls[1]?.body);
    const replayedBody = JSON.parse(String(calls[0]?.body)) as Record<string, unknown>;
    expect(replayedBody).toMatchObject({
      expected_workspace_revision: 7,
      idempotency_key: expect.any(String),
    });
  });

  it("does not replay an ordinary workspace conflict", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      detail: { code: "WORKSPACE_REVISION_CONFLICT", message: "workspace revision differs" },
    }), { status: 409, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(updateResource({
      project_id: "project-1",
      resource_id: "resource-1",
      expected_workspace_revision: 7,
      content: "Log('stale')\n",
    })).rejects.toMatchObject({ status: 409 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("uses the dedicated status, diff, selected-commit, and refresh-base contracts", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const calls: Array<{ path: string; method: string; body: Record<string, unknown> | null }> = [];
    const history = {
      history_revision_id: "history-1",
      project_id: "project-1",
      parent_revision_ids: [],
      tree_digest: "a".repeat(64),
      author_subject: "operator",
      message: "Selected",
      validation_summary_digest: "b".repeat(64),
      workspace_revision: 7,
      ordinal: 1,
      created_at: "2026-08-18T10:00:00Z",
    };
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      calls.push({ path, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : null });
      if (path.endsWith("/status")) return new Response(JSON.stringify({ status: { project_id: "project-1", workspace_revision: 7, base_history_revision_id: "history-1", clean: false, change_count: 1, changes: [{ resource_id: "resource-1", path: "src/demo.spell.py", old_path: null, status: "MODIFIED", before_sha256: "a".repeat(64), after_sha256: "b".repeat(64) }] } }), { headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/diff")) return new Response(JSON.stringify({ diff: { history_revision_id: null, against_revision_id: "history-1", project_id: "project-1", workspace_revision: 7, changes: [], dependency_delta: { before: [], after: [] }, validation_delta: { before_digest: null, after_digest: null, changed: false } } }), { headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/commit-selected")) return new Response(JSON.stringify({ history_revision: history }), { headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ project: { workspace_revision: 8 }, base_history_revision: history }), { headers: { "Content-Type": "application/json" } });
    }));

    await expect(getWorkspaceStatus("project-1")).resolves.toMatchObject({ change_count: 1, changes: [{ resource_id: "resource-1" }] });
    await expect(diffWorkspaceToBase("project-1")).resolves.toMatchObject({ against_revision_id: "history-1", changes: [] });
    await commitSelectedHistory({ project_id: "project-1", expected_workspace_revision: 7, message: "Selected", selected_resource_ids: ["resource-1"] });
    await refreshHistoryBase({ project_id: "project-1", history_revision_id: "history-1", expected_workspace_revision: 7 });

    expect(calls.map((call) => [call.method, call.path])).toEqual([
      ["GET", "/api/v1/development/projects/project-1/status"],
      ["GET", "/api/v1/development/projects/project-1/diff"],
      ["POST", "/api/v1/development/projects/project-1/history/commit-selected"],
      ["POST", "/api/v1/development/projects/project-1/history/refresh-base"],
    ]);
    expect(calls[2]?.body).toMatchObject({ message: "Selected", selected_resource_ids: ["resource-1"], expected_workspace_revision: 7, idempotency_key: expect.any(String) });
    expect(calls[3]?.body).toMatchObject({ history_revision_id: "history-1", expected_workspace_revision: 7, idempotency_key: expect.any(String) });
  });

  it("binds catalog decisions to each bundle's exact procedure and registry state", () => {
    const bundle: ProcedureBundle = {
      bundle_digest: "b".repeat(64),
      project_id: "project-1",
      history_revision_id: "history-1",
      source_tree_digest: "a".repeat(64),
      validation_report_digest: "c".repeat(64),
      author_subject: "operator",
      review_subject: "admin",
      builder_identity: "builder",
      byte_length: 10,
      manifest: { procedure_ids: ["local/demo"] },
      created_at: "2026-08-18T10:00:00Z",
      updated_at: "2026-08-18T10:00:00Z",
      state: "APPROVED",
      state_revision: 2,
      approved_by_subject: "admin",
      approval_reason: "approved",
    };
    const registry = (state: string, current: string | null): PromotionRegistry => ({
      catalog_entry: {
        procedure_id: "local/demo",
        registry_revision: 2,
        current_bundle_digest: current,
        previous_bundle_digest: null,
        state,
        updated_by_subject: "admin",
        created_at: "2026-08-18T10:00:00Z",
        updated_at: "2026-08-18T10:00:00Z",
      },
      decisions: [],
    });

    expect(bundleProcedureId(bundle)).toBe("local/demo");
    expect(bundleProcedureId({ ...bundle, manifest: { procedure_ids: [] } })).toBeNull();
    expect(bundleProcedureId({ ...bundle, manifest: { procedure_ids: ["one", "two"] } })).toBeNull();
    expect(bundleCatalogAllowsDecision(bundle, registry("UNPUBLISHED", null), "PROMOTE")).toBe(true);
    expect(bundleCatalogAllowsDecision(bundle, registry("PROMOTED", "d".repeat(64)), "PROMOTE")).toBe(false);

    const promoted = { ...bundle, state: "PROMOTED" as const };
    expect(bundleCatalogAllowsDecision(promoted, registry("PROMOTED", bundle.bundle_digest), "SUPERSEDE")).toBe(true);
    expect(bundleCatalogAllowsDecision(promoted, registry("PROMOTED", "d".repeat(64)), "SUPERSEDE")).toBe(false);
    expect(bundleCatalogAllowsDecision(promoted, registry("PROMOTED", bundle.bundle_digest), "WITHDRAW")).toBe(true);

    const superseded = { ...bundle, state: "SUPERSEDED" as const };
    expect(bundleCatalogAllowsDecision(superseded, registry("SUPERSEDED", null), "ROLLBACK_PROMOTE")).toBe(true);
    expect(bundleCatalogAllowsDecision(superseded, registry("PROMOTED", bundle.bundle_digest), "ROLLBACK_PROMOTE")).toBe(false);
    expect(bundleCatalogAllowsDecision(bundle, registry("SUPERSEDED", null), "WITHDRAW")).toBe(true);
  });

  it("creates exact DB and IMP documents with canonical SHA-256 digests", async () => {
    const db = await createEmptyDictionary("flight_mode", "DB");
    const imp = await createEmptyDictionary("flight_mode", "IMP");
    expect(db.mediaType).toBe("application/vnd.openbexi.spell.dictionary-db+json");
    expect(JSON.parse(db.content)).toMatchObject({ schema_version: "spell.dictionary.db/1", format: "DB", dictionary_id: "flight_mode", entries: [] });
    expect(JSON.parse(db.content).content_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(imp.mediaType).toBe("application/vnd.openbexi.spell.dictionary-imp+json");
    expect(JSON.parse(imp.content)).toMatchObject({ schema_version: "spell.dictionary.imp/1", format: "IMP", records: [] });
  });

  it("uploads exact authenticated archive bytes and hashes kept external content", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const calls: Array<{ path: string; body: BodyInit | null | undefined; headers: Headers }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ path: String(input), body: init?.body, headers: init?.headers as Headers });
      return new Response(JSON.stringify({ workspace_revision: 2 }), { headers: { "Content-Type": "application/json" } });
    }));
    const archive = new TextEncoder().encode("archive");
    const archiveDigest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", archive))]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    const filename = "prøject-航.zip";
    const encodedFilename = btoa(String.fromCharCode(...new TextEncoder().encode(filename.normalize("NFC"))))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/, "");
    const file = new File([archive], filename, { type: "application/zip" });
    Object.defineProperty(file, "arrayBuffer", { value: async () => archive.buffer });
    await importProject({ project_id: "project-1", file, expected_workspace_revision: 1 });
    await recordExternalChanges({ project_id: "project-1", base_workspace_revision: 2, resolution: "KEEP_AS_NEW_CHANGE", changes: [{ path: "src/demo.spell.py", content: "Log('new')\n", base_content_sha256: "a".repeat(64) }] });

    expect(Array.from(new Uint8Array(calls[0]?.body as ArrayBuffer))).toEqual(Array.from(archive));
    expect(calls[0]?.headers.get("Authorization")).toBe(`Bearer ${token}`);
    expect(calls[0]?.headers.get("Content-Type")).toBe("application/vnd.openbexi.spell.project+zip");
    expect(calls[0]?.headers.get("Content-SHA256")).toBe(archiveDigest);
    expect(calls[0]?.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]+$/);
    expect(calls[0]?.headers.get("X-Spell-Filename")).toBeNull();
    expect(calls[0]?.headers.get("X-Spell-Filename-Base64url")).toBe(encodedFilename);
    expect(calls[0]?.headers.get("X-Spell-Workspace-Revision")).toBe("1");
    expect(JSON.parse(String(calls[1]?.body)).changes[0].content_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("clears a rejected credential on raw project import", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ detail: { code: "AUTH", message: "expired" } }),
      { status: 401, headers: { "Content-Type": "application/json" } },
    )));
    const archive = new TextEncoder().encode("archive");
    const file = new File([archive], "project.zip", { type: "application/zip" });
    Object.defineProperty(file, "arrayBuffer", { value: async () => archive.buffer });

    await expect(importProject({ project_id: "project-1", file, expected_workspace_revision: 1 })).rejects.toThrow("AUTH: expired");
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
  });

  it("uses retained import operation routes and extracts only bounded conflict references", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const operation = {
      operation_id: "import-operation-1",
      project_id: "project-1",
      actor_subject: "operator",
      original_filename: "prøject.zip",
      original_media_type: "application/vnd.openbexi.spell.project+zip",
      original_byte_length: 100,
      original_bytes_sha256: "a".repeat(64),
      original_bytes_available: true,
      imported_tree_sha256: "b".repeat(64),
      canonical_tree_sha256: "c".repeat(64),
      base_workspace_revision: 7,
      status: "CONFLICT" as const,
      conflict_paths: ["src/demo.spell.py"],
      audit_id: "audit-1",
      created_at: "2026-08-18T10:00:00Z",
    };
    const calls: Array<{ path: string; method: string; body: Record<string, unknown> | null }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      calls.push({ path, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : null });
      if ((init?.method ?? "GET") === "GET") return new Response(JSON.stringify({ import_operation: operation }), { headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ project: { workspace_revision: 8 } }), { headers: { "Content-Type": "application/json" } });
    }));

    await expect(getImportOperation("project-1", operation.operation_id)).resolves.toEqual(operation);
    await applyImportOperation({ project_id: "project-1", operation_id: operation.operation_id, expected_workspace_revision: 7 });
    await discardImportOperation({ project_id: "project-1", operation_id: operation.operation_id, expected_workspace_revision: 8, reason: "Superseded upload" });

    expect(calls.map((call) => [call.method, call.path])).toEqual([
      ["GET", "/api/v1/development/projects/project-1/imports/import-operation-1"],
      ["POST", "/api/v1/development/projects/project-1/imports/import-operation-1/apply"],
      ["POST", "/api/v1/development/projects/project-1/imports/import-operation-1/discard"],
    ]);
    expect(calls[1]?.body).toMatchObject({ expected_workspace_revision: 7, idempotency_key: expect.any(String) });
    expect(calls[2]?.body).toMatchObject({ expected_workspace_revision: 8, reason: "Superseded upload", idempotency_key: expect.any(String) });

    expect(importOperationIdFromError(new ApiError("conflict", 409, { detail: { current: { operation_id: operation.operation_id } } }))).toBe(operation.operation_id);
    expect(importOperationIdFromError(new ApiError("conflict", 409, { detail: { current: { operation_id: "x".repeat(129) } } }))).toBeNull();
    expect(importOperationIdFromError(new ApiError("rejected", 422, { detail: { current: { operation_id: operation.operation_id } } }))).toBeNull();
  });

  it("requires an existing digest for external deletes before sending a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(recordExternalChanges({
      project_id: "project-1",
      base_workspace_revision: 2,
      resolution: "KEEP_AS_NEW_CHANGE",
      changes: [{ path: "src/demo.spell.py", delete: true }],
    })).rejects.toThrow("requires its current SHA-256 digest");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(externalResourceAtPath([document], "SRC/DEMO.SPELL.PY", "CASE_INSENSITIVE")?.resource_id).toBe(document.resource_id);
    expect(externalResourceAtPath([document], "SRC/DEMO.SPELL.PY", "CASE_SENSITIVE")).toBeNull();
  });

  it("reads project exports as authenticated digest-bound ZIP bytes", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const archive = new TextEncoder().encode("PK\u0003\u0004binary-zip");
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", archive))]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(archive, {
      headers: {
        "Content-SHA256": digest,
        "Content-Type": "application/vnd.openbexi.spell.project+zip",
      },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await exportProject("project-1", 7);

    expect(result.archive).toMatchObject({
      size: archive.byteLength,
      type: "application/vnd.openbexi.spell.project+zip",
    });
    expect(result).toMatchObject({
      filename: "project-1.spell-project.zip",
      media_type: "application/vnd.openbexi.spell.project+zip",
      archive_sha256: digest,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/development/projects/project-1/exports",
      expect.objectContaining({ method: "POST" }),
    );
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBe(`Bearer ${token}`);
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      expected_workspace_revision: 7,
    });
  });

  it("clears a rejected credential on binary project export", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ detail: { code: "AUTH", message: "expired" } }),
      { status: 401, headers: { "Content-Type": "application/json" } },
    )));

    await expect(exportProject("project-1", 7)).rejects.toThrow("AUTH: expired");
    expect(window.sessionStorage.getItem("openbexi.spell.access-token")).toBeNull();
  });

  it("verifies immutable bundle download headers and bytes", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const bytes = new TextEncoder().encode('{"format":"spell.bundle/1"}');
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(bytes, {
      headers: {
        "Content-SHA256": digest,
        "Content-Type": "application/vnd.openbexi.spell.bundle+json",
      },
    })));

    await expect(downloadBundle(digest)).resolves.toMatchObject({
      size: bytes.byteLength,
      type: "application/vnd.openbexi.spell.bundle+json",
    });
  });

  it("fails closed when immutable bundle download provenance differs", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new TextEncoder().encode("tampered"), {
      headers: { "Content-SHA256": "b".repeat(64) },
    })));

    await expect(downloadBundle("a".repeat(64))).rejects.toThrow("digest header differs");
  });

  it("downloads only digest-bound canonical semantic report bytes", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const bytes = new TextEncoder().encode('{"outcome":"PASS"}');
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(bytes, {
      headers: { "Content-SHA256": digest, "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(downloadSemanticReport("check-1", digest)).resolves.toMatchObject({
      size: bytes.byteLength,
      type: "application/json",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/development/checks/check-1/report",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    expect((fetchMock.mock.calls[0]?.[1]?.headers as Headers).get("Authorization")).toBe(`Bearer ${token}`);

    vi.stubGlobal("fetch", vi.fn(async () => new Response(bytes, {
      headers: { "Content-SHA256": "f".repeat(64), "Content-Type": "application/json" },
    })));
    await expect(downloadSemanticReport("check-1", digest)).rejects.toThrow("differs from the completed job");
  });

  it("projects a revision-zero registry for the first promotion", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: { code: "NOT_FOUND", message: "missing" } }), { status: 404, headers: { "Content-Type": "application/json" } })));
    const registry = await getPromotionRegistry("demo");
    expect(registry.catalog_entry).toMatchObject({ procedure_id: "demo", registry_revision: 0, current_bundle_digest: null });
  });

  it("updates the exact project manifest contract at the dedicated route", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ project: { workspace_revision: 8 } }), { headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    await updateProjectManifest({
      project_id: "project-1",
      expected_workspace_revision: 7,
      manifest: {
        schema_version: "spell.project/0.9",
        project_id: "project-1",
        display_name: "Demo",
        language_profile: "spell-restricted-ast/0.9",
        source_roots: ["src"],
        case_policy: "CASE_SENSITIVE",
        catalog_dependencies: [{ catalog_id: "local-catalog", catalog_revision: 2, content_digest: "c".repeat(64) }],
        owners: ["operator"],
        policy_labels: ["LOCAL_SYNTHETIC_NON_CUI_ONLY"],
      },
    });
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/development/projects/project-1/manifest", expect.objectContaining({ method: "PUT" }));
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)) as Record<string, unknown>;
    expect(body).toMatchObject({ expected_workspace_revision: 7, manifest: { language_profile: "spell-restricted-ast/0.9", source_roots: ["src"] } });
    expect(body.idempotency_key).toEqual(expect.any(String));
  });

  it("uses authoritative server metadata for a saved procedure", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ resource: {
      resource_id: "resource-1",
      project_id: "project-1",
      path: "src/demo.spell.py",
      kind: "PROCEDURE",
      media_type: "text/x-python",
      content: "# @procedure local-preview\nLog('ready')\n",
      content_sha256: "a".repeat(64),
      byte_length: 41,
      revision: 1,
      created_by_subject: "operator",
      updated_by_subject: "operator",
      created_at: "2026-08-18T10:00:00Z",
      updated_at: "2026-08-18T10:00:00Z",
      metadata: { procedure_id: "server-validated", display_name: "Validated", description: "", language_profile: "spell-restricted-ast/0.9", arguments: { mode: "STRING" }, catalog_dependencies: [] },
    } }), { headers: { "Content-Type": "application/json" } })));
    const result = await readResource("project-1", "resource-1");
    expect(result.metadata).toMatchObject({ procedure_id: "server-validated", arguments: { mode: "STRING" } });
  });
});
