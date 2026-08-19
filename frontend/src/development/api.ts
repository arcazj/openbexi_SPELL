import {
  ApiError,
  clearAccessToken,
  getAccessToken,
  normalizeAccessToken,
  setAccessToken,
} from "../api";
import type {
  BundleState,
  CheckScope,
  DevelopmentBootstrap,
  DevelopmentIdentity,
  ExternalResourceChange,
  HistoryRevision,
  ImportOperation,
  MutationResult,
  PageResult,
  ProcedureBundle,
  ProjectExport,
  ProjectManifest,
  ProjectProperties,
  ProjectResource,
  ProjectSummary,
  ProjectWorkspace,
  PromotionRegistry,
  ResourceDocument,
  ResourceKind,
  RevisionDiff,
  SemanticJob,
  WorkspaceConflict,
  WorkspaceStatus,
} from "./types";

const DEVELOPMENT_API_ROOT = "/api/v1/development";

type JsonRecord = Record<string, unknown>;
type WireResource = Omit<ProjectResource, "name" | "parent_path" | "has_children"> & {
  content?: string;
  language?: ResourceDocument["language"];
  metadata?: ResourceDocument["metadata"];
};
type WireHistory = Omit<HistoryRevision, "review_revision" | "review"> & {
  review_revision?: number;
  review?: HistoryRevision["review"];
};
type WireWorkspace = Omit<ProjectWorkspace, "resources" | "history" | "conflicts" | "pinned_catalog_entries"> & {
  resources: WireResource[];
  history: WireHistory[];
  conflicts?: WorkspaceConflict[];
  pinned_catalog_entries?: ProjectWorkspace["pinned_catalog_entries"];
};

function requestHeaders(token?: string, extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  const credential = token ?? getAccessToken();
  if (credential) headers.set("Authorization", `Bearer ${credential}`);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return headers;
}

function errorMessage(status: number, body: unknown): string {
  const detail = typeof body === "object" && body !== null && "detail" in body
    ? (body as { detail?: unknown }).detail
    : null;
  if (typeof detail === "object" && detail !== null) {
    const record = detail as JsonRecord;
    const code = typeof record.code === "string" ? `${record.code}: ` : "";
    const message = typeof record.message === "string" ? record.message : "Request rejected";
    return `${code}${message}`;
  }
  if (typeof detail === "string") return detail;
  if (status === 401) return "The backend rejected this signed JWT.";
  return `Development request failed (${status}).`;
}

function errorCode(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("detail" in body)) return null;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail !== "object" || detail === null || !("code" in detail)) return null;
  const code = (detail as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

const RETRYABLE_TRANSACTION_DELAYS_MS = [25, 75] as const;

async function request<T>(path: string, init?: RequestInit, token?: string): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    const response = await fetch(`${DEVELOPMENT_API_ROOT}${path}`, {
      ...init,
      headers: requestHeaders(token, init?.headers),
    });
    const body = response.status === 204
      ? null
      : await response.json().catch(() => null) as unknown;
    if (response.ok) return body as T;
    if (
      response.status === 409
      && errorCode(body) === "RETRYABLE_TRANSACTION_CONFLICT"
      && attempt < RETRYABLE_TRANSACTION_DELAYS_MS.length
    ) {
      await new Promise((resolve) => window.setTimeout(resolve, RETRYABLE_TRANSACTION_DELAYS_MS[attempt]));
      continue;
    }
    if (response.status === 401 && token === undefined) clearAccessToken();
    throw new ApiError(errorMessage(response.status, body), response.status, body);
  }
}

async function requestBinary(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(`${DEVELOPMENT_API_ROOT}${path}`, {
    ...init,
    headers: requestHeaders(undefined, init?.headers),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as unknown;
    if (response.status === 401) clearAccessToken();
    throw new ApiError(errorMessage(response.status, body), response.status, body);
  }
  return response;
}

function unwrap<T>(body: T | Record<string, unknown>, key: string): T {
  if (typeof body === "object" && body !== null && key in body) {
    return (body as Record<string, unknown>)[key] as T;
  }
  return body as T;
}

function unwrapItems<T>(body: T[] | PageResult<T>): T[] {
  return Array.isArray(body) ? body : body.items;
}

function resourceName(path: string): string {
  return path.split("/").filter(Boolean).at(-1) ?? path;
}

function resourceParent(path: string): string | null {
  const segments = path.split("/").filter(Boolean);
  return segments.length > 1 ? segments.slice(0, -1).join("/") : null;
}

function normalizeResource(resource: WireResource, resources: WireResource[] = [resource]): ProjectResource {
  return {
    ...resource,
    name: resourceName(resource.path),
    parent_path: resourceParent(resource.path),
    has_children: resources.some((candidate) => candidate.path.startsWith(`${resource.path}/`)),
  };
}

function normalizeResources(resources: WireResource[]): ProjectResource[] {
  return resources.map((resource) => normalizeResource(resource, resources));
}

function normalizeDocument(resource: WireResource): ResourceDocument {
  if (typeof resource.content !== "string") throw new Error("Resource content is absent.");
  return {
    ...resource,
    content: resource.content,
    metadata: resource.metadata ?? null,
  };
}

function normalizeHistory(revision: WireHistory): HistoryRevision {
  return {
    ...revision,
    review_revision: revision.review_revision ?? revision.review?.review_revision ?? 0,
    review: revision.review ?? null,
  };
}

function normalizeWorkspace(workspace: WireWorkspace): ProjectWorkspace {
  return {
    ...workspace,
    resources: normalizeResources(workspace.resources),
    history: workspace.history.map(normalizeHistory),
    conflicts: workspace.conflicts ?? [],
    pinned_catalog_entries: workspace.pinned_catalog_entries ?? [],
  };
}

function mutationResult(body: unknown): MutationResult {
  if (typeof body !== "object" || body === null) throw new Error("Development mutation response is invalid.");
  const record = body as { project?: ProjectSummary; workspace_revision?: number; resource?: WireResource };
  const workspaceRevision = record.project?.workspace_revision ?? record.workspace_revision;
  if (typeof workspaceRevision !== "number") throw new Error("Development mutation response lacks a workspace revision.");
  return {
    workspace_revision: workspaceRevision,
    ...(record.resource ? { resource: normalizeResource(record.resource) } : {}),
  };
}

function decodeIdentity(token: string): DevelopmentIdentity {
  try {
    const payloadSegment = token.split(".")[1] ?? "";
    const normalized = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded)) as { sub?: unknown; role?: unknown };
    const role = payload.role === "admin" || payload.role === "operator" || payload.role === "viewer"
      ? payload.role
      : "viewer";
    return {
      subject: typeof payload.sub === "string" && payload.sub ? payload.sub : "Authenticated user",
      role,
    };
  } catch {
    return { subject: "Authenticated user", role: "viewer" };
  }
}

function idempotencyKey(): string {
  return crypto.randomUUID();
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256BufferHex(value: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function filenameBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value.normalize("NFC"));
  if (bytes.length === 0 || bytes.length > 512) {
    throw new Error("Project archive filename must contain 1 to 512 UTF-8 bytes.");
  }
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function projectPath(projectId: string): string {
  return `/projects/${encodeURIComponent(projectId)}`;
}

export async function authenticateDevelopmentAccessToken(token: string): Promise<DevelopmentBootstrap> {
  const normalized = normalizeAccessToken(token);
  const body = await request<ProjectSummary[] | PageResult<ProjectSummary>>("/projects", undefined, normalized);
  const projects = unwrapItems(body);
  setAccessToken(normalized);
  return { identity: decodeIdentity(normalized), projects };
}

export function currentDevelopmentIdentity(): DevelopmentIdentity {
  const token = getAccessToken();
  return token ? decodeIdentity(token) : { subject: "Unauthenticated", role: "viewer" };
}

export async function listProjects(): Promise<ProjectSummary[]> {
  const body = await request<ProjectSummary[] | PageResult<ProjectSummary>>("/projects");
  return unwrapItems(body);
}

export async function createProject(input: {
  name: string;
  case_policy: ProjectSummary["case_policy"];
  manifest: Partial<ProjectManifest>;
}): Promise<ProjectSummary> {
  const body = await request<ProjectSummary | { project: ProjectSummary }>("/projects", {
    method: "POST",
    body: JSON.stringify({ ...input, idempotency_key: idempotencyKey() }),
  });
  return unwrap<ProjectSummary>(body, "project");
}

export async function updateProjectManifest(input: {
  project_id: string;
  manifest: ProjectManifest;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const body = await request<unknown>(`${projectPath(input.project_id)}/manifest`, {
    method: "PUT",
    body: JSON.stringify({
      manifest: input.manifest,
      expected_workspace_revision: input.expected_workspace_revision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function setProjectClosed(
  projectId: string,
  closed: boolean,
  expectedWorkspaceRevision: number,
): Promise<ProjectSummary> {
  const body = await request<{ project: ProjectSummary }>(`${projectPath(projectId)}/${closed ? "close" : "open"}`, {
    method: "POST",
    body: JSON.stringify({
      expected_workspace_revision: expectedWorkspaceRevision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return body.project;
}

export async function getProjectProperties(projectId: string): Promise<ProjectProperties> {
  return request<ProjectProperties>(`${projectPath(projectId)}/properties`);
}

export async function getWorkspace(projectId: string): Promise<ProjectWorkspace> {
  const body = await request<WireWorkspace | { workspace: WireWorkspace }>(`${projectPath(projectId)}/workspace`);
  return normalizeWorkspace(unwrap<WireWorkspace>(body, "workspace"));
}

export async function readResource(projectId: string, resourceId: string): Promise<ResourceDocument> {
  const body = await request<WireResource | { resource: WireResource }>(
    `${projectPath(projectId)}/resources/${encodeURIComponent(resourceId)}`,
  );
  return normalizeDocument(unwrap<WireResource>(body, "resource"));
}

export async function createResource(input: {
  project_id: string;
  path: string;
  kind: ResourceKind;
  media_type: string;
  content: string;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const body = await request<unknown>(`${projectPath(input.project_id)}/resources`, {
    method: "POST",
    body: JSON.stringify({
      path: input.path,
      kind: input.kind,
      media_type: input.media_type,
      content: input.content,
      content_sha256: await sha256Hex(input.content),
      expected_workspace_revision: input.expected_workspace_revision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function updateResource(input: {
  project_id: string;
  resource_id: string;
  expected_workspace_revision: number;
  path?: string;
  media_type?: string;
  content?: string;
}): Promise<MutationResult> {
  const contentFields = input.content === undefined
    ? {}
    : { content: input.content, content_sha256: await sha256Hex(input.content) };
  const body = await request<unknown>(`${projectPath(input.project_id)}/resources/${encodeURIComponent(input.resource_id)}`, {
    method: "PUT",
    body: JSON.stringify({
      ...(input.path === undefined ? {} : { path: input.path }),
      ...(input.media_type === undefined ? {} : { media_type: input.media_type }),
      ...contentFields,
      expected_workspace_revision: input.expected_workspace_revision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function deleteResource(
  projectId: string,
  resourceId: string,
  expectedWorkspaceRevision: number,
): Promise<MutationResult> {
  const body = await request<unknown>(`${projectPath(projectId)}/resources/${encodeURIComponent(resourceId)}`, {
    method: "DELETE",
    body: JSON.stringify({
      expected_workspace_revision: expectedWorkspaceRevision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function copyResource(input: {
  project_id: string;
  resource_id: string;
  destination_path: string;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const body = await request<unknown>(
    `${projectPath(input.project_id)}/resources/${encodeURIComponent(input.resource_id)}/copy`,
    {
      method: "POST",
      body: JSON.stringify({
        destination_path: input.destination_path,
        expected_workspace_revision: input.expected_workspace_revision,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return mutationResult(body);
}

export async function startSemanticCheck(input: {
  project_id: string;
  scope: CheckScope;
  scope_path?: string;
  expected_workspace_revision: number;
  reparse_libraries?: boolean;
}): Promise<SemanticJob> {
  const body = await request<SemanticJob | { job: SemanticJob }>(`${projectPath(input.project_id)}/checks`, {
    method: "POST",
    body: JSON.stringify({
      scope: input.scope,
      ...(input.scope_path ? { scope_path: input.scope_path } : {}),
      expected_workspace_revision: input.expected_workspace_revision,
      reparse_libraries: input.reparse_libraries ?? false,
      idempotency_key: idempotencyKey(),
    }),
  });
  return unwrap<SemanticJob>(body, "job");
}

export async function getSemanticCheck(jobId: string): Promise<SemanticJob> {
  const body = await request<SemanticJob | { job: SemanticJob }>(`/checks/${encodeURIComponent(jobId)}`);
  return unwrap<SemanticJob>(body, "job");
}

export async function cancelSemanticCheck(jobId: string): Promise<SemanticJob> {
  const body = await request<SemanticJob | { job: SemanticJob }>(`/checks/${encodeURIComponent(jobId)}/cancel`, {
    method: "POST",
    body: JSON.stringify({ idempotency_key: idempotencyKey() }),
  });
  return unwrap<SemanticJob>(body, "job");
}

export async function cleanProblems(projectId: string, expectedWorkspaceRevision: number): Promise<MutationResult> {
  const body = await request<unknown>(`${projectPath(projectId)}/problems/clean`, {
    method: "POST",
    body: JSON.stringify({
      expected_workspace_revision: expectedWorkspaceRevision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function commitHistory(input: {
  project_id: string;
  expected_workspace_revision: number;
  message: string;
}): Promise<HistoryRevision> {
  const body = await request<WireHistory | { history_revision: WireHistory }>(`${projectPath(input.project_id)}/history`, {
    method: "POST",
    body: JSON.stringify({
      expected_workspace_revision: input.expected_workspace_revision,
      message: input.message,
      idempotency_key: idempotencyKey(),
    }),
  });
  return normalizeHistory(unwrap<WireHistory>(body, "history_revision"));
}

export async function commitSelectedHistory(input: {
  project_id: string;
  expected_workspace_revision: number;
  message: string;
  selected_resource_ids: string[];
}): Promise<HistoryRevision> {
  const body = await request<WireHistory | { history_revision: WireHistory }>(
    `${projectPath(input.project_id)}/history/commit-selected`,
    {
      method: "POST",
      body: JSON.stringify({
        expected_workspace_revision: input.expected_workspace_revision,
        message: input.message,
        selected_resource_ids: input.selected_resource_ids,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return normalizeHistory(unwrap<WireHistory>(body, "history_revision"));
}

export async function getWorkspaceStatus(projectId: string): Promise<WorkspaceStatus> {
  const body = await request<WorkspaceStatus | { status: WorkspaceStatus }>(`${projectPath(projectId)}/status`);
  return unwrap<WorkspaceStatus>(body, "status");
}

export async function diffWorkspaceToBase(projectId: string): Promise<RevisionDiff> {
  const body = await request<RevisionDiff | { diff: RevisionDiff }>(`${projectPath(projectId)}/diff`);
  return unwrap<RevisionDiff>(body, "diff");
}

export async function refreshHistoryBase(input: {
  project_id: string;
  history_revision_id: string;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const body = await request<unknown>(`${projectPath(input.project_id)}/history/refresh-base`, {
    method: "POST",
    body: JSON.stringify({
      history_revision_id: input.history_revision_id,
      expected_workspace_revision: input.expected_workspace_revision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function getHistory(projectId: string): Promise<HistoryRevision[]> {
  const body = await request<WireHistory[] | PageResult<WireHistory>>(`${projectPath(projectId)}/history`);
  return unwrapItems(body).map(normalizeHistory);
}

export async function getHistoryRevision(revisionId: string): Promise<HistoryRevision> {
  const body = await request<{ history_revision: WireHistory; review: HistoryRevision["review"] }>(`/history/${encodeURIComponent(revisionId)}`);
  return {
    ...normalizeHistory(body.history_revision),
    review_revision: body.review?.review_revision ?? 0,
    review: body.review,
  };
}

export async function diffHistory(revisionId: string, againstRevisionId: string): Promise<RevisionDiff> {
  const query = new URLSearchParams({ against_revision_id: againstRevisionId });
  const body = await request<RevisionDiff | { diff: RevisionDiff }>(
    `/history/${encodeURIComponent(revisionId)}/diff?${query.toString()}`,
  );
  return unwrap<RevisionDiff>(body, "diff");
}

export async function reviewHistory(
  revisionId: string,
  expectedReviewRevision: number,
  reason: string,
): Promise<HistoryRevision> {
  const body = await request<{ history_revision: WireHistory; review: NonNullable<HistoryRevision["review"]> }>(
    `/history/${encodeURIComponent(revisionId)}/review`,
    {
      method: "POST",
      body: JSON.stringify({
        decision: "APPROVE",
        reason,
        expected_review_revision: expectedReviewRevision,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return { ...normalizeHistory(body.history_revision), review_revision: body.review.review_revision, review: body.review };
}

export async function revertHistory(
  revisionId: string,
  expectedWorkspaceRevision: number,
  reason: string,
): Promise<MutationResult> {
  const body = await request<unknown>(`/history/${encodeURIComponent(revisionId)}/revert`, {
    method: "POST",
    body: JSON.stringify({
      expected_workspace_revision: expectedWorkspaceRevision,
      reason,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function resolveConflict(input: {
  project_id: string;
  conflict: WorkspaceConflict;
  resolution: "OURS" | "THEIRS" | "MERGED" | "DELETE";
  resolved_content?: string;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const body = await request<unknown>(`${projectPath(input.project_id)}/conflicts/resolve`, {
    method: "POST",
    body: JSON.stringify({
      path: input.conflict.path,
      resolution: input.resolution,
      ...(input.resolved_content === undefined ? {} : { resolved_content: input.resolved_content }),
      expected_conflict_digest: input.conflict.conflict_digest,
      expected_workspace_revision: input.expected_workspace_revision,
      idempotency_key: idempotencyKey(),
    }),
  });
  return mutationResult(body);
}

export async function importProject(input: {
  project_id: string;
  file: File;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const archive = await input.file.arrayBuffer();
  const archiveSha = await sha256BufferHex(archive);
  const body = await request<unknown>(`${projectPath(input.project_id)}/imports`, {
    method: "POST",
    headers: {
      "Content-Type": "application/vnd.openbexi.spell.project+zip",
      "Content-SHA256": archiveSha,
      "Idempotency-Key": idempotencyKey(),
      "X-Spell-Filename-Base64url": filenameBase64Url(input.file.name),
      "X-Spell-Workspace-Revision": String(input.expected_workspace_revision),
    },
    body: archive,
  });
  return mutationResult(body);
}

export function importOperationIdFromError(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.status !== 409 || typeof error.details !== "object" || error.details === null) return null;
  const detail = "detail" in error.details ? (error.details as JsonRecord).detail : null;
  if (typeof detail !== "object" || detail === null) return null;
  const current = "current" in detail ? (detail as JsonRecord).current : null;
  if (typeof current !== "object" || current === null) return null;
  const operationId = (current as JsonRecord).operation_id;
  return typeof operationId === "string" && operationId.length > 0 && operationId.length <= 128
    ? operationId
    : null;
}

export async function getImportOperation(projectId: string, operationId: string): Promise<ImportOperation> {
  const body = await request<ImportOperation | { import_operation: ImportOperation }>(
    `${projectPath(projectId)}/imports/${encodeURIComponent(operationId)}`,
  );
  return unwrap<ImportOperation>(body, "import_operation");
}

export async function applyImportOperation(input: {
  project_id: string;
  operation_id: string;
  expected_workspace_revision: number;
}): Promise<MutationResult> {
  const body = await request<unknown>(
    `${projectPath(input.project_id)}/imports/${encodeURIComponent(input.operation_id)}/apply`,
    {
      method: "POST",
      body: JSON.stringify({
        expected_workspace_revision: input.expected_workspace_revision,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return mutationResult(body);
}

export async function discardImportOperation(input: {
  project_id: string;
  operation_id: string;
  expected_workspace_revision: number;
  reason: string;
}): Promise<MutationResult> {
  const body = await request<unknown>(
    `${projectPath(input.project_id)}/imports/${encodeURIComponent(input.operation_id)}/discard`,
    {
      method: "POST",
      body: JSON.stringify({
        expected_workspace_revision: input.expected_workspace_revision,
        reason: input.reason,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return mutationResult(body);
}

export async function exportProject(projectId: string, expectedWorkspaceRevision: number): Promise<ProjectExport> {
  const response = await requestBinary(`${projectPath(projectId)}/exports`, {
    method: "POST",
    headers: { Accept: "application/vnd.openbexi.spell.project+zip" },
    body: JSON.stringify({ expected_workspace_revision: expectedWorkspaceRevision }),
  });
  const archiveBytes = await response.arrayBuffer();
  const declaredDigest = response.headers.get("Content-SHA256");
  if (!declaredDigest || !/^[0-9a-f]{64}$/.test(declaredDigest)) {
    throw new Error("Project export response lacks a canonical SHA-256 digest.");
  }
  const actualDigest = await sha256BufferHex(archiveBytes);
  if (actualDigest !== declaredDigest) {
    throw new Error("Project export SHA-256 differs from the response digest.");
  }
  return {
    filename: `${projectId}.spell-project.zip`,
    media_type: response.headers.get("Content-Type")?.split(";", 1)[0]
      ?? "application/vnd.openbexi.spell.project+zip",
    archive: new Blob([archiveBytes], {
      type: "application/vnd.openbexi.spell.project+zip",
    }),
    archive_sha256: declaredDigest,
  };
}

export async function recordExternalChanges(input: {
  project_id: string;
  base_workspace_revision: number;
  base_history_revision_id?: string;
  changes: ExternalResourceChange[];
  resolution: "RELOAD" | "KEEP_AS_NEW_CHANGE" | "THREE_WAY_MERGE";
}): Promise<MutationResult> {
  for (const change of input.changes) {
    if (change.delete && !change.base_content_sha256) {
      throw new Error("Deleting an external resource requires its current SHA-256 digest.");
    }
    if (change.base_content_sha256 !== undefined && !/^[0-9a-f]{64}$/.test(change.base_content_sha256)) {
      throw new Error("External resource base SHA-256 must be 64 lowercase hexadecimal characters.");
    }
  }
  const changes = await Promise.all(input.changes.map(async (change) => {
    if (change.delete || change.content === undefined || input.resolution === "RELOAD") return change;
    return { ...change, content_sha256: await sha256Hex(change.content) };
  }));
  const body = await request<unknown>(`${projectPath(input.project_id)}/external-changes`, {
    method: "POST",
    body: JSON.stringify({ ...input, changes, idempotency_key: idempotencyKey() }),
  });
  return mutationResult(body);
}

export async function buildBundle(revisionId: string): Promise<ProcedureBundle> {
  const body = await request<ProcedureBundle | { bundle: ProcedureBundle }>(
    `/history/${encodeURIComponent(revisionId)}/bundles`,
    { method: "POST", body: JSON.stringify({ idempotency_key: idempotencyKey() }) },
  );
  return unwrap<ProcedureBundle>(body, "bundle");
}

export async function getBundle(bundleDigest: string): Promise<ProcedureBundle> {
  const body = await request<ProcedureBundle | { bundle: ProcedureBundle }>(`/bundles/${encodeURIComponent(bundleDigest)}`);
  return unwrap<ProcedureBundle>(body, "bundle");
}

export async function downloadBundle(bundleDigest: string): Promise<Blob> {
  const response = await requestBinary(`/bundles/${encodeURIComponent(bundleDigest)}/download`);
  const declaredDigest = response.headers.get("Content-SHA256")?.trim().toLowerCase() ?? "";
  if (!/^[0-9a-f]{64}$/.test(declaredDigest) || declaredDigest !== bundleDigest.toLowerCase()) {
    throw new Error("Bundle download digest header differs from the requested bundle.");
  }
  const bytes = await response.arrayBuffer();
  if (await sha256BufferHex(bytes) !== declaredDigest) {
    throw new Error("Bundle download bytes failed SHA-256 verification.");
  }
  return new Blob([bytes], {
    type: response.headers.get("Content-Type")?.split(";", 1)[0] || "application/vnd.openbexi.spell.bundle+json",
  });
}

export async function downloadSemanticReport(jobId: string, expectedDigest: string): Promise<Blob> {
  const digest = expectedDigest.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error("Semantic report lacks a canonical expected SHA-256 digest.");
  }
  const response = await requestBinary(`/checks/${encodeURIComponent(jobId)}/report`, {
    headers: { Accept: "application/json" },
  });
  const declaredDigest = response.headers.get("Content-SHA256")?.trim().toLowerCase() ?? "";
  if (declaredDigest !== digest) {
    throw new Error("Semantic report digest header differs from the completed job.");
  }
  const bytes = await response.arrayBuffer();
  if (await sha256BufferHex(bytes) !== digest) {
    throw new Error("Semantic report bytes failed SHA-256 verification.");
  }
  const mediaType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new Error("Semantic report response has an unexpected media type.");
  }
  return new Blob([bytes], { type: "application/json" });
}

export async function approveBundle(
  bundleDigest: string,
  expectedStateRevision: number,
  reason: string,
): Promise<ProcedureBundle> {
  const body = await request<ProcedureBundle | { bundle: ProcedureBundle }>(
    `/bundles/${encodeURIComponent(bundleDigest)}/approve`,
    {
      method: "POST",
      body: JSON.stringify({
        expected_state_revision: expectedStateRevision,
        reason,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return unwrap<ProcedureBundle>(body, "bundle");
}

export async function getPromotionRegistry(procedureId: string): Promise<PromotionRegistry> {
  try {
    return await request<PromotionRegistry>(`/catalog/${encodeURIComponent(procedureId)}`);
  } catch (caught) {
    if (!(caught instanceof ApiError) || caught.status !== 404) throw caught;
    return {
      catalog_entry: {
        procedure_id: procedureId,
        registry_revision: 0,
        current_bundle_digest: null,
        previous_bundle_digest: null,
        state: "UNPUBLISHED",
        updated_by_subject: "",
        created_at: "",
        updated_at: "",
      },
      decisions: [],
    };
  }
}

export async function decidePromotion(input: {
  procedure_id: string;
  operation: "PROMOTE" | "SUPERSEDE" | "ROLLBACK_PROMOTE" | "WITHDRAW";
  digest?: string;
  expected_registry_revision: number;
  reason: string;
}): Promise<PromotionRegistry> {
  const body = await request<{ catalog_entry: PromotionRegistry["catalog_entry"]; decision: PromotionRegistry["decisions"][number] }>(
    `/catalog/${encodeURIComponent(input.procedure_id)}/decisions`,
    {
      method: "POST",
      body: JSON.stringify({
        operation: input.operation,
        ...(input.digest ? { bundle_digest: input.digest } : {}),
        expected_registry_revision: input.expected_registry_revision,
        reason: input.reason,
        idempotency_key: idempotencyKey(),
      }),
    },
  );
  return { catalog_entry: body.catalog_entry, decisions: [body.decision] };
}

export function updatePresence(input: {
  project_id: string;
  resource_id?: string;
  client_instance_id: string;
  status: "VIEWING" | "EDITING" | "IDLE";
  expected_workspace_revision: number;
}): Promise<void> {
  return request(`${projectPath(input.project_id)}/presence`, {
    method: "PUT",
    body: JSON.stringify({
      ...(input.resource_id ? { resource_id: input.resource_id } : {}),
      client_instance_id: input.client_instance_id,
      status: input.status,
      expected_workspace_revision: input.expected_workspace_revision,
      idempotency_key: idempotencyKey(),
    }),
  });
}

export function downloadProjectFile(file: ProjectExport): void {
  const url = URL.createObjectURL(file.archive);
  const link = document.createElement("a");
  link.href = url;
  link.download = file.filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function downloadSemanticReportFile(jobId: string, report: Blob): void {
  const url = URL.createObjectURL(report);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${jobId}.semantic-report.json`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function bundleStateAllowsDecision(state: BundleState, operation: string): boolean {
  return (operation === "APPROVE" && state === "CANDIDATE")
    || (operation === "PROMOTE" && state === "APPROVED")
    || (operation === "SUPERSEDE" && state === "PROMOTED")
    || (operation === "WITHDRAW" && (state === "APPROVED" || state === "PROMOTED"))
    || (operation === "ROLLBACK_PROMOTE" && state === "SUPERSEDED");
}

export function bundleProcedureId(bundle: ProcedureBundle): string | null {
  const procedureIds = bundle.manifest.procedure_ids;
  return Array.isArray(procedureIds)
    && procedureIds.length === 1
    && typeof procedureIds[0] === "string"
    && procedureIds[0].trim() === procedureIds[0]
    && procedureIds[0].length > 0
    ? procedureIds[0]
    : null;
}

export function bundleCatalogAllowsDecision(
  bundle: ProcedureBundle,
  registry: PromotionRegistry | null,
  operation: "PROMOTE" | "SUPERSEDE" | "ROLLBACK_PROMOTE" | "WITHDRAW",
): boolean {
  if (!registry || !bundleStateAllowsDecision(bundle.state, operation)) return false;
  const entry = registry.catalog_entry;
  if (entry.procedure_id !== bundleProcedureId(bundle)) return false;
  if (operation === "PROMOTE") {
    return entry.current_bundle_digest === null && entry.state !== "PROMOTED";
  }
  if (operation === "SUPERSEDE") {
    return entry.state === "PROMOTED" && entry.current_bundle_digest === bundle.bundle_digest;
  }
  if (operation === "ROLLBACK_PROMOTE") {
    return entry.state === "SUPERSEDED" && entry.current_bundle_digest === null;
  }
  return bundle.state === "PROMOTED"
    ? entry.state === "PROMOTED" && entry.current_bundle_digest === bundle.bundle_digest
    : entry.current_bundle_digest === null;
}

export function resourceById(resources: ProjectResource[], resourceId: string | null): ProjectResource | null {
  return resources.find((resource) => resource.resource_id === resourceId) ?? null;
}
