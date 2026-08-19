import {
  Archive,
  CheckCheck,
  ChevronDown,
  CircleUserRound,
  Clock3,
  CodeXml,
  Download,
  GitCompareArrows,
  History,
  PackageCheck,
  Replace,
  RefreshCcw,
  RotateCcw,
  Save,
  ShieldCheck,
  Trash2,
  UploadCloud,
  WandSparkles,
  Users,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  approveBundle,
  buildBundle,
  bundleCatalogAllowsDecision,
  bundleProcedureId,
  bundleStateAllowsDecision,
  commitHistory,
  commitSelectedHistory,
  decidePromotion,
  diffHistory,
  diffWorkspaceToBase,
  downloadBundle,
  getPromotionRegistry,
  getWorkspaceStatus,
  refreshHistoryBase,
  revertHistory,
  reviewHistory,
} from "./api";
import type {
  DevelopmentIdentity,
  ImportOperation,
  HistoryRevision,
  ProjectResource,
  ProjectSummary,
  PresenceRecord,
  ProcedureBundle,
  PromotionRegistry,
  RevisionDiff,
  WorkspaceConflict,
  WorkspaceStatus,
  ExternalResourceChange,
} from "./types";

type ActivityTab = "changes" | "history" | "release" | "presence";

interface ActivityPanelProps {
  projectId: string;
  identity: DevelopmentIdentity;
  resources: ProjectResource[];
  casePolicy: ProjectSummary["case_policy"];
  workspaceRevision: number;
  baseHistoryRevision: Pick<HistoryRevision, "history_revision_id" | "workspace_revision"> | null;
  history: HistoryRevision[];
  conflicts: WorkspaceConflict[];
  bundles: ProcedureBundle[];
  presence: PresenceRecord[];
  canMutate: boolean;
  busy: boolean;
  retainedImportOperation: ImportOperation | null;
  onChanged: () => Promise<void>;
  onApplyImport: () => Promise<void>;
  onDiscardImport: (reason: string) => Promise<void>;
  onResolveConflict: (conflict: WorkspaceConflict, resolution: "OURS" | "THEIRS" | "MERGED" | "DELETE", resolvedContent?: string) => Promise<void>;
  onExternalChanges: (changes: ExternalResourceChange[], resolution: "RELOAD" | "KEEP_AS_NEW_CHANGE" | "THREE_WAY_MERGE") => Promise<void>;
  onError: (message: string) => void;
}

function shortDigest(value: string | null | undefined): string {
  return value ? `${value.slice(0, 10)}...${value.slice(-6)}` : "none";
}

export function externalResourceAtPath(
  resources: Array<Pick<ProjectResource, "resource_id" | "path" | "content_sha256">>,
  path: string,
  casePolicy: ProjectSummary["case_policy"],
): Pick<ProjectResource, "resource_id" | "path" | "content_sha256"> | null {
  const normalized = path.trim().normalize("NFC");
  if (!normalized) return null;
  const identity = casePolicy === "CASE_INSENSITIVE" ? normalized.toLowerCase() : normalized;
  return resources.find((resource) => {
    const candidate = resource.path.normalize("NFC");
    return (casePolicy === "CASE_INSENSITIVE" ? candidate.toLowerCase() : candidate) === identity;
  }) ?? null;
}

function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function ActivityPanel({
  projectId,
  identity,
  resources,
  casePolicy,
  workspaceRevision,
  baseHistoryRevision,
  history: revisions,
  conflicts,
  bundles,
  presence,
  canMutate,
  busy,
  retainedImportOperation,
  onChanged,
  onApplyImport,
  onDiscardImport,
  onResolveConflict,
  onExternalChanges,
  onError,
}: ActivityPanelProps) {
  const [tab, setTab] = useState<ActivityTab>("changes");
  const [message, setMessage] = useState("");
  const [reason, setReason] = useState("");
  const [diff, setDiff] = useState<RevisionDiff | null>(null);
  const [diffTitle, setDiffTitle] = useState("Revision diff");
  const [workspaceStatus, setWorkspaceStatus] = useState<WorkspaceStatus | null>(null);
  const [selectedChangeIds, setSelectedChangeIds] = useState<string[]>([]);
  const [registries, setRegistries] = useState<Record<string, PromotionRegistry>>({});
  const [working, setWorking] = useState(false);
  const [externalPath, setExternalPath] = useState("");
  const [externalContent, setExternalContent] = useState("");
  const [externalBaseDigest, setExternalBaseDigest] = useState("");
  const [externalFeedback, setExternalFeedback] = useState("");
  const [importDiscardReason, setImportDiscardReason] = useState("");
  const isAdmin = identity.role === "admin";
  const bundleProcedureIds = useMemo(() => [...new Set(
    bundles.map(bundleProcedureId).filter((value): value is string => value !== null),
  )].sort(), [bundles]);
  const externalResource = useMemo(
    () => externalResourceAtPath(resources, externalPath, casePolicy),
    [casePolicy, externalPath, resources],
  );
  const externalBaseDigestValid = /^[0-9a-f]{64}$/.test(externalBaseDigest.trim());

  useEffect(() => {
    let cancelled = false;
    if (bundleProcedureIds.length === 0) {
      setRegistries({});
      return;
    }
    void Promise.all(bundleProcedureIds.map(async (procedureId) => [procedureId, await getPromotionRegistry(procedureId)] as const))
      .then((next) => { if (!cancelled) setRegistries(Object.fromEntries(next)); })
      .catch(() => { if (!cancelled) setRegistries({}); });
    return () => { cancelled = true; };
  }, [bundleProcedureIds]);

  useEffect(() => {
    let cancelled = false;
    void getWorkspaceStatus(projectId)
      .then((next) => {
        if (cancelled) return;
        setWorkspaceStatus(next);
        const available = new Set(next.changes.map((change) => change.resource_id));
        setSelectedChangeIds((current) => current.filter((resourceId) => available.has(resourceId)));
      })
      .catch((caught: unknown) => {
        if (!cancelled) onError(caught instanceof Error ? caught.message : "Workspace status could not be loaded.");
      });
    return () => { cancelled = true; };
  }, [baseHistoryRevision?.history_revision_id, onError, projectId, workspaceRevision]);

  async function perform(action: () => Promise<unknown>) {
    setWorking(true);
    try {
      await action();
      await onChanged();
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "The development action failed.");
    } finally {
      setWorking(false);
    }
  }

  async function showDiff(revision: HistoryRevision, index: number) {
    const prior = revisions[index + 1];
    if (!prior) return;
    setWorking(true);
    try {
      setDiff(await diffHistory(revision.history_revision_id, prior.history_revision_id));
      setDiffTitle("Revision diff");
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "The revision diff could not be loaded.");
    } finally {
      setWorking(false);
    }
  }

  async function showWorkspaceDiff() {
    setWorking(true);
    try {
      setDiff(await diffWorkspaceToBase(projectId));
      setDiffTitle("Workspace to base");
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "The workspace diff could not be loaded.");
    } finally {
      setWorking(false);
    }
  }

  async function promotionDecision(operation: "PROMOTE" | "SUPERSEDE" | "ROLLBACK_PROMOTE" | "WITHDRAW", bundle: ProcedureBundle) {
    const procedureId = bundleProcedureId(bundle);
    if (!procedureId) return;
    const registry = registries[procedureId];
    if (!registry) return;
    await perform(async () => {
      const next = await decidePromotion({
        procedure_id: procedureId,
        operation,
        digest: bundle.bundle_digest,
        expected_registry_revision: registry.catalog_entry.registry_revision,
        reason: reason.trim() || `${operation.toLowerCase()} ${shortDigest(bundle.bundle_digest)}`,
      });
      setRegistries((current) => ({ ...current, [procedureId]: next }));
    });
  }

  const disabled = busy || working;
  const promotedDigests = Object.values(registries)
    .map((item) => item.catalog_entry.current_bundle_digest)
    .filter((value): value is string => value !== null);

  async function resolveExternal(resolution: "RELOAD" | "KEEP_AS_NEW_CHANGE" | "THREE_WAY_MERGE") {
    setWorking(true);
    setExternalFeedback("");
    try {
      const changes: ExternalResourceChange[] = resolution === "RELOAD" ? [] : [{
        path: externalPath.trim(),
        content: externalContent,
        ...(externalBaseDigest.trim() ? { base_content_sha256: externalBaseDigest.trim() } : {}),
      }];
      await onExternalChanges(changes, resolution);
      setExternalFeedback(resolution === "RELOAD" ? "Workspace reloaded." : resolution === "KEEP_AS_NEW_CHANGE" ? "External content kept as a new workspace change." : "Three-way merge conflicts recorded.");
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "External change resolution failed.";
      setExternalFeedback(message);
      onError(message);
    } finally {
      setWorking(false);
    }
  }

  function changeExternalPath(path: string) {
    setExternalPath(path);
    setExternalBaseDigest(externalResourceAtPath(resources, path, casePolicy)?.content_sha256 ?? "");
    setExternalFeedback("");
  }

  return (
    <aside className="dev-activity" aria-label="History and release activity">
      <div className="dev-activity-tabs" role="tablist" aria-label="Activity views">
        <button type="button" role="tab" aria-selected={tab === "changes"} title="Changes" aria-label="Changes" onClick={() => setTab("changes")}><CodeXml aria-hidden="true" size={15} />{(conflicts.length > 0 || retainedImportOperation) && <span>{conflicts.length + (retainedImportOperation ? 1 : 0)}</span>}</button>
        <button type="button" role="tab" aria-selected={tab === "history"} title="History" aria-label="History" onClick={() => setTab("history")}><History aria-hidden="true" size={15} /></button>
        <button type="button" role="tab" aria-selected={tab === "release"} title="Bundles and promotion" aria-label="Bundles and promotion" onClick={() => setTab("release")}><PackageCheck aria-hidden="true" size={15} /></button>
        <button type="button" role="tab" aria-selected={tab === "presence"} title="Presence" aria-label="Presence" onClick={() => setTab("presence")}><Users aria-hidden="true" size={15} /><span>{presence.length}</span></button>
      </div>

      {tab === "changes" && (
        <div className="dev-activity-view" role="tabpanel">
          <div className="dev-panel-title"><h2>Changes</h2><small>workspace r{workspaceRevision}</small></div>
          {retainedImportOperation && (
            <section className="dev-external-change" aria-labelledby="dev-retained-import-title">
              <div><h3 id="dev-retained-import-title">Retained project import</h3><small>{retainedImportOperation.status.replaceAll("_", " ").toLowerCase()}</small></div>
              <strong>{retainedImportOperation.original_filename}</strong>
              <code title={retainedImportOperation.original_bytes_sha256}>{shortDigest(retainedImportOperation.original_bytes_sha256)}</code>
              {retainedImportOperation.conflict_paths.length > 0 && (
                <ul aria-label="Import conflict paths">
                  {retainedImportOperation.conflict_paths.map((path) => <li key={path}>{path}</li>)}
                </ul>
              )}
              <label>Discard reason<input value={importDiscardReason} maxLength={4096} disabled={!canMutate || disabled} onChange={(event) => setImportDiscardReason(event.target.value)} /></label>
              <div className="dev-row-actions">
                <button type="button" title="Apply the retained archive after conflicting workspace paths are reconciled" onClick={() => void perform(onApplyImport)} disabled={!canMutate || disabled || !["QUARANTINED", "CONFLICT"].includes(retainedImportOperation.status)}><UploadCloud aria-hidden="true" size={13} /> Apply retained import</button>
                <button type="button" onClick={() => void perform(async () => { await onDiscardImport(importDiscardReason.trim()); setImportDiscardReason(""); })} disabled={!canMutate || disabled || !importDiscardReason.trim() || !["QUARANTINED", "CONFLICT"].includes(retainedImportOperation.status)}><Trash2 aria-hidden="true" size={13} /> Discard retained import</button>
              </div>
            </section>
          )}
          <section className="dev-external-change" aria-labelledby="dev-external-change-title">
            <div><h3 id="dev-external-change-title">Detected external change</h3><small>local file watcher or import</small></div>
            <label>Path<input value={externalPath} placeholder="src/procedure.spell.py" maxLength={1024} disabled={!canMutate || disabled} onChange={(event) => changeExternalPath(event.target.value)} /></label>
            <label>Base SHA-256<input value={externalBaseDigest} placeholder={externalResource ? "required current digest" : "required for merge"} maxLength={64} required={externalResource !== null} aria-invalid={externalBaseDigest.length > 0 && !externalBaseDigestValid} disabled={!canMutate || disabled} onChange={(event) => { setExternalBaseDigest(event.target.value); setExternalFeedback(""); }} /></label>
            <label>Incoming content<textarea value={externalContent} maxLength={2_097_152} disabled={!canMutate || disabled} onChange={(event) => { setExternalContent(event.target.value); setExternalFeedback(""); }} /></label>
            <div className="dev-row-actions">
              <button type="button" onClick={() => void resolveExternal("RELOAD")} disabled={!canMutate || disabled}>Reload</button>
              <button type="button" onClick={() => void resolveExternal("KEEP_AS_NEW_CHANGE")} disabled={!canMutate || disabled || !externalPath.trim() || (externalResource !== null && !externalBaseDigestValid)}>Keep as new change</button>
              <button type="button" title={baseHistoryRevision ? "Record conflicts against the immutable base" : "Commit a base revision before merging"} onClick={() => void resolveExternal("THREE_WAY_MERGE")} disabled={!canMutate || disabled || !externalPath.trim() || !externalBaseDigestValid || !baseHistoryRevision}><WandSparkles aria-hidden="true" size={13} /> Three-way merge</button>
            </div>
            {externalFeedback && <p className={/CONFLICT|failed|invalid|reject/i.test(externalFeedback) ? "dev-action-error" : "dev-action-status"} role="status">{externalFeedback}</p>}
          </section>
          {conflicts.length === 0 ? <div className="dev-empty">No unresolved conflicts</div> : conflicts.map((conflict) => (
            <div key={conflict.conflict_id} className="dev-conflict-row">
              <div><strong>{conflict.path}</strong><span>{conflict.kind.replaceAll("_", " ")}</span></div>
              <code>{shortDigest(conflict.conflict_digest)}</code>
              <div className="dev-row-actions">
                <button type="button" onClick={() => void onResolveConflict(conflict, "OURS")} disabled={!canMutate || disabled}>Keep local</button>
                <button type="button" onClick={() => void onResolveConflict(conflict, "THEIRS")} disabled={!canMutate || disabled}>Take incoming</button>
                {conflict.kind === "TEXT" && <button type="button" onClick={() => void onResolveConflict(conflict, "MERGED", externalContent)} disabled={!canMutate || disabled}>Use merged content</button>}
                <button type="button" onClick={() => void onResolveConflict(conflict, "DELETE")} disabled={!canMutate || disabled}><Trash2 aria-hidden="true" size={13} /> Delete result</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === "history" && (
        <div className="dev-activity-view" role="tabpanel">
          <div className="dev-panel-title">
            <h2>Local history</h2>
            <small>{workspaceStatus ? `${workspaceStatus.change_count} changes / ${revisions.length} revisions` : `${revisions.length} revisions`}</small>
            <button type="button" title="Compare workspace with base" aria-label="Compare workspace with base" onClick={() => void showWorkspaceDiff()} disabled={disabled || !workspaceStatus?.base_history_revision_id}><GitCompareArrows aria-hidden="true" size={14} /></button>
          </div>
          <div className="dev-workspace-status" aria-label="Workspace change status">
            {!workspaceStatus ? <div className="dev-empty">Workspace status unavailable</div> : workspaceStatus.changes.length === 0 ? <div className="dev-empty">Workspace matches its immutable base</div> : workspaceStatus.changes.map((change) => (
              <label key={change.resource_id}>
                <input
                  type="checkbox"
                  checked={selectedChangeIds.includes(change.resource_id)}
                  onChange={(event) => setSelectedChangeIds((current) => event.target.checked
                    ? [...new Set([...current, change.resource_id])]
                    : current.filter((resourceId) => resourceId !== change.resource_id))}
                  disabled={!canMutate || disabled}
                />
                <strong>{change.status.replaceAll("_", " ")}</strong>
                <span>{change.path}</span>
              </label>
            ))}
          </div>
          <form
            className="dev-commit-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (!message.trim()) return;
              void perform(async () => {
                await commitHistory({ project_id: projectId, expected_workspace_revision: workspaceRevision, message: message.trim() });
                setMessage("");
                setSelectedChangeIds([]);
              });
            }}
          >
            <label htmlFor="dev-commit-message" className="sr-only">Commit message</label>
            <input id="dev-commit-message" value={message} placeholder="Commit message" maxLength={4096} onChange={(event) => setMessage(event.target.value)} disabled={!canMutate || disabled} />
            <button type="button" title="Commit selected changes" aria-label="Commit selected changes" disabled={!canMutate || disabled || !message.trim() || selectedChangeIds.length === 0} onClick={() => void perform(async () => {
              await commitSelectedHistory({ project_id: projectId, expected_workspace_revision: workspaceRevision, message: message.trim(), selected_resource_ids: selectedChangeIds });
              setMessage("");
              setSelectedChangeIds([]);
            })}><CheckCheck aria-hidden="true" size={14} /></button>
            <button type="submit" title="Commit all changes" aria-label="Commit all changes" disabled={!canMutate || disabled || !message.trim() || workspaceStatus?.clean !== false}><Save aria-hidden="true" size={14} /></button>
          </form>
          <div className="dev-history-list">
            {revisions.map((revision, index) => (
              <div key={revision.history_revision_id} className="dev-history-row">
                <div><strong>{revision.message}</strong><span><CircleUserRound aria-hidden="true" size={12} />{revision.author_subject}</span></div>
                <code title={revision.tree_digest}>{shortDigest(revision.tree_digest)}</code>
                <small><Clock3 aria-hidden="true" size={12} />{new Date(revision.created_at).toLocaleString()}</small>
                <div className="dev-row-actions">
                  <button type="button" title="Compare with prior revision" aria-label={`Compare revision ${revision.history_revision_id}`} onClick={() => void showDiff(revision, index)} disabled={disabled || index === revisions.length - 1}><GitCompareArrows aria-hidden="true" size={14} /></button>
                  <button type="button" title="Revert as a new change" aria-label={`Revert revision ${revision.history_revision_id}`} onClick={() => void perform(() => revertHistory(revision.history_revision_id, workspaceRevision, reason.trim() || "Revert selected revision"))} disabled={!canMutate || disabled}><RotateCcw aria-hidden="true" size={14} /></button>
                  <button type="button" title="Refresh clean workspace to this base" aria-label={`Refresh base to revision ${revision.history_revision_id}`} onClick={() => void perform(() => refreshHistoryBase({ project_id: projectId, history_revision_id: revision.history_revision_id, expected_workspace_revision: workspaceRevision }))} disabled={!canMutate || disabled || !workspaceStatus?.clean || workspaceStatus.base_history_revision_id === revision.history_revision_id}><RefreshCcw aria-hidden="true" size={14} /></button>
                  <button type="button" title="Approve history revision" aria-label={`Approve revision ${revision.history_revision_id}`} onClick={() => void perform(() => reviewHistory(revision.history_revision_id, revision.review_revision, reason.trim() || "Reviewed for bundle construction"))} disabled={!isAdmin || disabled || revision.author_subject === identity.subject || revision.review?.decision === "APPROVED"}><ShieldCheck aria-hidden="true" size={14} /></button>
                  <button type="button" title="Build candidate bundle" aria-label={`Build bundle from revision ${revision.history_revision_id}`} onClick={() => void perform(() => buildBundle(revision.history_revision_id))} disabled={!canMutate || disabled || revision.review?.decision !== "APPROVED"}><Archive aria-hidden="true" size={14} /></button>
                </div>
              </div>
            ))}
          </div>
          {diff && (
            <div className="dev-diff-view" aria-label="Revision diff">
              <div className="dev-panel-title"><h3>{diffTitle}</h3><button type="button" title="Close diff" aria-label="Close diff" onClick={() => setDiff(null)}><ChevronDown aria-hidden="true" size={14} /></button></div>
              {diff.changes.map((file) => <div key={`${file.status}-${file.path}`}><strong>{file.status} {file.path}</strong><small>{shortDigest(file.before_sha256)} to {shortDigest(file.after_sha256)}</small><pre>{file.patch || "Binary or metadata-only change"}</pre></div>)}
            </div>
          )}
        </div>
      )}

      {tab === "release" && (
        <div className="dev-activity-view" role="tabpanel">
          <div className="dev-panel-title"><h2>Bundles</h2><small>local simulator</small></div>
          <label className="dev-reason"><span>Decision reason</span><input value={reason} maxLength={4096} onChange={(event) => setReason(event.target.value)} /></label>
          <div className="dev-bundle-list">
            {bundles.length === 0 ? <div className="dev-empty">No candidate bundles</div> : bundles.map((bundle) => {
              const procedureId = bundleProcedureId(bundle);
              const registry = procedureId ? registries[procedureId] ?? null : null;
              const administrativeDecisionDisabled = !isAdmin || disabled || bundle.author_subject === identity.subject;
              return (
                <div key={bundle.bundle_digest} className="dev-bundle-row">
                  <div><strong>{bundle.state}</strong><code title={bundle.bundle_digest}>{shortDigest(bundle.bundle_digest)}</code></div>
                  <span>history {shortDigest(bundle.history_revision_id)}</span>
                  <small>{procedureId ? `${procedureId} / reviewed by ${bundle.review_subject}` : "invalid bundle procedure identity"}</small>
                  <div className="dev-row-actions">
                    <button type="button" title="Download immutable bundle" aria-label={`Download bundle ${bundle.bundle_digest}`} onClick={() => void downloadBundle(bundle.bundle_digest).then((blob) => saveBlob(blob, `${bundle.bundle_digest}.spell-bundle`)).catch((caught: unknown) => onError(caught instanceof Error ? caught.message : "Bundle download failed."))} disabled={disabled}><Download aria-hidden="true" size={14} /></button>
                    <button type="button" title="Approve candidate bundle" aria-label={`Approve bundle ${bundle.bundle_digest}`} onClick={() => void perform(() => approveBundle(bundle.bundle_digest, bundle.state_revision, reason.trim() || "Approve validated candidate"))} disabled={administrativeDecisionDisabled || !procedureId || !bundleStateAllowsDecision(bundle.state, "APPROVE")}><CheckCheck aria-hidden="true" size={14} /></button>
                    <button type="button" title="Promote to local simulator" aria-label={`Promote bundle ${bundle.bundle_digest}`} onClick={() => void promotionDecision("PROMOTE", bundle)} disabled={administrativeDecisionDisabled || !bundleCatalogAllowsDecision(bundle, registry, "PROMOTE")}><UploadCloud aria-hidden="true" size={14} /></button>
                    <button type="button" title="Supersede current promotion" aria-label={`Supersede bundle ${bundle.bundle_digest}`} onClick={() => void promotionDecision("SUPERSEDE", bundle)} disabled={administrativeDecisionDisabled || !bundleCatalogAllowsDecision(bundle, registry, "SUPERSEDE")}><Replace aria-hidden="true" size={14} /></button>
                    <button type="button" title="Rollback promote this digest" aria-label={`Rollback promote bundle ${bundle.bundle_digest}`} onClick={() => void promotionDecision("ROLLBACK_PROMOTE", bundle)} disabled={administrativeDecisionDisabled || !bundleCatalogAllowsDecision(bundle, registry, "ROLLBACK_PROMOTE")}><RotateCcw aria-hidden="true" size={14} /></button>
                    <button type="button" title="Withdraw bundle" aria-label={`Withdraw bundle ${bundle.bundle_digest}`} onClick={() => void promotionDecision("WITHDRAW", bundle)} disabled={administrativeDecisionDisabled || !bundleCatalogAllowsDecision(bundle, registry, "WITHDRAW")}><Trash2 aria-hidden="true" size={14} /></button>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="dev-runtime-admission">
            <strong>Runtime admission</strong>
            <span>{promotedDigests.length === 1 ? shortDigest(promotedDigests[0]) : promotedDigests.length > 1 ? `${promotedDigests.length} bundles promoted` : "No v0.9 bundle promoted"}</span>
            <small>v0.8 bundled simulator fixtures remain inherited</small>
          </div>
        </div>
      )}

      {tab === "presence" && (
        <div className="dev-activity-view" role="tabpanel">
          <div className="dev-panel-title"><h2>Presence</h2><small>advisory</small></div>
          <div className="dev-presence-list">
            {presence.length === 0 ? <div className="dev-empty">No active collaborators</div> : presence.map((record) => (
              <div key={record.presence_id} className="dev-presence-row">
                <CircleUserRound aria-hidden="true" size={15} />
                <div><strong>{record.subject}</strong><span>{record.status.toLowerCase()}</span></div>
                <small>{record.resource_id ? shortDigest(record.resource_id) : "project"}</small>
              </div>
            ))}
          </div>
        </div>
      )}
    </aside>
  );
}
