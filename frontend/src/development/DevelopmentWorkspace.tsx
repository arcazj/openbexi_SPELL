import {
  Code2,
  FolderPlus,
  ListTree,
  ListChecks,
  PanelRight,
  Save,
  X,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  cancelSemanticCheck,
  cleanProblems,
  copyResource,
  createResource,
  deleteResource,
  applyImportOperation,
  discardImportOperation,
  downloadProjectFile,
  downloadSemanticReport,
  downloadSemanticReportFile,
  exportProject,
  getImportOperation,
  getProjectProperties,
  getSemanticCheck,
  getWorkspace,
  importProject,
  importOperationIdFromError,
  readResource,
  recordExternalChanges,
  resolveConflict,
  setProjectClosed,
  startSemanticCheck,
  updatePresence,
  updateProjectManifest,
  updateResource,
} from "./api";
import { ActivityPanel } from "./ActivityPanel";
import { CodeEditor } from "./CodeEditor";
import { ProblemsPanel } from "./ProblemsPanel";
import { ProjectManifestDialog } from "./ProjectManifestDialog";
import { ResourceExplorer, type ExplorerCommand } from "./ResourceExplorer";
import { CatalogBrowser, createEmptyDictionary, DictionaryEditor } from "./StructuredEditors";
import type {
  CheckScope,
  DevelopmentDiagnostic,
  DevelopmentIdentity,
  ExternalResourceChange,
  ImportOperation,
  ProjectResource,
  ProjectManifest,
  ProjectProperties,
  ProjectSummary,
  ProjectWorkspace,
  ResourceDocument,
  ResourceKind,
  SemanticJob,
  WorkspaceConflict,
} from "./types";

type MobilePanel = "explorer" | "editor" | "problems" | "activity";
type EditorMode = "source" | "dictionary" | "catalog";
type DialogState =
  | { type: "PROJECT"; value: string; casePolicy: ProjectSummary["case_policy"] }
  | { type: ExplorerCommand; value: string; dictionaryFormat?: "DB" | "IMP" }
  | null;

interface DevelopmentWorkspaceProps {
  identity: DevelopmentIdentity;
  selectedProjectId: string | null;
  onCreateProject: (name: string, casePolicy: ProjectSummary["case_policy"]) => Promise<void>;
  onProjectsChanged: () => Promise<void>;
  onDirtyChange: (dirty: boolean) => void;
  onError: (message: string | null) => void;
}

function dictionaryId(path: string): string {
  const name = path.split("/").pop()?.replace(/\.(?:db|imp)$/i, "") ?? "dictionary";
  const sanitized = name.normalize("NFKD").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[^A-Za-z0-9]+/, "").slice(0, 128);
  return sanitized || "dictionary";
}

async function templateFor(kind: ResourceKind, path: string, dictionaryFormat: "DB" | "IMP" = "DB"): Promise<{ content: string; mediaType: string }> {
  const name = path.split("/").pop()?.replace(/\.spell\.py$/i, "").replace(/\.[^.]+$/, "") || "Procedure";
  if (kind === "DICTIONARY") {
    return createEmptyDictionary(dictionaryId(path), dictionaryFormat);
  }
  if (kind !== "PROCEDURE") return { content: "", mediaType: "application/x-directory" };
  const procedureId = name.replace(/[^A-Za-z0-9_.-]+/g, "_").replace(/^[^A-Za-z0-9]+/, "").slice(0, 64) || "procedure";
  return { content: [
    `# @procedure ${procedureId}`,
    `# @display-name ${name.replaceAll("_", " ")}`,
    "# @description Local simulator procedure",
    "# @language-profile spell-restricted-ast/0.9",
    "",
    `"""${name.replaceAll("_", " ")} local simulator procedure."""`,
    "Log('Procedure ready')",
    "",
  ].join("\n"), mediaType: "text/x-python" };
}

function defaultPath(command: ExplorerCommand, selected: ProjectResource | null): string {
  const parent = selected?.kind === "FOLDER" || selected?.kind === "SOURCE_FOLDER"
    ? selected.path
    : selected?.parent_path ?? "src";
  if (command === "CREATE_FOLDER") return `${parent}/new-folder`;
  if (command === "CREATE_DICTIONARY") return `${parent}/dictionary.db`;
  if (command === "CREATE_PROCEDURE") return `${parent}/procedure.spell.py`;
  if (command === "COPY") {
    const path = selected?.path ?? "src/resource";
    const dot = path.lastIndexOf(".");
    return dot > path.lastIndexOf("/") ? `${path.slice(0, dot)}-copy${path.slice(dot)}` : `${path}-copy`;
  }
  return selected?.path ?? "";
}

function clientInstanceId(): string {
  const key = "openbexi.spell.development-client-instance";
  const existing = window.sessionStorage.getItem(key);
  if (existing) return existing;
  const created = crypto.randomUUID();
  window.sessionStorage.setItem(key, created);
  return created;
}

function importOperationStorageKey(projectId: string): string {
  return `openbexi.spell.import-operation:${projectId}`;
}

function rememberImportOperation(projectId: string, operationId: string | null): void {
  const key = importOperationStorageKey(projectId);
  if (operationId) window.sessionStorage.setItem(key, operationId);
  else window.sessionStorage.removeItem(key);
}

function importOperationIsOpen(operation: ImportOperation): boolean {
  return ["QUARANTINED", "APPLYING", "CONFLICT"].includes(operation.status);
}

export function displayedSemanticJob(jobs: SemanticJob[], workspaceRevision: number): SemanticJob | null {
  const newest = (candidates: SemanticJob[]) => candidates.sort((left, right) => {
    const leftTime = left.completed_at ?? left.started_at ?? left.created_at ?? "";
    const rightTime = right.completed_at ?? right.started_at ?? right.created_at ?? "";
    if (leftTime !== rightTime) return leftTime < rightTime ? 1 : -1;
    return left.job_id < right.job_id ? 1 : left.job_id === right.job_id ? 0 : -1;
  })[0] ?? null;
  return newest(jobs.filter((job) => ["QUEUED", "RUNNING", "CANCEL_REQUESTED"].includes(job.state)))
    ?? newest(jobs.filter((job) => job.workspace_revision === workspaceRevision));
}

export function DevelopmentWorkspace({
  identity,
  selectedProjectId,
  onCreateProject,
  onProjectsChanged,
  onDirtyChange,
  onError,
}: DevelopmentWorkspaceProps) {
  const [workspace, setWorkspace] = useState<ProjectWorkspace | null>(null);
  const [selectedResourceId, setSelectedResourceId] = useState<string | null>(null);
  const [document, setDocument] = useState<ResourceDocument | null>(null);
  const [content, setContent] = useState("");
  const [mediaType, setMediaType] = useState("");
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [editorMode, setEditorMode] = useState<EditorMode>("source");
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>("editor");
  const [dialog, setDialog] = useState<DialogState>(null);
  const [checkOnSave, setCheckOnSave] = useState(true);
  const [activeJob, setActiveJob] = useState<SemanticJob | null>(null);
  const [navigationTarget, setNavigationTarget] = useState<{ key: string; line: number; column: number } | null>(null);
  const [insertRequest, setInsertRequest] = useState<{ key: string; value: string } | null>(null);
  const [properties, setProperties] = useState<ProjectProperties | null>(null);
  const [manifestOpen, setManifestOpen] = useState(false);
  const [retainedImportOperation, setRetainedImportOperation] = useState<ImportOperation | null>(null);
  const checkTimerRef = useRef<number | null>(null);
  const activeJobRef = useRef<SemanticJob | null>(null);

  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);
  const canMutate = identity.role === "operator";
  const canAuthor = canMutate && !workspace?.project.closed;

  useEffect(() => { activeJobRef.current = activeJob; }, [activeJob]);

  useEffect(() => () => {
    if (checkTimerRef.current !== null) window.clearTimeout(checkTimerRef.current);
  }, []);

  const selectedResource = useMemo(
    () => workspace?.resources.find((resource) => resource.resource_id === selectedResourceId) ?? null,
    [selectedResourceId, workspace?.resources],
  );

  const loadWorkspace = useCallback(async (projectId = selectedProjectId) => {
    if (!projectId) {
      setWorkspace(null);
      setDocument(null);
      setSelectedResourceId(null);
      return;
    }
    setLoading(true);
    try {
      const next = await getWorkspace(projectId);
      setWorkspace(next);
      setActiveJob(displayedSemanticJob(next.jobs, next.workspace_revision));
      if (!next.resources.some((resource) => resource.kind === "PROCEDURE" || resource.kind === "DICTIONARY")) {
        setMobilePanel("explorer");
      }
      setSelectedResourceId((current) => {
        if (current && next.resources.some((resource) => resource.resource_id === current)) return current;
        return next.resources.find((resource) => resource.kind === "PROCEDURE")?.resource_id
          ?? next.resources.find((resource) => resource.kind === "DICTIONARY")?.resource_id
          ?? null;
      });
      onError(null);
    } catch (caught) {
      setWorkspace(null);
      onError(caught instanceof Error ? caught.message : "The project workspace could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [onError, selectedProjectId]);

  useEffect(() => {
    setSelectedResourceId(null);
    setDocument(null);
    setDirty(false);
    void loadWorkspace(selectedProjectId);
  }, [selectedProjectId, loadWorkspace]);

  useEffect(() => {
    setRetainedImportOperation(null);
    if (!selectedProjectId) return;
    const operationId = window.sessionStorage.getItem(importOperationStorageKey(selectedProjectId));
    if (!operationId) return;
    let cancelled = false;
    void getImportOperation(selectedProjectId, operationId)
      .then((operation) => {
        if (cancelled) return;
        if (importOperationIsOpen(operation)) setRetainedImportOperation(operation);
        else rememberImportOperation(selectedProjectId, null);
      })
      .catch(() => { if (!cancelled) rememberImportOperation(selectedProjectId, null); });
    return () => { cancelled = true; };
  }, [selectedProjectId]);

  useEffect(() => {
    let cancelled = false;
    if (dirty) return;
    if (!selectedProjectId || !selectedResourceId || selectedResource?.kind === "FOLDER" || selectedResource?.kind === "SOURCE_FOLDER") {
      setDocument(null);
      setContent("");
      setDirty(false);
      return;
    }
    setLoading(true);
    void readResource(selectedProjectId, selectedResourceId)
      .then((next) => {
        if (cancelled) return;
        setDocument(next);
        setContent(next.content);
        setMediaType(next.media_type);
        setDirty(false);
        setEditorMode(next.kind === "DICTIONARY" ? "dictionary" : "source");
      })
      .catch((caught: unknown) => { if (!cancelled) onError(caught instanceof Error ? caught.message : "The resource could not be opened."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [dirty, onError, selectedProjectId, selectedResource?.kind, selectedResourceId, workspace?.workspace_revision]);

  useEffect(() => {
    if (!selectedProjectId || !workspace || !canAuthor) return;
    let cancelled = false;
    const record = () => updatePresence({
      project_id: selectedProjectId,
      ...(selectedResourceId ? { resource_id: selectedResourceId } : {}),
      client_instance_id: clientInstanceId(),
      status: dirty ? "EDITING" : "VIEWING",
      expected_workspace_revision: workspace.workspace_revision,
    }).catch(() => undefined);
    void record();
    const timer = window.setInterval(() => { if (!cancelled) void record(); }, 30_000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [canAuthor, dirty, selectedProjectId, selectedResourceId, workspace?.workspace_revision]);

  useEffect(() => {
    if (!activeJob || !["QUEUED", "RUNNING", "CANCEL_REQUESTED"].includes(activeJob.state)) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void getSemanticCheck(activeJob.job_id).then((next) => {
        if (cancelled) return;
        setActiveJob(next);
        if (["COMPLETED", "FAILED", "CANCELLED"].includes(next.state)) void loadWorkspace();
      }).catch((caught: unknown) => {
        if (!cancelled) onError(caught instanceof Error ? caught.message : "Semantic check status could not be refreshed.");
      });
    }, 800);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [activeJob?.job_id, activeJob?.state, loadWorkspace, onError]);

  async function perform(action: () => Promise<unknown>, refresh = true) {
    setBusy(true);
    try {
      await action();
      if (refresh) await loadWorkspace();
      onError(null);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "The workspace action failed.");
    } finally {
      setBusy(false);
    }
  }

  async function importArchive(file: File) {
    if (!selectedProjectId || !workspace || !canAuthor) return;
    setBusy(true);
    try {
      await importProject({
        project_id: selectedProjectId,
        file,
        expected_workspace_revision: workspace.workspace_revision,
      });
      await loadWorkspace();
      onError(null);
    } catch (caught) {
      const operationId = importOperationIdFromError(caught);
      if (operationId) {
        rememberImportOperation(selectedProjectId, operationId);
        try {
          setRetainedImportOperation(await getImportOperation(selectedProjectId, operationId));
          setMobilePanel("activity");
        } catch {
          // The durable identifier is recovered on the next workspace load.
        }
      }
      onError(caught instanceof Error ? caught.message : "The project archive could not be imported.");
    } finally {
      setBusy(false);
    }
  }

  function scheduleCheckOnSave(projectId: string, path: string, workspaceRevision: number) {
    if (checkTimerRef.current !== null) window.clearTimeout(checkTimerRef.current);
    checkTimerRef.current = window.setTimeout(() => {
      checkTimerRef.current = null;
      void (async () => {
        try {
          const previous = activeJobRef.current;
          if (previous && ["QUEUED", "RUNNING", "CANCEL_REQUESTED"].includes(previous.state)) {
            await cancelSemanticCheck(previous.job_id);
          }
          const job = await startSemanticCheck({
            project_id: projectId,
            scope: "FILE",
            scope_path: path,
            expected_workspace_revision: workspaceRevision,
          });
          setActiveJob(job);
        } catch (caught) {
          onError(caught instanceof Error ? caught.message : "The check-on-save job could not be started.");
        }
      })();
    }, 600);
  }

  async function saveDocument() {
    if (!selectedProjectId || !workspace || !document || !dirty || !canAuthor) return;
    setBusy(true);
    try {
      const result = await updateResource({
        project_id: selectedProjectId,
        resource_id: document.resource_id,
        content,
        media_type: mediaType || document.media_type,
        expected_workspace_revision: workspace.workspace_revision,
      });
      setDirty(false);
      await loadWorkspace();
      if (checkOnSave) {
        scheduleCheckOnSave(selectedProjectId, document.path, result.workspace_revision);
      }
      onError(null);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "The resource could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  function openCommand(command: ExplorerCommand) {
    if (command === "DELETE") {
      setDialog({ type: command, value: selectedResource?.path ?? "" });
      return;
    }
    setDialog({ type: command, value: defaultPath(command, selectedResource), ...(command === "CREATE_DICTIONARY" ? { dictionaryFormat: "DB" as const } : {}) });
  }

  async function submitDialog(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dialog) return;
    if (dialog.type === "PROJECT") {
      const current = dialog;
      setDialog(null);
      await perform(() => onCreateProject(current.value.trim(), current.casePolicy), false);
      return;
    }
    if (!selectedProjectId || !workspace) return;
    const current = dialog;
    setDialog(null);
    if (current.type === "DELETE" && selectedResource) {
      await perform(() => deleteResource(selectedProjectId, selectedResource.resource_id, workspace.workspace_revision));
      setDocument(null);
      setSelectedResourceId(null);
      return;
    }
    if ((current.type === "RENAME" || current.type === "MOVE") && selectedResource) {
      await perform(() => updateResource({
        project_id: selectedProjectId,
        resource_id: selectedResource.resource_id,
        path: current.value.trim(),
        expected_workspace_revision: workspace.workspace_revision,
      }));
      return;
    }
    if (current.type === "COPY" && selectedResource) {
      await perform(() => copyResource({
        project_id: selectedProjectId,
        resource_id: selectedResource.resource_id,
        destination_path: current.value.trim(),
        expected_workspace_revision: workspace.workspace_revision,
      }));
      return;
    }
    const kind: ResourceKind = current.type === "CREATE_FOLDER" ? "FOLDER" : current.type === "CREATE_DICTIONARY" ? "DICTIONARY" : "PROCEDURE";
    const path = current.value.trim();
    const template = await templateFor(kind, path, current.dictionaryFormat);
    await perform(() => createResource({
      project_id: selectedProjectId,
      path,
      kind,
      media_type: template.mediaType,
      content: template.content,
      expected_workspace_revision: workspace.workspace_revision,
    }));
  }

  async function runCheck(scope: CheckScope, reparseLibraries: boolean) {
    if (!selectedProjectId || !workspace) return;
    const selectedIsFolder = selectedResource?.kind === "FOLDER" || selectedResource?.kind === "SOURCE_FOLDER";
    const scopePath = scope === "FOLDER"
      ? (selectedIsFolder ? selectedResource.path : null)
      : scope === "FILE"
        ? (selectedResource && !selectedIsFolder ? selectedResource.path : null)
        : null;
    if ((scope === "FILE" || scope === "FOLDER") && !scopePath) return;
    await perform(async () => {
      const job = await startSemanticCheck({
        project_id: selectedProjectId,
        scope,
        ...(scopePath ? { scope_path: scopePath } : {}),
        expected_workspace_revision: workspace.workspace_revision,
        reparse_libraries: reparseLibraries,
      });
      setActiveJob(job);
    }, false);
  }

  async function navigateToProblem(problem: DevelopmentDiagnostic) {
    const resource = workspace?.resources.find((candidate) => candidate.path === problem.source_path);
    if (resource && selectResource(resource.resource_id)) {
      setEditorMode("source");
      setNavigationTarget({ key: `${problem.diagnostic_id}-${Date.now()}`, line: problem.start_line, column: problem.start_column });
    }
  }

  function selectResource(resourceId: string): boolean {
    if (resourceId !== selectedResourceId && dirty && !window.confirm("Discard unsaved changes to this resource?")) {
      return false;
    }
    if (resourceId !== selectedResourceId) setDirty(false);
    setSelectedResourceId(resourceId);
    setMobilePanel("editor");
    return true;
  }

  async function changeProjectClosed(closed: boolean) {
    if (!selectedProjectId || !workspace || !canMutate) return;
    await perform(async () => {
      await setProjectClosed(selectedProjectId, closed, workspace.workspace_revision);
      await onProjectsChanged();
    });
  }

  async function showProperties() {
    if (!selectedProjectId) return;
    setBusy(true);
    try {
      setProperties(await getProjectProperties(selectedProjectId));
      onError(null);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "Project properties could not be loaded.");
    } finally {
      setBusy(false);
    }
  }

  async function saveManifest(manifest: ProjectManifest) {
    if (!selectedProjectId || !workspace || !canAuthor) return;
    setBusy(true);
    try {
      await updateProjectManifest({
        project_id: selectedProjectId,
        manifest,
        expected_workspace_revision: workspace.workspace_revision,
      });
      setManifestOpen(false);
      await Promise.all([loadWorkspace(), onProjectsChanged()]);
      onError(null);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "The project manifest could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  const baseHistoryRevision = workspace?.history.find((revision) => revision.history_revision_id === workspace.project.base_history_revision_id) ?? null;

  if (!selectedProjectId || !workspace) {
    return (
      <main className="dev-no-project">
        <FolderPlus aria-hidden="true" size={30} />
        <h1>{loading ? "Loading projects" : "No project selected"}</h1>
        {!loading && canMutate && <button type="button" className="dev-primary-command" onClick={() => setDialog({ type: "PROJECT", value: "", casePolicy: "CASE_SENSITIVE" })}>Create project</button>}
        {dialog?.type === "PROJECT" && <DevelopmentDialog state={dialog} onChange={setDialog} onCancel={() => setDialog(null)} onSubmit={submitDialog} />}
      </main>
    );
  }

  return (
    <main className="dev-workspace" data-mobile-panel={mobilePanel} data-workspace-revision={workspace.workspace_revision} aria-busy={loading || busy}>
      <ResourceExplorer
        resources={workspace.resources}
        selectedResourceId={selectedResourceId}
        canMutate={canMutate}
        projectClosed={workspace.project.closed}
        busy={loading || busy}
        onSelect={selectResource}
        onCommand={openCommand}
        onImport={(file) => void importArchive(file)}
        onExport={() => void perform(async () => downloadProjectFile(await exportProject(selectedProjectId, workspace.workspace_revision)), false)}
        onRefresh={() => void loadWorkspace()}
        onCreateProject={() => setDialog({ type: "PROJECT", value: "", casePolicy: "CASE_SENSITIVE" })}
        onProjectClosedChange={(closed) => void changeProjectClosed(closed)}
        onShowProperties={() => void showProperties()}
        onShowManifest={() => setManifestOpen(true)}
      />
      <div className="dev-center">
        <div className="dev-authoring">
          {document ? (
            <>
              <div className="dev-authoring-tabs" role="tablist" aria-label="Authoring views">
                <button type="button" role="tab" aria-selected={editorMode === "source"} onClick={() => setEditorMode("source")}><Code2 aria-hidden="true" size={14} />Source</button>
                <button type="button" role="tab" aria-selected={editorMode === "dictionary"} onClick={() => setEditorMode("dictionary")}>Dictionary</button>
                <button type="button" role="tab" aria-selected={editorMode === "catalog"} onClick={() => setEditorMode("catalog")}>Catalog</button>
              </div>
              {editorMode === "source" ? (
                <CodeEditor
                  document={document}
                  content={content}
                  dirty={dirty}
                  canEdit={canAuthor}
                  saving={busy}
                  catalogEntries={workspace.pinned_catalog_entries}
                  diagnostics={workspace.problems.filter((problem) => problem.source_path === document.path)}
                  insertRequest={insertRequest}
                  navigationTarget={navigationTarget}
                  onChange={(value) => { setContent(value); setDirty(value !== document.content); }}
                  onSave={() => void saveDocument()}
                />
              ) : (
                <div className="dev-structured-shell">
                   <div className="dev-structured-toolbar"><strong>{document.path}</strong><button type="button" title="Save resource" aria-label="Save resource" onClick={() => void saveDocument()} disabled={!canAuthor || !dirty || busy}><Save aria-hidden="true" size={15} /></button></div>
                   {editorMode === "dictionary"
                     ? <DictionaryEditor content={content} canEdit={canAuthor && document.kind === "DICTIONARY"} onMediaTypeChange={setMediaType} onChange={(value) => { setContent(value); setDirty(value !== document.content); }} />
                     : <CatalogBrowser entries={workspace.pinned_catalog_entries} canInsert={canAuthor && document.kind === "PROCEDURE"} onInsert={(value) => { setEditorMode("source"); setInsertRequest({ key: crypto.randomUUID(), value }); }} />}
                </div>
              )}
            </>
          ) : <div className="dev-empty-editor"><Code2 aria-hidden="true" size={24} /><span>Select a procedure or dictionary</span></div>}
        </div>
        <ProblemsPanel
          problems={workspace.problems}
          activeJob={activeJob}
          selectedResource={selectedResource}
          canMutate={canAuthor}
          busy={loading || busy}
          checkOnSave={checkOnSave}
          onCheckOnSaveChange={setCheckOnSave}
          onRun={(scope, reparse) => void runCheck(scope, reparse)}
          onCancel={() => { if (activeJob) void perform(async () => setActiveJob(await cancelSemanticCheck(activeJob.job_id)), false); }}
          onClean={() => void perform(() => cleanProblems(selectedProjectId, workspace.workspace_revision))}
          onDownloadReport={() => {
            if (!activeJob?.report_sha256) return;
            void perform(async () => downloadSemanticReportFile(
              activeJob.job_id,
              await downloadSemanticReport(activeJob.job_id, activeJob.report_sha256 ?? ""),
            ), false);
          }}
          onSelect={(problem) => void navigateToProblem(problem)}
        />
      </div>
      <ActivityPanel
        projectId={selectedProjectId}
        identity={identity}
        resources={workspace.resources}
        casePolicy={workspace.project.case_policy}
        workspaceRevision={workspace.workspace_revision}
        baseHistoryRevision={baseHistoryRevision}
        history={workspace.history}
        conflicts={workspace.conflicts}
        bundles={workspace.bundles}
        presence={workspace.presence}
        canMutate={canAuthor}
        busy={busy}
        retainedImportOperation={retainedImportOperation}
        onChanged={async () => loadWorkspace()}
        onApplyImport={async () => {
          if (!retainedImportOperation) return;
          await applyImportOperation({
            project_id: selectedProjectId,
            operation_id: retainedImportOperation.operation_id,
            expected_workspace_revision: workspace.workspace_revision,
          });
          rememberImportOperation(selectedProjectId, null);
          setRetainedImportOperation(null);
        }}
        onDiscardImport={async (reason) => {
          if (!retainedImportOperation) return;
          await discardImportOperation({
            project_id: selectedProjectId,
            operation_id: retainedImportOperation.operation_id,
            expected_workspace_revision: workspace.workspace_revision,
            reason,
          });
          rememberImportOperation(selectedProjectId, null);
          setRetainedImportOperation(null);
        }}
        onResolveConflict={async (conflict: WorkspaceConflict, resolution, resolvedContent) => {
          await perform(() => resolveConflict({ project_id: selectedProjectId, conflict, resolution, ...(resolution === "MERGED" ? { resolved_content: resolvedContent ?? "" } : {}), expected_workspace_revision: workspace.workspace_revision }));
        }}
        onExternalChanges={async (changes: ExternalResourceChange[], resolution) => {
          await recordExternalChanges({
            project_id: selectedProjectId,
            base_workspace_revision: resolution === "THREE_WAY_MERGE" && baseHistoryRevision ? baseHistoryRevision.workspace_revision : workspace.workspace_revision,
            ...(resolution === "THREE_WAY_MERGE" && baseHistoryRevision ? { base_history_revision_id: baseHistoryRevision.history_revision_id } : {}),
            changes,
            resolution,
          });
          await loadWorkspace();
        }}
        onError={(message) => onError(message)}
      />
      <nav className="dev-mobile-nav" aria-label="Development areas">
        {([
          ["explorer", "Explorer", ListTree],
          ["editor", "Editor", Code2],
          ["problems", "Problems", ListChecks],
          ["activity", "Activity", PanelRight],
        ] as const).map(([panel, label, Icon]) => (
          <button key={panel} type="button" aria-current={mobilePanel === panel ? "page" : undefined} onClick={() => setMobilePanel(panel)}><Icon aria-hidden="true" size={16} /><span>{label}</span></button>
        ))}
      </nav>
      {dialog && <DevelopmentDialog state={dialog} onChange={setDialog} onCancel={() => setDialog(null)} onSubmit={submitDialog} />}
      {properties && <PropertiesDialog properties={properties} resource={selectedResource} onClose={() => setProperties(null)} />}
      {manifestOpen && (
        <ProjectManifestDialog
          project={workspace.project}
          folderPaths={workspace.resources.filter((resource) => resource.kind === "SOURCE_FOLDER" || resource.kind === "FOLDER").map((resource) => resource.path)}
          canEdit={canAuthor}
          busy={busy}
          onClose={() => setManifestOpen(false)}
          onSave={saveManifest}
        />
      )}
    </main>
  );
}

interface DevelopmentDialogProps {
  state: Exclude<DialogState, null>;
  onChange: (value: Exclude<DialogState, null>) => void;
  onCancel: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

function dialogTitle(state: Exclude<DialogState, null>): string {
  if (state.type === "PROJECT") return "Create project";
  return state.type.replaceAll("_", " ").toLowerCase().replace(/^./, (value) => value.toUpperCase());
}

function DevelopmentDialog({ state, onChange, onCancel, onSubmit }: DevelopmentDialogProps) {
  const deleting = state.type === "DELETE";
  return (
    <div className="dev-modal-backdrop">
      <form className="dev-dialog" role="dialog" aria-modal="true" aria-labelledby="dev-dialog-title" onSubmit={onSubmit}>
        <div className="dev-panel-title"><h2 id="dev-dialog-title">{dialogTitle(state)}</h2><button type="button" title="Close" aria-label="Close" onClick={onCancel}><X aria-hidden="true" size={15} /></button></div>
        {deleting ? (
          <p>Delete <strong>{state.value}</strong> from this workspace revision?</p>
        ) : (
          <label>{state.type === "PROJECT" ? "Project name" : "Project-relative path"}<input autoFocus value={state.value} onChange={(event) => onChange({ ...state, value: event.target.value })} required maxLength={512} /></label>
        )}
        {state.type === "PROJECT" && (
          <label>Filename case policy<select value={state.casePolicy} onChange={(event) => onChange({ ...state, casePolicy: event.target.value as ProjectSummary["case_policy"] })}><option value="CASE_SENSITIVE">Case sensitive</option><option value="CASE_INSENSITIVE">Case insensitive</option></select></label>
        )}
        {state.type === "CREATE_DICTIONARY" && (
          <label>Dictionary exchange format<select value={state.dictionaryFormat ?? "DB"} onChange={(event) => {
            const dictionaryFormat = event.target.value as "DB" | "IMP";
            onChange({ ...state, dictionaryFormat, value: state.value.replace(/\.(?:db|imp)$/i, dictionaryFormat === "DB" ? ".db" : ".imp") });
          }}><option value="DB">DB snapshot</option><option value="IMP">IMP change set</option></select></label>
        )}
        <div className="dev-dialog-actions"><button type="button" onClick={onCancel}>Cancel</button><button type="submit" className={deleting ? "danger" : "primary"}>{deleting ? "Delete" : "Apply"}</button></div>
      </form>
    </div>
  );
}

function PropertiesDialog({ properties, resource, onClose }: { properties: ProjectProperties; resource: ProjectResource | null; onClose: () => void }) {
  return (
    <div className="dev-modal-backdrop">
      <section className="dev-dialog dev-properties" role="dialog" aria-modal="true" aria-labelledby="dev-properties-title">
        <div className="dev-panel-title"><h2 id="dev-properties-title">Properties</h2><button type="button" title="Close" aria-label="Close properties" onClick={onClose}><X aria-hidden="true" size={15} /></button></div>
        <dl>
          <dt>Project</dt><dd>{properties.project.display_name}</dd>
          <dt>Project ID</dt><dd><code>{properties.project.project_id}</code></dd>
          <dt>Workspace revision</dt><dd>{properties.project.workspace_revision}</dd>
          <dt>Case policy</dt><dd>{properties.project.case_policy}</dd>
          <dt>Lifecycle</dt><dd>{properties.project.closed ? "Closed" : "Open"}</dd>
          <dt>Resource bytes</dt><dd>{properties.byte_length.toLocaleString()}</dd>
          <dt>Resource counts</dt><dd><code>{JSON.stringify(properties.resource_counts)}</code></dd>
          {resource && <>
            <dt>Selected resource</dt><dd>{resource.path}</dd>
            <dt>Resource ID</dt><dd><code>{resource.resource_id}</code></dd>
            <dt>Kind / media</dt><dd>{resource.kind} / {resource.media_type}</dd>
            <dt>Content SHA-256</dt><dd><code>{resource.content_sha256}</code></dd>
            <dt>Revision / bytes</dt><dd>{resource.revision} / {resource.byte_length.toLocaleString()}</dd>
          </>}
        </dl>
      </section>
    </div>
  );
}
