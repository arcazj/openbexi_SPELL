import { Ban, CircleAlert, Copy, Download, Eraser, Play, RefreshCcw, TriangleAlert } from "lucide-react";
import { useState } from "react";
import type { CheckScope, DevelopmentDiagnostic, ProjectResource, SemanticJob } from "./types";

interface ProblemsPanelProps {
  problems: DevelopmentDiagnostic[];
  activeJob: SemanticJob | null;
  selectedResource: Pick<ProjectResource, "kind"> | null;
  canMutate: boolean;
  busy: boolean;
  checkOnSave: boolean;
  onCheckOnSaveChange: (value: boolean) => void;
  onRun: (scope: CheckScope, reparseLibraries: boolean) => void;
  onCancel: () => void;
  onClean: () => void;
  onDownloadReport: () => void;
  onSelect: (diagnostic: DevelopmentDiagnostic) => void;
}

export function ProblemsPanel({
  problems,
  activeJob,
  selectedResource,
  canMutate,
  busy,
  checkOnSave,
  onCheckOnSaveChange,
  onRun,
  onCancel,
  onClean,
  onDownloadReport,
  onSelect,
}: ProblemsPanelProps) {
  const [scope, setScope] = useState<CheckScope>("PROJECT");
  const [reparseLibraries, setReparseLibraries] = useState(false);
  const running = activeJob?.state === "QUEUED" || activeJob?.state === "RUNNING" || activeJob?.state === "CANCEL_REQUESTED";
  const selectedIsFolder = selectedResource?.kind === "FOLDER" || selectedResource?.kind === "SOURCE_FOLDER";
  const scopeHasSelection = scope === "PROJECT" || scope === "CHANGED_SET"
    || (scope === "FOLDER" ? selectedIsFolder : Boolean(selectedResource && !selectedIsFolder));
  const errorCount = problems.filter((problem) => problem.severity === "ERROR").length;
  const warningCount = problems.filter((problem) => problem.severity === "WARNING").length;
  const reportAvailable = activeJob?.state === "COMPLETED"
    && /^[0-9a-f]{64}$/.test(activeJob.report_sha256 ?? "");

  function diagnosticText(problem: DevelopmentDiagnostic): string {
    return `${problem.severity} ${problem.code}: ${problem.message}\n${problem.source_path}:${problem.start_line}:${problem.start_column}-${problem.end_line}:${problem.end_column}\n${problem.remediation_ref}`.slice(0, 4096);
  }

  return (
    <section className="dev-problems" aria-labelledby="dev-problems-title">
      <div className="dev-panel-title dev-problems-titlebar">
        <h2 id="dev-problems-title">Problems</h2>
        <div className="dev-problem-counts" aria-label={`${errorCount} errors and ${warningCount} warnings`}>
          <span className="error"><CircleAlert aria-hidden="true" size={13} />{errorCount}</span>
          <span className="warning"><TriangleAlert aria-hidden="true" size={13} />{warningCount}</span>
        </div>
        <div className="dev-check-controls">
          <label><span>Scope</span><select aria-label="Check scope" value={scope} onChange={(event) => setScope(event.target.value as CheckScope)} disabled={busy || running}>
            <option value="FILE">File</option><option value="FOLDER">Folder</option><option value="PROJECT">Project</option><option value="CHANGED_SET">Changed set</option>
          </select></label>
          <label className="dev-check-toggle dev-reparse-toggle"><input type="checkbox" checked={reparseLibraries} onChange={(event) => setReparseLibraries(event.target.checked)} disabled={busy || running} />Reparse libraries</label>
          <label className="dev-check-toggle dev-check-on-save-toggle"><input type="checkbox" checked={checkOnSave} onChange={(event) => onCheckOnSaveChange(event.target.checked)} disabled={busy} />Check on save</label>
          {running ? (
            <button type="button" title="Cancel semantic check" aria-label="Cancel semantic check" onClick={onCancel} disabled={!canMutate || busy || activeJob?.state === "CANCEL_REQUESTED"}>
              <Ban aria-hidden="true" size={14} />
            </button>
          ) : (
            <button type="button" title="Run semantic check" aria-label="Run semantic check" onClick={() => onRun(scope, reparseLibraries)} disabled={!canMutate || busy || !scopeHasSelection}>
              <Play aria-hidden="true" size={14} />
            </button>
          )}
          <button type="button" title="Clean problem results" aria-label="Clean problem results" onClick={onClean} disabled={!canMutate || busy || running || problems.length === 0}>
            <Eraser aria-hidden="true" size={14} />
          </button>
          <button type="button" title="Download verified semantic report" aria-label="Download semantic report" onClick={onDownloadReport} disabled={busy || !reportAvailable}>
            <Download aria-hidden="true" size={14} />
          </button>
        </div>
      </div>
      {activeJob && (
        <div className="dev-check-progress" role="status">
          <RefreshCcw aria-hidden="true" size={13} className={running ? "spinning" : undefined} />
          <span>{activeJob.state.replaceAll("_", " ")}</span>
          <progress max={100} value={Math.max(0, Math.min(100, activeJob.progress))}>{activeJob.progress}%</progress>
          <small>{activeJob.progress}% / revision {activeJob.workspace_revision}</small>
        </div>
      )}
      <div className="dev-problem-table" {...(problems.length > 0 ? { role: "list", "aria-label": "Semantic diagnostics" } : {})}>
        {problems.length === 0 ? <div className="dev-empty" role="status">No durable problems for this workspace revision</div> : problems.map((problem) => (
          <div key={problem.diagnostic_id} role="listitem" className={`dev-problem-row ${problem.severity.toLowerCase()}`} title={diagnosticText(problem)}>
            <button type="button" className="dev-problem-target" onClick={() => onSelect(problem)} aria-label={`Open ${problem.code} at exact source span`}>
              {problem.severity === "ERROR" ? <CircleAlert aria-hidden="true" size={14} /> : <TriangleAlert aria-hidden="true" size={14} />}
              <code>{problem.code}</code>
              <span>{problem.message}</span>
              <small>{problem.source_path}:{problem.start_line}:{problem.start_column}-{problem.end_line}:{problem.end_column}</small>
            </button>
            <button type="button" className="dev-problem-copy" title="Copy bounded diagnostic" aria-label={`Copy ${problem.code} diagnostic`} onClick={() => void navigator.clipboard.writeText(diagnosticText(problem))}><Copy aria-hidden="true" size={13} /></button>
          </div>
        ))}
      </div>
    </section>
  );
}
