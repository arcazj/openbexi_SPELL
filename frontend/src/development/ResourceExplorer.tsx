import {
  Copy,
  Download,
  FileCode2,
  FileJson2,
  FilePlus2,
  Folder,
  FolderPlus,
  Move,
  Pencil,
  Plus,
  Info,
  LockKeyhole,
  LockKeyholeOpen,
  RefreshCcw,
  Settings2,
  Trash2,
  Upload,
} from "lucide-react";
import { useRef } from "react";
import type { ProjectResource } from "./types";

export type ExplorerCommand = "CREATE_PROCEDURE" | "CREATE_DICTIONARY" | "CREATE_FOLDER" | "COPY" | "RENAME" | "MOVE" | "DELETE";

interface ResourceExplorerProps {
  resources: ProjectResource[];
  selectedResourceId: string | null;
  canMutate: boolean;
  busy: boolean;
  projectClosed: boolean;
  onSelect: (resourceId: string) => void;
  onCommand: (command: ExplorerCommand) => void;
  onImport: (file: File) => void;
  onExport: () => void;
  onRefresh: () => void;
  onCreateProject: () => void;
  onProjectClosedChange: (closed: boolean) => void;
  onShowProperties: () => void;
  onShowManifest: () => void;
}

function resourceIcon(resource: ProjectResource) {
  if (resource.kind === "PROCEDURE") return <FileCode2 aria-hidden="true" size={14} />;
  if (resource.kind === "DICTIONARY") return <FileJson2 aria-hidden="true" size={14} />;
  return <Folder aria-hidden="true" size={14} />;
}

function resourceDepth(path: string): number {
  return Math.max(0, path.split("/").filter(Boolean).length - 1);
}

export function ResourceExplorer({
  resources,
  selectedResourceId,
  canMutate,
  busy,
  projectClosed,
  onSelect,
  onCommand,
  onImport,
  onExport,
  onRefresh,
  onCreateProject,
  onProjectClosedChange,
  onShowProperties,
  onShowManifest,
}: ResourceExplorerProps) {
  const fileInput = useRef<HTMLInputElement>(null);
  const hasSelection = resources.some((resource) => resource.resource_id === selectedResourceId);
  const sorted = [...resources].sort((left, right) => left.path.localeCompare(right.path));

  return (
    <aside className="dev-explorer" aria-label="Project explorer">
      <div className="dev-panel-title">
        <h2>Explorer</h2>
        <div className="dev-toolbar" aria-label="Project commands">
          <button type="button" title="Create project" aria-label="Create project" onClick={onCreateProject} disabled={!canMutate || busy}>
            <Plus aria-hidden="true" size={15} />
          </button>
          <button type="button" title="Refresh workspace" aria-label="Refresh workspace" onClick={onRefresh} disabled={busy}>
            <RefreshCcw aria-hidden="true" size={15} className={busy ? "spinning" : undefined} />
          </button>
          <button type="button" title="Project properties" aria-label="Project properties" onClick={onShowProperties} disabled={busy}><Info aria-hidden="true" size={15} /></button>
          <button type="button" title="Project manifest" aria-label="Project manifest" onClick={onShowManifest} disabled={busy}><Settings2 aria-hidden="true" size={15} /></button>
          <button type="button" title={projectClosed ? "Open project" : "Close project"} aria-label={projectClosed ? "Open project" : "Close project"} onClick={() => onProjectClosedChange(!projectClosed)} disabled={!canMutate || busy}>
            {projectClosed ? <LockKeyholeOpen aria-hidden="true" size={15} /> : <LockKeyhole aria-hidden="true" size={15} />}
          </button>
        </div>
      </div>
      <div className="dev-resource-tools" role="toolbar" aria-label="Resource commands">
        <button type="button" title="New procedure" aria-label="New procedure" onClick={() => onCommand("CREATE_PROCEDURE")} disabled={!canMutate || projectClosed || busy}>
          <FilePlus2 aria-hidden="true" size={15} />
        </button>
        <button type="button" title="New dictionary" aria-label="New dictionary" onClick={() => onCommand("CREATE_DICTIONARY")} disabled={!canMutate || projectClosed || busy}>
          <FileJson2 aria-hidden="true" size={15} />
        </button>
        <button type="button" title="New folder" aria-label="New folder" onClick={() => onCommand("CREATE_FOLDER")} disabled={!canMutate || projectClosed || busy}>
          <FolderPlus aria-hidden="true" size={15} />
        </button>
        <span className="dev-toolbar-separator" aria-hidden="true" />
        <button type="button" title="Rename resource" aria-label="Rename resource" onClick={() => onCommand("RENAME")} disabled={!canMutate || projectClosed || !hasSelection || busy}>
          <Pencil aria-hidden="true" size={15} />
        </button>
        <button type="button" title="Move resource" aria-label="Move resource" onClick={() => onCommand("MOVE")} disabled={!canMutate || projectClosed || !hasSelection || busy}>
          <Move aria-hidden="true" size={15} />
        </button>
        <button type="button" title="Copy resource" aria-label="Copy resource" onClick={() => onCommand("COPY")} disabled={!canMutate || projectClosed || !hasSelection || busy}>
          <Copy aria-hidden="true" size={15} />
        </button>
        <button type="button" title="Delete resource" aria-label="Delete resource" onClick={() => onCommand("DELETE")} disabled={!canMutate || projectClosed || !hasSelection || busy}>
          <Trash2 aria-hidden="true" size={15} />
        </button>
        <span className="dev-toolbar-separator" aria-hidden="true" />
        <button type="button" title="Import project archive" aria-label="Import project archive" onClick={() => fileInput.current?.click()} disabled={!canMutate || projectClosed || busy}>
          <Upload aria-hidden="true" size={15} />
        </button>
        <button type="button" title="Export project archive" aria-label="Export project archive" onClick={onExport} disabled={resources.length === 0 || busy}>
          <Download aria-hidden="true" size={15} />
        </button>
        <input
          ref={fileInput}
          type="file"
          aria-label="Project archive file"
          className="sr-only"
          accept=".zip,application/zip,application/vnd.openbexi.spell.project+zip"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) onImport(file);
            event.target.value = "";
          }}
        />
      </div>
      <div className="dev-resource-tree" role="tree" aria-label="Project resources">
        {sorted.length === 0 ? (
          <div className="dev-empty">No project resources</div>
        ) : sorted.map((resource) => (
          <button
            key={resource.resource_id}
            type="button"
            role="treeitem"
            aria-selected={resource.resource_id === selectedResourceId}
            className="dev-resource-row"
            style={{ paddingInlineStart: `${12 + Math.min(resourceDepth(resource.path), 6) * 14}px` }}
            onClick={() => onSelect(resource.resource_id)}
            title={resource.path}
          >
            {resourceIcon(resource)}
            <span>{resource.name}</span>
            {resource.revision > 0 && <small>r{resource.revision}</small>}
          </button>
        ))}
      </div>
    </aside>
  );
}
