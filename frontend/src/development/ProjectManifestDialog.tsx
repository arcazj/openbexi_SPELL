import { Plus, Trash2, X } from "lucide-react";
import { FormEvent, useState } from "react";
import type { ProjectCatalogDependency, ProjectManifest, ProjectSummary } from "./types";

interface ProjectManifestDialogProps {
  project: ProjectSummary;
  folderPaths: string[];
  canEdit: boolean;
  busy: boolean;
  onClose: () => void;
  onSave: (manifest: ProjectManifest) => Promise<void>;
}

function exactManifest(project: ProjectSummary): ProjectManifest {
  const supplied = project.manifest as Partial<ProjectManifest>;
  return {
    schema_version: "spell.project/0.9",
    project_id: project.project_id,
    display_name: project.display_name,
    language_profile: "spell-restricted-ast/0.9",
    source_roots: Array.isArray(supplied.source_roots) && supplied.source_roots.length > 0 ? [...supplied.source_roots] : ["src"],
    case_policy: project.case_policy,
    catalog_dependencies: Array.isArray(supplied.catalog_dependencies)
      ? supplied.catalog_dependencies.map((item) => ({ ...item }))
      : [],
    owners: Array.isArray(supplied.owners) && supplied.owners.length > 0 ? [...supplied.owners] : [project.owner_subject],
    policy_labels: Array.isArray(supplied.policy_labels) && supplied.policy_labels.length > 0
      ? [...supplied.policy_labels]
      : ["LOCAL_SYNTHETIC_NON_CUI_ONLY"],
  };
}

function trimNonempty(values: string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean);
}

interface StringRowsProps {
  legend: string;
  singular: string;
  values: string[];
  disabled: boolean;
  listId?: string;
  onChange: (values: string[]) => void;
}

function StringRows({ legend, singular, values, disabled, listId, onChange }: StringRowsProps) {
  return (
    <fieldset className="dev-manifest-group">
      <legend>{legend}</legend>
      {values.map((value, index) => (
        <div className="dev-manifest-row" key={`${singular}-${index}`}>
          <label>
            <span className="sr-only">{singular} {index + 1}</span>
            <input
              aria-label={`${singular} ${index + 1}`}
              value={value}
              list={listId}
              disabled={disabled}
              required
              maxLength={512}
              onChange={(event) => onChange(values.map((item, itemIndex) => itemIndex === index ? event.target.value : item))}
            />
          </label>
          <button type="button" title={`Remove ${singular}`} aria-label={`Remove ${singular} ${index + 1}`} disabled={disabled || values.length === 1} onClick={() => onChange(values.filter((_, itemIndex) => itemIndex !== index))}>
            <Trash2 aria-hidden="true" size={14} />
          </button>
        </div>
      ))}
      <button type="button" className="dev-manifest-add" disabled={disabled} onClick={() => onChange([...values, ""])}>
        <Plus aria-hidden="true" size={14} /> Add {singular}
      </button>
    </fieldset>
  );
}

export function ProjectManifestDialog({ project, folderPaths, canEdit, busy, onClose, onSave }: ProjectManifestDialogProps) {
  const [manifest, setManifest] = useState(() => exactManifest(project));
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const next: ProjectManifest = {
      ...manifest,
      source_roots: trimNonempty(manifest.source_roots),
      owners: trimNonempty(manifest.owners),
      policy_labels: trimNonempty(manifest.policy_labels),
      catalog_dependencies: manifest.catalog_dependencies.map((item) => ({
        catalog_id: item.catalog_id.trim(),
        catalog_revision: Number(item.catalog_revision),
        content_digest: item.content_digest.trim().toLowerCase(),
      })),
    };
    if (!next.owners.includes(project.owner_subject)) {
      setError(`Owners must include ${project.owner_subject}.`);
      return;
    }
    if (!next.policy_labels.includes("LOCAL_SYNTHETIC_NON_CUI_ONLY")) {
      setError("Policy labels must include LOCAL_SYNTHETIC_NON_CUI_ONLY.");
      return;
    }
    setError(null);
    await onSave(next);
  }

  const updateDependency = (index: number, value: ProjectCatalogDependency) => {
    setManifest((current) => ({
      ...current,
      catalog_dependencies: current.catalog_dependencies.map((item, itemIndex) => itemIndex === index ? value : item),
    }));
  };

  return (
    <div className="dev-modal-backdrop">
      <form className="dev-dialog dev-manifest" role="dialog" aria-modal="true" aria-labelledby="dev-manifest-title" onSubmit={(event) => void submit(event)}>
        <div className="dev-panel-title">
          <h2 id="dev-manifest-title">Project manifest</h2>
          <button type="button" title="Close" aria-label="Close project manifest" onClick={onClose}><X aria-hidden="true" size={15} /></button>
        </div>
        <div className="dev-manifest-fixed">
          <label>Project ID<input value={manifest.project_id} readOnly /></label>
          <label>Display name<input value={manifest.display_name} readOnly /></label>
          <label>Language profile<input value={manifest.language_profile} readOnly /></label>
          <label>Case policy<input value={manifest.case_policy} readOnly /></label>
        </div>
        <StringRows
          legend="Source roots"
          singular="source root"
          values={manifest.source_roots}
          disabled={!canEdit || busy}
          listId="dev-source-roots"
          onChange={(source_roots) => setManifest((current) => ({ ...current, source_roots }))}
        />
        <datalist id="dev-source-roots">{folderPaths.map((path) => <option value={path} key={path} />)}</datalist>
        <StringRows legend="Owners" singular="owner" values={manifest.owners} disabled={!canEdit || busy} onChange={(owners) => setManifest((current) => ({ ...current, owners }))} />
        <StringRows legend="Policy labels" singular="policy label" values={manifest.policy_labels} disabled={!canEdit || busy} onChange={(policy_labels) => setManifest((current) => ({ ...current, policy_labels }))} />
        <fieldset className="dev-manifest-group">
          <legend>Pinned catalog dependencies</legend>
          {manifest.catalog_dependencies.map((dependency, index) => (
            <div className="dev-dependency-row" key={`dependency-${index}`}>
              <label>Catalog ID<input required maxLength={200} disabled={!canEdit || busy} value={dependency.catalog_id} onChange={(event) => updateDependency(index, { ...dependency, catalog_id: event.target.value })} /></label>
              <label>Revision<input required min={1} step={1} type="number" disabled={!canEdit || busy} value={dependency.catalog_revision} onChange={(event) => updateDependency(index, { ...dependency, catalog_revision: Number(event.target.value) })} /></label>
              <label>Content SHA-256<input required pattern="[0-9a-fA-F]{64}" maxLength={64} disabled={!canEdit || busy} value={dependency.content_digest} onChange={(event) => updateDependency(index, { ...dependency, content_digest: event.target.value })} /></label>
              <button type="button" title="Remove catalog dependency" aria-label={`Remove catalog dependency ${index + 1}`} disabled={!canEdit || busy} onClick={() => setManifest((current) => ({ ...current, catalog_dependencies: current.catalog_dependencies.filter((_, itemIndex) => itemIndex !== index) }))}>
                <Trash2 aria-hidden="true" size={14} />
              </button>
            </div>
          ))}
          <button type="button" className="dev-manifest-add" disabled={!canEdit || busy} onClick={() => setManifest((current) => ({ ...current, catalog_dependencies: [...current.catalog_dependencies, { catalog_id: "", catalog_revision: 1, content_digest: "" }] }))}>
            <Plus aria-hidden="true" size={14} /> Add dependency
          </button>
        </fieldset>
        {error && <p className="dev-manifest-error" role="alert">{error}</p>}
        <div className="dev-dialog-actions">
          <button type="button" onClick={onClose}>{canEdit ? "Cancel" : "Close"}</button>
          {canEdit && <button type="submit" className="primary" disabled={busy}>Save manifest</button>}
        </div>
      </form>
    </div>
  );
}
