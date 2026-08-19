export type DevelopmentRole = "viewer" | "operator" | "admin";

export interface DevelopmentIdentity {
  subject: string;
  role: DevelopmentRole;
}

export interface ProjectSummary {
  project_id: string;
  workspace_id: string;
  display_name: string;
  owner_subject: string;
  author_subject: string;
  workspace_revision: number;
  base_history_revision_id: string | null;
  base_bundle_digest: string | null;
  case_policy: "CASE_SENSITIVE" | "CASE_INSENSITIVE";
  manifest: ProjectManifest;
  closed: boolean;
  created_at: string;
  updated_at: string;
}

export interface ProjectCatalogDependency {
  catalog_id: string;
  catalog_revision: number;
  content_digest: string;
}

export interface ProjectManifest {
  schema_version: "spell.project/0.9";
  project_id: string;
  display_name: string;
  language_profile: "spell-restricted-ast/0.9";
  source_roots: string[];
  case_policy: ProjectSummary["case_policy"];
  catalog_dependencies: ProjectCatalogDependency[];
  owners: string[];
  policy_labels: string[];
}

export type ResourceKind =
  | "PROJECT"
  | "SOURCE_FOLDER"
  | "FOLDER"
  | "PROCEDURE"
  | "DICTIONARY"
  | "PROJECT_METADATA";

export interface ProjectResource {
  resource_id: string;
  project_id: string;
  path: string;
  name: string;
  parent_path: string | null;
  kind: ResourceKind;
  media_type: string;
  content_sha256: string;
  byte_length: number;
  revision: number;
  has_children: boolean;
  content?: string;
  created_by_subject: string;
  updated_by_subject: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectWorkspace {
  project: ProjectSummary;
  resources: ProjectResource[];
  workspace_revision: number;
  problems: DevelopmentDiagnostic[];
  jobs: SemanticJob[];
  history: HistoryRevision[];
  conflicts: WorkspaceConflict[];
  bundles: ProcedureBundle[];
  promotion_catalog_entries: PromotionCatalogEntry[];
  pinned_catalog_entries: PinnedCatalogItem[];
  presence: PresenceRecord[];
}

export interface ProjectProperties {
  project: ProjectSummary;
  resource_counts: Record<string, number>;
  byte_length: number;
}

export interface ResourceDocument {
  resource_id: string;
  project_id: string;
  path: string;
  kind: ResourceKind;
  media_type: string;
  content: string;
  content_sha256: string;
  byte_length: number;
  revision: number;
  metadata: ProcedureMetadata | null;
  language?: LanguageProjection;
}

export interface ProcedureMetadata {
  procedure_id: string;
  display_name: string;
  description: string;
  language_profile: string;
  arguments: Record<string, string>;
  catalog_dependencies: ProjectCatalogDependency[];
}

export interface LanguageOutlineItem {
  kind: string;
  name: string;
  line: number;
  column: number;
}

export interface LanguageCompletion {
  label: string;
  kind: string;
  insert_text: string;
  sort_text: string;
}

export interface LanguageProjection {
  diagnostics: DevelopmentDiagnostic[];
  outline: LanguageOutlineItem[];
  completions: LanguageCompletion[];
}

export interface PinnedCatalogItem {
  catalog_id: string;
  catalog_revision: number;
  content_digest: string;
  entry_id: string;
  qualified_name: string;
  catalog_kind: "TM" | "TC" | "RESOURCE" | "SCDB" | "GDB" | "PROC" | "MMD";
  data: Record<string, unknown>;
}

export interface DictionaryTypedValue {
  schema_version: "spell.data.value/1";
  type: "NULL" | "BOOLEAN" | "INT64" | "UINT64" | "DECIMAL" | "FINITE_DOUBLE" | "STRING" | "BYTES" | "UTC_DATETIME" | "REL_DURATION" | "LIST" | "MAP";
  value: unknown;
}

export interface DictionaryDbEntry {
  entry_id: string;
  qualified_name: string;
  value: DictionaryTypedValue;
  value_digest: string;
}

export interface DictionaryImpRecord {
  operation: "UPSERT" | "DELETE";
  entry_id: string;
  expected_entry_revision: number;
  qualified_name?: string;
  value?: DictionaryTypedValue;
  value_digest?: string;
}

export interface DictionaryDbDocument {
  base_revision: number;
  content_digest: string;
  dictionary_id: string;
  entries: DictionaryDbEntry[];
  format: "DB";
  schema_version: "spell.dictionary.db/1";
}

export interface DictionaryImpDocument {
  base_revision: number;
  content_digest: string;
  dictionary_id: string;
  records: DictionaryImpRecord[];
  format: "IMP";
  schema_version: "spell.dictionary.imp/1";
}

export type DictionaryDocument = DictionaryDbDocument | DictionaryImpDocument;

export interface ExternalResourceChange {
  path: string;
  content?: string;
  delete?: boolean;
  base_content_sha256?: string;
  kind?: ResourceKind;
  media_type?: string;
}

export interface ImportOperation {
  operation_id: string;
  project_id: string;
  actor_subject: string;
  original_filename: string;
  original_media_type: string;
  original_byte_length: number;
  original_bytes_sha256: string;
  original_bytes_available: boolean;
  imported_tree_sha256: string;
  canonical_tree_sha256: string;
  base_workspace_revision: number;
  status: "QUARANTINED" | "APPLYING" | "APPLIED" | "NO_CHANGE" | "CONFLICT" | "DISCARDED";
  conflict_paths: string[];
  audit_id: string;
  created_at: string;
}

export interface PromotionCatalogEntry {
  procedure_id: string;
  registry_revision: number;
  current_bundle_digest: string | null;
  previous_bundle_digest: string | null;
  state: string;
  updated_by_subject: string;
  created_at: string;
  updated_at: string;
}

export interface MutationResult {
  workspace_revision: number;
  resource?: ProjectResource;
}

export type DiagnosticSeverity = "ERROR" | "WARNING" | "INFO";

export interface DevelopmentDiagnostic {
  diagnostic_id: string;
  code: string;
  severity: DiagnosticSeverity;
  source_path: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
  language_profile: string;
  message: string;
  remediation_ref: string;
  tool_version: string;
}

export type CheckScope = "FILE" | "FOLDER" | "PROJECT" | "CHANGED_SET";
export type SemanticJobState =
  | "QUEUED"
  | "RUNNING"
  | "CANCEL_REQUESTED"
  | "CANCELLED"
  | "COMPLETED"
  | "FAILED";

export interface SemanticJob {
  job_id: string;
  project_id: string;
  workspace_revision: number;
  scope: CheckScope;
  state: SemanticJobState;
  progress: number;
  scope_path?: string | null;
  tool_version?: string;
  input_digest?: string;
  report_sha256?: string | null;
  failure_code?: string | null;
  created_at?: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface HistoryRevision {
  history_revision_id: string;
  project_id: string;
  parent_revision_ids: string[];
  tree_digest: string;
  author_subject: string;
  message: string;
  validation_summary_digest: string;
  workspace_revision: number;
  ordinal: number;
  created_at: string;
  review_revision: number;
  review?: HistoryReview | null;
}

export interface HistoryReview {
  review_id: string;
  history_revision_id: string;
  review_revision: number;
  reviewer_subject: string;
  decision: "APPROVED" | "CHANGES_REQUESTED";
  reason: string;
  created_at: string;
}

export interface RevisionDiffFile {
  resource_id: string;
  path: string;
  status: "ADDED" | "MODIFIED" | "DELETED" | "RENAMED" | "CASE_CHANGED";
  old_path: string | null;
  before_path: string | null;
  after_path: string | null;
  content_changed: boolean;
  before_sha256: string | null;
  after_sha256: string | null;
  metadata_delta: {
    before: { kind: ResourceKind; media_type: string } | null;
    after: { kind: ResourceKind; media_type: string } | null;
  };
  dependency_impact: boolean;
  patch: string;
}

export interface RevisionDiff {
  history_revision_id: string | null;
  against_revision_id: string | null;
  project_id?: string;
  workspace_revision?: number;
  changes: RevisionDiffFile[];
  dependency_delta: { before: unknown[]; after: unknown[] };
  validation_delta: { before_digest: string | null; after_digest: string | null; changed: boolean };
}

export interface WorkspaceStatusChange {
  resource_id: string;
  path: string;
  old_path: string | null;
  status: RevisionDiffFile["status"];
  before_sha256: string | null;
  after_sha256: string | null;
}

export interface WorkspaceStatus {
  project_id: string;
  workspace_revision: number;
  base_history_revision_id: string | null;
  clean: boolean;
  change_count: number;
  changes: WorkspaceStatusChange[];
}

export interface WorkspaceConflict {
  conflict_id: string;
  project_id: string;
  path: string;
  kind: "TEXT" | "DELETE_MODIFY" | "RENAME_RENAME" | "RENAME_DELETE" | "CASE_COLLISION" | "METADATA" | "DEPENDENCY";
  conflict_digest: string;
  base_content_sha256: string | null;
  ours_content_sha256: string | null;
  theirs_content_sha256: string | null;
  resolved?: boolean;
  state?: "OPEN" | "RESOLVED";
}

export interface PresenceRecord {
  presence_id: string;
  project_id: string;
  resource_id: string | null;
  subject: string;
  client_instance_id: string;
  status: "ACTIVE" | "IDLE" | "EDITING" | "VIEWING" | "OFFLINE";
  updated_at: string;
  expires_at: string;
}

export interface ProjectExport {
  filename: string;
  media_type: string;
  archive: Blob;
  archive_sha256: string;
}

export type BundleState = "CANDIDATE" | "APPROVED" | "PROMOTED" | "SUPERSEDED" | "WITHDRAWN";

export interface ProcedureBundle {
  bundle_digest: string;
  project_id: string;
  history_revision_id: string;
  source_tree_digest: string;
  validation_report_digest: string;
  author_subject: string;
  review_subject: string;
  builder_identity: string;
  byte_length: number;
  manifest: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  state: BundleState;
  state_revision: number;
  approved_by_subject: string | null;
  approval_reason: string | null;
}

export interface PromotionDecision {
  decision_id: string;
  procedure_id: string;
  operation: "PROMOTE" | "SUPERSEDE" | "WITHDRAW" | "ROLLBACK_PROMOTE";
  previous_bundle_digest: string | null;
  new_bundle_digest: string | null;
  actor_subject: string;
  reason: string;
  registry_revision: number;
  correlation_id: string;
  created_at?: string;
}

export interface PromotionRegistry {
  catalog_entry: PromotionCatalogEntry;
  decisions: PromotionDecision[];
}

export interface DevelopmentBootstrap {
  identity: DevelopmentIdentity;
  projects: ProjectSummary[];
}

export interface PageResult<T> {
  items: T[];
  next_cursor?: string | null;
}
