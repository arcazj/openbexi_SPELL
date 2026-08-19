# Procedure Navigation and Catalog

## 1. Purpose

This document specifies the left navigation tree and the procedure catalog
behind it. The tree is a projection of authorized Git-backed procedure
definitions and immutable promoted bundles. It is not a direct view of a server
filesystem.

## 2. Identity Model

Path, display name, and identity are separate:

| Resource | Stable identity | Mutable attributes |
| --- | --- | --- |
| Repository | `repository_id` | display name, remote URL policy |
| Folder/category | `folder_id` | name, parent, ordering, description |
| Procedure definition | `procedure_id` | name, path, category, metadata |
| Procedure version | `bundle_digest` plus `procedure_id` | none after promotion |
| Execution instance | `execution_id` | state and runtime projections |

Moves and renames preserve `folder_id` and `procedure_id`. A deleted
definition remains resolvable in historical executions by repository commit
and bundle digest. IDs are generated once and stored in validated project
metadata; path-derived IDs are prohibited.

## 3. Default Taxonomy

Each new mission repository shall offer these top-level categories unless the
mission configuration explicitly replaces them:

- Bus Procedures
- Payload Procedures
- Platform Procedures
- Test Procedures
- Commissioning Procedures
- Maintenance Procedures
- Emergency Procedures

Authorized developers may add user-defined categories and nested folders.
Category names are presentation metadata, not execution permissions.
Authorization is evaluated from policy-bound stable IDs and labels.

## 4. Tree Behavior

The tree shall support:

- arbitrary nesting within configured depth and item-count limits;
- expand/collapse, keyboard navigation, type-ahead, and accessible tree
  semantics;
- lazy loading and virtualization without changing logical order;
- deterministic server-provided ordering by explicit order, normalized name,
  and stable ID;
- badges for validation, Git change, promotion, dependency, active execution,
  alarm, and permission state;
- separate definition and active-instance affordances;
- drag/drop and move only in Edit Mode, represented as Git changes;
- durable deep links using stable IDs rather than display paths.

Expanding a folder shall not fetch unauthorized descendants and then hide them
in the browser. The catalog service returns only authorized metadata and must
not leak names, counts, paths, tags, existence, or search matches for denied
resources.

## 5. Search

Search shall cover authorized procedure name, path, identifier, description,
owner, approved tags, header metadata, and declared dependencies. Source-body
search is an explicit Edit Mode operation and is not enabled in operational
catalog search by default.

Search requests include repository/ref or promoted-catalog identity, mode,
query, filters, sort, page cursor, and requested result limit. Results include
matched fields, stable IDs, version/promotion status, permission summary, and a
server-issued continuation cursor. The client shall not attempt to reconstruct
authorization-filtered totals.

Normalization shall be locale-stable and documented. Exact identifier and
emergency-category results rank before fuzzy text results. Highlighting is a
presentation hint and shall escape untrusted text.

## 6. Filters and Views

Supported filters include:

- category and nested folder;
- approved metadata tags;
- owner or responsible team;
- validation status;
- promotion environment and bundle version;
- active, scheduled, or historical execution availability;
- changed, conflicted, untracked, or review status in Edit Mode;
- favorites and recent use.

Filters are combined explicitly and shown as removable criteria. Empty results
distinguish no match, no permission, unavailable catalog, and stale index.

### 6.1 Favorites

Favorites are per-user references to stable `procedure_id` or `folder_id`.
They do not modify the mission repository, catalog ordering, or operational
authorization. A favorite whose target was removed or access-revoked displays
an unavailable reference without revealing protected metadata.

### 6.2 Recent Procedures

Recent procedures derive from audited authorized actions such as view, edit,
validate, start, or monitor. The display distinguishes recent definitions from
recent executions. Retention and privacy follow mission policy. Clearing the
personal view does not delete audit history.

## 7. Selection Contract

Selecting a procedure definition shows:

- stable ID, current authorized display path, description, owners, tags, and
  declared criticality;
- repository commit or promoted bundle digest;
- language profile and validation result;
- dependencies and required driver capabilities;
- available versions and promotion status;
- active/scheduled instances visible to the user;
- allowed actions returned by policy evaluation.

Starting a procedure is never an implicit consequence of selection,
double-click, drag/drop, or opening a file. Start requires Execution Mode,
active lease, explicit version, validated arguments, expected catalog revision,
and a separate command confirmation when policy requires it.

Selecting an execution navigates by `execution_id` and preserves the pinned
bundle version even when the catalog's current version changes.

## 8. Edit Operations

Create, rename, move, organize, and delete are Git working-change operations:

1. Validate the target branch and base revision.
2. Apply the requested change to a server-managed workspace.
3. Preserve or create stable metadata IDs.
4. Run path, case-collision, dependency, import, and policy checks.
5. Return a structured diff and diagnostics.
6. Require an explicit commit through the workflow in
   [Authoring and Git](../procedures/AUTHORING_AND_GIT.md).

Delete removes a definition from a future commit; it does not delete prior
commits, promoted bundles, as-run evidence, or running executions. Recursive
folder deletion requires a complete item count, permission check, dependency
impact report, typed confirmation, and reason.

## 9. Catalog Consistency

The operational catalog is built only from promoted immutable bundle manifests.
The Edit tree is built from a named Git repository, branch, base commit, and
workspace revision. The two projections shall never be merged into an
ambiguous "latest" view.

Catalog responses carry `catalog_revision`, `generated_at`, source commit,
and index status. A start command references the same revision or fails with a
conflict that requires refresh. Index lag shall be visible and shall never
cause an unvalidated Git working copy to become executable.

Dependencies are displayed as a graph with cycle, missing-version, ambiguous
import, and permission diagnostics. Dependency paths resolve inside the pinned
bundle; no runtime fetch from a branch or remote repository is permitted.

## 10. Performance and Scale

The implementation shall define and test:

- maximum tree depth and children per folder;
- catalog and repository item counts;
- search-index freshness target;
- first-page and expanded-node latency targets;
- concurrent search and reconnect load;
- continuation-cursor lifetime and invalidation;
- memory limits for large trees and dependency graphs.

Client virtualization shall preserve accessible item count, position, focus,
selection, and keyboard behavior. It is an optimization, not a reason to omit
items silently.

## 11. Acceptance Criteria

| ID | Acceptance criterion |
| --- | --- |
| `WEB-023` | Nested default and user-defined categories render with stable IDs, accessible keyboard behavior, and deterministic ordering. |
| `WEB-024` | Rename and move preserve procedure identity; historical and running versions remain resolvable by digest. |
| `WEB-025` | Search, filters, favorites, and recent views cannot reveal unauthorized metadata or mutate runtime state. |
| `WEB-026` | Definition selection and execution selection are unambiguous, and no navigation gesture starts a procedure. |
| `WEB-027` | Edit operations produce validated Git diffs; delete cannot remove history, promoted artifacts, or active instances. |
| `WEB-028` | Start rejects a stale catalog revision and always pins an immutable bundle digest. |
| `GIT-023` | Folder and procedure organization is represented in versioned metadata with case-collision and dependency checks. |
| `GIT-024` | Operational and Edit trees display their distinct source commit, bundle, branch, and index states. |
