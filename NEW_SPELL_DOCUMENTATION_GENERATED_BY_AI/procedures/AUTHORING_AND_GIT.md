# Procedure Authoring and Git Governance

## 1. Purpose

This document defines how procedures are created, changed, validated, reviewed,
promoted, and rolled back. Git is the source of truth for editable procedure
source. The runtime consumes only immutable, content-addressed bundles produced
from approved Git revisions.

The design preserves the project, editor, dictionary, validation, history,
diff, conflict, and collaboration intent of the SPELL Development Environment
Manual 2.4.4 while replacing CVS/SVN and mutable runtime files with a controlled
Git workflow.

## 2. Trust Boundaries

The following stores have distinct purposes:

| Store | Authority | Prohibited use |
| --- | --- | --- |
| Git repository | Editable procedure source, metadata, dictionaries, tests, and review history | Direct execution from a branch or working tree |
| Authoring workspace | Temporary server-managed changes for one authenticated developer | System of record or operational runtime |
| Artifact repository | Immutable validated procedure bundles and attestations | Editing |
| Promotion registry | Approved mapping from environment/catalog entry to bundle digest | Storing mutable source |
| Execution store | Pinned as-run bundle, configuration, state, events, and audit | Inferring or modifying Git history |

No working tree is mounted into an execution worker. The browser does not hold
long-lived Git remote credentials. Repository access occurs through an
authenticated authoring service using user-delegated or service credentials
held in the approved secret store.

This implements `GIT-013`, `GIT-014`, and `COMP-016`.

## 3. Repository Contract

A procedure repository shall contain a versioned project manifest and may use
the following conventional areas:

| Area | Content |
| --- | --- |
| `spell-project.yaml` | Project identity, schema version, language profile, roots, catalog dependencies, owners, and policy labels |
| `procedures/` | Procedure source and stable procedure metadata |
| `libraries/` | Approved source libraries within the bounded language profile |
| `dictionaries/` | Typed project/user dictionaries and schemas |
| `catalogs/` | Pinned TM/TC/resource catalog references or approved snapshots |
| `tests/` | Parser, semantic, simulation, compatibility, and regression tests |
| `docs/` | Procedure-level operator and maintenance notes |

The manifest shall define:

- `project_id`, manifest schema version, and display name;
- source roots and case-sensitivity policy;
- exact language and compatibility profiles;
- dependency allowlist and resolution rules;
- required catalog identities and digests;
- default owners and review groups;
- criticality and promotion policy labels;
- permitted build-toolchain version range.

Each procedure has a stable `procedure_id` in validated metadata. The ID does
not change on rename or move and shall be unique across the repository's trust
domain. Paths are normalized and checked for case-only collision on every
supported build platform.

Secrets, private keys, live credentials, uncontrolled binaries, generated
build output, runtime checkpoints, and as-run logs shall not be committed to
the procedure repository.

## 4. Branch and Change Workflow

### 4.1 Protected Refs

The default integration and release branches are protected. They require:

- merge request or pull request;
- successful required validation checks;
- review from configured code owners;
- independent approval for critical procedures;
- verified commit signatures on protected history;
- no unresolved review, security, compatibility, or dependency finding;
- fast-forward or recorded merge strategy defined by repository policy;
- immutable release tag for a promotion candidate.

Direct force-push and history rewrite on protected refs are prohibited.
Deletion of protected refs requires separately audited repository
administration.

### 4.2 Authoring Session

An Edit Mode session creates or resumes a server-managed workspace identified
by repository, branch, base commit, developer, and `workspace_revision`.
Each save uses optimistic concurrency. If the base or workspace revision
changed, the service returns a structured conflict; it shall not overwrite
another edit silently.

The authoring service shall support:

1. create branch from an authorized ref;
2. create, modify, move, rename, and delete procedures or folders;
3. show source diff, metadata diff, dependency impact, and validation changes;
4. stage selected changes and construct a commit;
5. sign the commit using the approved user or service-backed signing flow;
6. push without exposing the remote credential to the browser;
7. open or update a review request;
8. resolve text, rename, case, metadata, and dependency conflicts explicitly;
9. inspect history, blame/provenance where authorized, tags, and prior bundles.

Advisory presence and file-lock indicators may reduce conflicting edits but
shall not replace Git concurrency checks. A stale lock cannot block recovery.

### 4.3 Commit Quality

Every commit proposed for a protected branch shall have:

- a descriptive message and linked change/request identity;
- authenticated author and committer;
- verified signature according to the mission trust policy;
- no generated bundle or credential material;
- stable procedure IDs and valid manifest schema;
- machine-readable validation status tied to the exact commit.

Review approval is invalidated when the protected content changes unless policy
explicitly determines the change is non-semantic and records that decision.

## 5. Non-Executing Language Services

The authoring service shall provide:

- syntax highlighting, folding, outline, symbol navigation, and completion;
- parser diagnostics with exact source spans;
- checks for headers, arguments, steps/gotos, functions, modifiers, SPELL
  calls, dictionaries, and TM/TC/resource references;
- dependency graph, cycle detection, version resolution, and unused/missing
  dependency findings;
- project, folder, file, and changed-set validation;
- cancellable progress and stable Problems entries;
- deterministic formatting where a profile defines it;
- source templates and catalog-driven snippets that generate text only.

Parsing, indexing, completion, validation, and formatting shall not import or
execute procedure modules, evaluate expressions, contact a driver/GCS, or
resolve arbitrary network resources. All catalog inputs are pinned,
schema-validated data.

Diagnostics include stable code, severity, source span, language profile,
message, remediation reference, and tool version. The same commit and pinned
inputs shall produce the same diagnostics.

## 6. Validation Pipeline

A promotion candidate passes these ordered gates:

| Gate | Required evidence |
| --- | --- |
| Repository integrity | Clean exact commit, valid signatures, manifest and ID uniqueness, no forbidden files or secrets |
| Parse and schema | All source, dictionaries, metadata, catalogs, and tests parse against pinned schemas |
| Semantic analysis | Control flow, steps/gotos, calls, modifiers, arguments, scopes, types, bounded constructs, and effects validate |
| Dependency resolution | Complete acyclic graph, pinned versions/digests, allowlisted licenses and sources |
| Compatibility | All used legacy constructs have approved ledger dispositions and golden tests |
| Security | Static analysis, secret scan, dependency and policy scan, signed toolchain provenance |
| Simulation | Deterministic simulator scenarios, failure paths, prompts, restart, abort, and expected trace assertions |
| Operational review | Owners approve arguments, effects, alarms, timeouts, recovery, and operator text |
| Bundle reproducibility | Independent build reproduces the same content digest |

Warnings require an explicit policy disposition; they cannot disappear by
changing UI severity. Emergency procedures may use an expedited review path
only if defined in advance, separately authorized, time-bounded, and followed
by retrospective review.

## 7. Immutable Procedure Bundle

The bundle builder consumes a clean approved commit in a hermetic, pinned
environment. It resolves all permitted dependencies and emits a deterministic
archive plus manifest. File ordering, paths, permissions, line endings,
encoding, timestamps, and compression parameters are canonicalized.

The manifest shall include:

- bundle format and schema versions;
- cryptographic content digest and digest algorithm;
- repository identity, exact commit, signed release tag, and source tree
  digest;
- project and procedure IDs;
- language profile, compatibility profile, parser, validator, compiler, and IR
  schema versions;
- complete dependency and catalog digests;
- generated source map and entry points;
- required driver capabilities and declared effect classes;
- validation evidence and test result digests;
- build service identity, UTC time, toolchain provenance, and signature;
- approval identities or signed approval attestation references;
- data classification and retention labels.

The bundle contains only declared inputs. It does not fetch dependencies or
source at load or run time. Any byte change produces a different digest.
Artifact storage rejects overwrite of an existing digest.

## 8. Promotion

Promotion is a signed, audited server-side operation that maps a catalog entry
and environment to an existing verified bundle digest. It does not rebuild the
bundle. The mapping and its history are authoritative, revisioned PostgreSQL
state; idempotency, approvals, audit evidence, and its outbox event commit in
one transaction. Search indexes and runtime catalog caches are rebuildable
projections of that registry.

| Promotion state | Meaning |
| --- | --- |
| Candidate | Bundle built and validated; not available to operational start |
| Approved | Required reviews and signatures verified |
| Promoted | Catalog/environment references the digest for new starts |
| Superseded | A newer approved digest is current; historical use remains valid |
| Withdrawn | New starts prohibited because of policy or defect; evidence retained |

Promotion verifies artifact signature, provenance, commit/tag signature,
approval policy, compatibility status, required driver capabilities, target
environment, and expiration constraints. The result records actor, reason,
previous and new digest, policy decision, and audit correlation.

A running execution remains pinned to its selected digest unless an explicit
state-machine operation authorizes reload to another approved digest. A
schedule pins its bundle digest and catalog revision when created; later
promotion cannot retarget it implicitly. Catalog promotion alone never changes
an execution or schedule.

## 9. Rollback and Withdrawal

Rollback promotes a previously approved immutable digest as a new audited
catalog decision. It shall not rewrite Git history, overwrite an artifact, or
silently replace running source.

Before rollback, the service reports:

- target and current bundle identities;
- language, schema, dependency, catalog, database, and driver compatibility;
- active and scheduled executions affected;
- migration or state-resume constraints;
- known vulnerability or withdrawal status;
- required reviews and operational hold points.

Withdrawing a bundle prevents new starts and triggers policy-defined review of
scheduled and active instances. Stopping, migrating, or continuing an active
instance is an explicit operational decision.

## 10. Authorization and Separation of Duties

Distinct permissions cover repository read, edit, push, review, merge, tag,
build, approve, promote to each environment, withdraw, and administer policy.
Production promotion and forced policy bypass require strong authentication,
reason, and independent approval when mission policy requires it.

A developer shall not be able to use Edit Mode to grant their own runtime
role, alter audit history, modify validation results, inject a bundle directly
into artifact storage, or promote without the promotion service.

## 11. Audit and Retention

The system records workspace creation, source mutations, Git operations,
validation inputs/results, signature verification, artifact build, review,
promotion, rollback, withdrawal, export, and policy override. Events reference
stable repository, commit, procedure, bundle, user, and correlation IDs.

Retention preserves the ability to reconstruct every as-run bundle and its
approval evidence for the required mission period, even after Git branch
deletion or repository migration.

## 12. Acceptance Criteria

| ID | Acceptance criterion |
| --- | --- |
| `GIT-013` | Git is the editable source of truth; no branch, working tree, or editor buffer can be loaded by an execution. |
| `GIT-014` | Protected history requires verified signatures, required checks, code-owner review, and no force-push. |
| `GIT-015` | Parser and semantic services complete with network and execution disabled and without a GCS. |
| `GIT-016` | The same commit and pinned inputs produce identical diagnostics and an independently reproducible bundle digest. |
| `GIT-017` | Bundle manifests carry complete source, toolchain, dependency, catalog, approval, capability, and provenance identities. |
| `GIT-018` | Promotion verifies a preexisting immutable artifact and cannot rebuild or overwrite it. |
| `GIT-019` | Promotion, supersession, withdrawal, and rollback never mutate a running execution implicitly. |
| `GIT-020` | Concurrent edits and case/rename/dependency conflicts fail visibly without lost updates. |
| `GIT-021` | Separation-of-duties tests prevent authors from bypassing review, validation, artifact, or environment promotion policy. |
| `GIT-022` | Every historical execution resolves to retained source, manifest, signatures, approvals, validation evidence, and bundle bytes. |

## 13. Related Decision

The architectural rationale and rejected alternatives are recorded in
[ADR-005: Git Promotion and Immutable Bundles](../architecture/decisions/ADR-005-git-promotion-and-immutable-bundles.md).
